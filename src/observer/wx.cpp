#include "occ/observer/wx.h"

#include "occ/syscall/errno.h"
#include "occ/util/fs.h"
#include "occ/util/string.h"

#include <algorithm>
#include <cstring>

namespace occ::obs {

namespace {

constexpr std::uint64_t kPageSize = 4096;

// The last page a user-space address can occupy, and the address one past its
// end. Both are needed and they are not the same value: a region beginning at
// kUserPageTop is entirely inside the space, so refusing it would make the
// highest usable page unavailable for no reason, while a region reaching
// kUserPageEnd has a page that does not exist.
constexpr std::uint64_t kUserPageTop = 0x00007ffffffff000ULL;
constexpr std::uint64_t kUserPageEnd = 0x0000800000000000ULL;

std::uint64_t page_floor(std::uint64_t v) noexcept {
    return v & ~(kPageSize - 1);
}

// Rounds up to a page boundary without wrapping.
//
// The subtraction form matters at the top of the address space. Adding
// kPageSize-1 to a value a page short of the end wraps to a small number,
// and page_ceil would then report a length near zero for a region whose
// pages are real, which every later calculation would treat as a region of
// almost no bytes rather than as the error it is.
std::uint64_t page_ceil(std::uint64_t v) noexcept {
    const std::uint64_t remainder = v & (kPageSize - 1);
    if (remainder == 0) {
        return v;
    }
    // The page-aligned value plus the difference, which cannot overflow for
    // any v whose last page begins at or below v: the sum is the next page
    // boundary and v is already below it.
    return (v & ~(kPageSize - 1)) + kPageSize;
}

// Parses one line of /proc/<pid>/maps into a range and its permissions.
// The format is "start-end perms offset dev inode pathname", and the
// permission field is always four characters, with '-' where a permission
// is absent. Parsing is done by hand rather than with a stream because this
// runs for every write the tracker sees.
//
// The pathname is returned as well as the range because whether a region
// has one is the single cheapest signal available for telling a program's
// own data apart from a buffer it generated code into.
bool parse_maps_line(std::string_view line, std::uint64_t& start,
                     std::uint64_t& end, RegionPerms& perms,
                     bool& anonymous) noexcept {
    // Range.
    const std::size_t dash = line.find('-');
    if (dash == std::string_view::npos) {
        return false;
    }
    std::uint64_t s = 0;
    for (char c : line.substr(0, dash)) {
        if (c >= '0' && c <= '9') {
            s = s * 16 + static_cast<std::uint64_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            s = s * 16 + static_cast<std::uint64_t>(c - 'a' + 10);
        } else {
            return false;
        }
    }

    const std::size_t space = line.find(' ', dash);
    if (space == std::string_view::npos) {
        return false;
    }
    std::uint64_t e = 0;
    for (char c : line.substr(dash + 1, space - dash - 1)) {
        if (c >= '0' && c <= '9') {
            e = e * 16 + static_cast<std::uint64_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            e = e * 16 + static_cast<std::uint64_t>(c - 'a' + 10);
        } else {
            return false;
        }
    }

    const std::size_t perms_at = line.find_first_not_of(' ', space);
    if (perms_at == std::string_view::npos || perms_at + 4 > line.size()) {
        return false;
    }

    RegionPerms p;
    p.readable = line[perms_at] == 'r';
    p.writable = line[perms_at + 1] == 'w';
    p.executable = line[perms_at + 2] == 'x';

    // The pathname is what follows the inode field, and a line with nothing
    // after the inode has no pathname at all. A mapping the kernel reports
    // with no file behind it is anonymous, which is where a decoder's
    // staging buffer lives.
    const std::size_t after_perms = line.find_first_not_of(' ', perms_at + 4);
    anonymous = true;
    if (after_perms != std::string_view::npos) {
        // offset, dev, inode are three space-separated fields.
        std::size_t field = after_perms;
        for (int i = 0; i < 3; ++i) {
            const std::size_t next = line.find(' ', field);
            if (next == std::string_view::npos) {
                return false;
            }
            field = next + 1;
            while (field < line.size() && line[field] == ' ') {
                ++field;
            }
        }
        anonymous = field >= line.size();
    }

    start = s;
    end = e;
    perms = p;
    return true;
}

// Decides what a region is, from its permission alone. The classes are the
// ones the tracker acts on differently: a writable region gets a write
// watch, an executable one gets an execute watch, and the overlap is
// reported as its own case because it is the only combination where a write
// is not a transition.
RegionClass classify(const RegionPerms& p) noexcept {
    if (p.writable && p.executable) {
        return RegionClass::WritableExecutable;
    }
    if (p.writable) {
        return RegionClass::WritableData;
    }
    if (p.executable) {
        return RegionClass::ExecutableOnly;
    }
    return RegionClass::Other;
}

} // namespace

std::size_t watch_width(std::uint64_t address, std::uint64_t left) noexcept {
    // A write watch is encodable at four or eight bytes and nothing else,
    // so the choice is between those two rather than among four widths: an
    // address that is eight-aligned gets the eight-byte form, and a
    // four-aligned one that is not gets the four-byte form. The first
    // address of a region is page-aligned, so the common case is eight.
    std::size_t widest = 0;
    if (address % 8 == 0 && left >= 8) {
        widest = 8;
    } else if (address % 4 == 0 && left >= 4) {
        widest = 4;
    }

    // A watch may reach past the end of the region -- the kernel allows it,
    // and the extra bytes belong to a mapping the tracker is not claiming --
    // but the bytes it counts must not. Charging a region for bytes it does
    // not contain would push its covered count past its own length, which
    // hides a partial coverage from the report and overstates what was
    // watched by up to four bytes.
    if (widest > left) {
        return static_cast<std::size_t>(left);
    }
    return widest;
}

std::vector<RegionInfo> process_regions(int pid) noexcept {
    std::vector<RegionInfo> out;

    const std::string path = "/proc/" + std::to_string(pid) + "/maps";
    auto content = fs::read_file(path);
    if (!content) {
        return out;
    }

    std::size_t pos = 0;
    const std::string& text = *content;
    while (pos < text.size()) {
        std::size_t end = text.find('\n', pos);
        if (end == std::string::npos) {
            end = text.size();
        }
        const std::string_view line(text.data() + pos, end - pos);

        RegionInfo info;
        bool anonymous = false;
        std::uint64_t range_end = 0;
        if (parse_maps_line(line, info.base, range_end, info.perms,
                            anonymous)) {
            if (range_end > info.base) {
                info.length = range_end - info.base;
                info.anonymous = anonymous;
                info.kind = classify(info.perms);
                out.push_back(info);
            }
        }

        pos = end + 1;
    }
    return out;
}

bool read_region_perms(int pid, std::uint64_t address,
                       RegionPerms& out) noexcept {
    const std::string path = "/proc/" + std::to_string(pid) + "/maps";
    auto content = fs::read_file(path);
    if (!content) {
        return false;
    }

    std::size_t pos = 0;
    const std::string& text = *content;
    while (pos < text.size()) {
        std::size_t end = text.find('\n', pos);
        if (end == std::string::npos) {
            end = text.size();
        }
        const std::string_view line(text.data() + pos, end - pos);

        std::uint64_t start = 0;
        std::uint64_t stop = 0;
        RegionPerms perms;
        bool anonymous = false;
        if (parse_maps_line(line, start, stop, perms, anonymous) &&
            address >= start && address < stop) {
            out = perms;
            return true;
        }

        pos = end + 1;
    }
    return false;
}

int WriteExecuteTracker::watch(int pid, std::uint64_t base,
                               std::uint64_t length,
                               std::string& detail) noexcept {
    if (length == 0) {
        detail = "the region is empty";
        return sys::kEinval;
    }

    // A region whose pages run off the end of the address space is refused
    // rather than rounded. page_ceil would wrap near the top, and the
    // subtraction that derives the length would then produce a value near two
    // to the sixty-four, which reads as a region rather than as the mistake
    // it is.
    //
    // The comparison is written as a difference because `base + length` is
    // the sum that wraps. A region one page long beginning at the last page
    // is inside the space and is accepted; one byte more, or a region
    // beginning at the address past it, is not.
    if (base > kUserPageTop || length > kUserPageEnd - base) {
        detail = "the region runs past the end of the address space";
        return sys::kEinval;
    }

    Region r;
    r.pid = pid;
    r.target.base = page_floor(base);
    r.target.length = page_ceil(base + length) - r.target.base;

    // The permission the region has right now. It is read once here so that
    // a later transition can be described as "written while not executable,
    // executable now" rather than as a change from an unknown baseline --
    // without it every first transition would compare against nothing.
    (void)read_region_perms(pid, base, r.perms);

    // A region already watched is extended rather than duplicated. Two
    // entries for one range would double-count the bytes and let the second
    // one's arm overwrite the first one's coverage.
    for (auto& existing : regions_) {
        if (existing.pid == pid && existing.target.base == r.target.base) {
            if (r.target.length > existing.target.length) {
                // Growing a region that already has watches invalidates the
                // coverage recorded for it, because the new bytes have none.
                existing.target.length = r.target.length;
                existing.armed = false;
                existing.covered = 0;
                existing.watch_addresses.clear();
            }
            return 0;
        }
    }

    // A region that overlaps one already tracked is merged into it, so that
    // the tracker never holds two entries that both claim the same bytes.
    // The pid is part of the test: another process mapping the same address
    // is a different region, and merging them would report one process's
    // writes as the other's.
    for (auto& existing : regions_) {
        if (existing.pid != pid) {
            continue;
        }
        const std::uint64_t a0 = existing.target.base;
        const std::uint64_t a1 = a0 + existing.target.length;
        const std::uint64_t b0 = r.target.base;
        const std::uint64_t b1 = b0 + r.target.length;
        if (b0 < a1 && a0 < b1) {
            const std::uint64_t lo = a0 < b0 ? a0 : b0;
            const std::uint64_t hi = a1 > b1 ? a1 : b1;
            const bool grew = hi - lo > existing.target.length;
            existing.target.length = hi - lo;
            if (grew) {
                existing.armed = false;
                existing.covered = 0;
                existing.watch_addresses.clear();
            }
            return 0;
        }
    }

    regions_.push_back(r);
    detail.clear();
    return 0;
}

WriteExecuteTracker::Region* WriteExecuteTracker::find_region(
    int pid, std::uint64_t address) noexcept {
    for (auto& r : regions_) {
        if (r.pid == pid && address >= r.target.base &&
            address < r.target.base + r.target.length) {
            return &r;
        }
    }
    return nullptr;
}

void WriteExecuteTracker::note_write(int pid, std::uint64_t address,
                                     std::uint64_t bytes,
                                     std::uint64_t rip) noexcept {
    (void)rip;
    ++writes_seen_;

    // The write is attributed to the region in the process that made it. A
    // region in another process that happens to cover the same address is a
    // different region, and crediting this write to it would build a
    // transition out of two unrelated processes.
    Region* r = find_region(pid, address);
    if (r == nullptr) {
        // A write outside every watched region. The watch hardware fires on
        // an address range, so this happens when the faulting instruction
        // touched a neighbouring address in the same slot, and it is not a
        // transition.
        return;
    }

    r->written = true;
    r->bytes += bytes;
    ++r->writes;

    // A write clears a previous report: the region has been modified again
    // since it was last seen to execute, so whatever is there now has not
    // been accounted for.
    r->reported = false;
}

bool WriteExecuteTracker::note_permission(int pid, std::uint64_t address,
                                          const RegionPerms& perms) noexcept {
    Region* r = find_region(pid, address);
    if (r == nullptr) {
        return false;
    }

    const RegionPerms before = r->perms;
    r->perms = perms;

    // The transition is "written while not executable, executable now". A
    // region that was already executable when it was written is not a
    // transition; it is a program writing to its own code, which is a
    // different observation and one the caller can make from the write
    // record alone.
    if (!r->written || r->reported || !perms.executable) {
        return false;
    }

    Transition t;
    t.pid = pid;
    t.address = r->target.base;
    t.bytes_written = r->bytes;
    t.write_count = r->writes;
    t.was_writable = before.writable;
    t.was_executable = before.executable;
    t.became_executable = true;

    transitions_.push_back(t);
    r->reported = true;

    return true;
}

void WriteExecuteTracker::flush(int pid, obs::Writer& events) noexcept {
    // The transitions carry the pid they happened in, which is not always the
    // one the caller passes: a region is attributed to the process that
    // wrote it, and a caller flushing after handling a stop in one thread
    // would otherwise stamp another thread's transition with its own pid.
    (void)pid;
    for (const auto& t : transitions_) {
        auto& e = events.begin(obs::EventKind::MemoryWrite);
        e.add("pid", static_cast<std::uint64_t>(t.pid));
        e.add_hex("address", t.address);
        e.add("bytes_written", t.bytes_written);
        e.add("write_count", t.write_count);
        e.add("was_writable", t.was_writable);
        e.add("was_executable", t.was_executable);
        e.add("became_executable", t.became_executable);
        events.commit();
    }
    transitions_.clear();
}

void WriteExecuteTracker::release(Watchpoints& watchpoints) noexcept {
    for (auto& r : regions_) {
        for (std::uint64_t addr : r.watch_addresses) {
            (void)watchpoints.remove(addr);
        }
        r.watch_addresses.clear();
        r.armed = false;
        r.covered = 0;
    }
}

const std::vector<WatchTarget>&
WriteExecuteTracker::targets() const noexcept {
    static const std::vector<WatchTarget> empty;
    if (regions_.empty()) {
        return empty;
    }
    // The regions are stored with their bookkeeping alongside, so the
    // public view is built once and cached rather than recomputed on a
    // query a caller may make per event.
    //
    // The cache is invalidated by the total length as well as the count.
    // Merging two regions or extending one changes a length without changing
    // how many regions there are, so a count-only test would hand back the
    // old lengths and a caller sizing coverage from them would be working
    // from a region that no longer exists.
    std::uint64_t length = 0;
    for (const auto& r : regions_) {
        length += r.target.length;
    }
    if (targets_cache_.size() != regions_.size() ||
        targets_cache_length_ != length) {
        targets_cache_.clear();
        targets_cache_.reserve(regions_.size());
        for (const auto& r : regions_) {
            targets_cache_.push_back(r.target);
        }
        targets_cache_length_ = length;
    }
    return targets_cache_;
}

ArmReport WriteExecuteTracker::arm(Watchpoints& watchpoints,
                                   int pid) noexcept {
    ArmReport report;

    // The regions are served shortest first.
    //
    // This is the decision the whole tracker rests on, and it is worth being
    // explicit about why it is not longest first. Four debug registers of
    // eight bytes each cover thirty-two bytes in total. A program image
    // carries hundreds of kilobytes of writable data, so the longest region
    // would consume every slot and cover thirty-two bytes of a data segment
    // the target treats as ordinary storage -- a guarantee of seeing
    // nothing. A region of at most thirty-two bytes can instead be covered
    // completely, and a completely covered region detects every write to it.
    //
    // Reach and certainty are the two things four registers cannot both
    // buy, and a decoder's staging buffer is short by nature: it holds one
    // decoded routine, not a heap. Certainty on the short region is what
    // catches the transition.
    //
    // Only this process's regions are considered. A watch is a per-process
    // resource, so spending a register on another process's region would
    // install nothing and consume a slot that could have covered a region
    // the target can actually write to.
    std::vector<std::size_t> order;
    for (std::size_t i = 0; i < regions_.size(); ++i) {
        if (regions_[i].pid == pid) {
            order.push_back(i);
        }
    }
    for (std::size_t i = 0; i < order.size(); ++i) {
        order[i] = i;
    }
    std::stable_sort(order.begin(), order.end(),
                     [this](std::size_t a, std::size_t b) {
                         return regions_[a].target.length <
                                regions_[b].target.length;
                     });

    std::size_t slots = watchpoints.free_slots();

    for (std::size_t idx : order) {
        Region& r = regions_[idx];
        report.bytes_total += r.target.length;

        if (r.armed) {
            // Already covered from a previous arm. The bytes are counted
            // again because the report describes the total coverage rather
            // than the coverage added by this call.
            report.bytes_covered += r.covered;
            continue;
        }

        // A region with a length that rounds to nothing after alignment is
        // not watchable at all.
        const std::uint64_t base = r.target.base;
        std::uint64_t covered = 0;

        while (covered < r.target.length && slots > 0) {
            // The widest watch that is naturally aligned at this offset and
            // does not run past the region. When nothing fits -- a base that
            // is neither four- nor eight-aligned, which the page rounding in
            // watch() makes unreachable -- the region is reported as
            // unwatched rather than given a watch the kernel would refuse.
            const std::uint64_t addr = base + covered;
            const std::size_t width =
                watch_width(addr, r.target.length - covered);

            if (width == 0) {
                break;
            }

            std::string detail;
            const int rc = watchpoints.add(pid, addr, WatchKind::Write,
                                           width == 8 ? WatchSize::Bytes8
                                                      : WatchSize::Bytes4,
                                           detail);
            if (rc != 0) {
                // Out of slots, or the watch was refused for another reason.
                // Either way this region stops growing, and the reason is
                // not retried per byte: a refusal is not going to become a
                // success on the next address.
                break;
            }

            r.watch_addresses.push_back(addr);
            // width is already bounded by what is left of the region --
            // watch_width returns the smaller of the widest encodable watch
            // and the bytes remaining -- so advancing by it cannot push
            // `covered` past the length. That bound is what keeps the
            // `covered < r.target.length` test above honest about a region
            // whose last few bytes no watch reaches.
            covered += width;
            --slots;
        }

        if (covered > 0) {
            r.armed = true;
            r.covered = covered;
            r.armed_at = ++arm_clock_;
            report.bytes_covered += covered;
            report.watches_installed += r.watch_addresses.size();
        }

        if (covered < r.target.length) {
            WatchTarget t;
            t.base = r.target.base;
            t.length = r.target.length;
            if (covered == 0) {
                report.unwatched.push_back(t);
            } else {
                report.partial.push_back(
                    ArmReport::Partial{t, covered});
            }
        }
    }

    return report;
}

std::size_t WriteExecuteTracker::evict_cold(Watchpoints& watchpoints,
                                            std::size_t need) noexcept {
    // The candidates are the armed regions that have never been written to,
    // oldest watch first. A region that has been written is never evicted:
    // it holds the only evidence a transition can still be built from, and
    // throwing it away to make room for an untouched region would discard a
    // fact in exchange for a possibility.
    //
    // `need` is a count of watches to free, not a number of regions to keep.
    // The two are different because a region may hold several watches, and
    // because "keep one region" is not a promise the hardware can honour
    // when the one region needs three of the four registers.
    std::vector<std::size_t> cold;
    for (std::size_t i = 0; i < regions_.size(); ++i) {
        if (regions_[i].armed && !regions_[i].written) {
            cold.push_back(i);
        }
    }
    std::stable_sort(cold.begin(), cold.end(),
                     [this](std::size_t a, std::size_t b) {
                         return regions_[a].armed_at < regions_[b].armed_at;
                     });

    // The count returned is watches released rather than regions visited:
    // a region may have held several watches, and the caller cares about
    // how many debug registers became free.
    std::size_t released_watches = 0;
    for (std::size_t idx : cold) {
        if (released_watches >= need) {
            break;
        }
        Region& r = regions_[idx];
        for (std::uint64_t addr : r.watch_addresses) {
            (void)watchpoints.remove(addr);
        }
        released_watches += r.watch_addresses.size();
        r.watch_addresses.clear();
        r.armed = false;
        r.covered = 0;
    }

    return released_watches;
}

ArmReport WriteExecuteTracker::chase(Watchpoints& watchpoints, int pid,
                                     std::uint64_t base,
                                     std::uint64_t length) noexcept {
    ArmReport report;

    std::string detail;
    if (watch(pid, base, length, detail) != 0) {
        return report;
    }

    Region* r = find_region(pid, base);
    if (r == nullptr) {
        return report;
    }
    report.bytes_total = r->target.length;

    if (r->armed) {
        report.bytes_covered = r->covered;
        return report;
    }

    // The debug registers the startup scan spent are held by regions nothing
    // has written to, and a fresh mapping is a better place for them. How
    // many are released is derived from what is free rather than guessed:
    // freeing everything and re-arming greedily lands back in the state the
    // scan produced, and freeing nothing installs nothing.
    const std::uint64_t region_base = r->target.base;

    // The watches this region needs if the registers allow it. Computed
    // before the eviction so the eviction knows what it is freeing room for.
    // The widths come from the same enumeration the install loop below uses,
    // so the count cannot disagree with what is later placed.
    const std::size_t capacity = Watchpoints::machine_slots();
    std::size_t wanted_watches = 0;
    {
        std::uint64_t left = r->target.length;
        std::uint64_t at = region_base;
        while (left > 0) {
            const std::size_t w = watch_width(at, left);
            if (w == 0) {
                break;
            }
            ++wanted_watches;
            at += w;
            left -= (w < left) ? w : left;
        }
    }
    if (wanted_watches > capacity) {
        wanted_watches = capacity;
    }
    if (wanted_watches > 0) {
        const std::size_t live = watchpoints.size();
        if (live + wanted_watches > capacity) {
            (void)evict_cold(watchpoints, live + wanted_watches - capacity);
        }
    }

    std::size_t slots = watchpoints.free_slots();
    std::uint64_t covered = r->covered;

    while (covered < r->target.length && slots > 0) {
        const std::uint64_t addr = region_base + covered;
        const std::size_t width =
            watch_width(addr, r->target.length - covered);
        if (width == 0) {
            break;
        }

        std::string why;
        const int rc = watchpoints.add(pid, addr, WatchKind::Write,
                                       width == 8 ? WatchSize::Bytes8
                                                  : WatchSize::Bytes4,
                                       why);
        if (rc != 0) {
            break;
        }
        r->watch_addresses.push_back(addr);
        // width is already bounded by the bytes left, so it is what the
        // region is credited with. The bound lives in watch_width because
        // both this loop and arm() need it and a second copy of the rule is
        // a second place for it to drift.
        covered += width;
        --slots;
    }

    if (covered > 0) {
        r->armed = true;
        r->covered = covered;
        r->armed_at = ++arm_clock_;
        report.watches_installed = r->watch_addresses.size();
    }

    // The accounting arm performs, so a chased region and an armed one are
    // described identically.
    report.bytes_covered = covered;
    if (covered < r->target.length) {
        WatchTarget t;
        t.base = r->target.base;
        t.length = r->target.length;
        if (covered == 0) {
            report.unwatched.push_back(t);
        } else {
            report.partial.push_back(ArmReport::Partial{t, covered});
        }
    }

    return report;
}

} // namespace occ::obs

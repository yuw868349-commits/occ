#include "occ/observer/uprobe.h"

#include "occ/syscall/errno.h"
#include "occ/syscall/kabi.h"
#include "occ/syscall/syscall.h"
#include "occ/util/fs.h"
#include "occ/util/string.h"

#include <cstring>

#include <linux/perf_event.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

namespace occ::obs {

namespace {

// The two directories a tracefs may be mounted at. The first is where a
// modern kernel mounts it by itself; the second is where a distribution that
// still uses debugfs as the container puts it. Both are checked because
// which one exists is a property of the host and not of the kernel version:
// a 6.x kernel with an old fstab has the second and not the first.
constexpr const char* kTracefsCandidates[] = {
    "/sys/kernel/tracing",
    "/sys/kernel/debug/tracing",
};

// The file a probe is registered through, and the file its id is read from.
// The paths are built rather than stored because the tracefs root is chosen
// at runtime.
constexpr const char* kUprobeEvents = "/uprobe_events";

// The record types the ring reader decodes. A uprobe delivers through the
// same perf ring as a hardware watch, so the framing is the same; what
// differs is the payload, which is a trace entry rather than a breakpoint
// sample.
constexpr std::uint32_t kPerfRecordSample = PERF_RECORD_SAMPLE;
constexpr std::uint32_t kPerfRecordLost = PERF_RECORD_LOST;

struct RingHeader {
    std::uint32_t type;
    std::uint16_t misc;
    std::uint16_t size;
};

// The ring buffer's two pointers. ABI rather than layout: offsetof on the
// 64-bit architecture is 1024 and the two fields are adjacent.
constexpr std::size_t kRingDataHeadByte = 1024;
constexpr std::size_t kRingDataTailByte = 1032;

// The ring size. Two data pages plus the control page, which is the
// smallest power-of-two ring the kernel accepts. A uprobe hit is a few
// dozen bytes, so two pages hold a burst of them; a target that makes more
// calls than that between two reads loses the excess and the loss is
// counted rather than hidden.
constexpr std::size_t kRingDataPages = 2;
constexpr std::size_t kRingPages = kRingDataPages + 1;

std::uint64_t ring_load(const void* ring, std::size_t byte_offset) noexcept {
    const auto* words = reinterpret_cast<const volatile std::uint64_t*>(
        static_cast<const std::uint8_t*>(ring));
    return __atomic_load_n(words + byte_offset / 8, __ATOMIC_ACQUIRE);
}

void ring_store(void* ring, std::size_t byte_offset,
                std::uint64_t value) noexcept {
    auto* words = reinterpret_cast<volatile std::uint64_t*>(
        static_cast<std::uint8_t*>(ring));
    __atomic_store_n(words + byte_offset / 8, value, __ATOMIC_RELEASE);
}

std::size_t page_size() noexcept {
    const long p = ::sysconf(_SC_PAGESIZE);
    return p > 0 ? static_cast<std::size_t>(p) : static_cast<std::size_t>(4096);
}

// Appends one decimal number. Local because the tracefs interface takes the
// id as text and pulling in a formatter for one call site would be a
// dependency for an integer.
void append_number(std::string& out, std::uint64_t v) {
    char buf[24];
    int n = 0;
    if (v == 0) {
        out.push_back('0');
        return;
    }
    while (v != 0 && n < 24) {
        buf[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    while (n > 0) {
        out.push_back(buf[--n]);
    }
}

// Appends a hexadecimal number with no padding and no fixed width.
//
// This is not append_hex with a width of zero. That function's width is a
// digit count -- the number of nibbles to emit, with the leading zeroes a
// caller asks for kept -- so a width of zero emits nothing at all. The
// tracefs line this feeds would then read ".../lib.so:" with no offset,
// which the kernel refuses for a reason that names neither the offset nor
// this file.
void append_hex_variable(std::string& out, std::uint64_t v) {
    constexpr char digits[] = "0123456789abcdef";
    if (v == 0) {
        out.push_back('0');
        return;
    }
    // Collected in reverse and then reversed, because the digits are
    // produced from the least significant end.
    char buf[16];
    int n = 0;
    while (v != 0 && n < 16) {
        buf[n++] = digits[v & 0xf];
        v >>= 4;
    }
    while (n > 0) {
        out.push_back(buf[--n]);
    }
}

// Writes a whole string to a file, opening it for append and closing it
// after. A short write is retried; anything else is the errno.
int write_all(const std::string& path, const std::string& text) noexcept {
    auto fd = sys::openat(AT_FDCWD, path.c_str(), O_WRONLY | O_APPEND, 0);
    if (fd.failed()) {
        return fd.error;
    }
    const int d = static_cast<int>(fd.value);
    std::size_t done = 0;
    int err = 0;
    while (done < text.size()) {
        auto w = sys::write(d, text.data() + done, text.size() - done);
        if (w.failed()) {
            err = w.error;
            break;
        }
        if (w.value <= 0) {
            err = sys::kEio;
            break;
        }
        done += static_cast<std::size_t>(w.value);
    }
    (void)sys::close(d);
    return err;
}

// Reads a whole small file. The tracefs id file is a handful of bytes; the
// bound is what keeps a file that is not one from being read into memory.
std::string read_small(const std::string& path) noexcept {
    std::string out;
    auto fd = sys::openat(AT_FDCWD, path.c_str(), O_RDONLY, 0);
    if (fd.failed()) {
        return out;
    }
    const int d = static_cast<int>(fd.value);
    char buf[256];
    for (;;) {
        auto r = sys::read(d, buf, sizeof(buf));
        if (r.failed() || r.value <= 0) {
            break;
        }
        out.append(buf, static_cast<std::size_t>(r.value));
        if (out.size() > 4096) {
            break;
        }
    }
    (void)sys::close(d);
    return out;
}

// The first integer in a string, which is what the id file holds. A file
// that holds something else yields zero, which is not a valid event id and
// is reported as a failure by the caller rather than used.
std::uint64_t parse_number(const std::string& s) noexcept {
    std::uint64_t v = 0;
    bool any = false;
    for (char c : s) {
        if (c < '0' || c > '9') {
            if (any) {
                break;
            }
            continue;
        }
        any = true;
        v = v * 10 + static_cast<std::uint64_t>(c - '0');
        if (v > (UINT64_MAX / 10)) {
            return 0;
        }
    }
    return any ? v : 0;
}

} // namespace

ProbeAvailability Uprobes::availability(const std::string& explicit_root) noexcept {
    ProbeAvailability out;

    // A root that was named is used and nothing else is tried. Searching
    // afterwards would let a run that was pointed at an empty directory
    // silently fall through to a host mount, which is the opposite of what
    // naming one asks for.
    const auto inspect = [&out](const std::string& root) -> bool {
        const std::string events = root + "/events";
        if (!fs::is_dir(events)) {
            return false;
        }
        out.tracefs_root = root;
        // The registration file has to exist and be writable. Checking
        // existence alone would report a host whose tracefs is mounted
        // read-only as ready, and the first registration would fail with an
        // errno that reads like a probe problem.
        const std::string reg = root + kUprobeEvents;
        if (!fs::exists(reg)) {
            out.reason = "tracefs is mounted at " + root +
                         " but has no uprobe_events file, so the kernel's "
                         "uprobe interface is not enabled on this build";
            return false;
        }
        // Writable-check by opening for append without writing. An open
        // that succeeds is the whole question; the alternative is to write
        // a probe and remove it, which changes state to answer a question.
        auto fd = sys::openat(AT_FDCWD, reg.c_str(), O_WRONLY | O_APPEND, 0);
        if (fd.failed()) {
            out.reason = "tracefs is mounted at " + root +
                         " but uprobe_events is not writable (errno " +
                         std::to_string(fd.error) +
                         "); function-level observation needs write access "
                         "to it and syscall-level observation does not";
            return false;
        }
        (void)sys::close(static_cast<int>(fd.value));
        out.available = true;
        out.reason.clear();
        return true;
    };

    if (!explicit_root.empty()) {
        if (inspect(explicit_root)) {
            return out;
        }
        // inspect left a reason describing the root that was named, which
        // is the useful one. It is returned as it stands rather than being
        // replaced by a message about the search that did not happen.
        if (out.reason.empty()) {
            out.reason = "the tracefs root named for this run, " +
                         explicit_root +
                         ", is not a tracefs: it has no events directory";
        }
        return out;
    }

    for (const char* candidate : kTracefsCandidates) {
        if (inspect(candidate)) {
            return out;
        }
        // A candidate that was found but unusable has already set a reason.
        // That reason is more specific than "nothing was mounted", so the
        // search stops with it rather than continuing and overwriting it
        // with the less informative message below.
        if (!out.reason.empty()) {
            return out;
        }
    }

    out.reason = "no tracefs is mounted at /sys/kernel/tracing or "
                 "/sys/kernel/debug/tracing, so the kernel's uprobe "
                 "interface cannot be reached; function-level observation "
                 "is not available and syscall-level observation continues";
    return out;
}

int Uprobes::read_event_id(const std::string& root, const std::string& event,
                           std::uint64_t& out) noexcept {
    // The id lives beside the event: events/<group>/<event>/id. The group is
    // the one the line named, which is "uprobes" for the interface written
    // here -- the kernel creates a group per probe system and a uprobe line
    // lands in the uprobes group.
    const std::string path = root + "/events/uprobes/" + event + "/id";
    const std::string text = read_small(path);
    if (text.empty()) {
        return sys::kEnoent;
    }
    const std::uint64_t id = parse_number(text);
    if (id == 0) {
        return sys::kEinval;
    }
    out = id;
    return 0;
}

int Uprobes::register_only(const std::string& name, const std::string& path,
                           std::uint64_t offset, ProbeKind kind,
                           std::size_t& out_index,
                           std::string& detail) noexcept {
    detail.clear();
    out_index = 0;

    // The root is resolved once and remembered. Resolving it per probe
    // would let a host that changed under the run produce the first probe
    // in one tracefs and the second in another, and the removal at the end
    // would then miss half of them.
    if (root_.empty()) {
        const ProbeAvailability avail = availability(explicit_root_);
        if (!avail.available) {
            detail = avail.reason;
            return sys::kEnotsup;
        }
        root_ = avail.tracefs_root;
    }

    // The event name has to be unique within the group. A counter is used
    // rather than a hash of the symbol, because two probes on the same
    // symbol at different offsets are a real thing and a name derived from
    // the symbol would collide.
    std::string event = "occ_";
    append_number(event, next_event_++);

    // The line. p is an entry probe and r a return probe; the two letters
    // are the kernel's, not this project's spelling of them.
    std::string line;
    line += (kind == ProbeKind::Return ? 'r' : 'p');
    line += ':';
    line += event;
    line += ' ';
    line += path;
    line += ':';
    // The offset is written in hexadecimal with a 0x prefix, which is how
    // the kernel's own documentation writes it and what a reader comparing
    // this line against readelf output expects. The kernel parses the field
    // with base 16, so a bare number is read as hexadecimal and a decimal
    // offset written without a prefix would be silently reinterpreted --
    // 4096 decimal read as 0x4096 is a probe at a byte nobody chose.
    line += "0x";
    append_hex_variable(line, offset);
    line += '\n';

    {
        const std::string reg = root_ + kUprobeEvents;
        const int err = write_all(reg, line);
        if (err != 0) {
            std::string off_hex = "0x";
            append_hex_variable(off_hex, offset);
            detail = "the kernel refused the probe on " + name + " at " +
                     path + " offset " + off_hex +
                     " (errno " + std::to_string(err) +
                     "); a probe needs a file offset that is inside the "
                     "file, and an address is not a file offset";
            return err;
        }
    }

    Uprobe p;
    p.name = name;
    p.event = event;
    p.path = path;
    p.offset = offset;
    p.kind = kind;

    {
        const int err = read_event_id(root_, event, p.id);
        if (err != 0) {
            // The kernel accepted the line and no usable id appeared. That
            // is the one case where the registration is half done, and
            // leaving the line behind would make the next attempt collide
            // with it.
            //
            // The two ways the id can fail are reported separately because
            // they have different causes. A missing file is the kernel
            // having refused the line after it was written; an unreadable
            // number is a file that is there and does not hold an id, and
            // zero is the value that reads as both "empty" and "the
            // software event group", which is a perf event that would open
            // and report nothing.
            const std::string rm = "-:" + event + "\n";
            (void)write_all(root_ + kUprobeEvents, rm);
            if (err == sys::kEinval) {
                detail = "the event the kernel created for the probe on " +
                         name + " has id 0, which is not a tracepoint id; "
                         "the id file is there and does not hold a number";
            } else {
                detail = "the probe on " + name + " was accepted but the "
                         "kernel created no event for it, so no id could be "
                         "read";
            }
            return err;
        }
    }

    // The probe is in the layer and not yet subscribed. This is the one
    // state that cannot be detected from the outside -- hits go to the
    // trace buffer and this layer never sees them -- which is why add
    // performs the subscription before returning and does not leave the
    // state reachable on its own.
    probes_.push_back(p);
    out_index = probes_.size() - 1;
    return 0;
}

int Uprobes::add(const std::string& name, const std::string& path,
                 std::uint64_t offset, ProbeKind kind,
                 std::string& detail) noexcept {
    std::size_t index = 0;
    const int reg = register_only(name, path, offset, kind, index, detail);
    if (reg != 0) {
        return reg;
    }

    const int err = subscribe(index, detail);
    if (err != 0) {
        // subscribe fills detail; the registration is removed here so the
        // caller sees a failure and a clean object. The tracefs event is
        // removed by name and the entry is dropped, in that order, because
        // dropping it first would lose the name the removal needs.
        //
        // The event name is read before the pop: pop_back invalidates the
        // reference the name would be taken from.
        const std::string event = probes_[index].event;
        const std::string rm = "-:" + event + "\n";
        (void)write_all(root_ + kUprobeEvents, rm);
        probes_.pop_back();
        return err;
    }
    return 0;
}

int Uprobes::subscribe(std::size_t index, std::string& detail) noexcept {
    if (index >= probes_.size()) {
        detail = "no such probe";
        return sys::kEinval;
    }
    Uprobe& p = probes_[index];
    if (p.fd >= 0) {
        // Already subscribed. Idempotent because a caller that re-enables
        // a probe should not have to track which ones it already did.
        return 0;
    }

    struct perf_event_attr attr;
    std::memset(&attr, 0, sizeof(attr));
    // The subscription is a tracepoint subscription: the tracefs line
    // created a dynamic event, and the event id is what a tracepoint perf
    // event counts. There is no PERF_TYPE_UPROBE type in the kernel's ABI;
    // the two-step form above is the interface, and a reader who expects a
    // single call will look for a type that does not exist.
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.size = sizeof(attr);
    attr.config = p.id;
    // While the ring is being set up. The event is enabled explicitly below
    // once the ring is mapped, so a hit cannot land in memory that is not
    // there yet -- a hit into an unmapped ring is a lost event, and a lost
    // event in a call count is a wrong number.
    attr.disabled = 1;
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    // The fields the record carries. The raw sample is the trace entry: it
    // holds the register set the kernel saved at the probe, which is where
    // the argument registers come from. ip and pid are asked for
    // separately because a trace entry's own header does not carry them and
    // without them a hit cannot be attributed to a thread.
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_RAW;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    // pid 0 with cpu -1 asks for every process. That is deliberate: a
    // uprobe on a shared library is attached once and fires for whichever
    // process maps it, and the ntdll case is exactly that -- Wine loads one
    // ntdll and every PE the session starts shares it. Restricting to one
    // pid would observe the first process and miss the children, which is
    // where a sample runs.
    auto r = sys::perf_event_open(&attr, 0, -1, -1, 0);
    if (r.failed()) {
        if (r.error == sys::kEacces || r.error == sys::kEperm) {
            detail = "perf_event_open refused the subscription to the " +
                     p.name + " probe; the perf_event_paranoid setting or a "
                     "security policy is blocking it, and function-level "
                     "observation needs it while syscall-level observation "
                     "does not";
        } else {
            detail = "perf_event_open refused the subscription to the " +
                     p.name + " probe (errno " + std::to_string(r.error) + ")";
        }
        return r.error;
    }
    const int fd = static_cast<int>(r.value);

    const std::size_t ps = page_size();
    const std::size_t ring_bytes = kRingPages * ps;
    auto mm = sys::mmap(nullptr, ring_bytes, PROT_READ | PROT_WRITE,
                        MAP_SHARED, fd, 0);
    if (mm.failed()) {
        (void)sys::close(fd);
        detail = "the probe's ring buffer could not be mapped";
        return mm.error;
    }
    void* ring =
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(mm.value));

    auto en = sys::ioctl(fd, PERF_EVENT_IOC_ENABLE, nullptr);
    if (en.failed()) {
        (void)sys::munmap(ring, ring_bytes);
        (void)sys::close(fd);
        detail = "the probe could not be enabled";
        return en.error;
    }

    p.fd = fd;
    p.ring = ring;
    p.ring_bytes = ring_bytes;
    p.ring_data_offset = ps;
    p.ring_tail = 0;
    return 0;
}

void Uprobes::release(Uprobe& p) noexcept {
    if (p.ring != nullptr) {
        (void)sys::munmap(p.ring, p.ring_bytes);
        p.ring = nullptr;
        p.ring_bytes = 0;
    }
    if (p.fd >= 0) {
        (void)sys::close(p.fd);
        p.fd = -1;
    }
}

void Uprobes::clear() noexcept {
    // The descriptors are closed and the rings unmapped first, then the
    // tracefs events are removed by name in one write, then the vector is
    // emptied. The order matters: the removal needs the names, and the
    // names live in the vector.
    for (auto& p : probes_) {
        release(p);
    }
    if (!root_.empty() && !probes_.empty()) {
        std::string all;
        all.reserve(probes_.size() * 8);
        for (const auto& p : probes_) {
            all += "-:";
            all += p.event;
            all += '\n';
        }
        (void)write_all(root_ + kUprobeEvents, all);
    }
    // Emptied unconditionally, and outside any branch that a previous
    // condition could have skipped.
    //
    // Each line above is "-:<event>", which is the kernel's syntax for
    // removing the event it created under that name. Removing by the
    // original line would not work: the file matches the group and event
    // name, and a removal that writes back a p: line reports nothing and
    // leaves the event attached -- so the next session's probe on the same
    // symbol collides with one that is still there.
    probes_.clear();
}

Uprobes::~Uprobes() { clear(); }

std::vector<int> Uprobes::fds() const noexcept {
    std::vector<int> out;
    out.reserve(probes_.size());
    for (const auto& p : probes_) {
        if (p.fd >= 0) {
            out.push_back(p.fd);
        }
    }
    return out;
}

std::size_t Uprobes::read_hits(std::vector<UprobeHit>& out) noexcept {
    const std::size_t before = out.size();

    for (auto& p : probes_) {
        if (p.ring == nullptr || p.ring_data_offset == 0) {
            continue;
        }

        const std::size_t head =
            static_cast<std::size_t>(ring_load(p.ring, kRingDataHeadByte));
        const std::size_t data_bytes = p.ring_bytes - p.ring_data_offset;

        if (head < p.ring_tail) {
            ring_store(p.ring, kRingDataTailByte,
                       static_cast<std::uint64_t>(head));
            p.ring_tail = head;
        }
        if (head > p.ring_tail + data_bytes) {
            // A head past the end of the ring is a foreign or corrupt
            // record. Recovering to the head is the only safe move; a
            // reader that trusted it would read unmapped memory.
            ring_store(p.ring, kRingDataTailByte,
                       static_cast<std::uint64_t>(head));
            p.ring_tail = head;
            continue;
        }

        const auto* base =
            static_cast<const std::uint8_t*>(p.ring) + p.ring_data_offset;

        while (p.ring_tail + sizeof(RingHeader) <= head) {
            RingHeader hdr{};
            std::memcpy(&hdr, base + p.ring_tail, sizeof(hdr));

            if (hdr.size < sizeof(RingHeader) ||
                p.ring_tail + hdr.size > head ||
                p.ring_tail + hdr.size >
                    p.ring_data_offset + data_bytes) {
                ring_store(p.ring, kRingDataTailByte,
                           static_cast<std::uint64_t>(head));
                p.ring_tail = head;
                break;
            }

            if (hdr.type == kPerfRecordLost) {
                // A lost record carries the count in the first eight bytes
                // after the header. The count is added rather than the
                // record being dropped silently: a call count that is short
                // by an unknown amount is a wrong answer, and the only way
                // to say so is to say how much is missing.
                if (hdr.size >= sizeof(RingHeader) + 8) {
                    std::uint64_t lost = 0;
                    std::memcpy(&lost, base + p.ring_tail + sizeof(RingHeader),
                                8);
                    lost_hits_ += lost;
                }
            } else if (hdr.type == kPerfRecordSample) {
                // The sample layout is the requested fields in bit order:
                // ip (8), tid (8: pid then tid as two u32), then the raw
                // trace entry (u32 size, then the bytes).
                std::size_t at = p.ring_tail + sizeof(RingHeader);
                const std::size_t end = p.ring_tail + hdr.size;

                if (at + 8 + 8 + 4 <= end) {
                    UprobeHit hit;
                    std::memcpy(&hit.ip, base + at, 8);
                    at += 8;
                    std::uint32_t pid32 = 0;
                    std::uint32_t tid32 = 0;
                    std::memcpy(&pid32, base + at, 4);
                    std::memcpy(&tid32, base + at + 4, 4);
                    at += 8;
                    hit.pid = static_cast<int>(pid32);
                    hit.tid = static_cast<int>(tid32);
                    // The hit is attributed to the probe whose ring it came
                    // from, which is the identity the per-probe ring
                    // exists to preserve. The name is not decoded out of
                    // the record because the record does not carry it --
                    // the kernel knows the id, and the id is the probe.
                    hit.name = p.name;
                    out.push_back(hit);
                }
            }

            p.ring_tail += hdr.size;
        }

        // The tail is published after the records above were consumed. The
        // store is a release, which is what keeps a producer that sees the
        // new tail from overwriting a record this loop has read but not
        // yet finished with.
        ring_store(p.ring, kRingDataTailByte,
                   static_cast<std::uint64_t>(p.ring_tail));
    }

    return out.size() - before;
}

} // namespace occ::obs

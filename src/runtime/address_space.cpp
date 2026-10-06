#include "occ/runtime/address_space.h"

#include <algorithm>

namespace occ::runtime {

namespace {

// Builds a region from the fields a caller supplies.
//
// Factored out so that record() and record_batch() cannot disagree about
// what a region is. The executable flag in particular is a rule about the
// protection enumeration, and a second copy of it in the batch path is
// exactly the kind of duplication that goes stale in one place.
//
// The window check is not here; it belongs to the caller because record()
// reports it before anything else and record_batch() needs it per
// candidate.
[[nodiscard]] Region make_region(std::uint64_t base, std::uint64_t size,
                                 PageProtection protection, RegionKind kind,
                                 std::string section,
                                 std::uint32_t section_index) {
    Region r;
    r.base = base;
    r.size = size;
    r.protection = protection;
    r.initial_protection = protection;
    r.kind = kind;
    r.section = std::move(section);
    r.section_index = section_index;
    // Whether the region is executable, decided by enumeration and not by a
    // bit test.
    //
    // The page protections are an enumeration whose values happen to be
    // powers of two, which makes a mask look right and be wrong. PAGE_EXECUTE
    // is 0x10 and PAGE_EXECUTE_READ is 0x20, so neither shares a bit with
    // the other; PAGE_READWRITE is 0x04, so a mask that included 0x04 would
    // mark every writable region executable. The question is "is this value
    // one of the executable protections", and that is what it is asked as.
    switch (protection_base(protection)) {
    case 0x10: // PAGE_EXECUTE
    case 0x20: // PAGE_EXECUTE_READ
    case 0x40: // PAGE_EXECUTE_READWRITE
    case 0x80: // PAGE_EXECUTE_WRITECOPY
        r.executable = true;
        break;
    default:
        r.executable = false;
        break;
    }
    return r;
}

// The window and zero-size rules, shared by record() and record_batch().
// Returns Success when the region may be recorded at all, and the status to
// report otherwise.
[[nodiscard]] Status check_region_extent(std::uint64_t base,
                                         std::uint64_t size) noexcept {
    if (size == 0) {
        return Status::InvalidParameter;
    }
    // The window check is a subtraction, not an addition.
    //
    // "base + size > kUserMax" is the obvious form and it is wrong: both
    // operands come from a program, their sum wraps, and a wrapped sum
    // compares as small. The subtraction form cannot wrap for the inputs
    // that reach it because the first check has already excluded a base
    // above the maximum.
    if (base < AddressSpace::kUserMin || base > AddressSpace::kUserMax ||
        size > AddressSpace::kUserMax - base) {
        return Status::InvalidAddress;
    }
    return Status::Success;
}

} // namespace

const char* protection_name(PageProtection p) noexcept {
    switch (static_cast<std::uint32_t>(p)) {
    case 0x01: return "PAGE_NOACCESS";
    case 0x02: return "PAGE_READONLY";
    case 0x04: return "PAGE_READWRITE";
    case 0x08: return "PAGE_WRITECOPY";
    case 0x10: return "PAGE_EXECUTE";
    case 0x20: return "PAGE_EXECUTE_READ";
    case 0x40: return "PAGE_EXECUTE_READWRITE";
    case 0x80: return "PAGE_EXECUTE_WRITECOPY";
    default: break;
    }
    // The modifier bits and any combination of them. Named rather than
    // numbered because a reader of an event wants the word: 0x140 tells
    // nobody anything and PAGE_EXECUTE_READWRITE|PAGE_GUARD tells them
    // what the page does. The static buffer is safe here because this is
    // called from the event writer, which formats and consumes the string
    // before the next call.
    static thread_local char buf[64];
    std::uint32_t v = static_cast<std::uint32_t>(p);
    const char* base = "PAGE_?";
    switch (v & 0xffU) {
    case 0x01: base = "PAGE_NOACCESS"; break;
    case 0x02: base = "PAGE_READONLY"; break;
    case 0x04: base = "PAGE_READWRITE"; break;
    case 0x08: base = "PAGE_WRITECOPY"; break;
    case 0x10: base = "PAGE_EXECUTE"; break;
    case 0x20: base = "PAGE_EXECUTE_READ"; break;
    case 0x40: base = "PAGE_EXECUTE_READWRITE"; break;
    case 0x80: base = "PAGE_EXECUTE_WRITECOPY"; break;
    default: break;
    }
    std::size_t n = 0;
    for (const char* q = base; *q != '\0' && n + 1 < sizeof(buf); ++q) {
        buf[n++] = *q;
    }
    if ((v & 0x100U) != 0U && n + 8 < sizeof(buf)) {
        const char* g = "|GUARD";
        for (const char* q = g; *q != '\0'; ++q) {
            buf[n++] = *q;
        }
    }
    if ((v & 0x200U) != 0U && n + 9 < sizeof(buf)) {
        const char* c = "|NOCACHE";
        for (const char* q = c; *q != '\0'; ++q) {
            buf[n++] = *q;
        }
    }
    if ((v & 0x400U) != 0U && n + 13 < sizeof(buf)) {
        const char* w = "|WRITECOMBINE";
        for (const char* q = w; *q != '\0'; ++q) {
            buf[n++] = *q;
        }
    }
    buf[n] = '\0';
    return buf;
}

const char* region_kind_name(RegionKind k) noexcept {
    switch (k) {
    case RegionKind::Image: return "image";
    case RegionKind::Private: return "private";
    case RegionKind::Stack: return "stack";
    case RegionKind::Control: return "control";
    case RegionKind::Mapped: return "mapped";
    }
    return "?";
}

const char* status_name(Status s) noexcept {
    switch (s) {
    case Status::Success: return "STATUS_SUCCESS";
    case Status::InvalidParameter: return "STATUS_INVALID_PARAMETER";
    case Status::InvalidParameter1: return "STATUS_INVALID_PARAMETER_1";
    case Status::InvalidParameter2: return "STATUS_INVALID_PARAMETER_2";
    case Status::InvalidParameter3: return "STATUS_INVALID_PARAMETER_3";
    case Status::InvalidParameter4: return "STATUS_INVALID_PARAMETER_4";
    case Status::InvalidParameter5: return "STATUS_INVALID_PARAMETER_5";
    case Status::InvalidParameter6: return "STATUS_INVALID_PARAMETER_6";
    case Status::ConflictingAddresses: return "STATUS_CONFLICTING_ADDRESSES";
    case Status::NotCommitted: return "STATUS_NOT_COMMITTED";
    case Status::InvalidAddress: return "STATUS_INVALID_ADDRESS";
    case Status::SectionProtection: return "STATUS_SECTION_PROTECTION";
    case Status::NoMemory: return "STATUS_NO_MEMORY";
    // "COMMITMENT", not "COMMIT": the extra T is in Windows' own spelling
    // and in Wine's ntstatus.h, and a log line that spells it differently
    // from the header a reader is holding is a log line they have to check.
    case Status::CommitLimit: return "STATUS_COMMITMENT_LIMIT";
    case Status::NotImplemented: return "STATUS_NOT_IMPLEMENTED";
    case Status::AccessViolation: return "STATUS_ACCESS_VIOLATION";
    case Status::PartialCopy: return "STATUS_PARTIAL_COPY";
    case Status::InvalidInfoClass: return "STATUS_INVALID_INFO_CLASS";
    case Status::InfoLengthMismatch: return "STATUS_INFO_LENGTH_MISMATCH";
    case Status::InvalidHandle: return "STATUS_INVALID_HANDLE";
    case Status::AccessDenied: return "STATUS_ACCESS_DENIED";
    case Status::UnableToFreeVm: return "STATUS_UNABLE_TO_FREE_VM";
    case Status::FreeVmNotAtBase: return "STATUS_FREE_VM_NOT_AT_BASE";
    case Status::MemoryNotAllocated: return "STATUS_MEMORY_NOT_ALLOCATED";
    case Status::MappedAlignment: return "STATUS_MAPPED_ALIGNMENT";
    case Status::NotSameDevice: return "STATUS_NOT_SAME_DEVICE";
    case Status::SectionNotImage: return "STATUS_SECTION_NOT_IMAGE";
    case Status::NotMappedData: return "STATUS_NOT_MAPPED_DATA";
    }
    return "STATUS_UNKNOWN";
}

Result<std::uint64_t> AddressSpace::record(std::uint64_t base,
                                           std::uint64_t size,
                                           PageProtection protection,
                                           RegionKind kind,
                                           std::string section,
                                           std::uint32_t section_index) noexcept {
    Result<std::uint64_t> out;

    const Status extent = check_region_extent(base, size);
    if (!ok(extent)) {
        out.status = extent;
        return out;
    }

    // No alignment requirement. See the note on record() in the header: the
    // 64 KiB granularity is a rule of the allocator, Windows applies it by
    // rounding rather than by refusing, and a PE's sections are 4 KiB
    // aligned by the section alignment every real linker uses. Requiring
    // 64 KiB here would refuse the second section of every image, which is
    // how this was found.

    Region r = make_region(base, size, protection, kind, std::move(section),
                           section_index);

    // The sorted insert. lower_bound gives the first region at or after the
    // new base; the region before it is the only one that can overlap the
    // new region from below, and the one at it is the only one that can
    // overlap from above. Checking those two is sufficient because the
    // vector is ordered and non-overlapping by construction, which is the
    // invariant the insert is maintaining.
    const auto at = std::lower_bound(
        regions_.begin(), regions_.end(), base,
        [](const Region& reg, std::uint64_t b) { return reg.base < b; });

    if (at != regions_.end() && at->base < base + size) {
        out.status = Status::ConflictingAddresses;
        return out;
    }
    if (at != regions_.begin()) {
        const Region& prev = *(at - 1);
        if (prev.end() > base) {
            out.status = Status::ConflictingAddresses;
            return out;
        }
    }

    regions_.insert(at, std::move(r));
    ++allocation_count_;
    out.value = base;
    out.status = Status::Success;
    return out;
}

Result<std::uint64_t> AddressSpace::record_batch(
    const std::vector<Candidate>& batch) noexcept {
    Result<std::uint64_t> out;

    // Build the regions first. Every one of them has to be constructible --
    // a zero size or an address outside the window is refused here, before
    // anything is inserted -- and the constructed vector is what the overlap
    // checks below work against.
    std::vector<Region> built;
    built.reserve(batch.size());
    for (const Candidate& c : batch) {
        const Status extent = check_region_extent(c.base, c.size);
        if (!ok(extent)) {
            out.status = extent;
            return out;
        }
        built.push_back(make_region(c.base, c.size, c.protection, c.kind,
                                    c.section, c.section_index));
    }

    // Every candidate is checked against the existing map first, so that a
    // conflict with a region the caller had already mapped is reported even
    // when the candidates among themselves would be fine.
    for (const Region& r : built) {
        const auto at = std::lower_bound(
            regions_.begin(), regions_.end(), r.base,
            [](const Region& reg, std::uint64_t b) { return reg.base < b; });
        if (at != regions_.end() && at->base < r.end()) {
            out.status = Status::ConflictingAddresses;
            return out;
        }
        if (at != regions_.begin()) {
            const Region& prev = *(at - 1);
            if (prev.end() > r.base) {
                out.status = Status::ConflictingAddresses;
                return out;
            }
        }
    }

    // Then the candidates against each other. Sorting the starts makes the
    // check a single sweep: after the sort, a candidate overlaps an earlier
    // one if and only if the largest end seen so far reaches past its start.
    // An interval that reaches into a later start without being adjacent in
    // the sorted order is impossible, because the sweep carries the maximum
    // end forward rather than only the previous one.
    //
    // A copy of the starts is sorted rather than the input, so the caller's
    // order is not disturbed and the failure reported is still the first
    // candidate in the caller's order that could not be placed.
    if (built.size() > 1) {
        std::vector<std::uint64_t> starts;
        starts.reserve(built.size());
        for (const Region& r : built) {
            starts.push_back(r.base);
        }
        std::sort(starts.begin(), starts.end());

        std::uint64_t furthest_end = 0;
        bool have_furthest = false;
        for (const std::uint64_t start : starts) {
            if (have_furthest && furthest_end > start) {
                out.status = Status::ConflictingAddresses;
                return out;
            }
            // The end of the candidate at this start. A linear lookup rather
            // than a parallel sorted vector because the count is small -- an
            // image has at most a few dozen sections -- and the clear version
            // is worth more than the asymptotically better one here.
            for (const Region& r : built) {
                if (r.base == start) {
                    const std::uint64_t e = r.end();
                    if (!have_furthest || e > furthest_end) {
                        furthest_end = e;
                        have_furthest = true;
                    }
                    break;
                }
            }
        }
    }

    // Nothing above could fail, so the inserts cannot either. They are done
    // through the same sorted insert record() uses, one at a time, because
    // the regions are already known to be non-overlapping and the vector
    // therefore stays ordered and non-overlapping throughout.
    for (Region& r : built) {
        const std::uint64_t b = r.base;
        const auto at = std::lower_bound(
            regions_.begin(), regions_.end(), b,
            [](const Region& reg, std::uint64_t v) { return reg.base < v; });
        regions_.insert(at, std::move(r));
        ++allocation_count_;
    }

    out.value = built.size();
    out.status = Status::Success;
    return out;
}

Result<std::uint64_t> AddressSpace::remove(std::uint64_t base) noexcept {
    Result<std::uint64_t> out;

    // The search is the same one record() and find() use, so the region this
    // finds is a region those two would have found. A lower_bound on the base
    // rather than an upper_bound on an address, because the question here is
    // "which region starts exactly here" and an address search would find the
    // region containing a base that is in the middle of one.
    const auto at = std::lower_bound(
        regions_.begin(), regions_.end(), base,
        [](const Region& reg, std::uint64_t b) { return reg.base < b; });

    if (at == regions_.end() || at->base != base) {
        out.status = Status::InvalidAddress;
        return out;
    }

    // The size is read before the erase because the region is gone afterwards
    // and the result carries it. A caller that wants to know what it just
    // released cannot ask the map afterwards.
    out.value = at->size;
    regions_.erase(at);

    // The allocation count does not move. It counts allocations, and it is
    // the sequence number a replay hands out; a region being forgotten is not
    // an allocation, and a replay that skipped a number would hand two
    // different allocations the same address.
    out.status = Status::Success;
    return out;
}

Result<std::uint32_t> AddressSpace::set_protection(
    std::uint64_t base, PageProtection protection) noexcept {
    Result<std::uint32_t> out;

    const auto at = std::lower_bound(
        regions_.begin(), regions_.end(), base,
        [](const Region& reg, std::uint64_t b) { return reg.base < b; });

    if (at == regions_.end() || at->base != base) {
        out.status = Status::InvalidAddress;
        return out;
    }

    return set_protection_at(static_cast<std::size_t>(at - regions_.begin()),
                             protection);
}

Result<std::uint32_t> AddressSpace::set_protection_at(
    std::size_t index, PageProtection protection) noexcept {
    Result<std::uint32_t> out;

    if (index >= regions_.size()) {
        out.status = Status::InvalidAddress;
        return out;
    }
    Region* at = &regions_[index];

    at->protection = protection;
    // The executable flag is recomputed rather than set from the new
    // protection's bits at the call site, because it is an enumeration
    // question and make_region() is where the enumeration lives. Recomputing
    // it here by calling nothing would be a second copy of a switch that
    // already exists; so the region keeps the answer it was given and this
    // updates it through the same helper the constructor uses.
    //
    // Which means the helper has to be reachable from here, and it is
    // declared above in this file, so the call is a name rather than a
    // duplicate switch. This is the second reader of make_region's rule and
    // the reason it is a function.
    Region updated = make_region(at->base, at->size, protection, at->kind,
                                 at->section, at->section_index);
    updated.initial_protection = at->initial_protection;
    updated.protection_changes = at->protection_changes + 1;
    // **The commit state is carried over, and it has to be.** `make_region`
    // builds a region that is committed because that is what every newly
    // recorded region is; a protection change on a reserved range would
    // otherwise commit it, which is the opposite of what a program that
    // decommitted and then re-protected the range expects. A protection is not
    // a commit and the two are independent fields.
    updated.committed = at->committed;
    *at = std::move(updated);

    out.value = at->protection_changes;
    out.status = Status::Success;
    return out;
}

Result<std::size_t> AddressSpace::split(std::uint64_t base,
                                        std::uint64_t size) noexcept {
    Result<std::size_t> out;

    if (size == 0) {
        out.status = Status::InvalidParameter;
        return out;
    }

    // The region that must contain the whole range. `find()` returns the
    // region holding the first address; the range is rejected unless that same
    // region holds the last address too, so a cut that straddles two regions
    // is refused rather than applied to one of them. This is the same rule
    // `decommit()` applies, and it is here rather than at the call sites so
    // that a caller cannot decide to skip it.
    const Region* found = find(base);
    if (found == nullptr) {
        out.status = Status::MemoryNotAllocated;
        return out;
    }
    if (found->kind != RegionKind::Private) {
        out.status = Status::InvalidParameter;
        return out;
    }
    // `last` is the first address past the range. The range must end at or
    // before the region's end, and it is `end()` rather than `end() - 1`
    // because a range that fills the region exactly ends where the region
    // does.
    const std::uint64_t last = base + size;
    if (last > found->end()) {
        out.status = Status::MemoryNotAllocated;
        return out;
    }

    // The three-way cut. The pieces are built as values and inserted at once,
    // because the vector may reallocate and `found` is a pointer into it -- the
    // hazard the header warns about at `find()` is exactly this, and holding
    // `found` across an `insert` is what it forbids.
    const Region whole = *found;
    const auto at = std::lower_bound(
        regions_.begin(), regions_.end(), whole.base,
        [](const Region& reg, std::uint64_t b) { return reg.base < b; });

    std::vector<Region> pieces;
    pieces.reserve(3);

    // The head: everything before the range. It keeps every field, including
    // the commit state -- the cut says nothing about what this memory is.
    if (base > whole.base) {
        Region head = make_region(whole.base, base - whole.base,
                                  whole.protection, whole.kind, whole.section,
                                  whole.section_index);
        head.initial_protection = whole.initial_protection;
        head.protection_changes = whole.protection_changes;
        head.committed = whole.committed;
        pieces.push_back(std::move(head));
    }

    // The middle: the range itself. Everything is carried over unchanged; the
    // caller is the one that decides what, if anything, this piece becomes.
    // Its index in the rebuilt vector is the answer, because a pointer into a
    // vector about to be inserted into is exactly the dangling pointer the
    // header warns about.
    Region middle = make_region(base, size, whole.protection, whole.kind,
                                whole.section, whole.section_index);
    middle.initial_protection = whole.initial_protection;
    middle.protection_changes = whole.protection_changes;
    middle.committed = whole.committed;
    const std::size_t middle_index = pieces.size();
    pieces.push_back(std::move(middle));

    // The tail: everything after the range, likewise unchanged.
    if (whole.end() > last) {
        Region tail = make_region(last, whole.end() - last, whole.protection,
                                  whole.kind, whole.section,
                                  whole.section_index);
        tail.initial_protection = whole.initial_protection;
        tail.protection_changes = whole.protection_changes;
        tail.committed = whole.committed;
        pieces.push_back(std::move(tail));
    }

    // Nothing to rebuild when the range already *is* the whole region: the
    // pieces would reproduce the single region that is already there. The
    // index is still the answer, and it is the index of the region in the
    // vector that is already there -- *not* zero, which is what the pieces
    // vector would have said and which is a different region the moment the
    // range is not the first one in the ledger. Getting this wrong changes the
    // wrong region, and the change is invisible until a program touches memory
    // it never named.
    if (pieces.size() == 1) {
        out.value = static_cast<std::size_t>(at - regions_.begin());
        out.status = Status::Success;
        return out;
    }

    regions_.erase(at);
    const auto insert_at = std::lower_bound(
        regions_.begin(), regions_.end(), pieces.front().base,
        [](const Region& reg, std::uint64_t b) { return reg.base < b; });
    // **The index has to be taken before the insert invalidates the iterator,
    // and it is not `middle_index` on its own.** `middle_index` is the
    // position of the middle piece *within `pieces`*, and `pieces` is spliced
    // in at `insert_at` -- which is not the start of the ledger unless the cut
    // happened to be at the first region. Reporting `middle_index` alone
    // addresses the wrong region whenever the cut is not at the front, and the
    // symptom is a caller switching the commit flag on a region it never
    // named. This was a real bug: a decommit of the second half of a
    // reservation cleared the commit of the *first* half.
    const std::size_t ledger_index =
        static_cast<std::size_t>(insert_at - regions_.begin()) + middle_index;
    regions_.insert(insert_at, std::make_move_iterator(pieces.begin()),
                    std::make_move_iterator(pieces.end()));

    out.value = ledger_index;
    out.status = Status::Success;
    return out;
}

Result<std::uint64_t> AddressSpace::decommit(std::uint64_t base,
                                             std::uint64_t size) noexcept {
    Result<std::uint64_t> out;

    // The range is cut as Wine cuts it, and the two roundings are in
    // *opposite* directions -- which is the part a reader gets wrong.
    //
    //   first  `ROUND_SIZE(0, base)` in Wine, which is the base rounded *up*
    //          to a page boundary.
    //   last   `ROUND_ADDR(base + size)` in Wine, which is the base plus the
    //          size rounded *down* to a page boundary.
    //
    // It looks like an inconsistency and it is a deliberate one: a decommit
    // releases the whole pages it *covers*, and the caller's `size` has already
    // been widened by one page by `ROUND_SIZE` at the call site above. Taking
    // the first page up and the last page down is what keeps the range the
    // ledger records equal to the range the kernel is told about.
    //
    // **A range that rounds away to nothing is a success and not an error.**
    // When the two roundings meet -- a range entirely inside one page, or one
    // that ends exactly where it starts after rounding -- there are no whole
    // pages to release, and Wine answers SUCCESS having done nothing
    // (`decommit_pages` guards its own mmap with `host_start < host_end` and
    // returns SUCCESS either way). Refusing would make this runtime reject a
    // call Windows accepts, which is the direction of divergence nobody tests
    // for; reporting zero bytes is the honest answer and the one a caller can
    // check.
    if (size == 0) {
        out.status = Status::InvalidParameter;
        return out;
    }
    const std::uint64_t first = round_up(base, kPageSize);
    const std::uint64_t last = round_down(base + size, kPageSize);
    if (first >= last) {
        out.value = 0;
        out.status = Status::Success;
        return out;
    }
    const std::uint64_t want = last - first;

    // A decommit of a range that is already reserved is not an error, but it
    // also has nothing to do: the bytes are already where the caller wants
    // them. Answering success rather than a status is Windows' behaviour and
    // the reason a program may decommit twice. It is checked before the cut
    // because a cut would otherwise split the reserved region for no reason,
    // and the ledger would grow without the answer changing.
    if (const Region* before = find(first);
        before != nullptr && before->kind == RegionKind::Private &&
        before->end() >= last && !before->committed) {
        out.value = want;
        out.status = Status::Success;
        return out;
    }

    // The cut. `split()` checks the range is inside one private region and
    // refuses otherwise; the statuses it produces are the ones a decommit
    // reports, so they are passed through unchanged.
    const Result<std::size_t> cut = split(first, want);
    if (!cut.ok()) {
        out.status = cut.status;
        return out;
    }

    // The middle piece loses its commit and nothing else. Its protection is
    // kept -- a reservation does not change the protection a later commit
    // would restore, and Windows reports the old protection back through a
    // recommit. Held by `split()`'s index rather than by address, because the
    // cut may have rebuilt the vector.
    regions_[cut.value].committed = false;

    out.value = want;
    out.status = Status::Success;
    return out;
}

const Region* AddressSpace::find(std::uint64_t addr) const noexcept {
    // The same comparison as the insert's search, so a region that the
    // insert would have rejected as overlapping is a region this finds.
    const auto at = std::upper_bound(
        regions_.begin(), regions_.end(), addr,
        [](std::uint64_t a, const Region& reg) { return a < reg.base; });
    if (at == regions_.begin()) {
        return nullptr;
    }
    const Region& candidate = *(at - 1);
    return candidate.contains(addr) ? &candidate : nullptr;
}

Result<std::uint64_t> AddressSpace::commit(std::uint64_t base,
                                           std::uint64_t size) noexcept {
    Result<std::uint64_t> out;

    // The same outward rounding a decommit does, and for the same reason: a
    // page is the unit the kernel commits, so a range that starts or ends
    // inside a page takes the whole page. `first` and `last` are the range the
    // cut works on, and they are what the answer reports.
    if (size == 0) {
        out.status = Status::InvalidParameter;
        return out;
    }
    const std::uint64_t first = round_up(base, kPageSize);
    const std::uint64_t last = round_down(base + size, kPageSize);
    if (first >= last) {
        out.value = 0;
        out.status = Status::Success;
        return out;
    }
    const std::uint64_t want = last - first;

    // A commit of a range that is already committed is not an error, but it
    // also has nothing to do. Checked before the cut so the ledger does not
    // grow for an answer that does not change, which is the same early return
    // `decommit()` makes for the same shape.
    if (const Region* before = find(first);
        before != nullptr && before->kind == RegionKind::Private &&
        before->end() >= last && before->committed) {
        out.value = want;
        out.status = Status::Success;
        return out;
    }

    // The cut, shared with `decommit()`. Its refusals are this call's
    // refusals: no region, not private, or a range past the region's end.
    const Result<std::size_t> cut = split(first, want);
    if (!cut.ok()) {
        out.status = cut.status;
        return out;
    }

    // The middle piece gains its commit and nothing else. The protection is
    // untouched: a commit does not change the protection a decommit preserved,
    // and Windows reports that protection back through the caller's next
    // query. The change counter does not move either, for the same reason.
    regions_[cut.value].committed = true;

    out.value = want;
    out.status = Status::Success;
    return out;
}

std::uint64_t AddressSpace::bytes_of_kind(RegionKind k) const noexcept {
    std::uint64_t total = 0;
    for (const Region& r : regions_) {
        if (r.kind == k) {
            total += r.size;
        }
    }
    return total;
}

std::uint64_t AddressSpace::high_water() const noexcept {
    std::uint64_t top = 0;
    for (const Region& r : regions_) {
        const std::uint64_t e = r.end();
        if (e > top) {
            top = e;
        }
    }
    return top;
}

} // namespace occ::runtime

// The Nt* memory interface. See ntdll.h for what this layer is and why each
// rule in it is the rule it is.
//
// The implementation is read against Wine's
// `dlls/ntdll/unix/virtual.c`, and every validation rule below has a Wine
// line it comes from. Where Wine has a rule this runtime does not implement
// -- because it belongs to the wineserver, or because it needs a process
// object table that is M5 -- the difference is a refusal with a status that
// says which, and never a silent success.

#include "occ/runtime/ntdll.h"

#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

namespace occ::runtime {

namespace {

// The rounding Wine applies to a size that starts partway into a page.
//
// `(size + (addr & page_mask) + page_mask) & ~page_mask` -- from
// `virtual.c:189`, `ROUND_SIZE`. It is not `round_up(size)` and the
// difference is a whole page whenever the address is not page-aligned: the
// region a caller asked about has to be *covered*, and covering `[addr,
// addr+size)` means extending to the end of the page `addr+size` lands on,
// which is one page further than rounding `size` alone would reach.
//
// **The term added is `page_mask`, which is `page_size - 1`, and writing
// `page_size` there is a bug that hides at the boundary.** With `page_mask`
// the three cases come out right: an unaligned address extends to the end of
// the page it lands on, an aligned `size` stays put (`aligned + mask` rounds
// back down to `aligned`), and the two combined extend once. With `page_size`
// the last two each gain a page: a request that was already page-aligned --
// which is every request made by a program that read the alignment rules --
// covers one page more than the caller named, so a free or a protect reaches
// into memory the program did not ask about. The formula was written both ways
// in this file at different times and the comment above always said
// `page_mask`, which is how the wrong one survived reading.
//
// `AddressSpace::round_up` rounds a size. This rounds a *range*, and the
// difference is named rather than hidden inside an existing call because a
// caller that gets it wrong frees or protects one page more than the program
// asked for, which is the kind of error that appears as a corruption in a
// different function entirely.
[[nodiscard]] constexpr std::uint64_t round_size_from(std::uint64_t addr,
                                                      std::uint64_t size) noexcept {
    return (size + (addr & (AddressSpace::kPageSize - 1)) +
            (AddressSpace::kPageSize - 1)) &
           ~(AddressSpace::kPageSize - 1);
}

// `ROUND_ADDR` from `virtual.c:188`.
[[nodiscard]] constexpr std::uint64_t round_addr(std::uint64_t addr) noexcept {
    return AddressSpace::round_down(addr, AddressSpace::kPageSize);
}

// The zero_bits check, from `virtual.c:4581-4582`.
//
// The hole is the point: 22 through 31 are refused while 21 and 32 are
// accepted. It looks like an off-by-one and is not -- it is Windows' rule,
// copied by Wine, and a program that relies on `zero_bits == 21` working is
// a program that works on Windows. "Fixing" the hole here would make this
// runtime refuse something Windows accepts, which is a compatibility bug in
// the direction nobody tests for: the failure appears on occ, in a program
// that was never wrong.
[[nodiscard]] constexpr bool zero_bits_is_acceptable(
    std::uint32_t zero_bits) noexcept {
    if (zero_bits > 21 && zero_bits < 32) {
        return false;
    }
    // The second clause reads `zero_bits > 32 && zero_bits < granularity_mask`,
    // and `granularity_mask` is 0xFFFF -- so this is unreachable, since no
    // value is simultaneously above 32 and below 65535. It is copied rather
    // than dropped for the same reason the hole is: the sequence a program
    // walks has to be the sequence Windows walks, and removing a clause that
    // does nothing is safe today and wrong the day the constant's value
    // changes. The compile cannot catch that, so the comment says it out.
    if (zero_bits > 32 && zero_bits < AddressSpace::kGranularity) {
        return false;
    }
    return true;
}

// The `type` bits `NtAllocateVirtualMemory` accepts, from `virtual.c:4575`.
[[nodiscard]] constexpr bool allocation_type_is_known(std::uint32_t type) noexcept {
    constexpr std::uint32_t kMask = mem::kCommit | mem::kReserve |
                                    mem::kTopDown | mem::kWriteWatch |
                                    mem::kReset;
    return (type & ~kMask) == 0;
}

// The stricter mask `NtAllocateVirtualMemoryEx` uses, from `virtual.c:4714`.
[[nodiscard]] constexpr bool allocation_type_is_known_ex(std::uint32_t type) noexcept {
    constexpr std::uint32_t kMask = mem::kCommit | mem::kReserve |
                                    mem::kTopDown | mem::kWriteWatch |
                                    mem::kReset | mem::kReservePlaceholder |
                                    mem::kReplacePlaceholder;
    return (type & ~kMask) == 0;
}

// Fills a failure with a status and a sentence a person reading a log can use.
//
// The detail is not decoration. A status tells a program what to do next and
// a person reading a log nothing at all -- "STATUS_INVALID_PARAMETER" on its
// own says that one of five parameters was wrong. Wine's TRACE lines say
// which; this is the same information in a form that survives being written
// to a file nobody is watching.
template <typename T>
Result<T> refuse(Status status, std::string detail) noexcept {
    Result<T> out;
    out.status = status;
    out.detail = std::move(detail);
    return out;
}

// The check every Nt* function makes first.
//
// Two refusals and neither of them is `InvalidParameter`, because they are
// different problems. A null `space` means the caller has no address space to
// operate on at all, which is a programming error in the *runtime*; a
// nonzero `target_process` means the call is for another process, which is a
// capability this runtime does not have yet. Reporting either as a bad
// parameter would be a lie a program could act on -- it would retry with a
// different argument, and the argument is not the problem.
template <typename T>
Result<T> check_context(NtContext& ctx) noexcept {
    if (ctx.target_process != 0) {
        return refuse<T>(Status::NotImplemented,
                         "cross-process memory operations are not implemented: "
                         "the call names another process, and occ has no "
                         "process object table to resolve it through (Wine "
                         "marshals these to wineserver)");
    }
    if (ctx.space == nullptr) {
        return refuse<T>(Status::InvalidParameter,
                         "no address space: this runtime has no space to "
                         "operate on, which is a bug in the caller rather "
                         "than a bad argument to the program");
    }
    if (ctx.placement == nullptr) {
        return refuse<T>(Status::InvalidParameter,
                         "no mapper: an Nt* call that changes memory needs "
                         "one, because AddressSpace is a ledger and not the "
                         "memory itself");
    }
    return Result<T>{};
}

// The same, for the calls that only read. They need a space but not a mapper:
// `occ check` inspects a file with no memory to change.
template <typename T>
Result<T> check_context_reading(NtContext& ctx) noexcept {
    if (ctx.target_process != 0) {
        return refuse<T>(Status::NotImplemented,
                         "cross-process memory operations are not implemented: "
                         "the call names another process, and occ has no "
                         "process object table to resolve it through");
    }
    if (ctx.space == nullptr) {
        return refuse<T>(Status::InvalidParameter,
                         "no address space: this runtime has no space to "
                         "read from, which is a bug in the caller");
    }
    return Result<T>{};
}

// The bit for a protection, as Windows numbers them. `PAGE_EXECUTE_READWRITE`
// is `0x40` and not `0x20|0x40`: Windows has no protection equal to a
// combination of these, and a reader that ors two of them has misread the
// format. That warning is on `PageProtection` and this is the function that
// makes it true.
[[nodiscard]] bool protection_is_known(std::uint32_t protect) noexcept {
    switch (protect & 0xffU) {
    case 0x01: case 0x02: case 0x04: case 0x08:
    case 0x10: case 0x20: case 0x40: case 0x80:
        return true;
    default:
        return false;
    }
}

// Whether a protection's modifier bits are ones this runtime implements.
//
// `PAGE_GUARD` and `PAGE_NOCACHE` are in the constant because a program can
// pass them, and this returns false for both: Linux has no `mprotect` flag
// for either. Refusing is the point of the modifier bits being separate from
// the protections -- a caller that asked for a guard page and got ordinary
// read-write memory has a buffer overflow that does not fault.
[[nodiscard]] bool protection_modifiers_are_implementable(
    std::uint32_t protect) noexcept {
    constexpr std::uint32_t kKnown =
        static_cast<std::uint32_t>(PageProtection::Guard) |
        static_cast<std::uint32_t>(PageProtection::NoCache) |
        static_cast<std::uint32_t>(PageProtection::WriteCombine);
    const std::uint32_t modifiers = protect & 0xff00U;
    if ((modifiers & ~kKnown) != 0) {
        return false;
    }
    // PAGE_GUARD alone is refused rather than treated as its base protection.
    // A guard page that does not guard is the failure this whole check exists
    // to prevent, and `PageProtection`'s comment says so in more words.
    return (modifiers &
            static_cast<std::uint32_t>(PageProtection::Guard)) == 0;
}

// Every region in `[base, base+size)`, in address order.
//
// A range that covers part of a region reports that whole region, because
// neither this layer nor Wine's splits: `AddressSpace::remove()` requires a
// region's exact base for the same reason. Returns false when the range
// touches a region that is not in the space, which the callers turn into
// `MemoryNotAllocated`.
[[nodiscard]] bool regions_covering(AddressSpace& space, std::uint64_t base,
                                    std::uint64_t size,
                                    std::vector<const Region*>& out) noexcept {
    const std::uint64_t end = base + size;
    for (const Region& r : space.regions()) {
        if (r.end() <= base) {
            continue;
        }
        if (r.base >= end) {
            break;
        }
        out.push_back(&r);
    }
    return true;
}

// How far the free run at `base` reaches.
//
// The answer to "how much of this address space is free from here", and the
// number a program walking unallocated addresses adds to `base` to get to the
// next thing it can look at. Wine computes it from a red-black tree walk that
// tracks the previous view's end and the next view's base
// (`virtual.c:4952-4971`), and the result is `next_base - base`.
//
// Here the regions are one sorted vector, so the same answer is the next
// region's base, or the window's top when there is none. That last case is
// Wine's `alloc_end = working_set_limit` initial value: a free address near
// the top of the space reports a run that ends at the window's top rather
// than at zero, so a program stepping by `RegionSize` terminates instead of
// running off the end and coming back.
[[nodiscard]] std::uint64_t next_region_after(const AddressSpace& space,
                                              std::uint64_t base) noexcept {
    for (const Region& r : space.regions()) {
        if (r.base > base) {
            return r.base - base;
        }
    }
    if (base >= AddressSpace::kUserMax) {
        return 0;
    }
    return AddressSpace::kUserMax - base;
}

// Whether this process can write `size` bytes at `addr`.
//
// Wine checks its caller's buffer with `virtual_check_buffer_for_write`
// (`virtual.c:5889`), which walks the range and asks the kernel. The
// equivalent here is the kernel's own answer to the same question, which is
// what `msync` on a read-only range would refuse -- but that is a syscall and
// this is on the path of every read.
//
// The check is `mincore`, which reports whether each page is resident, and
// resident is not the same as writable: a read-only file-backed page is
// resident. So the check here is a deliberate narrowing rather than a
// faithful reproduction, and the narrowing is in the safe direction: a range
// this says is writable is writable, and a range it refuses may be writable.
// The consequence is that a program reading into a buffer that happens to be
// read-only gets ACCESS_VIOLATION from this call, which Windows would also
// give it -- so the narrowing does not produce a wrong answer for the case
// that matters, only for a case the kernel already handles.
//
// A zero-size range is readable and writable whatever its address, and
// `mincore` is not called for one: `virtual_check_buffer_for_write` returns
// true for it (`virtual.c` reads `size` first), and a program that reads zero
// bytes through a bad pointer has not done anything wrong.
[[nodiscard]] bool address_is_writable(const void* addr,
                                       std::uint64_t size) noexcept {
    if (size == 0) {
        return true;
    }
    const auto base = reinterpret_cast<std::uintptr_t>(addr);
    if (base % AddressSpace::kPageSize != 0) {
        // An unaligned start. `mincore` requires a page-aligned address, and
        // the kernel refuses it -- so the range is checked from the page below
        // instead, which can only make this stricter.
        return address_is_writable(
            reinterpret_cast<const void*>(base & ~(AddressSpace::kPageSize - 1)),
            size + (base & (AddressSpace::kPageSize - 1)));
    }
    const std::size_t pages =
        static_cast<std::size_t>((size + AddressSpace::kPageSize - 1) /
                                 AddressSpace::kPageSize);
    std::vector<unsigned char> vec(pages);
    if (::mincore(const_cast<void*>(addr), pages * AddressSpace::kPageSize,
                  vec.data()) != 0) {
        return false;
    }
    for (std::size_t i = 0; i < pages; ++i) {
        // bit 0 of the vector byte is "resident", bit 1 is "referenced",
        // bit 2 is "modified", bit 3 is "swapped out on disk". A page that is
        // not resident cannot be written by this process without faulting,
        // so it fails the check.
        if ((vec[i] & 0x1) == 0) {
            return false;
        }
    }
    return true;
}

// Whether this process can read `size` bytes at `addr`. The same kernel
// question as above, and the same narrowing: a resident page is readable.
[[nodiscard]] bool address_is_readable(const void* addr,
                                       std::uint64_t size) noexcept {
    return address_is_writable(addr, size);
}

// Whether every byte of `[base, base + size)` is inside some region the ledger
// knows about.
//
// The ledger rather than `mincore`, and deliberately so. `mincore` answers
// "is this page resident", which is a question about the page cache and not
// about the process's address space: a file-backed page is resident, a
// PROT_NONE page is not but *is* mapped, and a page that is mapped and not
// resident answers the wrong way in both directions. What the read and write
// paths need to know is narrower and it is the question Windows answers --
// "did every byte of this range come from the target process" -- and the
// ledger is the only thing here that can answer it.
//
// The walk is by region rather than by page, and it is O(regions) rather than
// O(pages): a range is either inside one region or spans several, and the
// number of regions it spans is bounded by the number of regions, so there is
// no reason to look at a page boundary the ledger already knows the answer
// across.
//
// A zero size is mapped whatever the address, for the reason
// `address_is_writable` gives: a program that copies zero bytes through a
// bad pointer has not done anything wrong, and Wine's own size check is
// reached before its buffer check.
[[nodiscard]] bool range_is_mapped(const AddressSpace& space,
                                   std::uint64_t base,
                                   std::uint64_t size) noexcept {
    if (size == 0) {
        return true;
    }
    std::uint64_t at = base;
    std::uint64_t left = size;
    while (left != 0) {
        const Region* r = space.find(at);
        if (r == nullptr) {
            return false;
        }
        // The region ends at or before `at` only if the ledger is inconsistent,
        // and the check is here because a `left` that does not shrink is an
        // infinite loop rather than a wrong answer.
        if (r->end() <= at) {
            return false;
        }
        const std::uint64_t here = r->end() - at;
        if (here >= left) {
            return true;
        }
        at += here;
        left -= here;
    }
    return true;
}

} // namespace

// ------------------------------------------------------------------------
// Handles
// ------------------------------------------------------------------------

// The cookie, from the table's own address.
//
// Mixed rather than used raw, so that a cookie is never a small number and a
// handle is never a plausible pointer. The mixing is a multiply-shift-xor
// rather than a hash: it does not need to be collision-resistant against an
// adversary, because its job is only to make two *existing* tables' index
// spaces disjoint, and the address of a live table is already unique. What it
// does need is for the low bit of a handle to be predictable, because a handle
// with its low bit clear is a null pointer with an index in it and every
// `if (handle)` a program writes would be a test that passes for an invalid
// handle.
//
// The low bit is forced to one in `insert`, not here, so that the property
// belongs to the handle rather than to the cookie -- two tables with different
// addresses mix to cookies that differ in their low bits, and a handle built
// from one of them must still be odd.
std::uint64_t handle_cookie_for(const void* table) noexcept {
    const auto a = reinterpret_cast<std::uintptr_t>(table);
    // A 64-bit odd multiplier: the golden ratio, so that consecutive addresses
    // -- which is what a stack of tables gives -- produce cookies whose low
    // bits differ rather than sharing them.
    std::uint64_t h = a * 0x9E3779B97F4A7C15ULL;
    h ^= h >> 29;
    h *= 0xBF58476D1CE4E5B9ULL;
    h ^= h >> 32;
    // Never zero. A zero cookie with a zero index is a handle of zero, and zero
    // is the one value every caller already treats as "no handle" -- so a table
    // that produced one would hand out a handle that reads as absent.
    return h == 0 ? 0x9E3779B97F4A7C15ULL : h;
}

HandleParts handle_parts(Handle handle) noexcept {
    return HandleParts{handle >> 32, handle & 0xFFFFFFFFULL};
}

HandleTable::HandleTable() noexcept
    : cookie_(handle_cookie_for(this)) {}

Handle HandleTable::insert(HandleEntry entry) noexcept {
    entry.open = true;

    // A closed slot is reused before a new one is added, which is Wine's rule
    // (`free_tls_slot` reuses for the same reason: a handle table that never
    // reuses grows without bound and a long-running program closes millions).
    //
    // The consequence -- an old handle number now naming a new object -- is
    // Windows' behaviour too, and it is why `HandleEntry::open` exists. The
    // slot's *number* is reused and the old number then resolves to whatever
    // is in the slot now. Windows has no generation counter here either, so
    // this matches rather than diverges; a program that stores a handle past
    // its Close has the same bug on both.
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (!entries_[i].open) {
            entries_[i] = entry;
            ++open_count_;
            return make_handle(i);
        }
    }
    entries_.push_back(entry);
    ++open_count_;
    return make_handle(entries_.size() - 1);
}

Handle HandleTable::make_handle(std::size_t index) const noexcept {
    // The index **shifted left by one** in the low half, with the low bit
    // forced to one. The shift is the whole point and getting it wrong is a
    // silent one: masking the low bit instead -- `index & ~1` -- maps both slot
    // 0 and slot 1 to the same handle, so the first two handles a program opens
    // are the same number and closing either closes both. The two slots are
    // distinct and the handle has to say so, so the index gets a bit of its
    // own to shift into.
    //
    // The index is bounded to 31 bits by the shift rather than by a mask on the
    // way in: a table with more than two billion slots cannot be addressed, and
    // a slot that would need the 32nd bit is one this scheme cannot name. That
    // is far past any real process -- the table is one `HandleEntry` per open
    // handle, so two billion handles is more memory than the address space --
    // and it is written as a shift because a shift cannot silently alias two
    // slots the way the mask did.
    return ((cookie_ & 0xFFFFFFFFULL) << 32) |
           ((static_cast<std::uint64_t>(index) << 1) & 0xFFFFFFFFULL) | 1ULL;
}

HandleEntry* HandleTable::find(Handle handle) noexcept {
    if (handle == 0) {
        return nullptr;
    }
    // Both halves, in this order, and each check answers for **one** half.
    //
    // The cookie first because it is the only check that can reject a handle
    // from *another* table. An index alone is in range here often enough to
    // matter -- two tables in one address space is the normal case for the
    // observer and the fuzz harness, and both have several -- and indexing with
    // a stranger's index returns a real entry of this table for a handle that
    // names a real entry of another one. That is the plausible wrong answer,
    // and it is worse than a crash because nothing notices.
    const HandleParts parts = handle_parts(handle);
    if (parts.cookie != (cookie_ & 0xFFFFFFFFULL)) {
        return nullptr;
    }
    // The index is the low half shifted back down by the bit the low half
    // spends on being odd. The shift is the inverse of make_handle's, and the
    // two are written as inverses of each other on purpose: a find that decoded
    // the index any other way would resolve a handle to the wrong slot, which
    // is the one answer this whole scheme exists not to give.
    const std::size_t index = static_cast<std::size_t>(parts.index >> 1);
    if (index >= entries_.size()) {
        return nullptr;
    }
    // **The low half only.** This is the round trip, and it has to be a round
    // trip on `parts.index` alone -- reconstructing the whole handle here and
    // comparing all 64 bits would compare a second cookie check, because
    // `make_handle` mixes *this table's* cookie into its high half. That is not
    // harmless redundancy: it makes the check above unobservable. A mutant that
    // deletes the cookie comparison survives a suite in which the round trip
    // still refuses every foreign handle, and a test that cannot see a check
    // removed is not evidence the check was there. It is the same lesson the
    // flush path gave, one layer down -- an observation that cannot distinguish
    // two implementations is not an observation of either.
    //
    // So the invariant split is: the high half is the cookie's to answer for,
    // the low half is this one's, and neither check covers the other's half.
    // What the round trip is for is the pair of facts the shift hides -- that
    // the oddness bit is set, and that the index was not truncated on the way
    // in. A handle with an even low half is a forgery (or a table built wrong),
    // and a program makes one by adding one to a handle, which lands on a
    // neighbouring slot that is in range and belongs to a different object.
    //
    // It is written through `make_handle` rather than by hand-shifting again,
    // and the mask is what keeps that safe: the comparison is against the low
    // half, so the cookie half of the reconstruction is discarded rather than
    // compared, and the constructor stays the single place the shift exists.
    if ((make_handle(index) & 0xFFFFFFFFULL) != parts.index) {
        return nullptr;
    }
    return entries_[index].open ? &entries_[index] : nullptr;
}

const HandleEntry* HandleTable::find(Handle handle) const noexcept {
    return const_cast<HandleTable*>(this)->find(handle);
}

Status HandleTable::close(Handle handle) noexcept {
    HandleEntry* entry = find(handle);
    if (entry == nullptr) {
        // Counted rather than merely refused, because a caller that closes a
        // handle twice has one of two problems and they want different
        // responses: a program that hits this once has a bug, and a program
        // that hits it in a loop is attacking the table. The status is the
        // same either way -- Windows has one -- so the number is where the
        // difference lives.
        //
        // A *stale* handle (its slot reused) counts here too, and cannot be
        // told apart from one that was never valid. That is not this type's
        // limitation to fix; it is what reusing slots means.
        ++double_closes_;
        return Status::InvalidHandle;
    }
    entry->open = false;
    --open_count_;
    return Status::Success;
}

std::uint32_t HandleTable::open_count() const noexcept {
    return open_count_;
}

std::vector<Handle> HandleTable::open_handles() const noexcept {
    std::vector<Handle> out;
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].open) {
            out.push_back(make_handle(i));
        }
    }
    return out;
}

// ------------------------------------------------------------------------
// NtAllocateVirtualMemory
// ------------------------------------------------------------------------

Result<std::uint64_t> nt_allocate_virtual_memory(NtContext& ctx,
                                                 std::uint64_t* addr,
                                                 std::uint64_t* size,
                                                 std::uint32_t zero_bits,
                                                 std::uint32_t type,
                                                 std::uint32_t protect) noexcept {
    // The parameter checks, in Wine's order, because the order decides which
    // status a program with two bad parameters sees. `virtual.c:4580-4586`.
    if (addr == nullptr || size == nullptr) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "NtAllocateVirtualMemory was given a null "
                                     "output pointer");
    }
    const std::uint64_t requested_size = *size;
    if (requested_size == 0) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "a zero-size allocation: Windows refuses "
                                     "this, and a runtime that rounded it up "
                                     "would hand back a region no program "
                                     "asked for");
    }
    if (!zero_bits_is_acceptable(zero_bits)) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter3,
            "zero_bits " + std::to_string(zero_bits) +
                " asks for addresses in a 22- to 31-bit window, which Windows "
                "does not allow; the window exists on 16-bit systems and the "
                "hole is in Windows' own range check");
    }
    if (!allocation_type_is_known(type)) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "allocation type " + std::to_string(type) +
                " has bits this runtime does not define; Windows' mask is "
                "COMMIT, RESERVE, TOP_DOWN, WRITE_WATCH and RESET");
    }
    if (!protection_is_known(protect)) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "protection " + std::to_string(protect) +
                " is not one of the eight PAGE_ values; they are powers of "
                "two that do not compose into a combined protection");
    }
    if (!protection_modifiers_are_implementable(protect)) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "PAGE_GUARD is not implemented: a guard page signals on first "
            "touch and Linux has no mprotect flag for one, so a caller that "
            "asked for it and got ordinary memory would have a buffer "
            "overflow that does not fault");
    }
    if (const Result<std::uint64_t> guard = check_context<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard;
    }

    // The size is rounded up to the allocation granularity, not to a page.
    // This is the alignment rule `AddressSpace`'s `record()` refers to when
    // it says alignment belongs to the allocator: the ledger accepts any
    // alignment so it can describe a loaded image, and the layer that hands
    // out addresses applies the 64 KiB rule once.
    const std::uint64_t want =
        AddressSpace::round_up(requested_size, AddressSpace::kGranularity);
    if (want < requested_size) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "the requested size rounds up past the end "
                                     "of the address space");
    }

    // `MEM_RESERVE` with no address asks the kernel. A requested address is
    // rounded *down* to the granularity rather than refused, which is
    // Windows' behaviour and the reason `record()` imposes no alignment: a
    // program that asks for 0x12345 gets 0x10000 and is told so, and a
    // program that asked for an address it wanted exactly would be told it
    // got a different one. Wine does the same at `virtual.c` inside
    // `allocate_virtual_memory`.
    //
    // **`zero_bits` is not checked against a requested address here, and that
    // is Wine's rule rather than an omission.** `virtual.c:4618-4623`:
    //
    //     if (!*ret) limit = get_zero_bits_limit( zero_bits );
    //     else        limit = 0;
    //
    // `zero_bits` is the half of the request that says *where to put it* and is
    // only consulted when the caller did not say where. A caller that passes
    // both an address and a window has said where, and Wine places it there
    // without a word about the window. An earlier version of this function
    // checked the two against each other and refused, which made every call
    // that passed an address with the default window fail -- and that is what
    // a program passing an address and nothing else does, so it was most
    // calls. NtMapViewOfSection *does* check them (`virtual.c:5450-5455`) and
    // the two functions disagree in Wine too; that asymmetry is transcribed
    // rather than smoothed over, because a program that works on Windows relies
    // on each function's own rule.
    std::uint64_t base = 0;
    const std::uint64_t window = zero_bits_limit(zero_bits);
    if (*addr != 0) {
        base = AddressSpace::granularity_round_down(*addr);
    }

    // The commit bit. `MEM_COMMIT` without `MEM_RESERVE` commits inside an
    // existing reservation, which is the one combination that needs a region
    // to already be there and is handled below rather than by the reserve
    // path.
    const bool want_reserve = (type & mem::kReserve) != 0;

    if (!want_reserve) {
        // Commit-only: inside a region that already exists.
        if (base == 0 || *addr == 0) {
            return refuse<std::uint64_t>(
                Status::InvalidParameter,
                "MEM_COMMIT without MEM_RESERVE and without an address has "
                "nothing to commit: Windows commits into an existing "
                "reservation and this runtime will not invent one");
        }
        const Region* r = ctx.space->find(base);
        if (r == nullptr) {
            return refuse<std::uint64_t>(
                Status::MemoryNotAllocated,
                "nothing is reserved at " + std::to_string(base) +
                    " to commit");
        }
        if (base != r->base || r->end() - base < want) {
            return refuse<std::uint64_t>(
                Status::InvalidParameter,
                "a commit-only request must cover a whole reservation from its "
                "base; " + std::to_string(base) + " does not");
        }
        // The ledger first, so that a reserved range is marked committed before
        // the kernel's protection change can fail -- and the protection change
        // then carries the flag over rather than clearing it (`set_protection`
        // keeps `committed`). A commit that the kernel then refused has moved
        // `committed` and nothing else, and the caller sees the failure either
        // way; an ordering the other way round would let a successful mprotect
        // on a range the ledger still called reserved be reachable.
        const Result<std::uint64_t> committed = ctx.space->commit(base);
        if (!committed.ok()) {
            return refuse<std::uint64_t>(
                committed.status,
                "the commit of the reservation at " + std::to_string(base) +
                    " could not be recorded");
        }
        const Result<std::uint32_t> changed =
            ctx.placement->protect(r->base,
                                  static_cast<PageProtection>(protect));
        if (!changed.ok()) {
            return refuse<std::uint64_t>(changed.status,
                                         "the kernel refused the protection "
                                         "change on the committed region");
        }
        *addr = base;
        *size = want;
        return Result<std::uint64_t>{base};
    }

    // Reserve. With no address, ask for a free one.
    //
    // A `zero_bits` window is honoured here, which is the half of the request
    // that means *where* rather than *how much*. A caller that asked for
    // memory below 2^32 and got memory above it has a pointer it cannot use in
    // a 32-bit address computation, so the window is a real constraint and not
    // a hint. Wine gets this by handing the limit to wineserver; this runtime
    // has no server and asks the mapper to place the region itself, which is
    // why `map_below` exists.
    //
    // A window of zero -- the default, and what every caller that passes an
    // address or does not care gets -- is `map()` with no ceiling rather than
    // `map_below(0, ...)`: zero is also the bottom of the user window, and a
    // ceiling of zero would be a request for memory that cannot exist.
    const Result<std::uint64_t> mapped =
        (base == 0 && window != 0)
            ? ctx.placement->map_below(window, want,
                                      static_cast<PageProtection>(protect),
                                      RegionKind::Private)
            : (base == 0 ? ctx.placement->map(
                               0, want, static_cast<PageProtection>(protect),
                               RegionKind::Private)
                         : ctx.placement->map(
                               base, want,
                               static_cast<PageProtection>(protect),
                               RegionKind::Private));
    if (!mapped.ok()) {
        return refuse<std::uint64_t>(mapped.status,
                                     "the reservation could not be recorded at " +
                                         std::to_string(mapped.value) +
                                         (ctx.placement->last_failure().error != 0
                                              ? std::string(": ") +
                                                    std::strerror(ctx.placement->last_failure().error)
                                              : std::string()));
    }
    base = mapped.value;

    // The outputs. Both are written on success and only on success, which is
    // the rule every Nt* here follows and the one a program depends on when it
    // retries: a failed call that wrote a partial address would send the
    // retry somewhere else.
    *addr = base;
    *size = want;
    return Result<std::uint64_t>{base};
}

// ------------------------------------------------------------------------
// NtAllocateVirtualMemoryEx
// ------------------------------------------------------------------------

Result<std::uint64_t> nt_allocate_virtual_memory_ex(
    NtContext& ctx, std::uint64_t* addr, std::uint64_t* size,
    std::uint32_t type, std::uint32_t protect,
    const MemExtendedParameter* parameters, std::uint32_t count) noexcept {
    // `get_extended_params`, from `virtual.c:4627-4708`. It runs *before*
    // everything else in the function, including the `type` check, which is
    // why a call with both a bad type and a bad parameter gets the parameter
    // error.
    if (count != 0 && parameters == nullptr) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "a parameter count of " +
                                         std::to_string(count) +
                                         " with no array");
    }

    const MemExtendedParameterAddressRequirements* requirements = nullptr;
    std::uint64_t limit_low = 0;
    std::uint64_t limit_high = 0;
    std::uint64_t alignment = 0;
    std::uint32_t seen = 0;

    for (std::uint32_t i = 0; i < count; ++i) {
        const std::uint32_t kind = parameters[i].type;
        if (kind >= 32) {
            return refuse<std::uint64_t>(
                Status::InvalidParameter,
                "extended parameter " + std::to_string(i) + " has type " +
                    std::to_string(kind) +
                    ", and there are 32 of them; a type past the end is a "
                    "caller reading uninitialised memory");
        }
        if ((seen & (1u << kind)) != 0) {
            return refuse<std::uint64_t>(
                Status::InvalidParameter,
                "extended parameter type " + std::to_string(kind) +
                    " appears twice, and one answer slot cannot hold two "
                    "answers; Windows refuses rather than letting the second "
                    "win");
        }
        seen |= 1u << kind;

        if (kind == kMemExtendedParameterAddressRequirements) {
            if (parameters[i].pointer == nullptr) {
                return refuse<std::uint64_t>(
                    Status::InvalidParameter,
                    "an address-requirements parameter with a null pointer");
            }
            requirements = static_cast<const MemExtendedParameterAddressRequirements*>(
                parameters[i].pointer);
            const std::uint64_t limit = AddressSpace::kUserMax;

            if (requirements->alignment != 0) {
                const std::uint64_t a = requirements->alignment;
                // Wine's test, from `virtual.c:4653`: a power of two, and at
                // least a granularity. An alignment below the granularity
                // asks for an address the allocator never hands out, so
                // satisfying it would mean breaking a different rule.
                if ((a & (a - 1)) != 0 ||
                    a - 1 < AddressSpace::kGranularity) {
                    return refuse<std::uint64_t>(
                        Status::InvalidParameter,
                        "an alignment of " + std::to_string(a) +
                            " is not a power of two, or is smaller than the "
                            "64 KiB allocation granularity");
                }
                alignment = a;
            }
            if (requirements->lowest_starting_address != 0) {
                const std::uint64_t low = requirements->lowest_starting_address;
                if (low >= limit ||
                    !AddressSpace::is_granular(low)) {
                    return refuse<std::uint64_t>(
                        Status::InvalidParameter,
                        "a lowest starting address of " + std::to_string(low) +
                            " is outside the address window or is not a "
                            "multiple of the allocation granularity");
                }
                limit_low = low;
            }
            if (requirements->highest_ending_address != 0) {
                const std::uint64_t high = requirements->highest_ending_address;
                // `virtual.c:4674`: `high + 1` page-aligned. The `+ 1` is
                // what makes `high` the *end* exclusive -- a caller passing
                // the last usable address plus one is saying "up to but not
                // including", and the test has to match that reading.
                if (high > limit || high <= limit_low ||
                    ((high + 1) & (AddressSpace::kPageSize - 1)) != 0) {
                    return refuse<std::uint64_t>(
                        Status::InvalidParameter,
                        "a highest ending address of " + std::to_string(high) +
                            " is outside the window, is below the lowest "
                            "starting address, or does not end on a page "
                            "boundary");
                }
                limit_high = high;
            }
        }
    }

    if (!allocation_type_is_known_ex(type)) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "allocation type " + std::to_string(type) +
                " has bits NtAllocateVirtualMemoryEx does not define; its "
                "mask adds RESERVE_PLACEHOLDER and REPLACE_PLACEHOLDER to "
                "the five the plain call allows");
    }
    if (addr == nullptr || size == nullptr) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "NtAllocateVirtualMemoryEx was given a "
                                     "null output pointer");
    }
    // `virtual.c:4731`: a requested address and a set of requirements are
    // mutually exclusive. The address names one place; the requirements ask
    // the runtime to search. Honouring both would mean choosing which wins,
    // and a runtime that quietly picked one is a runtime a program cannot
    // predict.
    if (*addr != 0 && (alignment != 0 || limit_low != 0 || limit_high != 0)) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "an address and address requirements were both given; the first "
            "names a place and the second asks to search for one, and Windows "
            "refuses rather than choosing between them");
    }
    if (*size == 0) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "a zero-size allocation");
    }

    // The window the requirements describe, and a search for a base inside
    // it. This is where `Ex` earns its name: the plain call places below the
    // window's top, this one places inside a range the caller named.
    const std::uint64_t want =
        AddressSpace::round_up(*size, AddressSpace::kGranularity);

    if (limit_high != 0 && want > limit_high - std::min(limit_high, limit_low)) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "the requested size does not fit between the lowest and highest "
            "addresses the caller named");
    }

    // The search. Stepping down by the granularity from the highest address
    // the requirements allow, which is the same policy the loader's
    // `choose_base_below` uses and for the same reason: the highest free
    // address is the one that leaves room below, and a top-down search is what
    // a caller asking for "at or above this" wants.
    std::uint64_t top = limit_high != 0 ? limit_high : AddressSpace::kUserMax;
    top = AddressSpace::granularity_round_down(top);

    // The attempt cap. 64 attempts at one granule each is 4 MiB of search,
    // which is not enough: under a sanitizer the ordinary image bases are
    // inside the runtime's own mappings, and a caller asking for memory at or
    // above `0x140000000` finds all 4 MiB of it occupied and gives up on a
    // machine with terabytes free. The loader hit exactly this and the fix was
    // to stop counting attempts and start measuring progress -- see
    // `Mapper::map_below`, which is the same search with the same reasoning --
    // so the number here is generous enough that real fragmentation does not
    // reach it: sixteen thousand granules is a gigabyte of descending search.
    constexpr std::uint64_t kAttempts = 16384;
    for (std::uint64_t attempt = 0; attempt < kAttempts; ++attempt) {
        if (top < AddressSpace::kUserMin + AddressSpace::kGranularity) {
            break;
        }
        std::uint64_t candidate = top;
        if (alignment != 0) {
            candidate = top & ~(alignment - 1);
        }
        if (candidate < limit_low) {
            break;
        }
        if (ctx.space->find(candidate) != nullptr) {
            if (top < AddressSpace::kGranularity) {
                break;
            }
            top -= AddressSpace::kGranularity;
            continue;
        }

        // The mapping goes through the mapper, which does the `mmap` and the
        // ledger entry as one step. An earlier version made a `MAP_FIXED_NOREPLACE`
        // mapping here to test the candidate and then handed the address it got
        // to `Mapper::map`, which mapped the same range a second time -- and
        // the second one always failed with EEXIST, because the first was still
        // there. The search therefore never placed anything and reported no
        // memory on a machine with a terabyte of it.
        //
        // The ledger lookup above is kept, and it is *not* the safety check: it
        // is a cheap skip so the loop does not spend a syscall on an address
        // this process already knows it owns. The check that decides is
        // `MAP_FIXED_NOREPLACE` inside the mapper, and it is the only one that
        // can be, because only the kernel knows what *anything* has mapped.
        const Result<std::uint64_t> mapped = ctx.placement->map(
            candidate, want, static_cast<PageProtection>(protect),
            RegionKind::Private);
        if (!mapped.ok()) {
            if (top < AddressSpace::kGranularity) {
                break;
            }
            top -= AddressSpace::kGranularity;
            continue;
        }
        *addr = mapped.value;
        *size = want;
        return Result<std::uint64_t>{mapped.value};
    }

    return refuse<std::uint64_t>(
        Status::NoMemory,
        "no free range of " + std::to_string(want) +
            " bytes in the window the caller named, after " +
            std::to_string(kAttempts) + " candidates");
}

// ------------------------------------------------------------------------
// NtFreeVirtualMemory
// ------------------------------------------------------------------------

Result<std::uint64_t> nt_free_virtual_memory(NtContext& ctx,
                                             std::uint64_t* addr,
                                             std::uint64_t* size,
                                             std::uint32_t type) noexcept {
    // Wine's checks at `virtual.c:4779-4801` are: a null `addr_ptr` is a
    // fault before anything else, and the *only* check before the
    // cross-process branch. Everything below runs after the parameters have
    // been corrected, which is why `*addr_ptr` is re-read after the rounding
    // rather than before.
    if (addr == nullptr || size == nullptr) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "NtFreeVirtualMemory was given a null "
                                     "output pointer");
    }
    if (const Result<std::uint64_t> guard = check_context<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard;
    }

    const std::uint64_t given_addr = *addr;
    const std::uint64_t given_size = *size;

    // `virtual.c:4805-4806`. The rounding is applied to the *outputs*, so a
    // size of zero stays zero -- and that zero is not a request to free
    // nothing, it is `MEM_RELEASE`'s way of saying "at the base". The
    // distinction is the whole reason this function is not the same code as
    // `nt_flush_virtual_memory`, where a zero size means "everything".
    std::uint64_t effective_size = given_size;
    if (effective_size != 0) {
        effective_size = round_size_from(given_addr, effective_size);
    }
    const std::uint64_t base = round_addr(given_addr);

    // `virtual.c:4811-4818`. A base of zero is refused, and Wine's comment
    // says why: a broken program passing a null pointer would otherwise
    // unmap the DOS area. It is refused here rather than treated as
    // "everything" because the alternative is unmapping the address space.
    if (base == 0) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "a null address: Windows refuses rather than releasing the whole "
            "address space, which is what a broken program passing null "
            "would otherwise get");
    }

    const Region* region = ctx.space->find(base);
    if (region == nullptr) {
        // `virtual.c:4820`: nothing at the address is MEMORY_NOT_ALLOCATED,
        // not INVALID_PARAMETER. A program that frees an address it never
        // allocated gets a different answer than one that frees an address it
        // allocated wrongly, and the two have different bugs.
        return refuse<std::uint64_t>(
            Status::MemoryNotAllocated,
            "nothing is mapped at " + std::to_string(base) +
                ", so there is nothing to free");
    }

    // `virtual.c:4821`: only a VirtualAlloc region can be freed with this
    // call. An image section or a mapped file is released by
    // NtUnmapViewOfSection, and letting this call do it would give a program
    // two ways to tear down the same thing with different bookkeeping.
    if (region->kind != RegionKind::Private) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            std::string("the region at ") + std::to_string(base) + " is a " +
                region_kind_name(region->kind) +
                " region, and this call releases only private memory; a mapped "
                "one is released by NtUnmapViewOfSection");
    }

    // `virtual.c:4822`: a zero size requires the region's own base. The
    // status is FREE_VM_NOT_AT_BASE rather than INVALID_PARAMETER because a
    // program that got it wrong has almost certainly tried to release a
    // sub-allocation, which is a different mistake from a malformed call.
    if (given_size == 0 && base != region->base) {
        return refuse<std::uint64_t>(
            Status::FreeVmNotAtBase,
            "a zero size asks for a release of a whole region, and " +
                std::to_string(base) + " is not the base of the region that "
                "holds it (" + std::to_string(region->base) + ")");
    }

    // `virtual.c:4823`: the range must fit. A caller asking to free more than
    // the region has is not asking to free a part of it.
    if (region->end() - base < effective_size) {
        return refuse<std::uint64_t>(
            Status::UnableToFreeVm,
            "the request covers " + std::to_string(effective_size) +
                " bytes from " + std::to_string(base) + " but the region has " +
                std::to_string(region->end() - base) +
                " left, and a release that does not fit is not a release of a "
                "part of it");
    }

    // **The type check, which Wine does not do.**
    //
    // Wine's chain of `else if`s above uses `size` and the region lookup and
    // never asks what `type` is; the `switch (type)` at `virtual.c:4825` is
    // reached with whatever the caller passed, and its `default:` arm is the
    // only thing that rejects an unknown type. So Wine *does* reject one --
    // at the end, after the size and range checks, with a status that says
    // nothing about which argument was wrong.
    //
    // This asks first, and answers `InvalidParameter4` when the fourth
    // parameter is not a free type. A program that passes
    // `MEM_DECOMMIT|MEM_TOP_DOWN` -- a type with no meaning for a free --
    // gets told which parameter and which bit, instead of being told that one
    // of five parameters was invalid after two other checks ran. Same status
    // as Wine's `default`, one function earlier, and a sentence instead of
    // nothing.
    //
    // The check is *before* the size and range checks on purpose: a caller
    // with a bad type *and* a bad size should be told about the type, because
    // the size may be a consequence of it. This is the opposite of Wine's
    // order and it is deliberate.
    switch (type) {
    case mem::kDecommit:
    case mem::kRelease:
    case mem::kRelease | mem::kPreservePlaceholder:
        break;
    case mem::kRelease | mem::kCoalescePlaceholders:
    case mem::kCoalescePlaceholders:
        // `virtual.c:4837-4839`: coalescing placeholders *without* releasing
        // is refused with the numbered fourth-parameter status, because the
        // operation is meaningful only alongside a release.
        return refuse<std::uint64_t>(
            Status::InvalidParameter4,
            "MEM_COALESCE_PLACEHOLDERS without MEM_RELEASE: coalescing "
            "placeholders is part of releasing, and on its own it names no "
            "operation");
    default:
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "free type " + std::to_string(type) +
                " is not one of MEM_DECOMMIT, MEM_RELEASE, "
                "MEM_RELEASE|MEM_PRESERVE_PLACEHOLDER or "
                "MEM_RELEASE|MEM_COALESCE_PLACEHOLDERS");
    }

    // **`MEM_DECOMMIT` is not a release, and the two go different ways here.**
    //
    // This is the correction of a real defect: every accepted type used to fall
    // through to one `unmap()`, so a program that decommitted the middle of a
    // reservation had the *whole* reservation taken away -- the addresses went
    // back to the system, a later `MEM_COMMIT` into the same range failed with
    // MEMORY_NOT_ALLOCATED, and a pointer the program had kept into the
    // reservation dangled. Nothing about the call said so; it returned success.
    //
    // The two operations differ in three ways, and each is load-bearing:
    //
    //   size    DECOMMIT takes a nonzero size and may be told any range inside
    //           the region; RELEASE requires a zero size and the region's base.
    //   extent  DECOMMIT frees no address space, so the cut is within the
    //           ledger's region and the region survives as reserved memory.
    //   kernel  DECOMMIT's pages must fault on the next touch, so the range is
    //           mprotected away rather than unmapped -- an `unmap()` would
    //           release the addresses, which is the bug being fixed.
    if ((type & mem::kDecommit) != 0 && (type & mem::kRelease) == 0) {
        if (given_size == 0) {
            return refuse<std::uint64_t>(
                Status::InvalidParameter,
                "MEM_DECOMMIT with a size of zero: there is no range to "
                "decommit, and a zero size means something only to "
                "MEM_RELEASE");
        }

        // The kernel first, so that a refused mprotect leaves the ledger
        // describing the memory as it still is. The order is the reverse of
        // `unmap()`'s -- there the kernel call's result is what the ledger is
        // told -- and it is chosen here because the ledger's cut and the
        // kernel's mprotect must cover the *same* range, which is the one the
        // kernel rounds outward. Asking the ledger first and the kernel second
        // could leave the ledger with a cut the kernel refused.
        const Result<std::uint64_t> protected_range =
            ctx.placement->protect_range(base, effective_size,
                                         PageProtection::NoAccess);
        if (!protected_range.ok()) {
            return refuse<std::uint64_t>(
                protected_range.status,
                "the kernel refused to decommit " +
                    std::to_string(effective_size) + " bytes at " +
                    std::to_string(base) + ": " +
                    std::strerror(ctx.placement->last_failure().error));
        }

        const Result<std::uint64_t> cut =
            ctx.space->decommit(base, effective_size);
        if (!cut.ok()) {
            return refuse<std::uint64_t>(
                cut.status,
                "the decommit of " + std::to_string(effective_size) +
                    " bytes at " + std::to_string(base) +
                    " could not be recorded: the range is not inside one "
                    "private region");
        }

        // `*addr` is written back as the rounded address the call acted on and
        // `*size` as the size Wine reports back. Wine's `ROUND_SIZE` widens a
        // size by a whole page -- `(size + (addr & mask) + mask) & ~mask` -- so
        // a page-aligned request for 64 KiB is reported as 68 KiB. That looks
        // like an off-by-one and is the format: the caller learns the range
        // that actually lost its commit, which is one page past what it named.
        // Reporting `effective_size` rather than the ledger's cut keeps this
        // function's answer identical to Wine's, which is what a program
        // comparing the two would rely on.
        *addr = base;
        *size = effective_size;
        return Result<std::uint64_t>{base};
    }

    // A release of a placeholder-only region keeps the reservation. Neither
    // placeholder kind is implemented here -- a placeholder is a reservation
    // that is not committed, and this ledger's regions are committed from the
    // moment they exist -- so the flag is accepted and has no effect, which is
    // named because an accepted-and-ignored flag is worse than a refused one.
    // The whole region goes either way, because `unmap()` takes a base.

    const std::uint64_t unmap_base = region->base;
    const std::uint64_t unmap_size = region->size;

    const Result<std::uint64_t> unmapped =
        ctx.placement->unmap(unmap_base);
    if (!unmapped.ok()) {
        return refuse<std::uint64_t>(unmapped.status,
                                     "the kernel refused to unmap " +
                                         std::to_string(unmap_base) + ": " +
                                         std::strerror(
                                             ctx.placement->last_failure().error));
    }

    // The outputs, on success only. `*addr_ptr` becomes the region's base
    // rather than the page-rounded request, because a release always frees a
    // whole region and a caller reading the address back should see what was
    // actually freed. `virtual.c:4797` does the same in its cross-process
    // path, from the server's answer.
    *addr = unmap_base;
    *size = unmap_size;
    return Result<std::uint64_t>{unmap_base};
}

// ------------------------------------------------------------------------
// NtProtectVirtualMemory
// ------------------------------------------------------------------------

Result<std::uint64_t> nt_protect_virtual_memory(NtContext& ctx,
                                                std::uint64_t* addr,
                                                std::uint64_t* size,
                                                std::uint32_t new_protect,
                                                std::uint32_t* old_protect) noexcept {
    // `virtual.c:4876-4877`. This is the one check that happens *before* the
    // parameters are corrected, and it is the reason a null `old_prot` is an
    // ACCESS_VIOLATION rather than an INVALID_PARAMETER: Windows cannot write
    // the answer, so the call cannot proceed, and ACCESS_VIOLATION is what a
    // program dereferencing null would have got. It is also the only Nt*
    // call in this file whose null-pointer status differs from its siblings',
    // and it is preserved rather than harmonised.
    if (old_protect == nullptr) {
        return refuse<std::uint64_t>(Status::AccessViolation,
                                     "no place to write the old protection: "
                                     "Windows cannot report the answer without "
                                     "it, and answers ACCESS_VIOLATION rather "
                                     "than a parameter error");
    }
    if (addr == nullptr || size == nullptr) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "NtProtectVirtualMemory was given a null "
                                     "address or size pointer");
    }
    if (const Result<std::uint64_t> guard = check_context<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard;
    }

    if (!protection_is_known(new_protect)) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "protection " + std::to_string(new_protect) +
                " is not one of the eight PAGE_ values");
    }
    if (!protection_modifiers_are_implementable(new_protect)) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "PAGE_GUARD is not implemented: a guard page signals on first "
            "touch and Linux has no mprotect flag for one, so honouring it by "
            "silently applying the base protection would give a caller a "
            "buffer overflow that does not fault");
    }

    const std::uint64_t given_addr = *addr;
    // **A size of zero means the one page the address is in, and that is a
    // clause rather than a consequence of the rounding.** Wine computes
    // `ROUND_SIZE(addr, 0)`, which is `(0 + (addr & mask) + mask) & ~mask` --
    // zero for a page-aligned address -- and then asks the kernel to protect
    // nothing, which is a success that changed nothing. Windows protects the
    // page the address falls in, and a program that passes zero is asking for
    // exactly that: "the page this address is in". Answering with a real
    // protection change matters because the caller's next move is usually to
    // write through the address it just asked about.
    //
    // The rule is written out rather than left to the macro because the macro
    // cannot express it: `ROUND_SIZE`'s whole job is to widen a size to cover
    // the pages the *range* touches, and a range of length zero touches none.
    const std::uint64_t effective_size =
        *size == 0 ? AddressSpace::kPageSize
                   : round_size_from(given_addr, *size);
    const std::uint64_t base = round_addr(given_addr);

    if (base == 0) {
        return refuse<std::uint64_t>(
            Status::InvalidAddress,
            "a null address: there is no region at address zero to protect");
    }

    const Region* region = ctx.space->find(base);
    if (region == nullptr) {
        // `virtual.c:4919`: no view at all is INVALID_PARAMETER in Wine. Note
        // that this differs from NtFreeVirtualMemory's MEMORY_NOT_ALLOCATED
        // for the same situation -- a free that finds nothing says "not
        // allocated" and a protect that finds nothing says "bad parameter".
        // The inconsistency is Wine's and is preserved; harmonising it would
        // break a program that branches on which one it got.
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "no region covers " + std::to_string(base) +
                ", so there is nothing to protect");
    }

    // The whole range must be inside this one region. Wine checks the size
    // fits (`virtual.c:4912`), and this type does not split regions -- which
    // is the same reason `Mapper::protect()` changes the whole region and
    // says so.
    if (region->end() - base < effective_size) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "the range extends past the region at " + std::to_string(base) +
                ", and this runtime does not split a region to protect part of "
                "it");
    }

    const std::uint32_t previous =
        static_cast<std::uint32_t>(region->protection);

    const Result<std::uint32_t> changed = ctx.placement->protect(
        region->base, static_cast<PageProtection>(new_protect));
    if (!changed.ok()) {
        return refuse<std::uint64_t>(changed.status,
                                     "the kernel refused the protection change: " +
                                         std::string(std::strerror(
                                             ctx.placement->last_failure().error)));
    }

    // The outputs, on success only -- including `*old_protect`, which the
    // null check above exists because this line would fault.
    *addr = base;
    *size = effective_size;
    *old_protect = previous;
    return Result<std::uint64_t>{base};
}

// ------------------------------------------------------------------------
// NtReadVirtualMemory and NtWriteVirtualMemory
// ------------------------------------------------------------------------

Result<std::uint64_t> nt_read_virtual_memory(NtContext& ctx,
                                             std::uint64_t addr,
                                             void* buffer,
                                             std::uint64_t size,
                                             std::uint64_t* bytes_read) noexcept {
    if (const Result<std::uint64_t> guard = check_context_reading<std::uint64_t>(ctx);
        !guard.ok()) {
        // `bytes_read` is written even on this failure path, which is Wine's
        // rule (`virtual.c:5905`, outside the branch): a program that reads
        // the count before checking the status gets 0 rather than whatever
        // was in its variable.
        if (bytes_read != nullptr) {
            *bytes_read = 0;
        }
        return guard;
    }

    // The destination is the caller's own memory and it has to be writable.
    // Wine tests it with `virtual_check_buffer_for_write` and answers
    // ACCESS_VIOLATION when it fails -- and *that* is the code, not
    // PARTIAL_COPY. See nt_write_virtual_memory for why the two directions
    // differ, because it is the least obvious thing in this file.
    if (buffer != nullptr && size != 0) {
        if (!address_is_writable(buffer, size)) {
            if (bytes_read != nullptr) {
                *bytes_read = 0;
            }
            return refuse<std::uint64_t>(
                Status::AccessViolation,
                "the destination buffer is not writable by this process, so "
                "there is nowhere to put " + std::to_string(size) +
                    " bytes; a read whose destination is unusable is an access "
                "violation, while the same mistake in a write is a partial "
                "copy");
        }
    }

    // The source is a range of this process's space, and **the whole range**
    // has to be there. Checking only the first address is what an earlier
    // version of this function did, together with an `addr != 0` guard around
    // even that -- so a read of address 0 skipped the check entirely and went
    // on to `memcpy` from a null pointer, which is a segfault inside the
    // runtime rather than a status the caller can handle. A memory API that
    // faults on a call the caller was entitled to make is a crash in the
    // emulator, not a refusal, and a program probing for a mapping by reading
    // it is the ordinary way that shows up.
    //
    // The status is `ACCESS_VIOLATION` rather than `INVALID_ADDRESS` because
    // that is what the range produces. Wine's answer comes from the far side of
    // a `pread` on the target's `/proc/pid/mem` (`server/procfs.c:130-149`):
    // a short read or a failed one sets `STATUS_ACCESS_VIOLATION` and returns
    // zero bytes. A range that runs off the end of a mapping is a short read
    // there, and this runtime has no server to ask, so the ledger answers the
    // same question directly and reports what the server would have reported.
    const std::uint64_t end = addr + size;
    if (size != 0 && end <= addr) {
        // Wrapped. The range runs off the top of the address space, so it
        // cannot be mapped, and the answer is the same one a short read gets.
        if (bytes_read != nullptr) {
            *bytes_read = 0;
        }
        return refuse<std::uint64_t>(
            Status::AccessViolation,
            "the range " + std::to_string(addr) + "+" + std::to_string(size) +
                " runs off the end of the address space");
    }
    if (size != 0 && !range_is_mapped(*ctx.space, addr, size)) {
        if (bytes_read != nullptr) {
            *bytes_read = 0;
        }
        return refuse<std::uint64_t>(
            Status::AccessViolation,
            "the range " + std::to_string(addr) + "+" + std::to_string(size) +
                " is not entirely mapped, so it cannot be read in one piece; "
                "Wine answers the same case with ACCESS_VIOLATION because its "
                "read of the target's memory comes back short");
    }

    if (buffer == nullptr || size == 0) {
        // A zero-byte read succeeds and copies nothing. `bytes_read` is 0,
        // which is the answer and not an omission: a program looping until
        // the count is zero would spin forever on a call that returned an
        // error instead.
        if (bytes_read != nullptr) {
            *bytes_read = 0;
        }
        return Result<std::uint64_t>{0};
    }

    std::memcpy(buffer, reinterpret_cast<const void*>(addr), size);
    if (bytes_read != nullptr) {
        *bytes_read = size;
    }
    return Result<std::uint64_t>{size};
}

Result<std::uint64_t> nt_write_virtual_memory(NtContext& ctx,
                                              std::uint64_t addr,
                                              const void* buffer,
                                              std::uint64_t size,
                                              std::uint64_t* bytes_written) noexcept {
    if (const Result<std::uint64_t> guard = check_context_reading<std::uint64_t>(ctx);
        !guard.ok()) {
        if (bytes_written != nullptr) {
            *bytes_written = 0;
        }
        return guard;
    }

    // **The source this time, and a different status.** Wine's
    // `virtual_check_buffer_for_read` fails into `STATUS_PARTIAL_COPY`
    // (`virtual.c:5932`) where the read's equivalent failure is
    // `STATUS_ACCESS_VIOLATION` (`virtual.c:5902`).
    //
    // The asymmetry is Windows', and the format is the reason: a write can be
    // partial in general -- some of the source readable, some not -- so the
    // status says so. A read either copies all of it or none of it, so it has
    // no partial case and uses a status about the violation itself. A runtime
    // that used one code for both would send a program that branches on this
    // down a path Windows never takes.
    if (buffer != nullptr && size != 0) {
        if (!address_is_readable(buffer, size)) {
            if (bytes_written != nullptr) {
                *bytes_written = 0;
            }
            return refuse<std::uint64_t>(
                Status::PartialCopy,
                "the source buffer is not readable by this process, so there "
                "is nothing to write from; a write whose source is unusable is "
                "a partial copy, while the same mistake in a read is an access "
                "violation");
        }
    }

    // The destination is a range of this process's space, and the **whole
    // range** has to be there. This is the same check nt_read_virtual_memory
    // makes on its source and for the same reason: writing to address 0 with
    // no check is a `memcpy` to a null pointer, which faults inside the
    // runtime rather than answering the caller. A program that probes for a
    // mapping by writing to it is unusual, and a program that writes through a
    // stale pointer is not -- the second one is what this catches.
    //
    // The status is `PARTIAL_COPY` and not `ACCESS_VIOLATION`, and the reason
    // is the format rather than the direction: Wine's write path fails into
    // PARTIAL_COPY for an unusable *source* buffer (`virtual.c:5932`), and the
    // far side of a `pwrite` that could not cover the range returns the same
    // (`server/procfs.c:153-171`). This is a copy that did not happen, and
    // PARTIAL_COPY is the status that says so. Using ACCESS_VIOLATION here
    // would be defensible and would be wrong in the one case a program can
    // observe: a program that retries a failed write on ACCESS_VIOLATION and
    // gives up on PARTIAL_COPY.
    const std::uint64_t end = addr + size;
    if (size != 0 && end <= addr) {
        if (bytes_written != nullptr) {
            *bytes_written = 0;
        }
        return refuse<std::uint64_t>(
            Status::PartialCopy,
            "the range " + std::to_string(addr) + "+" + std::to_string(size) +
                " runs off the end of the address space");
    }
    if (size != 0 && !range_is_mapped(*ctx.space, addr, size)) {
        if (bytes_written != nullptr) {
            *bytes_written = 0;
        }
        return refuse<std::uint64_t>(
            Status::PartialCopy,
            "the range " + std::to_string(addr) + "+" + std::to_string(size) +
                " is not entirely mapped, so it cannot be written in one "
                "piece; nothing was written and the count says so");
    }

    if (buffer == nullptr || size == 0) {
        if (bytes_written != nullptr) {
            *bytes_written = 0;
        }
        return Result<std::uint64_t>{0};
    }

    std::memcpy(reinterpret_cast<void*>(addr), buffer, size);
    if (bytes_written != nullptr) {
        *bytes_written = size;
    }
    return Result<std::uint64_t>{size};
}

// ------------------------------------------------------------------------
// NtClose
// ------------------------------------------------------------------------

Status nt_close(NtContext& ctx, HandleTable& table, Handle handle) noexcept {
    if (const Result<std::uint64_t> guard = check_context_reading<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard.status;
    }
    return table.close(handle);
}

// ------------------------------------------------------------------------
// NtQueryVirtualMemory
// ------------------------------------------------------------------------

namespace {

// The size of what `MemoryBasicInformation` fills, which is what a caller's
// `len` is checked against. It is `sizeof` the structure rather than a
// constant because the structure is what it is and the two cannot drift.
constexpr std::uint64_t kBasicInformationSize =
    sizeof(MemoryBasicInformation);

} // namespace

Result<std::uint64_t> nt_query_virtual_memory(NtContext& ctx,
                                              std::uint64_t addr,
                                              MemoryInformationClass info_class,
                                              void* buffer,
                                              std::uint64_t len,
                                              std::uint64_t* result_length) noexcept {
    if (const Result<std::uint64_t> guard = check_context_reading<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard;
    }

    // `get_basic_memory_info`, from `virtual.c:5054-5057`: the length is
    // checked against the structure *first*, before anything else, and it is
    // the buffer's length rather than the structure the caller expected to
    // get. A caller that allocated too little gets INFO_LENGTH_MISMATCH and
    // an untouched buffer, which is the difference between a bug the program
    // can find at the call and one it finds when the fields are wrong.
    if (info_class == MemoryInformationClass::BasicInformation &&
        len < kBasicInformationSize) {
        return refuse<std::uint64_t>(
            Status::InfoLengthMismatch,
            "the buffer is " + std::to_string(len) + " bytes and "
                "MEMORY_BASIC_INFORMATION is " +
                std::to_string(kBasicInformationSize) +
                "; the call is refused rather than partly filled");
    }

    if (buffer == nullptr) {
        // `virtual.c:5726` for NtQuerySection and the same shape here: a null
        // buffer where one is required is an access violation rather than a
        // parameter error, because the call cannot proceed at all.
        return refuse<std::uint64_t>(Status::AccessViolation,
                                     "no output buffer: there is nowhere to put "
                                     "the answer");
    }

    const std::uint64_t base = round_addr(addr);

    switch (info_class) {
    case MemoryInformationClass::BasicInformation: {
        const Region* region = ctx.space->find(addr);

        MemoryBasicInformation out;
        out.base_address = base;
        out.allocation_base = 0;
        out.allocation_protect = 0;
        out.protect = 0;
        out.region_size = 0;
        out.state = mem_state::kFree;
        out.type = 0;

        if (region != nullptr) {
            // Wine's `alloc_base` and `alloc_end` come from the tree walk at
            // `virtual.c:4952-4971`, and the two answers they produce are not
            // the same as this layer's. Wine's `AllocationBase` is the *end of
            // the previous view*, not the start of the one containing the
            // address, because Wine's views are separate objects with gaps
            // between them. This ledger merges adjacent allocations of the
            // same request, so the base here is the region's own base --
            // which is what a program asking "what allocation is this part of"
            // means.
            out.allocation_base = region->base;
            out.region_size = region->end() - base;
            out.state = mem_state::kCommit;
            out.protect =
                static_cast<std::uint32_t>(region->protection) & 0xffU;
            out.allocation_protect =
                static_cast<std::uint32_t>(region->initial_protection) & 0xffU;
            switch (region->kind) {
            case RegionKind::Image:
                out.type = mem_type::kImage;
                break;
            case RegionKind::Mapped:
                out.type = mem_type::kMapped;
                break;
            case RegionKind::Private:
                out.type = mem_type::kPrivate;
                break;
            default:
                out.type = mem_type::kPrivate;
                break;
            }
        } else {
            // A free address reports how far the free run goes, which is how
            // a program walks the address space. The bound is the next
            // region's base, or the window's top when there is none --
            // Wine's `alloc_end` starts at `working_set_limit` and narrows
            // (`virtual.c:4937`), and this is the same shape with the user
            // window's top in place of the working set limit.
            out.region_size = next_region_after(*ctx.space, base);
        }

        std::memcpy(buffer, &out, sizeof(out));
        if (result_length != nullptr) {
            *result_length = sizeof(out);
        }
        return Result<std::uint64_t>{sizeof(out)};
    }

    case MemoryInformationClass::RegionLedger: {
        const Region* region = ctx.space->find(addr);
        if (region == nullptr) {
            return refuse<std::uint64_t>(
                Status::InvalidAddress,
                "nothing is mapped at " + std::to_string(addr) +
                    ", so there is no ledger to report");
        }
        MemoryRegionLedger out;
        out.protection = region->protection;
        out.initial_protection = region->initial_protection;
        out.protection_changes = region->protection_changes;
        out.kind = region->kind;
        out.section_index = region->section_index;
        out.executable = region->executable;
        // The name, copied by hand rather than assigned. `out.section` is a
        // byte array, so assigning a `std::string` to it does not exist, and
        // `std::memcpy(out.section, name.data(), n)` is only correct if `n` is
        // bounded and the terminator is written -- the zero-initialised array
        // already provides the terminator for a short name, and a full one
        // would run past the end.
        {
            const std::string& name = region->section;
            const std::size_t n =
                name.size() < MemoryRegionLedger::kSectionNameCapacity - 1
                    ? name.size()
                    : MemoryRegionLedger::kSectionNameCapacity - 1;
            if (n != 0) {
                std::memcpy(out.section, name.data(), n);
            }
            out.section[n] = '\0';
            out.section_length = static_cast<std::uint32_t>(n);
        }

        if (len < sizeof(MemoryRegionLedger)) {
            return refuse<std::uint64_t>(
                Status::InfoLengthMismatch,
                "the buffer is " + std::to_string(len) + " bytes and the "
                "ledger entry is " + std::to_string(sizeof(out)));
        }
        std::memcpy(buffer, &out, sizeof(out));
        if (result_length != nullptr) {
            *result_length = sizeof(out);
        }
        return Result<std::uint64_t>{sizeof(out)};
    }

    case MemoryInformationClass::RegionHistory: {
        // The allocation sequence and the space's size. A program asking
        // "how many allocations has this process made" gets a number Wine
        // cannot produce, because Wine's regions live in a wineserver that
        // hands out addresses itself and keeps no per-process counter this
        // layer could read.
        struct History {
            std::uint64_t allocation_count;
            std::uint64_t region_count;
            std::uint64_t high_water;
            std::uint64_t base;
        };
        if (len < sizeof(History)) {
            return refuse<std::uint64_t>(
                Status::InfoLengthMismatch,
                "the buffer is " + std::to_string(len) +
                    " bytes and the history is " + std::to_string(sizeof(History)));
        }
        const History out{ctx.space->allocation_count(),
                          ctx.space->regions().size(),
                          ctx.space->high_water(),
                          ctx.space->find(addr) != nullptr
                              ? ctx.space->find(addr)->base
                              : 0};
        std::memcpy(buffer, &out, sizeof(out));
        if (result_length != nullptr) {
            *result_length = sizeof(out);
        }
        return Result<std::uint64_t>{sizeof(out)};
    }

    case MemoryInformationClass::UnixFunctions:
    case MemoryInformationClass::UnixFunctionsWow64: {
        // Wine leaves both as `FIXME` -- `virtual.c:5340` returns
        // `STATUS_INVALID_INFO_CLASS` from the `default:` arm, so a program
        // asking gets nothing. This answers.
        //
        // The answer is a `unixlib_handle_t`, which is a pointer-sized value
        // naming a table of native function pointers. This runtime has one:
        // the tables the loader and the runtime already own. The wow64 class
        // gets the same table, because this runtime does not translate x86
        // code and a program asking for 32-bit entry points is told the same
        // thing rather than being handed a table of stubs that would fault on
        // first use.
        if (len != sizeof(std::uint64_t)) {
            return refuse<std::uint64_t>(
                Status::InfoLengthMismatch,
                "a unixlib handle is a pointer and the buffer is " +
                    std::to_string(len) + " bytes; Wine requires the length to "
                    "be exactly one and so does this");
        }
        // The value written is the address of this runtime's own table of
        // Nt* entry points -- which is, concretely, the address of a function
        // that returns the address of the table. A program that stores it can
        // compare it against a later call, which is the use Wine's version
        // does not support.
        const std::uint64_t handle = reinterpret_cast<std::uint64_t>(
            &nt_query_virtual_memory);
        std::memcpy(buffer, &handle, sizeof(handle));
        if (result_length != nullptr) {
            *result_length = sizeof(handle);
        }
        return Result<std::uint64_t>{sizeof(handle)};
    }

    case MemoryInformationClass::WorkingSetExInformation:
    case MemoryInformationClass::MappedFilenameInformation:
    case MemoryInformationClass::RegionInformation:
    case MemoryInformationClass::ImageInformation:
        // Wine answers these by asking wineserver for data this layer does
        // not have. The two that could be answered from the ledger are:
        //
        //   RegionInformation -- the whole region, unsplit. Wine's own
        //   `MemoryBasicInformation` splits at the requested address; this
        //   class is the same question asked without the split.
        //
        //   ImageInformation -- whether a region is an image, and which. The
        //   ledger knows, because `Region` carries the section index and the
        //   section name.
        //
        // The other two need the working set and a file name, neither of
        // which exists here: the resident size is the kernel's and the name
        // would come from a file this layer does not open. They are refused
        // with their own status rather than answered with a zero, because a
        // program reading a zero resident size cannot tell "nothing resident"
        // from "this runtime does not know".
        if (info_class == MemoryInformationClass::RegionInformation) {
            const Region* region = ctx.space->find(addr);
            if (region == nullptr) {
                return refuse<std::uint64_t>(
                    Status::InvalidAddress,
                    "nothing is mapped at " + std::to_string(addr));
            }
            struct RegionInfo {
                std::uint64_t base;
                std::uint64_t size;
                std::uint32_t state;
                std::uint32_t protect;
                std::uint64_t allocation_base;
                std::uint32_t allocation_protect;
                std::uint32_t type;
                std::uint32_t section_index;
                std::uint32_t pad;
            };
            if (len < sizeof(RegionInfo)) {
                return refuse<std::uint64_t>(
                    Status::InfoLengthMismatch,
                    "the buffer is " + std::to_string(len) +
                        " bytes and the region info is " +
                        std::to_string(sizeof(RegionInfo)));
            }
            const RegionInfo out{region->base,
                                 region->size,
                                 mem_state::kCommit,
                                 static_cast<std::uint32_t>(region->protection) &
                                     0xffU,
                                 region->base,
                                 static_cast<std::uint32_t>(
                                     region->initial_protection) &
                                     0xffU,
                                 region->kind == RegionKind::Image
                                     ? mem_type::kImage
                                     : (region->kind == RegionKind::Mapped
                                            ? mem_type::kMapped
                                            : mem_type::kPrivate),
                                 region->section_index,
                                 0};
            std::memcpy(buffer, &out, sizeof(out));
            if (result_length != nullptr) {
                *result_length = sizeof(out);
            }
            return Result<std::uint64_t>{sizeof(out)};
        }

        if (info_class == MemoryInformationClass::ImageInformation) {
            const Region* region = ctx.space->find(addr);
            if (region == nullptr || region->kind != RegionKind::Image) {
                return refuse<std::uint64_t>(
                    Status::SectionNotImage,
                    "the region at " + std::to_string(addr) +
                        " is not part of an image, so it has no image "
                        "information");
            }
            struct ImageInfo {
                std::uint64_t base;
                std::uint64_t size;
                std::uint32_t section_index;
                std::uint32_t is_image;
            };
            if (len < sizeof(ImageInfo)) {
                return refuse<std::uint64_t>(
                    Status::InfoLengthMismatch,
                    "the buffer is " + std::to_string(len) +
                        " bytes and the image info is " +
                        std::to_string(sizeof(ImageInfo)));
            }
            const ImageInfo out{region->base, region->size,
                                region->section_index, 1};
            std::memcpy(buffer, &out, sizeof(out));
            if (result_length != nullptr) {
                *result_length = sizeof(out);
            }
            return Result<std::uint64_t>{sizeof(out)};
        }

        return refuse<std::uint64_t>(
            info_class == MemoryInformationClass::WorkingSetExInformation
                ? Status::NotImplemented
                : Status::NotImplemented,
            std::string("this class needs information occ does not have: the ") +
                "working set is the kernel's and the mapped filename would "
                "come from a file this layer does not open. Wine answers it "
                "by asking wineserver, which is the difference between the "
                "two implementations rather than a difference in the format");

    default:
        break;
    }

    return refuse<std::uint64_t>(
        Status::InvalidInfoClass,
        "information class " +
            std::to_string(static_cast<std::uint32_t>(info_class)) +
            " is not one this function answers; the six Wine defines and this "
            "runtime's own two are the whole list");
}

// ------------------------------------------------------------------------
// NtFlushVirtualMemory
// ------------------------------------------------------------------------

Result<std::uint64_t> nt_flush_virtual_memory(NtContext& ctx,
                                              std::uint64_t* addr,
                                              std::uint64_t* size) noexcept {
    if (addr == nullptr || size == nullptr) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "NtFlushVirtualMemory was given a null "
                                     "output pointer");
    }
    if (const Result<std::uint64_t> guard = check_context<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard;
    }

    const std::uint64_t base = round_addr(*addr);

    const Region* region = ctx.space->find(base);
    if (region == nullptr) {
        // `virtual.c:5791`: no view is INVALID_PARAMETER here, the same code
        // NtProtectVirtualMemory uses and different from NtFreeVirtualMemory's
        // MEMORY_NOT_ALLOCATED. Wine's inconsistency, preserved.
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "no region covers " + std::to_string(base) + ", so there is "
            "nothing to flush");
    }

    // **A zero size means the whole region** -- `virtual.c:5793`. The
    // opposite of what zero means in nt_free_virtual_memory, where it means
    // "at the base". Both are Wine's readings and a caller has to know which
    // function it called, so the difference is in the comment at both ends.
    const std::uint64_t effective_size =
        *size != 0 ? round_size_from(*addr, *size) : region->size;
    if (region->end() - base < effective_size) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "the range extends past the region at " + std::to_string(base));
    }

    if (::msync(reinterpret_cast<void*>(base), effective_size, MS_SYNC) != 0) {
        return refuse<std::uint64_t>(
            Status::NotMappedData,
            "the kernel refused to flush " + std::to_string(effective_size) +
                " bytes at " + std::to_string(base) + ": " +
                std::strerror(errno));
    }

    *addr = base;
    *size = effective_size;
    return Result<std::uint64_t>{effective_size};
}

// ------------------------------------------------------------------------
// NtGetWriteWatch and NtResetWriteWatch
// ------------------------------------------------------------------------

Result<std::uint64_t> nt_get_write_watch(NtContext& ctx,
                                         std::uint32_t flags,
                                         std::uint64_t base, std::uint64_t size,
                                         std::uint64_t* addresses,
                                         std::uint64_t* count,
                                         std::uint32_t* granularity) noexcept {
    // `virtual.c:5816-5819`. The order matters: `count` and `granularity` are
    // tested for null *before* their values are read, and `addresses` is
    // tested after the flags, so a call with a null `addresses` and a bad flag
    // gets the flag error. Every one of these is ACCESS_VIOLATION rather than
    // INVALID_PARAMETER, which is the same choice NtProtectVirtualMemory makes
    // for a null `old_prot` and different from what the size checks below do.
    if (count == nullptr || granularity == nullptr) {
        return refuse<std::uint64_t>(Status::AccessViolation,
                                     "no place to write the count or the "
                                     "granularity: the call cannot report what "
                                     "it found");
    }
    if (const Result<std::uint64_t> guard = check_context_reading<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard;
    }

    const std::uint64_t given_base = base;
    const std::uint64_t effective_size = round_size_from(given_base, size);
    const std::uint64_t rounded = round_addr(given_base);

    if (*count == 0 || effective_size == 0) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "a zero count or a zero size: there is no range to ask about and "
            "no room to answer in");
    }
    constexpr std::uint32_t kWriteWatchFlagReset = 1;
    if ((flags & ~kWriteWatchFlagReset) != 0) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "flags " + std::to_string(flags) +
                " have bits this call does not define; the only flag is "
                "WRITE_WATCH_FLAG_RESET");
    }
    if (addresses == nullptr) {
        return refuse<std::uint64_t>(Status::AccessViolation,
                                     "no output array: there is nowhere to put "
                                     "the addresses");
    }

    // Wine walks pages and tests a per-page flag (`virtual.c:5830-5841`), so
    // its answer is page-granular. This answers region-granular from the
    // ledger's own record, which is the one place here that is more precise
    // than Wine: the regions are the things the program asked for, and the
    // number it gets back is a number of regions rather than a number of
    // pages it has to divide.
    std::uint64_t found = 0;
    const std::uint64_t wanted = *count;
    const std::uint64_t end = rounded + effective_size;
    for (const Region& r : ctx.space->regions()) {
        if (r.end() <= rounded) {
            continue;
        }
        if (r.base >= end) {
            break;
        }
        if (found >= wanted) {
            break;
        }
        // The pages that are *not* under a write watch, which is what
        // NtGetWriteWatch answers: `virtual.c:5836` writes an address when
        // the page lacks VPROT_WRITEWATCH.
        if (r.kind != RegionKind::Private) {
            continue;
        }
        addresses[found++] = r.base;
    }

    *count = found;
    // Wine reports the page size as the granularity (`virtual.c:5839`) even
    // though it walked pages. This reports the *region* granularity, which is
    // the unit the answers are in -- and saying so matters, because a program
    // that divides a total size by this to work out how many answers to expect
    // would be wrong about Wine and right here, and the two runtimes do not
    // have to agree for a program to be portable, they only have to each be
    // self-consistent.
    *granularity = static_cast<std::uint32_t>(AddressSpace::kGranularity);
    return Result<std::uint64_t>{found};
}

Result<std::uint64_t> nt_reset_write_watch(NtContext& ctx,
                                           std::uint64_t base,
                                           std::uint64_t size) noexcept {
    if (const Result<std::uint64_t> guard = check_context_reading<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard;
    }

    const std::uint64_t effective_size = round_size_from(base, size);
    const std::uint64_t rounded = round_addr(base);

    // `virtual.c:5873`: a zero size is refused here. It is legal in
    // nt_flush_virtual_memory and illegal here, and the difference is not an
    // oversight -- "flush everything" has a meaning in one and not the other.
    if (effective_size == 0) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "a zero size: a reset has to name the "
                                     "pages to clear, and a zero size names "
                                     "none");
    }
    if (rounded == 0) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "a null address");
    }
    if (ctx.space->find(rounded) == nullptr) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "no region covers " + std::to_string(rounded) +
                ", so there is no write watch to reset");
    }
    // The reset itself has no observable effect on this ledger: a write watch
    // records *that* a page changed, and the ledger does not record that --
    // it records what was asked for and what protection resulted, which is the
    // question the observer asks and the only one a region answers. So the
    // call succeeds and changes nothing, which is honest: there was no watch
    // state to clear because there never was any. A program that relies on
    // the reset to stop it being told about changes is relying on a mechanism
    // that is not implemented, and the honest answer is a success rather than
    // a failure that would send it looking for one.
    return Result<std::uint64_t>{effective_size};
}

// ------------------------------------------------------------------------
// NtLockVirtualMemory and NtUnlockVirtualMemory
// ------------------------------------------------------------------------

Result<std::uint64_t> nt_lock_virtual_memory(NtContext& ctx,
                                            std::uint64_t* addr,
                                            std::uint64_t* size) noexcept {
    if (addr == nullptr || size == nullptr) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "NtLockVirtualMemory was given a null "
                                     "output pointer");
    }
    if (const Result<std::uint64_t> guard = check_context<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard;
    }

    // `virtual.c:5390-5391`. The rounding is written to the caller's own
    // variables before the syscall, and that is Wine's order: a successful
    // pin reports the range it actually pinned, which is the page-aligned
    // range rather than the one asked for.
    const std::uint64_t given_addr = *addr;
    *size = round_size_from(given_addr, *size);
    *addr = round_addr(given_addr);

    if (*size == 0) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "a zero size: there is nothing to pin");
    }

    // `virtual.c:5392`: a refusal is ACCESS_DENIED rather than a parameter
    // error, because the usual cause is `RLIMIT_MEMLOCK` and not an argument
    // the caller can fix. A program that raises its limit and retries gets a
    // different answer; one that changed the address gets the same one.
    if (::mlock(reinterpret_cast<void*>(*addr), *size) != 0) {
        return refuse<std::uint64_t>(
            Status::AccessDenied,
            "the kernel would not pin " + std::to_string(*size) +
                " bytes at " + std::to_string(*addr) + ": " +
                std::strerror(errno) +
                ". This is usually RLIMIT_MEMLOCK rather than a bad address");
    }

    return Result<std::uint64_t>{*addr};
}

Result<std::uint64_t> nt_unlock_virtual_memory(NtContext& ctx,
                                              std::uint64_t* addr,
                                              std::uint64_t* size) noexcept {
    if (addr == nullptr || size == nullptr) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "NtUnlockVirtualMemory was given a null "
                                     "output pointer");
    }
    if (const Result<std::uint64_t> guard = check_context<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard;
    }

    const std::uint64_t given_addr = *addr;
    *size = round_size_from(given_addr, *size);
    *addr = round_addr(given_addr);

    if (*size == 0) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "a zero size: there is nothing to unpin");
    }
    if (::munlock(reinterpret_cast<void*>(*addr), *size) != 0) {
        return refuse<std::uint64_t>(Status::AccessDenied,
                                     std::string("the kernel would not unpin ") +
                                         std::to_string(*size) + " bytes at " +
                                         std::to_string(*addr) + ": " +
                                         std::strerror(errno));
    }

    return Result<std::uint64_t>{*addr};
}

// ------------------------------------------------------------------------
// NtAreMappedFilesTheSame
// ------------------------------------------------------------------------

Status nt_are_mapped_files_the_same(NtContext& ctx, std::uint64_t addr1,
                                    std::uint64_t addr2) noexcept {
    if (const Result<std::uint64_t> guard = check_context_reading<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard.status;
    }

    const Region* first = ctx.space->find(addr1);
    const Region* second = ctx.space->find(addr2);

    // `virtual.c:5957-5958`. Either address unmapped is INVALID_ADDRESS.
    if (first == nullptr || second == nullptr) {
        return Status::InvalidAddress;
    }

    // **Anonymous memory is CONFLICTING_ADDRESSES, not success.**
    // `virtual.c:5959`: `is_view_valloc` on either side refuses, so two
    // addresses in *different* VirtualAlloc regions are
    // CONFLICTING_ADDRESSES even though neither is a file and neither
    // conflicts with anything. Wine's reason is that the question only has a
    // meaning for files, and a private region has no file to be the same as.
    //
    // Two addresses in the *same* private region do succeed, and that is not
    // an inconsistency: Wine's check is "is either a valloc view", and it
    // tests the views rather than the addresses, so one view reached twice
    // passes. The distinction is copied because it is the one a program
    // comparing two pointers from one allocation depends on.
    if (first->kind == RegionKind::Private ||
        second->kind == RegionKind::Private) {
        if (first == second) {
            return Status::Success;
        }
        return Status::ConflictingAddresses;
    }

    if (first == second) {
        return Status::Success;
    }

    // Two different views. Wine asks the server whether they share a file and
    // answers NOT_SAME_DEVICE when one is `VPROT_SYSTEM`. This ledger has no
    // file identity to compare -- a region is a region, not a view of
    // something -- so the strongest claim available is the same-view one
    // above, and two different regions get NOT_SAME_DEVICE.
    //
    // That is the same code Wine gives for two different devices, and it is
    // the honest answer here for the same reason: two regions that this
    // runtime cannot prove are the same file are not the same file. The
    // difference is that Wine can sometimes prove it and this cannot, which
    // makes this answer *more often* NOT_SAME_DEVICE than Wine's would be.
    // It is named here rather than left to be discovered, because a program
    // that maps one file twice and asks this would get NOT_SAME_DEVICE from
    // occ and SUCCESS from Wine, and the file identity this layer lacks is
    // where M3's NtCreateFile will put it.
    return Status::NotSameDevice;
}

// ------------------------------------------------------------------------
// NtSetInformationVirtualMemory
// ------------------------------------------------------------------------

Result<std::uint64_t> nt_set_information_virtual_memory(
    NtContext& ctx, VirtualMemoryInformationClass info_class,
    std::uint64_t count, const MemoryRangeEntry* addresses, const void* ptr,
    std::uint32_t size) noexcept {
    if (const Result<std::uint64_t> guard = check_context<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard;
    }

    switch (info_class) {
    case VirtualMemoryInformationClass::PrefetchInformation: {
        // The checks, in Wine's order: `virtual.c:6027-6029`. The numbered
        // statuses are not decoration -- a program that passes no pointer, a
        // wrong size and no count has three bugs, and telling it which one is
        // at fault is the difference between one edit and three.
        if (ptr == nullptr) {
            return refuse<std::uint64_t>(Status::InvalidParameter5,
                                         "no flags pointer: the prefetch "
                                         "class takes an argument and it is "
                                         "missing");
        }
        if (size != sizeof(std::uint32_t)) {
            return refuse<std::uint64_t>(Status::InvalidParameter6,
                                         "the flags field is " +
                                             std::to_string(size) +
                                             " bytes and a ULONG is " +
                                             std::to_string(sizeof(std::uint32_t)));
        }
        if (count == 0) {
            return refuse<std::uint64_t>(Status::InvalidParameter3,
                                         "no ranges: a prefetch of nothing");
        }
        if (addresses == nullptr) {
            return refuse<std::uint64_t>(Status::InvalidParameter4,
                                         "a range count of " +
                                             std::to_string(count) +
                                             " with no array");
        }
        // `prefetch_memory`, from `virtual.c:5986-5988`: every range's size is
        // checked *before* any of them is prefetched, so a call with three
        // good ranges and one empty one prefetches nothing rather than two.
        for (std::uint64_t i = 0; i < count; ++i) {
            if (addresses[i].number_of_bytes == 0) {
                return refuse<std::uint64_t>(
                    Status::InvalidParameter4,
                    "range " + std::to_string(i) +
                        " has a size of zero; nothing is prefetched for a range "
                        "that names no bytes");
            }
        }

        for (std::uint64_t i = 0; i < count; ++i) {
            const std::uint64_t base =
                round_addr(addresses[i].virtual_address);
            const std::uint64_t range =
                round_size_from(addresses[i].virtual_address,
                                addresses[i].number_of_bytes);
            // `virtual.c:5996`: `madvise` with `MADV_WILLNEED`, whose failure
            // is ignored -- Wine does not check the return, and this does not
            // either, because a prefetch that did not happen is not a failure
            // the program can do anything about.
            (void)::madvise(reinterpret_cast<void*>(base), range, MADV_WILLNEED);
        }
        return Result<std::uint64_t>{count};
    }

    case VirtualMemoryInformationClass::RegionQueryInformation: {
        // occ's own. Which regions a set of ranges covers, with no change to
        // anything -- the read-only counterpart of every other call here, and
        // what a tool wants before deciding to rewrite a region.
        if (count == 0) {
            return refuse<std::uint64_t>(Status::InvalidParameter3,
                                         "no ranges to query");
        }
        if (addresses == nullptr) {
            return refuse<std::uint64_t>(Status::InvalidParameter4,
                                         "a range count with no array");
        }
        std::uint64_t regions_named = 0;
        for (std::uint64_t i = 0; i < count; ++i) {
            if (addresses[i].number_of_bytes == 0) {
                return refuse<std::uint64_t>(
                    Status::InvalidParameter4,
                    "range " + std::to_string(i) + " has a size of zero");
            }
            std::vector<const Region*> covered;
            if (!regions_covering(*ctx.space, addresses[i].virtual_address,
                                  addresses[i].number_of_bytes, covered)) {
                return refuse<std::uint64_t>(
                    Status::InvalidAddress,
                    "range " + std::to_string(i) + " at " +
                        std::to_string(addresses[i].virtual_address) +
                        " is not covered by any region");
            }
            regions_named += covered.size();
        }
        return Result<std::uint64_t>{regions_named};
    }

    default:
        break;
    }

    // `virtual.c:6032`: an unknown class is INVALID_PARAMETER_2 here, where
    // NtQueryVirtualMemory uses INVALID_INFO_CLASS. Two query functions with
    // two answers for the same mistake, and both are Wine's.
    return refuse<std::uint64_t>(
        Status::InvalidParameter2,
        "information class " +
            std::to_string(static_cast<std::uint32_t>(info_class)) +
            " is not one this function answers; the prefetch class is Wine's "
            "and the region-query class is this runtime's");
}

// ------------------------------------------------------------------------
// NtFlushInstructionCache
// ------------------------------------------------------------------------

Result<std::uint64_t> nt_flush_instruction_cache(NtContext& ctx,
                                                 std::uint64_t addr,
                                                 std::uint64_t size) noexcept {
    if (const Result<std::uint64_t> guard = check_context_reading<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard;
    }

    // x86 and x64 keep the instruction cache coherent with the data cache, so
    // there is nothing to do -- which is exactly Wine's conclusion
    // (`virtual.c:6044-6047`, a no-op behind a `#if`) and exactly the same
    // conclusion Windows draws.
    //
    // It is a no-op and *not* a stub, and the difference is worth naming: a
    // stub is a function that reports success without doing what its name
    // says. This reports success because the thing it names is already true.
    // Wine is careful about the same distinction -- its other arches call
    // `__clear_cache` -- and this runtime is on x64, so the cache is coherent.
    //
    // A range outside this space is refused rather than ignored: Wine's
    // no-op would happily accept any address, and a program flushing an
    // address that does not exist has a bug that this runtime can report.
    //
    // **Address zero is not exempt.** An earlier version guarded this with
    // `addr != 0 && size != 0`, on the reasoning that a null address means
    // "no particular address" -- which is a convention some calls have and
    // *not* this one. `NtFlushInstructionCache` takes a range and flushes that
    // range; a program passing zero has asked to flush the page at zero, which
    // is not mapped. The guard skipped exactly the address a program is most
    // likely to pass by accident, and it is the same `addr != 0` shape that
    // let a read of address zero through to a `memcpy` from a null pointer.
    if (size != 0) {
        if (addr + size < addr) {
            return refuse<std::uint64_t>(
                Status::InvalidAddress,
                "the range " + std::to_string(addr) + "+" +
                    std::to_string(size) +
                    " runs off the end of the address space, so there is no "
                    "instruction cache in it to flush");
        }
        const std::uint64_t base = round_addr(addr);
        if (!range_is_mapped(*ctx.space, base, round_size_from(addr, size))) {
            return refuse<std::uint64_t>(
                Status::InvalidAddress,
                "the range at " + std::to_string(base) +
                    " is not mapped, so there is no instruction cache in it to "
                    "flush; a program that computed an address it has not "
                    "mapped has a bug this reports rather than hides");
        }
    }
    return Result<std::uint64_t>{size};
}

// ------------------------------------------------------------------------
// NtFlushProcessWriteBuffers
// ------------------------------------------------------------------------

Result<std::uint64_t> nt_flush_process_write_buffers(NtContext& ctx) noexcept {
    if (const Result<std::uint64_t> guard = check_context<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard;
    }

    // **Wine stubs this.** `virtual.c:6069-6073`:
    //
    //     static int once = 0;
    //     if (!once++) FIXME( "stub\n" );
    //     return STATUS_SUCCESS;
    //
    // It reports success and writes nothing. A program that calls this before
    // telling the kernel its data is safe has a data-loss bug that no return
    // value will ever report, which is the worst kind of bug to have: it
    // cannot be detected by the program, only by the data it loses.
    //
    // So this flushes. Every region's dirty pages go to their backing store
    // with `msync(MS_SYNC)`, and the first refusal is reported rather than
    // swallowed. On Linux with anonymous memory there is nothing to flush to
    // a file, and `msync` on an anonymous mapping succeeds -- which is the
    // honest answer: the data *is* in the kernel, and this process's page
    // file or swap policy is what decides where from there.
    //
    // The call, and the record of the call, adjacent and in that order.
    //
    // The record is written *from the return value* rather than after the `if`
    // that tests it, and that placement is the whole reason this event exists
    // at all. Written after -- "we got here, so a flush happened" -- it is a
    // record of *control flow*, and control flow is exactly what an
    // implementation that never calls the syscall still has: a version testing
    // `if (false)` instead of the `msync` result walks the identical path,
    // records the identical event, and passes a suite asserting the count.
    //
    // That is not a hypothetical edit. It is this function's mutation, and it
    // survived a test asserting `count_of("msync") >= 1` -- the assertion was
    // right and the hook was lying, which is the worse of the two. An event
    // that describes a *decision* instead of an *action* cannot tell a real
    // flush from a stub, and an observability hook that cannot is worse than
    // no hook at all: it reports work that was never done.
    for (const Region& r : ctx.space->regions()) {
        // A region with no write access has no dirty pages. `msync` on a
        // read-only mapping succeeds on Linux but is a pointless call, and
        // skipping it keeps the report about regions that could have been
        // written.
        if ((protection_to_prot(r.protection) & PROT_WRITE) == 0) {
            continue;
        }
        // The syscall itself goes through the mapper, which is where this
        // runtime's syscalls live and where the counter is. Calling `::msync`
        // here would work and would bypass exactly the record of the work --
        // the counter is the one thing that cannot lie, for the reason
        // `Mapper::sync`'s comment gives -- and a layer that skips its own
        // accounting to save a call is a layer whose accounting is
        // decoration.
        const Result<std::uint64_t> flushed =
            ctx.placement->sync(r.base, r.size);
        if (ctx.events != nullptr) {
            ctx.events->record(EventSink{
                "msync", r.base, r.size,
                flushed.ok() ? Status::Success : Status::NotMappedData});
        }
        if (!flushed.ok()) {
            return refuse<std::uint64_t>(
                Status::NotMappedData,
                "the kernel refused to flush " + std::to_string(r.size) +
                    " bytes at " + std::to_string(r.base) + ": " +
                    std::strerror(ctx.placement->last_failure().error) +
                    ". Wine reports success here without flushing anything");
        }
    }
    return Result<std::uint64_t>{ctx.space->regions().size()};
}

// ------------------------------------------------------------------------
// NtCreatePagingFile
// ------------------------------------------------------------------------

Result<std::uint64_t> nt_create_paging_file(NtContext& ctx,
                                            std::uint64_t min_size,
                                            std::uint64_t max_size,
                                            std::uint64_t* actual_size) noexcept {
    if (actual_size == nullptr) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "no place to write the actual size");
    }
    if (const Result<std::uint64_t> guard = check_context<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard;
    }

    // **Wine stubs this too, and worse than the flush.** `virtual.c:6079`:
    //
    //     FIXME( "(%s %p %p %p) stub\n", ... );
    //     return STATUS_SUCCESS;
    //
    // It returns success and never writes `*actual_size`. A program that
    // sizes its working set from that answer reads whatever was in the
    // variable -- uninitialised stack memory on the first call -- and gets a
    // page file of an arbitrary size. This writes it.
    if (min_size == 0) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "a minimum size of zero: Windows refuses "
                                     "this, and a page file that may be zero "
                                     "bytes is not one");
    }
    if (max_size != 0 && max_size < min_size) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "a maximum size of " + std::to_string(max_size) +
                " is below the minimum of " + std::to_string(min_size) +
                ", so no size could satisfy both");
    }

    // The size actually reserved, which is what `*actual_size` reports. The
    // maximum is rounded up to the allocation granularity for the same reason
    // every other allocation here is: a page file is an allocation, and one
    // that came back at a size the program did not ask for would be reported
    // through this very parameter.
    const std::uint64_t want =
        AddressSpace::round_up(max_size != 0 ? max_size : min_size,
                               AddressSpace::kGranularity);

    // The reservation goes through the mapper directly, with no probe mapping
    // first. An earlier version mapped the size with `mmap(nullptr, ...)` to
    // learn an address and then handed that address to the mapper, which mapped
    // it *again* -- and the second mapping failed with EEXIST every single time,
    // because the first was still there. The call therefore never succeeded, and
    // the detail said "could not be recorded" and named an address that was
    // free a moment before.
    const Result<std::uint64_t> recorded =
        ctx.placement->map(0, want, PageProtection::ReadOnly,
                           RegionKind::Private);
    if (!recorded.ok()) {
        return refuse<std::uint64_t>(
            recorded.status,
            std::string("the page file reservation could not be recorded: ") +
                std::strerror(ctx.placement->last_failure().error));
    }

    // Read-only, because a page file is not memory the program may write. The
    // `PAGE_READWRITE` a program would expect for an allocation is refused
    // here deliberately: on Linux the page file *is* the swap backing store
    // and the kernel writes to it, and the program asking for it does not get
    // to read the kernel's copy of its own memory back through the mapping.
    *actual_size = want;
    return Result<std::uint64_t>{recorded.value};
}

// ------------------------------------------------------------------------
// Sections
// ------------------------------------------------------------------------

Result<std::uint64_t> nt_create_section(NtContext& ctx, HandleTable& table,
                                         std::uint64_t size,
                                         std::uint32_t protect,
                                         Handle* handle) noexcept {
    if (handle == nullptr) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "no place to write the section handle");
    }
    if (const Result<std::uint64_t> guard = check_context_reading<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard;
    }
    if (size == 0) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "a zero-sized section: Windows refuses, "
                                     "and a section that maps to nothing is a "
                                     "handle with no purpose");
    }
    if (!protection_is_known(protect)) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "protection " + std::to_string(protect) + " is not one of the "
            "eight PAGE_ values");
    }

    HandleEntry entry;
    entry.kind = HandleEntry::Kind::Section;
    // The size is rounded *up* to the granularity, because a section is
    // allocated in the same units as everything else this layer hands out.
    // A section whose size was not granular could not be mapped at a granular
    // address, and a program creating one and mapping it would get an address
    // the section does not cover.
    entry.section_size =
        AddressSpace::round_up(size, AddressSpace::kGranularity);
    entry.protection = static_cast<PageProtection>(protect);
    entry.image = false;
    entry.view_count = 0;

    const Handle h = table.insert(entry);
    if (h == 0) {
        return refuse<std::uint64_t>(Status::NoMemory,
                                     "the handle table is full");
    }
    *handle = h;
    return Result<std::uint64_t>{h};
}

Result<std::uint64_t> nt_map_view_of_section(NtContext& ctx,
                                             HandleTable& table, Handle handle,
                                             std::uint64_t* addr,
                                             std::uint32_t zero_bits,
                                             std::uint64_t commit_size,
                                             std::uint64_t offset,
                                             std::uint64_t* size,
                                             std::uint32_t inherit,
                                             std::uint32_t alloc_type,
                                             std::uint32_t protect) noexcept {
    if (addr == nullptr || size == nullptr) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "NtMapViewOfSection was given a null "
                                     "output pointer");
    }

    // `virtual.c:5446-5455`. The two `zero_bits` checks are different tests:
    // the first refuses the 22-31 window, and the second checks that a
    // requested address actually *fits* the window zero_bits describes -- by
    // shift below 32 and by mask at or above it. Writing one comparison for
    // both would accept an address the format forbids, and the reason they
    // are different is a comment in Wine's own source and nothing anybody
    // would guess.
    if (!zero_bits_is_acceptable(zero_bits)) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter4,
            "zero_bits " + std::to_string(zero_bits) +
                " asks for a 22- to 31-bit address window, which Windows "
                "does not allow");
    }
    if (*addr != 0 && !zero_bits_accepts(zero_bits, *addr)) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter4,
            "the requested address " + std::to_string(*addr) +
                " does not fit the window zero_bits " +
                std::to_string(zero_bits) + " describes");
    }

    // `virtual.c:5469-5470`: an offset that is not granular, or an address
    // that is not, is MAPPED_ALIGNMENT -- not INVALID_PARAMETER. A separate
    // status, and it is the one a program sees when it mis-computed an offset
    // it intended to be page-aligned; INVALID_PARAMETER would send it looking
    // for a bad argument rather than for a bad alignment.
    constexpr std::uint64_t kGranularityMask = AddressSpace::kGranularity - 1;
    if ((offset & kGranularityMask) != 0 ||
        (*addr != 0 && (*addr & kGranularityMask) != 0)) {
        return refuse<std::uint64_t>(
            Status::MappedAlignment,
            "the offset " + std::to_string(offset) +
                " or the requested address is not a multiple of the 64 KiB "
                "allocation granularity; a section view is placed in the same "
                "units as an allocation");
    }

    if (const Result<std::uint64_t> guard = check_context<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard;
    }

    // **`inherit` and `alloc_type` are checked, which Wine does not do.**
    //
    // Wine's `NtMapViewOfSection` passes both to `server_queue_process_apc`
    // without looking at them (`virtual.c:5477-5481`), so on Wine they are
    // whatever the server decides. This runtime has no server, so the only two
    // honest options are to refuse an unknown value or to accept everything.
    // Refusing is chosen for the values that name an operation this runtime
    // cannot perform, and accepting with a named limitation for the ones that
    // do not apply on x64:
    //
    //   inherit     A view that is not inheritable cannot be inherited, and
    //               `ViewInherit` is the only value that exists.
    //   alloc_type  `AT_ROUND_TO_PAGE` rounds a view's placement to a page
    //               rather than a granularity, and Wine only honours it in its
    //               wow64 path -- the `#ifndef _WIN64` around it at
    //               `virtual.c:5457-5467` is there because on x64 the flag
    //               changes nothing. This runtime is x64-only, so it is
    //               accepted and has no effect, and that is named here rather
    //               than left as a silently-ignored argument.
    if (inherit != section_inherit::kNoInherit &&
        inherit != section_inherit::kInherit) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "the inherit mode " + std::to_string(inherit) +
                " is not one this call expresses; a view is either inheritable "
                "or not");
    }
    constexpr std::uint32_t kKnownAllocType = alloc_type::kRoundToPage;
    if ((alloc_type & ~kKnownAllocType) != 0) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "allocation type " + std::to_string(alloc_type) +
                " has bits NtMapViewOfSection does not define; its only flag "
                "on x64 is AT_ROUND_TO_PAGE, which this runtime accepts and "
                "ignores because it does not translate x86 code");
    }

    HandleEntry* entry = table.find(handle);
    if (entry == nullptr) {
        return refuse<std::uint64_t>(Status::InvalidHandle,
                                     "the section handle is not one this "
                                     "process's table issued");
    }
    if (entry->kind != HandleEntry::Kind::Section) {
        return refuse<std::uint64_t>(
            Status::InvalidHandle,
            std::string("the handle names a ") +
                (entry->kind == HandleEntry::Kind::Event ? "event" : "file") +
                ", not a section");
    }

    // A view cannot be larger than the section, and an offset past its end is
    // a mapping of nothing. Both are the caller's arithmetic being wrong
    // rather than the section being damaged.
    if (offset >= entry->section_size) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "the offset " + std::to_string(offset) +
                " is past the end of a " +
                std::to_string(entry->section_size) + "-byte section");
    }
    std::uint64_t view_size = entry->section_size - offset;

    // `commit_size` of zero means the whole section: `virtual.c`'s
    // `NtMapViewOfSection` documents "a zero commit size commits the whole
    // section" and this is the ordinary call, so it is the common case rather
    // than an edge one.
    if (commit_size != 0) {
        if (commit_size > view_size) {
            return refuse<std::uint64_t>(
                Status::InvalidParameter,
                "a commit size of " + std::to_string(commit_size) +
                    " exceeds the " + std::to_string(view_size) +
                    " bytes of the section that remain after the offset");
        }
        view_size = commit_size;
    }

    // A section created with one protection cannot be mapped with a stronger
    // one. Windows enforces this and it is a real limit rather than a
    // convention: a section shared between two processes is as private as its
    // creator made it, and a map that could strengthen it would be a way for
    // one process to grant itself access another refused.
    if (protection_is_known(protect)) {
        const std::uint32_t section_prot =
            static_cast<std::uint32_t>(entry->protection) & 0xffU;
        if (section_prot == static_cast<std::uint32_t>(PageProtection::ReadOnly) &&
            (protect & 0xffU) != static_cast<std::uint32_t>(PageProtection::ReadOnly)) {
            return refuse<std::uint64_t>(
                Status::SectionProtection,
                "the section was created read-only and cannot be mapped "
                "writable: a shared section is as private as its creator made "
                "it");
        }
    }

    // The placement. A requested address is honoured when it is free; a null
    // one asks the mapper, and a `zero_bits` window narrows where the mapper
    // may look. Wine hands the window to wineserver as a limit
    // (`virtual.c:5498`) and there is no server here, so the placement is done
    // in this process -- see `map_below` for why the kernel's own placement
    // cannot be asked for a bounded address.
    //
    // Note that no probe mapping is made first. An earlier version mapped the
    // size with `mmap(nullptr, ...)` to learn a base and then handed that base
    // to the mapper, which mapped it *again* at the same address -- and the
    // second mapping failed with EEXIST every time, because the first one was
    // still there. The symptom was a view that could never be created, with a
    // "File exists" in the detail that named the real cause.
    std::uint64_t base = *addr;
    const std::uint64_t want =
        AddressSpace::round_up(view_size, AddressSpace::kGranularity);
    const std::uint64_t window = zero_bits_limit(zero_bits);
    const Result<std::uint64_t> mapped =
        (base == 0 && window != 0)
            ? ctx.placement->map_below(window, want,
                                      static_cast<PageProtection>(protect),
                                      RegionKind::Mapped)
            : ctx.placement->map(base, want,
                                 static_cast<PageProtection>(protect),
                                 RegionKind::Mapped);
    if (!mapped.ok()) {
        return refuse<std::uint64_t>(
            mapped.status,
            "the view at " + std::to_string(base) +
                " could not be recorded: " +
                std::strerror(ctx.placement->last_failure().error));
    }
    base = mapped.value;

    ++entry->view_count;
    *addr = base;
    *size = view_size;
    return Result<std::uint64_t>{base};
}

Result<std::uint64_t> nt_map_view_of_section_ex(
    NtContext& ctx, HandleTable& table, Handle handle, std::uint64_t* addr,
    std::uint64_t* size, std::uint32_t zero_bits, std::uint64_t commit_size,
    std::uint64_t offset, const MemExtendedParameter* parameters,
    std::uint32_t count, std::uint32_t inherit, std::uint32_t alloc_type,
    std::uint32_t protect) noexcept {
// The extended form validates its parameter array and then places the
    // view the same way, because the two forms differ in what they may say
    // about *where* rather than in what they do. So the parameter checks come
    // first and the placement is the shared code below.
    if (count != 0 && parameters == nullptr) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "a parameter count of " +
                                         std::to_string(count) +
                                         " with no array");
    }

    // What the requirements ask for, kept rather than only checked. This used
    // to validate the structure and then throw the answers away, so a caller
    // could ask for a view at or above an address and be given one anywhere:
    // the parse ran, every field was range-checked, and none of it reached the
    // placement. A requirement that is validated and not applied is worse than
    // one that is not validated, because the caller has been told its
    // parameters were understood.
    std::uint64_t req_alignment = 0;
    std::uint64_t req_low = 0;
    std::uint64_t req_high = 0;
    bool have_requirements = false;

    for (std::uint32_t i = 0; i < count; ++i) {
        if (parameters[i].type >= 32) {
            return refuse<std::uint64_t>(
                Status::InvalidParameter,
                "extended parameter " + std::to_string(i) + " has type " +
                    std::to_string(parameters[i].type) + ", and there are 32");
        }
        if (parameters[i].type == kMemExtendedParameterAddressRequirements) {
            if (parameters[i].pointer == nullptr) {
                return refuse<std::uint64_t>(
                    Status::InvalidParameter,
                    "an address-requirements parameter with a null pointer");
            }
            const auto* req =
                static_cast<const MemExtendedParameterAddressRequirements*>(
                    parameters[i].pointer);
            // The same three tests `NtAllocateVirtualMemoryEx` applies, and
            // for the same reasons: an alignment that is not a power of two or
            // is below the granularity asks for an address the allocator never
            // hands out, and a bound outside the window or not granular names
            // a place no mapping can be recorded.
            if (req->alignment != 0) {
                const std::uint64_t a = req->alignment;
                if ((a & (a - 1)) != 0 ||
                    a - 1 < AddressSpace::kGranularity) {
                    return refuse<std::uint64_t>(
                        Status::InvalidParameter,
                        "an alignment of " + std::to_string(a) +
                            " is not a power of two, or is smaller than the "
                            "allocation granularity");
                }
                req_alignment = a;
            }
            if (req->lowest_starting_address != 0 &&
                (!AddressSpace::is_granular(req->lowest_starting_address) ||
                 req->lowest_starting_address >= AddressSpace::kUserMax)) {
                return refuse<std::uint64_t>(
                    Status::InvalidParameter,
                    "a lowest starting address that is outside the window or "
                    "is not granular");
            }
            if (req->highest_ending_address != 0 &&
                req->highest_ending_address <= req->lowest_starting_address) {
                return refuse<std::uint64_t>(
                    Status::InvalidParameter,
                    "a highest ending address below the lowest starting one");
            }
            req_low = req->lowest_starting_address;
            req_high = req->highest_ending_address;
            have_requirements = true;
        }
    }

    if (addr == nullptr || size == nullptr) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "NtMapViewOfSectionEx was given a null "
                                     "output pointer");
    }

    // A requested address and address requirements are mutually exclusive,
    // which is the rule `NtAllocateVirtualMemoryEx` applies at
    // `virtual.c:4731` and the reason is the same: one names a place and the
    // other asks the runtime to search for one. Honouring both would mean
    // choosing which wins, and a runtime that quietly picked one is a runtime
    // a program cannot predict.
    if (have_requirements && *addr != 0) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            "an address and address requirements were both given; the first "
            "names a place and the second asks to search for one, and Windows "
            "refuses rather than choosing between them");
    }

    // The plain call does the placement, and the extended one differs only in
    // having checked the parameters above. Passing `MEM_RESERVE`-equivalent
    // behaviour through the shared path is deliberate: two implementations of
    // "put a view somewhere" would be two implementations to keep in step,
    // which is the thing this file exists to avoid.
    const Result<std::uint64_t> placed =
        nt_map_view_of_section(ctx, table, handle, addr, zero_bits,
                               commit_size, offset, size, inherit,
                               alloc_type, protect);
    if (!placed.ok() || !have_requirements) {
        return placed;
    }

    // The shared path places without knowing about the requirements, so its
    // answer is checked and, where it falls outside what the caller asked for,
    // undone and the request placed again under the constraints. Checking
    // afterwards and stopping there would be enough to be *correct* -- a
    // refused call has changed nothing -- but it would not be *useful*: a
    // caller that asked for 2 MiB alignment in a space with room would be told
    // it could not be had, which is a different answer from the one it asked
    // for and one it cannot act on. The retry is bounded and uses the same
    // `map` the shared path uses, so the only policy here is which addresses
    // are eligible, not how a mapping is made.
    const std::uint64_t view_bytes = *size;
    const std::uint64_t want =
        AddressSpace::round_up(view_bytes, AddressSpace::kGranularity);

    const auto violates = [&](std::uint64_t candidate) -> std::string {
        if (req_alignment != 0 &&
            (candidate & (req_alignment - 1)) != 0) {
            return "it is not aligned to the " +
                   std::to_string(req_alignment) + " the caller asked for";
        }
        if (req_low != 0 && candidate < req_low) {
            return "it is below the lowest starting address the caller named";
        }
        // The end is computed as a difference rather than a sum for the reason
        // `map_below` gives its own: a base and a size near the top of the
        // window add to a wrapped value, and a wrapped end compares as though
        // it fit inside a range it does not.
        if (req_high != 0 &&
            (want > req_high ||
             candidate > req_high - std::min(req_high, want))) {
            return "it ends above the highest ending address the caller named";
        }
        return std::string();
    };

    if (violates(*addr).empty()) {
        return placed;
    }

    // The undo, before the retry rather than after a failed one: a view left
    // mapped at an address the caller was not given is reachable by the guest,
    // and it would also be one more region competing with the retry for the
    // space the retry is about to search. The section's view count is
    // decremented for the same reason the unmap happens: the increment the
    // placement did is no longer true, and a count left high makes
    // NtQuerySection report a section as still mapped.
    const std::uint64_t rejected = *addr;
    HandleEntry* entry = table.find(handle);
    const Result<std::uint64_t> undone = ctx.placement->unmap(rejected);
    if (entry != nullptr && entry->view_count > 0) {
        --entry->view_count;
    }
    if (!undone.ok()) {
        return refuse<std::uint64_t>(
            undone.status,
            "the view the mapper chose at " + std::to_string(rejected) +
                " does not meet the address requirements the caller gave, and "
                "it could not be unmapped: " +
                std::strerror(ctx.placement->last_failure().error));
    }

    // The constrained search. It descends from the top of the permitted range,
    // as `map_below` does and for the same reason: the ranges a program names
    // are usually low, and descending reaches the dense low part of the space
    // first. The stride is the coarser of the alignment and the granularity --
    // a stride below the alignment would retry addresses that cannot satisfy it,
    // and a stride below the granularity would retry addresses the ledger can
    // never have free.
    const std::uint64_t stride =
        req_alignment > AddressSpace::kGranularity ? req_alignment
                                                   : AddressSpace::kGranularity;
    std::uint64_t ceiling =
        req_high != 0 ? req_high : AddressSpace::kUserMax;
    if (ceiling > AddressSpace::kUserMax) {
        ceiling = AddressSpace::kUserMax;
    }
    if (want > ceiling - AddressSpace::kUserMin) {
        return refuse<std::uint64_t>(
            Status::ConflictingAddresses,
            "a view of " + std::to_string(want) +
                " bytes cannot fit below the highest address the caller named, "
                + std::to_string(ceiling) +
                ", so there is no address in the permitted range");
    }

    std::uint64_t candidate =
        AddressSpace::round_down(ceiling - want, stride);
    // Sixteen thousand strides of 64 KiB is a gigabyte of search; a space with a
    // suitable hole in it has one within a few steps, and a space without one
    // has to be able to say so rather than walk the whole 47-bit window.
    constexpr std::uint64_t kMaxAttempts = 16384;
    for (std::uint64_t attempt = 0; attempt < kMaxAttempts; ++attempt) {
        if (candidate < req_low || candidate < AddressSpace::kUserMin) {
            break;
        }
        if (violates(candidate).empty()) {
            const Result<std::uint64_t> constrained =
                ctx.placement->map(candidate, want,
                                   static_cast<PageProtection>(protect),
                                   RegionKind::Mapped);
            if (constrained.ok()) {
                const std::uint64_t base = constrained.value;
                if (entry != nullptr) {
                    ++entry->view_count;
                }
                *addr = base;
                *size = view_bytes;
                return Result<std::uint64_t>{base};
            }
            // A hole the ledger does not know about is the kernel's to refuse,
            // and the refusal is about this candidate only: the next one down
            // may be free. Anything else means the space is out of room.
            if (constrained.status != Status::ConflictingAddresses) {
                return refuse<std::uint64_t>(
                    constrained.status,
                    "a view at " + std::to_string(candidate) +
                        " that meets the address requirements the caller gave "
                        "could not be mapped: " +
                        std::strerror(ctx.placement->last_failure().error));
            }
        }
        if (candidate < stride) {
            break;
        }
        candidate -= stride;
    }

    return refuse<std::uint64_t>(
        Status::ConflictingAddresses,
        "no address between " + std::to_string(req_low) + " and " +
            std::to_string(ceiling) + " is free, aligned to " +
            std::to_string(stride) + ", and big enough for a " +
            std::to_string(want) +
            "-byte view. The view the mapper chose without the requirements "
            "was unmapped rather than left in place");
}

Result<std::uint64_t> nt_unmap_view_of_section(NtContext& ctx,
                                               std::uint64_t* addr,
                                               std::uint64_t* size) noexcept {
    if (addr == nullptr || size == nullptr) {
        return refuse<std::uint64_t>(Status::InvalidParameter,
                                     "NtUnmapViewOfSection was given a null "
                                     "output pointer");
    }
    if (const Result<std::uint64_t> guard = check_context<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard;
    }

    const std::uint64_t base = AddressSpace::granularity_round_down(*addr);

    if (base == 0) {
        return refuse<std::uint64_t>(
            Status::InvalidAddress,
            "a null address: there is no view at address zero");
    }

    // **The region's exact base, or refused.** `AddressSpace::remove()`
    // requires it and this type does not split regions, so a view starting
    // inside a region cannot be unmapped on its own. A section view is
    // always whole, so this is a restriction on *where a view may start*
    // rather than a real limitation -- and saying it is better than
    // unmapping a region a view merely shares part of with.
    const Region* region = ctx.space->find(base);
    if (region == nullptr) {
        return refuse<std::uint64_t>(
            Status::InvalidAddress,
            "nothing is mapped at " + std::to_string(base) +
                ", so there is no view to unmap");
    }
    // The size, read **before** the unmap. `ctx.placement->unmap()` removes
    // the region from the ledger, and the ledger is a `std::vector<Region>` --
    // so the `Region*` this function has been holding points into an
    // allocation that the removal has just freed or moved, and reading
    // `region->size` afterwards is a use-after-free.
    //
    // This is not a subtle hazard and it is not specific to this call: the
    // ledger hands out `const Region*` into a container that grows, so *any*
    // pointer held across a `record()` is a pointer that can dangle. The
    // loader and the mapper both happen to read what they need before they
    // mutate, and this function is the third case. AddressSanitizer found this
    // one -- the test that unmaps a view while holding the pointer it got from
    // `find()` -- and a plain run of the same test reports the right answer,
    // because the freed memory usually still holds the size it had.
    //
    // The copy is of the two fields this function needs and not of the whole
    // region, so that nothing here is tempted to keep a pointer across the
    // mutation.
    const std::uint64_t region_base = region->base;
    const std::uint64_t region_size = region->size;
    const RegionKind region_kind = region->kind;
    if (region_base != base) {
        return refuse<std::uint64_t>(
            Status::FreeVmNotAtBase,
            "a view is unmapped from its own base, and " +
                std::to_string(base) + " is not the base of the region that "
                "holds it (" + std::to_string(region_base) +
                "). Unmapping a range would have to decide what happens to "
                "the two halves, and this runtime does not split regions");
    }
    if (region_kind != RegionKind::Mapped) {
        return refuse<std::uint64_t>(
            Status::InvalidParameter,
            std::string("the region at ") + std::to_string(base) + " is a " +
                region_kind_name(region_kind) +
                " region; this call unmaps section views, and a private one "
                "belongs to NtFreeVirtualMemory");
    }

    const Result<std::uint64_t> unmapped = ctx.placement->unmap(base);
    if (!unmapped.ok()) {
        return refuse<std::uint64_t>(unmapped.status,
                                     "the kernel refused to unmap " +
                                         std::to_string(base) + ": " +
                                         std::strerror(ctx.placement->last_failure().error));
    }

    *addr = base;
    *size = region_size;
    return Result<std::uint64_t>{base};
}

Result<std::uint64_t> nt_unmap_view_of_section_ex(NtContext& ctx,
                                                 std::uint64_t base) noexcept {
    std::uint64_t addr = base;
    std::uint64_t size = 0;
    const auto r = nt_unmap_view_of_section(ctx, &addr, &size);
    if (!r.ok()) {
        return r;
    }
    // The `Ex` form returns the unmapped *address*, not a pointer to it, and
    // does not report a size: `virtual.c`'s signature takes a plain address.
    return Result<std::uint64_t>{addr};
}

Result<std::uint64_t> nt_query_section(NtContext& ctx, HandleTable& table,
                                       Handle handle,
                                       SectionInformationClass info_class,
                                       void* buffer, std::uint64_t len,
                                       std::uint64_t* result_length) noexcept {
    if (const Result<std::uint64_t> guard = check_context_reading<std::uint64_t>(ctx);
        !guard.ok()) {
        return guard;
    }

    // `virtual.c:5716-5726`. The length is checked per class, before the
    // null-pointer check, and each class has its own structure size. The
    // order is the code's and it matters: a call with both a short buffer and
    // a null pointer gets the length mismatch, which is the more specific of
    // the two complaints.
    std::uint64_t wanted = 0;
    switch (info_class) {
    case SectionInformationClass::BasicInformation:
        wanted = sizeof(SectionBasicInformation);
        break;
    case SectionInformationClass::ImageInformation:
        wanted = sizeof(SectionImageInformation);
        break;
    case SectionInformationClass::SectionInformation:
        wanted = sizeof(SectionSectionInformation);
        break;
    default:
        // Wine's `default` arm is `STATUS_NOT_IMPLEMENTED`
        // (`virtual.c:5722-5724`) while NtQueryVirtualMemory's is
        // `STATUS_INVALID_INFO_CLASS`. Two query functions, two answers for
        // the same mistake, and this is Wine's answer for *this* one.
        return refuse<std::uint64_t>(
            Status::NotImplemented,
            "section information class " +
                std::to_string(static_cast<std::uint32_t>(info_class)) +
                " is not one this function answers. Wine answers NOT_IMPLEMENTED "
                "for every class but its own two; this answers those plus the "
                "section's own extent");
    }

    if (len < wanted) {
        return refuse<std::uint64_t>(
            Status::InfoLengthMismatch,
            "the buffer is " + std::to_string(len) + " bytes and this class "
            "fills " + std::to_string(wanted));
    }
    if (buffer == nullptr) {
        // `virtual.c:5726`.
        return refuse<std::uint64_t>(Status::AccessViolation,
                                     "no output buffer: there is nowhere to put "
                                     "the answer");
    }

    HandleEntry* entry = table.find(handle);
    if (entry == nullptr) {
        return refuse<std::uint64_t>(Status::InvalidHandle,
                                     "the section handle is not one this "
                                     "process's table issued");
    }

    switch (info_class) {
    case SectionInformationClass::BasicInformation: {
        // The answer is written into the caller's buffer one member at a time
        // rather than copied out of a local structure. A structure copy would
        // carry the padding between `attributes` and `base_address` with it, and
        // padding is not a member: it holds no defined value, so what a copy
        // would put there is whatever the compiler left on the stack. Those four
        // bytes then reach the guest as part of the answer -- a host address, in
        // the host's layout, different on every call. Windows leaves the padding
        // alone, and so does this.
        SectionBasicInformation out{};
        // **`SEC_*` attributes, not the `MEM_*` allocation type.** Wine fills
        // this from `reply->flags` (`virtual.c:5738`), which the server builds
        // from the view's protection word -- `SEC_IMAGE`, `SEC_FILE`,
        // `SEC_COMMIT`, `SEC_RESERVE` and the rest. Putting a `MEM_` value
        // here would be a different and wrong answer: `MEM_COMMIT` is 0x1000
        // and `SEC_COMMIT` is 0x08000000, so a section that is committed would
        // report as not committed to a program that checks. The protection is
        // reported in its own field here rather than smuggled in as
        // attributes, which is a third improvement over Wine: its
        // `BasicInformation` has no place for the protection at all.
        std::uint32_t attributes = sec::kCommit;
        if (entry->image) {
            attributes |= sec::kImage;
        }
        attributes |=
            static_cast<std::uint32_t>(entry->protection) & 0xffU;
        if (entry->view_count > 0) {
            attributes |= sec::kCommit;
        }
        out.attributes = attributes;
        // Always null: `virtual.c:5739` sets it to NULL and says why in the
        // shape of the code. The address a section is based at belongs to
        // whoever created it, and there is no address to report.
        out.base_address = 0;
        out.size = entry->section_size;
        // Member by member, for the reason given above: this is the one answer
        // structure with padding in it, so this is the one place a whole-
        // structure copy would carry stack bytes into the guest's buffer. The
        // other two have no padding and are copied whole below.
        auto* bytes = static_cast<std::uint8_t*>(buffer);
        std::memcpy(bytes + offsetof(SectionBasicInformation, attributes),
                    &out.attributes, sizeof(out.attributes));
        std::memcpy(bytes + offsetof(SectionBasicInformation, base_address),
                    &out.base_address, sizeof(out.base_address));
        std::memcpy(bytes + offsetof(SectionBasicInformation, size), &out.size,
                    sizeof(out.size));
        if (result_length != nullptr) {
            *result_length = sizeof(out);
        }
        return Result<std::uint64_t>{sizeof(out)};
    }

    case SectionInformationClass::ImageInformation: {
        // `virtual.c:5743-5749`: asking for image information about something
        // that is not an image is SECTION_NOT_IMAGE, not a generic refusal.
        // A program that mapped a file and asked what its entry point is has
        // made a mistake worth naming.
        if (!entry->image) {
            return refuse<std::uint64_t>(
                Status::SectionNotImage,
                "this section is not an image, so it has no entry point, base "
                "or size as an image does");
        }
        SectionImageInformation out;
        out.entry_point = 0;
        out.image_base = 0;
        out.image_size = static_cast<std::uint32_t>(entry->section_size);
        out.image_flags = 0;
        // Four members, all 4 or 8 bytes wide and in descending order, so this
        // structure has no padding and a whole-structure copy carries nothing
        // but the members.
        std::memcpy(buffer, &out, sizeof(out));
        if (result_length != nullptr) {
            *result_length = sizeof(out);
        }
        return Result<std::uint64_t>{sizeof(out)};
    }

    case SectionInformationClass::SectionInformation: {
        // occ's own. The section's address and total size, which
        // `BasicInformation` cannot give: its `BaseAddress` is always null and
        // its `Size` is the size of the *view* rather than of the section.
        // A program about to allocate out of a section needs the section's
        // extent, and there is no Wine call that reports it -- which is why
        // this class exists.
        SectionSectionInformation out;
        // Always null, and the reason is the same one `BasicInformation`
        // gives above: a section is an object, not a mapping, and it has no
        // address until somebody maps a view of it. There is no section
        // address in the guest's address space to report, and there never
        // will be -- the space a view lands in is chosen at NtMapViewOfSection
        // time, not at NtCreateSection time.
        //
        // This used to write `reinterpret_cast<std::uint64_t>(entry)`, which
        // is a pointer into this process's `HandleTable::entries_` vector. A
        // guest reading the buffer got a host heap address: it described a
        // region of the host's address space, it said nothing about the
        // guest's, and it leaked the host's allocator layout into a PE. The
        // number was also meaningless to the guest in the strongest sense --
        // no PE can do anything with it, because the address it names is not
        // in the address space the PE runs in. The size beside it was the
        // one field of the pair that could be answered, and it still is.
        out.section_address = 0;
        out.section_size = entry->section_size;
        // Two 8-byte members, so no padding to carry.
        std::memcpy(buffer, &out, sizeof(out));
        if (result_length != nullptr) {
            *result_length = sizeof(out);
        }
        return Result<std::uint64_t>{sizeof(out)};
    }
    }

    return refuse<std::uint64_t>(
        Status::NotImplemented,
        "section information class " +
            std::to_string(static_cast<std::uint32_t>(info_class)) +
            " is not one this function answers");
}

} // namespace occ::runtime
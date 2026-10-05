#include "occ/runtime/mapper.h"

#include <algorithm>

#include "occ/syscall/syscall.h"

namespace occ::runtime {

namespace {

// The three things this file has to be right about, each of which has a
// kernel primitive that gets it right atomically and an obvious way to write
// it that does not. They are collected here because each one's comment
// explains the obvious way, and three comments interleaved through the
// functions below would each have to restate the others to be readable.

// Whether an address is one this process may map at all.
//
// Linux refuses anything below mmap_min_addr with EPERM, and the default is
// 65536 -- which is the same 64 KiB floor Windows reserves and which is why
// AddressSpace::kUserMin is the value it is. The check here is against
// kUserMin rather than against mmap_min_addr: the ledger already has a window
// and a mapping outside it would be a mapping the ledger cannot describe, so
// the window is the rule and the kernel's is a second rule that happens to
// agree.
[[nodiscard]] bool in_the_user_window(std::uint64_t base,
                                      std::uint64_t size) noexcept {
    if (base < AddressSpace::kUserMin || base > AddressSpace::kUserMax) {
        return false;
    }
    // The subtraction, not base + size. Both operands can be near the top of
    // the window and the sum of two of them wraps, and a wrapped sum
    // compares as small.
    return size <= AddressSpace::kUserMax - base;
}

// The mmap flags every mapping in this file uses.
//
// MAP_FIXED_NOREPLACE is the load-bearing one. Without it, a mapping at an
// address that is already mapped does not fail -- it silently replaces what
// was there, and the ledger still describes the old region, and the result is
// a process whose map is a lie about its own memory. That failure is not
// hypothetical: it is what happens to the stack, to the heap, and to every
// shared library when a loader maps an image at an address it did not check.
//
// The alternative to the flag is a check-then-map, and a check-then-map is
// the TOCTOU shape: two threads both find the address free, the second mmap
// wins, and the first thread's ledger entry now describes memory belonging to
// the other thread. The flag makes the kernel do the check as part of the
// mapping, which is the only place the answer cannot change between the
// question and the act.
//
// MAP_PRIVATE | MAP_ANONYMOUS is what a Windows private region is: zero
// filled, copy on write against nothing, invisible to every other process.
constexpr int kPrivateFlags = MAP_PRIVATE | MAP_ANONYMOUS;

// Maps one region, without touching the ledger.
//
// Split out because map() and map_batch() must map identically, and a
// shared helper is the only way that survives one of them gaining an
// argument. Returns the mapped address, or 0 with `error` set. Zero is not a
// valid mapping address -- the kernel does not map page zero -- so it is an
// unambiguous failure marker.
[[nodiscard]] std::uint64_t map_one(std::uint64_t base, std::uint64_t size,
                                    PageProtection protection, int& error) noexcept {
    const std::size_t rounded = static_cast<std::size_t>(
        AddressSpace::page_round_up(size));

    // The flag is conditional and the condition is a kernel behaviour rather
    // than a preference. MAP_FIXED_NOREPLACE means "map exactly here, and fail
    // rather than replace what is here" -- and "exactly here" is not a
    // question the kernel can answer about address zero, which is not a
    // mapping address at all. Asked with a null address it does not place the
    // mapping somewhere sensible and return it; it fails with EPERM, because
    // the search for a hole starts at zero and zero is below mmap_min_addr.
    //
    // Which is harmless here, because a null address is exactly the case
    // where the flag has nothing to say: the kernel's own search already
    // finds a hole, and a hole is not something that can be silently
    // replaced. The flag is for the case where the caller named an address,
    // and that is the only case it is passed for.
    const int flags =
        (base == 0) ? kPrivateFlags
                    : (kPrivateFlags | MAP_FIXED_NOREPLACE);

    const void* addr = reinterpret_cast<const void*>(base);
    const sys::Result r =
        sys::mmap(const_cast<void*>(addr), rounded,
                  protection_to_prot(protection), flags, -1, 0);
    if (r.failed()) {
        error = r.error;
        return 0;
    }
    error = 0;
    // The kernel's return is a long holding a pointer, and the round trip out
    // of it is long -> uintptr_t -> void* -> uintptr_t, which is verbose and
    // is the shape the observer layer already uses on the same wrapper. It is
    // spelled out rather than shortened because a helper here would be one
    // function used once, and the alternative -- a cast that reads as a
    // single step -- is exactly the spelling clang rejects.
    const void* at = reinterpret_cast<void*>(static_cast<std::uintptr_t>(r.value));
    return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(at));
}

} // namespace

Result<std::uint64_t> Mapper::map(std::uint64_t base, std::uint64_t size,
                                  PageProtection protection, RegionKind kind,
                                  std::string section,
                                  std::uint32_t section_index) noexcept {
    if (size == 0) {
        return fail<std::uint64_t>(Status::InvalidParameter, 0, base);
    }

    // The window check before the alignment check, because a base outside the
    // window is wrong in a way no rounding fixes and the reader wants the
    // window's status rather than the alignment's.
    if (base != 0 && !in_the_user_window(base, size)) {
        return fail<std::uint64_t>(Status::InvalidAddress, 0, base);
    }
    if (base == 0) {
        // An unspecified base. The size still has to fit the window, and the
        // check is against the window's top because the kernel will place it
        // somewhere inside the window and a size that does not fit anywhere in
        // it cannot be satisfied anywhere in it.
        if (AddressSpace::page_round_up(size) >
            AddressSpace::kUserMax - AddressSpace::kUserMin) {
            return fail<std::uint64_t>(Status::NoMemory, 0, 0);
        }
    } else if (!AddressSpace::is_page_aligned(base)) {
        // Refused rather than rounded down. The reason is in the header: a
        // rounded-down base maps memory the caller did not name and records a
        // region the caller did not ask for, and both of those are worse than
        // a refusal. It is also the case mmap itself refuses, with EINVAL, so
        // this check exists to report the Windows status rather than to
        // prevent a mapping.
        return fail<std::uint64_t>(Status::InvalidParameter, 22 /* EINVAL */,
                                   base);
    }

    int error = 0;
    const std::uint64_t at = map_one(base, size, protection, error);
    // The counter moves whether or not the mapping happened, because a
    // syscall was made either way and that is what the counter is a count
    // of. It used to move only on success, on the reasoning that a failed
    // mapping left nothing behind to be accountable for -- which is true of
    // the *space* and false of the counter, and the second is what the
    // counter is for. A retry loop that spends three attempts discovering
    // three conflicts reported that it had made no syscalls at all, and a
    // reader checking that number against the attempt count had no way to
    // tell a loop that never tried from a loop whose every try was refused
    // by the kernel. (The retry case in tests/test_placement.cpp is what
    // found it, by asserting that the attempts did something and being told
    // they did nothing -- while in fact they had done exactly what they
    // said they had.)
    ++syscalls_made_;
    if (at == 0) {
        // The errno is translated rather than passed through, because the two
        // cases a caller of a memory API has to tell apart are "that address
        // is taken" and "there is no memory", and EEXIST and ENOMEM say
        // exactly that while STATUS_NO_MEMORY alone would not.
        //
        // EACCES is the third worth naming: it is what a mapping below
        // mmap_min_addr returns, and reporting it as NoMemory would send a
        // reader looking for an out-of-memory condition that is not there.
        if (error == 17 /* EEXIST */) {
            return fail<std::uint64_t>(Status::ConflictingAddresses, error,
                                       base);
        }
        if (error == 13 /* EACCES */) {
            return fail<std::uint64_t>(Status::InvalidAddress, error, base);
        }
        return fail<std::uint64_t>(Status::NoMemory, error, base);
    }

    // The ledger's turn, and the reason this type exists. The region is now
    // mapped and the ledger does not know it, and a failure here has to undo
    // the mapping: leaving it would be a mapping that no operation in this
    // file can ever remove, because unmap() looks the region up by address
    // and there is no region to find.
    const Result<std::uint64_t> recorded =
        space_->record(at, AddressSpace::page_round_up(size), protection, kind,
                       std::move(section), section_index);
    if (!recorded.ok()) {
        // The undo. It cannot be checked meaningfully -- a munmap that fails
        // on an address the kernel just mapped would be a kernel bug, and
        // there is nothing a caller could do about it either way -- so the
        // failure is not reported over the one the caller needs to see. The
        // counter still moves, because a syscall was made.
        ++syscalls_made_;
        (void)sys::munmap(reinterpret_cast<void*>(at),
                         static_cast<std::size_t>(
                             AddressSpace::page_round_up(size)));
        return fail<std::uint64_t>(recorded.status, 0, at);
    }

    Result<std::uint64_t> out;
    out.value = at;
    out.status = Status::Success;
    return out;
}

Result<std::uint64_t> Mapper::map_batch(
    const std::vector<Candidate>& batch) noexcept {
    // Everything the call could refuse, before any of it happens.
    //
    // The validations are run over the whole batch first, and in the
    // caller's order, so that the refusal names the first candidate that
    // could not be placed -- the order a reader of the file reached them in,
    // and the same rule record_batch() follows for the same reason.
    for (const Candidate& c : batch) {
        if (c.size == 0) {
            return fail<std::uint64_t>(Status::InvalidParameter, 0, c.base);
        }
        if (c.base == 0 || !in_the_user_window(c.base, c.size)) {
            return fail<std::uint64_t>(Status::InvalidAddress, 0, c.base);
        }
        if (!AddressSpace::is_page_aligned(c.base)) {
            return fail<std::uint64_t>(Status::InvalidParameter,
                                       22 /* EINVAL */, c.base);
        }
    }

    // Map each one, remembering what was mapped so the undo can be exact.
    //
    // `done` holds the address and the rounded size of every mapping this
    // call has made so far, which is what the rollback needs and is not the
    // same as the candidate: a candidate names what was asked for, a done
    // names what the kernel did, and for a zero base the two are unrelated.
    // Every entry here is a mapping this call made with MAP_FIXED_NOREPLACE,
    // so no entry can be a mapping someone else made, and the rollback cannot
    // remove something that was there before the call started.
    struct Placed {
        std::uint64_t at;
        std::uint64_t size;
    };
    std::vector<Placed> done;
    done.reserve(batch.size());

    for (const Candidate& c : batch) {
        int error = 0;
        const std::uint64_t at = map_one(c.base, c.size, c.protection, error);
        // Counted before the branch, for the reason map() gives: the counter
        // counts syscalls and this one was made whether or not it succeeded.
        // A batch refused on its first candidate had still asked the kernel
        // a question, and a reader comparing the counter against the number
        // of candidates is entitled to that answer being in the number.
        ++syscalls_made_;
        if (at == 0) {
            // Unwind, in reverse. Reverse because the mappings are the
            // caller's own regions in the caller's own order and the last one
            // placed is the first one a reader would expect to be gone.
            for (auto it = done.rbegin(); it != done.rend(); ++it) {
                ++syscalls_made_;
                (void)sys::munmap(reinterpret_cast<void*>(it->at),
                                 static_cast<std::size_t>(it->size));
            }
            const Status status = (error == 17 /* EEXIST */)
                                      ? Status::ConflictingAddresses
                                      : (error == 13 /* EACCES */)
                                            ? Status::InvalidAddress
                                            : Status::NoMemory;
            return fail<std::uint64_t>(status, error, c.base);
        }
        done.push_back(Placed{at, AddressSpace::page_round_up(c.size)});
    }

    // Every mapping exists. The ledger's turn, and record_batch's rule: all of
    // them or none, so that a fourth section which overlaps the second is
    // refused before the first is recorded rather than after.
    std::vector<AddressSpace::Candidate> for_the_ledger;
    for_the_ledger.reserve(batch.size());
    for (std::size_t i = 0; i < batch.size(); ++i) {
        for_the_ledger.push_back(AddressSpace::Candidate{
            done[i].at, done[i].size, batch[i].protection, batch[i].kind,
            batch[i].section, batch[i].section_index});
    }

    const Result<std::uint64_t> recorded =
        space_->record_batch(for_the_ledger);
    if (!recorded.ok()) {
        for (auto it = done.rbegin(); it != done.rend(); ++it) {
            ++syscalls_made_;
            (void)sys::munmap(reinterpret_cast<void*>(it->at),
                             static_cast<std::size_t>(it->size));
        }
        return fail<std::uint64_t>(recorded.status, 0, 0);
    }

    Result<std::uint64_t> out;
    out.value = batch.size();
    out.status = Status::Success;
    return out;
}

Result<std::uint64_t> Mapper::unmap(std::uint64_t base) noexcept {
    // The region has to exist. find() answers for an address, and the
    // requirement here is that the address is the *start* of what find()
    // returns, which is what makes this the whole region and not a range
    // inside one. See the header for why splitting is not offered.
    const Region* r = space_->find(base);
    if (r == nullptr) {
        return fail<std::uint64_t>(Status::InvalidAddress, 14 /* EFAULT */,
                                   base);
    }
    if (r->base != base) {
        return fail<std::uint64_t>(Status::InvalidAddress, 14 /* EFAULT */,
                                   base);
    }

    const std::uint64_t size = r->size;
    ++syscalls_made_;
    const sys::Result u =
        sys::munmap(reinterpret_cast<void*>(base),
                    static_cast<std::size_t>(size));
    if (u.failed()) {
        // The ledger is not touched. A mapping that survived a failed munmap
        // is still mapped, and a ledger that dropped it would be describing
        // memory that is still there -- which is the same class of lie as the
        // one MAP_FIXED_NOREPLACE exists to prevent, and the reason the
        // removal comes second here rather than first.
        return fail<std::uint64_t>(Status::InvalidAddress, u.error, base);
    }

    const Result<std::uint64_t> removed = space_->remove(base);
    if (!removed.ok()) {
        // Now the reverse inconsistency: the memory is gone and the ledger
        // still has it. There is no recovering from it and no way to make it
        // true again, so the report is the honest one and the mapping is not
        // re-created to match the ledger. A caller that sees this has a
        // space that describes memory it no longer has, and the only correct
        // response is to stop using it.
        return fail<std::uint64_t>(Status::InvalidAddress, 0, base);
    }

    Result<std::uint64_t> out;
    out.value = size;
    out.status = Status::Success;
    return out;
}

Result<std::uint32_t> Mapper::protect(std::uint64_t base,
                                      PageProtection protection) noexcept {
    // The modifier bits are refused, and specifically PAGE_GUARD, because a
    // guard page that arrives as ordinary memory is a buffer overflow that
    // does not fault. The others are refused for the same reason rather than
    // for want of a translation: silently dropping a modifier is the failure
    // this design exists to prevent, and the honest answer now is a refusal
    // and a smaller promise.
    if (static_cast<std::uint32_t>(protection) & 0xf00U) {
        return fail<std::uint32_t>(Status::NotImplemented, 0, base);
    }

    const Region* r = space_->find(base);
    if (r == nullptr || r->base != base) {
        return fail<std::uint32_t>(Status::InvalidAddress, 14 /* EFAULT */,
                                   base);
    }

    const std::uint64_t size = r->size;
    ++syscalls_made_;
    const sys::Result p = sys::mprotect(reinterpret_cast<void*>(base),
                                        static_cast<std::size_t>(size),
                                        protection_to_prot(protection));
    if (p.failed()) {
        return fail<std::uint32_t>(Status::InvalidAddress, p.error, base);
    }

    const Result<std::uint32_t> changed = space_->set_protection(base, protection);
    if (!changed.ok()) {
        return fail<std::uint32_t>(changed.status, 0, base);
    }

    Result<std::uint32_t> out;
    out.value = changed.value;
    out.status = Status::Success;
    return out;
}

} // namespace occ::runtime

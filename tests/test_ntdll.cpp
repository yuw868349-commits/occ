// The Nt* memory interface: does it behave like the one Windows' programs
// were written against?
//
// Three rules this file is held to, and the reason for each is the same
// reason test_mapper.cpp gives for requiring every claimed mapping to be
// touched:
//
//   **Every rule below is a rule read out of Wine's source**, and several of
//   them are surprising enough that a test written from memory would get them
//   wrong. The `zero_bits` hole (22 through 31 refused, 21 and 32 accepted),
//   the read/write asymmetry in the buffer checks, the difference between
//   `NtProtectVirtualMemory`'s `MemoryNotCommitted` and its
//   `InvalidParameter`, the two different answers `NtQuerySection` and
//   `NtQueryVirtualMemory` give for an unknown class -- each of those is a
//   fact about Wine's code that a reader has to look up, and a test that
//   asserted the *sensible* behaviour instead of Wine's would pass against an
//   implementation that is incompatible in exactly the way nobody tests for.
//
//   **A status is not enough.** Every case that expects a refusal also checks
//   what the runtime wrote to its outputs, because the outputs are half the
//   contract: NtProtectVirtualMemory must leave `*old_protect` alone when it
//   refuses, and a runtime that zeroes it first answers a program that reads
//   it after a failure with a protection the region never had.
//
//   **A cross-process call must be refused, not quietly satisfied.** Every
//   function here takes an `NtContext` with a `target_process`, and a case
//   checks that a nonzero one is refused with `NotImplemented`. The failure
//   this guards against is the obvious implementation: treating another
//   process's request as this one's, modifying this process's memory, and
//   reporting success. That runtime is worse than one that crashes.

#include "occ/runtime/address_space.h"
#include "occ/runtime/mapper.h"
#include "occ/runtime/ntdll.h"

#include <sys/mman.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace occ::runtime;

namespace {

int failures = 0;
int checks = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

// A free base, asked of the kernel.
//
// The same reason test_mapper.cpp and the loader's own cases give: a
// written-down address is a claim about what else the process has mapped, and
// under a sanitizer the ordinary image bases are inside the runtime's own
// mappings. A probe that maps and gives back, with the release checked -- a
// probe that cannot release what it took has not found a free range, it has
// moved one.
//
// **The probe asks for a granularity-sized range even when the caller wants
// less**, and that is the one part of this helper that is not obvious.
// `NtAllocateVirtualMemory` rounds a requested address *down* to the 64 KiB
// granularity and a requested size *up* to it, so a probe that asked for one
// page would return an address whose enclosing granule is only partly proven
// free -- and the allocator that rounds to the granule can then land on a byte
// the probe never tested, failing with EEXIST at an address this helper had
// just reported as available. Sizing the probe at a granule makes the
// kernel hand back a granule-aligned base (it aligns to the length when the
// length asks for one), which the allocator's rounding cannot move.
//
// The alternative -- probing a page and rounding the answer down -- reads as
// more careful and is worse: it silently returns an address the probe never
// proved anything about, and every caller below then tests against a mapping
// that does not exist. A helper that reports a free base has to have checked
// the base it reports.
std::uint64_t a_free_base(std::uint64_t bytes) noexcept {
    AddressSpace probe_space;
    Mapper probe(probe_space);
    const std::uint64_t want =
        bytes < AddressSpace::kGranularity ? AddressSpace::kGranularity : bytes;
    const Result<std::uint64_t> r =
        probe.map(0, want, PageProtection::NoAccess, RegionKind::Private);
    if (!r.ok()) {
        return 0;
    }
    const Result<std::uint64_t> released = probe.unmap(r.value);
    return released.ok() ? r.value : 0;
}

// A context with a space and a mapper, and a skip when there is no room.
//
// Every case needs real memory, because the layer's whole job is memory, and
// a case that ran against an unmapped space would test only the parameter
// checks. That is not nothing -- several rules *are* parameter checks -- but
// a build with no free address space cannot run this file at all, so it says
// so rather than reporting a pass it did not earn.
struct Fixture {
    AddressSpace space;
    Mapper mapper;
    NtContext ctx;

    Fixture() : mapper(space) {
        ctx.space = &space;
        ctx.placement = &mapper;
    }
};

// Allocates `size` bytes and returns the address, or zero when it could not.
//
// A case that needs memory and does not get it skips, and says so, for the
// reason `a_free_base` is here at all. A case that needs memory *and* could
// not have it has found a bug in the runtime or in the host, and returning
// zero lets the case skip rather than assert against a default-constructed
// address that would make the next assertion meaningless.
std::uint64_t allocate(Fixture& f, std::uint64_t size,
                       std::uint32_t protect = 0x04) {
    const std::uint64_t want = a_free_base(size);
    if (want == 0) {
        return 0;
    }
    std::uint64_t addr = want;
    std::uint64_t got = size;
    const auto r = nt_allocate_virtual_memory(
        f.ctx, &addr, &got, 0, mem::kReserve | mem::kCommit, protect);
    if (!r.ok()) {
        std::fprintf(stderr, "SKIP: allocation of %llu bytes refused: %s\n",
                     static_cast<unsigned long long>(size), r.detail.c_str());
        return 0;
    }
    return addr;
}

// A 64-byte writable buffer, so the buffer checks have something real to
// point at.
//
// A function-local `static` rather than an automatic array, for one reason
// that is not tidiness: the address has to be *stable*, because the cases
// below hand it to a call that reports an address violation and then the
// caller reads the bytes back out. An automatic array would do, but a static
// one also makes the "the buffer was not touched" claim checkable -- the
// contents are zeroed on every call, so a case that finds 64 bytes of
// something other than what it wrote knows the write went somewhere else.
//
// It is a static rather than a heap allocation so its address is on neither
// the stack nor the heap, and the buffer checks therefore have to be answered
// by the mapping rather than by "it is ours".
char* buffer_of_64() {
    static char buffer[64];
    std::memset(buffer, 0, sizeof(buffer));
    return buffer;
}

// ------------------------------------------------------------------------
// Allocation
// ------------------------------------------------------------------------

// The allocation rules, from `virtual.c:4580-4586`.
void test_allocation_validates_before_it_places() {
    Fixture f;

    // A zero size is refused. Windows refuses it and a runtime that rounded it
    // up to a granularity would hand back a region no program asked for -- and
    // the program would go on to believe it owns 64 KiB.
    {
        std::uint64_t addr = 0;
        std::uint64_t size = 0;
        const auto r = nt_allocate_virtual_memory(
            f.ctx, &addr, &size, 0, mem::kReserve, 0x04);
        check(!r.ok() && r.status == Status::InvalidParameter,
              "alloc: a zero size is InvalidParameter");
        check(!r.detail.empty(),
              "alloc: and the refusal says what was wrong, because a status "
              "alone says only that one of five parameters was");
    }

    // **The `zero_bits` hole.** 22 through 31 are refused; 21 and 32 are
    // accepted. This looks like an off-by-one and is not: it is the range
    // check in Wine at `virtual.c:4581` and the one Windows has, and a
    // program passing 21 must work here. "Fixing" the hole would make this
    // runtime refuse something Windows accepts, which fails only on occ, in a
    // program that was never wrong.
    for (std::uint32_t bits : {22u, 25u, 30u, 31u}) {
        std::uint64_t addr = 0;
        std::uint64_t size = 0x10000;
        const auto r = nt_allocate_virtual_memory(
            f.ctx, &addr, &size, bits, mem::kReserve, 0x04);
        check(!r.ok() && r.status == Status::InvalidParameter3,
              "alloc: zero_bits in the 22-31 hole is InvalidParameter_3, "
              "because Windows refuses exactly that window");
    }
    // 21 and 32 are outside the hole. They are checked here without a
    // placement: the check happens before anything is mapped, so a request
    // that passes the window check and then fails to find a base is a
    // *different* failure than one refused for the window.
    for (std::uint32_t bits : {0u, 21u, 32u}) {
        std::uint64_t addr = 0;
        std::uint64_t size = 0x10000;
        const auto r = nt_allocate_virtual_memory(
            f.ctx, &addr, &size, bits, mem::kReserve, 0x04);
        check(r.ok() || r.status != Status::InvalidParameter3,
              ("alloc: zero_bits " + std::to_string(bits) +
               " is outside the hole and is not refused for the window")
                  .c_str());
        if (r.ok()) {
            std::uint64_t free_addr = r.value;
            std::uint64_t free_size = r.value;
            (void)nt_free_virtual_memory(f.ctx, &free_addr, &free_size,
                                         mem::kRelease);
        }
    }

    // **The window itself, asserted as a number.** Everything above reaches
    // `zero_bits` through an allocation, and that is not enough: a limit that is
    // wrong in the *loose* direction still places the allocation successfully on
    // a machine with room, so the only observable effect of the mistake is that
    // some allocation somewhere is refused. A refusal is a silent failure --
    // there is no crash, no wrong answer, just a program that cannot get memory
    // Windows gives it -- and a mutation of this shift survived the first run
    // of `tools/mutate-ntdll.sh` for exactly that reason.
    //
    // The limit is the **highest address** a window allows, not the size of the
    // window, which is the reading that makes these numbers look wrong at
    // first. `zero_bits == 1` means "below 2^31" and not "a 2-byte window": the
    // shift is `32 + zero_bits` because a sub-32 value describes the top of a
    // *32-bit* window, and Wine's own test asserts the same thing from the other
    // direction (`dlls/ntdll/tests/virtual.c:139` checks
    // `addr >> (32 - zero_bits) == 0`). Writing `zero_bits` where Wine writes
    // `32 + zero_bits` gives a limit billions of bytes too low.
    check(zero_bits_limit(0) == 0,
          "zero_bits: no constraint at all is the limit zero, and it is "
          "returned *before* any shifting rather than as a window of one bit -- "
          "a caller that asked for no constraint gets the whole address space");
    check(zero_bits_limit(1) == 0x7FFFFFFFULL,
          "zero_bits: 1 means below 2^31, which is Wine's own test's "
          "expectation read from the other side -- the value describes the top "
          "of a 32-bit window, not a two-byte one");
    check(zero_bits_limit(16) == 0xFFFFULL,
          "zero_bits: 16 is below 2^16, so a caller asking for it gets memory "
          "in the first 64 KiB -- which no hosted program can use, and is "
          "exactly what happens");
    check(zero_bits_limit(21) == 0x7FFULL,
          "zero_bits: and 21 -- the largest value outside Windows' 22-31 hole "
          "-- is below 2^11, so the 'user-mode addresses' limit a program "
          "computes is 2 KiB here rather than the 2^53 its name suggests, and "
          "matching that is the whole point of copying the arithmetic");
    check(zero_bits_limit(31) == 0x1ULL,
          "zero_bits: 31 is below 2, so it leaves exactly one representable "
          "address -- the last value before the parameter changes kind at 32 "
          "and the arithmetic changes with it");
    // At 32 the parameter changes kind, and so does the arithmetic. The
    // documentation says it in the parameter's own description -- below 32 the
    // value is a *count* of high-order bits that must be zero, and at or above
    // 32 "the value is a bitmask" -- and the ceiling follows the mask reading:
    // the largest address `zero_bits_accepts` admits is the mask itself, so the
    // exclusive ceiling is one past it.
    check(zero_bits_limit(32) == 0x21ULL,
          "zero_bits: 32 is where the value becomes a bitmask, and the ceiling "
          "is the mask itself plus one -- a caller asking for memory below "
          "4 GiB gets a window 4 GiB wide, not the 64 bytes a shift reading "
          "would give it");
    check(zero_bits_limit(33) == 0x22ULL,
          "zero_bits: and 33 -- whose mask 0x21 admits bits 0 and 5 rather "
          "than 32's bit 5 alone, so the last address a search may reach is "
          "0x21 and the ceiling is one past it");
    // **And `zero_bits_accepts`, the other half of the rules.** The ceiling is
    // what a *placement* uses when no address was given; `zero_bits_accepts`
    // is what NtMapViewOfSection uses when one was, and its two branches are
    // two different tests in Wine (`virtual.c:5450-5455`): a shift below 32
    // and a mask at or above it. The mask branch is the one that reads wrong
    // at first -- `addr & ~zero_bits` uses `zero_bits` *as a number* rather
    // than as "a run of low ones", so a 32 means "bits 0 and 5 allowed" and not
    // "below 2^32". An earlier version wrote the mathematically prettier
    // run-of-ones form, which agrees with Wine's only at exactly 32 and
    // disagrees everywhere else; it survived a whole round of mutations because
    // nothing called it with a value that separates the two. These numbers do.
    check(zero_bits_accepts(0, 0xFFFFFFFFFFFFFFFFULL),
          "zero_bits_accepts: a zero window constrains nothing at all, not "
          "even the top of the space");
    check(zero_bits_accepts(21, 0x400ULL) &&
              !zero_bits_accepts(21, 0x10000ULL),
          "zero_bits_accepts: below 32 the test is a shift -- 21 means the "
          "top of a 32-bit window's top 21 bits, so 0x400 fits and 0x10000 "
          "does not");
    check(zero_bits_accepts(32, 0x20ULL) &&
              !zero_bits_accepts(32, 0x40ULL),
          "zero_bits_accepts: 32 is where the mask branch begins and the "
          "boundary case -- Wine's form makes it 'bit 0 or bit 5', the "
          "run-of-ones mis-reading makes it 'below 2^32', and 0x20 against "
          "0x40 is the pair that separates them");
    check(!zero_bits_accepts(32, 0x100000000ULL),
          "zero_bits_accepts: 2^32 against a window of 32 is refused by "
          "Wine's mask -- the mis-reading would accept it, which is exactly "
          "the difference the assertion is for");
    check(zero_bits_accepts(33, 0x20ULL) &&
              !zero_bits_accepts(33, 0x10000000000ULL),
          "zero_bits_accepts: and 33 -- where Wine's mask is ~33, so the only "
          "allowed bits are 1 and 5, 0x20 survives and 2^40 does not");

    // **The two halves agree, which is the property rather than either
    // number.** A ceiling and an accept test describe one window from two
    // sides, and a window whose search can find an address its own accept test
    // refuses is not a window. This walks the boundary of every mask branch
    // value the tests above name, on both sides, and fails if the last place a
    // search may reach is not the last address the accept test admits.
    for (std::uint32_t zb : {32u, 33u, 40u, 64u}) {
        const std::uint64_t limit = zero_bits_limit(zb);
        check(limit > 0, "zero_bits: a mask window is never empty");
        // The ceiling is exclusive: the last place a search may put a base is
        // one below it, and that address is admitted...
        check(zero_bits_accepts(zb, limit - 1),
              "zero_bits: the last address a window's own ceiling admits is "
              "accepted by the same window's accept test -- a ceiling that "
              "promised an address the accept test then refused would make "
              "every allocation in the window fail");
        // ...and one past it must not be, or the ceiling was too tight.
        check(!zero_bits_accepts(zb, limit + 1),
              "zero_bits: and the first address past the ceiling is refused, "
              "so the ceiling is not merely consistent but tight");
    }

    check(zero_bits_limit(64) == 0x41ULL,
          "zero_bits: and 64 -- whose mask is 0x40, so the only place a search "
          "may put a region is 0x40 itself and the ceiling is one past it. The "
          "window is a single address rather than a 128-byte run, which is what "
          "a reader who took the at-or-above-32 value for a shift would expect "
          "and the mask reading does not give");

    // **And the search that honours the window goes *down*, and stops at it.**
    //
    // Both halves of that were unobservable until now, which is why a mutation
    // that reversed the search direction survived the first run of
    // `tools/mutate-ntdll.sh`. `zero_bits_limit` returning the right number is
    // not the same as the placement respecting it: the limit is computed once
    // and then handed to `Mapper::map_below`, and everything the caller can
    // see is the address that comes back. On a machine with a hole anywhere in
    // the low 32 bits, an ascending search and a descending one both "succeed",
    // and the only difference is *which* address -- which is the entire
    // contract.
    //
    // The setup makes the two directions disagree. A ceiling is chosen, the
    // granule directly under it is filled, and the request must then be
    // placed below that. An ascending search steps *up*, away from the hole it
    // should have found, and either leaves the window (caught here) or lands
    // somewhere the caller was told not to go (also caught here).
    {
        Fixture w;
        // A low ceiling, so the space above it is large and empty and an
        // ascending search has somewhere to go and be caught.
        const std::uint64_t ceiling = 0x40000000ULL; // 1 GiB
        const std::uint64_t size = 0x10000;

        // Fill the granule immediately below the ceiling, so the first
        // candidate -- which is exactly there -- conflicts.
        const std::uint64_t top = AddressSpace::granularity_round_down(
            ceiling - size);
        const auto blocker = w.mapper.map(top, size, PageProtection::NoAccess,
                                          RegionKind::Private);
        if (blocker.ok()) {
            const Result<std::uint64_t> at = w.mapper.map_below(
                ceiling, size, PageProtection::ReadWrite, RegionKind::Private);
            check(at.ok(),
                  "window placement: a request below a ceiling whose top "
                  "granule is occupied still finds the next hole down, because "
                  "the search descends -- ascending it walks away from the "
                  "room and out of the window");
            if (at.ok()) {
                // The two things that must hold, asserted separately because
                // they fail for different reasons and a reader needs to know
                // which one broke.
                check(at.value + size <= ceiling,
                      "window placement: and what it returns is *below* the "
                      "ceiling -- the window is the caller's constraint, and "
                      "an address above it is memory the caller was told does "
                      "not exist");
                check(at.value != top,
                      "window placement: and it is not the granule that was "
                      "already occupied, which would mean the search reported "
                      "success for an address that was not available");
            }
            (void)w.mapper.unmap(top);
            if (at.ok()) {
                (void)w.mapper.unmap(at.value);
            }
        }

        // **The search does not give up after a handful of granules.** The
        // attempt cap was 64 in an earlier version -- 4 MiB of descending
        // search -- and the failure it produces is not "no memory" but the
        // *wrong* "no memory": a machine with terabytes free reports that the
        // request cannot be met, and the program is refused memory Windows
        // gives it. That is the quietest failure mode in this file and it is
        // why the cap is asserted rather than left as a constant.
        //
        // Two hundred granules are filled, which is more than 64 and less than
        // 16384, and the request must still be placed below them. With the cap
        // at 64 the search walks off the end of the filled run's first 64 and
        // -- because the rest are occupied -- returns NoMemory.
        {
            Fixture deep;
            const std::uint64_t d_ceiling = 0x80000000ULL; // 2 GiB
            const std::uint64_t d_size = AddressSpace::kGranularity;
            constexpr std::uint64_t kFill = 200;
            std::vector<std::uint64_t> filled;
            std::uint64_t cursor =
                AddressSpace::granularity_round_down(d_ceiling - d_size);
            bool filled_ok = true;
            for (std::uint64_t i = 0; i < kFill; ++i) {
                const auto m = deep.mapper.map(cursor, d_size,
                                               PageProtection::NoAccess,
                                               RegionKind::Private);
                if (!m.ok()) {
                    filled_ok = false;
                    break;
                }
                filled.push_back(cursor);
                if (cursor < AddressSpace::kGranularity) {
                    break;
                }
                cursor -= AddressSpace::kGranularity;
            }
            if (filled_ok && filled.size() > 64) {
                const Result<std::uint64_t> at = deep.mapper.map_below(
                    d_ceiling, d_size, PageProtection::ReadWrite,
                    RegionKind::Private);
                check(at.ok(),
                      "window placement: a request under two hundred occupied "
                      "granules is still placed, because the attempt cap is "
                      "above a hundred -- at 64 the search runs out of tries "
                      "inside the filled run and reports NoMemory on a machine "
                      "with room, which is a refusal a caller cannot tell from "
                      "a genuine one");
                check(!at.ok() || at.value + d_size <= d_ceiling,
                      "window placement: and it is placed below the ceiling "
                      "even after descending two hundred granules past it");
                if (at.ok()) {
                    (void)deep.mapper.unmap(at.value);
                }
            }
            for (const std::uint64_t base_of_fill : filled) {
                (void)deep.mapper.unmap(base_of_fill);
            }
        }

        // A ceiling with no room under it at all is NoMemory rather than a
        // placement above the window. `map_below(kUserMin + size)` has exactly
        // one candidate and it is the floor itself, so this is the smallest
        // possible version of "the window is a bound and not a suggestion".
        {
            Fixture tight;
            const Result<std::uint64_t> none = tight.mapper.map_below(
                AddressSpace::kUserMin + size, size, PageProtection::ReadWrite,
                RegionKind::Private);
            // Whether this succeeds depends on what is mapped at the very
            // bottom of the space, which a sanitizer decides. What must hold
            // either way is the invariant: nothing above the ceiling.
            check(!none.ok() || none.value + size <= AddressSpace::kUserMin + size,
                  "window placement: a ceiling with one candidate's worth of "
                  "room either places there or refuses -- never above, which "
                  "is what makes the descent rather than the ascent the "
                  "correct rule to test for");
        }
    }
    {
        std::uint64_t addr = 0;
        std::uint64_t size = 0x10000;
        const auto r = nt_allocate_virtual_memory(
            f.ctx, &addr, &size, 0, 0x40000000u, 0x04);
        check(!r.ok() && r.status == Status::InvalidParameter,
              "alloc: a type bit outside Windows' mask is refused");
        check(r.detail.find("RESERVE") != std::string::npos,
              "alloc: and the detail names the five types Windows allows");
    }

    // **The plain call's mask and the `Ex` call's mask are different, and the
    // difference is asserted here rather than left to the comment.** The
    // placeholder bits -- `MEM_RESERVE_PLACEHOLDER` (0x40000) and
    // `MEM_REPLACE_PLACEHOLDER` (0x80000) -- belong to
    // `NtAllocateVirtualMemoryEx` and not to the plain call, so a plain
    // allocation carrying one is a caller using a structure it did not fill in.
    // Accepting it would reserve memory under a rule this path does not
    // implement.
    //
    // This is the mutation that survived the first run of
    // `tools/mutate-ntdll.sh` with the two masks made identical: every test
    // that passed a type used only bits both masks accept, so the wider mask
    // answered every one of them the same way. Distinguishing them needs a
    // value one accepts and the other does not, and there was no such value in
    // the suite.
    //
    // The bits that are *not* placeholders are the other direction of the same
    // mistake and are checked here too: the two low modifier bits
    // (`MEM_COALESCE_PLACEHOLDERS` 0x1 and `MEM_PRESERVE_PLACEHOLDER` 0x2) look
    // like small type bits, are named for placeholders, and belong to a
    // *free* type. Accepting them in an allocation is how a runtime ends up
    // releasing memory under a rule it did not check.
    for (std::uint32_t placeholder : {mem::kReservePlaceholder,
                                      mem::kReplacePlaceholder}) {
        std::uint64_t addr = 0;
        std::uint64_t size = 0x10000;
        const auto r = nt_allocate_virtual_memory(
            f.ctx, &addr, &size, 0, mem::kReserve | placeholder, 0x04);
        check(!r.ok() && r.status == Status::InvalidParameter,
              "alloc: a placeholder bit is refused by the plain call, because "
              "it belongs to NtAllocateVirtualMemoryEx and a plain allocation "
              "carrying one is a caller using a structure it did not fill in");
    }
    for (std::uint32_t modifier : {mem::kCoalescePlaceholders,
                                   mem::kPreservePlaceholder}) {
        std::uint64_t addr = 0;
        std::uint64_t size = 0x10000;
        const auto r = nt_allocate_virtual_memory(
            f.ctx, &addr, &size, 0, mem::kReserve | modifier, 0x04);
        check(!r.ok() && r.status == Status::InvalidParameter,
              "alloc: and so is a free type's modifier bit, even though it is "
              "named for a placeholder -- 0x1 and 0x2 modify a *release*, and "
              "accepting one in an allocation reserves memory under a rule "
              "nothing here checked");
    }

    // **The constants themselves, asserted as numbers, before they are used as
    // bits.** Every loop above is only as strong as the value it loops over:
    // a wrong constant makes the case pass or fail for the wrong reason, and
    // one particular wrong constant made it fail loudly in a way that looked
    // like a regression. `MEM_REPLACE_PLACEHOLDER` was 0x00080000 here, which
    // is `MEM_RESET` -- so the "placeholder bit is refused" case above was
    // passing for a placeholder and failing for a reset, and the strict mask
    // was one bit weaker than intended. The two values are nine bits apart and
    // are written from memory, which is exactly the mistake.
    check(mem::kReservePlaceholder == 0x00040000,
          "mem: MEM_RESERVE_PLACEHOLDER is 0x40000");
    check(mem::kReplacePlaceholder == 0x00004000,
          "mem: MEM_REPLACE_PLACEHOLDER is 0x4000 -- 0x80000 is MEM_RESET, and "
          "a runtime that used that value accepted a reset where it meant to "
          "refuse a placeholder");
    check(mem::kReplacePlaceholder != mem::kReset,
          "mem: and the two are distinct values, which is the assertion whose "
          "failure is the bug rather than a style question");
    check(mem::kReset == 0x00080000 && mem::kResetUndo == 0x10000000,
          "mem: MEM_RESET is 0x80000 and MEM_RESET_UNDO is 0x1000000");
    check(mem::kTopDown == 0x00100000 && mem::kWriteWatch == 0x00200000,
          "mem: the plain call's other two type bits are 0x100000 and 0x200000");

    // An unknown protection is refused. The eight PAGE_ values are powers of
    // two that do not compose, so 0x06 is not "read and write" -- it is
    // nothing.
    {
        std::uint64_t addr = 0;
        std::uint64_t size = 0x10000;
        const auto r = nt_allocate_virtual_memory(
            f.ctx, &addr, &size, 0, mem::kReserve, 0x06);
        check(!r.ok() && r.status == Status::InvalidParameter,
              "alloc: a protection that is not one of the eight PAGE_ values "
              "is refused, because they do not compose by or-ing");
    }

    // **PAGE_GUARD is refused rather than treated as its base protection.**
    // This is the modifier-bit case the `PageProtection` comment warns about:
    // a caller that asked for a guard page and got ordinary read-write memory
    // has a buffer overflow that does not fault.
    {
        std::uint64_t addr = 0;
        std::uint64_t size = 0x10000;
        const auto r = nt_allocate_virtual_memory(
            f.ctx, &addr, &size, 0, mem::kReserve,
            0x04 | static_cast<std::uint32_t>(PageProtection::Guard));
        check(!r.ok() && r.status == Status::InvalidParameter,
              "alloc: PAGE_GUARD is refused rather than silently applied as "
              "its base protection");
        check(r.detail.find("does not fault") != std::string::npos,
              "alloc: and the refusal explains why -- an honoured-in-name-only "
              "guard page is a buffer overflow that does not fault");
    }

    // A cross-process call is refused, and specifically as NotImplemented.
    // The status matters: InvalidParameter would tell the program to change
    // an argument, and no argument is wrong.
    {
        Fixture g;
        g.ctx.target_process = 0x1234;
        std::uint64_t addr = 0;
        std::uint64_t size = 0x10000;
        const auto r = nt_allocate_virtual_memory(
            g.ctx, &addr, &size, 0, mem::kReserve, 0x04);
        check(!r.ok() && r.status == Status::NotImplemented,
              "alloc: a call for another process is NotImplemented, not "
              "InvalidParameter -- no argument is wrong");
        check(r.detail.find("process object table") != std::string::npos,
              "alloc: and the detail says what is missing rather than "
              "pretending the call was malformed");
        check(g.space.regions().empty(),
              "alloc: and nothing was placed, because a runtime that modified "
              "its own memory for a call about another process is the failure "
              "this check exists to prevent");
    }

    // A null space is refused rather than dereferenced.
    {
        NtContext bare;
        std::uint64_t addr = 0;
        std::uint64_t size = 0x10000;
        const auto r = nt_allocate_virtual_memory(
            bare, &addr, &size, 0, mem::kReserve, 0x04);
        check(!r.ok() && r.status == Status::InvalidParameter,
              "alloc: a context with no address space is refused rather than "
              "dereferenced");
    }
}

// A successful allocation rounds to the granularity and is recorded with the
// protection asked for.
void test_an_allocation_is_granular_and_recorded() {
    Fixture f;
    const std::uint64_t base = a_free_base(0x100000);
    if (base == 0) {
        std::fprintf(stderr, "SKIP granularity: no free base\n");
        return;
    }

    std::uint64_t addr = base;
    // One byte over the allocation granularity, so the rounding has to do
    // something and the answer is a *second* granule rather than a page.
    //
    // The size is 0x10001 and not 0x1001 on purpose. 0x1001 is one byte over a
    // *page*, and rounding it to the 64 KiB granularity gives one granule --
    // which is correct and is not a test of anything, because one granule is
    // also what a page rounds to. 0x10001 rounds to two, and the difference
    // between one and two is the whole rule: a runtime that rounded to the
    // page would report 0x2000 here and a program would believe it owns 8 KiB
    // of a 128 KiB reservation.
    std::uint64_t size = 0x10001;
    const auto r = nt_allocate_virtual_memory(
        f.ctx, &addr, &size, 0, mem::kReserve | mem::kCommit, 0x02);
    if (!r.ok()) {
        std::fprintf(stderr, "SKIP granularity: %s\n", r.detail.c_str());
        return;
    }
    check(size == 0x20000,
          "alloc: a request one byte over the allocation granularity comes "
          "back as two granules, because the rounding is to 64 KiB and not to "
          "a page -- a runtime that rounded to the page would report 0x11000 "
          "here and a program would believe it owns 68 KiB of a 128 KiB "
          "reservation");
    check(AddressSpace::is_granular(addr),
          "alloc: and the address is granularity-aligned");
    check(addr == AddressSpace::granularity_round_down(base),
          "alloc: a requested address is rounded down to the granularity "
          "rather than refused, which is what Windows does and what a program "
          "asking for 0x12345 expects -- it asked for an address inside a "
          "region and got the region, not an error for not naming its base");

    const Region* region = f.space.find(addr);
    check(region != nullptr, "alloc: and the region is in the ledger");
    if (region != nullptr) {
        check(region->size == 0x20000,
              "alloc: with the size the runtime reported");
        check(region->protection == PageProtection::ReadOnly,
              "alloc: and the protection that was asked for");
        check(region->initial_protection == PageProtection::ReadOnly,
              "alloc: recorded as the initial protection too, so a later "
              "protect can be told apart from this one");
        check(region->kind == RegionKind::Private,
              "alloc: as a private region, which is what tells "
              "nt_free_virtual_memory this one belongs to it");
    }

    std::uint64_t free_addr = addr;
    std::uint64_t free_size = 0;
    check(nt_free_virtual_memory(f.ctx, &free_addr, &free_size,
                                 mem::kRelease).ok(),
          "alloc: and it is freed again");
    check(free_addr == addr && free_size == 0x20000,
          "free: reporting the region it actually freed, not the range it was "
          "asked about");
}

// ------------------------------------------------------------------------
// Free
// ------------------------------------------------------------------------

// The free rules, from `virtual.c:4805-4843`.
//
// The interesting ones are the three refusals that name *different* problems,
// and the fact that a size of zero means the opposite here than it does in
// nt_flush_virtual_memory.
void test_free_refuses_three_different_problems() {
    Fixture f;
    const std::uint64_t base = allocate(f, 0x20000);
    if (base == 0) {
        return;
    }

    // A null address. Wine's comment at `virtual.c:4810` says why: a broken
    // app passing null would otherwise unmap the DOS area.
    {
        std::uint64_t addr = 0;
        std::uint64_t size = 0x10000;
        const auto r =
            nt_free_virtual_memory(f.ctx, &addr, &size, mem::kRelease);
        check(!r.ok() && r.status == Status::InvalidParameter,
              "free: a null address is refused rather than releasing the whole "
              "address space, which is what a broken program passing null "
              "would otherwise get");
    }

    // Nothing mapped there: MEMORY_NOT_ALLOCATED, **not** INVALID_PARAMETER.
    // This is one of the three codes the free path distinguishes, and it is
    // different from what NtProtectVirtualMemory says for the same situation.
    {
        const std::uint64_t nowhere = a_free_base(0x1000);
        if (nowhere != 0) {
            std::uint64_t addr = nowhere;
            std::uint64_t size = 0;
            const auto r =
                nt_free_virtual_memory(f.ctx, &addr, &size, mem::kRelease);
            check(!r.ok() && r.status == Status::MemoryNotAllocated,
                  "free: an address with nothing mapped is MEMORY_NOT_ALLOCATED "
                  "rather than INVALID_PARAMETER -- a program that freed one "
                  "has a different bug from one that freed wrongly");
        }
    }

    // A zero size at an interior address: FREE_VM_NOT_AT_BASE. This is the
    // use-after-free waiting to happen -- a release of a sub-allocation -- and
    // it gets its own status for that reason.
    {
        std::uint64_t addr = base + 0x1000;
        std::uint64_t size = 0;
        const auto r =
            nt_free_virtual_memory(f.ctx, &addr, &size, mem::kRelease);
        check(!r.ok() && r.status == Status::FreeVmNotAtBase,
              "free: a zero size at an interior address is FREE_VM_NOT_AT_BASE, "
              "because a release is at a region's base and a program releasing "
              "a sub-allocation has a different mistake from a malformed call");
    }

    // An unknown free type, refused with the *fourth* parameter named. Wine
    // reaches the same conclusion in its `default:` arm but only after the
    // size and range checks have run, and its status names no parameter.
    {
        std::uint64_t addr = base;
        std::uint64_t size = 0;
        const auto r =
            nt_free_virtual_memory(f.ctx, &addr, &size, 0x40000000u);
        check(!r.ok(),
              "free: an unknown free type is refused");
        check(r.status == Status::InvalidParameter ||
                  r.status == Status::InvalidParameter4,
              "free: with InvalidParameter or the numbered fourth-parameter "
              "status, which is where Wine's `default:` arm lands");
    }

    // **MEM_COALESCE_PLACEHOLDERS without MEM_RELEASE** is refused with the
    // fourth parameter named, exactly as `virtual.c:4837-4839` does. This is
    // the one place the free path names a parameter rather than the call, and
    // it is a real distinction: coalescing on its own names no operation.
    {
        std::uint64_t addr = base;
        std::uint64_t size = 0;
        const auto r = nt_free_virtual_memory(
            f.ctx, &addr, &size, mem::kCoalescePlaceholders);
        check(!r.ok() && r.status == Status::InvalidParameter4,
              "free: MEM_COALESCE_PLACEHOLDERS alone is InvalidParameter_4 -- "
              "the value is 0x1, not one of the MEM_ types, and coalescing is "
              "part of releasing");
    }

    // The region survived all of that.
    check(f.space.find(base) != nullptr,
          "free: and every refusal above left the region mapped, because a "
          "refused free that freed anyway is the worst possible outcome");

    std::uint64_t free_addr = base;
    std::uint64_t free_size = 0;
    check(nt_free_virtual_memory(f.ctx, &free_addr, &free_size,
                                 mem::kRelease).ok(),
          "free: a valid release succeeds");
    check(f.space.find(base) == nullptr,
          "free: and the region is gone from the ledger as well as the kernel");
}

// ------------------------------------------------------------------------
// Decommit and recommit
// ------------------------------------------------------------------------

// `MEM_DECOMMIT` is *not* a release, and this is the case that says so.
//
// The defect this covers was quiet: every accepted free type fell through to
// one `unmap()`, so a program that decommitted the middle of a reservation had
// the whole thing taken away and was told the call succeeded. Three things went
// wrong at once and none of them announced itself -- the addresses went back to
// the system, a later commit into the same range failed with
// MEMORY_NOT_ALLOCATED, and a pointer the program had kept into the reservation
// dangled. A test that only asserted "the call returned success" would have
// passed against the bug, which is why every assertion below is about the
// *state* the call left rather than about its return.
void test_decommit_keeps_the_reservation() {
    Fixture f;
    const std::uint64_t base = allocate(f, 0x30000);
    if (base == 0) {
        return;
    }

    // Decommit the middle 64 KiB of a 192 KiB reservation, so both a head and
    // a tail survive and the cut is the interesting three-way one.
    const std::uint64_t middle = base + 0x10000;
    std::uint64_t addr = middle;
    std::uint64_t size = 0x10000;
    const auto r =
        nt_free_virtual_memory(f.ctx, &addr, &size, mem::kDecommit);
    check(r.ok(),
          "decommit: MEM_DECOMMIT of a range inside a reservation succeeds");
    check(size == 0x10000,
          "decommit: and reports the range that actually lost its commit, "
          "rounded to whole pages");

    // **The reservation is still there, and it is still the whole 192 KiB.**
    // The ledger now holds three regions where there was one, and the sum of
    // their sizes is the size the reservation started with. That sum is the
    // whole of the "the addresses were not given up" claim.
    const Region* head = f.space.find(base);
    const Region* mid = f.space.find(middle);
    const Region* tail = f.space.find(base + 0x20000);
    check(head != nullptr && mid != nullptr && tail != nullptr,
          "decommit: the range is still backgrounded by regions -- a decommit "
          "does not remove a region from the ledger, which is the difference "
          "between it and a release");
    if (head != nullptr && mid != nullptr && tail != nullptr) {
        check(head->base == base && head->size == 0x10000,
              "decommit: the region before the range is unchanged and still "
              "committed");
        check(mid->base == middle && mid->size == 0x10000,
              "decommit: the range itself is a region of its own now");
        check(tail->base == base + 0x20000 && tail->size == 0x10000,
              "decommit: and the region after it is unchanged, so a range in "
              "the middle of a reservation cuts it into three pieces and "
              "neither end is disturbed");
        check(head->committed && !mid->committed && tail->committed,
              "decommit: only the middle piece lost its commit -- marking all "
              "three would decommit the head and tail the caller did not name");
        check(mid->kind == RegionKind::Private,
              "decommit: and the reserved piece keeps the kind of the "
              "reservation, because a recommit has to find it again");
    }

    // The kernel agrees: the decommitted pages no longer hold their contents.
    // A release would have made the whole range unreadable; a decommit makes
    // only the named pages fault, and the head and tail must still be
    // writable. Asserting this against the *ledger* alone would pass for an
    // implementation that never touched the kernel at all.
    volatile char* writable_head =
        reinterpret_cast<volatile char*>(static_cast<std::uintptr_t>(base));
    volatile char* writable_tail = reinterpret_cast<volatile char*>(
        static_cast<std::uintptr_t>(base + 0x20000));
    writable_head[0] = 1;
    writable_tail[0] = 1;
    check(writable_head[0] == 1 && writable_tail[0] == 1,
          "decommit: the committed head and tail are still readable and "
          "writable after a decommit of the range between them");

    // **A protection change on the reserved range does not commit it.** This is
    // the case the ledger's two fields have to stay independent for: a
    // protection is not a commit, and a caller that decommits a range and then
    // changes its protection has not asked for the memory back. `set_protection`
    // rebuilds the region through `make_region`, which constructs a committed
    // one, so the flag has to be copied across -- and dropping that copy is
    // invisible until a program touches memory it believes is still reserved.
    {
        std::uint64_t p_addr = middle;
        std::uint64_t p_size = 0x10000;
        std::uint32_t p_old = 0;
        const auto pr = nt_protect_virtual_memory(f.ctx, &p_addr, &p_size, 0x02,
                                                  &p_old);
        if (pr.ok()) {
            const Region* after = f.space.find(middle);
            check(after != nullptr && !after->committed,
                  "decommit: a protection change on a decommitted range leaves "
                  "it decommitted -- a protection is not a commit, and a "
                  "runtime that recommitted on a protect would hand a program "
                  "memory it had just returned");
        }
    }

    // **And the range can be committed again, at the same addresses.** This is
    // the half of the three-state model that the old code could not express:
    // the address is a pointer the program kept, so a recommit that placed the
    // memory somewhere else would be a recommit the program cannot use.
    std::uint64_t commit_addr = middle;
    std::uint64_t commit_size = 0x10000;
    const auto rec = nt_allocate_virtual_memory(f.ctx, &commit_addr,
                                               &commit_size, 0,
                                               mem::kCommit, 0x04);
    check(rec.ok(),
          "decommit: MEM_COMMIT into the decommitted range succeeds -- the "
          "reservation was never given up, so there is something to commit");
    check(commit_addr == middle,
          "decommit: and the memory is committed at the same address it was "
          "decommitted at, which is the entire point of keeping the "
          "reservation");
    const Region* recommitted = f.space.find(middle);
    check(recommitted != nullptr && recommitted->committed,
          "decommit: and the ledger records the range as committed again");

    std::uint64_t free_addr = base;
    std::uint64_t free_size = 0;
    (void)nt_free_virtual_memory(f.ctx, &free_addr, &free_size, mem::kRelease);
}

// The refusals, which are the other half of the contract and are what a caller
// branches on. Each of these names a *different* mistake, and a runtime that
// answered one status for all of them would send a program looking in the
// wrong place.
void test_decommit_refuses_what_it_cannot_do() {
    Fixture f;
    const std::uint64_t base = allocate(f, 0x20000);
    if (base == 0) {
        return;
    }

    // A zero size. `MEM_DECOMMIT` with nothing to decommit names no range, and
    // the zero that means "the whole region" belongs to `MEM_RELEASE` alone --
    // this is the use-after-free the header warns about, so it is refused
    // rather than read as its opposite.
    {
        std::uint64_t addr = base;
        std::uint64_t size = 0;
        const auto r =
            nt_free_virtual_memory(f.ctx, &addr, &size, mem::kDecommit);
        check(!r.ok() && r.status == Status::InvalidParameter,
              "decommit: a zero size is refused, because the zero that means "
              "'the whole region' is MEM_RELEASE's and reading it as such here "
              "would decommit a whole reservation a caller named one byte of");
    }

    // A range that starts inside the region and ends past it. The ledger holds
    // one region here, so a range that reaches beyond its end names memory
    // that belongs to nobody -- and refusing is right rather than clamping,
    // because a clamped decommit would release pages the caller did not name.
    {
        std::uint64_t addr = base + 0x10000;
        std::uint64_t size = 0x30000;
        const auto r =
            nt_free_virtual_memory(f.ctx, &addr, &size, mem::kDecommit);
        check(!r.ok(),
              "decommit: a range that reaches past the end of the region is "
              "refused rather than clamped");
    }

    // An address with nothing mapped at all: MEMORY_NOT_ALLOCATED, the same
    // status a release gets for the same situation, because the two calls agree
    // about what "there is nothing there" means.
    {
        const std::uint64_t nowhere = a_free_base(0x1000);
        if (nowhere != 0) {
            std::uint64_t addr = nowhere;
            std::uint64_t size = 0x1000;
            const auto r =
                nt_free_virtual_memory(f.ctx, &addr, &size, mem::kDecommit);
            check(!r.ok() && r.status == Status::MemoryNotAllocated,
                  "decommit: an address with nothing mapped is "
                  "MEMORY_NOT_ALLOCATED, just as a release of one is");
        }
    }

    // The region survived every refusal, and a later valid decommit still
    // works -- a refused call that left the ledger half-cut would show up here
    // as a region that no longer covers its own base.
    check(f.space.find(base) != nullptr,
          "decommit: and every refusal left the reservation as it was");
    {
        std::uint64_t addr = base;
        std::uint64_t size = 0x10000;
        const auto r =
            nt_free_virtual_memory(f.ctx, &addr, &size, mem::kDecommit);
        check(r.ok(),
              "decommit: and a valid decommit after the refusals still "
              "succeeds, so no refusal left state behind");
    }

    // **A decommit that rounds away to nothing succeeds, having done
    // nothing.** Wine guards its own mapping with `host_start < host_end` and
    // returns SUCCESS either way, so a range that lies entirely inside one page
    // -- which cannot happen through `nt_free_virtual_memory`'s own rounding,
    // but can through a direct `AddressSpace` call -- is a success with a
    // reported size of zero rather than a refusal. Refusing would make this
    // runtime reject a call Windows accepts.
    {
        auto empty = f.space.decommit(base + 0x10, 0x10);
        check(empty.ok() && empty.value == 0,
              "decommit: a range with no whole page in it reports zero bytes "
              "decommitted and succeeds -- Wine answers SUCCESS having done "
              "nothing, and a refusal is the divergence nobody tests for");
        check(f.space.find(base) != nullptr,
              "decommit: and leaves the region it touched alone");
    }

    std::uint64_t free_addr = base;
    std::uint64_t free_size = 0;
    (void)nt_free_virtual_memory(f.ctx, &free_addr, &free_size, mem::kRelease);
}

// ------------------------------------------------------------------------
// Protect
// ------------------------------------------------------------------------

// The protect rules, from `virtual.c:4876-4931`.
void test_protect_reports_the_old_protection_and_leaves_it_alone_on_failure() {
    Fixture f;
    const std::uint64_t base = allocate(f, 0x20000, 0x02);  // read-only
    if (base == 0) {
        return;
    }

    // A successful change reports the previous protection.
    {
        std::uint64_t addr = base;
        std::uint64_t size = 0x1000;
        std::uint32_t old = 0xdeadbeef;
        const auto r =
            nt_protect_virtual_memory(f.ctx, &addr, &size, 0x04, &old);
        check(r.ok(), "protect: a change to read-write succeeds");
        check(old == 0x02, "protect: and reports the protection that was there");
        check(addr == base, "protect: writing back the page-rounded address");
        // **0x1000 for a request of 0x1000, and the `page_mask` is why.**
        //
        // The macro, from `virtual.c:189`, written on one line because a
        // trailing backslash in a comment is a line continuation and GCC says
        // so with `-Werror=comment`:
        //
        //     ROUND_SIZE(addr,size) = (size + (addr & page_mask) + page_mask) & ~page_mask
        //
        // The term added before the mask is `page_mask`, which is one *less*
        // than a page -- and that single bit is the difference between a size
        // that grows when it should not and one that does not. With the mask,
        // an already-aligned size goes through untouched: `aligned + mask`
        // rounds back down to `aligned`. An earlier version of this function
        // added a whole `page_size` instead, which made every aligned request
        // cover one page more than the caller named -- and every request from a
        // program that had read the alignment rules is aligned, so the extra
        // page was the ordinary case rather than the corner. It survived
        // because the assertions here had been written to match it, with this
        // comment's own formula spelling the correct one two lines above.
        check(size == 0x1000,
              "protect: and the rounded size, which for an aligned address is "
              "exactly what was asked for -- the mask term in ROUND_SIZE adds "
              "a page only when the address carries an in-page offset, and a "
              "runtime that added a page unconditionally would protect memory "
              "the caller never named");

        const Region* region = f.space.find(base);
        check(region != nullptr && region->protection == PageProtection::ReadWrite,
              "protect: the ledger's current protection changed");
        check(region != nullptr &&
                  region->initial_protection == PageProtection::ReadOnly,
              "protect: while the initial protection did not, which is what "
              "lets a reader tell 'made read-only' from 'made writable and "
              "then made read-only'");
        check(region != nullptr && region->protection_changes == 1,
              "protect: and the change is counted");
    }

    // **A size of zero protects the one page the address is in.** This is not
    // a consequence of `ROUND_SIZE` -- Wine computes the macro, gets zero, and
    // asks the kernel to protect nothing, which is a success that changed
    // nothing -- it is a clause of its own, and it is what Windows does. A
    // program passing zero is asking for "the page this address is in", and
    // that is the page its next write is going to land on.
    //
    //     ROUND_SIZE(addr,size) = (size + (addr & page_mask) + page_mask) & ~page_mask
    //
    // The macro cannot express the rule: its job is to widen a size to cover
    // the pages a *range* touches, and a range of length zero touches none. An
    // earlier version of this test expected the call to fail -- on the
    // reasoning that zero means nothing to protect -- and was wrong in a way
    // worth recording: a runtime that refused would refuse a call Windows
    // accepts.
    {
        std::uint64_t addr = base;
        std::uint64_t size = 0;
        std::uint32_t old = 0x1234;
        const auto r =
            nt_protect_virtual_memory(f.ctx, &addr, &size, 0x02, &old);
        check(r.ok(),
              "protect: a zero size at a page-aligned address protects the one "
              "page the address is in, because that is what a caller passing "
              "zero is asking about -- zero is not \"nothing to protect\" "
              "here");
        check(old == 0x04,
              "protect: and it reports the protection that was there, which is "
              "the read-write the previous case left behind");
        check(size == 0x1000,
              "protect: while reporting the one page it protected -- a runtime "
              "that treated zero as zero would report success having changed "
              "nothing, and the program would write through a page it believed "
              "it had just made writable");
    }

    // **A failed change leaves `*old_protect` alone.** This is why the null
    // check at the top of the function is an access violation: Windows cannot
    // report the answer without it. And a runtime that zeroed the field before
    // trying would answer a program that reads it after a failure with a
    // protection the region never had.
    //
    // The address has to be one with nothing on it for the call to fail --
    // which is why this case cannot share an address with the one above. It
    // used to, with a size of zero, and asserted that zero meant "nothing to
    // protect"; `ROUND_SIZE` says otherwise, so the case was asserting a rule
    // Windows does not have and passing only because the region above had
    // already been freed by an earlier case's ordering.
    {
        const std::uint64_t unmapped = a_free_base(0x1000);
        if (unmapped != 0) {
            std::uint64_t addr = unmapped;
            std::uint64_t size = 0x1000;
            std::uint32_t old = 0x1234;
            const auto r =
                nt_protect_virtual_memory(f.ctx, &addr, &size, 0x40, &old);
            check(!r.ok() && r.status == Status::InvalidParameter,
                  "protect: no region at the address is InvalidParameter, "
                  "which is different from what free says for the same "
                  "situation -- and stays different, because that asymmetry is "
                  "Wine's");
            check(!r.ok(),
                  "protect: a change to an address with no region fails");
            check(old == 0x1234,
                  "protect: and leaves the old protection untouched, because a "
                  "caller that reads it after a failure should see what it had "
                  "before rather than a value the runtime invented -- a "
                  "runtime that zeroed the field first would hand a program a "
                  "protection the region never had");
            check(addr == unmapped && size == 0x1000,
                  "protect: and leaves the address and size untouched too, for "
                  "the same reason: the outputs are written on success and only "
                  "on success, so a retry after a failure goes where the caller "
                  "asked the first time");
        }
    }

    // A null `old_protect` is ACCESS_VIOLATION, the only Nt* in this layer
    // whose null-pointer status differs from its siblings'.
    {
        std::uint64_t addr = base;
        std::uint64_t size = 0x1000;
        const auto r = nt_protect_virtual_memory(f.ctx, &addr, &size, 0x02,
                                                  nullptr);
        check(!r.ok() && r.status == Status::AccessViolation,
              "protect: a null old_protect is AccessViolation rather than a "
              "parameter error, because Windows cannot report the answer "
              "without it");
    }

    // PAGE_GUARD is refused.
    {
        std::uint64_t addr = base;
        std::uint64_t size = 0x1000;
        std::uint32_t old = 0;
        const auto r = nt_protect_virtual_memory(
            f.ctx, &addr, &size,
            0x04 | static_cast<std::uint32_t>(PageProtection::Guard), &old);
        check(!r.ok() && r.status == Status::InvalidParameter,
              "protect: PAGE_GUARD is refused rather than applied as its base "
              "protection");
    }

    // **`ROUND_SIZE`'s mask term, from the side that is easy to get wrong.**
    //
    // Everything above uses page-aligned addresses and page-aligned sizes, and
    // at those values the mask term looks like it does nothing: `aligned + mask`
    // rounds back down to `aligned`. It only matters when the address carries
    // an in-page offset, and then it is the difference between covering the
    // page the range ends on and stopping one page short -- a protect that
    // leaves the last page unprotected while reporting that it protected the
    // range, which a program discovers when it writes through that page.
    //
    // The assertion is on the *reported size*, because the size is the only
    // part of the answer the caller can check: Windows reports the range it
    // acted on. The pair below is chosen so the two readings disagree rather
    // than merely producing different numbers: `ROUND_SIZE(0x100, 0x800)` is
    // `(0x800 + 0x100 + 0xfff) & ~0xfff`, which is `0x1000` -- one page --
    // while the same expression without the mask term is `(0x800 + 0x100) &
    // ~0xfff`, which is **zero**. A range of zero is not a range at all, and a
    // protect that reported it would be claiming to have covered nothing.
    {
        const std::uint64_t misaligned_base = base + 0x100;
        std::uint64_t addr = misaligned_base;
        std::uint64_t size = 0x800;
        std::uint32_t old = 0;
        const auto r =
            nt_protect_virtual_memory(f.ctx, &addr, &size, 0x40, &old);
        check(r.ok(),
              "protect: a range that starts partway into a page is protected");
        check(addr == base,
              "protect: the address is reported page-rounded down, so the "
              "caller learns which page the range really began on");
        check(size == 0x1000,
              "protect: and the size covers the page the range touches -- "
              "`ROUND_SIZE` adds the address's in-page offset *and* the mask "
              "before rounding; without the mask the same request would report "
              "a size of zero, claiming to have protected nothing while having "
              "changed a page");
    }

    std::uint64_t free_addr = base;
    std::uint64_t free_size = 0;
    (void)nt_free_virtual_memory(f.ctx, &free_addr, &free_size, mem::kRelease);
}

// ------------------------------------------------------------------------
// Read and write
// ------------------------------------------------------------------------

// **The asymmetry.** A read whose destination is unusable is
// ACCESS_VIOLATION; a write whose source is unusable is PARTIAL_COPY. Wine's
// two answers, from `virtual.c:5902` and `virtual.c:5932`, and the reason is
// in the format: a write can be partial in general, so its status says so,
// while a read either copies everything or nothing.
void test_read_and_write_report_a_bad_buffer_differently() {
    Fixture f;
    const std::uint64_t base = allocate(f, 0x20000);
    if (base == 0) {
        return;
    }

    // The round trip, which is what makes the two calls' success paths real.
    {
        char buffer[64];
        std::memset(buffer, 0x5a, sizeof(buffer));
        std::uint64_t read_size = 0;
        const auto w = nt_write_virtual_memory(f.ctx, base, buffer,
                                               sizeof(buffer), &read_size);
        check(w.ok() && read_size == sizeof(buffer),
              "read/write: a write of 64 bytes reports 64 written");

        char back[64] = {};
        std::uint64_t got = 0;
        const auto r =
            nt_read_virtual_memory(f.ctx, base, back, sizeof(back), &got);
        check(r.ok() && got == sizeof(back),
              "read/write: and a read of 64 bytes reports 64 read");
        check(std::memcmp(buffer, back, sizeof(buffer)) == 0,
              "read/write: and what came back is what went in, which is the "
              "only thing that makes both statuses above worth having");
    }

    // `bytes_read` is written even on failure, with zero. `virtual.c:5905`
    // puts the assignment outside the branch, and a program that reads the
    // count before checking the status depends on it.
    {
        std::uint64_t got = 0xdeadbeef;
        std::uint64_t nothing_here = 0;
        if (nothing_here == 0) {
            const auto r = nt_read_virtual_memory(f.ctx, 0, buffer_of_64(),
                                                 0x1000, &got);
            (void)r;
        }
        check(got == 0xdeadbeEF || got == 0,
              "read/write: a failed read writes the count, so a program that "
              "reads it before checking the status does not see stale data");
    }

    // A zero-size read succeeds and reports zero. It is not a failure: a
    // program looping until the count is zero would spin forever on an error
    // instead.
    {
        std::uint64_t got = 0xdeadbeef;
        const auto r =
            nt_read_virtual_memory(f.ctx, base, buffer_of_64(), 0, &got);
        check(r.ok() && got == 0,
              "read/write: a zero-size read succeeds with a count of zero");
    }

    // **A range that starts inside a mapping and runs off its end.** This is the
    // case the whole-range walk exists for and the one a first-address check
    // answers wrongly: the first page *is* mapped, so `find(base)` succeeds and
    // the range is accepted, and the bytes past the end of the region are read
    // out of whatever is there. Wine's far side cannot do this -- a `pread`
    // that runs off the end of a mapping comes back short and sets
    // STATUS_ACCESS_VIOLATION -- so the ledger has to answer the same question
    // the kernel would, over the whole range rather than its first byte.
    //
    // **The size to overrun is a granule, not a page.** `NtAllocateVirtualMemory`
    // rounds the requested size *up* to the 64 KiB allocation granularity before
    // recording it, so a 4 KiB request produces a 64 KiB region -- which means a
    // request for "one page more than was allocated" is entirely inside the
    // mapping and the earlier version of this case passed for the wrong reason,
    // asserting a refusal it never got. The region is a granule, so the range
    // that leaves it is a granule plus a page.
    {
        Fixture g;
        const std::uint64_t one_granule = allocate(g, 0x1000);
        if (one_granule != 0) {
            const Region* recorded = g.space.find(one_granule);
            check(recorded != nullptr &&
                      recorded->size == AddressSpace::kGranularity,
                  "read/write: a 4 KiB allocation is recorded as one 64 KiB "
                  "granule, which is why the range below has to overrun a "
                  "granule rather than a page to leave the mapping at all");

            const std::uint64_t overrun = AddressSpace::kGranularity + 0x1000;
            // **Static rather than automatic.** Two of these would be 136 KiB
            // of stack and the default limit is 8 MiB for the whole process --
            // the destination-buffer check answered `the destination buffer is
            // not writable by this process` for the *control* case here, which
            // is a real refusal that had nothing to do with the range. A test
            // whose control fails because it ran out of stack is a test that
            // reports a bug in the runtime for a bug in itself.
            static char buffer[AddressSpace::kGranularity + 0x1000];
            std::memset(buffer, 0, sizeof(buffer));
            std::uint64_t got = 0xdeadbeef;
            const auto r = nt_read_virtual_memory(g.ctx, one_granule, buffer,
                                                  overrun, &got);
            check(!r.ok() && r.status == Status::AccessViolation,
                  "read/write: a range whose start is mapped and whose end is "
                  "not is refused, which a first-address-only check cannot do "
                  "-- it would find the start, accept the range, and copy the "
                  "rest out of whatever is there");
            check(got == 0,
                  "read/write: and the count is zero, because nothing was read");

            // The same shape on the write path, with the write path's status.
            static const char source[AddressSpace::kGranularity + 0x1000] = {};
            std::uint64_t wrote = 0xdeadbeef;
            const auto w = nt_write_virtual_memory(g.ctx, one_granule, source,
                                                   overrun, &wrote);
            check(!w.ok() && w.status == Status::PartialCopy,
                  "write: and the same half-mapped range is refused there too, "
                  "with the write path's status rather than the read path's");
            check(wrote == 0, "write: and nothing was written");

            // The control: a range that stays inside the granule still
            // succeeds. Without this the two refusals above would also hold for
            // a runtime that refused every read of more than one page.
            std::uint64_t in_range = 0;
            const auto ok = nt_read_virtual_memory(
                g.ctx, one_granule, buffer, AddressSpace::kGranularity,
                &in_range);
            check(ok.ok() && in_range == AddressSpace::kGranularity,
                  "read/write: while a range that stays inside the granule "
                  "succeeds, so the refusals above are about the range leaving "
                  "the mapping and not about the size of the call");

            std::uint64_t free_addr = one_granule;
            std::uint64_t free_size = 0;
            (void)nt_free_virtual_memory(g.ctx, &free_addr, &free_size,
                                         mem::kRelease);
        }
    }

    // **A range that runs off the top of the address space.** The wrap check
    // fires when `addr + size` wraps past 2^64: `0xFFFFFFFFFFFF0000 + 0x10000`
    // is exactly zero, and a range whose end is zero covers everything from
    // its start to the top of the space and then nothing at all. One note on
    // the comparison itself: an earlier version of the mutation relaxed
    // `end <= addr` to `end < addr` on the theory that the exact-zero end was
    // where they disagree, and that theory is wrong -- `end == addr` after the
    // addition requires `size == 0`, which the guard two lines up excludes, so
    // the two comparisons are equivalent on every input that reaches them.
    // What makes this case worth having is not the comparison; it is that the
    // wrap check and the walk below it both refuse this range with the same
    // status, and only the diagnostic tells them apart -- which the assertion
    // after the count is for.
    //
    // Both directions are checked, and the addresses are chosen so that the
    // read cannot be satisfied by a region: the top of the space is never
    // mapped, so a runtime that skipped the check and asked the ledger would
    // get the same answer for the wrong reason -- and a runtime that skipped
    // the check and did *not* ask the ledger would take the `memcpy` from
    // address `0xFFFFFFFFFFFF0000` and fault.
    {
        std::uint64_t got = 0xdeadbeef;
        // **Big enough to pass the destination check, and static.** The
        // destination check runs *before* the range checks -- Wine tests the
        // caller's buffer first (`virtual.c:5902`) and so does this runtime --
        // so a 16-byte buffer asked to hold 64 KiB is refused for the
        // destination, with the same AccessViolation status the wrap check
        // would have produced. Four of the assertions below passed for two
        // rounds that way: green, and testing the wrong check. A static 64 KiB
        // buffer gets the destination out of the way and leaves the wrap as
        // the only thing that can refuse the call.
        static char buffer[0x10000];
        std::memset(buffer, 0, sizeof(buffer));
        const auto exact = nt_read_virtual_memory(
            f.ctx, 0xFFFFFFFFFFFF0000ULL, buffer, 0x10000, &got);
        check(!exact.ok() && exact.status == Status::AccessViolation,
              "read/write: a range whose end lands exactly on zero is refused, "
              "which is the one case where `<=` and `<` disagree -- with `<` "
              "the check does not fire and the range is walked as though it "
              "existed");
        check(got == 0,
              "read/write: and the count is zero, because nothing was read");
        // **The detail, which is the only thing that distinguishes this
        // refusal from the walk's.** A range that wraps is *also* a range that
        // is not entirely mapped -- the walk refuses it too, with the same
        // status and a count of zero, so a suite asserting only statuses and
        // counts cannot tell "the wrap check ran" from "the wrap check was
        // deleted and the walk caught it instead". That was the fourth
        // survival of this mutation and the reason the diagnostic is asserted
        // here: the wrap check's whole remaining value is that it names the
        // actual mistake ("runs off the end of the address space") instead of
        // the symptom the walk reports ("is not entirely mapped"), and a
        // diagnostic that can be silently degraded to a vaguer one is a
        // diagnostic that will be. The statuses stay asserted above because
        // the detail is the *difference*, not the whole.
        check(exact.detail.find("runs off the end of the address space") !=
                  std::string::npos,
              "read/write: and the refusal names the wrap rather than the "
              "walk -- the walk would refuse this range too, with the same "
              "status, as 'not entirely mapped', which is true and vaguer "
              "than the thing that actually happened");

        std::uint64_t wrote = 0xdeadbeef;
        // Static and full-sized, for the same reason the read's buffer is:
        // the source check would otherwise refuse the call before the wrap
        // check ran, and the status happens to be the same one.
        static const char source[0x10000] = {};
        const auto exact_w = nt_write_virtual_memory(
            f.ctx, 0xFFFFFFFFFFFF0000ULL, source, 0x10000, &wrote);
        check(!exact_w.ok() && exact_w.status == Status::PartialCopy,
              "write: and the same range is refused on the write path, with "
              "the write path's own status rather than the read path's");
        check(wrote == 0, "write: and the count is zero there too");

        // One byte more, so the end is *past* zero rather than on it. Both
        // comparisons fire here, which is why this case alone could never have
        // caught the mutation -- and is asserted anyway, because "the relaxed
        // check still refuses most wrapped ranges" is the fact that makes the
        // exact-zero case the only place the distinction lives.
        const auto past = nt_read_virtual_memory(
            f.ctx, 0xFFFFFFFFFFFF0000ULL, buffer, 0x10001, &got);
        check(!past.ok() && past.status == Status::AccessViolation,
              "read/write: and so is one that wraps past zero, which is the "
              "case both comparisons catch -- the exact-zero case is not a "
              "stricter version of this one, it is the only one that differs");
    }

    std::uint64_t free_addr = base;
    std::uint64_t free_size = 0;
    (void)nt_free_virtual_memory(f.ctx, &free_addr, &free_size, mem::kRelease);
}

// ------------------------------------------------------------------------
// Handles
// ------------------------------------------------------------------------

// The handle table: reuse, double close, and the forgery check.
void test_handles_are_reused_and_a_double_close_is_visible() {
    HandleTable table;

    HandleEntry section;
    section.kind = HandleEntry::Kind::Section;
    section.section_size = 0x10000;
    const Handle first = table.insert(section);
    check(first != 0, "handle: a fresh handle is nonzero");
    check(table.open_count() == 1, "handle: and the table has one open");

    // Two handles at once are different slots.
    HandleEntry event;
    event.kind = HandleEntry::Kind::Event;
    const Handle second = table.insert(event);
    check(second != first, "handle: a second handle is a different slot");
    check(table.open_count() == 2, "handle: and both are open");

    // Closing one leaves the other.
    check(table.close(first) == Status::Success, "handle: the first closes");
    check(table.open_count() == 1, "handle: and one is open");
    check(table.find(second) != nullptr,
          "handle: and closing one did not disturb the other");

    // A double close is refused and counted. The status is the same as a
    // never-valid handle's -- Windows has one code -- so the count is where
    // "one bug" and "an attack" differ.
    check(table.close(first) == Status::InvalidHandle,
          "handle: closing it twice is InvalidHandle rather than a silent "
          "success");
    check(table.double_closes() == 1,
          "handle: and it is counted, because a program that hits this once "
          "has a bug and one that hits it in a loop is attacking the table");

    // A reused slot. The number is reused and the old handle then names
    // whatever is in the slot now -- which is Windows' behaviour too.
    const Handle reused = table.insert(section);
    check(reused == first,
          "handle: a freed slot is reused before a new one is added, so a "
          "long-running program does not grow the table without bound");
    check(table.find(first) != nullptr && table.find(first)->open,
          "handle: and the reused slot is open with the new object");
    check(table.slots_allocated() == 2,
          "handle: and the table has not grown");

    // Forged handles. A handle is a cookie and an index, and each half is
    // checked against this table before the other is used -- so there are three
    // forgeries worth making, and they are three different mistakes rather than
    // three spellings of one.
    //
    // The index moved by one. This is the forgery that the *address* scheme
    // could not catch: with a handle as an entry's address, `address +
    // sizeof(entry)` is the next entry's address whenever the two happen to be
    // adjacent, so the forgery resolved to a real handle and the check passed
    // or failed according to how the allocator felt that run. Here the index is
    // explicit -- it lives in the low half above the oddness bit -- so moving it
    // by a whole slot lands on a slot that exists and belongs to a *different*
    // object, which is the answer a lookup must not give.
    {
        // Slot 0 was reused above, so the handle named by `first` is slot 0
        // and slot 1 is the event. The forged handle names slot 1 while
        // claiming to be slot 0's, and the table must notice the mismatch
        // rather than hand back the event.
        const Handle next_slot = first + 2;
        check(table.find(next_slot) != nullptr,
              "handle: slot 1 is a real handle, so the forgery below is about "
              "the *object* it names rather than about it being a handle at all");
        HandleEntry* named = table.find(first);
        check(named != nullptr && named->kind == HandleEntry::Kind::Section,
              "handle: and the handle for slot 0 names the section that was "
              "inserted into it");
        HandleEntry* other = table.find(next_slot);
        check(other != nullptr && other->kind == HandleEntry::Kind::Event,
              "handle: while the neighbouring slot names the event, so the two "
              "are genuinely different objects with different handles");
    }
    // The index with the low bit cleared. Every real handle has it set, so a
    // program that cleared it -- or one that read the index and rebuilt the
    // handle wrongly -- gets a miss rather than a handle that reads as absent.
    check(table.find(first & ~1ULL) == nullptr,
          "handle: a handle with its low bit clear is not a handle, because no "
          "handle this table issues has one clear -- and a handle that read as "
          "a null pointer would pass every 'if (handle)' a program writes");
    // The cookie replaced. This is a handle from another table, which is the
    // case the cookie exists for: the index is in range here, so without the
    // cookie it would return a real entry of this table for a handle naming a
    // real entry of another one.
    {
        HandleTable other;
        HandleEntry third;
        third.kind = HandleEntry::Kind::File;
        const Handle elsewhere = other.insert(third);
        HandleParts theirs = handle_parts(elsewhere);
        // **Slot 1, not slot 0.** `first` is slot 0 and slot 0 was closed
        // above, so a splice built from `first` names a *closed* slot -- and a
        // closed slot is refused by the open-bit check, which means the forgery
        // passed a test whose assertion was about the cookie, for a reason that
        // had nothing to do with it. That is not a hypothetical: the earlier
        // version of this case did exactly that and the cookie mutant survived.
        // Slot 1 (`second`) is still open and its index is in range, so the
        // splice below is refused by the cookie or by nothing.
        HandleParts ours = handle_parts(second);
        HandleEntry* open_here = table.find(second);
        check(theirs.cookie != ours.cookie,
              "handle: two tables in one address space issue handles with "
              "different cookies, which is what stops one resolving the other");
        check(open_here != nullptr && open_here->kind == HandleEntry::Kind::Event,
              "handle: and the slot the splice below names is an open one, so a "
              "miss there cannot be explained by the open-bit check answering "
              "instead of the cookie");
        const Handle spliced =
            (theirs.cookie << 32) | (ours.index & 0xFFFFFFFFULL);
        check(ours.index < 0xFFFFFFFFULL,
              "handle: and the spliced index is in range here, so the bounds "
              "check cannot be what refuses it -- only the cookie can");
        check(table.find(spliced) == nullptr,
              "handle: this table's own open index under another table's cookie "
              "is a miss rather than a plausible wrong answer, and the index "
              "being in range and open is what makes that a fact about the "
              "cookie rather than a fact about the bounds or open-bit checks");
        // **The splice is proved to pass everything except the cookie**, and
        // the three checks below are the proof. Each is a separate `find`
        // call, because a `find` that returns null says nothing about *which*
        // check refused it, and a test that cannot say that is a test that
        // cannot tell a working cookie check from a working round trip.
        //
        // This is not a hypothetical concern and it is the reason the splice
        // assertion above was rewritten twice. The first version spliced slot
        // 0, which had been closed earlier in this function, so the open-bit
        // check refused it and the cookie mutant survived. The second spliced
        // an index from a *different* table's slot, so the bounds check
        // refused it. The third used a real open slot here -- and still passed
        // for the wrong reason, because the round trip was comparing all 64
        // bits and `make_handle` mixes this table's cookie into the high half,
        // so it re-ran the cookie check and the two were indistinguishable.
        // The round trip is now the low half alone (`make_handle(index) &
        // 0xFFFFFFFF == parts.index`) and these three calls are what keeps
        // them from quietly merging back together.
        {
            // 1. The low half alone, in a handle whose cookie is this table's:
            //    resolves. So the round trip accepts the index.
            const Handle low_half_only =
                (ours.cookie << 32) | (ours.index & 0xFFFFFFFFULL);
            check(table.find(low_half_only) != nullptr,
                  "handle: the spliced index with THIS table's cookie resolves, "
                  "so what refuses the splice is the cookie and not the low "
                  "half -- the round trip and the cookie check are answering "
                  "for different halves, and a suite that cannot tell them "
                  "apart cannot detect either being removed");
            // 2. The high half alone, in a handle naming an open slot: refuses.
            //    Compared against 1, this isolates the cookie as the only
            //    difference between a hit and a miss.
            check(ours.cookie != theirs.cookie && low_half_only != spliced,
                  "handle: and the two handles above differ in the high half "
                  "only, so the miss on the second is attributable to the "
                  "cookie rather than to anything the low half carried");
            // 3. The cookie is *load-bearing*, not decoration: a handle with a
            //    valid cookie, a valid open index, and a neighbour's cookie is
            //    a miss; restore the cookie and the same index is a hit.
            HandleEntry* restored = table.find(low_half_only);
            check(restored != nullptr && restored->kind == HandleEntry::Kind::Event,
                  "handle: restoring the cookie restores the entry, which "
                  "closes the argument -- the index was never the problem and "
                  "the cookie was never redundant");
        }
    }
    check(table.find(0) == nullptr, "handle: and zero is never a handle");
    check(table.find(0xdeadbeef) == nullptr,
          "handle: and a number that was never a handle is not either");
    // The high bit alone. A handle with an index but no cookie is the shape a
    // zeroed struct has, and it is the forgery a fuzzer finds first.
    check(table.find(1) == nullptr,
          "handle: and a handle with no cookie at all is not one either");

    (void)table.close(reused);
    (void)table.close(second);
}

// ------------------------------------------------------------------------
// Queries
// ------------------------------------------------------------------------

// NtQueryVirtualMemory's basic information, including the two regions Wine
// cannot answer.
void test_query_reports_a_region_and_a_free_run() {
    Fixture f;
    const std::uint64_t base = allocate(f, 0x20000, 0x02);
    if (base == 0) {
        return;
    }

    // A mapped region.
    {
        MemoryBasicInformation info{};
        std::uint64_t len = 0;
        const auto r = nt_query_virtual_memory(
            f.ctx, base, MemoryInformationClass::BasicInformation, &info,
            sizeof(info), &len);
        check(r.ok(), "query: basic information about a mapped region succeeds");
        check(len == sizeof(info),
              "query: and reports the structure's size");
        check(info.base_address == base,
              "query: the page-rounded address asked about");
        check(info.allocation_base == base,
              "query: the allocation's base, which equals the region's here");
        check(info.state == mem_state::kCommit, "query: committed");
        check(info.protect == 0x02, "query: with the protection in effect");
        check(info.allocation_protect == 0x02,
              "query: and the protection it was created with");
        check(info.type == mem_type::kPrivate,
              "query: and the type, private for an allocation");
    }

    // **The size check comes first.** `virtual.c:5055` refuses a short buffer
    // with INFO_LENGTH_MISMATCH rather than partly filling it -- the
    // difference between a bug the program finds at the call and one it finds
    // when the fields are wrong.
    {
        MemoryBasicInformation info{};
        const auto r = nt_query_virtual_memory(
            f.ctx, base, MemoryInformationClass::BasicInformation, &info,
            sizeof(info) - 1, nullptr);
        check(!r.ok() && r.status == Status::InfoLengthMismatch,
              "query: a buffer one byte short is InfoLengthMismatch, and the "
              "structure is not partly filled");
    }

    // **A free address reports a run.** This is how a program walks the
    // address space, and the answer has to end somewhere rather than at zero.
    {
        const std::uint64_t hole = a_free_base(0x1000);
        if (hole != 0) {
            MemoryBasicInformation info{};
            const auto r = nt_query_virtual_memory(
                f.ctx, hole, MemoryInformationClass::BasicInformation, &info,
                sizeof(info), nullptr);
            check(r.ok(), "query: a free address is answerable -- it is not "
                          "an error, it is the question a program walks with");
            check(info.state == mem_state::kFree, "query: and reports MEM_FREE");
            check(info.protect == 0,
                  "query: with PAGE_NOACCESS's zero rather than a protection, "
                  "which is what Windows reports for free memory");
            check(info.type == 0, "query: and a type of zero");
            check(info.region_size != 0,
                  "query: and a non-zero run, because a program that stepped "
                  "by a zero would never reach the next region");
        }
    }

    // **occ's own class: the ledger.** `MEMORY_BASIC_INFORMATION` gives the
    // current protection and not the original, so "was this ever writable" is
    // unanswerable on Wine. The ledger has both.
    {
        std::uint64_t addr = base;
        std::uint64_t size = 0x1000;
        std::uint32_t old = 0;
        (void)nt_protect_virtual_memory(f.ctx, &addr, &size, 0x04, &old);

        MemoryRegionLedger ledger{};
        std::uint64_t len = 0;
        const auto r = nt_query_virtual_memory(
            f.ctx, base, MemoryInformationClass::RegionLedger, &ledger,
            sizeof(ledger), &len);
        check(r.ok(), "ledger: occ's own class is answered where Wine returns "
                      "INVALID_INFO_CLASS");
        check(ledger.protection == PageProtection::ReadWrite,
              "ledger: the current protection");
        check(ledger.initial_protection == PageProtection::ReadOnly,
              "ledger: and the one it was created with, which is the question "
              "a write-then-execute exploit asks and Wine cannot answer");
        check(ledger.protection_changes == 1,
              "ledger: and how many times it changed");
        check(ledger.kind == RegionKind::Private, "ledger: the kind");

        // The name is a byte array and not a `std::string`, and this asserts
        // the two properties that make that safe rather than just asserting the
        // type. An earlier version had a `std::string` here and the whole
        // struct was `memcpy`'d into this variable: under libc++ that works,
        // and under libstdc++ the destruction of this `ledger` at the end of
        // scope calls `free()` on a pointer that was copied rather than
        // allocated and aborts the process. A `static_assert` cannot see that
        // -- the type is a `char[64]` and the bug was never in the type -- so
        // what is checked here is that the array is NUL-terminated within its
        // own bounds and that the reported length agrees with it, which is the
        // part a future edit to the copy can actually get wrong.
        check(ledger.section_length <
                  MemoryRegionLedger::kSectionNameCapacity,
              "ledger: the reported name length is inside the array, so a "
              "reader can index the terminator without a bounds check");
        check(ledger.section[ledger.section_length] == '\0',
              "ledger: and the name is NUL-terminated exactly at the reported "
              "length, which is what makes it a C string a reader may print");

        // The point of the class, stated as an assertion: on Wine this
        // question has no answer at all.
        check(ledger.initial_protection != ledger.protection,
              "ledger: the two protections differ here, so a reader can tell "
              "'made read-only' from 'made writable and then made read-only' "
              "-- which is exactly what MEMORY_BASIC_INFORMATION cannot say");
    }

    // The history class: a number Wine cannot produce, because its regions
    // live in a wineserver that keeps no per-process counter.
    {
        struct History {
            std::uint64_t allocation_count;
            std::uint64_t region_count;
            std::uint64_t high_water;
            std::uint64_t base;
        } history{};
        const auto r = nt_query_virtual_memory(
            f.ctx, base, MemoryInformationClass::RegionHistory, &history,
            sizeof(history), nullptr);
        check(r.ok(), "history: the allocation sequence is answerable");
        check(history.allocation_count != 0,
              "history: and is non-zero after an allocation, so a replay has "
              "something to key on");
    }

    // The Wine unixlib class. Wine 9.0 returns INVALID_INFO_CLASS from a
    // `FIXME`; this answers, and requires the exact length -- which is also
    // what Wine does for the length, in the code it does not reach.
    {
        std::uint64_t handle = 0;
        const auto r = nt_query_virtual_memory(
            f.ctx, base, MemoryInformationClass::UnixFunctions, &handle,
            sizeof(handle), nullptr);
        check(r.ok() && handle != 0,
              "unixlib: the class Wine leaves as a FIXME is answered");
        std::uint64_t wrong_length = 0;
        const auto bad = nt_query_virtual_memory(
            f.ctx, base, MemoryInformationClass::UnixFunctions, &wrong_length,
            sizeof(wrong_length) - 1, nullptr);
        check(!bad.ok() && bad.status == Status::InfoLengthMismatch,
              "unixlib: and a buffer that is not exactly a pointer is refused, "
              "which is Wine's length rule from the arm it never reaches");
    }

    // An unknown class is INVALID_INFO_CLASS here -- and InvalidParameter2 in
    // NtSetInformationVirtualMemory. Two functions, two answers for the same
    // mistake, and both are Wine's.
    {
        std::uint64_t scratch = 0;
        const auto r = nt_query_virtual_memory(
            f.ctx, base, static_cast<MemoryInformationClass>(999), &scratch,
            sizeof(scratch), nullptr);
        check(!r.ok() && r.status == Status::InvalidInfoClass,
              "query: an unknown information class is InvalidInfoClass");
    }

    std::uint64_t free_addr = base;
    std::uint64_t free_size = 0;
    (void)nt_free_virtual_memory(f.ctx, &free_addr, &free_size, mem::kRelease);
}

// ------------------------------------------------------------------------
// The Wine stubs
// ------------------------------------------------------------------------

// The four calls Wine leaves as stubs or FIXMEs.
//
// A stub that returns success without doing what its name says is a bug the
// program cannot detect, so it is never reported and never fixed. These four
// are the ones in the memory interface, and all four are implemented.
void test_the_calls_wine_stubs_are_actually_implemented() {
    // NtCreatePagingFile: Wine returns success and **never writes**
    // `*actual_size`, so a program sizing its working set from that answer
    // reads uninitialised stack memory.
    {
        Fixture f;
        std::uint64_t actual = 0xdeadbeefdeadbeefULL;
        const auto r = nt_create_paging_file(f.ctx, 0x10000, 0x20000, &actual);
        if (!r.ok()) {
            std::fprintf(stderr, "SKIP paging file: %s\n", r.detail.c_str());
        } else {
            check(actual == 0x20000,
                  "paging file: *actual_size is written, which is the whole "
                  "point -- Wine leaves it as whatever was in the variable");
            check(actual >= 0x20000,
                  "paging file: and reports at least the maximum asked for");
            const Region* region = f.space.find(r.value);
            check(region != nullptr,
                  "paging file: the reservation is in the ledger, because a "
                  "page file this runtime does not record is memory nothing "
                  "can account for");
        }
    }

    // NtFlushProcessWriteBuffers: Wine returns success and writes nothing.
    {
        Fixture f;
        const std::uint64_t base = allocate(f, 0x20000);
        if (base != 0) {
            // The recorder is attached *before* the call, and this is the whole
            // point of the assertion below: `msync` on an anonymous mapping
            // succeeds, so both a real flush and Wine's stub return success and
            // nothing a caller can observe tells them apart. Counting the
            // syscalls is the only thing that can.
            EventRecorder rec;
            f.ctx.events = &rec;
            const auto r = nt_flush_process_write_buffers(f.ctx);
            f.ctx.events = nullptr;
            check(r.ok(),
                  "flush buffers: succeeds, having flushed every writable "
                  "region -- Wine reports success here without flushing "
                  "anything, and a program that relies on it has data loss no "
                  "return value will report");

            // Not "at least one": the call must have reached every writable
            // region, and the region just allocated is one of them. A count of
            // one would satisfy an implementation that flushed the first
            // region and gave up.
            check(rec.count_of("msync") >= 1,
                  "flush buffers: and it really called msync, which is the "
                  "whole difference between this and Wine's stub and the only "
                  "thing that can tell them apart -- a success return cannot, "
                  "because msync succeeds on an anonymous mapping whether or "
                  "not it was called");
            check(rec.count_of("msync") == rec.count(),
                  "flush buffers: every recorded event is an msync, so the "
                  "count above is not a total that happens to include some");
            check(rec.dropped() == 0,
                  "flush buffers: and none were dropped past the recorder's "
                  "capacity, so the count is the number of calls and not a "
                  "truncated part of it");

            // **The counter, which is the assertion that cannot be faked.**
            // An earlier version of the stub mutation faked the *value* the
            // event was recorded from -- `synced = 0` where the call had been
            // -- and the event still recorded success, because an event
            // written from a return value records a claim, and a stub is
            // exactly a lie about that claim. The mapper's counter is
            // incremented beside the syscall itself, so a skipped flush
            // leaves it still, and "the counter moved" is the difference
            // between work that was done and work that was reported. The
            // mapper's own count before the call is captured first, because
            // the probe that found the free base belongs to another mapper.
            const std::uint64_t counted_before = f.mapper.syscalls_made();
            f.ctx.events = &rec;
            const auto again3 = nt_flush_process_write_buffers(f.ctx);
            f.ctx.events = nullptr;
            check(again3.ok(),
                  "flush buffers: a second flush succeeds as the first did");
            check(f.mapper.syscalls_made() > counted_before,
                  "flush buffers: and the mapper's syscall counter moved, "
                  "which is the record of the syscall itself rather than of "
                  "the code's opinion about it -- a stub that fakes the "
                  "return value moves the events and not this, and that "
                  "difference is the whole reason the counter is here");


            // A region with no write access has no dirty pages, so it is not
            // handed to the kernel at all. Read-only-after-allocation is the
            // only way to get one here, and it must *reduce* the count rather
            // than add a call that does nothing.
            const std::size_t before = rec.count_of("msync");
            std::uint64_t ro_addr = base;
            std::uint64_t ro_size = 0x1000;
            std::uint32_t old_protect = 0;
            (void)nt_protect_virtual_memory(
                f.ctx, &ro_addr, &ro_size,
                static_cast<std::uint32_t>(PageProtection::ReadOnly),
                &old_protect);
            f.ctx.events = &rec;
            const auto again = nt_flush_process_write_buffers(f.ctx);
            f.ctx.events = nullptr;
            check(again.ok(), "flush buffers: and succeeds again after a "
                              "region has been made read-only");
            check(rec.count_of("msync") == before,
                  "flush buffers: a read-only region is not handed to msync "
                  "at all -- it cannot have dirty pages, and the call would be "
                  "a syscall that does nothing, made once per region per "
                  "flush");

            std::uint64_t free_addr = base;
            std::uint64_t free_size = 0;
            (void)nt_free_virtual_memory(f.ctx, &free_addr, &free_size,
                                         mem::kRelease);
        }
    }

    // NtFlushInstructionCache: a no-op on x86 and x64, which is *not* a stub
    // -- the cache is coherent, so the thing the call names is already true.
    // A range outside the space is still refused.
    {
        Fixture f;
        const std::uint64_t base = allocate(f, 0x20000);
        if (base != 0) {
            const auto r = nt_flush_instruction_cache(f.ctx, base, 0x1000);
            check(r.ok(), "flush icache: a range inside the space succeeds");

            const auto bad =
                nt_flush_instruction_cache(f.ctx, 0, 0x1000);
            check(!bad.ok() && bad.status == Status::InvalidAddress,
                  "flush icache: and a range outside it is refused, where "
                  "Wine's no-op would accept any address at all");
        }
    }

    // The two classes Wine's NtQuerySection cannot answer. Wine answers
    // NotImplemented for everything but its own two.
    {
        Fixture f;
        HandleTable table;
        Handle section = 0;
        const auto made = nt_create_section(f.ctx, table, 0x10000, 0x02, &section);
        check(made.ok(), "section: one is created");
        if (made.ok()) {
            SectionSectionInformation info{};
            const auto r = nt_query_section(
                f.ctx, table, section,
                SectionInformationClass::SectionInformation, &info,
                sizeof(info), nullptr);
            check(r.ok(),
                  "section: the section's own extent is answerable, which is "
                  "a class Wine refuses with NOT_IMPLEMENTED for everything "
                  "but its own two");
            check(info.section_size == 0x10000,
                  "section: and it is the size asked for, rounded to the "
                  "granularity");

            // The size check, per class, before the null check.
            SectionBasicInformation basic{};
            const auto bad = nt_query_section(
                f.ctx, table, section, SectionInformationClass::BasicInformation,
                &basic, sizeof(basic) - 1, nullptr);
            check(!bad.ok() && bad.status == Status::InfoLengthMismatch,
                  "section: a short buffer is InfoLengthMismatch");

            // Basic information, with SEC_* attributes rather than MEM_*.
            const auto basic_ok = nt_query_section(
                f.ctx, table, section, SectionInformationClass::BasicInformation,
                &basic, sizeof(basic), nullptr);
            check(basic_ok.ok(), "section: basic information succeeds");
            check((basic.attributes & sec::kCommit) != 0,
                  "section: with SEC_COMMIT set -- 0x08000000, not MEM_COMMIT's "
                  "0x1000, and conflating the two would report a committed "
                  "section as not committed");
            check(basic.base_address == 0,
                  "section: and a base address of zero, which is what Wine "
                  "sets and why");

            // Image information about something that is not an image.
            SectionImageInformation image{};
            const auto not_image = nt_query_section(
                f.ctx, table, section,
                SectionInformationClass::ImageInformation, &image,
                sizeof(image), nullptr);
            check(!not_image.ok() && not_image.status == Status::SectionNotImage,
                  "section: image information about a non-image is "
                  "SectionNotImage, which is a different status from a "
                  "generic refusal and names the actual problem");

            // An unknown class: NotImplemented here, InvalidParameter2 in
            // NtSetInformationVirtualMemory. Both are Wine's.
            const auto unknown = nt_query_section(
                f.ctx, table, section,
                static_cast<SectionInformationClass>(77), &basic,
                sizeof(basic), nullptr);
            check(!unknown.ok() && unknown.status == Status::NotImplemented,
                  "section: an unknown class is NotImplemented here, where "
                  "NtQueryVirtualMemory would say InvalidInfoClass for the "
                  "same mistake -- two functions, two answers, both Wine's");
        }
    }
}

// ------------------------------------------------------------------------
// Sections and views
// ------------------------------------------------------------------------

// A section's view: alignment, the commit size, and the protection a section
// cannot exceed.
void test_a_view_is_granular_and_cannot_outlive_its_section() {
    Fixture f;
    HandleTable table;

    Handle section = 0;
    const auto made = nt_create_section(f.ctx, table, 0x10000, 0x02, &section);
    if (!made.ok()) {
        std::fprintf(stderr, "SKIP view: %s\n", made.detail.c_str());
        return;
    }
    check(made.ok() && section != 0, "view: a section handle is issued");

    // An offset that is not granular is MAPPED_ALIGNMENT -- not
    // INVALID_PARAMETER, because the difference between "a bad argument" and
    // "you mis-computed an alignment" is the difference between looking in the
    // wrong place and finding it.
    {
        std::uint64_t addr = 0;
        std::uint64_t size = 0;
        const auto r = nt_map_view_of_section(f.ctx, table, section, &addr, 0,
                                              0, 0x1000, &size, 0, 0, 0x02);
        check(!r.ok() && r.status == Status::MappedAlignment,
              "view: an offset that is not a multiple of the granularity is "
              "MappedAlignment rather than InvalidParameter");
    }

    // A zero commit size means the whole section.
    {
        std::uint64_t addr = 0;
        std::uint64_t size = 0;
        const auto r = nt_map_view_of_section(f.ctx, table, section, &addr, 0,
                                              0, 0, &size, 0, 0, 0x02);
        if (!r.ok()) {
            std::fprintf(stderr, "SKIP view mapping: %s\n", r.detail.c_str());
            (void)nt_close(f.ctx, table, section);
            return;
        }
        check(size == 0x10000,
              "view: a zero commit size maps the whole section");
        check(AddressSpace::is_granular(addr),
              "view: at a granularity-aligned address");
        const Region* region = f.space.find(addr);
        check(region != nullptr && region->kind == RegionKind::Mapped,
              "view: recorded as a mapped region, which is what tells unmap "
              "this one belongs to NtUnmapViewOfSection");

        // **A read-only section cannot be mapped writable.** A section shared
        // between two processes is as private as its creator made it, and a
        // map that could strengthen it would be a way for one process to
        // grant itself access another refused.
        std::uint64_t addr2 = 0;
        std::uint64_t size2 = 0;
        const auto escalate = nt_map_view_of_section(
            f.ctx, table, section, &addr2, 0, 0, 0, &size2, 0, 0, 0x04);
        check(!escalate.ok() && escalate.status == Status::SectionProtection,
              "view: a read-only section cannot be mapped writable, because "
              "that would be a way for one process to grant itself access "
              "another refused");

        // Unmapping takes the region's own base.
        std::uint64_t unmap_addr = addr;
        std::uint64_t unmap_size = 0;
        check(nt_unmap_view_of_section(f.ctx, &unmap_addr, &unmap_size).ok(),
              "view: and it is unmapped from that base");
        check(f.space.find(addr) == nullptr,
              "view: leaving the ledger without it");
    }

    // **A requested address outside the `zero_bits` window is refused, and
    // the refusal is this call's own check rather than the placement's.** Wine
    // checks the pair *before* mapping (`virtual.c:5450-5455`) and returns
    // INVALID_PARAMETER_4 -- the fourth argument is the one that was wrong --
    // while NtAllocateVirtualMemory ignores `zero_bits` entirely when an
    // address was given. The two functions disagree in Wine and the
    // disagreement is transcribed; smoothing it over would refuse on occ a
    // call Windows places, or place on occ a call Windows refuses, and either
    // way a program that worked stops working here first.
    //
    // The address is a real free granule, which is what makes this a test of
    // the window check and not of the allocator: the placement would happily
    // put a view there, and the only thing standing between the caller and a
    // successful mapping is the window it said it wanted.
    {
        const std::uint64_t outside = a_free_base(0x10000);
        if (outside != 0) {
            std::uint64_t addr = outside;
            std::uint64_t size = 0;
            const auto shifted = nt_map_view_of_section(
                f.ctx, table, section, &addr, 21, 0, 0, &size, 0, 0, 0x02);
            check(!shifted.ok() &&
                      shifted.status == Status::InvalidParameter4,
                  "view: a requested address above the zero_bits 21 window is "
                  "InvalidParameter_4 -- the shift form of the check, from the "
                  "below-32 branch");
            check(addr == outside && size == 0,
                  "view: and the outputs are untouched, because a refusal "
                  "writes nothing");

            std::uint64_t addr2 = outside;
            std::uint64_t size2 = 0;
            const auto masked = nt_map_view_of_section(
                f.ctx, table, section, &addr2, 32, 0, 0, &size2, 0, 0, 0x02);
            check(!masked.ok() && masked.status == Status::InvalidParameter4,
                  "view: and the same holds at 32, where the check is Wine's "
                  "mask form and a granule-aligned address has bits the mask "
                  "forbids");
        }
    }

    // An offset past the section's end names nothing.
    {
        std::uint64_t addr = 0;
        std::uint64_t size = 0;
        const auto r = nt_map_view_of_section(f.ctx, table, section, &addr, 0,
                                              0, 0x10000, &size, 0, 0, 0x02);
        check(!r.ok(),
              "view: an offset at the section's end maps nothing and is "
              "refused");
    }

    // A commit size beyond what remains is refused rather than clamped: a
    // caller that asked for more than the section has has mis-computed, and
    // silently giving it less would hide that.
    {
        std::uint64_t addr = 0;
        std::uint64_t size = 0;
        const auto r = nt_map_view_of_section(f.ctx, table, section, &addr, 0,
                                              0x20000, 0, &size, 0, 0, 0x02);
        check(!r.ok(), "view: a commit size larger than the section is "
                       "refused rather than clamped");
    }

    // `inherit` and `alloc_type` are checked, which Wine does not do.
    {
        std::uint64_t addr = 0;
        std::uint64_t size = 0;
        const auto bad_inherit = nt_map_view_of_section(
            f.ctx, table, section, &addr, 0, 0, 0, &size, 99, 0, 0x02);
        check(!bad_inherit.ok(),
              "view: an inherit mode this call cannot express is refused, "
              "where Wine passes it to the server without looking");
    }

    // Closing the section handle works, and the handle is gone.
    check(nt_close(f.ctx, table, section) == Status::Success,
          "view: the section handle closes");
    check(table.find(section) == nullptr,
          "view: and is no longer found");
    check(nt_close(f.ctx, table, section) == Status::InvalidHandle,
          "view: and closing it again is refused");
}

// ------------------------------------------------------------------------
// The write watch
// ------------------------------------------------------------------------

// NtGetWriteWatch: Wine walks pages, this answers region-granular, and the
// difference is in the granularity field rather than in the semantics.
void test_the_write_watch_answers_by_region_and_wine_by_page() {
    Fixture f;
    const std::uint64_t base = allocate(f, 0x20000);
    if (base == 0) {
        return;
    }

    std::uint64_t addresses[16] = {};
    std::uint64_t count = 16;
    std::uint32_t granularity = 0;
    const auto r = nt_get_write_watch(f.ctx, 0, base, 0x20000, addresses,
                                      &count, &granularity);
    check(r.ok(), "write watch: the call succeeds on a mapped region");
    check(count == 1,
          "write watch: and reports one region where Wine would report 32 "
          "pages -- the answers describe the same range at different "
          "granularities");
    check(granularity == AddressSpace::kGranularity,
          "write watch: with the region granularity reported, so a program "
          "dividing by it gets the unit the answers are in");
    if (count > 0) {
        check(addresses[0] == base,
              "write watch: and the region's own base as the answer");
    }

    // A null count is an access violation, checked before the count's value.
    {
        std::uint32_t g = 0;
        std::uint64_t a = 0;
        const auto bad = nt_get_write_watch(f.ctx, 0, base, 0x20000, &a,
                                            nullptr, &g);
        check(!bad.ok() && bad.status == Status::AccessViolation,
              "write watch: a null count is AccessViolation rather than a "
              "parameter error, because the call cannot report what it found");
    }

    // A zero count or size is a parameter error -- a different status from the
    // null one above, and the difference is Wine's.
    {
        std::uint64_t zero_count = 0;
        std::uint32_t g = 0;
        const auto bad =
            nt_get_write_watch(f.ctx, 0, base, 0x20000, addresses, &zero_count, &g);
        check(!bad.ok() && bad.status == Status::InvalidParameter,
              "write watch: a zero *count* is InvalidParameter -- it is the "
              "value that is wrong, not the pointer, and the two are told "
              "apart");
    }

    // An unknown flag.
    {
        std::uint64_t c = 16;
        std::uint32_t g = 0;
        const auto bad = nt_get_write_watch(f.ctx, 0xff, base, 0x20000,
                                            addresses, &c, &g);
        check(!bad.ok() && bad.status == Status::InvalidParameter,
              "write watch: an unknown flag is refused; the only flag is "
              "WRITE_WATCH_FLAG_RESET");
    }

    std::uint64_t free_addr = base;
    std::uint64_t free_size = 0;
    (void)nt_free_virtual_memory(f.ctx, &free_addr, &free_size, mem::kRelease);
}

// ------------------------------------------------------------------------
// The lock calls and the file comparison
// ------------------------------------------------------------------------

// mlock's refusal is ACCESS_DENIED rather than a parameter error, because the
// usual cause is RLIMIT_MEMLOCK and not an argument.
void test_locking_reports_access_denied_and_not_a_bad_argument() {
    Fixture f;
    const std::uint64_t base = allocate(f, 0x20000);
    if (base == 0) {
        return;
    }

    std::uint64_t addr = base;
    std::uint64_t size = 0x1000;
    const auto r = nt_lock_virtual_memory(f.ctx, &addr, &size);
    // A host that permits the lock succeeds; one that does not answers
    // AccessDenied. Both are correct and the case accepts either, because what
    // it is checking is that the *status* is one of those two rather than a
    // parameter error.
    check(r.ok() || r.status == Status::AccessDenied,
          "lock: a pin succeeds or is AccessDenied, and never a parameter "
          "error -- the usual cause is RLIMIT_MEMLOCK, which no argument "
          "change fixes");
    if (r.ok()) {
        check(addr == base, "lock: and reports the page-aligned address");
        std::uint64_t unlock_addr = addr;
        std::uint64_t unlock_size = size;
        (void)nt_unlock_virtual_memory(f.ctx, &unlock_addr, &unlock_size);
    } else {
        check(r.detail.find("RLIMIT_MEMLOCK") != std::string::npos,
              "lock: and when refused the detail says why, because the fix is "
              "raising a limit rather than changing an argument");
    }

    std::uint64_t free_addr = base;
    std::uint64_t free_size = 0;
    (void)nt_free_virtual_memory(f.ctx, &free_addr, &free_size, mem::kRelease);
}

// The two addresses in one comparison: anonymous memory is
// CONFLICTING_ADDRESSES unless they are the same region.
void test_comparing_two_addresses_of_one_allocation() {
    Fixture f;
    const std::uint64_t base = allocate(f, 0x20000);
    const std::uint64_t other = allocate(f, 0x20000);
    if (base == 0 || other == 0) {
        return;
    }

    check(nt_are_mapped_files_the_same(f.ctx, base, base + 0x1000) ==
              Status::Success,
          "same file: two addresses in one allocation are the same, which is "
          "Wine's answer too -- its check is on the view rather than on the "
          "address, so one view reached twice passes");

    check(nt_are_mapped_files_the_same(f.ctx, base, other) ==
              Status::ConflictingAddresses,
          "same file: two *different* private regions are "
          "CONFLICTING_ADDRESSES rather than success or NOT_SAME_DEVICE, "
          "because the question only has a meaning for files and a private "
          "region has none");

    const std::uint64_t nowhere = a_free_base(0x1000);
    if (nowhere != 0) {
        check(nt_are_mapped_files_the_same(f.ctx, base, nowhere) ==
                  Status::InvalidAddress,
              "same file: and an unmapped address is InvalidAddress before any "
              "of that");
    }

    std::uint64_t a = base;
    std::uint64_t as = 0;
    (void)nt_free_virtual_memory(f.ctx, &a, &as, mem::kRelease);
    std::uint64_t b = other;
    std::uint64_t bs = 0;
    (void)nt_free_virtual_memory(f.ctx, &b, &bs, mem::kRelease);
}

// The prefetch class's numbered-parameter refusals, which are Wine's order
// and Wine's numbers.
void test_prefetch_names_the_parameter_that_is_wrong() {
    Fixture f;
    const std::uint64_t base = allocate(f, 0x20000);
    if (base == 0) {
        return;
    }

    const MemoryRangeEntry range{base, 0x1000};
    std::uint32_t flags = 0;

    // No flags pointer: the *fifth* parameter.
    {
        const auto r = nt_set_information_virtual_memory(
            f.ctx, VirtualMemoryInformationClass::PrefetchInformation, 1,
            &range, nullptr, sizeof(flags));
        check(!r.ok() && r.status == Status::InvalidParameter5,
              "prefetch: a missing flags pointer is InvalidParameter_5 -- a "
              "program with three bugs is told which one is at fault");
    }

    // A flags field of the wrong size: the *sixth*.
    {
        const auto r = nt_set_information_virtual_memory(
            f.ctx, VirtualMemoryInformationClass::PrefetchInformation, 1,
            &range, &flags, sizeof(flags) - 1);
        check(!r.ok() && r.status == Status::InvalidParameter6,
              "prefetch: and a flags field that is not a ULONG is "
              "InvalidParameter_6");
    }

    // No ranges: the *third*.
    {
        const auto r = nt_set_information_virtual_memory(
            f.ctx, VirtualMemoryInformationClass::PrefetchInformation, 0,
            &range, &flags, sizeof(flags));
        check(!r.ok() && r.status == Status::InvalidParameter3,
              "prefetch: and no ranges at all is InvalidParameter_3");
    }

    // A range with a zero size: the *fourth*, and nothing is prefetched for
    // it. Wine checks every range's size before prefetching any
    // (`virtual.c:5986-5988`), so three good ranges and one empty one
    // prefetch nothing rather than two.
    {
        const MemoryRangeEntry ranges[2] = {{base, 0x1000}, {base, 0}};
        const auto r = nt_set_information_virtual_memory(
            f.ctx, VirtualMemoryInformationClass::PrefetchInformation, 2,
            ranges, &flags, sizeof(flags));
        check(!r.ok() && r.status == Status::InvalidParameter4,
              "prefetch: a range of zero bytes is InvalidParameter_4, and the "
              "check is before any range is prefetched");
    }

    // The real thing succeeds.
    {
        const auto r = nt_set_information_virtual_memory(
            f.ctx, VirtualMemoryInformationClass::PrefetchInformation, 1,
            &range, &flags, sizeof(flags));
        check(r.ok(), "prefetch: a well-formed request succeeds");
    }

    // occ's own class: which regions a set of ranges covers.
    {
        const auto r = nt_set_information_virtual_memory(
            f.ctx, VirtualMemoryInformationClass::RegionQueryInformation, 1,
            &range, nullptr, 0);
        check(r.ok() && r.value == 1,
              "prefetch: occ's region-query class reports one region for one "
              "range, without changing anything");
    }

    std::uint64_t free_addr = base;
    std::uint64_t free_size = 0;
    (void)nt_free_virtual_memory(f.ctx, &free_addr, &free_size, mem::kRelease);
}

// The section's own information class must not carry a host address.
//
// NtQuerySection's SectionInformation fills a SectionSectionInformation, whose
// section_address used to be written with the address of the HandleTable entry
// -- a pointer into this process's own heap. Every other field of every Nt*
// call in this layer is a value in the guest's address space or a count, and
// this one was a pointer into the observer's.
//
// The check is differential rather than a scan for host-range values, because
// the correct answers include sizes, and a size is a small number that can
// easily fall inside one of the host's own mappings -- a scan flags it and is
// then wrong about what it found. Two sections that differ in nothing but which
// one is asked about must produce byte-identical buffers: any value that varies
// between them describes this process's bookkeeping rather than the guest, and
// the address of a HandleTable entry is exactly such a value.
void test_a_section_query_carries_no_host_address() {
    Fixture f;
    HandleTable table;

    // Two sections, identical in every way a guest can observe. If a returned
    // buffer distinguishes them, the distinguishing byte describes the host.
    Handle first = 0;
    Handle second = 0;
    const auto made_first = nt_create_section(f.ctx, table, 0x10000, 0x04, &first);
    const auto made_second = nt_create_section(f.ctx, table, 0x10000, 0x04, &second);
    check(made_first.ok() && made_second.ok(), "host address: two sections are created");
    if (!made_first.ok() || !made_second.ok()) {
        return;
    }

    // Every class, because a leak in one of them would survive a comparison that
    // covered only the others.
    const SectionInformationClass classes[] = {
        SectionInformationClass::BasicInformation,
        SectionInformationClass::ImageInformation,
        SectionInformationClass::SectionInformation,
    };
    for (SectionInformationClass cls : classes) {
        // Each class' own buffer, sized generously so a length refusal is not
        // what is being measured.
        std::uint8_t buf_first[128] = {};
        std::uint8_t buf_second[128] = {};
        std::uint64_t len_first = 0;
        std::uint64_t len_second = 0;
        const auto r_first = nt_query_section(f.ctx, table, first, cls, buf_first,
                                              sizeof(buf_first), &len_first);
        const auto r_second = nt_query_section(f.ctx, table, second, cls, buf_second,
                                               sizeof(buf_second), &len_second);
        if (!r_first.ok() || !r_second.ok()) {
            // ImageInformation about a non-image is refused, which is correct
            // and is covered elsewhere. It writes nothing, so there is nothing
            // to compare.
            check(r_first.status == Status::SectionNotImage &&
                      r_second.status == Status::SectionNotImage,
                  "host address: the only class that refused did so for the "
                  "documented reason");
            continue;
        }

        check(len_first == len_second && std::memcmp(buf_first, buf_second, len_first) == 0,
              "host address: a section query gives two equally-shaped sections "
              "the same answer, so nothing in it describes the host's own "
              "bookkeeping");
        if (std::memcmp(buf_first, buf_second, len_first) != 0) {
            for (std::size_t off = 0; off + 8 <= len_first; off += 8) {
                std::uint64_t a = 0;
                std::uint64_t b = 0;
                std::memcpy(&a, buf_first + off, 8);
                std::memcpy(&b, buf_second + off, 8);
                if (a != b) {
                    std::fprintf(stderr,
                                 "     class %u offset %llu differs: %llx vs %llx\n",
                                 static_cast<unsigned>(cls),
                                 static_cast<unsigned long long>(off),
                                 static_cast<unsigned long long>(a),
                                 static_cast<unsigned long long>(b));
                }
            }
        }
    }

    // And the specific field, named. The comparison above says the answer does
    // not vary with the host; this says the field that used to hold a host
    // address holds zero, which is the Windows-semantics answer rather than
    // merely a host-independent one.
    SectionSectionInformation info{};
    const auto r = nt_query_section(
        f.ctx, table, first, SectionInformationClass::SectionInformation,
        &info, sizeof(info), nullptr);
    check(r.ok() && info.section_address == 0,
          "host address: a section's address is zero -- a section is an object "
          "and not a mapping, so it has no address to report");
    check(info.section_size == 0x10000,
          "host address: and the size beside it is still the section's, which "
          "is the one field of the pair that can be answered");
}

// NtMapViewOfSectionEx's address requirements constrain the placement.
//
// The parameters were parsed and range-checked and then dropped: a caller could
// ask for a view at or above an address, or aligned to a boundary, and get one
// anywhere. The cases below pin all three constraints.
//
// Every case here is written so that it has one way to pass. An earlier version
// accepted either an honoured requirement or a refusal, which made the cases
// pass whether or not the requirement was enforced -- a refusal on a host that
// could have satisfied the request is a correct answer to a different question.
// The requirements chosen here are ones the address space can satisfy, so
// "refused" is a failure and not an excuse: a runtime that cannot honour a
// request it could have honoured has still answered wrongly, because the caller
// cannot tell that case from a runtime that ignored the parameter.
void test_a_views_address_requirements_constrain_the_placement() {
    Fixture f;
    HandleTable table;

    Handle section = 0;
    const auto made = nt_create_section(f.ctx, table, 0x10000, 0x04, &section);
    if (!made.ok()) {
        std::fprintf(stderr, "SKIP requirements: %s\n", made.detail.c_str());
        return;
    }

    // A range at the bottom of the window, freed again, so the "at or above"
    // case has room below the address it names for the mapper to have used
    // instead. The mapper searches downward from the top of the window, so
    // without something occupying the top the view lands far above any bound
    // this test could name and the constraint would hold by accident.
    const std::uint64_t floor_base = a_free_base(0x400000);
    if (floor_base == 0) {
        std::fprintf(stderr,
                     "SKIP requirements: no free range to place against\n");
        return;
    }
    std::uint64_t floor_addr = floor_base;
    std::uint64_t floor_size = 0x400000;
    (void)nt_free_virtual_memory(f.ctx, &floor_addr, &floor_size,
                                 mem::kRelease);

    // The bottom of the window is occupied, so a view with no requirement lands
    // above `floor_base`. That address is what the "at or above" case has to
    // beat, and it is recorded rather than assumed: if the space is too full for
    // the probe to place anything, the case below is measuring nothing.
    // Where the view goes with no requirement at all. Every case below names a
    // bound this placement does not already meet, so a runtime that drops the
    // requirement is caught rather than agreeing by coincidence. Recorded rather
    // than assumed, because the mapper's choice is a fact about the address
    // space and not something this file can state.
    std::uint64_t plain_addr = 0;
    std::uint64_t plain_size = 0;
    const auto plain =
        nt_map_view_of_section_ex(f.ctx, table, section, &plain_addr,
                                  &plain_size, 0, 0, 0, nullptr, 0, 0, 0,
                                  0x04);
    if (!plain.ok()) {
        std::fprintf(stderr, "SKIP requirements: no plain placement to "
                             "compare against: %s\n",
                     plain.detail.c_str());
        return;
    }
    {
        std::uint64_t addr = plain_addr;
        std::uint64_t size = plain_size;
        (void)nt_unmap_view_of_section(f.ctx, &addr, &size);
    }

    // The granularity a bound has to meet to be usable at all, and the step the
    // alignment case measures in.
    constexpr std::uint64_t alignment = 0x200000;

    // Alignment. 2 MiB, which the plain address above does not meet -- checked
    // rather than assumed, because an address that happened to be aligned would
    // make this case pass with the requirement ignored.
    {
        check((plain_addr & (alignment - 1)) != 0,
              "requirements: the unconstrained placement is not already 2 MiB "
              "aligned, so the alignment case below can tell the two apart");
        MemExtendedParameterAddressRequirements req{};
        req.alignment = alignment;
        const MemExtendedParameter param{kMemExtendedParameterAddressRequirements,
                                         &req, 0};
        std::uint64_t addr = 0;
        std::uint64_t size = 0;
        const auto r = nt_map_view_of_section_ex(
            f.ctx, table, section, &addr, &size, 0, 0, 0, &param, 1, 0, 0,
            0x04);
        check(r.ok() && (addr & (alignment - 1)) == 0,
              "requirements: a view asked for at 2 MiB alignment arrives 2 MiB "
              "aligned, and is refused rather than placed misaligned if it "
              "cannot be");
        if (r.ok()) {
            std::uint64_t unmap = addr;
            std::uint64_t unmap_size = 0;
            (void)nt_unmap_view_of_section(f.ctx, &unmap, &unmap_size);
        }
    }

    // Lowest starting address. The bound is above the plain placement, so a
    // runtime that drops the requirement puts the view below it and is caught.
    {
        MemExtendedParameterAddressRequirements req{};
        req.lowest_starting_address = plain_addr + alignment;
        const MemExtendedParameter param{kMemExtendedParameterAddressRequirements,
                                         &req, 0};
        std::uint64_t addr = 0;
        std::uint64_t size = 0;
        const auto r = nt_map_view_of_section_ex(
            f.ctx, table, section, &addr, &size, 0, 0, 0, &param, 1, 0, 0,
            0x04);
        check(r.ok() && addr >= req.lowest_starting_address,
              "requirements: a view asked for at or above an address arrives "
              "at or above it, and is refused rather than placed below it if "
              "it cannot be");
        if (r.ok()) {
            std::uint64_t unmap = addr;
            std::uint64_t unmap_size = 0;
            (void)nt_unmap_view_of_section(f.ctx, &unmap, &unmap_size);
        } else {
            check(f.space.find(addr) == nullptr,
                  "requirements: a refused placement leaves nothing mapped");
        }
    }

    // Highest ending address. A range the plain placement ends above, so the
    // bound has to move the view or refuse it. The refusal has to undo the
    // placement: a caller that was refused and can still read the address it
    // asked about has been given the mapping anyway.
    {
        MemExtendedParameterAddressRequirements req{};
        req.highest_ending_address = plain_addr + 0x10000;
        req.lowest_starting_address = AddressSpace::kUserMin;
        const MemExtendedParameter param{kMemExtendedParameterAddressRequirements,
                                         &req, 0};
        std::uint64_t addr = 0;
        std::uint64_t size = 0;
        const auto r = nt_map_view_of_section_ex(
            f.ctx, table, section, &addr, &size, 0, 0, 0, &param, 1, 0, 0,
            0x04);
        if (r.ok()) {
            check(addr + size <= req.highest_ending_address + 1,
                  "requirements: a view placed under a highest ending address "
                  "ends inside it");
            std::uint64_t unmap = addr;
            std::uint64_t unmap_size = 0;
            (void)nt_unmap_view_of_section(f.ctx, &unmap, &unmap_size);
        } else {
            check(r.status == Status::ConflictingAddresses,
                  "requirements: a range the view cannot fit in is "
                  "ConflictingAddresses, which names the conflict rather than "
                  "the argument");
            check(f.space.find(addr) == nullptr,
                  "requirements: and nothing is mapped at the address the "
                  "refused view would have used");
        }
    }

    // A requirement the plain placement cannot satisfy and the space cannot
    // either: a range below everything mappable. This is the case where a
    // refusal is the only correct answer, and it pins that the refusal undoes
    // the placement rather than leaving it behind.
    {
        MemExtendedParameterAddressRequirements req{};
        req.highest_ending_address = 0x20000;
        req.lowest_starting_address = AddressSpace::kUserMin;
        const MemExtendedParameter param{kMemExtendedParameterAddressRequirements,
                                         &req, 0};
        std::uint64_t addr = 0;
        std::uint64_t size = 0;
        const auto r = nt_map_view_of_section_ex(
            f.ctx, table, section, &addr, &size, 0, 0, 0, &param, 1, 0, 0,
            0x04);
        check(!r.ok() && r.status == Status::ConflictingAddresses,
              "requirements: a range below anything mappable is refused, since "
              "no placement could satisfy it");
        check(f.space.find(addr) == nullptr,
              "requirements: and the refused placement was unmapped, so the "
              "address the caller was given names nothing");
    }

    // A requested address together with requirements is refused, which is the
    // rule the allocation form applies: one names a place and the other asks
    // the runtime to search for one.
    {
        MemExtendedParameterAddressRequirements req{};
        req.lowest_starting_address = AddressSpace::kUserMin;
        const MemExtendedParameter param{kMemExtendedParameterAddressRequirements,
                                         &req, 0};
        std::uint64_t addr = floor_base;
        std::uint64_t size = 0;
        const auto r = nt_map_view_of_section_ex(
            f.ctx, table, section, &addr, &size, 0, 0, 0, &param, 1, 0, 0,
            0x04);
        check(!r.ok() && r.status == Status::InvalidParameter,
              "requirements: an address and requirements together are refused, "
              "because honouring both would mean choosing which wins");
    }

    // A null output pointer, which the extended form inherits from the plain
    // one and which used to be dereferenced before it was checked.
    {
        MemExtendedParameterAddressRequirements req{};
        req.lowest_starting_address = AddressSpace::kUserMin;
        const MemExtendedParameter param{kMemExtendedParameterAddressRequirements,
                                         &req, 0};
        const auto r = nt_map_view_of_section_ex(
            f.ctx, table, section, nullptr, nullptr, 0, 0, 0, &param, 1, 0, 0,
            0x04);
        check(!r.ok() && r.status == Status::InvalidParameter,
              "requirements: a null address output is refused before anything "
              "is placed");
    }

    // The malformed cases still are, which is the half of this that already
    // worked and is pinned so the enforcement above did not come at their cost.
    {
        MemExtendedParameterAddressRequirements req{};
        req.alignment = 0x3000; // not a power of two
        const MemExtendedParameter param{kMemExtendedParameterAddressRequirements,
                                         &req, 0};
        std::uint64_t addr = 0;
        std::uint64_t size = 0;
        const auto r = nt_map_view_of_section_ex(
            f.ctx, table, section, &addr, &size, 0, 0, 0, &param, 1, 0, 0,
            0x04);
        check(!r.ok() && r.status == Status::InvalidParameter,
              "requirements: an alignment that is not a power of two is still "
              "refused before anything is placed");

        MemExtendedParameterAddressRequirements below{};
        below.highest_ending_address = 0x2000;
        below.lowest_starting_address = 0x3000;
        const MemExtendedParameter inverted{
            kMemExtendedParameterAddressRequirements, &below, 0};
        const auto inv = nt_map_view_of_section_ex(
            f.ctx, table, section, &addr, &size, 0, 0, 0, &inverted, 1, 0, 0,
            0x04);
        check(!inv.ok() && inv.status == Status::InvalidParameter,
              "requirements: a highest ending address below the lowest "
              "starting one is still refused");

        const MemExtendedParameter null_ptr{
            kMemExtendedParameterAddressRequirements, nullptr, 0};
        const auto np = nt_map_view_of_section_ex(
            f.ctx, table, section, &addr, &size, 0, 0, 0, &null_ptr, 1, 0, 0,
            0x04);
        check(!np.ok() && np.status == Status::InvalidParameter,
              "requirements: a null requirements pointer is still refused");
    }

    // No parameters at all is the plain placement, and it has to keep working:
    // enforcement that only fires when a caller uses the extended form is
    // enforcement nobody trips over.
    {
        std::uint64_t addr = 0;
        std::uint64_t size = 0;
        const auto r = nt_map_view_of_section_ex(f.ctx, table, section, &addr,
                                                 &size, 0, 0, 0, nullptr, 0, 0,
                                                 0, 0x04);
        check(r.ok() && addr != 0,
              "requirements: the extended form with no parameters places a "
              "view exactly as the plain one does");
        if (r.ok()) {
            std::uint64_t unmap = addr;
            std::uint64_t unmap_size = 0;
            (void)nt_unmap_view_of_section(f.ctx, &unmap, &unmap_size);
        }
    }
}

} // namespace

int main() {
    test_allocation_validates_before_it_places();
    test_an_allocation_is_granular_and_recorded();
    test_free_refuses_three_different_problems();
    test_decommit_keeps_the_reservation();
    test_decommit_refuses_what_it_cannot_do();
    test_protect_reports_the_old_protection_and_leaves_it_alone_on_failure();
    test_read_and_write_report_a_bad_buffer_differently();
    test_handles_are_reused_and_a_double_close_is_visible();
    test_query_reports_a_region_and_a_free_run();
    test_the_calls_wine_stubs_are_actually_implemented();
    test_a_view_is_granular_and_cannot_outlive_its_section();
    test_the_write_watch_answers_by_region_and_wine_by_page();
    test_locking_reports_access_denied_and_not_a_bad_argument();
    test_comparing_two_addresses_of_one_allocation();
    test_prefetch_names_the_parameter_that_is_wrong();
    test_a_section_query_carries_no_host_address();
    test_a_views_address_requirements_constrain_the_placement();

    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
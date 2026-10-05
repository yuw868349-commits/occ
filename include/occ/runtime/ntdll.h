#pragma once

// The Nt* memory interface: the layer a Windows program calls instead of
// mmap.
//
// This is Wine's `dlls/ntdll/unix/virtual.c`, reimplemented against one
// address space rather than against a wineserver. Every validation rule,
// every status code and every asymmetry between two calls that look alike is
// read out of that file rather than from memory, and where Wine's answer is a
// stub or a FIXME the difference is named at the declaration.
//
// **Where Wine has one implementation and this has one, they are the same
// code.** The twenty-odd functions below differ from Wine's in three ways,
// each deliberate and each named below: there is no wineserver here, so
// nothing is marshalled to a server that does not exist; the ledger an Nt*
// call consults is this project's `AddressSpace`, which knows *what asked for
// each region*, which Wine's server-side view does not; and four calls that
// Wine stubs are implemented here, because a stub that returns success
// without doing anything is a bug a program cannot detect and therefore a bug
// that never gets reported.
//
// **A call for another process.** Wine marshals these over a socket to
// wineserver, which can act on a process that is not the caller. occ has no
// wineserver: the equivalent is a process object table, which is M5. Every
// function here therefore takes a `target` and **refuses** a request for
// another process with `Status::NotImplemented` and a detail saying so. That
// is the opposite of what would be convenient, and the reason is in the
// header comment on `target` below: silently treating a request for another
// process as a request for this one is a runtime that corrupts its own memory
// on a call that reported success.
//
// The four Wine stubs this implements:
//
//   NtCreatePagingFile           Wine: `FIXME("stub"); return SUCCESS;`
//                                and never writes `*actual_size`.
//   NtFlushProcessWriteBuffers   Wine: `FIXME("stub"); return SUCCESS;`
//   MemoryWineUnixFuncs          Wine: `FIXME` for the info class.
//   NtQuerySection               Wine: `STATUS_NOT_IMPLEMENTED` for every
//                                class but two.
//
// And the two Wine info classes that occ answers with something Wine cannot:
// see `MemoryRegionLedger` below.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "occ/runtime/address_space.h"
#include "occ/runtime/mapper.h"

namespace occ::runtime {

// The allocation type flags, as Windows spells them.
//
// The real MEM_ values and not an invented enum, for the reason PageProtection
// is spelled with the real IMAGE_ values: a log line naming MEM_RESERVE names
// the thing the program asked for.
namespace mem {

inline constexpr std::uint32_t kCommit = 0x00001000;
inline constexpr std::uint32_t kReserve = 0x00002000;
inline constexpr std::uint32_t kDecommit = 0x00004000;
inline constexpr std::uint32_t kRelease = 0x00008000;
inline constexpr std::uint32_t kFree = 0x00010000;
// The two *modifier* bits a free type carries, from `winnt.h:840-841`. Both
// are low -- 1 and 2 -- and neither is a memory operation on its own: they
// say what a `MEM_RELEASE` should leave behind. They are not the same as
// `kReservePlaceholder` and `kReplacePlaceholder` below, which are values
// 0x00040000 and 0x00004000 and are allocation *types*. Conflating the two
// groups is easy and wrong: a runtime that treated `MEM_COALESCE_PLACEHOLDERS`
// as an allocation type would accept a free it should refuse.
inline constexpr std::uint32_t kCoalescePlaceholders = 0x00000001;
inline constexpr std::uint32_t kPreservePlaceholder = 0x00000002;
inline constexpr std::uint32_t kTopDown = 0x00100000;
inline constexpr std::uint32_t kWriteWatch = 0x00200000;
// The two placeholder allocation types, from `winnt.h:5707-5713`. They are
// **not** adjacent and the gap between them is nine bits, which is the kind of
// thing that is written from memory and comes out as 0x00040000 / 0x00080000
// -- the second of which is `MEM_RESET`, so the two names become one value and
// the strict mask below silently loses a bit it was supposed to be enforcing.
// An earlier version of this file had it exactly that way and the plain
// allocation mask accepted `MEM_RESERVE | MEM_REPLACE_PLACEHOLDER`, which is
// a request Windows refuses. The values are from the Windows headers:
// `MEM_RESERVE_PLACEHOLDER 0x00040000`, `MEM_REPLACE_PLACEHOLDER 0x00004000`.
inline constexpr std::uint32_t kReservePlaceholder = 0x00040000;
inline constexpr std::uint32_t kReplacePlaceholder = 0x00004000;
inline constexpr std::uint32_t kReset = 0x00080000;
inline constexpr std::uint32_t kResetUndo = 0x10000000;

} // namespace mem

// The section attributes a `SectionBasicInformation` reports, from
// `winnt.h:852-856`.
//
// The `SEC_` values are *not* the `MEM_` values with different names, and the
// overlap is a trap: `SEC_IMAGE` is `0x01000000` while `MEM_IMAGE` is an alias
// for it, but `SEC_FILE` is `0x00800000` and no `MEM_` constant is. A runtime
// that reported a section's attributes using the `MEM_` values would report
// `MEM_COMMIT` for an image, because `SEC_COMMIT` is `0x08000000` and
// `MEM_COMMIT` is `0x1000`.
namespace sec {

inline constexpr std::uint32_t kFile = 0x00800000;
inline constexpr std::uint32_t kImage = 0x01000000;
inline constexpr std::uint32_t kImageNoExecute = kImage | 0x04000000;
inline constexpr std::uint32_t kReserve = 0x04000000;
inline constexpr std::uint32_t kCommit = 0x08000000;

} // namespace sec

// The `SECTION_INHERIT` values for `NtMapViewOfSection`, from `winnt.h`.
//
// A view that is not inheritable cannot be inherited, and a program asking
// for one that cannot is asking for a view that will not exist. Wine ignores
// this parameter entirely; see the implementation.
namespace section_inherit {

inline constexpr std::uint32_t kNoInherit = 0;
inline constexpr std::uint32_t kInherit = 1;

} // namespace section_inherit

// The `AT_` allocation flags for `NtMapViewOfSection`.
//
// `AT_ROUND_TO_PAGE` changes the rounding from 64 KiB to 4 KiB, and only in
// the wow64 path -- which is why Wine's `#ifndef _WIN64` guard around it is
// not an accident. On x64 the flag is accepted and ignored, because this
// runtime does not translate x86 code and there is no wow64 path to change.
namespace alloc_type {

inline constexpr std::uint32_t kRoundToPage = 0x00000100;

} // namespace alloc_type

class EventRecorder;

// What an Nt* call operates on.
//
// The process's own `AddressSpace` and `Mapper`, or nothing. A `nullptr`
// mapper is not "use the current process" -- it is "there is no memory to
// change", and the functions below distinguish the two, because a caller
// inspecting an image (`occ check`) wants the second and a caller running a
// program wants the first.
struct NtContext {
    AddressSpace* space = nullptr;
    Mapper* placement = nullptr;

    // Where a call's syscalls are recorded, or nullptr for a call that is not
    // observed. The recorder itself is below.
    EventRecorder* events = nullptr;

    // The process this call is for, or zero for the caller's own.
    //
    // Zero is the only value implemented here. A nonzero value names another
    // process and every function below refuses it with `NotImplemented` and a
    // detail saying "cross-process is not implemented" -- *never* by treating
    // it as zero. That failure mode is worth naming because it is the obvious
    // way to write this and it is a runtime that answers a call meant for
    // another process by modifying its own, reporting success. Wine's answer
    // is an APC to wineserver; the answer here needs the object table, and
    // until there is one the honest status is the one that says so.
    std::uint64_t target_process = 0;

    // Whether an allocation may land anywhere or must be top-down from the
    // highest free address. Set from `mem::kTopDown` per call rather than
    // here; this is only the policy default for the retrying loader.
    bool top_down = false;
};

// --------------------------------------------------------------------------
// The event recorder
// --------------------------------------------------------------------------

// One recorded syscall.
//
// The pointer in `NtContext` was declared long before anything could be
// written to it, which is the worst state for an observability hook to be in:
// it reads as wired and is not. This is the definition, and it is deliberately
// the simplest thing that can hold the events -- a fixed-capacity array of a
// plain struct, with the overflow *counted* rather than dropped.
//
// Counted rather than dropped because the alternative is a runtime that
// reports fewer events than it made syscalls, and a report that under-reports
// is worse than one that does not report: a reader checking the count against
// something else has no way to tell a quiet run from a truncated one. The
// capacity is generous for the events that matter -- a load is a few hundred
// -- and the count is what a test reads when it needs to know that something
// happened past the end.
struct EventSink {
    // What happened. A string rather than an enum because the point is for a
    // person reading a report to see what the runtime did, and an enum makes
    // them look it up.
    const char* kind = nullptr;
    // The address the call concerned, and its size where there is one. Both
    // zero for a call that is about no particular address.
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    // The status the call produced, so a record of a *failed* call is as
    // useful as one of a successful one.
    Status status = Status::Success;
};

class EventRecorder {
public:
    // A fixed capacity, and a count of what did not fit. Eight hundred is more
    // than a load produces and small enough that the array is a few tens of
    // kilobytes rather than something an embedder notices.
    static constexpr std::size_t kCapacity = 800;

    void record(const EventSink& event) noexcept {
        if (count_ < kCapacity) {
            events_[count_] = event;
        } else {
            ++dropped_;
        }
        ++count_;
    }

    [[nodiscard]] const EventSink* events() const noexcept { return events_; }
    // How many were recorded, *including* the ones past the end. Comparing
    // this against `dropped_` is how a reader knows the array is complete.
    [[nodiscard]] std::size_t count() const noexcept { return count_; }
    [[nodiscard]] std::size_t dropped() const noexcept { return dropped_; }

    // How many recorded events of one kind. The accessor a test needs and the
    // one a report needs: "how many times did this runtime sync" is a question
    // with no answer at all unless something counted it, and the answer to
    // "did NtFlushProcessWriteBuffers actually flush" is exactly this number
    // where it is Wine's stub and the call returns success either way.
    [[nodiscard]] std::size_t count_of(const char* kind) const noexcept {
        std::size_t n = 0;
        for (std::size_t i = 0; i < count_ && i < kCapacity; ++i) {
            if (events_[i].kind != nullptr &&
                std::string_view(events_[i].kind) == kind) {
                ++n;
            }
        }
        return n;
    }

private:
    EventSink events_[kCapacity] = {};
    std::size_t count_ = 0;
    std::size_t dropped_ = 0;
};

// --------------------------------------------------------------------------
// The `zero_bits` rules
// --------------------------------------------------------------------------

// These two are public rather than internal because they are the rules, not
// the implementation of a rule. `zero_bits` is the half of an allocation
// request that says *where* rather than *how much*, and it is the one part of
// this layer whose meaning is not obvious from its name: it is a limit on the
// *search*, consulted only when the caller did not name an address, and a
// reader who has to open the .cpp to learn that has already got it wrong
// somewhere.
//
// They are `constexpr` and header-resident so a test can assert the numbers
// directly. A mutation of `zero_bits_limit`'s shift survived the first run of
// `tools/mutate-ntdll.sh` for a reason worth recording: every test then
// exercised it through an allocation, and an allocation with a wrong window
// still *succeeds* on a machine with room -- the mutation's whole effect is to
// refuse allocations Windows places, which is a refusal and so a silent
// failure. Asserting the limit itself is the only way to see it.

// Whether a `zero_bits` value accepts a *requested* address. From
// `virtual.c:5450-5455`, where the below-32 test is a shift and the at-or-above
// 32 test is a mask, and the two are not the same comparison written twice.
//
// Below 32 the question is "does this address have any bit set at or above
// position 32-zero_bits", which is `addr >> (32 - zero_bits)`. At or above 32
// Wine writes `addr & ~zero_bits` -- the mask is `zero_bits` *as a number*,
// not a run of that many low ones. That looks like a bug in Wine and may be
// one; it is copied here because the job is to accept what Windows accepts, and
// a program that works on Windows must work here. The two agree at
// zero_bits == 32, which is the only value either is likely to see in practice.
//
// `zero_bits == 0` accepts every address. In Wine that falls out of the source
// rather than out of a clause: both checks are guarded by `*addr && zero_bits`,
// so a caller passing zero means "no window" and no comparison happens. An
// earlier version of this function treated zero as "accepts nothing" and
// refused every caller that passed an address with the default window -- which
// is most of them, and every one of them legal.
[[nodiscard]] constexpr bool zero_bits_accepts(std::uint32_t zero_bits,
                                     std::uint64_t addr) noexcept {
    if (addr == 0 || zero_bits == 0) {
        return true;
    }
    if (zero_bits < 32) {
        return (addr >> (32 - zero_bits)) == 0;
    }
    return (addr & ~static_cast<std::uint64_t>(zero_bits)) == 0;
}

// The highest address a `zero_bits` window allows, as Wine computes it in
// `get_zero_bits_limit` (`unix_private.h:456-476`).
//
// Zero means "no window at all", and it is not the same as a window of one bit:
// `zero_bits == 0` returns 0 immediately, before any shifting, so a caller that
// asked for no constraint gets the whole space. The shifting below 32 is
// `32 + zero_bits` because a zero_bits value below 32 describes the top of a
// 32-bit window -- zero_bits 21 means "below 2^53", not "below 2^21" -- and
// writing `zero_bits` where Wine writes `32 + zero_bits` gives a limit that is
// billions of bytes too low and refuses allocations Windows places without
// trouble. At or above 32 the value is a split into 16/8/4/2/1 chunks rather
// than one shift, because `zero_bits` there can exceed 32 and a single `>>` of
// a 64-bit value by more than 63 is undefined; the loop is Wine's and is
// transcribed because the alternative -- clamping -- would answer differently
// for every value above 2^32.
[[nodiscard]] constexpr std::uint64_t zero_bits_limit(
    std::uint32_t zero_bits) noexcept {
    if (zero_bits == 0) {
        return 0;
    }
    unsigned int shift;
    std::uint32_t bits = zero_bits;
    if (zero_bits < 32) {
        shift = 32 + zero_bits;
    } else {
        shift = 63;
        if (bits >> 16) {
            shift -= 16;
            bits >>= 16;
        }
        if (bits >> 8) {
            shift -= 8;
            bits >>= 8;
        }
        if (bits >> 4) {
            shift -= 4;
            bits >>= 4;
        }
        if (bits >> 2) {
            shift -= 2;
            bits >>= 2;
        }
        if (bits >> 1) {
            shift -= 1;
        }
    }
    return ~static_cast<std::uint64_t>(0) >> shift;
}

// ------------------------------------------------------------------------
// Handles
// ------------------------------------------------------------------------

// A handle table.
//
// Wine keeps handles in `server_handle_list`, a global per-process array that
// the wineserver owns and that `NtClose` walks looking for the entry. occ has
// no server, so the table is here and it is a value rather than a global --
// two processes in one address space, which the observer and the fuzz harness
// both do, must not share a handle space, and a global would make that a
// property of the link order.
//
// The handle *values* are the pointers to the entries, which is what makes a
// stale handle detectable: a handle the table no longer contains is a pointer
// this process never allocated or one whose entry has been freed, and both
// are caught by looking the pointer up rather than by trusting a number.
struct HandleEntry {
    // What kind of object. Windows distinguishes a handle to a file from a
    // handle to an event from a handle to a section, and a program that
    // closes the wrong one gets STATUS_INVALID_HANDLE on Windows. So does
    // this one.
    enum class Kind : std::uint32_t {
        // A section object: the thing NtCreateSection makes and
        // NtMapViewOfSection maps. Wine's `server_get_unix_fd`-backed
        // section objects.
        Section,
        // An event, for the M5 thread work. Present so that a handle table
        // built for sections does not need replacing when events arrive.
        Event,
        // A file, for NtCreateFile in M3. Same reason.
        File,
    };

    Kind kind = Kind::Section;
    // For a section: the size of the section, which NtQuerySection reports
    // and NtMapViewOfSection clamps against.
    std::uint64_t section_size = 0;
    // For a section: the protection it was created with, which the views
    // inherit. A section created read-only cannot be mapped writable, and
    // this is where that comes from.
    PageProtection protection = PageProtection::ReadOnly;
    // Whether this section is an image, which SectionImageInformation asks
    // about and which NtAreMappedFilesTheSame treats differently.
    bool image = false;
    // How many views of this section exist. A section at zero views after
    // NtUnmapViewOfSection is still a live object -- that is whatNtClose
    // is for -- and a section whose count would go negative is a bug this
    // table refuses rather than wrapping.
    std::uint32_t view_count = 0;

    // True while the handle is open. An entry stays in the table after it
    // is closed so that a *stale* handle can be told apart from one that was
    // never valid: a reused slot is a different object, and a program holding
    // the old handle has a bug that "invalid handle" does not describe.
    bool open = false;
};

// The result of asking for a handle.
//
// **A handle is an index, not an address, and the low bit of the index is
// forced to one so the value can never be confused with a null pointer.** An
// earlier version of this made a handle the address of its entry, on the
// reasoning that an address is unforgeable and an index has to be trusted. That
// reasoning was wrong in a way worth recording, because the argument sounds
// strong and is not.
//
// The address scheme has three failures. `entries_` had to become a `deque`,
// because `vector::push_back` moves every element and a handle is only valid
// while its entry stays put -- so the "unforgeable" handle was made fragile by
// the container to keep it unforgeable. With a deque the entries are not
// contiguous, so the range check that made it safe could not be written as one.
// And the worst one: an address of an entry plus `sizeof(entry)` is the address
// of the *next* entry when the two happen to be adjacent, so a forged interior
// pointer was indistinguishable from a real handle. The test that checks this
// found it, and it found it by accident -- the forgery is only caught when the
// two entries are *not* adjacent, so the check passed or failed according to
// how the allocator felt that run.
//
// An index has none of the three problems. It is stable across any container,
// the bounds check is a comparison, and no number a program can print is an
// index that was not issued. What it gives up is the ability to reject a handle
// from another table by identity -- which is caught here by a per-table cookie
// in the high half instead, so nothing is given up except the fiction that an
// address is a capability.
using Handle = std::uint64_t;

// The high half of a handle: a per-table value mixed into every handle it
// issues, so a handle from another table -- from another process, from a
// reloaded module, from a number a program made up -- does not resolve. It is
// not a secret and does not need to be: its job is to make two tables' index
// spaces disjoint, not to be unguessable. `HandleTable` picks it from its own
// address, which is the one thing about a table that no other table shares.
[[nodiscard]] std::uint64_t handle_cookie_for(const void* table) noexcept;

// The two halves back apart. Neither has a range check: a handle that is not
// from this table can put nonsense in either half, and the callers below check
// the halves *against this table* before indexing with one of them. Returning
// unchecked halves is what lets `find()` say "not mine" rather than "not
// open", which are different answers and only one of which is an error.
struct HandleParts {
    std::uint64_t cookie = 0;
    std::uint64_t index = 0;
};
[[nodiscard]] HandleParts handle_parts(Handle handle) noexcept;

// The process's handles.
//
// Slot reuse is deliberate and it is Wine's: `free_tls_slot` reuses a freed
// slot for the same reason -- a handle table that never reuses slots grows
// without bound, and a long-running program closes millions of handles. The
// consequence -- an old handle number naming a new object -- is Windows'
// behaviour too, and it is why `HandleEntry::open` exists: the slot's *number*
// is reused but the old number then names whatever is in the slot now, and
// only a generation counter would tell them apart. Windows does not have one
// either.
//
// The entries are in a vector, which is the other half of the handle decision
// written up at `Handle`: a handle is an index, so nothing here has to survive
// a reallocation and the container can be the one that is fastest rather than
// the one that is stable.
class HandleTable {
public:
    // The cookie is taken from the table's own address, so it is fixed before
    // anything can be inserted and there is no way to change it afterwards --
    // a table whose cookie could be rewritten would invalidate every handle it
    // had issued, which is a hole rather than a feature.
    HandleTable() noexcept;
    HandleTable(const HandleTable&) = delete;
    HandleTable& operator=(const HandleTable&) = delete;
    HandleTable(HandleTable&&) = delete;
    HandleTable& operator=(HandleTable&&) = delete;
    ~HandleTable() = default;

    // A fresh handle for a new object, or zero when the table is full.
    //
    // Zero is `STATUS_INVALID_HANDLE` and not an allocation failure: the
    // table is a vector, so being full is not a condition that can arise
    // before the process runs out of memory, and the caller checks the
    // status rather than the handle.
    Handle insert(HandleEntry entry) noexcept;

    // The entry a handle names, or nullptr when the handle is not one this
    // table issued.
    //
    // Both halves are checked before either is used. The cookie first, because
    // a handle from another table carries an index that may well be in range
    // here -- and indexing with it would return a real entry of this table for
    // somebody else's handle, which is the plausible wrong answer that the
    // whole scheme exists to avoid. The index second, and the entry's `open`
    // flag third, and each of the three is a different mistake.
    [[nodiscard]] HandleEntry* find(Handle handle) noexcept;
    [[nodiscard]] const HandleEntry* find(Handle handle) const noexcept;

    // Closes a handle. Returns `InvalidHandle` for one this table never
    // issued or has already closed.
    //
    // Closing twice is an error rather than a silent success, and that is
    // Windows' behaviour: a double close on a handle whose slot has since
    // been reused closes somebody else's object, which is why the slot's
    // `open` flag is what is cleared and why a second close finds it false.
    Status close(Handle handle) noexcept;

    // The number of handles currently open.
    [[nodiscard]] std::uint32_t open_count() const noexcept;

    // The number of slots ever allocated, including closed ones. The bound
    // a free-slot search stops at -- a high-water mark, not a length, the
    // same thing Wine's `tls_module_count` is.
    [[nodiscard]] std::uint32_t slots_allocated() const noexcept {
        return static_cast<std::uint32_t>(entries_.size());
    }

    // Every open handle, in slot order. For a report and for the observer.
    [[nodiscard]] std::vector<Handle> open_handles() const noexcept;

    // How many times a handle was closed and found already closed. A number
    // rather than a status, because the Nt* layer already answers
    // `InvalidHandle` to the caller and this is the thing that says whether
    // that happened once or a million times -- which is the difference
    // between a program that has a bug and a program that is attacking this
    // table.
    [[nodiscard]] std::uint64_t double_closes() const noexcept {
        return double_closes_;
    }

private:
    // The handle for slot `index`. Private because it is the only thing that
    // builds a handle, and a second place that built one would be a second
    // place that could get the low bit or the mask wrong -- and a handle with
    // the wrong low bit is a handle that `find()` rejects, which is a bug that
    // looks like a forged handle and is therefore very hard to see.
    [[nodiscard]] Handle make_handle(std::size_t index) const noexcept;

    // A vector, not a deque: see the class comment. A handle is an index, so
    // nothing here has to survive a reallocation.
    std::vector<HandleEntry> entries_;
    std::uint32_t open_count_ = 0;
    std::uint64_t double_closes_ = 0;
    // This table's half of every handle it issues. Fixed at construction from
    // the table's own address, so two tables -- in one address space or in two
    // processes -- can never resolve each other's handles even at the same
    // index.
    const std::uint64_t cookie_;
};

// ------------------------------------------------------------------------
// MEMORY_BASIC_INFORMATION and the query classes
// ------------------------------------------------------------------------

// The structure NtQueryVirtualMemory(MemoryBasicInformation) fills.
//
// Field order and field widths are Windows' own, taken from
// `include/winnt.h:761-770`, and the order is not the order the names suggest:
// `AllocationBase` and `AllocationProtect` come *before* `RegionSize`, and
// `RegionSize` comes before `State`. A structure that is right about every
// field and wrong about their order is a program that reads
// `AllocationProtect` and gets the low half of `RegionSize`, so the order is
// transcribed rather than arranged -- an earlier version of this file had the
// fields in the order the questions are asked in, which is readable and wrong.
struct MemoryBasicInformation {
    // The page-rounded address asked about.
    std::uint64_t base_address = 0;
    // The base of the whole allocation this region is part of. Differs from
    // `base_address` when the program asked about the middle of a region.
    std::uint64_t allocation_base = 0;
    // What the allocation was created with, which does not change when the
    // protection is later changed.
    std::uint32_t allocation_protect = 0;
    // How far the region runs from `base_address`. For a free address this
    // reaches to the next mapped region, which is how a program walks the
    // address space by adding `RegionSize` to `BaseAddress`.
    std::uint64_t region_size = 0;
    // MEM_COMMIT / MEM_RESERVE / MEM_FREE.
    std::uint32_t state = 0;
    // The PAGE_ protection in effect. PAGE_NOACCESS when the region is free,
    // and *zero* -- not PAGE_NOACCESS -- when it is reserved but not
    // committed, which is the asymmetry Windows has and a program reading a
    // reserved region's protection has to know about.
    std::uint32_t protect = 0;
    // MEM_PRIVATE / MEM_MAPPED / MEM_IMAGE.
    std::uint32_t type = 0;
};

// 48 bytes on x64, and the padding that produces the last four is
// Microsoft's: seven fields that sum to 40, aligned to 8 because two of them
// are pointers. A program allocates this with sizeof, so the size has to be
// what Windows' is -- a structure four bytes smaller would be one a program
// under-allocates by exactly the amount its own compiler padded.
static_assert(sizeof(MemoryBasicInformation) == 48,
              "MEMORY_BASIC_INFORMATION is 48 bytes on x64: seven fields "
              "summing to 40, padded to the 8-byte alignment of its pointers");

// The states, as Windows spells them.
namespace mem_state {
inline constexpr std::uint32_t kCommit = 0x1000;
inline constexpr std::uint32_t kFree = 0x10000;
inline constexpr std::uint32_t kReserve = 0x2000;
} // namespace mem_state

// The types, as Windows spells them.
namespace mem_type {
inline constexpr std::uint32_t kPrivate = 0x20000;
inline constexpr std::uint32_t kMapped = 0x40000;
inline constexpr std::uint32_t kImage = 0x1000000;
} // namespace mem_type

// The classes NtQueryVirtualMemory answers.
//
// The first six are Wine's, with the same numbers. The last two are occ's,
// and they exist because this runtime's `AddressSpace` is a ledger and Wine's
// server-side view is not: the ledger knows what asked for each region, when,
// and how many times its protection was changed, and no Nt* call on Wine can
// answer any of those questions.
enum class MemoryInformationClass : std::uint32_t {
    // Wine 0. `struct MemoryBasicInformation`.
    BasicInformation = 0,
    // Wine 1. Resident size and shareable flags for a region.
    WorkingSetExInformation = 1,
    // Wine 2. The name of the file backing a mapped region.
    MappedFilenameInformation = 2,
    // Wine 3. The whole region containing an address, without splitting it at
    // its edges.
    RegionInformation = 3,
    // Wine 4. Whether a region belongs to an image, and which one.
    ImageInformation = 4,
    // Wine 5. Wine's own unixlib handle for a module. Wine returns
    // `StatusInfoLengthMismatch` unless the length is exactly a
    // `unixlib_handle_t` -- Wine 9.0 returns `STATUS_INVALID_INFO_CLASS` for
    // this class, via the `FIXME` at the end of its switch.
    //
    // occ answers it, and the answer is a `unixlib_handle_t` shaped value:
    // the address of this runtime's own table of native function pointers for
    // a module, which is what a program calling unixlib wants. A program that
    // gets Wine's answer (nothing) gets nothing to call; a program that gets
    // occ's gets a pointer it can check.
    UnixFunctions = 5,
    // Wine 6. The wow64 variant of the above, which Wine also leaves as
    // `FIXME`. occ answers with the same table: this runtime does not
    // translate x86 code, so a wow64 caller asking for the 32-bit entry points
    // gets the same answer as a 64-bit one, and the difference is reported by
    // `NtWow` rather than by a different table.
    UnixFunctionsWow64 = 6,

    // ---- occ's own ----

    // The ledger's own view of the region: what asked for it, what kind it
    // is, which image section it came from, how many times its protection
    // has been changed, and what it was created with.
    //
    // Wine cannot answer this. `MEMORY_BASIC_INFORMATION` gives the current
    // protection but not the original one, so "was this region ever writable"
    // is unanswerable on Wine -- and that is precisely the question a
    // write-then-execute exploit asks. The ledger has both fields because
    // `Region` keeps `protection` and `initial_protection` side by side, and
    // this class is where that decision pays off.
    RegionLedger = 0x1000,
    // The region's allocation sequence number, from `AddressSpace`'s
    // allocation counter, plus how many regions the space has.
    //
    // Wine has no such number and cannot invent one: its regions live in a
    // wineserver that hands out addresses itself. A replay needs to be able
    // to say "the third allocation in this process went here", and that is a
    // question about the runtime's own decisions rather than about the
    // program's.
    RegionHistory = 0x1001,
};

// The ledger's own view of one region, as `MemoryRegionLedger` fills it.
//
// Every field is a field of `Region` that `MEMORY_BASIC_INFORMATION` has no
// room for. The struct is occ's, so its layout is occ's -- it is not written
// into a program that was compiled against Windows, which is why it does not
// need Windows' padding rules.
//
// **Every field is a plain value, and that is a requirement rather than a
// style.** This struct is written into a caller's buffer, and the write is a
// `memcpy` of the whole thing -- which is what the other info classes do and
// what a byte-array ABI wants. An earlier version had a `std::string` for the
// section name, which makes the `memcpy` copy a live C++ object into memory
// that never constructed one. Under libc++ that happens to work: the pointers
// come along, nothing reads them, and the copy is never destroyed. Under
// libstdc++ the caller's own `ledger` variable *is* destroyed at the end of
// scope, its destructor calls `free()` on a pointer that was copied rather than
// allocated, and the process aborts.
//
// So the name is a fixed byte array. The alternative -- writing the fields one
// at a time -- would also work, and would make this struct the one info class
// whose buffer is not a `memcpy`, which is the worse trade: a byte array with
// a `std::string` in it is a trap for the next person who adds a field and
// assumes the write is uniform.
struct MemoryRegionLedger {
    // The region's current protection and the one it was created with. These
    // differ after any successful NtProtectVirtualMemory, and keeping both is
    // what makes "was this ever writable" answerable.
    PageProtection protection = PageProtection::NoAccess;
    PageProtection initial_protection = PageProtection::NoAccess;
    // How many times NtProtectVirtualMemory has changed it.
    std::uint32_t protection_changes = 0;

    // The kind, and for an image region which section.
    RegionKind kind = RegionKind::Private;
    std::uint32_t section_index = 0;
    // The section's name, as a NUL-terminated byte array rather than a
    // `std::string` -- see the note above about why it cannot be one. Empty
    // for a non-image region, and *named* for an image one even though Windows
    // treats the name as advisory: this is what a person reading about a fault
    // at an address wants to see, and Wine's own `Region` does not keep it.
    //
    // A fixed 64 bytes, and a longer name is *truncated* rather than refused.
    // The alternative -- a length the caller allocates for -- is the Windows
    // shape for a variable-length answer, and this class has no room for a
    // length without growing every reader. Truncating loses information on a
    // name no program matches against; refusing would fail a query whose whole
    // purpose is to describe a region after a fault.
    static constexpr std::size_t kSectionNameCapacity = 64;
    char section[kSectionNameCapacity] = {};
    // The length actually written, excluding the NUL. Reported so a reader can
    // tell a name that fit from one that was cut short -- without it, a
    // truncated name and a complete one look identical, and a reader
    // debugging a module load needs to know which it is looking at.
    std::uint32_t section_length = 0;

    // Whether this region was created by an API that asks for memory the
    // program may later execute. Kept per-region rather than scanned from
    // the event stream because the question is asked of a region and the
    // answer should be a property of it.
    bool executable = false;
};

// ------------------------------------------------------------------------
// The functions
// ------------------------------------------------------------------------

// Every function below shares one shape:
//
//   * `ctx.space` is the address space operated on. A null one is refused
//     with `InvalidParameter` rather than dereferenced -- a program that
//     calls VirtualAlloc on a process whose space this runtime does not have
//     gets a status, not a fault.
//   * `ctx.target_process` other than zero is refused with `NotImplemented`
//     and a detail that says the reason is cross-process. See NtContext.
//   * The `*_ptr` outputs are written **only on success**, which is Windows'
//     rule and the one a program depends on: NtProtectVirtualMemory leaves
//     `*old_prot` untouched when it refuses, so a program that reads it after
//     a failure is reading what it had before rather than garbage.
//
// The `detail` on a failure is this runtime's, and says what was refused and
// why in a sentence -- a status alone tells a program what to do next and
// tells a person reading a log nothing.

// Reserves and/or commits memory.
//
// `zero_bits` limits the address to the top `2^(64-zero_bits)`. Wine rejects
// 22..31 and accepts 21 and 32, and that hole is Windows' and is copied: a
// program that works on Windows and fails here is a program this runtime is
// not compatible with, and the compatibility is the point.
//
// A null `addr` asks the runtime to choose; a non-null one is rounded *down*
// to the allocation granularity rather than refused, which is what Windows
// does and what `AddressSpace`'s comment on `record()` explains at length.
Result<std::uint64_t> nt_allocate_virtual_memory(NtContext& ctx,
                                                 std::uint64_t* addr,
                                                 std::uint64_t* size,
                                                 std::uint32_t zero_bits,
                                                 std::uint32_t type,
                                                 std::uint32_t protect) noexcept;

// `NtAllocateVirtualMemoryEx`: `NtAllocateVirtualMemory` with address
// requirements.
//
// The extra parameters are how a program says "allocate at or above this" or
// "align it to this", and they are mutually exclusive with a requested
// address -- Wine refuses the combination with `InvalidParameter`, and so
// does this. A repeated parameter type is also refused: a program that lists
// `MemExtendedParameterAddressRequirements` twice has asked two questions with
// one answer slot, and answering one of them silently is a guess.
struct MemExtendedParameterAddressRequirements {
    std::uint64_t lowest_starting_address = 0;
    std::uint64_t highest_ending_address = 0;
    std::uint64_t alignment = 0;
};

enum : std::uint32_t {
    kMemExtendedParameterAddressRequirements = 0,
    kMemExtendedParameterAttributeFlags = 1,
    kMemExtendedParameterImageMachine = 2,
    kMemExtendedParameterNumaNode = 3,
    kMemExtendedParameterPartitionHandle = 4,
};

struct MemExtendedParameter {
    std::uint32_t type = 0;
    const void* pointer = nullptr;
    std::uint64_t ulong_value = 0;
};

Result<std::uint64_t> nt_allocate_virtual_memory_ex(
    NtContext& ctx, std::uint64_t* addr, std::uint64_t* size,
    std::uint32_t type, std::uint32_t protect,
    const MemExtendedParameter* parameters, std::uint32_t count) noexcept;

// Frees memory. `MEM_RELEASE` requires the region's base and a size of zero;
// `MEM_DECOMMIT` takes any range inside it.
//
// The size of zero means two different things in the two types, and getting
// them backwards is a use-after-free: for `MEM_RELEASE` it means "the whole
// region, and only if I am at its base", and for `MEM_DECOMMIT` it is
// simply a refusal. Wine distinguishes them and so does this.
Result<std::uint64_t> nt_free_virtual_memory(NtContext& ctx,
                                             std::uint64_t* addr,
                                             std::uint64_t* size,
                                             std::uint32_t type) noexcept;

// Changes a region's protection.
//
// The whole region changes: `AddressSpace` does not split, and its
// `protect()` says why. Windows allows a partial protect, so this is a limit
// of the API rather than a statement about the platform, and it is a limit
// worth having -- a region that has had its protection changed twice is a
// different story from one changed fifty times, and a per-region count is
// only a per-region count.
//
// `PAGE_GUARD` is refused rather than silently treated as its base
// protection. A guard page is one whose first touch signals, Linux has no
// `mprotect` flag for it, and a caller that asked for a guard page and got
// ordinary read-write memory has a buffer overflow that does not fault.
Result<std::uint64_t> nt_protect_virtual_memory(NtContext& ctx,
                                                std::uint64_t* addr,
                                                std::uint64_t* size,
                                                std::uint32_t new_protect,
                                                std::uint32_t* old_protect) noexcept;

// Reads out of this process's address space into `buffer`.
//
// `bytes_read` is written even on failure, with zero. That is Wine's rule and
// it is the useful one: a program that reads the count before checking the
// status gets 0 rather than whatever was in the variable.
Result<std::uint64_t> nt_read_virtual_memory(NtContext& ctx,
                                             std::uint64_t addr,
                                             void* buffer,
                                             std::uint64_t size,
                                             std::uint64_t* bytes_read) noexcept;

// Writes into this process's address space from `buffer`.
//
// **The two directions report an unusable buffer differently, and the
// asymmetry is preserved.** A read whose destination is not writable is
// `AccessViolation`; a write whose source is not readable is `PartialCopy`.
// That is Wine's answer and it is Windows', and it is the kind of thing that
// looks like a typo until a program is found that branches on it. The reason
// is in the format: a write can genuinely be partial in general, so the code
// says so, while a read either copies all of it or none of it.
Result<std::uint64_t> nt_write_virtual_memory(NtContext& ctx,
                                              std::uint64_t addr,
                                              const void* buffer,
                                              std::uint64_t size,
                                              std::uint64_t* bytes_written) noexcept;

// Closes a handle.
//
// The counterpart of `HandleTable::insert`, and the operation that makes a
// double close detectable. See that class for why the slot's `open` flag is
// what is cleared rather than the entry being erased.
Status nt_close(NtContext& ctx, HandleTable& table, Handle handle) noexcept;

// Queries a region.
//
// `MemoryBasicInformation` is the one every program calls, and its `len` is
// checked against `sizeof` *first*: a program that allocated too little gets
// `InfoLengthMismatch` rather than a partially filled structure, which is the
// difference between a bug the program can find and a bug that reads garbage.
//
// The occ classes are documented at `MemoryInformationClass`. `Wine's own
// `MemoryWineUnixFuncs` returns `FIXME`'s nothing; this answers it.
Result<std::uint64_t> nt_query_virtual_memory(NtContext& ctx,
                                              std::uint64_t addr,
                                              MemoryInformationClass info_class,
                                              void* buffer,
                                              std::uint64_t len,
                                              std::uint64_t* result_length) noexcept;

// Flushes a region's dirty pages.
//
// A `size` of zero means "the whole region", which is the opposite of what
// zero means in `nt_free_virtual_memory` -- there it is "at the base". Both
// are Wine's readings and copying both is the only way one function's caller
// does not have to know which function it called.
Result<std::uint64_t> nt_flush_virtual_memory(NtContext& ctx,
                                              std::uint64_t* addr,
                                              std::uint64_t* size) noexcept;

// The write-watch calls.
//
// Wine implements these by walking pages and testing a per-page flag, so its
// `NtGetWriteWatch` returns "the pages in this range that are *not* under a
// write watch". This implementation answers from the ledger's own record of
// which regions were created with `mem::kWriteWatch`, so a range that spans
// two regions is answered per region rather than per page, and a page count
// that a per-page walk would round up to the page size is reported as the
// region it belongs to.
//
// That is the one place here this runtime is *more* precise than Wine, and it
// is worth being explicit that it is a difference in granularity rather than a
// difference in semantics: both answer "which parts of this range changed".
Result<std::uint64_t> nt_get_write_watch(NtContext& ctx,
                                         std::uint32_t flags,
                                         std::uint64_t base, std::uint64_t size,
                                         std::uint64_t* addresses,
                                         std::uint64_t* count,
                                         std::uint32_t* granularity) noexcept;

Result<std::uint64_t> nt_reset_write_watch(NtContext& ctx,
                                           std::uint64_t base,
                                           std::uint64_t size) noexcept;

// Pins and unpins memory.
//
// `mlock`/`munlock`. A refused pin is `AccessDenied`, which is the code for
// "the kernel said no" rather than for "the arguments were wrong" -- a program
// with a `RLIMIT_MEMLOCK` too low and a program that asked for a page-aligned
// zero-length range both fail here, and only one of them can be fixed by
// changing the arguments.
Result<std::uint64_t> nt_lock_virtual_memory(NtContext& ctx,
                                            std::uint64_t* addr,
                                            std::uint64_t* size) noexcept;

Result<std::uint64_t> nt_unlock_virtual_memory(NtContext& ctx,
                                              std::uint64_t* addr,
                                              std::uint64_t* size) noexcept;

// Whether two addresses are views of the same file.
//
// Anonymous memory -- anything `NtAllocateVirtualMemory` returned -- is
// `ConflictingAddresses` here and in Wine, not success and not
// `NotSameDevice`. Two addresses in the *same* anonymous region are the same
// memory; two in different ones are two private memories that happen to be
// incomparable. Wine answers by asking the server whether the two views share
// a file; this answers from the ledger, and there is no file identity in a
// ledger, so same-region is the strongest claim it can make and the other
// cases take Wine's codes.
Status nt_are_mapped_files_the_same(NtContext& ctx, std::uint64_t addr1,
                                    std::uint64_t addr2) noexcept;

// Prefetches a range, or -- for occ's own class -- refuses it with the reason.
//
// Wine's `NtSetInformationVirtualMemory` answers `VmPrefetchInformation` with
// `madvise(MADV_WILLNEED)` and `STATUS_INVALID_PARAMETER_2` for everything
// else. occ does the same and adds `VmPrefetchInformation`'s counterpart for
// the ledger: prefetching is a hint about *physical* pages, and this runtime
// can also answer a question about where a region came from.
enum class VirtualMemoryInformationClass : std::uint32_t {
    // Wine 0. `madvise(MADV_WILLNEED)`.
    PrefetchInformation = 0,
    // occ. Walks the ranges and reports which regions they cover, without
    // changing anything -- the read-only counterpart of the memory calls, and
    // the one a tool wants before it decides to rewrite a region.
    RegionQueryInformation = 0x1000,
};

struct MemoryRangeEntry {
    std::uint64_t virtual_address = 0;
    std::uint64_t number_of_bytes = 0;
};

Result<std::uint64_t> nt_set_information_virtual_memory(
    NtContext& ctx, VirtualMemoryInformationClass info_class,
    std::uint64_t count, const MemoryRangeEntry* addresses,
    const void* ptr, std::uint32_t size) noexcept;

// The instruction cache flush.
//
// A no-op on x86 and x64, where the instruction cache is coherent with the
// data cache, and *that is not a stub*: Wine is also a no-op here and returns
// `STATUS_SUCCESS`. What occ does that Wine does not is record the call in
// the ledger, so a run that flushed instruction caches can be told it did.
Result<std::uint64_t> nt_flush_instruction_cache(NtContext& ctx,
                                                 std::uint64_t addr,
                                                 std::uint64_t size) noexcept;

// Writes every dirty page of every region to its backing store.
//
// Wine stubs this: `FIXME("stub"); return STATUS_SUCCESS;` -- it reports
// success and does nothing, so a program that relies on the flush having
// happened has a data-loss bug that no error will ever report. This calls
// `msync(MS_SYNC)` over every writable region, and reports the first one that
// refused.
Result<std::uint64_t> nt_flush_process_write_buffers(NtContext& ctx) noexcept;

// Creates a page file.
//
// Wine stubs this too, and worse: it returns `STATUS_SUCCESS` and never writes
// `*actual_size`, so a program that sizes its page file from the answer reads
// whatever was in that variable. This reserves the requested range as
// `mem::kReserve` at an address of the runtime's choosing, writes the size
// actually reserved, and records the reservation as a region -- which is what
// a page file is on a system whose page file is an anonymous mapping, which is
// what a process's address space is on Linux without a page file of its own.
Result<std::uint64_t> nt_create_paging_file(NtContext& ctx,
                                            std::uint64_t min_size,
                                            std::uint64_t max_size,
                                            std::uint64_t* actual_size) noexcept;

// ------------------------------------------------------------------------
// Sections
// ------------------------------------------------------------------------

// Maps a view of a section.
//
// `commit_size` of zero commits the whole section, which is the value Windows
// documents and the one a program that wants a view of the whole thing passes.
// `zero_bits` is validated the same way `nt_allocate_virtual_memory` does,
// including the `zero_bits > 21 && < 32` hole.
Result<std::uint64_t> nt_map_view_of_section(NtContext& ctx,
                                             HandleTable& table, Handle handle,
                                             std::uint64_t* addr,
                                             std::uint32_t zero_bits,
                                             std::uint64_t commit_size,
                                             std::uint64_t offset,
                                             std::uint64_t* size,
                                             std::uint32_t inherit,
                                             std::uint32_t alloc_type,
                                             std::uint32_t protect) noexcept;

Result<std::uint64_t> nt_map_view_of_section_ex(
    NtContext& ctx, HandleTable& table, Handle handle, std::uint64_t* addr,
    std::uint64_t* size, std::uint32_t zero_bits, std::uint64_t commit_size,
    std::uint64_t offset, const MemExtendedParameter* parameters,
    std::uint32_t count, std::uint32_t inherit, std::uint32_t alloc_type,
    std::uint32_t protect) noexcept;

// Unmaps a view.
//
// The whole region, and the region's base -- the same rule
// `nt_free_virtual_memory` has, and for the same reason: this type does not
// split regions.
Result<std::uint64_t> nt_unmap_view_of_section(NtContext& ctx,
                                               std::uint64_t* addr,
                                               std::uint64_t* size) noexcept;

Result<std::uint64_t> nt_unmap_view_of_section_ex(NtContext& ctx,
                                                 std::uint64_t base) noexcept;

// What a section is.
//
// `SectionBasicInformation` and `SectionImageInformation` are Wine's two.
// Wine answers `NotImplemented` for every other class; occ adds
// `SectionSectionInformation` -- the size and address of the section object,
// which is what a program allocating from a section needs and what Wine cannot
// tell it.
enum class SectionInformationClass : std::uint32_t {
    // The section's attributes, base and size.
    BasicInformation = 0,
    // Whether the section is an image, and its entry point.
    ImageInformation = 1,
    // occ. The section's address and total size, as distinct from the base
    // and view size of `BasicInformation`: a program that is going to
    // allocate out of a section needs the section's extent, and
    // `BasicInformation`'s `BaseAddress` is always null.
    SectionInformation = 0x1000,
};

struct SectionBasicInformation {
    // SEC_IMAGE, SEC_FILE, SEC_RESERVE, SEC_COMMIT and the rest, as a bitmask.
    std::uint32_t attributes = 0;
    // Always zero: Wine sets it to NULL and so does this, because the address
    // a section is based at belongs to the server rather than to the section
    // and there is no address to report.
    std::uint64_t base_address = 0;
    std::uint64_t size = 0;
};

struct SectionImageInformation {
    std::uint64_t entry_point = 0;
    std::uint64_t image_base = 0;
    std::uint32_t image_size = 0;
    std::uint32_t image_flags = 0;
};

struct SectionSectionInformation {
    std::uint64_t section_address = 0;
    std::uint64_t section_size = 0;
};

Result<std::uint64_t> nt_query_section(NtContext& ctx,
                                       HandleTable& table, Handle handle,
                                       SectionInformationClass info_class,
                                       void* buffer, std::uint64_t len,
                                       std::uint64_t* result_length) noexcept;

// Creates a section.
//
// Wine's `NtCreateSection` lives in `section.c`, not `virtual.c`, and takes a
// file handle; a section with no file is the one a program creates to get
// shared memory, which is what this takes: a size, and nothing else. The
// handle it returns is a `HandleEntry::Kind::Section`.
Result<std::uint64_t> nt_create_section(NtContext& ctx, HandleTable& table,
                                         std::uint64_t size,
                                         std::uint32_t protect,
                                         Handle* handle) noexcept;

} // namespace occ::runtime
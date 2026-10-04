#pragma once

// The address space of a Windows process.
//
// This is the layer Wine does not have in one place. In Wine a virtual
// memory operation either stays in the calling process or is marshalled to
// a separate server process over a socket, and which of the two happens
// depends on the relationship between the caller and the target. That is
// two implementations of one API, and two implementations of one API drift.
//
// Here there is one. An AddressSpace is a value describing a set of mapped
// regions, and every operation on it -- allocate, free, protect, read,
// write -- is a method on that value. When the operation is for the calling
// process the value is reached through a thread-local pointer and when it
// is for another process it is reached through the object table, but that
// lookup is the only difference: everything below it is the same code, so
// there is no pair of behaviours to keep in step.
//
// The second thing this type exists for is that Wine's mappings live in the
// server and these live here. That is what makes "which region covers this
// address, when was it made, and with what protection" answerable at all,
// and it is the reason the runtime can explain itself rather than only
// report what it did.
//
// The bookkeeping is not a cache of the kernel's state. The kernel knows
// what is mapped; this knows what was *asked for*, by which call, in what
// order, and what happened. Those are different questions and the second
// one is the one an observer has.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "occ/util/span.h"

namespace occ::runtime {

// A page protection, in the values Windows uses.
//
// The real IMAGE_ constants are used rather than an invented enum so that a
// log line naming PAGE_EXECUTE_READWRITE names the thing the program asked
// for and not this project's word for it. Windows has no page protection
// equal to a combination of these: PAGE_READWRITE is one value, not
// READ|WRITE, and a reader that tries to or them together has misread the
// format.
enum class PageProtection : std::uint32_t {
    NoAccess = 0x01,
    ReadOnly = 0x02,
    ReadWrite = 0x04,
    WriteCopy = 0x08,
    Execute = 0x10,
    ExecuteRead = 0x20,
    ExecuteReadWrite = 0x40,
    ExecuteWriteCopy = 0x80,

    // The modifier bits, which are flags on the value above rather than
    // values of their own. PAGE_GUARD and PAGE_NOCACHE change what a page
    // does without changing what it allows, and a reader that treated them
    // as protection values would accept PAGE_GUARD alone and map something
    // with no access at all.
    Guard = 0x100,
    NoCache = 0x200,
    WriteCombine = 0x400,
};

// The base protection with the modifier bits removed.
[[nodiscard]] constexpr std::uint32_t protection_base(
    PageProtection p) noexcept {
    return static_cast<std::uint32_t>(p) & 0xffU;
}

[[nodiscard]] const char* protection_name(PageProtection p) noexcept;

// What a region was created for. Reported with every event because the
// answer to "why is this memory here" is usually the more interesting half
// of the question.
enum class RegionKind : std::uint8_t {
    // A section of a loaded image. Its extent came from the file.
    Image,
    // A region the program asked for through NtAllocateVirtualMemory.
    Private,
    // The stack the thread started on.
    Stack,
    // The TEB and the PEB.
    Control,
    // A section object mapped through NtMapViewOfSection.
    Mapped,
};

[[nodiscard]] const char* region_kind_name(RegionKind k) noexcept;

// One mapped region.
//
// The fields are the ones an observer needs and not the ones the kernel
// uses. There is no file descriptor here and no offset into a backing
// store, because those describe how the mapping was made and the questions
// worth answering are about what the region is and who asked for it.
struct Region {
    std::uint64_t base = 0;
    std::uint64_t size = 0;

    // The protection in effect, and the protection the region was created
    // with. They differ after a successful NtProtectVirtualMemory, and
    // keeping both is what lets a reader tell "this was made read-only"
    // from "this was made writable and then made read-only".
    PageProtection protection = PageProtection::NoAccess;
    PageProtection initial_protection = PageProtection::NoAccess;

    RegionKind kind = RegionKind::Private;

    // Which section of which image, for an image region. Empty otherwise.
    // The section name is advisory in the format and load-bearing here: it
    // is what a person reading about a fault at an address wants to see.
    std::string section;
    std::uint32_t section_index = 0;

    // The number of times this region has had its protection changed. A
    // region that has changed protection twice is a different story from
    // one that has changed fifty times, and the count is free to keep.
    std::uint32_t protection_changes = 0;

    // True when the region was created by an API that asks the kernel for
    // memory the program may later execute. Kept because the write-then-
    // execute question is asked of a region and the answer has to be a
    // property of the region rather than a scan of the event stream.
    bool executable = false;

    [[nodiscard]] std::uint64_t end() const noexcept { return base + size; }
    [[nodiscard]] bool contains(std::uint64_t addr) const noexcept {
        return addr >= base && addr < end();
    }
};

// Why an address space operation failed.
//
// The values are Windows NTSTATUS codes and they are kept as such because
// a program branches on them. An operation that returns "failure" and a
// string is an operation whose caller cannot behave differently for a
// conflict and for a bad parameter, which are the two cases that matter
// most in memory management.
enum class Status : std::uint32_t {
    Success = 0x00000000,
    // STATUS_INVALID_PARAMETER and its numbered variants. Windows
    // distinguishes "this parameter" from "the third parameter" and a
    // program that logs the difference is common enough to be worth the
    // extra values.
    InvalidParameter = 0xC000000D,
    InvalidParameter1 = 0xC00000EF,
    InvalidParameter2 = 0xC00000F0,
    InvalidParameter3 = 0xC00000F1,
    InvalidParameter4 = 0xC00000F2,
    // The requested range overlaps something already mapped.
    ConflictingAddresses = 0xC0000018,
    // The range is inside an existing region but was not itself allocated.
    // Windows can tell these apart and so can this, because the region map
    // is here rather than in a server that only stores the merged result.
    NotCommitted = 0xC000002C,
    // The range was never mapped at all.
    InvalidAddress = 0xC0000141,
    // The region is mapped from a file and cannot be changed as asked.
    SectionProtection = 0xC0000045,
    // The system is out of memory, or the request cannot be satisfied in
    // the address window it named.
    NoMemory = 0xC0000017,
    CommitLimit = 0xC000012D,
    // The operation is not one this runtime performs, and the caller
    // deserves to know the difference between "no" and "not implemented".
    NotImplemented = 0xC0000002,
};

[[nodiscard]] const char* status_name(Status s) noexcept;
[[nodiscard]] constexpr bool ok(Status s) noexcept {
    return static_cast<std::int32_t>(s) >= 0;
}

// The result of an operation that produces a value.
//
// A plain struct with a bool rather than std::expected because every
// failure here is a Status and nothing else, and because this type is on
// the hot path of every memory operation. The two-field form is what makes
// that possible; std::expected's generality is not needed and its
// constexpr machinery is not free.
template <typename T>
struct Result {
    T value{};
    Status status = Status::Success;

    [[nodiscard]] bool ok() const noexcept { return runtime::ok(status); }
};

// A set of mapped regions, and the operations that change it.
//
// Not thread-safe by design. The object table is the synchronization point
// and it is a separate concern; an address space that took a lock per
// operation would put a lock inside every memory operation of every thread
// to protect a structure that is changed far less often than it is read.
//
// Allocation granularity is 64 KiB on Windows and on this runtime, because
// a program that passes 64 KiB-aligned addresses is entitled to have them
// come back 64 KiB-aligned and a runtime that used the Linux 4 KiB
// granularity would return addresses the program did not expect. The page
// size, which is what mprotect works in, is 4 KiB and is a separate
// constant for a separate purpose.
class AddressSpace {
public:
    static constexpr std::uint64_t kGranularity = 0x10000;
    static constexpr std::uint64_t kPageSize = 0x1000;

    // The address window the space can hand out. The same values Windows
    // uses for a 64-bit process, kept as constants so that a refusal which
    // says "outside the address window" can also say where the window is.
    static constexpr std::uint64_t kUserMin = 0x10000;
    static constexpr std::uint64_t kUserMax = 0x7FFFFFFEFFFF;

    // The two roundings, named.
    //
    // They are the only arithmetic on addresses that every caller needs and
    // they are the two that get written wrong, in the same direction both
    // times: a page-rounded size computed as `size + 0xFFF` without the
    // mask, or a rounded-down base computed as `base - (base % page)` when
    // the base is already a multiple and the subtraction is a no-op that
    // reads as meaningful. Named here so that a caller says which rounding
    // it wants.
    //
    // `round_up` can wrap when size is near the top of the range, and that
    // is a real case for a request whose size a program chose. It returns
    // the wrapped value and the caller's window check catches it, which is
    // the same arrangement as everywhere else in this file: the rounding is
    // arithmetic and the refusal is a comparison.
    [[nodiscard]] static constexpr std::uint64_t round_up(
        std::uint64_t v, std::uint64_t unit) noexcept {
        return (v + unit - 1) & ~(unit - 1);
    }
    [[nodiscard]] static constexpr std::uint64_t round_down(
        std::uint64_t v, std::uint64_t unit) noexcept {
        return v & ~(unit - 1);
    }
    [[nodiscard]] static constexpr std::uint64_t page_round_up(
        std::uint64_t v) noexcept {
        return round_up(v, kPageSize);
    }
    [[nodiscard]] static constexpr std::uint64_t granularity_round_down(
        std::uint64_t v) noexcept {
        return round_down(v, kGranularity);
    }
    [[nodiscard]] static constexpr bool is_granular(
        std::uint64_t v) noexcept {
        return (v % kGranularity) == 0;
    }
    [[nodiscard]] static constexpr bool is_page_aligned(
        std::uint64_t v) noexcept {
        return (v % kPageSize) == 0;
    }

    // Records a region as mapped and returns it.
    //
    // This does not call mmap. The mapping is done by the caller that knows
    // whether the memory exists yet -- a section of an image is mapped from
    // a file, a private region is anonymous -- and this function is the
    // bookkeeping that has to follow. Separating them means the bookkeeping
    // can be tested against a space that is never mapped, which is what the
    // semantics cards for the Nt* layer do.
    //
    // Returns a failure when the region would overlap an existing one or
    // leaves the user window, so that the overlap check exists in exactly
    // one place.
    //
    // No alignment is required and none is imposed. That is deliberate and
    // it is the correction of a mistake, so the reasoning is worth stating:
    // the 64 KiB allocation granularity is a rule about
    // NtAllocateVirtualMemory's reservation requests, and Windows applies
    // it there by rounding the requested address *down* rather than
    // refusing it. A PE section is aligned to the section alignment, which
    // is 4 KiB in every real image, and the sections of one image are
    // contiguous 4 KiB-apart regions. A record() that demanded 64 KiB
    // alignment on every region could not represent a loaded image at all
    // -- the second section of every file would be refused. Alignment is a
    // rule of the layer that hands out addresses, and that layer is the
    // allocator, where allocate_aligned below applies it once.
    Result<std::uint64_t> record(std::uint64_t base, std::uint64_t size,
                                 PageProtection protection, RegionKind kind,
                                 std::string section = {},
                                 std::uint32_t section_index = 0) noexcept;

    // Records several regions as one operation: all of them, or none.
    //
    // The loader needs this and record() cannot provide it. Loading an image
    // records the headers and one region per section, and a file can be
    // damaged in a way that only becomes visible at the fourth section --
    // section two overlaps section one, or a section overlaps a region the
    // caller had already mapped. Calling record() in a loop commits the
    // first three before the fourth is refused, and the loader's own
    // contract says a refused load leaves the space unchanged. The choice
    // was therefore between a rollback (which needs a remove() and a way to
    // restore the allocation count, and every future writer has to remember
    // to pair the two) and a batch that cannot half-commit. The batch is
    // smaller and it is checkable: every candidate is validated against the
    // existing map and against the other candidates first, and the insert
    // loop below cannot fail.
    //
    // The candidates are validated in the order given, so the failure
    // reported is the first candidate that could not be placed, which is the
    // order a reader of the file would have reached them in.
    //
    // Returns the number of regions recorded, or the status of the first
    // candidate that could not be placed.
    struct Candidate {
        std::uint64_t base = 0;
        std::uint64_t size = 0;
        PageProtection protection = PageProtection::NoAccess;
        RegionKind kind = RegionKind::Private;
        std::string section;
        std::uint32_t section_index = 0;
    };
    Result<std::uint64_t> record_batch(const std::vector<Candidate>& batch) noexcept;

    // Finds the region containing an address, or nothing.
    [[nodiscard]] const Region* find(std::uint64_t addr) const noexcept;

    // Every region, in address order. Sorted rather than in insertion
    // order, because a reader looking at a dump of an address space is
    // reading a map and a map in insertion order is a puzzle.
    [[nodiscard]] const std::vector<Region>& regions() const noexcept {
        return regions_;
    }

    // The total bytes mapped, by kind. A convenience for the summary a run
    // prints at the end; computed rather than kept so that it cannot
    // disagree with the regions it describes.
    [[nodiscard]] std::uint64_t bytes_of_kind(RegionKind k) const noexcept;

    // What this space knows about non-determinism.
    //
    // A number that the space produces and a program observes: the address
    // an allocation without a requested base came back at. Recording the
    // sequence of these is what makes a run replayable, because a replay
    // has to hand back the same addresses or the program takes a different
    // path. This counter is the one the space owns; the replay log is a
    // separate structure that reads it.
    [[nodiscard]] std::uint64_t allocation_count() const noexcept {
        return allocation_count_;
    }

    // The highest address any region reaches. Used to bound a scan and to
    // answer "is this space empty".
    [[nodiscard]] std::uint64_t high_water() const noexcept;

private:
    // Kept sorted by base at all times so that find() is a binary search and
    // the regions() view needs no sorting pass. The insertion path is the
    // only writer and it restores the order, which is cheaper than sorting
    // on every read of a map that is read far more often than written.
    std::vector<Region> regions_;
    std::uint64_t allocation_count_ = 0;
};

} // namespace occ::runtime

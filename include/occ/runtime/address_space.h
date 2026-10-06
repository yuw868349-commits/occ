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
// The operations that create and destroy memory are on Mapper, in
// mapper.h, and this class holds the map they move. The split is the one the
// second paragraph below is about: this is a ledger, and a ledger that
// created memory would be untestable against a space that was never mapped.
// What the two must not do is disagree, which is why the pairs are paired --
// there is no public way to map memory into a space that does not know about
// it, and no way to forget a region whose memory is still there except
// remove(), which says in its comment what that costs.
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

    // Whether the pages are committed, as opposed to merely reserved.
    //
    // Windows has three states for a page -- free, reserved and committed --
    // and only the first two are address-space facts: a reserved range holds
    // the addresses and nothing else, and `MEM_DECOMMIT` moves a committed
    // range back to reserved without giving the addresses up. The ledger used
    // to have only "a region exists" and "it does not", which made DECOMMIT
    // indistinguishable from RELEASE and cost a program its reservations.
    //
    // A reserved region still occupies its addresses -- `find()` returns it,
    // no other `record()` may overlap it, and `NtAllocateVirtualMemory` with
    // `MEM_COMMIT` can commit it again -- but touching it faults, and that is
    // the whole of what the flag changes here.
    bool committed = true;

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
    InvalidParameter5 = 0xC00000F3,
    InvalidParameter6 = 0xC00000F4,
    // The requested range overlaps something already mapped.
    ConflictingAddresses = 0xC0000018,
    // The range is inside an existing region but was not itself allocated.
    // Windows can tell these apart and so can this, because the region map
    // is here rather than in a server that only stores the merged result.
    //
    // This was 0xC000002C and is 0xC000002D. A program that compares the
    // status numerically -- which is what a program written against the
    // realconstant does, and there are more of those than one would like --
    // was told "not committed" when the runtime meant "invalid parameter",
    // because 0xC000002C is `STATUS_INVALID_INFO_CLASS` and no Nt* path
    // produces it. The value is read out of Wine's include/ntstatus.h
    // rather than remembered, for the reason the whole enum is: a status
    // code is an ABI, and an ABI written from memory is a guess.
    NotCommitted = 0xC000002D,
    // The range was never mapped at all.
    InvalidAddress = 0xC0000141,
    // The region is mapped from a file and cannot be changed as asked.
    SectionProtection = 0xC000004E,
    // The system is out of memory, or the request cannot be satisfied in
    // the address window it named.
    NoMemory = 0xC0000017,
    CommitLimit = 0xC000012D,
    // The operation is not one this runtime performs, and the caller
    // deserves to know the difference between "no" and "not implemented".
    NotImplemented = 0xC0000002,

    // The rest of the codes the memory Nt* layer produces. Each value is
    // read out of Wine's include/ntstatus.h rather than remembered, and
    // that is not fastidiousness: three of the values this file carried
    // before the ntdll layer existed were wrong, and a program that
    // branches on a status numerically branches on the number, not on the
    // name this project gave it.
    //
    // Two of them exist in Windows rather than for Windows' sake. Windows
    // reuses 0xC0000045 for both `STATUS_IMAGE_ALREADY_LOADED` and
    // `STATUS_SECTION_PROTECTION`, and a runtime that "fixed" the collision
    // would answer SECTION_PROTECTION to a program asking about a loaded
    // image. So the value is 0xC000004E -- SECTION_PROTECTION's real one --
    // and the name says which of the two this is.

    // A pointer argument was null where the call requires one. Wine returns
    // this from NtProtectVirtualMemory, NtQuerySection and NtReadVirtualMemory,
    // and *not* from NtWriteVirtualMemory, which says PARTIAL_COPY for the
    // same kind of mistake. That asymmetry is Windows' and is preserved.
    AccessViolation = 0xC0000005,
    // A buffer the caller said was readable or writable is not. Used by
    // NtReadVirtualMemory (the destination) and NtWriteVirtualMemory (the
    // source) -- and the two use *different* codes, which is the single
    // most surprising thing in this group and is therefore named in the
    // header at the Nt* declarations as well as here.
    PartialCopy = 0x8000000D,
    // The `info_class` is not one this function answers.
    InvalidInfoClass = 0xC0000003,
    // The caller's buffer is smaller than the structure it asked about.
    // The query functions distinguish this from a bad parameter because a
    // program that allocated the wrong size has a bug a different program
    // does not, and the two want different advice.
    InfoLengthMismatch = 0xC0000004,
    // A handle that names nothing, or names something this call may not use.
    InvalidHandle = 0xC0000008,
    // The operation needs a privilege or a permission the caller does not
    // have. From NtLockVirtualMemory, where the kernel refused to pin.
    AccessDenied = 0xC0000022,
    // The release asked for more than the region has left. Distinct from
    // "not allocated" and from "not at base" because a program that walks
    // its own regions can hit all three and they need different responses.
    UnableToFreeVm = 0xC000001A,
    // The release named a size of zero at an address that is not the start
    // of its region. Windows requires MEM_RELEASE at a region's base, and
    // a program that frees an interior address is either confused or is
    // releasing a sub-allocation this runtime does not track.
    FreeVmNotAtBase = 0xC000009F,
    // The range is inside the address window but nothing is mapped there.
    // Distinct from InvalidAddress, which is about the address itself.
    MemoryNotAllocated = 0xC00000A0,
    // An offset or an address did not satisfy the alignment the section or
    // the allocation requires. From NtMapViewOfSection.
    MappedAlignment = 0xC0000220,
    // Two views of two files are not views of the same file. From
    // NtAreMappedFilesTheSame.
    NotSameDevice = 0xC00000D4,
    // SectionImageInformation was asked of something that is not an image.
    SectionNotImage = 0xC0000049,
    // The range is mapped but could not be flushed to its backing store.
    // Not the same as InvalidAddress: the memory exists and the msync
    // failed, which is a different problem with a different fix.
    NotMappedData = 0xC0000088,
};


[[nodiscard]] const char* status_name(Status s) noexcept;

// Whether a status means the operation succeeded.
//
// The two bits at the top of an NTSTATUS are a severity, not a sign, and
// treating them as a sign is a mistake this function made until the ntdll
// layer forced the question. `STATUS_PARTIAL_COPY` is `0x8000000D`: the high
// bit set, so read as a signed integer it is negative, but the severity in
// bits 30-31 is 2 -- a *warning*. A program asking to read a buffer this
// process cannot write has a bug, and Wine answers `STATUS_ACCESS_VIOLATION`
// there; a program asking to *write* through a buffer it cannot read is
// answered `STATUS_PARTIAL_COPY`, which Windows documents as a warning
// because a partial write is possible in general.
//
// The two callers here are not Windows' callers, though: nothing here does a
// partial write, so this runtime treats both as the failure they are. What it
// must not do is decide that by looking at the sign, because the next status
// added to this enum would then depend on whether somebody remembered which
// values have a high bit -- which is not a property a reader can see.
//
// Severity 0 is the only success. The severity field is what NTSTATUS defines,
// and using it makes "is this a warning or an error" a question the value can
// answer about itself.
[[nodiscard]] constexpr std::uint32_t status_severity(Status s) noexcept {
    return (static_cast<std::uint32_t>(s) >> 30) & 0x3U;
}

[[nodiscard]] constexpr bool ok(Status s) noexcept {
    return status_severity(s) == 0;
}

// Every status's severity must agree with what `ok()` claims.
//
// A status is added here when anNt* needs it, and the two ways to get it
// wrong are both silent. A *wrong value* sends a program that branches
// numerically down the wrong branch, which is why three of the values above
// were corrected against Wine's `ntstatus.h` rather than from memory. A wrong
// *severity* is worse, because `ok()` reads the top two bits and this enum
// had been deciding them with `status >= 0` -- so `STATUS_PARTIAL_COPY`,
// which is `0x8000000D` and therefore negative as an integer, would have
// been counted as a failure by the sign and would have been missed by a
// caller reading severity. Both are answered by the same rule, and the rule
// is checkable at compile time for every value:
//
//   severity 0 -- success. Nothing else.
//   severity 1 or 2 -- a failure this runtime reports.
//
// There is no third case, and this static assertion is what makes that a
// constraint on the enum rather than a sentence in a comment. A value with
// severity 3 -- `0xC0000000`'s neighbour, reserved by NTSTATUS for
// "unknown" -- would be reported as success by a sign test and as failure
// here, and the two must not both be live.
namespace detail {
constexpr bool a_status_is_mapped_correctly(Status s) noexcept {
    return s == Status::Success || status_severity(s) != 0;
}
static_assert(a_status_is_mapped_correctly(Status::Success));
static_assert(a_status_is_mapped_correctly(Status::InvalidParameter));
static_assert(a_status_is_mapped_correctly(Status::InvalidParameter1));
static_assert(a_status_is_mapped_correctly(Status::InvalidParameter2));
static_assert(a_status_is_mapped_correctly(Status::InvalidParameter3));
static_assert(a_status_is_mapped_correctly(Status::InvalidParameter4));
static_assert(a_status_is_mapped_correctly(Status::InvalidParameter5));
static_assert(a_status_is_mapped_correctly(Status::InvalidParameter6));
static_assert(a_status_is_mapped_correctly(Status::ConflictingAddresses));
static_assert(a_status_is_mapped_correctly(Status::NotCommitted));
static_assert(a_status_is_mapped_correctly(Status::InvalidAddress));
static_assert(a_status_is_mapped_correctly(Status::SectionProtection));
static_assert(a_status_is_mapped_correctly(Status::NoMemory));
static_assert(a_status_is_mapped_correctly(Status::CommitLimit));
static_assert(a_status_is_mapped_correctly(Status::NotImplemented));
static_assert(a_status_is_mapped_correctly(Status::AccessViolation));
static_assert(a_status_is_mapped_correctly(Status::PartialCopy));
static_assert(a_status_is_mapped_correctly(Status::InvalidInfoClass));
static_assert(a_status_is_mapped_correctly(Status::InfoLengthMismatch));
static_assert(a_status_is_mapped_correctly(Status::InvalidHandle));
static_assert(a_status_is_mapped_correctly(Status::AccessDenied));
static_assert(a_status_is_mapped_correctly(Status::UnableToFreeVm));
static_assert(a_status_is_mapped_correctly(Status::FreeVmNotAtBase));
static_assert(a_status_is_mapped_correctly(Status::MemoryNotAllocated));
static_assert(a_status_is_mapped_correctly(Status::MappedAlignment));
static_assert(a_status_is_mapped_correctly(Status::NotSameDevice));
static_assert(a_status_is_mapped_correctly(Status::SectionNotImage));
static_assert(a_status_is_mapped_correctly(Status::NotMappedData));
} // namespace detail

// The result of an operation that produces a value.
//
// A plain struct with a bool rather than std::expected because every
// failure here is a Status and nothing else, and because this type is on
// the hot path of every memory operation. The two-field form is what makes
// that possible; std::expected's generality is not needed and its
// constexpr machinery is not free.
//
// `detail` arrived with the ntdll layer and is a string rather than a
// `const char*` on purpose. A status says what to do next; it does not say
// which of five parameters was wrong, and a refusal that carries no
// information beyond the code is a refusal a person reading a log cannot
// act on. Wine's answer is a `TRACE` line, which is only visible under a
// debug build and to a debugger attached to it.
//
// The field costs a string on the success path, which is why it is not
// always there: it is empty on success and on every failure a caller that
// has already decided what to do. An empty detail is a statement that the
// status is the whole message, and the callers that leave it empty are the
// ones whose caller does not need a sentence -- a size of zero, say, where
// the status says everything.
template <typename T>
struct Result {
    T value{};
    Status status = Status::Success;

    // A sentence about this failure, or empty. Not a substitute for the
    // status and never to be branched on: a program branches on `status`,
    // and a program that branched on this string would break the first time
    // a sentence was reworded.
    //
    // `= {}` rather than left alone so that a `Result` built by aggregate
    // initialisation (`Result<T>{value}`) says "no detail" explicitly instead
    // of tripping the missing-field-initialiser warning on every success
    // path. The warning is the right one to have and silencing it by writing
    // the field is better than silencing it with a pragma: a reader of
    // `Result<T>{base}` should not have to look up whether the struct has a
    // third member.
    std::string detail = {};

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

    // Forgets a region. Does not unmap it.
    //
    // This exists for the mapper in mapper.h, and it exists as a separate
    // operation from record()'s absence for the reason the whole of that file
    // is about: the ledger and the kernel have to move together, and the
    // only way to let a caller with a kernel mapping in hand update the
    // ledger is to give it the one operation that updates the ledger alone.
    //
    // A caller that has not unmapped the memory and calls this has created a
    // mapping no operation can reach again. The header comment on the class
    // says the bookkeeping is not a cache of the kernel's state, and this is
    // where that stops being a defence and becomes a hazard: a ledger that
    // disagrees with the kernel is not a slow ledger, it is a wrong one. The
    // mapper orders the two operations so that the disagreement is visible
    // rather than silent.
    //
    // Returns the region's size, or InvalidAddress when no region starts at
    // `base`. Requiring the start rather than any address inside is the same
    // rule unmap() follows and for the same reason: a removal of a range
    // inside a region would have to decide what happens to the two halves,
    // and this type does not split.
    Result<std::uint64_t> remove(std::uint64_t base) noexcept;

    // Changes a region's recorded protection and counts the change.
    //
    // Does not call mprotect; the mapper in mapper.h does that and calls this
    // after the kernel has agreed, for the same reason unmap() calls remove()
    // after the kernel has agreed. A ledger that recorded a protection the
    // kernel never granted would answer "was this region ever writable" with
    // a yes that never happened, and that question is the one the whole
    // observer layer exists to answer.
    //
    // `initial_protection` is not touched. It is the answer to "what was this
    // made as", and a protection change does not rewrite it.
    //
    // Returns the new protection change count, or InvalidAddress when no
    // region starts at `base`.
    Result<std::uint32_t> set_protection(std::uint64_t base,
                                          PageProtection protection) noexcept;

    // Marks a range reserved and cleared of its commit, splitting the region
    // it lies in if the range does not cover it whole.
    //
    // This is `MEM_DECOMMIT`, and it is the one operation of the memory API
    // that changes what a range *is* without changing which addresses it
    // occupies. The range may start anywhere inside a region and may end
    // anywhere inside it -- Windows allows a decommit of the middle and is the
    // reason the operation cannot be an `unmap()` -- so the region is cut into
    // up to three parts and only the middle one loses its commit.
    //
    // Returns the number of bytes decommitted, or a status. The cut is
    // page-aligned outward: a range that starts or ends inside a page takes the
    // whole page, because a page is the unit the kernel commits and a
    // half-page reservation cannot exist.
    //
    // Refuses, rather than answering success, when the range reaches outside
    // the region that contains it, or when the region is not private memory.
    Result<std::uint64_t> decommit(std::uint64_t base, std::uint64_t size) noexcept;

    // Marks a region committed again after a decommit.
    //
    // This is `MEM_COMMIT` into a reservation that a `MEM_DECOMMIT` had
    // cleared, and it is the other half of the three-state model: the addresses
    // never moved, so nothing is cut here and the region is flipped back in
    // place. Returns the region's size, or InvalidAddress when no region starts
    // at `base`.
    Result<std::uint64_t> commit(std::uint64_t base) noexcept;

    // Finds the region containing an address, or nothing.
    //
    // **The returned pointer is only valid until the next call that adds or
    // removes a region.** The regions are a `std::vector<Region>`, so a
    // `record()` that grows the vector reallocates it and every pointer into it
    // dangles -- including interior ones, and including one the caller was
    // holding across an operation that happened to succeed.
    //
    // Two of the three are safe today and neither is safe by construction:
    // `set_protection()` rewrites a field of an existing element and does not
    // reallocate, so a pointer held across a protection change is fine; and
    // `erase()` does not shrink capacity, so a pointer into a region that is
    // merely *removed* still reads the bytes it had. A caller that relies on
    // either fact is relying on an implementation detail of one container, and
    // the failure when it stops holding is a use-after-free that a plain run
    // usually gets away with -- the freed memory still has the right bytes in
    // it. AddressSanitizer found exactly this in `nt_unmap_view_of_section`,
    // which read `region->size` after the unmap that removed the region.
    //
    // So: read what you need out of a `Region*` before the next call that
    // changes the set of regions, and do not hold one across a `map()`.
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

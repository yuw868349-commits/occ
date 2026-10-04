#pragma once

// Making memory real.
//
// The address space in address_space.h is a ledger. This file is the hand
// that moves what the kernel does and the ledger into the same step, which is
// the step neither of them can take alone.
//
// The split is not a layering preference. A ledger that maps nothing can be
// tested against spaces that were never mapped, which is what makes the
// overlap and window rules in record() checkable at all -- an address space
// whose every region cost a syscall would be a different kind of object to
// test and a much more expensive one. And a mapper that keeps no ledger cannot
// answer "which region covers this address", which is the question the
// observer layer exists to ask. Keeping them apart is what lets both be right.
//
// What cannot be kept apart is the *transaction*. Between "the kernel mapped
// it" and "the ledger recorded it" there is a window in which a second thread
// finds a region the map does not have, or a region the map has that nothing
// will ever free. So the operations that create and destroy memory come in
// pairs here: map() does the mmap and the record and undoes the mmap if the
// record refuses, and unmap() does the munmap and the removal and there is no
// way to call one without the other. There is deliberately no public way to
// map memory into an address space that does not know about it.
//
// The address space is a value, not a file, and this type holds a reference
// to one rather than owning it: a process has one address space and several
// subsystems that map into it, and an owning wrapper would either duplicate
// the map or hand out references to a copy. Not thread-safe, for the reason
// its header gives -- the object table is the synchronization point.

#include <sys/mman.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "occ/runtime/address_space.h"

namespace occ::runtime {

// Translates a Windows page protection into the kernel's.
//
// The translation is a function rather than an inline expression because the
// answer is not a mask operation and because it has to be one place: a
// translation written twice is a translation where the two copies disagree
// about PAGE_WRITECOPY, which is the value most likely to be gotten wrong
// because it looks like a protection with a copy semantic rather than a
// protection at all.
//
// The four executable protections and the two write-copy ones are the whole
// of the mapping. Written as a switch over the enumerated values rather than
// as arithmetic on them, for the reason Region::executable is: the constants
// are powers of two that do not compose into the protection they name.
[[nodiscard]] constexpr int protection_to_prot(PageProtection p) noexcept {
    switch (protection_base(p)) {
    case 0x01: // PAGE_NOACCESS
        return PROT_NONE;
    case 0x02: // PAGE_READONLY
        return PROT_READ;
    case 0x04: // PAGE_READWRITE
        return PROT_READ | PROT_WRITE;
    case 0x08: // PAGE_WRITECOPY
        return PROT_READ;
    case 0x10: // PAGE_EXECUTE
        return PROT_EXEC;
    case 0x20: // PAGE_EXECUTE_READ
        return PROT_READ | PROT_EXEC;
    case 0x40: // PAGE_EXECUTE_READWRITE
        return PROT_READ | PROT_WRITE | PROT_EXEC;
    case 0x80: // PAGE_EXECUTE_WRITECOPY
        return PROT_READ | PROT_EXEC;
    default:
        return PROT_NONE;
    }
}

// Why a mapping operation failed, in the kernel's own words.
//
// A mapper reports the errno beside the Windows status rather than instead
// of it. The two answer different questions -- STATUS_NO_MEMORY says what a
// program can branch on and EACCES says why this particular attempt on this
// particular kernel did not work -- and a layer that reports only the first
// has thrown away the only information that distinguishes "this cannot work
// here" from "this cannot work now".
struct MapFailure {
    Status status = Status::NoMemory;
    int error = 0;
    // The address the kernel refused or could not place, when the failure is
    // about an address. Zero for a failure that is not.
    std::uint64_t address = 0;
};

class Mapper {
public:
    explicit Mapper(AddressSpace& space) noexcept : space_(&space) {}

    Mapper(const Mapper&) = delete;
    Mapper& operator=(const Mapper&) = delete;
    Mapper(Mapper&&) = delete;
    Mapper& operator=(Mapper&&) = delete;

    [[nodiscard]] AddressSpace& space() const noexcept { return *space_; }

    // Maps `size` bytes at `base` and records the region. Either both happened
    // or neither did.
    //
    // `base` must be page aligned and `size` is rounded up to a page, because
    // the kernel rounds `size` up regardless and a caller that computed its
    // own end address from the unrounded size would be wrong by up to 4095
    // bytes about where its own mapping ends. A base that is not page aligned
    // is refused with InvalidParameter rather than rounded down, because
    // rounding the base down would map memory the caller did not ask for at
    // an address it did not name, and the ledger would then describe a
    // region the caller never requested.
    //
    // A zero base asks the kernel to choose. The chosen address is what the
    // result carries and what the ledger records; this runtime does not
    // reserve a base of its own, because a runtime that picked addresses
    // would have to keep the reservation policy and the collision policy and
    // the answer to "where does the stack go" in one place, and the kernel's
    // mmap already is that place and already does the collision avoidance.
    Result<std::uint64_t> map(std::uint64_t base, std::uint64_t size,
                              PageProtection protection, RegionKind kind,
                              std::string section = {},
                              std::uint32_t section_index = 0) noexcept;

    // Maps several regions as one operation: all of them mapped and recorded,
    // or none of either.
    //
    // The loader needs this for the same reason it needs record_batch: a file
    // can be damaged in a way that only shows at the fourth section, and a
    // load that mapped the first three and then refused leaves a program
    // running with three of its sections present. The rollback here is by
    // munmap of what this call mapped, in reverse order, and it is exact
    // because every mapping in the batch was made with MAP_FIXED_NOREPLACE
    // at an address this call chose -- none of them can be a mapping someone
    // else made, so none of them can be mistaken for one during the undo.
    struct Candidate {
        std::uint64_t base = 0;
        std::uint64_t size = 0;
        PageProtection protection = PageProtection::NoAccess;
        RegionKind kind = RegionKind::Private;
        std::string section;
        std::uint32_t section_index = 0;
    };
    Result<std::uint64_t> map_batch(const std::vector<Candidate>& batch) noexcept;

    // Unmaps a whole region and removes it from the ledger.
    //
    // The address has to name a region exactly, not a range inside one. That
    // is stricter than NtUnmapViewOfSection, which takes a range and splits,
    // and it is stricter on purpose: splitting a region means the ledger
    // learns about two regions where there was one, and the caller of a
    // partial unmap has to be able to name which of them it meant. A runtime
    // that split silently would make "the region that covers this address"
    // a different answer before and after a call that a reader would call the
    // same call.
    Result<std::uint64_t> unmap(std::uint64_t base) noexcept;

    // Changes a region's protection and updates the ledger.
    //
    // The whole region changes. A partial protect would split it, for the
    // reason unmap() does not, and Windows's NtProtectVirtualMemory does
    // allow a partial one -- so this is a limit of this API and not a
    // statement about the platform. It is the limit that lets the change
    // counter mean what its comment says: a region that has had its
    // protection changed twice is a different story from one changed fifty
    // times, and a per-region count is only a per-region count.
    //
    // PAGE_GUARD is refused. A guard page is a page whose first touch
    // signals and which then becomes ordinary, and Linux has no mprotect
    // flag for it: the closest is PROT_NONE plus a signal handler, which is a
    // mechanism this runtime does not have a place for yet. Refusing it
    // rather than silently treating it as its base protection is the whole
    // point of the modifier bits being separate from the protections -- a
    // caller that asked for a guard page and got ordinary read-write memory
    // has a buffer overflow that does not fault.
    Result<std::uint32_t> protect(std::uint64_t base,
                                  PageProtection protection) noexcept;

    // The address the last failure named, and the errno behind it. Kept on
    // the mapper so that a caller that only wants the status does not have to
    // declare a place to put the detail, and so that the detail cannot be
    // lost between the layer that produced it and the layer that reports it.
    [[nodiscard]] const MapFailure& last_failure() const noexcept {
        return last_failure_;
    }

    // How many regions this mapper has mapped and unmapped. The address
    // space counts allocations; this counts the operations that actually
    // reached the kernel, which is the number that distinguishes a test of
    // the ledger from a test of the mapper.
    [[nodiscard]] std::uint64_t syscalls_made() const noexcept {
        return syscalls_made_;
    }

private:
    // Records the failure and returns it, so that a refusal path is one
    // line at the call site and the errno cannot be forgotten on one of
    // them.
    template <typename T>
    Result<T> fail(Status status, int error, std::uint64_t address) noexcept {
        last_failure_ = MapFailure{status, error, address};
        Result<T> out;
        out.status = status;
        return out;
    }

    AddressSpace* space_;
    MapFailure last_failure_{};
    std::uint64_t syscalls_made_ = 0;
};

} // namespace occ::runtime

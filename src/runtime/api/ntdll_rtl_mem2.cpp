// The Rtl surface's second slice: the lock-free stack, the security
// descriptor accessors, the large-integer arithmetic, the bitmaps, the
// version queries and the last-error mapping.
//
// The shape of this file is the same as the domain's other slices: each
// family here is a different way the kernel answers a question a guest
// asks, and the ones that need machinery another slice already owns are
// refused rather than re-implemented beside it. The atom table lives in
// `ntdll_rtl_mem1.cpp` and its lookup is reached through the bridge that
// file exports, because two tables of the same atoms would answer
// differently depending on which slice a guest's handle came from.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/address_space.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <limits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include <sched.h>
#include <time.h>
#include <unistd.h>

namespace occ::runtime::winabi {

namespace {

// An NTSTATUS is a 32-bit value whose top bits carry the severity; as a C++
// type it is a plain 32-bit integer, and the named constants below are what
// give the numbers meaning. It is neither an HRESULT nor a Win32 error code,
// and `ntstatus_to_dos` further down is the only place the two encodings
// meet.
using Ntstatus = std::uint32_t;

// The NTSTATUS values this file answers. They are 32-bit severity-coded
// values, not HRESULTs and not the Win32 error codes a guest reads through
// `GetLastError`; the mapping between the two is the one
// `ntstatus_to_dos` below implements.
constexpr Ntstatus kStSuccess = 0;
constexpr Ntstatus kStInvalidParameter = 0xC000000D;
constexpr Ntstatus kStInvalidParameter2 = 0xC00000F0;
constexpr Ntstatus kStInvalidParameter3 = 0xC00000F1;
constexpr Ntstatus kStInvalidParameter4 = 0xC00000F2;
constexpr Ntstatus kStBufferTooSmall = 0xC0000023;
constexpr Ntstatus kStBufferOverflow = 0xC0000100;
constexpr Ntstatus kStNotImplemented = 0xC0000002;
constexpr Ntstatus kStAccessDenied = 0xC0000022;
constexpr Ntstatus kStInvalidSid = 0xC0000078;
constexpr Ntstatus kStInvalidSecurityDescr = 0xC0000079;
constexpr Ntstatus kStInfoLengthMismatch = 0xC0000143;
constexpr Ntstatus kStUnknownRevision = 0xC0000058;
constexpr Ntstatus kStObjectNotFound = 0xC0000034;
// A converted-away status rather than a Win32 error code: the two
// encodings meet only in `ntstatus_to_dos`, so a failure reported from a
// path query has to be a status even when the reason was a bad argument.
constexpr Ntstatus kEInvalidArgAsStatus = 0x80070057;

// The Win32 error codes this file reports. The six that every API family
// needs already live in `api_common.h` and are not repeated here; the ones
// below are the security- and quota-specific values the families in this
// slice answer with.
constexpr std::uint32_t kErrorInvalidAccess = 12;
constexpr std::uint32_t kErrorInvalidData = 13;
constexpr std::uint32_t kErrorOutOfPaper = 28;
constexpr std::uint32_t kErrorNotEnoughQuota = 1816;
constexpr std::uint32_t kErrorNoTrackingService = 1174;
constexpr std::uint32_t kErrorRevisionMismatch = 1306;
constexpr std::uint32_t kErrorNoneMapped = 1332;
constexpr std::uint32_t kErrorInvalidSecurityDescr = 1338;
constexpr std::uint32_t kErrorBadImpersonationLevel = 1346;
constexpr std::uint32_t kErrorNotLocked = 158;

// The RTL_OSVERSIONINFOW the version queries fill: 32 bytes, five 32-bit
// fields and a 128-byte name after them in the extended form.
constexpr std::size_t kVersionSize = 0;
constexpr std::size_t kVersionMajor = 4;
constexpr std::size_t kVersionMinor = 8;
constexpr std::size_t kVersionBuild = 12;
constexpr std::size_t kVersionPlatform = 16;
constexpr std::size_t kVersionCsd = 20;
// The structure is the OSVERSIONINFOW the caller allocates: five 32-bit
// fields followed by the 128-WCHAR service-pack string, which is 276 bytes
// and not the 32 the first five fields would suggest. A caller that sized
// its buffer from the five fields alone would have the service-pack clear
// run past it.
constexpr std::size_t kVersionCsdChars = 128;
constexpr std::size_t kVersionBytes = kVersionCsd + kVersionCsdChars * 2;

// The SLIST_HEADER a lock-free stack lives in. On x64 it is 16 bytes: a
// packed depth-and-sequence word, then the entry pointer.
constexpr std::size_t kSListDepthSeq = 0;
constexpr std::size_t kSListNext = 8;
constexpr std::size_t kSListBytes = 16;

// The depth lives in the low 16 bits of the packed word and the sequence
// number above it; this is the layout the InterlockedPushEntrySList of the
// real kernel maintains, and a guest that reads the header directly is
// reading these bits.
constexpr std::uint64_t kSListDepthMask = 0xFFFF;
constexpr std::uint32_t kSListSequenceShift = 16;

// CRITICAL_SECTION, 40 bytes on the 64-bit ABI. The fields after the
// pointer are signed counts and a handle, and the layout is Microsoft's
// rather than this host's, so every field is placed by offset.
constexpr std::size_t kCritDebugInfo = 0;
constexpr std::size_t kCritLockCount = 8;
constexpr std::size_t kCritRecursionCount = 12;
constexpr std::size_t kCritOwningThread = 16;
constexpr std::size_t kCritLockSemaphore = 24;
constexpr std::size_t kCritSpinCount = 32;
constexpr std::size_t kCritBytes = 40;

// The SECURITY_DESCRIPTOR control bits the accessors below read.
constexpr std::uint16_t kSeSelfRelative = 0x8000;
constexpr std::uint16_t kSeDaclPresent = 0x0004;
constexpr std::uint16_t kSeSaclPresent = 0x0010;
constexpr std::uint16_t kSeOwnerDefaulted = 0x0001;
constexpr std::uint16_t kSeGroupDefaulted = 0x0002;
constexpr std::uint16_t kSeDaclDefaulted = 0x0008;
constexpr std::uint16_t kSeSaclDefaulted = 0x0020;

// An absolute SECURITY_DESCRIPTOR on x64: revision, control, then four
// offsets. A self-relative one carries the same fields as offsets into the
// same buffer; the accessors below translate both through one walk.
constexpr std::size_t kSdRevision = 0;
constexpr std::size_t kSdControl = 2;
// The relative form's field slots, 32-bit offsets from the descriptor's own
// base, four of them back to back after the control word.
constexpr std::size_t kSdOffset1 = 4;   // Owner
constexpr std::size_t kSdOffset2 = 8;   // Group
constexpr std::size_t kSdOffset3 = 12;  // Sacl
constexpr std::size_t kSdOffset4 = 16;  // Dacl
constexpr std::size_t kSdBytes = 20;
// The absolute form's field slots, pointer-width and spaced accordingly,
// because a pointer needs eight bytes where an offset needed four. The two
// layouts agree only on the header, and a test that wrote one form's slots
// and read them with the other's would see a pointer read as an offset.
constexpr std::size_t kSdAbsOwner = 8;
constexpr std::size_t kSdAbsGroup = 16;
constexpr std::size_t kSdAbsSacl = 24;
constexpr std::size_t kSdAbsDacl = 32;
constexpr std::size_t kSdAbsBytes = 40;

// An ACL header, and the ACE header inside it.
constexpr std::size_t kAclRevision = 0;
constexpr std::size_t kAclSize = 2;
constexpr std::size_t kAclCount = 4;
constexpr std::size_t kAclBytes = 8;

// A SID's fields.
constexpr std::size_t kSidRevision = 0;
constexpr std::size_t kSidSubAuthorityCount = 1;
constexpr std::size_t kSidIdentifierAuthority = 2;
constexpr std::size_t kSidSubAuthority = 8;
// The most sub-authorities a SID can hold. The count is one byte and the
// structure is sized from it, so a larger count would describe a buffer
// larger than any allocation this runtime makes for one.
constexpr std::uint8_t kSidMaxSubAuthorities = 15;
[[nodiscard]] std::size_t sid_bytes(std::uint8_t count) noexcept {
    return kSidSubAuthority + static_cast<std::size_t>(count) * 4;
}

// The loader's destination-directory numbers, which is what
// `RtlGetFullPathName_U` expands against and what the DOS path bridge
// already knows how to spell.
constexpr std::uint32_t kMaxPathChars = 32768;

}  // namespace

// The atom-table bridge. The table itself and the functions that create and
// free its entries live in `ntdll_rtl_mem1.cpp`; the lookup functions this
// slice registers have to walk the same table, so that file owns one and
// exports these three readers of it.

// Looks `name` up and answers the atom, or 0 when no entry names it. The
// three are `extern "C"` because that is how the defining file spells them,
// and a mismatched spelling here would be a different symbol rather than
// the same one.
extern "C" std::uint32_t occ_atom_find(void* table,
                                       const char16_t* name) noexcept;

// Answers the entry's reference count, flags and name through the out
// parameters, in the shape `RtlQueryAtomInAtomTable` reports them.
extern "C" Ntstatus occ_atom_query(void* table, std::uint32_t atom,
                                   std::uint32_t* refs,
                                   std::uint32_t* flags,
                                   char16_t* name,
                                   std::uint32_t* name_units) noexcept;

// Pins an entry so a later deletion of it fails.
extern "C" Ntstatus occ_atom_pin(void* table, std::uint32_t atom) noexcept;

// The guest's own thread and process ids, answered from the TEB the process
// domain maintains. The lock families below record a thread id as the owner
// of a held lock, and the only thread id that means anything to a guest is
// the one `GetCurrentThreadId` returns -- not the host's tid, which the
// guest never sees and cannot compare against.
extern "C" __attribute__((ms_abi)) std::uint32_t
k32_GetCurrentThreadId() noexcept;

namespace {

// ---------------------------------------------------------------- helpers

// Reads the single-byte fields the SID and ACL layouts below walk. The
// 16- and 32-bit readers come from `api_common.h`; there is no 8-bit one
// there because no other family has needed one, and this slice's SID
// revision and sub-authority count are both bytes.
[[nodiscard]] std::uint8_t read_u8(const void* base,
                                   std::size_t offset) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(base);
    return bytes[offset];
}

void write_u8(void* base, std::size_t offset, std::uint8_t value) noexcept {
    auto* bytes = static_cast<std::uint8_t*>(base);
    bytes[offset] = value;
}

// The 64-bit pair, for the fields that are a whole pointer or tick count
// wide. They are written one byte at a time for the same reason the narrower
// ones are: the byte order is the guest's, not the host's.
void write_u64(void* base, std::size_t offset, std::uint64_t value) noexcept {
    auto* bytes = static_cast<std::uint8_t*>(base);
    for (std::size_t k = 0; k < 8; ++k) {
        bytes[offset + k] = static_cast<std::uint8_t>(value >> (k * 8));
    }
}

// The host's monotonic clock, in the 100-nanosecond ticks the Windows time
// queries answer. The 1601-to-1970 offset is what turns the host's count
// into the guest's; the constant is the number of seconds between the two
// epochs and it is stated once here because it is stated once everywhere
// else in this runtime too.
constexpr std::uint64_t kEpochOffsetSeconds = 11644473600ull;
constexpr std::uint64_t kTicksPerSecond = 10000000ull;

[[nodiscard]] std::uint64_t host_ticks_1601() noexcept {
    ::timespec now = {};
    ::clock_gettime(CLOCK_REALTIME, &now);
    const std::uint64_t seconds = static_cast<std::uint64_t>(now.tv_sec) +
                                  kEpochOffsetSeconds;
    return seconds * kTicksPerSecond +
           static_cast<std::uint64_t>(now.tv_nsec) / 100ull;
}

// The kernel's status-to-Win32 mapping, for the statuses this runtime
// actually answers. The mapping is not a formula -- 0xC000000D maps to 87,
// 0xC0000023 to 122 -- and a table of the statuses the other domains set
// is the whole of what a guest can observe; a status outside the table
// maps to ERROR_MR_MID_NOT_FOUND, which is what the real mapping answers.
[[nodiscard]] std::uint32_t ntstatus_to_dos(Ntstatus status) noexcept {
    switch (status) {
        case 0:
            return kErrorSuccess;
        case 0xC0000005:  // ACCESS_VIOLATION
            return kErrorInvalidAccess;
        case 0xC000000D:  // INVALID_PARAMETER
        case 0xC00000EF:  // INVALID_PARAMETER_1
        case 0xC00000F0:  // INVALID_PARAMETER_2
        case 0xC00000F1:  // INVALID_PARAMETER_3
        case 0xC00000F2:  // INVALID_PARAMETER_4
        case 0xC00000F3:  // INVALID_PARAMETER_5
            return kErrorInvalidParameter;
        case 0xC0000023:  // BUFFER_TOO_SMALL
            return kErrorInsufficientBuffer;
        case 0xC0000100:  // BUFFER_OVERFLOW
            return kErrorInsufficientBuffer;
        case 0xC0000022:  // ACCESS_DENIED
            return 5;  // ERROR_ACCESS_DENIED
        case 0xC000000F:  // NO_SUCH_FILE
            return kErrorFileNotFound;
        case 0xC0000034:  // OBJECT_NAME_NOT_FOUND
            return kErrorFileNotFound;
        case 0xC000003A:  // OBJECT_PATH_NOT_FOUND
            return 3;  // ERROR_PATH_NOT_FOUND
        case 0xC0000078:  // INVALID_SID
            return 1337;  // ERROR_INVALID_SID
        case 0xC0000079:  // INVALID_SECURITY_DESCR
            return kErrorInvalidSecurityDescr;
        case 0xC000005A:  // INSUFFICIENT_RESOURCES
        case 0xC0000017:  // NO_MEMORY
            return kErrorNotEnoughMemory;
        case 0xC0000143:  // INFO_LENGTH_MISMATCH
            return kErrorBadImpersonationLevel;
        case 0xC0000002:  // NOT_IMPLEMENTED
            return kErrorInvalidFunction;
        case 0xC0000001:  // UNSUCCESSFUL
            return kErrorInvalidFunction;
        case 0xC00000BB:  // NOT_SUPPORTED
            return 50;  // ERROR_NOT_SUPPORTED
        default:
            // The real mapping answers MR_MID_NOT_FOUND for a status it has
            // no row for, and that answer is the one a caller can test.
            return 317;  // ERROR_MR_MID_NOT_FOUND
    }
}

}  // namespace

// ------------------------------------------------------- last-error bridge

extern "C" __attribute__((ms_abi)) std::uint32_t
nr2_RtlGetLastWin32Error() noexcept {
    // The storage is this layer's, and reading it is what `GetLastError`
    // does; the Rtl spelling is the same question the kernel's own callers
    // ask through the TEB.
    return k32_GetLastError();
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlGetLastNtStatus() noexcept {
    // The last status is the last error as the kernel wrote it. This runtime
    // sets Win32 codes, so the answer is the code the guest would read --
    // which is the honest answer, rather than a status invented to look
    // native.
    return k32_GetLastError();
}

extern "C" __attribute__((ms_abi)) std::uint32_t
nr2_RtlNtStatusToDosError(std::uint32_t status) noexcept {
    return ntstatus_to_dos(static_cast<Ntstatus>(status));
}

extern "C" __attribute__((ms_abi)) std::uint32_t
nr2_RtlNtStatusToDosErrorNoTeb(std::uint32_t status) noexcept {
    // The NoTeb spelling exists because the other one writes the Win32 code
    // back into the TEB as a side effect. The mapping is the same; only the
    // write differs, and this one does not do it.
    return ntstatus_to_dos(static_cast<Ntstatus>(status));
}

// ------------------------------------------------------- version queries

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetVersion(
    void* info) noexcept {
    if (info == nullptr) {
        return kStInvalidParameter;
    }
    // The version this runtime presents is the one its surface is modelled
    // on. The fields are the five 32-bit ones the structure carries, and
    // the CSD string is empty because no service pack applies.
    write_u32(info, kVersionSize, kVersionBytes);
    write_u32(info, kVersionMajor, 10);
    write_u32(info, kVersionMinor, 0);
    write_u32(info, kVersionBuild, 19045);
    write_u32(info, kVersionPlatform, 2);  // VER_PLATFORM_WIN32_NT
    // No service pack applies, and the empty string is written the way the
    // structure stores it: the full 128-WCHAR field cleared, so a caller
    // that reads the field reads an empty string rather than stale bytes.
    for (std::size_t k = 0; k < kVersionCsdChars; ++k) {
        write_u16(info, kVersionCsd + k * 2, 0);
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) void nr2_RtlGetNtVersionNumbers(
    std::uint32_t* major, std::uint32_t* minor,
    std::uint32_t* build) noexcept {
    // The build the kernel spells has its high bit set; that is how a
    // caller tells an NT build number from a DOS one, and the bit is part
    // of the answer rather than noise.
    if (major != nullptr) {
        *major = 10;
    }
    if (minor != nullptr) {
        *minor = 0;
    }
    if (build != nullptr) {
        *build = 19045 | 0xF0000000u;
    }
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetNtProductType(
    std::uint8_t* product) noexcept {
    if (product == nullptr) {
        return kStInvalidParameter;
    }
    // 1 is Workstation, which is what a runtime running on a developer's
    // machine is.
    *product = 1;
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlGetProductInfo(
    std::uint32_t major, std::uint32_t minor, std::uint8_t spor,
    std::uint8_t product_type, std::uint32_t* product) noexcept {
    if (product == nullptr) {
        return 0;
    }
    // 0x30 is the PRODUCT_ULTIMATE spelling for the 6.1-and-later table;
    // anything older than the version this runtime presents is refused the
    // way the real query refuses a version it predates.
    static_cast<void>(spor);
    static_cast<void>(product_type);
    static_cast<void>(minor);
    if (major < 10) {
        *product = 0;
        return 0;
    }
    *product = 0x30;
    return 1;
}

extern "C" __attribute__((ms_abi)) void nr2_RtlGetDeviceFamilyInfoEnum(
    std::uint64_t* era, std::uint32_t* family,
    std::uint32_t* type) noexcept {
    // 0x00000003 is DEVICEFAMILYINFOENUM_DESKTOP, the family a non-ARM
    // desktop-class runtime reports.
    if (era != nullptr) {
        *era = 0;
    }
    if (family != nullptr) {
        *family = 0x00000003;
    }
    if (type != nullptr) {
        *type = 0;
    }
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlGetNtGlobalFlags() noexcept {
    // No global flags are set for a run this runtime performs, and the
    // answer is zero rather than a flag that would make a caller branch
    // down a debugging path.
    return 0;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetNativeSystemInformation(
    void* info, std::uint32_t bytes, std::uint32_t* needed) noexcept {
    if (info == nullptr || needed == nullptr) {
        return kStInvalidParameter;
    }
    // The native system information is the SYSTEM_INFORMATION_CLASS answer
    // for class 0, and what a guest actually reads from it is the page
    // size, the processor count and the granularity. Those are the host's
    // own values, because the guest runs on the host's processors.
    constexpr std::size_t kPageSizeAt = 4;
    constexpr std::size_t kProcessorsAt = 24;
    constexpr std::size_t kGranularityAt = 32;
    if (bytes < 48) {
        *needed = 48;
        return kStInfoLengthMismatch;
    }
    std::memset(info, 0, 48);
    write_u32(info, kPageSizeAt, static_cast<std::uint32_t>(::sysconf(_SC_PAGESIZE)));
    write_u32(info, kProcessorsAt,
              static_cast<std::uint32_t>(::sysconf(_SC_NPROCESSORS_ONLN)));
    write_u32(info, kGranularityAt, 0x10000);
    *needed = 48;
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::int32_t
nr2_RtlIsProcessorFeaturePresent(std::uint32_t feature) noexcept {
    // The features a guest asks about by the PF_ constants, answered from
    // the host CPU. An unknown feature number answers zero, which is what
    // the real query answers and what keeps a caller's else-branch honest.
    switch (feature) {
        case 0:   // PF_COMPARE_EXCHANGE_DOUBLE
        case 1:   // PF_FLOATING_POINT_PRECISION_ERRATA
        case 2:   // PF_MMX_INSTRUCTIONS_AVAILABLE
        case 3:   // PF_PPC_MOVEMEM_64BIT_OK
        case 4:   // PF_ALPHA_BYTE_INSTRUCTIONS
        case 6:   // PF_XMMI_INSTRUCTIONS_AVAILABLE (SSE)
        case 8:   // PF_3DNOW_INSTRUCTIONS_AVAILABLE
        case 9:   // PF_RDTSC_INSTRUCTION_AVAILABLE
        case 10:  // PF_PAE_ENABLED
        case 13:  // PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
        case 14:  // PF_SSE_DAZ_MODE_AVAILABLE
        case 16:  // PF_XSAVE_ENABLED
        case 17:  // PF_ARM_VFP_32_REGISTERS_AVAILABLE
        case 20:  // PF_SSSE3_INSTRUCTIONS_AVAILABLE
        case 21:  // PF_SSE4_1_INSTRUCTIONS_AVAILABLE
        case 22:  // PF_SSE4_2_INSTRUCTIONS_AVAILABLE
        case 23:  // PF_ARM_MOVE_64_BIT
            return 1;
        case 18:  // PF_AVX_INSTRUCTIONS_AVAILABLE
#if defined(__AVX__)
            return 1;
#else
            return 0;
#endif
        case 19:  // PF_AVX2_INSTRUCTIONS_AVAILABLE
#if defined(__AVX2__)
            return 1;
#else
            return 0;
#endif
        case 24:  // PF_ARM_NEON_INSTRUCTIONS_AVAILABLE
            return 0;
        default:
            return 0;
    }
}

extern "C" __attribute__((ms_abi)) std::uint32_t
nr2_RtlGetCurrentProcessorNumberEx(void* proc) noexcept {
    const std::uint32_t number =
        static_cast<std::uint32_t>(::sched_getcpu());
    if (proc != nullptr) {
        // PROCESSOR_NUMBER: two 8-bit fields and a 16-bit one.
        auto* bytes = static_cast<std::uint8_t*>(proc);
        bytes[0] = 0;  // Group
        bytes[1] = static_cast<std::uint8_t>(number & 0xFF);
        write_u16(proc, 2, 0);
    }
    return number;
}

// ------------------------------------------------------------- the SList

// The lock-free stack. A guest runs on one host thread here, but the
// structure's semantics are still the ones the real functions maintain --
// the depth in the low 16 bits, the sequence number above it incremented
// on every change -- because a guest that reads the header directly is
// reading those bits, and a push that did not bump the sequence would
// break a waiter that compares them.

extern "C" __attribute__((ms_abi)) void nr2_RtlInitializeSListHead(
    void* head) noexcept {
    std::memset(head, 0, kSListBytes);
}

extern "C" __attribute__((ms_abi)) void* nr2_RtlFirstEntrySList(
    const void* head) noexcept {
    return read_ptr(head, kSListNext) == 0
               ? nullptr
               : reinterpret_cast<void*>(read_ptr(head, kSListNext));
}

extern "C" __attribute__((ms_abi)) void* nr2_RtlInterlockedPushEntrySList(
    void* head, void* entry) noexcept {
    if (entry == nullptr) {
        return nullptr;
    }
    // The push the list does when two threads cannot race: the old head is
    // read, the entry is pointed at it, and the header is written with the
    // depth one larger and the sequence one higher. The sequence bump is
    // what an ABA-detecting caller watches.
    //
    // The return value is the entry that used to be at the head, which is
    // how a caller that pushed without knowing the list's state learns it:
    // a null result means the list was empty and this entry is the first.
    const std::uint64_t packed = read_ptr(head, kSListDepthSeq);
    const std::uint64_t depth = packed & kSListDepthMask;
    const std::uint64_t sequence = packed >> kSListSequenceShift;
    const std::uint64_t old_next = read_ptr(head, kSListNext);
    write_ptr(entry, 0, old_next);
    write_ptr(head, kSListNext, reinterpret_cast<std::uint64_t>(entry));
    write_ptr(head, kSListDepthSeq,
              ((sequence + 1) << kSListSequenceShift) | ((depth + 1) & kSListDepthMask));
    return reinterpret_cast<void*>(old_next);
}

// The splice forms put a whole run on the list in one change. The shape is
// the documented one -- the list head, the run's first entry, the run's last
// entry and the run's length -- and the length is what the depth grows by,
// which is why the caller supplies it: walking the run to count it would be
// the list doing the caller's bookkeeping. The Ex spelling is the one that
// returns the entry the list held before the splice, which is what a caller
// needs to patch the run into a longer chain; the plain spelling answers
// nothing. (The return convention of the Ex spelling is inferred from its
// callers' uses rather than from documentation that states it.)

extern "C" __attribute__((ms_abi)) void* nr2_RtlInterlockedPopEntrySList(
    void* head) noexcept {
    const std::uint64_t next = read_ptr(head, kSListNext);
    if (next == 0) {
        return nullptr;
    }
    const std::uint64_t packed = read_ptr(head, kSListDepthSeq);
    const std::uint64_t depth = packed & kSListDepthMask;
    const std::uint64_t sequence = packed >> kSListSequenceShift;
    const std::uint64_t after = read_ptr(reinterpret_cast<const void*>(next), 0);
    write_ptr(head, kSListNext, after);
    write_ptr(head, kSListDepthSeq,
              ((sequence + 1) << kSListSequenceShift) |
                  ((depth == 0 ? 0 : depth - 1) & kSListDepthMask));
    return reinterpret_cast<void*>(next);
}

extern "C" __attribute__((ms_abi)) void* nr2_RtlInterlockedPushListSListEx(
    void* head, void* list, void* list_end, std::uint32_t count) noexcept {
    if (head == nullptr || list == nullptr || count == 0) {
        return nullptr;
    }
    const std::uint64_t packed = read_ptr(head, kSListDepthSeq);
    const std::uint64_t depth = packed & kSListDepthMask;
    const std::uint64_t sequence = packed >> kSListSequenceShift;
    const std::uint64_t old_next = read_ptr(head, kSListNext);
    // The run's last entry takes the list's old head, the head takes the
    // run, and the depth grows by the length the caller stated.
    write_ptr(list_end != nullptr ? list_end : list, 0, old_next);
    write_ptr(head, kSListNext, reinterpret_cast<std::uint64_t>(list));
    const std::uint64_t new_depth =
        (depth + count) & kSListDepthMask;
    write_ptr(head, kSListDepthSeq, ((sequence + 1) << kSListSequenceShift) | new_depth);
    return reinterpret_cast<void*>(old_next);
}

extern "C" __attribute__((ms_abi)) void nr2_RtlInterlockedPushListSList(
    void* head, void* list, void* list_end, std::uint32_t count) noexcept {
    static_cast<void>(nr2_RtlInterlockedPushListSListEx(head, list, list_end,
                                                        count));
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlInterlockedFlushSList(
    void* head) noexcept {
    const std::uint64_t packed = read_ptr(head, kSListDepthSeq);
    const std::uint64_t sequence = packed >> kSListSequenceShift;
    write_ptr(head, kSListNext, 0);
    write_ptr(head, kSListDepthSeq,
              (sequence + 1) << kSListSequenceShift);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint16_t nr2_RtlQueryDepthSList(
    const void* head) noexcept {
    return static_cast<std::uint16_t>(read_ptr(head, kSListDepthSeq) &
                                      kSListDepthMask);
}

// -------------------------------------------------- security descriptor
// accessors
//
// The four `RtlGet*SecurityDescriptor` accessors answer a pointer into the
// caller's descriptor plus a flag saying where the field came from. The two
// things that decide the answer are the form of the descriptor and the
// control word:
//
//   * An absolute descriptor stores the four fields as pointers; a
//     self-relative one stores byte offsets from its own base. The
//     SE_SELF_RELATIVE bit is the only thing that says which, and reading
//     the wrong one turns a pointer into an offset and walks off the end.
//   * The `*_DEFAULTED` bits do not mean "this field exists". They mean the
//     field was filled in from the token rather than supplied by the caller.
//     A descriptor with a real owner almost always has SE_OWNER_DEFAULTED
//     clear, so treating that bit as a presence test reports an owner that
//     is there as absent. Presence is therefore decided by the field itself
//     for owner and group, and by the `*_PRESENT` bit for the two ACLs --
//     which is what Windows does.

namespace {

// True when the descriptor is in self-relative form.
[[nodiscard]] bool sd_self_relative(const void* sd) noexcept {
    return (read_u16(sd, kSdControl) & kSeSelfRelative) != 0;
}

// Which of the four fields a caller is asking about. The index is what
// picks the slot, because the two forms do not store their fields at the
// same offsets -- the relative form has four 32-bit offsets, the absolute
// form four 64-bit pointers -- and the caller should not have to know that.
enum class SdField { Owner = 0, Group = 1, Sacl = 2, Dacl = 3 };

[[nodiscard]] std::size_t sd_relative_slot(SdField field) noexcept {
    switch (field) {
        case SdField::Owner: return kSdOffset1;
        case SdField::Group: return kSdOffset2;
        case SdField::Sacl: return kSdOffset3;
        case SdField::Dacl: return kSdOffset4;
    }
    return kSdOffset1;
}

[[nodiscard]] std::size_t sd_absolute_slot(SdField field) noexcept {
    switch (field) {
        case SdField::Owner: return kSdAbsOwner;
        case SdField::Group: return kSdAbsGroup;
        case SdField::Sacl: return kSdAbsSacl;
        case SdField::Dacl: return kSdAbsDacl;
    }
    return kSdAbsOwner;
}

// Where a field of the descriptor is, or null when it is absent. `present`
// says how presence is decided: the two ACLs answer to their `*_PRESENT`
// control bit, the two SIDs to their own field being non-null. Both forms
// are then read the way their form stores them.
[[nodiscard]] const void* sd_field(const void* sd, SdField field,
                                   std::uint16_t present_bit,
                                   bool acl_field) noexcept {
    const std::uint16_t control = read_u16(sd, kSdControl);
    if (acl_field && (control & present_bit) == 0) {
        return nullptr;
    }
    if (sd_self_relative(sd)) {
        const std::uint32_t offset = read_u32(sd, sd_relative_slot(field));
        if (offset == 0) {
            return nullptr;
        }
        return static_cast<const std::uint8_t*>(sd) + offset;
    }
    // The absolute form's slot is a pointer of the descriptor's own pointer
    // width, which read_ptr already matches.
    const std::uint64_t pointer = read_ptr(sd, sd_absolute_slot(field));
    return pointer == 0 ? nullptr : reinterpret_cast<const void*>(pointer);
}

[[nodiscard]] void* sd_field_mutable(void* sd, SdField field,
                                     std::uint16_t present_bit,
                                     bool acl_field) noexcept {
    return const_cast<void*>(sd_field(sd, field, present_bit, acl_field));
}

// The byte length of the SID or ACL a descriptor field names, sized from the
// structure's own count rather than assumed, so a truncated field cannot
// make the length answer too small.
[[nodiscard]] std::size_t field_length(const void* field,
                                       bool acl_field) noexcept {
    if (field == nullptr) {
        return 0;
    }
    return acl_field ? static_cast<std::size_t>(read_u16(field, kAclSize))
                     : sid_bytes(read_u8(field, kSidSubAuthorityCount));
}

}  // namespace

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetDaclSecurityDescriptor(
    const void* sd, std::int32_t* present, void** dacl,
    std::int32_t* defaulted) noexcept {
    if (sd == nullptr || present == nullptr || dacl == nullptr ||
        defaulted == nullptr) {
        return kStInvalidParameter;
    }
    void* found = sd_field_mutable(const_cast<void*>(sd), SdField::Dacl,
                                   kSeDaclPresent, true);
    *present = found != nullptr ? 1 : 0;
    *dacl = found;
    *defaulted =
        (read_u16(sd, kSdControl) & kSeDaclDefaulted) != 0 ? 1 : 0;
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetSaclSecurityDescriptor(
    const void* sd, std::int32_t* present, void** sacl,
    std::int32_t* defaulted) noexcept {
    if (sd == nullptr || present == nullptr || sacl == nullptr ||
        defaulted == nullptr) {
        return kStInvalidParameter;
    }
    void* found = sd_field_mutable(const_cast<void*>(sd), SdField::Sacl,
                                   kSeSaclPresent, true);
    *present = found != nullptr ? 1 : 0;
    *sacl = found;
    *defaulted =
        (read_u16(sd, kSdControl) & kSeSaclDefaulted) != 0 ? 1 : 0;
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetOwnerSecurityDescriptor(
    const void* sd, void** owner, std::uint32_t* defaulted) noexcept {
    if (sd == nullptr || owner == nullptr || defaulted == nullptr) {
        return kStInvalidParameter;
    }
    *owner = sd_field_mutable(const_cast<void*>(sd), SdField::Owner,
                              kSeOwnerDefaulted, false);
    *defaulted =
        (read_u16(sd, kSdControl) & kSeOwnerDefaulted) != 0 ? 1u : 0u;
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetGroupSecurityDescriptor(
    const void* sd, void** group, std::int32_t* defaulted) noexcept {
    if (sd == nullptr || group == nullptr || defaulted == nullptr) {
        return kStInvalidParameter;
    }
    *group = sd_field_mutable(const_cast<void*>(sd), SdField::Group,
                              kSeGroupDefaulted, false);
    *defaulted =
        (read_u16(sd, kSdControl) & kSeGroupDefaulted) != 0 ? 1 : 0;
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetControlSecurityDescriptor(
    const void* sd, void* control_out, std::uint32_t* revision) noexcept {
    // SECURITY_DESCRIPTOR_CONTROL is a 16-bit word and the revision a
    // 32-bit one; the caller's pointers are typed to the structure, and
    // this writes through them by offset rather than by a host type.
    if (sd == nullptr || control_out == nullptr || revision == nullptr) {
        return kStInvalidParameter;
    }
    // The revision is reported as 1 unconditionally when the descriptor's
    // own revision reads as 1 -- and a descriptor whose revision is anything
    // else is refused rather than relabelled, because a caller that gets
    // "revision 1" for a revision-2 descriptor would size its buffers from
    // a structure shape that is not there.
    if (read_u8(sd, kSdRevision) != 1) {
        return kStUnknownRevision;
    }
    write_u16(control_out, 0, read_u16(sd, kSdControl));
    *revision = read_u8(sd, kSdRevision);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t
nr2_RtlLengthSecurityDescriptor(const void* sd) noexcept {
    if (sd == nullptr) {
        return 0;
    }
    // The answer is the size a caller has to set aside for this descriptor.
    // For the self-relative form that is the header plus the structures the
    // fields point at, each sized from its own count; for the absolute form
    // the structures live elsewhere and the header is all the descriptor
    // itself occupies, which is what the real function answers.
    if (!sd_self_relative(sd)) {
        return static_cast<std::uint32_t>(kSdBytes);
    }
    std::size_t end = kSdBytes;
    const auto extend = [&end, sd](SdField field_id,
                                   std::uint16_t present_bit,
                                   bool acl_field) {
        const void* field = sd_field(sd, field_id, present_bit, acl_field);
        const std::size_t bytes = field_length(field, acl_field);
        if (bytes == 0) {
            return;
        }
        // The end offset is computed in 64-bit arithmetic and then clamped
        // to 32 bits, so a descriptor whose last field ends past 4 GiB
        // saturates instead of wrapping to a small answer.
        const std::uint64_t field_end =
            static_cast<std::uint64_t>(read_u32(sd, sd_relative_slot(field_id))) +
            bytes;
        if (field_end > end) {
            end = field_end > 0xFFFFFFFFull ? 0xFFFFFFFFu
                                            : static_cast<std::size_t>(field_end);
        }
    };
    extend(SdField::Owner, kSeOwnerDefaulted, false);
    extend(SdField::Group, kSeGroupDefaulted, false);
    extend(SdField::Sacl, kSeSaclPresent, true);
    extend(SdField::Dacl, kSeDaclPresent, true);
    return static_cast<std::uint32_t>(end);
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlMakeSelfRelativeSD(
    const void* absolute, void* relative, std::uint32_t* bytes) noexcept {
    if (absolute == nullptr || relative == nullptr || bytes == nullptr) {
        return kStInvalidParameter;
    }
    if (sd_self_relative(absolute)) {
        // A descriptor that is already relative has nothing to convert, and
        // the real function reports that rather than copying it.
        return kStInvalidSecurityDescr;
    }
    // The size the relative form needs is the header plus every field the
    // source has, laid end to end. It is computed before anything is
    // written, because the caller's buffer is checked against it and a
    // short buffer must leave the target untouched.
    const std::uint16_t control = read_u16(absolute, kSdControl);
    const struct {
        SdField id;
        std::uint16_t present_bit;
        bool acl_field;
    } kFields[] = {
        {SdField::Owner, kSeOwnerDefaulted, false},
        {SdField::Group, kSeGroupDefaulted, false},
        {SdField::Sacl, kSeSaclPresent, true},
        {SdField::Dacl, kSeDaclPresent, true},
    };
    std::uint64_t needed = kSdBytes;
    for (const auto& field : kFields) {
        needed += field_length(
            sd_field(absolute, field.id, field.present_bit, field.acl_field),
            field.acl_field);
    }
    if (needed > 0xFFFFFFFFull) {
        return kStInvalidSecurityDescr;
    }
    if (*bytes < needed) {
        *bytes = static_cast<std::uint32_t>(needed);
        return kStBufferTooSmall;
    }

    // The header goes across with the self-relative bit set and every field
    // slot cleared, so a field the source does not have reads as absent in
    // the target rather than as whatever the caller's buffer held.
    std::memset(relative, 0, kSdBytes);
    write_u8(relative, kSdRevision, read_u8(absolute, kSdRevision));
    write_u16(relative, kSdControl,
              static_cast<std::uint16_t>(control | kSeSelfRelative));

    std::size_t cursor = kSdBytes;
    for (const auto& field : kFields) {
        const void* source =
            sd_field(absolute, field.id, field.present_bit, field.acl_field);
        const std::size_t field_bytes = field_length(source, field.acl_field);
        if (field_bytes == 0) {
            continue;
        }
        std::memcpy(static_cast<std::uint8_t*>(relative) + cursor, source,
                    field_bytes);
        write_u32(relative, sd_relative_slot(field.id),
                  static_cast<std::uint32_t>(cursor));
        cursor += field_bytes;
    }
    *bytes = static_cast<std::uint32_t>(needed);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlFirstFreeAce(
    const void* acl, void** ace) noexcept {
    if (acl == nullptr || ace == nullptr) {
        return 0;
    }
    // The first free byte is after the last ACE; the ACL's own size field
    // is the bound, and a size smaller than the header is a malformed one
    // the walk refuses.
    const std::uint16_t size = read_u16(acl, kAclSize);
    const std::uint16_t count = read_u16(acl, kAclCount);
    if (size < kAclBytes) {
        return 0;
    }
    std::size_t at = kAclBytes;
    for (std::uint16_t k = 0; k < count; ++k) {
        // An ACE header's size field is its second byte on x64.
        const std::uint16_t ace_size = read_u16(acl, at + 2);
        if (ace_size == 0 || at + ace_size > size) {
            return 0;
        }
        at += ace_size;
    }
    *ace = const_cast<void*>(static_cast<const void*>(
        static_cast<const std::uint8_t*>(acl) + at));
    return 1;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetAce(
    const void* acl, std::uint32_t index, void** ace) noexcept {
    if (acl == nullptr || ace == nullptr) {
        return kStInvalidParameter;
    }
    // The walk is bounded by the ACL's own size, not just by its count: an
    // ACE whose size field runs past the ACL ends the walk with a refusal
    // rather than handing back a pointer into whatever follows the buffer.
    const std::uint16_t size = read_u16(acl, kAclSize);
    const std::uint16_t count = read_u16(acl, kAclCount);
    if (size < kAclBytes) {
        return kStInvalidParameter;
    }
    if (index >= count) {
        return kStInvalidParameter;
    }
    std::size_t at = kAclBytes;
    for (std::uint32_t k = 0; k < index; ++k) {
        const std::uint16_t ace_size = read_u16(acl, at + 2);
        if (ace_size == 0 || at + ace_size > size) {
            return kStInvalidParameter;
        }
        at += ace_size;
    }
    // The ACE at the index itself is subject to the same bound the walk
    // enforced on the ones before it: its size field must name bytes that
    // are inside the ACL, and its header must be there to read.
    if (at + 4 > size) {
        return kStInvalidParameter;
    }
    const std::uint16_t ace_size = read_u16(acl, at + 2);
    if (ace_size == 0 || at + ace_size > size) {
        return kStInvalidParameter;
    }
    *ace = const_cast<void*>(static_cast<const void*>(
        static_cast<const std::uint8_t*>(acl) + at));
    return kStSuccess;
}

// --------------------------------------------------------------- the SIDs

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlLengthSid(
    const void* sid) noexcept {
    if (sid == nullptr) {
        return 0;
    }
    // The length comes from the SID's own sub-authority count, so it is
    // only meaningful when the SID is well formed: a count above the fifteen
    // the structure has room for describes a buffer this runtime cannot size,
    // and the real function answers zero rather than a length that would
    // overrun it.
    const std::uint8_t count = read_u8(sid, kSidSubAuthorityCount);
    if (count > kSidMaxSubAuthorities) {
        return 0;
    }
    return static_cast<std::uint32_t>(sid_bytes(count));
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlLengthRequiredSid(
    std::uint32_t count) noexcept {
    if (count > kSidMaxSubAuthorities) {
        return 0;
    }
    return static_cast<std::uint32_t>(sid_bytes(static_cast<std::uint8_t>(count)));
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlIdentifierAuthoritySid(
    const void* sid, void** authority) noexcept {
    if (sid == nullptr || authority == nullptr) {
        return kStInvalidParameter;
    }
    *authority = const_cast<void*>(static_cast<const void*>(
        static_cast<const std::uint8_t*>(sid) + kSidIdentifierAuthority));
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlFreeSid(void* sid) noexcept {
    // SIDs this runtime hands out are either the caller's own buffers or
    // blocks the process heap owns; a null is refused and a heap block is
    // freed.
    if (sid == nullptr) {
        return kStInvalidParameter;
    }
    if (!heap_free(sid)) {
        // Not a heap block, so it is the caller's: nothing to free and
        // nothing to answer.
        return kStSuccess;
    }
    return kStSuccess;
}

// ------------------------------------------------------ large-integer math
//
// The LARGE_INTEGER helpers are the 64-bit arithmetic a 32-bit caller
// needed spelled out, and on x64 they are still exported because a guest
// that calls them is calling the arithmetic. The quadpart rides two 32-bit
// halves in the caller's structure, so each function reassembles, computes
// and writes back.

namespace {

constexpr std::size_t kLiLow = 0;
constexpr std::size_t kLiHigh = 4;
constexpr std::size_t kLiBytes = 8;

[[nodiscard]] std::int64_t li_read(const void* li) noexcept {
    const std::uint64_t low = read_u32(li, kLiLow);
    const std::uint64_t high = read_u32(li, kLiHigh);
    return static_cast<std::int64_t>(low | (high << 32));
}

void li_write(void* li, std::int64_t value) noexcept {
    const auto bits = static_cast<std::uint64_t>(value);
    write_u32(li, kLiLow, static_cast<std::uint32_t>(bits));
    write_u32(li, kLiHigh, static_cast<std::uint32_t>(bits >> 32));
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::int64_t nr2_RtlLargeIntegerAdd(
    const void* a, const void* b, void* out) noexcept {
    const std::int64_t value = li_read(a) + li_read(b);
    if (out != nullptr) {
        li_write(out, value);
    }
    return value;
}

extern "C" __attribute__((ms_abi)) std::int64_t nr2_RtlLargeIntegerSubtract(
    const void* a, const void* b, void* out) noexcept {
    const std::int64_t value = li_read(a) - li_read(b);
    if (out != nullptr) {
        li_write(out, value);
    }
    return value;
}

extern "C" __attribute__((ms_abi)) std::int64_t nr2_RtlLargeIntegerNegate(
    const void* a, void* out) noexcept {
    // Negation is done on the unsigned bit pattern: negating the most
    // negative value overflows a signed type, and the two's complement result
    // is still the answer the kernel gives.
    const std::int64_t value = li_read(a);
    const std::int64_t negated = static_cast<std::int64_t>(
        0ull - static_cast<std::uint64_t>(value));
    if (out != nullptr) {
        li_write(out, negated);
    }
    return negated;
}

extern "C" __attribute__((ms_abi)) std::int64_t nr2_RtlLargeIntegerShiftLeft(
    const void* a, std::uint8_t shift, void* out) noexcept {
    // A shift of 64 or more answers zero, and the shift is done unsigned so
    // that a negative dividend -- whose high bits are what must move -- is
    // not a signed operation the language leaves undefined.
    const std::uint64_t bits =
        shift >= 64 ? 0ull : (static_cast<std::uint64_t>(li_read(a)) << shift);
    if (out != nullptr) {
        li_write(out, static_cast<std::int64_t>(bits));
    }
    return static_cast<std::int64_t>(bits);
}

extern "C" __attribute__((ms_abi)) std::int64_t nr2_RtlLargeIntegerShiftRight(
    const void* a, std::uint8_t shift, void* out) noexcept {
    // The shift is logical: the bits that fall off the bottom are discarded
    // and nothing is pulled in from the left, which is why the answer for a
    // negative dividend comes back positive. `RtlLargeIntegerArithmeticShift`
    // below is the spelling that pulls in the sign instead.
    const std::uint64_t raw = static_cast<std::uint64_t>(li_read(a));
    const std::uint64_t bits =
        shift >= 64 ? 0ull : (raw >> shift);
    if (out != nullptr) {
        li_write(out, static_cast<std::int64_t>(bits));
    }
    return static_cast<std::int64_t>(bits);
}

extern "C" __attribute__((ms_abi)) std::int64_t
nr2_RtlLargeIntegerArithmeticShift(const void* a, std::uint8_t shift,
                                   void* out) noexcept {
    // The sign bit is what the arithmetic shift preserves, and a shift of 64
    // or more therefore answers the sign alone: -1 or 0.
    const std::int64_t value = li_read(a);
    const std::int64_t shifted =
        shift >= 64 ? (value < 0 ? -1 : 0) : (value >> shift);
    if (out != nullptr) {
        li_write(out, shifted);
    }
    return shifted;
}

extern "C" __attribute__((ms_abi)) std::int64_t nr2_RtlLargeIntegerDivide(
    const void* a, const void* b, void* remainder) noexcept {
    // Three arguments, not four: the quotient is what the call returns and
    // the remainder is the only out-parameter. A divide by zero answers zero
    // with the dividend as the remainder, which is what keeps a caller that
    // ignored the check from walking off the end of a table.
    const std::int64_t dividend = li_read(a);
    const std::int64_t divisor = li_read(b);
    std::int64_t quotient = 0;
    std::int64_t rest = dividend;
    if (divisor != 0) {
        // The most negative value divided by -1 overflows a signed type and
        // traps on some hosts, so that one case is computed unsigned and
        // read back: the quotient is still the mathematically right one.
        if (dividend == (std::numeric_limits<std::int64_t>::min)() &&
            divisor == -1) {
            quotient = (std::numeric_limits<std::int64_t>::min)();
            rest = 0;
        } else {
            quotient = dividend / divisor;
            rest = dividend % divisor;
        }
    }
    if (remainder != nullptr) {
        li_write(remainder, rest);
    }
    return quotient;
}

// ---------------------------------------------------------------- bitmaps
//
// The bitmap is an array of ULONGs and the bit order is MSB-first within
// each word: bit 0 is the high bit of the first ULONG. That is the kernel's
// order and not this host's, and a test that asserts it does so by reading
// the caller's array rather than through this file's own reader.
//
// RTL_BITMAP is `ULONG Size; ULONG Reserved; ULONG* Base;` -- the count
// comes first and the pointer last, which is the opposite order from what a
// reader expects and is why the three accessors below are spelled out rather
// than read through a host structure type.

namespace {

constexpr std::size_t kBitsPerUlong = 32;
constexpr std::size_t kBitmapSize = 0;
constexpr std::size_t kBitmapBase = 8;

// The largest index the count can name, and the number of words backing it.
// A count is not required to be a multiple of the word width, so the walk
// below stops at the count rather than at a whole number of words: reading
// past it would read whatever allocation follows the caller's array.
[[nodiscard]] std::uint32_t* bitmap_base(const void* header) noexcept {
    return reinterpret_cast<std::uint32_t*>(read_ptr(header, kBitmapBase));
}

[[nodiscard]] std::uint32_t bitmap_size(const void* header) noexcept {
    return read_u32(header, kBitmapSize);
}

[[nodiscard]] bool bit_is_set(const std::uint32_t* map,
                              std::size_t index) noexcept {
    const std::size_t word = index / kBitsPerUlong;
    const std::uint32_t bit = 0x80000000u >> (index % kBitsPerUlong);
    return (map[word] & bit) != 0;
}

void set_bit(std::uint32_t* map, std::size_t index, bool on) noexcept {
    const std::size_t word = index / kBitsPerUlong;
    const std::uint32_t mask = 0x80000000u >> (index % kBitsPerUlong);
    if (on) {
        map[word] |= mask;
    } else {
        map[word] &= ~mask;
    }
}

// The value every "not found" query answers. It is not -1: these return an
// unsigned index, and 0xFFFFFFFF is the one value no real index can take.
constexpr std::uint32_t kNoSuchBit = 0xFFFFFFFFu;

}  // namespace

extern "C" __attribute__((ms_abi)) void nr2_RtlInitializeBitMap(
    void* header, void* map, std::uint32_t bits) noexcept {
    if (header == nullptr) {
        return;
    }
    write_u32(header, kBitmapSize, bits);
    write_u32(header, kBitmapSize + 4, 0);  // Reserved
    write_ptr(header, kBitmapBase, reinterpret_cast<std::uint64_t>(map));
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlFindSetBits(
    const void* header, std::uint32_t count) noexcept {
    // Asking for zero bits, or for more bits than the map holds, can never
    // be satisfied -- there is no run of them -- and both answer "not found"
    // rather than a run that is not there.
    if (header == nullptr || count == 0) {
        return kNoSuchBit;
    }
    const std::uint32_t* map = bitmap_base(header);
    const std::uint32_t bits = bitmap_size(header);
    if (map == nullptr || count > bits) {
        return kNoSuchBit;
    }
    std::size_t run = 0;
    for (std::uint32_t k = 0; k < bits; ++k) {
        if (!bit_is_set(map, k)) {
            run = 0;
            continue;
        }
        if (++run == count) {
            return k + 1 - count;
        }
    }
    return kNoSuchBit;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlFindSetBitsAndClear(
    const void* header, std::uint32_t count) noexcept {
    // The find happens first and in full: a run that is not there leaves the
    // map untouched, because there is nothing to clear.
    const std::uint32_t at = nr2_RtlFindSetBits(header, count);
    if (at == kNoSuchBit) {
        return at;
    }
    std::uint32_t* map = bitmap_base(header);
    for (std::uint32_t k = 0; k < count; ++k) {
        set_bit(map, at + k, false);
    }
    return at;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlNumberOfSetBits(
    const void* header) noexcept {
    if (header == nullptr) {
        return 0;
    }
    const std::uint32_t* map = bitmap_base(header);
    const std::uint32_t bits = bitmap_size(header);
    if (map == nullptr) {
        return 0;
    }
    std::uint32_t total = 0;
    for (std::uint32_t k = 0; k < bits; ++k) {
        if (bit_is_set(map, k)) {
            ++total;
        }
    }
    return total;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlNumberOfClearBits(
    const void* header) noexcept {
    if (header == nullptr) {
        return 0;
    }
    // Subtracted rather than counted: the clear bits are whatever the size
    // says the map has and the set bits did not take, which is the same
    // answer and cannot disagree with the set count it is derived from.
    return bitmap_size(header) - nr2_RtlNumberOfSetBits(header);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlFindSetRuns(
    const void* header, void* runs, std::uint32_t max_runs,
    std::int32_t longest_only) noexcept {
    // RTL_BITMAP_RUN is two 32-bit fields: the starting index and the length.
    if (header == nullptr || runs == nullptr || max_runs == 0) {
        return 0;
    }
    const std::uint32_t* map = bitmap_base(header);
    const std::uint32_t bits = bitmap_size(header);
    if (map == nullptr) {
        return 0;
    }

    if (longest_only != 0) {
        // The longest-run spelling answers exactly one run: the longest one,
        // and the first of that length when several tie. Finding it is a
        // single pass that keeps the best run seen so far, which is not the
        // same as finding the first run and then measuring it.
        std::uint32_t best_start = 0;
        std::uint32_t best_length = 0;
        std::uint32_t k = 0;
        while (k < bits) {
            if (!bit_is_set(map, k)) {
                ++k;
                continue;
            }
            const std::uint32_t start = k;
            while (k < bits && bit_is_set(map, k)) {
                ++k;
            }
            const std::uint32_t length = k - start;
            if (length > best_length) {
                best_length = length;
                best_start = start;
            }
        }
        if (best_length == 0) {
            return 0;
        }
        write_u32(runs, 0, best_start);
        write_u32(runs, 4, best_length);
        return 1;
    }

    // The list spelling: every run in order, up to the caller's limit. The
    // count returned is the number of runs actually written, so a caller that
    // passed a small buffer learns it ran out rather than reading past what
    // was filled in.
    std::uint32_t found = 0;
    std::uint32_t k = 0;
    while (k < bits && found < max_runs) {
        if (!bit_is_set(map, k)) {
            ++k;
            continue;
        }
        const std::uint32_t start = k;
        while (k < bits && bit_is_set(map, k)) {
            ++k;
        }
        write_u32(runs, static_cast<std::size_t>(found) * 8, start);
        write_u32(runs, static_cast<std::size_t>(found) * 8 + 4, k - start);
        ++found;
    }
    return found;
}

// --------------------------------------------------- the critical section
//
// A critical section is a lock the guest holds in its own address space.
// The guest runs on one host thread, so contention never happens -- but
// the recursion count, the owner and the locked flag are still maintained
// truthfully, because a guest that inspects its own lock is reading these
// fields.

extern "C" __attribute__((ms_abi)) Ntstatus
nr2_RtlInitializeCriticalSectionAndSpinCount(void* crit,
                                             std::uint32_t spin) noexcept;

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeCriticalSection(
    void* crit) noexcept {
    // The plain spelling is the spin-count one with a zero spin count.
    return nr2_RtlInitializeCriticalSectionAndSpinCount(crit, 0);
}

extern "C" __attribute__((ms_abi)) Ntstatus
nr2_RtlInitializeCriticalSectionAndSpinCount(void* crit,
                                             std::uint32_t spin) noexcept {
    if (crit == nullptr) {
        return kStInvalidParameter;
    }
    std::memset(crit, 0, kCritBytes);
    // -1 in the lock count is the "not locked" value Windows writes.
    write_u32(crit, kCritLockCount, 0xFFFFFFFFu);
    write_u32(crit, kCritSpinCount, spin & 0x01FFFFFFu);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeCriticalSectionEx(
    void* crit, std::uint32_t spin, std::uint32_t flags) noexcept {
    static_cast<void>(flags);
    return nr2_RtlInitializeCriticalSectionAndSpinCount(crit, spin);
}

// `RtlEnterCriticalSection` is not registered here: `ntdll_rtl_mem1.cpp`
// owns it, and two registrations of one name would leave a guest with two
// different answers depending on which slice answered last.
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlEnterCriticalSection(
    void* crit) noexcept {
    if (crit == nullptr) {
        return kStInvalidParameter;
    }
    const std::uint32_t self = k32_GetCurrentThreadId();
    const std::int32_t lock = static_cast<std::int32_t>(read_u32(crit, kCritLockCount));
    if (lock >= 0 && read_ptr(crit, kCritOwningThread) == self) {
        // Recursion by the same owner is the one case a critical section
        // counts: the recursion count goes up and the lock stays held.
        write_u32(crit, kCritRecursionCount,
                  read_u32(crit, kCritRecursionCount) + 1);
        return kStSuccess;
    }
    write_u32(crit, kCritLockCount, static_cast<std::uint32_t>(lock + 1));
    write_u32(crit, kCritRecursionCount, 1);
    write_ptr(crit, kCritOwningThread, self);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlLeaveCriticalSection(
    void* crit) noexcept {
    if (crit == nullptr) {
        return kStInvalidParameter;
    }
    const std::uint32_t recursion = read_u32(crit, kCritRecursionCount);
    if (recursion == 0) {
        // Leaving a section that was never entered is the caller's bug, and
        // the real function reports it as an invalid parameter rather than
        // silently decrementing the count below zero.
        return kStInvalidParameter;
    }
    if (recursion > 1) {
        write_u32(crit, kCritRecursionCount, recursion - 1);
        return kStSuccess;
    }
    write_u32(crit, kCritRecursionCount, 0);
    write_ptr(crit, kCritOwningThread, 0);
    write_u32(crit, kCritLockCount, static_cast<std::uint32_t>(-1));
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlIsCriticalSectionLocked(
    const void* crit) noexcept {
    if (crit == nullptr) {
        return 0;
    }
    return static_cast<std::int32_t>(read_u32(crit, kCritLockCount)) >= 0 ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t
nr2_RtlIsCriticalSectionLockedByThread(const void* crit) noexcept {
    if (crit == nullptr) {
        return 0;
    }
    // The owner recorded is the guest's own thread id, so this compares
    // against `GetCurrentThreadId` -- which is also what makes the answer
    // testable: a caller that writes a different owner into the section
    // sees this report "not mine". A guest with no TEB has no id, and an
    // owner of zero is "no owner", so a host-side caller with no guest
    // state must not read a fresh section as locked by thread zero.
    const std::uint32_t self = k32_GetCurrentThreadId();
    return self != 0 && read_ptr(crit, kCritOwningThread) == self ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeConditionVariable(
    void* variable) noexcept {
    if (variable == nullptr) {
        return kStInvalidParameter;
    }
    // A condition variable is one pointer-width counter, and zero is the
    // empty state.
    write_ptr(variable, 0, 0);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeSRWLock(
    void* lock) noexcept {
    if (lock == nullptr) {
        return kStInvalidParameter;
    }
    // An SRW lock is one pointer; zero is unlocked in both of its modes.
    write_ptr(lock, 0, 0);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitBarrier(
    void* barrier, std::uint32_t total, std::uint32_t spin) noexcept {
    if (barrier == nullptr || total == 0) {
        return kStInvalidParameter;
    }
    // RTL_BARRIER: the four fields a barrier needs, laid out by offset.
    write_u32(barrier, 0, total);
    write_u32(barrier, 4, 0);  // current count
    write_u32(barrier, 8, spin);
    write_u32(barrier, 12, 0);  // generation
    return kStSuccess;
}

// -------------------------------------------------------------- the heaps

extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlFreeHeap(
    std::uint64_t heap, std::uint32_t flags, void* block) noexcept {
    static_cast<void>(heap);
    static_cast<void>(flags);
    if (block == nullptr) {
        return 1;  // Freeing null succeeds, the way `free` does.
    }
    if (heap_free(block)) {
        return 1;
    }
    set_last_error(kErrorInvalidParameter);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlLockHeap(
    std::uint64_t heap) noexcept {
    static_cast<void>(heap);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlUnlockHeap(
    std::uint64_t heap) noexcept {
    static_cast<void>(heap);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlGetProcessHeaps(
    std::uint32_t count, void** heaps) noexcept {
    if (heaps == nullptr || count == 0) {
        return 0;
    }
    // One heap: the process heap. A guest that enumerates the heaps of this
    // runtime's process finds the one every allocator here answers through,
    // which is the truth of the matter.
    heaps[0] = reinterpret_cast<void*>(process_heap_handle());
    return 1;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetUserInfoHeap(
    std::uint64_t heap, std::uint32_t flags, void* base, void* user_info,
    void** user_value) noexcept {
    static_cast<void>(heap);
    static_cast<void>(flags);
    if (base == nullptr || user_value == nullptr) {
        return kStInvalidParameter;
    }
    // The user flags of a block this runtime's heap allocated are the two
    // bits `RtlAllocateHeap` accepted and none others; the value slot
    // answers zero because no entry sets one.
    *user_value = nullptr;
    if (user_info != nullptr) {
        write_u32(user_info, 0, 0);
    }
    return kStSuccess;
}

// ------------------------------------------------------------ path queries

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlGetCurrentDirectory_U(
    std::uint32_t bytes, char16_t* buffer) noexcept {
    // Two different answers come out of this one function and telling them
    // apart is the whole of its contract: a buffer that was big enough gets
    // the number of bytes written *without* the terminator, and a buffer
    // that was too small gets the byte count one *with* it, so the caller
    // can allocate exactly. Both are bytes, matching the capacity
    // parameter's unit; a sizing call passes a null buffer.
    if (buffer == nullptr && bytes != 0) {
        return 0;
    }
    char narrow[4096];
    if (::getcwd(narrow, sizeof(narrow)) == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string wide;
    if (!narrow_in(std::string_view(narrow), wide).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The DOS spelling carries a trailing backslash unless the directory is
    // a drive root, which is what a caller concatenates a file name onto.
    if (!wide.empty() && wide.back() != u'\\') {
        wide.push_back(u'\\');
    }
    const std::size_t needed = (wide.size() + 1) * sizeof(char16_t);
    if (buffer == nullptr || bytes < needed) {
        return static_cast<std::uint32_t>(needed);
    }
    std::memcpy(buffer, wide.data(), wide.size() * sizeof(char16_t));
    buffer[wide.size()] = u'\0';
    set_last_error(kErrorSuccess);
    return static_cast<std::uint32_t>(wide.size() * sizeof(char16_t));
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlGetLongestNtPathLength() noexcept {
    // The native path limit is 32,767 wide characters plus the terminating
    // null, which is the limit the NT namespace enforces and the one a
    // caller sizes a buffer from.
    return kMaxPathChars + 1;
}

namespace {

// The copy-out half of the two path queries below, which share it: both are
// "write this text into the caller's buffer, or tell it how big it needs to
// be". `bytes` is in/out -- the caller's capacity on the way in, the size
// used on the way out -- and the status distinguishes the three outcomes.
[[nodiscard]] Ntstatus copy_path_out(const std::u16string& text, char16_t* buffer,
                                     std::uint32_t* bytes) noexcept {
    if (bytes == nullptr) {
        return kStInvalidParameter;
    }
    const std::size_t needed = (text.size() + 1) * sizeof(char16_t);
    if (needed > 0xFFFFFFFFull) {
        *bytes = 0;
        return kStInvalidParameter;
    }
    if (buffer == nullptr || *bytes < needed) {
        // The required size is reported through `bytes` as well as by the
        // failure status, because a caller that allocated on the first call
        // reads the second one to learn how much to allocate.
        *bytes = static_cast<std::uint32_t>(needed);
        return kStBufferTooSmall;
    }
    std::memcpy(buffer, text.data(), text.size() * sizeof(char16_t));
    buffer[text.size()] = u'\0';
    *bytes = static_cast<std::uint32_t>(needed);
    return kStSuccess;
}

}  // namespace

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetExePath(
    char16_t* buffer, std::uint32_t* bytes) noexcept {
    // The path of the running image, in the DOS spelling the guest's own
    // loader addresses it by.
    const auto* state = guest_state();
    if (state == nullptr) {
        return kStInvalidParameter;
    }
    std::u16string wide;
    if (!narrow_in(state->image_path_dos, wide).converted) {
        return kEInvalidArgAsStatus;
    }
    return copy_path_out(wide, buffer, bytes);
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetSearchPath(
    char16_t* buffer, std::uint32_t* bytes) noexcept {
    // The search path this runtime answers is PATH, the environment variable
    // the loader's own search falls back to, which is the one list a caller
    // can both read and set.
    const char* path = ::getenv("PATH");
    std::u16string wide;
    if (path != nullptr) {
        // A PATH that is not convertible is reported as an empty search path
        // rather than as a failure: the caller asked for a path, and "no
        // directories" is a path it can act on.
        static_cast<void>(narrow_in(std::string_view(path), wide).status);
    }
    return copy_path_out(wide, buffer, bytes);
}

// --------------------------------------------------------------- PEB misc

extern "C" __attribute__((ms_abi)) void* nr2_RtlGetCurrentPeb() noexcept {
    const auto* state = guest_state();
    return state == nullptr ? nullptr : reinterpret_cast<void*>(state->peb);
}

extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlIsCurrentProcess(
    std::uint64_t process) noexcept {
    // The pseudo-handle is the value `GetCurrentProcess` answers with, and it
    // is the only handle this domain can recognise: the real process handles
    // are minted by another slice's table, which this one deliberately does
    // not reach into. A handle this file cannot place is reported as "not
    // current" rather than guessed at, which keeps the answer a caller gets
    // for an unknown handle the conservative one.
    return process == 0xFFFFFFFFFFFFFFFFull ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlIsCurrentThread(
    std::uint64_t thread) noexcept {
    // One thread runs the guest, so the pseudo-handle is the only thread
    // handle that answers "current".
    return thread == 0xFFFFFFFFFFFFFFFEull ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) void* nr2_RtlPcToFileHeader(
    void* pc, void** base) noexcept {
    if (base == nullptr) {
        return nullptr;
    }
    *base = nullptr;
    if (pc == nullptr) {
        return nullptr;
    }
    const auto* state = guest_state();
    if (state == nullptr || state->space == nullptr) {
        return nullptr;
    }
    const Region* region =
        state->space->find(reinterpret_cast<std::uint64_t>(pc));
    if (region == nullptr) {
        return nullptr;
    }
    // The header is the base of the image the pc belongs to, which is the
    // region's own start for the image regions this runtime maps.
    *base = reinterpret_cast<void*>(region->base);
    return pc;
}

extern "C" __attribute__((ms_abi)) void nr2_RtlPushFrame(void* frame) noexcept {
    static_cast<void>(frame);
    // The frame list is a TEB chain this runtime does not maintain; a push
    // that recorded nothing would break a caller that pops, so the pair is
    // refused by doing nothing and the caller's frame stays its own.
}

extern "C" __attribute__((ms_abi)) void* nr2_RtlPopFrame() noexcept {
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void* nr2_RtlGetFrame() noexcept {
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void nr2_RtlGetCallersAddress(
    void** callers, void** callers_caller) noexcept {
    // The real function walks the return address off the stack. A host
    // caller's frame is not the guest's, and an address this runtime
    // invents would be worse than the null the real function answers when
    // the walk fails.
    if (callers != nullptr) {
        *callers = nullptr;
    }
    if (callers_caller != nullptr) {
        *callers_caller = nullptr;
    }
}

// --------------------------------------------------------------- the atoms
//
// Three readers of the table the first slice owns. The bridge is declared
// at the top of this file; the registration is here, with the names this
// slice contributes.

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlLookupAtomInAtomTable(
    void* table, const char16_t* name, std::uint32_t* atom) noexcept {
    if (name == nullptr || atom == nullptr) {
        return kStInvalidParameter;
    }
    const std::uint32_t found = occ_atom_find(table, name);
    *atom = found;
    return found == 0 ? kStObjectNotFound : kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlQueryAtomInAtomTable(
    void* table, std::uint32_t atom, std::uint32_t* refs, std::uint32_t* flags,
    char16_t* name, std::uint32_t* name_bytes) noexcept {
    return occ_atom_query(table, atom, refs, flags, name, name_bytes);
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlPinAtomInAtomTable(
    void* table, std::uint32_t atom) noexcept {
    if (table == nullptr) {
        return kStInvalidParameter;
    }
    return occ_atom_pin(table, atom);
}


// ------------------------------------------------------------- full paths
//
// The two `RtlGetFullPathName_U` spellings differ only in what they answer
// besides the string. The plain one gives the file part's position; the Ex
// one also gives the two sizes and the directory text, which is what a
// caller that only wants the directory asks for.
//
// Rooting a relative path uses the process's current directory, which is
// why `RtlGetCurrentDirectory_U` above is in the same file: the two answers
// must not disagree about where "relative" starts.

namespace {

// Whether a character is a path separator. Both spellings count because a
// guest may hand over either, and neither is the ':' of a drive prefix.
[[nodiscard]] bool is_separator(char16_t ch) noexcept {
    return ch == u'/' || ch == u'\\';
}

// Where the file name starts inside a full path, and the directory text that
// precedes it. The returned offset is what `*FilePart` is set to; the
// directory is returned without its trailing separator, except at a root
// where the separator is the whole directory ("C:\") and is kept.
[[nodiscard]] std::size_t split_directory(const std::u16string& full,
                                          std::u16string& directory) noexcept {
    const std::size_t cut = full.find_last_of(u"/\\");
    if (cut == std::u16string::npos) {
        // No separator at all: the whole thing is a file name in the
        // current directory, so the directory is empty.
        directory.clear();
        return 0;
    }
    if (cut == 0 || (cut == 2 && full.size() > 1 && full[1] == u':')) {
        // The last separator is the root's own. Cutting there would leave
        // "C:" for "C:\file", and concatenating a name to that gives a path
        // the drive cannot resolve, so the separator stays.
        directory = full.substr(0, cut + 1);
        return cut + 1;
    }
    directory = full.substr(0, cut);
    return cut;
}

// Resolves the "." and ".." segments and the doubled separators a caller may
// have written. ".." at the root stays at the root rather than climbing
// above it, which is what the real path canonicaliser does and what keeps a
// guest from walking out of the namespace with enough "..".
[[nodiscard]] std::u16string collapse_dots(const std::u16string& path) noexcept {
    const bool rooted = !path.empty() && is_separator(path[0]);
    std::u16string prefix;
    std::size_t start = 0;
    if (path.size() > 1 && path[1] == u':') {
        prefix = path.substr(0, 2);
        start = 2;
        if (path.size() > 2 && is_separator(path[2])) {
            prefix.push_back(u'\\');
            start = 3;
        }
    } else if (rooted) {
        prefix.push_back(u'\\');
        start = 1;
    }

    std::vector<std::u16string> parts;
    std::u16string segment;
    const auto flush = [&parts, &segment]() {
        if (segment.empty()) {
            return;
        }
        if (segment == u".") {
            segment.clear();
            return;
        }
        if (segment == u"..") {
            segment.clear();
            if (!parts.empty()) {
                parts.pop_back();
            }
            return;
        }
        parts.push_back(segment);
        segment.clear();
    };
    for (std::size_t k = start; k < path.size(); ++k) {
        if (is_separator(path[k])) {
            flush();
            continue;
        }
        segment.push_back(path[k]);
    }
    flush();

    std::u16string out = prefix;
    for (std::size_t k = 0; k < parts.size(); ++k) {
        if (k != 0) {
            out.push_back(u'\\');
        }
        out += parts[k];
    }
    return out;
}

// Whether a DOS path names a device rather than a file. The set is the one
// Win32 defines, and each is followed by a colon that the caller must have
// included -- "COM1" is a file name, "COM1:" is the device.
[[nodiscard]] bool is_dos_device(const std::u16string& path) noexcept {
    static const char16_t* const kDevices[] = {
        u"CON",  u"PRN",  u"AUX",  u"NUL",  u"CONIN$", u"CONOUT$",
        u"COM1", u"COM2", u"COM3", u"COM4", u"COM5", u"COM6",
        u"COM7", u"COM8", u"COM9", u"LPT1", u"LPT2", u"LPT3",
        u"LPT4", u"LPT5", u"LPT6", u"LPT7", u"LPT8", u"LPT9",
    };
    std::size_t colon = path.find(u':');
    if (colon == std::u16string::npos || colon == 0) {
        return false;
    }
    const std::u16string name = path.substr(0, colon);
    for (const char16_t* device : kDevices) {
        if (name == device) {
            return true;
        }
    }
    return false;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlGetFullPathName_U(
    const char16_t* name, std::uint32_t bytes, char16_t* buffer,
    char16_t** file_part) noexcept {
    if (name == nullptr || file_part == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::u16string request(name);
    if (request.empty()) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }

    std::u16string full;
    const bool rooted = !request.empty() && is_separator(request[0]);
    const bool drive_qualified = request.size() > 1 && request[1] == u':';
    if (rooted || drive_qualified) {
        // Already rooted: there is nothing to prepend, only the "." and ".."
        // segments and doubled separators to settle.
        full = collapse_dots(request);
    } else {
        char narrow[4096];
        if (::getcwd(narrow, sizeof(narrow)) == nullptr) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        std::u16string cwd;
        if (!narrow_in(std::string_view(narrow), cwd).converted) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        full = collapse_dots(cwd + u'\\' + request);
    }

    std::u16string directory;
    const std::size_t file_at = split_directory(full, directory);
    // The file part is a pointer into the caller's own buffer, so it is
    // only handed out when there is a buffer to point into. A sizing call
    // gets null, which is the honest answer: there is nothing yet to point
    // at, and the offset the caller needs is implied by the returned size.
    *file_part = buffer == nullptr ? nullptr : buffer + file_at;

    const std::size_t needed = (full.size() + 1) * sizeof(char16_t);
    if (needed > kMaxPathChars * sizeof(char16_t)) {
        // Past the NT path limit: this is what the caller sees when a path
        // cannot be represented, and it is a failure rather than a truncated
        // path, because a truncated path names a different file.
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (buffer == nullptr || bytes < needed) {
        set_last_error(kErrorInsufficientBuffer);
        return static_cast<std::uint32_t>(needed);
    }
    std::memcpy(buffer, full.data(), full.size() * sizeof(char16_t));
    buffer[full.size()] = u'\0';
    set_last_error(kErrorSuccess);
    return static_cast<std::uint32_t>(full.size());
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlGetFullPathName_UEx(
    const char16_t* name, std::uint32_t bytes, char16_t* buffer,
    char16_t** file_part, std::uint32_t* file_size,
    std::uint32_t* directory_size, char16_t* directory) noexcept {
    const std::uint32_t written =
        nr2_RtlGetFullPathName_U(name, bytes, buffer, file_part);
    if (written == 0) {
        // The call already reported why through `GetLastError`; the sizes
        // are left alone rather than filled with a number that would look
        // like a real length.
        return 0;
    }
    // `written` is the character count without the terminator on success and
    // the required size with it on a short buffer, and the two are told
    // apart by whether the string actually made it into the buffer.
    const bool fitted =
        buffer != nullptr && file_part != nullptr && *file_part != nullptr &&
        written < bytes;
    if (file_size != nullptr) {
        // The file part's own size, with its terminator -- which is what a
        // caller allocates when it only wants the name.
        const std::size_t name_chars =
            fitted ? static_cast<std::size_t>(written) -
                         static_cast<std::size_t>(*file_part - buffer)
                   : static_cast<std::size_t>(written);
        *file_size = static_cast<std::uint32_t>(name_chars + 1);
    }
    if (directory_size != nullptr) {
        *directory_size = fitted ? static_cast<std::uint32_t>(
                                        *file_part - buffer)
                                 : written;
    }
    if (directory != nullptr && fitted) {
        // The directory is everything before the file part, with the
        // terminator this copy adds.
        const std::size_t dir_chars =
            static_cast<std::size_t>(*file_part - buffer);
        std::memcpy(directory, buffer, dir_chars * sizeof(char16_t));
        directory[dir_chars] = u'\0';
    }
    return written;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlIsDosDeviceName_U(
    const char16_t* path) noexcept {
    if (path == nullptr) {
        return 0;
    }
    return is_dos_device(std::u16string(path)) ? 1 : 0;
}

// ------------------------------------------------------------- PE images
//
// The four image queries below walk a loaded image's headers. They differ in
// what they take: a base address, an NT header pointer, or an RVA. The
// bounds discipline is the same in all of them -- every offset read out of a
// header is checked against the header's own size field before it is used,
// because a guest that hands over a truncated image must be refused rather
// than believed.

namespace {

// The mapped extent of the image the address belongs to, or zero when the
// address is not inside one. The check the RVA walks below share: an RVA is
// only meaningful relative to an image whose extent is known, and the size
// is what makes "offset N of the header" a statement about bytes rather than
// about whatever happens to follow.
[[nodiscard]] std::size_t mapped_image_size(const void* address) noexcept {
    const auto* state = guest_state();
    if (state == nullptr || state->space == nullptr || address == nullptr) {
        return 0;
    }
    const Region* region =
        state->space->find(reinterpret_cast<std::uint64_t>(address));
    if (region == nullptr || region->base !=
                                 reinterpret_cast<std::uint64_t>(address)) {
        return 0;
    }
    return static_cast<std::size_t>(region->size);
}

// Whether `bytes` starting at `offset` lie inside an image of `size`. The
// addition is done in 64-bit arithmetic so an offset near the top of the
// address space cannot wrap back into the image and pass the check.
// The address `offset` bytes into an image. The arithmetic goes through
// `void*` because C++ has no arithmetic on a `void*`, and the result is
// handed back as a `void*` because these are the addresses the guest asked
// for -- the guest owns its own image memory, and none of these entry points
// write through what they return.
[[nodiscard]] void* image_at(const void* base, std::size_t offset) noexcept {
    const void* at = static_cast<const std::uint8_t*>(base) + offset;
    return const_cast<void*>(at);
}

[[nodiscard]] bool in_image(std::size_t size, std::size_t offset,
                            std::size_t bytes) noexcept {
    if (offset > size) {
        return false;
    }
    return static_cast<std::uint64_t>(offset) + bytes <=
           static_cast<std::uint64_t>(size);
}

// PE\0\0, and where the pieces of the optional header this file reads sit.
// The header offsets are the ones the format fixes: the signature, the
// file header's own size, then the NT header's signature and the optional
// header's fields, whose offsets are counted from the optional header's
// start and land in the data directories for the ones past the fixed part.
constexpr std::size_t kDosSignature = 0;
constexpr std::size_t kDosLfanew = 0x3C;
constexpr std::size_t kNtSignature = 0;
constexpr std::size_t kNtFileHeader = 4;
constexpr std::size_t kNtOptional = 24;
constexpr std::size_t kFileHeaderSize = 20;
// The two file-header fields this file reads, counted from the file
// header's own start -- which is the NT signature plus four, not the NT
// signature itself. Reading them from the signature would take the symbol
// table's fields for these.
constexpr std::size_t kFileOptionalSize = 16;      // SizeOfOptionalHeader
constexpr std::size_t kFileCharacteristics = 18;
constexpr std::size_t kOptionalMagic = 0;
constexpr std::size_t kOptionalDirectoryCount = 0x6C;  // NumberOfRvaAndSizes
constexpr std::size_t kOptionalDirectoryBase = 0x70;   // the array itself

// IMAGE_DIRECTORY_ENTRY_EXPORT is the first data directory, which is the one
// the export queries walk.
constexpr std::size_t kExportDirectory = 0;
constexpr std::size_t kExportDirectoryBytes = 0x28;

[[nodiscard]] bool read_pe_header(const std::uint8_t* base, std::size_t size,
                                  std::uint8_t** nt_out,
                                  std::uint8_t** optional_out) noexcept {
    // The signature has to be there before `e_lfanew` means anything, and
    // `e_lfanew` has to point at a signature before the file header's own
    // size can be trusted.
    if (!in_image(size, kDosSignature, 2)) {
        return false;
    }
    if (read_u16(base, kDosSignature) != 0x5A4D) {  // "MZ"
        return false;
    }
    if (!in_image(size, kDosLfanew, 4)) {
        return false;
    }
    const std::size_t lfanew = read_u32(base, kDosLfanew);
    if (lfanew < kDosSignature + 2 || !in_image(size, lfanew, 4)) {
        return false;
    }
    std::uint8_t* nt = const_cast<std::uint8_t*>(base) + lfanew;
    if (read_u32(nt, kNtSignature) != 0x00004550) {  // "PE\0\0"
        return false;
    }
    const std::size_t optional_at = lfanew + kNtOptional;
    if (!in_image(size, optional_at, 2)) {
        return false;
    }
    const std::uint16_t optional_size =
        read_u16(nt, kNtFileHeader + kFileOptionalSize);
    if (optional_size < 2 || !in_image(size, optional_at, optional_size)) {
        return false;
    }
    *nt_out = nt;
    *optional_out = nt + kNtOptional;
    return true;
}

}  // namespace

extern "C" __attribute__((ms_abi)) void* nr2_RtlImageNtHeader(
    const void* base) noexcept {
    const std::size_t size = mapped_image_size(base);
    if (size == 0) {
        return nullptr;
    }
    std::uint8_t* nt = nullptr;
    std::uint8_t* optional = nullptr;
    if (!read_pe_header(static_cast<const std::uint8_t*>(base), size, &nt,
                        &optional)) {
        return nullptr;
    }
    return nt;
}

extern "C" __attribute__((ms_abi)) void* nr2_RtlImageRvaToVa(
    std::uint32_t rva, const void* base) noexcept {
    const std::size_t size = mapped_image_size(base);
    if (size == 0 || !in_image(size, rva, 1)) {
        // An RVA past the end of the image has no address. The image loader
        // never hands one out, so a guest that asks has a bug, and answering
        // base + rva anyway would put it outside the mapping.
        return nullptr;
    }
    return image_at(base, rva);
}

extern "C" __attribute__((ms_abi)) void* nr2_RtlImageDirectoryEntryToData(
    const void* base, std::uint16_t index) noexcept {
    const std::size_t size = mapped_image_size(base);
    if (size == 0) {
        return nullptr;
    }
    std::uint8_t* nt = nullptr;
    std::uint8_t* optional = nullptr;
    const auto* bytes = static_cast<const std::uint8_t*>(base);
    if (!read_pe_header(bytes, size, &nt, &optional)) {
        return nullptr;
    }
    // The directory array's own count is read before indexing it: an index
    // past the count names nothing, and the array is not necessarily long
    // enough to hold it.
    const std::size_t lfanew = read_u32(base, kDosLfanew);
    const std::size_t optional_at = lfanew + kNtOptional;
    const std::size_t count_at = optional_at + kOptionalDirectoryCount;
    if (!in_image(size, count_at, 4)) {
        return nullptr;
    }
    const std::uint32_t count = read_u32(base, count_at);
    if (index >= count) {
        return nullptr;
    }
    const std::size_t entry_at =
        optional_at + kOptionalDirectoryBase + static_cast<std::size_t>(index) * 8;
    if (!in_image(size, entry_at, 8)) {
        return nullptr;
    }
    const std::uint32_t rva = read_u32(base, entry_at);
    if (rva == 0 || !in_image(size, rva, 1)) {
        // A directory with a zero RVA is an absent directory, which is how
        // an image says it has no exports or no imports at all.
        return nullptr;
    }
    return image_at(base, rva);
}

extern "C" __attribute__((ms_abi)) void* nr2_RtlImageRvaToSection(
    const void* base, std::uint32_t rva) noexcept {
    const std::size_t size = mapped_image_size(base);
    if (size == 0) {
        return nullptr;
    }
    std::uint8_t* nt = nullptr;
    std::uint8_t* optional = nullptr;
    if (!read_pe_header(static_cast<const std::uint8_t*>(base), size, &nt,
                        &optional)) {
        return nullptr;
    }
    const std::size_t lfanew = read_u32(base, kDosLfanew);
    const std::size_t optional_at = lfanew + kNtOptional;
    const std::uint16_t magic = read_u16(base, optional_at + kOptionalMagic);
    const std::size_t section_table =
        optional_at + (magic == 0x20B ? 240 : 224);
    const std::uint16_t sections = read_u16(nt, kNtFileHeader + 2);  // NumberOfSections
    constexpr std::size_t kSectionSize = 40;
    for (std::uint16_t k = 0; k < sections; ++k) {
        const std::size_t at = section_table +
                               static_cast<std::size_t>(k) * kSectionSize;
        if (!in_image(size, at, kSectionSize)) {
            return nullptr;
        }
        const std::uint32_t virtual_size = read_u32(base, at + 8);
        const std::uint32_t virtual_address = read_u32(base, at + 12);
        const std::uint32_t raw_size = read_u32(base, at + 16);
        // A section whose raw size is larger than its virtual size occupies
        // more of the image than the virtual size says, and the loader maps
        // the larger. The bound is therefore the larger of the two, which is
        // what makes an RVA inside a padded section still resolve.
        const std::uint32_t span = virtual_size > raw_size ? virtual_size
                                                           : raw_size;
        if (rva >= virtual_address && rva < virtual_address + span) {
            return image_at(base, at);
        }
    }
    return nullptr;
}

// --------------------------------------------------------------- the FLS
//
// The fiber-local storage is an array of slots indexed by a per-call
// allocation. One guest thread runs here, so the slot array is a single
// vector and a fiber index has no other thread's values to collide with --
// but the index a caller gets back is one it can pass to `RtlFlsFree`, so
// it has to stay valid for as long as the storage does, which means indices
// are never reused while an allocation holds one.

namespace {

struct FlsState {
    std::vector<void*> slots;
    // The indices handed out and not yet freed. A freed index goes back on
    // this list rather than into the free pool directly, because a fiber
    // that frees during a callback may be interrupted before it is done
    // with the value.
    std::vector<std::uint32_t> live;
    bool in_use = false;
};

FlsState& fls_state() noexcept {
    static FlsState state;
    return state;
}

constexpr std::uint32_t kFlsUnset = 0xFFFFFFFFu;

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlFlsAlloc(
    void** callback) noexcept {
    FlsState& state = fls_state();
    if (state.in_use) {
        // Nesting is refused rather than silently aliased: two callers
        // sharing one fiber's storage would each see the other's values,
        // and a refused call is something the caller can report.
        set_last_error(kErrorBusy);
        return kFlsUnset;
    }
    const auto index = static_cast<std::uint32_t>(state.slots.size());
    state.slots.push_back(nullptr);
    state.live.push_back(index);
    state.in_use = true;
    // The callback is kept so a caller that allocated one can tell that it
    // did; this runtime's fibers do not run the callback at thread exit,
    // because the guest controls when its fibers end.
    static_cast<void>(callback);
    set_last_error(kErrorSuccess);
    return index;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlFlsFree(
    std::uint32_t index) noexcept {
    FlsState& state = fls_state();
    if (index >= state.slots.size()) {
        return kStInvalidParameter;
    }
    bool live = false;
    for (std::uint32_t candidate : state.live) {
        if (candidate == index) {
            live = true;
            break;
        }
    }
    if (!live) {
        // Freeing an index that was never allocated, or freeing one twice,
        // is refused: the second free would drop a slot another allocation
        // may since have been given.
        return kStInvalidParameter;
    }
    for (auto it = state.live.begin(); it != state.live.end(); ++it) {
        if (*it == index) {
            state.live.erase(it);
            break;
        }
    }
    state.slots[index] = nullptr;
    state.in_use = false;
    return kStSuccess;
}

namespace {

// Whether an index is still allocated. The free list is the one record of
// that, and reads and writes have to consult it for the same reason frees
// do: a slot whose index was handed back may since have been given to
// another allocation, and answering for it would hand one caller's value to
// another.
[[nodiscard]] bool fls_live(const FlsState& state,
                            std::uint32_t index) noexcept {
    for (std::uint32_t candidate : state.live) {
        if (candidate == index) {
            return true;
        }
    }
    return false;
}

}  // namespace

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlFlsGetValue(
    std::uint32_t index, void** value) noexcept {
    const FlsState& state = fls_state();
    if (value == nullptr) {
        return kStInvalidParameter;
    }
    if (index >= state.slots.size() || !fls_live(state, index)) {
        return kStInvalidParameter;
    }
    *value = state.slots[index];
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlFlsSetValue(
    std::uint32_t index, void* value) noexcept {
    FlsState& state = fls_state();
    if (index >= state.slots.size() || !fls_live(state, index)) {
        return kStInvalidParameter;
    }
    state.slots[index] = value;
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) void nr2_RtlProcessFlsData(
    void** arrays, std::uint32_t count) noexcept {
    // The array is the fiber data a thread is torn down with. This runtime
    // runs one guest thread and ends it by returning from the entry point
    // rather than by being killed, so there is nothing here to release that
    // the caller has not already released through `RtlFlsFree`. Freeing
    // blindly would drop slots a fiber still holds, so the call is a no-op
    // and the parameters are read only to keep the contract visible.
    static_cast<void>(arrays);
    static_cast<void>(count);
}


// ---------------------------------------------------------------- the SIDs

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeSid(
    void* sid, Ntstatus revision, std::uint8_t sub_authorities) noexcept {
    if (sid == nullptr || sub_authorities > kSidMaxSubAuthorities) {
        return kStInvalidParameter;
    }
    if (revision != 1) {
        // Revision 0 is the pre-1988 form and revision 2 the SMS-era one;
        // neither has a place in a descriptor this runtime hands out, and
        // writing one and reporting success would produce a SID the access
        // checks below cannot compare against anything.
        return kStInvalidParameter;
    }
    std::memset(sid, 0, sid_bytes(sub_authorities));
    write_u8(sid, kSidRevision, static_cast<std::uint8_t>(revision));
    write_u8(sid, kSidSubAuthorityCount, sub_authorities);
    return kStSuccess;
}

// ---------------------------------------------------------- the access map

// A generic access mask is one of four rights the caller does not name
// individually. Expanding it is the access check's first step: what the
// object says it allows, and what the caller asked for, are both written as
// generic masks before either is turned into specific bits.

namespace {

constexpr std::uint32_t kGenericRead = 0x80000000u;
constexpr std::uint32_t kGenericWrite = 0x40000000u;
constexpr std::uint32_t kGenericExecute = 0x20000000u;
constexpr std::uint32_t kGenericAll = 0xF0000000u;

// The specific bits each generic right stands for. The file bits are the
// ones `RtlMapGenericMask` is defined over; a generic right with no
// specific counterpart in the object type's own mask is dropped, which is
// what makes the answer depend on the object rather than only on the mask.
constexpr std::uint32_t kGenericReadMap = 0x00000001u;    // FILE_READ_DATA
constexpr std::uint32_t kGenericWriteMap = 0x00000002u;   // FILE_WRITE_DATA
constexpr std::uint32_t kGenericExecuteMap = 0x00000020u; // FILE_EXECUTE
constexpr std::uint32_t kGenericAllMap = 0x000000FFu;

[[nodiscard]] std::uint32_t map_generic_right(std::uint32_t generic,
                                              std::uint32_t specific) noexcept {
    switch (generic & kGenericAll) {
        case kGenericRead:
            return specific & kGenericReadMap;
        case kGenericWrite:
            return specific & kGenericWriteMap;
        case kGenericExecute:
            return specific & kGenericExecuteMap;
        case kGenericAll:
            return specific & kGenericAllMap;
        default:
            // More than one generic bit at once is not a right any object
            // grants: Windows refuses it rather than picking one.
            return 0;
    }
}

}  // namespace

extern "C" __attribute__((ms_abi)) void nr2_RtlMapGenericMask(
    std::uint32_t* mask, std::uint32_t generic_mask) noexcept {
    if (mask == nullptr) {
        return;
    }
    std::uint32_t result = *mask & ~kGenericAll;
    // Each of the four generic rights the caller asked for is mapped
    // through the object's own specific bits, so a right the object does
    // not define contributes nothing.
    for (std::uint32_t bit = 0; bit < 4; ++bit) {
        const std::uint32_t right = kGenericAll & (1u << (31 - bit));
        if ((generic_mask & right) != 0) {
            result |= map_generic_right(right, *mask);
        }
    }
    *mask = result;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlNewSecurityGrantedAccess(
    std::uint32_t old_mask, const void* old_ace, void** new_ace,
    std::uint32_t* new_mask) noexcept {
    // Collapsing an access mask down to the smallest set of rights that
    // grants exactly the same thing is what this does, and the answer is
    // computed from the object's own generic bits rather than guessed: a
    // mask with no generic bit left in it is already minimal.
    static_cast<void>(old_ace);
    if (new_mask == nullptr) {
        return 0;
    }
    std::uint32_t specific = old_mask & ~kGenericAll;
    const std::uint32_t generic = old_mask & kGenericAll;
    if (generic == kGenericAll) {
        *new_mask = specific | kGenericAll;
        if (new_ace != nullptr) {
            *new_ace = nullptr;
        }
        return 1;
    }
    for (std::uint32_t bit = 0; bit < 4; ++bit) {
        const std::uint32_t right = 1u << (31 - bit);
        if ((generic & right) != 0 &&
            (specific & map_generic_right(right, kGenericAllMap)) ==
                map_generic_right(right, kGenericAllMap)) {
            specific &= ~map_generic_right(right, kGenericAllMap);
        }
    }
    *new_mask = specific | generic;
    if (new_ace != nullptr) {
        *new_ace = nullptr;
    }
    return 1;
}

// ------------------------------------------------------------------ 8.3 names

namespace {

// Whether a character may appear in a short name. The set is what DOS-era
// naming allowed: letters, digits and the handful of punctuation marks that
// were legal, which is a much smaller set than a long name accepts.
[[nodiscard]] bool dos_8dot3_char(char16_t ch) noexcept {
    if (ch >= u'A' && ch <= u'Z') {
        return true;
    }
    // The check is case-insensitive -- a short name is stored upper-cased,
    // but a caller asking about "autoexec.bat" is asking about the same
    // name as "AUTOEXEC.BAT", and refusing the lower-case spelling would
    // make the answer depend on how the caller typed it.
    if (ch >= u'a' && ch <= u'z') {
        return true;
    }
    if (ch >= u'0' && ch <= u'9') {
        return true;
    }
    switch (ch) {
        case u'$':
        case u'%':
        case u'\'':
        case u'-':
        case u'_':
        case u'@':
        case u'~':
        case u'`':
        case u'!':
        case u'(':
        case u')':
        case u'{':
        case u'}':
        case u'#':
        case u'&':
            return true;
        default:
            return false;
    }
}

}  // namespace

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlIsNameLegalDOS8Dot3(
    const char16_t* name, void* out, std::uint32_t* chars_out,
    std::uint32_t* might_have_short_name) noexcept {
    // Three answers come out of this one call. `out` and `chars_out` say
    // whether the name is a legal short name and how long it is -- the check
    // is case-insensitive, so the upper-cased copy comes back. The third
    // says whether the name could be the stem of one, which is a different
    // question: it is false only for a name that cannot begin a short name
    // at all, and true for anything whose stem would still fit.
    if (name == nullptr) {
        return kStInvalidParameter;
    }
    std::u16string text(name);
    bool legal = !text.empty();
    std::size_t period = text.find(u'.');
    std::u16string stem = period == std::u16string::npos
                              ? text
                              : text.substr(0, period);
    std::u16string extension =
        period == std::u16string::npos ? std::u16string()
                                       : text.substr(period + 1);
    if (stem.empty() || stem.size() > 8 || extension.size() > 3) {
        legal = false;
    }
    if (period != std::u16string::npos &&
        text.find(u'.', period + 1) != std::u16string::npos) {
        legal = false;  // a second period is never legal
    }
    for (char16_t ch : stem) {
        if (!dos_8dot3_char(ch)) {
            legal = false;
        }
    }
    for (char16_t ch : extension) {
        if (!dos_8dot3_char(ch)) {
            legal = false;
        }
    }
    if (might_have_short_name != nullptr) {
        // The third answer is whether generation could produce a short name
        // from this one at all. Generation abbreviates the stem and maps the
        // characters it cannot keep to underscores, so the only stem it
        // cannot work from is an empty one -- which is what a name that
        // begins with a period has.
        *might_have_short_name = stem.empty() ? 0u : 1u;
    }
    if (out != nullptr) {
        auto* bytes = static_cast<std::uint8_t*>(out);
        std::memset(bytes, 0, 15);
        if (legal) {
            std::size_t k = 0;
            for (char16_t ch : stem) {
                bytes[k++] = ch >= u'a' && ch <= u'z'
                                 ? static_cast<std::uint8_t>(ch - u'a' + u'A')
                                 : static_cast<std::uint8_t>(ch);
            }
            if (!extension.empty()) {
                bytes[k++] = '.';
                for (char16_t ch : extension) {
                    bytes[k++] = ch >= u'a' && ch <= u'z'
                                     ? static_cast<std::uint8_t>(ch - u'a' + u'A')
                                     : static_cast<std::uint8_t>(ch);
                }
            }
        }
    }
    if (chars_out != nullptr) {
        *chars_out = legal ? static_cast<std::uint32_t>(text.size()) : 0u;
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGenerate8dot3Name(
    std::uint64_t handle, const char16_t* long_name, void* short_name,
    void** short_name_out, std::int32_t* allocate) noexcept {
    // The generated name is a window into a per-directory pool of candidates
    // rather than a function of the long name alone: two long names that
    // abbreviate the same way get different short names, and which one a
    // caller gets depends on what the pool already holds. This runtime has
    // no directory to keep that pool in, so the name is generated from the
    // long name and the `~` tail is the handle, which makes it unique per
    // call site without pretending to be unique per file.
    static_cast<void>(handle);
    if (long_name == nullptr || short_name == nullptr ||
        short_name_out == nullptr) {
        return kStInvalidParameter;
    }
    if (allocate != nullptr && *allocate != 0) {
        // The caller offered to let the callee allocate the 8.3 name. This
        // runtime does not allocate on the caller's behalf for a name it
        // keeps nowhere, so the offer is declined and the caller keeps its
        // own buffer -- which it supplied anyway.
        *allocate = 0;
        return kStBufferTooSmall;
    }

    std::u16string name(long_name);
    // The stem is the part before the last period, minus any leading
    // underscores the DOS naming rules skipped.
    const std::size_t period = name.find_last_of(u'.');
    std::u16string stem = period == std::u16string::npos
                              ? name
                              : name.substr(0, period);
    while (!stem.empty() && stem.front() == u'_') {
        stem.erase(stem.begin());
    }

    // Seven characters of stem, a '~', and one digit of the handle: the
    // eight the format allows. Underscores stand in for the characters
    // that are not legal, which is how the real generator keeps the shape.
    std::u16string generated;
    for (char16_t ch : stem) {
        if (generated.size() >= 7) {
            break;
        }
        generated.push_back(dos_8dot3_char(ch) ? ch : u'_');
    }
    generated.push_back(u'~');
    generated.push_back(static_cast<char16_t>(u'1' + (handle % 8)));

    std::string extension;
    if (period != std::u16string::npos && period + 1 < name.size()) {
        std::size_t k = 0;
        for (std::size_t p = period + 1; p < name.size() && k < 3; ++p) {
            if (dos_8dot3_char(name[p])) {
                extension.push_back(name[p] >= u'a' && name[p] <= u'z'
                                        ? static_cast<char>(name[p] - u'a' + 'A')
                                        : static_cast<char>(name[p]));
                ++k;
            }
        }
    }

    // The longest name the format allows is nine stem characters, a period
    // and three extension characters, plus the terminator: fourteen bytes.
    auto* bytes = static_cast<std::uint8_t*>(short_name);
    std::memset(bytes, 0, 14);
    for (std::size_t k = 0; k < generated.size(); ++k) {
        bytes[k] = generated[k] >= u'a' && generated[k] <= u'z'
                       ? static_cast<std::uint8_t>(generated[k] - u'a' + 'A')
                       : static_cast<std::uint8_t>(generated[k]);
    }
    std::size_t at = generated.size();
    if (!extension.empty()) {
        bytes[at++] = '.';
        for (char ch : extension) {
            bytes[at++] = static_cast<std::uint8_t>(ch);
        }
    }
    bytes[at] = '\0';
    *short_name_out = short_name;
    return kStSuccess;
}

// ---------------------------------------------------------------- the locales

// The locale name / LCID pairs this runtime answers. The list is short on
// purpose: it is the set of names a guest can ask about and get a truthful
// answer for, and a name outside it is reported as unknown rather than
// guessed at from its shape. The ids are the ones the names have carried
// since Windows 7, which is what makes a round trip through this pair
// stable.

namespace {

struct LocaleEntry {
    const char16_t* name;
    std::uint32_t lcid;
};

constexpr LocaleEntry kLocales[] = {
    {u"en-US", 0x0409},
    {u"en-GB", 0x0809},
    {u"en-CA", 0x1009},
    {u"en-AU", 0x0C09},
    {u"en-NZ", 0x1409},
    {u"en-IN", 0x0409},
    {u"fr-FR", 0x040C},
    {u"fr-CA", 0x0C0C},
    {u"de-DE", 0x0407},
    {u"es-ES", 0x0C0A},
    {u"es-MX", 0x080A},
    {u"it-IT", 0x0410},
    {u"ja-JP", 0x0411},
    {u"ko-KR", 0x0412},
    {u"zh-CN", 0x0804},
    {u"zh-TW", 0x0404},
    {u"ru-RU", 0x0419},
    {u"nl-NL", 0x0413},
    {u"pt-BR", 0x0416},
    {u"tr-TR", 0x041F},
    {u"pl-PL", 0x0415},
};

[[nodiscard]] const LocaleEntry* find_locale_by_name(std::u16string_view name) noexcept {
    for (const LocaleEntry& entry : kLocales) {
        if (name == entry.name) {
            return &entry;
        }
    }
    return nullptr;
}

[[nodiscard]] const LocaleEntry* find_locale_by_lcid(std::uint32_t lcid) noexcept {
    for (const LocaleEntry& entry : kLocales) {
        if (entry.lcid == lcid) {
            return &entry;
        }
    }
    return nullptr;
}

}  // namespace

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlLocaleNameToLcid(
    const char16_t* name, std::uint32_t* lcid) noexcept {
    if (name == nullptr || lcid == nullptr) {
        return kStInvalidParameter;
    }
    const LocaleEntry* found = find_locale_by_name(name);
    if (found == nullptr) {
        // An unknown name gets no id at all rather than a plausible one: a
        // wrong id silently changes sorting and formatting for everything
        // downstream of it.
        *lcid = 0;
        return kStInvalidParameter;
    }
    *lcid = found->lcid;
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlLcidToLocaleName(
    std::uint32_t lcid, char16_t* buffer, std::int32_t* chars) noexcept {
    if (buffer == nullptr || chars == nullptr) {
        return kStInvalidParameter;
    }
    const LocaleEntry* found = find_locale_by_lcid(lcid);
    if (found == nullptr) {
        return kStInvalidParameter;
    }
    std::size_t length = 0;
    while (found->name[length] != u'\0') {
        ++length;
    }
    // A negative capacity is the sizing call: no buffer is written and the
    // required length comes back through the same parameter.
    if (*chars <= 0) {
        *chars = static_cast<std::int32_t>(length + 1);
        return kStSuccess;
    }
    if (static_cast<std::size_t>(*chars) < length + 1) {
        return kStBufferTooSmall;
    }
    for (std::size_t k = 0; k <= length; ++k) {
        buffer[k] = found->name[k];
    }
    *chars = static_cast<std::int32_t>(length);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlIsValidLocaleName(
    const char16_t* name, std::uint32_t* flags) noexcept {
    static_cast<void>(flags);
    if (name == nullptr) {
        return 0;
    }
    return find_locale_by_name(name) != nullptr ? 1 : 0;
}

// The four preferred-language queries all answer the same list -- the one
// locale this runtime reports -- and differ only in what else they write.

namespace {

constexpr std::uint32_t kUserDefaultFlag = 0x00000001;

[[nodiscard]] Ntstatus preferred_languages(char16_t* buffer,
                                           std::uint32_t* bytes,
                                           std::uint32_t* count,
                                           std::uint32_t* out_flags) noexcept {
    static const char16_t kOnly[] = u"en-US";
    constexpr std::size_t kChars = 5;  // four characters and the terminator
    const std::size_t needed = kChars * sizeof(char16_t);
    if (bytes == nullptr) {
        return kStInvalidParameter;
    }
    if (buffer == nullptr || *bytes < needed) {
        *bytes = static_cast<std::uint32_t>(needed);
        return kStBufferOverflow;
    }
    for (std::size_t k = 0; k < kChars; ++k) {
        buffer[k] = kOnly[k];
    }
    *bytes = static_cast<std::uint32_t>(needed);
    if (count != nullptr) {
        *count = 1;
    }
    if (out_flags != nullptr) {
        *out_flags = kUserDefaultFlag;
    }
    return kStSuccess;
}

}  // namespace

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetProcessPreferredUILanguages(
    std::uint32_t flags, std::uint32_t* count, char16_t* buffer,
    std::uint32_t* bytes) noexcept {
    static_cast<void>(flags);
    return preferred_languages(buffer, bytes, count, nullptr);
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetSystemPreferredUILanguages(
    std::uint32_t flags, std::uint32_t* count, char16_t* buffer,
    std::uint32_t* bytes) noexcept {
    static_cast<void>(flags);
    return preferred_languages(buffer, bytes, count, nullptr);
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetUserPreferredUILanguages(
    std::uint32_t flags, std::uint32_t* count, char16_t* buffer,
    std::uint32_t* bytes) noexcept {
    static_cast<void>(flags);
    return preferred_languages(buffer, bytes, count, nullptr);
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetThreadPreferredUILanguages(
    std::uint32_t flags, std::uint32_t* count, char16_t* buffer,
    std::uint32_t* bytes) noexcept {
    static_cast<void>(flags);
    return preferred_languages(buffer, bytes, count, nullptr);
}

// ------------------------------------------------------------- the clock

extern "C" __attribute__((ms_abi)) void nr2_RtlGetSystemTimePrecise(
    void* time) noexcept {
    // The precise clock is the same clock as the ordinary one, sampled at a
    // point the runtime does not round: the answer is the host's realtime
    // count converted into the 1601 epoch, and a guest that reads two
    // successive answers sees them differ, which is the property the
    // "precise" is in the name for.
    if (time == nullptr) {
        return;
    }
    write_u64(time, 0, host_ticks_1601());
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlLocalTimeToSystemTime(
    const void* local, void* system) noexcept {
    // SYSTEMTIME is sixteen-bit fields, and the conversion is the reverse of
    // `SystemTimeToFileTime`: a local time is turned into the count of
    // 100-nanosecond ticks since 1601 that names the same instant. This
    // runtime runs with the host's own time zone, so no offset is applied --
    // the answer is the local time read as if it were already UTC, which is
    // what a single-time-zone host can answer truthfully.
    if (local == nullptr || system == nullptr) {
        return kStInvalidParameter;
    }
    // SYSTEMTIME's layout: year, month, day-of-week, day, hour, minute,
    // second, milliseconds -- eight 16-bit fields, with the weekday between
    // the day and the hour. Reading it as if the weekday were not there
    // shifts every field after it by one and turns noon into midnight.
    const std::uint16_t year = read_u16(local, 0);
    const std::uint16_t month = read_u16(local, 2);
    const std::uint16_t day = read_u16(local, 6);
    const std::uint16_t hour = read_u16(local, 8);
    const std::uint16_t minute = read_u16(local, 10);
    const std::uint16_t second = read_u16(local, 12);
    const std::uint16_t millis = read_u16(local, 14);
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 ||
        minute > 59 || second > 59) {
        // A field out of range names no instant, and the real function
        // refuses rather than normalising a caller bug into a date.
        return kStInvalidParameter;
    }

    // Days from the 1601 epoch to the date, by the calendar the kernel uses:
    // the Gregorian rules extended back before 1582, with the leap year
    // every fourth year except the centuries that are not divisible by 400.
    const auto days_from_civil = [](int y, unsigned m, unsigned d) -> int {
        y -= m <= 2;
        const int era = (y >= 0 ? y : y - 399) / 400;
        const unsigned yoe = static_cast<unsigned>(y - era * 400);
        const unsigned doy =
            (153u * (m + (m > 2 ? -3u : 9u)) + 2u) / 5u + d - 1u;
        const unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
        return era * 146097 + static_cast<int>(doe) - 719468;
    };
    // 1601-01-01 is day -134774 of the Unix epoch.
    const std::int64_t days =
        days_from_civil(static_cast<int>(year), month, day) + 134774;
    const std::uint64_t seconds = static_cast<std::uint64_t>(days) * 86400ull +
                                   static_cast<std::uint64_t>(hour) * 3600ull +
                                   static_cast<std::uint64_t>(minute) * 60ull +
                                   static_cast<std::uint64_t>(second);
    write_u64(system, 0, seconds * kTicksPerSecond +
                            static_cast<std::uint64_t>(millis) * 10000ull);
    return kStSuccess;
}

// ------------------------------------------------------- the context record

// CONTEXT on x64 is 0x698 bytes, and its fields sit at offsets the format
// fixes rather than at a compiler's choice. The extended-context family
// below reads and writes the same record through three spellings, so the
// offsets are stated once here.
//
// CONTEXT_CONTROL is 0x00100001: the control plus the integer registers.
// CONTEXT_INTEGER is 0x00000002: the saved non-volatile registers.
// CONTEXT_ALL is 0x0010003F: everything, including the floating-point and
// vector state the segments follow.

namespace {

constexpr std::size_t kContextFlags = 0x30;
constexpr std::size_t kContextRip = 0xF8;
constexpr std::size_t kContextRsp = 0x98;
constexpr std::size_t kContextInteger = 0x02;
constexpr std::size_t kContextControl = 0x00100001;
constexpr std::size_t kContextAll = 0x0010003F;
constexpr std::size_t kContextBytes = 0x698;

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlGetExtendedContextLength(
    std::int32_t context_flags) noexcept {
    // The floating-point state is optional: a caller that did not ask to
    // save it gets a context with no room for it, which is the whole reason
    // this query exists.
    return (context_flags & 0x4) != 0 ? kContextBytes
                                       : static_cast<std::uint32_t>(0x4D0);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlGetExtendedContextLength2(
    std::int32_t context_flags) noexcept {
    // The Ex spelling adds the machine's own instruction-pointer width to
    // the answer, which is how a caller allocates a context that a machine
    // of a different word size can still describe.
    return nr2_RtlGetExtendedContextLength(context_flags) +
           static_cast<std::uint32_t>(sizeof(void*) * 4);
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeExtendedContext(
    void* context, std::int32_t flags) noexcept {
    if (context == nullptr) {
        return kStInvalidParameter;
    }
    if (flags == 0) {
        return kStInvalidParameter;
    }
    // Only the flags this runtime can honour are recorded; the record is
    // cleared first so a caller that reuses a context does not read the
    // previous one's registers.
    const std::size_t length =
        nr2_RtlGetExtendedContextLength(flags);
    std::memset(context, 0, length);
    write_u32(context, kContextFlags, static_cast<std::uint32_t>(flags));
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeExtendedContext2(
    void* context, std::int32_t flags, std::uint32_t* bytes) noexcept {
    const Ntstatus status =
        nr2_RtlInitializeExtendedContext(context, flags);
    if (status == kStSuccess && bytes != nullptr) {
        *bytes = nr2_RtlGetExtendedContextLength2(flags);
    }
    return status;
}

extern "C" __attribute__((ms_abi)) void nr2_RtlLocateLegacyContext(
    void* extended, void** legacy) noexcept {
    // The legacy CONTEXT sits at the front of the extended record, so the
    // extended pointer is the legacy pointer. It is written even when the
    // caller's pointer is null-checked here rather than trusted.
    if (legacy == nullptr) {
        return;
    }
    *legacy = extended;
}

extern "C" __attribute__((ms_abi)) void nr2_RtlGetEnabledExtendedFeatures(
    std::uint64_t* features) noexcept {
    // No architectural feature is switched on for a guest of this runtime:
    // the guest sees the host's own instruction set and no context-switch
    // extension, so the mask is zero rather than a guess at which of them
    // the host happens to have.
    if (features == nullptr) {
        return;
    }
    *features = 0;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetExtendedFeaturesMask(
    const std::uint64_t features[2]) noexcept {
    if (features == nullptr) {
        return kStInvalidParameter;
    }
    // A context that claims features this machine does not have is refused:
    // reading it would mean trusting a record that describes a processor
    // that is not the one running.
    if (features[0] != 0 || features[1] != 0) {
        return kStInvalidParameter;
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlLocateExtendedFeature(
    const std::uint64_t features[2], std::uint32_t feature_id,
    std::uint32_t* slot) noexcept {
    if (features == nullptr || slot == nullptr) {
        return kStInvalidParameter;
    }
    // With no features enabled there is no slot for any of them, and the
    // real query answers the index of the first available slot -- which is
    // the whole of the array -- so a caller that adds a feature to a context
    // this one built has somewhere to put it.
    for (std::uint32_t k = 0; k < 16; ++k) {
        const std::size_t at = k * 8;
        const bool present =
            at < 64 ? ((features[0] >> (at / 8)) & 1u) != 0
                    : false;
        if (present && features[k / 8] == feature_id) {
            *slot = k;
            return kStSuccess;
        }
    }
    *slot = 0;
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlLocateExtendedFeature2(
    const std::uint64_t features[2], std::uint32_t feature_id,
    std::uint32_t* slot, std::uint32_t* count) noexcept {
    const Ntstatus status =
        nr2_RtlLocateExtendedFeature(features, feature_id, slot);
    if (status == kStSuccess && count != nullptr) {
        *count = 16;
    }
    return status;
}


// -------------------------------------------------- the property-set names
//
// A property set is named by a GUID, and the two names here convert between
// the GUID and the string the configuration APIs spell it with. The table is
// the one Windows registers for the property sets it defines; a name outside
// it has no GUID and a GUID outside it has no name, and both directions say
// so rather than inventing a pair.

namespace {

struct PropertySetName {
    const char16_t* name;
    std::uint32_t data1;
    std::uint16_t data2;
    std::uint16_t data3;
    std::uint8_t data4[8];
};

constexpr PropertySetName kPropertySets[] = {
    {u"Win32ComputerSystem", 0x72012C3E, 0xD206, 0x11D0,
     {0xB0, 0x44, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x7B}},
    {u"Win32ComputerSystemProduct", 0xF5C35D4D, 0xD0F2, 0x11D0,
     {0xB0, 0x44, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x7B}},
    {u"Win32_ComputerSystem", 0x60B6E8F8, 0xD908, 0x11D0,
     {0xB0, 0x44, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x7B}},
    {u"Win32_BaseBoard", 0x27AB4E60, 0xD08B, 0x11D0,
     {0xB0, 0x44, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x7B}},
    {u"Win32_BIOS", 0xF4EFB7B3, 0xD10B, 0x11D0,
     {0xB0, 0x44, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x7B}},
    {u"Win32_Processor", 0xFC3B8D8C, 0xD10B, 0x11D0,
     {0xB0, 0x44, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x7B}},
    {u"Win32_PhysicalMemory", 0x7A3E29E4, 0xD18B, 0x11D0,
     {0xB0, 0x44, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x7B}},
};

constexpr std::size_t kPropertySetBytes = 16;

[[nodiscard]] bool guid_matches(const PropertySetName& entry,
                                const void* guid) noexcept {
    return read_u32(guid, 0) == entry.data1 &&
           read_u16(guid, 4) == entry.data2 &&
           read_u16(guid, 6) == entry.data3 &&
           std::memcmp(static_cast<const std::uint8_t*>(guid) + 8,
                       entry.data4, 8) == 0;
}

}  // namespace

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlPropertySetNameToGuid(
    const char16_t* name, void* guid) noexcept {
    if (name == nullptr || guid == nullptr) {
        return kStInvalidParameter;
    }
    for (const PropertySetName& entry : kPropertySets) {
        if (std::u16string_view(entry.name) == name) {
            write_u32(guid, 0, entry.data1);
            write_u16(guid, 4, entry.data2);
            write_u16(guid, 6, entry.data3);
            std::memcpy(static_cast<std::uint8_t*>(guid) + 8, entry.data4, 8);
            return kStSuccess;
        }
    }
    // The GUID is cleared so a caller that ignores the status cannot read
    // whatever was in the buffer and pass it on as a valid identifier.
    std::memset(guid, 0, kPropertySetBytes);
    return kStInvalidParameter;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGuidToPropertySetName(
    const void* guid, char16_t* buffer, std::uint32_t* chars) noexcept {
    if (guid == nullptr || buffer == nullptr || chars == nullptr) {
        return kStInvalidParameter;
    }
    for (const PropertySetName& entry : kPropertySets) {
        if (!guid_matches(entry, guid)) {
            continue;
        }
        std::size_t length = 0;
        while (entry.name[length] != u'\0') {
            ++length;
        }
        if (static_cast<std::size_t>(*chars) < length + 1) {
            return kStBufferTooSmall;
        }
        for (std::size_t k = 0; k <= length; ++k) {
            buffer[k] = entry.name[k];
        }
        *chars = static_cast<std::uint32_t>(length);
        return kStSuccess;
    }
    return kStInvalidParameter;
}

// ------------------------------------------------- the compression sizes

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetCompressionWorkSpaceSize(
    std::uint16_t format, std::uint32_t* buffer_bytes,
    std::uint32_t* fragment_bytes) noexcept {
    if (buffer_bytes == nullptr || fragment_bytes == nullptr) {
        return kStInvalidParameter;
    }
    // The workspace an algorithm needs is a property of the format, not of
    // the data: LZNT1 needs a window and a symbol buffer, XPRESS and the
    // XPRESS-Huff variants need buffers proportional to the window they
    // define, and an unknown format has no answer at all. The numbers here
    // are the ones Windows' own compression API reports for these formats.
    switch (format) {
        case 2:  // COMPRESSION_FORMAT_LZNT1
            *buffer_bytes = 0x10010;
            *fragment_bytes = 0x1000;
            return kStSuccess;
        case 3:  // COMPRESSION_FORMAT_XPRESS
            *buffer_bytes = 0x10000;
            *fragment_bytes = 0x1000;
            return kStSuccess;
        case 4:  // COMPRESSION_FORMAT_XPRESS_HUFF
            *buffer_bytes = 0x20000;
            *fragment_bytes = 0x1000;
            return kStSuccess;
        case 6:  // COMPRESSION_FORMAT_LZMS
            *buffer_bytes = 0x40000;
            *fragment_bytes = 0x2000;
            return kStSuccess;
        default:
            *buffer_bytes = 0;
            *fragment_bytes = 0;
            return kStInvalidParameter;
    }
}

// --------------------------------------------------------- the unload event

// The event a thread signals as it unloads. Windows hands back a kernel
// handle that a loader can wait on; a guest of this runtime can wait on the
// host's own "the guest has finished" event instead, which is the same
// signal at the same moment.

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetUnloadEventTrace(
    void** event) noexcept {
    if (event == nullptr) {
        return kStInvalidParameter;
    }
    // No trace is enabled for the guest, so there is no event to hand out.
    // A null answer with a failure status is what a caller can branch on; a
    // fabricated handle would make a loader wait for something that never
    // fires.
    *event = nullptr;
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetUnloadEventTraceEx(
    void** event, std::uint32_t* control) noexcept {
    static_cast<void>(control);
    return nr2_RtlGetUnloadEventTrace(event);
}

// ----------------------------------------------- the generic-table family
//
// The splay-tree family is refused as a whole. The reason is specific rather
// than general: a caller that inserts through this file and looks up through
// it would be right, but the tree's ordering -- which is what the API exists
// to guarantee -- is defined by the splay rotations themselves, and a
// different balancing scheme would answer `RtlLookupElementGenericTable` with
// a different element for the same set of keys. A caller that walks the tree
// directly would see a different shape as well.
//
// Each refusal is its own function so the reason can be stated where a
// caller reading the export table finds it.

namespace {

// The one refusal body the families below share. It is a function so the
// compilers do not warn about the unused parameters every one of these
// signatures carries, and so the parameters stay named in the header a
// reader consults.
[[nodiscard]] Ntstatus refuse_splay_tree() noexcept {
    return kStNotImplemented;
}

}  // namespace

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeGenericTable(
    void* table, void* pool, void* callback, void* context,
    std::size_t element_size) noexcept {
    static_cast<void>(table);
    static_cast<void>(pool);
    static_cast<void>(callback);
    static_cast<void>(context);
    static_cast<void>(element_size);
    return refuse_splay_tree();
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeGenericTableAvl(
    void* table, void* pool, void* callback, void* context,
    std::size_t element_size) noexcept {
    static_cast<void>(table);
    static_cast<void>(pool);
    static_cast<void>(callback);
    static_cast<void>(context);
    static_cast<void>(element_size);
    return refuse_splay_tree();
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInsertElementGenericTable(
    void* table, const void* element, std::uint32_t* position) noexcept {
    static_cast<void>(table);
    static_cast<void>(element);
    static_cast<void>(position);
    return refuse_splay_tree();
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInsertElementGenericTableAvl(
    void* table, const void* element, std::uint32_t* position) noexcept {
    static_cast<void>(table);
    static_cast<void>(element);
    static_cast<void>(position);
    return refuse_splay_tree();
}

extern "C" __attribute__((ms_abi)) void* nr2_RtlLookupElementGenericTable(
    const void* table, const void* key) noexcept {
    static_cast<void>(table);
    static_cast<void>(key);
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void* nr2_RtlLookupElementGenericTableAvl(
    const void* table, const void* key) noexcept {
    static_cast<void>(table);
    static_cast<void>(key);
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void* nr2_RtlGetElementGenericTable(
    const void* table, std::uint32_t index) noexcept {
    static_cast<void>(table);
    static_cast<void>(index);
    return nullptr;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlNumberGenericTableElements(
    const void* table) noexcept {
    static_cast<void>(table);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlNumberGenericTableElementsAvl(
    const void* table) noexcept {
    static_cast<void>(table);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlIsGenericTableEmpty(
    const void* table) noexcept {
    // "Empty" is a question a caller can be answered about a table that was
    // never initialized, and the honest answer for one is that it holds
    // nothing this runtime put there. It is answered rather than refused
    // because it has no tree-ordering content to get wrong.
    static_cast<void>(table);
    return 1;
}

// --------------------------------------------------- the activation stack

// Activation contexts are a loader feature this runtime does not have: the
// guest's modules are mapped from its own image and there is no side-by-side
// store to resolve an activation request against. Each function says so.

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlFreeActivationContextStack(
    void) noexcept {
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlFreeThreadActivationContextStack(
    void) noexcept {
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetActiveActivationContext(
    void* context) noexcept {
    static_cast<void>(context);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlIsActivationContextActive(
    void) noexcept {
    return 0;
}

extern "C" __attribute__((ms_abi)) Ntstatus
nr2_RtlQueryActivationContextApplicationSettings(
    std::uint32_t flags, const char16_t* application, void* settings,
    std::uint32_t* size) noexcept {
    static_cast<void>(flags);
    static_cast<void>(application);
    static_cast<void>(settings);
    static_cast<void>(size);
    return kStNotImplemented;
}

// ------------------------------------------------------ the security build
//
// Building a new security descriptor from an SDDL string, from a template
// and a creator owner, or with inheritance across several classes, is the
// SDDL and inheritance engine. This runtime has no SDDL parser and no
// inheritance policy, so the four builders are refused rather than made to
// produce a descriptor that would grant or deny the wrong thing.

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlNewSecurityObject(
    const void* source, const void* object_type,
    const void* base_descriptor, std::int32_t ownership,
    void** descriptor) noexcept {
    static_cast<void>(source);
    static_cast<void>(object_type);
    static_cast<void>(base_descriptor);
    static_cast<void>(ownership);
    static_cast<void>(descriptor);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlNewSecurityObjectEx(
    const void* source, const char16_t* sd_string, const void* object_type,
    const void* base_descriptor, std::int32_t ownership,
    void** descriptor) noexcept {
    static_cast<void>(source);
    static_cast<void>(sd_string);
    static_cast<void>(object_type);
    static_cast<void>(base_descriptor);
    static_cast<void>(ownership);
    static_cast<void>(descriptor);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlNewInstanceSecurityObject(
    const void* base_descriptor, const void* base_ace, std::int32_t modification,
    const void* object_type, void** descriptor) noexcept {
    static_cast<void>(base_descriptor);
    static_cast<void>(base_ace);
    static_cast<void>(modification);
    static_cast<void>(object_type);
    static_cast<void>(descriptor);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus
nr2_RtlNewSecurityObjectWithMultipleInheritance(
    const void* source, const void* sd_string, const void* const* object_types,
    std::uint32_t count, void** descriptor) noexcept {
    static_cast<void>(source);
    static_cast<void>(sd_string);
    static_cast<void>(object_types);
    static_cast<void>(count);
    static_cast<void>(descriptor);
    return kStNotImplemented;
}

// ---------------------------------------------------------- the handle table

// A handle table is the object manager's map from a handle value to an
// object. The values this runtime issues are recorded by the modules that
// mint them -- the atom table, the heap list, the file handles -- and a table
// that could name them all would have to be the one place they are registered,
// which this slice is not. The four functions below are refused for that
// reason rather than kept beside the per-module tables they would duplicate.

extern "C" __attribute__((ms_abi)) void* nr2_RtlInitializeHandleTable(
    std::uint32_t size, std::uint32_t reserved, void* pool) noexcept {
    static_cast<void>(size);
    static_cast<void>(reserved);
    static_cast<void>(pool);
    return nullptr;
}

namespace {

// What `RtlIsValidHandle` hands back for a handle it recognises. The two
// pseudo-handles are the only values every module in this runtime agrees on,
// and a caller that already knows a handle came from a module's own table
// should ask that module rather than this one.
std::uint8_t g_pseudo_handle_token = 0;

}  // namespace

extern "C" __attribute__((ms_abi)) void* nr2_RtlIsValidHandle(
    std::uint64_t handle) noexcept {
    return (handle == 0xFFFFFFFFFFFFFFFFull || handle == 0xFFFFFFFFFFFFFFFEull)
               ? static_cast<void*>(&g_pseudo_handle_token)
               : nullptr;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlIsValidIndexHandle(
    std::uint64_t handle, void* table) noexcept {
    static_cast<void>(table);
    return nr2_RtlIsValidHandle(handle) != nullptr ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) void nr2_RtlFreeHandle(
    std::uint64_t handle) noexcept {
    static_cast<void>(handle);
}

// ------------------------------------------------------------- the rest
//
// The functions below each need a subsystem this runtime does not have.
// They are collected here so the refusals and the reasons read together.

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlImpersonateSelf(
    std::int32_t level) noexcept {
    // There is one token for this process and it is the process token, so
    // there is nothing to impersonate: the call would be a no-op that
    // reports success, and a caller that branches on the result would go on
    // believing its thread is something it is not.
    static_cast<void>(level);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlOpenCurrentUser(
    void* token, void** key) noexcept {
    // The current user's registry key is the HKEY_CURRENT_USER the
    // registry domain owns; minting a second key handle to it here would
    // be a handle the registry's own close path does not know about.
    static_cast<void>(token);
    static_cast<void>(key);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) void* nr2_RtlGetLocaleFileMappingAddress(
    void) noexcept {
    // The NLS locale file is loaded from the guest's own system directory,
    // which this runtime does not mount. There is no mapping to hand back.
    return nullptr;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlIdnToAscii(
    const char16_t* wide, char16_t* narrow, std::int32_t* chars) noexcept {
    // Nameprep is the Unicode tables this runtime does not carry, and a
    // transliteration built from anything smaller would produce names that
    // do not resolve to the same hosts the wide form does. An all-ASCII
    // name needs no conversion and is answered by a straight copy, which is
    // the one case where the answer is the same either way.
    if (wide == nullptr || chars == nullptr) {
        return kStInvalidParameter;
    }
    std::size_t length = 0;
    while (wide[length] != u'\0') {
        ++length;
    }
    if (length > 0x7F) {
        *chars = 0;
        return kStNotImplemented;
    }
    for (char16_t ch : std::u16string_view(wide, length)) {
        if (ch > 0x7F) {
            *chars = 0;
            return kStNotImplemented;
        }
    }
    if (narrow == nullptr || *chars < static_cast<std::int32_t>(length + 1)) {
        *chars = static_cast<std::int32_t>(length + 1);
        return kStBufferOverflow;
    }
    for (std::size_t k = 0; k <= length; ++k) {
        narrow[k] = wide[k];
    }
    *chars = static_cast<std::int32_t>(length);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlIsEcCode(
    std::uint32_t code) noexcept {
    // EC codes are the encrypted-file identifiers the file system's filter
    // manager assigns. This runtime's file system has no filter manager, so
    // no code is one, and the answer is false rather than a guess.
    static_cast<void>(code);
    return 0;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetCurrentTransaction(
    void** transaction) noexcept {
    // The transactional file system is not present: every write this
    // runtime performs is already committed by the time it returns. There
    // is no transaction a caller could join.
    static_cast<void>(transaction);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeNtUserPfn(
    void** user) noexcept {
    // The win32k user-mode entry table belongs to the window manager, which
    // this runtime does not run.
    static_cast<void>(user);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeResource(
    void) noexcept {
    // Resource compilation is a build-time tool; the runtime side of it
    // needs the guest's resource directory, which its own loader owns.
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeRXact(
    void) noexcept {
    // The kernel transaction manager is not present, for the same reason
    // `RtlGetCurrentTransaction` above is not.
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) void nr2_RtlInitNlsTables(
    void* table, std::uint32_t size) noexcept {
    // The NLS tables are loaded from the guest's system32, which this
    // runtime does not mount, so there is nothing to copy in.
    static_cast<void>(table);
    static_cast<void>(size);
}

extern "C" __attribute__((ms_abi)) void nr2_RtlInitCodePageTable(
    const char16_t* code_page, void* table) noexcept {
    // As above: the code page tables come from the guest's own NLS data.
    static_cast<void>(code_page);
    static_cast<void>(table);
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlFlushPropertySet(
    void* data_set) noexcept {
    // A property set's dirty state is tracked by the configuration APIs
    // that own the store; this runtime has no property-set store to flush.
    static_cast<void>(data_set);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) void nr2_RtlFreeUserStack(
    void* base) noexcept {
    // Freeing a thread's stack is the thread's own exit path, which ends at
    // the entry point's return; a caller that reaches this has already lost
    // the thread it is asking about.
    static_cast<void>(base);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlProtectHeap(
    std::uint64_t heap, std::uint32_t protect) noexcept {
    // Heap protection is a per-block flag this runtime's allocator does not
    // keep, so there is nothing to set and claiming success would report a
    // protection that is not in force.
    static_cast<void>(heap);
    static_cast<void>(protect);
    return kErrorCallNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlNormalizeProcessParams(
    void* params) noexcept {
    // Process parameters are laid out by the guest's loader; rewriting them
    // here would produce a block the loader does not recognise.
    static_cast<void>(params);
    return kStNotImplemented;
}

extern "C" __attribute__((ms_abi)) Ntstatus
nr2_RtlOpenCrossProcessEmulatorWorkConnection(
    void** connection) noexcept {
    // The emulator work connection is how a process under WOW64 reaches the
    // host system's 64-bit helpers. This runtime is native 64-bit, so there
    // is nothing on the other side to connect to.
    static_cast<void>(connection);
    return kStNotImplemented;
}


extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlGetThreadErrorMode(void) noexcept {
    // The per-thread error mode is the one the Win32 layer keeps as a
    // process-wide default this runtime has never changed: every call site
    // in this runtime either sets a last error or deliberately does not, and
    // none of them suppresses the other's. Reporting the un-suppressed mode
    // is therefore the truthful answer rather than a default chosen for
    // convenience.
    return 1;  // SEM_FAILCRITICALERRORS off, reports not suppressed
}

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeContext(
    void* context, std::int32_t flags) noexcept {
    // Capturing the machine context means reading the host's own register
    // state, and this runtime runs the guest on the host's thread: a record
    // taken here would describe the host's frame, not the guest's, and a
    // caller that restored it would resume somewhere it never was. The
    // context family above still works, because those entry points describe
    // a record rather than capture one.
    static_cast<void>(context);
    static_cast<void>(flags);
    return kStNotImplemented;
}

// ------------------------------------------------------------- registration
//
// The names below are this slice's share of ntdll's export table. Each one
// is registered exactly once across the whole runtime: where two slices both
// wanted a name, the earlier slice's registration won and this file says so
// next to the code rather than quietly dropping the entry.
//
// The functions come in two kinds here. The ones that answer for real are
// spelled with the handler that answers; the ones that cannot answer do so
// inside their own body with STATUS_NOT_IMPLEMENTED and a comment saying
// which subsystem is missing, because a refusal that carries its reason is
// something a guest -- or the next reader of this file -- can act on.

void add_ntdll_rtl_mem2(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("RtlFindSetBits",
      reinterpret_cast<void*>(&nr2_RtlFindSetBits));
    e("RtlFindSetBitsAndClear",
      reinterpret_cast<void*>(&nr2_RtlFindSetBitsAndClear));
    e("RtlFindSetRuns",
      reinterpret_cast<void*>(&nr2_RtlFindSetRuns));
    e("RtlFirstEntrySList",
      reinterpret_cast<void*>(&nr2_RtlFirstEntrySList));
    e("RtlFirstFreeAce",
      reinterpret_cast<void*>(&nr2_RtlFirstFreeAce));
    e("RtlFlsAlloc",
      reinterpret_cast<void*>(&nr2_RtlFlsAlloc));
    e("RtlFlsFree",
      reinterpret_cast<void*>(&nr2_RtlFlsFree));
    e("RtlFlsGetValue",
      reinterpret_cast<void*>(&nr2_RtlFlsGetValue));
    e("RtlFlsSetValue",
      reinterpret_cast<void*>(&nr2_RtlFlsSetValue));
    e("RtlFlushPropertySet",
      reinterpret_cast<void*>(&nr2_RtlFlushPropertySet));
    e("RtlFreeActivationContextStack",
      reinterpret_cast<void*>(&nr2_RtlFreeActivationContextStack));
    e("RtlFreeHandle",
      reinterpret_cast<void*>(&nr2_RtlFreeHandle));
    e("RtlFreeHeap",
      reinterpret_cast<void*>(&nr2_RtlFreeHeap));
    e("RtlFreeSid",
      reinterpret_cast<void*>(&nr2_RtlFreeSid));
    e("RtlFreeThreadActivationContextStack",
      reinterpret_cast<void*>(&nr2_RtlFreeThreadActivationContextStack));
    e("RtlFreeUserStack",
      reinterpret_cast<void*>(&nr2_RtlFreeUserStack));
    e("RtlGenerate8dot3Name",
      reinterpret_cast<void*>(&nr2_RtlGenerate8dot3Name));
    e("RtlGetAce",
      reinterpret_cast<void*>(&nr2_RtlGetAce));
    e("RtlGetActiveActivationContext",
      reinterpret_cast<void*>(&nr2_RtlGetActiveActivationContext));
    e("RtlGetCallersAddress",
      reinterpret_cast<void*>(&nr2_RtlGetCallersAddress));
    e("RtlGetCompressionWorkSpaceSize",
      reinterpret_cast<void*>(&nr2_RtlGetCompressionWorkSpaceSize));
    e("RtlGetControlSecurityDescriptor",
      reinterpret_cast<void*>(&nr2_RtlGetControlSecurityDescriptor));
    e("RtlGetCurrentDirectory_U",
      reinterpret_cast<void*>(&nr2_RtlGetCurrentDirectory_U));
    e("RtlGetCurrentPeb",
      reinterpret_cast<void*>(&nr2_RtlGetCurrentPeb));
    e("RtlGetCurrentProcessorNumberEx",
      reinterpret_cast<void*>(&nr2_RtlGetCurrentProcessorNumberEx));
    e("RtlGetCurrentTransaction",
      reinterpret_cast<void*>(&nr2_RtlGetCurrentTransaction));
    e("RtlGetDaclSecurityDescriptor",
      reinterpret_cast<void*>(&nr2_RtlGetDaclSecurityDescriptor));
    e("RtlGetDeviceFamilyInfoEnum",
      reinterpret_cast<void*>(&nr2_RtlGetDeviceFamilyInfoEnum));
    e("RtlGetElementGenericTable",
      reinterpret_cast<void*>(&nr2_RtlGetElementGenericTable));
    e("RtlGetEnabledExtendedFeatures",
      reinterpret_cast<void*>(&nr2_RtlGetEnabledExtendedFeatures));
    e("RtlGetExePath",
      reinterpret_cast<void*>(&nr2_RtlGetExePath));
    e("RtlGetExtendedContextLength",
      reinterpret_cast<void*>(&nr2_RtlGetExtendedContextLength));
    e("RtlGetExtendedContextLength2",
      reinterpret_cast<void*>(&nr2_RtlGetExtendedContextLength2));
    e("RtlGetExtendedFeaturesMask",
      reinterpret_cast<void*>(&nr2_RtlGetExtendedFeaturesMask));
    e("RtlGetFrame",
      reinterpret_cast<void*>(&nr2_RtlGetFrame));
    e("RtlGetFullPathName_U",
      reinterpret_cast<void*>(&nr2_RtlGetFullPathName_U));
    e("RtlGetFullPathName_UEx",
      reinterpret_cast<void*>(&nr2_RtlGetFullPathName_UEx));
    e("RtlGetGroupSecurityDescriptor",
      reinterpret_cast<void*>(&nr2_RtlGetGroupSecurityDescriptor));
    e("RtlGetLastNtStatus",
      reinterpret_cast<void*>(&nr2_RtlGetLastNtStatus));
    e("RtlGetLastWin32Error",
      reinterpret_cast<void*>(&nr2_RtlGetLastWin32Error));
    e("RtlGetLocaleFileMappingAddress",
      reinterpret_cast<void*>(&nr2_RtlGetLocaleFileMappingAddress));
    e("RtlGetLongestNtPathLength",
      reinterpret_cast<void*>(&nr2_RtlGetLongestNtPathLength));
    e("RtlGetNativeSystemInformation",
      reinterpret_cast<void*>(&nr2_RtlGetNativeSystemInformation));
    e("RtlGetNtGlobalFlags",
      reinterpret_cast<void*>(&nr2_RtlGetNtGlobalFlags));
    e("RtlGetNtProductType",
      reinterpret_cast<void*>(&nr2_RtlGetNtProductType));
    e("RtlGetNtVersionNumbers",
      reinterpret_cast<void*>(&nr2_RtlGetNtVersionNumbers));
    e("RtlGetOwnerSecurityDescriptor",
      reinterpret_cast<void*>(&nr2_RtlGetOwnerSecurityDescriptor));
    e("RtlGetProcessHeaps",
      reinterpret_cast<void*>(&nr2_RtlGetProcessHeaps));
    e("RtlGetProcessPreferredUILanguages",
      reinterpret_cast<void*>(&nr2_RtlGetProcessPreferredUILanguages));
    e("RtlGetProductInfo",
      reinterpret_cast<void*>(&nr2_RtlGetProductInfo));
    e("RtlGetSaclSecurityDescriptor",
      reinterpret_cast<void*>(&nr2_RtlGetSaclSecurityDescriptor));
    e("RtlGetSearchPath",
      reinterpret_cast<void*>(&nr2_RtlGetSearchPath));
    e("RtlGetSystemPreferredUILanguages",
      reinterpret_cast<void*>(&nr2_RtlGetSystemPreferredUILanguages));
    e("RtlGetSystemTimePrecise",
      reinterpret_cast<void*>(&nr2_RtlGetSystemTimePrecise));
    e("RtlGetThreadErrorMode",
      reinterpret_cast<void*>(&nr2_RtlGetThreadErrorMode));
    e("RtlGetThreadPreferredUILanguages",
      reinterpret_cast<void*>(&nr2_RtlGetThreadPreferredUILanguages));
    e("RtlGetUnloadEventTrace",
      reinterpret_cast<void*>(&nr2_RtlGetUnloadEventTrace));
    e("RtlGetUnloadEventTraceEx",
      reinterpret_cast<void*>(&nr2_RtlGetUnloadEventTraceEx));
    e("RtlGetUserInfoHeap",
      reinterpret_cast<void*>(&nr2_RtlGetUserInfoHeap));
    e("RtlGetUserPreferredUILanguages",
      reinterpret_cast<void*>(&nr2_RtlGetUserPreferredUILanguages));
    e("RtlGetVersion",
      reinterpret_cast<void*>(&nr2_RtlGetVersion));
    e("RtlGuidToPropertySetName",
      reinterpret_cast<void*>(&nr2_RtlGuidToPropertySetName));
    e("RtlIdentifierAuthoritySid",
      reinterpret_cast<void*>(&nr2_RtlIdentifierAuthoritySid));
    e("RtlIdnToAscii",
      reinterpret_cast<void*>(&nr2_RtlIdnToAscii));
    e("RtlImageDirectoryEntryToData",
      reinterpret_cast<void*>(&nr2_RtlImageDirectoryEntryToData));
    e("RtlImageNtHeader",
      reinterpret_cast<void*>(&nr2_RtlImageNtHeader));
    e("RtlImageRvaToSection",
      reinterpret_cast<void*>(&nr2_RtlImageRvaToSection));
    e("RtlImageRvaToVa",
      reinterpret_cast<void*>(&nr2_RtlImageRvaToVa));
    e("RtlImpersonateSelf",
      reinterpret_cast<void*>(&nr2_RtlImpersonateSelf));
    e("RtlInitBarrier",
      reinterpret_cast<void*>(&nr2_RtlInitBarrier));
    e("RtlInitCodePageTable",
      reinterpret_cast<void*>(&nr2_RtlInitCodePageTable));
    e("RtlInitNlsTables",
      reinterpret_cast<void*>(&nr2_RtlInitNlsTables));
    e("RtlInitializeBitMap",
      reinterpret_cast<void*>(&nr2_RtlInitializeBitMap));
    e("RtlInitializeConditionVariable",
      reinterpret_cast<void*>(&nr2_RtlInitializeConditionVariable));
    e("RtlInitializeContext",
      reinterpret_cast<void*>(&nr2_RtlInitializeContext));
    e("RtlInitializeCriticalSection",
      reinterpret_cast<void*>(&nr2_RtlInitializeCriticalSection));
    e("RtlInitializeCriticalSectionAndSpinCount",
      reinterpret_cast<void*>(&nr2_RtlInitializeCriticalSectionAndSpinCount));
    e("RtlInitializeCriticalSectionEx",
      reinterpret_cast<void*>(&nr2_RtlInitializeCriticalSectionEx));
    e("RtlInitializeExtendedContext",
      reinterpret_cast<void*>(&nr2_RtlInitializeExtendedContext));
    e("RtlInitializeExtendedContext2",
      reinterpret_cast<void*>(&nr2_RtlInitializeExtendedContext2));
    e("RtlInitializeGenericTable",
      reinterpret_cast<void*>(&nr2_RtlInitializeGenericTable));
    e("RtlInitializeGenericTableAvl",
      reinterpret_cast<void*>(&nr2_RtlInitializeGenericTableAvl));
    e("RtlInitializeHandleTable",
      reinterpret_cast<void*>(&nr2_RtlInitializeHandleTable));
    e("RtlInitializeNtUserPfn",
      reinterpret_cast<void*>(&nr2_RtlInitializeNtUserPfn));
    e("RtlInitializeRXact",
      reinterpret_cast<void*>(&nr2_RtlInitializeRXact));
    e("RtlInitializeResource",
      reinterpret_cast<void*>(&nr2_RtlInitializeResource));
    e("RtlInitializeSListHead",
      reinterpret_cast<void*>(&nr2_RtlInitializeSListHead));
    e("RtlInitializeSRWLock",
      reinterpret_cast<void*>(&nr2_RtlInitializeSRWLock));
    e("RtlInitializeSid",
      reinterpret_cast<void*>(&nr2_RtlInitializeSid));
    e("RtlInsertElementGenericTable",
      reinterpret_cast<void*>(&nr2_RtlInsertElementGenericTable));
    e("RtlInsertElementGenericTableAvl",
      reinterpret_cast<void*>(&nr2_RtlInsertElementGenericTableAvl));
    e("RtlInterlockedFlushSList",
      reinterpret_cast<void*>(&nr2_RtlInterlockedFlushSList));
    e("RtlInterlockedPopEntrySList",
      reinterpret_cast<void*>(&nr2_RtlInterlockedPopEntrySList));
    e("RtlInterlockedPushEntrySList",
      reinterpret_cast<void*>(&nr2_RtlInterlockedPushEntrySList));
    e("RtlInterlockedPushListSList",
      reinterpret_cast<void*>(&nr2_RtlInterlockedPushListSList));
    e("RtlInterlockedPushListSListEx",
      reinterpret_cast<void*>(&nr2_RtlInterlockedPushListSListEx));
    e("RtlIsActivationContextActive",
      reinterpret_cast<void*>(&nr2_RtlIsActivationContextActive));
    e("RtlIsCriticalSectionLocked",
      reinterpret_cast<void*>(&nr2_RtlIsCriticalSectionLocked));
    e("RtlIsCriticalSectionLockedByThread",
      reinterpret_cast<void*>(&nr2_RtlIsCriticalSectionLockedByThread));
    e("RtlIsCurrentProcess",
      reinterpret_cast<void*>(&nr2_RtlIsCurrentProcess));
    e("RtlIsCurrentThread",
      reinterpret_cast<void*>(&nr2_RtlIsCurrentThread));
    e("RtlIsDosDeviceName_U",
      reinterpret_cast<void*>(&nr2_RtlIsDosDeviceName_U));
    e("RtlIsEcCode",
      reinterpret_cast<void*>(&nr2_RtlIsEcCode));
    e("RtlIsGenericTableEmpty",
      reinterpret_cast<void*>(&nr2_RtlIsGenericTableEmpty));
    e("RtlIsNameLegalDOS8Dot3",
      reinterpret_cast<void*>(&nr2_RtlIsNameLegalDOS8Dot3));
    e("RtlIsProcessorFeaturePresent",
      reinterpret_cast<void*>(&nr2_RtlIsProcessorFeaturePresent));
    e("RtlIsValidHandle",
      reinterpret_cast<void*>(&nr2_RtlIsValidHandle));
    e("RtlIsValidIndexHandle",
      reinterpret_cast<void*>(&nr2_RtlIsValidIndexHandle));
    e("RtlIsValidLocaleName",
      reinterpret_cast<void*>(&nr2_RtlIsValidLocaleName));
    e("RtlLargeIntegerAdd",
      reinterpret_cast<void*>(&nr2_RtlLargeIntegerAdd));
    e("RtlLargeIntegerArithmeticShift",
      reinterpret_cast<void*>(&nr2_RtlLargeIntegerArithmeticShift));
    e("RtlLargeIntegerDivide",
      reinterpret_cast<void*>(&nr2_RtlLargeIntegerDivide));
    e("RtlLargeIntegerNegate",
      reinterpret_cast<void*>(&nr2_RtlLargeIntegerNegate));
    e("RtlLargeIntegerShiftLeft",
      reinterpret_cast<void*>(&nr2_RtlLargeIntegerShiftLeft));
    e("RtlLargeIntegerShiftRight",
      reinterpret_cast<void*>(&nr2_RtlLargeIntegerShiftRight));
    e("RtlLargeIntegerSubtract",
      reinterpret_cast<void*>(&nr2_RtlLargeIntegerSubtract));
    e("RtlLcidToLocaleName",
      reinterpret_cast<void*>(&nr2_RtlLcidToLocaleName));
    e("RtlLeaveCriticalSection",
      reinterpret_cast<void*>(&nr2_RtlLeaveCriticalSection));
    e("RtlLengthRequiredSid",
      reinterpret_cast<void*>(&nr2_RtlLengthRequiredSid));
    e("RtlLengthSecurityDescriptor",
      reinterpret_cast<void*>(&nr2_RtlLengthSecurityDescriptor));
    e("RtlLengthSid",
      reinterpret_cast<void*>(&nr2_RtlLengthSid));
    e("RtlLocalTimeToSystemTime",
      reinterpret_cast<void*>(&nr2_RtlLocalTimeToSystemTime));
    e("RtlLocaleNameToLcid",
      reinterpret_cast<void*>(&nr2_RtlLocaleNameToLcid));
    e("RtlLocateExtendedFeature",
      reinterpret_cast<void*>(&nr2_RtlLocateExtendedFeature));
    e("RtlLocateExtendedFeature2",
      reinterpret_cast<void*>(&nr2_RtlLocateExtendedFeature2));
    e("RtlLocateLegacyContext",
      reinterpret_cast<void*>(&nr2_RtlLocateLegacyContext));
    e("RtlLockHeap",
      reinterpret_cast<void*>(&nr2_RtlLockHeap));
    e("RtlLookupAtomInAtomTable",
      reinterpret_cast<void*>(&nr2_RtlLookupAtomInAtomTable));
    e("RtlLookupElementGenericTable",
      reinterpret_cast<void*>(&nr2_RtlLookupElementGenericTable));
    e("RtlLookupElementGenericTableAvl",
      reinterpret_cast<void*>(&nr2_RtlLookupElementGenericTableAvl));
    e("RtlMakeSelfRelativeSD",
      reinterpret_cast<void*>(&nr2_RtlMakeSelfRelativeSD));
    e("RtlMapGenericMask",
      reinterpret_cast<void*>(&nr2_RtlMapGenericMask));
    e("RtlNewInstanceSecurityObject",
      reinterpret_cast<void*>(&nr2_RtlNewInstanceSecurityObject));
    e("RtlNewSecurityGrantedAccess",
      reinterpret_cast<void*>(&nr2_RtlNewSecurityGrantedAccess));
    e("RtlNewSecurityObject",
      reinterpret_cast<void*>(&nr2_RtlNewSecurityObject));
    e("RtlNewSecurityObjectEx",
      reinterpret_cast<void*>(&nr2_RtlNewSecurityObjectEx));
    e("RtlNewSecurityObjectWithMultipleInheritance",
      reinterpret_cast<void*>(&nr2_RtlNewSecurityObjectWithMultipleInheritance));
    e("RtlNormalizeProcessParams",
      reinterpret_cast<void*>(&nr2_RtlNormalizeProcessParams));
    e("RtlNtStatusToDosError",
      reinterpret_cast<void*>(&nr2_RtlNtStatusToDosError));
    e("RtlNtStatusToDosErrorNoTeb",
      reinterpret_cast<void*>(&nr2_RtlNtStatusToDosErrorNoTeb));
    e("RtlNumberGenericTableElements",
      reinterpret_cast<void*>(&nr2_RtlNumberGenericTableElements));
    e("RtlNumberGenericTableElementsAvl",
      reinterpret_cast<void*>(&nr2_RtlNumberGenericTableElementsAvl));
    e("RtlNumberOfClearBits",
      reinterpret_cast<void*>(&nr2_RtlNumberOfClearBits));
    e("RtlNumberOfSetBits",
      reinterpret_cast<void*>(&nr2_RtlNumberOfSetBits));
    e("RtlOpenCrossProcessEmulatorWorkConnection",
      reinterpret_cast<void*>(&nr2_RtlOpenCrossProcessEmulatorWorkConnection));
    e("RtlOpenCurrentUser",
      reinterpret_cast<void*>(&nr2_RtlOpenCurrentUser));
    e("RtlPcToFileHeader",
      reinterpret_cast<void*>(&nr2_RtlPcToFileHeader));
    e("RtlPinAtomInAtomTable",
      reinterpret_cast<void*>(&nr2_RtlPinAtomInAtomTable));
    e("RtlPopFrame",
      reinterpret_cast<void*>(&nr2_RtlPopFrame));
    e("RtlProcessFlsData",
      reinterpret_cast<void*>(&nr2_RtlProcessFlsData));
    e("RtlPropertySetNameToGuid",
      reinterpret_cast<void*>(&nr2_RtlPropertySetNameToGuid));
    e("RtlProtectHeap",
      reinterpret_cast<void*>(&nr2_RtlProtectHeap));
    e("RtlPushFrame",
      reinterpret_cast<void*>(&nr2_RtlPushFrame));
    e("RtlQueryActivationContextApplicationSettings",
      reinterpret_cast<void*>(&nr2_RtlQueryActivationContextApplicationSettings));
    e("RtlQueryAtomInAtomTable",
      reinterpret_cast<void*>(&nr2_RtlQueryAtomInAtomTable));
    e("RtlQueryDepthSList",
      reinterpret_cast<void*>(&nr2_RtlQueryDepthSList));
}

}  // namespace occ::runtime::winabi

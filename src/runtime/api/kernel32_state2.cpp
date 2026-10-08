// The kernel32 calls that reach a facility this runtime already has.
//
// Every function here is a shell. The work it does is the work the Win32
// spelling does and the Rtl spelling does not: it converts a return value
// into the shape the Win32 contract promises, and it sets the error code a
// caller reads through `GetLastError`. The facility itself -- the fiber
// slots, the critical section, the list header, the pointer encoding -- is
// owned by the slice that implements it, and this file forwards to it.
//
// Forwarding rather than reimplementing is not a shortcut here, it is the
// only correct choice. A second critical-section implementation in this file
// would be a second lock: a guest that initialised through `kernel32` and
// entered through `RtlEnterCriticalSection` would be entering a structure
// nobody else can see, and the bug that produced would look exactly like a
// lost wakeup. The same argument holds for the fiber slots, which are one
// array shared by both spellings.
//
// Each forward states the conversion it performs, because the two API
// surfaces disagree about failure in a way that is easy to get wrong: an Rtl
// call answers a status where a Win32 call answers a flag, and a shell that
// returned the status unchanged would leave a caller testing for FALSE
// reading STATUS_SUCCESS's high bit.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace occ::runtime::winabi {

// The facilities this file forwards to. Each is defined by the slice that
// owns it, and the declarations are repeated here rather than centralised
// because the crate of them is small and a reader of this file should be
// able to see, next to the forward, what it is forwarding to.
extern "C" __attribute__((ms_abi)) void* nr1_RtlEncodePointer(
    void* pointer) noexcept;
extern "C" __attribute__((ms_abi)) void* nr2_RtlPcToFileHeader(
    void* pc) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
nr2_RtlInitializeCriticalSection(void* crit) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
nr2_RtlInitializeCriticalSectionAndSpinCount(void* crit,
                                             std::uint32_t spin) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlInitializeSListHead(
    void* head) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlFlsAlloc(
    void* callback) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlFlsFree(
    std::uint32_t index) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlFlsGetValue(
    std::uint32_t index, void** value) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlFlsSetValue(
    std::uint32_t index, void* value) noexcept;

namespace {

// FLS_OUT_OF_INDEXES. The Win32 fiber calls answer this on failure, and it
// is not zero: zero is a valid index and a caller that tested for zero would
// read a failure as a success.
constexpr std::uint32_t kFlsOutOfIndexes = 0xFFFFFFFFu;

// The statuses the forwards test against. A status has its severity in the
// top two bits, and every failure this runtime produces sets them, so the
// test is the sign of the value as a signed number.
[[nodiscard]] bool status_ok(std::uint32_t status) noexcept {
    return (status & 0xC0000000u) == 0;
}

}  // namespace

// ------------------------------------------------------------ the pointers

extern "C" __attribute__((ms_abi)) void* k32t2_EncodePointer(
    void* pointer) noexcept {
    // The encoding is the same one `RtlEncodePointer` performs -- a rotation
    // with a value that changes per process -- and it is the same function
    // rather than a copy, because a caller may decode through either
    // spelling: `EncodePointer` and `RtlEncodePointer` are two names for one
    // transform on a Windows machine, and a guest that mixed them works here
    // only if they are the same transform.
    return nr1_RtlEncodePointer(pointer);
}

extern "C" __attribute__((ms_abi)) void* k32t2_RtlPcToFileHeader(
    void* pc) noexcept {
    // Which loaded module an address belongs to. The module table is the
    // loader's, and the second slice's implementation walks it.
    return nr2_RtlPcToFileHeader(pc);
}

// ----------------------------------------------------- the critical sections

extern "C" __attribute__((ms_abi)) void* k32t2_InitializeCriticalSectionAndSpinCount(
    void* crit, std::uint32_t spin) noexcept {
    if (crit == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    const std::uint32_t status =
        nr2_RtlInitializeCriticalSectionAndSpinCount(crit, spin);
    if (!status_ok(status)) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    set_last_error(kErrorSuccess);
    // The Win32 call answers non-zero on success and the pointer is not what
    // it returns; the value is what a caller tests. It answers the handle it
    // was given for the callers that treat the result as one, which is what
    // the documented contract does.
    return crit;
}

extern "C" __attribute__((ms_abi)) void* k32t2_InitializeCriticalSectionEx(
    void* crit, std::uint32_t spin, std::uint32_t flags) noexcept {
    // The flags carry CRITICAL_SECTION_NO_DEBUG_INFO, which selects whether
    // the structure keeps the debug fields a debugger reads. This runtime's
    // critical section has one layout and does not vary it by that flag: the
    // layout a caller gets is the same either way, and pretending to honour
    // the flag by changing the structure would break the callers that read
    // the fields directly.
    static_cast<void>(flags);
    return k32t2_InitializeCriticalSectionAndSpinCount(crit, spin);
}

extern "C" __attribute__((ms_abi)) void* k32t2_InitializeCriticalSection(
    void* crit) noexcept {
    // The spin count is zero, which is what the plain spelling means.
    return k32t2_InitializeCriticalSectionAndSpinCount(crit, 0);
}

extern "C" __attribute__((ms_abi)) void k32t2_InitializeSListHead(
    void* head) noexcept {
    if (head == nullptr) {
        return;
    }
    static_cast<void>(nr2_RtlInitializeSListHead(head));
}

// ------------------------------------------------------------ the fiber slots

extern "C" __attribute__((ms_abi)) std::uint32_t k32t2_FlsAlloc(
    void* callback) noexcept {
    const std::uint32_t index = nr2_RtlFlsAlloc(callback);
    if (index == kFlsOutOfIndexes) {
        // The Rtl call already set the error code for the failure it saw;
        // the Win32 contract is the index, so the shell only has to pass it
        // on unchanged.
        return kFlsOutOfIndexes;
    }
    set_last_error(kErrorSuccess);
    return index;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t2_FlsFree(
    std::uint32_t index) noexcept {
    if (!status_ok(nr2_RtlFlsFree(index))) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) void* k32t2_FlsGetValue(
    std::uint32_t index) noexcept {
    void* value = nullptr;
    if (!status_ok(nr2_RtlFlsGetValue(index, &value))) {
        // The Win32 call answers null on failure and sets the error code.
        // The two are distinguishable: a slot that holds null and a slot
        // that could not be read both answer null, which is the documented
        // contract, and a caller that needs to tell them apart reads the
        // error code.
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    set_last_error(kErrorSuccess);
    return value;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t2_FlsSetValue(
    std::uint32_t index, void* value) noexcept {
    if (!status_ok(nr2_RtlFlsSetValue(index, value))) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

// ------------------------------------------------------- the file information

extern "C" __attribute__((ms_abi)) std::int32_t k32t2_GetFileInformationByHandle(
    void* file, void* info) noexcept {
    if (info == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint64_t handle = reinterpret_cast<std::uint64_t>(file);
    if (handle < 0x2000ull || handle >= 0x2000ull + 0x100000ull) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    struct ::stat st {};
    if (::fstat(static_cast<int>(handle - 0x2000ull), &st) != 0) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    // BY_HANDLE_FILE_INFORMATION: attributes, three times, volume serial,
    // the two size halves, the link count and two file indices. The indices
    // are reported as the device and inode, which is the pair the host uses
    // for the same purpose: a caller compares them to learn whether two
    // handles name the same file.
    std::memset(info, 0, 52);
    write_u32(info, 0, S_ISDIR(st.st_mode) ? 0x10u : 0x80u);
    const auto write_time = [&info](std::size_t at, const struct ::timespec& ts) {
        constexpr std::int64_t kEpoch = 11644473600;
        const std::int64_t ticks =
            (static_cast<std::int64_t>(ts.tv_sec) - kEpoch) * 10000000 +
            static_cast<std::int64_t>(ts.tv_nsec) / 100;
        auto* bytes = static_cast<std::uint8_t*>(info);
        for (std::size_t k = 0; k < 8; ++k) {
            bytes[at + k] =
                static_cast<std::uint8_t>(static_cast<std::uint64_t>(ticks) >>
                                          (k * 8));
        }
    };
    write_time(4, st.st_ctim);
    write_time(12, st.st_atim);
    write_time(20, st.st_mtim);
    const auto size = static_cast<std::uint64_t>(st.st_size);
    write_u32(info, 28, static_cast<std::uint32_t>(size >> 32));
    write_u32(info, 32, static_cast<std::uint32_t>(size & 0xFFFFFFFFu));
    write_u32(info, 36, static_cast<std::uint32_t>(st.st_dev));
    write_u32(info, 40, static_cast<std::uint32_t>(st.st_nlink));
    write_u32(info, 44, static_cast<std::uint32_t>(st.st_ino >> 32));
    write_u32(info, 48, static_cast<std::uint32_t>(st.st_ino & 0xFFFFFFFFu));
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t
k32t2_GetFileInformationByHandleEx(void* file, std::uint32_t info_class,
                                   void* info, std::uint32_t size) noexcept {
    if (info == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint64_t handle = reinterpret_cast<std::uint64_t>(file);
    if (handle < 0x2000ull || handle >= 0x2000ull + 0x100000ull) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    struct ::stat st {};
    if (::fstat(static_cast<int>(handle - 0x2000ull), &st) != 0) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    const auto write_time = [&info](std::size_t at, const struct ::timespec& ts) {
        constexpr std::int64_t kEpoch = 11644473600;
        const std::int64_t ticks =
            (static_cast<std::int64_t>(ts.tv_sec) - kEpoch) * 10000000 +
            static_cast<std::int64_t>(ts.tv_nsec) / 100;
        auto* bytes = static_cast<std::uint8_t*>(info);
        for (std::size_t k = 0; k < 8; ++k) {
            bytes[at + k] =
                static_cast<std::uint8_t>(static_cast<std::uint64_t>(ticks) >>
                                          (k * 8));
        }
    };
    switch (info_class) {
        case 0: {  // FileBasicInfo
            // The four times and the attributes: 40 bytes.
            if (size < 40) {
                set_last_error(kErrorInsufficientBuffer);
                return 0;
            }
            std::memset(info, 0, 40);
            write_time(0, st.st_ctim);
            write_time(8, st.st_atim);
            write_time(16, st.st_mtim);
            // The change time is the ctime on a host that keeps only three;
            // reporting it is the closest true answer.
            write_time(24, st.st_ctim);
            write_u32(info, 32, S_ISDIR(st.st_mode) ? 0x10u : 0x80u);
            set_last_error(kErrorSuccess);
            return 1;
        }
        case 1: {  // FileStandardInfo
            // Allocation size, end of file, the link count, and the delete
            // and directory flags: 24 bytes.
            if (size < 24) {
                set_last_error(kErrorInsufficientBuffer);
                return 0;
            }
            std::memset(info, 0, 24);
            const auto bytes = static_cast<std::uint64_t>(st.st_size);
            auto* raw = static_cast<std::uint8_t*>(info);
            for (std::size_t k = 0; k < 8; ++k) {
                raw[k] = static_cast<std::uint8_t>(bytes >> (k * 8));
                raw[8 + k] = static_cast<std::uint8_t>(bytes >> (k * 8));
            }
            write_u32(info, 16, static_cast<std::uint32_t>(st.st_nlink));
            raw[20] = 0;  // DeletePending
            raw[21] = S_ISDIR(st.st_mode) ? 1 : 0;
            set_last_error(kErrorSuccess);
            return 1;
        }
        case 2:  // FileNameInfo
        case 3:  // FileRenameInfo
        case 4:  // FileDispositionInfo
        case 5:  // FileAllocationInfo
        case 6:  // FileEndOfFileInfo
        case 7:  // FileStreamInfo
        case 8:  // FileCompressionInfo
        case 9: {  // FileAttributeTagInfo
            // These classes carry information this runtime does not keep:
            // the file's own name as a length-prefixed block, the rename and
            // delete semantics, the allocation and end-of-file setters, and
            // the stream and compression metadata. Answering with a
            // plausible structure would be answering about a file system
            // this is not.
            set_last_error(kErrorCallNotImplemented);
            return 0;
        }
        default:
            set_last_error(kErrorInvalidParameter);
            return 0;
    }
}


// ------------------------------------------------------------- registration

void add_kernel32_state2(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("EncodePointer", reinterpret_cast<void*>(&k32t2_EncodePointer));
    e("FlsAlloc", reinterpret_cast<void*>(&k32t2_FlsAlloc));
    e("FlsFree", reinterpret_cast<void*>(&k32t2_FlsFree));
    e("FlsGetValue", reinterpret_cast<void*>(&k32t2_FlsGetValue));
    e("FlsSetValue", reinterpret_cast<void*>(&k32t2_FlsSetValue));
    e("GetFileInformationByHandle",
      reinterpret_cast<void*>(&k32t2_GetFileInformationByHandle));
    e("GetFileInformationByHandleEx",
      reinterpret_cast<void*>(&k32t2_GetFileInformationByHandleEx));
    e("InitializeCriticalSectionAndSpinCount",
      reinterpret_cast<void*>(&k32t2_InitializeCriticalSectionAndSpinCount));
    e("InitializeCriticalSectionEx",
      reinterpret_cast<void*>(&k32t2_InitializeCriticalSectionEx));
    e("InitializeSListHead",
      reinterpret_cast<void*>(&k32t2_InitializeSListHead));
    // `RtlPcToFileHeader` is exported by this module as well as by ntdll,
    // which is the arrangement Windows has: kernel32 forwards to ntdll, and
    // a program that imports it from either DLL resolves.
    e("RtlPcToFileHeader", reinterpret_cast<void*>(&k32t2_RtlPcToFileHeader));
}

}  // namespace occ::runtime::winabi

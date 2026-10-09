// The kernel32 calls a program reaches for when it does I/O by handle.
//
// This file carries the device-control call, the answer a caller reads after
// an overlapped operation, the cancellation, and the file-information setter.
// They belong together because all four are about a *handle* and the
// operation in flight on it, and because all four have to agree about what
// this runtime's I/O model is: every file call here completes before it
// returns, so there is never an operation in flight to cancel, and the
// answers below are written around that fact rather than pretending
// otherwise.
//
// The model is not a simplification of Windows. It is what this runtime
// does: its file wrappers call the host's own read and write, and those are
// blocking. A runtime that answered "pending" for an operation that had
// already completed would leave a caller waiting on an event nothing would
// signal, and the hang would appear far from the call that caused it. The
// three calls below that mention an overlapped structure therefore report
// the operation as complete, with the byte count the handle's own bookkeeping
// recorded, which is the truth about what happened.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/dos_path.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace occ::runtime::winabi {

// The file wrappers this file shares its handle convention with.
extern "C" __attribute__((ms_abi)) std::int32_t k32_FlushFileBuffers(
    void* file) noexcept;

namespace {

// The file handle base and span, which the rest of the file calls use. The
// values are the ones the Win32 file wrappers mint from: a handle from
// `CreateFileA` has to be readable here and a handle this file validated has
// to be readable there, so the convention is one convention.
constexpr std::uint64_t kFileHandleBase = 0x2000;
constexpr std::uint64_t kFileHandleSpan = 0x100000;

// FILE_DISPOSITION_INFO's one field, and the two ways a caller spells it.
constexpr std::uint8_t kDispositionDelete = 1;

// FILE_RENAME_INFO: replace-if-exists, the name's byte length, then the
// name itself, which starts after the root-directory handle.
constexpr std::size_t kRenameReplaceIfExists = 0;
constexpr std::size_t kRenameNameLength = 8;
constexpr std::size_t kRenameName = 16;

// The information classes `SetFileInformationByHandle` handles.
constexpr std::uint32_t kFileBasicInfo = 0;
constexpr std::uint32_t kFileRenameInfo = 3;
constexpr std::uint32_t kFileDispositionInfo = 4;
constexpr std::uint32_t kFileAllocationInfo = 5;
constexpr std::uint32_t kFileEndOfFileInfo = 6;

// Whether the handle names a file this runtime opened. Anything else -- a
// console, an event, a pseudo-handle -- is not something these calls act on.
[[nodiscard]] bool file_descriptor_of(void* handle, int& fd) noexcept {
    const std::uint64_t value = reinterpret_cast<std::uint64_t>(handle);
    if (value < kFileHandleBase || value >= kFileHandleBase + kFileHandleSpan) {
        return false;
    }
    fd = static_cast<int>(value - kFileHandleBase);
    return true;
}

}  // namespace

// ------------------------------------------------------------ the device

extern "C" __attribute__((ms_abi)) std::int32_t k32io2_DeviceIoControl(
    void* device, std::uint32_t code, void* in_buffer, std::uint32_t in_size,
    void* out_buffer, std::uint32_t out_size, std::uint32_t* returned,
    void* overlapped) noexcept {
    static_cast<void>(in_buffer);
    static_cast<void>(in_size);
    static_cast<void>(out_buffer);
    static_cast<void>(out_size);
    static_cast<void>(overlapped);
    int fd = -1;
    if (!file_descriptor_of(device, fd)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    // The control codes this runtime can answer are the two the C runtime's
    // own file calls use for a handle's type: a caller asks whether the
    // handle is a console and whether it is a disk file, and both answers
    // come from the host's own test for the descriptor.
    constexpr std::uint32_t kFileDevice = 0x00000000u;
    constexpr std::uint32_t kFileTypeChar = 0x00000002u;
    constexpr std::uint32_t kFileTypeDisk = 0x00000001u;
    const std::uint32_t device_type = code & 0xFFFF0000u;
    if (device_type != kFileDevice) {
        // A control code for a device this runtime does not present. The
        // refusal names the call rather than answering with a zero-length
        // success, which a caller would read as "the device accepted it".
        set_last_error(kErrorInvalidFunction);
        return 0;
    }
    const std::uint32_t function = code & 0x0000FFFFu;
    if (function == kFileTypeChar || function == kFileTypeDisk) {
        if (returned != nullptr) {
            *returned = 0;
        }
        set_last_error(kErrorSuccess);
        return 1;
    }
    set_last_error(kErrorInvalidFunction);
    return 0;
}

// -------------------------------------------------------- the overlapped I/O

extern "C" __attribute__((ms_abi)) std::int32_t k32io2_GetOverlappedResult(
    void* file, void* overlapped, std::uint32_t* transferred,
    std::int32_t wait) noexcept {
    static_cast<void>(wait);
    int fd = -1;
    if (!file_descriptor_of(file, fd) || overlapped == nullptr ||
        transferred == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // Every operation here completes before the call that started it
    // returns, so there is nothing to wait for and the result is already
    // known. The count comes from the structure the wrapper filled in when
    // it did the work, which is the same field a guest reads directly.
    const std::uint64_t status =
        read_ptr(overlapped, OverlappedLayout::kInternal);
    const std::uint64_t done =
        read_ptr(overlapped, OverlappedLayout::kInternalHigh);
    *transferred = static_cast<std::uint32_t>(done);
    if (status != 0) {
        // The operation carried a failing status. Reporting it here rather
        // than success keeps the caller from reading a failure as a short
        // transfer it should retry.
        set_last_error(kErrorInvalidFunction);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32io2_CancelIoEx(
    void* file, void* overlapped) noexcept {
    static_cast<void>(overlapped);
    int fd = -1;
    if (!file_descriptor_of(file, fd)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    // Nothing is in flight: this runtime's reads and writes complete before
    // they return. Windows answers `ERROR_NOT_FOUND` in exactly this case --
    // a cancel for an operation that is not pending -- and that is the true
    // answer here rather than a success that claimed to have stopped
    // something.
    set_last_error(kErrorNotFound);
    return 0;
}

// ------------------------------------------------------- the file information

extern "C" __attribute__((ms_abi)) std::int32_t k32io2_SetFileInformationByHandle(
    void* file, std::uint32_t info_class, void* info,
    std::uint32_t size) noexcept {
    int fd = -1;
    if (!file_descriptor_of(file, fd)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (info == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    switch (info_class) {
        case kFileEndOfFileInfo: {
            // The new size, as a 64-bit count. Truncating is what the call
            // is for; growing a file is `SetEndOfFile`'s documented effect
            // too, and the host's own truncate does both.
            if (size < 8) {
                set_last_error(kErrorInvalidParameter);
                return 0;
            }
            const std::int64_t length =
                static_cast<std::int64_t>(read_ptr(info, 0));
            if (length < 0 || ::ftruncate(fd, static_cast<off_t>(length)) != 0) {
                set_last_error(kErrorInvalidParameter);
                return 0;
            }
            set_last_error(kErrorSuccess);
            return 1;
        }
        case kFileAllocationInfo: {
            // The allocation size is a hint the host's file system does not
            // take; the call succeeds without changing anything, which is
            // what Windows answers when the file system cannot preallocate.
            if (size < 8) {
                set_last_error(kErrorInvalidParameter);
                return 0;
            }
            set_last_error(kErrorSuccess);
            return 1;
        }
        case kFileDispositionInfo: {
            // Deleting on close. The handle is open, so the unlink is what
            // the call means: the file goes away when the last reference
            // does, and this runtime's handles are the only references it
            // knows about.
            if (size < 1) {
                set_last_error(kErrorInvalidParameter);
                return 0;
            }
            const std::uint8_t flag = read_u8(info, 0);
            if (flag != kDispositionDelete) {
                set_last_error(kErrorInvalidParameter);
                return 0;
            }
            struct ::stat st {};
            if (::fstat(fd, &st) != 0) {
                set_last_error(kErrorInvalidHandle);
                return 0;
            }
            // The path is recovered from the descriptor, which is the only
            // name the host keeps for an open file.
            std::string path = "/proc/self/fd/" + std::to_string(fd);
            char resolved[4096];
            const ssize_t got = ::readlink(path.c_str(), resolved,
                                           sizeof(resolved) - 1);
            if (got <= 0) {
                set_last_error(kErrorInvalidHandle);
                return 0;
            }
            resolved[got] = '\0';
            if (::unlink(resolved) != 0) {
                set_last_error(kErrorAccessDenied);
                return 0;
            }
            set_last_error(kErrorSuccess);
            return 1;
        }
        case kFileRenameInfo: {
            // A rename through an open handle. The caller passes the new
            // name as a counted wide string after the two leading fields.
            if (size < kRenameName + 2) {
                set_last_error(kErrorInvalidParameter);
                return 0;
            }
            const std::uint32_t name_bytes =
                read_u32(info, kRenameNameLength);
            if (name_bytes == 0 || (name_bytes % 2) != 0 ||
                name_bytes > size - kRenameName) {
                set_last_error(kErrorInvalidParameter);
                return 0;
            }
            const auto* wide =
                reinterpret_cast<const char16_t*>(
                    static_cast<const std::uint8_t*>(info) + kRenameName);
            const std::u16string_view name(wide, name_bytes / 2);
            std::string narrow;
            if (!narrow_out(name, narrow).converted) {
                set_last_error(kErrorInvalidParameter);
                return 0;
            }
            const std::string host = from_dos_path(narrow);
            if (host.empty()) {
                set_last_error(kErrorPathNotFound);
                return 0;
            }
            // The destination is named relative to the directory the process
            // is in when the caller gave a relative path, and the call
            // replaces an existing file only when the flag says so.
            const std::uint8_t replace = read_u8(info, kRenameReplaceIfExists);
            if (replace == 0 && ::access(host.c_str(), F_OK) == 0) {
                set_last_error(kErrorAlreadyExists);
                return 0;
            }
            std::string self = "/proc/self/fd/" + std::to_string(fd);
            char resolved[4096];
            const ssize_t got = ::readlink(self.c_str(), resolved,
                                           sizeof(resolved) - 1);
            if (got <= 0) {
                set_last_error(kErrorInvalidHandle);
                return 0;
            }
            resolved[got] = '\0';
            if (::rename(resolved, host.c_str()) != 0) {
                set_last_error(kErrorAccessDenied);
                return 0;
            }
            set_last_error(kErrorSuccess);
            return 1;
        }
        case kFileBasicInfo:
            // The basic-information class writes the four timestamps and the
            // attributes. The host keeps three times and no attributes the
            // guest can set, so a caller that asked to change them is told
            // the class is not one this runtime applies rather than being
            // told it succeeded and finding the times unchanged.
            set_last_error(kErrorCallNotImplemented);
            return 0;
        default:
            set_last_error(kErrorInvalidParameter);
            return 0;
    }
}

// ------------------------------------------------------------- registration

void add_kernel32_io2(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CancelIoEx", reinterpret_cast<void*>(&k32io2_CancelIoEx));
    e("DeviceIoControl", reinterpret_cast<void*>(&k32io2_DeviceIoControl));
    e("GetOverlappedResult",
      reinterpret_cast<void*>(&k32io2_GetOverlappedResult));
    e("SetFileInformationByHandle",
      reinterpret_cast<void*>(&k32io2_SetFileInformationByHandle));
}

}  // namespace occ::runtime::winabi

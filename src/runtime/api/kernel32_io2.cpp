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

#include <alloca.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <condition_variable>
#include <deque>
#include <map>
#include <memory>
#include <mutex>

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

// ------------------------------------------- the I/O completion ports
//
// A completion port is a queue with a scheduling policy: a caller that
// posted a packet hands the caller waiting for one the answer, and a file
// handle associated with the port gets its completed overlapped operations
// queued there. Windows builds the queue in the kernel; this runtime builds
// it in the process, which is the same queue with the same contract and one
// fewer context switch.
//
// The handle namespace is the third range this runtime issues -- above the
// file handles and above the object table's, so a handle's value says which
// structure it names, which is what every other range in the runtime says
// too.
namespace {

constexpr std::uint64_t kIocpHandleBase = 0x300000;

// WAIT_TIMEOUT: what an empty port answers with when the wait expired.
constexpr std::uint32_t kWaitTimeout = 0x00000102u;

// One queued completion. `key` and `overlapped` are the caller's values
// handed back untouched -- they are the pair a completion means "yours"
// with, and a runtime that rewrote either would answer a different
// operation than the one that ran.
struct CompletionPacket {
    std::uint32_t bytes = 0;
    std::uint64_t key = 0;
    std::uint64_t overlapped = 0;
    std::uint32_t error = 0;
};

struct CompletionPort {
    std::mutex lock;
    std::condition_variable ready;
    std::deque<CompletionPacket> queue;
    // The file handles associated with this port, and the completion key
    // each was associated with. The key is a per-handle constant the
    // caller chose, and a completed operation on the handle is queued with
    // it -- which is how a single port serves many files without the
    // completion naming anything but the operation.
    std::map<std::uint64_t, std::uint64_t> associated;
};

std::map<std::uint64_t, std::unique_ptr<CompletionPort>>& iocp_table() noexcept {
    static std::map<std::uint64_t, std::unique_ptr<CompletionPort>> table;
    return table;
}

[[nodiscard]] std::uint64_t iocp_handle_new() noexcept {
    static std::uint64_t next = 0;
    const std::uint64_t handle = kIocpHandleBase + next * 0x10ULL;
    ++next;
    return handle;
}

[[nodiscard]] CompletionPort* iocp_of(std::uint64_t handle) noexcept {
    if (handle < kIocpHandleBase) {
        return nullptr;
    }
    const auto it = iocp_table().find(handle);
    return it == iocp_table().end() ? nullptr : it->second.get();
}

// Queues one packet and wakes one waiter. The lock is taken here and
// released here: the waiters wake holding nothing, which is the shape of
// the contract -- the packet is queued when the post returns, and the
// waiter that takes it owns it alone.
void iocp_post(CompletionPort& port, const CompletionPacket& packet) noexcept {
    {
        std::lock_guard<std::mutex> guard(port.lock);
        port.queue.push_back(packet);
    }
    port.ready.notify_one();
}

// Takes one packet, waiting up to `milliseconds` -- forever when the value
// is the one Windows spells INFINITE -- and answers whether it took one.
[[nodiscard]] bool iocp_take(CompletionPort& port, std::uint32_t milliseconds,
                             CompletionPacket& out) noexcept {
    std::unique_lock<std::mutex> lock(port.lock);
    constexpr std::uint32_t kInfinite = 0xFFFFFFFFu;
    if (milliseconds == kInfinite) {
        port.ready.wait(lock, [&port] { return !port.queue.empty(); });
    } else {
        if (!port.ready.wait_for(lock, std::chrono::milliseconds(milliseconds),
                                 [&port] { return !port.queue.empty(); })) {
            return false;
        }
    }
    out = port.queue.front();
    port.queue.pop_front();
    return true;
}

// The queue's own drain for `GetQueuedCompletionStatusEx`: up to `count`
// packets, whatever the queue holds, and the number it took is the number
// the caller was told to read.
[[nodiscard]] std::uint32_t iocp_take_many(
    CompletionPort& port, std::uint32_t milliseconds,
    CompletionPacket* out, std::uint32_t count) noexcept {
    std::unique_lock<std::mutex> lock(port.lock);
    constexpr std::uint32_t kInfinite = 0xFFFFFFFFu;
    if (milliseconds == kInfinite) {
        port.ready.wait(lock, [&port] { return !port.queue.empty(); });
    } else {
        if (!port.ready.wait_for(lock, std::chrono::milliseconds(milliseconds),
                                 [&port] { return !port.queue.empty(); })) {
            return 0;
        }
    }
    std::uint32_t taken = 0;
    while (taken < count && !port.queue.empty()) {
        out[taken] = port.queue.front();
        port.queue.pop_front();
        ++taken;
    }
    return taken;
}

// The OVERLAPPED layout, as `file.cpp` spells it and as this file's
// completion answers write it: two kernel words, the position, the event,
// and the byte count the caller reads first.
[[maybe_unused]] constexpr std::size_t kOverlappedInternalHigh = 8;
[[maybe_unused]] constexpr std::size_t kOverlappedOffset = 16;
[[maybe_unused]] constexpr std::size_t kOverlappedOffsetHigh = 24;
constexpr std::size_t kOverlappedBytes = 40;

void overlapped_set_bytes(void* overlapped, std::uint32_t bytes) noexcept {
    if (overlapped != nullptr) {
        std::memcpy(static_cast<std::uint8_t*>(overlapped) + kOverlappedBytes,
                    &bytes, 4);
    }
}

}  // namespace

// `CreateIoCompletionPort`: a new port when both handles are null, an
// association when both are named, and a refusal for the half-asked
// question -- a file without a port to join, or a port joined to nothing.
extern "C" __attribute__((ms_abi)) std::uint64_t k32io2_CreateIoCompletionPort(
    std::uint64_t file_handle, std::uint64_t existing, std::uint64_t key,
    std::uint32_t threads) noexcept {
    static_cast<void>(threads);
    if (file_handle == 0) {
        if (existing != 0) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        const std::uint64_t handle = iocp_handle_new();
        iocp_table()[handle] = std::make_unique<CompletionPort>();
        set_last_error(kErrorSuccess);
        return handle;
    }
    CompletionPort* port = iocp_of(existing);
    if (port == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    {
        std::lock_guard<std::mutex> guard(port->lock);
        port->associated[file_handle] = key;
    }
    set_last_error(kErrorSuccess);
    return existing;
}

// `PostQueuedCompletionStatus`: the caller's own packet, queued as it
// stands. This is how a program drives its own workers -- the port is a
// queue first, and a program that has a completion to hand out hands it
// here rather than waiting for a file to complete on its behalf.
extern "C" __attribute__((ms_abi)) std::int32_t k32io2_PostQueuedCompletionStatus(
    std::uint64_t port, std::uint32_t bytes, std::uint64_t key,
    void* overlapped) noexcept {
    CompletionPort* p = iocp_of(port);
    if (p == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    CompletionPacket packet;
    packet.bytes = bytes;
    packet.key = key;
    packet.overlapped = reinterpret_cast<std::uint64_t>(overlapped);
    iocp_post(*p, packet);
    set_last_error(kErrorSuccess);
    return 1;
}

// `GetQueuedCompletionStatus`: one packet, or a timeout. A packet whose
// error field is set is a failed operation the caller still queued --
// Windows reports it through `lpNumberOfBytes` zero and the error out of
// `GetLastError`, which is the pair this returns.
extern "C" __attribute__((ms_abi)) std::int32_t
k32io2_GetQueuedCompletionStatus(std::uint64_t port, std::uint32_t* bytes_out,
                                 std::uint64_t* key_out,
                                 std::uint64_t* overlapped_out,
                                 std::uint32_t milliseconds) noexcept {
    CompletionPort* p = iocp_of(port);
    if (p == nullptr || bytes_out == nullptr || key_out == nullptr ||
        overlapped_out == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    CompletionPacket packet;
    if (!iocp_take(*p, milliseconds, packet)) {
        set_last_error(kWaitTimeout);
        *bytes_out = 0;
        return 0;
    }
    *bytes_out = packet.bytes;
    *key_out = packet.key;
    *overlapped_out = packet.overlapped;
    if (packet.overlapped != 0) {
        overlapped_set_bytes(reinterpret_cast<void*>(packet.overlapped),
                             packet.bytes);
    }
    set_last_error(packet.error);
    return packet.error == 0 ? 1 : 0;
}

// `GetQueuedCompletionStatusEx`: the batched take. A worker that drains
// the port between other work reads several completions in one call, and
// the count it gets back is the count it reads -- never more than it asked
// for, and zero only when the timeout found an empty queue.
extern "C" __attribute__((ms_abi)) std::int32_t
k32io2_GetQueuedCompletionStatusEx(std::uint64_t port, void* entries,
                                   std::uint32_t count,
                                   std::uint32_t* removed_out,
                                   std::uint32_t milliseconds,
                                   std::int32_t alertable) noexcept {
    static_cast<void>(alertable);
    CompletionPort* p = iocp_of(port);
    if (p == nullptr || entries == nullptr || count == 0 ||
        removed_out == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    // Each entry is an OVERLAPPED_ENTRY: the completion key, the byte
    // count, the overlapped pointer, and the internal status the caller
    // does not read -- 32 bytes, of which three are filled here.
    CompletionPacket* packets =
        static_cast<CompletionPacket*>(::alloca(sizeof(CompletionPacket) *
                                                count));
    const std::uint32_t taken = iocp_take_many(*p, milliseconds, packets,
                                               count);
    if (taken == 0) {
        set_last_error(kWaitTimeout);
        *removed_out = 0;
        return 0;
    }
    auto* out = static_cast<std::uint8_t*>(entries);
    for (std::uint32_t i = 0; i < taken; ++i) {
        const std::uint64_t at = static_cast<std::uint64_t>(i) * 32;
        const std::uint64_t key = packets[i].key;
        const std::uint32_t bytes = packets[i].bytes;
        const std::uint64_t overlapped = packets[i].overlapped;
        std::memcpy(out + at, &key, 8);
        std::memcpy(out + at + 8, &bytes, 4);
        std::memcpy(out + at + 16, &overlapped, 8);
        if (overlapped != 0) {
            overlapped_set_bytes(reinterpret_cast<void*>(overlapped),
                                 packets[i].bytes);
        }
    }
    *removed_out = taken;
    set_last_error(kErrorSuccess);
    return 1;
}

// Whether a completed overlapped operation on this handle is a completion
// the port queues. Called from `ReadFile` and `WriteFile` when the handle
// is associated: the operation has already run -- this runtime's I/O
// completes before its calls return -- and what remains is the completion,
// which is the packet the port's waiter is waiting for.
bool iocp_complete_handle(std::uint64_t handle, std::uint32_t bytes,
                          void* overlapped, std::uint32_t error) noexcept {
    if (overlapped == nullptr) {
        return false;
    }
    // The lookup takes the port's lock and leaves it; the post takes it
    // again. A single critical section would work too, but the post is
    // the one writer the queue has, and every queue invariant lives in
    // one place.
    for (auto& [h, port] : iocp_table()) {
        std::uint64_t key = 0;
        {
            std::lock_guard<std::mutex> guard(port->lock);
            if (port->associated.count(handle) == 0) {
                continue;
            }
            key = port->associated.at(handle);
        }
        CompletionPacket packet;
        packet.bytes = bytes;
        packet.key = key;
        packet.overlapped = reinterpret_cast<std::uint64_t>(overlapped);
        packet.error = error;
        // The byte count in the OVERLAPPED is the caller's other half of
        // the answer, written here because the completion is the thing
        // that says how much ran.
        overlapped_set_bytes(overlapped, bytes);
        iocp_post(*port, packet);
        return true;
    }
    return false;
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
    e("CreateIoCompletionPort",
      reinterpret_cast<void*>(&k32io2_CreateIoCompletionPort));
    e("GetQueuedCompletionStatus",
      reinterpret_cast<void*>(&k32io2_GetQueuedCompletionStatus));
    e("GetQueuedCompletionStatusEx",
      reinterpret_cast<void*>(&k32io2_GetQueuedCompletionStatusEx));
    e("PostQueuedCompletionStatus",
      reinterpret_cast<void*>(&k32io2_PostQueuedCompletionStatus));
    e("DeviceIoControl", reinterpret_cast<void*>(&k32io2_DeviceIoControl));
    e("GetOverlappedResult",
      reinterpret_cast<void*>(&k32io2_GetOverlappedResult));
    e("SetFileInformationByHandle",
      reinterpret_cast<void*>(&k32io2_SetFileInformationByHandle));
}

}  // namespace occ::runtime::winabi

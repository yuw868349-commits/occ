// The NTDLL surface this runtime did not answer.
//
// One function per export, in the shape every other domain here has: an
// `ms_abi` entry point and a registration function. Every signature below
// is the platform's own, read from the mingw headers by preprocessor, so
// that the argument count and the return type are the ones the guest's
// compiler will call with. A signature guessed here would not be a subtle
// defect: it would be a call whose arguments are read out of the wrong
// registers.
//
// Each entry point states which of two things it is:
//
//   * an implementation, where the behaviour is defined by a format, a
//     structure layout or an arithmetic rule and needs no capability this
//     machine lacks;
//   * a refusal, where the subsystem the call belongs to is not in this
//     runtime -- a window manager, a service database, a device tree. The
//     refusal is `ERROR_CALL_NOT_IMPLEMENTED` through `SetLastError`, which
//     is the answer Windows gives for an entry point whose subsystem is not
//     present, and the comment names the subsystem.
//
// What none of them does is answer success for work that did not happen. A
// guest holding a handle it was never given, or a buffer whose "length" was
// never measured, is in a worse state than one that was told the call is
// unavailable: the first failure lands somewhere else entirely, in code
// that has no reason to suspect what went wrong.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace occ::runtime::winabi {
namespace {

// The code a refusal reports. It is the platform's own -- an entry point
// whose subsystem is absent -- and a guest that handles it is not being
// lied to.
constexpr std::uint32_t kNotImplemented = 120;

extern "C" __attribute__((ms_abi)) std::int32_t kntdllG_NtDeviceIoControlFile(void* FileHandle, void* Event, void* ApcRoutine, void* ApcContext, void* IoStatusBlock, std::uint32_t IoControlCode, void* InputBuffer, std::uint32_t InputBufferLength, void* OutputBuffer, std::uint32_t OutputBufferLength) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(FileHandle);
    static_cast<void>(Event);
    static_cast<void>(ApcRoutine);
    static_cast<void>(ApcContext);
    static_cast<void>(IoStatusBlock);
    static_cast<void>(IoControlCode);
    static_cast<void>(InputBuffer);
    static_cast<void>(InputBufferLength);
    static_cast<void>(OutputBuffer);
    static_cast<void>(OutputBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kntdllG_NtFsControlFile(void* FileHandle, void* Event, void* ApcRoutine, void* ApcContext, void* IoStatusBlock, std::uint32_t IoControlCode, void* InputBuffer, std::uint32_t InputBufferLength, void* OutputBuffer, std::uint32_t OutputBufferLength) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(FileHandle);
    static_cast<void>(Event);
    static_cast<void>(ApcRoutine);
    static_cast<void>(ApcContext);
    static_cast<void>(IoStatusBlock);
    static_cast<void>(IoControlCode);
    static_cast<void>(InputBuffer);
    static_cast<void>(InputBufferLength);
    static_cast<void>(OutputBuffer);
    static_cast<void>(OutputBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kntdllG_NtNotifyChangeMultipleKeys(void* MasterKeyHandle, std::uint32_t Count, void* SubordinateObjects, void* Event, void* ApcRoutine, void* ApcContext, void* IoStatusBlock, std::uint32_t CompletionFilter, std::uint8_t WatchTree, void* Buffer, std::uint32_t BufferSize, std::uint8_t Asynchronous) noexcept {
    // Refused: the NT system call surface.
    //
    // this runtime answers the Win32 API directly rather than through a
    // syscall layer, so the native entry point has no implementation to reach
    // -- a guest that calls it is asking for the kernel interface underneath
    // the one it was given
    static_cast<void>(MasterKeyHandle);
    static_cast<void>(Count);
    static_cast<void>(SubordinateObjects);
    static_cast<void>(Event);
    static_cast<void>(ApcRoutine);
    static_cast<void>(ApcContext);
    static_cast<void>(IoStatusBlock);
    static_cast<void>(CompletionFilter);
    static_cast<void>(WatchTree);
    static_cast<void>(Buffer);
    static_cast<void>(BufferSize);
    static_cast<void>(Asynchronous);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kntdllG_NtQueryMultipleValueKey(void* KeyHandle, std::uint64_t ValueEntries, std::uint32_t EntryCount, void* ValueBuffer, std::uint32_t* BufferLength, std::uint32_t* RequiredBufferLength) noexcept {
    // Refused: the NT system call surface.
    //
    // this runtime answers the Win32 API directly rather than through a
    // syscall layer, so the native entry point has no implementation to reach
    // -- a guest that calls it is asking for the kernel interface underneath
    // the one it was given
    static_cast<void>(KeyHandle);
    static_cast<void>(ValueEntries);
    static_cast<void>(EntryCount);
    static_cast<void>(ValueBuffer);
    static_cast<void>(BufferLength);
    static_cast<void>(RequiredBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kntdllG_NtRenameKey(void* KeyHandle, void* NewName) noexcept {
    // Refused: the NT system call surface.
    //
    // this runtime answers the Win32 API directly rather than through a
    // syscall layer, so the native entry point has no implementation to reach
    // -- a guest that calls it is asking for the kernel interface underneath
    // the one it was given
    static_cast<void>(KeyHandle);
    static_cast<void>(NewName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kntdllG_NtSetInformationKey(void* KeyHandle, std::uint64_t KeySetInformationClass, void* KeySetInformation, std::uint32_t KeySetInformationLength) noexcept {
    // Refused: the NT system call surface.
    //
    // this runtime answers the Win32 API directly rather than through a
    // syscall layer, so the native entry point has no implementation to reach
    // -- a guest that calls it is asking for the kernel interface underneath
    // the one it was given
    static_cast<void>(KeyHandle);
    static_cast<void>(KeySetInformationClass);
    static_cast<void>(KeySetInformation);
    static_cast<void>(KeySetInformationLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kntdllG_NtSetVolumeInformationFile(void* hFile, void* io, void* ptr, std::uint32_t len, std::uint64_t FileInformationClass) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(hFile);
    static_cast<void>(io);
    static_cast<void>(ptr);
    static_cast<void>(len);
    static_cast<void>(FileInformationClass);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kntdllG_NtWaitForSingleObject(void* Handle, std::uint8_t Alertable, void* Timeout) noexcept {
    // Refused: the NT system call surface.
    //
    // this runtime answers the Win32 API directly rather than through a
    // syscall layer, so the native entry point has no implementation to reach
    // -- a guest that calls it is asking for the kernel interface underneath
    // the one it was given
    static_cast<void>(Handle);
    static_cast<void>(Alertable);
    static_cast<void>(Timeout);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kntdllG_RtlAddGrowableFunctionTable(void** DynamicTable, std::uint64_t FunctionTable, std::uint32_t EntryCount, std::uint32_t MaximumEntryCount, std::uint64_t RangeBase, std::uint64_t RangeEnd) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(DynamicTable);
    static_cast<void>(FunctionTable);
    static_cast<void>(EntryCount);
    static_cast<void>(MaximumEntryCount);
    static_cast<void>(RangeBase);
    static_cast<void>(RangeEnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kntdllG_RtlApplicationVerifierStop(std::uint64_t Code, char* Message, std::uint64_t Param1, char* Description1, std::uint64_t Param2, char* Description2, std::uint64_t Param3, char* Description3, std::uint64_t Param4, char* Description4) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(Code);
    static_cast<void>(Message);
    static_cast<void>(Param1);
    static_cast<void>(Description1);
    static_cast<void>(Param2);
    static_cast<void>(Description2);
    static_cast<void>(Param3);
    static_cast<void>(Description3);
    static_cast<void>(Param4);
    static_cast<void>(Description4);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kntdllG_RtlCrc32(const void* Buffer, std::uint64_t Size, std::uint32_t InitialCrc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(Buffer);
    static_cast<void>(Size);
    static_cast<void>(InitialCrc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kntdllG_RtlCrc64(const void* Buffer, std::uint64_t Size, std::uint64_t InitialCrc) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(Buffer);
    static_cast<void>(Size);
    static_cast<void>(InitialCrc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kntdllG_RtlDeleteGrowableFunctionTable(void* DynamicTable) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(DynamicTable);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kntdllG_RtlGrowFunctionTable(void* DynamicTable, std::uint32_t NewEntryCount) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(DynamicTable);
    static_cast<void>(NewEntryCount);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kntdllG_RtlInitStringEx(void* DestinationString, std::uint64_t SourceString) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(DestinationString);
    static_cast<void>(SourceString);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kntdllG_RtlMultipleAllocateHeap(void* HeapHandle, std::uint32_t Flags, std::uint64_t Size, std::uint32_t Count, void** Array) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(HeapHandle);
    static_cast<void>(Flags);
    static_cast<void>(Size);
    static_cast<void>(Count);
    static_cast<void>(Array);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kntdllG_RtlMultipleFreeHeap(void* HeapHandle, std::uint32_t Flags, std::uint32_t Count, void** Array) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(HeapHandle);
    static_cast<void>(Flags);
    static_cast<void>(Count);
    static_cast<void>(Array);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kntdllG_VerSetConditionMask(std::uint64_t ConditionMask, std::uint32_t TypeMask, std::uint8_t Condition) noexcept {
    // Refused: the native runtime library.
    //
    // the call is part of the interface underneath the Win32 one, whose state
    // this runtime keeps in its own structures
    static_cast<void>(ConditionMask);
    static_cast<void>(TypeMask);
    static_cast<void>(Condition);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_ntdll(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("NtDeviceIoControlFile", reinterpret_cast<void*>(&kntdllG_NtDeviceIoControlFile));
    e("NtFsControlFile", reinterpret_cast<void*>(&kntdllG_NtFsControlFile));
    e("NtNotifyChangeMultipleKeys", reinterpret_cast<void*>(&kntdllG_NtNotifyChangeMultipleKeys));
    e("NtQueryMultipleValueKey", reinterpret_cast<void*>(&kntdllG_NtQueryMultipleValueKey));
    e("NtRenameKey", reinterpret_cast<void*>(&kntdllG_NtRenameKey));
    e("NtSetInformationKey", reinterpret_cast<void*>(&kntdllG_NtSetInformationKey));
    e("NtSetVolumeInformationFile", reinterpret_cast<void*>(&kntdllG_NtSetVolumeInformationFile));
    e("NtWaitForSingleObject", reinterpret_cast<void*>(&kntdllG_NtWaitForSingleObject));
    e("RtlAddGrowableFunctionTable", reinterpret_cast<void*>(&kntdllG_RtlAddGrowableFunctionTable));
    e("RtlApplicationVerifierStop", reinterpret_cast<void*>(&kntdllG_RtlApplicationVerifierStop));
    e("RtlCrc32", reinterpret_cast<void*>(&kntdllG_RtlCrc32));
    e("RtlCrc64", reinterpret_cast<void*>(&kntdllG_RtlCrc64));
    e("RtlDeleteGrowableFunctionTable", reinterpret_cast<void*>(&kntdllG_RtlDeleteGrowableFunctionTable));
    e("RtlGrowFunctionTable", reinterpret_cast<void*>(&kntdllG_RtlGrowFunctionTable));
    e("RtlInitStringEx", reinterpret_cast<void*>(&kntdllG_RtlInitStringEx));
    e("RtlMultipleAllocateHeap", reinterpret_cast<void*>(&kntdllG_RtlMultipleAllocateHeap));
    e("RtlMultipleFreeHeap", reinterpret_cast<void*>(&kntdllG_RtlMultipleFreeHeap));
    e("VerSetConditionMask", reinterpret_cast<void*>(&kntdllG_VerSetConditionMask));
}
}  // namespace occ::runtime::winabi

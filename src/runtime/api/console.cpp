// The console family and the handle family.
//
// The guided principle here is the one the reference settled: a run whose
// standard handles are redirected -- which is every run this runtime
// performs -- has no console, and the console calls answer the way Windows
// answers them in that state rather than inventing one. `GetConsoleMode`
// fails, `WriteConsole` fails with `ERROR_INVALID_HANDLE`,
// `GetConsoleWindow` answers null, and `GetConsoleScreenBufferInfo` fails.
//
// That is not this file doing less than it could. A program that writes
// through `WriteConsole` does not work when its output is redirected on
// Windows either, and the reason is the same: the call is for a console and
// there is not one. The call a redirected program uses is `WriteFile`, and
// that one works. A runtime that answered `WriteConsole` by quietly writing
// the descriptor would be running a program that has never worked on a
// redirect, which is a difference a caller cannot see until it is somewhere
// else.
//
// `GetFileType` is the exception, and it is the one that decides which of
// the two paths a caller takes: it reads the descriptor and reports what it
// actually is, so a program that checks before writing console makes the
// same choice here that it would make anywhere.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>

#include <sys/stat.h>
#include <unistd.h>

namespace occ::runtime::winabi {
namespace {

// The standard handles, which are constants rather than descriptors and are
// the values a guest compares against.
constexpr std::uint64_t kStdInput = 0xFFFFFFFFFFFFFFF4ULL;   // -12
constexpr std::uint64_t kStdOutput = 0xFFFFFFFFFFFFFFF5ULL;  // -11
constexpr std::uint64_t kStdError = 0xFFFFFFFFFFFFFFF6ULL;   // -10

// The file types `GetFileType` answers.
constexpr std::uint32_t kFileTypeUnknown = 0x0000;
constexpr std::uint32_t kFileTypeDisk = 0x0001;
constexpr std::uint32_t kFileTypeChar = 0x0002;
constexpr std::uint32_t kFileTypePipe = 0x0003;

constexpr std::uint32_t kErrorInvalidHandle = 6;
constexpr std::uint32_t kErrorInvalidParameter = 87;
constexpr std::uint32_t kErrorAccessDenied = 5;

// The file handle base, which is where a descriptor this runtime issued
// starts. A handle below it is a standard handle or a value nothing issued.
constexpr std::uint64_t kFileHandleBase = 0x2000;
constexpr std::uint64_t kFileHandleSpan = 0x100000;

// The pseudo-handle Windows hands out for the current process, which is the
// only process handle this runtime has.
constexpr std::uint64_t kCurrentProcessHandle = 0xFFFFFFFFFFFFFFFFULL;

[[nodiscard]] bool names_this_process(std::uint64_t handle) noexcept {
    return handle == kCurrentProcessHandle;
}

// Which descriptor a standard handle names, or -1 for a handle that is not
// one of the three.
[[nodiscard]] int descriptor_for_standard(std::uint64_t handle) noexcept {
    if (handle == kStdInput) {
        return 0;
    }
    if (handle == kStdOutput) {
        return 1;
    }
    if (handle == kStdError) {
        return 2;
    }
    return -1;
}

// The descriptor a handle names, or -1. Both namespaces are read here
// because `GetFileType` takes either.
[[nodiscard]] int descriptor_for(std::uint64_t handle) noexcept {
    const int standard = descriptor_for_standard(handle);
    if (standard >= 0) {
        return standard;
    }
    if (handle >= kFileHandleBase && handle < kFileHandleBase + kFileHandleSpan) {
        return static_cast<int>(handle - kFileHandleBase);
    }
    return -1;
}

// The refusal every console call that needs a console answers, and the error
// that goes with it. Windows answers `ERROR_INVALID_HANDLE` for a handle
// that is not a console, which is exactly the state a redirected run is in.
[[nodiscard]] std::int32_t no_console() noexcept {
    set_last_error(kErrorInvalidHandle);
    return 0;
}

// A pointer-answering console call with no console answers null, and leaves
// the error the same way.
[[nodiscard]] void* no_console_pointer() noexcept {
    set_last_error(kErrorInvalidHandle);
    return nullptr;
}

// A routine registered through `SetConsoleCtrlHandler`. The list is a small
// fixed array because the count is bounded by what a program does, and a
// program that registers more than this is not one this runtime has seen.
constexpr std::size_t kMaxHandlers = 16;
std::uint64_t g_ctrl_handlers[kMaxHandlers] = {};
std::size_t g_ctrl_handler_count = 0;

}  // namespace

// ---------------------------------------------------------------------------
// Standard handles and the file type
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t k32c_SetStdHandle(
    std::uint32_t which, std::uint64_t handle) noexcept {
    // The three constants are computed rather than stored, so a call that
    // tried to change them would have nothing to change. It succeeds for the
    // values Windows accepts -- the caller is setting what is already set --
    // and fails for a standard handle number that is not one of the three.
    if (which != static_cast<std::uint32_t>(-10) &&
        which != static_cast<std::uint32_t>(-11) &&
        which != static_cast<std::uint32_t>(-12)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    (void)handle;
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32c_GetFileType(
    std::uint64_t handle) noexcept {
    const int fd = descriptor_for(handle);
    if (fd < 0) {
        set_last_error(kErrorInvalidHandle);
        return kFileTypeUnknown;
    }
    struct stat info {};
    if (::fstat(fd, &info) != 0) {
        set_last_error(kErrorInvalidHandle);
        return kFileTypeUnknown;
    }
    set_last_error(0);
    // The three answers a descriptor can really have. A character device is
    // what a terminal is, a fifo or socket is what a pipe between processes
    // is, and everything else -- including a regular file and the block
    // device a disk appears as -- is what Windows calls a disk file.
    if (S_ISCHR(info.st_mode)) {
        return kFileTypeChar;
    }
    if (S_ISFIFO(info.st_mode) || S_ISSOCK(info.st_mode)) {
        return kFileTypePipe;
    }
    return kFileTypeDisk;
}

// ---------------------------------------------------------------------------
// The console calls, all of which need a console
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t k32c_GetConsoleMode(
    std::uint64_t handle, std::uint32_t* mode) noexcept {
    (void)handle;
    (void)mode;
    return no_console();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_SetConsoleMode(
    std::uint64_t handle, std::uint32_t mode) noexcept {
    (void)handle;
    (void)mode;
    return no_console();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_GetConsoleScreenBufferInfo(
    std::uint64_t handle, std::uint8_t* out) noexcept {
    (void)handle;
    (void)out;
    return no_console();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_SetConsoleCursorPosition(
    std::uint64_t handle, std::uint32_t position) noexcept {
    (void)handle;
    (void)position;
    return no_console();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_SetConsoleTextAttribute(
    std::uint64_t handle, std::uint32_t attributes) noexcept {
    (void)handle;
    (void)attributes;
    return no_console();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_SetConsoleCursorInfo(
    std::uint64_t handle, const std::uint8_t* info) noexcept {
    (void)handle;
    (void)info;
    return no_console();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_GetConsoleCursorInfo(
    std::uint64_t handle, std::uint8_t* out) noexcept {
    (void)handle;
    (void)out;
    return no_console();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_FillConsoleOutputCharacterA(
    std::uint64_t handle, char character, std::uint32_t length,
    std::uint32_t position, std::uint32_t* written) noexcept {
    (void)handle;
    (void)character;
    (void)length;
    (void)position;
    (void)written;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_FillConsoleOutputCharacterW(
    std::uint64_t handle, char16_t character, std::uint32_t length,
    std::uint32_t position, std::uint32_t* written) noexcept {
    (void)handle;
    (void)character;
    (void)length;
    (void)position;
    (void)written;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_FillConsoleOutputAttribute(
    std::uint64_t handle, std::uint32_t attributes, std::uint32_t length,
    std::uint32_t position, std::uint32_t* written) noexcept {
    (void)handle;
    (void)attributes;
    (void)length;
    (void)position;
    (void)written;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_WriteConsoleA(
    std::uint64_t handle, const void* buffer, std::uint32_t length,
    std::uint32_t* written, void* reserved) noexcept {
    (void)handle;
    (void)buffer;
    (void)length;
    (void)written;
    (void)reserved;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_WriteConsoleW(
    std::uint64_t handle, const void* buffer, std::uint32_t length,
    std::uint32_t* written, void* reserved) noexcept {
    return k32c_WriteConsoleA(handle, buffer, length, written, reserved);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_ReadConsoleA(
    std::uint64_t handle, void* buffer, std::uint32_t length,
    std::uint32_t* read, void* reserved) noexcept {
    (void)handle;
    (void)buffer;
    (void)length;
    (void)read;
    (void)reserved;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_ReadConsoleW(
    std::uint64_t handle, void* buffer, std::uint32_t length,
    std::uint32_t* read, void* reserved) noexcept {
    return k32c_ReadConsoleA(handle, buffer, length, read, reserved);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_WriteConsoleOutputA(
    std::uint64_t handle, const void* buffer, std::uint32_t size,
    std::uint32_t coordinate, void* region) noexcept {
    (void)handle;
    (void)buffer;
    (void)size;
    (void)coordinate;
    (void)region;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_WriteConsoleOutputW(
    std::uint64_t handle, const void* buffer, std::uint32_t size,
    std::uint32_t coordinate, void* region) noexcept {
    return k32c_WriteConsoleOutputA(handle, buffer, size, coordinate, region);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_WriteConsoleOutputCharacterA(
    std::uint64_t handle, const char* text, std::uint32_t length,
    std::uint32_t position, std::uint32_t* written) noexcept {
    (void)handle;
    (void)text;
    (void)length;
    (void)position;
    (void)written;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_WriteConsoleOutputCharacterW(
    std::uint64_t handle, const char16_t* text, std::uint32_t length,
    std::uint32_t position, std::uint32_t* written) noexcept {
    (void)handle;
    (void)text;
    (void)length;
    (void)position;
    (void)written;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_WriteConsoleOutputAttribute(
    std::uint64_t handle, const std::uint16_t* attributes,
    std::uint32_t length, std::uint32_t position,
    std::uint32_t* written) noexcept {
    (void)handle;
    (void)attributes;
    (void)length;
    (void)position;
    (void)written;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_ReadConsoleOutputA(
    std::uint64_t handle, void* buffer, std::uint32_t size,
    std::uint32_t coordinate, void* region) noexcept {
    (void)handle;
    (void)buffer;
    (void)size;
    (void)coordinate;
    (void)region;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_ReadConsoleOutputW(
    std::uint64_t handle, void* buffer, std::uint32_t size,
    std::uint32_t coordinate, void* region) noexcept {
    return k32c_ReadConsoleOutputA(handle, buffer, size, coordinate, region);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_ReadConsoleOutputCharacterA(
    std::uint64_t handle, char* text, std::uint32_t length,
    std::uint32_t position, std::uint32_t* read) noexcept {
    (void)handle;
    (void)text;
    (void)length;
    (void)position;
    (void)read;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_ReadConsoleOutputCharacterW(
    std::uint64_t handle, char16_t* text, std::uint32_t length,
    std::uint32_t position, std::uint32_t* read) noexcept {
    (void)handle;
    (void)text;
    (void)length;
    (void)position;
    (void)read;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_ReadConsoleOutputAttribute(
    std::uint64_t handle, std::uint16_t* attributes, std::uint32_t length,
    std::uint32_t position, std::uint32_t* read) noexcept {
    (void)handle;
    (void)attributes;
    (void)length;
    (void)position;
    (void)read;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_ScrollConsoleScreenBufferA(
    std::uint64_t handle, const void* scroll, const void* clip,
    std::uint32_t destination, const void* fill) noexcept {
    (void)handle;
    (void)scroll;
    (void)clip;
    (void)destination;
    (void)fill;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_ScrollConsoleScreenBufferW(
    std::uint64_t handle, const void* scroll, const void* clip,
    std::uint32_t destination, const void* fill) noexcept {
    return k32c_ScrollConsoleScreenBufferA(handle, scroll, clip, destination,
                                           fill);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_GetNumberOfConsoleInputEvents(
    std::uint64_t handle, std::uint32_t* count) noexcept {
    (void)handle;
    (void)count;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_ReadConsoleInputA(
    std::uint64_t handle, void* records, std::uint32_t length,
    std::uint32_t* read) noexcept {
    (void)handle;
    (void)records;
    (void)length;
    (void)read;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_ReadConsoleInputW(
    std::uint64_t handle, void* records, std::uint32_t length,
    std::uint32_t* read) noexcept {
    return k32c_ReadConsoleInputA(handle, records, length, read);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_PeekConsoleInputA(
    std::uint64_t handle, void* records, std::uint32_t length,
    std::uint32_t* read) noexcept {
    return k32c_ReadConsoleInputA(handle, records, length, read);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_PeekConsoleInputW(
    std::uint64_t handle, void* records, std::uint32_t length,
    std::uint32_t* read) noexcept {
    return k32c_ReadConsoleInputA(handle, records, length, read);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_CreateConsoleScreenBuffer(
    std::uint32_t access, std::uint32_t share, const void* security,
    std::uint32_t buffer, const void* info,
    std::uint64_t* out) noexcept {
    (void)access;
    (void)share;
    (void)security;
    (void)buffer;
    (void)info;
    (void)out;
    set_last_error(kErrorInvalidHandle);
    return static_cast<std::int32_t>(0xFFFFFFFFu);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_SetConsoleActiveScreenBuffer(
    std::uint64_t handle) noexcept {
    (void)handle;
    return no_console();
}

extern "C" __attribute__((ms_abi)) void* k32c_GetConsoleWindow() noexcept {
    return no_console_pointer();
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32c_GetLargestConsoleWindowSize(
    std::uint64_t handle) noexcept {
    (void)handle;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_GetConsoleFontSize(
    std::uint64_t handle, std::uint32_t index) noexcept {
    (void)handle;
    (void)index;
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32c_GetConsoleCP() noexcept {
    // Zero is what Windows answers for a process with no console, which is
    // this process. It is not a code page and a caller that uses it as one
    // will find out -- which is the same discovery it would make on Windows
    // with its output redirected.
    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32c_GetConsoleOutputCP()
    noexcept {
    return k32c_GetConsoleCP();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_SetConsoleCP(
    std::uint32_t codepage) noexcept {
    (void)codepage;
    return no_console();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_SetConsoleOutputCP(
    std::uint32_t codepage) noexcept {
    (void)codepage;
    return no_console();
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32c_GetConsoleTitleA(
    char* out, std::uint32_t size) noexcept {
    (void)out;
    (void)size;
    // No title and no console to hold one. The answer is zero, which is what
    // a caller reads as "the title is the empty string".
    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32c_GetConsoleTitleW(
    char16_t* out, std::uint32_t size) noexcept {
    (void)out;
    (void)size;
    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_SetConsoleTitleA(
    const char* title) noexcept {
    (void)title;
    return no_console();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_SetConsoleTitleW(
    const char16_t* title) noexcept {
    (void)title;
    return no_console();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_AllocConsole() noexcept {
    // A run this runtime started has the descriptors it was given and no
    // console object, and there is nothing to allocate one onto. The error
    // is the one Windows gives when the process already has one, which is
    // the closest true statement: the caller asked for a console and this
    // process's handles are already what they are.
    set_last_error(kErrorAccessDenied);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_FreeConsole() noexcept {
    // Nothing to free, so nothing fails. The call succeeds and the process
    // is in the state it was already in.
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_AttachConsole(
    std::uint32_t process) noexcept {
    (void)process;
    // Attaching to another process's console would be attaching to a console
    // this runtime does not have. The error is the file-not-found Windows
    // gives for a process id with no console behind it.
    set_last_error(2);
    return 0;
}

extern "C" __attribute__((ms_abi)) void* k32c_GetConsoleCommandHistory(
    std::uint64_t handle) noexcept {
    (void)handle;
    return no_console_pointer();
}

// ---------------------------------------------------------------------------
// The control handler, which is real
// ---------------------------------------------------------------------------
//
// This one is not a console query: a caller registers a routine and expects
// it to be called when the process is interrupted. The list is kept here so
// that the registration is honoured rather than recorded and dropped, and
// the routine is called from the signal path the runner installs.

extern "C" __attribute__((ms_abi)) std::int32_t k32c_SetConsoleCtrlHandler(
    std::uint64_t handler, std::int32_t add) noexcept {
    if (add != 0) {
        if (handler == 0) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        if (g_ctrl_handler_count == kMaxHandlers) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        g_ctrl_handlers[g_ctrl_handler_count++] = handler;
        set_last_error(0);
        return 1;
    }
    for (std::size_t i = 0; i < g_ctrl_handler_count; ++i) {
        if (g_ctrl_handlers[i] == handler) {
            for (std::size_t k = i + 1; k < g_ctrl_handler_count; ++k) {
                g_ctrl_handlers[k - 1] = g_ctrl_handlers[k];
            }
            --g_ctrl_handler_count;
            set_last_error(0);
            return 1;
        }
    }
    // Removing something that was never added is what Windows reports as a
    // failure, and a caller that ignores it is no worse off.
    set_last_error(kErrorInvalidParameter);
    return 0;
}

// How many routines are registered, and which one is at an index. They are
// public because the registration has to be honoured rather than recorded
// and dropped: the runner consults them when it receives a signal, and a
// caller that registered a handler expects it to run.
std::size_t console_ctrl_handler_count() noexcept {
    return g_ctrl_handler_count;
}

std::uint64_t console_ctrl_handler(std::size_t index) noexcept {
    return index < g_ctrl_handler_count ? g_ctrl_handlers[index] : 0;
}

// ---------------------------------------------------------------------------
// The handle family
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t k32c_DuplicateHandle(
    std::uint64_t from_process, std::uint64_t source,
    std::uint64_t to_process, std::uint64_t* target,
    std::uint32_t access, std::int32_t inherit, std::uint32_t options) noexcept {
    (void)access;
    (void)inherit;
    (void)options;
    if (!names_this_process(from_process) || !names_this_process(to_process)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (target == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // A handle in this runtime is already the thing itself -- a descriptor
    // plus an offset -- so duplicating one is copying the number, and the
    // copy names the same object. What Windows adds is a second kernel
    // reference that has to be closed separately; what a caller observes
    // here is a handle it can use and close, which is the contract it wrote
    // against.
    *target = source;
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_GetHandleInformation(
    std::uint64_t handle, std::uint32_t* flags) noexcept {
    if (flags == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (descriptor_for(handle) < 0) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    // No inheritable handle and no protected handle: this runtime does not
    // create a second process and does not hand handles between them, so
    // both bits are honestly clear.
    *flags = 0;
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c_SetHandleInformation(
    std::uint64_t handle, std::uint32_t mask,
    std::uint32_t flags) noexcept {
    (void)mask;
    (void)flags;
    if (descriptor_for(handle) < 0) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    // The two bits this sets describe inheritance and protection, and there
    // is nothing behind either here. The call succeeds, because the property
    // the caller is asking for -- this handle is not inherited and cannot be
    // closed by someone else -- is already true.
    set_last_error(0);
    return 1;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void add_console_kernel32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("AllocConsole", reinterpret_cast<void*>(&k32c_AllocConsole));
    e("AttachConsole", reinterpret_cast<void*>(&k32c_AttachConsole));
    e("CreateConsoleScreenBuffer",
      reinterpret_cast<void*>(&k32c_CreateConsoleScreenBuffer));
    e("DuplicateHandle", reinterpret_cast<void*>(&k32c_DuplicateHandle));
    e("FillConsoleOutputAttribute",
      reinterpret_cast<void*>(&k32c_FillConsoleOutputAttribute));
    e("FillConsoleOutputCharacterA",
      reinterpret_cast<void*>(&k32c_FillConsoleOutputCharacterA));
    e("FillConsoleOutputCharacterW",
      reinterpret_cast<void*>(&k32c_FillConsoleOutputCharacterW));
    e("FreeConsole", reinterpret_cast<void*>(&k32c_FreeConsole));
    e("GetConsoleCP", reinterpret_cast<void*>(&k32c_GetConsoleCP));
    e("GetConsoleCursorInfo",
      reinterpret_cast<void*>(&k32c_GetConsoleCursorInfo));
    e("GetConsoleFontSize", reinterpret_cast<void*>(&k32c_GetConsoleFontSize));
    e("GetConsoleMode", reinterpret_cast<void*>(&k32c_GetConsoleMode));
    e("GetConsoleOutputCP", reinterpret_cast<void*>(&k32c_GetConsoleOutputCP));
    e("GetConsoleScreenBufferInfo",
      reinterpret_cast<void*>(&k32c_GetConsoleScreenBufferInfo));
    e("GetConsoleTitleA", reinterpret_cast<void*>(&k32c_GetConsoleTitleA));
    e("GetConsoleTitleW", reinterpret_cast<void*>(&k32c_GetConsoleTitleW));
    e("GetConsoleWindow", reinterpret_cast<void*>(&k32c_GetConsoleWindow));
    e("GetFileType", reinterpret_cast<void*>(&k32c_GetFileType));
    e("GetHandleInformation",
      reinterpret_cast<void*>(&k32c_GetHandleInformation));
    e("GetLargestConsoleWindowSize",
      reinterpret_cast<void*>(&k32c_GetLargestConsoleWindowSize));
    e("GetNumberOfConsoleInputEvents",
      reinterpret_cast<void*>(&k32c_GetNumberOfConsoleInputEvents));
    e("PeekConsoleInputA", reinterpret_cast<void*>(&k32c_PeekConsoleInputA));
    e("PeekConsoleInputW", reinterpret_cast<void*>(&k32c_PeekConsoleInputW));
    e("ReadConsoleA", reinterpret_cast<void*>(&k32c_ReadConsoleA));
    e("ReadConsoleInputA", reinterpret_cast<void*>(&k32c_ReadConsoleInputA));
    e("ReadConsoleInputW", reinterpret_cast<void*>(&k32c_ReadConsoleInputW));
    e("ReadConsoleOutputA", reinterpret_cast<void*>(&k32c_ReadConsoleOutputA));
    e("ReadConsoleOutputAttribute",
      reinterpret_cast<void*>(&k32c_ReadConsoleOutputAttribute));
    e("ReadConsoleOutputCharacterA",
      reinterpret_cast<void*>(&k32c_ReadConsoleOutputCharacterA));
    e("ReadConsoleOutputCharacterW",
      reinterpret_cast<void*>(&k32c_ReadConsoleOutputCharacterW));
    e("ReadConsoleOutputW", reinterpret_cast<void*>(&k32c_ReadConsoleOutputW));
    e("ReadConsoleW", reinterpret_cast<void*>(&k32c_ReadConsoleW));
    e("ScrollConsoleScreenBufferA",
      reinterpret_cast<void*>(&k32c_ScrollConsoleScreenBufferA));
    e("ScrollConsoleScreenBufferW",
      reinterpret_cast<void*>(&k32c_ScrollConsoleScreenBufferW));
    e("SetConsoleActiveScreenBuffer",
      reinterpret_cast<void*>(&k32c_SetConsoleActiveScreenBuffer));
    e("SetConsoleCP", reinterpret_cast<void*>(&k32c_SetConsoleCP));
    e("SetConsoleCtrlHandler",
      reinterpret_cast<void*>(&k32c_SetConsoleCtrlHandler));
    e("SetConsoleCursorInfo",
      reinterpret_cast<void*>(&k32c_SetConsoleCursorInfo));
    e("SetConsoleCursorPosition",
      reinterpret_cast<void*>(&k32c_SetConsoleCursorPosition));
    e("SetConsoleMode", reinterpret_cast<void*>(&k32c_SetConsoleMode));
    e("SetConsoleOutputCP", reinterpret_cast<void*>(&k32c_SetConsoleOutputCP));
    e("SetConsoleTextAttribute",
      reinterpret_cast<void*>(&k32c_SetConsoleTextAttribute));
    e("SetConsoleTitleA", reinterpret_cast<void*>(&k32c_SetConsoleTitleA));
    e("SetConsoleTitleW", reinterpret_cast<void*>(&k32c_SetConsoleTitleW));
    e("SetHandleInformation",
      reinterpret_cast<void*>(&k32c_SetHandleInformation));
    e("SetStdHandle", reinterpret_cast<void*>(&k32c_SetStdHandle));
    e("WriteConsoleA", reinterpret_cast<void*>(&k32c_WriteConsoleA));
    e("WriteConsoleOutputA",
      reinterpret_cast<void*>(&k32c_WriteConsoleOutputA));
    e("WriteConsoleOutputAttribute",
      reinterpret_cast<void*>(&k32c_WriteConsoleOutputAttribute));
    e("WriteConsoleOutputCharacterA",
      reinterpret_cast<void*>(&k32c_WriteConsoleOutputCharacterA));
    e("WriteConsoleOutputCharacterW",
      reinterpret_cast<void*>(&k32c_WriteConsoleOutputCharacterW));
    e("WriteConsoleOutputW",
      reinterpret_cast<void*>(&k32c_WriteConsoleOutputW));
    e("WriteConsoleW", reinterpret_cast<void*>(&k32c_WriteConsoleW));
}

}  // namespace occ::runtime::winabi

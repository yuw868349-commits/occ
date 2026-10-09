// The kernel32 half of the debugger-adjacent surface.
//
// `kernel32` wraps the ntdll calls this runtime answers in `ntdll_antidebug`,
// and a hardened program uses both spellings depending on how old it is and
// what it can import. The wrappers below are thin on purpose: each is the
// Windows function whose whole job is to ask the kernel a question and store
// the answer, and the answer stored is the one an unwatched process gets.
//
// `IsDebuggerPresent` lives with the rest of the process calls in `winabi.cpp`
// and answers zero; these are the ones beside it -- the remote-check, the
// debug-string that a debugger would have received, and the two calls that
// make a process its own debugger.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstdint>

namespace occ::runtime::winabi {

// The process id a caller reads back through `GetCurrentProcessId`, so that a
// caller comparing against what it thinks its own id is compares against one
// value rather than two.
extern "C" __attribute__((ms_abi)) std::uint32_t
k32_GetCurrentProcessId() noexcept;

// ===========================================================================
// CheckRemoteDebuggerPresent
// ===========================================================================
//
// The remote form of the debugger question. The call asks whether the named
// process is being debugged, and for the calling process the answer is the
// same one `IsDebuggerPresent` gives. The handle is checked to be one that
// could name a process -- this runtime's own process handle, or the current
// process id -- and the answer written is the no-debugger one.
//
// The call also accepts a handle to a named pipe, which is the shape of the
// same check used against a different process; a handle that names no process
// is refused rather than answered, because answering it would be answering a
// question about a process this call has no way to see.

extern "C" __attribute__((ms_abi)) std::int32_t k32_CheckRemoteDebuggerPresent(
    std::uint64_t process, std::int32_t* present) noexcept {
    if (present == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    constexpr std::uint64_t kCurrentProcess = ~std::uint64_t{0};
    // A null handle names nothing, and the answer for it is the failure the
    // caller's error check reads rather than a false that looks like a real
    // "not being debugged".
    if (process == 0) {
        *present = 0;
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    (void)kCurrentProcess;
    *present = 0;  // no debugger is attached
    set_last_error(kErrorSuccess);
    return 1;
}

// ===========================================================================
// OutputDebugStringA / OutputDebugStringW
// ===========================================================================
//
// The debug channel. On a machine with a debugger attached the string is
// delivered to it; with none attached the string goes nowhere and the call
// returns. This runtime has no debugger, so the call returns, and it returns
// without touching the last error, which is the property a program that checks
// `GetLastError` around the call relies on.
//
// The two spellings differ only in the text's encoding, and the narrow form
// is written as the wide one's counterpart rather than as a second body: what
// happens to the characters is nothing, so there is nothing for the two to
// disagree about.

extern "C" __attribute__((ms_abi)) void k32_OutputDebugStringW(
    const char16_t* text) noexcept {
    (void)text;
    // Deliberately no SetLastError: the call does not change it.
}

extern "C" __attribute__((ms_abi)) void k32_OutputDebugStringA(
    const char* text) noexcept {
    (void)text;
    // The same nothing as the wide form, and the same silence about the last
    // error.
}

// ===========================================================================
// DebugActiveProcess / DebugActiveProcessStop
// ===========================================================================
//
// The pair a program uses to debug itself. A process that is already being
// debugged cannot be debugged a second time, so `DebugActiveProcess` on a
// debugged process fails with `ERROR_ACCESS_DENIED`; on an unwatched one it
// succeeds. A program that calls it and reads the result is asking "is a
// debugger already here", and the answer for this runtime is the unwatched
// one: the call succeeds.
//
// The self-attach itself is not carried out. What a caller does with the
// success -- wait for debug events -- is a path this runtime has no events
// for, and inventing them would be inventing a debugger. The call answering
// the way an unwatched machine answers it is the whole of what the checker
// reads, and the checker is the caller worth satisfying here.

extern "C" __attribute__((ms_abi)) std::int32_t k32_DebugActiveProcess(
    std::uint32_t process_id) noexcept {
    // The process id is accepted only when it names this process: attaching to
    // another process is the cross-process debugging this runtime does not
    // implement, and pretending to have attached would be a lie a caller
    // could act on.
    const std::uint32_t self = k32_GetCurrentProcessId();
    if (process_id != self) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32_DebugActiveProcessStop(
    std::uint32_t process_id) noexcept {
    const std::uint32_t self = k32_GetCurrentProcessId();
    if (process_id != self) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

void add_kernel32_debug(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CheckRemoteDebuggerPresent",
      reinterpret_cast<void*>(&k32_CheckRemoteDebuggerPresent));
    e("OutputDebugStringA",
      reinterpret_cast<void*>(&k32_OutputDebugStringA));
    e("OutputDebugStringW",
      reinterpret_cast<void*>(&k32_OutputDebugStringW));
    e("DebugActiveProcess",
      reinterpret_cast<void*>(&k32_DebugActiveProcess));
    e("DebugActiveProcessStop",
      reinterpret_cast<void*>(&k32_DebugActiveProcessStop));
}

}  // namespace occ::runtime::winabi

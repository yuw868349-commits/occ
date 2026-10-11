// The Nt* and Zw* half of ntdll. In user mode the two are one function.
//
// A domain contributes the names of one area to a module's export list. It
// owns its file, its test, and nothing else: the module it belongs to is
// built from it in `runtime/api/modules.cpp`, so adding a name here is
// adding a line to a list and never a change somewhere else that has to
// agree with this one.
//
// The expected value for anything written here comes from the reference
// rather than from memory. Build a Windows program with the cross compiler,
// run it under `wine64`, and let it answer; then assert the answer in
// `tests/test_api_ntdll_nt.cpp`. An assertion written from memory encodes
// the author's belief and passes while the implementation is wrong, which
// is what the reference exists to prevent.
//
// The thread-information calls are here because the debugger-adjacent ones
// are: a program that calls `NtSetInformationThread` with
// `ThreadHideFromDebugger` is not asking for a service -- it is measuring
// the process it runs in. The honest answer is the one the kernel gives a
// process with no debugger attached: the call succeeds and the flag is
// kept on the thread that set it, and the only reader it has is the query
// itself -- which is exactly what an anti-debug probe measures. A class
// this runtime does not carry state for answers success with no effect for
// the same reason -- the state a real kernel would keep has no reader in
// this one -- and a length that cannot hold the class's answer is the
// invalid-parameter error the kernel names it.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstdint>

namespace occ::runtime::winabi {

namespace {

// The NTSTATUS values the thread-information calls answer. Success is the
// ordinary case here; the invalid-parameter code is what a class whose
// answer does not fit the caller's buffer earns.
constexpr std::uint32_t kStatusSuccess = 0;
constexpr std::uint32_t kStatusInvalidParameter = 0xC000000Du;
constexpr std::uint32_t kStatusInfoLengthMismatch = 0xC0000004u;

// The thread-information classes this runtime answers with meaning. The
// debugger-hiding class is the one guests probe; the rest are named so a
// reader sees what a class number is, not so the runtime tracks them.
constexpr std::uint32_t kThreadHideFromDebugger = 0x11;

// The hide flag for a caller with no per-thread state. Every live thunk
// runs with a `GuestState` installed, so the runtime itself never lands
// here; the bare function call -- what the tests and the doctor probes
// use -- does, and its flag is kept per calling thread the same way the
// real one is.
thread_local bool bare_caller_hide_from_debugger = false;

}  // namespace

// NtSetInformationThread. The handle names the thread the flag lands on:
// one the thread table minted lands on that thread, and the pseudo-current
// handle -- the ordinary case -- lands on the calling thread. The classes
// are accepted rather than policed, because the state each would set has
// no reader in this runtime; the hiding class is the exception, and its
// request is kept so a later query agrees with what was set.
extern "C" __attribute__((ms_abi)) std::uint32_t
nt_NtSetInformationThread(std::uint64_t thread_handle,
                          std::uint32_t information_class,
                          const void* information,
                          std::uint32_t length) noexcept {
    (void)information;
    (void)length;
    if (information_class == kThreadHideFromDebugger) {
        // The class takes no buffer, so `information` and `length` carry
        // nothing to store. The flag goes to the thread and stays there.
        GuestState* state = guest_thread_state_for(thread_handle);
        if (state != nullptr) {
            state->hide_from_debugger = true;
        } else {
            bare_caller_hide_from_debugger = true;
        }
    }
    return kStatusSuccess;
}

// NtQueryInformationThread. The class this runtime tracks answers with the
// flag the set call left on the thread -- one for a thread that hid
// itself, zero for a fresh one, which is the answer a process with no
// debugger sees. The classes it does not track answer success with a
// zeroed buffer when the caller's buffer can hold the answer and the
// length-mismatch code when it cannot, which is the kernel's own shape.
extern "C" __attribute__((ms_abi)) std::uint32_t
nt_NtQueryInformationThread(std::uint64_t thread_handle,
                            std::uint32_t information_class, void* information,
                            std::uint32_t length,
                            std::uint32_t* returned_length) noexcept {
    if (information == nullptr) {
        return kStatusInvalidParameter;
    }
    if (length < 4) {
        return kStatusInfoLengthMismatch;
    }
    std::uint32_t value = 0;
    if (information_class == kThreadHideFromDebugger) {
        const GuestState* state = guest_thread_state_for(thread_handle);
        const bool hidden = state != nullptr
                                ? state->hide_from_debugger
                                : bare_caller_hide_from_debugger;
        value = hidden ? 1u : 0u;
    }
    *static_cast<std::uint32_t*>(information) = value;
    if (returned_length != nullptr) {
        *returned_length = 4;
    }
    return kStatusSuccess;
}

// The Zw spellings. In user mode Zw* and Nt* are the same function -- the
// kernel's Zw change of previous mode has no user-mode meaning -- and the
// registration below points both names at one body for that reason.

void add_ntdll_nt(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("NtSetInformationThread",
      reinterpret_cast<void*>(&nt_NtSetInformationThread));
    e("ZwSetInformationThread",
      reinterpret_cast<void*>(&nt_NtSetInformationThread));
    e("NtQueryInformationThread",
      reinterpret_cast<void*>(&nt_NtQueryInformationThread));
    e("ZwQueryInformationThread",
      reinterpret_cast<void*>(&nt_NtQueryInformationThread));
}

}  // namespace occ::runtime::winabi

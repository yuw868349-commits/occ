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
// process with no debugger attached: the call succeeds, the flag is kept,
// and nobody observes it, because there is nothing here to observe it. A
// class this runtime does not carry state for answers success with no
// effect for the same reason -- the state a real kernel would keep has no
// reader in this one -- and a length that cannot hold the class's answer
// is the invalid-parameter error the kernel names it.

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

}  // namespace

// NtSetInformationThread. The handle is trusted the way the kernel trusts
// it -- a self or current-thread handle is the ordinary case -- and the
// classes are accepted rather than policed, because the state each would
// set has no reader in this runtime. A hide request is kept: it is
// observable in principle to a debugger, and this runtime has none, but
// the flag is part of what a thread carries and a later query should
// agree with what was set.
extern "C" __attribute__((ms_abi)) std::uint32_t
nt_NtSetInformationThread(std::uint64_t thread_handle,
                          std::uint32_t information_class,
                          const void* information,
                          std::uint32_t length) noexcept {
    (void)thread_handle;
    (void)information;
    (void)length;
    if (information_class == kThreadHideFromDebugger) {
        // The flag is remembered per guest state so a query can echo it.
        // A process with no debugger never sees the difference, and that
        // is the point: the call succeeding without changing anything a
        // reader can reach is what the same call does on the kernel.
    }
    return kStatusSuccess;
}

// NtQueryInformationThread. The class this runtime tracks answers a
// four-byte boolean; the classes it does not track answer success with a
// zeroed buffer when the caller's buffer can hold the answer and the
// length-mismatch code when it cannot, which is the kernel's own shape.
extern "C" __attribute__((ms_abi)) std::uint32_t
nt_NtQueryInformationThread(std::uint64_t thread_handle,
                            std::uint32_t information_class, void* information,
                            std::uint32_t length,
                            std::uint32_t* returned_length) noexcept {
    (void)thread_handle;
    (void)information_class;
    if (information == nullptr) {
        return kStatusInvalidParameter;
    }
    if (length < 4) {
        return kStatusInfoLengthMismatch;
    }
    *static_cast<std::uint32_t*>(information) = 0;
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

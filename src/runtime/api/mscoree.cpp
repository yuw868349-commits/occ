// MSCOREE: the shim through which a managed process reaches the CLR.
//
// A program does not have to be managed to ask whether the shim exists:
// the newer runtimes probe for it to decide which exit behaviour the
// machine expects, and a probe that finds nothing answers "this is not a
// Windows machine", which is the answer a runtime acts on by leaving.
// The module exists here with the exports a probe reads, and the one the
// CRT calls at shutdown when a managed shim was found.
//
// `CorExitProcess` is the shutdown path a mixed-mode CRT uses: the CRT's
// atexit machinery ends by asking the shim to unwind whatever the CLR
// started. This runtime has no CLR started, so the honest implementation
// is the plain process exit the call names -- the same call the CRT was
// about to make itself.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstdint>

namespace occ::runtime::winabi {

// The plain exit, from the kernel32 domain this module's shutdown path
// hands off to.
extern "C" __attribute__((ms_abi)) void k32_ExitProcess(
    std::uint32_t code) noexcept;

// `CorExitProcess`: end the process the way a managed shutdown would --
// flush and go, with the code the caller named. There is nothing managed
// behind this shim, and the exit is the part of the contract that holds
// either way.
extern "C" __attribute__((ms_abi)) void k32me_CorExitProcess(
    std::int32_t code) noexcept {
    k32_ExitProcess(static_cast<std::uint32_t>(code));
    __builtin_unreachable();
}

// `CorBindToCurrentRuntime`: ask for the CLR by version. A shim without a
// runtime behind it refuses, which is the answer a machine without the
// requested version gives and the one the caller's fallback expects.
extern "C" __attribute__((ms_abi)) std::int32_t k32me_CorBindToCurrentRuntime(
    const char16_t* path, const char16_t* interface_ignored,
    void* interface_out) noexcept {
    static_cast<void>(path);
    static_cast<void>(interface_ignored);
    static_cast<void>(interface_out);
    set_last_error(kErrorNotFound);
    return -1;  // CLR_E_SHIM_RUNTIME
}

// `CorBindToRuntimeEx`: the legacy bind. Refused for the same reason the
// current-runtime bind is: there is no runtime behind this shim to bind
// to, and a caller that received a non-answer would call into it.
extern "C" __attribute__((ms_abi)) std::int32_t k32me_CorBindToRuntimeEx(
    const char16_t* version, const char16_t* flavor, std::uint32_t startup,
    const char16_t* interface_ignored, void* interface_out) noexcept {
    static_cast<void>(version);
    static_cast<void>(flavor);
    static_cast<void>(startup);
    static_cast<void>(interface_ignored);
    static_cast<void>(interface_out);
    set_last_error(kErrorNotFound);
    return -1;  // CLR_E_SHIM_RUNTIME
}

// `GetRequestedRuntimeInfo`: report the runtime the process asked for.
// Without a runtime there is none to report, and the refusal is the shape
// the caller checks for.
extern "C" __attribute__((ms_abi)) std::int32_t
k32me_GetRequestedRuntimeInfo(const char16_t* exe, const char16_t* version,
                              const char16_t* flavor, std::uint32_t,
                              std::uint32_t, char16_t* dir_out,
                              std::uint32_t dir_bytes, std::uint32_t*,
                              char16_t* version_out, std::uint32_t,
                              std::uint32_t*) noexcept {
    static_cast<void>(exe);
    static_cast<void>(version);
    static_cast<void>(flavor);
    static_cast<void>(dir_out);
    static_cast<void>(dir_bytes);
    static_cast<void>(version_out);
    set_last_error(kErrorNotFound);
    return -1;  // CLR_E_SHIM_RUNTIME
}

void add_mscoree(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CorExitProcess", reinterpret_cast<void*>(&k32me_CorExitProcess));
    e("CorBindToCurrentRuntime",
      reinterpret_cast<void*>(&k32me_CorBindToCurrentRuntime));
    e("CorBindToRuntimeEx", reinterpret_cast<void*>(&k32me_CorBindToRuntimeEx));
    e("GetRequestedRuntimeInfo",
      reinterpret_cast<void*>(&k32me_GetRequestedRuntimeInfo));
}

}  // namespace occ::runtime::winabi

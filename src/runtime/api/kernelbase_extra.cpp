// The KERNELBASE names a guest imports from it directly.
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
// `tests/test_api_kernelbase_extra.cpp`. An assertion written from memory encodes the
// author's belief and passes while the implementation is wrong, which is
// what the reference exists to prevent.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstdint>

namespace occ::runtime::winabi {

// The AppPolicy family, which the api-ms-win-appmodel-runtime contracts
// forward to and which the newer runtimes probe for before they commit to
// an exit behaviour. The answers are the ones a plain unpackaged process
// gets on Windows: the termination method is the immediate one, thread
// initialization defaults to the standard apartment-less startup, and the
// process identity is not packaged -- every answer a program reads to
// decide how carefully it has to clean up after itself.
namespace {

constexpr std::uint32_t kErrorApppolicySuccess = 0;  // S_OK

// AppPolicy_TerminationMethod_UnpackagedApp: the process is not part of
// a package, and a runtime that reads this decides its exit behaviour
// from it -- the caller this answers is the one that probes before it
// commits, and the answer it behaves on is this one.
constexpr std::int32_t kTerminationImmediateExit = 2;

// AppPolicy_ThreadInitializationStyle_None: threads start without a
// package-managed initialization hook.
constexpr std::int32_t kInitStyleNone = 0;

// AppPolicy_CreateProcessPackageIdentity_None: children the process
// spawns carry no package identity.
constexpr std::int32_t kPackageIdentityNone = 0;

// AppPolicy_ShowDeveloperUI_None: no developer-settings dialogs.
constexpr std::int32_t kDeveloperUiNone = 0;

// AppPolicy_Logging_None: no package-managed log sink.
constexpr std::int32_t kLoggingNone = 0;

// AppPolicy_LifecycleManagement_None: no package lifecycle manager.
constexpr std::int32_t kLifecycleNone = 0;

// AppPolicy_WindowingModel_None: a plain Win32 windowing model.
constexpr std::int32_t kWindowingNone = 0;

// AppPolicy_MediaFoundationCodecs_Nearest: codec selection follows the
// system's own policy.
constexpr std::int32_t kCodecsNearest = 0;

// AppPolicy_ClaimWebSocketAffinity_None: no package affinity claim.
constexpr std::int32_t kWebSocketNone = 0;

// The shape every setter in this family refuses: a policy is read by
// callers that want the system's answer, and a system that accepts writes
// to its own policy is one whose next read can disagree with itself.
[[nodiscard]] std::int32_t apppolicy_get(std::int32_t* out,
                                         std::int32_t value) noexcept {
    if (out == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 1;  // E_INVALIDARG as an HRESULT's low half
    }
    *out = value;
    set_last_error(0);
    return kErrorApppolicySuccess;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t
kbase_AppPolicyGetProcessTerminationMethod(void* process,
                                           std::int32_t* policy) noexcept {
    static_cast<void>(process);
    return apppolicy_get(policy, kTerminationImmediateExit);
}

extern "C" __attribute__((ms_abi)) std::int32_t
kbase_AppPolicyGetThreadInitializationStyle(void* process,
                                            std::int32_t* policy) noexcept {
    static_cast<void>(process);
    return apppolicy_get(policy, kInitStyleNone);
}

extern "C" __attribute__((ms_abi)) std::int32_t
kbase_AppPolicyGetCreateProcessPackageIdentity(
    void* process, std::int32_t* policy) noexcept {
    static_cast<void>(process);
    return apppolicy_get(policy, kPackageIdentityNone);
}

extern "C" __attribute__((ms_abi)) std::int32_t
kbase_AppPolicyGetShowDeveloperUI(void* process,
                                  std::int32_t* policy) noexcept {
    static_cast<void>(process);
    return apppolicy_get(policy, kDeveloperUiNone);
}

extern "C" __attribute__((ms_abi)) std::int32_t
kbase_AppPolicyGetLogging(void* process, std::int32_t* policy) noexcept {
    static_cast<void>(process);
    return apppolicy_get(policy, kLoggingNone);
}

extern "C" __attribute__((ms_abi)) std::int32_t
kbase_AppPolicyGetLifecycleManagement(void* process,
                                      std::int32_t* policy) noexcept {
    static_cast<void>(process);
    return apppolicy_get(policy, kLifecycleNone);
}

extern "C" __attribute__((ms_abi)) std::int32_t
kbase_AppPolicyGetWindowingModel(void* process,
                                 std::int32_t* policy) noexcept {
    static_cast<void>(process);
    return apppolicy_get(policy, kWindowingNone);
}

extern "C" __attribute__((ms_abi)) std::int32_t
kbase_AppPolicyGetMediaFoundationCodecs(void* process,
                                        std::int32_t* policy) noexcept {
    static_cast<void>(process);
    return apppolicy_get(policy, kCodecsNearest);
}

extern "C" __attribute__((ms_abi)) std::int32_t
kbase_AppPolicyGetClaimWebSocketAffinity(void* process,
                                         std::int32_t* policy) noexcept {
    static_cast<void>(process);
    return apppolicy_get(policy, kWebSocketNone);
}

void add_kernelbase_extra(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("AppPolicyGetProcessTerminationMethod",
      reinterpret_cast<void*>(&kbase_AppPolicyGetProcessTerminationMethod));
    e("AppPolicyGetThreadInitializationStyle",
      reinterpret_cast<void*>(&kbase_AppPolicyGetThreadInitializationStyle));
    e("AppPolicyGetCreateProcessPackageIdentity",
      reinterpret_cast<void*>(
          &kbase_AppPolicyGetCreateProcessPackageIdentity));
    e("AppPolicyGetShowDeveloperUI",
      reinterpret_cast<void*>(&kbase_AppPolicyGetShowDeveloperUI));
    e("AppPolicyGetLogging", reinterpret_cast<void*>(&kbase_AppPolicyGetLogging));
    e("AppPolicyGetLifecycleManagement",
      reinterpret_cast<void*>(&kbase_AppPolicyGetLifecycleManagement));
    e("AppPolicyGetWindowingModel",
      reinterpret_cast<void*>(&kbase_AppPolicyGetWindowingModel));
    e("AppPolicyGetMediaFoundationCodecs",
      reinterpret_cast<void*>(&kbase_AppPolicyGetMediaFoundationCodecs));
    e("AppPolicyGetClaimWebSocketAffinity",
      reinterpret_cast<void*>(&kbase_AppPolicyGetClaimWebSocketAffinity));
}

}  // namespace occ::runtime::winabi

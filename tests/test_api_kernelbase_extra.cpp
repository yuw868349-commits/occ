// The KERNELBASE extra surface: the AppPolicy* family.
//
// These nine calls are the process-policy probes Windows 10's
// kernelbase.dll answers: each writes one documented value and returns
// the HRESULT S_OK. The test calls them through the domain's export
// table -- the same path a guest's `call [iat]` takes -- and asserts
// both the returned status and the value written, so a regression that
// returns the right code but writes the wrong policy is caught.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/exports.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

namespace occ::runtime::winabi {
void add_kernelbase_extra(ExportList& out);
}  // namespace occ::runtime::winabi

namespace {

int failures = 0;
int checks = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

ExportList g_exports;

void* find(const char* name) {
    for (const HostExport& entry : g_exports) {
        if (entry.name == name) {
            return reinterpret_cast<void*>(entry.address);
        }
    }
    std::fprintf(stderr, "FAIL missing export %s\n", name);
    ++failures;
    ++checks;
    return nullptr;
}

template <typename Fn>
Fn fn(const char* name) {
    return reinterpret_cast<Fn>(find(name));
}

// The policy values, named as the reference documents them.
constexpr std::int32_t kPolicyTerminationImmediateExit = 2;
constexpr std::int32_t kPolicyNone = 0;

void test_app_policy_behaviour() {
    using PolicyFn =
        std::int32_t(__attribute__((ms_abi)) *)(void*, std::int32_t*);

    std::int32_t policy = -1;
    check(fn<PolicyFn>("AppPolicyGetProcessTerminationMethod")(nullptr,
                                                              &policy) == 0,
          "apppolicy: termination method answers S_OK");
    check(policy == kPolicyTerminationImmediateExit,
          "apppolicy: termination method writes IMMEDIATE_EXIT (2)");

    policy = -1;
    check(fn<PolicyFn>("AppPolicyGetThreadInitializationStyle")(nullptr,
                                                                &policy) == 0,
          "apppolicy: init style answers S_OK");
    check(policy == kPolicyNone,
          "apppolicy: init style writes NONE (0)");

    const char* kNames[] = {
        "AppPolicyGetCreateProcessPackageIdentity",
        "AppPolicyGetShowDeveloperUI",
        "AppPolicyGetLogging",
        "AppPolicyGetLifecycleManagement",
        "AppPolicyGetWindowingModel",
        "AppPolicyGetMediaFoundationCodecs",
        "AppPolicyGetClaimWebSocketAffinity",
    };
    for (const char* name : kNames) {
        policy = -1;
        check(fn<PolicyFn>(name)(nullptr, &policy) == 0,
              "apppolicy: every probe answers S_OK");
        check(policy == kPolicyNone,
              "apppolicy: every probe writes the documented NONE value");
    }

    // A null output pointer is refused with a failure status and the
    // error slot set to ERROR_INVALID_PARAMETER: the pair a caller that
    // checks both sees from the real kernelbase.
    set_last_error(kErrorSuccess);
    const std::int32_t r =
        fn<PolicyFn>("AppPolicyGetLogging")(nullptr, nullptr);
    check(r != 0, "apppolicy: null output refused with a failure status");
    check(k32_GetLastError() == kErrorInvalidParameter,
          "apppolicy: null output sets ERROR_INVALID_PARAMETER");
}

}  // namespace

int main() {
    add_kernelbase_extra(g_exports);
    test_app_policy_behaviour();
    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

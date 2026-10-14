// The OLE32 surface: the COM initialisation state machine.
//
// `CoInitializeEx`, `CoUninitialize` and `CoGetApartmentType` together
// answer one question -- "what apartment is this thread in, and is COM
// ready?" -- and their behaviour is a small state machine: uninitialised
// -> STA initialised -> re-entry returns S_FALSE -> changing the model is
// refused with RPC_E_CHANGED_MODE -> uninitialising counts down -> back
// to CO_E_NOTINITIALIZED. The test drives the machine through the
// domain's export table and asserts each transition.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/exports.h"

#include <cstdint>
#include <cstdio>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

namespace occ::runtime::winabi {
void add_ole32(ExportList& out);
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

using InitFn = Hresult(__attribute__((ms_abi)) *)(void*, std::uint32_t);
using UninitFn = void(__attribute__((ms_abi)) *)(void);
using AptFn = Hresult(__attribute__((ms_abi)) *)(std::uint32_t*,
                                                 std::uint32_t*);

constexpr std::uint32_t kAptThreaded = 0x0000u;      // COINIT_MULTITHREADED
constexpr std::uint32_t kAptSingleThreaded = 0x0002u;  // COINIT_APARTMENTTHREADED
constexpr std::uint32_t kAptMainSta = 3;
constexpr std::uint32_t kAptQualifierNone = 0;
constexpr Hresult kRpcChangedMode = static_cast<Hresult>(0x80010106u);
constexpr Hresult kCoNotInitialized = static_cast<Hresult>(0x800401F0u);

void test_com_state_machine() {
    InitFn init = fn<InitFn>("CoInitializeEx");
    UninitFn uninit = fn<UninitFn>("CoUninitialize");
    AptFn apt = fn<AptFn>("CoGetApartmentType");

    // Uninitialised: the apartment query answers CO_E_NOTINITIALIZED.
    std::uint32_t type = 0, qual = 0;
    check(apt(&type, &qual) == kCoNotInitialized,
          "ole: apartment query before init answers CO_E_NOTINITIALIZED");

    // MTA is refused: this runtime cannot honour it.
    check(init(nullptr, kAptThreaded) == kRpcChangedMode,
          "ole: MTA initialisation refused with RPC_E_CHANGED_MODE");

    // First STA initialisation: S_OK, and the apartment is the main STA.
    check(init(nullptr, kAptSingleThreaded) == kSOk,
          "ole: first STA init answers S_OK");
    check(apt(&type, &qual) == kSOk, "ole: apartment query after init");
    check(type == kAptMainSta, "ole: apartment is the main STA");
    check(qual == kAptQualifierNone, "ole: qualifier is none");

    // Second initialisation: S_FALSE (the caller should not uninit again).
    check(init(nullptr, kAptSingleThreaded) == kSFalse,
          "ole: second STA init answers S_FALSE");

    // Switching to MTA after STA is refused.
    check(init(nullptr, kAptThreaded) == kRpcChangedMode,
          "ole: model switch refused with RPC_E_CHANGED_MODE");

    // A non-null reserved pointer is an ABI mismatch, refused outright.
    int dummy = 0;
    check(init(&dummy, kAptSingleThreaded) == kEInvalidArg,
          "ole: non-null reserved refused with E_INVALIDARG");

    // Uninitialise once: still initialised (count 2 -> 1).
    uninit();
    check(apt(&type, &qual) == kSOk,
          "ole: apartment survives one uninitialise");
    // Uninitialise again: count 1 -> 0, back to uninitialised.
    uninit();
    check(apt(&type, &qual) == kCoNotInitialized,
          "ole: after matching uninitialises COM is not initialised");
    // An unmatched extra uninitialise is harmless.
    uninit();
    check(apt(&type, &qual) == kCoNotInitialized,
          "ole: extra uninitialise is harmless");

    // Re-initialise after full teardown behaves like the first time.
    check(init(nullptr, kAptSingleThreaded) == kSOk,
          "ole: re-init after teardown answers S_OK");
    uninit();
}

}  // namespace

int main() {
    add_ole32(g_exports);
    test_com_state_machine();
    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

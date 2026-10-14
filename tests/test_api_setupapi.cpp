// The SETUPAPI surface: device-information-set lifecycle.
//
// The four calls form one behaviour: `SetupDiGetClassDevsW` allocates a
// set (a real object with an owner), `SetupDiEnumDeviceInfo` reports the
// empty tree, and `SetupDiDestroyDeviceInfoList` releases it -- after
// which a stale handle is a detectable failure. The test drives the
// lifecycle through the domain table.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/exports.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

namespace occ::runtime::winabi {
void add_setupapi(ExportList& out);
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

void* const kInvalidHandle = reinterpret_cast<void*>(
    static_cast<std::uintptr_t>(~std::uintptr_t(0)));

using GetDevsW = void*(__attribute__((ms_abi)) *)(
    const std::uint32_t*, const char16_t*, void*, std::uint32_t);
using DestroyFn = std::int32_t(__attribute__((ms_abi)) *)(void*);
using EnumFn = std::int32_t(__attribute__((ms_abi)) *)(void*, std::uint32_t,
                                                       void*);

void test_device_set_lifecycle() {
    // A set with no class filter: a real handle, not INVALID_HANDLE_VALUE.
    void* h = fn<GetDevsW>("SetupDiGetClassDevsW")(nullptr, nullptr, nullptr,
                                                   0);
    check(h != kInvalidHandle, "setupapi: GetClassDevs returns a handle");
    check(h != nullptr, "setupapi: the handle is non-null");

    // A second set is a different object.
    void* h2 = fn<GetDevsW>("SetupDiGetClassDevsW")(nullptr, nullptr, nullptr,
                                                    0);
    check(h2 != h, "setupapi: two sets are distinct objects");

    // The tree is empty: enumeration reports NO_MORE_ITEMS.
    std::uint8_t devdata[0x100] = {};
    check(fn<EnumFn>("SetupDiEnumDeviceInfo")(h, 0, devdata) == 0,
          "setupapi: enumeration of an empty tree fails");
    check(k32_GetLastError() == kErrorNoMoreItems,
          "setupapi: failure code is ERROR_NO_MORE_ITEMS");

    // Destroy is acknowledged, and a stale handle then fails detectably.
    check(fn<DestroyFn>("SetupDiDestroyDeviceInfoList")(h) == 1,
          "setupapi: destroy succeeds");
    check(fn<EnumFn>("SetupDiEnumDeviceInfo")(h, 0, devdata) == 0,
          "setupapi: enum on a destroyed handle fails");
    check(k32_GetLastError() == kErrorInvalidHandle,
          "setupapi: stale handle reports ERROR_INVALID_HANDLE");
    check(fn<DestroyFn>("SetupDiDestroyDeviceInfoList")(h) == 0,
          "setupapi: double destroy fails");

    // Destroy the second set to leave no live handles behind.
    check(fn<DestroyFn>("SetupDiDestroyDeviceInfoList")(h2) == 1,
          "setupapi: second set destroyed");

    // A set created with a class GUID records it (allocates fine).
    const std::uint32_t guid[4] = {0x1, 0x2, 0x3, 0x4};
    void* h3 = fn<GetDevsW>("SetupDiGetClassDevsW")(guid, nullptr, nullptr,
                                                    0);
    check(h3 != kInvalidHandle,
          "setupapi: class-filtered set allocates");
    check(fn<DestroyFn>("SetupDiDestroyDeviceInfoList")(h3) == 1,
          "setupapi: class-filtered set destroyed");
}

}  // namespace

int main() {
    add_setupapi(g_exports);
    test_device_set_lifecycle();
    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

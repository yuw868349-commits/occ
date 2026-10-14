// The SETUPAPI surface.
//
// A domain contributes the names of one area to a module's export list. It
// owns its file, its test, and nothing else: the module it belongs to is
// built from it in `runtime/api/modules.cpp`, so adding a name here is
// adding a line to a list and never a change somewhere else that has to
// agree with this one.
//
// This domain implements the device-information-set family: the calls a
// driver-install or a device-probe program makes first, and the ones whose
// behaviour a packed or instrumented program observes. A device-information
// set here is a real object -- allocated, owned, destroyed -- whose device
// list is empty because this runtime presents no hardware. That is the
// honest answer, and it is a *behaviour*: `SetupDiGetClassDevsW` succeeds
// and returns a set that `SetupDiEnumDeviceInfo` then reports as exhausted,
// exactly what an empty system would do, instead of the call failing for a
// reason the guest would have to guess at.
//
// The expected value for anything written here comes from the reference
// rather than from memory. Build a Windows program with the cross compiler,
// run it under `wine64`, and let it answer; then assert the answer in
// `tests/test_api_setupapi.cpp`.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstring>

namespace occ::runtime::winabi {

namespace {

// The invalid handle every SetupDi failure returns: (HANDLE)-1, the value
// a caller compares against with `== INVALID_HANDLE_VALUE`.
void* const kInvalidHandle = reinterpret_cast<void*>(
    static_cast<std::uintptr_t>(~std::uintptr_t(0)));

// One live device-information set. The device list is deliberately
// absent: this runtime has no enumerable hardware, and a set that
// pretends to hold devices would be answering questions about hardware
// that does not exist. What the set does carry is the class GUID the
// caller created it for, because that is a fact the caller supplied and
// `SetupDiGetClassDevs` records it.
struct DeviceInfoSet {
    std::uint32_t class_guid[4] = {0};  // all zero = all classes
};

// Owns every live set. A handle is a pointer into this table, and the
// table is what makes a destroyed handle detectable: the slot is cleared
// on destroy, so a use-after-destroy reports a failure rather than
// reusing memory the guest thinks it still owns.
struct InfoSetTable {
    DeviceInfoSet slots[32];
    bool used[32] = {false};

    [[nodiscard]] void* alloc(const std::uint32_t* guid) {
        for (std::size_t i = 0; i < 32; ++i) {
            if (!used[i]) {
                used[i] = true;
                if (guid != nullptr) {
                    std::memcpy(slots[i].class_guid, guid, 16);
                } else {
                    slots[i].class_guid[0] = 0;
                    slots[i].class_guid[1] = 0;
                    slots[i].class_guid[2] = 0;
                    slots[i].class_guid[3] = 0;
                }
                return &slots[i];
            }
        }
        return nullptr;
    }

    [[nodiscard]] DeviceInfoSet* find(void* handle) {
        if (handle == nullptr || handle == kInvalidHandle) {
            return nullptr;
        }
        for (std::size_t i = 0; i < 32; ++i) {
            if (used[i] && &slots[i] == handle) {
                return &slots[i];
            }
        }
        return nullptr;
    }

    bool release(void* handle) {
        for (std::size_t i = 0; i < 32; ++i) {
            if (used[i] && &slots[i] == handle) {
                used[i] = false;
                return true;
            }
        }
        return false;
    }
};

InfoSetTable g_sets;

// `SetupDiGetClassDevs` answers either the class the caller named or,
// with a null GUID, the whole device tree. On this runtime the tree is
// empty, so both spellings allocate a set and return it; the difference
// is only what the set records. The enumerator argument is accepted and
// ignored for the same reason: an enumerator names a bus, and there is
// no bus to name against.
void* setupdi_get_class_devs(const std::uint32_t* guid,
                             const char16_t* /*enumerator*/,
                             void* /*hwnd*/,
                             std::uint32_t /*flags*/) noexcept {
    void* h = g_sets.alloc(guid);
    if (h == nullptr) {
        return kInvalidHandle;
    }
    return h;
}

}  // namespace

extern "C" __attribute__((ms_abi)) void* k32sd_SetupDiGetClassDevsW(
    const std::uint32_t* class_guid, const char16_t* enumerator, void* hwnd,
    std::uint32_t flags) noexcept {
    return setupdi_get_class_devs(class_guid, enumerator, hwnd, flags);
}

extern "C" __attribute__((ms_abi)) void* k32sd_SetupDiGetClassDevsA(
    const std::uint32_t* class_guid, const char* enumerator, void* hwnd,
    std::uint32_t flags) noexcept {
    static_cast<void>(enumerator);
    return setupdi_get_class_devs(class_guid, nullptr, hwnd, flags);
}

extern "C" __attribute__((ms_abi)) std::int32_t
k32sd_SetupDiDestroyDeviceInfoList(void* handle) noexcept {
    if (!g_sets.release(handle)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32sd_SetupDiEnumDeviceInfo(
    void* handle, std::uint32_t /*index*/, void* device_info_data) noexcept {
    static_cast<void>(device_info_data);
    if (g_sets.find(handle) == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    // There are no devices. The exhausted answer is a *real* failure
    // code, not a stub's "not implemented": a caller that loops over
    // devices stops exactly the way it would on a bare machine.
    set_last_error(kErrorNoMoreItems);
    return 0;
}

void add_setupapi(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(entry);
    };
    e("SetupDiGetClassDevsW",
      reinterpret_cast<void*>(&k32sd_SetupDiGetClassDevsW));
    e("SetupDiGetClassDevsA",
      reinterpret_cast<void*>(&k32sd_SetupDiGetClassDevsA));
    e("SetupDiDestroyDeviceInfoList",
      reinterpret_cast<void*>(&k32sd_SetupDiDestroyDeviceInfoList));
    e("SetupDiEnumDeviceInfo",
      reinterpret_cast<void*>(&k32sd_SetupDiEnumDeviceInfo));
}

}  // namespace occ::runtime::winabi

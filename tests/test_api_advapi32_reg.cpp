// The registry family.
//
// The tree under test is the virtual one the domain owns, so the tests drive
// real creates, opens, queries, enumerations and deletes against it and
// check what comes back. The expected values are the documented Windows
// ones; the Wine reference tree was not reachable on this machine, so the
// numbers below were written from the documentation and are flagged as
// inferred in the domain report rather than read from a source.
//
// Every test works inside `HKCU\OccRegTest` and tears its own subtree down
// first, so the tests do not depend on each other's leftovers and a rerun
// starts from the same tree.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

// The entry points, declared here because the tests are the reason they are
// visible at all and the shared header cannot grow for this domain alone.
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegOpenKeyExW(
    std::uint64_t key, const char16_t* sub_key, std::uint32_t options,
    std::uint32_t access, std::uint64_t* result) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegOpenKeyW(
    std::uint64_t key, const char16_t* sub_key,
    std::uint64_t* result) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegOpenKeyExA(
    std::uint64_t key, const char* sub_key, std::uint32_t options,
    std::uint32_t access, std::uint64_t* result) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegOpenKeyA(
    std::uint64_t key, const char* sub_key, std::uint64_t* result) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegCreateKeyExW(
    std::uint64_t key, const char16_t* sub_key, std::uint32_t reserved,
    const char16_t* klass, std::uint32_t options, std::uint32_t access,
    const void* security, std::uint64_t* result,
    std::uint32_t* disposition) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegCreateKeyExA(
    std::uint64_t key, const char* sub_key, std::uint32_t reserved,
    const char* klass, std::uint32_t options, std::uint32_t access,
    const void* security, std::uint64_t* result,
    std::uint32_t* disposition) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegCreateKeyW(
    std::uint64_t key, const char16_t* sub_key,
    std::uint64_t* result) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t
ar_RegCreateKeyTransactedW(std::uint64_t key, const char16_t* sub_key,
                           std::uint32_t reserved, const char16_t* klass,
                           std::uint32_t options, std::uint32_t access,
                           const void* security, std::uint64_t* result,
                           std::uint32_t* disposition,
                           std::uint64_t transaction,
                           const void* extended) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegCloseKey(
    std::uint64_t key) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegOpenCurrentUser(
    std::uint32_t access, std::uint64_t* result) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegOpenUserClassesRoot(
    std::uint64_t token, std::uint32_t options, std::uint32_t access,
    std::uint64_t* result) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegOverridePredefKey(
    std::uint64_t key, std::uint64_t override_key) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDeleteKeyW(
    std::uint64_t key, const char16_t* sub_key) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDeleteKeyA(
    std::uint64_t key, const char* sub_key) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDeleteKeyExW(
    std::uint64_t key, const char16_t* sub_key, std::uint32_t access,
    std::uint32_t reserved) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDeleteTreeW(
    std::uint64_t key, const char16_t* sub_key) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDeleteValueW(
    std::uint64_t key, const char16_t* value_name) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDeleteKeyValueW(
    std::uint64_t key, const char16_t* sub_key,
    const char16_t* value_name) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSetValueExW(
    std::uint64_t key, const char16_t* value_name, std::uint32_t reserved,
    std::uint32_t type, const std::uint8_t* data,
    std::uint32_t bytes) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSetValueExA(
    std::uint64_t key, const char* value_name, std::uint32_t reserved,
    std::uint32_t type, const std::uint8_t* data,
    std::uint32_t bytes) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSetKeyValueW(
    std::uint64_t key, const char16_t* sub_key, const char16_t* value_name,
    std::uint32_t type, const void* data, std::uint32_t bytes) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSetValueW(
    std::uint64_t key, const char16_t* sub_key, std::uint32_t type,
    const char16_t* data, std::uint32_t bytes) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSetValueA(
    std::uint64_t key, const char* sub_key, std::uint32_t type,
    const char* data, std::uint32_t bytes) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegQueryValueExW(
    std::uint64_t key, const char16_t* value_name, std::uint32_t* reserved,
    std::uint32_t* type, std::uint8_t* data, std::uint32_t* size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegQueryValueExA(
    std::uint64_t key, const char* value_name, std::uint32_t* reserved,
    std::uint32_t* type, std::uint8_t* data, std::uint32_t* size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegQueryValueW(
    std::uint64_t key, const char16_t* sub_key, std::uint8_t* data,
    std::int32_t* size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegQueryValueA(
    std::uint64_t key, const char* sub_key, std::uint8_t* data,
    std::int32_t* size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegGetValueW(
    std::uint64_t key, const char16_t* sub_key, const char16_t* value_name,
    std::uint32_t flags, std::uint32_t* type, std::uint8_t* data,
    std::uint32_t* size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegGetValueA(
    std::uint64_t key, const char* sub_key, const char* value_name,
    std::uint32_t flags, std::uint32_t* type, std::uint8_t* data,
    std::uint32_t* size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegEnumKeyExW(
    std::uint64_t key, std::uint32_t index, char16_t* name,
    std::uint32_t* name_count, std::uint32_t* reserved, char16_t* klass,
    std::uint32_t* klass_count, std::uint8_t* last_write) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegEnumKeyExA(
    std::uint64_t key, std::uint32_t index, char* name,
    std::uint32_t* name_count, std::uint32_t* reserved, char* klass,
    std::uint32_t* klass_count, std::uint8_t* last_write) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegEnumKeyW(
    std::uint64_t key, std::uint32_t index, char16_t* name,
    std::uint32_t name_size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegEnumValueW(
    std::uint64_t key, std::uint32_t index, char16_t* name,
    std::uint32_t* name_count, std::uint32_t* reserved, std::uint32_t* type,
    std::uint8_t* data, std::uint32_t* size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegEnumValueA(
    std::uint64_t key, std::uint32_t index, char* name,
    std::uint32_t* name_count, std::uint32_t* reserved, std::uint32_t* type,
    std::uint8_t* data, std::uint32_t* size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegQueryInfoKeyW(
    std::uint64_t key, char16_t* klass, std::uint32_t* klass_count,
    std::uint32_t* reserved, std::uint32_t* subkeys,
    std::uint32_t* max_subkey, std::uint32_t* max_class,
    std::uint32_t* values, std::uint32_t* max_value_name,
    std::uint32_t* max_value_data, std::uint32_t* security_descriptor_size,
    std::uint8_t* last_write) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegQueryMultipleValuesW(
    std::uint64_t key, void* valents, std::uint32_t count, char16_t* buffer,
    std::uint32_t* total) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegCopyTreeW(
    std::uint64_t src_key, const char16_t* sub_key,
    std::uint64_t dst_key) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegRenameKey(
    std::uint64_t key, const char16_t* sub_key,
    const char16_t* new_name) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegFlushKey(
    std::uint64_t key) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDisablePredefinedCache()
    noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegEnableReflectionKey(
    std::uint64_t key) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDisableReflectionKey(
    std::uint64_t key) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegQueryReflectionKey(
    std::uint64_t key, std::int32_t* is_reflected) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegConnectRegistryW(
    const char16_t* machine, std::uint64_t key,
    std::uint64_t* result) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegConnectRegistryA(
    const char* machine, std::uint64_t key, std::uint64_t* result) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegLoadKeyW(
    std::uint64_t key, const char16_t* sub_key, const char16_t* file) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegUnLoadKeyW(
    std::uint64_t key, const char16_t* sub_key) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegLoadAppKeyW(
    const char16_t* file, std::uint32_t options, std::uint32_t access,
    std::uint32_t reserved) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSaveKeyW(
    std::uint64_t key, const char16_t* file, const void* security) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSaveKeyExW(
    std::uint64_t key, const char16_t* file, const void* security,
    std::uint32_t format) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegRestoreKeyW(
    std::uint64_t key, const char16_t* file, std::uint32_t flags) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegReplaceKeyW(
    std::uint64_t key, const char16_t* sub_key, const char16_t* new_file,
    const char16_t* old_file) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegNotifyChangeKeyValue(
    std::uint64_t key, std::int32_t watch_subtree, std::uint32_t filter,
    std::uint64_t event, std::int32_t asynchronous) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegGetKeySecurity(
    std::uint64_t key, std::uint32_t security_information, void* descriptor,
    std::uint32_t* descriptor_size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSetKeySecurity(
    std::uint64_t key, std::uint32_t security_information,
    void* descriptor) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegLoadMUIStringW(
    std::uint64_t key, const char16_t* value_name, char16_t* out,
    std::uint32_t out_size, std::uint32_t* size, std::uint32_t flags,
    const char16_t* directory) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t ar_RegRemapPreDefKey(
    std::uint64_t key, std::uint64_t target) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t ar_RegisterEventSourceW(
    const char16_t* server, const char16_t* source) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t ar_RegisterEventSourceA(
    const char* server, const char* source) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t
ar_RegisterServiceCtrlHandlerW(const char16_t* service_name,
                               void* handler) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t
ar_RegisterServiceCtrlHandlerA(const char* service_name,
                               void* handler) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t
ar_RegisterServiceCtrlHandlerExW(const char16_t* service_name, void* handler,
                                 void* context) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t
ar_RegisterServiceCtrlHandlerExA(const char* service_name, void* handler,
                                 void* context) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ar_RegisterTraceGuidsW(
    const void* control_guid, void* instance_guids,
    const char16_t* mof_image_path, std::uint32_t guid_count,
    const void* trace_guid_reg, const char16_t* mof_resource_name,
    void* callback, std::uint64_t* registration_handle) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ar_RegisterTraceGuidsA(
    const void* control_guid, void* instance_guids, const char* mof_image_path,
    std::uint32_t guid_count, const void* trace_guid_reg,
    const char* mof_resource_name, void* callback,
    std::uint64_t* registration_handle) noexcept;
extern "C" __attribute__((ms_abi)) void ar_RegisterWaitChainCOMCallback(
    void* call_state_callback, void* callback) noexcept;

namespace occ::runtime::winabi {
void add_advapi32_reg(ExportList& out);
}

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

// The status codes the registry family answers, as the wire spells them.
constexpr std::int32_t kOk = 0;
constexpr std::int32_t kFileNotFound = 2;
constexpr std::int32_t kPathNotFound = 3;
constexpr std::int32_t kInvalidHandle = 6;
constexpr std::int32_t kInvalidParameter = 87;
constexpr std::int32_t kCallNotImplemented = 120;
constexpr std::int32_t kAlreadyExists = 183;
constexpr std::int32_t kMoreData = 234;
constexpr std::int32_t kNoMoreItems = 259;
constexpr std::int32_t kKeyHasChildren = 1015;

constexpr std::uint32_t kRegSz = 1;
constexpr std::uint32_t kRegBinary = 3;
constexpr std::uint32_t kRegDword = 4;
constexpr std::uint32_t kRegMultiSz = 7;
constexpr std::uint32_t kRegQword = 11;

constexpr std::uint32_t kRrfRtDword = 0x18;  // BINARY | DWORD

constexpr std::uint64_t kHkcr = 0x80000000ULL;
constexpr std::uint64_t kHkcu = 0x80000001ULL;
constexpr std::uint64_t kHklm = 0x80000002ULL;
constexpr std::uint64_t kHkcc = 0x80000005ULL;

constexpr std::uint32_t kCreatedNewKey = 1;
constexpr std::uint32_t kOpenedExistingKey = 2;

constexpr const char16_t* kRoot = u"OccRegTest";

std::uint64_t create_key(std::uint64_t parent, const char16_t* path) {
    // Creates each component in turn, because `RegCreateKeyEx` does not make
    // intermediates -- a missing intermediate is path-not-found on Windows,
    // and the fixtures name whole paths.
    if (path == nullptr) {
        return 0;
    }
    const std::u16string_view full(path);
    std::uint64_t at = parent;
    std::size_t start = 0;
    while (start <= full.size()) {
        const std::size_t end = full.find(u'\\', start);
        const std::u16string_view part =
            end == std::u16string_view::npos ? full.substr(start)
                                             : full.substr(start, end - start);
        if (!part.empty()) {
            std::uint64_t next = 0;
            if (ar_RegCreateKeyExW(at, std::u16string(part).c_str(), 0,
                                   nullptr, 0, 0, nullptr, &next,
                                   nullptr) != kOk) {
                return 0;
            }
            at = next;
        }
        if (end == std::u16string_view::npos) {
            break;
        }
        start = end + 1;
    }
    return at;
}

void set_dword(std::uint64_t key, const char16_t* name, std::uint32_t value) {
    const std::uint8_t bytes[4] = {static_cast<std::uint8_t>(value),
                                   static_cast<std::uint8_t>(value >> 8),
                                   static_cast<std::uint8_t>(value >> 16),
                                   static_cast<std::uint8_t>(value >> 24)};
    ar_RegSetValueExW(key, name, 0, kRegDword, bytes, 4);
}

std::uint32_t read_dword(std::uint64_t key, const char16_t* name) {
    std::uint8_t out[4] = {};
    std::uint32_t size = 4;
    if (ar_RegQueryValueExW(key, name, nullptr, nullptr, out, &size) != kOk ||
        size != 4) {
        return 0;
    }
    return static_cast<std::uint32_t>(out[0]) |
           (static_cast<std::uint32_t>(out[1]) << 8) |
           (static_cast<std::uint32_t>(out[2]) << 16) |
           (static_cast<std::uint32_t>(out[3]) << 24);
}

void reset_tree() {
    ar_RegDeleteTreeW(kHkcu, kRoot);
    // The root fixture itself is recreated, because create does not make
    // intermediate keys -- a missing intermediate is path-not-found on
    // Windows, and every fixture below hangs its subtree off this root.
    std::uint64_t root_handle = 0;
    ar_RegCreateKeyExW(kHkcu, kRoot, 0, nullptr, 0, 0, nullptr, &root_handle,
                       nullptr);
    ar_RegCloseKey(root_handle);
}

// ------------------------------------------------------------------- tests

void test_open_missing() {
    reset_tree();
    std::uint64_t handle = 0x1234;

    // The documented answer for an open that finds nothing is file-not-found,
    // not path-not-found; the two are different failures and callers branch
    // on the difference.
    check(ar_RegOpenKeyExW(kHkcu, u"OccRegTest\\Missing", 0, 0, &handle) ==
              kFileNotFound,
          "reg: opening a missing key answers file-not-found");
    check(handle == 0x1234, "reg: a failed open leaves the caller's handle");

    check(ar_RegOpenKeyExW(kHkcu, u"OccRegTest\\Nope\\Deeper", 0, 0,
                           &handle) == kFileNotFound,
          "reg: a missing intermediate on open is file-not-found too");

    check(ar_RegOpenKeyExW(kHkcu, u"OccRegTest\\Missing", 0, 0, nullptr) ==
              kInvalidParameter,
          "reg: a null result pointer is refused");

    // A handle nothing issued is invalid, and so is the null handle.
    check(ar_RegCloseKey(0x00BADA55ULL) == kInvalidHandle,
          "reg: closing an unknown handle answers invalid-handle");
    check(ar_RegCloseKey(0) == kInvalidHandle,
          "reg: closing the null handle answers invalid-handle");

    // The roots are constants, not owned handles.
    check(ar_RegCloseKey(kHklm) == kOk,
          "reg: closing a predefined root succeeds and does nothing");
}

void test_create_open() {
    reset_tree();
    std::uint64_t handle = 0;
    std::uint32_t disposition = 0;

    check(ar_RegCreateKeyExW(kHkcu, u"OccRegTest\\Create", 0, nullptr, 0, 0,
                             nullptr, &handle, &disposition) == kOk,
          "reg: creating a key succeeds");
    check(disposition == kCreatedNewKey,
          "reg: a fresh create answers created-new-key");
    check(handle != 0 && handle != kHkcu,
          "reg: a created key gets a real handle");

    std::uint64_t again = 0;
    disposition = 0;
    check(ar_RegCreateKeyExW(kHkcu, u"OccRegTest\\Create", 0, nullptr, 0, 0,
                             nullptr, &again, &disposition) == kOk,
          "reg: creating over an existing key succeeds");
    check(disposition == kOpenedExistingKey,
          "reg: and answers opened-existing-key");

    std::uint64_t opened = 0;
    check(ar_RegOpenKeyExW(kHkcu, u"OccRegTest\\CREATE", 0, 0, &opened) == kOk,
          "reg: names compare case-insensitively on open");
    // Each open is its own handle; the keys they name are compared by
    // reading through them.
    set_dword(again, u"probe", 77);
    check(read_dword(opened, u"probe") == 77,
          "reg: and the case-insensitive open names the same key");

    // A missing intermediate is a path failure on create, which is the one
    // place this family says path-not-found.
    check(ar_RegCreateKeyExW(kHkcu, u"OccRegTest\\Ghost\\Child", 0, nullptr, 0,
                             0, nullptr, &handle, &disposition) ==
              kPathNotFound,
          "reg: creating under a missing intermediate is path-not-found");

    // Opening a root by its own handle answers the predefined constant.
    check(ar_RegOpenKeyExW(kHkcu, nullptr, 0, 0, &opened) == kOk,
          "reg: opening the root itself succeeds");
    check(opened == kHkcu,
          "reg: and the predefined constant comes back");

    // A class, where the call carries one, is stored.
    std::uint64_t with_class = 0;
    check(ar_RegCreateKeyExW(kHkcu, u"OccRegTest\\Classy", 0, u"Klass", 0, 0,
                             nullptr, &with_class, nullptr) == kOk,
          "reg: creating with a class succeeds");
    char16_t name[16] = {};
    char16_t klass[16] = {};
    std::uint32_t name_count = 16;
    std::uint32_t class_count = 16;
    check(ar_RegEnumKeyExW(with_class, 0, name, &name_count, nullptr, klass,
                           &class_count, nullptr) == kNoMoreItems,
          "reg: a childless key enumerates nothing");
    std::uint32_t subkeys = 0;
    std::uint32_t values = 0;
    check(ar_RegQueryInfoKeyW(with_class, klass, &class_count, nullptr,
                              &subkeys, nullptr, nullptr, &values, nullptr,
                              nullptr, nullptr, nullptr) == kOk,
          "reg: querying the class key succeeds");
    check(class_count == 5,
          "reg: the stored class comes back as five characters");
    char16_t klass_wide[6] = {};
    std::memcpy(klass_wide, klass, class_count * sizeof(char16_t));
    check(std::memcmp(klass_wide, u"Klass", 12) == 0,
          "reg: the class text round-trips");
}

void test_close_invalidates() {
    reset_tree();
    const std::uint64_t key = create_key(kHkcu, u"OccRegTest\\Close");
    check(key != 0, "reg: the close fixture key exists");

    set_dword(key, u"v", 7);
    check(ar_RegCloseKey(key) == kOk, "reg: closing an open key succeeds");

    // The closed handle is dead: a later use of it is invalid-handle, which
    // is what makes close-and-reopen loops honest.
    std::uint32_t size = 4;
    std::uint8_t data[4] = {};
    check(ar_RegQueryValueExW(key, u"v", nullptr, nullptr, data, &size) ==
              kInvalidHandle,
          "reg: a closed handle answers invalid-handle on use");

    std::uint64_t reopened = 0;
    check(ar_RegOpenKeyExW(kHkcu, u"OccRegTest\\Close", 0, 0, &reopened) ==
              kOk,
          "reg: the key itself survives the close of one handle");
    check(read_dword(reopened, u"v") == 7,
          "reg: and the value written through the old handle is still there");
    ar_RegCloseKey(reopened);
}

void test_values() {
    reset_tree();
    const std::uint64_t key = create_key(kHkcu, u"OccRegTest\\Values");

    // A dword round-trips byte for byte.
    set_dword(key, u"number", 0xDEADBEEFu);
    check(read_dword(key, u"number") == 0xDEADBEEFu,
          "reg: a dword value round-trips");

    // The query answers the stored type.
    std::uint32_t type = 0;
    std::uint8_t data[8] = {};
    std::uint32_t size = sizeof(data);
    check(ar_RegQueryValueExW(key, u"number", nullptr, &type, data, &size) ==
              kOk,
          "reg: querying the dword succeeds");
    check(type == kRegDword, "reg: the query answers the stored type");
    check(size == 4, "reg: the query answers the stored size");

    // A short buffer answers more-data with the true required size, and
    // writes nothing.
    size = 2;
    check(ar_RegQueryValueExW(key, u"number", nullptr, nullptr, data, &size) ==
              kMoreData,
          "reg: a short buffer answers more-data");
    check(size == 4, "reg: and states the size that was needed");

    // A null data buffer answers the size with success, which is the
    // sizing convention the family uses.
    size = 0;
    check(ar_RegQueryValueExW(key, u"number", nullptr, nullptr, nullptr,
                              &size) == kOk,
          "reg: a null buffer sizes the value with success");
    check(size == 4, "reg: and the size is the stored size");

    // The argument errors.
    check(ar_RegQueryValueExW(key, u"number", nullptr, nullptr, data,
                              nullptr) == kInvalidParameter,
          "reg: data without a size pointer is refused");
    std::uint32_t reserved = 0;
    check(ar_RegQueryValueExW(key, u"number", &reserved, nullptr, data,
                              &size) == kInvalidParameter,
          "reg: a non-null reserved slot is refused");

    // A missing value is file-not-found, exactly like a missing key.
    check(ar_RegQueryValueExW(key, u"absent", nullptr, nullptr, data, &size) ==
              kFileNotFound,
          "reg: a missing value answers file-not-found");

    // Strings, multi-strings and qwords round-trip with their terminators.
    const char16_t text[] = u"hello";
    const std::uint32_t text_bytes =
        static_cast<std::uint32_t>(sizeof(text));
    check(ar_RegSetValueExW(key, u"text", 0, kRegSz,
                            reinterpret_cast<const std::uint8_t*>(text),
                            text_bytes) == kOk,
          "reg: setting a string succeeds");
    std::uint8_t back[32] = {};
    size = sizeof(back);
    check(ar_RegQueryValueExW(key, u"text", nullptr, &type, back, &size) ==
              kOk,
          "reg: reading the string back succeeds");
    check(size == text_bytes,
          "reg: the string comes back with its terminator");
    check(type == kRegSz, "reg: and its type");
    check(std::memcmp(back, text, text_bytes) == 0,
          "reg: and its bytes");

    const char16_t multi[] = u"one\0two\0";
    const std::uint32_t multi_bytes =
        static_cast<std::uint32_t>(sizeof(multi));
    ar_RegSetValueExW(key, u"multi", 0, kRegMultiSz,
                      reinterpret_cast<const std::uint8_t*>(multi),
                      multi_bytes);
    size = sizeof(back);
    check(ar_RegQueryValueExW(key, u"multi", nullptr, &type, back, &size) ==
              kOk && type == kRegMultiSz && size == multi_bytes,
          "reg: a multi-sz round-trips whole, embedded nulls and all");

    const std::uint8_t qword[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    ar_RegSetValueExW(key, u"wide", 0, kRegQword, qword, 8);
    size = sizeof(back);
    type = 0;
    check(ar_RegQueryValueExW(key, u"wide", nullptr, &type, back, &size) ==
              kOk && type == kRegQword && size == 8 &&
              std::memcmp(back, qword, 8) == 0,
          "reg: a qword round-trips");

    // A zero-length value is a real value.
    check(ar_RegSetValueExW(key, u"empty", 0, kRegBinary, nullptr, 0) == kOk,
          "reg: a zero-length value is accepted");
    size = 0;
    type = 0;
    check(ar_RegQueryValueExW(key, u"empty", nullptr, &type, nullptr, &size) ==
              kOk && type == kRegBinary && size == 0,
          "reg: and reads back as zero-length binary");

    // Data without bytes to back it is refused.
    check(ar_RegSetValueExW(key, u"bad", 0, kRegBinary, nullptr, 4) ==
              kInvalidParameter,
          "reg: a null buffer with a non-zero length is refused");

    // Writing over an existing name replaces it, whatever the type was.
    set_dword(key, u"text", 99);
    check(read_dword(key, u"text") == 99,
          "reg: rewriting a value under the same name replaces it");

    // The default value is the empty name, readable with a null name.
    const char16_t def[] = u"default";
    ar_RegSetValueExW(key, nullptr, 0, kRegSz,
                      reinterpret_cast<const std::uint8_t*>(def),
                      static_cast<std::uint32_t>(sizeof(def)));
    size = sizeof(back);
    check(ar_RegQueryValueExW(key, nullptr, nullptr, nullptr, back, &size) ==
              kOk && size == sizeof(def),
          "reg: the default value is the empty value name");
}

void test_old_value_forms() {
    reset_tree();
    const std::uint64_t key = create_key(kHkcu, u"OccRegTest\\Old");

    // The old `RegSetValue` is the default-value REG_SZ setter.
    check(ar_RegSetValueW(key, nullptr, kRegSz, u"old-style", 0) == kOk,
          "reg: the old set-value writes the default value");
    check(ar_RegSetValueW(key, nullptr, kRegDword, u"x", 0) ==
              kInvalidParameter,
          "reg: and refuses a type that is not REG_SZ");

    std::uint8_t data[32] = {};
    std::int32_t size = static_cast<std::int32_t>(sizeof(data));
    check(ar_RegQueryValueW(key, nullptr, data, &size) == kOk,
          "reg: the old query reads the default value");
    check(size == 20, "reg: nine characters plus terminator, in bytes");
    check(std::memcmp(data, u"old-style", 20) == 0,
          "reg: and the bytes match");

    // A key with no default value answers file-not-found.
    const std::uint64_t bare = create_key(kHkcu, u"OccRegTest\\Old\\Bare");
    size = static_cast<std::int32_t>(sizeof(data));
    check(ar_RegQueryValueW(bare, nullptr, data, &size) == kFileNotFound,
          "reg: a key with no default value answers file-not-found");

    // The old query reaches through a subkey path too.
    ar_RegSetValueW(key, nullptr, kRegSz, u"again", 0);
    size = static_cast<std::int32_t>(sizeof(data));
    check(ar_RegQueryValueA(key, nullptr, data, &size) == kOk &&
              size == 6 && std::memcmp(data, "again", 6) == 0,
          "reg: the A form of the old query answers narrow bytes");
}

void test_enum_keys() {
    reset_tree();
    const std::uint64_t key = create_key(kHkcu, u"OccRegTest\\Enum");
    std::uint64_t kid = 0;
    ar_RegCreateKeyExW(key, u"Alpha", 0, nullptr, 0, 0, nullptr, &kid,
                       nullptr);
    ar_RegCreateKeyExW(key, u"Beta", 0, nullptr, 0, 0, nullptr, &kid,
                       nullptr);
    ar_RegCreateKeyExW(key, u"Gamma", 0, nullptr, 0, 0, nullptr, &kid,
                       nullptr);

    // Creation order is the enumeration order; Windows promises none, and
    // this runtime's order is the one asserted here.
    const char16_t* expected[3] = {u"Alpha", u"Beta", u"Gamma"};
    for (std::uint32_t i = 0; i < 3; ++i) {
        char16_t name[16] = {};
        std::uint32_t count = 16;
        const std::int32_t status =
            ar_RegEnumKeyExW(key, i, name, &count, nullptr, nullptr, nullptr,
                             nullptr);
        check(status == kOk, "reg: enumerating a present index succeeds");
        check(count == 5 || count == 4 || count == 5,
              "reg: the count excludes the terminator");
        check(std::memcmp(name, expected[i],
                          (std::u16string_view(expected[i]).size() + 1) *
                              sizeof(char16_t)) == 0,
              "reg: the name at the index is the name created there");
    }

    // Past the end is no-more-items.
    char16_t name[16] = {};
    std::uint32_t count = 16;
    check(ar_RegEnumKeyExW(key, 3, name, &count, nullptr, nullptr, nullptr,
                           nullptr) == kNoMoreItems,
          "reg: enumerating past the end answers no-more-items");

    // A short name buffer answers more-data with the capacity it needed,
    // terminator included.
    count = 4;
    check(ar_RegEnumKeyExW(key, 0, name, &count, nullptr, nullptr, nullptr,
                           nullptr) == kMoreData,
          "reg: a short name buffer answers more-data");
    check(count == 6, "reg: and states the capacity needed");

    // The old form, without the class or the out-count.
    check(ar_RegEnumKeyW(key, 1, name, 16) == kOk &&
              std::memcmp(name, u"Beta", 10) == 0,
          "reg: the old enum answers the name");
    check(ar_RegEnumKeyW(key, 1, name, 4) == kMoreData,
          "reg: and refuses a buffer that cannot hold it");

    // The A form answers narrow text for the same key.
    char narrow[16] = {};
    std::uint32_t narrow_count = sizeof(narrow);
    check(ar_RegEnumKeyExA(key, 0, narrow, &narrow_count, nullptr, nullptr,
                           nullptr, nullptr) == kOk,
          "reg: the A enum succeeds on the same index");
    check(narrow_count == 5 && std::memcmp(narrow, "Alpha", 6) == 0,
          "reg: and answers the same name in narrow text");
}

void test_enum_values() {
    reset_tree();
    const std::uint64_t key = create_key(kHkcu, u"OccRegTest\\EnumVals");
    set_dword(key, u"First", 1);
    set_dword(key, u"Second", 2);

    char16_t name[16] = {};
    std::uint32_t count = 16;
    std::uint32_t type = 0;
    std::uint8_t data[8] = {};
    std::uint32_t size = sizeof(data);
    check(ar_RegEnumValueW(key, 0, name, &count, nullptr, &type, data,
                           &size) == kOk,
          "reg: enumerating a value succeeds");
    check(count == 5 && std::memcmp(name, u"First", 12) == 0,
          "reg: the first value's name comes back");
    check(type == kRegDword && size == 4,
          "reg: the first value's type and size come back");

    count = 16;
    size = sizeof(data);
    check(ar_RegEnumValueW(key, 1, name, &count, nullptr, &type, data,
                           &size) == kOk &&
              std::memcmp(name, u"Second", 14) == 0,
          "reg: the second value follows");

    check(ar_RegEnumValueW(key, 2, name, &count, nullptr, &type, data,
                           &size) == kNoMoreItems,
          "reg: enumerating values past the end answers no-more-items");

    // A short data buffer answers more-data with the needed size.
    count = 16;
    size = 2;
    check(ar_RegEnumValueW(key, 0, name, &count, nullptr, nullptr, data,
                           &size) == kMoreData && size == 4,
          "reg: a short value buffer answers more-data with the size");

    // The A form converts the name out of the stored wide text.
    char narrow[16] = {};
    std::uint32_t narrow_count = sizeof(narrow);
    size = sizeof(data);
    type = 0;
    check(ar_RegEnumValueA(key, 0, narrow, &narrow_count, nullptr, &type,
                           data, &size) == kOk,
          "reg: the A value enum succeeds");
    check(narrow_count == 5 && std::memcmp(narrow, "First", 6) == 0,
          "reg: and answers the same name in narrow text");
    check(type == kRegDword && size == 4,
          "reg: with the same type and size as the W form");
}

void test_delete() {
    reset_tree();
    create_key(kHkcu, u"OccRegTest\\Del");
    create_key(kHkcu, u"OccRegTest\\Del\\Child");
    create_key(kHkcu, u"OccRegTest\\Del\\Child\\Leaf");

    // The documented contract: one key at a time, children first.
    check(ar_RegDeleteKeyW(kHkcu, u"OccRegTest\\Del\\Child") == kKeyHasChildren,
          "reg: deleting a key with children is refused");
    check(ar_RegDeleteKeyExW(kHkcu, u"OccRegTest\\Del\\Child", 0, 0) ==
              kKeyHasChildren,
          "reg: the Ex form refuses the same way");
    check(ar_RegDeleteKeyW(kHkcu, u"OccRegTest\\Del\\Child\\Leaf") == kOk,
          "reg: deleting a leaf succeeds");
    std::uint64_t gone = 0;
    check(ar_RegOpenKeyExW(kHkcu, u"OccRegTest\\Del\\Child\\Leaf", 0, 0,
                           &gone) == kFileNotFound,
          "reg: the deleted key is gone");
    check(ar_RegDeleteKeyW(kHkcu, u"OccRegTest\\Del\\Child\\Leaf") ==
              kFileNotFound,
          "reg: deleting it again answers file-not-found");

    // Now the child is deletable.
    check(ar_RegDeleteKeyW(kHkcu, u"OccRegTest\\Del\\Child") == kOk,
          "reg: deleting the emptied key succeeds");

    // The A form deletes the same tree.
    const std::uint64_t narrow_key = create_key(kHkcu, u"OccRegTest\\DelA");
    check(narrow_key != 0, "reg: the A-delete fixture exists");
    check(ar_RegDeleteKeyA(kHkcu, "OccRegTest\\DelA") == kOk,
          "reg: the A form deletes the key");
    check(ar_RegOpenKeyA(kHkcu, "OccRegTest\\DelA", &gone) == kFileNotFound,
          "reg: and it is gone");

    // Values: the direct and through-a-subkey forms, and the misses.
    const std::uint64_t values = create_key(kHkcu, u"OccRegTest\\DelV");
    set_dword(values, u"v", 1);
    check(ar_RegDeleteValueW(values, u"v") == kOk,
          "reg: deleting a value succeeds");
    check(ar_RegDeleteValueW(values, u"v") == kFileNotFound,
          "reg: deleting it again answers file-not-found");
    set_dword(values, u"w", 2);
    check(ar_RegDeleteKeyValueW(kHkcu, u"OccRegTest\\DelV", u"w") == kOk,
          "reg: the through-a-subkey form deletes too");
    check(ar_RegDeleteKeyValueW(kHkcu, u"OccRegTest\\DelV", u"absent") ==
              kFileNotFound,
          "reg: and answers file-not-found for a missing value");

    // The tree delete takes the subtree and keeps the named key.
    const std::uint64_t tree = create_key(kHkcu, u"OccRegTest\\Tree");
    std::uint64_t kid = 0;
    ar_RegCreateKeyExW(tree, u"A", 0, nullptr, 0, 0, nullptr, &kid, nullptr);
    const std::uint64_t deep = create_key(kHkcu, u"OccRegTest\\Tree\\A\\B");
    set_dword(deep, u"v", 3);
    check(ar_RegDeleteTreeW(kHkcu, u"OccRegTest\\Tree") == kOk,
          "reg: the tree delete succeeds");
    check(ar_RegOpenKeyExW(kHkcu, u"OccRegTest\\Tree\\A", 0, 0, &gone) ==
              kFileNotFound,
          "reg: the subtree is gone");
    check(ar_RegOpenKeyExW(kHkcu, u"OccRegTest\\Tree", 0, 0, &gone) ==
              kFileNotFound,
          "reg: and the named key goes with it");

    // The null-subkey form keeps the key itself and clears its contents.
    const std::uint64_t contents = create_key(kHkcu, u"OccRegTest\\Keep");
    set_dword(contents, u"v", 3);
    check(ar_RegDeleteTreeW(contents, nullptr) == kOk,
          "reg: the null-subkey form succeeds");
    std::uint32_t size = 4;
    std::uint8_t data[4] = {};
    check(ar_RegQueryValueExW(contents, u"v", nullptr, nullptr, data,
                              &size) == kFileNotFound,
          "reg: and the values are gone");
    check(ar_RegCloseKey(contents) == kOk,
          "reg: but the key itself survives");
}

void test_get_value() {
    reset_tree();
    const std::uint64_t key = create_key(kHkcu, u"OccRegTest\\GetV");
    set_dword(key, u"number", 42);

    // The plain path: subkey null, value by name.
    std::uint8_t data[8] = {};
    std::uint32_t size = sizeof(data);
    std::uint32_t type = 0;
    check(ar_RegGetValueW(kHkcu, u"OccRegTest\\GetV", u"number", 0, &type,
                          data, &size) == kOk,
          "reg: get-value with no type restriction succeeds");
    check(type == kRegDword && size == 4,
          "reg: with the stored type and size");

    // A type outside the restriction mask is refused, which is what the
    // flags are for.
    size = sizeof(data);
    check(ar_RegGetValueW(kHkcu, u"OccRegTest\\GetV", u"number", kRrfRtDword,
                          &type, data, &size) == kOk,
          "reg: a dword under the dword mask succeeds");
    const char16_t text[] = u"str";
    ar_RegSetValueExW(key, u"text", 0, kRegSz,
                      reinterpret_cast<const std::uint8_t*>(text),
                      static_cast<std::uint32_t>(sizeof(text)));
    size = sizeof(data);
    check(ar_RegGetValueW(kHkcu, u"OccRegTest\\GetV", u"text", kRrfRtDword,
                          &type, data, &size) == kInvalidParameter,
          "reg: a string under the dword mask is refused");
    size = sizeof(data);
    check(ar_RegGetValueW(kHkcu, u"OccRegTest\\GetV", u"text", 0, &type, data,
                          &size) == kOk && type == kRegSz,
          "reg: with no mask the stored type comes back");

    // A missing subkey is file-not-found.
    check(ar_RegGetValueW(kHkcu, u"OccRegTest\\Missing", u"number", 0, &type,
                          data, &size) == kFileNotFound,
          "reg: a missing subkey answers file-not-found");

    // The A form, both directions of the bridge. The dword is 42, so the
    // little-endian bytes are known here and `data` cannot be trusted for
    // the comparison -- the W calls further down reused it for the string.
    std::uint8_t narrow_data[8] = {};
    size = sizeof(narrow_data);
    type = 0;
    check(ar_RegGetValueA(kHkcu, "OccRegTest\\GetV", "number", 0, &type,
                          narrow_data, &size) == kOk,
          "reg: the A get-value succeeds on the same value");
    const std::uint8_t expected[4] = {42, 0, 0, 0};
    check(type == kRegDword && size == 4 &&
              std::memcmp(narrow_data, expected, 4) == 0,
          "reg: with the same bytes the W form answered");
}

void test_query_info() {
    reset_tree();
    const std::uint64_t key = create_key(kHkcu, u"OccRegTest\\Info");
    std::uint64_t kid = 0;
    ar_RegCreateKeyExW(key, u"One", 0, nullptr, 0, 0, nullptr, &kid, nullptr);
    ar_RegCreateKeyExW(key, u"Two22", 0, nullptr, 0, 0, nullptr, &kid,
                       nullptr);
    set_dword(key, u"a", 1);
    const char16_t sz[] = u"12345";
    ar_RegSetValueExW(key, u"bbb", 0, kRegSz,
                      reinterpret_cast<const std::uint8_t*>(sz), sizeof(sz));
    set_dword(key, u"ccccc", 3);

    std::uint32_t subkeys = 0;
    std::uint32_t max_subkey = 0;
    std::uint32_t values = 0;
    std::uint32_t max_value_name = 0;
    std::uint32_t max_value_data = 0;
    std::uint32_t sd_size = 0;
    check(ar_RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &subkeys,
                              &max_subkey, nullptr, &values,
                              &max_value_name, &max_value_data, &sd_size,
                              nullptr) == kOk,
          "reg: query-info succeeds");
    check(subkeys == 2, "reg: the subkey count is right");
    check(max_subkey == 5, "reg: the longest subkey name is five characters");
    check(values == 3, "reg: the value count is right");
    check(max_value_name == 5, "reg: the longest value name is five characters");
    check(max_value_data == 12, "reg: the largest value is the string with terminator");
    check(sd_size == 0, "reg: no security is modelled, so the size is zero");
}

void test_query_multiple_values() {
    reset_tree();
    const std::uint64_t key = create_key(kHkcu, u"OccRegTest\\Multi");
    set_dword(key, u"d", 0x11223344);
    const char16_t sz[] = u"abc";
    ar_RegSetValueExW(key, u"s", 0, kRegSz,
                      reinterpret_cast<const std::uint8_t*>(sz), sizeof(sz));

    // VALENTW, laid out as the 64-bit ABI lays it out.
    struct Valent {
        const char16_t* name;
        std::uint32_t length;
        std::uint64_t value_ptr;
        std::uint32_t type;
    };
    Valent entries[2] = {};
    entries[0].name = u"d";
    entries[1].name = u"s";
    char16_t buffer[32] = {};
    std::uint32_t total = sizeof(buffer);

    check(ar_RegQueryMultipleValuesW(key, entries, 2, buffer, &total) == kOk,
          "reg: the multiple-value query succeeds");
    check(total == 12, "reg: the total is the sum of the value sizes");
    check(entries[0].length == 4 && entries[0].type == kRegDword,
          "reg: the dword answers its length and type");
    check(entries[1].length == 8 && entries[1].type == kRegSz,
          "reg: the string answers its length and type");
    check(entries[0].value_ptr != 0 && entries[1].value_ptr != 0 &&
              entries[1].value_ptr != entries[0].value_ptr,
          "reg: each value pointer names its own slot");
    const std::uint8_t* at = reinterpret_cast<const std::uint8_t*>(
        entries[0].value_ptr);
    check(at[0] == 0x44 && at[1] == 0x33 && at[2] == 0x22 && at[3] == 0x11,
          "reg: the dword bytes are at the pointer the entry names");
    at = reinterpret_cast<const std::uint8_t*>(entries[1].value_ptr);
    check(std::memcmp(at, u"abc", 8) == 0,
          "reg: the string bytes are at the pointer the entry names");

    // A short buffer is refused whole, with the true total.
    entries[0].name = u"d";
    entries[1].name = u"s";
    total = 8;
    check(ar_RegQueryMultipleValuesW(key, entries, 2, buffer, &total) ==
              kMoreData,
          "reg: a short buffer answers more-data");
    check(total == 12, "reg: and states the total that was needed");

    // A missing value in the list fails the call.
    entries[0].name = u"absent";
    entries[1].name = u"s";
    total = sizeof(buffer);
    check(ar_RegQueryMultipleValuesW(key, entries, 2, buffer, &total) ==
              kFileNotFound,
          "reg: a missing value answers file-not-found");
}

void test_copy_and_rename() {
    reset_tree();
    const std::uint64_t src = create_key(kHkcu, u"OccRegTest\\Copy\\Src");
    set_dword(src, u"v", 11);
    const std::uint64_t child = create_key(kHkcu, u"OccRegTest\\Copy\\Src\\Kid");
    set_dword(child, u"w", 22);
    const std::uint64_t dst = create_key(kHkcu, u"OccRegTest\\Copy\\Dst");

    check(ar_RegCopyTreeW(src, nullptr, dst) == kOk,
          "reg: copying a subtree succeeds");
    check(read_dword(dst, u"v") == 11,
          "reg: the copied value is readable in the destination");
    std::uint64_t copied = 0;
    check(ar_RegOpenKeyExW(kHkcu, u"OccRegTest\\Copy\\Dst\\Kid", 0, 0,
                           &copied) == kOk,
          "reg: the copied child exists");
    check(read_dword(copied, u"w") == 22,
          "reg: with its value");
    ar_RegCloseKey(copied);

    // Copying a node onto itself is a no-op, not a walk that never ends.
    check(ar_RegCopyTreeW(src, nullptr, src) == kOk,
          "reg: copying a key onto itself succeeds as a no-op");

    // Rename: the key moves under its new name and keeps its values.
    const std::uint64_t renamed = create_key(kHkcu, u"OccRegTest\\Ren\\Old");
    set_dword(renamed, u"v", 33);
    ar_RegCloseKey(renamed);
    check(ar_RegRenameKey(kHkcu, u"OccRegTest\\Ren\\Old", u"New") == kOk,
          "reg: renaming succeeds");
    std::uint64_t old_key = 0;
    check(ar_RegOpenKeyExW(kHkcu, u"OccRegTest\\Ren\\Old", 0, 0, &old_key) ==
              kFileNotFound,
          "reg: the old name is gone");
    std::uint64_t new_key = 0;
    check(ar_RegOpenKeyExW(kHkcu, u"OccRegTest\\Ren\\New", 0, 0, &new_key) ==
              kOk,
          "reg: the new name opens");
    check(read_dword(new_key, u"v") == 33,
          "reg: and the values moved with it");
    ar_RegCloseKey(new_key);

    // A name that is already taken is refused.
    create_key(kHkcu, u"OccRegTest\\Ren\\Other");
    check(ar_RegRenameKey(kHkcu, u"OccRegTest\\Ren\\New", u"Other") ==
              kAlreadyExists,
          "reg: renaming onto an existing sibling is refused");
    check(ar_RegRenameKey(kHkcu, u"OccRegTest\\Ren\\New", u"") ==
              kInvalidParameter,
          "reg: an empty new name is refused");
}

void test_predefined_roots() {
    std::uint64_t user = 0;
    check(ar_RegOpenCurrentUser(0, &user) == kOk,
          "reg: opening the current user succeeds");
    check(user == kHkcu, "reg: and answers the predefined HKCU");
    std::uint64_t classes = 0;
    check(ar_RegOpenUserClassesRoot(0, 0, 0, &classes) == kOk,
          "reg: opening the user classes root succeeds");
    check(classes == kHkcr, "reg: and answers the predefined HKCR");

    // Override: opens through the root resolve to the override key until it
    // is restored with a null handle.
    const std::uint64_t real = create_key(kHkcu, u"OccRegTest\\Predef\\Real");
    set_dword(real, u"marker", 5);
    check(ar_RegOverridePredefKey(kHkcc, real) == kOk,
          "reg: overriding a predefined root succeeds");
    check(ar_RegOverridePredefKey(0x00BADA55ULL, real) == kInvalidParameter,
          "reg: overriding something that is not predefined is refused");
    std::uint64_t through = 0;
    check(ar_RegOpenKeyExW(kHkcc, nullptr, 0, 0, &through) == kOk,
          "reg: opening the overridden root succeeds");
    check(read_dword(kHkcc, u"marker") == 5,
          "reg: and the value lives in the override key");
    check(ar_RegOverridePredefKey(kHkcc, 0) == kOk,
          "reg: a null override restores the root");
    std::uint8_t data[4] = {};
    std::uint32_t size = 4;
    check(ar_RegQueryValueExW(kHkcc, u"marker", nullptr, nullptr, data,
                              &size) == kFileNotFound,
          "reg: and the restored root no longer sees the marker");
}

void test_stateless_answers() {
    check(ar_RegFlushKey(kHklm) == kOk,
          "reg: flushing a live key succeeds");
    check(ar_RegFlushKey(0x00BADA55ULL) == kInvalidHandle,
          "reg: flushing an unknown handle answers invalid-handle");
    check(ar_RegDisablePredefinedCache() == kOk,
          "reg: disabling the predefined cache succeeds");
    check(ar_RegEnableReflectionKey(kHklm) == kOk,
          "reg: enabling reflection on a view-less runtime succeeds");
    check(ar_RegDisableReflectionKey(kHklm) == kOk,
          "reg: disabling reflection succeeds");
    std::int32_t reflected = 1;
    check(ar_RegQueryReflectionKey(kHklm, &reflected) == kOk,
          "reg: the reflection query succeeds");
    check(reflected == 0, "reg: and answers not-reflected");
    check(ar_RegQueryReflectionKey(kHklm, nullptr) == kInvalidParameter,
          "reg: a null out pointer is refused");
    check(ar_RegEnableReflectionKey(0x00BADA55ULL) == kInvalidHandle,
          "reg: an unknown handle answers invalid-handle");

    // The transacted create does the create; the transaction handle is
    // carried but enrols nothing, because there is nothing here to enrol in.
    std::uint64_t handle = 0;
    std::uint32_t disposition = 0;
    check(ar_RegCreateKeyTransactedW(kHkcu, u"OccRegTest\\Transacted", 0,
                                     nullptr, 0, 0, nullptr, &handle,
                                     &disposition, 0, nullptr) == kOk,
          "reg: the transacted create succeeds");
    check(disposition == kCreatedNewKey,
          "reg: and really created the key");
    std::uint64_t plain = 0;
    check(ar_RegOpenKeyExW(kHkcu, u"OccRegTest\\Transacted", 0, 0, &plain) ==
              kOk,
          "reg: the created key opens without the transaction");
    ar_RegCloseKey(plain);
}

void test_rejections() {
    // Everything that needs a hive file, a remote machine, a notification
    // pipe, a security descriptor or an MUI catalogue is refused with
    // call-not-implemented -- a specific, testable refusal rather than a
    // fake success.
    std::uint64_t handle = 0;
    std::uint32_t size = 4;
    char16_t text[8] = {};

    check(ar_RegConnectRegistryW(nullptr, kHklm, &handle) ==
              kCallNotImplemented,
          "reg: remote connect is refused");
    check(ar_RegConnectRegistryA(nullptr, kHklm, &handle) ==
              kCallNotImplemented,
          "reg: remote connect, A form, is refused");
    check(ar_RegLoadKeyW(kHkcu, u"x", u"y") == kCallNotImplemented,
          "reg: hive load is refused");
    check(ar_RegUnLoadKeyW(kHkcu, u"x") == kCallNotImplemented,
          "reg: hive unload is refused");
    check(ar_RegLoadAppKeyW(u"file.hiv", 0, 0, 0) == kCallNotImplemented,
          "reg: app-key load is refused");
    check(ar_RegSaveKeyW(kHklm, u"file", nullptr) == kCallNotImplemented,
          "reg: hive save is refused");
    check(ar_RegSaveKeyExW(kHklm, u"file", nullptr, 0) ==
              kCallNotImplemented,
          "reg: the Ex hive save is refused");
    check(ar_RegRestoreKeyW(kHklm, u"file", 0) == kCallNotImplemented,
          "reg: hive restore is refused");
    check(ar_RegReplaceKeyW(kHklm, u"x", u"a", u"b") ==
              kCallNotImplemented,
          "reg: hive replace is refused");
    check(ar_RegNotifyChangeKeyValue(kHklm, 1, 0, 0, 0) ==
              kCallNotImplemented,
          "reg: change notification is refused");
    check(ar_RegGetKeySecurity(kHklm, 0, nullptr, &size) ==
              kCallNotImplemented,
          "reg: reading key security is refused");
    check(ar_RegSetKeySecurity(kHklm, 0, nullptr) == kCallNotImplemented,
          "reg: writing key security is refused");
    check(ar_RegLoadMUIStringW(kHklm, u"v", text, 8, &size, 0, nullptr) ==
              kCallNotImplemented,
          "reg: the MUI string lookup is refused");
    check(ar_RegRemapPreDefKey(kHklm, 0) == kCallNotImplemented,
          "reg: the predefined-key remap is refused");

    // The service dispatcher does not exist, so a registration would hand
    // back a handle nothing would ever serve.
    check(ar_RegisterServiceCtrlHandlerW(u"svc", nullptr) == 0,
          "reg: the service handler registration answers null");
    check(k32_GetLastError() == static_cast<std::uint32_t>(kCallNotImplemented),
          "reg: and leaves call-not-implemented as the error");
    check(ar_RegisterServiceCtrlHandlerA("svc", nullptr) == 0,
          "reg: the A form answers null too");
    check(ar_RegisterServiceCtrlHandlerExW(u"svc", nullptr, nullptr) == 0,
          "reg: the Ex form answers null");
    check(ar_RegisterServiceCtrlHandlerExA("svc", nullptr, nullptr) == 0,
          "reg: the Ex A form answers null");

    check(ar_RegisterTraceGuidsW(nullptr, nullptr, nullptr, 0, nullptr,
                                 nullptr, nullptr, nullptr) ==
              static_cast<std::uint32_t>(kCallNotImplemented),
          "reg: ETW registration is refused");
    check(ar_RegisterTraceGuidsA(nullptr, nullptr, nullptr, 0, nullptr,
                                 nullptr, nullptr, nullptr) ==
              static_cast<std::uint32_t>(kCallNotImplemented),
          "reg: the A ETW registration is refused");

    // A void function can only be a no-op; the callbacks are not invoked
    // because nothing here performs a wait-chain analysis.
    ar_RegisterWaitChainCOMCallback(nullptr, nullptr);
    ++checks;
}

void test_event_sources() {
    const std::uint64_t first = ar_RegisterEventSourceW(nullptr, u"Occ");
    const std::uint64_t second = ar_RegisterEventSourceW(nullptr, u"Occ2");
    check(first != 0, "reg: registering an event source answers a handle");
    check(second != 0 && second != first,
          "reg: a second registration answers a different handle");
    const std::uint64_t narrow = ar_RegisterEventSourceA(nullptr, "Occ3");
    check(narrow != 0, "reg: the A form answers a handle too");
}

void test_a_w_pairing() {
    reset_tree();

    // Create through W, reach the same key through A -- the bridge in both
    // directions on one key.
    const std::uint64_t wide = create_key(kHkcu, u"OccRegTest\\Aw");
    std::uint64_t created = 0;
    check(ar_RegCreateKeyExA(kHkcu, "OccRegTest\\AW", 0, nullptr, 0, 0,
                             nullptr, &created, nullptr) == kOk,
          "reg: the A create over the W-created name succeeds as existing");
    std::uint64_t narrow = 0;
    check(ar_RegOpenKeyExA(kHkcu, "occregtest\\aw", 0, 0, &narrow) == kOk,
          "reg: the A open reaches the W-created key");
    set_dword(wide, u"probe", 88);
    check(read_dword(narrow, u"probe") == 88,
          "reg: and it is the same key the W handle names");

    // A REG_SZ written wide comes back narrow through the A query.
    const char16_t text[] = u"hello";
    ar_RegSetValueExW(wide, u"text", 0, kRegSz,
                      reinterpret_cast<const std::uint8_t*>(text),
                      static_cast<std::uint32_t>(sizeof(text)));
    std::uint8_t data[16] = {};
    std::uint32_t size = sizeof(data);
    std::uint32_t type = 0;
    check(ar_RegQueryValueExA(wide, "text", nullptr, &type, data, &size) ==
              kOk,
          "reg: the A query reads the W-written string");
    check(type == kRegSz, "reg: with the stored type");
    check(size == 6 && std::memcmp(data, "hello", 6) == 0,
          "reg: and the narrow bytes, terminator included");

    // And the W query reads what the A form wrote.
    check(ar_RegSetValueExA(wide, "narrow_text", 0, kRegDword, data, 4) == kOk,
          "reg: the A set with a narrow name succeeds");
    check(read_dword(wide, u"NARROW_TEXT") == *(reinterpret_cast<const std::uint32_t*>(data)),
          "reg: and the W side sees the value under its wide name");

    // The default value through the old A pair.
    check(ar_RegSetValueA(wide, nullptr, kRegSz, "old", 0) == kOk,
          "reg: the A old-set writes the default value");
    std::int32_t narrow_size = static_cast<std::int32_t>(sizeof(data));
    check(ar_RegQueryValueA(wide, nullptr, data, &narrow_size) == kOk,
          "reg: the A old-query reads it back");
    check(narrow_size == 4 && std::memcmp(data, "old", 4) == 0,
          "reg: with the narrow bytes");
}

void test_registration() {
    ExportList list;
    add_advapi32_reg(list);

    // The order's count, exactly: a name missing from this list is an import
    // the guest resolves to nothing.
    check(list.size() == 85,
          "reg: the domain contributes exactly the eighty-five names");

    bool duplicate = false;
    for (std::size_t i = 0; i < list.size() && !duplicate; ++i) {
        for (std::size_t k = i + 1; k < list.size(); ++k) {
            if (list[i].name == list[k].name) {
                duplicate = true;
                break;
            }
        }
    }
    check(!duplicate, "reg: no name is registered twice");

    bool all_addressed = true;
    for (const HostExport& entry : list) {
        if (entry.name.empty() || entry.address == 0) {
            all_addressed = false;
        }
    }
    check(all_addressed, "reg: every entry has a name and an address");
}

}  // namespace

int main() {
    test_open_missing();
    test_create_open();
    test_close_invalidates();
    test_values();
    test_old_value_forms();
    test_enum_keys();
    test_enum_values();
    test_delete();
    test_get_value();
    test_query_info();
    test_query_multiple_values();
    test_copy_and_rename();
    test_predefined_roots();
    test_stateless_answers();
    test_rejections();
    test_event_sources();
    test_a_w_pairing();
    test_registration();

    reset_tree();

    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

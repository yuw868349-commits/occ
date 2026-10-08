// The registry family, as advapi32 spells it.
//
// A registry the guest can create, open, enumerate, query and delete needs a
// tree to answer from, and this process has no Windows registry behind it.
// The domain therefore owns a virtual one: an in-memory tree of keys and
// values whose behaviour follows the documented Windows semantics. The seven
// predefined roots are handles by constant, as they are on Windows, and keys
// created below them are real nodes in that tree -- `RegCreateKeyEx` makes a
// node, `RegSetValueEx` writes bytes into it, `RegQueryValueEx` reads those
// bytes back and answers the size it needed when the caller's buffer was
// short, and the delete family really removes nodes.
//
// The decisions worth recording, each checked against the Windows
// documentation (the Wine reference tree was not reachable on this machine,
// so every number below is documented behaviour or is flagged as inferred in
// the domain report rather than taken from a source read):
//
//   * Opening a key that is not there answers `ERROR_FILE_NOT_FOUND` (2),
//     which is what Windows answers, and not `ERROR_PATH_NOT_FOUND` -- the
//     latter is what `RegCreateKeyEx` answers when an *intermediate*
//     component is missing, and the two are kept apart for exactly that
//     reason.
//   * A handle closed by `RegCloseKey` is dead: a later use of it answers
//     `ERROR_INVALID_HANDLE`, and the key itself stays reachable by opening
//     it again, which is the contract a caller that closes and reopens in a
//     loop depends on.
//   * Key and value names compare case-insensitively, as the registry's
//     names do. Enumeration answers names in creation order; Windows does
//     not promise an order, so a runtime choosing one is within the contract.
//   * `RegQueryValueEx` answers the *stored* type and the stored bytes. It
//     does not convert between types on a mismatch -- the documented
//     contract is that `lpType` receives what is stored -- and the
//     type-restricted reads with conversion are what `RegGetValue` and its
//     `RRF_RT_*` flags are for.
//   * A short data buffer answers `ERROR_MORE_DATA` (234) with the true
//     required size, a null data buffer answers the size with success, and
//     `lpReserved` passed non-null answers `ERROR_INVALID_PARAMETER` because
//     Windows dereferences it and a runtime that would fault answers the
//     error instead.
//   * `RegDeleteKey` refuses a key that still has subkeys with
//     `ERROR_KEY_HAS_CHILDREN` (1015), which is the documented contract;
//     `RegDeleteTree` is the recursive spelling and takes the subtree.
//   * The calls whose real implementations need a file-backed hive or a
//     remote machine -- `RegConnectRegistry`, `RegLoadKey`, `RegSaveKey`,
//     `RegRestoreKey` and their siblings -- answer
//     `ERROR_CALL_NOT_IMPLEMENTED` rather than pretending a hive was saved
//     to a file that does not exist.
//
// The A forms convert their text in with `narrow_in`, delegate to the W
// entry point (or to the same core the W entry point drives, where the
// output is text the A caller reads back), and convert the answer out with
// `narrow_out`. No behaviour is written twice.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <cwctype>

namespace occ::runtime::winabi {
namespace {

// ---------------------------------------------------------------- constants

// LSTATUS is the signed spelling the registry family returns; the shared
// error codes are the unsigned spelling `GetLastError` reads. Every status
// this domain returns goes through one of these aliases so that the signed
// and unsigned worlds meet in exactly one place.
constexpr std::int32_t kStatusOk = static_cast<std::int32_t>(kErrorSuccess);
constexpr std::int32_t kStatusFileNotFound =
    static_cast<std::int32_t>(kErrorFileNotFound);
constexpr std::int32_t kStatusPathNotFound =
    static_cast<std::int32_t>(kErrorPathNotFound);
constexpr std::int32_t kStatusAccessDenied =
    static_cast<std::int32_t>(kErrorAccessDenied);
constexpr std::int32_t kStatusInvalidHandle =
    static_cast<std::int32_t>(kErrorInvalidHandle);
constexpr std::int32_t kStatusInvalidParameter =
    static_cast<std::int32_t>(kErrorInvalidParameter);
constexpr std::int32_t kStatusAlreadyExists =
    static_cast<std::int32_t>(kErrorAlreadyExists);
constexpr std::int32_t kStatusCallNotImplemented =
    static_cast<std::int32_t>(kErrorCallNotImplemented);
constexpr std::int32_t kStatusMoreData = 234;  // ERROR_MORE_DATA
constexpr std::int32_t kStatusNoMoreItems =
    static_cast<std::int32_t>(kErrorNoMoreItems);
constexpr std::int32_t kStatusKeyHasChildren = 1015;  // ERROR_KEY_HAS_CHILDREN

// The value type codes, as the wire spells them.
constexpr std::uint32_t kRegNone = 0;
constexpr std::uint32_t kRegSz = 1;
constexpr std::uint32_t kRegExpandSz = 2;
constexpr std::uint32_t kRegBinary = 3;
constexpr std::uint32_t kRegDword = 4;
constexpr std::uint32_t kRegDwordBigEndian = 5;
constexpr std::uint32_t kRegLink = 6;
constexpr std::uint32_t kRegMultiSz = 7;
constexpr std::uint32_t kRegResourceList = 8;
constexpr std::uint32_t kRegQword = 11;

constexpr std::uint32_t kRegCreatedNewKey = 1;
constexpr std::uint32_t kRegOpenedExistingKey = 2;

// `RegGetValue`'s type restrictions. The low word is a mask of allowed types;
// `RRF_NOEXPAND` asks that `REG_EXPAND_SZ` be handed back unexpanded.
constexpr std::uint32_t kRrfRtMask = 0x0000FFFFu;
constexpr std::uint32_t kRrfNoExpand = 0x10000000u;

// The predefined roots, which are handles by constant and need no table
// lookup to recognise.
constexpr std::uint64_t kFirstPredefined = 0x80000000ULL;
constexpr std::uint64_t kLastPredefined = 0x80000006ULL;
constexpr std::size_t kRootCount = 7;

// Where the handles this runtime issues for dynamically created keys start.
// The span is far above the predefined roots and far below anything a guest
// would confuse with a pointer.
constexpr std::uint64_t kDynamicHandleBase = 0x01000000ULL;

// Event-log source handles start where they cannot be confused with a key
// handle, and grow by one per registration.
constexpr std::uint64_t kEventSourceHandleBase = 0x00010000ULL;

// `VALENTW` on the 64-bit ABI: a pointer, a 32-bit length, padding, a
// pointer-sized value pointer, a 32-bit type and padding.
constexpr std::size_t kValentSize = 32;
constexpr std::size_t kValentName = 0;
constexpr std::size_t kValentLength = 8;
constexpr std::size_t kValentValuePtr = 16;
constexpr std::size_t kValentType = 24;

// ------------------------------------------------------------------ the tree

struct RegValue {
    std::u16string name;
    std::uint32_t type = kRegSz;
    std::vector<std::uint8_t> data;
};

struct RegKey {
    std::u16string name;
    std::u16string klass;
    RegKey* parent = nullptr;
    std::vector<std::unique_ptr<RegKey>> children;
    std::vector<RegValue> values;

    explicit RegKey(std::u16string_view key_name) : name(key_name) {}

    // Both lookups are case-insensitive, because registry names are.
    [[nodiscard]] RegKey* find_child(std::u16string_view wanted) noexcept {
        for (const auto& child : children) {
            if (iequal(child->name, wanted)) {
                return child.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] RegValue* find_value(std::u16string_view wanted) noexcept {
        for (RegValue& value : values) {
            if (iequal(value.name, wanted)) {
                return &value;
            }
        }
        return nullptr;
    }

private:
    [[nodiscard]] static bool iequal(std::u16string_view a,
                                     std::u16string_view b) noexcept {
        if (a.size() != b.size()) {
            return false;
        }
        for (std::size_t i = 0; i < a.size(); ++i) {
            if (towlower(static_cast<wint_t>(a[i])) !=
                towlower(static_cast<wint_t>(b[i]))) {
                return false;
            }
        }
        return true;
    }
};

// The roots, their current targets (which `RegOverridePredefKey` moves), and
// the table of handles this runtime has issued. A handle entry is the truth
// of "this handle is open": closing erases it, and every use of a closed
// handle falls off the lookup into `ERROR_INVALID_HANDLE`.
RegKey g_roots[kRootCount] = {
    RegKey(u"HKEY_CLASSES_ROOT"), RegKey(u"HKEY_CURRENT_USER"),
    RegKey(u"HKEY_LOCAL_MACHINE"), RegKey(u"HKEY_USERS"),
    RegKey(u"HKEY_PERFORMANCE_DATA"), RegKey(u"HKEY_CURRENT_CONFIG"),
    RegKey(u"HKEY_DYN_DATA"),
};

RegKey* g_root_target[kRootCount] = {&g_roots[0], &g_roots[1], &g_roots[2],
                                     &g_roots[3], &g_roots[4], &g_roots[5],
                                     &g_roots[6]};

std::unordered_map<std::uint64_t, RegKey*> g_open_handles;
std::uint64_t g_next_key_handle = kDynamicHandleBase;
std::uint64_t g_next_event_source = kEventSourceHandleBase;

// ------------------------------------------------------------------- helpers

// The one exit every LSTATUS entry takes: the status is both the return
// value the registry contract answers and the code `GetLastError` reads.
std::int32_t finish(std::int32_t status) noexcept {
    set_last_error(static_cast<std::uint32_t>(status));
    return status;
}

[[nodiscard]] bool is_predefined(std::uint64_t handle) noexcept {
    return handle >= kFirstPredefined && handle <= kLastPredefined;
}

// The key node a handle names: a predefined root resolves through its
// current target, anything else through the open-handle table.
[[nodiscard]] RegKey* base_key(std::uint64_t handle) noexcept {
    if (is_predefined(handle)) {
        return g_root_target[static_cast<std::size_t>(handle - kFirstPredefined)];
    }
    const auto it = g_open_handles.find(handle);
    return it == g_open_handles.end() ? nullptr : it->second;
}

// The predefined constant for one of the seven root nodes, or nothing.
[[nodiscard]] bool root_handle_of(const RegKey* key,
                                  std::uint64_t* out) noexcept {
    for (std::size_t i = 0; i < kRootCount; ++i) {
        if (key == &g_roots[i]) {
            *out = kFirstPredefined + i;
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::uint64_t allocate_handle(RegKey* key) noexcept {
    const std::uint64_t handle = g_next_key_handle++;
    g_open_handles.emplace(handle, key);
    return handle;
}

// A guest string as a view. Null and the empty string are both "no name",
// which every registry call below spells "the key itself" or "the default
// value" as the case may be.
[[nodiscard]] std::u16string_view view_of(const char16_t* text) noexcept {
    if (text == nullptr) {
        return {};
    }
    std::size_t n = 0;
    while (text[n] != u'\0') {
        ++n;
    }
    return std::u16string_view(text, n);
}

// The nodes of a subtree, so that the handles naming them can be dropped
// before the nodes themselves go away. An outstanding handle into a deleted
// subtree must not survive the delete -- a caller that kept one would
// otherwise be reading a node nothing can reach.
void collect_nodes(RegKey* node, std::vector<RegKey*>& out) noexcept {
    out.push_back(node);
    for (const auto& child : node->children) {
        collect_nodes(child.get(), out);
    }
}

void drop_handles_to(const std::vector<RegKey*>& nodes) noexcept {
    for (auto it = g_open_handles.begin(); it != g_open_handles.end();) {
        bool match = false;
        for (const RegKey* node : nodes) {
            if (it->second == node) {
                match = true;
                break;
            }
        }
        if (match) {
            it = g_open_handles.erase(it);
        } else {
            ++it;
        }
    }
}

void detach(RegKey* parent, RegKey* child) noexcept {
    for (auto it = parent->children.begin(); it != parent->children.end();
         ++it) {
        if (it->get() == child) {
            parent->children.erase(it);
            return;
        }
    }
}

// Resolves a path below `base`, component by component, case-insensitively.
// An empty path names the base itself. A missing component is
// `ERROR_FILE_NOT_FOUND`, which is what Windows answers for an open.
std::int32_t resolve(std::uint64_t base, std::u16string_view path,
                     RegKey** out) noexcept {
    RegKey* at = base_key(base);
    if (at == nullptr) {
        return kStatusInvalidHandle;
    }
    std::size_t start = 0;
    while (start < path.size()) {
        const std::size_t end = path.find(u'\\', start);
        const std::u16string_view part =
            end == std::u16string_view::npos ? path.substr(start)
                                             : path.substr(start, end - start);
        if (part.empty()) {
            return kStatusInvalidParameter;
        }
        RegKey* next = at->find_child(part);
        if (next == nullptr) {
            return kStatusFileNotFound;
        }
        at = next;
        if (end == std::u16string_view::npos) {
            break;
        }
        start = end + 1;
    }
    *out = at;
    return kStatusOk;
}

// ------------------------------------------------------------- the decisions

std::int32_t core_open(std::uint64_t base, std::u16string_view path,
                       std::uint64_t* out) noexcept {
    if (out == nullptr) {
        return kStatusInvalidParameter;
    }
    RegKey* at = nullptr;
    const std::int32_t status = resolve(base, path, &at);
    if (status != kStatusOk) {
        return status;
    }
    std::uint64_t handle = 0;
    if (root_handle_of(at, &handle)) {
        // A root opened by name answers its predefined constant, as Windows
        // answers the same value the caller passed in.
        *out = handle;
        return kStatusOk;
    }
    *out = allocate_handle(at);
    return kStatusOk;
}

std::int32_t core_create(std::uint64_t base, std::u16string_view path,
                         std::u16string_view klass,
                         std::uint32_t* disposition,
                         std::uint64_t* out) noexcept {
    if (out == nullptr) {
        return kStatusInvalidParameter;
    }
    if (path.empty()) {
        // No leaf to create: the call opens the base itself.
        RegKey* at = base_key(base);
        if (at == nullptr) {
            return kStatusInvalidHandle;
        }
        if (disposition != nullptr) {
            *disposition = kRegOpenedExistingKey;
        }
        std::uint64_t handle = base;
        if (!root_handle_of(at, &handle)) {
            handle = allocate_handle(at);
        }
        *out = handle;
        return kStatusOk;
    }
    const std::size_t cut = path.rfind(u'\\');
    const std::u16string_view parent_path =
        cut == std::u16string_view::npos ? std::u16string_view{}
                                         : path.substr(0, cut);
    const std::u16string_view leaf =
        cut == std::u16string_view::npos ? path : path.substr(cut + 1);
    if (leaf.empty()) {
        return kStatusInvalidParameter;
    }
    RegKey* parent = nullptr;
    if (parent_path.empty()) {
        parent = base_key(base);
        if (parent == nullptr) {
            return kStatusInvalidHandle;
        }
    } else {
        // A missing intermediate is a path failure on create, which is the
        // one place this family says `ERROR_PATH_NOT_FOUND`.
        const std::int32_t walk = resolve(base, parent_path, &parent);
        if (walk != kStatusOk) {
            return walk == kStatusFileNotFound ? kStatusPathNotFound : walk;
        }
    }
    if (RegKey* existing = parent->find_child(leaf); existing != nullptr) {
        if (disposition != nullptr) {
            *disposition = kRegOpenedExistingKey;
        }
        *out = allocate_handle(existing);
        return kStatusOk;
    }
    auto created = std::make_unique<RegKey>(leaf);
    created->parent = parent;
    if (!klass.empty()) {
        created->klass.assign(klass);
    }
    RegKey* held = created.get();
    parent->children.push_back(std::move(created));
    if (disposition != nullptr) {
        *disposition = kRegCreatedNewKey;
    }
    *out = allocate_handle(held);
    return kStatusOk;
}

std::int32_t core_delete_key(std::uint64_t base,
                             std::u16string_view path) noexcept {
    if (path.empty()) {
        // There is no leaf, so there is nothing a delete of a subkey could
        // mean; the roots themselves are not deletable either.
        return kStatusInvalidParameter;
    }
    const std::size_t cut = path.rfind(u'\\');
    const std::u16string_view parent_path =
        cut == std::u16string_view::npos ? std::u16string_view{}
                                         : path.substr(0, cut);
    const std::u16string_view leaf =
        cut == std::u16string_view::npos ? path : path.substr(cut + 1);
    if (leaf.empty()) {
        return kStatusInvalidParameter;
    }
    RegKey* parent = nullptr;
    std::int32_t status = kStatusOk;
    if (parent_path.empty()) {
        parent = base_key(base);
        if (parent == nullptr) {
            return kStatusInvalidHandle;
        }
    } else {
        status = resolve(base, parent_path, &parent);
        if (status != kStatusOk) {
            return status;
        }
    }
    RegKey* child = parent->find_child(leaf);
    if (child == nullptr) {
        return kStatusFileNotFound;
    }
    // The documented contract: one key at a time, children first.
    if (!child->children.empty()) {
        return kStatusKeyHasChildren;
    }
    const std::vector<RegKey*> doomed{child};
    drop_handles_to(doomed);
    detach(parent, child);
    return kStatusOk;
}

std::int32_t core_delete_tree(std::uint64_t base,
                              std::u16string_view path) noexcept {
    RegKey* target = nullptr;
    const std::int32_t status = resolve(base, path, &target);
    if (status != kStatusOk) {
        return status;
    }
    if (path.empty()) {
        // The key itself was named: its contents go, and the key -- with the
        // handle the caller holds -- stays, which is the null-subkey
        // contract.
        std::vector<RegKey*> doomed;
        for (const auto& child : target->children) {
            collect_nodes(child.get(), doomed);
        }
        drop_handles_to(doomed);
        target->children.clear();
        target->values.clear();
        return kStatusOk;
    }
    // A named subkey is deleted along with everything below it, handles
    // into the subtree included.
    std::vector<RegKey*> doomed;
    collect_nodes(target, doomed);
    drop_handles_to(doomed);
    detach(target->parent, target);
    return kStatusOk;
}

std::int32_t core_delete_value(std::uint64_t base, std::u16string_view path,
                               std::u16string_view name) noexcept {
    RegKey* at = nullptr;
    const std::int32_t status = resolve(base, path, &at);
    if (status != kStatusOk) {
        return status;
    }
    // Case-insensitive remove, default value spelled by an empty name.
    for (auto it = at->values.begin(); it != at->values.end(); ++it) {
        if (it->name.size() == name.size()) {
            bool same = true;
            for (std::size_t i = 0; i < name.size(); ++i) {
                if (towlower(static_cast<wint_t>(it->name[i])) !=
                    towlower(static_cast<wint_t>(name[i]))) {
                    same = false;
                    break;
                }
            }
            if (same) {
                at->values.erase(it);
                return kStatusOk;
            }
        }
    }
    return kStatusFileNotFound;
}

std::int32_t core_set_value(std::uint64_t base, std::u16string_view path,
                            std::u16string_view name, std::uint32_t type,
                            const void* data,
                            std::uint32_t bytes) noexcept {
    RegKey* at = nullptr;
    const std::int32_t status = resolve(base, path, &at);
    if (status != kStatusOk) {
        return status;
    }
    if (data == nullptr && bytes != 0) {
        return kStatusInvalidParameter;
    }
    RegValue* slot = at->find_value(name);
    if (slot == nullptr) {
        at->values.push_back(RegValue{std::u16string(name), type, {}});
        slot = &at->values.back();
    }
    slot->type = type;
    const auto* in = static_cast<const std::uint8_t*>(data);
    slot->data.assign(in, in + bytes);
    return kStatusOk;
}

std::int32_t core_get_value(std::uint64_t base, std::u16string_view path,
                            std::u16string_view name, std::uint32_t* type,
                            std::vector<std::uint8_t>* data) noexcept {
    RegKey* at = nullptr;
    const std::int32_t status = resolve(base, path, &at);
    if (status != kStatusOk) {
        return status;
    }
    const RegValue* slot = at->find_value(name);
    if (slot == nullptr) {
        return kStatusFileNotFound;
    }
    if (type != nullptr) {
        *type = slot->type;
    }
    *data = slot->data;
    return kStatusOk;
}

std::int32_t core_enum_key(std::uint64_t base, std::uint32_t index,
                           std::u16string* name,
                           std::u16string* klass) noexcept {
    RegKey* at = base_key(base);
    if (at == nullptr) {
        return kStatusInvalidHandle;
    }
    const std::size_t i = static_cast<std::size_t>(index);
    if (i >= at->children.size()) {
        return kStatusNoMoreItems;
    }
    *name = at->children[i]->name;
    *klass = at->children[i]->klass;
    return kStatusOk;
}

std::int32_t core_enum_value(std::uint64_t base, std::uint32_t index,
                             std::u16string* name, std::uint32_t* type,
                             std::vector<std::uint8_t>* data) noexcept {
    RegKey* at = base_key(base);
    if (at == nullptr) {
        return kStatusInvalidHandle;
    }
    const std::size_t i = static_cast<std::size_t>(index);
    if (i >= at->values.size()) {
        return kStatusNoMoreItems;
    }
    *name = at->values[i].name;
    if (type != nullptr) {
        *type = at->values[i].type;
    }
    *data = at->values[i].data;
    return kStatusOk;
}

struct KeyInfo {
    std::u16string klass;
    std::uint32_t subkeys = 0;
    std::uint32_t max_subkey_chars = 0;
    std::uint32_t max_class_chars = 0;
    std::uint32_t values = 0;
    std::uint32_t max_value_name_chars = 0;
    std::uint32_t max_value_data_bytes = 0;
};

std::int32_t core_query_info(std::uint64_t base, KeyInfo* info) noexcept {
    RegKey* at = base_key(base);
    if (at == nullptr) {
        return kStatusInvalidHandle;
    }
    info->klass = at->klass;
    info->subkeys = static_cast<std::uint32_t>(at->children.size());
    info->values = static_cast<std::uint32_t>(at->values.size());
    for (const auto& child : at->children) {
        if (child->name.size() > info->max_subkey_chars) {
            info->max_subkey_chars =
                static_cast<std::uint32_t>(child->name.size());
        }
        if (child->klass.size() > info->max_class_chars) {
            info->max_class_chars =
                static_cast<std::uint32_t>(child->klass.size());
        }
    }
    for (const RegValue& value : at->values) {
        if (value.name.size() > info->max_value_name_chars) {
            info->max_value_name_chars =
                static_cast<std::uint32_t>(value.name.size());
        }
        if (value.data.size() > info->max_value_data_bytes) {
            info->max_value_data_bytes =
                static_cast<std::uint32_t>(value.data.size());
        }
    }
    return kStatusOk;
}

std::int32_t core_copy_values(RegKey* from, RegKey* into) noexcept {
    if (from == into) {
        // Copying a node onto itself terminates here; the merge below would
        // otherwise visit the same nodes forever.
        return kStatusOk;
    }
    for (const RegValue& value : from->values) {
        RegValue* slot = into->find_value(value.name);
        if (slot == nullptr) {
            into->values.push_back(value);
        } else {
            slot->type = value.type;
            slot->data = value.data;
        }
    }
    for (const auto& child : from->children) {
        RegKey* target = into->find_child(child->name);
        if (target == nullptr) {
            auto copy = std::make_unique<RegKey>(child->name);
            copy->klass = child->klass;
            copy->parent = into;
            target = copy.get();
            into->children.push_back(std::move(copy));
        } else {
            target->klass = child->klass;
        }
        const std::int32_t status = core_copy_values(child.get(), target);
        if (status != kStatusOk) {
            return status;
        }
    }
    return kStatusOk;
}

std::int32_t core_copy_tree(std::uint64_t src_base,
                            std::u16string_view src_path,
                            std::uint64_t dst_handle) noexcept {
    RegKey* from = nullptr;
    const std::int32_t status = resolve(src_base, src_path, &from);
    if (status != kStatusOk) {
        return status;
    }
    RegKey* into = base_key(dst_handle);
    if (into == nullptr) {
        return kStatusInvalidHandle;
    }
    return core_copy_values(from, into);
}

std::int32_t core_rename(std::uint64_t base, std::u16string_view path,
                         std::u16string_view new_name) noexcept {
    if (new_name.empty()) {
        return kStatusInvalidParameter;
    }
    RegKey* target = nullptr;
    const std::int32_t status = resolve(base, path, &target);
    if (status != kStatusOk) {
        return status;
    }
    RegKey* parent = target->parent;
    if (parent == nullptr) {
        // A predefined root has nothing to be renamed within.
        return kStatusAccessDenied;
    }
    const RegKey* clash = parent->find_child(new_name);
    if (clash != nullptr && clash != target) {
        return kStatusAlreadyExists;
    }
    target->name.assign(new_name);
    return kStatusOk;
}

// ------------------------------------------------------------ the emitters

// Reports text into a guest buffer the way the registry enumerators do: the
// count in is the capacity in characters, the count out is the characters
// stored without the terminator, and a short buffer is told the capacity it
// needed, terminator included. (Wine reports the bare length on the short
// path; the required capacity is the more useful answer and is flagged as
// inferred in the domain report.)
std::int32_t emit_w_text(std::u16string_view text, char16_t* buffer,
                         std::uint32_t* count) noexcept {
    if (buffer == nullptr || count == nullptr) {
        return kStatusInvalidParameter;
    }
    const auto needed = static_cast<std::uint32_t>(text.size()) + 1;
    if (*count < needed) {
        *count = needed;
        return kStatusMoreData;
    }
    if (!text.empty()) {
        std::memcpy(buffer, text.data(), text.size() * sizeof(char16_t));
    }
    buffer[text.size()] = u'\0';
    *count = static_cast<std::uint32_t>(text.size());
    return kStatusOk;
}

std::int32_t emit_a_text(const std::u16string& text, char* buffer,
                         std::uint32_t* count) noexcept {
    if (buffer == nullptr || count == nullptr) {
        return kStatusInvalidParameter;
    }
    std::string narrow;
    if (!narrow_out(text, narrow).converted) {
        return kStatusInvalidParameter;
    }
    const auto needed = static_cast<std::uint32_t>(narrow.size()) + 1;
    if (*count < needed) {
        *count = needed;
        return kStatusMoreData;
    }
    if (!narrow.empty()) {
        std::memcpy(buffer, narrow.data(), narrow.size());
    }
    buffer[narrow.size()] = '\0';
    *count = static_cast<std::uint32_t>(narrow.size());
    return kStatusOk;
}

std::int32_t emit_bytes(const std::uint8_t* bytes, std::uint32_t needed,
                        std::uint8_t* buffer, std::uint32_t* size) noexcept {
    if (size == nullptr) {
        return kStatusInvalidParameter;
    }
    if (buffer == nullptr) {
        // The size-a-call convention: a null buffer answers what the call
        // would need, with success.
        *size = needed;
        return kStatusOk;
    }
    if (*size < needed) {
        *size = needed;
        return kStatusMoreData;
    }
    if (needed != 0) {
        std::memcpy(buffer, bytes, needed);
    }
    *size = needed;
    return kStatusOk;
}

std::int32_t emit_w_data(const std::vector<std::uint8_t>& data,
                         std::uint8_t* buffer,
                         std::uint32_t* size) noexcept {
    return emit_bytes(data.data(), static_cast<std::uint32_t>(data.size()),
                      buffer, size);
}

// The narrow form: the text-bearing types go through `narrow_out` and are
// sized as the narrow bytes they become, everything else is the same bytes
// the W form would answer.
[[nodiscard]] bool is_text_type(std::uint32_t type) noexcept {
    return type == kRegSz || type == kRegExpandSz || type == kRegMultiSz ||
           type == kRegLink;
}

std::int32_t ansi_of(const std::vector<std::uint8_t>& data,
                     std::uint32_t type, std::string* out) noexcept {
    if (!is_text_type(type)) {
        out->assign(reinterpret_cast<const char*>(data.data()), data.size());
        return kStatusOk;
    }
    // A stored string is whole UTF-16 units; a trailing odd byte is not text
    // this runtime wrote, and answering the raw bytes is the honest fallback.
    const std::size_t wide_bytes = data.size() - data.size() % 2;
    std::u16string wide(wide_bytes / 2, u'\0');
    if (!wide.empty()) {
        std::memcpy(wide.data(), data.data(), wide_bytes);
    }
    if (!narrow_out(wide, *out).converted) {
        return kStatusInvalidParameter;
    }
    return kStatusOk;
}

std::int32_t emit_a_data(const std::vector<std::uint8_t>& data,
                         std::uint32_t type, std::uint8_t* buffer,
                         std::uint32_t* size) noexcept {
    std::string narrow;
    const std::int32_t status = ansi_of(data, type, &narrow);
    if (status != kStatusOk) {
        return status;
    }
    return emit_bytes(reinterpret_cast<const std::uint8_t*>(narrow.data()),
                      static_cast<std::uint32_t>(narrow.size()), buffer, size);
}

// The type bit `RegGetValue`'s restriction mask is tested against.
std::uint32_t type_bit_of(std::uint32_t type) noexcept {
    return type < 32 ? (1u << type) : 0;
}

}  // namespace

// ---------------------------------------------------------------------------
// Open, create, close
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegOpenKeyExW(
    std::uint64_t key, const char16_t* sub_key, std::uint32_t options,
    std::uint32_t access, std::uint64_t* result) noexcept {
    (void)options;
    // Access control is not modelled: every open that finds its key
    // succeeds, whatever mask was asked for.
    (void)access;
    return finish(core_open(key, view_of(sub_key), result));
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegOpenKeyExA(
    std::uint64_t key, const char* sub_key, std::uint32_t options,
    std::uint32_t access, std::uint64_t* result) noexcept {
    if (result == nullptr) {
        return finish(kStatusInvalidParameter);
    }
    std::u16string wide;
    if (sub_key != nullptr && !narrow_in(sub_key, wide).converted) {
        return finish(kStatusInvalidParameter);
    }
    return ar_RegOpenKeyExW(key, sub_key == nullptr ? nullptr : wide.c_str(),
                            options, access, result);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegOpenKeyW(
    std::uint64_t key, const char16_t* sub_key, std::uint64_t* result) noexcept {
    return ar_RegOpenKeyExW(key, sub_key, 0, 0, result);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegOpenKeyA(
    std::uint64_t key, const char* sub_key, std::uint64_t* result) noexcept {
    return ar_RegOpenKeyExA(key, sub_key, 0, 0, result);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegCreateKeyExW(
    std::uint64_t key, const char16_t* sub_key, std::uint32_t reserved,
    const char16_t* klass, std::uint32_t options, std::uint32_t access,
    const void* security, std::uint64_t* result,
    std::uint32_t* disposition) noexcept {
    (void)reserved;
    (void)options;
    (void)access;
    (void)security;
    return finish(core_create(key, view_of(sub_key), view_of(klass),
                              disposition, result));
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegCreateKeyExA(
    std::uint64_t key, const char* sub_key, std::uint32_t reserved,
    const char* klass, std::uint32_t options, std::uint32_t access,
    const void* security, std::uint64_t* result,
    std::uint32_t* disposition) noexcept {
    if (result == nullptr) {
        return finish(kStatusInvalidParameter);
    }
    std::u16string wide_key;
    std::u16string wide_class;
    if (sub_key != nullptr && !narrow_in(sub_key, wide_key).converted) {
        return finish(kStatusInvalidParameter);
    }
    if (klass != nullptr && !narrow_in(klass, wide_class).converted) {
        return finish(kStatusInvalidParameter);
    }
    return ar_RegCreateKeyExW(
        key, sub_key == nullptr ? nullptr : wide_key.c_str(), reserved,
        klass == nullptr ? nullptr : wide_class.c_str(), options, access,
        security, result, disposition);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegCreateKeyW(
    std::uint64_t key, const char16_t* sub_key, std::uint64_t* result) noexcept {
    return ar_RegCreateKeyExW(key, sub_key, 0, nullptr, 0, 0, nullptr, result,
                              nullptr);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegCreateKeyA(
    std::uint64_t key, const char* sub_key, std::uint64_t* result) noexcept {
    return ar_RegCreateKeyExA(key, sub_key, 0, nullptr, 0, 0, nullptr, result,
                              nullptr);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegCreateKeyTransactedW(
    std::uint64_t key, const char16_t* sub_key, std::uint32_t reserved,
    const char16_t* klass, std::uint32_t options, std::uint32_t access,
    const void* security, std::uint64_t* result, std::uint32_t* disposition,
    std::uint64_t transaction, const void* extended) noexcept {
    // The transaction is accepted and not applied: this runtime has no
    // transaction machinery to enrol the create in, so the create happens
    // outside any transaction rather than failing a caller whose transaction
    // never had work to roll back.
    (void)transaction;
    (void)extended;
    return ar_RegCreateKeyExW(key, sub_key, reserved, klass, options, access,
                              security, result, disposition);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegCreateKeyTransactedA(
    std::uint64_t key, const char* sub_key, std::uint32_t reserved,
    const char* klass, std::uint32_t options, std::uint32_t access,
    const void* security, std::uint64_t* result, std::uint32_t* disposition,
    std::uint64_t transaction, const void* extended) noexcept {
    (void)transaction;
    (void)extended;
    return ar_RegCreateKeyExA(key, sub_key, reserved, klass, options, access,
                              security, result, disposition);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegCloseKey(
    std::uint64_t key) noexcept {
    if (is_predefined(key)) {
        // The roots are constants, not owned handles; closing one is what
        // Windows makes of it too -- a success and no effect.
        return finish(kStatusOk);
    }
    if (g_open_handles.erase(key) == 0) {
        return finish(kStatusInvalidHandle);
    }
    return finish(kStatusOk);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegOpenCurrentUser(
    std::uint32_t access, std::uint64_t* result) noexcept {
    (void)access;
    if (result == nullptr) {
        return finish(kStatusInvalidParameter);
    }
    // One process, one user: the handle is the predefined one.
    *result = 0x80000001ULL;  // HKEY_CURRENT_USER
    return finish(kStatusOk);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegOpenUserClassesRoot(
    std::uint64_t token, std::uint32_t options, std::uint32_t access,
    std::uint64_t* result) noexcept {
    (void)token;
    (void)options;
    (void)access;
    if (result == nullptr) {
        return finish(kStatusInvalidParameter);
    }
    // The per-user merged view of HKCR is the whole of HKCR here, because
    // there is exactly one user's classes tree to see.
    *result = 0x80000000ULL;  // HKEY_CLASSES_ROOT
    return finish(kStatusOk);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegOverridePredefKey(
    std::uint64_t key, std::uint64_t override_key) noexcept {
    if (!is_predefined(key)) {
        return finish(kStatusInvalidParameter);
    }
    auto* target =
        &g_root_target[static_cast<std::size_t>(key - kFirstPredefined)];
    if (override_key == kInvalidHandle) {
        // Null restores the predefined mapping, which is the documented way
        // back for a caller that redirected a root for the duration of a
        // load.
        *target = &g_roots[static_cast<std::size_t>(key - kFirstPredefined)];
        return finish(kStatusOk);
    }
    RegKey* replacement = base_key(override_key);
    if (replacement == nullptr) {
        return finish(kStatusInvalidHandle);
    }
    *target = replacement;
    return finish(kStatusOk);
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDeleteKeyW(
    std::uint64_t key, const char16_t* sub_key) noexcept {
    return finish(core_delete_key(key, view_of(sub_key)));
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDeleteKeyA(
    std::uint64_t key, const char* sub_key) noexcept {
    std::u16string wide;
    if (sub_key != nullptr && !narrow_in(sub_key, wide).converted) {
        return finish(kStatusInvalidParameter);
    }
    return ar_RegDeleteKeyW(key, sub_key == nullptr ? nullptr : wide.c_str());
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDeleteKeyExW(
    std::uint64_t key, const char16_t* sub_key, std::uint32_t access,
    std::uint32_t reserved) noexcept {
    (void)access;
    (void)reserved;
    return ar_RegDeleteKeyW(key, sub_key);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDeleteKeyExA(
    std::uint64_t key, const char* sub_key, std::uint32_t access,
    std::uint32_t reserved) noexcept {
    std::u16string wide;
    if (sub_key != nullptr && !narrow_in(sub_key, wide).converted) {
        return finish(kStatusInvalidParameter);
    }
    return ar_RegDeleteKeyExW(key,
                              sub_key == nullptr ? nullptr : wide.c_str(),
                              access, reserved);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDeleteTreeW(
    std::uint64_t key, const char16_t* sub_key) noexcept {
    return finish(core_delete_tree(key, view_of(sub_key)));
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDeleteTreeA(
    std::uint64_t key, const char* sub_key) noexcept {
    std::u16string wide;
    if (sub_key != nullptr && !narrow_in(sub_key, wide).converted) {
        return finish(kStatusInvalidParameter);
    }
    return ar_RegDeleteTreeW(key, sub_key == nullptr ? nullptr : wide.c_str());
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDeleteValueW(
    std::uint64_t key, const char16_t* value_name) noexcept {
    return finish(core_delete_value(key, {}, view_of(value_name)));
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDeleteValueA(
    std::uint64_t key, const char* value_name) noexcept {
    std::u16string wide;
    if (value_name != nullptr && !narrow_in(value_name, wide).converted) {
        return finish(kStatusInvalidParameter);
    }
    return ar_RegDeleteValueW(
        key, value_name == nullptr ? nullptr : wide.c_str());
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDeleteKeyValueW(
    std::uint64_t key, const char16_t* sub_key,
    const char16_t* value_name) noexcept {
    return finish(
        core_delete_value(key, view_of(sub_key), view_of(value_name)));
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDeleteKeyValueA(
    std::uint64_t key, const char* sub_key, const char* value_name) noexcept {
    std::u16string wide_key;
    std::u16string wide_value;
    if (sub_key != nullptr && !narrow_in(sub_key, wide_key).converted) {
        return finish(kStatusInvalidParameter);
    }
    if (value_name != nullptr && !narrow_in(value_name, wide_value).converted) {
        return finish(kStatusInvalidParameter);
    }
    return ar_RegDeleteKeyValueW(
        key, sub_key == nullptr ? nullptr : wide_key.c_str(),
        value_name == nullptr ? nullptr : wide_value.c_str());
}

// ---------------------------------------------------------------------------
// Set values
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSetValueExW(
    std::uint64_t key, const char16_t* value_name, std::uint32_t reserved,
    std::uint32_t type, const std::uint8_t* data,
    std::uint32_t bytes) noexcept {
    (void)reserved;
    // The type is stored as given. Windows accepts any type word here, and
    // so does the tree, because a value this runtime did not write should
    // still round-trip.
    return finish(core_set_value(key, {}, view_of(value_name), type, data,
                                 bytes));
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSetValueExA(
    std::uint64_t key, const char* value_name, std::uint32_t reserved,
    std::uint32_t type, const std::uint8_t* data,
    std::uint32_t bytes) noexcept {
    std::u16string wide;
    if (value_name != nullptr && !narrow_in(value_name, wide).converted) {
        return finish(kStatusInvalidParameter);
    }
    // The data is bytes in both forms; only the name converts.
    return ar_RegSetValueExW(
        key, value_name == nullptr ? nullptr : wide.c_str(), reserved, type,
        data, bytes);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSetKeyValueW(
    std::uint64_t key, const char16_t* sub_key, const char16_t* value_name,
    std::uint32_t type, const void* data, std::uint32_t bytes) noexcept {
    return finish(core_set_value(key, view_of(sub_key), view_of(value_name),
                                 type, data, bytes));
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSetKeyValueA(
    std::uint64_t key, const char* sub_key, const char* value_name,
    std::uint32_t type, const void* data, std::uint32_t bytes) noexcept {
    std::u16string wide_key;
    std::u16string wide_value;
    if (sub_key != nullptr && !narrow_in(sub_key, wide_key).converted) {
        return finish(kStatusInvalidParameter);
    }
    if (value_name != nullptr && !narrow_in(value_name, wide_value).converted) {
        return finish(kStatusInvalidParameter);
    }
    return ar_RegSetKeyValueW(
        key, sub_key == nullptr ? nullptr : wide_key.c_str(),
        value_name == nullptr ? nullptr : wide_value.c_str(), type, data,
        bytes);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSetValueW(
    std::uint64_t key, const char16_t* sub_key, std::uint32_t type,
    const char16_t* data, std::uint32_t bytes) noexcept {
    if (type != kRegSz || data == nullptr) {
        // The old `RegSetValue` is the default-value REG_SZ setter; a caller
        // passing another type is asking for what the call cannot mean.
        return finish(kStatusInvalidParameter);
    }
    (void)bytes;
    // The string is null-terminated and the terminator is stored, which is
    // how the old call writes it (Wine ignores `cbData` here as well).
    const std::u16string_view text = view_of(data);
    std::vector<std::uint8_t> blob((text.size() + 1) * sizeof(char16_t), 0);
    std::memcpy(blob.data(), text.data(), text.size() * sizeof(char16_t));
    return finish(core_set_value(key, view_of(sub_key), {}, kRegSz,
                                 blob.data(),
                                 static_cast<std::uint32_t>(blob.size())));
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSetValueA(
    std::uint64_t key, const char* sub_key, std::uint32_t type,
    const char* data, std::uint32_t bytes) noexcept {
    if (type != kRegSz || data == nullptr) {
        return finish(kStatusInvalidParameter);
    }
    (void)bytes;
    std::u16string wide_key;
    std::u16string wide_data;
    if (sub_key != nullptr && !narrow_in(sub_key, wide_key).converted) {
        return finish(kStatusInvalidParameter);
    }
    if (!narrow_in(data, wide_data).converted) {
        return finish(kStatusInvalidParameter);
    }
    return ar_RegSetValueW(key,
                           sub_key == nullptr ? nullptr : wide_key.c_str(),
                           type, wide_data.c_str(), 0);
}

// ---------------------------------------------------------------------------
// Query values
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegQueryValueExW(
    std::uint64_t key, const char16_t* value_name, std::uint32_t* reserved,
    std::uint32_t* type, std::uint8_t* data, std::uint32_t* size) noexcept {
    if (reserved != nullptr) {
        // Windows dereferences this slot and faults; the error is the
        // answer a runtime that cannot fault gives for the same mistake.
        return finish(kStatusInvalidParameter);
    }
    if (data != nullptr && size == nullptr) {
        return finish(kStatusInvalidParameter);
    }
    std::uint32_t stored = 0;
    std::vector<std::uint8_t> bytes;
    const std::int32_t status =
        core_get_value(key, {}, view_of(value_name), &stored, &bytes);
    if (status != kStatusOk) {
        return finish(status);
    }
    if (type != nullptr) {
        // The stored type, not the caller's expectation: the contract is
        // that the query reports what is there.
        *type = stored;
    }
    return finish(emit_w_data(bytes, data, size));
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegQueryValueExA(
    std::uint64_t key, const char* value_name, std::uint32_t* reserved,
    std::uint32_t* type, std::uint8_t* data, std::uint32_t* size) noexcept {
    if (reserved != nullptr) {
        return finish(kStatusInvalidParameter);
    }
    if (data != nullptr && size == nullptr) {
        return finish(kStatusInvalidParameter);
    }
    std::u16string wide;
    if (value_name != nullptr && !narrow_in(value_name, wide).converted) {
        return finish(kStatusInvalidParameter);
    }
    std::uint32_t stored = 0;
    std::vector<std::uint8_t> bytes;
    const std::int32_t status = core_get_value(
        key, {}, value_name == nullptr ? std::u16string_view{} : wide,
        &stored, &bytes);
    if (status != kStatusOk) {
        return finish(status);
    }
    if (type != nullptr) {
        *type = stored;
    }
    return finish(emit_a_data(bytes, stored, data, size));
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegQueryValueW(
    std::uint64_t key, const char16_t* sub_key, std::uint8_t* data,
    std::int32_t* size) noexcept {
    std::uint32_t stored = 0;
    std::vector<std::uint8_t> bytes;
    const std::int32_t status =
        core_get_value(key, view_of(sub_key), {}, &stored, &bytes);
    if (status != kStatusOk) {
        return finish(status);
    }
    if (size == nullptr) {
        return finish(kStatusOk);
    }
    std::uint32_t capacity = static_cast<std::uint32_t>(*size);
    const std::int32_t out = emit_w_data(bytes, data, &capacity);
    *size = static_cast<std::int32_t>(capacity);
    return finish(out);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegQueryValueA(
    std::uint64_t key, const char* sub_key, std::uint8_t* data,
    std::int32_t* size) noexcept {
    std::u16string wide;
    if (sub_key != nullptr && !narrow_in(sub_key, wide).converted) {
        return finish(kStatusInvalidParameter);
    }
    std::uint32_t stored = 0;
    std::vector<std::uint8_t> bytes;
    const std::int32_t status =
        core_get_value(key, sub_key == nullptr ? std::u16string_view{} : wide,
                       {}, &stored, &bytes);
    if (status != kStatusOk) {
        return finish(status);
    }
    if (size == nullptr) {
        return finish(kStatusOk);
    }
    std::uint32_t capacity = static_cast<std::uint32_t>(*size);
    const std::int32_t out = emit_a_data(bytes, stored, data, &capacity);
    *size = static_cast<std::int32_t>(capacity);
    return finish(out);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegGetValueW(
    std::uint64_t key, const char16_t* sub_key, const char16_t* value_name,
    std::uint32_t flags, std::uint32_t* type, std::uint8_t* data,
    std::uint32_t* size) noexcept {
    if (data != nullptr && size == nullptr) {
        return finish(kStatusInvalidParameter);
    }
    std::uint32_t stored = 0;
    std::vector<std::uint8_t> bytes;
    const std::int32_t status =
        core_get_value(key, view_of(sub_key), view_of(value_name), &stored,
                       &bytes);
    if (status != kStatusOk) {
        return finish(status);
    }
    // The restriction mask is what distinguishes this call from the plain
    // query: a stored type outside the mask is refused. Expansion of
    // REG_EXPAND_SZ is not performed -- the guest's environment block is not
    // this domain's to read -- so the value comes back with its stored type
    // and raw bytes.
    const std::uint32_t allowed = flags & kRrfRtMask;
    if (allowed != 0 && (type_bit_of(stored) & allowed) == 0) {
        return finish(kStatusInvalidParameter);
    }
    (void)kRrfNoExpand;
    if (type != nullptr) {
        *type = stored;
    }
    return finish(emit_w_data(bytes, data, size));
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegGetValueA(
    std::uint64_t key, const char* sub_key, const char* value_name,
    std::uint32_t flags, std::uint32_t* type, std::uint8_t* data,
    std::uint32_t* size) noexcept {
    if (data != nullptr && size == nullptr) {
        return finish(kStatusInvalidParameter);
    }
    std::u16string wide_key;
    std::u16string wide_value;
    if (sub_key != nullptr && !narrow_in(sub_key, wide_key).converted) {
        return finish(kStatusInvalidParameter);
    }
    if (value_name != nullptr && !narrow_in(value_name, wide_value).converted) {
        return finish(kStatusInvalidParameter);
    }
    std::uint32_t stored = 0;
    std::vector<std::uint8_t> bytes;
    const std::int32_t status = core_get_value(
        key,
        sub_key == nullptr ? std::u16string_view{}
                           : std::u16string_view(wide_key),
        value_name == nullptr ? std::u16string_view{}
                              : std::u16string_view(wide_value),
        &stored, &bytes);
    if (status != kStatusOk) {
        return finish(status);
    }
    const std::uint32_t allowed = flags & kRrfRtMask;
    if (allowed != 0 && (type_bit_of(stored) & allowed) == 0) {
        return finish(kStatusInvalidParameter);
    }
    if (type != nullptr) {
        *type = stored;
    }
    return finish(emit_a_data(bytes, stored, data, size));
}

// ---------------------------------------------------------------------------
// Enumerate
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegEnumKeyExW(
    std::uint64_t key, std::uint32_t index, char16_t* name,
    std::uint32_t* name_count, std::uint32_t* reserved, char16_t* klass,
    std::uint32_t* klass_count, std::uint8_t* last_write) noexcept {
    (void)reserved;
    if (name == nullptr || name_count == nullptr) {
        return finish(kStatusInvalidParameter);
    }
    std::u16string out_name;
    std::u16string out_class;
    const std::int32_t status = core_enum_key(key, index, &out_name, &out_class);
    if (status != kStatusOk) {
        return finish(status);
    }
    std::int32_t out = emit_w_text(out_name, name, name_count);
    if (out == kStatusOk && klass != nullptr) {
        out = emit_w_text(out_class, klass, klass_count);
    }
    if (out == kStatusOk && last_write != nullptr) {
        // The tree keeps no timestamps; a zero FILETIME is the "not known"
        // answer rather than an invented one.
        std::memset(last_write, 0, 8);
    }
    return finish(out);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegEnumKeyExA(
    std::uint64_t key, std::uint32_t index, char* name,
    std::uint32_t* name_count, std::uint32_t* reserved, char* klass,
    std::uint32_t* klass_count, std::uint8_t* last_write) noexcept {
    (void)reserved;
    if (name == nullptr || name_count == nullptr) {
        return finish(kStatusInvalidParameter);
    }
    std::u16string out_name;
    std::u16string out_class;
    const std::int32_t status = core_enum_key(key, index, &out_name, &out_class);
    if (status != kStatusOk) {
        return finish(status);
    }
    std::int32_t out = emit_a_text(out_name, name, name_count);
    if (out == kStatusOk && klass != nullptr) {
        out = emit_a_text(out_class, klass, klass_count);
    }
    if (out == kStatusOk && last_write != nullptr) {
        std::memset(last_write, 0, 8);
    }
    return finish(out);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegEnumKeyW(
    std::uint64_t key, std::uint32_t index, char16_t* name,
    std::uint32_t name_size) noexcept {
    if (name == nullptr) {
        return finish(kStatusInvalidParameter);
    }
    std::u16string out_name;
    std::u16string out_class;
    const std::int32_t status = core_enum_key(key, index, &out_name, &out_class);
    if (status != kStatusOk) {
        return finish(status);
    }
    const auto needed = static_cast<std::uint32_t>(out_name.size()) + 1;
    if (name_size < needed) {
        return finish(kStatusMoreData);
    }
    std::uint32_t ignored = name_size;
    return finish(emit_w_text(out_name, name, &ignored));
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegEnumKeyA(
    std::uint64_t key, std::uint32_t index, char* name,
    std::uint32_t name_size) noexcept {
    if (name == nullptr) {
        return finish(kStatusInvalidParameter);
    }
    std::u16string out_name;
    std::u16string out_class;
    const std::int32_t status = core_enum_key(key, index, &out_name, &out_class);
    if (status != kStatusOk) {
        return finish(status);
    }
    std::uint32_t capacity = name_size;
    return finish(emit_a_text(out_name, name, &capacity));
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegEnumValueW(
    std::uint64_t key, std::uint32_t index, char16_t* name,
    std::uint32_t* name_count, std::uint32_t* reserved, std::uint32_t* type,
    std::uint8_t* data, std::uint32_t* size) noexcept {
    (void)reserved;
    if (name == nullptr || name_count == nullptr) {
        return finish(kStatusInvalidParameter);
    }
    std::u16string out_name;
    std::uint32_t stored = 0;
    std::vector<std::uint8_t> bytes;
    const std::int32_t status =
        core_enum_value(key, index, &out_name, &stored, &bytes);
    if (status != kStatusOk) {
        return finish(status);
    }
    if (type != nullptr) {
        *type = stored;
    }
    std::int32_t out = emit_w_text(out_name, name, name_count);
    if (out == kStatusOk) {
        out = emit_w_data(bytes, data, size);
    }
    return finish(out);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegEnumValueA(
    std::uint64_t key, std::uint32_t index, char* name,
    std::uint32_t* name_count, std::uint32_t* reserved, std::uint32_t* type,
    std::uint8_t* data, std::uint32_t* size) noexcept {
    (void)reserved;
    if (name == nullptr || name_count == nullptr) {
        return finish(kStatusInvalidParameter);
    }
    std::u16string out_name;
    std::uint32_t stored = 0;
    std::vector<std::uint8_t> bytes;
    const std::int32_t status =
        core_enum_value(key, index, &out_name, &stored, &bytes);
    if (status != kStatusOk) {
        return finish(status);
    }
    if (type != nullptr) {
        *type = stored;
    }
    std::int32_t out = emit_a_text(out_name, name, name_count);
    if (out == kStatusOk) {
        out = emit_a_data(bytes, stored, data, size);
    }
    return finish(out);
}

// ---------------------------------------------------------------------------
// Key information, multiple values, copy, rename
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegQueryInfoKeyW(
    std::uint64_t key, char16_t* klass, std::uint32_t* klass_count,
    std::uint32_t* reserved, std::uint32_t* subkeys,
    std::uint32_t* max_subkey, std::uint32_t* max_class,
    std::uint32_t* values, std::uint32_t* max_value_name,
    std::uint32_t* max_value_data, std::uint32_t* security_descriptor_size,
    std::uint8_t* last_write) noexcept {
    (void)reserved;
    KeyInfo info;
    const std::int32_t status = core_query_info(key, &info);
    if (status != kStatusOk) {
        return finish(status);
    }
    if (subkeys != nullptr) {
        *subkeys = info.subkeys;
    }
    if (max_subkey != nullptr) {
        *max_subkey = info.max_subkey_chars;
    }
    if (max_class != nullptr) {
        *max_class = info.max_class_chars;
    }
    if (values != nullptr) {
        *values = info.values;
    }
    if (max_value_name != nullptr) {
        *max_value_name = info.max_value_name_chars;
    }
    if (max_value_data != nullptr) {
        *max_value_data = info.max_value_data_bytes;
    }
    if (security_descriptor_size != nullptr) {
        // No security is modelled, and the honest size of nothing is zero.
        *security_descriptor_size = 0;
    }
    if (last_write != nullptr) {
        std::memset(last_write, 0, 8);
    }
    if (klass != nullptr) {
        return finish(emit_w_text(info.klass, klass, klass_count));
    }
    return finish(kStatusOk);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegQueryInfoKeyA(
    std::uint64_t key, char* klass, std::uint32_t* klass_count,
    std::uint32_t* reserved, std::uint32_t* subkeys,
    std::uint32_t* max_subkey, std::uint32_t* max_class,
    std::uint32_t* values, std::uint32_t* max_value_name,
    std::uint32_t* max_value_data, std::uint32_t* security_descriptor_size,
    std::uint8_t* last_write) noexcept {
    (void)reserved;
    KeyInfo info;
    const std::int32_t status = core_query_info(key, &info);
    if (status != kStatusOk) {
        return finish(status);
    }
    if (subkeys != nullptr) {
        *subkeys = info.subkeys;
    }
    if (max_subkey != nullptr) {
        *max_subkey = info.max_subkey_chars;
    }
    if (max_class != nullptr) {
        *max_class = info.max_class_chars;
    }
    if (values != nullptr) {
        *values = info.values;
    }
    if (max_value_name != nullptr) {
        *max_value_name = info.max_value_name_chars;
    }
    if (max_value_data != nullptr) {
        *max_value_data = info.max_value_data_bytes;
    }
    if (security_descriptor_size != nullptr) {
        *security_descriptor_size = 0;
    }
    if (last_write != nullptr) {
        std::memset(last_write, 0, 8);
    }
    if (klass != nullptr) {
        return finish(emit_a_text(info.klass, klass, klass_count));
    }
    return finish(kStatusOk);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegQueryMultipleValuesW(
    std::uint64_t key, void* valents, std::uint32_t count, char16_t* buffer,
    std::uint32_t* total) noexcept {
    if (valents == nullptr || buffer == nullptr || total == nullptr ||
        count == 0) {
        return finish(kStatusInvalidParameter);
    }
    RegKey* at = base_key(key);
    if (at == nullptr) {
        return finish(kStatusInvalidHandle);
    }
    std::vector<const RegValue*> found;
    found.reserve(count);
    std::uint32_t needed = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto* entry =
            static_cast<const std::uint8_t*>(valents) + i * kValentSize;
        const std::uint64_t name_ptr = read_ptr(entry, kValentName);
        const RegValue* slot =
            at->find_value(view_of(reinterpret_cast<const char16_t*>(name_ptr)));
        if (slot == nullptr) {
            return finish(kStatusFileNotFound);
        }
        found.push_back(slot);
        needed += static_cast<std::uint32_t>(slot->data.size());
    }
    if (needed > *total) {
        // Nothing is written on the short path: the caller retries with the
        // size it was told.
        *total = needed;
        return finish(kStatusMoreData);
    }
    std::size_t offset = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        auto* entry = static_cast<std::uint8_t*>(valents) + i * kValentSize;
        const RegValue* slot = found[i];
        if (!slot->data.empty()) {
            std::memcpy(reinterpret_cast<std::uint8_t*>(buffer) + offset,
                        slot->data.data(), slot->data.size());
        }
        write_u32(entry, kValentLength,
                  static_cast<std::uint32_t>(slot->data.size()));
        write_ptr(entry, kValentValuePtr,
                  reinterpret_cast<std::uint64_t>(
                      reinterpret_cast<std::uint8_t*>(buffer) + offset));
        write_u32(entry, kValentType, slot->type);
        offset += slot->data.size();
    }
    *total = needed;
    return finish(kStatusOk);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegQueryMultipleValuesA(
    std::uint64_t key, void* valents, std::uint32_t count, char* buffer,
    std::uint32_t* total) noexcept {
    if (valents == nullptr || buffer == nullptr || total == nullptr ||
        count == 0) {
        return finish(kStatusInvalidParameter);
    }
    RegKey* at = base_key(key);
    if (at == nullptr) {
        return finish(kStatusInvalidHandle);
    }
    std::vector<const RegValue*> found;
    std::vector<std::string> narrow_data;
    found.reserve(count);
    narrow_data.reserve(count);
    std::uint32_t needed = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto* entry =
            static_cast<const std::uint8_t*>(valents) + i * kValentSize;
        const std::uint64_t name_ptr = read_ptr(entry, kValentName);
        const char16_t* wide_name =
            reinterpret_cast<const char16_t*>(name_ptr);
        const RegValue* slot = at->find_value(view_of(wide_name));
        if (slot == nullptr) {
            return finish(kStatusFileNotFound);
        }
        std::string narrow;
        const std::int32_t status = ansi_of(slot->data, slot->type, &narrow);
        if (status != kStatusOk) {
            return finish(status);
        }
        needed += static_cast<std::uint32_t>(narrow.size());
        found.push_back(slot);
        narrow_data.push_back(std::move(narrow));
    }
    if (needed > *total) {
        *total = needed;
        return finish(kStatusMoreData);
    }
    std::size_t offset = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        auto* entry = static_cast<std::uint8_t*>(valents) + i * kValentSize;
        const std::string& narrow = narrow_data[i];
        if (!narrow.empty()) {
            std::memcpy(reinterpret_cast<std::uint8_t*>(buffer) + offset,
                        narrow.data(), narrow.size());
        }
        write_u32(entry, kValentLength,
                  static_cast<std::uint32_t>(narrow.size()));
        write_ptr(entry, kValentValuePtr,
                  reinterpret_cast<std::uint64_t>(
                      reinterpret_cast<std::uint8_t*>(buffer) + offset));
        write_u32(entry, kValentType, found[i]->type);
        offset += narrow.size();
    }
    *total = needed;
    return finish(kStatusOk);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegCopyTreeW(
    std::uint64_t src_key, const char16_t* sub_key,
    std::uint64_t dst_key) noexcept {
    return finish(core_copy_tree(src_key, view_of(sub_key), dst_key));
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegCopyTreeA(
    std::uint64_t src_key, const char* sub_key, std::uint64_t dst_key) noexcept {
    std::u16string wide;
    if (sub_key != nullptr && !narrow_in(sub_key, wide).converted) {
        return finish(kStatusInvalidParameter);
    }
    return ar_RegCopyTreeW(src_key,
                           sub_key == nullptr ? nullptr : wide.c_str(),
                           dst_key);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegRenameKey(
    std::uint64_t key, const char16_t* sub_key,
    const char16_t* new_name) noexcept {
    return finish(core_rename(key, view_of(sub_key), view_of(new_name)));
}

// ---------------------------------------------------------------------------
// The stateless answers
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegFlushKey(
    std::uint64_t key) noexcept {
    // The tree is memory and nothing is pending behind it, so a flush is a
    // validity check with nothing to write.
    if (base_key(key) == nullptr) {
        return finish(kStatusInvalidHandle);
    }
    return finish(kStatusOk);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDisablePredefinedCache()
    noexcept {
    // This runtime never caches predefined handles, so the request is
    // already true.
    return finish(kStatusOk);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegEnableReflectionKey(
    std::uint64_t key) noexcept {
    if (base_key(key) == nullptr) {
        return finish(kStatusInvalidHandle);
    }
    // There is no WoW64 view here, so there is no reflection to enable; the
    // state the caller asks for is the state the tree is in.
    return finish(kStatusOk);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegDisableReflectionKey(
    std::uint64_t key) noexcept {
    if (base_key(key) == nullptr) {
        return finish(kStatusInvalidHandle);
    }
    return finish(kStatusOk);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegQueryReflectionKey(
    std::uint64_t key, std::int32_t* is_reflected) noexcept {
    if (is_reflected == nullptr) {
        return finish(kStatusInvalidParameter);
    }
    if (base_key(key) == nullptr) {
        return finish(kStatusInvalidHandle);
    }
    *is_reflected = 0;
    return finish(kStatusOk);
}

// ---------------------------------------------------------------------------
// The refusals
// ---------------------------------------------------------------------------

// Each of these needs something this runtime does not have: a file-backed
// hive, a remote machine, a change-notification pipe, a security descriptor
// or an MUI catalogue. Answering `ERROR_CALL_NOT_IMPLEMENTED` is the honest
// refusal; a fake success would be a lie a caller would build on.

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegConnectRegistryW(
    const char16_t* machine, std::uint64_t key, std::uint64_t* result) noexcept {
    (void)machine;
    (void)key;
    (void)result;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegConnectRegistryA(
    const char* machine, std::uint64_t key, std::uint64_t* result) noexcept {
    (void)machine;
    (void)key;
    (void)result;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegLoadKeyW(
    std::uint64_t key, const char16_t* sub_key, const char16_t* file) noexcept {
    (void)key;
    (void)sub_key;
    (void)file;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegLoadKeyA(
    std::uint64_t key, const char* sub_key, const char* file) noexcept {
    (void)key;
    (void)sub_key;
    (void)file;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegUnLoadKeyW(
    std::uint64_t key, const char16_t* sub_key) noexcept {
    (void)key;
    (void)sub_key;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegUnLoadKeyA(
    std::uint64_t key, const char* sub_key) noexcept {
    (void)key;
    (void)sub_key;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegLoadAppKeyW(
    const char16_t* file, std::uint32_t options, std::uint32_t access,
    std::uint32_t reserved) noexcept {
    (void)file;
    (void)options;
    (void)access;
    (void)reserved;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegLoadAppKeyA(
    const char* file, std::uint32_t options, std::uint32_t access,
    std::uint32_t reserved) noexcept {
    (void)file;
    (void)options;
    (void)access;
    (void)reserved;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSaveKeyW(
    std::uint64_t key, const char16_t* file, const void* security) noexcept {
    (void)key;
    (void)file;
    (void)security;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSaveKeyA(
    std::uint64_t key, const char* file, const void* security) noexcept {
    (void)key;
    (void)file;
    (void)security;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSaveKeyExW(
    std::uint64_t key, const char16_t* file, const void* security,
    std::uint32_t format) noexcept {
    (void)key;
    (void)file;
    (void)security;
    (void)format;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSaveKeyExA(
    std::uint64_t key, const char* file, const void* security,
    std::uint32_t format) noexcept {
    (void)key;
    (void)file;
    (void)security;
    (void)format;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegRestoreKeyW(
    std::uint64_t key, const char16_t* file, std::uint32_t flags) noexcept {
    (void)key;
    (void)file;
    (void)flags;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegRestoreKeyA(
    std::uint64_t key, const char* file, std::uint32_t flags) noexcept {
    (void)key;
    (void)file;
    (void)flags;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegReplaceKeyW(
    std::uint64_t key, const char16_t* sub_key, const char16_t* new_file,
    const char16_t* old_file) noexcept {
    (void)key;
    (void)sub_key;
    (void)new_file;
    (void)old_file;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegReplaceKeyA(
    std::uint64_t key, const char* sub_key, const char* new_file,
    const char* old_file) noexcept {
    (void)key;
    (void)sub_key;
    (void)new_file;
    (void)old_file;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegNotifyChangeKeyValue(
    std::uint64_t key, std::int32_t watch_subtree, std::uint32_t filter,
    std::uint64_t event, std::int32_t asynchronous) noexcept {
    (void)key;
    (void)watch_subtree;
    (void)filter;
    (void)event;
    (void)asynchronous;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegGetKeySecurity(
    std::uint64_t key, std::uint32_t security_information,
    void* descriptor, std::uint32_t* descriptor_size) noexcept {
    (void)key;
    (void)security_information;
    (void)descriptor;
    (void)descriptor_size;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegSetKeySecurity(
    std::uint64_t key, std::uint32_t security_information,
    void* descriptor) noexcept {
    (void)key;
    (void)security_information;
    (void)descriptor;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegLoadMUIStringW(
    std::uint64_t key, const char16_t* value_name, char16_t* out,
    std::uint32_t out_size, std::uint32_t* size, std::uint32_t flags,
    const char16_t* directory) noexcept {
    (void)key;
    (void)value_name;
    (void)out;
    (void)out_size;
    (void)size;
    (void)flags;
    (void)directory;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegLoadMUIStringA(
    std::uint64_t key, const char* value_name, char* out,
    std::uint32_t out_size, std::uint32_t* size, std::uint32_t flags,
    const char* directory) noexcept {
    (void)key;
    (void)value_name;
    (void)out;
    (void)out_size;
    (void)size;
    (void)flags;
    (void)directory;
    return finish(kStatusCallNotImplemented);
}

extern "C" __attribute__((ms_abi)) std::int32_t ar_RegRemapPreDefKey(
    std::uint64_t key, std::uint64_t target) noexcept {
    (void)key;
    (void)target;
    return finish(kStatusCallNotImplemented);
}

// ---------------------------------------------------------------------------
// The services, event log and tracing names the order assigns to this domain
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint64_t ar_RegisterEventSourceW(
    const char16_t* server, const char16_t* source) noexcept {
    (void)server;
    (void)source;
    // The registration hands back a unique opaque handle. No log is written:
    // this runtime has no event-log service behind it, and the handle is
    // exactly what it says -- a registration -- and nothing more.
    set_last_error(kErrorSuccess);
    return g_next_event_source++;
}

extern "C" __attribute__((ms_abi)) std::uint64_t ar_RegisterEventSourceA(
    const char* server, const char* source) noexcept {
    (void)server;
    (void)source;
    return ar_RegisterEventSourceW(nullptr, nullptr);
}

extern "C" __attribute__((ms_abi)) std::uint64_t
ar_RegisterServiceCtrlHandlerW(const char16_t* service_name,
                               void* handler) noexcept {
    (void)service_name;
    (void)handler;
    // There is no service control dispatcher to register with, so there is
    // no handle that could mean anything. The refusal is the answer a
    // service main can test for, and a fake handle would send it into a
    // status loop that would never be served.
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t
ar_RegisterServiceCtrlHandlerA(const char* service_name, void* handler) noexcept {
    (void)service_name;
    (void)handler;
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t
ar_RegisterServiceCtrlHandlerExW(const char16_t* service_name, void* handler,
                                 void* context) noexcept {
    (void)service_name;
    (void)handler;
    (void)context;
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t
ar_RegisterServiceCtrlHandlerExA(const char* service_name, void* handler,
                                 void* context) noexcept {
    (void)service_name;
    (void)handler;
    (void)context;
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t ar_RegisterTraceGuidsW(
    const void* control_guid, void* instance_guids,
    const char16_t* mof_image_path, std::uint32_t guid_count,
    const void* trace_guid_reg, const char16_t* mof_resource_name,
    void* callback, std::uint64_t* registration_handle) noexcept {
    (void)control_guid;
    (void)instance_guids;
    (void)mof_image_path;
    (void)guid_count;
    (void)trace_guid_reg;
    (void)mof_resource_name;
    (void)callback;
    (void)registration_handle;
    // No ETW session machinery exists here; the registration is refused with
    // the Win32 code the ULONG contract carries.
    set_last_error(kErrorCallNotImplemented);
    return kErrorCallNotImplemented;
}

extern "C" __attribute__((ms_abi)) std::uint32_t ar_RegisterTraceGuidsA(
    const void* control_guid, void* instance_guids, const char* mof_image_path,
    std::uint32_t guid_count, const void* trace_guid_reg,
    const char* mof_resource_name, void* callback,
    std::uint64_t* registration_handle) noexcept {
    (void)control_guid;
    (void)instance_guids;
    (void)mof_image_path;
    (void)guid_count;
    (void)trace_guid_reg;
    (void)mof_resource_name;
    (void)callback;
    (void)registration_handle;
    set_last_error(kErrorCallNotImplemented);
    return kErrorCallNotImplemented;
}

extern "C" __attribute__((ms_abi)) void ar_RegisterWaitChainCOMCallback(
    void* call_state_callback, void* callback) noexcept {
    // The callbacks are accepted and never invoked: no wait-chain analysis
    // runs in this runtime, so there is no event that could call them. A
    // void function has no failure to report, and this one makes no promise
    // beyond that.
    (void)call_state_callback;
    (void)callback;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void add_advapi32_reg(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("RegCloseKey", reinterpret_cast<void*>(&ar_RegCloseKey));
    e("RegConnectRegistryA", reinterpret_cast<void*>(&ar_RegConnectRegistryA));
    e("RegConnectRegistryW", reinterpret_cast<void*>(&ar_RegConnectRegistryW));
    e("RegCopyTreeA", reinterpret_cast<void*>(&ar_RegCopyTreeA));
    e("RegCopyTreeW", reinterpret_cast<void*>(&ar_RegCopyTreeW));
    e("RegCreateKeyA", reinterpret_cast<void*>(&ar_RegCreateKeyA));
    e("RegCreateKeyExA", reinterpret_cast<void*>(&ar_RegCreateKeyExA));
    e("RegCreateKeyExW", reinterpret_cast<void*>(&ar_RegCreateKeyExW));
    e("RegCreateKeyTransactedA",
      reinterpret_cast<void*>(&ar_RegCreateKeyTransactedA));
    e("RegCreateKeyTransactedW",
      reinterpret_cast<void*>(&ar_RegCreateKeyTransactedW));
    e("RegCreateKeyW", reinterpret_cast<void*>(&ar_RegCreateKeyW));
    e("RegDeleteKeyA", reinterpret_cast<void*>(&ar_RegDeleteKeyA));
    e("RegDeleteKeyExA", reinterpret_cast<void*>(&ar_RegDeleteKeyExA));
    e("RegDeleteKeyExW", reinterpret_cast<void*>(&ar_RegDeleteKeyExW));
    e("RegDeleteKeyValueA", reinterpret_cast<void*>(&ar_RegDeleteKeyValueA));
    e("RegDeleteKeyValueW", reinterpret_cast<void*>(&ar_RegDeleteKeyValueW));
    e("RegDeleteKeyW", reinterpret_cast<void*>(&ar_RegDeleteKeyW));
    e("RegDeleteTreeA", reinterpret_cast<void*>(&ar_RegDeleteTreeA));
    e("RegDeleteTreeW", reinterpret_cast<void*>(&ar_RegDeleteTreeW));
    e("RegDeleteValueA", reinterpret_cast<void*>(&ar_RegDeleteValueA));
    e("RegDeleteValueW", reinterpret_cast<void*>(&ar_RegDeleteValueW));
    e("RegDisablePredefinedCache",
      reinterpret_cast<void*>(&ar_RegDisablePredefinedCache));
    e("RegDisableReflectionKey",
      reinterpret_cast<void*>(&ar_RegDisableReflectionKey));
    e("RegEnableReflectionKey",
      reinterpret_cast<void*>(&ar_RegEnableReflectionKey));
    e("RegEnumKeyA", reinterpret_cast<void*>(&ar_RegEnumKeyA));
    e("RegEnumKeyExA", reinterpret_cast<void*>(&ar_RegEnumKeyExA));
    e("RegEnumKeyExW", reinterpret_cast<void*>(&ar_RegEnumKeyExW));
    e("RegEnumKeyW", reinterpret_cast<void*>(&ar_RegEnumKeyW));
    e("RegEnumValueA", reinterpret_cast<void*>(&ar_RegEnumValueA));
    e("RegEnumValueW", reinterpret_cast<void*>(&ar_RegEnumValueW));
    e("RegFlushKey", reinterpret_cast<void*>(&ar_RegFlushKey));
    e("RegGetKeySecurity", reinterpret_cast<void*>(&ar_RegGetKeySecurity));
    e("RegGetValueA", reinterpret_cast<void*>(&ar_RegGetValueA));
    e("RegGetValueW", reinterpret_cast<void*>(&ar_RegGetValueW));
    e("RegLoadAppKeyA", reinterpret_cast<void*>(&ar_RegLoadAppKeyA));
    e("RegLoadAppKeyW", reinterpret_cast<void*>(&ar_RegLoadAppKeyW));
    e("RegLoadKeyA", reinterpret_cast<void*>(&ar_RegLoadKeyA));
    e("RegLoadKeyW", reinterpret_cast<void*>(&ar_RegLoadKeyW));
    e("RegLoadMUIStringA", reinterpret_cast<void*>(&ar_RegLoadMUIStringA));
    e("RegLoadMUIStringW", reinterpret_cast<void*>(&ar_RegLoadMUIStringW));
    e("RegNotifyChangeKeyValue",
      reinterpret_cast<void*>(&ar_RegNotifyChangeKeyValue));
    e("RegOpenCurrentUser", reinterpret_cast<void*>(&ar_RegOpenCurrentUser));
    e("RegOpenKeyA", reinterpret_cast<void*>(&ar_RegOpenKeyA));
    e("RegOpenKeyExA", reinterpret_cast<void*>(&ar_RegOpenKeyExA));
    e("RegOpenKeyExW", reinterpret_cast<void*>(&ar_RegOpenKeyExW));
    e("RegOpenKeyW", reinterpret_cast<void*>(&ar_RegOpenKeyW));
    e("RegOpenUserClassesRoot",
      reinterpret_cast<void*>(&ar_RegOpenUserClassesRoot));
    e("RegOverridePredefKey", reinterpret_cast<void*>(&ar_RegOverridePredefKey));
    e("RegQueryInfoKeyA", reinterpret_cast<void*>(&ar_RegQueryInfoKeyA));
    e("RegQueryInfoKeyW", reinterpret_cast<void*>(&ar_RegQueryInfoKeyW));
    e("RegQueryMultipleValuesA",
      reinterpret_cast<void*>(&ar_RegQueryMultipleValuesA));
    e("RegQueryMultipleValuesW",
      reinterpret_cast<void*>(&ar_RegQueryMultipleValuesW));
    e("RegQueryReflectionKey", reinterpret_cast<void*>(&ar_RegQueryReflectionKey));
    e("RegQueryValueA", reinterpret_cast<void*>(&ar_RegQueryValueA));
    e("RegQueryValueExA", reinterpret_cast<void*>(&ar_RegQueryValueExA));
    e("RegQueryValueExW", reinterpret_cast<void*>(&ar_RegQueryValueExW));
    e("RegQueryValueW", reinterpret_cast<void*>(&ar_RegQueryValueW));
    e("RegRemapPreDefKey", reinterpret_cast<void*>(&ar_RegRemapPreDefKey));
    e("RegRenameKey", reinterpret_cast<void*>(&ar_RegRenameKey));
    e("RegReplaceKeyA", reinterpret_cast<void*>(&ar_RegReplaceKeyA));
    e("RegReplaceKeyW", reinterpret_cast<void*>(&ar_RegReplaceKeyW));
    e("RegRestoreKeyA", reinterpret_cast<void*>(&ar_RegRestoreKeyA));
    e("RegRestoreKeyW", reinterpret_cast<void*>(&ar_RegRestoreKeyW));
    e("RegSaveKeyA", reinterpret_cast<void*>(&ar_RegSaveKeyA));
    e("RegSaveKeyExA", reinterpret_cast<void*>(&ar_RegSaveKeyExA));
    e("RegSaveKeyExW", reinterpret_cast<void*>(&ar_RegSaveKeyExW));
    e("RegSaveKeyW", reinterpret_cast<void*>(&ar_RegSaveKeyW));
    e("RegSetKeySecurity", reinterpret_cast<void*>(&ar_RegSetKeySecurity));
    e("RegSetKeyValueA", reinterpret_cast<void*>(&ar_RegSetKeyValueA));
    e("RegSetKeyValueW", reinterpret_cast<void*>(&ar_RegSetKeyValueW));
    e("RegSetValueA", reinterpret_cast<void*>(&ar_RegSetValueA));
    e("RegSetValueExA", reinterpret_cast<void*>(&ar_RegSetValueExA));
    e("RegSetValueExW", reinterpret_cast<void*>(&ar_RegSetValueExW));
    e("RegSetValueW", reinterpret_cast<void*>(&ar_RegSetValueW));
    e("RegUnLoadKeyA", reinterpret_cast<void*>(&ar_RegUnLoadKeyA));
    e("RegUnLoadKeyW", reinterpret_cast<void*>(&ar_RegUnLoadKeyW));
    e("RegisterEventSourceA", reinterpret_cast<void*>(&ar_RegisterEventSourceA));
    e("RegisterEventSourceW", reinterpret_cast<void*>(&ar_RegisterEventSourceW));
    e("RegisterServiceCtrlHandlerA",
      reinterpret_cast<void*>(&ar_RegisterServiceCtrlHandlerA));
    e("RegisterServiceCtrlHandlerExA",
      reinterpret_cast<void*>(&ar_RegisterServiceCtrlHandlerExA));
    e("RegisterServiceCtrlHandlerExW",
      reinterpret_cast<void*>(&ar_RegisterServiceCtrlHandlerExW));
    e("RegisterServiceCtrlHandlerW",
      reinterpret_cast<void*>(&ar_RegisterServiceCtrlHandlerW));
    e("RegisterTraceGuidsA", reinterpret_cast<void*>(&ar_RegisterTraceGuidsA));
    e("RegisterTraceGuidsW", reinterpret_cast<void*>(&ar_RegisterTraceGuidsW));
    e("RegisterWaitChainCOMCallback",
      reinterpret_cast<void*>(&ar_RegisterWaitChainCOMCallback));
}

}  // namespace occ::runtime::winabi

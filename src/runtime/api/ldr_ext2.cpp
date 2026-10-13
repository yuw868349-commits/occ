// The loader's second shelf: the Ldr calls a program that works at the
// ntdll level reaches when it wants the module list, the loader lock, the
// module reference counts, or a module's resources -- plus the two Win32
// names that complete the loader family.
//
// Everything here is a real implementation over the machinery the loader
// already has. `LdrGetDllHandle` is `GetModuleHandleW` with an NTSTATUS
// answer and a counted name. `LdrUnloadDll`, `LdrAddRefDll` and
// `LdrReleaseDll` maintain the same module registry `LoadLibrary` writes,
// so an unload here is an unload a later load sees. `LdrFindEntryForAddress`
// walks the PEB's `InLoadOrderModuleList` in guest memory, which is the
// same list the guest-module layer built for hand-rolled walkers. The
// resource calls parse the placed image's `.rsrc` directory in guest memory
// with the real `IMAGE_RESOURCE_*` layouts, so a program that reads a
// resource's bytes through `LdrAccessResource` gets the bytes the image
// carries.
//
// Three boundaries are named:
//
//   * The module *image* survives `LdrUnloadDll`: the placed images are a
//     process-lifetime registry, and unload removes the handle from the
//     module table (so the handle is no longer valid and a later load gets
//     a fresh handle) while the image stays placed. That is the model the
//     rest of the loader uses, and an unload that freed the image would
//     break every other walker.
//
//   * `LdrRegisterDllNotification` registers for real -- entries are stored
//     and unregistered by cookie -- but the load path (`LoadLibrary` in
//     winabi.cpp) does not yet dispatch notifications. The registration
//     half is honest; the delivery half is a named gap.
//
//   * `LdrGetProcedureAddressEx` accepts the `SKIP_KNOWN_DLLS` magic flag
//     but both paths answer from the same table: this runtime's "known
//     DLLs" *are* the host implementation, so the distinction the flag
//     draws (skip the static export cache) has no second table to skip.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace occ::runtime::winabi {
namespace {

// ---------------------------------------------------------------------------
// The NTSTATUS values these calls answer with
// ---------------------------------------------------------------------------

constexpr std::uint32_t kStSuccess = 0x00000000u;
constexpr std::uint32_t kStInvalidHandle = 0xC0000008u;
constexpr std::uint32_t kStInvalidParameter = 0xC000000Du;
constexpr std::uint32_t kStDllNotFound = 0xC0000135u;
constexpr std::uint32_t kStNotFound = 0xC0000225u;
constexpr std::uint32_t kStNoMemory = 0xC0000017u;
constexpr std::uint32_t kStResourceDataNotFound = 0xC0000205u;
constexpr std::uint32_t kStResourceNameNotFound = 0xC0000206u;
constexpr std::uint32_t kStResourceLangNotFound = 0xC0000207u;
constexpr std::uint32_t kStResourceTypeNotFound = 0xC0000208u;

// The loader-lock cookie. The cookie is the address of a process-lifetime
// slot: unique per process, stable, and unforgeable by accident.
[[nodiscard]] std::uint64_t loader_lock_cookie() noexcept {
    static char cookie_slot = 0;
    return reinterpret_cast<std::uint64_t>(&cookie_slot);
}

// `LDR_GET_PROCEDURE_ADDRESS_EX_FLAGS`.
constexpr std::uint32_t kLdrGetProcedureAddressExSkipKnownDlls = 0x00000001u;
constexpr std::uint32_t kLdrGetProcedureAddressExFromUnicode = 0x00000002u;

// The `LDR_DATA_TABLE_ENTRY` layout, as `guest_module.cpp` builds it and a
// hand-rolled walker reads it. The InLoadOrder list link is at +0, the
// DllBase at +0x30, the SizeOfImage at +0x40, and the two name records at
// +0x48 / +0x58.
struct LdrEntryLayout {
    static constexpr std::size_t kInLoad = 0x00;
    static constexpr std::size_t kDllBase = 0x30;
    static constexpr std::size_t kSizeOfImage = 0x40;
    static constexpr std::size_t kFullDllName = 0x48;
    static constexpr std::size_t kBaseDllName = 0x58;
};

// A counted string record, as the loader spells it. UNICODE_STRING and
// ANSI_STRING share the layout.
struct CountedString {
    std::uint16_t length = 0;
    std::uint16_t maximum = 0;
    std::uint64_t buffer = 0;
};

// Copies a counted string record out of guest memory into a host string.
[[nodiscard]] bool read_counted_string(const std::uint8_t* record,
                                       std::string& out,
                                       bool wide) noexcept {
    if (record == nullptr) {
        return false;
    }
    CountedString cs;
    std::memcpy(&cs.length, record, 2);
    std::memcpy(&cs.maximum, record + 2, 2);
    std::memcpy(&cs.buffer, record + 8, 8);
    if (cs.buffer == 0) {
        return false;
    }
    if (wide) {
        const char16_t* chars = reinterpret_cast<const char16_t*>(cs.buffer);
        const std::size_t units = static_cast<std::size_t>(cs.length) / 2;
        for (std::size_t i = 0; i < units; ++i) {
            out.push_back(static_cast<char>(chars[i]));
        }
    } else {
        const char* chars = reinterpret_cast<const char*>(cs.buffer);
        out.assign(chars, cs.length);
    }
    return true;
}

// The bridges this file calls. `k32_LoadLibraryW` / `k32_GetModuleHandleW`
// / `k32_GetProcAddress` are the Win32 loader in winabi.cpp; the existing
// `k32ldr_LdrGetProcedureAddress` is the Ldr spelling of the same lookup.
extern "C" __attribute__((ms_abi)) std::uint64_t k32_LoadLibraryW(
    const char16_t* name) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32_LoadLibraryExW(
    const char16_t* name, void* file, std::uint32_t flags) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32_GetModuleHandleW(
    const char16_t* name) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32_GetProcAddress(
    std::uint64_t module, const char* name) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32ldr_LdrGetProcedureAddress(
    std::uint64_t module, const std::uint8_t* name, std::uint32_t ordinal,
    std::uint64_t* address) noexcept;

// ---------------------------------------------------------------------------
// The module reference-count table
// ---------------------------------------------------------------------------
//
// Real reference counts beside the module registry: `LdrAddRefDll` /
// `LdrReleaseDll` count and `LdrUnloadDll` / a release to zero remove the
// handle from the registry `LoadLibrary` answers from.

std::mutex& refcount_lock() noexcept {
    static std::mutex lock;
    return lock;
}

std::map<std::uint64_t, std::uint32_t>& module_refcounts() noexcept {
    static std::map<std::uint64_t, std::uint32_t> counts;
    return counts;
}

// Removes a module handle from the registry and its reference count.
[[nodiscard]] bool drop_module(GuestState& g, std::uint64_t base) noexcept {
    const auto it = g.libraries.find(base);
    if (it == g.libraries.end()) {
        return false;
    }
    g.libraries.erase(it);
    std::lock_guard<std::mutex> lock(refcount_lock());
    module_refcounts().erase(base);
    return true;
}

// ---------------------------------------------------------------------------
// The PEB loader-list walk
// ---------------------------------------------------------------------------
//
// The list is real guest memory built by the guest-module layer. The walk
// follows the same InLoadOrder links a hand-rolled walker follows, so an
// answer here and a walker's answer cannot disagree.

[[nodiscard]] std::uint64_t loader_list_head(GuestState& g) noexcept {
    return g.peb + 0x200 + 0x10;  // PEB_LDR_DATA + InLoadOrderModuleList
}

// The loader entry (guest address) whose BaseDllName matches `wanted`,
// compared without regard to case, or 0.
[[nodiscard]] std::uint64_t loader_entry_for_name(GuestState& g,
                                                  const std::u16string& wanted) noexcept {
    const std::uint64_t head = loader_list_head(g);
    std::uint64_t link = read_ptr(reinterpret_cast<const void*>(head), 0);
    while (link != head) {
        const std::uint64_t entry = link - LdrEntryLayout::kInLoad;
        const std::uint64_t name_record = entry + LdrEntryLayout::kBaseDllName;
        const std::uint16_t length = read_u16(reinterpret_cast<const void*>(name_record), 0);
        const std::uint64_t buffer = read_ptr(reinterpret_cast<const void*>(name_record), 8);
        if (buffer != 0 && static_cast<std::size_t>(length) == wanted.size() * 2) {
            const char16_t* chars = reinterpret_cast<const char16_t*>(buffer);
            bool same = true;
            for (std::size_t i = 0; i < wanted.size(); ++i) {
                char16_t a = wanted[i];
                char16_t b = chars[i];
                if (b >= u'A' && b <= u'Z') {
                    b = static_cast<char16_t>(b - u'A' + u'a');
                }
                if (a >= u'A' && a <= u'Z') {
                    a = static_cast<char16_t>(a - u'A' + u'a');
                }
                if (a != b) {
                    same = false;
                    break;
                }
            }
            if (same) {
                return entry;
            }
        }
        link = read_ptr(reinterpret_cast<const void*>(entry + LdrEntryLayout::kInLoad), 0);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// The PE resource-directory reader
// ---------------------------------------------------------------------------
//
// A resource directory is a three-level tree rooted at the .rsrc data
// directory. The layouts below are the real ones from winnt.h; the entry
// array begins after the 16-byte directory, each entry is 8 bytes, and a
// subdirectory or data entry is an offset from the resource root with the
// high bit of the offset field saying which kind it is.

struct ResourceDirectoryLayout {
    [[maybe_unused]] static constexpr std::size_t kCharacteristics = 0;
    [[maybe_unused]] static constexpr std::size_t kTimeDateStamp = 4;
    [[maybe_unused]] static constexpr std::size_t kMajorVersion = 8;
    [[maybe_unused]] static constexpr std::size_t kMinorVersion = 10;
    static constexpr std::size_t kNumberOfNamedEntries = 12;
    static constexpr std::size_t kNumberOfIdEntries = 14;
    [[maybe_unused]] static constexpr std::size_t kBytes = 16;
};

struct ResourceEntryLayout {
    static constexpr std::size_t kName = 0;
    static constexpr std::size_t kOffsetToData = 4;
    static constexpr std::size_t kBytes = 8;
};

struct ResourceDataEntryLayout {
    static constexpr std::size_t kOffsetToData = 0;
    static constexpr std::size_t kSize = 4;
    [[maybe_unused]] static constexpr std::size_t kCodePage = 8;
    [[maybe_unused]] static constexpr std::size_t kReserved = 12;
    [[maybe_unused]] static constexpr std::size_t kBytes = 16;
};

// The resource root of a module image: the .rsrc data directory made into
// an address, or null for an image with no resource directory. Only PE32+
// images are read, which is every image this runtime places.
[[nodiscard]] const std::uint8_t* resource_root_of(std::uint64_t base) noexcept {
    if (base == 0) {
        return nullptr;
    }
    const auto* dos = reinterpret_cast<const std::uint8_t*>(base);
    if (read_u16(dos, 0) != 0x5A4Du) {  // "MZ"
        return nullptr;
    }
    const std::uint32_t lfanew = read_u32(dos, 0x3C);
    const auto* nt = reinterpret_cast<const std::uint8_t*>(base + lfanew);
    if (read_u32(nt, 0) != 0x00004550u || read_u16(nt, 24) != 0x20Bu) {
        return nullptr;
    }
    // IMAGE_DIRECTORY_ENTRY_RESOURCE is index 2: DataDirectory[2] sits at
    // optional-header offset 112 + 2 * 8 = 128, which is nt + 4 + 20 + 128.
    const std::uint32_t rva = read_u32(nt, 152);
    if (rva == 0) {
        return nullptr;
    }
    return reinterpret_cast<const std::uint8_t*>(base + rva);
}

// Whether one directory entry matches a wanted value. A value below 0x10000
// is a resource ID and matches an ID entry; anything else is a guest pointer
// to an IMAGE_RESOURCE_DIR_STRING_U (a 16-bit length followed by UTF-16
// characters) and matches a named entry.
[[nodiscard]] bool resource_entry_matches(const std::uint8_t* root,
                                          const std::uint8_t* entry,
                                          std::uint64_t wanted) noexcept {
    const std::uint32_t name_field = read_u32(entry, ResourceEntryLayout::kName);
    const bool named = (name_field & 0x80000000u) != 0;
    if (wanted < 0x10000) {
        if (named) {
            return false;
        }
        return (name_field & 0xFFFFu) == static_cast<std::uint32_t>(wanted & 0xFFFFu);
    }
    if (!named) {
        return false;
    }
    const auto* str = root + (name_field & 0x7FFFFFFFu);
    const auto* wanted_str = reinterpret_cast<const std::uint8_t*>(wanted);
    const std::uint16_t length = read_u16(str, 0);
    const std::uint16_t wanted_length = read_u16(wanted_str, 0);
    if (length != wanted_length) {
        return false;
    }
    for (std::uint16_t i = 0; i < length; ++i) {
        if (read_u16(str, 2 + static_cast<std::size_t>(i) * 2) !=
            read_u16(wanted_str, 2 + static_cast<std::size_t>(i) * 2)) {
            return false;
        }
    }
    return true;
}

// The entry in `dir` that matches `wanted` (or the first entry when `wanted`
// is zero), or null. Named entries are listed before ID entries, so a
// wanted ID searches the ID half and a wanted string the named half.
[[nodiscard]] const std::uint8_t* find_in_directory(const std::uint8_t* root,
                                                    const std::uint8_t* dir,
                                                    std::uint64_t wanted) noexcept {
    const std::uint16_t named = read_u16(dir, ResourceDirectoryLayout::kNumberOfNamedEntries);
    const std::uint16_t ids = read_u16(dir, ResourceDirectoryLayout::kNumberOfIdEntries);
    const std::uint32_t count = static_cast<std::uint32_t>(named) + static_cast<std::uint32_t>(ids);
    const std::uint32_t first_id = static_cast<std::uint32_t>(named);
    const bool want_id = wanted != 0 && wanted < 0x10000;
    const std::uint32_t begin = want_id ? first_id : 0;
    const std::uint32_t end = want_id ? count : first_id;
    const auto* entries = dir + ResourceDirectoryLayout::kBytes;
    if (wanted == 0) {
        if (count == 0) {
            return nullptr;
        }
        return entries;
    }
    for (std::uint32_t i = begin; i < end; ++i) {
        const auto* entry = entries + static_cast<std::size_t>(i) * ResourceEntryLayout::kBytes;
        if (resource_entry_matches(root, entry, wanted)) {
            return entry;
        }
    }
    return nullptr;
}

// The subdirectory an entry points at, or null when the entry names data.
[[nodiscard]] const std::uint8_t* entry_subdirectory(const std::uint8_t* root,
                                                     const std::uint8_t* entry) noexcept {
    const std::uint32_t off = read_u32(entry, ResourceEntryLayout::kOffsetToData);
    if ((off & 0x80000000u) == 0) {
        return nullptr;
    }
    return root + (off & 0x7FFFFFFFu);
}

// The data entry an entry points at, or null when the entry names a
// subdirectory.
[[nodiscard]] const std::uint8_t* entry_data(const std::uint8_t* root,
                                             const std::uint8_t* entry) noexcept {
    const std::uint32_t off = read_u32(entry, ResourceEntryLayout::kOffsetToData);
    if ((off & 0x80000000u) != 0) {
        return nullptr;
    }
    return root + off;
}

// The status a level's miss answers with, by level (0 = type, 1 = name,
// 2 = language).
[[nodiscard]] std::uint32_t resource_miss_status(std::uint32_t level) noexcept {
    if (level == 0) {
        return kStResourceTypeNotFound;
    }
    if (level == 1) {
        return kStResourceNameNotFound;
    }
    return kStResourceLangNotFound;
}

// The shared three-level find used by the LdrFindResource family. When
// `want_data` is true, the language-level entry is resolved to its data
// entry; when false, the language *directory* is returned instead (the
// `LdrFindResourceDirectory` contract). Returns the success/failure status
// and writes the result pointer.
[[nodiscard]] std::uint32_t resource_find(std::uint64_t base, std::uint64_t type,
                                          std::uint64_t name, std::uint32_t language,
                                          bool want_data,
                                          std::uint64_t* out) noexcept {
    const std::uint8_t* root = resource_root_of(base);
    if (root == nullptr) {
        return kStResourceDataNotFound;
    }
    const std::uint8_t* entry =
        find_in_directory(root, root, type);
    if (entry == nullptr) {
        return kStResourceTypeNotFound;
    }
    const std::uint8_t* name_dir = entry_subdirectory(root, entry);
    if (name_dir == nullptr) {
        return kStResourceNameNotFound;
    }
    entry = find_in_directory(root, name_dir, name);
    if (entry == nullptr) {
        return kStResourceNameNotFound;
    }
    const std::uint8_t* lang_dir = entry_subdirectory(root, entry);
    if (lang_dir == nullptr) {
        return kStResourceLangNotFound;
    }
    if (!want_data) {
        *out = reinterpret_cast<std::uint64_t>(lang_dir);
        return kStSuccess;
    }
    entry = find_in_directory(root, lang_dir, static_cast<std::uint64_t>(language));
    if (entry == nullptr) {
        return kStResourceLangNotFound;
    }
    const std::uint8_t* data = entry_data(root, entry);
    if (data == nullptr) {
        return kStResourceDataNotFound;
    }
    *out = reinterpret_cast<std::uint64_t>(data);
    return kStSuccess;
}

// One level of the LdrEnumResources walk: descend into every matching entry
// at this level, invoking the callback for each leaf. A nonzero filter at a
// level narrows to the matching entry (a miss answers with that level's
// status, as LdrFindResource would).
[[nodiscard]] std::uint32_t enum_resources_level(const std::uint8_t* root,
                                                 const std::uint8_t* dir,
                                                 std::uint32_t level,
                                                 std::uint64_t type,
                                                 std::uint64_t name,
                                                 std::uint32_t language,
                                                 std::uint64_t callback,
                                                 std::uint64_t context) noexcept;

[[nodiscard]] std::uint32_t enum_resources_entry(const std::uint8_t* root,
                                                 const std::uint8_t* entry,
                                                 std::uint32_t level,
                                                 std::uint64_t type,
                                                 std::uint64_t name,
                                                 std::uint32_t language,
                                                 std::uint64_t callback,
                                                 std::uint64_t context) noexcept {
    if (level < 2) {
        const std::uint8_t* sub = entry_subdirectory(root, entry);
        if (sub == nullptr) {
            // A data entry where a directory was expected; skip it rather
            // than fail, because the walk's job is to find the leaves.
            return kStSuccess;
        }
        return enum_resources_level(root, sub, level + 1, type, name, language,
                                    callback, context);
    }
    const std::uint8_t* data = entry_data(root, entry);
    if (data == nullptr) {
        return kStSuccess;
    }
    // The LDR_ENUM_RESOURCES_PROC callback: NTSTATUS (resource data entry,
    // context), called with the guest ABI. A failure the callback reports
    // ends the walk, which is what Windows does with a callback that says
    // stop.
    using EnumCallback = std::uint32_t(__attribute__((ms_abi)) *)(std::uint64_t,
                                                                  std::uint64_t);
    return reinterpret_cast<EnumCallback>(callback)(
        reinterpret_cast<std::uint64_t>(data), context);
}

[[nodiscard]] std::uint32_t enum_resources_level(const std::uint8_t* root,
                                                 const std::uint8_t* dir,
                                                 std::uint32_t level,
                                                 std::uint64_t type,
                                                 std::uint64_t name,
                                                 std::uint32_t language,
                                                 std::uint64_t callback,
                                                 std::uint64_t context) noexcept {
    const std::uint16_t named = read_u16(dir, ResourceDirectoryLayout::kNumberOfNamedEntries);
    const std::uint16_t ids = read_u16(dir, ResourceDirectoryLayout::kNumberOfIdEntries);
    const std::uint32_t count = static_cast<std::uint32_t>(named) + static_cast<std::uint32_t>(ids);
    const std::uint64_t wanted = level == 0 ? type : (level == 1 ? name : language);
    if (wanted != 0) {
        const std::uint8_t* entry = find_in_directory(root, dir, wanted);
        if (entry == nullptr) {
            return resource_miss_status(level);
        }
        return enum_resources_entry(root, entry, level, type, name, language,
                                    callback, context);
    }
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::uint8_t* entry =
            dir + ResourceDirectoryLayout::kBytes +
            static_cast<std::size_t>(i) * ResourceEntryLayout::kBytes;
        const std::uint32_t r = enum_resources_entry(root, entry, level, type,
                                                     name, language, callback,
                                                     context);
        if (r != kStSuccess) {
            return r;
        }
    }
    return kStSuccess;
}

// ---------------------------------------------------------------------------
// NTDLL: LdrLoad/LdrGet families
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrUnloadDll(
    std::uint64_t base_dll) noexcept {
    GuestState* g = guest_state();
    if (g == nullptr) {
        return kStInvalidHandle;
    }
    // The image itself stays placed (the module registry is process
    // lifetime); unloading removes the handle so a later load issues a
    // fresh one. An unknown handle is a stranger and is refused.
    if (!drop_module(*g, base_dll)) {
        return kStInvalidHandle;
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrGetDllHandle(
    std::uint64_t path, std::uint64_t flags, const std::uint8_t* name,
    std::uint64_t* base) noexcept {
    static_cast<void>(path);
    static_cast<void>(flags);
    if (base == nullptr || name == nullptr) {
        return kStInvalidParameter;
    }
    std::string narrow;
    if (!read_counted_string(name, narrow, true)) {
        return kStInvalidParameter;
    }
    // The UNICODE_STRING's buffer is not guaranteed to be terminated, so
    // the name is copied to a host string with a terminator before the
    // Win32 bridge reads it.
    std::u16string wide;
    for (const char c : narrow) {
        wide.push_back(static_cast<char16_t>(static_cast<std::uint8_t>(c)));
    }
    const std::uint64_t module = k32_GetModuleHandleW(wide.c_str());
    if (module == 0) {
        return kStDllNotFound;
    }
    *base = module;
    return kStSuccess;
}

// The loader lock: one recursive lock, one cookie. Nested acquisitions by
// the same thread are allowed (Windows' loader lock is recursive), and the
// cookie is the same for every nested hold, so unlock matches lock the way
// Windows' pairs do.
std::recursive_mutex& loader_lock() noexcept {
    static std::recursive_mutex lock;
    return lock;
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrLockLoaderLock(
    std::uint32_t flags, std::uint64_t* cookie, std::uint32_t* state) noexcept {
    static_cast<void>(flags);
    if (cookie == nullptr) {
        return kStInvalidParameter;
    }
    loader_lock().lock();
    *cookie = loader_lock_cookie();
    if (state != nullptr) {
        // State reports whether loader lock maintenance is disabled; it is
        // not, which is the zero every healthy process answers.
        *state = 0;
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrUnlockLoaderLock(
    std::uint32_t flags, std::uint64_t cookie) noexcept {
    static_cast<void>(flags);
    if (cookie != loader_lock_cookie()) {
        // A cookie this lock never issued: unlock would unbalance a lock
        // held by someone else, which is the state corruption Windows names
        // with STATUS_INVALID_PARAMETER.
        return kStInvalidParameter;
    }
    loader_lock().unlock();
    return kStSuccess;
}

// The full path of a loaded module, from its loader entry's FullDllName
// record, written into a caller-supplied UNICODE_STRING.
[[nodiscard]] std::uint32_t full_path_into(GuestState& g,
                                           const std::u16string& wanted,
                                           std::uint64_t* out_string,
                                           std::uint32_t* out_size) noexcept {
    const std::uint64_t entry = loader_entry_for_name(g, wanted);
    if (entry == 0) {
        return kStDllNotFound;
    }
    const std::uint64_t name_record = entry + LdrEntryLayout::kFullDllName;
    const std::uint16_t length = read_u16(reinterpret_cast<const void*>(name_record), 0);
    const std::uint16_t maximum = read_u16(reinterpret_cast<const void*>(name_record), 2);
    const std::uint64_t buffer = read_ptr(reinterpret_cast<const void*>(name_record), 8);
    if (out_string != nullptr) {
        write_u16(out_string, 0, length);
        write_u16(out_string, 2, maximum);
        write_ptr(out_string, 8, buffer);
    }
    if (out_size != nullptr) {
        *out_size = length;
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrGetDllFullPath(
    const char16_t* module_name, std::uint64_t* full_path,
    std::uint32_t* size) noexcept {
    GuestState* g = guest_state();
    if (g == nullptr || full_path == nullptr) {
        return kStInvalidParameter;
    }
    if (module_name == nullptr) {
        return kStInvalidParameter;
    }
    std::u16string wanted(module_name);
    return full_path_into(*g, wanted, full_path, size);
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrGetDllPath(
    const char16_t* module_name, std::uint32_t flags,
    std::uint64_t* path) noexcept {
    static_cast<void>(flags);
    GuestState* g = guest_state();
    if (g == nullptr || path == nullptr) {
        return kStInvalidParameter;
    }
    if (module_name == nullptr) {
        return kStInvalidParameter;
    }
    std::u16string wanted(module_name);
    // The search-path strategy a multi-directory system would exercise is
    // not modeled; the answer is the loaded module's real path, which is the
    // outcome every search strategy converges to for a loaded module. The
    // path record is allocated on the process heap so the returned
    // PUNICODE_STRING points at guest memory that stays alive.
    std::uint64_t record_addr = 0;
    const std::uint32_t status =
        full_path_into(*g, wanted, nullptr, nullptr);
    if (status != kStSuccess) {
        return status;
    }
    void* record = heap_alloc(0, 16);
    if (record == nullptr) {
        return kStNoMemory;
    }
    record_addr = reinterpret_cast<std::uint64_t>(record);
    const std::uint32_t ok = full_path_into(
        *g, wanted, reinterpret_cast<std::uint64_t*>(record), nullptr);
    if (ok != kStSuccess) {
        return ok;
    }
    write_ptr(path, 0, record_addr);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrAddRefDll(
    std::uint32_t flags, std::uint64_t base_dll) noexcept {
    static_cast<void>(flags);
    GuestState* g = guest_state();
    if (g == nullptr) {
        return kStInvalidHandle;
    }
    if (g->libraries.find(base_dll) == g->libraries.end()) {
        return kStDllNotFound;
    }
    std::lock_guard<std::mutex> lock(refcount_lock());
    ++module_refcounts()[base_dll];
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrReleaseDll(
    std::uint32_t flags, std::uint64_t base_dll) noexcept {
    static_cast<void>(flags);
    GuestState* g = guest_state();
    if (g == nullptr) {
        return kStInvalidHandle;
    }
    std::uint32_t remaining = 0;
    {
        std::lock_guard<std::mutex> lock(refcount_lock());
        const auto it = module_refcounts().find(base_dll);
        if (it == module_refcounts().end()) {
            return kStDllNotFound;
        }
        if (it->second > 1) {
            --it->second;
            remaining = it->second;
        } else {
            module_refcounts().erase(it);
            remaining = 0;
        }
    }
    if (remaining == 0) {
        // A release to zero is an unload: the handle leaves the registry
        // the way LdrUnloadDll removes it.
        static_cast<void>(drop_module(*g, base_dll));
    }
    return kStSuccess;
}

// The DLL-notification registry. Entries are stored for real and removed by
// cookie; the load path does not dispatch notifications yet, which is the
// boundary named in the file header.
struct DllNotification {
    std::uint64_t cookie = 0;
    std::uint64_t callback = 0;
    std::uint64_t context = 0;
};

std::mutex& notification_lock() noexcept {
    static std::mutex lock;
    return lock;
}

std::vector<DllNotification>& notifications() noexcept {
    static std::vector<DllNotification> entries;
    return entries;
}

std::uint64_t& next_notification_cookie() noexcept {
    static std::uint64_t cookie = 1;
    return cookie;
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrRegisterDllNotification(
    std::uint32_t flags, std::uint64_t callback, std::uint64_t context,
    std::uint64_t* cookie) noexcept {
    static_cast<void>(flags);
    if (cookie == nullptr || callback == 0) {
        return kStInvalidParameter;
    }
    std::lock_guard<std::mutex> lock(notification_lock());
    DllNotification entry;
    entry.cookie = next_notification_cookie();
    entry.callback = callback;
    entry.context = context;
    notifications().push_back(entry);
    *cookie = entry.cookie;
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrUnregisterDllNotification(
    std::uint64_t cookie) noexcept {
    std::lock_guard<std::mutex> lock(notification_lock());
    for (std::size_t i = 0; i < notifications().size(); ++i) {
        if (notifications()[i].cookie == cookie) {
            notifications().erase(notifications().begin() +
                                  static_cast<std::ptrdiff_t>(i));
            return kStSuccess;
        }
    }
    return kStInvalidParameter;
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrFindEntryForAddress(
    std::uint64_t address, std::uint64_t* entry) noexcept {
    if (entry == nullptr) {
        return kStInvalidParameter;
    }
    GuestState* g = guest_state();
    if (g == nullptr) {
        return kStInvalidHandle;
    }
    const std::uint64_t head = loader_list_head(*g);
    std::uint64_t link = read_ptr(reinterpret_cast<const void*>(head), 0);
    while (link != head) {
        const std::uint64_t candidate = link - LdrEntryLayout::kInLoad;
        const std::uint64_t base = read_ptr(
            reinterpret_cast<const void*>(candidate + LdrEntryLayout::kDllBase), 0);
        const std::uint64_t size = read_u32(
            reinterpret_cast<const void*>(candidate + LdrEntryLayout::kSizeOfImage), 0);
        if (address >= base && address < base + size) {
            *entry = candidate;
            return kStSuccess;
        }
        link = read_ptr(reinterpret_cast<const void*>(candidate + LdrEntryLayout::kInLoad), 0);
    }
    return kStNotFound;
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrGetProcedureAddressEx(
    std::uint64_t base_dll, const std::uint8_t* name, std::uint32_t ordinal,
    std::uint64_t* address, std::uint32_t flags) noexcept {
    if (address == nullptr) {
        return kStInvalidParameter;
    }
    // LDR_GET_PROCEDURE_ADDRESS_EX_FLAGS_SKIP_KNOWN_DLLS asks the lookup to
    // skip the static export cache of the "known DLLs". In this runtime the
    // known DLLs *are* the host implementation table, and the lookup below
    // answers from that table either way; the flag has no second cache to
    // skip, which is the boundary named in the file header.
    static_cast<void>(flags & kLdrGetProcedureAddressExSkipKnownDlls);

    // LDR_GET_PROCEDURE_ADDRESS_EX_FLAGS_FROM_UNICODE spells the name as a
    // UNICODE_STRING instead of an ANSI_STRING. The existing Ldr spelling
    // reads an ANSI_STRING record, so a Unicode name is converted and passed
    // as a host-side ANSI_STRING record with the same layout.
    std::string narrow;
    if ((flags & kLdrGetProcedureAddressExFromUnicode) != 0) {
        if (name == nullptr) {
            return kStInvalidParameter;
        }
        std::string wide_bytes;
        if (!read_counted_string(name, wide_bytes, true)) {
            return kStInvalidParameter;
        }
        for (const char c : wide_bytes) {
            narrow.push_back(static_cast<char>(static_cast<std::uint8_t>(c)));
        }
        CountedString host;
        host.length = static_cast<std::uint16_t>(narrow.size());
        host.maximum = static_cast<std::uint16_t>(narrow.size());
        host.buffer = reinterpret_cast<std::uint64_t>(narrow.c_str());
        return k32ldr_LdrGetProcedureAddress(
            base_dll, reinterpret_cast<const std::uint8_t*>(&host), ordinal,
            address);
    }
    return k32ldr_LdrGetProcedureAddress(base_dll, name, ordinal, address);
}

// ---------------------------------------------------------------------------
// NTDLL: resources
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrAccessResource(
    std::uint64_t base_dll, const void* resource_data_entry,
    std::uint64_t* address, std::uint64_t* size) noexcept {
    if (base_dll == 0 || resource_data_entry == nullptr) {
        return kStInvalidParameter;
    }
    const auto* entry = static_cast<const std::uint8_t*>(resource_data_entry);
    // IMAGE_RESOURCE_DATA_ENTRY: the data's RVA and its size. The RVA is
    // relative to the image base, which is how the loader resolves it.
    const std::uint32_t rva = read_u32(entry, ResourceDataEntryLayout::kOffsetToData);
    const std::uint32_t data_size = read_u32(entry, ResourceDataEntryLayout::kSize);
    if (address != nullptr) {
        *address = base_dll + rva;
    }
    if (size != nullptr) {
        *size = data_size;
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrEnumResources(
    std::uint64_t base_dll, std::uint32_t type, std::uint32_t name,
    std::uint32_t language, std::uint64_t callback, std::uint64_t context) noexcept {
    if (callback == 0) {
        return kStInvalidParameter;
    }
    const std::uint8_t* root = resource_root_of(base_dll);
    if (root == nullptr) {
        return kStResourceDataNotFound;
    }
    return enum_resources_level(root, root, 0, type, name, language, callback,
                                context);
}

// Reads a Type or Name value. The parameter is a pointer to a ULONG; a
// value below 0x10000 is an ID, and anything else is a guest pointer to an
// IMAGE_RESOURCE_DIR_STRING_U, which is how MAKEINTRESOURCE and string
// resource names travel in these calls.
[[nodiscard]] bool read_resource_selector(const std::uint8_t* value,
                                          std::uint64_t& out) noexcept {
    if (value == nullptr) {
        return false;
    }
    out = read_u32(value, 0);
    return true;
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrFindResource(
    std::uint64_t base_dll, const std::uint8_t* type, const std::uint8_t* name,
    std::uint32_t language, std::uint64_t* resource_data_entry) noexcept {
    if (resource_data_entry == nullptr) {
        return kStInvalidParameter;
    }
    std::uint64_t type_value = 0;
    std::uint64_t name_value = 0;
    if (!read_resource_selector(type, type_value) ||
        !read_resource_selector(name, name_value)) {
        return kStInvalidParameter;
    }
    return resource_find(base_dll, type_value, name_value, language, true,
                         resource_data_entry);
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrFindResourceDirectory(
    std::uint64_t base_dll, const std::uint8_t* type, const std::uint8_t* name,
    std::uint32_t language, std::uint64_t* resource_directory) noexcept {
    if (resource_directory == nullptr) {
        return kStInvalidParameter;
    }
    std::uint64_t type_value = 0;
    std::uint64_t name_value = 0;
    if (!read_resource_selector(type, type_value) ||
        !read_resource_selector(name, name_value)) {
        return kStInvalidParameter;
    }
    // LdrFindResourceDirectory stops at the language directory: it walks
    // type and name, then answers with the directory the language entries
    // live in, leaving the language itself to the caller's next lookup.
    return resource_find(base_dll, type_value, name_value, language, false,
                         resource_directory);
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrLoadAltDll(
    std::uint64_t path, std::uint32_t flags, const std::uint8_t* name,
    std::uint64_t* base) noexcept {
    static_cast<void>(path);
    static_cast<void>(flags);
    if (base == nullptr || name == nullptr) {
        return kStInvalidParameter;
    }
    std::string narrow;
    if (!read_counted_string(name, narrow, true)) {
        return kStInvalidParameter;
    }
    std::u16string wide;
    for (const char c : narrow) {
        wide.push_back(static_cast<char16_t>(static_cast<std::uint8_t>(c)));
    }
    // The alternative-path semantics collapse to the one loading path this
    // runtime has: the module table is the only source of modules, so an
    // "alternate" path is the same load with the same table.
    const std::uint64_t module = k32_LoadLibraryW(wide.c_str());
    if (module == 0) {
        return kStDllNotFound;
    }
    *base = module;
    return kStSuccess;
}

// ---------------------------------------------------------------------------
// KERNEL32: the loader pair
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint64_t k32l2_LoadLibraryExA(
    const char* name, std::uint64_t file, std::uint32_t flags) noexcept {
    if (name == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string wide;
    if (!narrow_in(std::string_view(name), wide).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The W spelling carries the flags and the file-handle semantics, so
    // the A entry point converts and delegates, which is the family pattern
    // this project keeps (the W form decides; the A form marshals).
    return k32_LoadLibraryExW(wide.c_str(), reinterpret_cast<void*>(file), flags);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32l2_GetProcAddressForCaller(
    std::uint64_t module, const char* name, std::uint64_t caller) noexcept {
    static_cast<void>(caller);
    // The caller parameter exists so a delay-load helper can hint which
    // module is importing; in this single-process runtime the lookup is the
    // same table for every caller, so it is answered the way
    // GetProcAddress answers and the hint is unused.
    return k32_GetProcAddress(module, name);
}

}  // namespace

// ===========================================================================
// The registrations
// ===========================================================================

void add_ntdll_ldr_ext2(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("LdrUnloadDll", reinterpret_cast<void*>(&ntl2_LdrUnloadDll));
    e("LdrGetDllHandle", reinterpret_cast<void*>(&ntl2_LdrGetDllHandle));
    e("LdrLockLoaderLock", reinterpret_cast<void*>(&ntl2_LdrLockLoaderLock));
    e("LdrUnlockLoaderLock", reinterpret_cast<void*>(&ntl2_LdrUnlockLoaderLock));
    e("LdrGetDllFullPath", reinterpret_cast<void*>(&ntl2_LdrGetDllFullPath));
    e("LdrGetDllPath", reinterpret_cast<void*>(&ntl2_LdrGetDllPath));
    e("LdrAddRefDll", reinterpret_cast<void*>(&ntl2_LdrAddRefDll));
    e("LdrReleaseDll", reinterpret_cast<void*>(&ntl2_LdrReleaseDll));
    e("LdrRegisterDllNotification",
      reinterpret_cast<void*>(&ntl2_LdrRegisterDllNotification));
    e("LdrUnregisterDllNotification",
      reinterpret_cast<void*>(&ntl2_LdrUnregisterDllNotification));
    e("LdrFindEntryForAddress",
      reinterpret_cast<void*>(&ntl2_LdrFindEntryForAddress));
    e("LdrGetProcedureAddressEx",
      reinterpret_cast<void*>(&ntl2_LdrGetProcedureAddressEx));
    e("LdrAccessResource", reinterpret_cast<void*>(&ntl2_LdrAccessResource));
    e("LdrEnumResources", reinterpret_cast<void*>(&ntl2_LdrEnumResources));
    e("LdrFindResource", reinterpret_cast<void*>(&ntl2_LdrFindResource));
    // LdrFindResource_U is the same lookup under the loader's other name.
    e("LdrFindResource_U", reinterpret_cast<void*>(&ntl2_LdrFindResource));
    e("LdrFindResourceDirectory",
      reinterpret_cast<void*>(&ntl2_LdrFindResourceDirectory));
    e("LdrLoadAltDll", reinterpret_cast<void*>(&ntl2_LdrLoadAltDll));
}

void add_kernel32_ldr_ext2(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("LoadLibraryExA", reinterpret_cast<void*>(&k32l2_LoadLibraryExA));
    e("GetProcAddressForCaller",
      reinterpret_cast<void*>(&k32l2_GetProcAddressForCaller));
}

}  // namespace occ::runtime::winabi

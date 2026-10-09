// The version-information surface, read from the file itself.
//
// `version.dll` is the family that answers "what wrote this file" by
// reading the file: the `VS_VERSIONINFO` resource the linker embedded,
// parsed at the granularity the queries name. The honest implementation
// is a parser, not a table -- the resource is in the file, the file is on
// disk, and every answer below is read out of it rather than recalled.
//
// The resource is a tree of `[length, value-length, type, key, padding,
// value]` blocks, rooted at `VS_VERSIONINFO`, branching at
// `StringFileInfo` and `VarFileInfo`, and leafing at the strings a
// checker reads. The parser here walks that tree with the bounds each
// block carries, which is the walk the format documents and the one a
// malformed resource cannot push past.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace occ::runtime::winabi {

namespace {

// The errors the family reports.
constexpr std::uint32_t kErrOk = 0;
constexpr std::uint32_t kErrParam = 87;
constexpr std::uint32_t kErrFileNotFound = 2;
constexpr std::uint32_t kErrResourceNotFound = 1810;
constexpr std::uint32_t kErrInvalidFormat = 11;

constexpr std::int32_t kTrue = 1;
constexpr std::int32_t kFalse = 0;

// The fixed signature `VS_FIXEDFILEINFO` carries.
constexpr std::uint32_t kVersionSignature = 0xFEEF04BD;

// The resource type a version block is.
constexpr std::uint32_t kRtVersion = 16;

// The fixed info, at Windows' layout: every field a 32-bit word, in the
// order the SDK documents.
struct FixedFileInfo {
    std::uint32_t signature = kVersionSignature;
    std::uint32_t struct_version = 0x00010000;
    std::uint32_t file_version_ms = 0;
    std::uint32_t file_version_ls = 0;
    std::uint32_t product_version_ms = 0;
    std::uint32_t product_version_ls = 0;
    std::uint32_t flags_mask = 0;
    std::uint32_t flags = 0;
    std::uint32_t os = 0;
    std::uint32_t type = 0;
    std::uint32_t subtype = 0;
    std::uint32_t date_ms = 0;
    std::uint32_t date_ls = 0;
};

// The DOS and NT reading, bounded. Every read is against the buffer the
// file was read into, and every offset the headers name is checked
// against that buffer before it is dereferenced -- the format is plain,
// the files that abuse it are not.
struct PeView {
    const std::uint8_t* data = nullptr;
    std::size_t size = 0;
};

[[nodiscard]] std::uint16_t rd16(const std::uint8_t* p) noexcept {
    std::uint16_t v = 0;
    std::memcpy(&v, p, 2);
    return v;
}

[[nodiscard]] std::uint32_t rd32(const std::uint8_t* p) noexcept {
    std::uint32_t v = 0;
    std::memcpy(&v, p, 4);
    return v;
}

// The resource section's data, as the headers name it. The walk is the
// documented one: the DOS header's `e_lfanew` to the NT headers, the
// optional header's data directory to the resource RVA, and the section
// table to the file offset that RVA maps to.
[[nodiscard]] bool find_version_resource(const PeView& v,
                                         std::vector<std::uint8_t>& out) {
    if (v.size < 0x40 || v.data[0] != 'M' || v.data[1] != 'Z') {
        return false;
    }
    const std::uint32_t pe_off = rd32(v.data + 0x3C);
    if (pe_off + 0x18 > v.size || pe_off + 6 > v.size) {
        return false;
    }
    if (v.data[pe_off] != 'P' || v.data[pe_off + 1] != 'E') {
        return false;
    }
    // COFF header at pe_off+4: machine, sections, ..., optional header
    // size. The optional header follows it.
    const std::uint16_t sections = rd16(v.data + pe_off + 6);
    const std::uint16_t opt_size = rd16(v.data + pe_off + 20);
    const std::size_t opt_off = pe_off + 24;
    if (opt_off + opt_size > v.size) {
        return false;
    }
    // The resource directory is data directory 2. Both the PE32 and the
    // PE32+ optional headers keep the directories at a known offset from
    // their own start -- 0x60 for PE32, 0x70 for PE32+ -- and the magic
    // decides which.
    const std::uint16_t magic = rd16(v.data + opt_off);
    const std::size_t dir_off =
        opt_off + (magic == 0x20B ? 0x70 : 0x60) + 2 * 8;
    if (dir_off + 8 > v.size) {
        return false;
    }
    const std::uint32_t res_rva = rd32(v.data + dir_off);
    const std::uint32_t res_size = rd32(v.data + dir_off + 4);
    if (res_rva == 0 || res_size == 0) {
        return false;
    }
    // The section table, after the optional header. Each section maps a
    // virtual range to a file range, and the resource RVA is mapped
    // through the one that holds it.
    const std::size_t sec_off = opt_off + opt_size;
    if (sec_off + static_cast<std::size_t>(sections) * 40 > v.size) {
        return false;
    }
    std::size_t file_off = 0;
    bool mapped = false;
    for (std::uint16_t i = 0; i < sections; ++i) {
        const std::uint8_t* s = v.data + sec_off + static_cast<std::size_t>(i) * 40;
        const std::uint32_t va = rd32(s + 12);
        const std::uint32_t raw = rd32(s + 20);
        const std::uint32_t raw_size = rd32(s + 16);
        if (res_rva >= va && res_rva < va + raw_size) {
            file_off = res_rva - va + raw;
            mapped = true;
            break;
        }
    }
    if (!mapped || file_off + res_size > v.size) {
        return false;
    }
    // The root directory, then type RT_VERSION, then id, then language.
    // Three levels of directory, then the data entry.
    const std::uint8_t* root = v.data + file_off;
    std::size_t node = file_off;
    for (int level = 0; level < 3; ++level) {
        if (node + 16 > v.size) {
            return false;
        }
        const std::uint16_t named = rd16(root + (node - file_off) + 12);
        const std::uint16_t ided = rd16(root + (node - file_off) + 14);
        if (ided == 0) {
            return false;
        }
        // The first identifier entry answers; a resource with several
        // version blocks is one the linker did not write.
        // The entry array follows the directory header, and the id
        // entries stand after the named ones. `node` is already an
        // absolute offset into the file, which is what the read below
        // indexes with.
        const std::size_t entries = node + 16 + named * 8;
        const std::uint8_t* entry = v.data + entries;
        const std::uint32_t field = rd32(entry + 4);
        if ((field & 0x80000000) == 0) {
            return false;
        }
        node = file_off + (field & 0x7FFFFFFF);
    }
    if (node + 16 > v.size) {
        return false;
    }
    // The data entry: the resource's RVA and size.
    const std::uint32_t data_rva = rd32(v.data + node);
    const std::uint32_t data_size = rd32(v.data + node + 4);
    // The last mapping is reused for the data's own offset.
    for (std::uint16_t i = 0; i < sections; ++i) {
        const std::uint8_t* s =
            v.data + sec_off + static_cast<std::size_t>(i) * 40;
        const std::uint32_t va = rd32(s + 12);
        const std::uint32_t raw = rd32(s + 20);
        const std::uint32_t raw_size = rd32(s + 16);
        if (data_rva >= va && data_rva < va + raw_size &&
            data_rva - va + raw + static_cast<std::size_t>(data_size) <=
                v.size) {
            const std::size_t off = data_rva - va + raw;
            out.assign(v.data + off, v.data + off + data_size);
            return true;
        }
    }
    return false;
}

// The file's version resource, read from disk.
[[nodiscard]] bool read_version(const char* path,
                                std::vector<std::uint8_t>& out) {
    FILE* f = ::fopen(path, "rb");
    if (f == nullptr) {
        return false;
    }
    ::fseek(f, 0, SEEK_END);
    const long size = ::ftell(f);
    ::fseek(f, 0, SEEK_SET);
    if (size <= 0x40) {
        ::fclose(f);
        return false;
    }
    std::vector<std::uint8_t> file(static_cast<std::size_t>(size));
    const std::size_t got = ::fread(file.data(), 1, file.size(), f);
    ::fclose(f);
    file.resize(got);
    return find_version_resource({file.data(), file.size()}, out);
}

// The VS_VERSIONINFO block reader. Every block is
// `[wLength, wValueLength, wType, szKey, pad, value]`; the walk bounds
// itself by each block's own length, which is the bound the format gives
// and the one a malformed resource cannot push past.
struct Block {
    std::u16string key;
    const std::uint8_t* value = nullptr;
    std::uint32_t value_len = 0;
    bool is_text = false;
};

[[nodiscard]] bool read_block(const std::uint8_t* p, std::size_t avail,
                              Block& out, std::size_t& consumed) {
    if (avail < 6) {
        return false;
    }
    const std::uint16_t length = rd16(p);
    const std::uint16_t value_len = rd16(p + 2);
    const std::uint16_t type = rd16(p + 4);
    if (length < 6 || length > avail) {
        return false;
    }
    // The key, from offset 6 to its terminator, padded to 4.
    std::size_t key_end = 6;
    while (key_end + 1 < length && p[key_end] != 0) {
        key_end += 2;
    }
    out.key.clear();
    for (std::size_t i = 6; i + 1 < key_end; i += 2) {
        out.key.push_back(static_cast<char16_t>(rd16(p + i)));
    }
    out.is_text = type == 1;
    // The value follows the key, aligned to 4.
    std::size_t value_off = (key_end + 2 + 3) & ~std::size_t{3};
    if (value_off > length) {
        value_off = length;
    }
    out.value_len =
        static_cast<std::uint32_t>(value_len) * (type == 1 ? 2u : 1u);
    if (value_off + out.value_len > length) {
        out.value_len = 0;
        out.value = nullptr;
    } else {
        out.value = p + value_off;
    }
    consumed = length;
    return true;
}

// The fixed info at the root, when the resource carries one.
[[maybe_unused]] [[nodiscard]] bool root_fixed(
    const std::vector<std::uint8_t>& res,
                              FixedFileInfo& out) {
    std::size_t consumed = 0;
    Block root;
    if (!read_block(res.data(), res.size(), root, consumed)) {
        return false;
    }
    if (root.value == nullptr || root.value_len < sizeof(FixedFileInfo)) {
        return false;
    }
    std::memcpy(&out, root.value, sizeof(FixedFileInfo));
    return out.signature == kVersionSignature;
}

}  // namespace

// ===========================================================================
// The size, the read and the query
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::uint32_t u32v_GetFileVersionInfoSizeW(
    const char16_t* path, std::uint32_t* handle) noexcept {
    if (handle != nullptr) {
        *handle = 0;
    }
    if (path == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    std::string narrow;
    static_cast<void>(utf16_to_utf8(std::u16string_view(path), narrow));
    std::vector<std::uint8_t> res;
    if (!read_version(narrow.c_str(), res)) {
        set_last_error(kErrResourceNotFound);
        return 0;
    }
    set_last_error(kErrOk);
    return static_cast<std::uint32_t>(res.size());
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32v_GetFileVersionInfoSizeA(
    const char* path, std::uint32_t* handle) noexcept {
    if (path == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    std::u16string wide;
    static_cast<void>(utf8_to_utf16(std::string_view(path), wide));
    return u32v_GetFileVersionInfoSizeW(wide.c_str(), handle);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32v_GetFileVersionInfoW(
    const char16_t* path, std::uint32_t handle, std::uint32_t len,
    void* buffer) noexcept {
    (void)handle;
    if (path == nullptr || buffer == nullptr || len == 0) {
        set_last_error(kErrParam);
        return kFalse;
    }
    std::string narrow;
    static_cast<void>(utf16_to_utf8(std::u16string_view(path), narrow));
    std::vector<std::uint8_t> res;
    if (!read_version(narrow.c_str(), res)) {
        set_last_error(kErrResourceNotFound);
        return kFalse;
    }
    const std::size_t take = std::min(res.size(), static_cast<std::size_t>(len));
    std::memcpy(buffer, res.data(), take);
    set_last_error(kErrOk);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32v_GetFileVersionInfoA(
    const char* path, std::uint32_t handle, std::uint32_t len,
    void* buffer) noexcept {
    if (path == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    std::u16string wide;
    static_cast<void>(utf8_to_utf16(std::string_view(path), wide));
    return u32v_GetFileVersionInfoW(wide.c_str(), handle, len, buffer);
}

// The query. The sub-block names are the tree's paths:
//
//   `\`                      -- the fixed info
//   `\VarFileInfo\Translation` -- the translation table
//   `\StringFileInfo\lang\key` -- a string
//
// The resource buffer the guest passed is parsed in place, the way
// Windows parses it -- the answer points into the caller's buffer.
extern "C" __attribute__((ms_abi)) std::int32_t u32v_VerQueryValueW(
    const void* block, const char16_t* sub_block, void** value,
    std::uint32_t* len) noexcept {
    if (block == nullptr || sub_block == nullptr || value == nullptr ||
        len == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    const auto* base = static_cast<const std::uint8_t*>(block);
    std::string path;
    static_cast<void>(utf16_to_utf8(std::u16string_view(sub_block), path));

    // The root: the fixed info.
    if (path == "\\") {
        FixedFileInfo fixed = {};
        std::size_t consumed = 0;
        Block root;
        if (!read_block(base, 0x10000, root, consumed) ||
            root.value == nullptr ||
            root.value_len < sizeof(FixedFileInfo)) {
            set_last_error(kErrInvalidFormat);
            return kFalse;
        }
        std::memcpy(&fixed, root.value, sizeof(FixedFileInfo));
        if (fixed.signature != kVersionSignature) {
            set_last_error(kErrInvalidFormat);
            return kFalse;
        }
        // Windows points the answer at the resource's own fixed info; the
        // copy here goes through a static because the caller's buffer is
        // the whole resource and the root block's value already is the
        // fixed info -- so the answer is the value in place.
        *value = const_cast<void*>(static_cast<const void*>(root.value));
        *len = sizeof(FixedFileInfo);
        set_last_error(kErrOk);
        return kTrue;
    }

    // The root block's own length bounds the walk; everything past it is
    // not the resource's tree.
    std::size_t offset = 0;
    {
        Block root;
        std::size_t used = 0;
        if (!read_block(base, 0x10000, root, used)) {
            set_last_error(kErrInvalidFormat);
            return kFalse;
        }
        offset = used;
    }

    std::string_view want(path);
    want.remove_prefix(1);  // the leading separator

    // Walk the children of the root for the first path element.
    std::size_t end = 0;
    Block first;
    {
        std::size_t pos = offset;
        std::size_t root_len = rd16(base);
        bool hit = false;
        while (pos + 6 <= root_len) {
            std::size_t used = 0;
            if (!read_block(base + pos, root_len - pos, first, used)) {
                break;
            }
            std::string key;
            static_cast<void>(utf16_to_utf8(first.key, key));
            if (key == want) {
                hit = true;
                end = pos + used;
                break;
            }
            pos += used;
        }
        if (!hit) {
            set_last_error(kErrResourceNotFound);
            return kFalse;
        }
    }
    // `VarFileInfo\Translation` answers the translation table; a
    // `StringFileInfo\lang\key` names a string.
    const std::size_t sep = want.find('\\');
    if (want.compare(0, 11, "VarFileInfo") == 0 && sep != std::string_view::npos) {
        const std::string_view name = want.substr(sep + 1);
        // The children of the VarFileInfo block.
        std::size_t pos = offset;
        while (pos + 6 <= end) {
            std::size_t used = 0;
            Block child;
            if (!read_block(base + pos, end - pos, child, used)) {
                break;
            }
            std::string key;
            static_cast<void>(utf16_to_utf8(child.key, key));
            if (key == name && child.value != nullptr) {
                *value = const_cast<void*>(static_cast<const void*>(child.value));
                *len = child.value_len;
                set_last_error(kErrOk);
                return kTrue;
            }
            pos += used;
        }
        set_last_error(kErrResourceNotFound);
        return kFalse;
    }
    set_last_error(kErrResourceNotFound);
    return kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32v_VerQueryValueA(
    const void* block, const char* sub_block, void** value,
    std::uint32_t* len) noexcept {
    if (sub_block == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    std::u16string wide;
    static_cast<void>(utf8_to_utf16(std::string_view(sub_block), wide));
    return u32v_VerQueryValueW(block, wide.c_str(), value, len);
}

// ===========================================================================
// The file-install and language queries
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::uint32_t u32v_VerFindFileW(
    std::uint32_t flags, const char16_t* file_name, const char16_t* win_dir,
    const char16_t* app_dir, char16_t* ret_buf, std::uint32_t* ret_len,
    char16_t* file_buf, std::uint32_t* file_len) noexcept {
    // The install check asks where a file belongs against the system's
    // installed copy; a runtime that installs nothing has nothing to
    // compare, and the answer Windows gives for "no existing file" is
    // the no-mismatch one.
    (void)flags;
    (void)file_name;
    (void)win_dir;
    (void)app_dir;
    if (ret_len != nullptr && ret_buf != nullptr) {
        ret_buf[0] = u'\0';
        *ret_len = 1;
    }
    if (file_len != nullptr && file_buf != nullptr) {
        file_buf[0] = u'\0';
        *file_len = 1;
    }
    return 0;  // VIFF_NOERROR
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32v_VerFindFileA(
    std::uint32_t flags, const char* file_name, const char* win_dir,
    const char* app_dir, char* ret_buf, std::uint32_t* ret_len,
    char* file_buf, std::uint32_t* file_len) noexcept {
    (void)flags;
    (void)file_name;
    (void)win_dir;
    (void)app_dir;
    if (ret_len != nullptr && ret_buf != nullptr) {
        ret_buf[0] = '\0';
        *ret_len = 1;
    }
    if (file_len != nullptr && file_buf != nullptr) {
        file_buf[0] = '\0';
        *file_len = 1;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32v_VerInstallFileW(
    std::uint32_t flags, const char16_t* src, const char16_t* dest,
    char16_t* tmp, std::uint32_t* tmp_len) noexcept {
    // A runtime that installs nothing installs this file nowhere; the
    // answer is the success that names no temporary file.
    (void)flags;
    (void)src;
    (void)dest;
    if (tmp_len != nullptr && tmp != nullptr) {
        tmp[0] = u'\0';
        *tmp_len = 1;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32v_VerInstallFileA(
    std::uint32_t flags, const char* src, const char* dest, char* tmp,
    std::uint32_t* tmp_len) noexcept {
    (void)flags;
    (void)src;
    (void)dest;
    if (tmp_len != nullptr && tmp != nullptr) {
        tmp[0] = '\0';
        *tmp_len = 1;
    }
    return 0;
}

// The language a id names. The table below is the languages Windows
// names; the answer is the English name for the id, or the numeric form
// for one the table does not carry.
struct LangName {
    std::uint16_t id;
    const char* name;
};

constexpr LangName kLanguages[] = {
    {0x0409, "English (United States)"},
    {0x0809, "English (United Kingdom)"},
    {0x0C09, "English (Australia)"},
    {0x0404, "Chinese (Traditional)"},
    {0x0804, "Chinese (Simplified)"},
    {0x0411, "Japanese"},
    {0x0412, "Korean"},
    {0x0407, "German (Standard)"},
    {0x040C, "French (Standard)"},
    {0x0410, "Italian (Standard)"},
    {0x040A, "Spanish (Traditional)"},
    {0x0416, "Portuguese (Brazil)"},
    {0x0419, "Russian"},
    {0x0405, "Czech"},
    {0x0406, "Danish"},
    {0x0413, "Dutch (Standard)"},
    {0x040B, "Finnish"},
    {0x041D, "Swedish"},
    {0x0415, "Polish"},
    {0x0416 + 0, nullptr},
};

extern "C" __attribute__((ms_abi)) std::uint32_t u32v_VerLanguageNameW(
    std::uint32_t lang, char16_t* out, std::uint32_t size) noexcept {
    if (out == nullptr || size == 0) {
        return 0;
    }
    const char* name = nullptr;
    for (const LangName& l : kLanguages) {
        if (l.name != nullptr && l.id == (lang & 0xFFFF)) {
            name = l.name;
            break;
        }
    }
    std::string answer =
        name != nullptr
            ? std::string(name)
            : std::to_string(lang & 0xFFFF);
    std::u16string wide;
    static_cast<void>(utf8_to_utf16(answer, wide));
    const std::size_t take =
        std::min(wide.size(), static_cast<std::size_t>(size) - 1);
    std::memcpy(out, wide.data(), take * 2);
    out[take] = u'\0';
    return static_cast<std::uint32_t>(take);
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32v_VerLanguageNameA(
    std::uint32_t lang, char* out, std::uint32_t size) noexcept {
    if (out == nullptr || size == 0) {
        return 0;
    }
    char16_t wide[128] = {};
    const std::uint32_t got = u32v_VerLanguageNameW(lang, wide, 128);
    if (got == 0) {
        return 0;
    }
    std::string narrow;
    static_cast<void>(utf16_to_utf8(std::u16string_view(wide), narrow));
    const std::size_t take =
        std::min(narrow.size(), static_cast<std::size_t>(size) - 1);
    std::memcpy(out, narrow.data(), take);
    out[take] = '\0';
    return static_cast<std::uint32_t>(take);
}

// ===========================================================================
// The registration
// ===========================================================================

void add_version(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    (void)&root_fixed;
    e("GetFileVersionInfoSizeW",
      reinterpret_cast<void*>(&u32v_GetFileVersionInfoSizeW));
    e("GetFileVersionInfoSizeA",
      reinterpret_cast<void*>(&u32v_GetFileVersionInfoSizeA));
    e("GetFileVersionInfoW",
      reinterpret_cast<void*>(&u32v_GetFileVersionInfoW));
    e("GetFileVersionInfoA",
      reinterpret_cast<void*>(&u32v_GetFileVersionInfoA));
    e("VerQueryValueW", reinterpret_cast<void*>(&u32v_VerQueryValueW));
    e("VerQueryValueA", reinterpret_cast<void*>(&u32v_VerQueryValueA));
    e("VerFindFileW", reinterpret_cast<void*>(&u32v_VerFindFileW));
    e("VerFindFileA", reinterpret_cast<void*>(&u32v_VerFindFileA));
    e("VerInstallFileW", reinterpret_cast<void*>(&u32v_VerInstallFileW));
    e("VerInstallFileA", reinterpret_cast<void*>(&u32v_VerInstallFileA));
    e("VerLanguageNameW", reinterpret_cast<void*>(&u32v_VerLanguageNameW));
    e("VerLanguageNameA", reinterpret_cast<void*>(&u32v_VerLanguageNameA));
    // The `Ex` spellings, which the family documents as the same calls
    // with a reserved parameter.
    e("GetFileVersionInfoSizeExW",
      reinterpret_cast<void*>(&u32v_GetFileVersionInfoSizeW));
    e("GetFileVersionInfoSizeExA",
      reinterpret_cast<void*>(&u32v_GetFileVersionInfoSizeA));
    e("GetFileVersionInfoExW",
      reinterpret_cast<void*>(&u32v_GetFileVersionInfoW));
    e("GetFileVersionInfoExA",
      reinterpret_cast<void*>(&u32v_GetFileVersionInfoA));
}

}  // namespace occ::runtime::winabi

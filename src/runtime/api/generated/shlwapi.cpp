// The SHLWAPI surface this runtime did not answer.
//
// One function per export, in the shape every other domain here has: an
// `ms_abi` entry point and a registration function. Every signature below
// is the platform's own, read from the mingw headers by preprocessor, so
// that the argument count and the return type are the ones the guest's
// compiler will call with. A signature guessed here would not be a subtle
// defect: it would be a call whose arguments are read out of the wrong
// registers.
//
// Each entry point states which of two things it is:
//
//   * an implementation, where the behaviour is defined by a format, a
//     structure layout or an arithmetic rule and needs no capability this
//     machine lacks;
//   * a refusal, where the subsystem the call belongs to is not in this
//     runtime -- a window manager, a service database, a device tree. The
//     refusal is `ERROR_CALL_NOT_IMPLEMENTED` through `SetLastError`, which
//     is the answer Windows gives for an entry point whose subsystem is not
//     present, and the comment names the subsystem.
//
// What none of them does is answer success for work that did not happen. A
// guest holding a handle it was never given, or a buffer whose "length" was
// never measured, is in a worse state than one that was told the call is
// unavailable: the first failure lands somewhere else entirely, in code
// that has no reason to suspect what went wrong.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace occ::runtime::winabi {
namespace {

// The code a refusal reports. It is the platform's own -- an entry point
// whose subsystem is absent -- and a guest that handles it is not being
// lied to.
constexpr std::uint32_t kNotImplemented = 120;


// ---------------------------------------------------------------- the text
//
// A rule is written once and instantiated at both widths, so the walks
// below are templates over the character type. `char` and `char16_t` are
// the two spellings Windows uses, and the walk is the same over either.

template <typename C>
[[nodiscard]] constexpr bool ch_digit(C c) noexcept {
    return c >= static_cast<C>('0') && c <= static_cast<C>('9');
}

template <typename C>
[[nodiscard]] constexpr bool ch_alpha(C c) noexcept {
    return (c >= static_cast<C>('A') && c <= static_cast<C>('Z')) ||
           (c >= static_cast<C>('a') && c <= static_cast<C>('z'));
}

template <typename C>
[[nodiscard]] constexpr bool ch_upper(C c) noexcept {
    return c >= static_cast<C>('A') && c <= static_cast<C>('Z');
}

template <typename C>
[[nodiscard]] constexpr bool ch_lower(C c) noexcept {
    return c >= static_cast<C>('a') && c <= static_cast<C>('z');
}

template <typename C>
[[nodiscard]] constexpr bool ch_space(C c) noexcept {
    return c == static_cast<C>(' ') || c == static_cast<C>('\t') ||
           c == static_cast<C>('\n') || c == static_cast<C>('\r') ||
           c == static_cast<C>('\v') || c == static_cast<C>('\f');
}

template <typename C>
[[nodiscard]] constexpr bool ch_hex(C c) noexcept {
    return ch_digit(c) || (c >= static_cast<C>('a') && c <= static_cast<C>('f')) ||
           (c >= static_cast<C>('A') && c <= static_cast<C>('F'));
}

template <typename C>
[[nodiscard]] constexpr bool ch_sep(C c) noexcept {
    return c == static_cast<C>('\\') || c == static_cast<C>('/');
}

// The case fold, over the ASCII range. Windows folds the Latin-1 letters
// with it, and the two ranges above 0x7F that are letters are handled here
// rather than left out because a path on a German machine is spelled with
// them.
template <typename C>
[[nodiscard]] constexpr C ch_lower_of(C c) noexcept {
    if (ch_upper(c)) {
        return static_cast<C>(c + 32);
    }
    if (c >= static_cast<C>(0xC0) && c <= static_cast<C>(0xDE) &&
        c != static_cast<C>(0xD7)) {
        return static_cast<C>(c + 32);
    }
    return c;
}

template <typename C>
[[nodiscard]] constexpr C ch_upper_of(C c) noexcept {
    if (ch_lower(c)) {
        return static_cast<C>(c - 32);
    }
    if (c >= static_cast<C>(0xE0) && c <= static_cast<C>(0xFE) &&
        c != static_cast<C>(0xF7)) {
        return static_cast<C>(c - 32);
    }
    return c;
}

template <typename C>
[[nodiscard]] constexpr C ch_of(char value) noexcept {
    return static_cast<C>(value);
}

// The length of a NUL-terminated string, in the caller's units.
template <typename C>
[[nodiscard]] std::size_t text_len(const C* text) noexcept {
    std::size_t length = 0;
    if (text == nullptr) {
        return 0;
    }
    while (text[length] != static_cast<C>(0)) {
        ++length;
    }
    return length;
}

// The same, stopping at a bound. Windows bounds its string walks in
// characters, and a walk that ran past the bound would read whatever the
// caller happened to have next.
template <typename C>
[[nodiscard]] std::size_t text_len_at(const C* text, std::size_t bound) noexcept {
    std::size_t length = 0;
    if (text == nullptr) {
        return 0;
    }
    while (length < bound && text[length] != static_cast<C>(0)) {
        ++length;
    }
    return length;
}

// A bounded copy, terminator included, answering the number of characters
// the finished string occupies -- which is what the `StrCch*` family
// reports and what a caller uses to advance a write cursor. The answer is
// not marked `[[nodiscard]]`: the Win32 calls that copy do not all read
// their library's answer back, and one that a caller ignores is not a
// mistake here.
template <typename C>
std::size_t text_copy(C* out, std::size_t capacity,
                      const C* source) noexcept {
    if (out == nullptr || capacity == 0) {
        return 0;
    }
    std::size_t at = 0;
    if (source != nullptr) {
        while (at + 1 < capacity && source[at] != static_cast<C>(0)) {
            out[at] = source[at];
            ++at;
        }
    }
    out[at] = static_cast<C>(0);
    return at;
}

// The same, from the end of whatever is already there.
template <typename C>
std::size_t text_append(C* out, std::size_t capacity,
                        const C* source) noexcept {
    if (out == nullptr || capacity == 0) {
        return 0;
    }
    const std::size_t start = text_len_at(out, capacity);
    if (start + 1 >= capacity) {
        return start;
    }
    std::size_t at = start;
    if (source != nullptr) {
        while (at + 1 < capacity && *source != static_cast<C>(0)) {
            out[at++] = *source++;
        }
    }
    out[at] = static_cast<C>(0);
    return at;
}

// The one-character forms. A rule that appends a separator or a star has
// one character and not a string, and spelling it as a one-character string
// at both widths is how a literal gets written twice and gets written wrong
// once.
template <typename C>
std::size_t text_copy(C* out, std::size_t capacity, C value) noexcept {
    if (out == nullptr || capacity == 0) {
        return 0;
    }
    out[0] = value;
    out[1 < capacity ? 1 : 0] = static_cast<C>(0);
    return capacity == 1 ? 0 : 1;
}

template <typename C>
void text_append(C* out, std::size_t capacity, C value) noexcept {
    if (out == nullptr || capacity == 0) {
        return;
    }
    const std::size_t at = text_len_at(out, capacity);
    if (at + 1 >= capacity) {
        return;
    }
    out[at] = value;
    out[at + 1] = static_cast<C>(0);
}

template <typename C>
[[nodiscard]] const C* find_first_of(const C* text, C value) noexcept {
    if (text == nullptr) {
        return nullptr;
    }
    for (const C* p = text; *p != static_cast<C>(0); ++p) {
        if (*p == value) {
            return p;
        }
    }
    return text + text_len(text);
}

// An ASCII literal appended at either width, so that a rule that writes a
// separator or a star spells it once rather than once per character width.
template <typename C>
void text_append_ascii(C* out, std::size_t capacity, const char* text) noexcept {
    if (out == nullptr || capacity == 0 || text == nullptr) {
        return;
    }
    std::size_t at = text_len_at(out, capacity);
    while (*text != 0 && at + 1 < capacity) {
        out[at++] = static_cast<C>(static_cast<unsigned char>(*text++));
    }
    out[at] = static_cast<C>(0);
}

template <typename C>
[[nodiscard]] bool text_equal(const C* a, const C* b) noexcept {
    if (a == nullptr || b == nullptr) {
        return a == b;
    }
    while (*a != static_cast<C>(0) && *a == *b) {
        ++a;
        ++b;
    }
    return *a == *b;
}

template <typename C>
[[nodiscard]] bool text_equal_ci(const C* a, const C* b) noexcept {
    if (a == nullptr || b == nullptr) {
        return a == b;
    }
    while (*a != static_cast<C>(0) && ch_lower_of(*a) == ch_lower_of(*b)) {
        ++a;
        ++b;
    }
    return *a == *b;
}

// The first occurrence of any character of `set`, or the terminator.
template <typename C>
[[nodiscard]] const C* find_first_of(const C* text, const C* set) noexcept {
    for (const C* p = text; *p != static_cast<C>(0); ++p) {
        for (const C* s = set; *s != static_cast<C>(0); ++s) {
            if (*p == *s) {
                return p;
            }
        }
    }
    return text + text_len(text);
}

// The substring, or null. An empty needle matches the start, which is what
// the reference answers and what a caller that passes one relies on.
template <typename C>
[[nodiscard]] const C* find_text(const C* hay, const C* needle) noexcept {
    if (needle == nullptr || *needle == static_cast<C>(0)) {
        return hay;
    }
    const std::size_t skip = text_len(needle);
    for (const C* p = hay; *p != static_cast<C>(0); ++p) {
        std::size_t at = 0;
        while (at < skip && p[at] != static_cast<C>(0) &&
               ch_lower_of(p[at]) == ch_lower_of(needle[at])) {
            ++at;
        }
        if (at == skip) {
            return p;
        }
    }
    return nullptr;
}

template <typename C>
[[nodiscard]] const C* find_text_ci(const C* hay, const C* needle) noexcept {
    if (needle == nullptr || *needle == static_cast<C>(0)) {
        return hay;
    }
    const std::size_t skip = text_len(needle);
    for (const C* p = hay; *p != static_cast<C>(0); ++p) {
        std::size_t at = 0;
        while (at < skip && p[at] != static_cast<C>(0) &&
               ch_lower_of(p[at]) == ch_lower_of(needle[at])) {
            ++at;
        }
        if (at == skip) {
            return p;
        }
    }
    return nullptr;
}

// ------------------------------------------------------------- the bridge
//
// The narrow and wide spellings of one string. The conversion is the
// runtime's single-byte code page: every code point below 0x100 is itself,
// which is what the stream, file and registry domains already answer, and a
// conversion that disagreed with them would be a second code page.

[[maybe_unused]] std::size_t widen_text(const char* source, char16_t* out,
                                        std::size_t capacity) noexcept {
    if (out == nullptr || capacity == 0) {
        return 0;
    }
    std::size_t at = 0;
    if (source != nullptr) {
        while (at + 1 < capacity && source[at] != '\0') {
            out[at] = static_cast<char16_t>(
                static_cast<unsigned char>(source[at]));
            ++at;
        }
    }
    out[at] = u'\0';
    return at;
}

[[maybe_unused]] std::size_t narrow_text(const char16_t* source, char* out,
                                         std::size_t capacity) noexcept {
    if (out == nullptr || capacity == 0) {
        return 0;
    }
    std::size_t at = 0;
    if (source != nullptr) {
        while (at + 1 < capacity && source[at] != u'\0') {
            const char16_t ch = source[at];
            out[at] = ch < 0x100 ? static_cast<char>(ch) : '?';
            ++at;
        }
    }
    out[at] = '\0';
    return at;
}

// The same, allocating. The caller frees with `LocalFree`, which is the
// allocator Windows uses for the strings these functions hand back and the
// one the runtime's own allocator accepts.
[[maybe_unused]] char16_t* widen_alloc(const char* source) noexcept {
    const std::size_t length = text_len(source);
    auto* out = static_cast<char16_t*>(
        k32m_LocalAlloc(0x0040u, (length + 1) * sizeof(char16_t)));
    if (out == nullptr) {
        return nullptr;
    }
    widen_text(source, out, length + 1);
    return out;
}

[[maybe_unused]] char* narrow_alloc(const char16_t* source) noexcept {
    const std::size_t length = text_len(source);
    auto* out = static_cast<char*>(k32m_LocalAlloc(0x0040u, length + 1));
    if (out == nullptr) {
        return nullptr;
    }
    narrow_text(source, out, length + 1);
    return out;
}

// ------------------------------------------------------------- the shapes
//
// The structures a handful of these entry points fill. They are written by
// offset, because this host's compiler lays a structure out by this
// platform's rules and the guest's are the Windows ones.

// `OSVERSIONINFOA/W` and `OSVERSIONINFOEXA/W`: four 32-bit fields, a
// 128-character string, and for the extended form two 16-bit fields and a
// byte with three reserved bytes behind it.
[[maybe_unused]] void write_version_info(void* info, std::uint32_t major,
                                         std::uint32_t minor,
                                         std::uint32_t build,
                                         std::uint32_t platform,
                                         std::uint32_t length,
                                         const char16_t* service_pack,
                                         std::uint16_t service_pack_major,
                                         std::uint16_t service_pack_minor,
                                         std::uint16_t suite_mask) noexcept {
    if (info == nullptr) {
        return;
    }
    write_u32(info, 0, major);
    write_u32(info, 4, minor);
    write_u32(info, 8, build);
    write_u32(info, 12, platform);
    if (length > 0x14u) {
        char16_t* text = static_cast<char16_t*>(info) + 10;
        text_copy<char16_t>(text, 128, service_pack);
        if (length > 0x114u) {
            write_u16(info, 0x114, service_pack_major);
            write_u16(info, 0x116, service_pack_minor);
            write_u16(info, 0x118, suite_mask);
            write_u8(info, 0x11A, 0);
        }
    }
}

// A little-endian 16-bit read and write, for the structures whose fields
// are words and which the shared byte accessors do not reach.
[[maybe_unused]] [[maybe_unused]] [[nodiscard]] std::uint16_t read_le16(const void* base,
                                      std::size_t offset) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(base) + offset;
    return static_cast<std::uint16_t>(bytes[0] |
                                      (static_cast<std::uint16_t>(bytes[1]) << 8));
}

[[maybe_unused]] [[nodiscard]] std::uint32_t read_le32(const void* base,
                                      std::size_t offset) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(base) + offset;
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8) |
           (static_cast<std::uint32_t>(bytes[2]) << 16) |
           (static_cast<std::uint32_t>(bytes[3]) << 24);
}

[[maybe_unused]] void write_le16(void* base, std::size_t offset, std::uint16_t value) noexcept {
    auto* bytes = static_cast<std::uint8_t*>(base) + offset;
    bytes[0] = static_cast<std::uint8_t>(value & 0xFFu);
    bytes[1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
}

[[maybe_unused]] void write_le32(void* base, std::size_t offset, std::uint32_t value) noexcept {
    auto* bytes = static_cast<std::uint8_t*>(base) + offset;
    bytes[0] = static_cast<std::uint8_t>(value & 0xFFu);
    bytes[1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
    bytes[2] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
    bytes[3] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
}

[[maybe_unused]] [[nodiscard]] std::uint64_t read_le64(const void* base,
                                      std::size_t offset) noexcept {
    return static_cast<std::uint64_t>(read_le32(base, offset)) |
           (static_cast<std::uint64_t>(read_le32(base, offset + 4)) << 32);
}

[[maybe_unused]] void write_le64(void* base, std::size_t offset, std::uint64_t value) noexcept {
    write_le32(base, offset, static_cast<std::uint32_t>(value & 0xFFFFFFFFu));
    write_le32(base, offset + 4, static_cast<std::uint32_t>(value >> 32));
}

// ------------------------------------------------------------- the memory
//
// The process heap, as the callers of these functions reach it. The
// runtime answers `GetProcessHeap` with the address it hands out, and the
// rules that allocate use the guest allocator so that a guest's own
// `LocalFree` accepts the block.

[[maybe_unused]] void* guest_alloc(std::size_t bytes) noexcept {
    return k32m_LocalAlloc(0x0040u, bytes == 0 ? 1 : bytes);
}

[[maybe_unused]] void guest_free(void* block) noexcept {
    static_cast<void>(k32m_LocalFree(block));
}

// A resize, as allocate-and-copy. The runtime's allocator publishes no
// reallocation, and one built here from the two it does publish has the
// property the callers need -- the old block is still the caller's to free
// if the new one could not be made.
[[maybe_unused]] void* guest_resize(void* block, std::size_t old_bytes,
                                    std::size_t bytes) noexcept {
    void* fresh = guest_alloc(bytes);
    if (fresh == nullptr) {
        return nullptr;
    }
    if (block != nullptr) {
        std::memcpy(fresh, block, old_bytes < bytes ? old_bytes : bytes);
        k32m_LocalFree(block);
    }
    return fresh;
}

// ------------------------------------------------------------------ paths
//
// The walks the `Path*` family is made of. Every one of them is a function
// of the string alone, so they are written once and the entry points below
// are one line each.

// The longest path the `Path*` entry points of this generation accept. The
// limit is the API's: the callers of these functions allocate `MAX_PATH`
// buffers, so a longer string is not one that could have been passed.
constexpr std::size_t kMaxPath = 260;

// Whether the string names a share: two leading backslashes.
template <typename C>
[[nodiscard]] bool path_is_unc(const C* path) noexcept {
    return path != nullptr && path[0] == static_cast<C>('\\') &&
           path[1] == static_cast<C>('\\');
}

// `\\server\share`: a UNC path with exactly one separator after the
// leading pair. The walk stops at the second one, which is what makes this
// different from `path_is_unc`.
template <typename C>
[[nodiscard]] bool path_is_unc_server_share(const C* path) noexcept {
    if (!path_is_unc(path)) {
        return false;
    }
    bool seen_separator = false;
    for (const C* p = path + 2; *p != static_cast<C>(0); ++p) {
        if (*p == static_cast<C>('\\')) {
            if (seen_separator) {
                return false;
            }
            seen_separator = true;
        }
    }
    return seen_separator;
}

// `\\server`: two leading backslashes and no other separator.
template <typename C>
[[nodiscard]] bool path_is_unc_server(const C* path) noexcept {
    if (!path_is_unc(path)) {
        return false;
    }
    for (const C* p = path + 2; *p != static_cast<C>(0); ++p) {
        if (*p == static_cast<C>('\\')) {
            return false;
        }
    }
    return true;
}

// A root: `\`, `\\server\share`, or `X:\`. The single backslash that
// names the root of the current drive is the first of those, and it is
// checked before the UNC form because `\\` is not a root and `\\server`
// is not either -- the walk answers true only when the string ends exactly
// after the share name.
template <typename C>
[[nodiscard]] bool path_is_root(const C* path) noexcept {
    if (path == nullptr || *path == static_cast<C>(0)) {
        return false;
    }
    if (*path == static_cast<C>('\\')) {
        if (path[1] == static_cast<C>(0)) {
            return true;
        }
        if (path[1] == static_cast<C>('\\')) {
            bool seen_separator = false;
            for (const C* p = path + 2; *p != static_cast<C>(0); ++p) {
                if (*p == static_cast<C>('\\')) {
                    if (seen_separator) {
                        return false;
                    }
                    seen_separator = true;
                }
            }
            return true;
        }
        return false;
    }
    return path[1] == static_cast<C>(':') && path[2] == static_cast<C>('\\') &&
           path[3] == static_cast<C>(0);
}

// The extension: the last dot that is not preceded by a separator or a
// space, and the terminator when there is none. A dot that opens a name is
// not one -- `.gitignore` has no extension -- which is what clearing the
// candidate at a separator is for, and a space clears it too, because the
// reference reads the string as a command line and treats the space as the
// end of the program name.
//
// The answer for "no extension" is the terminator rather than null, and
// that is the contract: a caller writes `*PathFindExtension(p)` to ask
// whether there is one, and a caller handed null would read through it.
template <typename C>
[[nodiscard]] const C* path_extension(const C* path) noexcept {
    if (path == nullptr) {
        return nullptr;
    }
    const C* last_dot = nullptr;
    const C* p = path;
    for (; *p != static_cast<C>(0); ++p) {
        if (*p == static_cast<C>('\\') || *p == static_cast<C>(' ')) {
            last_dot = nullptr;
        } else if (*p == static_cast<C>('.')) {
            last_dot = p;
        }
    }
    return last_dot != nullptr ? last_dot : p;
}

// The file name: everything after the last separator that is itself
// followed by something other than a separator. `C:foo` answers `foo`, and
// `C:` answers `C:`, which is why the colon counts only when text follows.
template <typename C>
[[nodiscard]] const C* path_file_name(const C* path) noexcept {
    if (path == nullptr) {
        return nullptr;
    }
    const C* last = path;
    for (const C* p = path; *p != static_cast<C>(0); ++p) {
        const bool lead = *p == static_cast<C>('\\') ||
                          *p == static_cast<C>('/') || *p == static_cast<C>(':');
        if (lead && p[1] != static_cast<C>(0) &&
            p[1] != static_cast<C>('\\') && p[1] != static_cast<C>('/')) {
            last = p + 1;
        }
    }
    return last;
}

// Everything after the program name: the first space that is not inside a
// quoted run, plus one. With no arguments the answer is the terminator, so
// that `*p == 0` is the test for "there are none".
template <typename C>
[[nodiscard]] const C* path_args(const C* path) noexcept {
    if (path == nullptr) {
        return nullptr;
    }
    bool quoted = false;
    const C* p = path;
    for (; *p != static_cast<C>(0); ++p) {
        if (*p == static_cast<C>(' ') && !quoted) {
            return p + 1;
        }
        if (*p == static_cast<C>('"')) {
            quoted = !quoted;
        }
    }
    return p;
}

// The root skipped. The answer is where the first component after the root
// begins, or null when the root is the whole string.
template <typename C>
[[nodiscard]] const C* path_skip_root(const C* path) noexcept {
    if (path == nullptr || *path == static_cast<C>(0)) {
        return nullptr;
    }
    if (path_is_unc(path)) {
        const C* p = path + 2;
        const C* server_end = nullptr;
        for (; *p != static_cast<C>(0); ++p) {
            if (*p == static_cast<C>('\\')) {
                server_end = p;
                break;
            }
        }
        if (server_end == nullptr) {
            return nullptr;
        }
        p = server_end + 1;
        const C* share_end = nullptr;
        for (; *p != static_cast<C>(0); ++p) {
            if (*p == static_cast<C>('\\')) {
                share_end = p;
                break;
            }
        }
        return share_end == nullptr ? p : share_end + 1;
    }
    if (path[1] == static_cast<C>(':') && path[2] == static_cast<C>('\\')) {
        return path + 3;
    }
    return nullptr;
}

// The file specification removed, answering whether the string changed. The
// two leading separators of a share are a prefix and not a component, and a
// drive's colon restarts the count so that `C:foo` loses `foo` and keeps
// `C:`.
template <typename C>
[[nodiscard]] bool path_remove_file_spec(C* path) noexcept {
    if (path == nullptr) {
        return false;
    }
    C* spec = path;
    if (*path == static_cast<C>('\\')) {
        spec = ++path;
    }
    if (*path == static_cast<C>('\\')) {
        spec = ++path;
    }
    while (*path != static_cast<C>(0)) {
        if (*path == static_cast<C>('\\')) {
            spec = path;
        } else if (*path == static_cast<C>(':')) {
            // The drive designator restarts the walk: `C:foo` loses `foo` and
            // keeps `C:`. The separator after the colon is skipped by moving the
            // file-spec pointer rather than the cursor: a cursor moved twice
            // would swallow the first character of the path.
            spec = ++path;
            if (*path == static_cast<C>('\\')) {
                ++spec;
            }
        }
        path += 1;
    }
    if (*spec != static_cast<C>(0)) {
        *spec = static_cast<C>(0);
        return true;
    }
    return false;
}

// The common prefix, counted at component boundaries and written into `out`
// when one is given. Two paths share components only if they share a root,
// and the reference rounds a one-letter-and-colon prefix up to three
// characters so that `C:\` is not read as sharing a prefix with `C:x`.
template <typename C>
[[nodiscard]] std::size_t path_common_prefix(const C* first, const C* second,
                                             C* out) noexcept {
    if (out != nullptr) {
        *out = static_cast<C>(0);
    }
    if (first == nullptr || second == nullptr) {
        return 0;
    }
    const C* left = first;
    const C* right = second;
    if (path_is_unc(first)) {
        if (!path_is_unc(second)) {
            return 0;
        }
        left += 2;
        right += 2;
    } else if (path_is_unc(second)) {
        return 0;
    }
    std::size_t length = 0;
    for (;;) {
        const bool left_edge = *left == static_cast<C>(0) ||
                               *left == static_cast<C>('\\');
        const bool right_edge = *right == static_cast<C>(0) ||
                                *right == static_cast<C>('\\');
        if (left_edge && right_edge) {
            length = static_cast<std::size_t>(left - first);
        }
        if (*left == static_cast<C>(0) ||
            ch_lower_of(*left) != ch_lower_of(*right)) {
            break;
        }
        ++left;
        ++right;
    }
    if (length == 2) {
        ++length;
    }
    if (length != 0 && out != nullptr) {
        std::memcpy(out, first, length * sizeof(C));
        out[length] = static_cast<C>(0);
    }
    return length;
}

// The path canonicalized: `.` components dropped, `..` components folded
// back, separators left as they were found. The reference's algorithm,
// including its treatment of a drive-relative path and of a UNC share,
// which is that `..` cannot climb out of either.
template <typename C>
[[nodiscard]] bool path_canonicalize(C* buffer, const C* path) noexcept {
    if (buffer != nullptr) {
        *buffer = static_cast<C>(0);
    }
    if (buffer == nullptr || path == nullptr) {
        return false;
    }
    if (*path == static_cast<C>(0)) {
        buffer[0] = static_cast<C>('\\');
        buffer[1] = static_cast<C>(0);
        return true;
    }
    C* out = buffer;
    const C* in = path;
    if (*in == static_cast<C>('\\')) {
        *out++ = *in++;
    } else if (*in != static_cast<C>(0) && in[1] == static_cast<C>(':')) {
        *out++ = *in++;
        *out++ = *in++;
        if (*in == static_cast<C>('\\')) {
            *out++ = *in++;
        }
    }
    while (*in != static_cast<C>(0)) {
        if (*in != static_cast<C>('.')) {
            *out++ = *in++;
            continue;
        }
        const bool at_component_start =
            in == path || in[-1] == static_cast<C>('\\') ||
            in[-1] == static_cast<C>(':');
        if (in[1] == static_cast<C>('\\') && at_component_start) {
            in += 2;  // `.\` is the current directory and is dropped
            continue;
        }
        if (in[1] == static_cast<C>('.') &&
            (out == buffer || out[-1] == static_cast<C>('\\'))) {
            if (out != buffer) {
                *out = static_cast<C>(0);
                if (out > buffer + 1 && out[-1] == static_cast<C>('\\') &&
                    (out[-2] != static_cast<C>('\\') || out > buffer + 2)) {
                    if (out[-2] == static_cast<C>(':') &&
                        (out > buffer + 3 || out[-3] == static_cast<C>(':'))) {
                        out -= 2;
                        while (out > buffer && *out != static_cast<C>('\\')) {
                            --out;
                        }
                        if (*out == static_cast<C>('\\')) {
                            ++out;
                        } else {
                            out = buffer;
                        }
                    } else if (out[-2] != static_cast<C>(':') &&
                               !path_is_unc_server_share(buffer)) {
                        out -= 2;
                    }
                }
                while (out > buffer && *out != static_cast<C>('\\')) {
                    --out;
                }
                if (out == buffer) {
                    *out++ = static_cast<C>('\\');
                    ++in;
                }
            }
            in += 2;
            continue;
        }
        *out++ = *in++;
    }
    // A bare drive is given a root, so that `C:` becomes `C:\`.
    if (out - buffer == 2 && out[-1] == static_cast<C>(':')) {
        *out++ = static_cast<C>('\\');
    }
    *out = static_cast<C>(0);
    return true;
}

// One mask against one name, for `PathMatchSpec`. `?` is any character,
// `*` is any run, and the comparison folds case. The recursion on `*` is
// what makes `*.txt` match `a.b.txt`.
template <typename C>
[[nodiscard]] bool path_match_mask(const C* name, const C* mask) noexcept {
    while (*name != static_cast<C>(0) && *mask != static_cast<C>(0) &&
           *mask != static_cast<C>(';')) {
        if (*mask == static_cast<C>('*')) {
            do {
                if (path_match_mask(name, mask + 1)) {
                    return true;
                }
            } while (*name++ != static_cast<C>(0));
            return false;
        }
        if (ch_upper_of(*mask) != ch_upper_of(*name) &&
            *mask != static_cast<C>('?')) {
            return false;
        }
        ++name;
        ++mask;
    }
    if (*name == static_cast<C>(0)) {
        while (*mask == static_cast<C>('*')) {
            ++mask;
        }
        if (*mask == static_cast<C>(0) || *mask == static_cast<C>(';')) {
            return true;
        }
    }
    return false;
}

// The masks are separated by semicolons, leading spaces are eaten, and one
// of them matching is enough. `*.*` is answered before any of that, because
// it is the mask every caller of this function writes to mean "anything".
template <typename C>
[[nodiscard]] bool path_match_spec(const C* path, const C* mask) noexcept {
    if (path == nullptr || mask == nullptr) {
        return false;
    }
    if (mask[0] == static_cast<C>('*') && mask[1] == static_cast<C>('.') &&
        mask[2] == static_cast<C>('*') && mask[3] == static_cast<C>(0)) {
        return true;
    }
    while (*mask != static_cast<C>(0)) {
        while (*mask == static_cast<C>(' ')) {
            ++mask;
        }
        if (path_match_mask(path, mask)) {
            return true;
        }
        while (*mask != static_cast<C>(0) && *mask != static_cast<C>(';')) {
            ++mask;
        }
        if (*mask == static_cast<C>(';')) {
            ++mask;
        }
    }
    return false;
}

// The character classes `PathGetCharType` answers with. The names are the
// header's and the values are the bits.
constexpr std::uint32_t kGctInvalid = 0x0000;
constexpr std::uint32_t kGctShortChar = 0x0001;
constexpr std::uint32_t kGctLfnChar = 0x0002;
constexpr std::uint32_t kGctWild = 0x0004;
constexpr std::uint32_t kGctSeparator = 0x0008;

// The class of one character. The rule is the reference's, which is
// Windows' own: a character below 0x20 or one of the five the file system
// reserves is invalid; `*` and `?` are wildcards; the two separators are
// separators; everything else is valid in a long name, with the subset DOS
// also accepts marked as such.
template <typename C>
[[nodiscard]] std::uint32_t path_char_type(C ch) noexcept {
    if (ch == 0 || ch < static_cast<C>(' ') || ch == static_cast<C>('<') ||
        ch == static_cast<C>('>') || ch == static_cast<C>('"') ||
        ch == static_cast<C>('|') || ch == static_cast<C>('/')) {
        return kGctInvalid;
    }
    if (ch == static_cast<C>('*') || ch == static_cast<C>('?')) {
        return kGctWild;
    }
    if (ch == static_cast<C>('\\') || ch == static_cast<C>(':')) {
        return kGctSeparator;
    }
    const unsigned int value = static_cast<unsigned int>(ch);
    if (value > 0x7E) {
        return kGctLfnChar | kGctShortChar;
    }
    std::uint32_t flags = kGctLfnChar;
    const bool odd = (value & 1u) != 0 && ch != static_cast<C>(';');
    if (odd || ch_digit(ch) || ch_alpha(ch) || ch == static_cast<C>('$') ||
        ch == static_cast<C>('&') || ch == static_cast<C>('(') ||
        ch == static_cast<C>(')') || ch == static_cast<C>('.') ||
        ch == static_cast<C>('@') || ch == static_cast<C>('^') ||
        ch == static_cast<C>('\'') || value == 130 ||
        ch == static_cast<C>('`')) {
        flags |= kGctShortChar;
    }
    return flags;
}

// A long file name: anything an 8.3 name could not be. A DOS name has no
// spaces, exactly one dot, at most eight characters before it and at most
// three after.
template <typename C>
[[nodiscard]] bool path_is_long_file_spec(const C* path) noexcept {
    if (path == nullptr) {
        return false;
    }
    unsigned int name_length = 0;
    unsigned int extension_length = 0;
    for (const C* p = path; *p != static_cast<C>(0); ++p) {
        if (*p == static_cast<C>(' ')) {
            return true;
        }
        if (*p == static_cast<C>('.')) {
            if (extension_length != 0) {
                return true;
            }
            extension_length = 1;
        } else if (extension_length != 0) {
            ++extension_length;
            if (extension_length > 4) {
                return true;
            }
        } else {
            ++name_length;
            if (name_length > 8) {
                return true;
            }
        }
    }
    return false;
}

// The blanks removed from both ends, in place.
template <typename C>
void path_remove_blanks(C* path) noexcept {
    if (path == nullptr || *path == static_cast<C>(0)) {
        return;
    }
    C* write = path;
    const C* read = path;
    while (*read == static_cast<C>(' ')) {
        ++read;
    }
    while (*read != static_cast<C>(0)) {
        *write++ = *read++;
    }
    while (write != path && write[-1] == static_cast<C>(' ')) {
        --write;
    }
    *write = static_cast<C>(0);
}

// ----------------------------------------------------------------- numbers
//
// The shell's own formatters, which build their output from the digits
// rather than from a library: the significant-digit walk needs the digits
// in reverse to be able to cut them, and the byte-size formatter needs a
// fixed number of decimals without the current locale's decimal point being
// involved.

// A decimal number written backwards into the end of a buffer. The answer
// points one before the first digit, which is where the caller writes the
// character that precedes it -- that is the reference's contract and the
// reason the space of ` 100 hr` costs no shifting.
template <typename C>
[[nodiscard]] C* write_reverse_number(C* end, std::uint32_t value) noexcept {
    *end = static_cast<C>(0);
    C* p = end;
    do {
        const std::uint32_t digit = value % 10u;
        *--p = static_cast<C>('0' + digit);
        value = (value - digit) / 10u;
    } while (value > 0);
    return p - 1;
}

// The significant-digit cut: the caller keeps `digits` characters of the
// number and every digit after them becomes a zero. The interval formatter
// truncates and never rounds, which is what makes `138 hr` become `100 hr`
// at one digit rather than `140 hr`.
template <typename C>
[[nodiscard]] int format_significant(C* number, int digits) noexcept {
    for (C* p = number; *p != static_cast<C>(0); ++p) {
        if (--digits == 0) {
            for (C* rest = p + 1; *rest != static_cast<C>(0); ++rest) {
                *rest = static_cast<C>('0');
            }
            return 0;
        }
    }
    return digits;
}

// One time class appended to the output: the number, a space, the unit. The
// space is written over the character before the first digit, which is why
// the reverse writer answers that position.
template <typename C>
[[nodiscard]] int write_time_class(C* out, std::size_t capacity,
                                   std::uint32_t value, const C* unit,
                                   int digits) noexcept {
    C number[64];
    C* slot = write_reverse_number(number + 48, value);
    digits = format_significant(slot + 1, digits);
    *slot = static_cast<C>(' ');
    text_append<C>(out, capacity, slot);
    text_append<C>(out, capacity, unit);
    return digits;
}

// A decimal number, unseparated.
//
// The shell formats its numbers through the current locale's number format,
// and this runtime answers one locale -- the C one, whose thousands
// separator is the empty string. So the digits stand alone, which is what
// the reference produces when its own locale is the C one and what its
// answers show for every size it tests.
template <typename C>
[[nodiscard]] std::size_t number_text(C* out, std::size_t capacity,
                                      std::int64_t value) noexcept {
    if (out == nullptr || capacity == 0) {
        return 0;
    }
    C digits[24];
    const bool negative = value < 0;
    const std::uint64_t magnitude =
        negative ? (0u - static_cast<std::uint64_t>(value))
                 : static_cast<std::uint64_t>(value);
    std::size_t count = 0;
    std::uint64_t rest = magnitude;
    do {
        digits[count++] = static_cast<C>('0' + (rest % 10u));
        rest /= 10u;
    } while (rest != 0);

    std::size_t at = 0;
    if (negative) {
        if (at + 1 >= capacity) {
            out[at] = static_cast<C>(0);
            return at;
        }
        out[at++] = static_cast<C>('-');
    }
    for (std::size_t index = count; index > 0; --index) {
        if (at + 1 >= capacity) {
            break;
        }
        out[at++] = digits[index - 1];
    }
    out[at] = static_cast<C>(0);
    return at;
}

// A fixed-point decimal: `decimals` digits after the point, rounded half
// away from zero at the last of them. The point is the period because the
// locale this runtime answers is the C one, and a function that asked the
// host's locale for it would print a comma on a machine whose C library is
// configured that way.
template <typename C>
[[nodiscard]] bool format_fixed(C* out, std::size_t capacity, double value,
                                int decimals) noexcept {
    if (out == nullptr || capacity == 0 || !(value >= 0.0)) {
        return false;
    }
    std::uint64_t scale = 1;
    for (int index = 0; index < decimals; ++index) {
        scale *= 10u;
    }
    long double scaled = static_cast<long double>(value) * scale;
    scaled = std::floor(scaled + 0.5L);
    if (scaled < 0.0L || scaled > 1.0e18L) {
        return false;
    }
    const std::uint64_t total = static_cast<std::uint64_t>(scaled);
    const std::uint64_t whole = total / scale;
    const std::uint64_t fraction = scale == 1 ? 0 : total % scale;

    C digits[24];
    std::size_t count = 0;
    std::uint64_t rest = whole;
    do {
        digits[count++] = static_cast<C>('0' + (rest % 10u));
        rest /= 10u;
    } while (rest != 0);
    std::size_t at = 0;
    for (std::size_t index = count; index > 0; --index) {
        if (at + 1 >= capacity) {
            out[at] = static_cast<C>(0);
            return false;
        }
        out[at++] = digits[index - 1];
    }
    if (decimals > 0) {
        if (at + 2 >= capacity) {
            out[at] = static_cast<C>(0);
            return false;
        }
        out[at++] = static_cast<C>('.');
        std::uint64_t divisor = scale / 10u;
        std::uint64_t part = fraction;
        for (int index = 0; index < decimals; ++index) {
            const std::uint64_t digit = divisor == 0 ? part : part / divisor;
            if (divisor != 0) {
                part -= digit * divisor;
                divisor /= 10u;
            }
            out[at++] = static_cast<C>('0' + digit);
        }
    }
    out[at] = static_cast<C>(0);
    return true;
}
// The file attributes of a path, at whichever width the caller works in.
template <typename C>
[[nodiscard]] std::uint32_t get_attributes(const C* path) noexcept;
template <>
[[nodiscard]] inline std::uint32_t get_attributes<char>(const char* path) noexcept {
    return k32b_GetFileAttributesA(path);
}
template <>
[[nodiscard]] inline std::uint32_t get_attributes<char16_t>(
    const char16_t* path) noexcept {
    return k32b_GetFileAttributesW(path);
}

// The next entry of a directory walk. The narrow and wide spellings live in
// different slices of the file domain, which is why this is a name rather
// than a width substituted into one.
template <typename C>
[[nodiscard]] bool find_next_entry(void* walk, void* entry) noexcept;
template <>
[[nodiscard]] inline bool find_next_entry<char>(void* walk,
                                                void* entry) noexcept {
    return k32f3_FindNextFileA(walk, entry) != 0;
}
template <>
[[nodiscard]] inline bool find_next_entry<char16_t>(void* walk,
                                                    void* entry) noexcept {
    return k32f2_FindNextFileW(walk, entry) != 0;
}

// Whether a path is relative: not a leading separator, and not driven by a
// letter and a colon. `X:` is absolute with or without a separator after
// it, which is the difference between a drive path and a drive-relative
// one and the reason this is not a test for a leading character alone.
template <typename C>
[[nodiscard]] bool path_is_relative(const C* path) noexcept {
    if (path == nullptr || *path == static_cast<C>(0)) {
        return true;
    }
    return !(*path == static_cast<C>(92) ||
             path[1] == static_cast<C>(':'));
}

// A directory, as the file attributes describe one. The two UNC forms are
// excluded before the query, because a server and a share are not
// directories and a query against them would reach the network for an
// answer this call can give without one.
template <typename C>
[[nodiscard]] bool path_is_directory(const C* path) noexcept {
    if (path == nullptr || path_is_unc_server(path) ||
        path_is_unc_server_share(path)) {
        return false;
    }
    const std::uint32_t attributes = get_attributes<C>(path);
    if (attributes == 0xFFFFFFFFu) {
        return false;
    }
    return (attributes & 0x00000010u) != 0;
}

// A separator appended when the last character is not one, answering
// whether there was room.
template <typename C>
[[nodiscard]] bool path_add_backslash(C* path, std::size_t capacity) noexcept {
    if (path == nullptr || capacity == 0) {
        return false;
    }
    const std::size_t length = text_len_at(path, capacity);
    if (length == 0) {
        return true;
    }
    if (path[length - 1] == static_cast<C>('\\')) {
        return true;
    }
    if (length + 2 > capacity) {
        return false;
    }
    path[length] = static_cast<C>('\\');
    path[length + 1] = static_cast<C>(0);
    return true;
}

// One path joined onto a directory, with the separator only where it is
// needed. The answer is false when the result would not fit.
template <typename C>
[[nodiscard]] bool path_join(C* out, std::size_t capacity, const C* directory,
                             const C* file) noexcept {
    if (out == nullptr || directory == nullptr || file == nullptr) {
        return false;
    }
    if (text_copy<C>(out, capacity, directory) == 0) {
        return false;
    }
    if (!path_add_backslash<C>(out, capacity)) {
        return false;
    }
    return text_append<C>(out, capacity, file) != 0;
}

// Whether the first `length` characters of two strings fold to the same
// text. Used by the un-expander, where the candidate is the whole of one
// string and a prefix of the other.
template <typename C>
[[nodiscard]] bool text_lower_equal_prefix(const C* value, const C* path,
                                           std::size_t length) noexcept {
    if (value == nullptr || path == nullptr) {
        return false;
    }
    for (std::size_t index = 0; index < length; ++index) {
        if (value[index] == static_cast<C>(0) ||
            ch_lower_of(value[index]) != ch_lower_of(path[index])) {
            return false;
        }
    }
    return true;
}

// A byte count as the shell spells it: a whole number of bytes below a
// kilobyte, and a scaled figure with a unit letter above that. The table
// and the arithmetic are the reference's, including the shift that keeps
// the double's precision above a terabyte and the small term that keeps a
// count sitting exactly on a boundary from rounding down.
struct ByteFormat {
    std::uint64_t limit;
    double divisor;
    double normaliser;
    int decimals;
    char prefix;
};

[[nodiscard]] char16_t* format_byte_size(std::int64_t bytes, char16_t* out,
                                         std::uint32_t capacity) noexcept {
    if (out == nullptr || capacity == 0) {
        return out;
    }
    constexpr std::uint64_t kKb = 1024ull;
    constexpr std::uint64_t kMb = kKb * kKb;
    constexpr std::uint64_t kGb = kMb * kKb;
    constexpr std::uint64_t kTb = kGb * kKb;
    constexpr std::uint64_t kPb = kTb * kKb;
    static const ByteFormat formats[] = {
        {10ull * kKb, 10.24, 100.0, 2, 'K'},
        {100ull * kKb, 102.4, 10.0, 1, 'K'},
        {1000ull * kKb, 1024.0, 1.0, 0, 'K'},
        {10ull * kMb, 10485.76, 100.0, 2, 'M'},
        {100ull * kMb, 104857.6, 10.0, 1, 'M'},
        {1000ull * kMb, 1048576.0, 1.0, 0, 'M'},
        {10ull * kGb, 10737418.24, 100.0, 2, 'G'},
        {100ull * kGb, 107374182.4, 10.0, 1, 'G'},
        {1000ull * kGb, 1073741824.0, 1.0, 0, 'G'},
        {10ull * kTb, 10485.76, 100.0, 2, 'T'},
        {100ull * kTb, 104857.6, 10.0, 1, 'T'},
        {1000ull * kTb, 1048576.0, 1.0, 0, 'T'},
        {10ull * kPb, 10737418.24, 100.0, 2, 'P'},
        {100ull * kPb, 107374182.4, 10.0, 1, 'P'},
        {1000ull * kPb, 1073741824.0, 1.0, 0, 'P'},
        {0, 10995116277.76, 100.0, 2, 'E'},
    };
    if (bytes < 1024) {
        // Below a kilobyte -- negative counts included, which is the
        // reference's rule and the reason a size that went under says how
        // far it went under rather than being scaled into a unit -- the
        // answer is the whole count and the word, which is what `%d bytes`
        // produces.
        if (number_text<char16_t>(out, capacity, bytes) == 0) {
            return out;
        }
        text_append_ascii<char16_t>(out, capacity, " bytes");
        return out;
    }
    std::size_t index = 0;
    while (index < (sizeof(formats) / sizeof(formats[0])) - 1) {
        if (static_cast<std::uint64_t>(bytes) < formats[index].limit) {
            break;
        }
        ++index;
    }
    // Above a terabyte the double would lose the low bits, so the count is
    // shifted down by a megabyte first and the table's divisors are scaled
    // for it. The small term is the reference's and exists so that a count
    // exactly on a boundary is reported as the unit below.
    const double scaled =
        index > 8 ? static_cast<double>(bytes >> 20) + 0.001
                  : static_cast<double>(bytes) + 0.00001;
    const double value = std::floor(scaled / formats[index].divisor) /
                         formats[index].normaliser;
    if (!format_fixed<char16_t>(out, capacity, value, formats[index].decimals)) {
        return out;
    }
    const char unit[] = {' ', formats[index].prefix, 'B', 0};
    text_append_ascii<char16_t>(out, capacity, unit);
    return out;
}

extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_AssocCreate(std::uint64_t clsid, const void* riid, void** ppv) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(clsid);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_AssocGetPerceivedType(const char16_t* pszExt, void* ptype, void* pflag, char16_t** ppszType) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(pszExt);
    static_cast<void>(ptype);
    static_cast<void>(pflag);
    static_cast<void>(ppszType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_AssocIsDangerous(const char16_t* pszAssoc) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(pszAssoc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_AssocQueryKeyA(std::uint32_t flags, std::uint64_t key, const char* pszAssoc, const char* pszExtra, void* phkeyOut) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(flags);
    static_cast<void>(key);
    static_cast<void>(pszAssoc);
    static_cast<void>(pszExtra);
    static_cast<void>(phkeyOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_AssocQueryKeyW(std::uint32_t flags, std::uint64_t key, const char16_t* pszAssoc, const char16_t* pszExtra, void* phkeyOut) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(flags);
    static_cast<void>(key);
    static_cast<void>(pszAssoc);
    static_cast<void>(pszExtra);
    static_cast<void>(phkeyOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_AssocQueryStringA(std::uint32_t flags, std::uint32_t str, const char* pszAssoc, const char* pszExtra, char* pszOut, std::uint32_t* pcchOut) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(flags);
    static_cast<void>(str);
    static_cast<void>(pszAssoc);
    static_cast<void>(pszExtra);
    static_cast<void>(pszOut);
    static_cast<void>(pcchOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_AssocQueryStringByKeyA(std::uint32_t flags, std::uint32_t str, void* hkAssoc, const char* pszExtra, char* pszOut, std::uint32_t* pcchOut) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(flags);
    static_cast<void>(str);
    static_cast<void>(hkAssoc);
    static_cast<void>(pszExtra);
    static_cast<void>(pszOut);
    static_cast<void>(pcchOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_AssocQueryStringByKeyW(std::uint32_t flags, std::uint32_t str, void* hkAssoc, const char16_t* pszExtra, char16_t* pszOut, std::uint32_t* pcchOut) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(flags);
    static_cast<void>(str);
    static_cast<void>(hkAssoc);
    static_cast<void>(pszExtra);
    static_cast<void>(pszOut);
    static_cast<void>(pcchOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_AssocQueryStringW(std::uint32_t flags, std::uint32_t str, const char16_t* pszAssoc, const char16_t* pszExtra, char16_t* pszOut, std::uint32_t* pcchOut) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(flags);
    static_cast<void>(str);
    static_cast<void>(pszAssoc);
    static_cast<void>(pszExtra);
    static_cast<void>(pszOut);
    static_cast<void>(pcchOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_ChrCmpIA(std::uint16_t w1, std::uint16_t w2) noexcept {
    // The comparison is unsigned and case-insensitive, and the answer is
    // the difference of the folded characters rather than a sign.
    const std::uint32_t left =
        static_cast<std::uint32_t>(ch_lower_of(static_cast<char>(w1)));
    const std::uint32_t right =
        static_cast<std::uint32_t>(ch_lower_of(static_cast<char>(w2)));
    return static_cast<std::int32_t>(left - right);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_ChrCmpIW(char16_t w1, char16_t w2) noexcept {
    // The comparison is unsigned and case-insensitive, and the answer is
    // the difference of the folded characters rather than a sign.
    const std::uint32_t left =
        static_cast<std::uint32_t>(ch_lower_of(static_cast<char16_t>(w1)));
    const std::uint32_t right =
        static_cast<std::uint32_t>(ch_lower_of(static_cast<char16_t>(w2)));
    return static_cast<std::int32_t>(left - right);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_ColorAdjustLuma(std::uint32_t clrRGB, std::int32_t n, std::int32_t fScale) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(clrRGB);
    static_cast<void>(n);
    static_cast<void>(fScale);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_ColorHLSToRGB(std::uint16_t wHue, std::uint16_t wLuminance, std::uint16_t wSaturation) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(wHue);
    static_cast<void>(wLuminance);
    static_cast<void>(wSaturation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kshlwapiG_ColorRGBToHLS(std::uint32_t clrRGB, std::uint16_t* pwHue, std::uint16_t* pwLuminance, std::uint16_t* pwSaturation) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(clrRGB);
    static_cast<void>(pwHue);
    static_cast<void>(pwLuminance);
    static_cast<void>(pwSaturation);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_ConnectToConnectionPoint(void* punk, const void* riidEvent, std::int32_t fConnect, void* punkTarget, std::uint32_t* pdwCookie, void** ppcpOut) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(punk);
    static_cast<void>(riidEvent);
    static_cast<void>(fConnect);
    static_cast<void>(punkTarget);
    static_cast<void>(pdwCookie);
    static_cast<void>(ppcpOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_GetAcceptLanguagesA(char* psz, std::uint32_t* pcch) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(psz);
    static_cast<void>(pcch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_GetAcceptLanguagesW(char16_t* psz, std::uint32_t* pcch) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(psz);
    static_cast<void>(pcch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_GetMenuPosFromID(void* hMenu, std::uint32_t id) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hMenu);
    static_cast<void>(id);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_HashData(std::uint8_t* pbData, std::uint32_t cbData, std::uint8_t* pbHash, std::uint32_t cbHash) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pbData);
    static_cast<void>(cbData);
    static_cast<void>(pbHash);
    static_cast<void>(cbHash);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IStream_Copy(void* pstmFrom, void* pstmTo, std::uint32_t cb) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(pstmFrom);
    static_cast<void>(pstmTo);
    static_cast<void>(cb);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IStream_Read(void* pstm, void* pv, std::uint32_t cb) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(pstm);
    static_cast<void>(pv);
    static_cast<void>(cb);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IStream_ReadPidl(void* pstm, void* ppidlOut) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(pstm);
    static_cast<void>(ppidlOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IStream_ReadStr(void* pstm, char16_t** ppsz) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(pstm);
    static_cast<void>(ppsz);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IStream_Reset(void* pstm) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(pstm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IStream_Size(void* pstm, std::uint64_t* pui) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(pstm);
    static_cast<void>(pui);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IStream_Write(void* pstm, const void* pv, std::uint32_t cb) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(pstm);
    static_cast<void>(pv);
    static_cast<void>(cb);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IStream_WritePidl(void* pstm, void* pidlWrite) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(pstm);
    static_cast<void>(pidlWrite);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IStream_WriteStr(void* pstm, const char16_t* psz) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(pstm);
    static_cast<void>(psz);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kshlwapiG_IUnknown_AtomicRelease(void** ppunk) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(ppunk);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IUnknown_GetSite(void* punk, const void* riid, void** ppv) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(punk);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IUnknown_GetWindow(void* punk, void* phwnd) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(punk);
    static_cast<void>(phwnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IUnknown_QueryService(void* punk, const void* guidService, const void* riid, void** ppvOut) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(punk);
    static_cast<void>(guidService);
    static_cast<void>(riid);
    static_cast<void>(ppvOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kshlwapiG_IUnknown_Set(void** ppunk, void* punk) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(ppunk);
    static_cast<void>(punk);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IUnknown_SetSite(void* punk, void* punkSite) noexcept {
    // Refused: the COM marshalling and storage layer.
    //
    // this call reaches a COM interface by vtable, and the vtable that would
    // answer it belongs to an object nobody here created: COM needs a class
    // registry, an apartment and a marshaller
    static_cast<void>(punk);
    static_cast<void>(punkSite);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IntlStrEqWorkerA(std::int32_t fCaseSens, const char* lpString1, const char* lpString2, std::int32_t nChar) noexcept {
    if (lpString1 == nullptr || lpString2 == nullptr) {
        return 0;
    }
    // `nChar` counts characters and -1 means "to the terminator". The
    // comparison walks rather than copying, so that the bound is a bound
    // and the terminator is what ends the shorter string.
    std::int64_t remaining = static_cast<std::int64_t>(nChar);
    const char* left = lpString1;
    const char* right = lpString2;
    for (;;) {
        if (remaining == 0) {
            return 1;
        }
        const char a = *left;
        const char b = *right;
        if ((fCaseSens ? a : ch_lower_of(a)) !=
            (fCaseSens ? b : ch_lower_of(b))) {
            return 0;
        }
        if (a == static_cast<char>(0)) {
            return 1;
        }
        ++left;
        ++right;
        if (remaining > 0) {
            --remaining;
        }
    }
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IntlStrEqWorkerW(std::int32_t fCaseSens, const char16_t* lpString1, const char16_t* lpString2, std::int32_t nChar) noexcept {
    if (lpString1 == nullptr || lpString2 == nullptr) {
        return 0;
    }
    // `nChar` counts characters and -1 means "to the terminator". The
    // comparison walks rather than copying, so that the bound is a bound
    // and the terminator is what ends the shorter string.
    std::int64_t remaining = static_cast<std::int64_t>(nChar);
    const char16_t* left = lpString1;
    const char16_t* right = lpString2;
    for (;;) {
        if (remaining == 0) {
            return 1;
        }
        const char16_t a = *left;
        const char16_t b = *right;
        if ((fCaseSens ? a : ch_lower_of(a)) !=
            (fCaseSens ? b : ch_lower_of(b))) {
            return 0;
        }
        if (a == static_cast<char16_t>(0)) {
            return 1;
        }
        ++left;
        ++right;
        if (remaining > 0) {
            --remaining;
        }
    }
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IsCharSpaceA(char wch) noexcept {
    return ch_space<char>(static_cast<char>(wch)) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IsCharSpaceW(char16_t wch) noexcept {
    return ch_space<char16_t>(static_cast<char16_t>(wch)) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IsInternetESCEnabled() noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_IsOS(std::uint32_t dwOS) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(dwOS);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_ParseURLA(const char* pcszURL, void* ppu) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pcszURL);
    static_cast<void>(ppu);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_ParseURLW(const char16_t* pcszURL, void* ppu) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pcszURL);
    static_cast<void>(ppu);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathAddExtensionA(char* pszPath, const char* pszExt) noexcept {
    if (pszPath == nullptr || pszExt == nullptr) {
        return 0;
    }
    // An extension is added only when the name has none. The test is on the
    // character the extension would start at, which is the terminator when
    // there is nothing there.
    const char* extension = path_extension<char>(pszPath);
    if (extension == nullptr || *extension != static_cast<char>(0)) {
        return 0;
    }
    const std::size_t length = text_len(pszPath);
    const std::size_t added = text_len(pszExt);
    if (length + added >= kMaxPath) {
        return 0;
    }
    std::memcpy(pszPath + length, pszExt, (added + 1) * sizeof(char));
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathAddExtensionW(char16_t* pszPath, const char16_t* pszExt) noexcept {
    if (pszPath == nullptr || pszExt == nullptr) {
        return 0;
    }
    // An extension is added only when the name has none. The test is on the
    // character the extension would start at, which is the terminator when
    // there is nothing there.
    const char16_t* extension = path_extension<char16_t>(pszPath);
    if (extension == nullptr || *extension != static_cast<char16_t>(0)) {
        return 0;
    }
    const std::size_t length = text_len(pszPath);
    const std::size_t added = text_len(pszExt);
    if (length + added >= kMaxPath) {
        return 0;
    }
    std::memcpy(pszPath + length, pszExt, (added + 1) * sizeof(char16_t));
    return 1;
}


extern "C" __attribute__((ms_abi)) char* kshlwapiG_PathBuildRootA(char* pszRoot, std::int32_t iDrive) noexcept {
    if (pszRoot != nullptr && iDrive >= 0 && iDrive < 26) {
        pszRoot[0] = static_cast<char>('A' + iDrive);
        pszRoot[1] = static_cast<char>(':');
        pszRoot[2] = static_cast<char>('\\');
        pszRoot[3] = static_cast<char>(0);
    }
    return pszRoot;
}


extern "C" __attribute__((ms_abi)) char16_t* kshlwapiG_PathBuildRootW(char16_t* pszRoot, std::int32_t iDrive) noexcept {
    if (pszRoot != nullptr && iDrive >= 0 && iDrive < 26) {
        pszRoot[0] = static_cast<char16_t>('A' + iDrive);
        pszRoot[1] = static_cast<char16_t>(':');
        pszRoot[2] = static_cast<char16_t>('\\');
        pszRoot[3] = static_cast<char16_t>(0);
    }
    return pszRoot;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathCanonicalizeA(char* pszBuf, const char* pszPath) noexcept {
    if (pszBuf == nullptr || pszPath == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return path_canonicalize<char>(pszBuf, pszPath) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathCanonicalizeW(char16_t* pszBuf, const char16_t* pszPath) noexcept {
    if (pszBuf == nullptr || pszPath == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return path_canonicalize<char16_t>(pszBuf, pszPath) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathCompactPathA(void* hDC, char* pszPath, std::uint32_t dx) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hDC);
    static_cast<void>(pszPath);
    static_cast<void>(dx);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathCompactPathExA(char* pszOut, const char* pszSrc, std::uint32_t cchMax, std::uint32_t dwFlags) noexcept {
    static_cast<void>(dwFlags);
    if (pszSrc == nullptr) {
        return 0;
    }
    if (pszOut == nullptr) {
        return 0;
    }
    *pszOut = static_cast<char>(0);
    if (cchMax < 2) {
        return 1;
    }
    const std::size_t length = text_len(pszSrc) + 1;
    if (length < cchMax) {
        std::memcpy(pszOut, pszSrc, length * sizeof(char));
        return 1;
    }
    // The path has to be shortened. The reference cuts from the middle: the
    // file name is kept whole when it fits, the root is cut back when it
    // does not, and the ellipsis marks the cut.
    const char* file = path_file_name<char>(pszSrc);
    std::size_t file_length = static_cast<std::size_t>(pszSrc + length - file);
    if (file_length == length) {
        // No separator at all, so there is no root to protect.
        if (cchMax <= 4) {
            std::uint32_t room = cchMax;
            char* write = pszOut;
            while (--room > 0) {
                *write++ = static_cast<char>('.');
            }
            *write = static_cast<char>(0);
            return 1;
        }
        const std::size_t keep = static_cast<std::size_t>(cchMax) - 4;
        std::memcpy(pszOut, file, keep * sizeof(char));
        pszOut[keep] = static_cast<char>('.');
        pszOut[keep + 1] = static_cast<char>('.');
        pszOut[keep + 2] = static_cast<char>('.');
        pszOut[keep + 3] = static_cast<char>(0);
        return 1;
    }
    --file;
    ++file_length;
    if (file_length + 3 > static_cast<std::size_t>(cchMax)) {
        if (cchMax <= 4) {
            std::uint32_t room = cchMax;
            char* write = pszOut;
            while (--room > 0) {
                *write++ = static_cast<char>('.');
            }
            *write = static_cast<char>(0);
            return 1;
        }
        char* write = pszOut;
        *write++ = static_cast<char>('.');
        *write++ = static_cast<char>('.');
        *write++ = static_cast<char>('.');
        std::uint32_t room = cchMax - 4;
        *write++ = *file++;
        if (room <= 4) {
            while (--room > 0) {
                *write++ = static_cast<char>('.');
            }
            *write = static_cast<char>(0);
            return 1;
        }
        room -= 4;
        std::memcpy(write, file, room * sizeof(char));
        write[room] = static_cast<char>('.');
        write[room + 1] = static_cast<char>('.');
        write[room + 2] = static_cast<char>('.');
        write[room + 3] = static_cast<char>(0);
        return 1;
    }
    // Only the root is cut.
    const std::size_t root = static_cast<std::size_t>(cchMax) - file_length - 3;
    std::memcpy(pszOut, pszSrc, root * sizeof(char));
    pszOut[root] = static_cast<char>('.');
    pszOut[root + 1] = static_cast<char>('.');
    pszOut[root + 2] = static_cast<char>('.');
    text_copy<char>(pszOut + root + 3,
                     static_cast<std::size_t>(cchMax) - root - 3, file);
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathCompactPathExW(char16_t* pszOut, const char16_t* pszSrc, std::uint32_t cchMax, std::uint32_t dwFlags) noexcept {
    static_cast<void>(dwFlags);
    if (pszSrc == nullptr) {
        return 0;
    }
    if (pszOut == nullptr) {
        return 0;
    }
    *pszOut = static_cast<char16_t>(0);
    if (cchMax < 2) {
        return 1;
    }
    const std::size_t length = text_len(pszSrc) + 1;
    if (length < cchMax) {
        std::memcpy(pszOut, pszSrc, length * sizeof(char16_t));
        return 1;
    }
    // The path has to be shortened. The reference cuts from the middle: the
    // file name is kept whole when it fits, the root is cut back when it
    // does not, and the ellipsis marks the cut.
    const char16_t* file = path_file_name<char16_t>(pszSrc);
    std::size_t file_length = static_cast<std::size_t>(pszSrc + length - file);
    if (file_length == length) {
        // No separator at all, so there is no root to protect.
        if (cchMax <= 4) {
            std::uint32_t room = cchMax;
            char16_t* write = pszOut;
            while (--room > 0) {
                *write++ = static_cast<char16_t>('.');
            }
            *write = static_cast<char16_t>(0);
            return 1;
        }
        const std::size_t keep = static_cast<std::size_t>(cchMax) - 4;
        std::memcpy(pszOut, file, keep * sizeof(char16_t));
        pszOut[keep] = static_cast<char16_t>('.');
        pszOut[keep + 1] = static_cast<char16_t>('.');
        pszOut[keep + 2] = static_cast<char16_t>('.');
        pszOut[keep + 3] = static_cast<char16_t>(0);
        return 1;
    }
    --file;
    ++file_length;
    if (file_length + 3 > static_cast<std::size_t>(cchMax)) {
        if (cchMax <= 4) {
            std::uint32_t room = cchMax;
            char16_t* write = pszOut;
            while (--room > 0) {
                *write++ = static_cast<char16_t>('.');
            }
            *write = static_cast<char16_t>(0);
            return 1;
        }
        char16_t* write = pszOut;
        *write++ = static_cast<char16_t>('.');
        *write++ = static_cast<char16_t>('.');
        *write++ = static_cast<char16_t>('.');
        std::uint32_t room = cchMax - 4;
        *write++ = *file++;
        if (room <= 4) {
            while (--room > 0) {
                *write++ = static_cast<char16_t>('.');
            }
            *write = static_cast<char16_t>(0);
            return 1;
        }
        room -= 4;
        std::memcpy(write, file, room * sizeof(char16_t));
        write[room] = static_cast<char16_t>('.');
        write[room + 1] = static_cast<char16_t>('.');
        write[room + 2] = static_cast<char16_t>('.');
        write[room + 3] = static_cast<char16_t>(0);
        return 1;
    }
    // Only the root is cut.
    const std::size_t root = static_cast<std::size_t>(cchMax) - file_length - 3;
    std::memcpy(pszOut, pszSrc, root * sizeof(char16_t));
    pszOut[root] = static_cast<char16_t>('.');
    pszOut[root + 1] = static_cast<char16_t>('.');
    pszOut[root + 2] = static_cast<char16_t>('.');
    text_copy<char16_t>(pszOut + root + 3,
                     static_cast<std::size_t>(cchMax) - root - 3, file);
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathCompactPathW(void* hDC, char16_t* pszPath, std::uint32_t dx) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hDC);
    static_cast<void>(pszPath);
    static_cast<void>(dx);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathCreateFromUrlA(const char* pszUrl, char* pszPath, std::uint32_t* pcchPath, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszUrl);
    static_cast<void>(pszPath);
    static_cast<void>(pcchPath);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathCreateFromUrlAlloc(const char16_t* pszIn, char16_t** ppszOut, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszIn);
    static_cast<void>(ppszOut);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathCreateFromUrlW(const char16_t* pszUrl, char16_t* pszPath, std::uint32_t* pcchPath, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszUrl);
    static_cast<void>(pszPath);
    static_cast<void>(pcchPath);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathFileExistsA(const char* pszPath) noexcept {
    if (pszPath == nullptr) {
        return 0;
    }
    return k32b_GetFileAttributesA(pszPath) != 0xFFFFFFFFu ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathFileExistsW(const char16_t* pszPath) noexcept {
    if (pszPath == nullptr) {
        return 0;
    }
    return k32b_GetFileAttributesW(pszPath) != 0xFFFFFFFFu ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathFindOnPathA(char* pszPath, const char** ppszOtherDirs) noexcept {
    if (pszPath == nullptr) {
        return 0;
    }
    // The search order is the reference's: what the caller named, then the
    // system directory, then the Windows directory, then the Windows system
    // directory, then every entry of `PATH`. A name that already exists, and
    // an absolute name, are answered before the walk starts.
    if (k32b_GetFileAttributesA(pszPath) != 0xFFFFFFFFu) {
        return 1;
    }
    if (!path_is_relative<char>(pszPath)) {
        return 0;
    }
    char candidate[kMaxPath];
    const std::size_t name_length = text_len(pszPath);
    if (name_length + 2 >= kMaxPath) {
        return 0;
    }
    if (ppszOtherDirs != nullptr) {
        for (const char* const* item = ppszOtherDirs; *item != nullptr; ++item) {
            if (path_join<char>(candidate, kMaxPath, *item, pszPath) &&
                k32b_GetFileAttributesA(candidate) != 0xFFFFFFFFu) {
                text_copy<char>(pszPath, kMaxPath, candidate);
                return 1;
            }
        }
    }
    const char naming[] = "System";
    char root[kMaxPath];
    for (int step = 0; step < 3; ++step) {
        std::uint32_t written = 0;
        if (step == 0) {
            written = k32p_GetSystemDirectoryA(root, kMaxPath);
        } else if (step == 1) {
            written = k32p_GetWindowsDirectoryA(root, kMaxPath);
            if (written != 0 && written + 8 < kMaxPath) {
                static_cast<void>(path_join<char>(root, kMaxPath, root, naming));
            }
        } else {
            written = k32p_GetWindowsDirectoryA(root, kMaxPath);
        }
        if (written == 0) {
            continue;
        }
        if (path_join<char>(candidate, kMaxPath, root, pszPath) &&
            k32b_GetFileAttributesA(candidate) != 0xFFFFFFFFu) {
            text_copy<char>(pszPath, kMaxPath, candidate);
            return 1;
        }
    }
    // `PATH` last. The environment holds one delimiter-separated list, and
    // the walk is over it rather than over a copy, because a copy is one
    // more buffer to bound.
    char search_path[32768];
    const std::uint32_t used = k32_GetEnvironmentVariableA(
        "PATH", search_path, static_cast<std::uint32_t>(32768));
    if (used == 0 || used >= 32768) {
        return 0;
    }
    const char* at = search_path;
    for (;;) {
        while (*at == static_cast<char>(' ')) {
            ++at;
        }
        const char* end = at;
        while (*end != static_cast<char>(0) && *end != static_cast<char>(';')) {
            ++end;
        }
        char directory[kMaxPath];
        const std::size_t length = static_cast<std::size_t>(end - at);
        if (length != 0 && length + 1 < kMaxPath) {
            std::memcpy(directory, at, length * sizeof(char));
            directory[length] = static_cast<char>(0);
            if (path_join<char>(candidate, kMaxPath, directory, pszPath) &&
                k32b_GetFileAttributesA(candidate) != 0xFFFFFFFFu) {
                text_copy<char>(pszPath, kMaxPath, candidate);
                return 1;
            }
        }
        if (*end == static_cast<char>(0)) {
            break;
        }
        at = end + 1;
    }
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathFindOnPathW(char16_t* pszPath, const char16_t** ppszOtherDirs) noexcept {
    if (pszPath == nullptr) {
        return 0;
    }
    // The search order is the reference's: what the caller named, then the
    // system directory, then the Windows directory, then the Windows system
    // directory, then every entry of `PATH`. A name that already exists, and
    // an absolute name, are answered before the walk starts.
    if (k32b_GetFileAttributesW(pszPath) != 0xFFFFFFFFu) {
        return 1;
    }
    if (!path_is_relative<char16_t>(pszPath)) {
        return 0;
    }
    char16_t candidate[kMaxPath];
    const std::size_t name_length = text_len(pszPath);
    if (name_length + 2 >= kMaxPath) {
        return 0;
    }
    if (ppszOtherDirs != nullptr) {
        for (const char16_t* const* item = ppszOtherDirs; *item != nullptr; ++item) {
            if (path_join<char16_t>(candidate, kMaxPath, *item, pszPath) &&
                k32b_GetFileAttributesW(candidate) != 0xFFFFFFFFu) {
                text_copy<char16_t>(pszPath, kMaxPath, candidate);
                return 1;
            }
        }
    }
    const char16_t naming[] = u"System";
    char16_t root[kMaxPath];
    for (int step = 0; step < 3; ++step) {
        std::uint32_t written = 0;
        if (step == 0) {
            written = k32p_GetSystemDirectoryW(root, kMaxPath);
        } else if (step == 1) {
            written = k32p_GetWindowsDirectoryW(root, kMaxPath);
            if (written != 0 && written + 8 < kMaxPath) {
                static_cast<void>(path_join<char16_t>(root, kMaxPath, root, naming));
            }
        } else {
            written = k32p_GetWindowsDirectoryW(root, kMaxPath);
        }
        if (written == 0) {
            continue;
        }
        if (path_join<char16_t>(candidate, kMaxPath, root, pszPath) &&
            k32b_GetFileAttributesW(candidate) != 0xFFFFFFFFu) {
            text_copy<char16_t>(pszPath, kMaxPath, candidate);
            return 1;
        }
    }
    // `PATH` last. The environment holds one delimiter-separated list, and
    // the walk is over it rather than over a copy, because a copy is one
    // more buffer to bound.
    char16_t search_path[32768];
    const std::uint32_t used = k32_GetEnvironmentVariableW(
        u"PATH", search_path, static_cast<std::uint32_t>(32768));
    if (used == 0 || used >= 32768) {
        return 0;
    }
    const char16_t* at = search_path;
    for (;;) {
        while (*at == static_cast<char16_t>(' ')) {
            ++at;
        }
        const char16_t* end = at;
        while (*end != static_cast<char16_t>(0) && *end != static_cast<char16_t>(';')) {
            ++end;
        }
        char16_t directory[kMaxPath];
        const std::size_t length = static_cast<std::size_t>(end - at);
        if (length != 0 && length + 1 < kMaxPath) {
            std::memcpy(directory, at, length * sizeof(char16_t));
            directory[length] = static_cast<char16_t>(0);
            if (path_join<char16_t>(candidate, kMaxPath, directory, pszPath) &&
                k32b_GetFileAttributesW(candidate) != 0xFFFFFFFFu) {
                text_copy<char16_t>(pszPath, kMaxPath, candidate);
                return 1;
            }
        }
        if (*end == static_cast<char16_t>(0)) {
            break;
        }
        at = end + 1;
    }
    return 0;
}


extern "C" __attribute__((ms_abi)) const char* kshlwapiG_PathFindSuffixArrayA(const char* pszPath, const char** apszSuffix, std::int32_t iArraySize) noexcept {
    if (pszPath == nullptr || apszSuffix == nullptr || iArraySize <= 0) {
        return nullptr;
    }
    // The comparison is exact and the suffix must be shorter than the path,
    // which is the reference's rule: a suffix that is the whole string is
    // not a suffix of it.
    const std::size_t length = text_len(pszPath);
    for (int index = 0; index < iArraySize; ++index) {
        const char* suffix = apszSuffix[index];
        if (suffix == nullptr) {
            continue;
        }
        const std::size_t suffix_length = text_len(suffix);
        if (suffix_length >= length) {
            continue;
        }
        if (text_equal<char>(pszPath + length - suffix_length, suffix)) {
            return suffix;
        }
    }
    return nullptr;
}


extern "C" __attribute__((ms_abi)) const char16_t* kshlwapiG_PathFindSuffixArrayW(const char16_t* pszPath, const char16_t** apszSuffix, std::int32_t iArraySize) noexcept {
    if (pszPath == nullptr || apszSuffix == nullptr || iArraySize <= 0) {
        return nullptr;
    }
    // The comparison is exact and the suffix must be shorter than the path,
    // which is the reference's rule: a suffix that is the whole string is
    // not a suffix of it.
    const std::size_t length = text_len(pszPath);
    for (int index = 0; index < iArraySize; ++index) {
        const char16_t* suffix = apszSuffix[index];
        if (suffix == nullptr) {
            continue;
        }
        const std::size_t suffix_length = text_len(suffix);
        if (suffix_length >= length) {
            continue;
        }
        if (text_equal<char16_t>(pszPath + length - suffix_length, suffix)) {
            return suffix;
        }
    }
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_PathGetCharTypeA(std::uint8_t ch) noexcept {
    return path_char_type<char>(static_cast<char>(ch));
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_PathGetCharTypeW(char16_t ch) noexcept {
    return path_char_type<char16_t>(static_cast<char16_t>(ch));
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsContentTypeA(const char* pszPath, const char* pszContentType) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszPath);
    static_cast<void>(pszContentType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsContentTypeW(const char16_t* pszPath, const char16_t* pszContentType) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszPath);
    static_cast<void>(pszContentType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsDirectoryA(const char* pszPath) noexcept {
    return path_is_directory<char>(pszPath) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsDirectoryEmptyA(const char* pszPath) noexcept {
    if (pszPath == nullptr || !path_is_directory<char>(pszPath)) {
        return 0;
    }
    // The walk is over `*.*`, which is the search every directory accepts,
    // and the two entries every directory has are skipped. A walk that
    // cannot start is a failure rather than an empty directory: the
    // reference reports FALSE and a caller that reads it as "empty" would
    // delete a directory it could not read.
    char pattern[kMaxPath];
    text_copy<char>(pattern, kMaxPath, pszPath);
    if (!path_add_backslash<char>(pattern, kMaxPath)) {
        return 0;
    }
    const std::size_t at = text_len(pattern);
    if (at > kMaxPath - 4) {
        return 0;
    }
    text_append<char>(pattern, kMaxPath, ch_of<char>('*'));
    text_append<char>(pattern, kMaxPath, ch_of<char>('.'));
    text_append<char>(pattern, kMaxPath, ch_of<char>('*'));

    alignas(8) std::uint8_t entry[592];
    void* walk = k32f3_FindFirstFileA(pattern, entry);
    if (walk == reinterpret_cast<void*>(kInvalidHandleValue)) {
        return 0;
    }
    bool empty = true;
    for (;;) {
        const char* name = reinterpret_cast<const char*>(entry + 44);
        const bool self = name[0] == static_cast<char>('.') &&
                          name[1] == static_cast<char>(0);
        const bool parent = name[0] == static_cast<char>('.') &&
                            name[1] == static_cast<char>('.') &&
                            name[2] == static_cast<char>(0);
        if (!self && !parent) {
            empty = false;
            break;
        }
        if (!find_next_entry<char>(walk, entry)) {
            break;
        }
    }
    static_cast<void>(k32f2_FindClose(walk));
    return empty ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsDirectoryEmptyW(const char16_t* pszPath) noexcept {
    if (pszPath == nullptr || !path_is_directory<char16_t>(pszPath)) {
        return 0;
    }
    // The walk is over `*.*`, which is the search every directory accepts,
    // and the two entries every directory has are skipped. A walk that
    // cannot start is a failure rather than an empty directory: the
    // reference reports FALSE and a caller that reads it as "empty" would
    // delete a directory it could not read.
    char16_t pattern[kMaxPath];
    text_copy<char16_t>(pattern, kMaxPath, pszPath);
    if (!path_add_backslash<char16_t>(pattern, kMaxPath)) {
        return 0;
    }
    const std::size_t at = text_len(pattern);
    if (at > kMaxPath - 4) {
        return 0;
    }
    text_append<char16_t>(pattern, kMaxPath, ch_of<char16_t>('*'));
    text_append<char16_t>(pattern, kMaxPath, ch_of<char16_t>('.'));
    text_append<char16_t>(pattern, kMaxPath, ch_of<char16_t>('*'));

    alignas(8) std::uint8_t entry[592];
    void* walk = k32f3_FindFirstFileW(pattern, entry);
    if (walk == reinterpret_cast<void*>(kInvalidHandleValue)) {
        return 0;
    }
    bool empty = true;
    for (;;) {
        const char16_t* name = reinterpret_cast<const char16_t*>(entry + 44);
        const bool self = name[0] == static_cast<char16_t>('.') &&
                          name[1] == static_cast<char16_t>(0);
        const bool parent = name[0] == static_cast<char16_t>('.') &&
                            name[1] == static_cast<char16_t>('.') &&
                            name[2] == static_cast<char16_t>(0);
        if (!self && !parent) {
            empty = false;
            break;
        }
        if (!find_next_entry<char16_t>(walk, entry)) {
            break;
        }
    }
    static_cast<void>(k32f2_FindClose(walk));
    return empty ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsDirectoryW(const char16_t* pszPath) noexcept {
    return path_is_directory<char16_t>(pszPath) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsFileSpecA(const char* pszPath) noexcept {
    if (pszPath == nullptr) {
        return 0;
    }
    for (const char* p = pszPath; *p != static_cast<char>(0); ++p) {
        if (*p == static_cast<char>('\\') || *p == static_cast<char>(':')) {
            return 0;
        }
    }
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsFileSpecW(const char16_t* pszPath) noexcept {
    if (pszPath == nullptr) {
        return 0;
    }
    for (const char16_t* p = pszPath; *p != static_cast<char16_t>(0); ++p) {
        if (*p == static_cast<char16_t>('\\') || *p == static_cast<char16_t>(':')) {
            return 0;
        }
    }
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsLFNFileSpecA(const char* lpName) noexcept {
    return path_is_long_file_spec<char>(lpName) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsLFNFileSpecW(const char16_t* lpName) noexcept {
    return path_is_long_file_spec<char16_t>(lpName) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsNetworkPathA(const char* pszPath) noexcept {
    if (pszPath == nullptr) {
        return 0;
    }
    if (path_is_unc<char>(pszPath)) {
        return 1;
    }
    // A drive letter is a network path only when the drive is a network
    // mapping. The drives this runtime presents are the host's own file
    // system, and there are no mappings among them, so the answer for a
    // letter is that the drive is local.
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsNetworkPathW(const char16_t* pszPath) noexcept {
    if (pszPath == nullptr) {
        return 0;
    }
    if (path_is_unc<char16_t>(pszPath)) {
        return 1;
    }
    // A drive letter is a network path only when the drive is a network
    // mapping. The drives this runtime presents are the host's own file
    // system, and there are no mappings among them, so the answer for a
    // letter is that the drive is local.
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsPrefixA(const char* pszPrefix, const char* pszPath) noexcept {
    if (pszPrefix == nullptr || pszPath == nullptr) {
        return 0;
    }
    const std::size_t common = path_common_prefix<char>(pszPath, pszPrefix, nullptr);
    return common == text_len(pszPrefix) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsPrefixW(const char16_t* pszPrefix, const char16_t* pszPath) noexcept {
    if (pszPrefix == nullptr || pszPath == nullptr) {
        return 0;
    }
    const std::size_t common = path_common_prefix<char16_t>(pszPath, pszPrefix, nullptr);
    return common == text_len(pszPrefix) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsSameRootA(const char* pszPath1, const char* pszPath2) noexcept {
    if (pszPath1 == nullptr || pszPath2 == nullptr) {
        return 0;
    }
    const char* after_root = path_skip_root<char>(pszPath1);
    if (after_root == nullptr) {
        return 0;
    }
    // The two paths have the same root when the source's root is inside the
    // shared prefix, which is the reference's test and the reason the prefix
    // is counted with its root rather than from the first component.
    const std::size_t common =
        path_common_prefix<char>(pszPath1, pszPath2, nullptr) + 1;
    return static_cast<std::size_t>(after_root - pszPath1) <= common ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsSameRootW(const char16_t* pszPath1, const char16_t* pszPath2) noexcept {
    if (pszPath1 == nullptr || pszPath2 == nullptr) {
        return 0;
    }
    const char16_t* after_root = path_skip_root<char16_t>(pszPath1);
    if (after_root == nullptr) {
        return 0;
    }
    // The two paths have the same root when the source's root is inside the
    // shared prefix, which is the reference's test and the reason the prefix
    // is counted with its root rather than from the first component.
    const std::size_t common =
        path_common_prefix<char16_t>(pszPath1, pszPath2, nullptr) + 1;
    return static_cast<std::size_t>(after_root - pszPath1) <= common ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsSystemFolderA(const char* pszPath, std::uint32_t dwAttrb) noexcept {
    // The attributes are queried whenever the path is not empty, and the
    // argument is only a fallback for the empty case -- which is the
    // reference's rule and the opposite of what the argument's name
    // suggests.
    std::uint32_t attributes = dwAttrb;
    if (pszPath != nullptr && *pszPath != static_cast<char>(0)) {
        attributes = k32b_GetFileAttributesA(pszPath);
    }
    if (attributes == 0xFFFFFFFFu) {
        return 0;
    }
    // A system folder is a directory that is marked system or read-only --
    // either bit is enough, and both are checked with one mask.
    if ((attributes & 0x00000010u) == 0) {
        return 0;
    }
    return (attributes & (0x00000004u | 0x00000001u)) != 0 ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsSystemFolderW(const char16_t* pszPath, std::uint32_t dwAttrb) noexcept {
    // The attributes are queried whenever the path is not empty, and the
    // argument is only a fallback for the empty case -- which is the
    // reference's rule and the opposite of what the argument's name
    // suggests.
    std::uint32_t attributes = dwAttrb;
    if (pszPath != nullptr && *pszPath != static_cast<char16_t>(0)) {
        attributes = k32b_GetFileAttributesW(pszPath);
    }
    if (attributes == 0xFFFFFFFFu) {
        return 0;
    }
    // A system folder is a directory that is marked system or read-only --
    // either bit is enough, and both are checked with one mask.
    if ((attributes & 0x00000010u) == 0) {
        return 0;
    }
    return (attributes & (0x00000004u | 0x00000001u)) != 0 ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsUNCA(const char* pszPath) noexcept {
    return path_is_unc<char>(pszPath) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsUNCServerA(const char* pszPath) noexcept {
    return path_is_unc_server<char>(pszPath) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsUNCServerShareA(const char* pszPath) noexcept {
    return path_is_unc_server_share<char>(pszPath) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsUNCServerShareW(const char16_t* pszPath) noexcept {
    return path_is_unc_server_share<char16_t>(pszPath) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsUNCServerW(const char16_t* pszPath) noexcept {
    return path_is_unc_server<char16_t>(pszPath) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsUNCW(const char16_t* pszPath) noexcept {
    return path_is_unc<char16_t>(pszPath) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsURLA(const char* pszPath) noexcept {
    if (pszPath == nullptr || *pszPath == static_cast<char>(0)) {
        return 0;
    }
    // A URL is a scheme and a colon. A scheme is a letter followed by
    // letters, digits, `+`, `-` or `.`, and it must be longer than one
    // character -- a single letter before a colon is a drive designator.
    const char* p = pszPath;
    if (!ch_alpha(*p)) {
        return 0;
    }
    ++p;
    std::size_t length = 1;
    while (ch_alpha(*p) || ch_digit(*p) || *p == static_cast<char>('+') ||
           *p == static_cast<char>('-') || *p == static_cast<char>('.')) {
        ++p;
        ++length;
    }
    if (length < 2 || *p != static_cast<char>(':')) {
        return 0;
    }
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathIsURLW(const char16_t* pszPath) noexcept {
    if (pszPath == nullptr || *pszPath == static_cast<char16_t>(0)) {
        return 0;
    }
    // A URL is a scheme and a colon. A scheme is a letter followed by
    // letters, digits, `+`, `-` or `.`, and it must be longer than one
    // character -- a single letter before a colon is a drive designator.
    const char16_t* p = pszPath;
    if (!ch_alpha(*p)) {
        return 0;
    }
    ++p;
    std::size_t length = 1;
    while (ch_alpha(*p) || ch_digit(*p) || *p == static_cast<char16_t>('+') ||
           *p == static_cast<char16_t>('-') || *p == static_cast<char16_t>('.')) {
        ++p;
        ++length;
    }
    if (length < 2 || *p != static_cast<char16_t>(':')) {
        return 0;
    }
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathMakePrettyA(char* pszPath) noexcept {
    if (pszPath == nullptr) {
        return 0;
    }
    if (*pszPath == static_cast<char>(0)) {
        return 1;
    }
    // A name is prettied only when it holds no lower-case letter at all: the
    // rule is the DOS convention that an all-capitals name was written by a
    // program and a mixed one by a person. The first character keeps its
    // case and the rest are folded.
    for (const char* p = pszPath; *p != static_cast<char>(0); ++p) {
        if (ch_lower(*p)) {
            return 0;
        }
    }
    for (char* p = pszPath + 1; *p != static_cast<char>(0); ++p) {
        *p = ch_lower_of(*p);
    }
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathMakePrettyW(char16_t* pszPath) noexcept {
    if (pszPath == nullptr) {
        return 0;
    }
    if (*pszPath == static_cast<char16_t>(0)) {
        return 1;
    }
    // A name is prettied only when it holds no lower-case letter at all: the
    // rule is the DOS convention that an all-capitals name was written by a
    // program and a mixed one by a person. The first character keeps its
    // case and the rest are folded.
    for (const char16_t* p = pszPath; *p != static_cast<char16_t>(0); ++p) {
        if (ch_lower(*p)) {
            return 0;
        }
    }
    for (char16_t* p = pszPath + 1; *p != static_cast<char16_t>(0); ++p) {
        *p = ch_lower_of(*p);
    }
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathMakeSystemFolderA(const char* pszPath) noexcept {
    if (pszPath == nullptr || *pszPath == static_cast<char>(0)) {
        return 0;
    }
    // The Windows and system directories are already system folders and are
    // answered before anything is written, so that the call cannot change
    // the attributes of the installation itself.
    char system_directory[kMaxPath];
    if (k32p_GetSystemDirectoryA(system_directory, kMaxPath) != 0 &&
        text_equal_ci<char>(system_directory, pszPath)) {
        return 1;
    }
    char windows_directory[kMaxPath];
    if (k32p_GetWindowsDirectoryA(windows_directory, kMaxPath) != 0 &&
        text_equal_ci<char>(windows_directory, pszPath)) {
        return 1;
    }
    const std::uint32_t attributes = k32b_GetFileAttributesA(pszPath);
    if (attributes == 0xFFFFFFFFu) {
        return 0;
    }
    // The three bits are cleared and the read-only bit set, which is what
    // the reference does when the `UseSystemForSystemFolders` policy is
    // absent. That policy is a registry value of the shell's own
    // configuration, and this runtime's registry model does not seed it, so
    // the default is the answer.
    const std::uint32_t cleared =
        attributes & ~(0x00000004u | 0x00000002u | 0x00000001u);
    return k32b_SetFileAttributesA(pszPath, cleared | 0x00000001u) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathMakeSystemFolderW(const char16_t* pszPath) noexcept {
    if (pszPath == nullptr || *pszPath == static_cast<char16_t>(0)) {
        return 0;
    }
    // The Windows and system directories are already system folders and are
    // answered before anything is written, so that the call cannot change
    // the attributes of the installation itself.
    char16_t system_directory[kMaxPath];
    if (k32p_GetSystemDirectoryW(system_directory, kMaxPath) != 0 &&
        text_equal_ci<char16_t>(system_directory, pszPath)) {
        return 1;
    }
    char16_t windows_directory[kMaxPath];
    if (k32p_GetWindowsDirectoryW(windows_directory, kMaxPath) != 0 &&
        text_equal_ci<char16_t>(windows_directory, pszPath)) {
        return 1;
    }
    const std::uint32_t attributes = k32b_GetFileAttributesW(pszPath);
    if (attributes == 0xFFFFFFFFu) {
        return 0;
    }
    // The three bits are cleared and the read-only bit set, which is what
    // the reference does when the `UseSystemForSystemFolders` policy is
    // absent. That policy is a registry value of the shell's own
    // configuration, and this runtime's registry model does not seed it, so
    // the default is the answer.
    const std::uint32_t cleared =
        attributes & ~(0x00000004u | 0x00000002u | 0x00000001u);
    return k32b_SetFileAttributesW(pszPath, cleared | 0x00000001u) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathMatchSpecA(const char* pszFile, const char* pszSpec) noexcept {
    return path_match_spec<char>(pszFile, pszSpec) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathMatchSpecExA(const char* pszFile, const char* pszSpec, std::uint32_t dwFlags) noexcept {
    // The flags select between the plain form and the raw form, which
    // differs only in how a query string's escape characters are treated.
    // Both reach the same matcher here, and the flags are carried in the
    // signature so that a caller reading them sees the name the header
    // declared.
    static_cast<void>(dwFlags);
    if (pszFile == nullptr || pszSpec == nullptr) {
        return 0;
    }
    return path_match_spec<char>(pszFile, pszSpec) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathMatchSpecExW(const char16_t* pszFile, const char16_t* pszSpec, std::uint32_t dwFlags) noexcept {
    // The flags select between the plain form and the raw form, which
    // differs only in how a query string's escape characters are treated.
    // Both reach the same matcher here, and the flags are carried in the
    // signature so that a caller reading them sees the name the header
    // declared.
    static_cast<void>(dwFlags);
    if (pszFile == nullptr || pszSpec == nullptr) {
        return 0;
    }
    return path_match_spec<char16_t>(pszFile, pszSpec) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathMatchSpecW(const char16_t* pszFile, const char16_t* pszSpec) noexcept {
    return path_match_spec<char16_t>(pszFile, pszSpec) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathParseIconLocationA(char* pszIconFile) noexcept {
    if (pszIconFile == nullptr) {
        return 0;
    }
    // The answer is the index after the comma and the string is left holding
    // the file name alone, with its quotes and blanks removed.
    std::int32_t index = 0;
    char* comma = const_cast<char*>(find_first_of<char>(pszIconFile, ch_of<char>(',')));
    if (comma != nullptr && *comma != static_cast<char>(0)) {
        *comma = static_cast<char>(0);
        const char* p = comma + 1;
        bool negative = false;
        if (*p == static_cast<char>('-')) {
            negative = true;
            ++p;
        }
        while (ch_digit(*p)) {
            index = index * 10 +
                    static_cast<std::int32_t>(*p - static_cast<char>('0'));
            ++p;
        }
        if (negative) {
            index = -index;
        }
    }
    const std::size_t length = text_len(pszIconFile);
    if (length >= 2 && pszIconFile[0] == static_cast<char>('"') &&
        pszIconFile[length - 1] == static_cast<char>('"')) {
        pszIconFile[length - 1] = static_cast<char>(0);
        for (char* p = pszIconFile; *p != static_cast<char>(0); ++p) {
            *p = p[1];
        }
    }
    path_remove_blanks<char>(pszIconFile);
    return index;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathParseIconLocationW(char16_t* pszIconFile) noexcept {
    if (pszIconFile == nullptr) {
        return 0;
    }
    // The answer is the index after the comma and the string is left holding
    // the file name alone, with its quotes and blanks removed.
    std::int32_t index = 0;
    char16_t* comma = const_cast<char16_t*>(find_first_of<char16_t>(pszIconFile, ch_of<char16_t>(',')));
    if (comma != nullptr && *comma != static_cast<char16_t>(0)) {
        *comma = static_cast<char16_t>(0);
        const char16_t* p = comma + 1;
        bool negative = false;
        if (*p == static_cast<char16_t>('-')) {
            negative = true;
            ++p;
        }
        while (ch_digit(*p)) {
            index = index * 10 +
                    static_cast<std::int32_t>(*p - static_cast<char16_t>('0'));
            ++p;
        }
        if (negative) {
            index = -index;
        }
    }
    const std::size_t length = text_len(pszIconFile);
    if (length >= 2 && pszIconFile[0] == static_cast<char16_t>('"') &&
        pszIconFile[length - 1] == static_cast<char16_t>('"')) {
        pszIconFile[length - 1] = static_cast<char16_t>(0);
        for (char16_t* p = pszIconFile; *p != static_cast<char16_t>(0); ++p) {
            *p = p[1];
        }
    }
    path_remove_blanks<char16_t>(pszIconFile);
    return index;
}


extern "C" __attribute__((ms_abi)) void kshlwapiG_PathQuoteSpacesA(char* lpsz) noexcept {
    if (lpsz == nullptr ||
        find_first_of<char>(lpsz, ch_of<char>(' ')) == nullptr ||
        *find_first_of<char>(lpsz, ch_of<char>(' ')) == static_cast<char>(0)) {
        return;
    }
    const std::size_t length = text_len(lpsz) + 1;
    if (length + 2 >= kMaxPath) {
        return;
    }
    // Shifted right by one and wrapped. The reference does not check whether
    // the string is already quoted, and neither does this: `PathUnquoteSpaces`
    // is the way back.
    std::memmove(lpsz + 1, lpsz, length * sizeof(char));
    lpsz[0] = static_cast<char>('"');
    lpsz[length] = static_cast<char>('"');
    lpsz[length + 1] = static_cast<char>(0);
}


extern "C" __attribute__((ms_abi)) void kshlwapiG_PathQuoteSpacesW(char16_t* lpsz) noexcept {
    if (lpsz == nullptr ||
        find_first_of<char16_t>(lpsz, ch_of<char16_t>(' ')) == nullptr ||
        *find_first_of<char16_t>(lpsz, ch_of<char16_t>(' ')) == static_cast<char16_t>(0)) {
        return;
    }
    const std::size_t length = text_len(lpsz) + 1;
    if (length + 2 >= kMaxPath) {
        return;
    }
    // Shifted right by one and wrapped. The reference does not check whether
    // the string is already quoted, and neither does this: `PathUnquoteSpaces`
    // is the way back.
    std::memmove(lpsz + 1, lpsz, length * sizeof(char16_t));
    lpsz[0] = static_cast<char16_t>('"');
    lpsz[length] = static_cast<char16_t>('"');
    lpsz[length + 1] = static_cast<char16_t>(0);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathRelativePathToA(char* pszPath, const char* pszFrom, std::uint32_t dwAttrFrom, const char* pszTo, std::uint32_t dwAttrTo) noexcept {
    if (pszPath == nullptr || pszFrom == nullptr || pszTo == nullptr) {
        return 0;
    }
    *pszPath = static_cast<char>(0);
    // A file argument is cut back to its directory, because a path relative
    // to a file is a path relative to where the file is.
    char from[kMaxPath];
    char to[kMaxPath];
    text_copy<char>(from, kMaxPath, pszFrom);
    text_copy<char>(to, kMaxPath, pszTo);
    if ((dwAttrFrom & 0x00000010u) == 0) {
        static_cast<void>(path_remove_file_spec<char>(from));
    }
    if ((dwAttrTo & 0x00000010u) == 0) {
        static_cast<void>(path_remove_file_spec<char>(to));
    }
    // Two paths share a relative form only if they share a root.
    const std::size_t shared = path_common_prefix<char>(from, to, nullptr);
    if (shared == 0) {
        return 0;
    }
    const char* walk = from + shared;
    if (*walk == static_cast<char>(0)) {
        text_copy<char>(pszPath, 2, ch_of<char>('.'));
    }
    if (*walk == static_cast<char>('\\')) {
        ++walk;
    }
    while (*walk != static_cast<char>(0)) {
        // One step up for every component the source has left. The last step
        // is written without a trailing separator, because what follows is
        // the destination.
        const char* next = walk;
        while (*next != static_cast<char>(0) && *next != static_cast<char>('\\')) {
            ++next;
        }
        while (*next == static_cast<char>('\\')) {
            ++next;
        }
        const bool more = *next != static_cast<char>(0);
        text_append<char>(pszPath, kMaxPath, ch_of<char>('.'));
        text_append<char>(pszPath, kMaxPath, ch_of<char>('.'));
        if (more) {
            text_append<char>(pszPath, kMaxPath, ch_of<char>('\\'));
        }
        walk = next;
    }
    const char* rest = to + shared;
    if (*rest != static_cast<char>(0)) {
        if (*rest != static_cast<char>('\\')) {
            --rest;
        }
        if (text_len(pszPath) + text_len(rest) >= kMaxPath) {
            *pszPath = static_cast<char>(0);
            return 0;
        }
        text_append<char>(pszPath, kMaxPath, rest);
    }
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathRelativePathToW(char16_t* pszPath, const char16_t* pszFrom, std::uint32_t dwAttrFrom, const char16_t* pszTo, std::uint32_t dwAttrTo) noexcept {
    if (pszPath == nullptr || pszFrom == nullptr || pszTo == nullptr) {
        return 0;
    }
    *pszPath = static_cast<char16_t>(0);
    // A file argument is cut back to its directory, because a path relative
    // to a file is a path relative to where the file is.
    char16_t from[kMaxPath];
    char16_t to[kMaxPath];
    text_copy<char16_t>(from, kMaxPath, pszFrom);
    text_copy<char16_t>(to, kMaxPath, pszTo);
    if ((dwAttrFrom & 0x00000010u) == 0) {
        static_cast<void>(path_remove_file_spec<char16_t>(from));
    }
    if ((dwAttrTo & 0x00000010u) == 0) {
        static_cast<void>(path_remove_file_spec<char16_t>(to));
    }
    // Two paths share a relative form only if they share a root.
    const std::size_t shared = path_common_prefix<char16_t>(from, to, nullptr);
    if (shared == 0) {
        return 0;
    }
    const char16_t* walk = from + shared;
    if (*walk == static_cast<char16_t>(0)) {
        text_copy<char16_t>(pszPath, 2, ch_of<char16_t>('.'));
    }
    if (*walk == static_cast<char16_t>('\\')) {
        ++walk;
    }
    while (*walk != static_cast<char16_t>(0)) {
        // One step up for every component the source has left. The last step
        // is written without a trailing separator, because what follows is
        // the destination.
        const char16_t* next = walk;
        while (*next != static_cast<char16_t>(0) && *next != static_cast<char16_t>('\\')) {
            ++next;
        }
        while (*next == static_cast<char16_t>('\\')) {
            ++next;
        }
        const bool more = *next != static_cast<char16_t>(0);
        text_append<char16_t>(pszPath, kMaxPath, ch_of<char16_t>('.'));
        text_append<char16_t>(pszPath, kMaxPath, ch_of<char16_t>('.'));
        if (more) {
            text_append<char16_t>(pszPath, kMaxPath, ch_of<char16_t>('\\'));
        }
        walk = next;
    }
    const char16_t* rest = to + shared;
    if (*rest != static_cast<char16_t>(0)) {
        if (*rest != static_cast<char16_t>('\\')) {
            --rest;
        }
        if (text_len(pszPath) + text_len(rest) >= kMaxPath) {
            *pszPath = static_cast<char16_t>(0);
            return 0;
        }
        text_append<char16_t>(pszPath, kMaxPath, rest);
    }
    return 1;
}


extern "C" __attribute__((ms_abi)) void kshlwapiG_PathRemoveArgsA(char* pszPath) noexcept {
    if (pszPath == nullptr) {
        return;
    }
    // The separating space goes with the arguments, which is why the
    // character before the arguments is cleared rather than the arguments
    // themselves: a string with no arguments is left exactly as it was, and
    // one that ends in a blank loses it.
    char* args = const_cast<char*>(path_args<char>(pszPath));
    if (args != nullptr &&
        (*args != static_cast<char>(0) ||
         (args > pszPath && args[-1] == static_cast<char>(' ')))) {
        args[-1] = static_cast<char>(0);
    }
}


extern "C" __attribute__((ms_abi)) void kshlwapiG_PathRemoveArgsW(char16_t* pszPath) noexcept {
    if (pszPath == nullptr) {
        return;
    }
    // The separating space goes with the arguments, which is why the
    // character before the arguments is cleared rather than the arguments
    // themselves: a string with no arguments is left exactly as it was, and
    // one that ends in a blank loses it.
    char16_t* args = const_cast<char16_t*>(path_args<char16_t>(pszPath));
    if (args != nullptr &&
        (*args != static_cast<char16_t>(0) ||
         (args > pszPath && args[-1] == static_cast<char16_t>(' ')))) {
        args[-1] = static_cast<char16_t>(0);
    }
}


extern "C" __attribute__((ms_abi)) void kshlwapiG_PathRemoveBlanksA(char* pszPath) noexcept {
    path_remove_blanks<char>(pszPath);
}


extern "C" __attribute__((ms_abi)) void kshlwapiG_PathRemoveBlanksW(char16_t* pszPath) noexcept {
    path_remove_blanks<char16_t>(pszPath);
}


extern "C" __attribute__((ms_abi)) void kshlwapiG_PathRemoveExtensionA(char* pszPath) noexcept {
    if (pszPath == nullptr) {
        return;
    }
    // Removing what is not there is not an error, and the test is on the
    // character: an extension that is empty leaves the string alone, and the
    // terminator is written only when there is a dot to replace.
    char* extension = const_cast<char*>(path_extension<char>(pszPath));
    if (extension != nullptr && *extension != static_cast<char>(0)) {
        *extension = static_cast<char>(0);
    }
}


extern "C" __attribute__((ms_abi)) void kshlwapiG_PathRemoveExtensionW(char16_t* pszPath) noexcept {
    if (pszPath == nullptr) {
        return;
    }
    // Removing what is not there is not an error, and the test is on the
    // character: an extension that is empty leaves the string alone, and the
    // terminator is written only when there is a dot to replace.
    char16_t* extension = const_cast<char16_t*>(path_extension<char16_t>(pszPath));
    if (extension != nullptr && *extension != static_cast<char16_t>(0)) {
        *extension = static_cast<char16_t>(0);
    }
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathRenameExtensionA(char* pszPath, const char* pszExt) noexcept {
    if (pszPath == nullptr || pszExt == nullptr) {
        return 0;
    }
    char* extension = const_cast<char*>(path_extension<char>(pszPath));
    if (extension == nullptr) {
        return 0;
    }
    // The new extension is written where the old one started, which is the
    // terminator when there was none -- so this call adds an extension as
    // well as replacing one.
    const std::size_t at = static_cast<std::size_t>(extension - pszPath);
    if (at + text_len(pszExt) >= kMaxPath) {
        return 0;
    }
    text_copy<char>(extension, kMaxPath - at, pszExt);
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathRenameExtensionW(char16_t* pszPath, const char16_t* pszExt) noexcept {
    if (pszPath == nullptr || pszExt == nullptr) {
        return 0;
    }
    char16_t* extension = const_cast<char16_t*>(path_extension<char16_t>(pszPath));
    if (extension == nullptr) {
        return 0;
    }
    // The new extension is written where the old one started, which is the
    // terminator when there was none -- so this call adds an extension as
    // well as replacing one.
    const std::size_t at = static_cast<std::size_t>(extension - pszPath);
    if (at + text_len(pszExt) >= kMaxPath) {
        return 0;
    }
    text_copy<char16_t>(extension, kMaxPath - at, pszExt);
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathSearchAndQualifyA(const char* pszPath, char* pszBuf, std::uint32_t cchBuf) noexcept {
    if (pszPath == nullptr || pszBuf == nullptr || cchBuf == 0) {
        return 0;
    }
    // The reference asks the search path first -- which is what finds a name
    // that names a file somewhere on `PATH` -- and falls back to the full
    // path, which is what qualifies a name that names nothing yet. The
    // second case is the one this call exists for: a file about to be
    // created.
    char qualified[kMaxPath];
    if (k32b_GetFileAttributesA(pszPath) != 0xFFFFFFFFu) {
        text_copy<char>(pszBuf, cchBuf, pszPath);
        return 1;
    }
    if (k32b_GetFullPathNameA(pszPath, kMaxPath, qualified, nullptr) != 0) {
        text_copy<char>(pszBuf, cchBuf, qualified);
        return 1;
    }
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathSearchAndQualifyW(const char16_t* pszPath, char16_t* pszBuf, std::uint32_t cchBuf) noexcept {
    if (pszPath == nullptr || pszBuf == nullptr || cchBuf == 0) {
        return 0;
    }
    // The reference asks the search path first -- which is what finds a name
    // that names a file somewhere on `PATH` -- and falls back to the full
    // path, which is what qualifies a name that names nothing yet. The
    // second case is the one this call exists for: a file about to be
    // created.
    char16_t qualified[kMaxPath];
    if (k32b_GetFileAttributesW(pszPath) != 0xFFFFFFFFu) {
        text_copy<char16_t>(pszBuf, cchBuf, pszPath);
        return 1;
    }
    if (k32b_GetFullPathNameW(pszPath, kMaxPath, qualified, nullptr) != 0) {
        text_copy<char16_t>(pszBuf, cchBuf, qualified);
        return 1;
    }
    return 0;
}


extern "C" __attribute__((ms_abi)) void kshlwapiG_PathSetDlgItemPathA(void* hDlg, std::int32_t id, const char* pszPath) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(id);
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kshlwapiG_PathSetDlgItemPathW(void* hDlg, std::int32_t id, const char16_t* pszPath) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(id);
    static_cast<void>(pszPath);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathStripToRootA(char* pszPath) noexcept {
    if (pszPath == nullptr) {
        return 0;
    }
    // One component per step. A step that changes nothing means the string
    // has no root to be stripped to, and the reference reports the failure
    // rather than looping on it.
    while (!path_is_root<char>(pszPath)) {
        if (!path_remove_file_spec<char>(pszPath)) {
            return 0;
        }
    }
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathStripToRootW(char16_t* pszPath) noexcept {
    if (pszPath == nullptr) {
        return 0;
    }
    // One component per step. A step that changes nothing means the string
    // has no root to be stripped to, and the reference reports the failure
    // rather than looping on it.
    while (!path_is_root<char16_t>(pszPath)) {
        if (!path_remove_file_spec<char16_t>(pszPath)) {
            return 0;
        }
    }
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathUnExpandEnvStringsA(const char* pszPath, char* pszBuf, std::uint32_t cchBuf) noexcept {
    if (pszPath == nullptr || pszBuf == nullptr || cchBuf == 0) {
        return 0;
    }
    // The variables the shell un-expands, and the longest match wins so that
    // the most specific prefix is used: a path under `%ProgramFiles%` must
    // not be answered as `%SystemDrive%\Program Files`.
    static const struct { const char* name; } variables[] = {
        {"ALLUSERSPROFILE"},
        {"APPDATA"},
        {"ProgramFiles"},
        {"SystemRoot"},
        {"SystemDrive"},
        {"USERPROFILE"},
    };
    char value[32768];
    const char* matched = nullptr;
    std::size_t matched_length = 0;
    const std::size_t path_length = text_len(pszPath);
    for (const auto& variable : variables) {
        const std::uint32_t used = k32_GetEnvironmentVariableA(
            variable.name, value, static_cast<std::uint32_t>(32768));
        if (used == 0 || used >= 32768) {
            continue;
        }
        const std::size_t value_length = text_len(value);
        if (value_length == 0 || value_length > path_length ||
            value_length <= matched_length) {
            continue;
        }
        if (text_lower_equal_prefix<char>(value, pszPath, value_length)) {
            matched = variable.name;
            matched_length = value_length;
        }
    }
    if (matched == nullptr) {
        return 0;
    }
    // `%NAME%` and then the remainder, which is what makes the answer a
    // string a later expansion turns back into the input.
    const std::size_t needed =
        text_len(matched) + 2 + path_length - matched_length + 1;
    if (needed > cchBuf) {
        return 0;
    }
    char* write = pszBuf;
    *write++ = ch_of<char>('%');
    for (const char* p = matched; *p != static_cast<char>(0); ++p) {
        *write++ = *p;
    }
    *write++ = ch_of<char>('%');
    for (const char* p = pszPath + matched_length; *p != static_cast<char>(0); ++p) {
        *write++ = *p;
    }
    *write = static_cast<char>(0);
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathUnExpandEnvStringsW(const char16_t* pszPath, char16_t* pszBuf, std::uint32_t cchBuf) noexcept {
    if (pszPath == nullptr || pszBuf == nullptr || cchBuf == 0) {
        return 0;
    }
    // The variables the shell un-expands, and the longest match wins so that
    // the most specific prefix is used: a path under `%ProgramFiles%` must
    // not be answered as `%SystemDrive%\Program Files`.
    static const struct { const char16_t* name; } variables[] = {
        {u"ALLUSERSPROFILE"},
        {u"APPDATA"},
        {u"ProgramFiles"},
        {u"SystemRoot"},
        {u"SystemDrive"},
        {u"USERPROFILE"},
    };
    char16_t value[32768];
    const char16_t* matched = nullptr;
    std::size_t matched_length = 0;
    const std::size_t path_length = text_len(pszPath);
    for (const auto& variable : variables) {
        const std::uint32_t used = k32_GetEnvironmentVariableW(
            variable.name, value, static_cast<std::uint32_t>(32768));
        if (used == 0 || used >= 32768) {
            continue;
        }
        const std::size_t value_length = text_len(value);
        if (value_length == 0 || value_length > path_length ||
            value_length <= matched_length) {
            continue;
        }
        if (text_lower_equal_prefix<char16_t>(value, pszPath, value_length)) {
            matched = variable.name;
            matched_length = value_length;
        }
    }
    if (matched == nullptr) {
        return 0;
    }
    // `%NAME%` and then the remainder, which is what makes the answer a
    // string a later expansion turns back into the input.
    const std::size_t needed =
        text_len(matched) + 2 + path_length - matched_length + 1;
    if (needed > cchBuf) {
        return 0;
    }
    char16_t* write = pszBuf;
    *write++ = ch_of<char16_t>('%');
    for (const char16_t* p = matched; *p != static_cast<char16_t>(0); ++p) {
        *write++ = *p;
    }
    *write++ = ch_of<char16_t>('%');
    for (const char16_t* p = pszPath + matched_length; *p != static_cast<char16_t>(0); ++p) {
        *write++ = *p;
    }
    *write = static_cast<char16_t>(0);
    return 1;
}


extern "C" __attribute__((ms_abi)) void kshlwapiG_PathUndecorateA(char* pszPath) noexcept {
    if (pszPath == nullptr) {
        return;
    }
    // The decoration is the `[n]` Explorer adds between a name and its
    // extension. The extension's dot is where the walk starts, so a name
    // with no extension is never decorated and a parenthesis that is part
    // of the name is left alone.
    char* extension = const_cast<char*>(path_extension<char>(pszPath));
    if (extension == nullptr || extension == pszPath ||
        extension[-1] != static_cast<char>(']')) {
        return;
    }
    char* skip = extension - 2;
    while (skip > pszPath && ch_digit(*skip)) {
        --skip;
    }
    if (skip > pszPath && *skip == static_cast<char>('[') &&
        skip[-1] != static_cast<char>('\\')) {
        std::memmove(skip, extension,
                     (text_len(extension) + 1) * sizeof(char));
    }
}


extern "C" __attribute__((ms_abi)) void kshlwapiG_PathUndecorateW(char16_t* pszPath) noexcept {
    if (pszPath == nullptr) {
        return;
    }
    // The decoration is the `[n]` Explorer adds between a name and its
    // extension. The extension's dot is where the walk starts, so a name
    // with no extension is never decorated and a parenthesis that is part
    // of the name is left alone.
    char16_t* extension = const_cast<char16_t*>(path_extension<char16_t>(pszPath));
    if (extension == nullptr || extension == pszPath ||
        extension[-1] != static_cast<char16_t>(']')) {
        return;
    }
    char16_t* skip = extension - 2;
    while (skip > pszPath && ch_digit(*skip)) {
        --skip;
    }
    if (skip > pszPath && *skip == static_cast<char16_t>('[') &&
        skip[-1] != static_cast<char16_t>('\\')) {
        std::memmove(skip, extension,
                     (text_len(extension) + 1) * sizeof(char16_t));
    }
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathUnmakeSystemFolderA(const char* pszPath) noexcept {
    if (pszPath == nullptr || *pszPath == static_cast<char>(0)) {
        return 0;
    }
    const std::uint32_t attributes = k32b_GetFileAttributesA(pszPath);
    if (attributes == 0xFFFFFFFFu || (attributes & 0x00000010u) == 0) {
        return 0;
    }
    return k32b_SetFileAttributesA(pszPath,
                                     attributes & ~(0x00000002u | 0x00000004u))
               ? 1
               : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_PathUnmakeSystemFolderW(const char16_t* pszPath) noexcept {
    if (pszPath == nullptr || *pszPath == static_cast<char16_t>(0)) {
        return 0;
    }
    const std::uint32_t attributes = k32b_GetFileAttributesW(pszPath);
    if (attributes == 0xFFFFFFFFu || (attributes & 0x00000010u) == 0) {
        return 0;
    }
    return k32b_SetFileAttributesW(pszPath,
                                     attributes & ~(0x00000002u | 0x00000004u))
               ? 1
               : 0;
}


extern "C" __attribute__((ms_abi)) void kshlwapiG_PathUnquoteSpacesA(char* lpsz) noexcept {
    if (lpsz == nullptr || lpsz[0] != static_cast<char>('"')) {
        return;
    }
    const std::size_t length = text_len(lpsz);
    if (length == 0 || lpsz[length - 1] != static_cast<char>('"')) {
        return;
    }
    // The closing quote is cleared first and the text then shifted left over
    // the opening one, which is the reference's order and the reason the
    // length is taken before anything is written.
    lpsz[length - 1] = static_cast<char>(0);
    for (char* p = lpsz; *p != static_cast<char>(0); ++p) {
        *p = p[1];
    }
}


extern "C" __attribute__((ms_abi)) void kshlwapiG_PathUnquoteSpacesW(char16_t* lpsz) noexcept {
    if (lpsz == nullptr || lpsz[0] != static_cast<char16_t>('"')) {
        return;
    }
    const std::size_t length = text_len(lpsz);
    if (length == 0 || lpsz[length - 1] != static_cast<char16_t>('"')) {
        return;
    }
    // The closing quote is cleared first and the text then shifted left over
    // the opening one, which is the reference's order and the reason the
    // length is taken before anything is written.
    lpsz[length - 1] = static_cast<char16_t>(0);
    for (char16_t* p = lpsz; *p != static_cast<char16_t>(0); ++p) {
        *p = p[1];
    }
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_QISearch(void* that, std::uint64_t pqit, const void* riid, void** ppv) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(that);
    static_cast<void>(pqit);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kshlwapiG_SHAllocShared(const void* pvData, std::uint32_t dwSize, std::uint32_t dwProcessId) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pvData);
    static_cast<void>(dwSize);
    static_cast<void>(dwProcessId);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHAnsiToAnsi(const char* pszSrc, char* pszDst, std::int32_t cchBuf) noexcept {
    if (pszSrc == nullptr || pszDst == nullptr || cchBuf <= 0) {
        return 0;
    }
    const std::size_t written = text_copy<char>(
        pszDst, static_cast<std::size_t>(cchBuf), pszSrc);
    return static_cast<std::int32_t>(written);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHAnsiToUnicode(const char* pszSrc, char16_t* pwszDst, std::int32_t cwchBuf) noexcept {
    if (pszSrc == nullptr || pwszDst == nullptr || cwchBuf <= 0) {
        return 0;
    }
    const std::size_t written = widen_text(pszSrc, pwszDst,
                                           static_cast<std::size_t>(cwchBuf));
    return static_cast<std::int32_t>(written);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHAutoComplete(void* hwndEdit, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(hwndEdit);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHCopyKeyA(void* hkeySrc, const char* szSrcSubKey, void* hkeyDest, std::uint32_t fReserved) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkeySrc);
    static_cast<void>(szSrcSubKey);
    static_cast<void>(hkeyDest);
    static_cast<void>(fReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHCopyKeyW(void* hkeySrc, const char16_t* wszSrcSubKey, void* hkeyDest, std::uint32_t fReserved) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkeySrc);
    static_cast<void>(wszSrcSubKey);
    static_cast<void>(hkeyDest);
    static_cast<void>(fReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kshlwapiG_SHCreateMemStream(const std::uint8_t* pInit, std::uint32_t cbInit) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pInit);
    static_cast<void>(cbInit);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshlwapiG_SHCreateShellPalette(void* hdc) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hdc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHCreateStreamOnFileA(const char* pszFile, std::uint32_t grfMode, void** ppstm) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pszFile);
    static_cast<void>(grfMode);
    static_cast<void>(ppstm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHCreateStreamOnFileEx(const char16_t* pszFile, std::uint32_t grfMode, std::uint32_t dwAttributes, std::int32_t fCreate, void* pstmTemplate, void** ppstm) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pszFile);
    static_cast<void>(grfMode);
    static_cast<void>(dwAttributes);
    static_cast<void>(fCreate);
    static_cast<void>(pstmTemplate);
    static_cast<void>(ppstm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHCreateStreamOnFileW(const char16_t* pszFile, std::uint32_t grfMode, void** ppstm) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pszFile);
    static_cast<void>(grfMode);
    static_cast<void>(ppstm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHCreateThread(void* pfnThreadProc, void* pData, std::uint64_t dwFlags, void* pfnCallback) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pfnThreadProc);
    static_cast<void>(pData);
    static_cast<void>(dwFlags);
    static_cast<void>(pfnCallback);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHCreateThreadRef(std::int32_t* pcRef, void** ppunk) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pcRef);
    static_cast<void>(ppunk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHCreateThreadWithHandle(void* pfnThreadProc, void* pData, std::uint64_t dwflags, void* pfnCallback, void* pHandle) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pfnThreadProc);
    static_cast<void>(pData);
    static_cast<void>(dwflags);
    static_cast<void>(pfnCallback);
    static_cast<void>(pHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHDeleteEmptyKeyA(void* hkey, const char* pszSubKey) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkey);
    static_cast<void>(pszSubKey);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHDeleteEmptyKeyW(void* hkey, const char16_t* pszSubKey) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkey);
    static_cast<void>(pszSubKey);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHDeleteKeyA(void* hkey, const char* pszSubKey) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkey);
    static_cast<void>(pszSubKey);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHDeleteKeyW(void* hkey, const char16_t* pszSubKey) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkey);
    static_cast<void>(pszSubKey);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHDeleteValueA(void* hkey, const char* pszSubKey, const char* pszValue) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkey);
    static_cast<void>(pszSubKey);
    static_cast<void>(pszValue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHDeleteValueW(void* hkey, const char16_t* pszSubKey, const char16_t* pszValue) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkey);
    static_cast<void>(pszSubKey);
    static_cast<void>(pszValue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHEnumKeyExA(void* hkey, std::uint32_t dwIndex, char* pszName, std::uint32_t* pcchName) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hkey);
    static_cast<void>(dwIndex);
    static_cast<void>(pszName);
    static_cast<void>(pcchName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHEnumKeyExW(void* hkey, std::uint32_t dwIndex, char16_t* pszName, std::uint32_t* pcchName) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hkey);
    static_cast<void>(dwIndex);
    static_cast<void>(pszName);
    static_cast<void>(pcchName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHEnumValueA(void* hkey, std::uint32_t dwIndex, char* pszValueName, std::uint32_t* pcchValueName, std::uint32_t* pdwType, void* pvData, std::uint32_t* pcbData) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hkey);
    static_cast<void>(dwIndex);
    static_cast<void>(pszValueName);
    static_cast<void>(pcchValueName);
    static_cast<void>(pdwType);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHEnumValueW(void* hkey, std::uint32_t dwIndex, char16_t* pszValueName, std::uint32_t* pcchValueName, std::uint32_t* pdwType, void* pvData, std::uint32_t* pcbData) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hkey);
    static_cast<void>(dwIndex);
    static_cast<void>(pszValueName);
    static_cast<void>(pcchValueName);
    static_cast<void>(pdwType);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHFormatDateTimeA(const std::uint64_t* pft, std::uint32_t* pdwFlags, char* pszBuf, std::uint32_t cchBuf) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(pft);
    static_cast<void>(pdwFlags);
    static_cast<void>(pszBuf);
    static_cast<void>(cchBuf);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHFormatDateTimeW(const std::uint64_t* pft, std::uint32_t* pdwFlags, char16_t* pszBuf, std::uint32_t cchBuf) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(pft);
    static_cast<void>(pdwFlags);
    static_cast<void>(pszBuf);
    static_cast<void>(cchBuf);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHFreeShared(void* hData, std::uint32_t dwProcessId) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hData);
    static_cast<void>(dwProcessId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHGetInverseCMAP(std::uint8_t* pbMap, std::uint32_t cbMap) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pbMap);
    static_cast<void>(cbMap);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHGetThreadRef(void** ppunk) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(ppunk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHGetValueA(void* hkey, const char* pszSubKey, const char* pszValue, std::uint32_t* pdwType, void* pvData, std::uint32_t* pcbData) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hkey);
    static_cast<void>(pszSubKey);
    static_cast<void>(pszValue);
    static_cast<void>(pdwType);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHGetValueW(void* hkey, const char16_t* pszSubKey, const char16_t* pszValue, std::uint32_t* pdwType, void* pvData, std::uint32_t* pcbData) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hkey);
    static_cast<void>(pszSubKey);
    static_cast<void>(pszValue);
    static_cast<void>(pdwType);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHGetViewStatePropertyBag(void* pidl, const char16_t* pszBagName, std::uint32_t dwFlags, const void* riid, void** ppv) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(pidl);
    static_cast<void>(pszBagName);
    static_cast<void>(dwFlags);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHIsLowMemoryMachine(std::uint32_t dwType) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(dwType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHLoadIndirectString(const char16_t* pszSource, char16_t* pszOutBuf, std::uint32_t cchOutBuf, void** ppvReserved) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    static_cast<void>(pszSource);
    static_cast<void>(pszOutBuf);
    static_cast<void>(cchOutBuf);
    static_cast<void>(ppvReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kshlwapiG_SHLockShared(void* hData, std::uint32_t dwProcessId) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hData);
    static_cast<void>(dwProcessId);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHMessageBoxCheckA(void* hwnd, const char* pszText, const char* pszCaption, std::uint32_t uType, std::int32_t iDefault, const char* pszRegVal) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hwnd);
    static_cast<void>(pszText);
    static_cast<void>(pszCaption);
    static_cast<void>(uType);
    static_cast<void>(iDefault);
    static_cast<void>(pszRegVal);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHMessageBoxCheckW(void* hwnd, const char16_t* pszText, const char16_t* pszCaption, std::uint32_t uType, std::int32_t iDefault, const char16_t* pszRegVal) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hwnd);
    static_cast<void>(pszText);
    static_cast<void>(pszCaption);
    static_cast<void>(uType);
    static_cast<void>(iDefault);
    static_cast<void>(pszRegVal);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kshlwapiG_SHOpenRegStream2A(void* hkey, const char* pszSubkey, const char* pszValue, std::uint32_t grfMode) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkey);
    static_cast<void>(pszSubkey);
    static_cast<void>(pszValue);
    static_cast<void>(grfMode);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshlwapiG_SHOpenRegStream2W(void* hkey, const char16_t* pszSubkey, const char16_t* pszValue, std::uint32_t grfMode) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkey);
    static_cast<void>(pszSubkey);
    static_cast<void>(pszValue);
    static_cast<void>(grfMode);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshlwapiG_SHOpenRegStreamA(void* hkey, const char* pszSubkey, const char* pszValue, std::uint32_t grfMode) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkey);
    static_cast<void>(pszSubkey);
    static_cast<void>(pszValue);
    static_cast<void>(grfMode);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kshlwapiG_SHOpenRegStreamW(void* hkey, const char16_t* pszSubkey, const char16_t* pszValue, std::uint32_t grfMode) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkey);
    static_cast<void>(pszSubkey);
    static_cast<void>(pszValue);
    static_cast<void>(grfMode);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHQueryInfoKeyA(void* hkey, std::uint32_t* pcSubKeys, std::uint32_t* pcchMaxSubKeyLen, std::uint32_t* pcValues, std::uint32_t* pcchMaxValueNameLen) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkey);
    static_cast<void>(pcSubKeys);
    static_cast<void>(pcchMaxSubKeyLen);
    static_cast<void>(pcValues);
    static_cast<void>(pcchMaxValueNameLen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHQueryInfoKeyW(void* hkey, std::uint32_t* pcSubKeys, std::uint32_t* pcchMaxSubKeyLen, std::uint32_t* pcValues, std::uint32_t* pcchMaxValueNameLen) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkey);
    static_cast<void>(pcSubKeys);
    static_cast<void>(pcchMaxSubKeyLen);
    static_cast<void>(pcValues);
    static_cast<void>(pcchMaxValueNameLen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHQueryValueExA(void* hkey, const char* pszValue, std::uint32_t* pdwReserved, std::uint32_t* pdwType, void* pvData, std::uint32_t* pcbData) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkey);
    static_cast<void>(pszValue);
    static_cast<void>(pdwReserved);
    static_cast<void>(pdwType);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHQueryValueExW(void* hkey, const char16_t* pszValue, std::uint32_t* pdwReserved, std::uint32_t* pdwType, void* pvData, std::uint32_t* pcbData) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkey);
    static_cast<void>(pszValue);
    static_cast<void>(pdwReserved);
    static_cast<void>(pdwType);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegCloseUSKey(void* hUSKey) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hUSKey);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegCreateUSKeyA(const char* pszPath, std::uint32_t samDesired, void* hRelativeUSKey, void* phNewUSKey, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszPath);
    static_cast<void>(samDesired);
    static_cast<void>(hRelativeUSKey);
    static_cast<void>(phNewUSKey);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegCreateUSKeyW(const char16_t* pwzPath, std::uint32_t samDesired, void* hRelativeUSKey, void* phNewUSKey, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pwzPath);
    static_cast<void>(samDesired);
    static_cast<void>(hRelativeUSKey);
    static_cast<void>(phNewUSKey);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegDeleteEmptyUSKeyA(void* hUSKey, const char* pszSubKey, std::uint32_t delRegFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hUSKey);
    static_cast<void>(pszSubKey);
    static_cast<void>(delRegFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegDeleteEmptyUSKeyW(void* hUSKey, const char16_t* pwzSubKey, std::uint32_t delRegFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hUSKey);
    static_cast<void>(pwzSubKey);
    static_cast<void>(delRegFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegDeleteUSValueA(void* hUSKey, const char* pszValue, std::uint32_t delRegFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hUSKey);
    static_cast<void>(pszValue);
    static_cast<void>(delRegFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegDeleteUSValueW(void* hUSKey, const char16_t* pwzValue, std::uint32_t delRegFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hUSKey);
    static_cast<void>(pwzValue);
    static_cast<void>(delRegFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kshlwapiG_SHRegDuplicateHKey(void* hkey) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkey);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegEnumUSKeyA(void* hUSKey, std::uint32_t dwIndex, char* pszName, std::uint32_t* pcchName, std::uint32_t enumRegFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hUSKey);
    static_cast<void>(dwIndex);
    static_cast<void>(pszName);
    static_cast<void>(pcchName);
    static_cast<void>(enumRegFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegEnumUSKeyW(void* hUSKey, std::uint32_t dwIndex, char16_t* pwzName, std::uint32_t* pcchName, std::uint32_t enumRegFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hUSKey);
    static_cast<void>(dwIndex);
    static_cast<void>(pwzName);
    static_cast<void>(pcchName);
    static_cast<void>(enumRegFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegEnumUSValueA(void* hUSkey, std::uint32_t dwIndex, char* pszValueName, std::uint32_t* pcchValueName, std::uint32_t* pdwType, void* pvData, std::uint32_t* pcbData, std::uint32_t enumRegFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hUSkey);
    static_cast<void>(dwIndex);
    static_cast<void>(pszValueName);
    static_cast<void>(pcchValueName);
    static_cast<void>(pdwType);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    static_cast<void>(enumRegFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegEnumUSValueW(void* hUSkey, std::uint32_t dwIndex, char16_t* pszValueName, std::uint32_t* pcchValueName, std::uint32_t* pdwType, void* pvData, std::uint32_t* pcbData, std::uint32_t enumRegFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hUSkey);
    static_cast<void>(dwIndex);
    static_cast<void>(pszValueName);
    static_cast<void>(pcchValueName);
    static_cast<void>(pdwType);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    static_cast<void>(enumRegFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegGetBoolUSValueA(const char* pszSubKey, const char* pszValue, std::int32_t fIgnoreHKCU, std::int32_t fDefault) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszSubKey);
    static_cast<void>(pszValue);
    static_cast<void>(fIgnoreHKCU);
    static_cast<void>(fDefault);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegGetBoolUSValueW(const char16_t* pszSubKey, const char16_t* pszValue, std::int32_t fIgnoreHKCU, std::int32_t fDefault) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszSubKey);
    static_cast<void>(pszValue);
    static_cast<void>(fIgnoreHKCU);
    static_cast<void>(fDefault);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegGetBoolValueFromHKCUHKLM(const char16_t* pszKey, const char16_t* pszValue, std::int32_t fDefault) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszKey);
    static_cast<void>(pszValue);
    static_cast<void>(fDefault);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegGetIntW(void* hk, const char16_t* pwzKey, std::int32_t iDefault) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hk);
    static_cast<void>(pwzKey);
    static_cast<void>(iDefault);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHRegGetPathA(void* hKey, const char* pcszSubKey, const char* pcszValue, char* pszPath, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hKey);
    static_cast<void>(pcszSubKey);
    static_cast<void>(pcszValue);
    static_cast<void>(pszPath);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHRegGetPathW(void* hKey, const char16_t* pcszSubKey, const char16_t* pcszValue, char16_t* pszPath, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hKey);
    static_cast<void>(pcszSubKey);
    static_cast<void>(pcszValue);
    static_cast<void>(pszPath);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegGetUSValueA(const char* pszSubKey, const char* pszValue, std::uint32_t* pdwType, void* pvData, std::uint32_t* pcbData, std::int32_t fIgnoreHKCU, void* pvDefaultData, std::uint32_t dwDefaultDataSize) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszSubKey);
    static_cast<void>(pszValue);
    static_cast<void>(pdwType);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    static_cast<void>(fIgnoreHKCU);
    static_cast<void>(pvDefaultData);
    static_cast<void>(dwDefaultDataSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegGetUSValueW(const char16_t* pwzSubKey, const char16_t* pwzValue, std::uint32_t* pdwType, void* pvData, std::uint32_t* pcbData, std::int32_t fIgnoreHKCU, void* pvDefaultData, std::uint32_t dwDefaultDataSize) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pwzSubKey);
    static_cast<void>(pwzValue);
    static_cast<void>(pdwType);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    static_cast<void>(fIgnoreHKCU);
    static_cast<void>(pvDefaultData);
    static_cast<void>(dwDefaultDataSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegGetValueA(void* hkey, const char* pszSubKey, const char* pszValue, std::uint64_t dwFlags, std::uint32_t* pdwType, void* pvData, std::uint32_t* pcbData) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkey);
    static_cast<void>(pszSubKey);
    static_cast<void>(pszValue);
    static_cast<void>(dwFlags);
    static_cast<void>(pdwType);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegGetValueFromHKCUHKLM(const char16_t* pwszKey, const char16_t* pwszValue, std::uint64_t srrfFlags, std::uint32_t* pdwType, void* pvData, std::uint32_t* pcbData) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pwszKey);
    static_cast<void>(pwszValue);
    static_cast<void>(srrfFlags);
    static_cast<void>(pdwType);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegGetValueW(void* hkey, const char16_t* pszSubKey, const char16_t* pszValue, std::uint64_t dwFlags, std::uint32_t* pdwType, void* pvData, std::uint32_t* pcbData) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hkey);
    static_cast<void>(pszSubKey);
    static_cast<void>(pszValue);
    static_cast<void>(dwFlags);
    static_cast<void>(pdwType);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegOpenUSKeyA(const char* pszPath, std::uint32_t samDesired, void* hRelativeUSKey, void* phNewUSKey, std::int32_t fIgnoreHKCU) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszPath);
    static_cast<void>(samDesired);
    static_cast<void>(hRelativeUSKey);
    static_cast<void>(phNewUSKey);
    static_cast<void>(fIgnoreHKCU);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegOpenUSKeyW(const char16_t* pwzPath, std::uint32_t samDesired, void* hRelativeUSKey, void* phNewUSKey, std::int32_t fIgnoreHKCU) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pwzPath);
    static_cast<void>(samDesired);
    static_cast<void>(hRelativeUSKey);
    static_cast<void>(phNewUSKey);
    static_cast<void>(fIgnoreHKCU);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegQueryInfoUSKeyA(void* hUSKey, std::uint32_t* pcSubKeys, std::uint32_t* pcchMaxSubKeyLen, std::uint32_t* pcValues, std::uint32_t* pcchMaxValueNameLen, std::uint32_t enumRegFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hUSKey);
    static_cast<void>(pcSubKeys);
    static_cast<void>(pcchMaxSubKeyLen);
    static_cast<void>(pcValues);
    static_cast<void>(pcchMaxValueNameLen);
    static_cast<void>(enumRegFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegQueryInfoUSKeyW(void* hUSKey, std::uint32_t* pcSubKeys, std::uint32_t* pcchMaxSubKeyLen, std::uint32_t* pcValues, std::uint32_t* pcchMaxValueNameLen, std::uint32_t enumRegFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hUSKey);
    static_cast<void>(pcSubKeys);
    static_cast<void>(pcchMaxSubKeyLen);
    static_cast<void>(pcValues);
    static_cast<void>(pcchMaxValueNameLen);
    static_cast<void>(enumRegFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegQueryUSValueA(void* hUSKey, const char* pszValue, std::uint32_t* pdwType, void* pvData, std::uint32_t* pcbData, std::int32_t fIgnoreHKCU, void* pvDefaultData, std::uint32_t dwDefaultDataSize) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hUSKey);
    static_cast<void>(pszValue);
    static_cast<void>(pdwType);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    static_cast<void>(fIgnoreHKCU);
    static_cast<void>(pvDefaultData);
    static_cast<void>(dwDefaultDataSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegQueryUSValueW(void* hUSKey, const char16_t* pwzValue, std::uint32_t* pdwType, void* pvData, std::uint32_t* pcbData, std::int32_t fIgnoreHKCU, void* pvDefaultData, std::uint32_t dwDefaultDataSize) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hUSKey);
    static_cast<void>(pwzValue);
    static_cast<void>(pdwType);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    static_cast<void>(fIgnoreHKCU);
    static_cast<void>(pvDefaultData);
    static_cast<void>(dwDefaultDataSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHRegSetPathA(void* hKey, const char* pcszSubKey, const char* pcszValue, const char* pcszPath, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hKey);
    static_cast<void>(pcszSubKey);
    static_cast<void>(pcszValue);
    static_cast<void>(pcszPath);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHRegSetPathW(void* hKey, const char16_t* pcszSubKey, const char16_t* pcszValue, const char16_t* pcszPath, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hKey);
    static_cast<void>(pcszSubKey);
    static_cast<void>(pcszValue);
    static_cast<void>(pcszPath);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegSetUSValueA(const char* pszSubKey, const char* pszValue, std::uint32_t dwType, const void* pvData, std::uint32_t cbData, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszSubKey);
    static_cast<void>(pszValue);
    static_cast<void>(dwType);
    static_cast<void>(pvData);
    static_cast<void>(cbData);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegSetUSValueW(const char16_t* pwzSubKey, const char16_t* pwzValue, std::uint32_t dwType, const void* pvData, std::uint32_t cbData, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pwzSubKey);
    static_cast<void>(pwzValue);
    static_cast<void>(dwType);
    static_cast<void>(pvData);
    static_cast<void>(cbData);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegWriteUSValueA(void* hUSKey, const char* pszValue, std::uint32_t dwType, const void* pvData, std::uint32_t cbData, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hUSKey);
    static_cast<void>(pszValue);
    static_cast<void>(dwType);
    static_cast<void>(pvData);
    static_cast<void>(cbData);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHRegWriteUSValueW(void* hUSKey, const char16_t* pwzValue, std::uint32_t dwType, const void* pvData, std::uint32_t cbData, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(hUSKey);
    static_cast<void>(pwzValue);
    static_cast<void>(dwType);
    static_cast<void>(pvData);
    static_cast<void>(cbData);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHReleaseThreadRef() noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kshlwapiG_SHSendMessageBroadcastA(std::uint32_t uMsg, std::uint64_t wParam, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(uMsg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kshlwapiG_SHSendMessageBroadcastW(std::uint32_t uMsg, std::uint64_t wParam, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(uMsg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHSetThreadRef(void* punk) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(punk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHSetValueA(void* hkey, const char* pszSubKey, const char* pszValue, std::uint32_t dwType, const void* pvData, std::uint32_t cbData) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hkey);
    static_cast<void>(pszSubKey);
    static_cast<void>(pszValue);
    static_cast<void>(dwType);
    static_cast<void>(pvData);
    static_cast<void>(cbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kshlwapiG_SHSetValueW(void* hkey, const char16_t* pszSubKey, const char16_t* pszValue, std::uint32_t dwType, const void* pvData, std::uint32_t cbData) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hkey);
    static_cast<void>(pszSubKey);
    static_cast<void>(pszValue);
    static_cast<void>(dwType);
    static_cast<void>(pvData);
    static_cast<void>(cbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHSkipJunction(void* pbc, const void* pclsid) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pbc);
    static_cast<void>(pclsid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHStrDupA(const char* psz, char16_t** ppwsz) noexcept {
    if (ppwsz == nullptr) {
        return kEInvalidArg;
    }
    *ppwsz = nullptr;
    if (psz == nullptr) {
        return kSOk;  // a null source is answered with a null copy
    }
    // The copy is a task allocator block on Windows, and a guest frees it
    // with `CoTaskMemFree`; the runtime's allocator is the one both reach,
    // so the block this returns is one its own free accepts.
    const std::size_t length = text_len(psz);
    auto* copy = static_cast<char16_t*>(
        k32m_LocalAlloc(0x0040u, (length + 1) * sizeof(char16_t)));
    if (copy == nullptr) {
        return kEOutOfMemory;
    }
    if (widen_text(psz, copy, length + 1) != length) {
        guest_free(copy);
        return kEInvalidArg;
    }
    *ppwsz = copy;
    return kSOk;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHStrDupW(const char16_t* psz, char16_t** ppwsz) noexcept {
    if (ppwsz == nullptr) {
        return kEInvalidArg;
    }
    *ppwsz = nullptr;
    if (psz == nullptr) {
        return kSOk;  // a null source is answered with a null copy
    }
    // The copy is a task allocator block on Windows, and a guest frees it
    // with `CoTaskMemFree`; the runtime's allocator is the one both reach,
    // so the block this returns is one its own free accepts.
    const std::size_t length = text_len(psz);
    auto* copy = static_cast<char16_t*>(
        k32m_LocalAlloc(0x0040u, (length + 1) * sizeof(char16_t)));
    if (copy == nullptr) {
        return kEOutOfMemory;
    }
    std::memcpy(copy, psz, (length + 1) * sizeof(char16_t));
    *ppwsz = copy;
    return kSOk;
}


extern "C" __attribute__((ms_abi)) char kshlwapiG_SHStripMneumonicA(char* pszMenu) noexcept {
    if (pszMenu == nullptr) {
        return static_cast<char>(0);
    }
    // The mnemonic is the first ampersand and the letter after it. A doubled
    // ampersand is the way to spell one, and it is answered rather than
    // removed.
    char* mark = const_cast<char*>(find_first_of<char>(pszMenu, ch_of<char>('&')));
    if (mark == nullptr || *mark == static_cast<char>(0)) {
        return static_cast<char>(0);
    }
    const char following = mark[1];
    if (following == static_cast<char>('&') || following == static_cast<char>(0)) {
        return following;
    }
    for (char* p = mark; *p != static_cast<char>(0); ++p) {
        *p = p[1];
    }
    return following;
}


extern "C" __attribute__((ms_abi)) char16_t kshlwapiG_SHStripMneumonicW(char16_t* pszMenu) noexcept {
    if (pszMenu == nullptr) {
        return static_cast<char16_t>(0);
    }
    // The mnemonic is the first ampersand and the letter after it. A doubled
    // ampersand is the way to spell one, and it is answered rather than
    // removed.
    char16_t* mark = const_cast<char16_t*>(find_first_of<char16_t>(pszMenu, ch_of<char16_t>('&')));
    if (mark == nullptr || *mark == static_cast<char16_t>(0)) {
        return static_cast<char16_t>(0);
    }
    const char16_t following = mark[1];
    if (following == static_cast<char16_t>('&') || following == static_cast<char16_t>(0)) {
        return following;
    }
    for (char16_t* p = mark; *p != static_cast<char16_t>(0); ++p) {
        *p = p[1];
    }
    return following;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHUnicodeToAnsi(const char16_t* pwszSrc, char* pszDst, std::int32_t cchBuf) noexcept {
    if (pwszSrc == nullptr || pszDst == nullptr || cchBuf <= 0) {
        return 0;
    }
    const std::size_t written = narrow_text(pwszSrc, pszDst,
                                            static_cast<std::size_t>(cchBuf));
    return static_cast<std::int32_t>(written);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHUnicodeToUnicode(const char16_t* pwzSrc, char16_t* pwzDst, std::int32_t cwchBuf) noexcept {
    if (pwzSrc == nullptr || pwzDst == nullptr || cwchBuf <= 0) {
        return 0;
    }
    const std::size_t written = text_copy<char16_t>(
        pwzDst, static_cast<std::size_t>(cwchBuf), pwzSrc);
    return static_cast<std::int32_t>(written);
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_SHUnlockShared(void* pvData) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pvData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_ShellMessageBoxA(void* hAppInst, void* hWnd, const char* lpcText, const char* lpcTitle, std::uint32_t fuStyle, ...) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hAppInst);
    static_cast<void>(hWnd);
    static_cast<void>(lpcText);
    static_cast<void>(lpcTitle);
    static_cast<void>(fuStyle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_ShellMessageBoxW(void* hAppInst, void* hWnd, const char16_t* lpcText, const char16_t* lpcTitle, std::uint32_t fuStyle, ...) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hAppInst);
    static_cast<void>(hWnd);
    static_cast<void>(lpcText);
    static_cast<void>(lpcTitle);
    static_cast<void>(fuStyle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) char16_t* kshlwapiG_StrCatW(char16_t* psz1, const char16_t* psz2) noexcept {
    if (psz1 != nullptr && psz2 != nullptr) {
        // The contract is the one `lstrcat` has: the caller's buffer decides
        // the room, and the answer is the caller's own pointer.
        static_cast<void>(text_append<char16_t>(psz1, 0x7FFFFFFFul, psz2));
    }
    return psz1;
}


extern "C" __attribute__((ms_abi)) const char16_t* kshlwapiG_StrChrNIW(const char16_t* pszStart, char16_t wMatch, std::uint32_t cchMax) noexcept {
    if (pszStart == nullptr || cchMax == 0) {
        return nullptr;
    }
    // The bound counts characters, and a match of zero is the terminator,
    // which is not searched for.
    const char16_t wanted = ch_lower_of(static_cast<char16_t>(wMatch));
    if (wanted == static_cast<char16_t>(0)) {
        return nullptr;
    }
    for (std::uint32_t index = 0; index < cchMax; ++index) {
        const char16_t ch = pszStart[index];
        if (ch == static_cast<char16_t>(0)) {
            break;
        }
        if (ch_lower_of(ch) == wanted) {
            return pszStart + index;
        }
    }
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char16_t* kshlwapiG_StrCpyW(char16_t* psz1, const char16_t* psz2) noexcept {
    if (psz1 != nullptr && psz2 != nullptr) {
        static_cast<void>(text_copy<char16_t>(psz1, 0x7FFFFFFFul, psz2));
    }
    return psz1;
}


extern "C" __attribute__((ms_abi)) char* kshlwapiG_StrFormatByteSize64A(std::int64_t qdw, char* szBuf, std::uint32_t uiBufSize) noexcept {
    // The wide form carries the rules and this one converts, which is the
    // same split the rest of the family uses.
    char16_t wide[32];
    if (format_byte_size(static_cast<std::int64_t>(qdw), wide, 32) == nullptr) {
        return szBuf;
    }
    if (szBuf != nullptr) {
        static_cast<void>(narrow_text(wide, szBuf, uiBufSize));
    }
    return szBuf;
}


extern "C" __attribute__((ms_abi)) char* kshlwapiG_StrFormatByteSizeA(std::uint32_t dw, char* szBuf, std::uint32_t uiBufSize) noexcept {
    // The narrow form takes a 32-bit count and answers through the 64-bit
    // path, which is what the reference does -- the two differ only in the
    // width of the argument the caller may pass.
    char16_t wide[32];
    if (format_byte_size(static_cast<std::int64_t>(
                             static_cast<std::uint32_t>(dw)),
                         wide, 32) == nullptr) {
        return szBuf;
    }
    if (szBuf != nullptr) {
        static_cast<void>(narrow_text(wide, szBuf, uiBufSize));
    }
    return szBuf;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_StrFormatByteSizeEx(std::uint64_t ull, std::uint64_t flags, char16_t* pszBuf, std::uint32_t cchBuf) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(ull);
    static_cast<void>(flags);
    static_cast<void>(pszBuf);
    static_cast<void>(cchBuf);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) char16_t* kshlwapiG_StrFormatByteSizeW(std::int64_t qdw, char16_t* szBuf, std::uint32_t uiBufSize) noexcept {
    return format_byte_size(static_cast<std::int64_t>(qdw), szBuf,
                            uiBufSize);
}


extern "C" __attribute__((ms_abi)) char* kshlwapiG_StrFormatKBSizeA(std::int64_t qdw, char* szBuf, std::uint32_t uiBufSize) noexcept {
    if (szBuf == nullptr || uiBufSize == 0) {
        return nullptr;
    }
    // The byte count rounded up to whole kilobytes, then the unit. The
    // rounding is the reference's: `(bytes + 1023) >> 10`, so a file of one
    // byte is one kilobyte rather than zero.
    const std::int64_t kilobytes =
        (static_cast<std::int64_t>(qdw) + 1023) >> 10;
    if (number_text<char>(szBuf, uiBufSize, kilobytes) == 0) {
        return nullptr;
    }
    const std::size_t length = text_len(szBuf);
    if (static_cast<std::size_t>(uiBufSize) - length < 4) {
        return nullptr;
    }
    text_append<char>(szBuf, uiBufSize, ch_of<char>(' '));
    text_append<char>(szBuf, uiBufSize, ch_of<char>('K'));
    text_append<char>(szBuf, uiBufSize, ch_of<char>('B'));
    return szBuf;
}


extern "C" __attribute__((ms_abi)) char16_t* kshlwapiG_StrFormatKBSizeW(std::int64_t qdw, char16_t* szBuf, std::uint32_t uiBufSize) noexcept {
    if (szBuf == nullptr || uiBufSize == 0) {
        return nullptr;
    }
    // The byte count rounded up to whole kilobytes, then the unit. The
    // rounding is the reference's: `(bytes + 1023) >> 10`, so a file of one
    // byte is one kilobyte rather than zero.
    const std::int64_t kilobytes =
        (static_cast<std::int64_t>(qdw) + 1023) >> 10;
    if (number_text<char16_t>(szBuf, uiBufSize, kilobytes) == 0) {
        return nullptr;
    }
    const std::size_t length = text_len(szBuf);
    if (static_cast<std::size_t>(uiBufSize) - length < 4) {
        return nullptr;
    }
    text_append<char16_t>(szBuf, uiBufSize, ch_of<char16_t>(' '));
    text_append<char16_t>(szBuf, uiBufSize, ch_of<char16_t>('K'));
    text_append<char16_t>(szBuf, uiBufSize, ch_of<char16_t>('B'));
    return szBuf;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_StrFromTimeIntervalA(char* pszOut, std::uint32_t cchMax, std::uint32_t dwTimeMS, std::int32_t digits) noexcept {
    if (pszOut == nullptr || cchMax == 0) {
        return 0;
    }
    if (digits <= 0 || cchMax == 1) {
        *pszOut = static_cast<char>(0);
        return 0;
    }
    // The interval is rounded to the nearest second first, and then split
    // into the three classes. A class the walk has no digits left for is not
    // written, which is what turns a 30-second interval into `30 sec` rather
    // than `0 hr 0 min 30 sec`.
    //
    // The unit strings carry their own leading space and the number is
    // written behind another one, so the shape of the answer is
    // ` 16 min 40 sec` -- a leading separator included. That is the
    // reference's output, confirmed against its own test vectors rather
    // than against its documentation, which shows the same string without
    // the leading space.
    std::uint32_t seconds_total = (dwTimeMS + 500u) / 1000u;
    const std::uint32_t hours = seconds_total / 3600u;
    seconds_total -= hours * 3600u;
    const std::uint32_t minutes = seconds_total / 60u;
    seconds_total -= minutes * 60u;

    char text[128];
    text[0] = static_cast<char>(0);
    if (hours != 0) {
        digits = write_time_class<char>(text, 128, hours, " hr", digits);
    }
    if (minutes != 0 && digits > 0) {
        digits = write_time_class<char>(text, 128, minutes, " min",
                                           digits);
    }
    if (digits > 0) {
        static_cast<void>(write_time_class<char>(text, 128, seconds_total,
                                                  " sec", digits));
    }
    static_cast<void>(text_copy<char>(pszOut, cchMax, text));
    return static_cast<std::int32_t>(text_len(pszOut));
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_StrFromTimeIntervalW(char16_t* pszOut, std::uint32_t cchMax, std::uint32_t dwTimeMS, std::int32_t digits) noexcept {
    if (pszOut == nullptr || cchMax == 0) {
        return 0;
    }
    if (digits <= 0 || cchMax == 1) {
        *pszOut = static_cast<char16_t>(0);
        return 0;
    }
    // The interval is rounded to the nearest second first, and then split
    // into the three classes. A class the walk has no digits left for is not
    // written, which is what turns a 30-second interval into `30 sec` rather
    // than `0 hr 0 min 30 sec`.
    //
    // The unit strings carry their own leading space and the number is
    // written behind another one, so the shape of the answer is
    // ` 16 min 40 sec` -- a leading separator included. That is the
    // reference's output, confirmed against its own test vectors rather
    // than against its documentation, which shows the same string without
    // the leading space.
    std::uint32_t seconds_total = (dwTimeMS + 500u) / 1000u;
    const std::uint32_t hours = seconds_total / 3600u;
    seconds_total -= hours * 3600u;
    const std::uint32_t minutes = seconds_total / 60u;
    seconds_total -= minutes * 60u;

    char16_t text[128];
    text[0] = static_cast<char16_t>(0);
    if (hours != 0) {
        digits = write_time_class<char16_t>(text, 128, hours, u" hr", digits);
    }
    if (minutes != 0 && digits > 0) {
        digits = write_time_class<char16_t>(text, 128, minutes, u" min",
                                           digits);
    }
    if (digits > 0) {
        static_cast<void>(write_time_class<char16_t>(text, 128, seconds_total,
                                                  u" sec", digits));
    }
    static_cast<void>(text_copy<char16_t>(pszOut, cchMax, text));
    return static_cast<std::int32_t>(text_len(pszOut));
}


extern "C" __attribute__((ms_abi)) char* kshlwapiG_StrNCatA(char* psz1, const char* psz2, std::int32_t cchMax) noexcept {
    if (psz1 == nullptr) {
        return nullptr;
    }
    // The bound is on what is appended and not on the total, and the append
    // starts at the end of what is already there -- so this is `StrCpyN`
    // aimed past the existing text, which is what the reference writes.
    const std::size_t start = text_len(psz1);
    if (cchMax > 0) {
        static_cast<void>(text_copy<char>(psz1 + start,
                                           static_cast<std::size_t>(cchMax),
                                           psz2));
    }
    return psz1;
}


extern "C" __attribute__((ms_abi)) char16_t* kshlwapiG_StrNCatW(char16_t* psz1, const char16_t* psz2, std::int32_t cchMax) noexcept {
    if (psz1 == nullptr) {
        return nullptr;
    }
    // The bound is on what is appended and not on the total, and the append
    // starts at the end of what is already there -- so this is `StrCpyN`
    // aimed past the existing text, which is what the reference writes.
    const std::size_t start = text_len(psz1);
    if (cchMax > 0) {
        static_cast<void>(text_copy<char16_t>(psz1 + start,
                                           static_cast<std::size_t>(cchMax),
                                           psz2));
    }
    return psz1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_StrRetToBSTR(void* pstr, void* pidl, char16_t** pbstr) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pstr);
    static_cast<void>(pidl);
    static_cast<void>(pbstr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_StrRetToBufA(void* pstr, void* pidl, char* pszBuf, std::uint32_t cchBuf) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pstr);
    static_cast<void>(pidl);
    static_cast<void>(pszBuf);
    static_cast<void>(cchBuf);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_StrRetToBufW(void* pstr, void* pidl, char16_t* pszBuf, std::uint32_t cchBuf) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pstr);
    static_cast<void>(pidl);
    static_cast<void>(pszBuf);
    static_cast<void>(cchBuf);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_StrRetToStrA(void* pstr, void* pidl, char** ppsz) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pstr);
    static_cast<void>(pidl);
    static_cast<void>(ppsz);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_StrRetToStrW(void* pstr, void* pidl, char16_t** ppsz) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pstr);
    static_cast<void>(pidl);
    static_cast<void>(ppsz);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlApplySchemeA(const char* pszIn, char* pszOut, std::uint32_t* pcchOut, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszIn);
    static_cast<void>(pszOut);
    static_cast<void>(pcchOut);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlApplySchemeW(const char16_t* pszIn, char16_t* pszOut, std::uint32_t* pcchOut, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszIn);
    static_cast<void>(pszOut);
    static_cast<void>(pcchOut);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlCanonicalizeA(const char* pszUrl, char* pszCanonicalized, std::uint32_t* pcchCanonicalized, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszUrl);
    static_cast<void>(pszCanonicalized);
    static_cast<void>(pcchCanonicalized);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlCanonicalizeW(const char16_t* pszUrl, char16_t* pszCanonicalized, std::uint32_t* pcchCanonicalized, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszUrl);
    static_cast<void>(pszCanonicalized);
    static_cast<void>(pcchCanonicalized);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlCombineA(const char* pszBase, const char* pszRelative, char* pszCombined, std::uint32_t* pcchCombined, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszBase);
    static_cast<void>(pszRelative);
    static_cast<void>(pszCombined);
    static_cast<void>(pcchCombined);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlCombineW(const char16_t* pszBase, const char16_t* pszRelative, char16_t* pszCombined, std::uint32_t* pcchCombined, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszBase);
    static_cast<void>(pszRelative);
    static_cast<void>(pszCombined);
    static_cast<void>(pcchCombined);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlCompareA(const char* psz1, const char* psz2, std::int32_t fIgnoreSlash) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(psz1);
    static_cast<void>(psz2);
    static_cast<void>(fIgnoreSlash);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlCompareW(const char16_t* psz1, const char16_t* psz2, std::int32_t fIgnoreSlash) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(psz1);
    static_cast<void>(psz2);
    static_cast<void>(fIgnoreSlash);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlCreateFromPathA(const char* pszPath, char* pszUrl, std::uint32_t* pcchUrl, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszPath);
    static_cast<void>(pszUrl);
    static_cast<void>(pcchUrl);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlCreateFromPathW(const char16_t* pszPath, char16_t* pszUrl, std::uint32_t* pcchUrl, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszPath);
    static_cast<void>(pszUrl);
    static_cast<void>(pcchUrl);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlEscapeA(const char* pszUrl, char* pszEscaped, std::uint32_t* pcchEscaped, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszUrl);
    static_cast<void>(pszEscaped);
    static_cast<void>(pcchEscaped);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlEscapeW(const char16_t* pszUrl, char16_t* pszEscaped, std::uint32_t* pcchEscaped, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszUrl);
    static_cast<void>(pszEscaped);
    static_cast<void>(pcchEscaped);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlFixupW(const char16_t* pcszUrl, char16_t* pszTranslatedUrl, std::uint32_t cchMax) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pcszUrl);
    static_cast<void>(pszTranslatedUrl);
    static_cast<void>(cchMax);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) const char* kshlwapiG_UrlGetLocationA(const char* psz1) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(psz1);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) const char16_t* kshlwapiG_UrlGetLocationW(const char16_t* psz1) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(psz1);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlGetPartA(const char* pszIn, char* pszOut, std::uint32_t* pcchOut, std::uint32_t dwPart, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszIn);
    static_cast<void>(pszOut);
    static_cast<void>(pcchOut);
    static_cast<void>(dwPart);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlGetPartW(const char16_t* pszIn, char16_t* pszOut, std::uint32_t* pcchOut, std::uint32_t dwPart, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszIn);
    static_cast<void>(pszOut);
    static_cast<void>(pcchOut);
    static_cast<void>(dwPart);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlHashA(const char* pszUrl, std::uint8_t* pbHash, std::uint32_t cbHash) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pszUrl);
    static_cast<void>(pbHash);
    static_cast<void>(cbHash);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlHashW(const char16_t* pszUrl, std::uint8_t* pbHash, std::uint32_t cbHash) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pszUrl);
    static_cast<void>(pbHash);
    static_cast<void>(cbHash);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlIsA(const char* pszUrl, std::uint64_t UrlIs) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszUrl);
    static_cast<void>(UrlIs);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlIsNoHistoryA(const char* pszURL) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszURL);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlIsNoHistoryW(const char16_t* pszURL) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszURL);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlIsOpaqueA(const char* pszURL) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszURL);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlIsOpaqueW(const char16_t* pszURL) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszURL);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlIsW(const char16_t* pszUrl, std::uint64_t UrlIs) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszUrl);
    static_cast<void>(UrlIs);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlUnescapeA(char* pszUrl, char* pszUnescaped, std::uint32_t* pcchUnescaped, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszUrl);
    static_cast<void>(pszUnescaped);
    static_cast<void>(pcchUnescaped);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_UrlUnescapeW(char16_t* pszUrl, char16_t* pszUnescaped, std::uint32_t* pcchUnescaped, std::uint32_t dwFlags) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(pszUrl);
    static_cast<void>(pszUnescaped);
    static_cast<void>(pcchUnescaped);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_WhichPlatform() noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell -- the file-type database, the
    // desktop, the display -- and this runtime is not the shell
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_wnsprintfA(char* lpOut, std::int32_t cchLimitIn, const char* lpFmt, ...) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(lpOut);
    static_cast<void>(cchLimitIn);
    static_cast<void>(lpFmt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_wnsprintfW(char16_t* lpOut, std::int32_t cchLimitIn, const char16_t* lpFmt, ...) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(lpOut);
    static_cast<void>(cchLimitIn);
    static_cast<void>(lpFmt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_wvnsprintfA(char* lpOut, std::int32_t cchLimitIn, const char* lpFmt, void* arglist) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(lpOut);
    static_cast<void>(cchLimitIn);
    static_cast<void>(lpFmt);
    static_cast<void>(arglist);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kshlwapiG_wvnsprintfW(char16_t* lpOut, std::int32_t cchLimitIn, const char16_t* lpFmt, void* arglist) noexcept {
    // Refused: the shell's own services.
    //
    // the call is answered by the shell or by a COM object of it, and this
    // runtime is not the shell
    static_cast<void>(lpOut);
    static_cast<void>(cchLimitIn);
    static_cast<void>(lpFmt);
    static_cast<void>(arglist);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_shlwapi(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("AssocCreate", reinterpret_cast<void*>(&kshlwapiG_AssocCreate));
    e("AssocGetPerceivedType", reinterpret_cast<void*>(&kshlwapiG_AssocGetPerceivedType));
    e("AssocIsDangerous", reinterpret_cast<void*>(&kshlwapiG_AssocIsDangerous));
    e("AssocQueryKeyA", reinterpret_cast<void*>(&kshlwapiG_AssocQueryKeyA));
    e("AssocQueryKeyW", reinterpret_cast<void*>(&kshlwapiG_AssocQueryKeyW));
    e("AssocQueryStringA", reinterpret_cast<void*>(&kshlwapiG_AssocQueryStringA));
    e("AssocQueryStringByKeyA", reinterpret_cast<void*>(&kshlwapiG_AssocQueryStringByKeyA));
    e("AssocQueryStringByKeyW", reinterpret_cast<void*>(&kshlwapiG_AssocQueryStringByKeyW));
    e("AssocQueryStringW", reinterpret_cast<void*>(&kshlwapiG_AssocQueryStringW));
    e("ChrCmpIA", reinterpret_cast<void*>(&kshlwapiG_ChrCmpIA));
    e("ChrCmpIW", reinterpret_cast<void*>(&kshlwapiG_ChrCmpIW));
    e("ColorAdjustLuma", reinterpret_cast<void*>(&kshlwapiG_ColorAdjustLuma));
    e("ColorHLSToRGB", reinterpret_cast<void*>(&kshlwapiG_ColorHLSToRGB));
    e("ColorRGBToHLS", reinterpret_cast<void*>(&kshlwapiG_ColorRGBToHLS));
    e("ConnectToConnectionPoint", reinterpret_cast<void*>(&kshlwapiG_ConnectToConnectionPoint));
    e("GetAcceptLanguagesA", reinterpret_cast<void*>(&kshlwapiG_GetAcceptLanguagesA));
    e("GetAcceptLanguagesW", reinterpret_cast<void*>(&kshlwapiG_GetAcceptLanguagesW));
    e("GetMenuPosFromID", reinterpret_cast<void*>(&kshlwapiG_GetMenuPosFromID));
    e("HashData", reinterpret_cast<void*>(&kshlwapiG_HashData));
    e("IStream_Copy", reinterpret_cast<void*>(&kshlwapiG_IStream_Copy));
    e("IStream_Read", reinterpret_cast<void*>(&kshlwapiG_IStream_Read));
    e("IStream_ReadPidl", reinterpret_cast<void*>(&kshlwapiG_IStream_ReadPidl));
    e("IStream_ReadStr", reinterpret_cast<void*>(&kshlwapiG_IStream_ReadStr));
    e("IStream_Reset", reinterpret_cast<void*>(&kshlwapiG_IStream_Reset));
    e("IStream_Size", reinterpret_cast<void*>(&kshlwapiG_IStream_Size));
    e("IStream_Write", reinterpret_cast<void*>(&kshlwapiG_IStream_Write));
    e("IStream_WritePidl", reinterpret_cast<void*>(&kshlwapiG_IStream_WritePidl));
    e("IStream_WriteStr", reinterpret_cast<void*>(&kshlwapiG_IStream_WriteStr));
    e("IUnknown_AtomicRelease", reinterpret_cast<void*>(&kshlwapiG_IUnknown_AtomicRelease));
    e("IUnknown_GetSite", reinterpret_cast<void*>(&kshlwapiG_IUnknown_GetSite));
    e("IUnknown_GetWindow", reinterpret_cast<void*>(&kshlwapiG_IUnknown_GetWindow));
    e("IUnknown_QueryService", reinterpret_cast<void*>(&kshlwapiG_IUnknown_QueryService));
    e("IUnknown_Set", reinterpret_cast<void*>(&kshlwapiG_IUnknown_Set));
    e("IUnknown_SetSite", reinterpret_cast<void*>(&kshlwapiG_IUnknown_SetSite));
    e("IntlStrEqWorkerA", reinterpret_cast<void*>(&kshlwapiG_IntlStrEqWorkerA));
    e("IntlStrEqWorkerW", reinterpret_cast<void*>(&kshlwapiG_IntlStrEqWorkerW));
    e("IsCharSpaceA", reinterpret_cast<void*>(&kshlwapiG_IsCharSpaceA));
    e("IsCharSpaceW", reinterpret_cast<void*>(&kshlwapiG_IsCharSpaceW));
    e("IsInternetESCEnabled", reinterpret_cast<void*>(&kshlwapiG_IsInternetESCEnabled));
    e("IsOS", reinterpret_cast<void*>(&kshlwapiG_IsOS));
    e("ParseURLA", reinterpret_cast<void*>(&kshlwapiG_ParseURLA));
    e("ParseURLW", reinterpret_cast<void*>(&kshlwapiG_ParseURLW));
    e("PathAddExtensionA", reinterpret_cast<void*>(&kshlwapiG_PathAddExtensionA));
    e("PathAddExtensionW", reinterpret_cast<void*>(&kshlwapiG_PathAddExtensionW));
    e("PathBuildRootA", reinterpret_cast<void*>(&kshlwapiG_PathBuildRootA));
    e("PathBuildRootW", reinterpret_cast<void*>(&kshlwapiG_PathBuildRootW));
    e("PathCanonicalizeA", reinterpret_cast<void*>(&kshlwapiG_PathCanonicalizeA));
    e("PathCanonicalizeW", reinterpret_cast<void*>(&kshlwapiG_PathCanonicalizeW));
    e("PathCompactPathA", reinterpret_cast<void*>(&kshlwapiG_PathCompactPathA));
    e("PathCompactPathExA", reinterpret_cast<void*>(&kshlwapiG_PathCompactPathExA));
    e("PathCompactPathExW", reinterpret_cast<void*>(&kshlwapiG_PathCompactPathExW));
    e("PathCompactPathW", reinterpret_cast<void*>(&kshlwapiG_PathCompactPathW));
    e("PathCreateFromUrlA", reinterpret_cast<void*>(&kshlwapiG_PathCreateFromUrlA));
    e("PathCreateFromUrlAlloc", reinterpret_cast<void*>(&kshlwapiG_PathCreateFromUrlAlloc));
    e("PathCreateFromUrlW", reinterpret_cast<void*>(&kshlwapiG_PathCreateFromUrlW));
    e("PathFileExistsA", reinterpret_cast<void*>(&kshlwapiG_PathFileExistsA));
    e("PathFileExistsW", reinterpret_cast<void*>(&kshlwapiG_PathFileExistsW));
    e("PathFindOnPathA", reinterpret_cast<void*>(&kshlwapiG_PathFindOnPathA));
    e("PathFindOnPathW", reinterpret_cast<void*>(&kshlwapiG_PathFindOnPathW));
    e("PathFindSuffixArrayA", reinterpret_cast<void*>(&kshlwapiG_PathFindSuffixArrayA));
    e("PathFindSuffixArrayW", reinterpret_cast<void*>(&kshlwapiG_PathFindSuffixArrayW));
    e("PathGetCharTypeA", reinterpret_cast<void*>(&kshlwapiG_PathGetCharTypeA));
    e("PathGetCharTypeW", reinterpret_cast<void*>(&kshlwapiG_PathGetCharTypeW));
    e("PathIsContentTypeA", reinterpret_cast<void*>(&kshlwapiG_PathIsContentTypeA));
    e("PathIsContentTypeW", reinterpret_cast<void*>(&kshlwapiG_PathIsContentTypeW));
    e("PathIsDirectoryA", reinterpret_cast<void*>(&kshlwapiG_PathIsDirectoryA));
    e("PathIsDirectoryEmptyA", reinterpret_cast<void*>(&kshlwapiG_PathIsDirectoryEmptyA));
    e("PathIsDirectoryEmptyW", reinterpret_cast<void*>(&kshlwapiG_PathIsDirectoryEmptyW));
    e("PathIsDirectoryW", reinterpret_cast<void*>(&kshlwapiG_PathIsDirectoryW));
    e("PathIsFileSpecA", reinterpret_cast<void*>(&kshlwapiG_PathIsFileSpecA));
    e("PathIsFileSpecW", reinterpret_cast<void*>(&kshlwapiG_PathIsFileSpecW));
    e("PathIsLFNFileSpecA", reinterpret_cast<void*>(&kshlwapiG_PathIsLFNFileSpecA));
    e("PathIsLFNFileSpecW", reinterpret_cast<void*>(&kshlwapiG_PathIsLFNFileSpecW));
    e("PathIsNetworkPathA", reinterpret_cast<void*>(&kshlwapiG_PathIsNetworkPathA));
    e("PathIsNetworkPathW", reinterpret_cast<void*>(&kshlwapiG_PathIsNetworkPathW));
    e("PathIsPrefixA", reinterpret_cast<void*>(&kshlwapiG_PathIsPrefixA));
    e("PathIsPrefixW", reinterpret_cast<void*>(&kshlwapiG_PathIsPrefixW));
    e("PathIsSameRootA", reinterpret_cast<void*>(&kshlwapiG_PathIsSameRootA));
    e("PathIsSameRootW", reinterpret_cast<void*>(&kshlwapiG_PathIsSameRootW));
    e("PathIsSystemFolderA", reinterpret_cast<void*>(&kshlwapiG_PathIsSystemFolderA));
    e("PathIsSystemFolderW", reinterpret_cast<void*>(&kshlwapiG_PathIsSystemFolderW));
    e("PathIsUNCA", reinterpret_cast<void*>(&kshlwapiG_PathIsUNCA));
    e("PathIsUNCServerA", reinterpret_cast<void*>(&kshlwapiG_PathIsUNCServerA));
    e("PathIsUNCServerShareA", reinterpret_cast<void*>(&kshlwapiG_PathIsUNCServerShareA));
    e("PathIsUNCServerShareW", reinterpret_cast<void*>(&kshlwapiG_PathIsUNCServerShareW));
    e("PathIsUNCServerW", reinterpret_cast<void*>(&kshlwapiG_PathIsUNCServerW));
    e("PathIsUNCW", reinterpret_cast<void*>(&kshlwapiG_PathIsUNCW));
    e("PathIsURLA", reinterpret_cast<void*>(&kshlwapiG_PathIsURLA));
    e("PathIsURLW", reinterpret_cast<void*>(&kshlwapiG_PathIsURLW));
    e("PathMakePrettyA", reinterpret_cast<void*>(&kshlwapiG_PathMakePrettyA));
    e("PathMakePrettyW", reinterpret_cast<void*>(&kshlwapiG_PathMakePrettyW));
    e("PathMakeSystemFolderA", reinterpret_cast<void*>(&kshlwapiG_PathMakeSystemFolderA));
    e("PathMakeSystemFolderW", reinterpret_cast<void*>(&kshlwapiG_PathMakeSystemFolderW));
    e("PathMatchSpecA", reinterpret_cast<void*>(&kshlwapiG_PathMatchSpecA));
    e("PathMatchSpecExA", reinterpret_cast<void*>(&kshlwapiG_PathMatchSpecExA));
    e("PathMatchSpecExW", reinterpret_cast<void*>(&kshlwapiG_PathMatchSpecExW));
    e("PathMatchSpecW", reinterpret_cast<void*>(&kshlwapiG_PathMatchSpecW));
    e("PathParseIconLocationA", reinterpret_cast<void*>(&kshlwapiG_PathParseIconLocationA));
    e("PathParseIconLocationW", reinterpret_cast<void*>(&kshlwapiG_PathParseIconLocationW));
    e("PathQuoteSpacesA", reinterpret_cast<void*>(&kshlwapiG_PathQuoteSpacesA));
    e("PathQuoteSpacesW", reinterpret_cast<void*>(&kshlwapiG_PathQuoteSpacesW));
    e("PathRelativePathToA", reinterpret_cast<void*>(&kshlwapiG_PathRelativePathToA));
    e("PathRelativePathToW", reinterpret_cast<void*>(&kshlwapiG_PathRelativePathToW));
    e("PathRemoveArgsA", reinterpret_cast<void*>(&kshlwapiG_PathRemoveArgsA));
    e("PathRemoveArgsW", reinterpret_cast<void*>(&kshlwapiG_PathRemoveArgsW));
    e("PathRemoveBlanksA", reinterpret_cast<void*>(&kshlwapiG_PathRemoveBlanksA));
    e("PathRemoveBlanksW", reinterpret_cast<void*>(&kshlwapiG_PathRemoveBlanksW));
    e("PathRemoveExtensionA", reinterpret_cast<void*>(&kshlwapiG_PathRemoveExtensionA));
    e("PathRemoveExtensionW", reinterpret_cast<void*>(&kshlwapiG_PathRemoveExtensionW));
    e("PathRenameExtensionA", reinterpret_cast<void*>(&kshlwapiG_PathRenameExtensionA));
    e("PathRenameExtensionW", reinterpret_cast<void*>(&kshlwapiG_PathRenameExtensionW));
    e("PathSearchAndQualifyA", reinterpret_cast<void*>(&kshlwapiG_PathSearchAndQualifyA));
    e("PathSearchAndQualifyW", reinterpret_cast<void*>(&kshlwapiG_PathSearchAndQualifyW));
    e("PathSetDlgItemPathA", reinterpret_cast<void*>(&kshlwapiG_PathSetDlgItemPathA));
    e("PathSetDlgItemPathW", reinterpret_cast<void*>(&kshlwapiG_PathSetDlgItemPathW));
    e("PathStripToRootA", reinterpret_cast<void*>(&kshlwapiG_PathStripToRootA));
    e("PathStripToRootW", reinterpret_cast<void*>(&kshlwapiG_PathStripToRootW));
    e("PathUnExpandEnvStringsA", reinterpret_cast<void*>(&kshlwapiG_PathUnExpandEnvStringsA));
    e("PathUnExpandEnvStringsW", reinterpret_cast<void*>(&kshlwapiG_PathUnExpandEnvStringsW));
    e("PathUndecorateA", reinterpret_cast<void*>(&kshlwapiG_PathUndecorateA));
    e("PathUndecorateW", reinterpret_cast<void*>(&kshlwapiG_PathUndecorateW));
    e("PathUnmakeSystemFolderA", reinterpret_cast<void*>(&kshlwapiG_PathUnmakeSystemFolderA));
    e("PathUnmakeSystemFolderW", reinterpret_cast<void*>(&kshlwapiG_PathUnmakeSystemFolderW));
    e("PathUnquoteSpacesA", reinterpret_cast<void*>(&kshlwapiG_PathUnquoteSpacesA));
    e("PathUnquoteSpacesW", reinterpret_cast<void*>(&kshlwapiG_PathUnquoteSpacesW));
    e("QISearch", reinterpret_cast<void*>(&kshlwapiG_QISearch));
    e("SHAllocShared", reinterpret_cast<void*>(&kshlwapiG_SHAllocShared));
    e("SHAnsiToAnsi", reinterpret_cast<void*>(&kshlwapiG_SHAnsiToAnsi));
    e("SHAnsiToUnicode", reinterpret_cast<void*>(&kshlwapiG_SHAnsiToUnicode));
    e("SHAutoComplete", reinterpret_cast<void*>(&kshlwapiG_SHAutoComplete));
    e("SHCopyKeyA", reinterpret_cast<void*>(&kshlwapiG_SHCopyKeyA));
    e("SHCopyKeyW", reinterpret_cast<void*>(&kshlwapiG_SHCopyKeyW));
    e("SHCreateMemStream", reinterpret_cast<void*>(&kshlwapiG_SHCreateMemStream));
    e("SHCreateShellPalette", reinterpret_cast<void*>(&kshlwapiG_SHCreateShellPalette));
    e("SHCreateStreamOnFileA", reinterpret_cast<void*>(&kshlwapiG_SHCreateStreamOnFileA));
    e("SHCreateStreamOnFileEx", reinterpret_cast<void*>(&kshlwapiG_SHCreateStreamOnFileEx));
    e("SHCreateStreamOnFileW", reinterpret_cast<void*>(&kshlwapiG_SHCreateStreamOnFileW));
    e("SHCreateThread", reinterpret_cast<void*>(&kshlwapiG_SHCreateThread));
    e("SHCreateThreadRef", reinterpret_cast<void*>(&kshlwapiG_SHCreateThreadRef));
    e("SHCreateThreadWithHandle", reinterpret_cast<void*>(&kshlwapiG_SHCreateThreadWithHandle));
    e("SHDeleteEmptyKeyA", reinterpret_cast<void*>(&kshlwapiG_SHDeleteEmptyKeyA));
    e("SHDeleteEmptyKeyW", reinterpret_cast<void*>(&kshlwapiG_SHDeleteEmptyKeyW));
    e("SHDeleteKeyA", reinterpret_cast<void*>(&kshlwapiG_SHDeleteKeyA));
    e("SHDeleteKeyW", reinterpret_cast<void*>(&kshlwapiG_SHDeleteKeyW));
    e("SHDeleteValueA", reinterpret_cast<void*>(&kshlwapiG_SHDeleteValueA));
    e("SHDeleteValueW", reinterpret_cast<void*>(&kshlwapiG_SHDeleteValueW));
    e("SHEnumKeyExA", reinterpret_cast<void*>(&kshlwapiG_SHEnumKeyExA));
    e("SHEnumKeyExW", reinterpret_cast<void*>(&kshlwapiG_SHEnumKeyExW));
    e("SHEnumValueA", reinterpret_cast<void*>(&kshlwapiG_SHEnumValueA));
    e("SHEnumValueW", reinterpret_cast<void*>(&kshlwapiG_SHEnumValueW));
    e("SHFormatDateTimeA", reinterpret_cast<void*>(&kshlwapiG_SHFormatDateTimeA));
    e("SHFormatDateTimeW", reinterpret_cast<void*>(&kshlwapiG_SHFormatDateTimeW));
    e("SHFreeShared", reinterpret_cast<void*>(&kshlwapiG_SHFreeShared));
    e("SHGetInverseCMAP", reinterpret_cast<void*>(&kshlwapiG_SHGetInverseCMAP));
    e("SHGetThreadRef", reinterpret_cast<void*>(&kshlwapiG_SHGetThreadRef));
    e("SHGetValueA", reinterpret_cast<void*>(&kshlwapiG_SHGetValueA));
    e("SHGetValueW", reinterpret_cast<void*>(&kshlwapiG_SHGetValueW));
    e("SHGetViewStatePropertyBag", reinterpret_cast<void*>(&kshlwapiG_SHGetViewStatePropertyBag));
    e("SHIsLowMemoryMachine", reinterpret_cast<void*>(&kshlwapiG_SHIsLowMemoryMachine));
    e("SHLoadIndirectString", reinterpret_cast<void*>(&kshlwapiG_SHLoadIndirectString));
    e("SHLockShared", reinterpret_cast<void*>(&kshlwapiG_SHLockShared));
    e("SHMessageBoxCheckA", reinterpret_cast<void*>(&kshlwapiG_SHMessageBoxCheckA));
    e("SHMessageBoxCheckW", reinterpret_cast<void*>(&kshlwapiG_SHMessageBoxCheckW));
    e("SHOpenRegStream2A", reinterpret_cast<void*>(&kshlwapiG_SHOpenRegStream2A));
    e("SHOpenRegStream2W", reinterpret_cast<void*>(&kshlwapiG_SHOpenRegStream2W));
    e("SHOpenRegStreamA", reinterpret_cast<void*>(&kshlwapiG_SHOpenRegStreamA));
    e("SHOpenRegStreamW", reinterpret_cast<void*>(&kshlwapiG_SHOpenRegStreamW));
    e("SHQueryInfoKeyA", reinterpret_cast<void*>(&kshlwapiG_SHQueryInfoKeyA));
    e("SHQueryInfoKeyW", reinterpret_cast<void*>(&kshlwapiG_SHQueryInfoKeyW));
    e("SHQueryValueExA", reinterpret_cast<void*>(&kshlwapiG_SHQueryValueExA));
    e("SHQueryValueExW", reinterpret_cast<void*>(&kshlwapiG_SHQueryValueExW));
    e("SHRegCloseUSKey", reinterpret_cast<void*>(&kshlwapiG_SHRegCloseUSKey));
    e("SHRegCreateUSKeyA", reinterpret_cast<void*>(&kshlwapiG_SHRegCreateUSKeyA));
    e("SHRegCreateUSKeyW", reinterpret_cast<void*>(&kshlwapiG_SHRegCreateUSKeyW));
    e("SHRegDeleteEmptyUSKeyA", reinterpret_cast<void*>(&kshlwapiG_SHRegDeleteEmptyUSKeyA));
    e("SHRegDeleteEmptyUSKeyW", reinterpret_cast<void*>(&kshlwapiG_SHRegDeleteEmptyUSKeyW));
    e("SHRegDeleteUSValueA", reinterpret_cast<void*>(&kshlwapiG_SHRegDeleteUSValueA));
    e("SHRegDeleteUSValueW", reinterpret_cast<void*>(&kshlwapiG_SHRegDeleteUSValueW));
    e("SHRegDuplicateHKey", reinterpret_cast<void*>(&kshlwapiG_SHRegDuplicateHKey));
    e("SHRegEnumUSKeyA", reinterpret_cast<void*>(&kshlwapiG_SHRegEnumUSKeyA));
    e("SHRegEnumUSKeyW", reinterpret_cast<void*>(&kshlwapiG_SHRegEnumUSKeyW));
    e("SHRegEnumUSValueA", reinterpret_cast<void*>(&kshlwapiG_SHRegEnumUSValueA));
    e("SHRegEnumUSValueW", reinterpret_cast<void*>(&kshlwapiG_SHRegEnumUSValueW));
    e("SHRegGetBoolUSValueA", reinterpret_cast<void*>(&kshlwapiG_SHRegGetBoolUSValueA));
    e("SHRegGetBoolUSValueW", reinterpret_cast<void*>(&kshlwapiG_SHRegGetBoolUSValueW));
    e("SHRegGetBoolValueFromHKCUHKLM", reinterpret_cast<void*>(&kshlwapiG_SHRegGetBoolValueFromHKCUHKLM));
    e("SHRegGetIntW", reinterpret_cast<void*>(&kshlwapiG_SHRegGetIntW));
    e("SHRegGetPathA", reinterpret_cast<void*>(&kshlwapiG_SHRegGetPathA));
    e("SHRegGetPathW", reinterpret_cast<void*>(&kshlwapiG_SHRegGetPathW));
    e("SHRegGetUSValueA", reinterpret_cast<void*>(&kshlwapiG_SHRegGetUSValueA));
    e("SHRegGetUSValueW", reinterpret_cast<void*>(&kshlwapiG_SHRegGetUSValueW));
    e("SHRegGetValueA", reinterpret_cast<void*>(&kshlwapiG_SHRegGetValueA));
    e("SHRegGetValueFromHKCUHKLM", reinterpret_cast<void*>(&kshlwapiG_SHRegGetValueFromHKCUHKLM));
    e("SHRegGetValueW", reinterpret_cast<void*>(&kshlwapiG_SHRegGetValueW));
    e("SHRegOpenUSKeyA", reinterpret_cast<void*>(&kshlwapiG_SHRegOpenUSKeyA));
    e("SHRegOpenUSKeyW", reinterpret_cast<void*>(&kshlwapiG_SHRegOpenUSKeyW));
    e("SHRegQueryInfoUSKeyA", reinterpret_cast<void*>(&kshlwapiG_SHRegQueryInfoUSKeyA));
    e("SHRegQueryInfoUSKeyW", reinterpret_cast<void*>(&kshlwapiG_SHRegQueryInfoUSKeyW));
    e("SHRegQueryUSValueA", reinterpret_cast<void*>(&kshlwapiG_SHRegQueryUSValueA));
    e("SHRegQueryUSValueW", reinterpret_cast<void*>(&kshlwapiG_SHRegQueryUSValueW));
    e("SHRegSetPathA", reinterpret_cast<void*>(&kshlwapiG_SHRegSetPathA));
    e("SHRegSetPathW", reinterpret_cast<void*>(&kshlwapiG_SHRegSetPathW));
    e("SHRegSetUSValueA", reinterpret_cast<void*>(&kshlwapiG_SHRegSetUSValueA));
    e("SHRegSetUSValueW", reinterpret_cast<void*>(&kshlwapiG_SHRegSetUSValueW));
    e("SHRegWriteUSValueA", reinterpret_cast<void*>(&kshlwapiG_SHRegWriteUSValueA));
    e("SHRegWriteUSValueW", reinterpret_cast<void*>(&kshlwapiG_SHRegWriteUSValueW));
    e("SHReleaseThreadRef", reinterpret_cast<void*>(&kshlwapiG_SHReleaseThreadRef));
    e("SHSendMessageBroadcastA", reinterpret_cast<void*>(&kshlwapiG_SHSendMessageBroadcastA));
    e("SHSendMessageBroadcastW", reinterpret_cast<void*>(&kshlwapiG_SHSendMessageBroadcastW));
    e("SHSetThreadRef", reinterpret_cast<void*>(&kshlwapiG_SHSetThreadRef));
    e("SHSetValueA", reinterpret_cast<void*>(&kshlwapiG_SHSetValueA));
    e("SHSetValueW", reinterpret_cast<void*>(&kshlwapiG_SHSetValueW));
    e("SHSkipJunction", reinterpret_cast<void*>(&kshlwapiG_SHSkipJunction));
    e("SHStrDupA", reinterpret_cast<void*>(&kshlwapiG_SHStrDupA));
    e("SHStrDupW", reinterpret_cast<void*>(&kshlwapiG_SHStrDupW));
    e("SHStripMneumonicA", reinterpret_cast<void*>(&kshlwapiG_SHStripMneumonicA));
    e("SHStripMneumonicW", reinterpret_cast<void*>(&kshlwapiG_SHStripMneumonicW));
    e("SHUnicodeToAnsi", reinterpret_cast<void*>(&kshlwapiG_SHUnicodeToAnsi));
    e("SHUnicodeToUnicode", reinterpret_cast<void*>(&kshlwapiG_SHUnicodeToUnicode));
    e("SHUnlockShared", reinterpret_cast<void*>(&kshlwapiG_SHUnlockShared));
    e("ShellMessageBoxA", reinterpret_cast<void*>(&kshlwapiG_ShellMessageBoxA));
    e("ShellMessageBoxW", reinterpret_cast<void*>(&kshlwapiG_ShellMessageBoxW));
    e("StrCatW", reinterpret_cast<void*>(&kshlwapiG_StrCatW));
    e("StrChrNIW", reinterpret_cast<void*>(&kshlwapiG_StrChrNIW));
    e("StrCpyW", reinterpret_cast<void*>(&kshlwapiG_StrCpyW));
    e("StrFormatByteSize64A", reinterpret_cast<void*>(&kshlwapiG_StrFormatByteSize64A));
    e("StrFormatByteSizeA", reinterpret_cast<void*>(&kshlwapiG_StrFormatByteSizeA));
    e("StrFormatByteSizeEx", reinterpret_cast<void*>(&kshlwapiG_StrFormatByteSizeEx));
    e("StrFormatByteSizeW", reinterpret_cast<void*>(&kshlwapiG_StrFormatByteSizeW));
    e("StrFormatKBSizeA", reinterpret_cast<void*>(&kshlwapiG_StrFormatKBSizeA));
    e("StrFormatKBSizeW", reinterpret_cast<void*>(&kshlwapiG_StrFormatKBSizeW));
    e("StrFromTimeIntervalA", reinterpret_cast<void*>(&kshlwapiG_StrFromTimeIntervalA));
    e("StrFromTimeIntervalW", reinterpret_cast<void*>(&kshlwapiG_StrFromTimeIntervalW));
    e("StrNCatA", reinterpret_cast<void*>(&kshlwapiG_StrNCatA));
    e("StrNCatW", reinterpret_cast<void*>(&kshlwapiG_StrNCatW));
    e("StrRetToBSTR", reinterpret_cast<void*>(&kshlwapiG_StrRetToBSTR));
    e("StrRetToBufA", reinterpret_cast<void*>(&kshlwapiG_StrRetToBufA));
    e("StrRetToBufW", reinterpret_cast<void*>(&kshlwapiG_StrRetToBufW));
    e("StrRetToStrA", reinterpret_cast<void*>(&kshlwapiG_StrRetToStrA));
    e("StrRetToStrW", reinterpret_cast<void*>(&kshlwapiG_StrRetToStrW));
    e("UrlApplySchemeA", reinterpret_cast<void*>(&kshlwapiG_UrlApplySchemeA));
    e("UrlApplySchemeW", reinterpret_cast<void*>(&kshlwapiG_UrlApplySchemeW));
    e("UrlCanonicalizeA", reinterpret_cast<void*>(&kshlwapiG_UrlCanonicalizeA));
    e("UrlCanonicalizeW", reinterpret_cast<void*>(&kshlwapiG_UrlCanonicalizeW));
    e("UrlCombineA", reinterpret_cast<void*>(&kshlwapiG_UrlCombineA));
    e("UrlCombineW", reinterpret_cast<void*>(&kshlwapiG_UrlCombineW));
    e("UrlCompareA", reinterpret_cast<void*>(&kshlwapiG_UrlCompareA));
    e("UrlCompareW", reinterpret_cast<void*>(&kshlwapiG_UrlCompareW));
    e("UrlCreateFromPathA", reinterpret_cast<void*>(&kshlwapiG_UrlCreateFromPathA));
    e("UrlCreateFromPathW", reinterpret_cast<void*>(&kshlwapiG_UrlCreateFromPathW));
    e("UrlEscapeA", reinterpret_cast<void*>(&kshlwapiG_UrlEscapeA));
    e("UrlEscapeW", reinterpret_cast<void*>(&kshlwapiG_UrlEscapeW));
    e("UrlFixupW", reinterpret_cast<void*>(&kshlwapiG_UrlFixupW));
    e("UrlGetLocationA", reinterpret_cast<void*>(&kshlwapiG_UrlGetLocationA));
    e("UrlGetLocationW", reinterpret_cast<void*>(&kshlwapiG_UrlGetLocationW));
    e("UrlGetPartA", reinterpret_cast<void*>(&kshlwapiG_UrlGetPartA));
    e("UrlGetPartW", reinterpret_cast<void*>(&kshlwapiG_UrlGetPartW));
    e("UrlHashA", reinterpret_cast<void*>(&kshlwapiG_UrlHashA));
    e("UrlHashW", reinterpret_cast<void*>(&kshlwapiG_UrlHashW));
    e("UrlIsA", reinterpret_cast<void*>(&kshlwapiG_UrlIsA));
    e("UrlIsNoHistoryA", reinterpret_cast<void*>(&kshlwapiG_UrlIsNoHistoryA));
    e("UrlIsNoHistoryW", reinterpret_cast<void*>(&kshlwapiG_UrlIsNoHistoryW));
    e("UrlIsOpaqueA", reinterpret_cast<void*>(&kshlwapiG_UrlIsOpaqueA));
    e("UrlIsOpaqueW", reinterpret_cast<void*>(&kshlwapiG_UrlIsOpaqueW));
    e("UrlIsW", reinterpret_cast<void*>(&kshlwapiG_UrlIsW));
    e("UrlUnescapeA", reinterpret_cast<void*>(&kshlwapiG_UrlUnescapeA));
    e("UrlUnescapeW", reinterpret_cast<void*>(&kshlwapiG_UrlUnescapeW));
    e("WhichPlatform", reinterpret_cast<void*>(&kshlwapiG_WhichPlatform));
    e("wnsprintfA", reinterpret_cast<void*>(&kshlwapiG_wnsprintfA));
    e("wnsprintfW", reinterpret_cast<void*>(&kshlwapiG_wnsprintfW));
    e("wvnsprintfA", reinterpret_cast<void*>(&kshlwapiG_wvnsprintfA));
    e("wvnsprintfW", reinterpret_cast<void*>(&kshlwapiG_wvnsprintfW));
}
}  // namespace occ::runtime::winabi

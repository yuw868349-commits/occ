// The KERNEL32 surface this runtime did not answer.
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

// ------------------------------------------------------------------ bits
//
// The bit-test family is defined in terms of the bit it names, so it is
// written over the width rather than over a type: every one of them takes a
// bit index that is allowed to be out of range, and the answer for an
// out-of-range index is what makes the family usable as a test.

template <typename W>
[[nodiscard]] bool bit_of(W value, std::int64_t index) noexcept {
    const std::int64_t width = static_cast<std::int64_t>(sizeof(W) * 8);
    if (index < 0 || index >= width) {
        return false;
    }
    return ((value >> index) & static_cast<W>(1)) != 0;
}

template <typename W>
void bit_set(W* value, std::int64_t index, bool on) noexcept {
    const std::int64_t width = static_cast<std::int64_t>(sizeof(W) * 8);
    if (value == nullptr || index < 0 || index >= width) {
        return;
    }
    const W mask = static_cast<W>(static_cast<W>(1) << index);
    if (on) {
        *value = static_cast<W>(*value | mask);
    } else {
        *value = static_cast<W>(*value & static_cast<W>(~mask));
    }
}

// The position of the lowest set bit, as `_BitScanForward` reports it: the
// answer says whether there was one, and the index is written only when
// there was.
[[nodiscard]] bool scan_forward(std::uint64_t mask, std::uint32_t* index) noexcept {
    if (mask == 0) {
        return false;
    }
    std::uint32_t at = 0;
    while (((mask >> at) & 1u) == 0u) {
        ++at;
    }
    *index = at;
    return true;
}

// The position of the highest set bit, as `_BitScanReverse` reports it.
[[nodiscard]] bool scan_reverse(std::uint64_t mask, std::uint32_t* index) noexcept {
    if (mask == 0) {
        return false;
    }
    std::uint32_t at = 63;
    while (((mask >> at) & 1u) == 0u) {
        --at;
    }
    *index = at;
    return true;
}

// A 128-bit product, as the signed and unsigned pairs below need it. The
// host's own wide type is what makes the multiply exact: `(a*b) >> shift`
// computed in 64 bits would be a different answer, and it is the answer a
// caller of these functions is trying to avoid.
[[nodiscard]] unsigned __int128 widen_product(std::uint64_t left,
                                              std::uint64_t right) noexcept {
    return static_cast<unsigned __int128>(left) *
           static_cast<unsigned __int128>(right);
}

// ------------------------------------------------------------------- ini
//
// The profile format. A file is a sequence of lines; a line is a section
// header, a key and a value, a comment, or nothing. The rules that matter
// and that a naive reader gets wrong are:
//
//   * a key and its value are separated by `=` or `:`, and the first of
//     either is the separator -- a colon inside a value is part of it;
//   * the blank space around both is not part of either;
//   * a line whose first non-blank character is `;` is a comment;
//   * a section name is bracketed, and the brackets are not part of it;
//   * a key reached before any section belongs to no section, and asking
//     for it under a name finds nothing.

// Whether a line is blank or a comment.
template <typename C>
[[nodiscard]] bool ini_line_ignorable(const C* line) noexcept {
    while (*line == static_cast<C>(' ') || *line == static_cast<C>('\t')) {
        ++line;
    }
    return *line == static_cast<C>(0) || *line == static_cast<C>(';') ||
           *line == static_cast<C>('#');
}

// The span of a line, as a pointer and a length, so that a reader does not
// have to write a terminator into the caller's file.
template <typename C>
struct IniSpan {
    const C* text = nullptr;
    std::size_t length = 0;
};

// The next line, and a cursor past it.
template <typename C>
[[nodiscard]] bool ini_next_line(const C* file, std::size_t size,
                                 std::size_t* cursor,
                                 IniSpan<C>* line) noexcept {
    if (*cursor >= size || file[*cursor] == static_cast<C>(0)) {
        return false;
    }
    std::size_t end = *cursor;
    while (end < size && file[end] != static_cast<C>(0) &&
           file[end] != static_cast<C>('\n') &&
           file[end] != static_cast<C>('\r')) {
        ++end;
    }
    line->text = file + *cursor;
    line->length = end - *cursor;
    while (end < size && (file[end] == static_cast<C>('\n') ||
                          file[end] == static_cast<C>('\r'))) {
        ++end;
    }
    *cursor = end;
    return true;
}

// The section a line introduces, or nothing.
template <typename C>
[[nodiscard]] bool ini_section_of(const IniSpan<C>& line,
                                  IniSpan<C>* name) noexcept {
    std::size_t at = 0;
    while (at < line.length && (line.text[at] == static_cast<C>(' ') ||
                               line.text[at] == static_cast<C>('\t'))) {
        ++at;
    }
    if (at >= line.length || line.text[at] != static_cast<C>('[')) {
        return false;
    }
    ++at;
    const std::size_t start = at;
    while (at < line.length && line.text[at] != static_cast<C>(']') &&
           line.text[at] != static_cast<C>('\n')) {
        ++at;
    }
    if (at >= line.length || line.text[at] != static_cast<C>(']')) {
        return false;
    }
    name->text = line.text + start;
    name->length = at - start;
    return true;
}

// The key and the value of a line, or nothing. Split at the first `=` or
// `:` that is not inside the key, with the blank space trimmed from both
// ends of both halves.
template <typename C>
[[nodiscard]] bool ini_pair_of(const IniSpan<C>& line, IniSpan<C>* key,
                               IniSpan<C>* value) noexcept {
    std::size_t at = 0;
    while (at < line.length && (line.text[at] == static_cast<C>(' ') ||
                               line.text[at] == static_cast<C>('\t'))) {
        ++at;
    }
    if (at >= line.length) {
        return false;
    }
    const std::size_t key_start = at;
    while (at < line.length && line.text[at] != static_cast<C>('=') &&
           line.text[at] != static_cast<C>(':') &&
           line.text[at] != static_cast<C>('\n')) {
        ++at;
    }
    if (at >= line.length) {
        return false;
    }
    std::size_t key_end = at;
    while (key_end > key_start && (line.text[key_end - 1] == static_cast<C>(' ') ||
                                  line.text[key_end - 1] == static_cast<C>('\t'))) {
        --key_end;
    }
    if (key_end == key_start) {
        return false;
    }
    ++at;  // past the separator
    while (at < line.length && (line.text[at] == static_cast<C>(' ') ||
                               line.text[at] == static_cast<C>('\t'))) {
        ++at;
    }
    std::size_t value_end = line.length;
    while (value_end > at && (line.text[value_end - 1] == static_cast<C>(' ') ||
                              line.text[value_end - 1] == static_cast<C>('\t'))) {
        --value_end;
    }
    key->text = line.text + key_start;
    key->length = key_end - key_start;
    value->text = line.text + at;
    value->length = value_end - at;
    return true;
}

// Case-insensitive comparison against a span, which is how the format's
// names behave: `[Section]` and `[SECTION]` name the same section.
template <typename C>
[[nodiscard]] bool ini_span_equals(const IniSpan<C>& span, const C* wanted,
                                   std::size_t wanted_length) noexcept {
    if (span.length != wanted_length) {
        return false;
    }
    for (std::size_t index = 0; index < wanted_length; ++index) {
        if (ch_lower_of(span.text[index]) != ch_lower_of(wanted[index])) {
            return false;
        }
    }
    return true;
}

// The number a profile key holds. The reference parses an optional sign and
// a run of digits, and stops at the first character that is neither --
// which is why `10` and `10xyz` both answer ten.
[[nodiscard]] std::int64_t ini_number(const char16_t* text,
                                      std::size_t length) noexcept {
    std::size_t at = 0;
    while (at < length && (text[at] == u' ' || text[at] == u'\t')) {
        ++at;
    }
    bool negative = false;
    if (at < length && (text[at] == u'-' || text[at] == u'+')) {
        negative = text[at] == u'-';
        ++at;
    }
    std::int64_t value = 0;
    bool any = false;
    while (at < length && ch_digit(text[at])) {
        any = true;
        value = value * 10 + static_cast<std::int64_t>(text[at] - u'0');
        ++at;
    }
    if (!any) {
        return 0;
    }
    return negative ? -value : value;
}

// The whole of a profile file, read through the runtime's own file calls so
// that the code page and the path translation are the same ones every other
// file call uses.
[[nodiscard]] bool read_profile_file(const char16_t* path,
                                     std::u16string* out) noexcept {
    char narrow[1024];
    if (path == nullptr) {
        return false;
    }
    static_cast<void>(narrow_text(path, narrow, 1024));
    void* file = cr_fopen(narrow, "rb");
    if (file == nullptr) {
        return false;
    }
    char buffer[4096];
    for (;;) {
        const std::uint64_t got = cr_fread(buffer, 1, sizeof(buffer), file);
        if (got == 0) {
            break;
        }
        out->reserve(out->size() + static_cast<std::size_t>(got));
        for (std::uint64_t index = 0; index < got; ++index) {
            out->push_back(static_cast<char16_t>(
                static_cast<unsigned char>(buffer[index])));
        }
    }
    static_cast<void>(cr_fclose(file));
    return true;
}

// The profile-file state: one flag for the code page the file APIs report,
// and one cookie for the pointer encoding. Both are process-wide and both
// are written only by the calls that own them.

[[nodiscard]] bool& file_api_code_page_is_ansi_flag() noexcept {
    static bool ansi = true;
    return ansi;
}
[[nodiscard]] bool file_api_code_page_is_ansi() noexcept {
    return file_api_code_page_is_ansi_flag();
}
void set_file_api_code_page(bool ansi) noexcept {
    file_api_code_page_is_ansi_flag() = ansi;
}

// The value the pointer encoder xors with. Its address is what makes it
// differ between processes; its value is not a secret and the API does not
// claim it is.
[[nodiscard]] std::uintptr_t pointer_cookie() noexcept {
    static std::uintptr_t cookie = 0;
    if (cookie == 0) {
        cookie = reinterpret_cast<std::uintptr_t>(&cookie) ^
                 0x5EED5EED5EED5EEDull;
    }
    return cookie;
}

// The day count between a calendar date and the epoch a `FILETIME` counts
// from, which is 1601-01-01. The walk is the standard civil-from-days
// algorithm, run backwards and forwards, because the two conversions have
// to agree about the leap years or a date near a boundary round-trips
// wrong.
[[nodiscard]] bool leap_year(std::uint64_t year) noexcept {
    return (year % 4u == 0 && year % 100u != 0) || year % 400u == 0;
}

[[nodiscard]] std::uint64_t days_before_year(std::uint64_t year) noexcept {
    const std::uint64_t previous = year - 1;
    return previous * 365u + previous / 4u - previous / 100u + previous / 400u;
}

[[nodiscard]] std::uint64_t days_before_month(std::uint64_t year,
                                              std::uint32_t month) noexcept {
    static const std::uint32_t lengths[] = {0,  31, 59, 90, 120, 151,
                                            181, 212, 243, 273, 304, 334};
    const std::uint32_t index = month >= 1 && month <= 12 ? month - 1 : 0;
    std::uint64_t days = lengths[index];
    if (month > 2 && leap_year(year)) {
        ++days;
    }
    return days;
}

// Days from 1601-01-01 to the given date, which is the count a FILETIME's
// high half needs.
[[nodiscard]] std::uint64_t days_from_epoch(std::uint32_t year,
                                            std::uint32_t month,
                                            std::uint32_t day) noexcept {
    const std::uint64_t from_1601 = days_before_year(year) -
                                    days_before_year(1601);
    std::uint64_t days = from_1601 + days_before_month(year, month) + (day - 1);
    // The Gregorian correction: the days the calendar skipped. 1601 is
    // inside the Gregorian era, so only the leap-year rule applies, which
    // `days_before_year` already carries.
    return days;
}

// The inverse: the calendar date a day count from 1601 names.
void calendar_from_days(std::uint64_t days, std::uint32_t* year,
                        std::uint32_t* month, std::uint32_t* day) noexcept {
    std::uint64_t at = 1601;
    while (days >= (leap_year(at) ? 366u : 365u)) {
        days -= leap_year(at) ? 366u : 365u;
        ++at;
    }
    std::uint32_t month_at = 1;
    for (; month_at <= 12; ++month_at) {
        const std::uint32_t length =
            month_at == 2 ? (leap_year(at) ? 29u : 28u)
                          : ((month_at == 4 || month_at == 6 || month_at == 9 ||
                              month_at == 11)
                                 ? 30u
                                 : 31u);
        if (days < length) {
            break;
        }
        days -= length;
    }
    *year = static_cast<std::uint32_t>(at);
    *month = month_at;
    *day = static_cast<std::uint32_t>(days) + 1;
}


// ------------------------------------------------------------ the profile
//
// One INI file, held as its lines, so that a write can preserve everything
// it is not about.

[[nodiscard]] std::u16string profile_wide(const char* text) noexcept {
    std::u16string out;
    if (text == nullptr) {
        return out;
    }
    while (*text != 0) {
        out.push_back(static_cast<char16_t>(
            static_cast<unsigned char>(*text++)));
    }
    return out;
}

// The file, split into lines with their terminators removed. A file that is
// not there is an empty list rather than a failure: every caller of the
// read side treats a missing profile as one with nothing in it.
[[nodiscard]] bool profile_load(std::u16string_view path,
                                std::vector<std::u16string>* lines) noexcept {
    lines->clear();
    std::u16string text;
    static_cast<void>(read_profile_file(std::u16string(path).c_str(), &text));
    std::size_t at = 0;
    while (at < text.size()) {
        std::size_t end = at;
        while (end < text.size() && text[end] != char16_t{10} &&
               text[end] != char16_t{13}) {
            ++end;
        }
        lines->emplace_back(text.substr(at, end - at));
        while (end < text.size() && (text[end] == char16_t{10} ||
                                     text[end] == char16_t{13})) {
            ++end;
        }
        at = end;
    }
    return true;
}

[[nodiscard]] bool profile_store(std::u16string_view path,
                                 const std::vector<std::u16string>& lines) noexcept {
    char narrow[1024];
    static_cast<void>(narrow_text(std::u16string(path).c_str(), narrow, 1024));
    void* file = cr_fopen(narrow, "wb");
    if (file == nullptr) {
        return false;
    }
    for (const std::u16string& line : lines) {
        std::string bytes;
        bytes.reserve(line.size() + 1);
        for (char16_t ch : line) {
            bytes.push_back(ch < 0x100 ? static_cast<char>(ch) : '?');
        }
        bytes.push_back('\n');
        if (cr_fwrite(bytes.data(), 1, bytes.size(), file) != bytes.size()) {
            static_cast<void>(cr_fclose(file));
            return false;
        }
    }
    return cr_fclose(file) == 0;
}

// The lines of a section: the one after its header to the one before the
// next header. A section that is not in the file is an empty range at the
// end, which is where an insertion belongs.
[[nodiscard]] bool profile_section_range(
    const std::vector<std::u16string>& lines, std::u16string_view section,
    std::size_t* begin, std::size_t* end) noexcept {
    for (std::size_t at = 0; at < lines.size(); ++at) {
        IniSpan<char16_t> span{lines[at].c_str(), lines[at].size()};
        IniSpan<char16_t> name{};
        if (!ini_section_of<char16_t>(span, &name) ||
            !ini_span_equals<char16_t>(name, section.data(), section.size())) {
            continue;
        }
        *begin = at + 1;
        std::size_t stop = at + 1;
        while (stop < lines.size()) {
            IniSpan<char16_t> next{lines[stop].c_str(), lines[stop].size()};
            IniSpan<char16_t> other{};
            if (ini_section_of<char16_t>(next, &other)) {
                break;
            }
            ++stop;
        }
        *end = stop;
        return true;
    }
    *begin = lines.size();
    *end = lines.size();
    return false;
}

// The value a section holds for a key, or nothing. The first line that
// names the key wins, and a line that is a comment is skipped rather than
// read as a key that happens to begin with a semicolon.
[[nodiscard]] bool profile_get(const std::vector<std::u16string>& lines,
                               std::u16string_view section,
                               std::u16string_view key,
                               std::u16string* value) noexcept {
    std::size_t begin = 0;
    std::size_t end = 0;
    if (!profile_section_range(lines, section, &begin, &end)) {
        return false;
    }
    for (std::size_t at = begin; at < end; ++at) {
        IniSpan<char16_t> span{lines[at].c_str(), lines[at].size()};
        if (ini_line_ignorable<char16_t>(span.text)) {
            continue;
        }
        IniSpan<char16_t> found_key{};
        IniSpan<char16_t> found_value{};
        if (!ini_pair_of<char16_t>(span, &found_key, &found_value)) {
            continue;
        }
        if (ini_span_equals<char16_t>(found_key, key.data(), key.size())) {
            value->assign(found_value.text, found_value.length);
            return true;
        }
    }
    return false;
}

// A key written, replaced or removed. `remove` is the API's null-string
// case: a caller that passes one is asking for the key to go, which is a
// different request from storing an empty value.
void profile_set(std::vector<std::u16string>* lines,
                 std::u16string_view section, std::u16string_view key,
                 const std::u16string& value, bool remove) noexcept {
    std::size_t begin = 0;
    std::size_t end = 0;
    if (!profile_section_range(*lines, section, &begin, &end)) {
        if (remove) {
            return;
        }
        std::u16string header{'['};
        header.append(section.begin(), section.end());
        header.push_back(u']');
        lines->push_back(std::move(header));
        begin = lines->size();
        end = begin;
    }
    for (std::size_t at = begin; at < end; ++at) {
        IniSpan<char16_t> span{(*lines)[at].c_str(), (*lines)[at].size()};
        IniSpan<char16_t> found_key{};
        IniSpan<char16_t> found_value{};
        if (!ini_pair_of<char16_t>(span, &found_key, &found_value) ||
            !ini_span_equals<char16_t>(found_key, key.data(), key.size())) {
            continue;
        }
        if (remove) {
            lines->erase(lines->begin() + static_cast<std::ptrdiff_t>(at));
        } else {
            std::u16string fresh(key.begin(), key.end());
            fresh.push_back(u'=');
            fresh.append(value);
            (*lines)[at] = std::move(fresh);
        }
        return;
    }
    if (remove) {
        return;
    }
    std::u16string fresh(key.begin(), key.end());
    fresh.push_back(u'=');
    fresh.append(value);
    lines->insert(lines->begin() + static_cast<std::ptrdiff_t>(end),
                  std::move(fresh));
}

// A whole section removed: its header and every line under it.
void profile_remove_section(std::vector<std::u16string>* lines,
                            std::u16string_view section) noexcept {
    std::size_t begin = 0;
    std::size_t end = 0;
    if (!profile_section_range(*lines, section, &begin, &end)) {
        return;
    }
    lines->erase(lines->begin() + static_cast<std::ptrdiff_t>(begin - 1),
                 lines->begin() + static_cast<std::ptrdiff_t>(end));
}

// The section dumped as the format's lines: `key=value`, one per line, each
// terminated by its own null. This is the shape the `GetPrivateProfileSection`
// call answers with, and the shape its write side takes.
[[nodiscard]] std::u16string profile_section_text(
    const std::vector<std::u16string>& lines, std::u16string_view section) noexcept {
    std::u16string out;
    std::size_t begin = 0;
    std::size_t end = 0;
    if (!profile_section_range(lines, section, &begin, &end)) {
        return out;
    }
    for (std::size_t at = begin; at < end; ++at) {
        IniSpan<char16_t> span{lines[at].c_str(), lines[at].size()};
        if (ini_line_ignorable<char16_t>(span.text)) {
            continue;
        }
        IniSpan<char16_t> key{};
        IniSpan<char16_t> value{};
        if (!ini_pair_of<char16_t>(span, &key, &value)) {
            continue;
        }
        out.append(key.text, key.length);
        out.push_back(u'=');
        out.append(value.text, value.length);
        out.push_back(char16_t{0});
    }
    out.push_back(char16_t{0});
    return out;
}

// A NUL-separated list copied to the narrow width.
//
// The list ends with an empty entry -- two nulls in a row -- and the
// characters of the list other than the last are not a string. A converter
// that stopped at the first null would answer only the first name, which is
// the difference between a section list and a section name.
std::uint32_t copy_list_to_narrow(std::u16string_view list,
                                               char* out,
                                               std::uint32_t capacity) noexcept {
    if (out == nullptr || capacity == 0) {
        return 0;
    }
    std::uint32_t at = 0;
    for (std::size_t index = 0; index < list.size() && at + 2 < capacity;
         ++index) {
        const char16_t ch = list[index];
        out[at++] = ch < 0x100 ? static_cast<char>(ch) : '?';
        if (ch == char16_t{0} &&
            (index + 1 >= list.size() || list[index + 1] == char16_t{0})) {
            break;
        }
    }
    out[at] = 0;
    return at + 1;
}

// The section names, in the order they appear, each with its own null.
[[nodiscard]] std::u16string profile_section_names(
    const std::vector<std::u16string>& lines) noexcept {
    std::u16string out;
    for (const std::u16string& line : lines) {
        IniSpan<char16_t> span{line.c_str(), line.size()};
        IniSpan<char16_t> name{};
        if (!ini_section_of<char16_t>(span, &name)) {
            continue;
        }
        out.append(name.text, name.length);
        out.push_back(char16_t{0});
    }
    out.push_back(char16_t{0});
    return out;
}

// The two paths the plain profile calls use: `win.ini` under the Windows
// directory, which is where the platform keeps the file that predates the
// per-application ones.
[[nodiscard]] const char16_t* profile_shared_file() noexcept {
    static char16_t path[260] = {};
    if (path[0] == char16_t{0}) {
        char16_t directory[260] = {};
        if (k32p_GetWindowsDirectoryW(directory, 260) == 0) {
            return nullptr;
        }
        std::size_t at = text_copy<char16_t>(path, 260, directory);
        if (at == 0 || at + 8 >= 260) {
            return nullptr;
        }
        if (path[at - 1] != static_cast<char16_t>(92)) {
            path[at++] = static_cast<char16_t>(92);
        }
        text_copy<char16_t>(path + at, 260 - at, u"win.ini");
    }
    return path;
}

extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_ActivateActCtx(void* hActCtx, std::uint64_t* lpCookie) noexcept {
    // Refused: the side-by-side activation context.
    //
    // an activation context is built from a manifest and a catalog store by
    // the loader's own subsystem; this runtime resolves modules by name
    static_cast<void>(hActCtx);
    static_cast<void>(lpCookie);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_AddAtomA(const char* lpString) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(lpString);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_AddAtomW(const char16_t* lpString) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(lpString);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_AddConsoleAliasA(char* Source, char* Target, char* ExeName) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(Source);
    static_cast<void>(Target);
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_AddConsoleAliasW(char16_t* Source, char16_t* Target, char16_t* ExeName) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(Source);
    static_cast<void>(Target);
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kkernel32G_AddDllDirectory(const char16_t* NewDirectory) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(NewDirectory);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_AddIntegrityLabelToBoundaryDescriptor(void* BoundaryDescriptor, void* IntegrityLabel) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(BoundaryDescriptor);
    static_cast<void>(IntegrityLabel);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_AddRefActCtx(void* hActCtx) noexcept {
    // Refused: the side-by-side activation context.
    //
    // an activation context is built from a manifest and a catalog store by
    // the loader's own subsystem; this runtime resolves modules by name
    static_cast<void>(hActCtx);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_AddResourceAttributeAce(void* pAcl, std::uint32_t dwAceRevision, std::uint32_t AceFlags, std::uint32_t AccessMask, void* pSid, std::uint64_t pAttributeInfo, std::uint32_t* pReturnLength) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(pAcl);
    static_cast<void>(dwAceRevision);
    static_cast<void>(AceFlags);
    static_cast<void>(AccessMask);
    static_cast<void>(pSid);
    static_cast<void>(pAttributeInfo);
    static_cast<void>(pReturnLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_AddSIDToBoundaryDescriptor(void* BoundaryDescriptor, void* RequiredSid) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(BoundaryDescriptor);
    static_cast<void>(RequiredSid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_AddScopedPolicyIDAce(void* pAcl, std::uint32_t dwAceRevision, std::uint32_t AceFlags, std::uint32_t AccessMask, void* pSid) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(pAcl);
    static_cast<void>(dwAceRevision);
    static_cast<void>(AceFlags);
    static_cast<void>(AccessMask);
    static_cast<void>(pSid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_AddSecureMemoryCacheCallback(std::uint64_t pfnCallBack) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(pfnCallBack);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_AllocateUserPhysicalPages(void* hProcess, std::uint64_t* NumberOfPages, std::uint64_t* PageArray) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hProcess);
    static_cast<void>(NumberOfPages);
    static_cast<void>(PageArray);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_AllocateUserPhysicalPagesNuma(void* hProcess, std::uint64_t* NumberOfPages, std::uint64_t* PageArray, std::uint32_t nndPreferred) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hProcess);
    static_cast<void>(NumberOfPages);
    static_cast<void>(PageArray);
    static_cast<void>(nndPreferred);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_ApplicationRecoveryFinished(std::int32_t bSuccess) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(bSuccess);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_ApplicationRecoveryInProgress(std::int32_t* pbCancelled) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(pbCancelled);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_AreFileApisANSI() noexcept {
    return file_api_code_page_is_ansi() ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_AssignProcessToJobObject(void* hJob, void* hProcess) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(hJob);
    static_cast<void>(hProcess);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_BackupRead(void* hFile, std::uint8_t* lpBuffer, std::uint32_t nNumberOfBytesToRead, std::uint32_t* lpNumberOfBytesRead, std::int32_t bAbort, std::int32_t bProcessSecurity, void** lpContext) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lpBuffer);
    static_cast<void>(nNumberOfBytesToRead);
    static_cast<void>(lpNumberOfBytesRead);
    static_cast<void>(bAbort);
    static_cast<void>(bProcessSecurity);
    static_cast<void>(lpContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_BackupSeek(void* hFile, std::uint32_t dwLowBytesToSeek, std::uint32_t dwHighBytesToSeek, std::uint32_t* lpdwLowByteSeeked, std::uint32_t* lpdwHighByteSeeked, void** lpContext) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(dwLowBytesToSeek);
    static_cast<void>(dwHighBytesToSeek);
    static_cast<void>(lpdwLowByteSeeked);
    static_cast<void>(lpdwHighByteSeeked);
    static_cast<void>(lpContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_BackupWrite(void* hFile, std::uint8_t* lpBuffer, std::uint32_t nNumberOfBytesToWrite, std::uint32_t* lpNumberOfBytesWritten, std::int32_t bAbort, std::int32_t bProcessSecurity, void** lpContext) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lpBuffer);
    static_cast<void>(nNumberOfBytesToWrite);
    static_cast<void>(lpNumberOfBytesWritten);
    static_cast<void>(bAbort);
    static_cast<void>(bProcessSecurity);
    static_cast<void>(lpContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_BeginUpdateResourceA(const char* pFileName, std::int32_t bDeleteExistingResources) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(pFileName);
    static_cast<void>(bDeleteExistingResources);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_BeginUpdateResourceW(const char16_t* pFileName, std::int32_t bDeleteExistingResources) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(pFileName);
    static_cast<void>(bDeleteExistingResources);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_BindIoCompletionCallback(void* FileHandle, void* Function, std::uint32_t Flags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(FileHandle);
    static_cast<void>(Function);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_BuildCommDCBA(const char* lpDef, void* lpDCB) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(lpDef);
    static_cast<void>(lpDCB);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_BuildCommDCBAndTimeoutsA(const char* lpDef, void* lpDCB, void* lpCommTimeouts) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(lpDef);
    static_cast<void>(lpDCB);
    static_cast<void>(lpCommTimeouts);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_BuildCommDCBAndTimeoutsW(const char16_t* lpDef, void* lpDCB, void* lpCommTimeouts) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(lpDef);
    static_cast<void>(lpDCB);
    static_cast<void>(lpCommTimeouts);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_BuildCommDCBW(const char16_t* lpDef, void* lpDCB) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(lpDef);
    static_cast<void>(lpDCB);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CallNamedPipeA(const char* lpNamedPipeName, void* lpInBuffer, std::uint32_t nInBufferSize, void* lpOutBuffer, std::uint32_t nOutBufferSize, std::uint32_t* lpBytesRead, std::uint32_t nTimeOut) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(lpNamedPipeName);
    static_cast<void>(lpInBuffer);
    static_cast<void>(nInBufferSize);
    static_cast<void>(lpOutBuffer);
    static_cast<void>(nOutBufferSize);
    static_cast<void>(lpBytesRead);
    static_cast<void>(nTimeOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CallNamedPipeW(const char16_t* lpNamedPipeName, void* lpInBuffer, std::uint32_t nInBufferSize, void* lpOutBuffer, std::uint32_t nOutBufferSize, std::uint32_t* lpBytesRead, std::uint32_t nTimeOut) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(lpNamedPipeName);
    static_cast<void>(lpInBuffer);
    static_cast<void>(nInBufferSize);
    static_cast<void>(lpOutBuffer);
    static_cast<void>(nOutBufferSize);
    static_cast<void>(lpBytesRead);
    static_cast<void>(nTimeOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CallbackMayRunLong(void* pci) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(pci);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CancelDeviceWakeupRequest(void* hDevice) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(hDevice);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CancelIo(void* hFile) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CancelSynchronousIo(void* hThread) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hThread);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CheckNameLegalDOS8Dot3A(const char* lpName, char* lpOemName, std::uint32_t OemNameSize, std::int32_t* pbNameContainsSpaces, std::int32_t* pbNameLegal) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpName);
    static_cast<void>(lpOemName);
    static_cast<void>(OemNameSize);
    static_cast<void>(pbNameContainsSpaces);
    static_cast<void>(pbNameLegal);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CheckNameLegalDOS8Dot3W(const char16_t* lpName, char* lpOemName, std::uint32_t OemNameSize, std::int32_t* pbNameContainsSpaces, std::int32_t* pbNameLegal) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpName);
    static_cast<void>(lpOemName);
    static_cast<void>(OemNameSize);
    static_cast<void>(pbNameContainsSpaces);
    static_cast<void>(pbNameLegal);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CheckTokenCapability(void* TokenHandle, void* CapabilitySidToCheck, std::int32_t* HasCapability) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(TokenHandle);
    static_cast<void>(CapabilitySidToCheck);
    static_cast<void>(HasCapability);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CheckTokenMembershipEx(void* TokenHandle, void* SidToCheck, std::uint32_t Flags, std::int32_t* IsMember) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(TokenHandle);
    static_cast<void>(SidToCheck);
    static_cast<void>(Flags);
    static_cast<void>(IsMember);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_ClearCommBreak(void* hFile) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hFile);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_ClearCommError(void* hFile, std::uint32_t* lpErrors, std::uint64_t lpStat) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hFile);
    static_cast<void>(lpErrors);
    static_cast<void>(lpStat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_ClosePrivateNamespace(void* Handle, std::uint32_t Flags) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(Handle);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_CloseThreadpool(void* ptpp) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(ptpp);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kkernel32G_CloseThreadpoolCleanupGroup(std::uint64_t ptpcg) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(ptpcg);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kkernel32G_CloseThreadpoolCleanupGroupMembers(std::uint64_t ptpcg, std::int32_t fCancelPendingCallbacks, void* pvCleanupContext) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(ptpcg);
    static_cast<void>(fCancelPendingCallbacks);
    static_cast<void>(pvCleanupContext);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kkernel32G_CloseThreadpoolWork(std::uint64_t pwk) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(pwk);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CommConfigDialogA(const char* lpszName, void* hWnd, void* lpCC) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(lpszName);
    static_cast<void>(hWnd);
    static_cast<void>(lpCC);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CommConfigDialogW(const char16_t* lpszName, void* hWnd, void* lpCC) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(lpszName);
    static_cast<void>(hWnd);
    static_cast<void>(lpCC);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_ConnectNamedPipe(void* hNamedPipe, void* lpOverlapped) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(hNamedPipe);
    static_cast<void>(lpOverlapped);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_ConvertDefaultLocale(std::uint32_t Locale) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_ConvertFiberToThread() noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_ConvertThreadToFiber(void* lpParameter) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(lpParameter);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_ConvertThreadToFiberEx(void* lpParameter, std::uint32_t dwFlags) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(lpParameter);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CopyContext(void* Destination, std::uint32_t ContextFlags, void* Source) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Destination);
    static_cast<void>(ContextFlags);
    static_cast<void>(Source);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CopyFile2(const char16_t* pwszExistingFileName, const char16_t* pwszNewFileName, void* pExtendedParameters) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(pwszExistingFileName);
    static_cast<void>(pwszNewFileName);
    static_cast<void>(pExtendedParameters);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CopyFileTransactedA(const char* lpExistingFileName, const char* lpNewFileName, void* lpProgressRoutine, void* lpData, std::int32_t* pbCancel, std::uint32_t dwCopyFlags, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpExistingFileName);
    static_cast<void>(lpNewFileName);
    static_cast<void>(lpProgressRoutine);
    static_cast<void>(lpData);
    static_cast<void>(pbCancel);
    static_cast<void>(dwCopyFlags);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CopyFileTransactedW(const char16_t* lpExistingFileName, const char16_t* lpNewFileName, void* lpProgressRoutine, void* lpData, std::int32_t* pbCancel, std::uint32_t dwCopyFlags, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpExistingFileName);
    static_cast<void>(lpNewFileName);
    static_cast<void>(lpProgressRoutine);
    static_cast<void>(lpData);
    static_cast<void>(pbCancel);
    static_cast<void>(dwCopyFlags);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateActCtxA(std::uint64_t pActCtx) noexcept {
    // Refused: the side-by-side activation context.
    //
    // an activation context is built from a manifest and a catalog store by
    // the loader's own subsystem; this runtime resolves modules by name
    static_cast<void>(pActCtx);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateActCtxW(std::uint64_t pActCtx) noexcept {
    // Refused: the side-by-side activation context.
    //
    // an activation context is built from a manifest and a catalog store by
    // the loader's own subsystem; this runtime resolves modules by name
    static_cast<void>(pActCtx);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateBoundaryDescriptorA(const char* Name, std::uint32_t Flags) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(Name);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateBoundaryDescriptorW(const char16_t* Name, std::uint32_t Flags) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(Name);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CreateDirectoryExA(const char* lpTemplateDirectory, const char* lpNewDirectory, void* lpSecurityAttributes) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpTemplateDirectory);
    static_cast<void>(lpNewDirectory);
    static_cast<void>(lpSecurityAttributes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CreateDirectoryExW(const char16_t* lpTemplateDirectory, const char16_t* lpNewDirectory, void* lpSecurityAttributes) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpTemplateDirectory);
    static_cast<void>(lpNewDirectory);
    static_cast<void>(lpSecurityAttributes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CreateDirectoryTransactedA(const char* lpTemplateDirectory, const char* lpNewDirectory, void* lpSecurityAttributes, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpTemplateDirectory);
    static_cast<void>(lpNewDirectory);
    static_cast<void>(lpSecurityAttributes);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CreateDirectoryTransactedW(const char16_t* lpTemplateDirectory, const char16_t* lpNewDirectory, void* lpSecurityAttributes, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpTemplateDirectory);
    static_cast<void>(lpNewDirectory);
    static_cast<void>(lpSecurityAttributes);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateFiber(std::uint64_t dwStackSize, std::uint64_t lpStartAddress, void* lpParameter) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(dwStackSize);
    static_cast<void>(lpStartAddress);
    static_cast<void>(lpParameter);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateFiberEx(std::uint64_t dwStackCommitSize, std::uint64_t dwStackReserveSize, std::uint32_t dwFlags, std::uint64_t lpStartAddress, void* lpParameter) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(dwStackCommitSize);
    static_cast<void>(dwStackReserveSize);
    static_cast<void>(dwFlags);
    static_cast<void>(lpStartAddress);
    static_cast<void>(lpParameter);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateFile2(const char16_t* lpFileName, std::uint32_t dwDesiredAccess, std::uint32_t dwShareMode, std::uint32_t dwCreationDisposition, std::uint64_t pCreateExParams) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpFileName);
    static_cast<void>(dwDesiredAccess);
    static_cast<void>(dwShareMode);
    static_cast<void>(dwCreationDisposition);
    static_cast<void>(pCreateExParams);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateFileMappingFromApp(void* hFile, void* SecurityAttributes, std::uint32_t PageProtection, std::uint64_t MaximumSize, const char16_t* Name) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(SecurityAttributes);
    static_cast<void>(PageProtection);
    static_cast<void>(MaximumSize);
    static_cast<void>(Name);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateFileMappingNumaA(void* hFile, void* lpFileMappingAttributes, std::uint32_t flProtect, std::uint32_t dwMaximumSizeHigh, std::uint32_t dwMaximumSizeLow, const char* lpName, std::uint32_t nndPreferred) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lpFileMappingAttributes);
    static_cast<void>(flProtect);
    static_cast<void>(dwMaximumSizeHigh);
    static_cast<void>(dwMaximumSizeLow);
    static_cast<void>(lpName);
    static_cast<void>(nndPreferred);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateFileMappingNumaW(void* hFile, void* lpFileMappingAttributes, std::uint32_t flProtect, std::uint32_t dwMaximumSizeHigh, std::uint32_t dwMaximumSizeLow, const char16_t* lpName, std::uint32_t nndPreferred) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lpFileMappingAttributes);
    static_cast<void>(flProtect);
    static_cast<void>(dwMaximumSizeHigh);
    static_cast<void>(dwMaximumSizeLow);
    static_cast<void>(lpName);
    static_cast<void>(nndPreferred);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateFileTransactedA(const char* lpFileName, std::uint32_t dwDesiredAccess, std::uint32_t dwShareMode, void* lpSecurityAttributes, std::uint32_t dwCreationDisposition, std::uint32_t dwFlagsAndAttributes, void* hTemplateFile, void* hTransaction, std::uint16_t* pusMiniVersion, void* lpExtendedParameter) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(dwDesiredAccess);
    static_cast<void>(dwShareMode);
    static_cast<void>(lpSecurityAttributes);
    static_cast<void>(dwCreationDisposition);
    static_cast<void>(dwFlagsAndAttributes);
    static_cast<void>(hTemplateFile);
    static_cast<void>(hTransaction);
    static_cast<void>(pusMiniVersion);
    static_cast<void>(lpExtendedParameter);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateFileTransactedW(const char16_t* lpFileName, std::uint32_t dwDesiredAccess, std::uint32_t dwShareMode, void* lpSecurityAttributes, std::uint32_t dwCreationDisposition, std::uint32_t dwFlagsAndAttributes, void* hTemplateFile, void* hTransaction, std::uint16_t* pusMiniVersion, void* lpExtendedParameter) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(dwDesiredAccess);
    static_cast<void>(dwShareMode);
    static_cast<void>(lpSecurityAttributes);
    static_cast<void>(dwCreationDisposition);
    static_cast<void>(dwFlagsAndAttributes);
    static_cast<void>(hTemplateFile);
    static_cast<void>(hTransaction);
    static_cast<void>(pusMiniVersion);
    static_cast<void>(lpExtendedParameter);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CreateHardLinkTransactedA(const char* lpFileName, const char* lpExistingFileName, void* lpSecurityAttributes, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(lpExistingFileName);
    static_cast<void>(lpSecurityAttributes);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CreateHardLinkTransactedW(const char16_t* lpFileName, const char16_t* lpExistingFileName, void* lpSecurityAttributes, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(lpExistingFileName);
    static_cast<void>(lpSecurityAttributes);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateJobObjectA(void* lpJobAttributes, const char* lpName) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(lpJobAttributes);
    static_cast<void>(lpName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateJobObjectW(void* lpJobAttributes, const char16_t* lpName) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(lpJobAttributes);
    static_cast<void>(lpName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CreateJobSet(std::uint32_t NumJob, std::uint64_t UserJobSet, std::uint32_t Flags) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(NumJob);
    static_cast<void>(UserJobSet);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateMailslotA(const char* lpName, std::uint32_t nMaxMessageSize, std::uint32_t lReadTimeout, void* lpSecurityAttributes) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(lpName);
    static_cast<void>(nMaxMessageSize);
    static_cast<void>(lReadTimeout);
    static_cast<void>(lpSecurityAttributes);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateMailslotW(const char16_t* lpName, std::uint32_t nMaxMessageSize, std::uint32_t lReadTimeout, void* lpSecurityAttributes) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(lpName);
    static_cast<void>(nMaxMessageSize);
    static_cast<void>(lReadTimeout);
    static_cast<void>(lpSecurityAttributes);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateMemoryResourceNotification(std::int32_t NotificationType) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(NotificationType);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateNamedPipeA(const char* lpName, std::uint32_t dwOpenMode, std::uint32_t dwPipeMode, std::uint32_t nMaxInstances, std::uint32_t nOutBufferSize, std::uint32_t nInBufferSize, std::uint32_t nDefaultTimeOut, void* lpSecurityAttributes) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(lpName);
    static_cast<void>(dwOpenMode);
    static_cast<void>(dwPipeMode);
    static_cast<void>(nMaxInstances);
    static_cast<void>(nOutBufferSize);
    static_cast<void>(nInBufferSize);
    static_cast<void>(nDefaultTimeOut);
    static_cast<void>(lpSecurityAttributes);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateNamedPipeW(const char16_t* lpName, std::uint32_t dwOpenMode, std::uint32_t dwPipeMode, std::uint32_t nMaxInstances, std::uint32_t nOutBufferSize, std::uint32_t nInBufferSize, std::uint32_t nDefaultTimeOut, void* lpSecurityAttributes) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(lpName);
    static_cast<void>(dwOpenMode);
    static_cast<void>(dwPipeMode);
    static_cast<void>(nMaxInstances);
    static_cast<void>(nOutBufferSize);
    static_cast<void>(nInBufferSize);
    static_cast<void>(nDefaultTimeOut);
    static_cast<void>(lpSecurityAttributes);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CreatePipe(void** hReadPipe, void** hWritePipe, void* lpPipeAttributes, std::uint32_t nSize) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(hReadPipe);
    static_cast<void>(hWritePipe);
    static_cast<void>(lpPipeAttributes);
    static_cast<void>(nSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreatePrivateNamespaceA(void* lpPrivateNamespaceAttributes, void* lpBoundaryDescriptor, const char* lpAliasPrefix) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(lpPrivateNamespaceAttributes);
    static_cast<void>(lpBoundaryDescriptor);
    static_cast<void>(lpAliasPrefix);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreatePrivateNamespaceW(void* lpPrivateNamespaceAttributes, void* lpBoundaryDescriptor, const char16_t* lpAliasPrefix) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(lpPrivateNamespaceAttributes);
    static_cast<void>(lpBoundaryDescriptor);
    static_cast<void>(lpAliasPrefix);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_CreateRemoteThreadEx(void* hProcess, void* lpThreadAttributes, std::uint64_t dwStackSize, void* lpStartAddress, void* lpParameter, std::uint32_t dwCreationFlags, void* lpAttributeList, std::uint32_t* lpThreadId) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hProcess);
    static_cast<void>(lpThreadAttributes);
    static_cast<void>(dwStackSize);
    static_cast<void>(lpStartAddress);
    static_cast<void>(lpParameter);
    static_cast<void>(dwCreationFlags);
    static_cast<void>(lpAttributeList);
    static_cast<void>(lpThreadId);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_CreateSymbolicLinkA(const char* lpSymlinkFileName, const char* lpTargetFileName, std::uint32_t dwFlags) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(lpSymlinkFileName);
    static_cast<void>(lpTargetFileName);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_CreateSymbolicLinkTransactedA(const char* lpSymlinkFileName, const char* lpTargetFileName, std::uint32_t dwFlags, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpSymlinkFileName);
    static_cast<void>(lpTargetFileName);
    static_cast<void>(dwFlags);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_CreateSymbolicLinkTransactedW(const char16_t* lpSymlinkFileName, const char16_t* lpTargetFileName, std::uint32_t dwFlags, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpSymlinkFileName);
    static_cast<void>(lpTargetFileName);
    static_cast<void>(dwFlags);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_CreateSymbolicLinkW(const char16_t* lpSymlinkFileName, const char16_t* lpTargetFileName, std::uint32_t dwFlags) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(lpSymlinkFileName);
    static_cast<void>(lpTargetFileName);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_CreateTapePartition(void* hDevice, std::uint32_t dwPartitionMethod, std::uint32_t dwCount, std::uint32_t dwSize) noexcept {
    // Refused: the tape device layer.
    //
    // a tape is a device reached through the device I/O control surface
    static_cast<void>(hDevice);
    static_cast<void>(dwPartitionMethod);
    static_cast<void>(dwCount);
    static_cast<void>(dwSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CreateUmsCompletionList(void* UmsCompletionList) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(UmsCompletionList);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_CreateUmsThreadContext(void** lpUmsThread) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(lpUmsThread);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_DeactivateActCtx(std::uint32_t dwFlags, std::uint64_t ulCookie) noexcept {
    // Refused: the side-by-side activation context.
    //
    // an activation context is built from a manifest and a catalog store by
    // the loader's own subsystem; this runtime resolves modules by name
    static_cast<void>(dwFlags);
    static_cast<void>(ulCookie);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_DebugBreakProcess(void* Process) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(Process);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_DecodePointer(void* Ptr) noexcept {
    if (Ptr == nullptr) {
        return nullptr;
    }
    return reinterpret_cast<void*>(
        reinterpret_cast<std::uintptr_t>(Ptr) ^ pointer_cookie());
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_DecodeSystemPointer(void* Ptr) noexcept {
    if (Ptr == nullptr) {
        return nullptr;
    }
    return reinterpret_cast<void*>(
        reinterpret_cast<std::uintptr_t>(Ptr) ^ pointer_cookie());
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_DefineDosDeviceA(std::uint32_t dwFlags, const char* lpDeviceName, const char* lpTargetPath) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(dwFlags);
    static_cast<void>(lpDeviceName);
    static_cast<void>(lpTargetPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_DefineDosDeviceW(std::uint32_t dwFlags, const char16_t* lpDeviceName, const char16_t* lpTargetPath) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(dwFlags);
    static_cast<void>(lpDeviceName);
    static_cast<void>(lpTargetPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_DeleteAtom(std::uint16_t nAtom) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(nAtom);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_DeleteBoundaryDescriptor(void* BoundaryDescriptor) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(BoundaryDescriptor);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kkernel32G_DeleteFiber(void* lpFiber) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(lpFiber);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_DeleteFileTransactedA(const char* lpFileName, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_DeleteFileTransactedW(const char16_t* lpFileName, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_DeleteProcThreadAttributeList(void* lpAttributeList) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpAttributeList);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_DeleteSynchronizationBarrier(void* lpBarrier) noexcept {
    if (lpBarrier != nullptr) {
        auto* words = static_cast<std::uint64_t*>(lpBarrier);
        words[0] = 0;
        words[1] = 0;
        words[2] = 0;
        words[3] = 0;
    }
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_DeleteUmsCompletionList(std::uint64_t UmsCompletionList) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(UmsCompletionList);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_DeleteUmsThreadContext(void* UmsThread) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(UmsThread);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_DeleteVolumeMountPointA(const char* lpszVolumeMountPoint) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(lpszVolumeMountPoint);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_DeleteVolumeMountPointW(const char16_t* lpszVolumeMountPoint) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(lpszVolumeMountPoint);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_DequeueUmsCompletionListItems(std::uint64_t UmsCompletionList, std::uint32_t WaitTimeOut, void** UmsThreadList) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(UmsCompletionList);
    static_cast<void>(WaitTimeOut);
    static_cast<void>(UmsThreadList);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_DisableThreadLibraryCalls(void* hLibModule) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hLibModule);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_DisableThreadProfiling(void* PerformanceDataHandle) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(PerformanceDataHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_DisassociateCurrentThreadFromCallback(void* pci) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(pci);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_DiscardVirtualMemory(void* VirtualAddress, std::uint64_t Size) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(VirtualAddress);
    static_cast<void>(Size);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_DisconnectNamedPipe(void* hNamedPipe) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(hNamedPipe);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_DnsHostnameToComputerNameA(const char* Hostname, char* ComputerName, std::uint32_t* nSize) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Hostname);
    static_cast<void>(ComputerName);
    static_cast<void>(nSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_DnsHostnameToComputerNameW(const char16_t* Hostname, char16_t* ComputerName, std::uint32_t* nSize) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Hostname);
    static_cast<void>(ComputerName);
    static_cast<void>(nSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_DosDateTimeToFileTime(std::uint16_t wFatDate, std::uint16_t wFatTime, std::uint64_t* lpFileTime) noexcept {
    if (lpFileTime == nullptr) {
        return 0;
    }
    // The DOS word is a packed calendar: bits 9 to 15 the year from 1980,
    // bits 5 to 8 the month, bits 0 to 4 the day. The output is a count of
    // hundred-nanosecond ticks from 1601, which is where the conversion
    // lives: between 1601 and 1980 there are 134774 days.
    const std::uint32_t year = 1980u + ((wFatDate >> 9) & 0x7Fu);
    const std::uint32_t month = (wFatDate >> 5) & 0x0Fu;
    const std::uint32_t day = wFatDate & 0x1Fu;
    const std::uint32_t hour = (wFatTime >> 11) & 0x1Fu;
    const std::uint32_t minute = (wFatTime >> 5) & 0x3Fu;
    const std::uint32_t second = (wFatTime & 0x1Fu) * 2u;
    if (month < 1 || month > 12 || day < 1 || day > 31) {
        return 0;
    }
    const std::uint64_t days = days_from_epoch(year, month, day);
    const std::uint64_t ticks =
        ((days * 24u + hour) * 60u + minute) * 60u + second;
    write_le64(lpFileTime, 0, ticks * 10000000ull);
    return 1;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_EnableThreadProfiling(void* ThreadHandle, std::uint32_t Flags, std::uint64_t HardwareCounters, void* PerformanceDataHandle) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(ThreadHandle);
    static_cast<void>(Flags);
    static_cast<void>(HardwareCounters);
    static_cast<void>(PerformanceDataHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_EncodeSystemPointer(void* Ptr) noexcept {
    // The pointer and a per-process value, exclusive-ored. The value is not
    // a secret -- the API does not claim to be one -- and what it buys is
    // that a pointer a guest wrote down is not a usable address after the
    // process that wrote it has gone, which is what the call is for.
    if (Ptr == nullptr) {
        return nullptr;
    }
    return reinterpret_cast<void*>(
        reinterpret_cast<std::uintptr_t>(Ptr) ^ pointer_cookie());
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EndUpdateResourceA(void* hUpdate, std::int32_t fDiscard) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hUpdate);
    static_cast<void>(fDiscard);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EndUpdateResourceW(void* hUpdate, std::int32_t fDiscard) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hUpdate);
    static_cast<void>(fDiscard);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnterSynchronizationBarrier(void* lpBarrier, std::uint32_t dwFlags) noexcept {
    if (lpBarrier == nullptr) {
        return 0;
    }
    static_cast<void>(dwFlags);
    auto* words = static_cast<std::uint64_t*>(lpBarrier);
    const std::uint64_t generation =
        __atomic_load_n(&words[3], __ATOMIC_SEQ_CST) + 1;
    const std::uint64_t left =
        __atomic_sub_fetch(&words[0], 1, __ATOMIC_SEQ_CST);
    if (left == 0) {
        // The last arrival opens the barrier: the count is restored and the
        // generation advances, which is the signal every waiter is watching.
        __atomic_store_n(&words[0], words[1], __ATOMIC_SEQ_CST);
        __atomic_store_n(&words[3], generation, __ATOMIC_SEQ_CST);
        return 1;
    }
    while (__atomic_load_n(&words[3], __ATOMIC_SEQ_CST) != generation) {
    }
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnterUmsSchedulingMode(std::uint64_t SchedulerStartupInfo) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(SchedulerStartupInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumCalendarInfoA(std::uint64_t lpCalInfoEnumProc, std::uint32_t Locale, std::uint32_t Calendar, std::uint32_t CalType) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpCalInfoEnumProc);
    static_cast<void>(Locale);
    static_cast<void>(Calendar);
    static_cast<void>(CalType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumCalendarInfoExA(std::uint64_t lpCalInfoEnumProcEx, std::uint32_t Locale, std::uint32_t Calendar, std::uint32_t CalType) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpCalInfoEnumProcEx);
    static_cast<void>(Locale);
    static_cast<void>(Calendar);
    static_cast<void>(CalType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumCalendarInfoExEx(std::uint64_t pCalInfoEnumProcExEx, const char16_t* lpLocaleName, std::uint32_t Calendar, const char16_t* lpReserved, std::uint32_t CalType, std::int64_t lParam) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(pCalInfoEnumProcExEx);
    static_cast<void>(lpLocaleName);
    static_cast<void>(Calendar);
    static_cast<void>(lpReserved);
    static_cast<void>(CalType);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumCalendarInfoExW(std::uint64_t lpCalInfoEnumProcEx, std::uint32_t Locale, std::uint32_t Calendar, std::uint32_t CalType) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpCalInfoEnumProcEx);
    static_cast<void>(Locale);
    static_cast<void>(Calendar);
    static_cast<void>(CalType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumCalendarInfoW(std::uint64_t lpCalInfoEnumProc, std::uint32_t Locale, std::uint32_t Calendar, std::uint32_t CalType) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpCalInfoEnumProc);
    static_cast<void>(Locale);
    static_cast<void>(Calendar);
    static_cast<void>(CalType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumDateFormatsA(std::uint64_t lpDateFmtEnumProc, std::uint32_t Locale, std::uint32_t dwFlags) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpDateFmtEnumProc);
    static_cast<void>(Locale);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumDateFormatsExA(std::uint64_t lpDateFmtEnumProcEx, std::uint32_t Locale, std::uint32_t dwFlags) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpDateFmtEnumProcEx);
    static_cast<void>(Locale);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumDateFormatsExEx(std::uint64_t lpDateFmtEnumProcExEx, const char16_t* lpLocaleName, std::uint32_t dwFlags, std::int64_t lParam) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpDateFmtEnumProcExEx);
    static_cast<void>(lpLocaleName);
    static_cast<void>(dwFlags);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumDateFormatsExW(std::uint64_t lpDateFmtEnumProcEx, std::uint32_t Locale, std::uint32_t dwFlags) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpDateFmtEnumProcEx);
    static_cast<void>(Locale);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumDateFormatsW(std::uint64_t lpDateFmtEnumProc, std::uint32_t Locale, std::uint32_t dwFlags) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpDateFmtEnumProc);
    static_cast<void>(Locale);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumLanguageGroupLocalesA(std::uint64_t lpLangGroupLocaleEnumProc, std::uint64_t LanguageGroup, std::uint32_t dwFlags, std::int64_t lParam) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpLangGroupLocaleEnumProc);
    static_cast<void>(LanguageGroup);
    static_cast<void>(dwFlags);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumLanguageGroupLocalesW(std::uint64_t lpLangGroupLocaleEnumProc, std::uint64_t LanguageGroup, std::uint32_t dwFlags, std::int64_t lParam) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpLangGroupLocaleEnumProc);
    static_cast<void>(LanguageGroup);
    static_cast<void>(dwFlags);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumResourceLanguagesA(void* hModule, const char* lpType, const char* lpName, std::uint64_t lpEnumFunc, std::int64_t lParam) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(lpType);
    static_cast<void>(lpName);
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumResourceLanguagesExA(void* hModule, const char* lpType, const char* lpName, std::uint64_t lpEnumFunc, std::int64_t lParam, std::uint32_t dwFlags, std::uint16_t LangId) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(lpType);
    static_cast<void>(lpName);
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    static_cast<void>(dwFlags);
    static_cast<void>(LangId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumResourceLanguagesExW(void* hModule, const char16_t* lpType, const char16_t* lpName, std::uint64_t lpEnumFunc, std::int64_t lParam, std::uint32_t dwFlags, std::uint16_t LangId) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(lpType);
    static_cast<void>(lpName);
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    static_cast<void>(dwFlags);
    static_cast<void>(LangId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumResourceLanguagesW(void* hModule, const char16_t* lpType, const char16_t* lpName, std::uint64_t lpEnumFunc, std::int64_t lParam) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(lpType);
    static_cast<void>(lpName);
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumResourceNamesA(void* hModule, const char* lpType, std::uint64_t lpEnumFunc, std::int64_t lParam) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(lpType);
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumResourceNamesExA(void* hModule, const char* lpType, std::uint64_t lpEnumFunc, std::int64_t lParam, std::uint32_t dwFlags, std::uint16_t LangId) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(lpType);
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    static_cast<void>(dwFlags);
    static_cast<void>(LangId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumResourceNamesExW(void* hModule, const char16_t* lpType, std::uint64_t lpEnumFunc, std::int64_t lParam, std::uint32_t dwFlags, std::uint16_t LangId) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(lpType);
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    static_cast<void>(dwFlags);
    static_cast<void>(LangId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumResourceNamesW(void* hModule, const char16_t* lpType, std::uint64_t lpEnumFunc, std::int64_t lParam) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(lpType);
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumResourceTypesA(void* hModule, std::uint64_t lpEnumFunc, std::int64_t lParam) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumResourceTypesExA(void* hModule, std::uint64_t lpEnumFunc, std::int64_t lParam, std::uint32_t dwFlags, std::uint16_t LangId) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    static_cast<void>(dwFlags);
    static_cast<void>(LangId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumResourceTypesExW(void* hModule, std::uint64_t lpEnumFunc, std::int64_t lParam, std::uint32_t dwFlags, std::uint16_t LangId) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    static_cast<void>(dwFlags);
    static_cast<void>(LangId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumResourceTypesW(void* hModule, std::uint64_t lpEnumFunc, std::int64_t lParam) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumSystemCodePagesA(std::uint64_t lpCodePageEnumProc, std::uint32_t dwFlags) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpCodePageEnumProc);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumSystemCodePagesW(std::uint64_t lpCodePageEnumProc, std::uint32_t dwFlags) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpCodePageEnumProc);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumSystemGeoID(std::int32_t GeoClass, std::int32_t ParentGeoId, std::uint64_t lpGeoEnumProc) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(GeoClass);
    static_cast<void>(ParentGeoId);
    static_cast<void>(lpGeoEnumProc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumSystemLanguageGroupsA(std::uint64_t lpLanguageGroupEnumProc, std::uint32_t dwFlags, std::int64_t lParam) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpLanguageGroupEnumProc);
    static_cast<void>(dwFlags);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumSystemLanguageGroupsW(std::uint64_t lpLanguageGroupEnumProc, std::uint32_t dwFlags, std::int64_t lParam) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpLanguageGroupEnumProc);
    static_cast<void>(dwFlags);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumSystemLocalesA(std::uint64_t lpLocaleEnumProc, std::uint32_t dwFlags) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpLocaleEnumProc);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumSystemLocalesEx(std::uint64_t lpLocaleEnumProcEx, std::uint32_t dwFlags, std::int64_t lParam, void* lpReserved) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpLocaleEnumProcEx);
    static_cast<void>(dwFlags);
    static_cast<void>(lParam);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumSystemLocalesW(std::uint64_t lpLocaleEnumProc, std::uint32_t dwFlags) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpLocaleEnumProc);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumTimeFormatsA(std::uint64_t lpTimeFmtEnumProc, std::uint32_t Locale, std::uint32_t dwFlags) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpTimeFmtEnumProc);
    static_cast<void>(Locale);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumTimeFormatsEx(std::uint64_t lpTimeFmtEnumProcEx, const char16_t* lpLocaleName, std::uint32_t dwFlags, std::int64_t lParam) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpTimeFmtEnumProcEx);
    static_cast<void>(lpLocaleName);
    static_cast<void>(dwFlags);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumTimeFormatsW(std::uint64_t lpTimeFmtEnumProc, std::uint32_t Locale, std::uint32_t dwFlags) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpTimeFmtEnumProc);
    static_cast<void>(Locale);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumUILanguagesA(std::uint64_t lpUILanguageEnumProc, std::uint32_t dwFlags, std::int64_t lParam) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpUILanguageEnumProc);
    static_cast<void>(dwFlags);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EnumUILanguagesW(std::uint64_t lpUILanguageEnumProc, std::uint32_t dwFlags, std::int64_t lParam) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpUILanguageEnumProc);
    static_cast<void>(dwFlags);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_EraseTape(void* hDevice, std::uint32_t dwEraseType, std::int32_t bImmediate) noexcept {
    // Refused: the tape device layer.
    //
    // a tape is a device reached through the device I/O control surface
    static_cast<void>(hDevice);
    static_cast<void>(dwEraseType);
    static_cast<void>(bImmediate);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_EscapeCommFunction(void* hFile, std::uint32_t dwFunc) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hFile);
    static_cast<void>(dwFunc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_ExecuteUmsThread(void* UmsThread) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(UmsThread);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_ExpungeConsoleCommandHistoryA(char* ExeName) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kkernel32G_ExpungeConsoleCommandHistoryW(char16_t* ExeName) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kkernel32G_FatalExit(std::int32_t ExitCode) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(ExitCode);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FileTimeToDosDateTime(const std::uint64_t* lpFileTime, std::uint16_t* lpFatDate, std::uint16_t* lpFatTime) noexcept {
    if (lpFileTime == nullptr || lpFatDate == nullptr || lpFatTime == nullptr) {
        return 0;
    }
    const std::uint64_t ticks = read_le64(lpFileTime, 0) / 10000000ull;
    std::uint64_t days = ticks / 86400ull;
    std::uint64_t rest = ticks % 86400ull;
    const std::uint32_t hour = static_cast<std::uint32_t>(rest / 3600ull);
    rest %= 3600ull;
    const std::uint32_t minute = static_cast<std::uint32_t>(rest / 60ull);
    const std::uint32_t second = static_cast<std::uint32_t>(rest % 60ull);
    std::uint32_t year = 0;
    std::uint32_t month = 0;
    std::uint32_t day = 0;
    calendar_from_days(days, &year, &month, &day);
    // The DOS calendar starts at 1980, so anything earlier has no spelling
    // and the call refuses rather than answering a wrapped date.
    if (year < 1980 || year > 2107) {
        return 0;
    }
    *lpFatDate = static_cast<std::uint16_t>(
        ((year - 1980u) << 9) | (month << 5) | day);
    *lpFatTime = static_cast<std::uint16_t>(
        (hour << 11) | (minute << 5) | (second / 2u));
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FindActCtxSectionGuid(std::uint32_t dwFlags, const void* lpExtensionGuid, std::uint32_t ulSectionId, const void* lpGuidToFind, std::uint64_t ReturnedData) noexcept {
    // Refused: the side-by-side activation context.
    //
    // an activation context is built from a manifest and a catalog store by
    // the loader's own subsystem; this runtime resolves modules by name
    static_cast<void>(dwFlags);
    static_cast<void>(lpExtensionGuid);
    static_cast<void>(ulSectionId);
    static_cast<void>(lpGuidToFind);
    static_cast<void>(ReturnedData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FindActCtxSectionStringA(std::uint32_t dwFlags, const void* lpExtensionGuid, std::uint32_t ulSectionId, const char* lpStringToFind, std::uint64_t ReturnedData) noexcept {
    // Refused: the side-by-side activation context.
    //
    // an activation context is built from a manifest and a catalog store by
    // the loader's own subsystem; this runtime resolves modules by name
    static_cast<void>(dwFlags);
    static_cast<void>(lpExtensionGuid);
    static_cast<void>(ulSectionId);
    static_cast<void>(lpStringToFind);
    static_cast<void>(ReturnedData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FindActCtxSectionStringW(std::uint32_t dwFlags, const void* lpExtensionGuid, std::uint32_t ulSectionId, const char16_t* lpStringToFind, std::uint64_t ReturnedData) noexcept {
    // Refused: the side-by-side activation context.
    //
    // an activation context is built from a manifest and a catalog store by
    // the loader's own subsystem; this runtime resolves modules by name
    static_cast<void>(dwFlags);
    static_cast<void>(lpExtensionGuid);
    static_cast<void>(ulSectionId);
    static_cast<void>(lpStringToFind);
    static_cast<void>(ReturnedData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_FindAtomA(const char* lpString) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(lpString);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_FindAtomW(const char16_t* lpString) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(lpString);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FindCloseChangeNotification(void* hChangeHandle) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hChangeHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_FindFirstChangeNotificationA(const char* lpPathName, std::int32_t bWatchSubtree, std::uint32_t dwNotifyFilter) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpPathName);
    static_cast<void>(bWatchSubtree);
    static_cast<void>(dwNotifyFilter);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_FindFirstChangeNotificationW(const char16_t* lpPathName, std::int32_t bWatchSubtree, std::uint32_t dwNotifyFilter) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpPathName);
    static_cast<void>(bWatchSubtree);
    static_cast<void>(dwNotifyFilter);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_FindFirstFileExA(const char* lpFileName, std::uint64_t fInfoLevelId, void* lpFindFileData, std::uint64_t fSearchOp, void* lpSearchFilter, std::uint32_t dwAdditionalFlags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpFileName);
    static_cast<void>(fInfoLevelId);
    static_cast<void>(lpFindFileData);
    static_cast<void>(fSearchOp);
    static_cast<void>(lpSearchFilter);
    static_cast<void>(dwAdditionalFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_FindFirstFileNameTransactedW(const char16_t* lpFileName, std::uint32_t dwFlags, std::uint32_t* StringLength, char16_t* LinkName, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(dwFlags);
    static_cast<void>(StringLength);
    static_cast<void>(LinkName);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_FindFirstFileNameW(const char16_t* lpFileName, std::uint32_t dwFlags, std::uint32_t* StringLength, char16_t* LinkName) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpFileName);
    static_cast<void>(dwFlags);
    static_cast<void>(StringLength);
    static_cast<void>(LinkName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_FindFirstFileTransactedA(const char* lpFileName, std::uint64_t fInfoLevelId, void* lpFindFileData, std::uint64_t fSearchOp, void* lpSearchFilter, std::uint32_t dwAdditionalFlags, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(fInfoLevelId);
    static_cast<void>(lpFindFileData);
    static_cast<void>(fSearchOp);
    static_cast<void>(lpSearchFilter);
    static_cast<void>(dwAdditionalFlags);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_FindFirstFileTransactedW(const char16_t* lpFileName, std::uint64_t fInfoLevelId, void* lpFindFileData, std::uint64_t fSearchOp, void* lpSearchFilter, std::uint32_t dwAdditionalFlags, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(fInfoLevelId);
    static_cast<void>(lpFindFileData);
    static_cast<void>(fSearchOp);
    static_cast<void>(lpSearchFilter);
    static_cast<void>(dwAdditionalFlags);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_FindFirstStreamTransactedW(const char16_t* lpFileName, std::uint64_t InfoLevel, void* lpFindStreamData, std::uint32_t dwFlags, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(InfoLevel);
    static_cast<void>(lpFindStreamData);
    static_cast<void>(dwFlags);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_FindFirstStreamW(const char16_t* lpFileName, std::uint64_t InfoLevel, void* lpFindStreamData, std::uint32_t dwFlags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpFileName);
    static_cast<void>(InfoLevel);
    static_cast<void>(lpFindStreamData);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_FindFirstVolumeA(char* lpszVolumeName, std::uint32_t cchBufferLength) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(lpszVolumeName);
    static_cast<void>(cchBufferLength);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_FindFirstVolumeMountPointA(const char* lpszRootPathName, char* lpszVolumeMountPoint, std::uint32_t cchBufferLength) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(lpszRootPathName);
    static_cast<void>(lpszVolumeMountPoint);
    static_cast<void>(cchBufferLength);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_FindFirstVolumeMountPointW(const char16_t* lpszRootPathName, char16_t* lpszVolumeMountPoint, std::uint32_t cchBufferLength) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(lpszRootPathName);
    static_cast<void>(lpszVolumeMountPoint);
    static_cast<void>(cchBufferLength);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_FindFirstVolumeW(char16_t* lpszVolumeName, std::uint32_t cchBufferLength) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(lpszVolumeName);
    static_cast<void>(cchBufferLength);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FindNLSString(std::uint32_t Locale, std::uint32_t dwFindNLSStringFlags, const char16_t* lpStringSource, std::int32_t cchSource, const char16_t* lpStringValue, std::int32_t cchValue, std::int32_t* pcchFound) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(dwFindNLSStringFlags);
    static_cast<void>(lpStringSource);
    static_cast<void>(cchSource);
    static_cast<void>(lpStringValue);
    static_cast<void>(cchValue);
    static_cast<void>(pcchFound);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FindNLSStringEx(const char16_t* lpLocaleName, std::uint32_t dwFindNLSStringFlags, const char16_t* lpStringSource, std::int32_t cchSource, const char16_t* lpStringValue, std::int32_t cchValue, std::int32_t* pcchFound, std::uint64_t lpVersionInformation, void* lpReserved, std::int64_t sortHandle) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpLocaleName);
    static_cast<void>(dwFindNLSStringFlags);
    static_cast<void>(lpStringSource);
    static_cast<void>(cchSource);
    static_cast<void>(lpStringValue);
    static_cast<void>(cchValue);
    static_cast<void>(pcchFound);
    static_cast<void>(lpVersionInformation);
    static_cast<void>(lpReserved);
    static_cast<void>(sortHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FindNextChangeNotification(void* hChangeHandle) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hChangeHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FindNextFileNameW(void* hFindStream, std::uint32_t* StringLength, char16_t* LinkName) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFindStream);
    static_cast<void>(StringLength);
    static_cast<void>(LinkName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FindNextStreamW(void* hFindStream, void* lpFindStreamData) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFindStream);
    static_cast<void>(lpFindStreamData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FindNextVolumeA(void* hFindVolume, char* lpszVolumeName, std::uint32_t cchBufferLength) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(hFindVolume);
    static_cast<void>(lpszVolumeName);
    static_cast<void>(cchBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FindNextVolumeMountPointA(void* hFindVolumeMountPoint, char* lpszVolumeMountPoint, std::uint32_t cchBufferLength) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(hFindVolumeMountPoint);
    static_cast<void>(lpszVolumeMountPoint);
    static_cast<void>(cchBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FindNextVolumeMountPointW(void* hFindVolumeMountPoint, char16_t* lpszVolumeMountPoint, std::uint32_t cchBufferLength) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(hFindVolumeMountPoint);
    static_cast<void>(lpszVolumeMountPoint);
    static_cast<void>(cchBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FindNextVolumeW(void* hFindVolume, char16_t* lpszVolumeName, std::uint32_t cchBufferLength) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(hFindVolume);
    static_cast<void>(lpszVolumeName);
    static_cast<void>(cchBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_FindResourceA(void* hModule, const char* lpName, const char* lpType) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(lpName);
    static_cast<void>(lpType);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_FindResourceExA(void* hModule, const char* lpType, const char* lpName, std::uint16_t wLanguage) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(lpType);
    static_cast<void>(lpName);
    static_cast<void>(wLanguage);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_FindResourceExW(void* hModule, const char16_t* lpType, const char16_t* lpName, std::uint16_t wLanguage) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(lpType);
    static_cast<void>(lpName);
    static_cast<void>(wLanguage);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_FindResourceW(void* hModule, const char16_t* lpName, const char16_t* lpType) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(lpName);
    static_cast<void>(lpType);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FindStringOrdinal(std::uint32_t dwFindStringOrdinalFlags, const char16_t* lpStringSource, std::int32_t cchSource, const char16_t* lpStringValue, std::int32_t cchValue, std::int32_t bIgnoreCase) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(dwFindStringOrdinalFlags);
    static_cast<void>(lpStringSource);
    static_cast<void>(cchSource);
    static_cast<void>(lpStringValue);
    static_cast<void>(cchValue);
    static_cast<void>(bIgnoreCase);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FindVolumeClose(void* hFindVolume) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(hFindVolume);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FindVolumeMountPointClose(void* hFindVolumeMountPoint) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(hFindVolumeMountPoint);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FlushConsoleInputBuffer(void* hConsoleInput) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(hConsoleInput);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_FreeLibraryWhenCallbackReturns(void* pci, void* mod) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(pci);
    static_cast<void>(mod);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FreeResource(void* hResData) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hResData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_FreeUserPhysicalPages(void* hProcess, std::uint64_t* NumberOfPages, std::uint64_t* PageArray) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hProcess);
    static_cast<void>(NumberOfPages);
    static_cast<void>(PageArray);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_GetActiveProcessorGroupCount() noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetAppContainerAce(void* Acl, std::uint32_t StartingAceIndex, void** AppContainerAce, std::uint32_t* AppContainerAceIndex) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Acl);
    static_cast<void>(StartingAceIndex);
    static_cast<void>(AppContainerAce);
    static_cast<void>(AppContainerAceIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetAppContainerNamedObjectPath(void* Token, void* AppContainerSid, std::uint32_t ObjectPathLength, char16_t* ObjectPath, std::uint32_t* ReturnLength) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Token);
    static_cast<void>(AppContainerSid);
    static_cast<void>(ObjectPathLength);
    static_cast<void>(ObjectPath);
    static_cast<void>(ReturnLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetApplicationRecoveryCallback(void* hProcess, void** pRecoveryCallback, void** ppvParameter, std::uint32_t* pdwPingInterval, std::uint32_t* pdwFlags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hProcess);
    static_cast<void>(pRecoveryCallback);
    static_cast<void>(ppvParameter);
    static_cast<void>(pdwPingInterval);
    static_cast<void>(pdwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetApplicationRestartSettings(void* hProcess, char16_t* pwzCommandline, std::uint32_t* pcchSize, std::uint32_t* pdwFlags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hProcess);
    static_cast<void>(pwzCommandline);
    static_cast<void>(pcchSize);
    static_cast<void>(pdwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetAtomNameA(std::uint16_t nAtom, char* lpBuffer, std::int32_t nSize) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(nAtom);
    static_cast<void>(lpBuffer);
    static_cast<void>(nSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetAtomNameW(std::uint16_t nAtom, char16_t* lpBuffer, std::int32_t nSize) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(nAtom);
    static_cast<void>(lpBuffer);
    static_cast<void>(nSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetBinaryTypeA(const char* lpApplicationName, std::uint32_t* lpBinaryType) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpApplicationName);
    static_cast<void>(lpBinaryType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetBinaryTypeW(const char16_t* lpApplicationName, std::uint32_t* lpBinaryType) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpApplicationName);
    static_cast<void>(lpBinaryType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetCachedSigningLevel(void* File, std::uint32_t* Flags, std::uint32_t* SigningLevel, std::uint8_t* Thumbprint, std::uint32_t* ThumbprintSize, std::uint32_t* ThumbprintAlgorithm) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(File);
    static_cast<void>(Flags);
    static_cast<void>(SigningLevel);
    static_cast<void>(Thumbprint);
    static_cast<void>(ThumbprintSize);
    static_cast<void>(ThumbprintAlgorithm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetCalendarInfoA(std::uint32_t Locale, std::uint32_t Calendar, std::uint32_t CalType, char* lpCalData, std::int32_t cchData, std::uint32_t* lpValue) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(Calendar);
    static_cast<void>(CalType);
    static_cast<void>(lpCalData);
    static_cast<void>(cchData);
    static_cast<void>(lpValue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetCalendarInfoEx(const char16_t* lpLocaleName, std::uint32_t Calendar, const char16_t* lpReserved, std::uint32_t CalType, char16_t* lpCalData, std::int32_t cchData, std::uint32_t* lpValue) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpLocaleName);
    static_cast<void>(Calendar);
    static_cast<void>(lpReserved);
    static_cast<void>(CalType);
    static_cast<void>(lpCalData);
    static_cast<void>(cchData);
    static_cast<void>(lpValue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetCalendarInfoW(std::uint32_t Locale, std::uint32_t Calendar, std::uint32_t CalType, char16_t* lpCalData, std::int32_t cchData, std::uint32_t* lpValue) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(Calendar);
    static_cast<void>(CalType);
    static_cast<void>(lpCalData);
    static_cast<void>(cchData);
    static_cast<void>(lpValue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetCommConfig(void* hCommDev, void* lpCC, std::uint32_t* lpdwSize) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hCommDev);
    static_cast<void>(lpCC);
    static_cast<void>(lpdwSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetCommMask(void* hFile, std::uint32_t* lpEvtMask) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hFile);
    static_cast<void>(lpEvtMask);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetCommModemStatus(void* hFile, std::uint32_t* lpModemStat) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hFile);
    static_cast<void>(lpModemStat);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetCommProperties(void* hFile, void* lpCommProp) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hFile);
    static_cast<void>(lpCommProp);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetCommState(void* hFile, void* lpDCB) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hFile);
    static_cast<void>(lpDCB);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetCommTimeouts(void* hFile, void* lpCommTimeouts) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hFile);
    static_cast<void>(lpCommTimeouts);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetCompressedFileSizeTransactedA(const char* lpFileName, std::uint32_t* lpFileSizeHigh, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(lpFileSizeHigh);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetCompressedFileSizeTransactedW(const char16_t* lpFileName, std::uint32_t* lpFileSizeHigh, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(lpFileSizeHigh);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetConsoleAliasA(char* Source, char* TargetBuffer, std::uint32_t TargetBufferLength, char* ExeName) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(Source);
    static_cast<void>(TargetBuffer);
    static_cast<void>(TargetBufferLength);
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetConsoleAliasExesA(char* ExeNameBuffer, std::uint32_t ExeNameBufferLength) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(ExeNameBuffer);
    static_cast<void>(ExeNameBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetConsoleAliasExesLengthA() noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetConsoleAliasExesLengthW() noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetConsoleAliasExesW(char16_t* ExeNameBuffer, std::uint32_t ExeNameBufferLength) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(ExeNameBuffer);
    static_cast<void>(ExeNameBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetConsoleAliasW(char16_t* Source, char16_t* TargetBuffer, std::uint32_t TargetBufferLength, char16_t* ExeName) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(Source);
    static_cast<void>(TargetBuffer);
    static_cast<void>(TargetBufferLength);
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetConsoleAliasesA(char* AliasBuffer, std::uint32_t AliasBufferLength, char* ExeName) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(AliasBuffer);
    static_cast<void>(AliasBufferLength);
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetConsoleAliasesLengthA(char* ExeName) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetConsoleAliasesLengthW(char16_t* ExeName) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetConsoleAliasesW(char16_t* AliasBuffer, std::uint32_t AliasBufferLength, char16_t* ExeName) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(AliasBuffer);
    static_cast<void>(AliasBufferLength);
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetConsoleCommandHistoryA(char* Commands, std::uint32_t CommandBufferLength, char* ExeName) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(Commands);
    static_cast<void>(CommandBufferLength);
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetConsoleCommandHistoryLengthA(char* ExeName) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetConsoleCommandHistoryLengthW(char16_t* ExeName) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetConsoleCommandHistoryW(char16_t* Commands, std::uint32_t CommandBufferLength, char16_t* ExeName) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(Commands);
    static_cast<void>(CommandBufferLength);
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetConsoleDisplayMode(std::uint32_t* lpModeFlags) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(lpModeFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetConsoleHistoryInfo(std::uint64_t lpConsoleHistoryInfo) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(lpConsoleHistoryInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetConsoleProcessList(std::uint32_t* lpdwProcessList, std::uint32_t dwProcessCount) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(lpdwProcessList);
    static_cast<void>(dwProcessCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetConsoleScreenBufferInfoEx(void* hConsoleOutput, std::uint64_t lpConsoleScreenBufferInfoEx) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(hConsoleOutput);
    static_cast<void>(lpConsoleScreenBufferInfoEx);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetConsoleSelectionInfo(std::uint64_t lpConsoleSelectionInfo) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(lpConsoleSelectionInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetCurrencyFormatA(std::uint32_t Locale, std::uint32_t dwFlags, const char* lpValue, const void* lpFormat, char* lpCurrencyStr, std::int32_t cchCurrency) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(dwFlags);
    static_cast<void>(lpValue);
    static_cast<void>(lpFormat);
    static_cast<void>(lpCurrencyStr);
    static_cast<void>(cchCurrency);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetCurrencyFormatEx(const char16_t* lpLocaleName, std::uint32_t dwFlags, const char16_t* lpValue, const void* lpFormat, char16_t* lpCurrencyStr, std::int32_t cchCurrency) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpLocaleName);
    static_cast<void>(dwFlags);
    static_cast<void>(lpValue);
    static_cast<void>(lpFormat);
    static_cast<void>(lpCurrencyStr);
    static_cast<void>(cchCurrency);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetCurrencyFormatW(std::uint32_t Locale, std::uint32_t dwFlags, const char16_t* lpValue, const void* lpFormat, char16_t* lpCurrencyStr, std::int32_t cchCurrency) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(dwFlags);
    static_cast<void>(lpValue);
    static_cast<void>(lpFormat);
    static_cast<void>(lpCurrencyStr);
    static_cast<void>(cchCurrency);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetCurrentActCtx(void* lphActCtx) noexcept {
    // Refused: the side-by-side activation context.
    //
    // an activation context is built from a manifest and a catalog store by
    // the loader's own subsystem; this runtime resolves modules by name
    static_cast<void>(lphActCtx);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetCurrentConsoleFont(void* hConsoleOutput, std::int32_t bMaximumWindow, std::uint64_t lpConsoleCurrentFont) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(hConsoleOutput);
    static_cast<void>(bMaximumWindow);
    static_cast<void>(lpConsoleCurrentFont);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetCurrentConsoleFontEx(void* hConsoleOutput, std::int32_t bMaximumWindow, std::uint64_t lpConsoleCurrentFontEx) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(hConsoleOutput);
    static_cast<void>(bMaximumWindow);
    static_cast<void>(lpConsoleCurrentFontEx);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_GetCurrentThreadStackLimits(std::uint64_t* LowLimit, std::uint64_t* HighLimit) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(LowLimit);
    static_cast<void>(HighLimit);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_GetCurrentUmsThread() noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetDateFormatA(std::uint32_t Locale, std::uint32_t dwFlags, const void* lpDate, const char* lpFormat, char* lpDateStr, std::int32_t cchDate) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(dwFlags);
    static_cast<void>(lpDate);
    static_cast<void>(lpFormat);
    static_cast<void>(lpDateStr);
    static_cast<void>(cchDate);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetDateFormatEx(const char16_t* lpLocaleName, std::uint32_t dwFlags, const void* lpDate, const char16_t* lpFormat, char16_t* lpDateStr, std::int32_t cchDate, const char16_t* lpCalendar) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpLocaleName);
    static_cast<void>(dwFlags);
    static_cast<void>(lpDate);
    static_cast<void>(lpFormat);
    static_cast<void>(lpDateStr);
    static_cast<void>(cchDate);
    static_cast<void>(lpCalendar);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetDateFormatW(std::uint32_t Locale, std::uint32_t dwFlags, const void* lpDate, const char16_t* lpFormat, char16_t* lpDateStr, std::int32_t cchDate) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(dwFlags);
    static_cast<void>(lpDate);
    static_cast<void>(lpFormat);
    static_cast<void>(lpDateStr);
    static_cast<void>(cchDate);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetDefaultCommConfigA(const char* lpszName, void* lpCC, std::uint32_t* lpdwSize) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(lpszName);
    static_cast<void>(lpCC);
    static_cast<void>(lpdwSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetDefaultCommConfigW(const char16_t* lpszName, void* lpCC, std::uint32_t* lpdwSize) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(lpszName);
    static_cast<void>(lpCC);
    static_cast<void>(lpdwSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetDevicePowerState(void* hDevice, std::int32_t* pfOn) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(hDevice);
    static_cast<void>(pfOn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetDllDirectoryA(std::uint32_t nBufferLength, char* lpBuffer) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(nBufferLength);
    static_cast<void>(lpBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetDllDirectoryW(std::uint32_t nBufferLength, char16_t* lpBuffer) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(nBufferLength);
    static_cast<void>(lpBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetDurationFormat(std::uint32_t Locale, std::uint32_t dwFlags, const void* lpDuration, std::uint64_t ullDuration, const char16_t* lpFormat, char16_t* lpDurationStr, std::int32_t cchDuration) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(dwFlags);
    static_cast<void>(lpDuration);
    static_cast<void>(ullDuration);
    static_cast<void>(lpFormat);
    static_cast<void>(lpDurationStr);
    static_cast<void>(cchDuration);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetDurationFormatEx(const char16_t* lpLocaleName, std::uint32_t dwFlags, const void* lpDuration, std::uint64_t ullDuration, const char16_t* lpFormat, char16_t* lpDurationStr, std::int32_t cchDuration) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpLocaleName);
    static_cast<void>(dwFlags);
    static_cast<void>(lpDuration);
    static_cast<void>(ullDuration);
    static_cast<void>(lpFormat);
    static_cast<void>(lpDurationStr);
    static_cast<void>(cchDuration);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) char* kkernel32G_GetEnvironmentStrings() noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetFileAttributesTransactedA(const char* lpFileName, std::uint64_t fInfoLevelId, void* lpFileInformation, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(fInfoLevelId);
    static_cast<void>(lpFileInformation);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetFileAttributesTransactedW(const char16_t* lpFileName, std::uint64_t fInfoLevelId, void* lpFileInformation, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(fInfoLevelId);
    static_cast<void>(lpFileInformation);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetFileBandwidthReservation(void* hFile, std::uint32_t* lpPeriodMilliseconds, std::uint32_t* lpBytesPerPeriod, std::int32_t* pDiscardable, std::uint32_t* lpTransferSize, std::uint32_t* lpNumOutstandingRequests) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lpPeriodMilliseconds);
    static_cast<void>(lpBytesPerPeriod);
    static_cast<void>(pDiscardable);
    static_cast<void>(lpTransferSize);
    static_cast<void>(lpNumOutstandingRequests);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetFileMUIInfo(std::uint32_t dwFlags, const char16_t* pcwszFilePath, std::uint64_t pFileMUIInfo, std::uint32_t* pcbFileMUIInfo) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(dwFlags);
    static_cast<void>(pcwszFilePath);
    static_cast<void>(pFileMUIInfo);
    static_cast<void>(pcbFileMUIInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetFileMUIPath(std::uint32_t dwFlags, const char16_t* pcwszFilePath, char16_t* pwszLanguage, std::uint32_t* pcchLanguage, char16_t* pwszFileMUIPath, std::uint32_t* pcchFileMUIPath, std::uint64_t* pululEnumerator) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(dwFlags);
    static_cast<void>(pcwszFilePath);
    static_cast<void>(pwszLanguage);
    static_cast<void>(pcchLanguage);
    static_cast<void>(pwszFileMUIPath);
    static_cast<void>(pcchFileMUIPath);
    static_cast<void>(pululEnumerator);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetFileSize(void* hFile, std::uint32_t* lpFileSizeHigh) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lpFileSizeHigh);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetFinalPathNameByHandleA(void* hFile, char* lpszFilePath, std::uint32_t cchFilePath, std::uint32_t dwFlags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lpszFilePath);
    static_cast<void>(cchFilePath);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetFinalPathNameByHandleW(void* hFile, char16_t* lpszFilePath, std::uint32_t cchFilePath, std::uint32_t dwFlags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lpszFilePath);
    static_cast<void>(cchFilePath);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetFirmwareEnvironmentVariableExA(const char* lpName, const char* lpGuid, void* pBuffer, std::uint32_t nSize, std::uint32_t* pdwAttribubutes) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(lpName);
    static_cast<void>(lpGuid);
    static_cast<void>(pBuffer);
    static_cast<void>(nSize);
    static_cast<void>(pdwAttribubutes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetFirmwareEnvironmentVariableExW(const char16_t* lpName, const char16_t* lpGuid, void* pBuffer, std::uint32_t nSize, std::uint32_t* pdwAttribubutes) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(lpName);
    static_cast<void>(lpGuid);
    static_cast<void>(pBuffer);
    static_cast<void>(nSize);
    static_cast<void>(pdwAttribubutes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetFirmwareType(std::int32_t* FirmwareType) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(FirmwareType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetFullPathNameTransactedA(const char* lpFileName, std::uint32_t nBufferLength, char* lpBuffer, char** lpFilePart, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(nBufferLength);
    static_cast<void>(lpBuffer);
    static_cast<void>(lpFilePart);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetFullPathNameTransactedW(const char16_t* lpFileName, std::uint32_t nBufferLength, char16_t* lpBuffer, char16_t** lpFilePart, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(nBufferLength);
    static_cast<void>(lpBuffer);
    static_cast<void>(lpFilePart);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetGeoInfoA(std::int32_t Location, std::uint64_t GeoType, char* lpGeoData, std::int32_t cchData, std::uint16_t LangId) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Location);
    static_cast<void>(GeoType);
    static_cast<void>(lpGeoData);
    static_cast<void>(cchData);
    static_cast<void>(LangId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetGeoInfoW(std::int32_t Location, std::uint64_t GeoType, char16_t* lpGeoData, std::int32_t cchData, std::uint16_t LangId) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Location);
    static_cast<void>(GeoType);
    static_cast<void>(lpGeoData);
    static_cast<void>(cchData);
    static_cast<void>(LangId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetLocaleInfoEx(const char16_t* lpLocaleName, std::uint64_t LCType, char16_t* lpLCData, std::int32_t cchData) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpLocaleName);
    static_cast<void>(LCType);
    static_cast<void>(lpLCData);
    static_cast<void>(cchData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetLogicalDrives() noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetLongPathNameTransactedA(const char* lpszShortPath, char* lpszLongPath, std::uint32_t cchBuffer, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpszShortPath);
    static_cast<void>(lpszLongPath);
    static_cast<void>(cchBuffer);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetLongPathNameTransactedW(const char16_t* lpszShortPath, char16_t* lpszLongPath, std::uint32_t cchBuffer, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpszShortPath);
    static_cast<void>(lpszLongPath);
    static_cast<void>(cchBuffer);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetMailslotInfo(void* hMailslot, std::uint32_t* lpMaxMessageSize, std::uint32_t* lpNextSize, std::uint32_t* lpMessageCount, std::uint32_t* lpReadTimeout) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(hMailslot);
    static_cast<void>(lpMaxMessageSize);
    static_cast<void>(lpNextSize);
    static_cast<void>(lpMessageCount);
    static_cast<void>(lpReadTimeout);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetMaximumProcessorCount(std::uint16_t GroupNumber) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(GroupNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_GetMaximumProcessorGroupCount() noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetMemoryErrorHandlingCapabilities(std::uint32_t* Capabilities) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Capabilities);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNLSVersion(std::uint32_t Function, std::uint32_t Locale, std::uint64_t lpVersionInformation) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Function);
    static_cast<void>(Locale);
    static_cast<void>(lpVersionInformation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNLSVersionEx(std::uint32_t function, const char16_t* lpLocaleName, std::uint64_t lpVersionInformation) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(function);
    static_cast<void>(lpLocaleName);
    static_cast<void>(lpVersionInformation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNamedPipeClientComputerNameA(void* Pipe, char* ClientComputerName, std::uint32_t ClientComputerNameLength) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(Pipe);
    static_cast<void>(ClientComputerName);
    static_cast<void>(ClientComputerNameLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNamedPipeClientComputerNameW(void* Pipe, char16_t* ClientComputerName, std::uint32_t ClientComputerNameLength) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(Pipe);
    static_cast<void>(ClientComputerName);
    static_cast<void>(ClientComputerNameLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNamedPipeClientProcessId(void* Pipe, std::uint32_t* ClientProcessId) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(Pipe);
    static_cast<void>(ClientProcessId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNamedPipeClientSessionId(void* Pipe, std::uint32_t* ClientSessionId) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(Pipe);
    static_cast<void>(ClientSessionId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNamedPipeHandleStateA(void* hNamedPipe, std::uint32_t* lpState, std::uint32_t* lpCurInstances, std::uint32_t* lpMaxCollectionCount, std::uint32_t* lpCollectDataTimeout, char* lpUserName, std::uint32_t nMaxUserNameSize) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(hNamedPipe);
    static_cast<void>(lpState);
    static_cast<void>(lpCurInstances);
    static_cast<void>(lpMaxCollectionCount);
    static_cast<void>(lpCollectDataTimeout);
    static_cast<void>(lpUserName);
    static_cast<void>(nMaxUserNameSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNamedPipeHandleStateW(void* hNamedPipe, std::uint32_t* lpState, std::uint32_t* lpCurInstances, std::uint32_t* lpMaxCollectionCount, std::uint32_t* lpCollectDataTimeout, char16_t* lpUserName, std::uint32_t nMaxUserNameSize) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(hNamedPipe);
    static_cast<void>(lpState);
    static_cast<void>(lpCurInstances);
    static_cast<void>(lpMaxCollectionCount);
    static_cast<void>(lpCollectDataTimeout);
    static_cast<void>(lpUserName);
    static_cast<void>(nMaxUserNameSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNamedPipeInfo(void* hNamedPipe, std::uint32_t* lpFlags, std::uint32_t* lpOutBufferSize, std::uint32_t* lpInBufferSize, std::uint32_t* lpMaxInstances) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(hNamedPipe);
    static_cast<void>(lpFlags);
    static_cast<void>(lpOutBufferSize);
    static_cast<void>(lpInBufferSize);
    static_cast<void>(lpMaxInstances);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNamedPipeServerProcessId(void* Pipe, std::uint32_t* ServerProcessId) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(Pipe);
    static_cast<void>(ServerProcessId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNamedPipeServerSessionId(void* Pipe, std::uint32_t* ServerSessionId) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(Pipe);
    static_cast<void>(ServerSessionId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_GetNextUmsListItem(void* UmsContext) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(UmsContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNumaAvailableMemoryNode(std::uint8_t Node, std::uint64_t* AvailableBytes) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Node);
    static_cast<void>(AvailableBytes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNumaAvailableMemoryNodeEx(std::uint16_t Node, std::uint64_t* AvailableBytes) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Node);
    static_cast<void>(AvailableBytes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNumaNodeNumberFromHandle(void* hFile, std::uint16_t* NodeNumber) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(NodeNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNumaNodeProcessorMask(std::uint8_t Node, std::uint64_t* ProcessorMask) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Node);
    static_cast<void>(ProcessorMask);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNumaNodeProcessorMaskEx(std::uint16_t Node, void* ProcessorMask) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Node);
    static_cast<void>(ProcessorMask);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNumaProcessorNode(std::uint8_t Processor, std::uint8_t* NodeNumber) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Processor);
    static_cast<void>(NodeNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNumaProcessorNodeEx(std::uint32_t* Processor, std::uint16_t* NodeNumber) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Processor);
    static_cast<void>(NodeNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNumaProximityNode(std::uint32_t ProximityId, std::uint8_t* NodeNumber) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(ProximityId);
    static_cast<void>(NodeNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNumaProximityNodeEx(std::uint32_t ProximityId, std::uint16_t* NodeNumber) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(ProximityId);
    static_cast<void>(NodeNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNumberFormatA(std::uint32_t Locale, std::uint32_t dwFlags, const char* lpValue, const void* lpFormat, char* lpNumberStr, std::int32_t cchNumber) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(dwFlags);
    static_cast<void>(lpValue);
    static_cast<void>(lpFormat);
    static_cast<void>(lpNumberStr);
    static_cast<void>(cchNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNumberFormatEx(const char16_t* lpLocaleName, std::uint32_t dwFlags, const char16_t* lpValue, const void* lpFormat, char16_t* lpNumberStr, std::int32_t cchNumber) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpLocaleName);
    static_cast<void>(dwFlags);
    static_cast<void>(lpValue);
    static_cast<void>(lpFormat);
    static_cast<void>(lpNumberStr);
    static_cast<void>(cchNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNumberFormatW(std::uint32_t Locale, std::uint32_t dwFlags, const char16_t* lpValue, const void* lpFormat, char16_t* lpNumberStr, std::int32_t cchNumber) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(dwFlags);
    static_cast<void>(lpValue);
    static_cast<void>(lpFormat);
    static_cast<void>(lpNumberStr);
    static_cast<void>(cchNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetNumberOfConsoleMouseButtons(std::uint32_t* lpNumberOfMouseButtons) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(lpNumberOfMouseButtons);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetOverlappedResultEx(void* hFile, void* lpOverlapped, std::uint32_t* lpNumberOfBytesTransferred, std::uint32_t dwMilliseconds, std::int32_t bAlertable) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lpOverlapped);
    static_cast<void>(lpNumberOfBytesTransferred);
    static_cast<void>(dwMilliseconds);
    static_cast<void>(bAlertable);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetPhysicallyInstalledSystemMemory(std::uint64_t* TotalMemoryInKilobytes) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(TotalMemoryInKilobytes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetPrivateProfileIntA(const char* lpAppName, const char* lpKeyName, std::int32_t nDefault, const char* lpFileName) noexcept {
    const std::u16string wide_app = profile_wide(lpAppName);
    const std::u16string wide_key = profile_wide(lpKeyName);
    const std::u16string wide_path = profile_wide(lpFileName);
    if (lpAppName == nullptr || lpKeyName == nullptr || lpFileName == nullptr) {
        return static_cast<std::uint32_t>(nDefault);
    }
    std::u16string answer;
    std::vector<std::u16string> lines;
    if (!profile_load(wide_path, &lines) ||
        !profile_get(lines, wide_app, wide_key, &answer)) {
        return static_cast<std::uint32_t>(nDefault);
    }
    // The value is read as a decimal number and stops at the first character
    // that is not one. A value that holds no digit at all answers the
    // default, which is the reference's rule and the reason the call is
    // usable on a setting a user has typed into by hand.
    bool any = false;
    for (std::size_t index = 0; index < answer.size(); ++index) {
        if (ch_digit(answer[index])) {
            any = true;
            break;
        }
    }
    if (!any) {
        return static_cast<std::uint32_t>(nDefault);
    }
    return static_cast<std::uint32_t>(ini_number(answer.c_str(), answer.size()));
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetPrivateProfileIntW(const char16_t* lpAppName, const char16_t* lpKeyName, std::int32_t nDefault, const char16_t* lpFileName) noexcept {
    if (lpAppName == nullptr || lpKeyName == nullptr || lpFileName == nullptr) {
        return static_cast<std::uint32_t>(nDefault);
    }
    std::u16string answer;
    std::vector<std::u16string> lines;
    if (!profile_load(lpFileName, &lines) ||
        !profile_get(lines, lpAppName, lpKeyName, &answer)) {
        return static_cast<std::uint32_t>(nDefault);
    }
    // The value is read as a decimal number and stops at the first character
    // that is not one. A value that holds no digit at all answers the
    // default, which is the reference's rule and the reason the call is
    // usable on a setting a user has typed into by hand.
    bool any = false;
    for (std::size_t index = 0; index < answer.size(); ++index) {
        if (ch_digit(answer[index])) {
            any = true;
            break;
        }
    }
    if (!any) {
        return static_cast<std::uint32_t>(nDefault);
    }
    return static_cast<std::uint32_t>(ini_number(answer.c_str(), answer.size()));
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetPrivateProfileSectionA(const char* lpAppName, char* lpReturnedString, std::uint32_t nSize, const char* lpFileName) noexcept {
    const std::u16string wide_app = profile_wide(lpAppName);
    const std::u16string wide_path = profile_wide(lpFileName);
    if (lpReturnedString == nullptr || nSize == 0 || lpFileName == nullptr) {
        return 0;
    }
    std::u16string answer;
    if (lpAppName != nullptr) {
        std::vector<std::u16string> lines;
        static_cast<void>(profile_load(wide_path, &lines));
        answer = profile_section_text(lines, wide_app);
    }
        copy_list_to_narrow(answer, lpReturnedString, nSize);
    return static_cast<std::uint32_t>(text_len_at(lpReturnedString, nSize)) + 1;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetPrivateProfileSectionNamesA(char* lpszReturnBuffer, std::uint32_t nSize, const char* lpFileName) noexcept {
    const std::u16string wide_path = profile_wide(lpFileName);
    if (lpszReturnBuffer == nullptr || nSize == 0 || lpFileName == nullptr) {
        return 0;
    }
    std::vector<std::u16string> lines;
    static_cast<void>(profile_load(wide_path, &lines));
    const std::u16string answer = profile_section_names(lines);
        copy_list_to_narrow(answer, lpszReturnBuffer, nSize);
    return static_cast<std::uint32_t>(text_len_at(lpszReturnBuffer, nSize)) + 1;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetPrivateProfileSectionNamesW(char16_t* lpszReturnBuffer, std::uint32_t nSize, const char16_t* lpFileName) noexcept {
    if (lpszReturnBuffer == nullptr || nSize == 0 || lpFileName == nullptr) {
        return 0;
    }
    std::vector<std::u16string> lines;
    static_cast<void>(profile_load(lpFileName, &lines));
    const std::u16string answer = profile_section_names(lines);
        static_cast<void>(text_copy<char16_t>(lpszReturnBuffer, nSize, answer.c_str()));
    return static_cast<std::uint32_t>(text_len_at(lpszReturnBuffer, nSize)) + 1;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetPrivateProfileSectionW(const char16_t* lpAppName, char16_t* lpReturnedString, std::uint32_t nSize, const char16_t* lpFileName) noexcept {
    if (lpReturnedString == nullptr || nSize == 0 || lpFileName == nullptr) {
        return 0;
    }
    std::u16string answer;
    if (lpAppName != nullptr) {
        std::vector<std::u16string> lines;
        static_cast<void>(profile_load(lpFileName, &lines));
        answer = profile_section_text(lines, lpAppName);
    }
        static_cast<void>(text_copy<char16_t>(lpReturnedString, nSize, answer.c_str()));
    return static_cast<std::uint32_t>(text_len_at(lpReturnedString, nSize)) + 1;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetPrivateProfileStringA(const char* lpAppName, const char* lpKeyName, const char* lpDefault, char* lpReturnedString, std::uint32_t nSize, const char* lpFileName) noexcept {
    const std::u16string wide_app = profile_wide(lpAppName);
    const std::u16string wide_key = profile_wide(lpKeyName);
    const std::u16string wide_default = profile_wide(lpDefault);
    const std::u16string wide_path = profile_wide(lpFileName);
    if (lpReturnedString == nullptr || nSize == 0) {
        return 0;
    }
    // A missing key, a missing section and a missing file are one case in
    // the format, and each is answered with the default rather than with an
    // error: that is what makes the call usable for a setting that has
    // never been written.
    std::u16string answer;
    std::vector<std::u16string> lines;
    if (lpKeyName != nullptr && lpAppName != nullptr && lpFileName != nullptr &&
        profile_load(wide_path, &lines) &&
        profile_get(lines, wide_app, wide_key, &answer)) {
        static_cast<void>(0);
    } else {
        answer = lpDefault == nullptr ? std::u16string{}
                                        : std::u16string(wide_default);
    }
    // The answer is truncated to the caller's buffer, and the length
    // reported is what was written with the terminator counted, which is how
    // a caller detects that it was cut.
        static_cast<void>(narrow_text(answer.c_str(), lpReturnedString, nSize));
    lpReturnedString[nSize - 1] = 0;
    return static_cast<std::uint32_t>(text_len_at(lpReturnedString, nSize)) + 1;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetPrivateProfileStringW(const char16_t* lpAppName, const char16_t* lpKeyName, const char16_t* lpDefault, char16_t* lpReturnedString, std::uint32_t nSize, const char16_t* lpFileName) noexcept {
    if (lpReturnedString == nullptr || nSize == 0) {
        return 0;
    }
    // A missing key, a missing section and a missing file are one case in
    // the format, and each is answered with the default rather than with an
    // error: that is what makes the call usable for a setting that has
    // never been written.
    std::u16string answer;
    std::vector<std::u16string> lines;
    if (lpKeyName != nullptr && lpAppName != nullptr && lpFileName != nullptr &&
        profile_load(lpFileName, &lines) &&
        profile_get(lines, lpAppName, lpKeyName, &answer)) {
        static_cast<void>(0);
    } else {
        answer = lpDefault == nullptr ? std::u16string{}
                                        : std::u16string(lpDefault);
    }
    // The answer is truncated to the caller's buffer, and the length
    // reported is what was written with the terminator counted, which is how
    // a caller detects that it was cut.
        static_cast<void>(text_copy<char16_t>(lpReturnedString, nSize, answer.c_str()));
    return static_cast<std::uint32_t>(text_len_at(lpReturnedString, nSize)) + 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetPrivateProfileStructA(const char* lpszSection, const char* lpszKey, void* lpStruct, std::uint32_t uSizeStruct, const char* szFile) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(lpszSection);
    static_cast<void>(lpszKey);
    static_cast<void>(lpStruct);
    static_cast<void>(uSizeStruct);
    static_cast<void>(szFile);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetPrivateProfileStructW(const char16_t* lpszSection, const char16_t* lpszKey, void* lpStruct, std::uint32_t uSizeStruct, const char16_t* szFile) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(lpszSection);
    static_cast<void>(lpszKey);
    static_cast<void>(lpStruct);
    static_cast<void>(uSizeStruct);
    static_cast<void>(szFile);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetProcessHandleCount(void* hProcess, std::uint32_t* pdwHandleCount) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hProcess);
    static_cast<void>(pdwHandleCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetProcessInformation(void* hProcess, std::uint64_t ProcessInformationClass, void* ProcessInformation, std::uint32_t ProcessInformationSize) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hProcess);
    static_cast<void>(ProcessInformationClass);
    static_cast<void>(ProcessInformation);
    static_cast<void>(ProcessInformationSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetProcessPreferredUILanguages(std::uint32_t dwFlags, std::uint32_t* pulNumLanguages, char16_t* pwszLanguagesBuffer, std::uint32_t* pcchLanguagesBuffer) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(dwFlags);
    static_cast<void>(pulNumLanguages);
    static_cast<void>(pwszLanguagesBuffer);
    static_cast<void>(pcchLanguagesBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetProcessWorkingSetSizeEx(void* hProcess, std::uint64_t* lpMinimumWorkingSetSize, std::uint64_t* lpMaximumWorkingSetSize, std::uint32_t* Flags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hProcess);
    static_cast<void>(lpMinimumWorkingSetSize);
    static_cast<void>(lpMaximumWorkingSetSize);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetProcessorSystemCycleTime(std::uint16_t Group, std::uint64_t Buffer, std::uint32_t* ReturnedLength) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Group);
    static_cast<void>(Buffer);
    static_cast<void>(ReturnedLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetProfileIntA(const char* lpAppName, const char* lpKeyName, std::int32_t nDefault) noexcept {
    const std::u16string wide_app = profile_wide(lpAppName);
    const std::u16string wide_key = profile_wide(lpKeyName);
    if (lpAppName == nullptr || lpKeyName == nullptr || profile_shared_file() == nullptr) {
        return static_cast<std::uint32_t>(nDefault);
    }
    std::u16string answer;
    std::vector<std::u16string> lines;
    if (!profile_load(profile_shared_file(), &lines) ||
        !profile_get(lines, wide_app, wide_key, &answer)) {
        return static_cast<std::uint32_t>(nDefault);
    }
    // The value is read as a decimal number and stops at the first character
    // that is not one. A value that holds no digit at all answers the
    // default, which is the reference's rule and the reason the call is
    // usable on a setting a user has typed into by hand.
    bool any = false;
    for (std::size_t index = 0; index < answer.size(); ++index) {
        if (ch_digit(answer[index])) {
            any = true;
            break;
        }
    }
    if (!any) {
        return static_cast<std::uint32_t>(nDefault);
    }
    return static_cast<std::uint32_t>(ini_number(answer.c_str(), answer.size()));
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetProfileIntW(const char16_t* lpAppName, const char16_t* lpKeyName, std::int32_t nDefault) noexcept {
    if (lpAppName == nullptr || lpKeyName == nullptr || profile_shared_file() == nullptr) {
        return static_cast<std::uint32_t>(nDefault);
    }
    std::u16string answer;
    std::vector<std::u16string> lines;
    if (!profile_load(profile_shared_file(), &lines) ||
        !profile_get(lines, lpAppName, lpKeyName, &answer)) {
        return static_cast<std::uint32_t>(nDefault);
    }
    // The value is read as a decimal number and stops at the first character
    // that is not one. A value that holds no digit at all answers the
    // default, which is the reference's rule and the reason the call is
    // usable on a setting a user has typed into by hand.
    bool any = false;
    for (std::size_t index = 0; index < answer.size(); ++index) {
        if (ch_digit(answer[index])) {
            any = true;
            break;
        }
    }
    if (!any) {
        return static_cast<std::uint32_t>(nDefault);
    }
    return static_cast<std::uint32_t>(ini_number(answer.c_str(), answer.size()));
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetProfileSectionA(const char* lpAppName, char* lpReturnedString, std::uint32_t nSize) noexcept {
    const std::u16string wide_app = profile_wide(lpAppName);
    if (lpReturnedString == nullptr || nSize == 0 || profile_shared_file() == nullptr) {
        return 0;
    }
    std::u16string answer;
    if (lpAppName != nullptr) {
        std::vector<std::u16string> lines;
        static_cast<void>(profile_load(profile_shared_file(), &lines));
        answer = profile_section_text(lines, wide_app);
    }
        copy_list_to_narrow(answer, lpReturnedString, nSize);
    return static_cast<std::uint32_t>(text_len_at(lpReturnedString, nSize)) + 1;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetProfileSectionW(const char16_t* lpAppName, char16_t* lpReturnedString, std::uint32_t nSize) noexcept {
    if (lpReturnedString == nullptr || nSize == 0 || profile_shared_file() == nullptr) {
        return 0;
    }
    std::u16string answer;
    if (lpAppName != nullptr) {
        std::vector<std::u16string> lines;
        static_cast<void>(profile_load(profile_shared_file(), &lines));
        answer = profile_section_text(lines, lpAppName);
    }
        static_cast<void>(text_copy<char16_t>(lpReturnedString, nSize, answer.c_str()));
    return static_cast<std::uint32_t>(text_len_at(lpReturnedString, nSize)) + 1;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetProfileStringA(const char* lpAppName, const char* lpKeyName, const char* lpDefault, char* lpReturnedString, std::uint32_t nSize) noexcept {
    const std::u16string wide_app = profile_wide(lpAppName);
    const std::u16string wide_key = profile_wide(lpKeyName);
    const std::u16string wide_default = profile_wide(lpDefault);
    if (lpReturnedString == nullptr || nSize == 0) {
        return 0;
    }
    // A missing key, a missing section and a missing file are one case in
    // the format, and each is answered with the default rather than with an
    // error: that is what makes the call usable for a setting that has
    // never been written.
    std::u16string answer;
    std::vector<std::u16string> lines;
    if (lpKeyName != nullptr && lpAppName != nullptr && profile_shared_file() != nullptr &&
        profile_load(profile_shared_file(), &lines) &&
        profile_get(lines, wide_app, wide_key, &answer)) {
        static_cast<void>(0);
    } else {
        answer = lpDefault == nullptr ? std::u16string{}
                                        : std::u16string(wide_default);
    }
    // The answer is truncated to the caller's buffer, and the length
    // reported is what was written with the terminator counted, which is how
    // a caller detects that it was cut.
        static_cast<void>(narrow_text(answer.c_str(), lpReturnedString, nSize));
    lpReturnedString[nSize - 1] = 0;
    return static_cast<std::uint32_t>(text_len_at(lpReturnedString, nSize)) + 1;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetProfileStringW(const char16_t* lpAppName, const char16_t* lpKeyName, const char16_t* lpDefault, char16_t* lpReturnedString, std::uint32_t nSize) noexcept {
    if (lpReturnedString == nullptr || nSize == 0) {
        return 0;
    }
    // A missing key, a missing section and a missing file are one case in
    // the format, and each is answered with the default rather than with an
    // error: that is what makes the call usable for a setting that has
    // never been written.
    std::u16string answer;
    std::vector<std::u16string> lines;
    if (lpKeyName != nullptr && lpAppName != nullptr && profile_shared_file() != nullptr &&
        profile_load(profile_shared_file(), &lines) &&
        profile_get(lines, lpAppName, lpKeyName, &answer)) {
        static_cast<void>(0);
    } else {
        answer = lpDefault == nullptr ? std::u16string{}
                                        : std::u16string(lpDefault);
    }
    // The answer is truncated to the caller's buffer, and the length
    // reported is what was written with the terminator counted, which is how
    // a caller detects that it was cut.
        static_cast<void>(text_copy<char16_t>(lpReturnedString, nSize, answer.c_str()));
    return static_cast<std::uint32_t>(text_len_at(lpReturnedString, nSize)) + 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetStringScripts(std::uint32_t dwFlags, const char16_t* lpString, std::int32_t cchString, char16_t* lpScripts, std::int32_t cchScripts) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(dwFlags);
    static_cast<void>(lpString);
    static_cast<void>(cchString);
    static_cast<void>(lpScripts);
    static_cast<void>(cchScripts);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kkernel32G_GetSystemDEPPolicy() noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_GetSystemDefaultUILanguage() noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetSystemFileCacheSize(std::uint64_t* lpMinimumFileCacheSize, std::uint64_t* lpMaximumFileCacheSize, std::uint32_t* lpFlags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpMinimumFileCacheSize);
    static_cast<void>(lpMaximumFileCacheSize);
    static_cast<void>(lpFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetSystemPowerStatus(void* lpSystemPowerStatus) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(lpSystemPowerStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetSystemPreferredUILanguages(std::uint32_t dwFlags, std::uint32_t* pulNumLanguages, char16_t* pwszLanguagesBuffer, std::uint32_t* pcchLanguagesBuffer) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(dwFlags);
    static_cast<void>(pulNumLanguages);
    static_cast<void>(pwszLanguagesBuffer);
    static_cast<void>(pcchLanguagesBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetSystemRegistryQuota(std::uint32_t* pdwQuotaAllowed, std::uint32_t* pdwQuotaUsed) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(pdwQuotaAllowed);
    static_cast<void>(pdwQuotaUsed);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetSystemWindowsDirectoryA(char* lpBuffer, std::uint32_t uSize) noexcept {
    // On a machine that is not a terminal server the system Windows
    // directory and the Windows directory are the same, and this runtime
    // presents one installation rather than a session.
    return k32p_GetWindowsDirectoryA(lpBuffer, uSize);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetSystemWindowsDirectoryW(char16_t* lpBuffer, std::uint32_t uSize) noexcept {
    // On a machine that is not a terminal server the system Windows
    // directory and the Windows directory are the same, and this runtime
    // presents one installation rather than a session.
    return k32p_GetWindowsDirectoryW(lpBuffer, uSize);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetTapeParameters(void* hDevice, std::uint32_t dwOperation, std::uint32_t* lpdwSize, void* lpTapeInformation) noexcept {
    // Refused: the tape device layer.
    //
    // a tape is a device reached through the device I/O control surface
    static_cast<void>(hDevice);
    static_cast<void>(dwOperation);
    static_cast<void>(lpdwSize);
    static_cast<void>(lpTapeInformation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetTapePosition(void* hDevice, std::uint32_t dwPositionType, std::uint32_t* lpdwPartition, std::uint32_t* lpdwOffsetLow, std::uint32_t* lpdwOffsetHigh) noexcept {
    // Refused: the tape device layer.
    //
    // a tape is a device reached through the device I/O control surface
    static_cast<void>(hDevice);
    static_cast<void>(dwPositionType);
    static_cast<void>(lpdwPartition);
    static_cast<void>(lpdwOffsetLow);
    static_cast<void>(lpdwOffsetHigh);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetTapeStatus(void* hDevice) noexcept {
    // Refused: the tape device layer.
    //
    // a tape is a device reached through the device I/O control surface
    static_cast<void>(hDevice);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetThreadErrorMode() noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetThreadGroupAffinity(void* hThread, void* GroupAffinity) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hThread);
    static_cast<void>(GroupAffinity);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetThreadIOPendingFlag(void* hThread, std::int32_t* lpIOIsPending) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hThread);
    static_cast<void>(lpIOIsPending);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetThreadInformation(void* hThread, std::uint64_t ThreadInformationClass, void* ThreadInformation, std::uint32_t ThreadInformationSize) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hThread);
    static_cast<void>(ThreadInformationClass);
    static_cast<void>(ThreadInformation);
    static_cast<void>(ThreadInformationSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetThreadLocale() noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetThreadPreferredUILanguages(std::uint32_t dwFlags, std::uint32_t* pulNumLanguages, char16_t* pwszLanguagesBuffer, std::uint32_t* pcchLanguagesBuffer) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(dwFlags);
    static_cast<void>(pulNumLanguages);
    static_cast<void>(pwszLanguagesBuffer);
    static_cast<void>(pcchLanguagesBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetThreadPriorityBoost(void* hThread, std::int32_t* pDisablePriorityBoost) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hThread);
    static_cast<void>(pDisablePriorityBoost);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetThreadSelectorEntry(void* hThread, std::uint32_t dwSelector, std::uint64_t lpSelectorEntry) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hThread);
    static_cast<void>(dwSelector);
    static_cast<void>(lpSelectorEntry);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_GetThreadUILanguage() noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetTimeFormatA(std::uint32_t Locale, std::uint32_t dwFlags, const void* lpTime, const char* lpFormat, char* lpTimeStr, std::int32_t cchTime) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(dwFlags);
    static_cast<void>(lpTime);
    static_cast<void>(lpFormat);
    static_cast<void>(lpTimeStr);
    static_cast<void>(cchTime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetTimeFormatEx(const char16_t* lpLocaleName, std::uint32_t dwFlags, const void* lpTime, const char16_t* lpFormat, char16_t* lpTimeStr, std::int32_t cchTime) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpLocaleName);
    static_cast<void>(dwFlags);
    static_cast<void>(lpTime);
    static_cast<void>(lpFormat);
    static_cast<void>(lpTimeStr);
    static_cast<void>(cchTime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetTimeFormatW(std::uint32_t Locale, std::uint32_t dwFlags, const void* lpTime, const char16_t* lpFormat, char16_t* lpTimeStr, std::int32_t cchTime) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(dwFlags);
    static_cast<void>(lpTime);
    static_cast<void>(lpFormat);
    static_cast<void>(lpTimeStr);
    static_cast<void>(cchTime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetTimeZoneInformationForYear(std::uint16_t wYear, void* pdtzi, void* ptzi) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(wYear);
    static_cast<void>(pdtzi);
    static_cast<void>(ptzi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetUILanguageInfo(std::uint32_t dwFlags, std::uint64_t pwmszLanguage, char16_t* pwszFallbackLanguages, std::uint32_t* pcchFallbackLanguages, std::uint32_t* pAttributes) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(dwFlags);
    static_cast<void>(pwmszLanguage);
    static_cast<void>(pwszFallbackLanguages);
    static_cast<void>(pcchFallbackLanguages);
    static_cast<void>(pAttributes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetUmsSystemThreadInformation(void* ThreadHandle, std::uint64_t SystemThreadInfo) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(ThreadHandle);
    static_cast<void>(SystemThreadInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetUserDefaultGeoName(char16_t* geoName, std::int32_t geoNameCount) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(geoName);
    static_cast<void>(geoNameCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_GetUserDefaultUILanguage() noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetUserGeoID(std::int32_t GeoClass) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(GeoClass);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetVersion() noexcept {
    // The packed form: the major version in the low byte, the minor in the
    // next, and the build in the high word. The numbers are the ones the
    // system-information domain reports, which is what keeps this answer
    // and `GetVersionEx`'s the same.
    return (kReportedOsBuild << 16) | (kReportedOsMinor << 8) | kReportedOsMajor;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetVolumeInformationByHandleW(void* hFile, char16_t* lpVolumeNameBuffer, std::uint32_t nVolumeNameSize, std::uint32_t* lpVolumeSerialNumber, std::uint32_t* lpMaximumComponentLength, std::uint32_t* lpFileSystemFlags, char16_t* lpFileSystemNameBuffer, std::uint32_t nFileSystemNameSize) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(hFile);
    static_cast<void>(lpVolumeNameBuffer);
    static_cast<void>(nVolumeNameSize);
    static_cast<void>(lpVolumeSerialNumber);
    static_cast<void>(lpMaximumComponentLength);
    static_cast<void>(lpFileSystemFlags);
    static_cast<void>(lpFileSystemNameBuffer);
    static_cast<void>(nFileSystemNameSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetVolumeNameForVolumeMountPointA(const char* lpszVolumeMountPoint, char* lpszVolumeName, std::uint32_t cchBufferLength) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(lpszVolumeMountPoint);
    static_cast<void>(lpszVolumeName);
    static_cast<void>(cchBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetVolumeNameForVolumeMountPointW(const char16_t* lpszVolumeMountPoint, char16_t* lpszVolumeName, std::uint32_t cchBufferLength) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(lpszVolumeMountPoint);
    static_cast<void>(lpszVolumeName);
    static_cast<void>(cchBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetVolumePathNamesForVolumeNameA(const char* lpszVolumeName, char* lpszVolumePathNames, std::uint32_t cchBufferLength, std::uint32_t* lpcchReturnLength) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(lpszVolumeName);
    static_cast<void>(lpszVolumePathNames);
    static_cast<void>(cchBufferLength);
    static_cast<void>(lpcchReturnLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetVolumePathNamesForVolumeNameW(const char16_t* lpszVolumeName, char16_t* lpszVolumePathNames, std::uint32_t cchBufferLength, std::uint32_t* lpcchReturnLength) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(lpszVolumeName);
    static_cast<void>(lpszVolumePathNames);
    static_cast<void>(cchBufferLength);
    static_cast<void>(lpcchReturnLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GetWriteWatch(std::uint32_t dwFlags, void* lpBaseAddress, std::uint64_t dwRegionSize, void** lpAddresses, std::uint64_t* lpdwCount, std::uint32_t* lpdwGranularity) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(dwFlags);
    static_cast<void>(lpBaseAddress);
    static_cast<void>(dwRegionSize);
    static_cast<void>(lpAddresses);
    static_cast<void>(lpdwCount);
    static_cast<void>(lpdwGranularity);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GetXStateFeaturesMask(void* Context, std::uint64_t* FeatureMask) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Context);
    static_cast<void>(FeatureMask);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_GlobalAddAtomA(const char* lpString) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(lpString);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_GlobalAddAtomExA(const char* lpString, std::uint32_t Flags) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(lpString);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_GlobalAddAtomExW(const char16_t* lpString, std::uint32_t Flags) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(lpString);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_GlobalAddAtomW(const char16_t* lpString) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(lpString);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kkernel32G_GlobalCompact(std::uint32_t dwMinFree) noexcept {
    static_cast<void>(dwMinFree);
    // `GlobalCompact` is documented as having no effect on Win32: the heap
    // is compacted by the allocator, and the answer is the largest free
    // block. This runtime's allocator has no such query, and answering a
    // number would be inventing one, so the call reports that it could not
    // compact rather than a size.
    set_last_error(kErrorCallNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_GlobalDeleteAtom(std::uint16_t nAtom) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(nAtom);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_GlobalFindAtomA(const char* lpString) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(lpString);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_GlobalFindAtomW(const char16_t* lpString) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(lpString);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_GlobalFix(void* hMem) noexcept {
    static_cast<void>(hMem);
    // Documented as having no effect: the pages of a global block are
    // already pinned for the life of the allocation. The call is kept so
    // that a program written against the 16-bit API still runs.
    
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GlobalGetAtomNameA(std::uint16_t nAtom, char* lpBuffer, std::int32_t nSize) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(nAtom);
    static_cast<void>(lpBuffer);
    static_cast<void>(nSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_GlobalGetAtomNameW(std::uint16_t nAtom, char16_t* lpBuffer, std::int32_t nSize) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(nAtom);
    static_cast<void>(lpBuffer);
    static_cast<void>(nSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_GlobalMemoryStatus(void* lpBuffer) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpBuffer);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_GlobalUnWire(void* hMem) noexcept {
    static_cast<void>(hMem);
    return 1;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_GlobalUnfix(void* hMem) noexcept {
    static_cast<void>(hMem);
    // The other half of `GlobalFix`, and equally without effect.
    
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_GlobalWire(void* hMem) noexcept {
    // A wire that locks a block in place and answers the block. The lock is
    // the allocator's own, which is not movable here, so the answer is the
    // block and the call has nothing else to do.
    return hMem;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_HeapSummary(void* hHeap, std::uint32_t dwFlags, void* lpSummary) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hHeap);
    static_cast<void>(dwFlags);
    static_cast<void>(lpSummary);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_IdnToAscii(std::uint32_t dwFlags, const char16_t* lpUnicodeCharStr, std::int32_t cchUnicodeChar, char16_t* lpASCIICharStr, std::int32_t cchASCIIChar) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(dwFlags);
    static_cast<void>(lpUnicodeCharStr);
    static_cast<void>(cchUnicodeChar);
    static_cast<void>(lpASCIICharStr);
    static_cast<void>(cchASCIIChar);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_IdnToNameprepUnicode(std::uint32_t dwFlags, const char16_t* lpUnicodeCharStr, std::int32_t cchUnicodeChar, char16_t* lpNameprepCharStr, std::int32_t cchNameprepChar) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(dwFlags);
    static_cast<void>(lpUnicodeCharStr);
    static_cast<void>(cchUnicodeChar);
    static_cast<void>(lpNameprepCharStr);
    static_cast<void>(cchNameprepChar);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_IdnToUnicode(std::uint32_t dwFlags, const char16_t* lpASCIICharStr, std::int32_t cchASCIIChar, char16_t* lpUnicodeCharStr, std::int32_t cchUnicodeChar) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(dwFlags);
    static_cast<void>(lpASCIICharStr);
    static_cast<void>(cchASCIIChar);
    static_cast<void>(lpUnicodeCharStr);
    static_cast<void>(cchUnicodeChar);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_InitAtomTable(std::uint32_t nSize) noexcept {
    // Refused: the atom table.
    //
    // the atom table the call addresses is the window manager's, and this
    // runtime has no window manager to own one
    static_cast<void>(nSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_InitOnceBeginInitialize(void* lpInitOnce, std::uint32_t dwFlags, std::int32_t* fPending, void** lpContext) noexcept {
    if (lpInitOnce == nullptr || fPending == nullptr) {
        return 0;
    }
    constexpr std::uint32_t kInitOnceCheckOnly = 0x00000001u;
    auto* cell = static_cast<std::uint64_t*>(lpInitOnce);
    if ((dwFlags & kInitOnceCheckOnly) != 0) {
        // A check that does not run the initialisation: it either reports
        // that the work is not done, or reports the context and says so.
        const std::uint64_t seen = __atomic_load_n(cell, __ATOMIC_SEQ_CST);
        if (seen == 0 || seen == 1) {
            *fPending = 1;
            return 1;
        }
        *fPending = 0;
        if (lpContext != nullptr) {
            *lpContext = reinterpret_cast<void*>(static_cast<std::uintptr_t>(seen));
        }
        return 1;
    }
    std::uint64_t expected = 0;
    if (__atomic_compare_exchange_n(cell, &expected, 1, false,
                                    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        // This caller is the one that will run the work.
        *fPending = 1;
        return 1;
    }
    if (expected == 1) {
        // Another caller is running it. The caller that arrives second waits
        // for the first to finish, which is what makes the context readable.
        while (__atomic_load_n(cell, __ATOMIC_SEQ_CST) == 1) {
        }
        expected = __atomic_load_n(cell, __ATOMIC_SEQ_CST);
    }
    *fPending = 0;
    if (lpContext != nullptr) {
        *lpContext = reinterpret_cast<void*>(static_cast<std::uintptr_t>(expected));
    }
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_InitOnceComplete(void* lpInitOnce, std::uint32_t dwFlags, void* lpContext) noexcept {
    if (lpInitOnce == nullptr) {
        return 0;
    }
    constexpr std::uint32_t kInitOnceInitialize = 0x00000002u;
    auto* cell = static_cast<std::uint64_t*>(lpInitOnce);
    const std::uint64_t stored = (dwFlags & kInitOnceInitialize) != 0
                                     ? 0
                                     : static_cast<std::uint64_t>(
                                           reinterpret_cast<std::uintptr_t>(lpContext));
    __atomic_store_n(cell, stored, __ATOMIC_SEQ_CST);
    return 1;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_InitOnceInitialize(void* InitOnce) noexcept {
    if (InitOnce != nullptr) {
        // The state is one pointer-sized word: null means "not begun", a
        // sentinel means "in progress", and anything else is the caller's
        // context. Writing the sentinel here would start it; this call only
        // clears it.
        *static_cast<std::uint64_t*>(InitOnce) = 0;
    }
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_InitializeProcThreadAttributeList(void* lpAttributeList, std::uint32_t dwAttributeCount, std::uint32_t dwFlags, std::uint64_t* lpSize) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpAttributeList);
    static_cast<void>(dwAttributeCount);
    static_cast<void>(dwFlags);
    static_cast<void>(lpSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_InitializeSRWLock(void* SRWLock) noexcept {
    if (SRWLock != nullptr) {
        // An SRW lock in the unlocked state is a null pointer, which is what
        // makes `InitializeSRWLock` a store and nothing else.
        *static_cast<void**>(SRWLock) = nullptr;
    }
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_InitializeSynchronizationBarrier(void* lpBarrier, std::int32_t lTotalThreads, std::int32_t lSpinCount) noexcept {
    if (lpBarrier == nullptr || lTotalThreads < 1) {
        return 0;
    }
    // The barrier is four pointer-sized words: the count still to arrive,
    // the count the barrier was made with, the spin count, and a generation
    // that lets a caller tell one round from the next.
    auto* words = static_cast<std::uint64_t*>(lpBarrier);
    words[0] = static_cast<std::uint64_t>(lTotalThreads);
    words[1] = static_cast<std::uint64_t>(lTotalThreads);
    words[2] = static_cast<std::uint64_t>(lSpinCount);
    words[3] = 0;
    return 1;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_InterlockedBitTestAndComplement(std::int32_t* a, std::int32_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    // The bit test is the atomic form of the three non-atomic ones: the read
    // and the write are one operation, which is what a caller that uses it
    // as a lock relies on.
    auto* p = const_cast<std::int32_t*>(a);
    const std::int64_t at = static_cast<std::int64_t>(b);
    if (at < 0 || at >= static_cast<std::int64_t>(sizeof(std::int32_t) * 8)) {
        return 0;
    }
    const std::int32_t bit = static_cast<std::int32_t>(static_cast<std::int32_t>(1) << at);
    for (;;) {
        std::int32_t current = __atomic_load_n(p, __ATOMIC_SEQ_CST);
        const bool was = (current & bit) != 0;
        const std::int32_t wanted =
            static_cast<std::int32_t>(current ^ bit);
        if (__atomic_compare_exchange_n(p, &current, wanted, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            return was ? 1 : 0;
        }
    }
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_InterlockedBitTestAndComplement64(std::int64_t* a, std::int64_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    // The bit test is the atomic form of the three non-atomic ones: the read
    // and the write are one operation, which is what a caller that uses it
    // as a lock relies on.
    auto* p = const_cast<std::int64_t*>(a);
    const std::int64_t at = static_cast<std::int64_t>(b);
    if (at < 0 || at >= static_cast<std::int64_t>(sizeof(std::int64_t) * 8)) {
        return 0;
    }
    const std::int64_t bit = static_cast<std::int64_t>(static_cast<std::int64_t>(1) << at);
    for (;;) {
        std::int64_t current = __atomic_load_n(p, __ATOMIC_SEQ_CST);
        const bool was = (current & bit) != 0;
        const std::int64_t wanted =
            static_cast<std::int64_t>(current ^ bit);
        if (__atomic_compare_exchange_n(p, &current, wanted, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            return was ? 1 : 0;
        }
    }
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_InterlockedBitTestAndReset(std::int32_t* a, std::int32_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    // The bit test is the atomic form of the three non-atomic ones: the read
    // and the write are one operation, which is what a caller that uses it
    // as a lock relies on.
    auto* p = const_cast<std::int32_t*>(a);
    const std::int64_t at = static_cast<std::int64_t>(b);
    if (at < 0 || at >= static_cast<std::int64_t>(sizeof(std::int32_t) * 8)) {
        return 0;
    }
    const std::int32_t bit = static_cast<std::int32_t>(static_cast<std::int32_t>(1) << at);
    for (;;) {
        std::int32_t current = __atomic_load_n(p, __ATOMIC_SEQ_CST);
        const bool was = (current & bit) != 0;
        const std::int32_t wanted =
            static_cast<std::int32_t>(current & ~bit);
        if (__atomic_compare_exchange_n(p, &current, wanted, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            return was ? 1 : 0;
        }
    }
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_InterlockedBitTestAndReset64(std::int64_t* a, std::int64_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    // The bit test is the atomic form of the three non-atomic ones: the read
    // and the write are one operation, which is what a caller that uses it
    // as a lock relies on.
    auto* p = const_cast<std::int64_t*>(a);
    const std::int64_t at = static_cast<std::int64_t>(b);
    if (at < 0 || at >= static_cast<std::int64_t>(sizeof(std::int64_t) * 8)) {
        return 0;
    }
    const std::int64_t bit = static_cast<std::int64_t>(static_cast<std::int64_t>(1) << at);
    for (;;) {
        std::int64_t current = __atomic_load_n(p, __ATOMIC_SEQ_CST);
        const bool was = (current & bit) != 0;
        const std::int64_t wanted =
            static_cast<std::int64_t>(current & ~bit);
        if (__atomic_compare_exchange_n(p, &current, wanted, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            return was ? 1 : 0;
        }
    }
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_InterlockedBitTestAndSet(std::int32_t* a, std::int32_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    // The bit test is the atomic form of the three non-atomic ones: the read
    // and the write are one operation, which is what a caller that uses it
    // as a lock relies on.
    auto* p = const_cast<std::int32_t*>(a);
    const std::int64_t at = static_cast<std::int64_t>(b);
    if (at < 0 || at >= static_cast<std::int64_t>(sizeof(std::int32_t) * 8)) {
        return 0;
    }
    const std::int32_t bit = static_cast<std::int32_t>(static_cast<std::int32_t>(1) << at);
    for (;;) {
        std::int32_t current = __atomic_load_n(p, __ATOMIC_SEQ_CST);
        const bool was = (current & bit) != 0;
        const std::int32_t wanted =
            static_cast<std::int32_t>(current | bit);
        if (__atomic_compare_exchange_n(p, &current, wanted, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            return was ? 1 : 0;
        }
    }
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_InterlockedBitTestAndSet64(std::int64_t* a, std::int64_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    // The bit test is the atomic form of the three non-atomic ones: the read
    // and the write are one operation, which is what a caller that uses it
    // as a lock relies on.
    auto* p = const_cast<std::int64_t*>(a);
    const std::int64_t at = static_cast<std::int64_t>(b);
    if (at < 0 || at >= static_cast<std::int64_t>(sizeof(std::int64_t) * 8)) {
        return 0;
    }
    const std::int64_t bit = static_cast<std::int64_t>(static_cast<std::int64_t>(1) << at);
    for (;;) {
        std::int64_t current = __atomic_load_n(p, __ATOMIC_SEQ_CST);
        const bool was = (current & bit) != 0;
        const std::int64_t wanted =
            static_cast<std::int64_t>(current | bit);
        if (__atomic_compare_exchange_n(p, &current, wanted, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            return was ? 1 : 0;
        }
    }
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_InterlockedFlushSList(void* ListHead) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(ListHead);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_InterlockedPopEntrySList(void* ListHead) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(ListHead);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_InterlockedPushEntrySList(void* ListHead, void* ListEntry) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(ListHead);
    static_cast<void>(ListEntry);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_InterlockedPushListSListEx(void* ListHead, void* List, void* ListEnd, std::uint32_t Count) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(ListHead);
    static_cast<void>(List);
    static_cast<void>(ListEnd);
    static_cast<void>(Count);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_IsBadHugeReadPtr(const void* lp, std::uint64_t ucb) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lp);
    static_cast<void>(ucb);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_IsBadHugeWritePtr(void* lp, std::uint64_t ucb) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lp);
    static_cast<void>(ucb);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_IsNLSDefinedString(std::uint32_t Function, std::uint32_t dwFlags, std::uint64_t lpVersionInformation, const char16_t* lpString, std::int32_t cchStr) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Function);
    static_cast<void>(dwFlags);
    static_cast<void>(lpVersionInformation);
    static_cast<void>(lpString);
    static_cast<void>(cchStr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_IsNativeVhdBoot(std::int32_t* NativeVhdBoot) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(NativeVhdBoot);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_IsNormalizedString(std::uint64_t NormForm, const char16_t* lpString, std::int32_t cwLength) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(NormForm);
    static_cast<void>(lpString);
    static_cast<void>(cwLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_IsSystemResumeAutomatic() noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_IsThreadAFiber() noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_IsValidLanguageGroup(std::uint64_t LanguageGroup, std::uint32_t dwFlags) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(LanguageGroup);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_IsValidLocale(std::uint32_t Locale, std::uint32_t dwFlags) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_IsValidLocaleName(const char16_t* lpLocaleName) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpLocaleName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_IsValidNLSVersion(std::uint32_t function, const char16_t* lpLocaleName, std::uint64_t lpVersionInformation) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(function);
    static_cast<void>(lpLocaleName);
    static_cast<void>(lpVersionInformation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_IsWow64GuestMachineSupported(std::uint16_t WowGuestMachine, std::int32_t* MachineIsSupported) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(WowGuestMachine);
    static_cast<void>(MachineIsSupported);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_LCIDToLocaleName(std::uint32_t Locale, char16_t* lpName, std::int32_t cchName, std::uint32_t dwFlags) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(lpName);
    static_cast<void>(cchName);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_LeaveCriticalSectionWhenCallbackReturns(void* pci, void* pcs) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(pci);
    static_cast<void>(pcs);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_LoadModule(const char* lpModuleName, void* lpParameterBlock) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpModuleName);
    static_cast<void>(lpParameterBlock);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_LoadPackagedLibrary(const char16_t* lpwLibFileName, std::uint32_t Reserved) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpwLibFileName);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_LoadResource(void* hModule, void* hResInfo) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(hResInfo);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kkernel32G_LocalCompact(std::uint32_t uMinFree) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(uMinFree);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kkernel32G_LocalShrink(void* hMem, std::uint32_t cbNewSize) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hMem);
    static_cast<void>(cbNewSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_LocaleNameToLCID(const char16_t* lpName, std::uint32_t dwFlags) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpName);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_LocateXStateFeature(void* Context, std::uint32_t FeatureId, std::uint32_t* Length) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Context);
    static_cast<void>(FeatureId);
    static_cast<void>(Length);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_LockResource(void* hResData) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hResData);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_MapUserPhysicalPages(void* VirtualAddress, std::uint64_t NumberOfPages, std::uint64_t* PageArray) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(VirtualAddress);
    static_cast<void>(NumberOfPages);
    static_cast<void>(PageArray);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_MapUserPhysicalPagesScatter(void** VirtualAddresses, std::uint64_t NumberOfPages, std::uint64_t* PageArray) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(VirtualAddresses);
    static_cast<void>(NumberOfPages);
    static_cast<void>(PageArray);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_MapViewOfFileExNuma(void* hFileMappingObject, std::uint32_t dwDesiredAccess, std::uint32_t dwFileOffsetHigh, std::uint32_t dwFileOffsetLow, std::uint64_t dwNumberOfBytesToMap, void* lpBaseAddress, std::uint32_t nndPreferred) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFileMappingObject);
    static_cast<void>(dwDesiredAccess);
    static_cast<void>(dwFileOffsetHigh);
    static_cast<void>(dwFileOffsetLow);
    static_cast<void>(dwNumberOfBytesToMap);
    static_cast<void>(lpBaseAddress);
    static_cast<void>(nndPreferred);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_MapViewOfFileFromApp(void* hFileMappingObject, std::uint32_t DesiredAccess, std::uint64_t FileOffset, std::uint64_t NumberOfBytesToMap) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFileMappingObject);
    static_cast<void>(DesiredAccess);
    static_cast<void>(FileOffset);
    static_cast<void>(NumberOfBytesToMap);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_MoveFileTransactedA(const char* lpExistingFileName, const char* lpNewFileName, void* lpProgressRoutine, void* lpData, std::uint32_t dwFlags, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpExistingFileName);
    static_cast<void>(lpNewFileName);
    static_cast<void>(lpProgressRoutine);
    static_cast<void>(lpData);
    static_cast<void>(dwFlags);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_MoveFileTransactedW(const char16_t* lpExistingFileName, const char16_t* lpNewFileName, void* lpProgressRoutine, void* lpData, std::uint32_t dwFlags, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpExistingFileName);
    static_cast<void>(lpNewFileName);
    static_cast<void>(lpProgressRoutine);
    static_cast<void>(lpData);
    static_cast<void>(dwFlags);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_MoveFileWithProgressA(const char* lpExistingFileName, const char* lpNewFileName, void* lpProgressRoutine, void* lpData, std::uint32_t dwFlags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpExistingFileName);
    static_cast<void>(lpNewFileName);
    static_cast<void>(lpProgressRoutine);
    static_cast<void>(lpData);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_MoveFileWithProgressW(const char16_t* lpExistingFileName, const char16_t* lpNewFileName, void* lpProgressRoutine, void* lpData, std::uint32_t dwFlags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpExistingFileName);
    static_cast<void>(lpNewFileName);
    static_cast<void>(lpProgressRoutine);
    static_cast<void>(lpData);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_MulDiv(std::int32_t nNumber, std::int32_t nNumerator, std::int32_t nDenominator) noexcept {
    if (nDenominator == 0) {
        return -1;
    }
    // The product is formed in 64 bits and rounded half away from zero, and
    // the answer is refused when it does not fit the 32 bits the caller has
    // -- a truncated result would be read as a successful division, which is
    // the failure this function exists to avoid.
    const std::int64_t product =
        static_cast<std::int64_t>(nNumber) * static_cast<std::int64_t>(nNumerator);
    const std::int64_t half = static_cast<std::int64_t>(nDenominator) / 2;
    const std::int64_t rounded = product >= 0 ? product + half : product - half;
    const std::int64_t answer = rounded / static_cast<std::int64_t>(nDenominator);
    if (answer > 2147483647LL || answer < -2147483648LL) {
        return -1;
    }
    return static_cast<std::int32_t>(answer);
}


extern "C" __attribute__((ms_abi)) std::int64_t kkernel32G_MultiplyExtract128(std::int64_t Multiplier, std::int64_t Multiplicand, std::uint8_t Shift) noexcept {
    // The product is formed in 128 bits and then shifted right, which is the
    // whole point of the call: done in 64 bits the intermediate would be the
    // answer a caller of this function is trying to avoid.
    signed __int128 product = static_cast<signed __int128>(
        static_cast<std::int64_t>(Multiplier)) *
        static_cast<signed __int128>(static_cast<std::int64_t>(Multiplicand));
    const std::uint32_t at = static_cast<std::uint32_t>(Shift) & 0x7Fu;
    product >>= at;
    return static_cast<std::int64_t>(static_cast<std::uint64_t>(product));
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_NeedCurrentDirectoryForExePathA(const char* ExeName) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_NeedCurrentDirectoryForExePathW(const char16_t* ExeName) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_NormalizeString(std::uint64_t NormForm, const char16_t* lpSrcString, std::int32_t cwSrcLength, char16_t* lpDstString, std::int32_t cwDstLength) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(NormForm);
    static_cast<void>(lpSrcString);
    static_cast<void>(cwSrcLength);
    static_cast<void>(lpDstString);
    static_cast<void>(cwDstLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_NotifyUILanguageChange(std::uint32_t dwFlags, const char16_t* pcwstrNewLanguage, const char16_t* pcwstrPreviousLanguage, std::uint32_t dwReserved, std::uint32_t* pdwStatusRtrn) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(dwFlags);
    static_cast<void>(pcwstrNewLanguage);
    static_cast<void>(pcwstrPreviousLanguage);
    static_cast<void>(dwReserved);
    static_cast<void>(pdwStatusRtrn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_OfferVirtualMemory(void* VirtualAddress, std::uint64_t Size, std::int32_t Priority) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(VirtualAddress);
    static_cast<void>(Size);
    static_cast<void>(Priority);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_OpenFile(const char* lpFileName, std::uint64_t lpReOpenBuff, std::uint32_t uStyle) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpFileName);
    static_cast<void>(lpReOpenBuff);
    static_cast<void>(uStyle);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_OpenFileById(void* hVolumeHint, std::uint64_t lpFileId, std::uint32_t dwDesiredAccess, std::uint32_t dwShareMode, void* lpSecurityAttributes, std::uint32_t dwFlagsAndAttributes) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hVolumeHint);
    static_cast<void>(lpFileId);
    static_cast<void>(dwDesiredAccess);
    static_cast<void>(dwShareMode);
    static_cast<void>(lpSecurityAttributes);
    static_cast<void>(dwFlagsAndAttributes);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_OpenJobObjectA(std::uint32_t dwDesiredAccess, std::int32_t bInheritHandle, const char* lpName) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(dwDesiredAccess);
    static_cast<void>(bInheritHandle);
    static_cast<void>(lpName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_OpenJobObjectW(std::uint32_t dwDesiredAccess, std::int32_t bInheritHandle, const char16_t* lpName) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(dwDesiredAccess);
    static_cast<void>(bInheritHandle);
    static_cast<void>(lpName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_OpenPrivateNamespaceA(void* lpBoundaryDescriptor, const char* lpAliasPrefix) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(lpBoundaryDescriptor);
    static_cast<void>(lpAliasPrefix);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_OpenPrivateNamespaceW(void* lpBoundaryDescriptor, const char16_t* lpAliasPrefix) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(lpBoundaryDescriptor);
    static_cast<void>(lpAliasPrefix);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_PeekNamedPipe(void* hNamedPipe, void* lpBuffer, std::uint32_t nBufferSize, std::uint32_t* lpBytesRead, std::uint32_t* lpTotalBytesAvail, std::uint32_t* lpBytesLeftThisMessage) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(hNamedPipe);
    static_cast<void>(lpBuffer);
    static_cast<void>(nBufferSize);
    static_cast<void>(lpBytesRead);
    static_cast<void>(lpTotalBytesAvail);
    static_cast<void>(lpBytesLeftThisMessage);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_PowerClearRequest(void* PowerRequest, std::uint64_t RequestType) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(PowerRequest);
    static_cast<void>(RequestType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_PowerCreateRequest(std::uint64_t Context) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(Context);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_PowerSetRequest(void* PowerRequest, std::uint64_t RequestType) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(PowerRequest);
    static_cast<void>(RequestType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_PrefetchVirtualMemory(void* hProcess, std::uint64_t NumberOfEntries, void* VirtualAddresses, std::uint32_t Flags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hProcess);
    static_cast<void>(NumberOfEntries);
    static_cast<void>(VirtualAddresses);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_PrepareTape(void* hDevice, std::uint32_t dwOperation, std::int32_t bImmediate) noexcept {
    // Refused: the tape device layer.
    //
    // a tape is a device reached through the device I/O control surface
    static_cast<void>(hDevice);
    static_cast<void>(dwOperation);
    static_cast<void>(bImmediate);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_PurgeComm(void* hFile, std::uint32_t dwFlags) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hFile);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_QueryActCtxSettingsW(std::uint32_t dwFlags, void* hActCtx, const char16_t* settingsNameSpace, const char16_t* settingName, char16_t* pvBuffer, std::uint64_t dwBuffer, std::uint64_t* pdwWrittenOrRequired) noexcept {
    // Refused: the side-by-side activation context.
    //
    // an activation context is built from a manifest and a catalog store by
    // the loader's own subsystem; this runtime resolves modules by name
    static_cast<void>(dwFlags);
    static_cast<void>(hActCtx);
    static_cast<void>(settingsNameSpace);
    static_cast<void>(settingName);
    static_cast<void>(pvBuffer);
    static_cast<void>(dwBuffer);
    static_cast<void>(pdwWrittenOrRequired);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_QueryActCtxW(std::uint32_t dwFlags, void* hActCtx, void* pvSubInstance, std::uint32_t ulInfoClass, void* pvBuffer, std::uint64_t cbBuffer, std::uint64_t* pcbWrittenOrRequired) noexcept {
    // Refused: the side-by-side activation context.
    //
    // an activation context is built from a manifest and a catalog store by
    // the loader's own subsystem; this runtime resolves modules by name
    static_cast<void>(dwFlags);
    static_cast<void>(hActCtx);
    static_cast<void>(pvSubInstance);
    static_cast<void>(ulInfoClass);
    static_cast<void>(pvBuffer);
    static_cast<void>(cbBuffer);
    static_cast<void>(pcbWrittenOrRequired);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_QueryDepthSList(void* ListHead) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(ListHead);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_QueryDosDeviceA(const char* lpDeviceName, char* lpTargetPath, std::uint32_t ucchMax) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(lpDeviceName);
    static_cast<void>(lpTargetPath);
    static_cast<void>(ucchMax);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_QueryDosDeviceW(const char16_t* lpDeviceName, char16_t* lpTargetPath, std::uint32_t ucchMax) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(lpDeviceName);
    static_cast<void>(lpTargetPath);
    static_cast<void>(ucchMax);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_QueryIdleProcessorCycleTimeEx(std::uint16_t Group, std::uint32_t* BufferLength, std::uint64_t* ProcessorIdleCycleTime) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Group);
    static_cast<void>(BufferLength);
    static_cast<void>(ProcessorIdleCycleTime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_QueryMemoryResourceNotification(void* ResourceNotificationHandle, std::int32_t* ResourceState) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(ResourceNotificationHandle);
    static_cast<void>(ResourceState);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_QueryProcessCycleTime(void* ProcessHandle, std::uint64_t* CycleTime) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(ProcessHandle);
    static_cast<void>(CycleTime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_QueryThreadProfiling(void* ThreadHandle, std::uint8_t* Enabled) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(ThreadHandle);
    static_cast<void>(Enabled);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_QueryThreadpoolStackInformation(void* ptpp, std::uint64_t ptpsi) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(ptpp);
    static_cast<void>(ptpsi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_QueryUmsThreadInformation(void* UmsThread, std::uint64_t UmsThreadInfoClass, void* UmsThreadInformation, std::uint32_t UmsThreadInformationLength, std::uint32_t* ReturnLength) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(UmsThread);
    static_cast<void>(UmsThreadInfoClass);
    static_cast<void>(UmsThreadInformation);
    static_cast<void>(UmsThreadInformationLength);
    static_cast<void>(ReturnLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_QueryUnbiasedInterruptTime(std::uint64_t* UnbiasedTime) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(UnbiasedTime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_QueueUserWorkItem(void* Function, void* Context, std::uint32_t Flags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Function);
    static_cast<void>(Context);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_ReOpenFile(void* hOriginalFile, std::uint32_t dwDesiredAccess, std::uint32_t dwShareMode, std::uint32_t dwFlagsAndAttributes) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hOriginalFile);
    static_cast<void>(dwDesiredAccess);
    static_cast<void>(dwShareMode);
    static_cast<void>(dwFlagsAndAttributes);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_ReadDirectoryChangesW(void* hDirectory, void* lpBuffer, std::uint32_t nBufferLength, std::int32_t bWatchSubtree, std::uint32_t dwNotifyFilter, std::uint32_t* lpBytesReturned, void* lpOverlapped, void* lpCompletionRoutine) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hDirectory);
    static_cast<void>(lpBuffer);
    static_cast<void>(nBufferLength);
    static_cast<void>(bWatchSubtree);
    static_cast<void>(dwNotifyFilter);
    static_cast<void>(lpBytesReturned);
    static_cast<void>(lpOverlapped);
    static_cast<void>(lpCompletionRoutine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_ReadFileEx(void* hFile, void* lpBuffer, std::uint32_t nNumberOfBytesToRead, void* lpOverlapped, void* lpCompletionRoutine) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lpBuffer);
    static_cast<void>(nNumberOfBytesToRead);
    static_cast<void>(lpOverlapped);
    static_cast<void>(lpCompletionRoutine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_ReadFileScatter(void* hFile, std::uint64_t* aSegmentArray, std::uint32_t nNumberOfBytesToRead, std::uint32_t* lpReserved, void* lpOverlapped) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(aSegmentArray);
    static_cast<void>(nNumberOfBytesToRead);
    static_cast<void>(lpReserved);
    static_cast<void>(lpOverlapped);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_ReadThreadProfilingData(void* PerformanceDataHandle, std::uint32_t Flags, std::uint64_t PerformanceData) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(PerformanceDataHandle);
    static_cast<void>(Flags);
    static_cast<void>(PerformanceData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_ReclaimVirtualMemory(void* VirtualAddress, std::uint64_t Size) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(VirtualAddress);
    static_cast<void>(Size);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_RegisterApplicationRecoveryCallback(void* pRecoveyCallback, void* pvParameter, std::uint32_t dwPingInterval, std::uint32_t dwFlags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(pRecoveyCallback);
    static_cast<void>(pvParameter);
    static_cast<void>(dwPingInterval);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_RegisterApplicationRestart(const char16_t* pwzCommandline, std::uint32_t dwFlags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(pwzCommandline);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_RegisterBadMemoryNotification(std::uint64_t Callback) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Callback);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_ReleaseActCtx(void* hActCtx) noexcept {
    // Refused: the side-by-side activation context.
    //
    // an activation context is built from a manifest and a catalog store by
    // the loader's own subsystem; this runtime resolves modules by name
    static_cast<void>(hActCtx);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_RemoveDirectoryTransactedA(const char* lpPathName, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpPathName);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_RemoveDirectoryTransactedW(const char16_t* lpPathName, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpPathName);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_RemoveDllDirectory(std::uint64_t Cookie) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Cookie);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_RemoveSecureMemoryCacheCallback(std::uint64_t pfnCallBack) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(pfnCallBack);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_RemoveVectoredContinueHandler(void* Handle) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Handle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_ReplaceFileA(const char* lpReplacedFileName, const char* lpReplacementFileName, const char* lpBackupFileName, std::uint32_t dwReplaceFlags, void* lpExclude, void* lpReserved) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpReplacedFileName);
    static_cast<void>(lpReplacementFileName);
    static_cast<void>(lpBackupFileName);
    static_cast<void>(dwReplaceFlags);
    static_cast<void>(lpExclude);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_ReplaceFileW(const char16_t* lpReplacedFileName, const char16_t* lpReplacementFileName, const char16_t* lpBackupFileName, std::uint32_t dwReplaceFlags, void* lpExclude, void* lpReserved) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpReplacedFileName);
    static_cast<void>(lpReplacementFileName);
    static_cast<void>(lpBackupFileName);
    static_cast<void>(dwReplaceFlags);
    static_cast<void>(lpExclude);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_ReplacePartitionUnit(char16_t* TargetPartition, char16_t* SparePartition, std::uint32_t Flags) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(TargetPartition);
    static_cast<void>(SparePartition);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_RequestDeviceWakeup(void* hDevice) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(hDevice);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_RequestWakeupLatency(std::uint64_t latency) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(latency);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_ResetWriteWatch(void* lpBaseAddress, std::uint64_t dwRegionSize) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpBaseAddress);
    static_cast<void>(dwRegionSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_ResolveLocaleName(const char16_t* lpNameToResolve, char16_t* lpLocaleName, std::int32_t cchLocaleName) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(lpNameToResolve);
    static_cast<void>(lpLocaleName);
    static_cast<void>(cchLocaleName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_RtlSecureZeroMemory(void* ptr, std::uint64_t cnt) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(ptr);
    static_cast<void>(cnt);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetCachedSigningLevel(void** SourceFiles, std::uint32_t SourceFileCount, std::uint32_t Flags, void* TargetFile) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(SourceFiles);
    static_cast<void>(SourceFileCount);
    static_cast<void>(Flags);
    static_cast<void>(TargetFile);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetCalendarInfoA(std::uint32_t Locale, std::uint32_t Calendar, std::uint32_t CalType, const char* lpCalData) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(Calendar);
    static_cast<void>(CalType);
    static_cast<void>(lpCalData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetCalendarInfoW(std::uint32_t Locale, std::uint32_t Calendar, std::uint32_t CalType, const char16_t* lpCalData) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(Calendar);
    static_cast<void>(CalType);
    static_cast<void>(lpCalData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetCommBreak(void* hFile) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hFile);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetCommConfig(void* hCommDev, void* lpCC, std::uint32_t dwSize) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hCommDev);
    static_cast<void>(lpCC);
    static_cast<void>(dwSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetCommMask(void* hFile, std::uint32_t dwEvtMask) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hFile);
    static_cast<void>(dwEvtMask);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetCommState(void* hFile, void* lpDCB) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hFile);
    static_cast<void>(lpDCB);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetCommTimeouts(void* hFile, void* lpCommTimeouts) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hFile);
    static_cast<void>(lpCommTimeouts);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetComputerNameA(const char* lpComputerName) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpComputerName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetComputerNameExA(std::uint64_t NameType, std::uint64_t lpBuffer) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(NameType);
    static_cast<void>(lpBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetComputerNameExW(std::uint64_t NameType, const char16_t* lpBuffer) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(NameType);
    static_cast<void>(lpBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetComputerNameW(const char16_t* lpComputerName) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpComputerName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetConsoleDisplayMode(void* hConsoleOutput, std::uint32_t dwFlags, std::uint64_t lpNewScreenBufferDimensions) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(hConsoleOutput);
    static_cast<void>(dwFlags);
    static_cast<void>(lpNewScreenBufferDimensions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetConsoleHistoryInfo(std::uint64_t lpConsoleHistoryInfo) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(lpConsoleHistoryInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetConsoleNumberOfCommandsA(std::uint32_t Number, char* ExeName) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(Number);
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetConsoleNumberOfCommandsW(std::uint32_t Number, char16_t* ExeName) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(Number);
    static_cast<void>(ExeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetConsoleScreenBufferInfoEx(void* hConsoleOutput, std::uint64_t lpConsoleScreenBufferInfoEx) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(hConsoleOutput);
    static_cast<void>(lpConsoleScreenBufferInfoEx);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetConsoleScreenBufferSize(void* hConsoleOutput, std::uint64_t dwSize) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(hConsoleOutput);
    static_cast<void>(dwSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetConsoleWindowInfo(void* hConsoleOutput, std::int32_t bAbsolute, const void* lpConsoleWindow) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(hConsoleOutput);
    static_cast<void>(bAbsolute);
    static_cast<void>(lpConsoleWindow);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_SetCriticalSectionSpinCount(void* lpCriticalSection, std::uint32_t dwSpinCount) noexcept {
    if (lpCriticalSection == nullptr) {
        return 0;
    }
    // The spin count is the fifth pointer-sized field of a critical section
    // on the 64-bit ABI: the lock count, the recursion count, the owning
    // thread, the semaphore, and then this. The answer is the count that was
    // there, which is what lets a caller restore it.
    constexpr std::size_t kSpinCountOffset = 32;
    const std::uint32_t previous = read_le32(lpCriticalSection, kSpinCountOffset);
    write_le32(lpCriticalSection, kSpinCountOffset, dwSpinCount);
    return previous;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetCurrentConsoleFontEx(void* hConsoleOutput, std::int32_t bMaximumWindow, std::uint64_t lpConsoleCurrentFontEx) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(hConsoleOutput);
    static_cast<void>(bMaximumWindow);
    static_cast<void>(lpConsoleCurrentFontEx);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetDefaultCommConfigA(const char* lpszName, void* lpCC, std::uint32_t dwSize) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(lpszName);
    static_cast<void>(lpCC);
    static_cast<void>(dwSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetDefaultCommConfigW(const char16_t* lpszName, void* lpCC, std::uint32_t dwSize) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(lpszName);
    static_cast<void>(lpCC);
    static_cast<void>(dwSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetDefaultDllDirectories(std::uint32_t DirectoryFlags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(DirectoryFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetDllDirectoryA(const char* lpPathName) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpPathName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetDllDirectoryW(const char16_t* lpPathName) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpPathName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetDynamicTimeZoneInformation(const void* lpTimeZoneInformation) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpTimeZoneInformation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetEnvironmentStringsA(char* NewEnvironment) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(NewEnvironment);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetEnvironmentStringsW(char16_t* NewEnvironment) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(NewEnvironment);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_SetFileApisToANSI() noexcept {
    set_file_api_code_page(true);
}


extern "C" __attribute__((ms_abi)) void kkernel32G_SetFileApisToOEM() noexcept {
    // The switch is kept, and it changes the answer `AreFileApisANSI`
    // gives. It does not change any conversion, because this runtime answers
    // one single-byte code page for the two the platform keeps apart --
    // which is the same statement its stream and file domains already make.
    set_file_api_code_page(false);
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetFileAttributesTransactedA(const char* lpFileName, std::uint32_t dwFileAttributes, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(dwFileAttributes);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetFileAttributesTransactedW(const char16_t* lpFileName, std::uint32_t dwFileAttributes, void* hTransaction) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(lpFileName);
    static_cast<void>(dwFileAttributes);
    static_cast<void>(hTransaction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetFileBandwidthReservation(void* hFile, std::uint32_t nPeriodMilliseconds, std::uint32_t nBytesPerPeriod, std::int32_t bDiscardable, std::uint32_t* lpTransferSize, std::uint32_t* lpNumOutstandingRequests) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(nPeriodMilliseconds);
    static_cast<void>(nBytesPerPeriod);
    static_cast<void>(bDiscardable);
    static_cast<void>(lpTransferSize);
    static_cast<void>(lpNumOutstandingRequests);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetFileCompletionNotificationModes(void* FileHandle, std::uint8_t Flags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(FileHandle);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetFileIoOverlappedRange(void* FileHandle, std::uint8_t* OverlappedRangeStart, std::uint32_t Length) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(FileHandle);
    static_cast<void>(OverlappedRangeStart);
    static_cast<void>(Length);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetFileShortNameA(void* hFile, const char* lpShortName) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lpShortName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetFileShortNameW(void* hFile, const char16_t* lpShortName) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lpShortName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetFileValidData(void* hFile, std::int64_t ValidDataLength) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(ValidDataLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetFirmwareEnvironmentVariableA(const char* lpName, const char* lpGuid, void* pValue, std::uint32_t nSize) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(lpName);
    static_cast<void>(lpGuid);
    static_cast<void>(pValue);
    static_cast<void>(nSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetFirmwareEnvironmentVariableExA(const char* lpName, const char* lpGuid, void* pValue, std::uint32_t nSize, std::uint32_t dwAttributes) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(lpName);
    static_cast<void>(lpGuid);
    static_cast<void>(pValue);
    static_cast<void>(nSize);
    static_cast<void>(dwAttributes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetFirmwareEnvironmentVariableExW(const char16_t* lpName, const char16_t* lpGuid, void* pValue, std::uint32_t nSize, std::uint32_t dwAttributes) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(lpName);
    static_cast<void>(lpGuid);
    static_cast<void>(pValue);
    static_cast<void>(nSize);
    static_cast<void>(dwAttributes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetFirmwareEnvironmentVariableW(const char16_t* lpName, const char16_t* lpGuid, void* pValue, std::uint32_t nSize) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(lpName);
    static_cast<void>(lpGuid);
    static_cast<void>(pValue);
    static_cast<void>(nSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_SetHandleCount(std::uint32_t uNumber) noexcept {
    // The count the process had before, which is the count it still has: the
    // call is documented as having no effect from Win32 onwards, and a
    // runtime that refused it would break a caller that uses it to raise a
    // limit it does not actually have.
    static_cast<void>(uNumber);
    return 255;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetInformationJobObject(void* hJob, std::uint64_t JobObjectInformationClass, void* lpJobObjectInformation, std::uint32_t cbJobObjectInformationLength) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(hJob);
    static_cast<void>(JobObjectInformationClass);
    static_cast<void>(lpJobObjectInformation);
    static_cast<void>(cbJobObjectInformationLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetLocaleInfoA(std::uint32_t Locale, std::uint64_t LCType, const char* lpLCData) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(LCType);
    static_cast<void>(lpLCData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetLocaleInfoW(std::uint32_t Locale, std::uint64_t LCType, const char16_t* lpLCData) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    static_cast<void>(LCType);
    static_cast<void>(lpLCData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetMailslotInfo(void* hMailslot, std::uint32_t lReadTimeout) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(hMailslot);
    static_cast<void>(lReadTimeout);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetNamedPipeHandleState(void* hNamedPipe, std::uint32_t* lpMode, std::uint32_t* lpMaxCollectionCount, std::uint32_t* lpCollectDataTimeout) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(hNamedPipe);
    static_cast<void>(lpMode);
    static_cast<void>(lpMaxCollectionCount);
    static_cast<void>(lpCollectDataTimeout);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetProcessInformation(void* hProcess, std::uint64_t ProcessInformationClass, void* ProcessInformation, std::uint32_t ProcessInformationSize) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hProcess);
    static_cast<void>(ProcessInformationClass);
    static_cast<void>(ProcessInformation);
    static_cast<void>(ProcessInformationSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetProcessPreferredUILanguages(std::uint32_t dwFlags, std::uint64_t pwszLanguagesBuffer, std::uint32_t* pulNumLanguages) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(dwFlags);
    static_cast<void>(pwszLanguagesBuffer);
    static_cast<void>(pulNumLanguages);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetProcessWorkingSetSizeEx(void* hProcess, std::uint64_t dwMinimumWorkingSetSize, std::uint64_t dwMaximumWorkingSetSize, std::uint32_t Flags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hProcess);
    static_cast<void>(dwMinimumWorkingSetSize);
    static_cast<void>(dwMaximumWorkingSetSize);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetSearchPathMode(std::uint32_t Flags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetStdHandleEx(std::uint32_t nStdHandle, void* hHandle, void** phPrevValue) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(nStdHandle);
    static_cast<void>(hHandle);
    static_cast<void>(phPrevValue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetSystemFileCacheSize(std::uint64_t MinimumFileCacheSize, std::uint64_t MaximumFileCacheSize, std::uint32_t Flags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(MinimumFileCacheSize);
    static_cast<void>(MaximumFileCacheSize);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetSystemPowerState(std::int32_t fSuspend, std::int32_t fForce) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(fSuspend);
    static_cast<void>(fForce);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetSystemTimeAdjustment(std::uint32_t dwTimeAdjustment, std::int32_t bTimeAdjustmentDisabled) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(dwTimeAdjustment);
    static_cast<void>(bTimeAdjustmentDisabled);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_SetTapeParameters(void* hDevice, std::uint32_t dwOperation, void* lpTapeInformation) noexcept {
    // Refused: the tape device layer.
    //
    // a tape is a device reached through the device I/O control surface
    static_cast<void>(hDevice);
    static_cast<void>(dwOperation);
    static_cast<void>(lpTapeInformation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_SetTapePosition(void* hDevice, std::uint32_t dwPositionMethod, std::uint32_t dwPartition, std::uint32_t dwOffsetLow, std::uint32_t dwOffsetHigh, std::int32_t bImmediate) noexcept {
    // Refused: the tape device layer.
    //
    // a tape is a device reached through the device I/O control surface
    static_cast<void>(hDevice);
    static_cast<void>(dwPositionMethod);
    static_cast<void>(dwPartition);
    static_cast<void>(dwOffsetLow);
    static_cast<void>(dwOffsetHigh);
    static_cast<void>(bImmediate);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_SetThreadExecutionState(std::uint32_t esFlags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(esFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetThreadGroupAffinity(void* hThread, const void* GroupAffinity, void* PreviousGroupAffinity) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hThread);
    static_cast<void>(GroupAffinity);
    static_cast<void>(PreviousGroupAffinity);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_SetThreadIdealProcessor(void* hThread, std::uint32_t dwIdealProcessor) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hThread);
    static_cast<void>(dwIdealProcessor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetThreadInformation(void* hThread, std::uint64_t ThreadInformationClass, void* ThreadInformation, std::uint32_t ThreadInformationSize) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hThread);
    static_cast<void>(ThreadInformationClass);
    static_cast<void>(ThreadInformation);
    static_cast<void>(ThreadInformationSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetThreadLocale(std::uint32_t Locale) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(Locale);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetThreadPreferredUILanguages(std::uint32_t dwFlags, std::uint64_t pwszLanguagesBuffer, std::uint32_t* pulNumLanguages) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(dwFlags);
    static_cast<void>(pwszLanguagesBuffer);
    static_cast<void>(pulNumLanguages);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetThreadPriorityBoost(void* hThread, std::int32_t bDisablePriorityBoost) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hThread);
    static_cast<void>(bDisablePriorityBoost);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetThreadStackGuarantee(std::uint32_t* StackSizeInBytes) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(StackSizeInBytes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kkernel32G_SetThreadUILanguage(std::uint16_t LangId) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(LangId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetThreadpoolStackInformation(void* ptpp, std::uint64_t ptpsi) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(ptpp);
    static_cast<void>(ptpsi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_SetThreadpoolThreadMaximum(void* ptpp, std::uint32_t cthrdMost) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(ptpp);
    static_cast<void>(cthrdMost);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetThreadpoolThreadMinimum(void* ptpp, std::uint32_t cthrdMic) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(ptpp);
    static_cast<void>(cthrdMic);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetThreadpoolWaitEx(std::uint64_t pwa, void* h, std::uint64_t* pftTimeout, void* Reserved) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(pwa);
    static_cast<void>(h);
    static_cast<void>(pftTimeout);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetUmsThreadInformation(void* UmsThread, std::uint64_t UmsThreadInfoClass, void* UmsThreadInformation, std::uint32_t UmsThreadInformationLength) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(UmsThread);
    static_cast<void>(UmsThreadInfoClass);
    static_cast<void>(UmsThreadInformation);
    static_cast<void>(UmsThreadInformationLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetUserGeoID(std::int32_t GeoId) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(GeoId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetVolumeLabelA(const char* lpRootPathName, const char* lpVolumeName) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(lpRootPathName);
    static_cast<void>(lpVolumeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetVolumeLabelW(const char16_t* lpRootPathName, const char16_t* lpVolumeName) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(lpRootPathName);
    static_cast<void>(lpVolumeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetVolumeMountPointA(const char* lpszVolumeMountPoint, const char* lpszVolumeName) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(lpszVolumeMountPoint);
    static_cast<void>(lpszVolumeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetVolumeMountPointW(const char16_t* lpszVolumeMountPoint, const char16_t* lpszVolumeName) noexcept {
    // Refused: the storage subsystem.
    //
    // volumes, partitions and mount points belong to the storage stack
    // underneath the file system this runtime answers
    static_cast<void>(lpszVolumeMountPoint);
    static_cast<void>(lpszVolumeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SetupComm(void* hFile, std::uint32_t dwInQueue, std::uint32_t dwOutQueue) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hFile);
    static_cast<void>(dwInQueue);
    static_cast<void>(dwOutQueue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_SizeofResource(void* hModule, void* hResInfo) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hModule);
    static_cast<void>(hResInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kkernel32G_SubmitThreadpoolWork(std::uint64_t pwk) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(pwk);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kkernel32G_SwitchToFiber(void* lpFiber) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(lpFiber);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_SystemTimeToTzSpecificLocalTimeEx(const void* lpTimeZoneInformation, const void* lpUniversalTime, void* lpLocalTime) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpTimeZoneInformation);
    static_cast<void>(lpUniversalTime);
    static_cast<void>(lpLocalTime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_TerminateJobObject(void* hJob, std::uint32_t uExitCode) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(hJob);
    static_cast<void>(uExitCode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_TransactNamedPipe(void* hNamedPipe, void* lpInBuffer, std::uint32_t nInBufferSize, void* lpOutBuffer, std::uint32_t nOutBufferSize, std::uint32_t* lpBytesRead, void* lpOverlapped) noexcept {
    // Refused: the inter-process transport.
    //
    // the call names a peer process through a transport this runtime does not
    // connect: a guest here is the only process in its address space
    static_cast<void>(hNamedPipe);
    static_cast<void>(lpInBuffer);
    static_cast<void>(nInBufferSize);
    static_cast<void>(lpOutBuffer);
    static_cast<void>(nOutBufferSize);
    static_cast<void>(lpBytesRead);
    static_cast<void>(lpOverlapped);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_TransmitCommChar(void* hFile, char cChar) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(hFile);
    static_cast<void>(cChar);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_TryAcquireSRWLockShared(void* SRWLock) noexcept {
    if (SRWLock == nullptr) {
        return 0;
    }
    // The exclusive owner is the only state this runtime tracks: a shared
    // acquisition succeeds unless somebody holds the lock exclusively, and
    // the shared count is left at zero because the release for a shared
    // acquisition is not one of the entry points here.
    auto* cell = static_cast<std::uint64_t*>(SRWLock);
    std::uint64_t expected = 0;
    return __atomic_compare_exchange_n(cell, &expected, 0, false,
                                       __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
               ? 1
               : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_TrySubmitThreadpoolCallback(std::uint64_t pfns, void* pv, std::uint64_t pcbe) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(pfns);
    static_cast<void>(pv);
    static_cast<void>(pcbe);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_TzSpecificLocalTimeToSystemTimeEx(const void* lpTimeZoneInformation, const void* lpLocalTime, void* lpUniversalTime) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpTimeZoneInformation);
    static_cast<void>(lpLocalTime);
    static_cast<void>(lpUniversalTime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_UmsThreadYield(void* SchedulerParam) noexcept {
    // Refused: the kernel scheduling objects.
    //
    // a job, a thread-pool and a user-mode scheduler are kernel scheduling
    // objects with completion ports behind them, and this runtime is a
    // single-threaded host for the guest it runs
    static_cast<void>(SchedulerParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_UnmapViewOfFileEx(void* BaseAddress, std::uint32_t UnmapFlags) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(BaseAddress);
    static_cast<void>(UnmapFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_UnregisterApplicationRecoveryCallback() noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_UnregisterApplicationRestart() noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_UnregisterBadMemoryNotification(void* RegistrationHandle) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(RegistrationHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kkernel32G_UnsignedMultiplyExtract128(std::uint64_t Multiplier, std::uint64_t Multiplicand, std::uint8_t Shift) noexcept {
    const unsigned __int128 product = widen_product(
        static_cast<std::uint64_t>(Multiplier), static_cast<std::uint64_t>(Multiplicand));
    const std::uint32_t at = static_cast<std::uint32_t>(Shift) & 0x7Fu;
    return static_cast<std::uint64_t>(product >> at);
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_UpdateProcThreadAttribute(void* lpAttributeList, std::uint32_t dwFlags, std::uint64_t Attribute, void* lpValue, std::uint64_t cbSize, void* lpPreviousValue, std::uint64_t* lpReturnSize) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpAttributeList);
    static_cast<void>(dwFlags);
    static_cast<void>(Attribute);
    static_cast<void>(lpValue);
    static_cast<void>(cbSize);
    static_cast<void>(lpPreviousValue);
    static_cast<void>(lpReturnSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_UpdateResourceA(void* hUpdate, const char* lpType, const char* lpName, std::uint16_t wLanguage, void* lpData, std::uint32_t cb) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hUpdate);
    static_cast<void>(lpType);
    static_cast<void>(lpName);
    static_cast<void>(wLanguage);
    static_cast<void>(lpData);
    static_cast<void>(cb);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_UpdateResourceW(void* hUpdate, const char16_t* lpType, const char16_t* lpName, std::uint16_t wLanguage, void* lpData, std::uint32_t cb) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hUpdate);
    static_cast<void>(lpType);
    static_cast<void>(lpName);
    static_cast<void>(wLanguage);
    static_cast<void>(lpData);
    static_cast<void>(cb);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kkernel32G_VerSetConditionMask(std::uint64_t ConditionMask, std::uint32_t TypeMask, std::uint8_t Condition) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(ConditionMask);
    static_cast<void>(TypeMask);
    static_cast<void>(Condition);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_VerifyScripts(std::uint32_t dwFlags, const char16_t* lpLocaleScripts, std::int32_t cchLocaleScripts, const char16_t* lpTestScripts, std::int32_t cchTestScripts) noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    static_cast<void>(dwFlags);
    static_cast<void>(lpLocaleScripts);
    static_cast<void>(cchLocaleScripts);
    static_cast<void>(lpTestScripts);
    static_cast<void>(cchTestScripts);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_VerifyVersionInfoA(void* lpVersionInformation, std::uint32_t dwTypeMask, std::uint64_t dwlConditionMask) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpVersionInformation);
    static_cast<void>(dwTypeMask);
    static_cast<void>(dwlConditionMask);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_VerifyVersionInfoW(void* lpVersionInformation, std::uint32_t dwTypeMask, std::uint64_t dwlConditionMask) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpVersionInformation);
    static_cast<void>(dwTypeMask);
    static_cast<void>(dwlConditionMask);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_WTSGetActiveConsoleSessionId() noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_Wow64DisableWow64FsRedirection(void** OldValue) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(OldValue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_Wow64EnableWow64FsRedirection(std::uint8_t Wow64FsEnableRedirection) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(Wow64FsEnableRedirection);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_Wow64GetThreadSelectorEntry(void* hThread, std::uint32_t dwSelector, std::uint64_t lpSelectorEntry) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hThread);
    static_cast<void>(dwSelector);
    static_cast<void>(lpSelectorEntry);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_Wow64RevertWow64FsRedirection(void* OlValue) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(OlValue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_Wow64SuspendThread(void* hThread) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hThread);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_WriteConsoleInputA(void* hConsoleInput, const void* lpBuffer, std::uint32_t nLength, std::uint32_t* lpNumberOfEventsWritten) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(hConsoleInput);
    static_cast<void>(lpBuffer);
    static_cast<void>(nLength);
    static_cast<void>(lpNumberOfEventsWritten);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_WriteConsoleInputW(void* hConsoleInput, const void* lpBuffer, std::uint32_t nLength, std::uint32_t* lpNumberOfEventsWritten) noexcept {
    // Refused: the console subsystem.
    //
    // a console is a window manager window with a screen buffer behind it;
    // this runtime's standard streams are the host's, which is what the stream
    // API answers
    static_cast<void>(hConsoleInput);
    static_cast<void>(lpBuffer);
    static_cast<void>(nLength);
    static_cast<void>(lpNumberOfEventsWritten);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_WriteFileEx(void* hFile, const void* lpBuffer, std::uint32_t nNumberOfBytesToWrite, void* lpOverlapped, void* lpCompletionRoutine) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lpBuffer);
    static_cast<void>(nNumberOfBytesToWrite);
    static_cast<void>(lpOverlapped);
    static_cast<void>(lpCompletionRoutine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_WriteFileGather(void* hFile, std::uint64_t* aSegmentArray, std::uint32_t nNumberOfBytesToWrite, std::uint32_t* lpReserved, void* lpOverlapped) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(aSegmentArray);
    static_cast<void>(nNumberOfBytesToWrite);
    static_cast<void>(lpReserved);
    static_cast<void>(lpOverlapped);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_WritePrivateProfileSectionA(const char* lpAppName, const char* lpString, const char* lpFileName) noexcept {
    const std::u16string wide_app = profile_wide(lpAppName);
    const std::u16string wide_text = profile_wide(lpString);
    const std::u16string wide_path = profile_wide(lpFileName);
    if (lpFileName == nullptr || lpAppName == nullptr) {
        return 0;
    }
    std::vector<std::u16string> lines;
    static_cast<void>(profile_load(wide_path, &lines));
    profile_remove_section(&lines, wide_app);
    if (lpString == nullptr || *lpString == static_cast<char>(0)) {
        // An empty text leaves the section removed, which is the API's way
        // of deleting one.
        return profile_store(wide_path, lines) ? 1 : 0;
    }
    // The text is the format's own lines, each terminated by a null, in the
    // same shape the read side answers with. It is read at the wide width
    // whichever spelling the caller used, so that the pair splitter is the
    // one the read side uses. Only the pairs are taken: a comment in the
    // caller's text is not part of a section's contents.
    const char16_t* at = wide_text.c_str();
    for (;;) {
        const std::size_t length = text_len(at);
        if (length == 0) {
            break;
        }
        const std::u16string line(at, length);
        IniSpan<char16_t> span{line.c_str(), line.size()};
        IniSpan<char16_t> key{};
        IniSpan<char16_t> value{};
        if (ini_pair_of<char16_t>(span, &key, &value)) {
            profile_set(&lines, wide_app,
                        std::u16string_view(key.text, key.length),
                        std::u16string(value.text, value.length), false);
        }
        at += length + 1;
    }
    return profile_store(wide_path, lines) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_WritePrivateProfileSectionW(const char16_t* lpAppName, const char16_t* lpString, const char16_t* lpFileName) noexcept {
    if (lpFileName == nullptr || lpAppName == nullptr) {
        return 0;
    }
    std::vector<std::u16string> lines;
    static_cast<void>(profile_load(lpFileName, &lines));
    profile_remove_section(&lines, lpAppName);
    if (lpString == nullptr || *lpString == static_cast<char16_t>(0)) {
        // An empty text leaves the section removed, which is the API's way
        // of deleting one.
        return profile_store(lpFileName, lines) ? 1 : 0;
    }
    // The text is the format's own lines, each terminated by a null, in the
    // same shape the read side answers with. It is read at the wide width
    // whichever spelling the caller used, so that the pair splitter is the
    // one the read side uses. Only the pairs are taken: a comment in the
    // caller's text is not part of a section's contents.
    const char16_t* at = lpString;
    for (;;) {
        const std::size_t length = text_len(at);
        if (length == 0) {
            break;
        }
        const std::u16string line(at, length);
        IniSpan<char16_t> span{line.c_str(), line.size()};
        IniSpan<char16_t> key{};
        IniSpan<char16_t> value{};
        if (ini_pair_of<char16_t>(span, &key, &value)) {
            profile_set(&lines, lpAppName,
                        std::u16string_view(key.text, key.length),
                        std::u16string(value.text, value.length), false);
        }
        at += length + 1;
    }
    return profile_store(lpFileName, lines) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_WritePrivateProfileStringA(const char* lpAppName, const char* lpKeyName, const char* lpString, const char* lpFileName) noexcept {
    const std::u16string wide_app = profile_wide(lpAppName);
    const std::u16string wide_key = profile_wide(lpKeyName);
    const std::u16string wide_value = profile_wide(lpString);
    const std::u16string wide_path = profile_wide(lpFileName);
    if (lpFileName == nullptr) {
        return 0;
    }
    if (lpAppName == nullptr) {
        // A null section names nothing, and the call has nothing to do.
        return 0;
    }
    std::vector<std::u16string> lines;
    static_cast<void>(profile_load(wide_path, &lines));
    if (lpKeyName == nullptr) {
        // A null key asks for the section itself to go, which is a
        // different request from clearing one value in it.
        profile_remove_section(&lines, wide_app);
        return profile_store(wide_path, lines) ? 1 : 0;
    }
    if (lpString == nullptr) {
        profile_set(&lines, wide_app, wide_key, std::u16string{}, true);
    } else {
        profile_set(&lines, wide_app, wide_key, wide_value, false);
    }
    return profile_store(wide_path, lines) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_WritePrivateProfileStringW(const char16_t* lpAppName, const char16_t* lpKeyName, const char16_t* lpString, const char16_t* lpFileName) noexcept {
    if (lpFileName == nullptr) {
        return 0;
    }
    if (lpAppName == nullptr) {
        // A null section names nothing, and the call has nothing to do.
        return 0;
    }
    std::vector<std::u16string> lines;
    static_cast<void>(profile_load(lpFileName, &lines));
    if (lpKeyName == nullptr) {
        // A null key asks for the section itself to go, which is a
        // different request from clearing one value in it.
        profile_remove_section(&lines, lpAppName);
        return profile_store(lpFileName, lines) ? 1 : 0;
    }
    if (lpString == nullptr) {
        profile_set(&lines, lpAppName, lpKeyName, std::u16string{}, true);
    } else {
        profile_set(&lines, lpAppName, lpKeyName, lpString, false);
    }
    return profile_store(lpFileName, lines) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_WritePrivateProfileStructA(const char* lpszSection, const char* lpszKey, void* lpStruct, std::uint32_t uSizeStruct, const char* szFile) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(lpszSection);
    static_cast<void>(lpszKey);
    static_cast<void>(lpStruct);
    static_cast<void>(uSizeStruct);
    static_cast<void>(szFile);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_WritePrivateProfileStructW(const char16_t* lpszSection, const char16_t* lpszKey, void* lpStruct, std::uint32_t uSizeStruct, const char16_t* szFile) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(lpszSection);
    static_cast<void>(lpszKey);
    static_cast<void>(lpStruct);
    static_cast<void>(uSizeStruct);
    static_cast<void>(szFile);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_WriteProfileSectionA(const char* lpAppName, const char* lpString) noexcept {
    const std::u16string wide_app = profile_wide(lpAppName);
    const std::u16string wide_text = profile_wide(lpString);
    if (profile_shared_file() == nullptr || lpAppName == nullptr) {
        return 0;
    }
    std::vector<std::u16string> lines;
    static_cast<void>(profile_load(profile_shared_file(), &lines));
    profile_remove_section(&lines, wide_app);
    if (lpString == nullptr || *lpString == static_cast<char>(0)) {
        // An empty text leaves the section removed, which is the API's way
        // of deleting one.
        return profile_store(profile_shared_file(), lines) ? 1 : 0;
    }
    // The text is the format's own lines, each terminated by a null, in the
    // same shape the read side answers with. It is read at the wide width
    // whichever spelling the caller used, so that the pair splitter is the
    // one the read side uses. Only the pairs are taken: a comment in the
    // caller's text is not part of a section's contents.
    const char16_t* at = wide_text.c_str();
    for (;;) {
        const std::size_t length = text_len(at);
        if (length == 0) {
            break;
        }
        const std::u16string line(at, length);
        IniSpan<char16_t> span{line.c_str(), line.size()};
        IniSpan<char16_t> key{};
        IniSpan<char16_t> value{};
        if (ini_pair_of<char16_t>(span, &key, &value)) {
            profile_set(&lines, wide_app,
                        std::u16string_view(key.text, key.length),
                        std::u16string(value.text, value.length), false);
        }
        at += length + 1;
    }
    return profile_store(profile_shared_file(), lines) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_WriteProfileSectionW(const char16_t* lpAppName, const char16_t* lpString) noexcept {
    if (profile_shared_file() == nullptr || lpAppName == nullptr) {
        return 0;
    }
    std::vector<std::u16string> lines;
    static_cast<void>(profile_load(profile_shared_file(), &lines));
    profile_remove_section(&lines, lpAppName);
    if (lpString == nullptr || *lpString == static_cast<char16_t>(0)) {
        // An empty text leaves the section removed, which is the API's way
        // of deleting one.
        return profile_store(profile_shared_file(), lines) ? 1 : 0;
    }
    // The text is the format's own lines, each terminated by a null, in the
    // same shape the read side answers with. It is read at the wide width
    // whichever spelling the caller used, so that the pair splitter is the
    // one the read side uses. Only the pairs are taken: a comment in the
    // caller's text is not part of a section's contents.
    const char16_t* at = lpString;
    for (;;) {
        const std::size_t length = text_len(at);
        if (length == 0) {
            break;
        }
        const std::u16string line(at, length);
        IniSpan<char16_t> span{line.c_str(), line.size()};
        IniSpan<char16_t> key{};
        IniSpan<char16_t> value{};
        if (ini_pair_of<char16_t>(span, &key, &value)) {
            profile_set(&lines, lpAppName,
                        std::u16string_view(key.text, key.length),
                        std::u16string(value.text, value.length), false);
        }
        at += length + 1;
    }
    return profile_store(profile_shared_file(), lines) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_WriteProfileStringA(const char* lpAppName, const char* lpKeyName, const char* lpString) noexcept {
    const std::u16string wide_app = profile_wide(lpAppName);
    const std::u16string wide_key = profile_wide(lpKeyName);
    const std::u16string wide_value = profile_wide(lpString);
    if (profile_shared_file() == nullptr) {
        return 0;
    }
    if (lpAppName == nullptr) {
        // A null section names nothing, and the call has nothing to do.
        return 0;
    }
    std::vector<std::u16string> lines;
    static_cast<void>(profile_load(profile_shared_file(), &lines));
    if (lpKeyName == nullptr) {
        // A null key asks for the section itself to go, which is a
        // different request from clearing one value in it.
        profile_remove_section(&lines, wide_app);
        return profile_store(profile_shared_file(), lines) ? 1 : 0;
    }
    if (lpString == nullptr) {
        profile_set(&lines, wide_app, wide_key, std::u16string{}, true);
    } else {
        profile_set(&lines, wide_app, wide_key, wide_value, false);
    }
    return profile_store(profile_shared_file(), lines) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_WriteProfileStringW(const char16_t* lpAppName, const char16_t* lpKeyName, const char16_t* lpString) noexcept {
    if (profile_shared_file() == nullptr) {
        return 0;
    }
    if (lpAppName == nullptr) {
        // A null section names nothing, and the call has nothing to do.
        return 0;
    }
    std::vector<std::u16string> lines;
    static_cast<void>(profile_load(profile_shared_file(), &lines));
    if (lpKeyName == nullptr) {
        // A null key asks for the section itself to go, which is a
        // different request from clearing one value in it.
        profile_remove_section(&lines, lpAppName);
        return profile_store(profile_shared_file(), lines) ? 1 : 0;
    }
    if (lpString == nullptr) {
        profile_set(&lines, lpAppName, lpKeyName, std::u16string{}, true);
    } else {
        profile_set(&lines, lpAppName, lpKeyName, lpString, false);
    }
    return profile_store(profile_shared_file(), lines) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_WriteTapemark(void* hDevice, std::uint32_t dwTapemarkType, std::uint32_t dwTapemarkCount, std::int32_t bImmediate) noexcept {
    // Refused: the tape device layer.
    //
    // a tape is a device reached through the device I/O control surface
    static_cast<void>(hDevice);
    static_cast<void>(dwTapemarkType);
    static_cast<void>(dwTapemarkCount);
    static_cast<void>(bImmediate);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_ZombifyActCtx(void* hActCtx) noexcept {
    // Refused: the side-by-side activation context.
    //
    // an activation context is built from a manifest and a catalog store by
    // the loader's own subsystem; this runtime resolves modules by name
    static_cast<void>(hActCtx);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_BitScanForward(std::uint32_t* Index, std::uint32_t Mask) noexcept {
    if (Index == nullptr) {
        return 0;
    }
    std::uint32_t found = 0;
    if (!scan_forward(static_cast<std::uint32_t>(Mask), &found)) {
        return 0;
    }
    *Index = found;
    return 1;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_BitScanForward64(std::uint32_t* Index, std::uint64_t Mask) noexcept {
    if (Index == nullptr) {
        return 0;
    }
    std::uint32_t found = 0;
    if (!scan_forward(static_cast<std::uint64_t>(Mask), &found)) {
        return 0;
    }
    *Index = found;
    return 1;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_BitScanReverse(std::uint32_t* Index, std::uint32_t Mask) noexcept {
    if (Index == nullptr) {
        return 0;
    }
    std::uint32_t found = 0;
    if (!scan_reverse(static_cast<std::uint32_t>(Mask), &found)) {
        return 0;
    }
    *Index = found;
    return 1;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_BitScanReverse64(std::uint32_t* Index, std::uint64_t Mask) noexcept {
    if (Index == nullptr) {
        return 0;
    }
    std::uint32_t found = 0;
    if (!scan_reverse(static_cast<std::uint64_t>(Mask), &found)) {
        return 0;
    }
    *Index = found;
    return 1;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_InterlockedAdd(std::int32_t* Addend, std::int32_t Value) noexcept {
    if (Addend == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int32_t*>(Addend);
    std::int32_t value = static_cast<std::int32_t>(Value);
    return static_cast<std::int32_t>(__atomic_add_fetch(p, value, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::int64_t kkernel32G_InterlockedAdd64(std::int64_t* Addend, std::int64_t Value) noexcept {
    if (Addend == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int64_t*>(Addend);
    std::int64_t value = static_cast<std::int64_t>(Value);
    return static_cast<std::int64_t>(__atomic_add_fetch(p, value, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_InterlockedAnd(std::int32_t* arg0, std::int32_t arg1) noexcept {
    if (arg0 == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int32_t*>(arg0);
    std::int32_t value = static_cast<std::int32_t>(arg1);
    return static_cast<std::int32_t>(__atomic_fetch_and(p, value, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::int64_t kkernel32G_InterlockedAnd64(std::int64_t* arg0, std::int32_t long_) noexcept {
    if (arg0 == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int64_t*>(arg0);
    std::int64_t value = static_cast<std::int64_t>(long_);
    return static_cast<std::int64_t>(__atomic_fetch_and(p, value, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_InterlockedCompareExchange(std::int32_t* Destination, std::int32_t ExChange, std::int32_t Comperand) noexcept {
    if (Destination == nullptr) {
        return static_cast<std::int32_t>(0);
    }
    auto* p = const_cast<std::int32_t*>(Destination);
    std::int32_t expected = static_cast<std::int32_t>(Comperand);
    static_cast<void>(__atomic_compare_exchange_n(
        p, &expected, static_cast<std::int32_t>(ExChange), false,
        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST));
    return static_cast<std::int32_t>(expected);
}


extern "C" __attribute__((ms_abi)) std::int16_t kkernel32G_InterlockedCompareExchange16(std::int16_t* Destination, std::int16_t ExChange, std::int16_t Comperand) noexcept {
    if (Destination == nullptr) {
        return static_cast<std::int16_t>(0);
    }
    auto* p = const_cast<std::int16_t*>(Destination);
    std::int16_t expected = static_cast<std::int16_t>(Comperand);
    static_cast<void>(__atomic_compare_exchange_n(
        p, &expected, static_cast<std::int16_t>(ExChange), false,
        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST));
    return static_cast<std::int16_t>(expected);
}


extern "C" __attribute__((ms_abi)) std::int64_t kkernel32G_InterlockedCompareExchange64(std::int64_t* Destination, std::int64_t ExChange, std::int64_t Comperand) noexcept {
    if (Destination == nullptr) {
        return static_cast<std::int64_t>(0);
    }
    auto* p = const_cast<std::int64_t*>(Destination);
    std::int64_t expected = static_cast<std::int64_t>(Comperand);
    static_cast<void>(__atomic_compare_exchange_n(
        p, &expected, static_cast<std::int64_t>(ExChange), false,
        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST));
    return static_cast<std::int64_t>(expected);
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_InterlockedCompareExchangePointer(void** Destination, void* ExChange, void* Comperand) noexcept {
    if (Destination == nullptr) {
        return static_cast<void*>(0);
    }
    auto* p = const_cast<void**>(Destination);
    void* expected = static_cast<void*>(Comperand);
    static_cast<void>(__atomic_compare_exchange_n(
        p, &expected, static_cast<void*>(ExChange), false,
        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST));
    return static_cast<void*>(expected);
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_InterlockedDecrement(std::int32_t* Addend) noexcept {
    if (Addend == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int32_t*>(Addend);
    std::int32_t one = 1;
    return static_cast<std::int32_t>(__atomic_sub_fetch(p, one, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::int16_t kkernel32G_InterlockedDecrement16(std::int16_t* Addend) noexcept {
    if (Addend == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int16_t*>(Addend);
    std::int16_t one = 1;
    return static_cast<std::int16_t>(__atomic_sub_fetch(p, one, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::int64_t kkernel32G_InterlockedDecrement64(std::int64_t* Addend) noexcept {
    if (Addend == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int64_t*>(Addend);
    std::int64_t one = 1;
    return static_cast<std::int64_t>(__atomic_sub_fetch(p, one, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_InterlockedExchange(std::int32_t* Target, std::int32_t Value) noexcept {
    if (Target == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int32_t*>(Target);
    std::int32_t value = static_cast<std::int32_t>(Value);
    return static_cast<std::int32_t>(__atomic_exchange_n(p, value, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::int64_t kkernel32G_InterlockedExchange64(std::int64_t* Target, std::int64_t Value) noexcept {
    if (Target == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int64_t*>(Target);
    std::int64_t value = static_cast<std::int64_t>(Value);
    return static_cast<std::int64_t>(__atomic_exchange_n(p, value, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_InterlockedExchangeAdd(std::int32_t* Addend, std::int32_t Value) noexcept {
    if (Addend == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int32_t*>(Addend);
    std::int32_t value = static_cast<std::int32_t>(Value);
    return static_cast<std::int32_t>(__atomic_fetch_add(p, value, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::int64_t kkernel32G_InterlockedExchangeAdd64(std::int64_t* Addend, std::int64_t Value) noexcept {
    if (Addend == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int64_t*>(Addend);
    std::int64_t value = static_cast<std::int64_t>(Value);
    return static_cast<std::int64_t>(__atomic_fetch_add(p, value, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_InterlockedExchangePointer(void** Target, void* Value) noexcept {
    if (Target == nullptr) {
        return 0;
    }
    auto* p = const_cast<void**>(Target);
    void* value = static_cast<void*>(Value);
    return static_cast<void*>(__atomic_exchange_n(p, value, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_InterlockedIncrement(std::int32_t* Addend) noexcept {
    if (Addend == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int32_t*>(Addend);
    std::int32_t one = 1;
    return static_cast<std::int32_t>(__atomic_add_fetch(p, one, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::int16_t kkernel32G_InterlockedIncrement16(std::int16_t* Addend) noexcept {
    if (Addend == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int16_t*>(Addend);
    std::int16_t one = 1;
    return static_cast<std::int16_t>(__atomic_add_fetch(p, one, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::int64_t kkernel32G_InterlockedIncrement64(std::int64_t* Addend) noexcept {
    if (Addend == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int64_t*>(Addend);
    std::int64_t one = 1;
    return static_cast<std::int64_t>(__atomic_add_fetch(p, one, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_InterlockedOr(std::int32_t* arg0, std::int32_t arg1) noexcept {
    if (arg0 == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int32_t*>(arg0);
    std::int32_t value = static_cast<std::int32_t>(arg1);
    return static_cast<std::int32_t>(__atomic_fetch_or(p, value, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::int64_t kkernel32G_InterlockedOr64(std::int64_t* arg0, std::int32_t long_) noexcept {
    if (arg0 == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int64_t*>(arg0);
    std::int64_t value = static_cast<std::int64_t>(long_);
    return static_cast<std::int64_t>(__atomic_fetch_or(p, value, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_InterlockedXor(std::int32_t* arg0, std::int32_t arg1) noexcept {
    if (arg0 == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int32_t*>(arg0);
    std::int32_t value = static_cast<std::int32_t>(arg1);
    return static_cast<std::int32_t>(__atomic_fetch_xor(p, value, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::int64_t kkernel32G_InterlockedXor64(std::int64_t* arg0, std::int32_t long_) noexcept {
    if (arg0 == nullptr) {
        return 0;
    }
    auto* p = const_cast<std::int64_t*>(arg0);
    std::int64_t value = static_cast<std::int64_t>(long_);
    return static_cast<std::int64_t>(__atomic_fetch_xor(p, value, __ATOMIC_SEQ_CST));
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_bittest(std::int32_t* a, std::int32_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    return bit_of<std::int32_t>(*a, b) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_bittest64(std::int64_t* a, std::int64_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    return bit_of<std::int64_t>(*a, b) ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_bittestandcomplement(std::int32_t* a, std::int32_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    const bool was = bit_of<std::int32_t>(*a, b);
    bit_set<std::int32_t>(a, b, !was);
    return was ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_bittestandcomplement64(std::int64_t* a, std::int64_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    const bool was = bit_of<std::int64_t>(*a, b);
    bit_set<std::int64_t>(a, b, !was);
    return was ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_bittestandreset(std::int32_t* a, std::int32_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    const bool was = bit_of<std::int32_t>(*a, b);
    bit_set<std::int32_t>(a, b, false);
    return was ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_bittestandreset64(std::int64_t* a, std::int64_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    const bool was = bit_of<std::int64_t>(*a, b);
    bit_set<std::int64_t>(a, b, false);
    return was ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_bittestandset(std::int32_t* a, std::int32_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    const bool was = bit_of<std::int32_t>(*a, b);
    bit_set<std::int32_t>(a, b, true);
    return was ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_bittestandset64(std::int64_t* a, std::int64_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    const bool was = bit_of<std::int64_t>(*a, b);
    bit_set<std::int64_t>(a, b, true);
    return was ? 1 : 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_hread(void* hFile, void* lpBuffer, std::int32_t lBytes) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lpBuffer);
    static_cast<void>(lBytes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_hwrite(void* hFile, std::uint64_t lpBuffer, std::int32_t lBytes) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lpBuffer);
    static_cast<void>(lBytes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_interlockedbittestandcomplement(std::int32_t* a, std::int32_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    // The bit test is the atomic form of the three non-atomic ones: the read
    // and the write are one operation, which is what a caller that uses it
    // as a lock relies on.
    auto* p = const_cast<std::int32_t*>(a);
    const std::int64_t at = static_cast<std::int64_t>(b);
    if (at < 0 || at >= static_cast<std::int64_t>(sizeof(std::int32_t) * 8)) {
        return 0;
    }
    const std::int32_t bit = static_cast<std::int32_t>(static_cast<std::int32_t>(1) << at);
    for (;;) {
        std::int32_t current = __atomic_load_n(p, __ATOMIC_SEQ_CST);
        const bool was = (current & bit) != 0;
        const std::int32_t wanted =
            static_cast<std::int32_t>(current | bit);
        if (__atomic_compare_exchange_n(p, &current, wanted, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            return was ? 1 : 0;
        }
    }
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_interlockedbittestandcomplement64(std::int64_t* a, std::int64_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    // The bit test is the atomic form of the three non-atomic ones: the read
    // and the write are one operation, which is what a caller that uses it
    // as a lock relies on.
    auto* p = const_cast<std::int64_t*>(a);
    const std::int64_t at = static_cast<std::int64_t>(b);
    if (at < 0 || at >= static_cast<std::int64_t>(sizeof(std::int64_t) * 8)) {
        return 0;
    }
    const std::int64_t bit = static_cast<std::int64_t>(static_cast<std::int64_t>(1) << at);
    for (;;) {
        std::int64_t current = __atomic_load_n(p, __ATOMIC_SEQ_CST);
        const bool was = (current & bit) != 0;
        const std::int64_t wanted =
            static_cast<std::int64_t>(current | bit);
        if (__atomic_compare_exchange_n(p, &current, wanted, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            return was ? 1 : 0;
        }
    }
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_interlockedbittestandreset(std::int32_t* a, std::int32_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    // The bit test is the atomic form of the three non-atomic ones: the read
    // and the write are one operation, which is what a caller that uses it
    // as a lock relies on.
    auto* p = const_cast<std::int32_t*>(a);
    const std::int64_t at = static_cast<std::int64_t>(b);
    if (at < 0 || at >= static_cast<std::int64_t>(sizeof(std::int32_t) * 8)) {
        return 0;
    }
    const std::int32_t bit = static_cast<std::int32_t>(static_cast<std::int32_t>(1) << at);
    for (;;) {
        std::int32_t current = __atomic_load_n(p, __ATOMIC_SEQ_CST);
        const bool was = (current & bit) != 0;
        const std::int32_t wanted =
            static_cast<std::int32_t>(current | bit);
        if (__atomic_compare_exchange_n(p, &current, wanted, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            return was ? 1 : 0;
        }
    }
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_interlockedbittestandreset64(std::int64_t* a, std::int64_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    // The bit test is the atomic form of the three non-atomic ones: the read
    // and the write are one operation, which is what a caller that uses it
    // as a lock relies on.
    auto* p = const_cast<std::int64_t*>(a);
    const std::int64_t at = static_cast<std::int64_t>(b);
    if (at < 0 || at >= static_cast<std::int64_t>(sizeof(std::int64_t) * 8)) {
        return 0;
    }
    const std::int64_t bit = static_cast<std::int64_t>(static_cast<std::int64_t>(1) << at);
    for (;;) {
        std::int64_t current = __atomic_load_n(p, __ATOMIC_SEQ_CST);
        const bool was = (current & bit) != 0;
        const std::int64_t wanted =
            static_cast<std::int64_t>(current | bit);
        if (__atomic_compare_exchange_n(p, &current, wanted, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            return was ? 1 : 0;
        }
    }
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_interlockedbittestandset(std::int32_t* a, std::int32_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    // The bit test is the atomic form of the three non-atomic ones: the read
    // and the write are one operation, which is what a caller that uses it
    // as a lock relies on.
    auto* p = const_cast<std::int32_t*>(a);
    const std::int64_t at = static_cast<std::int64_t>(b);
    if (at < 0 || at >= static_cast<std::int64_t>(sizeof(std::int32_t) * 8)) {
        return 0;
    }
    const std::int32_t bit = static_cast<std::int32_t>(static_cast<std::int32_t>(1) << at);
    for (;;) {
        std::int32_t current = __atomic_load_n(p, __ATOMIC_SEQ_CST);
        const bool was = (current & bit) != 0;
        const std::int32_t wanted =
            static_cast<std::int32_t>(current | bit);
        if (__atomic_compare_exchange_n(p, &current, wanted, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            return was ? 1 : 0;
        }
    }
}


extern "C" __attribute__((ms_abi)) std::uint8_t kkernel32G_interlockedbittestandset64(std::int64_t* a, std::int64_t b) noexcept {
    if (a == nullptr) {
        return 0;
    }
    // The bit test is the atomic form of the three non-atomic ones: the read
    // and the write are one operation, which is what a caller that uses it
    // as a lock relies on.
    auto* p = const_cast<std::int64_t*>(a);
    const std::int64_t at = static_cast<std::int64_t>(b);
    if (at < 0 || at >= static_cast<std::int64_t>(sizeof(std::int64_t) * 8)) {
        return 0;
    }
    const std::int64_t bit = static_cast<std::int64_t>(static_cast<std::int64_t>(1) << at);
    for (;;) {
        std::int64_t current = __atomic_load_n(p, __ATOMIC_SEQ_CST);
        const bool was = (current & bit) != 0;
        const std::int64_t wanted =
            static_cast<std::int64_t>(current | bit);
        if (__atomic_compare_exchange_n(p, &current, wanted, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            return was ? 1 : 0;
        }
    }
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_lclose(void* hFile) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_lcreat(const char* lpPathName, std::int32_t iAttribute) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpPathName);
    static_cast<void>(iAttribute);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kkernel32G_llseek(void* hFile, std::int32_t lOffset, std::int32_t iOrigin) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lOffset);
    static_cast<void>(iOrigin);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kkernel32G_lopen(const char* lpPathName, std::int32_t iReadWrite) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(lpPathName);
    static_cast<void>(iReadWrite);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_lread(void* hFile, void* lpBuffer, std::uint32_t uBytes) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lpBuffer);
    static_cast<void>(uBytes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kkernel32G_lwrite(void* hFile, std::uint64_t lpBuffer, std::uint32_t uBytes) noexcept {
    // Refused: a kernel subsystem this runtime does not provide.
    //
    // the call reaches a device, a service or a kernel object this runtime has
    // no counterpart for
    static_cast<void>(hFile);
    static_cast<void>(lpBuffer);
    static_cast<void>(uBytes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kkernel32G_mul128(std::int64_t Multiplier, std::int64_t Multiplicand, std::int64_t* HighProduct) noexcept {
    const unsigned __int128 product = widen_product(
        static_cast<std::uint64_t>(Multiplier), static_cast<std::uint64_t>(Multiplicand));
    if (HighProduct != nullptr) {
        *HighProduct = static_cast<std::int64_t>(product >> 64);
    }
    return static_cast<std::int64_t>(static_cast<std::uint64_t>(product));
}


extern "C" __attribute__((ms_abi)) std::uint64_t kkernel32G_umul128(std::uint64_t Multiplier, std::uint64_t Multiplicand, std::uint64_t* HighProduct) noexcept {
    const unsigned __int128 product = widen_product(
        static_cast<std::uint64_t>(Multiplier), static_cast<std::uint64_t>(Multiplicand));
    if (HighProduct != nullptr) {
        *HighProduct = static_cast<std::uint64_t>(product >> 64);
    }
    return static_cast<std::uint64_t>(product);
}

}  // namespace

void add_generated_kernel32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("ActivateActCtx", reinterpret_cast<void*>(&kkernel32G_ActivateActCtx));
    e("AddAtomA", reinterpret_cast<void*>(&kkernel32G_AddAtomA));
    e("AddAtomW", reinterpret_cast<void*>(&kkernel32G_AddAtomW));
    e("AddConsoleAliasA", reinterpret_cast<void*>(&kkernel32G_AddConsoleAliasA));
    e("AddConsoleAliasW", reinterpret_cast<void*>(&kkernel32G_AddConsoleAliasW));
    e("AddDllDirectory", reinterpret_cast<void*>(&kkernel32G_AddDllDirectory));
    e("AddIntegrityLabelToBoundaryDescriptor", reinterpret_cast<void*>(&kkernel32G_AddIntegrityLabelToBoundaryDescriptor));
    e("AddRefActCtx", reinterpret_cast<void*>(&kkernel32G_AddRefActCtx));
    e("AddResourceAttributeAce", reinterpret_cast<void*>(&kkernel32G_AddResourceAttributeAce));
    e("AddSIDToBoundaryDescriptor", reinterpret_cast<void*>(&kkernel32G_AddSIDToBoundaryDescriptor));
    e("AddScopedPolicyIDAce", reinterpret_cast<void*>(&kkernel32G_AddScopedPolicyIDAce));
    e("AddSecureMemoryCacheCallback", reinterpret_cast<void*>(&kkernel32G_AddSecureMemoryCacheCallback));
    e("AllocateUserPhysicalPages", reinterpret_cast<void*>(&kkernel32G_AllocateUserPhysicalPages));
    e("AllocateUserPhysicalPagesNuma", reinterpret_cast<void*>(&kkernel32G_AllocateUserPhysicalPagesNuma));
    e("ApplicationRecoveryFinished", reinterpret_cast<void*>(&kkernel32G_ApplicationRecoveryFinished));
    e("ApplicationRecoveryInProgress", reinterpret_cast<void*>(&kkernel32G_ApplicationRecoveryInProgress));
    e("AreFileApisANSI", reinterpret_cast<void*>(&kkernel32G_AreFileApisANSI));
    e("AssignProcessToJobObject", reinterpret_cast<void*>(&kkernel32G_AssignProcessToJobObject));
    e("BackupRead", reinterpret_cast<void*>(&kkernel32G_BackupRead));
    e("BackupSeek", reinterpret_cast<void*>(&kkernel32G_BackupSeek));
    e("BackupWrite", reinterpret_cast<void*>(&kkernel32G_BackupWrite));
    e("BeginUpdateResourceA", reinterpret_cast<void*>(&kkernel32G_BeginUpdateResourceA));
    e("BeginUpdateResourceW", reinterpret_cast<void*>(&kkernel32G_BeginUpdateResourceW));
    e("BindIoCompletionCallback", reinterpret_cast<void*>(&kkernel32G_BindIoCompletionCallback));
    e("BuildCommDCBA", reinterpret_cast<void*>(&kkernel32G_BuildCommDCBA));
    e("BuildCommDCBAndTimeoutsA", reinterpret_cast<void*>(&kkernel32G_BuildCommDCBAndTimeoutsA));
    e("BuildCommDCBAndTimeoutsW", reinterpret_cast<void*>(&kkernel32G_BuildCommDCBAndTimeoutsW));
    e("BuildCommDCBW", reinterpret_cast<void*>(&kkernel32G_BuildCommDCBW));
    e("CallNamedPipeA", reinterpret_cast<void*>(&kkernel32G_CallNamedPipeA));
    e("CallNamedPipeW", reinterpret_cast<void*>(&kkernel32G_CallNamedPipeW));
    e("CallbackMayRunLong", reinterpret_cast<void*>(&kkernel32G_CallbackMayRunLong));
    e("CancelDeviceWakeupRequest", reinterpret_cast<void*>(&kkernel32G_CancelDeviceWakeupRequest));
    e("CancelIo", reinterpret_cast<void*>(&kkernel32G_CancelIo));
    e("CancelSynchronousIo", reinterpret_cast<void*>(&kkernel32G_CancelSynchronousIo));
    e("CheckNameLegalDOS8Dot3A", reinterpret_cast<void*>(&kkernel32G_CheckNameLegalDOS8Dot3A));
    e("CheckNameLegalDOS8Dot3W", reinterpret_cast<void*>(&kkernel32G_CheckNameLegalDOS8Dot3W));
    e("CheckTokenCapability", reinterpret_cast<void*>(&kkernel32G_CheckTokenCapability));
    e("CheckTokenMembershipEx", reinterpret_cast<void*>(&kkernel32G_CheckTokenMembershipEx));
    e("ClearCommBreak", reinterpret_cast<void*>(&kkernel32G_ClearCommBreak));
    e("ClearCommError", reinterpret_cast<void*>(&kkernel32G_ClearCommError));
    e("ClosePrivateNamespace", reinterpret_cast<void*>(&kkernel32G_ClosePrivateNamespace));
    e("CloseThreadpool", reinterpret_cast<void*>(&kkernel32G_CloseThreadpool));
    e("CloseThreadpoolCleanupGroup", reinterpret_cast<void*>(&kkernel32G_CloseThreadpoolCleanupGroup));
    e("CloseThreadpoolCleanupGroupMembers", reinterpret_cast<void*>(&kkernel32G_CloseThreadpoolCleanupGroupMembers));
    e("CloseThreadpoolWork", reinterpret_cast<void*>(&kkernel32G_CloseThreadpoolWork));
    e("CommConfigDialogA", reinterpret_cast<void*>(&kkernel32G_CommConfigDialogA));
    e("CommConfigDialogW", reinterpret_cast<void*>(&kkernel32G_CommConfigDialogW));
    e("ConnectNamedPipe", reinterpret_cast<void*>(&kkernel32G_ConnectNamedPipe));
    e("ConvertDefaultLocale", reinterpret_cast<void*>(&kkernel32G_ConvertDefaultLocale));
    e("ConvertFiberToThread", reinterpret_cast<void*>(&kkernel32G_ConvertFiberToThread));
    e("ConvertThreadToFiber", reinterpret_cast<void*>(&kkernel32G_ConvertThreadToFiber));
    e("ConvertThreadToFiberEx", reinterpret_cast<void*>(&kkernel32G_ConvertThreadToFiberEx));
    e("CopyContext", reinterpret_cast<void*>(&kkernel32G_CopyContext));
    e("CopyFile2", reinterpret_cast<void*>(&kkernel32G_CopyFile2));
    e("CopyFileTransactedA", reinterpret_cast<void*>(&kkernel32G_CopyFileTransactedA));
    e("CopyFileTransactedW", reinterpret_cast<void*>(&kkernel32G_CopyFileTransactedW));
    e("CreateActCtxA", reinterpret_cast<void*>(&kkernel32G_CreateActCtxA));
    e("CreateActCtxW", reinterpret_cast<void*>(&kkernel32G_CreateActCtxW));
    e("CreateBoundaryDescriptorA", reinterpret_cast<void*>(&kkernel32G_CreateBoundaryDescriptorA));
    e("CreateBoundaryDescriptorW", reinterpret_cast<void*>(&kkernel32G_CreateBoundaryDescriptorW));
    e("CreateDirectoryExA", reinterpret_cast<void*>(&kkernel32G_CreateDirectoryExA));
    e("CreateDirectoryExW", reinterpret_cast<void*>(&kkernel32G_CreateDirectoryExW));
    e("CreateDirectoryTransactedA", reinterpret_cast<void*>(&kkernel32G_CreateDirectoryTransactedA));
    e("CreateDirectoryTransactedW", reinterpret_cast<void*>(&kkernel32G_CreateDirectoryTransactedW));
    e("CreateFiber", reinterpret_cast<void*>(&kkernel32G_CreateFiber));
    e("CreateFiberEx", reinterpret_cast<void*>(&kkernel32G_CreateFiberEx));
    e("CreateFile2", reinterpret_cast<void*>(&kkernel32G_CreateFile2));
    e("CreateFileMappingFromApp", reinterpret_cast<void*>(&kkernel32G_CreateFileMappingFromApp));
    e("CreateFileMappingNumaA", reinterpret_cast<void*>(&kkernel32G_CreateFileMappingNumaA));
    e("CreateFileMappingNumaW", reinterpret_cast<void*>(&kkernel32G_CreateFileMappingNumaW));
    e("CreateFileTransactedA", reinterpret_cast<void*>(&kkernel32G_CreateFileTransactedA));
    e("CreateFileTransactedW", reinterpret_cast<void*>(&kkernel32G_CreateFileTransactedW));
    e("CreateHardLinkTransactedA", reinterpret_cast<void*>(&kkernel32G_CreateHardLinkTransactedA));
    e("CreateHardLinkTransactedW", reinterpret_cast<void*>(&kkernel32G_CreateHardLinkTransactedW));
    e("CreateJobObjectA", reinterpret_cast<void*>(&kkernel32G_CreateJobObjectA));
    e("CreateJobObjectW", reinterpret_cast<void*>(&kkernel32G_CreateJobObjectW));
    e("CreateJobSet", reinterpret_cast<void*>(&kkernel32G_CreateJobSet));
    e("CreateMailslotA", reinterpret_cast<void*>(&kkernel32G_CreateMailslotA));
    e("CreateMailslotW", reinterpret_cast<void*>(&kkernel32G_CreateMailslotW));
    e("CreateMemoryResourceNotification", reinterpret_cast<void*>(&kkernel32G_CreateMemoryResourceNotification));
    e("CreateNamedPipeA", reinterpret_cast<void*>(&kkernel32G_CreateNamedPipeA));
    e("CreateNamedPipeW", reinterpret_cast<void*>(&kkernel32G_CreateNamedPipeW));
    e("CreatePipe", reinterpret_cast<void*>(&kkernel32G_CreatePipe));
    e("CreatePrivateNamespaceA", reinterpret_cast<void*>(&kkernel32G_CreatePrivateNamespaceA));
    e("CreatePrivateNamespaceW", reinterpret_cast<void*>(&kkernel32G_CreatePrivateNamespaceW));
    e("CreateRemoteThreadEx", reinterpret_cast<void*>(&kkernel32G_CreateRemoteThreadEx));
    e("CreateSymbolicLinkA", reinterpret_cast<void*>(&kkernel32G_CreateSymbolicLinkA));
    e("CreateSymbolicLinkTransactedA", reinterpret_cast<void*>(&kkernel32G_CreateSymbolicLinkTransactedA));
    e("CreateSymbolicLinkTransactedW", reinterpret_cast<void*>(&kkernel32G_CreateSymbolicLinkTransactedW));
    e("CreateSymbolicLinkW", reinterpret_cast<void*>(&kkernel32G_CreateSymbolicLinkW));
    e("CreateTapePartition", reinterpret_cast<void*>(&kkernel32G_CreateTapePartition));
    e("CreateUmsCompletionList", reinterpret_cast<void*>(&kkernel32G_CreateUmsCompletionList));
    e("CreateUmsThreadContext", reinterpret_cast<void*>(&kkernel32G_CreateUmsThreadContext));
    e("DeactivateActCtx", reinterpret_cast<void*>(&kkernel32G_DeactivateActCtx));
    e("DebugBreakProcess", reinterpret_cast<void*>(&kkernel32G_DebugBreakProcess));
    e("DecodePointer", reinterpret_cast<void*>(&kkernel32G_DecodePointer));
    e("DecodeSystemPointer", reinterpret_cast<void*>(&kkernel32G_DecodeSystemPointer));
    e("DefineDosDeviceA", reinterpret_cast<void*>(&kkernel32G_DefineDosDeviceA));
    e("DefineDosDeviceW", reinterpret_cast<void*>(&kkernel32G_DefineDosDeviceW));
    e("DeleteAtom", reinterpret_cast<void*>(&kkernel32G_DeleteAtom));
    e("DeleteBoundaryDescriptor", reinterpret_cast<void*>(&kkernel32G_DeleteBoundaryDescriptor));
    e("DeleteFiber", reinterpret_cast<void*>(&kkernel32G_DeleteFiber));
    e("DeleteFileTransactedA", reinterpret_cast<void*>(&kkernel32G_DeleteFileTransactedA));
    e("DeleteFileTransactedW", reinterpret_cast<void*>(&kkernel32G_DeleteFileTransactedW));
    e("DeleteProcThreadAttributeList", reinterpret_cast<void*>(&kkernel32G_DeleteProcThreadAttributeList));
    e("DeleteSynchronizationBarrier", reinterpret_cast<void*>(&kkernel32G_DeleteSynchronizationBarrier));
    e("DeleteUmsCompletionList", reinterpret_cast<void*>(&kkernel32G_DeleteUmsCompletionList));
    e("DeleteUmsThreadContext", reinterpret_cast<void*>(&kkernel32G_DeleteUmsThreadContext));
    e("DeleteVolumeMountPointA", reinterpret_cast<void*>(&kkernel32G_DeleteVolumeMountPointA));
    e("DeleteVolumeMountPointW", reinterpret_cast<void*>(&kkernel32G_DeleteVolumeMountPointW));
    e("DequeueUmsCompletionListItems", reinterpret_cast<void*>(&kkernel32G_DequeueUmsCompletionListItems));
    e("DisableThreadLibraryCalls", reinterpret_cast<void*>(&kkernel32G_DisableThreadLibraryCalls));
    e("DisableThreadProfiling", reinterpret_cast<void*>(&kkernel32G_DisableThreadProfiling));
    e("DisassociateCurrentThreadFromCallback", reinterpret_cast<void*>(&kkernel32G_DisassociateCurrentThreadFromCallback));
    e("DiscardVirtualMemory", reinterpret_cast<void*>(&kkernel32G_DiscardVirtualMemory));
    e("DisconnectNamedPipe", reinterpret_cast<void*>(&kkernel32G_DisconnectNamedPipe));
    e("DnsHostnameToComputerNameA", reinterpret_cast<void*>(&kkernel32G_DnsHostnameToComputerNameA));
    e("DnsHostnameToComputerNameW", reinterpret_cast<void*>(&kkernel32G_DnsHostnameToComputerNameW));
    e("DosDateTimeToFileTime", reinterpret_cast<void*>(&kkernel32G_DosDateTimeToFileTime));
    e("EnableThreadProfiling", reinterpret_cast<void*>(&kkernel32G_EnableThreadProfiling));
    e("EncodeSystemPointer", reinterpret_cast<void*>(&kkernel32G_EncodeSystemPointer));
    e("EndUpdateResourceA", reinterpret_cast<void*>(&kkernel32G_EndUpdateResourceA));
    e("EndUpdateResourceW", reinterpret_cast<void*>(&kkernel32G_EndUpdateResourceW));
    e("EnterSynchronizationBarrier", reinterpret_cast<void*>(&kkernel32G_EnterSynchronizationBarrier));
    e("EnterUmsSchedulingMode", reinterpret_cast<void*>(&kkernel32G_EnterUmsSchedulingMode));
    e("EnumCalendarInfoA", reinterpret_cast<void*>(&kkernel32G_EnumCalendarInfoA));
    e("EnumCalendarInfoExA", reinterpret_cast<void*>(&kkernel32G_EnumCalendarInfoExA));
    e("EnumCalendarInfoExEx", reinterpret_cast<void*>(&kkernel32G_EnumCalendarInfoExEx));
    e("EnumCalendarInfoExW", reinterpret_cast<void*>(&kkernel32G_EnumCalendarInfoExW));
    e("EnumCalendarInfoW", reinterpret_cast<void*>(&kkernel32G_EnumCalendarInfoW));
    e("EnumDateFormatsA", reinterpret_cast<void*>(&kkernel32G_EnumDateFormatsA));
    e("EnumDateFormatsExA", reinterpret_cast<void*>(&kkernel32G_EnumDateFormatsExA));
    e("EnumDateFormatsExEx", reinterpret_cast<void*>(&kkernel32G_EnumDateFormatsExEx));
    e("EnumDateFormatsExW", reinterpret_cast<void*>(&kkernel32G_EnumDateFormatsExW));
    e("EnumDateFormatsW", reinterpret_cast<void*>(&kkernel32G_EnumDateFormatsW));
    e("EnumLanguageGroupLocalesA", reinterpret_cast<void*>(&kkernel32G_EnumLanguageGroupLocalesA));
    e("EnumLanguageGroupLocalesW", reinterpret_cast<void*>(&kkernel32G_EnumLanguageGroupLocalesW));
    e("EnumResourceLanguagesA", reinterpret_cast<void*>(&kkernel32G_EnumResourceLanguagesA));
    e("EnumResourceLanguagesExA", reinterpret_cast<void*>(&kkernel32G_EnumResourceLanguagesExA));
    e("EnumResourceLanguagesExW", reinterpret_cast<void*>(&kkernel32G_EnumResourceLanguagesExW));
    e("EnumResourceLanguagesW", reinterpret_cast<void*>(&kkernel32G_EnumResourceLanguagesW));
    e("EnumResourceNamesA", reinterpret_cast<void*>(&kkernel32G_EnumResourceNamesA));
    e("EnumResourceNamesExA", reinterpret_cast<void*>(&kkernel32G_EnumResourceNamesExA));
    e("EnumResourceNamesExW", reinterpret_cast<void*>(&kkernel32G_EnumResourceNamesExW));
    e("EnumResourceNamesW", reinterpret_cast<void*>(&kkernel32G_EnumResourceNamesW));
    e("EnumResourceTypesA", reinterpret_cast<void*>(&kkernel32G_EnumResourceTypesA));
    e("EnumResourceTypesExA", reinterpret_cast<void*>(&kkernel32G_EnumResourceTypesExA));
    e("EnumResourceTypesExW", reinterpret_cast<void*>(&kkernel32G_EnumResourceTypesExW));
    e("EnumResourceTypesW", reinterpret_cast<void*>(&kkernel32G_EnumResourceTypesW));
    e("EnumSystemCodePagesA", reinterpret_cast<void*>(&kkernel32G_EnumSystemCodePagesA));
    e("EnumSystemCodePagesW", reinterpret_cast<void*>(&kkernel32G_EnumSystemCodePagesW));
    e("EnumSystemGeoID", reinterpret_cast<void*>(&kkernel32G_EnumSystemGeoID));
    e("EnumSystemLanguageGroupsA", reinterpret_cast<void*>(&kkernel32G_EnumSystemLanguageGroupsA));
    e("EnumSystemLanguageGroupsW", reinterpret_cast<void*>(&kkernel32G_EnumSystemLanguageGroupsW));
    e("EnumSystemLocalesA", reinterpret_cast<void*>(&kkernel32G_EnumSystemLocalesA));
    e("EnumSystemLocalesEx", reinterpret_cast<void*>(&kkernel32G_EnumSystemLocalesEx));
    e("EnumSystemLocalesW", reinterpret_cast<void*>(&kkernel32G_EnumSystemLocalesW));
    e("EnumTimeFormatsA", reinterpret_cast<void*>(&kkernel32G_EnumTimeFormatsA));
    e("EnumTimeFormatsEx", reinterpret_cast<void*>(&kkernel32G_EnumTimeFormatsEx));
    e("EnumTimeFormatsW", reinterpret_cast<void*>(&kkernel32G_EnumTimeFormatsW));
    e("EnumUILanguagesA", reinterpret_cast<void*>(&kkernel32G_EnumUILanguagesA));
    e("EnumUILanguagesW", reinterpret_cast<void*>(&kkernel32G_EnumUILanguagesW));
    e("EraseTape", reinterpret_cast<void*>(&kkernel32G_EraseTape));
    e("EscapeCommFunction", reinterpret_cast<void*>(&kkernel32G_EscapeCommFunction));
    e("ExecuteUmsThread", reinterpret_cast<void*>(&kkernel32G_ExecuteUmsThread));
    e("ExpungeConsoleCommandHistoryA", reinterpret_cast<void*>(&kkernel32G_ExpungeConsoleCommandHistoryA));
    e("ExpungeConsoleCommandHistoryW", reinterpret_cast<void*>(&kkernel32G_ExpungeConsoleCommandHistoryW));
    e("FatalExit", reinterpret_cast<void*>(&kkernel32G_FatalExit));
    e("FileTimeToDosDateTime", reinterpret_cast<void*>(&kkernel32G_FileTimeToDosDateTime));
    e("FindActCtxSectionGuid", reinterpret_cast<void*>(&kkernel32G_FindActCtxSectionGuid));
    e("FindActCtxSectionStringA", reinterpret_cast<void*>(&kkernel32G_FindActCtxSectionStringA));
    e("FindActCtxSectionStringW", reinterpret_cast<void*>(&kkernel32G_FindActCtxSectionStringW));
    e("FindAtomA", reinterpret_cast<void*>(&kkernel32G_FindAtomA));
    e("FindAtomW", reinterpret_cast<void*>(&kkernel32G_FindAtomW));
    e("FindCloseChangeNotification", reinterpret_cast<void*>(&kkernel32G_FindCloseChangeNotification));
    e("FindFirstChangeNotificationA", reinterpret_cast<void*>(&kkernel32G_FindFirstChangeNotificationA));
    e("FindFirstChangeNotificationW", reinterpret_cast<void*>(&kkernel32G_FindFirstChangeNotificationW));
    e("FindFirstFileExA", reinterpret_cast<void*>(&kkernel32G_FindFirstFileExA));
    e("FindFirstFileNameTransactedW", reinterpret_cast<void*>(&kkernel32G_FindFirstFileNameTransactedW));
    e("FindFirstFileNameW", reinterpret_cast<void*>(&kkernel32G_FindFirstFileNameW));
    e("FindFirstFileTransactedA", reinterpret_cast<void*>(&kkernel32G_FindFirstFileTransactedA));
    e("FindFirstFileTransactedW", reinterpret_cast<void*>(&kkernel32G_FindFirstFileTransactedW));
    e("FindFirstStreamTransactedW", reinterpret_cast<void*>(&kkernel32G_FindFirstStreamTransactedW));
    e("FindFirstStreamW", reinterpret_cast<void*>(&kkernel32G_FindFirstStreamW));
    e("FindFirstVolumeA", reinterpret_cast<void*>(&kkernel32G_FindFirstVolumeA));
    e("FindFirstVolumeMountPointA", reinterpret_cast<void*>(&kkernel32G_FindFirstVolumeMountPointA));
    e("FindFirstVolumeMountPointW", reinterpret_cast<void*>(&kkernel32G_FindFirstVolumeMountPointW));
    e("FindFirstVolumeW", reinterpret_cast<void*>(&kkernel32G_FindFirstVolumeW));
    e("FindNLSString", reinterpret_cast<void*>(&kkernel32G_FindNLSString));
    e("FindNLSStringEx", reinterpret_cast<void*>(&kkernel32G_FindNLSStringEx));
    e("FindNextChangeNotification", reinterpret_cast<void*>(&kkernel32G_FindNextChangeNotification));
    e("FindNextFileNameW", reinterpret_cast<void*>(&kkernel32G_FindNextFileNameW));
    e("FindNextStreamW", reinterpret_cast<void*>(&kkernel32G_FindNextStreamW));
    e("FindNextVolumeA", reinterpret_cast<void*>(&kkernel32G_FindNextVolumeA));
    e("FindNextVolumeMountPointA", reinterpret_cast<void*>(&kkernel32G_FindNextVolumeMountPointA));
    e("FindNextVolumeMountPointW", reinterpret_cast<void*>(&kkernel32G_FindNextVolumeMountPointW));
    e("FindNextVolumeW", reinterpret_cast<void*>(&kkernel32G_FindNextVolumeW));
    e("FindResourceA", reinterpret_cast<void*>(&kkernel32G_FindResourceA));
    e("FindResourceExA", reinterpret_cast<void*>(&kkernel32G_FindResourceExA));
    e("FindResourceExW", reinterpret_cast<void*>(&kkernel32G_FindResourceExW));
    e("FindResourceW", reinterpret_cast<void*>(&kkernel32G_FindResourceW));
    e("FindStringOrdinal", reinterpret_cast<void*>(&kkernel32G_FindStringOrdinal));
    e("FindVolumeClose", reinterpret_cast<void*>(&kkernel32G_FindVolumeClose));
    e("FindVolumeMountPointClose", reinterpret_cast<void*>(&kkernel32G_FindVolumeMountPointClose));
    e("FlushConsoleInputBuffer", reinterpret_cast<void*>(&kkernel32G_FlushConsoleInputBuffer));
    e("FreeLibraryWhenCallbackReturns", reinterpret_cast<void*>(&kkernel32G_FreeLibraryWhenCallbackReturns));
    e("FreeResource", reinterpret_cast<void*>(&kkernel32G_FreeResource));
    e("FreeUserPhysicalPages", reinterpret_cast<void*>(&kkernel32G_FreeUserPhysicalPages));
    e("GetActiveProcessorGroupCount", reinterpret_cast<void*>(&kkernel32G_GetActiveProcessorGroupCount));
    e("GetAppContainerAce", reinterpret_cast<void*>(&kkernel32G_GetAppContainerAce));
    e("GetAppContainerNamedObjectPath", reinterpret_cast<void*>(&kkernel32G_GetAppContainerNamedObjectPath));
    e("GetApplicationRecoveryCallback", reinterpret_cast<void*>(&kkernel32G_GetApplicationRecoveryCallback));
    e("GetApplicationRestartSettings", reinterpret_cast<void*>(&kkernel32G_GetApplicationRestartSettings));
    e("GetAtomNameA", reinterpret_cast<void*>(&kkernel32G_GetAtomNameA));
    e("GetAtomNameW", reinterpret_cast<void*>(&kkernel32G_GetAtomNameW));
    e("GetBinaryTypeA", reinterpret_cast<void*>(&kkernel32G_GetBinaryTypeA));
    e("GetBinaryTypeW", reinterpret_cast<void*>(&kkernel32G_GetBinaryTypeW));
    e("GetCachedSigningLevel", reinterpret_cast<void*>(&kkernel32G_GetCachedSigningLevel));
    e("GetCalendarInfoA", reinterpret_cast<void*>(&kkernel32G_GetCalendarInfoA));
    e("GetCalendarInfoEx", reinterpret_cast<void*>(&kkernel32G_GetCalendarInfoEx));
    e("GetCalendarInfoW", reinterpret_cast<void*>(&kkernel32G_GetCalendarInfoW));
    e("GetCommConfig", reinterpret_cast<void*>(&kkernel32G_GetCommConfig));
    e("GetCommMask", reinterpret_cast<void*>(&kkernel32G_GetCommMask));
    e("GetCommModemStatus", reinterpret_cast<void*>(&kkernel32G_GetCommModemStatus));
    e("GetCommProperties", reinterpret_cast<void*>(&kkernel32G_GetCommProperties));
    e("GetCommState", reinterpret_cast<void*>(&kkernel32G_GetCommState));
    e("GetCommTimeouts", reinterpret_cast<void*>(&kkernel32G_GetCommTimeouts));
    e("GetCompressedFileSizeTransactedA", reinterpret_cast<void*>(&kkernel32G_GetCompressedFileSizeTransactedA));
    e("GetCompressedFileSizeTransactedW", reinterpret_cast<void*>(&kkernel32G_GetCompressedFileSizeTransactedW));
    e("GetConsoleAliasA", reinterpret_cast<void*>(&kkernel32G_GetConsoleAliasA));
    e("GetConsoleAliasExesA", reinterpret_cast<void*>(&kkernel32G_GetConsoleAliasExesA));
    e("GetConsoleAliasExesLengthA", reinterpret_cast<void*>(&kkernel32G_GetConsoleAliasExesLengthA));
    e("GetConsoleAliasExesLengthW", reinterpret_cast<void*>(&kkernel32G_GetConsoleAliasExesLengthW));
    e("GetConsoleAliasExesW", reinterpret_cast<void*>(&kkernel32G_GetConsoleAliasExesW));
    e("GetConsoleAliasW", reinterpret_cast<void*>(&kkernel32G_GetConsoleAliasW));
    e("GetConsoleAliasesA", reinterpret_cast<void*>(&kkernel32G_GetConsoleAliasesA));
    e("GetConsoleAliasesLengthA", reinterpret_cast<void*>(&kkernel32G_GetConsoleAliasesLengthA));
    e("GetConsoleAliasesLengthW", reinterpret_cast<void*>(&kkernel32G_GetConsoleAliasesLengthW));
    e("GetConsoleAliasesW", reinterpret_cast<void*>(&kkernel32G_GetConsoleAliasesW));
    e("GetConsoleCommandHistoryA", reinterpret_cast<void*>(&kkernel32G_GetConsoleCommandHistoryA));
    e("GetConsoleCommandHistoryLengthA", reinterpret_cast<void*>(&kkernel32G_GetConsoleCommandHistoryLengthA));
    e("GetConsoleCommandHistoryLengthW", reinterpret_cast<void*>(&kkernel32G_GetConsoleCommandHistoryLengthW));
    e("GetConsoleCommandHistoryW", reinterpret_cast<void*>(&kkernel32G_GetConsoleCommandHistoryW));
    e("GetConsoleDisplayMode", reinterpret_cast<void*>(&kkernel32G_GetConsoleDisplayMode));
    e("GetConsoleHistoryInfo", reinterpret_cast<void*>(&kkernel32G_GetConsoleHistoryInfo));
    e("GetConsoleProcessList", reinterpret_cast<void*>(&kkernel32G_GetConsoleProcessList));
    e("GetConsoleScreenBufferInfoEx", reinterpret_cast<void*>(&kkernel32G_GetConsoleScreenBufferInfoEx));
    e("GetConsoleSelectionInfo", reinterpret_cast<void*>(&kkernel32G_GetConsoleSelectionInfo));
    e("GetCurrencyFormatA", reinterpret_cast<void*>(&kkernel32G_GetCurrencyFormatA));
    e("GetCurrencyFormatEx", reinterpret_cast<void*>(&kkernel32G_GetCurrencyFormatEx));
    e("GetCurrencyFormatW", reinterpret_cast<void*>(&kkernel32G_GetCurrencyFormatW));
    e("GetCurrentActCtx", reinterpret_cast<void*>(&kkernel32G_GetCurrentActCtx));
    e("GetCurrentConsoleFont", reinterpret_cast<void*>(&kkernel32G_GetCurrentConsoleFont));
    e("GetCurrentConsoleFontEx", reinterpret_cast<void*>(&kkernel32G_GetCurrentConsoleFontEx));
    e("GetCurrentThreadStackLimits", reinterpret_cast<void*>(&kkernel32G_GetCurrentThreadStackLimits));
    e("GetCurrentUmsThread", reinterpret_cast<void*>(&kkernel32G_GetCurrentUmsThread));
    e("GetDateFormatA", reinterpret_cast<void*>(&kkernel32G_GetDateFormatA));
    e("GetDateFormatEx", reinterpret_cast<void*>(&kkernel32G_GetDateFormatEx));
    e("GetDateFormatW", reinterpret_cast<void*>(&kkernel32G_GetDateFormatW));
    e("GetDefaultCommConfigA", reinterpret_cast<void*>(&kkernel32G_GetDefaultCommConfigA));
    e("GetDefaultCommConfigW", reinterpret_cast<void*>(&kkernel32G_GetDefaultCommConfigW));
    e("GetDevicePowerState", reinterpret_cast<void*>(&kkernel32G_GetDevicePowerState));
    e("GetDllDirectoryA", reinterpret_cast<void*>(&kkernel32G_GetDllDirectoryA));
    e("GetDllDirectoryW", reinterpret_cast<void*>(&kkernel32G_GetDllDirectoryW));
    e("GetDurationFormat", reinterpret_cast<void*>(&kkernel32G_GetDurationFormat));
    e("GetDurationFormatEx", reinterpret_cast<void*>(&kkernel32G_GetDurationFormatEx));
    e("GetEnvironmentStrings", reinterpret_cast<void*>(&kkernel32G_GetEnvironmentStrings));
    e("GetFileAttributesTransactedA", reinterpret_cast<void*>(&kkernel32G_GetFileAttributesTransactedA));
    e("GetFileAttributesTransactedW", reinterpret_cast<void*>(&kkernel32G_GetFileAttributesTransactedW));
    e("GetFileBandwidthReservation", reinterpret_cast<void*>(&kkernel32G_GetFileBandwidthReservation));
    e("GetFileMUIInfo", reinterpret_cast<void*>(&kkernel32G_GetFileMUIInfo));
    e("GetFileMUIPath", reinterpret_cast<void*>(&kkernel32G_GetFileMUIPath));
    e("GetFileSize", reinterpret_cast<void*>(&kkernel32G_GetFileSize));
    e("GetFinalPathNameByHandleA", reinterpret_cast<void*>(&kkernel32G_GetFinalPathNameByHandleA));
    e("GetFinalPathNameByHandleW", reinterpret_cast<void*>(&kkernel32G_GetFinalPathNameByHandleW));
    e("GetFirmwareEnvironmentVariableExA", reinterpret_cast<void*>(&kkernel32G_GetFirmwareEnvironmentVariableExA));
    e("GetFirmwareEnvironmentVariableExW", reinterpret_cast<void*>(&kkernel32G_GetFirmwareEnvironmentVariableExW));
    e("GetFirmwareType", reinterpret_cast<void*>(&kkernel32G_GetFirmwareType));
    e("GetFullPathNameTransactedA", reinterpret_cast<void*>(&kkernel32G_GetFullPathNameTransactedA));
    e("GetFullPathNameTransactedW", reinterpret_cast<void*>(&kkernel32G_GetFullPathNameTransactedW));
    e("GetGeoInfoA", reinterpret_cast<void*>(&kkernel32G_GetGeoInfoA));
    e("GetGeoInfoW", reinterpret_cast<void*>(&kkernel32G_GetGeoInfoW));
    e("GetLocaleInfoEx", reinterpret_cast<void*>(&kkernel32G_GetLocaleInfoEx));
    e("GetLogicalDrives", reinterpret_cast<void*>(&kkernel32G_GetLogicalDrives));
    e("GetLongPathNameTransactedA", reinterpret_cast<void*>(&kkernel32G_GetLongPathNameTransactedA));
    e("GetLongPathNameTransactedW", reinterpret_cast<void*>(&kkernel32G_GetLongPathNameTransactedW));
    e("GetMailslotInfo", reinterpret_cast<void*>(&kkernel32G_GetMailslotInfo));
    e("GetMaximumProcessorCount", reinterpret_cast<void*>(&kkernel32G_GetMaximumProcessorCount));
    e("GetMaximumProcessorGroupCount", reinterpret_cast<void*>(&kkernel32G_GetMaximumProcessorGroupCount));
    e("GetMemoryErrorHandlingCapabilities", reinterpret_cast<void*>(&kkernel32G_GetMemoryErrorHandlingCapabilities));
    e("GetNLSVersion", reinterpret_cast<void*>(&kkernel32G_GetNLSVersion));
    e("GetNLSVersionEx", reinterpret_cast<void*>(&kkernel32G_GetNLSVersionEx));
    e("GetNamedPipeClientComputerNameA", reinterpret_cast<void*>(&kkernel32G_GetNamedPipeClientComputerNameA));
    e("GetNamedPipeClientComputerNameW", reinterpret_cast<void*>(&kkernel32G_GetNamedPipeClientComputerNameW));
    e("GetNamedPipeClientProcessId", reinterpret_cast<void*>(&kkernel32G_GetNamedPipeClientProcessId));
    e("GetNamedPipeClientSessionId", reinterpret_cast<void*>(&kkernel32G_GetNamedPipeClientSessionId));
    e("GetNamedPipeHandleStateA", reinterpret_cast<void*>(&kkernel32G_GetNamedPipeHandleStateA));
    e("GetNamedPipeHandleStateW", reinterpret_cast<void*>(&kkernel32G_GetNamedPipeHandleStateW));
    e("GetNamedPipeInfo", reinterpret_cast<void*>(&kkernel32G_GetNamedPipeInfo));
    e("GetNamedPipeServerProcessId", reinterpret_cast<void*>(&kkernel32G_GetNamedPipeServerProcessId));
    e("GetNamedPipeServerSessionId", reinterpret_cast<void*>(&kkernel32G_GetNamedPipeServerSessionId));
    e("GetNextUmsListItem", reinterpret_cast<void*>(&kkernel32G_GetNextUmsListItem));
    e("GetNumaAvailableMemoryNode", reinterpret_cast<void*>(&kkernel32G_GetNumaAvailableMemoryNode));
    e("GetNumaAvailableMemoryNodeEx", reinterpret_cast<void*>(&kkernel32G_GetNumaAvailableMemoryNodeEx));
    e("GetNumaNodeNumberFromHandle", reinterpret_cast<void*>(&kkernel32G_GetNumaNodeNumberFromHandle));
    e("GetNumaNodeProcessorMask", reinterpret_cast<void*>(&kkernel32G_GetNumaNodeProcessorMask));
    e("GetNumaNodeProcessorMaskEx", reinterpret_cast<void*>(&kkernel32G_GetNumaNodeProcessorMaskEx));
    e("GetNumaProcessorNode", reinterpret_cast<void*>(&kkernel32G_GetNumaProcessorNode));
    e("GetNumaProcessorNodeEx", reinterpret_cast<void*>(&kkernel32G_GetNumaProcessorNodeEx));
    e("GetNumaProximityNode", reinterpret_cast<void*>(&kkernel32G_GetNumaProximityNode));
    e("GetNumaProximityNodeEx", reinterpret_cast<void*>(&kkernel32G_GetNumaProximityNodeEx));
    e("GetNumberFormatA", reinterpret_cast<void*>(&kkernel32G_GetNumberFormatA));
    e("GetNumberFormatEx", reinterpret_cast<void*>(&kkernel32G_GetNumberFormatEx));
    e("GetNumberFormatW", reinterpret_cast<void*>(&kkernel32G_GetNumberFormatW));
    e("GetNumberOfConsoleMouseButtons", reinterpret_cast<void*>(&kkernel32G_GetNumberOfConsoleMouseButtons));
    e("GetOverlappedResultEx", reinterpret_cast<void*>(&kkernel32G_GetOverlappedResultEx));
    e("GetPhysicallyInstalledSystemMemory", reinterpret_cast<void*>(&kkernel32G_GetPhysicallyInstalledSystemMemory));
    e("GetPrivateProfileIntA", reinterpret_cast<void*>(&kkernel32G_GetPrivateProfileIntA));
    e("GetPrivateProfileIntW", reinterpret_cast<void*>(&kkernel32G_GetPrivateProfileIntW));
    e("GetPrivateProfileSectionA", reinterpret_cast<void*>(&kkernel32G_GetPrivateProfileSectionA));
    e("GetPrivateProfileSectionNamesA", reinterpret_cast<void*>(&kkernel32G_GetPrivateProfileSectionNamesA));
    e("GetPrivateProfileSectionNamesW", reinterpret_cast<void*>(&kkernel32G_GetPrivateProfileSectionNamesW));
    e("GetPrivateProfileSectionW", reinterpret_cast<void*>(&kkernel32G_GetPrivateProfileSectionW));
    e("GetPrivateProfileStringA", reinterpret_cast<void*>(&kkernel32G_GetPrivateProfileStringA));
    e("GetPrivateProfileStringW", reinterpret_cast<void*>(&kkernel32G_GetPrivateProfileStringW));
    e("GetPrivateProfileStructA", reinterpret_cast<void*>(&kkernel32G_GetPrivateProfileStructA));
    e("GetPrivateProfileStructW", reinterpret_cast<void*>(&kkernel32G_GetPrivateProfileStructW));
    e("GetProcessHandleCount", reinterpret_cast<void*>(&kkernel32G_GetProcessHandleCount));
    e("GetProcessInformation", reinterpret_cast<void*>(&kkernel32G_GetProcessInformation));
    e("GetProcessPreferredUILanguages", reinterpret_cast<void*>(&kkernel32G_GetProcessPreferredUILanguages));
    e("GetProcessWorkingSetSizeEx", reinterpret_cast<void*>(&kkernel32G_GetProcessWorkingSetSizeEx));
    e("GetProcessorSystemCycleTime", reinterpret_cast<void*>(&kkernel32G_GetProcessorSystemCycleTime));
    e("GetProfileIntA", reinterpret_cast<void*>(&kkernel32G_GetProfileIntA));
    e("GetProfileIntW", reinterpret_cast<void*>(&kkernel32G_GetProfileIntW));
    e("GetProfileSectionA", reinterpret_cast<void*>(&kkernel32G_GetProfileSectionA));
    e("GetProfileSectionW", reinterpret_cast<void*>(&kkernel32G_GetProfileSectionW));
    e("GetProfileStringA", reinterpret_cast<void*>(&kkernel32G_GetProfileStringA));
    e("GetProfileStringW", reinterpret_cast<void*>(&kkernel32G_GetProfileStringW));
    e("GetStringScripts", reinterpret_cast<void*>(&kkernel32G_GetStringScripts));
    e("GetSystemDEPPolicy", reinterpret_cast<void*>(&kkernel32G_GetSystemDEPPolicy));
    e("GetSystemDefaultUILanguage", reinterpret_cast<void*>(&kkernel32G_GetSystemDefaultUILanguage));
    e("GetSystemFileCacheSize", reinterpret_cast<void*>(&kkernel32G_GetSystemFileCacheSize));
    e("GetSystemPowerStatus", reinterpret_cast<void*>(&kkernel32G_GetSystemPowerStatus));
    e("GetSystemPreferredUILanguages", reinterpret_cast<void*>(&kkernel32G_GetSystemPreferredUILanguages));
    e("GetSystemRegistryQuota", reinterpret_cast<void*>(&kkernel32G_GetSystemRegistryQuota));
    e("GetSystemWindowsDirectoryA", reinterpret_cast<void*>(&kkernel32G_GetSystemWindowsDirectoryA));
    e("GetSystemWindowsDirectoryW", reinterpret_cast<void*>(&kkernel32G_GetSystemWindowsDirectoryW));
    e("GetTapeParameters", reinterpret_cast<void*>(&kkernel32G_GetTapeParameters));
    e("GetTapePosition", reinterpret_cast<void*>(&kkernel32G_GetTapePosition));
    e("GetTapeStatus", reinterpret_cast<void*>(&kkernel32G_GetTapeStatus));
    e("GetThreadErrorMode", reinterpret_cast<void*>(&kkernel32G_GetThreadErrorMode));
    e("GetThreadGroupAffinity", reinterpret_cast<void*>(&kkernel32G_GetThreadGroupAffinity));
    e("GetThreadIOPendingFlag", reinterpret_cast<void*>(&kkernel32G_GetThreadIOPendingFlag));
    e("GetThreadInformation", reinterpret_cast<void*>(&kkernel32G_GetThreadInformation));
    e("GetThreadLocale", reinterpret_cast<void*>(&kkernel32G_GetThreadLocale));
    e("GetThreadPreferredUILanguages", reinterpret_cast<void*>(&kkernel32G_GetThreadPreferredUILanguages));
    e("GetThreadPriorityBoost", reinterpret_cast<void*>(&kkernel32G_GetThreadPriorityBoost));
    e("GetThreadSelectorEntry", reinterpret_cast<void*>(&kkernel32G_GetThreadSelectorEntry));
    e("GetThreadUILanguage", reinterpret_cast<void*>(&kkernel32G_GetThreadUILanguage));
    e("GetTimeFormatA", reinterpret_cast<void*>(&kkernel32G_GetTimeFormatA));
    e("GetTimeFormatEx", reinterpret_cast<void*>(&kkernel32G_GetTimeFormatEx));
    e("GetTimeFormatW", reinterpret_cast<void*>(&kkernel32G_GetTimeFormatW));
    e("GetTimeZoneInformationForYear", reinterpret_cast<void*>(&kkernel32G_GetTimeZoneInformationForYear));
    e("GetUILanguageInfo", reinterpret_cast<void*>(&kkernel32G_GetUILanguageInfo));
    e("GetUmsSystemThreadInformation", reinterpret_cast<void*>(&kkernel32G_GetUmsSystemThreadInformation));
    e("GetUserDefaultGeoName", reinterpret_cast<void*>(&kkernel32G_GetUserDefaultGeoName));
    e("GetUserDefaultUILanguage", reinterpret_cast<void*>(&kkernel32G_GetUserDefaultUILanguage));
    e("GetUserGeoID", reinterpret_cast<void*>(&kkernel32G_GetUserGeoID));
    e("GetVersion", reinterpret_cast<void*>(&kkernel32G_GetVersion));
    e("GetVolumeInformationByHandleW", reinterpret_cast<void*>(&kkernel32G_GetVolumeInformationByHandleW));
    e("GetVolumeNameForVolumeMountPointA", reinterpret_cast<void*>(&kkernel32G_GetVolumeNameForVolumeMountPointA));
    e("GetVolumeNameForVolumeMountPointW", reinterpret_cast<void*>(&kkernel32G_GetVolumeNameForVolumeMountPointW));
    e("GetVolumePathNamesForVolumeNameA", reinterpret_cast<void*>(&kkernel32G_GetVolumePathNamesForVolumeNameA));
    e("GetVolumePathNamesForVolumeNameW", reinterpret_cast<void*>(&kkernel32G_GetVolumePathNamesForVolumeNameW));
    e("GetWriteWatch", reinterpret_cast<void*>(&kkernel32G_GetWriteWatch));
    e("GetXStateFeaturesMask", reinterpret_cast<void*>(&kkernel32G_GetXStateFeaturesMask));
    e("GlobalAddAtomA", reinterpret_cast<void*>(&kkernel32G_GlobalAddAtomA));
    e("GlobalAddAtomExA", reinterpret_cast<void*>(&kkernel32G_GlobalAddAtomExA));
    e("GlobalAddAtomExW", reinterpret_cast<void*>(&kkernel32G_GlobalAddAtomExW));
    e("GlobalAddAtomW", reinterpret_cast<void*>(&kkernel32G_GlobalAddAtomW));
    e("GlobalCompact", reinterpret_cast<void*>(&kkernel32G_GlobalCompact));
    e("GlobalDeleteAtom", reinterpret_cast<void*>(&kkernel32G_GlobalDeleteAtom));
    e("GlobalFindAtomA", reinterpret_cast<void*>(&kkernel32G_GlobalFindAtomA));
    e("GlobalFindAtomW", reinterpret_cast<void*>(&kkernel32G_GlobalFindAtomW));
    e("GlobalFix", reinterpret_cast<void*>(&kkernel32G_GlobalFix));
    e("GlobalGetAtomNameA", reinterpret_cast<void*>(&kkernel32G_GlobalGetAtomNameA));
    e("GlobalGetAtomNameW", reinterpret_cast<void*>(&kkernel32G_GlobalGetAtomNameW));
    e("GlobalMemoryStatus", reinterpret_cast<void*>(&kkernel32G_GlobalMemoryStatus));
    e("GlobalUnWire", reinterpret_cast<void*>(&kkernel32G_GlobalUnWire));
    e("GlobalUnfix", reinterpret_cast<void*>(&kkernel32G_GlobalUnfix));
    e("GlobalWire", reinterpret_cast<void*>(&kkernel32G_GlobalWire));
    e("HeapSummary", reinterpret_cast<void*>(&kkernel32G_HeapSummary));
    e("IdnToAscii", reinterpret_cast<void*>(&kkernel32G_IdnToAscii));
    e("IdnToNameprepUnicode", reinterpret_cast<void*>(&kkernel32G_IdnToNameprepUnicode));
    e("IdnToUnicode", reinterpret_cast<void*>(&kkernel32G_IdnToUnicode));
    e("InitAtomTable", reinterpret_cast<void*>(&kkernel32G_InitAtomTable));
    e("InitOnceBeginInitialize", reinterpret_cast<void*>(&kkernel32G_InitOnceBeginInitialize));
    e("InitOnceComplete", reinterpret_cast<void*>(&kkernel32G_InitOnceComplete));
    e("InitOnceInitialize", reinterpret_cast<void*>(&kkernel32G_InitOnceInitialize));
    e("InitializeProcThreadAttributeList", reinterpret_cast<void*>(&kkernel32G_InitializeProcThreadAttributeList));
    e("InitializeSRWLock", reinterpret_cast<void*>(&kkernel32G_InitializeSRWLock));
    e("InitializeSynchronizationBarrier", reinterpret_cast<void*>(&kkernel32G_InitializeSynchronizationBarrier));
    e("InterlockedBitTestAndComplement", reinterpret_cast<void*>(&kkernel32G_InterlockedBitTestAndComplement));
    e("InterlockedBitTestAndComplement64", reinterpret_cast<void*>(&kkernel32G_InterlockedBitTestAndComplement64));
    e("InterlockedBitTestAndReset", reinterpret_cast<void*>(&kkernel32G_InterlockedBitTestAndReset));
    e("InterlockedBitTestAndReset64", reinterpret_cast<void*>(&kkernel32G_InterlockedBitTestAndReset64));
    e("InterlockedBitTestAndSet", reinterpret_cast<void*>(&kkernel32G_InterlockedBitTestAndSet));
    e("InterlockedBitTestAndSet64", reinterpret_cast<void*>(&kkernel32G_InterlockedBitTestAndSet64));
    e("InterlockedFlushSList", reinterpret_cast<void*>(&kkernel32G_InterlockedFlushSList));
    e("InterlockedPopEntrySList", reinterpret_cast<void*>(&kkernel32G_InterlockedPopEntrySList));
    e("InterlockedPushEntrySList", reinterpret_cast<void*>(&kkernel32G_InterlockedPushEntrySList));
    e("InterlockedPushListSListEx", reinterpret_cast<void*>(&kkernel32G_InterlockedPushListSListEx));
    e("IsBadHugeReadPtr", reinterpret_cast<void*>(&kkernel32G_IsBadHugeReadPtr));
    e("IsBadHugeWritePtr", reinterpret_cast<void*>(&kkernel32G_IsBadHugeWritePtr));
    e("IsNLSDefinedString", reinterpret_cast<void*>(&kkernel32G_IsNLSDefinedString));
    e("IsNativeVhdBoot", reinterpret_cast<void*>(&kkernel32G_IsNativeVhdBoot));
    e("IsNormalizedString", reinterpret_cast<void*>(&kkernel32G_IsNormalizedString));
    e("IsSystemResumeAutomatic", reinterpret_cast<void*>(&kkernel32G_IsSystemResumeAutomatic));
    e("IsThreadAFiber", reinterpret_cast<void*>(&kkernel32G_IsThreadAFiber));
    e("IsValidLanguageGroup", reinterpret_cast<void*>(&kkernel32G_IsValidLanguageGroup));
    e("IsValidLocale", reinterpret_cast<void*>(&kkernel32G_IsValidLocale));
    e("IsValidLocaleName", reinterpret_cast<void*>(&kkernel32G_IsValidLocaleName));
    e("IsValidNLSVersion", reinterpret_cast<void*>(&kkernel32G_IsValidNLSVersion));
    e("IsWow64GuestMachineSupported", reinterpret_cast<void*>(&kkernel32G_IsWow64GuestMachineSupported));
    e("LCIDToLocaleName", reinterpret_cast<void*>(&kkernel32G_LCIDToLocaleName));
    e("LeaveCriticalSectionWhenCallbackReturns", reinterpret_cast<void*>(&kkernel32G_LeaveCriticalSectionWhenCallbackReturns));
    e("LoadModule", reinterpret_cast<void*>(&kkernel32G_LoadModule));
    e("LoadPackagedLibrary", reinterpret_cast<void*>(&kkernel32G_LoadPackagedLibrary));
    e("LoadResource", reinterpret_cast<void*>(&kkernel32G_LoadResource));
    e("LocalCompact", reinterpret_cast<void*>(&kkernel32G_LocalCompact));
    e("LocalShrink", reinterpret_cast<void*>(&kkernel32G_LocalShrink));
    e("LocaleNameToLCID", reinterpret_cast<void*>(&kkernel32G_LocaleNameToLCID));
    e("LocateXStateFeature", reinterpret_cast<void*>(&kkernel32G_LocateXStateFeature));
    e("LockResource", reinterpret_cast<void*>(&kkernel32G_LockResource));
    e("MapUserPhysicalPages", reinterpret_cast<void*>(&kkernel32G_MapUserPhysicalPages));
    e("MapUserPhysicalPagesScatter", reinterpret_cast<void*>(&kkernel32G_MapUserPhysicalPagesScatter));
    e("MapViewOfFileExNuma", reinterpret_cast<void*>(&kkernel32G_MapViewOfFileExNuma));
    e("MapViewOfFileFromApp", reinterpret_cast<void*>(&kkernel32G_MapViewOfFileFromApp));
    e("MoveFileTransactedA", reinterpret_cast<void*>(&kkernel32G_MoveFileTransactedA));
    e("MoveFileTransactedW", reinterpret_cast<void*>(&kkernel32G_MoveFileTransactedW));
    e("MoveFileWithProgressA", reinterpret_cast<void*>(&kkernel32G_MoveFileWithProgressA));
    e("MoveFileWithProgressW", reinterpret_cast<void*>(&kkernel32G_MoveFileWithProgressW));
    e("MulDiv", reinterpret_cast<void*>(&kkernel32G_MulDiv));
    e("MultiplyExtract128", reinterpret_cast<void*>(&kkernel32G_MultiplyExtract128));
    e("NeedCurrentDirectoryForExePathA", reinterpret_cast<void*>(&kkernel32G_NeedCurrentDirectoryForExePathA));
    e("NeedCurrentDirectoryForExePathW", reinterpret_cast<void*>(&kkernel32G_NeedCurrentDirectoryForExePathW));
    e("NormalizeString", reinterpret_cast<void*>(&kkernel32G_NormalizeString));
    e("NotifyUILanguageChange", reinterpret_cast<void*>(&kkernel32G_NotifyUILanguageChange));
    e("OfferVirtualMemory", reinterpret_cast<void*>(&kkernel32G_OfferVirtualMemory));
    e("OpenFile", reinterpret_cast<void*>(&kkernel32G_OpenFile));
    e("OpenFileById", reinterpret_cast<void*>(&kkernel32G_OpenFileById));
    e("OpenJobObjectA", reinterpret_cast<void*>(&kkernel32G_OpenJobObjectA));
    e("OpenJobObjectW", reinterpret_cast<void*>(&kkernel32G_OpenJobObjectW));
    e("OpenPrivateNamespaceA", reinterpret_cast<void*>(&kkernel32G_OpenPrivateNamespaceA));
    e("OpenPrivateNamespaceW", reinterpret_cast<void*>(&kkernel32G_OpenPrivateNamespaceW));
    e("PeekNamedPipe", reinterpret_cast<void*>(&kkernel32G_PeekNamedPipe));
    e("PowerClearRequest", reinterpret_cast<void*>(&kkernel32G_PowerClearRequest));
    e("PowerCreateRequest", reinterpret_cast<void*>(&kkernel32G_PowerCreateRequest));
    e("PowerSetRequest", reinterpret_cast<void*>(&kkernel32G_PowerSetRequest));
    e("PrefetchVirtualMemory", reinterpret_cast<void*>(&kkernel32G_PrefetchVirtualMemory));
    e("PrepareTape", reinterpret_cast<void*>(&kkernel32G_PrepareTape));
    e("PurgeComm", reinterpret_cast<void*>(&kkernel32G_PurgeComm));
    e("QueryActCtxSettingsW", reinterpret_cast<void*>(&kkernel32G_QueryActCtxSettingsW));
    e("QueryActCtxW", reinterpret_cast<void*>(&kkernel32G_QueryActCtxW));
    e("QueryDepthSList", reinterpret_cast<void*>(&kkernel32G_QueryDepthSList));
    e("QueryDosDeviceA", reinterpret_cast<void*>(&kkernel32G_QueryDosDeviceA));
    e("QueryDosDeviceW", reinterpret_cast<void*>(&kkernel32G_QueryDosDeviceW));
    e("QueryIdleProcessorCycleTimeEx", reinterpret_cast<void*>(&kkernel32G_QueryIdleProcessorCycleTimeEx));
    e("QueryMemoryResourceNotification", reinterpret_cast<void*>(&kkernel32G_QueryMemoryResourceNotification));
    e("QueryProcessCycleTime", reinterpret_cast<void*>(&kkernel32G_QueryProcessCycleTime));
    e("QueryThreadProfiling", reinterpret_cast<void*>(&kkernel32G_QueryThreadProfiling));
    e("QueryThreadpoolStackInformation", reinterpret_cast<void*>(&kkernel32G_QueryThreadpoolStackInformation));
    e("QueryUmsThreadInformation", reinterpret_cast<void*>(&kkernel32G_QueryUmsThreadInformation));
    e("QueryUnbiasedInterruptTime", reinterpret_cast<void*>(&kkernel32G_QueryUnbiasedInterruptTime));
    e("QueueUserWorkItem", reinterpret_cast<void*>(&kkernel32G_QueueUserWorkItem));
    e("ReOpenFile", reinterpret_cast<void*>(&kkernel32G_ReOpenFile));
    e("ReadDirectoryChangesW", reinterpret_cast<void*>(&kkernel32G_ReadDirectoryChangesW));
    e("ReadFileEx", reinterpret_cast<void*>(&kkernel32G_ReadFileEx));
    e("ReadFileScatter", reinterpret_cast<void*>(&kkernel32G_ReadFileScatter));
    e("ReadThreadProfilingData", reinterpret_cast<void*>(&kkernel32G_ReadThreadProfilingData));
    e("ReclaimVirtualMemory", reinterpret_cast<void*>(&kkernel32G_ReclaimVirtualMemory));
    e("RegisterApplicationRecoveryCallback", reinterpret_cast<void*>(&kkernel32G_RegisterApplicationRecoveryCallback));
    e("RegisterApplicationRestart", reinterpret_cast<void*>(&kkernel32G_RegisterApplicationRestart));
    e("RegisterBadMemoryNotification", reinterpret_cast<void*>(&kkernel32G_RegisterBadMemoryNotification));
    e("ReleaseActCtx", reinterpret_cast<void*>(&kkernel32G_ReleaseActCtx));
    e("RemoveDirectoryTransactedA", reinterpret_cast<void*>(&kkernel32G_RemoveDirectoryTransactedA));
    e("RemoveDirectoryTransactedW", reinterpret_cast<void*>(&kkernel32G_RemoveDirectoryTransactedW));
    e("RemoveDllDirectory", reinterpret_cast<void*>(&kkernel32G_RemoveDllDirectory));
    e("RemoveSecureMemoryCacheCallback", reinterpret_cast<void*>(&kkernel32G_RemoveSecureMemoryCacheCallback));
    e("RemoveVectoredContinueHandler", reinterpret_cast<void*>(&kkernel32G_RemoveVectoredContinueHandler));
    e("ReplaceFileA", reinterpret_cast<void*>(&kkernel32G_ReplaceFileA));
    e("ReplaceFileW", reinterpret_cast<void*>(&kkernel32G_ReplaceFileW));
    e("ReplacePartitionUnit", reinterpret_cast<void*>(&kkernel32G_ReplacePartitionUnit));
    e("RequestDeviceWakeup", reinterpret_cast<void*>(&kkernel32G_RequestDeviceWakeup));
    e("RequestWakeupLatency", reinterpret_cast<void*>(&kkernel32G_RequestWakeupLatency));
    e("ResetWriteWatch", reinterpret_cast<void*>(&kkernel32G_ResetWriteWatch));
    e("ResolveLocaleName", reinterpret_cast<void*>(&kkernel32G_ResolveLocaleName));
    e("RtlSecureZeroMemory", reinterpret_cast<void*>(&kkernel32G_RtlSecureZeroMemory));
    e("SetCachedSigningLevel", reinterpret_cast<void*>(&kkernel32G_SetCachedSigningLevel));
    e("SetCalendarInfoA", reinterpret_cast<void*>(&kkernel32G_SetCalendarInfoA));
    e("SetCalendarInfoW", reinterpret_cast<void*>(&kkernel32G_SetCalendarInfoW));
    e("SetCommBreak", reinterpret_cast<void*>(&kkernel32G_SetCommBreak));
    e("SetCommConfig", reinterpret_cast<void*>(&kkernel32G_SetCommConfig));
    e("SetCommMask", reinterpret_cast<void*>(&kkernel32G_SetCommMask));
    e("SetCommState", reinterpret_cast<void*>(&kkernel32G_SetCommState));
    e("SetCommTimeouts", reinterpret_cast<void*>(&kkernel32G_SetCommTimeouts));
    e("SetComputerNameA", reinterpret_cast<void*>(&kkernel32G_SetComputerNameA));
    e("SetComputerNameExA", reinterpret_cast<void*>(&kkernel32G_SetComputerNameExA));
    e("SetComputerNameExW", reinterpret_cast<void*>(&kkernel32G_SetComputerNameExW));
    e("SetComputerNameW", reinterpret_cast<void*>(&kkernel32G_SetComputerNameW));
    e("SetConsoleDisplayMode", reinterpret_cast<void*>(&kkernel32G_SetConsoleDisplayMode));
    e("SetConsoleHistoryInfo", reinterpret_cast<void*>(&kkernel32G_SetConsoleHistoryInfo));
    e("SetConsoleNumberOfCommandsA", reinterpret_cast<void*>(&kkernel32G_SetConsoleNumberOfCommandsA));
    e("SetConsoleNumberOfCommandsW", reinterpret_cast<void*>(&kkernel32G_SetConsoleNumberOfCommandsW));
    e("SetConsoleScreenBufferInfoEx", reinterpret_cast<void*>(&kkernel32G_SetConsoleScreenBufferInfoEx));
    e("SetConsoleScreenBufferSize", reinterpret_cast<void*>(&kkernel32G_SetConsoleScreenBufferSize));
    e("SetConsoleWindowInfo", reinterpret_cast<void*>(&kkernel32G_SetConsoleWindowInfo));
    e("SetCriticalSectionSpinCount", reinterpret_cast<void*>(&kkernel32G_SetCriticalSectionSpinCount));
    e("SetCurrentConsoleFontEx", reinterpret_cast<void*>(&kkernel32G_SetCurrentConsoleFontEx));
    e("SetDefaultCommConfigA", reinterpret_cast<void*>(&kkernel32G_SetDefaultCommConfigA));
    e("SetDefaultCommConfigW", reinterpret_cast<void*>(&kkernel32G_SetDefaultCommConfigW));
    e("SetDefaultDllDirectories", reinterpret_cast<void*>(&kkernel32G_SetDefaultDllDirectories));
    e("SetDllDirectoryA", reinterpret_cast<void*>(&kkernel32G_SetDllDirectoryA));
    e("SetDllDirectoryW", reinterpret_cast<void*>(&kkernel32G_SetDllDirectoryW));
    e("SetDynamicTimeZoneInformation", reinterpret_cast<void*>(&kkernel32G_SetDynamicTimeZoneInformation));
    e("SetEnvironmentStringsA", reinterpret_cast<void*>(&kkernel32G_SetEnvironmentStringsA));
    e("SetEnvironmentStringsW", reinterpret_cast<void*>(&kkernel32G_SetEnvironmentStringsW));
    e("SetFileApisToANSI", reinterpret_cast<void*>(&kkernel32G_SetFileApisToANSI));
    e("SetFileApisToOEM", reinterpret_cast<void*>(&kkernel32G_SetFileApisToOEM));
    e("SetFileAttributesTransactedA", reinterpret_cast<void*>(&kkernel32G_SetFileAttributesTransactedA));
    e("SetFileAttributesTransactedW", reinterpret_cast<void*>(&kkernel32G_SetFileAttributesTransactedW));
    e("SetFileBandwidthReservation", reinterpret_cast<void*>(&kkernel32G_SetFileBandwidthReservation));
    e("SetFileCompletionNotificationModes", reinterpret_cast<void*>(&kkernel32G_SetFileCompletionNotificationModes));
    e("SetFileIoOverlappedRange", reinterpret_cast<void*>(&kkernel32G_SetFileIoOverlappedRange));
    e("SetFileShortNameA", reinterpret_cast<void*>(&kkernel32G_SetFileShortNameA));
    e("SetFileShortNameW", reinterpret_cast<void*>(&kkernel32G_SetFileShortNameW));
    e("SetFileValidData", reinterpret_cast<void*>(&kkernel32G_SetFileValidData));
    e("SetFirmwareEnvironmentVariableA", reinterpret_cast<void*>(&kkernel32G_SetFirmwareEnvironmentVariableA));
    e("SetFirmwareEnvironmentVariableExA", reinterpret_cast<void*>(&kkernel32G_SetFirmwareEnvironmentVariableExA));
    e("SetFirmwareEnvironmentVariableExW", reinterpret_cast<void*>(&kkernel32G_SetFirmwareEnvironmentVariableExW));
    e("SetFirmwareEnvironmentVariableW", reinterpret_cast<void*>(&kkernel32G_SetFirmwareEnvironmentVariableW));
    e("SetHandleCount", reinterpret_cast<void*>(&kkernel32G_SetHandleCount));
    e("SetInformationJobObject", reinterpret_cast<void*>(&kkernel32G_SetInformationJobObject));
    e("SetLocaleInfoA", reinterpret_cast<void*>(&kkernel32G_SetLocaleInfoA));
    e("SetLocaleInfoW", reinterpret_cast<void*>(&kkernel32G_SetLocaleInfoW));
    e("SetMailslotInfo", reinterpret_cast<void*>(&kkernel32G_SetMailslotInfo));
    e("SetNamedPipeHandleState", reinterpret_cast<void*>(&kkernel32G_SetNamedPipeHandleState));
    e("SetProcessInformation", reinterpret_cast<void*>(&kkernel32G_SetProcessInformation));
    e("SetProcessPreferredUILanguages", reinterpret_cast<void*>(&kkernel32G_SetProcessPreferredUILanguages));
    e("SetProcessWorkingSetSizeEx", reinterpret_cast<void*>(&kkernel32G_SetProcessWorkingSetSizeEx));
    e("SetSearchPathMode", reinterpret_cast<void*>(&kkernel32G_SetSearchPathMode));
    e("SetStdHandleEx", reinterpret_cast<void*>(&kkernel32G_SetStdHandleEx));
    e("SetSystemFileCacheSize", reinterpret_cast<void*>(&kkernel32G_SetSystemFileCacheSize));
    e("SetSystemPowerState", reinterpret_cast<void*>(&kkernel32G_SetSystemPowerState));
    e("SetSystemTimeAdjustment", reinterpret_cast<void*>(&kkernel32G_SetSystemTimeAdjustment));
    e("SetTapeParameters", reinterpret_cast<void*>(&kkernel32G_SetTapeParameters));
    e("SetTapePosition", reinterpret_cast<void*>(&kkernel32G_SetTapePosition));
    e("SetThreadExecutionState", reinterpret_cast<void*>(&kkernel32G_SetThreadExecutionState));
    e("SetThreadGroupAffinity", reinterpret_cast<void*>(&kkernel32G_SetThreadGroupAffinity));
    e("SetThreadIdealProcessor", reinterpret_cast<void*>(&kkernel32G_SetThreadIdealProcessor));
    e("SetThreadInformation", reinterpret_cast<void*>(&kkernel32G_SetThreadInformation));
    e("SetThreadLocale", reinterpret_cast<void*>(&kkernel32G_SetThreadLocale));
    e("SetThreadPreferredUILanguages", reinterpret_cast<void*>(&kkernel32G_SetThreadPreferredUILanguages));
    e("SetThreadPriorityBoost", reinterpret_cast<void*>(&kkernel32G_SetThreadPriorityBoost));
    e("SetThreadStackGuarantee", reinterpret_cast<void*>(&kkernel32G_SetThreadStackGuarantee));
    e("SetThreadUILanguage", reinterpret_cast<void*>(&kkernel32G_SetThreadUILanguage));
    e("SetThreadpoolStackInformation", reinterpret_cast<void*>(&kkernel32G_SetThreadpoolStackInformation));
    e("SetThreadpoolThreadMaximum", reinterpret_cast<void*>(&kkernel32G_SetThreadpoolThreadMaximum));
    e("SetThreadpoolThreadMinimum", reinterpret_cast<void*>(&kkernel32G_SetThreadpoolThreadMinimum));
    e("SetThreadpoolWaitEx", reinterpret_cast<void*>(&kkernel32G_SetThreadpoolWaitEx));
    e("SetUmsThreadInformation", reinterpret_cast<void*>(&kkernel32G_SetUmsThreadInformation));
    e("SetUserGeoID", reinterpret_cast<void*>(&kkernel32G_SetUserGeoID));
    e("SetVolumeLabelA", reinterpret_cast<void*>(&kkernel32G_SetVolumeLabelA));
    e("SetVolumeLabelW", reinterpret_cast<void*>(&kkernel32G_SetVolumeLabelW));
    e("SetVolumeMountPointA", reinterpret_cast<void*>(&kkernel32G_SetVolumeMountPointA));
    e("SetVolumeMountPointW", reinterpret_cast<void*>(&kkernel32G_SetVolumeMountPointW));
    e("SetupComm", reinterpret_cast<void*>(&kkernel32G_SetupComm));
    e("SizeofResource", reinterpret_cast<void*>(&kkernel32G_SizeofResource));
    e("SubmitThreadpoolWork", reinterpret_cast<void*>(&kkernel32G_SubmitThreadpoolWork));
    e("SwitchToFiber", reinterpret_cast<void*>(&kkernel32G_SwitchToFiber));
    e("SystemTimeToTzSpecificLocalTimeEx", reinterpret_cast<void*>(&kkernel32G_SystemTimeToTzSpecificLocalTimeEx));
    e("TerminateJobObject", reinterpret_cast<void*>(&kkernel32G_TerminateJobObject));
    e("TransactNamedPipe", reinterpret_cast<void*>(&kkernel32G_TransactNamedPipe));
    e("TransmitCommChar", reinterpret_cast<void*>(&kkernel32G_TransmitCommChar));
    e("TryAcquireSRWLockShared", reinterpret_cast<void*>(&kkernel32G_TryAcquireSRWLockShared));
    e("TrySubmitThreadpoolCallback", reinterpret_cast<void*>(&kkernel32G_TrySubmitThreadpoolCallback));
    e("TzSpecificLocalTimeToSystemTimeEx", reinterpret_cast<void*>(&kkernel32G_TzSpecificLocalTimeToSystemTimeEx));
    e("UmsThreadYield", reinterpret_cast<void*>(&kkernel32G_UmsThreadYield));
    e("UnmapViewOfFileEx", reinterpret_cast<void*>(&kkernel32G_UnmapViewOfFileEx));
    e("UnregisterApplicationRecoveryCallback", reinterpret_cast<void*>(&kkernel32G_UnregisterApplicationRecoveryCallback));
    e("UnregisterApplicationRestart", reinterpret_cast<void*>(&kkernel32G_UnregisterApplicationRestart));
    e("UnregisterBadMemoryNotification", reinterpret_cast<void*>(&kkernel32G_UnregisterBadMemoryNotification));
    e("UnsignedMultiplyExtract128", reinterpret_cast<void*>(&kkernel32G_UnsignedMultiplyExtract128));
    e("UpdateProcThreadAttribute", reinterpret_cast<void*>(&kkernel32G_UpdateProcThreadAttribute));
    e("UpdateResourceA", reinterpret_cast<void*>(&kkernel32G_UpdateResourceA));
    e("UpdateResourceW", reinterpret_cast<void*>(&kkernel32G_UpdateResourceW));
    e("VerSetConditionMask", reinterpret_cast<void*>(&kkernel32G_VerSetConditionMask));
    e("VerifyScripts", reinterpret_cast<void*>(&kkernel32G_VerifyScripts));
    e("VerifyVersionInfoA", reinterpret_cast<void*>(&kkernel32G_VerifyVersionInfoA));
    e("VerifyVersionInfoW", reinterpret_cast<void*>(&kkernel32G_VerifyVersionInfoW));
    e("WTSGetActiveConsoleSessionId", reinterpret_cast<void*>(&kkernel32G_WTSGetActiveConsoleSessionId));
    e("Wow64DisableWow64FsRedirection", reinterpret_cast<void*>(&kkernel32G_Wow64DisableWow64FsRedirection));
    e("Wow64EnableWow64FsRedirection", reinterpret_cast<void*>(&kkernel32G_Wow64EnableWow64FsRedirection));
    e("Wow64GetThreadSelectorEntry", reinterpret_cast<void*>(&kkernel32G_Wow64GetThreadSelectorEntry));
    e("Wow64RevertWow64FsRedirection", reinterpret_cast<void*>(&kkernel32G_Wow64RevertWow64FsRedirection));
    e("Wow64SuspendThread", reinterpret_cast<void*>(&kkernel32G_Wow64SuspendThread));
    e("WriteConsoleInputA", reinterpret_cast<void*>(&kkernel32G_WriteConsoleInputA));
    e("WriteConsoleInputW", reinterpret_cast<void*>(&kkernel32G_WriteConsoleInputW));
    e("WriteFileEx", reinterpret_cast<void*>(&kkernel32G_WriteFileEx));
    e("WriteFileGather", reinterpret_cast<void*>(&kkernel32G_WriteFileGather));
    e("WritePrivateProfileSectionA", reinterpret_cast<void*>(&kkernel32G_WritePrivateProfileSectionA));
    e("WritePrivateProfileSectionW", reinterpret_cast<void*>(&kkernel32G_WritePrivateProfileSectionW));
    e("WritePrivateProfileStringA", reinterpret_cast<void*>(&kkernel32G_WritePrivateProfileStringA));
    e("WritePrivateProfileStringW", reinterpret_cast<void*>(&kkernel32G_WritePrivateProfileStringW));
    e("WritePrivateProfileStructA", reinterpret_cast<void*>(&kkernel32G_WritePrivateProfileStructA));
    e("WritePrivateProfileStructW", reinterpret_cast<void*>(&kkernel32G_WritePrivateProfileStructW));
    e("WriteProfileSectionA", reinterpret_cast<void*>(&kkernel32G_WriteProfileSectionA));
    e("WriteProfileSectionW", reinterpret_cast<void*>(&kkernel32G_WriteProfileSectionW));
    e("WriteProfileStringA", reinterpret_cast<void*>(&kkernel32G_WriteProfileStringA));
    e("WriteProfileStringW", reinterpret_cast<void*>(&kkernel32G_WriteProfileStringW));
    e("WriteTapemark", reinterpret_cast<void*>(&kkernel32G_WriteTapemark));
    e("ZombifyActCtx", reinterpret_cast<void*>(&kkernel32G_ZombifyActCtx));
    e("_BitScanForward", reinterpret_cast<void*>(&kkernel32G_BitScanForward));
    e("_BitScanForward64", reinterpret_cast<void*>(&kkernel32G_BitScanForward64));
    e("_BitScanReverse", reinterpret_cast<void*>(&kkernel32G_BitScanReverse));
    e("_BitScanReverse64", reinterpret_cast<void*>(&kkernel32G_BitScanReverse64));
    e("_InterlockedAdd", reinterpret_cast<void*>(&kkernel32G_InterlockedAdd));
    e("_InterlockedAdd64", reinterpret_cast<void*>(&kkernel32G_InterlockedAdd64));
    e("_InterlockedAnd", reinterpret_cast<void*>(&kkernel32G_InterlockedAnd));
    e("_InterlockedAnd64", reinterpret_cast<void*>(&kkernel32G_InterlockedAnd64));
    e("_InterlockedCompareExchange", reinterpret_cast<void*>(&kkernel32G_InterlockedCompareExchange));
    e("_InterlockedCompareExchange16", reinterpret_cast<void*>(&kkernel32G_InterlockedCompareExchange16));
    e("_InterlockedCompareExchange64", reinterpret_cast<void*>(&kkernel32G_InterlockedCompareExchange64));
    e("_InterlockedCompareExchangePointer", reinterpret_cast<void*>(&kkernel32G_InterlockedCompareExchangePointer));
    e("_InterlockedDecrement", reinterpret_cast<void*>(&kkernel32G_InterlockedDecrement));
    e("_InterlockedDecrement16", reinterpret_cast<void*>(&kkernel32G_InterlockedDecrement16));
    e("_InterlockedDecrement64", reinterpret_cast<void*>(&kkernel32G_InterlockedDecrement64));
    e("_InterlockedExchange", reinterpret_cast<void*>(&kkernel32G_InterlockedExchange));
    e("_InterlockedExchange64", reinterpret_cast<void*>(&kkernel32G_InterlockedExchange64));
    e("_InterlockedExchangeAdd", reinterpret_cast<void*>(&kkernel32G_InterlockedExchangeAdd));
    e("_InterlockedExchangeAdd64", reinterpret_cast<void*>(&kkernel32G_InterlockedExchangeAdd64));
    e("_InterlockedExchangePointer", reinterpret_cast<void*>(&kkernel32G_InterlockedExchangePointer));
    e("_InterlockedIncrement", reinterpret_cast<void*>(&kkernel32G_InterlockedIncrement));
    e("_InterlockedIncrement16", reinterpret_cast<void*>(&kkernel32G_InterlockedIncrement16));
    e("_InterlockedIncrement64", reinterpret_cast<void*>(&kkernel32G_InterlockedIncrement64));
    e("_InterlockedOr", reinterpret_cast<void*>(&kkernel32G_InterlockedOr));
    e("_InterlockedOr64", reinterpret_cast<void*>(&kkernel32G_InterlockedOr64));
    e("_InterlockedXor", reinterpret_cast<void*>(&kkernel32G_InterlockedXor));
    e("_InterlockedXor64", reinterpret_cast<void*>(&kkernel32G_InterlockedXor64));
    e("_bittest", reinterpret_cast<void*>(&kkernel32G_bittest));
    e("_bittest64", reinterpret_cast<void*>(&kkernel32G_bittest64));
    e("_bittestandcomplement", reinterpret_cast<void*>(&kkernel32G_bittestandcomplement));
    e("_bittestandcomplement64", reinterpret_cast<void*>(&kkernel32G_bittestandcomplement64));
    e("_bittestandreset", reinterpret_cast<void*>(&kkernel32G_bittestandreset));
    e("_bittestandreset64", reinterpret_cast<void*>(&kkernel32G_bittestandreset64));
    e("_bittestandset", reinterpret_cast<void*>(&kkernel32G_bittestandset));
    e("_bittestandset64", reinterpret_cast<void*>(&kkernel32G_bittestandset64));
    e("_hread", reinterpret_cast<void*>(&kkernel32G_hread));
    e("_hwrite", reinterpret_cast<void*>(&kkernel32G_hwrite));
    e("_interlockedbittestandcomplement", reinterpret_cast<void*>(&kkernel32G_interlockedbittestandcomplement));
    e("_interlockedbittestandcomplement64", reinterpret_cast<void*>(&kkernel32G_interlockedbittestandcomplement64));
    e("_interlockedbittestandreset", reinterpret_cast<void*>(&kkernel32G_interlockedbittestandreset));
    e("_interlockedbittestandreset64", reinterpret_cast<void*>(&kkernel32G_interlockedbittestandreset64));
    e("_interlockedbittestandset", reinterpret_cast<void*>(&kkernel32G_interlockedbittestandset));
    e("_interlockedbittestandset64", reinterpret_cast<void*>(&kkernel32G_interlockedbittestandset64));
    e("_lclose", reinterpret_cast<void*>(&kkernel32G_lclose));
    e("_lcreat", reinterpret_cast<void*>(&kkernel32G_lcreat));
    e("_llseek", reinterpret_cast<void*>(&kkernel32G_llseek));
    e("_lopen", reinterpret_cast<void*>(&kkernel32G_lopen));
    e("_lread", reinterpret_cast<void*>(&kkernel32G_lread));
    e("_lwrite", reinterpret_cast<void*>(&kkernel32G_lwrite));
    e("_mul128", reinterpret_cast<void*>(&kkernel32G_mul128));
    e("_umul128", reinterpret_cast<void*>(&kkernel32G_umul128));
}
}  // namespace occ::runtime::winabi

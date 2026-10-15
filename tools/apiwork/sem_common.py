"""The helpers the generated domains share.

A helper here is a function that has no meaning on its own -- a character
test, a bounded copy, a case fold -- and that every rule would otherwise
write out again. They are templates where a template will do, because a
template that is never instantiated is not a function the compiler has to
warn about, and `[[maybe_unused]]` where it will not.

Nothing here decides anything a caller could observe. The decisions stay in
the rule that made the call, which is where the comment explaining it is.
"""

COMMON = '''
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
    return c == static_cast<C>(' ') || c == static_cast<C>('\\t') ||
           c == static_cast<C>('\\n') || c == static_cast<C>('\\r') ||
           c == static_cast<C>('\\v') || c == static_cast<C>('\\f');
}

template <typename C>
[[nodiscard]] constexpr bool ch_hex(C c) noexcept {
    return ch_digit(c) || (c >= static_cast<C>('a') && c <= static_cast<C>('f')) ||
           (c >= static_cast<C>('A') && c <= static_cast<C>('F'));
}

template <typename C>
[[nodiscard]] constexpr bool ch_sep(C c) noexcept {
    return c == static_cast<C>('\\\\') || c == static_cast<C>('/');
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
        while (at + 1 < capacity && source[at] != '\\0') {
            out[at] = static_cast<char16_t>(
                static_cast<unsigned char>(source[at]));
            ++at;
        }
    }
    out[at] = u'\\0';
    return at;
}

[[maybe_unused]] std::size_t narrow_text(const char16_t* source, char* out,
                                         std::size_t capacity) noexcept {
    if (out == nullptr || capacity == 0) {
        return 0;
    }
    std::size_t at = 0;
    if (source != nullptr) {
        while (at + 1 < capacity && source[at] != u'\\0') {
            const char16_t ch = source[at];
            out[at] = ch < 0x100 ? static_cast<char>(ch) : '?';
            ++at;
        }
    }
    out[at] = '\\0';
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
'''

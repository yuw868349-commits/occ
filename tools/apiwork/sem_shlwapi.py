"""shlwapi: the path grammar, the bounded string helpers and the formatters.

The reference for everything below is wine's own implementation of the same
entry points -- `dlls/kernelbase/path.c`, `dlls/shlwapi/path.c` and
`dlls/shlwapi/string.c` -- which is the implementation this project already
cites for the `Path*` family it had. Where that code carries a comment
explaining a quirk, the quirk is carried here with it, because the quirk is
what a guest compiled against Windows depends on.

The strings are walked here rather than handed to the host. A Windows path
is not a POSIX path: `C:a` is drive-relative, `\\\\s\\sh` is a share, `\\` is
a root, and a function that asked the host what those mean would get three
wrong answers.
"""

import re

HELPERS = '''
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
    return path != nullptr && path[0] == static_cast<C>('\\\\') &&
           path[1] == static_cast<C>('\\\\');
}

// `\\\\server\\share`: a UNC path with exactly one separator after the
// leading pair. The walk stops at the second one, which is what makes this
// different from `path_is_unc`.
template <typename C>
[[nodiscard]] bool path_is_unc_server_share(const C* path) noexcept {
    if (!path_is_unc(path)) {
        return false;
    }
    bool seen_separator = false;
    for (const C* p = path + 2; *p != static_cast<C>(0); ++p) {
        if (*p == static_cast<C>('\\\\')) {
            if (seen_separator) {
                return false;
            }
            seen_separator = true;
        }
    }
    return seen_separator;
}

// `\\\\server`: two leading backslashes and no other separator.
template <typename C>
[[nodiscard]] bool path_is_unc_server(const C* path) noexcept {
    if (!path_is_unc(path)) {
        return false;
    }
    for (const C* p = path + 2; *p != static_cast<C>(0); ++p) {
        if (*p == static_cast<C>('\\\\')) {
            return false;
        }
    }
    return true;
}

// A root: `\\`, `\\\\server\\share`, or `X:\\`. The single backslash that
// names the root of the current drive is the first of those, and it is
// checked before the UNC form because `\\\\` is not a root and `\\\\server`
// is not either -- the walk answers true only when the string ends exactly
// after the share name.
template <typename C>
[[nodiscard]] bool path_is_root(const C* path) noexcept {
    if (path == nullptr || *path == static_cast<C>(0)) {
        return false;
    }
    if (*path == static_cast<C>('\\\\')) {
        if (path[1] == static_cast<C>(0)) {
            return true;
        }
        if (path[1] == static_cast<C>('\\\\')) {
            bool seen_separator = false;
            for (const C* p = path + 2; *p != static_cast<C>(0); ++p) {
                if (*p == static_cast<C>('\\\\')) {
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
    return path[1] == static_cast<C>(':') && path[2] == static_cast<C>('\\\\') &&
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
        if (*p == static_cast<C>('\\\\') || *p == static_cast<C>(' ')) {
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
        const bool lead = *p == static_cast<C>('\\\\') ||
                          *p == static_cast<C>('/') || *p == static_cast<C>(':');
        if (lead && p[1] != static_cast<C>(0) &&
            p[1] != static_cast<C>('\\\\') && p[1] != static_cast<C>('/')) {
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
            if (*p == static_cast<C>('\\\\')) {
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
            if (*p == static_cast<C>('\\\\')) {
                share_end = p;
                break;
            }
        }
        return share_end == nullptr ? p : share_end + 1;
    }
    if (path[1] == static_cast<C>(':') && path[2] == static_cast<C>('\\\\')) {
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
    if (*path == static_cast<C>('\\\\')) {
        spec = ++path;
    }
    if (*path == static_cast<C>('\\\\')) {
        spec = ++path;
    }
    while (*path != static_cast<C>(0)) {
        if (*path == static_cast<C>('\\\\')) {
            spec = path;
        } else if (*path == static_cast<C>(':')) {
            // The drive designator restarts the walk: `C:foo` loses `foo` and
            // keeps `C:`. The separator after the colon is skipped by moving the
            // file-spec pointer rather than the cursor: a cursor moved twice
            // would swallow the first character of the path.
            spec = ++path;
            if (*path == static_cast<C>('\\\\')) {
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
// characters so that `C:\\` is not read as sharing a prefix with `C:x`.
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
                               *left == static_cast<C>('\\\\');
        const bool right_edge = *right == static_cast<C>(0) ||
                                *right == static_cast<C>('\\\\');
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
        buffer[0] = static_cast<C>('\\\\');
        buffer[1] = static_cast<C>(0);
        return true;
    }
    C* out = buffer;
    const C* in = path;
    if (*in == static_cast<C>('\\\\')) {
        *out++ = *in++;
    } else if (*in != static_cast<C>(0) && in[1] == static_cast<C>(':')) {
        *out++ = *in++;
        *out++ = *in++;
        if (*in == static_cast<C>('\\\\')) {
            *out++ = *in++;
        }
    }
    while (*in != static_cast<C>(0)) {
        if (*in != static_cast<C>('.')) {
            *out++ = *in++;
            continue;
        }
        const bool at_component_start =
            in == path || in[-1] == static_cast<C>('\\\\') ||
            in[-1] == static_cast<C>(':');
        if (in[1] == static_cast<C>('\\\\') && at_component_start) {
            in += 2;  // `.\\` is the current directory and is dropped
            continue;
        }
        if (in[1] == static_cast<C>('.') &&
            (out == buffer || out[-1] == static_cast<C>('\\\\'))) {
            if (out != buffer) {
                *out = static_cast<C>(0);
                if (out > buffer + 1 && out[-1] == static_cast<C>('\\\\') &&
                    (out[-2] != static_cast<C>('\\\\') || out > buffer + 2)) {
                    if (out[-2] == static_cast<C>(':') &&
                        (out > buffer + 3 || out[-3] == static_cast<C>(':'))) {
                        out -= 2;
                        while (out > buffer && *out != static_cast<C>('\\\\')) {
                            --out;
                        }
                        if (*out == static_cast<C>('\\\\')) {
                            ++out;
                        } else {
                            out = buffer;
                        }
                    } else if (out[-2] != static_cast<C>(':') &&
                               !path_is_unc_server_share(buffer)) {
                        out -= 2;
                    }
                }
                while (out > buffer && *out != static_cast<C>('\\\\')) {
                    --out;
                }
                if (out == buffer) {
                    *out++ = static_cast<C>('\\\\');
                    ++in;
                }
            }
            in += 2;
            continue;
        }
        *out++ = *in++;
    }
    // A bare drive is given a root, so that `C:` becomes `C:\\`.
    if (out - buffer == 2 && out[-1] == static_cast<C>(':')) {
        *out++ = static_cast<C>('\\\\');
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
    if (ch == static_cast<C>('\\\\') || ch == static_cast<C>(':')) {
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
        ch == static_cast<C>('\\'') || value == 130 ||
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
    if (path[length - 1] == static_cast<C>('\\\\')) {
        return true;
    }
    if (length + 2 > capacity) {
        return false;
    }
    path[length] = static_cast<C>('\\\\');
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
'''


def _lit(ctx, text):
    """A string literal at the width the call works in."""
    return f'u"{text}"' if ctx.wide else f'"{text}"'


class Ctx:
    """One rule's view of one call."""

    def __init__(self, name, ret, args, names):
        self.name = name
        self.ret = ret
        self.args = args
        self.names = names
        self.wide = name.endswith('W')
        self.c = 'char16_t' if self.wide else 'char'

    def arg(self, index):
        return self.names[index] if index < len(self.names) else None


RULES = []


def rule(pattern):
    def decorate(builder):
        RULES.append((re.compile(pattern), builder))
        return builder
    return decorate


def _w(ctx):
    return 'W' if ctx.wide else 'A'


# --------------------------------------------------------------------- Path

@rule(r'^PathBuildRoot[AW]$')
def _build_root(c):
    root, drive = c.arg(0), c.arg(1)
    return f'''    if ({root} != nullptr && {drive} >= 0 && {drive} < 26) {{
        {root}[0] = static_cast<{c.c}>('A' + {drive});
        {root}[1] = static_cast<{c.c}>(':');
        {root}[2] = static_cast<{c.c}>('\\\\');
        {root}[3] = static_cast<{c.c}>(0);
    }}
    return {root};'''


@rule(r'^PathAddExtension[AW]$')
def _add_extension(c):
    path, ext = c.arg(0), c.arg(1)
    return f'''    if ({path} == nullptr || {ext} == nullptr) {{
        return 0;
    }}
    // An extension is added only when the name has none. The test is on the
    // character the extension would start at, which is the terminator when
    // there is nothing there.
    const {c.c}* extension = path_extension<{c.c}>({path});
    if (extension == nullptr || *extension != static_cast<{c.c}>(0)) {{
        return 0;
    }}
    const std::size_t length = text_len({path});
    const std::size_t added = text_len({ext});
    if (length + added >= kMaxPath) {{
        return 0;
    }}
    std::memcpy({path} + length, {ext}, (added + 1) * sizeof({c.c}));
    return 1;'''


@rule(r'^PathRemoveExtension[AW]$')
def _remove_extension(c):
    path = c.arg(0)
    return f'''    if ({path} == nullptr) {{
        return;
    }}
    // Removing what is not there is not an error, and the test is on the
    // character: an extension that is empty leaves the string alone, and the
    // terminator is written only when there is a dot to replace.
    {c.c}* extension = const_cast<{c.c}*>(path_extension<{c.c}>({path}));
    if (extension != nullptr && *extension != static_cast<{c.c}>(0)) {{
        *extension = static_cast<{c.c}>(0);
    }}'''


@rule(r'^PathRenameExtension[AW]$')
def _rename_extension(c):
    path, ext = c.arg(0), c.arg(1)
    return f'''    if ({path} == nullptr || {ext} == nullptr) {{
        return 0;
    }}
    {c.c}* extension = const_cast<{c.c}*>(path_extension<{c.c}>({path}));
    if (extension == nullptr) {{
        return 0;
    }}
    // The new extension is written where the old one started, which is the
    // terminator when there was none -- so this call adds an extension as
    // well as replacing one.
    const std::size_t at = static_cast<std::size_t>(extension - {path});
    if (at + text_len({ext}) >= kMaxPath) {{
        return 0;
    }}
    text_copy<{c.c}>(extension, kMaxPath - at, {ext});
    return 1;'''


@rule(r'^PathRemoveBlanks[AW]$')
def _remove_blanks(c):
    return f'''    path_remove_blanks<{c.c}>({c.arg(0)});'''


@rule(r'^PathRemoveArgs[AW]$')
def _remove_args(c):
    path = c.arg(0)
    return f'''    if ({path} == nullptr) {{
        return;
    }}
    // The separating space goes with the arguments, which is why the
    // character before the arguments is cleared rather than the arguments
    // themselves: a string with no arguments is left exactly as it was, and
    // one that ends in a blank loses it.
    {c.c}* args = const_cast<{c.c}*>(path_args<{c.c}>({path}));
    if (args != nullptr &&
        (*args != static_cast<{c.c}>(0) ||
         (args > {path} && args[-1] == static_cast<{c.c}>(' ')))) {{
        args[-1] = static_cast<{c.c}>(0);
    }}'''


@rule(r'^PathQuoteSpaces[AW]$')
def _quote_spaces(c):
    path = c.arg(0)
    return f'''    if ({path} == nullptr ||
        find_first_of<{c.c}>({path}, ch_of<{c.c}>(' ')) == nullptr ||
        *find_first_of<{c.c}>({path}, ch_of<{c.c}>(' ')) == static_cast<{c.c}>(0)) {{
        return;
    }}
    const std::size_t length = text_len({path}) + 1;
    if (length + 2 >= kMaxPath) {{
        return;
    }}
    // Shifted right by one and wrapped. The reference does not check whether
    // the string is already quoted, and neither does this: `PathUnquoteSpaces`
    // is the way back.
    std::memmove({path} + 1, {path}, length * sizeof({c.c}));
    {path}[0] = static_cast<{c.c}>('"');
    {path}[length] = static_cast<{c.c}>('"');
    {path}[length + 1] = static_cast<{c.c}>(0);'''


@rule(r'^PathUnquoteSpaces[AW]$')
def _unquote_spaces(c):
    path = c.arg(0)
    return f'''    if ({path} == nullptr || {path}[0] != static_cast<{c.c}>('"')) {{
        return;
    }}
    const std::size_t length = text_len({path});
    if (length == 0 || {path}[length - 1] != static_cast<{c.c}>('"')) {{
        return;
    }}
    // The closing quote is cleared first and the text then shifted left over
    // the opening one, which is the reference's order and the reason the
    // length is taken before anything is written.
    {path}[length - 1] = static_cast<{c.c}>(0);
    for ({c.c}* p = {path}; *p != static_cast<{c.c}>(0); ++p) {{
        *p = p[1];
    }}'''


@rule(r'^PathStripToRoot[AW]$')
def _strip_to_root(c):
    path = c.arg(0)
    return f'''    if ({path} == nullptr) {{
        return 0;
    }}
    // One component per step. A step that changes nothing means the string
    // has no root to be stripped to, and the reference reports the failure
    // rather than looping on it.
    while (!path_is_root<{c.c}>({path})) {{
        if (!path_remove_file_spec<{c.c}>({path})) {{
            return 0;
        }}
    }}
    return 1;'''


@rule(r'^PathIsRoot[AW]$')
def _is_root(c):
    return f'    return path_is_root<{c.c}>({c.arg(0)}) ? 1 : 0;'


@rule(r'^PathIsUNC[AW]$')
def _is_unc(c):
    return f'    return path_is_unc<{c.c}>({c.arg(0)}) ? 1 : 0;'


@rule(r'^PathIsUNCServerShare[AW]$')
def _is_unc_server_share(c):
    return f'    return path_is_unc_server_share<{c.c}>({c.arg(0)}) ? 1 : 0;'


@rule(r'^PathIsUNCServer[AW]$')
def _is_unc_server(c):
    return f'    return path_is_unc_server<{c.c}>({c.arg(0)}) ? 1 : 0;'


@rule(r'^PathIsRelative[AW]$')
def _is_relative(c):
    path = c.arg(0)
    return f'''    if ({path} == nullptr || *{path} == static_cast<{c.c}>(0)) {{
        return 1;
    }}
    // `X:` is absolute whether or not a separator follows, which is the
    // difference between a drive path and a drive-relative one -- both are
    // absolute, and only the second is relative to the drive's current
    // directory rather than to its root.
    return (*{path} == static_cast<{c.c}>('\\\\') ||
            {path}[1] == static_cast<{c.c}>(':'))
               ? 0
               : 1;'''


@rule(r'^PathGetCharType[AW]$')
def _get_char_type(c):
    return f'    return path_char_type<{c.c}>(static_cast<{c.c}>({c.arg(0)}));'


@rule(r'^PathIsFileSpec[AW]$')
def _is_file_spec(c):
    path = c.arg(0)
    return f'''    if ({path} == nullptr) {{
        return 0;
    }}
    for (const {c.c}* p = {path}; *p != static_cast<{c.c}>(0); ++p) {{
        if (*p == static_cast<{c.c}>('\\\\') || *p == static_cast<{c.c}>(':')) {{
            return 0;
        }}
    }}
    return 1;'''


@rule(r'^PathIsLFNFileSpec[AW]$')
def _is_lfn(c):
    return f'    return path_is_long_file_spec<{c.c}>({c.arg(0)}) ? 1 : 0;'


@rule(r'^PathIsPrefix[AW]$')
def _is_prefix(c):
    prefix, path = c.arg(0), c.arg(1)
    return f'''    if ({prefix} == nullptr || {path} == nullptr) {{
        return 0;
    }}
    const std::size_t common = path_common_prefix<{c.c}>({path}, {prefix}, nullptr);
    return common == text_len({prefix}) ? 1 : 0;'''


@rule(r'^PathIsSameRoot[AW]$')
def _is_same_root(c):
    first, second = c.arg(0), c.arg(1)
    return f'''    if ({first} == nullptr || {second} == nullptr) {{
        return 0;
    }}
    const {c.c}* after_root = path_skip_root<{c.c}>({first});
    if (after_root == nullptr) {{
        return 0;
    }}
    // The two paths have the same root when the source's root is inside the
    // shared prefix, which is the reference's test and the reason the prefix
    // is counted with its root rather than from the first component.
    const std::size_t common =
        path_common_prefix<{c.c}>({first}, {second}, nullptr) + 1;
    return static_cast<std::size_t>(after_root - {first}) <= common ? 1 : 0;'''


@rule(r'^PathCanonicalize[AW]$')
def _canonicalize(c):
    buffer, path = c.arg(0), c.arg(1)
    return f'''    if ({buffer} == nullptr || {path} == nullptr) {{
        set_last_error(kErrorInvalidParameter);
        return 0;
    }}
    return path_canonicalize<{c.c}>({buffer}, {path}) ? 1 : 0;'''


@rule(r'^PathMatchSpecEx[AW]$')
def _match_spec_ex(c):
    path, mask, flags = c.arg(0), c.arg(1), c.arg(2)
    return f'''    // The flags select between the plain form and the raw form, which
    // differs only in how a query string's escape characters are treated.
    // Both reach the same matcher here, and the flags are carried in the
    // signature so that a caller reading them sees the name the header
    // declared.
    static_cast<void>({flags});
    if ({path} == nullptr || {mask} == nullptr) {{
        return 0;
    }}
    return path_match_spec<{c.c}>({path}, {mask}) ? 1 : 0;'''


@rule(r'^PathMatchSpec[AW]$')
def _match_spec(c):
    path, mask = c.arg(0), c.arg(1)
    return f'''    return path_match_spec<{c.c}>({path}, {mask}) ? 1 : 0;'''


@rule(r'^PathIsDirectoryEmpty[AW]$')
def _is_directory_empty(c):
    path = c.arg(0)
    w = _w(c)
    other = 'W' if not c.wide else 'W'
    return f'''    if ({path} == nullptr || !path_is_directory<{c.c}>({path})) {{
        return 0;
    }}
    // The walk is over `*.*`, which is the search every directory accepts,
    // and the two entries every directory has are skipped. A walk that
    // cannot start is a failure rather than an empty directory: the
    // reference reports FALSE and a caller that reads it as "empty" would
    // delete a directory it could not read.
    {c.c} pattern[kMaxPath];
    text_copy<{c.c}>(pattern, kMaxPath, {path});
    if (!path_add_backslash<{c.c}>(pattern, kMaxPath)) {{
        return 0;
    }}
    const std::size_t at = text_len(pattern);
    if (at > kMaxPath - 4) {{
        return 0;
    }}
    text_append<{c.c}>(pattern, kMaxPath, ch_of<{c.c}>('*'));
    text_append<{c.c}>(pattern, kMaxPath, ch_of<{c.c}>('.'));
    text_append<{c.c}>(pattern, kMaxPath, ch_of<{c.c}>('*'));

    alignas(8) std::uint8_t entry[592];
    void* walk = k32f3_FindFirstFile{w}(pattern, entry);
    if (walk == reinterpret_cast<void*>(kInvalidHandleValue)) {{
        return 0;
    }}
    bool empty = true;
    for (;;) {{
        const {c.c}* name = reinterpret_cast<const {c.c}*>(entry + 44);
        const bool self = name[0] == static_cast<{c.c}>('.') &&
                          name[1] == static_cast<{c.c}>(0);
        const bool parent = name[0] == static_cast<{c.c}>('.') &&
                            name[1] == static_cast<{c.c}>('.') &&
                            name[2] == static_cast<{c.c}>(0);
        if (!self && !parent) {{
            empty = false;
            break;
        }}
        if (!find_next_entry<{c.c}>(walk, entry)) {{
            break;
        }}
    }}
    static_cast<void>(k32f2_FindClose(walk));
    return empty ? 1 : 0;'''


@rule(r'^PathIsDirectory[AW]$')
def _is_directory(c):
    path = c.arg(0)
    return f'''    return path_is_directory<{c.c}>({path}) ? 1 : 0;'''


@rule(r'^PathFileExists[AW]$')
def _file_exists(c):
    path = c.arg(0)
    w = _w(c)
    return f'''    if ({path} == nullptr) {{
        return 0;
    }}
    return k32b_GetFileAttributes{w}({path}) != 0xFFFFFFFFu ? 1 : 0;'''


@rule(r'^PathIsSystemFolder[AW]$')
def _is_system_folder(c):
    path, given = c.arg(0), c.arg(1)
    w = _w(c)
    return f'''    // The attributes are queried whenever the path is not empty, and the
    // argument is only a fallback for the empty case -- which is the
    // reference's rule and the opposite of what the argument's name
    // suggests.
    std::uint32_t attributes = {given};
    if ({path} != nullptr && *{path} != static_cast<{c.c}>(0)) {{
        attributes = k32b_GetFileAttributes{w}({path});
    }}
    if (attributes == 0xFFFFFFFFu) {{
        return 0;
    }}
    // A system folder is a directory that is marked system or read-only --
    // either bit is enough, and both are checked with one mask.
    if ((attributes & 0x00000010u) == 0) {{
        return 0;
    }}
    return (attributes & (0x00000004u | 0x00000001u)) != 0 ? 1 : 0;'''


@rule(r'^PathMakeSystemFolder[AW]$')
def _make_system_folder(c):
    path = c.arg(0)
    w = _w(c)
    return f'''    if ({path} == nullptr || *{path} == static_cast<{c.c}>(0)) {{
        return 0;
    }}
    // The Windows and system directories are already system folders and are
    // answered before anything is written, so that the call cannot change
    // the attributes of the installation itself.
    {c.c} system_directory[kMaxPath];
    if (k32p_GetSystemDirectory{w}(system_directory, kMaxPath) != 0 &&
        text_equal_ci<{c.c}>(system_directory, {path})) {{
        return 1;
    }}
    {c.c} windows_directory[kMaxPath];
    if (k32p_GetWindowsDirectory{w}(windows_directory, kMaxPath) != 0 &&
        text_equal_ci<{c.c}>(windows_directory, {path})) {{
        return 1;
    }}
    const std::uint32_t attributes = k32b_GetFileAttributes{w}({path});
    if (attributes == 0xFFFFFFFFu) {{
        return 0;
    }}
    // The three bits are cleared and the read-only bit set, which is what
    // the reference does when the `UseSystemForSystemFolders` policy is
    // absent. That policy is a registry value of the shell's own
    // configuration, and this runtime's registry model does not seed it, so
    // the default is the answer.
    const std::uint32_t cleared =
        attributes & ~(0x00000004u | 0x00000002u | 0x00000001u);
    return k32b_SetFileAttributes{w}({path}, cleared | 0x00000001u) ? 1 : 0;'''


@rule(r'^PathUnmakeSystemFolder[AW]$')
def _unmake_system_folder(c):
    path = c.arg(0)
    w = _w(c)
    return f'''    if ({path} == nullptr || *{path} == static_cast<{c.c}>(0)) {{
        return 0;
    }}
    const std::uint32_t attributes = k32b_GetFileAttributes{w}({path});
    if (attributes == 0xFFFFFFFFu || (attributes & 0x00000010u) == 0) {{
        return 0;
    }}
    return k32b_SetFileAttributes{w}({path},
                                     attributes & ~(0x00000002u | 0x00000004u))
               ? 1
               : 0;'''


@rule(r'^PathMakePretty[AW]$')
def _make_pretty(c):
    path = c.arg(0)
    return f'''    if ({path} == nullptr) {{
        return 0;
    }}
    if (*{path} == static_cast<{c.c}>(0)) {{
        return 1;
    }}
    // A name is prettied only when it holds no lower-case letter at all: the
    // rule is the DOS convention that an all-capitals name was written by a
    // program and a mixed one by a person. The first character keeps its
    // case and the rest are folded.
    for (const {c.c}* p = {path}; *p != static_cast<{c.c}>(0); ++p) {{
        if (ch_lower(*p)) {{
            return 0;
        }}
    }}
    for ({c.c}* p = {path} + 1; *p != static_cast<{c.c}>(0); ++p) {{
        *p = ch_lower_of(*p);
    }}
    return 1;'''


@rule(r'^PathUndecorate[AW]$')
def _undecorate(c):
    path = c.arg(0)
    return f'''    if ({path} == nullptr) {{
        return;
    }}
    // The decoration is the `[n]` Explorer adds between a name and its
    // extension. The extension's dot is where the walk starts, so a name
    // with no extension is never decorated and a parenthesis that is part
    // of the name is left alone.
    {c.c}* extension = const_cast<{c.c}*>(path_extension<{c.c}>({path}));
    if (extension == nullptr || extension == {path} ||
        extension[-1] != static_cast<{c.c}>(']')) {{
        return;
    }}
    {c.c}* skip = extension - 2;
    while (skip > {path} && ch_digit(*skip)) {{
        --skip;
    }}
    if (skip > {path} && *skip == static_cast<{c.c}>('[') &&
        skip[-1] != static_cast<{c.c}>('\\\\')) {{
        std::memmove(skip, extension,
                     (text_len(extension) + 1) * sizeof({c.c}));
    }}'''


@rule(r'^PathParseIconLocation[AW]$')
def _parse_icon_location(c):
    path = c.arg(0)
    return f'''    if ({path} == nullptr) {{
        return 0;
    }}
    // The answer is the index after the comma and the string is left holding
    // the file name alone, with its quotes and blanks removed.
    std::int32_t index = 0;
    {c.c}* comma = const_cast<{c.c}*>(find_first_of<{c.c}>({path}, ch_of<{c.c}>(',')));
    if (comma != nullptr && *comma != static_cast<{c.c}>(0)) {{
        *comma = static_cast<{c.c}>(0);
        const {c.c}* p = comma + 1;
        bool negative = false;
        if (*p == static_cast<{c.c}>('-')) {{
            negative = true;
            ++p;
        }}
        while (ch_digit(*p)) {{
            index = index * 10 +
                    static_cast<std::int32_t>(*p - static_cast<{c.c}>('0'));
            ++p;
        }}
        if (negative) {{
            index = -index;
        }}
    }}
    const std::size_t length = text_len({path});
    if (length >= 2 && {path}[0] == static_cast<{c.c}>('"') &&
        {path}[length - 1] == static_cast<{c.c}>('"')) {{
        {path}[length - 1] = static_cast<{c.c}>(0);
        for ({c.c}* p = {path}; *p != static_cast<{c.c}>(0); ++p) {{
            *p = p[1];
        }}
    }}
    path_remove_blanks<{c.c}>({path});
    return index;'''


@rule(r'^PathCompactPathEx[AW]$')
def _compact_path_ex(c):
    out, src, max_chars, flags = (c.arg(i) for i in range(4))
    return f'''    static_cast<void>({flags});
    if ({src} == nullptr) {{
        return 0;
    }}
    if ({out} == nullptr) {{
        return 0;
    }}
    *{out} = static_cast<{c.c}>(0);
    if ({max_chars} < 2) {{
        return 1;
    }}
    const std::size_t length = text_len({src}) + 1;
    if (length < {max_chars}) {{
        std::memcpy({out}, {src}, length * sizeof({c.c}));
        return 1;
    }}
    // The path has to be shortened. The reference cuts from the middle: the
    // file name is kept whole when it fits, the root is cut back when it
    // does not, and the ellipsis marks the cut.
    const {c.c}* file = path_file_name<{c.c}>({src});
    std::size_t file_length = static_cast<std::size_t>({src} + length - file);
    if (file_length == length) {{
        // No separator at all, so there is no root to protect.
        if ({max_chars} <= 4) {{
            std::uint32_t room = {max_chars};
            {c.c}* write = {out};
            while (--room > 0) {{
                *write++ = static_cast<{c.c}>('.');
            }}
            *write = static_cast<{c.c}>(0);
            return 1;
        }}
        const std::size_t keep = static_cast<std::size_t>({max_chars}) - 4;
        std::memcpy({out}, file, keep * sizeof({c.c}));
        {out}[keep] = static_cast<{c.c}>('.');
        {out}[keep + 1] = static_cast<{c.c}>('.');
        {out}[keep + 2] = static_cast<{c.c}>('.');
        {out}[keep + 3] = static_cast<{c.c}>(0);
        return 1;
    }}
    --file;
    ++file_length;
    if (file_length + 3 > static_cast<std::size_t>({max_chars})) {{
        if ({max_chars} <= 4) {{
            std::uint32_t room = {max_chars};
            {c.c}* write = {out};
            while (--room > 0) {{
                *write++ = static_cast<{c.c}>('.');
            }}
            *write = static_cast<{c.c}>(0);
            return 1;
        }}
        {c.c}* write = {out};
        *write++ = static_cast<{c.c}>('.');
        *write++ = static_cast<{c.c}>('.');
        *write++ = static_cast<{c.c}>('.');
        std::uint32_t room = {max_chars} - 4;
        *write++ = *file++;
        if (room <= 4) {{
            while (--room > 0) {{
                *write++ = static_cast<{c.c}>('.');
            }}
            *write = static_cast<{c.c}>(0);
            return 1;
        }}
        room -= 4;
        std::memcpy(write, file, room * sizeof({c.c}));
        write[room] = static_cast<{c.c}>('.');
        write[room + 1] = static_cast<{c.c}>('.');
        write[room + 2] = static_cast<{c.c}>('.');
        write[room + 3] = static_cast<{c.c}>(0);
        return 1;
    }}
    // Only the root is cut.
    const std::size_t root = static_cast<std::size_t>({max_chars}) - file_length - 3;
    std::memcpy({out}, {src}, root * sizeof({c.c}));
    {out}[root] = static_cast<{c.c}>('.');
    {out}[root + 1] = static_cast<{c.c}>('.');
    {out}[root + 2] = static_cast<{c.c}>('.');
    text_copy<{c.c}>({out} + root + 3,
                     static_cast<std::size_t>({max_chars}) - root - 3, file);
    return 1;'''


@rule(r'^PathFindSuffixArray[AW]$')
def _find_suffix(c):
    path, array, count = c.arg(0), c.arg(1), c.arg(2)
    return f'''    if ({path} == nullptr || {array} == nullptr || {count} <= 0) {{
        return nullptr;
    }}
    // The comparison is exact and the suffix must be shorter than the path,
    // which is the reference's rule: a suffix that is the whole string is
    // not a suffix of it.
    const std::size_t length = text_len({path});
    for (int index = 0; index < {count}; ++index) {{
        const {c.c}* suffix = {array}[index];
        if (suffix == nullptr) {{
            continue;
        }}
        const std::size_t suffix_length = text_len(suffix);
        if (suffix_length >= length) {{
            continue;
        }}
        if (text_equal<{c.c}>({path} + length - suffix_length, suffix)) {{
            return suffix;
        }}
    }}
    return nullptr;'''


@rule(r'^PathFindOnPath[AW]$')
def _find_on_path(c):
    path, others = c.arg(0), c.arg(1)
    w = _w(c)
    path_name = _lit(c, 'PATH')
    naming_literal = _lit(c, 'System')
    return f'''    if ({path} == nullptr) {{
        return 0;
    }}
    // The search order is the reference's: what the caller named, then the
    // system directory, then the Windows directory, then the Windows system
    // directory, then every entry of `PATH`. A name that already exists, and
    // an absolute name, are answered before the walk starts.
    if (k32b_GetFileAttributes{w}({path}) != 0xFFFFFFFFu) {{
        return 1;
    }}
    if (!path_is_relative<{c.c}>({path})) {{
        return 0;
    }}
    {c.c} candidate[kMaxPath];
    const std::size_t name_length = text_len({path});
    if (name_length + 2 >= kMaxPath) {{
        return 0;
    }}
    if ({others} != nullptr) {{
        for (const {c.c}* const* item = {others}; *item != nullptr; ++item) {{
            if (path_join<{c.c}>(candidate, kMaxPath, *item, {path}) &&
                k32b_GetFileAttributes{w}(candidate) != 0xFFFFFFFFu) {{
                text_copy<{c.c}>({path}, kMaxPath, candidate);
                return 1;
            }}
        }}
    }}
    const {c.c} naming[] = {naming_literal};
    {c.c} root[kMaxPath];
    for (int step = 0; step < 3; ++step) {{
        std::uint32_t written = 0;
        if (step == 0) {{
            written = k32p_GetSystemDirectory{w}(root, kMaxPath);
        }} else if (step == 1) {{
            written = k32p_GetWindowsDirectory{w}(root, kMaxPath);
            if (written != 0 && written + 8 < kMaxPath) {{
                static_cast<void>(path_join<{c.c}>(root, kMaxPath, root, naming));
            }}
        }} else {{
            written = k32p_GetWindowsDirectory{w}(root, kMaxPath);
        }}
        if (written == 0) {{
            continue;
        }}
        if (path_join<{c.c}>(candidate, kMaxPath, root, {path}) &&
            k32b_GetFileAttributes{w}(candidate) != 0xFFFFFFFFu) {{
            text_copy<{c.c}>({path}, kMaxPath, candidate);
            return 1;
        }}
    }}
    // `PATH` last. The environment holds one delimiter-separated list, and
    // the walk is over it rather than over a copy, because a copy is one
    // more buffer to bound.
    {c.c} search_path[32768];
    const std::uint32_t used = k32_GetEnvironmentVariable{w}(
        {path_name}, search_path, static_cast<std::uint32_t>(32768));
    if (used == 0 || used >= 32768) {{
        return 0;
    }}
    const {c.c}* at = search_path;
    for (;;) {{
        while (*at == static_cast<{c.c}>(' ')) {{
            ++at;
        }}
        const {c.c}* end = at;
        while (*end != static_cast<{c.c}>(0) && *end != static_cast<{c.c}>(';')) {{
            ++end;
        }}
        {c.c} directory[kMaxPath];
        const std::size_t length = static_cast<std::size_t>(end - at);
        if (length != 0 && length + 1 < kMaxPath) {{
            std::memcpy(directory, at, length * sizeof({c.c}));
            directory[length] = static_cast<{c.c}>(0);
            if (path_join<{c.c}>(candidate, kMaxPath, directory, {path}) &&
                k32b_GetFileAttributes{w}(candidate) != 0xFFFFFFFFu) {{
                text_copy<{c.c}>({path}, kMaxPath, candidate);
                return 1;
            }}
        }}
        if (*end == static_cast<{c.c}>(0)) {{
            break;
        }}
        at = end + 1;
    }}
    return 0;'''


@rule(r'^PathSearchAndQualify[AW]$')
def _search_and_qualify(c):
    path, buffer, length = c.arg(0), c.arg(1), c.arg(2)
    w = _w(c)
    return f'''    if ({path} == nullptr || {buffer} == nullptr || {length} == 0) {{
        return 0;
    }}
    // The reference asks the search path first -- which is what finds a name
    // that names a file somewhere on `PATH` -- and falls back to the full
    // path, which is what qualifies a name that names nothing yet. The
    // second case is the one this call exists for: a file about to be
    // created.
    {c.c} qualified[kMaxPath];
    if (k32b_GetFileAttributes{w}({path}) != 0xFFFFFFFFu) {{
        text_copy<{c.c}>({buffer}, {length}, {path});
        return 1;
    }}
    if (k32b_GetFullPathName{w}({path}, kMaxPath, qualified, nullptr) != 0) {{
        text_copy<{c.c}>({buffer}, {length}, qualified);
        return 1;
    }}
    return 0;'''


@rule(r'^PathRelativePathTo[AW]$')
def _relative_path_to(c):
    out, src, attr_from, dst, attr_to = (c.arg(i) for i in range(5))
    return f'''    if ({out} == nullptr || {src} == nullptr || {dst} == nullptr) {{
        return 0;
    }}
    *{out} = static_cast<{c.c}>(0);
    // A file argument is cut back to its directory, because a path relative
    // to a file is a path relative to where the file is.
    {c.c} from[kMaxPath];
    {c.c} to[kMaxPath];
    text_copy<{c.c}>(from, kMaxPath, {src});
    text_copy<{c.c}>(to, kMaxPath, {dst});
    if (({attr_from} & 0x00000010u) == 0) {{
        static_cast<void>(path_remove_file_spec<{c.c}>(from));
    }}
    if (({attr_to} & 0x00000010u) == 0) {{
        static_cast<void>(path_remove_file_spec<{c.c}>(to));
    }}
    // Two paths share a relative form only if they share a root.
    const std::size_t shared = path_common_prefix<{c.c}>(from, to, nullptr);
    if (shared == 0) {{
        return 0;
    }}
    const {c.c}* walk = from + shared;
    if (*walk == static_cast<{c.c}>(0)) {{
        text_copy<{c.c}>({out}, 2, ch_of<{c.c}>('.'));
    }}
    if (*walk == static_cast<{c.c}>('\\\\')) {{
        ++walk;
    }}
    while (*walk != static_cast<{c.c}>(0)) {{
        // One step up for every component the source has left. The last step
        // is written without a trailing separator, because what follows is
        // the destination.
        const {c.c}* next = walk;
        while (*next != static_cast<{c.c}>(0) && *next != static_cast<{c.c}>('\\\\')) {{
            ++next;
        }}
        while (*next == static_cast<{c.c}>('\\\\')) {{
            ++next;
        }}
        const bool more = *next != static_cast<{c.c}>(0);
        text_append<{c.c}>({out}, kMaxPath, ch_of<{c.c}>('.'));
        text_append<{c.c}>({out}, kMaxPath, ch_of<{c.c}>('.'));
        if (more) {{
            text_append<{c.c}>({out}, kMaxPath, ch_of<{c.c}>('\\\\'));
        }}
        walk = next;
    }}
    const {c.c}* rest = to + shared;
    if (*rest != static_cast<{c.c}>(0)) {{
        if (*rest != static_cast<{c.c}>('\\\\')) {{
            --rest;
        }}
        if (text_len({out}) + text_len(rest) >= kMaxPath) {{
            *{out} = static_cast<{c.c}>(0);
            return 0;
        }}
        text_append<{c.c}>({out}, kMaxPath, rest);
    }}
    return 1;'''


@rule(r'^PathUnExpandEnvStrings[AW]$')
def _unexpand_env(c):
    path, buffer, length = c.arg(0), c.arg(1), c.arg(2)
    w = _w(c)
    var_allusersprofile = _lit(c, 'ALLUSERSPROFILE')
    var_appdata = _lit(c, 'APPDATA')
    var_programfiles = _lit(c, 'ProgramFiles')
    var_systemroot = _lit(c, 'SystemRoot')
    var_systemdrive = _lit(c, 'SystemDrive')
    var_userprofile = _lit(c, 'USERPROFILE')
    return f'''    if ({path} == nullptr || {buffer} == nullptr || {length} == 0) {{
        return 0;
    }}
    // The variables the shell un-expands, and the longest match wins so that
    // the most specific prefix is used: a path under `%ProgramFiles%` must
    // not be answered as `%SystemDrive%\\Program Files`.
    static const struct {{ const {c.c}* name; }} variables[] = {{
        {{{var_allusersprofile}}},
        {{{var_appdata}}},
        {{{var_programfiles}}},
        {{{var_systemroot}}},
        {{{var_systemdrive}}},
        {{{var_userprofile}}},
    }};
    {c.c} value[32768];
    const {c.c}* matched = nullptr;
    std::size_t matched_length = 0;
    const std::size_t path_length = text_len({path});
    for (const auto& variable : variables) {{
        const std::uint32_t used = k32_GetEnvironmentVariable{w}(
            variable.name, value, static_cast<std::uint32_t>(32768));
        if (used == 0 || used >= 32768) {{
            continue;
        }}
        const std::size_t value_length = text_len(value);
        if (value_length == 0 || value_length > path_length ||
            value_length <= matched_length) {{
            continue;
        }}
        if (text_lower_equal_prefix<{c.c}>(value, {path}, value_length)) {{
            matched = variable.name;
            matched_length = value_length;
        }}
    }}
    if (matched == nullptr) {{
        return 0;
    }}
    // `%NAME%` and then the remainder, which is what makes the answer a
    // string a later expansion turns back into the input.
    const std::size_t needed =
        text_len(matched) + 2 + path_length - matched_length + 1;
    if (needed > {length}) {{
        return 0;
    }}
    {c.c}* write = {buffer};
    *write++ = ch_of<{c.c}>('%');
    for (const {c.c}* p = matched; *p != static_cast<{c.c}>(0); ++p) {{
        *write++ = *p;
    }}
    *write++ = ch_of<{c.c}>('%');
    for (const {c.c}* p = {path} + matched_length; *p != static_cast<{c.c}>(0); ++p) {{
        *write++ = *p;
    }}
    *write = static_cast<{c.c}>(0);
    return 1;'''


@rule(r'^PathIsURL[AW]$')
def _is_url(c):
    path = c.arg(0)
    return f'''    if ({path} == nullptr || *{path} == static_cast<{c.c}>(0)) {{
        return 0;
    }}
    // A URL is a scheme and a colon. A scheme is a letter followed by
    // letters, digits, `+`, `-` or `.`, and it must be longer than one
    // character -- a single letter before a colon is a drive designator.
    const {c.c}* p = {path};
    if (!ch_alpha(*p)) {{
        return 0;
    }}
    ++p;
    std::size_t length = 1;
    while (ch_alpha(*p) || ch_digit(*p) || *p == static_cast<{c.c}>('+') ||
           *p == static_cast<{c.c}>('-') || *p == static_cast<{c.c}>('.')) {{
        ++p;
        ++length;
    }}
    if (length < 2 || *p != static_cast<{c.c}>(':')) {{
        return 0;
    }}
    return 1;'''


@rule(r'^PathIsNetworkPath[AW]$')
def _is_network_path(c):
    path = c.arg(0)
    return f'''    if ({path} == nullptr) {{
        return 0;
    }}
    if (path_is_unc<{c.c}>({path})) {{
        return 1;
    }}
    // A drive letter is a network path only when the drive is a network
    // mapping. The drives this runtime presents are the host's own file
    // system, and there are no mappings among them, so the answer for a
    // letter is that the drive is local.
    return 0;'''


# --------------------------------------------------------------------- Str

@rule(r'^StrCatW$')
def _str_cat_w(c):
    dest, src = c.arg(0), c.arg(1)
    return f'''    if ({dest} != nullptr && {src} != nullptr) {{
        // The contract is the one `lstrcat` has: the caller's buffer decides
        // the room, and the answer is the caller's own pointer.
        static_cast<void>(text_append<{c.c}>({dest}, 0x7FFFFFFFul, {src}));
    }}
    return {dest};'''


@rule(r'^StrCpyW$')
def _str_cpy_w(c):
    dest, src = c.arg(0), c.arg(1)
    return f'''    if ({dest} != nullptr && {src} != nullptr) {{
        static_cast<void>(text_copy<{c.c}>({dest}, 0x7FFFFFFFul, {src}));
    }}
    return {dest};'''


@rule(r'^StrNCat[AW]$')
def _str_ncat(c):
    dest, src, count = c.arg(0), c.arg(1), c.arg(2)
    return f'''    if ({dest} == nullptr) {{
        return nullptr;
    }}
    // The bound is on what is appended and not on the total, and the append
    // starts at the end of what is already there -- so this is `StrCpyN`
    // aimed past the existing text, which is what the reference writes.
    const std::size_t start = text_len({dest});
    if ({count} > 0) {{
        static_cast<void>(text_copy<{c.c}>({dest} + start,
                                           static_cast<std::size_t>({count}),
                                           {src}));
    }}
    return {dest};'''


@rule(r'^StrChrNIW$')
def _str_chr_ni_w(c):
    text, match, count = c.arg(0), c.arg(1), c.arg(2)
    return f'''    if ({text} == nullptr || {count} == 0) {{
        return nullptr;
    }}
    // The bound counts characters, and a match of zero is the terminator,
    // which is not searched for.
    const char16_t wanted = ch_lower_of(static_cast<char16_t>({match}));
    if (wanted == static_cast<char16_t>(0)) {{
        return nullptr;
    }}
    for (std::uint32_t index = 0; index < {count}; ++index) {{
        const char16_t ch = {text}[index];
        if (ch == static_cast<char16_t>(0)) {{
            break;
        }}
        if (ch_lower_of(ch) == wanted) {{
            return {text} + index;
        }}
    }}
    return nullptr;'''


@rule(r'^ChrCmpI[AW]$')
def _chr_cmp_i(c):
    first, second = c.arg(0), c.arg(1)
    return f'''    // The comparison is unsigned and case-insensitive, and the answer is
    // the difference of the folded characters rather than a sign.
    const std::uint32_t left =
        static_cast<std::uint32_t>(ch_lower_of(static_cast<{c.c}>({first})));
    const std::uint32_t right =
        static_cast<std::uint32_t>(ch_lower_of(static_cast<{c.c}>({second})));
    return static_cast<std::int32_t>(left - right);'''


@rule(r'^IsCharSpace[AW]$')
def _is_char_space(c):
    return f'    return ch_space<{c.c}>(static_cast<{c.c}>({c.arg(0)})) ? 1 : 0;'


@rule(r'^IntlStrEqWorker[AW]$')
def _intl_str_eq(c):
    sensitive, first, second, count = (c.arg(i) for i in range(4))
    return f'''    if ({first} == nullptr || {second} == nullptr) {{
        return 0;
    }}
    // `nChar` counts characters and -1 means "to the terminator". The
    // comparison walks rather than copying, so that the bound is a bound
    // and the terminator is what ends the shorter string.
    std::int64_t remaining = static_cast<std::int64_t>({count});
    const {c.c}* left = {first};
    const {c.c}* right = {second};
    for (;;) {{
        if (remaining == 0) {{
            return 1;
        }}
        const {c.c} a = *left;
        const {c.c} b = *right;
        if (({sensitive} ? a : ch_lower_of(a)) !=
            ({sensitive} ? b : ch_lower_of(b))) {{
            return 0;
        }}
        if (a == static_cast<{c.c}>(0)) {{
            return 1;
        }}
        ++left;
        ++right;
        if (remaining > 0) {{
            --remaining;
        }}
    }}'''


@rule(r'^StrFromTimeInterval[AW]$')
def _str_from_time_interval(c):
    out, max_chars, milliseconds, digits = (c.arg(i) for i in range(4))
    hour_unit = _lit(c, ' hr')
    minute_unit = _lit(c, ' min')
    second_unit = _lit(c, ' sec')
    return f'''    if ({out} == nullptr || {max_chars} == 0) {{
        return 0;
    }}
    if ({digits} <= 0 || {max_chars} == 1) {{
        *{out} = static_cast<{c.c}>(0);
        return 0;
    }}
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
    std::uint32_t seconds_total = ({milliseconds} + 500u) / 1000u;
    const std::uint32_t hours = seconds_total / 3600u;
    seconds_total -= hours * 3600u;
    const std::uint32_t minutes = seconds_total / 60u;
    seconds_total -= minutes * 60u;

    {c.c} text[128];
    text[0] = static_cast<{c.c}>(0);
    if (hours != 0) {{
        {digits} = write_time_class<{c.c}>(text, 128, hours, {hour_unit}, {digits});
    }}
    if (minutes != 0 && {digits} > 0) {{
        {digits} = write_time_class<{c.c}>(text, 128, minutes, {minute_unit},
                                           {digits});
    }}
    if ({digits} > 0) {{
        static_cast<void>(write_time_class<{c.c}>(text, 128, seconds_total,
                                                  {second_unit}, {digits}));
    }}
    static_cast<void>(text_copy<{c.c}>({out}, {max_chars}, text));
    return static_cast<std::int32_t>(text_len({out}));'''


@rule(r'^StrFormatKBSize[AW]$')
def _format_kb_size(c):
    value, dest, max_chars = c.arg(0), c.arg(1), c.arg(2)
    return f'''    if ({dest} == nullptr || {max_chars} == 0) {{
        return nullptr;
    }}
    // The byte count rounded up to whole kilobytes, then the unit. The
    // rounding is the reference's: `(bytes + 1023) >> 10`, so a file of one
    // byte is one kilobyte rather than zero.
    const std::int64_t kilobytes =
        (static_cast<std::int64_t>({value}) + 1023) >> 10;
    if (number_text<{c.c}>({dest}, {max_chars}, kilobytes) == 0) {{
        return nullptr;
    }}
    const std::size_t length = text_len({dest});
    if (static_cast<std::size_t>({max_chars}) - length < 4) {{
        return nullptr;
    }}
    text_append<{c.c}>({dest}, {max_chars}, ch_of<{c.c}>(' '));
    text_append<{c.c}>({dest}, {max_chars}, ch_of<{c.c}>('K'));
    text_append<{c.c}>({dest}, {max_chars}, ch_of<{c.c}>('B'));
    return {dest};'''


@rule(r'^StrFormatByteSize64A$')
def _format_byte_size_64_a(c):
    value, dest, max_chars = c.arg(0), c.arg(1), c.arg(2)
    return f'''    // The wide form carries the rules and this one converts, which is the
    // same split the rest of the family uses.
    char16_t wide[32];
    if (format_byte_size(static_cast<std::int64_t>({value}), wide, 32) == nullptr) {{
        return {dest};
    }}
    if ({dest} != nullptr) {{
        static_cast<void>(narrow_text(wide, {dest}, {max_chars}));
    }}
    return {dest};'''


@rule(r'^StrFormatByteSizeA$')
def _format_byte_size_a(c):
    value, dest, max_chars = c.arg(0), c.arg(1), c.arg(2)
    return f'''    // The narrow form takes a 32-bit count and answers through the 64-bit
    // path, which is what the reference does -- the two differ only in the
    // width of the argument the caller may pass.
    char16_t wide[32];
    if (format_byte_size(static_cast<std::int64_t>(
                             static_cast<std::uint32_t>({value})),
                         wide, 32) == nullptr) {{
        return {dest};
    }}
    if ({dest} != nullptr) {{
        static_cast<void>(narrow_text(wide, {dest}, {max_chars}));
    }}
    return {dest};'''


@rule(r'^StrFormatByteSizeW$')
def _format_byte_size_w(c):
    value, dest, max_chars = c.arg(0), c.arg(1), c.arg(2)
    return f'''    return format_byte_size(static_cast<std::int64_t>({value}), {dest},
                            {max_chars});'''


# -------------------------------------------------------------- conversions

@rule(r'^SHAnsiToUnicode$')
def _ansi_to_unicode(c):
    src, dest, count = c.arg(0), c.arg(1), c.arg(2)
    return f'''    if ({src} == nullptr || {dest} == nullptr || {count} <= 0) {{
        return 0;
    }}
    const std::size_t written = widen_text({src}, {dest},
                                           static_cast<std::size_t>({count}));
    return static_cast<std::int32_t>(written);'''


@rule(r'^SHUnicodeToUnicode$')
def _unicode_to_unicode(c):
    src, dest, count = c.arg(0), c.arg(1), c.arg(2)
    return f'''    if ({src} == nullptr || {dest} == nullptr || {count} <= 0) {{
        return 0;
    }}
    const std::size_t written = text_copy<char16_t>(
        {dest}, static_cast<std::size_t>({count}), {src});
    return static_cast<std::int32_t>(written);'''


@rule(r'^SHAnsiToAnsi$')
def _ansi_to_ansi(c):
    src, dest, count = c.arg(0), c.arg(1), c.arg(2)
    return f'''    if ({src} == nullptr || {dest} == nullptr || {count} <= 0) {{
        return 0;
    }}
    const std::size_t written = text_copy<char>(
        {dest}, static_cast<std::size_t>({count}), {src});
    return static_cast<std::int32_t>(written);'''


@rule(r'^SHUnicodeToAnsi$')
def _unicode_to_ansi(c):
    src, dest, count = c.arg(0), c.arg(1), c.arg(2)
    return f'''    if ({src} == nullptr || {dest} == nullptr || {count} <= 0) {{
        return 0;
    }}
    const std::size_t written = narrow_text({src}, {dest},
                                            static_cast<std::size_t>({count}));
    return static_cast<std::int32_t>(written);'''


@rule(r'^SHStrDup[AW]$')
def _sh_str_dup(c):
    src, out = c.arg(0), c.arg(1)
    # Both spellings answer with a wide string: the narrow form takes a
    # narrow source and converts, the wide form copies. The destination is
    # wide either way, which is why this rule does not use the call's own
    # character type.
    if c.wide:
        length = f'text_len({src})'
        bytes_of = 'sizeof(char16_t)'
        fill = f'    std::memcpy(copy, {src}, (length + 1) * sizeof(char16_t));'
    else:
        length = f'text_len({src})'
        bytes_of = 'sizeof(char16_t)'
        fill = (f'    if (widen_text({src}, copy, length + 1) != length) {{\n'
                f'        guest_free(copy);\n'
                f'        return kEInvalidArg;\n'
                f'    }}')
    return f'''    if ({out} == nullptr) {{
        return kEInvalidArg;
    }}
    *{out} = nullptr;
    if ({src} == nullptr) {{
        return kSOk;  // a null source is answered with a null copy
    }}
    // The copy is a task allocator block on Windows, and a guest frees it
    // with `CoTaskMemFree`; the runtime's allocator is the one both reach,
    // so the block this returns is one its own free accepts.
    const std::size_t length = {length};
    auto* copy = static_cast<char16_t*>(
        k32m_LocalAlloc(0x0040u, (length + 1) * {bytes_of}));
    if (copy == nullptr) {{
        return kEOutOfMemory;
    }}
{fill}
    *{out} = copy;
    return kSOk;'''


@rule(r'^SHStripMneumonic[AW]$')
def _strip_mneumonic(c):
    text = c.arg(0)
    return f'''    if ({text} == nullptr) {{
        return static_cast<{c.c}>(0);
    }}
    // The mnemonic is the first ampersand and the letter after it. A doubled
    // ampersand is the way to spell one, and it is answered rather than
    // removed.
    {c.c}* mark = const_cast<{c.c}*>(find_first_of<{c.c}>({text}, ch_of<{c.c}>('&')));
    if (mark == nullptr || *mark == static_cast<{c.c}>(0)) {{
        return static_cast<{c.c}>(0);
    }}
    const {c.c} following = mark[1];
    if (following == static_cast<{c.c}>('&') || following == static_cast<{c.c}>(0)) {{
        return following;
    }}
    for ({c.c}* p = mark; *p != static_cast<{c.c}>(0); ++p) {{
        *p = p[1];
    }}
    return following;'''


def applies_to(dll, names):
    return dll in ('shlwapi', 'shell32')


def body(dll, name, ret, args, names):
    if dll not in ('shlwapi', 'shell32'):
        return None
    for pattern, builder in RULES:
        if pattern.match(name):
            try:
                return builder(Ctx(name, ret, args, names))
            except Exception:
                return None
    return None

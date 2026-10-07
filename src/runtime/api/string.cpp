// The `Str*` family, as SHLWAPI defines it.
//
// These look like the C library and are not. A bounded copy here takes the
// destination size in characters and always terminates, where `strncpy`
// pads; the compares have a spelling for each combination of "how many
// characters" and "does case matter" that no C library has; the searches
// take a set rather than a substring; and `StrCmpLogicalW` sorts the way
// Explorer sorts, which counts embedded numbers by value so that `file2`
// comes before `file10`.
//
// The signatures are Microsoft's, taken from the headers rather than from a
// guess: `StrChr` takes the character to find as a `WORD` and not an `int`,
// `StrRChr` takes the end of the range it searches as well as the start,
// and `StrTrim`'s second argument is the set of characters to trim rather
// than a flag. A handler with the wrong one of these works on the case the
// author tried and reads the wrong register on the case they did not.
//
// Each body is a template over the character type so that the A and W forms
// cannot drift apart.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <utility>

namespace occ::runtime::winabi {
namespace {

// ------------------------------------------------------------------ scanning

template <typename C>
[[nodiscard]] std::size_t length_of(const C* text) noexcept {
    std::size_t n = 0;
    while (text[n] != static_cast<C>(0)) {
        ++n;
    }
    return n;
}

// The fold the case-insensitive compares use. Windows folds through the
// locale's uppercase table; for the ASCII range every table agrees, and
// outside it the compares below are documented as culture-sensitive anyway.
// Folding the ASCII range here and leaving the rest alone is what makes the
// comparison total rather than dependent on which locale a host happened to
// have.
template <typename C>
[[nodiscard]] constexpr C fold(C c) noexcept {
    return (c >= static_cast<C>('a') && c <= static_cast<C>('z'))
               ? static_cast<C>(c - static_cast<C>('a') + static_cast<C>('A'))
               : c;
}

template <typename C>
[[nodiscard]] bool is_space(C c) noexcept {
    return c == static_cast<C>(' ') || c == static_cast<C>('\t') ||
           c == static_cast<C>('\n') || c == static_cast<C>('\r') ||
           c == static_cast<C>('\f') || c == static_cast<C>('\v');
}

template <typename C>
[[nodiscard]] bool in_set(C c, const C* set) noexcept {
    for (const C* p = set; *p != static_cast<C>(0); ++p) {
        if (*p == c) {
            return true;
        }
    }
    return false;
}

// --------------------------------------------------------------- the compares

// The three-way answer every one of these returns: negative, zero, positive.
//
// A compare that is bounded stops when either side ends or when the bound is
// reached, whichever comes first. A bound of zero compares nothing and
// answers equal, which is what Windows does and what makes `StrCmpN` usable
// with a size that came from a caller. A negative bound compares the whole
// string: the reference answers that way for -1, and `StrCmpI(path, ".exe",
// -1)` in a caller that passes -1 meaning "no limit" reads the same.
template <typename C>
[[nodiscard]] std::int32_t compare_n(const C* a, const C* b, std::int32_t bound,
                                     bool insensitive) noexcept {
    if (bound == 0) {
        return 0;
    }
    std::int32_t seen = 0;
    while (true) {
        if (bound > 0 && seen == bound) {
            return 0;
        }
        C ca = a[seen];
        C cb = b[seen];
        if (insensitive) {
            ca = fold(ca);
            cb = fold(cb);
        }
        if (ca != cb) {
            return ca < cb ? -1 : 1;
        }
        if (ca == static_cast<C>(0)) {
            return 0;
        }
        ++seen;
    }
}

// --------------------------------------------------------------- the searches

// The first character in a set. Answers null when none is found, which is
// the contract the family shares: a search that found nothing answers null
// and never answers "the end of the string".
template <typename C>
[[nodiscard]] const C* find_any(const C* text, const C* set) noexcept {
    for (const C* p = text; *p != static_cast<C>(0); ++p) {
        if (in_set(*p, set)) {
            return p;
        }
    }
    return nullptr;
}

// The first character *not* in a set.
template <typename C>
[[nodiscard]] std::int32_t span_not_in(const C* text, const C* set) noexcept {
    std::int32_t n = 0;
    while (text[n] != static_cast<C>(0) && !in_set(text[n], set)) {
        ++n;
    }
    return n;
}

// A first character, from the start or the end, with an optional bound.
template <typename C>
[[nodiscard]] const C* find_char_forward(const C* start, C match,
                                         std::int32_t bound) noexcept {
    std::int32_t seen = 0;
    for (const C* p = start; *p != static_cast<C>(0); ++p) {
        if (bound > 0 && seen == bound) {
            return nullptr;
        }
        if (*p == match) {
            return p;
        }
        ++seen;
    }
    return nullptr;
}

template <typename C>
[[nodiscard]] const C* find_char_forward_i(const C* start, C match,
                                           std::int32_t bound) noexcept {
    const C wanted = fold(match);
    std::int32_t seen = 0;
    for (const C* p = start; *p != static_cast<C>(0); ++p) {
        if (bound > 0 && seen == bound) {
            return nullptr;
        }
        if (fold(*p) == wanted) {
            return p;
        }
        ++seen;
    }
    return nullptr;
}

// The last character, searched backwards from `end` -- which is either the
// caller's own bound or the terminator. The range is half-open the way
// Windows documents it: `end` itself is one past the last character
// searched.
template <typename C>
[[nodiscard]] const C* find_char_backward(const C* start, const C* end,
                                          C match) noexcept {
    const C* stop = end != nullptr ? end : start + length_of(start);
    if (stop <= start) {
        return nullptr;
    }
    for (const C* p = stop; p != start; --p) {
        if (p[-1] == match) {
            return p - 1;
        }
    }
    return nullptr;
}

template <typename C>
[[nodiscard]] const C* find_char_backward_i(const C* start, const C* end,
                                            C match) noexcept {
    const C wanted = fold(match);
    const C* stop = end != nullptr ? end : start + length_of(start);
    if (stop <= start) {
        return nullptr;
    }
    for (const C* p = stop; p != start; --p) {
        if (fold(p[-1]) == wanted) {
            return p - 1;
        }
    }
    return nullptr;
}

// A substring, case-sensitive or not, with an optional bound on how far the
// *needle* may extend. An empty needle is found at the start, which is what
// Windows answers and what makes this usable in a loop that advances by the
// match length.
template <typename C>
[[nodiscard]] const C* find_substring(const C* hay, const C* needle,
                                      std::int32_t needle_bound,
                                      bool insensitive) noexcept {
    if (needle[0] == static_cast<C>(0)) {
        return hay;
    }
    for (const C* p = hay; *p != static_cast<C>(0); ++p) {
        const C* h = p;
        const C* n = needle;
        std::int32_t taken = 0;
        while (true) {
            if (needle_bound > 0 && taken == needle_bound) {
                return p;  // the bound was reached with every character equal
            }
            if (*n == static_cast<C>(0)) {
                return p;
            }
            if (*h == static_cast<C>(0)) {
                break;
            }
            const C a = insensitive ? fold(*h) : *h;
            const C b = insensitive ? fold(*n) : *n;
            if (a != b) {
                break;
            }
            ++h;
            ++n;
            ++taken;
        }
    }
    return nullptr;
}

// The last occurrence of a substring at or before a caller-supplied end. The
// searches run backwards from there rather than collecting matches, because
// the answer is the last one and the first found from the end is it. A null
// end means the end of the string, which is what the callers that do not
// care pass.
template <typename C>
[[nodiscard]] const C* find_substring_backward(const C* hay, const C* needle,
                                               const C* limit,
                                               bool insensitive) noexcept {
    const C* end = limit != nullptr ? limit : hay + length_of(hay);
    const std::size_t hay_len = static_cast<std::size_t>(end - hay);
    const std::size_t needle_len = length_of(needle);
    if (needle_len == 0) {
        return end;
    }
    if (needle_len > hay_len) {
        return nullptr;
    }
    for (std::size_t start = hay_len - needle_len + 1; start != 0; --start) {
        const std::size_t at = start - 1;
        bool same = true;
        for (std::size_t k = 0; k < needle_len; ++k) {
            const C a = insensitive ? fold(hay[at + k]) : hay[at + k];
            const C b = insensitive ? fold(needle[k]) : needle[k];
            if (a != b) {
                same = false;
                break;
            }
        }
        if (same) {
            return hay + at;
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------- the copies

// A bounded copy that always terminates. `StrCpyN` copies at most
// `capacity - 1` characters and terminates; a `capacity` of zero is a
// refusal, not a request to write at the start of the buffer, because the
// caller has said the buffer has no room for a terminator.
template <typename C>
void copy_bounded(C* dest, const C* source, std::int32_t capacity) noexcept {
    if (capacity <= 0) {
        return;
    }
    std::int32_t written = 0;
    while (written < capacity - 1 && source[written] != static_cast<C>(0)) {
        dest[written] = source[written];
        ++written;
    }
    dest[written] = static_cast<C>(0);
}

// A bounded concatenation. `StrCatBuff` is the one that takes the total
// size of the destination buffer rather than the room left in it, which is
// the difference a caller gets wrong: the count below starts from what is
// already there.
template <typename C>
void append_bounded(C* dest, const C* source, std::int32_t capacity) noexcept {
    if (capacity <= 0) {
        return;
    }
    std::int32_t at = 0;
    while (at < capacity && dest[at] != static_cast<C>(0)) {
        ++at;
    }
    if (at >= capacity) {
        // The destination was not terminated inside the buffer it was given
        // a size for. Writing at the end would be writing where the caller
        // said not to, so the copy is refused and the buffer is left alone.
        return;
    }
    std::int32_t written = at;
    const C* p = source;
    while (written < capacity - 1 && *p != static_cast<C>(0)) {
        dest[written] = *p;
        ++written;
        ++p;
    }
    dest[written] = static_cast<C>(0);
}

// `StrCatChainW` appends at an offset the caller carries between calls, and
// its interesting case is the offset being out of range: a caller that
// passes a stale offset gets the append refused rather than a write past the
// buffer. Answers the new offset, which is what the caller stores back.
template <typename C>
[[nodiscard]] std::uint32_t cat_chain(C* dest, std::uint32_t capacity,
                                      std::uint32_t at,
                                      const C* source) noexcept {
    if (dest == nullptr || capacity == 0) {
        return 0;
    }
    // `-1` asks for the end of what is already there.
    if (at == static_cast<std::uint32_t>(-1)) {
        at = 0;
        while (at < capacity && dest[at] != static_cast<C>(0)) {
            ++at;
        }
    }
    if (at >= capacity) {
        return capacity - 1;
    }
    std::uint32_t written = at;
    const C* p = source;
    while (written < capacity - 1 && *p != static_cast<C>(0)) {
        dest[written] = *p;
        ++written;
        ++p;
    }
    dest[written] = static_cast<C>(0);
    return written;
}

// ---------------------------------------------------------------- the trims

// `StrTrim` removes the characters named by the second argument from both
// ends. It is not a whitespace trim and the second argument is not a flag:
// `StrTrimA(s, " \t")` trims spaces and tabs, and a caller that wants the
// Windows default passes exactly that set.
template <typename C>
void trim_set(C* text, const C* set) noexcept {
    if (set == nullptr || set[0] == static_cast<C>(0)) {
        return;
    }
    C* start = text;
    while (*start != static_cast<C>(0) && in_set(*start, set)) {
        ++start;
    }
    C* end = start + length_of(start);
    while (end != start && in_set(end[-1], set)) {
        --end;
    }
    C* out = text;
    for (C* p = start; p != end; ++p) {
        *out++ = *p;
    }
    *out = static_cast<C>(0);
}

// --------------------------------------------------------------- the parses

// `StrToInt` and its relatives. The accepted grammar is a sign and then
// digits: hex digits when the caller asked for hex and a `0x` prefix is
// present, decimal digits otherwise. The trailing text is ignored, which is
// documented and is why a caller cannot use this to validate input; what it
// can use it for is the leading number of a string, which is what a command
// line is full of.
//
// Two things the reference settles and a reader of the documentation would
// not guess. Leading whitespace is not skipped, so `"  -45"` is not a number
// and answers zero -- the reference answers zero -- which matters because a
// caller that trimmed its input already gets the number and a caller that
// did not gets a zero rather than a silently wrong value. And `StrToInt`
// itself does not accept the `0x` form: `"0x1F"` parses as the decimal `0`
// followed by text, so it answers zero and reports success, and a caller
// that wants the hex form asks for it through `StrToIntEx` with the flag.
template <typename C>
[[nodiscard]] bool parse_integer(const C* text, bool allow_hex,
                                 std::int64_t& value) noexcept {
    const C* p = text;
    bool negative = false;
    if (*p == static_cast<C>('+')) {
        ++p;
    } else if (*p == static_cast<C>('-')) {
        negative = true;
        ++p;
    }
    // A sign with nothing after it is not a number.
    if (*p == static_cast<C>(0)) {
        return false;
    }
    unsigned base = 10;
    if (allow_hex && p[0] == static_cast<C>('0') &&
        (p[1] == static_cast<C>('x') || p[1] == static_cast<C>('X'))) {
        base = 16;
        p += 2;
        if (*p == static_cast<C>(0)) {
            return false;
        }
    }
    bool any = false;
    std::uint64_t acc = 0;
    // The accumulate saturates rather than wrapping: a caller that hands
    // this a number too large for the type it asked for gets the largest
    // answer rather than a small one, and a small one is the answer a
    // program cannot tell from a real parse.
    constexpr std::uint64_t kCeiling = 0x7FFFFFFFFFFFFFFFULL;
    while (*p != static_cast<C>(0)) {
        unsigned digit = 0;
        const C c = *p;
        if (c >= static_cast<C>('0') && c <= static_cast<C>('9')) {
            digit = static_cast<unsigned>(c - static_cast<C>('0'));
        } else if (c >= static_cast<C>('a') && c <= static_cast<C>('f')) {
            digit = static_cast<unsigned>(c - static_cast<C>('a')) + 10;
        } else if (c >= static_cast<C>('A') && c <= static_cast<C>('F')) {
            digit = static_cast<unsigned>(c - static_cast<C>('A')) + 10;
        } else {
            break;
        }
        if (digit >= base) {
            break;
        }
        if (acc > (kCeiling - digit) / base) {
            acc = kCeiling;
        } else {
            acc = acc * base + digit;
        }
        any = true;
        ++p;
    }
    if (!any) {
        return false;
    }
    value = negative ? -static_cast<std::int64_t>(acc)
                     : static_cast<std::int64_t>(acc);
    return true;
}

// --------------------------------------------------------------- the sort

// `StrCmpLogicalW`, the comparison Explorer uses for file names.
//
// It is not a string compare. A run of digits in either string is read as a
// number and compared by value, so `2` sorts before `10` where a character
// compare would put `10` first; a run with leading zeros is compared by
// length first so that `01` sorts before `1` rather than equal to it; and
// everything outside the digits is compared by code unit, case
// insensitively.
//
// This is the one function in the family whose answer no C library can give,
// which is why it is written out rather than forwarded. Wine implements the
// same rules in `dlls/shlwapi/string.c`, and the shape below follows them
// because the rules are Microsoft's and not Wine's -- the leading-zero tie
// break and the "digits only count when they start a number" rule are both
// documented behaviour that a caller can see in Explorer's ordering.
template <typename C>
[[nodiscard]] bool is_digit(C c) noexcept {
    return c >= static_cast<C>('0') && c <= static_cast<C>('9');
}

template <typename C>
[[nodiscard]] std::int32_t compare_logical(const C* a, const C* b) noexcept {
    while (*a != static_cast<C>(0) && *b != static_cast<C>(0)) {
        if (is_digit(*a) && is_digit(*b)) {
            // Skip leading zeros, counting them: the run with fewer is the
            // smaller number when the values are equal.
            const C* za = a;
            while (*za == static_cast<C>('0')) {
                ++za;
            }
            const C* zb = b;
            while (*zb == static_cast<C>('0')) {
                ++zb;
            }
            const C* enda = za;
            while (is_digit(*enda)) {
                ++enda;
            }
            const C* endb = zb;
            while (is_digit(*endb)) {
                ++endb;
            }
            const std::size_t la = static_cast<std::size_t>(enda - za);
            const std::size_t lb = static_cast<std::size_t>(endb - zb);
            if (la != lb) {
                // More digits is a larger number. A run of nothing but zeros
                // counts as no digits, so `0` and `00` fall through to the
                // case below rather than being ordered by how many zeros
                // they were written with.
                return la < lb ? -1 : 1;
            }
            for (std::size_t k = 0; k < la; ++k) {
                if (za[k] != zb[k]) {
                    return za[k] < zb[k] ? -1 : 1;
                }
            }
            // Equal values, including the two all-zero runs that reach here
            // with no digits each. The reference does not order those apart,
            // so neither does this.
            a = enda;
            b = endb;
            continue;
        }
        const C ca = fold(*a);
        const C cb = fold(*b);
        if (ca != cb) {
            return ca < cb ? -1 : 1;
        }
        ++a;
        ++b;
    }
    const C ca = fold(*a);
    const C cb = fold(*b);
    if (ca == cb) {
        return 0;
    }
    return ca < cb ? -1 : 1;
}

}  // namespace

// ---------------------------------------------------------------------------
// ABI entry points
// ---------------------------------------------------------------------------
//
// One per function, and nothing else. The signatures are the headers'; the
// bodies are the templates above.

extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCSpnA(
    const char* text, const char* set) noexcept {
    return span_not_in(text, set);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCSpnW(
    const char16_t* text, const char16_t* set) noexcept {
    return span_not_in(text, set);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCSpnIA(
    const char* text, const char* set) noexcept {
    return span_not_in(text, set);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCSpnIW(
    const char16_t* text, const char16_t* set) noexcept {
    return span_not_in(text, set);
}

extern "C" __attribute__((ms_abi)) char* sw_StrChrA(const char* text,
                                                    std::uint16_t match) noexcept {
    return const_cast<char*>(find_char_forward(text, static_cast<char>(match), 0));
}
extern "C" __attribute__((ms_abi)) char16_t* sw_StrChrW(
    const char16_t* text, char16_t match) noexcept {
    return const_cast<char16_t*>(find_char_forward(text, match, 0));
}
extern "C" __attribute__((ms_abi)) char* sw_StrChrIA(
    const char* text, std::uint16_t match) noexcept {
    return const_cast<char*>(
        find_char_forward_i(text, static_cast<char>(match), 0));
}
extern "C" __attribute__((ms_abi)) char16_t* sw_StrChrIW(
    const char16_t* text, char16_t match) noexcept {
    return const_cast<char16_t*>(find_char_forward_i(text, match, 0));
}
extern "C" __attribute__((ms_abi)) char16_t* sw_StrChrNW(
    const char16_t* text, char16_t match, std::uint32_t bound) noexcept {
    return const_cast<char16_t*>(
        find_char_forward(text, match, static_cast<std::int32_t>(bound)));
}

extern "C" __attribute__((ms_abi)) char* sw_StrRChrA(const char* text,
                                                     const char* end,
                                                     std::uint16_t match)
    noexcept {
    return const_cast<char*>(find_char_backward(
        text, end, static_cast<char>(match)));
}
extern "C" __attribute__((ms_abi)) char16_t* sw_StrRChrW(
    const char16_t* text, const char16_t* end, char16_t match) noexcept {
    return const_cast<char16_t*>(find_char_backward(text, end, match));
}
extern "C" __attribute__((ms_abi)) char* sw_StrRChrIA(const char* text,
                                                      const char* end,
                                                      std::uint16_t match)
    noexcept {
    return const_cast<char*>(
        find_char_backward_i(text, end, static_cast<char>(match)));
}
extern "C" __attribute__((ms_abi)) char16_t* sw_StrRChrIW(
    const char16_t* text, const char16_t* end, char16_t match) noexcept {
    return const_cast<char16_t*>(find_char_backward_i(text, end, match));
}

extern "C" __attribute__((ms_abi)) char* sw_StrPBrkA(const char* text,
                                                     const char* set) noexcept {
    return const_cast<char*>(find_any(text, set));
}
extern "C" __attribute__((ms_abi)) char16_t* sw_StrPBrkW(
    const char16_t* text, const char16_t* set) noexcept {
    return const_cast<char16_t*>(find_any(text, set));
}

extern "C" __attribute__((ms_abi)) std::int32_t sw_StrSpnA(
    const char* text, const char* set) noexcept {
    std::int32_t n = 0;
    while (text[n] != '\0' && in_set(text[n], set)) {
        ++n;
    }
    return n;
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrSpnW(
    const char16_t* text, const char16_t* set) noexcept {
    std::int32_t n = 0;
    while (text[n] != u'\0' && in_set(text[n], set)) {
        ++n;
    }
    return n;
}

extern "C" __attribute__((ms_abi)) char* sw_StrStrA(const char* hay,
                                                    const char* needle) noexcept {
    return const_cast<char*>(find_substring(hay, needle, 0, false));
}
extern "C" __attribute__((ms_abi)) char16_t* sw_StrStrW(
    const char16_t* hay, const char16_t* needle) noexcept {
    return const_cast<char16_t*>(find_substring(hay, needle, 0, false));
}
extern "C" __attribute__((ms_abi)) char* sw_StrStrIA(const char* hay,
                                                     const char* needle) noexcept {
    return const_cast<char*>(find_substring(hay, needle, 0, true));
}
extern "C" __attribute__((ms_abi)) char16_t* sw_StrStrIW(
    const char16_t* hay, const char16_t* needle) noexcept {
    return const_cast<char16_t*>(find_substring(hay, needle, 0, true));
}
extern "C" __attribute__((ms_abi)) char16_t* sw_StrStrNW(
    const char16_t* hay, const char16_t* needle, std::uint32_t bound) noexcept {
    return const_cast<char16_t*>(
        find_substring(hay, needle, static_cast<std::int32_t>(bound), false));
}
extern "C" __attribute__((ms_abi)) char16_t* sw_StrStrNIW(
    const char16_t* hay, const char16_t* needle, std::uint32_t bound) noexcept {
    return const_cast<char16_t*>(
        find_substring(hay, needle, static_cast<std::int32_t>(bound), true));
}

extern "C" __attribute__((ms_abi)) char* sw_StrRStrIA(const char* hay,
                                                      const char* last,
                                                      const char* needle)
    noexcept {
    return const_cast<char*>(find_substring_backward(hay, needle, last, true));
}
extern "C" __attribute__((ms_abi)) char16_t* sw_StrRStrIW(
    const char16_t* hay, const char16_t* last, const char16_t* needle) noexcept {
    return const_cast<char16_t*>(
        find_substring_backward(hay, needle, last, true));
}

extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpW(
    const char16_t* a, const char16_t* b) noexcept {
    return compare_n(a, b, -1, false);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpIW(
    const char16_t* a, const char16_t* b) noexcept {
    return compare_n(a, b, -1, true);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpCA(
    const char* a, const char* b) noexcept {
    return compare_n(a, b, -1, false);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpCW(
    const char16_t* a, const char16_t* b) noexcept {
    return compare_n(a, b, -1, false);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpICA(
    const char* a, const char* b) noexcept {
    return compare_n(a, b, -1, true);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpICW(
    const char16_t* a, const char16_t* b) noexcept {
    return compare_n(a, b, -1, true);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpNA(
    const char* a, const char* b, std::int32_t bound) noexcept {
    return compare_n(a, b, bound, false);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpNW(
    const char16_t* a, const char16_t* b, std::int32_t bound) noexcept {
    return compare_n(a, b, bound, false);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpNCA(
    const char* a, const char* b, std::int32_t bound) noexcept {
    return compare_n(a, b, bound, false);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpNCW(
    const char16_t* a, const char16_t* b, std::int32_t bound) noexcept {
    return compare_n(a, b, bound, false);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpNIA(
    const char* a, const char* b, std::int32_t bound) noexcept {
    return compare_n(a, b, bound, true);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpNIW(
    const char16_t* a, const char16_t* b, std::int32_t bound) noexcept {
    return compare_n(a, b, bound, true);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpNICA(
    const char* a, const char* b, std::int32_t bound) noexcept {
    return compare_n(a, b, bound, true);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpNICW(
    const char16_t* a, const char16_t* b, std::int32_t bound) noexcept {
    return compare_n(a, b, bound, true);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpLogicalW(
    const char16_t* a, const char16_t* b) noexcept {
    return compare_logical(a, b);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrIsIntlEqualA(
    std::int32_t case_sensitive, const char* a, const char* b,
    std::int32_t bound) noexcept {
    return compare_n(a, b, bound, case_sensitive == 0);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrIsIntlEqualW(
    std::int32_t case_sensitive, const char16_t* a, const char16_t* b,
    std::int32_t bound) noexcept {
    return compare_n(a, b, bound, case_sensitive == 0);
}

extern "C" __attribute__((ms_abi)) char16_t* sw_StrCpyNW(char16_t* dest,
                                                         const char16_t* source,
                                                         std::int32_t capacity)
    noexcept {
    copy_bounded(dest, source, capacity);
    return dest;
}
extern "C" __attribute__((ms_abi)) char* sw_StrCpyNXA(char* dest,
                                                      const char* source,
                                                      std::int32_t capacity)
    noexcept {
    copy_bounded(dest, source, capacity);
    return dest;
}
extern "C" __attribute__((ms_abi)) char16_t* sw_StrCpyNXW(
    char16_t* dest, const char16_t* source, std::int32_t capacity) noexcept {
    copy_bounded(dest, source, capacity);
    return dest;
}

extern "C" __attribute__((ms_abi)) char* sw_StrCatBuffA(char* dest,
                                                        const char* source,
                                                        std::int32_t capacity)
    noexcept {
    append_bounded(dest, source, capacity);
    return dest;
}
extern "C" __attribute__((ms_abi)) char16_t* sw_StrCatBuffW(
    char16_t* dest, const char16_t* source, std::int32_t capacity) noexcept {
    append_bounded(dest, source, capacity);
    return dest;
}
extern "C" __attribute__((ms_abi)) std::uint32_t sw_StrCatChainW(
    char16_t* dest, std::uint32_t capacity, std::uint32_t at,
    const char16_t* source) noexcept {
    return cat_chain(dest, capacity, at, source);
}

extern "C" __attribute__((ms_abi)) char* sw_StrDupA(const char* text) noexcept {
    // The allocation is the process heap, which is what makes the result
    // freeable by the same handle `LocalFree` closes over. A copy made with
    // the host's allocator would be freed by the host's `free` and leak for
    // a guest that does what the documentation says.
    if (text == nullptr) {
        return nullptr;
    }
    const std::size_t bytes = length_of(text) + 1;
    void* block = heap_alloc(0, bytes);
    if (block == nullptr) {
        return nullptr;
    }
    char* out = static_cast<char*>(block);
    for (std::size_t k = 0; k < bytes; ++k) {
        out[k] = text[k];
    }
    return out;
}
extern "C" __attribute__((ms_abi)) char16_t* sw_StrDupW(
    const char16_t* text) noexcept {
    if (text == nullptr) {
        return nullptr;
    }
    const std::size_t units = length_of(text) + 1;
    void* block = heap_alloc(0, units * sizeof(char16_t));
    if (block == nullptr) {
        return nullptr;
    }
    auto* out = static_cast<char16_t*>(block);
    for (std::size_t k = 0; k < units; ++k) {
        out[k] = text[k];
    }
    return out;
}

extern "C" __attribute__((ms_abi)) void sw_StrTrimA(char* text,
                                                    const char* set) noexcept {
    trim_set(text, set);
}
extern "C" __attribute__((ms_abi)) void sw_StrTrimW(char16_t* text,
                                                    const char16_t* set) noexcept {
    trim_set(text, set);
}

extern "C" __attribute__((ms_abi)) std::int32_t sw_StrToIntA(
    const char* text) noexcept {
    std::int64_t value = 0;
    if (!parse_integer(text, false, value)) {
        return 0;
    }
    return static_cast<std::int32_t>(value);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrToIntW(
    const char16_t* text) noexcept {
    std::int64_t value = 0;
    if (!parse_integer(text, false, value)) {
        return 0;
    }
    return static_cast<std::int32_t>(value);
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrToIntExA(
    const char* text, std::int32_t flags, std::int32_t* out) noexcept {
    std::int64_t value = 0;
    // The flag that matters is the one asking for the `0x` form; without it
    // such a string is not a number and the call fails, which is the
    // difference a caller relies on to tell a decimal from a hexadecimal.
    const bool ok = parse_integer(text, (flags & 1) != 0, value);
    if (!ok) {
        return 0;
    }
    if (out != nullptr) {
        *out = static_cast<std::int32_t>(value);
    }
    return 1;
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrToIntExW(
    const char16_t* text, std::int32_t flags, std::int32_t* out) noexcept {
    std::int64_t value = 0;
    const bool ok = parse_integer(text, (flags & 1) != 0, value);
    if (!ok) {
        return 0;
    }
    if (out != nullptr) {
        *out = static_cast<std::int32_t>(value);
    }
    return 1;
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrToInt64ExA(
    const char* text, std::int32_t flags, std::int64_t* out) noexcept {
    std::int64_t value = 0;
    const bool ok = parse_integer(text, (flags & 1) != 0, value);
    if (!ok) {
        return 0;
    }
    if (out != nullptr) {
        *out = value;
    }
    return 1;
}
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrToInt64ExW(
    const char16_t* text, std::int32_t flags, std::int64_t* out) noexcept {
    std::int64_t value = 0;
    const bool ok = parse_integer(text, (flags & 1) != 0, value);
    if (!ok) {
        return 0;
    }
    if (out != nullptr) {
        *out = value;
    }
    return 1;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// The ten names in this family that kernelbase exports rather than shlwapi.
//
// The split is not alphabetical and it is not obvious: the `StrCmpC` and
// `StrCmpNIC` spellings, which are the "C" forms of the compares, and the
// `StrCpyNX` pair all live in kernelbase, while `StrCmp`, `StrCmpI`,
// `StrCmpN`, `StrCmpNI` and `StrCpyN` live in shlwapi. A guest that imports
// the wrong one from the wrong module gets a module-not-found rather than a
// wrong answer, which is why the module a name is registered under has to be
// the module that exports it.
void add_string_kernelbase(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("StrCmpCA", reinterpret_cast<void*>(&sw_StrCmpCA));
    e("StrCmpCW", reinterpret_cast<void*>(&sw_StrCmpCW));
    e("StrCmpICA", reinterpret_cast<void*>(&sw_StrCmpICA));
    e("StrCmpICW", reinterpret_cast<void*>(&sw_StrCmpICW));
    e("StrCmpNCA", reinterpret_cast<void*>(&sw_StrCmpNCA));
    e("StrCmpNCW", reinterpret_cast<void*>(&sw_StrCmpNCW));
    e("StrCmpNICA", reinterpret_cast<void*>(&sw_StrCmpNICA));
    e("StrCmpNICW", reinterpret_cast<void*>(&sw_StrCmpNICW));
    e("StrCpyNXA", reinterpret_cast<void*>(&sw_StrCpyNXA));
    e("StrCpyNXW", reinterpret_cast<void*>(&sw_StrCpyNXW));
}

void add_string_shlwapi(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("StrCatBuffA", reinterpret_cast<void*>(&sw_StrCatBuffA));
    e("StrCatBuffW", reinterpret_cast<void*>(&sw_StrCatBuffW));
    e("StrCatChainW", reinterpret_cast<void*>(&sw_StrCatChainW));
    e("StrChrA", reinterpret_cast<void*>(&sw_StrChrA));
    e("StrChrW", reinterpret_cast<void*>(&sw_StrChrW));
    e("StrChrIA", reinterpret_cast<void*>(&sw_StrChrIA));
    e("StrChrIW", reinterpret_cast<void*>(&sw_StrChrIW));
    e("StrChrNW", reinterpret_cast<void*>(&sw_StrChrNW));
    e("StrCmpIW", reinterpret_cast<void*>(&sw_StrCmpIW));
    e("StrCmpLogicalW", reinterpret_cast<void*>(&sw_StrCmpLogicalW));
    e("StrCmpNA", reinterpret_cast<void*>(&sw_StrCmpNA));
    e("StrCmpNW", reinterpret_cast<void*>(&sw_StrCmpNW));
    e("StrCmpNIA", reinterpret_cast<void*>(&sw_StrCmpNIA));
    e("StrCmpNIW", reinterpret_cast<void*>(&sw_StrCmpNIW));
    e("StrCmpW", reinterpret_cast<void*>(&sw_StrCmpW));
    e("StrCpyNW", reinterpret_cast<void*>(&sw_StrCpyNW));
    e("StrCSpnA", reinterpret_cast<void*>(&sw_StrCSpnA));
    e("StrCSpnW", reinterpret_cast<void*>(&sw_StrCSpnW));
    e("StrCSpnIA", reinterpret_cast<void*>(&sw_StrCSpnIA));
    e("StrCSpnIW", reinterpret_cast<void*>(&sw_StrCSpnIW));
    e("StrDupA", reinterpret_cast<void*>(&sw_StrDupA));
    e("StrDupW", reinterpret_cast<void*>(&sw_StrDupW));
    e("StrIsIntlEqualA", reinterpret_cast<void*>(&sw_StrIsIntlEqualA));
    e("StrIsIntlEqualW", reinterpret_cast<void*>(&sw_StrIsIntlEqualW));
    e("StrPBrkA", reinterpret_cast<void*>(&sw_StrPBrkA));
    e("StrPBrkW", reinterpret_cast<void*>(&sw_StrPBrkW));
    e("StrRChrA", reinterpret_cast<void*>(&sw_StrRChrA));
    e("StrRChrW", reinterpret_cast<void*>(&sw_StrRChrW));
    e("StrRChrIA", reinterpret_cast<void*>(&sw_StrRChrIA));
    e("StrRChrIW", reinterpret_cast<void*>(&sw_StrRChrIW));
    e("StrRStrIA", reinterpret_cast<void*>(&sw_StrRStrIA));
    e("StrRStrIW", reinterpret_cast<void*>(&sw_StrRStrIW));
    e("StrSpnA", reinterpret_cast<void*>(&sw_StrSpnA));
    e("StrSpnW", reinterpret_cast<void*>(&sw_StrSpnW));
    e("StrStrA", reinterpret_cast<void*>(&sw_StrStrA));
    e("StrStrW", reinterpret_cast<void*>(&sw_StrStrW));
    e("StrStrIA", reinterpret_cast<void*>(&sw_StrStrIA));
    e("StrStrIW", reinterpret_cast<void*>(&sw_StrStrIW));
    e("StrStrNIW", reinterpret_cast<void*>(&sw_StrStrNIW));
    e("StrStrNW", reinterpret_cast<void*>(&sw_StrStrNW));
    e("StrToIntA", reinterpret_cast<void*>(&sw_StrToIntA));
    e("StrToIntW", reinterpret_cast<void*>(&sw_StrToIntW));
    e("StrToIntExA", reinterpret_cast<void*>(&sw_StrToIntExA));
    e("StrToIntExW", reinterpret_cast<void*>(&sw_StrToIntExW));
    e("StrToInt64ExA", reinterpret_cast<void*>(&sw_StrToInt64ExA));
    e("StrToInt64ExW", reinterpret_cast<void*>(&sw_StrToInt64ExW));
    e("StrTrimA", reinterpret_cast<void*>(&sw_StrTrimA));
    e("StrTrimW", reinterpret_cast<void*>(&sw_StrTrimW));
}

}  // namespace occ::runtime::winabi

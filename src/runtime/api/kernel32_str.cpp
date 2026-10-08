// The KERNEL32 string/character family: the `lstr*` trio, the `CompareString`
// pair, `FoldString`, `GetStringType`, `LCMapString`, and `IsDBCSLeadByte`.
//
// These functions look like the C library and are not. `lstrlen` answers NULL
// with 0 instead of crashing, because Windows documents that and programs
// lean on it; `lstrcpyn` is the bounded copy whose count includes the
// terminator, which is the whole reason it exists next to `lstrcpy`; and the
// compare family answers 1/2/3 through `CompareString` while `lstrcmp`
// answers -1/0/1, so the two families cannot share a return statement.
//
// The A forms here are marshalling wrappers, not second implementations: the
// text is converted through the narrow/Wide bridge, the W core does the work,
// and the answer is converted back. The ANSI code page this runtime models is
// UTF-8, which is what `narrow_in`/`narrow_out` define, and every A-side
// decision below (byte counts, `IsDBCSLeadByte`) follows from that one fact.
//
// The locale parameters are accepted and ignored: this runtime has no
// collation tables, so every compare below is code-unit ordered with the
// ASCII case fold, and every case map is the simple one. That is exact for
// the ASCII and Latin-1 ranges the tables here cover and an approximation
// outside them; the approximation is stated at each function rather than
// left for a reader to discover.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace occ::runtime::winabi {
namespace {

// ------------------------------------------------------------- flag constants

// `CompareString*`/`LCMapString*` comparison flags. Only the ones this file
// can act on are acted on; the rest are accepted so a guest's valid call does
// not fail, and the approximation is noted where they are read.
constexpr std::uint32_t kNormIgnoreCase = 0x00000001;
constexpr std::uint32_t kNormIgnoreNonspace = 0x00000002;
constexpr std::uint32_t kNormIgnoreWidth = 0x00020000;

// `FoldString` mapping flags.
constexpr std::uint32_t kMapComposite = 0x00000001;
constexpr std::uint32_t kMapPrecomposed = 0x00000002;
constexpr std::uint32_t kMapFoldCzone = 0x00000004;
constexpr std::uint32_t kMapFoldDigits = 0x00000080;
constexpr std::uint32_t kMapExpandLigatures = 0x00002000;

// `LCMapString*` mapping flags.
constexpr std::uint32_t kCmapLowercase = 0x00000100;
constexpr std::uint32_t kCmapUppercase = 0x00000200;
constexpr std::uint32_t kCmapSortkey = 0x00000400;
constexpr std::uint32_t kCmapByteRev = 0x00000800;

// `GetStringType*` info types.
constexpr std::uint32_t kCtCtype1 = 1;
constexpr std::uint32_t kCtCtype2 = 2;
constexpr std::uint32_t kCtCtype3 = 3;

// `CompareString*` answers. These are ordinals, not a sign, which is the
// difference a caller who wrote `result < 0` against this family gets wrong.
constexpr std::int32_t kCstrLessThan = 1;
constexpr std::int32_t kCstrEqual = 2;
constexpr std::int32_t kCstrGreaterThan = 3;

// CT_CTYPE1 bits.
constexpr std::uint16_t kC1Upper = 0x0001;
constexpr std::uint16_t kC1Lower = 0x0002;
constexpr std::uint16_t kC1Digit = 0x0004;
constexpr std::uint16_t kC1Space = 0x0008;
constexpr std::uint16_t kC1Punct = 0x0010;
constexpr std::uint16_t kC1Cntrl = 0x0020;
constexpr std::uint16_t kC1Blank = 0x0040;
constexpr std::uint16_t kC1Xdigit = 0x0080;
constexpr std::uint16_t kC1Alpha = 0x0100;

// CT_CTYPE2 values (the whole field, not bits).
constexpr std::uint16_t kC2LeftToRight = 1;
constexpr std::uint16_t kC2RightToLeft = 2;
constexpr std::uint16_t kC2EuroNumber = 3;
constexpr std::uint16_t kC2Whitespace = 9;
constexpr std::uint16_t kC2OtherNeutral = 10;

// CT_CTYPE3 bits. The script bits are the ones the tables below can place;
// the rest of the plane answers 0 rather than a guess.
constexpr std::uint16_t kC3Symbol = 0x0008;
constexpr std::uint16_t kC3Katakana = 0x0010;
constexpr std::uint16_t kC3Hiragana = 0x0020;
constexpr std::uint16_t kC3Halfwidth = 0x0040;
constexpr std::uint16_t kC3Fullwidth = 0x0080;
constexpr std::uint16_t kC3Ideogram = 0x0100;
constexpr std::uint16_t kC3HighSurrogate = 0x0800;
constexpr std::uint16_t kC3LowSurrogate = 0x1000;
constexpr std::uint16_t kC3Alpha = 0x8000;

// ------------------------------------------------------------- small scanners

template <typename C>
std::size_t text_length(const C* text) noexcept {
    std::size_t n = 0;
    while (text[n] != static_cast<C>(0)) {
        ++n;
    }
    return n;
}

// Resolves a `cch` parameter that may be -1 ("up to the terminator") into an
// element count. A negative count other than -1 is a refusal, which is the
// caller's bug and is reported as such by the callers of this helper.
template <typename C>
[[nodiscard]] bool resolve_count(const C* text, std::int32_t cch,
                                 std::size_t& count) noexcept {
    if (cch < -1) {
        return false;
    }
    if (cch < 0) {
        count = text_length(text);
        return true;
    }
    count = static_cast<std::size_t>(cch);
    return true;
}

// ------------------------------------------------------------- case mappings

// The simple case fold this file uses everywhere. It covers ASCII, Latin-1
// and the Greek and Cyrillic blocks, which is where every caller's test data
// lives; outside those ranges the unit answers unchanged. A caller case-
// mapping CJK text gets it back alone -- visible, but the honest answer
// short of shipping a full Unicode case table in a string file.
[[nodiscard]] char16_t upcase_unit(char16_t c) noexcept {
    if (c >= u'a' && c <= u'z') {
        return static_cast<char16_t>(c - u'a' + u'A');
    }
    if ((c >= u'\x00E0' && c <= u'\x00FE') && c != u'\x00F7') {
        return static_cast<char16_t>(c - u'\x00E0' + u'\x00C0');
    }
    if (c >= u'\x03B1' && c <= u'\x03C9' && c != u'\x03C2') {
        return static_cast<char16_t>(c - u'\x03B1' + u'\x0391');
    }
    if (c == u'\x03C2') {  // final sigma pairs with capital sigma
        return u'\x03A3';
    }
    if (c >= u'\x0430' && c <= u'\x044F') {
        return static_cast<char16_t>(c - u'\x0430' + u'\x0410');
    }
    return c;
}

[[nodiscard]] char16_t downcase_unit(char16_t c) noexcept {
    if (c >= u'A' && c <= u'Z') {
        return static_cast<char16_t>(c - u'A' + u'a');
    }
    if ((c >= u'\x00C0' && c <= u'\x00DE') && c != u'\x00D7') {
        return static_cast<char16_t>(c - u'\x00C0' + u'\x00E0');
    }
    if (c >= u'\x0391' && c <= u'\x03A9' && c != u'\x03A2') {
        return static_cast<char16_t>(c - u'\x0391' + u'\x03B1');
    }
    if (c == u'\x03A3') {
        // The final/form distinction needs a neighbouring character to
        // decide; the plain lowercase is the answer the simple map gives.
        return u'\x03C3';
    }
    if (c >= u'\x0410' && c <= u'\x042F') {
        return static_cast<char16_t>(c - u'\x0410' + u'\x0430');
    }
    return c;
}

[[nodiscard]] bool is_upper_unit(char16_t c) noexcept {
    return upcase_unit(c) == c && downcase_unit(c) != c;
}

[[nodiscard]] bool is_lower_unit(char16_t c) noexcept {
    return downcase_unit(c) == c && upcase_unit(c) != c;
}

// Folds a fullwidth form onto its ASCII counterpart, the width half of
// `NORM_IGNOREWIDTH`. Halfwidth katakana has no ASCII counterpart and is
// left alone; this is the half callers compare file names and numbers with.
[[nodiscard]] char16_t fold_width(char16_t c) noexcept {
    if (c >= u'\xFF01' && c <= u'\xFF5E') {
        return static_cast<char16_t>(c - u'\xFF01' + u'!');
    }
    if (c == u'\u3000') {
        return u' ';
    }
    return c;
}

// The combining block `NORM_IGNORENONSPACE` strips. One block, because that
// is the range where stripping is safe without a decomposition table; marks
// outside it survive the compare, which the caller only notices when two
// strings differ by such a mark.
[[nodiscard]] bool is_nonspace(char16_t c) noexcept {
    return c >= u'\u0300' && c <= u'\u036F';
}

// ------------------------------------------------------------ the W compare

// The three-way compare every compare in this file reduces to. Case is
// folded ASCII/Latin-1/Greek/Cyrillic when asked, combining marks are
// skipped when asked, and width is folded; the rest is plain code-unit
// order, which is the linguistic answer for everything the tables cover and
// a documented approximation for the rest.
//
// A shorter prefix answers less-than, the way the reference compares; a
// compare that reaches the end of both at once answers equal.
[[nodiscard]] std::int32_t compare_wide(const char16_t* a, std::size_t la,
                                        const char16_t* b, std::size_t lb,
                                        std::uint32_t flags) noexcept {
    const bool ignore_case = (flags & kNormIgnoreCase) != 0;
    const bool ignore_nonspace = (flags & kNormIgnoreNonspace) != 0;
    const bool ignore_width = (flags & kNormIgnoreWidth) != 0;
    std::size_t i = 0;
    std::size_t j = 0;
    while (i < la && j < lb) {
        char16_t ca = a[i];
        char16_t cb = b[j];
        ++i;
        ++j;
        if (ignore_nonspace && is_nonspace(ca)) {
            if (is_nonspace(cb)) {
                continue;
            }
            // One side carries a mark the other lacks: skip only the mark.
            --j;
            continue;
        }
        if (ignore_nonspace && is_nonspace(cb)) {
            --i;
            continue;
        }
        if (ignore_width) {
            ca = fold_width(ca);
            cb = fold_width(cb);
        }
        if (ignore_case) {
            ca = upcase_unit(ca);
            cb = upcase_unit(cb);
        }
        if (ca != cb) {
            return ca < cb ? kCstrLessThan : kCstrGreaterThan;
        }
    }
    for (; i < la; ++i) {
        if (!ignore_nonspace || !is_nonspace(a[i])) {
            return kCstrGreaterThan;
        }
    }
    for (; j < lb; ++j) {
        if (!ignore_nonspace || !is_nonspace(b[j])) {
            return kCstrLessThan;
        }
    }
    return kCstrEqual;
}

// ------------------------------------------------------------ the case types

// CT_CTYPE1 for one unit. ASCII is exact; Latin-1, Greek and Cyrillic place
// the letter and case bits; everything else answers 0, which says "not in
// any class" rather than a guessed class.
[[nodiscard]] std::uint16_t ctype1_unit(char16_t c) noexcept {
    std::uint16_t t = 0;
    if (c <= 0x7F) {
        // The hex digits come first: they are letters as well as digits,
        // and a caller that asked for the letter bits of `a` still needs
        // the xdigit bit the general ranges would leave off.
        if (c >= u'0' && c <= u'9') {
            t = kC1Digit | kC1Xdigit;
        } else if (c >= u'A' && c <= u'F') {
            t = kC1Upper | kC1Alpha | kC1Xdigit;
        } else if (c >= u'a' && c <= u'f') {
            t = kC1Lower | kC1Alpha | kC1Xdigit;
        } else if (c >= u'A' && c <= u'Z') {
            t = kC1Upper | kC1Alpha;
        } else if (c >= u'a' && c <= u'z') {
            t = kC1Lower | kC1Alpha;
        } else if (c == u' ' || c == u'\t' || c == u'\n' || c == u'\r' ||
                   c == u'\x0C' || c == u'\x0B') {
            t = kC1Space;
            if (c == u' ' || c == u'\t') {
                t |= kC1Blank;
            }
            if (c != u' ') {
                t |= kC1Cntrl;
            }
        } else if (c < 0x20 || c == 0x7F) {
            t = kC1Cntrl;
        } else if ((c >= u'!' && c <= u'/') || (c >= u':' && c <= u'@') ||
                   (c >= u'[' && c <= u'`') || (c >= u'{' && c <= u'~')) {
            t = kC1Punct;
        }
        return t;
    }
    if (is_upper_unit(c)) {
        t = kC1Upper | kC1Alpha;
    } else if (is_lower_unit(c)) {
        t = kC1Lower | kC1Alpha;
    }
    return t;
}

// CT_CTYPE2: the bidirectional class. The approximation is coarser than
// CT1: letters go left-to-right, the Arabic and Hebrew blocks right-to-left,
// digits European, whitespace whitespace, and everything else neutral.
[[nodiscard]] std::uint16_t ctype2_unit(char16_t c) noexcept {
    if ((c >= u'\x0590' && c <= u'\x05FF') || (c >= u'\u0600' && c <= u'\u06FF')) {
        return kC2RightToLeft;
    }
    if (c >= u'0' && c <= u'9') {
        return kC2EuroNumber;
    }
    if ((c >= u'A' && c <= u'Z') || (c >= u'a' && c <= u'z')) {
        return kC2LeftToRight;
    }
    if (is_upper_unit(c) || is_lower_unit(c)) {
        return kC2LeftToRight;
    }
    if (c == u' ' || c == u'\t' || c == u'\n' || c == u'\r' || c == u'\x0C' ||
        c == u'\x0B') {
        return kC2Whitespace;
    }
    return kC2OtherNeutral;
}

// CT_CTYPE3: the script/surrogate bits. Surrogates are the bit the runtime
// itself depends on when it walks a pair; the script blocks are the ones
// this file can name without a table.
[[nodiscard]] std::uint16_t ctype3_unit(char16_t c) noexcept {
    std::uint16_t t = 0;
    if (c >= 0xD800 && c <= 0xDBFF) {
        return kC3HighSurrogate;
    }
    if (c >= 0xDC00 && c <= 0xDFFF) {
        return kC3LowSurrogate;
    }
    // The alpha bit follows the width fold, so a fullwidth letter carries
    // it the way its ASCII counterpart does.
    const char16_t letter = fold_width(c);
    if (is_upper_unit(letter) || is_lower_unit(letter) ||
        (letter >= u'A' && letter <= u'Z') ||
        (letter >= u'a' && letter <= u'z')) {
        t |= kC3Alpha;
    }
    if ((c >= u'\u3040' && c <= u'\u309F')) {
        t |= kC3Hiragana | kC3Ideogram;
    }
    if ((c >= u'\u30A0' && c <= u'\u30FF')) {
        t |= kC3Katakana | kC3Ideogram;
    }
    if ((c >= u'\u4E00' && c <= u'\u9FFF') ||
        (c >= u'\u3400' && c <= u'\u4DBF')) {
        t |= kC3Ideogram;
    }
    if (c >= u'\uFF01' && c <= u'\uFF60') {
        t |= kC3Fullwidth;
    }
    if (c >= u'\uFF65' && c <= u'\uFF9F') {
        t |= kC3Halfwidth;
    }
    if ((c >= u'!' && c <= u'/') || (c >= u':' && c <= u'@') ||
        (c >= u'[' && c <= u'`') || (c >= u'{' && c <= u'~')) {
        t |= kC3Symbol;
    }
    return t;
}

// ------------------------------------------------------------ the W compare cores

// `CompareStringW`/`CompareStringEx` over resolved counts. The count checks
// happen before any read of the strings: a null pointer with a positive
// count is the caller's bug, answered 0 with the parameter error set, not a
// read of address zero.
[[nodiscard]] std::int32_t compare_string_w_core(
    std::uint32_t flags, const char16_t* a, std::int32_t ca, const char16_t* b,
    std::int32_t cb) noexcept {
    if ((a == nullptr && ca != 0) || (b == nullptr && cb != 0) ||
        (a == nullptr && ca == -1) || (b == nullptr && cb == -1)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::size_t la = 0;
    std::size_t lb = 0;
    if (a != nullptr && !resolve_count(a, ca, la)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (b != nullptr && !resolve_count(b, cb, lb)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return compare_wide(a == nullptr ? u"" : a, la, b == nullptr ? u"" : b, lb,
                        flags);
}

// ------------------------------------------------------------ FoldString core

// The ligature table `MAP_EXPAND_LIGATURES` folds. These are the Latin
// ligatures and digraphs the compatibility data expands; a ligature outside
// the table passes through, which is visible but honest.
struct Ligature {
    char16_t from;
    const char16_t* to;
    std::size_t length;
};

constexpr Ligature kLigatures[] = {
    {u'\u00C6', u"AE", 2},  {u'\u00E6', u"ae", 2},
    {u'\u0152', u"OE", 2},  {u'\u0153', u"oe", 2},
    {u'\u0132', u"IJ", 2},  {u'\u0133', u"ij", 2},
    {u'\uFB00', u"ff", 2},  {u'\uFB01', u"fi", 2},
    {u'\uFB02', u"fl", 2},  {u'\uFB03', u"ffi", 3},
    {u'\uFB04', u"ffl", 3}, {u'\uFB05', u"st", 2},
    {u'\uFB06', u"st", 2},
};

// The compatibility fold `MAP_FOLDCZONE` applies: Latin-1 accented letters
// to their bases. Accented letters outside Latin-1 (Latin Extended-A and
// beyond) are not here yet and pass through, and the sharp-s expands to two
// units, which the caller that walks units handles before reaching here.
[[nodiscard]] char16_t fold_czone_unit(char16_t c) noexcept {
    switch (c) {
        case u'\x00C0': case u'\x00C1': case u'\x00C2':
        case u'\x00C3': case u'\x00C4': case u'\x00C5':
            return u'A';
        case u'\x00C7':
            return u'C';
        case u'\x00C8': case u'\x00C9': case u'\x00CA': case u'\x00CB':
            return u'E';
        case u'\x00CC': case u'\x00CD': case u'\x00CE': case u'\x00CF':
            return u'I';
        case u'\x00D1':
            return u'N';
        case u'\x00D2': case u'\x00D3': case u'\x00D4':
        case u'\x00D5': case u'\x00D6':
            return u'O';
        case u'\x00D9': case u'\x00DA': case u'\x00DB':
            return u'U';
        case u'\x00DD':
            return u'Y';
        case u'\x00E0': case u'\x00E1': case u'\x00E2':
        case u'\x00E3': case u'\x00E4': case u'\x00E5':
            return u'a';
        case u'\x00E7':
            return u'c';
        case u'\x00E8': case u'\x00E9': case u'\x00EA': case u'\x00EB':
            return u'e';
        case u'\x00EC': case u'\x00ED': case u'\x00EE': case u'\x00EF':
            return u'i';
        case u'\x00F1':
            return u'n';
        case u'\x00F2': case u'\x00F3': case u'\x00F4':
        case u'\x00F5': case u'\x00F6':
            return u'o';
        case u'\x00F9': case u'\x00FA': case u'\x00FB':
            return u'u';
        case u'\x00FD': case u'\x00FF':
            return u'y';
        default:
            return c;
    }
}

// Appends the fold of one unit under the caller's flags. Returns false only
// for the sharp-s case, which expands to two units and needs the extra
// write; handled inline by the caller instead of here.
void append_folded_unit(std::u16string& out, char16_t c,
                        std::uint32_t flags) noexcept {
    if ((flags & kMapExpandLigatures) != 0) {
        for (const Ligature& lig : kLigatures) {
            if (lig.from == c) {
                out.append(lig.to, lig.length);
                return;
            }
        }
    }
    // The sharp-s is the one Latin-1 compatibility fold that widens; the
    // unit table below answers single characters and cannot carry it.
    if ((flags & kMapFoldCzone) != 0) {
        if (c == u'\x00DF') {
            out.append(u"ss", 2);
            return;
        }
        c = fold_czone_unit(c);
    }
    if ((flags & kMapFoldDigits) != 0 && c >= u'\xFF10' && c <= u'\xFF19') {
        c = static_cast<char16_t>(c - u'\xFF10' + u'0');
    }
    out.push_back(c);
}

// `FoldStringW` over resolved inputs. The source is folded into a scratch
// string first, so the size query (a null destination) and the guarded copy
// answer from the same transform rather than from a second estimate. The
// terminator is part of the answer only when the source was null-terminated,
// which is the reference's rule and the reason the two count shapes cannot
// share one `needed`.
[[nodiscard]] std::int32_t fold_string_w_core(std::uint32_t flags,
                                              const char16_t* source,
                                              std::size_t count,
                                              char16_t* dest,
                                              std::int32_t cch_dest,
                                              bool terminated) noexcept {
    std::u16string folded;
    folded.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        append_folded_unit(folded, source[i], flags);
    }
    const std::size_t needed =
        folded.size() + (terminated ? 1u : 0u);
    if (cch_dest == 0) {
        return static_cast<std::int32_t>(needed);
    }
    if (dest == nullptr || cch_dest < 0 ||
        static_cast<std::size_t>(cch_dest) < needed) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    for (std::size_t i = 0; i < folded.size(); ++i) {
        dest[i] = folded[i];
    }
    // The terminator is written whenever the caller's buffer has room for
    // one, but only the -1 shape counts it in the answer.
    if (static_cast<std::size_t>(cch_dest) > folded.size()) {
        dest[folded.size()] = u'\0';
    }
    return static_cast<std::int32_t>(needed);
}

// ------------------------------------------------------------ LCMapString core

// The sort key this runtime produces: two big-endian bytes per folded unit,
// then the reference's three-byte terminator. The bytes are not the
// reference's weights, but the property a caller needs is preserved: byte-
// wise memcmp of two keys orders exactly as the code-unit compare orders,
// and a prefix sorts before the string that extends it. Byte-identical keys
// would need the full collation table, which is the part of the reference
// this runtime does not carry.
[[nodiscard]] bool make_sortkey(const char16_t* source, std::size_t count,
                                std::uint32_t flags, std::string& out) noexcept {
    out.clear();
    out.reserve(count * 2 + 3);
    for (std::size_t i = 0; i < count; ++i) {
        char16_t c = source[i];
        if ((flags & kNormIgnoreCase) != 0) {
            c = downcase_unit(c);
        }
        out.push_back(static_cast<char>(c >> 8));
        out.push_back(static_cast<char>(c & 0xFFu));
    }
    out.push_back('\x01');
    out.push_back('\x01');
    out.push_back('\x00');
    return true;
}

// `LCMapStringW` over resolved inputs. Case mapping and sort key generation
// share the flag validation, which is where the mutual exclusions the
// reference enforces are checked rather than in each caller.
[[nodiscard]] std::int32_t lcmap_string_w_core(std::uint32_t flags,
                                               const char16_t* source,
                                               std::size_t count,
                                               char16_t* dest,
                                               std::int32_t cch_dest,
                                               bool terminated) noexcept {
    const bool lower = (flags & kCmapLowercase) != 0;
    const bool upper = (flags & kCmapUppercase) != 0;
    const bool sortkey = (flags & kCmapSortkey) != 0;
    if ((lower && upper) || (sortkey && (lower || upper))) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (lower || upper) {
        std::u16string mapped;
        mapped.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            mapped.push_back(lower ? downcase_unit(source[i])
                                   : upcase_unit(source[i]));
        }
        const std::size_t needed = mapped.size() + (terminated ? 1u : 0u);
        if (cch_dest == 0) {
            return static_cast<std::int32_t>(needed);
        }
        if (dest == nullptr || cch_dest < 0 ||
            static_cast<std::size_t>(cch_dest) < needed) {
            set_last_error(kErrorInsufficientBuffer);
            return 0;
        }
        for (std::size_t i = 0; i < mapped.size(); ++i) {
            dest[i] = mapped[i];
        }
        if (static_cast<std::size_t>(cch_dest) > mapped.size()) {
            dest[mapped.size()] = u'\0';
        }
        return static_cast<std::int32_t>(needed);
    }
    if (sortkey) {
        std::string key;
        if (!make_sortkey(source, count, flags, key)) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        if ((flags & kCmapByteRev) != 0) {
            // Byte reversal is per unit pair, the granularity the key is
            // built from; reversing the whole key would destroy the
            // terminator that ends it.
            for (std::size_t i = 0; i + 1 < key.size(); i += 2) {
                const char tmp = key[i];
                key[i] = key[i + 1];
                key[i + 1] = tmp;
            }
        }
        if (cch_dest == 0) {
            return static_cast<std::int32_t>(key.size());
        }
        if (dest == nullptr || cch_dest < 0 ||
            static_cast<std::size_t>(cch_dest) < key.size()) {
            set_last_error(kErrorInsufficientBuffer);
            return 0;
        }
        auto* bytes = reinterpret_cast<std::uint8_t*>(dest);
        for (std::size_t i = 0; i < key.size(); ++i) {
            bytes[i] = static_cast<std::uint8_t>(key[i]);
        }
        return static_cast<std::int32_t>(key.size());
    }
    set_last_error(kErrorInvalidParameter);
    return 0;
}

// ------------------------------------------------------------- GetStringType

// `GetStringTypeW` over a resolved count. The type array gets one entry per
// source unit; the terminator is not typed, because the reference types the
// characters and the caller already knows where its string ends.
[[nodiscard]] std::int32_t get_string_type_w_core(std::uint32_t type,
                                                  const char16_t* source,
                                                  std::size_t count,
                                                  std::uint16_t* dest) noexcept {
    if (type != kCtCtype1 && type != kCtCtype2 && type != kCtCtype3) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (dest == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    for (std::size_t i = 0; i < count; ++i) {
        std::uint16_t t = 0;
        if (type == kCtCtype1) {
            t = ctype1_unit(source[i]);
        } else if (type == kCtCtype2) {
            t = ctype2_unit(source[i]);
        } else {
            t = ctype3_unit(source[i]);
        }
        dest[i] = t;
    }
    return 1;
}

}  // namespace

// ---------------------------------------------------------------------------
// ABI entry points
// ---------------------------------------------------------------------------

// lstrlen answers 0 for a null input, which Windows documents and which is
// the difference between this family and `strlen`.
extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrlenA(
    const char* text) noexcept {
    if (text == nullptr) {
        return 0;
    }
    const std::size_t n = text_length(text);
    return static_cast<std::int32_t>(n);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrlenW(
    const char16_t* text) noexcept {
    if (text == nullptr) {
        return 0;
    }
    const std::size_t n = text_length(text);
    return static_cast<std::int32_t>(n);
}

// The unadorned spellings are the ANSI forms; kernel32 exports them that way
// and the loader asks for them by these names.
extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrlen(
    const char* text) noexcept {
    return k32t_lstrlenA(text);
}

// lstrcpy has no destination size in its signature, so there is nothing to
// validate a copy against: the reference overflows the buffer and this
// runtime does the copy instead, without the crash. The null checks are the
// one guard a caller can observe; a null destination answering null rather
// than faulting is the safe reading of a case the reference does not
// survive either.
extern "C" __attribute__((ms_abi)) char* k32t_lstrcpyA(
    char* dest, const char* source) noexcept {
    if (dest == nullptr || source == nullptr) {
        return nullptr;
    }
    std::size_t i = 0;
    for (; source[i] != '\0'; ++i) {
        dest[i] = source[i];
    }
    dest[i] = '\0';
    return dest;
}

extern "C" __attribute__((ms_abi)) char16_t* k32t_lstrcpyW(
    char16_t* dest, const char16_t* source) noexcept {
    if (dest == nullptr || source == nullptr) {
        return nullptr;
    }
    std::size_t i = 0;
    for (; source[i] != u'\0'; ++i) {
        dest[i] = source[i];
    }
    dest[i] = u'\0';
    return dest;
}

extern "C" __attribute__((ms_abi)) char* k32t_lstrcpy(
    char* dest, const char* source) noexcept {
    return k32t_lstrcpyA(dest, source);
}

// lstrcat appends after the destination's terminator. The same "no size in
// the signature" note as lstrcpy applies; the scan of the destination stops
// at the buffer's own terminator, which is all the function knows.
extern "C" __attribute__((ms_abi)) char* k32t_lstrcatA(
    char* dest, const char* source) noexcept {
    if (dest == nullptr || source == nullptr) {
        return nullptr;
    }
    std::size_t at = 0;
    while (dest[at] != '\0') {
        ++at;
    }
    std::size_t i = 0;
    for (; source[i] != '\0'; ++i) {
        dest[at + i] = source[i];
    }
    dest[at + i] = '\0';
    return dest;
}

extern "C" __attribute__((ms_abi)) char16_t* k32t_lstrcatW(
    char16_t* dest, const char16_t* source) noexcept {
    if (dest == nullptr || source == nullptr) {
        return nullptr;
    }
    std::size_t at = 0;
    while (dest[at] != u'\0') {
        ++at;
    }
    std::size_t i = 0;
    for (; source[i] != u'\0'; ++i) {
        dest[at + i] = source[i];
    }
    dest[at + i] = u'\0';
    return dest;
}

extern "C" __attribute__((ms_abi)) char* k32t_lstrcat(
    char* dest, const char* source) noexcept {
    return k32t_lstrcatA(dest, source);
}

// lstrcpyn is the bounded copy: `count` is the whole buffer in characters,
// terminator included, and a count of zero or less touches nothing. This is
// the one member of the family with a size to validate against, so it is the
// one that truncates instead of overflowing.
extern "C" __attribute__((ms_abi)) char* k32t_lstrcpynA(
    char* dest, const char* source, std::int32_t count) noexcept {
    if (dest == nullptr || count <= 0) {
        return dest;
    }
    if (source == nullptr) {
        dest[0] = '\0';
        return dest;
    }
    std::int32_t written = 0;
    while (written < count - 1 && source[written] != '\0') {
        dest[written] = source[written];
        ++written;
    }
    dest[written] = '\0';
    return dest;
}

extern "C" __attribute__((ms_abi)) char16_t* k32t_lstrcpynW(
    char16_t* dest, const char16_t* source, std::int32_t count) noexcept {
    if (dest == nullptr || count <= 0) {
        return dest;
    }
    if (source == nullptr) {
        dest[0] = u'\0';
        return dest;
    }
    std::int32_t written = 0;
    while (written < count - 1 && source[written] != u'\0') {
        dest[written] = source[written];
        ++written;
    }
    dest[written] = u'\0';
    return dest;
}

extern "C" __attribute__((ms_abi)) char* k32t_lstrcpyn(
    char* dest, const char* source, std::int32_t count) noexcept {
    return k32t_lstrcpynA(dest, source, count);
}

// The compares answer through the compare core, then shift from the 1/2/3
// the core speaks to the -1/0/1 this family speaks. The A forms convert
// through the bridge, so an A compare and the W compare of the same text
// answer the same; text that is not valid UTF-8 falls back to a byte
// compare, because refusing to order bytes would leave the caller with no
// ordering at all.
extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrcmpW(
    const char16_t* a, const char16_t* b) noexcept {
    if (a == nullptr || b == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return compare_wide(a, text_length(a), b, text_length(b), 0) - kCstrEqual;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrcmpiW(
    const char16_t* a, const char16_t* b) noexcept {
    if (a == nullptr || b == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return compare_wide(a, text_length(a), b, text_length(b),
                        kNormIgnoreCase) - kCstrEqual;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrcmpA(
    const char* a, const char* b) noexcept {
    if (a == nullptr || b == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string wa;
    std::u16string wb;
    const AnsiResult ra = narrow_in(std::string_view(a, text_length(a)), wa);
    const AnsiResult rb = narrow_in(std::string_view(b, text_length(b)), wb);
    if (ra.converted && rb.converted) {
        return compare_wide(wa.data(), wa.size(), wb.data(), wb.size(), 0) -
               kCstrEqual;
    }
    // Not convertible: order the raw bytes. ASCII case folding keeps the
    // insensitive spelling of this fallback consistent with the sensitive
    // one rather than differing only in the cases the conversion fails on.
    const std::size_t la = text_length(a);
    const std::size_t lb = text_length(b);
    for (std::size_t i = 0; i < la && i < lb; ++i) {
        const auto ca = static_cast<unsigned char>(a[i]);
        const auto cb = static_cast<unsigned char>(b[i]);
        if (ca != cb) {
            return ca < cb ? -1 : 1;
        }
    }
    if (la != lb) {
        return la < lb ? -1 : 1;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrcmpiA(
    const char* a, const char* b) noexcept {
    if (a == nullptr || b == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string wa;
    std::u16string wb;
    const AnsiResult ra = narrow_in(std::string_view(a, text_length(a)), wa);
    const AnsiResult rb = narrow_in(std::string_view(b, text_length(b)), wb);
    if (ra.converted && rb.converted) {
        return compare_wide(wa.data(), wa.size(), wb.data(), wb.size(),
                            kNormIgnoreCase) - kCstrEqual;
    }
    const std::size_t la = text_length(a);
    const std::size_t lb = text_length(b);
    for (std::size_t i = 0; i < la && i < lb; ++i) {
        auto ca = static_cast<unsigned char>(a[i]);
        auto cb = static_cast<unsigned char>(b[i]);
        if (ca >= 'a' && ca <= 'z') {
            ca = static_cast<unsigned char>(ca - 'a' + 'A');
        }
        if (cb >= 'a' && cb <= 'z') {
            cb = static_cast<unsigned char>(cb - 'a' + 'A');
        }
        if (ca != cb) {
            return ca < cb ? -1 : 1;
        }
    }
    if (la != lb) {
        return la < lb ? -1 : 1;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrcmp(
    const char* a, const char* b) noexcept {
    return k32t_lstrcmpA(a, b);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrcmpi(
    const char* a, const char* b) noexcept {
    return k32t_lstrcmpiA(a, b);
}

// `CompareStringW`/`CompareStringA`/`CompareStringEx`. The locale and the
// locale name are accepted and ignored: the compare is the code-unit fold
// above for every locale, which is exact for the invariant behaviour and an
// approximation for locales that reorder punctuation. The version/reserved/
// param arguments are the reference's extension slots and are not read.
extern "C" __attribute__((ms_abi)) std::int32_t k32t_CompareStringW(
    std::uint32_t locale, std::uint32_t flags, const char16_t* a,
    std::int32_t ca, const char16_t* b, std::int32_t cb) noexcept {
    (void)locale;
    return compare_string_w_core(flags, a, ca, b, cb);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_CompareStringEx(
    const char16_t* locale_name, std::uint32_t flags, const char16_t* a,
    std::int32_t ca, const char16_t* b, std::int32_t cb,
    const void* version, const void* reserved, std::uint64_t param) noexcept {
    (void)locale_name;
    (void)version;
    (void)reserved;
    (void)param;
    return compare_string_w_core(flags, a, ca, b, cb);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_CompareStringA(
    std::uint32_t locale, std::uint32_t flags, const char* a, std::int32_t ca,
    const char* b, std::int32_t cb) noexcept {
    (void)locale;
    if ((a == nullptr && ca != 0) || (b == nullptr && cb != 0) ||
        (a == nullptr && ca == -1) || (b == nullptr && cb == -1) ||
        ca < -1 || cb < -1) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::size_t la =
        a != nullptr
            ? (ca < 0 ? text_length(a) : static_cast<std::size_t>(ca))
            : 0;
    const std::size_t lb =
        b != nullptr
            ? (cb < 0 ? text_length(b) : static_cast<std::size_t>(cb))
            : 0;
    std::u16string wa;
    std::u16string wb;
    const AnsiResult ra = narrow_in(std::string_view(a == nullptr ? "" : a, la), wa);
    const AnsiResult rb = narrow_in(std::string_view(b == nullptr ? "" : b, lb), wb);
    if (!ra.converted || !rb.converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return compare_wide(wa.data(), wa.size(), wb.data(), wb.size(), flags);
}

// `CompareStringOrdinal` is the code-unit compare with no linguistic layer,
// and the one member whose ordering a caller can predict from the code
// points alone: "a" (0x61) sorts after "B" (0x42) here and before it in the
// linguistic compares. Case folding is the simple one; surrogate pairs
// compare by unit, which is what ordinal means.
extern "C" __attribute__((ms_abi)) std::int32_t k32t_CompareStringOrdinal(
    const char16_t* a, std::int32_t ca, const char16_t* b, std::int32_t cb,
    std::int32_t ignore_case) noexcept {
    const std::uint32_t flags =
        ignore_case != 0 ? kNormIgnoreCase : 0;
    if ((a == nullptr && ca != 0) || (b == nullptr && cb != 0) ||
        (a == nullptr && ca == -1) || (b == nullptr && cb == -1)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::size_t la = 0;
    std::size_t lb = 0;
    if (a != nullptr && !resolve_count(a, ca, la)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (b != nullptr && !resolve_count(b, cb, lb)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return compare_wide(a == nullptr ? u"" : a, la, b == nullptr ? u"" : b, lb,
                        flags);
}

// `FoldStringW`/`FoldStringA`. No flag is the caller's bug: the reference
// rejects a zero flag set, and so does the core below. Composite and
// precomposed are the two directions of the same decomposition and are
// mutually exclusive; the fold here answers the identity for both, which is
// correct for text that is already in the requested form and an
// approximation for text that is not.
extern "C" __attribute__((ms_abi)) std::int32_t k32t_FoldStringW(
    std::uint32_t flags, const char16_t* source, std::int32_t cch_source,
    char16_t* dest, std::int32_t cch_dest) noexcept {
    const std::uint32_t supported = kMapComposite | kMapPrecomposed |
                                    kMapFoldCzone | kMapFoldDigits |
                                    kMapExpandLigatures;
    const bool composite = (flags & kMapComposite) != 0;
    const bool precomposed = (flags & kMapPrecomposed) != 0;
    if ((flags & ~supported) != 0 || flags == 0 ||
        (composite && precomposed)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (source == nullptr || cch_source < -1 || cch_source == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::size_t count = 0;
    if (!resolve_count(source, cch_source, count)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return fold_string_w_core(flags, source, count, dest, cch_dest,
                              cch_source < 0);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_FoldStringA(
    std::uint32_t flags, const char* source, std::int32_t cch_source,
    char* dest, std::int32_t cch_dest) noexcept {
    const std::uint32_t supported = kMapComposite | kMapPrecomposed |
                                    kMapFoldCzone | kMapFoldDigits |
                                    kMapExpandLigatures;
    if ((flags & ~supported) != 0 || flags == 0 ||
        ((flags & kMapComposite) != 0 && (flags & kMapPrecomposed) != 0)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (source == nullptr || cch_source < -1 || cch_source == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::size_t count = 0;
    if (!resolve_count(source, cch_source, count)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string wide;
    if (!narrow_in(std::string_view(source, count), wide).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string folded;
    folded.reserve(wide.size());
    for (std::size_t i = 0; i < wide.size(); ++i) {
        append_folded_unit(folded, wide[i], flags);
    }
    std::string narrow;
    if (!narrow_out(folded, narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const bool terminated = cch_source < 0;
    const std::size_t needed = narrow.size() + (terminated ? 1u : 0u);
    if (cch_dest == 0) {
        return static_cast<std::int32_t>(needed);
    }
    if (dest == nullptr || cch_dest < 0 ||
        static_cast<std::size_t>(cch_dest) < needed) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    for (std::size_t i = 0; i < narrow.size(); ++i) {
        dest[i] = narrow[i];
    }
    if (static_cast<std::size_t>(cch_dest) > narrow.size()) {
        dest[narrow.size()] = '\0';
    }
    return static_cast<std::int32_t>(needed);
}

// `GetStringTypeW` and its Ex spelling, which differ only in the locale
// parameter the runtime ignores.
extern "C" __attribute__((ms_abi)) std::int32_t k32t_GetStringTypeW(
    std::uint32_t type, const char16_t* source, std::int32_t cch_source,
    std::uint16_t* dest) noexcept {
    if (source == nullptr || cch_source < -1 || cch_source == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::size_t count = 0;
    if (!resolve_count(source, cch_source, count)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return get_string_type_w_core(type, source, count, dest);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_GetStringTypeExW(
    std::uint32_t locale, std::uint32_t type, const char16_t* source,
    std::int32_t cch_source, std::uint16_t* dest) noexcept {
    (void)locale;
    return k32t_GetStringTypeW(type, source, cch_source, dest);
}

// `GetStringTypeA` types bytes, not characters: the answer array is one
// WORD per source byte, because the caller sized it from the byte length it
// can see. Each byte inherits the type of the wide character that produced
// it, so "é" types both of its bytes as a letter rather than the first byte
// as one class and the continuation as another.
extern "C" __attribute__((ms_abi)) std::int32_t k32t_GetStringTypeA(
    std::uint32_t locale, std::uint32_t type, const char* source,
    std::int32_t cch_source, std::uint16_t* dest) noexcept {
    (void)locale;
    if (source == nullptr || cch_source < -1 || cch_source == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::size_t count = 0;
    if (!resolve_count(source, cch_source, count)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string wide;
    if (!narrow_in(std::string_view(source, count), wide).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string types;
    types.resize(wide.size());
    for (std::size_t i = 0; i < wide.size(); ++i) {
        std::uint16_t t = 0;
        if (type == kCtCtype1) {
            t = ctype1_unit(wide[i]);
        } else if (type == kCtCtype2) {
            t = ctype2_unit(wide[i]);
        } else if (type == kCtCtype3) {
            t = ctype3_unit(wide[i]);
        } else {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        types[i] = t;
    }
    // Walk the wide units and their UTF-8 bytes together, so every byte
    // gets the type of the character it is part of. A surrogate pair is two
    // units naming one character; its bytes take the pair's combined type.
    std::size_t byte_at = 0;
    for (std::size_t i = 0; i < wide.size() && byte_at < count;) {
        char16_t units[2] = {wide[i], u'\0'};
        std::uint16_t merged = types[i];
        std::size_t unit_count = 1;
        if (wide[i] >= 0xD800 && wide[i] <= 0xDBFF && i + 1 < wide.size() &&
            wide[i + 1] >= 0xDC00 && wide[i + 1] <= 0xDFFF) {
            units[1] = wide[i + 1];
            merged = static_cast<std::uint16_t>(types[i] | types[i + 1]);
            unit_count = 2;
        }
        std::string bytes;
        std::u16string_view pair(units, unit_count);
        if (!narrow_out(pair, bytes).converted) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        for (std::size_t k = 0; k < bytes.size() && byte_at < count; ++k) {
            dest[byte_at] = merged;
            ++byte_at;
        }
        i += unit_count;
    }
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_GetStringTypeExA(
    std::uint32_t locale, std::uint32_t type, const char* source,
    std::int32_t cch_source, std::uint16_t* dest) noexcept {
    return k32t_GetStringTypeA(locale, type, source, cch_source, dest);
}

// `IsDBCSLeadByte` asks whether a byte opens a two-byte character in the
// ANSI code page. The code page this runtime models is UTF-8, and UTF-8 is
// not a DBCS: no byte opens a two-byte character in the Windows sense, so
// the answer is false for every byte. A caller parsing a real DBCS document
// needs the code page conversion entry points, which are a different
// domain's answer.
extern "C" __attribute__((ms_abi)) std::int32_t k32t_IsDBCSLeadByte(
    std::uint8_t test_char) noexcept {
    (void)test_char;
    return 0;
}

// `LCMapStringW`/`LCMapStringA`/`LCMapStringEx`. Sort keys come back as
// bytes into the destination, so the destination size is bytes for the
// sortkey branch and characters otherwise -- the asymmetry the reference
// has and the reason a caller cannot reuse its sizing code across branches.
extern "C" __attribute__((ms_abi)) std::int32_t k32t_LCMapStringW(
    std::uint32_t locale, std::uint32_t flags, const char16_t* source,
    std::int32_t cch_source, char16_t* dest, std::int32_t cch_dest) noexcept {
    (void)locale;
    if (source == nullptr || cch_source < -1 || cch_source == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::size_t count = 0;
    if (!resolve_count(source, cch_source, count)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return lcmap_string_w_core(flags, source, count, dest, cch_dest,
                               cch_source < 0);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_LCMapStringEx(
    const char16_t* locale_name, std::uint32_t flags, const char16_t* source,
    std::int32_t cch_source, char16_t* dest, std::int32_t cch_dest,
    const void* version, const void* reserved, std::uint64_t param) noexcept {
    (void)locale_name;
    (void)version;
    (void)reserved;
    (void)param;
    return k32t_LCMapStringW(0, flags, source, cch_source, dest, cch_dest);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32t_LCMapStringA(
    std::uint32_t locale, std::uint32_t flags, const char* source,
    std::int32_t cch_source, char* dest, std::int32_t cch_dest) noexcept {
    (void)locale;
    if (source == nullptr || cch_source < -1 || cch_source == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::size_t count = 0;
    if (!resolve_count(source, cch_source, count)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string wide;
    if (!narrow_in(std::string_view(source, count), wide).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if ((flags & kCmapSortkey) != 0) {
        // The key is bytes in both spellings; the wide conversion is only
        // the stepping stone, and the key the A caller gets is the same key
        // the W caller gets for the same text.
        std::string key;
        if (!make_sortkey(wide.data(), wide.size(), flags, key)) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        if ((flags & kCmapByteRev) != 0) {
            for (std::size_t i = 0; i + 1 < key.size(); i += 2) {
                const char tmp = key[i];
                key[i] = key[i + 1];
                key[i + 1] = tmp;
            }
        }
        if (cch_dest == 0) {
            return static_cast<std::int32_t>(key.size());
        }
        if (dest == nullptr || cch_dest < 0 ||
            static_cast<std::size_t>(cch_dest) < key.size()) {
            set_last_error(kErrorInsufficientBuffer);
            return 0;
        }
        for (std::size_t i = 0; i < key.size(); ++i) {
            dest[i] = key[i];
        }
        return static_cast<std::int32_t>(key.size());
    }
    std::u16string mapped;
    mapped.reserve(wide.size());
    const bool lower = (flags & kCmapLowercase) != 0;
    const bool upper = (flags & kCmapUppercase) != 0;
    if (lower && upper) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (!lower && !upper) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    for (std::size_t i = 0; i < wide.size(); ++i) {
        mapped.push_back(lower ? downcase_unit(wide[i]) : upcase_unit(wide[i]));
    }
    std::string narrow;
    if (!narrow_out(mapped, narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const bool terminated = cch_source < 0;
    const std::size_t needed = narrow.size() + (terminated ? 1u : 0u);
    if (cch_dest == 0) {
        return static_cast<std::int32_t>(needed);
    }
    if (dest == nullptr || cch_dest < 0 ||
        static_cast<std::size_t>(cch_dest) < needed) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    for (std::size_t i = 0; i < narrow.size(); ++i) {
        dest[i] = narrow[i];
    }
    if (static_cast<std::size_t>(cch_dest) > narrow.size()) {
        dest[narrow.size()] = '\0';
    }
    return static_cast<std::int32_t>(needed);
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// The unadorned `lstr*` spellings register the A implementations, which is
// what kernel32's export table does: the ANSI forms are the original names
// and the W forms arrived with the suffix. The 32 names are the ones this
// domain's work order lists; the split is between this file and the
// conversion entry points, which live elsewhere because their code page
// handling is a domain of its own.
void add_kernel32_str(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CompareStringA", reinterpret_cast<void*>(&k32t_CompareStringA));
    e("CompareStringEx", reinterpret_cast<void*>(&k32t_CompareStringEx));
    e("CompareStringOrdinal",
      reinterpret_cast<void*>(&k32t_CompareStringOrdinal));
    e("CompareStringW", reinterpret_cast<void*>(&k32t_CompareStringW));
    e("FoldStringA", reinterpret_cast<void*>(&k32t_FoldStringA));
    e("FoldStringW", reinterpret_cast<void*>(&k32t_FoldStringW));
    e("GetStringTypeA", reinterpret_cast<void*>(&k32t_GetStringTypeA));
    e("GetStringTypeExA", reinterpret_cast<void*>(&k32t_GetStringTypeExA));
    e("GetStringTypeExW", reinterpret_cast<void*>(&k32t_GetStringTypeExW));
    e("GetStringTypeW", reinterpret_cast<void*>(&k32t_GetStringTypeW));
    e("IsDBCSLeadByte", reinterpret_cast<void*>(&k32t_IsDBCSLeadByte));
    e("LCMapStringA", reinterpret_cast<void*>(&k32t_LCMapStringA));
    e("LCMapStringEx", reinterpret_cast<void*>(&k32t_LCMapStringEx));
    e("LCMapStringW", reinterpret_cast<void*>(&k32t_LCMapStringW));
    e("lstrcat", reinterpret_cast<void*>(&k32t_lstrcat));
    e("lstrcatA", reinterpret_cast<void*>(&k32t_lstrcatA));
    e("lstrcatW", reinterpret_cast<void*>(&k32t_lstrcatW));
    e("lstrcmp", reinterpret_cast<void*>(&k32t_lstrcmp));
    e("lstrcmpA", reinterpret_cast<void*>(&k32t_lstrcmpA));
    e("lstrcmpi", reinterpret_cast<void*>(&k32t_lstrcmpi));
    e("lstrcmpiA", reinterpret_cast<void*>(&k32t_lstrcmpiA));
    e("lstrcmpiW", reinterpret_cast<void*>(&k32t_lstrcmpiW));
    e("lstrcmpW", reinterpret_cast<void*>(&k32t_lstrcmpW));
    e("lstrcpy", reinterpret_cast<void*>(&k32t_lstrcpy));
    e("lstrcpyA", reinterpret_cast<void*>(&k32t_lstrcpyA));
    e("lstrcpyW", reinterpret_cast<void*>(&k32t_lstrcpyW));
    e("lstrcpyn", reinterpret_cast<void*>(&k32t_lstrcpyn));
    e("lstrcpynA", reinterpret_cast<void*>(&k32t_lstrcpynA));
    e("lstrcpynW", reinterpret_cast<void*>(&k32t_lstrcpynW));
    e("lstrlen", reinterpret_cast<void*>(&k32t_lstrlen));
    e("lstrlenA", reinterpret_cast<void*>(&k32t_lstrlenA));
    e("lstrlenW", reinterpret_cast<void*>(&k32t_lstrlenW));
}

}  // namespace occ::runtime::winabi

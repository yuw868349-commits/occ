// The KERNEL32 string/character family's tests.
//
// These are pure functions over text, so every answer asserted here is a
// fact about the grammar rather than about a machine. The cases are the
// ones where a plausible implementation is wrong:
//
//   * `lstrlen` answers 0 for NULL instead of crashing, and `lstrlenA`
//     counts bytes where `lstrlenW` counts UTF-16 units, so the same text
//     gives the two spellings different answers;
//   * the `lstr*` compares answer exactly -1/0/1 while `CompareString`
//     answers exactly 1/2/3, and a handler that returns one family's shape
//     to the other is wrong in every non-equal case;
//   * `lstrcpyn`'s count includes the terminator, and a count of zero or
//     less touches nothing;
//   * `CompareStringOrdinal` and the linguistic compares order "a" against
//     "B" differently, which is the observable difference between them;
//   * the A forms are the W forms over the UTF-8 bridge, so an A answer and
//     the W answer for the same text agree -- and a byte-level call like
//     `GetStringTypeA` types every byte of a multi-byte character with the
//     character's class.
//
// The error-code assertions read the storage `set_last_error` writes, the
// way a guest's `GetLastError` would.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

// The entry points this domain contributes. They are declared here rather
// than in api.h only because the header gains them when the domain is wired
// up; the signatures are the ones the implementation defines and must match
// it exactly, which the linker checks.
extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrlen(
    const char* text) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrlenA(
    const char* text) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrlenW(
    const char16_t* text) noexcept;
extern "C" __attribute__((ms_abi)) char* k32t_lstrcpy(
    char* dest, const char* source) noexcept;
extern "C" __attribute__((ms_abi)) char* k32t_lstrcpyA(
    char* dest, const char* source) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* k32t_lstrcpyW(
    char16_t* dest, const char16_t* source) noexcept;
extern "C" __attribute__((ms_abi)) char* k32t_lstrcat(
    char* dest, const char* source) noexcept;
extern "C" __attribute__((ms_abi)) char* k32t_lstrcatA(
    char* dest, const char* source) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* k32t_lstrcatW(
    char16_t* dest, const char16_t* source) noexcept;
extern "C" __attribute__((ms_abi)) char* k32t_lstrcpyn(
    char* dest, const char* source, std::int32_t count) noexcept;
extern "C" __attribute__((ms_abi)) char* k32t_lstrcpynA(
    char* dest, const char* source, std::int32_t count) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* k32t_lstrcpynW(
    char16_t* dest, const char16_t* source, std::int32_t count) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrcmp(
    const char* a, const char* b) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrcmpA(
    const char* a, const char* b) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrcmpW(
    const char16_t* a, const char16_t* b) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrcmpi(
    const char* a, const char* b) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrcmpiA(
    const char* a, const char* b) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_lstrcmpiW(
    const char16_t* a, const char16_t* b) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_CompareStringA(
    std::uint32_t locale, std::uint32_t flags, const char* a, std::int32_t ca,
    const char* b, std::int32_t cb) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_CompareStringW(
    std::uint32_t locale, std::uint32_t flags, const char16_t* a,
    std::int32_t ca, const char16_t* b, std::int32_t cb) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_CompareStringEx(
    const char16_t* locale_name, std::uint32_t flags, const char16_t* a,
    std::int32_t ca, const char16_t* b, std::int32_t cb,
    const void* version, const void* reserved, std::uint64_t param) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_CompareStringOrdinal(
    const char16_t* a, std::int32_t ca, const char16_t* b, std::int32_t cb,
    std::int32_t ignore_case) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_FoldStringA(
    std::uint32_t flags, const char* source, std::int32_t cch_source,
    char* dest, std::int32_t cch_dest) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_FoldStringW(
    std::uint32_t flags, const char16_t* source, std::int32_t cch_source,
    char16_t* dest, std::int32_t cch_dest) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_GetStringTypeA(
    std::uint32_t locale, std::uint32_t type, const char* source,
    std::int32_t cch_source, std::uint16_t* dest) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_GetStringTypeW(
    std::uint32_t type, const char16_t* source, std::int32_t cch_source,
    std::uint16_t* dest) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_GetStringTypeExA(
    std::uint32_t locale, std::uint32_t type, const char* source,
    std::int32_t cch_source, std::uint16_t* dest) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_GetStringTypeExW(
    std::uint32_t locale, std::uint32_t type, const char16_t* source,
    std::int32_t cch_source, std::uint16_t* dest) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_IsDBCSLeadByte(
    std::uint8_t test_char) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_LCMapStringA(
    std::uint32_t locale, std::uint32_t flags, const char* source,
    std::int32_t cch_source, char* dest, std::int32_t cch_dest) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_LCMapStringW(
    std::uint32_t locale, std::uint32_t flags, const char16_t* source,
    std::int32_t cch_source, char16_t* dest, std::int32_t cch_dest) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_LCMapStringEx(
    const char16_t* locale_name, std::uint32_t flags, const char16_t* source,
    std::int32_t cch_source, char16_t* dest, std::int32_t cch_dest,
    const void* version, const void* reserved, std::uint64_t param) noexcept;

namespace occ::runtime::winabi {
// The domain's registration function, declared here for the same reason the
// entry points above are: the header gains it when the domain is wired up.
void add_kernel32_str(ExportList& out);
}  // namespace occ::runtime::winabi

using namespace occ::runtime;
using namespace occ::runtime::winabi;

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

// The flags the tests name, spelled as the guest spells them.
constexpr std::uint32_t kNormIgnoreCase = 0x00000001;
constexpr std::uint32_t kNormIgnoreWidth = 0x00020000;
constexpr std::uint32_t kMapComposite = 0x00000001;
constexpr std::uint32_t kMapPrecomposed = 0x00000002;
constexpr std::uint32_t kMapFoldCzone = 0x00000004;
constexpr std::uint32_t kMapFoldDigits = 0x00000080;
constexpr std::uint32_t kMapExpandLigatures = 0x00002000;
constexpr std::uint32_t kCmapLowercase = 0x00000100;
constexpr std::uint32_t kCmapUppercase = 0x00000200;
constexpr std::uint32_t kCmapSortkey = 0x00000400;
constexpr std::uint32_t kCmapByteRev = 0x00000800;

constexpr std::int32_t kCstrLessThan = 1;
constexpr std::int32_t kCstrEqual = 2;
constexpr std::int32_t kCstrGreaterThan = 3;

// ----------------------------------------------------------------- lstrlen

void test_lstrlen() {
    check(k32t_lstrlenA(nullptr) == 0, "lstrlen: a null A string answers 0");
    check(k32t_lstrlenW(nullptr) == 0, "lstrlen: a null W string answers 0");
    check(k32t_lstrlenA("") == 0, "lstrlen: the empty A string answers 0");
    check(k32t_lstrlenW(u"") == 0, "lstrlen: the empty W string answers 0");

    check(k32t_lstrlenA("hello") == 5, "lstrlen: ASCII counts characters");
    check(k32t_lstrlenW(u"hello") == 5, "lstrlen: W counts UTF-16 units");

    // The A form counts bytes, so the same text gives the two spellings
    // different answers: the accented character is two bytes and one unit.
    check(k32t_lstrlenA("h\xC3\xA9llo") == 6,
          "lstrlen: the A form counts bytes of a UTF-8 character");
    check(k32t_lstrlenW(u"h\x00E9llo") == 5,
          "lstrlen: the W form counts the character once");

    // A surrogate pair is two units, because that is what the W family
    // counts and what CharNextW walks.
    check(k32t_lstrlenW(u"\U0001F600") == 2,
          "lstrlen: a surrogate pair counts as two units");

    // The unadorned spelling is the A form.
    check(k32t_lstrlen("hello") == 5, "lstrlen: the plain name is the A form");
}

// ---------------------------------------------------------------- compares

void test_lstrcmp() {
    check(k32t_lstrcmpW(u"abc", u"abc") == 0, "lstrcmp: equal answers 0");
    check(k32t_lstrcmpW(u"abc", u"abd") == -1,
          "lstrcmp: less answers exactly -1");
    check(k32t_lstrcmpW(u"b", u"a") == 1, "lstrcmp: greater answers exactly 1");

    // A prefix is the smaller string, which is the answer the compare
    // gives for any length a caller can distinguish.
    check(k32t_lstrcmpW(u"abc", u"abcd") == -1,
          "lstrcmp: a prefix sorts first");

    // Case matters, and the W compare is code-unit ordered: lowercase
    // letters sort after uppercase ones.
    check(k32t_lstrcmpW(u"abc", u"ABC") == 1,
          "lstrcmp: lowercase sorts after uppercase");

    check(k32t_lstrcmpiW(u"abc", u"ABC") == 0,
          "lstrcmpi: case alone does not order");
    check(k32t_lstrcmpiW(u"AbC", u"aBc") == 0,
          "lstrcmpi: mixed case folds to equal");
    check(k32t_lstrcmpiW(u"abc", u"abd") == -1,
          "lstrcmpi: the fold does not hide ordering");
    check(k32t_lstrcmpiW(u"abcd", u"ABC") == 1,
          "lstrcmpi: a prefix is still a prefix after folding");

    // The A and W forms agree on the same text, which is the whole point
    // of the bridge.
    check(k32t_lstrcmpA("abc", "abd") == k32t_lstrcmpW(u"abc", u"abd"),
          "lstrcmp: the A and W forms agree");
    check(k32t_lstrcmpiA("Stra\xDF" "e", "STRASSE") != 0,
          "lstrcmpi: the sharp-s is not folded onto SS");
    check(k32t_lstrcmpA("h\xC3\xA9llo", "h\xC3\xA9llo") == 0,
          "lstrcmp: UTF-8 text compares equal to itself");

    check(k32t_lstrcmp("abc", "abc") == 0,
          "lstrcmp: the plain name is the A form");
    check(k32t_lstrcmpi("ABC", "abc") == 0,
          "lstrcmpi: the plain name folds case");

    check(k32t_lstrcmpW(nullptr, u"a") == 0,
          "lstrcmp: a null input answers 0 with the parameter error");
    check(k32_GetLastError() == kErrorInvalidParameter,
          "lstrcmp: a null input sets ERROR_INVALID_PARAMETER");
}

// ------------------------------------------------- lstrcpy / lstrcat / lstrcpyn

void test_lstrcpy_lstrcat_lstrcpyn() {
    char buf[8] = {};
    char16_t wbuf[8] = {};

    check(k32t_lstrcpyA(buf, "ab") == buf, "lstrcpy: answers the destination");
    check(std::strcmp(buf, "ab") == 0,
          "lstrcpy: the copy is terminated");
    check(k32t_lstrcpyW(wbuf, u"ab") == wbuf, "lstrcpyW: answers the destination");
    check(wbuf[0] == u'a' && wbuf[1] == u'b' && wbuf[2] == u'\0',
          "lstrcpyW: the copy is terminated");
    check(k32t_lstrcpy(buf, "cd") == buf,
          "lstrcpy: the plain name is the A form");

    // The guarded null cases answer null instead of faulting, which is the
    // one behaviour a caller can observe without surviving a crash first.
    check(k32t_lstrcpyA(nullptr, "x") == nullptr,
          "lstrcpy: a null destination answers null");
    check(k32t_lstrcpyA(buf, nullptr) == nullptr,
          "lstrcpy: a null source answers null");

    buf[0] = 'a';
    buf[1] = 'b';
    buf[2] = '\0';
    check(k32t_lstrcatA(buf, "cd") == buf, "lstrcat: answers the destination");
    check(std::strcmp(buf, "abcd") == 0, "lstrcat: the append is terminated");
    check(k32t_lstrcat(nullptr, "x") == nullptr,
          "lstrcat: a null destination answers null");

    wbuf[0] = u'a';
    wbuf[1] = u'b';
    wbuf[2] = u'\0';
    check(k32t_lstrcatW(wbuf, u"cd") == wbuf, "lstrcatW: answers the destination");
    check(wbuf[2] == u'c' && wbuf[3] == u'd' && wbuf[4] == u'\0',
          "lstrcatW: the append is terminated");

    // lstrcpyn is the bounded copy: the count is the whole buffer,
    // terminator included, so a source longer than the count truncates and
    // still terminates.
    std::memset(buf, 'Z', sizeof(buf));
    check(k32t_lstrcpynA(buf, "abcdef", 4) == buf,
          "lstrcpyn: answers the destination");
    check(std::strcmp(buf, "abc") == 0,
          "lstrcpyn: truncates to count-1 characters");
    check(buf[3] == '\0' && buf[4] == 'Z',
          "lstrcpyn: writes exactly the terminator past the copy");

    std::memset(buf, 'Z', sizeof(buf));
    (void)k32t_lstrcpynA(buf, "ab", 4);
    check(std::strcmp(buf, "ab") == 0,
          "lstrcpyn: a short source copies whole and terminates");

    std::memset(buf, 'Z', sizeof(buf));
    (void)k32t_lstrcpynA(buf, "ab", 0);
    check(buf[0] == 'Z',
          "lstrcpyn: a count of zero touches nothing");
    (void)k32t_lstrcpynA(buf, "ab", -1);
    check(buf[0] == 'Z',
          "lstrcpyn: a negative count touches nothing");
    check(k32t_lstrcpynA(nullptr, "ab", 4) == nullptr,
          "lstrcpyn: a null destination answers null");

    std::memset(wbuf, 0x5A * 0x0101, sizeof(wbuf));
    (void)k32t_lstrcpynW(wbuf, u"abcdef", 4);
    check(wbuf[0] == u'a' && wbuf[1] == u'b' && wbuf[2] == u'c' &&
              wbuf[3] == u'\0',
          "lstrcpynW: truncates to count-1 units and terminates");
}

// ------------------------------------------------------------ CompareString

void test_compare_string() {
    // The answers are the ordinals 1/2/3, which is the shape a caller who
    // wrote `result < 0` against this family gets wrong.
    check(k32t_CompareStringW(0, 0, u"a", -1, u"b", -1) == kCstrLessThan,
          "CompareStringW: less answers CSTR_LESS_THAN");
    check(k32t_CompareStringW(0, 0, u"a", -1, u"a", -1) == kCstrEqual,
          "CompareStringW: equal answers CSTR_EQUAL");
    check(k32t_CompareStringW(0, 0, u"b", -1, u"a", -1) == kCstrGreaterThan,
          "CompareStringW: greater answers CSTR_GREATER_THAN");

    check(k32t_CompareStringW(0, 0, u"ab", -1, u"abc", -1) == kCstrLessThan,
          "CompareStringW: a prefix sorts first");
    check(k32t_CompareStringW(0, kNormIgnoreCase, u"ABC", -1, u"abc", -1) ==
              kCstrEqual,
          "CompareStringW: NORM_IGNORECASE folds case");

    // An explicit count compares exactly that many units, so a difference
    // past the count is invisible.
    check(k32t_CompareStringW(0, 0, u"abcx", 3, u"abcy", 3) == kCstrEqual,
          "CompareStringW: a count bounds the compare");
    check(k32t_CompareStringW(0, 0, u"ax", 2, u"ay", 2) == kCstrLessThan,
          "CompareStringW: a count still orders");
    check(k32t_CompareStringW(0, 0, u"a", 0, u"", -1) == kCstrEqual,
          "CompareStringW: a count of zero is the empty string");

    // Width folding: the fullwidth A folds onto the ASCII A only when the
    // flag asks, and the two disagree otherwise.
    check(k32t_CompareStringW(0, kNormIgnoreCase | kNormIgnoreWidth,
                              u"\uFF21", -1, u"A", -1) == kCstrEqual,
          "CompareStringW: NORM_IGNOREWIDTH folds fullwidth onto ASCII");
    check(k32t_CompareStringW(0, 0, u"\uFF21", -1, u"A", -1) ==
              kCstrGreaterThan,
          "CompareStringW: without the width flag the units order");

    // A null with a count is the caller's bug, answered 0 with the
    // parameter error; a null with a count of zero is the empty string.
    check(k32t_CompareStringW(0, 0, nullptr, -1, u"a", -1) == 0,
          "CompareStringW: a null string with -1 fails");
    check(k32_GetLastError() == kErrorInvalidParameter,
          "CompareStringW: the null failure sets ERROR_INVALID_PARAMETER");
    check(k32t_CompareStringW(0, 0, nullptr, 0, u"", -1) == kCstrEqual,
          "CompareStringW: a null with count 0 compares as empty");

    check(k32t_CompareStringA(0, 0, "abc", -1, "abd", -1) == kCstrLessThan,
          "CompareStringA: the A form orders through the bridge");
    check(k32t_CompareStringA(0, 0, "abc", -1, "abc", -1) == kCstrEqual,
          "CompareStringA: the A form answers equal");
    check(k32t_CompareStringA(0, kNormIgnoreCase, "ABC", -1, "abc", -1) ==
              kCstrEqual,
          "CompareStringA: the A form folds case");

    check(k32t_CompareStringEx(nullptr, 0, u"a", -1, u"b", -1, nullptr,
                               nullptr, 0) == kCstrLessThan,
          "CompareStringEx: the extended form orders like W");
    check(k32t_CompareStringEx(nullptr, kNormIgnoreCase, u"ABC", -1, u"abc",
                               -1, nullptr, nullptr, 0) == kCstrEqual,
          "CompareStringEx: the extended form folds case");
    check(k32t_CompareStringEx(nullptr, 0, nullptr, -1, u"a", -1, nullptr,
                               nullptr, 0) == 0,
          "CompareStringEx: a null string with -1 fails");

    // The ordinal compare is where "a" and "B" disagree with the linguistic
    // order: code units put 0x61 after 0x42, the case-folded compare puts
    // A before B. Both answers are asserted so the two layers cannot drift
    // into each other.
    check(k32t_CompareStringOrdinal(u"a", -1, u"B", -1, 0) ==
              kCstrGreaterThan,
          "CompareStringOrdinal: code units order a after B");
    check(k32t_CompareStringOrdinal(u"a", -1, u"B", -1, 1) == kCstrLessThan,
          "CompareStringOrdinal: the case-insensitive form folds first");
    check(k32t_CompareStringOrdinal(u"abc", -1, u"abc", -1, 0) == kCstrEqual,
          "CompareStringOrdinal: equal answers CSTR_EQUAL");
    check(k32t_CompareStringOrdinal(nullptr, -1, u"a", -1, 0) == 0,
          "CompareStringOrdinal: a null string with -1 fails");
}

// -------------------------------------------------------------- FoldString

void test_fold_string() {
    char16_t wbuf[16] = {};

    // Ligature expansion is the one flag whose answer grows the string.
    const std::int32_t lig =
        k32t_FoldStringW(kMapExpandLigatures, u"\u00C6", -1, wbuf, 16);
    check(lig == 3, "FoldStringW: the ligature answer counts the terminator");
    check(wbuf[0] == u'A' && wbuf[1] == u'E' && wbuf[2] == u'\0',
          "FoldStringW: the AE ligature expands");

    std::memset(wbuf, 0, sizeof(wbuf));
    (void)k32t_FoldStringW(kMapFoldDigits, u"\uFF12", -1, wbuf, 16);
    check(wbuf[0] == u'2',
          "FoldStringW: the fullwidth digit folds onto ASCII");

    std::memset(wbuf, 0, sizeof(wbuf));
    const std::int32_t sharp =
        k32t_FoldStringW(kMapFoldCzone, u"\u00E9", -1, wbuf, 16);
    check(sharp == 2 && wbuf[0] == u'e',
          "FoldStringW: the accented e folds to its base");

    std::memset(wbuf, 0, sizeof(wbuf));
    const std::int32_t ss =
        k32t_FoldStringW(kMapFoldCzone, u"\u00DF", -1, wbuf, 16);
    check(ss == 3 && wbuf[0] == u's' && wbuf[1] == u's',
          "FoldStringW: the sharp-s expands to ss");

    std::memset(wbuf, 0, sizeof(wbuf));
    (void)k32t_FoldStringW(kMapExpandLigatures | kMapFoldCzone, u"\u00C6\u00E9",
                           -1, wbuf, 16);
    check(wbuf[0] == u'A' && wbuf[1] == u'E' && wbuf[2] == u'e',
          "FoldStringW: the flags combine");

    // An explicit count does not add a terminator to the answer.
    check(k32t_FoldStringW(kMapExpandLigatures, u"\u00C6", 1, wbuf, 16) == 2,
          "FoldStringW: an explicit count answers without the terminator");

    // The size query answers the required count and touches nothing.
    check(k32t_FoldStringW(kMapExpandLigatures, u"\u00C6", -1, nullptr, 0) ==
              3,
          "FoldStringW: a null destination answers the required size");
    check(k32t_FoldStringW(kMapExpandLigatures, u"\u00C6", -1, wbuf, 1) == 0,
          "FoldStringW: a short buffer fails");
    check(k32_GetLastError() == kErrorInsufficientBuffer,
          "FoldStringW: the short buffer sets ERROR_INSUFFICIENT_BUFFER");

    // The refusals: no flag, both directions at once, and a bit the fold
    // does not know.
    set_last_error(0);
    check(k32t_FoldStringW(0, u"a", -1, wbuf, 16) == 0,
          "FoldStringW: a zero flag set fails");
    check(k32_GetLastError() == kErrorInvalidParameter,
          "FoldStringW: the zero flag sets ERROR_INVALID_PARAMETER");
    check(k32t_FoldStringW(kMapComposite | kMapPrecomposed, u"a", -1, wbuf,
                           16) == 0,
          "FoldStringW: composite and precomposed are exclusive");
    check(k32t_FoldStringW(0x80000000u, u"a", -1, wbuf, 16) == 0,
          "FoldStringW: an unknown flag bit fails");
    check(k32t_FoldStringW(kMapExpandLigatures, nullptr, -1, wbuf, 16) == 0,
          "FoldStringW: a null source fails");

    // The A form runs the same fold over the UTF-8 bridge: the bytes of
    // the AE ligature go in, the expansion comes out.
    char buf[16] = {};
    const std::int32_t alig =
        k32t_FoldStringA(kMapExpandLigatures, "\xC3\x86", -1, buf, 16);
    check(alig == 3 && std::strcmp(buf, "AE") == 0,
          "FoldStringA: the A form expands through the bridge");
    check(k32t_FoldStringA(kMapExpandLigatures, "\xC3\x86", -1, nullptr, 0) ==
              3,
          "FoldStringA: the A size query answers bytes");
}

// ------------------------------------------------------------ GetStringType

void test_get_string_type() {
    std::uint16_t types[8] = {};

    check(k32t_GetStringTypeW(1, u"aB3", -1, types) == 1,
          "GetStringTypeW: CT_CTYPE1 succeeds");
    check(types[0] == (0x0002 | 0x0100 | 0x0080),
          "GetStringTypeW: lowercase a is lower, alpha, xdigit");
    check(types[1] == (0x0001 | 0x0100 | 0x0080),
          "GetStringTypeW: uppercase B is upper, alpha, xdigit");
    check(types[2] == (0x0004 | 0x0080),
          "GetStringTypeW: digit 3 is digit and xdigit");

    check(k32t_GetStringTypeW(1, u" \t\n;@\x01", -1, types) == 1,
          "GetStringTypeW: the punctuation and space sweep succeeds");
    check(types[0] == (0x0008 | 0x0040),
          "GetStringTypeW: space is space and blank");
    check(types[1] == (0x0008 | 0x0040 | 0x0020),
          "GetStringTypeW: tab is space, blank and control");
    check(types[2] == (0x0008 | 0x0020),
          "GetStringTypeW: newline is space and control");
    check(types[3] == 0x0010 && types[4] == 0x0010,
          "GetStringTypeW: semicolon and at are punctuation");
    check(types[5] == 0x0020, "GetStringTypeW: 0x01 is control");

    check(k32t_GetStringTypeW(1, u"\x00E9", -1, types) == 1 &&
              types[0] == (0x0002 | 0x0100),
          "GetStringTypeW: the accented e is lower and alpha");

    // CT2 places direction and number class.
    check(k32t_GetStringTypeW(2, u"A5 \u0627", -1, types) == 1,
          "GetStringTypeW: CT_CTYPE2 succeeds");
    check(types[0] == 1, "GetStringTypeW: a letter is left-to-right");
    check(types[1] == 3, "GetStringTypeW: a digit is European number");
    check(types[2] == 9, "GetStringTypeW: space is whitespace");
    check(types[3] == 2, "GetStringTypeW: Arabic alef is right-to-left");

    // CT3 places the surrogate and script bits the runtime walks.
    check(k32t_GetStringTypeW(3, u"\U0001F600A\u3042\uFF21", -1, types) == 1,
          "GetStringTypeW: CT_CTYPE3 succeeds");
    check(types[0] == 0x0800, "GetStringTypeW: the high surrogate is marked");
    check(types[1] == 0x1000, "GetStringTypeW: the low surrogate is marked");
    check(types[2] == 0x8000, "GetStringTypeW: A carries the alpha bit");
    check(types[3] == (0x0020 | 0x0100),
          "GetStringTypeW: hiragana carries hiragana and ideogram");
    check(types[4] == (0x8000 | 0x0080),
          "GetStringTypeW: fullwidth A is alpha and fullwidth");

    // The refusals.
    set_last_error(0);
    check(k32t_GetStringTypeW(0, u"a", -1, types) == 0,
          "GetStringTypeW: an unknown info type fails");
    check(k32_GetLastError() == kErrorInvalidParameter,
          "GetStringTypeW: the unknown type sets ERROR_INVALID_PARAMETER");
    check(k32t_GetStringTypeW(1, nullptr, -1, types) == 0,
          "GetStringTypeW: a null source fails");
    check(k32t_GetStringTypeW(1, u"a", -1, nullptr) == 0,
          "GetStringTypeW: a null answer array fails");

    check(k32t_GetStringTypeExW(0, 1, u"aB3", -1, types) == 1,
          "GetStringTypeExW: the Ex form answers like W");
    check(types[0] == (0x0002 | 0x0100 | 0x0080),
          "GetStringTypeExW: the Ex form agrees on the classes");

    // The A form types bytes: every byte of a multi-byte character carries
    // the character's class, which is what a caller sizing the array from
    // the byte length relies on.
    check(k32t_GetStringTypeA(0, 1, "aB3", -1, types) == 1,
          "GetStringTypeA: CT_CTYPE1 succeeds");
    check(types[0] == (0x0002 | 0x0100 | 0x0080) &&
              types[1] == (0x0001 | 0x0100 | 0x0080) &&
              types[2] == (0x0004 | 0x0080),
          "GetStringTypeA: the byte types match the character classes");
    check(k32t_GetStringTypeA(0, 1, "\xC3\x89", -1, types) == 1,
          "GetStringTypeA: a two-byte character succeeds");
    check(types[0] == (0x0001 | 0x0100) && types[1] == (0x0001 | 0x0100),
          "GetStringTypeA: both bytes of E-acute carry upper and alpha");
    check(k32t_GetStringTypeExA(0, 1, "aB3", -1, types) == 1,
          "GetStringTypeExA: the Ex form answers like A");
    check(k32t_GetStringTypeA(0, 99, "a", -1, types) == 0,
          "GetStringTypeA: an unknown info type fails");
}

// ---------------------------------------------------------- IsDBCSLeadByte

void test_is_dbcs_lead_byte() {
    // The ANSI code page this runtime models is UTF-8, which is not a DBCS:
    // no byte opens a two-byte character in the Windows sense, so every
    // byte answers false. The bytes probed are the ones a DBCS code page
    // would name as leads.
    check(k32t_IsDBCSLeadByte(0x81) == 0,
          "IsDBCSLeadByte: 0x81 is not a lead byte under UTF-8");
    check(k32t_IsDBCSLeadByte(0xE0) == 0,
          "IsDBCSLeadByte: 0xE0 is not a lead byte under UTF-8");
    check(k32t_IsDBCSLeadByte(0xC2) == 0,
          "IsDBCSLeadByte: a UTF-8 lead is not a DBCS lead");
    check(k32t_IsDBCSLeadByte(0x41) == 0,
          "IsDBCSLeadByte: ASCII is not a lead byte");
}

// ------------------------------------------------------------ LCMapString

void test_lcmap_string() {
    char16_t wbuf[16] = {};

    check(k32t_LCMapStringW(0, kCmapLowercase, u"AbC", -1, wbuf, 16) == 4,
          "LCMapStringW: lowercase answers with the terminator");
    check(wbuf[0] == u'a' && wbuf[1] == u'b' && wbuf[2] == u'c' &&
              wbuf[3] == u'\0',
          "LCMapStringW: the lowercase copy is terminated");

    std::memset(wbuf, 0, sizeof(wbuf));
    check(k32t_LCMapStringW(0, kCmapUppercase, u"\x00E9\x03B1\x0430", -1,
                            wbuf, 16) == 4,
          "LCMapStringW: uppercase spans the covered blocks");
    check(wbuf[0] == u'\x00C9' && wbuf[1] == u'\x0391' && wbuf[2] == u'\x0410',
          "LCMapStringW: Latin, Greek and Cyrillic all upcase");

    // An explicit count answers without the terminator.
    check(k32t_LCMapStringW(0, kCmapLowercase, u"ABC", 3, wbuf, 16) == 3,
          "LCMapStringW: an explicit count answers without the terminator");

    check(k32t_LCMapStringW(0, kCmapLowercase, u"ABC", -1, nullptr, 0) == 4,
          "LCMapStringW: the size query answers the required count");
    check(k32t_LCMapStringW(0, kCmapLowercase, u"ABC", -1, wbuf, 2) == 0,
          "LCMapStringW: a short buffer fails");
    check(k32_GetLastError() == kErrorInsufficientBuffer,
          "LCMapStringW: the short buffer sets ERROR_INSUFFICIENT_BUFFER");

    set_last_error(0);
    check(k32t_LCMapStringW(0, kCmapLowercase | kCmapUppercase, u"ABC", -1,
                            wbuf, 16) == 0,
          "LCMapStringW: both case directions at once fails");
    check(k32_GetLastError() == kErrorInvalidParameter,
          "LCMapStringW: the mixed case flags set ERROR_INVALID_PARAMETER");
    check(k32t_LCMapStringW(0, kCmapSortkey | kCmapLowercase, u"ABC", -1,
                            wbuf, 16) == 0,
          "LCMapStringW: a sort key with a case map fails");
    check(k32t_LCMapStringW(0, 0, u"ABC", -1, wbuf, 16) == 0,
          "LCMapStringW: no mapping flag fails");
    check(k32t_LCMapStringW(0, kCmapLowercase, nullptr, -1, wbuf, 16) == 0,
          "LCMapStringW: a null source fails");
    check(k32t_LCMapStringW(0, kCmapLowercase, u"ABC", 0, wbuf, 16) == 0,
          "LCMapStringW: a zero source count fails");

    // The sort key is bytes: the size is bytes, the key of folded-equal
    // text is equal, and the keys order the way the strings do.
    const std::int32_t key_size =
        k32t_LCMapStringW(0, kCmapSortkey, u"abc", -1, nullptr, 0);
    check(key_size == 9,
          "LCMapStringW: the sort key query answers bytes (2 per unit + end)");

    std::string keys[3] = {};
    const auto key_of = [&keys](const char16_t* text) {
        const std::int32_t n = k32t_LCMapStringW(0, kCmapSortkey, text, -1,
                                                 nullptr, 0);
        keys[0].resize(static_cast<std::size_t>(n));
        const std::int32_t got =
            k32t_LCMapStringW(0, kCmapSortkey, text, -1,
                              reinterpret_cast<char16_t*>(keys[0].data()), n);
        return got > 0 && static_cast<std::size_t>(got) == keys[0].size();
    };
    check(key_of(u"abc"), "LCMapStringW: the sort key copies whole");

    const std::int32_t kAB =
        k32t_LCMapStringW(0, kCmapSortkey | kNormIgnoreCase, u"AB", -1,
                          nullptr, 0);
    std::string ka(static_cast<std::size_t>(kAB), '\0');
    std::string kb(static_cast<std::size_t>(kAB), '\0');
    (void)k32t_LCMapStringW(0, kCmapSortkey | kNormIgnoreCase, u"AB", -1,
                            reinterpret_cast<char16_t*>(ka.data()), kAB);
    (void)k32t_LCMapStringW(0, kCmapSortkey | kNormIgnoreCase, u"ab", -1,
                            reinterpret_cast<char16_t*>(kb.data()), kAB);
    check(ka == kb,
          "LCMapStringW: the sort key folds case under NORM_IGNORECASE");

    const std::int32_t one = k32t_LCMapStringW(0, kCmapSortkey, u"a", -1,
                                               nullptr, 0);
    std::string key_a(static_cast<std::size_t>(one), '\0');
    std::string key_b(static_cast<std::size_t>(one), '\0');
    (void)k32t_LCMapStringW(0, kCmapSortkey, u"a", -1,
                            reinterpret_cast<char16_t*>(key_a.data()), one);
    (void)k32t_LCMapStringW(0, kCmapSortkey, u"b", -1,
                            reinterpret_cast<char16_t*>(key_b.data()), one);
    check(std::memcmp(key_a.data(), key_b.data(), 2) < 0,
          "LCMapStringW: sort keys order as the strings do");

    const std::int32_t rev =
        k32t_LCMapStringW(0, kCmapSortkey | kCmapByteRev, u"a", -1, nullptr, 0);
    std::string key_plain(static_cast<std::size_t>(one), '\0');
    std::string key_reversed(static_cast<std::size_t>(rev), '\0');
    (void)k32t_LCMapStringW(0, kCmapSortkey, u"a", -1,
                            reinterpret_cast<char16_t*>(key_plain.data()), one);
    (void)k32t_LCMapStringW(0, kCmapSortkey | kCmapByteRev, u"a", -1,
                            reinterpret_cast<char16_t*>(key_reversed.data()),
                            rev);
    check(key_plain.size() == key_reversed.size() &&
              key_plain[0] == key_reversed[1] && key_plain[1] == key_reversed[0],
          "LCMapStringW: byte reversal swaps each unit pair");

    // The A form answers in bytes over the bridge, so the size of a result
    // differs from the W form exactly as UTF-8 differs from UTF-16.
    char buf[16] = {};
    check(k32t_LCMapStringA(0, kCmapLowercase, "AbC", -1, buf, 16) == 4,
          "LCMapStringA: lowercase answers with the terminator");
    check(std::strcmp(buf, "abc") == 0,
          "LCMapStringA: the lowercase copy is terminated");
    check(k32t_LCMapStringA(0, kCmapUppercase, "\xC3\xA9", -1, buf, 16) == 3,
          "LCMapStringA: uppercase answers the byte count");
    check(static_cast<unsigned char>(buf[0]) == 0xC3 &&
              static_cast<unsigned char>(buf[1]) == 0x89,
          "LCMapStringA: e-acute upcases to E-acute in UTF-8");
    check(k32t_LCMapStringA(0, kCmapLowercase, "AbC", -1, nullptr, 0) == 4,
          "LCMapStringA: the size query answers bytes");
    const std::int32_t akey =
        k32t_LCMapStringA(0, kCmapSortkey, "abc", -1, nullptr, 0);
    check(akey == key_size,
          "LCMapStringA: the A sort key is the same key the W form makes");

    check(k32t_LCMapStringEx(nullptr, kCmapLowercase, u"AbC", -1, wbuf, 16,
                             nullptr, nullptr, 0) == 4,
          "LCMapStringEx: the extended form maps like W");
    check(wbuf[0] == u'a' && wbuf[1] == u'b' && wbuf[2] == u'c',
          "LCMapStringEx: the extended form copies the map");
}

// ------------------------------------------------------------ registration

void test_registration() {
    ExportList list;
    add_kernel32_str(list);

    check(list.size() == 32, "api: the domain registers exactly its 32 names");

    bool duplicate = false;
    for (std::size_t i = 0; i < list.size() && !duplicate; ++i) {
        for (std::size_t k = i + 1; k < list.size(); ++k) {
            if (list[i].name == list[k].name) {
                duplicate = true;
                break;
            }
        }
    }
    check(!duplicate, "api: no name is registered twice");

    bool all_named = true;
    bool all_addressed = true;
    for (const HostExport& entry : list) {
        if (entry.name.empty()) {
            all_named = false;
        }
        if (entry.address == 0) {
            all_addressed = false;
        }
    }
    check(all_named, "api: every entry has a name");
    check(all_addressed, "api: every entry has an address");

    // The names the work order lists, each found once.
    static const char* const kNames[] = {
        "CompareStringA",    "CompareStringEx",   "CompareStringOrdinal",
        "CompareStringW",    "FoldStringA",       "FoldStringW",
        "GetStringTypeA",    "GetStringTypeExA",  "GetStringTypeExW",
        "GetStringTypeW",    "IsDBCSLeadByte",    "LCMapStringA",
        "LCMapStringEx",     "LCMapStringW",      "lstrcat",
        "lstrcatA",          "lstrcatW",          "lstrcmp",
        "lstrcmpA",          "lstrcmpW",          "lstrcmpi",
        "lstrcmpiA",         "lstrcmpiW",         "lstrcpy",
        "lstrcpyA",          "lstrcpyW",          "lstrcpyn",
        "lstrcpynA",         "lstrcpynW",         "lstrlen",
        "lstrlenA",          "lstrlenW",
    };
    for (const char* name : kNames) {
        bool found = false;
        for (const HostExport& entry : list) {
            if (entry.name == name) {
                found = true;
                break;
            }
        }
        check(found, name);
    }
}

}  // namespace

int main() {
    test_lstrlen();
    test_lstrcmp();
    test_lstrcpy_lstrcat_lstrcpyn();
    test_compare_string();
    test_fold_string();
    test_get_string_type();
    test_is_dbcs_lead_byte();
    test_lcmap_string();
    test_registration();

    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

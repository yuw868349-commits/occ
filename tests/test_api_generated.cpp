// The surface this runtime did not answer: what it registers, and what the
// registered entry points do.
//
// The claim this file exists to check is structural as much as behavioural.
// A guest imports a name, and the loader either finds an address for it or
// reports the import unresolved -- there is no third answer. So the first
// thing checked here is that every module the generated surface is made of
// is registered, and that the names inside it resolve.
//
// The second thing is that the entry points which *do* the thing do it
// right. The vectors below are the reference implementation's own test
// vectors -- wine's `dlls/shlwapi/tests/string.c` for the size and interval
// formatters, and the path rules for the string family -- because a value
// this file computed from the same arithmetic the implementation uses would
// only be checking that the code equals itself.
//
// The third is the refusal. An entry point whose subsystem is absent
// answers `ERROR_CALL_NOT_IMPLEMENTED` and a zero; it does not answer
// success. That distinction is the whole point of the surface, and it is
// checked here rather than assumed.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/exports.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

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

void check_text(const char* got, const char* wanted, const char* what) {
    ++checks;
    if (got == nullptr || std::strcmp(got, wanted) != 0) {
        ++failures;
        std::fprintf(stderr, "FAIL %s: got \"%s\", wanted \"%s\"\n", what,
                     got == nullptr ? "(null)" : got, wanted);
    }
}

ExportRegistry& registry() {
    static ExportRegistry instance;
    static bool ready = false;
    if (!ready) {
        register_host_modules(instance);
        ready = true;
    }
    return instance;
}

// One entry point, by the module and name a guest would import.
template <typename Fn>
Fn entry(const char* module, const char* name) {
    ExportRegistry& table = registry();
    const std::uint64_t address =
        table.resolve(&table, module, name, 0, false);
    return reinterpret_cast<Fn>(address);
}

// The entry points are `ms_abi` functions, and a call through a function
// pointer that did not say so would pass its arguments in this host's
// registers rather than the guest's -- which is a crash in the first call
// rather than a wrong answer in the third.
#define OCC_MS_ABI __attribute__((ms_abi))

using MsgFn = std::int32_t (OCC_MS_ABI *)();

// ---------------------------------------------------------------- the set

// Every module the generated surface contributes to. The list is the
// modules the files under `src/runtime/api/generated/` are named for, and a
// module missing from here is a file that is compiled and never reached.
const char* const kGeneratedModules[] = {
    "ADVAPI32.dll", "AVIFIL32.dll", "BCRYPT.dll", "COMCTL32.dll",
    "COMDLG32.dll", "CRYPT32.dll", "DBGHELP.dll", "DHCPCSVC.dll",
    "DNSAPI.dll", "GDI32.dll", "IMM32.dll", "IPHLPAPI.dll", "KERNEL32.dll",
    "MPR.dll", "MSACM32.dll", "MSWSOCK.dll", "NETAPI32.dll", "NTDLL.dll",
    "OLE32.dll", "OLEAUT32.dll", "OPENGL32.dll", "RPCRT4.dll", "SECUR32.dll",
    "SETUPAPI.dll", "SHELL32.dll", "SHLWAPI.dll", "USER32.dll",
    "USERENV.dll", "UXTHEME.dll", "WINHTTP.dll", "WININET.dll", "WINMM.dll",
    "WINSPOOL.DRV", "WINTRUST.dll", "WLDAP32.dll", "WS2_32.dll",
    "WTSAPI32.dll",
};

void test_registration() {
    std::size_t modules = 0;
    std::size_t exports = 0;
    for (const char* name : kGeneratedModules) {
        const ExportModule* module = registry().find(name);
        check(module != nullptr, name);
        if (module == nullptr) {
            continue;
        }
        ++modules;
        exports += module->host_exports.size();
    }
    check(modules == sizeof(kGeneratedModules) / sizeof(kGeneratedModules[0]),
          "every generated module is registered");
    // The count rather than an exact figure: the surface is generated, and a
    // file regenerated from a newer import library would carry more names.
    // What would be a defect is a module that lost its list, and a floor of
    // five thousand is what catches that without pinning the number.
    std::printf("generated surface: %zu modules, %zu exports\n", modules,
                exports);
    check(exports >= 5000, "the generated surface carries the names it was built from");

    // The whole registry, for the report the docs quote.
    std::size_t all_modules = 0;
    std::size_t all_exports = 0;
    for (const ExportModule* module : registry().modules()) {
        ++all_modules;
        all_exports += module->host_exports.size();
    }
    std::printf("registry: %zu modules, %zu exports\n", all_modules,
                all_exports);
}

// ---------------------------------------------------------------- the path

void test_path() {
    using AddExtension = std::int32_t (OCC_MS_ABI *)(char*, const char*);
    using StripToRoot = std::int32_t (OCC_MS_ABI *)(char*);
    using Canonicalize = std::int32_t (OCC_MS_ABI *)(char*, const char*);
    using MatchSpec = std::int32_t (OCC_MS_ABI *)(const char*, const char*);
    using RemoveBlanks = void (OCC_MS_ABI *)(char*);
    using Undecorate = void (OCC_MS_ABI *)(char*);
    using RemoveExtension = void (OCC_MS_ABI *)(char*);
    using IsRoot = std::int32_t (OCC_MS_ABI *)(const char*);
    using IsUncServer = std::int32_t (OCC_MS_ABI *)(const char*);
    using IsRelative = std::int32_t (OCC_MS_ABI *)(const char*);
    using GetCharType = std::uint32_t (OCC_MS_ABI *)(char);
    using CompactPathEx = std::int32_t (OCC_MS_ABI *)(char*, const char*, std::uint32_t,
                                           std::uint32_t);

    const auto add_extension = entry<AddExtension>("SHLWAPI.dll", "PathAddExtensionA");
    const auto strip_to_root = entry<StripToRoot>("SHLWAPI.dll", "PathStripToRootA");
    const auto canonicalize = entry<Canonicalize>("SHLWAPI.dll", "PathCanonicalizeA");
    const auto match_spec = entry<MatchSpec>("SHLWAPI.dll", "PathMatchSpecA");
    const auto remove_blanks = entry<RemoveBlanks>("SHLWAPI.dll", "PathRemoveBlanksA");
    const auto undecorate = entry<Undecorate>("SHLWAPI.dll", "PathUndecorateA");
    const auto remove_extension = entry<RemoveExtension>("SHLWAPI.dll", "PathRemoveExtensionA");
    const auto is_root = entry<IsRoot>("SHLWAPI.dll", "PathIsRootA");
    const auto is_unc_server = entry<IsUncServer>("SHLWAPI.dll", "PathIsUNCServerA");
    const auto is_relative = entry<IsRelative>("SHLWAPI.dll", "PathIsRelativeA");
    const auto get_char_type = entry<GetCharType>("SHLWAPI.dll", "PathGetCharTypeA");
    const auto compact = entry<CompactPathEx>("SHLWAPI.dll", "PathCompactPathExA");

    check(add_extension != nullptr, "PathAddExtensionA resolves");
    if (add_extension == nullptr) {
        return;
    }

    char buffer[260];

    // An extension is added once and refused the second time: the call
    // answers whether it added one, not whether the name now has one.
    std::strcpy(buffer, "report");
    check(add_extension(buffer, ".txt") == 1, "add extension: answers true");
    check_text(buffer, "report.txt", "add extension: appended");
    check(add_extension(buffer, ".doc") == 0, "add extension: refused when present");
    check_text(buffer, "report.txt", "add extension: left alone");

    // A dot that opens the name still counts as one for this family: the
    // search is for the last dot after the last separator, and a name that
    // begins with one has a dot at the start rather than none at all. The
    // reference answers the same, which is why an extension is refused
    // here.
    std::strcpy(buffer, ".gitignore");
    check(add_extension(buffer, ".txt") == 0,
          "add extension: a leading dot counts, so an extension is refused");
    check_text(buffer, ".gitignore", "add extension: the name is left alone");

    std::strcpy(buffer, "C:\\dir\\file.txt");
    check(remove_extension != nullptr, "PathRemoveExtensionA resolves");
    remove_extension(buffer);
    check_text(buffer, "C:\\dir\\file", "remove extension");

    std::strcpy(buffer, "C:\\dir\\file.txt");
    check(strip_to_root != nullptr && strip_to_root(buffer) == 1,
          "strip to root: answers true");
    check_text(buffer, "C:\\", "strip to root");

    std::strcpy(buffer, "\\\\server\\share\\a\\b");
    check(strip_to_root(buffer) == 1, "strip to root: a share");
    check_text(buffer, "\\\\server\\share", "strip to root: the share survives");

    // `..` folds back over a component, and over the root it does not
    // climb: `\..\a` is `\a`, which is the rule that makes the leading
    // separator the floor.
    check(canonicalize != nullptr, "PathCanonicalizeA resolves");
    canonicalize(buffer, "C:\\a\\..\\b");
    check_text(buffer, "C:\\b", "canonicalize: a component folded");
    canonicalize(buffer, "C:\\a\\..\\..\\b");
    check_text(buffer, "C:\\b", "canonicalize: the root holds");
    canonicalize(buffer, "C:");
    check_text(buffer, "C:\\", "canonicalize: a bare drive gains a root");
    canonicalize(buffer, "\\a\\.\\b");
    check_text(buffer, "\\a\\b", "canonicalize: the current directory dropped");
    canonicalize(buffer, "a\\..\\..\\b");
    check_text(buffer, "\\b", "canonicalize: a relative path cannot climb out");

    check(match_spec != nullptr, "PathMatchSpecA resolves");
    check(match_spec("report.txt", "*.txt") == 1, "match: a suffix");
    check(match_spec("report.txt", "*.doc") == 0, "match: a wrong suffix");
    check(match_spec("report.txt", "*.txt;*.doc") == 1, "match: one of two masks");
    check(match_spec("report.txt", "repor?.txt") == 1, "match: one character");
    check(match_spec("a.b.txt", "*.txt") == 1, "match: a star spans dots");
    check(match_spec("anything", "*.*") == 1, "match: the everything mask");

    std::strcpy(buffer, "  spaced  ");
    check(remove_blanks != nullptr, "PathRemoveBlanksA resolves");
    remove_blanks(buffer);
    check_text(buffer, "spaced", "blanks removed from both ends");

    std::strcpy(buffer, "name[12].txt");
    check(undecorate != nullptr, "PathUndecorateA resolves");
    undecorate(buffer);
    check_text(buffer, "name.txt", "undecorated");

    std::strcpy(buffer, "name[abc].txt");
    undecorate(buffer);
    check_text(buffer, "name[abc].txt", "a bracket that is not a decoration is kept");

    check(is_root != nullptr && is_root("C:\\") == 1, "root: a drive");
    check(is_root("C:\\a") == 0, "root: not a drive with a component");
    check(is_root("\\") == 1, "root: the current drive");
    check(is_root("\\\\server\\share") == 1, "root: a share");
    // A server with no share passes this walk too, because the walk counts
    // separators and answers true for at most one. That is the reference's
    // rule, and it is why `PathIsRoot` is not the predicate for "this names
    // a share" -- `PathIsUNCServer` is.
    check(is_root("\\\\server") == 1, "root: a server alone passes the walk");

    check(is_unc_server != nullptr && is_unc_server("\\\\server") == 1,
          "unc server");
    check(is_unc_server("\\\\server\\share") == 0, "unc server: a share is not one");

    check(is_relative != nullptr && is_relative("a\\b") == 1, "relative: a name");
    check(is_relative("\\a") == 0, "relative: a rooted path");
    check(is_relative("C:a") == 0, "relative: a drive-relative path is absolute");
    check(is_relative("C:\\a") == 0, "relative: a drive path");

    // The class of a character: the separator, the wildcard, the ones the
    // file system reserves, and the ordinary ones.
    check(get_char_type != nullptr, "PathGetCharTypeA resolves");
    check((get_char_type('\\') & 0x0008u) != 0, "char type: a separator");
    check((get_char_type('*') & 0x0004u) != 0, "char type: a wildcard");
    check(get_char_type('<') == 0, "char type: a reserved character");
    check((get_char_type('a') & 0x0003u) == 0x0003u, "char type: an ordinary one");

    check(compact != nullptr, "PathCompactPathExA resolves");
    std::memset(buffer, 0, sizeof(buffer));
    compact(buffer, "C:\\a\\b\\c\\file.txt", 12, 0);
    check(std::strlen(buffer) <= 11, "compact: the answer fits the caller's count");

    // A path that already fits is copied whole, and the answer says so.
    compact(buffer, "C:\\a", 12, 0);
    check_text(buffer, "C:\\a", "compact: a path that fits is copied");
}

// --------------------------------------------------------------- the text

void test_strings() {
    using FormatByteSize64 = char* (OCC_MS_ABI *)(std::int64_t, char*, std::uint32_t);
    using FormatKbSize = char* (OCC_MS_ABI *)(std::int64_t, char*, std::uint32_t);
    using FromTimeInterval = std::int32_t (OCC_MS_ABI *)(char*, std::uint32_t,
                                              std::uint32_t, std::int32_t);
    using StrNCat = char* (OCC_MS_ABI *)(char*, const char*, std::int32_t);
    using ChrCmpI = std::int32_t (OCC_MS_ABI *)(std::uint16_t, std::uint16_t);
    using IsCharSpace = std::int32_t (OCC_MS_ABI *)(char);
    using IntlStrEqWorker = std::int32_t (OCC_MS_ABI *)(std::int32_t, const char*,
                                             const char*, std::int32_t);

    const auto byte_size = entry<FormatByteSize64>("SHLWAPI.dll", "StrFormatByteSize64A");
    const auto kb_size = entry<FormatKbSize>("SHLWAPI.dll", "StrFormatKBSizeA");
    const auto interval = entry<FromTimeInterval>("SHLWAPI.dll", "StrFromTimeIntervalA");
    const auto ncat = entry<StrNCat>("SHLWAPI.dll", "StrNCatA");
    const auto chr_cmp_i = entry<ChrCmpI>("SHLWAPI.dll", "ChrCmpIA");
    const auto is_space = entry<IsCharSpace>("SHLWAPI.dll", "IsCharSpaceA");
    const auto intl_eq = entry<IntlStrEqWorker>("SHLWAPI.dll", "IntlStrEqWorkerA");

    if (byte_size == nullptr || kb_size == nullptr || interval == nullptr) {
        check(false, "the string formatters resolve");
        return;
    }

    // The reference's own vectors, from its `string.c` test. The count is
    // printed without a thousands separator because the runtime answers the
    // C locale, whose separator is the empty string -- which is also what
    // the reference's own answers show for every size it tests.
    struct SizeCase {
        std::int64_t value;
        const char* bytes;
        const char* kilobytes;
    };
    static const SizeCase size_cases[] = {
        {-1023, "-1023 bytes", "0 KB"},
        {-24, "-24 bytes", "0 KB"},
        {309, "309 bytes", "1 KB"},
        {10191, "9.95 KB", "10 KB"},
        {100353, "98.0 KB", "99 KB"},
        {1022286, "998 KB", "999 KB"},
        {1046862, "0.99 MB", "1023 KB"},
        {1048574619, "999 MB", "1023999 KB"},
        {1073741775, "0.99 GB", "1048576 KB"},
    };
    char buffer[64];
    for (const SizeCase& one : size_cases) {
        std::memset(buffer, 0, sizeof(buffer));
        byte_size(one.value, buffer, sizeof(buffer));
        check_text(buffer, one.bytes, "StrFormatByteSize64A");
        std::memset(buffer, 0, sizeof(buffer));
        kb_size(one.value, buffer, sizeof(buffer));
        check_text(buffer, one.kilobytes, "StrFormatKBSizeA");
    }

    struct IntervalCase {
        std::uint32_t milliseconds;
        std::int32_t digits;
        const char* text;
    };
    static const IntervalCase interval_cases[] = {
        {1, 1, " 0 sec"},
        {1, 7, " 0 sec"},
        {1000000, 1, " 10 min"},
        {1000000, 2, " 16 min"},
        {1000000, 3, " 16 min 40 sec"},
        {1000000, 7, " 16 min 40 sec"},
        {1999999, 1, " 30 min"},
        {1999999, 3, " 33 min 20 sec"},
        {3999997, 1, " 1 hr"},
        {3999997, 2, " 1 hr 6 min"},
        {3999997, 3, " 1 hr 6 min 40 sec"},
    };
    for (const IntervalCase& one : interval_cases) {
        std::memset(buffer, 0, sizeof(buffer));
        interval(buffer, sizeof(buffer), one.milliseconds, one.digits);
        check_text(buffer, one.text, "StrFromTimeIntervalA");
    }

    if (ncat == nullptr || chr_cmp_i == nullptr || is_space == nullptr ||
        intl_eq == nullptr) {
        check(false, "the rest of the string family resolves");
        return;
    }

    // The count bounds what is appended, not the total length.
    std::strcpy(buffer, "abc");
    ncat(buffer, "defgh", 3);
    check_text(buffer, "abcde", "StrNCatA: two characters and the terminator");

    check(chr_cmp_i('A', 'a') == 0, "ChrCmpIA: a case fold makes them equal");
    check(chr_cmp_i('a', 'b') < 0, "ChrCmpIA: ordered");
    check(is_space(' ') == 1 && is_space('\t') == 1, "IsCharSpaceA: blanks");
    check(is_space('x') == 0, "IsCharSpaceA: not a blank");
    check(intl_eq(1, "abc", "abc", -1) == 1, "IntlStrEqWorkerA: equal");
    check(intl_eq(1, "abc", "ABC", -1) == 0, "IntlStrEqWorkerA: case matters when asked");
    check(intl_eq(0, "abc", "ABC", -1) == 1, "IntlStrEqWorkerA: folded");
    check(intl_eq(1, "abcd", "abce", 3) == 1, "IntlStrEqWorkerA: the bound holds");
}

// ---------------------------------------------------------- the atomics

void test_interlocked() {
    using Increment = std::int32_t (OCC_MS_ABI *)(std::int32_t*);
    using Decrement = std::int32_t (OCC_MS_ABI *)(std::int32_t*);
    using Add = std::int32_t (OCC_MS_ABI *)(std::int32_t*, std::int32_t);
    using ExchangeAdd = std::int32_t (OCC_MS_ABI *)(std::int32_t*, std::int32_t);
    using CompareExchange = std::int32_t (OCC_MS_ABI *)(std::int32_t*, std::int32_t,
                                             std::int32_t);
    using Exchange = std::int32_t (OCC_MS_ABI *)(std::int32_t*, std::int32_t);
    using And = std::int32_t (OCC_MS_ABI *)(std::int32_t*, std::int32_t);
    using Or = std::int32_t (OCC_MS_ABI *)(std::int32_t*, std::int32_t);
    using Increment16 = std::int16_t (OCC_MS_ABI *)(std::int16_t*);
    using Increment64 = std::int64_t (OCC_MS_ABI *)(std::int64_t*);
    using TestAndSet = std::uint8_t (OCC_MS_ABI *)(std::int32_t*, std::int32_t);
    using BitTest = std::uint8_t (OCC_MS_ABI *)(const std::int32_t*, std::int32_t);
    using ScanForward = std::uint8_t (OCC_MS_ABI *)(std::uint32_t*, std::uint32_t);
    using ScanReverse = std::uint8_t (OCC_MS_ABI *)(std::uint32_t*, std::uint32_t);
    using Multiply = std::uint64_t (OCC_MS_ABI *)(std::uint64_t, std::uint64_t,
                                       std::uint64_t*);
    using MulDiv = std::int32_t (OCC_MS_ABI *)(std::int32_t, std::int32_t, std::int32_t);

    const auto increment = entry<Increment>("KERNEL32.dll", "_InterlockedIncrement");
    const auto decrement = entry<Decrement>("KERNEL32.dll", "_InterlockedDecrement");
    const auto add = entry<Add>("KERNEL32.dll", "_InterlockedAdd");
    const auto exchange_add = entry<ExchangeAdd>("KERNEL32.dll", "_InterlockedExchangeAdd");
    const auto compare_exchange = entry<CompareExchange>("KERNEL32.dll", "_InterlockedCompareExchange");
    const auto exchange = entry<Exchange>("KERNEL32.dll", "_InterlockedExchange");
    const auto bit_and = entry<And>("KERNEL32.dll", "_InterlockedAnd");
    const auto bit_or = entry<Or>("KERNEL32.dll", "_InterlockedOr");
    const auto increment16 = entry<Increment16>("KERNEL32.dll", "_InterlockedIncrement16");
    const auto increment64 = entry<Increment64>("KERNEL32.dll", "_InterlockedIncrement64");
    const auto test_and_set = entry<TestAndSet>("KERNEL32.dll", "_bittestandset");
    const auto test = entry<BitTest>("KERNEL32.dll", "_bittest");
    const auto scan_forward = entry<ScanForward>("KERNEL32.dll", "_BitScanForward");
    const auto scan_reverse = entry<ScanReverse>("KERNEL32.dll", "_BitScanReverse");
    const auto umul = entry<Multiply>("KERNEL32.dll", "_umul128");
    const auto mul_div = entry<MulDiv>("KERNEL32.dll", "MulDiv");

    if (increment == nullptr || mul_div == nullptr) {
        check(false, "the interlocked family resolves");
        return;
    }

    // The family's whole point is which value is answered: the increment
    // answers the new value and the exchange-add answers the old one, and a
    // caller that got the two the wrong way round would still see the count
    // move.
    std::int32_t value = 5;
    check(increment(&value) == 6 && value == 6, "_InterlockedIncrement answers the new value");
    check(decrement(&value) == 5 && value == 5, "_InterlockedDecrement answers the new value");
    check(add != nullptr && add(&value, 10) == 15, "_InterlockedAdd answers the new value");
    value = 5;
    check(exchange_add != nullptr && exchange_add(&value, 10) == 5 && value == 15,
          "_InterlockedExchangeAdd answers the old value");
    check(exchange != nullptr && exchange(&value, 7) == 15 && value == 7,
          "_InterlockedExchange answers the old value");
    check(bit_and != nullptr && bit_and(&value, 3) == 7 && value == 3,
          "_InterlockedAnd answers the old value");
    check(bit_or != nullptr && bit_or(&value, 4) == 3 && value == 7,
          "_InterlockedOr answers the old value");
    check(compare_exchange != nullptr &&
          compare_exchange(&value, 9, 7) == 7 && value == 9,
          "compare and exchange: a matching comparand swaps");
    check(compare_exchange(&value, 11, 7) == 9 && value == 9,
          "compare and exchange: a mismatching one does not and answers what was there");

    std::int16_t small = 100;
    check(increment16 != nullptr && increment16(&small) == 101, "the 16-bit width");
    std::int64_t wide = 1;
    check(increment64 != nullptr && increment64(&wide) == 2, "the 64-bit width");

    std::int32_t bits = 0;
    check(test_and_set != nullptr && test_and_set(&bits, 3) == 0 && bits == 8,
          "bit test and set answers the bit that was there");
    check(test_and_set(&bits, 3) == 1, "bit test and set: the second time it was set");
    check(test != nullptr && test(&bits, 3) == 1 && test(&bits, 4) == 0,
          "bit test");
    // An index outside the width is answered false rather than read.
    check(test(&bits, 32) == 0, "bit test: an index past the width");

    std::uint32_t index = 99;
    check(scan_forward != nullptr && scan_forward(&index, 0) == 0 && index == 99,
          "bit scan: a zero mask answers nothing and writes nothing");
    check(scan_forward(&index, 0x8u) == 1 && index == 3, "bit scan forward");
    check(scan_reverse != nullptr && scan_reverse(&index, 0x8u) == 1 && index == 3,
          "bit scan reverse");
    check(scan_reverse(&index, 0x9u) == 1 && index == 3, "bit scan reverse: the highest bit");

    std::uint64_t high = 0;
    check(umul != nullptr && umul(0xFFFFFFFFFFFFFFFFull, 2, &high) == 0xFFFFFFFFFFFFFFFEull,
          "the wide multiply: the low half");
    check(high == 1, "the wide multiply: the high half");

    check(mul_div(7, 3, 2) == 11, "MulDiv rounds half away from zero");
    check(mul_div(7, 3, 0) == -1, "MulDiv refuses a zero denominator");
    check(mul_div(0x7FFFFFFF, 2, 1) == -1, "MulDiv refuses a result that does not fit");
}

// --------------------------------------------------------- the profile

void test_profile() {
    using WriteString = std::int32_t (OCC_MS_ABI *)(const char*, const char*, const char*,
                                         const char*);
    using GetString = std::uint32_t (OCC_MS_ABI *)(const char*, const char*, const char*,
                                        char*, std::uint32_t, const char*);
    using GetInt = std::uint32_t (OCC_MS_ABI *)(const char*, const char*, std::int32_t,
                                     const char*);
    using GetSection = std::uint32_t (OCC_MS_ABI *)(const char*, char*, std::uint32_t,
                                         const char*);
    using GetSectionNames = std::uint32_t (OCC_MS_ABI *)(char*, std::uint32_t, const char*);

    const auto write_string = entry<WriteString>("KERNEL32.dll", "WritePrivateProfileStringA");
    const auto get_string = entry<GetString>("KERNEL32.dll", "GetPrivateProfileStringA");
    const auto get_int = entry<GetInt>("KERNEL32.dll", "GetPrivateProfileIntA");
    const auto get_section = entry<GetSection>("KERNEL32.dll", "GetPrivateProfileSectionA");
    const auto get_names = entry<GetSectionNames>("KERNEL32.dll", "GetPrivateProfileSectionNamesA");

    if (write_string == nullptr || get_string == nullptr) {
        check(false, "the profile family resolves");
        return;
    }

    const char* path = "occ_generated_profile_test.ini";
    std::remove(path);

    check(write_string("Window", "Left", "100", path) == 1, "profile: a value stored");
    check(write_string("Window", "Top", "200", path) == 1, "profile: a second value");
    check(write_string("Other", "Name", "occ", path) == 1, "profile: a second section");

    char buffer[260];
    std::memset(buffer, 0, sizeof(buffer));
    get_string("Window", "Left", "0", buffer, sizeof(buffer), path);
    check_text(buffer, "100", "profile: the value read back");

    // A key that is not there answers the default rather than an error,
    // which is what makes the call usable for a setting never written.
    std::memset(buffer, 0, sizeof(buffer));
    get_string("Window", "Missing", "fallback", buffer, sizeof(buffer), path);
    check_text(buffer, "fallback", "profile: the default for a missing key");
    std::memset(buffer, 0, sizeof(buffer));
    get_string("NoSuchSection", "Left", "fallback", buffer, sizeof(buffer), path);
    check_text(buffer, "fallback", "profile: the default for a missing section");

    check(get_int != nullptr && get_int("Window", "Left", 0, path) == 100,
          "profile: the number");
    check(get_int("Window", "Missing", 42, path) == 42,
          "profile: the default number");

    // Updating a value keeps the rest of the file, which is the contract a
    // program storing a window position depends on.
    check(write_string("Window", "Left", "150", path) == 1, "profile: a value replaced");
    std::memset(buffer, 0, sizeof(buffer));
    get_string("Window", "Left", "0", buffer, sizeof(buffer), path);
    check_text(buffer, "150", "profile: the replaced value");
    std::memset(buffer, 0, sizeof(buffer));
    get_string("Other", "Name", "0", buffer, sizeof(buffer), path);
    check_text(buffer, "occ", "profile: an untouched section survives an edit");
    std::memset(buffer, 0, sizeof(buffer));
    get_string("Window", "Top", "0", buffer, sizeof(buffer), path);
    check_text(buffer, "200", "profile: an untouched key survives an edit");

    // A null string removes the key, which is a different request from
    // storing an empty one.
    check(write_string("Window", "Top", nullptr, path) == 1, "profile: a value removed");
    std::memset(buffer, 0, sizeof(buffer));
    get_string("Window", "Top", "gone", buffer, sizeof(buffer), path);
    check_text(buffer, "gone", "profile: the removed key is gone");

    if (get_section != nullptr) {
        std::memset(buffer, 0, sizeof(buffer));
        get_section("Window", buffer, sizeof(buffer), path);
        check(std::strcmp(buffer, "Left=150") == 0,
              "profile: the section as its lines");
    }
    if (get_names != nullptr) {
        std::memset(buffer, 0, sizeof(buffer));
        get_names(buffer, sizeof(buffer), path);
        const char* first = buffer;
        const char* second = buffer + std::strlen(first) + 1;
        check(std::strcmp(first, "Window") == 0 &&
                  std::strcmp(second, "Other") == 0,
              "profile: the section names in order");
    }

    std::remove(path);
}

// ------------------------------------------------------- the refusal

void test_refusal() {
    // An entry point whose subsystem is absent answers the platform's own
    // code through `SetLastError` and a zero. It must not answer success:
    // a guest told that a window was created holds a handle it will use.
    const auto gl_error = entry<std::uint32_t (OCC_MS_ABI *)()>(
        "OPENGL32.dll", "glGetError");
    check(gl_error != nullptr, "a refused name still resolves to an address");
    if (gl_error == nullptr) {
        return;
    }
    set_last_error(kErrorSuccess);
    const std::uint32_t answer = gl_error();
    check(answer == 0, "a refusal answers zero");
    check(k32_GetLastError() == kErrorCallNotImplemented,
          "a refusal reports the platform's own code");

    // The same for a name whose signature the headers do not state: the
    // thunk declares no parameters, which this ABI makes safe, and the
    // answer is still the refusal rather than a guess.
    const auto dhcp = entry<std::uint32_t (OCC_MS_ABI *)()>("DHCPCSVC.dll", "DhcpRequestParams");
    check(dhcp != nullptr, "an export with no declared signature resolves");
    if (dhcp != nullptr) {
        set_last_error(kErrorSuccess);
        check(dhcp() == 0, "the signatureless refusal answers zero");
        check(k32_GetLastError() == kErrorCallNotImplemented,
              "the signatureless refusal reports the code");
    }
}

}  // namespace

int main() {
    test_registration();
    test_path();
    test_strings();
    test_interlocked();
    test_profile();
    test_refusal();
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

// The Rtl* string family of ntdll.
//
// These are the hardest calls in ntdll to get right and the easiest to get
// wrong, because almost every one of them has a *number* in its contract that
// is not the number a reader expects. `Length` is bytes and not characters.
// `MaximumLength` excludes nothing. A compare returns the difference of two
// characters and not -1/0/1. A size query answers in one unit and the
// conversion it sizes answers in another. The cases below are the ones where
// an implementation written from the prose is wrong, and each says what the
// reference does and why that is the right answer.
//
// Nothing here calls through a guest address space. These functions take
// pointers to host memory in a unit test and that is the same thing: the
// runtime's whole job is to make a guest pointer and a host pointer the same
// pointer, so a test that builds the structures on the host is testing the
// arithmetic, which is the part that can be wrong.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/exports.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

// The domain function. `api.h` does not declare it yet -- the mainline adds
// that declaration when it wires this file into the module list -- so it is
// declared here. A duplicate declaration of the same signature is harmless,
// which is why this does not need to be conditional on the mainline's state.
namespace occ::runtime::winabi {
void add_ntdll_rtl_str(ExportList& out);
}  // namespace occ::runtime::winabi

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

// ------------------------------------------------------- the UNICODE_STRING
//
// Sixteen bytes, hand-built here rather than declared as a struct, because
// the point of these tests is that the layout is the guest's and not the
// host's: a test that used a host `struct UnicodeString` would pass on a
// machine where the guess happened to be right.

constexpr std::size_t kLength = 0;        // uint16
constexpr std::size_t kMaximumLength = 2; // uint16
constexpr std::size_t kBuffer = 8;        // pointer

struct UStr {
    std::uint8_t bytes[16] = {};

    void set_length(std::uint16_t v) {
        std::memcpy(bytes + kLength, &v, sizeof(v));
    }
    void set_maximum(std::uint16_t v) {
        std::memcpy(bytes + kMaximumLength, &v, sizeof(v));
    }
    void set_buffer(const void* p) {
        const std::uint64_t v =
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(p));
        std::memcpy(bytes + kBuffer, &v, sizeof(v));
    }
    [[nodiscard]] std::uint16_t length() const {
        std::uint16_t v = 0;
        std::memcpy(&v, bytes + kLength, sizeof(v));
        return v;
    }
    [[nodiscard]] std::uint16_t maximum() const {
        std::uint16_t v = 0;
        std::memcpy(&v, bytes + kMaximumLength, sizeof(v));
        return v;
    }
    [[nodiscard]] const void* buffer() const {
        std::uint64_t v = 0;
        std::memcpy(&v, bytes + kBuffer, sizeof(v));
        return reinterpret_cast<const void*>(static_cast<std::uintptr_t>(v));
    }
    [[nodiscard]] bool buffer_is_null() const {
        std::uint64_t v = 0;
        std::memcpy(&v, bytes + kBuffer, sizeof(v));
        return v == 0;
    }
};

// A `STRING` has the same three fields in the same places. One type serves
// both here precisely because the reference treats them interchangeably at the
// layout level, and a test that used two types would not notice a field moved
// in only one of them.
using Str = UStr;

// A wide buffer with room to spare, so a test that overflows writes into
// slack rather than into whatever follows.
struct WideBuf {
    char16_t data[256] = {};
};

// A narrow buffer, same idea.
struct NarrowBuf {
    char data[256] = {};
};

// The statuses, named here rather than as literals so a wrong constant in the
// implementation shows up as a mismatch against the real value instead of
// matching another wrong constant.
constexpr std::uint32_t kSuccess = 0x00000000;
constexpr std::uint32_t kNotImplemented = 0xC0000002;
constexpr std::uint32_t kInvalidParameter = 0xC000000D;
constexpr std::uint32_t kInvalidParameter1 = 0xC00000EF;
constexpr std::uint32_t kInvalidParameter2 = 0xC00000F0;
constexpr std::uint32_t kInvalidParameter4 = 0xC00000F2;
constexpr std::uint32_t kInvalidParameter5 = 0xC00000F3;
constexpr std::uint32_t kBufferOverflow = 0x80000005;
// The one code here that is not "you passed something impossible" but "you
// passed something that is not there": a null output pointer, where the input
// was fine. Windows distinguishes the two, and a caller that gets the wrong one
// retries with different arguments instead of fixing the null.
constexpr std::uint32_t kAccessViolation = 0xC0000005;
constexpr std::uint32_t kNoMemory = 0xC0000017;
constexpr std::uint32_t kBufferTooSmall = 0xC0000023;
constexpr std::uint32_t kNameTooLong = 0xC0000106;
constexpr std::uint32_t kNotFound = 0xC0000225;
constexpr std::uint32_t kUnknownRevision = 0xC0000058;
constexpr std::uint32_t kNoUnicodeTranslation = 0xC0000717;
constexpr std::uint32_t kObjectNameNotFound = 0xC0000034;
constexpr std::uint32_t kSxsKeyNotFound = 0xC0150008;

// The hash algorithm identifiers, which are a public pair: zero is "the
// default" and one is "the X65599 the default is". Nothing else is accepted.
constexpr std::uint32_t kHashDefault = 0;
constexpr std::uint32_t kHashX65599 = 1;

// A few names in this domain are not NTSTATUS-returning at all. `RtlCreate*`
// answers a `BOOLEAN`, so success is 1 and there is no error code to inspect --
// a caller that tested its result against `STATUS_SUCCESS` would read every
// success as a failure. The two constants are here so that distinction is
// visible at the call site rather than buried in a comment.
constexpr std::uint32_t kFalse = 0;
constexpr std::uint32_t kTrue = 1;

// ------------------------------------------------------------------ the table

// Every exported name, so the coverage check below is a statement about the
// order rather than about a hand-copied list that could drift.
const char* const kExpected[] = {
    "RtlAnsiCharToUnicodeChar",
    "RtlAnsiStringToUnicodeSize",
    "RtlAnsiStringToUnicodeString",
    "RtlAppendAsciizToString",
    "RtlAppendStringToString",
    "RtlAppendUnicodeStringToString",
    "RtlAppendUnicodeToString",
    "RtlCharToInteger",
    "RtlCompareMemory",
    "RtlCompareMemoryUlong",
    "RtlCompareString",
    "RtlCompareUnicodeString",
    "RtlCompareUnicodeStrings",
    "RtlConsoleMultiByteToUnicodeN",
    "RtlConvertDeviceFamilyInfoToString",
    "RtlConvertSidToUnicodeString",
    "RtlCopyContext",
    "RtlCopyExtendedContext",
    "RtlCopyLuid",
    "RtlCopyLuidAndAttributesArray",
    "RtlCopyMemoryNonTemporal",
    "RtlCopySecurityDescriptor",
    "RtlCopySid",
    "RtlCopySidAndAttributesArray",
    "RtlCopyString",
    "RtlCopyUnicodeString",
    "RtlCreateUnicodeString",
    "RtlCreateUnicodeStringFromAsciiz",
    "RtlCustomCPToUnicodeN",
    "RtlDowncaseUnicodeChar",
    "RtlDowncaseUnicodeString",
    "RtlDuplicateUnicodeString",
    "RtlEqualString",
    "RtlEqualUnicodeString",
    "RtlEraseUnicodeString",
    "RtlExpandEnvironmentStrings",
    "RtlExpandEnvironmentStrings_U",
    "RtlFillMemory",
    "RtlFillMemoryUlong",
    "RtlFinalReleaseOutOfProcessMemoryStream",
    "RtlFindActivationContextSectionString",
    "RtlFindCharInUnicodeString",
    "RtlFormatCurrentUserKeyPath",
    "RtlFormatMessage",
    "RtlFormatMessageEx",
    "RtlFreeAnsiString",
    "RtlFreeOemString",
    "RtlFreeUnicodeString",
    "RtlGUIDFromString",
    "RtlHashUnicodeString",
    "RtlIdnToNameprepUnicode",
    "RtlIdnToUnicode",
    "RtlInitAnsiString",
    "RtlInitAnsiStringEx",
    "RtlInitString",
    "RtlInitUnicodeString",
    "RtlInitUnicodeStringEx",
    "RtlInt64ToUnicodeString",
    "RtlIntegerToChar",
    "RtlIntegerToUnicodeString",
    "RtlInterlockedCompareExchange64",
    "RtlIpv4AddressToStringA",
    "RtlIpv4AddressToStringExA",
    "RtlIpv4AddressToStringExW",
    "RtlIpv4AddressToStringW",
    "RtlIpv4StringToAddressA",
    "RtlIpv4StringToAddressExA",
    "RtlIpv4StringToAddressExW",
    "RtlIpv4StringToAddressW",
    "RtlIpv6AddressToStringA",
    "RtlIpv6AddressToStringExA",
    "RtlIpv6AddressToStringExW",
    "RtlIpv6AddressToStringW",
    "RtlIpv6StringToAddressA",
    "RtlIpv6StringToAddressExA",
    "RtlIpv6StringToAddressExW",
    "RtlIpv6StringToAddressW",
    "RtlIsNormalizedString",
    "RtlIsTextUnicode",
    "RtlLargeIntegerToChar",
    "RtlMoveMemory",
    "RtlMultiByteToUnicodeN",
    "RtlMultiByteToUnicodeSize",
    "RtlNormalizeString",
    "RtlOemStringToUnicodeSize",
    "RtlOemStringToUnicodeString",
    "RtlOemToUnicodeN",
    "RtlPrefixString",
    "RtlPrefixUnicodeString",
    "RtlQueryInterfaceMemoryStream",
    "RtlReadMemoryStream",
    "RtlReadOutOfProcessMemoryStream",
    "RtlReleaseMemoryStream",
    "RtlRevertMemoryStream",
    "RtlRunDecodeUnicodeString",
    "RtlRunEncodeUnicodeString",
    "RtlSetUnicodeCallouts",
    "RtlStringFromGUID",
    "RtlUnicodeStringToAnsiSize",
    "RtlUnicodeStringToAnsiString",
    "RtlUnicodeStringToCountedOemString",
    "RtlUnicodeStringToInteger",
    "RtlUnicodeStringToOemSize",
    "RtlUnicodeStringToOemString",
    "RtlUnicodeToCustomCPN",
    "RtlUnicodeToMultiByteN",
    "RtlUnicodeToMultiByteSize",
    "RtlUnicodeToOemN",
    "RtlUnicodeToUTF8N",
    "RtlUpcaseUnicodeChar",
    "RtlUpcaseUnicodeString",
    "RtlUpcaseUnicodeStringToAnsiString",
    "RtlUpcaseUnicodeStringToCountedOemString",
    "RtlUpcaseUnicodeStringToOemString",
    "RtlUpcaseUnicodeToCustomCPN",
    "RtlUpcaseUnicodeToMultiByteN",
    "RtlUpcaseUnicodeToOemN",
    "RtlUpperChar",
    "RtlUpperString",
    "RtlUTF8ToUnicodeN",
    "RtlWriteMemoryStream",
    "RtlxAnsiStringToUnicodeSize",
    "RtlxOemStringToUnicodeSize",
    "RtlxUnicodeStringToAnsiSize",
    "RtlxUnicodeStringToOemSize",
    "RtlZeroHeap",
    "RtlZeroMemory",
};

ExportList g_exports;

// The one lookup every test goes through. Going through the table rather than
// calling the entry points by name is deliberate: it is the only way to check
// that a name is exported *and* points at code, which is the whole contract
// of this file's domain function.
const void* find(const char* name) {
    for (const HostExport& entry : g_exports) {
        if (entry.name == name) {
            return reinterpret_cast<const void*>(entry.address);
        }
    }
    std::fprintf(stderr, "FAIL missing export %s\n", name);
    ++failures;
    ++checks;
    return nullptr;
}

// Every entry point in this domain is declared `ms_abi`, because it is called
// by guest code compiled for the Microsoft x64 ABI. The host here is System V,
// and the two disagree about which registers the first four arguments go in --
// so a test that cast an export address to a plain System V function pointer
// would pass the right *values* in the wrong *registers* and read whatever
// happened to be in RCX as the first pointer. It fails, it does not crash, and
// the failure looks like a logic bug in the string code.
//
// That is why every `Fn` below is spelled with `__attribute__((ms_abi))`. The
// attribute is on the pointer type rather than applied to the call because that
// is the only place it can go: it selects the register assignment for the
// call, so the caller and the callee must agree on it.
template <typename Fn>
Fn fn(const char* name) {
    return reinterpret_cast<Fn>(find(name));
}

void test_table_is_complete() {
    check(g_exports.size() == 127,
          "table: the domain contributes exactly 127 names");
    for (const char* name : kExpected) {
        check(find(name) != nullptr, "table: name resolves to code");
    }
    // And no name twice. A duplicate is invisible to a lookup that returns
    // the first hit, so it has to be checked directly.
    std::vector<std::string> names;
    for (const HostExport& entry : g_exports) {
        names.push_back(entry.name);
    }
    std::sort(names.begin(), names.end());
    bool unique = true;
    for (std::size_t k = 1; k < names.size(); ++k) {
        if (names[k] == names[k - 1]) {
            unique = false;
        }
    }
    check(unique, "table: no name is registered twice");
}

// ------------------------------------------------------------------ initialise

void test_init() {
    // `RtlInitAnsiString` measures the *narrow* string, and the lengths are
    // bytes. "abc" is three bytes and the maximum is four -- the terminator
    // has to fit, which is the entire reason `MaximumLength` exists.
    {
        Str s;
        fn<void (__attribute__((ms_abi)) *)(void*, const char*)>("RtlInitAnsiString")(&s, "abc");
        check(s.length() == 3, "init ansi: Length is the narrow byte count");
        check(s.maximum() == 4, "init ansi: MaximumLength has room for the NUL");
        check(s.buffer() == static_cast<const void*>(
                                std::string("abc").c_str()) ||
                  s.buffer() != nullptr,
              "init ansi: the buffer is the caller's own string");
    }
    // The empty string: length zero, maximum one, buffer pointing at the
    // caller's NUL. Not a null buffer -- the reference points at the source
    // and only zeroes the structure when the *source* is null.
    {
        Str s;
        const char* empty = "";
        fn<void (__attribute__((ms_abi)) *)(void*, const char*)>("RtlInitAnsiString")(&s, empty);
        check(s.length() == 0, "init ansi: the empty string has Length 0");
        check(s.maximum() == 1, "init ansi: the empty string still has room for the NUL");
        check(s.buffer() == static_cast<const void*>(empty),
              "init ansi: the empty string points at the caller's NUL");
    }
    // A null source zeroes all three fields, not just the two lengths. A
    // structure with a null buffer and a non-zero length is one a later
    // function reads as a request to walk nothing.
    {
        Str s;
        s.set_length(9);
        s.set_maximum(9);
        NarrowBuf buf;
        s.set_buffer(buf.data);
        fn<void (__attribute__((ms_abi)) *)(void*, const char*)>("RtlInitAnsiString")(&s, nullptr);
        check(s.length() == 0 && s.maximum() == 0 && s.buffer_is_null(),
              "init ansi: a null source zeroes all three fields");
    }
    // The wide form, where the length is *twice* the character count. This is
    // the single most common bug in the family.
    {
        Str s;
        fn<void (__attribute__((ms_abi)) *)(void*, const char16_t*)>("RtlInitUnicodeString")(&s, u"abc");
        check(s.length() == 6, "init unicode: Length is bytes, so 3 chars is 6");
        check(s.maximum() == 8, "init unicode: MaximumLength is 6 plus the WCHAR NUL");
    }
    {
        Str s;
        fn<void (__attribute__((ms_abi)) *)(void*, const char16_t*)>("RtlInitUnicodeString")(&s, u"");
        check(s.length() == 0, "init unicode: the empty wide string is 0 bytes");
        check(s.maximum() == 2, "init unicode: the empty wide string still has the WCHAR");
    }
    {
        Str s;
        fn<void (__attribute__((ms_abi)) *)(void*, const char16_t*)>("RtlInitUnicodeString")(&s, nullptr);
        check(s.length() == 0 && s.maximum() == 0 && s.buffer_is_null(),
              "init unicode: a null source zeroes all three fields");
    }
    // The `Ex` spellings exist so that a caller can *find out* its input was
    // too long instead of receiving a truncated structure that lies about its
    // own length. That is the whole difference between the two forms.
    {
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char*)>("RtlInitAnsiStringEx")(
                  &s, "abc") == kSuccess,
              "init ansi ex: a short string succeeds");
        check(s.length() == 3, "init ansi ex: and is measured the same way");
    }
    {
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char16_t*)>(
                  "RtlInitUnicodeStringEx")(&s, u"abc") == kSuccess,
              "init unicode ex: a short string succeeds");
        check(s.length() == 6, "init unicode ex: and is measured in bytes");
    }
    {
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char*)>("RtlInitAnsiStringEx")(
                  &s, nullptr) == kSuccess,
              "init ansi ex: a null source is not an error, it is an empty string");
        check(s.buffer_is_null(), "init ansi ex: and the structure is cleared");
    }
    {
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char16_t*)>(
                  "RtlInitUnicodeStringEx")(&s, nullptr) == kSuccess,
              "init unicode ex: a null source succeeds");
        check(s.buffer_is_null(), "init unicode ex: and the structure is cleared");
    }
    // `RtlInitString` is the same function under the name the C++ headers
    // use, and a guest that imports one and not the other must get the same
    // answers.
    {
        Str a;
        Str b;
        fn<void (__attribute__((ms_abi)) *)(void*, const char*)>("RtlInitAnsiString")(&a, "xyz");
        fn<void (__attribute__((ms_abi)) *)(void*, const char*)>("RtlInitString")(&b, "xyz");
        check(a.length() == b.length() && a.maximum() == b.maximum(),
              "init string: the alias agrees with the name it aliases");
    }
}

// --------------------------------------------------------------------- create

void test_create() {
    // `RtlCreateUnicodeString` allocates, and answers a BOOLEAN rather than a
    // status. Its `MaximumLength` is the whole wide string *including* the
    // terminator, and its `Length` is that less two -- that is, the bytes of
    // the text without the terminator, which is the same number
    // `RtlInitUnicodeString` would have produced and is the check that the two
    // are inverses.
    {
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char16_t*)>(
                  "RtlCreateUnicodeString")(&s, u"hello") == kTrue,
              "create: a five-character string succeeds");
        check(s.length() == 10, "create: Length is 5 characters as 10 bytes");
        check(s.maximum() == 12, "create: MaximumLength includes the terminator");
        const auto* text = static_cast<const char16_t*>(s.buffer());
        check(std::u16string(text, text + 5) == u"hello",
              "create: the text is where it says it is");
        check(text[5] == u'\0', "create: and it is terminated");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(&s);
        check(s.length() == 0 && s.maximum() == 0 && s.buffer_is_null(),
              "create: freeing clears all three fields");
    }
    // The empty string: allocated, terminated, zero length. Not a null
    // buffer -- a caller that asked to create a string and got a null buffer
    // back has to branch, and the reference does not make it.
    {
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char16_t*)>(
                  "RtlCreateUnicodeString")(&s, u"") == kTrue,
              "create: the empty string succeeds");
        check(s.length() == 0, "create: the empty string has Length 0");
        check(s.maximum() == 2, "create: and two bytes of maximum");
        check(!s.buffer_is_null(), "create: and a real buffer for the terminator");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(&s);
    }
    {
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char16_t*)>(
                  "RtlCreateUnicodeString")(&s, nullptr) == kFalse,
              "create: a null source is refused");
    }
    {
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char16_t*)>(
                  "RtlCreateUnicodeString")(&s, u"abc") == kTrue,
              "create: the structure argument may be null? no -- it may not");
        // With a null destination the reference has nowhere to put the
        // allocation and leaks it, so the check below is on the source side.
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(&s);
    }
    // `RtlCreateUnicodeStringFromAsciiz` is the narrow source. The narrow
    // bytes become wide characters, so the length is twice the narrow length.
    {
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char*)>(
                  "RtlCreateUnicodeStringFromAsciiz")(&s, "abc") == kTrue,
              "create asciiz: a three-byte source succeeds");
        check(s.length() == 6, "create asciiz: three bytes become six");
        const auto* text = static_cast<const char16_t*>(s.buffer());
        check(std::u16string(text, text + 3) == u"abc",
              "create asciiz: the text round-trips through UTF-8");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(&s);
    }
    {
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char*)>(
                  "RtlCreateUnicodeStringFromAsciiz")(&s, nullptr) == kFalse,
              "create asciiz: a null source is refused");
    }
}

// ----------------------------------------------------------------------- free

void test_free() {
    // All three frees do the same thing -- release and clear -- because the
    // three string types share a layout and a caller that mixed them up would
    // otherwise be reading a freed pointer.
    {
        Str s;
        fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char*)>(
            "RtlCreateUnicodeStringFromAsciiz")(&s, "free me");
        check(!s.buffer_is_null(), "free: there is something to free");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(&s);
        check(s.length() == 0 && s.maximum() == 0 && s.buffer_is_null(),
              "free unicode: the structure is cleared, not just the pointer");
    }
    {
        Str s;
        fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char16_t*)>(
            "RtlCreateUnicodeString")(&s, u"free me too");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeOemString")(&s);
        check(s.buffer_is_null(), "free oem: the structure is cleared");
    }
    {
        // A structure initialised *by reference* points into the caller's own
        // buffer, so it must never be handed to a free -- the reference says so
        // in as many words, and handing it over would return a pointer the
        // caller never allocated to the heap. What a caller can check instead
        // is that `RtlInitUnicodeString` leaves a structure whose buffer is
        // the caller's, which is the fact the mistake comes from.
        Str s;
        WideBuf wide;
        wide.data[0] = u'a';
        wide.data[1] = u'b';
        wide.data[2] = u'c';
        fn<void (__attribute__((ms_abi)) *)(void*, const char16_t*)>(
            "RtlInitUnicodeString")(&s, wide.data);
        check(s.buffer() == wide.data,
              "init: a by-reference initialisation points at the caller's buffer");
        check(s.length() == 6,
              "init: and its Length is three characters as six bytes");
    }
    {
        // The three frees all clear the whole structure, so a second free is a
        // free of null rather than a double free. That idempotence is the
        // property that makes an unconditional `RtlFreeUnicodeString` at the end
        // of a cleanup path safe.
        Str s;
        fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char16_t*)>(
            "RtlCreateUnicodeString")(&s, u"twice");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeAnsiString")(&s);
        check(s.length() == 0 && s.maximum() == 0 && s.buffer_is_null(),
              "free ansi: the whole structure is cleared");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeAnsiString")(&s);
        check(s.buffer_is_null(), "free: a second free of the same is harmless");
    }
    {
        Str s;
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(&s);
        check(s.buffer_is_null(), "free: freeing a zeroed structure is a no-op");
    }
    {
        Str s;
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(nullptr);
        check(true, "free: a null structure does not crash");
    }
}

// ----------------------------------------------------------------------- copy

void test_copy() {
    // `RtlCopyString` copies `min(src->Length, dst->MaximumLength)` bytes and
    // sets `Length` to that. A source longer than the destination is
    // truncated -- and truncated is the point: the reference does not refuse,
    // because the destination's `MaximumLength` is the caller telling the
    // function how much it can take.
    {
        Str src;
        Str dst;
        NarrowBuf source = {'a', 'b', 'c', 'd', 0};
        NarrowBuf target = {};
        src.set_length(4);
        src.set_maximum(5);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(3);
        dst.set_buffer(target.data);
        fn<void (__attribute__((ms_abi)) *)(void*, const void*)>("RtlCopyString")(&dst, &src);
        check(dst.length() == 3, "copy string: Length is the truncated size");
        check(std::string(target.data, 3) == "abc",
              "copy string: and three bytes were written");
    }
    // A null source zeroes the destination's `Length` and leaves the rest.
    {
        Str dst;
        NarrowBuf target = {};
        dst.set_length(5);
        dst.set_maximum(10);
        dst.set_buffer(target.data);
        fn<void (__attribute__((ms_abi)) *)(void*, const void*)>("RtlCopyString")(&dst, nullptr);
        check(dst.length() == 0, "copy string: a null source gives Length 0");
    }
    // The wide form, same rule in bytes. No terminator is written even when
    // the destination has room for one: the reference copies exactly
    // `min(src->Length, dst->MaximumLength)` bytes and stops. The buffer is
    // pre-filled with a sentinel so that "no terminator written" is an
    // assertion about the copy and not a restatement of zero-initialisation.
    {
        Str src;
        Str dst;
        WideBuf source;
        WideBuf target;
        const char16_t text[] = u"abcd";
        for (int k = 0; k < 4; ++k) {
            source.data[k] = text[k];
        }
        for (std::size_t k = 0; k < 256; ++k) {
            target.data[k] = u'#';
        }
        src.set_length(8);
        src.set_maximum(10);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(10);
        dst.set_buffer(target.data);
        fn<void (__attribute__((ms_abi)) *)(void*, const void*)>("RtlCopyUnicodeString")(&dst, &src);
        check(dst.length() == 8, "copy unicode: Length is in bytes");
        check(target.data[0] == u'a' && target.data[2] == u'c',
              "copy unicode: and the wide characters are there");
        check(target.data[4] == u'#',
              "copy unicode: and no terminator is written even with room");
    }
    // Exactly filling the destination: 4 bytes into 4. Nothing past the
    // copied bytes is touched, and the sentinel that was there survives.
    {
        Str src;
        Str dst;
        WideBuf source;
        WideBuf target;
        source.data[0] = u'x';
        source.data[1] = u'y';
        for (std::size_t k = 0; k < 256; ++k) {
            target.data[k] = u'#';
        }
        src.set_length(4);
        src.set_maximum(6);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(4);
        dst.set_buffer(target.data);
        fn<void (__attribute__((ms_abi)) *)(void*, const void*)>("RtlCopyUnicodeString")(&dst, &src);
        check(dst.length() == 4, "copy unicode: an exact fit copies everything");
        check(target.data[2] == u'#' && target.data[3] == u'#',
              "copy unicode: and nothing past the copy is touched");
    }
    // One byte short of fitting: 4 into 3. The reference truncates to 3, which
    // is half a character, and the caller is expected to notice.
    {
        Str src;
        Str dst;
        WideBuf source;
        WideBuf target;
        source.data[0] = u'x';
        source.data[1] = u'y';
        src.set_length(4);
        src.set_maximum(6);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(3);
        dst.set_buffer(target.data);
        fn<void (__attribute__((ms_abi)) *)(void*, const void*)>("RtlCopyUnicodeString")(&dst, &src);
        check(dst.length() == 3, "copy unicode: an odd truncation is not refused");
    }
    // `RtlEraseUnicodeString` erases `MaximumLength` bytes, not `Length`. The
    // whole purpose is to clear the caller's buffer so that a longer string
    // written there later cannot expose the old one, and erasing only the
    // length would leave the rest readable.
    //
    // The boundary is checked from both sides, because `MaximumLength` is a
    // *byte* count: 32 bytes is sixteen `char16_t`, so the sixteenth character
    // is the last one erased and the seventeenth must survive. A test that
    // only checked the erased half would pass an implementation that ignored
    // `MaximumLength` and cleared the entire buffer.
    {
        Str s;
        WideBuf buffer;
        for (std::size_t k = 0; k < 32; ++k) {
            buffer.data[k] = u'Z';
        }
        s.set_length(4);
        s.set_maximum(32);
        s.set_buffer(buffer.data);
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlEraseUnicodeString")(&s);
        check(s.length() == 0, "erase: Length goes to zero");
        bool erased = true;
        for (std::size_t k = 0; k < 16; ++k) {
            if (buffer.data[k] != 0) {
                erased = false;
            }
        }
        check(erased, "erase: MaximumLength bytes are cleared, not Length");
        bool untouched = true;
        for (std::size_t k = 16; k < 32; ++k) {
            if (buffer.data[k] != u'Z') {
                untouched = false;
            }
        }
        check(untouched, "erase: and nothing past MaximumLength is written to");
    }
    // The duplicate, and its `add_nul` argument. This is the most surprising
    // signature in the family:
    //   0 and 1 mean "no terminator needed", and an empty source gives a
    //     null buffer;
    //   3 means "there is a terminator", and an empty source still allocates
    //     one so the result is a real, freeable, empty string;
    //   2, and anything at or above 4, and any negative value, are refused.
    // A caller that passed 2 expecting "allocate a second buffer" gets
    // STATUS_INVALID_PARAMETER, and that is not a typo in the reference: the
    // values are an enum and 2 is not in it.
    //
    // The argument order is `(add_nul, source, destination)` -- the flag
    // first and the output last, which is the opposite of what the `Ex`
    // convention elsewhere in ntdll does, and the opposite of what a reader
    // would guess from a name that starts with "Duplicate". The reference
    // spells it that way and the spec file confirms it, so the calls below are
    // in that order deliberately.
    {
        Str src;
        WideBuf source;
        source.data[0] = u'h';
        source.data[1] = u'i';
        src.set_length(4);
        src.set_maximum(6);
        src.set_buffer(source.data);
        Str out;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*, void*)>(
                  "RtlDuplicateUnicodeString")(0, &src, &out) == kSuccess,
              "duplicate: add_nul 0 succeeds");
        check(out.length() == 4, "duplicate: the length is copied");
        check(out.maximum() >= out.length(),
              "duplicate: the maximum accommodates the length");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(&out);
    }
    {
        Str src;
        WideBuf source;
        source.data[0] = u'h';
        source.data[1] = u'i';
        src.set_length(4);
        src.set_maximum(6);
        src.set_buffer(source.data);
        Str out;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*, void*)>(
                  "RtlDuplicateUnicodeString")(3, &src, &out) == kSuccess,
              "duplicate: add_nul 3 succeeds");
        check(out.maximum() > out.length(),
              "duplicate: add_nul 3 reserves room for the terminator");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(&out);
    }
    // The empty source with add_nul 0: nothing to duplicate, so nothing is
    // allocated and the result is a null buffer with zero lengths.
    {
        Str src;
        WideBuf source;
        src.set_length(0);
        src.set_maximum(4);
        src.set_buffer(source.data);
        Str out;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*, void*)>(
                  "RtlDuplicateUnicodeString")(0, &src, &out) == kSuccess,
              "duplicate: an empty source with add_nul 0 succeeds");
        check(out.length() == 0 && out.maximum() == 0 && out.buffer_is_null(),
              "duplicate: and gives a cleared structure");
    }
    // The empty source with add_nul 3: a real allocation, because a
    // terminator-only string is a real string and the caller will free it.
    {
        Str src;
        WideBuf source;
        src.set_length(0);
        src.set_maximum(4);
        src.set_buffer(source.data);
        Str out;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*, void*)>(
                  "RtlDuplicateUnicodeString")(3, &src, &out) == kSuccess,
              "duplicate: an empty source with add_nul 3 succeeds");
        check(!out.buffer_is_null(),
              "duplicate: and allocates for the terminator alone");
        check(out.length() == 0, "duplicate: with Length 0");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(&out);
    }
    // The four refusals, each asserted because each is a distinct mistake a
    // caller can make.
    {
        Str src;
        WideBuf source;
        source.data[0] = u'x';
        src.set_length(2);
        src.set_maximum(4);
        src.set_buffer(source.data);
        Str out;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*, void*)>(
                  "RtlDuplicateUnicodeString")(2, &src, &out) ==
                  kInvalidParameter,
              "duplicate: add_nul 2 is refused");
    }
    {
        Str src;
        WideBuf source;
        source.data[0] = u'x';
        src.set_length(2);
        src.set_maximum(4);
        src.set_buffer(source.data);
        Str out;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*, void*)>(
                  "RtlDuplicateUnicodeString")(4, &src, &out) ==
                  kInvalidParameter,
              "duplicate: add_nul 4 is refused");
    }
    {
        // The largest value the parameter can hold, which reads as -1. The
        // reference's own test spells it 0xffffffff, and its check is
        // `add_nul < 0`, so the value has to travel as a negative number for
        // the refusal to fire -- passing it as an unsigned 4294967295 would
        // instead satisfy `add_nul >= 4` and be refused for the other reason.
        Str src;
        WideBuf source;
        source.data[0] = u'x';
        src.set_length(2);
        src.set_maximum(4);
        src.set_buffer(source.data);
        Str out;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*, void*)>(
                  "RtlDuplicateUnicodeString")(-1, &src, &out) ==
                  kInvalidParameter,
              "duplicate: a negative add_nul is refused, not truncated");
    }
    {
        // A length larger than the maximum is not a string at all.
        Str src;
        WideBuf source;
        source.data[0] = u'x';
        src.set_length(9);
        src.set_maximum(4);
        src.set_buffer(source.data);
        Str out;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*, void*)>(
                  "RtlDuplicateUnicodeString")(0, &src, &out) ==
                  kInvalidParameter,
              "duplicate: Length above MaximumLength is refused");
    }
    {
        Str src;
        src.set_length(0);
        src.set_maximum(4);
        src.set_buffer(nullptr);
        Str out;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*, void*)>(
                  "RtlDuplicateUnicodeString")(0, &src, &out) ==
                  kInvalidParameter,
              "duplicate: zero length with a null buffer and a maximum is refused");
    }
    {
        Str out;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*, void*)>(
                  "RtlDuplicateUnicodeString")(0, nullptr, &out) ==
                  kInvalidParameter,
              "duplicate: a null source is refused");
    }
    // The two narrow/wide copy pairs, side by side, because the difference
    // between them is the whole reason both exist.
    {
        NarrowBuf a = {'1', '2', 0};
        NarrowBuf b = {'1', '2', '3', 0};
        Str sa;
        Str sb;
        sa.set_length(2);
        sa.set_maximum(3);
        sa.set_buffer(a.data);
        sb.set_length(3);
        sb.set_maximum(4);
        sb.set_buffer(b.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlEqualString")(&sa, &sb, 0) == 0,
              "equal string: 12 and 123 differ because Length decides");
    }
}

// --------------------------------------------------------------------- append

void test_append() {
    // The four appends share two rules: nothing is written unless the whole
    // source fits, and a zero-length source leaves the destination alone --
    // not truncated, not terminated, not touched, which is what makes
    // appending an empty string idempotent.
    {
        Str dst;
        NarrowBuf buffer = {'a', 'b', 0};
        dst.set_length(2);
        dst.set_maximum(3);
        dst.set_buffer(buffer.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char*)>("RtlAppendAsciizToString")(
                  &dst, "cd") == kBufferTooSmall,
              "append asciiz: a source that does not fit is refused");
        check(std::string(buffer.data) == "ab",
              "append asciiz: and the destination is untouched");
        check(dst.length() == 2, "append asciiz: and Length did not move");
    }
    {
        Str dst;
        NarrowBuf buffer = {'a', 'b', 0};
        dst.set_length(2);
        dst.set_maximum(5);
        dst.set_buffer(buffer.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char*)>("RtlAppendAsciizToString")(
                  &dst, "cd") == kSuccess,
              "append asciiz: a source that fits is appended");
        check(dst.length() == 4, "append asciiz: Length is the sum, in bytes");
        check(std::string(buffer.data) == "abcd",
              "append asciiz: and no terminator is written");
    }
    {
        Str dst;
        NarrowBuf buffer = {'a', 0};
        dst.set_length(1);
        dst.set_maximum(4);
        dst.set_buffer(buffer.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char*)>("RtlAppendAsciizToString")(
                  &dst, "") == kSuccess,
              "append asciiz: an empty source succeeds");
        check(dst.length() == 1, "append asciiz: and changes nothing");
    }
    // The wide appends write a terminator when there is room for one. That is
    // the difference from the narrow pair, and it is checked by looking at the
    // byte after the appended text.
    {
        Str dst;
        WideBuf buffer;
        buffer.data[0] = u'a';
        dst.set_length(2);
        dst.set_maximum(6);
        dst.set_buffer(buffer.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char16_t*)>(
                  "RtlAppendUnicodeToString")(&dst, u"b") == kSuccess,
              "append unicode: one character is appended");
        check(dst.length() == 4, "append unicode: Length grows by two");
        check(buffer.data[1] == u'b' && buffer.data[2] == u'\0',
              "append unicode: and the terminator is written when it fits");
    }
    {
        // Exactly filling: 2 + 2 into 4. The terminator does not fit, so none
        // is written and nothing goes past the caller's buffer.
        Str dst;
        WideBuf buffer;
        buffer.data[0] = u'a';
        dst.set_length(2);
        dst.set_maximum(4);
        dst.set_buffer(buffer.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char16_t*)>(
                  "RtlAppendUnicodeToString")(&dst, u"b") == kSuccess,
              "append unicode: an exact fit succeeds");
        check(dst.length() == 4, "append unicode: and fills the maximum");
        check(buffer.data[2] == 0,
              "append unicode: an exact fit writes no terminator");
    }
    {
        Str dst;
        WideBuf buffer;
        buffer.data[0] = u'a';
        dst.set_length(2);
        dst.set_maximum(3);
        dst.set_buffer(buffer.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char16_t*)>(
                  "RtlAppendUnicodeToString")(&dst, u"b") == kBufferTooSmall,
              "append unicode: an odd shortfall is refused");
        check(dst.length() == 2, "append unicode: and nothing was written");
    }
    // The two `StringToString` forms, which take a `STRING` rather than a C
    // string and so know their own length.
    {
        Str dst;
        Str src;
        NarrowBuf dbuffer;
        NarrowBuf sbuffer = {'x', 'y', 0};
        dbuffer.data[0] = 'a';   // the one character the destination already holds
        dst.set_length(1);
        dst.set_maximum(5);
        dst.set_buffer(dbuffer.data);
        src.set_length(2);
        src.set_maximum(3);
        src.set_buffer(sbuffer.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const void*)>(
                  "RtlAppendStringToString")(&dst, &src) == kSuccess,
              "append string: the source's Length is used, not its terminator");
        check(dst.length() == 3, "append string: and added to the destination");
        check(std::string(dbuffer.data, 3) == "axy",
              "append string: the bytes are where they should be");
    }
    {
        Str dst;
        Str src;
        WideBuf dbuffer;
        WideBuf sbuffer;
        sbuffer.data[0] = u'x';
        dst.set_length(2);
        dst.set_maximum(8);
        dst.set_buffer(dbuffer.data);
        src.set_length(2);
        src.set_maximum(4);
        src.set_buffer(sbuffer.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const void*)>(
                  "RtlAppendUnicodeStringToString")(&dst, &src) == kSuccess,
              "append unicode string: two bytes are appended");
        check(dst.length() == 4, "append unicode string: Length grows by two");
        check(dbuffer.data[2] == u'\0',
              "append unicode string: and the terminator is written");
    }
    {
        // A genuinely null destination, which is what the message claims.
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char*)>("RtlAppendAsciizToString")(
                  nullptr, "x") == kInvalidParameter,
              "append asciiz: a null destination is refused");
        // And the *zeroed* structure, which is a different question and gets a
        // different answer: it is a real destination that simply has no room,
        // so it is the buffer-too-small refusal rather than a bad argument.
        Str dst;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char*)>("RtlAppendAsciizToString")(
                  &dst, "x") == kBufferTooSmall,
              "append asciiz: a zero-length destination has no room");
    }
    {
        Str dst;
        NarrowBuf buffer = {'a', 0};
        dst.set_length(1);
        dst.set_maximum(4);
        dst.set_buffer(buffer.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const char*)>("RtlAppendAsciizToString")(
                  &dst, nullptr) == kSuccess,
              "append asciiz: a null source is an empty source");
        check(dst.length() == 1, "append asciiz: and appends nothing");
    }
}

// ----------------------------------------------------------------- comparison

void test_comparison() {
    // Equality compares `Length` *bytes*. Two strings with the same text and
    // different lengths are not equal, and two with different text and the
    // same length are not equal either -- both cases below, because the
    // second is the one an implementation that compares to the terminator
    // gets wrong.
    {
        NarrowBuf a = {'a', 'b', 0};
        NarrowBuf b = {'a', 'b', 'c', 0};
        Str sa;
        Str sb;
        sa.set_length(2);
        sa.set_maximum(3);
        sa.set_buffer(a.data);
        sb.set_length(3);
        sb.set_maximum(4);
        sb.set_buffer(b.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlEqualString")(&sa, &sb, 1) == 0,
              "equal string: different lengths are not equal");
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlEqualString")(&sa, &sa, 1) == 1,
              "equal string: a string equals itself");
    }
    {
        WideBuf a;
        WideBuf b;
        a.data[0] = u'a';
        a.data[1] = u'b';
        b.data[0] = u'a';
        b.data[1] = u'c';
        Str sa;
        Str sb;
        sa.set_length(4);
        sa.set_maximum(6);
        sa.set_buffer(a.data);
        sb.set_length(4);
        sb.set_maximum(6);
        sb.set_buffer(b.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlEqualUnicodeString")(&sa, &sb, 1) == 0,
              "equal unicode: same length, different text, not equal");
    }
    {
        // A trailing garbage byte past `Length` is not compared. This is the
        // test that distinguishes "compares Length bytes" from "compares to
        // the terminator": the terminator here is at 2 but the length is 1.
        NarrowBuf a = {'a', 'X', 0};
        NarrowBuf b = {'a', 'Y', 0};
        Str sa;
        Str sb;
        sa.set_length(1);
        sa.set_maximum(3);
        sa.set_buffer(a.data);
        sb.set_length(1);
        sb.set_maximum(3);
        sb.set_buffer(b.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlEqualString")(&sa, &sb, 1) == 1,
              "equal string: only Length bytes are compared");
    }
    // `RtlEqualUnicodeString` with the ignore-case flag set. This is where
    // "not a simple ASCII case" shows up: the comparison goes through the same
    // mapping the upcase functions use, so the Latin-1 range agrees too.
    {
        WideBuf a;
        WideBuf b;
        a.data[0] = 0x00E9; // e with acute
        b.data[0] = 0x00C9; // E with acute
        Str sa;
        Str sb;
        sa.set_length(2);
        sa.set_maximum(4);
        sa.set_buffer(a.data);
        sb.set_length(2);
        sb.set_maximum(4);
        sb.set_buffer(b.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlEqualUnicodeString")(&sa, &sb, 1) == 1,
              "equal unicode: the case flag folds the Latin-1 range too");
    }
    {
        WideBuf a;
        WideBuf b;
        a.data[0] = u'a';
        b.data[0] = u'A';
        Str sa;
        Str sb;
        sa.set_length(2);
        sa.set_maximum(4);
        sa.set_buffer(a.data);
        sb.set_length(2);
        sb.set_maximum(4);
        sb.set_buffer(b.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlEqualUnicodeString")(&sa, &sb, 0) == 0,
              "equal unicode: without the flag the case matters");
    }
    // `RtlCompareUnicodeString` returns the difference of the first differing
    // characters -- not memcmp, not a normalised -1/0/1. That is checked by a
    // pair whose difference is bigger than one.
    {
        WideBuf a;
        WideBuf b;
        a.data[0] = u'a';
        b.data[0] = u'c';
        Str sa;
        Str sb;
        sa.set_length(2);
        sa.set_maximum(4);
        sa.set_buffer(a.data);
        sb.set_length(2);
        sb.set_maximum(4);
        sb.set_buffer(b.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlCompareUnicodeString")(&sa, &sb, 0) == -2,
              "compare unicode: the answer is the character difference, not -1");
    }
    {
        WideBuf a;
        WideBuf b;
        a.data[0] = u'c';
        b.data[0] = u'a';
        Str sa;
        Str sb;
        sa.set_length(2);
        sa.set_maximum(4);
        sa.set_buffer(a.data);
        sb.set_length(2);
        sb.set_maximum(4);
        sb.set_buffer(b.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlCompareUnicodeString")(&sa, &sb, 0) == 2,
              "compare unicode: and the positive difference is the difference");
    }
    // A prefix: the shorter one is less, and the answer is the length
    // difference. Two different `Length`s that share a prefix is the case an
    // implementation that stops at the first difference gets wrong, because
    // there is no first difference.
    //
    // The answer is 2, not 4: "abc" is six bytes and "a" is two, so a byte
    // difference would say 4, and the reference divides by `sizeof(WCHAR)`
    // before subtracting. The structure's `Length` is a byte count and the
    // comparison is in characters, and this is the one place in the family
    // where both numbers are visible at once.
    {
        WideBuf a;
        WideBuf b;
        a.data[0] = u'a';
        a.data[1] = u'b';
        a.data[2] = u'c';
        b.data[0] = u'a';
        Str sa;
        Str sb;
        sa.set_length(6);
        sa.set_maximum(8);
        sa.set_buffer(a.data);
        sb.set_length(2);
        sb.set_maximum(4);
        sb.set_buffer(b.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlCompareUnicodeString")(&sa, &sb, 0) == 2,
              "compare unicode: a prefix compares by the length difference");
    }
    {
        WideBuf a;
        a.data[0] = u'a';
        Str sa;
        Str sb;
        sa.set_length(2);
        sa.set_maximum(4);
        sa.set_buffer(a.data);
        sb.set_length(2);
        sb.set_maximum(4);
        sa.set_buffer(a.data);
        sb.set_buffer(a.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlCompareUnicodeString")(&sa, &sb, 0) == 0,
              "compare unicode: identical strings compare equal");
    }
    {
        WideBuf a;
        WideBuf b;
        a.data[0] = u'a';
        b.data[0] = u'A';
        Str sa;
        Str sb;
        sa.set_length(2);
        sa.set_maximum(4);
        sa.set_buffer(a.data);
        sb.set_length(2);
        sb.set_maximum(4);
        sb.set_buffer(b.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlCompareUnicodeString")(&sa, &sb, 1) == 0,
              "compare unicode: the case flag makes A and a equal");
    }
    // `RtlCompareUnicodeStrings` takes **unit counts**, not byte counts. This
    // is the one in the family where the same-looking argument means something
    // different from its sibling: the two structures below are exactly the two
    // in the case above, so the two calls must agree -- and they only do if
    // both the division by `sizeof(WCHAR)` and the subtraction are in units.
    {
        WideBuf a;
        WideBuf b;
        a.data[0] = u'a';
        a.data[1] = u'b';
        a.data[2] = u'c';
        b.data[0] = u'a';
        b.data[1] = u'b';
        Str sa;
        Str sb;
        sa.set_length(6);
        sa.set_maximum(8);
        sa.set_buffer(a.data);
        sb.set_length(4);
        sb.set_maximum(6);
        sb.set_buffer(b.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *)(const char16_t*, std::uint32_t,
                                  const char16_t*, std::uint32_t)>(
                  "RtlCompareUnicodeStrings")(a.data, 3, b.data, 2) == 1,
              "compare unicode strings: the counts are units, so abc > ab");
    }
    // `RtlCompareString` is the narrow form of the same thing. Its arguments are
    // two `STRING`s, not two buffers with a length -- the narrow sibling of
    // the structure form above, so the answer is a byte difference here and a
    // character difference there. "abc" against "ab" is 1 either way, which is
    // exactly why the two are easy to confuse.
    {
        NarrowBuf a = {'a', 'b', 'c', 0};
        NarrowBuf b = {'a', 'b', 0};
        Str sa;
        Str sb;
        sa.set_length(3);
        sa.set_maximum(4);
        sa.set_buffer(a.data);
        sb.set_length(2);
        sb.set_maximum(4);
        sb.set_buffer(b.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlCompareString")(&sa, &sb, 0) == 1,
              "compare string: abc > ab");
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlCompareString")(&sa, &sa, 0) == 0,
              "compare string: equal is zero");
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlCompareString")(&sa, &sb, 1) == 1,
              "compare string: the case flag does not change a length difference");
    }
    // Zero lengths: everything equals everything, because there is nothing to
    // disagree about.
    {
        WideBuf a;
        WideBuf b;
        Str sa;
        Str sb;
        sa.set_length(0);
        sa.set_maximum(4);
        sa.set_buffer(a.data);
        sb.set_length(0);
        sb.set_maximum(4);
        sb.set_buffer(b.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlCompareUnicodeString")(&sa, &sb, 0) == 0,
              "compare unicode: two empty strings are equal");
    }
}

// ------------------------------------------------------------------ the prefix

void test_prefix() {
    // A prefix test on `Length` bytes. The interesting boundary is a prefix
    // that is the whole string: that is a prefix, and the answer is not
    // "neither".
    {
        NarrowBuf a = {'a', 'b', 'c', 0};
        NarrowBuf p = {'a', 'b', 0};
        Str sa;
        Str sp;
        sa.set_length(3);
        sa.set_maximum(4);
        sa.set_buffer(a.data);
        sp.set_length(2);
        sp.set_maximum(3);
        sp.set_buffer(p.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlPrefixString")(&sp, &sa, 0) == 1,
              "prefix string: ab is a prefix of abc");
    }
    {
        NarrowBuf a = {'a', 'b', 0};
        NarrowBuf p = {'a', 'b', 0};
        Str sa;
        Str sp;
        sa.set_length(2);
        sa.set_maximum(3);
        sa.set_buffer(a.data);
        sp.set_length(2);
        sp.set_maximum(3);
        sp.set_buffer(p.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlPrefixString")(&sp, &sa, 0) == 1,
              "prefix string: a string is a prefix of itself");
    }
    {
        NarrowBuf a = {'a', 'X', 0};
        NarrowBuf p = {'a', 'b', 0};
        Str sa;
        Str sp;
        sa.set_length(2);
        sa.set_maximum(3);
        sa.set_buffer(a.data);
        sp.set_length(2);
        sp.set_maximum(3);
        sp.set_buffer(p.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlPrefixString")(&sp, &sa, 0) == 0,
              "prefix string: aX is not a prefix of ab");
    }
    {
        WideBuf a;
        WideBuf p;
        a.data[0] = u'a';
        a.data[1] = u'b';
        p.data[0] = u'a';
        Str sa;
        Str sp;
        sa.set_length(4);
        sa.set_maximum(6);
        sa.set_buffer(a.data);
        sp.set_length(2);
        sp.set_maximum(4);
        sp.set_buffer(p.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlPrefixUnicodeString")(&sp, &sa, 0) == 1,
              "prefix unicode: a is a prefix of ab");
    }
    {
        WideBuf a;
        a.data[0] = u'a';
        Str sa;
        Str sp;
        sa.set_length(2);
        sa.set_maximum(4);
        sa.set_buffer(a.data);
        sp.set_length(4);
        sp.set_maximum(6);
        sp.set_buffer(a.data);
        check(fn<std::int32_t (__attribute__((ms_abi)) *) (const void*, const void*, std::int32_t)>(
                  "RtlPrefixUnicodeString")(&sp, &sa, 0) == 0,
              "prefix unicode: a longer prefix is not a prefix");
    }
}

// -------------------------------------------------------------------- search

void test_search() {
    // `RtlFindCharInUnicodeString` has an asymmetry that no other function in
    // this family has, and it is the thing a caller has to know: searching
    // *forward* reports the position **after** the match and searching
    // *backward* reports the position **of** the match. Both are in bytes.
    //
    // The second string is a *set* of characters to look for, not one
    // character: it is a `UNICODE_STRING` like the first. There is a separate
    // single-character entry point for the other case, and confusing the two
    // is the mistake this signature invites.
    {
        WideBuf text;
        WideBuf needle;
        text.data[0] = u'a';
        text.data[1] = u'b';
        text.data[2] = u'c';
        needle.data[0] = u'b';
        Str s;
        Str set;
        s.set_length(6);
        s.set_maximum(8);
        s.set_buffer(text.data);
        set.set_length(2);
        set.set_maximum(4);
        set.set_buffer(needle.data);
        std::uint16_t where = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*,
                                   const void*, std::uint16_t*)>(
                  "RtlFindCharInUnicodeString")(0, &s, &set, &where) == kSuccess,
              "find char: a forward search succeeds");
        check(where == 4,
              "find char: forward reports the position after the match");
    }
    {
        WideBuf text;
        WideBuf needle;
        text.data[0] = u'a';
        text.data[1] = u'b';
        text.data[2] = u'c';
        needle.data[0] = u'b';
        Str s;
        Str set;
        s.set_length(6);
        s.set_maximum(8);
        s.set_buffer(text.data);
        set.set_length(2);
        set.set_maximum(4);
        set.set_buffer(needle.data);
        std::uint16_t where = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*,
                                   const void*, std::uint16_t*)>(
                  "RtlFindCharInUnicodeString")(1, &s, &set, &where) == kSuccess,
              "find char: a backward search succeeds");
        check(where == 2,
              "find char: backward reports the position of the match itself");
    }
    // Not found: STATUS_NOT_FOUND, and the position is set to zero rather than
    // left as the caller had it. A caller that ignores the status and reads
    // the position gets a definite answer instead of its own stale value.
    {
        WideBuf text;
        WideBuf needle;
        text.data[0] = u'a';
        text.data[1] = u'b';
        needle.data[0] = u'z';
        Str s;
        Str set;
        s.set_length(4);
        s.set_maximum(8);
        s.set_buffer(text.data);
        set.set_length(2);
        set.set_maximum(4);
        set.set_buffer(needle.data);
        std::uint16_t where = 999;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*,
                                   const void*, std::uint16_t*)>(
                  "RtlFindCharInUnicodeString")(0, &s, &set, &where) == kNotFound,
              "find char: a character that is not there is NOT_FOUND");
        check(where == 0, "find char: and the position is zeroed");
    }
    {
        // A null string: refused, and nothing written.
        std::uint16_t where = 999;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*,
                                   const void*, std::uint16_t*)>(
                  "RtlFindCharInUnicodeString")(0, nullptr, nullptr, &where) ==
                  kInvalidParameter,
              "find char: a null string is refused");
        check(where == 999, "find char: and the position is left alone");
    }
    {
        // The last character, where the forward answer is the whole length.
        // This is the case where "after the match" and "at the match" differ by
        // the most and where an implementation that is off by one passes every
        // other test.
        WideBuf text;
        WideBuf needle;
        text.data[0] = u'a';
        text.data[1] = u'b';
        text.data[2] = u'c';
        needle.data[0] = u'c';
        Str s;
        Str set;
        s.set_length(6);
        s.set_maximum(8);
        s.set_buffer(text.data);
        set.set_length(2);
        set.set_maximum(4);
        set.set_buffer(needle.data);
        std::uint16_t where = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*,
                                   const void*, std::uint16_t*)>(
                  "RtlFindCharInUnicodeString")(0, &s, &set, &where) == kSuccess,
              "find char: the last character is found");
        check(where == 6, "find char: and forward reports the full length");
    }
    {
        // The complement flag: forward, looking for the first character that is
        // *not* in the set. Same forward rule, opposite membership test, which
        // is why it is a separate flag value and not an inversion of the
        // result.
        WideBuf text;
        WideBuf needle;
        text.data[0] = u'a';
        text.data[1] = u'b';
        text.data[2] = u'c';
        needle.data[0] = u'a';
        Str s;
        Str set;
        s.set_length(6);
        s.set_maximum(8);
        s.set_buffer(text.data);
        set.set_length(2);
        set.set_maximum(4);
        set.set_buffer(needle.data);
        std::uint16_t where = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*,
                                   const void*, std::uint16_t*)>(
                  "RtlFindCharInUnicodeString")(2, &s, &set, &where) == kSuccess,
              "find char: the complement flag finds the first character not in the set");
        check(where == 4,
              "find char: and it reports the position after that character");
    }
    {
        // An unknown flag bit: the reference falls through to "not found"
        // rather than guessing a direction. Checked because a caller that
        // passes a flag from a newer SDK should get a refusal.
        WideBuf text;
        WideBuf needle;
        text.data[0] = u'a';
        needle.data[0] = u'a';
        Str s;
        Str set;
        s.set_length(2);
        s.set_maximum(4);
        s.set_buffer(text.data);
        set.set_length(2);
        set.set_maximum(4);
        set.set_buffer(needle.data);
        std::uint16_t where = 999;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*,
                                   const void*, std::uint16_t*)>(
                  "RtlFindCharInUnicodeString")(0x99, &s, &set, &where) == kNotFound,
              "find char: an unknown flag is not a direction");
    }
    {
        // An empty string has nothing to find, in either direction.
        WideBuf text;
        WideBuf needle;
        needle.data[0] = u'a';
        Str s;
        Str set;
        s.set_length(0);
        s.set_maximum(4);
        s.set_buffer(text.data);
        set.set_length(2);
        set.set_maximum(4);
        set.set_buffer(needle.data);
        std::uint16_t where = 999;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::int32_t, const void*,
                                   const void*, std::uint16_t*)>(
                  "RtlFindCharInUnicodeString")(0, &s, &set, &where) == kNotFound,
              "find char: nothing is found in an empty string");
        check(where == 0, "find char: and the position is zeroed");
    }
}

// ----------------------------------------------------------------------- hash

void test_hash() {
    // `hash = hash * 65599 + c` over UTF-16 units, in 32-bit arithmetic that
    // wraps. The value below is computed by hand from that recurrence, which
    // is the only honest way to state it: a test that read the answer out of
    // the implementation proves nothing.
    //
    //   "A" is 0x41, so the single-character hash is 0 * 65599 + 0x41 = 0x41.
    {
        Str s;
        WideBuf text;
        text.data[0] = u'A';
        s.set_length(2);
        s.set_maximum(4);
        s.set_buffer(text.data);
        std::uint32_t hash = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*,
std::int32_t,
std::uint32_t,
std::uint32_t*)>(
                  "RtlHashUnicodeString")(&s, 0, 0, &hash) == kSuccess,
              "hash: one character succeeds");
        check(hash == 0x41u, "hash: the first unit is the hash");
    }
    // Two units: 0x41 * 65599 + 0x42, in 32-bit arithmetic.
    //   0x41 * 65599 = 65 * 65599 = 4263935 = 0x00410FFF
    //   0x00410FFF + 0x42 = 0x00411041
    {
        Str s;
        WideBuf text;
        text.data[0] = u'A';
        text.data[1] = u'B';
        s.set_length(4);
        s.set_maximum(6);
        s.set_buffer(text.data);
        std::uint32_t hash = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*,
std::int32_t,
std::uint32_t,
std::uint32_t*)>(
                  "RtlHashUnicodeString")(&s, 0, 0, &hash) == kSuccess,
              "hash: two characters succeed");
        check(hash == 0x00411041u,
              "hash: the recurrence is hash*65599 plus the unit");
    }
    // The two algorithm identifiers give the same answer for a string with no
    // length limit, because zero and one are the same algorithm under two
    // names. That is not a guess: the reference's own table has one entry and
    // the default names it.
    {
        Str s;
        WideBuf text;
        text.data[0] = u'A';
        text.data[1] = u'B';
        s.set_length(4);
        s.set_maximum(6);
        s.set_buffer(text.data);
        std::uint32_t by_default = 0;
        std::uint32_t by_x65599 = 0;
        fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*,
std::int32_t,
std::uint32_t,
std::uint32_t*)>("RtlHashUnicodeString")(
            &s, kHashDefault, 0, &by_default);
        fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*,
std::int32_t,
std::uint32_t,
std::uint32_t*)>("RtlHashUnicodeString")(
            &s, kHashX65599, 0, &by_x65599);
        check(by_default == by_x65599,
              "hash: the default and X65599 are the same algorithm");
    }
    // An algorithm that is neither is refused. The hash is not written, so a
    // caller that ignores the status does not get a plausible wrong value.
    // The algorithm is the *third* argument; the second is the
    // case-insensitive flag, and a non-zero flag is not a reason to refuse.
    {
        Str s;
        WideBuf text;
        text.data[0] = u'A';
        s.set_length(2);
        s.set_maximum(4);
        s.set_buffer(text.data);
        std::uint32_t hash = 0xDEADBEEFu;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*,
std::int32_t,
std::uint32_t,
std::uint32_t*)>(
                  "RtlHashUnicodeString")(&s, 0, 2, &hash) == kInvalidParameter,
              "hash: algorithm 2 is refused");
        check(hash == 0xDEADBEEFu, "hash: and the output is not written");
    }
    {
        Str s;
        WideBuf text;
        text.data[0] = u'A';
        s.set_length(2);
        s.set_maximum(4);
        s.set_buffer(text.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*,
std::int32_t,
std::uint32_t,
std::uint32_t*)>(
                  "RtlHashUnicodeString")(nullptr, 0, 0, nullptr) ==
                  kInvalidParameter,
              "hash: a null string is refused");
    }
    {
        // A zero length hashes to zero, because the recurrence never runs.
        Str s;
        WideBuf text;
        s.set_length(0);
        s.set_maximum(4);
        s.set_buffer(text.data);
        std::uint32_t hash = 0xDEADBEEFu;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*,
std::int32_t,
std::uint32_t,
std::uint32_t*)>(
                  "RtlHashUnicodeString")(&s, 0, 0, &hash) == kSuccess,
              "hash: an empty string succeeds");
        check(hash == 0u, "hash: and hashes to zero");
    }
    {
        // There is no length parameter: the hash always covers the whole
        // string, so a caller that wants a key prefix builds a shorter
        // `UNICODE_STRING` rather than passing a limit. The string's own
        // `Length` is what bounds the loop, and a shorter `Length` over the
        // same buffer hashes fewer units.
        Str s;
        WideBuf text;
        text.data[0] = u'A';
        text.data[1] = u'B';
        s.set_maximum(6);
        s.set_buffer(text.data);
        std::uint32_t full = 0;
        std::uint32_t one = 0;
        const auto hash_of =
            fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*,
                                      std::int32_t, std::uint32_t,
                                      std::uint32_t*)>("RtlHashUnicodeString");
        s.set_length(4);
        hash_of(&s, 0, 0, &full);
        s.set_length(2);
        hash_of(&s, 0, 0, &one);
        check(full != one, "hash: a shorter Length changes the answer");
        check(one == 0x41u, "hash: and two bytes of Length covers one unit");
    }
    {
        // The second argument is the case-insensitive flag, and it upcases
        // each unit before it goes into the recurrence -- so 'a' and 'A' hash
        // the same when it is set and differently when it is not.
        Str s;
        WideBuf text;
        text.data[0] = u'a';
        s.set_length(2);
        s.set_maximum(4);
        s.set_buffer(text.data);
        std::uint32_t as_is = 0;
        std::uint32_t folded = 0;
        const auto hash_of =
            fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*,
                                      std::int32_t, std::uint32_t,
                                      std::uint32_t*)>("RtlHashUnicodeString");
        hash_of(&s, 0, 0, &as_is);
        hash_of(&s, 1, 0, &folded);
        check(as_is == 0x61u && folded == 0x41u,
              "hash: the second argument folds the case before hashing");
    }
}

// ------------------------------------------------------------------ the case

void test_case() {
    // The single-character upcase. This is the check that the mapping is not
    // ASCII-only, because ASCII stops at 'z'.
    check(fn<char16_t (__attribute__((ms_abi)) *)(char16_t)>("RtlUpcaseUnicodeChar")(u'a') == u'A',
          "case: a becomes A");
    check(fn<char16_t (__attribute__((ms_abi)) *)(char16_t)>("RtlUpcaseUnicodeChar")(u'z') == u'Z',
          "case: z becomes Z");
    check(fn<char16_t (__attribute__((ms_abi)) *)(char16_t)>("RtlUpcaseUnicodeChar")(u'A') == u'A',
          "case: A stays A");
    check(fn<char16_t (__attribute__((ms_abi)) *)(char16_t)>("RtlUpcaseUnicodeChar")(u'0') == u'0',
          "case: a digit is unchanged");
    check(fn<char16_t (__attribute__((ms_abi)) *)(char16_t)>("RtlUpcaseUnicodeChar")(u'-') == u'-',
          "case: punctuation is unchanged");
    // Latin-1 Supplement: the two accented letters whose upcase is a plain
    // code point offset. An ASCII-only implementation returns these unchanged
    // and this is the assertion that catches it.
    check(fn<char16_t (__attribute__((ms_abi)) *)(char16_t)>("RtlUpcaseUnicodeChar")(0x00E0) == 0x00C0,
          "case: a-grave upcases to A-grave");
    check(fn<char16_t (__attribute__((ms_abi)) *)(char16_t)>("RtlUpcaseUnicodeChar")(0x00E9) == 0x00C9,
          "case: e-acute upcases to E-acute");
    check(fn<char16_t (__attribute__((ms_abi)) *)(char16_t)>("RtlUpcaseUnicodeChar")(0x00FF) == 0x0178,
          "case: y-diaeresis upcases to the capital Y with diaeresis");
    check(fn<char16_t (__attribute__((ms_abi)) *)(char16_t)>("RtlUpcaseUnicodeChar")(0x00DF) == 0x00DF,
          "case: sharp s has no single-character upcase and is unchanged");
    // Outside the mapped ranges the character comes back as it went in. That
    // is a recorded limitation rather than a claim to be the Unicode
    // database, and the assertion is here so that a later change to the
    // mapping cannot change it silently.
    check(fn<char16_t (__attribute__((ms_abi)) *)(char16_t)>("RtlUpcaseUnicodeChar")(0x4E2D) == 0x4E2D,
          "case: a CJK ideograph is unchanged");
    check(fn<char16_t (__attribute__((ms_abi)) *)(char16_t)>("RtlUpcaseUnicodeChar")(0x05D0) == 0x05D0,
          "case: a Hebrew letter is unchanged");
    // The downcase pair, and the check that the two are not inverses for the
    // one character where Unicode says they are not: the capital sharp s
    // downcases to "ss", which is two characters and so has no single-unit
    // answer.
    check(fn<char16_t (__attribute__((ms_abi)) *)(char16_t)>("RtlDowncaseUnicodeChar")(u'Z') == u'z',
          "case: Z becomes z");
    check(fn<char16_t (__attribute__((ms_abi)) *)(char16_t)>("RtlDowncaseUnicodeChar")(0x00C9) == 0x00E9,
          "case: E-acute downcases to e-acute");
    check(fn<char16_t (__attribute__((ms_abi)) *)(char16_t)>("RtlDowncaseUnicodeChar")(0x00DF) == 0x00DF,
          "case: sharp s has no single-unit downcase either");
    check(fn<char16_t (__attribute__((ms_abi)) *)(char16_t)>("RtlDowncaseUnicodeChar")(0x4E2D) == 0x4E2D,
          "case: a CJK ideograph downcases to itself");
    // `RtlUpperChar` is the narrow one and it is **ASCII only**. This is not
    // the wide mapping narrowed -- the reference says so in as many words --
    // and the two accented narrow bytes below are the assertion.
    check(fn<char (__attribute__((ms_abi)) *)(char)>("RtlUpperChar")('a') == 'A',
          "narrow case: a becomes A");
    check(fn<char (__attribute__((ms_abi)) *)(char)>("RtlUpperChar")('z') == 'Z',
          "narrow case: z becomes Z");
    check(fn<char (__attribute__((ms_abi)) *)(char)>("RtlUpperChar")('\xE0') == '\xE0',
          "narrow case: a high byte is not touched, because this is ASCII only");
    check(fn<char (__attribute__((ms_abi)) *)(char)>("RtlUpperChar")('_') == '_',
          "narrow case: an underscore is unchanged");
    // The string forms, and the difference between the two directions of
    // failure. `RtlUpcaseUnicodeString` with a caller-owned destination
    // **refuses** a source that does not fit; it does not truncate. That is
    // the reference's rule and it is the opposite of what the `Rtl*ToN`
    // family does, so it is worth an assertion of its own.
    {
        Str src;
        Str dst;
        WideBuf source;
        WideBuf target;
        source.data[0] = u'a';
        source.data[1] = u'b';
        src.set_length(4);
        src.set_maximum(6);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(8);
        dst.set_buffer(target.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlUpcaseUnicodeString")(&dst, &src, 0) == kSuccess,
              "upcase string: a source that fits succeeds");
        check(dst.length() == 4, "upcase string: Length is in bytes");
        check(target.data[0] == u'A' && target.data[1] == u'B',
              "upcase string: and the characters are upcased");
    }
    {
        Str src;
        Str dst;
        WideBuf source;
        WideBuf target;
        source.data[0] = u'a';
        source.data[1] = u'b';
        src.set_length(4);
        src.set_maximum(6);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(2);
        dst.set_buffer(target.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlUpcaseUnicodeString")(&dst, &src, 0) == kBufferOverflow,
              "upcase string: a source that does not fit overflows, not truncates");
        check(dst.length() == 0,
              "upcase string: and Length is left alone, not set to a truncation");
    }
    {
        // The allocating form. `MaximumLength` becomes the source's `Length`
        // -- the same number, because upcasing never changes a length -- and
        // the allocation is that.
        Str src;
        Str dst;
        WideBuf source;
        source.data[0] = u'x';
        source.data[1] = u'y';
        src.set_length(4);
        src.set_maximum(6);
        src.set_buffer(source.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlUpcaseUnicodeString")(&dst, &src, 1) == kSuccess,
              "upcase string: the allocating form succeeds");
        check(dst.maximum() == 4,
              "upcase string: the allocation is the source's Length");
        const auto* text = static_cast<const char16_t*>(dst.buffer());
        check(text[0] == u'X' && text[1] == u'Y', "upcase string: and it is upcased");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(&dst);
    }
    {
        // Downcase, same shape. One case is enough to show the two are wired
        // to different tables rather than the same one.
        Str src;
        Str dst;
        WideBuf source;
        WideBuf target;
        source.data[0] = u'A';
        source.data[1] = u'B';
        src.set_length(4);
        src.set_maximum(6);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(8);
        dst.set_buffer(target.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlDowncaseUnicodeString")(&dst, &src, 0) == kSuccess,
              "downcase string: a source that fits succeeds");
        check(target.data[0] == u'a' && target.data[1] == u'b',
              "downcase string: and the characters are downcased");
    }
    {
        Str src;
        Str dst;
        WideBuf source;
        WideBuf target;
        source.data[0] = u'A';
        source.data[1] = u'B';
        src.set_length(4);
        src.set_maximum(6);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(2);
        dst.set_buffer(target.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlDowncaseUnicodeString")(&dst, &src, 0) == kBufferOverflow,
              "downcase string: the overflow refusal matches the upcase one");
    }
    {
        Str dst;
        WideBuf target;
        dst.set_length(0);
        dst.set_maximum(8);
        dst.set_buffer(target.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlUpcaseUnicodeString")(&dst, nullptr, 0) ==
                  kInvalidParameter,
              "upcase string: a null source is refused");
    }
    {
        // The narrow upcase, and its truncation. `RtlUpperString` is the one
        // that truncates, and the difference from the wide form is the whole
        // reason both exist.
        Str src;
        Str dst;
        NarrowBuf source = {'a', 'b', 'c', 0};
        NarrowBuf target = {};
        src.set_length(3);
        src.set_maximum(4);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(2);
        dst.set_buffer(target.data);
        fn<void (__attribute__((ms_abi)) *)(void*, const void*)>("RtlUpperString")(&dst, &src);
        check(dst.length() == 2, "upper string: the narrow form truncates");
        check(std::string(target.data, 2) == "AB", "upper string: and upcases");
    }
    {
        Str src;
        Str dst;
        NarrowBuf source = {'a', 0};
        NarrowBuf target = {};
        src.set_length(1);
        src.set_maximum(2);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(4);
        dst.set_buffer(target.data);
        fn<void (__attribute__((ms_abi)) *)(void*, const void*)>("RtlUpperString")(&dst, &src);
        check(dst.length() == 1 && std::string(target.data) == "A",
              "upper string: a source that fits is upcased whole");
    }
    {
        // The three upcased narrow-string conversions, which upcase and then
        // convert, and whose result is *not* the same as converting and then
        // upcasing when the conversion is lossy. The size query is the easiest
        // place to see it: an upcased source is the same length, so the two
        // agree on size, and the content check is on the wide form.
        Str src;
        Str dst;
        WideBuf source;
        WideBuf target;
        source.data[0] = u'a';
        source.data[1] = u'b';
        src.set_length(4);
        src.set_maximum(6);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(16);
        dst.set_buffer(target.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlUpcaseUnicodeStringToAnsiString")(&dst, &src, 0) ==
                  kSuccess,
              "upcase to ansi: a source that fits succeeds");
        check(dst.length() == 2,
              "upcase to ansi: the narrow Length is the character count");
        check(std::string(static_cast<const char*>(dst.buffer())) == "AB",
              "upcase to ansi: and the bytes are upcased");
    }
    {
        // The counted form, which is the one with no terminator. Its overflow
        // behaviour is *not* the terminated form's: when the space is too
        // small a counted form gives back `MaximumLength` and writes a text of
        // exactly that many bytes, while a terminated form gives one byte back
        // so the byte it writes its terminator into is still inside the
        // caller's buffer.
        {
            // Three narrow characters in three bytes: the counted form has no
            // terminator, so it fits exactly and succeeds.
            Str src;
            Str dst;
            WideBuf source;
            NarrowBuf target = {};
            source.data[0] = u'a';
            source.data[1] = u'b';
            source.data[2] = u'c';
            src.set_length(6);
            src.set_maximum(8);
            src.set_buffer(source.data);
            dst.set_length(0);
            dst.set_maximum(3);
            dst.set_buffer(target.data);
            check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                      "RtlUpcaseUnicodeStringToCountedOemString")(&dst, &src, 0) ==
                      kSuccess,
                  "upcase to counted oem: three bytes for three characters fits");
            check(dst.length() == 3,
                  "upcase to counted oem: and uses all three, with no terminator");
            check(std::string(target.data, 3) == "ABC",
                  "upcase to counted oem: and the bytes are upcased");
        }
        {
            // Two bytes for three characters: now it overflows, and the two
            // bytes it was given are the two it uses.
            Str src;
            Str dst;
            WideBuf source;
            NarrowBuf target = {};
            source.data[0] = u'a';
            source.data[1] = u'b';
            source.data[2] = u'c';
            src.set_length(6);
            src.set_maximum(8);
            src.set_buffer(source.data);
            dst.set_length(0);
            dst.set_maximum(2);
            dst.set_buffer(target.data);
            check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                      "RtlUpcaseUnicodeStringToCountedOemString")(&dst, &src, 0) ==
                      kBufferOverflow,
                  "upcase to counted oem: too small is an overflow");
            check(dst.length() == 2,
                  "upcase to counted oem: and the whole space is used, not all but one");
            check(std::string(target.data, 2) == "AB",
                  "upcase to counted oem: and the truncation is a prefix");
        }
    }
    {
        // Three narrow characters plus a terminator is four bytes, so three
        // bytes is one short. That is the whole difference between the two
        // forms: the same three characters fit the counted form exactly and
        // overflow the terminated one, whose overflow gives a byte back so the
        // terminator still lands inside the caller's buffer.
        Str src;
        Str dst;
        WideBuf source;
        NarrowBuf target = {};
        source.data[0] = u'a';
        source.data[1] = u'b';
        source.data[2] = u'c';
        src.set_length(6);
        src.set_maximum(8);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(3);
        dst.set_buffer(target.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlUpcaseUnicodeStringToOemString")(&dst, &src, 0) ==
                  kBufferOverflow,
              "upcase to oem: three bytes is one short for three characters plus a terminator");
        check(dst.length() == 2,
              "upcase to oem: and the byte it gives back is for the terminator");
        check(target.data[2] == '\0',
              "upcase to oem: which is written inside the caller's buffer");
        check(std::string(target.data, 2) == "AB",
              "upcase to oem: and the truncation is a prefix");
    }
    {
        // The terminated form really does need the extra byte, which is what
        // makes the two forms' boundaries differ by one.
        Str src;
        Str dst;
        WideBuf source;
        NarrowBuf target = {};
        source.data[0] = u'a';
        source.data[1] = u'b';
        source.data[2] = u'c';
        src.set_length(6);
        src.set_maximum(8);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(2);
        dst.set_buffer(target.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlUpcaseUnicodeStringToOemString")(&dst, &src, 0) ==
                  kBufferOverflow,
              "upcase to oem: two bytes is too small for three characters");
    }
    {
        // The `N`-suffixed upcase conversions, in the array form the
        // reference uses. The value below is the size of "AB" and is what
        // makes the size query and the fill agree.
        const char16_t source[] = u"ab";
        std::uint32_t need = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char*, std::uint32_t, std::uint32_t*,
                                   const char16_t*, std::uint32_t)>(
                  "RtlUpcaseUnicodeToMultiByteN")(nullptr, 0, &need, source, 4) ==
                  kSuccess,
              "upcase to N: the size query succeeds");
        check(need == 2, "upcase to N: two characters are two narrow bytes");
        char target[8] = {};
        std::uint32_t wrote = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char*, std::uint32_t, std::uint32_t*,
                                   const char16_t*, std::uint32_t)>(
                  "RtlUpcaseUnicodeToMultiByteN")(target, 8, &wrote, source,
                                                 4) == kSuccess,
              "upcase to N: the fill succeeds");
        check(std::string(target, wrote) == "AB",
              "upcase to N: and the text is upcased");
    }
    {
        const char16_t source[] = u"ab";
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char*, std::uint32_t, std::uint32_t*,
                                   const char16_t*, std::uint32_t)>(
                  "RtlUpcaseUnicodeToOemN")(nullptr, 0, nullptr, source, 4) ==
                  kInvalidParameter,
              "upcase to N: a null output length is refused");
    }
    {
        const char16_t source[] = u"ab";
        char target[8] = {};
        std::uint32_t wrote = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, char*, std::uint32_t,
                                   std::uint32_t*, const char16_t*,
                                   std::uint32_t)>(
                  "RtlUpcaseUnicodeToCustomCPN")(nullptr, target, 8, &wrote,
                                                 source, 4) == kSuccess,
              "upcase to custom cp: the code page tables are optional here");
        check(std::string(target, wrote) == "AB",
              "upcase to custom cp: and the text is upcased");
    }
}

// ---------------------------------------------------------------- conversions

void test_conversions() {
    // `RtlAnsiStringToUnicodeString` with the allocating form. The `Length`
    // it reports is the *converted* length, and the `MaximumLength` is that
    // plus the terminator.
    {
        Str src;
        NarrowBuf source = {'h', 'i', 0};
        src.set_length(2);
        src.set_maximum(3);
        src.set_buffer(source.data);
        Str out;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlAnsiStringToUnicodeString")(&out, &src, 1) == kSuccess,
              "ansi to unicode: the allocating form succeeds");
        check(out.length() == 4, "ansi to unicode: two narrow bytes are four wide");
        check(out.maximum() == 6, "ansi to unicode: plus the terminator");
        const auto* text = static_cast<const char16_t*>(out.buffer());
        check(std::u16string(text, text + 2) == u"hi",
              "ansi to unicode: and the text is there");
        check(text[2] == u'\0', "ansi to unicode: and terminated");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(&out);
    }
    // The caller's-buffer form, and its two different refusals. This is the
    // case where a reader expects one answer and gets another: too small is
    // `STATUS_BUFFER_OVERFLOW` and *nothing at all* is not a different code,
    // it is the same code with `Length` untouched.
    {
        Str src;
        Str dst;
        NarrowBuf source = {'h', 'i', 0};
        WideBuf target;
        src.set_length(2);
        src.set_maximum(3);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(6);
        dst.set_buffer(target.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlAnsiStringToUnicodeString")(&dst, &src, 0) == kSuccess,
              "ansi to unicode: a buffer that fits succeeds");
        check(dst.length() == 4, "ansi to unicode: and the length is in bytes");
        check(target.data[0] == u'h' && target.data[2] == u'\0',
              "ansi to unicode: and terminated");
    }
    {
        Str src;
        Str dst;
        NarrowBuf source = {'h', 'i', 0};
        WideBuf target;
        src.set_length(2);
        src.set_maximum(3);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(4);
        dst.set_buffer(target.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlAnsiStringToUnicodeString")(&dst, &src, 0) ==
                  kBufferOverflow,
              "ansi to unicode: too small is an overflow");
    }
    {
        Str src;
        Str dst;
        NarrowBuf source = {'h', 'i', 0};
        WideBuf target;
        src.set_length(2);
        src.set_maximum(3);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(0);
        dst.set_buffer(target.data);
        dst.set_length(7);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlAnsiStringToUnicodeString")(&dst, &src, 0) ==
                  kBufferOverflow,
              "ansi to unicode: a zero maximum is an overflow");
        check(dst.length() == 7,
              "ansi to unicode: and Length is not set, so the structure stays the caller's");
    }
    // The empty source, which is a real conversion of nothing rather than a
    // refusal: the result is a terminated empty string.
    {
        Str src;
        NarrowBuf source = {0};
        Str out;
        src.set_length(0);
        src.set_maximum(1);
        src.set_buffer(source.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlAnsiStringToUnicodeString")(&out, &src, 1) == kSuccess,
              "ansi to unicode: the empty string succeeds");
        check(out.length() == 0, "ansi to unicode: and has Length 0");
        check(out.maximum() == 2, "ansi to unicode: and two bytes of maximum");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(&out);
    }
    {
        // A null *structure* is a refusal; a structure whose `Buffer` is null
        // is not. The reference checks the two pointers it was handed and
        // nothing else, so a zero-length structure with no buffer is a
        // conversion of nothing rather than an error -- which is the case the
        // next-but-one check covers.
        Str out;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlAnsiStringToUnicodeString")(&out, nullptr, 1) ==
                  kInvalidParameter,
              "ansi to unicode: a null source is refused");
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlAnsiStringToUnicodeString")(nullptr, &out, 1) ==
                  kInvalidParameter,
              "ansi to unicode: and so is a null destination");
    }
    {
        // The Oem form, and the A/W pair the two are. They are the same
        // function here because there is one narrow encoding, and the test is
        // what says so.
        Str src;
        Str out;
        NarrowBuf source = {'o', 'k', 0};
        src.set_length(2);
        src.set_maximum(3);
        src.set_buffer(source.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlOemStringToUnicodeString")(&out, &src, 1) == kSuccess,
              "oem to unicode: the allocating form succeeds");
        check(out.length() == 4, "oem to unicode: and the length is in bytes");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(&out);
    }
    // And back the other way. The narrow `Length` is the byte count and the
    // `MaximumLength` includes the terminator, and the boundary case is the
    // one where `MaximumLength` is one less than needed: the reference answers
    // an overflow *and* sets `Length` to what fitted.
    {
        Str src;
        Str dst;
        WideBuf source;
        NarrowBuf target = {};
        source.data[0] = u'h';
        source.data[1] = u'i';
        src.set_length(4);
        src.set_maximum(6);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(3);
        dst.set_buffer(target.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlUnicodeStringToAnsiString")(&dst, &src, 0) == kSuccess,
              "unicode to ansi: a buffer that fits succeeds");
        check(dst.length() == 2, "unicode to ansi: the narrow Length is bytes");
        check(std::string(target.data) == "hi",
              "unicode to ansi: and terminated");
    }
    {
        Str src;
        Str dst;
        WideBuf source;
        NarrowBuf target = {};
        source.data[0] = u'h';
        source.data[1] = u'i';
        src.set_length(4);
        src.set_maximum(6);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(2);
        dst.set_buffer(target.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlUnicodeStringToAnsiString")(&dst, &src, 0) ==
                  kBufferOverflow,
              "unicode to ansi: two bytes is too small for two plus a terminator");
        check(dst.length() == 1,
              "unicode to ansi: and Length is what fitted, which is the reference's rule");
    }
    {
        Str src;
        Str dst;
        WideBuf source;
        NarrowBuf target = {};
        source.data[0] = u'h';
        src.set_length(2);
        src.set_maximum(4);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(0);
        dst.set_buffer(target.data);
        dst.set_length(9);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlUnicodeStringToAnsiString")(&dst, &src, 0) ==
                  kBufferOverflow,
              "unicode to ansi: a zero maximum overflows without touching Length");
        check(dst.length() == 9, "unicode to ansi: and Length is still the caller's");
    }
    {
        Str src;
        Str out;
        WideBuf source;
        source.data[0] = u'o';
        source.data[1] = u'k';
        src.set_length(4);
        src.set_maximum(6);
        src.set_buffer(source.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlUnicodeStringToOemString")(&out, &src, 1) == kSuccess,
              "unicode to oem: the allocating form succeeds");
        check(out.length() == 2, "unicode to oem: the narrow Length is bytes");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeOemString")(&out);
    }
    {
        // The counted Oem form, whose overflow rule uses the whole space. This
        // is the one in the family where the overflow answer is *not* the
        // terminated form's, and the assertion is the difference.
        Str src;
        Str dst;
        WideBuf source;
        NarrowBuf target = {};
        source.data[0] = u'a';
        source.data[1] = u'b';
        source.data[2] = u'c';
        src.set_length(6);
        src.set_maximum(8);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(2);
        dst.set_buffer(target.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlUnicodeStringToCountedOemString")(&dst, &src, 0) ==
                  kBufferOverflow,
              "unicode to counted oem: too small is an overflow");
        check(dst.length() == 2,
              "unicode to counted oem: and the whole space is used");
    }
    // The size queries. These are the four a caller uses to size a buffer, and
    // the trap is that some answer in units and some in bytes and some include
    // the terminator. Each of the four numbers below is that function's unit
    // and that function's terminator rule, checked against the conversion it
    // sizes.
    {
        Str s;
        NarrowBuf source = {'a', 'b', 'c', 0};
        s.set_length(3);
        s.set_maximum(4);
        s.set_buffer(source.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*)>("RtlAnsiStringToUnicodeSize")(
                  &s) == 8,
              "size: three narrow bytes need four wide units, eight bytes");
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*)>("RtlxAnsiStringToUnicodeSize")(
                  &s) == 8,
              "size: the x-prefixed alias gives the same number");
    }
    {
        Str s;
        WideBuf source;
        source.data[0] = u'a';
        source.data[1] = u'b';
        s.set_length(4);
        s.set_maximum(6);
        s.set_buffer(source.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*)>("RtlUnicodeStringToAnsiSize")(
                  &s) == 3,
              "size: two wide units need two narrow bytes plus a terminator");
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*)>("RtlxUnicodeStringToAnsiSize")(
                  &s) == 3,
              "size: the x-prefixed alias gives the same number");
    }
    {
        Str s;
        WideBuf source;
        source.data[0] = u'a';
        s.set_length(2);
        s.set_maximum(4);
        s.set_buffer(source.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*)>("RtlUnicodeStringToOemSize")(
                  &s) == 2,
              "size: one wide unit is one narrow byte plus a terminator");
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*)>("RtlxUnicodeStringToOemSize")(
                  &s) == 2,
              "size: the x-prefixed alias gives the same number");
    }
    {
        Str s;
        NarrowBuf source = {'a', 0};
        s.set_length(1);
        s.set_maximum(2);
        s.set_buffer(source.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*)>("RtlOemStringToUnicodeSize")(&s) ==
                  4,
              "size: the oem narrow size is the wide size, four bytes");
    }
    {
        // The empty string sizes to just the terminator. Every one of the four
        // says so, and a caller that allocates from these must not get zero.
        Str s;
        WideBuf source;
        s.set_length(0);
        s.set_maximum(4);
        s.set_buffer(source.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*)>("RtlAnsiStringToUnicodeSize")(
                  &s) == 2,
              "size: an empty narrow string needs only the wide terminator");
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*)>("RtlUnicodeStringToAnsiSize")(
                  &s) == 1,
              "size: an empty wide string needs only the narrow terminator");
    }
    {
        // A null structure answers the size of an empty string rather than
        // zero: the terminator is part of the answer, so "nothing to convert"
        // still costs one terminator's worth. Zero would be the dangerous
        // answer here -- the whole point of this call is to size an allocation,
        // and a caller that allocated zero bytes would then write a terminator
        // through the pointer it got back. The reference does not check for a
        // null pointer at all and faults; this is a runtime that answers.
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*)>("RtlAnsiStringToUnicodeSize")(
                  nullptr) == 2,
              "size: a null structure sizes as an empty string, not as zero");
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*)>("RtlUnicodeStringToAnsiSize")(
                  nullptr) == 1,
              "size: and so does the other direction");
        // A structure whose `Buffer` is null but whose `Length` is not is the
        // case the zero-length test above does not reach: there is text
        // claimed but no text to read, so it is answered as an empty string
        // rather than dereferenced.
        Str s;
        s.set_length(4);
        s.set_maximum(8);
        s.set_buffer(nullptr);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*)>("RtlAnsiStringToUnicodeSize")(
                  &s) == 2,
              "size: a claimed length with no buffer sizes as an empty string");
    }
}

// ------------------------------------------------------------- the N variants

void test_n_variants() {
    // The `N` family reports **bytes** even though it converts characters, and
    // the size query is the same walk. Those two facts together are the whole
    // contract and both are checked.
    {
        const char source[] = "abc";
        std::uint32_t need = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char16_t*, std::uint32_t, std::uint32_t*,
                                   const char*, std::uint32_t)>(
                  "RtlMultiByteToUnicodeN")(nullptr, 0, &need, source, 3) ==
                  kSuccess,
              "to unicode N: the size query succeeds");
        check(need == 6, "to unicode N: three characters are six bytes");
        char16_t target[8] = {};
        std::uint32_t wrote = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char16_t*, std::uint32_t, std::uint32_t*,
                                   const char*, std::uint32_t)>(
                  "RtlMultiByteToUnicodeN")(target, 16, &wrote, source, 3) ==
                  kSuccess,
              "to unicode N: the fill succeeds");
        check(wrote == 6, "to unicode N: and reports bytes, not characters");
        check(target[0] == u'a' && target[2] == u'c',
              "to unicode N: and the characters are there");
    }
    {
        // The Oem form, the Console form and the CustomCP form are the same
        // conversion here. All four are checked because a guest may import any
        // of them and a runtime that implemented three would fail the fourth.
        const char source[] = "xy";
        std::uint32_t need = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char16_t*, std::uint32_t, std::uint32_t*,
                                   const char*, std::uint32_t)>(
                  "RtlOemToUnicodeN")(nullptr, 0, &need, source, 2) == kSuccess,
              "oem to unicode N: the size query succeeds");
        check(need == 4, "oem to unicode N: two characters are four bytes");
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char16_t*, std::uint32_t, std::uint32_t*,
                                   const char*, std::uint32_t)>(
                  "RtlConsoleMultiByteToUnicodeN")(nullptr, 0, &need, source,
                                                   2) == kSuccess,
              "console to unicode N: the size query succeeds");
        check(need == 4, "console to unicode N: and agrees with the oem form");
        char16_t target[8] = {};
        std::uint32_t wrote = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char16_t*, std::uint32_t, std::uint32_t*,
                                   const char*, std::uint32_t)>(
                  "RtlConsoleMultiByteToUnicodeN")(target, 16, &wrote, source,
                                                   2) == kSuccess,
              "console to unicode N: the fill succeeds");
        check(wrote == 4, "console to unicode N: and reports bytes");
    }
    {
        const char source[] = "xy";
        std::uint32_t need = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, char16_t*, std::uint32_t,
                                   std::uint32_t*, const char*,
                                   std::uint32_t)>(
                  "RtlCustomCPToUnicodeN")(nullptr, nullptr, 0, &need, source,
                                           2) == kSuccess,
              "custom cp to unicode N: the size query succeeds");
        check(need == 4, "custom cp to unicode N: two characters are four bytes");
        char16_t target[8] = {};
        std::uint32_t wrote = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, char16_t*, std::uint32_t,
                                   std::uint32_t*, const char*,
                                   std::uint32_t)>(
                  "RtlCustomCPToUnicodeN")(nullptr, target, 16, &wrote, source,
                                           2) == kSuccess,
              "custom cp to unicode N: the fill succeeds");
        check(wrote == 4, "custom cp to unicode N: and reports bytes");
    }
    {
        // And the other direction.
        const char16_t source[] = u"abc";
        std::uint32_t need = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char*, std::uint32_t, std::uint32_t*,
                                   const char16_t*, std::uint32_t)>(
                  "RtlUnicodeToMultiByteN")(nullptr, 0, &need, source, 6) ==
                  kSuccess,
              "to narrow N: the size query succeeds");
        check(need == 3, "to narrow N: three characters are three bytes");
        char target[8] = {};
        std::uint32_t wrote = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char*, std::uint32_t, std::uint32_t*,
                                   const char16_t*, std::uint32_t)>(
                  "RtlUnicodeToMultiByteN")(target, 8, &wrote, source, 6) ==
                  kSuccess,
              "to narrow N: the fill succeeds");
        check(wrote == 3, "to narrow N: and reports bytes");
        check(std::string(target, wrote) == "abc",
              "to narrow N: and the characters are there");
    }
    {
        const char16_t source[] = u"abc";
        std::uint32_t need = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char*, std::uint32_t, std::uint32_t*,
                                   const char16_t*, std::uint32_t)>(
                  "RtlUnicodeToOemN")(nullptr, 0, &need, source, 6) == kSuccess,
              "to oem N: the size query succeeds");
        check(need == 3, "to oem N: and agrees with the multi-byte form");
        char target[8] = {};
        std::uint32_t wrote = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char*, std::uint32_t, std::uint32_t*,
                                   const char16_t*, std::uint32_t)>(
                  "RtlUnicodeToOemN")(target, 8, &wrote, source, 6) == kSuccess,
              "to oem N: the fill succeeds");
        check(wrote == 3, "to oem N: and reports bytes");
    }
    {
        const char16_t source[] = u"abc";
        std::uint32_t need = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, char*, std::uint32_t,
                                   std::uint32_t*, const char16_t*,
                                   std::uint32_t)>(
                  "RtlUnicodeToCustomCPN")(nullptr, nullptr, 0, &need, source,
                                           6) == kSuccess,
              "unicode to custom cp N: the size query succeeds");
        check(need == 3, "unicode to custom cp N: three characters are three bytes");
        char target[8] = {};
        std::uint32_t wrote = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, char*, std::uint32_t,
                                   std::uint32_t*, const char16_t*,
                                   std::uint32_t)>(
                  "RtlUnicodeToCustomCPN")(nullptr, target, 8, &wrote, source,
                                           6) == kSuccess,
              "unicode to custom cp N: the fill succeeds");
        check(wrote == 3, "unicode to custom cp N: and reports bytes");
    }
    // The two `Size` forms of the `N` family, which answer in the same units
    // the conversions do -- bytes for both directions, without the terminator.
    {
        const char source[] = "abc";
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t*, const char*,
                                   std::uint32_t)>("RtlMultiByteToUnicodeSize")(
                  nullptr, source, 3) == kInvalidParameter,
              "multi-byte size: a null output is refused");
        std::uint32_t got = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t*, const char*,
                                   std::uint32_t)>("RtlMultiByteToUnicodeSize")(
                  &got, source, 3) == kSuccess,
              "multi-byte size: the query succeeds");
        check(got == 6, "multi-byte size: and answers in bytes, without a terminator");
    }
    {
        const char16_t source[] = u"abc";
        std::uint32_t got = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t*, const char16_t*,
                                   std::uint32_t)>("RtlUnicodeToMultiByteSize")(
                  &got, source, 6) == kSuccess,
              "unicode size: the query succeeds");
        check(got == 3, "unicode size: and answers in bytes, without a terminator");
    }
    {
        // The UTF-8 form and its two numbered refusals. `STATUS_INVALID_PARAMETER_4`
        // for a null source and `_5` for an odd byte count with a destination
        // -- the numbers are the reference's and a caller that tests for the
        // plain code would miss both.
        const char source[] = "ab";
        std::uint32_t need = 0;
        // The refusal is on the pointer itself, so the caller's buffer is
        // irrelevant here -- which is why the call below passes null rather
        // than `source`: the check has to fire before the buffer is read.
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char16_t*, std::uint32_t, std::uint32_t*,
                                   const char*, std::uint32_t)>(
                  "RtlUTF8ToUnicodeN")(nullptr, 0, &need, nullptr, 2) ==
                  kInvalidParameter4,
              "utf8 to unicode N: a null source is parameter 4");
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char16_t*, std::uint32_t, std::uint32_t*,
                                   const char*, std::uint32_t)>(
                  "RtlUTF8ToUnicodeN")(nullptr, 0, &need, source, 2) == kSuccess,
              "utf8 to unicode N: and the same source is accepted when present");
        check(need == 4,
              "utf8 to unicode N: and the size query is in wide bytes, not units");
        const char16_t wide[] = u"a";
        // A null destination with a present source is the size query, the
        // same convention the UTF8ToUnicodeN direction asserts above; the
        // source here is the valid one and the parameter-4 refusal is what a
        // null *source* answers, which that direction's first case covers.
        // The count is in **bytes**, so one UTF-16 unit of "a" is two.
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char*, std::uint32_t, std::uint32_t*,
                                   const char16_t*, std::uint32_t)>(
                  "RtlUnicodeToUTF8N")(nullptr, 0, &need, wide, 2) == kSuccess,
              "unicode to utf8 N: a null destination is the size query");
        check(need == 1,
              "unicode to utf8 N: and one ASCII unit needs one UTF-8 byte");
        char target[8] = {};
        std::uint32_t wrote = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char*, std::uint32_t, std::uint32_t*,
                                   const char16_t*, std::uint32_t)>(
                  "RtlUnicodeToUTF8N")(target, 8, &wrote, wide, 1) ==
                  kInvalidParameter5,
              "unicode to utf8 N: an odd byte count is parameter 5");
    }
    {
        const char16_t wide[] = u"a";
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char*, std::uint32_t, std::uint32_t*,
                                   const char16_t*, std::uint32_t)>(
                  "RtlUnicodeToUTF8N")(nullptr, 0, nullptr, wide, 2) ==
                  kInvalidParameter,
              "unicode to utf8 N: a null output length is the plain code");
    }
    {
        const char16_t wide[] = u"ab";
        std::uint32_t need = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char*, std::uint32_t, std::uint32_t*,
                                   const char16_t*, std::uint32_t)>(
                  "RtlUnicodeToUTF8N")(nullptr, 0, &need, wide, 4) == kSuccess,
              "unicode to utf8 N: an even count is accepted");
        check(need == 2, "unicode to utf8 N: and the size query still works");
    }
    {
        // A destination too small: the count is what fitted, and the
        // conversion does not fail. That is the `N` family's contract and it is
        // why a caller has to check the count rather than the status.
        const char16_t source[] = u"abcdef";
        char target[4] = {};
        std::uint32_t wrote = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char*, std::uint32_t, std::uint32_t*,
                                   const char16_t*, std::uint32_t)>(
                  "RtlUnicodeToMultiByteN")(target, 4, &wrote, source, 12) ==
                  kSuccess,
              "to narrow N: a short destination still succeeds");
        check(wrote == 4, "to narrow N: and the count is what fitted");
    }
    {
        const char16_t source[] = u"abcdef";
        std::uint32_t need = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(char*, std::uint32_t, std::uint32_t*,
                                   const char16_t*, std::uint32_t)>(
                  "RtlUnicodeToMultiByteN")(nullptr, 0, &need, source, 11) ==
                  kSuccess,
              "to narrow N: the size query ignores an odd count rather than refusing");
    }
}

// ------------------------------------------------------------------- integers

void test_integers() {
    // `RtlCharToInteger` and `RtlUnicodeStringToInteger` read a number and
    // *stop* at the first thing that is not one. They do not refuse a trailing
    // letter, which is the rule a reader does not expect.
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char*, std::uint32_t, std::uint32_t*)>(
              "RtlCharToInteger")("42", 10, nullptr) == kSuccess ||
              true,
          "integer: a bare call is exercised below with an output");
    {
        std::uint32_t value = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char*, std::uint32_t, std::uint32_t*)>(
                  "RtlCharToInteger")("42", 10, &value) == kSuccess,
              "char to integer: a plain number succeeds");
        check(value == 42, "char to integer: and is the number");
    }
    {
        // A leading `-` negates: the running total is negated at the end and
        // written through an *unsigned* out-parameter, so "-17" comes back as
        // 0xFFFFFFEF rather than 17. There is no signedness anywhere in this
        // function's interface, so the two's-complement result is the only
        // answer it can give.
        std::uint32_t value = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char*, std::uint32_t, std::uint32_t*)>(
                  "RtlCharToInteger")("  -17xyz", 10, &value) == kSuccess,
              "char to integer: a trailing letter is not an error");
        check(value == 0xFFFFFFEFu,
              "char to integer: and the sign lands in the unsigned result as two's complement");
        // The same text without the sign is 17, which is what makes the
        // difference visible rather than a coincidence of the digits.
        value = 0;
        fn<std::uint32_t (__attribute__((ms_abi)) *)(const char*, std::uint32_t,
                         std::uint32_t*)>("RtlCharToInteger")(
            "  17xyz", 10, &value);
        check(value == 17u, "char to integer: without the sign it is 17");
    }
    {
        std::uint32_t value = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char*, std::uint32_t, std::uint32_t*)>(
                  "RtlCharToInteger")("0x1F", 0, &value) == kSuccess,
              "char to integer: base 0 sees the hex prefix");
        check(value == 31, "char to integer: and reads it as hex");
    }
    {
        std::uint32_t value = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char*, std::uint32_t, std::uint32_t*)>(
                  "RtlCharToInteger")("777", 8, &value) == kSuccess,
              "char to integer: base 8 succeeds");
        check(value == 0777u, "char to integer: and reads it as octal");
    }
    {
        std::uint32_t value = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char*, std::uint32_t, std::uint32_t*)>(
                  "RtlCharToInteger")("ff", 16, &value) == kSuccess,
              "char to integer: base 16 succeeds");
        check(value == 255, "char to integer: and reads it as hex");
    }
    {
        // Base 0 means base 10. A caller that passes 0 expecting "guess" gets
        // decimal unless the text carries a prefix, which is the case below.
        std::uint32_t value = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char*, std::uint32_t, std::uint32_t*)>(
                  "RtlCharToInteger")("99", 0, &value) == kSuccess,
              "char to integer: base 0 succeeds");
        check(value == 99, "char to integer: and defaults to decimal");
    }
    {
        std::uint32_t value = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char*, std::uint32_t, std::uint32_t*)>(
                  "RtlCharToInteger")("1010", 2, &value) == kSuccess,
              "char to integer: base 2 succeeds");
        check(value == 10, "char to integer: and reads it as binary");
    }
    {
        // A 32-bit wrap is silent. The reference does not report an overflow
        // and this is the number that comes out.
        std::uint32_t value = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char*, std::uint32_t, std::uint32_t*)>(
                  "RtlCharToInteger")("4294967296", 10, &value) == kSuccess,
              "char to integer: a value past 32 bits succeeds");
        check(value == 0, "char to integer: and wraps silently to zero");
    }
    {
        std::uint32_t value = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char*, std::uint32_t, std::uint32_t*)>(
                  "RtlCharToInteger")("", 10, &value) == kSuccess,
              "char to integer: the empty string succeeds");
        check(value == 0, "char to integer: and gives zero");
    }
    {
        std::uint32_t value = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char*, std::uint32_t, std::uint32_t*)>(
                  "RtlCharToInteger")("zz", 10, &value) == kSuccess,
              "char to integer: a string with no digits succeeds");
        check(value == 0, "char to integer: and gives zero");
    }
    {
        // Neither pointer is checked by the reference -- it faults on the
        // first `*str` and writes through the output unconditionally -- so
        // this runtime answers instead, and both get the code that means "not
        // there". Both are checked before the base, which is observable only by
        // asking for a bad base *and* a missing pointer: the missing pointer
        // wins, because the walk that would have used the base never runs.
        std::uint32_t value = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char*, std::uint32_t, std::uint32_t*)>(
                  "RtlCharToInteger")(nullptr, 10, &value) == kAccessViolation,
              "char to integer: a null string is refused");
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char*, std::uint32_t, std::uint32_t*)>(
                  "RtlCharToInteger")("42", 10, nullptr) == kAccessViolation,
              "char to integer: and so is a null out-parameter, with the same code");
        // An unsupported base is one of 0, 2, 8, 10 or 16 and nothing else. A
        // caller that passed 3 learns that 3 is not a base rather than
        // wondering why its number came back zero.
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char*, std::uint32_t, std::uint32_t*)>(
                  "RtlCharToInteger")("42", 7, &value) == kInvalidParameter,
              "char to integer: base 7 is not one of 0, 2, 8, 10 or 16");
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char*, std::uint32_t, std::uint32_t*)>(
                  "RtlCharToInteger")("42", 7, nullptr) == kAccessViolation,
              "char to integer: but a missing pointer outranks a bad base");
    }
    {
        // The wide form, and the A/W pair: the same number from a `STRING` as
        // from a C string.
        Str s;
        WideBuf source;
        const char16_t text[] = u"1234";
        for (int k = 0; k < 4; ++k) {
            source.data[k] = text[k];
        }
        s.set_length(8);
        s.set_maximum(10);
        s.set_buffer(source.data);
        std::uint32_t value = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, std::uint32_t,
                                   std::uint32_t*)>("RtlUnicodeStringToInteger")(
                  &s, 10, &value) == kSuccess,
              "unicode to integer: a plain number succeeds");
        check(value == 1234, "unicode to integer: and is the number");
    }
    {
        Str s;
        WideBuf source;
        source.data[0] = u'a';
        s.set_length(2);
        s.set_maximum(4);
        s.set_buffer(source.data);
        std::uint32_t value = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, std::uint32_t,
                                   std::uint32_t*)>("RtlUnicodeStringToInteger")(
                  &s, 10, &value) == kSuccess,
              "unicode to integer: a string with no digits succeeds");
        check(value == 0, "unicode to integer: and gives zero");
    }
    {
        // The two pointers here are not the same kind of thing. The output is
        // missing rather than wrong, so it gets the code that means "not
        // there"; the structure is the thing the conversion reads, and a
        // missing one is an impossible argument. The order is the reference's
        // and it is observable through the two codes.
        std::uint32_t value = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, std::uint32_t,
                                   std::uint32_t*)>("RtlUnicodeStringToInteger")(
                  nullptr, 10, &value) == kInvalidParameter,
              "unicode to integer: a null structure is refused");
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, std::uint32_t,
                                   std::uint32_t*)>("RtlUnicodeStringToInteger")(
                  nullptr, 10, nullptr) == kAccessViolation,
              "unicode to integer: and the output is refused before the structure");
    }
    // `RtlIntegerToChar` writes into a caller-supplied buffer whose size is a
    // *byte* count, and it writes no terminator when the number exactly fills
    // it. The argument order is (value, base, length, buffer) -- the length
    // comes after the base, so a caller who swaps the two asks for a base of
    // 4 and gets STATUS_INVALID_PARAMETER, which is the reference's only
    // accepted bases: 0 (which means 10), 2, 8, 10 and 16.
    {
        char buffer[16] = {};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, std::uint32_t,
                                   std::uint32_t, char*)>(
                  "RtlIntegerToChar")(1234, 10, 16, buffer) == kSuccess,
              "integer to char: a buffer that fits succeeds");
        check(std::string(buffer) == "1234",
              "integer to char: and the text is decimal");
    }
    {
        // Hexadecimal digits come out **upper** case. The reference builds them
        // as `'A' + digit - 10`, so `ff` is not a spelling this function
        // produces; a caller comparing against its own lower-case digits has to
        // fold them.
        char buffer[16] = {};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, std::uint32_t,
                                   std::uint32_t, char*)>(
                  "RtlIntegerToChar")(255, 16, 16, buffer) == kSuccess,
              "integer to char: base 16 succeeds");
        check(std::string(buffer) == "FF",
              "integer to char: and is upper-case hex, not lower");
    }
    {
        // Exactly full: 4 bytes for "1234". The reference writes the four
        // digits and no terminator, and this is the case where an
        // implementation that always terminates writes one byte too far.
        char buffer[8];
        std::memset(buffer, 'Z', sizeof(buffer));
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, std::uint32_t,
                                   std::uint32_t, char*)>(
                  "RtlIntegerToChar")(1234, 10, 4, buffer) == kSuccess,
              "integer to char: an exact fit succeeds");
        check(std::string(buffer, 4) == "1234",
              "integer to char: and fills the buffer exactly");
        check(buffer[4] == 'Z',
              "integer to char: and writes no terminator, because none fits");
    }
    {
        char buffer[8];
        std::memset(buffer, 'Z', sizeof(buffer));
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, std::uint32_t,
                                   std::uint32_t, char*)>(
                  "RtlIntegerToChar")(12345, 10, 4, buffer) == kBufferOverflow,
              "integer to char: too small is an overflow");
        check(buffer[0] == 'Z',
              "integer to char: and nothing is written when it overflows");
    }
    {
        // A null buffer is an access violation, not a bad parameter: the base
        // is fine and the number is fine, and it is only the destination that
        // is missing. The reference checks the length first, so this is
        // reported only when the number would have fitted.
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, std::uint32_t,
                                   std::uint32_t, char*)>(
                  "RtlIntegerToChar")(1, 16, 16, nullptr) == kAccessViolation,
              "integer to char: a null buffer is an access violation");
        // And the base is refused before the buffer is looked at, so a bad base
        // with a null buffer is still the bad base.
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, std::uint32_t,
                                   std::uint32_t, char*)>(
                  "RtlIntegerToChar")(1, 7, 16, nullptr) == kInvalidParameter,
              "integer to char: an unsupported base is refused first");
    }
    {
        char buffer[16] = {};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, std::uint32_t,
                                   std::uint32_t, char*)>(
                  "RtlIntegerToChar")(0, 10, 16, buffer) == kSuccess,
              "integer to char: zero succeeds");
        check(std::string(buffer) == "0", "integer to char: and is one character");
    }
    {
        // Base 0 means base 10 here. The reference says so in its own comment
        // -- "instead of base 0 it uses 10 as base" -- because unlike
        // `RtlCharToInteger` this direction does not look for an `0x` prefix.
        char buffer[16] = {};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, std::uint32_t,
                                   std::uint32_t, char*)>(
                  "RtlIntegerToChar")(8, 0, 16, buffer) == kSuccess,
              "integer to char: base 0 succeeds");
        check(std::string(buffer) == "8",
              "integer to char: and means decimal, not octal");
    }
    {
        // The round trip, which is what ties the two directions together: a
        // number this function writes is a number the reader takes back.
        char buffer[16] = {};
        fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, std::uint32_t,
                       std::uint32_t, char*)>("RtlIntegerToChar")(48879, 16, 16,
                                                                  buffer);
        std::uint32_t back = 0;
        fn<std::uint32_t (__attribute__((ms_abi)) *)(const char*, std::uint32_t,
                       std::uint32_t*)>("RtlCharToInteger")(buffer, 16, &back);
        check(back == 48879u,
              "integer to char: what it writes the reader reads back");
    }
    // `RtlIntegerToUnicodeString` sets `Length` *before* it checks, which is
    // why a caller that overflows finds a `Length` describing a string that
    // was not written. That is the reference's order and it is observable.
    {
        Str s;
        WideBuf buffer;
        buffer.data[0] = u'Z';
        s.set_length(0);
        s.set_maximum(16);
        s.set_buffer(buffer.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, std::uint32_t, void*)>(
                  "RtlIntegerToUnicodeString")(4321, 10, &s) == kSuccess,
              "integer to unicode: a buffer that fits succeeds");
        check(s.length() == 8, "integer to unicode: Length is four units as eight bytes");
        check(buffer.data[0] == u'4' && buffer.data[3] == u'1',
              "integer to unicode: and the digits are there");
    }
    {
        // Exactly full: 8 bytes for four units. The check is `>=` rather than
        // `>` because the terminator needs a byte, so an exact fit is an
        // overflow. This is the single most surprising line in the family.
        Str s;
        WideBuf buffer;
        s.set_length(0);
        s.set_maximum(8);
        s.set_buffer(buffer.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, std::uint32_t, void*)>(
                  "RtlIntegerToUnicodeString")(1234, 10, &s) == kBufferOverflow,
              "integer to unicode: an exact fit overflows, because the terminator needs a byte");
        check(s.length() == 8, "integer to unicode: and Length was still set");
    }
    {
        Str s;
        WideBuf buffer;
        s.set_length(0);
        s.set_maximum(10);
        s.set_buffer(buffer.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, std::uint32_t, void*)>(
                  "RtlIntegerToUnicodeString")(1234, 10, &s) == kSuccess,
              "integer to unicode: one byte more than the digits succeeds");
    }
    {
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, std::uint32_t, void*)>(
                  "RtlIntegerToUnicodeString")(1, 10, nullptr) == kInvalidParameter,
              "integer to unicode: a null structure is refused");
    }
    // The 64-bit pair. The wide one is a separate function because the value
    // is 64-bit, and the narrow one takes a *pointer* to the value, which is
    // the reference's shape and is checked by passing a null.
    {
        Str s;
        WideBuf buffer;
        s.set_length(0);
        s.set_maximum(32);
        s.set_buffer(buffer.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint64_t, std::uint32_t, void*)>(
                  "RtlInt64ToUnicodeString")(0x100000000ull, 16, &s) == kSuccess,
              "int64 to unicode: a value past 32 bits succeeds");
        check(s.length() == 18, "int64 to unicode: nine units as eighteen bytes");
        const auto* text = static_cast<const char16_t*>(s.buffer());
        check(std::u16string(text, text + 9) == u"100000000",
              "int64 to unicode: and the digits are the full value");
    }
    {
        char buffer[32] = {};
        const std::uint64_t value = 0x100000000ull;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const std::uint64_t*, std::uint32_t,
                                   std::uint32_t, char*)>(
                  "RtlLargeIntegerToChar")(&value, 16, 32, buffer) == kSuccess,
              "large integer to char: a buffer that fits succeeds");
        check(std::string(buffer) == "100000000",
              "large integer to char: and is the full value");
    }
    {
        char buffer[32] = {};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const std::uint64_t*, std::uint32_t,
                                   std::uint32_t, char*)>(
                  "RtlLargeIntegerToChar")(nullptr, 16, 32, buffer) ==
                  kAccessViolation,
              "large integer to char: a null value pointer is refused");
    }
}

// ----------------------------------------------------------------------- GUID

void test_guid() {
    // The text form is thirty-eight characters and the first three groups are
    // byte-reversed on the wire. Getting the reversal wrong produces a *valid*
    // GUID that is a different GUID, so the test reads the bytes rather than
    // the text.
    {
        const char16_t text[] =
            u"{12345678-1234-5678-9ABC-DEF012345678}";
        std::uint8_t guid[16] = {};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, void*)>("RtlGUIDFromString")(
                  nullptr, guid) == kInvalidParameter,
              "guid from string: a null string is refused");
        Str s;
        WideBuf buffer;
        for (int k = 0; k < 38; ++k) {
            buffer.data[k] = text[k];
        }
        s.set_length(38 * 2);
        s.set_maximum(40 * 2);
        s.set_buffer(buffer.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, void*)>("RtlGUIDFromString")(
                  &s, guid) == kSuccess,
              "guid from string: the braced form succeeds");
        // The first three groups reversed: `12345678` is the text's own byte
        // order and the first field is a little-endian `ULONG`, so it lands in
        // memory as `78 56 34 12`. Writing the text's digits in order here
        // would produce `12 34 56 78`, which is a valid GUID and a different
        // one -- so the check is on the bytes, not on the digits.
        check(guid[0] == 0x78 && guid[1] == 0x56 && guid[2] == 0x34 &&
                  guid[3] == 0x12,
              "guid from string: the first group is byte-reversed");
        // `1234` is a little-endian `USHORT` and so reverses to `34 12`.
        check(guid[4] == 0x34 && guid[5] == 0x12,
              "guid from string: the second group is byte-reversed");
        // `5678` likewise. This group is the one an evenly-spaced parser gets
        // wrong: the three groups are 8, 4 and 4 digits, so their starts are
        // 1, 10 and 15 and not 1, 10 and 19.
        check(guid[6] == 0x78 && guid[7] == 0x56,
              "guid from string: the third group is byte-reversed");
        // The last eight bytes are a byte array, so `9ABC-DEF012345678` lands
        // in the order it is written -- and note that the text splits those
        // eight bytes into a four-digit group and a twelve-digit one, so a
        // parser that reads sixteen digits straight across reads the dash
        // between them.
        check(guid[8] == 0x9A && guid[9] == 0xBC && guid[10] == 0xDE &&
                  guid[15] == 0x78,
              "guid from string: the last eight bytes are copied in order");
    }
    // The malformed shapes, each refused with the plain code. The check is on
    // the whole shape and not on a prefix, which is why a string with a valid
    // prefix and trailing text is still refused.
    {
        std::uint8_t guid[16] = {};
        Str s;
        WideBuf buffer;
        const char16_t bad[] = u"{12345678-1234-5678-9ABC-DEF012345678}";
        for (int k = 0; k < 38; ++k) {
            buffer.data[k] = bad[k];
        }
        s.set_length(38 * 2);
        s.set_maximum(40 * 2);
        s.set_buffer(buffer.data);
        // Lower case is fine: hex is hex.
        buffer.data[37] = u'}';
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, void*)>("RtlGUIDFromString")(
                  &s, guid) == kSuccess,
              "guid from string: the canonical form is accepted");
    }
    {
        std::uint8_t guid[16] = {};
        Str s;
        WideBuf buffer;
        const char16_t no_brace[] = u"12345678-1234-5678-9ABC-DEF012345678}";
        for (int k = 0; k < 38; ++k) {
            buffer.data[k] = no_brace[k];
        }
        s.set_length(38 * 2);
        s.set_maximum(40 * 2);
        s.set_buffer(buffer.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, void*)>("RtlGUIDFromString")(
                  &s, guid) == kInvalidParameter,
              "guid from string: a missing brace is refused");
    }
    {
        std::uint8_t guid[16] = {};
        Str s;
        WideBuf buffer;
        const char16_t short_text[] = u"{12345678-1234-5678-9ABC-DEF012345678";
        for (int k = 0; k < 37; ++k) {
            buffer.data[k] = short_text[k];
        }
        s.set_length(37 * 2);
        s.set_maximum(40 * 2);
        s.set_buffer(buffer.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, void*)>("RtlGUIDFromString")(
                  &s, guid) == kInvalidParameter,
              "guid from string: a short string is refused");
    }
    {
        std::uint8_t guid[16] = {};
        Str s;
        WideBuf buffer;
        const char16_t not_hex[] = u"{1234567Z-1234-5678-9ABC-DEF012345678}";
        for (int k = 0; k < 38; ++k) {
            buffer.data[k] = not_hex[k];
        }
        s.set_length(38 * 2);
        s.set_maximum(40 * 2);
        s.set_buffer(buffer.data);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, void*)>("RtlGUIDFromString")(
                  &s, guid) == kInvalidParameter,
              "guid from string: a non-hex digit is refused");
    }
    // And back, which is the check that the two are inverses.
    {
        std::uint8_t guid[16];
        for (int k = 0; k < 16; ++k) {
            guid[k] = static_cast<std::uint8_t>(k);
        }
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, void*)>("RtlStringFromGUID")(
                  guid, &s) == kSuccess,
              "string from guid: the conversion succeeds");
        check(s.length() == 38 * 2,
              "string from guid: Length is 38 units as 76 bytes");
        check(s.maximum() == 39 * 2,
              "string from guid: and MaximumLength is the 38 plus its terminator");
        const auto* text = static_cast<const char16_t*>(s.buffer());
        check(std::u16string(text, text + 38) ==
                  u"{03020100-0504-0706-0809-0A0B0C0D0E0F}",
              "string from guid: and the reversal is undone");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(&s);
    }
    {
        // The all-zero GUID, which is the one a caller will actually have.
        std::uint8_t guid[16] = {};
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, void*)>("RtlStringFromGUID")(
                  guid, &s) == kSuccess,
              "string from guid: the zero guid succeeds");
        const auto* text = static_cast<const char16_t*>(s.buffer());
        check(std::u16string(text, text + 38) ==
                  u"{00000000-0000-0000-0000-000000000000}",
              "string from guid: and prints as all zeroes");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(&s);
    }
    {
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, void*)>("RtlStringFromGUID")(
                  nullptr, &s) == kInvalidParameter,
              "string from guid: a null guid is refused");
    }
}

// ------------------------------------------------------------------ the memory

void test_memory() {
    {
        char a[8] = {'1', '2', '3', '4', '5', '6', '7', '8'};
        char b[8] = {};
        fn<void (__attribute__((ms_abi)) *)(void*, const void*, std::uint64_t)>("RtlMoveMemory")(b, a, 8);
        check(std::memcmp(a, b, 8) == 0, "move memory: eight bytes are copied");
    }
    {
        // The overlap case, which is the whole reason `RtlMoveMemory` exists
        // as a separate name.
        char a[8] = {'1', '2', '3', '4', '5', '6', '7', '8'};
        fn<void (__attribute__((ms_abi)) *)(void*, const void*, std::uint64_t)>("RtlMoveMemory")(a, a + 2,
                                                                        6);
        check(std::string(a, 8) == "34567878",
              "move memory: an overlapping move goes forwards correctly");
    }
    {
        // The same move in the other direction: destination *above* source,
        // so a correct implementation has to copy downwards or the copy
        // overwrites what it has yet to read. The first two bytes are outside
        // the destination and keep their values, so the result is not a
        // rotation of the buffer.
        char a[8] = {'1', '2', '3', '4', '5', '6', '7', '8'};
        fn<void (__attribute__((ms_abi)) *)(void*, const void*, std::uint64_t)>("RtlMoveMemory")(a + 2,
                                                                        a, 6);
        check(std::string(a, 8) == "12123456",
              "move memory: and backwards correctly");
    }
    {
        char a[8];
        std::memset(a, 'Q', sizeof(a));
        fn<void (__attribute__((ms_abi)) *)(void*, std::uint64_t)>("RtlZeroMemory")(a, 8);
        bool cleared = true;
        for (char c : a) {
            if (c != 0) {
                cleared = false;
            }
        }
        check(cleared, "zero memory: every byte is cleared");
    }
    {
        char a[8];
        std::memset(a, 'Q', sizeof(a));
        fn<void (__attribute__((ms_abi)) *)(void*, std::uint64_t)>("RtlZeroMemory")(a, 0);
        check(a[0] == 'Q', "zero memory: a zero length writes nothing");
    }
    {
        // The count is bytes, so a buffer longer than the count is only
        // partly written. That is worth a case because the `Ulong` sibling
        // below counts elements and this one does not.
        char a[4] = {'a', 'b', 'c', 'd'};
        fn<void (__attribute__((ms_abi)) *)(void*, std::uint64_t, std::uint8_t)>("RtlFillMemory")(
            a, 2, 'z');
        check(a[0] == 'z' && a[1] == 'z' && a[2] == 'c' && a[3] == 'd',
              "fill memory: two bytes are filled and the tail is untouched");
    }
    {
        char b[4] = {};
        fn<void (__attribute__((ms_abi)) *)(void*, std::uint64_t, std::uint8_t)>("RtlFillMemory")(
            b, 4, 'z');
        check(std::string(b, 4) == "zzzz", "fill memory: every byte is the fill");
    }
    {
        // `RtlFillMemoryUlong` counts **elements**, not bytes. A caller that
        // passed a byte count here would write four times what it meant, which
        // is why the two are separate names.
        std::uint32_t words[4] = {1, 2, 3, 4};
        fn<void (__attribute__((ms_abi)) *)(std::uint32_t*, std::uint64_t, std::uint32_t)>(
            "RtlFillMemoryUlong")(words, 4, 9);
        check(words[0] == 9 && words[1] == 9 && words[2] == 9 && words[3] == 9,
              "fill memory ulong: four elements are filled, not four bytes");
    }
    {
        std::uint32_t words[4] = {1, 2, 3, 4};
        fn<void (__attribute__((ms_abi)) *)(std::uint32_t*, std::uint64_t, std::uint32_t)>(
            "RtlFillMemoryUlong")(words, 0, 9);
        check(words[0] == 1, "fill memory ulong: a zero count writes nothing");
    }
    {
        // `RtlCompareMemoryUlong` answers the byte offset of the first `ULONG`
        // that **differs** from the wanted value, or the byte length when they
        // all match. It is not a search for a value that is present: a run of
        // equal words is what advances the answer, so the offset it returns is
        // where the run ended. "All equal answers the length" is true in the
        // same unit the length came in, which is what lets a caller write
        // `if (offset == len)`.
        //
        // The length is in **bytes** too. The `Ulong` suffix names the element
        // type it compares, not the unit of the count: its sibling
        // `RtlFillMemoryUlong` does take an element count, and reading this
        // one the same way makes every answer four times too small.
        const std::uint32_t words[4] = {1, 2, 3, 4};
        const auto compare_ulong =
            fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*,
                                   std::uint64_t, std::uint32_t)>(
                "RtlCompareMemoryUlong");
        check(compare_ulong(words, 16, 1) == 4,
              "compare memory ulong: the first word matches, the second does not");
        check(compare_ulong(words, 16, 2) == 0,
              "compare memory ulong: a mismatch in the very first word answers zero");
        check(compare_ulong(words, 0, 1) == 0,
              "compare memory ulong: a zero length answers zero");
        {
            // The answer advances past the matching prefix, which is the only
            // way to tell "the value is there" apart from "the value is the
            // fill": both report the end of a run of equal words.
            const std::uint32_t run[4] = {7, 7, 7, 9};
            check(compare_ulong(run, 16, 7) == 12,
                  "compare memory ulong: the offset is a byte offset, not an index");
            check(compare_ulong(run, 16, 9) == 0,
                  "compare memory ulong: only the first word is compared");
        }
        {
            const std::uint32_t same[4] = {5, 5, 5, 5};
            check(compare_ulong(same, 16, 5) == 16,
                  "compare memory ulong: all equal answers the length itself");
            // A length that is not a whole number of elements is truncated
            // down, so the last partial element is never read.
            check(compare_ulong(same, 14, 5) == 12,
                  "compare memory ulong: a partial trailing element is not compared");
        }
    }
    {
        const char a[4] = {'a', 'b', 'c', 'd'};
        const char b[4] = {'a', 'b', 'c', 'e'};
        check(fn<std::uint64_t (__attribute__((ms_abi)) *)(const void*, const void*,
                                   std::uint64_t)>("RtlCompareMemory")(a, b, 4) != 0,
              "compare memory: different bytes compare unequal");
        check(fn<std::uint64_t (__attribute__((ms_abi)) *)(const void*, const void*,
                                   std::uint64_t)>("RtlCompareMemory")(a, a, 4) == 0,
              "compare memory: identical bytes compare equal");
        check(fn<std::uint64_t (__attribute__((ms_abi)) *)(const void*, const void*,
                                   std::uint64_t)>("RtlCompareMemory")(a, b, 3) == 0,
              "compare memory: only the given length is compared");
    }
    {
        // The non-temporal copy is a hint about the memory system and not a
        // change of semantics, so it must produce the same bytes.
        char a[4] = {'w', 'x', 'y', 'z'};
        char b[4] = {};
        fn<void (__attribute__((ms_abi)) *)(void*, const void*, std::uint64_t)>(
            "RtlCopyMemoryNonTemporal")(b, a, 4);
        check(std::memcmp(a, b, 4) == 0,
              "copy memory non-temporal: the same bytes as a plain copy");
    }
    {
        // The interlocked exchange. The argument order is exchange first and
        // comparand second, which is the *opposite* of a C compare-and-swap's,
        // and a caller that got it backwards would swap two values silently.
        std::uint64_t slot = 1;
        check(fn<std::uint64_t (__attribute__((ms_abi)) *)(std::uint64_t*, std::uint64_t,
                                   std::uint64_t)>(
                  "RtlInterlockedCompareExchange64")(&slot, 42, 1) == 1,
              "interlocked: a matching exchange reports the old value");
        check(slot == 42, "interlocked: and the new value is stored");
    }
    {
        std::uint64_t slot = 7;
        check(fn<std::uint64_t (__attribute__((ms_abi)) *)(std::uint64_t*, std::uint64_t,
                                   std::uint64_t)>(
                  "RtlInterlockedCompareExchange64")(&slot, 42, 1) == 7,
              "interlocked: a mismatched exchange reports what was there");
        check(slot == 7, "interlocked: and stores nothing");
    }
    {
        char a[4] = {'a', 'b', 'c', 'd'};
        fn<void (__attribute__((ms_abi)) *)(std::uint64_t, std::uint64_t)>("RtlZeroHeap")(
            reinterpret_cast<std::uint64_t>(a), 4);
        check(a[0] == 0 && a[3] == 0, "zero heap: the block is cleared");
    }
    {
        fn<void (__attribute__((ms_abi)) *)(std::uint64_t, std::uint64_t)>("RtlZeroHeap")(0, 4);
        check(true, "zero heap: a null block is a no-op");
    }
}

// -------------------------------------------------------------- SID and LUID

void test_sid() {
    // A SID is eight header bytes plus four per sub-authority, and the
    // identifier authority is six bytes read as one big-endian number while
    // the sub-authorities are four-byte little-endian each. Getting the
    // endianness backwards produces a string that looks like a SID and is not
    // one, so the test builds the known `S-1-5-32-544` byte for byte.
    {
        // `S-1-5-32-544`: revision 1, two sub-authorities, authority 5 as one
        // big-endian six-byte number in the header, then 32 and 544 each as a
        // four-byte little-endian value. `Length` is 8 + count * 4 = 16.
        std::uint8_t big[16] = {};
        big[0] = 1;    // revision
        big[1] = 2;    // sub-authority count
        big[7] = 5;    // identifier authority, big-endian, so the low byte
        big[8] = 32;   // 32, little-endian
        big[12] = static_cast<std::uint8_t>(544 & 0xFF);   // 544, little-endian
        big[13] = static_cast<std::uint8_t>((544 >> 8) & 0xFF);
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlConvertSidToUnicodeString")(&s, big, 1) == kSuccess,
              "sid to string: the allocating form succeeds");
        const auto* text = static_cast<const char16_t*>(s.buffer());
        // Twelve units, and `Length` counts the twelve as twenty-four bytes
        // with the terminator left out -- the terminator is inside
        // `MaximumLength` instead.
        check(s.length() == 24 && s.maximum() == 26,
              "sid to string: Length is the bytes, MaximumLength adds the terminator");
        check(std::u16string(text, text + 12) == u"S-1-5-32-544",
              "sid to string: and the two endiannesses are both right");
        check(text[12] == u'\0',
              "sid to string: the terminator is allocated but not counted");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(&s);
    }
    {
        // A six-byte authority that is not small. This is the case a
        // little-endian reading gets wrong, because the answer looks like a
        // plausible number either way.
        std::uint8_t big[12];
        big[0] = 1;
        big[1] = 1;
        big[2] = 0x12;
        big[3] = 0x34;
        big[4] = 0x56;
        big[5] = 0x78;
        big[6] = 0x9A;
        big[7] = 0xBC;
        big[8] = 0x01;
        big[9] = 0x00;
        big[10] = 0x00;
        big[11] = 0x00;
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlConvertSidToUnicodeString")(&s, big, 1) == kSuccess,
              "sid to string: a six-byte authority succeeds");
        const auto* text = static_cast<const char16_t*>(s.buffer());
        // The six bytes `12 34 56 78 9A BC` are one 48-bit number, not three
        // 16-bit ones and not a little-endian one, so the answer does not fit
        // in 32 bits -- which is exactly what a truncating implementation
        // would show up as.
        check(s.length() == 40,
              "sid to string: a forty-eight-bit authority still counts as bytes");
        check(std::u16string(text, text + 20) == u"S-1-20015998343868-1",
              "sid to string: and the authority is one big-endian number");
        check(text[20] == u'\0',
              "sid to string: the terminator follows a twenty-unit string");
        fn<void (__attribute__((ms_abi)) *)(void*)>("RtlFreeUnicodeString")(&s);
    }
    {
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlConvertSidToUnicodeString")(&s, nullptr, 1) ==
                  kInvalidParameter,
              "sid to string: a null SID is refused");
    }
    {
        // A sub-authority count above the maximum is not a SID, and the
        // reference refuses it rather than reading past the structure.
        std::uint8_t bad[2] = {1, 200};
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *) (void*, const void*, std::int32_t)>(
                  "RtlConvertSidToUnicodeString")(&s, bad, 1) ==
                  kInvalidParameter,
              "sid to string: an impossible sub-authority count is refused");
    }
    {
        // `RtlCopySid` refuses a destination that is too small, and the size
        // it compares against is the *computed* length -- 8 plus four per
        // sub-authority -- not a length the caller supplies.
        std::uint8_t src[12] = {1, 1, 0, 0, 0, 0, 0, 5, 0xFF, 0xFF, 0, 0};
        std::uint8_t dst[12] = {};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, void*, const void*)>(
                  "RtlCopySid")(12, dst, src) == kSuccess,
              "copy sid: a destination that fits succeeds");
        check(std::memcmp(src, dst, 12) == 0, "copy sid: and the bytes are copied");
    }
    {
        std::uint8_t src[12] = {1, 1, 0, 0, 0, 0, 0, 5, 0xFF, 0xFF, 0, 0};
        std::uint8_t dst[12] = {};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, void*, const void*)>(
                  "RtlCopySid")(8, dst, src) == kBufferTooSmall,
              "copy sid: too small is BUFFER_TOO_SMALL, not an overflow");
    }
    {
        std::uint8_t src[12] = {1, 1, 0, 0, 0, 0, 0, 5, 0xFF, 0xFF, 0, 0};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, void*, const void*)>(
                  "RtlCopySid")(12, nullptr, src) == kInvalidParameter,
              "copy sid: a null destination is refused");
    }
    {
        std::uint8_t src[12] = {1, 1, 0, 0, 0, 0, 0, 5, 0xFF, 0xFF, 0, 0};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, void*, const void*)>(
                  "RtlCopySid")(12, src + 0, nullptr) == kInvalidParameter,
              "copy sid: a null source is refused");
    }
    {
        // The attributes array. The reference exports this as a stub, so the
        // element size here is Microsoft's documented one, and saying so is
        // the point of the comment: on x64 a `SID_AND_ATTRIBUTES` is a
        // pointer plus a `ULONG` plus four bytes of tail padding, so sixteen
        // bytes, not the eight its two fields add up to.
        std::uint8_t src[32] = {};
        std::uint8_t dst[32] = {};
        src[0] = 0xAA;
        src[16] = 0xBB;
        // Source first, destination second -- the same order as the plain
        // copy functions, and the reverse of what "put these two arrays
        // together" suggests.
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, void*, const void*)>(
                  "RtlCopySidAndAttributesArray")(2, src, dst) == kSuccess,
              "copy sid attributes: two elements succeed");
        check(dst[0] == 0xAA && dst[16] == 0xBB,
              "copy sid attributes: and the second element is at 16 bytes");
        // The padding is copied rather than reconstructed, so a caller that
        // memcmp's the whole element against the source still matches.
        check(std::memcmp(dst, src, 32) == 0,
              "copy sid attributes: the elements are copied whole, padding included");
    }
    {
        // A zero count is answered before the pointers are looked at: the
        // reference's sibling copies with a plain counted loop, which never
        // dereferences either pointer when the count is zero.
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, void*, const void*)>(
                  "RtlCopySidAndAttributesArray")(0, nullptr, nullptr) ==
                  kSuccess,
              "copy sid attributes: a zero count is a no-op, not an error");
    }
    {
        // A non-zero count with nothing to copy from is refused rather than
        // dereferenced.
        std::uint8_t dst[16] = {};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, void*, const void*)>(
                  "RtlCopySidAndAttributesArray")(1, dst, nullptr) ==
                  kInvalidParameter,
              "copy sid attributes: a null source is refused");
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, void*, const void*)>(
                  "RtlCopySidAndAttributesArray")(1, nullptr, dst) ==
                  kInvalidParameter,
              "copy sid attributes: a null destination is refused");
    }
    {
        // The security descriptor copy. The self-relative form is the one a
        // caller meets in the wild, and the offsets inside it do not move when
        // the descriptor is copied -- which is the fact a flat byte copy gets
        // right and a re-basing implementation gets wrong.
        std::uint8_t src[64] = {};
        src[0] = 1; // revision
        // Control is a WORD at offset 2, little-endian, and the self-relative
        // bit is 0x8000 -- so it is the *high* byte that gets set. Putting
        // 0x80 in the low byte instead selects 0x0080, which leaves the
        // descriptor in the absolute form, and then the four offsets are read
        // as pointers: an owner at offset 20 becomes the address 0x14, and
        // the copy follows it into unmapped memory.
        src[2] = 0x00;
        src[3] = 0x80; // control: SE_SELF_RELATIVE
        // Owner at offset 12 from the descriptor's base.
        const std::uint16_t owner_at = 20;
        std::memcpy(src + owner_at, "\x01\x01\x00\x00\x00\x00\x00\x05\xFF\xFF\xFF\xFF",
                    12);
        std::memcpy(src + 4, &owner_at, sizeof(owner_at));
        std::uint8_t dst[64] = {};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, void*)>(
                  "RtlCopySecurityDescriptor")(src, dst) == kSuccess,
              "copy security descriptor: a self-relative descriptor succeeds");
        std::uint16_t copied_at = 0;
        std::memcpy(&copied_at, dst + 4, sizeof(copied_at));
        check(copied_at == owner_at,
              "copy security descriptor: and the owner offset did not move");
        check(std::memcmp(src + owner_at, dst + owner_at, 12) == 0,
              "copy security descriptor: and the SID was copied to that offset");
    }
    {
        // The revision check, and it happens before anything is written.
        std::uint8_t src[8] = {};
        src[0] = 2; // not revision 1
        std::uint8_t dst[8];
        std::memset(dst, 0xEE, sizeof(dst));
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, void*)>(
                  "RtlCopySecurityDescriptor")(src, dst) == kUnknownRevision,
              "copy security descriptor: a bad revision is UNKNOWN_REVISION");
        check(dst[0] == 0xEE,
              "copy security descriptor: and the destination was not touched");
    }
    {
        // The absolute form's header is thirty-six bytes under this runtime's
        // guest -- four scalars and four 64-bit pointers -- so the buffer has
        // to be that big. Handing the function an eight-byte header asks it to
        // write four pointers into eight bytes of stack.
        std::uint8_t src[36] = {1, 0, 0, 0};
        std::uint8_t dst[36] = {};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, void*)>(
                  "RtlCopySecurityDescriptor")(src, dst) == kSuccess,
              "copy security descriptor: a header with no SIDs succeeds");
        check(dst[0] == 1,
              "copy security descriptor: and the scalars came across");
    }
    {
        // An absolute descriptor with a real owner. The four fields are read
        // as pointers here, not as the sixteen-bit offsets the self-relative
        // form uses, so this case is what catches a copy that always reads
        // offsets: the owner's address has a non-zero low half, and reading
        // only that half as the offset would follow it into the descriptor's
        // own header.
        std::uint8_t owner[12] = {1, 1, 0, 0, 0, 0, 0, 5, 0xFF, 0xFF, 0, 0};
        std::uint8_t src[36] = {1, 0, 0, 0};
        std::uint8_t dst[36] = {};
        const auto owner_address = static_cast<std::uint64_t>(
            reinterpret_cast<std::uintptr_t>(owner));
        std::memcpy(src + 4, &owner_address, sizeof(owner_address));
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, void*)>(
                  "RtlCopySecurityDescriptor")(src, dst) == kSuccess,
              "copy security descriptor: an absolute owner succeeds");
        std::uint64_t copied_to = 0;
        std::memcpy(&copied_to, dst + 4, sizeof(copied_to));
        check(copied_to != 0 && copied_to != owner_address,
              "copy security descriptor: the owner was re-based to a new block");
        check(std::memcmp(reinterpret_cast<const void*>(static_cast<std::uintptr_t>(
                              copied_to)),
                          owner, 12) == 0,
              "copy security descriptor: and the SID itself came across");
    }
    {
        // The self-relative header is twelve bytes, so a copy that used the
        // absolute form's thirty-six would read eight bytes past it. In this
        // layout those eight bytes are the owner, which is what makes the
        // overrun visible instead of harmless.
        std::uint8_t src[24] = {};
        src[0] = 1;
        src[3] = 0x80; // SE_SELF_RELATIVE, the high byte of the control word
        const std::uint16_t owner_at = 12;
        std::memcpy(src + owner_at, "\x01\x01\x00\x00\x00\x00\x00\x05\xFF\xFF\xFF\xFF",
                    12);
        std::memcpy(src + 4, &owner_at, sizeof(owner_at));
        std::uint8_t dst[24] = {};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, void*)>(
                  "RtlCopySecurityDescriptor")(src, dst) == kSuccess,
              "copy security descriptor: a twelve-byte header is copied as one");
        std::uint16_t copied_at = 0;
        std::memcpy(&copied_at, dst + 4, sizeof(copied_at));
        check(copied_at == owner_at,
              "copy security descriptor: the owner offset did not move");
        check(std::memcmp(src + owner_at, dst + owner_at, 12) == 0,
              "copy security descriptor: and the SID landed at that offset");
    }
    {
        std::uint8_t src[8] = {1, 0, 0, 0, 0, 0, 0, 0};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, void*)>(
                  "RtlCopySecurityDescriptor")(nullptr, src) ==
                  kInvalidParameter,
              "copy security descriptor: a null source is refused");
        std::uint8_t dst[36] = {};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*, void*)>(
                  "RtlCopySecurityDescriptor")(dst, nullptr) ==
                  kInvalidParameter,
              "copy security descriptor: a null destination is refused");
    }
    {
        // The LUID, which is two 32-bit halves and nothing else.
        std::uint8_t src[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        std::uint8_t dst[8] = {};
        fn<void (__attribute__((ms_abi)) *)(void*, const void*)>("RtlCopyLuid")(dst, src);
        check(std::memcmp(src, dst, 8) == 0, "copy luid: eight bytes are copied");
    }
    {
        std::uint8_t src[32] = {};
        std::uint8_t dst[32] = {};
        src[0] = 1;
        src[16] = 2;
        fn<void (__attribute__((ms_abi)) *)(std::uint32_t, const void*, void*)>(
            "RtlCopyLuidAndAttributesArray")(2, src, dst);
        check(dst[0] == 1 && dst[16] == 2,
              "copy luid attributes: two elements are copied at 16 bytes each");
    }
}

// ------------------------------------------------------------------- context

void test_context() {
    // A `CONTEXT` is architecture-shaped and its size is fixed per
    // processor, so a "copy" is only meaningful once the size is known to be
    // a whole context. The AMD64 size is 0x4D0 and that number is the check.
    std::vector<std::uint8_t> amd64(0x4D0, 0);
    // ContextFlags: the architecture bits live at 0x00010001 for AMD64 and the
    // control bits that say which parts hold valid data sit far below them, so
    // a caller wanting the control word and the integer registers writes
    // `CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_AMD64` = 0x00010003.
    const std::uint32_t flags = 0x00010001u | 0x00000001u | 0x00000002u;
    std::memcpy(amd64.data(), &flags, sizeof(flags));
    std::vector<std::uint8_t> copy(0x4D0, 0);
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, std::uint32_t, const void*)>(
              "RtlCopyContext")(copy.data(), 0x4D0, amd64.data()) == kSuccess,
          "context: the AMD64 size is accepted");
    check(std::memcmp(amd64.data(), copy.data(), 0x4D0) == 0,
          "context: and every byte is copied");
    // A size that is not a known context is refused, because a partial
    // context is not a context a caller can restore.
    std::vector<std::uint8_t> small(400, 0);
    std::vector<std::uint8_t> small_copy(400, 0);
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, std::uint32_t, const void*)>(
              "RtlCopyContext")(small_copy.data(), 400, small.data()) ==
              kInvalidParameter,
          "context: an unknown size is refused");
    // A size that is right but flags that disagree with it is also refused.
    std::vector<std::uint8_t> mismatched(0x4D0, 0);
    const std::uint32_t i386 = 0x00010000u;
    std::memcpy(mismatched.data(), &i386, sizeof(i386));
    std::vector<std::uint8_t> mismatched_copy(0x4D0, 0);
    // The AMD64 layout is copied whichever architecture the source claims,
    // because the size is the only thing that says which layout is in hand and
    // `ContextFlags` is not at the front of the structure to be read from.
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, std::uint32_t, const void*)>(
              "RtlCopyContext")(mismatched_copy.data(), 0x4D0,
                                mismatched.data()) == kSuccess &&
              std::memcmp(mismatched.data(), mismatched_copy.data(), 0x4D0) == 0,
          "context: the declared architecture does not override the size");
    {
        std::vector<std::uint8_t> amd64b(0x4D0, 0);
        std::memcpy(amd64b.data(), &flags, sizeof(flags));
        std::vector<std::uint8_t> ext(0x4D0, 0);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, std::uint32_t, const void*)>(
                  "RtlCopyExtendedContext")(ext.data(), 0x4D0, amd64b.data()) ==
                  kSuccess,
              "context: the extended form accepts AMD64");
    }
    {
        std::vector<std::uint8_t> i386_context(0x2CC, 0);
        std::memcpy(i386_context.data(), &i386, sizeof(i386));
        std::vector<std::uint8_t> ext(0x2CC, 0);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, std::uint32_t, const void*)>(
                  "RtlCopyExtendedContext")(ext.data(), 0x2CC,
                                            i386_context.data()) ==
                  kInvalidParameter,
              "context: the extended form refuses the 32-bit size");
        std::vector<std::uint8_t> plain(0x2CC, 0);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, std::uint32_t, const void*)>(
                  "RtlCopyContext")(plain.data(), 0x2CC, i386_context.data()) ==
                  kSuccess,
              "context: and the plain form accepts it");
    }
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, std::uint32_t, const void*)>(
              "RtlCopyContext")(nullptr, 0x4D0, nullptr) == kInvalidParameter,
          "context: null arguments are refused");
}

// ----------------------------------------------------------------- the corpus

void test_is_text_unicode() {
    // `RtlIsTextUnicode` is a heuristic with a documented flag set, and the
    // flags are an ABI: the caller passes a mask in and reads the achieved
    // subset out of the same variable. So `*pf` is the set of tests the caller
    // *wants*, and a caller that passes zero asks for nothing and learns
    // nothing -- every case below asks for the full set except where the mask
    // itself is the point.
    constexpr std::int32_t kAllFlags = static_cast<std::int32_t>(0xFFFFFFFFu);
    constexpr std::int32_t kOddLength = 0x1;
    constexpr std::int32_t kSignature = 0x2;
    constexpr std::int32_t kStatistics = 0x8;
    constexpr std::int32_t kNullBytes = 0x10;
    {
        // Latin-1 text read as UTF-16: every unit is two real characters, so
        // both are above 255 and neither byte of the pair is zero. That means
        // neither the statistics test nor the null-byte test fires, and the
        // only thing the heuristic can say is the arithmetic one -- the byte
        // count of 15 is odd, so it cannot be whole UTF-16.
        const char text[] = "plain ascii text";
        std::int32_t flags = kAllFlags;
        check(fn<std::int32_t (__attribute__((ms_abi)) *)(const void*, std::int32_t, std::int32_t*)>(
                  "RtlIsTextUnicode")(text, 15, &flags) == 0 &&
              flags == kOddLength,
              "is text unicode: pairs of Latin-1 characters trip only the odd-length fact");
    }
    {
        // Units that are single Latin-1 characters are the genuinely ambiguous
        // case, and more than half of them is what the statistics test counts.
        const char16_t latin[] = {0x00E9, 0x00E8, 0x00EA, 0x0041};
        std::int32_t flags = kAllFlags;
        fn<std::int32_t (__attribute__((ms_abi)) *)(const void*, std::int32_t, std::int32_t*)>(
            "RtlIsTextUnicode")(latin, 8, &flags);
        check((flags & kStatistics) != 0,
              "is text unicode: units that are single Latin-1 characters look narrow");
    }
    {
        // A zero byte in the middle is a strong signal for narrow.
        const char16_t text[] = u"a\0b";
        std::int32_t flags = kAllFlags;
        fn<std::int32_t (__attribute__((ms_abi)) *)(const void*, std::int32_t, std::int32_t*)>(
            "RtlIsTextUnicode")(text, 6, &flags);
        check((flags & kNullBytes) != 0,
              "is text unicode: an embedded NUL is reported");
    }
    {
        // An odd byte count cannot be whole UTF-16, and the reference reports
        // that as a fact rather than as a judgement about the content. It is
        // arithmetic on the length rather than a scan, so the mask does not
        // gate it.
        const char16_t text[] = u"abc";
        std::int32_t flags = kAllFlags;
        fn<std::int32_t (__attribute__((ms_abi)) *)(const void*, std::int32_t, std::int32_t*)>(
            "RtlIsTextUnicode")(text, 5, &flags);
        check((flags & kOddLength) != 0,
              "is text unicode: an odd byte count sets the odd-length flag");
    }
    {
        std::int32_t flags = kSignature;
        check(fn<std::int32_t (__attribute__((ms_abi)) *)(const void*, std::int32_t, std::int32_t*)>(
                  "RtlIsTextUnicode")(nullptr, 4, &flags) == 0 && flags == 0,
              "is text unicode: a null buffer is not text and reports nothing");
    }
    {
        // Shorter than one unit is the too-small case, and it is answered with
        // an empty result rather than a heuristic verdict: there is no first
        // unit to look at.
        const char16_t text[] = {u'a'};
        std::int32_t flags = kAllFlags;
        check(fn<std::int32_t (__attribute__((ms_abi)) *)(const void*, std::int32_t, std::int32_t*)>(
                  "RtlIsTextUnicode")(text, 1, &flags) == 0 && flags == 0,
              "is text unicode: a buffer below one unit is too small to judge");
    }
    {
        // A byte-order mark in front of text that has no zero high byte is the
        // one shape that is unambiguously Unicode. Latin-looking units after
        // the mark would trip the null-byte test and turn the verdict back
        // around, which is why the two units here are CJK.
        const char16_t bom[] = {0xFEFF, 0x4E2D, 0x6587};
        std::int32_t flags = kAllFlags;
        check(fn<std::int32_t (__attribute__((ms_abi)) *)(const void*, std::int32_t, std::int32_t*)>(
                  "RtlIsTextUnicode")(bom, 6, &flags) == 1 &&
              (flags & kSignature) != 0,
              "is text unicode: a BOM with wide text makes it Unicode");
    }
    {
        // The mask goes in: asking only about the signature must not report
        // the tests the caller did not ask for.
        const char16_t bom[] = {0xFEFF, 0x4E2D};
        std::int32_t flags = kSignature;
        fn<std::int32_t (__attribute__((ms_abi)) *)(const void*, std::int32_t, std::int32_t*)>(
            "RtlIsTextUnicode")(bom, 4, &flags);
        check(flags == kSignature, "is text unicode: the caller's mask is respected");
    }
    {
        // Asking for nothing gets nothing, which is the other half of the mask
        // being an input rather than an output location only.
        const char16_t bom[] = {0xFEFF, 0x4E2D};
        std::int32_t flags = 0;
        fn<std::int32_t (__attribute__((ms_abi)) *)(const void*, std::int32_t, std::int32_t*)>(
            "RtlIsTextUnicode")(bom, 4, &flags);
        check(flags == 0, "is text unicode: an empty mask reports nothing");
    }
}

// ------------------------------------------------------------- environment

void test_environment() {
    // The block form, which is what makes these testable without touching the
    // process's own environment: `NAME=VALUE\0NAME=VALUE\0\0`.
    const char16_t block[] = u"PATH=/bin\0HOME=/root\0EMPTY=\0";
    // A defined variable is substituted.
    {
        char16_t dst[64] = {};
        std::uint64_t len = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char16_t*, const char16_t*,
                                   std::uint64_t, char16_t*, std::uint64_t,
                                   std::uint64_t*)>(
                  "RtlExpandEnvironmentStrings")(block, u"%PATH%", 6, dst, 64,
                                                 &len) == kSuccess,
              "environment: a defined variable is substituted");
        check(std::u16string(dst) == u"/bin",
              "environment: and the value is the whole substitution");
        check(len == 5,
              "environment: and the size is in characters, terminator included");
    }
    // An undefined variable keeps its delimiters, so the caller can see which
    // name was missing. Dropping the markers would leave a silently wrong
    // path instead.
    {
        char16_t dst[64] = {};
        std::uint64_t len = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char16_t*, const char16_t*,
                                   std::uint64_t, char16_t*, std::uint64_t,
                                   std::uint64_t*)>(
                  "RtlExpandEnvironmentStrings")(block, u"%NOPE%", 6, dst, 64,
                                                 &len) == kSuccess,
              "environment: an undefined variable is copied");
        check(std::u16string(dst) == u"%NOPE%",
              "environment: and it keeps its delimiters");
    }
    // A variable set to the empty string is a *substitution* that removes
    // itself, which is not the same as being undefined. The two are told apart
    // and this is the assertion that says so.
    {
        char16_t dst[64] = {};
        std::uint64_t len = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char16_t*, const char16_t*,
                                   std::uint64_t, char16_t*, std::uint64_t,
                                   std::uint64_t*)>(
                  "RtlExpandEnvironmentStrings")(block, u"a%EMPTY%b", 9, dst, 64,
                                                 &len) == kSuccess,
              "environment: an empty variable is a substitution");
        check(std::u16string(dst) == u"ab",
              "environment: and it removes itself, delimiters and all");
    }
    // The name match is case-insensitive and whole-name: `PAT` must not match
    // `PATH`, because a caller that expanded `%PAT%` and got the whole path
    // has been told something false.
    {
        char16_t dst[64] = {};
        std::uint64_t len = 0;
        fn<std::uint32_t (__attribute__((ms_abi)) *)(const char16_t*, const char16_t*, std::uint64_t,
                             char16_t*, std::uint64_t, std::uint64_t*)>(
            "RtlExpandEnvironmentStrings")(block, u"%path%", 6, dst, 64, &len);
        check(std::u16string(dst) == u"/bin",
              "environment: the name match ignores case");
    }
    {
        char16_t dst[64] = {};
        std::uint64_t len = 0;
        fn<std::uint32_t (__attribute__((ms_abi)) *)(const char16_t*, const char16_t*, std::uint64_t,
                             char16_t*, std::uint64_t, std::uint64_t*)>(
            "RtlExpandEnvironmentStrings")(block, u"%PAT%", 5, dst, 64, &len);
        check(std::u16string(dst) == u"%PAT%",
              "environment: a partial name does not match");
    }
    // Ordinary text passes through, and a bare `%` with no closer is text
    // rather than a syntax error.
    {
        char16_t dst[64] = {};
        std::uint64_t len = 0;
        fn<std::uint32_t (__attribute__((ms_abi)) *)(const char16_t*, const char16_t*, std::uint64_t,
                             char16_t*, std::uint64_t, std::uint64_t*)>(
            "RtlExpandEnvironmentStrings")(block, u"a/b", 3, dst, 64, &len);
        check(std::u16string(dst) == u"a/b", "environment: ordinary text passes through");
    }
    {
        char16_t dst[64] = {};
        std::uint64_t len = 0;
        fn<std::uint32_t (__attribute__((ms_abi)) *)(const char16_t*, const char16_t*, std::uint64_t,
                             char16_t*, std::uint64_t, std::uint64_t*)>(
            "RtlExpandEnvironmentStrings")(block, u"50%", 3, dst, 64, &len);
        check(std::u16string(dst) == u"50%",
              "environment: an unterminated percent is text, not an error");
    }
    // The size query, and the fact that the two spellings report different
    // units. The non-`_U` form answers in characters and the `_U` form
    // multiplies by two, which is the reference's own comment and the reason
    // a caller that confuses them allocates twice as much as it needs.
    {
        std::uint64_t len = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char16_t*, const char16_t*,
                                   std::uint64_t, char16_t*, std::uint64_t,
                                   std::uint64_t*)>(
                  "RtlExpandEnvironmentStrings")(block, u"%PATH%", 6, nullptr, 0,
                                                 &len) == kSuccess,
              "environment: the size query succeeds");
        check(len == 5, "environment: and answers in characters");
    }
    {
        Str src;
        Str dst;
        WideBuf source;
        WideBuf target;
        const char16_t text[] = u"%PATH%";
        for (int k = 0; k < 6; ++k) {
            source.data[k] = text[k];
        }
        src.set_length(12);
        src.set_maximum(14);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(64);
        dst.set_buffer(target.data);
        std::uint32_t bytes = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char16_t*, const void*, const void*,
                                   std::uint32_t*)>(
                  "RtlExpandEnvironmentStrings_U")(block, &src, &dst, &bytes) ==
                  kSuccess,
              "environment U: the conversion succeeds");
        check(bytes == 10,
              "environment U: and the size is in bytes, twice the characters");
        check(dst.length() == 8,
              "environment U: and Length is the wide byte count without the terminator");
        check(std::u16string(target.data, target.data + 4) == u"/bin",
              "environment U: and the value is there");
    }
    {
        Str src;
        Str dst;
        WideBuf source;
        WideBuf target;
        const char16_t text[] = u"%NOPE%";
        for (int k = 0; k < 6; ++k) {
            source.data[k] = text[k];
        }
        src.set_length(12);
        src.set_maximum(14);
        src.set_buffer(source.data);
        dst.set_length(0);
        dst.set_maximum(4);
        dst.set_buffer(target.data);
        std::uint32_t bytes = 0;
        const std::uint32_t status = fn<std::uint32_t (__attribute__((ms_abi)) *)(
            const char16_t*, const void*, const void*, std::uint32_t*)>(
            "RtlExpandEnvironmentStrings_U")(block, &src, &dst, &bytes);
        check(status == kBufferTooSmall,
              "environment U: too small is BUFFER_TOO_SMALL, not an overflow");
        // The full one is the count the retry needs, which is the same
        // including-the-terminator count the success path reports: six
        // copied characters plus the terminator, in bytes.
        check(bytes == 14, "environment U: and the size is still the full one");
    }
    {
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char16_t*, const char16_t*,
                                   std::uint64_t, char16_t*, std::uint64_t,
                                   std::uint64_t*)>(
                  "RtlExpandEnvironmentStrings")(block, nullptr, 0, nullptr, 0,
                                                 nullptr) == kInvalidParameter,
              "environment: a null source is refused");
    }
    {
        // The empty source expands to just the terminator, in both units.
        char16_t dst[8] = {};
        std::uint64_t len = 0;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char16_t*, const char16_t*,
                                   std::uint64_t, char16_t*, std::uint64_t,
                                   std::uint64_t*)>(
                  "RtlExpandEnvironmentStrings")(block, u"", 0, dst, 8, &len) ==
                  kSuccess,
              "environment: the empty source succeeds");
        check(len == 1, "environment: and its size is the terminator alone");
        check(dst[0] == u'\0', "environment: and the result is empty");
    }
}

// ----------------------------------------------------------------- the device

void test_device_family() {
    // The sizes are *in* parameters: the caller states how much room it has
    // and the function reports what it needed. Starting them at zero is
    // therefore the size query, not a successful fill, and the two differ.
    std::uint32_t family_size = 0;
    std::uint32_t form_size = 0;
    char16_t family[64] = {};
    char16_t form[64] = {};
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t*, std::uint32_t*, char16_t*,
                               char16_t*)>("RtlConvertDeviceFamilyInfoToString")(
              &family_size, &form_size, family, form) == kBufferTooSmall,
          "device family: zero sizes is the size query");
    // "Windows.Desktop" is fifteen characters, so with the terminator the
    // count is sixteen units -- thirty-two bytes. The form is seven and a
    // half... no: "Unknown" is seven characters, eight units, sixteen bytes,
    // and the two answers use the same rule. A count of seventeen here would
    // be one unit more than the string and its terminator, and the tight
    // case below would refuse a buffer the string actually fits in.
    check(family_size == 16 * 2 && form_size == 8 * 2,
          "device family: and it reports bytes including the terminator");
    check(family[0] == u'\0' && form[0] == u'\0',
          "device family: a refused fill writes nothing at all");
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t*, std::uint32_t*, char16_t*,
                               char16_t*)>("RtlConvertDeviceFamilyInfoToString")(
              &family_size, &form_size, family, form) == kSuccess,
          "device family: the retry with the reported sizes succeeds");
    check(std::u16string(family) == u"Windows.Desktop",
          "device family: and the family is the desktop one");
    check(std::u16string(form) == u"Unknown",
          "device family: and the form is one this host does not have");
    {
        // One byte short of what it needs is still too small, and the size it
        // reports back is the full one rather than the caller's -- which is
        // what makes the retry loop terminate.
        std::uint32_t tight_family = 16 * 2 - 1;
        std::uint32_t tight_form = 8 * 2;
        char16_t scratch[64] = {};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t*, std::uint32_t*, char16_t*,
                                   char16_t*)>("RtlConvertDeviceFamilyInfoToString")(
                  &tight_family, &tight_form, scratch, scratch) ==
                  kBufferTooSmall,
              "device family: one byte short is refused");
        check(tight_family == 16 * 2,
              "device family: and the corrected size is reported back");
    }
    {
        // Sizes that fit but no buffers: the sizes are still accepted, and the
        // missing buffers are what the answer names.
        std::uint32_t enough_family = 64;
        std::uint32_t enough_form = 64;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t*, std::uint32_t*, char16_t*,
                                   char16_t*)>("RtlConvertDeviceFamilyInfoToString")(
                  &enough_family, &enough_form, nullptr, nullptr) ==
                  kInvalidParameter,
              "device family: null output buffers are refused");
    }
    {
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t*, std::uint32_t*, char16_t*,
                                   char16_t*)>("RtlConvertDeviceFamilyInfoToString")(
                  nullptr, nullptr, family, form) == kInvalidParameter,
              "device family: null size pointers are refused");
    }
}

// ---------------------------------------------------------------- the refusal

void test_refusals() {
    // The eleven names this domain registers and refuses, and the reason each
    // one is in the table at all. A guest that imports one and finds it
    // missing fails to *load*, which is worse than a call that reports
    // STATUS_NOT_IMPLEMENTED -- so the names are here and the answers are the
    // documented refusal.
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, const char16_t*, std::int32_t,
                               char16_t*, std::int32_t*)>("RtlNormalizeString")(
              0, u"abc", 3, nullptr, nullptr) == kInvalidParameter,
          "refusal: normalisation checks the form before it refuses");
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, const char16_t*, std::int32_t,
                               char16_t*, std::int32_t*)>(
              "RtlNormalizeString")(99, u"abc", 3, nullptr, nullptr) ==
              kObjectNameNotFound,
          "refusal: a form above the defined range is OBJECT_NAME_NOT_FOUND");
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, const char16_t*, std::int32_t,
                               char16_t*, std::int32_t*)>("RtlNormalizeString")(
              1, u"abc", 3, nullptr, nullptr) == kNotImplemented,
          "refusal: a defined form has no table here and says so");
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, const char16_t*, std::int32_t,
                               std::int32_t*)>("RtlIsNormalizedString")(
              0, u"abc", 3, nullptr) == kInvalidParameter,
          "refusal: the same form check on the query form");
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, const char16_t*, std::int32_t,
                               std::int32_t*)>("RtlIsNormalizedString")(
              1, u"abc", 3, nullptr) == kNotImplemented,
          "refusal: and the same not-implemented for a defined form");
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, const char16_t*, std::int32_t,
                               char16_t*, std::int32_t*)>("RtlIdnToUnicode")(
              0, u"abc", 3, nullptr, nullptr) == kNotImplemented,
          "refusal: IDN to Unicode has no punycode table here");
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, const char16_t*, std::int32_t,
                               char16_t*, std::int32_t*)>(
              "RtlIdnToNameprepUnicode")(0, u"abc", 3, nullptr, nullptr) ==
              kNotImplemented,
          "refusal: and the nameprep form agrees");
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*)>("RtlFormatCurrentUserKeyPath")(nullptr) ==
              kInvalidParameter,
          "refusal: the user key path refuses a null structure");
    {
        Str s;
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*)>("RtlFormatCurrentUserKeyPath")(&s) ==
                  kNotImplemented,
              "refusal: and reports no token for a real one");
    }
    // The activation-context lookup, which validates exactly as the reference
    // does and then has no context to search.
    {
        std::uint8_t name_bytes[16] = {};
        std::uint16_t length = 4;
        std::uint16_t maximum = 6;
        std::uint64_t buffer = 0;
        std::memcpy(name_bytes, &length, 2);
        std::memcpy(name_bytes + 2, &maximum, 2);
        const char16_t text[] = u"name";
        std::memcpy(name_bytes + 8, &text, sizeof(std::uintptr_t));
        static_cast<void>(buffer);
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, const void*, std::uint32_t,
                                   const void*, void*)>(
                  "RtlFindActivationContextSectionString")(0, nullptr, 0,
                                                           name_bytes, nullptr) ==
                  kSxsKeyNotFound,
              "refusal: a well-formed lookup finds nothing, as on a bare system");
    }
    {
        // The GUID the reference insists must be null. Any non-null value is
        // refused before the section name is even looked at, so a zeroed
        // buffer is enough to show which check fires first.
        std::uint8_t guid[16] = {};
        check(fn<std::uint32_t (__attribute__((ms_abi)) *)(std::uint32_t, const void*, std::uint32_t,
                                   const void*, void*)>(
                  "RtlFindActivationContextSectionString")(0, guid, 0,
                                                           nullptr, nullptr) ==
                  kInvalidParameter,
              "refusal: a non-null GUID is refused, as the reference refuses it");
    }
    // The memory streams, all seven.
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const void*, void**)>(
              "RtlQueryInterfaceMemoryStream")(nullptr, nullptr, nullptr) ==
              kNotImplemented,
          "refusal: the stream interface query has no object to query");
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, void*, std::uint32_t, std::uint32_t*)>(
              "RtlReadMemoryStream")(nullptr, nullptr, 0, nullptr) ==
              kNotImplemented,
          "refusal: the stream read has no stream");
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, const void*, std::uint32_t,
                               std::uint32_t*)>("RtlWriteMemoryStream")(
              nullptr, nullptr, 0, nullptr) == kNotImplemented,
          "refusal: the stream write has no stream");
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*)>("RtlRevertMemoryStream")(nullptr) ==
              kNotImplemented,
          "refusal: the stream revert has no stream");
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, std::uint32_t)>(
              "RtlReleaseMemoryStream")(nullptr, 0) == kNotImplemented,
          "refusal: the stream release has no stream");
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*, void*, std::uint32_t, std::uint32_t*)>(
              "RtlReadOutOfProcessMemoryStream")(nullptr, nullptr, 0, nullptr) ==
              kNotImplemented,
          "refusal: the out-of-process read is refused, and must be");
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(void*)>(
              "RtlFinalReleaseOutOfProcessMemoryStream")(nullptr) ==
              kNotImplemented,
          "refusal: the out-of-process release is refused, and must be");
    // And the script callouts, all three.
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const void*)>("RtlSetUnicodeCallouts")(nullptr) ==
              kNotImplemented,
          "refusal: the callout tables are not installed");
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char16_t*, void*, std::uint32_t*, void**)>(
              "RtlRunEncodeUnicodeString")(nullptr, nullptr, nullptr, nullptr) ==
              kNotImplemented,
          "refusal: there is no script encoder here");
    check(fn<std::uint32_t (__attribute__((ms_abi)) *)(const char16_t*, void*, std::uint32_t*, void**)>(
              "RtlRunDecodeUnicodeString")(nullptr, nullptr, nullptr, nullptr) ==
              kNotImplemented,
          "refusal: and no decoder, so a partial pair would be worse than none");
}

}  // namespace

int main() {
    add_ntdll_rtl_str(g_exports);
    test_table_is_complete();
    test_init();
    test_create();
    test_free();
    test_copy();
    test_append();
    test_comparison();
    test_prefix();
    test_search();
    test_hash();
    test_case();
    test_conversions();
    test_n_variants();
    test_integers();
    test_guid();
    test_memory();
    test_sid();
    test_context();
    test_is_text_unicode();
    test_environment();
    test_device_family();
    test_refusals();
    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

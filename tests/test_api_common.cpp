// The shared shapes, tested on their own.
//
// `api_common.h` exists so that no family re-implements the error list, the
// Narrow/Wide bridge, the buffer arithmetic or the structure layouts. A
// shared helper that is wrong is worse than a copy that is wrong, because
// every family inherits the mistake and none of them has a test that
// attributes it -- so the helpers are checked here, once, against what the
// Windows spellings say rather than against what the families happen to
// need.
//
// The conversions are the ones with a right answer outside this project:
// UTF-8 round trips through UTF-16 for the whole BMP plus the astral
// planes, the layout constants are the Windows ABI's own offsets, and the
// buffer arithmetic is the "include the terminator" rule that a caller
// which gets wrong gets wrong exactly once.

#include "occ/runtime/api_common.h"

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

void check_eq_u64(std::uint64_t got, std::uint64_t want, const char* what) {
    ++checks;
    if (got != want) {
        ++failures;
        std::fprintf(stderr, "FAIL %s: got %llu want %llu\n", what,
                     static_cast<unsigned long long>(got),
                     static_cast<unsigned long long>(want));
    }
}

void check_eq_i32(std::int32_t got, std::int32_t want, const char* what) {
    ++checks;
    if (got != want) {
        ++failures;
        std::fprintf(stderr, "FAIL %s: got %d want %d\n", what, got, want);
    }
}

// ----------------------------------------------------------------- errors

void test_error_codes() {
    // The values a guest branches on. Each of these is a number a caller
    // compares against, so a wrong one silently reroutes a program.
    check_eq_u64(kErrorSuccess, 0, "error: success is zero");
    check_eq_u64(kErrorFileNotFound, 2, "error: file not found is 2");
    check_eq_u64(kErrorPathNotFound, 3, "error: path not found is 3");
    check_eq_u64(kErrorAccessDenied, 5, "error: access denied is 5");
    check_eq_u64(kErrorInvalidHandle, 6, "error: invalid handle is 6");
    check_eq_u64(kErrorNotEnoughMemory, 8, "error: out of memory is 8");
    check_eq_u64(kErrorNoMoreFiles, 18, "error: no more files is 18");
    check_eq_u64(kErrorNotSupported, 50, "error: not supported is 50");
    check_eq_u64(kErrorInvalidParameter, 87, "error: invalid parameter is 87");
    check_eq_u64(kErrorInsufficientBuffer, 122,
                 "error: insufficient buffer is 122");
    check_eq_u64(kErrorDirectoryNotEmpty, 145,
                 "error: directory not empty is 145");
    check_eq_u64(kErrorAlreadyExists, 183, "error: already exists is 183");
    // This one is the value a directory enumeration stops on, and it is the
    // one this project got wrong once: 381 is `ERROR_PRINTER_NOT_READY` or
    // similar from a different table, and a loop written against it never
    // terminates.
    check_eq_u64(kErrorNoMoreItems, 259, "error: no more items is 259");
    check_eq_u64(kErrorNotFound, 1168, "error: not found is 1168");
}

void test_hresults() {
    // HRESULT's encoding is what the constants are for. A caller reading a
    // failed `HRESULT` checks the sign bit, so the boundary matters: `S_OK`
    // and `S_FALSE` are both success, and everything with the high bit set
    // is a failure.
    check(!failed(kSOk), "hresult: S_OK is not a failure");
    check(!failed(kSFalse), "hresult: S_FALSE is not a failure");
    check(failed(kEFail), "hresult: E_FAIL is a failure");
    check(failed(kEInvalidArg), "hresult: E_INVALIDARG is a failure");

    // The wire values, since a caller that marshals these has to agree with
    // the encoding rather than with this file's spelling of it.
    check_eq_u64(static_cast<std::uint64_t>(static_cast<std::uint32_t>(kEFail)),
                 0x80004005ull, "hresult: E_FAIL is 0x80004005");
    check_eq_u64(
        static_cast<std::uint64_t>(static_cast<std::uint32_t>(kEInvalidArg)),
        0x80070057ull, "hresult: E_INVALIDARG is 0x80070057");
    check_eq_u64(static_cast<std::uint64_t>(static_cast<std::uint32_t>(kEAbi)),
                 0x80000001ull, "hresult: E_ABI is 0x80000001");
}

// -------------------------------------------------------------- the bridge

void test_narrow_in() {
    std::u16string wide;
    const AnsiResult ok = narrow_in("hello", wide);
    check(ok.converted, "bridge: plain ASCII converts");
    check_eq_u64(wide.size(), 5, "bridge: ASCII has one unit per byte");
    check(wide == u"hello", "bridge: and it is the same text");

    // The cases that make this a conversion rather than a byte copy: a
    // character outside ASCII is two UTF-16 units, and one above the BMP
    // is a surrogate pair.
    wide.clear();
    check(narrow_in("\xc3\xa9", wide).converted, "bridge: U+00E9 converts");
    check_eq_u64(wide.size(), 1, "bridge: U+00E9 is one UTF-16 unit");
    check(wide == u"\u00e9", "bridge: and it is the right code point");

    wide.clear();
    check(narrow_in("\xf0\x9f\x98\x80", wide).converted,
          "bridge: an astral character converts");
    check_eq_u64(wide.size(), 2, "bridge: it is a surrogate pair");
    check(wide == u"\U0001F600", "bridge: and it is U+1F600");

    // Malformed input is refused rather than replaced. A runtime that
    // substitutes a replacement character has rewritten the program's data
    // and reports success doing it.
    wide.clear();
    check(!narrow_in("\xff\xfe", wide).converted,
          "bridge: malformed UTF-8 is refused");
    check(wide.empty(), "bridge: and the output is empty, not partial");

    const AnsiResult bad = narrow_in("\xff", wide);
    check_eq_i32(bad.status, kEInvalidArg,
                 "bridge: a refused conversion reports E_INVALIDARG");
}

void test_narrow_out() {
    std::string narrow;
    check(narrow_out(u"hello", narrow).converted, "bridge: reverse ASCII");
    check(narrow == "hello", "bridge: reverse ASCII is the same text");

    narrow.clear();
    check(narrow_out(u"\u00e9", narrow).converted, "bridge: reverse U+00E9");
    check(narrow == "\xc3\xa9", "bridge: reverse U+00E9 is two UTF-8 bytes");

    narrow.clear();
    check(narrow_out(u"\U0001F600", narrow).converted,
          "bridge: reverse astral");
    check(narrow == "\xf0\x9f\x98\x80", "bridge: reverse astral is four bytes");

    // A lone surrogate is the malformed case in UTF-16, and it is the one a
    // program that truncated a string mid-pair actually produces.
    narrow.clear();
    check(!narrow_out(u"\xd83d", narrow).converted,
          "bridge: a lone surrogate is refused");
    check(narrow.empty(), "bridge: and nothing is written");
}

void test_bridge_round_trip() {
    // The property the two directions exist for: what goes in comes out.
    // Round-tripping is what a family that marshals in and back out needs,
    // and a bridge that fails only in one direction is a bridge that loses
    // data for half of them.
    const char* cases[] = {
        "",
        "a",
        "hello, world",
        "\xc3\xa9\xc3\xa8\xc3\xaa",              // Latin-1 accents
        "\xe4\xb8\xad\xe6\x96\x87",              // CJK
        "\xf0\x9f\x98\x80\xf0\x9f\x8e\x89",      // two astral characters
    };
    for (const char* text : cases) {
        std::u16string wide;
        std::string back;
        const bool in_ok = narrow_in(text, wide).converted;
        const bool out_ok = narrow_out(wide, back).converted;
        check(in_ok && out_ok, "bridge: round trip converts both ways");
        check(std::strcmp(back.c_str(), text) == 0,
              "bridge: and the text survives the round trip");
    }
}

// -------------------------------------------------------------- the buffers

void test_buffer_arithmetic() {
    // The rule is "including the terminator", and it is the one a caller
    // gets wrong by one. A buffer of exactly the string's length is short,
    // which is the case a `>=` gets wrong and which this asserts directly.
    check_eq_u64(required_capacity(std::u16string_view(u"hello")), 6,
                 "buffer: Wide needed is length plus terminator");
    check(!fits(u"hello", 5), "buffer: length alone is too small");
    check(fits(u"hello", 6), "buffer: length plus terminator fits");
    check(fits(u"hello", 7), "buffer: and more fits");
    check(fits(std::u16string_view(), 1), "buffer: empty needs one unit");

    check_eq_u64(required_capacity(std::string_view("hello")), 6,
                 "buffer: Narrow needed is length plus terminator");
    check(!fits(std::string_view("hello"), 5),
          "buffer: Narrow length alone is too small");
    check(fits(std::string_view("hello"), 6),
          "buffer: Narrow length plus terminator fits");

    // The Narrow spelling of a Wide string is longer than one byte per
    // unit, which is why `narrow_length` exists rather than `size() + 1`.
    check_eq_u64(narrow_length(u"hello"), 6,
                 "buffer: narrow length of ASCII is length plus terminator");
    check_eq_u64(narrow_length(u"\u00e9"), 3,
                 "buffer: narrow length of U+00E9 counts UTF-8 bytes");
}

// -------------------------------------------------------------- the layouts

void test_system_time_layout() {
    // The Windows offsets. A writer that placed the year at 2 would produce
    // a year of zero and a month of the real value, and the calendar would
    // be wrong in a way that looks like a bad clock rather than a bad
    // layout.
    check_eq_u64(SystemTimeLayout::kYear, 0, "layout: year is first");
    check_eq_u64(SystemTimeLayout::kMonth, 2, "layout: month is a word on");
    check_eq_u64(SystemTimeLayout::kDayOfWeek, 4, "layout: weekday follows");
    check_eq_u64(SystemTimeLayout::kDay, 6, "layout: then the day");
    check_eq_u64(SystemTimeLayout::kHour, 8, "layout: hour next");
    check_eq_u64(SystemTimeLayout::kMinute, 10, "layout: minute next");
    check_eq_u64(SystemTimeLayout::kSecond, 12, "layout: second next");
    check_eq_u64(SystemTimeLayout::kMilliseconds, 14,
                 "layout: milliseconds last");
    check_eq_u64(SystemTimeLayout::kBytes, 16, "layout: SYSTEMTIME is 16");

    // And the same offsets through the accessors, which is the path a
    // family actually takes.
    std::uint8_t buffer[SystemTimeLayout::kBytes] = {};
    write_u16(buffer, SystemTimeLayout::kYear, 2026);
    write_u16(buffer, SystemTimeLayout::kMonth, 10);
    write_u16(buffer, SystemTimeLayout::kDayOfWeek, 3);
    write_u16(buffer, SystemTimeLayout::kDay, 7);
    write_u16(buffer, SystemTimeLayout::kHour, 20);
    write_u16(buffer, SystemTimeLayout::kMinute, 31);
    write_u16(buffer, SystemTimeLayout::kSecond, 16);
    write_u16(buffer, SystemTimeLayout::kMilliseconds, 250);
    check_eq_u64(read_u16(buffer, SystemTimeLayout::kYear), 2026,
                 "layout: year round trips");
    check_eq_u64(read_u16(buffer, SystemTimeLayout::kMonth), 10,
                 "layout: month round trips");
    check_eq_u64(read_u16(buffer, SystemTimeLayout::kMilliseconds), 250,
                 "layout: milliseconds round trips");
}

void test_endianness_is_little() {
    // Every multi-byte write above assumes the guest's byte order, and the
    // guest is x64: little-endian. On a big-endian host these helpers would
    // produce a structure a guest reads backwards, so the assertion is on
    // the order rather than on the host, which is the property being relied
    // on.
    std::uint8_t buffer[4] = {};
    write_u32(buffer, 0, 0x01020304u);
    check(buffer[0] == 0x04 && buffer[1] == 0x03 && buffer[2] == 0x02 &&
              buffer[3] == 0x01,
          "layout: a DWORD is written little-endian");

    check_eq_u64(read_u32(buffer, 0), 0x01020304u,
                 "layout: and read back the same");
}

void test_wide_fields() {
    // A 64-bit field at a non-zero offset: the OVERLAPPED's `OffsetHigh` is
    // at 24, and getting it wrong moves a file pointer by four gigabytes,
    // which is a silent corruption rather than a visible one.
    std::uint8_t buffer[OverlappedLayout::kBytes] = {};
    write_ptr(buffer, OverlappedLayout::kOffset, 0x1122334455667788ull);
    write_ptr(buffer, OverlappedLayout::kOffsetHigh, 0x99aabbccddeeff00ull);
    check_eq_u64(read_ptr(buffer, OverlappedLayout::kOffset),
                 0x1122334455667788ull, "layout: a pointer-width field writes");
    check_eq_u64(read_ptr(buffer, OverlappedLayout::kOffsetHigh),
                 0x99aabbccddeeff00ull,
                 "layout: and the next one is not overwritten by it");

    check_eq_u64(OverlappedLayout::kOffset, 16, "layout: OVERLAPPED offset");
    check_eq_u64(OverlappedLayout::kBytes, 40,
                 "layout: OVERLAPPED is 40 bytes on x64");

    // And a 32-bit field next to it, which is what a host `bool` would get
    // wrong.
    write_u32(buffer, OverlappedLayout::kInternal, 0xDEADBEEFu);
    check_eq_u64(read_u32(buffer, OverlappedLayout::kInternal), 0xDEADBEEFu,
                 "layout: a DWORD in the middle round trips");
    check_eq_u64(read_ptr(buffer, OverlappedLayout::kOffset),
                 0x1122334455667788ull,
                 "layout: and the pointer beside it is untouched");
}

void test_handle_sentinels() {
    // The two failure values a Windows program tells apart. A zero handle
    // means "none was created"; the all-ones value is a specific failure
    // that a caller may branch on. Collapsing them makes every
    // `if (handle == INVALID_HANDLE_VALUE)` in a guest test true when it
    // should be false.
    check_eq_u64(kInvalidHandleValue, 0xFFFFFFFFFFFFFFFFull,
                 "handle: INVALID_HANDLE_VALUE is all ones");
    check_eq_u64(kInvalidHandle, 0, "handle: NULL is zero");
    check(kInvalidHandleValue != kInvalidHandle,
          "handle: and the two are different answers");
}

}  // namespace

int main() {
    test_error_codes();
    test_hresults();
    test_narrow_in();
    test_narrow_out();
    test_bridge_round_trip();
    test_buffer_arithmetic();
    test_system_time_layout();
    test_endianness_is_little();
    test_wide_fields();
    test_handle_sentinels();

    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}
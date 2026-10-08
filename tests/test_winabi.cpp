// The host API layer: the parts a guest call touches before any code runs.
//
// The thunks themselves are exercised by a guest, and the full chain is
// exercised on the machine that runs the fixtures; what a unit test can pin
// down is everything those two layers trust without checking:
//
//   * that the command line the runtime builds is the one its own split
//     returns to the guest, and that both follow the Microsoft rules -- the
//     round trip is the property `__getmainargs` rests on, because a
//     program that prints its argv is printing this parse;
//   * that the text conversions are total over the encoding -- a malformed
//     sequence is reported, not rewritten, because a runtime that replaces
//     a program's bytes has replaced the program's data;
//   * that the `vfprintf` bridge reads each argument from the slot the
//     Microsoft ABI put it in -- including the two that would be silently
//     wrong if the bridge trusted its luck: an `int` occupies the *low half*
//     of its slot and `long` is 32 bits on this data model, so a slot whose
//     upper half holds garbage must print exactly what the guest passed;
//   * that the heap answers `HeapSize` with the size the guest *asked* for,
//     which is the number the guest compares against and not the number the
//     host's allocator rounded to;
//   * and that the registry answers every import the fixtures name, since a
//     table that missed one name would fail a program that only ever runs
//     somewhere else.

#include "occ/runtime/exports.h"
#include "occ/runtime/objects.h"
#include "occ/runtime/winabi.h"

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using namespace occ;
using namespace occ::runtime;

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

// The vector comparison the round trip reports through. Defined before the
// tests that call it, so a failure reads as a mismatch rather than as a
// missing declaration.
bool check_same(const std::vector<std::string>& got,
                const std::vector<std::string>& want) {
    if (got.size() != want.size()) {
        return false;
    }
    for (std::size_t i = 0; i < want.size(); ++i) {
        if (got[i] != want[i]) {
            return false;
        }
    }
    return true;
}

// ------------------------------------------------------------ command line

void test_split_basics() {
    // The rules `CommandLineToArgvW` implements, each one as a case that
    // would parse differently if the rule were missing.
    std::vector<std::string> plain = winabi::split_command_line("a b c");
    check(plain.size() == 3, "whitespace separates unquoted arguments");

    std::vector<std::string> quoted = winabi::split_command_line("a \"b c\" d");
    check(quoted.size() == 3, "a quoted argument is one argument");
    check(quoted.size() == 3 && quoted[1] == "b c",
          "the quoted argument keeps its space");

    // An empty argument exists only because the caller quoted it.
    std::vector<std::string> empty = winabi::split_command_line("a \"\" b");
    check(empty.size() == 3 && empty[1].empty(),
          "a pair of quotes produces an empty argument");

    // 2n backslashes before a quote: n backslashes, quote toggles. The `b`
    // after the toggle sits outside the quotes and joins the argument.
    std::vector<std::string> pair = winabi::split_command_line("\"a\\\\\"b");
    check(pair.size() == 1 && pair[0] == "a\\b",
          "two backslashes before a quote are one backslash and a toggle");

    // 2n+1 backslashes before a quote: n backslashes and a literal quote.
    std::vector<std::string> odd = winabi::split_command_line("\"a\\\"b\"");
    check(odd.size() == 1 && odd[0] == "a\"b",
          "three backslashes before a quote keep the quote literal");

    // Backslashes not followed by a quote are themselves, however many.
    std::vector<std::string> raw = winabi::split_command_line("a\\\\b");
    check(raw.size() == 1 && raw[0] == "a\\\\b",
          "backslashes with no quote behind them stay as they are");

    // The empty-argument-at-the-end case: a trailing quote pair is an
    // argument, and dropping it would shift every later index.
    std::vector<std::string> trailing =
        winabi::split_command_line("a b \"\"");
    check(trailing.size() == 3 && trailing[2].empty(),
          "a trailing empty argument is kept");
}

void test_build_known_values() {
    check(winabi::build_command_line("p", {}) == "p",
          "no arguments produce the program alone");
    check(winabi::build_command_line("p", {"a b"}) == "p \"a b\"",
          "an argument with a space is quoted");
    check(winabi::build_command_line("p", {""}) == "p \"\"",
          "an empty argument is a pair of quotes");
    check(winabi::build_command_line("p", {"a\"b"}) == "p \"a\\\"b\"",
          "an embedded quote is escaped with an odd backslash run");
    // A backslash alone does not need quoting: with no quote behind it the
    // split keeps it as it is, so the bare text round-trips.
    check(winabi::build_command_line("p", {"a\\"}) == "p a\\",
          "a trailing backslash with no whitespace goes through bare");
    check(winabi::build_command_line("p", {"C:\\x\\y"}) == "p C:\\x\\y",
          "backslashes with no quote behind them are left alone");
    // Inside quotes the trailing backslash doubles, because the closing
    // quote follows it: bare it would escape the quote and the parse would
    // swallow the boundary.
    check(winabi::build_command_line("p", {" b\\"}) == "p \" b\\\\\"",
          "a trailing backslash in a quoted argument is doubled");
}

void test_round_trip() {
    // The property the CRT startup rests on: what the split returns from
    // what the builder wrote is what the caller passed. Every entry in the
    // corpus is here because one of the rules above touches it.
    const std::vector<std::vector<std::string>> corpus = {
        {},
        {"a"},
        {"a", "b c"},
        {"a", "b c", ""},
        {"", ""},
        {"a\"b"},
        {"quote's in the middle\"here"},
        {"back\\slash"},
        {"back\\slash\\", "two"},
        {"trailing space "},
        {" leading space"},
        {"tab\tinside"},
        {"C:\\Program Files\\app.exe"},
        {"a\\\\b"},
        {"a\\\\\\"},
        {"\""},
        {"\"\""},
        {"a \"b\" c"},
    };

    for (const std::vector<std::string>& args : corpus) {
        const std::string line =
            winabi::build_command_line("prog.exe", args);
        std::vector<std::string> parsed = winabi::split_command_line(line);
        // The program is the first thing the split returns: the line the
        // builder wrote *is* the guest's command line, and `__getmainargs`
        // hands the guest its parse of it whole.
        std::vector<std::string> want;
        want.push_back("prog.exe");
        want.insert(want.end(), args.begin(), args.end());
        if (!check_same(parsed, want)) {
            std::fprintf(stderr,
                         "  round trip failed for line: %s\n", line.c_str());
        }
    }
}

// ----------------------------------------------------------------- paths

void test_to_dos_path() {
    check(winabi::to_dos_path("/root/x/args.exe") == "Z:\\root\\x\\args.exe",
          "a Unix path becomes a Z: drive path with backslashes");
    check(winabi::to_dos_path("/") == "Z:\\",
          "the root becomes the drive alone");
    check(winabi::to_dos_path("Z:\\already\\dos") == "Z:\\already\\dos",
          "a path that is already DOS-shaped is returned unchanged");
    check(winabi::to_dos_path("relative/path") == "relative/path",
          "a path with no drive prefix is returned unchanged");
    check(winabi::to_dos_path("") == "",
          "an empty path stays empty");
}

// ------------------------------------------------------------------- utf

void test_utf_conversion() {
    std::u16string wide;
    check(winabi::utf8_to_utf16("plain", wide) && wide == u"plain",
          "ASCII converts to itself");

    // U+00E9 é: two bytes in UTF-8, one unit in UTF-16.
    check(winabi::utf8_to_utf16("caf\xC3\xA9", wide) &&
              wide == u"caf\x00E9",
          "a two-byte sequence becomes one UTF-16 unit");

    // U+20AC €: three bytes in UTF-8, one unit in UTF-16.
    check(winabi::utf8_to_utf16("\xE2\x82\xAC", wide) &&
              wide == std::u16string{0x20AC},
          "a three-byte sequence becomes one UTF-16 unit");

    // U+1D11E 𝄞: four bytes in UTF-8, a surrogate pair in UTF-16.
    check(winabi::utf8_to_utf16("\xF0\x9D\x84\x9E", wide) &&
              wide == std::u16string{0xD834, 0xDD1E},
          "a four-byte sequence becomes a surrogate pair");

    // The malformed cases. Each is reported rather than rewritten.
    check(!winabi::utf8_to_utf16("\xC0\x80", wide),
          "an overlong encoding is refused");
    check(!winabi::utf8_to_utf16("\xE2\x82", wide),
          "a truncated sequence is refused");
    check(!winabi::utf8_to_utf16("\xFF", wide),
          "a continuation byte in the lead position is refused");
    check(!winabi::utf8_to_utf16("\xED\xA0\x80", wide),
          "a lone surrogate in UTF-8 clothing is refused");

    // And back. The surrogate pair reassembles; the malformed input has no
    // round trip because the forward direction already refused it.
    std::string narrow;
    check(winabi::utf16_to_utf8(std::u16string{0xD834, 0xDD1E}, narrow) &&
              narrow == "\xF0\x9D\x84\x9E",
          "a surrogate pair becomes one four-byte sequence");
    check(winabi::utf16_to_utf8(u"caf\x00E9", narrow) &&
              narrow == "caf\xC3\xA9",
          "a two-byte sequence comes back from one UTF-16 unit");
    check(!winabi::utf16_to_utf8(std::u16string{0xD800}, narrow),
          "a lone surrogate going the other way is refused too");
}

// The two conversions as the guest calls them. The guest reaches them
// through the export table, so the test takes the address the same way a
// guest would and calls through it: a name in the table that is not the
// function is a fault the fixture could not report from where it sits.
using MultiByteToWideCharFn = std::int32_t(__attribute__((ms_abi))*)(
    std::uint32_t, std::uint32_t, const char*, std::int32_t, char16_t*,
    std::int32_t);
using WideCharToMultiByteFn = std::int32_t(__attribute__((ms_abi))*)(
    std::uint32_t, std::uint32_t, const char16_t*, std::int32_t, char*,
    std::int32_t, const char*, std::int32_t*);

void test_multibyte_wide_lengths() {
    ExportRegistry registry;
    winabi::register_host_modules(registry);
    const auto mb = registry.find_by_name("kernel32.dll",
                                          "MultiByteToWideChar", 0);
    const auto wc = registry.find_by_name("kernel32.dll",
                                          "WideCharToMultiByte", 0);
    check(mb.address != 0 && wc.address != 0,
          "both conversions resolve through the export table");
    if (mb.address == 0 || wc.address == 0) {
        return;
    }
    const auto to_wide =
        reinterpret_cast<MultiByteToWideCharFn>(mb.address);
    const auto to_narrow =
        reinterpret_cast<WideCharToMultiByteFn>(wc.address);

    char16_t wide[16];
    char narrow[16];

    // A negative target length is Windows' "this buffer is not usable".
    // Reading it as unsigned would make it the largest value of the type,
    // which every buffer passes -- and the copy would run off the end of
    // whatever the caller really had. The call must be refused instead.
    std::memset(wide, 0xAB, sizeof(wide));
    check(to_wide(0, 0, "abc", 3, wide, -1) == 0,
          "a negative target length is refused on the widen side");
    std::memset(narrow, 0xAB, sizeof(narrow));
    check(to_narrow(0, 0, u"abc", 3, narrow, -1, nullptr, nullptr) == 0,
          "a negative target length is refused on the narrow side");

    // The refusals must not have written a byte, which is what the memset
    // above makes visible.
    bool wide_untouched = true;
    bool narrow_untouched = true;
    for (char16_t unit : wide) {
        wide_untouched = wide_untouched && (unit & 0xFF) == 0xAB;
    }
    for (char byte : narrow) {
        narrow_untouched = narrow_untouched && (byte & 0xFF) == 0xAB;
    }
    check(wide_untouched, "the refused widen wrote nothing");
    check(narrow_untouched, "the refused narrow wrote nothing");

    // A target that really is too small is refused the same way, and the
    // size query a null target asks for still answers the need.
    check(to_wide(0, 0, "abc", -1, nullptr, 0) == 4,
          "the widen size query answers the count a null target asks for");
    check(to_wide(0, 0, "abc", 3, wide, 2) == 0,
          "a widen target one unit short is refused");
    check(to_narrow(0, 0, u"abc", 3, narrow, 2, nullptr, nullptr) == 0,
          "a narrow target one byte short is refused");

    // The conversion itself, once the length is honest. `caf\xC3\xA9` is
    // five bytes: the é is the two-byte sequence, and a length that cut it
    // in half would be the truncated input the forward direction refuses.
    check(to_wide(0, 0, "caf\xC3\xA9", 5, wide, 16) == 4 &&
              wide[0] == u'c' && wide[3] == 0x00E9,
          "a well-sized widen converts the text");
    check(to_narrow(0, 0, u"caf\x00E9", 4, narrow, 16, nullptr, nullptr) == 5 &&
              std::strncmp(narrow, "caf\xC3\xA9", 5) == 0,
          "a well-sized narrow converts the text back");
}

// ------------------------------------------------------------- vfprintf

// Prints through the bridge into memory. Returns what the bridge returns,
// and leaves the text in `out` where the caller's check can compare it.
int bridge_printf(std::string& out, const char* fmt,
                  const std::vector<std::uint64_t>& slots) {
    char* buffer = nullptr;
    std::size_t length = 0;
    std::FILE* stream = ::open_memstream(&buffer, &length);
    if (stream == nullptr) {
        out = "<no memstream>";
        return -1;
    }
    const int result = winabi::host_vfprintf(stream, fmt, slots.data());
    ::fclose(stream);
    if (buffer != nullptr) {
        out.assign(buffer, length);
        ::free(buffer);
    }
    return result;
}

// The slot builder. One 8-byte slot per argument, in Microsoft order: an
// int sits in the low half, a 64-bit value fills the slot, a double is its
// own bit pattern. The garbage in the unused half of a slot is deliberate:
// the guest's ABI says the upper half is undefined, and a bridge that
// believed the whole slot was its argument would print whatever the caller
// left in a register.
class Slots {
public:
    Slots& raw(std::uint64_t value) {
        slots_.push_back(value);
        return *this;
    }

    Slots& i32(std::int32_t value) {
        // Low half is the argument; high half is register garbage.
        return raw((0xDEADBEEFULL << 32) |
                   static_cast<std::uint64_t>(
                       static_cast<std::uint32_t>(value)));
    }

    Slots& u32(std::uint32_t value) {
        return i32(static_cast<std::int32_t>(value));
    }

    Slots& u64(std::uint64_t value) {
        return raw(value);
    }

    Slots& str(const char* text) {
        return raw(reinterpret_cast<std::uintptr_t>(text));
    }

    Slots& f64(double value) {
        std::uint64_t bits = 0;
        std::memcpy(&bits, &value, sizeof(bits));
        return raw(bits);
    }

    [[nodiscard]] const std::vector<std::uint64_t>& get() const noexcept {
        return slots_;
    }

private:
    std::vector<std::uint64_t> slots_;
};

void test_vfprintf_conversions() {
    std::string out;

    check(bridge_printf(out, "%d", Slots().i32(-7).get()) == 2 && out == "-7",
          "%d reads the low half of its slot and signs correctly");
    check(bridge_printf(out, "%u", Slots().u32(4000000000u).get()) == 10 &&
              out == "4000000000",
          "%u reads its slot unsigned");
    check(bridge_printf(out, "%x", Slots().u32(0x1234ABCDu).get()) == 8 &&
              out == "1234abcd",
          "%x reads its slot as hex");
    check(bridge_printf(out, "%c", Slots().i32('A').get()) == 1 && out == "A",
          "%c takes one byte out of the slot");

    // The one the data model decides. On Windows a long is 32 bits, so the
    // bridge must read four bytes; a bridge that read eight would print a
    // number the guest never passed.
    check(bridge_printf(out, "%ld",
                        Slots().raw(0x1234567800000000ULL | 0x7FFFFFFFULL)
                            .get()) == 10 &&
              out == "2147483647",
          "%ld reads 32 bits, because MS long is 32 bits");

    check(bridge_printf(out, "%lld", Slots().u64(5000000000ULL).get()) == 10 &&
              out == "5000000000",
          "%lld reads the whole slot");

    const char* text = "hello";
    check(bridge_printf(out, "%s", Slots().str(text).get()) == 5 &&
              out == "hello",
          "%s reads a pointer out of the slot");
    check(bridge_printf(out, "%s=%d", Slots().str(text).i32(7).get()) == 7 &&
              out == "hello=7",
          "two conversions read two slots in order");

    check(bridge_printf(out, "%f", Slots().f64(1.5).get()) == 8 &&
              out == "1.500000",
          "%f reads the slot as a double's bit pattern");
    check(bridge_printf(out, "%.2f", Slots().f64(1.005).get()) == 4 &&
              out == "1.00",
          "a precision passes through to the host's formatter");
    check(bridge_printf(out, "%g", Slots().f64(0.0001).get()) == 6 &&
              out == "0.0001",
          "%g picks its own representation");

    check(bridge_printf(out, "%6d|", Slots().i32(42).get()) == 7 &&
              out == "    42|",
          "a width pads on the left");
    check(bridge_printf(out, "%-6d|", Slots().i32(42).get()) == 7 &&
              out == "42    |",
          "a minus flag pads on the right");

    // The dynamic width comes out of its own slot and the text no longer
    // needs to describe it.
    check(bridge_printf(out, "%*d", Slots().i32(5).i32(42).get()) == 5 &&
              out == "   42",
          "a * width is folded in from its slot");

    // The doubled percent takes no argument, but the save area a guest
    // hands over is never empty -- a real `va_list` always points at
    // something -- so the slot here is what a caller would have.
    check(bridge_printf(out, "100%%", Slots().raw(0).get()) == 4 &&
              out == "100%",
          "a doubled percent is text, not an argument");
    // And mid-text, where a bare percent in the rebuilt format would
    // start a conversion the host reads as garbage.
    check(bridge_printf(out, "%d%% done", Slots().i32(50).get()) == 8 &&
              out == "50% done",
          "a mid-text doubled percent survives the rebuild");

    // The registers run out. The fourth integer argument lives in the
    // overflow area, and a descriptor whose cursors do not walk there
    // reads zero for everything after the third.
    check(bridge_printf(out, "%d-%d-%d-%d",
                        Slots().i32(1).i32(2).i32(3).i32(4).get()) == 7 &&
              out == "1-2-3-4",
          "the fourth argument comes from the overflow area");

    // The two cursors are independent: an integer does not consume an SSE
    // slot, and a double does not push the integer that follows it past
    // its own register.
    check(bridge_printf(out, "%d|%.1f|%d",
                        Slots().i32(5).f64(2.5).i32(6).get()) == 7 &&
              out == "5|2.5|6",
          "integer and floating cursors advance independently");

    // The width spellings the guest writes and what the host reads:
    // `I64` is Windows for `ll`, a single `l` is the guest's 32-bit long,
    // and `L` on a floating conversion is a double rather than the host's
    // 16-byte long double.
    check(bridge_printf(out, "%I64d",
                        Slots().u64(5000000000ULL).get()) == 10 &&
              out == "5000000000",
          "I64 reads the whole slot, as ll does");
    check(bridge_printf(out, "%lu", Slots().u32(3000000000u).get()) == 10 &&
              out == "3000000000",
          "a 32-bit long is read as four bytes");
    check(bridge_printf(out, "%Lf", Slots().f64(1.5).get()) == 8 &&
              out == "1.500000",
          "L on a floating conversion reads a double");

    // The stream's text mode. A newline through the CRT leaves as a
    // carriage return and a newline -- what the Windows CRT does before a
    // byte ever reaches WriteFile -- while the answer the guest sees is
    // the format's own count, the newline still one character.
    check(bridge_printf(out, "line\n", Slots().raw(0).get()) == 5 &&
              out == "line\r\n",
          "the CRT's text mode expands a newline on the way out");
    check(bridge_printf(out, "plain", Slots().raw(0).get()) == 5 &&
              out == "plain",
          "text without newlines goes through unchanged");

    // The refusals that keep the host from misreading the guest: the
    // guest's `wchar_t` is 16 bits and the host's is 32, so a wide string
    // passed through would print half its characters; and `%n` cannot
    // cross at all, because the fortified host aborts rather than fails
    // on it. Each refusal happens before a slot is consumed, which is why
    // the slot contents do not matter.
    check(bridge_printf(out, "%ls", Slots().str("x").get()) == -1,
          "a wide string is refused, not misread");
    check(bridge_printf(out, "%S", Slots().str("x").get()) == -1,
          "the capital spelling of wide is refused too");
    check(bridge_printf(out, "%C", Slots().i32(0x41).get()) == -1,
          "a wide character is refused");
    check(bridge_printf(out, "%ws", Slots().str("x").get()) == -1,
          "the Windows wide prefix is refused");
    check(bridge_printf(out, "%n", Slots().str("x").get()) == -1,
          "%n never crosses the bridge");
    check(bridge_printf(out, "%I", Slots().i32(1).get()) == -1,
          "an I with no width is refused");

    // The refusals. A conversion the bridge cannot classify has to fail
    // rather than guess, because a wrong guess shifts every later slot and
    // every argument after it lands in the wrong parameter.
    check(bridge_printf(out, "%y", Slots().i32(1).get()) == -1,
          "an unknown conversion is refused");
    check(bridge_printf(out, "%", Slots().i32(1).get()) == -1,
          "a truncated conversion is refused");
}

// ------------------------------------------------------------------ heap

void test_heap_semantics() {
    constexpr std::uint32_t kZero = 0x00000008u;  // HEAP_ZERO_MEMORY

    // The size the guest asked for is the size `HeapSize` answers with --
    // not the usable size, which is larger, and which is the number a heap
    // test would lie with.
    void* block = winabi::heap_alloc(0, 100);
    check(block != nullptr, "an allocation succeeds");
    check(winabi::heap_size(block) == 100,
          "HeapSize answers with the requested size");
    check(winabi::heap_free(block), "the block frees");
    // A second free is *not* tested: Windows leaves the double free
    // undefined, this header shares the chunk's lifetime with malloc, and
    // answering it would mean reading memory the allocator owns again.
    check(winabi::heap_free(nullptr),
          "freeing nothing succeeds, as HeapFree(NULL) does on Windows");

    void* zeroed = winabi::heap_alloc(kZero, 64);
    check(zeroed != nullptr, "a zeroed allocation succeeds");
    bool all_zero = true;
    for (std::size_t i = 0; i < 64; ++i) {
        if (static_cast<unsigned char*>(zeroed)[i] != 0) {
            all_zero = false;
            break;
        }
    }
    check(all_zero, "HEAP_ZERO_MEMORY zeroes the block");
    (void)winabi::heap_free(zeroed);

    // The realloc: a new block, the shared prefix copied, the extension
    // zeroed when asked, the old block gone. The prefix is what a program
    // building a buffer in place depends on; the extension is what a
    // program that asked for zeroing depends on.
    void* small = winabi::heap_alloc(0, 100);
    std::memcpy(small, "prefix-data", 12);
    void* big = winabi::heap_realloc(kZero, small, 5000);
    check(big != nullptr && big != small,
          "the realloc produced a new block");
    check(winabi::heap_size(big) == 5000,
          "the realloc's size is the new request");
    check(std::memcmp(big, "prefix-data", 12) == 0,
          "the shared prefix survived the move");
    // The zero flag zeroes what *grew*, not what was carried: the carried
    // 100 bytes are the old block's own content -- its first twelve the
    // prefix this test wrote, the rest whatever the old allocation held --
    // and rewriting those would be a corruption that reports success. The
    // extension starts where the carried size ends.
    bool extension_zero = true;
    const auto* bytes = static_cast<const unsigned char*>(big);
    for (std::size_t i = 100; i < 5000; ++i) {
        if (bytes[i] != 0) {
            extension_zero = false;
            break;
        }
    }
    check(extension_zero,
          "the extension is zeroed, because the flags asked for it");
    check(winabi::heap_free(big), "the new block frees");

    check(winabi::heap_size(nullptr) == 0,
          "the size of nothing is zero");
    void* nothing = winabi::heap_alloc(0, 0);
    check(nothing != nullptr,
          "a zero-byte allocation is still a block");
    check(winabi::heap_free(nothing), "the zero-byte block frees");
}

// ---------------------------------------------------------------- streams

void test_translate_stream() {
    // The iob table is the state's own; a guest that took `&stdout`'s
    // address passes back what its macro computed -- the base the runtime
    // handed `__iob_func` from, stepped by the *guest's* FILE size, not
    // the host's -- and the translation is what turns that address into
    // the stream object the host's `vfprintf` accepts.
    winabi::GuestState state;
    state.iob[0] = ::stdin;
    state.iob[1] = ::stdout;
    state.iob[2] = ::stderr;
    state.iob_base =
        reinterpret_cast<std::uint64_t>(state.iob);

    // The guest's FILE is three pointers and five ints, padded to 48: the
    // stride `(&__iob_func()[1])` steps by. The first slot is `stdin`, so
    // `stdout` sits at +48 and `stderr` at +96.
    check(winabi::translate_stream(state, state.iob_base + 48) == ::stdout,
          "the guest's stdout address translates to stdout");
    check(winabi::translate_stream(state, state.iob_base + 96) == ::stderr,
          "the guest's stderr address translates to stderr");
    check(winabi::translate_stream(state, state.iob_base) == ::stdin,
          "the guest's stdin address translates to stdin");
    // A stride the guest's FILE does not produce is not a table position:
    // this is the address the host's own pointer array holds at index 1,
    // which a guest macro cannot compute.
    check(winabi::translate_stream(state, state.iob_base + 8) ==
              reinterpret_cast<std::FILE*>(state.iob_base + 8),
          "an offset between guest slots is not a table position");
    check(winabi::translate_stream(
              state, reinterpret_cast<std::uint64_t>(::stdout)) == ::stdout,
          "a host pointer passes through unchanged");
    check(winabi::translate_stream(state, state.iob_base + 4 * 48) ==
              reinterpret_cast<std::FILE*>(state.iob_base + 4 * 48),
          "an offset past the table is not a table position");
    check(winabi::translate_stream(state, 0) == nullptr,
          "a null stream translates to null");
}

// ------------------------------------------------- the CRT's computations

// The comparison functions the sort and search hand back to the guest are
// guest code, which means Microsoft ABI code; the host compiled these, so
// their addresses are exactly what a guest would pass.
extern "C" std::int32_t __attribute__((ms_abi)) compare_int_asc(
    const void* a, const void* b) noexcept {
    const int left = *static_cast<const int*>(a);
    const int right = *static_cast<const int*>(b);
    return left < right ? -1 : (left > right ? 1 : 0);
}

extern "C" std::int32_t __attribute__((ms_abi)) compare_int_desc(
    const void* a, const void* b) noexcept {
    return -compare_int_asc(a, b);
}

void test_crt_computational() {
    // The conversions. The guest's long is 32 bits, so an answer past it
    // is Windows' clamp-and-ERANGE, not the host's 64-bit value; and a
    // leading minus on an unsigned conversion is a complement, not an
    // error, until the magnitude passes what 32 bits hold.
    char* end = nullptr;
    check(winabi::cr_strtol("  -42abc", &end, 10) == -42 && end != nullptr &&
              std::string(end) == "abc",
          "strtol skips whitespace, reads the sign, and reports the stop");
    errno = 0;
    check(winabi::cr_strtol("5000000000", nullptr, 10) == 2147483647 &&
              errno == ERANGE,
          "strtol clamps past the 32-bit long and marks ERANGE");
    errno = 0;
    check(winabi::cr_strtol("-5000000000", nullptr, 10) == -2147483648 &&
              errno == ERANGE,
          "strtol clamps below the 32-bit long the same way");
    errno = 0;
    check(winabi::cr_strtol("0x1F", &end, 16) == 31,
          "strtol reads the base it is given");
    errno = 0;
    check(winabi::cr_strtoul("-1", nullptr, 10) == 4294967295u &&
              errno == 0,
          "strtoul spells a minus as the complement, without an error");
    errno = 0;
    check(winabi::cr_strtoul("5000000000", nullptr, 10) == 4294967295u &&
              errno == ERANGE,
          "strtoul clamps past the 32-bit unsigned long");
    check(winabi::cr_strtoll("12345678901", nullptr, 10) == 12345678901LL,
          "strtoll is 64 bits");
    check(winabi::cr_atoi("  +7rest") == 7, "atoi reads what it reads");
    check(winabi::cr_atol("2147483647") == 2147483647,
          "atol answers the 32-bit long");

    // The itoa family the host has never had. Base 10 spells the value
    // signed; any other base spells the value's own bit pattern, which is
    // why -1 in hexadecimal is the full complement and not "-1".
    char buf[72];
    check(winabi::cr_itoa(-42, buf, 10) == buf && std::string(buf) == "-42",
          "itoa in base 10 spells the sign");
    check(winabi::cr_itoa(-1, buf, 16) != nullptr &&
              std::string(buf) == "ffffffff",
          "itoa in base 16 spells the bit pattern");
    check(winabi::cr__itoa(-2147483648, buf, 10) != nullptr &&
              std::string(buf) == "-2147483648",
          "itoa negates the minimum safely in unsigned");
    check(winabi::cr__itoa(0, buf, 2) != nullptr && std::string(buf) == "0",
          "itoa spells zero as a digit, not nothing");
    check(winabi::cr__i64toa(-1, buf, 10) != nullptr &&
              std::string(buf) == "-1",
          "i64toa in base 10 is signed");
    check(winabi::cr__i64toa(-1, buf, 16) != nullptr &&
              std::string(buf) == "ffffffffffffffff",
          "i64toa in base 16 is the 64-bit complement");
    check(winabi::cr__ui64toa(18446744073709551615ULL, buf, 16) != nullptr &&
              std::string(buf) == "ffffffffffffffff",
          "ui64toa spells the full unsigned range");
    check(winabi::cr__itoa(255, buf, 36) != nullptr && std::string(buf) == "73",
          "itoa reaches base 36 with lower-case digits");

    // The random sequence. Windows' rand is a fixed recurrence with a
    // fixed start, so a guest that seeds 1 sees the values Windows -- and
    // wine -- produce, not whatever the host's own generator says.
    winabi::cr_srand(1);
    check(winabi::cr_rand() == 41, "srand(1) starts where Windows starts");
    check(winabi::cr_rand() == 18467,
          "the sequence continues the Windows recurrence");
    check(winabi::cr_rand() == 6334,
          "the recurrence steps by 214013 and 2531011");
    winabi::cr_srand(1);
    check(winabi::cr_rand() == 41, "reseeding restarts the sequence");

    // Sorting and searching across the ABI. The comparison function the
    // host calls back into is guest code -- here, host code compiled with
    // the guest's convention, which is the same bridge either way.
    int values[] = {5, 3, 9, 1, 7};
    winabi::cr_qsort(values, 5, sizeof(int), compare_int_asc);
    check(values[0] == 1 && values[1] == 3 && values[2] == 5 &&
              values[3] == 7 && values[4] == 9,
          "qsort orders through the guest's comparison function");
    winabi::cr_qsort(values, 5, sizeof(int), compare_int_desc);
    check(values[0] == 9 && values[4] == 1,
          "the same bridge answers a different comparison");
    const int key = 7;
    const int* found = static_cast<const int*>(winabi::cr_bsearch(
        &key, values, 5, sizeof(int), compare_int_desc));
    check(found != nullptr && *found == 7,
          "bsearch walks its own binary half-steps");
    const int absent = 4;
    check(winabi::cr_bsearch(&absent, values, 5, sizeof(int),
                          compare_int_desc) == nullptr,
          "a value the table does not hold comes back null");

    // The quotient/remainder pairs. The layouts are the guest's: two
    // 32-bit halves for div and ldiv, two 64-bit halves for lldiv.
    const div_t d = winabi::cr_div(7, 2);
    check(d.quot == 3 && d.rem == 1, "div answers its own pair");
    const div_t negative = winabi::cr_div(-7, 2);
    check(negative.quot == -3 && negative.rem == -1,
          "div truncates toward zero, the way C divides");
    const auto ld = winabi::cr_ldiv(-7, 2);
    check(ld.quot == -3 && ld.rem == -1,
          "ldiv is the 32-bit pair the guest's long spells");
    const auto lld = winabi::cr_lldiv(-7, 2);
    check(lld.quot == -3 && lld.rem == -1,
          "lldiv is the 64-bit pair");

    // The string family the host already has, plus the case spellings it
    // names differently.
    char text[32];
    std::memcpy(text, "Hello", 6);
    check(winabi::cr_strcmp(text, "Hello") == 0, "strcmp answers equality");
    check(winabi::cr_strchr(text, 'l') == text + 2 &&
              winabi::cr_strrchr(text, 'l') == text + 3,
          "strchr and strrchr find from opposite ends");
    check(winabi::cr_strstr("haystack", "stack") != nullptr,
          "strstr finds the needle");
    check(winabi::cr_strspn("abcXY", "cba") == 3 &&
              winabi::cr_strcspn("abcXY", "XY") == 3,
          "strspn and strcspn count complementary sets");
    check(winabi::cr_strnlen("abcdef", 4) == 4,
          "strnlen stops at the limit it is given");
    winabi::cr__strupr(text);
    check(std::string(text) == "HELLO", "_strupr folds in place");
    winabi::cr__strlwr(text);
    check(std::string(text) == "hello", "_strlwr folds back");
    check(winabi::cr__stricmp("HeLLo", "hello") == 0,
          "_stricmp compares without case");
    char overlap[11];
    std::memcpy(overlap, "1234567890", 11);
    winabi::cr_memmove(overlap + 2, overlap, 8);
    check(std::string(overlap) == "1212345678",
          "memmove moves through the overlap like memmove does");
    check(winabi::cr_memcmp("abc", "abd", 2) == 0 &&
              winabi::cr_memcmp("abc", "abd", 3) < 0,
          "memcmp compares only the bytes it is given");
    winabi::cr_strcat(text, "-world");
    check(std::string(text) == "hello-world", "strcat appends");
    winabi::cr_strncpy(text, "XYZ", 2);
    check(std::string(text) == "XYllo-world",
          "strncpy copies its count, no more");

    // Character classification: a spot check per table the guest reads.
    check(winabi::cr_isdigit('7') != 0 && winabi::cr_isdigit('x') == 0,
          "isdigit answers the digit table");
    check(winabi::cr_isxdigit('f') != 0 && winabi::cr_ispunct('!') != 0 &&
              winabi::cr_isspace(' ') != 0 && winabi::cr_isalpha('Q') != 0,
          "the classification tables answer through");
    check(winabi::cr_tolower('A') == 'a' && winabi::cr_toupper('b') == 'B',
          "case conversion answers the folded byte");

    // The 16-bit wchar_t family. The guest's wchar_t is two bytes and
    // unsigned, and the comparison answers the difference of units.
    char16_t wide[32];
    check(winabi::cr_wcscpy(wide, u"wide") == wide &&
              winabi::cr_wcslen(wide) == 4,
          "wcscpy copies unit by unit");
    check(winabi::cr_wcscmp(u"abc", u"abd") == -1,
          "wcscmp answers the unsigned difference");
    check(winabi::cr_wcscmp(u"abc", u"abc") == 0,
          "wcscmp answers equality");
    check(winabi::cr_wcsncmp(u"abc", u"abd", 2) == 0,
          "wcsncmp compares only its count");
    check(winabi::cr_wcschr(wide, 'd') == wide + 2,
          "wcschr folds its character to 16 bits");
    // A surrogate half is one 16-bit unit like any other: the guest seeks
    // the low half of an emoji and finds it inside the pair.
    check(winabi::cr_wcschr(u"\U0001F600", 0xDE00) != nullptr,
          "a surrogate half the guest seeks is a unit like any other");
    check(winabi::cr_wcsstr(u"haystack", u"stack") != nullptr,
          "wcsstr finds the needle in 16-bit text");
    winabi::cr_wcscat(wide, u"-text");
    check(winabi::cr_wcslen(wide) == 9, "wcscat appends units");
    char16_t padded[8];
    check(winabi::cr_wcsncpy(padded, u"ab", 6) == padded &&
              padded[0] == u'a' && padded[2] == u'\0' && padded[5] == u'\0',
          "wcsncpy pads the rest of its count with terminators");
    check(winabi::cr_wcsnlen(u"abcdef", 3) == 3,
          "wcsnlen stops at the limit it is given");
    const char16_t* dup = winabi::cr_wcsdup(u"kept");
    check(dup != nullptr && winabi::cr_wcslen(dup) == 4 &&
              winabi::cr_wcscmp(dup, u"kept") == 0,
          "wcsdup answers a copy the guest can free");
    ::free(const_cast<char16_t*>(dup));

    // The multibyte bridge. The guest's narrow bytes are this runtime's
    // UTF-8, its wide units are UTF-16, and a null destination asks only
    // for the room the text needs.
    check(winabi::cr_mbstowcs(nullptr, "hello", 0) == 5,
          "mbstowcs counts the units a text needs");
    char16_t round[16];
    check(winabi::cr_mbstowcs(round, "h\xc3\xa9llo", 16) == 5 &&
              round[1] == 0xE9 && round[5] == u'\0',
          "mbstowcs turns the two-byte spelling into one wide unit");
    check(winabi::cr_mbstowcs(round, "h\xc3\xa9llo", 3) == 3,
          "mbstowcs stores only what its count holds");
    check(winabi::cr_mbstowcs(round, "\xff", 16) ==
              static_cast<std::uint64_t>(-1),
          "mbstowcs refuses an invalid byte, it does not rewrite it");
    check(winabi::cr_wcstombs(nullptr, u"wide", 0) == 4,
          "wcstombs counts the bytes a text needs");
    char narrow[16];
    check(winabi::cr_wcstombs(narrow, u"h\xE9llo", 16) == 6 &&
              std::string(narrow) == "h\xc3\xa9llo",
          "wcstombs turns one wide unit into its UTF-8 spelling");
}

// ----------------------------------------------------- the CRT's stdio

void test_crt_stdio_buffers() {
    // The buffer spellings run the stream format with no text mode after
    // it: a buffer has no mode, and a newline in one stays a newline.
    char buffer[64];
    check(winabi::cr_sprintf(buffer, "n=%d s=%s", 42, "hi") == 9 &&
              std::string(buffer) == "n=42 s=hi",
          "sprintf answers the format's own count");
    check(winabi::cr_sprintf(buffer, "line\nnext") == 9 &&
              std::string(buffer) == "line\nnext",
          "a newline in a buffer stays a newline");

    // The slot layout the stream bridge reads is the one the variadic
    // spellings hand over -- an int in the low half, the rest by slot --
    // which the variadic call itself assembles.
    check(winabi::cr_sprintf(buffer, "%lld|%f|%x",
                             5000000000LL, 1.5, 0x1234ABCDu) == 28 &&
              std::string(buffer) == "5000000000|1.500000|1234abcd",
          "the variadic slots carry what the slots carry");

    // C99's snprintf: truncation is part of the answer, the terminator
    // always lands, and the count is the whole text's length.
    char small[8];
    const int whole = winabi::cr_snprintf(small, sizeof(small), "%s-%d",
                                          "truncate", 9);
    check(whole == 10 && std::string(small) == "truncat" &&
              small[7] == '\0',
          "snprintf truncates, terminates, and counts the whole text");
    check(winabi::cr_snprintf(small, sizeof(small), "fits") == 4 &&
              std::string(small) == "fits",
          "a text that fits comes back whole");

    // The Microsoft spelling keeps the dangerous contract C99 fixed: a
    // text that fills its count leaves no terminator at all.
    const int ms = winabi::cr__snprintf(small, sizeof(small), "%s-%d",
                                        "truncate", 9);
    check(ms == 10 && std::memcmp(small, "truncat", 7) == 0,
          "_snprintf filling its count writes no terminator");
    check(winabi::cr__snprintf(small, sizeof(small), "ok") == 2 &&
              std::string(small) == "ok",
          "_snprintf with room terminates the way MS does");

    // The vs spellings take the descriptor straight.
    Slots slots;
    slots.u32(7).u64(reinterpret_cast<std::uint64_t>("seven"));
    const std::vector<std::uint64_t> args = slots.get();
    check(winabi::cr_vsprintf(buffer, "n=%d s=%s",
                              const_cast<std::uint64_t*>(args.data())) == 11 &&
              std::string(buffer) == "n=7 s=seven",
          "vsprintf reads the descriptor it is handed");

    // user32's wsprintf: the wide spelling walks its own format, and its
    // `%s` reads a UTF-16 string the narrow bridge would misread.
    char16_t wide_buffer[48] = {};
    check(winabi::cr_wsprintfW(wide_buffer, u"n=%d|x=%X|s=%s|c=%c",
                               41, 0xABCu, u"ok", u'Z') == 19 &&
              std::u16string(wide_buffer) == u"n=41|x=ABC|s=ok|c=Z",
          "wsprintfW reads the slots the wide format names");
    check(winabi::cr_wsprintfW(wide_buffer, u"pad=[%5d][%-5d][%05d]",
                               42, 42, 42) == 25 &&
              std::u16string(wide_buffer) == u"pad=[   42][42   ][00042]",
          "wsprintfW pads the fields the width asks for");
    check(winabi::cr_wsprintfW(wide_buffer, u"neg=%05d l64=%l64u",
                               -42, 5000000000ULL) == 24 &&
              std::u16string(wide_buffer) == u"neg=-0042 l64=5000000000",
          "wsprintfW fills after the sign and reads 64-bit slots");
    check(winabi::cr_wsprintfA(buffer, "n=%d s=%s", 7, "seven") == 11 &&
              std::string(buffer) == "n=7 s=seven",
          "wsprintfA is the narrow bridge under its user32 name");
}

void test_crt_stdio_files() {
    // The DOS path the guest spells is the file the host opens.
    const char* dos_path = "Z:\\tmp\\occ_winabi_io_test.dat";
    std::remove("/tmp/occ_winabi_io_test.dat");

    char* handle = static_cast<char*>(winabi::cr_fopen(dos_path, "w"));
    check(handle != nullptr, "fopen opens the DOS path the guest spells");

    // The write side of the text mode: what the guest writes with a
    // newline is what the Windows CRT would put in the file.
    const std::int32_t put =
        winabi::cr_fwrite("a\nb\n", 1, 4, handle) == 4 ? 0 : 1;
    check(put == 0, "fwrite delivers its count through the text mode");
    check(winabi::cr_fclose(handle) == 0, "fclose closes what fopen opened");

    std::FILE* raw = ::fopen("/tmp/occ_winabi_io_test.dat", "rb");
    check(raw != nullptr, "the file the guest named holds what a host sees");
    if (raw != nullptr) {
        char bytes[16] = {};
        const std::size_t got = ::fread(bytes, 1, sizeof(bytes), raw);
        ::fclose(raw);
        check(got == 6 && std::string(bytes, got) == "a\r\nb\r\n",
              "the text mode expanded every newline on the way in");
    }

    // The read side presses the pair back into one newline.
    handle = static_cast<char*>(winabi::cr_fopen(dos_path, "r"));
    check(handle != nullptr, "the file opens again for reading");
    char readback[16] = {};
    check(winabi::cr_fread(readback, 1, sizeof(readback), handle) == 4 &&
              std::string(readback) == "a\nb\n",
          "fread presses the carriage returns back into newlines");

    // One byte at a time, where the pair straddles two reads: the return
    // that lost its newline waits for the read that brings it.
    char one[4];
    check(winabi::cr_fseek(handle, 0, 0) == 0, "fseek returns to the start");
    check(winabi::cr_fread(one, 1, 1, handle) == 1 && one[0] == 'a',
          "the first byte comes back first");
    check(winabi::cr_fread(one, 1, 1, handle) == 1 && one[0] == '\r',
          "a return before its newline goes out as it is");
    check(winabi::cr_fread(one, 1, 1, handle) == 1 && one[0] == '\n',
          "the newline that closed the pair comes back as one");
    check(winabi::cr_ftell(handle) == 3,
          "ftell answers the offset the reads have walked to");

    // fgets hands the guest the line Windows' fgets would: one newline,
    // whatever the file held.
    check(winabi::cr_fseek(handle, 0, 0) == 0, "fseek returns for the line");
    char line[16] = {};
    check(winabi::cr_fgets(line, sizeof(line), handle) == line &&
              std::string(line) == "a\n",
          "fgets hands back the line with one newline");
    check(winabi::cr_feof(handle) == 0,
          "a line that ended in a newline is not the end");

    // A binary mode names itself: nothing expands, nothing presses back.
    check(winabi::cr_fclose(handle) == 0, "the read side closes");
    handle = static_cast<char*>(winabi::cr_fopen(dos_path, "wb"));
    check(handle != nullptr, "the binary mode opens");
    check(winabi::cr_fwrite("x\ny", 1, 3, handle) == 3,
          "binary fwrite delivers its bytes");
    check(winabi::cr_fclose(handle) == 0, "the binary write closes");
    handle = static_cast<char*>(winabi::cr_fopen(dos_path, "rb"));
    char binary[8] = {};
    check(handle != nullptr && winabi::cr_fread(binary, 1, 8, handle) == 3 &&
              std::string(binary, 3) == "x\ny",
          "binary fread hands back the bytes the file holds");
    check(winabi::cr_fclose(handle) == 0, "the binary read closes");

    check(winabi::cr_remove(dos_path) == 0, "remove clears the file away");
    check(winabi::cr_fopen(dos_path, "r") == nullptr,
          "a file that is gone does not open");

    // The rename that moves one DOS name to another.
    char* made = static_cast<char*>(winabi::cr_fopen(dos_path, "w"));
    check(made != nullptr && winabi::cr_fclose(made) == 0,
          "the rename's source opens and closes");
    check(winabi::cr_rename(dos_path, "Z:\\tmp\\occ_winabi_io_moved.dat") == 0,
          "rename answers across the DOS spellings");
    check(winabi::cr_fopen(dos_path, "r") == nullptr,
          "the old name is gone");
    char* moved = static_cast<char*>(
        winabi::cr_fopen("Z:\\tmp\\occ_winabi_io_moved.dat", "r"));
    check(moved != nullptr, "the new name opens");
    check(winabi::cr_fclose(moved) == 0, "the moved file closes");
    check(winabi::cr_remove("Z:\\tmp\\occ_winabi_io_moved.dat") == 0,
          "the moved file is cleared away too");

    // The wide spelling of open, over the same UTF-16 the guest's
    // wchar_t strings carry.
    char* opened = static_cast<char*>(
        winabi::cr__wfopen(u"Z:\\tmp\\occ_winabi_io_wide.dat", u"w"));
    check(opened != nullptr, "_wfopen reads the wide spelling");
    check(winabi::cr_fclose(opened) == 0, "the wide open closes");
    check(winabi::cr_remove("Z:\\tmp\\occ_winabi_io_wide.dat") == 0,
          "the wide-named file clears away");

    // ungetc hands the byte back before the next read takes it.
    handle = static_cast<char*>(
        winabi::cr_fopen("Z:\\tmp\\occ_winabi_ungetc.dat", "wb"));
    check(handle != nullptr && winabi::cr_fwrite("AB", 1, 2, handle) == 2 &&
              winabi::cr_fclose(handle) == 0,
          "the ungetc fixture writes two bytes");
    handle = static_cast<char*>(
        winabi::cr_fopen("Z:\\tmp\\occ_winabi_ungetc.dat", "rb"));
    check(handle != nullptr && winabi::cr_fgetc(handle) == 'A',
          "the first byte reads");
    check(winabi::cr_ungetc('A', handle) == 'A', "ungetc hands the byte back");
    check(winabi::cr_fgetc(handle) == 'A', "the handed-back byte reads again");
    check(winabi::cr_fclose(handle) == 0, "the ungetc fixture closes");
    check(winabi::cr_remove("Z:\\tmp\\occ_winabi_ungetc.dat") == 0,
          "the ungetc file clears away");
}

// ---------------------------------------------------------------- calendar

void test_crt_time_env() {
    // time: the guest's time_t is the host's -- sixty-four bits of
    // seconds -- and both spellings of the answer agree.
    std::int64_t stored = 0;
    const std::int64_t now = winabi::cr_time(&stored);
    check(now > 1700000000 && stored == now,
          "time answers the seconds it also stores");

    // clock: wall time in thousandths of a second, and it moves forward.
    const std::int32_t first_tick = winabi::cr_clock();
    const std::int32_t second_tick = winabi::cr_clock();
    check(second_tick >= first_tick, "clock moves forward");

    // gmtime over a fixed instant: 86400 is the second day of 1970, and
    // the nine ints the answer carries are the ones the UTC calendar
    // spells -- zero seconds through midnight, February-less month zero,
    // years since 1900, a Friday, the year's first day, no DST.
    std::int64_t day = 86400;
    const int* fields = static_cast<const int*>(winabi::cr_gmtime(&day));
    check(fields != nullptr && fields[0] == 0 && fields[1] == 0 &&
              fields[2] == 0 && fields[3] == 2 && fields[4] == 0 &&
              fields[5] == 70 && fields[6] == 5 && fields[7] == 1 &&
              fields[8] == 0,
          "gmtime reads the calendar the instant names");
    check(winabi::cr_gmtime(nullptr) == nullptr,
          "a null timer answers no broken-down time");

    // asctime over the same fields: the zone-free line the epoch spells.
    std::int64_t zero = 0;
    const char* line = winabi::cr_asctime(winabi::cr_gmtime(&zero));
    check(line != nullptr &&
              std::string(line) == "Thu Jan 01 00:00:00 1970\n",
          "asctime spells the line the fields make");

    // _mkgmtime inverts it, with no time zone to guess around.
    int round[9] = {0, 0, 0, 2, 0, 70, 0, 0, 0};
    check(winabi::cr__mkgmtime(round) == 86400 && round[6] == 5 &&
              round[7] == 1,
          "_mkgmtime reads the fields back into the instant");

    // mktime answers the local spelling of the fields it is given and
    // writes the normalized week day and year day back; localtime reads
    // the instant back into the fields that produced it.
    int local[9] = {45, 30, 12, 29, 1, 124, 0, 0, -1}; // 2024-02-29 12:30:45
    const std::int64_t stamp = winabi::cr_mktime(local);
    check(stamp != -1 && local[6] >= 0 && local[7] >= 0,
          "mktime normalizes the fields it answers");
    const int* back = static_cast<const int*>(winabi::cr_localtime(&stamp));
    check(back != nullptr && back[0] == 45 && back[1] == 30 &&
              back[2] == 12 && back[3] == 29 && back[4] == 1 &&
              back[5] == 124,
          "localtime reads the instant back into the fields");
    check(winabi::cr_localtime(nullptr) == nullptr,
          "a null timer answers no local time");

    // strftime over the UTC fields: the date, the weekday, the year day.
    char formatted[64] = {};
    check(winabi::cr_strftime(formatted, sizeof(formatted),
                              "%Y-%m-%d %H:%M:%S|%A|%j",
                              winabi::cr_gmtime(&day)) == 30 &&
              std::string(formatted) == "1970-01-02 00:00:00|Friday|002",
          "strftime spells what the format asks");
    char tiny[8] = {};
    check(winabi::cr_strftime(tiny, sizeof(tiny), "%Y-%m-%d %H:%M:%S",
                              winabi::cr_gmtime(&day)) == 0,
          "a strftime that cannot fit answers zero");

    // difftime is the difference it names.
    check(winabi::cr_difftime(172800, 86400) == 86400.0,
          "difftime answers the seconds between");

    // ------------------------------------------------------ environment

    // getenv over a name the table carries and one it does not.
    const char* path = winabi::cr_getenv("PATH");
    check(path != nullptr && std::strchr(path, '/') != nullptr,
          "getenv reads a name the environment carries");
    check(winabi::cr_getenv("OCC_DEFINITELY_NOT_SET_9F2") == nullptr,
          "getenv answers null for a name it does not carry");

    // _putenv_s writes, and the kernel32 narrow call sees the same value:
    // one environment, two spellings.
    check(winabi::cr__putenv_s("OCC_TEST_VAR", "41") == 0,
          "_putenv_s writes the name");
    const char* read = winabi::cr_getenv("OCC_TEST_VAR");
    check(read != nullptr && std::string(read) == "41",
          "getenv reads what putenv wrote");
    char value[8] = {};
    check(winabi::k32_GetEnvironmentVariableA("OCC_TEST_VAR", value,
                                              sizeof(value)) == 2 &&
              std::string(value) == "41",
          "the kernel32 spelling reads the same environment");
    char tight[2] = {};
    check(winabi::k32_GetEnvironmentVariableA("OCC_TEST_VAR", tight,
                                              sizeof(tight)) == 3,
          "a tight buffer asks for the count it needed, terminator in");
    check(winabi::k32_GetEnvironmentVariableA("OCC_DEFINITELY_NOT_SET_9F2",
                                              value, sizeof(value)) == 0,
          "an unknown name answers zero");

    // _putenv with the "NAME=VALUE" spelling, and "NAME=" for the delete.
    check(winabi::cr__putenv("OCC_TEST_VAR2=7") == 0,
          "_putenv writes the form it spells");
    read = winabi::cr_getenv("OCC_TEST_VAR2");
    check(read != nullptr && std::string(read) == "7",
          "the second name reads back");
    check(winabi::cr__putenv("OCC_TEST_VAR2=") == 0,
          "_putenv with no value deletes");
    check(winabi::cr_getenv("OCC_TEST_VAR2") == nullptr,
          "the deleted name reads as gone");

    // SetEnvironmentVariable deletes on a null value and on an empty one.
    check(winabi::k32_SetEnvironmentVariableA("OCC_TEST_VAR", "x") == 1,
          "the kernel32 set writes");
    check(winabi::k32_GetEnvironmentVariableA("OCC_TEST_VAR", value,
                                              sizeof(value)) == 1 &&
              std::string(value) == "x",
          "the set the kernel32 wrote reads back");
    check(winabi::k32_SetEnvironmentVariableA("OCC_TEST_VAR", nullptr) == 1,
          "the kernel32 set with no value deletes");
    check(winabi::k32_GetEnvironmentVariableA("OCC_TEST_VAR", value,
                                              sizeof(value)) == 0,
          "the kernel32-deleted name reads as gone");
    check(winabi::k32_SetEnvironmentVariableA("OCC_TEST_VAR", "") == 1,
          "the kernel32 set with an empty value deletes");
    check(winabi::k32_GetEnvironmentVariableA("OCC_TEST_VAR", value,
                                              sizeof(value)) == 0,
          "the empty-set name reads as gone");
    check(winabi::k32_SetEnvironmentVariableA("OCC_HAS=EQ", "x") == 0,
          "a name with an equals is no name");

    // the wide spelling carries the same value over the UTF-16 the
    // guest's wchar_t is
    check(winabi::k32_SetEnvironmentVariableW(u"OCC_TEST_WVAR", u"ok") == 1,
          "the wide set writes");
    char16_t wide[8] = {};
    check(winabi::k32_GetEnvironmentVariableW(u"OCC_TEST_WVAR", wide, 8) ==
                  2 &&
              std::u16string(wide) == u"ok",
          "the wide get reads what the wide set wrote");
    check(winabi::k32_SetEnvironmentVariableW(u"OCC_TEST_WVAR", nullptr) == 1,
          "the wide delete deletes");
    check(winabi::k32_GetEnvironmentVariableW(u"OCC_TEST_WVAR", wide, 8) == 0,
          "the wide-deleted name reads as gone");
}

// --------------------------------------------------------------- registry

// The synchronization objects: what a wait does to the thing it waited on.
//
// The table answers handles and the waits block on them, so what is worth
// asserting is not that a handle came back but what the wait did to the
// object's state. The two event kinds differ in exactly that, and the
// difference is what a program depends on: one `SetEvent` on a manual-reset
// event releases every waiter and leaves the event signalled, and on an
// auto-reset event it releases one and spends the signal.
void test_synchronization_objects() {
    const std::uint64_t before = objects::live_count();

    // An event starts in the state the caller asked for, and its handle
    // comes from the object namespace rather than the file one.
    const std::uint64_t manual = objects::create_event(true, false);
    check(manual != 0, "event: a manual-reset event is created");
    check(manual >= objects::kHandleBase,
          "event: the handle comes from the object namespace");
    check(objects::is_object(manual), "event: and the table knows it");
    check(objects::live_count() == before + 1,
          "event: creating one leaves one more live object");

    // Not signalled yet: a zero timeout asks now and is told so.
    check(objects::wait_one(manual, 0) == objects::WaitOutcome::TimedOut,
          "event: a non-signalled event times out a zero wait");

    check(objects::set_event(manual), "event: setting it succeeds");
    check(objects::wait_one(manual, 0) == objects::WaitOutcome::Signalled,
          "event: and the wait finds it");
    check(objects::wait_one(manual, 0) == objects::WaitOutcome::Signalled,
          "event: a manual-reset event stays signalled for the next waiter");

    check(objects::reset_event(manual), "event: resetting it succeeds");
    check(objects::wait_one(manual, 0) == objects::WaitOutcome::TimedOut,
          "event: and it is not signalled afterwards");

    // The auto-reset kind spends its signal on the wait that finds it,
    // which is what makes it a one-shot wakeup.
    const std::uint64_t automatic = objects::create_event(false, false);
    check(automatic != 0 && automatic != manual,
          "event: an auto-reset event gets its own handle");
    check(objects::set_event(automatic), "event: setting the auto-reset one");
    check(objects::wait_one(automatic, 0) == objects::WaitOutcome::Signalled,
          "event: the first wait is released");
    check(objects::wait_one(automatic, 0) == objects::WaitOutcome::TimedOut,
          "event: the second is not, because the first consumed the signal");

    // A handle that names nothing is its own outcome rather than a timeout.
    // A poll that found nothing and a handle that is not one are different
    // answers and Windows gives them different statuses.
    check(objects::wait_one(0xDEAD, 0) == objects::WaitOutcome::NoSuchObject,
          "wait: a handle that names nothing is not a timeout");
    check(!objects::set_event(0xDEAD), "event: setting one fails");
    check(!objects::reset_event(0xDEAD), "event: resetting one fails");

    // Closing releases the entry, and closing twice does not: the second
    // call names a handle the table no longer has.
    check(objects::close(manual), "event: closing a live object succeeds");
    check(!objects::close(manual), "event: closing it twice does not");
    check(!objects::is_object(manual), "event: and the table no longer has it");
    check(objects::close(automatic), "event: closing the other one");
    check(objects::live_count() == before,
          "event: and the live count is back where it started");
}

// A wait with nothing to find blocks, and a `SetEvent` on another thread is
// what releases it.
//
// This is the case the table exists for. It is separate from the state
// transitions above because a release needs a second thread: everything
// there can be answered on one, and this cannot. The wait is given a long
// deadline and the signal arrives well inside it, so a machine slow enough
// to make the two race still reports the release rather than a timeout --
// and if the signal lands before the waiter starts waiting, the event is
// signalled when the wait reads it and the answer is the same.
void test_a_wait_is_released_by_another_thread() {
    const std::uint64_t handle = objects::create_event(false, false);
    check(handle != 0, "release: the event is created");

    objects::WaitOutcome seen = objects::WaitOutcome::TimedOut;
    std::thread waiter([&] { seen = objects::wait_one(handle, 5000); });

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    check(objects::set_event(handle), "release: the signal is sent");
    waiter.join();

    check(seen == objects::WaitOutcome::Signalled,
          "release: the waiting thread is released by the signal");
    check(objects::close(handle), "release: and the event is closed");
}

// A wait that nothing signals spends its whole timeout before answering.
//
// The assertion that matters is the second one: an implementation that
// returned `TimedOut` without waiting would satisfy the first, and the
// difference is a program that polls in a loop burning a core instead of
// sleeping.
void test_a_wait_that_times_out_takes_its_time() {
    const std::uint64_t handle = objects::create_event(true, false);
    const auto started = std::chrono::steady_clock::now();
    const objects::WaitOutcome outcome = objects::wait_one(handle, 40);
    const auto spent = std::chrono::steady_clock::now() - started;

    check(outcome == objects::WaitOutcome::TimedOut,
          "timeout: an unsignalled event reports the timeout");
    check(spent >= std::chrono::milliseconds(30),
          "timeout: and the wait spent its timeout rather than returning "
          "early");
    check(objects::close(handle), "timeout: the event is closed");
}

void test_every_fixture_import_resolves() {
    // The union of every import the three fixtures name, in the spelling
    // their import tables use. This list is the API contract: a name added
    // here is a name a program reaches for, and the check below is what
    // notices the runtime missing it.
    const char* kernel32[] = {
        "DeleteCriticalSection",  "EnterCriticalSection",
        "GetEnvironmentVariableA", "GetEnvironmentVariableW",
        "GetLastError",           "GetProcessHeap",
        "GetStdHandle",           "HeapAlloc",
        "HeapFree",               "HeapReAlloc",
        "HeapSize",               "InitializeCriticalSection",
        "IsDBCSLeadByteEx",       "LeaveCriticalSection",
        "MultiByteToWideChar",    "SetEnvironmentVariableA",
        "SetEnvironmentVariableW", "SetUnhandledExceptionFilter",
        "Sleep",                  "TlsGetValue",
        "VirtualProtect",         "VirtualQuery",
        "WideCharToMultiByte",
    };
    const char* msvcrt[] = {
        "__C_specific_handler", "___lc_codepage_func",
        "___mb_cur_max_func",   "__getmainargs",
        "__initenv",            "__iob_func",
        "__set_app_type",       "__setusermatherr",
        "_amsg_exit",           "_cexit",
        "_commode",             "_environ",
        "_errno",               "_fmode",
        "_i64toa",              "_initterm",
        "_itoa",                "_localtime64",
        "_lock",                "_ltoa",
        "_mkgmtime",            "_mktime64",
        "_onexit",              "_putenv",
        "_putenv_s",            "_stricmp",
        "_strlwr",              "_strnicmp",
        "_strupr",              "_ui64toa",
        "_ultoa",               "_unlock",
        "abs",                  "asctime",
        "atof",                 "atoi",
        "atol",                 "bsearch",
        "calloc",               "clock",
        "ctime",                "difftime",
        "div",                  "exit",
        "fprintf",              "fputc",
        "free",                 "fwrite",
        "getenv",               "gmtime",
        "isalpha",              "isdigit",
        "isspace",              "isupper",
        "itoa",                 "labs",
        "ldiv",                 "lldiv",
        "localeconv",           "localtime",
        "malloc",               "mbstowcs",
        "memcmp",               "memcpy",
        "memmove",              "memset",
        "mktime",               "putenv",
        "qsort",                "rand",
        "srand",                "signal",
        "strcat",               "strchr",
        "strcmp",               "strcspn",
        "strerror",             "strftime",
        "strlen",               "strncat",
        "strncmp",              "strncpy",
        "strnlen",              "strpbrk",
        "strrchr",              "strspn",
        "strstr",               "strtod",
        "strtol",               "strtoll",
        "strtoul",              "strtoull",
        "time",                 "tolower",
        "toupper",              "vfprintf",
        "wcschr",               "wcscmp",
        "wcscpy",               "wcsdup",
        "wcslen",               "wcsncmp",
        "wcsncpy",              "wcsnlen",
        "wcsrchr",              "wcsstr",
        "wcstombs",
    };
    const char* user32[] = {
        "wsprintfA", "wsprintfW",
    };

    ExportRegistry registry;
    winabi::register_host_modules(registry);

    check(registry.find("kernel32.dll") != nullptr,
          "kernel32.dll is registered");
    check(registry.find("msvcrt.dll") != nullptr,
          "msvcrt.dll is registered");
    check(registry.find("KERNEL32.DLL") != nullptr,
          "the module name matches without case");

    for (const char* name : kernel32) {
        const ExportLookup found =
            registry.find_by_name("KERNEL32.dll", name, 0);
        if (found.address == 0) {
            std::fprintf(stderr, "  kernel32 miss: %s\n", name);
        }
        check(found.address != 0, "every kernel32 import resolves");
    }
    for (const char* name : msvcrt) {
        const ExportLookup found = registry.find_by_name("msvcrt.dll", name, 0);
        if (found.address == 0) {
            std::fprintf(stderr, "  msvcrt miss: %s\n", name);
        }
        check(found.address != 0, "every msvcrt import resolves");
    }
    for (const char* name : user32) {
        const ExportLookup found =
            registry.find_by_name("USER32.dll", name, 0);
        if (found.address == 0) {
            std::fprintf(stderr, "  user32 miss: %s\n", name);
        }
        check(found.address != 0, "every user32 import resolves");
    }

    // The data imports: `__initenv`, `_commode` and `_fmode` are variables
    // rather than functions, and a registry entry for one is the variable's
    // address. There is no calling convention to bridge, which is exactly
    // why an address is the whole answer.
    const ExportLookup fmode = registry.find_by_name("msvcrt.dll", "_fmode", 0);
    check(fmode.address != 0, "_fmode resolves to its variable");

    // A name the layer does not implement must not resolve, because an
    // import that resolved to nothing would fault with a null in its IAT
    // where a refusal -- or, later, a message -- would have named it.
    //
    // The name is deliberately one no Windows DLL exports. An earlier
    // version of this case named a real API that had not been written yet,
    // which made the assertion a statement about how far the surface had
    // been filled in rather than about the lookup: the day that API was
    // implemented the case started failing, and it said nothing about
    // whether an unknown name is refused.
    const ExportLookup missing = registry.find_by_name(
        "kernel32.dll", "OCC_NoSuchExportExists", 0);
    check(missing.address == 0,
          "an export the layer does not have does not resolve");
}

} // namespace

int main() {
    test_split_basics();
    test_build_known_values();
    test_round_trip();
    test_to_dos_path();
    test_utf_conversion();
    test_multibyte_wide_lengths();
    test_vfprintf_conversions();
    test_heap_semantics();
    test_translate_stream();
    test_crt_computational();
    test_crt_stdio_buffers();
    test_crt_stdio_files();
    test_crt_time_env();
    test_synchronization_objects();
    test_a_wait_is_released_by_another_thread();
    test_a_wait_that_times_out_takes_its_time();
    test_every_fixture_import_resolves();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

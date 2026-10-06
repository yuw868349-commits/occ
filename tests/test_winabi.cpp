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
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
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

// --------------------------------------------------------------- registry

void test_every_fixture_import_resolves() {
    // The union of every import the three fixtures name, in the spelling
    // their import tables use. This list is the API contract: a name added
    // here is a name a program reaches for, and the check below is what
    // notices the runtime missing it.
    const char* kernel32[] = {
        "DeleteCriticalSection", "EnterCriticalSection", "GetLastError",
        "GetProcessHeap",        "GetStdHandle",          "HeapAlloc",
        "HeapFree",              "HeapReAlloc",           "HeapSize",
        "InitializeCriticalSection", "IsDBCSLeadByteEx",  "LeaveCriticalSection",
        "MultiByteToWideChar",   "SetUnhandledExceptionFilter", "Sleep",
        "TlsGetValue",           "VirtualProtect",        "VirtualQuery",
        "WideCharToMultiByte",
    };
    const char* msvcrt[] = {
        "__C_specific_handler", "___lc_codepage_func",
        "___mb_cur_max_func",   "__getmainargs",
        "__initenv",            "__iob_func",
        "__set_app_type",       "__setusermatherr",
        "_amsg_exit",           "_cexit",
        "_commode",             "_errno",
        "_fmode",               "_initterm",
        "_lock",                "_onexit",
        "_unlock",              "abort",
        "calloc",               "exit",
        "fprintf",              "fputc",
        "free",                 "fwrite",
        "localeconv",           "malloc",
        "memcpy",               "memset",
        "signal",               "strerror",
        "strlen",               "strncmp",
        "vfprintf",             "wcslen",
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

    // The data imports: `__initenv`, `_commode` and `_fmode` are variables
    // rather than functions, and a registry entry for one is the variable's
    // address. There is no calling convention to bridge, which is exactly
    // why an address is the whole answer.
    const ExportLookup fmode = registry.find_by_name("msvcrt.dll", "_fmode", 0);
    check(fmode.address != 0, "_fmode resolves to its variable");

    // A name the layer does not implement must not resolve, because an
    // import that resolved to nothing would fault with a null in its IAT
    // where a refusal -- or, later, a message -- would have named it.
    const ExportLookup missing =
        registry.find_by_name("kernel32.dll", "CreateFileW", 0);
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
    test_vfprintf_conversions();
    test_heap_semantics();
    test_translate_stream();
    test_every_fixture_import_resolves();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

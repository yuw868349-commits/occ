// The kernel32 error/format/misc family.
//
// Every expectation below is spelled out rather than derived from the code
// under test, so a wrong answer here is a wrong answer against the Windows
// contract and not a self-consistent one. The message texts and the failure
// codes come from the documented FormatMessage/Beep/SetErrorMode behaviour;
// the exact system message texts were written from the documents because no
// Wine tree was available on this server, and that is the one place a real
// Windows build could disagree about punctuation.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

// The domain's own surface. api.h does not carry these declarations yet --
// the mainline wires the domain in after delivery -- so the test declares
// what it calls, exactly as a guest's import would resolve it.
namespace occ::runtime::winabi {

void add_kernel32_err(ExportList& out);

extern "C" __attribute__((ms_abi)) std::uint32_t k32e_FormatMessageW(
    std::uint32_t flags, const void* source, std::uint32_t message_id,
    std::uint32_t language_id, char16_t* buffer, std::uint32_t size,
    void* arguments) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32e_FormatMessageA(
    std::uint32_t flags, const void* source, std::uint32_t message_id,
    std::uint32_t language_id, char* buffer, std::uint32_t size,
    void* arguments) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32e_GetErrorMode() noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32e_SetErrorMode(
    std::uint32_t mode) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32e_Beep(
    std::uint32_t frequency, std::uint32_t duration_ms) noexcept;

}  // namespace occ::runtime::winabi

namespace {

constexpr std::uint32_t kFormatAllocateBuffer = 0x0100;
constexpr std::uint32_t kFormatIgnoreInserts = 0x0200;
constexpr std::uint32_t kFormatFromString = 0x0400;
constexpr std::uint32_t kFormatFromHmodule = 0x0800;
constexpr std::uint32_t kFormatFromSystem = 0x1000;

int failures = 0;
int checks = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

void check_wide(const std::u16string& got, std::u16string_view want,
                const char* what) {
    ++checks;
    if (got != want) {
        ++failures;
        std::fprintf(stderr, "FAIL %s: got %zu units, want %zu\n", what,
                     got.size(), want.size());
    }
}

void check_narrow(const std::string& got, std::string_view want,
                  const char* what) {
    ++checks;
    if (got != want) {
        ++failures;
        std::fprintf(stderr, "FAIL %s: got %zu bytes, want %zu\n", what,
                     got.size(), want.size());
    }
}

void check_error(std::uint32_t want, const char* what) {
    ++checks;
    const std::uint32_t got = k32_GetLastError();
    if (got != want) {
        ++failures;
        std::fprintf(stderr, "FAIL %s: last error %u, want %u\n", what, got,
                     want);
    }
}

// ---------------------------------------------------------------- registration

void test_registration() {
    ExportList list;
    add_kernel32_err(list);
    check(list.size() == 5, "err: the domain exports five names");
    bool named = true;
    bool addressed = true;
    for (const HostExport& entry : list) {
        if (entry.name.empty()) {
            named = false;
        }
        if (entry.address == 0) {
            addressed = false;
        }
    }
    check(named, "err: every entry has a name");
    check(addressed, "err: every entry has an address");
}

// ----------------------------------------------------------------------- Beep

void test_beep() {
    // Inside the documented 37..32767 Hz range the call succeeds; there is
    // no speaker device here, so success is silent, which is what the same
    // call does on a machine with no sound hardware.
    check(k32e_Beep(800, 1) == 1, "beep: an ordinary tone succeeds");
    check(k32e_Beep(37, 1) == 1, "beep: the low boundary is valid");
    check(k32e_Beep(32767, 1) == 1, "beep: the high boundary is valid");
    check_error(kErrorSuccess, "beep: success leaves no error");

    check(k32e_Beep(36, 1) == 0, "beep: below the range fails");
    check_error(kErrorInvalidParameter, "beep: low tone is a parameter error");
    check(k32e_Beep(32768, 1) == 0, "beep: above the range fails");
    check_error(kErrorInvalidParameter,
                "beep: high tone is a parameter error");
    check(k32e_Beep(0, 1) == 0, "beep: a zero frequency fails");
}

// ----------------------------------------------------------------- error mode

void test_error_mode() {
    // Sequence dependent on purpose: the contract is "returns the previous
    // value", and only an ordered run can see it.
    check(k32e_GetErrorMode() == 0, "errmode: a fresh process has none");
    check(k32e_SetErrorMode(1) == 0,
          "errmode: setting returns the previous mode");
    check(k32e_GetErrorMode() == 1, "errmode: the mode is process state");
    check(k32e_SetErrorMode(0x8000) == 1,
          "errmode: the second set returns the first mode");
    check(k32e_GetErrorMode() == 0x8000, "errmode: the mode tracks the set");
    check(k32e_SetErrorMode(0) == 0x8000,
          "errmode: restoring returns what it replaces");
    check(k32e_GetErrorMode() == 0, "errmode: cleared again");
}

// ------------------------------------------------------- FormatMessage helpers

// Runs the wide call with a caller-owned buffer and answers the composed
// text; the return value is asserted separately by the caller.
struct WideRun {
    std::uint32_t ret = 0;
    std::u16string text;
};

WideRun format_wide(std::uint32_t flags, std::u16string_view source,
                    std::uint32_t message_id, char16_t* buffer,
                    std::uint32_t size, void* arguments) {
    WideRun run;
    std::u16string owned;
    const char16_t* fmt = nullptr;
    if ((flags & kFormatFromString) != 0 && !source.empty()) {
        owned = std::u16string(source);
        fmt = owned.c_str();
    }
    run.ret = k32e_FormatMessageW(flags, fmt, message_id, 0, buffer, size,
                                  arguments);
    if (run.ret != 0 && buffer != nullptr &&
        (flags & kFormatAllocateBuffer) == 0) {
        run.text.assign(buffer, run.ret);
    }
    return run;
}

void test_format_system_messages() {
    char16_t buf[128];

    // A table hit: the documented text, and the return is the character
    // count without the terminator.
    const WideRun hit = format_wide(kFormatFromSystem, u"", 2, buf, 128,
                                    nullptr);
    check(hit.ret == std::char_traits<char16_t>::length(
                         u"The system cannot find the file specified."),
          "formatW: the return is the length, terminator excluded");
    check_wide(hit.text,
               u"The system cannot find the file specified.",
               "formatW: message 2 is the file-not-found text");
    check_wide(format_wide(kFormatFromSystem, u"", 5, buf, 128, nullptr).text,
               u"Access is denied.", "formatW: message 5 is access denied");

    // A table miss: Windows answers with the diagnosis text rather than a
    // bare failure.
    const WideRun miss = format_wide(kFormatFromSystem, u"", 0x1234, buf, 128,
                                     nullptr);
    check(miss.ret != 0, "formatW: an unknown id answers the fallback text");
    check_wide(miss.text,
               u"The system cannot find message text for message number "
               u"0x1234 in the message file for Application.",
               "formatW: the fallback names the number");

    // IGNORE_INSERTS copies the insert sequence through unchanged, which is
    // the only way to read message 193's template without an argument.
    const WideRun raw =
        format_wide(kFormatFromSystem | kFormatIgnoreInserts, u"", 193, buf,
                    128, nullptr);
    check_wide(raw.text, u"%1 is not a valid Win32 application.",
               "formatW: ignore-inserts leaves the sequence in place");
}

void test_format_from_string() {
    char16_t buf[128];

    // Positional inserts, in order.
    const char16_t* one = u"hello";
    const char16_t* two = u"world";
    std::uint64_t slots[2] = {
        reinterpret_cast<std::uint64_t>(one),
        reinterpret_cast<std::uint64_t>(two),
    };
    void* args = slots;
    const WideRun pair =
        format_wide(kFormatFromString, u"%1 %2", 0, buf, 128, &args);
    check(pair.ret == 11, "formatW: two inserts compose to eleven units");
    check_wide(pair.text, u"hello world",
               "formatW: %1 %2 substitutes in order");

    // Out of order and repeated: the insert number, not the position in the
    // text, picks the argument.
    const WideRun swapped =
        format_wide(kFormatFromString, u"%2 %2 %1", 0, buf, 128, &args);
    check_wide(swapped.text, u"world world hello",
               "formatW: inserts are positional, not sequential");

    // An integer insert goes through the argument slot's low half.
    std::uint64_t num_slots[1] = {42};
    void* num_args = num_slots;
    check_wide(format_wide(kFormatFromString, u"%1!d!", 0, buf, 128, &num_args)
                   .text,
               u"42", "formatW: %1!d! formats the slot as a decimal");
    check_wide(
        format_wide(kFormatFromString, u"%1!x!", 0, buf, 128, &num_args).text,
        u"2a", "formatW: %1!x! formats the slot as hexadecimal");

    // A width on a string insert.
    std::uint64_t pad_slots[1] = {reinterpret_cast<std::uint64_t>(one)};
    void* pad_args = pad_slots;
    check_wide(
        format_wide(kFormatFromString, u"%1!-8s!|", 0, buf, 128, &pad_args)
            .text,
        u"hello   |", "formatW: a negative width left-aligns");
    check_wide(
        format_wide(kFormatFromString, u"%1!8s!|", 0, buf, 128, &pad_args)
            .text,
        u"   hello|", "formatW: a plain width right-aligns");

    // The escapes.
    check_wide(format_wide(kFormatFromString, u"a%%b", 0, buf, 128, &args)
                   .text,
               u"a%b", "formatW: %% is one percent");
    check_wide(format_wide(kFormatFromString, u"hi%!now", 0, buf, 128, &args)
                   .text,
               u"hi!now", "formatW: %! is one exclamation mark");
    check_wide(format_wide(kFormatFromString, u"a%nb", 0, buf, 128, &args)
                   .text,
               u"a\nb", "formatW: %n is a newline");
    check_wide(
        format_wide(kFormatFromString, u"keep%0drop", 0, buf, 128, &args)
            .text,
        u"keep", "formatW: %0 terminates and drops the rest");
    check_wide(
        format_wide(kFormatFromString, u"100%% of %q", 0, buf, 128, &args)
            .text,
        u"100% of %q", "formatW: an unknown sequence goes through as-is");

    // An 'S' insert names a narrow string from the wide call.
    const char* narrow_text = "ansi";
    std::uint64_t s_slots[1] = {reinterpret_cast<std::uint64_t>(narrow_text)};
    void* s_args = s_slots;
    check_wide(format_wide(kFormatFromString, u"%1!S!", 0, buf, 128, &s_args)
                   .text,
               u"ansi", "formatW: %1!S! reads a narrow string");

    // A null string argument prints like the CRT's, not as a crash.
    std::uint64_t null_slots[1] = {0};
    void* null_args = null_slots;
    check_wide(format_wide(kFormatFromString, u"[%1]", 0, buf, 128, &null_args)
                   .text,
               u"[(null)]", "formatW: a null string insert prints (null)");

    // A character insert.
    std::uint64_t char_slots[1] = {'X'};
    void* char_args = char_slots;
    check_wide(format_wide(kFormatFromString, u"%1!c!", 0, buf, 128, &char_args)
                   .text,
               u"X", "formatW: %1!c! formats the slot as a character");
}

void test_format_failures() {
    char16_t buf[128];

    // An insert with no argument list is a parameter error, not a crash.
    const WideRun no_args =
        format_wide(kFormatFromString, u"%1", 0, buf, 128, nullptr);
    check(no_args.ret == 0, "formatW: an insert without arguments fails");
    check_error(kErrorInvalidParameter,
                "formatW: a missing argument list is ERROR_INVALID_PARAMETER");

    // A buffer that cannot hold the text plus its terminator is refused and
    // left untouched. The four inserts get four real slots so the expansion
    // itself is well formed and only the write is refused.
    const char16_t* filler = u"x";
    std::uint64_t fill[4] = {
        reinterpret_cast<std::uint64_t>(filler),
        reinterpret_cast<std::uint64_t>(filler),
        reinterpret_cast<std::uint64_t>(filler),
        reinterpret_cast<std::uint64_t>(filler),
    };
    void* fill_args = fill;
    char16_t small[4];
    const WideRun tight =
        format_wide(kFormatFromString, u"%1 %2 %3 %4", 0, small, 4,
                    &fill_args);
    check(tight.ret == 0, "formatW: a small buffer fails");
    check_error(kErrorInsufficientBuffer,
                "formatW: a small buffer is ERROR_INSUFFICIENT_BUFFER");

    // FROM_HMODULE: refused -- there are no module message tables here.
    check(k32e_FormatMessageW(kFormatFromHmodule, nullptr, 2, 0, buf, 128,
                              nullptr) == 0,
          "formatW: FROM_HMODULE is refused");
    check_error(kErrorInvalidParameter,
                "formatW: FROM_HMODULE is ERROR_INVALID_PARAMETER");

    // Neither source named.
    check(k32e_FormatMessageW(0, nullptr, 2, 0, buf, 128, nullptr) == 0,
          "formatW: no source flag fails");
    check_error(kErrorInvalidParameter,
                "formatW: no source flag is ERROR_INVALID_PARAMETER");

    // A null source with FROM_STRING.
    check(k32e_FormatMessageW(kFormatFromString, nullptr, 0, 0, buf, 128,
                              nullptr) == 0,
          "formatW: a null format string fails");

    // A null buffer.
    check(k32e_FormatMessageW(kFormatFromSystem, nullptr, 2, 0, nullptr, 128,
                              nullptr) == 0,
          "formatW: a null buffer fails");
}

void test_format_allocate_buffer() {
    // ALLOCATE_BUFFER: lpBuffer is a pointer to a pointer variable, and the
    // block it receives must be one LocalFree can release -- which is why
    // it comes from the heap facility, not from a raw malloc.
    char16_t* allocated = nullptr;
    std::uint64_t slots[1] = {42};
    void* args = slots;
    const std::uint32_t ret = k32e_FormatMessageW(
        kFormatFromString | kFormatAllocateBuffer, u"n=%1!d!", 0, 0,
        reinterpret_cast<char16_t*>(&allocated), 0, &args);
    check(ret == 4, "formatW: allocate-buffer answers the length");
    check(allocated != nullptr, "formatW: allocate-buffer hands out a block");
    if (allocated != nullptr) {
        check_wide(std::u16string(allocated), u"n=42",
                   "formatW: the allocated block holds the text");
        check(heap_free(allocated), "formatW: the block is heap-freeable");
    }

    // The narrow call allocates bytes.
    char* allocated_a = nullptr;
    const std::uint32_t ret_a = k32e_FormatMessageA(
        kFormatFromSystem | kFormatAllocateBuffer, nullptr, 6, 0,
        reinterpret_cast<char*>(&allocated_a), 0, nullptr);
    check(ret_a == static_cast<std::uint32_t>(
                       std::char_traits<char>::length("The handle is "
                                                      "invalid.")),
          "formatA: allocate-buffer answers the byte count");
    check(allocated_a != nullptr, "formatA: allocate-buffer hands out a block");
    if (allocated_a != nullptr) {
        check_narrow(std::string(allocated_a), "The handle is invalid.",
                     "formatA: the allocated block holds the text");
        check(heap_free(allocated_a), "formatA: the block is heap-freeable");
    }
}

void test_format_width() {
    char16_t buf[128];
    // The low eight flag bits name a maximum line width; the break replaces
    // the space that fits.
    const WideRun wrapped =
        format_wide(kFormatFromString | 7, u"aaa bbb ccc", 0, buf, 128,
                    nullptr);
    check_wide(wrapped.text, u"aaa bbb\nccc",
               "formatW: a width of 7 wraps at the last fitting space");
}

void test_format_narrow() {
    char buf[128];

    // The narrow call answers the same texts in bytes: one conversion each
    // way around the one wide implementation, and the return counts bytes.
    std::uint32_t ret = k32e_FormatMessageA(kFormatFromSystem, nullptr, 5, 0,
                                            buf, sizeof(buf), nullptr);
    check(ret == std::char_traits<char>::length("Access is denied."),
          "formatA: the return is the byte count");
    check_narrow(std::string(buf, ret), "Access is denied.",
                 "formatA: message 5 matches the wide text");

    // The same string inserts, narrow spelling.
    const char* one = "hello";
    const char* two = "world";
    std::uint64_t slots[2] = {
        reinterpret_cast<std::uint64_t>(one),
        reinterpret_cast<std::uint64_t>(two),
    };
    void* args = slots;
    ret = k32e_FormatMessageA(kFormatFromString, "%1 %2", 0, 0, buf,
                              sizeof(buf), &args);
    check_narrow(std::string(buf, ret), "hello world",
                 "formatA: %1 %2 substitutes like the wide call");

    // The A and W answers agree for a same-shaped call, which is the pairing
    // the two entry points promise.
    char16_t wbuf[128];
    const char16_t* wone = u"hello";
    const char16_t* wtwo = u"world";
    std::uint64_t wslots[2] = {
        reinterpret_cast<std::uint64_t>(wone),
        reinterpret_cast<std::uint64_t>(wtwo),
    };
    void* wargs = wslots;
    const std::uint32_t wret =
        k32e_FormatMessageW(kFormatFromString, u"%1 %2", 0, 0, wbuf, 128,
                            &wargs);
    std::string as_narrow;
    if (utf16_to_utf8(std::u16string_view(wbuf, wret), as_narrow)) {
        check_narrow(std::string(buf, ret), as_narrow,
                     "formatA/W: the pair answers the same text");
    } else {
        check(false, "formatA/W: the wide answer converts");
    }

    // The narrow fallback names the number too.
    ret = k32e_FormatMessageA(kFormatFromSystem, nullptr, 0x2a, 0, buf,
                              sizeof(buf), nullptr);
    check_narrow(std::string(buf, ret),
                 "The system cannot find message text for message number "
                 "0x2a in the message file for Application.",
                 "formatA: the fallback names the number");

    // Narrow failures mirror the wide ones.
    check(k32e_FormatMessageA(kFormatFromHmodule, nullptr, 2, 0, buf,
                              sizeof(buf), nullptr) == 0,
          "formatA: FROM_HMODULE is refused");
    check(k32e_FormatMessageA(kFormatFromSystem, nullptr, 5, 0, buf, 4,
                              nullptr) == 0,
          "formatA: a small buffer fails");
    check_error(kErrorInsufficientBuffer,
                "formatA: a small buffer is ERROR_INSUFFICIENT_BUFFER");
}

}  // namespace

int main() {
    test_registration();
    test_beep();
    test_error_mode();
    test_format_system_messages();
    test_format_from_string();
    test_format_failures();
    test_format_allocate_buffer();
    test_format_width();
    test_format_narrow();

    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

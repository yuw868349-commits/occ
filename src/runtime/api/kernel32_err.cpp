// The kernel32 error/format/misc family: `Beep`, the `FormatMessage` pair,
// and the process error mode.
//
// The reference for the behaviour below is the FormatMessage contract in the
// Microsoft documents plus Wine's `dlls/kernelbase/format_msg.c`, which this
// server does not carry; the message texts and the exact failure codes are
// therefore written from the documented behaviour and marked as inferred in
// the domain report rather than checked against Wine source.
//
// Two decisions are worth stating up front:
//
//   * `FORMAT_MESSAGE_FROM_HMODULE` is refused. A module message table needs
//     the module's `.rsrc` message resources and this runtime has no reader
//     for them; answering with a made-up text would be worse than refusing,
//     because a caller that gets text back believes it.
//
//   * `FORMAT_MESSAGE_ALLOCATE_BUFFER` allocates through `heap_alloc`, the
//     same facility `LocalAlloc` in the memory domain hands out, so the
//     block a caller receives can be released with `LocalFree`/`HeapFree`
//     the way the documented contract requires. A bare `malloc` here would
//     produce a pointer `LocalFree` cannot recognise.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

#include <cerrno>
#include <time.h>

namespace occ::runtime::winabi {
namespace {

// ------------------------------------------------------------- flag constants

constexpr std::uint32_t kFormatAllocateBuffer = 0x0100;
constexpr std::uint32_t kFormatIgnoreInserts = 0x0200;
constexpr std::uint32_t kFormatFromString = 0x0400;
constexpr std::uint32_t kFormatFromHmodule = 0x0800;
constexpr std::uint32_t kFormatFromSystem = 0x1000;
// The low eight bits of the flags are the maximum output line width; zero
// means no wrapping.
constexpr std::uint32_t kFormatWidthMask = 0x00FF;

constexpr std::uint32_t kErrorSharingViolation = 32;
constexpr std::uint32_t kErrorFileExists = 80;

// ---------------------------------------------------------- the message table
//
// A subset of kernel32's own system message table: the codes the other API
// domains in this runtime actually produce, keyed by the same named
// constants where api_common.h carries one. The texts are the documented
// Windows texts; they were written from the documents, not read out of a
// message resource, so an exact-punctuation mismatch with a real Windows
// build is possible and was accepted.

struct SystemMessage {
    std::uint32_t code;
    const char16_t* text;
};

constexpr SystemMessage kSystemMessages[] = {
    {kErrorInvalidFunction, u"Incorrect function."},
    {kErrorFileNotFound, u"The system cannot find the file specified."},
    {kErrorPathNotFound, u"The system cannot find the path specified."},
    {kErrorTooManyOpenFiles, u"The system cannot open the file."},
    {kErrorAccessDenied, u"Access is denied."},
    {kErrorInvalidHandle, u"The handle is invalid."},
    {kErrorNotEnoughMemory,
     u"Not enough storage is available to process this command."},
    {kErrorNoMoreFiles, u"There are no more files."},
    {kErrorSharingViolation,
     u"The process cannot access the file because it is being used by "
     u"another process."},
    {kErrorNotSupported, u"The request is not supported."},
    {kErrorFileExists, u"The file exists."},
    {kErrorInvalidParameter, u"The parameter is incorrect."},
    {kErrorCallNotImplemented,
     u"This function is not supported on this system."},
    {kErrorInsufficientBuffer,
     u"The data area passed to a system call is too small."},
    {kErrorDirectoryNotEmpty, u"The directory is not empty."},
    {kErrorBusy, u"The requested resource is in use."},
    {kErrorAlreadyExists,
     u"Cannot create a file when that file already exists."},
    {kErrorBadExeFormat, u"%1 is not a valid Win32 application."},
    {kErrorNoMoreItems, u"No more data is available."},
    {kErrorInvalidAddress, u"Attempt to access invalid address."},
    {kErrorNotFound, u"Element not found."},
};

constexpr std::size_t kSystemMessageCount =
    sizeof(kSystemMessages) / sizeof(kSystemMessages[0]);

// The file a system message is looked up in when a caller does not name a
// module, which is the answer Windows' own message 317 gives for this
// context.
constexpr const char* kFallbackMessageFile = "Application";

// The lookup, and the documented answer when the table misses: Windows
// reports the miss as text naming the message number rather than as a bare
// failure, so a caller printing the result prints a diagnosis.
[[nodiscard]] bool system_message_text(std::uint32_t message_id,
                                       std::u16string& out) noexcept {
    for (std::size_t i = 0; i < kSystemMessageCount; ++i) {
        if (kSystemMessages[i].code == message_id) {
            out = kSystemMessages[i].text;
            return true;
        }
    }
    char buf[192];
    const int written = std::snprintf(
        buf, sizeof(buf),
        "The system cannot find message text for message number 0x%x in the "
        "message file for %s.",
        message_id, kFallbackMessageFile);
    if (written <= 0) {
        set_last_error(kErrorInvalidParameter);
        return false;
    }
    std::u16string wide;
    if (!narrow_in(std::string_view(buf, static_cast<std::size_t>(written)),
                   wide)
             .converted) {
        set_last_error(kErrorInvalidParameter);
        return false;
    }
    out = std::move(wide);
    return true;
}

// ---------------------------------------------------------- insert expansion
//
// `Arguments` is a pointer to the caller's `va_list`. Under the guest's
// Microsoft x64 ABI a `va_list` is a pointer into the argument save area,
// one 8-byte slot per argument -- the same shape `host_vformat` consumes --
// so `*(void**)Arguments` is the base of the slot array and insert `n` is
// slot `n-1`.

constexpr std::size_t kSlotBytes = 8;

// Appends `text` padded to `width` with spaces, left-aligned when `left`.
void append_padded(std::u16string& out, const std::u16string& text, bool left,
                   std::uint32_t width) {
    const std::size_t count =
        width > text.size() ? static_cast<std::size_t>(width) - text.size() : 0;
    if (left) {
        out += text;
        out.append(count, u' ');
    } else {
        out.append(count, u' ');
        out += text;
    }
}

// True when the character is an ASCII letter.
[[nodiscard]] bool is_ascii_alpha(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

// Formats insert number `index` (1-based). `spec` is the text between the
// two `!` marks of the insert's format, with `!!` already folded to `!`,
// empty when the insert had no format. Returns false after setting the last
// error.
[[nodiscard]] bool append_insert(std::u16string& out, std::uint32_t index,
                                 const std::string& spec, bool wide_call,
                                 const std::uint8_t* slots) noexcept {
    if (slots == nullptr) {
        // An insert needs an argument and the caller supplied none; Windows
        // answers "parameter incorrect" rather than printing a guess.
        set_last_error(kErrorInvalidParameter);
        return false;
    }
    const std::uint8_t* slot = slots + static_cast<std::size_t>(index - 1) * kSlotBytes;

    // The conversion is the last letter of the spec; a spec without one
    // means the insert is a string, which is the documented default.
    char conv = 's';
    for (auto it = spec.rbegin(); it != spec.rend(); ++it) {
        if (is_ascii_alpha(*it)) {
            conv = *it;
            break;
        }
    }

    // A character insert: one argument, one character, no bridge needed.
    if (conv == 'c' || conv == 'C') {
        std::uint64_t raw = 0;
        std::memcpy(&raw, slot, sizeof(raw));
        const bool native_wide = (conv == 'c') == wide_call;
        if (native_wide) {
            out.push_back(static_cast<char16_t>(raw & 0xFFFFu));
            return true;
        }
        const char narrow = static_cast<char>(raw & 0xFFu);
        std::u16string piece;
        if (!narrow_in(std::string_view(&narrow, 1), piece).converted) {
            set_last_error(kErrorInvalidParameter);
            return false;
        }
        out += piece;
        return true;
    }

    // Integer inserts go through the printf bridge, which consumes the slot
    // with the guest's own argument layout. The bridge answers -1 for a
    // conversion it does not translate (floating point among them); failing
    // the call beats printing a wrong number.
    if (conv == 'd' || conv == 'i' || conv == 'u' || conv == 'x' ||
        conv == 'X' || conv == 'o') {
        std::string pf = "%";
        for (const char c : spec) {
            // Length modifiers are lies here: every integer slot is a full
            // 8-byte slot and the bridge already reads the right half.
            if (c == 'h' || c == 'l' || c == 'w' || c == 'L') {
                continue;
            }
            pf.push_back(c);
        }
        std::string piece;
        if (host_vformat(piece, pf.c_str(), slot) < 0) {
            set_last_error(kErrorInvalidParameter);
            return false;
        }
        std::u16string wide;
        if (!narrow_in(piece, wide).converted) {
            set_last_error(kErrorInvalidParameter);
            return false;
        }
        out += wide;
        return true;
    }

    // Everything else is the documented default: a string. `s` names a
    // string in the width of this call, `S` names the other width.
    std::uint64_t raw = 0;
    std::memcpy(&raw, slot, sizeof(raw));
    if (raw == 0) {
        out += u"(null)";
        return true;
    }
    const bool native_wide = (conv != 'S') == wide_call;
    std::u16string piece;
    if (native_wide) {
        const char16_t* text = reinterpret_cast<const char16_t*>(
            static_cast<std::uintptr_t>(raw));
        piece = std::u16string_view(text);
    } else {
        const char* text = reinterpret_cast<const char*>(
            static_cast<std::uintptr_t>(raw));
        if (!narrow_in(std::string_view(text), piece).converted) {
            set_last_error(kErrorInvalidParameter);
            return false;
        }
    }

    // The width the spec asked for, if any: an optional '-' then digits.
    std::size_t at = 0;
    bool left = false;
    if (at < spec.size() && spec[at] == '-') {
        left = true;
        ++at;
    }
    std::uint32_t width = 0;
    while (at < spec.size() && spec[at] >= '0' && spec[at] <= '9') {
        width = width * 10u + static_cast<std::uint32_t>(spec[at] - '0');
        ++at;
    }
    append_padded(out, piece, left, width);
    return true;
}

// Expands the message text. `wide_call` says which width `s`/`S` name.
[[nodiscard]] bool expand_message(bool ignore_inserts, bool wide_call,
                                  std::u16string_view fmt, void* arguments,
                                  std::u16string& out) noexcept {
    if (ignore_inserts) {
        // Insert sequences are copied through unchanged, which is what the
        // flag is for: a caller that only wants the text around the inserts.
        out.append(fmt);
        return true;
    }

    const std::uint8_t* slots = nullptr;
    bool resolved = false;
    const auto slot_base = [&]() -> const std::uint8_t* {
        if (!resolved) {
            resolved = true;
            if (arguments != nullptr) {
                slots = static_cast<const std::uint8_t*>(
                    *static_cast<void* const*>(arguments));
            }
        }
        return slots;
    };

    const std::size_t n = fmt.size();
    std::size_t i = 0;
    while (i < n) {
        const char16_t c = fmt[i];
        if (c != u'%') {
            out.push_back(c);
            ++i;
            continue;
        }
        if (i + 1 >= n) {
            // A trailing percent with nothing after it: Windows copies it.
            out.push_back(u'%');
            break;
        }
        const char16_t d = fmt[i + 1];
        if (d == u'%') {
            out.push_back(u'%');
            i += 2;
            continue;
        }
        if (d == u'!') {
            // The escape for a literal exclamation mark.
            out.push_back(u'!');
            i += 2;
            continue;
        }
        if (d == u'n') {
            out.push_back(u'\n');
            i += 2;
            continue;
        }
        if (d == u'0') {
            // %0 ends the message; anything after it is dropped and no
            // trailing newline is added.
            return true;
        }
        if (d < u'1' || d > u'9') {
            // Not an insert sequence: both characters go through as they
            // are, which is what Windows does with an unknown one.
            out.push_back(u'%');
            out.push_back(d);
            i += 2;
            continue;
        }

        std::uint32_t number = static_cast<std::uint32_t>(d - u'0');
        std::size_t j = i + 2;
        if (j < n && fmt[j] >= u'0' && fmt[j] <= u'9') {
            number = number * 10u + static_cast<std::uint32_t>(fmt[j] - u'0');
            ++j;
        }

        std::string spec;
        std::size_t after = j;
        if (j < n && fmt[j] == u'!') {
            std::size_t k = j + 1;
            bool closed = false;
            while (k < n) {
                if (fmt[k] == u'!') {
                    if (k + 1 < n && fmt[k + 1] == u'!') {
                        spec.push_back('!');
                        k += 2;
                        continue;
                    }
                    closed = true;
                    ++k;
                    break;
                }
                spec.push_back(static_cast<char>(fmt[k]));
                ++k;
            }
            if (!closed) {
                // An unclosed `!` is literal text: the `%nn` goes through
                // as it is and the `!` is left for the following passes.
                out.append(fmt.substr(i, j - i));
                i = j;
                continue;
            }
            after = k;
        }
        // An insert with no format at all is still an insert; its spec is
        // then empty and the documented default, a string, applies.
        if (!append_insert(out, number, spec, wide_call, slot_base())) {
            return false;
        }
        i = after;
    }
    return true;
}

// ------------------------------------------------------------ width wrapping
//
// The eight low flag bits name a maximum line width. Lines are broken at
// the last space that keeps them within it, or at the width when a line has
// none, which is the documented behaviour; the break replaces the space.
void wrap_lines(std::u16string& text, std::uint32_t width) {
    std::u16string out;
    std::size_t start = 0;
    while (start <= text.size()) {
        std::size_t end = text.find(u'\n', start);
        if (end == std::u16string::npos) {
            end = text.size();
        }
        std::size_t line = start;
        while (end - line > width) {
            // The break goes at the last space within the width, the space
            // itself consumed; a line with none is cut at the width.
            std::size_t brk = line + width;
            bool broke_at_space = false;
            for (std::size_t k = line + width; k > line; --k) {
                if (text[k] == u' ') {
                    brk = k;
                    broke_at_space = true;
                    break;
                }
            }
            out.append(text, line, brk - line);
            out.push_back(u'\n');
            line = broke_at_space ? brk + 1 : brk;
        }
        out.append(text, line, end - line);
        if (end == text.size()) {
            break;
        }
        out.push_back(u'\n');
        start = end + 1;
    }
    text = std::move(out);
}

// ------------------------------------------------------------- result writers

// Writes the composed wide text into the caller's arrangement. With
// ALLOCATE_BUFFER the buffer parameter is a pointer to a pointer variable
// and receives a block the caller releases with `LocalFree`.
[[nodiscard]] std::uint32_t write_wide(const std::u16string& text,
                                       bool allocate, char16_t* buffer,
                                       std::uint32_t size) noexcept {
    if (buffer == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint64_t needed = static_cast<std::uint64_t>(text.size()) + 1;
    if (allocate) {
        // The flags' own nSize is a minimum for this mode; the text decides
        // the real size. heap_alloc so a guest's LocalFree recognises it.
        void* block = heap_alloc(
            0, needed * static_cast<std::uint64_t>(sizeof(char16_t)));
        if (block == nullptr) {
            set_last_error(kErrorNotEnoughMemory);
            return 0;
        }
        auto* out = static_cast<char16_t*>(block);
        std::memcpy(out, text.data(), text.size() * sizeof(char16_t));
        out[text.size()] = u'\0';
        *reinterpret_cast<char16_t**>(buffer) = out;
        return static_cast<std::uint32_t>(text.size());
    }
    if (static_cast<std::uint64_t>(size) < needed) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    std::memcpy(buffer, text.data(), text.size() * sizeof(char16_t));
    buffer[text.size()] = u'\0';
    return static_cast<std::uint32_t>(text.size());
}

// The narrow writer: the composed wide text converted once, then the same
// two arrangements. The count is bytes, because a TCHAR is a byte here.
[[nodiscard]] std::uint32_t write_narrow(const std::u16string& text,
                                         bool allocate, char* buffer,
                                         std::uint32_t size) noexcept {
    if (buffer == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string narrow;
    if (!narrow_out(text, narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint64_t needed = static_cast<std::uint64_t>(narrow.size()) + 1;
    if (allocate) {
        void* block = heap_alloc(0, needed);
        if (block == nullptr) {
            set_last_error(kErrorNotEnoughMemory);
            return 0;
        }
        auto* out = static_cast<char*>(block);
        std::memcpy(out, narrow.data(), narrow.size());
        out[narrow.size()] = '\0';
        *reinterpret_cast<char**>(buffer) = out;
        return static_cast<std::uint32_t>(narrow.size());
    }
    if (static_cast<std::uint64_t>(size) < needed) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    std::memcpy(buffer, narrow.data(), narrow.size());
    buffer[narrow.size()] = '\0';
    return static_cast<std::uint32_t>(narrow.size());
}

// ------------------------------------------------------------ the error mode

// The process error mode, four documented bits of it. One value per
// process, and this process runs one guest on one thread, so a plain
// variable is the whole of the storage; the guest's own TEB is not the
// place for it because the mode outlives no TEB and is read by calls that
// never touch one.

std::uint32_t g_error_mode = 0;

}  // namespace

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint32_t k32e_FormatMessageW(
    std::uint32_t flags, const void* source, std::uint32_t message_id,
    std::uint32_t language_id, char16_t* buffer, std::uint32_t size,
    void* arguments) noexcept {
    // One language is provided and it answers for every language id, which
    // is the neutral-language answer a message table with a single entry
    // gives.
    (void)language_id;

    if ((flags & kFormatFromHmodule) != 0) {
        // No module message tables exist here; see the file comment.
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const bool from_string = (flags & kFormatFromString) != 0;
    const bool from_system = (flags & kFormatFromSystem) != 0;
    if (!from_string && !from_system) {
        // Neither source named: Windows refuses rather than guessing one.
        set_last_error(kErrorInvalidParameter);
        return 0;
    }

    std::u16string_view fmt;
    std::u16string owned;
    if (from_string) {
        // FROM_STRING wins when both are set, which is the order Wine's
        // implementation answers in.
        if (source == nullptr) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        fmt = std::u16string_view(static_cast<const char16_t*>(source));
    } else {
        if (!system_message_text(message_id, owned)) {
            return 0;
        }
        fmt = owned;
    }

    std::u16string text;
    if (!expand_message((flags & kFormatIgnoreInserts) != 0, true, fmt,
                        arguments, text)) {
        return 0;
    }
    const std::uint32_t width = flags & kFormatWidthMask;
    if (width != 0) {
        wrap_lines(text, width);
    }
    return write_wide(text, (flags & kFormatAllocateBuffer) != 0, buffer,
                      size);
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32e_FormatMessageA(
    std::uint32_t flags, const void* source, std::uint32_t message_id,
    std::uint32_t language_id, char* buffer, std::uint32_t size,
    void* arguments) noexcept {
    (void)language_id;

    if ((flags & kFormatFromHmodule) != 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const bool from_string = (flags & kFormatFromString) != 0;
    const bool from_system = (flags & kFormatFromSystem) != 0;
    if (!from_string && !from_system) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }

    // The narrow call converts in, runs the one wide expansion, converts
    // out; it is the same function with different spellings, not a second
    // implementation.
    std::u16string fmt;
    if (from_string) {
        if (source == nullptr) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        if (!narrow_in(std::string_view(static_cast<const char*>(source)),
                       fmt)
                 .converted) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
    } else if (!system_message_text(message_id, fmt)) {
        return 0;
    }

    std::u16string text;
    if (!expand_message((flags & kFormatIgnoreInserts) != 0, false, fmt,
                        arguments, text)) {
        return 0;
    }
    const std::uint32_t width = flags & kFormatWidthMask;
    if (width != 0) {
        wrap_lines(text, width);
    }
    return write_narrow(text, (flags & kFormatAllocateBuffer) != 0, buffer,
                        size);
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32e_GetErrorMode() noexcept {
    // The mode is a plain fact about the process, not the result of a call;
    // Windows leaves the last error alone here and so does this.
    return g_error_mode;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32e_SetErrorMode(
    std::uint32_t mode) noexcept {
    // The answer is the mode that was in effect, not the one just set --
    // the documented contract, and the one a caller that restores a mode
    // depends on. Bits outside the four documented ones are stored as they
    // came, which is what Windows stores.
    const std::uint32_t previous = g_error_mode;
    g_error_mode = mode;
    return previous;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32e_Beep(
    std::uint32_t frequency, std::uint32_t duration_ms) noexcept {
    // The same validation Windows does: a tone outside the speaker's range
    // is a parameter error, not a beep at a clipped pitch.
    if (frequency < 0x25 || frequency > 0x7FFF) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The call is synchronous on Windows: it returns when the tone is over.
    // The tone itself is not sounded -- there is no speaker device on this
    // host and reaching for one would reach the machine's real one -- so
    // the duration passes as silence, which is what the same call does on
    // a machine with no sound hardware.
    if (duration_ms != 0) {
        struct timespec req {};
        req.tv_sec = static_cast<time_t>(duration_ms / 1000u);
        req.tv_nsec = static_cast<long>(duration_ms % 1000u) * 1000000L;
        while (::nanosleep(&req, &req) == -1 && errno == EINTR) {
        }
    }
    set_last_error(0);
    return 1;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void add_kernel32_err(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("Beep", reinterpret_cast<void*>(&k32e_Beep));
    e("FormatMessageA", reinterpret_cast<void*>(&k32e_FormatMessageA));
    e("FormatMessageW", reinterpret_cast<void*>(&k32e_FormatMessageW));
    e("GetErrorMode", reinterpret_cast<void*>(&k32e_GetErrorMode));
    e("SetErrorMode", reinterpret_cast<void*>(&k32e_SetErrorMode));
}

}  // namespace occ::runtime::winabi

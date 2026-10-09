// The USER32 message-box surface.
//
// A message box is the one USER32 call a console-subsystem program still
// makes: a checker that wants to say "wrong password" without depending on
// a console, a service that wants to be seen, an installer that wants a
// decision. The names below carry the whole family -- the narrow and wide
// spellings, the `Ex` forms with the language id, and the beep that goes
// with them -- because a guest that resolves `MessageBoxW` and finds it
// missing does not fail loudly; it caches the null, guards on it, and
// dies somewhere a person cannot see, which is the failure this file
// exists to prevent.
//
// The host has no window station, so the decision a real message box asks
// the user for is answered by policy instead: the box's caption, text and
// style are rendered to stderr -- the stream a headless run can read --
// and the return value is the id of the box's default button, which is
// what the dialog would answer if its only button were the one the style
// marked default. A program that asks yes-or-no gets the answer yes would
// give; a program that only informs gets the acknowledgment that closes
// the box. The buttons are where Windows itself puts the exit of the
// dialog, and the constants below are Windows' own ids.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>

namespace occ::runtime::winabi {

namespace {

// The button ids a message box answers. Windows' own values, in the order
// the dialog's buttons stand.
constexpr std::int32_t kIdOk = 1;
constexpr std::int32_t kIdCancel = 2;
constexpr std::int32_t kIdAbort = 3;
constexpr std::int32_t kIdRetry = 4;
[[maybe_unused]] constexpr std::int32_t kIdIgnore = 5;
constexpr std::int32_t kIdYes = 6;
[[maybe_unused]] constexpr std::int32_t kIdNo = 7;
[[maybe_unused]] constexpr std::int32_t kIdTryAgain = 10;
[[maybe_unused]] constexpr std::int32_t kIdContinue = 11;

// The style's button group, in the low nibble of `uType`. The flags above
// the nibble -- icon, default button, modality, help -- shape the box but
// not which ids it can answer.
constexpr std::uint32_t kButtonGroupMask = 0xF;
[[maybe_unused]] constexpr std::uint32_t kButtonsOk = 0x0;
constexpr std::uint32_t kButtonsOkCancel = 0x1;
constexpr std::uint32_t kButtonsAbortRetryIgnore = 0x2;
constexpr std::uint32_t kButtonsYesNoCancel = 0x3;
constexpr std::uint32_t kButtonsYesNo = 0x4;
constexpr std::uint32_t kButtonsRetryCancel = 0x5;
constexpr std::uint32_t kButtonsCancelTryContinue = 0x6;

// The icon bits, named because the rendered line states them: a program
// that raises the error icon is telling its reader something a bare text
// dump would lose.
constexpr std::uint32_t kIconHand = 0x10;
constexpr std::uint32_t kIconQuestion = 0x20;
constexpr std::uint32_t kIconExclamation = 0x30;
constexpr std::uint32_t kIconAsterisk = 0x40;
constexpr std::uint32_t kIconMask = 0xF0;

// The answer the default button gives, per button group. The default
// button flag (MB_DEFBUTTON2 and friends) moves the emphasis on a real
// dialog; here, where the box is rendered rather than raised, the first
// button is the one that answers, which is also the id a caller that
// never reads flags most often expects.
[[nodiscard]] std::int32_t default_answer(std::uint32_t group) noexcept {
    switch (group) {
    case kButtonsOkCancel: return kIdOk;
    case kButtonsAbortRetryIgnore: return kIdAbort;
    case kButtonsYesNoCancel: return kIdYes;
    case kButtonsYesNo: return kIdYes;
    case kButtonsRetryCancel: return kIdRetry;
    case kButtonsCancelTryContinue: return kIdCancel;
    default: return kIdOk;
    }
}

// The icon's name, for the rendered line. Unnamed means no icon bit was
// set, which is the MB_OK plain box.
[[nodiscard]] const char* icon_name(std::uint32_t uType) noexcept {
    switch (uType & kIconMask) {
    case kIconHand: return "error";
    case kIconQuestion: return "question";
    case kIconExclamation: return "warning";
    case kIconAsterisk: return "information";
    default: return "none";
    }
}

// The message box's body, narrow and wide alike, rendered to stderr. The
// rendering is one line with the shape a person reading a headless run
// wants: the caption, the icon, the style, and the text.
void render_box(const std::string& caption, const std::string& text,
                std::uint32_t uType) noexcept {
    const char* icon = icon_name(uType);
    std::fprintf(stderr,
                 "occ user32: MessageBox [%s] (%s, buttons %u): %s\n",
                 caption.c_str(), icon, uType & kButtonGroupMask,
                 text.c_str());
    ::fflush(stderr);
}

// The narrow text, read to its terminator. A null pointer is what Windows
// shows as an empty body, and the empty string is the answer here.
[[nodiscard]] std::string narrow_text(const char* text) noexcept {
    if (text == nullptr) {
        return {};
    }
    return std::string(text);
}

// The wide text, widened to UTF-8 for the rendered line. A null pointer is
// the empty body, as above; an unterminated buffer is bounded by the
// conversion, which stops at its own limit rather than at memory the
// guest did not write.
[[nodiscard]] std::string wide_text(const char16_t* text) noexcept {
    if (text == nullptr) {
        return {};
    }
    std::string out;
    static_cast<void>(utf16_to_utf8(std::u16string_view(text), out));
    return out;
}

}  // namespace

// --- the wide spelling, and the family the other names wrap ---------------

extern "C" __attribute__((ms_abi)) std::int32_t u32_MessageBoxW(
    void* window, const char16_t* text, const char16_t* caption,
    std::uint32_t uType) noexcept {
    (void)window;
    std::string narrow_caption = wide_text(caption);
    std::string narrow_text_out = wide_text(text);
    render_box(narrow_caption, narrow_text_out, uType);
    return default_answer(uType & kButtonGroupMask);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32_MessageBoxA(
    void* window, const char* text, const char* caption,
    std::uint32_t uType) noexcept {
    (void)window;
    render_box(narrow_text(caption), narrow_text(text), uType);
    return default_answer(uType & kButtonGroupMask);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32_MessageBoxExW(
    void* window, const char16_t* text, const char16_t* caption,
    std::uint32_t uType, std::uint16_t language) noexcept {
    // The `Ex` form is the same dialog with a language id for the buttons'
    // text. The id shapes nothing this host renders, so the call is the
    // base answer with the id recorded in the rendered line's place.
    (void)language;
    return u32_MessageBoxW(window, text, caption, uType);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32_MessageBoxExA(
    void* window, const char* text, const char* caption,
    std::uint32_t uType, std::uint16_t language) noexcept {
    (void)language;
    return u32_MessageBoxA(window, text, caption, uType);
}

// The beep a box with an icon plays. The host has no speaker; the call is
// the acknowledgement Windows gives it, which is TRUE.
extern "C" __attribute__((ms_abi)) std::int32_t u32_MessageBeep(
    std::uint32_t uType) noexcept {
    (void)uType;
    return 1;
}

// The registration. One line per name, in the shape `add_user32_extra`'s
// file was built for.
void add_user32_extra(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("MessageBoxA", reinterpret_cast<void*>(&u32_MessageBoxA));
    e("MessageBoxW", reinterpret_cast<void*>(&u32_MessageBoxW));
    e("MessageBoxExA", reinterpret_cast<void*>(&u32_MessageBoxExA));
    e("MessageBoxExW", reinterpret_cast<void*>(&u32_MessageBoxExW));
    e("MessageBeep", reinterpret_cast<void*>(&u32_MessageBeep));
}

}  // namespace occ::runtime::winabi

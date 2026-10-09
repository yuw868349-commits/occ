// The USER32 surface beyond the two printf-style names already here.
//
// The message-box family is what this domain carries. The ids it answers
// are Windows' own button ids, and the answers below are the policy the
// headless host applies: the default button of the style's button group.
// A reference run under wine shows the same ids for a box the caller
// closes with its first button, which is the comparison these checks
// encode.
//
// The rendering side writes one line to stderr per box; the tests do not
// read it back, because the line is for a person and the id is the
// contract.

#include "occ/runtime/api.h"
#include "occ/runtime/exports.h"

#include <cstdint>
#include <cstdio>
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

// The host functions the tests call. They are declared here rather than
// in a header because they are the guest-facing surface -- `ms_abi`, C
// names -- and the only caller that needs their C++ name is this test.
// The attribute is on the declaration because the host's own convention
// is not the one these bodies read their arguments in.
extern "C" __attribute__((ms_abi)) std::int32_t u32_MessageBoxA(
    void*, const char*, const char*, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32_MessageBoxW(
    void*, const char16_t*, const char16_t*, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32_MessageBoxExW(
    void*, const char16_t*, const char16_t*, std::uint32_t,
    std::uint16_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32_MessageBeep(
    std::uint32_t) noexcept;

void test_table_is_well_formed() {
    ExportList list;
    add_user32_extra(list);
    bool addressed = true;
    bool has_box = false;
    for (const HostExport& entry : list) {
        if (entry.name.empty() || entry.address == 0) {
            addressed = false;
        }
        if (entry.name == "MessageBoxW") {
            has_box = true;
        }
    }
    check(addressed, "api: every entry has a name and an address");
    check(has_box, "api: the message box is registered");
}

// The button group decides the id. Each case is the group's first button,
// which is the default the headless box answers with.
void test_button_group_answers() {
    // MB_OK -- the plain box acknowledges.
    check(u32_MessageBoxW(nullptr, u"body", u"caption", 0x0) == 1,
          "user32: MB_OK answers IDOK");
    // MB_OKCANCEL -- the OK side answers.
    check(u32_MessageBoxW(nullptr, u"body", u"caption", 0x1) == 1,
          "user32: MB_OKCANCEL answers IDOK");
    // MB_ABORTRETRYIGNORE -- the abort side answers.
    check(u32_MessageBoxW(nullptr, u"body", u"caption", 0x2) == 3,
          "user32: MB_ABORTRETRYIGNORE answers IDABORT");
    // MB_YESNOCANCEL -- the yes side answers.
    check(u32_MessageBoxW(nullptr, u"body", u"caption", 0x3) == 6,
          "user32: MB_YESNOCANCEL answers IDYES");
    // MB_YESNO -- the yes side answers.
    check(u32_MessageBoxW(nullptr, u"body", u"caption", 0x4) == 6,
          "user32: MB_YESNO answers IDYES");
    // MB_RETRYCANCEL -- the retry side answers.
    check(u32_MessageBoxW(nullptr, u"body", u"caption", 0x5) == 4,
          "user32: MB_RETRYCANCEL answers IDRETRY");
    // MB_CANCELTRYCONTINUE -- the cancel side answers.
    check(u32_MessageBoxW(nullptr, u"body", u"caption", 0x6) == 2,
          "user32: MB_CANCELTRYCONTINUE answers IDCANCEL");
}

// The flags above the button group change nothing about the id. An icon
// and a default-button flag ride along with a group and the id is the
// group's, which is the caller's contract.
void test_style_flags_do_not_move_the_answer() {
    check(u32_MessageBoxW(nullptr, u"body", u"caption", 0x10) == 1,
          "user32: the error icon leaves MB_OK's answer");
    check(u32_MessageBoxW(nullptr, u"body", u"caption", 0x101) == 1,
          "user32: a default-button flag leaves MB_OKCANCEL's answer");
    check(u32_MessageBoxW(nullptr, u"body", u"caption", 0x30) == 1,
          "user32: the warning icon leaves MB_OK's answer");
}

// The narrow spelling is the same dialog. The text travels as the host's
// own bytes and the id is the group's.
void test_narrow_spelling_agrees() {
    check(u32_MessageBoxA(nullptr, "body", "caption", 0x0) == 1,
          "user32: MessageBoxA answers IDOK for MB_OK");
    check(u32_MessageBoxA(nullptr, "body", "caption", 0x4) == 6,
          "user32: MessageBoxA answers IDYES for MB_YESNO");
}

// The Ex form is the same dialog with a language id, and the id is the
// group's whatever the language says.
void test_ex_form_agrees() {
    check(u32_MessageBoxExW(nullptr, u"body", u"caption", 0x0, 0x409) == 1,
          "user32: MessageBoxExW answers IDOK for MB_OK");
    check(u32_MessageBoxExW(nullptr, u"body", u"caption", 0x5, 0x809) == 4,
          "user32: MessageBoxExW answers IDRETRY for MB_RETRYCANCEL");
}

// A null text or caption is the empty body, not a fault. Windows shows an
// empty box; the host renders the empty strings and answers the id.
void test_null_text_is_the_empty_body() {
    check(u32_MessageBoxW(nullptr, nullptr, nullptr, 0x0) == 1,
          "user32: a null body answers IDOK");
    check(u32_MessageBoxA(nullptr, nullptr, nullptr, 0x1) == 1,
          "user32: a null narrow body answers IDOK");
}

// The beep acknowledges. There is no speaker here, and the kernel's own
// answer to the call is TRUE.
void test_message_beep_acknowledges() {
    check(u32_MessageBeep(0x0) == 1, "user32: MessageBeep acknowledges");
    check(u32_MessageBeep(0x30) == 1, "user32: MessageBeep with an icon");
}

}  // namespace

int main() {
    test_table_is_well_formed();
    test_button_group_answers();
    test_style_flags_do_not_move_the_answer();
    test_narrow_spelling_agrees();
    test_ex_form_agrees();
    test_null_text_is_the_empty_body();
    test_message_beep_acknowledges();
    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

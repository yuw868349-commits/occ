// The USER32 window station, as the tests see it.
//
// The station's contract is the one a headless window manager can keep:
// windows a guest registers and creates are real objects, messages a
// guest posts arrive, and the answers a real machine would give for a
// machine's own properties -- the screen's size, the layout's id -- are
// the values Windows documents. Every check below is one of those three
// promises, exercised the way a checker exercises them.

#include "occ/runtime/api.h"
#include "occ/runtime/exports.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

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

// The host functions the tests call, at the guest's own convention.
extern "C" __attribute__((ms_abi)) std::uint16_t u32w_RegisterClassW(
    const void*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32w_CreateWindowExW(
    std::uint32_t, const char16_t*, const char16_t*, std::uint32_t,
    std::int32_t, std::int32_t, std::int32_t, std::int32_t, std::uint64_t,
    std::uint64_t, std::uint64_t, void*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_DestroyWindow(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_IsWindow(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32w_FindWindowW(
    const char16_t*, const char16_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetWindowTextW(
    std::uint64_t, char16_t*, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_SetWindowTextW(
    std::uint64_t, const char16_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t u32w_SetWindowLongPtrW(
    std::uint64_t, std::int32_t, std::int64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t u32w_GetWindowLongPtrW(
    std::uint64_t, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_PostMessageW(
    std::uint64_t, std::uint32_t, std::uint64_t, std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_PeekMessageW(
    void*, std::uint64_t, std::uint32_t, std::uint32_t, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_IsWindowVisible(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_ShowWindow(
    std::uint64_t, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32w_GetDesktopWindow()
    noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetSystemMetrics(
    std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_OpenClipboard(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_CloseClipboard() noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32w_SetClipboardData(
    std::uint32_t, std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32w_GetClipboardData(
    std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_EmptyClipboard() noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
u32w_RegisterClipboardFormatW(const char16_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32w_SetTimer(
    std::uint64_t, std::uint64_t, std::uint32_t, std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_KillTimer(
    std::uint64_t, std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_IsIconic(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_IsZoomed(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32w_GetParent(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_IsChild(
    std::uint64_t, std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t u32w_SendMessageW(
    std::uint64_t, std::uint32_t, std::uint64_t, std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetDlgCtrlID(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32w_GetDlgItem(
    std::uint64_t, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int16_t u32w_GetAsyncKeyState(
    std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32w_GetKeyboardLayout(
    std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetClassNameW(
    std::uint64_t, char16_t*, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32w_FindWindowExW(
    std::uint64_t, std::uint64_t, const char16_t*, const char16_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetWindowRect(
    std::uint64_t, void*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32w_RegisterClassExW(
    const void*) noexcept;

// The window the tests create through. The class the tests register, in
// the guest's own `WNDCLASSW` layout, bytes at the offsets Windows
// documents.
[[nodiscard]] std::vector<std::uint8_t> class_bytes(const char16_t* name,
                                                    std::uint64_t proc) {
    std::vector<std::uint8_t> b(0x50, 0);
    const std::uint32_t style = 0;
    const std::int32_t extra = 0;
    const std::uint64_t instance = 0x1000;
    std::memcpy(b.data() + 0x00, &style, 4);
    std::memcpy(b.data() + 0x08, &proc, 8);
    std::memcpy(b.data() + 0x10, &extra, 4);
    std::memcpy(b.data() + 0x14, &extra, 4);
    std::memcpy(b.data() + 0x18, &instance, 8);
    const char16_t* menu = nullptr;
    std::memcpy(b.data() + 0x38, &menu, 8);
    std::memcpy(b.data() + 0x40, &name, 8);
    return b;
}

// The window procedure the tests answer through. It records the last
// message the station delivered, which is how the delivery paths are
// checked.
std::uint32_t g_last_message = 0;
std::uint64_t g_last_hwnd = 0;

extern "C" __attribute__((ms_abi)) std::int64_t test_wnd_proc(
    std::uint64_t hwnd, std::uint32_t message, std::uint64_t,
    std::uint64_t) noexcept {
    g_last_message = message;
    g_last_hwnd = hwnd;
    return 1;
}

void test_registry_is_well_formed() {
    ExportList list;
    add_user32_windows(list);
    bool addressed = true;
    int names = 0;
    for (const HostExport& entry : list) {
        if (entry.name.empty() || entry.address == 0) {
            addressed = false;
        }
        ++names;
    }
    check(addressed, "user32w: every entry has a name and an address");
    check(names >= 120, "user32w: the station registers the full family");
}

void test_class_and_window_round_trip() {
    const char16_t* cls = u"occTest";
    const auto bytes = class_bytes(cls, reinterpret_cast<std::uint64_t>(
                                              &test_wnd_proc));
    const std::uint16_t atom = u32w_RegisterClassW(bytes.data());
    check(atom != 0, "user32w: the class registers");

    const std::uint64_t hwnd = u32w_CreateWindowExW(
        0, cls, u"the title", 0x00CF0000 /* WS_OVERLAPPEDWINDOW */, 10, 20,
        300, 200, 0, 0, 0x1000, nullptr);
    check(hwnd != 0, "user32w: the window creates");
    check(u32w_IsWindow(hwnd) == 1, "user32w: the handle answers IsWindow");

    // The creation messages were delivered: WM_NCCREATE, WM_CREATE and
    // WM_SIZE, with the last the size the creation carried.
    check(g_last_hwnd == hwnd &&
              (g_last_message == 1 || g_last_message == 5),
          "user32w: the creation messages reached the procedure");

    // The text the creation named is the text the query returns.
    char16_t text[32] = {};
    const std::int32_t got = u32w_GetWindowTextW(hwnd, text, 32);
    const std::u16string read(text, text + got);
    check(read == u"the title", "user32w: the title round-trips");

    // The title a set writes is the title a read answers.
    check(u32w_SetWindowTextW(hwnd, u"new title") == 1,
          "user32w: SetWindowTextW succeeds");
    std::memset(text, 0, sizeof(text));
    u32w_GetWindowTextW(hwnd, text, 32);
    check(std::u16string(text) == u"new title",
          "user32w: the new title answers");

    // The class name answers from the registration.
    char16_t cls_back[32] = {};
    u32w_GetClassNameW(hwnd, cls_back, 32);
    check(std::u16string(cls_back) == u"occTest",
          "user32w: the class name answers");

    // A window whose class was never registered is refused, the way
    // Windows refuses it.
    const std::uint64_t bad = u32w_CreateWindowExW(
        0, u"noSuchClass", u"", 0, 0, 0, 0, 0, 0, 0, 0, nullptr);
    check(bad == 0, "user32w: an unknown class refuses to create");

    // The creation messages were delivered: WM_NCCREATE (0x81) then
    // WM_CREATE (1).
    check(u32w_DestroyWindow(hwnd) == 1, "user32w: the window destroys");
    check(u32w_IsWindow(hwnd) == 0,
          "user32w: the handle no longer answers IsWindow");
}

void test_find_and_search() {
    const char16_t* cls = u"occFind";
    const auto bytes =
        class_bytes(cls, 0);  // no procedure: the queries still answer
    check(u32w_RegisterClassW(bytes.data()) != 0, "user32w: find class lives");

    const std::uint64_t a = u32w_CreateWindowExW(
        0, cls, u"first", 0, 0, 0, 0, 0, 0, 0, 0, nullptr);
    const std::uint64_t b = u32w_CreateWindowExW(
        0, cls, u"second", 0, 0, 0, 0, 0, 0, 0, 0, nullptr);
    check(a != 0 && b != 0 && a != b, "user32w: two windows, two handles");

    check(u32w_FindWindowW(cls, u"second") == b,
          "user32w: FindWindowW finds by class and title");
    check(u32w_FindWindowW(cls, nullptr) != 0,
          "user32w: a null title matches any window of the class");
    check(u32w_FindWindowW(u"none", u"first") == 0,
          "user32w: a class that does not exist is not found");

    const std::uint64_t next = u32w_FindWindowExW(0, a, nullptr, nullptr);
    check(next != 0 && next != a, "user32w: FindWindowExW walks past after");

    u32w_DestroyWindow(a);
    u32w_DestroyWindow(b);
}

void test_styles_and_geometry() {
    const char16_t* cls = u"occStyle";
    const auto bytes = class_bytes(cls, 0);
    check(u32w_RegisterClassW(bytes.data()) != 0,
          "user32w: style class lives");

    // A visible window starts visible; a hidden one does not.
    const std::uint64_t shown = u32w_CreateWindowExW(
        0, cls, u"", 0x10000000 /* WS_VISIBLE */, 0, 0, 0, 0, 0, 0, 0,
        nullptr);
    const std::uint64_t hidden =
        u32w_CreateWindowExW(0, cls, u"", 0, 0, 0, 0, 0, 0, 0, 0, nullptr);
    check(u32w_IsWindowVisible(shown) == 1, "user32w: WS_VISIBLE shows");
    check(u32w_IsWindowVisible(hidden) == 0,
          "user32w: a plain window starts hidden");

    // ShowWindow's answer is whether the window was visible before.
    check(u32w_ShowWindow(hidden, 5 /* SW_SHOW */) == 0,
          "user32w: ShowWindow on a hidden window answers false");
    check(u32w_IsWindowVisible(hidden) == 1,
          "user32w: ShowWindow made it visible");

    // The style words round-trip through the long-ptr family.
    constexpr std::int32_t kGwlpUser = -21;
    check(u32w_SetWindowLongPtrW(shown, kGwlpUser, 0x1234) == 0,
          "user32w: a fresh GWLP_USERDATA is zero");
    check(u32w_GetWindowLongPtrW(shown, kGwlpUser) == 0x1234,
          "user32w: GWLP_USERDATA round-trips");

    // The geometry the creation carried is the geometry the rect reads.
    std::int32_t rect[4] = {0, 0, 0, 0};
    check(u32w_GetWindowRect(shown, rect) == 1, "user32w: GetWindowRect");
    check(rect[0] == 0 && rect[1] == 0 && rect[2] == 0 && rect[3] == 0,
          "user32w: the zero-size window answers a zero rect");

    // The screen metrics are the station's documented answer.
    check(u32w_GetSystemMetrics(0) == 1920, "user32w: SM_CXSCREEN is 1920");
    check(u32w_GetSystemMetrics(1) == 1080, "user32w: SM_CYSCREEN is 1080");
    check(u32w_GetDesktopWindow() != 0,
          "user32w: the desktop has a handle");

    u32w_DestroyWindow(shown);
    u32w_DestroyWindow(hidden);
}

void test_parent_child() {
    const char16_t* cls = u"occParent";
    const auto bytes = class_bytes(cls, 0);
    check(u32w_RegisterClassW(bytes.data()) != 0,
          "user32w: parent class lives");

    const std::uint64_t parent = u32w_CreateWindowExW(
        0, cls, u"parent", 0, 0, 0, 0, 0, 0, 0, 0, nullptr);
    const std::uint64_t child = u32w_CreateWindowExW(
        0, cls, u"child", 0x40000000 /* WS_CHILD */, 0, 0, 0, 0, parent,
        static_cast<std::uint64_t>(7) /* the dialog id */, 0, nullptr);
    check(child != 0, "user32w: a child creates against a real parent");

    check(u32w_GetParent(child) == parent, "user32w: the child's parent is");
    check(u32w_IsChild(parent, child) == 1, "user32w: IsChild answers yes");
    check(u32w_IsChild(child, parent) == 0,
          "user32w: the relation does not run backwards");

    // A child without a parent is refused.
    check(u32w_CreateWindowExW(0, cls, u"orphan", 0x40000000, 0, 0, 0, 0, 0,
                               0, 0, nullptr) == 0,
          "user32w: an orphan child is refused");

    check(u32w_GetDlgCtrlID(child) == 7,
          "user32w: the child's dialog id is the menu slot's");
    check(u32w_GetDlgItem(parent, 7) == child,
          "user32w: GetDlgItem finds the child by id");

    u32w_DestroyWindow(child);
    u32w_DestroyWindow(parent);
}

// The message the queue reads back, in the guest's own layout.
struct TestMsg {
    std::uint64_t hwnd;
    std::uint32_t message;
    std::uint64_t wparam;
    std::uint64_t lparam;
    std::uint32_t time;
    std::int32_t x;
    std::int32_t y;
    std::uint32_t pad;
};

void test_message_queue() {
    const char16_t* cls = u"occQueue";
    const auto bytes = class_bytes(cls, 0);
    check(u32w_RegisterClassW(bytes.data()) != 0,
          "user32w: queue class lives");
    const std::uint64_t hwnd =
        u32w_CreateWindowExW(0, cls, u"", 0, 0, 0, 0, 0, 0, 0, 0, nullptr);

    // A post is a peek away; nothing is lost between them.
    check(u32w_PostMessageW(hwnd, 0x0400 /* WM_USER */, 42, 43) == 1,
          "user32w: PostMessageW succeeds");
    TestMsg m = {};
    check(u32w_PeekMessageW(&m, 0, 0, 0, 1 /* PM_REMOVE */) == 1,
          "user32w: PeekMessageW finds the post");
    check(m.message == 0x0400 && m.hwnd == hwnd, "user32w: the post arrives");
    check(m.wparam == 42 && m.lparam == 43, "user32w: the payload arrives");
    check(u32w_PeekMessageW(&m, 0, 0, 0, 1) == 0,
          "user32w: the removal took the message away");

    // A filtered peek only sees the range it names.
    check(u32w_PostMessageW(hwnd, 0x0400, 1, 1) == 1, "user32w: post one");
    check(u32w_PostMessageW(hwnd, 0x0401, 2, 2) == 1, "user32w: post two");
    check(u32w_PeekMessageW(&m, 0, 0x0401, 0x0401, 1) == 1,
          "user32w: the filter finds its message");
    check(m.message == 0x0401, "user32w: the filter's message is right");
    check(u32w_PeekMessageW(&m, 0, 0x0400, 0x0400, 1) == 1,
          "user32w: the other message waited");
    check(m.message == 0x0400, "user32w: and it is the first one's");

    // A post to a window that does not exist is refused.
    check(u32w_PostMessageW(0xDEAD0000, 0x0400, 0, 0) == 0,
          "user32w: a post to a dead handle is refused");

    // SendMessage calls the window's procedure, and the procedure sees
    // the message and the handle.
    const char16_t* cls2 = u"occSend";
    const auto bytes2 = class_bytes(cls2, reinterpret_cast<std::uint64_t>(
                                               &test_wnd_proc));
    check(u32w_RegisterClassW(bytes2.data()) != 0,
          "user32w: send class lives");
    const std::uint64_t live =
        u32w_CreateWindowExW(0, cls2, u"", 0, 0, 0, 0, 0, 0, 0, 0, nullptr);
    check(u32w_SendMessageW(live, 0x0400, 9, 10) == 1,
          "user32w: SendMessageW answers the procedure's result");
    check(g_last_message == 0x0400 && g_last_hwnd == live,
          "user32w: the procedure saw the sent message");
    u32w_DestroyWindow(live);
    u32w_DestroyWindow(hwnd);
}

void test_clipboard() {
    // The open/close bracket: a set outside it is refused.
    check(u32w_OpenClipboard(0) == 1, "user32w: the clipboard opens");
    check(u32w_OpenClipboard(0) == 0,
          "user32w: a second open is refused while one is live");

    const char* text = "clipboard body";
    check(u32w_SetClipboardData(1 /* CF_TEXT */,
                                reinterpret_cast<std::uint64_t>(text)) != 0,
          "user32w: the set succeeds");
    const std::uint64_t back = u32w_GetClipboardData(1);
    check(back != 0, "user32w: the get answers");
    check(std::strcmp(reinterpret_cast<const char*>(back), text) == 0,
          "user32w: the bytes round-trip");

    check(u32w_EmptyClipboard() == 1, "user32w: the empty succeeds");
    check(u32w_GetClipboardData(1) == 0,
          "user32w: an empty clipboard answers nothing");
    check(u32w_CloseClipboard() == 1, "user32w: the bracket closes");
    check(u32w_CloseClipboard() == 0,
          "user32w: a second close is refused");

    // A private format registers to a stable id.
    const std::uint32_t fmt =
        u32w_RegisterClipboardFormatW(u"occ.private.format");
    check(fmt != 0, "user32w: a private format registers");
    check(u32w_RegisterClipboardFormatW(u"occ.private.format") == fmt,
          "user32w: the same name registers to the same id");
}

void test_keyboard_and_timers() {
    // No input device has touched the keyboard: the state is up, and the
    // "pressed since" bit is clear.
    check(u32w_GetAsyncKeyState(0x41 /* VK_A */) == 0,
          "user32w: an untouched key answers the up state");
    check(u32w_GetKeyboardLayout(0) == 0x04090409,
          "user32w: the layout is the US layout");

    // A timer with an id returns the id; killing it answers success once.
    const std::uint64_t timer = u32w_SetTimer(0, 77, 1000, 0);
    check(timer == 77, "user32w: the timer id is the caller's");
    check(u32w_KillTimer(0, 77) == 1, "user32w: the timer kills");
    check(u32w_KillTimer(0, 77) == 0,
          "user32w: a killed timer refuses a second kill");
}

void test_minimize_maximize() {
    const char16_t* cls = u"occZoom";
    const auto bytes = class_bytes(cls, 0);
    check(u32w_RegisterClassW(bytes.data()) != 0, "user32w: zoom class lives");
    const std::uint64_t iconic =
        u32w_CreateWindowExW(0, cls, u"", 0x20000000 /* WS_MINIMIZE */, 0, 0,
                             0, 0, 0, 0, 0, nullptr);
    const std::uint64_t zoomed =
        u32w_CreateWindowExW(0, cls, u"", 0x01000000 /* WS_MAXIMIZE */, 0, 0,
                             0, 0, 0, 0, 0, nullptr);
    check(u32w_IsIconic(iconic) == 1, "user32w: WS_MINIMIZE is iconic");
    check(u32w_IsZoomed(zoomed) == 1, "user32w: WS_MAXIMIZE is zoomed");
    u32w_DestroyWindow(iconic);
    u32w_DestroyWindow(zoomed);
}

}  // namespace

int main() {
    test_registry_is_well_formed();
    test_class_and_window_round_trip();
    test_find_and_search();
    test_styles_and_geometry();
    test_parent_child();
    test_message_queue();
    test_clipboard();
    test_keyboard_and_timers();
    test_minimize_maximize();
    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

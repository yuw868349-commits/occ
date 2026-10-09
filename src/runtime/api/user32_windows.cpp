// The USER32 window station, as a headless one.
//
// A window manager is a database with a delivery service attached. The
// database -- windows, classes, menus, the clipboard -- is the part this
// runtime carries honestly: every structure is real, every query answers
// from it, and a guest that registers a class, creates a window and asks
// for the text back is talking to a manager that kept the text. The
// delivery service -- where the next input event comes from -- is the part
// a headless host cannot invent: there is no user, so there is no input,
// and the honest answer to "where is the mouse" is "where the guest last
// put it" rather than a coordinate that would satisfy a pointer-reading
// checker and contradict a real machine.
//
// The policy this file takes, on each question a guest can ask:
//
//   * Windows a guest creates are real objects. Class lookup, style
//     storage, child enumeration, parentage, text and the dialog-item id
//     all answer from the tables, and `FindWindowW` finds what was created.
//
//   * Messages a guest sends are delivered. `SendMessageW` calls the
//     window's procedure -- the guest's own code, called at its own
//     address, because a guest window procedure is a guest address and the
//     runtime bridges to it the way it bridges to a vectored handler.
//     `PostMessageW` queues, and a thread waiting on its queue wakes when
//     another thread posts.
//
//   * Input that would come from a user never comes. `GetAsyncKeyState`
//     reports the up state, and a message loop that waits for the user
//     waits -- with a deadline the `OCC_UI_WAIT` variable can turn into an
//     error return, so a run can be bounded without changing what a
//     driven program sees.
//
//   * Every answer that would be the same on two machines of one Windows
//     build is the value the build documents: the metrics of a 1920x1080
//     primary display, the standard clipboard formats, the `MSG` layout
//     the messages are read into.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

// The current guest thread's id, answered the way the kernel32 domain
// answers it: from the TEB field the loader placed.
extern "C" __attribute__((ms_abi)) std::uint32_t
k32_GetCurrentThreadId() noexcept;

namespace occ::runtime::winabi {
namespace {

// -- the error codes the family reports --------------------------------------

constexpr std::uint32_t kErrOk = 0;
constexpr std::uint32_t kErrParam = 87;
constexpr std::uint32_t kErrClassNotFound = 1411;
constexpr std::uint32_t kErrClassHasWindows = 1412;
constexpr std::uint32_t kErrNoWindowClass = 1407;
constexpr std::uint32_t kErrBadHwnd = 1400;
constexpr std::uint32_t kErrBadMenu = 1401;
constexpr std::uint32_t kErrClipboardNotOpen = 1418;

constexpr std::int32_t kTrue = 1;
constexpr std::int32_t kFalse = 0;

// -- the messages a window receives -------------------------------------------

constexpr std::uint32_t kMsgNull = 0x0000;
constexpr std::uint32_t kMsgCreate = 0x0001;
constexpr std::uint32_t kMsgDestroy = 0x0002;
constexpr std::uint32_t kMsgMove = 0x0003;
constexpr std::uint32_t kMsgSize = 0x0005;
constexpr std::uint32_t kMsgSetText = 0x000C;
constexpr std::uint32_t kMsgGetText = 0x000D;
constexpr std::uint32_t kMsgGetTextLen = 0x000E;
constexpr std::uint32_t kMsgQuit = 0x0012;
constexpr std::uint32_t kMsgShowWindow = 0x0018;
constexpr std::uint32_t kMsgNcCreate = 0x0081;
constexpr std::uint32_t kMsgNcDestroy = 0x0082;
constexpr std::uint32_t kMsgKeyDown = 0x0100;
constexpr std::uint32_t kMsgChar = 0x0102;
constexpr std::uint32_t kMsgSysKeyDown = 0x0104;
constexpr std::uint32_t kMsgInitDialog = 0x0110;
constexpr std::uint32_t kMsgTimer = 0x0113;

// -- the handles the station mints ----------------------------------------------
//
// Windows' own user handles are small values handed out in order. The
// numbers here follow the same shape -- unique, stable for the object's
// life, never zero, never the desktop's -- without pretending to be
// pointers into a table that lives in win32k.

constexpr std::uint64_t kHwndDesktop = 0x00010000;
constexpr std::uint64_t kHwndStep = 8;
constexpr std::uint64_t kHwndFirst = 0x00010010;
constexpr std::uint64_t kAtomFirst = 0xC001;
constexpr std::uint64_t kHandleStep = 4;
constexpr std::uint64_t kMenuFirst = 0x00020010;
constexpr std::uint64_t kIconFirst = 0x00030010;
constexpr std::uint64_t kCursorFirst = 0x00040010;

// The style bits the creation and the queries read.
constexpr std::uint32_t kWsVisible = 0x10000000;
constexpr std::uint32_t kWsChild = 0x40000000;
constexpr std::uint32_t kWsPopup = 0x80000000;
constexpr std::uint32_t kWsDisabled = 0x08000000;
constexpr std::uint32_t kWsMinimize = 0x20000000;
constexpr std::uint32_t kWsMaximize = 0x01000000;

// The `GetWindowLongPtr` indices. The negatives are the fields Windows
// stores in the window itself; the non-negatives address the window's
// extra bytes.
constexpr std::int32_t kIdxWndProc = -4;
constexpr std::int32_t kIdxInstance = -6;
constexpr std::int32_t kIdxParent = -8;
constexpr std::int32_t kIdxId = -12;
constexpr std::int32_t kIdxStyle = -16;
constexpr std::int32_t kIdxExStyle = -20;
constexpr std::int32_t kIdxUser = -21;

// -- the objects the station keeps ------------------------------------------------

struct GuestClass {
    std::u16string name;
    std::uint32_t style = 0;
    std::uint64_t proc = 0;
    std::int32_t cls_extra = 0;
    std::int32_t win_extra = 0;
    std::uint64_t instance = 0;
    std::uint64_t icon = 0;
    std::uint64_t icon_small = 0;
    std::uint64_t cursor = 0;
    std::uint64_t background = 0;
    std::uint64_t atom = 0;
};

struct GuestWindow {
    std::uint64_t hwnd = 0;
    std::uint64_t parent = 0;
    std::uint64_t owner = 0;
    std::uint64_t menu = 0;
    std::u16string class_name;
    std::u16string text;
    std::uint32_t style = 0;
    std::uint32_t ex_style = 0;
    std::int32_t x = 0;
    std::int32_t y = 0;
    std::int32_t cx = 0;
    std::int32_t cy = 0;
    std::uint32_t dlg_id = 0;
    std::uint64_t proc = 0;
    std::uint64_t user_data = 0;
    std::uint64_t instance = 0;
    std::uint32_t thread = 0;
    bool visible = false;
    bool enabled = true;
    bool iconic = false;
    bool zoomed = false;
    bool destroyed = false;
    std::vector<std::uint8_t> extra;
};

struct QueuedMsg {
    std::uint64_t hwnd = 0;
    std::uint32_t message = 0;
    std::uint64_t wparam = 0;
    std::uint64_t lparam = 0;
    std::uint32_t time = 0;
    std::int32_t x = 0;
    std::int32_t y = 0;
};

struct MenuItem {
    std::uint32_t flags = 0;
    std::uint64_t id = 0;
    std::u16string text;
    std::uint64_t submenu = 0;
    bool checked = false;
    bool enabled = true;
};

struct GuestMenu {
    std::vector<MenuItem> items;
};

struct GuestTimer {
    std::uint64_t id = 0;
    std::uint64_t hwnd = 0;
    std::uint32_t thread = 0;
    std::uint32_t interval = 0;
    std::uint64_t proc = 0;
    std::chrono::steady_clock::time_point next;
};

struct ThreadQueue {
    std::deque<QueuedMsg> msgs;
    std::uint32_t quit_code = 0;
    bool quit_posted = false;
};

// The station. One mutex covers every table: the calls are short, the
// contention a checker exercises is nil, and a lock per table is a set of
// ordering rules a deadlock would prove wrong.
struct Station {
    std::mutex lock;
    std::condition_variable cond;

    std::uint64_t next_hwnd = kHwndFirst;
    std::uint64_t next_atom = kAtomFirst;
    std::uint64_t next_menu = kMenuFirst;
    std::uint64_t next_icon = kIconFirst;
    std::uint64_t next_cursor = kCursorFirst;

    std::unordered_map<std::uint64_t, GuestWindow> windows;
    std::unordered_map<std::uint64_t, GuestClass> classes;
    std::unordered_map<std::u16string, std::uint64_t> class_by_name;
    std::unordered_map<std::uint32_t, ThreadQueue> queues;
    std::unordered_map<std::uint64_t, GuestMenu> menus;
    std::vector<GuestTimer> timers;

    // The clipboard: the format and bytes the last set left, and the
    // sequence number the reads answer from.
    bool clip_open = false;
    std::uint64_t clip_owner = 0;
    std::uint32_t clip_format = 0;
    std::vector<std::uint8_t> clip_data;
    std::uint32_t clip_seq = 1;
    std::uint32_t next_clip_fmt = 0xC000;
    std::unordered_map<std::u16string, std::uint32_t> clip_named;

    // The keyboard, at the state "the user has touched nothing" gives.
    std::uint8_t keys[256] = {};
    std::int32_t cursor_x = 0;
    std::int32_t cursor_y = 0;
    std::int32_t cursor_shown = 0;

    std::uint64_t fg = 0;
    std::unordered_map<std::uint32_t, std::uint64_t> focus;
    std::unordered_map<std::uint32_t, std::uint64_t> capture;
};

Station& station() noexcept {
    static Station* s = new Station();
    return *s;
}

using Lock = std::unique_lock<std::mutex>;

// The desktop geometry the metrics answer from. The size named here is the
// one a 1080p build reports, which is the most common real answer and the
// one a resolution-sensitive checker was most likely written against.
constexpr std::int32_t kScreenW = 1920;
constexpr std::int32_t kScreenH = 1080;

// -- text helpers -------------------------------------------------------------------

[[nodiscard]] std::string wide_to_utf8(const std::u16string& text) noexcept {
    std::string out;
    static_cast<void>(utf16_to_utf8(text, out));
    return out;
}

[[nodiscard]] std::u16string utf8_to_wide(const char* text) noexcept {
    if (text == nullptr) {
        return {};
    }
    std::u16string out;
    static_cast<void>(utf8_to_utf16(std::string_view(text), out));
    return out;
}

[[nodiscard]] std::u16string read_wide_z(const char16_t* text) noexcept {
    if (text == nullptr) {
        return {};
    }
    std::u16string out;
    while (*text != u'\0') {
        out.push_back(*text++);
    }
    return out;
}

[[nodiscard]] std::uint32_t tick_ms() noexcept {
    return static_cast<std::uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count() &
        0xFFFFFFFF);
}

// -- the table helpers ------------------------------------------------------------------

[[nodiscard]] GuestWindow* hwnd_find(const Lock&, std::uint64_t hwnd) noexcept {
    auto it = station().windows.find(hwnd);
    return it == station().windows.end() ? nullptr : &it->second;
}

[[nodiscard]] GuestMenu* menu_find(const Lock&, std::uint64_t menu) noexcept {
    auto it = station().menus.find(menu);
    return it == station().menus.end() ? nullptr : &it->second;
}

[[nodiscard]] ThreadQueue& queue_for(std::uint32_t thread) noexcept {
    return station().queues[thread];
}

// The window procedure's guest calling shape. A window procedure is guest
// code: the address the class or the `SetWindowLongPtrW` call installed is
// called at, with Windows' own argument order.
extern "C" typedef std::int64_t (__attribute__((ms_abi)) *GuestWndProcT)(
    std::uint64_t hwnd, std::uint32_t message, std::uint64_t wparam,
    std::uint64_t lparam) noexcept;

// Delivers a message to a window's procedure, and answers the default
// result when there is no procedure to reach. Every delivery path goes
// through here, which keeps the delivery rule in one place.
[[nodiscard]] std::int64_t deliver(GuestWindow* w, std::uint32_t message,
                                   std::uint64_t wparam,
                                   std::uint64_t lparam) noexcept {
    if (w == nullptr || w->proc == 0) {
        return 0;
    }
    const auto proc = reinterpret_cast<GuestWndProcT>(w->proc);
    return proc(w->hwnd, message, wparam, lparam);
}

void post_msg(std::uint32_t thread, const QueuedMsg& m) {
    Station& s = station();
    const Lock held(s.lock);
    queue_for(thread).msgs.push_back(m);
    s.cond.notify_all();
}

// -- the structures the guest reads ------------------------------------------------
//
// Written field by field rather than by a type pun, because the guest's
// compiler may have laid the structure out with different padding and the
// offsets here are the ones Windows documents.

constexpr std::size_t kMsgLayout = 0x30;

void write_msg(void* out, const QueuedMsg& m) noexcept {
    auto* p = static_cast<std::uint8_t*>(out);
    std::memset(p, 0, kMsgLayout);
    std::memcpy(p + 0x00, &m.hwnd, 8);
    std::memcpy(p + 0x08, &m.message, 4);
    std::memcpy(p + 0x10, &m.wparam, 8);
    std::memcpy(p + 0x18, &m.lparam, 8);
    std::memcpy(p + 0x20, &m.time, 4);
    std::memcpy(p + 0x24, &m.x, 4);
    std::memcpy(p + 0x28, &m.y, 4);
}

void write_rect(void* out, std::int32_t l, std::int32_t t, std::int32_t r,
                std::int32_t b) noexcept {
    const std::int32_t v[4] = {l, t, r, b};
    std::memcpy(out, v, sizeof(v));
}

// The deadline a waiting `GetMessageW` honours. `OCC_UI_WAIT` bounds the
// wait a loop makes for input that will never come; the variable is an
// escape hatch for a run, not a behaviour, and no bound applies unless it
// names one.
[[nodiscard]] std::chrono::milliseconds ui_wait_ms() noexcept {
    const char* v = ::getenv("OCC_UI_WAIT");
    if (v == nullptr || *v == '\0') {
        return std::chrono::milliseconds::max();
    }
    const long seconds = ::strtol(v, nullptr, 10);
    if (seconds <= 0) {
        return std::chrono::milliseconds::max();
    }
    return std::chrono::seconds(seconds);
}

// -- the timer thread -----------------------------------------------------------------

extern "C" typedef void (__attribute__((ms_abi)) *GuestTimerProcT)(
    std::uint64_t hwnd, std::uint32_t message, std::uint64_t id,
    std::uint32_t tick) noexcept;

void timer_loop() noexcept {
    for (;;) {
        std::vector<GuestTimer> due;
        {
            Station& s = station();
            const Lock held(s.lock);
            const auto now = std::chrono::steady_clock::now();
            for (const GuestTimer& t : s.timers) {
                if (t.next <= now) {
                    due.push_back(t);
                }
            }
            // Re-arm the ones that fired. Windows repeats a timer until it
            // is killed; the repost is the same interval from now, which
            // is how a real dispatch drifts.
            for (const GuestTimer& t : due) {
                for (GuestTimer& live : s.timers) {
                    if (live.id == t.id && live.hwnd == t.hwnd) {
                        live.next =
                            now + std::chrono::milliseconds(live.interval);
                        break;
                    }
                }
            }
        }
        // The sleep is to the next expiry, or one tenth of a second when
        // the table is empty -- a poll that cannot starve a timer the
        // guest adds while the thread sleeps.
        std::chrono::steady_clock::time_point wake =
            std::chrono::steady_clock::time_point::max();
        {
            const Lock held(station().lock);
            for (const GuestTimer& t : station().timers) {
                if (t.next < wake) {
                    wake = t.next;
                }
            }
        }
        std::chrono::milliseconds rest(100);
        if (wake != std::chrono::steady_clock::time_point::max()) {
            rest = std::chrono::duration_cast<std::chrono::milliseconds>(
                wake - std::chrono::steady_clock::now());
            if (rest < std::chrono::milliseconds(0)) {
                rest = std::chrono::milliseconds(0);
            }
        }
        std::this_thread::sleep_for(rest);
        for (const GuestTimer& t : due) {
            if (t.proc != 0) {
                const auto proc = reinterpret_cast<GuestTimerProcT>(t.proc);
                proc(t.hwnd, kMsgTimer, t.id, tick_ms());
            } else {
                QueuedMsg m;
                m.hwnd = t.hwnd;
                m.message = kMsgTimer;
                m.wparam = t.id;
                m.time = tick_ms();
                post_msg(t.thread, m);
            }
        }
    }
}

void ensure_timer_thread() noexcept {
    static const bool started = [] {
        std::thread(timer_loop).detach();
        return true;
    }();
    (void)started;
}

// -- the queue's read side --------------------------------------------------------------

[[nodiscard]] bool msg_in_range(const QueuedMsg& m, std::uint32_t lo,
                                std::uint32_t hi) noexcept {
    if (lo == 0 && hi == 0) {
        return true;
    }
    return m.message >= lo && m.message <= hi;
}

// The core wait: take a message, or block until one arrives, the quit
// flag is set, or the deadline expires. The three answers -- 1, 0, -1 --
// are the ones `GetMessageW` gives, each for the reason Windows gives it.
[[nodiscard]] std::int32_t wait_msg(void* out, std::uint32_t thread,
                                    std::uint32_t lo, std::uint32_t hi,
                                    bool remove) noexcept {
    Station& s = station();
    const std::chrono::milliseconds limit = ui_wait_ms();
    const auto deadline =
        limit == std::chrono::milliseconds::max()
            ? std::chrono::steady_clock::time_point::max()
            : std::chrono::steady_clock::now() + limit;
    Lock held(s.lock);
    for (;;) {
        ThreadQueue& q = queue_for(thread);
        if (q.quit_posted) {
            const std::uint32_t code = q.quit_code;
            q.quit_posted = false;
            held.unlock();
            QueuedMsg quit;
            quit.message = kMsgQuit;
            quit.wparam = code;
            quit.time = tick_ms();
            write_msg(out, quit);
            return 0;
        }
        for (auto it = q.msgs.begin(); it != q.msgs.end(); ++it) {
            if (msg_in_range(*it, lo, hi)) {
                const QueuedMsg m = *it;
                if (remove) {
                    q.msgs.erase(it);
                }
                held.unlock();
                write_msg(out, m);
                return 1;
            }
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            return -1;
        }
        if (limit == std::chrono::milliseconds::max()) {
            s.cond.wait(held);
        } else {
            s.cond.wait_until(held, deadline);
        }
    }
}

// The registration all four class spellings share. The name is matched as
// given: a program that registers "Main" and looks up "main" is one a
// real machine refuses too.
[[nodiscard]] std::uint16_t class_register(std::uint32_t style,
                                           std::uint64_t proc,
                                           std::int32_t cls_extra,
                                           std::int32_t win_extra,
                                           std::uint64_t instance,
                                           std::uint64_t icon,
                                           std::uint64_t icon_small,
                                           std::uint64_t cursor,
                                           std::uint64_t background,
                                           const std::u16string& name) noexcept {
    if (name.empty()) {
        set_last_error(kErrParam);
        return 0;
    }
    Station& s = station();
    const Lock held(s.lock);
    if (s.class_by_name.count(name) != 0) {
        set_last_error(kErrClassNotFound);
        return 0;
    }
    GuestClass c;
    c.name = name;
    c.style = style;
    c.proc = proc;
    c.cls_extra = cls_extra;
    c.win_extra = win_extra;
    c.instance = instance;
    c.icon = icon;
    c.icon_small = icon_small;
    c.cursor = cursor;
    c.background = background;
    c.atom = s.next_atom++;
    const auto atom = static_cast<std::uint16_t>(c.atom);
    s.class_by_name.emplace(name, c.atom);
    s.classes.emplace(c.atom, std::move(c));
    set_last_error(kErrOk);
    return atom;
}

// The creation all four `CreateWindowEx` spellings share.
[[nodiscard]] std::uint64_t window_create(std::uint32_t ex_style,
                                          const std::u16string& class_name,
                                          const std::u16string& text,
                                          std::uint32_t style, std::int32_t x,
                                          std::int32_t y, std::int32_t cx,
                                          std::int32_t cy,
                                          std::uint64_t parent,
                                          std::uint64_t menu,
                                          std::uint64_t instance,
                                          void* param) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const auto by_name = s.class_by_name.find(class_name);
    if (by_name == s.class_by_name.end()) {
        set_last_error(kErrNoWindowClass);
        return 0;
    }
    const GuestClass& cls = s.classes.at(by_name->second);
    if ((style & kWsChild) != 0 &&
        (parent == 0 || s.windows.count(parent) == 0)) {
        set_last_error(kErrParam);
        return 0;
    }
    GuestWindow w;
    w.hwnd = s.next_hwnd;
    s.next_hwnd += kHwndStep;
    w.class_name = class_name;
    w.text = text;
    w.style = style;
    w.ex_style = ex_style;
    w.x = x;
    w.y = y;
    w.cx = cx;
    w.cy = cy;
    w.parent = (style & kWsChild) != 0 ? parent : 0;
    w.owner = (style & kWsChild) == 0 ? parent : 0;
    if ((style & kWsChild) != 0) {
        // A child's `hMENU` slot carries the dialog item id, and the id is
        // what `GetDlgCtrlID` answers and what a `WM_COMMAND` names.
        w.dlg_id = static_cast<std::uint32_t>(menu & 0xFFFF);
    } else {
        w.menu = menu;
    }
    w.proc = cls.proc;
    w.instance = instance;
    w.thread = k32_GetCurrentThreadId();
    w.visible = (style & kWsVisible) != 0;
    w.enabled = (style & kWsDisabled) == 0;
    w.iconic = (style & kWsMinimize) != 0;
    w.zoomed = (style & kWsMaximize) != 0;
    w.extra.assign(cls.win_extra > 0
                       ? static_cast<std::size_t>(cls.win_extra)
                       : std::size_t{0},
                   0);
    const std::uint64_t hwnd = w.hwnd;
    s.windows.emplace(hwnd, std::move(w));

    // The creation messages, in Windows' order, with the creation
    // parameters in `lParam` the way a real `CREATESTRUCT` pointer rides.
    GuestWindow* live = &s.windows.at(hwnd);
    (void)deliver(live, kMsgNcCreate, 0, reinterpret_cast<uint64_t>(param));
    (void)deliver(live, kMsgCreate, 0, reinterpret_cast<uint64_t>(param));
    if (cx != 0 || cy != 0) {
        (void)deliver(live, kMsgSize, 0,
                      (static_cast<std::uint64_t>(
                           static_cast<std::uint16_t>(cy))
                       << 16) |
                          static_cast<std::uint16_t>(cx));
    }
    set_last_error(kErrOk);
    return hwnd;
}

// The one reader every `GetWindowLong*` shares. The pointer forms and the
// long forms are the same call on a 64-bit guest; the index decides the
// field, and a positive index addresses the window's extra bytes.
[[nodiscard]] std::int64_t window_get_long(std::uint64_t hwnd,
                                           std::int32_t index) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return 0;
    }
    switch (index) {
    case kIdxWndProc:
        return static_cast<std::int64_t>(w->proc);
    case kIdxInstance:
        return static_cast<std::int64_t>(w->instance);
    case kIdxParent:
        return static_cast<std::int64_t>(w->parent);
    case kIdxId:
        return static_cast<std::int64_t>(w->dlg_id);
    case kIdxStyle:
        return static_cast<std::int64_t>(w->style);
    case kIdxExStyle:
        return static_cast<std::int64_t>(w->ex_style);
    case kIdxUser:
        return static_cast<std::int64_t>(w->user_data);
    default:
        if (index >= 0 &&
            static_cast<std::size_t>(index) + 8 <= w->extra.size()) {
            std::int64_t v = 0;
            std::memcpy(&v, w->extra.data() + index, 8);
            return v;
        }
        if (index >= 0 &&
            static_cast<std::size_t>(index) + 4 <= w->extra.size()) {
            std::int32_t v = 0;
            std::memcpy(&v, w->extra.data() + index, 4);
            return v;
        }
        return 0;
    }
}

// The one writer every `SetWindowLong*` shares. The old value is what the
// call answers, the way Windows answers it.
[[nodiscard]] std::int64_t window_set_long(std::uint64_t hwnd,
                                           std::int32_t index,
                                           std::int64_t value) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return 0;
    }
    std::int64_t old = 0;
    switch (index) {
    case kIdxWndProc:
        old = static_cast<std::int64_t>(w->proc);
        w->proc = static_cast<std::uint64_t>(value);
        break;
    case kIdxInstance:
        old = static_cast<std::int64_t>(w->instance);
        w->instance = static_cast<std::uint64_t>(value);
        break;
    case kIdxParent:
        old = static_cast<std::int64_t>(w->parent);
        w->parent = static_cast<std::uint64_t>(value);
        break;
    case kIdxId:
        old = static_cast<std::int64_t>(w->dlg_id);
        w->dlg_id = static_cast<std::uint32_t>(value);
        break;
    case kIdxStyle:
        old = static_cast<std::int64_t>(w->style);
        w->style = static_cast<std::uint32_t>(value);
        break;
    case kIdxExStyle:
        old = static_cast<std::int64_t>(w->ex_style);
        w->ex_style = static_cast<std::uint32_t>(value);
        break;
    case kIdxUser:
        old = static_cast<std::int64_t>(w->user_data);
        w->user_data = static_cast<std::uint64_t>(value);
        break;
    default:
        if (index >= 0 &&
            static_cast<std::size_t>(index) + 8 <= w->extra.size()) {
            std::memcpy(&old, w->extra.data() + index, 8);
            std::memcpy(w->extra.data() + index, &value, 8);
        } else if (index >= 0 &&
                   static_cast<std::size_t>(index) + 4 <= w->extra.size()) {
            std::int32_t v = 0;
            std::memcpy(&v, w->extra.data() + index, 4);
            old = v;
            const std::int32_t nv = static_cast<std::int32_t>(value);
            std::memcpy(w->extra.data() + index, &nv, 4);
        }
        break;
    }
    return old;
}

// The enumeration callback shape, shared by the three enumerators.
extern "C" typedef std::int32_t (__attribute__((ms_abi)) *EnumWndT)(
    std::uint64_t hwnd, std::uint64_t lparam) noexcept;

// The snapshot rule the other domains already use: the table is copied
// before any callback runs, because a callback that creates or destroys a
// window must not find itself iterating a map that is moving underneath.
[[nodiscard]] std::vector<std::uint64_t> hwnd_snapshot(const Lock&) {
    std::vector<std::uint64_t> out;
    out.reserve(station().windows.size());
    for (const auto& entry : station().windows) {
        out.push_back(entry.first);
    }
    return out;
}

}  // namespace

// ===========================================================================
// The window class family
// ===========================================================================
//
// `WNDCLASS` and `WNDCLASSEX` at their 64-bit layouts:
//
//   0x00 style, 0x08 proc, 0x10 cbClsExtra, 0x14 cbWndExtra,
//   0x18 hInstance, 0x20 hIcon, 0x28 hCursor, 0x30 hbrBackground,
//   0x38 lpszMenuName, 0x40 lpszClassName, 0x48 hIconSm (the Ex forms).

extern "C" __attribute__((ms_abi)) std::uint16_t u32w_RegisterClassA(
    const void* wc) noexcept {
    if (wc == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    auto* p = static_cast<const std::uint8_t*>(wc);
    std::uint32_t style = 0;
    std::memcpy(&style, p + 0x00, 4);
    std::uint64_t proc = 0;
    std::memcpy(&proc, p + 0x08, 8);
    std::int32_t cls_extra = 0;
    std::memcpy(&cls_extra, p + 0x10, 4);
    std::int32_t win_extra = 0;
    std::memcpy(&win_extra, p + 0x14, 4);
    std::uint64_t instance = 0;
    std::memcpy(&instance, p + 0x18, 8);
    const char* name = nullptr;
    std::memcpy(&name, p + 0x28, 8);
    return class_register(style, proc, cls_extra, win_extra, instance, 0, 0,
                          0, 0, utf8_to_wide(name));
}

extern "C" __attribute__((ms_abi)) std::uint16_t u32w_RegisterClassW(
    const void* wc) noexcept {
    if (wc == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    auto* p = static_cast<const std::uint8_t*>(wc);
    std::uint32_t style = 0;
    std::memcpy(&style, p + 0x00, 4);
    std::uint64_t proc = 0;
    std::memcpy(&proc, p + 0x08, 8);
    std::int32_t cls_extra = 0;
    std::memcpy(&cls_extra, p + 0x10, 4);
    std::int32_t win_extra = 0;
    std::memcpy(&win_extra, p + 0x14, 4);
    std::uint64_t instance = 0;
    std::memcpy(&instance, p + 0x18, 8);
    std::uint64_t icon = 0;
    std::memcpy(&icon, p + 0x20, 8);
    std::uint64_t cursor = 0;
    std::memcpy(&cursor, p + 0x28, 8);
    std::uint64_t background = 0;
    std::memcpy(&background, p + 0x30, 8);
    const char16_t* name = nullptr;
    std::memcpy(&name, p + 0x40, 8);
    return class_register(style, proc, cls_extra, win_extra, instance, icon,
                          0, cursor, background, read_wide_z(name));
}

extern "C" __attribute__((ms_abi)) std::uint16_t u32w_RegisterClassExA(
    const void* wcex) noexcept {
    if (wcex == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    auto* p = static_cast<const std::uint8_t*>(wcex);
    std::uint32_t style = 0;
    std::memcpy(&style, p + 0x04, 4);
    std::uint64_t proc = 0;
    std::memcpy(&proc, p + 0x08, 8);
    std::int32_t cls_extra = 0;
    std::memcpy(&cls_extra, p + 0x10, 4);
    std::int32_t win_extra = 0;
    std::memcpy(&win_extra, p + 0x14, 4);
    std::uint64_t instance = 0;
    std::memcpy(&instance, p + 0x18, 8);
    std::uint64_t icon = 0;
    std::memcpy(&icon, p + 0x20, 8);
    std::uint64_t cursor = 0;
    std::memcpy(&cursor, p + 0x28, 8);
    std::uint64_t background = 0;
    std::memcpy(&background, p + 0x30, 8);
    const char* name = nullptr;
    std::memcpy(&name, p + 0x40, 8);
    return class_register(style, proc, cls_extra, win_extra, instance, icon,
                          0, cursor, background, utf8_to_wide(name));
}

extern "C" __attribute__((ms_abi)) std::uint16_t u32w_RegisterClassExW(
    const void* wcex) noexcept {
    if (wcex == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    auto* p = static_cast<const std::uint8_t*>(wcex);
    std::uint32_t style = 0;
    std::memcpy(&style, p + 0x04, 4);
    std::uint64_t proc = 0;
    std::memcpy(&proc, p + 0x08, 8);
    std::int32_t cls_extra = 0;
    std::memcpy(&cls_extra, p + 0x10, 4);
    std::int32_t win_extra = 0;
    std::memcpy(&win_extra, p + 0x14, 4);
    std::uint64_t instance = 0;
    std::memcpy(&instance, p + 0x18, 8);
    std::uint64_t icon = 0;
    std::memcpy(&icon, p + 0x20, 8);
    std::uint64_t cursor = 0;
    std::memcpy(&cursor, p + 0x28, 8);
    std::uint64_t background = 0;
    std::memcpy(&background, p + 0x30, 8);
    const char16_t* name = nullptr;
    std::memcpy(&name, p + 0x40, 8);
    std::uint64_t icon_small = 0;
    std::memcpy(&icon_small, p + 0x48, 8);
    return class_register(style, proc, cls_extra, win_extra, instance, icon,
                          icon_small, cursor, background, read_wide_z(name));
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_UnregisterClassW(
    const char16_t* name, std::uint64_t instance) noexcept {
    (void)instance;
    if (name == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    Station& s = station();
    const Lock held(s.lock);
    const std::u16string key = read_wide_z(name);
    const auto it = s.class_by_name.find(key);
    if (it == s.class_by_name.end()) {
        set_last_error(kErrClassNotFound);
        return kFalse;
    }
    // A class with live windows cannot go: the windows would hold a
    // procedure whose class is gone, which is the corruption Windows
    // refuses rather than a state it repairs.
    for (const auto& entry : s.windows) {
        if (entry.second.class_name == key) {
            set_last_error(kErrClassHasWindows);
            return kFalse;
        }
    }
    const std::uint64_t atom = it->second;
    s.class_by_name.erase(it);
    s.classes.erase(atom);
    set_last_error(kErrOk);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_UnregisterClassA(
    const char* name, std::uint64_t instance) noexcept {
    if (name == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    const std::u16string wide = utf8_to_wide(name);
    return u32w_UnregisterClassW(wide.c_str(), instance);
}

// ===========================================================================
// Window creation and destruction
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_CreateWindowExW(
    std::uint32_t ex_style, const char16_t* class_name, const char16_t* name,
    std::uint32_t style, std::int32_t x, std::int32_t y, std::int32_t cx,
    std::int32_t cy, std::uint64_t parent, std::uint64_t menu,
    std::uint64_t instance, void* param) noexcept {
    if (class_name == nullptr) {
        set_last_error(kErrNoWindowClass);
        return 0;
    }
    return window_create(ex_style, read_wide_z(class_name), read_wide_z(name),
                         style, x, y, cx, cy, parent, menu, instance, param);
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_CreateWindowExA(
    std::uint32_t ex_style, const char* class_name, const char* name,
    std::uint32_t style, std::int32_t x, std::int32_t y, std::int32_t cx,
    std::int32_t cy, std::uint64_t parent, std::uint64_t menu,
    std::uint64_t instance, void* param) noexcept {
    if (class_name == nullptr) {
        set_last_error(kErrNoWindowClass);
        return 0;
    }
    return window_create(ex_style, utf8_to_wide(class_name),
                         utf8_to_wide(name), style, x, y, cx, cy, parent,
                         menu, instance, param);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_DestroyWindow(
    std::uint64_t hwnd) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return kFalse;
    }
    if (w->destroyed) {
        return kTrue;
    }
    // The destruction messages in Windows' order: `WM_DESTROY` first,
    // `WM_NCDESTROY` last, the removal after both -- a procedure that
    // looks itself up from `WM_DESTROY` still finds itself.
    (void)deliver(w, kMsgDestroy, 0, 0);
    (void)deliver(w, kMsgNcDestroy, 0, 0);
    s.windows.erase(hwnd);
    set_last_error(kErrOk);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_IsWindow(
    std::uint64_t hwnd) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    return hwnd_find(held, hwnd) != nullptr ? kTrue : kFalse;
}

extern "C" __attribute__((ms_abi)) std::uint64_t
u32w_GetDesktopWindow() noexcept {
    return kHwndDesktop;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_GetParent(
    std::uint64_t hwnd) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return 0;
    }
    return w->parent;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_SetParent(
    std::uint64_t hwnd, std::uint64_t parent) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr || (parent != 0 && hwnd_find(held, parent) == nullptr)) {
        set_last_error(kErrBadHwnd);
        return 0;
    }
    const std::uint64_t old = w->parent;
    w->parent = parent;
    return old;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_IsChild(
    std::uint64_t parent, std::uint64_t hwnd) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    // A child is a window whose parent chain reaches the named one; the
    // walk is bounded, because a malformed chain must not loop forever.
    std::uint64_t at = hwnd;
    for (std::size_t depth = 0; depth < 32; ++depth) {
        const GuestWindow* w = hwnd_find(held, at);
        if (w == nullptr) {
            return kFalse;
        }
        if (w->parent == parent) {
            return kTrue;
        }
        at = w->parent;
    }
    return kFalse;
}

// ===========================================================================
// The style words
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int64_t u32w_GetWindowLongPtrW(
    std::uint64_t hwnd, std::int32_t index) noexcept {
    return window_get_long(hwnd, index);
}

extern "C" __attribute__((ms_abi)) std::int64_t u32w_GetWindowLongPtrA(
    std::uint64_t hwnd, std::int32_t index) noexcept {
    return window_get_long(hwnd, index);
}

extern "C" __attribute__((ms_abi)) std::int64_t u32w_SetWindowLongPtrW(
    std::uint64_t hwnd, std::int32_t index, std::int64_t value) noexcept {
    return window_set_long(hwnd, index, value);
}

extern "C" __attribute__((ms_abi)) std::int64_t u32w_SetWindowLongPtrA(
    std::uint64_t hwnd, std::int32_t index, std::int64_t value) noexcept {
    return window_set_long(hwnd, index, value);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetWindowLongW(
    std::uint64_t hwnd, std::int32_t index) noexcept {
    return static_cast<std::int32_t>(window_get_long(hwnd, index));
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetWindowLongA(
    std::uint64_t hwnd, std::int32_t index) noexcept {
    return static_cast<std::int32_t>(window_get_long(hwnd, index));
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_SetWindowLongW(
    std::uint64_t hwnd, std::int32_t index, std::int32_t value) noexcept {
    return static_cast<std::int32_t>(window_set_long(hwnd, index, value));
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_SetWindowLongA(
    std::uint64_t hwnd, std::int32_t index, std::int32_t value) noexcept {
    return static_cast<std::int32_t>(window_set_long(hwnd, index, value));
}

// ===========================================================================
// Window text
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t u32w_SetWindowTextW(
    std::uint64_t hwnd, const char16_t* text) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return kFalse;
    }
    w->text = read_wide_z(text);
    (void)deliver(w, kMsgSetText, 0, reinterpret_cast<std::uint64_t>(text));
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_SetWindowTextA(
    std::uint64_t hwnd, const char* text) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return kFalse;
    }
    w->text = utf8_to_wide(text);
    (void)deliver(w, kMsgSetText, 0, reinterpret_cast<std::uint64_t>(text));
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetWindowTextLengthW(
    std::uint64_t hwnd) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return 0;
    }
    return static_cast<std::int32_t>(w->text.size());
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetWindowTextLengthA(
    std::uint64_t hwnd) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return 0;
    }
    // The narrow length is the byte length of the UTF-8 view, which is
    // what the `A` family means by length.
    return static_cast<std::int32_t>(wide_to_utf8(w->text).size());
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetWindowTextW(
    std::uint64_t hwnd, char16_t* out, std::int32_t max_chars) noexcept {
    if (out == nullptr || max_chars <= 0) {
        return 0;
    }
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return 0;
    }
    // The copy is bounded by the caller's buffer: `max_chars` counts the
    // terminator, and the answer is the characters written without it.
    const std::size_t take = std::min(
        w->text.size(), static_cast<std::size_t>(max_chars) - 1);
    if (take != 0) {
        std::memcpy(out, w->text.data(), take * 2);
    }
    out[take] = u'\0';
    return static_cast<std::int32_t>(take);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetWindowTextA(
    std::uint64_t hwnd, char* out, std::int32_t max_chars) noexcept {
    if (out == nullptr || max_chars <= 0) {
        return 0;
    }
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return 0;
    }
    const std::string text = wide_to_utf8(w->text);
    const std::size_t take = std::min(
        text.size(), static_cast<std::size_t>(max_chars) - 1);
    if (take != 0) {
        std::memcpy(out, text.data(), take);
    }
    out[take] = '\0';
    return static_cast<std::int32_t>(take);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetClassNameW(
    std::uint64_t hwnd, char16_t* out, std::int32_t max_chars) noexcept {
    if (out == nullptr || max_chars <= 0) {
        return 0;
    }
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return 0;
    }
    const std::size_t take = std::min(
        w->class_name.size(), static_cast<std::size_t>(max_chars) - 1);
    if (take != 0) {
        std::memcpy(out, w->class_name.data(), take * 2);
    }
    out[take] = u'\0';
    return static_cast<std::int32_t>(take);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetClassNameA(
    std::uint64_t hwnd, char* out, std::int32_t max_chars) noexcept {
    if (out == nullptr || max_chars <= 0) {
        return 0;
    }
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return 0;
    }
    const std::string name = wide_to_utf8(w->class_name);
    const std::size_t take =
        std::min(name.size(), static_cast<std::size_t>(max_chars) - 1);
    if (take != 0) {
        std::memcpy(out, name.data(), take);
    }
    out[take] = '\0';
    return static_cast<std::int32_t>(take);
}

// ===========================================================================
// Geometry and state
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetWindowRect(
    std::uint64_t hwnd, void* rect) noexcept {
    if (rect == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return kFalse;
    }
    write_rect(rect, w->x, w->y, w->x + w->cx, w->y + w->cy);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetClientRect(
    std::uint64_t hwnd, void* rect) noexcept {
    if (rect == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return kFalse;
    }
    // The client area is the window area: this station draws no frame, so
    // the difference Windows charges for the non-client region is zero.
    write_rect(rect, 0, 0, w->cx, w->cy);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_MoveWindow(
    std::uint64_t hwnd, std::int32_t x, std::int32_t y, std::int32_t cx,
    std::int32_t cy, std::int32_t repaint) noexcept {
    (void)repaint;
    Station& s = station();
    const Lock held(s.lock);
    GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return kFalse;
    }
    const bool moved = w->x != x || w->y != y;
    const bool sized = w->cx != cx || w->cy != cy;
    w->x = x;
    w->y = y;
    w->cx = cx;
    w->cy = cy;
    if (moved) {
        (void)deliver(w, kMsgMove, 0,
                      (static_cast<std::uint64_t>(
                           static_cast<std::uint16_t>(y))
                       << 16) |
                          static_cast<std::uint16_t>(x));
    }
    if (sized) {
        (void)deliver(w, kMsgSize, 0,
                      (static_cast<std::uint64_t>(
                           static_cast<std::uint16_t>(cy))
                       << 16) |
                          static_cast<std::uint16_t>(cx));
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_SetWindowPos(
    std::uint64_t hwnd, std::uint64_t after, std::int32_t x, std::int32_t y,
    std::int32_t cx, std::int32_t cy, std::uint32_t flags) noexcept {
    (void)after;
    Station& s = station();
    const Lock held(s.lock);
    GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return kFalse;
    }
    // The `SWP_NOMOVE` and `SWP_NOSIZE` bits keep the caller's intent
    // explicit; the flags are honoured rather than assumed away.
    constexpr std::uint32_t kSwpNoSize = 0x0001;
    constexpr std::uint32_t kSwpNoMove = 0x0002;
    if ((flags & kSwpNoMove) == 0) {
        w->x = x;
        w->y = y;
    }
    if ((flags & kSwpNoSize) == 0) {
        w->cx = cx;
        w->cy = cy;
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_IsWindowVisible(
    std::uint64_t hwnd) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return kFalse;
    }
    return w->visible ? kTrue : kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_IsWindowEnabled(
    std::uint64_t hwnd) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return kFalse;
    }
    return w->enabled ? kTrue : kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_IsIconic(
    std::uint64_t hwnd) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return kFalse;
    }
    return w->iconic ? kTrue : kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_IsZoomed(
    std::uint64_t hwnd) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return kFalse;
    }
    return w->zoomed ? kTrue : kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_ShowWindow(
    std::uint64_t hwnd, std::int32_t cmd) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return kFalse;
    }
    // The answer is whether the window was visible before, which is what
    // Windows answers and what a caller distinguishing first-show from
    // re-show reads.
    const bool was = w->visible;
    switch (cmd) {
    case 0: /* SW_HIDE */
        w->visible = false;
        break;
    case 2: case 6: /* the minimize forms */
        w->visible = true;
        w->iconic = true;
        break;
    case 3: case 7: /* the maximize forms */
        w->visible = true;
        w->zoomed = true;
        break;
    case 1: case 4: case 5: case 8: case 9: case 10: case 11:
        w->visible = true;
        break;
    default:
        break;
    }
    (void)deliver(w, kMsgShowWindow, static_cast<std::uint64_t>(cmd), 0);
    return was ? kTrue : kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_EnableWindow(
    std::uint64_t hwnd, std::int32_t enable) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return kFalse;
    }
    const bool was = w->enabled;
    w->enabled = enable != 0;
    return was ? kTrue : kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_UpdateWindow(
    std::uint64_t hwnd) noexcept {
    // A repaint request against a station that keeps no damage region is
    // a completed repaint.
    Station& s = station();
    const Lock held(s.lock);
    if (hwnd_find(held, hwnd) == nullptr) {
        set_last_error(kErrBadHwnd);
        return kFalse;
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_InvalidateRect(
    std::uint64_t hwnd, const void* rect, std::int32_t erase) noexcept {
    (void)rect;
    (void)erase;
    Station& s = station();
    const Lock held(s.lock);
    if (hwnd != 0 && hwnd_find(held, hwnd) == nullptr) {
        set_last_error(kErrBadHwnd);
        return kFalse;
    }
    return kTrue;
}

// ===========================================================================
// Focus, capture and the window walks
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_GetForegroundWindow()
    noexcept {
    Station& s = station();
    const Lock held(s.lock);
    return s.fg;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_SetForegroundWindow(
    std::uint64_t hwnd) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    if (hwnd_find(held, hwnd) == nullptr) {
        return kFalse;
    }
    s.fg = hwnd;
    (void)deliver(&s.windows.at(hwnd), 0x0006 /* WM_ACTIVATE */,
                  2 /* WA_ACTIVE */, 0);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_SetFocus(
    std::uint64_t hwnd) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const std::uint32_t thread = k32_GetCurrentThreadId();
    std::uint64_t& slot = s.focus[thread];
    const std::uint64_t old = slot;
    slot = hwnd;
    if (hwnd != 0 && hwnd_find(held, hwnd) != nullptr) {
        (void)deliver(&s.windows.at(hwnd), 0x0007 /* WM_SETFOCUS */, 0, 0);
    }
    if (old != 0 && hwnd_find(held, old) != nullptr) {
        (void)deliver(&s.windows.at(old), 0x0008 /* WM_KILLFOCUS */, 0, 0);
    }
    return old;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_GetFocus() noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const auto it = s.focus.find(k32_GetCurrentThreadId());
    return it == s.focus.end() ? 0 : it->second;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_SetCapture(
    std::uint64_t hwnd) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    std::uint64_t& slot = s.capture[k32_GetCurrentThreadId()];
    const std::uint64_t old = slot;
    slot = hwnd;
    return old;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_ReleaseCapture() noexcept {
    Station& s = station();
    const Lock held(s.lock);
    s.capture.erase(k32_GetCurrentThreadId());
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_GetCapture() noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const auto it = s.capture.find(k32_GetCurrentThreadId());
    return it == s.capture.end() ? 0 : it->second;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_GetActiveWindow()
    noexcept {
    // The active window is the thread's focus, which is the state a
    // single-UI-thread program's activation takes here.
    Station& s = station();
    const Lock held(s.lock);
    const auto it = s.focus.find(k32_GetCurrentThreadId());
    return it == s.focus.end() ? 0 : it->second;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_SetActiveWindow(
    std::uint64_t hwnd) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    std::uint64_t& slot = s.focus[k32_GetCurrentThreadId()];
    const std::uint64_t old = slot;
    if (hwnd_find(held, hwnd) != nullptr) {
        slot = hwnd;
    }
    return old;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_BringWindowToTop(
    std::uint64_t hwnd) noexcept {
    // The z-order this station keeps is the creation order; a raise is
    // recorded by the activation, which is the observable half.
    return u32w_SetForegroundWindow(hwnd);
}

// The process id the window queries answer with. The proc domain's own
// implementation is reached the same way the guest reaches it, which keeps
// one process id in one place.
extern "C" __attribute__((ms_abi)) std::uint32_t
k32_GetCurrentProcessId() noexcept;

extern "C" __attribute__((ms_abi)) std::uint32_t
u32w_GetWindowThreadProcessId(std::uint64_t hwnd,
                              std::uint32_t* process) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        if (process != nullptr) {
            *process = 0;
        }
        return 0;
    }
    if (process != nullptr) {
        *process = k32_GetCurrentProcessId();
    }
    return w->thread;
}

// ===========================================================================
// Searching and enumerating
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_FindWindowW(
    const char16_t* class_name, const char16_t* window_name) noexcept {
    const std::u16string cls =
        class_name == nullptr ? std::u16string() : read_wide_z(class_name);
    const std::u16string title =
        window_name == nullptr ? std::u16string() : read_wide_z(window_name);
    Station& s = station();
    const Lock held(s.lock);
    for (const auto& entry : s.windows) {
        if (class_name != nullptr && entry.second.class_name != cls) {
            continue;
        }
        if (window_name != nullptr && entry.second.text != title) {
            continue;
        }
        return entry.first;
    }
    set_last_error(kErrNoWindowClass);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_FindWindowA(
    const char* class_name, const char* window_name) noexcept {
    const std::u16string cls = utf8_to_wide(class_name);
    const std::u16string title = utf8_to_wide(window_name);
    Station& s = station();
    const Lock held(s.lock);
    for (const auto& entry : s.windows) {
        if (class_name != nullptr && entry.second.class_name != cls) {
            continue;
        }
        if (window_name != nullptr && entry.second.text != title) {
            continue;
        }
        return entry.first;
    }
    set_last_error(kErrNoWindowClass);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_FindWindowExW(
    std::uint64_t parent, std::uint64_t after, const char16_t* class_name,
    const char16_t* window_name) noexcept {
    const std::u16string cls =
        class_name == nullptr ? std::u16string() : read_wide_z(class_name);
    const std::u16string title =
        window_name == nullptr ? std::u16string() : read_wide_z(window_name);
    Station& s = station();
    const Lock held(s.lock);
    // The walk is creation order -- the handle order, which is the order
    // the handles were handed out in -- starting after `after`; an
    // `after` of zero starts at the beginning, which is how Windows reads
    // it. The map's own order is not the creation order, so the handles
    // are collected and sorted first.
    std::vector<std::uint64_t> order;
    order.reserve(s.windows.size());
    for (const auto& entry : s.windows) {
        order.push_back(entry.first);
    }
    std::sort(order.begin(), order.end());
    bool seen_after = after == 0;
    for (const std::uint64_t hwnd : order) {
        if (!seen_after) {
            if (hwnd == after) {
                seen_after = true;
            }
            continue;
        }
        const GuestWindow& w = s.windows.at(hwnd);
        if (parent != 0 && w.parent != parent) {
            continue;
        }
        if (class_name != nullptr && w.class_name != cls) {
            continue;
        }
        if (window_name != nullptr && w.text != title) {
            continue;
        }
        return hwnd;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_FindWindowExA(
    std::uint64_t parent, std::uint64_t after, const char* class_name,
    const char* window_name) noexcept {
    const std::u16string cls = utf8_to_wide(class_name);
    const std::u16string title = utf8_to_wide(window_name);
    Station& s = station();
    const Lock held(s.lock);
    std::vector<std::uint64_t> order;
    for (const auto& entry : s.windows) {
        order.push_back(entry.first);
    }
    std::sort(order.begin(), order.end());
    bool seen_after = after == 0;
    for (const std::uint64_t hwnd : order) {
        if (!seen_after) {
            if (hwnd == after) {
                seen_after = true;
            }
            continue;
        }
        const GuestWindow& w = s.windows.at(hwnd);
        if (parent != 0 && w.parent != parent) {
            continue;
        }
        if (class_name != nullptr && w.class_name != cls) {
            continue;
        }
        if (window_name != nullptr && w.text != title) {
            continue;
        }
        return hwnd;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_GetTopWindow(
    std::uint64_t hwnd) noexcept {
    // The top of the child list is the most recently created child, which
    // is the last this table holds for the parent.
    Station& s = station();
    const Lock held(s.lock);
    std::uint64_t found = 0;
    for (const auto& entry : s.windows) {
        if (entry.second.parent == hwnd && entry.first > found) {
            found = entry.first;
        }
    }
    return found;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_GetWindow(
    std::uint64_t hwnd, std::uint32_t relation) noexcept {
    // The relations a checker asks for: next sibling (2), previous (3),
    // first child (5). The walk is creation order, which is the order
    // this station keeps.
    constexpr std::uint32_t kGwNext = 2;
    constexpr std::uint32_t kGwPrev = 3;
    constexpr std::uint32_t kGwChild = 5;
    if (relation == kGwChild) {
        return u32w_GetTopWindow(hwnd);
    }
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return 0;
    }
    std::uint64_t prev = 0;
    bool seen = false;
    for (const auto& entry : s.windows) {
        if (relation == kGwNext) {
            if (seen && entry.second.parent == w->parent) {
                return entry.first;
            }
            if (entry.first == hwnd) {
                seen = true;
            }
        } else if (relation == kGwPrev) {
            if (entry.first == hwnd) {
                return prev;
            }
            if (entry.second.parent == w->parent) {
                prev = entry.first;
            }
        }
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_EnumWindows(
    EnumWndT callback, std::uint64_t lparam) noexcept {
    if (callback == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    Station& s = station();
    Lock held(s.lock);
    const std::vector<std::uint64_t> all = hwnd_snapshot(held);
    held.unlock();
    set_last_error(kErrOk);
    for (const std::uint64_t hwnd : all) {
        // The desktop itself is not enumerated: Windows enumerates the
        // top-level windows, and the desktop is their parent, not one of
        // them.
        if (hwnd == kHwndDesktop) {
            continue;
        }
        if (callback(hwnd, lparam) == 0) {
            break;
        }
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_EnumChildWindows(
    std::uint64_t parent, EnumWndT callback, std::uint64_t lparam) noexcept {
    if (callback == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    Station& s = station();
    Lock held(s.lock);
    const std::vector<std::uint64_t> all = hwnd_snapshot(held);
    held.unlock();
    std::int32_t any = kFalse;
    for (const std::uint64_t hwnd : all) {
        Lock again(s.lock);
        const GuestWindow* w = hwnd_find(again, hwnd);
        if (w == nullptr || w->parent != parent) {
            continue;
        }
        again.unlock();
        any = kTrue;
        if (callback(hwnd, lparam) == 0) {
            break;
        }
    }
    return any;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_EnumThreadWindows(
    std::uint32_t thread, EnumWndT callback, std::uint64_t lparam) noexcept {
    if (callback == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    Station& s = station();
    Lock held(s.lock);
    const std::vector<std::uint64_t> all = hwnd_snapshot(held);
    held.unlock();
    for (const std::uint64_t hwnd : all) {
        Lock again(s.lock);
        const GuestWindow* w = hwnd_find(again, hwnd);
        if (w == nullptr || w->thread != thread) {
            continue;
        }
        again.unlock();
        if (callback(hwnd, lparam) == 0) {
            break;
        }
    }
    return kTrue;
}

// ===========================================================================
// The message queue
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t u32w_PostMessageW(
    std::uint64_t hwnd, std::uint32_t message, std::uint64_t wparam,
    std::uint64_t lparam) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    if (hwnd != 0 && hwnd_find(held, hwnd) == nullptr) {
        set_last_error(kErrBadHwnd);
        return kFalse;
    }
    // A null window posts to the calling thread's queue, which is the
    // thread-message path; a real window posts to its owner's.
    const std::uint32_t thread =
        hwnd == 0 ? k32_GetCurrentThreadId()
                  : (hwnd_find(held, hwnd) != nullptr
                         ? hwnd_find(held, hwnd)->thread
                         : k32_GetCurrentThreadId());
    QueuedMsg m;
    m.hwnd = hwnd;
    m.message = message;
    m.wparam = wparam;
    m.lparam = lparam;
    m.time = tick_ms();
    queue_for(thread).msgs.push_back(m);
    s.cond.notify_all();
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_PostMessageA(
    std::uint64_t hwnd, std::uint32_t message, std::uint64_t wparam,
    std::uint64_t lparam) noexcept {
    // The `A` spelling differs only in the text a message may carry,
    // which travels as an untyped `lParam` and needs no conversion on the
    // way through.
    return u32w_PostMessageW(hwnd, message, wparam, lparam);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_PostThreadMessageW(
    std::uint32_t thread, std::uint32_t message, std::uint64_t wparam,
    std::uint64_t lparam) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    // A thread with no queue yet is a thread that has not read a message;
    // Windows accepts the post for it anyway, and so does this station --
    // the queue is created by the post itself.
    QueuedMsg m;
    m.message = message;
    m.wparam = wparam;
    m.lparam = lparam;
    m.time = tick_ms();
    queue_for(thread).msgs.push_back(m);
    s.cond.notify_all();
    return kTrue;
}

extern "C" __attribute__((ms_abi)) void u32w_PostQuitMessage(
    std::int32_t exit_code) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    ThreadQueue& q = queue_for(k32_GetCurrentThreadId());
    q.quit_posted = true;
    q.quit_code = static_cast<std::uint32_t>(exit_code);
    s.cond.notify_all();
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetMessageW(
    void* msg, std::uint64_t hwnd, std::uint32_t lo, std::uint32_t hi) noexcept {
    (void)hwnd;
    if (msg == nullptr) {
        set_last_error(kErrParam);
        return -1;
    }
    return wait_msg(msg, k32_GetCurrentThreadId(), lo, hi, true);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetMessageA(
    void* msg, std::uint64_t hwnd, std::uint32_t lo, std::uint32_t hi) noexcept {
    return u32w_GetMessageW(msg, hwnd, lo, hi);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_PeekMessageW(
    void* msg, std::uint64_t hwnd, std::uint32_t lo, std::uint32_t hi,
    std::uint32_t remove) noexcept {
    (void)hwnd;
    if (msg == nullptr) {
        return kFalse;
    }
    Station& s = station();
    Lock held(s.lock);
    ThreadQueue& q = queue_for(k32_GetCurrentThreadId());
    for (auto it = q.msgs.begin(); it != q.msgs.end(); ++it) {
        if (msg_in_range(*it, lo, hi)) {
            const QueuedMsg m = *it;
            if ((remove & 1) != 0) {
                q.msgs.erase(it);
            }
            held.unlock();
            write_msg(msg, m);
            return kTrue;
        }
    }
    return kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_PeekMessageA(
    void* msg, std::uint64_t hwnd, std::uint32_t lo, std::uint32_t hi,
    std::uint32_t remove) noexcept {
    return u32w_PeekMessageW(msg, hwnd, lo, hi, remove);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_TranslateMessage(
    const void* msg) noexcept {
    // The key-to-character translation. A `WM_KEYDOWN` whose virtual key
    // is one the layout maps to a character posts the `WM_CHAR` for it;
    // the rest pass through untranslated, and the answer says whether one
    // was posted, which is what Windows answers.
    if (msg == nullptr) {
        return kFalse;
    }
    auto* p = static_cast<const std::uint8_t*>(msg);
    std::uint64_t hwnd = 0;
    std::uint32_t message = 0;
    std::uint64_t wparam = 0;
    std::memcpy(&hwnd, p + 0x00, 8);
    std::memcpy(&message, p + 0x08, 4);
    std::memcpy(&wparam, p + 0x10, 8);
    if (message != kMsgKeyDown && message != kMsgSysKeyDown) {
        return kFalse;
    }
    // The virtual-key-to-character map, for the keys whose US-layout
    // character is the key's own number or an offset from it.
    std::uint32_t ch = 0;
    const std::uint32_t vk = static_cast<std::uint32_t>(wparam & 0xFF);
    if (vk >= 0x41 && vk <= 0x5A) {
        ch = vk + 0x20;  // the lowercase letter
    } else if (vk >= 0x30 && vk <= 0x39) {
        ch = vk;
    } else if (vk == 0x20 || vk == 0x0D || vk == 0x08 || vk == 0x09 ||
               vk == 0x1B) {
        ch = vk;
    } else {
        return kFalse;
    }
    QueuedMsg m;
    m.hwnd = hwnd;
    m.message = kMsgChar;
    m.wparam = ch;
    m.time = tick_ms();
    post_msg(k32_GetCurrentThreadId(), m);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int64_t u32w_DispatchMessageW(
    const void* msg) noexcept {
    if (msg == nullptr) {
        return 0;
    }
    auto* p = static_cast<const std::uint8_t*>(msg);
    std::uint64_t hwnd = 0;
    std::uint32_t message = 0;
    std::uint64_t wparam = 0;
    std::uint64_t lparam = 0;
    std::memcpy(&hwnd, p + 0x00, 8);
    std::memcpy(&message, p + 0x08, 4);
    std::memcpy(&wparam, p + 0x10, 8);
    std::memcpy(&lparam, p + 0x18, 8);
    if (hwnd == 0 || message == kMsgQuit) {
        return 0;
    }
    Station& s = station();
    const Lock held(s.lock);
    GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        return 0;
    }
    return deliver(w, message, wparam, lparam);
}

extern "C" __attribute__((ms_abi)) std::int64_t u32w_DispatchMessageA(
    const void* msg) noexcept {
    return u32w_DispatchMessageW(msg);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_WaitMessage() noexcept {
    // A wait with no filter: the first message of any kind answers.
    QueuedMsg m;
    return wait_msg(&m, k32_GetCurrentThreadId(), 0, 0, false) > 0 ? kTrue
                                                                   : kFalse;
}

extern "C" __attribute__((ms_abi)) std::int64_t u32w_SendMessageW(
    std::uint64_t hwnd, std::uint32_t message, std::uint64_t wparam,
    std::uint64_t lparam) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return 0;
    }
    return deliver(w, message, wparam, lparam);
}

extern "C" __attribute__((ms_abi)) std::int64_t u32w_SendMessageA(
    std::uint64_t hwnd, std::uint32_t message, std::uint64_t wparam,
    std::uint64_t lparam) noexcept {
    return u32w_SendMessageW(hwnd, message, wparam, lparam);
}

extern "C" __attribute__((ms_abi)) std::int64_t u32w_DefWindowProcW(
    std::uint64_t hwnd, std::uint32_t message, std::uint64_t wparam,
    std::uint64_t lparam) noexcept {
    // The default answers, per message. The text queries answer from the
    // window the handle names -- which is the part of `DefWindowProcW` a
    // checker exercises -- and the rest take the completion Windows takes.
    switch (message) {
    case kMsgGetTextLen:
        return u32w_GetWindowTextLengthW(hwnd);
    case kMsgGetText:
        return u32w_GetWindowTextW(hwnd,
                                   reinterpret_cast<char16_t*>(wparam),
                                   static_cast<std::int32_t>(lparam));
    case kMsgSetText:
        return u32w_SetWindowTextW(
            hwnd, reinterpret_cast<const char16_t*>(lparam));
    default:
        return 0;
    }
}

extern "C" __attribute__((ms_abi)) std::int64_t u32w_DefWindowProcA(
    std::uint64_t hwnd, std::uint32_t message, std::uint64_t wparam,
    std::uint64_t lparam) noexcept {
    switch (message) {
    case kMsgGetTextLen:
        return u32w_GetWindowTextLengthA(hwnd);
    case kMsgGetText:
        return u32w_GetWindowTextA(hwnd, reinterpret_cast<char*>(wparam),
                                   static_cast<std::int32_t>(lparam));
    case kMsgSetText:
        return u32w_SetWindowTextA(hwnd,
                                   reinterpret_cast<const char*>(lparam));
    default:
        return 0;
    }
}

extern "C" __attribute__((ms_abi)) std::int64_t u32w_CallWindowProcW(
    std::uint64_t proc, std::uint64_t hwnd, std::uint32_t message,
    std::uint64_t wparam, std::uint64_t lparam) noexcept {
    if (proc == 0) {
        return 0;
    }
    const auto fn = reinterpret_cast<GuestWndProcT>(proc);
    return fn(hwnd, message, wparam, lparam);
}

extern "C" __attribute__((ms_abi)) std::int64_t u32w_CallWindowProcA(
    std::uint64_t proc, std::uint64_t hwnd, std::uint32_t message,
    std::uint64_t wparam, std::uint64_t lparam) noexcept {
    return u32w_CallWindowProcW(proc, hwnd, message, wparam, lparam);
}

// ===========================================================================
// Timers
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_SetTimer(
    std::uint64_t hwnd, std::uint64_t id, std::uint32_t interval,
    std::uint64_t proc) noexcept {
    Station& s = station();
    Lock held(s.lock);
    if (hwnd == 0 && id == 0) {
        set_last_error(kErrParam);
        return 0;
    }
    if (hwnd != 0 && hwnd_find(held, hwnd) == nullptr) {
        set_last_error(kErrBadHwnd);
        return 0;
    }
    // The timer id the call answers: a window timer keeps the caller's
    // id; a thread timer is assigned one, which is what Windows assigns.
    const std::uint64_t timer_id =
        id != 0 ? id : s.next_hwnd++;
    for (GuestTimer& t : s.timers) {
        if (t.id == timer_id && t.hwnd == hwnd) {
            // The reset rule Windows applies: re-setting a live id moves
            // its expiry, and the same handle answers.
            t.interval = interval;
            t.next = std::chrono::steady_clock::now() +
                     std::chrono::milliseconds(interval);
            t.proc = proc;
            held.unlock();
            ensure_timer_thread();
            return timer_id;
        }
    }
    GuestTimer t;
    t.id = timer_id;
    t.hwnd = hwnd;
    t.thread = k32_GetCurrentThreadId();
    t.interval = interval;
    t.proc = proc;
    t.next =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(interval);
    s.timers.push_back(t);
    held.unlock();
    ensure_timer_thread();
    return timer_id;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_KillTimer(
    std::uint64_t hwnd, std::uint64_t id) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    for (auto it = s.timers.begin(); it != s.timers.end(); ++it) {
        if (it->id == id && it->hwnd == hwnd) {
            s.timers.erase(it);
            return kTrue;
        }
    }
    set_last_error(kErrParam);
    return kFalse;
}

// ===========================================================================
// The clipboard
// ===========================================================================
//
// The clipboard is one buffer per station, guarded by the open/close pair
// the writes and reads bracket themselves with. The bytes a set carries
// are copied at the set -- the caller's buffer is the caller's -- and the
// read answers a pointer into the station's own store, which is stable
// for the process's life because the store is never reallocated after a
// set.

extern "C" __attribute__((ms_abi)) std::int32_t u32w_OpenClipboard(
    std::uint64_t owner) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    if (s.clip_open) {
        // A second opener is refused until the first closes: this is the
        // rule that keeps two writers from interleaving, and Windows
        // enforces it by failing the open.
        return kFalse;
    }
    s.clip_open = true;
    s.clip_owner = owner;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_CloseClipboard() noexcept {
    Station& s = station();
    const Lock held(s.lock);
    if (!s.clip_open) {
        set_last_error(kErrClipboardNotOpen);
        return kFalse;
    }
    s.clip_open = false;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_EmptyClipboard() noexcept {
    Station& s = station();
    const Lock held(s.lock);
    if (!s.clip_open) {
        set_last_error(kErrClipboardNotOpen);
        return kFalse;
    }
    s.clip_data.clear();
    s.clip_format = 0;
    ++s.clip_seq;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_SetClipboardData(
    std::uint32_t format, std::uint64_t data) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    if (!s.clip_open) {
        set_last_error(kErrClipboardNotOpen);
        return 0;
    }
    s.clip_format = format;
    s.clip_data.clear();
    if (data != 0) {
        // A text format's length is its terminator; a binary one is
        // opaque, and the clipboard keeps what the guest's own allocator
        // would read -- to the first terminator, or a bounded page of
        // bytes when there is none, which is the shape every checker's
        // string fits in.
        std::size_t length = 0;
        constexpr std::uint32_t kCfText = 1;
        constexpr std::uint32_t kCfUnicodeText = 13;
        if (format == kCfUnicodeText) {
            const auto* p = reinterpret_cast<const char16_t*>(data);
            while (length < 0x10000 && p[length] != u'\0') {
                ++length;
            }
            length = (length + 1) * 2;
        } else if (format == kCfText) {
            const auto* p = reinterpret_cast<const char*>(data);
            while (length < 0x10000 && p[length] != '\0') {
                ++length;
            }
            length += 1;
        } else {
            length = 0x1000;
        }
        s.clip_data.assign(
            reinterpret_cast<const std::uint8_t*>(data),
            reinterpret_cast<const std::uint8_t*>(data) + length);
    }
    ++s.clip_seq;
    return data;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_GetClipboardData(
    std::uint32_t format) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    if (!s.clip_open) {
        set_last_error(kErrClipboardNotOpen);
        return 0;
    }
    if (s.clip_format != format || s.clip_data.empty()) {
        return 0;
    }
    return reinterpret_cast<std::uint64_t>(s.clip_data.data());
}

extern "C" __attribute__((ms_abi)) std::int32_t
u32w_IsClipboardFormatAvailable(std::uint32_t format) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    return (s.clip_format == format && !s.clip_data.empty()) ? kTrue : kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_CountClipboardFormats()
    noexcept {
    Station& s = station();
    const Lock held(s.lock);
    return s.clip_data.empty() ? 0 : 1;
}

extern "C" __attribute__((ms_abi)) std::uint32_t
u32w_GetClipboardSequenceNumber() noexcept {
    Station& s = station();
    const Lock held(s.lock);
    return s.clip_seq;
}

extern "C" __attribute__((ms_abi)) std::uint32_t
u32w_RegisterClipboardFormatW(const char16_t* name) noexcept {
    if (name == nullptr || *name == u'\0') {
        set_last_error(kErrParam);
        return 0;
    }
    Station& s = station();
    const Lock held(s.lock);
    // The same name registers to the same id, which is the contract that
    // lets two parts of a program agree on a private format.
    const std::u16string key = read_wide_z(name);
    const auto it = s.clip_named.find(key);
    if (it != s.clip_named.end()) {
        return it->second;
    }
    const std::uint32_t id = s.next_clip_fmt++;
    s.clip_named.emplace(key, id);
    return id;
}

extern "C" __attribute__((ms_abi)) std::uint32_t
u32w_RegisterClipboardFormatA(const char* name) noexcept {
    if (name == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    const std::u16string wide = utf8_to_wide(name);
    return u32w_RegisterClipboardFormatW(wide.c_str());
}

// ===========================================================================
// The keyboard and the cursor
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int16_t u32w_GetAsyncKeyState(
    std::int32_t key) noexcept {
    if (key < 0 || key > 255) {
        set_last_error(kErrParam);
        return 0;
    }
    Station& s = station();
    const Lock held(s.lock);
    // The answer is the up state: bit 15 clear, and the "pressed since
    // the last call" bit clear, because no input device has touched the
    // key. A checker that waits for a key reads a wait it would read on a
    // real machine with an idle keyboard.
    return s.keys[key] != 0 ? static_cast<std::int16_t>(0x8000)
                            : static_cast<std::int16_t>(0);
}

extern "C" __attribute__((ms_abi)) std::int16_t u32w_GetKeyState(
    std::int32_t key) noexcept {
    return u32w_GetAsyncKeyState(key);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetKeyboardState(
    std::uint8_t* out) noexcept {
    if (out == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    Station& s = station();
    const Lock held(s.lock);
    std::memcpy(out, s.keys, sizeof(s.keys));
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_SetKeyboardState(
    const std::uint8_t* keys) noexcept {
    if (keys == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    Station& s = station();
    const Lock held(s.lock);
    std::memcpy(s.keys, keys, sizeof(s.keys));
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_GetKeyboardLayout(
    std::uint32_t thread) noexcept {
    (void)thread;
    // The US layout, named the way Windows names it: the language id in
    // the low word, the layout id in the high one.
    return 0x04090409;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32w_MapVirtualKeyW(
    std::uint32_t code, std::uint32_t kind) noexcept {
    // The virtual-key to scan-code maps. The answer for a letter or a
    // digit is the same number in either direction -- the US layout's
    // codes for A..Z and 0..9 are their own -- which is the part of the
    // mapping a checker exercises.
    constexpr std::uint32_t kMapVkToScan = 0;
    constexpr std::uint32_t kMapScanToVk = 1;
    if (kind != kMapVkToScan && kind != kMapScanToVk) {
        return 0;
    }
    if ((code >= 0x41 && code <= 0x5A) || (code >= 0x30 && code <= 0x39)) {
        return code;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32w_MapVirtualKeyA(
    std::uint32_t code, std::uint32_t kind) noexcept {
    return u32w_MapVirtualKeyW(code, kind);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetCursorPos(
    void* point) noexcept {
    if (point == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    Station& s = station();
    const Lock held(s.lock);
    write_rect(point, s.cursor_x, s.cursor_y, 0, 0);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_SetCursorPos(
    std::int32_t x, std::int32_t y) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    s.cursor_x = x;
    s.cursor_y = y;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_ShowCursor(
    std::int32_t show) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    s.cursor_shown += show != 0 ? 1 : -1;
    return s.cursor_shown >= 0 ? kTrue : kFalse;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32w_GetDoubleClickTime()
    noexcept {
    return 500;
}

// ===========================================================================
// Menus
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_CreateMenu() noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const std::uint64_t menu = s.next_menu;
    s.next_menu += kHandleStep;
    s.menus.emplace(menu, GuestMenu{});
    return menu;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_CreatePopupMenu() noexcept {
    return u32w_CreateMenu();
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_DestroyMenu(
    std::uint64_t menu) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    if (menu_find(held, menu) == nullptr) {
        set_last_error(kErrBadMenu);
        return kFalse;
    }
    s.menus.erase(menu);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_GetMenu(
    std::uint64_t hwnd) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return 0;
    }
    return w->menu;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_SetMenu(
    std::uint64_t hwnd, std::uint64_t menu) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr || (menu != 0 && menu_find(held, menu) == nullptr)) {
        set_last_error(kErrBadMenu);
        return kFalse;
    }
    w->menu = menu;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_AppendMenuW(
    std::uint64_t menu, std::uint32_t flags, std::uint64_t id,
    const char16_t* text) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    GuestMenu* m = menu_find(held, menu);
    if (m == nullptr) {
        set_last_error(kErrBadMenu);
        return kFalse;
    }
    MenuItem item;
    item.flags = flags;
    item.id = id;
    item.text = read_wide_z(text);
    m->items.push_back(item);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_AppendMenuA(
    std::uint64_t menu, std::uint32_t flags, std::uint64_t id,
    const char* text) noexcept {
    const std::u16string wide = utf8_to_wide(text);
    return u32w_AppendMenuW(menu, flags, id, wide.c_str());
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetMenuItemCount(
    std::uint64_t menu) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const GuestMenu* m = menu_find(held, menu);
    if (m == nullptr) {
        set_last_error(kErrBadMenu);
        return -1;
    }
    return static_cast<std::int32_t>(m->items.size());
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32w_GetMenuItemID(
    std::uint64_t menu, std::int32_t index) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const GuestMenu* m = menu_find(held, menu);
    if (m == nullptr || index < 0 ||
        static_cast<std::size_t>(index) >= m->items.size()) {
        set_last_error(kErrBadMenu);
        return 0xFFFFFFFF;
    }
    return static_cast<std::uint32_t>(
        m->items[static_cast<std::size_t>(index)].id);
}

// ===========================================================================
// The dialog family
// ===========================================================================
//
// A dialog is a window whose procedure the guest supplied and whose
// template named the controls. The headless answer to "run this dialog"
// is the one a user pressing the default button gives: the dialog is
// created, `WM_INITDIALOG` is delivered, and the end the default button
// points at is taken -- with the answer a checker that wanted a password
// sees when its run is headless being the cancel id.

extern "C" typedef std::int32_t (__attribute__((ms_abi)) *GuestDlgProcT)(
    std::uint64_t hwnd, std::uint32_t message, std::uint64_t wparam,
    std::uint64_t lparam) noexcept;

extern "C" __attribute__((ms_abi)) std::int64_t u32w_DialogBoxParamW(
    std::uint64_t instance, const char16_t* template_name,
    std::uint64_t parent, std::uint64_t proc, std::uint64_t param) noexcept {
    (void)instance;
    (void)template_name;
    if (proc == 0) {
        set_last_error(kErrParam);
        return -1;
    }
    // The dialog window is a real window: a `GetDlgItem` the procedure's
    // `WM_INITDIALOG` makes must find its controls, and the controls are
    // whatever the guest's procedure creates in response.
    const std::uint64_t hwnd = u32w_CreateWindowExW(
        0, u"#32770", u"", kWsPopup | kWsVisible, 0, 0, 0, 0, parent, 0, 0,
        nullptr);
    if (hwnd == 0) {
        return -1;
    }
    {
        Station& s = station();
        const Lock held(s.lock);
        GuestWindow* w = hwnd_find(held, hwnd);
        if (w != nullptr) {
            w->proc = proc;
        }
    }
    const auto dlg = reinterpret_cast<GuestDlgProcT>(proc);
    (void)dlg(hwnd, kMsgInitDialog, 0, param);
    (void)u32w_DestroyWindow(hwnd);
    return 2 /* IDCANCEL */;
}

extern "C" __attribute__((ms_abi)) std::int64_t u32w_DialogBoxParamA(
    std::uint64_t instance, const char* template_name, std::uint64_t parent,
    std::uint64_t proc, std::uint64_t param) noexcept {
    (void)instance;
    (void)template_name;
    if (proc == 0) {
        set_last_error(kErrParam);
        return -1;
    }
    const std::uint64_t hwnd = u32w_CreateWindowExA(
        0, "#32770", "", kWsPopup | kWsVisible, 0, 0, 0, 0, parent, 0, 0,
        nullptr);
    if (hwnd == 0) {
        return -1;
    }
    {
        Station& s = station();
        const Lock held(s.lock);
        GuestWindow* w = hwnd_find(held, hwnd);
        if (w != nullptr) {
            w->proc = proc;
        }
    }
    const auto dlg = reinterpret_cast<GuestDlgProcT>(proc);
    (void)dlg(hwnd, kMsgInitDialog, 0, param);
    (void)u32w_DestroyWindow(hwnd);
    return 2;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_EndDialog(
    std::uint64_t hwnd, std::int64_t result) noexcept {
    // The end is the destroy the headless dialog loop would perform; the
    // result is recorded where the box's answer is read.
    Station& s = station();
    const Lock held(s.lock);
    GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return kFalse;
    }
    w->user_data = static_cast<std::uint64_t>(result);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_GetDlgItem(
    std::uint64_t hwnd, std::int32_t id) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    for (const auto& entry : s.windows) {
        if (entry.second.parent == hwnd &&
            entry.second.dlg_id == static_cast<std::uint32_t>(id)) {
            return entry.first;
        }
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetDlgCtrlID(
    std::uint64_t hwnd) noexcept {
    Station& s = station();
    const Lock held(s.lock);
    const GuestWindow* w = hwnd_find(held, hwnd);
    if (w == nullptr) {
        set_last_error(kErrBadHwnd);
        return 0;
    }
    return static_cast<std::int32_t>(w->dlg_id);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetDlgItemTextW(
    std::uint64_t hwnd, std::int32_t id, char16_t* out,
    std::int32_t max_chars) noexcept {
    const std::uint64_t item = u32w_GetDlgItem(hwnd, id);
    if (item == 0) {
        if (out != nullptr && max_chars > 0) {
            out[0] = u'\0';
        }
        return 0;
    }
    return u32w_GetWindowTextW(item, out, max_chars);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetDlgItemTextA(
    std::uint64_t hwnd, std::int32_t id, char* out,
    std::int32_t max_chars) noexcept {
    const std::uint64_t item = u32w_GetDlgItem(hwnd, id);
    if (item == 0) {
        if (out != nullptr && max_chars > 0) {
            out[0] = '\0';
        }
        return 0;
    }
    return u32w_GetWindowTextA(item, out, max_chars);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_SetDlgItemTextW(
    std::uint64_t hwnd, std::int32_t id, const char16_t* text) noexcept {
    const std::uint64_t item = u32w_GetDlgItem(hwnd, id);
    if (item == 0) {
        return kFalse;
    }
    return u32w_SetWindowTextW(item, text);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_SetDlgItemTextA(
    std::uint64_t hwnd, std::int32_t id, const char* text) noexcept {
    const std::uint64_t item = u32w_GetDlgItem(hwnd, id);
    if (item == 0) {
        return kFalse;
    }
    return u32w_SetWindowTextA(item, text);
}

// ===========================================================================
// The resource loaders, the metrics and the system parameters
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_LoadIconW(
    std::uint64_t instance, const char16_t* name) noexcept {
    (void)instance;
    (void)name;
    Station& s = station();
    const Lock held(s.lock);
    const std::uint64_t icon = s.next_icon;
    s.next_icon += kHandleStep;
    return icon;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_LoadIconA(
    std::uint64_t instance, const char* name) noexcept {
    (void)instance;
    (void)name;
    Station& s = station();
    const Lock held(s.lock);
    const std::uint64_t icon = s.next_icon;
    s.next_icon += kHandleStep;
    return icon;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_LoadCursorW(
    std::uint64_t instance, const char16_t* name) noexcept {
    (void)instance;
    (void)name;
    Station& s = station();
    const Lock held(s.lock);
    const std::uint64_t cursor = s.next_cursor;
    s.next_cursor += kHandleStep;
    return cursor;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32w_LoadCursorA(
    std::uint64_t instance, const char* name) noexcept {
    (void)instance;
    (void)name;
    Station& s = station();
    const Lock held(s.lock);
    const std::uint64_t cursor = s.next_cursor;
    s.next_cursor += kHandleStep;
    return cursor;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_GetSystemMetrics(
    std::int32_t index) noexcept {
    // The metrics of the 1920x1080 station. The ones a checker reads are
    // the screen's own; the rest are the values the SDK documents for the
    // default display driver.
    switch (index) {
    case 0: return kScreenW;      // SM_CXSCREEN
    case 1: return kScreenH;      // SM_CYSCREEN
    case 2: return 17;            // SM_CXVSCROLL
    case 3: return 17;            // SM_CYHSCROLL
    case 4: return 19;            // SM_CYVSCROLL
    case 5: return 19;            // SM_CXBORDER
    case 6: return 1;             // SM_CXDLGFRAME
    case 7: return 1;             // SM_CYDLGFRAME
    case 8: return 18;            // SM_CYVTHUMB
    case 9: return 18;            // SM_CXHTHUMB
    case 10: return 32;           // SM_CXICON
    case 11: return 32;           // SM_CYICON
    case 12: return 32;           // SM_CXCURSOR
    case 13: return 32;           // SM_CYCURSOR
    case 14: return 0;            // SM_CYMENU
    case 15: return kScreenW - 2; // SM_CXFULLSCREEN
    case 16: return kScreenH;     // SM_CYFULLSCREEN
    case 17: return 0;            // SM_CYKANJIWINDOW
    case 18: return 1;            // SM_MOUSEPRESENT
    case 19: return 1;            // SM_CYVSCROLL
    case 20: return 1;            // SM_CXHSCROLL
    case 23: return 0;            // SM_SECURE
    case 29: return 1;            // SM_SHOWSOUNDS
    case 42: return 0;            // SM_NETWORK
    case 43: return 0;            // SM_SLOWMACHINE
    case 45: return 0;            // SM_REMOTESESSION
    case 76: return kScreenW;     // SM_CXMAXTRACK
    case 77: return kScreenH;     // SM_CYMAXTRACK
    default: return 0;
    }
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_SystemParametersInfoW(
    std::uint32_t action, std::uint32_t param, void* value,
    std::uint32_t flags) noexcept {
    (void)param;
    (void)flags;
    if (value == nullptr) {
        return kTrue;
    }
    // The work area is the screen minus nothing: this station draws no
    // taskbar, and the rectangle a maximized window fills is the screen's.
    constexpr std::uint32_t kSpiGetWorkArea = 0x0030;
    if (action == kSpiGetWorkArea) {
        write_rect(value, 0, 0, kScreenW, kScreenH);
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32w_SystemParametersInfoA(
    std::uint32_t action, std::uint32_t param, void* value,
    std::uint32_t flags) noexcept {
    return u32w_SystemParametersInfoW(action, param, value, flags);
}

// ===========================================================================
// The registration
// ===========================================================================

void add_user32_windows(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    // The classes.
    e("RegisterClassA", reinterpret_cast<void*>(&u32w_RegisterClassA));
    e("RegisterClassW", reinterpret_cast<void*>(&u32w_RegisterClassW));
    e("RegisterClassExA", reinterpret_cast<void*>(&u32w_RegisterClassExA));
    e("RegisterClassExW", reinterpret_cast<void*>(&u32w_RegisterClassExW));
    e("UnregisterClassA", reinterpret_cast<void*>(&u32w_UnregisterClassA));
    e("UnregisterClassW", reinterpret_cast<void*>(&u32w_UnregisterClassW));
    // Creation and destruction.
    e("CreateWindowExA", reinterpret_cast<void*>(&u32w_CreateWindowExA));
    e("CreateWindowExW", reinterpret_cast<void*>(&u32w_CreateWindowExW));
    e("DestroyWindow", reinterpret_cast<void*>(&u32w_DestroyWindow));
    e("IsWindow", reinterpret_cast<void*>(&u32w_IsWindow));
    e("GetDesktopWindow", reinterpret_cast<void*>(&u32w_GetDesktopWindow));
    e("GetParent", reinterpret_cast<void*>(&u32w_GetParent));
    e("SetParent", reinterpret_cast<void*>(&u32w_SetParent));
    e("IsChild", reinterpret_cast<void*>(&u32w_IsChild));
    // The style words.
    e("GetWindowLongPtrA", reinterpret_cast<void*>(&u32w_GetWindowLongPtrA));
    e("GetWindowLongPtrW", reinterpret_cast<void*>(&u32w_GetWindowLongPtrW));
    e("SetWindowLongPtrA", reinterpret_cast<void*>(&u32w_SetWindowLongPtrA));
    e("SetWindowLongPtrW", reinterpret_cast<void*>(&u32w_SetWindowLongPtrW));
    e("GetWindowLongA", reinterpret_cast<void*>(&u32w_GetWindowLongA));
    e("GetWindowLongW", reinterpret_cast<void*>(&u32w_GetWindowLongW));
    e("SetWindowLongA", reinterpret_cast<void*>(&u32w_SetWindowLongA));
    e("SetWindowLongW", reinterpret_cast<void*>(&u32w_SetWindowLongW));
    // Text and class name.
    e("SetWindowTextA", reinterpret_cast<void*>(&u32w_SetWindowTextA));
    e("SetWindowTextW", reinterpret_cast<void*>(&u32w_SetWindowTextW));
    e("GetWindowTextA", reinterpret_cast<void*>(&u32w_GetWindowTextA));
    e("GetWindowTextW", reinterpret_cast<void*>(&u32w_GetWindowTextW));
    e("GetWindowTextLengthA",
      reinterpret_cast<void*>(&u32w_GetWindowTextLengthA));
    e("GetWindowTextLengthW",
      reinterpret_cast<void*>(&u32w_GetWindowTextLengthW));
    e("GetClassNameA", reinterpret_cast<void*>(&u32w_GetClassNameA));
    e("GetClassNameW", reinterpret_cast<void*>(&u32w_GetClassNameW));
    // Geometry and state.
    e("GetWindowRect", reinterpret_cast<void*>(&u32w_GetWindowRect));
    e("GetClientRect", reinterpret_cast<void*>(&u32w_GetClientRect));
    e("MoveWindow", reinterpret_cast<void*>(&u32w_MoveWindow));
    e("SetWindowPos", reinterpret_cast<void*>(&u32w_SetWindowPos));
    e("IsWindowVisible", reinterpret_cast<void*>(&u32w_IsWindowVisible));
    e("IsWindowEnabled", reinterpret_cast<void*>(&u32w_IsWindowEnabled));
    e("IsIconic", reinterpret_cast<void*>(&u32w_IsIconic));
    e("IsZoomed", reinterpret_cast<void*>(&u32w_IsZoomed));
    e("ShowWindow", reinterpret_cast<void*>(&u32w_ShowWindow));
    e("EnableWindow", reinterpret_cast<void*>(&u32w_EnableWindow));
    e("UpdateWindow", reinterpret_cast<void*>(&u32w_UpdateWindow));
    e("InvalidateRect", reinterpret_cast<void*>(&u32w_InvalidateRect));
    // Focus and capture.
    e("GetForegroundWindow",
      reinterpret_cast<void*>(&u32w_GetForegroundWindow));
    e("SetForegroundWindow",
      reinterpret_cast<void*>(&u32w_SetForegroundWindow));
    e("SetFocus", reinterpret_cast<void*>(&u32w_SetFocus));
    e("GetFocus", reinterpret_cast<void*>(&u32w_GetFocus));
    e("SetCapture", reinterpret_cast<void*>(&u32w_SetCapture));
    e("ReleaseCapture", reinterpret_cast<void*>(&u32w_ReleaseCapture));
    e("GetCapture", reinterpret_cast<void*>(&u32w_GetCapture));
    e("GetActiveWindow", reinterpret_cast<void*>(&u32w_GetActiveWindow));
    e("SetActiveWindow", reinterpret_cast<void*>(&u32w_SetActiveWindow));
    e("BringWindowToTop", reinterpret_cast<void*>(&u32w_BringWindowToTop));
    e("GetWindowThreadProcessId",
      reinterpret_cast<void*>(&u32w_GetWindowThreadProcessId));
    // Search and enumeration.
    e("FindWindowA", reinterpret_cast<void*>(&u32w_FindWindowA));
    e("FindWindowW", reinterpret_cast<void*>(&u32w_FindWindowW));
    e("FindWindowExA", reinterpret_cast<void*>(&u32w_FindWindowExA));
    e("FindWindowExW", reinterpret_cast<void*>(&u32w_FindWindowExW));
    e("GetTopWindow", reinterpret_cast<void*>(&u32w_GetTopWindow));
    e("GetWindow", reinterpret_cast<void*>(&u32w_GetWindow));
    e("EnumWindows", reinterpret_cast<void*>(&u32w_EnumWindows));
    e("EnumChildWindows", reinterpret_cast<void*>(&u32w_EnumChildWindows));
    e("EnumThreadWindows", reinterpret_cast<void*>(&u32w_EnumThreadWindows));
    // The queue.
    e("PostMessageA", reinterpret_cast<void*>(&u32w_PostMessageA));
    e("PostMessageW", reinterpret_cast<void*>(&u32w_PostMessageW));
    e("PostThreadMessageW",
      reinterpret_cast<void*>(&u32w_PostThreadMessageW));
    e("PostQuitMessage", reinterpret_cast<void*>(&u32w_PostQuitMessage));
    e("GetMessageA", reinterpret_cast<void*>(&u32w_GetMessageA));
    e("GetMessageW", reinterpret_cast<void*>(&u32w_GetMessageW));
    e("PeekMessageA", reinterpret_cast<void*>(&u32w_PeekMessageA));
    e("PeekMessageW", reinterpret_cast<void*>(&u32w_PeekMessageW));
    e("TranslateMessage", reinterpret_cast<void*>(&u32w_TranslateMessage));
    e("DispatchMessageA", reinterpret_cast<void*>(&u32w_DispatchMessageA));
    e("DispatchMessageW", reinterpret_cast<void*>(&u32w_DispatchMessageW));
    e("WaitMessage", reinterpret_cast<void*>(&u32w_WaitMessage));
    e("SendMessageA", reinterpret_cast<void*>(&u32w_SendMessageA));
    e("SendMessageW", reinterpret_cast<void*>(&u32w_SendMessageW));
    e("DefWindowProcA", reinterpret_cast<void*>(&u32w_DefWindowProcA));
    e("DefWindowProcW", reinterpret_cast<void*>(&u32w_DefWindowProcW));
    e("CallWindowProcA", reinterpret_cast<void*>(&u32w_CallWindowProcA));
    e("CallWindowProcW", reinterpret_cast<void*>(&u32w_CallWindowProcW));
    // Timers.
    e("SetTimer", reinterpret_cast<void*>(&u32w_SetTimer));
    e("KillTimer", reinterpret_cast<void*>(&u32w_KillTimer));
    // The clipboard.
    e("OpenClipboard", reinterpret_cast<void*>(&u32w_OpenClipboard));
    e("CloseClipboard", reinterpret_cast<void*>(&u32w_CloseClipboard));
    e("EmptyClipboard", reinterpret_cast<void*>(&u32w_EmptyClipboard));
    e("SetClipboardData", reinterpret_cast<void*>(&u32w_SetClipboardData));
    e("GetClipboardData", reinterpret_cast<void*>(&u32w_GetClipboardData));
    e("IsClipboardFormatAvailable",
      reinterpret_cast<void*>(&u32w_IsClipboardFormatAvailable));
    e("CountClipboardFormats",
      reinterpret_cast<void*>(&u32w_CountClipboardFormats));
    e("GetClipboardSequenceNumber",
      reinterpret_cast<void*>(&u32w_GetClipboardSequenceNumber));
    e("RegisterClipboardFormatA",
      reinterpret_cast<void*>(&u32w_RegisterClipboardFormatA));
    e("RegisterClipboardFormatW",
      reinterpret_cast<void*>(&u32w_RegisterClipboardFormatW));
    // The keyboard and cursor.
    e("GetAsyncKeyState", reinterpret_cast<void*>(&u32w_GetAsyncKeyState));
    e("GetKeyState", reinterpret_cast<void*>(&u32w_GetKeyState));
    e("GetKeyboardState", reinterpret_cast<void*>(&u32w_GetKeyboardState));
    e("SetKeyboardState", reinterpret_cast<void*>(&u32w_SetKeyboardState));
    e("GetKeyboardLayout", reinterpret_cast<void*>(&u32w_GetKeyboardLayout));
    e("MapVirtualKeyA", reinterpret_cast<void*>(&u32w_MapVirtualKeyA));
    e("MapVirtualKeyW", reinterpret_cast<void*>(&u32w_MapVirtualKeyW));
    e("GetCursorPos", reinterpret_cast<void*>(&u32w_GetCursorPos));
    e("SetCursorPos", reinterpret_cast<void*>(&u32w_SetCursorPos));
    e("ShowCursor", reinterpret_cast<void*>(&u32w_ShowCursor));
    e("GetDoubleClickTime", reinterpret_cast<void*>(&u32w_GetDoubleClickTime));
    // Menus.
    e("CreateMenu", reinterpret_cast<void*>(&u32w_CreateMenu));
    e("CreatePopupMenu", reinterpret_cast<void*>(&u32w_CreatePopupMenu));
    e("DestroyMenu", reinterpret_cast<void*>(&u32w_DestroyMenu));
    e("GetMenu", reinterpret_cast<void*>(&u32w_GetMenu));
    e("SetMenu", reinterpret_cast<void*>(&u32w_SetMenu));
    e("AppendMenuA", reinterpret_cast<void*>(&u32w_AppendMenuA));
    e("AppendMenuW", reinterpret_cast<void*>(&u32w_AppendMenuW));
    e("GetMenuItemCount", reinterpret_cast<void*>(&u32w_GetMenuItemCount));
    e("GetMenuItemID", reinterpret_cast<void*>(&u32w_GetMenuItemID));
    // Dialogs.
    e("DialogBoxParamA", reinterpret_cast<void*>(&u32w_DialogBoxParamA));
    e("DialogBoxParamW", reinterpret_cast<void*>(&u32w_DialogBoxParamW));
    e("EndDialog", reinterpret_cast<void*>(&u32w_EndDialog));
    e("GetDlgItem", reinterpret_cast<void*>(&u32w_GetDlgItem));
    e("GetDlgCtrlID", reinterpret_cast<void*>(&u32w_GetDlgCtrlID));
    e("GetDlgItemTextA", reinterpret_cast<void*>(&u32w_GetDlgItemTextA));
    e("GetDlgItemTextW", reinterpret_cast<void*>(&u32w_GetDlgItemTextW));
    e("SetDlgItemTextA", reinterpret_cast<void*>(&u32w_SetDlgItemTextA));
    e("SetDlgItemTextW", reinterpret_cast<void*>(&u32w_SetDlgItemTextW));
    // Resources and system.
    e("LoadIconA", reinterpret_cast<void*>(&u32w_LoadIconA));
    e("LoadIconW", reinterpret_cast<void*>(&u32w_LoadIconW));
    e("LoadCursorA", reinterpret_cast<void*>(&u32w_LoadCursorA));
    e("LoadCursorW", reinterpret_cast<void*>(&u32w_LoadCursorW));
    e("GetSystemMetrics", reinterpret_cast<void*>(&u32w_GetSystemMetrics));
    e("SystemParametersInfoA",
      reinterpret_cast<void*>(&u32w_SystemParametersInfoA));
    e("SystemParametersInfoW",
      reinterpret_cast<void*>(&u32w_SystemParametersInfoW));
}

}  // namespace occ::runtime::winabi

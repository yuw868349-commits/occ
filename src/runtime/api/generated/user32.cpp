// The USER32 surface this runtime did not answer.
//
// One function per export, in the shape every other domain here has: an
// `ms_abi` entry point and a registration function. Every signature below
// is the platform's own, read from the mingw headers by preprocessor, so
// that the argument count and the return type are the ones the guest's
// compiler will call with. A signature guessed here would not be a subtle
// defect: it would be a call whose arguments are read out of the wrong
// registers.
//
// Each entry point states which of two things it is:
//
//   * an implementation, where the behaviour is defined by a format, a
//     structure layout or an arithmetic rule and needs no capability this
//     machine lacks;
//   * a refusal, where the subsystem the call belongs to is not in this
//     runtime -- a window manager, a service database, a device tree. The
//     refusal is `ERROR_CALL_NOT_IMPLEMENTED` through `SetLastError`, which
//     is the answer Windows gives for an entry point whose subsystem is not
//     present, and the comment names the subsystem.
//
// What none of them does is answer success for work that did not happen. A
// guest holding a handle it was never given, or a buffer whose "length" was
// never measured, is in a worse state than one that was told the call is
// unavailable: the first failure lands somewhere else entirely, in code
// that has no reason to suspect what went wrong.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace occ::runtime::winabi {
namespace {

// The code a refusal reports. It is the platform's own -- an entry point
// whose subsystem is absent -- and a guest that handles it is not being
// lied to.
constexpr std::uint32_t kNotImplemented = 120;

extern "C" __attribute__((ms_abi)) void* kuser32G_ActivateKeyboardLayout(void* hkl, std::uint32_t Flags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hkl);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_AdjustWindowRect(void* lpRect, std::uint32_t dwStyle, std::int32_t bMenu) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(lpRect);
    static_cast<void>(dwStyle);
    static_cast<void>(bMenu);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_AdjustWindowRectEx(void* lpRect, std::uint32_t dwStyle, std::int32_t bMenu, std::uint32_t dwExStyle) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(lpRect);
    static_cast<void>(dwStyle);
    static_cast<void>(bMenu);
    static_cast<void>(dwExStyle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_AllowSetForegroundWindow(std::uint32_t dwProcessId) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(dwProcessId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_AnimateWindow(void* hWnd, std::uint32_t dwTime, std::uint32_t dwFlags) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    static_cast<void>(dwTime);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_AnyPopup() noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_ArrangeIconicWindows(void* hWnd) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_AttachThreadInput(std::uint32_t idAttach, std::uint32_t idAttachTo, std::int32_t fAttach) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(idAttach);
    static_cast<void>(idAttachTo);
    static_cast<void>(fAttach);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_BeginDeferWindowPos(std::int32_t nNumWindows) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(nNumWindows);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_BeginPaint(void* hWnd, void* lpPaint) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(lpPaint);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_BlockInput(std::int32_t fBlockIt) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(fBlockIt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_BroadcastSystemMessageA(std::uint32_t flags, std::uint32_t* lpInfo, std::uint32_t Msg, std::uint64_t wParam, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(flags);
    static_cast<void>(lpInfo);
    static_cast<void>(Msg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_BroadcastSystemMessageExA(std::uint32_t flags, std::uint32_t* lpInfo, std::uint32_t Msg, std::uint64_t wParam, std::int64_t lParam, std::uint64_t pbsmInfo) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(flags);
    static_cast<void>(lpInfo);
    static_cast<void>(Msg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    static_cast<void>(pbsmInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_BroadcastSystemMessageExW(std::uint32_t flags, std::uint32_t* lpInfo, std::uint32_t Msg, std::uint64_t wParam, std::int64_t lParam, std::uint64_t pbsmInfo) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(flags);
    static_cast<void>(lpInfo);
    static_cast<void>(Msg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    static_cast<void>(pbsmInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_BroadcastSystemMessageW(std::uint32_t flags, std::uint32_t* lpInfo, std::uint32_t Msg, std::uint64_t wParam, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(flags);
    static_cast<void>(lpInfo);
    static_cast<void>(Msg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_CalculatePopupWindowPosition(const std::uint64_t* anchorPoint, const void* windowSize, std::uint32_t flags, void* excludeRect, void* popupWindowPosition) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(anchorPoint);
    static_cast<void>(windowSize);
    static_cast<void>(flags);
    static_cast<void>(excludeRect);
    static_cast<void>(popupWindowPosition);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_CallMsgFilterA(void* lpMsg, std::int32_t nCode) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(lpMsg);
    static_cast<void>(nCode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_CallMsgFilterW(void* lpMsg, std::int32_t nCode) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(lpMsg);
    static_cast<void>(nCode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_CallNextHookEx(void* hhk, std::int32_t nCode, std::uint64_t wParam, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hhk);
    static_cast<void>(nCode);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_CancelShutdown() noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kuser32G_CascadeWindows(void* hwndParent, std::uint32_t wHow, const void* lpRect, std::uint32_t cKids, const void* lpKids) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hwndParent);
    static_cast<void>(wHow);
    static_cast<void>(lpRect);
    static_cast<void>(cKids);
    static_cast<void>(lpKids);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ChangeClipboardChain(void* hWndRemove, void* hWndNewNext) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWndRemove);
    static_cast<void>(hWndNewNext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ChangeMenuA(void* hMenu, std::uint32_t cmd, const char* lpszNewItem, std::uint32_t cmdInsert, std::uint32_t flags) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMenu);
    static_cast<void>(cmd);
    static_cast<void>(lpszNewItem);
    static_cast<void>(cmdInsert);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ChangeMenuW(void* hMenu, std::uint32_t cmd, const char16_t* lpszNewItem, std::uint32_t cmdInsert, std::uint32_t flags) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMenu);
    static_cast<void>(cmd);
    static_cast<void>(lpszNewItem);
    static_cast<void>(cmdInsert);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_CharLowerBuffA(char* lpsz, std::uint32_t cchLength) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(lpsz);
    static_cast<void>(cchLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_CharLowerBuffW(char16_t* lpsz, std::uint32_t cchLength) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(lpsz);
    static_cast<void>(cchLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) char* kuser32G_CharNextA(const char* lpsz) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(lpsz);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char* kuser32G_CharNextExA(std::uint16_t CodePage, const char* lpCurrentChar, std::uint32_t dwFlags) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(CodePage);
    static_cast<void>(lpCurrentChar);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char16_t* kuser32G_CharNextW(const char16_t* lpsz) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(lpsz);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char* kuser32G_CharPrevA(const char* lpszStart, const char* lpszCurrent) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(lpszStart);
    static_cast<void>(lpszCurrent);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char* kuser32G_CharPrevExA(std::uint16_t CodePage, const char* lpStart, const char* lpCurrentChar, std::uint32_t dwFlags) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(CodePage);
    static_cast<void>(lpStart);
    static_cast<void>(lpCurrentChar);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char16_t* kuser32G_CharPrevW(const char16_t* lpszStart, const char16_t* lpszCurrent) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(lpszStart);
    static_cast<void>(lpszCurrent);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_CharToOemBuffA(const char* lpszSrc, char* lpszDst, std::uint32_t cchDstLength) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(lpszSrc);
    static_cast<void>(lpszDst);
    static_cast<void>(cchDstLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_CharToOemBuffW(const char16_t* lpszSrc, char* lpszDst, std::uint32_t cchDstLength) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(lpszSrc);
    static_cast<void>(lpszDst);
    static_cast<void>(cchDstLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_CharUpperBuffA(char* lpsz, std::uint32_t cchLength) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(lpsz);
    static_cast<void>(cchLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_CharUpperBuffW(char16_t* lpsz, std::uint32_t cchLength) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(lpsz);
    static_cast<void>(cchLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_CheckDlgButton(void* hDlg, std::int32_t nIDButton, std::uint32_t uCheck) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(nIDButton);
    static_cast<void>(uCheck);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_CheckMenuItem(void* hMenu, std::uint32_t uIDCheckItem, std::uint32_t uCheck) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMenu);
    static_cast<void>(uIDCheckItem);
    static_cast<void>(uCheck);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_CheckMenuRadioItem(void* hmenu, std::uint32_t first, std::uint32_t last, std::uint32_t check, std::uint32_t flags) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hmenu);
    static_cast<void>(first);
    static_cast<void>(last);
    static_cast<void>(check);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_CheckRadioButton(void* hDlg, std::int32_t nIDFirstButton, std::int32_t nIDLastButton, std::int32_t nIDCheckButton) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hDlg);
    static_cast<void>(nIDFirstButton);
    static_cast<void>(nIDLastButton);
    static_cast<void>(nIDCheckButton);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_ChildWindowFromPoint(void* hWndParent, std::uint64_t Point) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWndParent);
    static_cast<void>(Point);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_ChildWindowFromPointEx(void* hwnd, std::uint64_t pt, std::uint32_t flags) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hwnd);
    static_cast<void>(pt);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ClientToScreen(void* hWnd, void* lpPoint) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(lpPoint);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ClipCursor(const void* lpRect) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(lpRect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_CloseDesktop(std::uint64_t hDesktop) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hDesktop);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_CloseWindow(void* hWnd) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_CloseWindowStation(std::uint64_t hWinSta) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWinSta);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_CopyAcceleratorTableA(void* hAccelSrc, void* lpAccelDst, std::int32_t cAccelEntries) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hAccelSrc);
    static_cast<void>(lpAccelDst);
    static_cast<void>(cAccelEntries);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_CopyAcceleratorTableW(void* hAccelSrc, void* lpAccelDst, std::int32_t cAccelEntries) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hAccelSrc);
    static_cast<void>(lpAccelDst);
    static_cast<void>(cAccelEntries);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_CopyIcon(void* hIcon) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hIcon);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_CopyImage(void* h, std::uint32_t type, std::int32_t cx, std::int32_t cy, std::uint32_t flags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(h);
    static_cast<void>(type);
    static_cast<void>(cx);
    static_cast<void>(cy);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_CopyRect(void* lprcDst, const void* lprcSrc) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(lprcDst);
    static_cast<void>(lprcSrc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_CreateAcceleratorTableA(void* paccel, std::int32_t cAccel) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(paccel);
    static_cast<void>(cAccel);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_CreateAcceleratorTableW(void* paccel, std::int32_t cAccel) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(paccel);
    static_cast<void>(cAccel);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_CreateCaret(void* hWnd, void* hBitmap, std::int32_t nWidth, std::int32_t nHeight) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(hBitmap);
    static_cast<void>(nWidth);
    static_cast<void>(nHeight);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_CreateCursor(void* hInst, std::int32_t xHotSpot, std::int32_t yHotSpot, std::int32_t nWidth, std::int32_t nHeight, const void* pvANDPlane, const void* pvXORPlane) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hInst);
    static_cast<void>(xHotSpot);
    static_cast<void>(yHotSpot);
    static_cast<void>(nWidth);
    static_cast<void>(nHeight);
    static_cast<void>(pvANDPlane);
    static_cast<void>(pvXORPlane);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_CreateDialogIndirectParamA(void* hInstance, std::uint64_t lpTemplate, void* hWndParent, void* lpDialogFunc, std::int64_t dwInitParam) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hInstance);
    static_cast<void>(lpTemplate);
    static_cast<void>(hWndParent);
    static_cast<void>(lpDialogFunc);
    static_cast<void>(dwInitParam);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_CreateDialogIndirectParamW(void* hInstance, std::uint64_t lpTemplate, void* hWndParent, void* lpDialogFunc, std::int64_t dwInitParam) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hInstance);
    static_cast<void>(lpTemplate);
    static_cast<void>(hWndParent);
    static_cast<void>(lpDialogFunc);
    static_cast<void>(dwInitParam);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_CreateDialogParamA(void* hInstance, const char* lpTemplateName, void* hWndParent, void* lpDialogFunc, std::int64_t dwInitParam) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hInstance);
    static_cast<void>(lpTemplateName);
    static_cast<void>(hWndParent);
    static_cast<void>(lpDialogFunc);
    static_cast<void>(dwInitParam);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_CreateDialogParamW(void* hInstance, const char16_t* lpTemplateName, void* hWndParent, void* lpDialogFunc, std::int64_t dwInitParam) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hInstance);
    static_cast<void>(lpTemplateName);
    static_cast<void>(hWndParent);
    static_cast<void>(lpDialogFunc);
    static_cast<void>(dwInitParam);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_CreateIcon(void* hInstance, std::int32_t nWidth, std::int32_t nHeight, std::uint8_t cPlanes, std::uint8_t cBitsPixel, const std::uint8_t* lpbANDbits, const std::uint8_t* lpbXORbits) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hInstance);
    static_cast<void>(nWidth);
    static_cast<void>(nHeight);
    static_cast<void>(cPlanes);
    static_cast<void>(cBitsPixel);
    static_cast<void>(lpbANDbits);
    static_cast<void>(lpbXORbits);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_CreateIconFromResource(std::uint8_t* presbits, std::uint32_t dwResSize, std::int32_t fIcon, std::uint32_t dwVer) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(presbits);
    static_cast<void>(dwResSize);
    static_cast<void>(fIcon);
    static_cast<void>(dwVer);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_CreateIconFromResourceEx(std::uint8_t* presbits, std::uint32_t dwResSize, std::int32_t fIcon, std::uint32_t dwVer, std::int32_t cxDesired, std::int32_t cyDesired, std::uint32_t Flags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(presbits);
    static_cast<void>(dwResSize);
    static_cast<void>(fIcon);
    static_cast<void>(dwVer);
    static_cast<void>(cxDesired);
    static_cast<void>(cyDesired);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_CreateIconIndirect(void* piconinfo) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(piconinfo);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_CreateMDIWindowA(const char* lpClassName, const char* lpWindowName, std::uint32_t dwStyle, std::int32_t X, std::int32_t Y, std::int32_t nWidth, std::int32_t nHeight, void* hWndParent, void* hInstance, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(lpClassName);
    static_cast<void>(lpWindowName);
    static_cast<void>(dwStyle);
    static_cast<void>(X);
    static_cast<void>(Y);
    static_cast<void>(nWidth);
    static_cast<void>(nHeight);
    static_cast<void>(hWndParent);
    static_cast<void>(hInstance);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_CreateMDIWindowW(const char16_t* lpClassName, const char16_t* lpWindowName, std::uint32_t dwStyle, std::int32_t X, std::int32_t Y, std::int32_t nWidth, std::int32_t nHeight, void* hWndParent, void* hInstance, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(lpClassName);
    static_cast<void>(lpWindowName);
    static_cast<void>(dwStyle);
    static_cast<void>(X);
    static_cast<void>(Y);
    static_cast<void>(nWidth);
    static_cast<void>(nHeight);
    static_cast<void>(hWndParent);
    static_cast<void>(hInstance);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuser32G_CreateWindowStationA(const char* lpwinsta, std::uint32_t dwFlags, std::uint32_t dwDesiredAccess, void* lpsa) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(lpwinsta);
    static_cast<void>(dwFlags);
    static_cast<void>(dwDesiredAccess);
    static_cast<void>(lpsa);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuser32G_CreateWindowStationW(const char16_t* lpwinsta, std::uint32_t dwFlags, std::uint32_t dwDesiredAccess, void* lpsa) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(lpwinsta);
    static_cast<void>(dwFlags);
    static_cast<void>(dwDesiredAccess);
    static_cast<void>(lpsa);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DdeSetQualityOfService(void* hwndClient, const void* pqosNew, std::uint64_t pqosPrev) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hwndClient);
    static_cast<void>(pqosNew);
    static_cast<void>(pqosPrev);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_DefDlgProcA(void* hDlg, std::uint32_t Msg, std::uint64_t wParam, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(Msg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_DefDlgProcW(void* hDlg, std::uint32_t Msg, std::uint64_t wParam, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(Msg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_DefFrameProcA(void* hWnd, void* hWndMDIClient, std::uint32_t uMsg, std::uint64_t wParam, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(hWndMDIClient);
    static_cast<void>(uMsg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_DefFrameProcW(void* hWnd, void* hWndMDIClient, std::uint32_t uMsg, std::uint64_t wParam, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(hWndMDIClient);
    static_cast<void>(uMsg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_DefMDIChildProcA(void* hWnd, std::uint32_t uMsg, std::uint64_t wParam, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(uMsg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_DefMDIChildProcW(void* hWnd, std::uint32_t uMsg, std::uint64_t wParam, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(uMsg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_DefRawInputProc(void* paRawInput, std::int32_t nInput, std::uint32_t cbSizeHeader) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(paRawInput);
    static_cast<void>(nInput);
    static_cast<void>(cbSizeHeader);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_DeferWindowPos(void* hWinPosInfo, void* hWnd, void* hWndInsertAfter, std::int32_t x, std::int32_t y, std::int32_t cx, std::int32_t cy, std::uint32_t uFlags) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWinPosInfo);
    static_cast<void>(hWnd);
    static_cast<void>(hWndInsertAfter);
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(cx);
    static_cast<void>(cy);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DeleteMenu(void* hMenu, std::uint32_t uPosition, std::uint32_t uFlags) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMenu);
    static_cast<void>(uPosition);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DeregisterShellHookWindow(void* hwnd) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hwnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DestroyAcceleratorTable(void* hAccel) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hAccel);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DestroyCaret() noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DestroyCursor(void* hCursor) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hCursor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DestroyIcon(void* hIcon) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hIcon);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_DialogBoxIndirectParamA(void* hInstance, std::uint64_t hDialogTemplate, void* hWndParent, void* lpDialogFunc, std::int64_t dwInitParam) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hInstance);
    static_cast<void>(hDialogTemplate);
    static_cast<void>(hWndParent);
    static_cast<void>(lpDialogFunc);
    static_cast<void>(dwInitParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_DialogBoxIndirectParamW(void* hInstance, std::uint64_t hDialogTemplate, void* hWndParent, void* lpDialogFunc, std::int64_t dwInitParam) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hInstance);
    static_cast<void>(hDialogTemplate);
    static_cast<void>(hWndParent);
    static_cast<void>(lpDialogFunc);
    static_cast<void>(dwInitParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kuser32G_DisableProcessWindowsGhosting() noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DlgDirListA(void* hDlg, char* lpPathSpec, std::int32_t nIDListBox, std::int32_t nIDStaticPath, std::uint32_t uFileType) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(lpPathSpec);
    static_cast<void>(nIDListBox);
    static_cast<void>(nIDStaticPath);
    static_cast<void>(uFileType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DlgDirListComboBoxA(void* hDlg, char* lpPathSpec, std::int32_t nIDComboBox, std::int32_t nIDStaticPath, std::uint32_t uFiletype) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(lpPathSpec);
    static_cast<void>(nIDComboBox);
    static_cast<void>(nIDStaticPath);
    static_cast<void>(uFiletype);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DlgDirListComboBoxW(void* hDlg, char16_t* lpPathSpec, std::int32_t nIDComboBox, std::int32_t nIDStaticPath, std::uint32_t uFiletype) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(lpPathSpec);
    static_cast<void>(nIDComboBox);
    static_cast<void>(nIDStaticPath);
    static_cast<void>(uFiletype);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DlgDirListW(void* hDlg, char16_t* lpPathSpec, std::int32_t nIDListBox, std::int32_t nIDStaticPath, std::uint32_t uFileType) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(lpPathSpec);
    static_cast<void>(nIDListBox);
    static_cast<void>(nIDStaticPath);
    static_cast<void>(uFileType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DlgDirSelectComboBoxExA(void* hwndDlg, char* lpString, std::int32_t cchOut, std::int32_t idComboBox) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hwndDlg);
    static_cast<void>(lpString);
    static_cast<void>(cchOut);
    static_cast<void>(idComboBox);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DlgDirSelectComboBoxExW(void* hwndDlg, char16_t* lpString, std::int32_t cchOut, std::int32_t idComboBox) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hwndDlg);
    static_cast<void>(lpString);
    static_cast<void>(cchOut);
    static_cast<void>(idComboBox);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DlgDirSelectExA(void* hwndDlg, char* lpString, std::int32_t chCount, std::int32_t idListBox) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hwndDlg);
    static_cast<void>(lpString);
    static_cast<void>(chCount);
    static_cast<void>(idListBox);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DlgDirSelectExW(void* hwndDlg, char16_t* lpString, std::int32_t chCount, std::int32_t idListBox) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hwndDlg);
    static_cast<void>(lpString);
    static_cast<void>(chCount);
    static_cast<void>(idListBox);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DragDetect(void* hwnd, std::uint64_t pt) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwnd);
    static_cast<void>(pt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_DragObject(void* hwndParent, void* hwndFrom, std::uint32_t fmt, std::uint64_t data, void* hcur) noexcept {
    // Refused: the shell namespace.
    //
    // the shell namespace is a tree of folders each of which is a COM object,
    // and there is no shell here for one to belong to
    static_cast<void>(hwndParent);
    static_cast<void>(hwndFrom);
    static_cast<void>(fmt);
    static_cast<void>(data);
    static_cast<void>(hcur);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DrawAnimatedRects(void* hwnd, std::int32_t idAni, const void* lprcFrom, const void* lprcTo) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hwnd);
    static_cast<void>(idAni);
    static_cast<void>(lprcFrom);
    static_cast<void>(lprcTo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DrawCaption(void* hwnd, void* hdc, const void* lprect, std::uint32_t flags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hwnd);
    static_cast<void>(hdc);
    static_cast<void>(lprect);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DrawEdge(void* hdc, void* qrc, std::uint32_t edge, std::uint32_t grfFlags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hdc);
    static_cast<void>(qrc);
    static_cast<void>(edge);
    static_cast<void>(grfFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DrawFocusRect(void* hDC, const void* lprc) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hDC);
    static_cast<void>(lprc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DrawFrameControl(void* arg0, void* arg1, std::uint32_t arg2, std::uint32_t arg3) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DrawIcon(void* hDC, std::int32_t X, std::int32_t Y, void* hIcon) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hDC);
    static_cast<void>(X);
    static_cast<void>(Y);
    static_cast<void>(hIcon);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DrawIconEx(void* hdc, std::int32_t xLeft, std::int32_t yTop, void* hIcon, std::int32_t cxWidth, std::int32_t cyWidth, std::uint32_t istepIfAniCur, void* hbrFlickerFreeDraw, std::uint32_t diFlags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hdc);
    static_cast<void>(xLeft);
    static_cast<void>(yTop);
    static_cast<void>(hIcon);
    static_cast<void>(cxWidth);
    static_cast<void>(cyWidth);
    static_cast<void>(istepIfAniCur);
    static_cast<void>(hbrFlickerFreeDraw);
    static_cast<void>(diFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DrawMenuBar(void* hWnd) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hWnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DrawStateA(void* hdc, void* hbrFore, std::uint64_t qfnCallBack, std::int64_t lData, std::uint64_t wData, std::int32_t x, std::int32_t y, std::int32_t cx, std::int32_t cy, std::uint32_t uFlags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hdc);
    static_cast<void>(hbrFore);
    static_cast<void>(qfnCallBack);
    static_cast<void>(lData);
    static_cast<void>(wData);
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(cx);
    static_cast<void>(cy);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_DrawStateW(void* hdc, void* hbrFore, std::uint64_t qfnCallBack, std::int64_t lData, std::uint64_t wData, std::int32_t x, std::int32_t y, std::int32_t cx, std::int32_t cy, std::uint32_t uFlags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hdc);
    static_cast<void>(hbrFore);
    static_cast<void>(qfnCallBack);
    static_cast<void>(lData);
    static_cast<void>(wData);
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(cx);
    static_cast<void>(cy);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_EnableMenuItem(void* hMenu, std::uint32_t uIDEnableItem, std::uint32_t uEnable) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMenu);
    static_cast<void>(uIDEnableItem);
    static_cast<void>(uEnable);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_EnableScrollBar(void* hWnd, std::uint32_t wSBflags, std::uint32_t wArrows) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(wSBflags);
    static_cast<void>(wArrows);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_EndDeferWindowPos(void* hWinPosInfo) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWinPosInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_EndMenu() noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_EndPaint(void* hWnd, const void* lpPaint) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(lpPaint);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_EndTask(void* hWnd, std::int32_t fShutDown, std::int32_t fForce) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(fShutDown);
    static_cast<void>(fForce);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_EnumClipboardFormats(std::uint32_t format) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(format);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_EnumDesktopWindows(std::uint64_t hDesktop, void* lpfn, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hDesktop);
    static_cast<void>(lpfn);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_EnumDesktopsA(std::uint64_t hwinsta, std::uint64_t lpEnumFunc, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hwinsta);
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_EnumDesktopsW(std::uint64_t hwinsta, std::uint64_t lpEnumFunc, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hwinsta);
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_EnumDisplayMonitors(void* hdc, void* lprcClip, std::uint64_t lpfnEnum, std::int64_t dwData) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hdc);
    static_cast<void>(lprcClip);
    static_cast<void>(lpfnEnum);
    static_cast<void>(dwData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_EnumPropsA(void* hWnd, std::uint64_t lpEnumFunc) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(lpEnumFunc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_EnumPropsExA(void* hWnd, std::uint64_t lpEnumFunc, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_EnumPropsExW(void* hWnd, std::uint64_t lpEnumFunc, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_EnumPropsW(void* hWnd, std::uint64_t lpEnumFunc) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(lpEnumFunc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_EnumWindowStationsA(std::uint64_t lpEnumFunc, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_EnumWindowStationsW(std::uint64_t lpEnumFunc, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(lpEnumFunc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_EqualRect(const void* lprc1, const void* lprc2) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(lprc1);
    static_cast<void>(lprc2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ExcludeUpdateRgn(void* hDC, void* hWnd) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hDC);
    static_cast<void>(hWnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ExitWindowsEx(std::uint32_t uFlags, std::uint32_t dwReason) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(uFlags);
    static_cast<void>(dwReason);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_FlashWindow(void* hWnd, std::int32_t bInvert) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    static_cast<void>(bInvert);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_FlashWindowEx(std::uint64_t pfwi) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(pfwi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_FreeDDElParam(std::uint32_t msg, std::int64_t lParam) noexcept {
    // Refused: dynamic data exchange.
    //
    // DDE is a protocol of the window manager's message queue
    static_cast<void>(msg);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetAltTabInfoA(void* hwnd, std::int32_t iItem, std::uint64_t pati, char* pszItemText, std::uint32_t cchItemText) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hwnd);
    static_cast<void>(iItem);
    static_cast<void>(pati);
    static_cast<void>(pszItemText);
    static_cast<void>(cchItemText);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetAltTabInfoW(void* hwnd, std::int32_t iItem, std::uint64_t pati, char16_t* pszItemText, std::uint32_t cchItemText) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hwnd);
    static_cast<void>(iItem);
    static_cast<void>(pati);
    static_cast<void>(pszItemText);
    static_cast<void>(cchItemText);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_GetAncestor(void* hwnd, std::uint32_t gaFlags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hwnd);
    static_cast<void>(gaFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetCaretBlinkTime() noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetCaretPos(void* lpPoint) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(lpPoint);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetClassInfoA(void* hInstance, const char* lpClassName, void* lpWndClass) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hInstance);
    static_cast<void>(lpClassName);
    static_cast<void>(lpWndClass);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetClassInfoExA(void* hInstance, const char* lpszClass, void* lpwcx) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hInstance);
    static_cast<void>(lpszClass);
    static_cast<void>(lpwcx);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetClassInfoExW(void* hInstance, const char16_t* lpszClass, void* lpwcx) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hInstance);
    static_cast<void>(lpszClass);
    static_cast<void>(lpwcx);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetClassInfoW(void* hInstance, const char16_t* lpClassName, void* lpWndClass) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hInstance);
    static_cast<void>(lpClassName);
    static_cast<void>(lpWndClass);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetClassLongA(void* hWnd, std::int32_t nIndex) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(nIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuser32G_GetClassLongPtrA(void* hWnd, std::int32_t nIndex) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(nIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuser32G_GetClassLongPtrW(void* hWnd, std::int32_t nIndex) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(nIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetClassLongW(void* hWnd, std::int32_t nIndex) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(nIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kuser32G_GetClassWord(void* hWnd, std::int32_t nIndex) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(nIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetClipCursor(void* lpRect) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(lpRect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetClipboardFormatNameA(std::uint32_t format, char* lpszFormatName, std::int32_t cchMaxCount) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(format);
    static_cast<void>(lpszFormatName);
    static_cast<void>(cchMaxCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetClipboardFormatNameW(std::uint32_t format, char16_t* lpszFormatName, std::int32_t cchMaxCount) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(format);
    static_cast<void>(lpszFormatName);
    static_cast<void>(cchMaxCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_GetClipboardOwner() noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_GetClipboardViewer() noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetComboBoxInfo(void* hwndCombo, std::uint64_t pcbi) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hwndCombo);
    static_cast<void>(pcbi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_GetCursor() noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetCursorInfo(void* pci) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(pci);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetDialogBaseUnits() noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetDlgItemInt(void* hDlg, std::int32_t nIDDlgItem, std::int32_t* lpTranslated, std::int32_t bSigned) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(nIDDlgItem);
    static_cast<void>(lpTranslated);
    static_cast<void>(bSigned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetGUIThreadInfo(std::uint32_t idThread, void* pgui) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(idThread);
    static_cast<void>(pgui);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetIconInfo(void* hIcon, void* piconinfo) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hIcon);
    static_cast<void>(piconinfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetIconInfoExA(void* hicon, std::uint64_t piconinfo) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hicon);
    static_cast<void>(piconinfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetIconInfoExW(void* hicon, std::uint64_t piconinfo) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hicon);
    static_cast<void>(piconinfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetInputState() noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetKBCodePage() noexcept {
    // Refused: the national language support data.
    //
    // the locale, calendar and collation tables are data files of a system
    // installation; this runtime would be inventing them, and a guest that
    // formats a date through invented tables is told a wrong answer rather
    // than an unavailable one
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetKeyNameTextA(std::int32_t lParam, char* lpString, std::int32_t cchSize) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(lParam);
    static_cast<void>(lpString);
    static_cast<void>(cchSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetKeyNameTextW(std::int32_t lParam, char16_t* lpString, std::int32_t cchSize) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(lParam);
    static_cast<void>(lpString);
    static_cast<void>(cchSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetKeyboardLayoutNameA(char* pwszKLID) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(pwszKLID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetKeyboardLayoutNameW(char16_t* pwszKLID) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(pwszKLID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_GetLastActivePopup(void* hWnd) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetLastInputInfo(std::uint64_t plii) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(plii);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetLayeredWindowAttributes(void* hwnd, std::uint32_t* pcrKey, std::uint8_t* pbAlpha, std::uint32_t* pdwFlags) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hwnd);
    static_cast<void>(pcrKey);
    static_cast<void>(pbAlpha);
    static_cast<void>(pdwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetListBoxInfo(void* hwnd) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hwnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetMenuBarInfo(void* hwnd, std::int32_t idObject, std::int32_t idItem, std::uint64_t pmbi) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hwnd);
    static_cast<void>(idObject);
    static_cast<void>(idItem);
    static_cast<void>(pmbi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetMenuCheckMarkDimensions() noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetMenuContextHelpId(void* arg0) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetMenuDefaultItem(void* hMenu, std::uint32_t fByPos, std::uint32_t gmdiFlags) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMenu);
    static_cast<void>(fByPos);
    static_cast<void>(gmdiFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetMenuInfo(void* arg0, void* arg1) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetMenuItemInfoA(void* hmenu, std::uint32_t item, std::int32_t fByPosition, std::uint64_t lpmii) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hmenu);
    static_cast<void>(item);
    static_cast<void>(fByPosition);
    static_cast<void>(lpmii);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetMenuItemInfoW(void* hmenu, std::uint32_t item, std::int32_t fByPosition, std::uint64_t lpmii) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hmenu);
    static_cast<void>(item);
    static_cast<void>(fByPosition);
    static_cast<void>(lpmii);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetMenuItemRect(void* hWnd, void* hMenu, std::uint32_t uItem, void* lprcItem) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hWnd);
    static_cast<void>(hMenu);
    static_cast<void>(uItem);
    static_cast<void>(lprcItem);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetMenuState(void* hMenu, std::uint32_t uId, std::uint32_t uFlags) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMenu);
    static_cast<void>(uId);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetMenuStringA(void* hMenu, std::uint32_t uIDItem, char* lpString, std::int32_t cchMax, std::uint32_t flags) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMenu);
    static_cast<void>(uIDItem);
    static_cast<void>(lpString);
    static_cast<void>(cchMax);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetMenuStringW(void* hMenu, std::uint32_t uIDItem, char16_t* lpString, std::int32_t cchMax, std::uint32_t flags) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMenu);
    static_cast<void>(uIDItem);
    static_cast<void>(lpString);
    static_cast<void>(cchMax);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_GetMessageExtraInfo() noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetMessagePos() noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetMessageTime() noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetMonitorInfoA(void* hMonitor, std::uint64_t lpmi) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hMonitor);
    static_cast<void>(lpmi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetMonitorInfoW(void* hMonitor, std::uint64_t lpmi) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hMonitor);
    static_cast<void>(lpmi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetMouseMovePointsEx(std::uint32_t cbSize, std::uint64_t lppt, std::uint64_t lpptBuf, std::int32_t nBufPoints, std::uint32_t resolution) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(cbSize);
    static_cast<void>(lppt);
    static_cast<void>(lpptBuf);
    static_cast<void>(nBufPoints);
    static_cast<void>(resolution);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_GetNextDlgGroupItem(void* hDlg, void* hCtl, std::int32_t bPrevious) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(hCtl);
    static_cast<void>(bPrevious);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_GetNextDlgTabItem(void* hDlg, void* hCtl, std::int32_t bPrevious) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(hCtl);
    static_cast<void>(bPrevious);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_GetOpenClipboardWindow() noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetPointerInputTransform(std::uint32_t pointerId, std::uint32_t historyCount, std::uint32_t* inputTransform) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(pointerId);
    static_cast<void>(historyCount);
    static_cast<void>(inputTransform);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetPriorityClipboardFormat(std::uint32_t* paFormatPriorityList, std::int32_t cFormats) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(paFormatPriorityList);
    static_cast<void>(cFormats);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetProcessDefaultLayout(std::uint32_t* pdwDefaultLayout) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(pdwDefaultLayout);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_GetPropA(void* hWnd, const char* lpString) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(lpString);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_GetPropW(void* hWnd, const char16_t* lpString) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(lpString);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetQueueStatus(std::uint32_t flags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetRawInputBuffer(std::uint64_t pData, std::uint32_t* pcbSize, std::uint32_t cbSizeHeader) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(pData);
    static_cast<void>(pcbSize);
    static_cast<void>(cbSizeHeader);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetRawInputData(std::uint64_t hRawInput, std::uint32_t uiCommand, void* pData, std::uint32_t* pcbSize, std::uint32_t cbSizeHeader) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hRawInput);
    static_cast<void>(uiCommand);
    static_cast<void>(pData);
    static_cast<void>(pcbSize);
    static_cast<void>(cbSizeHeader);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetRawInputDeviceInfoA(void* hDevice, std::uint32_t uiCommand, void* pData, std::uint32_t* pcbSize) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hDevice);
    static_cast<void>(uiCommand);
    static_cast<void>(pData);
    static_cast<void>(pcbSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetRawInputDeviceInfoW(void* hDevice, std::uint32_t uiCommand, void* pData, std::uint32_t* pcbSize) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hDevice);
    static_cast<void>(uiCommand);
    static_cast<void>(pData);
    static_cast<void>(pcbSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetRawInputDeviceList(std::uint64_t pRawInputDeviceList, std::uint32_t* puiNumDevices, std::uint32_t cbSize) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(pRawInputDeviceList);
    static_cast<void>(puiNumDevices);
    static_cast<void>(cbSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetRegisteredRawInputDevices(std::uint64_t pRawInputDevices, std::uint32_t* puiNumDevices, std::uint32_t cbSize) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(pRawInputDevices);
    static_cast<void>(puiNumDevices);
    static_cast<void>(cbSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetScrollBarInfo(void* hwnd, std::int32_t idObject, std::uint64_t psbi) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hwnd);
    static_cast<void>(idObject);
    static_cast<void>(psbi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetScrollInfo(void* hwnd, std::int32_t nBar, void* lpsi) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hwnd);
    static_cast<void>(nBar);
    static_cast<void>(lpsi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetScrollPos(void* hWnd, std::int32_t nBar) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(nBar);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetScrollRange(void* hWnd, std::int32_t nBar, std::int32_t* lpMinPos, std::int32_t* lpMaxPos) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(nBar);
    static_cast<void>(lpMinPos);
    static_cast<void>(lpMaxPos);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_GetShellWindow() noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_GetSubMenu(void* hMenu, std::int32_t nPos) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMenu);
    static_cast<void>(nPos);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetSysColor(std::int32_t nIndex) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(nIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_GetSysColorBrush(std::int32_t nIndex) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(nIndex);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_GetSystemMenu(void* hWnd, std::int32_t bRevert) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hWnd);
    static_cast<void>(bRevert);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetTabbedTextExtentA(void* hdc, const char* lpString, std::int32_t chCount, std::int32_t nTabPositions, const std::int32_t* lpnTabStopPositions) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(hdc);
    static_cast<void>(lpString);
    static_cast<void>(chCount);
    static_cast<void>(nTabPositions);
    static_cast<void>(lpnTabStopPositions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetTabbedTextExtentW(void* hdc, const char16_t* lpString, std::int32_t chCount, std::int32_t nTabPositions, const std::int32_t* lpnTabStopPositions) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(hdc);
    static_cast<void>(lpString);
    static_cast<void>(chCount);
    static_cast<void>(nTabPositions);
    static_cast<void>(lpnTabStopPositions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuser32G_GetThreadDesktop(std::uint32_t dwThreadId) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(dwThreadId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetTitleBarInfo(void* hwnd, std::uint64_t pti) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hwnd);
    static_cast<void>(pti);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetUnpredictedMessagePos() noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetUpdateRect(void* hWnd, void* lpRect, std::int32_t bErase) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(lpRect);
    static_cast<void>(bErase);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetUpdateRgn(void* hWnd, std::uint64_t hRgn, std::int32_t bErase) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(hRgn);
    static_cast<void>(bErase);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetUserObjectInformationA(void* hObj, std::int32_t nIndex, void* pvInfo, std::uint32_t nLength, std::uint32_t* lpnLengthNeeded) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hObj);
    static_cast<void>(nIndex);
    static_cast<void>(pvInfo);
    static_cast<void>(nLength);
    static_cast<void>(lpnLengthNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetUserObjectInformationW(void* hObj, std::int32_t nIndex, void* pvInfo, std::uint32_t nLength, std::uint32_t* lpnLengthNeeded) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hObj);
    static_cast<void>(nIndex);
    static_cast<void>(pvInfo);
    static_cast<void>(nLength);
    static_cast<void>(lpnLengthNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetUserObjectSecurity(void* hObj, std::uint32_t* pSIRequested, void* pSID, std::uint32_t nLength, std::uint32_t* lpnLengthNeeded) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hObj);
    static_cast<void>(pSIRequested);
    static_cast<void>(pSID);
    static_cast<void>(nLength);
    static_cast<void>(lpnLengthNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetWindowContextHelpId(void* arg0) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetWindowDisplayAffinity(void* hWnd, std::uint32_t* pdwAffinity) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    static_cast<void>(pdwAffinity);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetWindowInfo(void* hwnd, void* pwi) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hwnd);
    static_cast<void>(pwi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetWindowModuleFileNameA(void* hwnd, char* pszFileName, std::uint32_t cchFileNameMax) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hwnd);
    static_cast<void>(pszFileName);
    static_cast<void>(cchFileNameMax);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_GetWindowModuleFileNameW(void* hwnd, char16_t* pszFileName, std::uint32_t cchFileNameMax) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hwnd);
    static_cast<void>(pszFileName);
    static_cast<void>(cchFileNameMax);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetWindowPlacement(void* hWnd, void* lpwndpl) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    static_cast<void>(lpwndpl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetWindowRgn(void* hWnd, std::uint64_t hRgn) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    static_cast<void>(hRgn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GetWindowRgnBox(void* hWnd, void* lprc) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    static_cast<void>(lprc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kuser32G_GetWindowWord(void* hWnd, std::int32_t nIndex) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    static_cast<void>(nIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GrayStringA(void* hDC, void* hBrush, std::uint64_t lpOutputFunc, std::int64_t lpData, std::int32_t nCount, std::int32_t X, std::int32_t Y, std::int32_t nWidth, std::int32_t nHeight) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(hDC);
    static_cast<void>(hBrush);
    static_cast<void>(lpOutputFunc);
    static_cast<void>(lpData);
    static_cast<void>(nCount);
    static_cast<void>(X);
    static_cast<void>(Y);
    static_cast<void>(nWidth);
    static_cast<void>(nHeight);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_GrayStringW(void* hDC, void* hBrush, std::uint64_t lpOutputFunc, std::int64_t lpData, std::int32_t nCount, std::int32_t X, std::int32_t Y, std::int32_t nWidth, std::int32_t nHeight) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(hDC);
    static_cast<void>(hBrush);
    static_cast<void>(lpOutputFunc);
    static_cast<void>(lpData);
    static_cast<void>(nCount);
    static_cast<void>(X);
    static_cast<void>(Y);
    static_cast<void>(nWidth);
    static_cast<void>(nHeight);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_HideCaret(void* hWnd) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_HiliteMenuItem(void* hWnd, void* hMenu, std::uint32_t uIDHiliteItem, std::uint32_t uHilite) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hWnd);
    static_cast<void>(hMenu);
    static_cast<void>(uIDHiliteItem);
    static_cast<void>(uHilite);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ImpersonateDdeClientWindow(void* hWndClient, void* hWndServer) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWndClient);
    static_cast<void>(hWndServer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_InSendMessage() noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_InSendMessageEx(void* lpReserved) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_InflateRect(void* lprc, std::int32_t dx, std::int32_t dy) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(lprc);
    static_cast<void>(dx);
    static_cast<void>(dy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_InsertMenuA(void* hMenu, std::uint32_t uPosition, std::uint32_t uFlags, std::uint64_t uIDNewItem, const char* lpNewItem) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMenu);
    static_cast<void>(uPosition);
    static_cast<void>(uFlags);
    static_cast<void>(uIDNewItem);
    static_cast<void>(lpNewItem);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_InsertMenuItemA(void* hmenu, std::uint32_t item, std::int32_t fByPosition, std::uint64_t lpmi) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hmenu);
    static_cast<void>(item);
    static_cast<void>(fByPosition);
    static_cast<void>(lpmi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_InsertMenuItemW(void* hmenu, std::uint32_t item, std::int32_t fByPosition, std::uint64_t lpmi) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hmenu);
    static_cast<void>(item);
    static_cast<void>(fByPosition);
    static_cast<void>(lpmi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_InsertMenuW(void* hMenu, std::uint32_t uPosition, std::uint32_t uFlags, std::uint64_t uIDNewItem, const char16_t* lpNewItem) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMenu);
    static_cast<void>(uPosition);
    static_cast<void>(uFlags);
    static_cast<void>(uIDNewItem);
    static_cast<void>(lpNewItem);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_InternalGetWindowText(void* hWnd, char16_t* pString, std::int32_t cchMaxCount) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    static_cast<void>(pString);
    static_cast<void>(cchMaxCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IntersectRect(void* lprcDst, const void* lprcSrc1, const void* lprcSrc2) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(lprcDst);
    static_cast<void>(lprcSrc1);
    static_cast<void>(lprcSrc2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_InvalidateRgn(void* hWnd, std::uint64_t hRgn, std::int32_t bErase) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(hRgn);
    static_cast<void>(bErase);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsCharAlphaA(char ch) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(ch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsCharAlphaNumericA(char ch) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(ch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsCharAlphaNumericW(char16_t ch) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(ch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsCharAlphaW(char16_t ch) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(ch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsCharLowerA(char ch) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(ch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsCharLowerW(char16_t ch) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(ch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsCharUpperA(char ch) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(ch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsCharUpperW(char16_t ch) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(ch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsDialogMessageA(void* hDlg, void* lpMsg) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(lpMsg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsDialogMessageW(void* hDlg, void* lpMsg) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(lpMsg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_IsDlgButtonChecked(void* hDlg, std::int32_t nIDButton) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(nIDButton);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsGUIThread(std::int32_t bConvert) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(bConvert);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsHungAppWindow(void* hwnd) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hwnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsMenu(void* hMenu) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMenu);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsProcessDPIAware() noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsRectEmpty(const void* lprc) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(lprc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsWinEventHookInstalled(std::uint32_t event) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(event);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsWindowUnicode(void* hWnd) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_IsWow64Message() noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_LoadAcceleratorsA(void* hInstance, const char* lpTableName) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hInstance);
    static_cast<void>(lpTableName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_LoadAcceleratorsW(void* hInstance, const char16_t* lpTableName) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hInstance);
    static_cast<void>(lpTableName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_LoadBitmapA(void* hInstance, const char* lpBitmapName) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hInstance);
    static_cast<void>(lpBitmapName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_LoadBitmapW(void* hInstance, const char16_t* lpBitmapName) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hInstance);
    static_cast<void>(lpBitmapName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_LoadCursorFromFileA(const char* lpFileName) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(lpFileName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_LoadCursorFromFileW(const char16_t* lpFileName) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(lpFileName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_LoadImageA(void* hInst, const char* name, std::uint32_t type, std::int32_t cx, std::int32_t cy, std::uint32_t fuLoad) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hInst);
    static_cast<void>(name);
    static_cast<void>(type);
    static_cast<void>(cx);
    static_cast<void>(cy);
    static_cast<void>(fuLoad);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_LoadImageW(void* hInst, const char16_t* name, std::uint32_t type, std::int32_t cx, std::int32_t cy, std::uint32_t fuLoad) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hInst);
    static_cast<void>(name);
    static_cast<void>(type);
    static_cast<void>(cx);
    static_cast<void>(cy);
    static_cast<void>(fuLoad);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_LoadKeyboardLayoutA(const char* pwszKLID, std::uint32_t Flags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(pwszKLID);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_LoadKeyboardLayoutW(const char16_t* pwszKLID, std::uint32_t Flags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(pwszKLID);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_LoadMenuA(void* hInstance, const char* lpMenuName) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hInstance);
    static_cast<void>(lpMenuName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_LoadMenuIndirectA(const void* lpMenuTemplate) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(lpMenuTemplate);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_LoadMenuIndirectW(const void* lpMenuTemplate) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(lpMenuTemplate);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_LoadMenuW(void* hInstance, const char16_t* lpMenuName) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hInstance);
    static_cast<void>(lpMenuName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_LoadStringA(void* hInstance, std::uint32_t uID, char* lpBuffer, std::int32_t cchBufferMax) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(hInstance);
    static_cast<void>(uID);
    static_cast<void>(lpBuffer);
    static_cast<void>(cchBufferMax);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_LoadStringW(void* hInstance, std::uint32_t uID, char16_t* lpBuffer, std::int32_t cchBufferMax) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(hInstance);
    static_cast<void>(uID);
    static_cast<void>(lpBuffer);
    static_cast<void>(cchBufferMax);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_LockSetForegroundWindow(std::uint32_t uLockCode) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(uLockCode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_LockWindowUpdate(void* hWndLock) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWndLock);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_LockWorkStation() noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_LookupIconIdFromDirectory(std::uint8_t* presbits, std::int32_t fIcon) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(presbits);
    static_cast<void>(fIcon);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_LookupIconIdFromDirectoryEx(std::uint8_t* presbits, std::int32_t fIcon, std::int32_t cxDesired, std::int32_t cyDesired, std::uint32_t Flags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(presbits);
    static_cast<void>(fIcon);
    static_cast<void>(cxDesired);
    static_cast<void>(cyDesired);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_MapDialogRect(void* hDlg, void* lpRect) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(lpRect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_MapVirtualKeyExA(std::uint32_t uCode, std::uint32_t uMapType, void* dwhkl) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(uCode);
    static_cast<void>(uMapType);
    static_cast<void>(dwhkl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_MapVirtualKeyExW(std::uint32_t uCode, std::uint32_t uMapType, void* dwhkl) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(uCode);
    static_cast<void>(uMapType);
    static_cast<void>(dwhkl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_MapWindowPoints(void* hWndFrom, void* hWndTo, void* lpPoints, std::uint32_t cPoints) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWndFrom);
    static_cast<void>(hWndTo);
    static_cast<void>(lpPoints);
    static_cast<void>(cPoints);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_MenuItemFromPoint(void* hWnd, void* hMenu, std::uint64_t ptScreen) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hWnd);
    static_cast<void>(hMenu);
    static_cast<void>(ptScreen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_MessageBoxIndirectA(const void* lpmbp) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(lpmbp);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_MessageBoxIndirectW(const void* lpmbp) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(lpmbp);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ModifyMenuA(void* hMnu, std::uint32_t uPosition, std::uint32_t uFlags, std::uint64_t uIDNewItem, const char* lpNewItem) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMnu);
    static_cast<void>(uPosition);
    static_cast<void>(uFlags);
    static_cast<void>(uIDNewItem);
    static_cast<void>(lpNewItem);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ModifyMenuW(void* hMnu, std::uint32_t uPosition, std::uint32_t uFlags, std::uint64_t uIDNewItem, const char16_t* lpNewItem) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMnu);
    static_cast<void>(uPosition);
    static_cast<void>(uFlags);
    static_cast<void>(uIDNewItem);
    static_cast<void>(lpNewItem);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_MonitorFromPoint(std::uint64_t pt, std::uint32_t dwFlags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(pt);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_MonitorFromRect(void* lprc, std::uint32_t dwFlags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(lprc);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_MonitorFromWindow(void* hwnd, std::uint32_t dwFlags) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hwnd);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_MsgWaitForMultipleObjects(std::uint32_t nCount, const void* pHandles, std::int32_t fWaitAll, std::uint32_t dwMilliseconds, std::uint32_t dwWakeMask) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(nCount);
    static_cast<void>(pHandles);
    static_cast<void>(fWaitAll);
    static_cast<void>(dwMilliseconds);
    static_cast<void>(dwWakeMask);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_MsgWaitForMultipleObjectsEx(std::uint32_t nCount, const void* pHandles, std::uint32_t dwMilliseconds, std::uint32_t dwWakeMask, std::uint32_t dwFlags) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(nCount);
    static_cast<void>(pHandles);
    static_cast<void>(dwMilliseconds);
    static_cast<void>(dwWakeMask);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kuser32G_NotifyWinEvent(std::uint32_t event, void* hwnd, std::int32_t idObject, std::int32_t idChild) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(event);
    static_cast<void>(hwnd);
    static_cast<void>(idObject);
    static_cast<void>(idChild);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_OemKeyScan(std::uint16_t wOemChar) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(wOemChar);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_OemToCharBuffA(const char* lpszSrc, char* lpszDst, std::uint32_t cchDstLength) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(lpszSrc);
    static_cast<void>(lpszDst);
    static_cast<void>(cchDstLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_OemToCharBuffW(const char* lpszSrc, char16_t* lpszDst, std::uint32_t cchDstLength) noexcept {
    // Refused: the window manager.
    //
    // the call is part of the window manager's text handling and has no
    // meaning without a window or a device context to draw into
    static_cast<void>(lpszSrc);
    static_cast<void>(lpszDst);
    static_cast<void>(cchDstLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_OffsetRect(void* lprc, std::int32_t dx, std::int32_t dy) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(lprc);
    static_cast<void>(dx);
    static_cast<void>(dy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuser32G_OpenDesktopA(const char* lpszDesktop, std::uint32_t dwFlags, std::int32_t fInherit, std::uint32_t dwDesiredAccess) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(lpszDesktop);
    static_cast<void>(dwFlags);
    static_cast<void>(fInherit);
    static_cast<void>(dwDesiredAccess);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuser32G_OpenDesktopW(const char16_t* lpszDesktop, std::uint32_t dwFlags, std::int32_t fInherit, std::uint32_t dwDesiredAccess) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(lpszDesktop);
    static_cast<void>(dwFlags);
    static_cast<void>(fInherit);
    static_cast<void>(dwDesiredAccess);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_OpenIcon(void* hWnd) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuser32G_OpenInputDesktop(std::uint32_t dwFlags, std::int32_t fInherit, std::uint32_t dwDesiredAccess) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(dwFlags);
    static_cast<void>(fInherit);
    static_cast<void>(dwDesiredAccess);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuser32G_OpenWindowStationA(const char* lpszWinSta, std::int32_t fInherit, std::uint32_t dwDesiredAccess) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(lpszWinSta);
    static_cast<void>(fInherit);
    static_cast<void>(dwDesiredAccess);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuser32G_OpenWindowStationW(const char16_t* lpszWinSta, std::int32_t fInherit, std::uint32_t dwDesiredAccess) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(lpszWinSta);
    static_cast<void>(fInherit);
    static_cast<void>(dwDesiredAccess);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_PackDDElParam(std::uint32_t msg, std::uint64_t uiLo, std::uint64_t uiHi) noexcept {
    // Refused: dynamic data exchange.
    //
    // DDE is a protocol of the window manager's message queue
    static_cast<void>(msg);
    static_cast<void>(uiLo);
    static_cast<void>(uiHi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_PaintDesktop(void* hdc) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hdc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_PostThreadMessageA(std::uint32_t idThread, std::uint32_t Msg, std::uint64_t wParam, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(idThread);
    static_cast<void>(Msg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_PrintWindow(void* hwnd, void* hdcBlt, std::uint32_t nFlags) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hwnd);
    static_cast<void>(hdcBlt);
    static_cast<void>(nFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_PrivateExtractIconsA(const char* szFileName, std::int32_t nIconIndex, std::int32_t cxIcon, std::int32_t cyIcon, void* phicon, std::uint32_t* piconid, std::uint32_t nIcons, std::uint32_t flags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(szFileName);
    static_cast<void>(nIconIndex);
    static_cast<void>(cxIcon);
    static_cast<void>(cyIcon);
    static_cast<void>(phicon);
    static_cast<void>(piconid);
    static_cast<void>(nIcons);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_PrivateExtractIconsW(const char16_t* szFileName, std::int32_t nIconIndex, std::int32_t cxIcon, std::int32_t cyIcon, void* phicon, std::uint32_t* piconid, std::uint32_t nIcons, std::uint32_t flags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(szFileName);
    static_cast<void>(nIconIndex);
    static_cast<void>(cxIcon);
    static_cast<void>(cyIcon);
    static_cast<void>(phicon);
    static_cast<void>(piconid);
    static_cast<void>(nIcons);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_PtInRect(const void* lprc, std::uint64_t pt) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(lprc);
    static_cast<void>(pt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_RealChildWindowFromPoint(void* hwndParent, std::uint64_t ptParentClientCoords) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hwndParent);
    static_cast<void>(ptParentClientCoords);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_RealGetWindowClassA(void* hwnd, char* ptszClassName, std::uint32_t cchClassNameMax) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hwnd);
    static_cast<void>(ptszClassName);
    static_cast<void>(cchClassNameMax);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_RealGetWindowClassW(void* hwnd, char16_t* ptszClassName, std::uint32_t cchClassNameMax) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hwnd);
    static_cast<void>(ptszClassName);
    static_cast<void>(cchClassNameMax);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_RedrawWindow(void* hWnd, const void* lprcUpdate, std::uint64_t hrgnUpdate, std::uint32_t flags) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    static_cast<void>(lprcUpdate);
    static_cast<void>(hrgnUpdate);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuser32G_RegisterDeviceNotificationA(void* hRecipient, void* NotificationFilter, std::uint32_t Flags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hRecipient);
    static_cast<void>(NotificationFilter);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuser32G_RegisterDeviceNotificationW(void* hRecipient, void* NotificationFilter, std::uint32_t Flags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hRecipient);
    static_cast<void>(NotificationFilter);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_RegisterHotKey(void* hWnd, std::int32_t id, std::uint32_t fsModifiers, std::uint32_t vk) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(id);
    static_cast<void>(fsModifiers);
    static_cast<void>(vk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuser32G_RegisterPowerSettingNotification(void* hRecipient, void* PowerSettingGuid, std::uint32_t Flags) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(hRecipient);
    static_cast<void>(PowerSettingGuid);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_RegisterRawInputDevices(std::uint64_t pRawInputDevices, std::uint32_t uiNumDevices, std::uint32_t cbSize) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(pRawInputDevices);
    static_cast<void>(uiNumDevices);
    static_cast<void>(cbSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_RegisterShellHookWindow(void* hwnd) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hwnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuser32G_RegisterSuspendResumeNotification(void* hRecipient, std::uint32_t Flags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hRecipient);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_RegisterWindowMessageA(const char* lpString) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(lpString);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_RegisterWindowMessageW(const char16_t* lpString) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(lpString);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_RemoveMenu(void* hMenu, std::uint32_t uPosition, std::uint32_t uFlags) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMenu);
    static_cast<void>(uPosition);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_RemovePropA(void* hWnd, const char* lpString) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(lpString);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_RemovePropW(void* hWnd, const char16_t* lpString) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(lpString);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ReplyMessage(std::int64_t lResult) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(lResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_ReuseDDElParam(std::int64_t lParam, std::uint32_t msgIn, std::uint32_t msgOut, std::uint64_t uiLo, std::uint64_t uiHi) noexcept {
    // Refused: dynamic data exchange.
    //
    // DDE is a protocol of the window manager's message queue
    static_cast<void>(lParam);
    static_cast<void>(msgIn);
    static_cast<void>(msgOut);
    static_cast<void>(uiLo);
    static_cast<void>(uiHi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ScreenToClient(void* hWnd, void* lpPoint) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(lpPoint);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ScrollDC(void* hDC, std::int32_t dx, std::int32_t dy, const void* lprcScroll, const void* lprcClip, std::uint64_t hrgnUpdate, void* lprcUpdate) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hDC);
    static_cast<void>(dx);
    static_cast<void>(dy);
    static_cast<void>(lprcScroll);
    static_cast<void>(lprcClip);
    static_cast<void>(hrgnUpdate);
    static_cast<void>(lprcUpdate);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ScrollWindow(void* hWnd, std::int32_t XAmount, std::int32_t YAmount, const void* lpRect, const void* lpClipRect) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    static_cast<void>(XAmount);
    static_cast<void>(YAmount);
    static_cast<void>(lpRect);
    static_cast<void>(lpClipRect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ScrollWindowEx(void* hWnd, std::int32_t dx, std::int32_t dy, const void* prcScroll, const void* prcClip, std::uint64_t hrgnUpdate, void* prcUpdate, std::uint32_t flags) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    static_cast<void>(dx);
    static_cast<void>(dy);
    static_cast<void>(prcScroll);
    static_cast<void>(prcClip);
    static_cast<void>(hrgnUpdate);
    static_cast<void>(prcUpdate);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_SendDlgItemMessageA(void* hDlg, std::int32_t nIDDlgItem, std::uint32_t Msg, std::uint64_t wParam, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(nIDDlgItem);
    static_cast<void>(Msg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_SendDlgItemMessageW(void* hDlg, std::int32_t nIDDlgItem, std::uint32_t Msg, std::uint64_t wParam, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(nIDDlgItem);
    static_cast<void>(Msg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_SendInput(std::uint32_t cInputs, void* pInputs, std::int32_t cbSize) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(cInputs);
    static_cast<void>(pInputs);
    static_cast<void>(cbSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SendMessageCallbackA(void* hWnd, std::uint32_t Msg, std::uint64_t wParam, std::int64_t lParam, std::uint64_t lpResultCallBack, std::uint64_t dwData) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(hWnd);
    static_cast<void>(Msg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    static_cast<void>(lpResultCallBack);
    static_cast<void>(dwData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SendMessageCallbackW(void* hWnd, std::uint32_t Msg, std::uint64_t wParam, std::int64_t lParam, std::uint64_t lpResultCallBack, std::uint64_t dwData) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(hWnd);
    static_cast<void>(Msg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    static_cast<void>(lpResultCallBack);
    static_cast<void>(dwData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_SendMessageTimeoutA(void* hWnd, std::uint32_t Msg, std::uint64_t wParam, std::int64_t lParam, std::uint32_t fuFlags, std::uint32_t uTimeout, std::uint64_t* lpdwResult) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(hWnd);
    static_cast<void>(Msg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    static_cast<void>(fuFlags);
    static_cast<void>(uTimeout);
    static_cast<void>(lpdwResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_SendMessageTimeoutW(void* hWnd, std::uint32_t Msg, std::uint64_t wParam, std::int64_t lParam, std::uint32_t fuFlags, std::uint32_t uTimeout, std::uint64_t* lpdwResult) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(hWnd);
    static_cast<void>(Msg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    static_cast<void>(fuFlags);
    static_cast<void>(uTimeout);
    static_cast<void>(lpdwResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SendNotifyMessageA(void* hWnd, std::uint32_t Msg, std::uint64_t wParam, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(hWnd);
    static_cast<void>(Msg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SendNotifyMessageW(void* hWnd, std::uint32_t Msg, std::uint64_t wParam, std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(hWnd);
    static_cast<void>(Msg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetCaretBlinkTime(std::uint32_t uMSeconds) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(uMSeconds);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetCaretPos(std::int32_t X, std::int32_t Y) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(X);
    static_cast<void>(Y);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_SetClassLongA(void* hWnd, std::int32_t nIndex, std::int32_t dwNewLong) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(nIndex);
    static_cast<void>(dwNewLong);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuser32G_SetClassLongPtrA(void* hWnd, std::int32_t nIndex, std::int64_t dwNewLong) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(nIndex);
    static_cast<void>(dwNewLong);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuser32G_SetClassLongPtrW(void* hWnd, std::int32_t nIndex, std::int64_t dwNewLong) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(nIndex);
    static_cast<void>(dwNewLong);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_SetClassLongW(void* hWnd, std::int32_t nIndex, std::int32_t dwNewLong) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(nIndex);
    static_cast<void>(dwNewLong);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kuser32G_SetClassWord(void* hWnd, std::int32_t nIndex, std::uint16_t wNewWord) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(nIndex);
    static_cast<void>(wNewWord);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_SetClipboardViewer(void* hWndNewViewer) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWndNewViewer);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_SetCursor(void* hCursor) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hCursor);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kuser32G_SetDebugErrorLevel(std::uint32_t dwLevel) noexcept {
    // Refused: the debugging interface.
    //
    // a debugger needs the kernel to stop a process and report its events;
    // this runtime runs its guest in-process and answers the queries that read
    // its own state
    static_cast<void>(dwLevel);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetDlgItemInt(void* hDlg, std::int32_t nIDDlgItem, std::uint32_t uValue, std::int32_t bSigned) noexcept {
    // Refused: the window manager.
    //
    // a dialog is a window with a message loop behind it; there is no window
    // manager in this runtime and therefore no dialog
    static_cast<void>(hDlg);
    static_cast<void>(nIDDlgItem);
    static_cast<void>(uValue);
    static_cast<void>(bSigned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetDoubleClickTime(std::uint32_t arg0) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kuser32G_SetLastErrorEx(std::uint32_t dwErrCode, std::uint32_t dwType) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(dwErrCode);
    static_cast<void>(dwType);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetLayeredWindowAttributes(void* hwnd, std::uint32_t crKey, std::uint8_t bAlpha, std::uint32_t dwFlags) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hwnd);
    static_cast<void>(crKey);
    static_cast<void>(bAlpha);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetMenuContextHelpId(void* arg0, std::uint32_t arg1) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetMenuDefaultItem(void* hMenu, std::uint32_t uItem, std::uint32_t fByPos) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMenu);
    static_cast<void>(uItem);
    static_cast<void>(fByPos);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetMenuInfo(void* arg0, void* arg1) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetMenuItemBitmaps(void* hMenu, std::uint32_t uPosition, std::uint32_t uFlags, void* hBitmapUnchecked, void* hBitmapChecked) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMenu);
    static_cast<void>(uPosition);
    static_cast<void>(uFlags);
    static_cast<void>(hBitmapUnchecked);
    static_cast<void>(hBitmapChecked);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetMenuItemInfoA(void* hmenu, std::uint32_t item, std::int32_t fByPositon, std::uint64_t lpmii) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hmenu);
    static_cast<void>(item);
    static_cast<void>(fByPositon);
    static_cast<void>(lpmii);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetMenuItemInfoW(void* hmenu, std::uint32_t item, std::int32_t fByPositon, std::uint64_t lpmii) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hmenu);
    static_cast<void>(item);
    static_cast<void>(fByPositon);
    static_cast<void>(lpmii);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kuser32G_SetMessageExtraInfo(std::int64_t lParam) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetMessageQueue(std::int32_t cMessagesMax) noexcept {
    // Refused: the window manager.
    //
    // a message is addressed to a window and delivered through the window
    // manager's queue; neither exists here
    static_cast<void>(cMessagesMax);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetProcessDPIAware() noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetProcessDefaultLayout(std::uint32_t dwDefaultLayout) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(dwDefaultLayout);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetProcessWindowStation(std::uint64_t hWinSta) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWinSta);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetPropA(void* hWnd, const char* lpString, void* hData) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(lpString);
    static_cast<void>(hData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetPropW(void* hWnd, const char16_t* lpString, void* hData) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(lpString);
    static_cast<void>(hData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetRect(void* lprc, std::int32_t xLeft, std::int32_t yTop, std::int32_t xRight, std::int32_t yBottom) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(lprc);
    static_cast<void>(xLeft);
    static_cast<void>(yTop);
    static_cast<void>(xRight);
    static_cast<void>(yBottom);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetRectEmpty(void* lprc) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(lprc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetScrollInfo(void* hwnd, std::int32_t nBar, void* lpsi, std::int32_t redraw) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hwnd);
    static_cast<void>(nBar);
    static_cast<void>(lpsi);
    static_cast<void>(redraw);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetScrollPos(void* hWnd, std::int32_t nBar, std::int32_t nPos, std::int32_t bRedraw) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(nBar);
    static_cast<void>(nPos);
    static_cast<void>(bRedraw);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetScrollRange(void* hWnd, std::int32_t nBar, std::int32_t nMinPos, std::int32_t nMaxPos, std::int32_t bRedraw) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(nBar);
    static_cast<void>(nMinPos);
    static_cast<void>(nMaxPos);
    static_cast<void>(bRedraw);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetSysColors(std::int32_t cElements, const std::int32_t* lpaElements, const std::uint32_t* lpaRgbValues) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(cElements);
    static_cast<void>(lpaElements);
    static_cast<void>(lpaRgbValues);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetSystemCursor(void* hcur, std::uint32_t id) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hcur);
    static_cast<void>(id);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetThreadDesktop(std::uint64_t hDesktop) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hDesktop);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetUserObjectInformationA(void* hObj, std::int32_t nIndex, void* pvInfo, std::uint32_t nLength) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hObj);
    static_cast<void>(nIndex);
    static_cast<void>(pvInfo);
    static_cast<void>(nLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetUserObjectInformationW(void* hObj, std::int32_t nIndex, void* pvInfo, std::uint32_t nLength) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hObj);
    static_cast<void>(nIndex);
    static_cast<void>(pvInfo);
    static_cast<void>(nLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetUserObjectSecurity(void* hObj, std::uint32_t* pSIRequested, void* pSID) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hObj);
    static_cast<void>(pSIRequested);
    static_cast<void>(pSID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuser32G_SetWinEventHook(std::uint32_t eventMin, std::uint32_t eventMax, void* hmodWinEventProc, std::uint64_t pfnWinEventProc, std::uint32_t idProcess, std::uint32_t idThread, std::uint32_t dwFlags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(eventMin);
    static_cast<void>(eventMax);
    static_cast<void>(hmodWinEventProc);
    static_cast<void>(pfnWinEventProc);
    static_cast<void>(idProcess);
    static_cast<void>(idThread);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetWindowContextHelpId(void* arg0, std::uint32_t arg1) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetWindowDisplayAffinity(void* hWnd, std::uint32_t dwAffinity) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    static_cast<void>(dwAffinity);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetWindowPlacement(void* hWnd, const void* lpwndpl) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    static_cast<void>(lpwndpl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SetWindowRgn(void* hWnd, std::uint64_t hRgn, std::int32_t bRedraw) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    static_cast<void>(hRgn);
    static_cast<void>(bRedraw);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint16_t kuser32G_SetWindowWord(void* hWnd, std::int32_t nIndex, std::uint16_t wNewWord) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    static_cast<void>(nIndex);
    static_cast<void>(wNewWord);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_SetWindowsHookA(std::int32_t nFilterType, void* pfnFilterProc) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(nFilterType);
    static_cast<void>(pfnFilterProc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_SetWindowsHookExA(std::int32_t idHook, void* lpfn, void* hmod, std::uint32_t dwThreadId) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(idHook);
    static_cast<void>(lpfn);
    static_cast<void>(hmod);
    static_cast<void>(dwThreadId);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_SetWindowsHookExW(std::int32_t idHook, void* lpfn, void* hmod, std::uint32_t dwThreadId) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(idHook);
    static_cast<void>(lpfn);
    static_cast<void>(hmod);
    static_cast<void>(dwThreadId);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_SetWindowsHookW(std::int32_t nFilterType, void* pfnFilterProc) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(nFilterType);
    static_cast<void>(pfnFilterProc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ShowCaret(void* hWnd) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ShowOwnedPopups(void* hWnd, std::int32_t fShow) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(fShow);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ShowScrollBar(void* hWnd, std::int32_t wBar, std::int32_t bShow) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWnd);
    static_cast<void>(wBar);
    static_cast<void>(bShow);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ShowWindowAsync(void* hWnd, std::int32_t nCmdShow) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hWnd);
    static_cast<void>(nCmdShow);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ShutdownBlockReasonCreate(void* hWnd, const char16_t* pwszReason) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(pwszReason);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ShutdownBlockReasonDestroy(void* hWnd) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ShutdownBlockReasonQuery(void* hWnd, char16_t* pwszBuff, std::uint32_t* pcchBuff) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(pwszBuff);
    static_cast<void>(pcchBuff);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SoundSentry() noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SubtractRect(void* lprcDst, const void* lprcSrc1, const void* lprcSrc2) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(lprcDst);
    static_cast<void>(lprcSrc1);
    static_cast<void>(lprcSrc2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SwapMouseButton(std::int32_t fSwap) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(fSwap);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_SwitchDesktop(std::uint64_t hDesktop) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hDesktop);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kuser32G_SwitchToThisWindow(void* hwnd, std::int32_t fUnknown) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hwnd);
    static_cast<void>(fUnknown);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint16_t kuser32G_TileWindows(void* hwndParent, std::uint32_t wHow, const void* lpRect, std::uint32_t cKids, const void* lpKids) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hwndParent);
    static_cast<void>(wHow);
    static_cast<void>(lpRect);
    static_cast<void>(cKids);
    static_cast<void>(lpKids);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ToAscii(std::uint32_t uVirtKey, std::uint32_t uScanCode, const std::uint8_t* lpKeyState, std::uint16_t* lpChar, std::uint32_t uFlags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(uVirtKey);
    static_cast<void>(uScanCode);
    static_cast<void>(lpKeyState);
    static_cast<void>(lpChar);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ToAsciiEx(std::uint32_t uVirtKey, std::uint32_t uScanCode, const std::uint8_t* lpKeyState, std::uint16_t* lpChar, std::uint32_t uFlags, void* dwhkl) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(uVirtKey);
    static_cast<void>(uScanCode);
    static_cast<void>(lpKeyState);
    static_cast<void>(lpChar);
    static_cast<void>(uFlags);
    static_cast<void>(dwhkl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ToUnicode(std::uint32_t wVirtKey, std::uint32_t wScanCode, const std::uint8_t* lpKeyState, char16_t* pwszBuff, std::int32_t cchBuff, std::uint32_t wFlags) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(wVirtKey);
    static_cast<void>(wScanCode);
    static_cast<void>(lpKeyState);
    static_cast<void>(pwszBuff);
    static_cast<void>(cchBuff);
    static_cast<void>(wFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ToUnicodeEx(std::uint32_t wVirtKey, std::uint32_t wScanCode, const std::uint8_t* lpKeyState, char16_t* pwszBuff, std::int32_t cchBuff, std::uint32_t wFlags, void* dwhkl) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(wVirtKey);
    static_cast<void>(wScanCode);
    static_cast<void>(lpKeyState);
    static_cast<void>(pwszBuff);
    static_cast<void>(cchBuff);
    static_cast<void>(wFlags);
    static_cast<void>(dwhkl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_TrackMouseEvent(void* lpEventTrack) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(lpEventTrack);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_TrackPopupMenu(void* hMenu, std::uint32_t uFlags, std::int32_t x, std::int32_t y, std::int32_t nReserved, void* hWnd, const void* prcRect) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(hMenu);
    static_cast<void>(uFlags);
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(nReserved);
    static_cast<void>(hWnd);
    static_cast<void>(prcRect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_TrackPopupMenuEx(void* arg0, std::uint32_t arg1, std::int32_t arg2, std::int32_t arg3, void* arg4, void* arg5) noexcept {
    // Refused: the window manager.
    //
    // menus are objects of a window manager, and there is none here
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    static_cast<void>(arg5);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_TranslateAcceleratorA(void* hWnd, void* hAccTable, void* lpMsg) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(hAccTable);
    static_cast<void>(lpMsg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_TranslateAcceleratorW(void* hWnd, void* hAccTable, void* lpMsg) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(hAccTable);
    static_cast<void>(lpMsg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_TranslateMDISysAccel(void* hWndClient, void* lpMsg) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWndClient);
    static_cast<void>(lpMsg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_UnhookWinEvent(std::uint64_t hWinEventHook) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hWinEventHook);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_UnhookWindowsHook(std::int32_t nCode, void* pfnFilterProc) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(nCode);
    static_cast<void>(pfnFilterProc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_UnhookWindowsHookEx(void* hhk) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hhk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_UnionRect(void* lprcDst, const void* lprcSrc1, const void* lprcSrc2) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(lprcDst);
    static_cast<void>(lprcSrc1);
    static_cast<void>(lprcSrc2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_UnloadKeyboardLayout(void* hkl) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hkl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_UnpackDDElParam(std::uint32_t msg, std::int64_t lParam, std::uint64_t* puiLo, std::uint64_t* puiHi) noexcept {
    // Refused: dynamic data exchange.
    //
    // DDE is a protocol of the window manager's message queue
    static_cast<void>(msg);
    static_cast<void>(lParam);
    static_cast<void>(puiLo);
    static_cast<void>(puiHi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_UnregisterDeviceNotification(std::uint64_t Handle) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(Handle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_UnregisterHotKey(void* hWnd, std::int32_t id) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(id);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_UnregisterPowerSettingNotification(std::uint64_t Handle) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(Handle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_UnregisterSuspendResumeNotification(std::uint64_t Handle) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(Handle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_UserHandleGrantAccess(void* hUserHandle, void* hJob, std::int32_t bGrant) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hUserHandle);
    static_cast<void>(hJob);
    static_cast<void>(bGrant);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ValidateRect(void* hWnd, const void* lpRect) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(lpRect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_ValidateRgn(void* hWnd, std::uint64_t hRgn) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWnd);
    static_cast<void>(hRgn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int16_t kuser32G_VkKeyScanA(char ch) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(ch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int16_t kuser32G_VkKeyScanExA(char ch, void* dwhkl) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(ch);
    static_cast<void>(dwhkl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int16_t kuser32G_VkKeyScanExW(char16_t ch, void* dwhkl) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(ch);
    static_cast<void>(dwhkl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int16_t kuser32G_VkKeyScanW(char16_t ch) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(ch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuser32G_WaitForInputIdle(void* hProcess, std::uint32_t dwMilliseconds) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display to describe
    static_cast<void>(hProcess);
    static_cast<void>(dwMilliseconds);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_WinHelpA(void* hWndMain, const char* lpszHelp, std::uint32_t uCommand, std::uint64_t dwData) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWndMain);
    static_cast<void>(lpszHelp);
    static_cast<void>(uCommand);
    static_cast<void>(dwData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_WinHelpW(void* hWndMain, const char16_t* lpszHelp, std::uint32_t uCommand, std::uint64_t dwData) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(hWndMain);
    static_cast<void>(lpszHelp);
    static_cast<void>(uCommand);
    static_cast<void>(dwData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_WindowFromDC(void* hDC) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(hDC);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuser32G_WindowFromPoint(std::uint64_t Point) noexcept {
    // Refused: the window manager.
    //
    // no window is ever created in this process, so there is no window to
    // name, no message queue to post to and no window procedure to call
    static_cast<void>(Point);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kuser32G_keybd_event(std::uint8_t bVk, std::uint8_t bScan, std::uint32_t dwFlags, std::uint64_t dwExtraInfo) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(bVk);
    static_cast<void>(bScan);
    static_cast<void>(dwFlags);
    static_cast<void>(dwExtraInfo);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kuser32G_mouse_event(std::uint32_t dwFlags, std::uint32_t dx, std::uint32_t dy, std::uint32_t dwData, std::uint64_t dwExtraInfo) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(dwFlags);
    static_cast<void>(dx);
    static_cast<void>(dy);
    static_cast<void>(dwData);
    static_cast<void>(dwExtraInfo);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_wvsprintfA(char* arg0, const char* arg1, void* arglist) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arglist);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuser32G_wvsprintfW(char16_t* arg0, const char16_t* arg1, void* arglist) noexcept {
    // Refused: the window manager.
    //
    // this runtime presents no desktop: there is no window station, no input
    // queue and no display
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arglist);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_user32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("ActivateKeyboardLayout", reinterpret_cast<void*>(&kuser32G_ActivateKeyboardLayout));
    e("AdjustWindowRect", reinterpret_cast<void*>(&kuser32G_AdjustWindowRect));
    e("AdjustWindowRectEx", reinterpret_cast<void*>(&kuser32G_AdjustWindowRectEx));
    e("AllowSetForegroundWindow", reinterpret_cast<void*>(&kuser32G_AllowSetForegroundWindow));
    e("AnimateWindow", reinterpret_cast<void*>(&kuser32G_AnimateWindow));
    e("AnyPopup", reinterpret_cast<void*>(&kuser32G_AnyPopup));
    e("ArrangeIconicWindows", reinterpret_cast<void*>(&kuser32G_ArrangeIconicWindows));
    e("AttachThreadInput", reinterpret_cast<void*>(&kuser32G_AttachThreadInput));
    e("BeginDeferWindowPos", reinterpret_cast<void*>(&kuser32G_BeginDeferWindowPos));
    e("BeginPaint", reinterpret_cast<void*>(&kuser32G_BeginPaint));
    e("BlockInput", reinterpret_cast<void*>(&kuser32G_BlockInput));
    e("BroadcastSystemMessageA", reinterpret_cast<void*>(&kuser32G_BroadcastSystemMessageA));
    e("BroadcastSystemMessageExA", reinterpret_cast<void*>(&kuser32G_BroadcastSystemMessageExA));
    e("BroadcastSystemMessageExW", reinterpret_cast<void*>(&kuser32G_BroadcastSystemMessageExW));
    e("BroadcastSystemMessageW", reinterpret_cast<void*>(&kuser32G_BroadcastSystemMessageW));
    e("CalculatePopupWindowPosition", reinterpret_cast<void*>(&kuser32G_CalculatePopupWindowPosition));
    e("CallMsgFilterA", reinterpret_cast<void*>(&kuser32G_CallMsgFilterA));
    e("CallMsgFilterW", reinterpret_cast<void*>(&kuser32G_CallMsgFilterW));
    e("CallNextHookEx", reinterpret_cast<void*>(&kuser32G_CallNextHookEx));
    e("CancelShutdown", reinterpret_cast<void*>(&kuser32G_CancelShutdown));
    e("CascadeWindows", reinterpret_cast<void*>(&kuser32G_CascadeWindows));
    e("ChangeClipboardChain", reinterpret_cast<void*>(&kuser32G_ChangeClipboardChain));
    e("ChangeMenuA", reinterpret_cast<void*>(&kuser32G_ChangeMenuA));
    e("ChangeMenuW", reinterpret_cast<void*>(&kuser32G_ChangeMenuW));
    e("CharLowerBuffA", reinterpret_cast<void*>(&kuser32G_CharLowerBuffA));
    e("CharLowerBuffW", reinterpret_cast<void*>(&kuser32G_CharLowerBuffW));
    e("CharNextA", reinterpret_cast<void*>(&kuser32G_CharNextA));
    e("CharNextExA", reinterpret_cast<void*>(&kuser32G_CharNextExA));
    e("CharNextW", reinterpret_cast<void*>(&kuser32G_CharNextW));
    e("CharPrevA", reinterpret_cast<void*>(&kuser32G_CharPrevA));
    e("CharPrevExA", reinterpret_cast<void*>(&kuser32G_CharPrevExA));
    e("CharPrevW", reinterpret_cast<void*>(&kuser32G_CharPrevW));
    e("CharToOemBuffA", reinterpret_cast<void*>(&kuser32G_CharToOemBuffA));
    e("CharToOemBuffW", reinterpret_cast<void*>(&kuser32G_CharToOemBuffW));
    e("CharUpperBuffA", reinterpret_cast<void*>(&kuser32G_CharUpperBuffA));
    e("CharUpperBuffW", reinterpret_cast<void*>(&kuser32G_CharUpperBuffW));
    e("CheckDlgButton", reinterpret_cast<void*>(&kuser32G_CheckDlgButton));
    e("CheckMenuItem", reinterpret_cast<void*>(&kuser32G_CheckMenuItem));
    e("CheckMenuRadioItem", reinterpret_cast<void*>(&kuser32G_CheckMenuRadioItem));
    e("CheckRadioButton", reinterpret_cast<void*>(&kuser32G_CheckRadioButton));
    e("ChildWindowFromPoint", reinterpret_cast<void*>(&kuser32G_ChildWindowFromPoint));
    e("ChildWindowFromPointEx", reinterpret_cast<void*>(&kuser32G_ChildWindowFromPointEx));
    e("ClientToScreen", reinterpret_cast<void*>(&kuser32G_ClientToScreen));
    e("ClipCursor", reinterpret_cast<void*>(&kuser32G_ClipCursor));
    e("CloseDesktop", reinterpret_cast<void*>(&kuser32G_CloseDesktop));
    e("CloseWindow", reinterpret_cast<void*>(&kuser32G_CloseWindow));
    e("CloseWindowStation", reinterpret_cast<void*>(&kuser32G_CloseWindowStation));
    e("CopyAcceleratorTableA", reinterpret_cast<void*>(&kuser32G_CopyAcceleratorTableA));
    e("CopyAcceleratorTableW", reinterpret_cast<void*>(&kuser32G_CopyAcceleratorTableW));
    e("CopyIcon", reinterpret_cast<void*>(&kuser32G_CopyIcon));
    e("CopyImage", reinterpret_cast<void*>(&kuser32G_CopyImage));
    e("CopyRect", reinterpret_cast<void*>(&kuser32G_CopyRect));
    e("CreateAcceleratorTableA", reinterpret_cast<void*>(&kuser32G_CreateAcceleratorTableA));
    e("CreateAcceleratorTableW", reinterpret_cast<void*>(&kuser32G_CreateAcceleratorTableW));
    e("CreateCaret", reinterpret_cast<void*>(&kuser32G_CreateCaret));
    e("CreateCursor", reinterpret_cast<void*>(&kuser32G_CreateCursor));
    e("CreateDialogIndirectParamA", reinterpret_cast<void*>(&kuser32G_CreateDialogIndirectParamA));
    e("CreateDialogIndirectParamW", reinterpret_cast<void*>(&kuser32G_CreateDialogIndirectParamW));
    e("CreateDialogParamA", reinterpret_cast<void*>(&kuser32G_CreateDialogParamA));
    e("CreateDialogParamW", reinterpret_cast<void*>(&kuser32G_CreateDialogParamW));
    e("CreateIcon", reinterpret_cast<void*>(&kuser32G_CreateIcon));
    e("CreateIconFromResource", reinterpret_cast<void*>(&kuser32G_CreateIconFromResource));
    e("CreateIconFromResourceEx", reinterpret_cast<void*>(&kuser32G_CreateIconFromResourceEx));
    e("CreateIconIndirect", reinterpret_cast<void*>(&kuser32G_CreateIconIndirect));
    e("CreateMDIWindowA", reinterpret_cast<void*>(&kuser32G_CreateMDIWindowA));
    e("CreateMDIWindowW", reinterpret_cast<void*>(&kuser32G_CreateMDIWindowW));
    e("CreateWindowStationA", reinterpret_cast<void*>(&kuser32G_CreateWindowStationA));
    e("CreateWindowStationW", reinterpret_cast<void*>(&kuser32G_CreateWindowStationW));
    e("DdeSetQualityOfService", reinterpret_cast<void*>(&kuser32G_DdeSetQualityOfService));
    e("DefDlgProcA", reinterpret_cast<void*>(&kuser32G_DefDlgProcA));
    e("DefDlgProcW", reinterpret_cast<void*>(&kuser32G_DefDlgProcW));
    e("DefFrameProcA", reinterpret_cast<void*>(&kuser32G_DefFrameProcA));
    e("DefFrameProcW", reinterpret_cast<void*>(&kuser32G_DefFrameProcW));
    e("DefMDIChildProcA", reinterpret_cast<void*>(&kuser32G_DefMDIChildProcA));
    e("DefMDIChildProcW", reinterpret_cast<void*>(&kuser32G_DefMDIChildProcW));
    e("DefRawInputProc", reinterpret_cast<void*>(&kuser32G_DefRawInputProc));
    e("DeferWindowPos", reinterpret_cast<void*>(&kuser32G_DeferWindowPos));
    e("DeleteMenu", reinterpret_cast<void*>(&kuser32G_DeleteMenu));
    e("DeregisterShellHookWindow", reinterpret_cast<void*>(&kuser32G_DeregisterShellHookWindow));
    e("DestroyAcceleratorTable", reinterpret_cast<void*>(&kuser32G_DestroyAcceleratorTable));
    e("DestroyCaret", reinterpret_cast<void*>(&kuser32G_DestroyCaret));
    e("DestroyCursor", reinterpret_cast<void*>(&kuser32G_DestroyCursor));
    e("DestroyIcon", reinterpret_cast<void*>(&kuser32G_DestroyIcon));
    e("DialogBoxIndirectParamA", reinterpret_cast<void*>(&kuser32G_DialogBoxIndirectParamA));
    e("DialogBoxIndirectParamW", reinterpret_cast<void*>(&kuser32G_DialogBoxIndirectParamW));
    e("DisableProcessWindowsGhosting", reinterpret_cast<void*>(&kuser32G_DisableProcessWindowsGhosting));
    e("DlgDirListA", reinterpret_cast<void*>(&kuser32G_DlgDirListA));
    e("DlgDirListComboBoxA", reinterpret_cast<void*>(&kuser32G_DlgDirListComboBoxA));
    e("DlgDirListComboBoxW", reinterpret_cast<void*>(&kuser32G_DlgDirListComboBoxW));
    e("DlgDirListW", reinterpret_cast<void*>(&kuser32G_DlgDirListW));
    e("DlgDirSelectComboBoxExA", reinterpret_cast<void*>(&kuser32G_DlgDirSelectComboBoxExA));
    e("DlgDirSelectComboBoxExW", reinterpret_cast<void*>(&kuser32G_DlgDirSelectComboBoxExW));
    e("DlgDirSelectExA", reinterpret_cast<void*>(&kuser32G_DlgDirSelectExA));
    e("DlgDirSelectExW", reinterpret_cast<void*>(&kuser32G_DlgDirSelectExW));
    e("DragDetect", reinterpret_cast<void*>(&kuser32G_DragDetect));
    e("DragObject", reinterpret_cast<void*>(&kuser32G_DragObject));
    e("DrawAnimatedRects", reinterpret_cast<void*>(&kuser32G_DrawAnimatedRects));
    e("DrawCaption", reinterpret_cast<void*>(&kuser32G_DrawCaption));
    e("DrawEdge", reinterpret_cast<void*>(&kuser32G_DrawEdge));
    e("DrawFocusRect", reinterpret_cast<void*>(&kuser32G_DrawFocusRect));
    e("DrawFrameControl", reinterpret_cast<void*>(&kuser32G_DrawFrameControl));
    e("DrawIcon", reinterpret_cast<void*>(&kuser32G_DrawIcon));
    e("DrawIconEx", reinterpret_cast<void*>(&kuser32G_DrawIconEx));
    e("DrawMenuBar", reinterpret_cast<void*>(&kuser32G_DrawMenuBar));
    e("DrawStateA", reinterpret_cast<void*>(&kuser32G_DrawStateA));
    e("DrawStateW", reinterpret_cast<void*>(&kuser32G_DrawStateW));
    e("EnableMenuItem", reinterpret_cast<void*>(&kuser32G_EnableMenuItem));
    e("EnableScrollBar", reinterpret_cast<void*>(&kuser32G_EnableScrollBar));
    e("EndDeferWindowPos", reinterpret_cast<void*>(&kuser32G_EndDeferWindowPos));
    e("EndMenu", reinterpret_cast<void*>(&kuser32G_EndMenu));
    e("EndPaint", reinterpret_cast<void*>(&kuser32G_EndPaint));
    e("EndTask", reinterpret_cast<void*>(&kuser32G_EndTask));
    e("EnumClipboardFormats", reinterpret_cast<void*>(&kuser32G_EnumClipboardFormats));
    e("EnumDesktopWindows", reinterpret_cast<void*>(&kuser32G_EnumDesktopWindows));
    e("EnumDesktopsA", reinterpret_cast<void*>(&kuser32G_EnumDesktopsA));
    e("EnumDesktopsW", reinterpret_cast<void*>(&kuser32G_EnumDesktopsW));
    e("EnumDisplayMonitors", reinterpret_cast<void*>(&kuser32G_EnumDisplayMonitors));
    e("EnumPropsA", reinterpret_cast<void*>(&kuser32G_EnumPropsA));
    e("EnumPropsExA", reinterpret_cast<void*>(&kuser32G_EnumPropsExA));
    e("EnumPropsExW", reinterpret_cast<void*>(&kuser32G_EnumPropsExW));
    e("EnumPropsW", reinterpret_cast<void*>(&kuser32G_EnumPropsW));
    e("EnumWindowStationsA", reinterpret_cast<void*>(&kuser32G_EnumWindowStationsA));
    e("EnumWindowStationsW", reinterpret_cast<void*>(&kuser32G_EnumWindowStationsW));
    e("EqualRect", reinterpret_cast<void*>(&kuser32G_EqualRect));
    e("ExcludeUpdateRgn", reinterpret_cast<void*>(&kuser32G_ExcludeUpdateRgn));
    e("ExitWindowsEx", reinterpret_cast<void*>(&kuser32G_ExitWindowsEx));
    e("FlashWindow", reinterpret_cast<void*>(&kuser32G_FlashWindow));
    e("FlashWindowEx", reinterpret_cast<void*>(&kuser32G_FlashWindowEx));
    e("FreeDDElParam", reinterpret_cast<void*>(&kuser32G_FreeDDElParam));
    e("GetAltTabInfoA", reinterpret_cast<void*>(&kuser32G_GetAltTabInfoA));
    e("GetAltTabInfoW", reinterpret_cast<void*>(&kuser32G_GetAltTabInfoW));
    e("GetAncestor", reinterpret_cast<void*>(&kuser32G_GetAncestor));
    e("GetCaretBlinkTime", reinterpret_cast<void*>(&kuser32G_GetCaretBlinkTime));
    e("GetCaretPos", reinterpret_cast<void*>(&kuser32G_GetCaretPos));
    e("GetClassInfoA", reinterpret_cast<void*>(&kuser32G_GetClassInfoA));
    e("GetClassInfoExA", reinterpret_cast<void*>(&kuser32G_GetClassInfoExA));
    e("GetClassInfoExW", reinterpret_cast<void*>(&kuser32G_GetClassInfoExW));
    e("GetClassInfoW", reinterpret_cast<void*>(&kuser32G_GetClassInfoW));
    e("GetClassLongA", reinterpret_cast<void*>(&kuser32G_GetClassLongA));
    e("GetClassLongPtrA", reinterpret_cast<void*>(&kuser32G_GetClassLongPtrA));
    e("GetClassLongPtrW", reinterpret_cast<void*>(&kuser32G_GetClassLongPtrW));
    e("GetClassLongW", reinterpret_cast<void*>(&kuser32G_GetClassLongW));
    e("GetClassWord", reinterpret_cast<void*>(&kuser32G_GetClassWord));
    e("GetClipCursor", reinterpret_cast<void*>(&kuser32G_GetClipCursor));
    e("GetClipboardFormatNameA", reinterpret_cast<void*>(&kuser32G_GetClipboardFormatNameA));
    e("GetClipboardFormatNameW", reinterpret_cast<void*>(&kuser32G_GetClipboardFormatNameW));
    e("GetClipboardOwner", reinterpret_cast<void*>(&kuser32G_GetClipboardOwner));
    e("GetClipboardViewer", reinterpret_cast<void*>(&kuser32G_GetClipboardViewer));
    e("GetComboBoxInfo", reinterpret_cast<void*>(&kuser32G_GetComboBoxInfo));
    e("GetCursor", reinterpret_cast<void*>(&kuser32G_GetCursor));
    e("GetCursorInfo", reinterpret_cast<void*>(&kuser32G_GetCursorInfo));
    e("GetDialogBaseUnits", reinterpret_cast<void*>(&kuser32G_GetDialogBaseUnits));
    e("GetDlgItemInt", reinterpret_cast<void*>(&kuser32G_GetDlgItemInt));
    e("GetGUIThreadInfo", reinterpret_cast<void*>(&kuser32G_GetGUIThreadInfo));
    e("GetIconInfo", reinterpret_cast<void*>(&kuser32G_GetIconInfo));
    e("GetIconInfoExA", reinterpret_cast<void*>(&kuser32G_GetIconInfoExA));
    e("GetIconInfoExW", reinterpret_cast<void*>(&kuser32G_GetIconInfoExW));
    e("GetInputState", reinterpret_cast<void*>(&kuser32G_GetInputState));
    e("GetKBCodePage", reinterpret_cast<void*>(&kuser32G_GetKBCodePage));
    e("GetKeyNameTextA", reinterpret_cast<void*>(&kuser32G_GetKeyNameTextA));
    e("GetKeyNameTextW", reinterpret_cast<void*>(&kuser32G_GetKeyNameTextW));
    e("GetKeyboardLayoutNameA", reinterpret_cast<void*>(&kuser32G_GetKeyboardLayoutNameA));
    e("GetKeyboardLayoutNameW", reinterpret_cast<void*>(&kuser32G_GetKeyboardLayoutNameW));
    e("GetLastActivePopup", reinterpret_cast<void*>(&kuser32G_GetLastActivePopup));
    e("GetLastInputInfo", reinterpret_cast<void*>(&kuser32G_GetLastInputInfo));
    e("GetLayeredWindowAttributes", reinterpret_cast<void*>(&kuser32G_GetLayeredWindowAttributes));
    e("GetListBoxInfo", reinterpret_cast<void*>(&kuser32G_GetListBoxInfo));
    e("GetMenuBarInfo", reinterpret_cast<void*>(&kuser32G_GetMenuBarInfo));
    e("GetMenuCheckMarkDimensions", reinterpret_cast<void*>(&kuser32G_GetMenuCheckMarkDimensions));
    e("GetMenuContextHelpId", reinterpret_cast<void*>(&kuser32G_GetMenuContextHelpId));
    e("GetMenuDefaultItem", reinterpret_cast<void*>(&kuser32G_GetMenuDefaultItem));
    e("GetMenuInfo", reinterpret_cast<void*>(&kuser32G_GetMenuInfo));
    e("GetMenuItemInfoA", reinterpret_cast<void*>(&kuser32G_GetMenuItemInfoA));
    e("GetMenuItemInfoW", reinterpret_cast<void*>(&kuser32G_GetMenuItemInfoW));
    e("GetMenuItemRect", reinterpret_cast<void*>(&kuser32G_GetMenuItemRect));
    e("GetMenuState", reinterpret_cast<void*>(&kuser32G_GetMenuState));
    e("GetMenuStringA", reinterpret_cast<void*>(&kuser32G_GetMenuStringA));
    e("GetMenuStringW", reinterpret_cast<void*>(&kuser32G_GetMenuStringW));
    e("GetMessageExtraInfo", reinterpret_cast<void*>(&kuser32G_GetMessageExtraInfo));
    e("GetMessagePos", reinterpret_cast<void*>(&kuser32G_GetMessagePos));
    e("GetMessageTime", reinterpret_cast<void*>(&kuser32G_GetMessageTime));
    e("GetMonitorInfoA", reinterpret_cast<void*>(&kuser32G_GetMonitorInfoA));
    e("GetMonitorInfoW", reinterpret_cast<void*>(&kuser32G_GetMonitorInfoW));
    e("GetMouseMovePointsEx", reinterpret_cast<void*>(&kuser32G_GetMouseMovePointsEx));
    e("GetNextDlgGroupItem", reinterpret_cast<void*>(&kuser32G_GetNextDlgGroupItem));
    e("GetNextDlgTabItem", reinterpret_cast<void*>(&kuser32G_GetNextDlgTabItem));
    e("GetOpenClipboardWindow", reinterpret_cast<void*>(&kuser32G_GetOpenClipboardWindow));
    e("GetPointerInputTransform", reinterpret_cast<void*>(&kuser32G_GetPointerInputTransform));
    e("GetPriorityClipboardFormat", reinterpret_cast<void*>(&kuser32G_GetPriorityClipboardFormat));
    e("GetProcessDefaultLayout", reinterpret_cast<void*>(&kuser32G_GetProcessDefaultLayout));
    e("GetPropA", reinterpret_cast<void*>(&kuser32G_GetPropA));
    e("GetPropW", reinterpret_cast<void*>(&kuser32G_GetPropW));
    e("GetQueueStatus", reinterpret_cast<void*>(&kuser32G_GetQueueStatus));
    e("GetRawInputBuffer", reinterpret_cast<void*>(&kuser32G_GetRawInputBuffer));
    e("GetRawInputData", reinterpret_cast<void*>(&kuser32G_GetRawInputData));
    e("GetRawInputDeviceInfoA", reinterpret_cast<void*>(&kuser32G_GetRawInputDeviceInfoA));
    e("GetRawInputDeviceInfoW", reinterpret_cast<void*>(&kuser32G_GetRawInputDeviceInfoW));
    e("GetRawInputDeviceList", reinterpret_cast<void*>(&kuser32G_GetRawInputDeviceList));
    e("GetRegisteredRawInputDevices", reinterpret_cast<void*>(&kuser32G_GetRegisteredRawInputDevices));
    e("GetScrollBarInfo", reinterpret_cast<void*>(&kuser32G_GetScrollBarInfo));
    e("GetScrollInfo", reinterpret_cast<void*>(&kuser32G_GetScrollInfo));
    e("GetScrollPos", reinterpret_cast<void*>(&kuser32G_GetScrollPos));
    e("GetScrollRange", reinterpret_cast<void*>(&kuser32G_GetScrollRange));
    e("GetShellWindow", reinterpret_cast<void*>(&kuser32G_GetShellWindow));
    e("GetSubMenu", reinterpret_cast<void*>(&kuser32G_GetSubMenu));
    e("GetSysColor", reinterpret_cast<void*>(&kuser32G_GetSysColor));
    e("GetSysColorBrush", reinterpret_cast<void*>(&kuser32G_GetSysColorBrush));
    e("GetSystemMenu", reinterpret_cast<void*>(&kuser32G_GetSystemMenu));
    e("GetTabbedTextExtentA", reinterpret_cast<void*>(&kuser32G_GetTabbedTextExtentA));
    e("GetTabbedTextExtentW", reinterpret_cast<void*>(&kuser32G_GetTabbedTextExtentW));
    e("GetThreadDesktop", reinterpret_cast<void*>(&kuser32G_GetThreadDesktop));
    e("GetTitleBarInfo", reinterpret_cast<void*>(&kuser32G_GetTitleBarInfo));
    e("GetUnpredictedMessagePos", reinterpret_cast<void*>(&kuser32G_GetUnpredictedMessagePos));
    e("GetUpdateRect", reinterpret_cast<void*>(&kuser32G_GetUpdateRect));
    e("GetUpdateRgn", reinterpret_cast<void*>(&kuser32G_GetUpdateRgn));
    e("GetUserObjectInformationA", reinterpret_cast<void*>(&kuser32G_GetUserObjectInformationA));
    e("GetUserObjectInformationW", reinterpret_cast<void*>(&kuser32G_GetUserObjectInformationW));
    e("GetUserObjectSecurity", reinterpret_cast<void*>(&kuser32G_GetUserObjectSecurity));
    e("GetWindowContextHelpId", reinterpret_cast<void*>(&kuser32G_GetWindowContextHelpId));
    e("GetWindowDisplayAffinity", reinterpret_cast<void*>(&kuser32G_GetWindowDisplayAffinity));
    e("GetWindowInfo", reinterpret_cast<void*>(&kuser32G_GetWindowInfo));
    e("GetWindowModuleFileNameA", reinterpret_cast<void*>(&kuser32G_GetWindowModuleFileNameA));
    e("GetWindowModuleFileNameW", reinterpret_cast<void*>(&kuser32G_GetWindowModuleFileNameW));
    e("GetWindowPlacement", reinterpret_cast<void*>(&kuser32G_GetWindowPlacement));
    e("GetWindowRgn", reinterpret_cast<void*>(&kuser32G_GetWindowRgn));
    e("GetWindowRgnBox", reinterpret_cast<void*>(&kuser32G_GetWindowRgnBox));
    e("GetWindowWord", reinterpret_cast<void*>(&kuser32G_GetWindowWord));
    e("GrayStringA", reinterpret_cast<void*>(&kuser32G_GrayStringA));
    e("GrayStringW", reinterpret_cast<void*>(&kuser32G_GrayStringW));
    e("HideCaret", reinterpret_cast<void*>(&kuser32G_HideCaret));
    e("HiliteMenuItem", reinterpret_cast<void*>(&kuser32G_HiliteMenuItem));
    e("ImpersonateDdeClientWindow", reinterpret_cast<void*>(&kuser32G_ImpersonateDdeClientWindow));
    e("InSendMessage", reinterpret_cast<void*>(&kuser32G_InSendMessage));
    e("InSendMessageEx", reinterpret_cast<void*>(&kuser32G_InSendMessageEx));
    e("InflateRect", reinterpret_cast<void*>(&kuser32G_InflateRect));
    e("InsertMenuA", reinterpret_cast<void*>(&kuser32G_InsertMenuA));
    e("InsertMenuItemA", reinterpret_cast<void*>(&kuser32G_InsertMenuItemA));
    e("InsertMenuItemW", reinterpret_cast<void*>(&kuser32G_InsertMenuItemW));
    e("InsertMenuW", reinterpret_cast<void*>(&kuser32G_InsertMenuW));
    e("InternalGetWindowText", reinterpret_cast<void*>(&kuser32G_InternalGetWindowText));
    e("IntersectRect", reinterpret_cast<void*>(&kuser32G_IntersectRect));
    e("InvalidateRgn", reinterpret_cast<void*>(&kuser32G_InvalidateRgn));
    e("IsCharAlphaA", reinterpret_cast<void*>(&kuser32G_IsCharAlphaA));
    e("IsCharAlphaNumericA", reinterpret_cast<void*>(&kuser32G_IsCharAlphaNumericA));
    e("IsCharAlphaNumericW", reinterpret_cast<void*>(&kuser32G_IsCharAlphaNumericW));
    e("IsCharAlphaW", reinterpret_cast<void*>(&kuser32G_IsCharAlphaW));
    e("IsCharLowerA", reinterpret_cast<void*>(&kuser32G_IsCharLowerA));
    e("IsCharLowerW", reinterpret_cast<void*>(&kuser32G_IsCharLowerW));
    e("IsCharUpperA", reinterpret_cast<void*>(&kuser32G_IsCharUpperA));
    e("IsCharUpperW", reinterpret_cast<void*>(&kuser32G_IsCharUpperW));
    e("IsDialogMessageA", reinterpret_cast<void*>(&kuser32G_IsDialogMessageA));
    e("IsDialogMessageW", reinterpret_cast<void*>(&kuser32G_IsDialogMessageW));
    e("IsDlgButtonChecked", reinterpret_cast<void*>(&kuser32G_IsDlgButtonChecked));
    e("IsGUIThread", reinterpret_cast<void*>(&kuser32G_IsGUIThread));
    e("IsHungAppWindow", reinterpret_cast<void*>(&kuser32G_IsHungAppWindow));
    e("IsMenu", reinterpret_cast<void*>(&kuser32G_IsMenu));
    e("IsProcessDPIAware", reinterpret_cast<void*>(&kuser32G_IsProcessDPIAware));
    e("IsRectEmpty", reinterpret_cast<void*>(&kuser32G_IsRectEmpty));
    e("IsWinEventHookInstalled", reinterpret_cast<void*>(&kuser32G_IsWinEventHookInstalled));
    e("IsWindowUnicode", reinterpret_cast<void*>(&kuser32G_IsWindowUnicode));
    e("IsWow64Message", reinterpret_cast<void*>(&kuser32G_IsWow64Message));
    e("LoadAcceleratorsA", reinterpret_cast<void*>(&kuser32G_LoadAcceleratorsA));
    e("LoadAcceleratorsW", reinterpret_cast<void*>(&kuser32G_LoadAcceleratorsW));
    e("LoadBitmapA", reinterpret_cast<void*>(&kuser32G_LoadBitmapA));
    e("LoadBitmapW", reinterpret_cast<void*>(&kuser32G_LoadBitmapW));
    e("LoadCursorFromFileA", reinterpret_cast<void*>(&kuser32G_LoadCursorFromFileA));
    e("LoadCursorFromFileW", reinterpret_cast<void*>(&kuser32G_LoadCursorFromFileW));
    e("LoadImageA", reinterpret_cast<void*>(&kuser32G_LoadImageA));
    e("LoadImageW", reinterpret_cast<void*>(&kuser32G_LoadImageW));
    e("LoadKeyboardLayoutA", reinterpret_cast<void*>(&kuser32G_LoadKeyboardLayoutA));
    e("LoadKeyboardLayoutW", reinterpret_cast<void*>(&kuser32G_LoadKeyboardLayoutW));
    e("LoadMenuA", reinterpret_cast<void*>(&kuser32G_LoadMenuA));
    e("LoadMenuIndirectA", reinterpret_cast<void*>(&kuser32G_LoadMenuIndirectA));
    e("LoadMenuIndirectW", reinterpret_cast<void*>(&kuser32G_LoadMenuIndirectW));
    e("LoadMenuW", reinterpret_cast<void*>(&kuser32G_LoadMenuW));
    e("LoadStringA", reinterpret_cast<void*>(&kuser32G_LoadStringA));
    e("LoadStringW", reinterpret_cast<void*>(&kuser32G_LoadStringW));
    e("LockSetForegroundWindow", reinterpret_cast<void*>(&kuser32G_LockSetForegroundWindow));
    e("LockWindowUpdate", reinterpret_cast<void*>(&kuser32G_LockWindowUpdate));
    e("LockWorkStation", reinterpret_cast<void*>(&kuser32G_LockWorkStation));
    e("LookupIconIdFromDirectory", reinterpret_cast<void*>(&kuser32G_LookupIconIdFromDirectory));
    e("LookupIconIdFromDirectoryEx", reinterpret_cast<void*>(&kuser32G_LookupIconIdFromDirectoryEx));
    e("MapDialogRect", reinterpret_cast<void*>(&kuser32G_MapDialogRect));
    e("MapVirtualKeyExA", reinterpret_cast<void*>(&kuser32G_MapVirtualKeyExA));
    e("MapVirtualKeyExW", reinterpret_cast<void*>(&kuser32G_MapVirtualKeyExW));
    e("MapWindowPoints", reinterpret_cast<void*>(&kuser32G_MapWindowPoints));
    e("MenuItemFromPoint", reinterpret_cast<void*>(&kuser32G_MenuItemFromPoint));
    e("MessageBoxIndirectA", reinterpret_cast<void*>(&kuser32G_MessageBoxIndirectA));
    e("MessageBoxIndirectW", reinterpret_cast<void*>(&kuser32G_MessageBoxIndirectW));
    e("ModifyMenuA", reinterpret_cast<void*>(&kuser32G_ModifyMenuA));
    e("ModifyMenuW", reinterpret_cast<void*>(&kuser32G_ModifyMenuW));
    e("MonitorFromPoint", reinterpret_cast<void*>(&kuser32G_MonitorFromPoint));
    e("MonitorFromRect", reinterpret_cast<void*>(&kuser32G_MonitorFromRect));
    e("MonitorFromWindow", reinterpret_cast<void*>(&kuser32G_MonitorFromWindow));
    e("MsgWaitForMultipleObjects", reinterpret_cast<void*>(&kuser32G_MsgWaitForMultipleObjects));
    e("MsgWaitForMultipleObjectsEx", reinterpret_cast<void*>(&kuser32G_MsgWaitForMultipleObjectsEx));
    e("NotifyWinEvent", reinterpret_cast<void*>(&kuser32G_NotifyWinEvent));
    e("OemKeyScan", reinterpret_cast<void*>(&kuser32G_OemKeyScan));
    e("OemToCharBuffA", reinterpret_cast<void*>(&kuser32G_OemToCharBuffA));
    e("OemToCharBuffW", reinterpret_cast<void*>(&kuser32G_OemToCharBuffW));
    e("OffsetRect", reinterpret_cast<void*>(&kuser32G_OffsetRect));
    e("OpenDesktopA", reinterpret_cast<void*>(&kuser32G_OpenDesktopA));
    e("OpenDesktopW", reinterpret_cast<void*>(&kuser32G_OpenDesktopW));
    e("OpenIcon", reinterpret_cast<void*>(&kuser32G_OpenIcon));
    e("OpenInputDesktop", reinterpret_cast<void*>(&kuser32G_OpenInputDesktop));
    e("OpenWindowStationA", reinterpret_cast<void*>(&kuser32G_OpenWindowStationA));
    e("OpenWindowStationW", reinterpret_cast<void*>(&kuser32G_OpenWindowStationW));
    e("PackDDElParam", reinterpret_cast<void*>(&kuser32G_PackDDElParam));
    e("PaintDesktop", reinterpret_cast<void*>(&kuser32G_PaintDesktop));
    e("PostThreadMessageA", reinterpret_cast<void*>(&kuser32G_PostThreadMessageA));
    e("PrintWindow", reinterpret_cast<void*>(&kuser32G_PrintWindow));
    e("PrivateExtractIconsA", reinterpret_cast<void*>(&kuser32G_PrivateExtractIconsA));
    e("PrivateExtractIconsW", reinterpret_cast<void*>(&kuser32G_PrivateExtractIconsW));
    e("PtInRect", reinterpret_cast<void*>(&kuser32G_PtInRect));
    e("RealChildWindowFromPoint", reinterpret_cast<void*>(&kuser32G_RealChildWindowFromPoint));
    e("RealGetWindowClassA", reinterpret_cast<void*>(&kuser32G_RealGetWindowClassA));
    e("RealGetWindowClassW", reinterpret_cast<void*>(&kuser32G_RealGetWindowClassW));
    e("RedrawWindow", reinterpret_cast<void*>(&kuser32G_RedrawWindow));
    e("RegisterDeviceNotificationA", reinterpret_cast<void*>(&kuser32G_RegisterDeviceNotificationA));
    e("RegisterDeviceNotificationW", reinterpret_cast<void*>(&kuser32G_RegisterDeviceNotificationW));
    e("RegisterHotKey", reinterpret_cast<void*>(&kuser32G_RegisterHotKey));
    e("RegisterPowerSettingNotification", reinterpret_cast<void*>(&kuser32G_RegisterPowerSettingNotification));
    e("RegisterRawInputDevices", reinterpret_cast<void*>(&kuser32G_RegisterRawInputDevices));
    e("RegisterShellHookWindow", reinterpret_cast<void*>(&kuser32G_RegisterShellHookWindow));
    e("RegisterSuspendResumeNotification", reinterpret_cast<void*>(&kuser32G_RegisterSuspendResumeNotification));
    e("RegisterWindowMessageA", reinterpret_cast<void*>(&kuser32G_RegisterWindowMessageA));
    e("RegisterWindowMessageW", reinterpret_cast<void*>(&kuser32G_RegisterWindowMessageW));
    e("RemoveMenu", reinterpret_cast<void*>(&kuser32G_RemoveMenu));
    e("RemovePropA", reinterpret_cast<void*>(&kuser32G_RemovePropA));
    e("RemovePropW", reinterpret_cast<void*>(&kuser32G_RemovePropW));
    e("ReplyMessage", reinterpret_cast<void*>(&kuser32G_ReplyMessage));
    e("ReuseDDElParam", reinterpret_cast<void*>(&kuser32G_ReuseDDElParam));
    e("ScreenToClient", reinterpret_cast<void*>(&kuser32G_ScreenToClient));
    e("ScrollDC", reinterpret_cast<void*>(&kuser32G_ScrollDC));
    e("ScrollWindow", reinterpret_cast<void*>(&kuser32G_ScrollWindow));
    e("ScrollWindowEx", reinterpret_cast<void*>(&kuser32G_ScrollWindowEx));
    e("SendDlgItemMessageA", reinterpret_cast<void*>(&kuser32G_SendDlgItemMessageA));
    e("SendDlgItemMessageW", reinterpret_cast<void*>(&kuser32G_SendDlgItemMessageW));
    e("SendInput", reinterpret_cast<void*>(&kuser32G_SendInput));
    e("SendMessageCallbackA", reinterpret_cast<void*>(&kuser32G_SendMessageCallbackA));
    e("SendMessageCallbackW", reinterpret_cast<void*>(&kuser32G_SendMessageCallbackW));
    e("SendMessageTimeoutA", reinterpret_cast<void*>(&kuser32G_SendMessageTimeoutA));
    e("SendMessageTimeoutW", reinterpret_cast<void*>(&kuser32G_SendMessageTimeoutW));
    e("SendNotifyMessageA", reinterpret_cast<void*>(&kuser32G_SendNotifyMessageA));
    e("SendNotifyMessageW", reinterpret_cast<void*>(&kuser32G_SendNotifyMessageW));
    e("SetCaretBlinkTime", reinterpret_cast<void*>(&kuser32G_SetCaretBlinkTime));
    e("SetCaretPos", reinterpret_cast<void*>(&kuser32G_SetCaretPos));
    e("SetClassLongA", reinterpret_cast<void*>(&kuser32G_SetClassLongA));
    e("SetClassLongPtrA", reinterpret_cast<void*>(&kuser32G_SetClassLongPtrA));
    e("SetClassLongPtrW", reinterpret_cast<void*>(&kuser32G_SetClassLongPtrW));
    e("SetClassLongW", reinterpret_cast<void*>(&kuser32G_SetClassLongW));
    e("SetClassWord", reinterpret_cast<void*>(&kuser32G_SetClassWord));
    e("SetClipboardViewer", reinterpret_cast<void*>(&kuser32G_SetClipboardViewer));
    e("SetCursor", reinterpret_cast<void*>(&kuser32G_SetCursor));
    e("SetDebugErrorLevel", reinterpret_cast<void*>(&kuser32G_SetDebugErrorLevel));
    e("SetDlgItemInt", reinterpret_cast<void*>(&kuser32G_SetDlgItemInt));
    e("SetDoubleClickTime", reinterpret_cast<void*>(&kuser32G_SetDoubleClickTime));
    e("SetLastErrorEx", reinterpret_cast<void*>(&kuser32G_SetLastErrorEx));
    e("SetLayeredWindowAttributes", reinterpret_cast<void*>(&kuser32G_SetLayeredWindowAttributes));
    e("SetMenuContextHelpId", reinterpret_cast<void*>(&kuser32G_SetMenuContextHelpId));
    e("SetMenuDefaultItem", reinterpret_cast<void*>(&kuser32G_SetMenuDefaultItem));
    e("SetMenuInfo", reinterpret_cast<void*>(&kuser32G_SetMenuInfo));
    e("SetMenuItemBitmaps", reinterpret_cast<void*>(&kuser32G_SetMenuItemBitmaps));
    e("SetMenuItemInfoA", reinterpret_cast<void*>(&kuser32G_SetMenuItemInfoA));
    e("SetMenuItemInfoW", reinterpret_cast<void*>(&kuser32G_SetMenuItemInfoW));
    e("SetMessageExtraInfo", reinterpret_cast<void*>(&kuser32G_SetMessageExtraInfo));
    e("SetMessageQueue", reinterpret_cast<void*>(&kuser32G_SetMessageQueue));
    e("SetProcessDPIAware", reinterpret_cast<void*>(&kuser32G_SetProcessDPIAware));
    e("SetProcessDefaultLayout", reinterpret_cast<void*>(&kuser32G_SetProcessDefaultLayout));
    e("SetProcessWindowStation", reinterpret_cast<void*>(&kuser32G_SetProcessWindowStation));
    e("SetPropA", reinterpret_cast<void*>(&kuser32G_SetPropA));
    e("SetPropW", reinterpret_cast<void*>(&kuser32G_SetPropW));
    e("SetRect", reinterpret_cast<void*>(&kuser32G_SetRect));
    e("SetRectEmpty", reinterpret_cast<void*>(&kuser32G_SetRectEmpty));
    e("SetScrollInfo", reinterpret_cast<void*>(&kuser32G_SetScrollInfo));
    e("SetScrollPos", reinterpret_cast<void*>(&kuser32G_SetScrollPos));
    e("SetScrollRange", reinterpret_cast<void*>(&kuser32G_SetScrollRange));
    e("SetSysColors", reinterpret_cast<void*>(&kuser32G_SetSysColors));
    e("SetSystemCursor", reinterpret_cast<void*>(&kuser32G_SetSystemCursor));
    e("SetThreadDesktop", reinterpret_cast<void*>(&kuser32G_SetThreadDesktop));
    e("SetUserObjectInformationA", reinterpret_cast<void*>(&kuser32G_SetUserObjectInformationA));
    e("SetUserObjectInformationW", reinterpret_cast<void*>(&kuser32G_SetUserObjectInformationW));
    e("SetUserObjectSecurity", reinterpret_cast<void*>(&kuser32G_SetUserObjectSecurity));
    e("SetWinEventHook", reinterpret_cast<void*>(&kuser32G_SetWinEventHook));
    e("SetWindowContextHelpId", reinterpret_cast<void*>(&kuser32G_SetWindowContextHelpId));
    e("SetWindowDisplayAffinity", reinterpret_cast<void*>(&kuser32G_SetWindowDisplayAffinity));
    e("SetWindowPlacement", reinterpret_cast<void*>(&kuser32G_SetWindowPlacement));
    e("SetWindowRgn", reinterpret_cast<void*>(&kuser32G_SetWindowRgn));
    e("SetWindowWord", reinterpret_cast<void*>(&kuser32G_SetWindowWord));
    e("SetWindowsHookA", reinterpret_cast<void*>(&kuser32G_SetWindowsHookA));
    e("SetWindowsHookExA", reinterpret_cast<void*>(&kuser32G_SetWindowsHookExA));
    e("SetWindowsHookExW", reinterpret_cast<void*>(&kuser32G_SetWindowsHookExW));
    e("SetWindowsHookW", reinterpret_cast<void*>(&kuser32G_SetWindowsHookW));
    e("ShowCaret", reinterpret_cast<void*>(&kuser32G_ShowCaret));
    e("ShowOwnedPopups", reinterpret_cast<void*>(&kuser32G_ShowOwnedPopups));
    e("ShowScrollBar", reinterpret_cast<void*>(&kuser32G_ShowScrollBar));
    e("ShowWindowAsync", reinterpret_cast<void*>(&kuser32G_ShowWindowAsync));
    e("ShutdownBlockReasonCreate", reinterpret_cast<void*>(&kuser32G_ShutdownBlockReasonCreate));
    e("ShutdownBlockReasonDestroy", reinterpret_cast<void*>(&kuser32G_ShutdownBlockReasonDestroy));
    e("ShutdownBlockReasonQuery", reinterpret_cast<void*>(&kuser32G_ShutdownBlockReasonQuery));
    e("SoundSentry", reinterpret_cast<void*>(&kuser32G_SoundSentry));
    e("SubtractRect", reinterpret_cast<void*>(&kuser32G_SubtractRect));
    e("SwapMouseButton", reinterpret_cast<void*>(&kuser32G_SwapMouseButton));
    e("SwitchDesktop", reinterpret_cast<void*>(&kuser32G_SwitchDesktop));
    e("SwitchToThisWindow", reinterpret_cast<void*>(&kuser32G_SwitchToThisWindow));
    e("TileWindows", reinterpret_cast<void*>(&kuser32G_TileWindows));
    e("ToAscii", reinterpret_cast<void*>(&kuser32G_ToAscii));
    e("ToAsciiEx", reinterpret_cast<void*>(&kuser32G_ToAsciiEx));
    e("ToUnicode", reinterpret_cast<void*>(&kuser32G_ToUnicode));
    e("ToUnicodeEx", reinterpret_cast<void*>(&kuser32G_ToUnicodeEx));
    e("TrackMouseEvent", reinterpret_cast<void*>(&kuser32G_TrackMouseEvent));
    e("TrackPopupMenu", reinterpret_cast<void*>(&kuser32G_TrackPopupMenu));
    e("TrackPopupMenuEx", reinterpret_cast<void*>(&kuser32G_TrackPopupMenuEx));
    e("TranslateAcceleratorA", reinterpret_cast<void*>(&kuser32G_TranslateAcceleratorA));
    e("TranslateAcceleratorW", reinterpret_cast<void*>(&kuser32G_TranslateAcceleratorW));
    e("TranslateMDISysAccel", reinterpret_cast<void*>(&kuser32G_TranslateMDISysAccel));
    e("UnhookWinEvent", reinterpret_cast<void*>(&kuser32G_UnhookWinEvent));
    e("UnhookWindowsHook", reinterpret_cast<void*>(&kuser32G_UnhookWindowsHook));
    e("UnhookWindowsHookEx", reinterpret_cast<void*>(&kuser32G_UnhookWindowsHookEx));
    e("UnionRect", reinterpret_cast<void*>(&kuser32G_UnionRect));
    e("UnloadKeyboardLayout", reinterpret_cast<void*>(&kuser32G_UnloadKeyboardLayout));
    e("UnpackDDElParam", reinterpret_cast<void*>(&kuser32G_UnpackDDElParam));
    e("UnregisterDeviceNotification", reinterpret_cast<void*>(&kuser32G_UnregisterDeviceNotification));
    e("UnregisterHotKey", reinterpret_cast<void*>(&kuser32G_UnregisterHotKey));
    e("UnregisterPowerSettingNotification", reinterpret_cast<void*>(&kuser32G_UnregisterPowerSettingNotification));
    e("UnregisterSuspendResumeNotification", reinterpret_cast<void*>(&kuser32G_UnregisterSuspendResumeNotification));
    e("UserHandleGrantAccess", reinterpret_cast<void*>(&kuser32G_UserHandleGrantAccess));
    e("ValidateRect", reinterpret_cast<void*>(&kuser32G_ValidateRect));
    e("ValidateRgn", reinterpret_cast<void*>(&kuser32G_ValidateRgn));
    e("VkKeyScanA", reinterpret_cast<void*>(&kuser32G_VkKeyScanA));
    e("VkKeyScanExA", reinterpret_cast<void*>(&kuser32G_VkKeyScanExA));
    e("VkKeyScanExW", reinterpret_cast<void*>(&kuser32G_VkKeyScanExW));
    e("VkKeyScanW", reinterpret_cast<void*>(&kuser32G_VkKeyScanW));
    e("WaitForInputIdle", reinterpret_cast<void*>(&kuser32G_WaitForInputIdle));
    e("WinHelpA", reinterpret_cast<void*>(&kuser32G_WinHelpA));
    e("WinHelpW", reinterpret_cast<void*>(&kuser32G_WinHelpW));
    e("WindowFromDC", reinterpret_cast<void*>(&kuser32G_WindowFromDC));
    e("WindowFromPoint", reinterpret_cast<void*>(&kuser32G_WindowFromPoint));
    e("keybd_event", reinterpret_cast<void*>(&kuser32G_keybd_event));
    e("mouse_event", reinterpret_cast<void*>(&kuser32G_mouse_event));
    e("wvsprintfA", reinterpret_cast<void*>(&kuser32G_wvsprintfA));
    e("wvsprintfW", reinterpret_cast<void*>(&kuser32G_wvsprintfW));
}
}  // namespace occ::runtime::winabi

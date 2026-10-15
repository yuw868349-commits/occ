// The UXTHEME surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::uint64_t kuxthemeG_BeginBufferedAnimation(void* hwnd, void* hdcTarget, const void* rcTarget, std::uint64_t dwFormat, void* pPaintParams, void* pAnimationParams, void* phdcFrom, void* phdcTo) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hwnd);
    static_cast<void>(hdcTarget);
    static_cast<void>(rcTarget);
    static_cast<void>(dwFormat);
    static_cast<void>(pPaintParams);
    static_cast<void>(pAnimationParams);
    static_cast<void>(phdcFrom);
    static_cast<void>(phdcTo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kuxthemeG_BeginBufferedPaint(void* hdcTarget, const void* prcTarget, std::uint64_t dwFormat, void* pPaintParams, void* phdc) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hdcTarget);
    static_cast<void>(prcTarget);
    static_cast<void>(dwFormat);
    static_cast<void>(pPaintParams);
    static_cast<void>(phdc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_BeginPanningFeedback(void* hwnd) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hwnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_BufferedPaintClear(std::uint64_t hBufferedPaint, const void* prc) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hBufferedPaint);
    static_cast<void>(prc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_BufferedPaintInit() noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_BufferedPaintRenderAnimation(void* hwnd, void* hdcTarget) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hwnd);
    static_cast<void>(hdcTarget);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_BufferedPaintSetAlpha(std::uint64_t hBufferedPaint, const void* prc, std::uint8_t alpha) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hBufferedPaint);
    static_cast<void>(prc);
    static_cast<void>(alpha);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_BufferedPaintStopAllAnimations(void* hwnd) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hwnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_BufferedPaintUnInit() noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_CloseThemeData(void* hTheme) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_DrawThemeBackground(void* hTheme, void* hdc, std::int32_t iPartId, std::int32_t iStateId, const void* pRect, const void* pClipRect) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(hdc);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(pRect);
    static_cast<void>(pClipRect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_DrawThemeBackgroundEx(void* hTheme, void* hdc, std::int32_t iPartId, std::int32_t iStateId, const void* pRect, const void* pOptions) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(hdc);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(pRect);
    static_cast<void>(pOptions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_DrawThemeEdge(void* hTheme, void* hdc, std::int32_t iPartId, std::int32_t iStateId, const void* pDestRect, std::uint32_t uEdge, std::uint32_t uFlags, void* pContentRect) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(hdc);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(pDestRect);
    static_cast<void>(uEdge);
    static_cast<void>(uFlags);
    static_cast<void>(pContentRect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_DrawThemeIcon(void* hTheme, void* hdc, std::int32_t iPartId, std::int32_t iStateId, const void* pRect, void* himl, std::int32_t iImageIndex) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(hdc);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(pRect);
    static_cast<void>(himl);
    static_cast<void>(iImageIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_DrawThemeParentBackground(void* hwnd, void* hdc, void* prc) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hwnd);
    static_cast<void>(hdc);
    static_cast<void>(prc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_DrawThemeParentBackgroundEx(void* hwnd, void* hdc, std::uint32_t dwFlags, const void* prc) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hwnd);
    static_cast<void>(hdc);
    static_cast<void>(dwFlags);
    static_cast<void>(prc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_DrawThemeText(void* hTheme, void* hdc, std::int32_t iPartId, std::int32_t iStateId, const char16_t* pszText, std::int32_t iCharCount, std::uint32_t dwTextFlags, std::uint32_t dwTextFlags2, const void* pRect) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(hdc);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(pszText);
    static_cast<void>(iCharCount);
    static_cast<void>(dwTextFlags);
    static_cast<void>(dwTextFlags2);
    static_cast<void>(pRect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_DrawThemeTextEx(void* hTheme, void* hdc, std::int32_t iPartId, std::int32_t iStateId, const char16_t* pszText, std::int32_t iCharCount, std::uint32_t dwFlags, void* pRect, const void* pOptions) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(hdc);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(pszText);
    static_cast<void>(iCharCount);
    static_cast<void>(dwFlags);
    static_cast<void>(pRect);
    static_cast<void>(pOptions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_EnableThemeDialogTexture(void* hwnd, std::uint32_t dwFlags) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hwnd);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_EnableTheming(std::int32_t fEnable) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(fEnable);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_EndBufferedAnimation(std::uint64_t hbpAnimation, std::int32_t fUpdateTarget) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hbpAnimation);
    static_cast<void>(fUpdateTarget);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_EndBufferedPaint(std::uint64_t hBufferedPaint, std::int32_t fUpdateTarget) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hBufferedPaint);
    static_cast<void>(fUpdateTarget);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_EndPanningFeedback(void* hwnd, std::int32_t fAnimateBack) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hwnd);
    static_cast<void>(fAnimateBack);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetBufferedPaintBits(std::uint64_t hBufferedPaint, void** ppbBuffer, std::int32_t* pcxRow) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hBufferedPaint);
    static_cast<void>(ppbBuffer);
    static_cast<void>(pcxRow);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuxthemeG_GetBufferedPaintDC(std::uint64_t hBufferedPaint) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hBufferedPaint);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuxthemeG_GetBufferedPaintTargetDC(std::uint64_t hBufferedPaint) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hBufferedPaint);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetBufferedPaintTargetRect(std::uint64_t hBufferedPaint, void* prc) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hBufferedPaint);
    static_cast<void>(prc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetCurrentThemeName(char16_t* pszThemeFileName, std::int32_t cchMaxNameChars, char16_t* pszColorBuff, std::int32_t cchMaxColorChars, char16_t* pszSizeBuff, std::int32_t cchMaxSizeChars) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(pszThemeFileName);
    static_cast<void>(cchMaxNameChars);
    static_cast<void>(pszColorBuff);
    static_cast<void>(cchMaxColorChars);
    static_cast<void>(pszSizeBuff);
    static_cast<void>(cchMaxSizeChars);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeAnimationProperty(void* hTheme, std::int32_t iStoryboardId, std::int32_t iTargetId, std::uint64_t eProperty, void* pvProperty, std::uint32_t cbSize, std::uint32_t* pcbSizeOut) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iStoryboardId);
    static_cast<void>(iTargetId);
    static_cast<void>(eProperty);
    static_cast<void>(pvProperty);
    static_cast<void>(cbSize);
    static_cast<void>(pcbSizeOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeAnimationTransform(void* hTheme, std::int32_t iStoryboardId, std::int32_t iTargetId, std::uint32_t dwTransformIndex, void* pTransform, std::uint32_t cbSize, std::uint32_t* pcbSizeOut) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iStoryboardId);
    static_cast<void>(iTargetId);
    static_cast<void>(dwTransformIndex);
    static_cast<void>(pTransform);
    static_cast<void>(cbSize);
    static_cast<void>(pcbSizeOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuxthemeG_GetThemeAppProperties() noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeBackgroundContentRect(void* hTheme, void* hdc, std::int32_t iPartId, std::int32_t iStateId, const void* pBoundingRect, void* pContentRect) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(hdc);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(pBoundingRect);
    static_cast<void>(pContentRect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeBackgroundExtent(void* hTheme, void* hdc, std::int32_t iPartId, std::int32_t iStateId, const void* pContentRect, void* pExtentRect) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(hdc);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(pContentRect);
    static_cast<void>(pExtentRect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeBackgroundRegion(void* hTheme, void* hdc, std::int32_t iPartId, std::int32_t iStateId, const void* pRect, std::uint64_t* pRegion) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(hdc);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(pRect);
    static_cast<void>(pRegion);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeBitmap(void* hTheme, std::int32_t iPartId, std::int32_t iStateId, std::int32_t iPropId, std::uint32_t dwFlags, void* phBitmap) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(iPropId);
    static_cast<void>(dwFlags);
    static_cast<void>(phBitmap);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeBool(void* hTheme, std::int32_t iPartId, std::int32_t iStateId, std::int32_t iPropId, std::int32_t* pfVal) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(iPropId);
    static_cast<void>(pfVal);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeColor(void* hTheme, std::int32_t iPartId, std::int32_t iStateId, std::int32_t iPropId, std::uint32_t* pColor) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(iPropId);
    static_cast<void>(pColor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeDocumentationProperty(const char16_t* pszThemeName, const char16_t* pszPropertyName, char16_t* pszValueBuff, std::int32_t cchMaxValChars) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(pszThemeName);
    static_cast<void>(pszPropertyName);
    static_cast<void>(pszValueBuff);
    static_cast<void>(cchMaxValChars);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeEnumValue(void* hTheme, std::int32_t iPartId, std::int32_t iStateId, std::int32_t iPropId, std::int32_t* piVal) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(iPropId);
    static_cast<void>(piVal);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeFilename(void* hTheme, std::int32_t iPartId, std::int32_t iStateId, std::int32_t iPropId, char16_t* pszThemeFileName, std::int32_t cchMaxBuffChars) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(iPropId);
    static_cast<void>(pszThemeFileName);
    static_cast<void>(cchMaxBuffChars);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeFont(void* hTheme, void* hdc, std::int32_t iPartId, std::int32_t iStateId, std::int32_t iPropId, void* pFont) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(hdc);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(iPropId);
    static_cast<void>(pFont);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeInt(void* hTheme, std::int32_t iPartId, std::int32_t iStateId, std::int32_t iPropId, std::int32_t* piVal) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(iPropId);
    static_cast<void>(piVal);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeIntList(void* hTheme, std::int32_t iPartId, std::int32_t iStateId, std::int32_t iPropId, void* pIntList) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(iPropId);
    static_cast<void>(pIntList);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeMargins(void* hTheme, void* hdc, std::int32_t iPartId, std::int32_t iStateId, std::int32_t iPropId, void* prc, void* pMargins) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(hdc);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(iPropId);
    static_cast<void>(prc);
    static_cast<void>(pMargins);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeMetric(void* hTheme, void* hdc, std::int32_t iPartId, std::int32_t iStateId, std::int32_t iPropId, std::int32_t* piVal) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(hdc);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(iPropId);
    static_cast<void>(piVal);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemePartSize(void* hTheme, void* hdc, std::int32_t iPartId, std::int32_t iStateId, void* prc, std::uint64_t eSize, void* psz) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(hdc);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(prc);
    static_cast<void>(eSize);
    static_cast<void>(psz);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemePosition(void* hTheme, std::int32_t iPartId, std::int32_t iStateId, std::int32_t iPropId, std::uint64_t* pPoint) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(iPropId);
    static_cast<void>(pPoint);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemePropertyOrigin(void* hTheme, std::int32_t iPartId, std::int32_t iStateId, std::int32_t iPropId, void* pOrigin) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(iPropId);
    static_cast<void>(pOrigin);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeRect(void* hTheme, std::int32_t iPartId, std::int32_t iStateId, std::int32_t iPropId, void* pRect) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(iPropId);
    static_cast<void>(pRect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeStream(void* hTheme, std::int32_t iPartId, std::int32_t iStateId, std::int32_t iPropId, void** ppvStream, std::uint32_t* pcbStream, void* hInst) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(iPropId);
    static_cast<void>(ppvStream);
    static_cast<void>(pcbStream);
    static_cast<void>(hInst);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeString(void* hTheme, std::int32_t iPartId, std::int32_t iStateId, std::int32_t iPropId, char16_t* pszBuff, std::int32_t cchMaxBuffChars) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(iPropId);
    static_cast<void>(pszBuff);
    static_cast<void>(cchMaxBuffChars);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeSysBool(void* hTheme, std::int32_t iBoolId) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iBoolId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuxthemeG_GetThemeSysColor(void* hTheme, std::int32_t iColorId) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iColorId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuxthemeG_GetThemeSysColorBrush(void* hTheme, std::int32_t iColorId) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iColorId);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeSysFont(void* hTheme, std::int32_t iFontId, void* plf) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iFontId);
    static_cast<void>(plf);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeSysInt(void* hTheme, std::int32_t iIntId, std::int32_t* piValue) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iIntId);
    static_cast<void>(piValue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeSysSize(void* hTheme, std::int32_t iSizeId) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iSizeId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeSysString(void* hTheme, std::int32_t iStringId, char16_t* pszStringBuff, std::int32_t cchMaxStringChars) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iStringId);
    static_cast<void>(pszStringBuff);
    static_cast<void>(cchMaxStringChars);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeTextExtent(void* hTheme, void* hdc, std::int32_t iPartId, std::int32_t iStateId, const char16_t* pszText, std::int32_t iCharCount, std::uint32_t dwTextFlags, const void* pBoundingRect, void* pExtentRect) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(hdc);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(pszText);
    static_cast<void>(iCharCount);
    static_cast<void>(dwTextFlags);
    static_cast<void>(pBoundingRect);
    static_cast<void>(pExtentRect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeTextMetrics(void* hTheme, void* hdc, std::int32_t iPartId, std::int32_t iStateId, void* ptm) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(hdc);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(ptm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeTimingFunction(void* hTheme, std::int32_t iTimingFunctionId, void* pTimingFunction, std::uint32_t cbSize, std::uint32_t* pcbSizeOut) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iTimingFunctionId);
    static_cast<void>(pTimingFunction);
    static_cast<void>(cbSize);
    static_cast<void>(pcbSizeOut);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_GetThemeTransitionDuration(void* hTheme, std::int32_t iPartId, std::int32_t iStateIdFrom, std::int32_t iStateIdTo, std::int32_t iPropId, std::uint32_t* pdwDuration) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iPartId);
    static_cast<void>(iStateIdFrom);
    static_cast<void>(iStateIdTo);
    static_cast<void>(iPropId);
    static_cast<void>(pdwDuration);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuxthemeG_GetWindowTheme(void* hwnd) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hwnd);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_HitTestThemeBackground(void* hTheme, void* hdc, std::int32_t iPartId, std::int32_t iStateId, std::uint32_t dwOptions, const void* pRect, std::uint64_t hrgn, std::uint64_t ptTest, std::uint16_t* pwHitTestCode) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(hdc);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    static_cast<void>(dwOptions);
    static_cast<void>(pRect);
    static_cast<void>(hrgn);
    static_cast<void>(ptTest);
    static_cast<void>(pwHitTestCode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_IsAppThemed() noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_IsCompositionActive() noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_IsThemeActive() noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_IsThemeBackgroundPartiallyTransparent(void* hTheme, std::int32_t iPartId, std::int32_t iStateId) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_IsThemeDialogTextureEnabled(void* hwnd) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hwnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_IsThemePartDefined(void* hTheme, std::int32_t iPartId, std::int32_t iStateId) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hTheme);
    static_cast<void>(iPartId);
    static_cast<void>(iStateId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuxthemeG_OpenThemeData(void* hwnd, const char16_t* pszClassList) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hwnd);
    static_cast<void>(pszClassList);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kuxthemeG_OpenThemeDataEx(void* hwnd, const char16_t* pszClassList, std::uint32_t dwFlags) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hwnd);
    static_cast<void>(pszClassList);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kuxthemeG_SetThemeAppProperties(std::uint32_t dwFlags) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_SetWindowTheme(void* hwnd, const char16_t* pszSubAppName, const char16_t* pszSubIdList) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hwnd);
    static_cast<void>(pszSubAppName);
    static_cast<void>(pszSubIdList);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_SetWindowThemeAttribute(void* hwnd, std::uint64_t eAttribute, void* pvAttribute, std::uint32_t cbAttribute) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hwnd);
    static_cast<void>(eAttribute);
    static_cast<void>(pvAttribute);
    static_cast<void>(cbAttribute);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuxthemeG_UpdatePanningFeedback(void* hwnd, std::int32_t lTotalOverpanOffsetX, std::int32_t lTotalOverpanOffsetY, std::int32_t fInInertia) noexcept {
    // Refused: the theming subsystem.
    //
    // a theme describes how a window is drawn; there is no window and no
    // surface to draw on
    static_cast<void>(hwnd);
    static_cast<void>(lTotalOverpanOffsetX);
    static_cast<void>(lTotalOverpanOffsetY);
    static_cast<void>(fInInertia);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_uxtheme(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("BeginBufferedAnimation", reinterpret_cast<void*>(&kuxthemeG_BeginBufferedAnimation));
    e("BeginBufferedPaint", reinterpret_cast<void*>(&kuxthemeG_BeginBufferedPaint));
    e("BeginPanningFeedback", reinterpret_cast<void*>(&kuxthemeG_BeginPanningFeedback));
    e("BufferedPaintClear", reinterpret_cast<void*>(&kuxthemeG_BufferedPaintClear));
    e("BufferedPaintInit", reinterpret_cast<void*>(&kuxthemeG_BufferedPaintInit));
    e("BufferedPaintRenderAnimation", reinterpret_cast<void*>(&kuxthemeG_BufferedPaintRenderAnimation));
    e("BufferedPaintSetAlpha", reinterpret_cast<void*>(&kuxthemeG_BufferedPaintSetAlpha));
    e("BufferedPaintStopAllAnimations", reinterpret_cast<void*>(&kuxthemeG_BufferedPaintStopAllAnimations));
    e("BufferedPaintUnInit", reinterpret_cast<void*>(&kuxthemeG_BufferedPaintUnInit));
    e("CloseThemeData", reinterpret_cast<void*>(&kuxthemeG_CloseThemeData));
    e("DrawThemeBackground", reinterpret_cast<void*>(&kuxthemeG_DrawThemeBackground));
    e("DrawThemeBackgroundEx", reinterpret_cast<void*>(&kuxthemeG_DrawThemeBackgroundEx));
    e("DrawThemeEdge", reinterpret_cast<void*>(&kuxthemeG_DrawThemeEdge));
    e("DrawThemeIcon", reinterpret_cast<void*>(&kuxthemeG_DrawThemeIcon));
    e("DrawThemeParentBackground", reinterpret_cast<void*>(&kuxthemeG_DrawThemeParentBackground));
    e("DrawThemeParentBackgroundEx", reinterpret_cast<void*>(&kuxthemeG_DrawThemeParentBackgroundEx));
    e("DrawThemeText", reinterpret_cast<void*>(&kuxthemeG_DrawThemeText));
    e("DrawThemeTextEx", reinterpret_cast<void*>(&kuxthemeG_DrawThemeTextEx));
    e("EnableThemeDialogTexture", reinterpret_cast<void*>(&kuxthemeG_EnableThemeDialogTexture));
    e("EnableTheming", reinterpret_cast<void*>(&kuxthemeG_EnableTheming));
    e("EndBufferedAnimation", reinterpret_cast<void*>(&kuxthemeG_EndBufferedAnimation));
    e("EndBufferedPaint", reinterpret_cast<void*>(&kuxthemeG_EndBufferedPaint));
    e("EndPanningFeedback", reinterpret_cast<void*>(&kuxthemeG_EndPanningFeedback));
    e("GetBufferedPaintBits", reinterpret_cast<void*>(&kuxthemeG_GetBufferedPaintBits));
    e("GetBufferedPaintDC", reinterpret_cast<void*>(&kuxthemeG_GetBufferedPaintDC));
    e("GetBufferedPaintTargetDC", reinterpret_cast<void*>(&kuxthemeG_GetBufferedPaintTargetDC));
    e("GetBufferedPaintTargetRect", reinterpret_cast<void*>(&kuxthemeG_GetBufferedPaintTargetRect));
    e("GetCurrentThemeName", reinterpret_cast<void*>(&kuxthemeG_GetCurrentThemeName));
    e("GetThemeAnimationProperty", reinterpret_cast<void*>(&kuxthemeG_GetThemeAnimationProperty));
    e("GetThemeAnimationTransform", reinterpret_cast<void*>(&kuxthemeG_GetThemeAnimationTransform));
    e("GetThemeAppProperties", reinterpret_cast<void*>(&kuxthemeG_GetThemeAppProperties));
    e("GetThemeBackgroundContentRect", reinterpret_cast<void*>(&kuxthemeG_GetThemeBackgroundContentRect));
    e("GetThemeBackgroundExtent", reinterpret_cast<void*>(&kuxthemeG_GetThemeBackgroundExtent));
    e("GetThemeBackgroundRegion", reinterpret_cast<void*>(&kuxthemeG_GetThemeBackgroundRegion));
    e("GetThemeBitmap", reinterpret_cast<void*>(&kuxthemeG_GetThemeBitmap));
    e("GetThemeBool", reinterpret_cast<void*>(&kuxthemeG_GetThemeBool));
    e("GetThemeColor", reinterpret_cast<void*>(&kuxthemeG_GetThemeColor));
    e("GetThemeDocumentationProperty", reinterpret_cast<void*>(&kuxthemeG_GetThemeDocumentationProperty));
    e("GetThemeEnumValue", reinterpret_cast<void*>(&kuxthemeG_GetThemeEnumValue));
    e("GetThemeFilename", reinterpret_cast<void*>(&kuxthemeG_GetThemeFilename));
    e("GetThemeFont", reinterpret_cast<void*>(&kuxthemeG_GetThemeFont));
    e("GetThemeInt", reinterpret_cast<void*>(&kuxthemeG_GetThemeInt));
    e("GetThemeIntList", reinterpret_cast<void*>(&kuxthemeG_GetThemeIntList));
    e("GetThemeMargins", reinterpret_cast<void*>(&kuxthemeG_GetThemeMargins));
    e("GetThemeMetric", reinterpret_cast<void*>(&kuxthemeG_GetThemeMetric));
    e("GetThemePartSize", reinterpret_cast<void*>(&kuxthemeG_GetThemePartSize));
    e("GetThemePosition", reinterpret_cast<void*>(&kuxthemeG_GetThemePosition));
    e("GetThemePropertyOrigin", reinterpret_cast<void*>(&kuxthemeG_GetThemePropertyOrigin));
    e("GetThemeRect", reinterpret_cast<void*>(&kuxthemeG_GetThemeRect));
    e("GetThemeStream", reinterpret_cast<void*>(&kuxthemeG_GetThemeStream));
    e("GetThemeString", reinterpret_cast<void*>(&kuxthemeG_GetThemeString));
    e("GetThemeSysBool", reinterpret_cast<void*>(&kuxthemeG_GetThemeSysBool));
    e("GetThemeSysColor", reinterpret_cast<void*>(&kuxthemeG_GetThemeSysColor));
    e("GetThemeSysColorBrush", reinterpret_cast<void*>(&kuxthemeG_GetThemeSysColorBrush));
    e("GetThemeSysFont", reinterpret_cast<void*>(&kuxthemeG_GetThemeSysFont));
    e("GetThemeSysInt", reinterpret_cast<void*>(&kuxthemeG_GetThemeSysInt));
    e("GetThemeSysSize", reinterpret_cast<void*>(&kuxthemeG_GetThemeSysSize));
    e("GetThemeSysString", reinterpret_cast<void*>(&kuxthemeG_GetThemeSysString));
    e("GetThemeTextExtent", reinterpret_cast<void*>(&kuxthemeG_GetThemeTextExtent));
    e("GetThemeTextMetrics", reinterpret_cast<void*>(&kuxthemeG_GetThemeTextMetrics));
    e("GetThemeTimingFunction", reinterpret_cast<void*>(&kuxthemeG_GetThemeTimingFunction));
    e("GetThemeTransitionDuration", reinterpret_cast<void*>(&kuxthemeG_GetThemeTransitionDuration));
    e("GetWindowTheme", reinterpret_cast<void*>(&kuxthemeG_GetWindowTheme));
    e("HitTestThemeBackground", reinterpret_cast<void*>(&kuxthemeG_HitTestThemeBackground));
    e("IsAppThemed", reinterpret_cast<void*>(&kuxthemeG_IsAppThemed));
    e("IsCompositionActive", reinterpret_cast<void*>(&kuxthemeG_IsCompositionActive));
    e("IsThemeActive", reinterpret_cast<void*>(&kuxthemeG_IsThemeActive));
    e("IsThemeBackgroundPartiallyTransparent", reinterpret_cast<void*>(&kuxthemeG_IsThemeBackgroundPartiallyTransparent));
    e("IsThemeDialogTextureEnabled", reinterpret_cast<void*>(&kuxthemeG_IsThemeDialogTextureEnabled));
    e("IsThemePartDefined", reinterpret_cast<void*>(&kuxthemeG_IsThemePartDefined));
    e("OpenThemeData", reinterpret_cast<void*>(&kuxthemeG_OpenThemeData));
    e("OpenThemeDataEx", reinterpret_cast<void*>(&kuxthemeG_OpenThemeDataEx));
    e("SetThemeAppProperties", reinterpret_cast<void*>(&kuxthemeG_SetThemeAppProperties));
    e("SetWindowTheme", reinterpret_cast<void*>(&kuxthemeG_SetWindowTheme));
    e("SetWindowThemeAttribute", reinterpret_cast<void*>(&kuxthemeG_SetWindowThemeAttribute));
    e("UpdatePanningFeedback", reinterpret_cast<void*>(&kuxthemeG_UpdatePanningFeedback));
}
}  // namespace occ::runtime::winabi

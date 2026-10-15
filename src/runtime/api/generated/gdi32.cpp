// The GDI32 surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_AbortDoc(void* hdc) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_AddFontMemResourceEx(void* pFileView, std::uint32_t cjSize, void* pvResrved, std::uint32_t* pNumFonts) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(pFileView);
    static_cast<void>(cjSize);
    static_cast<void>(pvResrved);
    static_cast<void>(pNumFonts);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_AddFontResourceA(const char* arg0) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_AddFontResourceExA(const char* name, std::uint32_t fl, void* res) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(name);
    static_cast<void>(fl);
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_AddFontResourceExW(const char16_t* name, std::uint32_t fl, void* res) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(name);
    static_cast<void>(fl);
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_AddFontResourceW(const char16_t* arg0) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_CheckColorsInGamut(void* hdc, void* lpRGBTriple, void* dlpBuffer, std::uint32_t nCount) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lpRGBTriple);
    static_cast<void>(dlpBuffer);
    static_cast<void>(nCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_ChoosePixelFormat(void* hdc, const void* ppfd) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(ppfd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_CloseEnhMetaFile(void* hdc) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_CloseMetaFile(void* hdc) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_ColorCorrectPalette(void* hdc, void* hPal, std::uint32_t deFirst, std::uint32_t num) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(hPal);
    static_cast<void>(deFirst);
    static_cast<void>(num);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_ColorMatchToTarget(void* hdc, void* hdcTarget, std::uint32_t action) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(hdcTarget);
    static_cast<void>(action);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_CombineTransform(void* lpxfOut, const void* lpxf1, const void* lpxf2) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(lpxfOut);
    static_cast<void>(lpxf1);
    static_cast<void>(lpxf2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_CopyEnhMetaFileA(void* hEnh, const char* lpFileName) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hEnh);
    static_cast<void>(lpFileName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_CopyEnhMetaFileW(void* hEnh, const char16_t* lpFileName) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hEnh);
    static_cast<void>(lpFileName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_CopyMetaFileA(void* arg0, const char* arg1) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_CopyMetaFileW(void* arg0, const char16_t* arg1) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kgdi32G_CreateColorSpaceA(std::uint64_t lplcs) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(lplcs);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kgdi32G_CreateColorSpaceW(std::uint64_t lplcs) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(lplcs);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_CreateEnhMetaFileA(void* hdc, const char* lpFilename, const void* lprc, const char* lpDesc) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lpFilename);
    static_cast<void>(lprc);
    static_cast<void>(lpDesc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_CreateEnhMetaFileW(void* hdc, const char16_t* lpFilename, const void* lprc, const char16_t* lpDesc) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lpFilename);
    static_cast<void>(lprc);
    static_cast<void>(lpDesc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_CreateHalftonePalette(void* hdc) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_CreateMetaFileA(const char* pszFile) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(pszFile);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_CreateMetaFileW(const char16_t* pszFile) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(pszFile);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_CreateScalableFontResourceA(std::uint32_t fdwHidden, const char* lpszFont, const char* lpszFile, const char* lpszPath) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(fdwHidden);
    static_cast<void>(lpszFont);
    static_cast<void>(lpszFile);
    static_cast<void>(lpszPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_CreateScalableFontResourceW(std::uint32_t fdwHidden, const char16_t* lpszFont, const char16_t* lpszFile, const char16_t* lpszPath) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(fdwHidden);
    static_cast<void>(lpszFont);
    static_cast<void>(lpszFile);
    static_cast<void>(lpszPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_DPtoLP(void* hdc, void* lppt, std::int32_t c) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lppt);
    static_cast<void>(c);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_DeleteColorSpace(std::uint64_t hcs) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hcs);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_DeleteEnhMetaFile(void* hmf) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hmf);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_DeleteMetaFile(void* hmf) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hmf);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_DescribePixelFormat(void* hdc, std::int32_t iPixelFormat, std::uint32_t nBytes, void* ppfd) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(iPixelFormat);
    static_cast<void>(nBytes);
    static_cast<void>(ppfd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_DrawEscape(void* hdc, std::int32_t iEscape, std::int32_t cjIn, const char* lpIn) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(iEscape);
    static_cast<void>(cjIn);
    static_cast<void>(lpIn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_EndDoc(void* hdc) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_EndPage(void* hdc) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_EnumEnhMetaFile(void* hdc, void* hmf, void* lpProc, void* lpParam, const void* lpRect) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(hmf);
    static_cast<void>(lpProc);
    static_cast<void>(lpParam);
    static_cast<void>(lpRect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_EnumFontFamiliesA(void* hdc, const char* lpLogfont, std::uint64_t lpProc, std::int64_t lParam) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lpLogfont);
    static_cast<void>(lpProc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_EnumFontFamiliesExA(void* hdc, void* lpLogfont, std::uint64_t lpProc, std::int64_t lParam, std::uint32_t dwFlags) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lpLogfont);
    static_cast<void>(lpProc);
    static_cast<void>(lParam);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_EnumFontFamiliesExW(void* hdc, void* lpLogfont, std::uint64_t lpProc, std::int64_t lParam, std::uint32_t dwFlags) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lpLogfont);
    static_cast<void>(lpProc);
    static_cast<void>(lParam);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_EnumFontFamiliesW(void* hdc, const char16_t* lpLogfont, std::uint64_t lpProc, std::int64_t lParam) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lpLogfont);
    static_cast<void>(lpProc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_EnumFontsA(void* hdc, const char* lpLogfont, std::uint64_t lpProc, std::int64_t lParam) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lpLogfont);
    static_cast<void>(lpProc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_EnumFontsW(void* hdc, const char16_t* lpLogfont, std::uint64_t lpProc, std::int64_t lParam) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lpLogfont);
    static_cast<void>(lpProc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_EnumICMProfilesA(void* hdc, void* lpProc, std::int64_t lParam) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lpProc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_EnumICMProfilesW(void* hdc, void* lpProc, std::int64_t lParam) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lpProc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_EnumMetaFile(void* hdc, void* hmf, std::uint64_t lpProc, std::int64_t lParam) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(hmf);
    static_cast<void>(lpProc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_EnumObjects(void* hdc, std::int32_t nType, std::uint64_t lpFunc, std::int64_t lParam) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(nType);
    static_cast<void>(lpFunc);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kgdi32G_ExtCreateRegion(const void* lpx, std::uint32_t nCount, const void* lpData) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(lpx);
    static_cast<void>(nCount);
    static_cast<void>(lpData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_ExtFloodFill(void* hdc, std::int32_t x, std::int32_t y, std::uint32_t color, std::uint32_t type) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(color);
    static_cast<void>(type);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_FillRgn(void* hdc, std::uint64_t hrgn, void* hbr) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(hrgn);
    static_cast<void>(hbr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_FixBrushOrgEx(void* hdc, std::int32_t x, std::int32_t y, void* ptl) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(ptl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_FloodFill(void* hdc, std::int32_t x, std::int32_t y, std::uint32_t color) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(color);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_FrameRgn(void* hdc, std::uint64_t hrgn, void* hbr, std::int32_t w, std::int32_t h) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(hrgn);
    static_cast<void>(hbr);
    static_cast<void>(w);
    static_cast<void>(h);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GdiAlphaBlend(void* hdcDest, std::int32_t xoriginDest, std::int32_t yoriginDest, std::int32_t wDest, std::int32_t hDest, void* hdcSrc, std::int32_t xoriginSrc, std::int32_t yoriginSrc, std::int32_t wSrc, std::int32_t hSrc, std::uint64_t ftn) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdcDest);
    static_cast<void>(xoriginDest);
    static_cast<void>(yoriginDest);
    static_cast<void>(wDest);
    static_cast<void>(hDest);
    static_cast<void>(hdcSrc);
    static_cast<void>(xoriginSrc);
    static_cast<void>(yoriginSrc);
    static_cast<void>(wSrc);
    static_cast<void>(hSrc);
    static_cast<void>(ftn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GdiComment(void* hdc, std::uint32_t nSize, const std::uint8_t* lpData) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(nSize);
    static_cast<void>(lpData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GdiGradientFill(void* hdc, std::uint64_t pVertex, std::uint32_t nVertex, void* pMesh, std::uint32_t nMesh, std::uint32_t ulMode) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(pVertex);
    static_cast<void>(nVertex);
    static_cast<void>(pMesh);
    static_cast<void>(nMesh);
    static_cast<void>(ulMode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GdiTransparentBlt(void* hdcDest, std::int32_t xoriginDest, std::int32_t yoriginDest, std::int32_t wDest, std::int32_t hDest, void* hdcSrc, std::int32_t xoriginSrc, std::int32_t yoriginSrc, std::int32_t wSrc, std::int32_t hSrc, std::uint32_t crTransparent) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdcDest);
    static_cast<void>(xoriginDest);
    static_cast<void>(yoriginDest);
    static_cast<void>(wDest);
    static_cast<void>(hDest);
    static_cast<void>(hdcSrc);
    static_cast<void>(xoriginSrc);
    static_cast<void>(yoriginSrc);
    static_cast<void>(wSrc);
    static_cast<void>(hSrc);
    static_cast<void>(crTransparent);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetArcDirection(void* hdc) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetAspectRatioFilterEx(void* hdc, void* lpsize) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lpsize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetBitmapBits(void* hbit, std::int32_t cb, void* lpvBits) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hbit);
    static_cast<void>(cb);
    static_cast<void>(lpvBits);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetBitmapDimensionEx(void* hbit, void* lpsize) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hbit);
    static_cast<void>(lpsize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetBoundsRect(void* hdc, void* lprect, std::uint32_t flags) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lprect);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetCharABCWidthsFloatA(void* hdc, std::uint32_t iFirst, std::uint32_t iLast, std::uint64_t lpABC) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(iFirst);
    static_cast<void>(iLast);
    static_cast<void>(lpABC);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetCharABCWidthsFloatW(void* hdc, std::uint32_t iFirst, std::uint32_t iLast, std::uint64_t lpABC) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(iFirst);
    static_cast<void>(iLast);
    static_cast<void>(lpABC);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetCharABCWidthsI(void* hdc, std::uint32_t giFirst, std::uint32_t cgi, std::uint16_t* pgi, std::uint64_t pabc) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(giFirst);
    static_cast<void>(cgi);
    static_cast<void>(pgi);
    static_cast<void>(pabc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetCharWidth32A(void* hdc, std::uint32_t iFirst, std::uint32_t iLast, std::int32_t* lpBuffer) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(iFirst);
    static_cast<void>(iLast);
    static_cast<void>(lpBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetCharWidth32W(void* hdc, std::uint32_t iFirst, std::uint32_t iLast, std::int32_t* lpBuffer) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(iFirst);
    static_cast<void>(iLast);
    static_cast<void>(lpBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetCharWidthFloatA(void* hdc, std::uint32_t iFirst, std::uint32_t iLast, float* lpBuffer) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(iFirst);
    static_cast<void>(iLast);
    static_cast<void>(lpBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetCharWidthFloatW(void* hdc, std::uint32_t iFirst, std::uint32_t iLast, float* lpBuffer) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(iFirst);
    static_cast<void>(iLast);
    static_cast<void>(lpBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetCharWidthI(void* hdc, std::uint32_t giFirst, std::uint32_t cgi, std::uint16_t* pgi, std::int32_t* piWidths) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(giFirst);
    static_cast<void>(cgi);
    static_cast<void>(pgi);
    static_cast<void>(piWidths);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetCharacterPlacementA(void* hdc, const char* lpString, std::int32_t nCount, std::int32_t nMexExtent, std::uint64_t lpResults, std::uint32_t dwFlags) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lpString);
    static_cast<void>(nCount);
    static_cast<void>(nMexExtent);
    static_cast<void>(lpResults);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetCharacterPlacementW(void* hdc, const char16_t* lpString, std::int32_t nCount, std::int32_t nMexExtent, std::uint64_t lpResults, std::uint32_t dwFlags) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lpString);
    static_cast<void>(nCount);
    static_cast<void>(nMexExtent);
    static_cast<void>(lpResults);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetColorAdjustment(void* hdc, void* lpca) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lpca);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kgdi32G_GetColorSpace(void* hdc) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_GetCurrentObject(void* hdc, std::uint32_t type) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(type);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetCurrentPositionEx(void* hdc, void* lppt) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lppt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetDCBrushColor(void* hdc) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetDCOrgEx(void* hdc, void* lppt) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lppt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetDCPenColor(void* hdc) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetDeviceGammaRamp(void* hdc, void* lpRamp) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lpRamp);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_GetEnhMetaFileA(const char* lpName) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(lpName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetEnhMetaFileBits(void* hEMF, std::uint32_t nSize, std::uint8_t* lpData) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hEMF);
    static_cast<void>(nSize);
    static_cast<void>(lpData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetEnhMetaFileDescriptionA(void* hemf, std::uint32_t cchBuffer, char* lpDescription) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hemf);
    static_cast<void>(cchBuffer);
    static_cast<void>(lpDescription);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetEnhMetaFileDescriptionW(void* hemf, std::uint32_t cchBuffer, char16_t* lpDescription) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hemf);
    static_cast<void>(cchBuffer);
    static_cast<void>(lpDescription);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetEnhMetaFileHeader(void* hemf, std::uint32_t nSize, std::uint64_t lpEnhMetaHeader) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hemf);
    static_cast<void>(nSize);
    static_cast<void>(lpEnhMetaHeader);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetEnhMetaFilePaletteEntries(void* hemf, std::uint32_t nNumEntries, std::uint32_t* lpPaletteEntries) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hemf);
    static_cast<void>(nNumEntries);
    static_cast<void>(lpPaletteEntries);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetEnhMetaFilePixelFormat(void* hemf, std::uint32_t cbBuffer, void* ppfd) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hemf);
    static_cast<void>(cbBuffer);
    static_cast<void>(ppfd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_GetEnhMetaFileW(const char16_t* lpName) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(lpName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetFontData(void* hdc, std::uint32_t dwTable, std::uint32_t dwOffset, void* pvBuffer, std::uint32_t cjBuffer) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(dwTable);
    static_cast<void>(dwOffset);
    static_cast<void>(pvBuffer);
    static_cast<void>(cjBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetFontLanguageInfo(void* hdc) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetFontUnicodeRanges(void* hdc, std::uint64_t lpgs) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lpgs);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetGlyphIndicesA(void* hdc, const char* lpstr, std::int32_t c, std::uint16_t* pgi, std::uint32_t fl) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lpstr);
    static_cast<void>(c);
    static_cast<void>(pgi);
    static_cast<void>(fl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetGlyphIndicesW(void* hdc, const char16_t* lpstr, std::int32_t c, std::uint16_t* pgi, std::uint32_t fl) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lpstr);
    static_cast<void>(c);
    static_cast<void>(pgi);
    static_cast<void>(fl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetGlyphOutlineA(void* hdc, std::uint32_t uChar, std::uint32_t fuFormat, std::uint64_t lpgm, std::uint32_t cjBuffer, void* pvBuffer, const void* lpmat2) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(uChar);
    static_cast<void>(fuFormat);
    static_cast<void>(lpgm);
    static_cast<void>(cjBuffer);
    static_cast<void>(pvBuffer);
    static_cast<void>(lpmat2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetGlyphOutlineW(void* hdc, std::uint32_t uChar, std::uint32_t fuFormat, std::uint64_t lpgm, std::uint32_t cjBuffer, void* pvBuffer, const void* lpmat2) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(uChar);
    static_cast<void>(fuFormat);
    static_cast<void>(lpgm);
    static_cast<void>(cjBuffer);
    static_cast<void>(pvBuffer);
    static_cast<void>(lpmat2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetICMProfileA(void* hdc, std::uint32_t* pBufSize, char* pszFilename) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(pBufSize);
    static_cast<void>(pszFilename);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetICMProfileW(void* hdc, std::uint32_t* pBufSize, char16_t* pszFilename) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(pBufSize);
    static_cast<void>(pszFilename);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetKerningPairsA(void* hdc, std::uint32_t nPairs, std::uint64_t lpKernPair) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(nPairs);
    static_cast<void>(lpKernPair);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetKerningPairsW(void* hdc, std::uint32_t nPairs, std::uint64_t lpKernPair) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(nPairs);
    static_cast<void>(lpKernPair);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetLogColorSpaceA(std::uint64_t hColorSpace, std::uint64_t lpBuffer, std::uint32_t nSize) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hColorSpace);
    static_cast<void>(lpBuffer);
    static_cast<void>(nSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetLogColorSpaceW(std::uint64_t hColorSpace, std::uint64_t lpBuffer, std::uint32_t nSize) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hColorSpace);
    static_cast<void>(lpBuffer);
    static_cast<void>(nSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_GetMetaFileA(const char* lpName) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(lpName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetMetaFileBitsEx(void* hMF, std::uint32_t cbBuffer, void* lpData) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hMF);
    static_cast<void>(cbBuffer);
    static_cast<void>(lpData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_GetMetaFileW(const char16_t* lpName) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(lpName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetMetaRgn(void* hdc, std::uint64_t hrgn) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(hrgn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetMiterLimit(void* hdc, float* plimit) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(plimit);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetOutlineTextMetricsA(void* hdc, std::uint32_t cjCopy, void* potm) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(cjCopy);
    static_cast<void>(potm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetOutlineTextMetricsW(void* hdc, std::uint32_t cjCopy, std::uint64_t potm) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(cjCopy);
    static_cast<void>(potm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetPixelFormat(void* hdc) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetRandomRgn(void* hdc, std::uint64_t hrgn, std::int32_t i) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(hrgn);
    static_cast<void>(i);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetRasterizerCaps(std::uint64_t lpraststat, std::uint32_t cjBytes) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(lpraststat);
    static_cast<void>(cjBytes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetRegionData(std::uint64_t hrgn, std::uint32_t nCount, void* lpRgnData) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hrgn);
    static_cast<void>(nCount);
    static_cast<void>(lpRgnData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetTextExtentPointI(void* hdc, std::uint16_t* pgiIn, std::int32_t cgi, void* psize) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(pgiIn);
    static_cast<void>(cgi);
    static_cast<void>(psize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetViewportExtEx(void* hdc, void* lpsize) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lpsize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetViewportOrgEx(void* hdc, void* lppoint) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lppoint);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_GetWinMetaFileBits(void* hemf, std::uint32_t cbData16, std::uint8_t* pData16, std::int32_t iMapMode, void* hdcRef) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hemf);
    static_cast<void>(cbData16);
    static_cast<void>(pData16);
    static_cast<void>(iMapMode);
    static_cast<void>(hdcRef);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetWindowExtEx(void* hdc, void* lpsize) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lpsize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_GetWindowOrgEx(void* hdc, void* lppoint) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lppoint);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_InvertRgn(void* hdc, std::uint64_t hrgn) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(hrgn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_LPtoDP(void* hdc, void* lppt, std::int32_t c) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lppt);
    static_cast<void>(c);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_LineDDA(std::int32_t xStart, std::int32_t yStart, std::int32_t xEnd, std::int32_t yEnd, std::uint64_t lpProc, std::int64_t data) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(xStart);
    static_cast<void>(yStart);
    static_cast<void>(xEnd);
    static_cast<void>(yEnd);
    static_cast<void>(lpProc);
    static_cast<void>(data);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_MaskBlt(void* hdcDest, std::int32_t xDest, std::int32_t yDest, std::int32_t width, std::int32_t height, void* hdcSrc, std::int32_t xSrc, std::int32_t ySrc, void* hbmMask, std::int32_t xMask, std::int32_t yMask, std::uint32_t rop) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdcDest);
    static_cast<void>(xDest);
    static_cast<void>(yDest);
    static_cast<void>(width);
    static_cast<void>(height);
    static_cast<void>(hdcSrc);
    static_cast<void>(xSrc);
    static_cast<void>(ySrc);
    static_cast<void>(hbmMask);
    static_cast<void>(xMask);
    static_cast<void>(yMask);
    static_cast<void>(rop);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_PaintRgn(void* hdc, std::uint64_t hrgn) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(hrgn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_PlayEnhMetaFile(void* hdc, void* hmf, const void* lprect) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(hmf);
    static_cast<void>(lprect);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_PlayEnhMetaFileRecord(void* hdc, std::uint64_t pht, const void* pmr, std::uint32_t cht) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(pht);
    static_cast<void>(pmr);
    static_cast<void>(cht);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_PlayMetaFile(void* hdc, void* hmf) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(hmf);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_PlayMetaFileRecord(void* hdc, std::uint64_t lpHandleTable, std::uint64_t lpMR, std::uint32_t noObjs) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lpHandleTable);
    static_cast<void>(lpMR);
    static_cast<void>(noObjs);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_PlgBlt(void* hdcDest, const std::uint64_t* lpPoint, void* hdcSrc, std::int32_t xSrc, std::int32_t ySrc, std::int32_t width, std::int32_t height, void* hbmMask, std::int32_t xMask, std::int32_t yMask) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdcDest);
    static_cast<void>(lpPoint);
    static_cast<void>(hdcSrc);
    static_cast<void>(xSrc);
    static_cast<void>(ySrc);
    static_cast<void>(width);
    static_cast<void>(height);
    static_cast<void>(hbmMask);
    static_cast<void>(xMask);
    static_cast<void>(yMask);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_PolyDraw(void* hdc, const std::uint64_t* apt, const std::uint8_t* aj, std::int32_t cpt) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(apt);
    static_cast<void>(aj);
    static_cast<void>(cpt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_PolyTextOutA(void* hdc, const void* ppt, std::int32_t nstrings) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(ppt);
    static_cast<void>(nstrings);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_PolyTextOutW(void* hdc, const void* ppt, std::int32_t nstrings) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(ppt);
    static_cast<void>(nstrings);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_RemoveFontMemResourceEx(void* h) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(h);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_RemoveFontResourceA(const char* lpFileName) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(lpFileName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_RemoveFontResourceExA(const char* name, std::uint32_t fl, void* pdv) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(name);
    static_cast<void>(fl);
    static_cast<void>(pdv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_RemoveFontResourceExW(const char16_t* name, std::uint32_t fl, void* pdv) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(name);
    static_cast<void>(fl);
    static_cast<void>(pdv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_RemoveFontResourceW(const char16_t* lpFileName) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(lpFileName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_ResetDCA(void* hdc, const void* lpdm) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lpdm);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_ResetDCW(void* hdc, const void* lpdm) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lpdm);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_SetArcDirection(void* hdc, std::int32_t dir) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(dir);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_SetBitmapBits(void* hbm, std::uint32_t cb, const void* pvBits) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hbm);
    static_cast<void>(cb);
    static_cast<void>(pvBits);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_SetBitmapDimensionEx(void* hbm, std::int32_t w, std::int32_t h, void* lpsz) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hbm);
    static_cast<void>(w);
    static_cast<void>(h);
    static_cast<void>(lpsz);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_SetBoundsRect(void* hdc, const void* lprect, std::uint32_t flags) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lprect);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_SetColorAdjustment(void* hdc, const void* lpca) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(lpca);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kgdi32G_SetColorSpace(void* hdc, std::uint64_t hcs) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(hcs);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_SetDeviceGammaRamp(void* hdc, void* lpRamp) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lpRamp);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_SetEnhMetaFileBits(std::uint32_t nSize, const std::uint8_t* pb) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(nSize);
    static_cast<void>(pb);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_SetICMMode(void* hdc, std::int32_t mode) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(mode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_SetICMProfileA(void* hdc, char* lpFileName) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lpFileName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_SetICMProfileW(void* hdc, char16_t* lpFileName) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lpFileName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kgdi32G_SetMapperFlags(void* hdc, std::uint32_t flags) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_SetMetaFileBitsEx(std::uint32_t cbBuffer, const std::uint8_t* lpData) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(cbBuffer);
    static_cast<void>(lpData);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_SetMetaRgn(void* hdc) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_SetMiterLimit(void* hdc, float limit, float* old) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(limit);
    static_cast<void>(old);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_SetPixelFormat(void* hdc, std::int32_t format, const void* ppfd) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(format);
    static_cast<void>(ppfd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_SetTextJustification(void* hdc, std::int32_t extra, std::int32_t count) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    static_cast<void>(extra);
    static_cast<void>(count);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kgdi32G_SetWinMetaFileBits(std::uint32_t nSize, const std::uint8_t* lpMeta16Data, void* hdcRef, const void* lpMFP) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(nSize);
    static_cast<void>(lpMeta16Data);
    static_cast<void>(hdcRef);
    static_cast<void>(lpMFP);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_StartDocA(void* hdc, const void* lpdi) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lpdi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_StartDocW(void* hdc, const void* lpdi) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    static_cast<void>(lpdi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_StartPage(void* hdc) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(hdc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_SwapBuffers(void* arg0) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_TranslateCharsetInfo(std::uint32_t* lpSrc, std::uint64_t lpCs, std::uint32_t dwFlags) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(lpSrc);
    static_cast<void>(lpCs);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_UnrealizeObject(void* h) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(h);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_UpdateColors(void* hdc) noexcept {
    // Refused: the graphics device layer.
    //
    // there is no device context in this runtime: drawing needs a surface and
    // a rasterizer, and neither is present -- the rasterizing this runtime
    // does is the ASCII report its own commands print
    static_cast<void>(hdc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_UpdateICMRegKeyA(std::uint32_t reserved, char* lpszCMID, char* lpszFileName, std::uint32_t command) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(reserved);
    static_cast<void>(lpszCMID);
    static_cast<void>(lpszFileName);
    static_cast<void>(command);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kgdi32G_UpdateICMRegKeyW(std::uint32_t reserved, char16_t* lpszCMID, char16_t* lpszFileName, std::uint32_t command) noexcept {
    // Refused: the graphics device layer.
    //
    // the call names a GDI object or a device context; this runtime has
    // neither, because it has no surface to draw on
    static_cast<void>(reserved);
    static_cast<void>(lpszCMID);
    static_cast<void>(lpszFileName);
    static_cast<void>(command);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_gdi32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("AbortDoc", reinterpret_cast<void*>(&kgdi32G_AbortDoc));
    e("AddFontMemResourceEx", reinterpret_cast<void*>(&kgdi32G_AddFontMemResourceEx));
    e("AddFontResourceA", reinterpret_cast<void*>(&kgdi32G_AddFontResourceA));
    e("AddFontResourceExA", reinterpret_cast<void*>(&kgdi32G_AddFontResourceExA));
    e("AddFontResourceExW", reinterpret_cast<void*>(&kgdi32G_AddFontResourceExW));
    e("AddFontResourceW", reinterpret_cast<void*>(&kgdi32G_AddFontResourceW));
    e("CheckColorsInGamut", reinterpret_cast<void*>(&kgdi32G_CheckColorsInGamut));
    e("ChoosePixelFormat", reinterpret_cast<void*>(&kgdi32G_ChoosePixelFormat));
    e("CloseEnhMetaFile", reinterpret_cast<void*>(&kgdi32G_CloseEnhMetaFile));
    e("CloseMetaFile", reinterpret_cast<void*>(&kgdi32G_CloseMetaFile));
    e("ColorCorrectPalette", reinterpret_cast<void*>(&kgdi32G_ColorCorrectPalette));
    e("ColorMatchToTarget", reinterpret_cast<void*>(&kgdi32G_ColorMatchToTarget));
    e("CombineTransform", reinterpret_cast<void*>(&kgdi32G_CombineTransform));
    e("CopyEnhMetaFileA", reinterpret_cast<void*>(&kgdi32G_CopyEnhMetaFileA));
    e("CopyEnhMetaFileW", reinterpret_cast<void*>(&kgdi32G_CopyEnhMetaFileW));
    e("CopyMetaFileA", reinterpret_cast<void*>(&kgdi32G_CopyMetaFileA));
    e("CopyMetaFileW", reinterpret_cast<void*>(&kgdi32G_CopyMetaFileW));
    e("CreateColorSpaceA", reinterpret_cast<void*>(&kgdi32G_CreateColorSpaceA));
    e("CreateColorSpaceW", reinterpret_cast<void*>(&kgdi32G_CreateColorSpaceW));
    e("CreateEnhMetaFileA", reinterpret_cast<void*>(&kgdi32G_CreateEnhMetaFileA));
    e("CreateEnhMetaFileW", reinterpret_cast<void*>(&kgdi32G_CreateEnhMetaFileW));
    e("CreateHalftonePalette", reinterpret_cast<void*>(&kgdi32G_CreateHalftonePalette));
    e("CreateMetaFileA", reinterpret_cast<void*>(&kgdi32G_CreateMetaFileA));
    e("CreateMetaFileW", reinterpret_cast<void*>(&kgdi32G_CreateMetaFileW));
    e("CreateScalableFontResourceA", reinterpret_cast<void*>(&kgdi32G_CreateScalableFontResourceA));
    e("CreateScalableFontResourceW", reinterpret_cast<void*>(&kgdi32G_CreateScalableFontResourceW));
    e("DPtoLP", reinterpret_cast<void*>(&kgdi32G_DPtoLP));
    e("DeleteColorSpace", reinterpret_cast<void*>(&kgdi32G_DeleteColorSpace));
    e("DeleteEnhMetaFile", reinterpret_cast<void*>(&kgdi32G_DeleteEnhMetaFile));
    e("DeleteMetaFile", reinterpret_cast<void*>(&kgdi32G_DeleteMetaFile));
    e("DescribePixelFormat", reinterpret_cast<void*>(&kgdi32G_DescribePixelFormat));
    e("DrawEscape", reinterpret_cast<void*>(&kgdi32G_DrawEscape));
    e("EndDoc", reinterpret_cast<void*>(&kgdi32G_EndDoc));
    e("EndPage", reinterpret_cast<void*>(&kgdi32G_EndPage));
    e("EnumEnhMetaFile", reinterpret_cast<void*>(&kgdi32G_EnumEnhMetaFile));
    e("EnumFontFamiliesA", reinterpret_cast<void*>(&kgdi32G_EnumFontFamiliesA));
    e("EnumFontFamiliesExA", reinterpret_cast<void*>(&kgdi32G_EnumFontFamiliesExA));
    e("EnumFontFamiliesExW", reinterpret_cast<void*>(&kgdi32G_EnumFontFamiliesExW));
    e("EnumFontFamiliesW", reinterpret_cast<void*>(&kgdi32G_EnumFontFamiliesW));
    e("EnumFontsA", reinterpret_cast<void*>(&kgdi32G_EnumFontsA));
    e("EnumFontsW", reinterpret_cast<void*>(&kgdi32G_EnumFontsW));
    e("EnumICMProfilesA", reinterpret_cast<void*>(&kgdi32G_EnumICMProfilesA));
    e("EnumICMProfilesW", reinterpret_cast<void*>(&kgdi32G_EnumICMProfilesW));
    e("EnumMetaFile", reinterpret_cast<void*>(&kgdi32G_EnumMetaFile));
    e("EnumObjects", reinterpret_cast<void*>(&kgdi32G_EnumObjects));
    e("ExtCreateRegion", reinterpret_cast<void*>(&kgdi32G_ExtCreateRegion));
    e("ExtFloodFill", reinterpret_cast<void*>(&kgdi32G_ExtFloodFill));
    e("FillRgn", reinterpret_cast<void*>(&kgdi32G_FillRgn));
    e("FixBrushOrgEx", reinterpret_cast<void*>(&kgdi32G_FixBrushOrgEx));
    e("FloodFill", reinterpret_cast<void*>(&kgdi32G_FloodFill));
    e("FrameRgn", reinterpret_cast<void*>(&kgdi32G_FrameRgn));
    e("GdiAlphaBlend", reinterpret_cast<void*>(&kgdi32G_GdiAlphaBlend));
    e("GdiComment", reinterpret_cast<void*>(&kgdi32G_GdiComment));
    e("GdiGradientFill", reinterpret_cast<void*>(&kgdi32G_GdiGradientFill));
    e("GdiTransparentBlt", reinterpret_cast<void*>(&kgdi32G_GdiTransparentBlt));
    e("GetArcDirection", reinterpret_cast<void*>(&kgdi32G_GetArcDirection));
    e("GetAspectRatioFilterEx", reinterpret_cast<void*>(&kgdi32G_GetAspectRatioFilterEx));
    e("GetBitmapBits", reinterpret_cast<void*>(&kgdi32G_GetBitmapBits));
    e("GetBitmapDimensionEx", reinterpret_cast<void*>(&kgdi32G_GetBitmapDimensionEx));
    e("GetBoundsRect", reinterpret_cast<void*>(&kgdi32G_GetBoundsRect));
    e("GetCharABCWidthsFloatA", reinterpret_cast<void*>(&kgdi32G_GetCharABCWidthsFloatA));
    e("GetCharABCWidthsFloatW", reinterpret_cast<void*>(&kgdi32G_GetCharABCWidthsFloatW));
    e("GetCharABCWidthsI", reinterpret_cast<void*>(&kgdi32G_GetCharABCWidthsI));
    e("GetCharWidth32A", reinterpret_cast<void*>(&kgdi32G_GetCharWidth32A));
    e("GetCharWidth32W", reinterpret_cast<void*>(&kgdi32G_GetCharWidth32W));
    e("GetCharWidthFloatA", reinterpret_cast<void*>(&kgdi32G_GetCharWidthFloatA));
    e("GetCharWidthFloatW", reinterpret_cast<void*>(&kgdi32G_GetCharWidthFloatW));
    e("GetCharWidthI", reinterpret_cast<void*>(&kgdi32G_GetCharWidthI));
    e("GetCharacterPlacementA", reinterpret_cast<void*>(&kgdi32G_GetCharacterPlacementA));
    e("GetCharacterPlacementW", reinterpret_cast<void*>(&kgdi32G_GetCharacterPlacementW));
    e("GetColorAdjustment", reinterpret_cast<void*>(&kgdi32G_GetColorAdjustment));
    e("GetColorSpace", reinterpret_cast<void*>(&kgdi32G_GetColorSpace));
    e("GetCurrentObject", reinterpret_cast<void*>(&kgdi32G_GetCurrentObject));
    e("GetCurrentPositionEx", reinterpret_cast<void*>(&kgdi32G_GetCurrentPositionEx));
    e("GetDCBrushColor", reinterpret_cast<void*>(&kgdi32G_GetDCBrushColor));
    e("GetDCOrgEx", reinterpret_cast<void*>(&kgdi32G_GetDCOrgEx));
    e("GetDCPenColor", reinterpret_cast<void*>(&kgdi32G_GetDCPenColor));
    e("GetDeviceGammaRamp", reinterpret_cast<void*>(&kgdi32G_GetDeviceGammaRamp));
    e("GetEnhMetaFileA", reinterpret_cast<void*>(&kgdi32G_GetEnhMetaFileA));
    e("GetEnhMetaFileBits", reinterpret_cast<void*>(&kgdi32G_GetEnhMetaFileBits));
    e("GetEnhMetaFileDescriptionA", reinterpret_cast<void*>(&kgdi32G_GetEnhMetaFileDescriptionA));
    e("GetEnhMetaFileDescriptionW", reinterpret_cast<void*>(&kgdi32G_GetEnhMetaFileDescriptionW));
    e("GetEnhMetaFileHeader", reinterpret_cast<void*>(&kgdi32G_GetEnhMetaFileHeader));
    e("GetEnhMetaFilePaletteEntries", reinterpret_cast<void*>(&kgdi32G_GetEnhMetaFilePaletteEntries));
    e("GetEnhMetaFilePixelFormat", reinterpret_cast<void*>(&kgdi32G_GetEnhMetaFilePixelFormat));
    e("GetEnhMetaFileW", reinterpret_cast<void*>(&kgdi32G_GetEnhMetaFileW));
    e("GetFontData", reinterpret_cast<void*>(&kgdi32G_GetFontData));
    e("GetFontLanguageInfo", reinterpret_cast<void*>(&kgdi32G_GetFontLanguageInfo));
    e("GetFontUnicodeRanges", reinterpret_cast<void*>(&kgdi32G_GetFontUnicodeRanges));
    e("GetGlyphIndicesA", reinterpret_cast<void*>(&kgdi32G_GetGlyphIndicesA));
    e("GetGlyphIndicesW", reinterpret_cast<void*>(&kgdi32G_GetGlyphIndicesW));
    e("GetGlyphOutlineA", reinterpret_cast<void*>(&kgdi32G_GetGlyphOutlineA));
    e("GetGlyphOutlineW", reinterpret_cast<void*>(&kgdi32G_GetGlyphOutlineW));
    e("GetICMProfileA", reinterpret_cast<void*>(&kgdi32G_GetICMProfileA));
    e("GetICMProfileW", reinterpret_cast<void*>(&kgdi32G_GetICMProfileW));
    e("GetKerningPairsA", reinterpret_cast<void*>(&kgdi32G_GetKerningPairsA));
    e("GetKerningPairsW", reinterpret_cast<void*>(&kgdi32G_GetKerningPairsW));
    e("GetLogColorSpaceA", reinterpret_cast<void*>(&kgdi32G_GetLogColorSpaceA));
    e("GetLogColorSpaceW", reinterpret_cast<void*>(&kgdi32G_GetLogColorSpaceW));
    e("GetMetaFileA", reinterpret_cast<void*>(&kgdi32G_GetMetaFileA));
    e("GetMetaFileBitsEx", reinterpret_cast<void*>(&kgdi32G_GetMetaFileBitsEx));
    e("GetMetaFileW", reinterpret_cast<void*>(&kgdi32G_GetMetaFileW));
    e("GetMetaRgn", reinterpret_cast<void*>(&kgdi32G_GetMetaRgn));
    e("GetMiterLimit", reinterpret_cast<void*>(&kgdi32G_GetMiterLimit));
    e("GetOutlineTextMetricsA", reinterpret_cast<void*>(&kgdi32G_GetOutlineTextMetricsA));
    e("GetOutlineTextMetricsW", reinterpret_cast<void*>(&kgdi32G_GetOutlineTextMetricsW));
    e("GetPixelFormat", reinterpret_cast<void*>(&kgdi32G_GetPixelFormat));
    e("GetRandomRgn", reinterpret_cast<void*>(&kgdi32G_GetRandomRgn));
    e("GetRasterizerCaps", reinterpret_cast<void*>(&kgdi32G_GetRasterizerCaps));
    e("GetRegionData", reinterpret_cast<void*>(&kgdi32G_GetRegionData));
    e("GetTextExtentPointI", reinterpret_cast<void*>(&kgdi32G_GetTextExtentPointI));
    e("GetViewportExtEx", reinterpret_cast<void*>(&kgdi32G_GetViewportExtEx));
    e("GetViewportOrgEx", reinterpret_cast<void*>(&kgdi32G_GetViewportOrgEx));
    e("GetWinMetaFileBits", reinterpret_cast<void*>(&kgdi32G_GetWinMetaFileBits));
    e("GetWindowExtEx", reinterpret_cast<void*>(&kgdi32G_GetWindowExtEx));
    e("GetWindowOrgEx", reinterpret_cast<void*>(&kgdi32G_GetWindowOrgEx));
    e("InvertRgn", reinterpret_cast<void*>(&kgdi32G_InvertRgn));
    e("LPtoDP", reinterpret_cast<void*>(&kgdi32G_LPtoDP));
    e("LineDDA", reinterpret_cast<void*>(&kgdi32G_LineDDA));
    e("MaskBlt", reinterpret_cast<void*>(&kgdi32G_MaskBlt));
    e("PaintRgn", reinterpret_cast<void*>(&kgdi32G_PaintRgn));
    e("PlayEnhMetaFile", reinterpret_cast<void*>(&kgdi32G_PlayEnhMetaFile));
    e("PlayEnhMetaFileRecord", reinterpret_cast<void*>(&kgdi32G_PlayEnhMetaFileRecord));
    e("PlayMetaFile", reinterpret_cast<void*>(&kgdi32G_PlayMetaFile));
    e("PlayMetaFileRecord", reinterpret_cast<void*>(&kgdi32G_PlayMetaFileRecord));
    e("PlgBlt", reinterpret_cast<void*>(&kgdi32G_PlgBlt));
    e("PolyDraw", reinterpret_cast<void*>(&kgdi32G_PolyDraw));
    e("PolyTextOutA", reinterpret_cast<void*>(&kgdi32G_PolyTextOutA));
    e("PolyTextOutW", reinterpret_cast<void*>(&kgdi32G_PolyTextOutW));
    e("RemoveFontMemResourceEx", reinterpret_cast<void*>(&kgdi32G_RemoveFontMemResourceEx));
    e("RemoveFontResourceA", reinterpret_cast<void*>(&kgdi32G_RemoveFontResourceA));
    e("RemoveFontResourceExA", reinterpret_cast<void*>(&kgdi32G_RemoveFontResourceExA));
    e("RemoveFontResourceExW", reinterpret_cast<void*>(&kgdi32G_RemoveFontResourceExW));
    e("RemoveFontResourceW", reinterpret_cast<void*>(&kgdi32G_RemoveFontResourceW));
    e("ResetDCA", reinterpret_cast<void*>(&kgdi32G_ResetDCA));
    e("ResetDCW", reinterpret_cast<void*>(&kgdi32G_ResetDCW));
    e("SetArcDirection", reinterpret_cast<void*>(&kgdi32G_SetArcDirection));
    e("SetBitmapBits", reinterpret_cast<void*>(&kgdi32G_SetBitmapBits));
    e("SetBitmapDimensionEx", reinterpret_cast<void*>(&kgdi32G_SetBitmapDimensionEx));
    e("SetBoundsRect", reinterpret_cast<void*>(&kgdi32G_SetBoundsRect));
    e("SetColorAdjustment", reinterpret_cast<void*>(&kgdi32G_SetColorAdjustment));
    e("SetColorSpace", reinterpret_cast<void*>(&kgdi32G_SetColorSpace));
    e("SetDeviceGammaRamp", reinterpret_cast<void*>(&kgdi32G_SetDeviceGammaRamp));
    e("SetEnhMetaFileBits", reinterpret_cast<void*>(&kgdi32G_SetEnhMetaFileBits));
    e("SetICMMode", reinterpret_cast<void*>(&kgdi32G_SetICMMode));
    e("SetICMProfileA", reinterpret_cast<void*>(&kgdi32G_SetICMProfileA));
    e("SetICMProfileW", reinterpret_cast<void*>(&kgdi32G_SetICMProfileW));
    e("SetMapperFlags", reinterpret_cast<void*>(&kgdi32G_SetMapperFlags));
    e("SetMetaFileBitsEx", reinterpret_cast<void*>(&kgdi32G_SetMetaFileBitsEx));
    e("SetMetaRgn", reinterpret_cast<void*>(&kgdi32G_SetMetaRgn));
    e("SetMiterLimit", reinterpret_cast<void*>(&kgdi32G_SetMiterLimit));
    e("SetPixelFormat", reinterpret_cast<void*>(&kgdi32G_SetPixelFormat));
    e("SetTextJustification", reinterpret_cast<void*>(&kgdi32G_SetTextJustification));
    e("SetWinMetaFileBits", reinterpret_cast<void*>(&kgdi32G_SetWinMetaFileBits));
    e("StartDocA", reinterpret_cast<void*>(&kgdi32G_StartDocA));
    e("StartDocW", reinterpret_cast<void*>(&kgdi32G_StartDocW));
    e("StartPage", reinterpret_cast<void*>(&kgdi32G_StartPage));
    e("SwapBuffers", reinterpret_cast<void*>(&kgdi32G_SwapBuffers));
    e("TranslateCharsetInfo", reinterpret_cast<void*>(&kgdi32G_TranslateCharsetInfo));
    e("UnrealizeObject", reinterpret_cast<void*>(&kgdi32G_UnrealizeObject));
    e("UpdateColors", reinterpret_cast<void*>(&kgdi32G_UpdateColors));
    e("UpdateICMRegKeyA", reinterpret_cast<void*>(&kgdi32G_UpdateICMRegKeyA));
    e("UpdateICMRegKeyW", reinterpret_cast<void*>(&kgdi32G_UpdateICMRegKeyW));
}
}  // namespace occ::runtime::winabi

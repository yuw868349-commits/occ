// The COMCTL32 surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) void* kcomctl32G_CreateMappedBitmap(void* hInstance, std::int64_t idBitmap, std::uint32_t wFlags, std::uint64_t lpColorMap, std::int32_t iNumMaps) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hInstance);
    static_cast<void>(idBitmap);
    static_cast<void>(wFlags);
    static_cast<void>(lpColorMap);
    static_cast<void>(iNumMaps);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_CreatePropertySheetPageA(std::uint64_t constPropSheetPagePointer) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(constPropSheetPagePointer);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_CreatePropertySheetPageW(std::uint64_t constPropSheetPagePointer) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(constPropSheetPagePointer);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_CreateStatusWindowA(std::int32_t style, const char* lpszText, void* hwndParent, std::uint32_t wID) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(style);
    static_cast<void>(lpszText);
    static_cast<void>(hwndParent);
    static_cast<void>(wID);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_CreateStatusWindowW(std::int32_t style, const char16_t* lpszText, void* hwndParent, std::uint32_t wID) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(style);
    static_cast<void>(lpszText);
    static_cast<void>(hwndParent);
    static_cast<void>(wID);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_CreateToolbarEx(void* hwnd, std::uint32_t ws, std::uint32_t wID, std::int32_t nBitmaps, void* hBMInst, std::uint64_t wBMID, void* lpButtons, std::int32_t iNumButtons, std::int32_t dxButton, std::int32_t dyButton, std::int32_t dxBitmap, std::int32_t dyBitmap, std::uint32_t uStructSize) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hwnd);
    static_cast<void>(ws);
    static_cast<void>(wID);
    static_cast<void>(nBitmaps);
    static_cast<void>(hBMInst);
    static_cast<void>(wBMID);
    static_cast<void>(lpButtons);
    static_cast<void>(iNumButtons);
    static_cast<void>(dxButton);
    static_cast<void>(dyButton);
    static_cast<void>(dxBitmap);
    static_cast<void>(dyBitmap);
    static_cast<void>(uStructSize);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_CreateUpDownControl(std::uint32_t dwStyle, std::int32_t x, std::int32_t y, std::int32_t cx, std::int32_t cy, void* hParent, std::int32_t nID, void* hInst, void* hBuddy, std::int32_t nUpper, std::int32_t nLower, std::int32_t nPos) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(dwStyle);
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(cx);
    static_cast<void>(cy);
    static_cast<void>(hParent);
    static_cast<void>(nID);
    static_cast<void>(hInst);
    static_cast<void>(hBuddy);
    static_cast<void>(nUpper);
    static_cast<void>(nLower);
    static_cast<void>(nPos);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_DPA_Clone(void* hdpa, void* hdpaNew) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdpa);
    static_cast<void>(hdpaNew);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_DPA_Create(std::int32_t cItemGrow) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(cItemGrow);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_DPA_CreateEx(std::int32_t cpGrow, void* hheap) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(cpGrow);
    static_cast<void>(hheap);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DPA_DeleteAllPtrs(void* hdpa) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdpa);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_DPA_DeletePtr(void* hdpa, std::int32_t i) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdpa);
    static_cast<void>(i);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DPA_Destroy(void* hdpa) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdpa);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kcomctl32G_DPA_DestroyCallback(void* hdpa, std::uint64_t pfnCB, void* pData) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdpa);
    static_cast<void>(pfnCB);
    static_cast<void>(pData);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kcomctl32G_DPA_EnumCallback(void* hdpa, std::uint64_t pfnCB, void* pData) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdpa);
    static_cast<void>(pfnCB);
    static_cast<void>(pData);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_DPA_GetPtr(void* hdpa, std::int64_t i) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdpa);
    static_cast<void>(i);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DPA_GetPtrIndex(void* hdpa, const void* p) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdpa);
    static_cast<void>(p);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DPA_Grow(void* pdpa, std::int32_t cp) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(pdpa);
    static_cast<void>(cp);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DPA_InsertPtr(void* hdpa, std::int32_t i, void* p) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdpa);
    static_cast<void>(i);
    static_cast<void>(p);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DPA_LoadStream(void* phdpa, std::uint64_t pfn, void* pstream, void* pvInstData) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(phdpa);
    static_cast<void>(pfn);
    static_cast<void>(pstream);
    static_cast<void>(pvInstData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DPA_Merge(void* hdpaDest, void* hdpaSrc, std::uint32_t dwFlags, std::uint64_t pfnCompare, std::uint64_t pfnMerge, std::int64_t lParam) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdpaDest);
    static_cast<void>(hdpaSrc);
    static_cast<void>(dwFlags);
    static_cast<void>(pfnCompare);
    static_cast<void>(pfnMerge);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DPA_SaveStream(void* hdpa, std::uint64_t pfn, void* pstream, void* pvInstData) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdpa);
    static_cast<void>(pfn);
    static_cast<void>(pstream);
    static_cast<void>(pvInstData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DPA_Search(void* hdpa, void* pFind, std::int32_t iStart, std::uint64_t pfnCompare, std::int64_t lParam, std::uint32_t options) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdpa);
    static_cast<void>(pFind);
    static_cast<void>(iStart);
    static_cast<void>(pfnCompare);
    static_cast<void>(lParam);
    static_cast<void>(options);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DPA_SetPtr(void* hdpa, std::int32_t i, void* p) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdpa);
    static_cast<void>(i);
    static_cast<void>(p);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DPA_Sort(void* hdpa, std::uint64_t pfnCompare, std::int64_t lParam) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdpa);
    static_cast<void>(pfnCompare);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_DSA_Create(std::int32_t cbItem, std::int32_t cItemGrow) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(cbItem);
    static_cast<void>(cItemGrow);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DSA_DeleteAllItems(void* hdsa) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdsa);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DSA_DeleteItem(void* hdsa, std::int32_t i) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdsa);
    static_cast<void>(i);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DSA_Destroy(void* hdsa) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdsa);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kcomctl32G_DSA_DestroyCallback(void* hdsa, std::uint64_t pfnCB, void* pData) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdsa);
    static_cast<void>(pfnCB);
    static_cast<void>(pData);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kcomctl32G_DSA_EnumCallback(void* hdsa, std::uint64_t pfnCB, void* pData) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdsa);
    static_cast<void>(pfnCB);
    static_cast<void>(pData);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DSA_GetItem(void* hdsa, std::int32_t i, void* pitem) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdsa);
    static_cast<void>(i);
    static_cast<void>(pitem);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_DSA_GetItemPtr(void* hdsa, std::int32_t i) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdsa);
    static_cast<void>(i);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DSA_InsertItem(void* hdsa, std::int32_t i, const void* pitem) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdsa);
    static_cast<void>(i);
    static_cast<void>(pitem);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DSA_SetItem(void* hdsa, std::int32_t i, const void* pitem) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdsa);
    static_cast<void>(i);
    static_cast<void>(pitem);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kcomctl32G_DefSubclassProc(void* hWnd, std::uint32_t uMsg, std::uint64_t wParam, std::int64_t lParam) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hWnd);
    static_cast<void>(uMsg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DestroyPropertySheetPage(void* arg0) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kcomctl32G_DrawInsert(void* handParent, void* hLB, std::int32_t nItem) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(handParent);
    static_cast<void>(hLB);
    static_cast<void>(nItem);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_DrawShadowText(void* hdc, const char16_t* pszText, std::uint32_t cch, void* prc, std::uint32_t dwFlags, std::uint32_t crText, std::uint32_t crShadow, std::int32_t ixOffset, std::int32_t iyOffset) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hdc);
    static_cast<void>(pszText);
    static_cast<void>(cch);
    static_cast<void>(prc);
    static_cast<void>(dwFlags);
    static_cast<void>(crText);
    static_cast<void>(crShadow);
    static_cast<void>(ixOffset);
    static_cast<void>(iyOffset);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kcomctl32G_DrawStatusTextA(void* hDC, void* lprc, const char* pszText, std::uint32_t uFlags) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hDC);
    static_cast<void>(lprc);
    static_cast<void>(pszText);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kcomctl32G_DrawStatusTextW(void* hDC, void* lprc, const char16_t* pszText, std::uint32_t uFlags) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hDC);
    static_cast<void>(lprc);
    static_cast<void>(pszText);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_FlatSB_EnableScrollBar(void* arg0, std::int32_t arg1, std::uint32_t arg2) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_FlatSB_GetScrollInfo(void* arg0, std::int32_t code, void* arg2) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(arg0);
    static_cast<void>(code);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_FlatSB_GetScrollPos(void* arg0, std::int32_t code) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(arg0);
    static_cast<void>(code);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_FlatSB_GetScrollProp(void* arg0, std::int32_t propIndex, std::int32_t* arg2) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(arg0);
    static_cast<void>(propIndex);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_FlatSB_GetScrollPropPtr(void* arg0, std::int32_t propIndex, std::int64_t* arg2) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(arg0);
    static_cast<void>(propIndex);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_FlatSB_GetScrollRange(void* arg0, std::int32_t code, std::int32_t* arg2, std::int32_t* arg3) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(arg0);
    static_cast<void>(code);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_FlatSB_SetScrollInfo(void* arg0, std::int32_t code, void* arg2, std::int32_t fRedraw) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(arg0);
    static_cast<void>(code);
    static_cast<void>(arg2);
    static_cast<void>(fRedraw);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_FlatSB_SetScrollPos(void* arg0, std::int32_t code, std::int32_t pos, std::int32_t fRedraw) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(arg0);
    static_cast<void>(code);
    static_cast<void>(pos);
    static_cast<void>(fRedraw);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_FlatSB_SetScrollProp(void* arg0, std::uint32_t index, std::int64_t newValue, std::int32_t arg3) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(arg0);
    static_cast<void>(index);
    static_cast<void>(newValue);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_FlatSB_SetScrollRange(void* arg0, std::int32_t code, std::int32_t min, std::int32_t max, std::int32_t fRedraw) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(arg0);
    static_cast<void>(code);
    static_cast<void>(min);
    static_cast<void>(max);
    static_cast<void>(fRedraw);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_FlatSB_ShowScrollBar(void* arg0, std::int32_t code, std::int32_t arg2) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(arg0);
    static_cast<void>(code);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kcomctl32G_GetEffectiveClientRect(void* hWnd, void* lprc, const std::int32_t* lpInfo) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hWnd);
    static_cast<void>(lprc);
    static_cast<void>(lpInfo);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint16_t kcomctl32G_GetMUILanguage() noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_GetWindowSubclass(void* hWnd, std::uint64_t pfnSubclass, std::uint64_t uIdSubclass, std::uint64_t* pdwRefData) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hWnd);
    static_cast<void>(pfnSubclass);
    static_cast<void>(uIdSubclass);
    static_cast<void>(pdwRefData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_HIMAGELIST_QueryInterface(void* himl, std::uint64_t riid, void** ppv) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    static_cast<void>(riid);
    static_cast<void>(ppv);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_Add(void* himl, void* hbmImage, void* hbmMask) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    static_cast<void>(hbmImage);
    static_cast<void>(hbmMask);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_AddMasked(void* himl, void* hbmImage, std::uint32_t crMask) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    static_cast<void>(hbmImage);
    static_cast<void>(crMask);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_BeginDrag(void* himlTrack, std::int32_t iTrack, std::int32_t dxHotspot, std::int32_t dyHotspot) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himlTrack);
    static_cast<void>(iTrack);
    static_cast<void>(dxHotspot);
    static_cast<void>(dyHotspot);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_Copy(void* himlDst, std::int32_t iDst, void* himlSrc, std::int32_t iSrc, std::uint32_t uFlags) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himlDst);
    static_cast<void>(iDst);
    static_cast<void>(himlSrc);
    static_cast<void>(iSrc);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_ImageList_Create(std::int32_t cx, std::int32_t cy, std::uint32_t flags, std::int32_t cInitial, std::int32_t cGrow) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(cx);
    static_cast<void>(cy);
    static_cast<void>(flags);
    static_cast<void>(cInitial);
    static_cast<void>(cGrow);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_Destroy(void* himl) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_DragEnter(void* hwndLock, std::int32_t x, std::int32_t y) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hwndLock);
    static_cast<void>(x);
    static_cast<void>(y);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_DragLeave(void* hwndLock) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hwndLock);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_DragMove(std::int32_t x, std::int32_t y) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(x);
    static_cast<void>(y);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_DragShowNolock(std::int32_t fShow) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(fShow);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_Draw(void* himl, std::int32_t i, void* hdcDst, std::int32_t x, std::int32_t y, std::uint32_t fStyle) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    static_cast<void>(i);
    static_cast<void>(hdcDst);
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(fStyle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_DrawEx(void* himl, std::int32_t i, void* hdcDst, std::int32_t x, std::int32_t y, std::int32_t dx, std::int32_t dy, std::uint32_t rgbBk, std::uint32_t rgbFg, std::uint32_t fStyle) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    static_cast<void>(i);
    static_cast<void>(hdcDst);
    static_cast<void>(x);
    static_cast<void>(y);
    static_cast<void>(dx);
    static_cast<void>(dy);
    static_cast<void>(rgbBk);
    static_cast<void>(rgbFg);
    static_cast<void>(fStyle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_DrawIndirect(void* pimldp) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(pimldp);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_ImageList_Duplicate(void* himl) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kcomctl32G_ImageList_EndDrag() noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kcomctl32G_ImageList_GetBkColor(void* himl) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_ImageList_GetDragImage(std::uint64_t* ppt, std::uint64_t* pptHotspot) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(ppt);
    static_cast<void>(pptHotspot);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_ImageList_GetIcon(void* himl, std::int32_t i, std::uint32_t flags) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    static_cast<void>(i);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_GetIconSize(void* himl, std::int32_t* cx, std::int32_t* cy) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    static_cast<void>(cx);
    static_cast<void>(cy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_GetImageCount(void* himl) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_GetImageInfo(void* himl, std::int32_t i, void* pImageInfo) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    static_cast<void>(i);
    static_cast<void>(pImageInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_ImageList_LoadImageA(void* hi, const char* lpbmp, std::int32_t cx, std::int32_t cGrow, std::uint32_t crMask, std::uint32_t uType, std::uint32_t uFlags) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hi);
    static_cast<void>(lpbmp);
    static_cast<void>(cx);
    static_cast<void>(cGrow);
    static_cast<void>(crMask);
    static_cast<void>(uType);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_ImageList_LoadImageW(void* hi, const char16_t* lpbmp, std::int32_t cx, std::int32_t cGrow, std::uint32_t crMask, std::uint32_t uType, std::uint32_t uFlags) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hi);
    static_cast<void>(lpbmp);
    static_cast<void>(cx);
    static_cast<void>(cGrow);
    static_cast<void>(crMask);
    static_cast<void>(uType);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcomctl32G_ImageList_Merge(void* himl1, std::int32_t i1, void* himl2, std::int32_t i2, std::int32_t dx, std::int32_t dy) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl1);
    static_cast<void>(i1);
    static_cast<void>(himl2);
    static_cast<void>(i2);
    static_cast<void>(dx);
    static_cast<void>(dy);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_Remove(void* himl, std::int32_t i) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    static_cast<void>(i);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_Replace(void* himl, std::int32_t i, void* hbmImage, void* hbmMask) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    static_cast<void>(i);
    static_cast<void>(hbmImage);
    static_cast<void>(hbmMask);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_ReplaceIcon(void* himl, std::int32_t i, void* hicon) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    static_cast<void>(i);
    static_cast<void>(hicon);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kcomctl32G_ImageList_SetBkColor(void* himl, std::uint32_t clrBk) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    static_cast<void>(clrBk);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_SetDragCursorImage(void* himlDrag, std::int32_t iDrag, std::int32_t dxHotspot, std::int32_t dyHotspot) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himlDrag);
    static_cast<void>(iDrag);
    static_cast<void>(dxHotspot);
    static_cast<void>(dyHotspot);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_SetIconSize(void* himl, std::int32_t cx, std::int32_t cy) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    static_cast<void>(cx);
    static_cast<void>(cy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_SetImageCount(void* himl, std::uint32_t uNewCount) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    static_cast<void>(uNewCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ImageList_SetOverlayImage(void* himl, std::int32_t iImage, std::int32_t iOverlay) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(himl);
    static_cast<void>(iImage);
    static_cast<void>(iOverlay);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kcomctl32G_InitCommonControls() noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_InitCommonControlsEx(const void* arg0) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kcomctl32G_InitMUILanguage(std::uint16_t uiLang) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(uiLang);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_InitializeFlatSB(void* arg0) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_LBItemFromPt(void* hLB, std::uint64_t pt, std::int32_t bAutoScroll) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hLB);
    static_cast<void>(pt);
    static_cast<void>(bAutoScroll);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_MakeDragList(void* hLB) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hLB);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kcomctl32G_MenuHelp(std::uint32_t uMsg, std::uint64_t wParam, std::int64_t lParam, void* hMainMenu, void* hInst, void* hwndStatus, std::uint32_t* lpwIDs) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(uMsg);
    static_cast<void>(wParam);
    static_cast<void>(lParam);
    static_cast<void>(hMainMenu);
    static_cast<void>(hInst);
    static_cast<void>(hwndStatus);
    static_cast<void>(lpwIDs);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int64_t kcomctl32G_PropertySheetA(std::uint64_t arg0) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kcomctl32G_PropertySheetW(std::uint64_t arg0) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_RemoveWindowSubclass(void* hWnd, std::uint64_t pfnSubclass, std::uint64_t uIdSubclass) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hWnd);
    static_cast<void>(pfnSubclass);
    static_cast<void>(uIdSubclass);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_SetWindowSubclass(void* hWnd, std::uint64_t pfnSubclass, std::uint64_t uIdSubclass, std::uint64_t dwRefData) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hWnd);
    static_cast<void>(pfnSubclass);
    static_cast<void>(uIdSubclass);
    static_cast<void>(dwRefData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_ShowHideMenuCtl(void* hWnd, std::uint64_t uFlags, std::int32_t* lpInfo) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(hWnd);
    static_cast<void>(uFlags);
    static_cast<void>(lpInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_Str_SetPtrW(char16_t** ppsz, const char16_t* psz) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(ppsz);
    static_cast<void>(psz);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_UninitializeFlatSB(void* arg0) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcomctl32G_TrackMouseEvent(void* lpEventTrack) noexcept {
    // Refused: the common controls.
    //
    // the common controls are windows; every one of these calls names a window
    // handle, and there is no window manager here
    static_cast<void>(lpEventTrack);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_comctl32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CreateMappedBitmap", reinterpret_cast<void*>(&kcomctl32G_CreateMappedBitmap));
    e("CreatePropertySheetPageA", reinterpret_cast<void*>(&kcomctl32G_CreatePropertySheetPageA));
    e("CreatePropertySheetPageW", reinterpret_cast<void*>(&kcomctl32G_CreatePropertySheetPageW));
    e("CreateStatusWindowA", reinterpret_cast<void*>(&kcomctl32G_CreateStatusWindowA));
    e("CreateStatusWindowW", reinterpret_cast<void*>(&kcomctl32G_CreateStatusWindowW));
    e("CreateToolbarEx", reinterpret_cast<void*>(&kcomctl32G_CreateToolbarEx));
    e("CreateUpDownControl", reinterpret_cast<void*>(&kcomctl32G_CreateUpDownControl));
    e("DPA_Clone", reinterpret_cast<void*>(&kcomctl32G_DPA_Clone));
    e("DPA_Create", reinterpret_cast<void*>(&kcomctl32G_DPA_Create));
    e("DPA_CreateEx", reinterpret_cast<void*>(&kcomctl32G_DPA_CreateEx));
    e("DPA_DeleteAllPtrs", reinterpret_cast<void*>(&kcomctl32G_DPA_DeleteAllPtrs));
    e("DPA_DeletePtr", reinterpret_cast<void*>(&kcomctl32G_DPA_DeletePtr));
    e("DPA_Destroy", reinterpret_cast<void*>(&kcomctl32G_DPA_Destroy));
    e("DPA_DestroyCallback", reinterpret_cast<void*>(&kcomctl32G_DPA_DestroyCallback));
    e("DPA_EnumCallback", reinterpret_cast<void*>(&kcomctl32G_DPA_EnumCallback));
    e("DPA_GetPtr", reinterpret_cast<void*>(&kcomctl32G_DPA_GetPtr));
    e("DPA_GetPtrIndex", reinterpret_cast<void*>(&kcomctl32G_DPA_GetPtrIndex));
    e("DPA_Grow", reinterpret_cast<void*>(&kcomctl32G_DPA_Grow));
    e("DPA_InsertPtr", reinterpret_cast<void*>(&kcomctl32G_DPA_InsertPtr));
    e("DPA_LoadStream", reinterpret_cast<void*>(&kcomctl32G_DPA_LoadStream));
    e("DPA_Merge", reinterpret_cast<void*>(&kcomctl32G_DPA_Merge));
    e("DPA_SaveStream", reinterpret_cast<void*>(&kcomctl32G_DPA_SaveStream));
    e("DPA_Search", reinterpret_cast<void*>(&kcomctl32G_DPA_Search));
    e("DPA_SetPtr", reinterpret_cast<void*>(&kcomctl32G_DPA_SetPtr));
    e("DPA_Sort", reinterpret_cast<void*>(&kcomctl32G_DPA_Sort));
    e("DSA_Create", reinterpret_cast<void*>(&kcomctl32G_DSA_Create));
    e("DSA_DeleteAllItems", reinterpret_cast<void*>(&kcomctl32G_DSA_DeleteAllItems));
    e("DSA_DeleteItem", reinterpret_cast<void*>(&kcomctl32G_DSA_DeleteItem));
    e("DSA_Destroy", reinterpret_cast<void*>(&kcomctl32G_DSA_Destroy));
    e("DSA_DestroyCallback", reinterpret_cast<void*>(&kcomctl32G_DSA_DestroyCallback));
    e("DSA_EnumCallback", reinterpret_cast<void*>(&kcomctl32G_DSA_EnumCallback));
    e("DSA_GetItem", reinterpret_cast<void*>(&kcomctl32G_DSA_GetItem));
    e("DSA_GetItemPtr", reinterpret_cast<void*>(&kcomctl32G_DSA_GetItemPtr));
    e("DSA_InsertItem", reinterpret_cast<void*>(&kcomctl32G_DSA_InsertItem));
    e("DSA_SetItem", reinterpret_cast<void*>(&kcomctl32G_DSA_SetItem));
    e("DefSubclassProc", reinterpret_cast<void*>(&kcomctl32G_DefSubclassProc));
    e("DestroyPropertySheetPage", reinterpret_cast<void*>(&kcomctl32G_DestroyPropertySheetPage));
    e("DrawInsert", reinterpret_cast<void*>(&kcomctl32G_DrawInsert));
    e("DrawShadowText", reinterpret_cast<void*>(&kcomctl32G_DrawShadowText));
    e("DrawStatusTextA", reinterpret_cast<void*>(&kcomctl32G_DrawStatusTextA));
    e("DrawStatusTextW", reinterpret_cast<void*>(&kcomctl32G_DrawStatusTextW));
    e("FlatSB_EnableScrollBar", reinterpret_cast<void*>(&kcomctl32G_FlatSB_EnableScrollBar));
    e("FlatSB_GetScrollInfo", reinterpret_cast<void*>(&kcomctl32G_FlatSB_GetScrollInfo));
    e("FlatSB_GetScrollPos", reinterpret_cast<void*>(&kcomctl32G_FlatSB_GetScrollPos));
    e("FlatSB_GetScrollProp", reinterpret_cast<void*>(&kcomctl32G_FlatSB_GetScrollProp));
    e("FlatSB_GetScrollPropPtr", reinterpret_cast<void*>(&kcomctl32G_FlatSB_GetScrollPropPtr));
    e("FlatSB_GetScrollRange", reinterpret_cast<void*>(&kcomctl32G_FlatSB_GetScrollRange));
    e("FlatSB_SetScrollInfo", reinterpret_cast<void*>(&kcomctl32G_FlatSB_SetScrollInfo));
    e("FlatSB_SetScrollPos", reinterpret_cast<void*>(&kcomctl32G_FlatSB_SetScrollPos));
    e("FlatSB_SetScrollProp", reinterpret_cast<void*>(&kcomctl32G_FlatSB_SetScrollProp));
    e("FlatSB_SetScrollRange", reinterpret_cast<void*>(&kcomctl32G_FlatSB_SetScrollRange));
    e("FlatSB_ShowScrollBar", reinterpret_cast<void*>(&kcomctl32G_FlatSB_ShowScrollBar));
    e("GetEffectiveClientRect", reinterpret_cast<void*>(&kcomctl32G_GetEffectiveClientRect));
    e("GetMUILanguage", reinterpret_cast<void*>(&kcomctl32G_GetMUILanguage));
    e("GetWindowSubclass", reinterpret_cast<void*>(&kcomctl32G_GetWindowSubclass));
    e("HIMAGELIST_QueryInterface", reinterpret_cast<void*>(&kcomctl32G_HIMAGELIST_QueryInterface));
    e("ImageList_Add", reinterpret_cast<void*>(&kcomctl32G_ImageList_Add));
    e("ImageList_AddMasked", reinterpret_cast<void*>(&kcomctl32G_ImageList_AddMasked));
    e("ImageList_BeginDrag", reinterpret_cast<void*>(&kcomctl32G_ImageList_BeginDrag));
    e("ImageList_Copy", reinterpret_cast<void*>(&kcomctl32G_ImageList_Copy));
    e("ImageList_Create", reinterpret_cast<void*>(&kcomctl32G_ImageList_Create));
    e("ImageList_Destroy", reinterpret_cast<void*>(&kcomctl32G_ImageList_Destroy));
    e("ImageList_DragEnter", reinterpret_cast<void*>(&kcomctl32G_ImageList_DragEnter));
    e("ImageList_DragLeave", reinterpret_cast<void*>(&kcomctl32G_ImageList_DragLeave));
    e("ImageList_DragMove", reinterpret_cast<void*>(&kcomctl32G_ImageList_DragMove));
    e("ImageList_DragShowNolock", reinterpret_cast<void*>(&kcomctl32G_ImageList_DragShowNolock));
    e("ImageList_Draw", reinterpret_cast<void*>(&kcomctl32G_ImageList_Draw));
    e("ImageList_DrawEx", reinterpret_cast<void*>(&kcomctl32G_ImageList_DrawEx));
    e("ImageList_DrawIndirect", reinterpret_cast<void*>(&kcomctl32G_ImageList_DrawIndirect));
    e("ImageList_Duplicate", reinterpret_cast<void*>(&kcomctl32G_ImageList_Duplicate));
    e("ImageList_EndDrag", reinterpret_cast<void*>(&kcomctl32G_ImageList_EndDrag));
    e("ImageList_GetBkColor", reinterpret_cast<void*>(&kcomctl32G_ImageList_GetBkColor));
    e("ImageList_GetDragImage", reinterpret_cast<void*>(&kcomctl32G_ImageList_GetDragImage));
    e("ImageList_GetIcon", reinterpret_cast<void*>(&kcomctl32G_ImageList_GetIcon));
    e("ImageList_GetIconSize", reinterpret_cast<void*>(&kcomctl32G_ImageList_GetIconSize));
    e("ImageList_GetImageCount", reinterpret_cast<void*>(&kcomctl32G_ImageList_GetImageCount));
    e("ImageList_GetImageInfo", reinterpret_cast<void*>(&kcomctl32G_ImageList_GetImageInfo));
    e("ImageList_LoadImageA", reinterpret_cast<void*>(&kcomctl32G_ImageList_LoadImageA));
    e("ImageList_LoadImageW", reinterpret_cast<void*>(&kcomctl32G_ImageList_LoadImageW));
    e("ImageList_Merge", reinterpret_cast<void*>(&kcomctl32G_ImageList_Merge));
    e("ImageList_Remove", reinterpret_cast<void*>(&kcomctl32G_ImageList_Remove));
    e("ImageList_Replace", reinterpret_cast<void*>(&kcomctl32G_ImageList_Replace));
    e("ImageList_ReplaceIcon", reinterpret_cast<void*>(&kcomctl32G_ImageList_ReplaceIcon));
    e("ImageList_SetBkColor", reinterpret_cast<void*>(&kcomctl32G_ImageList_SetBkColor));
    e("ImageList_SetDragCursorImage", reinterpret_cast<void*>(&kcomctl32G_ImageList_SetDragCursorImage));
    e("ImageList_SetIconSize", reinterpret_cast<void*>(&kcomctl32G_ImageList_SetIconSize));
    e("ImageList_SetImageCount", reinterpret_cast<void*>(&kcomctl32G_ImageList_SetImageCount));
    e("ImageList_SetOverlayImage", reinterpret_cast<void*>(&kcomctl32G_ImageList_SetOverlayImage));
    e("InitCommonControls", reinterpret_cast<void*>(&kcomctl32G_InitCommonControls));
    e("InitCommonControlsEx", reinterpret_cast<void*>(&kcomctl32G_InitCommonControlsEx));
    e("InitMUILanguage", reinterpret_cast<void*>(&kcomctl32G_InitMUILanguage));
    e("InitializeFlatSB", reinterpret_cast<void*>(&kcomctl32G_InitializeFlatSB));
    e("LBItemFromPt", reinterpret_cast<void*>(&kcomctl32G_LBItemFromPt));
    e("MakeDragList", reinterpret_cast<void*>(&kcomctl32G_MakeDragList));
    e("MenuHelp", reinterpret_cast<void*>(&kcomctl32G_MenuHelp));
    e("PropertySheetA", reinterpret_cast<void*>(&kcomctl32G_PropertySheetA));
    e("PropertySheetW", reinterpret_cast<void*>(&kcomctl32G_PropertySheetW));
    e("RemoveWindowSubclass", reinterpret_cast<void*>(&kcomctl32G_RemoveWindowSubclass));
    e("SetWindowSubclass", reinterpret_cast<void*>(&kcomctl32G_SetWindowSubclass));
    e("ShowHideMenuCtl", reinterpret_cast<void*>(&kcomctl32G_ShowHideMenuCtl));
    e("Str_SetPtrW", reinterpret_cast<void*>(&kcomctl32G_Str_SetPtrW));
    e("UninitializeFlatSB", reinterpret_cast<void*>(&kcomctl32G_UninitializeFlatSB));
    e("_TrackMouseEvent", reinterpret_cast<void*>(&kcomctl32G_TrackMouseEvent));
}
}  // namespace occ::runtime::winabi

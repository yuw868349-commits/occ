// The IMM32 surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) void* kimm32G_ImmAssociateContext(void* arg0, void* arg1) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmAssociateContextEx(void* arg0, void* arg1, std::uint32_t arg2) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmConfigureIMEA(void* arg0, void* arg1, std::uint32_t arg2, void* arg3) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmConfigureIMEW(void* arg0, void* arg1, std::uint32_t arg2, void* arg3) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kimm32G_ImmCreateContext() noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmDestroyContext(void* arg0) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmDisableIME(std::uint32_t arg0) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmDisableTextFrameService(std::uint32_t idThread) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(idThread);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmEnumInputContext(std::uint32_t idThread, void* lpfn, std::int64_t lParam) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(idThread);
    static_cast<void>(lpfn);
    static_cast<void>(lParam);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmEnumRegisterWordA(void* arg0, std::uint64_t arg1, const char* lpszReading, std::uint32_t arg3, const char* lpszRegister, void* arg5) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(lpszReading);
    static_cast<void>(arg3);
    static_cast<void>(lpszRegister);
    static_cast<void>(arg5);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmEnumRegisterWordW(void* arg0, std::uint64_t arg1, const char16_t* lpszReading, std::uint32_t arg3, const char16_t* lpszRegister, void* arg5) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(lpszReading);
    static_cast<void>(arg3);
    static_cast<void>(lpszRegister);
    static_cast<void>(arg5);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kimm32G_ImmEscapeA(void* arg0, void* arg1, std::uint32_t arg2, void* arg3) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kimm32G_ImmEscapeW(void* arg0, void* arg1, std::uint32_t arg2, void* arg3) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetCandidateListA(void* arg0, std::uint32_t deIndex, void* arg2, std::uint32_t dwBufLen) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(deIndex);
    static_cast<void>(arg2);
    static_cast<void>(dwBufLen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetCandidateListCountA(void* arg0, std::uint32_t* lpdwListCount) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(lpdwListCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetCandidateListCountW(void* arg0, std::uint32_t* lpdwListCount) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(lpdwListCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetCandidateListW(void* arg0, std::uint32_t deIndex, void* arg2, std::uint32_t dwBufLen) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(deIndex);
    static_cast<void>(arg2);
    static_cast<void>(dwBufLen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmGetCandidateWindow(void* arg0, std::uint32_t arg1, void* arg2) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmGetCompositionStringA(void* arg0, std::uint32_t arg1, void* arg2, std::uint32_t arg3) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmGetCompositionStringW(void* arg0, std::uint32_t arg1, void* arg2, std::uint32_t arg3) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmGetCompositionWindow(void* arg0, void* arg1) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kimm32G_ImmGetContext(void* arg0) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetConversionListA(void* arg0, void* arg1, const char* arg2, void* arg3, std::uint32_t dwBufLen, std::uint32_t uFlag) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(dwBufLen);
    static_cast<void>(uFlag);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetConversionListW(void* arg0, void* arg1, const char16_t* arg2, void* arg3, std::uint32_t dwBufLen, std::uint32_t uFlag) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(dwBufLen);
    static_cast<void>(uFlag);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmGetConversionStatus(void* arg0, std::uint32_t* arg1, std::uint32_t* arg2) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kimm32G_ImmGetDefaultIMEWnd(void* arg0) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetDescriptionA(void* arg0, char* arg1, std::uint32_t uBufLen) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(uBufLen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetDescriptionW(void* arg0, char16_t* arg1, std::uint32_t uBufLen) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(uBufLen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetGuideLineA(void* arg0, std::uint32_t dwIndex, char* arg2, std::uint32_t dwBufLen) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(dwIndex);
    static_cast<void>(arg2);
    static_cast<void>(dwBufLen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetGuideLineW(void* arg0, std::uint32_t dwIndex, char16_t* arg2, std::uint32_t dwBufLen) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(dwIndex);
    static_cast<void>(arg2);
    static_cast<void>(dwBufLen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetIMEFileNameA(void* arg0, char* arg1, std::uint32_t uBufLen) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(uBufLen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetIMEFileNameW(void* arg0, char16_t* arg1, std::uint32_t uBufLen) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(uBufLen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetImeMenuItemsA(void* arg0, std::uint32_t arg1, std::uint32_t arg2, std::uint64_t arg3, std::uint64_t arg4, std::uint32_t arg5) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    static_cast<void>(arg5);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetImeMenuItemsW(void* arg0, std::uint32_t arg1, std::uint32_t arg2, std::uint64_t arg3, std::uint64_t arg4, std::uint32_t arg5) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    static_cast<void>(arg5);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmGetOpenStatus(void* arg0) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetProperty(void* arg0, std::uint32_t arg1) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetRegisterWordStyleA(void* arg0, std::uint32_t nItem, std::uint64_t arg2) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(nItem);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetRegisterWordStyleW(void* arg0, std::uint32_t nItem, std::uint64_t arg2) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(nItem);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmGetStatusWindowPos(void* arg0, void* arg1) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kimm32G_ImmGetVirtualKey(void* arg0) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kimm32G_ImmInstallIMEA(const char* lpszIMEFileName, const char* lpszLayoutText) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(lpszIMEFileName);
    static_cast<void>(lpszLayoutText);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kimm32G_ImmInstallIMEW(const char16_t* lpszIMEFileName, const char16_t* lpszLayoutText) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(lpszIMEFileName);
    static_cast<void>(lpszLayoutText);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmIsIME(void* arg0) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmIsUIMessageA(void* arg0, std::uint32_t arg1, std::uint64_t arg2, std::int64_t arg3) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmIsUIMessageW(void* arg0, std::uint32_t arg1, std::uint64_t arg2, std::int64_t arg3) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmNotifyIME(void* arg0, std::uint32_t dwAction, std::uint32_t dwIndex, std::uint32_t dwValue) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(dwAction);
    static_cast<void>(dwIndex);
    static_cast<void>(dwValue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmRegisterWordA(void* arg0, const char* lpszReading, std::uint32_t arg2, const char* lpszRegister) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(lpszReading);
    static_cast<void>(arg2);
    static_cast<void>(lpszRegister);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmRegisterWordW(void* arg0, const char16_t* lpszReading, std::uint32_t arg2, const char16_t* lpszRegister) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(lpszReading);
    static_cast<void>(arg2);
    static_cast<void>(lpszRegister);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmReleaseContext(void* arg0, void* arg1) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmSetCandidateWindow(void* arg0, void* arg1) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmSetCompositionStringA(void* arg0, std::uint32_t dwIndex, void* lpComp, std::uint32_t arg3, void* lpRead, std::uint32_t arg5) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(dwIndex);
    static_cast<void>(lpComp);
    static_cast<void>(arg3);
    static_cast<void>(lpRead);
    static_cast<void>(arg5);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmSetCompositionStringW(void* arg0, std::uint32_t dwIndex, void* lpComp, std::uint32_t arg3, void* lpRead, std::uint32_t arg5) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(dwIndex);
    static_cast<void>(lpComp);
    static_cast<void>(arg3);
    static_cast<void>(lpRead);
    static_cast<void>(arg5);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmSetCompositionWindow(void* arg0, void* arg1) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmSetConversionStatus(void* arg0, std::uint32_t arg1, std::uint32_t arg2) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmSetOpenStatus(void* arg0, std::int32_t arg1) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmSetStatusWindowPos(void* arg0, void* arg1) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmSimulateHotKey(void* arg0, std::uint32_t arg1) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmUnregisterWordA(void* arg0, const char* lpszReading, std::uint32_t arg2, const char* lpszUnregister) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(lpszReading);
    static_cast<void>(arg2);
    static_cast<void>(lpszUnregister);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kimm32G_ImmUnregisterWordW(void* arg0, const char16_t* lpszReading, std::uint32_t arg2, const char16_t* lpszUnregister) noexcept {
    // Refused: the input method editor.
    //
    // an input context belongs to a window and to the input queue of the
    // window manager, neither of which this runtime has
    static_cast<void>(arg0);
    static_cast<void>(lpszReading);
    static_cast<void>(arg2);
    static_cast<void>(lpszUnregister);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_imm32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("ImmAssociateContext", reinterpret_cast<void*>(&kimm32G_ImmAssociateContext));
    e("ImmAssociateContextEx", reinterpret_cast<void*>(&kimm32G_ImmAssociateContextEx));
    e("ImmConfigureIMEA", reinterpret_cast<void*>(&kimm32G_ImmConfigureIMEA));
    e("ImmConfigureIMEW", reinterpret_cast<void*>(&kimm32G_ImmConfigureIMEW));
    e("ImmCreateContext", reinterpret_cast<void*>(&kimm32G_ImmCreateContext));
    e("ImmDestroyContext", reinterpret_cast<void*>(&kimm32G_ImmDestroyContext));
    e("ImmDisableIME", reinterpret_cast<void*>(&kimm32G_ImmDisableIME));
    e("ImmDisableTextFrameService", reinterpret_cast<void*>(&kimm32G_ImmDisableTextFrameService));
    e("ImmEnumInputContext", reinterpret_cast<void*>(&kimm32G_ImmEnumInputContext));
    e("ImmEnumRegisterWordA", reinterpret_cast<void*>(&kimm32G_ImmEnumRegisterWordA));
    e("ImmEnumRegisterWordW", reinterpret_cast<void*>(&kimm32G_ImmEnumRegisterWordW));
    e("ImmEscapeA", reinterpret_cast<void*>(&kimm32G_ImmEscapeA));
    e("ImmEscapeW", reinterpret_cast<void*>(&kimm32G_ImmEscapeW));
    e("ImmGetCandidateListA", reinterpret_cast<void*>(&kimm32G_ImmGetCandidateListA));
    e("ImmGetCandidateListCountA", reinterpret_cast<void*>(&kimm32G_ImmGetCandidateListCountA));
    e("ImmGetCandidateListCountW", reinterpret_cast<void*>(&kimm32G_ImmGetCandidateListCountW));
    e("ImmGetCandidateListW", reinterpret_cast<void*>(&kimm32G_ImmGetCandidateListW));
    e("ImmGetCandidateWindow", reinterpret_cast<void*>(&kimm32G_ImmGetCandidateWindow));
    e("ImmGetCompositionStringA", reinterpret_cast<void*>(&kimm32G_ImmGetCompositionStringA));
    e("ImmGetCompositionStringW", reinterpret_cast<void*>(&kimm32G_ImmGetCompositionStringW));
    e("ImmGetCompositionWindow", reinterpret_cast<void*>(&kimm32G_ImmGetCompositionWindow));
    e("ImmGetContext", reinterpret_cast<void*>(&kimm32G_ImmGetContext));
    e("ImmGetConversionListA", reinterpret_cast<void*>(&kimm32G_ImmGetConversionListA));
    e("ImmGetConversionListW", reinterpret_cast<void*>(&kimm32G_ImmGetConversionListW));
    e("ImmGetConversionStatus", reinterpret_cast<void*>(&kimm32G_ImmGetConversionStatus));
    e("ImmGetDefaultIMEWnd", reinterpret_cast<void*>(&kimm32G_ImmGetDefaultIMEWnd));
    e("ImmGetDescriptionA", reinterpret_cast<void*>(&kimm32G_ImmGetDescriptionA));
    e("ImmGetDescriptionW", reinterpret_cast<void*>(&kimm32G_ImmGetDescriptionW));
    e("ImmGetGuideLineA", reinterpret_cast<void*>(&kimm32G_ImmGetGuideLineA));
    e("ImmGetGuideLineW", reinterpret_cast<void*>(&kimm32G_ImmGetGuideLineW));
    e("ImmGetIMEFileNameA", reinterpret_cast<void*>(&kimm32G_ImmGetIMEFileNameA));
    e("ImmGetIMEFileNameW", reinterpret_cast<void*>(&kimm32G_ImmGetIMEFileNameW));
    e("ImmGetImeMenuItemsA", reinterpret_cast<void*>(&kimm32G_ImmGetImeMenuItemsA));
    e("ImmGetImeMenuItemsW", reinterpret_cast<void*>(&kimm32G_ImmGetImeMenuItemsW));
    e("ImmGetOpenStatus", reinterpret_cast<void*>(&kimm32G_ImmGetOpenStatus));
    e("ImmGetProperty", reinterpret_cast<void*>(&kimm32G_ImmGetProperty));
    e("ImmGetRegisterWordStyleA", reinterpret_cast<void*>(&kimm32G_ImmGetRegisterWordStyleA));
    e("ImmGetRegisterWordStyleW", reinterpret_cast<void*>(&kimm32G_ImmGetRegisterWordStyleW));
    e("ImmGetStatusWindowPos", reinterpret_cast<void*>(&kimm32G_ImmGetStatusWindowPos));
    e("ImmGetVirtualKey", reinterpret_cast<void*>(&kimm32G_ImmGetVirtualKey));
    e("ImmInstallIMEA", reinterpret_cast<void*>(&kimm32G_ImmInstallIMEA));
    e("ImmInstallIMEW", reinterpret_cast<void*>(&kimm32G_ImmInstallIMEW));
    e("ImmIsIME", reinterpret_cast<void*>(&kimm32G_ImmIsIME));
    e("ImmIsUIMessageA", reinterpret_cast<void*>(&kimm32G_ImmIsUIMessageA));
    e("ImmIsUIMessageW", reinterpret_cast<void*>(&kimm32G_ImmIsUIMessageW));
    e("ImmNotifyIME", reinterpret_cast<void*>(&kimm32G_ImmNotifyIME));
    e("ImmRegisterWordA", reinterpret_cast<void*>(&kimm32G_ImmRegisterWordA));
    e("ImmRegisterWordW", reinterpret_cast<void*>(&kimm32G_ImmRegisterWordW));
    e("ImmReleaseContext", reinterpret_cast<void*>(&kimm32G_ImmReleaseContext));
    e("ImmSetCandidateWindow", reinterpret_cast<void*>(&kimm32G_ImmSetCandidateWindow));
    e("ImmSetCompositionStringA", reinterpret_cast<void*>(&kimm32G_ImmSetCompositionStringA));
    e("ImmSetCompositionStringW", reinterpret_cast<void*>(&kimm32G_ImmSetCompositionStringW));
    e("ImmSetCompositionWindow", reinterpret_cast<void*>(&kimm32G_ImmSetCompositionWindow));
    e("ImmSetConversionStatus", reinterpret_cast<void*>(&kimm32G_ImmSetConversionStatus));
    e("ImmSetOpenStatus", reinterpret_cast<void*>(&kimm32G_ImmSetOpenStatus));
    e("ImmSetStatusWindowPos", reinterpret_cast<void*>(&kimm32G_ImmSetStatusWindowPos));
    e("ImmSimulateHotKey", reinterpret_cast<void*>(&kimm32G_ImmSimulateHotKey));
    e("ImmUnregisterWordA", reinterpret_cast<void*>(&kimm32G_ImmUnregisterWordA));
    e("ImmUnregisterWordW", reinterpret_cast<void*>(&kimm32G_ImmUnregisterWordW));
}
}  // namespace occ::runtime::winabi

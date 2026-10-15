// The WINMM surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int64_t kwinmmG_CloseDriver(std::uint64_t hDriver, std::int64_t lParam1, std::int64_t lParam2) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hDriver);
    static_cast<void>(lParam1);
    static_cast<void>(lParam2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kwinmmG_DefDriverProc(std::uint64_t dwDriverIdentifier, std::uint64_t hdrvr, std::uint32_t uMsg, std::int64_t lParam1, std::int64_t lParam2) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(dwDriverIdentifier);
    static_cast<void>(hdrvr);
    static_cast<void>(uMsg);
    static_cast<void>(lParam1);
    static_cast<void>(lParam2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinmmG_DriverCallback(std::uint64_t dwCallback, std::uint32_t dwFlags, std::uint64_t hDevice, std::uint32_t dwMsg, std::uint64_t dwUser, std::uint64_t dwParam1, std::uint64_t dwParam2) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(dwCallback);
    static_cast<void>(dwFlags);
    static_cast<void>(hDevice);
    static_cast<void>(dwMsg);
    static_cast<void>(dwUser);
    static_cast<void>(dwParam1);
    static_cast<void>(dwParam2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwinmmG_DrvGetModuleHandle(std::uint64_t hDriver) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(hDriver);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwinmmG_GetDriverModuleHandle(std::uint64_t hDriver) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hDriver);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kwinmmG_OpenDriver(const char16_t* szDriverName, const char16_t* szSectionName, std::int64_t lParam2) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(szDriverName);
    static_cast<void>(szSectionName);
    static_cast<void>(lParam2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinmmG_PlaySoundA(const char* pszSound, void* hmod, std::uint32_t fdwSound) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(pszSound);
    static_cast<void>(hmod);
    static_cast<void>(fdwSound);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinmmG_PlaySoundW(const char16_t* pszSound, void* hmod, std::uint32_t fdwSound) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(pszSound);
    static_cast<void>(hmod);
    static_cast<void>(fdwSound);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kwinmmG_SendDriverMessage(std::uint64_t hDriver, std::uint32_t message, std::int64_t lParam1, std::int64_t lParam2) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hDriver);
    static_cast<void>(message);
    static_cast<void>(lParam1);
    static_cast<void>(lParam2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_auxGetDevCapsA(std::uint64_t uDeviceID, std::uint64_t pac, std::uint32_t cbac) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uDeviceID);
    static_cast<void>(pac);
    static_cast<void>(cbac);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_auxGetDevCapsW(std::uint64_t uDeviceID, std::uint64_t pac, std::uint32_t cbac) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uDeviceID);
    static_cast<void>(pac);
    static_cast<void>(cbac);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_auxGetNumDevs() noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_auxGetVolume(std::uint32_t uDeviceID, std::uint32_t* pdwVolume) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uDeviceID);
    static_cast<void>(pdwVolume);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_auxOutMessage(std::uint32_t uDeviceID, std::uint32_t uMsg, std::uint64_t dw1, std::uint64_t dw2) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uDeviceID);
    static_cast<void>(uMsg);
    static_cast<void>(dw1);
    static_cast<void>(dw2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_auxSetVolume(std::uint32_t uDeviceID, std::uint32_t dwVolume) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uDeviceID);
    static_cast<void>(dwVolume);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_joyConfigChanged(std::uint32_t dwFlags) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_joyGetDevCapsA(std::uint64_t uJoyID, void* pjc, std::uint32_t cbjc) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uJoyID);
    static_cast<void>(pjc);
    static_cast<void>(cbjc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_joyGetDevCapsW(std::uint64_t uJoyID, std::uint64_t pjc, std::uint32_t cbjc) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uJoyID);
    static_cast<void>(pjc);
    static_cast<void>(cbjc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_joyGetNumDevs() noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_joyGetPos(std::uint32_t uJoyID, void* pji) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uJoyID);
    static_cast<void>(pji);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_joyGetPosEx(std::uint32_t uJoyID, void* pji) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uJoyID);
    static_cast<void>(pji);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_joyGetThreshold(std::uint32_t uJoyID, std::uint32_t* puThreshold) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uJoyID);
    static_cast<void>(puThreshold);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_joyReleaseCapture(std::uint32_t uJoyID) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uJoyID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_joySetCapture(void* hwnd, std::uint32_t uJoyID, std::uint32_t uPeriod, std::int32_t fChanged) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwnd);
    static_cast<void>(uJoyID);
    static_cast<void>(uPeriod);
    static_cast<void>(fChanged);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_joySetThreshold(std::uint32_t uJoyID, std::uint32_t uThreshold) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uJoyID);
    static_cast<void>(uThreshold);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinmmG_mciDriverNotify(void* hwndCallback, std::uint32_t wDeviceID, std::uint32_t uStatus) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwndCallback);
    static_cast<void>(wDeviceID);
    static_cast<void>(uStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mciDriverYield(std::uint32_t wDeviceID) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(wDeviceID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinmmG_mciExecute(const char* pszCommand) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(pszCommand);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinmmG_mciFreeCommandResource(std::uint32_t wTable) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(wTable);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kwinmmG_mciGetCreatorTask(std::uint32_t mciId) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(mciId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mciGetDeviceIDA(const char* pszDevice) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(pszDevice);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mciGetDeviceIDFromElementIDA(std::uint32_t dwElementID, const char* lpstrType) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(dwElementID);
    static_cast<void>(lpstrType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mciGetDeviceIDFromElementIDW(std::uint32_t dwElementID, const char16_t* lpstrType) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(dwElementID);
    static_cast<void>(lpstrType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mciGetDeviceIDW(const char16_t* pszDevice) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(pszDevice);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kwinmmG_mciGetDriverData(std::uint32_t wDeviceID) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(wDeviceID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinmmG_mciGetErrorStringA(std::uint32_t mcierr, char* pszText, std::uint32_t cchText) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(mcierr);
    static_cast<void>(pszText);
    static_cast<void>(cchText);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinmmG_mciGetErrorStringW(std::uint32_t mcierr, char16_t* pszText, std::uint32_t cchText) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(mcierr);
    static_cast<void>(pszText);
    static_cast<void>(cchText);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kwinmmG_mciGetYieldProc(std::uint32_t mciId, std::uint32_t* pdwYieldData) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(mciId);
    static_cast<void>(pdwYieldData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mciLoadCommandResource(void* hInstance, const char16_t* lpResName, std::uint32_t wType) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hInstance);
    static_cast<void>(lpResName);
    static_cast<void>(wType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mciSendCommandA(std::uint32_t mciId, std::uint32_t uMsg, std::uint64_t dwParam1, std::uint64_t dwParam2) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(mciId);
    static_cast<void>(uMsg);
    static_cast<void>(dwParam1);
    static_cast<void>(dwParam2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mciSendCommandW(std::uint32_t mciId, std::uint32_t uMsg, std::uint64_t dwParam1, std::uint64_t dwParam2) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(mciId);
    static_cast<void>(uMsg);
    static_cast<void>(dwParam1);
    static_cast<void>(dwParam2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mciSendStringA(const char* lpstrCommand, char* lpstrReturnString, std::uint32_t uReturnLength, void* hwndCallback) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(lpstrCommand);
    static_cast<void>(lpstrReturnString);
    static_cast<void>(uReturnLength);
    static_cast<void>(hwndCallback);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mciSendStringW(const char16_t* lpstrCommand, char16_t* lpstrReturnString, std::uint32_t uReturnLength, void* hwndCallback) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(lpstrCommand);
    static_cast<void>(lpstrReturnString);
    static_cast<void>(uReturnLength);
    static_cast<void>(hwndCallback);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinmmG_mciSetDriverData(std::uint32_t wDeviceID, std::uint64_t dwData) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(wDeviceID);
    static_cast<void>(dwData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinmmG_mciSetYieldProc(std::uint32_t mciId, std::uint64_t fpYieldProc, std::uint32_t dwYieldData) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(mciId);
    static_cast<void>(fpYieldProc);
    static_cast<void>(dwYieldData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiConnect(std::uint64_t hmi, void* hmo, void* pReserved) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmi);
    static_cast<void>(hmo);
    static_cast<void>(pReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiDisconnect(std::uint64_t hmi, void* hmo, void* pReserved) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmi);
    static_cast<void>(hmo);
    static_cast<void>(pReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiInAddBuffer(void* hmi, void* pmh, std::uint32_t cbmh) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmi);
    static_cast<void>(pmh);
    static_cast<void>(cbmh);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiInClose(void* hmi) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiInGetDevCapsA(std::uint64_t uDeviceID, void* pmic, std::uint32_t cbmic) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uDeviceID);
    static_cast<void>(pmic);
    static_cast<void>(cbmic);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiInGetDevCapsW(std::uint64_t uDeviceID, std::uint64_t pmic, std::uint32_t cbmic) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uDeviceID);
    static_cast<void>(pmic);
    static_cast<void>(cbmic);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiInGetErrorTextA(std::uint32_t mmrError, char* pszText, std::uint32_t cchText) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(mmrError);
    static_cast<void>(pszText);
    static_cast<void>(cchText);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiInGetErrorTextW(std::uint32_t mmrError, char16_t* pszText, std::uint32_t cchText) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(mmrError);
    static_cast<void>(pszText);
    static_cast<void>(cchText);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiInGetID(void* hmi, std::uint32_t* puDeviceID) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmi);
    static_cast<void>(puDeviceID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiInGetNumDevs() noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiInMessage(void* hmi, std::uint32_t uMsg, std::uint64_t dw1, std::uint64_t dw2) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmi);
    static_cast<void>(uMsg);
    static_cast<void>(dw1);
    static_cast<void>(dw2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiInOpen(void* phmi, std::uint32_t uDeviceID, std::uint64_t dwCallback, std::uint64_t dwInstance, std::uint32_t fdwOpen) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(phmi);
    static_cast<void>(uDeviceID);
    static_cast<void>(dwCallback);
    static_cast<void>(dwInstance);
    static_cast<void>(fdwOpen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiInPrepareHeader(void* hmi, void* pmh, std::uint32_t cbmh) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmi);
    static_cast<void>(pmh);
    static_cast<void>(cbmh);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiInReset(void* hmi) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiInStart(void* hmi) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiInStop(void* hmi) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiInUnprepareHeader(void* hmi, void* pmh, std::uint32_t cbmh) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmi);
    static_cast<void>(pmh);
    static_cast<void>(cbmh);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutCacheDrumPatches(void* hmo, std::uint32_t uPatch, std::uint16_t* pwkya, std::uint32_t fuCache) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmo);
    static_cast<void>(uPatch);
    static_cast<void>(pwkya);
    static_cast<void>(fuCache);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutCachePatches(void* hmo, std::uint32_t uBank, std::uint16_t* pwpa, std::uint32_t fuCache) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmo);
    static_cast<void>(uBank);
    static_cast<void>(pwpa);
    static_cast<void>(fuCache);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutClose(void* hmo) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutGetDevCapsA(std::uint64_t uDeviceID, void* pmoc, std::uint32_t cbmoc) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uDeviceID);
    static_cast<void>(pmoc);
    static_cast<void>(cbmoc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutGetDevCapsW(std::uint64_t uDeviceID, std::uint64_t pmoc, std::uint32_t cbmoc) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uDeviceID);
    static_cast<void>(pmoc);
    static_cast<void>(cbmoc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutGetErrorTextA(std::uint32_t mmrError, char* pszText, std::uint32_t cchText) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(mmrError);
    static_cast<void>(pszText);
    static_cast<void>(cchText);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutGetErrorTextW(std::uint32_t mmrError, char16_t* pszText, std::uint32_t cchText) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(mmrError);
    static_cast<void>(pszText);
    static_cast<void>(cchText);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutGetID(void* hmo, std::uint32_t* puDeviceID) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmo);
    static_cast<void>(puDeviceID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutGetNumDevs() noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutGetVolume(void* hmo, std::uint32_t* pdwVolume) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmo);
    static_cast<void>(pdwVolume);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutLongMsg(void* hmo, void* pmh, std::uint32_t cbmh) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmo);
    static_cast<void>(pmh);
    static_cast<void>(cbmh);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutMessage(void* hmo, std::uint32_t uMsg, std::uint64_t dw1, std::uint64_t dw2) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmo);
    static_cast<void>(uMsg);
    static_cast<void>(dw1);
    static_cast<void>(dw2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutOpen(void* phmo, std::uint32_t uDeviceID, std::uint64_t dwCallback, std::uint64_t dwInstance, std::uint32_t fdwOpen) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(phmo);
    static_cast<void>(uDeviceID);
    static_cast<void>(dwCallback);
    static_cast<void>(dwInstance);
    static_cast<void>(fdwOpen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutPrepareHeader(void* hmo, void* pmh, std::uint32_t cbmh) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmo);
    static_cast<void>(pmh);
    static_cast<void>(cbmh);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutReset(void* hmo) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutSetVolume(void* hmo, std::uint32_t dwVolume) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmo);
    static_cast<void>(dwVolume);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutShortMsg(void* hmo, std::uint32_t dwMsg) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmo);
    static_cast<void>(dwMsg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiOutUnprepareHeader(void* hmo, void* pmh, std::uint32_t cbmh) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmo);
    static_cast<void>(pmh);
    static_cast<void>(cbmh);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiStreamClose(std::uint64_t hms) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hms);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiStreamOpen(std::uint64_t* phms, std::uint32_t* puDeviceID, std::uint32_t cMidi, std::uint64_t dwCallback, std::uint64_t dwInstance, std::uint32_t fdwOpen) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(phms);
    static_cast<void>(puDeviceID);
    static_cast<void>(cMidi);
    static_cast<void>(dwCallback);
    static_cast<void>(dwInstance);
    static_cast<void>(fdwOpen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiStreamOut(std::uint64_t hms, void* pmh, std::uint32_t cbmh) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hms);
    static_cast<void>(pmh);
    static_cast<void>(cbmh);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiStreamPause(std::uint64_t hms) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hms);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiStreamPosition(std::uint64_t hms, void* lpmmt, std::uint32_t cbmmt) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hms);
    static_cast<void>(lpmmt);
    static_cast<void>(cbmmt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiStreamProperty(std::uint64_t hms, std::uint8_t* lppropdata, std::uint32_t dwProperty) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hms);
    static_cast<void>(lppropdata);
    static_cast<void>(dwProperty);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiStreamRestart(std::uint64_t hms) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hms);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_midiStreamStop(std::uint64_t hms) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hms);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mixerClose(void* hmx) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmx);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mixerGetControlDetailsA(void* hmxobj, void* pmxcd, std::uint32_t fdwDetails) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmxobj);
    static_cast<void>(pmxcd);
    static_cast<void>(fdwDetails);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mixerGetControlDetailsW(void* hmxobj, void* pmxcd, std::uint32_t fdwDetails) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmxobj);
    static_cast<void>(pmxcd);
    static_cast<void>(fdwDetails);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mixerGetDevCapsA(std::uint64_t uMxId, void* pmxcaps, std::uint32_t cbmxcaps) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uMxId);
    static_cast<void>(pmxcaps);
    static_cast<void>(cbmxcaps);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mixerGetDevCapsW(std::uint64_t uMxId, std::uint64_t pmxcaps, std::uint32_t cbmxcaps) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uMxId);
    static_cast<void>(pmxcaps);
    static_cast<void>(cbmxcaps);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mixerGetID(void* hmxobj, std::uint32_t* puMxId, std::uint32_t fdwId) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmxobj);
    static_cast<void>(puMxId);
    static_cast<void>(fdwId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mixerGetLineControlsA(void* hmxobj, std::uint64_t pmxlc, std::uint32_t fdwControls) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmxobj);
    static_cast<void>(pmxlc);
    static_cast<void>(fdwControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mixerGetLineControlsW(void* hmxobj, std::uint64_t pmxlc, std::uint32_t fdwControls) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmxobj);
    static_cast<void>(pmxlc);
    static_cast<void>(fdwControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mixerGetLineInfoA(void* hmxobj, void* pmxl, std::uint32_t fdwInfo) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmxobj);
    static_cast<void>(pmxl);
    static_cast<void>(fdwInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mixerGetLineInfoW(void* hmxobj, std::uint64_t pmxl, std::uint32_t fdwInfo) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmxobj);
    static_cast<void>(pmxl);
    static_cast<void>(fdwInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mixerGetNumDevs() noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mixerMessage(void* hmx, std::uint32_t uMsg, std::uint64_t dwParam1, std::uint64_t dwParam2) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmx);
    static_cast<void>(uMsg);
    static_cast<void>(dwParam1);
    static_cast<void>(dwParam2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mixerOpen(void* phmx, std::uint32_t uMxId, std::uint64_t dwCallback, std::uint64_t dwInstance, std::uint32_t fdwOpen) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(phmx);
    static_cast<void>(uMxId);
    static_cast<void>(dwCallback);
    static_cast<void>(dwInstance);
    static_cast<void>(fdwOpen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mixerSetControlDetails(void* hmxobj, void* pmxcd, std::uint32_t fdwDetails) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hmxobj);
    static_cast<void>(pmxcd);
    static_cast<void>(fdwDetails);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mmDrvInstall(std::uint64_t hDriver, const char16_t* wszDrvEntry, std::uint64_t drvMessage, std::uint32_t wFlags) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(hDriver);
    static_cast<void>(wszDrvEntry);
    static_cast<void>(drvMessage);
    static_cast<void>(wFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mmioAdvance(std::uint64_t hmmio, std::uint64_t pmmioinfo, std::uint32_t fuAdvance) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(hmmio);
    static_cast<void>(pmmioinfo);
    static_cast<void>(fuAdvance);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mmioAscend(std::uint64_t hmmio, std::uint64_t pmmcki, std::uint32_t fuAscend) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(hmmio);
    static_cast<void>(pmmcki);
    static_cast<void>(fuAscend);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mmioClose(std::uint64_t hmmio, std::uint32_t fuClose) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(hmmio);
    static_cast<void>(fuClose);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mmioCreateChunk(std::uint64_t hmmio, std::uint64_t pmmcki, std::uint32_t fuCreate) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(hmmio);
    static_cast<void>(pmmcki);
    static_cast<void>(fuCreate);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mmioDescend(std::uint64_t hmmio, std::uint64_t pmmcki, const void* pmmckiParent, std::uint32_t fuDescend) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(hmmio);
    static_cast<void>(pmmcki);
    static_cast<void>(pmmckiParent);
    static_cast<void>(fuDescend);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mmioFlush(std::uint64_t hmmio, std::uint32_t fuFlush) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(hmmio);
    static_cast<void>(fuFlush);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mmioGetInfo(std::uint64_t hmmio, std::uint64_t pmmioinfo, std::uint32_t fuInfo) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(hmmio);
    static_cast<void>(pmmioinfo);
    static_cast<void>(fuInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kwinmmG_mmioInstallIOProcA(std::uint32_t fccIOProc, std::uint64_t pIOProc, std::uint32_t dwFlags) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(fccIOProc);
    static_cast<void>(pIOProc);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kwinmmG_mmioInstallIOProcW(std::uint32_t fccIOProc, std::uint64_t pIOProc, std::uint32_t dwFlags) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(fccIOProc);
    static_cast<void>(pIOProc);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kwinmmG_mmioOpenA(char* pszFileName, std::uint64_t pmmioinfo, std::uint32_t fdwOpen) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(pszFileName);
    static_cast<void>(pmmioinfo);
    static_cast<void>(fdwOpen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kwinmmG_mmioOpenW(char16_t* pszFileName, std::uint64_t pmmioinfo, std::uint32_t fdwOpen) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(pszFileName);
    static_cast<void>(pmmioinfo);
    static_cast<void>(fdwOpen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinmmG_mmioRead(std::uint64_t hmmio, std::uint64_t pch, std::int32_t cch) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(hmmio);
    static_cast<void>(pch);
    static_cast<void>(cch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mmioRenameA(const char* pszFileName, const char* pszNewFileName, std::uint64_t pmmioinfo, std::uint32_t fdwRename) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(pszFileName);
    static_cast<void>(pszNewFileName);
    static_cast<void>(pmmioinfo);
    static_cast<void>(fdwRename);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mmioRenameW(const char16_t* pszFileName, const char16_t* pszNewFileName, std::uint64_t pmmioinfo, std::uint32_t fdwRename) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(pszFileName);
    static_cast<void>(pszNewFileName);
    static_cast<void>(pmmioinfo);
    static_cast<void>(fdwRename);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinmmG_mmioSeek(std::uint64_t hmmio, std::int32_t lOffset, std::int32_t iOrigin) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(hmmio);
    static_cast<void>(lOffset);
    static_cast<void>(iOrigin);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int64_t kwinmmG_mmioSendMessage(std::uint64_t hmmio, std::uint32_t uMsg, std::int64_t lParam1, std::int64_t lParam2) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(hmmio);
    static_cast<void>(uMsg);
    static_cast<void>(lParam1);
    static_cast<void>(lParam2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mmioSetBuffer(std::uint64_t hmmio, char* pchBuffer, std::int32_t cchBuffer, std::uint32_t fuBuffer) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(hmmio);
    static_cast<void>(pchBuffer);
    static_cast<void>(cchBuffer);
    static_cast<void>(fuBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mmioSetInfo(std::uint64_t hmmio, std::uint64_t pmmioinfo, std::uint32_t fuInfo) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(hmmio);
    static_cast<void>(pmmioinfo);
    static_cast<void>(fuInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mmioStringToFOURCCA(const char* sz, std::uint32_t uFlags) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(sz);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_mmioStringToFOURCCW(const char16_t* sz, std::uint32_t uFlags) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(sz);
    static_cast<void>(uFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinmmG_mmioWrite(std::uint64_t hmmio, const char* pch, std::int32_t cch) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(hmmio);
    static_cast<void>(pch);
    static_cast<void>(cch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinmmG_sndPlaySoundA(const char* pszSound, std::uint32_t fuSound) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(pszSound);
    static_cast<void>(fuSound);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinmmG_sndPlaySoundW(const char16_t* pszSound, std::uint32_t fuSound) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(pszSound);
    static_cast<void>(fuSound);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_timeGetSystemTime(void* pmmt, std::uint32_t cbmmt) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(pmmt);
    static_cast<void>(cbmmt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_timeKillEvent(std::uint32_t uTimerID) noexcept {
    // Refused: the multimedia device layer.
    //
    // the call reaches an installed multimedia driver; there are none here
    static_cast<void>(uTimerID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_timeSetEvent(std::uint32_t uDelay, std::uint32_t uResolution, std::uint64_t fptc, std::uint64_t dwUser, std::uint32_t fuEvent) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uDelay);
    static_cast<void>(uResolution);
    static_cast<void>(fptc);
    static_cast<void>(dwUser);
    static_cast<void>(fuEvent);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveInAddBuffer(void* hwi, void* pwh, std::uint32_t cbwh) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwi);
    static_cast<void>(pwh);
    static_cast<void>(cbwh);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveInClose(void* hwi) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveInGetDevCapsA(std::uint64_t uDeviceID, void* pwic, std::uint32_t cbwic) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uDeviceID);
    static_cast<void>(pwic);
    static_cast<void>(cbwic);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveInGetDevCapsW(std::uint64_t uDeviceID, std::uint64_t pwic, std::uint32_t cbwic) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uDeviceID);
    static_cast<void>(pwic);
    static_cast<void>(cbwic);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveInGetErrorTextA(std::uint32_t mmrError, char* pszText, std::uint32_t cchText) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(mmrError);
    static_cast<void>(pszText);
    static_cast<void>(cchText);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveInGetErrorTextW(std::uint32_t mmrError, char16_t* pszText, std::uint32_t cchText) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(mmrError);
    static_cast<void>(pszText);
    static_cast<void>(cchText);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveInGetID(void* hwi, std::uint32_t* puDeviceID) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwi);
    static_cast<void>(puDeviceID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveInGetNumDevs() noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveInGetPosition(void* hwi, void* pmmt, std::uint32_t cbmmt) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwi);
    static_cast<void>(pmmt);
    static_cast<void>(cbmmt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveInMessage(void* hwi, std::uint32_t uMsg, std::uint64_t dw1, std::uint64_t dw2) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwi);
    static_cast<void>(uMsg);
    static_cast<void>(dw1);
    static_cast<void>(dw2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveInOpen(void* phwi, std::uint32_t uDeviceID, void* pwfx, std::uint64_t dwCallback, std::uint64_t dwInstance, std::uint32_t fdwOpen) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(phwi);
    static_cast<void>(uDeviceID);
    static_cast<void>(pwfx);
    static_cast<void>(dwCallback);
    static_cast<void>(dwInstance);
    static_cast<void>(fdwOpen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveInPrepareHeader(void* hwi, void* pwh, std::uint32_t cbwh) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwi);
    static_cast<void>(pwh);
    static_cast<void>(cbwh);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveInReset(void* hwi) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveInStart(void* hwi) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveInStop(void* hwi) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwi);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveInUnprepareHeader(void* hwi, void* pwh, std::uint32_t cbwh) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwi);
    static_cast<void>(pwh);
    static_cast<void>(cbwh);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutBreakLoop(void* hwo) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutClose(void* hwo) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutGetDevCapsA(std::uint64_t uDeviceID, void* pwoc, std::uint32_t cbwoc) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uDeviceID);
    static_cast<void>(pwoc);
    static_cast<void>(cbwoc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutGetDevCapsW(std::uint64_t uDeviceID, std::uint64_t pwoc, std::uint32_t cbwoc) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(uDeviceID);
    static_cast<void>(pwoc);
    static_cast<void>(cbwoc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutGetErrorTextA(std::uint32_t mmrError, char* pszText, std::uint32_t cchText) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(mmrError);
    static_cast<void>(pszText);
    static_cast<void>(cchText);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutGetErrorTextW(std::uint32_t mmrError, char16_t* pszText, std::uint32_t cchText) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(mmrError);
    static_cast<void>(pszText);
    static_cast<void>(cchText);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutGetID(void* hwo, std::uint32_t* puDeviceID) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwo);
    static_cast<void>(puDeviceID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutGetNumDevs() noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutGetPitch(void* hwo, std::uint32_t* pdwPitch) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwo);
    static_cast<void>(pdwPitch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutGetPlaybackRate(void* hwo, std::uint32_t* pdwRate) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwo);
    static_cast<void>(pdwRate);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutGetPosition(void* hwo, void* pmmt, std::uint32_t cbmmt) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwo);
    static_cast<void>(pmmt);
    static_cast<void>(cbmmt);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutGetVolume(void* hwo, std::uint32_t* pdwVolume) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwo);
    static_cast<void>(pdwVolume);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutMessage(void* hwo, std::uint32_t uMsg, std::uint64_t dw1, std::uint64_t dw2) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwo);
    static_cast<void>(uMsg);
    static_cast<void>(dw1);
    static_cast<void>(dw2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutOpen(void* phwo, std::uint32_t uDeviceID, void* pwfx, std::uint64_t dwCallback, std::uint64_t dwInstance, std::uint32_t fdwOpen) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(phwo);
    static_cast<void>(uDeviceID);
    static_cast<void>(pwfx);
    static_cast<void>(dwCallback);
    static_cast<void>(dwInstance);
    static_cast<void>(fdwOpen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutPause(void* hwo) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutPrepareHeader(void* hwo, void* pwh, std::uint32_t cbwh) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwo);
    static_cast<void>(pwh);
    static_cast<void>(cbwh);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutReset(void* hwo) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutRestart(void* hwo) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutSetPitch(void* hwo, std::uint32_t dwPitch) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwo);
    static_cast<void>(dwPitch);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutSetPlaybackRate(void* hwo, std::uint32_t dwRate) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwo);
    static_cast<void>(dwRate);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutSetVolume(void* hwo, std::uint32_t dwVolume) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwo);
    static_cast<void>(dwVolume);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutUnprepareHeader(void* hwo, void* pwh, std::uint32_t cbwh) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwo);
    static_cast<void>(pwh);
    static_cast<void>(cbwh);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinmmG_waveOutWrite(void* hwo, void* pwh, std::uint32_t cbwh) noexcept {
    // Refused: the multimedia device layer.
    //
    // audio, MIDI and joystick access is device access, and this runtime has
    // no audio device to open
    static_cast<void>(hwo);
    static_cast<void>(pwh);
    static_cast<void>(cbwh);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_winmm(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CloseDriver", reinterpret_cast<void*>(&kwinmmG_CloseDriver));
    e("DefDriverProc", reinterpret_cast<void*>(&kwinmmG_DefDriverProc));
    e("DriverCallback", reinterpret_cast<void*>(&kwinmmG_DriverCallback));
    e("DrvGetModuleHandle", reinterpret_cast<void*>(&kwinmmG_DrvGetModuleHandle));
    e("GetDriverModuleHandle", reinterpret_cast<void*>(&kwinmmG_GetDriverModuleHandle));
    e("OpenDriver", reinterpret_cast<void*>(&kwinmmG_OpenDriver));
    e("PlaySoundA", reinterpret_cast<void*>(&kwinmmG_PlaySoundA));
    e("PlaySoundW", reinterpret_cast<void*>(&kwinmmG_PlaySoundW));
    e("SendDriverMessage", reinterpret_cast<void*>(&kwinmmG_SendDriverMessage));
    e("auxGetDevCapsA", reinterpret_cast<void*>(&kwinmmG_auxGetDevCapsA));
    e("auxGetDevCapsW", reinterpret_cast<void*>(&kwinmmG_auxGetDevCapsW));
    e("auxGetNumDevs", reinterpret_cast<void*>(&kwinmmG_auxGetNumDevs));
    e("auxGetVolume", reinterpret_cast<void*>(&kwinmmG_auxGetVolume));
    e("auxOutMessage", reinterpret_cast<void*>(&kwinmmG_auxOutMessage));
    e("auxSetVolume", reinterpret_cast<void*>(&kwinmmG_auxSetVolume));
    e("joyConfigChanged", reinterpret_cast<void*>(&kwinmmG_joyConfigChanged));
    e("joyGetDevCapsA", reinterpret_cast<void*>(&kwinmmG_joyGetDevCapsA));
    e("joyGetDevCapsW", reinterpret_cast<void*>(&kwinmmG_joyGetDevCapsW));
    e("joyGetNumDevs", reinterpret_cast<void*>(&kwinmmG_joyGetNumDevs));
    e("joyGetPos", reinterpret_cast<void*>(&kwinmmG_joyGetPos));
    e("joyGetPosEx", reinterpret_cast<void*>(&kwinmmG_joyGetPosEx));
    e("joyGetThreshold", reinterpret_cast<void*>(&kwinmmG_joyGetThreshold));
    e("joyReleaseCapture", reinterpret_cast<void*>(&kwinmmG_joyReleaseCapture));
    e("joySetCapture", reinterpret_cast<void*>(&kwinmmG_joySetCapture));
    e("joySetThreshold", reinterpret_cast<void*>(&kwinmmG_joySetThreshold));
    e("mciDriverNotify", reinterpret_cast<void*>(&kwinmmG_mciDriverNotify));
    e("mciDriverYield", reinterpret_cast<void*>(&kwinmmG_mciDriverYield));
    e("mciExecute", reinterpret_cast<void*>(&kwinmmG_mciExecute));
    e("mciFreeCommandResource", reinterpret_cast<void*>(&kwinmmG_mciFreeCommandResource));
    e("mciGetCreatorTask", reinterpret_cast<void*>(&kwinmmG_mciGetCreatorTask));
    e("mciGetDeviceIDA", reinterpret_cast<void*>(&kwinmmG_mciGetDeviceIDA));
    e("mciGetDeviceIDFromElementIDA", reinterpret_cast<void*>(&kwinmmG_mciGetDeviceIDFromElementIDA));
    e("mciGetDeviceIDFromElementIDW", reinterpret_cast<void*>(&kwinmmG_mciGetDeviceIDFromElementIDW));
    e("mciGetDeviceIDW", reinterpret_cast<void*>(&kwinmmG_mciGetDeviceIDW));
    e("mciGetDriverData", reinterpret_cast<void*>(&kwinmmG_mciGetDriverData));
    e("mciGetErrorStringA", reinterpret_cast<void*>(&kwinmmG_mciGetErrorStringA));
    e("mciGetErrorStringW", reinterpret_cast<void*>(&kwinmmG_mciGetErrorStringW));
    e("mciGetYieldProc", reinterpret_cast<void*>(&kwinmmG_mciGetYieldProc));
    e("mciLoadCommandResource", reinterpret_cast<void*>(&kwinmmG_mciLoadCommandResource));
    e("mciSendCommandA", reinterpret_cast<void*>(&kwinmmG_mciSendCommandA));
    e("mciSendCommandW", reinterpret_cast<void*>(&kwinmmG_mciSendCommandW));
    e("mciSendStringA", reinterpret_cast<void*>(&kwinmmG_mciSendStringA));
    e("mciSendStringW", reinterpret_cast<void*>(&kwinmmG_mciSendStringW));
    e("mciSetDriverData", reinterpret_cast<void*>(&kwinmmG_mciSetDriverData));
    e("mciSetYieldProc", reinterpret_cast<void*>(&kwinmmG_mciSetYieldProc));
    e("midiConnect", reinterpret_cast<void*>(&kwinmmG_midiConnect));
    e("midiDisconnect", reinterpret_cast<void*>(&kwinmmG_midiDisconnect));
    e("midiInAddBuffer", reinterpret_cast<void*>(&kwinmmG_midiInAddBuffer));
    e("midiInClose", reinterpret_cast<void*>(&kwinmmG_midiInClose));
    e("midiInGetDevCapsA", reinterpret_cast<void*>(&kwinmmG_midiInGetDevCapsA));
    e("midiInGetDevCapsW", reinterpret_cast<void*>(&kwinmmG_midiInGetDevCapsW));
    e("midiInGetErrorTextA", reinterpret_cast<void*>(&kwinmmG_midiInGetErrorTextA));
    e("midiInGetErrorTextW", reinterpret_cast<void*>(&kwinmmG_midiInGetErrorTextW));
    e("midiInGetID", reinterpret_cast<void*>(&kwinmmG_midiInGetID));
    e("midiInGetNumDevs", reinterpret_cast<void*>(&kwinmmG_midiInGetNumDevs));
    e("midiInMessage", reinterpret_cast<void*>(&kwinmmG_midiInMessage));
    e("midiInOpen", reinterpret_cast<void*>(&kwinmmG_midiInOpen));
    e("midiInPrepareHeader", reinterpret_cast<void*>(&kwinmmG_midiInPrepareHeader));
    e("midiInReset", reinterpret_cast<void*>(&kwinmmG_midiInReset));
    e("midiInStart", reinterpret_cast<void*>(&kwinmmG_midiInStart));
    e("midiInStop", reinterpret_cast<void*>(&kwinmmG_midiInStop));
    e("midiInUnprepareHeader", reinterpret_cast<void*>(&kwinmmG_midiInUnprepareHeader));
    e("midiOutCacheDrumPatches", reinterpret_cast<void*>(&kwinmmG_midiOutCacheDrumPatches));
    e("midiOutCachePatches", reinterpret_cast<void*>(&kwinmmG_midiOutCachePatches));
    e("midiOutClose", reinterpret_cast<void*>(&kwinmmG_midiOutClose));
    e("midiOutGetDevCapsA", reinterpret_cast<void*>(&kwinmmG_midiOutGetDevCapsA));
    e("midiOutGetDevCapsW", reinterpret_cast<void*>(&kwinmmG_midiOutGetDevCapsW));
    e("midiOutGetErrorTextA", reinterpret_cast<void*>(&kwinmmG_midiOutGetErrorTextA));
    e("midiOutGetErrorTextW", reinterpret_cast<void*>(&kwinmmG_midiOutGetErrorTextW));
    e("midiOutGetID", reinterpret_cast<void*>(&kwinmmG_midiOutGetID));
    e("midiOutGetNumDevs", reinterpret_cast<void*>(&kwinmmG_midiOutGetNumDevs));
    e("midiOutGetVolume", reinterpret_cast<void*>(&kwinmmG_midiOutGetVolume));
    e("midiOutLongMsg", reinterpret_cast<void*>(&kwinmmG_midiOutLongMsg));
    e("midiOutMessage", reinterpret_cast<void*>(&kwinmmG_midiOutMessage));
    e("midiOutOpen", reinterpret_cast<void*>(&kwinmmG_midiOutOpen));
    e("midiOutPrepareHeader", reinterpret_cast<void*>(&kwinmmG_midiOutPrepareHeader));
    e("midiOutReset", reinterpret_cast<void*>(&kwinmmG_midiOutReset));
    e("midiOutSetVolume", reinterpret_cast<void*>(&kwinmmG_midiOutSetVolume));
    e("midiOutShortMsg", reinterpret_cast<void*>(&kwinmmG_midiOutShortMsg));
    e("midiOutUnprepareHeader", reinterpret_cast<void*>(&kwinmmG_midiOutUnprepareHeader));
    e("midiStreamClose", reinterpret_cast<void*>(&kwinmmG_midiStreamClose));
    e("midiStreamOpen", reinterpret_cast<void*>(&kwinmmG_midiStreamOpen));
    e("midiStreamOut", reinterpret_cast<void*>(&kwinmmG_midiStreamOut));
    e("midiStreamPause", reinterpret_cast<void*>(&kwinmmG_midiStreamPause));
    e("midiStreamPosition", reinterpret_cast<void*>(&kwinmmG_midiStreamPosition));
    e("midiStreamProperty", reinterpret_cast<void*>(&kwinmmG_midiStreamProperty));
    e("midiStreamRestart", reinterpret_cast<void*>(&kwinmmG_midiStreamRestart));
    e("midiStreamStop", reinterpret_cast<void*>(&kwinmmG_midiStreamStop));
    e("mixerClose", reinterpret_cast<void*>(&kwinmmG_mixerClose));
    e("mixerGetControlDetailsA", reinterpret_cast<void*>(&kwinmmG_mixerGetControlDetailsA));
    e("mixerGetControlDetailsW", reinterpret_cast<void*>(&kwinmmG_mixerGetControlDetailsW));
    e("mixerGetDevCapsA", reinterpret_cast<void*>(&kwinmmG_mixerGetDevCapsA));
    e("mixerGetDevCapsW", reinterpret_cast<void*>(&kwinmmG_mixerGetDevCapsW));
    e("mixerGetID", reinterpret_cast<void*>(&kwinmmG_mixerGetID));
    e("mixerGetLineControlsA", reinterpret_cast<void*>(&kwinmmG_mixerGetLineControlsA));
    e("mixerGetLineControlsW", reinterpret_cast<void*>(&kwinmmG_mixerGetLineControlsW));
    e("mixerGetLineInfoA", reinterpret_cast<void*>(&kwinmmG_mixerGetLineInfoA));
    e("mixerGetLineInfoW", reinterpret_cast<void*>(&kwinmmG_mixerGetLineInfoW));
    e("mixerGetNumDevs", reinterpret_cast<void*>(&kwinmmG_mixerGetNumDevs));
    e("mixerMessage", reinterpret_cast<void*>(&kwinmmG_mixerMessage));
    e("mixerOpen", reinterpret_cast<void*>(&kwinmmG_mixerOpen));
    e("mixerSetControlDetails", reinterpret_cast<void*>(&kwinmmG_mixerSetControlDetails));
    e("mmDrvInstall", reinterpret_cast<void*>(&kwinmmG_mmDrvInstall));
    e("mmioAdvance", reinterpret_cast<void*>(&kwinmmG_mmioAdvance));
    e("mmioAscend", reinterpret_cast<void*>(&kwinmmG_mmioAscend));
    e("mmioClose", reinterpret_cast<void*>(&kwinmmG_mmioClose));
    e("mmioCreateChunk", reinterpret_cast<void*>(&kwinmmG_mmioCreateChunk));
    e("mmioDescend", reinterpret_cast<void*>(&kwinmmG_mmioDescend));
    e("mmioFlush", reinterpret_cast<void*>(&kwinmmG_mmioFlush));
    e("mmioGetInfo", reinterpret_cast<void*>(&kwinmmG_mmioGetInfo));
    e("mmioInstallIOProcA", reinterpret_cast<void*>(&kwinmmG_mmioInstallIOProcA));
    e("mmioInstallIOProcW", reinterpret_cast<void*>(&kwinmmG_mmioInstallIOProcW));
    e("mmioOpenA", reinterpret_cast<void*>(&kwinmmG_mmioOpenA));
    e("mmioOpenW", reinterpret_cast<void*>(&kwinmmG_mmioOpenW));
    e("mmioRead", reinterpret_cast<void*>(&kwinmmG_mmioRead));
    e("mmioRenameA", reinterpret_cast<void*>(&kwinmmG_mmioRenameA));
    e("mmioRenameW", reinterpret_cast<void*>(&kwinmmG_mmioRenameW));
    e("mmioSeek", reinterpret_cast<void*>(&kwinmmG_mmioSeek));
    e("mmioSendMessage", reinterpret_cast<void*>(&kwinmmG_mmioSendMessage));
    e("mmioSetBuffer", reinterpret_cast<void*>(&kwinmmG_mmioSetBuffer));
    e("mmioSetInfo", reinterpret_cast<void*>(&kwinmmG_mmioSetInfo));
    e("mmioStringToFOURCCA", reinterpret_cast<void*>(&kwinmmG_mmioStringToFOURCCA));
    e("mmioStringToFOURCCW", reinterpret_cast<void*>(&kwinmmG_mmioStringToFOURCCW));
    e("mmioWrite", reinterpret_cast<void*>(&kwinmmG_mmioWrite));
    e("sndPlaySoundA", reinterpret_cast<void*>(&kwinmmG_sndPlaySoundA));
    e("sndPlaySoundW", reinterpret_cast<void*>(&kwinmmG_sndPlaySoundW));
    e("timeGetSystemTime", reinterpret_cast<void*>(&kwinmmG_timeGetSystemTime));
    e("timeKillEvent", reinterpret_cast<void*>(&kwinmmG_timeKillEvent));
    e("timeSetEvent", reinterpret_cast<void*>(&kwinmmG_timeSetEvent));
    e("waveInAddBuffer", reinterpret_cast<void*>(&kwinmmG_waveInAddBuffer));
    e("waveInClose", reinterpret_cast<void*>(&kwinmmG_waveInClose));
    e("waveInGetDevCapsA", reinterpret_cast<void*>(&kwinmmG_waveInGetDevCapsA));
    e("waveInGetDevCapsW", reinterpret_cast<void*>(&kwinmmG_waveInGetDevCapsW));
    e("waveInGetErrorTextA", reinterpret_cast<void*>(&kwinmmG_waveInGetErrorTextA));
    e("waveInGetErrorTextW", reinterpret_cast<void*>(&kwinmmG_waveInGetErrorTextW));
    e("waveInGetID", reinterpret_cast<void*>(&kwinmmG_waveInGetID));
    e("waveInGetNumDevs", reinterpret_cast<void*>(&kwinmmG_waveInGetNumDevs));
    e("waveInGetPosition", reinterpret_cast<void*>(&kwinmmG_waveInGetPosition));
    e("waveInMessage", reinterpret_cast<void*>(&kwinmmG_waveInMessage));
    e("waveInOpen", reinterpret_cast<void*>(&kwinmmG_waveInOpen));
    e("waveInPrepareHeader", reinterpret_cast<void*>(&kwinmmG_waveInPrepareHeader));
    e("waveInReset", reinterpret_cast<void*>(&kwinmmG_waveInReset));
    e("waveInStart", reinterpret_cast<void*>(&kwinmmG_waveInStart));
    e("waveInStop", reinterpret_cast<void*>(&kwinmmG_waveInStop));
    e("waveInUnprepareHeader", reinterpret_cast<void*>(&kwinmmG_waveInUnprepareHeader));
    e("waveOutBreakLoop", reinterpret_cast<void*>(&kwinmmG_waveOutBreakLoop));
    e("waveOutClose", reinterpret_cast<void*>(&kwinmmG_waveOutClose));
    e("waveOutGetDevCapsA", reinterpret_cast<void*>(&kwinmmG_waveOutGetDevCapsA));
    e("waveOutGetDevCapsW", reinterpret_cast<void*>(&kwinmmG_waveOutGetDevCapsW));
    e("waveOutGetErrorTextA", reinterpret_cast<void*>(&kwinmmG_waveOutGetErrorTextA));
    e("waveOutGetErrorTextW", reinterpret_cast<void*>(&kwinmmG_waveOutGetErrorTextW));
    e("waveOutGetID", reinterpret_cast<void*>(&kwinmmG_waveOutGetID));
    e("waveOutGetNumDevs", reinterpret_cast<void*>(&kwinmmG_waveOutGetNumDevs));
    e("waveOutGetPitch", reinterpret_cast<void*>(&kwinmmG_waveOutGetPitch));
    e("waveOutGetPlaybackRate", reinterpret_cast<void*>(&kwinmmG_waveOutGetPlaybackRate));
    e("waveOutGetPosition", reinterpret_cast<void*>(&kwinmmG_waveOutGetPosition));
    e("waveOutGetVolume", reinterpret_cast<void*>(&kwinmmG_waveOutGetVolume));
    e("waveOutMessage", reinterpret_cast<void*>(&kwinmmG_waveOutMessage));
    e("waveOutOpen", reinterpret_cast<void*>(&kwinmmG_waveOutOpen));
    e("waveOutPause", reinterpret_cast<void*>(&kwinmmG_waveOutPause));
    e("waveOutPrepareHeader", reinterpret_cast<void*>(&kwinmmG_waveOutPrepareHeader));
    e("waveOutReset", reinterpret_cast<void*>(&kwinmmG_waveOutReset));
    e("waveOutRestart", reinterpret_cast<void*>(&kwinmmG_waveOutRestart));
    e("waveOutSetPitch", reinterpret_cast<void*>(&kwinmmG_waveOutSetPitch));
    e("waveOutSetPlaybackRate", reinterpret_cast<void*>(&kwinmmG_waveOutSetPlaybackRate));
    e("waveOutSetVolume", reinterpret_cast<void*>(&kwinmmG_waveOutSetVolume));
    e("waveOutUnprepareHeader", reinterpret_cast<void*>(&kwinmmG_waveOutUnprepareHeader));
    e("waveOutWrite", reinterpret_cast<void*>(&kwinmmG_waveOutWrite));
}
}  // namespace occ::runtime::winabi

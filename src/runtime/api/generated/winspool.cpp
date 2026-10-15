// The WINSPOOL surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AbortPrinter(void* hPrinter) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddFormA(void* hPrinter, std::uint32_t Level, std::uint8_t* pForm) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(Level);
    static_cast<void>(pForm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddFormW(void* hPrinter, std::uint32_t Level, std::uint8_t* pForm) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(Level);
    static_cast<void>(pForm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddJobA(void* hPrinter, std::uint32_t Level, std::uint8_t* pData, std::uint32_t cbBuf, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(Level);
    static_cast<void>(pData);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddJobW(void* hPrinter, std::uint32_t Level, std::uint8_t* pData, std::uint32_t cbBuf, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(Level);
    static_cast<void>(pData);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddMonitorA(char* pName, std::uint32_t Level, std::uint8_t* pMonitorInfo) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(Level);
    static_cast<void>(pMonitorInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddMonitorW(char16_t* pName, std::uint32_t Level, std::uint8_t* pMonitorInfo) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(Level);
    static_cast<void>(pMonitorInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddPortA(char* pName, void* hWnd, char* pMonitorName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(hWnd);
    static_cast<void>(pMonitorName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddPortW(char16_t* pName, void* hWnd, char16_t* pMonitorName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(hWnd);
    static_cast<void>(pMonitorName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddPrintProcessorA(char* pName, char* pEnvironment, char* pPathName, char* pPrintProcessorName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(pPathName);
    static_cast<void>(pPrintProcessorName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddPrintProcessorW(char16_t* pName, char16_t* pEnvironment, char16_t* pPathName, char16_t* pPrintProcessorName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(pPathName);
    static_cast<void>(pPrintProcessorName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddPrintProvidorA(char* pName, std::uint32_t level, std::uint8_t* pProvidorInfo) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(level);
    static_cast<void>(pProvidorInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddPrintProvidorW(char16_t* pName, std::uint32_t level, std::uint8_t* pProvidorInfo) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(level);
    static_cast<void>(pProvidorInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwinspoolG_AddPrinterA(char* pName, std::uint32_t Level, std::uint8_t* pPrinter) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(Level);
    static_cast<void>(pPrinter);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddPrinterConnectionA(char* pName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddPrinterConnectionW(char16_t* pName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddPrinterDriverA(char* pName, std::uint32_t Level, std::uint8_t* pDriverInfo) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(Level);
    static_cast<void>(pDriverInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddPrinterDriverExA(char* pName, std::uint32_t Level, std::uint8_t* pDriverInfo, std::uint32_t dwFileCopyFlags) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(Level);
    static_cast<void>(pDriverInfo);
    static_cast<void>(dwFileCopyFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddPrinterDriverExW(char16_t* pName, std::uint32_t Level, std::uint8_t* pDriverInfo, std::uint32_t dwFileCopyFlags) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(Level);
    static_cast<void>(pDriverInfo);
    static_cast<void>(dwFileCopyFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AddPrinterDriverW(char16_t* pName, std::uint32_t Level, std::uint8_t* pDriverInfo) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(Level);
    static_cast<void>(pDriverInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwinspoolG_AddPrinterW(char16_t* pName, std::uint32_t Level, std::uint8_t* pPrinter) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(Level);
    static_cast<void>(pPrinter);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AdvancedDocumentPropertiesA(void* hWnd, void* hPrinter, char* pDeviceName, void* pDevModeOutput, void* pDevModeInput) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hWnd);
    static_cast<void>(hPrinter);
    static_cast<void>(pDeviceName);
    static_cast<void>(pDevModeOutput);
    static_cast<void>(pDevModeInput);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_AdvancedDocumentPropertiesW(void* hWnd, void* hPrinter, char16_t* pDeviceName, void* pDevModeOutput, void* pDevModeInput) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hWnd);
    static_cast<void>(hPrinter);
    static_cast<void>(pDeviceName);
    static_cast<void>(pDevModeOutput);
    static_cast<void>(pDevModeInput);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_ClosePrinter(void* hPrinter) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_ConfigurePortA(char* pName, void* hWnd, char* pPortName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(hWnd);
    static_cast<void>(pPortName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_ConfigurePortW(char16_t* pName, void* hWnd, char16_t* pPortName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(hWnd);
    static_cast<void>(pPortName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwinspoolG_ConnectToPrinterDlg(void* hwnd, std::uint32_t Flags) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hwnd);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DeleteFormA(void* hPrinter, char* pFormName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pFormName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DeleteFormW(void* hPrinter, char16_t* pFormName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pFormName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DeleteMonitorA(char* pName, char* pEnvironment, char* pMonitorName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(pMonitorName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DeleteMonitorW(char16_t* pName, char16_t* pEnvironment, char16_t* pMonitorName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(pMonitorName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DeletePortA(char* pName, void* hWnd, char* pPortName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(hWnd);
    static_cast<void>(pPortName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DeletePortW(char16_t* pName, void* hWnd, char16_t* pPortName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(hWnd);
    static_cast<void>(pPortName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DeletePrintProcessorA(char* pName, char* pEnvironment, char* pPrintProcessorName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(pPrintProcessorName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DeletePrintProcessorW(char16_t* pName, char16_t* pEnvironment, char16_t* pPrintProcessorName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(pPrintProcessorName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DeletePrintProvidorA(char* pName, char* pEnvironment, char* pPrintProvidorName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(pPrintProvidorName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DeletePrintProvidorW(char16_t* pName, char16_t* pEnvironment, char16_t* pPrintProvidorName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(pPrintProvidorName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DeletePrinter(void* hPrinter) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DeletePrinterConnectionA(char* pName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DeletePrinterConnectionW(char16_t* pName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_DeletePrinterDataA(void* hPrinter, char* pValueName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pValueName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_DeletePrinterDataExA(void* hPrinter, const char* pKeyName, const char* pValueName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pKeyName);
    static_cast<void>(pValueName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_DeletePrinterDataExW(void* hPrinter, const char16_t* pKeyName, const char16_t* pValueName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pKeyName);
    static_cast<void>(pValueName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_DeletePrinterDataW(void* hPrinter, char16_t* pValueName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pValueName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DeletePrinterDriverA(char* pName, char* pEnvironment, char* pDriverName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(pDriverName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DeletePrinterDriverExA(char* pName, char* pEnvironment, char* pDriverName, std::uint32_t dwDeleteFlag, std::uint32_t dwVersionFlag) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(pDriverName);
    static_cast<void>(dwDeleteFlag);
    static_cast<void>(dwVersionFlag);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DeletePrinterDriverExW(char16_t* pName, char16_t* pEnvironment, char16_t* pDriverName, std::uint32_t dwDeleteFlag, std::uint32_t dwVersionFlag) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(pDriverName);
    static_cast<void>(dwDeleteFlag);
    static_cast<void>(dwVersionFlag);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DeletePrinterDriverW(char16_t* pName, char16_t* pEnvironment, char16_t* pDriverName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(pDriverName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_DeletePrinterKeyA(void* hPrinter, const char* pKeyName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pKeyName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_DeletePrinterKeyW(void* hPrinter, const char16_t* pKeyName) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pKeyName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DocumentPropertiesA(void* hWnd, void* hPrinter, char* pDeviceName, void* pDevModeOutput, void* pDevModeInput, std::uint32_t fMode) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hWnd);
    static_cast<void>(hPrinter);
    static_cast<void>(pDeviceName);
    static_cast<void>(pDevModeOutput);
    static_cast<void>(pDevModeInput);
    static_cast<void>(fMode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_DocumentPropertiesW(void* hWnd, void* hPrinter, char16_t* pDeviceName, void* pDevModeOutput, void* pDevModeInput, std::uint32_t fMode) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hWnd);
    static_cast<void>(hPrinter);
    static_cast<void>(pDeviceName);
    static_cast<void>(pDevModeOutput);
    static_cast<void>(pDevModeInput);
    static_cast<void>(fMode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EndDocPrinter(void* hPrinter) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EndPagePrinter(void* hPrinter) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EnumFormsA(void* hPrinter, std::uint32_t Level, std::uint8_t* pForm, std::uint32_t cbBuf, std::uint32_t* pcbNeeded, std::uint32_t* pcReturned) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(Level);
    static_cast<void>(pForm);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    static_cast<void>(pcReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EnumFormsW(void* hPrinter, std::uint32_t Level, std::uint8_t* pForm, std::uint32_t cbBuf, std::uint32_t* pcbNeeded, std::uint32_t* pcReturned) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(Level);
    static_cast<void>(pForm);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    static_cast<void>(pcReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EnumJobsA(void* hPrinter, std::uint32_t FirstJob, std::uint32_t NoJobs, std::uint32_t Level, std::uint8_t* pJob, std::uint32_t cbBuf, std::uint32_t* pcbNeeded, std::uint32_t* pcReturned) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(FirstJob);
    static_cast<void>(NoJobs);
    static_cast<void>(Level);
    static_cast<void>(pJob);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    static_cast<void>(pcReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EnumJobsW(void* hPrinter, std::uint32_t FirstJob, std::uint32_t NoJobs, std::uint32_t Level, std::uint8_t* pJob, std::uint32_t cbBuf, std::uint32_t* pcbNeeded, std::uint32_t* pcReturned) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(FirstJob);
    static_cast<void>(NoJobs);
    static_cast<void>(Level);
    static_cast<void>(pJob);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    static_cast<void>(pcReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EnumMonitorsA(char* pName, std::uint32_t Level, std::uint8_t* pMonitor, std::uint32_t cbBuf, std::uint32_t* pcbNeeded, std::uint32_t* pcReturned) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(Level);
    static_cast<void>(pMonitor);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    static_cast<void>(pcReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EnumMonitorsW(char16_t* pName, std::uint32_t Level, std::uint8_t* pMonitor, std::uint32_t cbBuf, std::uint32_t* pcbNeeded, std::uint32_t* pcReturned) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(Level);
    static_cast<void>(pMonitor);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    static_cast<void>(pcReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EnumPortsA(char* pName, std::uint32_t Level, std::uint8_t* pPorts, std::uint32_t cbBuf, std::uint32_t* pcbNeeded, std::uint32_t* pcReturned) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(Level);
    static_cast<void>(pPorts);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    static_cast<void>(pcReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EnumPortsW(char16_t* pName, std::uint32_t Level, std::uint8_t* pPorts, std::uint32_t cbBuf, std::uint32_t* pcbNeeded, std::uint32_t* pcReturned) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(Level);
    static_cast<void>(pPorts);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    static_cast<void>(pcReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EnumPrintProcessorDatatypesA(char* pName, char* pPrintProcessorName, std::uint32_t Level, std::uint8_t* pDatatypes, std::uint32_t cbBuf, std::uint32_t* pcbNeeded, std::uint32_t* pcReturned) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pPrintProcessorName);
    static_cast<void>(Level);
    static_cast<void>(pDatatypes);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    static_cast<void>(pcReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EnumPrintProcessorDatatypesW(char16_t* pName, char16_t* pPrintProcessorName, std::uint32_t Level, std::uint8_t* pDatatypes, std::uint32_t cbBuf, std::uint32_t* pcbNeeded, std::uint32_t* pcReturned) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pPrintProcessorName);
    static_cast<void>(Level);
    static_cast<void>(pDatatypes);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    static_cast<void>(pcReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EnumPrintProcessorsA(char* pName, char* pEnvironment, std::uint32_t Level, std::uint8_t* pPrintProcessorInfo, std::uint32_t cbBuf, std::uint32_t* pcbNeeded, std::uint32_t* pcReturned) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(Level);
    static_cast<void>(pPrintProcessorInfo);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    static_cast<void>(pcReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EnumPrintProcessorsW(char16_t* pName, char16_t* pEnvironment, std::uint32_t Level, std::uint8_t* pPrintProcessorInfo, std::uint32_t cbBuf, std::uint32_t* pcbNeeded, std::uint32_t* pcReturned) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(Level);
    static_cast<void>(pPrintProcessorInfo);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    static_cast<void>(pcReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_EnumPrinterDataA(void* hPrinter, std::uint32_t dwIndex, char* pValueName, std::uint32_t cbValueName, std::uint32_t* pcbValueName, std::uint32_t* pType, std::uint8_t* pData, std::uint32_t cbData, std::uint32_t* pcbData) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(dwIndex);
    static_cast<void>(pValueName);
    static_cast<void>(cbValueName);
    static_cast<void>(pcbValueName);
    static_cast<void>(pType);
    static_cast<void>(pData);
    static_cast<void>(cbData);
    static_cast<void>(pcbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_EnumPrinterDataExA(void* hPrinter, const char* pKeyName, std::uint8_t* pEnumValues, std::uint32_t cbEnumValues, std::uint32_t* pcbEnumValues, std::uint32_t* pnEnumValues) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pKeyName);
    static_cast<void>(pEnumValues);
    static_cast<void>(cbEnumValues);
    static_cast<void>(pcbEnumValues);
    static_cast<void>(pnEnumValues);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_EnumPrinterDataExW(void* hPrinter, const char16_t* pKeyName, std::uint8_t* pEnumValues, std::uint32_t cbEnumValues, std::uint32_t* pcbEnumValues, std::uint32_t* pnEnumValues) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pKeyName);
    static_cast<void>(pEnumValues);
    static_cast<void>(cbEnumValues);
    static_cast<void>(pcbEnumValues);
    static_cast<void>(pnEnumValues);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_EnumPrinterDataW(void* hPrinter, std::uint32_t dwIndex, char16_t* pValueName, std::uint32_t cbValueName, std::uint32_t* pcbValueName, std::uint32_t* pType, std::uint8_t* pData, std::uint32_t cbData, std::uint32_t* pcbData) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(dwIndex);
    static_cast<void>(pValueName);
    static_cast<void>(cbValueName);
    static_cast<void>(pcbValueName);
    static_cast<void>(pType);
    static_cast<void>(pData);
    static_cast<void>(cbData);
    static_cast<void>(pcbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EnumPrinterDriversA(char* pName, char* pEnvironment, std::uint32_t Level, std::uint8_t* pDriverInfo, std::uint32_t cbBuf, std::uint32_t* pcbNeeded, std::uint32_t* pcReturned) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(Level);
    static_cast<void>(pDriverInfo);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    static_cast<void>(pcReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EnumPrinterDriversW(char16_t* pName, char16_t* pEnvironment, std::uint32_t Level, std::uint8_t* pDriverInfo, std::uint32_t cbBuf, std::uint32_t* pcbNeeded, std::uint32_t* pcReturned) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(Level);
    static_cast<void>(pDriverInfo);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    static_cast<void>(pcReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_EnumPrinterKeyA(void* hPrinter, const char* pKeyName, char* pSubkey, std::uint32_t cbSubkey, std::uint32_t* pcbSubkey) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pKeyName);
    static_cast<void>(pSubkey);
    static_cast<void>(cbSubkey);
    static_cast<void>(pcbSubkey);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_EnumPrinterKeyW(void* hPrinter, const char16_t* pKeyName, char16_t* pSubkey, std::uint32_t cbSubkey, std::uint32_t* pcbSubkey) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pKeyName);
    static_cast<void>(pSubkey);
    static_cast<void>(cbSubkey);
    static_cast<void>(pcbSubkey);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EnumPrintersA(std::uint32_t Flags, char* Name, std::uint32_t Level, std::uint8_t* pPrinterEnum, std::uint32_t cbBuf, std::uint32_t* pcbNeeded, std::uint32_t* pcReturned) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(Flags);
    static_cast<void>(Name);
    static_cast<void>(Level);
    static_cast<void>(pPrinterEnum);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    static_cast<void>(pcReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_EnumPrintersW(std::uint32_t Flags, char16_t* Name, std::uint32_t Level, std::uint8_t* pPrinterEnum, std::uint32_t cbBuf, std::uint32_t* pcbNeeded, std::uint32_t* pcReturned) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(Flags);
    static_cast<void>(Name);
    static_cast<void>(Level);
    static_cast<void>(pPrinterEnum);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    static_cast<void>(pcReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_ExtDeviceMode(void* hWnd, void* hInst, void* pDevModeOutput, char* pDeviceName, char* pPort, void* pDevModeInput, char* pProfile, std::uint32_t fMode) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hWnd);
    static_cast<void>(hInst);
    static_cast<void>(pDevModeOutput);
    static_cast<void>(pDeviceName);
    static_cast<void>(pPort);
    static_cast<void>(pDevModeInput);
    static_cast<void>(pProfile);
    static_cast<void>(fMode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_FindClosePrinterChangeNotification(void* hChange) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hChange);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwinspoolG_FindFirstPrinterChangeNotification(void* hPrinter, std::uint32_t fdwFlags, std::uint32_t fdwOptions, void* pPrinterNotifyOptions) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(fdwFlags);
    static_cast<void>(fdwOptions);
    static_cast<void>(pPrinterNotifyOptions);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_FindNextPrinterChangeNotification(void* hChange, std::uint32_t* pdwChange, void* pPrinterNotifyOptions, void** ppPrinterNotifyInfo) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hChange);
    static_cast<void>(pdwChange);
    static_cast<void>(pPrinterNotifyOptions);
    static_cast<void>(ppPrinterNotifyInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_FlushPrinter(void* hPrinter, void* pBuf, std::uint32_t cbBuf, std::uint32_t* pcWritten, std::uint32_t cSleep) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pBuf);
    static_cast<void>(cbBuf);
    static_cast<void>(pcWritten);
    static_cast<void>(cSleep);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_FreePrinterNotifyInfo(std::uint64_t pPrinterNotifyInfo) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pPrinterNotifyInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_GetDefaultPrinterA(char* pszBuffer, std::uint32_t* pcchBuffer) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pszBuffer);
    static_cast<void>(pcchBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_GetDefaultPrinterW(char16_t* pszBuffer, std::uint32_t* pcchBuffer) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pszBuffer);
    static_cast<void>(pcchBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_GetFormA(void* hPrinter, char* pFormName, std::uint32_t Level, std::uint8_t* pForm, std::uint32_t cbBuf, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pFormName);
    static_cast<void>(Level);
    static_cast<void>(pForm);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_GetFormW(void* hPrinter, char16_t* pFormName, std::uint32_t Level, std::uint8_t* pForm, std::uint32_t cbBuf, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pFormName);
    static_cast<void>(Level);
    static_cast<void>(pForm);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_GetJobA(void* hPrinter, std::uint32_t JobId, std::uint32_t Level, std::uint8_t* pJob, std::uint32_t cbBuf, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(JobId);
    static_cast<void>(Level);
    static_cast<void>(pJob);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_GetJobW(void* hPrinter, std::uint32_t JobId, std::uint32_t Level, std::uint8_t* pJob, std::uint32_t cbBuf, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(JobId);
    static_cast<void>(Level);
    static_cast<void>(pJob);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_GetPrintProcessorDirectoryA(char* pName, char* pEnvironment, std::uint32_t Level, std::uint8_t* pPrintProcessorInfo, std::uint32_t cbBuf, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(Level);
    static_cast<void>(pPrintProcessorInfo);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_GetPrintProcessorDirectoryW(char16_t* pName, char16_t* pEnvironment, std::uint32_t Level, std::uint8_t* pPrintProcessorInfo, std::uint32_t cbBuf, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(Level);
    static_cast<void>(pPrintProcessorInfo);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_GetPrinterA(void* hPrinter, std::uint32_t Level, std::uint8_t* pPrinter, std::uint32_t cbBuf, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(Level);
    static_cast<void>(pPrinter);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_GetPrinterDataA(void* hPrinter, char* pValueName, std::uint32_t* pType, std::uint8_t* pData, std::uint32_t nSize, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pValueName);
    static_cast<void>(pType);
    static_cast<void>(pData);
    static_cast<void>(nSize);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_GetPrinterDataExA(void* hPrinter, const char* pKeyName, const char* pValueName, std::uint32_t* pType, std::uint8_t* pData, std::uint32_t nSize, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pKeyName);
    static_cast<void>(pValueName);
    static_cast<void>(pType);
    static_cast<void>(pData);
    static_cast<void>(nSize);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_GetPrinterDataExW(void* hPrinter, const char16_t* pKeyName, const char16_t* pValueName, std::uint32_t* pType, std::uint8_t* pData, std::uint32_t nSize, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pKeyName);
    static_cast<void>(pValueName);
    static_cast<void>(pType);
    static_cast<void>(pData);
    static_cast<void>(nSize);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_GetPrinterDataW(void* hPrinter, char16_t* pValueName, std::uint32_t* pType, std::uint8_t* pData, std::uint32_t nSize, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pValueName);
    static_cast<void>(pType);
    static_cast<void>(pData);
    static_cast<void>(nSize);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_GetPrinterDriverA(void* hPrinter, char* pEnvironment, std::uint32_t Level, std::uint8_t* pDriverInfo, std::uint32_t cbBuf, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pEnvironment);
    static_cast<void>(Level);
    static_cast<void>(pDriverInfo);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_GetPrinterDriverDirectoryA(char* pName, char* pEnvironment, std::uint32_t Level, std::uint8_t* pDriverDirectory, std::uint32_t cbBuf, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(Level);
    static_cast<void>(pDriverDirectory);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_GetPrinterDriverDirectoryW(char16_t* pName, char16_t* pEnvironment, std::uint32_t Level, std::uint8_t* pDriverDirectory, std::uint32_t cbBuf, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pEnvironment);
    static_cast<void>(Level);
    static_cast<void>(pDriverDirectory);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_GetPrinterDriverW(void* hPrinter, char16_t* pEnvironment, std::uint32_t Level, std::uint8_t* pDriverInfo, std::uint32_t cbBuf, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pEnvironment);
    static_cast<void>(Level);
    static_cast<void>(pDriverInfo);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_GetPrinterW(void* hPrinter, std::uint32_t Level, std::uint8_t* pPrinter, std::uint32_t cbBuf, std::uint32_t* pcbNeeded) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(Level);
    static_cast<void>(pPrinter);
    static_cast<void>(cbBuf);
    static_cast<void>(pcbNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_IsValidDevmodeA(void* pDevmode, std::uint64_t DevmodeSize) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pDevmode);
    static_cast<void>(DevmodeSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_IsValidDevmodeW(void* pDevmode, std::uint64_t DevmodeSize) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pDevmode);
    static_cast<void>(DevmodeSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_OpenPrinterA(char* pPrinterName, void* phPrinter, void* pDefault) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pPrinterName);
    static_cast<void>(phPrinter);
    static_cast<void>(pDefault);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_OpenPrinterW(char16_t* pPrinterName, void* phPrinter, void* pDefault) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pPrinterName);
    static_cast<void>(phPrinter);
    static_cast<void>(pDefault);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_PrinterMessageBoxA(void* hPrinter, std::uint32_t Error, void* hWnd, char* pText, char* pCaption, std::uint32_t dwType) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(Error);
    static_cast<void>(hWnd);
    static_cast<void>(pText);
    static_cast<void>(pCaption);
    static_cast<void>(dwType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_PrinterMessageBoxW(void* hPrinter, std::uint32_t Error, void* hWnd, char16_t* pText, char16_t* pCaption, std::uint32_t dwType) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(Error);
    static_cast<void>(hWnd);
    static_cast<void>(pText);
    static_cast<void>(pCaption);
    static_cast<void>(dwType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_PrinterProperties(void* hWnd, void* hPrinter) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hWnd);
    static_cast<void>(hPrinter);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_ReadPrinter(void* hPrinter, void* pBuf, std::uint32_t cbBuf, std::uint32_t* pNoBytesRead) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pBuf);
    static_cast<void>(cbBuf);
    static_cast<void>(pNoBytesRead);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_ResetPrinterA(void* hPrinter, void* pDefault) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pDefault);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_ResetPrinterW(void* hPrinter, void* pDefault) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pDefault);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_ScheduleJob(void* hPrinter, std::uint32_t JobId) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(JobId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_SetDefaultPrinterA(const char* pszPrinter) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pszPrinter);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_SetDefaultPrinterW(const char16_t* pszPrinter) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pszPrinter);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_SetFormA(void* hPrinter, char* pFormName, std::uint32_t Level, std::uint8_t* pForm) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pFormName);
    static_cast<void>(Level);
    static_cast<void>(pForm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_SetFormW(void* hPrinter, char16_t* pFormName, std::uint32_t Level, std::uint8_t* pForm) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pFormName);
    static_cast<void>(Level);
    static_cast<void>(pForm);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_SetJobA(void* hPrinter, std::uint32_t JobId, std::uint32_t Level, std::uint8_t* pJob, std::uint32_t Command) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(JobId);
    static_cast<void>(Level);
    static_cast<void>(pJob);
    static_cast<void>(Command);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_SetJobW(void* hPrinter, std::uint32_t JobId, std::uint32_t Level, std::uint8_t* pJob, std::uint32_t Command) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(JobId);
    static_cast<void>(Level);
    static_cast<void>(pJob);
    static_cast<void>(Command);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_SetPortA(char* pName, char* pPortName, std::uint32_t dwLevel, std::uint8_t* pPortInfo) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pPortName);
    static_cast<void>(dwLevel);
    static_cast<void>(pPortInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_SetPortW(char16_t* pName, char16_t* pPortName, std::uint32_t dwLevel, std::uint8_t* pPortInfo) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(pName);
    static_cast<void>(pPortName);
    static_cast<void>(dwLevel);
    static_cast<void>(pPortInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_SetPrinterA(void* hPrinter, std::uint32_t Level, std::uint8_t* pPrinter, std::uint32_t Command) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(Level);
    static_cast<void>(pPrinter);
    static_cast<void>(Command);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_SetPrinterDataA(void* hPrinter, char* pValueName, std::uint32_t Type, std::uint8_t* pData, std::uint32_t cbData) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pValueName);
    static_cast<void>(Type);
    static_cast<void>(pData);
    static_cast<void>(cbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_SetPrinterDataExA(void* hPrinter, const char* pKeyName, const char* pValueName, std::uint32_t Type, std::uint8_t* pData, std::uint32_t cbData) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pKeyName);
    static_cast<void>(pValueName);
    static_cast<void>(Type);
    static_cast<void>(pData);
    static_cast<void>(cbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_SetPrinterDataExW(void* hPrinter, const char16_t* pKeyName, const char16_t* pValueName, std::uint32_t Type, std::uint8_t* pData, std::uint32_t cbData) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pKeyName);
    static_cast<void>(pValueName);
    static_cast<void>(Type);
    static_cast<void>(pData);
    static_cast<void>(cbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_SetPrinterDataW(void* hPrinter, char16_t* pValueName, std::uint32_t Type, std::uint8_t* pData, std::uint32_t cbData) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pValueName);
    static_cast<void>(Type);
    static_cast<void>(pData);
    static_cast<void>(cbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_SetPrinterW(void* hPrinter, std::uint32_t Level, std::uint8_t* pPrinter, std::uint32_t Command) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(Level);
    static_cast<void>(pPrinter);
    static_cast<void>(Command);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_StartDocPrinterA(void* hPrinter, std::uint32_t Level, std::uint8_t* pDocInfo) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(Level);
    static_cast<void>(pDocInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_StartDocPrinterW(void* hPrinter, std::uint32_t Level, std::uint8_t* pDocInfo) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(Level);
    static_cast<void>(pDocInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_StartPagePrinter(void* hPrinter) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinspoolG_WaitForPrinterChange(void* hPrinter, std::uint32_t Flags) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_WritePrinter(void* hPrinter, void* pBuf, std::uint32_t cbBuf, std::uint32_t* pcWritten) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hPrinter);
    static_cast<void>(pBuf);
    static_cast<void>(cbBuf);
    static_cast<void>(pcWritten);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinspoolG_XcvDataW(void* hXcv, const char16_t* pszDataName, std::uint8_t* pInputData, std::uint32_t cbInputData, std::uint8_t* pOutputData, std::uint32_t cbOutputData, std::uint32_t* pcbOutputNeeded, std::uint32_t* pdwStatus) noexcept {
    // Refused: the print spooler.
    //
    // printing needs a spooler service, a printer port and a driver, and the
    // call reaches all three through the spooler's named pipe
    static_cast<void>(hXcv);
    static_cast<void>(pszDataName);
    static_cast<void>(pInputData);
    static_cast<void>(cbInputData);
    static_cast<void>(pOutputData);
    static_cast<void>(cbOutputData);
    static_cast<void>(pcbOutputNeeded);
    static_cast<void>(pdwStatus);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_winspool(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("AbortPrinter", reinterpret_cast<void*>(&kwinspoolG_AbortPrinter));
    e("AddFormA", reinterpret_cast<void*>(&kwinspoolG_AddFormA));
    e("AddFormW", reinterpret_cast<void*>(&kwinspoolG_AddFormW));
    e("AddJobA", reinterpret_cast<void*>(&kwinspoolG_AddJobA));
    e("AddJobW", reinterpret_cast<void*>(&kwinspoolG_AddJobW));
    e("AddMonitorA", reinterpret_cast<void*>(&kwinspoolG_AddMonitorA));
    e("AddMonitorW", reinterpret_cast<void*>(&kwinspoolG_AddMonitorW));
    e("AddPortA", reinterpret_cast<void*>(&kwinspoolG_AddPortA));
    e("AddPortW", reinterpret_cast<void*>(&kwinspoolG_AddPortW));
    e("AddPrintProcessorA", reinterpret_cast<void*>(&kwinspoolG_AddPrintProcessorA));
    e("AddPrintProcessorW", reinterpret_cast<void*>(&kwinspoolG_AddPrintProcessorW));
    e("AddPrintProvidorA", reinterpret_cast<void*>(&kwinspoolG_AddPrintProvidorA));
    e("AddPrintProvidorW", reinterpret_cast<void*>(&kwinspoolG_AddPrintProvidorW));
    e("AddPrinterA", reinterpret_cast<void*>(&kwinspoolG_AddPrinterA));
    e("AddPrinterConnectionA", reinterpret_cast<void*>(&kwinspoolG_AddPrinterConnectionA));
    e("AddPrinterConnectionW", reinterpret_cast<void*>(&kwinspoolG_AddPrinterConnectionW));
    e("AddPrinterDriverA", reinterpret_cast<void*>(&kwinspoolG_AddPrinterDriverA));
    e("AddPrinterDriverExA", reinterpret_cast<void*>(&kwinspoolG_AddPrinterDriverExA));
    e("AddPrinterDriverExW", reinterpret_cast<void*>(&kwinspoolG_AddPrinterDriverExW));
    e("AddPrinterDriverW", reinterpret_cast<void*>(&kwinspoolG_AddPrinterDriverW));
    e("AddPrinterW", reinterpret_cast<void*>(&kwinspoolG_AddPrinterW));
    e("AdvancedDocumentPropertiesA", reinterpret_cast<void*>(&kwinspoolG_AdvancedDocumentPropertiesA));
    e("AdvancedDocumentPropertiesW", reinterpret_cast<void*>(&kwinspoolG_AdvancedDocumentPropertiesW));
    e("ClosePrinter", reinterpret_cast<void*>(&kwinspoolG_ClosePrinter));
    e("ConfigurePortA", reinterpret_cast<void*>(&kwinspoolG_ConfigurePortA));
    e("ConfigurePortW", reinterpret_cast<void*>(&kwinspoolG_ConfigurePortW));
    e("ConnectToPrinterDlg", reinterpret_cast<void*>(&kwinspoolG_ConnectToPrinterDlg));
    e("DeleteFormA", reinterpret_cast<void*>(&kwinspoolG_DeleteFormA));
    e("DeleteFormW", reinterpret_cast<void*>(&kwinspoolG_DeleteFormW));
    e("DeleteMonitorA", reinterpret_cast<void*>(&kwinspoolG_DeleteMonitorA));
    e("DeleteMonitorW", reinterpret_cast<void*>(&kwinspoolG_DeleteMonitorW));
    e("DeletePortA", reinterpret_cast<void*>(&kwinspoolG_DeletePortA));
    e("DeletePortW", reinterpret_cast<void*>(&kwinspoolG_DeletePortW));
    e("DeletePrintProcessorA", reinterpret_cast<void*>(&kwinspoolG_DeletePrintProcessorA));
    e("DeletePrintProcessorW", reinterpret_cast<void*>(&kwinspoolG_DeletePrintProcessorW));
    e("DeletePrintProvidorA", reinterpret_cast<void*>(&kwinspoolG_DeletePrintProvidorA));
    e("DeletePrintProvidorW", reinterpret_cast<void*>(&kwinspoolG_DeletePrintProvidorW));
    e("DeletePrinter", reinterpret_cast<void*>(&kwinspoolG_DeletePrinter));
    e("DeletePrinterConnectionA", reinterpret_cast<void*>(&kwinspoolG_DeletePrinterConnectionA));
    e("DeletePrinterConnectionW", reinterpret_cast<void*>(&kwinspoolG_DeletePrinterConnectionW));
    e("DeletePrinterDataA", reinterpret_cast<void*>(&kwinspoolG_DeletePrinterDataA));
    e("DeletePrinterDataExA", reinterpret_cast<void*>(&kwinspoolG_DeletePrinterDataExA));
    e("DeletePrinterDataExW", reinterpret_cast<void*>(&kwinspoolG_DeletePrinterDataExW));
    e("DeletePrinterDataW", reinterpret_cast<void*>(&kwinspoolG_DeletePrinterDataW));
    e("DeletePrinterDriverA", reinterpret_cast<void*>(&kwinspoolG_DeletePrinterDriverA));
    e("DeletePrinterDriverExA", reinterpret_cast<void*>(&kwinspoolG_DeletePrinterDriverExA));
    e("DeletePrinterDriverExW", reinterpret_cast<void*>(&kwinspoolG_DeletePrinterDriverExW));
    e("DeletePrinterDriverW", reinterpret_cast<void*>(&kwinspoolG_DeletePrinterDriverW));
    e("DeletePrinterKeyA", reinterpret_cast<void*>(&kwinspoolG_DeletePrinterKeyA));
    e("DeletePrinterKeyW", reinterpret_cast<void*>(&kwinspoolG_DeletePrinterKeyW));
    e("DocumentPropertiesA", reinterpret_cast<void*>(&kwinspoolG_DocumentPropertiesA));
    e("DocumentPropertiesW", reinterpret_cast<void*>(&kwinspoolG_DocumentPropertiesW));
    e("EndDocPrinter", reinterpret_cast<void*>(&kwinspoolG_EndDocPrinter));
    e("EndPagePrinter", reinterpret_cast<void*>(&kwinspoolG_EndPagePrinter));
    e("EnumFormsA", reinterpret_cast<void*>(&kwinspoolG_EnumFormsA));
    e("EnumFormsW", reinterpret_cast<void*>(&kwinspoolG_EnumFormsW));
    e("EnumJobsA", reinterpret_cast<void*>(&kwinspoolG_EnumJobsA));
    e("EnumJobsW", reinterpret_cast<void*>(&kwinspoolG_EnumJobsW));
    e("EnumMonitorsA", reinterpret_cast<void*>(&kwinspoolG_EnumMonitorsA));
    e("EnumMonitorsW", reinterpret_cast<void*>(&kwinspoolG_EnumMonitorsW));
    e("EnumPortsA", reinterpret_cast<void*>(&kwinspoolG_EnumPortsA));
    e("EnumPortsW", reinterpret_cast<void*>(&kwinspoolG_EnumPortsW));
    e("EnumPrintProcessorDatatypesA", reinterpret_cast<void*>(&kwinspoolG_EnumPrintProcessorDatatypesA));
    e("EnumPrintProcessorDatatypesW", reinterpret_cast<void*>(&kwinspoolG_EnumPrintProcessorDatatypesW));
    e("EnumPrintProcessorsA", reinterpret_cast<void*>(&kwinspoolG_EnumPrintProcessorsA));
    e("EnumPrintProcessorsW", reinterpret_cast<void*>(&kwinspoolG_EnumPrintProcessorsW));
    e("EnumPrinterDataA", reinterpret_cast<void*>(&kwinspoolG_EnumPrinterDataA));
    e("EnumPrinterDataExA", reinterpret_cast<void*>(&kwinspoolG_EnumPrinterDataExA));
    e("EnumPrinterDataExW", reinterpret_cast<void*>(&kwinspoolG_EnumPrinterDataExW));
    e("EnumPrinterDataW", reinterpret_cast<void*>(&kwinspoolG_EnumPrinterDataW));
    e("EnumPrinterDriversA", reinterpret_cast<void*>(&kwinspoolG_EnumPrinterDriversA));
    e("EnumPrinterDriversW", reinterpret_cast<void*>(&kwinspoolG_EnumPrinterDriversW));
    e("EnumPrinterKeyA", reinterpret_cast<void*>(&kwinspoolG_EnumPrinterKeyA));
    e("EnumPrinterKeyW", reinterpret_cast<void*>(&kwinspoolG_EnumPrinterKeyW));
    e("EnumPrintersA", reinterpret_cast<void*>(&kwinspoolG_EnumPrintersA));
    e("EnumPrintersW", reinterpret_cast<void*>(&kwinspoolG_EnumPrintersW));
    e("ExtDeviceMode", reinterpret_cast<void*>(&kwinspoolG_ExtDeviceMode));
    e("FindClosePrinterChangeNotification", reinterpret_cast<void*>(&kwinspoolG_FindClosePrinterChangeNotification));
    e("FindFirstPrinterChangeNotification", reinterpret_cast<void*>(&kwinspoolG_FindFirstPrinterChangeNotification));
    e("FindNextPrinterChangeNotification", reinterpret_cast<void*>(&kwinspoolG_FindNextPrinterChangeNotification));
    e("FlushPrinter", reinterpret_cast<void*>(&kwinspoolG_FlushPrinter));
    e("FreePrinterNotifyInfo", reinterpret_cast<void*>(&kwinspoolG_FreePrinterNotifyInfo));
    e("GetDefaultPrinterA", reinterpret_cast<void*>(&kwinspoolG_GetDefaultPrinterA));
    e("GetDefaultPrinterW", reinterpret_cast<void*>(&kwinspoolG_GetDefaultPrinterW));
    e("GetFormA", reinterpret_cast<void*>(&kwinspoolG_GetFormA));
    e("GetFormW", reinterpret_cast<void*>(&kwinspoolG_GetFormW));
    e("GetJobA", reinterpret_cast<void*>(&kwinspoolG_GetJobA));
    e("GetJobW", reinterpret_cast<void*>(&kwinspoolG_GetJobW));
    e("GetPrintProcessorDirectoryA", reinterpret_cast<void*>(&kwinspoolG_GetPrintProcessorDirectoryA));
    e("GetPrintProcessorDirectoryW", reinterpret_cast<void*>(&kwinspoolG_GetPrintProcessorDirectoryW));
    e("GetPrinterA", reinterpret_cast<void*>(&kwinspoolG_GetPrinterA));
    e("GetPrinterDataA", reinterpret_cast<void*>(&kwinspoolG_GetPrinterDataA));
    e("GetPrinterDataExA", reinterpret_cast<void*>(&kwinspoolG_GetPrinterDataExA));
    e("GetPrinterDataExW", reinterpret_cast<void*>(&kwinspoolG_GetPrinterDataExW));
    e("GetPrinterDataW", reinterpret_cast<void*>(&kwinspoolG_GetPrinterDataW));
    e("GetPrinterDriverA", reinterpret_cast<void*>(&kwinspoolG_GetPrinterDriverA));
    e("GetPrinterDriverDirectoryA", reinterpret_cast<void*>(&kwinspoolG_GetPrinterDriverDirectoryA));
    e("GetPrinterDriverDirectoryW", reinterpret_cast<void*>(&kwinspoolG_GetPrinterDriverDirectoryW));
    e("GetPrinterDriverW", reinterpret_cast<void*>(&kwinspoolG_GetPrinterDriverW));
    e("GetPrinterW", reinterpret_cast<void*>(&kwinspoolG_GetPrinterW));
    e("IsValidDevmodeA", reinterpret_cast<void*>(&kwinspoolG_IsValidDevmodeA));
    e("IsValidDevmodeW", reinterpret_cast<void*>(&kwinspoolG_IsValidDevmodeW));
    e("OpenPrinterA", reinterpret_cast<void*>(&kwinspoolG_OpenPrinterA));
    e("OpenPrinterW", reinterpret_cast<void*>(&kwinspoolG_OpenPrinterW));
    e("PrinterMessageBoxA", reinterpret_cast<void*>(&kwinspoolG_PrinterMessageBoxA));
    e("PrinterMessageBoxW", reinterpret_cast<void*>(&kwinspoolG_PrinterMessageBoxW));
    e("PrinterProperties", reinterpret_cast<void*>(&kwinspoolG_PrinterProperties));
    e("ReadPrinter", reinterpret_cast<void*>(&kwinspoolG_ReadPrinter));
    e("ResetPrinterA", reinterpret_cast<void*>(&kwinspoolG_ResetPrinterA));
    e("ResetPrinterW", reinterpret_cast<void*>(&kwinspoolG_ResetPrinterW));
    e("ScheduleJob", reinterpret_cast<void*>(&kwinspoolG_ScheduleJob));
    e("SetDefaultPrinterA", reinterpret_cast<void*>(&kwinspoolG_SetDefaultPrinterA));
    e("SetDefaultPrinterW", reinterpret_cast<void*>(&kwinspoolG_SetDefaultPrinterW));
    e("SetFormA", reinterpret_cast<void*>(&kwinspoolG_SetFormA));
    e("SetFormW", reinterpret_cast<void*>(&kwinspoolG_SetFormW));
    e("SetJobA", reinterpret_cast<void*>(&kwinspoolG_SetJobA));
    e("SetJobW", reinterpret_cast<void*>(&kwinspoolG_SetJobW));
    e("SetPortA", reinterpret_cast<void*>(&kwinspoolG_SetPortA));
    e("SetPortW", reinterpret_cast<void*>(&kwinspoolG_SetPortW));
    e("SetPrinterA", reinterpret_cast<void*>(&kwinspoolG_SetPrinterA));
    e("SetPrinterDataA", reinterpret_cast<void*>(&kwinspoolG_SetPrinterDataA));
    e("SetPrinterDataExA", reinterpret_cast<void*>(&kwinspoolG_SetPrinterDataExA));
    e("SetPrinterDataExW", reinterpret_cast<void*>(&kwinspoolG_SetPrinterDataExW));
    e("SetPrinterDataW", reinterpret_cast<void*>(&kwinspoolG_SetPrinterDataW));
    e("SetPrinterW", reinterpret_cast<void*>(&kwinspoolG_SetPrinterW));
    e("StartDocPrinterA", reinterpret_cast<void*>(&kwinspoolG_StartDocPrinterA));
    e("StartDocPrinterW", reinterpret_cast<void*>(&kwinspoolG_StartDocPrinterW));
    e("StartPagePrinter", reinterpret_cast<void*>(&kwinspoolG_StartPagePrinter));
    e("WaitForPrinterChange", reinterpret_cast<void*>(&kwinspoolG_WaitForPrinterChange));
    e("WritePrinter", reinterpret_cast<void*>(&kwinspoolG_WritePrinter));
    e("XcvDataW", reinterpret_cast<void*>(&kwinspoolG_XcvDataW));
}
}  // namespace occ::runtime::winabi

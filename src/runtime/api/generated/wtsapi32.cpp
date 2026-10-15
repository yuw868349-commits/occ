// The WTSAPI32 surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) void kwtsapi32G_WTSCloseServer(void* hServer) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hServer);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSDisconnectSession(void* hServer, std::uint32_t SessionId, std::int32_t bWait) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hServer);
    static_cast<void>(SessionId);
    static_cast<void>(bWait);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSEnumerateProcessesA(void* hServer, std::uint32_t Reserved, std::uint32_t Version, void* ppProcessInfo, std::uint32_t* pCount) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hServer);
    static_cast<void>(Reserved);
    static_cast<void>(Version);
    static_cast<void>(ppProcessInfo);
    static_cast<void>(pCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSEnumerateProcessesW(void* hServer, std::uint32_t Reserved, std::uint32_t Version, void* ppProcessInfo, std::uint32_t* pCount) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hServer);
    static_cast<void>(Reserved);
    static_cast<void>(Version);
    static_cast<void>(ppProcessInfo);
    static_cast<void>(pCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSEnumerateServersA(char* pDomainName, std::uint32_t Reserved, std::uint32_t Version, void* ppServerInfo, std::uint32_t* pCount) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(pDomainName);
    static_cast<void>(Reserved);
    static_cast<void>(Version);
    static_cast<void>(ppServerInfo);
    static_cast<void>(pCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSEnumerateServersW(char16_t* pDomainName, std::uint32_t Reserved, std::uint32_t Version, void* ppServerInfo, std::uint32_t* pCount) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(pDomainName);
    static_cast<void>(Reserved);
    static_cast<void>(Version);
    static_cast<void>(ppServerInfo);
    static_cast<void>(pCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSEnumerateSessionsA(void* hServer, std::uint32_t Reserved, std::uint32_t Version, void* ppSessionInfo, std::uint32_t* pCount) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hServer);
    static_cast<void>(Reserved);
    static_cast<void>(Version);
    static_cast<void>(ppSessionInfo);
    static_cast<void>(pCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSEnumerateSessionsW(void* hServer, std::uint32_t Reserved, std::uint32_t Version, void* ppSessionInfo, std::uint32_t* pCount) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hServer);
    static_cast<void>(Reserved);
    static_cast<void>(Version);
    static_cast<void>(ppSessionInfo);
    static_cast<void>(pCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kwtsapi32G_WTSFreeMemory(void* pMemory) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(pMemory);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSLogoffSession(void* hServer, std::uint32_t SessionId, std::int32_t bWait) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hServer);
    static_cast<void>(SessionId);
    static_cast<void>(bWait);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwtsapi32G_WTSOpenServerA(char* pServerName) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(pServerName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwtsapi32G_WTSOpenServerW(char16_t* pServerName) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(pServerName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSQuerySessionInformationA(void* hServer, std::uint32_t SessionId, std::uint64_t WTSInfoClass, char** ppBuffer, std::uint32_t* pBytesReturned) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hServer);
    static_cast<void>(SessionId);
    static_cast<void>(WTSInfoClass);
    static_cast<void>(ppBuffer);
    static_cast<void>(pBytesReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSQuerySessionInformationW(void* hServer, std::uint32_t SessionId, std::uint64_t WTSInfoClass, char16_t** ppBuffer, std::uint32_t* pBytesReturned) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hServer);
    static_cast<void>(SessionId);
    static_cast<void>(WTSInfoClass);
    static_cast<void>(ppBuffer);
    static_cast<void>(pBytesReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSQueryUserConfigA(char* pServerName, char* pUserName, std::uint64_t WTSConfigClass, char** ppBuffer, std::uint32_t* pBytesReturned) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(pServerName);
    static_cast<void>(pUserName);
    static_cast<void>(WTSConfigClass);
    static_cast<void>(ppBuffer);
    static_cast<void>(pBytesReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSQueryUserConfigW(char16_t* pServerName, char16_t* pUserName, std::uint64_t WTSConfigClass, char16_t** ppBuffer, std::uint32_t* pBytesReturned) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(pServerName);
    static_cast<void>(pUserName);
    static_cast<void>(WTSConfigClass);
    static_cast<void>(ppBuffer);
    static_cast<void>(pBytesReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSQueryUserToken(std::uint32_t SessionId, void** phToken) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(SessionId);
    static_cast<void>(phToken);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSRegisterSessionNotification(void* hWnd, std::uint32_t dwFlags) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hWnd);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSSendMessageA(void* hServer, std::uint32_t SessionId, char* pTitle, std::uint32_t TitleLength, char* pMessage, std::uint32_t MessageLength, std::uint32_t Style, std::uint32_t Timeout, std::uint32_t* pResponse, std::int32_t bWait) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hServer);
    static_cast<void>(SessionId);
    static_cast<void>(pTitle);
    static_cast<void>(TitleLength);
    static_cast<void>(pMessage);
    static_cast<void>(MessageLength);
    static_cast<void>(Style);
    static_cast<void>(Timeout);
    static_cast<void>(pResponse);
    static_cast<void>(bWait);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSSendMessageW(void* hServer, std::uint32_t SessionId, char16_t* pTitle, std::uint32_t TitleLength, char16_t* pMessage, std::uint32_t MessageLength, std::uint32_t Style, std::uint32_t Timeout, std::uint32_t* pResponse, std::int32_t bWait) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hServer);
    static_cast<void>(SessionId);
    static_cast<void>(pTitle);
    static_cast<void>(TitleLength);
    static_cast<void>(pMessage);
    static_cast<void>(MessageLength);
    static_cast<void>(Style);
    static_cast<void>(Timeout);
    static_cast<void>(pResponse);
    static_cast<void>(bWait);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSSetUserConfigA(char* pServerName, char* pUserName, std::uint64_t WTSConfigClass, char* pBuffer, std::uint32_t DataLength) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(pServerName);
    static_cast<void>(pUserName);
    static_cast<void>(WTSConfigClass);
    static_cast<void>(pBuffer);
    static_cast<void>(DataLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSSetUserConfigW(char16_t* pServerName, char16_t* pUserName, std::uint64_t WTSConfigClass, char16_t* pBuffer, std::uint32_t DataLength) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(pServerName);
    static_cast<void>(pUserName);
    static_cast<void>(WTSConfigClass);
    static_cast<void>(pBuffer);
    static_cast<void>(DataLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSShutdownSystem(void* hServer, std::uint32_t ShutdownFlag) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hServer);
    static_cast<void>(ShutdownFlag);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSTerminateProcess(void* hServer, std::uint32_t ProcessId, std::uint32_t ExitCode) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hServer);
    static_cast<void>(ProcessId);
    static_cast<void>(ExitCode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSUnRegisterSessionNotification(void* hWnd) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hWnd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSVirtualChannelClose(void* hChannelHandle) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hChannelHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwtsapi32G_WTSVirtualChannelOpen(void* hServer, std::uint32_t SessionId, char* pVirtualName) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hServer);
    static_cast<void>(SessionId);
    static_cast<void>(pVirtualName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSVirtualChannelPurgeInput(void* hChannelHandle) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hChannelHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSVirtualChannelPurgeOutput(void* hChannelHandle) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hChannelHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSVirtualChannelQuery(void* hChannelHandle, std::uint64_t arg1, void** ppBuffer, std::uint32_t* pBytesReturned) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hChannelHandle);
    static_cast<void>(arg1);
    static_cast<void>(ppBuffer);
    static_cast<void>(pBytesReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSVirtualChannelRead(void* hChannelHandle, std::uint32_t TimeOut, char* Buffer, std::uint32_t BufferSize, std::uint32_t* pBytesRead) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hChannelHandle);
    static_cast<void>(TimeOut);
    static_cast<void>(Buffer);
    static_cast<void>(BufferSize);
    static_cast<void>(pBytesRead);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSVirtualChannelWrite(void* hChannelHandle, char* Buffer, std::uint32_t Length, std::uint32_t* pBytesWritten) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hChannelHandle);
    static_cast<void>(Buffer);
    static_cast<void>(Length);
    static_cast<void>(pBytesWritten);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwtsapi32G_WTSWaitSystemEvent(void* hServer, std::uint32_t EventMask, std::uint32_t* pEventFlags) noexcept {
    // Refused: the terminal services API.
    //
    // the sessions this describes are sessions of a station manager that this
    // runtime does not run under
    static_cast<void>(hServer);
    static_cast<void>(EventMask);
    static_cast<void>(pEventFlags);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_wtsapi32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("WTSCloseServer", reinterpret_cast<void*>(&kwtsapi32G_WTSCloseServer));
    e("WTSDisconnectSession", reinterpret_cast<void*>(&kwtsapi32G_WTSDisconnectSession));
    e("WTSEnumerateProcessesA", reinterpret_cast<void*>(&kwtsapi32G_WTSEnumerateProcessesA));
    e("WTSEnumerateProcessesW", reinterpret_cast<void*>(&kwtsapi32G_WTSEnumerateProcessesW));
    e("WTSEnumerateServersA", reinterpret_cast<void*>(&kwtsapi32G_WTSEnumerateServersA));
    e("WTSEnumerateServersW", reinterpret_cast<void*>(&kwtsapi32G_WTSEnumerateServersW));
    e("WTSEnumerateSessionsA", reinterpret_cast<void*>(&kwtsapi32G_WTSEnumerateSessionsA));
    e("WTSEnumerateSessionsW", reinterpret_cast<void*>(&kwtsapi32G_WTSEnumerateSessionsW));
    e("WTSFreeMemory", reinterpret_cast<void*>(&kwtsapi32G_WTSFreeMemory));
    e("WTSLogoffSession", reinterpret_cast<void*>(&kwtsapi32G_WTSLogoffSession));
    e("WTSOpenServerA", reinterpret_cast<void*>(&kwtsapi32G_WTSOpenServerA));
    e("WTSOpenServerW", reinterpret_cast<void*>(&kwtsapi32G_WTSOpenServerW));
    e("WTSQuerySessionInformationA", reinterpret_cast<void*>(&kwtsapi32G_WTSQuerySessionInformationA));
    e("WTSQuerySessionInformationW", reinterpret_cast<void*>(&kwtsapi32G_WTSQuerySessionInformationW));
    e("WTSQueryUserConfigA", reinterpret_cast<void*>(&kwtsapi32G_WTSQueryUserConfigA));
    e("WTSQueryUserConfigW", reinterpret_cast<void*>(&kwtsapi32G_WTSQueryUserConfigW));
    e("WTSQueryUserToken", reinterpret_cast<void*>(&kwtsapi32G_WTSQueryUserToken));
    e("WTSRegisterSessionNotification", reinterpret_cast<void*>(&kwtsapi32G_WTSRegisterSessionNotification));
    e("WTSSendMessageA", reinterpret_cast<void*>(&kwtsapi32G_WTSSendMessageA));
    e("WTSSendMessageW", reinterpret_cast<void*>(&kwtsapi32G_WTSSendMessageW));
    e("WTSSetUserConfigA", reinterpret_cast<void*>(&kwtsapi32G_WTSSetUserConfigA));
    e("WTSSetUserConfigW", reinterpret_cast<void*>(&kwtsapi32G_WTSSetUserConfigW));
    e("WTSShutdownSystem", reinterpret_cast<void*>(&kwtsapi32G_WTSShutdownSystem));
    e("WTSTerminateProcess", reinterpret_cast<void*>(&kwtsapi32G_WTSTerminateProcess));
    e("WTSUnRegisterSessionNotification", reinterpret_cast<void*>(&kwtsapi32G_WTSUnRegisterSessionNotification));
    e("WTSVirtualChannelClose", reinterpret_cast<void*>(&kwtsapi32G_WTSVirtualChannelClose));
    e("WTSVirtualChannelOpen", reinterpret_cast<void*>(&kwtsapi32G_WTSVirtualChannelOpen));
    e("WTSVirtualChannelPurgeInput", reinterpret_cast<void*>(&kwtsapi32G_WTSVirtualChannelPurgeInput));
    e("WTSVirtualChannelPurgeOutput", reinterpret_cast<void*>(&kwtsapi32G_WTSVirtualChannelPurgeOutput));
    e("WTSVirtualChannelQuery", reinterpret_cast<void*>(&kwtsapi32G_WTSVirtualChannelQuery));
    e("WTSVirtualChannelRead", reinterpret_cast<void*>(&kwtsapi32G_WTSVirtualChannelRead));
    e("WTSVirtualChannelWrite", reinterpret_cast<void*>(&kwtsapi32G_WTSVirtualChannelWrite));
    e("WTSWaitSystemEvent", reinterpret_cast<void*>(&kwtsapi32G_WTSWaitSystemEvent));
}
}  // namespace occ::runtime::winabi

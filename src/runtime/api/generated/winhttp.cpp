// The WINHTTP surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpAddRequestHeaders(void* arg0, const char16_t* arg1, std::uint32_t arg2, std::uint32_t arg3) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpCheckPlatform() noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpCloseHandle(void* arg0) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwinhttpG_WinHttpConnect(void* arg0, const char16_t* arg1, std::uint16_t arg2, std::uint32_t arg3) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpCrackUrl(const char16_t* arg0, std::uint32_t arg1, std::uint32_t arg2, std::uint64_t arg3) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinhttpG_WinHttpCreateProxyResolver(void* arg0, void* arg1) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpCreateUrl(std::uint64_t arg0, std::uint32_t arg1, char16_t* arg2, std::uint32_t* arg3) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpDetectAutoProxyConfigUrl(std::uint32_t arg0, char16_t** arg1) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kwinhttpG_WinHttpFreeProxyResult(void* arg0) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kwinhttpG_WinHttpFreeProxyResultEx(void* arg0) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kwinhttpG_WinHttpFreeProxySettings(void* arg0) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpGetDefaultProxyConfiguration(void* arg0) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpGetIEProxyConfigForCurrentUser(void* arg0) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpGetProxyForUrl(void* arg0, const char16_t* arg1, void* arg2, void* arg3) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinhttpG_WinHttpGetProxyForUrlEx(void* arg0, const char16_t* arg1, void* arg2, std::uint64_t arg3) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinhttpG_WinHttpGetProxyForUrlEx2(void* arg0, const char16_t* arg1, void* arg2, std::uint32_t arg3, std::uint8_t* arg4, std::uint64_t arg5) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    static_cast<void>(arg5);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinhttpG_WinHttpGetProxyResult(void* arg0, void* arg1) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinhttpG_WinHttpGetProxyResultEx(void* arg0, void* arg1) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinhttpG_WinHttpGetProxySettingsVersion(void* arg0, std::uint32_t* arg1) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwinhttpG_WinHttpOpen(const char16_t* arg0, std::uint32_t arg1, const char16_t* arg2, const char16_t* arg3, std::uint32_t arg4) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwinhttpG_WinHttpOpenRequest(void* arg0, const char16_t* arg1, const char16_t* arg2, const char16_t* arg3, const char16_t* arg4, const char16_t** arg5, std::uint32_t arg6) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    static_cast<void>(arg5);
    static_cast<void>(arg6);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpQueryAuthSchemes(void* arg0, std::uint32_t* arg1, std::uint32_t* arg2, std::uint32_t* arg3) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpQueryDataAvailable(void* arg0, std::uint32_t* arg1) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpQueryHeaders(void* arg0, std::uint32_t arg1, const char16_t* arg2, void* arg3, std::uint32_t* arg4, std::uint32_t* arg5) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    static_cast<void>(arg5);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpQueryOption(void* arg0, std::uint32_t arg1, void* arg2, std::uint32_t* arg3) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpReadData(void* arg0, void* arg1, std::uint32_t arg2, std::uint32_t* arg3) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinhttpG_WinHttpReadProxySettings(void* arg0, const char16_t* arg1, std::int32_t arg2, std::int32_t arg3, std::uint32_t* arg4, std::int32_t* arg5, void* arg6) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    static_cast<void>(arg5);
    static_cast<void>(arg6);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpReceiveResponse(void* arg0, void* arg1) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinhttpG_WinHttpResetAutoProxy(void* arg0, std::uint32_t arg1) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpSendRequest(void* arg0, const char16_t* arg1, std::uint32_t arg2, void* arg3, std::uint32_t arg4, std::uint32_t arg5, std::uint64_t arg6) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    static_cast<void>(arg5);
    static_cast<void>(arg6);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpSetCredentials(void* arg0, std::uint32_t arg1, std::uint32_t arg2, const char16_t* arg3, const char16_t* arg4, void* arg5) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    static_cast<void>(arg5);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpSetDefaultProxyConfiguration(void* arg0) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpSetOption(void* arg0, std::uint32_t arg1, void* arg2, std::uint32_t arg3) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kwinhttpG_WinHttpSetStatusCallback(void* arg0, std::uint64_t arg1, std::uint32_t arg2, std::uint64_t arg3) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpSetTimeouts(void* arg0, std::int32_t arg1, std::int32_t arg2, std::int32_t arg3, std::int32_t arg4) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpTimeFromSystemTime(const void* arg0, char16_t* arg1) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpTimeToSystemTime(const char16_t* arg0, void* arg1) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinhttpG_WinHttpWebSocketClose(void* arg0, std::uint16_t arg1, void* arg2, std::uint32_t arg3) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwinhttpG_WinHttpWebSocketCompleteUpgrade(void* arg0, std::uint64_t arg1) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinhttpG_WinHttpWebSocketQueryCloseStatus(void* arg0, std::uint16_t* arg1, void* arg2, std::uint32_t arg3, std::uint32_t* arg4) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinhttpG_WinHttpWebSocketReceive(void* arg0, void* arg1, std::uint32_t arg2, std::uint32_t* arg3, void* arg4) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinhttpG_WinHttpWebSocketSend(void* arg0, std::uint64_t arg1, void* arg2, std::uint32_t arg3) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinhttpG_WinHttpWebSocketShutdown(void* arg0, std::uint16_t arg1, void* arg2, std::uint32_t arg3) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwinhttpG_WinHttpWriteData(void* arg0, const void* arg1, std::uint32_t arg2, std::uint32_t* arg3) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwinhttpG_WinHttpWriteProxySettings(void* arg0, std::int32_t arg1, void* arg2) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_winhttp(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("WinHttpAddRequestHeaders", reinterpret_cast<void*>(&kwinhttpG_WinHttpAddRequestHeaders));
    e("WinHttpCheckPlatform", reinterpret_cast<void*>(&kwinhttpG_WinHttpCheckPlatform));
    e("WinHttpCloseHandle", reinterpret_cast<void*>(&kwinhttpG_WinHttpCloseHandle));
    e("WinHttpConnect", reinterpret_cast<void*>(&kwinhttpG_WinHttpConnect));
    e("WinHttpCrackUrl", reinterpret_cast<void*>(&kwinhttpG_WinHttpCrackUrl));
    e("WinHttpCreateProxyResolver", reinterpret_cast<void*>(&kwinhttpG_WinHttpCreateProxyResolver));
    e("WinHttpCreateUrl", reinterpret_cast<void*>(&kwinhttpG_WinHttpCreateUrl));
    e("WinHttpDetectAutoProxyConfigUrl", reinterpret_cast<void*>(&kwinhttpG_WinHttpDetectAutoProxyConfigUrl));
    e("WinHttpFreeProxyResult", reinterpret_cast<void*>(&kwinhttpG_WinHttpFreeProxyResult));
    e("WinHttpFreeProxyResultEx", reinterpret_cast<void*>(&kwinhttpG_WinHttpFreeProxyResultEx));
    e("WinHttpFreeProxySettings", reinterpret_cast<void*>(&kwinhttpG_WinHttpFreeProxySettings));
    e("WinHttpGetDefaultProxyConfiguration", reinterpret_cast<void*>(&kwinhttpG_WinHttpGetDefaultProxyConfiguration));
    e("WinHttpGetIEProxyConfigForCurrentUser", reinterpret_cast<void*>(&kwinhttpG_WinHttpGetIEProxyConfigForCurrentUser));
    e("WinHttpGetProxyForUrl", reinterpret_cast<void*>(&kwinhttpG_WinHttpGetProxyForUrl));
    e("WinHttpGetProxyForUrlEx", reinterpret_cast<void*>(&kwinhttpG_WinHttpGetProxyForUrlEx));
    e("WinHttpGetProxyForUrlEx2", reinterpret_cast<void*>(&kwinhttpG_WinHttpGetProxyForUrlEx2));
    e("WinHttpGetProxyResult", reinterpret_cast<void*>(&kwinhttpG_WinHttpGetProxyResult));
    e("WinHttpGetProxyResultEx", reinterpret_cast<void*>(&kwinhttpG_WinHttpGetProxyResultEx));
    e("WinHttpGetProxySettingsVersion", reinterpret_cast<void*>(&kwinhttpG_WinHttpGetProxySettingsVersion));
    e("WinHttpOpen", reinterpret_cast<void*>(&kwinhttpG_WinHttpOpen));
    e("WinHttpOpenRequest", reinterpret_cast<void*>(&kwinhttpG_WinHttpOpenRequest));
    e("WinHttpQueryAuthSchemes", reinterpret_cast<void*>(&kwinhttpG_WinHttpQueryAuthSchemes));
    e("WinHttpQueryDataAvailable", reinterpret_cast<void*>(&kwinhttpG_WinHttpQueryDataAvailable));
    e("WinHttpQueryHeaders", reinterpret_cast<void*>(&kwinhttpG_WinHttpQueryHeaders));
    e("WinHttpQueryOption", reinterpret_cast<void*>(&kwinhttpG_WinHttpQueryOption));
    e("WinHttpReadData", reinterpret_cast<void*>(&kwinhttpG_WinHttpReadData));
    e("WinHttpReadProxySettings", reinterpret_cast<void*>(&kwinhttpG_WinHttpReadProxySettings));
    e("WinHttpReceiveResponse", reinterpret_cast<void*>(&kwinhttpG_WinHttpReceiveResponse));
    e("WinHttpResetAutoProxy", reinterpret_cast<void*>(&kwinhttpG_WinHttpResetAutoProxy));
    e("WinHttpSendRequest", reinterpret_cast<void*>(&kwinhttpG_WinHttpSendRequest));
    e("WinHttpSetCredentials", reinterpret_cast<void*>(&kwinhttpG_WinHttpSetCredentials));
    e("WinHttpSetDefaultProxyConfiguration", reinterpret_cast<void*>(&kwinhttpG_WinHttpSetDefaultProxyConfiguration));
    e("WinHttpSetOption", reinterpret_cast<void*>(&kwinhttpG_WinHttpSetOption));
    e("WinHttpSetStatusCallback", reinterpret_cast<void*>(&kwinhttpG_WinHttpSetStatusCallback));
    e("WinHttpSetTimeouts", reinterpret_cast<void*>(&kwinhttpG_WinHttpSetTimeouts));
    e("WinHttpTimeFromSystemTime", reinterpret_cast<void*>(&kwinhttpG_WinHttpTimeFromSystemTime));
    e("WinHttpTimeToSystemTime", reinterpret_cast<void*>(&kwinhttpG_WinHttpTimeToSystemTime));
    e("WinHttpWebSocketClose", reinterpret_cast<void*>(&kwinhttpG_WinHttpWebSocketClose));
    e("WinHttpWebSocketCompleteUpgrade", reinterpret_cast<void*>(&kwinhttpG_WinHttpWebSocketCompleteUpgrade));
    e("WinHttpWebSocketQueryCloseStatus", reinterpret_cast<void*>(&kwinhttpG_WinHttpWebSocketQueryCloseStatus));
    e("WinHttpWebSocketReceive", reinterpret_cast<void*>(&kwinhttpG_WinHttpWebSocketReceive));
    e("WinHttpWebSocketSend", reinterpret_cast<void*>(&kwinhttpG_WinHttpWebSocketSend));
    e("WinHttpWebSocketShutdown", reinterpret_cast<void*>(&kwinhttpG_WinHttpWebSocketShutdown));
    e("WinHttpWriteData", reinterpret_cast<void*>(&kwinhttpG_WinHttpWriteData));
    e("WinHttpWriteProxySettings", reinterpret_cast<void*>(&kwinhttpG_WinHttpWriteProxySettings));
}
}  // namespace occ::runtime::winabi

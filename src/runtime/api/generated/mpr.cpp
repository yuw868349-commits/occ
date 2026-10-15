// The MPR surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_MultinetGetConnectionPerformanceA(void* lpNetResource, std::uint64_t lpNetConnectInfoStruct) noexcept {
    // Refused: the network redirector.
    //
    // the call names a network resource to connect or enumerate, and the
    // provider that would answer it is not here
    static_cast<void>(lpNetResource);
    static_cast<void>(lpNetConnectInfoStruct);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_MultinetGetConnectionPerformanceW(void* lpNetResource, std::uint64_t lpNetConnectInfoStruct) noexcept {
    // Refused: the network redirector.
    //
    // the call names a network resource to connect or enumerate, and the
    // provider that would answer it is not here
    static_cast<void>(lpNetResource);
    static_cast<void>(lpNetConnectInfoStruct);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetAddConnection2A(void* lpNetResource, const char* lpPassword, const char* lpUserName, std::uint32_t dwFlags) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpNetResource);
    static_cast<void>(lpPassword);
    static_cast<void>(lpUserName);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetAddConnection2W(void* lpNetResource, const char16_t* lpPassword, const char16_t* lpUserName, std::uint32_t dwFlags) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpNetResource);
    static_cast<void>(lpPassword);
    static_cast<void>(lpUserName);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetAddConnection3A(void* hwndOwner, void* lpNetResource, const char* lpPassword, const char* lpUserName, std::uint32_t dwFlags) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(hwndOwner);
    static_cast<void>(lpNetResource);
    static_cast<void>(lpPassword);
    static_cast<void>(lpUserName);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetAddConnection3W(void* hwndOwner, void* lpNetResource, const char16_t* lpPassword, const char16_t* lpUserName, std::uint32_t dwFlags) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(hwndOwner);
    static_cast<void>(lpNetResource);
    static_cast<void>(lpPassword);
    static_cast<void>(lpUserName);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetAddConnectionA(const char* lpRemoteName, const char* lpPassword, const char* lpLocalName) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpRemoteName);
    static_cast<void>(lpPassword);
    static_cast<void>(lpLocalName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetAddConnectionW(const char16_t* lpRemoteName, const char16_t* lpPassword, const char16_t* lpLocalName) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpRemoteName);
    static_cast<void>(lpPassword);
    static_cast<void>(lpLocalName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetCancelConnection2A(const char* lpName, std::uint32_t dwFlags, std::int32_t fForce) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpName);
    static_cast<void>(dwFlags);
    static_cast<void>(fForce);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetCancelConnection2W(const char16_t* lpName, std::uint32_t dwFlags, std::int32_t fForce) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpName);
    static_cast<void>(dwFlags);
    static_cast<void>(fForce);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetCancelConnectionA(const char* lpName, std::int32_t fForce) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpName);
    static_cast<void>(fForce);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetCancelConnectionW(const char16_t* lpName, std::int32_t fForce) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpName);
    static_cast<void>(fForce);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetCloseEnum(void* hEnum) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(hEnum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetConnectionDialog(void* hwnd, std::uint32_t dwType) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(hwnd);
    static_cast<void>(dwType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetConnectionDialog1A(std::uint64_t lpConnDlgStruct) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpConnDlgStruct);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetConnectionDialog1W(std::uint64_t lpConnDlgStruct) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpConnDlgStruct);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetDisconnectDialog(void* hwnd, std::uint32_t dwType) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(hwnd);
    static_cast<void>(dwType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetDisconnectDialog1A(std::uint64_t lpConnDlgStruct) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpConnDlgStruct);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetDisconnectDialog1W(std::uint64_t lpConnDlgStruct) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpConnDlgStruct);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetEnumResourceA(void* hEnum, std::uint32_t* lpcCount, void* lpBuffer, std::uint32_t* lpBufferSize) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(hEnum);
    static_cast<void>(lpcCount);
    static_cast<void>(lpBuffer);
    static_cast<void>(lpBufferSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetEnumResourceW(void* hEnum, std::uint32_t* lpcCount, void* lpBuffer, std::uint32_t* lpBufferSize) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(hEnum);
    static_cast<void>(lpcCount);
    static_cast<void>(lpBuffer);
    static_cast<void>(lpBufferSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetGetConnectionA(const char* lpLocalName, char* lpRemoteName, std::uint32_t* lpnLength) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpLocalName);
    static_cast<void>(lpRemoteName);
    static_cast<void>(lpnLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetGetConnectionW(const char16_t* lpLocalName, char16_t* lpRemoteName, std::uint32_t* lpnLength) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpLocalName);
    static_cast<void>(lpRemoteName);
    static_cast<void>(lpnLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetGetLastErrorA(std::uint32_t* lpError, char* lpErrorBuf, std::uint32_t nErrorBufSize, char* lpNameBuf, std::uint32_t nNameBufSize) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpError);
    static_cast<void>(lpErrorBuf);
    static_cast<void>(nErrorBufSize);
    static_cast<void>(lpNameBuf);
    static_cast<void>(nNameBufSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetGetLastErrorW(std::uint32_t* lpError, char16_t* lpErrorBuf, std::uint32_t nErrorBufSize, char16_t* lpNameBuf, std::uint32_t nNameBufSize) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpError);
    static_cast<void>(lpErrorBuf);
    static_cast<void>(nErrorBufSize);
    static_cast<void>(lpNameBuf);
    static_cast<void>(nNameBufSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetGetNetworkInformationA(const char* lpProvider, std::uint64_t lpNetInfoStruct) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpProvider);
    static_cast<void>(lpNetInfoStruct);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetGetNetworkInformationW(const char16_t* lpProvider, std::uint64_t lpNetInfoStruct) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpProvider);
    static_cast<void>(lpNetInfoStruct);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetGetProviderNameA(std::uint32_t dwNetType, char* lpProviderName, std::uint32_t* lpBufferSize) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(dwNetType);
    static_cast<void>(lpProviderName);
    static_cast<void>(lpBufferSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetGetProviderNameW(std::uint32_t dwNetType, char16_t* lpProviderName, std::uint32_t* lpBufferSize) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(dwNetType);
    static_cast<void>(lpProviderName);
    static_cast<void>(lpBufferSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetGetResourceInformationA(void* lpNetResource, void* lpBuffer, std::uint32_t* lpcbBuffer, char** lplpSystem) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpNetResource);
    static_cast<void>(lpBuffer);
    static_cast<void>(lpcbBuffer);
    static_cast<void>(lplpSystem);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetGetResourceInformationW(void* lpNetResource, void* lpBuffer, std::uint32_t* lpcbBuffer, char16_t** lplpSystem) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpNetResource);
    static_cast<void>(lpBuffer);
    static_cast<void>(lpcbBuffer);
    static_cast<void>(lplpSystem);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetGetResourceParentA(void* lpNetResource, void* lpBuffer, std::uint32_t* lpcbBuffer) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpNetResource);
    static_cast<void>(lpBuffer);
    static_cast<void>(lpcbBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetGetResourceParentW(void* lpNetResource, void* lpBuffer, std::uint32_t* lpcbBuffer) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpNetResource);
    static_cast<void>(lpBuffer);
    static_cast<void>(lpcbBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetGetUniversalNameA(const char* lpLocalPath, std::uint32_t dwInfoLevel, void* lpBuffer, std::uint32_t* lpBufferSize) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpLocalPath);
    static_cast<void>(dwInfoLevel);
    static_cast<void>(lpBuffer);
    static_cast<void>(lpBufferSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetGetUniversalNameW(const char16_t* lpLocalPath, std::uint32_t dwInfoLevel, void* lpBuffer, std::uint32_t* lpBufferSize) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpLocalPath);
    static_cast<void>(dwInfoLevel);
    static_cast<void>(lpBuffer);
    static_cast<void>(lpBufferSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetGetUserA(const char* lpName, char* lpUserName, std::uint32_t* lpnLength) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpName);
    static_cast<void>(lpUserName);
    static_cast<void>(lpnLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetGetUserW(const char16_t* lpName, char16_t* lpUserName, std::uint32_t* lpnLength) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpName);
    static_cast<void>(lpUserName);
    static_cast<void>(lpnLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetOpenEnumA(std::uint32_t dwScope, std::uint32_t dwType, std::uint32_t dwUsage, void* lpNetResource, void* lphEnum) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(dwScope);
    static_cast<void>(dwType);
    static_cast<void>(dwUsage);
    static_cast<void>(lpNetResource);
    static_cast<void>(lphEnum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetOpenEnumW(std::uint32_t dwScope, std::uint32_t dwType, std::uint32_t dwUsage, void* lpNetResource, void* lphEnum) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(dwScope);
    static_cast<void>(dwType);
    static_cast<void>(dwUsage);
    static_cast<void>(lpNetResource);
    static_cast<void>(lphEnum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetRestoreSingleConnectionW(void* hwndParent, const char16_t* lpDevice, std::int32_t fUseUI) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(hwndParent);
    static_cast<void>(lpDevice);
    static_cast<void>(fUseUI);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetUseConnectionA(void* hwndOwner, void* lpNetResource, const char* lpPassword, const char* lpUserID, std::uint32_t dwFlags, char* lpAccessName, std::uint32_t* lpBufferSize, std::uint32_t* lpResult) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(hwndOwner);
    static_cast<void>(lpNetResource);
    static_cast<void>(lpPassword);
    static_cast<void>(lpUserID);
    static_cast<void>(dwFlags);
    static_cast<void>(lpAccessName);
    static_cast<void>(lpBufferSize);
    static_cast<void>(lpResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kmprG_WNetUseConnectionW(void* hwndOwner, void* lpNetResource, const char16_t* lpPassword, const char16_t* lpUserID, std::uint32_t dwFlags, char16_t* lpAccessName, std::uint32_t* lpBufferSize, std::uint32_t* lpResult) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(hwndOwner);
    static_cast<void>(lpNetResource);
    static_cast<void>(lpPassword);
    static_cast<void>(lpUserID);
    static_cast<void>(dwFlags);
    static_cast<void>(lpAccessName);
    static_cast<void>(lpBufferSize);
    static_cast<void>(lpResult);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_mpr(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("MultinetGetConnectionPerformanceA", reinterpret_cast<void*>(&kmprG_MultinetGetConnectionPerformanceA));
    e("MultinetGetConnectionPerformanceW", reinterpret_cast<void*>(&kmprG_MultinetGetConnectionPerformanceW));
    e("WNetAddConnection2A", reinterpret_cast<void*>(&kmprG_WNetAddConnection2A));
    e("WNetAddConnection2W", reinterpret_cast<void*>(&kmprG_WNetAddConnection2W));
    e("WNetAddConnection3A", reinterpret_cast<void*>(&kmprG_WNetAddConnection3A));
    e("WNetAddConnection3W", reinterpret_cast<void*>(&kmprG_WNetAddConnection3W));
    e("WNetAddConnectionA", reinterpret_cast<void*>(&kmprG_WNetAddConnectionA));
    e("WNetAddConnectionW", reinterpret_cast<void*>(&kmprG_WNetAddConnectionW));
    e("WNetCancelConnection2A", reinterpret_cast<void*>(&kmprG_WNetCancelConnection2A));
    e("WNetCancelConnection2W", reinterpret_cast<void*>(&kmprG_WNetCancelConnection2W));
    e("WNetCancelConnectionA", reinterpret_cast<void*>(&kmprG_WNetCancelConnectionA));
    e("WNetCancelConnectionW", reinterpret_cast<void*>(&kmprG_WNetCancelConnectionW));
    e("WNetCloseEnum", reinterpret_cast<void*>(&kmprG_WNetCloseEnum));
    e("WNetConnectionDialog", reinterpret_cast<void*>(&kmprG_WNetConnectionDialog));
    e("WNetConnectionDialog1A", reinterpret_cast<void*>(&kmprG_WNetConnectionDialog1A));
    e("WNetConnectionDialog1W", reinterpret_cast<void*>(&kmprG_WNetConnectionDialog1W));
    e("WNetDisconnectDialog", reinterpret_cast<void*>(&kmprG_WNetDisconnectDialog));
    e("WNetDisconnectDialog1A", reinterpret_cast<void*>(&kmprG_WNetDisconnectDialog1A));
    e("WNetDisconnectDialog1W", reinterpret_cast<void*>(&kmprG_WNetDisconnectDialog1W));
    e("WNetEnumResourceA", reinterpret_cast<void*>(&kmprG_WNetEnumResourceA));
    e("WNetEnumResourceW", reinterpret_cast<void*>(&kmprG_WNetEnumResourceW));
    e("WNetGetConnectionA", reinterpret_cast<void*>(&kmprG_WNetGetConnectionA));
    e("WNetGetConnectionW", reinterpret_cast<void*>(&kmprG_WNetGetConnectionW));
    e("WNetGetLastErrorA", reinterpret_cast<void*>(&kmprG_WNetGetLastErrorA));
    e("WNetGetLastErrorW", reinterpret_cast<void*>(&kmprG_WNetGetLastErrorW));
    e("WNetGetNetworkInformationA", reinterpret_cast<void*>(&kmprG_WNetGetNetworkInformationA));
    e("WNetGetNetworkInformationW", reinterpret_cast<void*>(&kmprG_WNetGetNetworkInformationW));
    e("WNetGetProviderNameA", reinterpret_cast<void*>(&kmprG_WNetGetProviderNameA));
    e("WNetGetProviderNameW", reinterpret_cast<void*>(&kmprG_WNetGetProviderNameW));
    e("WNetGetResourceInformationA", reinterpret_cast<void*>(&kmprG_WNetGetResourceInformationA));
    e("WNetGetResourceInformationW", reinterpret_cast<void*>(&kmprG_WNetGetResourceInformationW));
    e("WNetGetResourceParentA", reinterpret_cast<void*>(&kmprG_WNetGetResourceParentA));
    e("WNetGetResourceParentW", reinterpret_cast<void*>(&kmprG_WNetGetResourceParentW));
    e("WNetGetUniversalNameA", reinterpret_cast<void*>(&kmprG_WNetGetUniversalNameA));
    e("WNetGetUniversalNameW", reinterpret_cast<void*>(&kmprG_WNetGetUniversalNameW));
    e("WNetGetUserA", reinterpret_cast<void*>(&kmprG_WNetGetUserA));
    e("WNetGetUserW", reinterpret_cast<void*>(&kmprG_WNetGetUserW));
    e("WNetOpenEnumA", reinterpret_cast<void*>(&kmprG_WNetOpenEnumA));
    e("WNetOpenEnumW", reinterpret_cast<void*>(&kmprG_WNetOpenEnumW));
    e("WNetRestoreSingleConnectionW", reinterpret_cast<void*>(&kmprG_WNetRestoreSingleConnectionW));
    e("WNetUseConnectionA", reinterpret_cast<void*>(&kmprG_WNetUseConnectionA));
    e("WNetUseConnectionW", reinterpret_cast<void*>(&kmprG_WNetUseConnectionW));
}
}  // namespace occ::runtime::winabi

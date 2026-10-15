// The WININET surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_CommitUrlCacheEntryA(const char* lpszUrlName, const char* lpszLocalFileName, std::uint64_t ExpireTime, std::uint64_t LastModifiedTime, std::uint32_t CacheEntryType, std::uint8_t* lpHeaderInfo, std::uint32_t dwHeaderSize, const char* lpszFileExtension, const char* lpszOriginalUrl) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(lpszUrlName);
    static_cast<void>(lpszLocalFileName);
    static_cast<void>(ExpireTime);
    static_cast<void>(LastModifiedTime);
    static_cast<void>(CacheEntryType);
    static_cast<void>(lpHeaderInfo);
    static_cast<void>(dwHeaderSize);
    static_cast<void>(lpszFileExtension);
    static_cast<void>(lpszOriginalUrl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_CommitUrlCacheEntryW(const char16_t* lpszUrlName, const char16_t* lpszLocalFileName, std::uint64_t ExpireTime, std::uint64_t LastModifiedTime, std::uint32_t CacheEntryType, char16_t* lpszHeaderInfo, std::uint32_t dwHeaders, const char16_t* lpszFileExtension, const char16_t* lpszOriginalUrl) noexcept {
    // Refused: the serial device layer.
    //
    // a serial port is a device; there is no device node to open, no buffer to
    // flush and no modem to report on
    static_cast<void>(lpszUrlName);
    static_cast<void>(lpszLocalFileName);
    static_cast<void>(ExpireTime);
    static_cast<void>(LastModifiedTime);
    static_cast<void>(CacheEntryType);
    static_cast<void>(lpszHeaderInfo);
    static_cast<void>(dwHeaders);
    static_cast<void>(lpszFileExtension);
    static_cast<void>(lpszOriginalUrl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_CreateMD5SSOHash(char16_t* pszChallengeInfo, char16_t* pwszRealm, char16_t* pwszTarget, std::uint8_t* pbHexHash) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pszChallengeInfo);
    static_cast<void>(pwszRealm);
    static_cast<void>(pwszTarget);
    static_cast<void>(pbHexHash);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_CreateUrlCacheEntryA(const char* lpszUrlName, std::uint32_t dwExpectedFileSize, const char* lpszFileExtension, char* lpszFileName, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    static_cast<void>(dwExpectedFileSize);
    static_cast<void>(lpszFileExtension);
    static_cast<void>(lpszFileName);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_CreateUrlCacheEntryW(const char16_t* lpszUrlName, std::uint32_t dwExpectedFileSize, const char16_t* lpszFileExtension, char16_t* lpszFileName, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    static_cast<void>(dwExpectedFileSize);
    static_cast<void>(lpszFileExtension);
    static_cast<void>(lpszFileName);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwininetG_CreateUrlCacheGroup(std::uint32_t dwFlags, void* lpReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(dwFlags);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_DeleteUrlCacheEntry(const char* lpszUrlName) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_DeleteUrlCacheEntryA(const char* lpszUrlName) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_DeleteUrlCacheEntryW(const char16_t* lpszUrlName) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_DeleteUrlCacheGroup(std::uint32_t GroupId, std::uint32_t dwFlags, void* lpReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(GroupId);
    static_cast<void>(dwFlags);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_DetectAutoProxyUrl(char* lpszAutoProxyUrl, std::uint32_t dwAutoProxyUrlLength, std::uint32_t dwDetectFlags) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszAutoProxyUrl);
    static_cast<void>(dwAutoProxyUrlLength);
    static_cast<void>(dwDetectFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FindCloseUrlCache(void* hEnumHandle) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hEnumHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_FindFirstUrlCacheEntryA(const char* lpszUrlSearchPattern, void* lpFirstCacheEntryInfo, std::uint32_t* lpcbCacheEntryInfo) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlSearchPattern);
    static_cast<void>(lpFirstCacheEntryInfo);
    static_cast<void>(lpcbCacheEntryInfo);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_FindFirstUrlCacheEntryExA(const char* lpszUrlSearchPattern, std::uint32_t dwFlags, std::uint32_t dwFilter, std::uint32_t GroupId, void* lpFirstCacheEntryInfo, std::uint32_t* lpcbEntryInfo, void* lpGroupAttributes, std::uint32_t* lpcbGroupAttributes, void* lpReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlSearchPattern);
    static_cast<void>(dwFlags);
    static_cast<void>(dwFilter);
    static_cast<void>(GroupId);
    static_cast<void>(lpFirstCacheEntryInfo);
    static_cast<void>(lpcbEntryInfo);
    static_cast<void>(lpGroupAttributes);
    static_cast<void>(lpcbGroupAttributes);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_FindFirstUrlCacheEntryExW(const char16_t* lpszUrlSearchPattern, std::uint32_t dwFlags, std::uint32_t dwFilter, std::uint32_t GroupId, void* lpFirstCacheEntryInfo, std::uint32_t* lpcbEntryInfo, void* lpGroupAttributes, std::uint32_t* lpcbGroupAttributes, void* lpReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlSearchPattern);
    static_cast<void>(dwFlags);
    static_cast<void>(dwFilter);
    static_cast<void>(GroupId);
    static_cast<void>(lpFirstCacheEntryInfo);
    static_cast<void>(lpcbEntryInfo);
    static_cast<void>(lpGroupAttributes);
    static_cast<void>(lpcbGroupAttributes);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_FindFirstUrlCacheEntryW(const char16_t* lpszUrlSearchPattern, void* lpFirstCacheEntryInfo, std::uint32_t* lpcbCacheEntryInfo) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlSearchPattern);
    static_cast<void>(lpFirstCacheEntryInfo);
    static_cast<void>(lpcbCacheEntryInfo);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_FindFirstUrlCacheGroup(std::uint32_t dwFlags, std::uint32_t dwFilter, void* lpSearchCondition, std::uint32_t dwSearchCondition, std::uint32_t* lpGroupId, void* lpReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(dwFlags);
    static_cast<void>(dwFilter);
    static_cast<void>(lpSearchCondition);
    static_cast<void>(dwSearchCondition);
    static_cast<void>(lpGroupId);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FindNextUrlCacheEntryA(void* hEnumHandle, void* lpNextCacheEntryInfo, std::uint32_t* lpcbCacheEntryInfo) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hEnumHandle);
    static_cast<void>(lpNextCacheEntryInfo);
    static_cast<void>(lpcbCacheEntryInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FindNextUrlCacheEntryExA(void* hEnumHandle, void* lpNextCacheEntryInfo, std::uint32_t* lpcbEntryInfo, void* lpGroupAttributes, std::uint32_t* lpcbGroupAttributes, void* lpReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hEnumHandle);
    static_cast<void>(lpNextCacheEntryInfo);
    static_cast<void>(lpcbEntryInfo);
    static_cast<void>(lpGroupAttributes);
    static_cast<void>(lpcbGroupAttributes);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FindNextUrlCacheEntryExW(void* hEnumHandle, void* lpNextCacheEntryInfo, std::uint32_t* lpcbEntryInfo, void* lpGroupAttributes, std::uint32_t* lpcbGroupAttributes, void* lpReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hEnumHandle);
    static_cast<void>(lpNextCacheEntryInfo);
    static_cast<void>(lpcbEntryInfo);
    static_cast<void>(lpGroupAttributes);
    static_cast<void>(lpcbGroupAttributes);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FindNextUrlCacheEntryW(void* hEnumHandle, void* lpNextCacheEntryInfo, std::uint32_t* lpcbCacheEntryInfo) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hEnumHandle);
    static_cast<void>(lpNextCacheEntryInfo);
    static_cast<void>(lpcbCacheEntryInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FindNextUrlCacheGroup(void* hFind, std::uint32_t* lpGroupId, void* lpReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hFind);
    static_cast<void>(lpGroupId);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpCommandA(void* hConnect, std::int32_t fExpectResponse, std::uint32_t dwFlags, const char* lpszCommand, std::uint64_t dwContext, void* phFtpCommand) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(fExpectResponse);
    static_cast<void>(dwFlags);
    static_cast<void>(lpszCommand);
    static_cast<void>(dwContext);
    static_cast<void>(phFtpCommand);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpCommandW(void* hConnect, std::int32_t fExpectResponse, std::uint32_t dwFlags, const char16_t* lpszCommand, std::uint64_t dwContext, void* phFtpCommand) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(fExpectResponse);
    static_cast<void>(dwFlags);
    static_cast<void>(lpszCommand);
    static_cast<void>(dwContext);
    static_cast<void>(phFtpCommand);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpCreateDirectoryA(void* hConnect, const char* lpszDirectory) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszDirectory);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpCreateDirectoryW(void* hConnect, const char16_t* lpszDirectory) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszDirectory);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpDeleteFileA(void* hConnect, const char* lpszFileName) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszFileName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpDeleteFileW(void* hConnect, const char16_t* lpszFileName) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszFileName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_FtpFindFirstFileA(void* hConnect, const char* lpszSearchFile, void* lpFindFileData, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszSearchFile);
    static_cast<void>(lpFindFileData);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_FtpFindFirstFileW(void* hConnect, const char16_t* lpszSearchFile, void* lpFindFileData, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszSearchFile);
    static_cast<void>(lpFindFileData);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpGetCurrentDirectoryA(void* hConnect, char* lpszCurrentDirectory, std::uint32_t* lpdwCurrentDirectory) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszCurrentDirectory);
    static_cast<void>(lpdwCurrentDirectory);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpGetCurrentDirectoryW(void* hConnect, char16_t* lpszCurrentDirectory, std::uint32_t* lpdwCurrentDirectory) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszCurrentDirectory);
    static_cast<void>(lpdwCurrentDirectory);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpGetFileA(void* hConnect, const char* lpszRemoteFile, const char* lpszNewFile, std::int32_t fFailIfExists, std::uint32_t dwFlagsAndAttributes, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszRemoteFile);
    static_cast<void>(lpszNewFile);
    static_cast<void>(fFailIfExists);
    static_cast<void>(dwFlagsAndAttributes);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpGetFileEx(void* hFtpSession, const char* lpszRemoteFile, const char16_t* lpszNewFile, std::int32_t fFailIfExists, std::uint32_t dwFlagsAndAttributes, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hFtpSession);
    static_cast<void>(lpszRemoteFile);
    static_cast<void>(lpszNewFile);
    static_cast<void>(fFailIfExists);
    static_cast<void>(dwFlagsAndAttributes);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwininetG_FtpGetFileSize(void* hFile, std::uint32_t* lpdwFileSizeHigh) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hFile);
    static_cast<void>(lpdwFileSizeHigh);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpGetFileW(void* hConnect, const char16_t* lpszRemoteFile, const char16_t* lpszNewFile, std::int32_t fFailIfExists, std::uint32_t dwFlagsAndAttributes, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszRemoteFile);
    static_cast<void>(lpszNewFile);
    static_cast<void>(fFailIfExists);
    static_cast<void>(dwFlagsAndAttributes);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_FtpOpenFileA(void* hConnect, const char* lpszFileName, std::uint32_t dwAccess, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszFileName);
    static_cast<void>(dwAccess);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_FtpOpenFileW(void* hConnect, const char16_t* lpszFileName, std::uint32_t dwAccess, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszFileName);
    static_cast<void>(dwAccess);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpPutFileA(void* hConnect, const char* lpszLocalFile, const char* lpszNewRemoteFile, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszLocalFile);
    static_cast<void>(lpszNewRemoteFile);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpPutFileEx(void* hFtpSession, const char16_t* lpszLocalFile, const char* lpszNewRemoteFile, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hFtpSession);
    static_cast<void>(lpszLocalFile);
    static_cast<void>(lpszNewRemoteFile);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpPutFileW(void* hConnect, const char16_t* lpszLocalFile, const char16_t* lpszNewRemoteFile, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszLocalFile);
    static_cast<void>(lpszNewRemoteFile);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpRemoveDirectoryA(void* hConnect, const char* lpszDirectory) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszDirectory);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpRemoveDirectoryW(void* hConnect, const char16_t* lpszDirectory) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszDirectory);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpRenameFileA(void* hConnect, const char* lpszExisting, const char* lpszNew) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszExisting);
    static_cast<void>(lpszNew);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpRenameFileW(void* hConnect, const char16_t* lpszExisting, const char16_t* lpszNew) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszExisting);
    static_cast<void>(lpszNew);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpSetCurrentDirectoryA(void* hConnect, const char* lpszDirectory) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszDirectory);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_FtpSetCurrentDirectoryW(void* hConnect, const char16_t* lpszDirectory) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszDirectory);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_GetUrlCacheEntryInfoA(const char* lpszUrlName, void* lpCacheEntryInfo, std::uint32_t* lpcbCacheEntryInfo) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    static_cast<void>(lpCacheEntryInfo);
    static_cast<void>(lpcbCacheEntryInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_GetUrlCacheEntryInfoExA(const char* lpszUrl, void* lpCacheEntryInfo, std::uint32_t* lpcbCacheEntryInfo, char* lpszRedirectUrl, std::uint32_t* lpcbRedirectUrl, void* lpReserved, std::uint32_t dwFlags) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrl);
    static_cast<void>(lpCacheEntryInfo);
    static_cast<void>(lpcbCacheEntryInfo);
    static_cast<void>(lpszRedirectUrl);
    static_cast<void>(lpcbRedirectUrl);
    static_cast<void>(lpReserved);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_GetUrlCacheEntryInfoExW(const char16_t* lpszUrl, void* lpCacheEntryInfo, std::uint32_t* lpcbCacheEntryInfo, char16_t* lpszRedirectUrl, std::uint32_t* lpcbRedirectUrl, void* lpReserved, std::uint32_t dwFlags) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrl);
    static_cast<void>(lpCacheEntryInfo);
    static_cast<void>(lpcbCacheEntryInfo);
    static_cast<void>(lpszRedirectUrl);
    static_cast<void>(lpcbRedirectUrl);
    static_cast<void>(lpReserved);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_GetUrlCacheEntryInfoW(const char16_t* lpszUrlName, void* lpCacheEntryInfo, std::uint32_t* lpcbCacheEntryInfo) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    static_cast<void>(lpCacheEntryInfo);
    static_cast<void>(lpcbCacheEntryInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_GetUrlCacheGroupAttributeA(std::uint32_t gid, std::uint32_t dwFlags, std::uint32_t dwAttributes, std::uint64_t lpGroupInfo, std::uint32_t* lpdwGroupInfo, void* lpReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(gid);
    static_cast<void>(dwFlags);
    static_cast<void>(dwAttributes);
    static_cast<void>(lpGroupInfo);
    static_cast<void>(lpdwGroupInfo);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_GetUrlCacheGroupAttributeW(std::uint32_t gid, std::uint32_t dwFlags, std::uint32_t dwAttributes, std::uint64_t lpGroupInfo, std::uint32_t* lpdwGroupInfo, void* lpReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(gid);
    static_cast<void>(dwFlags);
    static_cast<void>(dwAttributes);
    static_cast<void>(lpGroupInfo);
    static_cast<void>(lpdwGroupInfo);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_GopherCreateLocatorA(const char* lpszHost, std::uint16_t nServerPort, const char* lpszDisplayString, const char* lpszSelectorString, std::uint32_t dwGopherType, char* lpszLocator, std::uint32_t* lpdwBufferLength) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszHost);
    static_cast<void>(nServerPort);
    static_cast<void>(lpszDisplayString);
    static_cast<void>(lpszSelectorString);
    static_cast<void>(dwGopherType);
    static_cast<void>(lpszLocator);
    static_cast<void>(lpdwBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_GopherCreateLocatorW(const char16_t* lpszHost, std::uint16_t nServerPort, const char16_t* lpszDisplayString, const char16_t* lpszSelectorString, std::uint32_t dwGopherType, char16_t* lpszLocator, std::uint32_t* lpdwBufferLength) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszHost);
    static_cast<void>(nServerPort);
    static_cast<void>(lpszDisplayString);
    static_cast<void>(lpszSelectorString);
    static_cast<void>(dwGopherType);
    static_cast<void>(lpszLocator);
    static_cast<void>(lpdwBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_GopherFindFirstFileA(void* hConnect, const char* lpszLocator, const char* lpszSearchString, std::uint64_t lpFindData, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszLocator);
    static_cast<void>(lpszSearchString);
    static_cast<void>(lpFindData);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_GopherFindFirstFileW(void* hConnect, const char16_t* lpszLocator, const char16_t* lpszSearchString, std::uint64_t lpFindData, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszLocator);
    static_cast<void>(lpszSearchString);
    static_cast<void>(lpFindData);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_GopherGetAttributeA(void* hConnect, const char* lpszLocator, const char* lpszAttributeName, std::uint8_t* lpBuffer, std::uint32_t dwBufferLength, std::uint32_t* lpdwCharactersReturned, std::uint64_t lpfnEnumerator, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszLocator);
    static_cast<void>(lpszAttributeName);
    static_cast<void>(lpBuffer);
    static_cast<void>(dwBufferLength);
    static_cast<void>(lpdwCharactersReturned);
    static_cast<void>(lpfnEnumerator);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_GopherGetAttributeW(void* hConnect, const char16_t* lpszLocator, const char16_t* lpszAttributeName, std::uint8_t* lpBuffer, std::uint32_t dwBufferLength, std::uint32_t* lpdwCharactersReturned, std::uint64_t lpfnEnumerator, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszLocator);
    static_cast<void>(lpszAttributeName);
    static_cast<void>(lpBuffer);
    static_cast<void>(dwBufferLength);
    static_cast<void>(lpdwCharactersReturned);
    static_cast<void>(lpfnEnumerator);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_GopherGetLocatorTypeA(const char* lpszLocator, std::uint32_t* lpdwGopherType) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszLocator);
    static_cast<void>(lpdwGopherType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_GopherGetLocatorTypeW(const char16_t* lpszLocator, std::uint32_t* lpdwGopherType) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszLocator);
    static_cast<void>(lpdwGopherType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_GopherOpenFileA(void* hConnect, const char* lpszLocator, const char* lpszView, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszLocator);
    static_cast<void>(lpszView);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_GopherOpenFileW(void* hConnect, const char16_t* lpszLocator, const char16_t* lpszView, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszLocator);
    static_cast<void>(lpszView);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_HttpAddRequestHeadersA(void* hRequest, const char* lpszHeaders, std::uint32_t dwHeadersLength, std::uint32_t dwModifiers) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hRequest);
    static_cast<void>(lpszHeaders);
    static_cast<void>(dwHeadersLength);
    static_cast<void>(dwModifiers);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_HttpAddRequestHeadersW(void* hRequest, const char16_t* lpszHeaders, std::uint32_t dwHeadersLength, std::uint32_t dwModifiers) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hRequest);
    static_cast<void>(lpszHeaders);
    static_cast<void>(dwHeadersLength);
    static_cast<void>(dwModifiers);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_HttpEndRequestA(void* hRequest, std::uint64_t lpBuffersOut, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hRequest);
    static_cast<void>(lpBuffersOut);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_HttpEndRequestW(void* hRequest, std::uint64_t lpBuffersOut, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hRequest);
    static_cast<void>(lpBuffersOut);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_HttpOpenRequestA(void* hConnect, const char* lpszVerb, const char* lpszObjectName, const char* lpszVersion, const char* lpszReferrer, const char** lplpszAcceptTypes, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszVerb);
    static_cast<void>(lpszObjectName);
    static_cast<void>(lpszVersion);
    static_cast<void>(lpszReferrer);
    static_cast<void>(lplpszAcceptTypes);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_HttpOpenRequestW(void* hConnect, const char16_t* lpszVerb, const char16_t* lpszObjectName, const char16_t* lpszVersion, const char16_t* lpszReferrer, const char16_t** lplpszAcceptTypes, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hConnect);
    static_cast<void>(lpszVerb);
    static_cast<void>(lpszObjectName);
    static_cast<void>(lpszVersion);
    static_cast<void>(lpszReferrer);
    static_cast<void>(lplpszAcceptTypes);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_HttpQueryInfoA(void* hRequest, std::uint32_t dwInfoLevel, void* lpBuffer, std::uint32_t* lpdwBufferLength, std::uint32_t* lpdwIndex) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hRequest);
    static_cast<void>(dwInfoLevel);
    static_cast<void>(lpBuffer);
    static_cast<void>(lpdwBufferLength);
    static_cast<void>(lpdwIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_HttpQueryInfoW(void* hRequest, std::uint32_t dwInfoLevel, void* lpBuffer, std::uint32_t* lpdwBufferLength, std::uint32_t* lpdwIndex) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hRequest);
    static_cast<void>(dwInfoLevel);
    static_cast<void>(lpBuffer);
    static_cast<void>(lpdwBufferLength);
    static_cast<void>(lpdwIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_HttpSendRequestExA(void* hRequest, std::uint64_t lpBuffersIn, std::uint64_t lpBuffersOut, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hRequest);
    static_cast<void>(lpBuffersIn);
    static_cast<void>(lpBuffersOut);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_HttpSendRequestExW(void* hRequest, std::uint64_t lpBuffersIn, std::uint64_t lpBuffersOut, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hRequest);
    static_cast<void>(lpBuffersIn);
    static_cast<void>(lpBuffersOut);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_HttpSendRequestW(void* hRequest, const char16_t* lpszHeaders, std::uint32_t dwHeadersLength, void* lpOptional, std::uint32_t dwOptionalLength) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hRequest);
    static_cast<void>(lpszHeaders);
    static_cast<void>(dwHeadersLength);
    static_cast<void>(lpOptional);
    static_cast<void>(dwOptionalLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwininetG_InternetAttemptConnect(std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetAutodial(std::uint32_t dwFlags, void* hwndParent) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(dwFlags);
    static_cast<void>(hwndParent);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetAutodialHangup(std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetCanonicalizeUrlA(const char* lpszUrl, char* lpszBuffer, std::uint32_t* lpdwBufferLength, std::uint32_t dwFlags) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszUrl);
    static_cast<void>(lpszBuffer);
    static_cast<void>(lpdwBufferLength);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetCanonicalizeUrlW(const char16_t* lpszUrl, char16_t* lpszBuffer, std::uint32_t* lpdwBufferLength, std::uint32_t dwFlags) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszUrl);
    static_cast<void>(lpszBuffer);
    static_cast<void>(lpdwBufferLength);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetCheckConnectionA(const char* lpszUrl, std::uint32_t dwFlags, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszUrl);
    static_cast<void>(dwFlags);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetCheckConnectionW(const char16_t* lpszUrl, std::uint32_t dwFlags, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszUrl);
    static_cast<void>(dwFlags);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetClearAllPerSiteCookieDecisions() noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetCombineUrlA(const char* lpszBaseUrl, const char* lpszRelativeUrl, char* lpszBuffer, std::uint32_t* lpdwBufferLength, std::uint32_t dwFlags) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszBaseUrl);
    static_cast<void>(lpszRelativeUrl);
    static_cast<void>(lpszBuffer);
    static_cast<void>(lpdwBufferLength);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetCombineUrlW(const char16_t* lpszBaseUrl, const char16_t* lpszRelativeUrl, char16_t* lpszBuffer, std::uint32_t* lpdwBufferLength, std::uint32_t dwFlags) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszBaseUrl);
    static_cast<void>(lpszRelativeUrl);
    static_cast<void>(lpszBuffer);
    static_cast<void>(lpdwBufferLength);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwininetG_InternetConfirmZoneCrossing(void* hWnd, char* szUrlPrev, char* szUrlNew, std::int32_t bPost) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hWnd);
    static_cast<void>(szUrlPrev);
    static_cast<void>(szUrlNew);
    static_cast<void>(bPost);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwininetG_InternetConfirmZoneCrossingA(void* hWnd, char* szUrlPrev, char* szUrlNew, std::int32_t bPost) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hWnd);
    static_cast<void>(szUrlPrev);
    static_cast<void>(szUrlNew);
    static_cast<void>(bPost);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwininetG_InternetConfirmZoneCrossingW(void* hWnd, char16_t* szUrlPrev, char16_t* szUrlNew, std::int32_t bPost) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hWnd);
    static_cast<void>(szUrlPrev);
    static_cast<void>(szUrlNew);
    static_cast<void>(bPost);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_InternetConnectW(void* hInternet, const char16_t* lpszServerName, std::uint16_t nServerPort, const char16_t* lpszUserName, const char16_t* lpszPassword, std::uint32_t dwService, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hInternet);
    static_cast<void>(lpszServerName);
    static_cast<void>(nServerPort);
    static_cast<void>(lpszUserName);
    static_cast<void>(lpszPassword);
    static_cast<void>(dwService);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetCrackUrlA(const char* lpszUrl, std::uint32_t dwUrlLength, std::uint32_t dwFlags, std::uint64_t lpUrlComponents) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszUrl);
    static_cast<void>(dwUrlLength);
    static_cast<void>(dwFlags);
    static_cast<void>(lpUrlComponents);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetCrackUrlW(const char16_t* lpszUrl, std::uint32_t dwUrlLength, std::uint32_t dwFlags, std::uint64_t lpUrlComponents) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszUrl);
    static_cast<void>(dwUrlLength);
    static_cast<void>(dwFlags);
    static_cast<void>(lpUrlComponents);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetCreateUrlA(std::uint64_t lpUrlComponents, std::uint32_t dwFlags, char* lpszUrl, std::uint32_t* lpdwUrlLength) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpUrlComponents);
    static_cast<void>(dwFlags);
    static_cast<void>(lpszUrl);
    static_cast<void>(lpdwUrlLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetCreateUrlW(std::uint64_t lpUrlComponents, std::uint32_t dwFlags, char16_t* lpszUrl, std::uint32_t* lpdwUrlLength) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpUrlComponents);
    static_cast<void>(dwFlags);
    static_cast<void>(lpszUrl);
    static_cast<void>(lpdwUrlLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwininetG_InternetDial(void* hwndParent, char* lpszConnectoid, std::uint32_t dwFlags, std::uint32_t* lpdwConnection, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hwndParent);
    static_cast<void>(lpszConnectoid);
    static_cast<void>(dwFlags);
    static_cast<void>(lpdwConnection);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwininetG_InternetDialA(void* hwndParent, char* lpszConnectoid, std::uint32_t dwFlags, std::uint64_t* lpdwConnection, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hwndParent);
    static_cast<void>(lpszConnectoid);
    static_cast<void>(dwFlags);
    static_cast<void>(lpdwConnection);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwininetG_InternetDialW(void* hwndParent, char16_t* lpszConnectoid, std::uint32_t dwFlags, std::uint64_t* lpdwConnection, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hwndParent);
    static_cast<void>(lpszConnectoid);
    static_cast<void>(dwFlags);
    static_cast<void>(lpdwConnection);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetEnumPerSiteCookieDecisionA(char* pszSiteName, void* pcSiteNameSize, void* pdwDecision, std::uint64_t dwIndex) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(pszSiteName);
    static_cast<void>(pcSiteNameSize);
    static_cast<void>(pdwDecision);
    static_cast<void>(dwIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetEnumPerSiteCookieDecisionW(char16_t* pszSiteName, void* pcSiteNameSize, void* pdwDecision, std::uint64_t dwIndex) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(pszSiteName);
    static_cast<void>(pcSiteNameSize);
    static_cast<void>(pdwDecision);
    static_cast<void>(dwIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwininetG_InternetErrorDlg(void* hWnd, void* hRequest, std::uint32_t dwError, std::uint32_t dwFlags, void** lppvData) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hWnd);
    static_cast<void>(hRequest);
    static_cast<void>(dwError);
    static_cast<void>(dwFlags);
    static_cast<void>(lppvData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetFindNextFileA(void* hFind, void* lpvFindData) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hFind);
    static_cast<void>(lpvFindData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetFindNextFileW(void* hFind, void* lpvFindData) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hFind);
    static_cast<void>(lpvFindData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetGetConnectedState(std::uint32_t* lpdwFlags, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpdwFlags);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetGetConnectedStateEx(std::uint32_t* lpdwFlags, char* lpszConnectionName, std::uint32_t dwNameLen, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpdwFlags);
    static_cast<void>(lpszConnectionName);
    static_cast<void>(dwNameLen);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetGetConnectedStateExA(std::uint32_t* lpdwFlags, char* lpszConnectionName, std::uint32_t dwBufLen, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpdwFlags);
    static_cast<void>(lpszConnectionName);
    static_cast<void>(dwBufLen);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetGetConnectedStateExW(std::uint32_t* lpdwFlags, char16_t* lpszConnectionName, std::uint32_t dwBufLen, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpdwFlags);
    static_cast<void>(lpszConnectionName);
    static_cast<void>(dwBufLen);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetGetCookieA(const char* lpszUrl, const char* lpszCookieName, char* lpszCookieData, std::uint32_t* lpdwSize) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszUrl);
    static_cast<void>(lpszCookieName);
    static_cast<void>(lpszCookieData);
    static_cast<void>(lpdwSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetGetCookieExA(const char* lpszUrl, const char* lpszCookieName, char* lpszCookieData, std::uint32_t* lpdwSize, std::uint32_t dwFlags, void* lpReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszUrl);
    static_cast<void>(lpszCookieName);
    static_cast<void>(lpszCookieData);
    static_cast<void>(lpdwSize);
    static_cast<void>(dwFlags);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetGetCookieExW(const char16_t* lpszUrl, const char16_t* lpszCookieName, char16_t* lpszCookieData, std::uint32_t* lpdwSize, std::uint32_t dwFlags, void* lpReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszUrl);
    static_cast<void>(lpszCookieName);
    static_cast<void>(lpszCookieData);
    static_cast<void>(lpdwSize);
    static_cast<void>(dwFlags);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetGetCookieW(const char16_t* lpszUrl, const char16_t* lpszCookieName, char16_t* lpszCookieData, std::uint32_t* lpdwSize) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszUrl);
    static_cast<void>(lpszCookieName);
    static_cast<void>(lpszCookieData);
    static_cast<void>(lpdwSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetGetLastResponseInfoA(std::uint32_t* lpdwError, char* lpszBuffer, std::uint32_t* lpdwBufferLength) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpdwError);
    static_cast<void>(lpszBuffer);
    static_cast<void>(lpdwBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetGetLastResponseInfoW(std::uint32_t* lpdwError, char16_t* lpszBuffer, std::uint32_t* lpdwBufferLength) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpdwError);
    static_cast<void>(lpszBuffer);
    static_cast<void>(lpdwBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetGetPerSiteCookieDecisionA(const char* pchHostName, void* pResult) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(pchHostName);
    static_cast<void>(pResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetGetPerSiteCookieDecisionW(const char16_t* pchHostName, void* pResult) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(pchHostName);
    static_cast<void>(pResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetGoOnline(char* lpszURL, void* hwndParent, std::uint32_t dwFlags) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszURL);
    static_cast<void>(hwndParent);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetGoOnlineA(char* lpszURL, void* hwndParent, std::uint32_t dwFlags) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszURL);
    static_cast<void>(hwndParent);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetGoOnlineW(char16_t* lpszURL, void* hwndParent, std::uint32_t dwFlags) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszURL);
    static_cast<void>(hwndParent);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwininetG_InternetHangUp(std::uint64_t dwConnection, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(dwConnection);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetInitializeAutoProxyDll(std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetLockRequestFile(void* hInternet, void* lphLockRequestInfo) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hInternet);
    static_cast<void>(lphLockRequestInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_InternetOpenUrlW(void* hInternet, const char16_t* lpszUrl, const char16_t* lpszHeaders, std::uint32_t dwHeadersLength, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hInternet);
    static_cast<void>(lpszUrl);
    static_cast<void>(lpszHeaders);
    static_cast<void>(dwHeadersLength);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_InternetOpenW(const char16_t* lpszAgent, std::uint32_t dwAccessType, const char16_t* lpszProxy, const char16_t* lpszProxyBypass, std::uint32_t dwFlags) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszAgent);
    static_cast<void>(dwAccessType);
    static_cast<void>(lpszProxy);
    static_cast<void>(lpszProxyBypass);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetQueryDataAvailable(void* hFile, std::uint32_t* lpdwNumberOfBytesAvailable, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hFile);
    static_cast<void>(lpdwNumberOfBytesAvailable);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetQueryOptionA(void* hInternet, std::uint32_t dwOption, void* lpBuffer, std::uint32_t* lpdwBufferLength) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hInternet);
    static_cast<void>(dwOption);
    static_cast<void>(lpBuffer);
    static_cast<void>(lpdwBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetQueryOptionW(void* hInternet, std::uint32_t dwOption, void* lpBuffer, std::uint32_t* lpdwBufferLength) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hInternet);
    static_cast<void>(dwOption);
    static_cast<void>(lpBuffer);
    static_cast<void>(lpdwBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetReadFileExA(void* hFile, std::uint64_t lpBuffersOut, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hFile);
    static_cast<void>(lpBuffersOut);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetReadFileExW(void* hFile, std::uint64_t lpBuffersOut, std::uint32_t dwFlags, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hFile);
    static_cast<void>(lpBuffersOut);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetSetCookieA(const char* lpszUrl, const char* lpszCookieName, const char* lpszCookieData) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszUrl);
    static_cast<void>(lpszCookieName);
    static_cast<void>(lpszCookieData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwininetG_InternetSetCookieExA(const char* lpszUrl, const char* lpszCookieName, const char* lpszCookieData, std::uint32_t dwFlags, std::uint64_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszUrl);
    static_cast<void>(lpszCookieName);
    static_cast<void>(lpszCookieData);
    static_cast<void>(dwFlags);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwininetG_InternetSetCookieExW(const char16_t* lpszUrl, const char16_t* lpszCookieName, const char16_t* lpszCookieData, std::uint32_t dwFlags, std::uint64_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszUrl);
    static_cast<void>(lpszCookieName);
    static_cast<void>(lpszCookieData);
    static_cast<void>(dwFlags);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetSetCookieW(const char16_t* lpszUrl, const char16_t* lpszCookieName, const char16_t* lpszCookieData) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszUrl);
    static_cast<void>(lpszCookieName);
    static_cast<void>(lpszCookieData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetSetDialState(const char* lpszConnectoid, std::uint32_t dwState, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszConnectoid);
    static_cast<void>(dwState);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetSetDialStateA(const char* lpszConnectoid, std::uint32_t dwState, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszConnectoid);
    static_cast<void>(dwState);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetSetDialStateW(const char16_t* lpszConnectoid, std::uint32_t dwState, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszConnectoid);
    static_cast<void>(dwState);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwininetG_InternetSetFilePointer(void* hFile, std::int32_t lDistanceToMove, void* pReserved, std::uint32_t dwMoveMethod, std::uint64_t dwContext) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hFile);
    static_cast<void>(lDistanceToMove);
    static_cast<void>(pReserved);
    static_cast<void>(dwMoveMethod);
    static_cast<void>(dwContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetSetOptionA(void* hInternet, std::uint32_t dwOption, void* lpBuffer, std::uint32_t dwBufferLength) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hInternet);
    static_cast<void>(dwOption);
    static_cast<void>(lpBuffer);
    static_cast<void>(dwBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetSetOptionExA(void* hInternet, std::uint32_t dwOption, void* lpBuffer, std::uint32_t dwBufferLength, std::uint32_t dwFlags) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hInternet);
    static_cast<void>(dwOption);
    static_cast<void>(lpBuffer);
    static_cast<void>(dwBufferLength);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetSetOptionExW(void* hInternet, std::uint32_t dwOption, void* lpBuffer, std::uint32_t dwBufferLength, std::uint32_t dwFlags) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hInternet);
    static_cast<void>(dwOption);
    static_cast<void>(lpBuffer);
    static_cast<void>(dwBufferLength);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetSetOptionW(void* hInternet, std::uint32_t dwOption, void* lpBuffer, std::uint32_t dwBufferLength) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hInternet);
    static_cast<void>(dwOption);
    static_cast<void>(lpBuffer);
    static_cast<void>(dwBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetSetPerSiteCookieDecisionA(const char* pchHostName, std::uint32_t dwDecision) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(pchHostName);
    static_cast<void>(dwDecision);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetSetPerSiteCookieDecisionW(const char16_t* pchHostName, std::uint32_t dwDecision) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(pchHostName);
    static_cast<void>(dwDecision);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_InternetSetStatusCallback(void* hInternet, void* lpfnInternetCallback) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hInternet);
    static_cast<void>(lpfnInternetCallback);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_InternetSetStatusCallbackA(void* hInternet, void* lpfnInternetCallback) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hInternet);
    static_cast<void>(lpfnInternetCallback);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_InternetSetStatusCallbackW(void* hInternet, void* lpfnInternetCallback) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hInternet);
    static_cast<void>(lpfnInternetCallback);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetTimeFromSystemTime(const void* pst, std::uint32_t dwRFC, char* lpszTime, std::uint32_t cbTime) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(pst);
    static_cast<void>(dwRFC);
    static_cast<void>(lpszTime);
    static_cast<void>(cbTime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetTimeFromSystemTimeA(const void* pst, std::uint32_t dwRFC, char* lpszTime, std::uint32_t cbTime) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(pst);
    static_cast<void>(dwRFC);
    static_cast<void>(lpszTime);
    static_cast<void>(cbTime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetTimeFromSystemTimeW(const void* pst, std::uint32_t dwRFC, char16_t* lpszTime, std::uint32_t cbTime) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(pst);
    static_cast<void>(dwRFC);
    static_cast<void>(lpszTime);
    static_cast<void>(cbTime);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetTimeToSystemTime(const char* lpszTime, void* pst, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszTime);
    static_cast<void>(pst);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetTimeToSystemTimeA(const char* lpszTime, void* pst, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszTime);
    static_cast<void>(pst);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetTimeToSystemTimeW(const char16_t* lpszTime, void* pst, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(lpszTime);
    static_cast<void>(pst);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetUnlockRequestFile(void* hLockRequestInfo) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hLockRequestInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_InternetWriteFile(void* hFile, const void* lpBuffer, std::uint32_t dwNumberOfBytesToWrite, std::uint32_t* lpdwNumberOfBytesWritten) noexcept {
    // Refused: the WinINet and WinHTTP stacks.
    //
    // these are protocol clients with their own caches, cookie stores and
    // proxy configuration; the socket surface is answered instead
    static_cast<void>(hFile);
    static_cast<void>(lpBuffer);
    static_cast<void>(dwNumberOfBytesToWrite);
    static_cast<void>(lpdwNumberOfBytesWritten);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwininetG_PrivacyGetZonePreferenceW(std::uint32_t dwZone, std::uint32_t dwType, std::uint32_t* pdwTemplate, char16_t* pszBuffer, std::uint32_t* pdwBufferLength) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(dwZone);
    static_cast<void>(dwType);
    static_cast<void>(pdwTemplate);
    static_cast<void>(pszBuffer);
    static_cast<void>(pdwBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwininetG_PrivacySetZonePreferenceW(std::uint32_t dwZone, std::uint32_t dwType, std::uint32_t dwTemplate, const char16_t* pszPreference) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(dwZone);
    static_cast<void>(dwType);
    static_cast<void>(dwTemplate);
    static_cast<void>(pszPreference);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_ReadUrlCacheEntryStream(void* hUrlCacheStream, std::uint32_t dwLocation, void* lpBuffer, std::uint32_t* lpdwLen, std::uint32_t Reserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hUrlCacheStream);
    static_cast<void>(dwLocation);
    static_cast<void>(lpBuffer);
    static_cast<void>(lpdwLen);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_ResumeSuspendedDownload(void* hRequest, std::uint32_t dwResultCode) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hRequest);
    static_cast<void>(dwResultCode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_RetrieveUrlCacheEntryFileA(const char* lpszUrlName, void* lpCacheEntryInfo, std::uint32_t* lpcbCacheEntryInfo, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    static_cast<void>(lpCacheEntryInfo);
    static_cast<void>(lpcbCacheEntryInfo);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_RetrieveUrlCacheEntryFileW(const char16_t* lpszUrlName, void* lpCacheEntryInfo, std::uint32_t* lpcbCacheEntryInfo, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    static_cast<void>(lpCacheEntryInfo);
    static_cast<void>(lpcbCacheEntryInfo);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_RetrieveUrlCacheEntryStreamA(const char* lpszUrlName, void* lpCacheEntryInfo, std::uint32_t* lpcbCacheEntryInfo, std::int32_t fRandomRead, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    static_cast<void>(lpCacheEntryInfo);
    static_cast<void>(lpcbCacheEntryInfo);
    static_cast<void>(fRandomRead);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwininetG_RetrieveUrlCacheEntryStreamW(const char16_t* lpszUrlName, void* lpCacheEntryInfo, std::uint32_t* lpcbCacheEntryInfo, std::int32_t fRandomRead, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    static_cast<void>(lpCacheEntryInfo);
    static_cast<void>(lpcbCacheEntryInfo);
    static_cast<void>(fRandomRead);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_SetUrlCacheEntryGroup(const char* lpszUrlName, std::uint32_t dwFlags, std::uint32_t GroupId, std::uint8_t* pbGroupAttributes, std::uint32_t cbGroupAttributes, void* lpReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    static_cast<void>(dwFlags);
    static_cast<void>(GroupId);
    static_cast<void>(pbGroupAttributes);
    static_cast<void>(cbGroupAttributes);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_SetUrlCacheEntryGroupA(const char* lpszUrlName, std::uint32_t dwFlags, std::uint32_t GroupId, std::uint8_t* pbGroupAttributes, std::uint32_t cbGroupAttributes, void* lpReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    static_cast<void>(dwFlags);
    static_cast<void>(GroupId);
    static_cast<void>(pbGroupAttributes);
    static_cast<void>(cbGroupAttributes);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_SetUrlCacheEntryGroupW(const char16_t* lpszUrlName, std::uint32_t dwFlags, std::uint32_t GroupId, std::uint8_t* pbGroupAttributes, std::uint32_t cbGroupAttributes, void* lpReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    static_cast<void>(dwFlags);
    static_cast<void>(GroupId);
    static_cast<void>(pbGroupAttributes);
    static_cast<void>(cbGroupAttributes);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_SetUrlCacheEntryInfoA(const char* lpszUrlName, void* lpCacheEntryInfo, std::uint32_t dwFieldControl) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    static_cast<void>(lpCacheEntryInfo);
    static_cast<void>(dwFieldControl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_SetUrlCacheEntryInfoW(const char16_t* lpszUrlName, void* lpCacheEntryInfo, std::uint32_t dwFieldControl) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    static_cast<void>(lpCacheEntryInfo);
    static_cast<void>(dwFieldControl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_SetUrlCacheGroupAttributeA(std::uint32_t gid, std::uint32_t dwFlags, std::uint32_t dwAttributes, std::uint64_t lpGroupInfo, void* lpReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(gid);
    static_cast<void>(dwFlags);
    static_cast<void>(dwAttributes);
    static_cast<void>(lpGroupInfo);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_SetUrlCacheGroupAttributeW(std::uint32_t gid, std::uint32_t dwFlags, std::uint32_t dwAttributes, std::uint64_t lpGroupInfo, void* lpReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(gid);
    static_cast<void>(dwFlags);
    static_cast<void>(dwAttributes);
    static_cast<void>(lpGroupInfo);
    static_cast<void>(lpReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_UnlockUrlCacheEntryFileA(const char* lpszUrlName, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_UnlockUrlCacheEntryFileW(const char16_t* lpszUrlName, std::uint32_t dwReserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(lpszUrlName);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwininetG_UnlockUrlCacheEntryStream(void* hUrlCacheStream, std::uint32_t Reserved) noexcept {
    // Refused: the WinINet stack.
    //
    // a protocol client with its own cache and cookie store; the socket
    // surface is answered instead
    static_cast<void>(hUrlCacheStream);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_wininet(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CommitUrlCacheEntryA", reinterpret_cast<void*>(&kwininetG_CommitUrlCacheEntryA));
    e("CommitUrlCacheEntryW", reinterpret_cast<void*>(&kwininetG_CommitUrlCacheEntryW));
    e("CreateMD5SSOHash", reinterpret_cast<void*>(&kwininetG_CreateMD5SSOHash));
    e("CreateUrlCacheEntryA", reinterpret_cast<void*>(&kwininetG_CreateUrlCacheEntryA));
    e("CreateUrlCacheEntryW", reinterpret_cast<void*>(&kwininetG_CreateUrlCacheEntryW));
    e("CreateUrlCacheGroup", reinterpret_cast<void*>(&kwininetG_CreateUrlCacheGroup));
    e("DeleteUrlCacheEntry", reinterpret_cast<void*>(&kwininetG_DeleteUrlCacheEntry));
    e("DeleteUrlCacheEntryA", reinterpret_cast<void*>(&kwininetG_DeleteUrlCacheEntryA));
    e("DeleteUrlCacheEntryW", reinterpret_cast<void*>(&kwininetG_DeleteUrlCacheEntryW));
    e("DeleteUrlCacheGroup", reinterpret_cast<void*>(&kwininetG_DeleteUrlCacheGroup));
    e("DetectAutoProxyUrl", reinterpret_cast<void*>(&kwininetG_DetectAutoProxyUrl));
    e("FindCloseUrlCache", reinterpret_cast<void*>(&kwininetG_FindCloseUrlCache));
    e("FindFirstUrlCacheEntryA", reinterpret_cast<void*>(&kwininetG_FindFirstUrlCacheEntryA));
    e("FindFirstUrlCacheEntryExA", reinterpret_cast<void*>(&kwininetG_FindFirstUrlCacheEntryExA));
    e("FindFirstUrlCacheEntryExW", reinterpret_cast<void*>(&kwininetG_FindFirstUrlCacheEntryExW));
    e("FindFirstUrlCacheEntryW", reinterpret_cast<void*>(&kwininetG_FindFirstUrlCacheEntryW));
    e("FindFirstUrlCacheGroup", reinterpret_cast<void*>(&kwininetG_FindFirstUrlCacheGroup));
    e("FindNextUrlCacheEntryA", reinterpret_cast<void*>(&kwininetG_FindNextUrlCacheEntryA));
    e("FindNextUrlCacheEntryExA", reinterpret_cast<void*>(&kwininetG_FindNextUrlCacheEntryExA));
    e("FindNextUrlCacheEntryExW", reinterpret_cast<void*>(&kwininetG_FindNextUrlCacheEntryExW));
    e("FindNextUrlCacheEntryW", reinterpret_cast<void*>(&kwininetG_FindNextUrlCacheEntryW));
    e("FindNextUrlCacheGroup", reinterpret_cast<void*>(&kwininetG_FindNextUrlCacheGroup));
    e("FtpCommandA", reinterpret_cast<void*>(&kwininetG_FtpCommandA));
    e("FtpCommandW", reinterpret_cast<void*>(&kwininetG_FtpCommandW));
    e("FtpCreateDirectoryA", reinterpret_cast<void*>(&kwininetG_FtpCreateDirectoryA));
    e("FtpCreateDirectoryW", reinterpret_cast<void*>(&kwininetG_FtpCreateDirectoryW));
    e("FtpDeleteFileA", reinterpret_cast<void*>(&kwininetG_FtpDeleteFileA));
    e("FtpDeleteFileW", reinterpret_cast<void*>(&kwininetG_FtpDeleteFileW));
    e("FtpFindFirstFileA", reinterpret_cast<void*>(&kwininetG_FtpFindFirstFileA));
    e("FtpFindFirstFileW", reinterpret_cast<void*>(&kwininetG_FtpFindFirstFileW));
    e("FtpGetCurrentDirectoryA", reinterpret_cast<void*>(&kwininetG_FtpGetCurrentDirectoryA));
    e("FtpGetCurrentDirectoryW", reinterpret_cast<void*>(&kwininetG_FtpGetCurrentDirectoryW));
    e("FtpGetFileA", reinterpret_cast<void*>(&kwininetG_FtpGetFileA));
    e("FtpGetFileEx", reinterpret_cast<void*>(&kwininetG_FtpGetFileEx));
    e("FtpGetFileSize", reinterpret_cast<void*>(&kwininetG_FtpGetFileSize));
    e("FtpGetFileW", reinterpret_cast<void*>(&kwininetG_FtpGetFileW));
    e("FtpOpenFileA", reinterpret_cast<void*>(&kwininetG_FtpOpenFileA));
    e("FtpOpenFileW", reinterpret_cast<void*>(&kwininetG_FtpOpenFileW));
    e("FtpPutFileA", reinterpret_cast<void*>(&kwininetG_FtpPutFileA));
    e("FtpPutFileEx", reinterpret_cast<void*>(&kwininetG_FtpPutFileEx));
    e("FtpPutFileW", reinterpret_cast<void*>(&kwininetG_FtpPutFileW));
    e("FtpRemoveDirectoryA", reinterpret_cast<void*>(&kwininetG_FtpRemoveDirectoryA));
    e("FtpRemoveDirectoryW", reinterpret_cast<void*>(&kwininetG_FtpRemoveDirectoryW));
    e("FtpRenameFileA", reinterpret_cast<void*>(&kwininetG_FtpRenameFileA));
    e("FtpRenameFileW", reinterpret_cast<void*>(&kwininetG_FtpRenameFileW));
    e("FtpSetCurrentDirectoryA", reinterpret_cast<void*>(&kwininetG_FtpSetCurrentDirectoryA));
    e("FtpSetCurrentDirectoryW", reinterpret_cast<void*>(&kwininetG_FtpSetCurrentDirectoryW));
    e("GetUrlCacheEntryInfoA", reinterpret_cast<void*>(&kwininetG_GetUrlCacheEntryInfoA));
    e("GetUrlCacheEntryInfoExA", reinterpret_cast<void*>(&kwininetG_GetUrlCacheEntryInfoExA));
    e("GetUrlCacheEntryInfoExW", reinterpret_cast<void*>(&kwininetG_GetUrlCacheEntryInfoExW));
    e("GetUrlCacheEntryInfoW", reinterpret_cast<void*>(&kwininetG_GetUrlCacheEntryInfoW));
    e("GetUrlCacheGroupAttributeA", reinterpret_cast<void*>(&kwininetG_GetUrlCacheGroupAttributeA));
    e("GetUrlCacheGroupAttributeW", reinterpret_cast<void*>(&kwininetG_GetUrlCacheGroupAttributeW));
    e("GopherCreateLocatorA", reinterpret_cast<void*>(&kwininetG_GopherCreateLocatorA));
    e("GopherCreateLocatorW", reinterpret_cast<void*>(&kwininetG_GopherCreateLocatorW));
    e("GopherFindFirstFileA", reinterpret_cast<void*>(&kwininetG_GopherFindFirstFileA));
    e("GopherFindFirstFileW", reinterpret_cast<void*>(&kwininetG_GopherFindFirstFileW));
    e("GopherGetAttributeA", reinterpret_cast<void*>(&kwininetG_GopherGetAttributeA));
    e("GopherGetAttributeW", reinterpret_cast<void*>(&kwininetG_GopherGetAttributeW));
    e("GopherGetLocatorTypeA", reinterpret_cast<void*>(&kwininetG_GopherGetLocatorTypeA));
    e("GopherGetLocatorTypeW", reinterpret_cast<void*>(&kwininetG_GopherGetLocatorTypeW));
    e("GopherOpenFileA", reinterpret_cast<void*>(&kwininetG_GopherOpenFileA));
    e("GopherOpenFileW", reinterpret_cast<void*>(&kwininetG_GopherOpenFileW));
    e("HttpAddRequestHeadersA", reinterpret_cast<void*>(&kwininetG_HttpAddRequestHeadersA));
    e("HttpAddRequestHeadersW", reinterpret_cast<void*>(&kwininetG_HttpAddRequestHeadersW));
    e("HttpEndRequestA", reinterpret_cast<void*>(&kwininetG_HttpEndRequestA));
    e("HttpEndRequestW", reinterpret_cast<void*>(&kwininetG_HttpEndRequestW));
    e("HttpOpenRequestA", reinterpret_cast<void*>(&kwininetG_HttpOpenRequestA));
    e("HttpOpenRequestW", reinterpret_cast<void*>(&kwininetG_HttpOpenRequestW));
    e("HttpQueryInfoA", reinterpret_cast<void*>(&kwininetG_HttpQueryInfoA));
    e("HttpQueryInfoW", reinterpret_cast<void*>(&kwininetG_HttpQueryInfoW));
    e("HttpSendRequestExA", reinterpret_cast<void*>(&kwininetG_HttpSendRequestExA));
    e("HttpSendRequestExW", reinterpret_cast<void*>(&kwininetG_HttpSendRequestExW));
    e("HttpSendRequestW", reinterpret_cast<void*>(&kwininetG_HttpSendRequestW));
    e("InternetAttemptConnect", reinterpret_cast<void*>(&kwininetG_InternetAttemptConnect));
    e("InternetAutodial", reinterpret_cast<void*>(&kwininetG_InternetAutodial));
    e("InternetAutodialHangup", reinterpret_cast<void*>(&kwininetG_InternetAutodialHangup));
    e("InternetCanonicalizeUrlA", reinterpret_cast<void*>(&kwininetG_InternetCanonicalizeUrlA));
    e("InternetCanonicalizeUrlW", reinterpret_cast<void*>(&kwininetG_InternetCanonicalizeUrlW));
    e("InternetCheckConnectionA", reinterpret_cast<void*>(&kwininetG_InternetCheckConnectionA));
    e("InternetCheckConnectionW", reinterpret_cast<void*>(&kwininetG_InternetCheckConnectionW));
    e("InternetClearAllPerSiteCookieDecisions", reinterpret_cast<void*>(&kwininetG_InternetClearAllPerSiteCookieDecisions));
    e("InternetCombineUrlA", reinterpret_cast<void*>(&kwininetG_InternetCombineUrlA));
    e("InternetCombineUrlW", reinterpret_cast<void*>(&kwininetG_InternetCombineUrlW));
    e("InternetConfirmZoneCrossing", reinterpret_cast<void*>(&kwininetG_InternetConfirmZoneCrossing));
    e("InternetConfirmZoneCrossingA", reinterpret_cast<void*>(&kwininetG_InternetConfirmZoneCrossingA));
    e("InternetConfirmZoneCrossingW", reinterpret_cast<void*>(&kwininetG_InternetConfirmZoneCrossingW));
    e("InternetConnectW", reinterpret_cast<void*>(&kwininetG_InternetConnectW));
    e("InternetCrackUrlA", reinterpret_cast<void*>(&kwininetG_InternetCrackUrlA));
    e("InternetCrackUrlW", reinterpret_cast<void*>(&kwininetG_InternetCrackUrlW));
    e("InternetCreateUrlA", reinterpret_cast<void*>(&kwininetG_InternetCreateUrlA));
    e("InternetCreateUrlW", reinterpret_cast<void*>(&kwininetG_InternetCreateUrlW));
    e("InternetDial", reinterpret_cast<void*>(&kwininetG_InternetDial));
    e("InternetDialA", reinterpret_cast<void*>(&kwininetG_InternetDialA));
    e("InternetDialW", reinterpret_cast<void*>(&kwininetG_InternetDialW));
    e("InternetEnumPerSiteCookieDecisionA", reinterpret_cast<void*>(&kwininetG_InternetEnumPerSiteCookieDecisionA));
    e("InternetEnumPerSiteCookieDecisionW", reinterpret_cast<void*>(&kwininetG_InternetEnumPerSiteCookieDecisionW));
    e("InternetErrorDlg", reinterpret_cast<void*>(&kwininetG_InternetErrorDlg));
    e("InternetFindNextFileA", reinterpret_cast<void*>(&kwininetG_InternetFindNextFileA));
    e("InternetFindNextFileW", reinterpret_cast<void*>(&kwininetG_InternetFindNextFileW));
    e("InternetGetConnectedState", reinterpret_cast<void*>(&kwininetG_InternetGetConnectedState));
    e("InternetGetConnectedStateEx", reinterpret_cast<void*>(&kwininetG_InternetGetConnectedStateEx));
    e("InternetGetConnectedStateExA", reinterpret_cast<void*>(&kwininetG_InternetGetConnectedStateExA));
    e("InternetGetConnectedStateExW", reinterpret_cast<void*>(&kwininetG_InternetGetConnectedStateExW));
    e("InternetGetCookieA", reinterpret_cast<void*>(&kwininetG_InternetGetCookieA));
    e("InternetGetCookieExA", reinterpret_cast<void*>(&kwininetG_InternetGetCookieExA));
    e("InternetGetCookieExW", reinterpret_cast<void*>(&kwininetG_InternetGetCookieExW));
    e("InternetGetCookieW", reinterpret_cast<void*>(&kwininetG_InternetGetCookieW));
    e("InternetGetLastResponseInfoA", reinterpret_cast<void*>(&kwininetG_InternetGetLastResponseInfoA));
    e("InternetGetLastResponseInfoW", reinterpret_cast<void*>(&kwininetG_InternetGetLastResponseInfoW));
    e("InternetGetPerSiteCookieDecisionA", reinterpret_cast<void*>(&kwininetG_InternetGetPerSiteCookieDecisionA));
    e("InternetGetPerSiteCookieDecisionW", reinterpret_cast<void*>(&kwininetG_InternetGetPerSiteCookieDecisionW));
    e("InternetGoOnline", reinterpret_cast<void*>(&kwininetG_InternetGoOnline));
    e("InternetGoOnlineA", reinterpret_cast<void*>(&kwininetG_InternetGoOnlineA));
    e("InternetGoOnlineW", reinterpret_cast<void*>(&kwininetG_InternetGoOnlineW));
    e("InternetHangUp", reinterpret_cast<void*>(&kwininetG_InternetHangUp));
    e("InternetInitializeAutoProxyDll", reinterpret_cast<void*>(&kwininetG_InternetInitializeAutoProxyDll));
    e("InternetLockRequestFile", reinterpret_cast<void*>(&kwininetG_InternetLockRequestFile));
    e("InternetOpenUrlW", reinterpret_cast<void*>(&kwininetG_InternetOpenUrlW));
    e("InternetOpenW", reinterpret_cast<void*>(&kwininetG_InternetOpenW));
    e("InternetQueryDataAvailable", reinterpret_cast<void*>(&kwininetG_InternetQueryDataAvailable));
    e("InternetQueryOptionA", reinterpret_cast<void*>(&kwininetG_InternetQueryOptionA));
    e("InternetQueryOptionW", reinterpret_cast<void*>(&kwininetG_InternetQueryOptionW));
    e("InternetReadFileExA", reinterpret_cast<void*>(&kwininetG_InternetReadFileExA));
    e("InternetReadFileExW", reinterpret_cast<void*>(&kwininetG_InternetReadFileExW));
    e("InternetSetCookieA", reinterpret_cast<void*>(&kwininetG_InternetSetCookieA));
    e("InternetSetCookieExA", reinterpret_cast<void*>(&kwininetG_InternetSetCookieExA));
    e("InternetSetCookieExW", reinterpret_cast<void*>(&kwininetG_InternetSetCookieExW));
    e("InternetSetCookieW", reinterpret_cast<void*>(&kwininetG_InternetSetCookieW));
    e("InternetSetDialState", reinterpret_cast<void*>(&kwininetG_InternetSetDialState));
    e("InternetSetDialStateA", reinterpret_cast<void*>(&kwininetG_InternetSetDialStateA));
    e("InternetSetDialStateW", reinterpret_cast<void*>(&kwininetG_InternetSetDialStateW));
    e("InternetSetFilePointer", reinterpret_cast<void*>(&kwininetG_InternetSetFilePointer));
    e("InternetSetOptionA", reinterpret_cast<void*>(&kwininetG_InternetSetOptionA));
    e("InternetSetOptionExA", reinterpret_cast<void*>(&kwininetG_InternetSetOptionExA));
    e("InternetSetOptionExW", reinterpret_cast<void*>(&kwininetG_InternetSetOptionExW));
    e("InternetSetOptionW", reinterpret_cast<void*>(&kwininetG_InternetSetOptionW));
    e("InternetSetPerSiteCookieDecisionA", reinterpret_cast<void*>(&kwininetG_InternetSetPerSiteCookieDecisionA));
    e("InternetSetPerSiteCookieDecisionW", reinterpret_cast<void*>(&kwininetG_InternetSetPerSiteCookieDecisionW));
    e("InternetSetStatusCallback", reinterpret_cast<void*>(&kwininetG_InternetSetStatusCallback));
    e("InternetSetStatusCallbackA", reinterpret_cast<void*>(&kwininetG_InternetSetStatusCallbackA));
    e("InternetSetStatusCallbackW", reinterpret_cast<void*>(&kwininetG_InternetSetStatusCallbackW));
    e("InternetTimeFromSystemTime", reinterpret_cast<void*>(&kwininetG_InternetTimeFromSystemTime));
    e("InternetTimeFromSystemTimeA", reinterpret_cast<void*>(&kwininetG_InternetTimeFromSystemTimeA));
    e("InternetTimeFromSystemTimeW", reinterpret_cast<void*>(&kwininetG_InternetTimeFromSystemTimeW));
    e("InternetTimeToSystemTime", reinterpret_cast<void*>(&kwininetG_InternetTimeToSystemTime));
    e("InternetTimeToSystemTimeA", reinterpret_cast<void*>(&kwininetG_InternetTimeToSystemTimeA));
    e("InternetTimeToSystemTimeW", reinterpret_cast<void*>(&kwininetG_InternetTimeToSystemTimeW));
    e("InternetUnlockRequestFile", reinterpret_cast<void*>(&kwininetG_InternetUnlockRequestFile));
    e("InternetWriteFile", reinterpret_cast<void*>(&kwininetG_InternetWriteFile));
    e("PrivacyGetZonePreferenceW", reinterpret_cast<void*>(&kwininetG_PrivacyGetZonePreferenceW));
    e("PrivacySetZonePreferenceW", reinterpret_cast<void*>(&kwininetG_PrivacySetZonePreferenceW));
    e("ReadUrlCacheEntryStream", reinterpret_cast<void*>(&kwininetG_ReadUrlCacheEntryStream));
    e("ResumeSuspendedDownload", reinterpret_cast<void*>(&kwininetG_ResumeSuspendedDownload));
    e("RetrieveUrlCacheEntryFileA", reinterpret_cast<void*>(&kwininetG_RetrieveUrlCacheEntryFileA));
    e("RetrieveUrlCacheEntryFileW", reinterpret_cast<void*>(&kwininetG_RetrieveUrlCacheEntryFileW));
    e("RetrieveUrlCacheEntryStreamA", reinterpret_cast<void*>(&kwininetG_RetrieveUrlCacheEntryStreamA));
    e("RetrieveUrlCacheEntryStreamW", reinterpret_cast<void*>(&kwininetG_RetrieveUrlCacheEntryStreamW));
    e("SetUrlCacheEntryGroup", reinterpret_cast<void*>(&kwininetG_SetUrlCacheEntryGroup));
    e("SetUrlCacheEntryGroupA", reinterpret_cast<void*>(&kwininetG_SetUrlCacheEntryGroupA));
    e("SetUrlCacheEntryGroupW", reinterpret_cast<void*>(&kwininetG_SetUrlCacheEntryGroupW));
    e("SetUrlCacheEntryInfoA", reinterpret_cast<void*>(&kwininetG_SetUrlCacheEntryInfoA));
    e("SetUrlCacheEntryInfoW", reinterpret_cast<void*>(&kwininetG_SetUrlCacheEntryInfoW));
    e("SetUrlCacheGroupAttributeA", reinterpret_cast<void*>(&kwininetG_SetUrlCacheGroupAttributeA));
    e("SetUrlCacheGroupAttributeW", reinterpret_cast<void*>(&kwininetG_SetUrlCacheGroupAttributeW));
    e("UnlockUrlCacheEntryFileA", reinterpret_cast<void*>(&kwininetG_UnlockUrlCacheEntryFileA));
    e("UnlockUrlCacheEntryFileW", reinterpret_cast<void*>(&kwininetG_UnlockUrlCacheEntryFileW));
    e("UnlockUrlCacheEntryStream", reinterpret_cast<void*>(&kwininetG_UnlockUrlCacheEntryStream));
}
}  // namespace occ::runtime::winabi

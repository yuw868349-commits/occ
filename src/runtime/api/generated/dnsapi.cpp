// The DNSAPI surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsAcquireContextHandle_A(std::uint32_t CredentialFlags, void* pCredentials, void** pContextHandle) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(CredentialFlags);
    static_cast<void>(pCredentials);
    static_cast<void>(pContextHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsAcquireContextHandle_W(std::uint32_t CredentialFlags, void* pCredentials, void** pContextHandle) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(CredentialFlags);
    static_cast<void>(pCredentials);
    static_cast<void>(pContextHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdnsapiG_DnsConnectionDeletePolicyEntries(std::uint64_t PolicyEntryTag) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(PolicyEntryTag);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdnsapiG_DnsConnectionDeleteProxyInfo(const char16_t* pwszConnectionName, std::uint64_t Type) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pwszConnectionName);
    static_cast<void>(Type);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kdnsapiG_DnsConnectionFreeNameList(void* pNameList) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pNameList);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kdnsapiG_DnsConnectionFreeProxyInfo(void* pProxyInfo) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pProxyInfo);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kdnsapiG_DnsConnectionFreeProxyInfoEx(void* pProxyInfoEx) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pProxyInfoEx);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kdnsapiG_DnsConnectionFreeProxyList(void* pProxyList) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pProxyList);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdnsapiG_DnsConnectionGetNameList(void* pNameList) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pNameList);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdnsapiG_DnsConnectionGetProxyInfo(const char16_t* pwszConnectionName, std::uint64_t Type, void* pProxyInfo) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pwszConnectionName);
    static_cast<void>(Type);
    static_cast<void>(pProxyInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdnsapiG_DnsConnectionGetProxyInfoForHostUrl(const char16_t* pwszHostUrl, std::uint8_t* pSelectionContext, std::uint32_t dwSelectionContextLength, std::uint32_t dwExplicitInterfaceIndex, void* pProxyInfoEx) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pwszHostUrl);
    static_cast<void>(pSelectionContext);
    static_cast<void>(dwSelectionContextLength);
    static_cast<void>(dwExplicitInterfaceIndex);
    static_cast<void>(pProxyInfoEx);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdnsapiG_DnsConnectionGetProxyList(const char16_t* pwszConnectionName, void* pProxyList) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pwszConnectionName);
    static_cast<void>(pProxyList);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdnsapiG_DnsConnectionSetPolicyEntries(std::uint64_t PolicyEntryTag, void* pPolicyEntryList) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(PolicyEntryTag);
    static_cast<void>(pPolicyEntryList);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdnsapiG_DnsConnectionSetProxyInfo(const char16_t* pwszConnectionName, std::uint64_t Type, const void* pProxyInfo) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pwszConnectionName);
    static_cast<void>(Type);
    static_cast<void>(pProxyInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdnsapiG_DnsConnectionUpdateIfIndexTable(void* pConnectionIfIndexEntries) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pConnectionIfIndexEntries);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsExtractRecordsFromMessage_UTF8(std::uint64_t pDnsBuffer, std::uint16_t wMessageLength, void* ppRecord) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pDnsBuffer);
    static_cast<void>(wMessageLength);
    static_cast<void>(ppRecord);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsExtractRecordsFromMessage_W(std::uint64_t pDnsBuffer, std::uint16_t wMessageLength, void* ppRecord) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pDnsBuffer);
    static_cast<void>(wMessageLength);
    static_cast<void>(ppRecord);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kdnsapiG_DnsFree(void* pData, std::uint64_t FreeType) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pData);
    static_cast<void>(FreeType);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kdnsapiG_DnsFreeProxyName(char16_t* proxyName) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(proxyName);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdnsapiG_DnsGetProxyInformation(const char16_t* hostName, void* proxyInformation, void* defaultProxyInformation, std::uint64_t completionRoutine, void* completionContext) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(hostName);
    static_cast<void>(proxyInformation);
    static_cast<void>(defaultProxyInformation);
    static_cast<void>(completionRoutine);
    static_cast<void>(completionContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsModifyRecordsInSet_A(void* pAddRecords, void* pDeleteRecords, std::uint32_t Options, void* hContext, std::uint64_t* pServerList, void* pReserved) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pAddRecords);
    static_cast<void>(pDeleteRecords);
    static_cast<void>(Options);
    static_cast<void>(hContext);
    static_cast<void>(pServerList);
    static_cast<void>(pReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsModifyRecordsInSet_UTF8(std::uint64_t pAddRecords, std::uint64_t pDeleteRecords, std::uint32_t Options, void* hContext, std::uint64_t* pServerList, void* pReserved) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pAddRecords);
    static_cast<void>(pDeleteRecords);
    static_cast<void>(Options);
    static_cast<void>(hContext);
    static_cast<void>(pServerList);
    static_cast<void>(pReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsModifyRecordsInSet_W(void* pAddRecords, void* pDeleteRecords, std::uint32_t Options, void* hContext, std::uint64_t* pServerList, void* pReserved) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pAddRecords);
    static_cast<void>(pDeleteRecords);
    static_cast<void>(Options);
    static_cast<void>(hContext);
    static_cast<void>(pServerList);
    static_cast<void>(pReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsNameCompare_A(char* pName1, char* pName2) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pName1);
    static_cast<void>(pName2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsNameCompare_W(char16_t* pName1, char16_t* pName2) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pName1);
    static_cast<void>(pName2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsQueryConfig(std::uint64_t Config, std::uint32_t Flag, char16_t* pwsAdapterName, void* pReserved, void* pBuffer, std::uint32_t* pBufferLength) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(Config);
    static_cast<void>(Flag);
    static_cast<void>(pwsAdapterName);
    static_cast<void>(pReserved);
    static_cast<void>(pBuffer);
    static_cast<void>(pBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsQuery_A(const char* pszName, std::uint16_t wType, std::uint32_t Options, std::uint64_t* aipServers, void* ppQueryResults, void** pReserved) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pszName);
    static_cast<void>(wType);
    static_cast<void>(Options);
    static_cast<void>(aipServers);
    static_cast<void>(ppQueryResults);
    static_cast<void>(pReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsQuery_UTF8(const char* pszName, std::uint16_t wType, std::uint32_t Options, std::uint64_t* aipServers, void* ppQueryResults, void** pReserved) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pszName);
    static_cast<void>(wType);
    static_cast<void>(Options);
    static_cast<void>(aipServers);
    static_cast<void>(ppQueryResults);
    static_cast<void>(pReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsQuery_W(const char16_t* pszName, std::uint16_t wType, std::uint32_t Options, std::uint64_t* aipServers, void* ppQueryResults, void** pReserved) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pszName);
    static_cast<void>(wType);
    static_cast<void>(Options);
    static_cast<void>(aipServers);
    static_cast<void>(ppQueryResults);
    static_cast<void>(pReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsRecordCompare(void* pRecord1, void* pRecord2) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pRecord1);
    static_cast<void>(pRecord2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kdnsapiG_DnsRecordCopyEx(void* pRecord, std::uint32_t CharSetIn, std::uint32_t CharSetOut) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pRecord);
    static_cast<void>(CharSetIn);
    static_cast<void>(CharSetOut);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kdnsapiG_DnsRecordListFree(void* pRecordList, std::uint64_t FreeType) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pRecordList);
    static_cast<void>(FreeType);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsRecordSetCompare(void* pRR1, void* pRR2, void* ppDiff1, void* ppDiff2) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pRR1);
    static_cast<void>(pRR2);
    static_cast<void>(ppDiff1);
    static_cast<void>(ppDiff2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kdnsapiG_DnsRecordSetCopyEx(void* pRecordSet, std::uint32_t CharSetIn, std::uint32_t CharSetOut) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pRecordSet);
    static_cast<void>(CharSetIn);
    static_cast<void>(CharSetOut);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kdnsapiG_DnsRecordSetDetach(void* pRecordList) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pRecordList);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kdnsapiG_DnsReleaseContextHandle(void* hContext) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(hContext);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsReplaceRecordSetA(void* pNewSet, std::uint32_t Options, void* hContext, std::uint64_t* pServerList, void* pReserved) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pNewSet);
    static_cast<void>(Options);
    static_cast<void>(hContext);
    static_cast<void>(pServerList);
    static_cast<void>(pReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsReplaceRecordSetUTF8(std::uint64_t pNewSet, std::uint32_t Options, void* hContext, std::uint64_t* pServerList, void* pReserved) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pNewSet);
    static_cast<void>(Options);
    static_cast<void>(hContext);
    static_cast<void>(pServerList);
    static_cast<void>(pReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsReplaceRecordSetW(void* pNewSet, std::uint32_t Options, void* hContext, std::uint64_t* pServerList, void* pReserved) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pNewSet);
    static_cast<void>(Options);
    static_cast<void>(hContext);
    static_cast<void>(pServerList);
    static_cast<void>(pReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsServiceBrowse(std::uint64_t pRequest, void* pCancel) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(pRequest);
    static_cast<void>(pCancel);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsServiceBrowseCancel(void* pCancelHandle) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(pCancelHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kdnsapiG_DnsServiceConstructInstance(const char16_t* pServiceName, const char16_t* pHostName, std::uint64_t pIp4, std::uint64_t pIp6, std::uint16_t wPort, std::uint16_t wPriority, std::uint16_t wWeight, std::uint32_t dwPropertiesCount, const char16_t** keys, const char16_t** values) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(pServiceName);
    static_cast<void>(pHostName);
    static_cast<void>(pIp4);
    static_cast<void>(pIp6);
    static_cast<void>(wPort);
    static_cast<void>(wPriority);
    static_cast<void>(wWeight);
    static_cast<void>(dwPropertiesCount);
    static_cast<void>(keys);
    static_cast<void>(values);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kdnsapiG_DnsServiceCopyInstance(std::uint64_t pOrig) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(pOrig);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdnsapiG_DnsServiceDeRegister(std::uint64_t pRequest, void* pCancel) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(pRequest);
    static_cast<void>(pCancel);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kdnsapiG_DnsServiceFreeInstance(std::uint64_t pInstance) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(pInstance);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdnsapiG_DnsServiceRegister(std::uint64_t pRequest, void* pCancel) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(pRequest);
    static_cast<void>(pCancel);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdnsapiG_DnsServiceRegisterCancel(void* pCancelHandle) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(pCancelHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsServiceResolve(std::uint64_t pRequest, void* pCancel) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(pRequest);
    static_cast<void>(pCancel);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsServiceResolveCancel(void* pCancelHandle) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(pCancelHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsStartMulticastQuery(std::uint64_t pQueryRequest, std::uint64_t pHandle) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pQueryRequest);
    static_cast<void>(pHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsStopMulticastQuery(std::uint64_t pHandle) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsValidateName_A(const char* pszName, std::uint64_t Format) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pszName);
    static_cast<void>(Format);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsValidateName_UTF8(const char* pszName, std::uint64_t Format) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pszName);
    static_cast<void>(Format);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsValidateName_W(const char16_t* pwszName, std::uint64_t Format) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pwszName);
    static_cast<void>(Format);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsWriteQuestionToBuffer_UTF8(std::uint64_t pDnsBuffer, std::uint32_t* pdwBufferSize, char* pszName, std::uint16_t wType, std::uint16_t Xid, std::int32_t fRecursionDesired) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pDnsBuffer);
    static_cast<void>(pdwBufferSize);
    static_cast<void>(pszName);
    static_cast<void>(wType);
    static_cast<void>(Xid);
    static_cast<void>(fRecursionDesired);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kdnsapiG_DnsWriteQuestionToBuffer_W(std::uint64_t pDnsBuffer, std::uint32_t* pdwBufferSize, char16_t* pszName, std::uint16_t wType, std::uint16_t Xid, std::int32_t fRecursionDesired) noexcept {
    // Refused: the DNS client.
    //
    // the call reaches a resolver whose configuration is a service's state;
    // this runtime answers the host resolver through WinSock
    static_cast<void>(pDnsBuffer);
    static_cast<void>(pdwBufferSize);
    static_cast<void>(pszName);
    static_cast<void>(wType);
    static_cast<void>(Xid);
    static_cast<void>(fRecursionDesired);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_dnsapi(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("DnsAcquireContextHandle_A", reinterpret_cast<void*>(&kdnsapiG_DnsAcquireContextHandle_A));
    e("DnsAcquireContextHandle_W", reinterpret_cast<void*>(&kdnsapiG_DnsAcquireContextHandle_W));
    e("DnsConnectionDeletePolicyEntries", reinterpret_cast<void*>(&kdnsapiG_DnsConnectionDeletePolicyEntries));
    e("DnsConnectionDeleteProxyInfo", reinterpret_cast<void*>(&kdnsapiG_DnsConnectionDeleteProxyInfo));
    e("DnsConnectionFreeNameList", reinterpret_cast<void*>(&kdnsapiG_DnsConnectionFreeNameList));
    e("DnsConnectionFreeProxyInfo", reinterpret_cast<void*>(&kdnsapiG_DnsConnectionFreeProxyInfo));
    e("DnsConnectionFreeProxyInfoEx", reinterpret_cast<void*>(&kdnsapiG_DnsConnectionFreeProxyInfoEx));
    e("DnsConnectionFreeProxyList", reinterpret_cast<void*>(&kdnsapiG_DnsConnectionFreeProxyList));
    e("DnsConnectionGetNameList", reinterpret_cast<void*>(&kdnsapiG_DnsConnectionGetNameList));
    e("DnsConnectionGetProxyInfo", reinterpret_cast<void*>(&kdnsapiG_DnsConnectionGetProxyInfo));
    e("DnsConnectionGetProxyInfoForHostUrl", reinterpret_cast<void*>(&kdnsapiG_DnsConnectionGetProxyInfoForHostUrl));
    e("DnsConnectionGetProxyList", reinterpret_cast<void*>(&kdnsapiG_DnsConnectionGetProxyList));
    e("DnsConnectionSetPolicyEntries", reinterpret_cast<void*>(&kdnsapiG_DnsConnectionSetPolicyEntries));
    e("DnsConnectionSetProxyInfo", reinterpret_cast<void*>(&kdnsapiG_DnsConnectionSetProxyInfo));
    e("DnsConnectionUpdateIfIndexTable", reinterpret_cast<void*>(&kdnsapiG_DnsConnectionUpdateIfIndexTable));
    e("DnsExtractRecordsFromMessage_UTF8", reinterpret_cast<void*>(&kdnsapiG_DnsExtractRecordsFromMessage_UTF8));
    e("DnsExtractRecordsFromMessage_W", reinterpret_cast<void*>(&kdnsapiG_DnsExtractRecordsFromMessage_W));
    e("DnsFree", reinterpret_cast<void*>(&kdnsapiG_DnsFree));
    e("DnsFreeProxyName", reinterpret_cast<void*>(&kdnsapiG_DnsFreeProxyName));
    e("DnsGetProxyInformation", reinterpret_cast<void*>(&kdnsapiG_DnsGetProxyInformation));
    e("DnsModifyRecordsInSet_A", reinterpret_cast<void*>(&kdnsapiG_DnsModifyRecordsInSet_A));
    e("DnsModifyRecordsInSet_UTF8", reinterpret_cast<void*>(&kdnsapiG_DnsModifyRecordsInSet_UTF8));
    e("DnsModifyRecordsInSet_W", reinterpret_cast<void*>(&kdnsapiG_DnsModifyRecordsInSet_W));
    e("DnsNameCompare_A", reinterpret_cast<void*>(&kdnsapiG_DnsNameCompare_A));
    e("DnsNameCompare_W", reinterpret_cast<void*>(&kdnsapiG_DnsNameCompare_W));
    e("DnsQueryConfig", reinterpret_cast<void*>(&kdnsapiG_DnsQueryConfig));
    e("DnsQuery_A", reinterpret_cast<void*>(&kdnsapiG_DnsQuery_A));
    e("DnsQuery_UTF8", reinterpret_cast<void*>(&kdnsapiG_DnsQuery_UTF8));
    e("DnsQuery_W", reinterpret_cast<void*>(&kdnsapiG_DnsQuery_W));
    e("DnsRecordCompare", reinterpret_cast<void*>(&kdnsapiG_DnsRecordCompare));
    e("DnsRecordCopyEx", reinterpret_cast<void*>(&kdnsapiG_DnsRecordCopyEx));
    e("DnsRecordListFree", reinterpret_cast<void*>(&kdnsapiG_DnsRecordListFree));
    e("DnsRecordSetCompare", reinterpret_cast<void*>(&kdnsapiG_DnsRecordSetCompare));
    e("DnsRecordSetCopyEx", reinterpret_cast<void*>(&kdnsapiG_DnsRecordSetCopyEx));
    e("DnsRecordSetDetach", reinterpret_cast<void*>(&kdnsapiG_DnsRecordSetDetach));
    e("DnsReleaseContextHandle", reinterpret_cast<void*>(&kdnsapiG_DnsReleaseContextHandle));
    e("DnsReplaceRecordSetA", reinterpret_cast<void*>(&kdnsapiG_DnsReplaceRecordSetA));
    e("DnsReplaceRecordSetUTF8", reinterpret_cast<void*>(&kdnsapiG_DnsReplaceRecordSetUTF8));
    e("DnsReplaceRecordSetW", reinterpret_cast<void*>(&kdnsapiG_DnsReplaceRecordSetW));
    e("DnsServiceBrowse", reinterpret_cast<void*>(&kdnsapiG_DnsServiceBrowse));
    e("DnsServiceBrowseCancel", reinterpret_cast<void*>(&kdnsapiG_DnsServiceBrowseCancel));
    e("DnsServiceConstructInstance", reinterpret_cast<void*>(&kdnsapiG_DnsServiceConstructInstance));
    e("DnsServiceCopyInstance", reinterpret_cast<void*>(&kdnsapiG_DnsServiceCopyInstance));
    e("DnsServiceDeRegister", reinterpret_cast<void*>(&kdnsapiG_DnsServiceDeRegister));
    e("DnsServiceFreeInstance", reinterpret_cast<void*>(&kdnsapiG_DnsServiceFreeInstance));
    e("DnsServiceRegister", reinterpret_cast<void*>(&kdnsapiG_DnsServiceRegister));
    e("DnsServiceRegisterCancel", reinterpret_cast<void*>(&kdnsapiG_DnsServiceRegisterCancel));
    e("DnsServiceResolve", reinterpret_cast<void*>(&kdnsapiG_DnsServiceResolve));
    e("DnsServiceResolveCancel", reinterpret_cast<void*>(&kdnsapiG_DnsServiceResolveCancel));
    e("DnsStartMulticastQuery", reinterpret_cast<void*>(&kdnsapiG_DnsStartMulticastQuery));
    e("DnsStopMulticastQuery", reinterpret_cast<void*>(&kdnsapiG_DnsStopMulticastQuery));
    e("DnsValidateName_A", reinterpret_cast<void*>(&kdnsapiG_DnsValidateName_A));
    e("DnsValidateName_UTF8", reinterpret_cast<void*>(&kdnsapiG_DnsValidateName_UTF8));
    e("DnsValidateName_W", reinterpret_cast<void*>(&kdnsapiG_DnsValidateName_W));
    e("DnsWriteQuestionToBuffer_UTF8", reinterpret_cast<void*>(&kdnsapiG_DnsWriteQuestionToBuffer_UTF8));
    e("DnsWriteQuestionToBuffer_W", reinterpret_cast<void*>(&kdnsapiG_DnsWriteQuestionToBuffer_W));
}
}  // namespace occ::runtime::winabi

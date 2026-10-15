// The IPHLPAPI surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_AddIPAddress(void* Address, void* IpMask, std::uint32_t IfIndex, std::uint32_t* NTEContext, std::uint32_t* NTEInstance) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(Address);
    static_cast<void>(IpMask);
    static_cast<void>(IfIndex);
    static_cast<void>(NTEContext);
    static_cast<void>(NTEInstance);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kiphlpapiG_CancelIPChangeNotify(void* notifyOverlapped) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(notifyOverlapped);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_ConvertInterfaceAliasToLuid(const char16_t* InterfaceAlias, std::uint64_t* InterfaceLuid) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(InterfaceAlias);
    static_cast<void>(InterfaceLuid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_ConvertInterfaceGuidToLuid(const void* InterfaceGuid, std::uint64_t* InterfaceLuid) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(InterfaceGuid);
    static_cast<void>(InterfaceLuid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_ConvertInterfaceIndexToLuid(std::uint64_t InterfaceIndex, std::uint64_t* InterfaceLuid) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(InterfaceIndex);
    static_cast<void>(InterfaceLuid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_ConvertInterfaceLuidToAlias(const std::uint64_t* InterfaceLuid, char16_t* InterfaceAlias, std::uint64_t Length) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(InterfaceLuid);
    static_cast<void>(InterfaceAlias);
    static_cast<void>(Length);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_ConvertInterfaceLuidToGuid(const std::uint64_t* InterfaceLuid, void* InterfaceGuid) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(InterfaceLuid);
    static_cast<void>(InterfaceGuid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_ConvertInterfaceLuidToIndex(const std::uint64_t* InterfaceLuid, std::uint64_t InterfaceIndex) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(InterfaceLuid);
    static_cast<void>(InterfaceIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_ConvertInterfaceLuidToNameA(const std::uint64_t* InterfaceLuid, char* InterfaceName, std::uint64_t Length) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(InterfaceLuid);
    static_cast<void>(InterfaceName);
    static_cast<void>(Length);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_ConvertInterfaceLuidToNameW(const std::uint64_t* InterfaceLuid, char16_t* InterfaceName, std::uint64_t Length) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(InterfaceLuid);
    static_cast<void>(InterfaceName);
    static_cast<void>(Length);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_ConvertInterfaceNameToLuidA(const char* InterfaceName, std::uint64_t* InterfaceLuid) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(InterfaceName);
    static_cast<void>(InterfaceLuid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_ConvertInterfaceNameToLuidW(const char16_t* InterfaceName, std::uint64_t* InterfaceLuid) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(InterfaceName);
    static_cast<void>(InterfaceLuid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_ConvertIpv4MaskToLength(std::uint32_t Mask, std::uint8_t* MaskLength) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(Mask);
    static_cast<void>(MaskLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_ConvertLengthToIpv4Mask(std::uint32_t MaskLength, std::uint32_t* Mask) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(MaskLength);
    static_cast<void>(Mask);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_CreateIpNetEntry(std::uint64_t pArpEntry) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(pArpEntry);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_CreatePersistentTcpPortReservation(std::uint16_t StartPort, std::uint16_t NumberOfPorts, std::uint64_t* Token) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(StartPort);
    static_cast<void>(NumberOfPorts);
    static_cast<void>(Token);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_CreatePersistentUdpPortReservation(std::uint16_t StartPort, std::uint16_t NumberOfPorts, std::uint64_t* Token) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(StartPort);
    static_cast<void>(NumberOfPorts);
    static_cast<void>(Token);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_CreateProxyArpEntry(std::uint32_t dwAddress, std::uint32_t dwMask, std::uint32_t dwIfIndex) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(dwAddress);
    static_cast<void>(dwMask);
    static_cast<void>(dwIfIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_DeleteIPAddress(std::uint32_t NTEContext) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(NTEContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_DeleteIpNetEntry(std::uint64_t pArpEntry) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(pArpEntry);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_DeletePersistentTcpPortReservation(std::uint16_t StartPort, std::uint16_t NumberOfPorts) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(StartPort);
    static_cast<void>(NumberOfPorts);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_DeletePersistentUdpPortReservation(std::uint16_t StartPort, std::uint16_t NumberOfPorts) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(StartPort);
    static_cast<void>(NumberOfPorts);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_DeleteProxyArpEntry(std::uint32_t dwAddress, std::uint32_t dwMask, std::uint32_t dwIfIndex) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(dwAddress);
    static_cast<void>(dwMask);
    static_cast<void>(dwIfIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_DisableMediaSense(void* pHandle, void* pOverLapped) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(pHandle);
    static_cast<void>(pOverLapped);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_EnableRouter(void* pHandle, void* pOverlapped) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(pHandle);
    static_cast<void>(pOverlapped);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_FlushIpNetTable(std::uint32_t dwIfIndex) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(dwIfIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_GetAdapterIndex(char16_t* AdapterName, std::uint32_t* IfIndex) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(AdapterName);
    static_cast<void>(IfIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kiphlpapiG_GetAdapterOrderMap() noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_GetCurrentThreadCompartmentId() noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_GetIcmpStatisticsEx(std::uint64_t Statistics, std::uint32_t Family) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(Statistics);
    static_cast<void>(Family);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_GetIpErrorString(std::uint64_t ErrorCode, char16_t* Buffer, std::uint32_t* Size) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(ErrorCode);
    static_cast<void>(Buffer);
    static_cast<void>(Size);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_GetNetworkInformation(const void* NetworkGuid, std::uint32_t* CompartmentId, std::uint32_t* SiteId, char16_t* NetworkName, std::uint32_t Length) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(NetworkGuid);
    static_cast<void>(CompartmentId);
    static_cast<void>(SiteId);
    static_cast<void>(NetworkName);
    static_cast<void>(Length);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_GetOwnerModuleFromPidAndInfo(std::uint32_t ulPid, std::uint64_t* pInfo, std::uint64_t Class, void* pBuffer, std::uint32_t* pdwSize) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(ulPid);
    static_cast<void>(pInfo);
    static_cast<void>(Class);
    static_cast<void>(pBuffer);
    static_cast<void>(pdwSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_GetPerAdapterInfo(std::uint32_t IfIndex, std::uint64_t pPerAdapterInfo, std::uint32_t* pOutBufLen) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(IfIndex);
    static_cast<void>(pPerAdapterInfo);
    static_cast<void>(pOutBufLen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kiphlpapiG_GetRTTAndHopCount(void* DestIpAddress, std::uint32_t* HopCount, std::uint32_t MaxHops, std::uint32_t* RTT) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(DestIpAddress);
    static_cast<void>(HopCount);
    static_cast<void>(MaxHops);
    static_cast<void>(RTT);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_GetSessionCompartmentId(std::uint32_t SessionId) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(SessionId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_GetTcpTable2(std::uint64_t TcpTable, std::uint32_t* SizePointer, std::int32_t Order) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(TcpTable);
    static_cast<void>(SizePointer);
    static_cast<void>(Order);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_GetUniDirectionalAdapterInfo(std::uint64_t pIPIfInfo, std::uint32_t* dwOutBufLen) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(pIPIfInfo);
    static_cast<void>(dwOutBufLen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_IpReleaseAddress(std::uint64_t AdapterInfo) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(AdapterInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_IpRenewAddress(std::uint64_t AdapterInfo) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(AdapterInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_LookupPersistentTcpPortReservation(std::uint16_t StartPort, std::uint16_t NumberOfPorts, std::uint64_t* Token) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(StartPort);
    static_cast<void>(NumberOfPorts);
    static_cast<void>(Token);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_LookupPersistentUdpPortReservation(std::uint16_t StartPort, std::uint16_t NumberOfPorts, std::uint64_t* Token) noexcept {
    // Refused: the loader and runtime library internals.
    //
    // this call is part of the native runtime library, whose state this
    // runtime keeps in its own structures rather than in the kernel's
    static_cast<void>(StartPort);
    static_cast<void>(NumberOfPorts);
    static_cast<void>(Token);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_NhpAllocateAndGetInterfaceInfoFromStack(void** ppTable, std::uint32_t* pdwCount, std::int32_t bOrder, void* hHeap, std::uint32_t dwFlags) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(ppTable);
    static_cast<void>(pdwCount);
    static_cast<void>(bOrder);
    static_cast<void>(hHeap);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_RestoreMediaSense(void* pOverlapped, std::uint32_t* lpdwEnableCount) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(pOverlapped);
    static_cast<void>(lpdwEnableCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_SendARP(void* DestIP, void* SrcIP, void* pMacAddr, std::uint32_t* PhyAddrLen) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(DestIP);
    static_cast<void>(SrcIP);
    static_cast<void>(pMacAddr);
    static_cast<void>(PhyAddrLen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_SetCurrentThreadCompartmentId(std::uint32_t CompartmentId) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(CompartmentId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_SetIfEntry(std::uint64_t pIfRow) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(pIfRow);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_SetIpNetEntry(std::uint64_t pArpEntry) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(pArpEntry);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_SetIpStatistics(std::uint64_t pIpStats) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(pIpStats);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_SetIpStatisticsEx(std::uint64_t Statistics, std::uint32_t Family) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(Statistics);
    static_cast<void>(Family);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_SetIpTTL(std::uint32_t nTTL) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(nTTL);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_SetNetworkInformation(const void* NetworkGuid, std::uint32_t CompartmentId, const char16_t* NetworkName) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(NetworkGuid);
    static_cast<void>(CompartmentId);
    static_cast<void>(NetworkName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_SetSessionCompartmentId(std::uint32_t SessionId, std::uint32_t CompartmentId) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(SessionId);
    static_cast<void>(CompartmentId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_SetTcpEntry(std::uint64_t pTcpRow) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(pTcpRow);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kiphlpapiG_UnenableRouter(void* pOverlapped, std::uint32_t* lpdwEnableCount) noexcept {
    // Refused: the interface and routing tables.
    //
    // the call describes the machine's own network configuration, which
    // belongs to the host's network stack and not to this process
    static_cast<void>(pOverlapped);
    static_cast<void>(lpdwEnableCount);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_iphlpapi(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("AddIPAddress", reinterpret_cast<void*>(&kiphlpapiG_AddIPAddress));
    e("CancelIPChangeNotify", reinterpret_cast<void*>(&kiphlpapiG_CancelIPChangeNotify));
    e("ConvertInterfaceAliasToLuid", reinterpret_cast<void*>(&kiphlpapiG_ConvertInterfaceAliasToLuid));
    e("ConvertInterfaceGuidToLuid", reinterpret_cast<void*>(&kiphlpapiG_ConvertInterfaceGuidToLuid));
    e("ConvertInterfaceIndexToLuid", reinterpret_cast<void*>(&kiphlpapiG_ConvertInterfaceIndexToLuid));
    e("ConvertInterfaceLuidToAlias", reinterpret_cast<void*>(&kiphlpapiG_ConvertInterfaceLuidToAlias));
    e("ConvertInterfaceLuidToGuid", reinterpret_cast<void*>(&kiphlpapiG_ConvertInterfaceLuidToGuid));
    e("ConvertInterfaceLuidToIndex", reinterpret_cast<void*>(&kiphlpapiG_ConvertInterfaceLuidToIndex));
    e("ConvertInterfaceLuidToNameA", reinterpret_cast<void*>(&kiphlpapiG_ConvertInterfaceLuidToNameA));
    e("ConvertInterfaceLuidToNameW", reinterpret_cast<void*>(&kiphlpapiG_ConvertInterfaceLuidToNameW));
    e("ConvertInterfaceNameToLuidA", reinterpret_cast<void*>(&kiphlpapiG_ConvertInterfaceNameToLuidA));
    e("ConvertInterfaceNameToLuidW", reinterpret_cast<void*>(&kiphlpapiG_ConvertInterfaceNameToLuidW));
    e("ConvertIpv4MaskToLength", reinterpret_cast<void*>(&kiphlpapiG_ConvertIpv4MaskToLength));
    e("ConvertLengthToIpv4Mask", reinterpret_cast<void*>(&kiphlpapiG_ConvertLengthToIpv4Mask));
    e("CreateIpNetEntry", reinterpret_cast<void*>(&kiphlpapiG_CreateIpNetEntry));
    e("CreatePersistentTcpPortReservation", reinterpret_cast<void*>(&kiphlpapiG_CreatePersistentTcpPortReservation));
    e("CreatePersistentUdpPortReservation", reinterpret_cast<void*>(&kiphlpapiG_CreatePersistentUdpPortReservation));
    e("CreateProxyArpEntry", reinterpret_cast<void*>(&kiphlpapiG_CreateProxyArpEntry));
    e("DeleteIPAddress", reinterpret_cast<void*>(&kiphlpapiG_DeleteIPAddress));
    e("DeleteIpNetEntry", reinterpret_cast<void*>(&kiphlpapiG_DeleteIpNetEntry));
    e("DeletePersistentTcpPortReservation", reinterpret_cast<void*>(&kiphlpapiG_DeletePersistentTcpPortReservation));
    e("DeletePersistentUdpPortReservation", reinterpret_cast<void*>(&kiphlpapiG_DeletePersistentUdpPortReservation));
    e("DeleteProxyArpEntry", reinterpret_cast<void*>(&kiphlpapiG_DeleteProxyArpEntry));
    e("DisableMediaSense", reinterpret_cast<void*>(&kiphlpapiG_DisableMediaSense));
    e("EnableRouter", reinterpret_cast<void*>(&kiphlpapiG_EnableRouter));
    e("FlushIpNetTable", reinterpret_cast<void*>(&kiphlpapiG_FlushIpNetTable));
    e("GetAdapterIndex", reinterpret_cast<void*>(&kiphlpapiG_GetAdapterIndex));
    e("GetAdapterOrderMap", reinterpret_cast<void*>(&kiphlpapiG_GetAdapterOrderMap));
    e("GetCurrentThreadCompartmentId", reinterpret_cast<void*>(&kiphlpapiG_GetCurrentThreadCompartmentId));
    e("GetIcmpStatisticsEx", reinterpret_cast<void*>(&kiphlpapiG_GetIcmpStatisticsEx));
    e("GetIpErrorString", reinterpret_cast<void*>(&kiphlpapiG_GetIpErrorString));
    e("GetNetworkInformation", reinterpret_cast<void*>(&kiphlpapiG_GetNetworkInformation));
    e("GetOwnerModuleFromPidAndInfo", reinterpret_cast<void*>(&kiphlpapiG_GetOwnerModuleFromPidAndInfo));
    e("GetPerAdapterInfo", reinterpret_cast<void*>(&kiphlpapiG_GetPerAdapterInfo));
    e("GetRTTAndHopCount", reinterpret_cast<void*>(&kiphlpapiG_GetRTTAndHopCount));
    e("GetSessionCompartmentId", reinterpret_cast<void*>(&kiphlpapiG_GetSessionCompartmentId));
    e("GetTcpTable2", reinterpret_cast<void*>(&kiphlpapiG_GetTcpTable2));
    e("GetUniDirectionalAdapterInfo", reinterpret_cast<void*>(&kiphlpapiG_GetUniDirectionalAdapterInfo));
    e("IpReleaseAddress", reinterpret_cast<void*>(&kiphlpapiG_IpReleaseAddress));
    e("IpRenewAddress", reinterpret_cast<void*>(&kiphlpapiG_IpRenewAddress));
    e("LookupPersistentTcpPortReservation", reinterpret_cast<void*>(&kiphlpapiG_LookupPersistentTcpPortReservation));
    e("LookupPersistentUdpPortReservation", reinterpret_cast<void*>(&kiphlpapiG_LookupPersistentUdpPortReservation));
    e("NhpAllocateAndGetInterfaceInfoFromStack", reinterpret_cast<void*>(&kiphlpapiG_NhpAllocateAndGetInterfaceInfoFromStack));
    e("RestoreMediaSense", reinterpret_cast<void*>(&kiphlpapiG_RestoreMediaSense));
    e("SendARP", reinterpret_cast<void*>(&kiphlpapiG_SendARP));
    e("SetCurrentThreadCompartmentId", reinterpret_cast<void*>(&kiphlpapiG_SetCurrentThreadCompartmentId));
    e("SetIfEntry", reinterpret_cast<void*>(&kiphlpapiG_SetIfEntry));
    e("SetIpNetEntry", reinterpret_cast<void*>(&kiphlpapiG_SetIpNetEntry));
    e("SetIpStatistics", reinterpret_cast<void*>(&kiphlpapiG_SetIpStatistics));
    e("SetIpStatisticsEx", reinterpret_cast<void*>(&kiphlpapiG_SetIpStatisticsEx));
    e("SetIpTTL", reinterpret_cast<void*>(&kiphlpapiG_SetIpTTL));
    e("SetNetworkInformation", reinterpret_cast<void*>(&kiphlpapiG_SetNetworkInformation));
    e("SetSessionCompartmentId", reinterpret_cast<void*>(&kiphlpapiG_SetSessionCompartmentId));
    e("SetTcpEntry", reinterpret_cast<void*>(&kiphlpapiG_SetTcpEntry));
    e("UnenableRouter", reinterpret_cast<void*>(&kiphlpapiG_UnenableRouter));
}
}  // namespace occ::runtime::winabi

// The MSWSOCK surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t kmswsockG_AcceptEx(std::uint64_t sListenSocket, std::uint64_t sAcceptSocket, void* lpOutputBuffer, std::uint32_t dwReceiveDataLength, std::uint32_t dwLocalAddressLength, std::uint32_t dwRemoteAddressLength, std::uint32_t* lpdwBytesReceived, void* lpOverlapped) noexcept {
    // Refused: the Winsock service provider extensions.
    //
    // these entry points are the layered-provider interface: they hand a
    // provider a request structure and the provider answers. The base socket
    // surface is answered instead
    static_cast<void>(sListenSocket);
    static_cast<void>(sAcceptSocket);
    static_cast<void>(lpOutputBuffer);
    static_cast<void>(dwReceiveDataLength);
    static_cast<void>(dwLocalAddressLength);
    static_cast<void>(dwRemoteAddressLength);
    static_cast<void>(lpdwBytesReceived);
    static_cast<void>(lpOverlapped);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kmswsockG_GetAcceptExSockaddrs(void* lpOutputBuffer, std::uint32_t dwReceiveDataLength, std::uint32_t dwLocalAddressLength, std::uint32_t dwRemoteAddressLength, void** LocalSockaddr, std::int32_t* LocalSockaddrLength, void** RemoteSockaddr, std::int32_t* RemoteSockaddrLength) noexcept {
    // Refused: the Winsock service provider extensions.
    //
    // these entry points are the layered-provider interface: they hand a
    // provider a request structure and the provider answers. The base socket
    // surface is answered instead
    static_cast<void>(lpOutputBuffer);
    static_cast<void>(dwReceiveDataLength);
    static_cast<void>(dwLocalAddressLength);
    static_cast<void>(dwRemoteAddressLength);
    static_cast<void>(LocalSockaddr);
    static_cast<void>(LocalSockaddrLength);
    static_cast<void>(RemoteSockaddr);
    static_cast<void>(RemoteSockaddrLength);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kmswsockG_TransmitFile(std::uint64_t hSocket, void* hFile, std::uint32_t nNumberOfBytesToWrite, std::uint32_t nNumberOfBytesPerSend, void* lpOverlapped, void* lpTransmitBuffers, std::uint32_t dwReserved) noexcept {
    // Refused: the Winsock service provider extensions.
    //
    // these entry points are the layered-provider interface: they hand a
    // provider a request structure and the provider answers. The base socket
    // surface is answered instead
    static_cast<void>(hSocket);
    static_cast<void>(hFile);
    static_cast<void>(nNumberOfBytesToWrite);
    static_cast<void>(nNumberOfBytesPerSend);
    static_cast<void>(lpOverlapped);
    static_cast<void>(lpTransmitBuffers);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kmswsockG_WSARecvEx(std::uint64_t s, char* buf, std::int32_t len, std::int32_t* flags) noexcept {
    // Refused: the Winsock service provider extensions.
    //
    // these entry points are the layered-provider interface: they hand a
    // provider a request structure and the provider answers. The base socket
    // surface is answered instead
    static_cast<void>(s);
    static_cast<void>(buf);
    static_cast<void>(len);
    static_cast<void>(flags);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_mswsock(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("AcceptEx", reinterpret_cast<void*>(&kmswsockG_AcceptEx));
    e("GetAcceptExSockaddrs", reinterpret_cast<void*>(&kmswsockG_GetAcceptExSockaddrs));
    e("TransmitFile", reinterpret_cast<void*>(&kmswsockG_TransmitFile));
    e("WSARecvEx", reinterpret_cast<void*>(&kmswsockG_WSARecvEx));
}
}  // namespace occ::runtime::winabi

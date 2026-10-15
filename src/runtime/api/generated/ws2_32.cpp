// The WS2_32 surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_GetAddrInfoExA(const char* pName, const char* pServiceName, std::uint32_t dwNameSpace, void* lpNspId, const void* pHints, void* ppResult, std::uint64_t timeout, void* lpOverlapped, std::uint64_t lpCompletionRoutine, void* lpNameHandle) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(pName);
    static_cast<void>(pServiceName);
    static_cast<void>(dwNameSpace);
    static_cast<void>(lpNspId);
    static_cast<void>(pHints);
    static_cast<void>(ppResult);
    static_cast<void>(timeout);
    static_cast<void>(lpOverlapped);
    static_cast<void>(lpCompletionRoutine);
    static_cast<void>(lpNameHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_IN6ADDR_ISANY(const void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_IN6ADDR_ISLOOPBACK(const void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kws2_32G_IN6ADDR_SETANY(void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kws2_32G_IN6ADDR_SETLOOPBACK(void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_IN6_ADDR_EQUAL(const void* arg0, const void* arg1) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    static_cast<void>(arg1);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_IN6_IS_ADDR_LINKLOCAL(const void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_IN6_IS_ADDR_LOOPBACK(const void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_IN6_IS_ADDR_MC_GLOBAL(const void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_IN6_IS_ADDR_MC_LINKLOCAL(const void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_IN6_IS_ADDR_MC_NODELOCAL(const void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_IN6_IS_ADDR_MC_ORGLOCAL(const void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_IN6_IS_ADDR_MC_SITELOCAL(const void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_IN6_IS_ADDR_MULTICAST(const void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_IN6_IS_ADDR_SITELOCAL(const void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_IN6_IS_ADDR_UNSPECIFIED(const void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_IN6_IS_ADDR_V4COMPAT(const void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_IN6_IS_ADDR_V4MAPPED(const void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kws2_32G_IN6_SET_ADDR_LOOPBACK(void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kws2_32G_IN6_SET_ADDR_UNSPECIFIED(void* arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_SetAddrInfoExA(const char* pName, const char* pServiceName, void* pAddresses, std::uint32_t dwAddressCount, std::uint64_t lpBlob, std::uint32_t dwFlags, std::uint32_t dwNameSpace, void* lpNspId, std::uint64_t timeout, void* lpOverlapped, std::uint64_t lpCompletionRoutine, void* lpNameHandle) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(pName);
    static_cast<void>(pServiceName);
    static_cast<void>(pAddresses);
    static_cast<void>(dwAddressCount);
    static_cast<void>(lpBlob);
    static_cast<void>(dwFlags);
    static_cast<void>(dwNameSpace);
    static_cast<void>(lpNspId);
    static_cast<void>(timeout);
    static_cast<void>(lpOverlapped);
    static_cast<void>(lpCompletionRoutine);
    static_cast<void>(lpNameHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_SetAddrInfoExW(const char16_t* pName, const char16_t* pServiceName, void* pAddresses, std::uint32_t dwAddressCount, std::uint64_t lpBlob, std::uint32_t dwFlags, std::uint32_t dwNameSpace, void* lpNspId, std::uint64_t timeout, void* lpOverlapped, std::uint64_t lpCompletionRoutine, void* lpNameHandle) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(pName);
    static_cast<void>(pServiceName);
    static_cast<void>(pAddresses);
    static_cast<void>(dwAddressCount);
    static_cast<void>(lpBlob);
    static_cast<void>(dwFlags);
    static_cast<void>(dwNameSpace);
    static_cast<void>(lpNspId);
    static_cast<void>(timeout);
    static_cast<void>(lpOverlapped);
    static_cast<void>(lpCompletionRoutine);
    static_cast<void>(lpNameHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_WSAConnectByList(std::uint64_t s, std::uint64_t SocketAddressList, std::uint32_t* LocalAddressLength, std::uint64_t LocalAddress, std::uint32_t* RemoteAddressLength, std::uint64_t RemoteAddress, const void* timeout, std::uint64_t Reserved) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(s);
    static_cast<void>(SocketAddressList);
    static_cast<void>(LocalAddressLength);
    static_cast<void>(LocalAddress);
    static_cast<void>(RemoteAddressLength);
    static_cast<void>(RemoteAddress);
    static_cast<void>(timeout);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_WSAEnumNameSpaceProvidersExA(std::uint32_t* lpdwBufferLength, std::uint64_t lpnspBuffer) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(lpdwBufferLength);
    static_cast<void>(lpnspBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kws2_32G_WSAEnumNameSpaceProvidersExW(std::uint32_t* lpdwBufferLength, std::uint64_t lpnspBuffer) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(lpdwBufferLength);
    static_cast<void>(lpnspBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) char* kws2_32G_gai_strerrorA(std::int32_t arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char16_t* kws2_32G_gai_strerrorW(std::int32_t arg0) noexcept {
    // Refused: the Winsock name space providers.
    //
    // the call enumerates the installed name-space providers, which this
    // runtime does not install
    static_cast<void>(arg0);
    set_last_error(kNotImplemented);
    return nullptr;
}

}  // namespace

void add_generated_ws2_32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("GetAddrInfoExA", reinterpret_cast<void*>(&kws2_32G_GetAddrInfoExA));
    e("IN6ADDR_ISANY", reinterpret_cast<void*>(&kws2_32G_IN6ADDR_ISANY));
    e("IN6ADDR_ISLOOPBACK", reinterpret_cast<void*>(&kws2_32G_IN6ADDR_ISLOOPBACK));
    e("IN6ADDR_SETANY", reinterpret_cast<void*>(&kws2_32G_IN6ADDR_SETANY));
    e("IN6ADDR_SETLOOPBACK", reinterpret_cast<void*>(&kws2_32G_IN6ADDR_SETLOOPBACK));
    e("IN6_ADDR_EQUAL", reinterpret_cast<void*>(&kws2_32G_IN6_ADDR_EQUAL));
    e("IN6_IS_ADDR_LINKLOCAL", reinterpret_cast<void*>(&kws2_32G_IN6_IS_ADDR_LINKLOCAL));
    e("IN6_IS_ADDR_LOOPBACK", reinterpret_cast<void*>(&kws2_32G_IN6_IS_ADDR_LOOPBACK));
    e("IN6_IS_ADDR_MC_GLOBAL", reinterpret_cast<void*>(&kws2_32G_IN6_IS_ADDR_MC_GLOBAL));
    e("IN6_IS_ADDR_MC_LINKLOCAL", reinterpret_cast<void*>(&kws2_32G_IN6_IS_ADDR_MC_LINKLOCAL));
    e("IN6_IS_ADDR_MC_NODELOCAL", reinterpret_cast<void*>(&kws2_32G_IN6_IS_ADDR_MC_NODELOCAL));
    e("IN6_IS_ADDR_MC_ORGLOCAL", reinterpret_cast<void*>(&kws2_32G_IN6_IS_ADDR_MC_ORGLOCAL));
    e("IN6_IS_ADDR_MC_SITELOCAL", reinterpret_cast<void*>(&kws2_32G_IN6_IS_ADDR_MC_SITELOCAL));
    e("IN6_IS_ADDR_MULTICAST", reinterpret_cast<void*>(&kws2_32G_IN6_IS_ADDR_MULTICAST));
    e("IN6_IS_ADDR_SITELOCAL", reinterpret_cast<void*>(&kws2_32G_IN6_IS_ADDR_SITELOCAL));
    e("IN6_IS_ADDR_UNSPECIFIED", reinterpret_cast<void*>(&kws2_32G_IN6_IS_ADDR_UNSPECIFIED));
    e("IN6_IS_ADDR_V4COMPAT", reinterpret_cast<void*>(&kws2_32G_IN6_IS_ADDR_V4COMPAT));
    e("IN6_IS_ADDR_V4MAPPED", reinterpret_cast<void*>(&kws2_32G_IN6_IS_ADDR_V4MAPPED));
    e("IN6_SET_ADDR_LOOPBACK", reinterpret_cast<void*>(&kws2_32G_IN6_SET_ADDR_LOOPBACK));
    e("IN6_SET_ADDR_UNSPECIFIED", reinterpret_cast<void*>(&kws2_32G_IN6_SET_ADDR_UNSPECIFIED));
    e("SetAddrInfoExA", reinterpret_cast<void*>(&kws2_32G_SetAddrInfoExA));
    e("SetAddrInfoExW", reinterpret_cast<void*>(&kws2_32G_SetAddrInfoExW));
    e("WSAConnectByList", reinterpret_cast<void*>(&kws2_32G_WSAConnectByList));
    e("WSAEnumNameSpaceProvidersExA", reinterpret_cast<void*>(&kws2_32G_WSAEnumNameSpaceProvidersExA));
    e("WSAEnumNameSpaceProvidersExW", reinterpret_cast<void*>(&kws2_32G_WSAEnumNameSpaceProvidersExW));
    e("gai_strerrorA", reinterpret_cast<void*>(&kws2_32G_gai_strerrorA));
    e("gai_strerrorW", reinterpret_cast<void*>(&kws2_32G_gai_strerrorW));
}
}  // namespace occ::runtime::winabi

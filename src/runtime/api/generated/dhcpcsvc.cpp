// The DHCPCSVC surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::uint32_t kdhcpcsvcG_DhcpCApiCleanup() noexcept {
    // Refused: the DHCP client.
    //
    // the call reaches the DHCP client service through its RPC interface
    //
    // The signature is not in the headers, so this thunk declares no
    // parameters at all. That is safe on this ABI: the caller allocates
    // and releases the shadow space, and a callee that names no
    // parameter reads neither it nor the registers the arguments
    // arrived in. The answer is a zero, which is the answer a refused
    // call already gives.
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdhcpcsvcG_DhcpCApiInitialize() noexcept {
    // Refused: the DHCP client.
    //
    // the call reaches the DHCP client service through its RPC interface
    //
    // The signature is not in the headers, so this thunk declares no
    // parameters at all. That is safe on this ABI: the caller allocates
    // and releases the shadow space, and a callee that names no
    // parameter reads neither it nor the registers the arguments
    // arrived in. The answer is a zero, which is the answer a refused
    // call already gives.
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdhcpcsvcG_DhcpDeRegisterParamChange() noexcept {
    // Refused: the DHCP client.
    //
    // the call reaches the DHCP client service through its RPC interface
    //
    // The signature is not in the headers, so this thunk declares no
    // parameters at all. That is safe on this ABI: the caller allocates
    // and releases the shadow space, and a callee that names no
    // parameter reads neither it nor the registers the arguments
    // arrived in. The answer is a zero, which is the answer a refused
    // call already gives.
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdhcpcsvcG_DhcpRegisterParamChange() noexcept {
    // Refused: the DHCP client.
    //
    // the call reaches the DHCP client service through its RPC interface
    //
    // The signature is not in the headers, so this thunk declares no
    // parameters at all. That is safe on this ABI: the caller allocates
    // and releases the shadow space, and a callee that names no
    // parameter reads neither it nor the registers the arguments
    // arrived in. The answer is a zero, which is the answer a refused
    // call already gives.
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdhcpcsvcG_DhcpRemoveDNSRegistrations() noexcept {
    // Refused: the DHCP client.
    //
    // the call reaches the DHCP client service through its RPC interface
    //
    // The signature is not in the headers, so this thunk declares no
    // parameters at all. That is safe on this ABI: the caller allocates
    // and releases the shadow space, and a callee that names no
    // parameter reads neither it nor the registers the arguments
    // arrived in. The answer is a zero, which is the answer a refused
    // call already gives.
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdhcpcsvcG_DhcpRequestParams() noexcept {
    // Refused: the DHCP client.
    //
    // the call reaches the DHCP client service through its RPC interface
    //
    // The signature is not in the headers, so this thunk declares no
    // parameters at all. That is safe on this ABI: the caller allocates
    // and releases the shadow space, and a callee that names no
    // parameter reads neither it nor the registers the arguments
    // arrived in. The answer is a zero, which is the answer a refused
    // call already gives.
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kdhcpcsvcG_DhcpUndoRequestParams() noexcept {
    // Refused: the DHCP client.
    //
    // the call reaches the DHCP client service through its RPC interface
    //
    // The signature is not in the headers, so this thunk declares no
    // parameters at all. That is safe on this ABI: the caller allocates
    // and releases the shadow space, and a callee that names no
    // parameter reads neither it nor the registers the arguments
    // arrived in. The answer is a zero, which is the answer a refused
    // call already gives.
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_dhcpcsvc(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("DhcpCApiCleanup", reinterpret_cast<void*>(&kdhcpcsvcG_DhcpCApiCleanup));
    e("DhcpCApiInitialize", reinterpret_cast<void*>(&kdhcpcsvcG_DhcpCApiInitialize));
    e("DhcpDeRegisterParamChange", reinterpret_cast<void*>(&kdhcpcsvcG_DhcpDeRegisterParamChange));
    e("DhcpRegisterParamChange", reinterpret_cast<void*>(&kdhcpcsvcG_DhcpRegisterParamChange));
    e("DhcpRemoveDNSRegistrations", reinterpret_cast<void*>(&kdhcpcsvcG_DhcpRemoveDNSRegistrations));
    e("DhcpRequestParams", reinterpret_cast<void*>(&kdhcpcsvcG_DhcpRequestParams));
    e("DhcpUndoRequestParams", reinterpret_cast<void*>(&kdhcpcsvcG_DhcpUndoRequestParams));
}
}  // namespace occ::runtime::winabi

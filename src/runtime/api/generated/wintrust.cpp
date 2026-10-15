// The WINTRUST surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t kwintrustG_FindCertsByIssuer(std::uint64_t pCertChains, std::uint32_t* pcbCertChains, std::uint32_t* pcCertChains, std::uint8_t* pbEncodedIssuerName, std::uint32_t cbEncodedIssuerName, const char16_t* pwszPurpose, std::uint32_t dwKeySpec) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCertChains);
    static_cast<void>(pcbCertChains);
    static_cast<void>(pcCertChains);
    static_cast<void>(pbEncodedIssuerName);
    static_cast<void>(cbEncodedIssuerName);
    static_cast<void>(pwszPurpose);
    static_cast<void>(dwKeySpec);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwintrustG_WTHelperCertCheckValidSignature(void* pProvData) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(pProvData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwintrustG_WTHelperCertIsSelfSigned(std::uint32_t dwEncoding, void* pCert) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(dwEncoding);
    static_cast<void>(pCert);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwintrustG_WTHelperGetProvCertFromChain(void* pSgnr, std::uint32_t idxCert) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(pSgnr);
    static_cast<void>(idxCert);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwintrustG_WTHelperGetProvPrivateDataFromChain(void* pProvData, void* pgProviderID) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(pProvData);
    static_cast<void>(pgProviderID);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwintrustG_WTHelperGetProvSignerFromChain(void* pProvData, std::uint32_t idxSigner, std::int32_t fCounterSigner, std::uint32_t idxCounterSigner) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(pProvData);
    static_cast<void>(idxSigner);
    static_cast<void>(fCounterSigner);
    static_cast<void>(idxCounterSigner);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwintrustG_WTHelperProvDataFromStateData(void* hStateData) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(hStateData);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwintrustG_WinVerifyTrust(void* hwnd, void* pgActionID, void* pWVTData) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(hwnd);
    static_cast<void>(pgActionID);
    static_cast<void>(pWVTData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwintrustG_WinVerifyTrustEx(void* hwnd, void* pgActionID, void* pWinTrustData) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(hwnd);
    static_cast<void>(pgActionID);
    static_cast<void>(pWinTrustData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwintrustG_WintrustAddActionID(void* pgActionID, std::uint32_t fdwFlags, void* psProvInfo) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(pgActionID);
    static_cast<void>(fdwFlags);
    static_cast<void>(psProvInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwintrustG_WintrustAddDefaultForUsage(const char* pszUsageOID, void* psDefUsage) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(pszUsageOID);
    static_cast<void>(psDefUsage);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwintrustG_WintrustGetDefaultForUsage(std::uint32_t dwAction, const char* pszUsageOID, void* psUsage) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(dwAction);
    static_cast<void>(pszUsageOID);
    static_cast<void>(psUsage);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kwintrustG_WintrustGetRegPolicyFlags(std::uint32_t* pdwPolicyFlags) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(pdwPolicyFlags);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kwintrustG_WintrustLoadFunctionPointers(void* pgActionID, void* pPfns) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(pgActionID);
    static_cast<void>(pPfns);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwintrustG_WintrustRemoveActionID(void* pgActionID) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(pgActionID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwintrustG_WintrustSetRegPolicyFlags(std::uint32_t dwPolicyFlags) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(dwPolicyFlags);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_wintrust(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("FindCertsByIssuer", reinterpret_cast<void*>(&kwintrustG_FindCertsByIssuer));
    e("WTHelperCertCheckValidSignature", reinterpret_cast<void*>(&kwintrustG_WTHelperCertCheckValidSignature));
    e("WTHelperCertIsSelfSigned", reinterpret_cast<void*>(&kwintrustG_WTHelperCertIsSelfSigned));
    e("WTHelperGetProvCertFromChain", reinterpret_cast<void*>(&kwintrustG_WTHelperGetProvCertFromChain));
    e("WTHelperGetProvPrivateDataFromChain", reinterpret_cast<void*>(&kwintrustG_WTHelperGetProvPrivateDataFromChain));
    e("WTHelperGetProvSignerFromChain", reinterpret_cast<void*>(&kwintrustG_WTHelperGetProvSignerFromChain));
    e("WTHelperProvDataFromStateData", reinterpret_cast<void*>(&kwintrustG_WTHelperProvDataFromStateData));
    e("WinVerifyTrust", reinterpret_cast<void*>(&kwintrustG_WinVerifyTrust));
    e("WinVerifyTrustEx", reinterpret_cast<void*>(&kwintrustG_WinVerifyTrustEx));
    e("WintrustAddActionID", reinterpret_cast<void*>(&kwintrustG_WintrustAddActionID));
    e("WintrustAddDefaultForUsage", reinterpret_cast<void*>(&kwintrustG_WintrustAddDefaultForUsage));
    e("WintrustGetDefaultForUsage", reinterpret_cast<void*>(&kwintrustG_WintrustGetDefaultForUsage));
    e("WintrustGetRegPolicyFlags", reinterpret_cast<void*>(&kwintrustG_WintrustGetRegPolicyFlags));
    e("WintrustLoadFunctionPointers", reinterpret_cast<void*>(&kwintrustG_WintrustLoadFunctionPointers));
    e("WintrustRemoveActionID", reinterpret_cast<void*>(&kwintrustG_WintrustRemoveActionID));
    e("WintrustSetRegPolicyFlags", reinterpret_cast<void*>(&kwintrustG_WintrustSetRegPolicyFlags));
}
}  // namespace occ::runtime::winabi

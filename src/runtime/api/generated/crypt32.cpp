// The CRYPT32 surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertAddCRLContextToStore(void* hCertStore, void* pCrlContext, std::uint32_t dwAddDisposition, void* ppStoreContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(pCrlContext);
    static_cast<void>(dwAddDisposition);
    static_cast<void>(ppStoreContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertAddCRLLinkToStore(void* hCertStore, void* pCrlContext, std::uint32_t dwAddDisposition, void* ppStoreContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(pCrlContext);
    static_cast<void>(dwAddDisposition);
    static_cast<void>(ppStoreContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertAddCTLContextToStore(void* hCertStore, void* pCtlContext, std::uint32_t dwAddDisposition, void* ppStoreContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(pCtlContext);
    static_cast<void>(dwAddDisposition);
    static_cast<void>(ppStoreContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertAddCTLLinkToStore(void* hCertStore, void* pCtlContext, std::uint32_t dwAddDisposition, void* ppStoreContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(pCtlContext);
    static_cast<void>(dwAddDisposition);
    static_cast<void>(ppStoreContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertAddCertificateLinkToStore(void* hCertStore, void* pCertContext, std::uint32_t dwAddDisposition, void* ppStoreContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(pCertContext);
    static_cast<void>(dwAddDisposition);
    static_cast<void>(ppStoreContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertAddEncodedCRLToStore(void* hCertStore, std::uint32_t dwCertEncodingType, const std::uint8_t* pbCrlEncoded, std::uint32_t cbCrlEncoded, std::uint32_t dwAddDisposition, void* ppCrlContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pbCrlEncoded);
    static_cast<void>(cbCrlEncoded);
    static_cast<void>(dwAddDisposition);
    static_cast<void>(ppCrlContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertAddEncodedCTLToStore(void* hCertStore, std::uint32_t dwMsgAndCertEncodingType, const std::uint8_t* pbCtlEncoded, std::uint32_t cbCtlEncoded, std::uint32_t dwAddDisposition, void* ppCtlContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(dwMsgAndCertEncodingType);
    static_cast<void>(pbCtlEncoded);
    static_cast<void>(cbCtlEncoded);
    static_cast<void>(dwAddDisposition);
    static_cast<void>(ppCtlContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertAddEncodedCertificateToSystemStoreA(const char* szCertStoreName, const std::uint8_t* pbCertEncoded, std::uint32_t cbCertEncoded) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(szCertStoreName);
    static_cast<void>(pbCertEncoded);
    static_cast<void>(cbCertEncoded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertAddEncodedCertificateToSystemStoreW(const char16_t* szCertStoreName, const std::uint8_t* pbCertEncoded, std::uint32_t cbCertEncoded) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(szCertStoreName);
    static_cast<void>(pbCertEncoded);
    static_cast<void>(cbCertEncoded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertAddEnhancedKeyUsageIdentifier(void* pCertContext, const char* pszUsageIdentifier) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCertContext);
    static_cast<void>(pszUsageIdentifier);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kcrypt32G_CertAddRefServerOcspResponse(std::uint64_t hServerOcspResponse) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hServerOcspResponse);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kcrypt32G_CertAddRefServerOcspResponseContext(std::uint64_t pServerOcspResponseContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pServerOcspResponseContext);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertAddSerializedElementToStore(void* hCertStore, const std::uint8_t* pbElement, std::uint32_t cbElement, std::uint32_t dwAddDisposition, std::uint32_t dwFlags, std::uint32_t dwContextTypeFlags, std::uint32_t* pdwContextType, const void** ppvContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(pbElement);
    static_cast<void>(cbElement);
    static_cast<void>(dwAddDisposition);
    static_cast<void>(dwFlags);
    static_cast<void>(dwContextTypeFlags);
    static_cast<void>(pdwContextType);
    static_cast<void>(ppvContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertAddStoreToCollection(void* hCollectionStore, void* hSiblingStore, std::uint32_t dwUpdateFlags, std::uint32_t dwPriority) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCollectionStore);
    static_cast<void>(hSiblingStore);
    static_cast<void>(dwUpdateFlags);
    static_cast<void>(dwPriority);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) const char* kcrypt32G_CertAlgIdToOID(std::uint32_t dwAlgId) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwAlgId);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kcrypt32G_CertCloseServerOcspResponse(std::uint64_t hServerOcspResponse, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hServerOcspResponse);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertCompareIntegerBlob(std::uint64_t pInt1, std::uint64_t pInt2) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pInt1);
    static_cast<void>(pInt2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertComparePublicKeyInfo(std::uint32_t dwCertEncodingType, const void* pPublicKey1, const void* pPublicKey2) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pPublicKey1);
    static_cast<void>(pPublicKey2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertControlStore(void* hCertStore, std::uint32_t dwFlags, std::uint32_t dwCtrlType, void* pvCtrlPara) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(dwFlags);
    static_cast<void>(dwCtrlType);
    static_cast<void>(pvCtrlPara);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CertCreateCRLContext(std::uint32_t dwCertEncodingType, const std::uint8_t* pbCrlEncoded, std::uint32_t cbCrlEncoded) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pbCrlEncoded);
    static_cast<void>(cbCrlEncoded);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CertCreateCTLContext(std::uint32_t dwMsgAndCertEncodingType, const std::uint8_t* pbCtlEncoded, std::uint32_t cbCtlEncoded) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwMsgAndCertEncodingType);
    static_cast<void>(pbCtlEncoded);
    static_cast<void>(cbCtlEncoded);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertCreateCTLEntryFromCertificateContextProperties(void* pCertContext, std::uint32_t cOptAttr, std::uint64_t rgOptAttr, std::uint32_t dwFlags, void* pvReserved, std::uint64_t pCtlEntry, std::uint32_t* pcbCtlEntry) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCertContext);
    static_cast<void>(cOptAttr);
    static_cast<void>(rgOptAttr);
    static_cast<void>(dwFlags);
    static_cast<void>(pvReserved);
    static_cast<void>(pCtlEntry);
    static_cast<void>(pcbCtlEntry);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertCreateCertificateChainEngine(std::uint64_t pConfig, void* phChainEngine) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pConfig);
    static_cast<void>(phChainEngine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CertCreateContext(std::uint32_t dwContextType, std::uint32_t dwEncodingType, const std::uint8_t* pbEncoded, std::uint32_t cbEncoded, std::uint32_t dwFlags, std::uint64_t pCreatePara) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwContextType);
    static_cast<void>(dwEncodingType);
    static_cast<void>(pbEncoded);
    static_cast<void>(cbEncoded);
    static_cast<void>(dwFlags);
    static_cast<void>(pCreatePara);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CertCreateSelfSignCertificate(std::uint64_t hCryptProvOrNCryptKey, std::uint64_t pSubjectIssuerBlob, std::uint32_t dwFlags, std::uint64_t pKeyProvInfo, void* pSignatureAlgorithm, void* pStartTime, void* pEndTime, std::uint64_t pExtensions) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCryptProvOrNCryptKey);
    static_cast<void>(pSubjectIssuerBlob);
    static_cast<void>(dwFlags);
    static_cast<void>(pKeyProvInfo);
    static_cast<void>(pSignatureAlgorithm);
    static_cast<void>(pStartTime);
    static_cast<void>(pEndTime);
    static_cast<void>(pExtensions);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertDeleteCRLFromStore(void* pCrlContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCrlContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertDeleteCTLFromStore(void* pCtlContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCtlContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CertDuplicateCRLContext(void* pCrlContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCrlContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CertDuplicateCTLContext(void* pCtlContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCtlContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CertDuplicateCertificateChain(void* pChainContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pChainContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CertDuplicateStore(void* hCertStore) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kcrypt32G_CertEnumCRLContextProperties(void* pCrlContext, std::uint32_t dwPropId) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCrlContext);
    static_cast<void>(dwPropId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CertEnumCRLsInStore(void* hCertStore, void* pPrevCrlContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(pPrevCrlContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kcrypt32G_CertEnumCTLContextProperties(void* pCtlContext, std::uint32_t dwPropId) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCtlContext);
    static_cast<void>(dwPropId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CertEnumCTLsInStore(void* hCertStore, void* pPrevCtlContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(pPrevCtlContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kcrypt32G_CertEnumCertificateContextProperties(void* pCertContext, std::uint32_t dwPropId) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCertContext);
    static_cast<void>(dwPropId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertEnumPhysicalStore(const void* pvSystemStore, std::uint32_t dwFlags, void* pvArg, std::uint64_t pfnEnum) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pvSystemStore);
    static_cast<void>(dwFlags);
    static_cast<void>(pvArg);
    static_cast<void>(pfnEnum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertEnumSubjectInSortedCTL(void* pCtlContext, void** ppvNextSubject, std::uint64_t pSubjectIdentifier, std::uint64_t pEncodedAttributes) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCtlContext);
    static_cast<void>(ppvNextSubject);
    static_cast<void>(pSubjectIdentifier);
    static_cast<void>(pEncodedAttributes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertEnumSystemStore(std::uint32_t dwFlags, void* pvSystemStoreLocationPara, void* pvArg, std::uint64_t pfnEnum) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwFlags);
    static_cast<void>(pvSystemStoreLocationPara);
    static_cast<void>(pvArg);
    static_cast<void>(pfnEnum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertEnumSystemStoreLocation(std::uint32_t dwFlags, void* pvArg, std::uint64_t pfnEnum) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwFlags);
    static_cast<void>(pvArg);
    static_cast<void>(pfnEnum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kcrypt32G_CertFindAttribute(const char* pszObjId, std::uint32_t cAttr, void* rgAttr) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pszObjId);
    static_cast<void>(cAttr);
    static_cast<void>(rgAttr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CertFindCRLInStore(void* hCertStore, std::uint32_t dwCertEncodingType, std::uint32_t dwFindFlags, std::uint32_t dwFindType, const void* pvFindPara, void* pPrevCrlContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(dwFindFlags);
    static_cast<void>(dwFindType);
    static_cast<void>(pvFindPara);
    static_cast<void>(pPrevCrlContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CertFindCTLInStore(void* hCertStore, std::uint32_t dwMsgAndCertEncodingType, std::uint32_t dwFindFlags, std::uint32_t dwFindType, const void* pvFindPara, void* pPrevCtlContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(dwMsgAndCertEncodingType);
    static_cast<void>(dwFindFlags);
    static_cast<void>(dwFindType);
    static_cast<void>(pvFindPara);
    static_cast<void>(pPrevCtlContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertFindCertificateInCRL(void* pCert, void* pCrlContext, std::uint32_t dwFlags, void* pvReserved, void* ppCrlEntry) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCert);
    static_cast<void>(pCrlContext);
    static_cast<void>(dwFlags);
    static_cast<void>(pvReserved);
    static_cast<void>(ppCrlEntry);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CertFindChainInStore(void* hCertStore, std::uint32_t dwCertEncodingType, std::uint32_t dwFindFlags, std::uint32_t dwFindType, const void* pvFindPara, void* pPrevChainContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(dwFindFlags);
    static_cast<void>(dwFindType);
    static_cast<void>(pvFindPara);
    static_cast<void>(pPrevChainContext);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kcrypt32G_CertFindExtension(const char* pszObjId, std::uint32_t cExtensions, void* rgExtensions) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pszObjId);
    static_cast<void>(cExtensions);
    static_cast<void>(rgExtensions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kcrypt32G_CertFindRDNAttr(const char* pszObjId, std::uint64_t pName) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pszObjId);
    static_cast<void>(pName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kcrypt32G_CertFindSubjectInCTL(std::uint32_t dwEncodingType, std::uint32_t dwSubjectType, void* pvSubject, void* pCtlContext, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwEncodingType);
    static_cast<void>(dwSubjectType);
    static_cast<void>(pvSubject);
    static_cast<void>(pCtlContext);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertFindSubjectInSortedCTL(void* pSubjectIdentifier, void* pCtlContext, std::uint32_t dwFlags, void* pvReserved, std::uint64_t pEncodedAttributes) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pSubjectIdentifier);
    static_cast<void>(pCtlContext);
    static_cast<void>(dwFlags);
    static_cast<void>(pvReserved);
    static_cast<void>(pEncodedAttributes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertFreeCRLContext(void* pCrlContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCrlContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertFreeCTLContext(void* pCtlContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCtlContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kcrypt32G_CertFreeCertificateChain(void* pChainContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pChainContext);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kcrypt32G_CertFreeCertificateChainEngine(void* hChainEngine) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hChainEngine);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kcrypt32G_CertFreeCertificateChainList(void* prgpSelection) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(prgpSelection);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kcrypt32G_CertFreeServerOcspResponseContext(std::uint64_t pServerOcspResponseContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pServerOcspResponseContext);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertGetCRLContextProperty(void* pCrlContext, std::uint32_t dwPropId, void* pvData, std::uint32_t* pcbData) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCrlContext);
    static_cast<void>(dwPropId);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CertGetCRLFromStore(void* hCertStore, void* pIssuerContext, void* pPrevCrlContext, std::uint32_t* pdwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(pIssuerContext);
    static_cast<void>(pPrevCrlContext);
    static_cast<void>(pdwFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertGetCTLContextProperty(void* pCtlContext, std::uint32_t dwPropId, void* pvData, std::uint32_t* pcbData) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCtlContext);
    static_cast<void>(dwPropId);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertGetCertificateChain(void* hChainEngine, void* pCertContext, std::uint64_t* pTime, void* hAdditionalStore, void* pChainPara, std::uint32_t dwFlags, void* pvReserved, void* ppChainContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hChainEngine);
    static_cast<void>(pCertContext);
    static_cast<void>(pTime);
    static_cast<void>(hAdditionalStore);
    static_cast<void>(pChainPara);
    static_cast<void>(dwFlags);
    static_cast<void>(pvReserved);
    static_cast<void>(ppChainContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertGetEnhancedKeyUsage(void* pCertContext, std::uint32_t dwFlags, std::uint64_t pUsage, std::uint32_t* pcbUsage) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCertContext);
    static_cast<void>(dwFlags);
    static_cast<void>(pUsage);
    static_cast<void>(pcbUsage);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CertGetIssuerCertificateFromStore(void* hCertStore, void* pSubjectContext, void* pPrevIssuerContext, std::uint32_t* pdwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(pSubjectContext);
    static_cast<void>(pPrevIssuerContext);
    static_cast<void>(pdwFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kcrypt32G_CertGetServerOcspResponseContext(std::uint64_t hServerOcspResponse, std::uint32_t dwFlags, void* pvReserved) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hServerOcspResponse);
    static_cast<void>(dwFlags);
    static_cast<void>(pvReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertGetStoreProperty(void* hCertStore, std::uint32_t dwPropId, void* pvData, std::uint32_t* pcbData) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(dwPropId);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CertGetSubjectCertificateFromStore(void* hCertStore, std::uint32_t dwCertEncodingType, std::uint64_t pCertId) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pCertId);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertGetValidUsages(std::uint32_t cCerts, void* rghCerts, std::int32_t* cNumOIDs, char** rghOIDs, std::uint32_t* pcbOIDs) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(cCerts);
    static_cast<void>(rghCerts);
    static_cast<void>(cNumOIDs);
    static_cast<void>(rghOIDs);
    static_cast<void>(pcbOIDs);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertIsRDNAttrsInCertificateName(std::uint32_t dwCertEncodingType, std::uint32_t dwFlags, std::uint64_t pCertName, std::uint64_t pRDN) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(dwFlags);
    static_cast<void>(pCertName);
    static_cast<void>(pRDN);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertIsStrongHashToSign(std::uint64_t pStrongSignPara, const char16_t* pwszCNGHashAlgid, void* pSigningCert) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pStrongSignPara);
    static_cast<void>(pwszCNGHashAlgid);
    static_cast<void>(pSigningCert);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertIsValidCRLForCertificate(void* pCert, void* pCrl, std::uint32_t dwFlags, void* pvReserved) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCert);
    static_cast<void>(pCrl);
    static_cast<void>(dwFlags);
    static_cast<void>(pvReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertIsWeakHash(std::uint32_t dwHashUseType, const char16_t* pwszCNGHashAlgid, std::uint32_t dwChainFlags, void* pSignerChainContext, std::uint64_t* pTimeStamp, const char16_t* pwszFileName) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwHashUseType);
    static_cast<void>(pwszCNGHashAlgid);
    static_cast<void>(dwChainFlags);
    static_cast<void>(pSignerChainContext);
    static_cast<void>(pTimeStamp);
    static_cast<void>(pwszFileName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kcrypt32G_CertOIDToAlgId(const char* pszObjId) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pszObjId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kcrypt32G_CertOpenServerOcspResponse(void* pChainContext, std::uint32_t dwFlags, void* pvReserved) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pChainContext);
    static_cast<void>(dwFlags);
    static_cast<void>(pvReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kcrypt32G_CertRDNValueToStrA(std::uint32_t dwValueType, std::uint64_t pValue, char* psz, std::uint32_t csz) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwValueType);
    static_cast<void>(pValue);
    static_cast<void>(psz);
    static_cast<void>(csz);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kcrypt32G_CertRDNValueToStrW(std::uint32_t dwValueType, std::uint64_t pValue, char16_t* psz, std::uint32_t csz) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwValueType);
    static_cast<void>(pValue);
    static_cast<void>(psz);
    static_cast<void>(csz);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertRegisterPhysicalStore(const void* pvSystemStore, std::uint32_t dwFlags, const char16_t* pwszStoreName, std::uint64_t pStoreInfo, void* pvReserved) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pvSystemStore);
    static_cast<void>(dwFlags);
    static_cast<void>(pwszStoreName);
    static_cast<void>(pStoreInfo);
    static_cast<void>(pvReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertRegisterSystemStore(const void* pvSystemStore, std::uint32_t dwFlags, std::uint64_t pStoreInfo, void* pvReserved) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pvSystemStore);
    static_cast<void>(dwFlags);
    static_cast<void>(pStoreInfo);
    static_cast<void>(pvReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertRemoveEnhancedKeyUsageIdentifier(void* pCertContext, const char* pszUsageIdentifier) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCertContext);
    static_cast<void>(pszUsageIdentifier);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kcrypt32G_CertRemoveStoreFromCollection(void* hCollectionStore, void* hSiblingStore) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCollectionStore);
    static_cast<void>(hSiblingStore);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertResyncCertificateChainEngine(void* hChainEngine) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hChainEngine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertRetrieveLogoOrBiometricInfo(void* pCertContext, const char* lpszLogoOrBiometricType, std::uint32_t dwRetrievalFlags, std::uint32_t dwTimeout, std::uint32_t dwFlags, void* pvReserved, std::uint8_t** ppbData, std::uint32_t* pcbData, char16_t** ppwszMimeType) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCertContext);
    static_cast<void>(lpszLogoOrBiometricType);
    static_cast<void>(dwRetrievalFlags);
    static_cast<void>(dwTimeout);
    static_cast<void>(dwFlags);
    static_cast<void>(pvReserved);
    static_cast<void>(ppbData);
    static_cast<void>(pcbData);
    static_cast<void>(ppwszMimeType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertSaveStore(void* hCertStore, std::uint32_t dwEncodingType, std::uint32_t dwSaveAs, std::uint32_t dwSaveTo, void* pvSaveToPara, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(dwEncodingType);
    static_cast<void>(dwSaveAs);
    static_cast<void>(dwSaveTo);
    static_cast<void>(pvSaveToPara);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertSelectCertificateChains(void* pSelectionContext, std::uint32_t dwFlags, std::uint64_t pChainParameters, std::uint32_t cCriteria, std::uint64_t rgpCriteria, void* hStore, std::uint32_t* pcSelection, void** pprgpSelection) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pSelectionContext);
    static_cast<void>(dwFlags);
    static_cast<void>(pChainParameters);
    static_cast<void>(cCriteria);
    static_cast<void>(rgpCriteria);
    static_cast<void>(hStore);
    static_cast<void>(pcSelection);
    static_cast<void>(pprgpSelection);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertSerializeCRLStoreElement(void* pCrlContext, std::uint32_t dwFlags, std::uint8_t* pbElement, std::uint32_t* pcbElement) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCrlContext);
    static_cast<void>(dwFlags);
    static_cast<void>(pbElement);
    static_cast<void>(pcbElement);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertSerializeCTLStoreElement(void* pCtlContext, std::uint32_t dwFlags, std::uint8_t* pbElement, std::uint32_t* pcbElement) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCtlContext);
    static_cast<void>(dwFlags);
    static_cast<void>(pbElement);
    static_cast<void>(pcbElement);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertSerializeCertificateStoreElement(void* pCertContext, std::uint32_t dwFlags, std::uint8_t* pbElement, std::uint32_t* pcbElement) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCertContext);
    static_cast<void>(dwFlags);
    static_cast<void>(pbElement);
    static_cast<void>(pcbElement);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertSetCRLContextProperty(void* pCrlContext, std::uint32_t dwPropId, std::uint32_t dwFlags, const void* pvData) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCrlContext);
    static_cast<void>(dwPropId);
    static_cast<void>(dwFlags);
    static_cast<void>(pvData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertSetCTLContextProperty(void* pCtlContext, std::uint32_t dwPropId, std::uint32_t dwFlags, const void* pvData) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCtlContext);
    static_cast<void>(dwPropId);
    static_cast<void>(dwFlags);
    static_cast<void>(pvData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertSetCertificateContextPropertiesFromCTLEntry(void* pCertContext, std::uint64_t pCtlEntry, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCertContext);
    static_cast<void>(pCtlEntry);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertSetCertificateContextProperty(void* pCertContext, std::uint32_t dwPropId, std::uint32_t dwFlags, const void* pvData) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCertContext);
    static_cast<void>(dwPropId);
    static_cast<void>(dwFlags);
    static_cast<void>(pvData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertSetEnhancedKeyUsage(void* pCertContext, std::uint64_t pUsage) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCertContext);
    static_cast<void>(pUsage);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertSetStoreProperty(void* hCertStore, std::uint32_t dwPropId, std::uint32_t dwFlags, const void* pvData) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCertStore);
    static_cast<void>(dwPropId);
    static_cast<void>(dwFlags);
    static_cast<void>(pvData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertStrToNameA(std::uint32_t dwCertEncodingType, const char* pszX500, std::uint32_t dwStrType, void* pvReserved, std::uint8_t* pbEncoded, std::uint32_t* pcbEncoded, const char** ppszError) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pszX500);
    static_cast<void>(dwStrType);
    static_cast<void>(pvReserved);
    static_cast<void>(pbEncoded);
    static_cast<void>(pcbEncoded);
    static_cast<void>(ppszError);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertStrToNameW(std::uint32_t dwCertEncodingType, const char16_t* pszX500, std::uint32_t dwStrType, void* pvReserved, std::uint8_t* pbEncoded, std::uint32_t* pcbEncoded, const char16_t** ppszError) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pszX500);
    static_cast<void>(dwStrType);
    static_cast<void>(pvReserved);
    static_cast<void>(pbEncoded);
    static_cast<void>(pcbEncoded);
    static_cast<void>(ppszError);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertUnregisterPhysicalStore(const void* pvSystemStore, std::uint32_t dwFlags, const char16_t* pwszStoreName) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pvSystemStore);
    static_cast<void>(dwFlags);
    static_cast<void>(pwszStoreName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertUnregisterSystemStore(const void* pvSystemStore, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pvSystemStore);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertVerifyCRLRevocation(std::uint32_t dwCertEncodingType, std::uint64_t pCertId, std::uint32_t cCrlInfo, void* rgpCrlInfo) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pCertId);
    static_cast<void>(cCrlInfo);
    static_cast<void>(rgpCrlInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertVerifyCRLTimeValidity(std::uint64_t* pTimeToVerify, std::uint64_t pCrlInfo) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(pTimeToVerify);
    static_cast<void>(pCrlInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertVerifyCTLUsage(std::uint32_t dwEncodingType, std::uint32_t dwSubjectType, void* pvSubject, void* pSubjectUsage, std::uint32_t dwFlags, std::uint64_t pVerifyUsagePara, std::uint64_t pVerifyUsageStatus) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(dwEncodingType);
    static_cast<void>(dwSubjectType);
    static_cast<void>(pvSubject);
    static_cast<void>(pSubjectUsage);
    static_cast<void>(dwFlags);
    static_cast<void>(pVerifyUsagePara);
    static_cast<void>(pVerifyUsageStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertVerifyCertificateChainPolicy(const char* pszPolicyOID, void* pChainContext, std::uint64_t pPolicyPara, std::uint64_t pPolicyStatus) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(pszPolicyOID);
    static_cast<void>(pChainContext);
    static_cast<void>(pPolicyPara);
    static_cast<void>(pPolicyStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CertVerifyRevocation(std::uint32_t dwEncodingType, std::uint32_t dwRevType, std::uint32_t cContext, void** rgpvContext, std::uint32_t dwFlags, std::uint64_t pRevPara, std::uint64_t pRevStatus) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(dwEncodingType);
    static_cast<void>(dwRevType);
    static_cast<void>(cContext);
    static_cast<void>(rgpvContext);
    static_cast<void>(dwFlags);
    static_cast<void>(pRevPara);
    static_cast<void>(pRevStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptAcquireCertificatePrivateKey(void* pCert, std::uint32_t dwFlags, void* pvParameters, std::uint64_t* phCryptProvOrNCryptKey, std::uint32_t* pdwKeySpec, std::int32_t* pfCallerFreeProvOrNCryptKey) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCert);
    static_cast<void>(dwFlags);
    static_cast<void>(pvParameters);
    static_cast<void>(phCryptProvOrNCryptKey);
    static_cast<void>(pdwKeySpec);
    static_cast<void>(pfCallerFreeProvOrNCryptKey);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptCloseAsyncHandle(std::uint64_t hAsync) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hAsync);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptCreateAsyncHandle(std::uint32_t dwFlags, std::uint64_t phAsync) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwFlags);
    static_cast<void>(phAsync);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptCreateKeyIdentifierFromCSP(std::uint32_t dwCertEncodingType, const char* pszPubKeyOID, const void* pPubKeyStruc, std::uint32_t cbPubKeyStruc, std::uint32_t dwFlags, void* pvReserved, std::uint8_t* pbHash, std::uint32_t* pcbHash) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pszPubKeyOID);
    static_cast<void>(pPubKeyStruc);
    static_cast<void>(cbPubKeyStruc);
    static_cast<void>(dwFlags);
    static_cast<void>(pvReserved);
    static_cast<void>(pbHash);
    static_cast<void>(pcbHash);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptDecodeMessage(std::uint32_t dwMsgTypeFlags, void* pDecryptPara, void* pVerifyPara, std::uint32_t dwSignerIndex, const std::uint8_t* pbEncodedBlob, std::uint32_t cbEncodedBlob, std::uint32_t dwPrevInnerContentType, std::uint32_t* pdwMsgType, std::uint32_t* pdwInnerContentType, std::uint8_t* pbDecoded, std::uint32_t* pcbDecoded, void* ppXchgCert, void* ppSignerCert) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwMsgTypeFlags);
    static_cast<void>(pDecryptPara);
    static_cast<void>(pVerifyPara);
    static_cast<void>(dwSignerIndex);
    static_cast<void>(pbEncodedBlob);
    static_cast<void>(cbEncodedBlob);
    static_cast<void>(dwPrevInnerContentType);
    static_cast<void>(pdwMsgType);
    static_cast<void>(pdwInnerContentType);
    static_cast<void>(pbDecoded);
    static_cast<void>(pcbDecoded);
    static_cast<void>(ppXchgCert);
    static_cast<void>(ppSignerCert);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptDecodeObjectEx(std::uint32_t dwCertEncodingType, const char* lpszStructType, const std::uint8_t* pbEncoded, std::uint32_t cbEncoded, std::uint32_t dwFlags, std::uint64_t pDecodePara, void* pvStructInfo, std::uint32_t* pcbStructInfo) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(lpszStructType);
    static_cast<void>(pbEncoded);
    static_cast<void>(cbEncoded);
    static_cast<void>(dwFlags);
    static_cast<void>(pDecodePara);
    static_cast<void>(pvStructInfo);
    static_cast<void>(pcbStructInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptDecryptAndVerifyMessageSignature(void* pDecryptPara, void* pVerifyPara, std::uint32_t dwSignerIndex, const std::uint8_t* pbEncryptedBlob, std::uint32_t cbEncryptedBlob, std::uint8_t* pbDecrypted, std::uint32_t* pcbDecrypted, void* ppXchgCert, void* ppSignerCert) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pDecryptPara);
    static_cast<void>(pVerifyPara);
    static_cast<void>(dwSignerIndex);
    static_cast<void>(pbEncryptedBlob);
    static_cast<void>(cbEncryptedBlob);
    static_cast<void>(pbDecrypted);
    static_cast<void>(pcbDecrypted);
    static_cast<void>(ppXchgCert);
    static_cast<void>(ppSignerCert);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptDecryptMessage(void* pDecryptPara, const std::uint8_t* pbEncryptedBlob, std::uint32_t cbEncryptedBlob, std::uint8_t* pbDecrypted, std::uint32_t* pcbDecrypted, void* ppXchgCert) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pDecryptPara);
    static_cast<void>(pbEncryptedBlob);
    static_cast<void>(cbEncryptedBlob);
    static_cast<void>(pbDecrypted);
    static_cast<void>(pcbDecrypted);
    static_cast<void>(ppXchgCert);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptEncodeObjectEx(std::uint32_t dwCertEncodingType, const char* lpszStructType, const void* pvStructInfo, std::uint32_t dwFlags, std::uint64_t pEncodePara, void* pvEncoded, std::uint32_t* pcbEncoded) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(lpszStructType);
    static_cast<void>(pvStructInfo);
    static_cast<void>(dwFlags);
    static_cast<void>(pEncodePara);
    static_cast<void>(pvEncoded);
    static_cast<void>(pcbEncoded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptEncryptMessage(void* pEncryptPara, std::uint32_t cRecipientCert, void* rgpRecipientCert, const std::uint8_t* pbToBeEncrypted, std::uint32_t cbToBeEncrypted, std::uint8_t* pbEncryptedBlob, std::uint32_t* pcbEncryptedBlob) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pEncryptPara);
    static_cast<void>(cRecipientCert);
    static_cast<void>(rgpRecipientCert);
    static_cast<void>(pbToBeEncrypted);
    static_cast<void>(cbToBeEncrypted);
    static_cast<void>(pbEncryptedBlob);
    static_cast<void>(pcbEncryptedBlob);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptEnumKeyIdentifierProperties(const void* pKeyIdentifier, std::uint32_t dwPropId, std::uint32_t dwFlags, const char16_t* pwszComputerName, void* pvReserved, void* pvArg, std::uint64_t pfnEnum) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pKeyIdentifier);
    static_cast<void>(dwPropId);
    static_cast<void>(dwFlags);
    static_cast<void>(pwszComputerName);
    static_cast<void>(pvReserved);
    static_cast<void>(pvArg);
    static_cast<void>(pfnEnum);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptEnumOIDFunction(std::uint32_t dwEncodingType, const char* pszFuncName, const char* pszOID, std::uint32_t dwFlags, void* pvArg, std::uint64_t pfnEnumOIDFunc) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwEncodingType);
    static_cast<void>(pszFuncName);
    static_cast<void>(pszOID);
    static_cast<void>(dwFlags);
    static_cast<void>(pvArg);
    static_cast<void>(pfnEnumOIDFunc);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptEnumOIDInfo(std::uint32_t dwGroupId, std::uint32_t dwFlags, void* pvArg, std::uint64_t pfnEnumOIDInfo) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwGroupId);
    static_cast<void>(dwFlags);
    static_cast<void>(pvArg);
    static_cast<void>(pfnEnumOIDInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptExportPKCS8(void* hCryptProv, std::uint32_t dwKeySpec, char* pszPrivateKeyObjId, std::uint32_t dwFlags, void* pvAuxInfo, std::uint8_t* pbPrivateKeyBlob, std::uint32_t* pcbPrivateKeyBlob) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCryptProv);
    static_cast<void>(dwKeySpec);
    static_cast<void>(pszPrivateKeyObjId);
    static_cast<void>(dwFlags);
    static_cast<void>(pvAuxInfo);
    static_cast<void>(pbPrivateKeyBlob);
    static_cast<void>(pcbPrivateKeyBlob);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptExportPublicKeyInfo(std::uint64_t hCryptProvOrNCryptKey, std::uint32_t dwKeySpec, std::uint32_t dwCertEncodingType, const void* pInfo, std::uint32_t* pcbInfo) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCryptProvOrNCryptKey);
    static_cast<void>(dwKeySpec);
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pInfo);
    static_cast<void>(pcbInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptExportPublicKeyInfoEx(std::uint64_t hCryptProvOrNCryptKey, std::uint32_t dwKeySpec, std::uint32_t dwCertEncodingType, char* pszPublicKeyObjId, std::uint32_t dwFlags, void* pvAuxInfo, const void* pInfo, std::uint32_t* pcbInfo) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCryptProvOrNCryptKey);
    static_cast<void>(dwKeySpec);
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pszPublicKeyObjId);
    static_cast<void>(dwFlags);
    static_cast<void>(pvAuxInfo);
    static_cast<void>(pInfo);
    static_cast<void>(pcbInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptExportPublicKeyInfoFromBCryptKeyHandle(void* hBCryptKey, std::uint32_t dwCertEncodingType, char* pszPublicKeyObjId, std::uint32_t dwFlags, void* pvAuxInfo, const void* pInfo, std::uint32_t* pcbInfo) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hBCryptKey);
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pszPublicKeyObjId);
    static_cast<void>(dwFlags);
    static_cast<void>(pvAuxInfo);
    static_cast<void>(pInfo);
    static_cast<void>(pcbInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptFindCertificateKeyProvInfo(void* pCert, std::uint32_t dwFlags, void* pvReserved) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pCert);
    static_cast<void>(dwFlags);
    static_cast<void>(pvReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) const char16_t* kcrypt32G_CryptFindLocalizedName(const char16_t* pwszCryptName) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pwszCryptName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kcrypt32G_CryptFindOIDInfo(std::uint32_t dwKeyType, void* pvKey, std::uint32_t dwGroupId) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwKeyType);
    static_cast<void>(pvKey);
    static_cast<void>(dwGroupId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptFreeOIDFunctionAddress(std::uint64_t hFuncAddr, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hFuncAddr);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptGetAsyncParam(std::uint64_t hAsync, char* pszParamOid, void** ppvParam, void* ppfnFree) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hAsync);
    static_cast<void>(pszParamOid);
    static_cast<void>(ppvParam);
    static_cast<void>(ppfnFree);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptGetDefaultOIDDllList(std::uint64_t hFuncSet, std::uint32_t dwEncodingType, char16_t* pwszDllList, std::uint32_t* pcchDllList) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hFuncSet);
    static_cast<void>(dwEncodingType);
    static_cast<void>(pwszDllList);
    static_cast<void>(pcchDllList);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptGetDefaultOIDFunctionAddress(std::uint64_t hFuncSet, std::uint32_t dwEncodingType, const char16_t* pwszDll, std::uint32_t dwFlags, void** ppvFuncAddr, void* phFuncAddr) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hFuncSet);
    static_cast<void>(dwEncodingType);
    static_cast<void>(pwszDll);
    static_cast<void>(dwFlags);
    static_cast<void>(ppvFuncAddr);
    static_cast<void>(phFuncAddr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptGetKeyIdentifierProperty(const void* pKeyIdentifier, std::uint32_t dwPropId, std::uint32_t dwFlags, const char16_t* pwszComputerName, void* pvReserved, void* pvData, std::uint32_t* pcbData) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pKeyIdentifier);
    static_cast<void>(dwPropId);
    static_cast<void>(dwFlags);
    static_cast<void>(pwszComputerName);
    static_cast<void>(pvReserved);
    static_cast<void>(pvData);
    static_cast<void>(pcbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CryptGetMessageCertificates(std::uint32_t dwMsgAndCertEncodingType, std::uint64_t hCryptProv, std::uint32_t dwFlags, const std::uint8_t* pbSignedBlob, std::uint32_t cbSignedBlob) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwMsgAndCertEncodingType);
    static_cast<void>(hCryptProv);
    static_cast<void>(dwFlags);
    static_cast<void>(pbSignedBlob);
    static_cast<void>(cbSignedBlob);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptGetMessageSignerCount(std::uint32_t dwMsgEncodingType, const std::uint8_t* pbSignedBlob, std::uint32_t cbSignedBlob) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwMsgEncodingType);
    static_cast<void>(pbSignedBlob);
    static_cast<void>(cbSignedBlob);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptGetOIDFunctionAddress(std::uint64_t hFuncSet, std::uint32_t dwEncodingType, const char* pszOID, std::uint32_t dwFlags, void** ppvFuncAddr, void* phFuncAddr) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hFuncSet);
    static_cast<void>(dwEncodingType);
    static_cast<void>(pszOID);
    static_cast<void>(dwFlags);
    static_cast<void>(ppvFuncAddr);
    static_cast<void>(phFuncAddr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptGetOIDFunctionValue(std::uint32_t dwEncodingType, const char* pszFuncName, const char* pszOID, const char16_t* pwszValueName, std::uint32_t* pdwValueType, std::uint8_t* pbValueData, std::uint32_t* pcbValueData) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwEncodingType);
    static_cast<void>(pszFuncName);
    static_cast<void>(pszOID);
    static_cast<void>(pwszValueName);
    static_cast<void>(pdwValueType);
    static_cast<void>(pbValueData);
    static_cast<void>(pcbValueData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptHashCertificate(std::uint64_t hCryptProv, std::uint64_t Algid, std::uint32_t dwFlags, const std::uint8_t* pbEncoded, std::uint32_t cbEncoded, std::uint8_t* pbComputedHash, std::uint32_t* pcbComputedHash) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCryptProv);
    static_cast<void>(Algid);
    static_cast<void>(dwFlags);
    static_cast<void>(pbEncoded);
    static_cast<void>(cbEncoded);
    static_cast<void>(pbComputedHash);
    static_cast<void>(pcbComputedHash);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptHashCertificate2(const char16_t* pwszCNGHashAlgid, std::uint32_t dwFlags, void* pvReserved, const std::uint8_t* pbEncoded, std::uint32_t cbEncoded, std::uint8_t* pbComputedHash, std::uint32_t* pcbComputedHash) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pwszCNGHashAlgid);
    static_cast<void>(dwFlags);
    static_cast<void>(pvReserved);
    static_cast<void>(pbEncoded);
    static_cast<void>(cbEncoded);
    static_cast<void>(pbComputedHash);
    static_cast<void>(pcbComputedHash);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptHashMessage(std::uint64_t pHashPara, std::int32_t fDetachedHash, std::uint32_t cToBeHashed, const std::uint8_t** rgpbToBeHashed, std::uint32_t* rgcbToBeHashed, std::uint8_t* pbHashedBlob, std::uint32_t* pcbHashedBlob, std::uint8_t* pbComputedHash, std::uint32_t* pcbComputedHash) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pHashPara);
    static_cast<void>(fDetachedHash);
    static_cast<void>(cToBeHashed);
    static_cast<void>(rgpbToBeHashed);
    static_cast<void>(rgcbToBeHashed);
    static_cast<void>(pbHashedBlob);
    static_cast<void>(pcbHashedBlob);
    static_cast<void>(pbComputedHash);
    static_cast<void>(pcbComputedHash);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptHashPublicKeyInfo(std::uint64_t hCryptProv, std::uint64_t Algid, std::uint32_t dwFlags, std::uint32_t dwCertEncodingType, const void* pInfo, std::uint8_t* pbComputedHash, std::uint32_t* pcbComputedHash) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCryptProv);
    static_cast<void>(Algid);
    static_cast<void>(dwFlags);
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pInfo);
    static_cast<void>(pbComputedHash);
    static_cast<void>(pcbComputedHash);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptHashToBeSigned(std::uint64_t hCryptProv, std::uint32_t dwCertEncodingType, const std::uint8_t* pbEncoded, std::uint32_t cbEncoded, std::uint8_t* pbComputedHash, std::uint32_t* pcbComputedHash) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCryptProv);
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pbEncoded);
    static_cast<void>(cbEncoded);
    static_cast<void>(pbComputedHash);
    static_cast<void>(pcbComputedHash);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptImportPKCS8(std::uint64_t sPrivateKeyAndParams, std::uint32_t dwFlags, void* phCryptProv, void* pvAuxInfo) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(sPrivateKeyAndParams);
    static_cast<void>(dwFlags);
    static_cast<void>(phCryptProv);
    static_cast<void>(pvAuxInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptImportPublicKeyInfo(void* hCryptProv, std::uint32_t dwCertEncodingType, const void* pInfo, void* phKey) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCryptProv);
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pInfo);
    static_cast<void>(phKey);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptImportPublicKeyInfoEx(void* hCryptProv, std::uint32_t dwCertEncodingType, const void* pInfo, std::uint64_t aiKeyAlg, std::uint32_t dwFlags, void* pvAuxInfo, void* phKey) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCryptProv);
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pInfo);
    static_cast<void>(aiKeyAlg);
    static_cast<void>(dwFlags);
    static_cast<void>(pvAuxInfo);
    static_cast<void>(phKey);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptImportPublicKeyInfoEx2(std::uint32_t dwCertEncodingType, const void* pInfo, std::uint32_t dwFlags, void* pvAuxInfo, void* phKey) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pInfo);
    static_cast<void>(dwFlags);
    static_cast<void>(pvAuxInfo);
    static_cast<void>(phKey);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kcrypt32G_CryptInitOIDFunctionSet(const char* pszFuncName, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pszFuncName);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptInstallDefaultContext(void* hCryptProv, std::uint32_t dwDefaultType, const void* pvDefaultPara, std::uint32_t dwFlags, void* pvReserved, void* phDefaultContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCryptProv);
    static_cast<void>(dwDefaultType);
    static_cast<void>(pvDefaultPara);
    static_cast<void>(dwFlags);
    static_cast<void>(pvReserved);
    static_cast<void>(phDefaultContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptInstallOIDFunctionAddress(void* hModule, std::uint32_t dwEncodingType, const char* pszFuncName, std::uint32_t cFuncEntry, const void* rgFuncEntry, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hModule);
    static_cast<void>(dwEncodingType);
    static_cast<void>(pszFuncName);
    static_cast<void>(cFuncEntry);
    static_cast<void>(rgFuncEntry);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kcrypt32G_CryptMsgCalculateEncodedLength(std::uint32_t dwMsgEncodingType, std::uint32_t dwFlags, std::uint32_t dwMsgType, void* pvMsgEncodeInfo, char* pszInnerContentObjID, std::uint32_t cbData) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwMsgEncodingType);
    static_cast<void>(dwFlags);
    static_cast<void>(dwMsgType);
    static_cast<void>(pvMsgEncodeInfo);
    static_cast<void>(pszInnerContentObjID);
    static_cast<void>(cbData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptMsgCountersign(void* hCryptMsg, std::uint32_t dwIndex, std::uint32_t cCountersigners, std::uint64_t rgCountersigners) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCryptMsg);
    static_cast<void>(dwIndex);
    static_cast<void>(cCountersigners);
    static_cast<void>(rgCountersigners);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptMsgCountersignEncoded(std::uint32_t dwEncodingType, std::uint8_t* pbSignerInfo, std::uint32_t cbSignerInfo, std::uint32_t cCountersigners, std::uint64_t rgCountersigners, std::uint8_t* pbCountersignature, std::uint32_t* pcbCountersignature) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwEncodingType);
    static_cast<void>(pbSignerInfo);
    static_cast<void>(cbSignerInfo);
    static_cast<void>(cCountersigners);
    static_cast<void>(rgCountersigners);
    static_cast<void>(pbCountersignature);
    static_cast<void>(pcbCountersignature);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_CryptMsgDuplicate(void* hCryptMsg) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCryptMsg);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptMsgEncodeAndSignCTL(std::uint32_t dwMsgEncodingType, std::uint64_t pCtlInfo, std::uint64_t pSignInfo, std::uint32_t dwFlags, std::uint8_t* pbEncoded, std::uint32_t* pcbEncoded) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwMsgEncodingType);
    static_cast<void>(pCtlInfo);
    static_cast<void>(pSignInfo);
    static_cast<void>(dwFlags);
    static_cast<void>(pbEncoded);
    static_cast<void>(pcbEncoded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptMsgGetAndVerifySigner(void* hCryptMsg, std::uint32_t cSignerStore, void* rghSignerStore, std::uint32_t dwFlags, void* ppSigner, std::uint32_t* pdwSignerIndex) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCryptMsg);
    static_cast<void>(cSignerStore);
    static_cast<void>(rghSignerStore);
    static_cast<void>(dwFlags);
    static_cast<void>(ppSigner);
    static_cast<void>(pdwSignerIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptMsgSignCTL(std::uint32_t dwMsgEncodingType, std::uint8_t* pbCtlContent, std::uint32_t cbCtlContent, std::uint64_t pSignInfo, std::uint32_t dwFlags, std::uint8_t* pbEncoded, std::uint32_t* pcbEncoded) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwMsgEncodingType);
    static_cast<void>(pbCtlContent);
    static_cast<void>(cbCtlContent);
    static_cast<void>(pSignInfo);
    static_cast<void>(dwFlags);
    static_cast<void>(pbEncoded);
    static_cast<void>(pcbEncoded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptMsgVerifyCountersignatureEncoded(std::uint64_t hCryptProv, std::uint32_t dwEncodingType, std::uint8_t* pbSignerInfo, std::uint32_t cbSignerInfo, std::uint8_t* pbSignerInfoCountersignature, std::uint32_t cbSignerInfoCountersignature, std::uint64_t pciCountersigner) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCryptProv);
    static_cast<void>(dwEncodingType);
    static_cast<void>(pbSignerInfo);
    static_cast<void>(cbSignerInfo);
    static_cast<void>(pbSignerInfoCountersignature);
    static_cast<void>(cbSignerInfoCountersignature);
    static_cast<void>(pciCountersigner);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptMsgVerifyCountersignatureEncodedEx(std::uint64_t hCryptProv, std::uint32_t dwEncodingType, std::uint8_t* pbSignerInfo, std::uint32_t cbSignerInfo, std::uint8_t* pbSignerInfoCountersignature, std::uint32_t cbSignerInfoCountersignature, std::uint32_t dwSignerType, void* pvSigner, std::uint32_t dwFlags, void* pvExtra) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCryptProv);
    static_cast<void>(dwEncodingType);
    static_cast<void>(pbSignerInfo);
    static_cast<void>(cbSignerInfo);
    static_cast<void>(pbSignerInfoCountersignature);
    static_cast<void>(cbSignerInfoCountersignature);
    static_cast<void>(dwSignerType);
    static_cast<void>(pvSigner);
    static_cast<void>(dwFlags);
    static_cast<void>(pvExtra);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptProtectMemory(void* pDataIn, std::uint32_t cbDataIn, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pDataIn);
    static_cast<void>(cbDataIn);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptRegisterDefaultOIDFunction(std::uint32_t dwEncodingType, const char* pszFuncName, std::uint32_t dwIndex, const char16_t* pwszDll) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwEncodingType);
    static_cast<void>(pszFuncName);
    static_cast<void>(dwIndex);
    static_cast<void>(pwszDll);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptRegisterOIDFunction(std::uint32_t dwEncodingType, const char* pszFuncName, const char* pszOID, const char16_t* pwszDll, const char* pszOverrideFuncName) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwEncodingType);
    static_cast<void>(pszFuncName);
    static_cast<void>(pszOID);
    static_cast<void>(pwszDll);
    static_cast<void>(pszOverrideFuncName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptRegisterOIDInfo(std::uint64_t pInfo, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pInfo);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptRetrieveTimeStamp(const char16_t* wszUrl, std::uint32_t dwRetrievalFlags, std::uint32_t dwTimeout, const char* pszHashId, const void* pPara, const std::uint8_t* pbData, std::uint32_t cbData, void* ppTsContext, void* ppTsSigner, void* phStore) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(wszUrl);
    static_cast<void>(dwRetrievalFlags);
    static_cast<void>(dwTimeout);
    static_cast<void>(pszHashId);
    static_cast<void>(pPara);
    static_cast<void>(pbData);
    static_cast<void>(cbData);
    static_cast<void>(ppTsContext);
    static_cast<void>(ppTsSigner);
    static_cast<void>(phStore);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptSetAsyncParam(std::uint64_t hAsync, char* pszParamOid, void* pvParam, std::uint64_t pfnFree) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hAsync);
    static_cast<void>(pszParamOid);
    static_cast<void>(pvParam);
    static_cast<void>(pfnFree);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptSetKeyIdentifierProperty(const void* pKeyIdentifier, std::uint32_t dwPropId, std::uint32_t dwFlags, const char16_t* pwszComputerName, void* pvReserved, const void* pvData) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pKeyIdentifier);
    static_cast<void>(dwPropId);
    static_cast<void>(dwFlags);
    static_cast<void>(pwszComputerName);
    static_cast<void>(pvReserved);
    static_cast<void>(pvData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptSetOIDFunctionValue(std::uint32_t dwEncodingType, const char* pszFuncName, const char* pszOID, const char16_t* pwszValueName, std::uint32_t dwValueType, const std::uint8_t* pbValueData, std::uint32_t cbValueData) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwEncodingType);
    static_cast<void>(pszFuncName);
    static_cast<void>(pszOID);
    static_cast<void>(pwszValueName);
    static_cast<void>(dwValueType);
    static_cast<void>(pbValueData);
    static_cast<void>(cbValueData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptSignAndEncodeCertificate(std::uint64_t hCryptProvOrNCryptKey, std::uint32_t dwKeySpec, std::uint32_t dwCertEncodingType, const char* lpszStructType, const void* pvStructInfo, void* pSignatureAlgorithm, const void* pvHashAuxInfo, std::uint8_t* pbEncoded, std::uint32_t* pcbEncoded) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCryptProvOrNCryptKey);
    static_cast<void>(dwKeySpec);
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(lpszStructType);
    static_cast<void>(pvStructInfo);
    static_cast<void>(pSignatureAlgorithm);
    static_cast<void>(pvHashAuxInfo);
    static_cast<void>(pbEncoded);
    static_cast<void>(pcbEncoded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptSignAndEncryptMessage(void* pSignPara, void* pEncryptPara, std::uint32_t cRecipientCert, void* rgpRecipientCert, const std::uint8_t* pbToBeSignedAndEncrypted, std::uint32_t cbToBeSignedAndEncrypted, std::uint8_t* pbSignedAndEncryptedBlob, std::uint32_t* pcbSignedAndEncryptedBlob) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pSignPara);
    static_cast<void>(pEncryptPara);
    static_cast<void>(cRecipientCert);
    static_cast<void>(rgpRecipientCert);
    static_cast<void>(pbToBeSignedAndEncrypted);
    static_cast<void>(cbToBeSignedAndEncrypted);
    static_cast<void>(pbSignedAndEncryptedBlob);
    static_cast<void>(pcbSignedAndEncryptedBlob);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptSignCertificate(std::uint64_t hCryptProvOrNCryptKey, std::uint32_t dwKeySpec, std::uint32_t dwCertEncodingType, const std::uint8_t* pbEncodedToBeSigned, std::uint32_t cbEncodedToBeSigned, void* pSignatureAlgorithm, const void* pvHashAuxInfo, std::uint8_t* pbSignature, std::uint32_t* pcbSignature) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hCryptProvOrNCryptKey);
    static_cast<void>(dwKeySpec);
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pbEncodedToBeSigned);
    static_cast<void>(cbEncodedToBeSigned);
    static_cast<void>(pSignatureAlgorithm);
    static_cast<void>(pvHashAuxInfo);
    static_cast<void>(pbSignature);
    static_cast<void>(pcbSignature);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptSignMessage(void* pSignPara, std::int32_t fDetachedSignature, std::uint32_t cToBeSigned, const std::uint8_t** rgpbToBeSigned, std::uint32_t* rgcbToBeSigned, std::uint8_t* pbSignedBlob, std::uint32_t* pcbSignedBlob) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pSignPara);
    static_cast<void>(fDetachedSignature);
    static_cast<void>(cToBeSigned);
    static_cast<void>(rgpbToBeSigned);
    static_cast<void>(rgcbToBeSigned);
    static_cast<void>(pbSignedBlob);
    static_cast<void>(pcbSignedBlob);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptSignMessageWithKey(std::uint64_t pSignPara, const std::uint8_t* pbToBeSigned, std::uint32_t cbToBeSigned, std::uint8_t* pbSignedBlob, std::uint32_t* pcbSignedBlob) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pSignPara);
    static_cast<void>(pbToBeSigned);
    static_cast<void>(cbToBeSigned);
    static_cast<void>(pbSignedBlob);
    static_cast<void>(pcbSignedBlob);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptUninstallDefaultContext(std::uint64_t hDefaultContext, std::uint32_t dwFlags, void* pvReserved) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hDefaultContext);
    static_cast<void>(dwFlags);
    static_cast<void>(pvReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptUnprotectMemory(void* pDataIn, std::uint32_t cbDataIn, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pDataIn);
    static_cast<void>(cbDataIn);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptUnregisterDefaultOIDFunction(std::uint32_t dwEncodingType, const char* pszFuncName, const char16_t* pwszDll) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwEncodingType);
    static_cast<void>(pszFuncName);
    static_cast<void>(pwszDll);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptUnregisterOIDFunction(std::uint32_t dwEncodingType, const char* pszFuncName, const char* pszOID) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwEncodingType);
    static_cast<void>(pszFuncName);
    static_cast<void>(pszOID);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptUnregisterOIDInfo(std::uint64_t pInfo) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptVerifyCertificateSignature(std::uint64_t hCryptProv, std::uint32_t dwCertEncodingType, const std::uint8_t* pbEncoded, std::uint32_t cbEncoded, const void* pPublicKey) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(hCryptProv);
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(pbEncoded);
    static_cast<void>(cbEncoded);
    static_cast<void>(pPublicKey);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptVerifyCertificateSignatureEx(std::uint64_t hCryptProv, std::uint32_t dwCertEncodingType, std::uint32_t dwSubjectType, void* pvSubject, std::uint32_t dwIssuerType, void* pvIssuer, std::uint32_t dwFlags, void* pvExtra) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(hCryptProv);
    static_cast<void>(dwCertEncodingType);
    static_cast<void>(dwSubjectType);
    static_cast<void>(pvSubject);
    static_cast<void>(dwIssuerType);
    static_cast<void>(pvIssuer);
    static_cast<void>(dwFlags);
    static_cast<void>(pvExtra);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptVerifyDetachedMessageHash(std::uint64_t pHashPara, std::uint8_t* pbDetachedHashBlob, std::uint32_t cbDetachedHashBlob, std::uint32_t cToBeHashed, const std::uint8_t** rgpbToBeHashed, std::uint32_t* rgcbToBeHashed, std::uint8_t* pbComputedHash, std::uint32_t* pcbComputedHash) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(pHashPara);
    static_cast<void>(pbDetachedHashBlob);
    static_cast<void>(cbDetachedHashBlob);
    static_cast<void>(cToBeHashed);
    static_cast<void>(rgpbToBeHashed);
    static_cast<void>(rgcbToBeHashed);
    static_cast<void>(pbComputedHash);
    static_cast<void>(pcbComputedHash);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptVerifyDetachedMessageSignature(void* pVerifyPara, std::uint32_t dwSignerIndex, const std::uint8_t* pbDetachedSignBlob, std::uint32_t cbDetachedSignBlob, std::uint32_t cToBeSigned, const std::uint8_t** rgpbToBeSigned, std::uint32_t* rgcbToBeSigned, void* ppSignerCert) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(pVerifyPara);
    static_cast<void>(dwSignerIndex);
    static_cast<void>(pbDetachedSignBlob);
    static_cast<void>(cbDetachedSignBlob);
    static_cast<void>(cToBeSigned);
    static_cast<void>(rgpbToBeSigned);
    static_cast<void>(rgcbToBeSigned);
    static_cast<void>(ppSignerCert);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptVerifyMessageHash(std::uint64_t pHashPara, std::uint8_t* pbHashedBlob, std::uint32_t cbHashedBlob, std::uint8_t* pbToBeHashed, std::uint32_t* pcbToBeHashed, std::uint8_t* pbComputedHash, std::uint32_t* pcbComputedHash) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(pHashPara);
    static_cast<void>(pbHashedBlob);
    static_cast<void>(cbHashedBlob);
    static_cast<void>(pbToBeHashed);
    static_cast<void>(pcbToBeHashed);
    static_cast<void>(pbComputedHash);
    static_cast<void>(pcbComputedHash);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptVerifyMessageSignature(void* pVerifyPara, std::uint32_t dwSignerIndex, const std::uint8_t* pbSignedBlob, std::uint32_t cbSignedBlob, std::uint8_t* pbDecoded, std::uint32_t* pcbDecoded, void* ppSignerCert) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(pVerifyPara);
    static_cast<void>(dwSignerIndex);
    static_cast<void>(pbSignedBlob);
    static_cast<void>(cbSignedBlob);
    static_cast<void>(pbDecoded);
    static_cast<void>(pcbDecoded);
    static_cast<void>(ppSignerCert);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptVerifyMessageSignatureWithKey(std::uint64_t pVerifyPara, const void* pPublicKeyInfo, const std::uint8_t* pbSignedBlob, std::uint32_t cbSignedBlob, std::uint8_t* pbDecoded, std::uint32_t* pcbDecoded) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(pVerifyPara);
    static_cast<void>(pPublicKeyInfo);
    static_cast<void>(pbSignedBlob);
    static_cast<void>(cbSignedBlob);
    static_cast<void>(pbDecoded);
    static_cast<void>(pcbDecoded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_CryptVerifyTimeStampSignature(const std::uint8_t* pbTSContentInfo, std::uint32_t cbTSContentInfo, const std::uint8_t* pbData, std::uint32_t cbData, void* hAdditionalStore, void* ppTsContext, void* ppTsSigner, void* phStore) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(pbTSContentInfo);
    static_cast<void>(cbTSContentInfo);
    static_cast<void>(pbData);
    static_cast<void>(cbData);
    static_cast<void>(hAdditionalStore);
    static_cast<void>(ppTsContext);
    static_cast<void>(ppTsSigner);
    static_cast<void>(phStore);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_PFXExportCertStore(void* hStore, void* pPFX, const char16_t* szPassword, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hStore);
    static_cast<void>(pPFX);
    static_cast<void>(szPassword);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_PFXExportCertStoreEx(void* hStore, void* pPFX, const char16_t* szPassword, void* pvPara, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hStore);
    static_cast<void>(pPFX);
    static_cast<void>(szPassword);
    static_cast<void>(pvPara);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kcrypt32G_PFXImportCertStore(void* pPFX, const char16_t* szPassword, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pPFX);
    static_cast<void>(szPassword);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_PFXIsPFXBlob(void* pPFX) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement
    static_cast<void>(pPFX);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kcrypt32G_PFXVerifyPassword(void* pPFX, const char16_t* szPassword, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement
    static_cast<void>(pPFX);
    static_cast<void>(szPassword);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_crypt32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CertAddCRLContextToStore", reinterpret_cast<void*>(&kcrypt32G_CertAddCRLContextToStore));
    e("CertAddCRLLinkToStore", reinterpret_cast<void*>(&kcrypt32G_CertAddCRLLinkToStore));
    e("CertAddCTLContextToStore", reinterpret_cast<void*>(&kcrypt32G_CertAddCTLContextToStore));
    e("CertAddCTLLinkToStore", reinterpret_cast<void*>(&kcrypt32G_CertAddCTLLinkToStore));
    e("CertAddCertificateLinkToStore", reinterpret_cast<void*>(&kcrypt32G_CertAddCertificateLinkToStore));
    e("CertAddEncodedCRLToStore", reinterpret_cast<void*>(&kcrypt32G_CertAddEncodedCRLToStore));
    e("CertAddEncodedCTLToStore", reinterpret_cast<void*>(&kcrypt32G_CertAddEncodedCTLToStore));
    e("CertAddEncodedCertificateToSystemStoreA", reinterpret_cast<void*>(&kcrypt32G_CertAddEncodedCertificateToSystemStoreA));
    e("CertAddEncodedCertificateToSystemStoreW", reinterpret_cast<void*>(&kcrypt32G_CertAddEncodedCertificateToSystemStoreW));
    e("CertAddEnhancedKeyUsageIdentifier", reinterpret_cast<void*>(&kcrypt32G_CertAddEnhancedKeyUsageIdentifier));
    e("CertAddRefServerOcspResponse", reinterpret_cast<void*>(&kcrypt32G_CertAddRefServerOcspResponse));
    e("CertAddRefServerOcspResponseContext", reinterpret_cast<void*>(&kcrypt32G_CertAddRefServerOcspResponseContext));
    e("CertAddSerializedElementToStore", reinterpret_cast<void*>(&kcrypt32G_CertAddSerializedElementToStore));
    e("CertAddStoreToCollection", reinterpret_cast<void*>(&kcrypt32G_CertAddStoreToCollection));
    e("CertAlgIdToOID", reinterpret_cast<void*>(&kcrypt32G_CertAlgIdToOID));
    e("CertCloseServerOcspResponse", reinterpret_cast<void*>(&kcrypt32G_CertCloseServerOcspResponse));
    e("CertCompareIntegerBlob", reinterpret_cast<void*>(&kcrypt32G_CertCompareIntegerBlob));
    e("CertComparePublicKeyInfo", reinterpret_cast<void*>(&kcrypt32G_CertComparePublicKeyInfo));
    e("CertControlStore", reinterpret_cast<void*>(&kcrypt32G_CertControlStore));
    e("CertCreateCRLContext", reinterpret_cast<void*>(&kcrypt32G_CertCreateCRLContext));
    e("CertCreateCTLContext", reinterpret_cast<void*>(&kcrypt32G_CertCreateCTLContext));
    e("CertCreateCTLEntryFromCertificateContextProperties", reinterpret_cast<void*>(&kcrypt32G_CertCreateCTLEntryFromCertificateContextProperties));
    e("CertCreateCertificateChainEngine", reinterpret_cast<void*>(&kcrypt32G_CertCreateCertificateChainEngine));
    e("CertCreateContext", reinterpret_cast<void*>(&kcrypt32G_CertCreateContext));
    e("CertCreateSelfSignCertificate", reinterpret_cast<void*>(&kcrypt32G_CertCreateSelfSignCertificate));
    e("CertDeleteCRLFromStore", reinterpret_cast<void*>(&kcrypt32G_CertDeleteCRLFromStore));
    e("CertDeleteCTLFromStore", reinterpret_cast<void*>(&kcrypt32G_CertDeleteCTLFromStore));
    e("CertDuplicateCRLContext", reinterpret_cast<void*>(&kcrypt32G_CertDuplicateCRLContext));
    e("CertDuplicateCTLContext", reinterpret_cast<void*>(&kcrypt32G_CertDuplicateCTLContext));
    e("CertDuplicateCertificateChain", reinterpret_cast<void*>(&kcrypt32G_CertDuplicateCertificateChain));
    e("CertDuplicateStore", reinterpret_cast<void*>(&kcrypt32G_CertDuplicateStore));
    e("CertEnumCRLContextProperties", reinterpret_cast<void*>(&kcrypt32G_CertEnumCRLContextProperties));
    e("CertEnumCRLsInStore", reinterpret_cast<void*>(&kcrypt32G_CertEnumCRLsInStore));
    e("CertEnumCTLContextProperties", reinterpret_cast<void*>(&kcrypt32G_CertEnumCTLContextProperties));
    e("CertEnumCTLsInStore", reinterpret_cast<void*>(&kcrypt32G_CertEnumCTLsInStore));
    e("CertEnumCertificateContextProperties", reinterpret_cast<void*>(&kcrypt32G_CertEnumCertificateContextProperties));
    e("CertEnumPhysicalStore", reinterpret_cast<void*>(&kcrypt32G_CertEnumPhysicalStore));
    e("CertEnumSubjectInSortedCTL", reinterpret_cast<void*>(&kcrypt32G_CertEnumSubjectInSortedCTL));
    e("CertEnumSystemStore", reinterpret_cast<void*>(&kcrypt32G_CertEnumSystemStore));
    e("CertEnumSystemStoreLocation", reinterpret_cast<void*>(&kcrypt32G_CertEnumSystemStoreLocation));
    e("CertFindAttribute", reinterpret_cast<void*>(&kcrypt32G_CertFindAttribute));
    e("CertFindCRLInStore", reinterpret_cast<void*>(&kcrypt32G_CertFindCRLInStore));
    e("CertFindCTLInStore", reinterpret_cast<void*>(&kcrypt32G_CertFindCTLInStore));
    e("CertFindCertificateInCRL", reinterpret_cast<void*>(&kcrypt32G_CertFindCertificateInCRL));
    e("CertFindChainInStore", reinterpret_cast<void*>(&kcrypt32G_CertFindChainInStore));
    e("CertFindExtension", reinterpret_cast<void*>(&kcrypt32G_CertFindExtension));
    e("CertFindRDNAttr", reinterpret_cast<void*>(&kcrypt32G_CertFindRDNAttr));
    e("CertFindSubjectInCTL", reinterpret_cast<void*>(&kcrypt32G_CertFindSubjectInCTL));
    e("CertFindSubjectInSortedCTL", reinterpret_cast<void*>(&kcrypt32G_CertFindSubjectInSortedCTL));
    e("CertFreeCRLContext", reinterpret_cast<void*>(&kcrypt32G_CertFreeCRLContext));
    e("CertFreeCTLContext", reinterpret_cast<void*>(&kcrypt32G_CertFreeCTLContext));
    e("CertFreeCertificateChain", reinterpret_cast<void*>(&kcrypt32G_CertFreeCertificateChain));
    e("CertFreeCertificateChainEngine", reinterpret_cast<void*>(&kcrypt32G_CertFreeCertificateChainEngine));
    e("CertFreeCertificateChainList", reinterpret_cast<void*>(&kcrypt32G_CertFreeCertificateChainList));
    e("CertFreeServerOcspResponseContext", reinterpret_cast<void*>(&kcrypt32G_CertFreeServerOcspResponseContext));
    e("CertGetCRLContextProperty", reinterpret_cast<void*>(&kcrypt32G_CertGetCRLContextProperty));
    e("CertGetCRLFromStore", reinterpret_cast<void*>(&kcrypt32G_CertGetCRLFromStore));
    e("CertGetCTLContextProperty", reinterpret_cast<void*>(&kcrypt32G_CertGetCTLContextProperty));
    e("CertGetCertificateChain", reinterpret_cast<void*>(&kcrypt32G_CertGetCertificateChain));
    e("CertGetEnhancedKeyUsage", reinterpret_cast<void*>(&kcrypt32G_CertGetEnhancedKeyUsage));
    e("CertGetIssuerCertificateFromStore", reinterpret_cast<void*>(&kcrypt32G_CertGetIssuerCertificateFromStore));
    e("CertGetServerOcspResponseContext", reinterpret_cast<void*>(&kcrypt32G_CertGetServerOcspResponseContext));
    e("CertGetStoreProperty", reinterpret_cast<void*>(&kcrypt32G_CertGetStoreProperty));
    e("CertGetSubjectCertificateFromStore", reinterpret_cast<void*>(&kcrypt32G_CertGetSubjectCertificateFromStore));
    e("CertGetValidUsages", reinterpret_cast<void*>(&kcrypt32G_CertGetValidUsages));
    e("CertIsRDNAttrsInCertificateName", reinterpret_cast<void*>(&kcrypt32G_CertIsRDNAttrsInCertificateName));
    e("CertIsStrongHashToSign", reinterpret_cast<void*>(&kcrypt32G_CertIsStrongHashToSign));
    e("CertIsValidCRLForCertificate", reinterpret_cast<void*>(&kcrypt32G_CertIsValidCRLForCertificate));
    e("CertIsWeakHash", reinterpret_cast<void*>(&kcrypt32G_CertIsWeakHash));
    e("CertOIDToAlgId", reinterpret_cast<void*>(&kcrypt32G_CertOIDToAlgId));
    e("CertOpenServerOcspResponse", reinterpret_cast<void*>(&kcrypt32G_CertOpenServerOcspResponse));
    e("CertRDNValueToStrA", reinterpret_cast<void*>(&kcrypt32G_CertRDNValueToStrA));
    e("CertRDNValueToStrW", reinterpret_cast<void*>(&kcrypt32G_CertRDNValueToStrW));
    e("CertRegisterPhysicalStore", reinterpret_cast<void*>(&kcrypt32G_CertRegisterPhysicalStore));
    e("CertRegisterSystemStore", reinterpret_cast<void*>(&kcrypt32G_CertRegisterSystemStore));
    e("CertRemoveEnhancedKeyUsageIdentifier", reinterpret_cast<void*>(&kcrypt32G_CertRemoveEnhancedKeyUsageIdentifier));
    e("CertRemoveStoreFromCollection", reinterpret_cast<void*>(&kcrypt32G_CertRemoveStoreFromCollection));
    e("CertResyncCertificateChainEngine", reinterpret_cast<void*>(&kcrypt32G_CertResyncCertificateChainEngine));
    e("CertRetrieveLogoOrBiometricInfo", reinterpret_cast<void*>(&kcrypt32G_CertRetrieveLogoOrBiometricInfo));
    e("CertSaveStore", reinterpret_cast<void*>(&kcrypt32G_CertSaveStore));
    e("CertSelectCertificateChains", reinterpret_cast<void*>(&kcrypt32G_CertSelectCertificateChains));
    e("CertSerializeCRLStoreElement", reinterpret_cast<void*>(&kcrypt32G_CertSerializeCRLStoreElement));
    e("CertSerializeCTLStoreElement", reinterpret_cast<void*>(&kcrypt32G_CertSerializeCTLStoreElement));
    e("CertSerializeCertificateStoreElement", reinterpret_cast<void*>(&kcrypt32G_CertSerializeCertificateStoreElement));
    e("CertSetCRLContextProperty", reinterpret_cast<void*>(&kcrypt32G_CertSetCRLContextProperty));
    e("CertSetCTLContextProperty", reinterpret_cast<void*>(&kcrypt32G_CertSetCTLContextProperty));
    e("CertSetCertificateContextPropertiesFromCTLEntry", reinterpret_cast<void*>(&kcrypt32G_CertSetCertificateContextPropertiesFromCTLEntry));
    e("CertSetCertificateContextProperty", reinterpret_cast<void*>(&kcrypt32G_CertSetCertificateContextProperty));
    e("CertSetEnhancedKeyUsage", reinterpret_cast<void*>(&kcrypt32G_CertSetEnhancedKeyUsage));
    e("CertSetStoreProperty", reinterpret_cast<void*>(&kcrypt32G_CertSetStoreProperty));
    e("CertStrToNameA", reinterpret_cast<void*>(&kcrypt32G_CertStrToNameA));
    e("CertStrToNameW", reinterpret_cast<void*>(&kcrypt32G_CertStrToNameW));
    e("CertUnregisterPhysicalStore", reinterpret_cast<void*>(&kcrypt32G_CertUnregisterPhysicalStore));
    e("CertUnregisterSystemStore", reinterpret_cast<void*>(&kcrypt32G_CertUnregisterSystemStore));
    e("CertVerifyCRLRevocation", reinterpret_cast<void*>(&kcrypt32G_CertVerifyCRLRevocation));
    e("CertVerifyCRLTimeValidity", reinterpret_cast<void*>(&kcrypt32G_CertVerifyCRLTimeValidity));
    e("CertVerifyCTLUsage", reinterpret_cast<void*>(&kcrypt32G_CertVerifyCTLUsage));
    e("CertVerifyCertificateChainPolicy", reinterpret_cast<void*>(&kcrypt32G_CertVerifyCertificateChainPolicy));
    e("CertVerifyRevocation", reinterpret_cast<void*>(&kcrypt32G_CertVerifyRevocation));
    e("CryptAcquireCertificatePrivateKey", reinterpret_cast<void*>(&kcrypt32G_CryptAcquireCertificatePrivateKey));
    e("CryptCloseAsyncHandle", reinterpret_cast<void*>(&kcrypt32G_CryptCloseAsyncHandle));
    e("CryptCreateAsyncHandle", reinterpret_cast<void*>(&kcrypt32G_CryptCreateAsyncHandle));
    e("CryptCreateKeyIdentifierFromCSP", reinterpret_cast<void*>(&kcrypt32G_CryptCreateKeyIdentifierFromCSP));
    e("CryptDecodeMessage", reinterpret_cast<void*>(&kcrypt32G_CryptDecodeMessage));
    e("CryptDecodeObjectEx", reinterpret_cast<void*>(&kcrypt32G_CryptDecodeObjectEx));
    e("CryptDecryptAndVerifyMessageSignature", reinterpret_cast<void*>(&kcrypt32G_CryptDecryptAndVerifyMessageSignature));
    e("CryptDecryptMessage", reinterpret_cast<void*>(&kcrypt32G_CryptDecryptMessage));
    e("CryptEncodeObjectEx", reinterpret_cast<void*>(&kcrypt32G_CryptEncodeObjectEx));
    e("CryptEncryptMessage", reinterpret_cast<void*>(&kcrypt32G_CryptEncryptMessage));
    e("CryptEnumKeyIdentifierProperties", reinterpret_cast<void*>(&kcrypt32G_CryptEnumKeyIdentifierProperties));
    e("CryptEnumOIDFunction", reinterpret_cast<void*>(&kcrypt32G_CryptEnumOIDFunction));
    e("CryptEnumOIDInfo", reinterpret_cast<void*>(&kcrypt32G_CryptEnumOIDInfo));
    e("CryptExportPKCS8", reinterpret_cast<void*>(&kcrypt32G_CryptExportPKCS8));
    e("CryptExportPublicKeyInfo", reinterpret_cast<void*>(&kcrypt32G_CryptExportPublicKeyInfo));
    e("CryptExportPublicKeyInfoEx", reinterpret_cast<void*>(&kcrypt32G_CryptExportPublicKeyInfoEx));
    e("CryptExportPublicKeyInfoFromBCryptKeyHandle", reinterpret_cast<void*>(&kcrypt32G_CryptExportPublicKeyInfoFromBCryptKeyHandle));
    e("CryptFindCertificateKeyProvInfo", reinterpret_cast<void*>(&kcrypt32G_CryptFindCertificateKeyProvInfo));
    e("CryptFindLocalizedName", reinterpret_cast<void*>(&kcrypt32G_CryptFindLocalizedName));
    e("CryptFindOIDInfo", reinterpret_cast<void*>(&kcrypt32G_CryptFindOIDInfo));
    e("CryptFreeOIDFunctionAddress", reinterpret_cast<void*>(&kcrypt32G_CryptFreeOIDFunctionAddress));
    e("CryptGetAsyncParam", reinterpret_cast<void*>(&kcrypt32G_CryptGetAsyncParam));
    e("CryptGetDefaultOIDDllList", reinterpret_cast<void*>(&kcrypt32G_CryptGetDefaultOIDDllList));
    e("CryptGetDefaultOIDFunctionAddress", reinterpret_cast<void*>(&kcrypt32G_CryptGetDefaultOIDFunctionAddress));
    e("CryptGetKeyIdentifierProperty", reinterpret_cast<void*>(&kcrypt32G_CryptGetKeyIdentifierProperty));
    e("CryptGetMessageCertificates", reinterpret_cast<void*>(&kcrypt32G_CryptGetMessageCertificates));
    e("CryptGetMessageSignerCount", reinterpret_cast<void*>(&kcrypt32G_CryptGetMessageSignerCount));
    e("CryptGetOIDFunctionAddress", reinterpret_cast<void*>(&kcrypt32G_CryptGetOIDFunctionAddress));
    e("CryptGetOIDFunctionValue", reinterpret_cast<void*>(&kcrypt32G_CryptGetOIDFunctionValue));
    e("CryptHashCertificate", reinterpret_cast<void*>(&kcrypt32G_CryptHashCertificate));
    e("CryptHashCertificate2", reinterpret_cast<void*>(&kcrypt32G_CryptHashCertificate2));
    e("CryptHashMessage", reinterpret_cast<void*>(&kcrypt32G_CryptHashMessage));
    e("CryptHashPublicKeyInfo", reinterpret_cast<void*>(&kcrypt32G_CryptHashPublicKeyInfo));
    e("CryptHashToBeSigned", reinterpret_cast<void*>(&kcrypt32G_CryptHashToBeSigned));
    e("CryptImportPKCS8", reinterpret_cast<void*>(&kcrypt32G_CryptImportPKCS8));
    e("CryptImportPublicKeyInfo", reinterpret_cast<void*>(&kcrypt32G_CryptImportPublicKeyInfo));
    e("CryptImportPublicKeyInfoEx", reinterpret_cast<void*>(&kcrypt32G_CryptImportPublicKeyInfoEx));
    e("CryptImportPublicKeyInfoEx2", reinterpret_cast<void*>(&kcrypt32G_CryptImportPublicKeyInfoEx2));
    e("CryptInitOIDFunctionSet", reinterpret_cast<void*>(&kcrypt32G_CryptInitOIDFunctionSet));
    e("CryptInstallDefaultContext", reinterpret_cast<void*>(&kcrypt32G_CryptInstallDefaultContext));
    e("CryptInstallOIDFunctionAddress", reinterpret_cast<void*>(&kcrypt32G_CryptInstallOIDFunctionAddress));
    e("CryptMsgCalculateEncodedLength", reinterpret_cast<void*>(&kcrypt32G_CryptMsgCalculateEncodedLength));
    e("CryptMsgCountersign", reinterpret_cast<void*>(&kcrypt32G_CryptMsgCountersign));
    e("CryptMsgCountersignEncoded", reinterpret_cast<void*>(&kcrypt32G_CryptMsgCountersignEncoded));
    e("CryptMsgDuplicate", reinterpret_cast<void*>(&kcrypt32G_CryptMsgDuplicate));
    e("CryptMsgEncodeAndSignCTL", reinterpret_cast<void*>(&kcrypt32G_CryptMsgEncodeAndSignCTL));
    e("CryptMsgGetAndVerifySigner", reinterpret_cast<void*>(&kcrypt32G_CryptMsgGetAndVerifySigner));
    e("CryptMsgSignCTL", reinterpret_cast<void*>(&kcrypt32G_CryptMsgSignCTL));
    e("CryptMsgVerifyCountersignatureEncoded", reinterpret_cast<void*>(&kcrypt32G_CryptMsgVerifyCountersignatureEncoded));
    e("CryptMsgVerifyCountersignatureEncodedEx", reinterpret_cast<void*>(&kcrypt32G_CryptMsgVerifyCountersignatureEncodedEx));
    e("CryptProtectMemory", reinterpret_cast<void*>(&kcrypt32G_CryptProtectMemory));
    e("CryptRegisterDefaultOIDFunction", reinterpret_cast<void*>(&kcrypt32G_CryptRegisterDefaultOIDFunction));
    e("CryptRegisterOIDFunction", reinterpret_cast<void*>(&kcrypt32G_CryptRegisterOIDFunction));
    e("CryptRegisterOIDInfo", reinterpret_cast<void*>(&kcrypt32G_CryptRegisterOIDInfo));
    e("CryptRetrieveTimeStamp", reinterpret_cast<void*>(&kcrypt32G_CryptRetrieveTimeStamp));
    e("CryptSetAsyncParam", reinterpret_cast<void*>(&kcrypt32G_CryptSetAsyncParam));
    e("CryptSetKeyIdentifierProperty", reinterpret_cast<void*>(&kcrypt32G_CryptSetKeyIdentifierProperty));
    e("CryptSetOIDFunctionValue", reinterpret_cast<void*>(&kcrypt32G_CryptSetOIDFunctionValue));
    e("CryptSignAndEncodeCertificate", reinterpret_cast<void*>(&kcrypt32G_CryptSignAndEncodeCertificate));
    e("CryptSignAndEncryptMessage", reinterpret_cast<void*>(&kcrypt32G_CryptSignAndEncryptMessage));
    e("CryptSignCertificate", reinterpret_cast<void*>(&kcrypt32G_CryptSignCertificate));
    e("CryptSignMessage", reinterpret_cast<void*>(&kcrypt32G_CryptSignMessage));
    e("CryptSignMessageWithKey", reinterpret_cast<void*>(&kcrypt32G_CryptSignMessageWithKey));
    e("CryptUninstallDefaultContext", reinterpret_cast<void*>(&kcrypt32G_CryptUninstallDefaultContext));
    e("CryptUnprotectMemory", reinterpret_cast<void*>(&kcrypt32G_CryptUnprotectMemory));
    e("CryptUnregisterDefaultOIDFunction", reinterpret_cast<void*>(&kcrypt32G_CryptUnregisterDefaultOIDFunction));
    e("CryptUnregisterOIDFunction", reinterpret_cast<void*>(&kcrypt32G_CryptUnregisterOIDFunction));
    e("CryptUnregisterOIDInfo", reinterpret_cast<void*>(&kcrypt32G_CryptUnregisterOIDInfo));
    e("CryptVerifyCertificateSignature", reinterpret_cast<void*>(&kcrypt32G_CryptVerifyCertificateSignature));
    e("CryptVerifyCertificateSignatureEx", reinterpret_cast<void*>(&kcrypt32G_CryptVerifyCertificateSignatureEx));
    e("CryptVerifyDetachedMessageHash", reinterpret_cast<void*>(&kcrypt32G_CryptVerifyDetachedMessageHash));
    e("CryptVerifyDetachedMessageSignature", reinterpret_cast<void*>(&kcrypt32G_CryptVerifyDetachedMessageSignature));
    e("CryptVerifyMessageHash", reinterpret_cast<void*>(&kcrypt32G_CryptVerifyMessageHash));
    e("CryptVerifyMessageSignature", reinterpret_cast<void*>(&kcrypt32G_CryptVerifyMessageSignature));
    e("CryptVerifyMessageSignatureWithKey", reinterpret_cast<void*>(&kcrypt32G_CryptVerifyMessageSignatureWithKey));
    e("CryptVerifyTimeStampSignature", reinterpret_cast<void*>(&kcrypt32G_CryptVerifyTimeStampSignature));
    e("PFXExportCertStore", reinterpret_cast<void*>(&kcrypt32G_PFXExportCertStore));
    e("PFXExportCertStoreEx", reinterpret_cast<void*>(&kcrypt32G_PFXExportCertStoreEx));
    e("PFXImportCertStore", reinterpret_cast<void*>(&kcrypt32G_PFXImportCertStore));
    e("PFXIsPFXBlob", reinterpret_cast<void*>(&kcrypt32G_PFXIsPFXBlob));
    e("PFXVerifyPassword", reinterpret_cast<void*>(&kcrypt32G_PFXVerifyPassword));
}
}  // namespace occ::runtime::winabi

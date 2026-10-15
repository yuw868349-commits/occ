// The BCRYPT surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptAddContextFunction(std::uint32_t dwTable, const char16_t* pszContext, std::uint32_t dwInterface, const char16_t* pszFunction, std::uint32_t dwPosition) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwTable);
    static_cast<void>(pszContext);
    static_cast<void>(dwInterface);
    static_cast<void>(pszFunction);
    static_cast<void>(dwPosition);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptConfigureContext(std::uint32_t dwTable, const char16_t* pszContext, std::uint64_t pConfig) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwTable);
    static_cast<void>(pszContext);
    static_cast<void>(pConfig);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptConfigureContextFunction(std::uint32_t dwTable, const char16_t* pszContext, std::uint32_t dwInterface, const char16_t* pszFunction, std::uint64_t pConfig) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwTable);
    static_cast<void>(pszContext);
    static_cast<void>(dwInterface);
    static_cast<void>(pszFunction);
    static_cast<void>(pConfig);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptCreateContext(std::uint32_t dwTable, const char16_t* pszContext, std::uint64_t pConfig) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwTable);
    static_cast<void>(pszContext);
    static_cast<void>(pConfig);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptDecrypt(void* hKey, std::uint8_t* pbInput, std::uint32_t cbInput, void* pPaddingInfo, std::uint8_t* pbIV, std::uint32_t cbIV, std::uint8_t* pbOutput, std::uint32_t cbOutput, std::uint32_t* pcbResult, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hKey);
    static_cast<void>(pbInput);
    static_cast<void>(cbInput);
    static_cast<void>(pPaddingInfo);
    static_cast<void>(pbIV);
    static_cast<void>(cbIV);
    static_cast<void>(pbOutput);
    static_cast<void>(cbOutput);
    static_cast<void>(pcbResult);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptDeleteContext(std::uint32_t dwTable, const char16_t* pszContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwTable);
    static_cast<void>(pszContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptDeriveKey(void* hSharedSecret, const char16_t* pwszKDF, void* pParameterList, std::uint8_t* pbDerivedKey, std::uint32_t cbDerivedKey, std::uint32_t* pcbResult, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hSharedSecret);
    static_cast<void>(pwszKDF);
    static_cast<void>(pParameterList);
    static_cast<void>(pbDerivedKey);
    static_cast<void>(cbDerivedKey);
    static_cast<void>(pcbResult);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptDeriveKeyCapi(void* hHash, void* hTargetAlg, std::uint8_t* pbDerivedKey, std::uint32_t cbDerivedKey, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hHash);
    static_cast<void>(hTargetAlg);
    static_cast<void>(pbDerivedKey);
    static_cast<void>(cbDerivedKey);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptDeriveKeyPBKDF2(void* hPrf, std::uint8_t* pbPassword, std::uint32_t cbPassword, std::uint8_t* pbSalt, std::uint32_t cbSalt, std::uint64_t cIterations, std::uint8_t* pbDerivedKey, std::uint32_t cbDerivedKey, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hPrf);
    static_cast<void>(pbPassword);
    static_cast<void>(cbPassword);
    static_cast<void>(pbSalt);
    static_cast<void>(cbSalt);
    static_cast<void>(cIterations);
    static_cast<void>(pbDerivedKey);
    static_cast<void>(cbDerivedKey);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptDestroyKey(void* hKey) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hKey);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptDestroySecret(void* hSecret) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hSecret);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptDuplicateHash(void* hHash, void* phNewHash, std::uint8_t* pbHashObject, std::uint32_t cbHashObject, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hHash);
    static_cast<void>(phNewHash);
    static_cast<void>(pbHashObject);
    static_cast<void>(cbHashObject);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptDuplicateKey(void* hKey, void* phNewKey, std::uint8_t* pbKeyObject, std::uint32_t cbKeyObject, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hKey);
    static_cast<void>(phNewKey);
    static_cast<void>(pbKeyObject);
    static_cast<void>(cbKeyObject);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptEncrypt(void* hKey, std::uint8_t* pbInput, std::uint32_t cbInput, void* pPaddingInfo, std::uint8_t* pbIV, std::uint32_t cbIV, std::uint8_t* pbOutput, std::uint32_t cbOutput, std::uint32_t* pcbResult, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hKey);
    static_cast<void>(pbInput);
    static_cast<void>(cbInput);
    static_cast<void>(pPaddingInfo);
    static_cast<void>(pbIV);
    static_cast<void>(cbIV);
    static_cast<void>(pbOutput);
    static_cast<void>(cbOutput);
    static_cast<void>(pcbResult);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptEnumAlgorithms(std::uint32_t dwAlgOperations, std::uint32_t* pAlgCount, void** ppAlgList, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwAlgOperations);
    static_cast<void>(pAlgCount);
    static_cast<void>(ppAlgList);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptEnumContextFunctionProviders(std::uint32_t dwTable, const char16_t* pszContext, std::uint32_t dwInterface, const char16_t* pszFunction, std::uint32_t* pcbBuffer, void* ppBuffer) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwTable);
    static_cast<void>(pszContext);
    static_cast<void>(dwInterface);
    static_cast<void>(pszFunction);
    static_cast<void>(pcbBuffer);
    static_cast<void>(ppBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptEnumContextFunctions(std::uint32_t dwTable, const char16_t* pszContext, std::uint32_t dwInterface, std::uint32_t* pcbBuffer, void* ppBuffer) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwTable);
    static_cast<void>(pszContext);
    static_cast<void>(dwInterface);
    static_cast<void>(pcbBuffer);
    static_cast<void>(ppBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptEnumContexts(std::uint32_t dwTable, std::uint32_t* pcbBuffer, void* ppBuffer) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwTable);
    static_cast<void>(pcbBuffer);
    static_cast<void>(ppBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptEnumProviders(const char16_t* pszAlgId, std::uint32_t* pImplCount, void** ppImplList, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pszAlgId);
    static_cast<void>(pImplCount);
    static_cast<void>(ppImplList);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptEnumRegisteredProviders(std::uint32_t* pcbBuffer, void* ppBuffer) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pcbBuffer);
    static_cast<void>(ppBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptExportKey(void* hKey, void* hExportKey, const char16_t* pszBlobType, std::uint8_t* pbOutput, std::uint32_t cbOutput, std::uint32_t* pcbResult, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hKey);
    static_cast<void>(hExportKey);
    static_cast<void>(pszBlobType);
    static_cast<void>(pbOutput);
    static_cast<void>(cbOutput);
    static_cast<void>(pcbResult);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptFinalizeKeyPair(void* hKey, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hKey);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kbcryptG_BCryptFreeBuffer(void* pvBuffer) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pvBuffer);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptGenerateKeyPair(void* hAlgorithm, void* phKey, std::uint32_t dwLength, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hAlgorithm);
    static_cast<void>(phKey);
    static_cast<void>(dwLength);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptGenerateSymmetricKey(void* hAlgorithm, void* phKey, std::uint8_t* pbKeyObject, std::uint32_t cbKeyObject, std::uint8_t* pbSecret, std::uint32_t cbSecret, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hAlgorithm);
    static_cast<void>(phKey);
    static_cast<void>(pbKeyObject);
    static_cast<void>(cbKeyObject);
    static_cast<void>(pbSecret);
    static_cast<void>(cbSecret);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptGetFipsAlgorithmMode(std::uint8_t* pfEnabled) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pfEnabled);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptHash(void* hAlgorithm, std::uint8_t* pbSecret, std::uint32_t cbSecret, std::uint8_t* pbInput, std::uint32_t cbInput, std::uint8_t* pbOutput, std::uint32_t cbOutput) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hAlgorithm);
    static_cast<void>(pbSecret);
    static_cast<void>(cbSecret);
    static_cast<void>(pbInput);
    static_cast<void>(cbInput);
    static_cast<void>(pbOutput);
    static_cast<void>(cbOutput);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptImportKey(void* hAlgorithm, void* hImportKey, const char16_t* pszBlobType, void* phKey, std::uint8_t* pbKeyObject, std::uint32_t cbKeyObject, std::uint8_t* pbInput, std::uint32_t cbInput, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hAlgorithm);
    static_cast<void>(hImportKey);
    static_cast<void>(pszBlobType);
    static_cast<void>(phKey);
    static_cast<void>(pbKeyObject);
    static_cast<void>(cbKeyObject);
    static_cast<void>(pbInput);
    static_cast<void>(cbInput);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptImportKeyPair(void* hAlgorithm, void* hImportKey, const char16_t* pszBlobType, void* phKey, std::uint8_t* pbInput, std::uint32_t cbInput, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hAlgorithm);
    static_cast<void>(hImportKey);
    static_cast<void>(pszBlobType);
    static_cast<void>(phKey);
    static_cast<void>(pbInput);
    static_cast<void>(cbInput);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptKeyDerivation(void* hKey, void* pParameterList, std::uint8_t* pbDerivedKey, std::uint32_t cbDerivedKey, std::uint32_t* pcbResult, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hKey);
    static_cast<void>(pParameterList);
    static_cast<void>(pbDerivedKey);
    static_cast<void>(cbDerivedKey);
    static_cast<void>(pcbResult);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptQueryContextConfiguration(std::uint32_t dwTable, const char16_t* pszContext, std::uint32_t* pcbBuffer, void* ppBuffer) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwTable);
    static_cast<void>(pszContext);
    static_cast<void>(pcbBuffer);
    static_cast<void>(ppBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptQueryContextFunctionConfiguration(std::uint32_t dwTable, const char16_t* pszContext, std::uint32_t dwInterface, const char16_t* pszFunction, std::uint32_t* pcbBuffer, void* ppBuffer) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwTable);
    static_cast<void>(pszContext);
    static_cast<void>(dwInterface);
    static_cast<void>(pszFunction);
    static_cast<void>(pcbBuffer);
    static_cast<void>(ppBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptQueryContextFunctionProperty(std::uint32_t dwTable, const char16_t* pszContext, std::uint32_t dwInterface, const char16_t* pszFunction, const char16_t* pszProperty, std::uint32_t* pcbValue, std::uint8_t** ppbValue) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwTable);
    static_cast<void>(pszContext);
    static_cast<void>(dwInterface);
    static_cast<void>(pszFunction);
    static_cast<void>(pszProperty);
    static_cast<void>(pcbValue);
    static_cast<void>(ppbValue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptQueryProviderRegistration(const char16_t* pszProvider, std::uint32_t dwMode, std::uint32_t dwInterface, std::uint32_t* pcbBuffer, void* ppBuffer) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pszProvider);
    static_cast<void>(dwMode);
    static_cast<void>(dwInterface);
    static_cast<void>(pcbBuffer);
    static_cast<void>(ppBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptRegisterConfigChangeNotify(void* phEvent) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(phEvent);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptRemoveContextFunction(std::uint32_t dwTable, const char16_t* pszContext, std::uint32_t dwInterface, const char16_t* pszFunction) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwTable);
    static_cast<void>(pszContext);
    static_cast<void>(dwInterface);
    static_cast<void>(pszFunction);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptResolveProviders(const char16_t* pszContext, std::uint32_t dwInterface, const char16_t* pszFunction, const char16_t* pszProvider, std::uint32_t dwMode, std::uint32_t dwFlags, std::uint32_t* pcbBuffer, void* ppBuffer) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pszContext);
    static_cast<void>(dwInterface);
    static_cast<void>(pszFunction);
    static_cast<void>(pszProvider);
    static_cast<void>(dwMode);
    static_cast<void>(dwFlags);
    static_cast<void>(pcbBuffer);
    static_cast<void>(ppBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptSecretAgreement(void* hPrivKey, void* hPubKey, void* phAgreedSecret, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hPrivKey);
    static_cast<void>(hPubKey);
    static_cast<void>(phAgreedSecret);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptSetContextFunctionProperty(std::uint32_t dwTable, const char16_t* pszContext, std::uint32_t dwInterface, const char16_t* pszFunction, const char16_t* pszProperty, std::uint32_t cbValue, std::uint8_t* pbValue) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwTable);
    static_cast<void>(pszContext);
    static_cast<void>(dwInterface);
    static_cast<void>(pszFunction);
    static_cast<void>(pszProperty);
    static_cast<void>(cbValue);
    static_cast<void>(pbValue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptSetProperty(std::uint64_t hObject, const char16_t* pszProperty, std::uint8_t* pbInput, std::uint32_t cbInput, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hObject);
    static_cast<void>(pszProperty);
    static_cast<void>(pbInput);
    static_cast<void>(cbInput);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptSignHash(void* hKey, void* pPaddingInfo, std::uint8_t* pbInput, std::uint32_t cbInput, std::uint8_t* pbOutput, std::uint32_t cbOutput, std::uint32_t* pcbResult, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hKey);
    static_cast<void>(pPaddingInfo);
    static_cast<void>(pbInput);
    static_cast<void>(cbInput);
    static_cast<void>(pbOutput);
    static_cast<void>(cbOutput);
    static_cast<void>(pcbResult);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptUnregisterConfigChangeNotify(void* hEvent) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hEvent);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kbcryptG_BCryptVerifySignature(void* hKey, void* pPaddingInfo, std::uint8_t* pbHash, std::uint32_t cbHash, std::uint8_t* pbSignature, std::uint32_t cbSignature, std::uint32_t dwFlags) noexcept {
    // Refused: the trust verification provider.
    //
    // verifying a signature needs a trust provider and a certificate store
    // that the system services maintain
    static_cast<void>(hKey);
    static_cast<void>(pPaddingInfo);
    static_cast<void>(pbHash);
    static_cast<void>(cbHash);
    static_cast<void>(pbSignature);
    static_cast<void>(cbSignature);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_bcrypt(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("BCryptAddContextFunction", reinterpret_cast<void*>(&kbcryptG_BCryptAddContextFunction));
    e("BCryptConfigureContext", reinterpret_cast<void*>(&kbcryptG_BCryptConfigureContext));
    e("BCryptConfigureContextFunction", reinterpret_cast<void*>(&kbcryptG_BCryptConfigureContextFunction));
    e("BCryptCreateContext", reinterpret_cast<void*>(&kbcryptG_BCryptCreateContext));
    e("BCryptDecrypt", reinterpret_cast<void*>(&kbcryptG_BCryptDecrypt));
    e("BCryptDeleteContext", reinterpret_cast<void*>(&kbcryptG_BCryptDeleteContext));
    e("BCryptDeriveKey", reinterpret_cast<void*>(&kbcryptG_BCryptDeriveKey));
    e("BCryptDeriveKeyCapi", reinterpret_cast<void*>(&kbcryptG_BCryptDeriveKeyCapi));
    e("BCryptDeriveKeyPBKDF2", reinterpret_cast<void*>(&kbcryptG_BCryptDeriveKeyPBKDF2));
    e("BCryptDestroyKey", reinterpret_cast<void*>(&kbcryptG_BCryptDestroyKey));
    e("BCryptDestroySecret", reinterpret_cast<void*>(&kbcryptG_BCryptDestroySecret));
    e("BCryptDuplicateHash", reinterpret_cast<void*>(&kbcryptG_BCryptDuplicateHash));
    e("BCryptDuplicateKey", reinterpret_cast<void*>(&kbcryptG_BCryptDuplicateKey));
    e("BCryptEncrypt", reinterpret_cast<void*>(&kbcryptG_BCryptEncrypt));
    e("BCryptEnumAlgorithms", reinterpret_cast<void*>(&kbcryptG_BCryptEnumAlgorithms));
    e("BCryptEnumContextFunctionProviders", reinterpret_cast<void*>(&kbcryptG_BCryptEnumContextFunctionProviders));
    e("BCryptEnumContextFunctions", reinterpret_cast<void*>(&kbcryptG_BCryptEnumContextFunctions));
    e("BCryptEnumContexts", reinterpret_cast<void*>(&kbcryptG_BCryptEnumContexts));
    e("BCryptEnumProviders", reinterpret_cast<void*>(&kbcryptG_BCryptEnumProviders));
    e("BCryptEnumRegisteredProviders", reinterpret_cast<void*>(&kbcryptG_BCryptEnumRegisteredProviders));
    e("BCryptExportKey", reinterpret_cast<void*>(&kbcryptG_BCryptExportKey));
    e("BCryptFinalizeKeyPair", reinterpret_cast<void*>(&kbcryptG_BCryptFinalizeKeyPair));
    e("BCryptFreeBuffer", reinterpret_cast<void*>(&kbcryptG_BCryptFreeBuffer));
    e("BCryptGenerateKeyPair", reinterpret_cast<void*>(&kbcryptG_BCryptGenerateKeyPair));
    e("BCryptGenerateSymmetricKey", reinterpret_cast<void*>(&kbcryptG_BCryptGenerateSymmetricKey));
    e("BCryptGetFipsAlgorithmMode", reinterpret_cast<void*>(&kbcryptG_BCryptGetFipsAlgorithmMode));
    e("BCryptHash", reinterpret_cast<void*>(&kbcryptG_BCryptHash));
    e("BCryptImportKey", reinterpret_cast<void*>(&kbcryptG_BCryptImportKey));
    e("BCryptImportKeyPair", reinterpret_cast<void*>(&kbcryptG_BCryptImportKeyPair));
    e("BCryptKeyDerivation", reinterpret_cast<void*>(&kbcryptG_BCryptKeyDerivation));
    e("BCryptQueryContextConfiguration", reinterpret_cast<void*>(&kbcryptG_BCryptQueryContextConfiguration));
    e("BCryptQueryContextFunctionConfiguration", reinterpret_cast<void*>(&kbcryptG_BCryptQueryContextFunctionConfiguration));
    e("BCryptQueryContextFunctionProperty", reinterpret_cast<void*>(&kbcryptG_BCryptQueryContextFunctionProperty));
    e("BCryptQueryProviderRegistration", reinterpret_cast<void*>(&kbcryptG_BCryptQueryProviderRegistration));
    e("BCryptRegisterConfigChangeNotify", reinterpret_cast<void*>(&kbcryptG_BCryptRegisterConfigChangeNotify));
    e("BCryptRemoveContextFunction", reinterpret_cast<void*>(&kbcryptG_BCryptRemoveContextFunction));
    e("BCryptResolveProviders", reinterpret_cast<void*>(&kbcryptG_BCryptResolveProviders));
    e("BCryptSecretAgreement", reinterpret_cast<void*>(&kbcryptG_BCryptSecretAgreement));
    e("BCryptSetContextFunctionProperty", reinterpret_cast<void*>(&kbcryptG_BCryptSetContextFunctionProperty));
    e("BCryptSetProperty", reinterpret_cast<void*>(&kbcryptG_BCryptSetProperty));
    e("BCryptSignHash", reinterpret_cast<void*>(&kbcryptG_BCryptSignHash));
    e("BCryptUnregisterConfigChangeNotify", reinterpret_cast<void*>(&kbcryptG_BCryptUnregisterConfigChangeNotify));
    e("BCryptVerifySignature", reinterpret_cast<void*>(&kbcryptG_BCryptVerifySignature));
}
}  // namespace occ::runtime::winabi

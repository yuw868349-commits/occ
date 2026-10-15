// The SECUR32 surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_AddCredentialsA(void* hCredentials, void* pszPrincipal, void* pszPackage, std::uint32_t fCredentialUse, void* pAuthData, std::uint64_t pGetKeyFn, void* pvGetKeyArgument, std::uint64_t ptsExpiry) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded by the local security authority,
    // which is not present here
    static_cast<void>(hCredentials);
    static_cast<void>(pszPrincipal);
    static_cast<void>(pszPackage);
    static_cast<void>(fCredentialUse);
    static_cast<void>(pAuthData);
    static_cast<void>(pGetKeyFn);
    static_cast<void>(pvGetKeyArgument);
    static_cast<void>(ptsExpiry);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_AddCredentialsW(void* hCredentials, std::uint64_t pPrincipal, std::uint64_t pPackage, std::uint32_t fCredentialUse, void* pAuthData, std::uint64_t pGetKeyFn, void* pvGetKeyArgument, std::uint64_t ptsExpiry) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded by the local security authority,
    // which is not present here
    static_cast<void>(hCredentials);
    static_cast<void>(pPrincipal);
    static_cast<void>(pPackage);
    static_cast<void>(fCredentialUse);
    static_cast<void>(pAuthData);
    static_cast<void>(pGetKeyFn);
    static_cast<void>(pvGetKeyArgument);
    static_cast<void>(ptsExpiry);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_AddSecurityPackageA(char* pszPackageName, std::uint64_t pOptions) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded by the local security authority,
    // which is not present here
    static_cast<void>(pszPackageName);
    static_cast<void>(pOptions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_AddSecurityPackageW(char16_t* pszPackageName, std::uint64_t pOptions) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded by the local security authority,
    // which is not present here
    static_cast<void>(pszPackageName);
    static_cast<void>(pOptions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_DeleteSecurityPackageA(void* pszPackageName) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded by the local security authority,
    // which is not present here
    static_cast<void>(pszPackageName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_DeleteSecurityPackageW(void* pszPackageName) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded by the local security authority,
    // which is not present here
    static_cast<void>(pszPackageName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_ExportSecurityContext(void* phContext, std::uint32_t fFlags, std::uint64_t pPackedContext, void** pToken) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded by the local security authority,
    // which is not present here
    static_cast<void>(phContext);
    static_cast<void>(fFlags);
    static_cast<void>(pPackedContext);
    static_cast<void>(pToken);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_ImportSecurityContextA(void* pszPackage, std::uint64_t pPackedContext, void* Token, void* phContext) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded by the local security authority,
    // which is not present here
    static_cast<void>(pszPackage);
    static_cast<void>(pPackedContext);
    static_cast<void>(Token);
    static_cast<void>(phContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_ImportSecurityContextW(std::uint64_t pszPackage, std::uint64_t pPackedContext, void* Token, void* phContext) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded by the local security authority,
    // which is not present here
    static_cast<void>(pszPackage);
    static_cast<void>(pPackedContext);
    static_cast<void>(Token);
    static_cast<void>(phContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_LsaLogonUser(void* LsaHandle, std::uint64_t OriginName, std::uint64_t LogonType, std::uint32_t AuthenticationPackage, void* AuthenticationInformation, std::uint32_t AuthenticationInformationLength, void* LocalGroups, std::uint64_t SourceContext, void** ProfileBuffer, std::uint32_t* ProfileBufferLength, std::uint64_t LogonId, void** Token, std::uint64_t Quotas, std::int32_t* SubStatus) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(LsaHandle);
    static_cast<void>(OriginName);
    static_cast<void>(LogonType);
    static_cast<void>(AuthenticationPackage);
    static_cast<void>(AuthenticationInformation);
    static_cast<void>(AuthenticationInformationLength);
    static_cast<void>(LocalGroups);
    static_cast<void>(SourceContext);
    static_cast<void>(ProfileBuffer);
    static_cast<void>(ProfileBufferLength);
    static_cast<void>(LogonId);
    static_cast<void>(Token);
    static_cast<void>(Quotas);
    static_cast<void>(SubStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_LsaRegisterPolicyChangeNotification(std::uint64_t InformationClass, void* NotificationEventHandle) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(InformationClass);
    static_cast<void>(NotificationEventHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_LsaUnregisterPolicyChangeNotification(std::uint64_t InformationClass, void* NotificationEventHandle) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(InformationClass);
    static_cast<void>(NotificationEventHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_QueryCredentialsAttributesA(void* phCredential, std::uint32_t ulAttribute, void* pBuffer) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded by the local security authority,
    // which is not present here
    static_cast<void>(phCredential);
    static_cast<void>(ulAttribute);
    static_cast<void>(pBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_QueryCredentialsAttributesW(void* phCredential, std::uint32_t ulAttribute, void* pBuffer) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded by the local security authority,
    // which is not present here
    static_cast<void>(phCredential);
    static_cast<void>(ulAttribute);
    static_cast<void>(pBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_QuerySecurityContextToken(void* phContext, void* Token) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(phContext);
    static_cast<void>(Token);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_SetContextAttributesA(void* phContext, std::uint32_t ulAttribute, void* pBuffer, std::uint32_t cbBuffer) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded by the local security authority,
    // which is not present here
    static_cast<void>(phContext);
    static_cast<void>(ulAttribute);
    static_cast<void>(pBuffer);
    static_cast<void>(cbBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_SetContextAttributesW(void* phContext, std::uint32_t ulAttribute, void* pBuffer, std::uint32_t cbBuffer) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded by the local security authority,
    // which is not present here
    static_cast<void>(phContext);
    static_cast<void>(ulAttribute);
    static_cast<void>(pBuffer);
    static_cast<void>(cbBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_SetCredentialsAttributesA(void* phCredential, std::uint32_t ulAttribute, void* pBuffer, std::uint32_t cbBuffer) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded by the local security authority,
    // which is not present here
    static_cast<void>(phCredential);
    static_cast<void>(ulAttribute);
    static_cast<void>(pBuffer);
    static_cast<void>(cbBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_SetCredentialsAttributesW(void* phCredential, std::uint32_t ulAttribute, void* pBuffer, std::uint32_t cbBuffer) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded by the local security authority,
    // which is not present here
    static_cast<void>(phCredential);
    static_cast<void>(ulAttribute);
    static_cast<void>(pBuffer);
    static_cast<void>(cbBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_SspiCompareAuthIdentities(void* AuthIdentity1, void* AuthIdentity2, std::uint8_t* SameSuppliedUser, std::uint8_t* SameSuppliedIdentity) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(AuthIdentity1);
    static_cast<void>(AuthIdentity2);
    static_cast<void>(SameSuppliedUser);
    static_cast<void>(SameSuppliedIdentity);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_SspiCopyAuthIdentity(void* AuthData, void* AuthDataCopy) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(AuthData);
    static_cast<void>(AuthDataCopy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_SspiDecryptAuthIdentity(void* EncryptedAuthData) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(EncryptedAuthData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_SspiEncodeAuthIdentityAsStrings(void* pAuthIdentity, const char16_t** ppszUserName, const char16_t** ppszDomainName, const char16_t** ppszPackedCredentialsString) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(pAuthIdentity);
    static_cast<void>(ppszUserName);
    static_cast<void>(ppszDomainName);
    static_cast<void>(ppszPackedCredentialsString);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_SspiEncodeStringsAsAuthIdentity(const char16_t* pszUserName, const char16_t* pszDomainName, const char16_t* pszPackedCredentialsString, void* ppAuthIdentity) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(pszUserName);
    static_cast<void>(pszDomainName);
    static_cast<void>(pszPackedCredentialsString);
    static_cast<void>(ppAuthIdentity);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_SspiEncryptAuthIdentity(void* AuthData) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(AuthData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_SspiExcludePackage(void* AuthIdentity, const char16_t* pszPackageName, void* ppNewAuthIdentity) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(AuthIdentity);
    static_cast<void>(pszPackageName);
    static_cast<void>(ppNewAuthIdentity);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void ksecur32G_SspiFreeAuthIdentity(void* AuthData) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(AuthData);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_SspiGetTargetHostName(const char16_t* pszTargetName, char16_t** pszHostName) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(pszTargetName);
    static_cast<void>(pszHostName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t ksecur32G_SspiIsAuthIdentityEncrypted(void* EncryptedAuthData) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(EncryptedAuthData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void ksecur32G_SspiLocalFree(void* DataBuffer) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(DataBuffer);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_SspiMarshalAuthIdentity(void* AuthIdentity, std::uint32_t* AuthIdentityLength, char** AuthIdentityByteArray) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(AuthIdentity);
    static_cast<void>(AuthIdentityLength);
    static_cast<void>(AuthIdentityByteArray);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_SspiPrepareForCredRead(void* AuthIdentity, const char16_t* pszTargetName, std::uint32_t* pCredmanCredentialType, const char16_t** ppszCredmanTargetName) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(AuthIdentity);
    static_cast<void>(pszTargetName);
    static_cast<void>(pCredmanCredentialType);
    static_cast<void>(ppszCredmanTargetName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_SspiPrepareForCredWrite(void* AuthIdentity, const char16_t* pszTargetName, std::uint32_t* pCredmanCredentialType, const char16_t** ppszCredmanTargetName, const char16_t** ppszCredmanUserName, std::uint8_t** ppCredentialBlob, std::uint32_t* pCredentialBlobSize) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(AuthIdentity);
    static_cast<void>(pszTargetName);
    static_cast<void>(pCredmanCredentialType);
    static_cast<void>(ppszCredmanTargetName);
    static_cast<void>(ppszCredmanUserName);
    static_cast<void>(ppCredentialBlob);
    static_cast<void>(pCredentialBlobSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_SspiUnmarshalAuthIdentity(std::uint32_t AuthIdentityLength, char* AuthIdentityByteArray, void* ppAuthIdentity) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(AuthIdentityLength);
    static_cast<void>(AuthIdentityByteArray);
    static_cast<void>(ppAuthIdentity);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t ksecur32G_SspiValidateAuthIdentity(void* AuthData) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(AuthData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void ksecur32G_SspiZeroAuthIdentity(void* AuthData) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(AuthData);
    set_last_error(kNotImplemented);
}

}  // namespace

void add_generated_secur32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("AddCredentialsA", reinterpret_cast<void*>(&ksecur32G_AddCredentialsA));
    e("AddCredentialsW", reinterpret_cast<void*>(&ksecur32G_AddCredentialsW));
    e("AddSecurityPackageA", reinterpret_cast<void*>(&ksecur32G_AddSecurityPackageA));
    e("AddSecurityPackageW", reinterpret_cast<void*>(&ksecur32G_AddSecurityPackageW));
    e("DeleteSecurityPackageA", reinterpret_cast<void*>(&ksecur32G_DeleteSecurityPackageA));
    e("DeleteSecurityPackageW", reinterpret_cast<void*>(&ksecur32G_DeleteSecurityPackageW));
    e("ExportSecurityContext", reinterpret_cast<void*>(&ksecur32G_ExportSecurityContext));
    e("ImportSecurityContextA", reinterpret_cast<void*>(&ksecur32G_ImportSecurityContextA));
    e("ImportSecurityContextW", reinterpret_cast<void*>(&ksecur32G_ImportSecurityContextW));
    e("LsaLogonUser", reinterpret_cast<void*>(&ksecur32G_LsaLogonUser));
    e("LsaRegisterPolicyChangeNotification", reinterpret_cast<void*>(&ksecur32G_LsaRegisterPolicyChangeNotification));
    e("LsaUnregisterPolicyChangeNotification", reinterpret_cast<void*>(&ksecur32G_LsaUnregisterPolicyChangeNotification));
    e("QueryCredentialsAttributesA", reinterpret_cast<void*>(&ksecur32G_QueryCredentialsAttributesA));
    e("QueryCredentialsAttributesW", reinterpret_cast<void*>(&ksecur32G_QueryCredentialsAttributesW));
    e("QuerySecurityContextToken", reinterpret_cast<void*>(&ksecur32G_QuerySecurityContextToken));
    e("SetContextAttributesA", reinterpret_cast<void*>(&ksecur32G_SetContextAttributesA));
    e("SetContextAttributesW", reinterpret_cast<void*>(&ksecur32G_SetContextAttributesW));
    e("SetCredentialsAttributesA", reinterpret_cast<void*>(&ksecur32G_SetCredentialsAttributesA));
    e("SetCredentialsAttributesW", reinterpret_cast<void*>(&ksecur32G_SetCredentialsAttributesW));
    e("SspiCompareAuthIdentities", reinterpret_cast<void*>(&ksecur32G_SspiCompareAuthIdentities));
    e("SspiCopyAuthIdentity", reinterpret_cast<void*>(&ksecur32G_SspiCopyAuthIdentity));
    e("SspiDecryptAuthIdentity", reinterpret_cast<void*>(&ksecur32G_SspiDecryptAuthIdentity));
    e("SspiEncodeAuthIdentityAsStrings", reinterpret_cast<void*>(&ksecur32G_SspiEncodeAuthIdentityAsStrings));
    e("SspiEncodeStringsAsAuthIdentity", reinterpret_cast<void*>(&ksecur32G_SspiEncodeStringsAsAuthIdentity));
    e("SspiEncryptAuthIdentity", reinterpret_cast<void*>(&ksecur32G_SspiEncryptAuthIdentity));
    e("SspiExcludePackage", reinterpret_cast<void*>(&ksecur32G_SspiExcludePackage));
    e("SspiFreeAuthIdentity", reinterpret_cast<void*>(&ksecur32G_SspiFreeAuthIdentity));
    e("SspiGetTargetHostName", reinterpret_cast<void*>(&ksecur32G_SspiGetTargetHostName));
    e("SspiIsAuthIdentityEncrypted", reinterpret_cast<void*>(&ksecur32G_SspiIsAuthIdentityEncrypted));
    e("SspiLocalFree", reinterpret_cast<void*>(&ksecur32G_SspiLocalFree));
    e("SspiMarshalAuthIdentity", reinterpret_cast<void*>(&ksecur32G_SspiMarshalAuthIdentity));
    e("SspiPrepareForCredRead", reinterpret_cast<void*>(&ksecur32G_SspiPrepareForCredRead));
    e("SspiPrepareForCredWrite", reinterpret_cast<void*>(&ksecur32G_SspiPrepareForCredWrite));
    e("SspiUnmarshalAuthIdentity", reinterpret_cast<void*>(&ksecur32G_SspiUnmarshalAuthIdentity));
    e("SspiValidateAuthIdentity", reinterpret_cast<void*>(&ksecur32G_SspiValidateAuthIdentity));
    e("SspiZeroAuthIdentity", reinterpret_cast<void*>(&ksecur32G_SspiZeroAuthIdentity));
}
}  // namespace occ::runtime::winabi

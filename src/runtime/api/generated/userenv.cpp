// The USERENV surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_CreateAppContainerProfile(const char16_t* pszAppContainerName, const char16_t* pszDisplayName, const char16_t* pszDescription, std::uint64_t pCapabilities, std::uint32_t dwCapabilityCount, void* ppSidAppContainerSid) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(pszAppContainerName);
    static_cast<void>(pszDisplayName);
    static_cast<void>(pszDescription);
    static_cast<void>(pCapabilities);
    static_cast<void>(dwCapabilityCount);
    static_cast<void>(ppSidAppContainerSid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_CreateEnvironmentBlock(void** lpEnvironment, void* hToken, std::int32_t bInherit) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(lpEnvironment);
    static_cast<void>(hToken);
    static_cast<void>(bInherit);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_CreateProfile(const char16_t* pszUserSid, const char16_t* pszUserName, char16_t* pszProfilePath, std::uint32_t cchProfilePath) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(pszUserSid);
    static_cast<void>(pszUserName);
    static_cast<void>(pszProfilePath);
    static_cast<void>(cchProfilePath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_DeleteAppContainerProfile(const char16_t* pszAppContainerName) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(pszAppContainerName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_DeleteProfileA(const char* lpSidString, const char* lpProfilePath, const char* lpComputerName) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(lpSidString);
    static_cast<void>(lpProfilePath);
    static_cast<void>(lpComputerName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_DeleteProfileW(const char16_t* lpSidString, const char16_t* lpProfilePath, const char16_t* lpComputerName) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(lpSidString);
    static_cast<void>(lpProfilePath);
    static_cast<void>(lpComputerName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_DeriveAppContainerSidFromAppContainerName(const char16_t* pszAppContainerName, void* ppsidAppContainerSid) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pszAppContainerName);
    static_cast<void>(ppsidAppContainerSid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_DestroyEnvironmentBlock(void* lpEnvironment) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(lpEnvironment);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kuserenvG_EnterCriticalPolicySection(std::int32_t bMachine) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(bMachine);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_ExpandEnvironmentStringsForUserA(void* hToken, const char* lpSrc, char* lpDest, std::uint32_t dwSize) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy shaping it are built by the logon process
    static_cast<void>(hToken);
    static_cast<void>(lpSrc);
    static_cast<void>(lpDest);
    static_cast<void>(dwSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_ExpandEnvironmentStringsForUserW(void* hToken, const char16_t* lpSrc, char16_t* lpDest, std::uint32_t dwSize) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy shaping it are built by the logon process
    static_cast<void>(hToken);
    static_cast<void>(lpSrc);
    static_cast<void>(lpDest);
    static_cast<void>(dwSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_FreeGPOListA(std::uint64_t pGPOList) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy shaping it are built by the logon process
    static_cast<void>(pGPOList);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_FreeGPOListW(std::uint64_t pGPOList) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy shaping it are built by the logon process
    static_cast<void>(pGPOList);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuserenvG_GenerateGPNotification(std::int32_t bMachine, const char16_t* lpwszMgmtProduct, std::uint32_t dwMgmtProductOptions) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy shaping it are built by the logon process
    static_cast<void>(bMachine);
    static_cast<void>(lpwszMgmtProduct);
    static_cast<void>(dwMgmtProductOptions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_GetAllUsersProfileDirectoryA(char* lpProfileDir, std::uint32_t* lpcchSize) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(lpProfileDir);
    static_cast<void>(lpcchSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_GetAllUsersProfileDirectoryW(char16_t* lpProfileDir, std::uint32_t* lpcchSize) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(lpProfileDir);
    static_cast<void>(lpcchSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_GetAppContainerFolderPath(const char16_t* pszAppContainerSid, char16_t** ppszPath) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy shaping it are built by the logon process
    static_cast<void>(pszAppContainerSid);
    static_cast<void>(ppszPath);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_GetAppContainerRegistryLocation(std::uint32_t desiredAccess, void** phAppContainerKey) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy shaping it are built by the logon process
    static_cast<void>(desiredAccess);
    static_cast<void>(phAppContainerKey);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuserenvG_GetAppliedGPOListA(std::uint32_t dwFlags, const char* pMachineName, void* pSidUser, void* pGuidExtension, void* ppGPOList) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy shaping it are built by the logon process
    static_cast<void>(dwFlags);
    static_cast<void>(pMachineName);
    static_cast<void>(pSidUser);
    static_cast<void>(pGuidExtension);
    static_cast<void>(ppGPOList);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuserenvG_GetAppliedGPOListW(std::uint32_t dwFlags, const char16_t* pMachineName, void* pSidUser, void* pGuidExtension, void* ppGPOList) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy shaping it are built by the logon process
    static_cast<void>(dwFlags);
    static_cast<void>(pMachineName);
    static_cast<void>(pSidUser);
    static_cast<void>(pGuidExtension);
    static_cast<void>(ppGPOList);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_GetDefaultUserProfileDirectoryA(char* lpProfileDir, std::uint32_t* lpcchSize) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(lpProfileDir);
    static_cast<void>(lpcchSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_GetDefaultUserProfileDirectoryW(char16_t* lpProfileDir, std::uint32_t* lpcchSize) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(lpProfileDir);
    static_cast<void>(lpcchSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_GetGPOListA(void* hToken, const char* lpName, const char* lpHostName, const char* lpComputerName, std::uint32_t dwFlags, void* pGPOList) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy shaping it are built by the logon process
    static_cast<void>(hToken);
    static_cast<void>(lpName);
    static_cast<void>(lpHostName);
    static_cast<void>(lpComputerName);
    static_cast<void>(dwFlags);
    static_cast<void>(pGPOList);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_GetGPOListW(void* hToken, const char16_t* lpName, const char16_t* lpHostName, const char16_t* lpComputerName, std::uint32_t dwFlags, void* pGPOList) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy shaping it are built by the logon process
    static_cast<void>(hToken);
    static_cast<void>(lpName);
    static_cast<void>(lpHostName);
    static_cast<void>(lpComputerName);
    static_cast<void>(dwFlags);
    static_cast<void>(pGPOList);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_GetProfileType(std::uint32_t* dwFlags) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_GetProfilesDirectoryA(char* lpProfileDir, std::uint32_t* lpcchSize) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(lpProfileDir);
    static_cast<void>(lpcchSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_GetProfilesDirectoryW(char16_t* lpProfileDir, std::uint32_t* lpcchSize) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(lpProfileDir);
    static_cast<void>(lpcchSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_GetUserProfileDirectoryA(void* hToken, char* lpProfileDir, std::uint32_t* lpcchSize) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(hToken);
    static_cast<void>(lpProfileDir);
    static_cast<void>(lpcchSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_GetUserProfileDirectoryW(void* hToken, char16_t* lpProfileDir, std::uint32_t* lpcchSize) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(hToken);
    static_cast<void>(lpProfileDir);
    static_cast<void>(lpcchSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_LeaveCriticalPolicySection(void* hSection) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(hSection);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_LoadUserProfileA(void* hToken, std::uint64_t lpProfileInfo) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(hToken);
    static_cast<void>(lpProfileInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_LoadUserProfileW(void* hToken, std::uint64_t lpProfileInfo) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(hToken);
    static_cast<void>(lpProfileInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuserenvG_ProcessGroupPolicyCompleted(std::uint64_t extensionId, std::uint64_t pAsyncHandle, std::uint32_t dwStatus) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(extensionId);
    static_cast<void>(pAsyncHandle);
    static_cast<void>(dwStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kuserenvG_ProcessGroupPolicyCompletedEx(std::uint64_t extensionId, std::uint64_t pAsyncHandle, std::uint32_t dwStatus, std::int32_t RsopStatus) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(extensionId);
    static_cast<void>(pAsyncHandle);
    static_cast<void>(dwStatus);
    static_cast<void>(RsopStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_RefreshPolicy(std::int32_t bMachine) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(bMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_RefreshPolicyEx(std::int32_t bMachine, std::uint32_t dwOptions) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(bMachine);
    static_cast<void>(dwOptions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_RegisterGPNotification(void* hEvent, std::int32_t bMachine) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy shaping it are built by the logon process
    static_cast<void>(hEvent);
    static_cast<void>(bMachine);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_RsopAccessCheckByType(void* pSecurityDescriptor, void* pPrincipalSelfSid, std::uint64_t pRsopToken, std::uint32_t dwDesiredAccessMask, void* pObjectTypeList, std::uint32_t ObjectTypeListLength, void* pGenericMapping, void* pPrivilegeSet, std::uint32_t* pdwPrivilegeSetLength, std::uint32_t* pdwGrantedAccessMask, std::int32_t* pbAccessStatus) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pSecurityDescriptor);
    static_cast<void>(pPrincipalSelfSid);
    static_cast<void>(pRsopToken);
    static_cast<void>(dwDesiredAccessMask);
    static_cast<void>(pObjectTypeList);
    static_cast<void>(ObjectTypeListLength);
    static_cast<void>(pGenericMapping);
    static_cast<void>(pPrivilegeSet);
    static_cast<void>(pdwPrivilegeSetLength);
    static_cast<void>(pdwGrantedAccessMask);
    static_cast<void>(pbAccessStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_RsopFileAccessCheck(char16_t* pszFileName, std::uint64_t pRsopToken, std::uint32_t dwDesiredAccessMask, std::uint32_t* pdwGrantedAccessMask, std::int32_t* pbAccessStatus) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pszFileName);
    static_cast<void>(pRsopToken);
    static_cast<void>(dwDesiredAccessMask);
    static_cast<void>(pdwGrantedAccessMask);
    static_cast<void>(pbAccessStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_RsopResetPolicySettingStatus(std::uint32_t dwFlags, void* pServices, void* pSettingInstance) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(dwFlags);
    static_cast<void>(pServices);
    static_cast<void>(pSettingInstance);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_RsopSetPolicySettingStatus(std::uint32_t dwFlags, void* pServices, void* pSettingInstance, std::uint32_t nInfo, void* pStatus) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(dwFlags);
    static_cast<void>(pServices);
    static_cast<void>(pSettingInstance);
    static_cast<void>(nInfo);
    static_cast<void>(pStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_UnloadUserProfile(void* hToken, void* hProfile) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(hToken);
    static_cast<void>(hProfile);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kuserenvG_UnregisterGPNotification(void* hEvent) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy shaping it are built by the logon process
    static_cast<void>(hEvent);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_userenv(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CreateAppContainerProfile", reinterpret_cast<void*>(&kuserenvG_CreateAppContainerProfile));
    e("CreateEnvironmentBlock", reinterpret_cast<void*>(&kuserenvG_CreateEnvironmentBlock));
    e("CreateProfile", reinterpret_cast<void*>(&kuserenvG_CreateProfile));
    e("DeleteAppContainerProfile", reinterpret_cast<void*>(&kuserenvG_DeleteAppContainerProfile));
    e("DeleteProfileA", reinterpret_cast<void*>(&kuserenvG_DeleteProfileA));
    e("DeleteProfileW", reinterpret_cast<void*>(&kuserenvG_DeleteProfileW));
    e("DeriveAppContainerSidFromAppContainerName", reinterpret_cast<void*>(&kuserenvG_DeriveAppContainerSidFromAppContainerName));
    e("DestroyEnvironmentBlock", reinterpret_cast<void*>(&kuserenvG_DestroyEnvironmentBlock));
    e("EnterCriticalPolicySection", reinterpret_cast<void*>(&kuserenvG_EnterCriticalPolicySection));
    e("ExpandEnvironmentStringsForUserA", reinterpret_cast<void*>(&kuserenvG_ExpandEnvironmentStringsForUserA));
    e("ExpandEnvironmentStringsForUserW", reinterpret_cast<void*>(&kuserenvG_ExpandEnvironmentStringsForUserW));
    e("FreeGPOListA", reinterpret_cast<void*>(&kuserenvG_FreeGPOListA));
    e("FreeGPOListW", reinterpret_cast<void*>(&kuserenvG_FreeGPOListW));
    e("GenerateGPNotification", reinterpret_cast<void*>(&kuserenvG_GenerateGPNotification));
    e("GetAllUsersProfileDirectoryA", reinterpret_cast<void*>(&kuserenvG_GetAllUsersProfileDirectoryA));
    e("GetAllUsersProfileDirectoryW", reinterpret_cast<void*>(&kuserenvG_GetAllUsersProfileDirectoryW));
    e("GetAppContainerFolderPath", reinterpret_cast<void*>(&kuserenvG_GetAppContainerFolderPath));
    e("GetAppContainerRegistryLocation", reinterpret_cast<void*>(&kuserenvG_GetAppContainerRegistryLocation));
    e("GetAppliedGPOListA", reinterpret_cast<void*>(&kuserenvG_GetAppliedGPOListA));
    e("GetAppliedGPOListW", reinterpret_cast<void*>(&kuserenvG_GetAppliedGPOListW));
    e("GetDefaultUserProfileDirectoryA", reinterpret_cast<void*>(&kuserenvG_GetDefaultUserProfileDirectoryA));
    e("GetDefaultUserProfileDirectoryW", reinterpret_cast<void*>(&kuserenvG_GetDefaultUserProfileDirectoryW));
    e("GetGPOListA", reinterpret_cast<void*>(&kuserenvG_GetGPOListA));
    e("GetGPOListW", reinterpret_cast<void*>(&kuserenvG_GetGPOListW));
    e("GetProfileType", reinterpret_cast<void*>(&kuserenvG_GetProfileType));
    e("GetProfilesDirectoryA", reinterpret_cast<void*>(&kuserenvG_GetProfilesDirectoryA));
    e("GetProfilesDirectoryW", reinterpret_cast<void*>(&kuserenvG_GetProfilesDirectoryW));
    e("GetUserProfileDirectoryA", reinterpret_cast<void*>(&kuserenvG_GetUserProfileDirectoryA));
    e("GetUserProfileDirectoryW", reinterpret_cast<void*>(&kuserenvG_GetUserProfileDirectoryW));
    e("LeaveCriticalPolicySection", reinterpret_cast<void*>(&kuserenvG_LeaveCriticalPolicySection));
    e("LoadUserProfileA", reinterpret_cast<void*>(&kuserenvG_LoadUserProfileA));
    e("LoadUserProfileW", reinterpret_cast<void*>(&kuserenvG_LoadUserProfileW));
    e("ProcessGroupPolicyCompleted", reinterpret_cast<void*>(&kuserenvG_ProcessGroupPolicyCompleted));
    e("ProcessGroupPolicyCompletedEx", reinterpret_cast<void*>(&kuserenvG_ProcessGroupPolicyCompletedEx));
    e("RefreshPolicy", reinterpret_cast<void*>(&kuserenvG_RefreshPolicy));
    e("RefreshPolicyEx", reinterpret_cast<void*>(&kuserenvG_RefreshPolicyEx));
    e("RegisterGPNotification", reinterpret_cast<void*>(&kuserenvG_RegisterGPNotification));
    e("RsopAccessCheckByType", reinterpret_cast<void*>(&kuserenvG_RsopAccessCheckByType));
    e("RsopFileAccessCheck", reinterpret_cast<void*>(&kuserenvG_RsopFileAccessCheck));
    e("RsopResetPolicySettingStatus", reinterpret_cast<void*>(&kuserenvG_RsopResetPolicySettingStatus));
    e("RsopSetPolicySettingStatus", reinterpret_cast<void*>(&kuserenvG_RsopSetPolicySettingStatus));
    e("UnloadUserProfile", reinterpret_cast<void*>(&kuserenvG_UnloadUserProfile));
    e("UnregisterGPNotification", reinterpret_cast<void*>(&kuserenvG_UnregisterGPNotification));
}
}  // namespace occ::runtime::winabi

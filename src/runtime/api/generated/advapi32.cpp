// The ADVAPI32 surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AbortSystemShutdownA(char* lpMachineName) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(lpMachineName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AbortSystemShutdownW(char16_t* lpMachineName) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(lpMachineName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AccessCheckAndAuditAlarmA(const char* SubsystemName, void* HandleId, char* ObjectTypeName, char* ObjectName, void* SecurityDescriptor, std::uint32_t DesiredAccess, void* GenericMapping, std::int32_t ObjectCreation, std::uint32_t* GrantedAccess, std::int32_t* AccessStatus, std::int32_t* pfGenerateOnClose) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SubsystemName);
    static_cast<void>(HandleId);
    static_cast<void>(ObjectTypeName);
    static_cast<void>(ObjectName);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(DesiredAccess);
    static_cast<void>(GenericMapping);
    static_cast<void>(ObjectCreation);
    static_cast<void>(GrantedAccess);
    static_cast<void>(AccessStatus);
    static_cast<void>(pfGenerateOnClose);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AccessCheckAndAuditAlarmW(const char16_t* SubsystemName, void* HandleId, char16_t* ObjectTypeName, char16_t* ObjectName, void* SecurityDescriptor, std::uint32_t DesiredAccess, void* GenericMapping, std::int32_t ObjectCreation, std::uint32_t* GrantedAccess, std::int32_t* AccessStatus, std::int32_t* pfGenerateOnClose) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SubsystemName);
    static_cast<void>(HandleId);
    static_cast<void>(ObjectTypeName);
    static_cast<void>(ObjectName);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(DesiredAccess);
    static_cast<void>(GenericMapping);
    static_cast<void>(ObjectCreation);
    static_cast<void>(GrantedAccess);
    static_cast<void>(AccessStatus);
    static_cast<void>(pfGenerateOnClose);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AccessCheckByType(void* pSecurityDescriptor, void* PrincipalSelfSid, void* ClientToken, std::uint32_t DesiredAccess, void* ObjectTypeList, std::uint32_t ObjectTypeListLength, void* GenericMapping, void* PrivilegeSet, std::uint32_t* PrivilegeSetLength, std::uint32_t* GrantedAccess, std::int32_t* AccessStatus) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pSecurityDescriptor);
    static_cast<void>(PrincipalSelfSid);
    static_cast<void>(ClientToken);
    static_cast<void>(DesiredAccess);
    static_cast<void>(ObjectTypeList);
    static_cast<void>(ObjectTypeListLength);
    static_cast<void>(GenericMapping);
    static_cast<void>(PrivilegeSet);
    static_cast<void>(PrivilegeSetLength);
    static_cast<void>(GrantedAccess);
    static_cast<void>(AccessStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AccessCheckByTypeAndAuditAlarmA(const char* SubsystemName, void* HandleId, const char* ObjectTypeName, const char* ObjectName, void* SecurityDescriptor, void* PrincipalSelfSid, std::uint32_t DesiredAccess, std::int32_t AuditType, std::uint32_t Flags, void* ObjectTypeList, std::uint32_t ObjectTypeListLength, void* GenericMapping, std::int32_t ObjectCreation, std::uint32_t* GrantedAccess, std::int32_t* AccessStatus, std::int32_t* pfGenerateOnClose) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SubsystemName);
    static_cast<void>(HandleId);
    static_cast<void>(ObjectTypeName);
    static_cast<void>(ObjectName);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(PrincipalSelfSid);
    static_cast<void>(DesiredAccess);
    static_cast<void>(AuditType);
    static_cast<void>(Flags);
    static_cast<void>(ObjectTypeList);
    static_cast<void>(ObjectTypeListLength);
    static_cast<void>(GenericMapping);
    static_cast<void>(ObjectCreation);
    static_cast<void>(GrantedAccess);
    static_cast<void>(AccessStatus);
    static_cast<void>(pfGenerateOnClose);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AccessCheckByTypeAndAuditAlarmW(const char16_t* SubsystemName, void* HandleId, const char16_t* ObjectTypeName, const char16_t* ObjectName, void* SecurityDescriptor, void* PrincipalSelfSid, std::uint32_t DesiredAccess, std::int32_t AuditType, std::uint32_t Flags, void* ObjectTypeList, std::uint32_t ObjectTypeListLength, void* GenericMapping, std::int32_t ObjectCreation, std::uint32_t* GrantedAccess, std::int32_t* AccessStatus, std::int32_t* pfGenerateOnClose) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SubsystemName);
    static_cast<void>(HandleId);
    static_cast<void>(ObjectTypeName);
    static_cast<void>(ObjectName);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(PrincipalSelfSid);
    static_cast<void>(DesiredAccess);
    static_cast<void>(AuditType);
    static_cast<void>(Flags);
    static_cast<void>(ObjectTypeList);
    static_cast<void>(ObjectTypeListLength);
    static_cast<void>(GenericMapping);
    static_cast<void>(ObjectCreation);
    static_cast<void>(GrantedAccess);
    static_cast<void>(AccessStatus);
    static_cast<void>(pfGenerateOnClose);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AccessCheckByTypeResultList(void* pSecurityDescriptor, void* PrincipalSelfSid, void* ClientToken, std::uint32_t DesiredAccess, void* ObjectTypeList, std::uint32_t ObjectTypeListLength, void* GenericMapping, void* PrivilegeSet, std::uint32_t* PrivilegeSetLength, std::uint32_t* GrantedAccessList, std::uint32_t* AccessStatusList) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pSecurityDescriptor);
    static_cast<void>(PrincipalSelfSid);
    static_cast<void>(ClientToken);
    static_cast<void>(DesiredAccess);
    static_cast<void>(ObjectTypeList);
    static_cast<void>(ObjectTypeListLength);
    static_cast<void>(GenericMapping);
    static_cast<void>(PrivilegeSet);
    static_cast<void>(PrivilegeSetLength);
    static_cast<void>(GrantedAccessList);
    static_cast<void>(AccessStatusList);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AccessCheckByTypeResultListAndAuditAlarmA(const char* SubsystemName, void* HandleId, const char* ObjectTypeName, const char* ObjectName, void* SecurityDescriptor, void* PrincipalSelfSid, std::uint32_t DesiredAccess, std::int32_t AuditType, std::uint32_t Flags, void* ObjectTypeList, std::uint32_t ObjectTypeListLength, void* GenericMapping, std::int32_t ObjectCreation, std::uint32_t* GrantedAccess, std::uint32_t* AccessStatusList, std::int32_t* pfGenerateOnClose) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SubsystemName);
    static_cast<void>(HandleId);
    static_cast<void>(ObjectTypeName);
    static_cast<void>(ObjectName);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(PrincipalSelfSid);
    static_cast<void>(DesiredAccess);
    static_cast<void>(AuditType);
    static_cast<void>(Flags);
    static_cast<void>(ObjectTypeList);
    static_cast<void>(ObjectTypeListLength);
    static_cast<void>(GenericMapping);
    static_cast<void>(ObjectCreation);
    static_cast<void>(GrantedAccess);
    static_cast<void>(AccessStatusList);
    static_cast<void>(pfGenerateOnClose);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AccessCheckByTypeResultListAndAuditAlarmByHandleA(const char* SubsystemName, void* HandleId, void* ClientToken, const char* ObjectTypeName, const char* ObjectName, void* SecurityDescriptor, void* PrincipalSelfSid, std::uint32_t DesiredAccess, std::int32_t AuditType, std::uint32_t Flags, void* ObjectTypeList, std::uint32_t ObjectTypeListLength, void* GenericMapping, std::int32_t ObjectCreation, std::uint32_t* GrantedAccess, std::uint32_t* AccessStatusList, std::int32_t* pfGenerateOnClose) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SubsystemName);
    static_cast<void>(HandleId);
    static_cast<void>(ClientToken);
    static_cast<void>(ObjectTypeName);
    static_cast<void>(ObjectName);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(PrincipalSelfSid);
    static_cast<void>(DesiredAccess);
    static_cast<void>(AuditType);
    static_cast<void>(Flags);
    static_cast<void>(ObjectTypeList);
    static_cast<void>(ObjectTypeListLength);
    static_cast<void>(GenericMapping);
    static_cast<void>(ObjectCreation);
    static_cast<void>(GrantedAccess);
    static_cast<void>(AccessStatusList);
    static_cast<void>(pfGenerateOnClose);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AccessCheckByTypeResultListAndAuditAlarmByHandleW(const char16_t* SubsystemName, void* HandleId, void* ClientToken, const char16_t* ObjectTypeName, const char16_t* ObjectName, void* SecurityDescriptor, void* PrincipalSelfSid, std::uint32_t DesiredAccess, std::int32_t AuditType, std::uint32_t Flags, void* ObjectTypeList, std::uint32_t ObjectTypeListLength, void* GenericMapping, std::int32_t ObjectCreation, std::uint32_t* GrantedAccessList, std::uint32_t* AccessStatusList, std::int32_t* pfGenerateOnClose) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SubsystemName);
    static_cast<void>(HandleId);
    static_cast<void>(ClientToken);
    static_cast<void>(ObjectTypeName);
    static_cast<void>(ObjectName);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(PrincipalSelfSid);
    static_cast<void>(DesiredAccess);
    static_cast<void>(AuditType);
    static_cast<void>(Flags);
    static_cast<void>(ObjectTypeList);
    static_cast<void>(ObjectTypeListLength);
    static_cast<void>(GenericMapping);
    static_cast<void>(ObjectCreation);
    static_cast<void>(GrantedAccessList);
    static_cast<void>(AccessStatusList);
    static_cast<void>(pfGenerateOnClose);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AccessCheckByTypeResultListAndAuditAlarmW(const char16_t* SubsystemName, void* HandleId, const char16_t* ObjectTypeName, const char16_t* ObjectName, void* SecurityDescriptor, void* PrincipalSelfSid, std::uint32_t DesiredAccess, std::int32_t AuditType, std::uint32_t Flags, void* ObjectTypeList, std::uint32_t ObjectTypeListLength, void* GenericMapping, std::int32_t ObjectCreation, std::uint32_t* GrantedAccessList, std::uint32_t* AccessStatusList, std::int32_t* pfGenerateOnClose) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SubsystemName);
    static_cast<void>(HandleId);
    static_cast<void>(ObjectTypeName);
    static_cast<void>(ObjectName);
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(PrincipalSelfSid);
    static_cast<void>(DesiredAccess);
    static_cast<void>(AuditType);
    static_cast<void>(Flags);
    static_cast<void>(ObjectTypeList);
    static_cast<void>(ObjectTypeListLength);
    static_cast<void>(GenericMapping);
    static_cast<void>(ObjectCreation);
    static_cast<void>(GrantedAccessList);
    static_cast<void>(AccessStatusList);
    static_cast<void>(pfGenerateOnClose);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AddAccessAllowedObjectAce(void* pAcl, std::uint32_t dwAceRevision, std::uint32_t AceFlags, std::uint32_t AccessMask, void* ObjectTypeGuid, void* InheritedObjectTypeGuid, void* pSid) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pAcl);
    static_cast<void>(dwAceRevision);
    static_cast<void>(AceFlags);
    static_cast<void>(AccessMask);
    static_cast<void>(ObjectTypeGuid);
    static_cast<void>(InheritedObjectTypeGuid);
    static_cast<void>(pSid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AddAccessDeniedAce(void* pAcl, std::uint32_t dwAceRevision, std::uint32_t AccessMask, void* pSid) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pAcl);
    static_cast<void>(dwAceRevision);
    static_cast<void>(AccessMask);
    static_cast<void>(pSid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AddAccessDeniedAceEx(void* pAcl, std::uint32_t dwAceRevision, std::uint32_t AceFlags, std::uint32_t AccessMask, void* pSid) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pAcl);
    static_cast<void>(dwAceRevision);
    static_cast<void>(AceFlags);
    static_cast<void>(AccessMask);
    static_cast<void>(pSid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AddAccessDeniedObjectAce(void* pAcl, std::uint32_t dwAceRevision, std::uint32_t AceFlags, std::uint32_t AccessMask, void* ObjectTypeGuid, void* InheritedObjectTypeGuid, void* pSid) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pAcl);
    static_cast<void>(dwAceRevision);
    static_cast<void>(AceFlags);
    static_cast<void>(AccessMask);
    static_cast<void>(ObjectTypeGuid);
    static_cast<void>(InheritedObjectTypeGuid);
    static_cast<void>(pSid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AddAce(void* pAcl, std::uint32_t dwAceRevision, std::uint32_t dwStartingAceIndex, void* pAceList, std::uint32_t nAceListLength) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(pAcl);
    static_cast<void>(dwAceRevision);
    static_cast<void>(dwStartingAceIndex);
    static_cast<void>(pAceList);
    static_cast<void>(nAceListLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AddAuditAccessAce(void* pAcl, std::uint32_t dwAceRevision, std::uint32_t dwAccessMask, void* pSid, std::int32_t bAuditSuccess, std::int32_t bAuditFailure) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(pAcl);
    static_cast<void>(dwAceRevision);
    static_cast<void>(dwAccessMask);
    static_cast<void>(pSid);
    static_cast<void>(bAuditSuccess);
    static_cast<void>(bAuditFailure);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AddAuditAccessAceEx(void* pAcl, std::uint32_t dwAceRevision, std::uint32_t AceFlags, std::uint32_t dwAccessMask, void* pSid, std::int32_t bAuditSuccess, std::int32_t bAuditFailure) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(pAcl);
    static_cast<void>(dwAceRevision);
    static_cast<void>(AceFlags);
    static_cast<void>(dwAccessMask);
    static_cast<void>(pSid);
    static_cast<void>(bAuditSuccess);
    static_cast<void>(bAuditFailure);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AddAuditAccessObjectAce(void* pAcl, std::uint32_t dwAceRevision, std::uint32_t AceFlags, std::uint32_t AccessMask, void* ObjectTypeGuid, void* InheritedObjectTypeGuid, void* pSid, std::int32_t bAuditSuccess, std::int32_t bAuditFailure) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(pAcl);
    static_cast<void>(dwAceRevision);
    static_cast<void>(AceFlags);
    static_cast<void>(AccessMask);
    static_cast<void>(ObjectTypeGuid);
    static_cast<void>(InheritedObjectTypeGuid);
    static_cast<void>(pSid);
    static_cast<void>(bAuditSuccess);
    static_cast<void>(bAuditFailure);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AddConditionalAce(void* pAcl, std::uint32_t dwAceRevision, std::uint32_t AceFlags, std::uint8_t AceType, std::uint32_t AccessMask, void* pSid, char16_t* ConditionStr, std::uint32_t* ReturnLength) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(pAcl);
    static_cast<void>(dwAceRevision);
    static_cast<void>(AceFlags);
    static_cast<void>(AceType);
    static_cast<void>(AccessMask);
    static_cast<void>(pSid);
    static_cast<void>(ConditionStr);
    static_cast<void>(ReturnLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AddMandatoryAce(void* pAcl, std::uint32_t dwAceRevision, std::uint32_t AceFlags, std::uint32_t MandatoryPolicy, void* pLabelSid) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pAcl);
    static_cast<void>(dwAceRevision);
    static_cast<void>(AceFlags);
    static_cast<void>(MandatoryPolicy);
    static_cast<void>(pLabelSid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_AddUsersToEncryptedFile(const char16_t* lpFileName, std::uint64_t pUsers) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(lpFileName);
    static_cast<void>(pUsers);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AllocateLocallyUniqueId(std::uint64_t Luid) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(Luid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_AreAnyAccessesGranted(std::uint32_t GrantedAccess, std::uint32_t DesiredAccess) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(GrantedAccess);
    static_cast<void>(DesiredAccess);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditComputeEffectivePolicyBySid(void* pSid, const void* pSubCategoryGuids, std::uint32_t PolicyCount, void** ppAuditPolicy) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(pSid);
    static_cast<void>(pSubCategoryGuids);
    static_cast<void>(PolicyCount);
    static_cast<void>(ppAuditPolicy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditComputeEffectivePolicyByToken(void* hTokenHandle, const void* pSubCategoryGuids, std::uint32_t PolicyCount, void** ppAuditPolicy) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(hTokenHandle);
    static_cast<void>(pSubCategoryGuids);
    static_cast<void>(PolicyCount);
    static_cast<void>(ppAuditPolicy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditEnumerateCategories(void** ppAuditCategoriesArray, std::uint32_t* pCountReturned) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(ppAuditCategoriesArray);
    static_cast<void>(pCountReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditEnumeratePerUserPolicy(void* ppAuditSidArray) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(ppAuditSidArray);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditEnumerateSubCategories(const void* pAuditCategoryGuid, std::uint8_t bRetrieveAllSubCategories, void** ppAuditSubCategoriesArray, std::uint32_t* pCountReturned) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(pAuditCategoryGuid);
    static_cast<void>(bRetrieveAllSubCategories);
    static_cast<void>(ppAuditSubCategoriesArray);
    static_cast<void>(pCountReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_AuditFree(void* Buffer) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(Buffer);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditLookupCategoryGuidFromCategoryId(std::int32_t AuditCategoryId, void* pAuditCategoryGuid) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(AuditCategoryId);
    static_cast<void>(pAuditCategoryGuid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditLookupCategoryIdFromCategoryGuid(const void* pAuditCategoryGuid, std::int32_t* pAuditCategoryId) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(pAuditCategoryGuid);
    static_cast<void>(pAuditCategoryId);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditLookupCategoryNameA(const void* pAuditCategoryGuid, char** ppszCategoryName) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(pAuditCategoryGuid);
    static_cast<void>(ppszCategoryName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditLookupCategoryNameW(const void* pAuditCategoryGuid, char16_t** ppszCategoryName) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(pAuditCategoryGuid);
    static_cast<void>(ppszCategoryName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditLookupSubCategoryNameA(const void* pAuditSubCategoryGuid, char** ppszSubCategoryName) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(pAuditSubCategoryGuid);
    static_cast<void>(ppszSubCategoryName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditLookupSubCategoryNameW(const void* pAuditSubCategoryGuid, char16_t** ppszSubCategoryName) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(pAuditSubCategoryGuid);
    static_cast<void>(ppszSubCategoryName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditQueryGlobalSaclA(const char* ObjectTypeName, void* Acl) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(ObjectTypeName);
    static_cast<void>(Acl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditQueryGlobalSaclW(const char16_t* ObjectTypeName, void* Acl) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(ObjectTypeName);
    static_cast<void>(Acl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditQueryPerUserPolicy(void* pSid, const void* pSubCategoryGuids, std::uint32_t PolicyCount, void** ppAuditPolicy) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(pSid);
    static_cast<void>(pSubCategoryGuids);
    static_cast<void>(PolicyCount);
    static_cast<void>(ppAuditPolicy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditQuerySecurity(std::uint32_t SecurityInformation, void* ppSecurityDescriptor) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SecurityInformation);
    static_cast<void>(ppSecurityDescriptor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditQuerySystemPolicy(const void* pSubCategoryGuids, std::uint32_t PolicyCount, void** ppAuditPolicy) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(pSubCategoryGuids);
    static_cast<void>(PolicyCount);
    static_cast<void>(ppAuditPolicy);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditSetGlobalSaclA(const char* ObjectTypeName, void* Acl) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(ObjectTypeName);
    static_cast<void>(Acl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditSetGlobalSaclW(const char16_t* ObjectTypeName, void* Acl) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(ObjectTypeName);
    static_cast<void>(Acl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditSetPerUserPolicy(void* pSid, void* pAuditPolicy, std::uint32_t PolicyCount) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(pSid);
    static_cast<void>(pAuditPolicy);
    static_cast<void>(PolicyCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditSetSecurity(std::uint32_t SecurityInformation, void* pSecurityDescriptor) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SecurityInformation);
    static_cast<void>(pSecurityDescriptor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_AuditSetSystemPolicy(void* pAuditPolicy, std::uint32_t PolicyCount) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(pAuditPolicy);
    static_cast<void>(PolicyCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_BackupEventLogA(void* hEventLog, const char* lpBackupFileName) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(hEventLog);
    static_cast<void>(lpBackupFileName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_BackupEventLogW(void* hEventLog, const char16_t* lpBackupFileName) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(hEventLog);
    static_cast<void>(lpBackupFileName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_BuildExplicitAccessWithNameA(void* pExplicitAccess, char* pTrusteeName, std::uint32_t AccessPermissions, std::int32_t AccessMode, std::uint32_t Inheritance) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pExplicitAccess);
    static_cast<void>(pTrusteeName);
    static_cast<void>(AccessPermissions);
    static_cast<void>(AccessMode);
    static_cast<void>(Inheritance);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_BuildExplicitAccessWithNameW(void* pExplicitAccess, char16_t* pTrusteeName, std::uint32_t AccessPermissions, std::int32_t AccessMode, std::uint32_t Inheritance) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pExplicitAccess);
    static_cast<void>(pTrusteeName);
    static_cast<void>(AccessPermissions);
    static_cast<void>(AccessMode);
    static_cast<void>(Inheritance);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_BuildImpersonateExplicitAccessWithNameA(void* pExplicitAccess, char* pTrusteeName, void* pTrustee, std::uint32_t AccessPermissions, std::int32_t AccessMode, std::uint32_t Inheritance) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pExplicitAccess);
    static_cast<void>(pTrusteeName);
    static_cast<void>(pTrustee);
    static_cast<void>(AccessPermissions);
    static_cast<void>(AccessMode);
    static_cast<void>(Inheritance);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_BuildImpersonateExplicitAccessWithNameW(void* pExplicitAccess, char16_t* pTrusteeName, void* pTrustee, std::uint32_t AccessPermissions, std::int32_t AccessMode, std::uint32_t Inheritance) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pExplicitAccess);
    static_cast<void>(pTrusteeName);
    static_cast<void>(pTrustee);
    static_cast<void>(AccessPermissions);
    static_cast<void>(AccessMode);
    static_cast<void>(Inheritance);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_BuildImpersonateTrusteeA(void* pTrustee, void* pImpersonateTrustee) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    static_cast<void>(pImpersonateTrustee);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_BuildImpersonateTrusteeW(void* pTrustee, void* pImpersonateTrustee) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    static_cast<void>(pImpersonateTrustee);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_BuildSecurityDescriptorA(void* pOwner, void* pGroup, std::uint32_t cCountOfAccessEntries, void* pListOfAccessEntries, std::uint32_t cCountOfAuditEntries, void* pListOfAuditEntries, void* pOldSD, std::uint32_t* pSizeNewSD, void* pNewSD) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pOwner);
    static_cast<void>(pGroup);
    static_cast<void>(cCountOfAccessEntries);
    static_cast<void>(pListOfAccessEntries);
    static_cast<void>(cCountOfAuditEntries);
    static_cast<void>(pListOfAuditEntries);
    static_cast<void>(pOldSD);
    static_cast<void>(pSizeNewSD);
    static_cast<void>(pNewSD);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_BuildSecurityDescriptorW(void* pOwner, void* pGroup, std::uint32_t cCountOfAccessEntries, void* pListOfAccessEntries, std::uint32_t cCountOfAuditEntries, void* pListOfAuditEntries, void* pOldSD, std::uint32_t* pSizeNewSD, void* pNewSD) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pOwner);
    static_cast<void>(pGroup);
    static_cast<void>(cCountOfAccessEntries);
    static_cast<void>(pListOfAccessEntries);
    static_cast<void>(cCountOfAuditEntries);
    static_cast<void>(pListOfAuditEntries);
    static_cast<void>(pOldSD);
    static_cast<void>(pSizeNewSD);
    static_cast<void>(pNewSD);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_BuildTrusteeWithNameA(void* pTrustee, char* pName) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    static_cast<void>(pName);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_BuildTrusteeWithNameW(void* pTrustee, char16_t* pName) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    static_cast<void>(pName);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_BuildTrusteeWithObjectsAndNameA(void* pTrustee, std::uint64_t pObjName, std::int32_t ObjectType, char* ObjectTypeName, char* InheritedObjectTypeName, char* Name) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    static_cast<void>(pObjName);
    static_cast<void>(ObjectType);
    static_cast<void>(ObjectTypeName);
    static_cast<void>(InheritedObjectTypeName);
    static_cast<void>(Name);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_BuildTrusteeWithObjectsAndNameW(void* pTrustee, std::uint64_t pObjName, std::int32_t ObjectType, char16_t* ObjectTypeName, char16_t* InheritedObjectTypeName, char16_t* Name) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    static_cast<void>(pObjName);
    static_cast<void>(ObjectType);
    static_cast<void>(ObjectTypeName);
    static_cast<void>(InheritedObjectTypeName);
    static_cast<void>(Name);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_BuildTrusteeWithObjectsAndSidA(void* pTrustee, std::uint64_t pObjSid, void* pObjectGuid, void* pInheritedObjectGuid, void* pSid) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    static_cast<void>(pObjSid);
    static_cast<void>(pObjectGuid);
    static_cast<void>(pInheritedObjectGuid);
    static_cast<void>(pSid);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_BuildTrusteeWithObjectsAndSidW(void* pTrustee, std::uint64_t pObjSid, void* pObjectGuid, void* pInheritedObjectGuid, void* pSid) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    static_cast<void>(pObjSid);
    static_cast<void>(pObjectGuid);
    static_cast<void>(pInheritedObjectGuid);
    static_cast<void>(pSid);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_BuildTrusteeWithSidA(void* pTrustee, void* pSid) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    static_cast<void>(pSid);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_BuildTrusteeWithSidW(void* pTrustee, void* pSid) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    static_cast<void>(pSid);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ChangeServiceConfig2A(void* hService, std::uint32_t dwInfoLevel, void* lpInfo) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hService);
    static_cast<void>(dwInfoLevel);
    static_cast<void>(lpInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ChangeServiceConfig2W(void* hService, std::uint32_t dwInfoLevel, void* lpInfo) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hService);
    static_cast<void>(dwInfoLevel);
    static_cast<void>(lpInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ChangeServiceConfigA(void* hService, std::uint32_t dwServiceType, std::uint32_t dwStartType, std::uint32_t dwErrorControl, const char* lpBinaryPathName, const char* lpLoadOrderGroup, std::uint32_t* lpdwTagId, const char* lpDependencies, const char* lpServiceStartName, const char* lpPassword, const char* lpDisplayName) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hService);
    static_cast<void>(dwServiceType);
    static_cast<void>(dwStartType);
    static_cast<void>(dwErrorControl);
    static_cast<void>(lpBinaryPathName);
    static_cast<void>(lpLoadOrderGroup);
    static_cast<void>(lpdwTagId);
    static_cast<void>(lpDependencies);
    static_cast<void>(lpServiceStartName);
    static_cast<void>(lpPassword);
    static_cast<void>(lpDisplayName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ChangeServiceConfigW(void* hService, std::uint32_t dwServiceType, std::uint32_t dwStartType, std::uint32_t dwErrorControl, const char16_t* lpBinaryPathName, const char16_t* lpLoadOrderGroup, std::uint32_t* lpdwTagId, const char16_t* lpDependencies, const char16_t* lpServiceStartName, const char16_t* lpPassword, const char16_t* lpDisplayName) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hService);
    static_cast<void>(dwServiceType);
    static_cast<void>(dwStartType);
    static_cast<void>(dwErrorControl);
    static_cast<void>(lpBinaryPathName);
    static_cast<void>(lpLoadOrderGroup);
    static_cast<void>(lpdwTagId);
    static_cast<void>(lpDependencies);
    static_cast<void>(lpServiceStartName);
    static_cast<void>(lpPassword);
    static_cast<void>(lpDisplayName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_CheckForHiberboot(std::uint8_t* pHiberboot, std::uint8_t bClearFlag) noexcept {
    // Refused: the power management interface.
    //
    // power requests are made to the platform firmware through the kernel, and
    // this runtime is a process on a host that has its own
    static_cast<void>(pHiberboot);
    static_cast<void>(bClearFlag);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ClearEventLogA(void* hEventLog, const char* lpBackupFileName) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(hEventLog);
    static_cast<void>(lpBackupFileName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ClearEventLogW(void* hEventLog, const char16_t* lpBackupFileName) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(hEventLog);
    static_cast<void>(lpBackupFileName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_CloseEncryptedFileRaw(void* pvContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pvContext);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CloseEventLog(void* hEventLog) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(hEventLog);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ControlServiceExA(void* hService, std::uint32_t dwControl, std::uint32_t dwInfoLevel, void* pControlParams) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hService);
    static_cast<void>(dwControl);
    static_cast<void>(dwInfoLevel);
    static_cast<void>(pControlParams);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ControlServiceExW(void* hService, std::uint32_t dwControl, std::uint32_t dwInfoLevel, void* pControlParams) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hService);
    static_cast<void>(dwControl);
    static_cast<void>(dwInfoLevel);
    static_cast<void>(pControlParams);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ConvertSecurityDescriptorToStringSecurityDescriptorA(void* SecurityDescriptor, std::uint32_t RequestedStringSDRevision, std::uint32_t SecurityInformation, char** StringSecurityDescriptor, std::uint32_t* StringSecurityDescriptorLen) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(RequestedStringSDRevision);
    static_cast<void>(SecurityInformation);
    static_cast<void>(StringSecurityDescriptor);
    static_cast<void>(StringSecurityDescriptorLen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ConvertSecurityDescriptorToStringSecurityDescriptorW(void* SecurityDescriptor, std::uint32_t RequestedStringSDRevision, std::uint32_t SecurityInformation, char16_t** StringSecurityDescriptor, std::uint32_t* StringSecurityDescriptorLen) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(RequestedStringSDRevision);
    static_cast<void>(SecurityInformation);
    static_cast<void>(StringSecurityDescriptor);
    static_cast<void>(StringSecurityDescriptorLen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ConvertToAutoInheritPrivateObjectSecurity(void* ParentDescriptor, void* CurrentSecurityDescriptor, void* NewSecurityDescriptor, void* ObjectType, std::uint8_t IsDirectoryObject, void* GenericMapping) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(ParentDescriptor);
    static_cast<void>(CurrentSecurityDescriptor);
    static_cast<void>(NewSecurityDescriptor);
    static_cast<void>(ObjectType);
    static_cast<void>(IsDirectoryObject);
    static_cast<void>(GenericMapping);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CreatePrivateObjectSecurity(void* ParentDescriptor, void* CreatorDescriptor, void* NewDescriptor, std::int32_t IsDirectoryObject, void* Token, void* GenericMapping) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(ParentDescriptor);
    static_cast<void>(CreatorDescriptor);
    static_cast<void>(NewDescriptor);
    static_cast<void>(IsDirectoryObject);
    static_cast<void>(Token);
    static_cast<void>(GenericMapping);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CreatePrivateObjectSecurityEx(void* ParentDescriptor, void* CreatorDescriptor, void* NewDescriptor, void* ObjectType, std::int32_t IsContainerObject, std::uint32_t AutoInheritFlags, void* Token, void* GenericMapping) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(ParentDescriptor);
    static_cast<void>(CreatorDescriptor);
    static_cast<void>(NewDescriptor);
    static_cast<void>(ObjectType);
    static_cast<void>(IsContainerObject);
    static_cast<void>(AutoInheritFlags);
    static_cast<void>(Token);
    static_cast<void>(GenericMapping);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CreatePrivateObjectSecurityWithMultipleInheritance(void* ParentDescriptor, void* CreatorDescriptor, void* NewDescriptor, void** ObjectTypes, std::uint32_t GuidCount, std::int32_t IsContainerObject, std::uint32_t AutoInheritFlags, void* Token, void* GenericMapping) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(ParentDescriptor);
    static_cast<void>(CreatorDescriptor);
    static_cast<void>(NewDescriptor);
    static_cast<void>(ObjectTypes);
    static_cast<void>(GuidCount);
    static_cast<void>(IsContainerObject);
    static_cast<void>(AutoInheritFlags);
    static_cast<void>(Token);
    static_cast<void>(GenericMapping);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CreateProcessWithLogonW(const char16_t* lpUsername, const char16_t* lpDomain, const char16_t* lpPassword, std::uint32_t dwLogonFlags, const char16_t* lpApplicationName, char16_t* lpCommandLine, std::uint32_t dwCreationFlags, void* lpEnvironment, const char16_t* lpCurrentDirectory, void* lpStartupInfo, void* lpProcessInformation) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(lpUsername);
    static_cast<void>(lpDomain);
    static_cast<void>(lpPassword);
    static_cast<void>(dwLogonFlags);
    static_cast<void>(lpApplicationName);
    static_cast<void>(lpCommandLine);
    static_cast<void>(dwCreationFlags);
    static_cast<void>(lpEnvironment);
    static_cast<void>(lpCurrentDirectory);
    static_cast<void>(lpStartupInfo);
    static_cast<void>(lpProcessInformation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CreateProcessWithTokenW(void* hToken, std::uint32_t dwLogonFlags, const char16_t* lpApplicationName, char16_t* lpCommandLine, std::uint32_t dwCreationFlags, void* lpEnvironment, const char16_t* lpCurrentDirectory, void* lpStartupInfo, void* lpProcessInformation) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(hToken);
    static_cast<void>(dwLogonFlags);
    static_cast<void>(lpApplicationName);
    static_cast<void>(lpCommandLine);
    static_cast<void>(dwCreationFlags);
    static_cast<void>(lpEnvironment);
    static_cast<void>(lpCurrentDirectory);
    static_cast<void>(lpStartupInfo);
    static_cast<void>(lpProcessInformation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CreateRestrictedToken(void* ExistingTokenHandle, std::uint32_t Flags, std::uint32_t DisableSidCount, std::uint64_t SidsToDisable, std::uint32_t DeletePrivilegeCount, std::uint64_t PrivilegesToDelete, std::uint32_t RestrictedSidCount, std::uint64_t SidsToRestrict, void** NewTokenHandle) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(ExistingTokenHandle);
    static_cast<void>(Flags);
    static_cast<void>(DisableSidCount);
    static_cast<void>(SidsToDisable);
    static_cast<void>(DeletePrivilegeCount);
    static_cast<void>(PrivilegesToDelete);
    static_cast<void>(RestrictedSidCount);
    static_cast<void>(SidsToRestrict);
    static_cast<void>(NewTokenHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CreateWellKnownSid(std::int32_t WellKnownSidType, void* DomainSid, void* pSid, std::uint32_t* cbSid) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(WellKnownSidType);
    static_cast<void>(DomainSid);
    static_cast<void>(pSid);
    static_cast<void>(cbSid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CryptContextAddRef(void* hProv, std::uint32_t* pdwReserved, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hProv);
    static_cast<void>(pdwReserved);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CryptEnumProviderTypesA(std::uint32_t dwIndex, std::uint32_t* pdwReserved, std::uint32_t dwFlags, std::uint32_t* pdwProvType, char* szTypeName, std::uint32_t* pcbTypeName) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwIndex);
    static_cast<void>(pdwReserved);
    static_cast<void>(dwFlags);
    static_cast<void>(pdwProvType);
    static_cast<void>(szTypeName);
    static_cast<void>(pcbTypeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CryptEnumProviderTypesW(std::uint32_t dwIndex, std::uint32_t* pdwReserved, std::uint32_t dwFlags, std::uint32_t* pdwProvType, char16_t* szTypeName, std::uint32_t* pcbTypeName) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(dwIndex);
    static_cast<void>(pdwReserved);
    static_cast<void>(dwFlags);
    static_cast<void>(pdwProvType);
    static_cast<void>(szTypeName);
    static_cast<void>(pcbTypeName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CryptGetUserKey(void* hProv, std::uint32_t dwKeySpec, void* phUserKey) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hProv);
    static_cast<void>(dwKeySpec);
    static_cast<void>(phUserKey);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CryptSetProvParam(void* hProv, std::uint32_t dwParam, const std::uint8_t* pbData, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(hProv);
    static_cast<void>(dwParam);
    static_cast<void>(pbData);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CryptSetProviderA(const char* pszProvName, std::uint32_t dwProvType) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pszProvName);
    static_cast<void>(dwProvType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CryptSetProviderExA(const char* pszProvName, std::uint32_t dwProvType, std::uint32_t* pdwReserved, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pszProvName);
    static_cast<void>(dwProvType);
    static_cast<void>(pdwReserved);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CryptSetProviderExW(const char16_t* pszProvName, std::uint32_t dwProvType, std::uint32_t* pdwReserved, std::uint32_t dwFlags) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pszProvName);
    static_cast<void>(dwProvType);
    static_cast<void>(pdwReserved);
    static_cast<void>(dwFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CryptSetProviderW(const char16_t* pszProvName, std::uint32_t dwProvType) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pszProvName);
    static_cast<void>(dwProvType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_CveEventWrite(const char16_t* CveId, const char16_t* AdditionalDetails) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(CveId);
    static_cast<void>(AdditionalDetails);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_DecryptFileA(const char* lpFileName, std::uint32_t dwReserved) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(lpFileName);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_DecryptFileW(const char16_t* lpFileName, std::uint32_t dwReserved) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(lpFileName);
    static_cast<void>(dwReserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_DeleteAce(void* pAcl, std::uint32_t dwAceIndex) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(pAcl);
    static_cast<void>(dwAceIndex);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_DeregisterEventSource(void* hEventLog) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(hEventLog);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_DestroyPrivateObjectSecurity(void* ObjectDescriptor) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(ObjectDescriptor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_DuplicateEncryptionInfoFile(const char16_t* SrcFileName, const char16_t* DstFileName, std::uint32_t dwCreationDistribution, std::uint32_t dwAttributes, void* lpSecurityAttributes) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(SrcFileName);
    static_cast<void>(DstFileName);
    static_cast<void>(dwCreationDistribution);
    static_cast<void>(dwAttributes);
    static_cast<void>(lpSecurityAttributes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_EncryptFileA(const char* lpFileName) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(lpFileName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_EncryptFileW(const char16_t* lpFileName) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(lpFileName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_EncryptionDisable(const char16_t* DirPath, std::int32_t Disable) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(DirPath);
    static_cast<void>(Disable);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_EnumDependentServicesA(void* hService, std::uint32_t dwServiceState, std::uint64_t lpServices, std::uint32_t cbBufSize, std::uint32_t* pcbBytesNeeded, std::uint32_t* lpServicesReturned) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hService);
    static_cast<void>(dwServiceState);
    static_cast<void>(lpServices);
    static_cast<void>(cbBufSize);
    static_cast<void>(pcbBytesNeeded);
    static_cast<void>(lpServicesReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_EnumDependentServicesW(void* hService, std::uint32_t dwServiceState, std::uint64_t lpServices, std::uint32_t cbBufSize, std::uint32_t* pcbBytesNeeded, std::uint32_t* lpServicesReturned) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hService);
    static_cast<void>(dwServiceState);
    static_cast<void>(lpServices);
    static_cast<void>(cbBufSize);
    static_cast<void>(pcbBytesNeeded);
    static_cast<void>(lpServicesReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_EnumDynamicTimeZoneInformation(std::uint32_t dwIndex, void* lpTimeZoneInformation) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(dwIndex);
    static_cast<void>(lpTimeZoneInformation);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_EqualDomainSid(void* pSid1, void* pSid2, std::int32_t* pfEqual) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pSid1);
    static_cast<void>(pSid2);
    static_cast<void>(pfEqual);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_EqualPrefixSid(void* pSid1, void* pSid2) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pSid1);
    static_cast<void>(pSid2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_FileEncryptionStatusA(const char* lpFileName, std::uint32_t* lpStatus) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(lpFileName);
    static_cast<void>(lpStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_FileEncryptionStatusW(const char16_t* lpFileName, std::uint32_t* lpStatus) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(lpFileName);
    static_cast<void>(lpStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_FreeEncryptionCertificateHashList(std::uint64_t pHashes) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pHashes);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_FreeInheritedFromArray(std::uint64_t pInheritArray, std::uint16_t AceCnt, std::uint64_t pfnArray) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(pInheritArray);
    static_cast<void>(AceCnt);
    static_cast<void>(pfnArray);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_GetAuditedPermissionsFromAclA(void* pacl, void* pTrustee, std::uint32_t* pSuccessfulAuditedRights, std::uint32_t* pFailedAuditRights) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(pacl);
    static_cast<void>(pTrustee);
    static_cast<void>(pSuccessfulAuditedRights);
    static_cast<void>(pFailedAuditRights);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_GetAuditedPermissionsFromAclW(void* pacl, void* pTrustee, std::uint32_t* pSuccessfulAuditedRights, std::uint32_t* pFailedAuditRights) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(pacl);
    static_cast<void>(pTrustee);
    static_cast<void>(pSuccessfulAuditedRights);
    static_cast<void>(pFailedAuditRights);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetCurrentHwProfileA(std::uint64_t lpHwProfileInfo) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(lpHwProfileInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetCurrentHwProfileW(std::uint64_t lpHwProfileInfo) noexcept {
    // Refused: the user environment and policy.
    //
    // a user profile and the policy that shapes it are built by the logon
    // process, which this runtime is not
    static_cast<void>(lpHwProfileInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_GetDynamicTimeZoneInformationEffectiveYears(void* lpTimeZoneInformation, std::uint32_t* FirstYear, std::uint32_t* LastYear) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(lpTimeZoneInformation);
    static_cast<void>(FirstYear);
    static_cast<void>(LastYear);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetEventLogInformation(void* hEventLog, std::uint32_t dwInfoLevel, void* lpBuffer, std::uint32_t cbBufSize, std::uint32_t* pcbBytesNeeded) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(hEventLog);
    static_cast<void>(dwInfoLevel);
    static_cast<void>(lpBuffer);
    static_cast<void>(cbBufSize);
    static_cast<void>(pcbBytesNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_GetExplicitEntriesFromAclA(void* pacl, std::uint32_t* pcCountOfExplicitEntries, void* pListOfExplicitEntries) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pacl);
    static_cast<void>(pcCountOfExplicitEntries);
    static_cast<void>(pListOfExplicitEntries);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_GetExplicitEntriesFromAclW(void* pacl, std::uint32_t* pcCountOfExplicitEntries, void* pListOfExplicitEntries) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pacl);
    static_cast<void>(pcCountOfExplicitEntries);
    static_cast<void>(pListOfExplicitEntries);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetFileSecurityA(const char* lpFileName, std::uint32_t RequestedInformation, void* pSecurityDescriptor, std::uint32_t nLength, std::uint32_t* lpnLengthNeeded) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(lpFileName);
    static_cast<void>(RequestedInformation);
    static_cast<void>(pSecurityDescriptor);
    static_cast<void>(nLength);
    static_cast<void>(lpnLengthNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetFileSecurityW(const char16_t* lpFileName, std::uint32_t RequestedInformation, void* pSecurityDescriptor, std::uint32_t nLength, std::uint32_t* lpnLengthNeeded) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(lpFileName);
    static_cast<void>(RequestedInformation);
    static_cast<void>(pSecurityDescriptor);
    static_cast<void>(nLength);
    static_cast<void>(lpnLengthNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_GetInheritanceSourceA(char* pObjectName, std::int32_t ObjectType, std::uint32_t SecurityInfo, std::int32_t Container, void** pObjectClassGuids, std::uint32_t GuidCount, void* pAcl, std::uint64_t pfnArray, void* pGenericMapping, std::uint64_t pInheritArray) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(pObjectName);
    static_cast<void>(ObjectType);
    static_cast<void>(SecurityInfo);
    static_cast<void>(Container);
    static_cast<void>(pObjectClassGuids);
    static_cast<void>(GuidCount);
    static_cast<void>(pAcl);
    static_cast<void>(pfnArray);
    static_cast<void>(pGenericMapping);
    static_cast<void>(pInheritArray);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_GetInheritanceSourceW(char16_t* pObjectName, std::int32_t ObjectType, std::uint32_t SecurityInfo, std::int32_t Container, void** pObjectClassGuids, std::uint32_t GuidCount, void* pAcl, std::uint64_t pfnArray, void* pGenericMapping, std::uint64_t pInheritArray) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(pObjectName);
    static_cast<void>(ObjectType);
    static_cast<void>(SecurityInfo);
    static_cast<void>(Container);
    static_cast<void>(pObjectClassGuids);
    static_cast<void>(GuidCount);
    static_cast<void>(pAcl);
    static_cast<void>(pfnArray);
    static_cast<void>(pGenericMapping);
    static_cast<void>(pInheritArray);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetKernelObjectSecurity(void* Handle, std::uint32_t RequestedInformation, void* pSecurityDescriptor, std::uint32_t nLength, std::uint32_t* lpnLengthNeeded) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(Handle);
    static_cast<void>(RequestedInformation);
    static_cast<void>(pSecurityDescriptor);
    static_cast<void>(nLength);
    static_cast<void>(lpnLengthNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kadvapi32G_GetMultipleTrusteeA(void* pTrustee) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetMultipleTrusteeOperationA(void* pTrustee) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetMultipleTrusteeOperationW(void* pTrustee) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kadvapi32G_GetMultipleTrusteeW(void* pTrustee) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_GetNamedSecurityInfoA(const char* pObjectName, std::int32_t ObjectType, std::uint32_t SecurityInfo, void* ppsidOwner, void* ppsidGroup, void* ppDacl, void* ppSacl, void* ppSecurityDescriptor) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pObjectName);
    static_cast<void>(ObjectType);
    static_cast<void>(SecurityInfo);
    static_cast<void>(ppsidOwner);
    static_cast<void>(ppsidGroup);
    static_cast<void>(ppDacl);
    static_cast<void>(ppSacl);
    static_cast<void>(ppSecurityDescriptor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_GetNamedSecurityInfoW(const char16_t* pObjectName, std::int32_t ObjectType, std::uint32_t SecurityInfo, void* ppsidOwner, void* ppsidGroup, void* ppDacl, void* ppSacl, void* ppSecurityDescriptor) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pObjectName);
    static_cast<void>(ObjectType);
    static_cast<void>(SecurityInfo);
    static_cast<void>(ppsidOwner);
    static_cast<void>(ppsidGroup);
    static_cast<void>(ppDacl);
    static_cast<void>(ppSacl);
    static_cast<void>(ppSecurityDescriptor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetNumberOfEventLogRecords(void* hEventLog, std::uint32_t* NumberOfRecords) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(hEventLog);
    static_cast<void>(NumberOfRecords);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetOldestEventLogRecord(void* hEventLog, std::uint32_t* OldestRecord) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(hEventLog);
    static_cast<void>(OldestRecord);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetPrivateObjectSecurity(void* ObjectDescriptor, std::uint32_t SecurityInformation, void* ResultantDescriptor, std::uint32_t DescriptorLength, std::uint32_t* ReturnLength) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(ObjectDescriptor);
    static_cast<void>(SecurityInformation);
    static_cast<void>(ResultantDescriptor);
    static_cast<void>(DescriptorLength);
    static_cast<void>(ReturnLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_GetSecurityDescriptorRMControl(void* SecurityDescriptor, std::uint8_t* RMControl) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(RMControl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetServiceDisplayNameA(void* hSCManager, const char* lpServiceName, char* lpDisplayName, std::uint32_t* lpcchBuffer) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hSCManager);
    static_cast<void>(lpServiceName);
    static_cast<void>(lpDisplayName);
    static_cast<void>(lpcchBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetServiceDisplayNameW(void* hSCManager, const char16_t* lpServiceName, char16_t* lpDisplayName, std::uint32_t* lpcchBuffer) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hSCManager);
    static_cast<void>(lpServiceName);
    static_cast<void>(lpDisplayName);
    static_cast<void>(lpcchBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetServiceKeyNameA(void* hSCManager, const char* lpDisplayName, char* lpServiceName, std::uint32_t* lpcchBuffer) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hSCManager);
    static_cast<void>(lpDisplayName);
    static_cast<void>(lpServiceName);
    static_cast<void>(lpcchBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetServiceKeyNameW(void* hSCManager, const char16_t* lpDisplayName, char16_t* lpServiceName, std::uint32_t* lpcchBuffer) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hSCManager);
    static_cast<void>(lpDisplayName);
    static_cast<void>(lpServiceName);
    static_cast<void>(lpcchBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetTrusteeFormA(void* pTrustee) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetTrusteeFormW(void* pTrustee) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) char* kadvapi32G_GetTrusteeNameA(void* pTrustee) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char16_t* kadvapi32G_GetTrusteeNameW(void* pTrustee) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetTrusteeTypeA(void* pTrustee) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetTrusteeTypeW(void* pTrustee) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pTrustee);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_GetWindowsAccountDomainSid(void* pSid, void* pDomainSid, std::uint32_t* cbDomainSid) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pSid);
    static_cast<void>(pDomainSid);
    static_cast<void>(cbDomainSid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_InitializeSid(void* Sid, void* pIdentifierAuthority, std::uint8_t nSubAuthorityCount) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(Sid);
    static_cast<void>(pIdentifierAuthority);
    static_cast<void>(nSubAuthorityCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_InitiateShutdownA(char* lpMachineName, char* lpMessage, std::uint32_t dwGracePeriod, std::uint32_t dwShutdownFlags, std::uint32_t dwReason) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(lpMachineName);
    static_cast<void>(lpMessage);
    static_cast<void>(dwGracePeriod);
    static_cast<void>(dwShutdownFlags);
    static_cast<void>(dwReason);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_InitiateShutdownW(char16_t* lpMachineName, char16_t* lpMessage, std::uint32_t dwGracePeriod, std::uint32_t dwShutdownFlags, std::uint32_t dwReason) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(lpMachineName);
    static_cast<void>(lpMessage);
    static_cast<void>(dwGracePeriod);
    static_cast<void>(dwShutdownFlags);
    static_cast<void>(dwReason);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_InitiateSystemShutdownA(char* lpMachineName, char* lpMessage, std::uint32_t dwTimeout, std::int32_t bForceAppsClosed, std::int32_t bRebootAfterShutdown) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(lpMachineName);
    static_cast<void>(lpMessage);
    static_cast<void>(dwTimeout);
    static_cast<void>(bForceAppsClosed);
    static_cast<void>(bRebootAfterShutdown);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_InitiateSystemShutdownExA(char* lpMachineName, char* lpMessage, std::uint32_t dwTimeout, std::int32_t bForceAppsClosed, std::int32_t bRebootAfterShutdown, std::uint32_t dwReason) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(lpMachineName);
    static_cast<void>(lpMessage);
    static_cast<void>(dwTimeout);
    static_cast<void>(bForceAppsClosed);
    static_cast<void>(bRebootAfterShutdown);
    static_cast<void>(dwReason);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_InitiateSystemShutdownExW(char16_t* lpMachineName, char16_t* lpMessage, std::uint32_t dwTimeout, std::int32_t bForceAppsClosed, std::int32_t bRebootAfterShutdown, std::uint32_t dwReason) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(lpMachineName);
    static_cast<void>(lpMessage);
    static_cast<void>(dwTimeout);
    static_cast<void>(bForceAppsClosed);
    static_cast<void>(bRebootAfterShutdown);
    static_cast<void>(dwReason);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_InitiateSystemShutdownW(char16_t* lpMachineName, char16_t* lpMessage, std::uint32_t dwTimeout, std::int32_t bForceAppsClosed, std::int32_t bRebootAfterShutdown) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(lpMachineName);
    static_cast<void>(lpMessage);
    static_cast<void>(dwTimeout);
    static_cast<void>(bForceAppsClosed);
    static_cast<void>(bRebootAfterShutdown);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_IsTextUnicode(const void* lpv, std::int32_t iSize, std::int32_t* lpiResult) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(lpv);
    static_cast<void>(iSize);
    static_cast<void>(lpiResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_IsTokenRestricted(void* TokenHandle) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(TokenHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_IsTokenUntrusted(void* TokenHandle) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(TokenHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_IsValidAcl(void* pAcl) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pAcl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_IsValidSecurityDescriptor(void* pSecurityDescriptor) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pSecurityDescriptor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_IsWellKnownSid(void* pSid, std::int32_t WellKnownSidType) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pSid);
    static_cast<void>(WellKnownSidType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint64_t kadvapi32G_LockServiceDatabase(void* hSCManager) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hSCManager);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LogonUserExA(const char* lpszUsername, const char* lpszDomain, const char* lpszPassword, std::uint32_t dwLogonType, std::uint32_t dwLogonProvider, void** phToken, void* ppLogonSid, void** ppProfileBuffer, std::uint32_t* pdwProfileLength, std::uint64_t pQuotaLimits) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(lpszUsername);
    static_cast<void>(lpszDomain);
    static_cast<void>(lpszPassword);
    static_cast<void>(dwLogonType);
    static_cast<void>(dwLogonProvider);
    static_cast<void>(phToken);
    static_cast<void>(ppLogonSid);
    static_cast<void>(ppProfileBuffer);
    static_cast<void>(pdwProfileLength);
    static_cast<void>(pQuotaLimits);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LogonUserExW(const char16_t* lpszUsername, const char16_t* lpszDomain, const char16_t* lpszPassword, std::uint32_t dwLogonType, std::uint32_t dwLogonProvider, void** phToken, void* ppLogonSid, void** ppProfileBuffer, std::uint32_t* pdwProfileLength, std::uint64_t pQuotaLimits) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(lpszUsername);
    static_cast<void>(lpszDomain);
    static_cast<void>(lpszPassword);
    static_cast<void>(dwLogonType);
    static_cast<void>(dwLogonProvider);
    static_cast<void>(phToken);
    static_cast<void>(ppLogonSid);
    static_cast<void>(ppProfileBuffer);
    static_cast<void>(pdwProfileLength);
    static_cast<void>(pQuotaLimits);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_LookupSecurityDescriptorPartsA(void* ppOwner, void* ppGroup, std::uint32_t* pcCountOfAccessEntries, void* ppListOfAccessEntries, std::uint32_t* pcCountOfAuditEntries, void* ppListOfAuditEntries, void* pSD) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(ppOwner);
    static_cast<void>(ppGroup);
    static_cast<void>(pcCountOfAccessEntries);
    static_cast<void>(ppListOfAccessEntries);
    static_cast<void>(pcCountOfAuditEntries);
    static_cast<void>(ppListOfAuditEntries);
    static_cast<void>(pSD);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_LookupSecurityDescriptorPartsW(void* ppOwner, void* ppGroup, std::uint32_t* pcCountOfAccessEntries, void* ppListOfAccessEntries, std::uint32_t* pcCountOfAuditEntries, void* ppListOfAuditEntries, void* pSD) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(ppOwner);
    static_cast<void>(ppGroup);
    static_cast<void>(pcCountOfAccessEntries);
    static_cast<void>(ppListOfAccessEntries);
    static_cast<void>(pcCountOfAuditEntries);
    static_cast<void>(ppListOfAuditEntries);
    static_cast<void>(pSD);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaAddAccountRights(void* PolicyHandle, void* AccountSid, void* UserRights, std::uint32_t CountOfRights) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(AccountSid);
    static_cast<void>(UserRights);
    static_cast<void>(CountOfRights);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaCreateTrustedDomainEx(void* PolicyHandle, std::uint64_t TrustedDomainInformation, std::uint64_t AuthenticationInformation, std::uint32_t DesiredAccess, void* TrustedDomainHandle) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(TrustedDomainInformation);
    static_cast<void>(AuthenticationInformation);
    static_cast<void>(DesiredAccess);
    static_cast<void>(TrustedDomainHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaDeleteTrustedDomain(void* PolicyHandle, void* TrustedDomainSid) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(TrustedDomainSid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaEnumerateAccountRights(void* PolicyHandle, void* AccountSid, void* UserRights, std::uint32_t* CountOfRights) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(AccountSid);
    static_cast<void>(UserRights);
    static_cast<void>(CountOfRights);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaEnumerateAccountsWithUserRight(void* PolicyHandle, void* UserRight, void** Buffer, std::uint32_t* CountReturned) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(UserRight);
    static_cast<void>(Buffer);
    static_cast<void>(CountReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaEnumerateTrustedDomains(void* PolicyHandle, std::uint64_t EnumerationContext, void** Buffer, std::uint32_t PreferedMaximumLength, std::uint32_t* CountReturned) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(EnumerationContext);
    static_cast<void>(Buffer);
    static_cast<void>(PreferedMaximumLength);
    static_cast<void>(CountReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaEnumerateTrustedDomainsEx(void* PolicyHandle, std::uint64_t EnumerationContext, void** Buffer, std::uint32_t PreferedMaximumLength, std::uint32_t* CountReturned) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(EnumerationContext);
    static_cast<void>(Buffer);
    static_cast<void>(PreferedMaximumLength);
    static_cast<void>(CountReturned);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaFreeMemory(void* Buffer) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(Buffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaGetAppliedCAPIDs(void* SystemName, void** CAPIDs, std::uint32_t* CAPIDCount) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(SystemName);
    static_cast<void>(CAPIDs);
    static_cast<void>(CAPIDCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaLookupNames(void* PolicyHandle, std::uint32_t Count, void* Names, void** ReferencedDomains, void* Sids) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(Count);
    static_cast<void>(Names);
    static_cast<void>(ReferencedDomains);
    static_cast<void>(Sids);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaLookupNames2(void* PolicyHandle, std::uint32_t Flags, std::uint32_t Count, void* Names, void** ReferencedDomains, void* Sids) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(Flags);
    static_cast<void>(Count);
    static_cast<void>(Names);
    static_cast<void>(ReferencedDomains);
    static_cast<void>(Sids);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaLookupSids(void* PolicyHandle, std::uint32_t Count, void* Sids, void** ReferencedDomains, void* Names) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(Count);
    static_cast<void>(Sids);
    static_cast<void>(ReferencedDomains);
    static_cast<void>(Names);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaLookupSids2(void* PolicyHandle, std::uint32_t LookupOptions, std::uint32_t Count, void* Sids, void** ReferencedDomains, void* Names) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(LookupOptions);
    static_cast<void>(Count);
    static_cast<void>(Sids);
    static_cast<void>(ReferencedDomains);
    static_cast<void>(Names);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_LsaNtStatusToWinError(std::int32_t Status) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(Status);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaOpenTrustedDomainByName(void* PolicyHandle, void* TrustedDomainName, std::uint32_t DesiredAccess, void* TrustedDomainHandle) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(TrustedDomainName);
    static_cast<void>(DesiredAccess);
    static_cast<void>(TrustedDomainHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaQueryCAPs(void* CAPIDs, std::uint32_t CAPIDCount, void* CAPs, std::uint32_t* CAPCount) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(CAPIDs);
    static_cast<void>(CAPIDCount);
    static_cast<void>(CAPs);
    static_cast<void>(CAPCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaQueryDomainInformationPolicy(void* PolicyHandle, std::uint64_t InformationClass, void** Buffer) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(InformationClass);
    static_cast<void>(Buffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaQueryForestTrustInformation(void* PolicyHandle, void* TrustedDomainName, void* ForestTrustInfo) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(TrustedDomainName);
    static_cast<void>(ForestTrustInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaQueryInformationPolicy(void* PolicyHandle, std::uint64_t InformationClass, void** Buffer) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(InformationClass);
    static_cast<void>(Buffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaQueryTrustedDomainInfo(void* PolicyHandle, void* TrustedDomainSid, std::int32_t InformationClass, void** Buffer) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(TrustedDomainSid);
    static_cast<void>(InformationClass);
    static_cast<void>(Buffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaQueryTrustedDomainInfoByName(void* PolicyHandle, void* TrustedDomainName, std::int32_t InformationClass, void** Buffer) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(TrustedDomainName);
    static_cast<void>(InformationClass);
    static_cast<void>(Buffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaRemoveAccountRights(void* PolicyHandle, void* AccountSid, std::uint8_t AllRights, void* UserRights, std::uint32_t CountOfRights) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(AccountSid);
    static_cast<void>(AllRights);
    static_cast<void>(UserRights);
    static_cast<void>(CountOfRights);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaRetrievePrivateData(void* PolicyHandle, void* KeyName, void* PrivateData) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(KeyName);
    static_cast<void>(PrivateData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaSetCAPs(void* CAPDNs, std::uint32_t CAPDNCount, std::uint32_t Flags) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(CAPDNs);
    static_cast<void>(CAPDNCount);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaSetDomainInformationPolicy(void* PolicyHandle, std::uint64_t InformationClass, void* Buffer) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(InformationClass);
    static_cast<void>(Buffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaSetForestTrustInformation(void* PolicyHandle, void* TrustedDomainName, std::uint64_t ForestTrustInfo, std::uint8_t CheckOnly, void* CollisionInfo) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(TrustedDomainName);
    static_cast<void>(ForestTrustInfo);
    static_cast<void>(CheckOnly);
    static_cast<void>(CollisionInfo);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaSetInformationPolicy(void* PolicyHandle, std::uint64_t InformationClass, void* Buffer) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(InformationClass);
    static_cast<void>(Buffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaSetTrustedDomainInfoByName(void* PolicyHandle, void* TrustedDomainName, std::int32_t InformationClass, void* Buffer) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(TrustedDomainName);
    static_cast<void>(InformationClass);
    static_cast<void>(Buffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaSetTrustedDomainInformation(void* PolicyHandle, void* TrustedDomainSid, std::int32_t InformationClass, void* Buffer) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(TrustedDomainSid);
    static_cast<void>(InformationClass);
    static_cast<void>(Buffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_LsaStorePrivateData(void* PolicyHandle, void* KeyName, void* PrivateData) noexcept {
    // Refused: the security packages.
    //
    // an authentication package is loaded into the process by the local
    // security authority; there is no such authority here
    static_cast<void>(PolicyHandle);
    static_cast<void>(KeyName);
    static_cast<void>(PrivateData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_MakeAbsoluteSD(void* pSelfRelativeSecurityDescriptor, void* pAbsoluteSecurityDescriptor, std::uint32_t* lpdwAbsoluteSecurityDescriptorSize, void* pDacl, std::uint32_t* lpdwDaclSize, void* pSacl, std::uint32_t* lpdwSaclSize, void* pOwner, std::uint32_t* lpdwOwnerSize, void* pPrimaryGroup, std::uint32_t* lpdwPrimaryGroupSize) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(pSelfRelativeSecurityDescriptor);
    static_cast<void>(pAbsoluteSecurityDescriptor);
    static_cast<void>(lpdwAbsoluteSecurityDescriptorSize);
    static_cast<void>(pDacl);
    static_cast<void>(lpdwDaclSize);
    static_cast<void>(pSacl);
    static_cast<void>(lpdwSaclSize);
    static_cast<void>(pOwner);
    static_cast<void>(lpdwOwnerSize);
    static_cast<void>(pPrimaryGroup);
    static_cast<void>(lpdwPrimaryGroupSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_MakeSelfRelativeSD(void* pAbsoluteSecurityDescriptor, void* pSelfRelativeSecurityDescriptor, std::uint32_t* lpdwBufferLength) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(pAbsoluteSecurityDescriptor);
    static_cast<void>(pSelfRelativeSecurityDescriptor);
    static_cast<void>(lpdwBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_NotifyBootConfigStatus(std::int32_t BootAcceptable) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(BootAcceptable);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_NotifyChangeEventLog(void* hEventLog, void* hEvent) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(hEventLog);
    static_cast<void>(hEvent);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_NotifyServiceStatusChangeA(void* hService, std::uint32_t dwNotifyMask, std::uint64_t pNotifyBuffer) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hService);
    static_cast<void>(dwNotifyMask);
    static_cast<void>(pNotifyBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_NotifyServiceStatusChangeW(void* hService, std::uint32_t dwNotifyMask, std::uint64_t pNotifyBuffer) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hService);
    static_cast<void>(dwNotifyMask);
    static_cast<void>(pNotifyBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ObjectCloseAuditAlarmA(const char* SubsystemName, void* HandleId, std::int32_t GenerateOnClose) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SubsystemName);
    static_cast<void>(HandleId);
    static_cast<void>(GenerateOnClose);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ObjectCloseAuditAlarmW(const char16_t* SubsystemName, void* HandleId, std::int32_t GenerateOnClose) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SubsystemName);
    static_cast<void>(HandleId);
    static_cast<void>(GenerateOnClose);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ObjectDeleteAuditAlarmA(const char* SubsystemName, void* HandleId, std::int32_t GenerateOnClose) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SubsystemName);
    static_cast<void>(HandleId);
    static_cast<void>(GenerateOnClose);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ObjectDeleteAuditAlarmW(const char16_t* SubsystemName, void* HandleId, std::int32_t GenerateOnClose) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SubsystemName);
    static_cast<void>(HandleId);
    static_cast<void>(GenerateOnClose);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ObjectOpenAuditAlarmA(const char* SubsystemName, void* HandleId, char* ObjectTypeName, char* ObjectName, void* pSecurityDescriptor, void* ClientToken, std::uint32_t DesiredAccess, std::uint32_t GrantedAccess, void* Privileges, std::int32_t ObjectCreation, std::int32_t AccessGranted, std::int32_t* GenerateOnClose) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SubsystemName);
    static_cast<void>(HandleId);
    static_cast<void>(ObjectTypeName);
    static_cast<void>(ObjectName);
    static_cast<void>(pSecurityDescriptor);
    static_cast<void>(ClientToken);
    static_cast<void>(DesiredAccess);
    static_cast<void>(GrantedAccess);
    static_cast<void>(Privileges);
    static_cast<void>(ObjectCreation);
    static_cast<void>(AccessGranted);
    static_cast<void>(GenerateOnClose);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ObjectOpenAuditAlarmW(const char16_t* SubsystemName, void* HandleId, char16_t* ObjectTypeName, char16_t* ObjectName, void* pSecurityDescriptor, void* ClientToken, std::uint32_t DesiredAccess, std::uint32_t GrantedAccess, void* Privileges, std::int32_t ObjectCreation, std::int32_t AccessGranted, std::int32_t* GenerateOnClose) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SubsystemName);
    static_cast<void>(HandleId);
    static_cast<void>(ObjectTypeName);
    static_cast<void>(ObjectName);
    static_cast<void>(pSecurityDescriptor);
    static_cast<void>(ClientToken);
    static_cast<void>(DesiredAccess);
    static_cast<void>(GrantedAccess);
    static_cast<void>(Privileges);
    static_cast<void>(ObjectCreation);
    static_cast<void>(AccessGranted);
    static_cast<void>(GenerateOnClose);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ObjectPrivilegeAuditAlarmA(const char* SubsystemName, void* HandleId, void* ClientToken, std::uint32_t DesiredAccess, void* Privileges, std::int32_t AccessGranted) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SubsystemName);
    static_cast<void>(HandleId);
    static_cast<void>(ClientToken);
    static_cast<void>(DesiredAccess);
    static_cast<void>(Privileges);
    static_cast<void>(AccessGranted);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ObjectPrivilegeAuditAlarmW(const char16_t* SubsystemName, void* HandleId, void* ClientToken, std::uint32_t DesiredAccess, void* Privileges, std::int32_t AccessGranted) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(SubsystemName);
    static_cast<void>(HandleId);
    static_cast<void>(ClientToken);
    static_cast<void>(DesiredAccess);
    static_cast<void>(Privileges);
    static_cast<void>(AccessGranted);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kadvapi32G_OpenBackupEventLogA(const char* lpUNCServerName, const char* lpFileName) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(lpUNCServerName);
    static_cast<void>(lpFileName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kadvapi32G_OpenBackupEventLogW(const char16_t* lpUNCServerName, const char16_t* lpFileName) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(lpUNCServerName);
    static_cast<void>(lpFileName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_OpenEncryptedFileRawA(const char* lpFileName, std::uint32_t ulFlags, void** pvContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(lpFileName);
    static_cast<void>(ulFlags);
    static_cast<void>(pvContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_OpenEncryptedFileRawW(const char16_t* lpFileName, std::uint32_t ulFlags, void** pvContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(lpFileName);
    static_cast<void>(ulFlags);
    static_cast<void>(pvContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kadvapi32G_OpenEventLogA(const char* lpUNCServerName, const char* lpSourceName) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(lpUNCServerName);
    static_cast<void>(lpSourceName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kadvapi32G_OpenEventLogW(const char16_t* lpUNCServerName, const char16_t* lpSourceName) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(lpUNCServerName);
    static_cast<void>(lpSourceName);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_OperationEnd(void* OperationEndParams) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(OperationEndParams);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_OperationStart(void* OperationStartParams) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(OperationStartParams);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_PrivilegedServiceAuditAlarmA(const char* SubsystemName, const char* ServiceName, void* ClientToken, void* Privileges, std::int32_t AccessGranted) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(SubsystemName);
    static_cast<void>(ServiceName);
    static_cast<void>(ClientToken);
    static_cast<void>(Privileges);
    static_cast<void>(AccessGranted);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_PrivilegedServiceAuditAlarmW(const char16_t* SubsystemName, const char16_t* ServiceName, void* ClientToken, void* Privileges, std::int32_t AccessGranted) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(SubsystemName);
    static_cast<void>(ServiceName);
    static_cast<void>(ClientToken);
    static_cast<void>(Privileges);
    static_cast<void>(AccessGranted);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_QueryRecoveryAgentsOnEncryptedFile(const char16_t* lpFileName, void* pRecoveryAgents) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(lpFileName);
    static_cast<void>(pRecoveryAgents);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_QuerySecurityAccessMask(std::uint32_t SecurityInformation, std::uint32_t* DesiredAccess) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(SecurityInformation);
    static_cast<void>(DesiredAccess);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_QueryUsersOnEncryptedFile(const char16_t* lpFileName, void* pUsers) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(lpFileName);
    static_cast<void>(pUsers);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_ReadEncryptedFileRaw(std::uint64_t pfExportCallback, void* pvCallbackContext, void* pvContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pfExportCallback);
    static_cast<void>(pvCallbackContext);
    static_cast<void>(pvContext);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ReadEventLogA(void* hEventLog, std::uint32_t dwReadFlags, std::uint32_t dwRecordOffset, void* lpBuffer, std::uint32_t nNumberOfBytesToRead, std::uint32_t* pnBytesRead, std::uint32_t* pnMinNumberOfBytesNeeded) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(hEventLog);
    static_cast<void>(dwReadFlags);
    static_cast<void>(dwRecordOffset);
    static_cast<void>(lpBuffer);
    static_cast<void>(nNumberOfBytesToRead);
    static_cast<void>(pnBytesRead);
    static_cast<void>(pnMinNumberOfBytesNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ReadEventLogW(void* hEventLog, std::uint32_t dwReadFlags, std::uint32_t dwRecordOffset, void* lpBuffer, std::uint32_t nNumberOfBytesToRead, std::uint32_t* pnBytesRead, std::uint32_t* pnMinNumberOfBytesNeeded) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(hEventLog);
    static_cast<void>(dwReadFlags);
    static_cast<void>(dwRecordOffset);
    static_cast<void>(lpBuffer);
    static_cast<void>(nNumberOfBytesToRead);
    static_cast<void>(pnBytesRead);
    static_cast<void>(pnMinNumberOfBytesNeeded);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_RegConnectRegistryExA(const char* lpMachineName, void* hKey, std::uint32_t Flags, void** phkResult) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(lpMachineName);
    static_cast<void>(hKey);
    static_cast<void>(Flags);
    static_cast<void>(phkResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_RegConnectRegistryExW(const char16_t* lpMachineName, void* hKey, std::uint32_t Flags, void** phkResult) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(lpMachineName);
    static_cast<void>(hKey);
    static_cast<void>(Flags);
    static_cast<void>(phkResult);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_RegDeleteKeyTransactedA(void* hKey, const char* lpSubKey, std::uint32_t samDesired, std::uint32_t Reserved, void* hTransaction, void* pExtendedParameter) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(hKey);
    static_cast<void>(lpSubKey);
    static_cast<void>(samDesired);
    static_cast<void>(Reserved);
    static_cast<void>(hTransaction);
    static_cast<void>(pExtendedParameter);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_RegDeleteKeyTransactedW(void* hKey, const char16_t* lpSubKey, std::uint32_t samDesired, std::uint32_t Reserved, void* hTransaction, void* pExtendedParameter) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(hKey);
    static_cast<void>(lpSubKey);
    static_cast<void>(samDesired);
    static_cast<void>(Reserved);
    static_cast<void>(hTransaction);
    static_cast<void>(pExtendedParameter);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_RegDisablePredefinedCacheEx() noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_RegOpenKeyTransactedA(void* hKey, const char* lpSubKey, std::uint32_t ulOptions, std::uint32_t samDesired, void** phkResult, void* hTransaction, void* pExtendedParameter) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(hKey);
    static_cast<void>(lpSubKey);
    static_cast<void>(ulOptions);
    static_cast<void>(samDesired);
    static_cast<void>(phkResult);
    static_cast<void>(hTransaction);
    static_cast<void>(pExtendedParameter);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_RegOpenKeyTransactedW(void* hKey, const char16_t* lpSubKey, std::uint32_t ulOptions, std::uint32_t samDesired, void** phkResult, void* hTransaction, void* pExtendedParameter) noexcept {
    // Refused: the transactional NTFS and kernel transaction manager.
    //
    // a transaction needs the kernel transaction manager to enlist the file
    // system in it, and there is none here
    static_cast<void>(hKey);
    static_cast<void>(lpSubKey);
    static_cast<void>(ulOptions);
    static_cast<void>(samDesired);
    static_cast<void>(phkResult);
    static_cast<void>(hTransaction);
    static_cast<void>(pExtendedParameter);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_RemoveUsersFromEncryptedFile(const char16_t* lpFileName, std::uint64_t pHashes) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(lpFileName);
    static_cast<void>(pHashes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ReportEventA(void* hEventLog, std::uint16_t wType, std::uint16_t wCategory, std::uint32_t dwEventID, void* lpUserSid, std::uint16_t wNumStrings, std::uint32_t dwDataSize, const char** lpStrings, void* lpRawData) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(hEventLog);
    static_cast<void>(wType);
    static_cast<void>(wCategory);
    static_cast<void>(dwEventID);
    static_cast<void>(lpUserSid);
    static_cast<void>(wNumStrings);
    static_cast<void>(dwDataSize);
    static_cast<void>(lpStrings);
    static_cast<void>(lpRawData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_ReportEventW(void* hEventLog, std::uint16_t wType, std::uint16_t wCategory, std::uint32_t dwEventID, void* lpUserSid, std::uint16_t wNumStrings, std::uint32_t dwDataSize, const char16_t** lpStrings, void* lpRawData) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(hEventLog);
    static_cast<void>(wType);
    static_cast<void>(wCategory);
    static_cast<void>(dwEventID);
    static_cast<void>(lpUserSid);
    static_cast<void>(wNumStrings);
    static_cast<void>(dwDataSize);
    static_cast<void>(lpStrings);
    static_cast<void>(lpRawData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_SetAclInformation(void* pAcl, void* pAclInformation, std::uint32_t nAclInformationLength, std::int32_t dwAclInformationClass) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pAcl);
    static_cast<void>(pAclInformation);
    static_cast<void>(nAclInformationLength);
    static_cast<void>(dwAclInformationClass);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_SetFileSecurityA(const char* lpFileName, std::uint32_t SecurityInformation, void* pSecurityDescriptor) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(lpFileName);
    static_cast<void>(SecurityInformation);
    static_cast<void>(pSecurityDescriptor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_SetFileSecurityW(const char16_t* lpFileName, std::uint32_t SecurityInformation, void* pSecurityDescriptor) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(lpFileName);
    static_cast<void>(SecurityInformation);
    static_cast<void>(pSecurityDescriptor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_SetKernelObjectSecurity(void* Handle, std::uint32_t SecurityInformation, void* SecurityDescriptor) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(Handle);
    static_cast<void>(SecurityInformation);
    static_cast<void>(SecurityDescriptor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_SetNamedSecurityInfoA(char* pObjectName, std::int32_t ObjectType, std::uint32_t SecurityInfo, void* psidOwner, void* psidGroup, void* pDacl, void* pSacl) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pObjectName);
    static_cast<void>(ObjectType);
    static_cast<void>(SecurityInfo);
    static_cast<void>(psidOwner);
    static_cast<void>(psidGroup);
    static_cast<void>(pDacl);
    static_cast<void>(pSacl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_SetNamedSecurityInfoW(char16_t* pObjectName, std::int32_t ObjectType, std::uint32_t SecurityInfo, void* psidOwner, void* psidGroup, void* pDacl, void* pSacl) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pObjectName);
    static_cast<void>(ObjectType);
    static_cast<void>(SecurityInfo);
    static_cast<void>(psidOwner);
    static_cast<void>(psidGroup);
    static_cast<void>(pDacl);
    static_cast<void>(pSacl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_SetPrivateObjectSecurity(std::uint32_t SecurityInformation, void* ModificationDescriptor, void* ObjectsSecurityDescriptor, void* GenericMapping, void* Token) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(SecurityInformation);
    static_cast<void>(ModificationDescriptor);
    static_cast<void>(ObjectsSecurityDescriptor);
    static_cast<void>(GenericMapping);
    static_cast<void>(Token);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_SetPrivateObjectSecurityEx(std::uint32_t SecurityInformation, void* ModificationDescriptor, void* ObjectsSecurityDescriptor, std::uint32_t AutoInheritFlags, void* GenericMapping, void* Token) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(SecurityInformation);
    static_cast<void>(ModificationDescriptor);
    static_cast<void>(ObjectsSecurityDescriptor);
    static_cast<void>(AutoInheritFlags);
    static_cast<void>(GenericMapping);
    static_cast<void>(Token);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kadvapi32G_SetSecurityAccessMask(std::uint32_t SecurityInformation, std::uint32_t* DesiredAccess) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(SecurityInformation);
    static_cast<void>(DesiredAccess);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_SetSecurityDescriptorRMControl(void* SecurityDescriptor, std::uint8_t* RMControl) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(SecurityDescriptor);
    static_cast<void>(RMControl);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_SetServiceObjectSecurity(void* hService, std::uint32_t dwSecurityInformation, void* lpSecurityDescriptor) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hService);
    static_cast<void>(dwSecurityInformation);
    static_cast<void>(lpSecurityDescriptor);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_SetServiceStatus(void* hServiceStatus, std::uint64_t lpServiceStatus) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(hServiceStatus);
    static_cast<void>(lpServiceStatus);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_SetUserFileEncryptionKey(std::uint64_t pEncryptionCertificate) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pEncryptionCertificate);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kadvapi32G_SystemFunction036(void* RandomBuffer, std::uint32_t RandomBufferLength) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(RandomBuffer);
    static_cast<void>(RandomBufferLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_SystemFunction040(void* Memory, std::uint32_t MemorySize, std::uint32_t OptionFlags) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(Memory);
    static_cast<void>(MemorySize);
    static_cast<void>(OptionFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_SystemFunction041(void* Memory, std::uint32_t MemorySize, std::uint32_t OptionFlags) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(Memory);
    static_cast<void>(MemorySize);
    static_cast<void>(OptionFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_TreeResetNamedSecurityInfoA(char* pObjectName, std::int32_t ObjectType, std::uint32_t SecurityInfo, void* pOwner, void* pGroup, void* pDacl, void* pSacl, std::int32_t KeepExplicit, void* fnProgress, std::uint32_t ProgressInvokeSetting, void* Args) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pObjectName);
    static_cast<void>(ObjectType);
    static_cast<void>(SecurityInfo);
    static_cast<void>(pOwner);
    static_cast<void>(pGroup);
    static_cast<void>(pDacl);
    static_cast<void>(pSacl);
    static_cast<void>(KeepExplicit);
    static_cast<void>(fnProgress);
    static_cast<void>(ProgressInvokeSetting);
    static_cast<void>(Args);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_TreeResetNamedSecurityInfoW(char16_t* pObjectName, std::int32_t ObjectType, std::uint32_t SecurityInfo, void* pOwner, void* pGroup, void* pDacl, void* pSacl, std::int32_t KeepExplicit, void* fnProgress, std::uint32_t ProgressInvokeSetting, void* Args) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pObjectName);
    static_cast<void>(ObjectType);
    static_cast<void>(SecurityInfo);
    static_cast<void>(pOwner);
    static_cast<void>(pGroup);
    static_cast<void>(pDacl);
    static_cast<void>(pSacl);
    static_cast<void>(KeepExplicit);
    static_cast<void>(fnProgress);
    static_cast<void>(ProgressInvokeSetting);
    static_cast<void>(Args);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_TreeSetNamedSecurityInfoA(char* pObjectName, std::int32_t ObjectType, std::uint32_t SecurityInfo, void* pOwner, void* pGroup, void* pDacl, void* pSacl, std::uint32_t dwAction, void* fnProgress, std::uint32_t ProgressInvokeSetting, void* Args) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pObjectName);
    static_cast<void>(ObjectType);
    static_cast<void>(SecurityInfo);
    static_cast<void>(pOwner);
    static_cast<void>(pGroup);
    static_cast<void>(pDacl);
    static_cast<void>(pSacl);
    static_cast<void>(dwAction);
    static_cast<void>(fnProgress);
    static_cast<void>(ProgressInvokeSetting);
    static_cast<void>(Args);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_TreeSetNamedSecurityInfoW(char16_t* pObjectName, std::int32_t ObjectType, std::uint32_t SecurityInfo, void* pOwner, void* pGroup, void* pDacl, void* pSacl, std::uint32_t dwAction, void* fnProgress, std::uint32_t ProgressInvokeSetting, void* Args) noexcept {
    // Refused: the security subsystem.
    //
    // tokens, descriptors and access checks are kernel objects backed by a
    // security database; this runtime answers the registry and file surface
    // without a security model behind it
    static_cast<void>(pObjectName);
    static_cast<void>(ObjectType);
    static_cast<void>(SecurityInfo);
    static_cast<void>(pOwner);
    static_cast<void>(pGroup);
    static_cast<void>(pDacl);
    static_cast<void>(pSacl);
    static_cast<void>(dwAction);
    static_cast<void>(fnProgress);
    static_cast<void>(ProgressInvokeSetting);
    static_cast<void>(Args);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_UnlockServiceDatabase(std::uint64_t ScLock) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(ScLock);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kadvapi32G_Wow64Win32ApiEntry(std::uint32_t dwFuncNumber, std::uint32_t dwFlag, std::uint32_t dwRes) noexcept {
    // Refused: a subsystem of the security and service layer.
    //
    // the call reaches the service database, the audit policy or the security
    // database, none of which is here
    static_cast<void>(dwFuncNumber);
    static_cast<void>(dwFlag);
    static_cast<void>(dwRes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kadvapi32G_WriteEncryptedFileRaw(std::uint64_t pfImportCallback, void* pvCallbackContext, void* pvContext) noexcept {
    // Refused: the cryptography providers.
    //
    // a provider selected by the platform is a kernel and service arrangement;
    // the primitives this runtime implements are its own and are reached
    // through their own entry points
    static_cast<void>(pfImportCallback);
    static_cast<void>(pvCallbackContext);
    static_cast<void>(pvContext);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_advapi32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("AbortSystemShutdownA", reinterpret_cast<void*>(&kadvapi32G_AbortSystemShutdownA));
    e("AbortSystemShutdownW", reinterpret_cast<void*>(&kadvapi32G_AbortSystemShutdownW));
    e("AccessCheckAndAuditAlarmA", reinterpret_cast<void*>(&kadvapi32G_AccessCheckAndAuditAlarmA));
    e("AccessCheckAndAuditAlarmW", reinterpret_cast<void*>(&kadvapi32G_AccessCheckAndAuditAlarmW));
    e("AccessCheckByType", reinterpret_cast<void*>(&kadvapi32G_AccessCheckByType));
    e("AccessCheckByTypeAndAuditAlarmA", reinterpret_cast<void*>(&kadvapi32G_AccessCheckByTypeAndAuditAlarmA));
    e("AccessCheckByTypeAndAuditAlarmW", reinterpret_cast<void*>(&kadvapi32G_AccessCheckByTypeAndAuditAlarmW));
    e("AccessCheckByTypeResultList", reinterpret_cast<void*>(&kadvapi32G_AccessCheckByTypeResultList));
    e("AccessCheckByTypeResultListAndAuditAlarmA", reinterpret_cast<void*>(&kadvapi32G_AccessCheckByTypeResultListAndAuditAlarmA));
    e("AccessCheckByTypeResultListAndAuditAlarmByHandleA", reinterpret_cast<void*>(&kadvapi32G_AccessCheckByTypeResultListAndAuditAlarmByHandleA));
    e("AccessCheckByTypeResultListAndAuditAlarmByHandleW", reinterpret_cast<void*>(&kadvapi32G_AccessCheckByTypeResultListAndAuditAlarmByHandleW));
    e("AccessCheckByTypeResultListAndAuditAlarmW", reinterpret_cast<void*>(&kadvapi32G_AccessCheckByTypeResultListAndAuditAlarmW));
    e("AddAccessAllowedObjectAce", reinterpret_cast<void*>(&kadvapi32G_AddAccessAllowedObjectAce));
    e("AddAccessDeniedAce", reinterpret_cast<void*>(&kadvapi32G_AddAccessDeniedAce));
    e("AddAccessDeniedAceEx", reinterpret_cast<void*>(&kadvapi32G_AddAccessDeniedAceEx));
    e("AddAccessDeniedObjectAce", reinterpret_cast<void*>(&kadvapi32G_AddAccessDeniedObjectAce));
    e("AddAce", reinterpret_cast<void*>(&kadvapi32G_AddAce));
    e("AddAuditAccessAce", reinterpret_cast<void*>(&kadvapi32G_AddAuditAccessAce));
    e("AddAuditAccessAceEx", reinterpret_cast<void*>(&kadvapi32G_AddAuditAccessAceEx));
    e("AddAuditAccessObjectAce", reinterpret_cast<void*>(&kadvapi32G_AddAuditAccessObjectAce));
    e("AddConditionalAce", reinterpret_cast<void*>(&kadvapi32G_AddConditionalAce));
    e("AddMandatoryAce", reinterpret_cast<void*>(&kadvapi32G_AddMandatoryAce));
    e("AddUsersToEncryptedFile", reinterpret_cast<void*>(&kadvapi32G_AddUsersToEncryptedFile));
    e("AllocateLocallyUniqueId", reinterpret_cast<void*>(&kadvapi32G_AllocateLocallyUniqueId));
    e("AreAnyAccessesGranted", reinterpret_cast<void*>(&kadvapi32G_AreAnyAccessesGranted));
    e("AuditComputeEffectivePolicyBySid", reinterpret_cast<void*>(&kadvapi32G_AuditComputeEffectivePolicyBySid));
    e("AuditComputeEffectivePolicyByToken", reinterpret_cast<void*>(&kadvapi32G_AuditComputeEffectivePolicyByToken));
    e("AuditEnumerateCategories", reinterpret_cast<void*>(&kadvapi32G_AuditEnumerateCategories));
    e("AuditEnumeratePerUserPolicy", reinterpret_cast<void*>(&kadvapi32G_AuditEnumeratePerUserPolicy));
    e("AuditEnumerateSubCategories", reinterpret_cast<void*>(&kadvapi32G_AuditEnumerateSubCategories));
    e("AuditFree", reinterpret_cast<void*>(&kadvapi32G_AuditFree));
    e("AuditLookupCategoryGuidFromCategoryId", reinterpret_cast<void*>(&kadvapi32G_AuditLookupCategoryGuidFromCategoryId));
    e("AuditLookupCategoryIdFromCategoryGuid", reinterpret_cast<void*>(&kadvapi32G_AuditLookupCategoryIdFromCategoryGuid));
    e("AuditLookupCategoryNameA", reinterpret_cast<void*>(&kadvapi32G_AuditLookupCategoryNameA));
    e("AuditLookupCategoryNameW", reinterpret_cast<void*>(&kadvapi32G_AuditLookupCategoryNameW));
    e("AuditLookupSubCategoryNameA", reinterpret_cast<void*>(&kadvapi32G_AuditLookupSubCategoryNameA));
    e("AuditLookupSubCategoryNameW", reinterpret_cast<void*>(&kadvapi32G_AuditLookupSubCategoryNameW));
    e("AuditQueryGlobalSaclA", reinterpret_cast<void*>(&kadvapi32G_AuditQueryGlobalSaclA));
    e("AuditQueryGlobalSaclW", reinterpret_cast<void*>(&kadvapi32G_AuditQueryGlobalSaclW));
    e("AuditQueryPerUserPolicy", reinterpret_cast<void*>(&kadvapi32G_AuditQueryPerUserPolicy));
    e("AuditQuerySecurity", reinterpret_cast<void*>(&kadvapi32G_AuditQuerySecurity));
    e("AuditQuerySystemPolicy", reinterpret_cast<void*>(&kadvapi32G_AuditQuerySystemPolicy));
    e("AuditSetGlobalSaclA", reinterpret_cast<void*>(&kadvapi32G_AuditSetGlobalSaclA));
    e("AuditSetGlobalSaclW", reinterpret_cast<void*>(&kadvapi32G_AuditSetGlobalSaclW));
    e("AuditSetPerUserPolicy", reinterpret_cast<void*>(&kadvapi32G_AuditSetPerUserPolicy));
    e("AuditSetSecurity", reinterpret_cast<void*>(&kadvapi32G_AuditSetSecurity));
    e("AuditSetSystemPolicy", reinterpret_cast<void*>(&kadvapi32G_AuditSetSystemPolicy));
    e("BackupEventLogA", reinterpret_cast<void*>(&kadvapi32G_BackupEventLogA));
    e("BackupEventLogW", reinterpret_cast<void*>(&kadvapi32G_BackupEventLogW));
    e("BuildExplicitAccessWithNameA", reinterpret_cast<void*>(&kadvapi32G_BuildExplicitAccessWithNameA));
    e("BuildExplicitAccessWithNameW", reinterpret_cast<void*>(&kadvapi32G_BuildExplicitAccessWithNameW));
    e("BuildImpersonateExplicitAccessWithNameA", reinterpret_cast<void*>(&kadvapi32G_BuildImpersonateExplicitAccessWithNameA));
    e("BuildImpersonateExplicitAccessWithNameW", reinterpret_cast<void*>(&kadvapi32G_BuildImpersonateExplicitAccessWithNameW));
    e("BuildImpersonateTrusteeA", reinterpret_cast<void*>(&kadvapi32G_BuildImpersonateTrusteeA));
    e("BuildImpersonateTrusteeW", reinterpret_cast<void*>(&kadvapi32G_BuildImpersonateTrusteeW));
    e("BuildSecurityDescriptorA", reinterpret_cast<void*>(&kadvapi32G_BuildSecurityDescriptorA));
    e("BuildSecurityDescriptorW", reinterpret_cast<void*>(&kadvapi32G_BuildSecurityDescriptorW));
    e("BuildTrusteeWithNameA", reinterpret_cast<void*>(&kadvapi32G_BuildTrusteeWithNameA));
    e("BuildTrusteeWithNameW", reinterpret_cast<void*>(&kadvapi32G_BuildTrusteeWithNameW));
    e("BuildTrusteeWithObjectsAndNameA", reinterpret_cast<void*>(&kadvapi32G_BuildTrusteeWithObjectsAndNameA));
    e("BuildTrusteeWithObjectsAndNameW", reinterpret_cast<void*>(&kadvapi32G_BuildTrusteeWithObjectsAndNameW));
    e("BuildTrusteeWithObjectsAndSidA", reinterpret_cast<void*>(&kadvapi32G_BuildTrusteeWithObjectsAndSidA));
    e("BuildTrusteeWithObjectsAndSidW", reinterpret_cast<void*>(&kadvapi32G_BuildTrusteeWithObjectsAndSidW));
    e("BuildTrusteeWithSidA", reinterpret_cast<void*>(&kadvapi32G_BuildTrusteeWithSidA));
    e("BuildTrusteeWithSidW", reinterpret_cast<void*>(&kadvapi32G_BuildTrusteeWithSidW));
    e("ChangeServiceConfig2A", reinterpret_cast<void*>(&kadvapi32G_ChangeServiceConfig2A));
    e("ChangeServiceConfig2W", reinterpret_cast<void*>(&kadvapi32G_ChangeServiceConfig2W));
    e("ChangeServiceConfigA", reinterpret_cast<void*>(&kadvapi32G_ChangeServiceConfigA));
    e("ChangeServiceConfigW", reinterpret_cast<void*>(&kadvapi32G_ChangeServiceConfigW));
    e("CheckForHiberboot", reinterpret_cast<void*>(&kadvapi32G_CheckForHiberboot));
    e("ClearEventLogA", reinterpret_cast<void*>(&kadvapi32G_ClearEventLogA));
    e("ClearEventLogW", reinterpret_cast<void*>(&kadvapi32G_ClearEventLogW));
    e("CloseEncryptedFileRaw", reinterpret_cast<void*>(&kadvapi32G_CloseEncryptedFileRaw));
    e("CloseEventLog", reinterpret_cast<void*>(&kadvapi32G_CloseEventLog));
    e("ControlServiceExA", reinterpret_cast<void*>(&kadvapi32G_ControlServiceExA));
    e("ControlServiceExW", reinterpret_cast<void*>(&kadvapi32G_ControlServiceExW));
    e("ConvertSecurityDescriptorToStringSecurityDescriptorA", reinterpret_cast<void*>(&kadvapi32G_ConvertSecurityDescriptorToStringSecurityDescriptorA));
    e("ConvertSecurityDescriptorToStringSecurityDescriptorW", reinterpret_cast<void*>(&kadvapi32G_ConvertSecurityDescriptorToStringSecurityDescriptorW));
    e("ConvertToAutoInheritPrivateObjectSecurity", reinterpret_cast<void*>(&kadvapi32G_ConvertToAutoInheritPrivateObjectSecurity));
    e("CreatePrivateObjectSecurity", reinterpret_cast<void*>(&kadvapi32G_CreatePrivateObjectSecurity));
    e("CreatePrivateObjectSecurityEx", reinterpret_cast<void*>(&kadvapi32G_CreatePrivateObjectSecurityEx));
    e("CreatePrivateObjectSecurityWithMultipleInheritance", reinterpret_cast<void*>(&kadvapi32G_CreatePrivateObjectSecurityWithMultipleInheritance));
    e("CreateProcessWithLogonW", reinterpret_cast<void*>(&kadvapi32G_CreateProcessWithLogonW));
    e("CreateProcessWithTokenW", reinterpret_cast<void*>(&kadvapi32G_CreateProcessWithTokenW));
    e("CreateRestrictedToken", reinterpret_cast<void*>(&kadvapi32G_CreateRestrictedToken));
    e("CreateWellKnownSid", reinterpret_cast<void*>(&kadvapi32G_CreateWellKnownSid));
    e("CryptContextAddRef", reinterpret_cast<void*>(&kadvapi32G_CryptContextAddRef));
    e("CryptEnumProviderTypesA", reinterpret_cast<void*>(&kadvapi32G_CryptEnumProviderTypesA));
    e("CryptEnumProviderTypesW", reinterpret_cast<void*>(&kadvapi32G_CryptEnumProviderTypesW));
    e("CryptGetUserKey", reinterpret_cast<void*>(&kadvapi32G_CryptGetUserKey));
    e("CryptSetProvParam", reinterpret_cast<void*>(&kadvapi32G_CryptSetProvParam));
    e("CryptSetProviderA", reinterpret_cast<void*>(&kadvapi32G_CryptSetProviderA));
    e("CryptSetProviderExA", reinterpret_cast<void*>(&kadvapi32G_CryptSetProviderExA));
    e("CryptSetProviderExW", reinterpret_cast<void*>(&kadvapi32G_CryptSetProviderExW));
    e("CryptSetProviderW", reinterpret_cast<void*>(&kadvapi32G_CryptSetProviderW));
    e("CveEventWrite", reinterpret_cast<void*>(&kadvapi32G_CveEventWrite));
    e("DecryptFileA", reinterpret_cast<void*>(&kadvapi32G_DecryptFileA));
    e("DecryptFileW", reinterpret_cast<void*>(&kadvapi32G_DecryptFileW));
    e("DeleteAce", reinterpret_cast<void*>(&kadvapi32G_DeleteAce));
    e("DeregisterEventSource", reinterpret_cast<void*>(&kadvapi32G_DeregisterEventSource));
    e("DestroyPrivateObjectSecurity", reinterpret_cast<void*>(&kadvapi32G_DestroyPrivateObjectSecurity));
    e("DuplicateEncryptionInfoFile", reinterpret_cast<void*>(&kadvapi32G_DuplicateEncryptionInfoFile));
    e("EncryptFileA", reinterpret_cast<void*>(&kadvapi32G_EncryptFileA));
    e("EncryptFileW", reinterpret_cast<void*>(&kadvapi32G_EncryptFileW));
    e("EncryptionDisable", reinterpret_cast<void*>(&kadvapi32G_EncryptionDisable));
    e("EnumDependentServicesA", reinterpret_cast<void*>(&kadvapi32G_EnumDependentServicesA));
    e("EnumDependentServicesW", reinterpret_cast<void*>(&kadvapi32G_EnumDependentServicesW));
    e("EnumDynamicTimeZoneInformation", reinterpret_cast<void*>(&kadvapi32G_EnumDynamicTimeZoneInformation));
    e("EqualDomainSid", reinterpret_cast<void*>(&kadvapi32G_EqualDomainSid));
    e("EqualPrefixSid", reinterpret_cast<void*>(&kadvapi32G_EqualPrefixSid));
    e("FileEncryptionStatusA", reinterpret_cast<void*>(&kadvapi32G_FileEncryptionStatusA));
    e("FileEncryptionStatusW", reinterpret_cast<void*>(&kadvapi32G_FileEncryptionStatusW));
    e("FreeEncryptionCertificateHashList", reinterpret_cast<void*>(&kadvapi32G_FreeEncryptionCertificateHashList));
    e("FreeInheritedFromArray", reinterpret_cast<void*>(&kadvapi32G_FreeInheritedFromArray));
    e("GetAuditedPermissionsFromAclA", reinterpret_cast<void*>(&kadvapi32G_GetAuditedPermissionsFromAclA));
    e("GetAuditedPermissionsFromAclW", reinterpret_cast<void*>(&kadvapi32G_GetAuditedPermissionsFromAclW));
    e("GetCurrentHwProfileA", reinterpret_cast<void*>(&kadvapi32G_GetCurrentHwProfileA));
    e("GetCurrentHwProfileW", reinterpret_cast<void*>(&kadvapi32G_GetCurrentHwProfileW));
    e("GetDynamicTimeZoneInformationEffectiveYears", reinterpret_cast<void*>(&kadvapi32G_GetDynamicTimeZoneInformationEffectiveYears));
    e("GetEventLogInformation", reinterpret_cast<void*>(&kadvapi32G_GetEventLogInformation));
    e("GetExplicitEntriesFromAclA", reinterpret_cast<void*>(&kadvapi32G_GetExplicitEntriesFromAclA));
    e("GetExplicitEntriesFromAclW", reinterpret_cast<void*>(&kadvapi32G_GetExplicitEntriesFromAclW));
    e("GetFileSecurityA", reinterpret_cast<void*>(&kadvapi32G_GetFileSecurityA));
    e("GetFileSecurityW", reinterpret_cast<void*>(&kadvapi32G_GetFileSecurityW));
    e("GetInheritanceSourceA", reinterpret_cast<void*>(&kadvapi32G_GetInheritanceSourceA));
    e("GetInheritanceSourceW", reinterpret_cast<void*>(&kadvapi32G_GetInheritanceSourceW));
    e("GetKernelObjectSecurity", reinterpret_cast<void*>(&kadvapi32G_GetKernelObjectSecurity));
    e("GetMultipleTrusteeA", reinterpret_cast<void*>(&kadvapi32G_GetMultipleTrusteeA));
    e("GetMultipleTrusteeOperationA", reinterpret_cast<void*>(&kadvapi32G_GetMultipleTrusteeOperationA));
    e("GetMultipleTrusteeOperationW", reinterpret_cast<void*>(&kadvapi32G_GetMultipleTrusteeOperationW));
    e("GetMultipleTrusteeW", reinterpret_cast<void*>(&kadvapi32G_GetMultipleTrusteeW));
    e("GetNamedSecurityInfoA", reinterpret_cast<void*>(&kadvapi32G_GetNamedSecurityInfoA));
    e("GetNamedSecurityInfoW", reinterpret_cast<void*>(&kadvapi32G_GetNamedSecurityInfoW));
    e("GetNumberOfEventLogRecords", reinterpret_cast<void*>(&kadvapi32G_GetNumberOfEventLogRecords));
    e("GetOldestEventLogRecord", reinterpret_cast<void*>(&kadvapi32G_GetOldestEventLogRecord));
    e("GetPrivateObjectSecurity", reinterpret_cast<void*>(&kadvapi32G_GetPrivateObjectSecurity));
    e("GetSecurityDescriptorRMControl", reinterpret_cast<void*>(&kadvapi32G_GetSecurityDescriptorRMControl));
    e("GetServiceDisplayNameA", reinterpret_cast<void*>(&kadvapi32G_GetServiceDisplayNameA));
    e("GetServiceDisplayNameW", reinterpret_cast<void*>(&kadvapi32G_GetServiceDisplayNameW));
    e("GetServiceKeyNameA", reinterpret_cast<void*>(&kadvapi32G_GetServiceKeyNameA));
    e("GetServiceKeyNameW", reinterpret_cast<void*>(&kadvapi32G_GetServiceKeyNameW));
    e("GetTrusteeFormA", reinterpret_cast<void*>(&kadvapi32G_GetTrusteeFormA));
    e("GetTrusteeFormW", reinterpret_cast<void*>(&kadvapi32G_GetTrusteeFormW));
    e("GetTrusteeNameA", reinterpret_cast<void*>(&kadvapi32G_GetTrusteeNameA));
    e("GetTrusteeNameW", reinterpret_cast<void*>(&kadvapi32G_GetTrusteeNameW));
    e("GetTrusteeTypeA", reinterpret_cast<void*>(&kadvapi32G_GetTrusteeTypeA));
    e("GetTrusteeTypeW", reinterpret_cast<void*>(&kadvapi32G_GetTrusteeTypeW));
    e("GetWindowsAccountDomainSid", reinterpret_cast<void*>(&kadvapi32G_GetWindowsAccountDomainSid));
    e("InitializeSid", reinterpret_cast<void*>(&kadvapi32G_InitializeSid));
    e("InitiateShutdownA", reinterpret_cast<void*>(&kadvapi32G_InitiateShutdownA));
    e("InitiateShutdownW", reinterpret_cast<void*>(&kadvapi32G_InitiateShutdownW));
    e("InitiateSystemShutdownA", reinterpret_cast<void*>(&kadvapi32G_InitiateSystemShutdownA));
    e("InitiateSystemShutdownExA", reinterpret_cast<void*>(&kadvapi32G_InitiateSystemShutdownExA));
    e("InitiateSystemShutdownExW", reinterpret_cast<void*>(&kadvapi32G_InitiateSystemShutdownExW));
    e("InitiateSystemShutdownW", reinterpret_cast<void*>(&kadvapi32G_InitiateSystemShutdownW));
    e("IsTextUnicode", reinterpret_cast<void*>(&kadvapi32G_IsTextUnicode));
    e("IsTokenRestricted", reinterpret_cast<void*>(&kadvapi32G_IsTokenRestricted));
    e("IsTokenUntrusted", reinterpret_cast<void*>(&kadvapi32G_IsTokenUntrusted));
    e("IsValidAcl", reinterpret_cast<void*>(&kadvapi32G_IsValidAcl));
    e("IsValidSecurityDescriptor", reinterpret_cast<void*>(&kadvapi32G_IsValidSecurityDescriptor));
    e("IsWellKnownSid", reinterpret_cast<void*>(&kadvapi32G_IsWellKnownSid));
    e("LockServiceDatabase", reinterpret_cast<void*>(&kadvapi32G_LockServiceDatabase));
    e("LogonUserExA", reinterpret_cast<void*>(&kadvapi32G_LogonUserExA));
    e("LogonUserExW", reinterpret_cast<void*>(&kadvapi32G_LogonUserExW));
    e("LookupSecurityDescriptorPartsA", reinterpret_cast<void*>(&kadvapi32G_LookupSecurityDescriptorPartsA));
    e("LookupSecurityDescriptorPartsW", reinterpret_cast<void*>(&kadvapi32G_LookupSecurityDescriptorPartsW));
    e("LsaAddAccountRights", reinterpret_cast<void*>(&kadvapi32G_LsaAddAccountRights));
    e("LsaCreateTrustedDomainEx", reinterpret_cast<void*>(&kadvapi32G_LsaCreateTrustedDomainEx));
    e("LsaDeleteTrustedDomain", reinterpret_cast<void*>(&kadvapi32G_LsaDeleteTrustedDomain));
    e("LsaEnumerateAccountRights", reinterpret_cast<void*>(&kadvapi32G_LsaEnumerateAccountRights));
    e("LsaEnumerateAccountsWithUserRight", reinterpret_cast<void*>(&kadvapi32G_LsaEnumerateAccountsWithUserRight));
    e("LsaEnumerateTrustedDomains", reinterpret_cast<void*>(&kadvapi32G_LsaEnumerateTrustedDomains));
    e("LsaEnumerateTrustedDomainsEx", reinterpret_cast<void*>(&kadvapi32G_LsaEnumerateTrustedDomainsEx));
    e("LsaFreeMemory", reinterpret_cast<void*>(&kadvapi32G_LsaFreeMemory));
    e("LsaGetAppliedCAPIDs", reinterpret_cast<void*>(&kadvapi32G_LsaGetAppliedCAPIDs));
    e("LsaLookupNames", reinterpret_cast<void*>(&kadvapi32G_LsaLookupNames));
    e("LsaLookupNames2", reinterpret_cast<void*>(&kadvapi32G_LsaLookupNames2));
    e("LsaLookupSids", reinterpret_cast<void*>(&kadvapi32G_LsaLookupSids));
    e("LsaLookupSids2", reinterpret_cast<void*>(&kadvapi32G_LsaLookupSids2));
    e("LsaNtStatusToWinError", reinterpret_cast<void*>(&kadvapi32G_LsaNtStatusToWinError));
    e("LsaOpenTrustedDomainByName", reinterpret_cast<void*>(&kadvapi32G_LsaOpenTrustedDomainByName));
    e("LsaQueryCAPs", reinterpret_cast<void*>(&kadvapi32G_LsaQueryCAPs));
    e("LsaQueryDomainInformationPolicy", reinterpret_cast<void*>(&kadvapi32G_LsaQueryDomainInformationPolicy));
    e("LsaQueryForestTrustInformation", reinterpret_cast<void*>(&kadvapi32G_LsaQueryForestTrustInformation));
    e("LsaQueryInformationPolicy", reinterpret_cast<void*>(&kadvapi32G_LsaQueryInformationPolicy));
    e("LsaQueryTrustedDomainInfo", reinterpret_cast<void*>(&kadvapi32G_LsaQueryTrustedDomainInfo));
    e("LsaQueryTrustedDomainInfoByName", reinterpret_cast<void*>(&kadvapi32G_LsaQueryTrustedDomainInfoByName));
    e("LsaRemoveAccountRights", reinterpret_cast<void*>(&kadvapi32G_LsaRemoveAccountRights));
    e("LsaRetrievePrivateData", reinterpret_cast<void*>(&kadvapi32G_LsaRetrievePrivateData));
    e("LsaSetCAPs", reinterpret_cast<void*>(&kadvapi32G_LsaSetCAPs));
    e("LsaSetDomainInformationPolicy", reinterpret_cast<void*>(&kadvapi32G_LsaSetDomainInformationPolicy));
    e("LsaSetForestTrustInformation", reinterpret_cast<void*>(&kadvapi32G_LsaSetForestTrustInformation));
    e("LsaSetInformationPolicy", reinterpret_cast<void*>(&kadvapi32G_LsaSetInformationPolicy));
    e("LsaSetTrustedDomainInfoByName", reinterpret_cast<void*>(&kadvapi32G_LsaSetTrustedDomainInfoByName));
    e("LsaSetTrustedDomainInformation", reinterpret_cast<void*>(&kadvapi32G_LsaSetTrustedDomainInformation));
    e("LsaStorePrivateData", reinterpret_cast<void*>(&kadvapi32G_LsaStorePrivateData));
    e("MakeAbsoluteSD", reinterpret_cast<void*>(&kadvapi32G_MakeAbsoluteSD));
    e("MakeSelfRelativeSD", reinterpret_cast<void*>(&kadvapi32G_MakeSelfRelativeSD));
    e("NotifyBootConfigStatus", reinterpret_cast<void*>(&kadvapi32G_NotifyBootConfigStatus));
    e("NotifyChangeEventLog", reinterpret_cast<void*>(&kadvapi32G_NotifyChangeEventLog));
    e("NotifyServiceStatusChangeA", reinterpret_cast<void*>(&kadvapi32G_NotifyServiceStatusChangeA));
    e("NotifyServiceStatusChangeW", reinterpret_cast<void*>(&kadvapi32G_NotifyServiceStatusChangeW));
    e("ObjectCloseAuditAlarmA", reinterpret_cast<void*>(&kadvapi32G_ObjectCloseAuditAlarmA));
    e("ObjectCloseAuditAlarmW", reinterpret_cast<void*>(&kadvapi32G_ObjectCloseAuditAlarmW));
    e("ObjectDeleteAuditAlarmA", reinterpret_cast<void*>(&kadvapi32G_ObjectDeleteAuditAlarmA));
    e("ObjectDeleteAuditAlarmW", reinterpret_cast<void*>(&kadvapi32G_ObjectDeleteAuditAlarmW));
    e("ObjectOpenAuditAlarmA", reinterpret_cast<void*>(&kadvapi32G_ObjectOpenAuditAlarmA));
    e("ObjectOpenAuditAlarmW", reinterpret_cast<void*>(&kadvapi32G_ObjectOpenAuditAlarmW));
    e("ObjectPrivilegeAuditAlarmA", reinterpret_cast<void*>(&kadvapi32G_ObjectPrivilegeAuditAlarmA));
    e("ObjectPrivilegeAuditAlarmW", reinterpret_cast<void*>(&kadvapi32G_ObjectPrivilegeAuditAlarmW));
    e("OpenBackupEventLogA", reinterpret_cast<void*>(&kadvapi32G_OpenBackupEventLogA));
    e("OpenBackupEventLogW", reinterpret_cast<void*>(&kadvapi32G_OpenBackupEventLogW));
    e("OpenEncryptedFileRawA", reinterpret_cast<void*>(&kadvapi32G_OpenEncryptedFileRawA));
    e("OpenEncryptedFileRawW", reinterpret_cast<void*>(&kadvapi32G_OpenEncryptedFileRawW));
    e("OpenEventLogA", reinterpret_cast<void*>(&kadvapi32G_OpenEventLogA));
    e("OpenEventLogW", reinterpret_cast<void*>(&kadvapi32G_OpenEventLogW));
    e("OperationEnd", reinterpret_cast<void*>(&kadvapi32G_OperationEnd));
    e("OperationStart", reinterpret_cast<void*>(&kadvapi32G_OperationStart));
    e("PrivilegedServiceAuditAlarmA", reinterpret_cast<void*>(&kadvapi32G_PrivilegedServiceAuditAlarmA));
    e("PrivilegedServiceAuditAlarmW", reinterpret_cast<void*>(&kadvapi32G_PrivilegedServiceAuditAlarmW));
    e("QueryRecoveryAgentsOnEncryptedFile", reinterpret_cast<void*>(&kadvapi32G_QueryRecoveryAgentsOnEncryptedFile));
    e("QuerySecurityAccessMask", reinterpret_cast<void*>(&kadvapi32G_QuerySecurityAccessMask));
    e("QueryUsersOnEncryptedFile", reinterpret_cast<void*>(&kadvapi32G_QueryUsersOnEncryptedFile));
    e("ReadEncryptedFileRaw", reinterpret_cast<void*>(&kadvapi32G_ReadEncryptedFileRaw));
    e("ReadEventLogA", reinterpret_cast<void*>(&kadvapi32G_ReadEventLogA));
    e("ReadEventLogW", reinterpret_cast<void*>(&kadvapi32G_ReadEventLogW));
    e("RegConnectRegistryExA", reinterpret_cast<void*>(&kadvapi32G_RegConnectRegistryExA));
    e("RegConnectRegistryExW", reinterpret_cast<void*>(&kadvapi32G_RegConnectRegistryExW));
    e("RegDeleteKeyTransactedA", reinterpret_cast<void*>(&kadvapi32G_RegDeleteKeyTransactedA));
    e("RegDeleteKeyTransactedW", reinterpret_cast<void*>(&kadvapi32G_RegDeleteKeyTransactedW));
    e("RegDisablePredefinedCacheEx", reinterpret_cast<void*>(&kadvapi32G_RegDisablePredefinedCacheEx));
    e("RegOpenKeyTransactedA", reinterpret_cast<void*>(&kadvapi32G_RegOpenKeyTransactedA));
    e("RegOpenKeyTransactedW", reinterpret_cast<void*>(&kadvapi32G_RegOpenKeyTransactedW));
    e("RemoveUsersFromEncryptedFile", reinterpret_cast<void*>(&kadvapi32G_RemoveUsersFromEncryptedFile));
    e("ReportEventA", reinterpret_cast<void*>(&kadvapi32G_ReportEventA));
    e("ReportEventW", reinterpret_cast<void*>(&kadvapi32G_ReportEventW));
    e("SetAclInformation", reinterpret_cast<void*>(&kadvapi32G_SetAclInformation));
    e("SetFileSecurityA", reinterpret_cast<void*>(&kadvapi32G_SetFileSecurityA));
    e("SetFileSecurityW", reinterpret_cast<void*>(&kadvapi32G_SetFileSecurityW));
    e("SetKernelObjectSecurity", reinterpret_cast<void*>(&kadvapi32G_SetKernelObjectSecurity));
    e("SetNamedSecurityInfoA", reinterpret_cast<void*>(&kadvapi32G_SetNamedSecurityInfoA));
    e("SetNamedSecurityInfoW", reinterpret_cast<void*>(&kadvapi32G_SetNamedSecurityInfoW));
    e("SetPrivateObjectSecurity", reinterpret_cast<void*>(&kadvapi32G_SetPrivateObjectSecurity));
    e("SetPrivateObjectSecurityEx", reinterpret_cast<void*>(&kadvapi32G_SetPrivateObjectSecurityEx));
    e("SetSecurityAccessMask", reinterpret_cast<void*>(&kadvapi32G_SetSecurityAccessMask));
    e("SetSecurityDescriptorRMControl", reinterpret_cast<void*>(&kadvapi32G_SetSecurityDescriptorRMControl));
    e("SetServiceObjectSecurity", reinterpret_cast<void*>(&kadvapi32G_SetServiceObjectSecurity));
    e("SetServiceStatus", reinterpret_cast<void*>(&kadvapi32G_SetServiceStatus));
    e("SetUserFileEncryptionKey", reinterpret_cast<void*>(&kadvapi32G_SetUserFileEncryptionKey));
    e("SystemFunction036", reinterpret_cast<void*>(&kadvapi32G_SystemFunction036));
    e("SystemFunction040", reinterpret_cast<void*>(&kadvapi32G_SystemFunction040));
    e("SystemFunction041", reinterpret_cast<void*>(&kadvapi32G_SystemFunction041));
    e("TreeResetNamedSecurityInfoA", reinterpret_cast<void*>(&kadvapi32G_TreeResetNamedSecurityInfoA));
    e("TreeResetNamedSecurityInfoW", reinterpret_cast<void*>(&kadvapi32G_TreeResetNamedSecurityInfoW));
    e("TreeSetNamedSecurityInfoA", reinterpret_cast<void*>(&kadvapi32G_TreeSetNamedSecurityInfoA));
    e("TreeSetNamedSecurityInfoW", reinterpret_cast<void*>(&kadvapi32G_TreeSetNamedSecurityInfoW));
    e("UnlockServiceDatabase", reinterpret_cast<void*>(&kadvapi32G_UnlockServiceDatabase));
    e("Wow64Win32ApiEntry", reinterpret_cast<void*>(&kadvapi32G_Wow64Win32ApiEntry));
    e("WriteEncryptedFileRaw", reinterpret_cast<void*>(&kadvapi32G_WriteEncryptedFileRaw));
}
}  // namespace occ::runtime::winabi

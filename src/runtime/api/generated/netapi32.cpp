// The NETAPI32 surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_I_NetLogonControl(const char16_t* ServerName, std::uint32_t FunctionCode, std::uint32_t QueryLevel, std::uint8_t** Buffer) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(ServerName);
    static_cast<void>(FunctionCode);
    static_cast<void>(QueryLevel);
    static_cast<void>(Buffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_I_NetLogonControl2(const char16_t* ServerName, std::uint32_t FunctionCode, std::uint32_t QueryLevel, std::uint8_t* Data, std::uint8_t** Buffer) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(ServerName);
    static_cast<void>(FunctionCode);
    static_cast<void>(QueryLevel);
    static_cast<void>(Data);
    static_cast<void>(Buffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetAddAlternateComputerName(const char16_t* Server, const char16_t* AlternateName, const char16_t* DomainAccount, const char16_t* DomainAccountPassword, std::uint32_t Reserved) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(Server);
    static_cast<void>(AlternateName);
    static_cast<void>(DomainAccount);
    static_cast<void>(DomainAccountPassword);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetAlertRaise(const char16_t* AlertEventName, void* Buffer, std::uint32_t BufferSize) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(AlertEventName);
    static_cast<void>(Buffer);
    static_cast<void>(BufferSize);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetAlertRaiseEx(const char16_t* AlertEventName, void* VariableInfo, std::uint32_t VariableInfoSize, const char16_t* ServiceName) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(AlertEventName);
    static_cast<void>(VariableInfo);
    static_cast<void>(VariableInfoSize);
    static_cast<void>(ServiceName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetApiBufferAllocate(std::uint32_t ByteCount, void** Buffer) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(ByteCount);
    static_cast<void>(Buffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetApiBufferFree(void* Buffer) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(Buffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetApiBufferReallocate(void* OldBuffer, std::uint32_t NewByteCount, void** NewBuffer) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(OldBuffer);
    static_cast<void>(NewByteCount);
    static_cast<void>(NewBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetApiBufferSize(void* Buffer, std::uint32_t* ByteCount) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(Buffer);
    static_cast<void>(ByteCount);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetAuditClear(const char16_t* server, const char16_t* backupfile, const char16_t* service) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(server);
    static_cast<void>(backupfile);
    static_cast<void>(service);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetAuditRead(const char16_t* server, const char16_t* service, std::uint64_t auditloghandle, std::uint32_t offset, std::uint32_t* reserved1, std::uint32_t reserved2, std::uint32_t offsetflag, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* bytesread, std::uint32_t* totalavailable) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(server);
    static_cast<void>(service);
    static_cast<void>(auditloghandle);
    static_cast<void>(offset);
    static_cast<void>(reserved1);
    static_cast<void>(reserved2);
    static_cast<void>(offsetflag);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(bytesread);
    static_cast<void>(totalavailable);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetAuditWrite(std::uint32_t type, std::uint8_t* buf, std::uint32_t numbytes, const char16_t* service, std::uint8_t* reserved) noexcept {
    // Refused: the event log and audit subsystem.
    //
    // the event log is a service's file, and auditing is a policy the kernel
    // applies; this runtime does not stand in as either
    static_cast<void>(type);
    static_cast<void>(buf);
    static_cast<void>(numbytes);
    static_cast<void>(service);
    static_cast<void>(reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetConfigGet(const char16_t* server, const char16_t* component, const char16_t* parameter, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(server);
    static_cast<void>(component);
    static_cast<void>(parameter);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetConfigGetAll(const char16_t* server, const char16_t* component, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(server);
    static_cast<void>(component);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetConfigSet(const char16_t* server, const char16_t* reserved1, const char16_t* component, std::uint32_t level, std::uint32_t reserved2, std::uint8_t* buf, std::uint32_t reserved3) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(server);
    static_cast<void>(reserved1);
    static_cast<void>(component);
    static_cast<void>(level);
    static_cast<void>(reserved2);
    static_cast<void>(buf);
    static_cast<void>(reserved3);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetConnectionEnum(char16_t* servername, char16_t* qualifier, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint32_t* resume_handle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(qualifier);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resume_handle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetEnumerateComputerNames(const char16_t* Server, std::uint64_t NameType, std::uint32_t Reserved, std::uint32_t* EntryCount, char16_t*** ComputerNames) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(Server);
    static_cast<void>(NameType);
    static_cast<void>(Reserved);
    static_cast<void>(EntryCount);
    static_cast<void>(ComputerNames);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t knetapi32G_NetEnumerateTrustedDomains(char16_t* ServerName, char16_t** DomainNames) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(ServerName);
    static_cast<void>(DomainNames);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetErrorLogClear(const char16_t* server, const char16_t* backupfile, std::uint8_t* reserved) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(server);
    static_cast<void>(backupfile);
    static_cast<void>(reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetErrorLogRead(const char16_t* server, char16_t* reserved1, std::uint64_t errloghandle, std::uint32_t offset, std::uint32_t* reserved2, std::uint32_t reserved3, std::uint32_t offsetflag, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* bytesread, std::uint32_t* totalbytes) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(server);
    static_cast<void>(reserved1);
    static_cast<void>(errloghandle);
    static_cast<void>(offset);
    static_cast<void>(reserved2);
    static_cast<void>(reserved3);
    static_cast<void>(offsetflag);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(bytesread);
    static_cast<void>(totalbytes);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetErrorLogWrite(std::uint8_t* reserved1, std::uint32_t code, const char16_t* component, std::uint8_t* buffer, std::uint32_t numbytes, std::uint8_t* msgbuf, std::uint32_t strcount, std::uint8_t* reserved2) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(reserved1);
    static_cast<void>(code);
    static_cast<void>(component);
    static_cast<void>(buffer);
    static_cast<void>(numbytes);
    static_cast<void>(msgbuf);
    static_cast<void>(strcount);
    static_cast<void>(reserved2);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetFileClose(char16_t* servername, std::uint32_t fileid) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(fileid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetFileEnum(char16_t* servername, char16_t* basepath, char16_t* username, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint64_t* resume_handle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(basepath);
    static_cast<void>(username);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resume_handle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetFileGetInfo(char16_t* servername, std::uint32_t fileid, std::uint32_t level, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(fileid);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetGetAnyDCName(const char16_t* servername, const char16_t* domainname, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(domainname);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetGetDCName(const char16_t* servername, const char16_t* domainname, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(domainname);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetGetDisplayInformationIndex(const char16_t* ServerName, std::uint32_t Level, const char16_t* Prefix, std::uint32_t* Index) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(ServerName);
    static_cast<void>(Level);
    static_cast<void>(Prefix);
    static_cast<void>(Index);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetGetJoinInformation(const char16_t* lpServer, char16_t** lpNameBuffer, std::uint64_t BufferType) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpServer);
    static_cast<void>(lpNameBuffer);
    static_cast<void>(BufferType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetGetJoinableOUs(const char16_t* lpServer, const char16_t* lpDomain, const char16_t* lpAccount, const char16_t* lpPassword, std::uint32_t* OUCount, char16_t*** OUs) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpServer);
    static_cast<void>(lpDomain);
    static_cast<void>(lpAccount);
    static_cast<void>(lpPassword);
    static_cast<void>(OUCount);
    static_cast<void>(OUs);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetGroupAdd(const char16_t* servername, std::uint32_t level, std::uint8_t* buf, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetGroupAddUser(const char16_t* servername, const char16_t* GroupName, const char16_t* username) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(GroupName);
    static_cast<void>(username);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetGroupDel(const char16_t* servername, const char16_t* groupname) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(groupname);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetGroupDelUser(const char16_t* servername, const char16_t* GroupName, const char16_t* Username) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(GroupName);
    static_cast<void>(Username);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetGroupEnum(const char16_t* servername, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint64_t* resume_handle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resume_handle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetGroupGetInfo(const char16_t* servername, const char16_t* groupname, std::uint32_t level, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(groupname);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetGroupGetUsers(const char16_t* servername, const char16_t* groupname, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint64_t* ResumeHandle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(groupname);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(ResumeHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetGroupSetInfo(const char16_t* servername, const char16_t* groupname, std::uint32_t level, std::uint8_t* buf, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(groupname);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetGroupSetUsers(const char16_t* servername, const char16_t* groupname, std::uint32_t level, std::uint8_t* buf, std::uint32_t totalentries) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(groupname);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(totalentries);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetJoinDomain(const char16_t* lpServer, const char16_t* lpDomain, const char16_t* lpAccountOU, const char16_t* lpAccount, const char16_t* lpPassword, std::uint32_t fJoinOptions) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpServer);
    static_cast<void>(lpDomain);
    static_cast<void>(lpAccountOU);
    static_cast<void>(lpAccount);
    static_cast<void>(lpPassword);
    static_cast<void>(fJoinOptions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetLocalGroupAdd(const char16_t* servername, std::uint32_t level, std::uint8_t* buf, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetLocalGroupAddMember(const char16_t* servername, const char16_t* groupname, void* membersid) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(groupname);
    static_cast<void>(membersid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetLocalGroupAddMembers(const char16_t* servername, const char16_t* groupname, std::uint32_t level, std::uint8_t* buf, std::uint32_t totalentries) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(groupname);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(totalentries);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetLocalGroupDel(const char16_t* servername, const char16_t* groupname) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(groupname);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetLocalGroupDelMember(const char16_t* servername, const char16_t* groupname, void* membersid) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(groupname);
    static_cast<void>(membersid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetLocalGroupDelMembers(const char16_t* servername, const char16_t* groupname, std::uint32_t level, std::uint8_t* buf, std::uint32_t totalentries) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(groupname);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(totalentries);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetLocalGroupEnum(const char16_t* servername, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint64_t* resumehandle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resumehandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetLocalGroupGetInfo(const char16_t* servername, const char16_t* groupname, std::uint32_t level, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(groupname);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetLocalGroupGetMembers(const char16_t* servername, const char16_t* localgroupname, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint64_t* resumehandle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(localgroupname);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resumehandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetLocalGroupSetInfo(const char16_t* servername, const char16_t* groupname, std::uint32_t level, std::uint8_t* buf, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(groupname);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetLocalGroupSetMembers(const char16_t* servername, const char16_t* groupname, std::uint32_t level, std::uint8_t* buf, std::uint32_t totalentries) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(groupname);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(totalentries);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetMessageBufferSend(const char16_t* servername, const char16_t* msgname, const char16_t* fromname, std::uint8_t* buf, std::uint32_t buflen) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(msgname);
    static_cast<void>(fromname);
    static_cast<void>(buf);
    static_cast<void>(buflen);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetMessageNameAdd(const char16_t* servername, const char16_t* msgname) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(msgname);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetMessageNameDel(const char16_t* servername, const char16_t* msgname) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(msgname);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetMessageNameEnum(const char16_t* servername, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint32_t* resume_handle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resume_handle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetMessageNameGetInfo(const char16_t* servername, const char16_t* msgname, std::uint32_t level, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(msgname);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetQueryDisplayInformation(const char16_t* ServerName, std::uint32_t Level, std::uint32_t Index, std::uint32_t EntriesRequested, std::uint32_t PreferredMaximumLength, std::uint32_t* ReturnedEntryCount, void** SortedBuffer) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(ServerName);
    static_cast<void>(Level);
    static_cast<void>(Index);
    static_cast<void>(EntriesRequested);
    static_cast<void>(PreferredMaximumLength);
    static_cast<void>(ReturnedEntryCount);
    static_cast<void>(SortedBuffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetRegisterDomainNameChangeNotification(void** NotificationEventHandle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(NotificationEventHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetRemoteComputerSupports(const char16_t* UncServerName, std::uint32_t OptionsWanted, std::uint32_t* OptionsSupported) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(UncServerName);
    static_cast<void>(OptionsWanted);
    static_cast<void>(OptionsSupported);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetRemoteTOD(const char16_t* UncServerName, std::uint8_t** BufferPtr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(UncServerName);
    static_cast<void>(BufferPtr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetRemoveAlternateComputerName(const char16_t* Server, const char16_t* AlternateName, const char16_t* DomainAccount, const char16_t* DomainAccountPassword, std::uint32_t Reserved) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(Server);
    static_cast<void>(AlternateName);
    static_cast<void>(DomainAccount);
    static_cast<void>(DomainAccountPassword);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetRenameMachineInDomain(const char16_t* lpServer, const char16_t* lpNewMachineName, const char16_t* lpAccount, const char16_t* lpPassword, std::uint32_t fRenameOptions) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpServer);
    static_cast<void>(lpNewMachineName);
    static_cast<void>(lpAccount);
    static_cast<void>(lpPassword);
    static_cast<void>(fRenameOptions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetReplExportDirAdd(const char16_t* servername, std::uint32_t level, std::uint8_t* buf, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetReplExportDirDel(const char16_t* servername, const char16_t* dirname) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(dirname);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetReplExportDirEnum(const char16_t* servername, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint32_t* resumehandle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resumehandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetReplExportDirGetInfo(const char16_t* servername, const char16_t* dirname, std::uint32_t level, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(dirname);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetReplExportDirLock(const char16_t* servername, const char16_t* dirname) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(dirname);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetReplExportDirSetInfo(const char16_t* servername, const char16_t* dirname, std::uint32_t level, std::uint8_t* buf, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(dirname);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetReplExportDirUnlock(const char16_t* servername, const char16_t* dirname, std::uint32_t unlockforce) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(dirname);
    static_cast<void>(unlockforce);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetReplGetInfo(const char16_t* servername, std::uint32_t level, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetReplImportDirAdd(const char16_t* servername, std::uint32_t level, std::uint8_t* buf, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetReplImportDirDel(const char16_t* servername, const char16_t* dirname) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(dirname);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetReplImportDirEnum(const char16_t* servername, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint32_t* resumehandle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resumehandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetReplImportDirGetInfo(const char16_t* servername, const char16_t* dirname, std::uint32_t level, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(dirname);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetReplImportDirLock(const char16_t* servername, const char16_t* dirname) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(dirname);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetReplImportDirUnlock(const char16_t* servername, const char16_t* dirname, std::uint32_t unlockforce) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(dirname);
    static_cast<void>(unlockforce);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetReplSetInfo(const char16_t* servername, std::uint32_t level, std::uint8_t* buf, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetServerComputerNameAdd(char16_t* ServerName, char16_t* EmulatedDomainName, char16_t* EmulatedServerName) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(ServerName);
    static_cast<void>(EmulatedDomainName);
    static_cast<void>(EmulatedServerName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetServerComputerNameDel(char16_t* ServerName, char16_t* EmulatedServerName) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(ServerName);
    static_cast<void>(EmulatedServerName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetServerDiskEnum(char16_t* servername, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint32_t* resume_handle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resume_handle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetServerEnum(const char16_t* servername, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint32_t servertype, const char16_t* domain, std::uint32_t* resume_handle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(servertype);
    static_cast<void>(domain);
    static_cast<void>(resume_handle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetServerEnumEx(const char16_t* ServerName, std::uint32_t Level, std::uint8_t** Bufptr, std::uint32_t PrefMaxlen, std::uint32_t* EntriesRead, std::uint32_t* totalentries, std::uint32_t servertype, const char16_t* domain, const char16_t* FirstNameToReturn) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(ServerName);
    static_cast<void>(Level);
    static_cast<void>(Bufptr);
    static_cast<void>(PrefMaxlen);
    static_cast<void>(EntriesRead);
    static_cast<void>(totalentries);
    static_cast<void>(servertype);
    static_cast<void>(domain);
    static_cast<void>(FirstNameToReturn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetServerGetInfo(char16_t* servername, std::uint32_t level, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetServerSetInfo(char16_t* servername, std::uint32_t level, std::uint8_t* buf, std::uint32_t* ParmError) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(ParmError);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetServerTransportAdd(char16_t* servername, std::uint32_t level, std::uint8_t* bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetServerTransportAddEx(char16_t* servername, std::uint32_t level, std::uint8_t* bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetServerTransportDel(char16_t* servername, std::uint32_t level, std::uint8_t* bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetServerTransportEnum(char16_t* servername, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint32_t* resumehandle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resumehandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetServiceControl(const char16_t* servername, const char16_t* service, std::uint32_t opcode, std::uint32_t arg, std::uint8_t** bufptr) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(servername);
    static_cast<void>(service);
    static_cast<void>(opcode);
    static_cast<void>(arg);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetServiceEnum(const char16_t* servername, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint32_t* resume_handle) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resume_handle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetServiceGetInfo(const char16_t* servername, const char16_t* service, std::uint32_t level, std::uint8_t** bufptr) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(servername);
    static_cast<void>(service);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetServiceInstall(const char16_t* servername, const char16_t* service, std::uint32_t argc, const char16_t** argv, std::uint8_t** bufptr) noexcept {
    // Refused: the service control manager.
    //
    // services are processes the kernel starts on behalf of a service database
    // this runtime does not have
    static_cast<void>(servername);
    static_cast<void>(service);
    static_cast<void>(argc);
    static_cast<void>(argv);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetSessionDel(char16_t* servername, char16_t* UncClientName, char16_t* username) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(UncClientName);
    static_cast<void>(username);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetSessionEnum(char16_t* servername, char16_t* UncClientName, char16_t* username, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint32_t* resume_handle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(UncClientName);
    static_cast<void>(username);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resume_handle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetSessionGetInfo(char16_t* servername, char16_t* UncClientName, char16_t* username, std::uint32_t level, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(UncClientName);
    static_cast<void>(username);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetSetPrimaryComputerName(const char16_t* Server, const char16_t* PrimaryName, const char16_t* DomainAccount, const char16_t* DomainAccountPassword, std::uint32_t Reserved) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(Server);
    static_cast<void>(PrimaryName);
    static_cast<void>(DomainAccount);
    static_cast<void>(DomainAccountPassword);
    static_cast<void>(Reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetShareAdd(char16_t* servername, std::uint32_t level, std::uint8_t* buf, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetShareCheck(char16_t* servername, char16_t* device, std::uint32_t* type) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(device);
    static_cast<void>(type);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetShareDel(char16_t* servername, char16_t* netname, std::uint32_t reserved) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(netname);
    static_cast<void>(reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetShareDelSticky(char16_t* servername, char16_t* netname, std::uint32_t reserved) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(netname);
    static_cast<void>(reserved);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetShareEnum(char16_t* servername, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint32_t* resume_handle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resume_handle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetShareEnumSticky(char16_t* servername, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint32_t* resume_handle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resume_handle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetShareGetInfo(char16_t* servername, char16_t* netname, std::uint32_t level, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(netname);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetShareSetInfo(char16_t* servername, char16_t* netname, std::uint32_t level, std::uint8_t* buf, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(netname);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetStatisticsGet(char16_t* server, char16_t* service, std::uint32_t level, std::uint32_t options, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(server);
    static_cast<void>(service);
    static_cast<void>(level);
    static_cast<void>(options);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetUnjoinDomain(const char16_t* lpServer, const char16_t* lpAccount, const char16_t* lpPassword, std::uint32_t fUnjoinOptions) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpServer);
    static_cast<void>(lpAccount);
    static_cast<void>(lpPassword);
    static_cast<void>(fUnjoinOptions);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetUnregisterDomainNameChangeNotification(void* NotificationEventHandle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(NotificationEventHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetUseAdd(char16_t* UncServerName, std::uint32_t Level, std::uint8_t* Buf, std::uint32_t* ParmError) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(UncServerName);
    static_cast<void>(Level);
    static_cast<void>(Buf);
    static_cast<void>(ParmError);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetUseDel(char16_t* UncServerName, char16_t* UseName, std::uint32_t ForceCond) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(UncServerName);
    static_cast<void>(UseName);
    static_cast<void>(ForceCond);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetUseEnum(char16_t* UncServerName, std::uint32_t Level, std::uint8_t** BufPtr, std::uint32_t PreferedMaximumSize, std::uint32_t* EntriesRead, std::uint32_t* TotalEntries, std::uint32_t* ResumeHandle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(UncServerName);
    static_cast<void>(Level);
    static_cast<void>(BufPtr);
    static_cast<void>(PreferedMaximumSize);
    static_cast<void>(EntriesRead);
    static_cast<void>(TotalEntries);
    static_cast<void>(ResumeHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetUseGetInfo(char16_t* UncServerName, char16_t* UseName, std::uint32_t Level, std::uint8_t** BufPtr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(UncServerName);
    static_cast<void>(UseName);
    static_cast<void>(Level);
    static_cast<void>(BufPtr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetUserAdd(const char16_t* servername, std::uint32_t level, std::uint8_t* buf, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetUserChangePassword(const char16_t* domainname, const char16_t* username, const char16_t* oldpassword, const char16_t* newpassword) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(domainname);
    static_cast<void>(username);
    static_cast<void>(oldpassword);
    static_cast<void>(newpassword);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetUserDel(const char16_t* servername, const char16_t* username) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(username);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetUserEnum(const char16_t* servername, std::uint32_t level, std::uint32_t filter, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint32_t* resume_handle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(filter);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resume_handle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetUserGetGroups(const char16_t* servername, const char16_t* username, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(username);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetUserGetInfo(const char16_t* servername, const char16_t* username, std::uint32_t level, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(username);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetUserGetLocalGroups(const char16_t* servername, const char16_t* username, std::uint32_t level, std::uint32_t flags, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(username);
    static_cast<void>(level);
    static_cast<void>(flags);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetUserModalsGet(const char16_t* servername, std::uint32_t level, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetUserModalsSet(const char16_t* servername, std::uint32_t level, std::uint8_t* buf, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetUserSetGroups(const char16_t* servername, const char16_t* username, std::uint32_t level, std::uint8_t* buf, std::uint32_t num_entries) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(username);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(num_entries);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetUserSetInfo(const char16_t* servername, const char16_t* username, std::uint32_t level, std::uint8_t* buf, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(username);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetValidateName(const char16_t* lpServer, const char16_t* lpName, const char16_t* lpAccount, const char16_t* lpPassword, std::uint64_t NameType) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(lpServer);
    static_cast<void>(lpName);
    static_cast<void>(lpAccount);
    static_cast<void>(lpPassword);
    static_cast<void>(NameType);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetValidatePasswordPolicy(const char16_t* ServerName, void* Qualifier, std::uint64_t ValidationType, void* InputArg, void** OutputArg) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(ServerName);
    static_cast<void>(Qualifier);
    static_cast<void>(ValidationType);
    static_cast<void>(InputArg);
    static_cast<void>(OutputArg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetValidatePasswordPolicyFree(void** OutputArg) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(OutputArg);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetWkstaGetInfo(char16_t* servername, std::uint32_t level, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetWkstaSetInfo(char16_t* servername, std::uint32_t level, std::uint8_t* buffer, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(buffer);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetWkstaTransportAdd(char16_t* servername, std::uint32_t level, std::uint8_t* buf, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetWkstaTransportDel(char16_t* servername, char16_t* transportname, std::uint32_t ucond) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(transportname);
    static_cast<void>(ucond);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetWkstaTransportEnum(char16_t* servername, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint32_t* resumehandle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resumehandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetWkstaUserEnum(char16_t* servername, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint32_t* resumehandle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resumehandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetWkstaUserGetInfo(char16_t* reserved, std::uint32_t level, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(reserved);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetWkstaUserSetInfo(char16_t* reserved, std::uint32_t level, std::uint8_t* buf, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(reserved);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_NetapipBufferAllocate(std::uint32_t ByteCount, void** Buffer) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(ByteCount);
    static_cast<void>(Buffer);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_RxNetAccessAdd(const char16_t* servername, std::uint32_t level, std::uint8_t* buf, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_RxNetAccessDel(const char16_t* servername, const char16_t* resource) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(resource);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_RxNetAccessEnum(const char16_t* servername, const char16_t* BasePath, std::uint32_t Recursive, std::uint32_t level, std::uint8_t** bufptr, std::uint32_t prefmaxlen, std::uint32_t* entriesread, std::uint32_t* totalentries, std::uint32_t* resume_handle) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(BasePath);
    static_cast<void>(Recursive);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    static_cast<void>(prefmaxlen);
    static_cast<void>(entriesread);
    static_cast<void>(totalentries);
    static_cast<void>(resume_handle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_RxNetAccessGetInfo(const char16_t* servername, const char16_t* resource, std::uint32_t level, std::uint8_t** bufptr) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(resource);
    static_cast<void>(level);
    static_cast<void>(bufptr);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_RxNetAccessGetUserPerms(const char16_t* servername, const char16_t* UGname, const char16_t* resource, std::uint32_t* Perms) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(UGname);
    static_cast<void>(resource);
    static_cast<void>(Perms);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_RxNetAccessSetInfo(const char16_t* servername, const char16_t* resource, std::uint32_t level, std::uint8_t* buf, std::uint32_t* parm_err) noexcept {
    // Refused: the network redirector and the directory service.
    //
    // these calls reach a network provider -- a share, a domain controller or
    // a directory -- over a protocol this runtime does not carry; the socket
    // and name-resolution surface is answered instead
    static_cast<void>(servername);
    static_cast<void>(resource);
    static_cast<void>(level);
    static_cast<void>(buf);
    static_cast<void>(parm_err);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t knetapi32G_RxRemoteApi(std::uint32_t ApiNumber, const char16_t* UncServerName, void* ParmDescString, void* DataDesc16, void* DataDesc32, void* DataDescSmb, void* AuxDesc16, void* AuxDesc32, void* AuxDescSmb, std::uint32_t Flags, ...) noexcept {
    // Refused: the network redirector.
    //
    // these calls reach a share or a domain over a protocol served by another
    // machine
    static_cast<void>(ApiNumber);
    static_cast<void>(UncServerName);
    static_cast<void>(ParmDescString);
    static_cast<void>(DataDesc16);
    static_cast<void>(DataDesc32);
    static_cast<void>(DataDescSmb);
    static_cast<void>(AuxDesc16);
    static_cast<void>(AuxDesc32);
    static_cast<void>(AuxDescSmb);
    static_cast<void>(Flags);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_netapi32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("I_NetLogonControl", reinterpret_cast<void*>(&knetapi32G_I_NetLogonControl));
    e("I_NetLogonControl2", reinterpret_cast<void*>(&knetapi32G_I_NetLogonControl2));
    e("NetAddAlternateComputerName", reinterpret_cast<void*>(&knetapi32G_NetAddAlternateComputerName));
    e("NetAlertRaise", reinterpret_cast<void*>(&knetapi32G_NetAlertRaise));
    e("NetAlertRaiseEx", reinterpret_cast<void*>(&knetapi32G_NetAlertRaiseEx));
    e("NetApiBufferAllocate", reinterpret_cast<void*>(&knetapi32G_NetApiBufferAllocate));
    e("NetApiBufferFree", reinterpret_cast<void*>(&knetapi32G_NetApiBufferFree));
    e("NetApiBufferReallocate", reinterpret_cast<void*>(&knetapi32G_NetApiBufferReallocate));
    e("NetApiBufferSize", reinterpret_cast<void*>(&knetapi32G_NetApiBufferSize));
    e("NetAuditClear", reinterpret_cast<void*>(&knetapi32G_NetAuditClear));
    e("NetAuditRead", reinterpret_cast<void*>(&knetapi32G_NetAuditRead));
    e("NetAuditWrite", reinterpret_cast<void*>(&knetapi32G_NetAuditWrite));
    e("NetConfigGet", reinterpret_cast<void*>(&knetapi32G_NetConfigGet));
    e("NetConfigGetAll", reinterpret_cast<void*>(&knetapi32G_NetConfigGetAll));
    e("NetConfigSet", reinterpret_cast<void*>(&knetapi32G_NetConfigSet));
    e("NetConnectionEnum", reinterpret_cast<void*>(&knetapi32G_NetConnectionEnum));
    e("NetEnumerateComputerNames", reinterpret_cast<void*>(&knetapi32G_NetEnumerateComputerNames));
    e("NetEnumerateTrustedDomains", reinterpret_cast<void*>(&knetapi32G_NetEnumerateTrustedDomains));
    e("NetErrorLogClear", reinterpret_cast<void*>(&knetapi32G_NetErrorLogClear));
    e("NetErrorLogRead", reinterpret_cast<void*>(&knetapi32G_NetErrorLogRead));
    e("NetErrorLogWrite", reinterpret_cast<void*>(&knetapi32G_NetErrorLogWrite));
    e("NetFileClose", reinterpret_cast<void*>(&knetapi32G_NetFileClose));
    e("NetFileEnum", reinterpret_cast<void*>(&knetapi32G_NetFileEnum));
    e("NetFileGetInfo", reinterpret_cast<void*>(&knetapi32G_NetFileGetInfo));
    e("NetGetAnyDCName", reinterpret_cast<void*>(&knetapi32G_NetGetAnyDCName));
    e("NetGetDCName", reinterpret_cast<void*>(&knetapi32G_NetGetDCName));
    e("NetGetDisplayInformationIndex", reinterpret_cast<void*>(&knetapi32G_NetGetDisplayInformationIndex));
    e("NetGetJoinInformation", reinterpret_cast<void*>(&knetapi32G_NetGetJoinInformation));
    e("NetGetJoinableOUs", reinterpret_cast<void*>(&knetapi32G_NetGetJoinableOUs));
    e("NetGroupAdd", reinterpret_cast<void*>(&knetapi32G_NetGroupAdd));
    e("NetGroupAddUser", reinterpret_cast<void*>(&knetapi32G_NetGroupAddUser));
    e("NetGroupDel", reinterpret_cast<void*>(&knetapi32G_NetGroupDel));
    e("NetGroupDelUser", reinterpret_cast<void*>(&knetapi32G_NetGroupDelUser));
    e("NetGroupEnum", reinterpret_cast<void*>(&knetapi32G_NetGroupEnum));
    e("NetGroupGetInfo", reinterpret_cast<void*>(&knetapi32G_NetGroupGetInfo));
    e("NetGroupGetUsers", reinterpret_cast<void*>(&knetapi32G_NetGroupGetUsers));
    e("NetGroupSetInfo", reinterpret_cast<void*>(&knetapi32G_NetGroupSetInfo));
    e("NetGroupSetUsers", reinterpret_cast<void*>(&knetapi32G_NetGroupSetUsers));
    e("NetJoinDomain", reinterpret_cast<void*>(&knetapi32G_NetJoinDomain));
    e("NetLocalGroupAdd", reinterpret_cast<void*>(&knetapi32G_NetLocalGroupAdd));
    e("NetLocalGroupAddMember", reinterpret_cast<void*>(&knetapi32G_NetLocalGroupAddMember));
    e("NetLocalGroupAddMembers", reinterpret_cast<void*>(&knetapi32G_NetLocalGroupAddMembers));
    e("NetLocalGroupDel", reinterpret_cast<void*>(&knetapi32G_NetLocalGroupDel));
    e("NetLocalGroupDelMember", reinterpret_cast<void*>(&knetapi32G_NetLocalGroupDelMember));
    e("NetLocalGroupDelMembers", reinterpret_cast<void*>(&knetapi32G_NetLocalGroupDelMembers));
    e("NetLocalGroupEnum", reinterpret_cast<void*>(&knetapi32G_NetLocalGroupEnum));
    e("NetLocalGroupGetInfo", reinterpret_cast<void*>(&knetapi32G_NetLocalGroupGetInfo));
    e("NetLocalGroupGetMembers", reinterpret_cast<void*>(&knetapi32G_NetLocalGroupGetMembers));
    e("NetLocalGroupSetInfo", reinterpret_cast<void*>(&knetapi32G_NetLocalGroupSetInfo));
    e("NetLocalGroupSetMembers", reinterpret_cast<void*>(&knetapi32G_NetLocalGroupSetMembers));
    e("NetMessageBufferSend", reinterpret_cast<void*>(&knetapi32G_NetMessageBufferSend));
    e("NetMessageNameAdd", reinterpret_cast<void*>(&knetapi32G_NetMessageNameAdd));
    e("NetMessageNameDel", reinterpret_cast<void*>(&knetapi32G_NetMessageNameDel));
    e("NetMessageNameEnum", reinterpret_cast<void*>(&knetapi32G_NetMessageNameEnum));
    e("NetMessageNameGetInfo", reinterpret_cast<void*>(&knetapi32G_NetMessageNameGetInfo));
    e("NetQueryDisplayInformation", reinterpret_cast<void*>(&knetapi32G_NetQueryDisplayInformation));
    e("NetRegisterDomainNameChangeNotification", reinterpret_cast<void*>(&knetapi32G_NetRegisterDomainNameChangeNotification));
    e("NetRemoteComputerSupports", reinterpret_cast<void*>(&knetapi32G_NetRemoteComputerSupports));
    e("NetRemoteTOD", reinterpret_cast<void*>(&knetapi32G_NetRemoteTOD));
    e("NetRemoveAlternateComputerName", reinterpret_cast<void*>(&knetapi32G_NetRemoveAlternateComputerName));
    e("NetRenameMachineInDomain", reinterpret_cast<void*>(&knetapi32G_NetRenameMachineInDomain));
    e("NetReplExportDirAdd", reinterpret_cast<void*>(&knetapi32G_NetReplExportDirAdd));
    e("NetReplExportDirDel", reinterpret_cast<void*>(&knetapi32G_NetReplExportDirDel));
    e("NetReplExportDirEnum", reinterpret_cast<void*>(&knetapi32G_NetReplExportDirEnum));
    e("NetReplExportDirGetInfo", reinterpret_cast<void*>(&knetapi32G_NetReplExportDirGetInfo));
    e("NetReplExportDirLock", reinterpret_cast<void*>(&knetapi32G_NetReplExportDirLock));
    e("NetReplExportDirSetInfo", reinterpret_cast<void*>(&knetapi32G_NetReplExportDirSetInfo));
    e("NetReplExportDirUnlock", reinterpret_cast<void*>(&knetapi32G_NetReplExportDirUnlock));
    e("NetReplGetInfo", reinterpret_cast<void*>(&knetapi32G_NetReplGetInfo));
    e("NetReplImportDirAdd", reinterpret_cast<void*>(&knetapi32G_NetReplImportDirAdd));
    e("NetReplImportDirDel", reinterpret_cast<void*>(&knetapi32G_NetReplImportDirDel));
    e("NetReplImportDirEnum", reinterpret_cast<void*>(&knetapi32G_NetReplImportDirEnum));
    e("NetReplImportDirGetInfo", reinterpret_cast<void*>(&knetapi32G_NetReplImportDirGetInfo));
    e("NetReplImportDirLock", reinterpret_cast<void*>(&knetapi32G_NetReplImportDirLock));
    e("NetReplImportDirUnlock", reinterpret_cast<void*>(&knetapi32G_NetReplImportDirUnlock));
    e("NetReplSetInfo", reinterpret_cast<void*>(&knetapi32G_NetReplSetInfo));
    e("NetServerComputerNameAdd", reinterpret_cast<void*>(&knetapi32G_NetServerComputerNameAdd));
    e("NetServerComputerNameDel", reinterpret_cast<void*>(&knetapi32G_NetServerComputerNameDel));
    e("NetServerDiskEnum", reinterpret_cast<void*>(&knetapi32G_NetServerDiskEnum));
    e("NetServerEnum", reinterpret_cast<void*>(&knetapi32G_NetServerEnum));
    e("NetServerEnumEx", reinterpret_cast<void*>(&knetapi32G_NetServerEnumEx));
    e("NetServerGetInfo", reinterpret_cast<void*>(&knetapi32G_NetServerGetInfo));
    e("NetServerSetInfo", reinterpret_cast<void*>(&knetapi32G_NetServerSetInfo));
    e("NetServerTransportAdd", reinterpret_cast<void*>(&knetapi32G_NetServerTransportAdd));
    e("NetServerTransportAddEx", reinterpret_cast<void*>(&knetapi32G_NetServerTransportAddEx));
    e("NetServerTransportDel", reinterpret_cast<void*>(&knetapi32G_NetServerTransportDel));
    e("NetServerTransportEnum", reinterpret_cast<void*>(&knetapi32G_NetServerTransportEnum));
    e("NetServiceControl", reinterpret_cast<void*>(&knetapi32G_NetServiceControl));
    e("NetServiceEnum", reinterpret_cast<void*>(&knetapi32G_NetServiceEnum));
    e("NetServiceGetInfo", reinterpret_cast<void*>(&knetapi32G_NetServiceGetInfo));
    e("NetServiceInstall", reinterpret_cast<void*>(&knetapi32G_NetServiceInstall));
    e("NetSessionDel", reinterpret_cast<void*>(&knetapi32G_NetSessionDel));
    e("NetSessionEnum", reinterpret_cast<void*>(&knetapi32G_NetSessionEnum));
    e("NetSessionGetInfo", reinterpret_cast<void*>(&knetapi32G_NetSessionGetInfo));
    e("NetSetPrimaryComputerName", reinterpret_cast<void*>(&knetapi32G_NetSetPrimaryComputerName));
    e("NetShareAdd", reinterpret_cast<void*>(&knetapi32G_NetShareAdd));
    e("NetShareCheck", reinterpret_cast<void*>(&knetapi32G_NetShareCheck));
    e("NetShareDel", reinterpret_cast<void*>(&knetapi32G_NetShareDel));
    e("NetShareDelSticky", reinterpret_cast<void*>(&knetapi32G_NetShareDelSticky));
    e("NetShareEnum", reinterpret_cast<void*>(&knetapi32G_NetShareEnum));
    e("NetShareEnumSticky", reinterpret_cast<void*>(&knetapi32G_NetShareEnumSticky));
    e("NetShareGetInfo", reinterpret_cast<void*>(&knetapi32G_NetShareGetInfo));
    e("NetShareSetInfo", reinterpret_cast<void*>(&knetapi32G_NetShareSetInfo));
    e("NetStatisticsGet", reinterpret_cast<void*>(&knetapi32G_NetStatisticsGet));
    e("NetUnjoinDomain", reinterpret_cast<void*>(&knetapi32G_NetUnjoinDomain));
    e("NetUnregisterDomainNameChangeNotification", reinterpret_cast<void*>(&knetapi32G_NetUnregisterDomainNameChangeNotification));
    e("NetUseAdd", reinterpret_cast<void*>(&knetapi32G_NetUseAdd));
    e("NetUseDel", reinterpret_cast<void*>(&knetapi32G_NetUseDel));
    e("NetUseEnum", reinterpret_cast<void*>(&knetapi32G_NetUseEnum));
    e("NetUseGetInfo", reinterpret_cast<void*>(&knetapi32G_NetUseGetInfo));
    e("NetUserAdd", reinterpret_cast<void*>(&knetapi32G_NetUserAdd));
    e("NetUserChangePassword", reinterpret_cast<void*>(&knetapi32G_NetUserChangePassword));
    e("NetUserDel", reinterpret_cast<void*>(&knetapi32G_NetUserDel));
    e("NetUserEnum", reinterpret_cast<void*>(&knetapi32G_NetUserEnum));
    e("NetUserGetGroups", reinterpret_cast<void*>(&knetapi32G_NetUserGetGroups));
    e("NetUserGetInfo", reinterpret_cast<void*>(&knetapi32G_NetUserGetInfo));
    e("NetUserGetLocalGroups", reinterpret_cast<void*>(&knetapi32G_NetUserGetLocalGroups));
    e("NetUserModalsGet", reinterpret_cast<void*>(&knetapi32G_NetUserModalsGet));
    e("NetUserModalsSet", reinterpret_cast<void*>(&knetapi32G_NetUserModalsSet));
    e("NetUserSetGroups", reinterpret_cast<void*>(&knetapi32G_NetUserSetGroups));
    e("NetUserSetInfo", reinterpret_cast<void*>(&knetapi32G_NetUserSetInfo));
    e("NetValidateName", reinterpret_cast<void*>(&knetapi32G_NetValidateName));
    e("NetValidatePasswordPolicy", reinterpret_cast<void*>(&knetapi32G_NetValidatePasswordPolicy));
    e("NetValidatePasswordPolicyFree", reinterpret_cast<void*>(&knetapi32G_NetValidatePasswordPolicyFree));
    e("NetWkstaGetInfo", reinterpret_cast<void*>(&knetapi32G_NetWkstaGetInfo));
    e("NetWkstaSetInfo", reinterpret_cast<void*>(&knetapi32G_NetWkstaSetInfo));
    e("NetWkstaTransportAdd", reinterpret_cast<void*>(&knetapi32G_NetWkstaTransportAdd));
    e("NetWkstaTransportDel", reinterpret_cast<void*>(&knetapi32G_NetWkstaTransportDel));
    e("NetWkstaTransportEnum", reinterpret_cast<void*>(&knetapi32G_NetWkstaTransportEnum));
    e("NetWkstaUserEnum", reinterpret_cast<void*>(&knetapi32G_NetWkstaUserEnum));
    e("NetWkstaUserGetInfo", reinterpret_cast<void*>(&knetapi32G_NetWkstaUserGetInfo));
    e("NetWkstaUserSetInfo", reinterpret_cast<void*>(&knetapi32G_NetWkstaUserSetInfo));
    e("NetapipBufferAllocate", reinterpret_cast<void*>(&knetapi32G_NetapipBufferAllocate));
    e("RxNetAccessAdd", reinterpret_cast<void*>(&knetapi32G_RxNetAccessAdd));
    e("RxNetAccessDel", reinterpret_cast<void*>(&knetapi32G_RxNetAccessDel));
    e("RxNetAccessEnum", reinterpret_cast<void*>(&knetapi32G_RxNetAccessEnum));
    e("RxNetAccessGetInfo", reinterpret_cast<void*>(&knetapi32G_RxNetAccessGetInfo));
    e("RxNetAccessGetUserPerms", reinterpret_cast<void*>(&knetapi32G_RxNetAccessGetUserPerms));
    e("RxNetAccessSetInfo", reinterpret_cast<void*>(&knetapi32G_RxNetAccessSetInfo));
    e("RxRemoteApi", reinterpret_cast<void*>(&knetapi32G_RxRemoteApi));
}
}  // namespace occ::runtime::winabi

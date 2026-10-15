// The WLDAP32 surface this runtime did not answer.
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

extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_LdapGetLastError() noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and its own session
    // state; the socket surface is answered instead
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_LdapMapErrorToWin32(std::uint32_t LdapError) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and its own session
    // state; the socket surface is answered instead
    static_cast<void>(LdapError);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwldap32G_LdapUTF8ToUnicode(const char* lpSrcStr, std::int32_t cchSrc, char16_t* lpDestStr, std::int32_t cchDest) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and its own session
    // state; the socket surface is answered instead
    static_cast<void>(lpSrcStr);
    static_cast<void>(cchSrc);
    static_cast<void>(lpDestStr);
    static_cast<void>(cchDest);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwldap32G_LdapUnicodeToUTF8(const char16_t* lpSrcStr, std::int32_t cchSrc, char* lpDestStr, std::int32_t cchDest) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and its own session
    // state; the socket surface is answered instead
    static_cast<void>(lpSrcStr);
    static_cast<void>(cchSrc);
    static_cast<void>(lpDestStr);
    static_cast<void>(cchDest);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kwldap32G_ber_bvfree(void* bv) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(bv);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_cldap_open(char* HostName, std::uint32_t PortNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(HostName);
    static_cast<void>(PortNumber);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_cldap_openA(char* HostName, std::uint32_t PortNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(HostName);
    static_cast<void>(PortNumber);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_cldap_openW(char16_t* HostName, std::uint32_t PortNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(HostName);
    static_cast<void>(PortNumber);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_abandon(void* ld, std::uint32_t msgid) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(msgid);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_add(void* ld, char* dn, void** attrs) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attrs);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_addA(void* ld, char* dn, void** attrs) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attrs);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_addW(void* ld, char16_t* dn, void** attrs) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attrs);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_add_ext(void* ld, char* dn, void** attrs, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attrs);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_add_extA(void* ld, char* dn, void** attrs, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attrs);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_add_extW(void* ld, char16_t* dn, void** attrs, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attrs);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_add_ext_s(void* ld, char* dn, void** attrs, void** ServerControls, void** ClientControls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attrs);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_add_ext_sA(void* ld, char* dn, void** attrs, void** ServerControls, void** ClientControls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attrs);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_add_ext_sW(void* ld, char16_t* dn, void** attrs, void** ServerControls, void** ClientControls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attrs);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_add_s(void* ld, char* dn, void** attrs) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attrs);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_add_sA(void* ld, char* dn, void** attrs) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attrs);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_add_sW(void* ld, char16_t* dn, void** attrs) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attrs);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_bind(void* ld, char* dn, char* cred, std::uint32_t method) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(cred);
    static_cast<void>(method);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_bindA(void* ld, char* dn, char* cred, std::uint32_t method) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(cred);
    static_cast<void>(method);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_bindW(void* ld, char16_t* dn, char16_t* cred, std::uint32_t method) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(cred);
    static_cast<void>(method);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_bind_s(void* ld, char* dn, char* cred, std::uint32_t method) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(cred);
    static_cast<void>(method);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_bind_sA(void* ld, char* dn, char* cred, std::uint32_t method) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(cred);
    static_cast<void>(method);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_bind_sW(void* ld, char16_t* dn, char16_t* cred, std::uint32_t method) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(cred);
    static_cast<void>(method);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_check_filterA(void* ld, char* SearchFilter) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(SearchFilter);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_check_filterW(void* ld, char16_t* SearchFilter) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(SearchFilter);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_cleanup(void* hInstance) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(hInstance);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_close_extended_op(void* ld, std::uint32_t MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_compare(void* ld, char* dn, char* attr, char* value) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attr);
    static_cast<void>(value);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_compareA(void* ld, char* dn, char* attr, char* value) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attr);
    static_cast<void>(value);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_compareW(void* ld, char16_t* dn, char16_t* attr, char16_t* value) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attr);
    static_cast<void>(value);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_compare_ext(void* ld, char* dn, char* Attr, char* Value, void* Data, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(Attr);
    static_cast<void>(Value);
    static_cast<void>(Data);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_compare_extA(void* ld, char* dn, char* Attr, char* Value, void* Data, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(Attr);
    static_cast<void>(Value);
    static_cast<void>(Data);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_compare_extW(void* ld, char16_t* dn, char16_t* Attr, char16_t* Value, void* Data, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(Attr);
    static_cast<void>(Value);
    static_cast<void>(Data);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_compare_ext_s(void* ld, char* dn, char* Attr, char* Value, void* Data, void** ServerControls, void** ClientControls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(Attr);
    static_cast<void>(Value);
    static_cast<void>(Data);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_compare_ext_sA(void* ld, char* dn, char* Attr, char* Value, void* Data, void** ServerControls, void** ClientControls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(Attr);
    static_cast<void>(Value);
    static_cast<void>(Data);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_compare_ext_sW(void* ld, char16_t* dn, char16_t* Attr, char16_t* Value, void* Data, void** ServerControls, void** ClientControls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(Attr);
    static_cast<void>(Value);
    static_cast<void>(Data);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_compare_s(void* ld, char* dn, char* attr, char* value) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attr);
    static_cast<void>(value);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_compare_sA(void* ld, char* dn, char* attr, char* value) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attr);
    static_cast<void>(value);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_compare_sW(void* ld, char16_t* dn, char16_t* attr, char16_t* value) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(attr);
    static_cast<void>(value);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_ldap_conn_from_msg(void* PrimaryConn, void* res) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(PrimaryConn);
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_connect(void* ld, void* timeout) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(timeout);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_control_free(void* Control) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Control);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_control_freeA(void* Controls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Controls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_control_freeW(void* Control) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Control);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_controls_free(void** Controls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Controls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_controls_freeA(void** Controls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Controls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_controls_freeW(void** Control) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Control);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_count_entries(void* ld, void* res) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_count_references(void* ld, void* res) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_count_values(char** vals) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(vals);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_count_valuesA(char** vals) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(vals);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_count_valuesW(char16_t** vals) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(vals);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_count_values_len(void** vals) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(vals);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_create_page_control(void* ExternalHandle, std::uint32_t PageSize, void* Cookie, std::uint8_t IsCritical, void** Control) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(PageSize);
    static_cast<void>(Cookie);
    static_cast<void>(IsCritical);
    static_cast<void>(Control);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_create_page_controlA(void* ExternalHandle, std::uint32_t PageSize, void* Cookie, std::uint8_t IsCritical, void** Control) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(PageSize);
    static_cast<void>(Cookie);
    static_cast<void>(IsCritical);
    static_cast<void>(Control);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_create_page_controlW(void* ExternalHandle, std::uint32_t PageSize, void* Cookie, std::uint8_t IsCritical, void** Control) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(PageSize);
    static_cast<void>(Cookie);
    static_cast<void>(IsCritical);
    static_cast<void>(Control);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_create_sort_control(void* ExternalHandle, void** SortKeys, std::uint8_t IsCritical, void** Control) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(SortKeys);
    static_cast<void>(IsCritical);
    static_cast<void>(Control);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_create_sort_controlA(void* ExternalHandle, void** SortKeys, std::uint8_t IsCritical, void** Control) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(SortKeys);
    static_cast<void>(IsCritical);
    static_cast<void>(Control);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_create_sort_controlW(void* ExternalHandle, void** SortKeys, std::uint8_t IsCritical, void** Control) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(SortKeys);
    static_cast<void>(IsCritical);
    static_cast<void>(Control);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwldap32G_ldap_create_vlv_controlA(void* ExternalHandle, std::uint64_t VlvInfo, std::uint8_t IsCritical, void** Control) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(VlvInfo);
    static_cast<void>(IsCritical);
    static_cast<void>(Control);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwldap32G_ldap_create_vlv_controlW(void* ExternalHandle, std::uint64_t VlvInfo, std::uint8_t IsCritical, void** Control) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(VlvInfo);
    static_cast<void>(IsCritical);
    static_cast<void>(Control);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_delete(void* ld, char* dn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_deleteA(void* ld, char* dn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_deleteW(void* ld, char16_t* dn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_delete_ext(void* ld, char* dn, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_delete_extA(void* ld, char* dn, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_delete_extW(void* ld, char16_t* dn, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_delete_ext_s(void* ld, char* dn, void** ServerControls, void** ClientControls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_delete_ext_sA(void* ld, char* dn, void** ServerControls, void** ClientControls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_delete_ext_sW(void* ld, char16_t* dn, void** ServerControls, void** ClientControls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_delete_s(void* ld, char* dn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_delete_sA(void* ld, char* dn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_delete_sW(void* ld, char16_t* dn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) char* kwldap32G_ldap_dn2ufn(char* dn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(dn);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char* kwldap32G_ldap_dn2ufnA(char* dn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(dn);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char16_t* kwldap32G_ldap_dn2ufnW(char16_t* dn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(dn);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_encode_sort_controlA(void* ExternalHandle, void** SortKeys, void* Control, std::uint8_t Criticality) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(SortKeys);
    static_cast<void>(Control);
    static_cast<void>(Criticality);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_encode_sort_controlW(void* ExternalHandle, void** SortKeys, void* Control, std::uint8_t Criticality) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(SortKeys);
    static_cast<void>(Control);
    static_cast<void>(Criticality);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) char* kwldap32G_ldap_err2string(std::uint32_t err) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(err);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char* kwldap32G_ldap_err2stringA(std::uint32_t err) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(err);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char16_t* kwldap32G_ldap_err2stringW(std::uint32_t err) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(err);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_escape_filter_element(char* sourceFilterElement, std::uint32_t sourceLength, char* destFilterElement, std::uint32_t destLength) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(sourceFilterElement);
    static_cast<void>(sourceLength);
    static_cast<void>(destFilterElement);
    static_cast<void>(destLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_escape_filter_elementA(char* sourceFilterElement, std::uint32_t sourceLength, char* destFilterElement, std::uint32_t destLength) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(sourceFilterElement);
    static_cast<void>(sourceLength);
    static_cast<void>(destFilterElement);
    static_cast<void>(destLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_escape_filter_elementW(char* sourceFilterElement, std::uint32_t sourceLength, char16_t* destFilterElement, std::uint32_t destLength) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(sourceFilterElement);
    static_cast<void>(sourceLength);
    static_cast<void>(destFilterElement);
    static_cast<void>(destLength);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) char** kwldap32G_ldap_explode_dn(char* dn, std::uint32_t notypes) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(dn);
    static_cast<void>(notypes);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char** kwldap32G_ldap_explode_dnA(char* dn, std::uint32_t notypes) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(dn);
    static_cast<void>(notypes);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char16_t** kwldap32G_ldap_explode_dnW(char16_t* dn, std::uint32_t notypes) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(dn);
    static_cast<void>(notypes);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_extended_operation(void* ld, char* Oid, void* Data, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(Oid);
    static_cast<void>(Data);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_extended_operationA(void* ld, char* Oid, void* Data, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(Oid);
    static_cast<void>(Data);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_extended_operationW(void* ld, char16_t* Oid, void* Data, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(Oid);
    static_cast<void>(Data);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_extended_operation_sA(void* ExternalHandle, char* Oid, void* Data, void** ServerControls, void** ClientControls, char** ReturnedOid, void** ReturnedData) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(Oid);
    static_cast<void>(Data);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(ReturnedOid);
    static_cast<void>(ReturnedData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_extended_operation_sW(void* ExternalHandle, char16_t* Oid, void* Data, void** ServerControls, void** ClientControls, char16_t** ReturnedOid, void** ReturnedData) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(Oid);
    static_cast<void>(Data);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(ReturnedOid);
    static_cast<void>(ReturnedData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) char* kwldap32G_ldap_first_attribute(void* ld, void* entry_, void** ptr) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(entry_);
    static_cast<void>(ptr);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char* kwldap32G_ldap_first_attributeA(void* ld, void* entry_, void** ptr) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(entry_);
    static_cast<void>(ptr);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char16_t* kwldap32G_ldap_first_attributeW(void* ld, void* entry_, void** ptr) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(entry_);
    static_cast<void>(ptr);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_ldap_first_entry(void* ld, void* res) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_ldap_first_reference(void* ld, void* res) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_free_controls(void** Controls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Controls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_free_controlsA(void** Controls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Controls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_free_controlsW(void** Controls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Controls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) char* kwldap32G_ldap_get_dn(void* ld, void* entry_) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(entry_);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char* kwldap32G_ldap_get_dnA(void* ld, void* entry_) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(entry_);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char16_t* kwldap32G_ldap_get_dnW(void* ld, void* entry_) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(entry_);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_get_next_page(void* ExternalHandle, void* SearchHandle, std::uint32_t PageSize, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(SearchHandle);
    static_cast<void>(PageSize);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_get_next_page_s(void* ExternalHandle, void* SearchHandle, void* timeout, std::uint32_t PageSize, std::uint32_t* TotalCount, void** Results) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(SearchHandle);
    static_cast<void>(timeout);
    static_cast<void>(PageSize);
    static_cast<void>(TotalCount);
    static_cast<void>(Results);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_get_option(void* ld, std::int32_t option, void* outvalue) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(option);
    static_cast<void>(outvalue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_get_optionW(void* ld, std::int32_t option, void* outvalue) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(option);
    static_cast<void>(outvalue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_get_paged_count(void* ExternalHandle, void* SearchBlock, std::uint32_t* TotalCount, void* Results) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(SearchBlock);
    static_cast<void>(TotalCount);
    static_cast<void>(Results);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) char** kwldap32G_ldap_get_values(void* ld, void* entry_, char* attr) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(entry_);
    static_cast<void>(attr);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char** kwldap32G_ldap_get_valuesA(void* ld, void* entry_, char* attr) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(entry_);
    static_cast<void>(attr);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char16_t** kwldap32G_ldap_get_valuesW(void* ld, void* entry_, char16_t* attr) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(entry_);
    static_cast<void>(attr);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void** kwldap32G_ldap_get_values_len(void* ExternalHandle, void* Message, char* attr) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(Message);
    static_cast<void>(attr);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void** kwldap32G_ldap_get_values_lenA(void* ExternalHandle, void* Message, char* attr) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(Message);
    static_cast<void>(attr);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void** kwldap32G_ldap_get_values_lenW(void* ExternalHandle, void* Message, char16_t* attr) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(Message);
    static_cast<void>(attr);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_ldap_init(char* HostName, std::uint32_t PortNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(HostName);
    static_cast<void>(PortNumber);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_ldap_initA(char* HostName, std::uint32_t PortNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(HostName);
    static_cast<void>(PortNumber);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_ldap_initW(char16_t* HostName, std::uint32_t PortNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(HostName);
    static_cast<void>(PortNumber);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void kwldap32G_ldap_memfree(char* Block) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Block);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kwldap32G_ldap_memfreeA(char* Block) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Block);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) void kwldap32G_ldap_memfreeW(char16_t* Block) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Block);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modify(void* ld, char* dn, void** mods) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(mods);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modifyA(void* ld, char* dn, void** mods) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(mods);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modifyW(void* ld, char16_t* dn, void** mods) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(mods);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modify_ext(void* ld, char* dn, void** mods, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(mods);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modify_extA(void* ld, char* dn, void** mods, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(mods);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modify_extW(void* ld, char16_t* dn, void** mods, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(mods);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modify_ext_s(void* ld, char* dn, void** mods, void** ServerControls, void** ClientControls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(mods);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modify_ext_sA(void* ld, char* dn, void** mods, void** ServerControls, void** ClientControls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(mods);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modify_ext_sW(void* ld, char16_t* dn, void** mods, void** ServerControls, void** ClientControls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(mods);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modify_s(void* ld, char* dn, void** mods) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(mods);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modify_sA(void* ld, char* dn, void** mods) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(mods);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modify_sW(void* ld, char16_t* dn, void** mods) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(mods);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modrdn(void* ExternalHandle, char* DistinguishedName, char* NewDistinguishedName) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistinguishedName);
    static_cast<void>(NewDistinguishedName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modrdn2(void* ExternalHandle, char* DistinguishedName, char* NewDistinguishedName, std::int32_t DeleteOldRdn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistinguishedName);
    static_cast<void>(NewDistinguishedName);
    static_cast<void>(DeleteOldRdn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modrdn2A(void* ExternalHandle, char* DistinguishedName, char* NewDistinguishedName, std::int32_t DeleteOldRdn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistinguishedName);
    static_cast<void>(NewDistinguishedName);
    static_cast<void>(DeleteOldRdn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modrdn2W(void* ExternalHandle, char16_t* DistinguishedName, char16_t* NewDistinguishedName, std::int32_t DeleteOldRdn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistinguishedName);
    static_cast<void>(NewDistinguishedName);
    static_cast<void>(DeleteOldRdn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modrdn2_s(void* ExternalHandle, char* DistinguishedName, char* NewDistinguishedName, std::int32_t DeleteOldRdn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistinguishedName);
    static_cast<void>(NewDistinguishedName);
    static_cast<void>(DeleteOldRdn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modrdn2_sA(void* ExternalHandle, char* DistinguishedName, char* NewDistinguishedName, std::int32_t DeleteOldRdn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistinguishedName);
    static_cast<void>(NewDistinguishedName);
    static_cast<void>(DeleteOldRdn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modrdn2_sW(void* ExternalHandle, char16_t* DistinguishedName, char16_t* NewDistinguishedName, std::int32_t DeleteOldRdn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistinguishedName);
    static_cast<void>(NewDistinguishedName);
    static_cast<void>(DeleteOldRdn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modrdnA(void* ExternalHandle, char* DistinguishedName, char* NewDistinguishedName) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistinguishedName);
    static_cast<void>(NewDistinguishedName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modrdnW(void* ExternalHandle, char16_t* DistinguishedName, char16_t* NewDistinguishedName) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistinguishedName);
    static_cast<void>(NewDistinguishedName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modrdn_s(void* ExternalHandle, char* DistinguishedName, char* NewDistinguishedName) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistinguishedName);
    static_cast<void>(NewDistinguishedName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modrdn_sA(void* ExternalHandle, char* DistinguishedName, char* NewDistinguishedName) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistinguishedName);
    static_cast<void>(NewDistinguishedName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_modrdn_sW(void* ExternalHandle, char16_t* DistinguishedName, char16_t* NewDistinguishedName) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistinguishedName);
    static_cast<void>(NewDistinguishedName);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_msgfree(void* res) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) char* kwldap32G_ldap_next_attribute(void* ld, void* entry_, void* ptr) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(entry_);
    static_cast<void>(ptr);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char* kwldap32G_ldap_next_attributeA(void* ld, void* entry_, void* ptr) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(entry_);
    static_cast<void>(ptr);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) char16_t* kwldap32G_ldap_next_attributeW(void* ld, void* entry_, void* ptr) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(entry_);
    static_cast<void>(ptr);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_ldap_next_entry(void* ld, void* entry_) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(entry_);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_ldap_next_reference(void* ld, void* entry_) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(entry_);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_ldap_open(char* HostName, std::uint32_t PortNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(HostName);
    static_cast<void>(PortNumber);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_ldap_openA(char* HostName, std::uint32_t PortNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(HostName);
    static_cast<void>(PortNumber);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_ldap_openW(char16_t* HostName, std::uint32_t PortNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(HostName);
    static_cast<void>(PortNumber);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_parse_extended_resultA(void* Connection, void* ResultMessage, char** ResultOID, void** ResultData, std::uint8_t Freeit) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Connection);
    static_cast<void>(ResultMessage);
    static_cast<void>(ResultOID);
    static_cast<void>(ResultData);
    static_cast<void>(Freeit);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_parse_extended_resultW(void* Connection, void* ResultMessage, char16_t** ResultOID, void** ResultData, std::uint8_t Freeit) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Connection);
    static_cast<void>(ResultMessage);
    static_cast<void>(ResultOID);
    static_cast<void>(ResultData);
    static_cast<void>(Freeit);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_parse_page_control(void* ExternalHandle, void** ServerControls, std::uint32_t* TotalCount, void** Cookie) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(ServerControls);
    static_cast<void>(TotalCount);
    static_cast<void>(Cookie);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_parse_page_controlA(void* ExternalHandle, void** ServerControls, std::uint32_t* TotalCount, void** Cookie) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(ServerControls);
    static_cast<void>(TotalCount);
    static_cast<void>(Cookie);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_parse_page_controlW(void* ExternalHandle, void** ServerControls, std::uint32_t* TotalCount, void** Cookie) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(ServerControls);
    static_cast<void>(TotalCount);
    static_cast<void>(Cookie);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_parse_reference(void* Connection, void* ResultMessage, char*** Referrals) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Connection);
    static_cast<void>(ResultMessage);
    static_cast<void>(Referrals);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_parse_referenceA(void* Connection, void* ResultMessage, char*** Referrals) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Connection);
    static_cast<void>(ResultMessage);
    static_cast<void>(Referrals);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_parse_referenceW(void* Connection, void* ResultMessage, char16_t*** Referrals) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Connection);
    static_cast<void>(ResultMessage);
    static_cast<void>(Referrals);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_parse_result(void* Connection, void* ResultMessage, std::uint32_t* ReturnCode, char** MatchedDNs, char** ErrorMessage, char*** Referrals, void*** ServerControls, std::uint8_t Freeit) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Connection);
    static_cast<void>(ResultMessage);
    static_cast<void>(ReturnCode);
    static_cast<void>(MatchedDNs);
    static_cast<void>(ErrorMessage);
    static_cast<void>(Referrals);
    static_cast<void>(ServerControls);
    static_cast<void>(Freeit);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_parse_resultA(void* Connection, void* ResultMessage, std::uint32_t* ReturnCode, char** MatchedDNs, char** ErrorMessage, char*** Referrals, void*** ServerControls, std::uint8_t Freeit) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Connection);
    static_cast<void>(ResultMessage);
    static_cast<void>(ReturnCode);
    static_cast<void>(MatchedDNs);
    static_cast<void>(ErrorMessage);
    static_cast<void>(Referrals);
    static_cast<void>(ServerControls);
    static_cast<void>(Freeit);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_parse_resultW(void* Connection, void* ResultMessage, std::uint32_t* ReturnCode, char16_t** MatchedDNs, char16_t** ErrorMessage, char16_t*** Referrals, void*** ServerControls, std::uint8_t Freeit) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(Connection);
    static_cast<void>(ResultMessage);
    static_cast<void>(ReturnCode);
    static_cast<void>(MatchedDNs);
    static_cast<void>(ErrorMessage);
    static_cast<void>(Referrals);
    static_cast<void>(ServerControls);
    static_cast<void>(Freeit);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_parse_sort_control(void* ExternalHandle, void** Control, std::uint32_t* Result, char** Attribute) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(Control);
    static_cast<void>(Result);
    static_cast<void>(Attribute);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_parse_sort_controlA(void* ExternalHandle, void** Control, std::uint32_t* Result, char** Attribute) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(Control);
    static_cast<void>(Result);
    static_cast<void>(Attribute);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_parse_sort_controlW(void* ExternalHandle, void** Control, std::uint32_t* Result, char16_t** Attribute) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(Control);
    static_cast<void>(Result);
    static_cast<void>(Attribute);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwldap32G_ldap_parse_vlv_controlA(void* ExternalHandle, void** Control, std::uint32_t* TargetPos, std::uint32_t* ListCount, void* Context, std::int32_t* ErrCode) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(Control);
    static_cast<void>(TargetPos);
    static_cast<void>(ListCount);
    static_cast<void>(Context);
    static_cast<void>(ErrCode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwldap32G_ldap_parse_vlv_controlW(void* ExternalHandle, void** Control, std::uint32_t* TargetPos, std::uint32_t* ListCount, void* Context, std::int32_t* ErrCode) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(Control);
    static_cast<void>(TargetPos);
    static_cast<void>(ListCount);
    static_cast<void>(Context);
    static_cast<void>(ErrCode);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kwldap32G_ldap_perror(void* ld, char* msg) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(msg);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_rename_ext(void* ld, char* dn, char* NewRDN, char* NewParent, std::int32_t DeleteOldRdn, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(NewRDN);
    static_cast<void>(NewParent);
    static_cast<void>(DeleteOldRdn);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_rename_extA(void* ld, char* dn, char* NewRDN, char* NewParent, std::int32_t DeleteOldRdn, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(NewRDN);
    static_cast<void>(NewParent);
    static_cast<void>(DeleteOldRdn);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_rename_extW(void* ld, char16_t* dn, char16_t* NewRDN, char16_t* NewParent, std::int32_t DeleteOldRdn, void** ServerControls, void** ClientControls, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(NewRDN);
    static_cast<void>(NewParent);
    static_cast<void>(DeleteOldRdn);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_rename_ext_s(void* ld, char* dn, char* NewRDN, char* NewParent, std::int32_t DeleteOldRdn, void** ServerControls, void** ClientControls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(NewRDN);
    static_cast<void>(NewParent);
    static_cast<void>(DeleteOldRdn);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_rename_ext_sA(void* ld, char* dn, char* NewRDN, char* NewParent, std::int32_t DeleteOldRdn, void** ServerControls, void** ClientControls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(NewRDN);
    static_cast<void>(NewParent);
    static_cast<void>(DeleteOldRdn);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_rename_ext_sW(void* ld, char16_t* dn, char16_t* NewRDN, char16_t* NewParent, std::int32_t DeleteOldRdn, void** ServerControls, void** ClientControls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(NewRDN);
    static_cast<void>(NewParent);
    static_cast<void>(DeleteOldRdn);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_result(void* ld, std::uint32_t msgid, std::uint32_t all, void* timeout, void** res) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(msgid);
    static_cast<void>(all);
    static_cast<void>(timeout);
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_result2error(void* ld, void* res, std::uint32_t freeit) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(res);
    static_cast<void>(freeit);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwldap32G_ldap_sasl_bindA(void* ExternalHandle, char* DistName, char* AuthMechanism, const void* cred, void** ServerCtrls, void** ClientCtrls, std::int32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistName);
    static_cast<void>(AuthMechanism);
    static_cast<void>(cred);
    static_cast<void>(ServerCtrls);
    static_cast<void>(ClientCtrls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwldap32G_ldap_sasl_bindW(void* ExternalHandle, char16_t* DistName, char16_t* AuthMechanism, const void* cred, void** ServerCtrls, void** ClientCtrls, std::int32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistName);
    static_cast<void>(AuthMechanism);
    static_cast<void>(cred);
    static_cast<void>(ServerCtrls);
    static_cast<void>(ClientCtrls);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwldap32G_ldap_sasl_bind_sA(void* ExternalHandle, char* DistName, char* AuthMechanism, const void* cred, void** ServerCtrls, void** ClientCtrls, void* ServerData) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistName);
    static_cast<void>(AuthMechanism);
    static_cast<void>(cred);
    static_cast<void>(ServerCtrls);
    static_cast<void>(ClientCtrls);
    static_cast<void>(ServerData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::int32_t kwldap32G_ldap_sasl_bind_sW(void* ExternalHandle, char16_t* DistName, char16_t* AuthMechanism, const void* cred, void** ServerCtrls, void** ClientCtrls, void* ServerData) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistName);
    static_cast<void>(AuthMechanism);
    static_cast<void>(cred);
    static_cast<void>(ServerCtrls);
    static_cast<void>(ClientCtrls);
    static_cast<void>(ServerData);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_search(void* ld, char* base, std::uint32_t scope, char* filter, char** attrs, std::uint32_t attrsonly) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(base);
    static_cast<void>(scope);
    static_cast<void>(filter);
    static_cast<void>(attrs);
    static_cast<void>(attrsonly);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_searchA(void* ld, char* base, std::uint32_t scope, char* filter, char** attrs, std::uint32_t attrsonly) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(base);
    static_cast<void>(scope);
    static_cast<void>(filter);
    static_cast<void>(attrs);
    static_cast<void>(attrsonly);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_searchW(void* ld, char16_t* base, std::uint32_t scope, char16_t* filter, char16_t** attrs, std::uint32_t attrsonly) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(base);
    static_cast<void>(scope);
    static_cast<void>(filter);
    static_cast<void>(attrs);
    static_cast<void>(attrsonly);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_search_abandon_page(void* ExternalHandle, void* SearchBlock) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(SearchBlock);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_search_ext(void* ld, char* base, std::uint32_t scope, char* filter, char** attrs, std::uint32_t attrsonly, void** ServerControls, void** ClientControls, std::uint32_t TimeLimit, std::uint32_t SizeLimit, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(base);
    static_cast<void>(scope);
    static_cast<void>(filter);
    static_cast<void>(attrs);
    static_cast<void>(attrsonly);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(TimeLimit);
    static_cast<void>(SizeLimit);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_search_extA(void* ld, char* base, std::uint32_t scope, char* filter, char** attrs, std::uint32_t attrsonly, void** ServerControls, void** ClientControls, std::uint32_t TimeLimit, std::uint32_t SizeLimit, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(base);
    static_cast<void>(scope);
    static_cast<void>(filter);
    static_cast<void>(attrs);
    static_cast<void>(attrsonly);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(TimeLimit);
    static_cast<void>(SizeLimit);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_search_extW(void* ld, char16_t* base, std::uint32_t scope, char16_t* filter, char16_t** attrs, std::uint32_t attrsonly, void** ServerControls, void** ClientControls, std::uint32_t TimeLimit, std::uint32_t SizeLimit, std::uint32_t* MessageNumber) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(base);
    static_cast<void>(scope);
    static_cast<void>(filter);
    static_cast<void>(attrs);
    static_cast<void>(attrsonly);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(TimeLimit);
    static_cast<void>(SizeLimit);
    static_cast<void>(MessageNumber);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_search_ext_s(void* ld, char* base, std::uint32_t scope, char* filter, char** attrs, std::uint32_t attrsonly, void** ServerControls, void** ClientControls, void* timeout, std::uint32_t SizeLimit, void** res) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(base);
    static_cast<void>(scope);
    static_cast<void>(filter);
    static_cast<void>(attrs);
    static_cast<void>(attrsonly);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(timeout);
    static_cast<void>(SizeLimit);
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_search_ext_sA(void* ld, char* base, std::uint32_t scope, char* filter, char** attrs, std::uint32_t attrsonly, void** ServerControls, void** ClientControls, void* timeout, std::uint32_t SizeLimit, void** res) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(base);
    static_cast<void>(scope);
    static_cast<void>(filter);
    static_cast<void>(attrs);
    static_cast<void>(attrsonly);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(timeout);
    static_cast<void>(SizeLimit);
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_search_ext_sW(void* ld, char16_t* base, std::uint32_t scope, char16_t* filter, char16_t** attrs, std::uint32_t attrsonly, void** ServerControls, void** ClientControls, void* timeout, std::uint32_t SizeLimit, void** res) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(base);
    static_cast<void>(scope);
    static_cast<void>(filter);
    static_cast<void>(attrs);
    static_cast<void>(attrsonly);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(timeout);
    static_cast<void>(SizeLimit);
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_ldap_search_init_page(void* ExternalHandle, char* DistinguishedName, std::uint32_t ScopeOfSearch, char* SearchFilter, char** AttributeList, std::uint32_t AttributesOnly, void** ServerControls, void** ClientControls, std::uint32_t PageTimeLimit, std::uint32_t TotalSizeLimit, void** SortKeys) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistinguishedName);
    static_cast<void>(ScopeOfSearch);
    static_cast<void>(SearchFilter);
    static_cast<void>(AttributeList);
    static_cast<void>(AttributesOnly);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(PageTimeLimit);
    static_cast<void>(TotalSizeLimit);
    static_cast<void>(SortKeys);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_ldap_search_init_pageA(void* ExternalHandle, char* DistinguishedName, std::uint32_t ScopeOfSearch, char* SearchFilter, char** AttributeList, std::uint32_t AttributesOnly, void** ServerControls, void** ClientControls, std::uint32_t PageTimeLimit, std::uint32_t TotalSizeLimit, void** SortKeys) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistinguishedName);
    static_cast<void>(ScopeOfSearch);
    static_cast<void>(SearchFilter);
    static_cast<void>(AttributeList);
    static_cast<void>(AttributesOnly);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(PageTimeLimit);
    static_cast<void>(TotalSizeLimit);
    static_cast<void>(SortKeys);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_ldap_search_init_pageW(void* ExternalHandle, char16_t* DistinguishedName, std::uint32_t ScopeOfSearch, char16_t* SearchFilter, char16_t** AttributeList, std::uint32_t AttributesOnly, void** ServerControls, void** ClientControls, std::uint32_t PageTimeLimit, std::uint32_t TotalSizeLimit, void** SortKeys) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(DistinguishedName);
    static_cast<void>(ScopeOfSearch);
    static_cast<void>(SearchFilter);
    static_cast<void>(AttributeList);
    static_cast<void>(AttributesOnly);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    static_cast<void>(PageTimeLimit);
    static_cast<void>(TotalSizeLimit);
    static_cast<void>(SortKeys);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_search_s(void* ld, char* base, std::uint32_t scope, char* filter, char** attrs, std::uint32_t attrsonly, void** res) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(base);
    static_cast<void>(scope);
    static_cast<void>(filter);
    static_cast<void>(attrs);
    static_cast<void>(attrsonly);
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_search_sA(void* ld, char* base, std::uint32_t scope, char* filter, char** attrs, std::uint32_t attrsonly, void** res) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(base);
    static_cast<void>(scope);
    static_cast<void>(filter);
    static_cast<void>(attrs);
    static_cast<void>(attrsonly);
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_search_sW(void* ld, char16_t* base, std::uint32_t scope, char16_t* filter, char16_t** attrs, std::uint32_t attrsonly, void** res) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(base);
    static_cast<void>(scope);
    static_cast<void>(filter);
    static_cast<void>(attrs);
    static_cast<void>(attrsonly);
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_search_st(void* ld, char* base, std::uint32_t scope, char* filter, char** attrs, std::uint32_t attrsonly, void* timeout, void** res) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(base);
    static_cast<void>(scope);
    static_cast<void>(filter);
    static_cast<void>(attrs);
    static_cast<void>(attrsonly);
    static_cast<void>(timeout);
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_search_stA(void* ld, char* base, std::uint32_t scope, char* filter, char** attrs, std::uint32_t attrsonly, void* timeout, void** res) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(base);
    static_cast<void>(scope);
    static_cast<void>(filter);
    static_cast<void>(attrs);
    static_cast<void>(attrsonly);
    static_cast<void>(timeout);
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_search_stW(void* ld, char16_t* base, std::uint32_t scope, char16_t* filter, char16_t** attrs, std::uint32_t attrsonly, void* timeout, void** res) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(base);
    static_cast<void>(scope);
    static_cast<void>(filter);
    static_cast<void>(attrs);
    static_cast<void>(attrsonly);
    static_cast<void>(timeout);
    static_cast<void>(res);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_set_dbg_flags(std::uint32_t NewFlags) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(NewFlags);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void kwldap32G_ldap_set_dbg_routine(std::uint64_t DebugPrintRoutine) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(DebugPrintRoutine);
    set_last_error(kNotImplemented);
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_set_option(void* ld, std::int32_t option, const void* invalue) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(option);
    static_cast<void>(invalue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_set_optionW(void* ld, std::int32_t option, const void* invalue) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(option);
    static_cast<void>(invalue);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_simple_bind(void* ld, char* dn, char* passwd) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(passwd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_simple_bindA(void* ld, char* dn, char* passwd) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(passwd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_simple_bindW(void* ld, char16_t* dn, char16_t* passwd) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(passwd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_simple_bind_s(void* ld, char* dn, char* passwd) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(passwd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_simple_bind_sA(void* ld, char* dn, char* passwd) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(passwd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_simple_bind_sW(void* ld, char16_t* dn, char16_t* passwd) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    static_cast<void>(dn);
    static_cast<void>(passwd);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_ldap_sslinit(char* HostName, std::uint32_t PortNumber, std::int32_t secure) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(HostName);
    static_cast<void>(PortNumber);
    static_cast<void>(secure);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_ldap_sslinitA(char* HostName, std::uint32_t PortNumber, std::int32_t secure) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(HostName);
    static_cast<void>(PortNumber);
    static_cast<void>(secure);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) void* kwldap32G_ldap_sslinitW(char16_t* HostName, std::uint32_t PortNumber, std::int32_t secure) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(HostName);
    static_cast<void>(PortNumber);
    static_cast<void>(secure);
    set_last_error(kNotImplemented);
    return nullptr;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_start_tls_sA(void* ExternalHandle, std::uint32_t* ServerReturnValue, void** result, void** ServerControls, void** ClientControls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(ServerReturnValue);
    static_cast<void>(result);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_start_tls_sW(void* ExternalHandle, std::uint32_t* ServerReturnValue, void** result, void** ServerControls, void** ClientControls) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    static_cast<void>(ServerReturnValue);
    static_cast<void>(result);
    static_cast<void>(ServerControls);
    static_cast<void>(ClientControls);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_startup(std::uint64_t version, void* Instance) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(version);
    static_cast<void>(Instance);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint8_t kwldap32G_ldap_stop_tls_s(void* ExternalHandle) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ExternalHandle);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_ufn2dn(char* ufn, char** pDn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ufn);
    static_cast<void>(pDn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_ufn2dnA(char* ufn, char** pDn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ufn);
    static_cast<void>(pDn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_ufn2dnW(char16_t* ufn, char16_t** pDn) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ufn);
    static_cast<void>(pDn);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_unbind(void* ld) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_unbind_s(void* ld) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(ld);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_value_free(char** vals) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(vals);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_value_freeA(char** vals) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(vals);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_value_freeW(char16_t** vals) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(vals);
    set_last_error(kNotImplemented);
    return 0;
}


extern "C" __attribute__((ms_abi)) std::uint32_t kwldap32G_ldap_value_free_len(void** vals) noexcept {
    // Refused: the LDAP client.
    //
    // this is a protocol client with its own encoding and session state,
    // reached over a socket this runtime does provide but does not build an
    // LDAP session on
    static_cast<void>(vals);
    set_last_error(kNotImplemented);
    return 0;
}

}  // namespace

void add_generated_wldap32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("LdapGetLastError", reinterpret_cast<void*>(&kwldap32G_LdapGetLastError));
    e("LdapMapErrorToWin32", reinterpret_cast<void*>(&kwldap32G_LdapMapErrorToWin32));
    e("LdapUTF8ToUnicode", reinterpret_cast<void*>(&kwldap32G_LdapUTF8ToUnicode));
    e("LdapUnicodeToUTF8", reinterpret_cast<void*>(&kwldap32G_LdapUnicodeToUTF8));
    e("ber_bvfree", reinterpret_cast<void*>(&kwldap32G_ber_bvfree));
    e("cldap_open", reinterpret_cast<void*>(&kwldap32G_cldap_open));
    e("cldap_openA", reinterpret_cast<void*>(&kwldap32G_cldap_openA));
    e("cldap_openW", reinterpret_cast<void*>(&kwldap32G_cldap_openW));
    e("ldap_abandon", reinterpret_cast<void*>(&kwldap32G_ldap_abandon));
    e("ldap_add", reinterpret_cast<void*>(&kwldap32G_ldap_add));
    e("ldap_addA", reinterpret_cast<void*>(&kwldap32G_ldap_addA));
    e("ldap_addW", reinterpret_cast<void*>(&kwldap32G_ldap_addW));
    e("ldap_add_ext", reinterpret_cast<void*>(&kwldap32G_ldap_add_ext));
    e("ldap_add_extA", reinterpret_cast<void*>(&kwldap32G_ldap_add_extA));
    e("ldap_add_extW", reinterpret_cast<void*>(&kwldap32G_ldap_add_extW));
    e("ldap_add_ext_s", reinterpret_cast<void*>(&kwldap32G_ldap_add_ext_s));
    e("ldap_add_ext_sA", reinterpret_cast<void*>(&kwldap32G_ldap_add_ext_sA));
    e("ldap_add_ext_sW", reinterpret_cast<void*>(&kwldap32G_ldap_add_ext_sW));
    e("ldap_add_s", reinterpret_cast<void*>(&kwldap32G_ldap_add_s));
    e("ldap_add_sA", reinterpret_cast<void*>(&kwldap32G_ldap_add_sA));
    e("ldap_add_sW", reinterpret_cast<void*>(&kwldap32G_ldap_add_sW));
    e("ldap_bind", reinterpret_cast<void*>(&kwldap32G_ldap_bind));
    e("ldap_bindA", reinterpret_cast<void*>(&kwldap32G_ldap_bindA));
    e("ldap_bindW", reinterpret_cast<void*>(&kwldap32G_ldap_bindW));
    e("ldap_bind_s", reinterpret_cast<void*>(&kwldap32G_ldap_bind_s));
    e("ldap_bind_sA", reinterpret_cast<void*>(&kwldap32G_ldap_bind_sA));
    e("ldap_bind_sW", reinterpret_cast<void*>(&kwldap32G_ldap_bind_sW));
    e("ldap_check_filterA", reinterpret_cast<void*>(&kwldap32G_ldap_check_filterA));
    e("ldap_check_filterW", reinterpret_cast<void*>(&kwldap32G_ldap_check_filterW));
    e("ldap_cleanup", reinterpret_cast<void*>(&kwldap32G_ldap_cleanup));
    e("ldap_close_extended_op", reinterpret_cast<void*>(&kwldap32G_ldap_close_extended_op));
    e("ldap_compare", reinterpret_cast<void*>(&kwldap32G_ldap_compare));
    e("ldap_compareA", reinterpret_cast<void*>(&kwldap32G_ldap_compareA));
    e("ldap_compareW", reinterpret_cast<void*>(&kwldap32G_ldap_compareW));
    e("ldap_compare_ext", reinterpret_cast<void*>(&kwldap32G_ldap_compare_ext));
    e("ldap_compare_extA", reinterpret_cast<void*>(&kwldap32G_ldap_compare_extA));
    e("ldap_compare_extW", reinterpret_cast<void*>(&kwldap32G_ldap_compare_extW));
    e("ldap_compare_ext_s", reinterpret_cast<void*>(&kwldap32G_ldap_compare_ext_s));
    e("ldap_compare_ext_sA", reinterpret_cast<void*>(&kwldap32G_ldap_compare_ext_sA));
    e("ldap_compare_ext_sW", reinterpret_cast<void*>(&kwldap32G_ldap_compare_ext_sW));
    e("ldap_compare_s", reinterpret_cast<void*>(&kwldap32G_ldap_compare_s));
    e("ldap_compare_sA", reinterpret_cast<void*>(&kwldap32G_ldap_compare_sA));
    e("ldap_compare_sW", reinterpret_cast<void*>(&kwldap32G_ldap_compare_sW));
    e("ldap_conn_from_msg", reinterpret_cast<void*>(&kwldap32G_ldap_conn_from_msg));
    e("ldap_connect", reinterpret_cast<void*>(&kwldap32G_ldap_connect));
    e("ldap_control_free", reinterpret_cast<void*>(&kwldap32G_ldap_control_free));
    e("ldap_control_freeA", reinterpret_cast<void*>(&kwldap32G_ldap_control_freeA));
    e("ldap_control_freeW", reinterpret_cast<void*>(&kwldap32G_ldap_control_freeW));
    e("ldap_controls_free", reinterpret_cast<void*>(&kwldap32G_ldap_controls_free));
    e("ldap_controls_freeA", reinterpret_cast<void*>(&kwldap32G_ldap_controls_freeA));
    e("ldap_controls_freeW", reinterpret_cast<void*>(&kwldap32G_ldap_controls_freeW));
    e("ldap_count_entries", reinterpret_cast<void*>(&kwldap32G_ldap_count_entries));
    e("ldap_count_references", reinterpret_cast<void*>(&kwldap32G_ldap_count_references));
    e("ldap_count_values", reinterpret_cast<void*>(&kwldap32G_ldap_count_values));
    e("ldap_count_valuesA", reinterpret_cast<void*>(&kwldap32G_ldap_count_valuesA));
    e("ldap_count_valuesW", reinterpret_cast<void*>(&kwldap32G_ldap_count_valuesW));
    e("ldap_count_values_len", reinterpret_cast<void*>(&kwldap32G_ldap_count_values_len));
    e("ldap_create_page_control", reinterpret_cast<void*>(&kwldap32G_ldap_create_page_control));
    e("ldap_create_page_controlA", reinterpret_cast<void*>(&kwldap32G_ldap_create_page_controlA));
    e("ldap_create_page_controlW", reinterpret_cast<void*>(&kwldap32G_ldap_create_page_controlW));
    e("ldap_create_sort_control", reinterpret_cast<void*>(&kwldap32G_ldap_create_sort_control));
    e("ldap_create_sort_controlA", reinterpret_cast<void*>(&kwldap32G_ldap_create_sort_controlA));
    e("ldap_create_sort_controlW", reinterpret_cast<void*>(&kwldap32G_ldap_create_sort_controlW));
    e("ldap_create_vlv_controlA", reinterpret_cast<void*>(&kwldap32G_ldap_create_vlv_controlA));
    e("ldap_create_vlv_controlW", reinterpret_cast<void*>(&kwldap32G_ldap_create_vlv_controlW));
    e("ldap_delete", reinterpret_cast<void*>(&kwldap32G_ldap_delete));
    e("ldap_deleteA", reinterpret_cast<void*>(&kwldap32G_ldap_deleteA));
    e("ldap_deleteW", reinterpret_cast<void*>(&kwldap32G_ldap_deleteW));
    e("ldap_delete_ext", reinterpret_cast<void*>(&kwldap32G_ldap_delete_ext));
    e("ldap_delete_extA", reinterpret_cast<void*>(&kwldap32G_ldap_delete_extA));
    e("ldap_delete_extW", reinterpret_cast<void*>(&kwldap32G_ldap_delete_extW));
    e("ldap_delete_ext_s", reinterpret_cast<void*>(&kwldap32G_ldap_delete_ext_s));
    e("ldap_delete_ext_sA", reinterpret_cast<void*>(&kwldap32G_ldap_delete_ext_sA));
    e("ldap_delete_ext_sW", reinterpret_cast<void*>(&kwldap32G_ldap_delete_ext_sW));
    e("ldap_delete_s", reinterpret_cast<void*>(&kwldap32G_ldap_delete_s));
    e("ldap_delete_sA", reinterpret_cast<void*>(&kwldap32G_ldap_delete_sA));
    e("ldap_delete_sW", reinterpret_cast<void*>(&kwldap32G_ldap_delete_sW));
    e("ldap_dn2ufn", reinterpret_cast<void*>(&kwldap32G_ldap_dn2ufn));
    e("ldap_dn2ufnA", reinterpret_cast<void*>(&kwldap32G_ldap_dn2ufnA));
    e("ldap_dn2ufnW", reinterpret_cast<void*>(&kwldap32G_ldap_dn2ufnW));
    e("ldap_encode_sort_controlA", reinterpret_cast<void*>(&kwldap32G_ldap_encode_sort_controlA));
    e("ldap_encode_sort_controlW", reinterpret_cast<void*>(&kwldap32G_ldap_encode_sort_controlW));
    e("ldap_err2string", reinterpret_cast<void*>(&kwldap32G_ldap_err2string));
    e("ldap_err2stringA", reinterpret_cast<void*>(&kwldap32G_ldap_err2stringA));
    e("ldap_err2stringW", reinterpret_cast<void*>(&kwldap32G_ldap_err2stringW));
    e("ldap_escape_filter_element", reinterpret_cast<void*>(&kwldap32G_ldap_escape_filter_element));
    e("ldap_escape_filter_elementA", reinterpret_cast<void*>(&kwldap32G_ldap_escape_filter_elementA));
    e("ldap_escape_filter_elementW", reinterpret_cast<void*>(&kwldap32G_ldap_escape_filter_elementW));
    e("ldap_explode_dn", reinterpret_cast<void*>(&kwldap32G_ldap_explode_dn));
    e("ldap_explode_dnA", reinterpret_cast<void*>(&kwldap32G_ldap_explode_dnA));
    e("ldap_explode_dnW", reinterpret_cast<void*>(&kwldap32G_ldap_explode_dnW));
    e("ldap_extended_operation", reinterpret_cast<void*>(&kwldap32G_ldap_extended_operation));
    e("ldap_extended_operationA", reinterpret_cast<void*>(&kwldap32G_ldap_extended_operationA));
    e("ldap_extended_operationW", reinterpret_cast<void*>(&kwldap32G_ldap_extended_operationW));
    e("ldap_extended_operation_sA", reinterpret_cast<void*>(&kwldap32G_ldap_extended_operation_sA));
    e("ldap_extended_operation_sW", reinterpret_cast<void*>(&kwldap32G_ldap_extended_operation_sW));
    e("ldap_first_attribute", reinterpret_cast<void*>(&kwldap32G_ldap_first_attribute));
    e("ldap_first_attributeA", reinterpret_cast<void*>(&kwldap32G_ldap_first_attributeA));
    e("ldap_first_attributeW", reinterpret_cast<void*>(&kwldap32G_ldap_first_attributeW));
    e("ldap_first_entry", reinterpret_cast<void*>(&kwldap32G_ldap_first_entry));
    e("ldap_first_reference", reinterpret_cast<void*>(&kwldap32G_ldap_first_reference));
    e("ldap_free_controls", reinterpret_cast<void*>(&kwldap32G_ldap_free_controls));
    e("ldap_free_controlsA", reinterpret_cast<void*>(&kwldap32G_ldap_free_controlsA));
    e("ldap_free_controlsW", reinterpret_cast<void*>(&kwldap32G_ldap_free_controlsW));
    e("ldap_get_dn", reinterpret_cast<void*>(&kwldap32G_ldap_get_dn));
    e("ldap_get_dnA", reinterpret_cast<void*>(&kwldap32G_ldap_get_dnA));
    e("ldap_get_dnW", reinterpret_cast<void*>(&kwldap32G_ldap_get_dnW));
    e("ldap_get_next_page", reinterpret_cast<void*>(&kwldap32G_ldap_get_next_page));
    e("ldap_get_next_page_s", reinterpret_cast<void*>(&kwldap32G_ldap_get_next_page_s));
    e("ldap_get_option", reinterpret_cast<void*>(&kwldap32G_ldap_get_option));
    e("ldap_get_optionW", reinterpret_cast<void*>(&kwldap32G_ldap_get_optionW));
    e("ldap_get_paged_count", reinterpret_cast<void*>(&kwldap32G_ldap_get_paged_count));
    e("ldap_get_values", reinterpret_cast<void*>(&kwldap32G_ldap_get_values));
    e("ldap_get_valuesA", reinterpret_cast<void*>(&kwldap32G_ldap_get_valuesA));
    e("ldap_get_valuesW", reinterpret_cast<void*>(&kwldap32G_ldap_get_valuesW));
    e("ldap_get_values_len", reinterpret_cast<void*>(&kwldap32G_ldap_get_values_len));
    e("ldap_get_values_lenA", reinterpret_cast<void*>(&kwldap32G_ldap_get_values_lenA));
    e("ldap_get_values_lenW", reinterpret_cast<void*>(&kwldap32G_ldap_get_values_lenW));
    e("ldap_init", reinterpret_cast<void*>(&kwldap32G_ldap_init));
    e("ldap_initA", reinterpret_cast<void*>(&kwldap32G_ldap_initA));
    e("ldap_initW", reinterpret_cast<void*>(&kwldap32G_ldap_initW));
    e("ldap_memfree", reinterpret_cast<void*>(&kwldap32G_ldap_memfree));
    e("ldap_memfreeA", reinterpret_cast<void*>(&kwldap32G_ldap_memfreeA));
    e("ldap_memfreeW", reinterpret_cast<void*>(&kwldap32G_ldap_memfreeW));
    e("ldap_modify", reinterpret_cast<void*>(&kwldap32G_ldap_modify));
    e("ldap_modifyA", reinterpret_cast<void*>(&kwldap32G_ldap_modifyA));
    e("ldap_modifyW", reinterpret_cast<void*>(&kwldap32G_ldap_modifyW));
    e("ldap_modify_ext", reinterpret_cast<void*>(&kwldap32G_ldap_modify_ext));
    e("ldap_modify_extA", reinterpret_cast<void*>(&kwldap32G_ldap_modify_extA));
    e("ldap_modify_extW", reinterpret_cast<void*>(&kwldap32G_ldap_modify_extW));
    e("ldap_modify_ext_s", reinterpret_cast<void*>(&kwldap32G_ldap_modify_ext_s));
    e("ldap_modify_ext_sA", reinterpret_cast<void*>(&kwldap32G_ldap_modify_ext_sA));
    e("ldap_modify_ext_sW", reinterpret_cast<void*>(&kwldap32G_ldap_modify_ext_sW));
    e("ldap_modify_s", reinterpret_cast<void*>(&kwldap32G_ldap_modify_s));
    e("ldap_modify_sA", reinterpret_cast<void*>(&kwldap32G_ldap_modify_sA));
    e("ldap_modify_sW", reinterpret_cast<void*>(&kwldap32G_ldap_modify_sW));
    e("ldap_modrdn", reinterpret_cast<void*>(&kwldap32G_ldap_modrdn));
    e("ldap_modrdn2", reinterpret_cast<void*>(&kwldap32G_ldap_modrdn2));
    e("ldap_modrdn2A", reinterpret_cast<void*>(&kwldap32G_ldap_modrdn2A));
    e("ldap_modrdn2W", reinterpret_cast<void*>(&kwldap32G_ldap_modrdn2W));
    e("ldap_modrdn2_s", reinterpret_cast<void*>(&kwldap32G_ldap_modrdn2_s));
    e("ldap_modrdn2_sA", reinterpret_cast<void*>(&kwldap32G_ldap_modrdn2_sA));
    e("ldap_modrdn2_sW", reinterpret_cast<void*>(&kwldap32G_ldap_modrdn2_sW));
    e("ldap_modrdnA", reinterpret_cast<void*>(&kwldap32G_ldap_modrdnA));
    e("ldap_modrdnW", reinterpret_cast<void*>(&kwldap32G_ldap_modrdnW));
    e("ldap_modrdn_s", reinterpret_cast<void*>(&kwldap32G_ldap_modrdn_s));
    e("ldap_modrdn_sA", reinterpret_cast<void*>(&kwldap32G_ldap_modrdn_sA));
    e("ldap_modrdn_sW", reinterpret_cast<void*>(&kwldap32G_ldap_modrdn_sW));
    e("ldap_msgfree", reinterpret_cast<void*>(&kwldap32G_ldap_msgfree));
    e("ldap_next_attribute", reinterpret_cast<void*>(&kwldap32G_ldap_next_attribute));
    e("ldap_next_attributeA", reinterpret_cast<void*>(&kwldap32G_ldap_next_attributeA));
    e("ldap_next_attributeW", reinterpret_cast<void*>(&kwldap32G_ldap_next_attributeW));
    e("ldap_next_entry", reinterpret_cast<void*>(&kwldap32G_ldap_next_entry));
    e("ldap_next_reference", reinterpret_cast<void*>(&kwldap32G_ldap_next_reference));
    e("ldap_open", reinterpret_cast<void*>(&kwldap32G_ldap_open));
    e("ldap_openA", reinterpret_cast<void*>(&kwldap32G_ldap_openA));
    e("ldap_openW", reinterpret_cast<void*>(&kwldap32G_ldap_openW));
    e("ldap_parse_extended_resultA", reinterpret_cast<void*>(&kwldap32G_ldap_parse_extended_resultA));
    e("ldap_parse_extended_resultW", reinterpret_cast<void*>(&kwldap32G_ldap_parse_extended_resultW));
    e("ldap_parse_page_control", reinterpret_cast<void*>(&kwldap32G_ldap_parse_page_control));
    e("ldap_parse_page_controlA", reinterpret_cast<void*>(&kwldap32G_ldap_parse_page_controlA));
    e("ldap_parse_page_controlW", reinterpret_cast<void*>(&kwldap32G_ldap_parse_page_controlW));
    e("ldap_parse_reference", reinterpret_cast<void*>(&kwldap32G_ldap_parse_reference));
    e("ldap_parse_referenceA", reinterpret_cast<void*>(&kwldap32G_ldap_parse_referenceA));
    e("ldap_parse_referenceW", reinterpret_cast<void*>(&kwldap32G_ldap_parse_referenceW));
    e("ldap_parse_result", reinterpret_cast<void*>(&kwldap32G_ldap_parse_result));
    e("ldap_parse_resultA", reinterpret_cast<void*>(&kwldap32G_ldap_parse_resultA));
    e("ldap_parse_resultW", reinterpret_cast<void*>(&kwldap32G_ldap_parse_resultW));
    e("ldap_parse_sort_control", reinterpret_cast<void*>(&kwldap32G_ldap_parse_sort_control));
    e("ldap_parse_sort_controlA", reinterpret_cast<void*>(&kwldap32G_ldap_parse_sort_controlA));
    e("ldap_parse_sort_controlW", reinterpret_cast<void*>(&kwldap32G_ldap_parse_sort_controlW));
    e("ldap_parse_vlv_controlA", reinterpret_cast<void*>(&kwldap32G_ldap_parse_vlv_controlA));
    e("ldap_parse_vlv_controlW", reinterpret_cast<void*>(&kwldap32G_ldap_parse_vlv_controlW));
    e("ldap_perror", reinterpret_cast<void*>(&kwldap32G_ldap_perror));
    e("ldap_rename_ext", reinterpret_cast<void*>(&kwldap32G_ldap_rename_ext));
    e("ldap_rename_extA", reinterpret_cast<void*>(&kwldap32G_ldap_rename_extA));
    e("ldap_rename_extW", reinterpret_cast<void*>(&kwldap32G_ldap_rename_extW));
    e("ldap_rename_ext_s", reinterpret_cast<void*>(&kwldap32G_ldap_rename_ext_s));
    e("ldap_rename_ext_sA", reinterpret_cast<void*>(&kwldap32G_ldap_rename_ext_sA));
    e("ldap_rename_ext_sW", reinterpret_cast<void*>(&kwldap32G_ldap_rename_ext_sW));
    e("ldap_result", reinterpret_cast<void*>(&kwldap32G_ldap_result));
    e("ldap_result2error", reinterpret_cast<void*>(&kwldap32G_ldap_result2error));
    e("ldap_sasl_bindA", reinterpret_cast<void*>(&kwldap32G_ldap_sasl_bindA));
    e("ldap_sasl_bindW", reinterpret_cast<void*>(&kwldap32G_ldap_sasl_bindW));
    e("ldap_sasl_bind_sA", reinterpret_cast<void*>(&kwldap32G_ldap_sasl_bind_sA));
    e("ldap_sasl_bind_sW", reinterpret_cast<void*>(&kwldap32G_ldap_sasl_bind_sW));
    e("ldap_search", reinterpret_cast<void*>(&kwldap32G_ldap_search));
    e("ldap_searchA", reinterpret_cast<void*>(&kwldap32G_ldap_searchA));
    e("ldap_searchW", reinterpret_cast<void*>(&kwldap32G_ldap_searchW));
    e("ldap_search_abandon_page", reinterpret_cast<void*>(&kwldap32G_ldap_search_abandon_page));
    e("ldap_search_ext", reinterpret_cast<void*>(&kwldap32G_ldap_search_ext));
    e("ldap_search_extA", reinterpret_cast<void*>(&kwldap32G_ldap_search_extA));
    e("ldap_search_extW", reinterpret_cast<void*>(&kwldap32G_ldap_search_extW));
    e("ldap_search_ext_s", reinterpret_cast<void*>(&kwldap32G_ldap_search_ext_s));
    e("ldap_search_ext_sA", reinterpret_cast<void*>(&kwldap32G_ldap_search_ext_sA));
    e("ldap_search_ext_sW", reinterpret_cast<void*>(&kwldap32G_ldap_search_ext_sW));
    e("ldap_search_init_page", reinterpret_cast<void*>(&kwldap32G_ldap_search_init_page));
    e("ldap_search_init_pageA", reinterpret_cast<void*>(&kwldap32G_ldap_search_init_pageA));
    e("ldap_search_init_pageW", reinterpret_cast<void*>(&kwldap32G_ldap_search_init_pageW));
    e("ldap_search_s", reinterpret_cast<void*>(&kwldap32G_ldap_search_s));
    e("ldap_search_sA", reinterpret_cast<void*>(&kwldap32G_ldap_search_sA));
    e("ldap_search_sW", reinterpret_cast<void*>(&kwldap32G_ldap_search_sW));
    e("ldap_search_st", reinterpret_cast<void*>(&kwldap32G_ldap_search_st));
    e("ldap_search_stA", reinterpret_cast<void*>(&kwldap32G_ldap_search_stA));
    e("ldap_search_stW", reinterpret_cast<void*>(&kwldap32G_ldap_search_stW));
    e("ldap_set_dbg_flags", reinterpret_cast<void*>(&kwldap32G_ldap_set_dbg_flags));
    e("ldap_set_dbg_routine", reinterpret_cast<void*>(&kwldap32G_ldap_set_dbg_routine));
    e("ldap_set_option", reinterpret_cast<void*>(&kwldap32G_ldap_set_option));
    e("ldap_set_optionW", reinterpret_cast<void*>(&kwldap32G_ldap_set_optionW));
    e("ldap_simple_bind", reinterpret_cast<void*>(&kwldap32G_ldap_simple_bind));
    e("ldap_simple_bindA", reinterpret_cast<void*>(&kwldap32G_ldap_simple_bindA));
    e("ldap_simple_bindW", reinterpret_cast<void*>(&kwldap32G_ldap_simple_bindW));
    e("ldap_simple_bind_s", reinterpret_cast<void*>(&kwldap32G_ldap_simple_bind_s));
    e("ldap_simple_bind_sA", reinterpret_cast<void*>(&kwldap32G_ldap_simple_bind_sA));
    e("ldap_simple_bind_sW", reinterpret_cast<void*>(&kwldap32G_ldap_simple_bind_sW));
    e("ldap_sslinit", reinterpret_cast<void*>(&kwldap32G_ldap_sslinit));
    e("ldap_sslinitA", reinterpret_cast<void*>(&kwldap32G_ldap_sslinitA));
    e("ldap_sslinitW", reinterpret_cast<void*>(&kwldap32G_ldap_sslinitW));
    e("ldap_start_tls_sA", reinterpret_cast<void*>(&kwldap32G_ldap_start_tls_sA));
    e("ldap_start_tls_sW", reinterpret_cast<void*>(&kwldap32G_ldap_start_tls_sW));
    e("ldap_startup", reinterpret_cast<void*>(&kwldap32G_ldap_startup));
    e("ldap_stop_tls_s", reinterpret_cast<void*>(&kwldap32G_ldap_stop_tls_s));
    e("ldap_ufn2dn", reinterpret_cast<void*>(&kwldap32G_ldap_ufn2dn));
    e("ldap_ufn2dnA", reinterpret_cast<void*>(&kwldap32G_ldap_ufn2dnA));
    e("ldap_ufn2dnW", reinterpret_cast<void*>(&kwldap32G_ldap_ufn2dnW));
    e("ldap_unbind", reinterpret_cast<void*>(&kwldap32G_ldap_unbind));
    e("ldap_unbind_s", reinterpret_cast<void*>(&kwldap32G_ldap_unbind_s));
    e("ldap_value_free", reinterpret_cast<void*>(&kwldap32G_ldap_value_free));
    e("ldap_value_freeA", reinterpret_cast<void*>(&kwldap32G_ldap_value_freeA));
    e("ldap_value_freeW", reinterpret_cast<void*>(&kwldap32G_ldap_value_freeW));
    e("ldap_value_free_len", reinterpret_cast<void*>(&kwldap32G_ldap_value_free_len));
}
}  // namespace occ::runtime::winabi

// The advapi32 security family.
//
// These tests run against the host's own identity -- the token user is the
// effective uid's mapped SID, the user name is the passwd entry -- so the
// expected values are computed from the same sources the implementation
// reads, and each assertion pins one decision the implementation makes: the
// SID accessors return interior pointers, AdjustTokenPrivileges returns
// success while the last error says NOT_ALL_ASSIGNED, a DACL check denies
// with a successful call, and every refusal answers ERROR_CALL_NOT_IMPLEMENTED
// rather than a success no object backs.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include <pwd.h>
#include <unistd.h>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

// ---------------------------------------------------------------------------
// The entry points under test. `api.h` carries the wired domains; this one is
// wired after delivery, so the prototypes live here until then.
// ---------------------------------------------------------------------------

extern "C" {
// SIDs
__attribute__((ms_abi)) std::uint32_t as_GetSidLengthRequired(std::uint32_t) noexcept;
__attribute__((ms_abi)) std::int32_t as_AllocateAndInitializeSid(const void*, std::uint32_t,
                                         std::uint32_t, std::uint32_t,
                                         std::uint32_t, std::uint32_t,
                                         std::uint32_t, std::uint32_t,
                                         std::uint32_t, std::uint32_t,
                                         void**) noexcept;
__attribute__((ms_abi)) void* as_FreeSid(void*) noexcept;
__attribute__((ms_abi)) std::int32_t as_CopySid(std::uint32_t, void*, const void*) noexcept;
__attribute__((ms_abi)) std::int32_t as_IsValidSid(const void*) noexcept;
__attribute__((ms_abi)) std::int32_t as_EqualSid(const void*, const void*) noexcept;
__attribute__((ms_abi)) std::uint32_t as_GetLengthSid(const void*) noexcept;
__attribute__((ms_abi)) const void* as_GetSidIdentifierAuthority(const void*) noexcept;
__attribute__((ms_abi)) void* as_GetSidSubAuthority(const void*, std::uint32_t) noexcept;
__attribute__((ms_abi)) void* as_GetSidSubAuthorityCount(const void*) noexcept;

// SID <-> string
__attribute__((ms_abi)) std::int32_t as_ConvertSidToStringSidW(const void*, char16_t**) noexcept;
__attribute__((ms_abi)) std::int32_t as_ConvertSidToStringSidA(const void*, char**) noexcept;
__attribute__((ms_abi)) std::int32_t as_ConvertStringSidToSidW(const char16_t*, void**) noexcept;
__attribute__((ms_abi)) std::int32_t as_ConvertStringSidToSidA(const char*, void**) noexcept;

// Token
__attribute__((ms_abi)) std::int32_t as_OpenProcessToken(std::uint64_t, std::uint32_t,
                                 std::uint64_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_OpenThreadToken(std::uint64_t, std::uint32_t, std::int32_t,
                                std::uint64_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_GetTokenInformation(std::uint64_t, std::uint32_t, void*,
                                    std::uint32_t, std::uint32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_AdjustTokenPrivileges(std::uint64_t, std::int32_t,
                                      const void*, std::uint32_t, void*,
                                      std::uint32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_CheckTokenMembership(std::uint64_t, const void*,
                                     std::int32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_PrivilegeCheck(std::uint64_t, const void*,
                               std::int32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_AccessCheck(const void*, std::uint64_t, std::uint32_t,
                            const void*, const void*, std::uint32_t,
                            std::uint32_t*, std::int32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_SetTokenInformation(std::uint64_t, std::uint32_t, const void*,
                                    std::uint32_t) noexcept;

// User / accounts / privileges
__attribute__((ms_abi)) std::int32_t as_GetUserNameW(char16_t*, std::uint32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_GetUserNameA(char*, std::uint32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_LookupAccountSidW(const void*, const void*, char16_t*,
                                  std::uint32_t*, char16_t*, std::uint32_t*,
                                  std::uint32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_LookupAccountSidA(const void*, const void*, char*,
                                  std::uint32_t*, char*, std::uint32_t*,
                                  std::uint32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_LookupAccountSidLocalW(const void*, char16_t*, std::uint32_t*,
                                       char16_t*, std::uint32_t*,
                                       std::uint32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_LookupAccountSidLocalA(const void*, char*, std::uint32_t*,
                                       char*, std::uint32_t*,
                                       std::uint32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_LookupAccountNameW(const void*, const char16_t*, void*,
                                   std::uint32_t*, char16_t*, std::uint32_t*,
                                   std::uint32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_LookupAccountNameA(const void*, const char*, void*,
                                   std::uint32_t*, char*, std::uint32_t*,
                                   std::uint32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_LookupPrivilegeValueW(const void*, const char16_t*,
                                      void*) noexcept;
__attribute__((ms_abi)) std::int32_t as_LookupPrivilegeValueA(const void*, const char*, void*) noexcept;
__attribute__((ms_abi)) std::int32_t as_LookupPrivilegeNameW(const void*, std::uint32_t, std::uint32_t,
                                     char16_t*, std::uint32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_LookupPrivilegeNameA(const void*, std::uint32_t, std::uint32_t,
                                     char*, std::uint32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_LookupPrivilegeDisplayNameW(const void*, const char16_t*,
                                            char16_t*, std::uint32_t*,
                                            std::uint32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_LookupPrivilegeDisplayNameA(const void*, const char*, char*,
                                            std::uint32_t*,
                                            std::uint32_t*) noexcept;

// Security descriptors and ACLs
__attribute__((ms_abi)) std::int32_t as_InitializeSecurityDescriptor(void*, std::uint32_t) noexcept;
__attribute__((ms_abi)) std::int32_t as_SetSecurityDescriptorOwner(void*, const void*,
                                           std::int32_t) noexcept;
__attribute__((ms_abi)) std::int32_t as_GetSecurityDescriptorOwner(const void*, const void**,
                                           std::int32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_SetSecurityDescriptorGroup(void*, const void*,
                                           std::int32_t) noexcept;
__attribute__((ms_abi)) std::int32_t as_GetSecurityDescriptorGroup(const void*, const void**,
                                           std::int32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_SetSecurityDescriptorDacl(void*, std::int32_t, const void*,
                                          std::int32_t) noexcept;
__attribute__((ms_abi)) std::int32_t as_GetSecurityDescriptorDacl(const void*, std::int32_t*,
                                          const void**, std::int32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_SetSecurityDescriptorSacl(void*, std::int32_t, const void*,
                                          std::int32_t) noexcept;
__attribute__((ms_abi)) std::int32_t as_GetSecurityDescriptorSacl(const void*, std::int32_t*,
                                          const void**, std::int32_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_SetSecurityDescriptorControl(void*, std::uint16_t,
                                             std::uint16_t) noexcept;
__attribute__((ms_abi)) std::int32_t as_GetSecurityDescriptorControl(const void*, std::uint16_t*,
                                             std::uint32_t*) noexcept;
__attribute__((ms_abi)) std::uint32_t as_GetSecurityDescriptorLength(const void*) noexcept;
__attribute__((ms_abi)) std::int32_t as_InitializeAcl(void*, std::uint32_t, std::uint32_t) noexcept;
__attribute__((ms_abi)) std::int32_t as_AddAccessAllowedAce(void*, std::uint32_t, std::uint32_t,
                                    const void*) noexcept;
__attribute__((ms_abi)) std::int32_t as_AddAccessAllowedAceEx(void*, std::uint32_t, std::uint32_t,
                                      std::uint32_t, const void*) noexcept;
__attribute__((ms_abi)) std::int32_t as_GetAce(const void*, std::uint32_t, void**) noexcept;
__attribute__((ms_abi)) std::int32_t as_FindFirstFreeAce(const void*, void**) noexcept;
__attribute__((ms_abi)) std::int32_t as_GetAclInformation(const void*, void*, std::uint32_t,
                                  std::uint32_t) noexcept;
__attribute__((ms_abi)) std::int32_t as_AreAllAccessesGranted(std::uint32_t, std::uint32_t) noexcept;
__attribute__((ms_abi)) void as_MapGenericMask(std::uint32_t*, const void*) noexcept;
__attribute__((ms_abi)) std::uint32_t as_GetEffectiveRightsFromAclW(const void*, const void*,
                                            std::uint32_t*) noexcept;
__attribute__((ms_abi)) std::uint32_t as_GetEffectiveRightsFromAclA(const void*, const void*,
                                            std::uint32_t*) noexcept;

// Refusals
__attribute__((ms_abi)) std::uint64_t as_OpenSCManagerW(const void*, const void*, std::uint32_t) noexcept;
__attribute__((ms_abi)) std::int32_t as_CloseServiceHandle(std::uint64_t) noexcept;
__attribute__((ms_abi)) std::int32_t as_LogonUserW(const void*, const void*, const void*, std::uint32_t,
                           std::uint32_t, std::uint64_t*) noexcept;
__attribute__((ms_abi)) std::int32_t as_RevertToSelf() noexcept;
__attribute__((ms_abi)) std::int32_t as_ImpersonateSelf(std::uint32_t) noexcept;
__attribute__((ms_abi)) std::uint32_t as_SetEntriesInAclW(std::uint32_t, const void*, const void*,
                                  void**) noexcept;
__attribute__((ms_abi)) std::int32_t as_ConvertStringSecurityDescriptorToSecurityDescriptorW(
    const void*, std::uint32_t, void**, std::uint32_t*) noexcept;
__attribute__((ms_abi)) std::uint32_t as_GetSecurityInfo(std::uint64_t, std::uint32_t, std::uint32_t,
                                 const void**, const void**, const void**,
                                 const void**, const void**) noexcept;
}

// ---------------------------------------------------------------------------

namespace {

int failures = 0;
int checks = 0;

__attribute__((ms_abi)) void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

// Error codes this family answers with, named for the assertions.
constexpr std::uint32_t kErrInvalidParameter = 87;
constexpr std::uint32_t kErrInsufficientBuffer = 122;
constexpr std::uint32_t kErrInvalidHandle = 6;
constexpr std::uint32_t kErrCallNotImplemented = 120;
constexpr std::uint32_t kErrNotAllAssigned = 1300;
constexpr std::uint32_t kErrUnknownRevision = 1305;
constexpr std::uint32_t kErrPrivilegeNotHeld = 1314;
constexpr std::uint32_t kErrNoSuchPrivilege = 1313;
constexpr std::uint32_t kErrNoneMapped = 1332;
constexpr std::uint32_t kErrInvalidSid = 1337;

constexpr std::uint64_t kCurrentProcess = 0xFFFFFFFFFFFFFFFFULL;
constexpr std::uint64_t kCurrentThread = 0xFFFFFFFFFFFFFFFEULL;
constexpr std::uint32_t kGenericRead = 0x80000000u;
constexpr std::uint32_t kMaximumAllowed = 0x02000000u;

// The generic mapping a test uses: READ maps to bit 0, WRITE to bit 1,
// EXECUTE to bit 2, ALL to bits 0..2. The specific bits are the test's own,
// so a wrong mapping shows up as a wrong mask.
constexpr std::uint32_t kMapping[4] = {0x00000001u, 0x00000002u, 0x00000004u,
                                       0x00000007u};

std::string host_name() noexcept {
    const ::passwd* pw = ::getpwuid(::geteuid());
    return pw != nullptr ? std::string(pw->pw_name) : std::string("user");
}

std::string host_domain() noexcept {
    char name[256] = {};
    if (::gethostname(name, sizeof(name) - 1) != 0) {
        return {};
    }
    return std::string(name);
}

// The token handle, opened once.
__attribute__((ms_abi)) std::uint64_t open_token() noexcept {
    std::uint64_t token = 0;
    if (as_OpenProcessToken(kCurrentProcess, 0, &token) == 0) {
        return 0;
    }
    return token;
}

// A SID built through the API: authority 5, `count` subauthorities taken
// from `subs`.
__attribute__((ms_abi)) void* make_sid(const std::uint8_t authority[6], std::uint32_t count,
               const std::uint32_t* subs) noexcept {
    void* sid = nullptr;
    const auto ok = as_AllocateAndInitializeSid(
        authority, count, subs[0], subs[1], subs[2], subs[3], subs[4], subs[5],
        subs[6], subs[7], &sid);
    return ok != 0 ? sid : nullptr;
}

// The wide text a conversion answered, read back into a std::u16string.
std::u16string wide_at(const char16_t* text) noexcept {
    if (text == nullptr) {
        return {};
    }
    std::size_t n = 0;
    while (text[n] != u'\0') {
        ++n;
    }
    return std::u16string(text, n);
}

std::string narrow_at(const char* text) noexcept {
    return text != nullptr ? std::string(text) : std::string();
}

// The Everyone SID, S-1-1-0, built by hand.
__attribute__((ms_abi)) void* make_everyone_sid() noexcept {
    const std::uint8_t authority[6] = {0, 0, 0, 0, 0, 1};
    const std::uint32_t subs[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    return make_sid(authority, 1, subs);
}

// A corrupt SID: the revision byte is right, the count is past the maximum.
bool write_corrupt_sid(std::uint8_t* buffer) noexcept {
    std::memset(buffer, 0, 72);
    buffer[0] = 1;
    buffer[1] = 16;
    return true;
}

// TOKEN_PRIVILEGES with one entry, for AdjustTokenPrivileges.
__attribute__((ms_abi)) void make_privilege_request(std::uint8_t* buffer, std::uint32_t luid,
                            std::uint32_t attributes) noexcept {
    std::memset(buffer, 0, 16);
    write_u32(buffer, 0, 1);
    write_u32(buffer, 4, luid);
    write_u32(buffer, 8, 0);
    write_u32(buffer, 12, attributes);
}

}  // namespace

// ---------------------------------------------------------------------------

int main() {
    // ===================================================================
    // SID arithmetic and structure
    // ===================================================================
    check(as_GetSidLengthRequired(0) == 8, "sid: zero subauthorities is 8 bytes");
    check(as_GetSidLengthRequired(15) == 68, "sid: maximum is 68 bytes");

    const std::uint8_t authority_nt[6] = {0, 0, 0, 0, 0, 5};
    const std::uint32_t subs_admin[8] = {32, 544, 0, 0, 0, 0, 0, 0};
    void* sid = make_sid(authority_nt, 2, subs_admin);
    check(sid != nullptr, "sid: AllocateAndInitializeSid allocates");
    check(as_IsValidSid(sid) == 1, "sid: allocated SID is valid");
    check(as_GetLengthSid(sid) == 16, "sid: length follows the count");
    check(as_GetSidSubAuthorityCount(sid) != nullptr &&
              *static_cast<std::uint8_t*>(as_GetSidSubAuthorityCount(sid)) == 2,
          "sid: count accessor points inside the SID");
    check(as_GetSidSubAuthority(sid, 0) != nullptr &&
              *static_cast<std::uint32_t*>(as_GetSidSubAuthority(sid, 0)) == 32,
          "sid: subauthority accessor returns an interior pointer");
    *static_cast<std::uint32_t*>(as_GetSidSubAuthority(sid, 0)) = 545;
    check(as_GetSidSubAuthority(sid, 0) != nullptr &&
              *static_cast<std::uint32_t*>(as_GetSidSubAuthority(sid, 0)) == 545,
          "sid: the interior pointer writes through to the SID");
    *static_cast<std::uint32_t*>(as_GetSidSubAuthority(sid, 0)) = 32;
    check(as_GetSidIdentifierAuthority(sid) != nullptr &&
              static_cast<const std::uint8_t*>(
                  as_GetSidIdentifierAuthority(sid))[5] == 5,
          "sid: authority accessor reads the big-endian bytes");
    check(as_GetSidSubAuthority(sid, 2) == nullptr &&
              k32_GetLastError() == kErrInvalidParameter,
          "sid: out-of-range subauthority index is refused");
    check(as_GetSidSubAuthority(nullptr, 0) == nullptr,
          "sid: null SID is refused by the accessor");

    std::uint8_t corrupt[72];
    (void)write_corrupt_sid(corrupt);
    check(as_IsValidSid(corrupt) == 0, "sid: count past 15 is not a SID");
    check(as_IsValidSid(nullptr) == 0, "sid: null is not a SID");
    check(as_GetLengthSid(nullptr) == 0, "sid: null length is zero");

    std::uint8_t copy[16];
    check(as_CopySid(sizeof(copy), copy, sid) == 1 &&
              as_EqualSid(copy, sid) == 1,
          "sid: CopySid copies and EqualSid agrees");
    check(as_CopySid(12, copy, sid) == 0 &&
              k32_GetLastError() == kErrInsufficientBuffer,
          "sid: CopySid refuses a short destination");
    check(as_EqualSid(copy, nullptr) == 0, "sid: EqualSid against null is false");

    const std::uint32_t subs_other[8] = {32, 0, 0, 0, 0, 0, 0, 0};
    void* other = make_sid(authority_nt, 1, subs_other);
    check(other != nullptr && as_EqualSid(sid, other) == 0,
          "sid: distinct SIDs are not equal");
    as_FreeSid(other);
    check(as_FreeSid(nullptr) == nullptr, "sid: FreeSid answers null");
    check(as_AllocateAndInitializeSid(authority_nt, 9, 0, 0, 0, 0, 0, 0, 0, 0,
                                      &sid) == 0 &&
              k32_GetLastError() == kErrInvalidParameter,
          "sid: nine subauthorities exceed the entry point's arity");

    // ===================================================================
    // SID <-> string
    // ===================================================================
    char16_t* wide_text = nullptr;
    check(as_ConvertSidToStringSidW(sid, &wide_text) == 1 &&
              wide_text != nullptr,
          "sidstr: W conversion succeeds");
    const std::u16string expect = u"S-1-5-32-544";
    check(wide_text == nullptr || wide_at(wide_text) == expect,
          "sidstr: the W form is the S-1-5-32-544 spelling");
    char* narrow_text = nullptr;
    check(as_ConvertSidToStringSidA(sid, &narrow_text) == 1 &&
              narrow_text != nullptr && narrow_at(narrow_text) == "S-1-5-32-544",
          "sidstr: the A form agrees with the W form");

    void* parsed = nullptr;
    check(as_ConvertStringSidToSidW(u"S-1-5-32-544", &parsed) == 1 &&
              parsed != nullptr && as_EqualSid(parsed, sid) == 1,
          "sidstr: W parse round-trips to the same SID");
    as_FreeSid(parsed);
    parsed = nullptr;
    check(as_ConvertStringSidToSidA("S-1-5-32-544", &parsed) == 1 &&
              as_EqualSid(parsed, sid) == 1,
          "sidstr: A parse agrees with the W parse");
    as_FreeSid(parsed);
    std::free(wide_text);
    std::free(narrow_text);

    set_last_error(0);
    check(as_ConvertStringSidToSidW(nullptr, &parsed) == 0 &&
              k32_GetLastError() == kErrInvalidSid,
          "sidstr: null text is an invalid SID");
    check(as_ConvertStringSidToSidW(u"S-1-5-32-544X", &parsed) == 0 &&
              k32_GetLastError() == kErrInvalidSid,
          "sidstr: trailing junk is refused");
    check(as_ConvertStringSidToSidW(u"X-1-5", &parsed) == 0,
          "sidstr: a foreign prefix is refused");
    check(as_ConvertStringSidToSidW(u"S-2-5", &parsed) == 0,
          "sidstr: the revision literal is 1");
    check(as_ConvertStringSidToSidW(u"S-1-99999999999999999999", &parsed) == 0,
          "sidstr: authority overflow is refused");
    check(as_ConvertStringSidToSidW(u"S-1-4294967296", &parsed) == 0,
          "sidstr: a subauthority past 32 bits is refused");
    check(as_ConvertStringSidToSidW(u"S-1-5-", &parsed) == 0,
          "sidstr: a trailing dash is refused");
    check(as_ConvertStringSidToSidW(u"S-1-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0",
                                    &parsed) == 0,
          "sidstr: sixteen subauthorities are refused");
    check(as_ConvertStringSidToSidW(u"S-1-0", &parsed) == 0,
          "sidstr: at least one subauthority is required");
    check(as_ConvertStringSidToSidW(u"S-1-0-0", &parsed) == 1,
          "sidstr: the null SID parses");
    as_FreeSid(parsed);
    parsed = nullptr;
    std::uint8_t corrupt2[72];
    (void)write_corrupt_sid(corrupt2);
    // A descriptor-shaped buffer with a revision that was never defined,
    // for the paths that read a SECURITY_DESCRIPTOR's head.
    std::uint8_t bad_sd[40];
    std::memset(bad_sd, 0, sizeof(bad_sd));
    bad_sd[0] = 9;
    set_last_error(0);
    char16_t* refused = nullptr;
    check(as_ConvertSidToStringSidW(corrupt2, &refused) == 0 &&
              k32_GetLastError() == kErrInvalidSid,
          "sidstr: a corrupt SID is refused, not spelled");

    // ===================================================================
    // Token handles
    // ===================================================================
    const std::uint64_t token = open_token();
    check(token != 0, "token: OpenProcessToken answers a handle");
    std::uint64_t token2 = 0;
    check(as_OpenThreadToken(kCurrentThread, 0, 0, &token2) == 1 &&
              token2 == token,
          "token: the thread token is the process token");
    check(as_OpenProcessToken(1234, 0, &token2) == 0 &&
              k32_GetLastError() == kErrInvalidHandle,
          "token: a foreign process handle is refused");
    check(as_OpenThreadToken(0, 0, 0, &token2) == 0 &&
              k32_GetLastError() == kErrInvalidHandle,
          "token: a foreign thread handle is refused");
    check(as_OpenProcessToken(kCurrentProcess, 0, nullptr) == 0 &&
              k32_GetLastError() == kErrInvalidParameter,
          "token: a null out-pointer is refused");

    // ===================================================================
    // Token information
    // ===================================================================
    std::uint32_t needed = 0;
    std::uint8_t info[128];
    std::memset(info, 0, sizeof(info));
    check(as_GetTokenInformation(token, 1, info, 16, &needed) == 0 &&
              k32_GetLastError() == kErrInsufficientBuffer &&
              needed == 32,
          "token: TokenUser reports 16-byte header plus SID first");
    check(as_GetTokenInformation(token, 1, info, sizeof(info), &needed) == 1 &&
              needed == 32,
          "token: TokenUser fits and reports its true size");
    check(read_ptr(info, 0) == reinterpret_cast<std::uint64_t>(info) + 16,
          "token: TokenUser's SID pointer aims at the inline SID");
    check(read_u32(info, 8) == 0, "token: TokenUser attributes are zero");

    // The user the SID names: LookupAccountName gives the same SID back.
    const std::string user = host_name();
    std::u16string user_wide;
    (void)utf8_to_utf16(user, user_wide);
    std::uint8_t looked_up[16];
    std::uint32_t sid_size = sizeof(looked_up);
    char16_t domain_buf[64];
    std::uint32_t domain_chars = 64;
    std::uint32_t use = 0;
    check(as_LookupAccountNameW(nullptr, user_wide.c_str(), looked_up,
                                &sid_size, domain_buf, &domain_chars,
                                &use) == 1 &&
              sid_size == 16 && use == 1,
          "token: the user name maps to a 16-byte user SID");
    check(std::memcmp(info + 16, looked_up, 16) == 0,
          "token: TokenUser's SID is the mapped user SID");

    needed = 0;
    check(as_GetTokenInformation(token, 2, info, 2, &needed) == 0 &&
              k32_GetLastError() == kErrInsufficientBuffer && needed == 4,
          "token: TokenGroups reports 4 bytes when short");
    check(as_GetTokenInformation(token, 2, info, sizeof(info), &needed) == 1 &&
              needed == 4 && read_u32(info, 0) == 0,
          "token: TokenGroups is the empty group list");
    check(as_GetTokenInformation(token, 3, info, sizeof(info), &needed) == 1 &&
              needed == 4 && read_u32(info, 0) == 0,
          "token: TokenPrivileges is the empty privilege list");
    check(as_GetTokenInformation(token, 4, info, sizeof(info), &needed) == 1 &&
              needed == 24,
          "token: TokenOwner is the user SID behind an 8-byte header");
    check(as_GetTokenInformation(token, 5, info, sizeof(info), &needed) == 1 &&
              needed == 24,
          "token: TokenPrimaryGroup is the group SID");
    check(as_GetTokenInformation(token, 7, info, sizeof(info), &needed) == 1 &&
              needed == 16 && std::memcmp(info, "OCC-RUN\0", 8) == 0,
          "token: TokenSource names this runtime");
    check(as_GetTokenInformation(token, 10, info, sizeof(info), &needed) == 1 &&
              needed == 56 && read_u32(info, 24) == 1,
          "token: TokenStatistics is a 56-byte primary token");
    set_last_error(0);
    check(as_GetTokenInformation(token, 99, info, sizeof(info), &needed) == 0 &&
              k32_GetLastError() == kErrInvalidParameter,
          "token: an unknown information class is a wrong question");
    check(as_GetTokenInformation(0x1234, 2, info, sizeof(info), &needed) == 0 &&
              k32_GetLastError() == kErrInvalidHandle,
          "token: an unknown token is refused");

    // ===================================================================
    // AdjustTokenPrivileges: two answers on one call
    // ===================================================================
    std::uint8_t request[16];
    std::uint8_t previous[32];
    std::uint32_t prev_needed = 0;
    make_privilege_request(request, 20, 2);  // enable SeDebugPrivilege
    set_last_error(0);
    check(as_AdjustTokenPrivileges(token, 0, request, 0, nullptr, nullptr) == 1 &&
              k32_GetLastError() == kErrNotAllAssigned,
          "priv: an unheld enable returns TRUE with NOT_ALL_ASSIGNED");
    set_last_error(0);
    check(as_AdjustTokenPrivileges(token, 0, request, sizeof(previous),
                                   previous, &prev_needed) == 1 &&
              k32_GetLastError() == kErrNotAllAssigned && prev_needed == 16,
          "priv: previous state is written and the shortfall still reported");
    check(read_u32(previous, 0) == 1 && read_u32(previous, 12) == 0,
          "priv: the previous attributes of an unheld privilege are zero");
    check(as_AdjustTokenPrivileges(token, 0, request, 4, previous,
                                   &prev_needed) == 0 &&
              k32_GetLastError() == kErrInsufficientBuffer && prev_needed == 16,
          "priv: a short previous-state buffer reports what it needs");
    make_privilege_request(request, 20, 4);  // remove an unheld privilege
    check(as_AdjustTokenPrivileges(token, 0, request, 0, nullptr, nullptr) == 0 &&
              k32_GetLastError() == kErrPrivilegeNotHeld,
          "priv: removing an unheld privilege fails outright");
    std::memset(request, 0, sizeof(request));  // count 0
    set_last_error(0);
    check(as_AdjustTokenPrivileges(token, 0, request, 0, nullptr, nullptr) == 1 &&
              k32_GetLastError() == kErrorSuccess,
          "priv: an empty request succeeds with no shortfall");
    set_last_error(0);
    check(as_AdjustTokenPrivileges(token, 1, nullptr, 0, nullptr, nullptr) == 1 &&
              k32_GetLastError() == kErrorSuccess,
          "priv: disable-all touches nothing that exists and succeeds");
    check(as_AdjustTokenPrivileges(token, 0, nullptr, 0, nullptr, nullptr) == 0 &&
              k32_GetLastError() == kErrInvalidParameter,
          "priv: a null new state is refused");
    check(as_AdjustTokenPrivileges(0x99, 1, nullptr, 0, nullptr, nullptr) == 0 &&
              k32_GetLastError() == kErrInvalidHandle,
          "priv: an unknown token is refused");

    // ===================================================================
    // PrivilegeCheck / CheckTokenMembership
    // ===================================================================
    std::uint8_t privilege_set[16];
    std::memset(privilege_set, 0, sizeof(privilege_set));
    write_u32(privilege_set, 0, 1);   // one privilege
    write_u32(privilege_set, 8, 20);  // SeDebugPrivilege LUID
    std::int32_t has = 1;
    check(as_PrivilegeCheck(token, privilege_set, &has) == 1 && has == 0,
          "priv: PrivilegeCheck answers no with a successful call");
    check(as_PrivilegeCheck(token, nullptr, &has) == 0 &&
              k32_GetLastError() == kErrInvalidParameter,
          "priv: a null privilege set is refused");

    void* everyone = make_everyone_sid();
    std::int32_t member = 0;
    check(as_CheckTokenMembership(0, looked_up, &member) == 1 && member == 1,
          "group: the user SID is a member");
    check(as_CheckTokenMembership(0, everyone, &member) == 1 && member == 1,
          "group: Everyone is implicit membership");
    check(as_CheckTokenMembership(0, sid, &member) == 1 && member == 0,
          "group: an unrelated SID is not a member");
    check(as_CheckTokenMembership(0, nullptr, &member) == 0 &&
              k32_GetLastError() == kErrInvalidParameter,
          "group: a null SID is refused");

    // ===================================================================
    // User name
    // ===================================================================
    std::uint32_t chars = 1;
    char16_t name_buf[64];
    check(as_GetUserNameW(name_buf, &chars) == 0 &&
              k32_GetLastError() == kErrInsufficientBuffer && chars > 1,
          "user: W answers the required size when short");
    const std::uint32_t need = chars;
    chars = sizeof(name_buf) / sizeof(char16_t);
    check(as_GetUserNameW(name_buf, &chars) == 1 && chars == need,
          "user: W succeeds and reports the count with the terminator");
    check(wide_at(name_buf) == user_wide,
          "user: W answers the passwd entry's name");
    char narrow_buf[64];
    chars = 1;
    check(as_GetUserNameA(narrow_buf, &chars) == 0 && chars == need,
          "user: A answers the same required size in narrow chars");
    chars = sizeof(narrow_buf);
    check(as_GetUserNameA(narrow_buf, &chars) == 1 &&
              narrow_at(narrow_buf) == user,
          "user: A answers the same name as W");
    chars = 4;
    check(as_GetUserNameW(nullptr, &chars) == 0 &&
              k32_GetLastError() == kErrInsufficientBuffer,
          "user: a null buffer is a too-small answer, not a crash");
    check(as_GetUserNameW(name_buf, nullptr) == 0 &&
              k32_GetLastError() == kErrInvalidParameter,
          "user: a null size is refused");

    // ===================================================================
    // Account lookup by SID and by name
    // ===================================================================
    chars = 1;
    std::uint32_t domain_need = 1;
    char16_t domain2[64];
    set_last_error(0);
    check(as_LookupAccountSidW(nullptr, looked_up, name_buf, &chars, domain2,
                               &domain_need, &use) == 0 &&
              k32_GetLastError() == kErrInsufficientBuffer && chars == need &&
              domain_need > 0,
          "account: both sizes are reported when either buffer is short");
    chars = 64;
    domain_need = 64;
    check(as_LookupAccountSidW(nullptr, looked_up, name_buf, &chars, domain2,
                               &domain_need, &use) == 1 &&
              use == 1,
          "account: the user SID resolves");
    check(wide_at(name_buf) == user_wide, "account: the name is the passwd name");
    std::u16string domain_wide;
    (void)utf8_to_utf16(host_domain(), domain_wide);
    check(wide_at(domain2) == domain_wide,
          "account: the domain is the host's own name");
    chars = 64;
    domain_need = 64;
    check(as_LookupAccountSidLocalW(looked_up, name_buf, &chars, domain2,
                                    &domain_need, &use) == 1 &&
              use == 1,
          "account: the Local form answers what the W form answers");
    chars = 64;
    domain_need = 64;
    check(as_LookupAccountSidW(nullptr, everyone, name_buf, &chars, domain2,
                               &domain_need, &use) == 1 &&
              use == 5 && wide_at(name_buf) == u"Everyone",
          "account: Everyone resolves as a well-known group");
    set_last_error(0);
    check(as_LookupAccountSidW(nullptr, corrupt2, name_buf, &chars, domain2,
                               &domain_need, &use) == 0 &&
              k32_GetLastError() == kErrInvalidSid,
          "account: a corrupt SID is INVALID_SID, not NONE_MAPPED");
    check(as_LookupAccountSidW(nullptr, nullptr, name_buf, &chars, domain2,
                               &domain_need, &use) == 0 &&
              k32_GetLastError() == kErrInvalidParameter,
          "account: a null SID is a parameter error");
    char narrow_name[64];
    char narrow_domain[64];
    chars = 64;
    domain_need = 64;
    check(as_LookupAccountSidA(nullptr, looked_up, narrow_name, &chars,
                               narrow_domain, &domain_need, &use) == 1 &&
              narrow_at(narrow_name) == user && use == 1,
          "account: the A form answers the narrow spelling of the W answer");

    std::uint8_t sid_out[16];
    sid_size = sizeof(sid_out);
    domain_need = 64;
    check(as_LookupAccountNameW(nullptr, user_wide.c_str(), sid_out, &sid_size,
                                domain2, &domain_need, &use) == 1 &&
              sid_size == 16 && use == 1 &&
              std::memcmp(sid_out, looked_up, 16) == 0,
          "account: the user name maps back to the same SID");
    sid_size = 4;
    check(as_LookupAccountNameW(nullptr, user_wide.c_str(), sid_out, &sid_size,
                                domain2, &domain_need, &use) == 0 &&
              k32_GetLastError() == kErrInsufficientBuffer && sid_size == 16,
          "account: a short SID buffer reports the SID's size");
    sid_size = sizeof(sid_out);
    domain_need = 64;
    check(as_LookupAccountNameW(nullptr, u"Everyone", sid_out, &sid_size,
                                domain2, &domain_need, &use) == 1 &&
              use == 5 && std::memcmp(sid_out, everyone, 12) == 0,
          "account: Everyone maps to S-1-1-0");
    set_last_error(0);
    check(as_LookupAccountNameW(nullptr, u"No Such Name At All", sid_out,
                                &sid_size, domain2, &domain_need, &use) == 0 &&
              k32_GetLastError() == kErrNoneMapped,
          "account: a foreign name is NONE_MAPPED");
    char narrow_name2[64];
    narrow_name2[0] = '\0';
    std::snprintf(narrow_name2, sizeof(narrow_name2), "%s", user.c_str());
    sid_size = sizeof(sid_out);
    domain_need = 64;
    check(as_LookupAccountNameA(nullptr, narrow_name2, sid_out, &sid_size,
                                narrow_domain, &domain_need, &use) == 1 &&
              std::memcmp(sid_out, looked_up, 16) == 0,
          "account: the A form maps the same name");
    check(as_LookupAccountNameW(nullptr, nullptr, sid_out, &sid_size, domain2,
                                &domain_need, &use) == 0 &&
              k32_GetLastError() == kErrInvalidParameter,
          "account: a null name is refused");

    // ===================================================================
    // Privilege name / LUID lookups
    // ===================================================================
    std::uint8_t luid[8];
    check(as_LookupPrivilegeValueW(nullptr, u"SeDebugPrivilege", luid) == 1 &&
              read_u32(luid, 0) == 20 && read_u32(luid, 4) == 0,
          "privname: SeDebugPrivilege is LUID 20");
    check(as_LookupPrivilegeValueW(nullptr, u"sedebugprivilege", luid) == 1,
          "privname: the lookup is case-insensitive");
    set_last_error(0);
    check(as_LookupPrivilegeValueW(nullptr, u"SeNopePrivilege", luid) == 0 &&
              k32_GetLastError() == kErrNoSuchPrivilege,
          "privname: an unknown name is NO_SUCH_PRIVILEGE");
    check(as_LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", luid) == 1,
          "privname: the A form agrees with the W form");
    check(as_LookupPrivilegeValueW(nullptr, nullptr, luid) == 0,
          "privname: a null name is refused");

    chars = 4;
    check(as_LookupPrivilegeNameW(nullptr, 20, 0, name_buf, &chars) == 0 &&
              k32_GetLastError() == kErrInsufficientBuffer && chars == 17,
          "privname: the name needs 17 chars with the terminator");
    chars = 64;
    check(as_LookupPrivilegeNameW(nullptr, 20, 0, name_buf, &chars) == 1 &&
              chars == 16 && wide_at(name_buf) == u"SeDebugPrivilege",
          "privname: LUID 20 is SeDebugPrivilege");
    set_last_error(0);
    check(as_LookupPrivilegeNameW(nullptr, 999, 0, name_buf, &chars) == 0 &&
              k32_GetLastError() == kErrNoSuchPrivilege,
          "privname: an unknown LUID is refused");
    check(as_LookupPrivilegeNameW(nullptr, 20, 1, name_buf, &chars) == 0,
          "privname: a nonzero LUID high part is refused");
    chars = 64;
    check(as_LookupPrivilegeNameA(nullptr, 20, 0, narrow_name, &chars) == 1 &&
              narrow_at(narrow_name) == "SeDebugPrivilege",
          "privname: the A form answers the narrow name");

    chars = 4;
    check(as_LookupPrivilegeDisplayNameW(nullptr, u"SeDebugPrivilege",
                                         name_buf, &chars, &use) == 0 &&
              k32_GetLastError() == kErrInsufficientBuffer && chars == 15,
          "privname: the display name needs 15 chars with the terminator");
    chars = 64;
    check(as_LookupPrivilegeDisplayNameW(nullptr, u"SeDebugPrivilege",
                                         name_buf, &chars, &use) == 1 &&
              chars == 14 && wide_at(name_buf) == u"Debug programs" &&
              use == 0x0409,
          "privname: the display name and the US language id are answered");
    set_last_error(0);
    check(as_LookupPrivilegeDisplayNameW(nullptr, u"SeNope", name_buf, &chars,
                                         &use) == 0 &&
              k32_GetLastError() == kErrNoSuchPrivilege,
          "privname: an unknown display name is refused");
    chars = 64;
    check(as_LookupPrivilegeDisplayNameA(nullptr, "SeDebugPrivilege",
                                         narrow_name, &chars, &use) == 1 &&
              narrow_at(narrow_name) == "Debug programs",
          "privname: the A display name agrees");

    // ===================================================================
    // Security descriptors
    // ===================================================================
    std::uint8_t sd[40];
    check(as_InitializeSecurityDescriptor(sd, 1) == 1,
          "sd: revision 1 initialises");
    check(as_InitializeSecurityDescriptor(sd, 2) == 0 &&
              k32_GetLastError() == kErrUnknownRevision,
          "sd: revision 2 is a format that does not exist");
    check(as_InitializeSecurityDescriptor(nullptr, 1) == 0 &&
              k32_GetLastError() == kErrInvalidParameter,
          "sd: a null descriptor is refused");
    std::uint16_t control = 0xFFFF;
    std::uint32_t revision = 0;
    check(as_GetSecurityDescriptorControl(sd, &control, &revision) == 1 &&
              control == 0 && revision == 1,
          "sd: a fresh descriptor has no control bits and revision 1");
    check(as_GetSecurityDescriptorLength(sd) == 40,
          "sd: the non-relative form is 40 bytes");
    check(as_GetSecurityDescriptorLength(nullptr) == 0,
          "sd: an uninitialised descriptor has no length to stand behind");

    check(as_SetSecurityDescriptorOwner(sd, looked_up, 1) == 1,
          "sd: the owner is set");
    const void* owner = nullptr;
    std::int32_t defaulted = 0;
    check(as_GetSecurityDescriptorOwner(sd, &owner, &defaulted) == 1 &&
          owner == reinterpret_cast<const void*>(looked_up) && defaulted == 1,
          "sd: the owner reads back with its defaulted bit");
    check(as_SetSecurityDescriptorOwner(sd, looked_up, 0) == 1 &&
              as_GetSecurityDescriptorOwner(sd, &owner, &defaulted) == 1 &&
              defaulted == 0,
          "sd: clearing the defaulted bit is visible in the getter");
    check(as_SetSecurityDescriptorGroup(sd, looked_up, 0) == 1,
          "sd: the group is set");
    const void* group = nullptr;
    check(as_GetSecurityDescriptorGroup(sd, &group, &defaulted) == 1 &&
              group == reinterpret_cast<const void*>(looked_up),
          "sd: the group reads back");

    // The ACL the descriptor points at, built in its own buffer.
    std::uint8_t acl[64];
    check(as_InitializeAcl(acl, sizeof(acl), 2) == 1, "acl: revision 2 inits");
    check(as_InitializeAcl(acl, 4, 2) == 0 &&
              k32_GetLastError() == kErrInsufficientBuffer,
          "acl: a header-short buffer is refused");
    check(as_InitializeAcl(acl, sizeof(acl), 3) == 0 &&
              k32_GetLastError() == kErrInvalidParameter,
          "acl: revision 3 is not an ACL format");
    check(as_InitializeAcl(nullptr, 64, 2) == 0,
          "acl: a null ACL is refused");

    check(as_AddAccessAllowedAce(acl, 2, 0x00000001, looked_up) == 1,
          "acl: an allowed ACE is added");
    check(as_AddAccessAllowedAceEx(acl, 2, 0x03, 0x00000002, everyone) == 1,
          "acl: an ACE with flags is added through the Ex form");
    void* ace = nullptr;
    check(as_GetAce(acl, 0, &ace) == 1 && ace != nullptr &&
              static_cast<std::uint8_t*>(ace)[0] == 0 &&
              read_u32(ace, 4) == 0x00000001,
          "acl: GetAce returns the ACE interior and its mask");
    check(ace != nullptr &&
              std::memcmp(static_cast<std::uint8_t*>(ace) + 8, looked_up, 16) == 0,
          "acl: the ACE's SID rides inline after the header");
    check(as_GetAce(acl, 1, &ace) == 1 &&
              static_cast<std::uint8_t*>(ace)[1] == 0x03 &&
              read_u32(ace, 4) == 0x00000002,
          "acl: the second ACE keeps its flags and mask");
    check(as_GetAce(acl, 5, &ace) == 0 &&
              k32_GetLastError() == kErrInvalidParameter,
          "acl: an index past the count is refused");
    check(as_FindFirstFreeAce(acl, &ace) == 1 && ace != nullptr &&
              read_u16(acl, 2) >= static_cast<std::size_t>(
                                      static_cast<std::uint8_t*>(ace) - acl),
          "acl: FindFirstFreeAce points inside the buffer");
    std::uint8_t info_buf[8];
    check(as_GetAclInformation(acl, info_buf, 8, 2) == 1 &&
              read_u32(info_buf, 0) == 64 && read_u32(info_buf, 4) == 2,
          "acl: size information reports the buffer and the count");
    check(as_GetAclInformation(acl, info_buf, 4, 1) == 1 &&
              read_u32(info_buf, 0) == 2,
          "acl: revision information reports revision 2");
    check(as_GetAclInformation(acl, info_buf, 2, 2) == 0 &&
              k32_GetLastError() == kErrInsufficientBuffer,
          "acl: a short information buffer is refused");
    check(as_GetAclInformation(acl, info_buf, 8, 9) == 0 &&
              k32_GetLastError() == kErrInvalidParameter,
          "acl: an unknown information class is refused");
    check(as_AddAccessAllowedAce(acl, 4, 1, looked_up) == 0 &&
              k32_GetLastError() == kErrInvalidParameter,
          "acl: the revision must be what the ACL already is");

    // A preallocated ACL that fits exactly one ACE refuses the second.
    std::uint8_t tight[8 + 8 + 16];
    check(as_InitializeAcl(tight, sizeof(tight), 2) == 1 &&
              as_AddAccessAllowedAce(tight, 2, 1, looked_up) == 1,
          "acl: an exactly-fitting ACE is accepted");
    set_last_error(0);
    check(as_AddAccessAllowedAce(tight, 2, 1, everyone) == 0 &&
              k32_GetLastError() == kErrInvalidParameter,
          "acl: an ACE past the allocation is refused, not written");

    check(as_AreAllAccessesGranted(0x1F01FF, 0x1F01FF) == 1,
          "mask: an exact grant is granted");
    check(as_AreAllAccessesGranted(0x1F01FF, 0x1F03FF) == 0,
          "mask: a missing bit is not granted");
    check(as_AreAllAccessesGranted(0, 0) == 1, "mask: nothing desired is granted");

    std::uint32_t mask = kGenericRead;
    as_MapGenericMask(&mask, kMapping);
    check(mask == 0x00000001, "mask: GENERIC_READ maps and the bit is cleared");
    mask = kGenericRead | 0x40000000u;
    as_MapGenericMask(&mask, kMapping);
    check(mask == 0x00000003, "mask: two generic bits map through both fields");
    mask = 0x00000008;
    as_MapGenericMask(&mask, kMapping);
    check(mask == 0x00000008, "mask: a specific mask passes through untouched");

    // Descriptor + ACL wiring, then Get reads what Set wrote.
    check(as_SetSecurityDescriptorDacl(sd, 1, acl, 0) == 1, "sd: the DACL is set");
    std::int32_t present = 0;
    const void* dacl = nullptr;
    check(as_GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) == 1 &&
              present == 1 && dacl == reinterpret_cast<const void*>(acl) &&
              defaulted == 0,
          "sd: the DACL reads back with its present bit");
    check(as_GetSecurityDescriptorControl(sd, &control, &revision) == 1 &&
              (control & 0x0004) != 0,
          "sd: SE_DACL_PRESENT lands in the control word");
    check(as_SetSecurityDescriptorDacl(sd, 0, nullptr, 0) == 1 &&
              as_GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) == 1 &&
              present == 0 && dacl == nullptr,
          "sd: clearing the DACL clears the pointer and the bit");
    check(as_SetSecurityDescriptorSacl(sd, 1, acl, 1) == 1 &&
              as_GetSecurityDescriptorSacl(sd, &present, &dacl, &defaulted) == 1 &&
              present == 1 && defaulted == 1,
          "sd: the SACL reads back with its defaulted bit");
    check(as_SetSecurityDescriptorControl(sd, 0x1000, 0x1000) == 1 &&
              as_GetSecurityDescriptorControl(sd, &control, &revision) == 1 &&
              (control & 0x1000) != 0,
          "sd: SetSecurityDescriptorControl sets exactly the masked bits");

    // ===================================================================
    // AccessCheck
    // ===================================================================
    // A fresh descriptor, no DACL: everything is granted.
    check(as_InitializeSecurityDescriptor(sd, 1) == 1, "ac: a fresh descriptor");
    std::uint32_t granted = 0xFFFFFFFFu;
    std::int32_t status = -1;
    check(as_AccessCheck(sd, token, 0x7F, kMapping, nullptr, 0, &granted,
                         &status) == 1 &&
              k32_GetLastError() == kErrorSuccess && granted == 0x7F &&
              status == 1,
          "ac: no DACL grants everything with a successful call");
    // Present-but-null DACL is the same answer.
    check(as_SetSecurityDescriptorDacl(sd, 1, nullptr, 0) == 1 &&
              as_AccessCheck(sd, token, 0x7F, kMapping, nullptr, 0, &granted,
                             &status) == 1 &&
              granted == 0x7F && status == 1,
          "ac: a present null DACL grants everything");

    // DACL: user allowed bit 0 only.
    check(as_InitializeAcl(acl, sizeof(acl), 2) == 1 &&
              as_AddAccessAllowedAce(acl, 2, 0x00000001, looked_up) == 1 &&
              as_SetSecurityDescriptorDacl(sd, 1, acl, 0) == 1,
          "ac: a one-ACE DACL is built");
    check(as_AccessCheck(sd, token, 0x00000001, kMapping, nullptr, 0, &granted,
                         &status) == 1 &&
              granted == 0x00000001 && status == 1,
          "ac: an allowed bit is granted");
    check(as_AccessCheck(sd, token, 0x00000003, kMapping, nullptr, 0, &granted,
                         &status) == 1 &&
              granted == 0 && status == 0,
          "ac: a partially-allowed request is denied with a successful call");
    check(as_AccessCheck(sd, token, kMaximumAllowed | 0x00000003, kMapping,
                         nullptr, 0, &granted, &status) == 1 &&
              granted == 0x00000001 && status == 1,
          "ac: MAXIMUM_ALLOWED answers the best mask instead");
    check(as_AccessCheck(sd, token, kGenericRead, kMapping, nullptr, 0,
                         &granted, &status) == 1 &&
              granted == 0x00000001,
          "ac: the generic bits map before the walk");
    check(as_AccessCheck(bad_sd, token, 1, kMapping, nullptr, 0, &granted,
                         &status) == 0 &&
              k32_GetLastError() == kErrInvalidParameter,
          "ac: a corrupt descriptor is refused");
    check(as_AccessCheck(sd, 0x99, 1, kMapping, nullptr, 0, &granted,
                         &status) == 0 &&
              k32_GetLastError() == kErrInvalidHandle,
          "ac: an unknown token is refused");
    check(as_AccessCheck(sd, token, 1, nullptr, nullptr, 0, &granted,
                         &status) == 0 &&
              k32_GetLastError() == kErrInvalidParameter,
          "ac: a null mapping is refused");

    // Empty DACL denies; deny-then-allow denies; Everyone adds its bits.
    check(as_InitializeAcl(tight, sizeof(tight), 2) == 1,
          "ac: an empty ACL is built");
    check(as_SetSecurityDescriptorDacl(sd, 1, tight, 0) == 1 &&
              as_AccessCheck(sd, token, 1, kMapping, nullptr, 0, &granted,
                             &status) == 1 &&
              status == 0,
          "ac: an empty DACL denies everything");
    check(as_InitializeAcl(acl, sizeof(acl), 2) == 1 &&
              as_AddAccessAllowedAce(acl, 2, 0x00000001, looked_up) == 1 &&
              as_AddAccessAllowedAce(acl, 2, 0x00000002, everyone) == 1 &&
              as_SetSecurityDescriptorDacl(sd, 1, acl, 0) == 1 &&
              as_AccessCheck(sd, token, 0x00000003, kMapping, nullptr, 0,
                             &granted, &status) == 1 &&
              granted == 0x00000003 && status == 1,
          "ac: the user's bits and Everyone's bits accumulate");
    std::uint8_t deny_acl[64];
    check(as_InitializeAcl(deny_acl, sizeof(deny_acl), 2) == 1,
          "ac: the deny ACL is built");
    (void)as_AddAccessAllowedAce(deny_acl, 2, 0x00000001, everyone);
    // Write a denied ACE by hand: AddAccessAllowed* only writes allowed ones.
    {
        // The everyone ACE just added occupies 8 + 12 bytes; the deny ACE
        // goes behind it.
        auto* deny = deny_acl + 8 + (8 + 12);
        deny[0] = 1;  // ACCESS_DENIED_ACE_TYPE
        deny[1] = 0;
        write_u16(deny, 2, 8 + 16);
        write_u32(deny, 4, 0x00000001);
        std::memcpy(deny + 8, looked_up, 16);
        write_u16(deny_acl, 4, 2);
    }
    check(as_SetSecurityDescriptorDacl(sd, 1, deny_acl, 0) == 1 &&
              as_AccessCheck(sd, token, 0x00000001, kMapping, nullptr, 0,
                             &granted, &status) == 1 &&
              granted == 0 && status == 0,
          "ac: a matching deny ACE stops the walk with nothing granted");

    // ===================================================================
    // GetEffectiveRightsFromAcl
    // ===================================================================
    std::uint8_t rights_acl[64];
    check(as_InitializeAcl(rights_acl, sizeof(rights_acl), 2) == 1 &&
              as_AddAccessAllowedAce(rights_acl, 2, 0x00000005, looked_up) == 1,
          "er: the rights ACL is built");
    // Everyone denies bit 2: the net answer is 0x5 & ~0x4.
    (void)as_AddAccessAllowedAce(rights_acl, 2, 0x00000004, everyone);
    {
        // Overwrite the second ACE's type to denied, in place.
        void* second = nullptr;
        (void)as_GetAce(rights_acl, 1, &second);
        if (second != nullptr) {
            static_cast<std::uint8_t*>(second)[0] = 1;
        }
    }
    std::uint32_t rights = 0;
    std::uint8_t trustee[32];
    std::memset(trustee, 0, sizeof(trustee));
    write_ptr(trustee, 0, 0);              // no multiple trustee
    write_u32(trustee, 8, 0);              // not impersonate
    write_u32(trustee, 12, 0);             // TRUSTEE_IS_SID
    write_ptr(trustee, 24, reinterpret_cast<std::uint64_t>(looked_up));
    check(as_GetEffectiveRightsFromAclW(rights_acl, trustee, &rights) ==
              kErrorSuccess &&
              rights == 0x00000001,
          "er: allowed minus denied is the net mask for the SID trustee");
    // The trustee names the user instead of carrying the SID.
    std::u16string trustee_name = user_wide;
    write_u32(trustee, 12, 1);  // TRUSTEE_IS_NAME
    write_ptr(trustee, 24,
              reinterpret_cast<std::uint64_t>(trustee_name.c_str()));
    check(as_GetEffectiveRightsFromAclW(rights_acl, trustee, &rights) ==
              kErrorSuccess &&
              rights == 0x00000001,
          "er: a name trustee resolves to the same net mask");
    std::u16string nobody = u"No Such Trustee";
    write_ptr(trustee, 24, reinterpret_cast<std::uint64_t>(nobody.c_str()));
    check(as_GetEffectiveRightsFromAclW(rights_acl, trustee, &rights) ==
              kErrNoneMapped,
          "er: an unresolvable name is NONE_MAPPED");
    write_u32(trustee, 12, 7);  // not a form this runtime knows
    check(as_GetEffectiveRightsFromAclW(rights_acl, trustee, &rights) ==
              kErrInvalidParameter,
          "er: an unknown trustee form is refused");
    // The A form takes the narrow name and answers the same mask.
    write_u32(trustee, 12, 1);
    write_ptr(trustee, 24,
              reinterpret_cast<std::uint64_t>(narrow_name2));
    check(as_GetEffectiveRightsFromAclA(rights_acl, trustee, &rights) ==
              kErrorSuccess &&
              rights == 0x00000001,
          "er: the A form resolves the narrow name to the same mask");
    check(as_GetEffectiveRightsFromAclW(nullptr, trustee, &rights) ==
              kErrInvalidParameter,
          "er: a null ACL is refused");
    // ===================================================================
    // Refusals: the subsystems this runtime does not run
    // ===================================================================
    set_last_error(0);
    check(as_OpenSCManagerW(nullptr, nullptr, 0) == 0 &&
              k32_GetLastError() == kErrCallNotImplemented,
          "refuse: no service control manager behind OpenSCManager");
    check(as_CloseServiceHandle(1) == 0 &&
              k32_GetLastError() == kErrCallNotImplemented,
          "refuse: CloseServiceHandle refuses without a fake success");
    check(as_LogonUserW(nullptr, nullptr, nullptr, 0, 0, &token2) == 0 &&
              k32_GetLastError() == kErrCallNotImplemented,
          "refuse: LogonUser needs an authentication stack");
    check(as_RevertToSelf() == 0 &&
              k32_GetLastError() == kErrCallNotImplemented,
          "refuse: RevertToSelf has nothing to revert to");
    check(as_ImpersonateSelf(2) == 0 &&
              k32_GetLastError() == kErrCallNotImplemented,
          "refuse: ImpersonateSelf refuses rather than pretending");
    check(as_SetEntriesInAclW(0, nullptr, nullptr, &ace) == kErrCallNotImplemented,
          "refuse: SetEntriesInAcl refuses with the error as its return");
    check(as_ConvertStringSecurityDescriptorToSecurityDescriptorW(
              u"O:SY", 1, &parsed, nullptr) == 0 &&
              k32_GetLastError() == kErrCallNotImplemented,
          "refuse: the SDDL grammar is refused, not half-parsed");
    check(as_GetSecurityInfo(1, 1, 0, nullptr, nullptr, nullptr, nullptr,
                             nullptr) == kErrCallNotImplemented,
          "refuse: object security needs securable objects to exist");
    check(as_SetTokenInformation(token, 1, info, 4) == 0 &&
              k32_GetLastError() == kErrCallNotImplemented,
          "refuse: the token has no writable state to set");
    check(as_SetTokenInformation(0x99, 1, info, 4) == 0 &&
              k32_GetLastError() == kErrInvalidHandle,
          "refuse: SetTokenInformation still validates the handle first");

    as_FreeSid(everyone);
    as_FreeSid(parsed);
    as_FreeSid(sid);

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

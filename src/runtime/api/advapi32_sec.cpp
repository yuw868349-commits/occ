// The advapi32 security surface: SIDs, tokens, security descriptors, ACLs.
//
// The runtime is a single process with a single user, and that is not a
// limitation to apologise for here -- it is what lets most of this family be
// real instead of stubbed. A SID is a byte structure this file builds and
// reads; the token is one synthetic token whose user is the host's effective
// uid mapped to the Unix-user SID convention (`S-1-22-1-<uid>`, the same
// mapping Wine and Samba use); a security descriptor is a byte structure the
// Set/Get calls really read and write. The checks that Windows answers by
// walking a DACL -- `AccessCheck`, `CheckTokenMembership`,
// `GetEffectiveRightsFromAcl` -- walk one here too.
//
// The token deliberately holds no privileges. That is the one place the
// synthetic model diverges from a logged-on Windows token, which carries
// `SeChangeNotifyPrivilege` at least; a guest that checks for a specific
// privilege gets the honest answer "not held" rather than a lucky yes.
//
// Refusals are explicit. Service control needs an SCM subsystem this
// runtime does not have, impersonation needs an authentication subsystem,
// and SDDL needs a string grammar worth doing properly or not at all; each
// of those answers `ERROR_CALL_NOT_IMPLEMENTED` rather than a success that
// would promise behaviour no object backs. An entry point that answers
// success without state behind it is a lie a guest builds on.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

#include <pwd.h>
#include <unistd.h>

namespace occ::runtime::winabi {
namespace {

// ------------------------------------------------------------- win32 errors
//
// The codes this domain answers that `api_common.h` does not carry. They are
// named here for the same reason the shared ones are: a reader should not
// have to look a failure up.
constexpr std::uint32_t kErrorNotAllAssigned = 1300;
constexpr std::uint32_t kErrorUnknownRevision = 1305;
constexpr std::uint32_t kErrorNoSuchPrivilege = 1313;
constexpr std::uint32_t kErrorPrivilegeNotHeld = 1314;
constexpr std::uint32_t kErrorNoneMapped = 1332;
constexpr std::uint32_t kErrorInvalidSid = 1337;

// ------------------------------------------------------------ SID structure
//
// REVISION(1) + SubAuthorityCount(1) + IdentifierAuthority(6) +
// SubAuthority[n](4). The authority is big-endian, the subauthorities are
// little-endian DWORDs, and the accessors return pointers *inside* the SID
// because that is what the Windows spellings do -- a caller that writes
// through `GetSidSubAuthority` must reach the caller's own buffer.
constexpr std::size_t kSidRevision = 0;
constexpr std::size_t kSidCount = 1;
constexpr std::size_t kSidAuthority = 2;
constexpr std::size_t kSidSubAuthority = 8;
constexpr std::uint8_t kSidRevisionValue = 1;
constexpr std::uint32_t kSidMaxSubAuthorities = 15;

constexpr std::uint8_t kAclRevisionValue = 2;
constexpr std::uint8_t kAclRevisionDsValue = 4;
constexpr std::size_t kAclHeaderBytes = 8;

// ACE types and the header a walk steps over.
constexpr std::uint8_t kAceTypeAllowed = 0;
constexpr std::uint8_t kAceTypeDenied = 1;

// SECURITY_DESCRIPTOR, non-relative, 64-bit: revision, control word, four
// pointers. `GetSecurityDescriptorLength` answers 40 for this shape.
constexpr std::size_t kSdRevision = 0;
constexpr std::size_t kSdControl = 2;
constexpr std::size_t kSdOwner = 8;
constexpr std::size_t kSdGroup = 16;
constexpr std::size_t kSdSacl = 24;
constexpr std::size_t kSdDacl = 32;
constexpr std::uint32_t kSdBytes = 40;
constexpr std::uint16_t kSeOwnerDefaulted = 0x0001;
constexpr std::uint16_t kSeGroupDefaulted = 0x0002;
constexpr std::uint16_t kSeDaclPresent = 0x0004;
constexpr std::uint16_t kSeDaclDefaulted = 0x0008;
constexpr std::uint16_t kSeSaclPresent = 0x0010;
constexpr std::uint16_t kSeSaclDefaulted = 0x0020;

// ACL header: revision, sbz1, AclSize, AceCount, sbz2.
constexpr std::size_t kAclRevision = 0;
constexpr std::size_t kAclSize = 2;
constexpr std::size_t kAclCount = 4;
// ACE header: type, flags, AceSize, AccessMask, then the SID inline.
constexpr std::size_t kAceSize = 2;
constexpr std::size_t kAceMask = 4;
constexpr std::size_t kAceSid = 8;

// Access-mask bits this domain decides on.
constexpr std::uint32_t kGenericRead = 0x80000000u;
constexpr std::uint32_t kGenericWrite = 0x40000000u;
constexpr std::uint32_t kGenericExecute = 0x20000000u;
constexpr std::uint32_t kGenericAll = 0x10000000u;
constexpr std::uint32_t kMaximumAllowed = 0x02000000u;

// Token information classes.
constexpr std::uint32_t kTokenUserClass = 1;
constexpr std::uint32_t kTokenGroupsClass = 2;
constexpr std::uint32_t kTokenPrivilegesClass = 3;
constexpr std::uint32_t kTokenOwnerClass = 4;
constexpr std::uint32_t kTokenPrimaryGroupClass = 5;
constexpr std::uint32_t kTokenSourceClass = 7;
constexpr std::uint32_t kTokenStatisticsClass = 10;
// TOKEN_STATISTICS fields, 64-bit layout: two LUIDs, an expiration time,
// then the small fields, then the modified LUID.
constexpr std::size_t kTokenStatsBytes = 56;
constexpr std::size_t kTokenStatsTokenType = 24;

// PRIVILEGE_SET: count, control, LUID_AND_ATTRIBUTES[1].
constexpr std::size_t kPrivilegeSetMinimum = 16;

// The synthetic token handle. Any nonzero value nothing else issues; the
// token has no per-instance state, so one constant identifies it.
constexpr std::uint64_t kTokenHandle = 0x0053454300000001ULL;

// Current process / thread pseudo-handles, the only handles a single-process
// run can name.
constexpr std::uint64_t kCurrentProcessPseudo = 0xFFFFFFFFFFFFFFFFULL;
constexpr std::uint64_t kCurrentThreadPseudo = 0xFFFFFFFFFFFFFFFEULL;

// SE_PRIVILEGE_ENABLED, the bit an enable request sets.
constexpr std::uint32_t kSePrivilegeEnabled = 0x00000002u;
constexpr std::uint32_t kSePrivilegeRemoved = 0x00000004u;

// LANGID answered by LookupPrivilegeDisplayName: US English, the only
// language this runtime's display names are written in.
constexpr std::uint32_t kLangIdUsEnglish = 0x0409u;

// TRUSTEE layout, 64-bit: pMultipleTrustee, MultipleTrusteeOperation,
// TrusteeForm, TrusteeType, pad, ptstrName.
constexpr std::size_t kTrusteeMultiple = 0;
constexpr std::size_t kTrusteeMultipleOp = 8;
constexpr std::size_t kTrusteeForm = 12;
constexpr std::size_t kTrusteeName = 24;
constexpr std::uint32_t kTrusteeFormIsSid = 0;
constexpr std::uint32_t kTrusteeFormIsName = 1;
constexpr std::uint32_t kTrusteeIsImpersonate = 1;

// SidTypeUser / SidTypeWellKnownGroup, the two answers this runtime gives.
constexpr std::uint32_t kSidTypeUser = 1;
constexpr std::uint32_t kSidTypeWellKnownGroup = 5;

// The privilege table. The LUID low parts are the machine-invariant values
// Windows assigns (the well-known constant LUIDs, constant across systems
// because they are allocated in winnt.h order starting at 2); the programmatic
// names are the winnt.h spellings and the display names are the English
// strings the documentation lists. This is the table a real system answers
// for a fresh install; nothing here is inferred per-call.
struct PrivilegeEntry {
    std::uint32_t value;
    const char* name;
    const char* display;
};

constexpr PrivilegeEntry kPrivileges[] = {
    {2, "SeCreateTokenPrivilege", "Create a token object"},
    {3, "SeAssignPrimaryTokenPrivilege", "Replace a process level token"},
    {4, "SeLockMemoryPrivilege", "Lock pages in memory"},
    {5, "SeIncreaseQuotaPrivilege", "Increase quotas"},
    {6, "SeMachineAccountPrivilege", "Add workstations to domain"},
    {7, "SeTcbPrivilege", "Act as part of the operating system"},
    {8, "SeSecurityPrivilege", "Manage auditing and security log"},
    {9, "SeTakeOwnershipPrivilege", "Take ownership of files or other objects"},
    {10, "SeLoadDriverPrivilege", "Load and unload device drivers"},
    {11, "SeSystemProfilePrivilege", "Profile system performance"},
    {12, "SeSystemtimePrivilege", "Change the system time"},
    {13, "SeProfSingleProcessPrivilege", "Profile single process"},
    {14, "SeIncreaseBasePriorityPrivilege", "Increase scheduling priority"},
    {15, "SeCreatePagefilePrivilege", "Create a pagefile"},
    {16, "SeCreatePermanentPrivilege", "Create permanent shared objects"},
    {17, "SeBackupPrivilege", "Back up files and directories"},
    {18, "SeRestorePrivilege", "Restore files and directories"},
    {19, "SeShutdownPrivilege", "Shut down the system"},
    {20, "SeDebugPrivilege", "Debug programs"},
    {21, "SeAuditPrivilege", "Generate security audits"},
    {22, "SeSystemEnvironmentPrivilege", "Modify firmware environment values"},
    {23, "SeChangeNotifyPrivilege",
     "Receive notifications of changes of files or directories"},
    {24, "SeRemoteShutdownPrivilege",
     "Force shutdown from a remote system"},
    {25, "SeUndockPrivilege", "Remove computer from docking station"},
    {26, "SeSyncAgentPrivilege", "Synchronize directory service data"},
    {27, "SeEnableDelegationPrivilege",
     "Enable computer and user accounts to be trusted for delegation"},
    {28, "SeManageVolumePrivilege", "Perform volume maintenance tasks"},
    {29, "SeImpersonatePrivilege",
     "Impersonate a client after authentication"},
    {30, "SeCreateGlobalPrivilege", "Create global objects"},
    {31, "SeTrustedCredManAccessPrivilege",
     "Access Credential Manager as a trusted caller"},
    {32, "SeRelabelPrivilege", "Modify an object label"},
    {33, "SeIncreaseWorkingSetPrivilege", "Increase a process working set"},
    {34, "SeTimeZonePrivilege", "Change the time zone"},
    {35, "SeCreateSymbolicLinkPrivilege", "Create symbolic links"},
    {36, "SeDelegateSessionUserImpersonatePrivilege",
     "Obtain an impersonation token for another session"},
};

// ------------------------------------------------------------------ helpers

// A SID small enough to hold any this domain builds: 15 subauthorities max.
struct SidBuffer {
    std::uint8_t bytes[kSidSubAuthority + 4 * kSidMaxSubAuthorities] = {};
    std::uint32_t length = 0;
};

[[nodiscard]] bool valid_sid(const void* sid) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(sid);
    if (bytes == nullptr) {
        return false;
    }
    // A revision other than 1 is not a SID this runtime can name, and a
    // subauthority count past the maximum the structure can hold is a
    // corrupt buffer, not a large identity.
    return bytes[kSidRevision] == kSidRevisionValue &&
           bytes[kSidCount] <= kSidMaxSubAuthorities;
}

[[nodiscard]] std::uint32_t sid_length(const void* sid) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(sid);
    return kSidSubAuthority + 4u * bytes[kSidCount];
}

[[nodiscard]] bool sid_equals(const void* a, const void* b) noexcept {
    if (!valid_sid(a) || !valid_sid(b)) {
        return false;
    }
    const std::uint32_t length = sid_length(a);
    return length == sid_length(b) &&
           std::memcmp(a, b, length) == 0;
}

// The Everyone SID, S-1-1-0. Membership in it is implicit for every caller
// on Windows -- it is in every token's group list -- so the checks below
// treat it as the subject's own group even though `TokenGroups` answers an
// empty list.
[[nodiscard]] SidBuffer everyone_sid() noexcept {
    SidBuffer out;
    out.length = kSidSubAuthority + 4;
    out.bytes[kSidRevision] = kSidRevisionValue;
    out.bytes[kSidCount] = 1;
    out.bytes[kSidAuthority + 5] = 1;  // identifier authority 1
    // SubAuthority[0] = 0 stays zero.
    return out;
}

// The Unix-user SID, S-1-22-1-<uid>: identifier authority 22 with
// subauthority 1 marking a user, the convention Wine and Samba use to map
// Unix identities into the Windows namespace. This is the token's user.
[[nodiscard]] SidBuffer user_sid() noexcept {
    const auto uid = static_cast<std::uint32_t>(::geteuid());
    SidBuffer out;
    out.length = kSidSubAuthority + 8;
    out.bytes[kSidRevision] = kSidRevisionValue;
    out.bytes[kSidCount] = 2;
    out.bytes[kSidAuthority + 5] = 22;
    write_u32(out.bytes, kSidSubAuthority, 1);
    write_u32(out.bytes, kSidSubAuthority + 4, uid);
    return out;
}

// The primary group, S-1-22-2-<gid>, the same convention's group form.
[[nodiscard]] SidBuffer group_sid() noexcept {
    gid_t gid = ::getegid();
    const ::passwd* pw = ::getpwuid(::geteuid());
    if (pw != nullptr) {
        gid = pw->pw_gid;
    }
    const auto value = static_cast<std::uint32_t>(gid);
    SidBuffer out;
    out.length = kSidSubAuthority + 8;
    out.bytes[kSidRevision] = kSidRevisionValue;
    out.bytes[kSidCount] = 2;
    out.bytes[kSidAuthority + 5] = 22;
    write_u32(out.bytes, kSidSubAuthority, 2);
    write_u32(out.bytes, kSidSubAuthority + 4, value);
    return out;
}

// The subject a DACL check runs against: the token user, or the Everyone
// group every token belongs to.
[[nodiscard]] bool sid_matches_subject(const void* sid) noexcept {
    const SidBuffer user = user_sid();
    if (sid_equals(sid, user.bytes)) {
        return true;
    }
    const SidBuffer world = everyone_sid();
    return sid_equals(sid, world.bytes);
}

[[nodiscard]] std::string host_user_name() noexcept {
    const ::passwd* pw = ::getpwuid(::geteuid());
    // The fallback is the account a uid without a passwd entry still is;
    // Windows never fails this query and neither does this runtime.
    return pw != nullptr ? std::string(pw->pw_name) : std::string("user");
}

[[nodiscard]] std::string host_domain_name() noexcept {
    // A standalone Windows machine answers its own name as the account
    // domain; the host name is the closest true statement here.
    char name[256] = {};
    if (::gethostname(name, sizeof(name) - 1) != 0) {
        return {};
    }
    return std::string(name);
}

[[nodiscard]] std::u16string wide_of_utf8(const std::string& text) noexcept {
    std::u16string out;
    if (!utf8_to_utf16(text, out)) {
        out.clear();
    }
    return out;
}

[[nodiscard]] std::u16string read_wide(const char16_t* text) noexcept {
    if (text == nullptr) {
        return {};
    }
    std::size_t n = 0;
    while (text[n] != u'\0') {
        ++n;
    }
    return std::u16string(text, n);
}

[[nodiscard]] bool read_narrow(const char* text, std::u16string& out) noexcept {
    out.clear();
    if (text == nullptr) {
        return true;
    }
    return narrow_in(std::string_view(text), out).converted;
}

[[nodiscard]] bool ascii_iequal(std::string_view a,
                                std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        const char left = a[i] >= 'A' && a[i] <= 'Z'
                              ? static_cast<char>(a[i] - 'A' + 'a')
                              : a[i];
        const char right = b[i] >= 'A' && b[i] <= 'Z'
                               ? static_cast<char>(b[i] - 'A' + 'a')
                               : b[i];
        if (left != right) {
            return false;
        }
    }
    return true;
}

// Writes `text` into a caller's buffer under the Lookup* convention: on
// success `*chars` receives the count copied without the terminator, on a
// too-small buffer it receives the required size with the terminator and
// the error is `ERROR_INSUFFICIENT_BUFFER`.
bool write_chars_wide(std::u16string_view text, char16_t* buffer,
                      std::uint32_t* chars) noexcept {
    const std::size_t need = required_capacity(text);
    if (buffer == nullptr || *chars < need) {
        *chars = static_cast<std::uint32_t>(need);
        set_last_error(kErrorInsufficientBuffer);
        return false;
    }
    if (!text.empty()) {
        std::memcpy(buffer, text.data(), text.size() * sizeof(char16_t));
    }
    buffer[text.size()] = u'\0';
    *chars = static_cast<std::uint32_t>(text.size());
    return true;
}

bool write_chars_narrow(std::string_view text, char* buffer,
                        std::uint32_t* chars) noexcept {
    const std::size_t need = required_capacity(text);
    if (buffer == nullptr || *chars < need) {
        *chars = static_cast<std::uint32_t>(need);
        set_last_error(kErrorInsufficientBuffer);
        return false;
    }
    if (!text.empty()) {
        std::memcpy(buffer, text.data(), text.size());
    }
    buffer[text.size()] = '\0';
    *chars = static_cast<std::uint32_t>(text.size());
    return true;
}

[[nodiscard]] bool is_token(std::uint64_t handle) noexcept {
    return handle == kTokenHandle;
}

// ----------------------------------------------------------- SID <-> string

void append_decimal(std::u16string& out, std::uint64_t value) noexcept {
    const std::string digits = std::to_string(value);
    for (const char c : digits) {
        out.push_back(static_cast<char16_t>(c));
    }
}

[[nodiscard]] std::u16string sid_to_string(const void* sid, bool& ok) noexcept {
    ok = valid_sid(sid);
    if (!ok) {
        return {};
    }
    const auto* bytes = static_cast<const std::uint8_t*>(sid);
    std::uint64_t authority = 0;
    for (std::size_t i = 0; i < 6; ++i) {
        authority = (authority << 8) | bytes[kSidAuthority + i];
    }
    std::u16string out = u"S-1-";
    append_decimal(out, authority);
    const std::size_t count = bytes[kSidCount];
    for (std::size_t i = 0; i < count; ++i) {
        out.push_back(u'-');
        append_decimal(out, read_u32(sid, kSidSubAuthority + 4 * i));
    }
    return out;
}

// Parses `S-1-<authority>[-<subauthority>]...`. The grammar is strict: the
// revision literal is 1, every component is at least one digit, a component
// must fit its field (48 bits for the authority, 32 for a subauthority),
// the subauthority count tops out at the structure's maximum, and the string
// ends with the last digit. Anything else is ERROR_INVALID_SID -- a caller
// that hands this a mangled string is asking for the structure, and a
// half-parsed SID is worse than no SID.
[[nodiscard]] bool parse_sid_string(std::u16string_view text,
                                    SidBuffer& out) noexcept {
    const auto digits = [&text](std::size_t& pos, std::uint64_t limit,
                                std::uint64_t& value) noexcept {
        if (pos >= text.size() || text[pos] < u'0' || text[pos] > u'9') {
            return false;
        }
        std::uint64_t acc = 0;
        while (pos < text.size() && text[pos] >= u'0' && text[pos] <= u'9') {
            acc = acc * 10 + static_cast<std::uint64_t>(text[pos] - u'0');
            if (acc > limit) {
                return false;
            }
            ++pos;
        }
        value = acc;
        return true;
    };

    // "S-1-" then the authority: the revision literal is part of the format,
    // not a component a caller can choose.
    if (text.size() < 5 || text[0] != u'S' || text[1] != u'-' ||
        text[2] != u'1' || text[3] != u'-') {
        return false;
    }
    std::size_t pos = 4;
    std::uint64_t authority = 0;
    constexpr std::uint64_t kMaxAuthority = 0xFFFFFFFFFFFFULL;
    if (!digits(pos, kMaxAuthority, authority) || pos >= text.size() ||
        text[pos] != u'-') {
        return false;
    }
    ++pos;

    // At least one subauthority: the string form always names one, the null
    // SID included ("S-1-0-0").
    std::uint32_t count = 0;
    for (;;) {
        std::uint64_t sub = 0;
        if (!digits(pos, 0xFFFFFFFFULL, sub)) {
            return false;
        }
        if (count == kSidMaxSubAuthorities) {
            return false;
        }
        write_u32(out.bytes, kSidSubAuthority + 4 * count,
                  static_cast<std::uint32_t>(sub));
        ++count;
        if (pos == text.size()) {
            break;
        }
        if (text[pos] != u'-') {
            return false;
        }
        ++pos;
    }

    out.length = kSidSubAuthority + 4 * count;
    out.bytes[kSidRevision] = kSidRevisionValue;
    out.bytes[kSidCount] = static_cast<std::uint8_t>(count);
    for (std::size_t i = 0; i < 6; ++i) {
        out.bytes[kSidAuthority + i] =
            static_cast<std::uint8_t>((authority >> (8 * (5 - i))) & 0xFF);
    }
    return true;
}

// -------------------------------------------------------------- DACL walk

// Walks `acl` for `subject`, accumulating the allowed bits and stopping at a
// matching denied ACE that intersects `desired`. `denied` reports whether the
// walk was stopped that way; a caller that wants the net mask instead reads
// the ACEs itself.
[[nodiscard]] std::uint32_t acl_granted_for(const void* acl,
                                            std::uint32_t desired,
                                            bool& denied) noexcept {
    denied = false;
    const std::size_t count = read_u16(acl, kAclCount);
    std::size_t pos = kAclHeaderBytes;
    std::uint32_t granted = 0;
    for (std::size_t i = 0; i < count; ++i) {
        const std::size_t size = read_u16(acl, pos + kAceSize);
        if (size < kAceSid) {
            break;  // malformed tail; treat as no further ACEs
        }
        const auto* ace = static_cast<const std::uint8_t*>(acl) + pos;
        const std::uint8_t type = ace[0];
        if (type == kAceTypeAllowed || type == kAceTypeDenied) {
            const std::uint32_t mask = read_u32(ace, kAceMask);
            const void* sid = ace + kAceSid;
            if (valid_sid(sid) && sid_matches_subject(sid)) {
                if (type == kAceTypeDenied && (mask & desired) != 0) {
                    denied = true;
                    return granted;
                }
                if (type == kAceTypeAllowed) {
                    granted |= mask;
                }
            }
        }
        pos += size;
    }
    return granted;
}

// The offset of the first byte past the last ACE, which is where
// `FindFirstFreeAce` points and where the next `Add*Ace` writes.
[[nodiscard]] std::size_t acl_end_offset(const void* acl,
                                         bool& well_formed) noexcept {
    well_formed = true;
    const std::size_t count = read_u16(acl, kAclCount);
    std::size_t pos = kAclHeaderBytes;
    for (std::size_t i = 0; i < count; ++i) {
        const std::size_t size = read_u16(acl, pos + kAceSize);
        if (size < kAceSid) {
            well_formed = false;
            return pos;
        }
        pos += size;
    }
    return pos;
}

[[nodiscard]] bool valid_acl(const void* acl) noexcept {
    if (acl == nullptr) {
        return false;
    }
    const std::uint8_t revision = static_cast<const std::uint8_t*>(acl)[kAclRevision];
    return revision == kAclRevisionValue || revision == kAclRevisionDsValue;
}

// A security descriptor this runtime initialised: revision 1 at the head.
[[nodiscard]] bool valid_sd(const void* sd) noexcept {
    return sd != nullptr &&
           static_cast<const std::uint8_t*>(sd)[kSdRevision] ==
               kSidRevisionValue;
}

// Maps the generic bits of `mask` through `mapping`, clearing the generic
// bits, exactly as `MapGenericMask` does; `AccessCheck` maps its own copy.
[[nodiscard]] std::uint32_t map_generic(std::uint32_t mask,
                                        const void* mapping) noexcept {
    if ((mask & kGenericRead) != 0) {
        mask |= read_u32(mapping, 0);
    }
    if ((mask & kGenericWrite) != 0) {
        mask |= read_u32(mapping, 4);
    }
    if ((mask & kGenericExecute) != 0) {
        mask |= read_u32(mapping, 8);
    }
    if ((mask & kGenericAll) != 0) {
        mask |= read_u32(mapping, 12);
    }
    mask &= ~(kGenericRead | kGenericWrite | kGenericExecute | kGenericAll);
    return mask;
}

// --------------------------------------------------------------- accounts

struct AccountAnswer {
    std::u16string name;
    std::u16string domain;
    std::uint32_t use = 0;
    bool ok = false;
    std::uint32_t error = 0;
};

// What this runtime answers for a SID: the mapped user, or Everyone. There
// are no other accounts to name and no lookup service behind them, so the
// answer is computed rather than searched.
[[nodiscard]] AccountAnswer lookup_account_sid_core(const void* sid) noexcept {
    AccountAnswer out;
    if (sid == nullptr) {
        out.error = kErrorInvalidParameter;
        return out;
    }
    if (!valid_sid(sid)) {
        out.error = kErrorInvalidSid;
        return out;
    }
    if (sid_equals(sid, everyone_sid().bytes)) {
        out.name = u"Everyone";
        out.use = kSidTypeWellKnownGroup;
    } else {
        out.name = wide_of_utf8(host_user_name());
        out.use = kSidTypeUser;
    }
    out.domain = wide_of_utf8(host_domain_name());
    out.ok = true;
    return out;
}

struct NameAnswer {
    SidBuffer sid;
    std::uint32_t use = 0;
    std::u16string domain;
    bool ok = false;
    std::uint32_t error = 0;
};

// The reverse: a name to a SID. Two names are answerable in a single-user
// model -- the host's own user and Everyone -- and everything else is
// NONE_MAPPED, which is the same answer a standalone machine gives for a
// name outside its account database.
[[nodiscard]] NameAnswer lookup_account_name_core(
    const std::u16string& name) noexcept {
    NameAnswer out;
    std::string narrow;
    if (!utf16_to_utf8(name, narrow)) {
        out.error = kErrorNoneMapped;
        return out;
    }
    if (ascii_iequal(narrow, "Everyone")) {
        out.sid = everyone_sid();
        out.use = kSidTypeWellKnownGroup;
    } else if (ascii_iequal(narrow, host_user_name())) {
        out.sid = user_sid();
        out.use = kSidTypeUser;
    } else {
        out.error = kErrorNoneMapped;
        return out;
    }
    out.domain = wide_of_utf8(host_domain_name());
    out.ok = true;
    return out;
}

// -------------------------------------------------------------- privileges

[[nodiscard]] const PrivilegeEntry* privilege_by_luid(std::uint32_t low,
                                                      std::uint32_t high) noexcept {
    if (high != 0) {
        return nullptr;
    }
    for (const auto& entry : kPrivileges) {
        if (entry.value == low) {
            return &entry;
        }
    }
    return nullptr;
}

[[nodiscard]] const PrivilegeEntry* privilege_by_name(
    const std::u16string& name) noexcept {
    std::string narrow;
    if (!utf16_to_utf8(name, narrow)) {
        return nullptr;
    }
    for (const auto& entry : kPrivileges) {
        if (ascii_iequal(narrow, entry.name)) {
            return &entry;
        }
    }
    return nullptr;
}

}  // namespace

// ===========================================================================
// SIDs
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::uint32_t as_GetSidLengthRequired(
    std::uint32_t sub_authority_count) noexcept {
    // The size question is arithmetic, not validation: Windows answers it
    // for any count, and a caller uses the answer to decide whether its own
    // buffer is worth offering.
    return kSidSubAuthority + 4u * sub_authority_count;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_AllocateAndInitializeSid(
    const void* identifier_authority, std::uint32_t sub_authority_count,
    std::uint32_t s0, std::uint32_t s1, std::uint32_t s2, std::uint32_t s3,
    std::uint32_t s4, std::uint32_t s5, std::uint32_t s6, std::uint32_t s7,
    void** sid) noexcept {
    if (identifier_authority == nullptr || sid == nullptr ||
        sub_authority_count > 8) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // Validation before allocation: the count is checked above, the authority
    // read below happens before the buffer is handed out.
    const std::uint32_t length = kSidSubAuthority + 4u * sub_authority_count;
    auto* bytes = static_cast<std::uint8_t*>(std::malloc(length));
    if (bytes == nullptr) {
        set_last_error(kErrorNotEnoughMemory);
        return 0;
    }
    bytes[kSidRevision] = kSidRevisionValue;
    bytes[kSidCount] = static_cast<std::uint8_t>(sub_authority_count);
    std::memcpy(bytes + kSidAuthority, identifier_authority, 6);
    const std::uint32_t values[8] = {s0, s1, s2, s3, s4, s5, s6, s7};
    for (std::uint32_t i = 0; i < sub_authority_count; ++i) {
        write_u32(bytes, kSidSubAuthority + 4 * i, values[i]);
    }
    *sid = bytes;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) void* as_FreeSid(void* sid) noexcept {
    std::free(sid);
    // FreeSid's return is the null pointer on every path; callers compare
    // against it or ignore it.
    return nullptr;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_CopySid(
    std::uint32_t destination_length, void* destination,
    const void* source) noexcept {
    if (!valid_sid(source) || destination == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint32_t length = sid_length(source);
    if (destination_length < length) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    std::memcpy(destination, source, length);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_IsValidSid(
    const void* sid) noexcept {
    return valid_sid(sid) ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_EqualSid(const void* a,
                                                            const void* b) noexcept {
    return sid_equals(a, b) ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t as_GetLengthSid(
    const void* sid) noexcept {
    if (sid == nullptr) {
        return 0;
    }
    return sid_length(sid);
}

extern "C" __attribute__((ms_abi)) const void* as_GetSidIdentifierAuthority(
    const void* sid) noexcept {
    // The accessors return addresses inside the caller's own SID; a caller
    // that writes through this pointer edits its structure in place, which
    // is the contract the Windows spellings carry.
    return sid == nullptr ? nullptr
                          : static_cast<const std::uint8_t*>(sid) +
                                kSidAuthority;
}

extern "C" __attribute__((ms_abi)) void* as_GetSidSubAuthority(
    const void* sid, std::uint32_t index) noexcept {
    if (!valid_sid(sid) ||
        index >= static_cast<const std::uint8_t*>(sid)[kSidCount]) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    return static_cast<std::uint8_t*>(const_cast<void*>(sid)) +
           kSidSubAuthority + 4u * index;
}

extern "C" __attribute__((ms_abi)) void* as_GetSidSubAuthorityCount(
    const void* sid) noexcept {
    if (!valid_sid(sid)) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    return static_cast<std::uint8_t*>(const_cast<void*>(sid)) + kSidCount;
}

// ===========================================================================
// SID <-> string
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t as_ConvertSidToStringSidW(
    const void* sid, char16_t** out) noexcept {
    if (out == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    bool ok = false;
    const std::u16string text = sid_to_string(sid, ok);
    if (!ok) {
        set_last_error(kErrorInvalidSid);
        return 0;
    }
    // The caller frees this with LocalFree, which is allocator-compatible
    // with malloc in every runtime this family is linked into.
    auto* buffer = static_cast<char16_t*>(
        std::malloc((text.size() + 1) * sizeof(char16_t)));
    if (buffer == nullptr) {
        set_last_error(kErrorNotEnoughMemory);
        return 0;
    }
    std::memcpy(buffer, text.data(), text.size() * sizeof(char16_t));
    buffer[text.size()] = u'\0';
    *out = buffer;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_ConvertSidToStringSidA(
    const void* sid, char** out) noexcept {
    if (out == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    bool ok = false;
    const std::u16string wide = sid_to_string(sid, ok);
    if (!ok) {
        set_last_error(kErrorInvalidSid);
        return 0;
    }
    std::string narrow;
    if (!narrow_out(wide, narrow).converted) {
        set_last_error(kErrorInvalidSid);
        return 0;
    }
    auto* buffer = static_cast<char*>(std::malloc(narrow.size() + 1));
    if (buffer == nullptr) {
        set_last_error(kErrorNotEnoughMemory);
        return 0;
    }
    std::memcpy(buffer, narrow.data(), narrow.size());
    buffer[narrow.size()] = '\0';
    *out = buffer;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_ConvertStringSidToSidW(
    const char16_t* text, void** sid) noexcept {
    if (sid == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    SidBuffer parsed;
    if (!parse_sid_string(read_wide(text), parsed)) {
        set_last_error(kErrorInvalidSid);
        return 0;
    }
    auto* bytes = static_cast<std::uint8_t*>(std::malloc(parsed.length));
    if (bytes == nullptr) {
        set_last_error(kErrorNotEnoughMemory);
        return 0;
    }
    std::memcpy(bytes, parsed.bytes, parsed.length);
    *sid = bytes;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_ConvertStringSidToSidA(
    const char* text, void** sid) noexcept {
    std::u16string wide;
    if (!read_narrow(text, wide)) {
        if (sid != nullptr) {
            set_last_error(kErrorInvalidSid);
        }
        return 0;
    }
    return as_ConvertStringSidToSidW(wide.c_str(), sid);
}

// ===========================================================================
// The synthetic token
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t as_OpenProcessToken(
    std::uint64_t process, std::uint32_t desired_access,
    std::uint64_t* token) noexcept {
    (void)desired_access;
    if (token == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // There is one process to open and one token it has; the access mask
    // asks for nothing this runtime can refuse.
    if (process != kCurrentProcessPseudo) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    *token = kTokenHandle;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_OpenThreadToken(
    std::uint64_t thread, std::uint32_t desired_access, std::int32_t open_as,
    std::uint64_t* token) noexcept {
    (void)desired_access;
    (void)open_as;
    if (token == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // One thread, and its token is the process token; Windows answers
    // ERROR_NO_TOKEN for a thread without its own token, but the thread a
    // single-threaded run names is the one this handle stands for.
    if (thread != kCurrentThreadPseudo) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    *token = kTokenHandle;
    set_last_error(kErrorSuccess);
    return 1;
}

namespace {

// Fills the SID-bearing information classes: the SID rides inline behind the
// class's fixed header, and the header's pointer field aims at it.
[[nodiscard]] std::size_t fill_sid_class(void* info, std::size_t header_bytes,
                                         const SidBuffer& sid) noexcept {
    write_ptr(info, 0, reinterpret_cast<std::uint64_t>(info) + header_bytes);
    std::memcpy(static_cast<std::uint8_t*>(info) + header_bytes, sid.bytes,
                sid.length);
    return header_bytes + sid.length;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t as_GetTokenInformation(
    std::uint64_t token, std::uint32_t class_, void* info, std::uint32_t length,
    std::uint32_t* return_length) noexcept {
    if (!is_token(token)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (return_length == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }

    // Each class computes its true size first; a too-small buffer is told
    // the size and nothing is written, which is the token family's own
    // buffer convention.
    std::size_t needed = 0;
    switch (class_) {
    case kTokenUserClass: {
        const SidBuffer user = user_sid();
        // TOKEN_USER = SID_AND_ATTRIBUTES { PSID, ULONG }, padded to 16.
        needed = 16 + user.length;
        if (info == nullptr || length < needed) {
            break;
        }
        needed = fill_sid_class(info, 16, user);
        break;
    }
    case kTokenOwnerClass: {
        const SidBuffer user = user_sid();
        needed = 8 + user.length;
        if (info == nullptr || length < needed) {
            break;
        }
        needed = fill_sid_class(info, 8, user);
        break;
    }
    case kTokenPrimaryGroupClass: {
        const SidBuffer group = group_sid();
        needed = 8 + group.length;
        if (info == nullptr || length < needed) {
            break;
        }
        needed = fill_sid_class(info, 8, group);
        break;
    }
    case kTokenGroupsClass:
        // TOKEN_GROUPS answers an empty group list; the user's own identity
        // rides in TokenUser and Everyone is implicit in the checks.
        needed = 4;
        if (info == nullptr || length < needed) {
            break;
        }
        write_u32(info, 0, 0);
        break;
    case kTokenPrivilegesClass:
        // The synthetic token holds no privileges, and the count field is
        // the honest statement of that.
        needed = 4;
        if (info == nullptr || length < needed) {
            break;
        }
        write_u32(info, 0, 0);
        break;
    case kTokenSourceClass: {
        // TOKEN_SOURCE: an 8-byte name and the logon session LUID.
        needed = 16;
        if (info == nullptr || length < needed) {
            break;
        }
        std::memset(info, 0, 16);
        std::memcpy(info, "OCC-RUN\0", 8);
        break;
    }
    case kTokenStatisticsClass: {
        needed = kTokenStatsBytes;
        if (info == nullptr || length < needed) {
            break;
        }
        std::memset(info, 0, kTokenStatsBytes);
        // Token primary, from a fixed logon session; the dynamic charge is
        // the small default a primary token carries.
        write_u32(info, 0, 1);   // TokenId
        write_u32(info, 8, 1);   // AuthenticationId
        write_u32(info, kTokenStatsTokenType, 1);  // TokenPrimary
        write_u32(info, 32, 2048);  // DynamicCharged
        write_u32(info, 36, 2048);  // DynamicAvailable
        break;
    }
    default:
        // An information class this runtime does not model is a wrong
        // question, not an empty answer.
        set_last_error(kErrorInvalidParameter);
        return 0;
    }

    if (info == nullptr || length < needed) {
        *return_length = static_cast<std::uint32_t>(needed);
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    *return_length = static_cast<std::uint32_t>(needed);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_AdjustTokenPrivileges(
    std::uint64_t token, std::int32_t disable_all, const void* new_state,
    std::uint32_t buffer_length, void* previous_state,
    std::uint32_t* return_length) noexcept {
    if (!is_token(token)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (disable_all == 0 && new_state == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // TOKEN_PRIVILEGES { DWORD count; LUID_AND_ATTRIBUTES[] } with 12-byte
    // entries: LUID low, LUID high, attributes.
    const std::uint32_t count =
        disable_all != 0 ? 0 : read_u32(new_state, 0);

    if (previous_state != nullptr) {
        if (return_length == nullptr) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        const std::size_t needed = 4 + 12ull * count;
        if (buffer_length < needed) {
            *return_length = static_cast<std::uint32_t>(needed);
            set_last_error(kErrorInsufficientBuffer);
            return 0;
        }
        write_u32(previous_state, 0, count);
        for (std::uint32_t i = 0; i < count; ++i) {
            const std::size_t at = 4 + 12ull * i;
            // The previous state of a privilege this token does not hold is
            // "absent": the LUID is echoed, the attributes are zero.
            write_u32(previous_state, at, read_u32(new_state, at));
            write_u32(previous_state, at + 4, read_u32(new_state, at + 4));
            write_u32(previous_state, at + 8, 0);
        }
        *return_length = static_cast<std::uint32_t>(needed);
    }

    // Two answers leave this call, and both are real. The return value says
    // the call itself succeeded; the last error says whether every requested
    // privilege was assigned. The token holds nothing, so an enable request
    // is never assigned -- and Windows still returns TRUE, which is the
    // behaviour the documentation names and guests depend on. A REMOVE
    // request for a privilege the token does not hold is the one hard
    // failure: ERROR_PRIVILEGE_NOT_HELD with a FALSE return.
    if (disable_all == 0) {
        for (std::uint32_t i = 0; i < count; ++i) {
            const std::uint32_t attributes =
                read_u32(new_state, 4 + 12ull * i + 8);
            if ((attributes & kSePrivilegeRemoved) != 0) {
                set_last_error(kErrorPrivilegeNotHeld);
                return 0;
            }
        }
    }
    bool all_assigned = true;
    if (disable_all == 0) {
        for (std::uint32_t i = 0; i < count; ++i) {
            const std::uint32_t attributes =
                read_u32(new_state, 4 + 12ull * i + 8);
            if ((attributes & kSePrivilegeEnabled) != 0) {
                all_assigned = false;
                break;
            }
        }
    }
    set_last_error(all_assigned ? kErrorSuccess : kErrorNotAllAssigned);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_CheckTokenMembership(
    std::uint64_t reserved, const void* sid, std::int32_t* is_member) noexcept {
    (void)reserved;
    if (is_member == nullptr || !valid_sid(sid)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The token's group list is empty and Everyone is implicit, so the
    // membership question is "this SID is the user, or it is Everyone".
    *is_member = sid_matches_subject(sid) ? 1 : 0;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_PrivilegeCheck(
    std::uint64_t token, const void* privilege_set,
    std::int32_t* has_privilege) noexcept {
    if (!is_token(token)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (privilege_set == nullptr || has_privilege == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The token holds no privileges, so every requested LUID is absent and
    // the call itself succeeds -- a FALSE result is an answer, not a failure.
    *has_privilege = 0;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_AccessCheck(
    const void* security_descriptor, std::uint64_t token,
    std::uint32_t desired_access, const void* generic_mapping,
    const void* privilege_set, std::uint32_t privilege_set_length,
    std::uint32_t* granted_access, std::int32_t* access_status) noexcept {
    if (!valid_sd(security_descriptor)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (!is_token(token)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (generic_mapping == nullptr || granted_access == nullptr ||
        access_status == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (privilege_set != nullptr && privilege_set_length < kPrivilegeSetMinimum) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }

    // No privilege exists that can add access to a mask in this runtime, so
    // the privilege set is validated and otherwise left as the caller gave
    // it; the walk below decides from the DACL alone.
    const std::uint32_t want = map_generic(desired_access, generic_mapping);

    const std::uint16_t control = read_u16(security_descriptor, kSdControl);
    const bool dacl_present = (control & kSeDaclPresent) != 0;
    const auto* dacl = reinterpret_cast<const void*>(
        read_ptr(security_descriptor, kSdDacl));

    // No DACL -- including a present-but-null one -- grants everything;
    // this is the Windows rule a caller's fallback paths depend on.
    if (!dacl_present || dacl == nullptr) {
        *granted_access = want;
        *access_status = 1;
        set_last_error(kErrorSuccess);
        return 1;
    }
    if (!valid_acl(dacl)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }

    const std::uint32_t maximum = want & kMaximumAllowed;
    const std::uint32_t effective = want & ~kMaximumAllowed;
    bool denied = false;
    const std::uint32_t accumulated =
        acl_granted_for(dacl, effective, denied);

    if (denied) {
        // A denied ACE that intersects the request stops the check: zero is
        // granted and the status says no, with a successful call -- access
        // denied is an answer, not an error.
        *granted_access = 0;
        *access_status = 0;
        set_last_error(kErrorSuccess);
        return 1;
    }
    if (maximum != 0) {
        // MAXIMUM_ALLOWED wants the best mask rather than the asked-for one;
        // with nothing allowed the status is still "no".
        *granted_access = accumulated;
        *access_status = accumulated != 0 ? 1 : 0;
        set_last_error(kErrorSuccess);
        return 1;
    }
    // A request that is not fully covered answers status FALSE with a zero
    // grant, the way the Windows spelling leaves a failed check.
    const std::uint32_t covered = accumulated & effective;
    *granted_access = covered == effective ? covered : 0;
    *access_status = covered == effective ? 1 : 0;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_SetTokenInformation(
    std::uint64_t token, std::uint32_t class_, const void* info,
    std::uint32_t length) noexcept {
    (void)class_;
    (void)info;
    (void)length;
    // There is no writable token state behind any information class: the
    // token is derived from the host identity on every read, so a write
    // would have nothing to land in and no reader to see it. Refused rather
    // than silently dropped.
    if (!is_token(token)) {
        set_last_error(kErrorInvalidHandle);
    } else {
        set_last_error(kErrorCallNotImplemented);
    }
    return 0;
}

// ===========================================================================
// User and account lookups
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t as_GetUserNameW(
    char16_t* buffer, std::uint32_t* size) noexcept {
    if (size == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::u16string name = wide_of_utf8(host_user_name());
    const std::size_t need = required_capacity(name);
    if (buffer == nullptr || *size < need) {
        // GetUserName's convention: the required size, terminator included,
        // and ERROR_INSUFFICIENT_BUFFER.
        *size = static_cast<std::uint32_t>(need);
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    if (!name.empty()) {
        std::memcpy(buffer, name.data(), name.size() * sizeof(char16_t));
    }
    buffer[name.size()] = u'\0';
    *size = static_cast<std::uint32_t>(need);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_GetUserNameA(
    char* buffer, std::uint32_t* size) noexcept {
    if (size == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string narrow;
    if (!narrow_out(wide_of_utf8(host_user_name()), narrow).converted) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    const bool written =
        write_chars_narrow(narrow, buffer, size);
    // write_chars_* reports the Lookup* convention (count without the
    // terminator on success); GetUserName reports the terminator included,
    // so the successful count is adjusted here rather than in the helper.
    if (written) {
        *size += 1;
    }
    return written ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_LookupAccountSidW(
    const void* system_name, const void* sid, char16_t* name,
    std::uint32_t* name_chars, char16_t* domain, std::uint32_t* domain_chars,
    std::uint32_t* use) noexcept {
    (void)system_name;
    if (name_chars == nullptr || domain_chars == nullptr || use == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const AccountAnswer answer = lookup_account_sid_core(sid);
    if (!answer.ok) {
        set_last_error(answer.error);
        return 0;
    }
    // Both sizes are reported even when only one buffer is short, which is
    // what lets a caller retry once instead of twice.
    const bool name_ok = write_chars_wide(answer.name, name, name_chars);
    const bool domain_ok =
        write_chars_wide(answer.domain, domain, domain_chars);
    if (!name_ok || !domain_ok) {
        return 0;
    }
    *use = answer.use;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_LookupAccountSidLocalW(
    const void* sid, char16_t* name, std::uint32_t* name_chars,
    char16_t* domain, std::uint32_t* domain_chars, std::uint32_t* use) noexcept {
    return as_LookupAccountSidW(nullptr, sid, name, name_chars, domain,
                                domain_chars, use);
}

extern "C" __attribute__((ms_abi)) std::int32_t as_LookupAccountSidA(
    const void* system_name, const void* sid, char* name,
    std::uint32_t* name_chars, char* domain, std::uint32_t* domain_chars,
    std::uint32_t* use) noexcept {
    (void)system_name;
    if (name_chars == nullptr || domain_chars == nullptr || use == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const AccountAnswer answer = lookup_account_sid_core(sid);
    if (!answer.ok) {
        set_last_error(answer.error);
        return 0;
    }
    std::string narrow_name;
    std::string narrow_domain;
    if (!narrow_out(answer.name, narrow_name).converted ||
        !narrow_out(answer.domain, narrow_domain).converted) {
        set_last_error(kErrorInvalidSid);
        return 0;
    }
    const bool name_ok =
        write_chars_narrow(narrow_name, name, name_chars);
    const bool domain_ok =
        write_chars_narrow(narrow_domain, domain, domain_chars);
    if (!name_ok || !domain_ok) {
        return 0;
    }
    *use = answer.use;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_LookupAccountSidLocalA(
    const void* sid, char* name, std::uint32_t* name_chars, char* domain,
    std::uint32_t* domain_chars, std::uint32_t* use) noexcept {
    return as_LookupAccountSidA(nullptr, sid, name, name_chars, domain,
                                domain_chars, use);
}

extern "C" __attribute__((ms_abi)) std::int32_t as_LookupAccountNameW(
    const void* system_name, const char16_t* account_name, void* sid,
    std::uint32_t* sid_length_out, char16_t* domain,
    std::uint32_t* domain_chars, std::uint32_t* use) noexcept {
    (void)system_name;
    if (account_name == nullptr || sid_length_out == nullptr ||
        domain_chars == nullptr || use == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const NameAnswer answer = lookup_account_name_core(read_wide(account_name));
    if (!answer.ok) {
        set_last_error(answer.error);
        return 0;
    }
    if (sid == nullptr || *sid_length_out < answer.sid.length) {
        *sid_length_out = answer.sid.length;
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    std::memcpy(sid, answer.sid.bytes, answer.sid.length);
    *sid_length_out = answer.sid.length;
    const bool domain_ok =
        write_chars_wide(answer.domain, domain, domain_chars);
    if (!domain_ok) {
        return 0;
    }
    *use = answer.use;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_LookupAccountNameA(
    const void* system_name, const char* account_name, void* sid,
    std::uint32_t* sid_length_out, char* domain,
    std::uint32_t* domain_chars, std::uint32_t* use) noexcept {
    (void)system_name;
    std::u16string wide;
    if (account_name == nullptr || !read_narrow(account_name, wide)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const NameAnswer answer = lookup_account_name_core(wide);
    if (!answer.ok) {
        set_last_error(answer.error);
        return 0;
    }
    if (sid == nullptr || sid_length_out == nullptr ||
        domain_chars == nullptr || use == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (sid == nullptr || *sid_length_out < answer.sid.length) {
        *sid_length_out = answer.sid.length;
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    std::memcpy(sid, answer.sid.bytes, answer.sid.length);
    *sid_length_out = answer.sid.length;
    std::string narrow_domain;
    if (!narrow_out(answer.domain, narrow_domain).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (!write_chars_narrow(narrow_domain, domain, domain_chars)) {
        return 0;
    }
    *use = answer.use;
    set_last_error(kErrorSuccess);
    return 1;
}

// ===========================================================================
// Privilege name / LUID lookups
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t as_LookupPrivilegeValueW(
    const void* system_name, const char16_t* name, void* luid) noexcept {
    (void)system_name;
    if (name == nullptr || luid == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const PrivilegeEntry* entry = privilege_by_name(read_wide(name));
    if (entry == nullptr) {
        set_last_error(kErrorNoSuchPrivilege);
        return 0;
    }
    write_u32(luid, 0, entry->value);
    write_u32(luid, 4, 0);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_LookupPrivilegeValueA(
    const void* system_name, const char* name, void* luid) noexcept {
    std::u16string wide;
    if (name == nullptr || luid == nullptr || !read_narrow(name, wide)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return as_LookupPrivilegeValueW(system_name, wide.c_str(), luid);
}

extern "C" __attribute__((ms_abi)) std::int32_t as_LookupPrivilegeNameW(
    const void* system_name, std::uint32_t luid_low, std::uint32_t luid_high,
    char16_t* buffer, std::uint32_t* chars) noexcept {
    (void)system_name;
    if (chars == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const PrivilegeEntry* entry = privilege_by_luid(luid_low, luid_high);
    if (entry == nullptr) {
        set_last_error(kErrorNoSuchPrivilege);
        return 0;
    }
    const std::u16string name = wide_of_utf8(entry->name);
    if (!write_chars_wide(name, buffer, chars)) {
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_LookupPrivilegeNameA(
    const void* system_name, std::uint32_t luid_low, std::uint32_t luid_high,
    char* buffer, std::uint32_t* chars) noexcept {
    (void)system_name;
    if (chars == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const PrivilegeEntry* entry = privilege_by_luid(luid_low, luid_high);
    if (entry == nullptr) {
        set_last_error(kErrorNoSuchPrivilege);
        return 0;
    }
    if (!write_chars_narrow(entry->name, buffer, chars)) {
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_LookupPrivilegeDisplayNameW(
    const void* system_name, const char16_t* name, char16_t* buffer,
    std::uint32_t* chars, std::uint32_t* language_id) noexcept {
    (void)system_name;
    if (name == nullptr || chars == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const PrivilegeEntry* entry = privilege_by_name(read_wide(name));
    if (entry == nullptr) {
        set_last_error(kErrorNoSuchPrivilege);
        return 0;
    }
    const std::u16string display = wide_of_utf8(entry->display);
    if (!write_chars_wide(display, buffer, chars)) {
        return 0;
    }
    if (language_id != nullptr) {
        *language_id = kLangIdUsEnglish;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_LookupPrivilegeDisplayNameA(
    const void* system_name, const char* name, char* buffer,
    std::uint32_t* chars, std::uint32_t* language_id) noexcept {
    (void)system_name;
    if (name == nullptr || chars == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string wide;
    if (!read_narrow(name, wide)) {
        set_last_error(kErrorNoSuchPrivilege);
        return 0;
    }
    const PrivilegeEntry* entry = privilege_by_name(wide);
    if (entry == nullptr) {
        set_last_error(kErrorNoSuchPrivilege);
        return 0;
    }
    if (!write_chars_narrow(entry->display, buffer, chars)) {
        return 0;
    }
    if (language_id != nullptr) {
        *language_id = kLangIdUsEnglish;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

// ===========================================================================
// Security descriptors
// ===========================================================================

namespace {

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t as_InitializeSecurityDescriptor(
    void* descriptor, std::uint32_t revision) noexcept {
    if (descriptor == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (revision != kSidRevisionValue) {
        // SECURITY_DESCRIPTOR_REVISION is the only revision this structure
        // has ever had; a caller asking for another is asking for a format
        // that does not exist.
        set_last_error(kErrorUnknownRevision);
        return 0;
    }
    auto* bytes = static_cast<std::uint8_t*>(descriptor);
    bytes[kSdRevision] = kSidRevisionValue;
    bytes[1] = 0;
    write_u16(descriptor, kSdControl, 0);
    write_ptr(descriptor, kSdOwner, 0);
    write_ptr(descriptor, kSdGroup, 0);
    write_ptr(descriptor, kSdSacl, 0);
    write_ptr(descriptor, kSdDacl, 0);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_SetSecurityDescriptorOwner(
    void* descriptor, const void* owner, std::int32_t defaulted) noexcept {
    if (!valid_sd(descriptor)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    write_ptr(descriptor, kSdOwner, reinterpret_cast<std::uint64_t>(owner));
    std::uint16_t control = read_u16(descriptor, kSdControl);
    if (defaulted != 0) {
        control |= kSeOwnerDefaulted;
    } else {
        control &= static_cast<std::uint16_t>(~kSeOwnerDefaulted);
    }
    write_u16(descriptor, kSdControl, control);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_GetSecurityDescriptorOwner(
    const void* descriptor, const void** owner, std::int32_t* defaulted) noexcept {
    if (!valid_sd(descriptor) || owner == nullptr || defaulted == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    *owner = reinterpret_cast<const void*>(read_ptr(descriptor, kSdOwner));
    *defaulted =
        (read_u16(descriptor, kSdControl) & kSeOwnerDefaulted) != 0 ? 1 : 0;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_SetSecurityDescriptorGroup(
    void* descriptor, const void* group, std::int32_t defaulted) noexcept {
    if (!valid_sd(descriptor)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    write_ptr(descriptor, kSdGroup, reinterpret_cast<std::uint64_t>(group));
    std::uint16_t control = read_u16(descriptor, kSdControl);
    if (defaulted != 0) {
        control |= kSeGroupDefaulted;
    } else {
        control &= static_cast<std::uint16_t>(~kSeGroupDefaulted);
    }
    write_u16(descriptor, kSdControl, control);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_GetSecurityDescriptorGroup(
    const void* descriptor, const void** group, std::int32_t* defaulted) noexcept {
    if (!valid_sd(descriptor) || group == nullptr || defaulted == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    *group = reinterpret_cast<const void*>(read_ptr(descriptor, kSdGroup));
    *defaulted =
        (read_u16(descriptor, kSdControl) & kSeGroupDefaulted) != 0 ? 1 : 0;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_SetSecurityDescriptorDacl(
    void* descriptor, std::int32_t present, const void* dacl,
    std::int32_t defaulted) noexcept {
    if (!valid_sd(descriptor)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // A null DACL with present set is a real state -- "no restriction" --
    // and is different from a cleared present bit, which is "inherit";
    // both the pointer and the control bit carry the distinction.
    write_ptr(descriptor, kSdDacl,
              present != 0 ? reinterpret_cast<std::uint64_t>(dacl) : 0);
    std::uint16_t control = read_u16(descriptor, kSdControl);
    if (present != 0) {
        control |= kSeDaclPresent;
    } else {
        control &= static_cast<std::uint16_t>(~kSeDaclPresent);
    }
    if (defaulted != 0) {
        control |= kSeDaclDefaulted;
    } else {
        control &= static_cast<std::uint16_t>(~kSeDaclDefaulted);
    }
    write_u16(descriptor, kSdControl, control);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_GetSecurityDescriptorDacl(
    const void* descriptor, std::int32_t* present, const void** dacl,
    std::int32_t* defaulted) noexcept {
    if (!valid_sd(descriptor) || present == nullptr || dacl == nullptr ||
        defaulted == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint16_t control = read_u16(descriptor, kSdControl);
    *present = (control & kSeDaclPresent) != 0 ? 1 : 0;
    *dacl = reinterpret_cast<const void*>(read_ptr(descriptor, kSdDacl));
    *defaulted = (control & kSeDaclDefaulted) != 0 ? 1 : 0;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_SetSecurityDescriptorSacl(
    void* descriptor, std::int32_t present, const void* sacl,
    std::int32_t defaulted) noexcept {
    if (!valid_sd(descriptor)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    write_ptr(descriptor, kSdSacl,
              present != 0 ? reinterpret_cast<std::uint64_t>(sacl) : 0);
    std::uint16_t control = read_u16(descriptor, kSdControl);
    if (present != 0) {
        control |= kSeSaclPresent;
    } else {
        control &= static_cast<std::uint16_t>(~kSeSaclPresent);
    }
    if (defaulted != 0) {
        control |= kSeSaclDefaulted;
    } else {
        control &= static_cast<std::uint16_t>(~kSeSaclDefaulted);
    }
    write_u16(descriptor, kSdControl, control);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_GetSecurityDescriptorSacl(
    const void* descriptor, std::int32_t* present, const void** sacl,
    std::int32_t* defaulted) noexcept {
    if (!valid_sd(descriptor) || present == nullptr || sacl == nullptr ||
        defaulted == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint16_t control = read_u16(descriptor, kSdControl);
    *present = (control & kSeSaclPresent) != 0 ? 1 : 0;
    *sacl = reinterpret_cast<const void*>(read_ptr(descriptor, kSdSacl));
    *defaulted = (control & kSeSaclDefaulted) != 0 ? 1 : 0;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_SetSecurityDescriptorControl(
    void* descriptor, std::uint16_t control_mask,
    std::uint16_t control_bits) noexcept {
    if (!valid_sd(descriptor)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint16_t control = read_u16(descriptor, kSdControl);
    const std::uint16_t updated = static_cast<std::uint16_t>(
        (control & static_cast<std::uint16_t>(~control_mask)) |
        (control_bits & control_mask));
    write_u16(descriptor, kSdControl, updated);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_GetSecurityDescriptorControl(
    const void* descriptor, std::uint16_t* control,
    std::uint32_t* revision) noexcept {
    if (!valid_sd(descriptor) || control == nullptr || revision == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    *control = read_u16(descriptor, kSdControl);
    *revision = static_cast<const std::uint8_t*>(descriptor)[kSdRevision];
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint32_t as_GetSecurityDescriptorLength(
    const void* descriptor) noexcept {
    // The non-relative form is a fixed 40 bytes; a descriptor this runtime
    // did not initialise answers 0 rather than a length it cannot stand
    // behind.
    return valid_sd(descriptor) ? kSdBytes : 0;
}

// ===========================================================================
// ACLs
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t as_InitializeAcl(
    void* acl, std::uint32_t length, std::uint32_t revision) noexcept {
    if (acl == nullptr ||
        (revision != kAclRevisionValue && revision != kAclRevisionDsValue)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (length < kAclHeaderBytes) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    auto* bytes = static_cast<std::uint8_t*>(acl);
    bytes[kAclRevision] = static_cast<std::uint8_t>(revision);
    bytes[1] = 0;
    write_u16(acl, kAclSize, static_cast<std::uint16_t>(length));
    write_u16(acl, kAclCount, 0);
    write_u16(acl, 6, 0);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_AddAccessAllowedAceEx(
    void* acl, std::uint32_t revision, std::uint32_t flags, std::uint32_t mask,
    const void* sid) noexcept {
    if (!valid_acl(acl) || !valid_sid(sid)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The requested revision must be what the ACL already is; an ACL does
    // not change format because an ACE was appended to it.
    if (revision != static_cast<std::uint8_t*>(acl)[kAclRevision]) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    bool formed = false;
    const std::size_t end = acl_end_offset(acl, formed);
    const std::size_t capacity = read_u16(acl, kAclSize);
    const std::size_t needed = kAceSid + sid_length(sid);
    // An ACL is preallocated by InitializeAcl and never grows; a caller that
    // sized it too small gets the parameter error rather than a write past
    // the buffer it owns.
    if (!formed || capacity < end || capacity - end < needed) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    auto* ace = static_cast<std::uint8_t*>(acl) + end;
    ace[0] = kAceTypeAllowed;
    ace[1] = static_cast<std::uint8_t>(flags);
    write_u16(ace, kAceSize, static_cast<std::uint16_t>(needed));
    write_u32(ace, kAceMask, mask);
    std::memcpy(ace + kAceSid, sid, sid_length(sid));
    write_u16(acl, kAclCount, static_cast<std::uint16_t>(read_u16(acl, kAclCount) + 1));
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_AddAccessAllowedAce(
    void* acl, std::uint32_t revision, std::uint32_t mask,
    const void* sid) noexcept {
    return as_AddAccessAllowedAceEx(acl, revision, 0, mask, sid);
}

extern "C" __attribute__((ms_abi)) std::int32_t as_GetAce(
    const void* acl, std::uint32_t index, void** ace) noexcept {
    if (!valid_acl(acl) || ace == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::size_t count = read_u16(acl, kAclCount);
    if (index >= count) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::size_t pos = kAclHeaderBytes;
    for (std::size_t i = 0; i < index; ++i) {
        pos += read_u16(acl, pos + kAceSize);
    }
    *ace = static_cast<std::uint8_t*>(const_cast<void*>(acl)) + pos;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_FindFirstFreeAce(
    const void* acl, void** ace) noexcept {
    if (!valid_acl(acl) || ace == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    bool formed = false;
    const std::size_t end = acl_end_offset(acl, formed);
    if (!formed || end > read_u16(acl, kAclSize)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // "First free" is an address, not a guarantee that anything fits: a
    // full ACL still points at its end, and the caller compares before
    // writing -- exactly as the Windows spelling behaves.
    *ace = static_cast<std::uint8_t*>(const_cast<void*>(acl)) + end;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_GetAclInformation(
    const void* acl, void* information, std::uint32_t size,
    std::uint32_t class_) noexcept {
    if (!valid_acl(acl) || information == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    switch (class_) {
    case 1:  // AclRevisionInformation
        if (size < 4) {
            set_last_error(kErrorInsufficientBuffer);
            return 0;
        }
        write_u32(information, 0,
                  static_cast<std::uint8_t*>(const_cast<void*>(acl))[kAclRevision]);
        break;
    case 2:  // AclSizeInformation
        if (size < 8) {
            set_last_error(kErrorInsufficientBuffer);
            return 0;
        }
        write_u32(information, 0, read_u16(acl, kAclSize));
        write_u32(information, 4, read_u16(acl, kAclCount));
        break;
    default:
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t as_AreAllAccessesGranted(
    std::uint32_t granted, std::uint32_t desired) noexcept {
    return (granted & desired) == desired ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) void as_MapGenericMask(
    std::uint32_t* access_mask, const void* generic_mapping) noexcept {
    if (access_mask == nullptr || generic_mapping == nullptr) {
        return;
    }
    *access_mask = map_generic(*access_mask, generic_mapping);
}

namespace {

// Resolves a TRUSTEE to the SID it names, following the impersonation chain
// the structure allows. The answer is either a SID the caller already owns
// or one built into `storage`.
[[nodiscard]] std::uint32_t resolve_trustee_wide(const void* trustee,
                                                 SidBuffer& storage,
                                                 const void*& sid) noexcept {
    const void* current = trustee;
    // pMultipleTrustee + TRUSTEE_IS_IMPERSONATE names the trustee the
    // access question is really about.
    while (read_ptr(current, kTrusteeMultiple) != 0 &&
           read_u32(current, kTrusteeMultipleOp) == kTrusteeIsImpersonate) {
        current = reinterpret_cast<const void*>(
            read_ptr(current, kTrusteeMultiple));
    }
    switch (read_u32(current, kTrusteeForm)) {
    case kTrusteeFormIsSid: {
        const auto* candidate = reinterpret_cast<const void*>(
            read_ptr(current, kTrusteeName));
        if (!valid_sid(candidate)) {
            return kErrorInvalidParameter;
        }
        sid = candidate;
        return kErrorSuccess;
    }
    case kTrusteeFormIsName: {
        const auto* name = reinterpret_cast<const char16_t*>(
            read_ptr(current, kTrusteeName));
        const NameAnswer answer = lookup_account_name_core(read_wide(name));
        if (!answer.ok) {
            return answer.error;
        }
        storage = answer.sid;
        sid = storage.bytes;
        return kErrorSuccess;
    }
    default:
        return kErrorInvalidParameter;
    }
}

[[nodiscard]] std::uint32_t resolve_trustee_narrow(const void* trustee,
                                                   SidBuffer& storage,
                                                   const void*& sid) noexcept {
    const void* current = trustee;
    while (read_ptr(current, kTrusteeMultiple) != 0 &&
           read_u32(current, kTrusteeMultipleOp) == kTrusteeIsImpersonate) {
        current = reinterpret_cast<const void*>(
            read_ptr(current, kTrusteeMultiple));
    }
    switch (read_u32(current, kTrusteeForm)) {
    case kTrusteeFormIsSid: {
        const auto* candidate = reinterpret_cast<const void*>(
            read_ptr(current, kTrusteeName));
        if (!valid_sid(candidate)) {
            return kErrorInvalidParameter;
        }
        sid = candidate;
        return kErrorSuccess;
    }
    case kTrusteeFormIsName: {
        const auto* name =
            reinterpret_cast<const char*>(read_ptr(current, kTrusteeName));
        std::u16string wide;
        if (!read_narrow(name, wide)) {
            return kErrorNoneMapped;
        }
        const NameAnswer answer = lookup_account_name_core(wide);
        if (!answer.ok) {
            return answer.error;
        }
        storage = answer.sid;
        sid = storage.bytes;
        return kErrorSuccess;
    }
    default:
        return kErrorInvalidParameter;
    }
}

// The net rights a DACL gives `sid`: allowed bits accumulate, matching
// denied bits subtract as the walk meets them, in ACE order.
[[nodiscard]] std::uint32_t effective_rights_for(const void* acl,
                                                 const void* sid) noexcept {
    std::uint32_t rights = 0;
    const std::size_t count = read_u16(acl, kAclCount);
    std::size_t pos = kAclHeaderBytes;
    for (std::size_t i = 0; i < count; ++i) {
        const std::size_t size = read_u16(acl, pos + kAceSize);
        if (size < kAceSid) {
            break;
        }
        const auto* ace = static_cast<const std::uint8_t*>(acl) + pos;
        const std::uint8_t type = ace[0];
        if (type == kAceTypeAllowed || type == kAceTypeDenied) {
            const std::uint32_t mask = read_u32(ace, kAceMask);
            const void* ace_sid = ace + kAceSid;
            if (valid_sid(ace_sid) &&
                (sid_equals(ace_sid, sid) || sid_matches_subject(ace_sid))) {
                if (type == kAceTypeAllowed) {
                    rights |= mask;
                } else {
                    rights &= ~mask;
                }
            }
        }
        pos += size;
    }
    return rights;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t as_GetEffectiveRightsFromAclW(
    const void* acl, const void* trustee, std::uint32_t* mask) noexcept {
    if (!valid_acl(acl) || trustee == nullptr || mask == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return kErrorInvalidParameter;
    }
    SidBuffer storage;
    const void* sid = nullptr;
    const std::uint32_t status = resolve_trustee_wide(trustee, storage, sid);
    if (status != kErrorSuccess) {
        set_last_error(status);
        return status;
    }
    *mask = effective_rights_for(acl, sid);
    set_last_error(kErrorSuccess);
    return kErrorSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t as_GetEffectiveRightsFromAclA(
    const void* acl, const void* trustee, std::uint32_t* mask) noexcept {
    if (!valid_acl(acl) || trustee == nullptr || mask == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return kErrorInvalidParameter;
    }
    SidBuffer storage;
    const void* sid = nullptr;
    const std::uint32_t status = resolve_trustee_narrow(trustee, storage, sid);
    if (status != kErrorSuccess) {
        set_last_error(status);
        return status;
    }
    *mask = effective_rights_for(acl, sid);
    set_last_error(kErrorSuccess);
    return kErrorSuccess;
}

// ===========================================================================
// Explicit refusals
// ===========================================================================
//
// Each group below needs a subsystem this runtime does not run: the service
// control manager, an authentication stack, or a real SDDL grammar. The
// refusal is ERROR_CALL_NOT_IMPLEMENTED with a failure return -- the same
// answer Windows gives for its own unimplemented surface, and a better
// neighbour than a success no object backs.

namespace {

[[nodiscard]] std::int32_t refused_bool() noexcept {
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

[[nodiscard]] std::uint32_t refused_dword() noexcept {
    set_last_error(kErrorCallNotImplemented);
    return kErrorCallNotImplemented;
}

[[nodiscard]] std::uint64_t refused_handle() noexcept {
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

}  // namespace

// ---- service control ------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint64_t as_OpenSCManagerW(
    const void*, const void*, std::uint32_t) noexcept {
    return refused_handle();
}

extern "C" __attribute__((ms_abi)) std::uint64_t as_OpenSCManagerA(
    const void*, const void*, std::uint32_t) noexcept {
    return refused_handle();
}

extern "C" __attribute__((ms_abi)) std::uint64_t as_CreateServiceW(
    std::uint64_t, const void*, const void*, std::uint32_t, std::uint32_t,
    std::uint32_t, std::uint32_t, const void*, const void*, const void*,
    const void*, const void*) noexcept {
    return refused_handle();
}

extern "C" __attribute__((ms_abi)) std::uint64_t as_CreateServiceA(
    std::uint64_t, const void*, const void*, std::uint32_t, std::uint32_t,
    std::uint32_t, std::uint32_t, const void*, const void*, const void*,
    const void*, const void*) noexcept {
    return refused_handle();
}

extern "C" __attribute__((ms_abi)) std::uint64_t as_OpenServiceW(
    std::uint64_t, const void*, std::uint32_t) noexcept {
    return refused_handle();
}

extern "C" __attribute__((ms_abi)) std::uint64_t as_OpenServiceA(
    std::uint64_t, const void*, std::uint32_t) noexcept {
    return refused_handle();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_StartServiceW(
    std::uint64_t, std::uint32_t, const void*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_StartServiceA(
    std::uint64_t, std::uint32_t, const void*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_ControlService(
    std::uint64_t, std::uint32_t, void*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_DeleteService(
    std::uint64_t) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_QueryServiceConfigW(
    std::uint64_t, void*, std::uint32_t, std::uint32_t*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_QueryServiceConfigA(
    std::uint64_t, void*, std::uint32_t, std::uint32_t*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_QueryServiceConfig2W(
    std::uint64_t, std::uint32_t, void*, std::uint32_t, std::uint32_t*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_QueryServiceConfig2A(
    std::uint64_t, std::uint32_t, void*, std::uint32_t, std::uint32_t*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_QueryServiceLockStatusW(
    std::uint64_t, void*, std::uint32_t, std::uint32_t*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_QueryServiceLockStatusA(
    std::uint64_t, void*, std::uint32_t, std::uint32_t*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_QueryServiceObjectSecurity(
    std::uint64_t, std::uint32_t, void*, std::uint32_t, std::uint32_t*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_QueryServiceStatus(
    std::uint64_t, void*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_QueryServiceStatusEx(
    std::uint64_t, std::uint32_t, void*, std::uint32_t, std::uint32_t*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_EnumServicesStatusW(
    std::uint64_t, std::uint32_t, std::uint32_t, void*, std::uint32_t,
    std::uint32_t*, std::uint32_t*, std::uint32_t*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_EnumServicesStatusA(
    std::uint64_t, std::uint32_t, std::uint32_t, void*, std::uint32_t,
    std::uint32_t*, std::uint32_t*, std::uint32_t*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_EnumServicesStatusExW(
    std::uint64_t, std::uint32_t, std::uint32_t, std::uint32_t, void*,
    std::uint32_t, std::uint32_t*, std::uint32_t*, std::uint32_t*,
    const void*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_EnumServicesStatusExA(
    std::uint64_t, std::uint32_t, std::uint32_t, std::uint32_t, void*,
    std::uint32_t, std::uint32_t*, std::uint32_t*, std::uint32_t*,
    const void*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_CloseServiceHandle(
    std::uint64_t) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_StartServiceCtrlDispatcherW(
    const void*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_StartServiceCtrlDispatcherA(
    const void*) noexcept {
    return refused_bool();
}

// ---- impersonation and logon ----------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t as_LogonUserW(
    const void*, const void*, const void*, std::uint32_t, std::uint32_t,
    std::uint64_t*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_LogonUserA(
    const void*, const void*, const void*, std::uint32_t, std::uint32_t,
    std::uint64_t*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_ImpersonateSelf(
    std::uint32_t) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_ImpersonateAnonymousToken(
    std::uint64_t) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_ImpersonateLoggedOnUser(
    std::uint64_t) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_ImpersonateNamedPipeClient(
    std::uint64_t) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t as_RevertToSelf() noexcept {
    return refused_bool();
}

// ---- SDDL and ACL editing -------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t
as_ConvertStringSecurityDescriptorToSecurityDescriptorW(
    const void*, std::uint32_t, void**, std::uint32_t*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::int32_t
as_ConvertStringSecurityDescriptorToSecurityDescriptorA(
    const void*, std::uint32_t, void**, std::uint32_t*) noexcept {
    return refused_bool();
}

extern "C" __attribute__((ms_abi)) std::uint32_t as_SetEntriesInAclW(
    std::uint32_t, const void*, const void*, void**) noexcept {
    return refused_dword();
}

extern "C" __attribute__((ms_abi)) std::uint32_t as_SetEntriesInAclA(
    std::uint32_t, const void*, const void*, void**) noexcept {
    return refused_dword();
}

// ---- object security ------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint32_t as_GetSecurityInfo(
    std::uint64_t, std::uint32_t, std::uint32_t, const void**, const void**,
    const void**, const void**, const void**) noexcept {
    return refused_dword();
}

extern "C" __attribute__((ms_abi)) std::uint32_t as_SetSecurityInfo(
    std::uint64_t, std::uint32_t, std::uint32_t, const void*, const void*,
    const void*, const void*) noexcept {
    return refused_dword();
}

// ===========================================================================
// Registration
// ===========================================================================

void add_advapi32_sec(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("AccessCheck", reinterpret_cast<void*>(&as_AccessCheck));
    e("AddAccessAllowedAce", reinterpret_cast<void*>(&as_AddAccessAllowedAce));
    e("AddAccessAllowedAceEx",
      reinterpret_cast<void*>(&as_AddAccessAllowedAceEx));
    e("AdjustTokenPrivileges",
      reinterpret_cast<void*>(&as_AdjustTokenPrivileges));
    e("AllocateAndInitializeSid",
      reinterpret_cast<void*>(&as_AllocateAndInitializeSid));
    e("AreAllAccessesGranted",
      reinterpret_cast<void*>(&as_AreAllAccessesGranted));
    e("CheckTokenMembership",
      reinterpret_cast<void*>(&as_CheckTokenMembership));
    e("CloseServiceHandle", reinterpret_cast<void*>(&as_CloseServiceHandle));
    e("ControlService", reinterpret_cast<void*>(&as_ControlService));
    e("ConvertSidToStringSidA",
      reinterpret_cast<void*>(&as_ConvertSidToStringSidA));
    e("ConvertSidToStringSidW",
      reinterpret_cast<void*>(&as_ConvertSidToStringSidW));
    e("ConvertStringSecurityDescriptorToSecurityDescriptorA",
      reinterpret_cast<void*>(
          &as_ConvertStringSecurityDescriptorToSecurityDescriptorA));
    e("ConvertStringSecurityDescriptorToSecurityDescriptorW",
      reinterpret_cast<void*>(
          &as_ConvertStringSecurityDescriptorToSecurityDescriptorW));
    e("ConvertStringSidToSidA",
      reinterpret_cast<void*>(&as_ConvertStringSidToSidA));
    e("ConvertStringSidToSidW",
      reinterpret_cast<void*>(&as_ConvertStringSidToSidW));
    e("CopySid", reinterpret_cast<void*>(&as_CopySid));
    e("CreateServiceA", reinterpret_cast<void*>(&as_CreateServiceA));
    e("CreateServiceW", reinterpret_cast<void*>(&as_CreateServiceW));
    e("DeleteService", reinterpret_cast<void*>(&as_DeleteService));
    e("EnumServicesStatusA", reinterpret_cast<void*>(&as_EnumServicesStatusA));
    e("EnumServicesStatusExA",
      reinterpret_cast<void*>(&as_EnumServicesStatusExA));
    e("EnumServicesStatusExW",
      reinterpret_cast<void*>(&as_EnumServicesStatusExW));
    e("EnumServicesStatusW", reinterpret_cast<void*>(&as_EnumServicesStatusW));
    e("EqualSid", reinterpret_cast<void*>(&as_EqualSid));
    e("FindFirstFreeAce", reinterpret_cast<void*>(&as_FindFirstFreeAce));
    e("FreeSid", reinterpret_cast<void*>(&as_FreeSid));
    e("GetAce", reinterpret_cast<void*>(&as_GetAce));
    e("GetAclInformation", reinterpret_cast<void*>(&as_GetAclInformation));
    e("GetEffectiveRightsFromAclA",
      reinterpret_cast<void*>(&as_GetEffectiveRightsFromAclA));
    e("GetEffectiveRightsFromAclW",
      reinterpret_cast<void*>(&as_GetEffectiveRightsFromAclW));
    e("GetLengthSid", reinterpret_cast<void*>(&as_GetLengthSid));
    e("GetSecurityDescriptorControl",
      reinterpret_cast<void*>(&as_GetSecurityDescriptorControl));
    e("GetSecurityDescriptorDacl",
      reinterpret_cast<void*>(&as_GetSecurityDescriptorDacl));
    e("GetSecurityDescriptorGroup",
      reinterpret_cast<void*>(&as_GetSecurityDescriptorGroup));
    e("GetSecurityDescriptorLength",
      reinterpret_cast<void*>(&as_GetSecurityDescriptorLength));
    e("GetSecurityDescriptorOwner",
      reinterpret_cast<void*>(&as_GetSecurityDescriptorOwner));
    e("GetSecurityDescriptorSacl",
      reinterpret_cast<void*>(&as_GetSecurityDescriptorSacl));
    e("GetSecurityInfo", reinterpret_cast<void*>(&as_GetSecurityInfo));
    e("GetSidIdentifierAuthority",
      reinterpret_cast<void*>(&as_GetSidIdentifierAuthority));
    e("GetSidLengthRequired", reinterpret_cast<void*>(&as_GetSidLengthRequired));
    e("GetSidSubAuthority", reinterpret_cast<void*>(&as_GetSidSubAuthority));
    e("GetSidSubAuthorityCount",
      reinterpret_cast<void*>(&as_GetSidSubAuthorityCount));
    e("GetTokenInformation", reinterpret_cast<void*>(&as_GetTokenInformation));
    e("GetUserNameA", reinterpret_cast<void*>(&as_GetUserNameA));
    e("GetUserNameW", reinterpret_cast<void*>(&as_GetUserNameW));
    e("ImpersonateAnonymousToken",
      reinterpret_cast<void*>(&as_ImpersonateAnonymousToken));
    e("ImpersonateLoggedOnUser",
      reinterpret_cast<void*>(&as_ImpersonateLoggedOnUser));
    e("ImpersonateNamedPipeClient",
      reinterpret_cast<void*>(&as_ImpersonateNamedPipeClient));
    e("ImpersonateSelf", reinterpret_cast<void*>(&as_ImpersonateSelf));
    e("InitializeAcl", reinterpret_cast<void*>(&as_InitializeAcl));
    e("InitializeSecurityDescriptor",
      reinterpret_cast<void*>(&as_InitializeSecurityDescriptor));
    e("IsValidSid", reinterpret_cast<void*>(&as_IsValidSid));
    e("LogonUserA", reinterpret_cast<void*>(&as_LogonUserA));
    e("LogonUserW", reinterpret_cast<void*>(&as_LogonUserW));
    e("LookupAccountNameA", reinterpret_cast<void*>(&as_LookupAccountNameA));
    e("LookupAccountNameW", reinterpret_cast<void*>(&as_LookupAccountNameW));
    e("LookupAccountSidA", reinterpret_cast<void*>(&as_LookupAccountSidA));
    e("LookupAccountSidLocalA",
      reinterpret_cast<void*>(&as_LookupAccountSidLocalA));
    e("LookupAccountSidLocalW",
      reinterpret_cast<void*>(&as_LookupAccountSidLocalW));
    e("LookupAccountSidW", reinterpret_cast<void*>(&as_LookupAccountSidW));
    e("LookupPrivilegeDisplayNameA",
      reinterpret_cast<void*>(&as_LookupPrivilegeDisplayNameA));
    e("LookupPrivilegeDisplayNameW",
      reinterpret_cast<void*>(&as_LookupPrivilegeDisplayNameW));
    e("LookupPrivilegeNameA", reinterpret_cast<void*>(&as_LookupPrivilegeNameA));
    e("LookupPrivilegeNameW", reinterpret_cast<void*>(&as_LookupPrivilegeNameW));
    e("LookupPrivilegeValueA", reinterpret_cast<void*>(&as_LookupPrivilegeValueA));
    e("LookupPrivilegeValueW", reinterpret_cast<void*>(&as_LookupPrivilegeValueW));
    e("MapGenericMask", reinterpret_cast<void*>(&as_MapGenericMask));
    e("OpenProcessToken", reinterpret_cast<void*>(&as_OpenProcessToken));
    e("OpenSCManagerA", reinterpret_cast<void*>(&as_OpenSCManagerA));
    e("OpenSCManagerW", reinterpret_cast<void*>(&as_OpenSCManagerW));
    e("OpenServiceA", reinterpret_cast<void*>(&as_OpenServiceA));
    e("OpenServiceW", reinterpret_cast<void*>(&as_OpenServiceW));
    e("OpenThreadToken", reinterpret_cast<void*>(&as_OpenThreadToken));
    e("PrivilegeCheck", reinterpret_cast<void*>(&as_PrivilegeCheck));
    e("QueryServiceConfig2A", reinterpret_cast<void*>(&as_QueryServiceConfig2A));
    e("QueryServiceConfig2W", reinterpret_cast<void*>(&as_QueryServiceConfig2W));
    e("QueryServiceConfigA", reinterpret_cast<void*>(&as_QueryServiceConfigA));
    e("QueryServiceConfigW", reinterpret_cast<void*>(&as_QueryServiceConfigW));
    e("QueryServiceLockStatusA",
      reinterpret_cast<void*>(&as_QueryServiceLockStatusA));
    e("QueryServiceLockStatusW",
      reinterpret_cast<void*>(&as_QueryServiceLockStatusW));
    e("QueryServiceObjectSecurity",
      reinterpret_cast<void*>(&as_QueryServiceObjectSecurity));
    e("QueryServiceStatus", reinterpret_cast<void*>(&as_QueryServiceStatus));
    e("QueryServiceStatusEx", reinterpret_cast<void*>(&as_QueryServiceStatusEx));
    e("RevertToSelf", reinterpret_cast<void*>(&as_RevertToSelf));
    e("SetEntriesInAclA", reinterpret_cast<void*>(&as_SetEntriesInAclA));
    e("SetEntriesInAclW", reinterpret_cast<void*>(&as_SetEntriesInAclW));
    e("SetSecurityDescriptorControl",
      reinterpret_cast<void*>(&as_SetSecurityDescriptorControl));
    e("SetSecurityDescriptorDacl",
      reinterpret_cast<void*>(&as_SetSecurityDescriptorDacl));
    e("SetSecurityDescriptorGroup",
      reinterpret_cast<void*>(&as_SetSecurityDescriptorGroup));
    e("SetSecurityDescriptorOwner",
      reinterpret_cast<void*>(&as_SetSecurityDescriptorOwner));
    e("SetSecurityDescriptorSacl",
      reinterpret_cast<void*>(&as_SetSecurityDescriptorSacl));
    e("SetSecurityInfo", reinterpret_cast<void*>(&as_SetSecurityInfo));
    e("SetTokenInformation", reinterpret_cast<void*>(&as_SetTokenInformation));
    e("StartServiceA", reinterpret_cast<void*>(&as_StartServiceA));
    e("StartServiceCtrlDispatcherA",
      reinterpret_cast<void*>(&as_StartServiceCtrlDispatcherA));
    e("StartServiceCtrlDispatcherW",
      reinterpret_cast<void*>(&as_StartServiceCtrlDispatcherW));
    e("StartServiceW", reinterpret_cast<void*>(&as_StartServiceW));
}

}  // namespace occ::runtime::winabi

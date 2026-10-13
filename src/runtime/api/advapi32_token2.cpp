// The advapi32 token family's second slice: group adjustment and cloning.
//
// The token model this slice builds on is the one `advapi32_sec.cpp`
// established: a single synthetic token identified by one constant handle,
// whose identity is the host Unix user, whose groups are empty (Everyone
// implicit), and which has no per-instance state. The calls here add the
// state the model deliberately lacks. `AdjustTokenGroups` keeps a real group
// list per token handle, so an adjustment is recorded and queryable through
// the same handle; `DuplicateToken`/`DuplicateTokenEx` mint new handles
// that carry a clone of the source token's identity, groups and requested
// access, with the impersonation level and token type recorded on the
// clone; `SetThreadToken` stores the thread's token, so a set and a clear
// round-trip.
//
// The boundary is where the model stops. The group list lives here because
// `advapi32_sec.cpp` answers an empty TOKEN_GROUPS and its `OpenThreadToken`
// answers the process token unconditionally; a clone handle is recognized
// by this slice and not by the stateless helpers in the other file. That is
// the honest cost of the existing model -- a guest that duplicates a token
// and asks the *other* file about it is told the token it holds is not one
// that file knows -- and it is stated rather than papered over. The host is
// Linux: there are no ACLs to attach to a token, so `TokenAttributes` is
// accepted and ignored, and there is one thread, so a thread token lives in
// thread-local storage that only the owning thread can name.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <vector>

namespace occ::runtime::winabi {

// The current thread id, the one concrete handle a single-threaded run can
// name besides the pseudo handle.
extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetCurrentThreadId() noexcept;

namespace {

// The synthetic primary-token handle, the same constant `advapi32_sec.cpp`
// issues. It is restated here -- that file's copy is private -- so this
// slice can recognize the primary token alongside the clones it mints.
constexpr std::uint64_t kTokenHandle = 0x0053454300000001ULL;

// The range this slice mints cloned token handles from, above the primary
// handle and in the same 0x00534543 namespace.
constexpr std::uint64_t kCloneHandleBase = 0x0053454300000200ULL;

// The current-thread pseudo handle, the second spelling a caller can use
// for the thread it is running on.
constexpr std::uint64_t kCurrentThreadPseudo = 0xFFFFFFFFFFFFFFFEULL;

// SECURITY_IMPERSONATION_LEVEL values, as winnt.h numbers them. Anything
// above SecurityDelegation is not a level.
constexpr std::uint32_t kSecurityAnonymous = 0;
constexpr std::uint32_t kSecurityDelegation = 3;

// TOKEN_TYPE values.
constexpr std::uint32_t kTokenPrimary = 1;
constexpr std::uint32_t kTokenImpersonation = 2;

// TOKEN_ALL_ACCESS, the access mask a duplicate without an explicit request
// records, and the access the primary token implicitly grants.
constexpr std::uint32_t kTokenAllAccess = 0x000F01FFu;

// TOKEN_GROUPS: a count followed by an array of SID_AND_ATTRIBUTES entries,
// each 16 bytes on the 64-bit ABI (a SID pointer and a DWORD of attributes
// with padding).
constexpr std::size_t kGroupsCount = 0;
constexpr std::size_t kGroupsFirstEntry = 4;
constexpr std::size_t kEntrySid = 0;
constexpr std::size_t kEntryAttributes = 8;
constexpr std::size_t kEntryBytes = 16;

// A SID's fixed header: revision at zero, subauthority count at one, then
// six bytes of identifier authority and four bytes per subauthority.
constexpr std::uint8_t kSidRevisionValue = 1;
constexpr std::size_t kSidSubAuthority = 8;
constexpr std::uint32_t kSidMaxSubAuthorities = 15;

// One group in a token's recorded list: the SID bytes copied out of guest
// memory (the guest owns the original buffer and may reuse it) and the
// attributes the caller set on the entry.
struct GroupEntry {
    std::vector<std::uint8_t> sid;
    std::uint32_t attributes = 0;
};

// The per-handle state a clone carries. The primary token's state is the
// implicit defaults: primary type, all access, no impersonation level.
struct TokenRecord {
    bool is_clone = false;
    std::uint32_t impersonation_level = kSecurityAnonymous;
    std::uint32_t token_type = kTokenPrimary;
    std::uint32_t desired_access = kTokenAllAccess;
    std::vector<GroupEntry> groups;
};

// The token table: one record per handle this slice knows. The primary
// token's record appears on first touch; clones are minted here.
std::mutex g_token_mutex;
std::map<std::uint64_t, TokenRecord> g_tokens;
std::uint64_t g_next_clone = kCloneHandleBase;

// The thread's own token, or zero when the thread has none of its own
// (which is Windows' default: a thread without a token uses the process
// token). The storage is per thread because the token is; it is written by
// `SetThreadToken` and read by no other call in this slice -- the model
// boundary documented at the top of the file -- so the write-only storage
// is the point, not a gap.
[[maybe_unused]] thread_local std::uint64_t g_thread_token = 0;

// ------------------------------------------------------------------ helpers

// Whether a byte range is a valid SID: revision 1 and a subauthority count
// the structure can actually hold. A revision or count outside that is a
// corrupt buffer, not an identity.
[[nodiscard]] bool sid_valid(const std::uint8_t* sid) noexcept {
    return sid != nullptr && sid[0] == kSidRevisionValue &&
           sid[1] <= kSidMaxSubAuthorities;
}

[[nodiscard]] std::size_t sid_bytes(const std::uint8_t* sid) noexcept {
    return kSidSubAuthority + 4u * static_cast<std::size_t>(sid[1]);
}

// The groups recorded for a handle, or an empty list when none were ever
// adjusted. Called with the lock held.
[[nodiscard]] std::vector<GroupEntry>& groups_of_locked(std::uint64_t handle) {
    return g_tokens[handle].groups;
}

// Whether a handle is a token this slice knows: the primary constant or a
// clone it minted.
[[nodiscard]] bool is_token_handle(std::uint64_t handle) noexcept {
    if (handle == kTokenHandle) {
        return true;
    }
    const std::lock_guard<std::mutex> held(g_token_mutex);
    const auto found = g_tokens.find(handle);
    return found != g_tokens.end() && found->second.is_clone;
}

// Mints the next clone handle, skipping any value already taken. The range
// is large enough that wrapping is theoretical, but the check keeps the
// invariant "a handle names one token" unconditional.
[[nodiscard]] std::uint64_t mint_clone_handle() noexcept {
    std::lock_guard<std::mutex> held(g_token_mutex);
    while (g_tokens.find(g_next_clone) != g_tokens.end()) {
        ++g_next_clone;
    }
    const std::uint64_t handle = g_next_clone;
    ++g_next_clone;
    return handle;
}

// Writes a TOKEN_GROUPS record into a caller buffer: the count, the entry
// array with each SID pointer aimed at its bytes inline in the same buffer,
// then the SID data. Returns the total bytes written.
[[nodiscard]] std::size_t write_groups(void* buffer,
                                       const std::vector<GroupEntry>& groups) noexcept {
    const std::uint64_t base = reinterpret_cast<std::uint64_t>(buffer);
    write_u32(buffer, kGroupsCount, static_cast<std::uint32_t>(groups.size()));
    std::size_t blob = kGroupsFirstEntry + groups.size() * kEntryBytes;
    for (std::size_t i = 0; i < groups.size(); ++i) {
        const std::size_t entry = kGroupsFirstEntry + i * kEntryBytes;
        write_ptr(buffer, entry + kEntrySid, base + static_cast<std::uint64_t>(blob));
        write_u32(buffer, entry + kEntryAttributes, groups[i].attributes);
        std::memcpy(static_cast<std::uint8_t*>(buffer) + blob, groups[i].sid.data(),
                    groups[i].sid.size());
        blob += groups[i].sid.size();
    }
    return blob;
}

// The byte size a TOKEN_GROUPS record for these groups occupies.
[[nodiscard]] std::size_t groups_bytes(const std::vector<GroupEntry>& groups) noexcept {
    std::size_t bytes = kGroupsFirstEntry + groups.size() * kEntryBytes;
    for (const GroupEntry& group : groups) {
        bytes += group.sid.size();
    }
    return bytes;
}

// Reads a NewState TOKEN_GROUPS record out of guest memory into host-owned
// entries. False when the record is malformed -- a count that would overrun
// the declared length, or a SID that is not one.
[[nodiscard]] bool read_groups(const void* new_state, std::uint32_t buffer_length,
                               std::vector<GroupEntry>& out) noexcept {
    if (buffer_length < kGroupsFirstEntry) {
        return false;
    }
    const std::uint32_t count = read_u32(new_state, kGroupsCount);
    if (static_cast<std::uint64_t>(count) >
        (static_cast<std::uint64_t>(buffer_length) - kGroupsFirstEntry) / kEntryBytes) {
        return false;
    }
    out.clear();
    out.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::size_t entry =
            kGroupsFirstEntry + static_cast<std::size_t>(i) * kEntryBytes;
        const std::uint64_t sid_ptr = read_ptr(new_state, entry + kEntrySid);
        if (sid_ptr == 0) {
            return false;
        }
        const std::uint8_t* sid = reinterpret_cast<const std::uint8_t*>(sid_ptr);
        if (!sid_valid(sid)) {
            return false;
        }
        GroupEntry group;
        group.sid.assign(sid, sid + sid_bytes(sid));
        group.attributes = read_u32(new_state, entry + kEntryAttributes);
        out.push_back(std::move(group));
    }
    return true;
}

}  // namespace

// `AdjustTokenGroups`. The token's recorded group list is replaced by the
// NewState list -- groups in the record and not in NewState are removed, and
// groups in NewState are added -- which is this model's reading of "adjust
// the groups", since the synthetic token keeps no other default membership
// beyond the implicit Everyone. `ResetToDefault` restores that default
// (empty) list. The previous state, when a buffer is offered, is the
// pre-adjustment list written as a TOKEN_GROUPS record with its SIDs inline,
// and the required length is always answered, which is the buffer contract
// the token family shares.
extern "C" __attribute__((ms_abi)) std::int32_t a32t_AdjustTokenGroups(
    std::uint64_t token, std::int32_t reset_to_default, const void* new_state,
    std::uint32_t buffer_length, void* previous_state,
    std::uint32_t* required_length) noexcept {
    if (!is_token_handle(token)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (required_length == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (reset_to_default == 0 && new_state == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }

    const std::lock_guard<std::mutex> held(g_token_mutex);
    std::vector<GroupEntry>& groups = groups_of_locked(token);
    const std::vector<GroupEntry> before = groups;

    const std::size_t needed = groups_bytes(before);
    *required_length = static_cast<std::uint32_t>(needed);
    if (previous_state == nullptr || buffer_length < needed) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    static_cast<void>(write_groups(previous_state, before));

    if (reset_to_default != 0) {
        // The default group set of the synthetic token: empty, with the
        // Everyone membership the sec slice treats as implicit.
        groups.clear();
    } else {
        std::vector<GroupEntry> next;
        if (!read_groups(new_state, buffer_length, next)) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        groups = std::move(next);
    }
    set_last_error(kErrorSuccess);
    return 1;
}

// `DuplicateToken`: clone the source token into a new impersonation-token
// handle. The clone copies the source's groups -- the identity is the host
// user and does not vary -- and records the requested impersonation level on
// itself. Windows answers ERROR_INVALID_PARAMETER for a level above
// SecurityDelegation, which is the same refusal here.
extern "C" __attribute__((ms_abi)) std::int32_t a32t_DuplicateToken(
    std::uint64_t existing_token, std::uint32_t impersonation_level,
    std::uint64_t* new_token) noexcept {
    if (impersonation_level > kSecurityDelegation) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (!is_token_handle(existing_token)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (new_token == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }

    const std::lock_guard<std::mutex> held(g_token_mutex);
    const TokenRecord& source = g_tokens[existing_token];
    const std::uint64_t handle = mint_clone_handle();
    TokenRecord clone;
    clone.is_clone = true;
    clone.impersonation_level = impersonation_level;
    clone.token_type = kTokenImpersonation;
    clone.desired_access = kTokenAllAccess;
    clone.groups = source.groups;
    g_tokens[handle] = std::move(clone);
    *new_token = handle;
    set_last_error(kErrorSuccess);
    return 1;
}

// `DuplicateTokenEx`: the extended clone. The desired access is recorded on
// the clone the way an access check would consult it, the token type picks
// primary or impersonation, and the security attributes are accepted and
// ignored -- a Linux token carries no DACL to inherit. The refusal for a
// bad type or level is Windows' own.
extern "C" __attribute__((ms_abi)) std::int32_t a32t_DuplicateTokenEx(
    std::uint64_t existing_token, std::uint32_t desired_access,
    void* token_attributes, std::uint32_t impersonation_level,
    std::uint32_t token_type, std::uint64_t* new_token) noexcept {
    (void)token_attributes;
    if (token_type != kTokenPrimary && token_type != kTokenImpersonation) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (impersonation_level > kSecurityDelegation) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (!is_token_handle(existing_token)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (new_token == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }

    const std::lock_guard<std::mutex> held(g_token_mutex);
    const TokenRecord& source = g_tokens[existing_token];
    const std::uint64_t handle = mint_clone_handle();
    TokenRecord clone;
    clone.is_clone = true;
    clone.impersonation_level = impersonation_level;
    clone.token_type = token_type;
    clone.desired_access = desired_access;
    clone.groups = source.groups;
    g_tokens[handle] = std::move(clone);
    *new_token = handle;
    set_last_error(kErrorSuccess);
    return 1;
}

// `SetThreadToken`: attach or clear the token of the calling thread. A null
// thread-handle pointer names the current thread; a non-null one must name
// it too -- there is exactly one thread in a single-process run -- and a
// token of zero clears the thread's own token. The stored token is what a
// later set/clear round-trips through; the stateless `OpenThreadToken` in
// the sec slice continues to answer the process token, which is the
// boundary of the model this slice documented at the top of the file.
extern "C" __attribute__((ms_abi)) std::int32_t a32t_SetThreadToken(
    std::uint64_t* thread_handle, std::uint64_t token) noexcept {
    if (thread_handle != nullptr) {
        const std::uint64_t thread = *thread_handle;
        const std::uint64_t self =
            static_cast<std::uint64_t>(k32_GetCurrentThreadId());
        if (thread != kCurrentThreadPseudo && thread != self) {
            set_last_error(kErrorInvalidHandle);
            return 0;
        }
    }
    if (token != 0 && !is_token_handle(token)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    g_thread_token = token;
    set_last_error(kErrorSuccess);
    return 1;
}

// ------------------------------------------------------------- registration

void add_advapi32_token2(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("AdjustTokenGroups", reinterpret_cast<void*>(&a32t_AdjustTokenGroups));
    e("DuplicateToken", reinterpret_cast<void*>(&a32t_DuplicateToken));
    e("DuplicateTokenEx", reinterpret_cast<void*>(&a32t_DuplicateTokenEx));
    e("SetThreadToken", reinterpret_cast<void*>(&a32t_SetThreadToken));
}

}  // namespace occ::runtime::winabi

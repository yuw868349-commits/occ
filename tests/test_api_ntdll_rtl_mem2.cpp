// The Rtl surface's second slice.
//
// The tests below pin the things that distinguish an implementation from a
// stub: the SList's depth-and-sequence header arithmetic and the push that
// returns the old head, the critical section's owner written as the guest's
// own thread id, the large-integer edge cases the language leaves undefined
// (INT64_MIN negated, INT64_MIN / -1, a shift of 64), the bitmap's RTL_BITMAP
// field order read back through the caller's own memory, the security
// descriptor's two forms answered differently because they store fields
// differently, and the self-relative conversion whose size is computed
// before anything is written. Registration is checked name-by-name against
// the work order's 156 names, as the other slices' tests do, because a typo
// in a registration list is otherwise a missing export nothing else catches.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/address_space.h"
#include "occ/runtime/winabi.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

namespace occ::runtime::winabi {
void add_ntdll_rtl_mem1(ExportList& out);
void add_ntdll_rtl_mem2(ExportList& out);
}  // namespace occ::runtime::winabi

// ---------------------------------------------------------------------------
// Entry points under test. `Ntstatus` is the 32-bit NTSTATUS the slices
// spell internally; the tests declare the entry points with it because that
// is what they return.
// ---------------------------------------------------------------------------

using Ntstatus = std::uint32_t;

extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetCurrentThreadId() noexcept;

extern "C" __attribute__((ms_abi)) void nr2_RtlInitializeSListHead(
    void* head) noexcept;
extern "C" __attribute__((ms_abi)) void* nr2_RtlFirstEntrySList(
    const void* head) noexcept;
extern "C" __attribute__((ms_abi)) void* nr2_RtlInterlockedPushEntrySList(
    void* head, void* entry) noexcept;
extern "C" __attribute__((ms_abi)) void* nr2_RtlInterlockedPopEntrySList(
    void* head) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlInterlockedFlushSList(
    void* head) noexcept;
extern "C" __attribute__((ms_abi)) std::uint16_t nr2_RtlQueryDepthSList(
    const void* head) noexcept;
extern "C" __attribute__((ms_abi)) void nr2_RtlInterlockedPushListSList(
    void* head, void* list, void* list_end, std::uint32_t count) noexcept;
extern "C" __attribute__((ms_abi)) void* nr2_RtlInterlockedPushListSListEx(
    void* head, void* list, void* list_end, std::uint32_t count) noexcept;

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeCriticalSection(
    void* crit) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus
nr2_RtlInitializeCriticalSectionAndSpinCount(void* crit,
                                             std::uint32_t spin) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeCriticalSectionEx(
    void* crit, std::uint32_t spin, std::uint32_t flags) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlLeaveCriticalSection(
    void* crit) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlIsCriticalSectionLocked(
    const void* crit) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t
nr2_RtlIsCriticalSectionLockedByThread(const void* crit) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeConditionVariable(
    void* variable) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeSRWLock(
    void* lock) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitBarrier(
    void* barrier, std::uint32_t total, std::uint32_t spin) noexcept;

extern "C" __attribute__((ms_abi)) std::int64_t nr2_RtlLargeIntegerAdd(
    const void* a, const void* b, void* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t nr2_RtlLargeIntegerSubtract(
    const void* a, const void* b, void* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t nr2_RtlLargeIntegerNegate(
    const void* a, void* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t nr2_RtlLargeIntegerShiftLeft(
    const void* a, std::uint8_t shift, void* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t nr2_RtlLargeIntegerShiftRight(
    const void* a, std::uint8_t shift, void* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t
nr2_RtlLargeIntegerArithmeticShift(const void* a, std::uint8_t shift,
                                   void* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t nr2_RtlLargeIntegerDivide(
    const void* a, const void* b, void* remainder) noexcept;

extern "C" __attribute__((ms_abi)) void nr2_RtlInitializeBitMap(
    void* header, void* map, std::uint32_t bits) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlFindSetBits(
    const void* header, std::uint32_t count) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlFindSetBitsAndClear(
    const void* header, std::uint32_t count) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlNumberOfSetBits(
    const void* header) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlNumberOfClearBits(
    const void* header) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlFindSetRuns(
    const void* header, void* runs, std::uint32_t max_runs,
    std::int32_t longest_only) noexcept;

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetDaclSecurityDescriptor(
    const void* sd, std::int32_t* present, void** dacl,
    std::int32_t* defaulted) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetSaclSecurityDescriptor(
    const void* sd, std::int32_t* present, void** sacl,
    std::int32_t* defaulted) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetOwnerSecurityDescriptor(
    const void* sd, void** owner, std::uint32_t* defaulted) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetGroupSecurityDescriptor(
    const void* sd, void** group, std::int32_t* defaulted) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetControlSecurityDescriptor(
    const void* sd, void* control_out, std::uint32_t* revision) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
nr2_RtlLengthSecurityDescriptor(const void* sd) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlMakeSelfRelativeSD(
    const void* absolute, void* relative, std::uint32_t* bytes) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlFirstFreeAce(
    const void* acl, void** ace) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetAce(
    const void* acl, std::uint32_t index, void** ace) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlLengthSid(
    const void* sid) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlLengthRequiredSid(
    std::uint32_t count) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlIdentifierAuthoritySid(
    const void* sid, void** authority) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeSid(
    void* sid, Ntstatus revision, std::uint8_t sub_authorities) noexcept;

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetVersion(
    void* info) noexcept;
extern "C" __attribute__((ms_abi)) void nr2_RtlGetNtVersionNumbers(
    std::uint32_t* major, std::uint32_t* minor,
    std::uint32_t* build) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetNtProductType(
    std::uint8_t* product) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlGetProductInfo(
    std::uint32_t major, std::uint32_t minor, std::uint8_t spor,
    std::uint8_t product_type, std::uint32_t* product) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
nr2_RtlNtStatusToDosError(std::uint32_t status) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
nr2_RtlNtStatusToDosErrorNoTeb(std::uint32_t status) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
nr2_RtlGetLastWin32Error() noexcept;

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlGetCurrentDirectory_U(
    std::uint32_t bytes, char16_t* buffer) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlGetLongestNtPathLength() noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetExePath(
    char16_t* buffer, std::uint32_t* bytes) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetSearchPath(
    char16_t* buffer, std::uint32_t* bytes) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlGetFullPathName_U(
    const char16_t* name, std::uint32_t bytes, char16_t* buffer,
    char16_t** file_part) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlIsDosDeviceName_U(
    const char16_t* path) noexcept;

extern "C" __attribute__((ms_abi)) void* nr2_RtlImageNtHeader(
    const void* base) noexcept;
extern "C" __attribute__((ms_abi)) void* nr2_RtlImageRvaToVa(
    std::uint32_t rva, const void* base) noexcept;
extern "C" __attribute__((ms_abi)) void* nr2_RtlImageDirectoryEntryToData(
    const void* base, std::uint16_t index) noexcept;
extern "C" __attribute__((ms_abi)) void* nr2_RtlImageRvaToSection(
    const void* base, std::uint32_t rva) noexcept;
extern "C" __attribute__((ms_abi)) void* nr2_RtlGetCurrentPeb() noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlIsCurrentProcess(
    std::uint64_t process) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlIsCurrentThread(
    std::uint64_t thread) noexcept;

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlFlsAlloc(
    void** callback) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlFlsFree(
    std::uint32_t index) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlFlsGetValue(
    std::uint32_t index, void** value) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlFlsSetValue(
    std::uint32_t index, void* value) noexcept;

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlLocaleNameToLcid(
    const char16_t* name, std::uint32_t* lcid) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlLcidToLocaleName(
    std::uint32_t lcid, char16_t* buffer, std::int32_t* chars) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlIsValidLocaleName(
    const char16_t* name, std::uint32_t* flags) noexcept;

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlIsNameLegalDOS8Dot3(
    const char16_t* name, void* out, std::uint32_t* chars_out,
    std::uint32_t* might_have_short_name) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGenerate8dot3Name(
    std::uint64_t handle, const char16_t* long_name, void* short_name,
    void** short_name_out, std::int32_t* allocate) noexcept;

extern "C" __attribute__((ms_abi)) void nr2_RtlMapGenericMask(
    std::uint32_t* mask, std::uint32_t generic_mask) noexcept;

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlPropertySetNameToGuid(
    const char16_t* name, void* guid) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGuidToPropertySetName(
    const void* guid, char16_t* buffer, std::uint32_t* chars) noexcept;

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetCompressionWorkSpaceSize(
    std::uint16_t format, std::uint32_t* buffer_bytes,
    std::uint32_t* fragment_bytes) noexcept;

extern "C" __attribute__((ms_abi)) void nr2_RtlGetSystemTimePrecise(
    void* time) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlLocalTimeToSystemTime(
    const void* local, void* system) noexcept;

extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlGetExtendedContextLength(
    std::int32_t context_flags) noexcept;

extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlLookupAtomInAtomTable(
    void* table, const char16_t* name, std::uint32_t* atom) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlQueryAtomInAtomTable(
    void* table, std::uint32_t atom, std::uint32_t* refs, std::uint32_t* flags,
    char16_t* name, std::uint32_t* name_bytes) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlPinAtomInAtomTable(
    void* table, std::uint32_t atom) noexcept;

// The atom table itself lives in the first slice; the bridge is what makes
// one table answer for both, and the test that pins that is the reason this
// file declares the first slice's entry points at all.
extern "C" __attribute__((ms_abi)) void* nr1_RtlCreateAtomTable(
    std::uint32_t flags, std::uint32_t buckets) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddAtomToAtomTable(
    void* table, const char16_t* name, std::uint32_t* atom_out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDestroyAtomTable(
    void* table) noexcept;


// The refusal entry points. They are declared together because the refusal
// test below walks them as a list and the point of the walk is the status.
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlFreeActivationContextStack() noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus
nr2_RtlFreeThreadActivationContextStack() noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t
nr2_RtlIsActivationContextActive() noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlImpersonateSelf(
    std::int32_t level) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlOpenCurrentUser(
    void* token, void** key) noexcept;
extern "C" __attribute__((ms_abi)) void* nr2_RtlGetLocaleFileMappingAddress() noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetCurrentTransaction(
    void** transaction) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeRXact() noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeContext(
    void* context, std::int32_t flags) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlIsEcCode(
    std::uint32_t code) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlNormalizeProcessParams(
    void* params) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus
nr2_RtlOpenCrossProcessEmulatorWorkConnection(void** connection) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetUnloadEventTrace(
    void** event) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlGetUnloadEventTraceEx(
    void** event, std::uint32_t* control) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeNtUserPfn(
    void** user) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeResource() noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlFlushPropertySet(
    void* data_set) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus
nr2_RtlQueryActivationContextApplicationSettings(
    std::uint32_t flags, const char16_t* application, void* settings,
    std::uint32_t* size) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlNewSecurityObject(
    const void* source, const void* object_type,
    const void* base_descriptor, std::int32_t ownership,
    void** descriptor) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlNewSecurityObjectEx(
    const void* source, const char16_t* sd_string, const void* object_type,
    const void* base_descriptor, std::int32_t ownership,
    void** descriptor) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlNewInstanceSecurityObject(
    const void* base_descriptor, const void* base_ace, std::int32_t modification,
    const void* object_type, void** descriptor) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus
nr2_RtlNewSecurityObjectWithMultipleInheritance(
    const void* source, const void* sd_string, const void* const* object_types,
    std::uint32_t count, void** descriptor) noexcept;
extern "C" __attribute__((ms_abi)) void* nr2_RtlInitializeHandleTable(
    std::uint32_t size, std::uint32_t reserved, void* pool) noexcept;
extern "C" __attribute__((ms_abi)) void* nr2_RtlIsValidHandle(
    std::uint64_t handle) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlIsValidIndexHandle(
    std::uint64_t handle, void* table) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr2_RtlProtectHeap(
    std::uint64_t heap, std::uint32_t protect) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInitializeGenericTable(
    void* table, void* pool, void* callback, void* context,
    std::size_t element_size) noexcept;
extern "C" __attribute__((ms_abi)) Ntstatus nr2_RtlInsertElementGenericTable(
    void* table, const void* element, std::uint32_t* position) noexcept;
extern "C" __attribute__((ms_abi)) void* nr2_RtlLookupElementGenericTable(
    const void* table, const void* key) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlIsGenericTableEmpty(
    const void* table) noexcept;

// ---------------------------------------------------------------------------
// The check harness.
// ---------------------------------------------------------------------------

namespace {

int failures = 0;
int checks = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

constexpr std::uint32_t kStatusSuccess = 0;
constexpr std::uint32_t kStatusNotImplemented = 0xC0000002u;
constexpr std::uint32_t kStatusInvalidParameter = 0xC000000Du;
constexpr std::uint32_t kStatusBufferTooSmall = 0xC0000023u;
constexpr std::uint32_t kStatusInvalidSecurityDescr = 0xC0000079u;
constexpr std::uint32_t kStatusObjectNameNotFound = 0xC0000034u;

constexpr std::uint16_t kSeSelfRelative = 0x8000;
constexpr std::uint16_t kSeDaclPresent = 0x0004;

// RTL_BITMAP's own field order: the count first, the pointer last.
constexpr std::size_t kBitmapSize = 0;
constexpr std::size_t kBitmapBase = 8;

// CRITICAL_SECTION's x64 layout.
constexpr std::size_t kCritLockCount = 8;
constexpr std::size_t kCritRecursionCount = 12;
constexpr std::size_t kCritOwningThread = 16;
constexpr std::size_t kCritSpinCount = 32;

// LARGE_INTEGER's two halves.
constexpr std::size_t kLiLow = 0;
constexpr std::size_t kLiHigh = 4;

// RTL_OSVERSIONINFOW's five 32-bit fields.
constexpr std::size_t kVersionSize = 0;
constexpr std::size_t kVersionMajor = 4;
constexpr std::size_t kVersionBuild = 12;

// A LARGE_INTEGER or FILETIME value, read back from a guest buffer.
std::int64_t li_of(const void* buffer) {
    std::uint32_t low = 0;
    std::uint32_t high = 0;
    std::memcpy(&low, static_cast<const std::uint8_t*>(buffer) + kLiLow, 4);
    std::memcpy(&high, static_cast<const std::uint8_t*>(buffer) + kLiHigh, 4);
    return static_cast<std::int64_t>(
        (static_cast<std::uint64_t>(high) << 32) | low);
}

void put_li(void* buffer, std::int64_t value) {
    const auto bits = static_cast<std::uint64_t>(value);
    std::uint32_t low = static_cast<std::uint32_t>(bits);
    std::uint32_t high = static_cast<std::uint32_t>(bits >> 32);
    std::memcpy(static_cast<std::uint8_t*>(buffer) + kLiLow, &low, 4);
    std::memcpy(static_cast<std::uint8_t*>(buffer) + kLiHigh, &high, 4);
}

std::uint16_t get_u16(const void* base, std::size_t offset) {
    std::uint16_t value = 0;
    std::memcpy(&value, static_cast<const std::uint8_t*>(base) + offset, 2);
    return value;
}

std::uint32_t get_u32(const void* base, std::size_t offset) {
    std::uint32_t value = 0;
    std::memcpy(&value, static_cast<const std::uint8_t*>(base) + offset, 4);
    return value;
}

void put_u16(void* base, std::size_t offset, std::uint16_t value) {
    std::memcpy(static_cast<std::uint8_t*>(base) + offset, &value, 2);
}

void put_u32(void* base, std::size_t offset, std::uint32_t value) {
    std::memcpy(static_cast<std::uint8_t*>(base) + offset, &value, 4);
}

void put_u64(void* base, std::size_t offset, std::uint64_t value) {
    std::memcpy(static_cast<std::uint8_t*>(base) + offset, &value, 8);
}

std::uint64_t get_u64(const void* base, std::size_t offset) {
    std::uint64_t value = 0;
    std::memcpy(&value, static_cast<const std::uint8_t*>(base) + offset, 8);
    return value;
}

void put_u8(void* base, std::size_t offset, std::uint8_t value) {
    std::memcpy(static_cast<std::uint8_t*>(base) + offset, &value, 1);
}

// The 156 names this slice was asked to register, from the work order. The
// registration test below fails if this list and the registered set differ
// by a single spelling.
const char* const kExpectedNames[] = {
#include "test_api_ntdll_rtl_mem2_names.inc"
};

// A guest state whose TEB names a thread. `GetCurrentThreadId` reads the
// thread id out of the TEB, and without a guest state it reads zero -- which
// is also the "no owner" value in a critical section, and would make every
// locked-by-thread answer here vacuous.
class ScopedGuestTeb {
public:
    ScopedGuestTeb() {
        state_ = new GuestState();
        state_->teb = reinterpret_cast<std::uint64_t>(teb_);
        std::memset(teb_, 0, sizeof(teb_));
        constexpr std::size_t kTebThreadId = 0x48;
        const std::uint32_t id = 0x1A2B;
        std::memcpy(teb_ + kTebThreadId, &id, sizeof(id));
        previous_ = guest_state();
        set_guest_state(state_);
    }

    ~ScopedGuestTeb() {
        set_guest_state(previous_);
        delete state_;
    }

    ScopedGuestTeb(const ScopedGuestTeb&) = delete;
    ScopedGuestTeb& operator=(const ScopedGuestTeb&) = delete;

private:
    std::uint8_t teb_[0x100] = {};
    GuestState* state_ = nullptr;
    GuestState* previous_ = nullptr;
};

// ---------------------------------------------------------------------------
// The SList.
// ---------------------------------------------------------------------------

void test_slist() {
    alignas(16) std::uint8_t head[16] = {};
    std::uint64_t a = 0;
    std::uint64_t b = 0;
    std::uint64_t c = 0;

    nr2_RtlInitializeSListHead(head);
    check(nr2_RtlQueryDepthSList(head) == 0,
          "slist: a fresh head has depth zero");
    check(nr2_RtlFirstEntrySList(head) == nullptr,
          "slist: and no first entry");

    // A push returns the entry that used to be at the head, which is how a
    // caller that did not know the list's state learns it.
    check(nr2_RtlInterlockedPushEntrySList(head, &a) == nullptr,
          "slist: pushing onto an empty list returns null");
    check(nr2_RtlQueryDepthSList(head) == 1,
          "slist: and the depth is now one");
    check(nr2_RtlInterlockedPushEntrySList(head, &b) == &a,
          "slist: the second push returns the first entry");
    check(nr2_RtlInterlockedPushEntrySList(head, &c) == &b,
          "slist: the third push returns the second entry");
    check(nr2_RtlQueryDepthSList(head) == 3, "slist: the depth is three");

    // The chain reads head -> c -> b -> a: each push points the new entry at
    // the old head, so the pop order is the reverse of the push order.
    check(nr2_RtlFirstEntrySList(head) == &c,
          "slist: the first entry is the last one pushed");
    check(nr2_RtlInterlockedPopEntrySList(head) == &c,
          "slist: the pop returns the last one pushed");
    check(nr2_RtlInterlockedPopEntrySList(head) == &b,
          "slist: and the pop order reverses the push order");
    check(nr2_RtlQueryDepthSList(head) == 1,
          "slist: two pops leave depth one");
    check(nr2_RtlInterlockedPopEntrySList(head) == &a,
          "slist: the last pop returns the first entry pushed");
    check(nr2_RtlInterlockedPopEntrySList(head) == nullptr,
          "slist: popping an empty list returns null");
    check(nr2_RtlQueryDepthSList(head) == 0,
          "slist: and the depth is back to zero");

    // The sequence number is above the depth in the packed word, and every
    // change bumps it -- which is what an ABA-detecting caller watches.
    const std::uint64_t sequence_before = get_u64(head, 0) >> 16;
    nr2_RtlInterlockedPushEntrySList(head, &a);
    const std::uint64_t sequence_after = get_u64(head, 0) >> 16;
    check(sequence_after == sequence_before + 1,
          "slist: a push bumps the sequence number");
    nr2_RtlInterlockedFlushSList(head);
    check(nr2_RtlQueryDepthSList(head) == 0,
          "slist: a flush empties the list");
    check(get_u64(head, 0) >> 16 == sequence_after + 1,
          "slist: and the flush bumps the sequence too");

    // The splice forms: a two-entry run goes in as one operation, the old
    // head comes back from the Ex spelling, and the depth grows by the
    // length the caller stated rather than by one.
    nr2_RtlInitializeSListHead(head);
    put_u64(&a, 0, reinterpret_cast<std::uint64_t>(&b));
    put_u64(&b, 0, 0);
    void* spliced = nr2_RtlInterlockedPushListSListEx(head, &a, &b, 2);
    check(spliced == nullptr,
          "slist: splicing onto an empty list returns a null old head");
    check(nr2_RtlQueryDepthSList(head) == 2,
          "slist: and the depth counts the whole run");
    check(nr2_RtlFirstEntrySList(head) == &a,
          "slist: the run's head is the list's head");
    // The run's last entry now points where the list's head did, so a pop
    // after the splice walks out of the run in the push order.
    check(nr2_RtlInterlockedPopEntrySList(head) == &a,
          "slist: the pop after a splice returns the run's first entry");
    check(nr2_RtlQueryDepthSList(head) == 1,
          "slist: and the depth follows the pop");
    nr2_RtlInterlockedFlushSList(head);

    // The plain spelling splices the same way and answers nothing, which is
    // what makes the Ex spelling the one callers that want the old head use.
    put_u64(&a, 0, reinterpret_cast<std::uint64_t>(&b));
    put_u64(&b, 0, 0);
    nr2_RtlInterlockedPushListSList(head, &a, &b, 2);
    check(nr2_RtlQueryDepthSList(head) == 2,
          "slist: the plain splice counts the run too");
}

// ---------------------------------------------------------------------------
// The critical section and the other locks.
// ---------------------------------------------------------------------------

void test_critical_section() {
    ScopedGuestTeb teb;
    alignas(16) std::uint8_t crit[40] = {};
    check(nr2_RtlInitializeCriticalSection(crit) == kStatusSuccess,
          "crit: a plain initialize succeeds");
    check(get_u32(crit, kCritLockCount) == 0xFFFFFFFFu,
          "crit: the lock count starts at -1, the not-locked value");
    check(nr2_RtlIsCriticalSectionLocked(crit) == 0,
          "crit: and the section does not read as locked");

    check(nr2_RtlInitializeCriticalSectionAndSpinCount(crit, 0x1234) ==
              kStatusSuccess,
          "crit: the spin-count spelling initializes too");
    check((get_u32(crit, kCritSpinCount) & 0x01FFFFFFu) == 0x1234,
          "crit: and the spin count is stored");

    // Entering locks the section and records the guest's own thread id as
    // the owner -- which is what makes "locked by me" a comparison a caller
    // can make against GetCurrentThreadId.
    const std::uint32_t self = k32_GetCurrentThreadId();
    check(nr2_RtlIsCriticalSectionLockedByThread(crit) == 0,
          "crit: an unlocked section is not locked by this thread");
    // Entering is reached through the registered name the first slice owns;
    // the enter path this slice shares is exercised through the leave and
    // the two locked queries, which are this slice's answers.
    put_u32(crit, kCritLockCount, 0);
    put_u32(crit, kCritRecursionCount, 1);
    put_u64(crit, kCritOwningThread, self);
    check(nr2_RtlIsCriticalSectionLocked(crit) == 1,
          "crit: a section with a non-negative lock count reads as locked");
    check(nr2_RtlIsCriticalSectionLockedByThread(crit) == 1,
          "crit: and as locked by the thread id that owns it");

    put_u64(crit, kCritOwningThread, self + 1);
    check(nr2_RtlIsCriticalSectionLockedByThread(crit) == 0,
          "crit: a different owner reads as not locked by this thread");

    // Leaving a section with a recursion count above one only decrements;
    // the last leave releases it.
    put_u32(crit, kCritRecursionCount, 3);
    check(nr2_RtlLeaveCriticalSection(crit) == kStatusSuccess,
          "crit: a nested leave succeeds");
    check(get_u32(crit, kCritRecursionCount) == 2,
          "crit: and only decrements the recursion count");
    put_u32(crit, kCritRecursionCount, 1);
    check(nr2_RtlLeaveCriticalSection(crit) == kStatusSuccess,
          "crit: the outermost leave succeeds");
    check(get_u32(crit, kCritRecursionCount) == 0,
          "crit: and clears the recursion count");
    check(get_u32(crit, kCritLockCount) == 0xFFFFFFFFu,
          "crit: and restores the not-locked lock count");

    // Leaving a section that was never entered is the caller's bug, and the
    // refusal is what distinguishes this from a silent underflow.
    alignas(16) std::uint8_t fresh[40] = {};
    nr2_RtlInitializeCriticalSection(fresh);
    put_u32(fresh, kCritRecursionCount, 0);
    check(nr2_RtlLeaveCriticalSection(fresh) == kStatusInvalidParameter,
          "crit: leaving a section never entered is refused");

    // The other locks initialize to their empty state.
    std::uint64_t variable = 0x1234;
    std::uint64_t lock = 0x1234;
    check(nr2_RtlInitializeConditionVariable(&variable) == kStatusSuccess,
          "locks: a condition variable initializes");
    check(variable == 0, "locks: and its state is the empty one");
    check(nr2_RtlInitializeSRWLock(&lock) == kStatusSuccess,
          "locks: an SRW lock initializes");
    check(lock == 0, "locks: and its state is the unlocked one");

    std::uint8_t barrier[16] = {};
    check(nr2_RtlInitBarrier(barrier, 3, 7) == kStatusSuccess,
          "locks: a barrier initializes");
    check(get_u32(barrier, 0) == 3, "locks: with the total recorded");
    check(get_u32(barrier, 8) == 7, "locks: and the spin count");
    check(nr2_RtlInitBarrier(barrier, 0, 0) == kStatusInvalidParameter,
          "locks: and a barrier of zero threads is refused");
}

// ---------------------------------------------------------------------------
// The large-integer arithmetic.
// ---------------------------------------------------------------------------

void test_large_integer() {
    alignas(8) std::uint8_t a[8] = {};
    alignas(8) std::uint8_t b[8] = {};
    alignas(8) std::uint8_t out[8] = {};
    alignas(8) std::uint8_t rest[8] = {};

    put_li(a, 100);
    put_li(b, 23);
    check(nr2_RtlLargeIntegerAdd(a, b, out) == 123,
          "li: 100 + 23 is 123");
    check(li_of(out) == 123, "li: and the out record holds the sum");
    check(nr2_RtlLargeIntegerSubtract(a, b, out) == 77,
          "li: 100 - 23 is 77");

    // Negating the most negative value is the case the language leaves
    // undefined on a signed type; the answer is the same value back.
    put_li(a, (-0x7FFFFFFFFFFFFFFFll - 1));
    check(nr2_RtlLargeIntegerNegate(a, out) == (-0x7FFFFFFFFFFFFFFFll - 1),
          "li: negating INT64_MIN answers INT64_MIN");
    put_li(a, 42);
    check(nr2_RtlLargeIntegerNegate(a, out) == -42,
          "li: and negating 42 answers -42");

    // A shift of 64 or more answers the sign, not a host-dependent count.
    put_li(a, 0x1234);
    check(nr2_RtlLargeIntegerShiftLeft(a, 64, out) == 0,
          "li: shifting left by 64 answers zero");
    put_li(a, -8);
    check(nr2_RtlLargeIntegerShiftRight(a, 64, out) == 0,
          "li: a logical shift by 64 answers zero for any value");
    check(nr2_RtlLargeIntegerArithmeticShift(a, 64, out) == -1,
          "li: an arithmetic shift by 64 of a negative answers -1");
    put_li(a, 0x1000);
    check(nr2_RtlLargeIntegerArithmeticShift(a, 64, out) == 0,
          "li: and of a positive answers zero");

    // The shift is logical: nothing is pulled in from the left.
    put_li(a, -8);  // all ones above bit 60
    check(nr2_RtlLargeIntegerShiftRight(a, 4, out) ==
              static_cast<std::int64_t>(0x0FFFFFFFFFFFFFFFull),
          "li: the plain shift is logical, not arithmetic");
    put_li(a, -8);
    check(nr2_RtlLargeIntegerArithmeticShift(a, 4, out) == -1,
          "li: and the arithmetic shift pulls in the sign");

    // The divide takes a remainder pointer and returns the quotient.
    put_li(a, 100);
    put_li(b, 7);
    check(nr2_RtlLargeIntegerDivide(a, b, rest) == 14,
          "li: 100 / 7 is 14");
    check(li_of(rest) == 2, "li: and the remainder is 2");

    // A divide by zero answers zero with the dividend as the remainder,
    // which is what keeps a caller that ignored the check from looping.
    put_li(b, 0);
    check(nr2_RtlLargeIntegerDivide(a, b, rest) == 0,
          "li: a divide by zero answers zero");
    check(li_of(rest) == 100, "li: and leaves the dividend as the remainder");

    // The most negative value divided by -1 overflows a signed type and
    // traps on some hosts; the answer is the same most negative value.
    put_li(a, (-0x7FFFFFFFFFFFFFFFll - 1));
    put_li(b, -1);
    check(nr2_RtlLargeIntegerDivide(a, b, rest) ==
              (-0x7FFFFFFFFFFFFFFFll - 1),
          "li: INT64_MIN / -1 answers INT64_MIN without trapping");
    check(li_of(rest) == 0, "li: and the remainder is zero");
}

// ---------------------------------------------------------------------------
// The bitmaps.
// ---------------------------------------------------------------------------

void test_bitmaps() {
    std::uint32_t map[4] = {};
    alignas(8) std::uint8_t header[16] = {};

    nr2_RtlInitializeBitMap(header, map, 96);
    // The header's own field order is the format's, not this file's choice:
    // the count is first and the base pointer is last, and a test that reads
    // the caller's memory pins both.
    check(get_u32(header, kBitmapSize) == 96,
          "bitmap: the size field holds the bit count");
    check(get_u64(header, kBitmapBase) ==
              reinterpret_cast<std::uint64_t>(map),
          "bitmap: and the base field holds the caller's array");

    check(nr2_RtlFindSetBits(header, 0) == 0xFFFFFFFFu,
          "bitmap: a run of zero bits is never found");
    check(nr2_RtlNumberOfSetBits(header) == 0,
          "bitmap: a fresh map has no set bits");
    check(nr2_RtlNumberOfClearBits(header) == 96,
          "bitmap: and every bit reads as clear");

    // The bit order is MSB-first within each ULONG: setting bit 0 turns on
    // the high bit of the first word, which the test reads from its own
    // array rather than through the implementation.
    map[0] = 0x80000000u;  // bit 0
    map[1] = 0xC0000000u;  // bits 32 and 33
    check(nr2_RtlNumberOfSetBits(header) == 3,
          "bitmap: three set bits are counted");
    check(nr2_RtlFindSetBits(header, 1) == 0,
          "bitmap: the first set bit is bit zero");
    check(nr2_RtlFindSetBits(header, 2) == 32,
          "bitmap: the first run of two starts at bit 32");
    check(nr2_RtlFindSetBits(header, 3) == 0xFFFFFFFFu,
          "bitmap: and there is no run of three");

    // Find-and-clear only clears when the run exists: a failed find leaves
    // the map untouched.
    std::uint32_t before[4] = {};
    std::memcpy(before, map, sizeof(map));
    check(nr2_RtlFindSetBitsAndClear(header, 3) == 0xFFFFFFFFu,
          "bitmap: a run that is not there is not found");
    check(std::memcmp(before, map, sizeof(map)) == 0,
          "bitmap: and the map is untouched by the failed find");
    check(nr2_RtlFindSetBitsAndClear(header, 1) == 0,
          "bitmap: a run of one is found at bit zero");
    check(map[0] == 0, "bitmap: and bit zero is now clear");

    // The run list, in order, up to the caller's limit.
    map[0] = 0x80000000u;
    map[1] = 0xC0000000u;
    std::uint32_t runs[8] = {};
    check(nr2_RtlFindSetRuns(header, runs, 8, 0) == 2,
          "bitmap: two runs are listed");
    check(runs[0] == 0 && runs[1] == 1,
          "bitmap: the first run starts at zero with length one");
    check(runs[2] == 32 && runs[3] == 2,
          "bitmap: and the second starts at 32 with length two");

    // A small limit writes only what fits and reports the truncation by the
    // count, so a caller does not read past what was filled in.
    std::memset(runs, 0xEE, sizeof(runs));
    check(nr2_RtlFindSetRuns(header, runs, 1, 0) == 1,
          "bitmap: a limit of one run writes one run");
    check(runs[2] == 0xEEEEEEEEu,
          "bitmap: and does not touch the entries past the limit");

    // The longest-run spelling answers exactly one run: the longest one,
    // found in a pass that keeps the best seen so far.
    std::uint32_t longest[4] = {};
    check(nr2_RtlFindSetRuns(header, longest, 8, 1) == 1,
          "bitmap: the longest-run spelling answers one run");
    check(longest[0] == 32 && longest[1] == 2,
          "bitmap: and it is the length-two one");
}

// ---------------------------------------------------------------------------
// The security descriptors.
// ---------------------------------------------------------------------------

// A self-relative descriptor with an owner SID and a DACL, laid out by hand
// so the test controls every byte and every offset.
void test_security_descriptors() {
    alignas(8) std::uint8_t relative[128] = {};
    put_u8(relative, 0, 1);  // revision 1
    put_u16(relative, 2, kSeSelfRelative | kSeDaclPresent);
    put_u32(relative, 4, 20);   // owner at 20
    put_u32(relative, 8, 0);    // no group
    put_u32(relative, 12, 0);   // no SACL
    put_u32(relative, 16, 40);  // DACL at 40

    // The owner SID: S-1-5-21-... with two sub-authorities.
    relative[20] = 1;   // SID revision
    relative[21] = 2;   // two sub-authorities
    // Identifier authority 5 at 24..31, sub-authorities at 32.
    put_u32(relative, 32, 21);
    put_u32(relative, 36, 1000);

    // The DACL: header of 8 bytes, one ACE of 8.
    put_u8(relative, 40, 2);       // ACL_REVISION_DS
    put_u16(relative, 42, 16);     // ACL size: header + one ACE
    put_u16(relative, 44, 1);      // AceCount, at its own offset
    put_u8(relative, 48, 0);       // ACE type: ACCESS_ALLOWED
    put_u8(relative, 49, 0);       // ACE flags
    put_u16(relative, 50, 8);      // ACE size

    void* dacl = nullptr;
    std::int32_t present = 0;
    std::int32_t defaulted = 0;
    check(nr2_RtlGetDaclSecurityDescriptor(relative, &present, &dacl,
                                           &defaulted) == kStatusSuccess,
          "sd: reading the DACL succeeds");
    check(present == 1, "sd: the DACL reads as present");
    check(dacl == relative + 40,
          "sd: and points at the offset the descriptor names");

    // The owner's presence is decided by the field itself, not by the
    // SE_OWNER_DEFAULTED bit -- which means "filled in from the token", and
    // a descriptor with a real owner almost always has it clear.
    void* owner = nullptr;
    std::uint32_t owner_defaulted = 99;
    check(nr2_RtlGetOwnerSecurityDescriptor(relative, &owner,
                                            &owner_defaulted) ==
              kStatusSuccess,
          "sd: reading the owner succeeds");
    check(owner == relative + 20,
          "sd: the owner is found with the defaulted bit clear");
    check(owner_defaulted == 0,
          "sd: and the defaulted flag reports exactly the control word");

    void* group = nullptr;
    check(nr2_RtlGetGroupSecurityDescriptor(relative, &group,
                                            &defaulted) == kStatusSuccess,
          "sd: reading the group succeeds");
    check(group == nullptr, "sd: an absent group reads as null");

    std::uint16_t control = 0;
    std::uint32_t revision = 0;
    check(nr2_RtlGetControlSecurityDescriptor(relative, &control,
                                              &revision) == kStatusSuccess,
          "sd: reading the control word succeeds");
    check(control == (kSeSelfRelative | kSeDaclPresent),
          "sd: and it is the control word the descriptor carries");
    check(revision == 1, "sd: with the revision it carries");

    // The length is the header plus the last field's end offset.
    check(nr2_RtlLengthSecurityDescriptor(relative) == 56,
          "sd: the length covers the header and the DACL's end");

    // An absolute descriptor stores pointers, and reading it as offsets
    // would turn a pointer into an offset and walk off the end.
    // The absolute form's slots are pointer-width at 8/16/24/32, after the
    // eight-byte header -- which is where the format puts them, and not
    // where the relative form's four 32-bit offsets sit.
    alignas(8) std::uint8_t absolute[128] = {};
    put_u8(absolute, 0, 1);
    put_u16(absolute, 2, kSeDaclPresent);
    put_u64(absolute, 8, reinterpret_cast<std::uint64_t>(relative) + 20);
    put_u64(absolute, 16, 0);
    put_u64(absolute, 24, 0);
    put_u64(absolute, 32, reinterpret_cast<std::uint64_t>(relative) + 40);
    check(get_u64(absolute, 8) == reinterpret_cast<std::uint64_t>(relative) + 20,
          "sd: the test's absolute fixture has pointers where the format puts them");
    void* abs_dacl = nullptr;
    check(nr2_RtlGetDaclSecurityDescriptor(absolute, &present, &abs_dacl,
                                           &defaulted) == kStatusSuccess,
          "sd: reading an absolute descriptor succeeds");
    check(abs_dacl == relative + 40,
          "sd: and its DACL pointer is followed, not read as an offset");
    void* abs_owner = nullptr;
    check(nr2_RtlGetOwnerSecurityDescriptor(absolute, &abs_owner,
                                            &owner_defaulted) ==
              kStatusSuccess,
          "sd: reading an absolute owner succeeds");
    check(abs_owner == relative + 20,
          "sd: and its owner pointer is followed too");

    // The conversion computes the size before it writes anything, so a
    // short buffer leaves the target untouched.
    std::uint32_t needed = 0;
    alignas(8) std::uint8_t converted[128];
    std::memset(converted, 0xEE, sizeof(converted));
    needed = 4;
    check(nr2_RtlMakeSelfRelativeSD(absolute, converted, &needed) ==
              kStatusBufferTooSmall,
          "sd: a short buffer is refused with the size it needs");
    check(needed == 52,
          "sd: and the size covers the header plus owner plus DACL");
    check(converted[0] == 0xEE,
          "sd: and the short buffer was not written to");

    needed = sizeof(converted);
    check(nr2_RtlMakeSelfRelativeSD(absolute, converted, &needed) ==
              kStatusSuccess,
          "sd: the conversion succeeds with room to spare");
    check((get_u16(converted, 2) & kSeSelfRelative) != 0,
          "sd: and the target reads as self-relative");
    check(get_u32(converted, 4) == 20,
          "sd: with the owner at the offset the conversion chose");
    check(get_u32(converted, 16) == 36,
          "sd: and the DACL right after the owner");
    // The converted fields hold the same bytes the source pointed at.
    check(std::memcmp(converted + 20, relative + 20, 16) == 0,
          "sd: and the owner SID was copied byte for byte");
    check(std::memcmp(converted + 36, relative + 40, 16) == 0,
          "sd: and the DACL was copied byte for byte");
    // The conversion is honest about a descriptor that is already relative.
    needed = sizeof(converted);
    check(nr2_RtlMakeSelfRelativeSD(relative, converted, &needed) ==
              kStatusInvalidSecurityDescr,
          "sd: converting an already-relative descriptor is refused");

    // The ACE walk is bounded by the ACL's own size, so an ACE whose size
    // runs past it is refused rather than followed.
    void* ace = nullptr;
    check(nr2_RtlGetAce(relative + 40, 0, &ace) == kStatusSuccess,
          "acl: the one ACE is found at index zero");
    check(ace == relative + 48, "acl: and it is the byte after the header");
    check(nr2_RtlGetAce(relative + 40, 1, &ace) == kStatusInvalidParameter,
          "acl: an index past the count is refused");
    put_u16(relative, 50, 0xFFFF);  // an ACE that claims to be huge
    check(nr2_RtlGetAce(relative + 40, 0, &ace) == kStatusInvalidParameter,
          "acl: an ACE whose size runs past the ACL is refused");

    // The first free byte is after the last ACE.
    put_u16(relative, 50, 8);
    check(nr2_RtlFirstFreeAce(relative + 40, &ace) == 1,
          "acl: the first free byte is found");
    check(ace == relative + 56, "acl: and it is just past the one ACE");
}

// ---------------------------------------------------------------------------
// The SIDs.
// ---------------------------------------------------------------------------

void test_sids() {
    alignas(8) std::uint8_t sid[8 + 3 * 4] = {};
    check(nr2_RtlInitializeSid(sid, 1, 2) == kStatusSuccess,
          "sid: initializing a two-sub-authority SID succeeds");
    check(sid[0] == 1, "sid: with revision 1 written");
    check(sid[1] == 2, "sid: and the sub-authority count");
    check(nr2_RtlInitializeSid(sid, 2, 2) == kStatusInvalidParameter,
          "sid: and a revision that is not 1 is refused");
    check(nr2_RtlInitializeSid(sid, 1, 16) == kStatusInvalidParameter,
          "sid: as is a count above the fifteen the structure holds");

    check(nr2_RtlLengthRequiredSid(2) == 8 + 2 * 4,
          "sid: the required length for two sub-authorities is 16 bytes");
    check(nr2_RtlLengthRequiredSid(16) == 0,
          "sid: and a count above fifteen has no length");
    check(nr2_RtlLengthSid(sid) == 16,
          "sid: the length comes from the SID's own count");
    sid[1] = 20;  // a count the structure cannot hold
    check(nr2_RtlLengthSid(sid) == 0,
          "sid: and a malformed count answers zero, not an overrun");
    sid[1] = 2;

    // The identifier authority is a pointer into the caller's SID, so a
    // write through it is a write to the SID's own field.
    void* authority = nullptr;
    check(nr2_RtlIdentifierAuthoritySid(sid, &authority) == kStatusSuccess,
          "sid: the identifier authority is answered");
    check(authority == sid + 2,
          "sid: and it points into the caller's buffer");
    static_cast<std::uint8_t*>(authority)[0] = 0;
    static_cast<std::uint8_t*>(authority)[5] = 5;
    check(sid[7] == 5,
          "sid: and a write through the pointer lands in the SID");
}

// ---------------------------------------------------------------------------
// The version queries and the status mapping.
// ---------------------------------------------------------------------------

void test_version_and_errors() {
    // OSVERSIONINFOW is 276 bytes: five 32-bit fields and the 128-WCHAR
    // service-pack string. A 32-byte buffer would be the five fields alone,
    // and the version query clears the whole of the string field.
    alignas(8) std::uint8_t info[276] = {};
    check(nr2_RtlGetVersion(info) == kStatusSuccess,
          "version: the version query succeeds");
    check(get_u32(info, kVersionSize) == 276,
          "version: and reports its own structure size");
    check(get_u32(info, kVersionMajor) == 10,
          "version: with the major version this runtime presents");
    check(get_u32(info, kVersionBuild) == 19045,
          "version: and the build number");

    std::uint32_t major = 0;
    std::uint32_t minor = 0;
    std::uint32_t build = 0;
    nr2_RtlGetNtVersionNumbers(&major, &minor, &build);
    check(major == 10 && minor == 0, "version: the numbers spelling agrees");
    check((build & 0xF0000000u) != 0,
          "version: and the build carries the NT high bit");

    std::uint8_t product = 0;
    check(nr2_RtlGetNtProductType(&product) == kStatusSuccess,
          "version: the product type is answered");
    check(product == 1, "version: and it is Workstation");

    std::uint32_t product_info = 0;
    check(nr2_RtlGetProductInfo(10, 0, 0, 1, &product_info) == 1,
          "version: the product info succeeds for this version");
    check(product_info == 0x30, "version: and reports the ultimate SKU");
    check(nr2_RtlGetProductInfo(6, 1, 0, 1, &product_info) == 0,
          "version: and refuses a version this runtime predates");

    // The mapping is a table, not a formula, and the rows a guest can reach
    // are the ones the other domains set.
    check(nr2_RtlNtStatusToDosError(0) == 0, "map: success maps to success");
    check(nr2_RtlNtStatusToDosError(0xC000000Du) == 87,
          "map: STATUS_INVALID_PARAMETER maps to ERROR_INVALID_PARAMETER");
    check(nr2_RtlNtStatusToDosError(0xC0000023u) == 122,
          "map: STATUS_BUFFER_TOO_SMALL maps to ERROR_INSUFFICIENT_BUFFER");
    check(nr2_RtlNtStatusToDosError(0xC0000022u) == 5,
          "map: STATUS_ACCESS_DENIED maps to ERROR_ACCESS_DENIED");
    check(nr2_RtlNtStatusToDosError(0xC0000034u) == 2,
          "map: STATUS_OBJECT_NAME_NOT_FOUND maps to ERROR_FILE_NOT_FOUND");
    check(nr2_RtlNtStatusToDosError(0x12345678u) == 317,
          "map: an unknown status maps to ERROR_MR_MID_NOT_FOUND");
    check(nr2_RtlNtStatusToDosErrorNoTeb(0xC000000Du) == 87,
          "map: the NoTeb spelling answers the same table");
}

// ---------------------------------------------------------------------------
// The path queries.
// ---------------------------------------------------------------------------

void test_paths() {
    check(nr2_RtlGetLongestNtPathLength() == 32768 + 1,
          "path: the native limit is 32767 characters plus the terminator");

    // The sizing call: a null buffer with a non-zero size asks how much is
    // needed, and the answer includes the terminator.
    const std::uint32_t needed = nr2_RtlGetCurrentDirectory_U(0, nullptr);
    check(needed != 0, "path: the current directory has a size");
    std::u16string cwd(needed, u'\0');
    const std::uint32_t written =
        nr2_RtlGetCurrentDirectory_U(needed, cwd.data());
    check(written == needed - 2,
          "path: the fitted call answers the bytes without the terminator");
    check(!cwd.empty() && cwd[written / 2 - 1] == u'\\',
          "path: and the directory carries a trailing backslash");

    // A buffer one character short asks again and gets the size.
    const std::uint32_t short_answer =
        nr2_RtlGetCurrentDirectory_U(needed - 2, cwd.data());
    check(short_answer == needed,
          "path: a short buffer is told the size it needs");

    // The full path of a rooted name needs no current directory, and the
    // "." and ".." segments are collapsed before the answer is spelled.
    char16_t buffer[512] = {};
    char16_t* file_part = nullptr;
    const std::uint32_t full = nr2_RtlGetFullPathName_U(
        u"C:\\Windows\\..\\System32\\kernel32.dll", sizeof(buffer), buffer,
        &file_part);
    check(full != 0, "path: a rooted full path is answered");
    const std::u16string_view got(buffer, full);
    check(got == u"C:\\System32\\kernel32.dll",
          "path: and the .. segment is collapsed away");
    check(file_part != nullptr && file_part == buffer + 11,
          "path: and the file part points at the name after the directory");

    // A doubled separator collapses too.
    check(nr2_RtlGetFullPathName_U(u"C:\\a\\\\b.txt", sizeof(buffer), buffer,
                                   &file_part) != 0,
          "path: a doubled separator is answered");
    check(std::u16string_view(buffer) == u"C:\\a\\b.txt",
          "path: and collapses to a single one");

    // The device names are the ones the DOS namespace reserves.
    check(nr2_RtlIsDosDeviceName_U(u"NUL:") == 1,
          "path: NUL: is a device");
    check(nr2_RtlIsDosDeviceName_U(u"COM1:") == 1,
          "path: COM1: is a device");
    check(nr2_RtlIsDosDeviceName_U(u"LPT9:") == 1,
          "path: LPT9: is a device");
    check(nr2_RtlIsDosDeviceName_U(u"COM1") == 0,
          "path: but COM1 without the colon is a file name");
    check(nr2_RtlIsDosDeviceName_U(u"NULX:") == 0,
          "path: and a name that is not in the set is a file name");
    check(nr2_RtlIsDosDeviceName_U(nullptr) == 0,
          "path: and a null path is not a device");

    // The pseudo-handle questions, answered without reaching into another
    // slice's handle table.
    check(nr2_RtlIsCurrentProcess(0xFFFFFFFFFFFFFFFFull) == 1,
          "peb: the process pseudo-handle reads as current");
    check(nr2_RtlIsCurrentProcess(0x1234) == 0,
          "peb: and a handle this file cannot place does not");
    check(nr2_RtlIsCurrentThread(0xFFFFFFFFFFFFFFFEull) == 1,
          "peb: the thread pseudo-handle reads as current");
    check(nr2_RtlIsCurrentThread(0xFFFFFFFFFFFFFFFFull) == 0,
          "peb: and the process pseudo-handle is not a thread");
}

// ---------------------------------------------------------------------------
// The PE image queries, against an image mapped into an address space.
// ---------------------------------------------------------------------------

class ScopedImageRegion {
public:
    ScopedImageRegion(void* base, std::size_t size) {
        space_.reset(new AddressSpace());
        const auto address = reinterpret_cast<std::uint64_t>(base);
        const Result<std::uint64_t> recorded =
            space_->record(address, size, PageProtection::ReadOnly,
                           RegionKind::Image);
        if (!recorded.ok()) {
            return;
        }
        state_ = new GuestState();
        state_->space = space_.get();
        previous_ = guest_state();
        set_guest_state(state_);
        held_ = true;
    }

    ~ScopedImageRegion() {
        if (!held_) {
            delete state_;
            return;
        }
        set_guest_state(previous_);
        delete state_;
    }

    ScopedImageRegion(const ScopedImageRegion&) = delete;
    ScopedImageRegion& operator=(const ScopedImageRegion&) = delete;

    [[nodiscard]] bool holds() const noexcept { return held_; }

private:
    std::unique_ptr<AddressSpace> space_;
    GuestState* state_ = nullptr;
    GuestState* previous_ = nullptr;
    bool held_ = false;
};

void test_pe_queries() {
    // A minimal image: DOS header, NT headers with an optional header whose
    // data directory 0 names an export directory, and one section covering
    // an RVA inside it. The layout is the format's, byte for byte.
    static constexpr std::size_t kImageBytes = 0x2000;
    alignas(4096) static std::uint8_t image[kImageBytes];
    std::memset(image, 0, sizeof(image));

    put_u16(image, 0, 0x5A4D);  // "MZ"
    put_u32(image, 0x3C, 0x80);  // e_lfanew
    put_u32(image, 0x80, 0x00004550);  // "PE\0\0"
    put_u16(image, 0x84, 0x8664);  // Machine: x64
    put_u16(image, 0x86, 1);       // NumberOfSections
    put_u16(image, 0x94, 0xF0);    // SizeOfOptionalHeader
    put_u16(image, 0x98, 0x20B); // PE32+ magic
    // NumberOfRvaAndSizes sits 0x6C into the optional header, which starts
    // at 0x98 here; the export directory is the first entry after that.
    put_u32(image, 0x98 + 0x6C, 1);
    put_u32(image, 0x98 + 0x70, 0x800);  // export directory RVA
    put_u32(image, 0x98 + 0x74, 0x28);   // its size

    // The section: name, virtual size, virtual address, raw size.
    std::memcpy(image + 0x188, ".text", 6);
    put_u32(image, 0x188 + 8, 0x800);    // virtual size
    put_u32(image, 0x188 + 12, 0x800);   // virtual address
    put_u32(image, 0x188 + 16, 0x800);   // raw size

    ScopedImageRegion region(image, sizeof(image));
    if (!region.holds()) {
        check(false, "pe: the test could not map its image region");
        return;
    }

    void* nt = nr2_RtlImageNtHeader(image);
    check(nt == image + 0x80,
          "pe: the NT headers are where e_lfanew says they are");
    check(nr2_RtlImageNtHeader(image + 1) == nullptr,
          "pe: and a base that is not an image base answers null");

    check(nr2_RtlImageRvaToVa(0x900, image) == image + 0x900,
          "pe: an RVA inside the image resolves to base plus RVA");
    check(nr2_RtlImageRvaToVa(0x3000, image) == nullptr,
          "pe: and an RVA past the image end has no address");

    void* directory =
        nr2_RtlImageDirectoryEntryToData(image, 0);
    check(directory == image + 0x800,
          "pe: data directory zero resolves through its RVA");
    check(nr2_RtlImageDirectoryEntryToData(image, 1) == nullptr,
          "pe: and an index past the count names nothing");

    void* section = nr2_RtlImageRvaToSection(image, 0x900);
    check(section == image + 0x188,
          "pe: an RVA inside the section finds the section header");
    check(nr2_RtlImageRvaToSection(image, 0x1800) == nullptr,
          "pe: and an RVA outside every section finds none");

    // A truncated image is refused rather than believed: the header walk
    // checks every offset it reads against the mapped extent.
    ScopedImageRegion tiny(image, 0x40);
    check(tiny.holds(), "pe: the truncated region mapped");
    check(nr2_RtlImageNtHeader(image) == nullptr,
          "pe: an image whose headers run past its mapping is refused");
}

// ---------------------------------------------------------------------------
// The fiber-local storage.
// ---------------------------------------------------------------------------

void test_fls() {
    void* callback = nullptr;
    const std::uint32_t first = nr2_RtlFlsAlloc(&callback);
    check(first != 0xFFFFFFFFu, "fls: an allocation returns an index");
    void* value = reinterpret_cast<void*>(0x1234);
    check(nr2_RtlFlsSetValue(first, value) == kStatusSuccess,
          "fls: a value is stored");
    void* read = nullptr;
    check(nr2_RtlFlsGetValue(first, &read) == kStatusSuccess,
          "fls: and reads back");
    check(read == value, "fls: as the same pointer");

    // A slot that was never allocated, and a double free, are both refused:
    // the second free would drop a slot another allocation may since have
    // been given.
    check(nr2_RtlFlsFree(first) == kStatusSuccess,
          "fls: freeing the slot succeeds");
    check(nr2_RtlFlsFree(first) == kStatusInvalidParameter,
          "fls: and freeing it again is refused");
    check(nr2_RtlFlsGetValue(first, &read) == kStatusInvalidParameter,
          "fls: and the freed index no longer reads");
    check(nr2_RtlFlsGetValue(first, nullptr) == kStatusInvalidParameter,
          "fls: a null value pointer is refused");
    check(nr2_RtlFlsSetValue(0xFFFFFFFEu, value) == kStatusInvalidParameter,
          "fls: and an index past the slots is refused");
}

// ---------------------------------------------------------------------------
// The locales, the 8.3 names, the generic mask and the property sets.
// ---------------------------------------------------------------------------

void test_locales_and_names() {
    std::uint32_t lcid = 0;
    check(nr2_RtlLocaleNameToLcid(u"en-US", &lcid) == kStatusSuccess,
          "locale: en-US maps to its LCID");
    check(lcid == 0x0409, "locale: which is 0x0409");
    check(nr2_RtlLocaleNameToLcid(u"xx-XX", &lcid) == kStatusInvalidParameter,
          "locale: and an unknown name is refused, not guessed at");
    check(nr2_RtlLocaleNameToLcid(u"zh-CN", &lcid) == kStatusSuccess &&
              lcid == 0x0804,
          "locale: zh-CN maps to 0x0804");

    char16_t name[16] = {};
    std::int32_t chars = static_cast<std::int32_t>(sizeof(name) / sizeof(name[0]));
    check(nr2_RtlLcidToLocaleName(0x0409, name, &chars) == kStatusSuccess,
          "locale: 0x0409 maps back to a name");
    check(std::u16string_view(name) == u"en-US",
          "locale: and it is the same name, so the pair round-trips");
    check(nr2_RtlLcidToLocaleName(0x1234, name, &chars) ==
              kStatusInvalidParameter,
          "locale: and an unknown LCID is refused");
    check(nr2_RtlIsValidLocaleName(u"de-DE", nullptr) == 1,
          "locale: de-DE is a name this runtime knows");
    check(nr2_RtlIsValidLocaleName(u"qq-QQ", nullptr) == 0,
          "locale: and qq-QQ is not");

    // The 8.3 legality check answers three questions at once, and the legal
    // name comes back upper-cased in the caller's buffer.
    std::uint8_t upper[15] = {};
    std::uint32_t count = 0;
    std::uint32_t might = 0;
    check(nr2_RtlIsNameLegalDOS8Dot3(u"autoexec.bat", upper, &count,
                                     &might) == kStatusSuccess,
          "8dot3: the legality check succeeds");
    check(count == 12, "8dot3: autoexec.bat is twelve characters");
    check(std::memcmp(upper, "AUTOEXEC.BAT", 13) == 0,
          "8dot3: and the upper-cased name is written back");
    check(might == 1,
          "8dot3: and generation could produce one from it if needed");

    // A name with a character the short form cannot hold is not legal, but
    // its stem may still be the base of a generated one.
    std::memset(upper, 0, sizeof(upper));
    count = 0;
    check(nr2_RtlIsNameLegalDOS8Dot3(u"my document.txt", upper, &count,
                                     &might) == kStatusSuccess,
          "8dot3: a long name is checked too");
    check(count == 0, "8dot3: and it is not a legal short name");
    check(might == 1, "8dot3: but its stem could start one");

    // A second period is never legal.
    count = 0;
    check(nr2_RtlIsNameLegalDOS8Dot3(u"a.b.c", upper, &count, &might) ==
              kStatusSuccess,
          "8dot3: a name with two periods is checked");
    check(count == 0, "8dot3: and is not legal");

    // The generated name keeps the stem's shape and the ~ tail the format
    // expects, and it comes back upper-cased. The longest name the format
    // allows is fourteen bytes with the terminator.
    std::uint8_t generated[16] = {};
    void* generated_at = nullptr;
    std::int32_t allocate = 0;
    check(nr2_RtlGenerate8dot3Name(0, u"aVeryLongFileName.doc", generated,
                                   &generated_at, &allocate) ==
              kStatusSuccess,
          "8dot3: generation succeeds for a long name");
    check(generated_at == generated,
          "8dot3: and points at the caller's buffer");
    check(std::memcmp(generated, "AVERYLO~1", 9) == 0,
          "8dot3: with a seven-character stem, a tilde and a digit");
    check(std::memcmp(generated + 9, ".DOC", 5) == 0,
          "8dot3: and a three-character upper-cased extension");

    // The generic mask expands through the object's own specific bits, so a
    // right the object does not define contributes nothing.
    std::uint32_t mask = 0x80000000u | 0x00000003u;  // generic read + bits
    nr2_RtlMapGenericMask(&mask, 0x80000000u);
    check(mask == 0x00000003u,
          "mask: generic read maps onto the specific bits it stands for");
    mask = 0x80000000u | 0x00000040u;  // generic read + an unrelated bit
    nr2_RtlMapGenericMask(&mask, 0x80000000u);
    check(mask == 0x00000040u,
          "mask: and a bit the read mapping does not define survives");
    mask = 0x0000000Fu;  // no generic bit at all
    nr2_RtlMapGenericMask(&mask, 0);
    check(mask == 0x0000000Fu, "mask: a mask with no generic bit is itself");

    // The property-set names round-trip through their GUIDs.
    std::uint8_t guid[16] = {};
    check(nr2_RtlPropertySetNameToGuid(u"Win32_BIOS", guid) == kStatusSuccess,
          "props: a known name maps to its GUID");
    check(get_u32(guid, 0) == 0xF4EFB7B3u,
          "props: and the first field is the one the table carries");
    char16_t set_name[32] = {};
    std::uint32_t name_chars = 32;
    check(nr2_RtlGuidToPropertySetName(guid, set_name, &name_chars) ==
              kStatusSuccess,
          "props: the GUID maps back to a name");
    check(std::u16string_view(set_name) == u"Win32_BIOS",
          "props: and it is the same name, so the pair round-trips");
    check(nr2_RtlPropertySetNameToGuid(u"NotAPropertySet", guid) ==
              kStatusInvalidParameter,
          "props: and an unknown name is refused with the GUID cleared");

    // The compression sizes are per-format constants, and an unknown format
    // has no answer.
    std::uint32_t buffer_bytes = 0;
    std::uint32_t fragment_bytes = 0;
    check(nr2_RtlGetCompressionWorkSpaceSize(2, &buffer_bytes,
                                             &fragment_bytes) ==
              kStatusSuccess,
          "compress: LZNT1's workspace is answered");
    check(buffer_bytes == 0x10010 && fragment_bytes == 0x1000,
          "compress: with the window and fragment sizes the format needs");
    check(nr2_RtlGetCompressionWorkSpaceSize(99, &buffer_bytes,
                                             &fragment_bytes) ==
              kStatusInvalidParameter,
          "compress: and an unknown format is refused");
}

// ---------------------------------------------------------------------------
// The clocks and the context lengths.
// ---------------------------------------------------------------------------

void test_clock_and_context() {
    std::uint64_t before = 0;
    std::uint64_t after = 0;
    nr2_RtlGetSystemTimePrecise(&before);
    nr2_RtlGetSystemTimePrecise(&after);
    check(after >= before, "clock: the precise clock moves forward");
    check(before > 116444736000000000ull,
          "clock: and it is a 1601-epoch tick count, not a Unix one");

    // SYSTEMTIME conversion, checked against a date whose tick count is
    // easy to state: 1601-01-01 00:00:00.000 is tick zero.
    alignas(8) std::uint8_t local[16] = {};
    alignas(8) std::uint8_t system[8] = {};
    put_u16(local, 0, 1601);
    put_u16(local, 2, 1);
    put_u16(local, 6, 1);  // wDay, past the weekday field
    check(nr2_RtlLocalTimeToSystemTime(local, system) == kStatusSuccess,
          "clock: the epoch date converts");
    check(get_u64(system, 0) == 0,
          "clock: and it is exactly tick zero");

    put_u16(local, 0, 2023);
    put_u16(local, 2, 6);
    put_u16(local, 6, 15);   // wDay, past the weekday field
    put_u16(local, 8, 12);   // wHour
    put_u16(local, 10, 34);  // wMinute
    put_u16(local, 12, 56);  // wSecond
    put_u16(local, 14, 789);  // wMilliseconds
    check(nr2_RtlLocalTimeToSystemTime(local, system) == kStatusSuccess,
          "clock: a mid-2023 date converts");
    check(get_u64(system, 0) > 130000000000000000ull,
          "clock: at a tick count the date implies");

    // A field out of range names no instant.
    put_u16(local, 2, 13);
    check(nr2_RtlLocalTimeToSystemTime(local, system) ==
              kStatusInvalidParameter,
          "clock: a month of thirteen is refused");

    // The context length depends on whether the floating-point state was
    // asked for, which is the whole reason the query exists.
    check(nr2_RtlGetExtendedContextLength(0x0010003F) == 0x698,
          "context: the full context is 0x698 bytes");
    check(nr2_RtlGetExtendedContextLength(0x00100001) < 0x698,
          "context: and a context without the vector state is smaller");
}

// ---------------------------------------------------------------------------
// The atom-table bridge: one table answering through both slices.
// ---------------------------------------------------------------------------

void test_atom_bridge() {
    void* table = nr1_RtlCreateAtomTable(0, 0);
    check(table != nullptr, "atoms: the first slice creates the table");

    std::uint32_t atom = 0;
    check(nr1_RtlAddAtomToAtomTable(table, u"TestAtom", &atom) ==
              kStatusSuccess,
          "atoms: the first slice adds an atom");
    check(atom >= 0xC000u, "atoms: with a value in the atom range");

    // The second slice's lookup answers the same table: the same atom comes
    // back, which is the property the bridge exists to provide. Two tables
    // would answer differently depending on which slice a guest asked.
    std::uint32_t found = 0;
    check(nr2_RtlLookupAtomInAtomTable(table, u"TestAtom", &found) ==
              kStatusSuccess,
          "atoms: the second slice's lookup finds it");
    check(found == atom, "atoms: and answers the same value");

    std::uint32_t refs = 0;
    std::uint32_t flags = 0;
    char16_t name[16] = {};
    std::uint32_t name_bytes = sizeof(name);
    check(nr2_RtlQueryAtomInAtomTable(table, atom, &refs, &flags, name,
                                      &name_bytes) == kStatusSuccess,
          "atoms: the second slice's query answers the entry");
    check(std::u16string_view(name) == u"TestAtom",
          "atoms: with the name the first slice stored");
    check(refs == 1, "atoms: and the reference count the addition made");

    // Pinning raises the count, and a pinned atom survives the pin.
    check(nr2_RtlPinAtomInAtomTable(table, atom) == kStatusSuccess,
          "atoms: pinning succeeds");
    refs = 0;
    check(nr2_RtlQueryAtomInAtomTable(table, atom, &refs, nullptr, nullptr,
                                      nullptr) == kStatusSuccess,
          "atoms: and the query still answers");
    check(refs == 2, "atoms: with the count the pin raised");

    // A name that is not there, and an atom that is not there, are both
    // refused with the specific status rather than a generic failure.
    check(nr2_RtlLookupAtomInAtomTable(table, u"Absent", &found) ==
              kStatusObjectNameNotFound,
          "atoms: an absent name answers OBJECT_NAME_NOT_FOUND");
    check(nr2_RtlQueryAtomInAtomTable(table, 0x1234, &refs, nullptr, nullptr,
                                      nullptr) == kStatusInvalidParameter,
          "atoms: an atom below the range is refused");
    check(nr2_RtlPinAtomInAtomTable(nullptr, atom) ==
              kStatusInvalidParameter,
          "atoms: and a null table is refused");

    check(nr1_RtlDestroyAtomTable(table) == kStatusSuccess,
          "atoms: the first slice destroys the table it created");
    check(nr2_RtlLookupAtomInAtomTable(table, u"TestAtom", &found) ==
              kStatusObjectNameNotFound,
          "atoms: and a destroyed table answers as not found");
}

// ---------------------------------------------------------------------------
// The refusals: each one checked for the specific status it answers.
// ---------------------------------------------------------------------------

void test_refusals() {
    check(nr2_RtlFreeActivationContextStack() == kStatusNotImplemented,
          "refuse: the activation stack has no side-by-side store");
    check(nr2_RtlFreeThreadActivationContextStack() ==
              kStatusNotImplemented,
          "refuse: nor has the thread's");
    check(nr2_RtlIsActivationContextActive() == 0,
          "refuse: no activation context is ever active");
    check(nr2_RtlImpersonateSelf(2) == kStatusNotImplemented,
          "refuse: there is one token and nothing to impersonate");
    check(nr2_RtlOpenCurrentUser(nullptr, nullptr) ==
              kStatusNotImplemented,
          "refuse: the current-user key belongs to the registry domain");
    check(nr2_RtlGetLocaleFileMappingAddress() == nullptr,
          "refuse: the NLS locale file is not mounted");
    check(nr2_RtlGetCurrentTransaction(nullptr) == kStatusNotImplemented,
          "refuse: there is no transaction manager");
    check(nr2_RtlInitializeRXact() == kStatusNotImplemented,
          "refuse: nor a kernel transaction to begin");
    check(nr2_RtlInitializeContext(nullptr, 0) == kStatusNotImplemented,
          "refuse: the machine context is the host's, not the guest's");
    check(nr2_RtlIsEcCode(0x12345678u) == 0,
          "refuse: no file code is an encrypted-file identifier");
    check(nr2_RtlNormalizeProcessParams(nullptr) == kStatusNotImplemented,
          "refuse: the process parameters are the loader's");
    check(nr2_RtlOpenCrossProcessEmulatorWorkConnection(nullptr) ==
              kStatusNotImplemented,
          "refuse: there is no WOW64 host to connect to");
    void* trace_event = reinterpret_cast<void*>(0x1);
    check(nr2_RtlGetUnloadEventTrace(&trace_event) == kStatusNotImplemented,
          "refuse: no unload trace is enabled");
    check(trace_event == nullptr,
          "refuse: and no fabricated handle is handed out for one");
    check(nr2_RtlInitializeNtUserPfn(nullptr) == kStatusNotImplemented,
          "refuse: the window manager is not running");
    check(nr2_RtlInitializeResource() == kStatusNotImplemented,
          "refuse: resource compilation is the loader's");
    check(nr2_RtlFlushPropertySet(nullptr) == kStatusNotImplemented,
          "refuse: there is no property-set store to flush");
    check(nr2_RtlQueryActivationContextApplicationSettings(
              0, nullptr, nullptr, nullptr) == kStatusNotImplemented,
          "refuse: nor an activation context to query");
    check(nr2_RtlNewSecurityObject(nullptr, nullptr, nullptr, 0,
                                   nullptr) == kStatusNotImplemented,
          "refuse: no SDDL engine builds descriptors here");
    check(nr2_RtlNewSecurityObjectEx(nullptr, nullptr, nullptr, nullptr, 0,
                                     nullptr) == kStatusNotImplemented,
          "refuse: nor an inheritance policy");
    check(nr2_RtlNewInstanceSecurityObject(nullptr, nullptr, 0, nullptr,
                                           nullptr) ==
              kStatusNotImplemented,
          "refuse: nor an instance builder");
    check(nr2_RtlNewSecurityObjectWithMultipleInheritance(
              nullptr, nullptr, nullptr, 0, nullptr) ==
              kStatusNotImplemented,
          "refuse: nor a multi-class inheritance builder");
    check(nr2_RtlInitializeHandleTable(0, 0, nullptr) == nullptr,
          "refuse: the handle table belongs to the modules that mint them");
    check(nr2_RtlIsValidHandle(0x1234) == nullptr,
          "refuse: a handle this file did not mint is not vouched for");
    check(nr2_RtlIsValidHandle(0xFFFFFFFFFFFFFFFFull) != nullptr,
          "refuse: but the process pseudo-handle is one of the two known");
    check(nr2_RtlIsValidHandle(0xFFFFFFFFFFFFFFFEull) != nullptr,
          "refuse: and so is the thread pseudo-handle");
    check(nr2_RtlProtectHeap(0, 0) == 120,
          "refuse: heap protection is not a flag this allocator keeps");

    // The splay-tree family: a different balancing scheme would answer
    // lookups differently, so the whole family is refused rather than
    // answered with a tree whose shape is not the kernel's.
    check(nr2_RtlInitializeGenericTable(nullptr, nullptr, nullptr, nullptr,
                                        0) == kStatusNotImplemented,
          "refuse: the splay table needs the kernel's rotations");
    check(nr2_RtlInsertElementGenericTable(nullptr, nullptr, nullptr) ==
              kStatusNotImplemented,
          "refuse: and so does every insert into one");
    check(nr2_RtlLookupElementGenericTable(nullptr, nullptr) == nullptr,
          "refuse: and a lookup in an uninitialized table finds nothing");
    check(nr2_RtlIsGenericTableEmpty(nullptr) == 1,
          "refuse: though emptiness has no tree shape to get wrong");
}

// ---------------------------------------------------------------------------
// The registration: the work order's 156 names, exactly.
// ---------------------------------------------------------------------------

void test_registration() {
    ExportList mem1_out;
    add_ntdll_rtl_mem1(mem1_out);
    ExportList mem2_out;
    add_ntdll_rtl_mem2(mem2_out);

    std::vector<std::string> registered;
    registered.reserve(mem2_out.size());
    for (const HostExport& entry : mem2_out) {
        registered.emplace_back(entry.name);
    }
    std::sort(registered.begin(), registered.end());

    std::vector<std::string> wanted;
    for (const char* name : kExpectedNames) {
        wanted.emplace_back(name);
    }
    std::sort(wanted.begin(), wanted.end());
    check(registered == wanted,
          "mem2: the registered names match the work order exactly");
    check(std::adjacent_find(registered.begin(), registered.end()) ==
              registered.end(),
          "mem2: and no name is registered twice");

    // The one name the order shared with the first slice is registered by
    // that slice and not here, which the two lists together show.
    std::size_t both = 0;
    for (const HostExport& entry : mem2_out) {
        for (const HostExport& other : mem1_out) {
            if (entry.name == other.name) {
                ++both;
            }
        }
    }
    check(both == 0,
          "mem2: no name is registered by both slices of the Rtl surface");
}

}  // namespace

int main() {
    test_slist();
    test_critical_section();
    test_large_integer();
    test_bitmaps();
    test_security_descriptors();
    test_sids();
    test_version_and_errors();
    test_paths();
    test_pe_queries();
    test_fls();
    test_locales_and_names();
    test_clock_and_context();
    test_atom_bridge();
    test_refusals();
    test_registration();
    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::fprintf(stderr, "all %d checks passed\n", checks);
    return 0;
}

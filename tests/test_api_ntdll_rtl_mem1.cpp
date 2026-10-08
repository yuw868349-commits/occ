// The Rtl* memory-family slice, first alphabetical segment.
//
// The tests below assert behaviour that distinguishes implementations, not
// "the call ran": the bitmap bit order is pinned by reading the guest's own
// ULONG words after a set, the CRC is pinned against the standard test
// vector, and every refusal is checked for the specific status it answers
// rather than for "not success". Registration is checked name-by-name
// against the work order's 156 names, because a typo in a registration list
// is otherwise a missing export the loader reports and nothing here catches.

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
}

// ---------------------------------------------------------------------------
// Entry points under test. Declared here because the tests are the reason
// they are visible, and the main line wires the domain into api.h.
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) void* nr1_RtlCreateHeap(
    std::uint32_t flags, void* base, std::uint64_t reserve,
    std::uint64_t commit, void* lock, void* parameters) noexcept;
extern "C" __attribute__((ms_abi)) void* nr1_RtlDestroyHeap(
    void* heap) noexcept;
extern "C" __attribute__((ms_abi)) void* nr1_RtlAllocateHeap(
    void* heap, std::uint32_t flags, std::uint64_t size) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t nr1_RtlCompactHeap(
    void* heap, std::uint32_t flags) noexcept;
extern "C" __attribute__((ms_abi)) void* nr1_RtlExtendHeap(
    void* heap, std::uint32_t flags, void* base, std::uint64_t bytes) noexcept;
extern "C" typedef std::int32_t (__attribute__((ms_abi)) *EnumHeapsCb)(
    void* heap, void* parameter) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlEnumProcessHeaps(
    EnumHeapsCb callback, void* parameter) noexcept;

extern "C" __attribute__((ms_abi)) std::uint8_t nr1_RtlAreBitsSet(
    const void* header, std::uint32_t index, std::uint32_t count) noexcept;
extern "C" __attribute__((ms_abi)) std::uint8_t nr1_RtlAreBitsClear(
    const void* header, std::uint32_t index, std::uint32_t count) noexcept;
extern "C" __attribute__((ms_abi)) void nr1_RtlClearAllBits(
    void* header) noexcept;
extern "C" __attribute__((ms_abi)) void nr1_RtlClearBits(
    void* header, std::uint32_t index, std::uint32_t count) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlFindClearBits(
    const void* header, std::uint32_t count, std::uint32_t hint) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlFindClearBitsAndSet(
    const void* header, std::uint32_t count, std::uint32_t hint) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlFindClearRuns(
    const void* header, void* runs_out, std::uint32_t run_count,
    std::uint32_t find_longest) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlFindLongestRunClear(
    const void* header, std::uint32_t* first) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlFindLongestRunSet(
    const void* header, std::uint32_t* first) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlFindNextForwardRunClear(
    const void* header, std::uint32_t from, std::uint32_t* first) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
nr1_RtlFindLastBackwardRunClear(const void* header, std::uint32_t from,
                                std::uint32_t* first) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlFindMostSignificantBit(
    std::uint64_t value) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlFindLeastSignificantBit(
    std::uint64_t value) noexcept;

extern "C" __attribute__((ms_abi)) std::uint64_t nr1_RtlConvertLongToLargeInteger(
    std::int32_t value) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t
nr1_RtlConvertUlongToLargeInteger(std::uint32_t value) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t nr1_RtlEnlargedIntegerMultiply(
    std::int32_t left, std::int32_t right) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t
nr1_RtlEnlargedUnsignedMultiply(std::uint32_t left,
                                std::uint32_t right) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t nr1_RtlEnlargedUnsignedDivide(
    std::uint64_t dividend, std::uint32_t divisor,
    std::uint32_t* remainder) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t nr1_RtlExtendedIntegerMultiply(
    std::uint64_t multiplicand, std::int32_t multiplier) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t
nr1_RtlExtendedLargeIntegerDivide(std::uint64_t dividend, std::int32_t divisor,
                                  std::int32_t* remainder) noexcept;

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlAreAllAccessesGranted(
    std::uint32_t desired, std::uint32_t granted) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlAreAnyAccessesGranted(
    std::uint32_t desired, std::uint32_t granted) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlEqualLuid(
    const void* left, const void* right) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlComputeCrc32(
    std::uint32_t initial, const std::uint8_t* data,
    std::uint32_t length) noexcept;
extern "C" __attribute__((ms_abi)) void* nr1_RtlEncodePointer(
    void* pointer) noexcept;
extern "C" __attribute__((ms_abi)) void* nr1_RtlDecodePointer(
    void* pointer) noexcept;
extern "C" __attribute__((ms_abi)) void* nr1_RtlEncodeSystemPointer(
    void* pointer) noexcept;
extern "C" __attribute__((ms_abi)) void* nr1_RtlDecodeSystemPointer(
    void* pointer) noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlEnterCriticalSection(
    void* critical_section) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDeleteCriticalSection(
    void* critical_section) noexcept;
extern "C" __attribute__((ms_abi)) void nr1_RtlAcquirePebLock() noexcept;
extern "C" __attribute__((ms_abi)) void nr1_RtlAcquireSRWLockExclusive(
    void* lock) noexcept;
extern "C" __attribute__((ms_abi)) void nr1_RtlAcquireSRWLockShared(
    void* lock) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
nr1_RtlAcquireResourceExclusive(void* resource, std::uint32_t wait) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlAcquireResourceShared(
    void* resource, std::uint32_t wait) noexcept;
extern "C" __attribute__((ms_abi)) void nr1_RtlDeleteResource(
    void* resource) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t
nr1_RtlConvertExclusiveToShared(void* resource) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t
nr1_RtlConvertSharedToExclusive(void* resource) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlBarrier(
    void* barrier, std::uint32_t flags) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDeleteBarrier(
    void* barrier) noexcept;
extern "C" __attribute__((ms_abi)) void nr1_RtlDumpResource(
    const void* resource) noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCreateAcl(
    void* acl, std::uint32_t size, std::uint32_t revision) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddAccessAllowedAce(
    void* acl, std::uint32_t revision, std::uint32_t mask,
    const void* sid) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddAccessDeniedAce(
    void* acl, std::uint32_t revision, std::uint32_t mask,
    const void* sid) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddAce(
    void* acl, std::uint32_t revision, std::uint32_t index,
    const void* ace_list, std::uint32_t list_bytes) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDeleteAce(
    void* acl, std::uint32_t index) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddMandatoryAce(
    void* acl, std::uint32_t revision, std::uint32_t flags,
    std::uint32_t mandatory_policy, std::uint8_t ace_type,
    const void* sid) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCreateSecurityDescriptor(
    void* descriptor, std::uint32_t revision) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t
nr1_RtlAbsoluteToSelfRelativeSD(const void* descriptor, void* self_relative,
                                std::uint32_t* buffer_length) noexcept;
extern "C" __attribute__((ms_abi)) void* nr1_RtlAllocateAndInitializeSid(
    const void* identifier_authority, std::uint32_t sub_authority_count,
    std::uint32_t sub0, std::uint32_t sub1, std::uint32_t sub2,
    std::uint32_t sub3, std::uint32_t sub4, std::uint32_t sub5,
    std::uint32_t sub6, std::uint32_t sub7) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlEqualSid(
    const void* left, const void* right) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlEqualPrefixSid(
    const void* left, const void* right) noexcept;

extern "C" __attribute__((ms_abi)) std::uint32_t
nr1_RtlDetermineDosPathNameType_U(const char16_t* path) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlDosPathNameToNtPathName_U(
    const char16_t* dos, void* nt_name, std::uint32_t* file_part,
    void* relative_name) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t
nr1_RtlDosPathNameToNtPathName_U_WithStatus(const char16_t* dos,
                                            void* nt_name,
                                            std::uint32_t* file_part,
                                            void* relative_name) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlDoesFileExists_U(
    const char16_t* path) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlEqualComputerName(
    const void* left, const void* right) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlEqualDomainName(
    const void* left, const void* right) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
nr1_RtlDllShutdownInProgress() noexcept;
extern "C" __attribute__((ms_abi)) void* nr1_RtlAddressInSectionTable(
    const void* nt_headers, const void* base, std::uint32_t rva) noexcept;
extern "C" __attribute__((ms_abi)) void* nr1_RtlFindExportedRoutineByName(
    const void* image_base, const char* name) noexcept;

extern "C" __attribute__((ms_abi)) void* nr1_RtlCreateAtomTable(
    std::uint32_t flags, std::uint32_t buckets) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDestroyAtomTable(
    void* table) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddAtomToAtomTable(
    void* table, const char16_t* name, std::uint32_t* atom_out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDeleteAtomFromAtomTable(
    void* table, std::uint32_t atom) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlEmptyAtomTable(
    void* table, std::uint32_t include_pinned) noexcept;

extern "C" __attribute__((ms_abi)) void* nr1_RtlAddVectoredExceptionHandler(
    std::uint32_t first, void* handler) noexcept;
extern "C" __attribute__((ms_abi)) void* nr1_RtlAddVectoredContinueHandler(
    std::uint32_t first, void* handler) noexcept;

extern "C" __attribute__((ms_abi)) void nr1_RtlAssert(
    const void* failed_assertion, const void* file_name,
    std::uint32_t line_number, const char* message) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlCaptureStackBackTrace(
    std::uint32_t frames_to_skip, std::uint32_t frames_to_capture,
    void** back_trace, std::uint32_t* back_trace_hash) noexcept;

// Refusals under test, one per refusal shape.
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAbortRXact(
    void* rxact_context) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCompressBuffer(
    std::uint16_t format, const void* source, std::uint32_t source_length,
    void* destination, std::uint32_t destination_length,
    std::uint32_t chunk_size, std::uint32_t* final_size,
    void* workspace) noexcept;
extern "C" __attribute__((ms_abi)) void* nr1_RtlCreateTagHeap(
    void* heap, std::uint32_t flags, const char16_t* tag_prefix,
    const char16_t* tag_names) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t nr1_RtlExtendedMagicDivide(
    std::uint64_t value, std::uint64_t magic_divisor,
    std::int32_t shift) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlDosSearchPath_U(
    const char16_t* path, const char16_t* file, const char16_t* extension,
    char16_t* result) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
nr1_RtlDosPathNameToRelativeNtPathName_U(const char16_t* dos, void* nt_name,
                                         std::uint32_t* file_part,
                                         void* relative_name) noexcept;

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

constexpr std::int32_t kStatusSuccess = 0;
constexpr std::int32_t kStatusNotImplemented =
    static_cast<std::int32_t>(0xC0000002u);
constexpr std::int32_t kStatusInvalidParameter =
    static_cast<std::int32_t>(0xC000000Du);
constexpr std::int32_t kStatusInvalidHandle =
    static_cast<std::int32_t>(0xC0000008u);
constexpr std::int32_t kStatusInvalidAcl =
    static_cast<std::int32_t>(0xC0000077u);
constexpr std::int32_t kStatusInvalidSid =
    static_cast<std::int32_t>(0xC0000078u);
constexpr std::int32_t kStatusBufferTooSmall =
    static_cast<std::int32_t>(0xC0000023u);
constexpr std::int32_t kStatusRevisionMismatch =
    static_cast<std::int32_t>(0xC0000059u);
constexpr std::int32_t kStatusUnknownRevision =
    static_cast<std::int32_t>(0xC0000091u);
constexpr std::uint32_t kBitmapError = 0xFFFFFFFFu;

constexpr std::uint32_t kHeapZeroMemory = 0x00000008;

void put_u32(void* base, std::size_t offset, std::uint32_t value) {
    std::memcpy(static_cast<std::uint8_t*>(base) + offset, &value, 4);
}

// A buffer registered as a mapped image region, so that the PE walkers can
// be given one to bound themselves against.
//
// The state the runtime keeps is the running guest's, so the fixture
// installs one for the duration and puts the previous one back on the way
// out. A test that left a fixture in it would answer the next test's
// questions about a buffer that is no longer there.
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

void put_u16(void* base, std::size_t offset, std::uint16_t value) {
    std::memcpy(static_cast<std::uint8_t*>(base) + offset, &value, 2);
}

void put_u8(void* base, std::size_t offset, std::uint8_t value) {
    std::memcpy(static_cast<std::uint8_t*>(base) + offset, &value, 1);
}

std::uint32_t get_u32(const void* base, std::size_t offset) {
    std::uint32_t value = 0;
    std::memcpy(&value, static_cast<const std::uint8_t*>(base) + offset, 4);
    return value;
}

std::uint16_t get_u16(const void* base, std::size_t offset) {
    std::uint16_t value = 0;
    std::memcpy(&value, static_cast<const std::uint8_t*>(base) + offset, 2);
    return value;
}

// A guest bitmap: the header the RTL_BITMAP spells, plus a word array big
// enough for 256 bits. The words are read back raw, which is what pins the
// bit order.
struct TestBitmap {
    std::uint8_t header[16] = {};
    std::uint32_t words[8] = {};

    void init(std::uint32_t bit_count) {
        std::memset(words, 0, sizeof(words));
        write_u32(header, 0, bit_count);
        write_ptr(header, 8, reinterpret_cast<std::uint64_t>(words));
    }
};

// Guest UNICODE_STRING, written by hand.
struct TestUnicodeString {
    std::uint8_t bytes[16] = {};
    std::u16string text;

    void set(const char16_t* value) {
        text = value;
        std::memset(bytes, 0, sizeof(bytes));
        put_u16(bytes, 0, static_cast<std::uint16_t>(text.size() * 2));
        put_u16(bytes, 2, static_cast<std::uint16_t>(text.size() * 2 + 2));
        write_ptr(bytes, 8, reinterpret_cast<std::uint64_t>(text.data()));
    }
};

// ------------------------------------------------------------------- heaps

std::uint64_t g_last_heap_seen = 0;

extern "C" __attribute__((ms_abi)) std::int32_t enum_heap_callback(
    void* heap, void* parameter) noexcept {
    auto* hits = static_cast<std::uint32_t*>(parameter);
    ++*hits;
    g_last_heap_seen = reinterpret_cast<std::uint64_t>(heap);
    return 1;
}

void test_heaps() {
    void* heap = nr1_RtlCreateHeap(0, nullptr, 0x10000, 0x1000, nullptr,
                                   nullptr);
    check(heap != nullptr, "rtl_mem1: a section-less heap is created");

    // Zeroed allocation: the bytes are zero, which is the observable the
    // flag exists for.
    auto* zeroed = static_cast<std::uint8_t*>(
        nr1_RtlAllocateHeap(heap, kHeapZeroMemory, 64));
    check(zeroed != nullptr, "rtl_mem1: a zeroed allocation returns a block");
    bool all_zero = true;
    for (std::size_t i = 0; i < 64; ++i) {
        all_zero = all_zero && zeroed[i] == 0;
    }
    check(all_zero, "rtl_mem1: and its bytes are zero");
    zeroed[0] = 0xAB;  // writable

    auto* plain = static_cast<std::uint8_t*>(nr1_RtlAllocateHeap(heap, 0, 32));
    check(plain != nullptr, "rtl_mem1: a plain allocation returns a block");
    std::memset(plain, 0x5A, 32);

    // A zero-byte allocation succeeds on Windows and must not hand back a
    // pointer the caller treats as failure. The block is kept and freed with
    // the others: a test that drops it leaks it, which a leak-checked run
    // reports against the whole file.
    void* zero_byte = nr1_RtlAllocateHeap(heap, 0, 0);
    check(zero_byte != nullptr,
          "rtl_mem1: a zero-byte allocation still succeeds");
    void* from_process_heap = nr1_RtlAllocateHeap(nullptr, 0, 16);
    check(from_process_heap != nullptr,
          "rtl_mem1: the process heap answers a null handle");
    check(nr1_RtlAllocateHeap(reinterpret_cast<void*>(0xDEAD0000ULL), 0, 16) ==
              nullptr,
          "rtl_mem1: an unknown heap handle is refused");
    check(nr1_RtlCompactHeap(heap, 0) == 0,
          "rtl_mem1: compaction reports zero bytes moved");
    check(nr1_RtlExtendHeap(heap, 0, nullptr, 0x1000) == nullptr,
          "rtl_mem1: extending a host-backed heap is refused");
    // Everything this test allocated comes back before the heap goes, so a
    // leak-checked build ends the file with nothing outstanding.
    winabi::heap_free(zeroed);
    winabi::heap_free(plain);
    winabi::heap_free(zero_byte);
    winabi::heap_free(from_process_heap);
    check(nr1_RtlDestroyHeap(nullptr) == nullptr,
          "rtl_mem1: destroying the process heap is refused in place");
    check(nr1_RtlDestroyHeap(heap) == nullptr,
          "rtl_mem1: destroying a created heap answers null");

    // Enumeration sees the process heap at minimum; the created heap from
    // this test was destroyed above, so the callback runs exactly once.
    std::uint32_t hits = 0;
    const std::uint32_t counted =
        nr1_RtlEnumProcessHeaps(&enum_heap_callback, &hits);
    check(counted >= 1, "rtl_mem1: enumeration counts at least one heap");
    check(counted == hits, "rtl_mem1: and the callback saw each one");
    check(g_last_heap_seen == process_heap_handle(),
          "rtl_mem1: the process heap is among them");
}

// ----------------------------------------------------------------- bitmaps

void test_bitmaps() {
    TestBitmap bm;
    bm.init(64);
    // Bits 0 and 1 set: MSB-first, that is the two high bits of word zero.
    bm.words[0] = 0xC0000000u;

    check(nr1_RtlAreBitsSet(bm.header, 0, 2) == 1,
          "rtl_mem1: the two set bits are set");
    check(nr1_RtlAreBitsSet(bm.header, 0, 3) == 0,
          "rtl_mem1: a run crossing an unset bit is not all set");
    check(nr1_RtlAreBitsClear(bm.header, 2, 62) == 1,
          "rtl_mem1: the rest of the bitmap is clear");
    check(nr1_RtlAreBitsSet(bm.header, 60, 10) == 0,
          "rtl_mem1: a range past the end is refused, not read");

    check(nr1_RtlFindClearBits(bm.header, 1, 2) == 2,
          "rtl_mem1: the first clear bit from the hint is bit 2");
    check(nr1_RtlFindClearBits(bm.header, 62, 2) == 2,
          "rtl_mem1: and the whole clear run starts there");
    check(nr1_RtlFindClearBits(bm.header, 63, 2) == kBitmapError,
          "rtl_mem1: a run longer than any that exists is not found");

    // Find-and-set, then read the guest's words back: bits 2..6 of an
    // MSB-first ULONG are 0x3E000000.
    check(nr1_RtlFindClearBitsAndSet(bm.header, 5, 2) == 2,
          "rtl_mem1: find-and-set returns the run it claimed");
    check(bm.words[0] == 0xFE000000u,
          "rtl_mem1: and the guest's words carry the MSB-first bits");

    std::uint32_t first = 99;
    check(nr1_RtlFindLongestRunClear(bm.header, &first) == 57,
          "rtl_mem1: the longest clear run spans the remaining bits");
    check(first == 7, "rtl_mem1: and starts at bit 7");
    check(nr1_RtlFindNextForwardRunClear(bm.header, 0, &first) == 57,
          "rtl_mem1: the first forward clear run is the same one");
    check(nr1_RtlFindLastBackwardRunClear(bm.header, 63, &first) == 57,
          "rtl_mem1: the backward scan from the end finds it too");

    nr1_RtlClearBits(bm.header, 0, 1);
    check(nr1_RtlAreBitsClear(bm.header, 0, 1) == 1,
          "rtl_mem1: clearing bit 0 leaves it clear");
    check(bm.words[0] == 0x7E000000u,
          "rtl_mem1: and the guest's word shows the cleared top bit");

    nr1_RtlClearAllBits(bm.header);
    check(nr1_RtlAreBitsSet(bm.header, 0, 64) == 0,
          "rtl_mem1: nothing is set after clear-all");
    check(nr1_RtlFindLongestRunSet(bm.header, &first) == 0,
          "rtl_mem1: no set run exists");
    check(nr1_RtlFindClearBitsAndSet(bm.header, 64, 0) == 0,
          "rtl_mem1: the whole bitmap can be claimed at once");
    check(nr1_RtlFindLongestRunSet(bm.header, &first) == 64 && first == 0,
          "rtl_mem1: and the longest set run is the whole bitmap");

    // The MSB-first order across words: bit 33 lands in word 1 at position
    // 30, which is 0x40000000 -- the assertion that catches an LSB-first
    // implementation.
    nr1_RtlClearAllBits(bm.header);
    check(nr1_RtlFindClearBitsAndSet(bm.header, 1, 33) == 33,
          "rtl_mem1: a bit past the first word is found");
    check(bm.words[1] == 0x40000000u,
          "rtl_mem1: and lands at word 1, bit position 30 (MSB-first)");

    // Runs: set bits 0-3, 8-11 and 20 directly, then read the run list both
    // ways.
    nr1_RtlClearAllBits(bm.header);
    bm.words[0] = 0xF0F00800u;
    std::uint8_t runs[8 * 8] = {};
    const std::uint32_t found = nr1_RtlFindClearRuns(bm.header, runs, 8, 0);
    check(found == 3, "rtl_mem1: the bitmap splits into three clear runs");
    if (found == 3) {
        check(get_u32(runs, 0) == 4 && get_u32(runs, 4) == 4,
              "rtl_mem1: the first run is 4..7");
        check(get_u32(runs, 16) == 21 && get_u32(runs, 20) == 43,
              "rtl_mem1: the last run is 21..63");
    }
    const std::uint32_t longest = nr1_RtlFindClearRuns(bm.header, runs, 8, 1);
    check(longest == 3 && get_u32(runs, 4) == 43,
          "rtl_mem1: longest-first ordering puts the 43-bit run first");
    check(nr1_RtlFindClearRuns(bm.header, nullptr, 8, 0) == 0,
          "rtl_mem1: no output buffer, no runs");

    check(nr1_RtlFindMostSignificantBit(0) == -1,
          "rtl_mem1: no significant bit in zero");
    check(nr1_RtlFindMostSignificantBit(1ULL << 40) == 40,
          "rtl_mem1: bit 40 is the most significant of its power");
    check(nr1_RtlFindLeastSignificantBit(0x100) == 8,
          "rtl_mem1: bit 8 is the least significant set bit");
    check(nr1_RtlFindLeastSignificantBit(0) == -1,
          "rtl_mem1: zero has no least significant bit");

    // A null header is refused, not dereferenced.
    check(nr1_RtlAreBitsSet(nullptr, 0, 1) == 0,
          "rtl_mem1: a null bitmap header answers false");
    check(nr1_RtlFindLongestRunClear(nullptr, nullptr) == 0,
          "rtl_mem1: and the longest-run scan answers zero");
}

// ------------------------------------------------------------ integer math

void test_integer_math() {
    check(nr1_RtlConvertLongToLargeInteger(-1) == 0xFFFFFFFFFFFFFFFFULL,
          "rtl_mem1: -1 sign-extends to all ones");
    check(nr1_RtlConvertUlongToLargeInteger(0x80000000u) == 0x80000000ULL,
          "rtl_mem1: an unsigned long zero-extends");
    check(nr1_RtlEnlargedIntegerMultiply(-3, 5) ==
              static_cast<std::uint64_t>(-15LL),
          "rtl_mem1: a signed 32x32 product is -15");
    check(nr1_RtlEnlargedUnsignedMultiply(0x10000u, 0x10000u) ==
              0x100000000ULL,
          "rtl_mem1: an unsigned product can reach bit 32");
    std::uint32_t rem = 99;
    check(nr1_RtlEnlargedUnsignedDivide(0x100000001ULL, 2, &rem) ==
              0x80000000ULL,
          "rtl_mem1: the 64-bit quotient is exact");
    check(rem == 1, "rtl_mem1: and the remainder is one");
    check(nr1_RtlEnlargedUnsignedDivide(5, 0, &rem) == 0,
          "rtl_mem1: division by zero answers zero instead of faulting");
    check(rem == 0, "rtl_mem1: with a defined remainder");
    check(nr1_RtlExtendedIntegerMultiply(0xFFFFFFFFFFFFFFFFULL, 7) ==
              0xFFFFFFFFFFFFFFF9ULL,
          "rtl_mem1: -1 times 7 is -7");
    std::int32_t signed_rem = 0;
    check(nr1_RtlExtendedLargeIntegerDivide(static_cast<std::uint64_t>(-10LL),
                                            3, &signed_rem) ==
              static_cast<std::uint64_t>(-3LL),
          "rtl_mem1: -10 / 3 is -3");
    check(signed_rem == -1, "rtl_mem1: and the remainder is -1");
}

// -------------------------------------------------- access masks and CRC

void test_access_and_crc() {
    check(nr1_RtlAreAllAccessesGranted(0x1Fu, 0x1Fu) == 1,
          "rtl_mem1: every bit granted passes the all test");
    check(nr1_RtlAreAllAccessesGranted(0x1Fu, 0x0Fu) == 0,
          "rtl_mem1: one missing bit fails it");
    check(nr1_RtlAreAnyAccessesGranted(0x10u, 0x01u) == 0,
          "rtl_mem1: no overlap, no access");
    check(nr1_RtlAreAnyAccessesGranted(0x11u, 0x01u) == 1,
          "rtl_mem1: one shared bit is access");

    const std::uint64_t luid_a = 0x000003E900000123ULL;
    const std::uint64_t luid_b = 0x000003E900000124ULL;
    check(nr1_RtlEqualLuid(&luid_a, &luid_a) == 1,
          "rtl_mem1: a LUID equals itself");
    check(nr1_RtlEqualLuid(&luid_a, &luid_b) == 0,
          "rtl_mem1: a different LUID does not compare equal");
    check(nr1_RtlEqualLuid(nullptr, &luid_a) == 0,
          "rtl_mem1: a null LUID pointer compares unequal");

    const std::uint8_t payload[] = "123456789";
    check(nr1_RtlComputeCrc32(0, payload, 9) == 0xCBF43926u,
          "rtl_mem1: the CRC-32 check value of 123456789");
    const std::uint32_t chained = nr1_RtlComputeCrc32(
        nr1_RtlComputeCrc32(0, payload, 4), payload + 4, 5);
    check(chained == 0xCBF43926u,
          "rtl_mem1: the CRC chains across calls to the same value");
}

// -------------------------------------------------------- pointer encoding

void test_pointer_encoding() {
    void* raw = reinterpret_cast<void*>(0x00007FFEEF000123ULL);
    void* encoded = nr1_RtlEncodePointer(raw);
    check(encoded != raw, "rtl_mem1: an encoded pointer differs from its raw");
    check(nr1_RtlDecodePointer(encoded) == raw,
          "rtl_mem1: and decodes back to it");
    void* encoded_system = nr1_RtlEncodeSystemPointer(raw);
    check(nr1_RtlDecodeSystemPointer(encoded_system) == raw,
          "rtl_mem1: the system-pointer pair round-trips too");
    check(nr1_RtlEncodePointer(nullptr) != nullptr,
          "rtl_mem1: encoding a null pointer does not answer null");
}

// ------------------------------------------------------------------- locks

void test_locks() {
    std::uint8_t storage[64] = {};
    check(nr1_RtlEnterCriticalSection(storage) == kStatusSuccess,
          "rtl_mem1: an uncontended critical section is entered");
    check(nr1_RtlDeleteCriticalSection(storage) == kStatusSuccess,
          "rtl_mem1: and deleted without waiters");
    nr1_RtlAcquirePebLock();
    nr1_RtlAcquireSRWLockExclusive(storage);
    nr1_RtlAcquireSRWLockShared(storage);
    check(nr1_RtlAcquireResourceExclusive(storage, 1) == 1,
          "rtl_mem1: an exclusive resource is acquired");
    check(nr1_RtlAcquireResourceShared(storage, 0) == 1,
          "rtl_mem1: a shared resource is acquired");
    nr1_RtlDeleteResource(storage);
    check(nr1_RtlConvertExclusiveToShared(storage) == kStatusSuccess,
          "rtl_mem1: an uncontended upgrade succeeds");
    check(nr1_RtlConvertSharedToExclusive(storage) == kStatusSuccess,
          "rtl_mem1: and so does the downgrade path's inverse");
    check(nr1_RtlBarrier(storage, 0) == kStatusSuccess,
          "rtl_mem1: the single thread's barrier passes immediately");
    check(nr1_RtlDeleteBarrier(storage) == kStatusSuccess,
          "rtl_mem1: and the barrier deletes");
    nr1_RtlDumpResource(storage);
}

// ------------------------------------------------------------- ACLs / SDs

void test_acl_sid() {
    // A SID is built through the entry point itself, which also checks the
    // allocation path: S-1-5-21-1000-2000-3000.
    const std::uint8_t authority[6] = {0, 0, 0, 0, 0, 5};
    auto* sid = static_cast<std::uint8_t*>(nr1_RtlAllocateAndInitializeSid(
        authority, 4, 21, 1000, 2000, 3000, 0, 0, 0, 0));
    check(sid != nullptr, "rtl_mem1: a SID is allocated and initialized");
    if (sid == nullptr) {
        return;
    }
    check(sid[0] == 1, "rtl_mem1: the SID revision is 1");
    check(sid[1] == 4, "rtl_mem1: and carries four subauthorities");
    check(get_u32(sid, 8) == 21, "rtl_mem1: the first subauthority is 21");
    check(get_u32(sid, 20) == 3000, "rtl_mem1: the last subauthority is 3000");
    check(nr1_RtlAllocateAndInitializeSid(authority, 9, 0, 0, 0, 0, 0, 0, 0,
                                          0) == nullptr,
          "rtl_mem1: nine subauthorities do not fit the entry point");

    const std::uint8_t other_authority[6] = {0, 0, 0, 0, 0, 6};
    auto* sid_b = static_cast<std::uint8_t*>(nr1_RtlAllocateAndInitializeSid(
        other_authority, 4, 21, 1000, 2000, 3000, 0, 0, 0, 0));
    auto* sid_same_prefix = static_cast<std::uint8_t*>(
        nr1_RtlAllocateAndInitializeSid(authority, 4, 21, 1000, 2000, 9999, 0,
                                        0, 0, 0));
    check(nr1_RtlEqualSid(sid, sid_b) == 0,
          "rtl_mem1: a different authority makes a different SID");
    check(nr1_RtlEqualPrefixSid(sid, sid_same_prefix) == 1,
          "rtl_mem1: the prefix ignores the subauthorities");
    check(nr1_RtlEqualPrefixSid(sid, sid_b) == 0,
          "rtl_mem1: but not a different authority");
    check(nr1_RtlEqualSid(sid, nullptr) == 0,
          "rtl_mem1: a null SID compares unequal");

    std::uint8_t acl[128] = {};
    check(nr1_RtlCreateAcl(acl, 128, 2) == kStatusSuccess,
          "rtl_mem1: an ACL is created");
    check(acl[0] == 2, "rtl_mem1: with the requested revision");
    check(get_u16(acl, 2) == 128,
          "rtl_mem1: its size field is the buffer size");
    check(get_u16(acl, 4) == 0, "rtl_mem1: and the ACE count starts at zero");
    check(nr1_RtlCreateAcl(acl, 4, 2) == kStatusInvalidParameter,
          "rtl_mem1: a too-small ACL is refused");
    check(nr1_RtlCreateAcl(acl, 128, 3) == kStatusInvalidParameter,
          "rtl_mem1: revision 3 is not an ACL revision");
    check(nr1_RtlCreateAcl(acl, 127, 2) == kStatusInvalidParameter,
          "rtl_mem1: an unaligned size is refused");

    // The allowed ACE is 8 header-and-mask bytes plus a 24-byte SID.
    check(nr1_RtlAddAccessAllowedAce(acl, 2, 0x1F, sid) == kStatusSuccess,
          "rtl_mem1: an allowed ACE is added");
    check(get_u16(acl, 4) == 1, "rtl_mem1: the ACE count went to one");
    check(acl[8] == 0, "rtl_mem1: the ACE type is access-allowed");
    check(get_u16(acl, 10) == 32,
          "rtl_mem1: the ACE size is 8 bytes plus the SID");
    check(get_u32(acl, 12) == 0x1F,
          "rtl_mem1: the mask landed where the header says it is");
    check(std::memcmp(acl + 16, sid, 24) == 0,
          "rtl_mem1: and the SID is copied into the ACE");

    check(nr1_RtlAddAccessDeniedAce(acl, 2, 0x20, sid) == kStatusSuccess,
          "rtl_mem1: a denied ACE is added after it");
    check(get_u16(acl, 4) == 2, "rtl_mem1: the count is two");
    check(acl[8 + 32] == 1, "rtl_mem1: and the second ACE is access-denied");

    // An ACL with no room left for the ACE is refused without touching it.
    std::uint8_t small[8 + 32] = {};
    check(nr1_RtlCreateAcl(small, sizeof(small), 2) == kStatusSuccess,
          "rtl_mem1: a one-ACE ACL buffer is created");
    check(nr1_RtlAddAccessAllowedAce(small, 2, 0x1F, sid) == kStatusSuccess,
          "rtl_mem1: its one ACE fits exactly");
    check(nr1_RtlAddAccessAllowedAce(small, 2, 0x1F, sid) ==
              kStatusBufferTooSmall,
          "rtl_mem1: a second ACE does not fit and is refused");
    check(get_u16(acl, 4) == 2, "rtl_mem1: and the other ACL was not disturbed");

    check(nr1_RtlAddAccessAllowedAce(acl, 2, 0x1F, nullptr) == kStatusInvalidSid,
          "rtl_mem1: a null SID is a bad SID, not a bad ACL");
    check(nr1_RtlAddAccessAllowedAce(acl, 1, 0x1F, sid) ==
              kStatusRevisionMismatch,
          "rtl_mem1: an unknown revision is a mismatch");

    // Insert and delete by index: a raw ACE list goes in at position 1.
    std::uint8_t raw_ace[20] = {};
    raw_ace[0] = 0;                // allowed
    put_u16(raw_ace, 2, 20);       // size: 8 header bytes + a 12-byte SID
    put_u32(raw_ace, 4, 0x12345678u);
    const std::uint8_t one_sid[8 + 4] = {1, 1, 0, 0, 0, 0, 5, 0xAA,
                                         0, 0, 0, 0};
    std::memcpy(raw_ace + 8, one_sid, sizeof(one_sid));
    check(nr1_RtlAddAce(acl, 2, 1, raw_ace, 20) == kStatusSuccess,
          "rtl_mem1: a raw ACE list is inserted at index 1");
    check(get_u16(acl, 4) == 3, "rtl_mem1: the count went to three");
    check(get_u16(acl, 40 + 2) == 20 && get_u32(acl, 40 + 4) == 0x12345678u,
          "rtl_mem1: the inserted ACE is where index 1 said");
    check(acl[40 + 20] == 1, "rtl_mem1: and the denied ACE moved behind it");
    check(nr1_RtlAddAce(acl, 2, 4, raw_ace, 20) == kStatusInvalidParameter,
          "rtl_mem1: an index past the end is refused");
    check(nr1_RtlAddAce(acl, 2, 0, raw_ace, 15) == kStatusInvalidAcl,
          "rtl_mem1: a list that does not add up is a bad ACL");

    check(nr1_RtlDeleteAce(acl, 1) == kStatusSuccess,
          "rtl_mem1: the inserted ACE is deleted by index");
    check(get_u16(acl, 4) == 2, "rtl_mem1: the count is back to two");
    check(acl[40] == 1, "rtl_mem1: and the denied ACE closed over the gap");
    check(nr1_RtlDeleteAce(acl, 2) == kStatusInvalidParameter,
          "rtl_mem1: an index that is not an ACE is refused");

    check(nr1_RtlAddMandatoryAce(acl, 2, 0, 0x2, 0x11, sid) == kStatusSuccess,
          "rtl_mem1: a mandatory-label ACE is added");
    check(acl[72] == 0x11, "rtl_mem1: with the label type in the header");
    check(get_u32(acl, 72 + 4) == 0x2, "rtl_mem1: and the policy as its mask");
    check(nr1_RtlAddMandatoryAce(acl, 2, 0, 0x2, 0x42, sid) ==
              kStatusInvalidParameter,
          "rtl_mem1: an unknown label type is refused");

    std::uint8_t descriptor[40] = {};
    check(nr1_RtlCreateSecurityDescriptor(descriptor, 1) == kStatusSuccess,
          "rtl_mem1: a security descriptor is created");
    check(descriptor[0] == 1, "rtl_mem1: with revision 1");
    check(nr1_RtlCreateSecurityDescriptor(descriptor, 2) ==
              kStatusUnknownRevision,
          "rtl_mem1: revision 2 is not a descriptor revision");

    // Absolute to self-relative: owner and DACL in, offsets out.
    std::uint8_t absolute[40] = {};
    put_u8(absolute, 0, 1);
    write_u16(absolute, 2, 0x0004u);  // SE_DACL_PRESENT
    write_ptr(absolute, 8, reinterpret_cast<std::uint64_t>(sid));
    write_ptr(absolute, 32, reinterpret_cast<std::uint64_t>(acl));
    std::uint8_t relative[256] = {};
    std::uint32_t length = sizeof(relative);
    check(nr1_RtlAbsoluteToSelfRelativeSD(nullptr, relative, &length) ==
              kStatusInvalidParameter,
          "rtl_mem1: a null descriptor is refused");
    check(nr1_RtlAbsoluteToSelfRelativeSD(absolute, nullptr, &length) ==
                  kStatusBufferTooSmall &&
              length == 40 + 24 + 128,
          "rtl_mem1: a sizing call answers the length it needs");
    check(nr1_RtlAbsoluteToSelfRelativeSD(absolute, relative, &length) ==
              kStatusSuccess,
          "rtl_mem1: and the conversion fills that length");
    check((get_u32(relative, 2) & 0x8000u) != 0,
          "rtl_mem1: the self-relative control bit is set");
    check(get_u32(relative, 8) == 40,
          "rtl_mem1: the owner became an offset past the header");
    check(std::memcmp(relative + 40, sid, 24) == 0,
          "rtl_mem1: the SID body follows it");
    check(get_u32(relative, 32) == 64,
          "rtl_mem1: the DACL offset lands after the SID");
    write_u16(absolute, 2, 0x8004u);  // now with SE_SELF_RELATIVE
    check(nr1_RtlAbsoluteToSelfRelativeSD(absolute, relative, &length) ==
              kStatusInvalidParameter,
          "rtl_mem1: an already self-relative descriptor is refused");
    // The three SIDs come back at the end of the ACL and SID test, which is
    // where the last comparison against them happens.
    winabi::heap_free(sid);
    winabi::heap_free(sid_b);
    winabi::heap_free(sid_same_prefix);
}

// ------------------------------------------------------------- DOS paths

void test_dos_paths() {
    check(nr1_RtlDetermineDosPathNameType_U(u"C:\\x") == 2,
          "rtl_mem1: C:\\x is drive-absolute");
    check(nr1_RtlDetermineDosPathNameType_U(u"C:x") == 3,
          "rtl_mem1: C:x is drive-relative");
    check(nr1_RtlDetermineDosPathNameType_U(u"\\x") == 4,
          "rtl_mem1: \\x is rooted");
    check(nr1_RtlDetermineDosPathNameType_U(u"x") == 5,
          "rtl_mem1: x is relative");
    check(nr1_RtlDetermineDosPathNameType_U(u"\\\\srv\\share") == 1,
          "rtl_mem1: a server path is a UNC absolute");
    check(nr1_RtlDetermineDosPathNameType_U(u"\\\\?\\C:\\x") == 6,
          "rtl_mem1: the question-mark device prefix is a local device");
    check(nr1_RtlDetermineDosPathNameType_U(u"\\\\.\\x") == 7,
          "rtl_mem1: the dot device prefix is a device");
    check(nr1_RtlDetermineDosPathNameType_U(u"") == 0,
          "rtl_mem1: the empty path is unknown");

    std::uint8_t nt_name[16] = {};
    std::uint32_t file_part = 0;
    std::uint8_t relative[32] = {};
    check(nr1_RtlDosPathNameToNtPathName_U(u"C:\\foo\\bar.txt", nt_name,
                                           &file_part, relative) == 1,
          "rtl_mem1: a DOS path converts to an NT name");
    const auto* buffer =
        reinterpret_cast<const char16_t*>(read_ptr(nt_name, 8));
    check(buffer != nullptr, "rtl_mem1: the NT name has a buffer");
    if (buffer != nullptr) {
        const char16_t expect[] = u"\\??\\C:\\foo\\bar.txt";
        const std::size_t chars = (sizeof(expect) / sizeof(expect[0])) - 1;
        check(read_u16(nt_name, 0) == chars * 2,
              "rtl_mem1: the length counts bytes for the whole NT name");
        check(std::u16string(buffer, chars) == expect,
              "rtl_mem1: and the text is the NT spelling");
    }
    check(file_part == 11,
          "rtl_mem1: the filename starts after the last separator");
    check(relative[0] == 0 && relative[8] == 0 && relative[24] == 0,
          "rtl_mem1: the relative-name structure is zeroed, no fake form");
    // The conversion allocated the name's buffer out of the heap; the test
    // gives it back now that nothing reads it.
    winabi::heap_free(reinterpret_cast<void*>(read_ptr(nt_name, 8)));

    std::uint8_t nt_name_b[16] = {};
    check(nr1_RtlDosPathNameToNtPathName_U_WithStatus(
              nullptr, nt_name_b, nullptr,
              nullptr) == kStatusInvalidParameter,
          "rtl_mem1: a null path is a status, not a boolean");
    check(nr1_RtlDosPathNameToNtPathName_U_WithStatus(
              u"C:\\x", nullptr, nullptr, nullptr) == kStatusInvalidParameter,
          "rtl_mem1: and so is a null output string");

    check(nr1_RtlDoesFileExists_U(u"Z:\\tmp") == 1,
          "rtl_mem1: Z:\\tmp maps to the host's /tmp");
    check(nr1_RtlDoesFileExists_U(u"Z:\\tmp\\no_such_file_4312") == 0,
          "rtl_mem1: a missing file answers false");
    check(nr1_RtlDoesFileExists_U(u"Q:\\tmp") == 0,
          "rtl_mem1: a drive this runtime has not mounted answers false");

    TestUnicodeString a;
    TestUnicodeString b;
    a.set(u"Machine-01");
    b.set(u"machine-01");
    check(nr1_RtlEqualComputerName(a.bytes, b.bytes) == 1,
          "rtl_mem1: computer names compare case-insensitively");
    b.set(u"Machine-02");
    check(nr1_RtlEqualComputerName(a.bytes, b.bytes) == 0,
          "rtl_mem1: and different names do not match");
    a.set(u"DOMAIN");
    b.set(u"domain");
    check(nr1_RtlEqualDomainName(a.bytes, b.bytes) == 1,
          "rtl_mem1: domain names fold case the same way");

    check(nr1_RtlDllShutdownInProgress() == 0,
          "rtl_mem1: a run inside this runtime is never in loader shutdown");
}

// ----------------------------------------------------------- PE queries

void test_pe_queries() {
    // A hand-built image: DOS header pointing at an NT header with one
    // section, plus an export directory with one name.
    static std::uint8_t image[0x20000] = {};
    std::memset(image, 0, sizeof(image));

    // The walkers bound every RVA against the mapped region, so the fixture
    // has to be one. That is the real path rather than a convenience: these
    // are called on a mapped image, and a caller whose buffer is not mapped
    // gets the answer that says so instead of a read past the end.
    ScopedImageRegion region(image, sizeof(image));
    if (!region.holds()) {
        std::fprintf(stderr,
                     "FAIL rtl_mem1: the fixture could not be mapped\n");
        return;
    }

    put_u32(image, 0x3C, 0x40);  // e_lfanew
    put_u32(image, 0x40, 0x00004550u);
    put_u32(image, 0x40 + 4, 0x8664u);   // machine
    put_u32(image, 0x40 + 6, 1);         // one section
    put_u32(image, 0x40 + 20, 240);      // size of optional header
    put_u32(image, 0x40 + 24, 0x20B);    // PE32+
    put_u32(image, 0x40 + 24 + 112, 0x100);  // export directory RVA
    // Section table at 24 + 240 from the NT header.
    const std::size_t section = 0x40 + 24 + 240;
    put_u32(image, section + 8, 0x100);   // virtual size
    put_u32(image, section + 12, 0x1000);  // virtual address
    put_u32(image, section + 16, 0x200);  // size of raw data

    // Export directory at RVA 0x100, one name "FooBar", function at 0x200.
    const std::size_t exports = 0x100;
    put_u32(image, exports + 16, 1);    // base
    put_u32(image, exports + 20, 1);    // number of functions
    put_u32(image, exports + 24, 1);    // number of names
    put_u32(image, exports + 28, 0x200);  // address of functions
    put_u32(image, exports + 32, 0x300);  // address of names
    put_u32(image, exports + 36, 0x400);  // address of ordinals
    put_u32(image, 0x200, 0x9090);      // the function RVA, in its slot
    put_u32(image, 0x300, 0x500);       // name RVA
    std::memcpy(image + 0x500, "FooBar", 7);
    put_u32(image, 0x400, 0);           // ordinal 0
    // The function RVA has to address something inside the image, so the
    // fixture's is inside the 2 KiB it mapped rather than out in the middle
    // of nowhere: an export entry pointing past the end of the image is a
    // malformed one, and the walk refuses it below.
    constexpr std::uint32_t kFunctionRva = 0x600;
    put_u32(image, 0x200, kFunctionRva);
    check(nr1_RtlFindExportedRoutineByName(image, "FooBar") ==
              image + kFunctionRva,
          "rtl_mem1: an exported routine is found by name");
    check(nr1_RtlFindExportedRoutineByName(image, "NotThere") == nullptr,
          "rtl_mem1: a missing name answers null");
    check(nr1_RtlFindExportedRoutineByName(image, nullptr) == nullptr,
          "rtl_mem1: a null name answers null");

    // The refusals the bounds exist for. Each is a pointer the image
    // supplies that names nothing this runtime can hand back, and the
    // answer is a refusal rather than an address past the end.
    put_u32(image, 0x200, 0x100000u);
    check(nr1_RtlFindExportedRoutineByName(image, "FooBar") == nullptr,
          "rtl_mem1: an export RVA past the image is refused");
    put_u32(image, 0x200, kFunctionRva);

    put_u32(image, exports + 24, 0x40000u);
    check(nr1_RtlFindExportedRoutineByName(image, "FooBar") == nullptr,
          "rtl_mem1: a name count that overruns the image is refused");
    put_u32(image, exports + 24, 1);

    put_u32(image, exports + 32, 0x100000u);  // names table
    check(nr1_RtlFindExportedRoutineByName(image, "FooBar") == nullptr,
          "rtl_mem1: a name table past the image is refused");
    put_u32(image, exports + 32, 0x300);

    // And the section walker, which bounds against the region the same way.
    // The buffer is 128 KiB so that the section's whole claimed range is
    // inside it: an assertion about an RVA past the end of the image needs
    // an image that ends, and a buffer that ends at the same place as the
    // section would make the two bounds indistinguishable.
    check(nr1_RtlAddressInSectionTable(image + 0x40, image, 0x1000) ==
              image + 0x1000,
          "rtl_mem1: an RVA inside the section and the image resolves");
    check(nr1_RtlAddressInSectionTable(image + 0x40, image, 0x2000) == nullptr,
          "rtl_mem1: an RVA outside every section answers null");
    check(nr1_RtlAddressInSectionTable(image + 0x40, image, 0x20000) == nullptr,
          "rtl_mem1: an RVA the section covers but the image does not is "
          "refused");
    put_u32(image, 0x40, 0x12345678u);
    check(nr1_RtlAddressInSectionTable(image + 0x40, image, 0x1000) == nullptr,
          "rtl_mem1: a bad NT signature answers null");
    put_u32(image, 0x40, 0x00004550u);
}

// ------------------------------------------------------------ atom tables

void test_atoms() {
    void* table = nr1_RtlCreateAtomTable(0, 0);
    check(table != nullptr, "rtl_mem1: an atom table is created");
    if (table == nullptr) {
        return;
    }
    std::uint32_t atom = 0;
    check(nr1_RtlAddAtomToAtomTable(table, u"hello", &atom) == kStatusSuccess,
          "rtl_mem1: an atom is added");
    check(atom == 0xC001, "rtl_mem1: the first unpinned atom is 0xC001");
    std::uint32_t again = 0;
    check(nr1_RtlAddAtomToAtomTable(table, u"hello", &again) ==
                  kStatusSuccess &&
              again == atom,
          "rtl_mem1: adding the same name finds the same atom");
    std::uint32_t pinned = 0;
    check(nr1_RtlAddAtomToAtomTable(table, u"", &pinned) == kStatusSuccess &&
              pinned == 0xC000,
          "rtl_mem1: the empty string answers the pinned atom");
    check(nr1_RtlDeleteAtomFromAtomTable(table, 0xC000) ==
              kStatusInvalidParameter,
          "rtl_mem1: the pinned atom cannot be deleted");
    check(nr1_RtlDeleteAtomFromAtomTable(table, atom) == kStatusSuccess,
          "rtl_mem1: the hello atom is deleted");
    check(nr1_RtlDeleteAtomFromAtomTable(table, atom) == kStatusSuccess,
          "rtl_mem1: the second add's reference is deleted too");
    check(nr1_RtlDeleteAtomFromAtomTable(table, atom) == kStatusInvalidHandle,
          "rtl_mem1: deleting it again is an unknown atom");
    std::uint32_t next = 0;
    check(nr1_RtlAddAtomToAtomTable(table, u"hello", &next) ==
                  kStatusSuccess &&
              next == 0xC002,
          "rtl_mem1: a re-added name gets a fresh value");
    check(nr1_RtlAddAtomToAtomTable(table, u"", &next) == kStatusSuccess &&
              next == 0xC000,
          "rtl_mem1: the pinned atom survives the deletion beside it");

    check(nr1_RtlEmptyAtomTable(table, 0) == kStatusSuccess,
          "rtl_mem1: the table empties");
    std::uint32_t after_empty = 0;
    check(nr1_RtlAddAtomToAtomTable(table, u"hello", &after_empty) ==
                  kStatusSuccess &&
              after_empty == 0xC003,
          "rtl_mem1: and the unpinned names are gone");
    check(nr1_RtlAddAtomToAtomTable(table, u"", &next) == kStatusSuccess &&
              next == 0xC000,
          "rtl_mem1: while the pinned atom stays");
    std::uint16_t long_name[300] = {};
    for (std::size_t i = 0; i < 256; ++i) {
        long_name[i] = u'a';
    }
    check(nr1_RtlAddAtomToAtomTable(
              table, reinterpret_cast<const char16_t*>(long_name), &atom) ==
              kStatusInvalidParameter,
          "rtl_mem1: a name over 255 characters is refused");
    check(nr1_RtlDestroyAtomTable(table) == kStatusSuccess,
          "rtl_mem1: the table is destroyed");
    check(nr1_RtlDestroyAtomTable(table) == kStatusInvalidHandle,
          "rtl_mem1: destroying it again is an unknown handle");
    check(nr1_RtlDestroyAtomTable(nullptr) == kStatusInvalidHandle,
          "rtl_mem1: and so is a null handle");
}

// ------------------------------------------------------ vectored handlers

void test_vectored() {
    int storage = 0;
    void* token = nr1_RtlAddVectoredExceptionHandler(0, &storage);
    check(token != nullptr, "rtl_mem1: a vectored handler is registered");
    check(nr1_RtlAddVectoredExceptionHandler(1, &storage) != nullptr,
          "rtl_mem1: a first-handler registration answers a token");
    check(nr1_RtlAddVectoredExceptionHandler(0, nullptr) == nullptr,
          "rtl_mem1: a null handler is refused");
    check(nr1_RtlAddVectoredContinueHandler(0, &storage) != nullptr,
          "rtl_mem1: the continue list takes its own registration");
}

// ------------------------------------------------------------ misc answers

void test_misc() {
    nr1_RtlAssert(u"assertion", u"file.c", 42, "message");
    void* frames[8] = {};
    std::uint32_t hash = 7;
    check(nr1_RtlCaptureStackBackTrace(0, 8, frames, &hash) == 0,
          "rtl_mem1: no guest frames are captured, honestly");
    check(hash == 0, "rtl_mem1: the hash is zeroed with them");
}

// -------------------------------------------------------------- refusals

void test_refusals() {
    check(nr1_RtlAbortRXact(nullptr) == kStatusNotImplemented,
          "rtl_mem1: RXact is refused with STATUS_NOT_IMPLEMENTED");
    check(nr1_RtlCompressBuffer(0, nullptr, 0, nullptr, 0, 0, nullptr,
                                nullptr) == kStatusNotImplemented,
          "rtl_mem1: compression is refused, not faked");
    check(nr1_RtlCreateTagHeap(nullptr, 0, nullptr, nullptr) == nullptr,
          "rtl_mem1: a tag heap is refused with null");
    check(nr1_RtlExtendedMagicDivide(1, 1, 1) == 0,
          "rtl_mem1: the magic divide is refused");
    check(nr1_RtlDosSearchPath_U(u"", u"", u"", nullptr) == 0,
          "rtl_mem1: the DOS path search is refused");
    check(nr1_RtlDosPathNameToRelativeNtPathName_U(u"C:\\x", nullptr, nullptr,
                                                   nullptr) == 0,
          "rtl_mem1: relative NT names are refused");
}

// --------------------------------------------------------- registration

void test_registration() {
    // The work order's 156 names, verbatim. A registration that misses one
    // or invents one is a guest-visible bug no other test catches.
    static const char* const expected[] = {
        "RtlAbortRXact",
        "RtlAbsoluteToSelfRelativeSD",
        "RtlAcquirePebLock",
        "RtlAcquireResourceExclusive",
        "RtlAcquireResourceShared",
        "RtlAcquireSRWLockExclusive",
        "RtlAcquireSRWLockShared",
        "RtlActivateActivationContext",
        "RtlActivateActivationContextEx",
        "RtlActivateActivationContextUnsafeFast",
        "RtlAddAccessAllowedAce",
        "RtlAddAccessAllowedAceEx",
        "RtlAddAccessAllowedObjectAce",
        "RtlAddAccessDeniedAce",
        "RtlAddAccessDeniedAceEx",
        "RtlAddAccessDeniedObjectAce",
        "RtlAddAce",
        "RtlAddActionToRXact",
        "RtlAddAtomToAtomTable",
        "RtlAddAttributeActionToRXact",
        "RtlAddAuditAccessAce",
        "RtlAddAuditAccessAceEx",
        "RtlAddAuditAccessObjectAce",
        "RtlAddMandatoryAce",
        "RtlAddProcessTrustLabelAce",
        "RtlAddRefActivationContext",
        "RtlAddVectoredContinueHandler",
        "RtlAddVectoredExceptionHandler",
        "RtlAddressInSectionTable",
        "RtlAdjustPrivilege",
        "RtlAllocateAndInitializeSid",
        "RtlAllocateHandle",
        "RtlAllocateHeap",
        "RtlApplyRXact",
        "RtlApplyRXactNoFlush",
        "RtlAreAllAccessesGranted",
        "RtlAreAnyAccessesGranted",
        "RtlAreBitsClear",
        "RtlAreBitsSet",
        "RtlAssert",
        "RtlBarrier",
        "RtlCaptureStackBackTrace",
        "RtlCheckRegistryKey",
        "RtlClearAllBits",
        "RtlClearBits",
        "RtlClosePropertySet",
        "RtlCompactHeap",
        "RtlCompressBuffer",
        "RtlComputeCrc32",
        "RtlConvertExclusiveToShared",
        "RtlConvertLongToLargeInteger",
        "RtlConvertSharedToExclusive",
        "RtlConvertToAutoInheritSecurityObject",
        "RtlConvertUiListToApiList",
        "RtlConvertUlongToLargeInteger",
        "RtlCreateAcl",
        "RtlCreateActivationContext",
        "RtlCreateAndSetSD",
        "RtlCreateAtomTable",
        "RtlCreateEnvironment",
        "RtlCreateHeap",
        "RtlCreateProcessParameters",
        "RtlCreateProcessParametersEx",
        "RtlCreatePropertySet",
        "RtlCreateQueryDebugBuffer",
        "RtlCreateRegistryKey",
        "RtlCreateSecurityDescriptor",
        "RtlCreateServiceSid",
        "RtlCreateTagHeap",
        "RtlCreateTimer",
        "RtlCreateTimerQueue",
        "RtlCreateUserProcess",
        "RtlCreateUserSecurityObject",
        "RtlCreateUserStack",
        "RtlCreateUserThread",
        "RtlCutoverTimeToSystemTime",
        "RtlDeNormalizeProcessParams",
        "RtlDeactivateActivationContext",
        "RtlDeactivateActivationContextUnsafeFast",
        "RtlDebugPrintTimes",
        "RtlDecodePointer",
        "RtlDecodeSystemPointer",
        "RtlDecompressBuffer",
        "RtlDecompressFragment",
        "RtlDefaultNpAcl",
        "RtlDelete",
        "RtlDeleteAce",
        "RtlDeleteAtomFromAtomTable",
        "RtlDeleteBarrier",
        "RtlDeleteCriticalSection",
        "RtlDeleteElementGenericTable",
        "RtlDeleteElementGenericTableAvl",
        "RtlDeleteNoSplay",
        "RtlDeleteOwnersRanges",
        "RtlDeleteRange",
        "RtlDeleteRegistryValue",
        "RtlDeleteResource",
        "RtlDeleteSecurityObject",
        "RtlDeleteTimer",
        "RtlDeleteTimerQueueEx",
        "RtlDeregisterWait",
        "RtlDeregisterWaitEx",
        "RtlDeriveCapabilitySidsFromName",
        "RtlDestroyAtomTable",
        "RtlDestroyEnvironment",
        "RtlDestroyHandleTable",
        "RtlDestroyHeap",
        "RtlDestroyProcessParameters",
        "RtlDestroyQueryDebugBuffer",
        "RtlDetermineDosPathNameType_U",
        "RtlDllShutdownInProgress",
        "RtlDoesFileExists_U",
        "RtlDosPathNameToNtPathName_U",
        "RtlDosPathNameToNtPathName_U_WithStatus",
        "RtlDosPathNameToRelativeNtPathName_U",
        "RtlDosPathNameToRelativeNtPathName_U_WithStatus",
        "RtlDosSearchPath_U",
        "RtlDumpResource",
        "RtlEmptyAtomTable",
        "RtlEncodePointer",
        "RtlEncodeSystemPointer",
        "RtlEnlargedIntegerMultiply",
        "RtlEnlargedUnsignedDivide",
        "RtlEnlargedUnsignedMultiply",
        "RtlEnterCriticalSection",
        "RtlEnumProcessHeaps",
        "RtlEnumerateGenericTable",
        "RtlEnumerateGenericTableWithoutSplaying",
        "RtlEnumerateGenericTableWithoutSplayingAvl",
        "RtlEnumerateProperties",
        "RtlEqualComputerName",
        "RtlEqualDomainName",
        "RtlEqualLuid",
        "RtlEqualPrefixSid",
        "RtlEqualSid",
        "RtlExitUserProcess",
        "RtlExitUserThread",
        "RtlExtendHeap",
        "RtlExtendedIntegerMultiply",
        "RtlExtendedLargeIntegerDivide",
        "RtlExtendedMagicDivide",
        "RtlFindActivationContextSectionGuid",
        "RtlFindClearBits",
        "RtlFindClearBitsAndSet",
        "RtlFindClearRuns",
        "RtlFindExportedRoutineByName",
        "RtlFindLastBackwardRunClear",
        "RtlFindLastBackwardRunSet",
        "RtlFindLeastSignificantBit",
        "RtlFindLongestRunClear",
        "RtlFindLongestRunSet",
        "RtlFindMessage",
        "RtlFindMostSignificantBit",
        "RtlFindNextForwardRunClear",
        "RtlFindNextForwardRunSet",
        "RtlFindRange",
    };

    ExportList out;
    add_ntdll_rtl_mem1(out);
    check(out.size() == 156,
          "rtl_mem1: the domain registers exactly the work order's count");
    std::vector<std::string> registered;
    for (const HostExport& entry : out) {
        registered.emplace_back(entry.name);
    }
    std::sort(registered.begin(), registered.end());
    std::vector<std::string> wanted;
    for (const char* name : expected) {
        wanted.emplace_back(name);
    }
    std::sort(wanted.begin(), wanted.end());
    check(registered == wanted,
          "rtl_mem1: the registered names match the work order exactly");
    check(std::adjacent_find(registered.begin(), registered.end()) ==
              registered.end(),
          "rtl_mem1: and no name is registered twice");
}

}  // namespace

int main() {
    test_heaps();
    test_bitmaps();
    test_integer_math();
    test_access_and_crc();
    test_pointer_encoding();
    test_locks();
    test_acl_sid();
    test_dos_paths();
    test_pe_queries();
    test_atoms();
    test_vectored();
    test_misc();
    test_refusals();
    test_registration();
    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::fprintf(stderr, "all %d checks passed\n", checks);
    return 0;
}

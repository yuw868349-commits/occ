// The Rtl* half of ntdll, first alphabetical slice (RtlAbortRXact through
// RtlFindRange): heaps, bitmaps, extended-integer arithmetic, ACLs and SIDs,
// atom tables, DOS path analysis, PE image queries, and the lock primitives
// a single-threaded guest takes uncontended.
//
// The reference for behaviour is the Windows documentation and the ABI
// itself; no Wine source tree was reachable when this was written, and every
// choice below that the documentation does not settle is marked "inferred"
// where it happens. The file prefers a refusal with a reason over an answer
// it cannot stand behind: a subsystem this runtime does not have (activation
// contexts, splay tables, compression engines, the timer queue) answers
// STATUS_NOT_IMPLEMENTED rather than a plausible-looking success, because a
// guest that branches on a fake success corrupts itself further down.
//
// Layout constants are the guest's byte offsets throughout. This host's
// compiler lays a structure out by its own rules and the guest's are
// Windows', so nothing here trusts a host `sizeof`.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/address_space.h"
#include "occ/runtime/winabi.h"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <string>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

namespace occ::runtime::winabi {

// The exit path the process layer provides. Declared here rather than taken
// from a header because the process layer owns it and this domain only
// forwards the two exits a guest reaches without kernel32 in between.
extern "C" __attribute__((ms_abi)) void k32_ExitProcess(
    std::uint32_t code) noexcept;

namespace {

// ---------------------------------------------------------------- statuses
//
// ntdll functions return NTSTATUS, which api_common's Win32 codes do not
// cover: a Win32 code in an NTSTATUS return would read as a success to
// anything testing the severity bit. These are the statuses this file
// answers with, named rather than written as literals at the call sites.
constexpr std::int32_t kStatusSuccess = 0;
constexpr std::int32_t kStatusNotImplemented =
    static_cast<std::int32_t>(0xC0000002u);
constexpr std::int32_t kStatusInvalidHandle =
    static_cast<std::int32_t>(0xC0000008u);
constexpr std::int32_t kStatusNoMemory =
    static_cast<std::int32_t>(0xC0000017u);
constexpr std::int32_t kStatusBufferTooSmall =
    static_cast<std::int32_t>(0xC0000023u);
constexpr std::int32_t kStatusInvalidParameter =
    static_cast<std::int32_t>(0xC000000Du);
constexpr std::int32_t kStatusInvalidAcl =
    static_cast<std::int32_t>(0xC0000077u);
constexpr std::int32_t kStatusInvalidSid =
    static_cast<std::int32_t>(0xC0000078u);
constexpr std::int32_t kStatusRevisionMismatch =
    static_cast<std::int32_t>(0xC0000059u);
constexpr std::int32_t kStatusUnknownRevision =
    static_cast<std::int32_t>(0xC0000091u);
constexpr std::int32_t kStatusInsufficientResources =
    static_cast<std::int32_t>(0xC000009Au);

// The refusal a caller gets for a subsystem this runtime does not carry.
// Both channels say so: the NTSTATUS return is what an ntdll caller reads,
// and the last-error code is what the work order names.
[[nodiscard]] std::int32_t refuse() noexcept {
    set_last_error(kErrorCallNotImplemented);
    return kStatusNotImplemented;
}

[[nodiscard]] std::uint32_t refuse_boolean() noexcept {
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

[[nodiscard]] void* refuse_handle() noexcept {
    set_last_error(kErrorCallNotImplemented);
    return nullptr;
}

// ---------------------------------------------------------------- small reads
//
// api_common covers words and pointers; ACL and SID headers are byte-sized.
[[nodiscard]] std::uint8_t read_u8(const void* base,
                                   std::size_t offset) noexcept {
    std::uint8_t value = 0;
    std::memcpy(&value, static_cast<const std::uint8_t*>(base) + offset,
                sizeof(value));
    return value;
}

void write_u8(void* base, std::size_t offset, std::uint8_t value) noexcept {
    std::memcpy(static_cast<std::uint8_t*>(base) + offset, &value,
                sizeof(value));
}

// ===========================================================================
// Heaps
// ===========================================================================
//
// A heap handle is a small control block the runtime owns, allocated out of
// the same pool the blocks come from. The allocation itself is the host
// allocator through `heap_alloc`, so a block `RtlAllocateHeap` returns is a
// block `RtlFreeHeap` (wherever that name lands) can free through the same
// path `HeapFree` uses -- there is no second spelling of a heap block to
// disagree with itself.
//
// Handle zero and the published process-heap handle both name the process
// heap, the way Windows treats them as the same arena.

constexpr std::uint64_t kHeapHandleMagic = 0x4F4343484E523144ULL;  // "OCCHNR1D"
constexpr std::uint32_t kHeapZeroMemory = 0x00000008;

struct GuestHeap {
    std::uint64_t magic = kHeapHandleMagic;
    std::uint32_t flags = 0;
    std::uint32_t spare = 0;
};

// One list, appended on create, removed on destroy. The guest runs on one
// host thread and every writer below is reached from it, so there is no
// lock here: a lock would guard against a reentrancy that cannot happen
// and add an acquisition to every create.
std::vector<GuestHeap*>& heap_registry() noexcept {
    static std::vector<GuestHeap*> heaps;
    return heaps;
}

[[nodiscard]] bool is_process_heap(std::uint64_t heap) noexcept {
    return heap == 0 || heap == process_heap_handle();
}

[[nodiscard]] GuestHeap* as_created_heap(std::uint64_t heap) noexcept {
    if (is_process_heap(heap)) {
        return nullptr;
    }
    // The registry is the source of truth, and the lookup happens before
    // any dereference: a handle the guest invented must be refused without
    // reading the memory it points at, which would fault here the way a
    // wild handle faults on Windows.
    for (GuestHeap* candidate : heap_registry()) {
        if (reinterpret_cast<std::uint64_t>(candidate) == heap) {
            return candidate;
        }
    }
    return nullptr;
}

}  // namespace

extern "C" __attribute__((ms_abi)) void* nr1_RtlCreateHeap(
    std::uint32_t flags, void* base, std::uint64_t reserve,
    std::uint64_t commit, void* lock, void* parameters) noexcept {
    (void)reserve;
    (void)commit;
    (void)lock;
    (void)parameters;
    // A heap carved out of a caller-provided section has to live where the
    // section lives, and the host allocator does not place blocks on demand.
    // Refusing it beats handing back a heap that ignores where its memory
    // was supposed to come from.
    if (base != nullptr) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    void* raw = heap_alloc(0, sizeof(GuestHeap));
    if (raw == nullptr) {
        set_last_error(kErrorNotEnoughMemory);
        return nullptr;
    }
    auto* heap = new (raw) GuestHeap;
    heap->flags = flags;
    heap_registry().push_back(heap);
    set_last_error(0);
    return heap;
}

extern "C" __attribute__((ms_abi)) void* nr1_RtlDestroyHeap(
    void* heap) noexcept {
    // The failure answer is the input handle, so a caller that checks
    // against what it passed sees the refusal rather than mistaking null
    // for "already destroyed". The process heap is not destroyable: every
    // allocation in the process lives in it.
    const std::uint64_t handle = reinterpret_cast<std::uint64_t>(heap);
    if (is_process_heap(handle)) {
        set_last_error(kErrorInvalidHandle);
        return heap;
    }
    GuestHeap* created = as_created_heap(handle);
    if (created == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return heap;
    }
    auto& heaps = heap_registry();
    for (std::size_t i = 0; i < heaps.size(); ++i) {
        if (heaps[i] == created) {
            heaps.erase(heaps.begin() + static_cast<std::ptrdiff_t>(i));
            break;
        }
    }
    created->magic = 0;
    heap_free(created);
    set_last_error(0);
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void* nr1_RtlAllocateHeap(
    void* heap, std::uint32_t flags, std::uint64_t size) noexcept {
    // An unknown handle is refused before any allocation: allocating into
    // "some heap" because the handle was garbage would hand the caller a
    // block it can free through a path that never heard of it.
    if (!is_process_heap(reinterpret_cast<std::uint64_t>(heap)) &&
        as_created_heap(reinterpret_cast<std::uint64_t>(heap)) == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return nullptr;
    }
    void* block = heap_alloc(flags & kHeapZeroMemory, size);
    if (block == nullptr) {
        set_last_error(kErrorNotEnoughMemory);
        return nullptr;
    }
    set_last_error(0);
    return block;
}

extern "C" __attribute__((ms_abi)) std::uint64_t nr1_RtlCompactHeap(
    void* heap, std::uint32_t flags) noexcept {
    (void)heap;
    (void)flags;
    // Compaction is the allocator's own business here; zero bytes moved is
    // the true count for a pool that never fragments by design.
    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) void* nr1_RtlExtendHeap(
    void* heap, std::uint32_t flags, void* base,
    std::uint64_t bytes) noexcept {
    (void)heap;
    (void)flags;
    (void)base;
    (void)bytes;
    // Extending means adding caller-owned memory to a heap, which needs the
    // section-backed heap this runtime refused to create in the first
    // place. Null is the failure answer; there is no partial growth to
    // report.
    set_last_error(kErrorInvalidFunction);
    return nullptr;
}

// The guest callback shape for `RtlEnumProcessHeaps`.
extern "C" typedef std::int32_t (__attribute__((ms_abi)) *EnumHeapsCb)(
    void* heap, void* parameter) noexcept;

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlEnumProcessHeaps(
    EnumHeapsCb callback, void* parameter) noexcept {
    if (callback == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The list is copied before any callback runs: a callback that creates
    // or destroys a heap must not find itself iterating a vector that is
    // moving underneath it.
    std::vector<std::uint64_t> snapshot;
    snapshot.push_back(process_heap_handle());
    for (GuestHeap* heap : heap_registry()) {
        snapshot.push_back(reinterpret_cast<std::uint64_t>(heap));
    }
    set_last_error(0);
    std::uint32_t seen = 0;
    for (std::uint64_t heap : snapshot) {
        ++seen;
        if (callback(reinterpret_cast<void*>(heap), parameter) == 0) {
            break;
        }
    }
    return seen;
}

namespace {

// ===========================================================================
// Bitmaps
// ===========================================================================
//
// RTL_BITMAP, as byte offsets: the bit count first, then the buffer pointer.
// The buffer is the guest's own memory and stays the guest's; these calls
// read and rewrite it in place.
constexpr std::size_t kBitmapSizeOf = 0;  // uint32
constexpr std::size_t kBitmapBuffer = 8;  // pointer to uint32 array

// Bit zero is the most significant bit of the first ULONG, and bit i sits at
// word i/32, position 31 - i%32. Getting this backwards would make a guest's
// bit 0 and this file's bit 0 two different bits.
constexpr std::uint32_t kBitmapError = 0xFFFFFFFFu;

struct BitmapView {
    const std::uint8_t* words = nullptr;
    std::uint32_t bits = 0;
};

[[nodiscard]] bool bitmap_view(const void* header, BitmapView& out) noexcept {
    if (header == nullptr) {
        return false;
    }
    out.bits = read_u32(header, kBitmapSizeOf);
    out.words = reinterpret_cast<const std::uint8_t*>(
        read_ptr(header, kBitmapBuffer));
    if (out.bits == 0) {
        return true;  // an empty bitmap is well-formed and has no bits
    }
    return out.words != nullptr;
}

[[nodiscard]] std::uint32_t bitmap_word_count(
    const BitmapView& bitmap) noexcept {
    return (bitmap.bits + 31) / 32;
}

[[nodiscard]] bool bitmap_get(const BitmapView& bitmap,
                              std::uint32_t index) noexcept {
    const std::uint32_t word = read_u32(bitmap.words,
                                        static_cast<std::size_t>(index >> 5) * 4);
    return ((word >> (31 - (index & 31))) & 1u) != 0;
}

void bitmap_put(const BitmapView& bitmap, std::uint32_t index,
                bool value) noexcept {
    const std::size_t offset = static_cast<std::size_t>(index >> 5) * 4;
    const std::uint32_t mask = 0x80000000u >> (index & 31);
    std::uint32_t word = read_u32(bitmap.words, offset);
    if (value) {
        word |= mask;
    } else {
        word &= ~mask;
    }
    write_u32(const_cast<std::uint8_t*>(bitmap.words), offset, word);
}

// The first run of `count` wanted bits fully inside [from, to), or the error
// value. The scan is linear because a guest bitmap is guest memory this
// file does not own an index into.
[[nodiscard]] std::uint32_t bitmap_find_in_range(const BitmapView& bitmap,
                                                 std::uint32_t count,
                                                 std::uint32_t from,
                                                 std::uint32_t to,
                                                 bool want_set) noexcept {
    std::uint32_t run = 0;
    for (std::uint32_t i = from; i < to; ++i) {
        if (bitmap_get(bitmap, i) == want_set) {
            ++run;
            if (run == count) {
                return i - (count - 1);
            }
        } else {
            run = 0;
        }
    }
    return kBitmapError;
}

// The circular scan Windows spells: from the hint to the end, then from the
// beginning. A run never wraps, because the bitmap is linear and a caller
// asking for a run across the end is asking for two.
[[nodiscard]] std::uint32_t bitmap_find_run(const BitmapView& bitmap,
                                            std::uint32_t count,
                                            std::uint32_t hint,
                                            bool want_set) noexcept {
    if (count == 0 || count > bitmap.bits) {
        // The zero-count answer is inferred: nothing here settles what an
        // empty request returns, and the error value says "not found" which
        // is what an empty request cannot be.
        return kBitmapError;
    }
    const std::uint32_t start = hint % bitmap.bits;
    const std::uint32_t forward =
        bitmap_find_in_range(bitmap, count, start, bitmap.bits, want_set);
    if (forward != kBitmapError || start == 0) {
        return forward;
    }
    return bitmap_find_in_range(bitmap, count, 0, start, want_set);
}

void bitmap_set_run(const BitmapView& bitmap, std::uint32_t index,
                    std::uint32_t count, bool value) noexcept {
    for (std::uint32_t i = 0; i < count; ++i) {
        bitmap_put(bitmap, index + i, value);
    }
}

struct BitmapRun {
    std::uint32_t start = 0;
    std::uint32_t length = 0;
};

// Every run of wanted bits, in address order. Collected whole rather than
// scanned twice so the "longest first" ordering shares one walk with the
// plain ordering.
void bitmap_all_runs(const BitmapView& bitmap, bool want_set,
                     std::vector<BitmapRun>& out) noexcept {
    std::uint32_t i = 0;
    while (i < bitmap.bits) {
        if (bitmap_get(bitmap, i) == want_set) {
            const std::uint32_t start = i;
            while (i < bitmap.bits && bitmap_get(bitmap, i) == want_set) {
                ++i;
            }
            out.push_back(BitmapRun{start, i - start});
        } else {
            ++i;
        }
    }
}

[[nodiscard]] bool bitmap_range_ok(const BitmapView& bitmap,
                                   std::uint32_t index,
                                   std::uint32_t count) noexcept {
    // `count == 0` is in range wherever the index is: an empty range cannot
    // fall outside the bitmap. The subtraction below is safe because the
    // first test already handled index >= bits.
    if (index >= bitmap.bits && !(index == bitmap.bits && count == 0)) {
        return false;
    }
    return count <= bitmap.bits - index;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint8_t nr1_RtlAreBitsSet(
    const void* header, std::uint32_t index, std::uint32_t count) noexcept {
    BitmapView bitmap;
    if (!bitmap_view(header, bitmap) || !bitmap_range_ok(bitmap, index, count)) {
        return 0;
    }
    for (std::uint32_t i = 0; i < count; ++i) {
        if (!bitmap_get(bitmap, index + i)) {
            return 0;
        }
    }
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint8_t nr1_RtlAreBitsClear(
    const void* header, std::uint32_t index, std::uint32_t count) noexcept {
    BitmapView bitmap;
    if (!bitmap_view(header, bitmap) || !bitmap_range_ok(bitmap, index, count)) {
        return 0;
    }
    for (std::uint32_t i = 0; i < count; ++i) {
        if (bitmap_get(bitmap, index + i)) {
            return 0;
        }
    }
    return 1;
}

extern "C" __attribute__((ms_abi)) void nr1_RtlClearAllBits(
    void* header) noexcept {
    BitmapView bitmap;
    if (!bitmap_view(header, bitmap) || bitmap.bits == 0) {
        return;
    }
    const std::uint32_t words = bitmap_word_count(bitmap);
    for (std::uint32_t w = 0; w < words; ++w) {
        write_u32(const_cast<std::uint8_t*>(bitmap.words),
                  static_cast<std::size_t>(w) * 4, 0);
    }
}

extern "C" __attribute__((ms_abi)) void nr1_RtlClearBits(
    void* header, std::uint32_t index, std::uint32_t count) noexcept {
    BitmapView bitmap;
    if (!bitmap_view(header, bitmap) || !bitmap_range_ok(bitmap, index, count)) {
        return;
    }
    bitmap_set_run(bitmap, index, count, false);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlFindClearBits(
    const void* header, std::uint32_t count, std::uint32_t hint) noexcept {
    BitmapView bitmap;
    if (!bitmap_view(header, bitmap)) {
        return kBitmapError;
    }
    return bitmap_find_run(bitmap, count, hint, false);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlFindClearBitsAndSet(
    const void* header, std::uint32_t count, std::uint32_t hint) noexcept {
    BitmapView bitmap;
    if (!bitmap_view(header, bitmap)) {
        return kBitmapError;
    }
    const std::uint32_t found = bitmap_find_run(bitmap, count, hint, false);
    if (found != kBitmapError) {
        bitmap_set_run(bitmap, found, count, true);
    }
    return found;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlFindClearRuns(
    const void* header, void* runs_out, std::uint32_t run_count,
    std::uint32_t find_longest) noexcept {
    // RTL_BITMAP_RUN: the starting index and the length, two words.
    constexpr std::size_t kRunStart = 0;
    constexpr std::size_t kRunLength = 4;
    constexpr std::size_t kRunBytes = 8;

    BitmapView bitmap;
    if (runs_out == nullptr || run_count == 0 || !bitmap_view(header, bitmap)) {
        return 0;
    }
    std::vector<BitmapRun> runs;
    bitmap_all_runs(bitmap, false, runs);
    if (find_longest != 0) {
        // Stable so that equal-length runs keep their address order, which
        // is the tie-break a caller can reason about.
        for (std::size_t i = 1; i < runs.size(); ++i) {
            BitmapRun key = runs[i];
            std::size_t j = i;
            while (j > 0 && runs[j - 1].length < key.length) {
                runs[j] = runs[j - 1];
                --j;
            }
            runs[j] = key;
        }
    }
    const std::size_t written =
        runs.size() < static_cast<std::size_t>(run_count)
            ? runs.size()
            : static_cast<std::size_t>(run_count);
    for (std::size_t i = 0; i < written; ++i) {
        const std::size_t at = i * kRunBytes;
        write_u32(runs_out, at + kRunStart, runs[i].start);
        write_u32(runs_out, at + kRunLength, runs[i].length);
    }
    return static_cast<std::uint32_t>(written);
}

namespace {

// The shared answer for the longest-run pair: the longest run and where it
// starts, zero when the bitmap has no wanted bits at all.
std::uint32_t bitmap_longest_run(const BitmapView& bitmap, bool want_set,
                                 std::uint32_t* first) noexcept {
    std::vector<BitmapRun> runs;
    bitmap_all_runs(bitmap, want_set, runs);
    const BitmapRun* best = nullptr;
    for (const BitmapRun& run : runs) {
        if (best == nullptr || run.length > best->length) {
            best = &run;
        }
    }
    const std::uint32_t length = best != nullptr ? best->length : 0;
    if (first != nullptr) {
        *first = best != nullptr ? best->start : 0;
    }
    return length;
}

// The first wanted run at or after `from`, scanning forward.
std::uint32_t bitmap_next_forward_run(const BitmapView& bitmap, bool want_set,
                                      std::uint32_t from,
                                      std::uint32_t* first) noexcept {
    if (first != nullptr) {
        *first = 0;
    }
    if (from >= bitmap.bits) {
        return 0;
    }
    std::uint32_t i = from;
    while (i < bitmap.bits && bitmap_get(bitmap, i) != want_set) {
        ++i;
    }
    if (i == bitmap.bits) {
        return 0;
    }
    const std::uint32_t start = i;
    while (i < bitmap.bits && bitmap_get(bitmap, i) == want_set) {
        ++i;
    }
    if (first != nullptr) {
        *first = start;
    }
    return i - start;
}

// The first wanted run at or before `from`, scanning backward.
std::uint32_t bitmap_last_backward_run(const BitmapView& bitmap, bool want_set,
                                       std::uint32_t from,
                                       std::uint32_t* first) noexcept {
    if (first != nullptr) {
        *first = 0;
    }
    if (from >= bitmap.bits) {
        return 0;
    }
    std::uint32_t i = from + 1;
    while (i > 0 && bitmap_get(bitmap, i - 1) != want_set) {
        --i;
    }
    if (i == 0) {
        return 0;
    }
    const std::uint32_t end = i;  // one past the last bit of the run
    while (i > 0 && bitmap_get(bitmap, i - 1) == want_set) {
        --i;
    }
    if (first != nullptr) {
        *first = i;
    }
    return end - i;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlFindLongestRunClear(
    const void* header, std::uint32_t* first) noexcept {
    BitmapView bitmap;
    if (!bitmap_view(header, bitmap)) {
        return 0;
    }
    return bitmap_longest_run(bitmap, false, first);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlFindLongestRunSet(
    const void* header, std::uint32_t* first) noexcept {
    BitmapView bitmap;
    if (!bitmap_view(header, bitmap)) {
        return 0;
    }
    return bitmap_longest_run(bitmap, true, first);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlFindNextForwardRunClear(
    const void* header, std::uint32_t from, std::uint32_t* first) noexcept {
    BitmapView bitmap;
    if (!bitmap_view(header, bitmap)) {
        return 0;
    }
    return bitmap_next_forward_run(bitmap, false, from, first);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlFindNextForwardRunSet(
    const void* header, std::uint32_t from, std::uint32_t* first) noexcept {
    BitmapView bitmap;
    if (!bitmap_view(header, bitmap)) {
        return 0;
    }
    return bitmap_next_forward_run(bitmap, true, from, first);
}

extern "C" __attribute__((ms_abi)) std::uint32_t
nr1_RtlFindLastBackwardRunClear(const void* header, std::uint32_t from,
                                std::uint32_t* first) noexcept {
    BitmapView bitmap;
    if (!bitmap_view(header, bitmap)) {
        return 0;
    }
    return bitmap_last_backward_run(bitmap, false, from, first);
}

extern "C" __attribute__((ms_abi)) std::uint32_t
nr1_RtlFindLastBackwardRunSet(const void* header, std::uint32_t from,
                              std::uint32_t* first) noexcept {
    BitmapView bitmap;
    if (!bitmap_view(header, bitmap)) {
        return 0;
    }
    return bitmap_last_backward_run(bitmap, true, from, first);
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlFindMostSignificantBit(
    std::uint64_t value) noexcept {
    if (value == 0) {
        return -1;
    }
    return static_cast<std::int32_t>(63 - std::countl_zero(value));
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlFindLeastSignificantBit(
    std::uint64_t value) noexcept {
    if (value == 0) {
        return -1;
    }
    return static_cast<std::int32_t>(std::countr_zero(value));
}

namespace {

// ===========================================================================
// Extended-integer arithmetic
// ===========================================================================
//
// The 32-bit-era helpers that answer in a 64-bit register. The multiply is
// done unsigned and reinterpreted: the low 64 bits of the product are the
// same whether the operands were signed or not, and that is what the guest
// reads.

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint64_t nr1_RtlConvertLongToLargeInteger(
    std::int32_t value) noexcept {
    return static_cast<std::uint64_t>(static_cast<std::int64_t>(value));
}

extern "C" __attribute__((ms_abi)) std::uint64_t
nr1_RtlConvertUlongToLargeInteger(std::uint32_t value) noexcept {
    return static_cast<std::uint64_t>(value);
}

extern "C" __attribute__((ms_abi)) std::uint64_t nr1_RtlEnlargedIntegerMultiply(
    std::int32_t left, std::int32_t right) noexcept {
    return static_cast<std::uint64_t>(
        static_cast<std::uint64_t>(static_cast<std::int64_t>(left)) *
        static_cast<std::uint64_t>(static_cast<std::int64_t>(right)));
}

extern "C" __attribute__((ms_abi)) std::uint64_t
nr1_RtlEnlargedUnsignedMultiply(std::uint32_t left,
                                std::uint32_t right) noexcept {
    return static_cast<std::uint64_t>(left) *
           static_cast<std::uint64_t>(right);
}

extern "C" __attribute__((ms_abi)) std::uint64_t nr1_RtlEnlargedUnsignedDivide(
    std::uint64_t dividend, std::uint32_t divisor,
    std::uint32_t* remainder) noexcept {
    // Division by zero is the caller's bug on Windows and would fault there;
    // here it answers zero rather than taking the runtime down, and the
    // remainder is zeroed so a caller that reads it unconditionally reads
    // something defined.
    if (divisor == 0) {
        if (remainder != nullptr) {
            *remainder = 0;
        }
        return 0;
    }
    if (remainder != nullptr) {
        *remainder = static_cast<std::uint32_t>(dividend % divisor);
    }
    return dividend / divisor;
}

extern "C" __attribute__((ms_abi)) std::uint64_t nr1_RtlExtendedIntegerMultiply(
    std::uint64_t multiplicand, std::int32_t multiplier) noexcept {
    // The product's low 64 bits are the same in signed and unsigned
    // arithmetic, so the multiply runs unsigned and the guest reinterprets.
    const std::uint64_t left =
        static_cast<std::uint64_t>(static_cast<std::int64_t>(multiplicand));
    const std::uint64_t right =
        static_cast<std::uint64_t>(static_cast<std::int64_t>(multiplier));
    return left * right;
}

extern "C" __attribute__((ms_abi)) std::uint64_t
nr1_RtlExtendedLargeIntegerDivide(std::uint64_t dividend, std::int32_t divisor,
                                  std::int32_t* remainder) noexcept {
    const std::int64_t numer = static_cast<std::int64_t>(dividend);
    if (divisor == 0 || (numer == INT64_MIN && divisor == -1)) {
        // The INT64_MIN / -1 case is the one signed division that has no
        // 64-bit answer; Windows traps on it and this answers the dividend
        // rather than taking the runtime down.
        if (remainder != nullptr) {
            *remainder = 0;
        }
        return 0;
    }
    if (remainder != nullptr) {
        *remainder = static_cast<std::int32_t>(numer % divisor);
    }
    return static_cast<std::uint64_t>(numer / divisor);
}

namespace {

// ===========================================================================
// Access masks, LUIDs
// ===========================================================================

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlAreAllAccessesGranted(
    std::uint32_t desired, std::uint32_t granted) noexcept {
    return (desired & ~granted) == 0 ? 1u : 0u;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlAreAnyAccessesGranted(
    std::uint32_t desired, std::uint32_t granted) noexcept {
    return (desired & granted) != 0 ? 1u : 0u;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlEqualLuid(
    const void* left, const void* right) noexcept {
    if (left == nullptr || right == nullptr) {
        return 0;
    }
    return read_ptr(left, 0) == read_ptr(right, 0) ? 1u : 0u;
}

namespace {

// ===========================================================================
// CRC-32
// ===========================================================================
//
// The zlib polynomial and the zlib framing: the caller's value is the
// previous CRC, complemented on the way in and complemented on the way out,
// which is what makes the result chainable across calls.

constexpr std::uint32_t kCrcPolynomial = 0xEDB88320u;

[[nodiscard]] const std::uint32_t* crc_table() noexcept {
    static const std::uint32_t table = 0;  // never used directly; see below
    (void)table;
    struct TableBuilder {
        std::uint32_t values[256];
    };
    static const TableBuilder built = [] {
        TableBuilder t{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int bit = 0; bit < 8; ++bit) {
                c = (c & 1u) != 0 ? (c >> 1) ^ kCrcPolynomial : c >> 1;
            }
            t.values[i] = c;
        }
        return t;
    }();
    return built.values;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlComputeCrc32(
    std::uint32_t initial, const std::uint8_t* data,
    std::uint32_t length) noexcept {
    // A null buffer with a zero length is the "continue the stream" call and
    // answers the complement pair around a zero, which chains correctly; a
    // null buffer with bytes to read would fault on Windows and is refused
    // here with the same answer.
    std::uint32_t crc = initial ^ 0xFFFFFFFFu;
    if (data != nullptr) {
        const std::uint32_t* table = crc_table();
        for (std::uint32_t i = 0; i < length; ++i) {
            crc = table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

namespace {

// ===========================================================================
// Pointer encoding
// ===========================================================================
//
// One per-process cookie, mixed from addresses and clock state so that a
// restart re-keys the process. The scramble is rotate-16 then exclusive-or,
// which is the shape Microsoft's own encoder uses and, more importantly, is
// exactly reversible -- a decoder that disagrees with its encoder by one bit
// would corrupt every pointer through it.

[[nodiscard]] std::uint64_t pointer_cookie() noexcept {
    static const std::uint64_t cookie = [] {
        const std::uint64_t self =
            reinterpret_cast<std::uint64_t>(&cookie);
        const std::uint64_t pid = static_cast<std::uint64_t>(::getpid());
        const std::uint64_t ticks = static_cast<std::uint64_t>(::clock());
        std::uint64_t v = self ^ (pid << 1) ^ (ticks << 17) ^ ticks;
        v ^= v >> 33;
        v *= 0xFF51AFD7ED558CCDULL;
        v ^= v >> 33;
        return v != 0 ? v : 0x9E3779B97F4A7C15ULL;
    }();
    return cookie;
}

}  // namespace

extern "C" __attribute__((ms_abi)) void* nr1_RtlEncodePointer(
    void* pointer) noexcept {
    const auto raw = reinterpret_cast<std::uint64_t>(pointer);
    return reinterpret_cast<void*>(
        std::rotl(raw, 16) ^ pointer_cookie());
}

extern "C" __attribute__((ms_abi)) void* nr1_RtlDecodePointer(
    void* pointer) noexcept {
    const auto raw = reinterpret_cast<std::uint64_t>(pointer);
    return reinterpret_cast<void*>(
        std::rotr(raw ^ pointer_cookie(), 16));
}

// The system-cookie pair shares the cookie here. On Windows the two cookies
// differ; nothing a guest can observe depends on that, and one cookie keeps
// the decoder honest by construction.
extern "C" __attribute__((ms_abi)) void* nr1_RtlEncodeSystemPointer(
    void* pointer) noexcept {
    return nr1_RtlEncodePointer(pointer);
}

extern "C" __attribute__((ms_abi)) void* nr1_RtlDecodeSystemPointer(
    void* pointer) noexcept {
    return nr1_RtlDecodePointer(pointer);
}

namespace {

// ===========================================================================
// Locks a single-threaded guest takes uncontended
// ===========================================================================
//
// Every acquisition below is immediate success, which is the real semantics
// for the one thread this runtime runs: a critical section, SRW lock or
// resource with no other contender is acquired on entry on Windows too.
// There are no corresponding release calls in this slice to disagree with.

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlEnterCriticalSection(
    void* critical_section) noexcept {
    (void)critical_section;
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDeleteCriticalSection(
    void* critical_section) noexcept {
    (void)critical_section;
    // Deletion fails on Windows only when threads are queued on the lock;
    // there are none.
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) void nr1_RtlAcquirePebLock() noexcept {
    // The PEB lock is contended only by other threads of this process.
}

extern "C" __attribute__((ms_abi)) void nr1_RtlAcquireSRWLockExclusive(
    void* lock) noexcept {
    (void)lock;
}

extern "C" __attribute__((ms_abi)) void nr1_RtlAcquireSRWLockShared(
    void* lock) noexcept {
    (void)lock;
}

extern "C" __attribute__((ms_abi)) std::uint32_t
nr1_RtlAcquireResourceExclusive(void* resource, std::uint32_t wait) noexcept {
    (void)resource;
    (void)wait;
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlAcquireResourceShared(
    void* resource, std::uint32_t wait) noexcept {
    (void)resource;
    (void)wait;
    return 1;
}

extern "C" __attribute__((ms_abi)) void nr1_RtlDeleteResource(
    void* resource) noexcept {
    (void)resource;
}

extern "C" __attribute__((ms_abi)) std::int32_t
nr1_RtlConvertExclusiveToShared(void* resource) noexcept {
    (void)resource;
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::int32_t
nr1_RtlConvertSharedToExclusive(void* resource) noexcept {
    (void)resource;
    // An upgrade on Windows fails when a second reader holds the resource;
    // there is no second reader.
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlBarrier(
    void* barrier, std::uint32_t flags) noexcept {
    (void)barrier;
    (void)flags;
    // A barrier releases when its thread count arrives; the count for the
    // one thread here arrived the moment it was asked.
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDeleteBarrier(
    void* barrier) noexcept {
    (void)barrier;
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) void nr1_RtlDumpResource(
    const void* resource) noexcept {
    (void)resource;
    // The checked-build debug channel this dumps to has no equivalent here;
    // shipping nothing is the free build's answer.
}

namespace {

// ===========================================================================
// ACLs, security descriptors, SIDs
// ===========================================================================
//
// ACL, byte offsets. An ACL is a fixed-size buffer the caller owns: the
// size field is the buffer's capacity and never grows after creation, and
// an add that does not fit is refused rather than reallocated, because the
// caller sized the buffer and a silent growth would move ACEs it already
// holds pointers into.
constexpr std::size_t kAclRevision = 0;  // uint8
[[maybe_unused]] constexpr std::size_t kAclSbz1 = 1;
constexpr std::size_t kAclSize = 2;      // uint16, buffer capacity
constexpr std::size_t kAclAceCount = 4;  // uint16
[[maybe_unused]] constexpr std::size_t kAclSbz2 = 6;
constexpr std::size_t kAclHeaderBytes = 8;

// ACE, byte offsets. The header is four bytes, the mask four, and the SID
// follows the mask for the simple ACE shapes.
constexpr std::size_t kAceType = 0;   // uint8
constexpr std::size_t kAceFlags = 1;  // uint8
constexpr std::size_t kAceSize = 2;   // uint16
constexpr std::size_t kAceMask = 4;   // uint32
constexpr std::size_t kAceSid = 8;

constexpr std::uint8_t kRevisionAcl = 2;
constexpr std::uint8_t kRevisionAclDs = 4;

constexpr std::uint8_t kAceTypeAllowed = 0;
constexpr std::uint8_t kAceTypeDenied = 1;
constexpr std::uint8_t kAceTypeAudit = 2;
constexpr std::uint8_t kAceTypeMandatoryLabel = 0x11;
constexpr std::uint8_t kAceTypeProcessTrustLabel = 0x12;

// SID, byte offsets. The length is 8 bytes of header plus four per
// subauthority, and the subauthority count is capped by the format itself.
constexpr std::size_t kSidRevision = 0;           // uint8, always 1
constexpr std::size_t kSidSubAuthorityCount = 1;  // uint8
constexpr std::size_t kSidIdentifierAuthority = 2;  // six bytes
constexpr std::size_t kSidSubAuthorities = 8;       // uint32 array
constexpr std::uint8_t kSidMaxSubAuthorities = 15;

// Returns the SID's byte length, or zero when the SID is malformed. Every
// caller treats zero as "not a SID".
[[nodiscard]] std::uint32_t sid_length(const void* sid) noexcept {
    if (sid == nullptr) {
        return 0;
    }
    if (read_u8(sid, kSidRevision) != 1) {
        return 0;
    }
    const std::uint8_t count = read_u8(sid, kSidSubAuthorityCount);
    if (count > kSidMaxSubAuthorities) {
        return 0;
    }
    return kSidSubAuthorities + 4u * static_cast<std::uint32_t>(count);
}

// The byte offset one past the last ACE, walked from the header. The walk
// stops at a malformed size rather than running off the buffer.
[[nodiscard]] std::size_t acl_aces_end(const void* acl) noexcept {
    const std::uint16_t count = read_u16(acl, kAclAceCount);
    std::size_t at = kAclHeaderBytes;
    for (std::uint16_t i = 0; i < count; ++i) {
        const std::uint16_t size = read_u16(acl, at + kAceSize);
        if (size < 4) {
            break;
        }
        at += size;
    }
    return at;
}

[[nodiscard]] bool acl_revision_ok(const void* acl) noexcept {
    const std::uint8_t revision = read_u8(acl, kAclRevision);
    return revision == kRevisionAcl || revision == kRevisionAclDs;
}

// The core every simple ACE lands in: validate, place the ACE at the end of
// the used space, and count it.
[[nodiscard]] std::int32_t acl_add_simple_ace(void* acl,
                                              std::uint32_t revision,
                                              std::uint8_t type,
                                              std::uint32_t flags,
                                              std::uint32_t mask,
                                              const void* sid) noexcept {
    if (acl == nullptr) {
        return kStatusInvalidParameter;
    }
    if (!acl_revision_ok(acl)) {
        return kStatusInvalidAcl;
    }
    if (revision != kRevisionAcl && revision != kRevisionAclDs) {
        return kStatusRevisionMismatch;
    }
    if (revision < read_u8(acl, kAclRevision)) {
        // Inferred: the ACE revision may not be older than the ACL's. The
        // documentation names a revision mismatch here without spelling out
        // the comparison direction; "the ACL is at least as new as the ACE"
        // is the reading that keeps a DS revision ACL from receiving a
        // revision-2 ACE its format cannot express.
        return kStatusRevisionMismatch;
    }
    const std::uint32_t sid_bytes = sid_length(sid);
    if (sid_bytes == 0) {
        return kStatusInvalidSid;
    }
    const std::uint32_t ace_bytes = kAceSid + sid_bytes;
    if (ace_bytes > 0xFFFFu) {
        return kStatusInvalidParameter;
    }
    const std::size_t end = acl_aces_end(acl);
    if (end + ace_bytes > read_u16(acl, kAclSize)) {
        return kStatusBufferTooSmall;
    }
    if (read_u16(acl, kAclAceCount) == 0xFFFFu) {
        return kStatusInvalidAcl;
    }
    write_u8(acl, end + kAceType, type);
    write_u8(acl, end + kAceFlags, static_cast<std::uint8_t>(flags));
    write_u16(acl, end + kAceSize, static_cast<std::uint16_t>(ace_bytes));
    write_u32(acl, end + kAceMask, mask);
    std::memcpy(static_cast<std::uint8_t*>(acl) + end + kAceSid, sid,
                sid_bytes);
    write_u16(acl, kAclAceCount,
              static_cast<std::uint16_t>(read_u16(acl, kAclAceCount) + 1));
    return kStatusSuccess;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCreateAcl(
    void* acl, std::uint32_t size, std::uint32_t revision) noexcept {
    if (acl == nullptr) {
        return kStatusInvalidParameter;
    }
    if (size < kAclHeaderBytes || size > 0xFFFFu || (size & 3u) != 0) {
        return kStatusInvalidParameter;
    }
    if (revision != kRevisionAcl && revision != kRevisionAclDs) {
        return kStatusInvalidParameter;
    }
    std::memset(acl, 0, size);
    write_u8(acl, kAclRevision, static_cast<std::uint8_t>(revision));
    write_u16(acl, kAclSize, static_cast<std::uint16_t>(size));
    write_u16(acl, kAclAceCount, 0);
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddAccessAllowedAce(
    void* acl, std::uint32_t revision, std::uint32_t mask,
    const void* sid) noexcept {
    return acl_add_simple_ace(acl, revision, kAceTypeAllowed, 0, mask, sid);
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddAccessAllowedAceEx(
    void* acl, std::uint32_t revision, std::uint32_t flags,
    std::uint32_t mask, const void* sid) noexcept {
    return acl_add_simple_ace(acl, revision, kAceTypeAllowed, flags, mask,
                              sid);
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddAccessDeniedAce(
    void* acl, std::uint32_t revision, std::uint32_t mask,
    const void* sid) noexcept {
    return acl_add_simple_ace(acl, revision, kAceTypeDenied, 0, mask, sid);
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddAccessDeniedAceEx(
    void* acl, std::uint32_t revision, std::uint32_t flags,
    std::uint32_t mask, const void* sid) noexcept {
    return acl_add_simple_ace(acl, revision, kAceTypeDenied, flags, mask,
                              sid);
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddAuditAccessAce(
    void* acl, std::uint32_t revision, std::uint32_t mask, const void* sid,
    std::uint32_t success, std::uint32_t failure) noexcept {
    // Audit ACEs carry their success/failure usage in the ACE flags.
    std::uint32_t flags = 0;
    if (success != 0) {
        flags |= 0x40u;  // SUCCESSFUL_ACCESS_ACE_FLAG
    }
    if (failure != 0) {
        flags |= 0x80u;  // FAILED_ACCESS_ACE_FLAG
    }
    return acl_add_simple_ace(acl, revision, kAceTypeAudit, flags, mask, sid);
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddAuditAccessAceEx(
    void* acl, std::uint32_t revision, std::uint32_t flags,
    std::uint32_t mask, const void* sid, std::uint32_t success,
    std::uint32_t failure) noexcept {
    std::uint32_t all_flags = flags;
    if (success != 0) {
        all_flags |= 0x40u;
    }
    if (failure != 0) {
        all_flags |= 0x80u;
    }
    return acl_add_simple_ace(acl, revision, kAceTypeAudit, all_flags, mask,
                              sid);
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddMandatoryAce(
    void* acl, std::uint32_t revision, std::uint32_t flags,
    std::uint32_t mandatory_policy, std::uint8_t ace_type,
    const void* sid) noexcept {
    if (ace_type != kAceTypeMandatoryLabel &&
        ace_type != kAceTypeProcessTrustLabel) {
        return kStatusInvalidParameter;
    }
    return acl_add_simple_ace(acl, revision, ace_type, flags,
                              mandatory_policy, sid);
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddProcessTrustLabelAce(
    void* acl, std::uint32_t revision, std::uint32_t flags,
    std::uint32_t access_mask, std::uint8_t ace_type,
    const void* sid) noexcept {
    if (ace_type != kAceTypeMandatoryLabel &&
        ace_type != kAceTypeProcessTrustLabel) {
        return kStatusInvalidParameter;
    }
    return acl_add_simple_ace(acl, revision, ace_type, flags, access_mask,
                              sid);
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddAce(
    void* acl, std::uint32_t revision, std::uint32_t index,
    const void* ace_list, std::uint32_t list_bytes) noexcept {
    if (acl == nullptr) {
        return kStatusInvalidParameter;
    }
    if (!acl_revision_ok(acl)) {
        return kStatusInvalidAcl;
    }
    if (revision != kRevisionAcl && revision != kRevisionAclDs) {
        return kStatusRevisionMismatch;
    }
    if (revision < read_u8(acl, kAclRevision)) {
        return kStatusRevisionMismatch;
    }
    if (list_bytes == 0) {
        return kStatusSuccess;
    }
    if (ace_list == nullptr) {
        return kStatusInvalidParameter;
    }
    // Walk the caller's list once: every ACE must be a whole number of
    // dwords, at least a header, and together they must exactly span the
    // byte count given. A list that does not add up is not a list to paste.
    std::uint32_t total = 0;
    std::uint16_t parsed = 0;
    while (total < list_bytes) {
        if (list_bytes - total < 4) {
            return kStatusInvalidAcl;
        }
        const std::uint16_t size = read_u16(ace_list, total + kAceSize);
        if (size < 4 || (size & 3u) != 0 || total + size > list_bytes) {
            return kStatusInvalidAcl;
        }
        total += size;
        ++parsed;
    }
    const std::uint16_t count = read_u16(acl, kAclAceCount);
    if (index > count) {
        return kStatusInvalidParameter;
    }
    if (static_cast<std::uint32_t>(count) + parsed > 0xFFFFu) {
        return kStatusInvalidAcl;
    }
    // Walk to the insertion point, then open a gap of exactly the list size.
    std::size_t at = kAclHeaderBytes;
    for (std::uint32_t i = 0; i < index; ++i) {
        at += read_u16(acl, at + kAceSize);
    }
    const std::size_t end = acl_aces_end(acl);
    if (end + list_bytes > read_u16(acl, kAclSize)) {
        return kStatusBufferTooSmall;
    }
    std::memmove(static_cast<std::uint8_t*>(acl) + at + list_bytes,
                 static_cast<const std::uint8_t*>(acl) + at, end - at);
    std::memcpy(static_cast<std::uint8_t*>(acl) + at, ace_list, list_bytes);
    write_u16(acl, kAclAceCount, static_cast<std::uint16_t>(count + parsed));
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDeleteAce(
    void* acl, std::uint32_t index) noexcept {
    if (acl == nullptr) {
        return kStatusInvalidParameter;
    }
    const std::uint16_t count = read_u16(acl, kAclAceCount);
    if (index >= count) {
        return kStatusInvalidParameter;
    }
    std::size_t at = kAclHeaderBytes;
    for (std::uint32_t i = 0; i < index; ++i) {
        at += read_u16(acl, at + kAceSize);
    }
    const std::uint16_t size = read_u16(acl, at + kAceSize);
    const std::size_t end = acl_aces_end(acl);
    std::memmove(static_cast<std::uint8_t*>(acl) + at,
                 static_cast<const std::uint8_t*>(acl) + at + size,
                 end - at - size);
    write_u16(acl, kAclAceCount, static_cast<std::uint16_t>(count - 1));
    // The buffer's capacity is the caller's; removing an ACE frees space
    // inside it, not bytes of it.
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::int32_t
nr1_RtlCreateSecurityDescriptor(void* descriptor,
                                std::uint32_t revision) noexcept {
    if (descriptor == nullptr) {
        return kStatusInvalidParameter;
    }
    if (revision != 1) {
        return kStatusUnknownRevision;
    }
    std::memset(descriptor, 0, 40);
    write_u8(descriptor, 0, 1);
    return kStatusSuccess;
}

namespace {
// SECURITY_DESCRIPTOR, absolute form, byte offsets on the 64-bit ABI: two
// bytes of header, the control word, then four pointers.
[[maybe_unused]] constexpr std::size_t kSdRevision = 0;  // uint8
constexpr std::size_t kSdControl = 2;   // uint16
constexpr std::size_t kSdOwner = 8;
constexpr std::size_t kSdGroup = 16;
constexpr std::size_t kSdSacl = 24;
constexpr std::size_t kSdDacl = 32;
constexpr std::size_t kSdBytes = 40;
constexpr std::uint16_t kSdControlSelfRelative = 0x8000;
}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t
nr1_RtlAbsoluteToSelfRelativeSD(const void* descriptor, void* self_relative,
                                std::uint32_t* buffer_length) noexcept {
    if (descriptor == nullptr || buffer_length == nullptr) {
        return kStatusInvalidParameter;
    }
    if ((read_u16(descriptor, kSdControl) & kSdControlSelfRelative) != 0) {
        // Already self-relative: the conversion has no answer and Windows
        // refuses it the same way.
        return kStatusInvalidParameter;
    }
    // The self-relative form is the same 40-byte header with offsets in
    // place of pointers, followed by the pointed-to bodies.
    std::uint32_t needed = kSdBytes;
    const void* owner = reinterpret_cast<const void*>(
        read_ptr(descriptor, kSdOwner));
    const void* group = reinterpret_cast<const void*>(
        read_ptr(descriptor, kSdGroup));
    const void* sacl = reinterpret_cast<const void*>(
        read_ptr(descriptor, kSdSacl));
    const void* dacl = reinterpret_cast<const void*>(
        read_ptr(descriptor, kSdDacl));
    const std::uint32_t owner_len = sid_length(owner);
    const std::uint32_t group_len = sid_length(group);
    const std::uint32_t sacl_len =
        sacl != nullptr ? read_u16(sacl, kAclSize) : 0;
    const std::uint32_t dacl_len =
        dacl != nullptr ? read_u16(dacl, kAclSize) : 0;
    needed += owner_len + group_len + sacl_len + dacl_len;
    if (self_relative == nullptr || *buffer_length < needed) {
        *buffer_length = needed;
        return kStatusBufferTooSmall;
    }
    auto* out = static_cast<std::uint8_t*>(self_relative);
    std::memcpy(out, descriptor, kSdBytes);
    std::uint32_t at = kSdBytes;
    const auto place = [&](std::size_t field, const void* body,
                           std::uint32_t body_len) {
        if (body != nullptr && body_len != 0) {
            write_u32(out, field, at);
            std::memcpy(out + at, body, body_len);
            at += body_len;
        } else {
            write_u32(out, field, 0);
        }
    };
    place(kSdOwner, owner, owner_len);
    place(kSdGroup, group, group_len);
    place(kSdSacl, sacl, sacl_len);
    place(kSdDacl, dacl, dacl_len);
    write_u16(out, kSdControl,
              static_cast<std::uint16_t>(read_u16(descriptor, kSdControl) |
                                         kSdControlSelfRelative));
    *buffer_length = needed;
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) void* nr1_RtlAllocateAndInitializeSid(
    const void* identifier_authority, std::uint32_t sub_authority_count,
    std::uint32_t sub0, std::uint32_t sub1, std::uint32_t sub2,
    std::uint32_t sub3, std::uint32_t sub4, std::uint32_t sub5,
    std::uint32_t sub6, std::uint32_t sub7) noexcept {
    // This entry point carries exactly eight subauthority slots, which caps
    // the count below the format's own limit of fifteen.
    if (identifier_authority == nullptr || sub_authority_count > 8) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    const std::uint64_t bytes =
        kSidSubAuthorities + 4ull * sub_authority_count;
    void* raw = heap_alloc(0, bytes);
    if (raw == nullptr) {
        set_last_error(kErrorNotEnoughMemory);
        return nullptr;
    }
    write_u8(raw, kSidRevision, 1);
    write_u8(raw, kSidSubAuthorityCount,
             static_cast<std::uint8_t>(sub_authority_count));
    std::memcpy(static_cast<std::uint8_t*>(raw) + kSidIdentifierAuthority,
                identifier_authority, 6);
    const std::uint32_t subs[8] = {sub0, sub1, sub2, sub3,
                                   sub4, sub5, sub6, sub7};
    for (std::uint32_t i = 0; i < sub_authority_count; ++i) {
        write_u32(raw,
                  kSidSubAuthorities + static_cast<std::size_t>(i) * 4,
                  subs[i]);
    }
    set_last_error(0);
    return raw;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlEqualSid(
    const void* left, const void* right) noexcept {
    const std::uint32_t left_len = sid_length(left);
    const std::uint32_t right_len = sid_length(right);
    if (left_len == 0 || left_len != right_len) {
        return 0;
    }
    return std::memcmp(left, right, left_len) == 0 ? 1u : 0u;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlEqualPrefixSid(
    const void* left, const void* right) noexcept {
    if (sid_length(left) == 0 || sid_length(right) == 0) {
        return 0;
    }
    // The prefix is everything through the identifier authority: revision,
    // count and the six authority bytes, and none of the subauthorities.
    return std::memcmp(left, right, kSidSubAuthorities) == 0 ? 1u : 0u;
}

namespace {

// ===========================================================================
// DOS paths and NT names
// ===========================================================================
//
// UNICODE_STRING, byte offsets on the 64-bit ABI.
constexpr std::size_t kUniLength = 0;        // uint16, bytes
constexpr std::size_t kUniMaximumLength = 2;  // uint16, bytes
constexpr std::size_t kUniBuffer = 8;         // pointer
[[maybe_unused]] constexpr std::size_t kUniBytes = 16;

// RTL_RELATIVE_NAME_U: one UNICODE_STRING, a directory handle, and the
// curdir reference -- 32 bytes. The relative-name entries zero it, which is
// the truthful "this name has no relative form".
constexpr std::size_t kRelativeNameBytes = 32;

// RTL_PATH_TYPE values. The ordering follows the header spelling (unknown,
// UNC, drive-absolute, drive-relative, rooted, relative, local device,
// device); no binary reference was available to confirm the numbering, so
// the test pins exactly these values and flags the choice.
constexpr std::uint32_t kPathTypeUnknown = 0;
constexpr std::uint32_t kPathTypeUncAbsolute = 1;
constexpr std::uint32_t kPathTypeDriveAbsolute = 2;
constexpr std::uint32_t kPathTypeDriveRelative = 3;
constexpr std::uint32_t kPathTypeRooted = 4;
constexpr std::uint32_t kPathTypeRelative = 5;
constexpr std::uint32_t kPathTypeLocalDevice = 6;
constexpr std::uint32_t kPathTypeDevice = 7;

[[nodiscard]] bool is_ascii_letter(char16_t c) noexcept {
    return (c >= u'a' && c <= u'z') || (c >= u'A' && c <= u'Z');
}

// The NT form of a DOS path: the on-disk-device prefix and backslashes
// throughout. The guest owns the characters; the prefix is what NtCreateFile
// resolves against.
[[nodiscard]] std::u16string nt_name_from_dos(std::u16string_view dos) noexcept {
    std::u16string out = u"\\??\\";
    out.reserve(4 + dos.size());
    for (const char16_t c : dos) {
        out.push_back(c == u'/' ? u'\\' : c);
    }
    return out;
}

// The core the two DosPathNameToNtPathName entries share. Fills the
// UNICODE_STRING with a heap-allocated NT name, reports the filename
// component offset, and zeroes the relative-name structure when the caller
// passed one -- zero is the truthful "no relative form", not a stand-in for
// one this runtime could not compute.
[[nodiscard]] std::int32_t dos_to_nt_name(const char16_t* dos, void* nt_name,
                                          std::uint32_t* file_part,
                                          void* relative_name) noexcept {
    if (dos == nullptr || nt_name == nullptr) {
        return kStatusInvalidParameter;
    }
    std::size_t chars = 0;
    while (dos[chars] != u'\0') {
        ++chars;
    }
    const std::u16string nt = nt_name_from_dos(std::u16string_view(dos, chars));
    if (nt.size() >= 0x8000u) {
        // A UNICODE_STRING carries its length in 16 bits; a name that does
        // not fit is refused rather than truncated.
        return kStatusInvalidParameter;
    }
    const std::uint64_t bytes = (static_cast<std::uint64_t>(nt.size()) + 1) * 2;
    void* buffer = heap_alloc(0, bytes);
    if (buffer == nullptr) {
        return kStatusNoMemory;
    }
    std::memcpy(buffer, nt.data(), nt.size() * 2);
    write_u16(buffer, nt.size() * 2, 0);
    write_u16(nt_name, kUniLength,
              static_cast<std::uint16_t>(nt.size() * 2));
    write_u16(nt_name, kUniMaximumLength,
              static_cast<std::uint16_t>(nt.size() * 2 + 2));
    write_ptr(nt_name, kUniBuffer,
              reinterpret_cast<std::uint64_t>(buffer));
    if (file_part != nullptr) {
        // The character offset just past the last separator, which is where
        // the filename component starts; zero when there is none.
        std::size_t last_slash = nt.size();
        for (std::size_t i = nt.size(); i > 0; --i) {
            if (nt[i - 1] == u'\\') {
                last_slash = i - 1;
                break;
            }
        }
        *file_part = last_slash == nt.size()
                         ? 0
                         : static_cast<std::uint32_t>(last_slash + 1);
    }
    if (relative_name != nullptr) {
        std::memset(relative_name, 0, kRelativeNameBytes);
    }
    return kStatusSuccess;
}

// The host path a guest DOS path names. The runtime's drive is `Z:` (see
// `to_dos_path`), so a `Z:` path maps under the host root, a rooted path
// maps to the current drive's root, and a drive this runtime has not
// defined maps to nothing.
[[nodiscard]] bool host_path_from_dos(std::u16string_view dos,
                                      std::string& out) noexcept {
    std::string narrow;
    if (!utf16_to_utf8(dos, narrow)) {
        return false;
    }
    if (narrow.size() >= 2 && (narrow[0] == 'Z' || narrow[0] == 'z') &&
        narrow[1] == ':') {
        std::string rest = narrow.substr(2);
        if (!rest.empty() && (rest.front() == '\\' || rest.front() == '/')) {
            rest.erase(rest.begin());
        }
        out = "/";
        for (const char c : rest) {
            out.push_back(c == '\\' ? '/' : c);
        }
        return true;
    }
    if (narrow.size() >= 2 && is_ascii_letter(static_cast<char16_t>(narrow[0])) &&
        narrow[1] == ':') {
        return false;  // a drive this runtime has not mounted
    }
    if (!narrow.empty() && (narrow[0] == '\\' || narrow[0] == '/')) {
        out = "/";
        for (const char c : narrow.substr(1)) {
            out.push_back(c == '\\' ? '/' : c);
        }
        return true;
    }
    // Relative paths resolve against the process's own working directory,
    // which is the same directory the guest's relative paths have always
    // resolved against in this runtime.
    out.clear();
    for (const char c : narrow) {
        out.push_back(c == '\\' ? '/' : c);
    }
    return true;
}

// Case-folded UTF-16 comparison, ASCII subset. The Windows answer folds
// through the full NLS table; for the ASCII range the two agree, and the
// range beyond it is compared exactly, which is stated rather than hidden.
[[nodiscard]] std::uint16_t upcase_ascii(std::uint16_t c) noexcept {
    return (c >= u'a' && c <= u'z') ? static_cast<std::uint16_t>(c - 0x20) : c;
}

[[nodiscard]] bool unicode_strings_equal_folded(const void* left,
                                                const void* right) noexcept {
    if (left == nullptr || right == nullptr) {
        return false;
    }
    const std::uint64_t left_buffer = read_ptr(left, kUniBuffer);
    const std::uint64_t right_buffer = read_ptr(right, kUniBuffer);
    if (left_buffer == 0 || right_buffer == 0) {
        return false;
    }
    const std::uint16_t left_bytes = read_u16(left, kUniLength);
    if (left_bytes != read_u16(right, kUniLength)) {
        return false;
    }
    const auto* a = reinterpret_cast<const char16_t*>(left_buffer);
    const auto* b = reinterpret_cast<const char16_t*>(right_buffer);
    for (std::size_t i = 0; i < left_bytes / 2; ++i) {
        if (upcase_ascii(static_cast<std::uint16_t>(a[i])) !=
            upcase_ascii(static_cast<std::uint16_t>(b[i]))) {
            return false;
        }
    }
    return true;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t
nr1_RtlDetermineDosPathNameType_U(const char16_t* path) noexcept {
    if (path == nullptr || path[0] == u'\0') {
        return kPathTypeUnknown;
    }
    if (path[0] == u'\\') {
        if (path[1] == u'\\') {
            if (path[2] == u'?' && path[3] == u'\\') {
                return kPathTypeLocalDevice;
            }
            if (path[2] == u'.' && path[3] == u'\\') {
                return kPathTypeDevice;
            }
            return kPathTypeUncAbsolute;
        }
        return kPathTypeRooted;
    }
    if (is_ascii_letter(path[0]) && path[1] == u':') {
        return path[2] == u'\\' ? kPathTypeDriveAbsolute
                                : kPathTypeDriveRelative;
    }
    return kPathTypeRelative;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlDosPathNameToNtPathName_U(
    const char16_t* dos, void* nt_name, std::uint32_t* file_part,
    void* relative_name) noexcept {
    return dos_to_nt_name(dos, nt_name, file_part, relative_name) ==
                   kStatusSuccess
               ? 1u
               : 0u;
}

extern "C" __attribute__((ms_abi)) std::int32_t
nr1_RtlDosPathNameToNtPathName_U_WithStatus(const char16_t* dos,
                                            void* nt_name,
                                            std::uint32_t* file_part,
                                            void* relative_name) noexcept {
    return dos_to_nt_name(dos, nt_name, file_part, relative_name);
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlDoesFileExists_U(
    const char16_t* path) noexcept {
    if (path == nullptr) {
        return 0;
    }
    std::size_t chars = 0;
    while (path[chars] != u'\0') {
        ++chars;
    }
    std::string host;
    if (!host_path_from_dos(std::u16string_view(path, chars), host)) {
        return 0;
    }
    struct stat st {};
    return ::stat(host.c_str(), &st) == 0 ? 1u : 0u;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlEqualComputerName(
    const void* left, const void* right) noexcept {
    return unicode_strings_equal_folded(left, right) ? 1u : 0u;
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlEqualDomainName(
    const void* left, const void* right) noexcept {
    return unicode_strings_equal_folded(left, right) ? 1u : 0u;
}

extern "C" __attribute__((ms_abi)) std::uint32_t
nr1_RtlDllShutdownInProgress() noexcept {
    // The loader shutdown flag this reads is set by a teardown sequence a
    // run inside this runtime never enters; FALSE is the real state.
    return 0;
}

namespace {

// ===========================================================================
// PE image queries
// ===========================================================================
//
// Both queries read the guest's image in place. The image is mapped flat in
// this process, so an RVA is a byte offset from the base and there is no
// section walk to convert it through.

constexpr std::uint32_t kPeSignature = 0x00004550u;  // "PE\0\0"
[[maybe_unused]] constexpr std::size_t kNtMachine = 4;                 // uint16
constexpr std::size_t kNtNumberOfSections = 6;        // uint16
constexpr std::size_t kNtSizeOfOptionalHeader = 20;   // uint16
constexpr std::size_t kNtOptionalHeader = 24;
constexpr std::size_t kOptionalMagic = 0;  // uint16 within optional header
constexpr std::uint16_t kPe32Magic = 0x10B;
constexpr std::uint16_t kPe32PlusMagic = 0x20B;
constexpr std::size_t kPe32DataDirectories = 96;
constexpr std::size_t kPe32PlusDataDirectories = 112;
constexpr std::size_t kSectionBytes = 40;
constexpr std::size_t kSectionVirtualSize = 8;      // uint32
constexpr std::size_t kSectionVirtualAddress = 12;  // uint32
constexpr std::size_t kSectionSizeOfRawData = 16;   // uint32

constexpr std::size_t kDosHeaderLfanew = 0x3C;  // uint32

// The export directory, field offsets.
[[maybe_unused]] constexpr std::size_t kExportBase = 16;
[[maybe_unused]] constexpr std::size_t kExportNumberOfFunctions = 20;
constexpr std::size_t kExportNumberOfNames = 24;
constexpr std::size_t kExportAddressOfFunctions = 28;
constexpr std::size_t kExportAddressOfNames = 32;
constexpr std::size_t kExportAddressOfNameOrdinals = 36;

// The size of the mapped image `base` names, or 0 when `base` is not the
// base of one.
//
// The PE walkers below need a bound, and the only place this runtime knows
// one is its own address-space ledger: a region that starts at `base` is an
// image region with a recorded size, and a pointer that is not the base of
// one is a buffer whose length this layer cannot know. Answering 0 for that
// case is what makes the walkers refuse rather than read past the end --
// which is the right default, because these are called on whatever the
// caller is parsing, not on a file this runtime mapped and therefore knows
// the length of.
[[nodiscard]] std::size_t mapped_image_size(const void* base) noexcept {
    const auto* state = guest_state();
    if (state == nullptr || state->space == nullptr || base == nullptr) {
        return 0;
    }
    const auto address = reinterpret_cast<std::uint64_t>(base);
    const Region* region = state->space->find(address);
    if (region == nullptr || region->base != address) {
        return 0;
    }
    return static_cast<std::size_t>(region->size);
}

// True when `rva` addresses at least `bytes` inside an image of `size`. The
// addition is done in 64 bits because a 32-bit RVA near the top of the
// address space would wrap and pass a check it should fail.
[[nodiscard]] bool in_image(std::uint32_t rva, std::size_t bytes,
                            std::size_t size) noexcept {
    const std::uint64_t end = static_cast<std::uint64_t>(rva) + bytes;
    return end <= static_cast<std::uint64_t>(size);
}

}  // namespace

extern "C" __attribute__((ms_abi)) void* nr1_RtlAddressInSectionTable(
    const void* nt_headers, const void* base, std::uint32_t rva) noexcept {
    if (nt_headers == nullptr || base == nullptr) {
        return nullptr;
    }
    if (read_u32(nt_headers, 0) != kPeSignature) {
        return nullptr;
    }
    // A section may claim a range larger than the image it is in -- the
    // header came from somewhere else, or the file was edited -- and
    // answering with an address inside that range would be an address in
    // memory that is not there.
    const std::size_t image_size = mapped_image_size(base);
    if (image_size == 0) {
        return nullptr;
    }
    const std::uint16_t sections = read_u16(nt_headers, kNtNumberOfSections);
    const std::size_t table =
        kNtOptionalHeader +
        static_cast<std::size_t>(read_u16(nt_headers, kNtSizeOfOptionalHeader));
    for (std::uint16_t i = 0; i < sections; ++i) {
        const std::size_t at = table + static_cast<std::size_t>(i) * kSectionBytes;
        const std::uint32_t va = read_u32(nt_headers, at + kSectionVirtualAddress);
        const std::uint32_t vsize = read_u32(nt_headers, at + kSectionVirtualSize);
        const std::uint32_t raw = read_u32(nt_headers, at + kSectionSizeOfRawData);
        const std::uint32_t span = vsize > raw ? vsize : raw;
        const std::uint64_t upper =
            static_cast<std::uint64_t>(va) + span;
        if (rva >= va && static_cast<std::uint64_t>(rva) < upper) {
            if (!in_image(rva, 1, image_size)) {
                return nullptr;
            }
            return const_cast<std::uint8_t*>(static_cast<const std::uint8_t*>(
                       base) + rva);
        }
    }
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void* nr1_RtlFindExportedRoutineByName(
    const void* image_base, const char* name) noexcept {
    if (image_base == nullptr || name == nullptr) {
        return nullptr;
    }
    const std::size_t image_size = mapped_image_size(image_base);
    if (image_size == 0) {
        return nullptr;
    }
    const std::uint32_t lfanew = read_u32(image_base, kDosHeaderLfanew);
    if (!in_image(lfanew, 0x100, image_size)) {
        return nullptr;
    }
    const auto* nt = static_cast<const std::uint8_t*>(image_base) + lfanew;
    if (read_u32(nt, 0) != kPeSignature) {
        return nullptr;
    }
    const std::uint16_t magic = read_u16(nt, kNtOptionalHeader + kOptionalMagic);
    std::size_t directories = 0;
    if (magic == kPe32PlusMagic) {
        directories = kPe32PlusDataDirectories;
    } else if (magic == kPe32Magic) {
        directories = kPe32DataDirectories;
    } else {
        return nullptr;
    }
    const std::uint32_t export_rva =
        read_u32(nt, kNtOptionalHeader + directories);
    if (export_rva == 0 || !in_image(export_rva, 0x28, image_size)) {
        return nullptr;
    }
    const auto* exports =
        static_cast<const std::uint8_t*>(image_base) + export_rva;
    const std::uint32_t number_of_names =
        read_u32(exports, kExportNumberOfNames);
    if (number_of_names == 0) {
        return nullptr;
    }
    // The three tables are RVAs the image supplies and their sizes follow
    // from the count, so a count that would run one off the end of the image
    // is refused here rather than walked.
    const std::size_t table_bytes =
        static_cast<std::size_t>(number_of_names) * 4;
    const std::uint32_t names_rva = read_u32(exports, kExportAddressOfNames);
    const std::uint32_t ordinals_rva =
        read_u32(exports, kExportAddressOfNameOrdinals);
    const std::uint32_t functions_rva =
        read_u32(exports, kExportAddressOfFunctions);
    if (!in_image(names_rva, table_bytes, image_size) ||
        !in_image(ordinals_rva, table_bytes / 2, image_size) ||
        !in_image(functions_rva, table_bytes, image_size)) {
        return nullptr;
    }
    const auto* names = static_cast<const std::uint8_t*>(image_base) + names_rva;
    const auto* ordinals =
        static_cast<const std::uint8_t*>(image_base) + ordinals_rva;
    const auto* functions =
        static_cast<const std::uint8_t*>(image_base) + functions_rva;
    for (std::uint32_t i = 0; i < number_of_names; ++i) {
        const std::uint32_t name_rva =
            read_u32(names, static_cast<std::size_t>(i) * 4);
        if (!in_image(name_rva, 1, image_size)) {
            continue;
        }
        const char* candidate = static_cast<const char*>(image_base) + name_rva;
        if (std::strcmp(candidate, name) != 0) {
            continue;
        }
        const std::uint16_t ordinal =
            read_u16(ordinals, static_cast<std::size_t>(i) * 2);
        const std::uint32_t function_rva =
            read_u32(functions, static_cast<std::size_t>(ordinal) * 4);
        if (!in_image(function_rva, 1, image_size)) {
            return nullptr;
        }
        return const_cast<std::uint8_t*>(
            static_cast<const std::uint8_t*>(image_base) + function_rva);
    }
    return nullptr;
}

namespace {

// ===========================================================================
// Atom tables
// ===========================================================================
//
// An atom table is a host-side object behind a handle the guest cannot
// interpret: the entries live in host memory the guest does not walk, so a
// corrupt handle is refused by magic rather than dereferenced. Atom values
// start at 0xC000, and the first atom -- the empty string -- is pinned the
// way Windows pins it: additions of "" return it, deletions refuse it.

constexpr std::uint64_t kAtomTableMagic = 0x4F434341544F4D31ULL;  // "OCCATOM1"
constexpr std::uint32_t kAtomFirst = 0xC000;
constexpr std::size_t kMaxAtomNameChars = 255;

struct AtomEntry {
    std::uint32_t atom = 0;
    std::uint32_t refs = 0;
    std::u16string name;
};

struct AtomTable {
    std::uint64_t magic = kAtomTableMagic;
    std::uint32_t next_atom = kAtomFirst + 1;
    std::vector<AtomEntry> entries;
};

// The live tables. The guest runs on one host thread and every writer below
// is reached from it, so there is no lock here for the same reason the heap
// list has none.
std::vector<AtomTable*>& atom_tables() noexcept {
    static std::vector<AtomTable*> tables;
    return tables;
}

[[nodiscard]] AtomTable* atom_table_of(void* handle) noexcept {
    if (handle == nullptr) {
        return nullptr;
    }
    // Membership in the live-table list is checked before any dereference:
    // a handle the guest invented, or one this file already destroyed, must
    // be refused without reading the memory it points at.
    for (AtomTable* live : atom_tables()) {
        if (static_cast<void*>(live) == handle) {
            return live->magic == kAtomTableMagic ? live : nullptr;
        }
    }
    return nullptr;
}

}  // namespace

// Whether a heap handle names a heap this runtime knows.
//
// The heap APIs are split across the Rtl slices: this file mints the
// handles and the third slice answers the queries. A query that accepted
// any non-null handle would answer "the block is not mine" for a block
// that is in a heap it was never told about, so the check lives here,
// with the table that can make it, and the third slice asks.
extern "C" bool occ_heap_handle_ok(std::uint64_t handle) noexcept {
    if (is_process_heap(handle)) {
        return true;
    }
    return as_created_heap(handle) != nullptr;
}

// The three questions `ntdll_rtl_mem2.cpp` asks about an atom table reach
// the table through here rather than keeping a second copy of the entries.
// The reason is not tidiness: two tables of the same atoms would answer
// differently depending on which slice's `RtlCreateAtomTable` the guest saw,
// and an atom added through one spelling would be invisible to the other.
extern "C" std::uint32_t occ_atom_find(void* table, const char16_t* name) noexcept {
    AtomTable* atoms = atom_table_of(table);
    if (atoms == nullptr || name == nullptr) {
        return 0;
    }
    std::size_t chars = 0;
    while (name[chars] != u'\0') {
        ++chars;
    }
    const std::u16string_view text(name, chars);
    for (const AtomEntry& entry : atoms->entries) {
        if (entry.name == text) {
            return entry.atom;
        }
    }
    return 0;
}

extern "C" std::uint32_t occ_atom_query(void* table, std::uint32_t atom,
                                        std::uint32_t* refs, std::uint32_t* flags,
                                        char16_t* name,
                                        std::uint32_t* name_bytes) noexcept {
    constexpr std::uint32_t kAtomQuerySuccess = 0;
    constexpr std::uint32_t kAtomQueryBadParameter = 0xC000000D;
    constexpr std::uint32_t kAtomQueryBadHandle = 0xC0000008;
    constexpr std::uint32_t kAtomQueryShortBuffer = 0xC0000023;
    AtomTable* atoms = atom_table_of(table);
    if (atoms == nullptr) {
        return kAtomQueryBadHandle;
    }
    if (atom < kAtomFirst) {
        return kAtomQueryBadParameter;
    }
    const AtomEntry* found = nullptr;
    for (const AtomEntry& entry : atoms->entries) {
        if (entry.atom == atom) {
            found = &entry;
            break;
        }
    }
    if (found == nullptr) {
        return kAtomQueryBadHandle;
    }
    if (refs != nullptr) {
        *refs = found->refs;
    }
    if (flags != nullptr) {
        // The two flags Windows defines for an atom: 0 for an ordinary
        // string atom, and ATOM_HEAP (1) once the entry is large enough that
        // the table keeps it on the heap rather than in the pool.
        *flags = found->name.size() >= 256 ? 1u : 0u;
    }
    if (name == nullptr || name_bytes == nullptr) {
        return kAtomQuerySuccess;
    }
    // The name comes back without the terminator, and `name_bytes` is both
    // the size the caller's buffer has and the size the name needs -- the
    // in/out convention that lets a caller ask first and then read.
    const std::uint32_t needed =
        static_cast<std::uint32_t>(found->name.size() * sizeof(char16_t));
    if (*name_bytes < needed) {
        *name_bytes = needed;
        return kAtomQueryShortBuffer;
    }
    for (std::size_t i = 0; i < found->name.size(); ++i) {
        name[i] = found->name[i];
    }
    *name_bytes = needed;
    return kAtomQuerySuccess;
}

extern "C" std::uint32_t occ_atom_pin(void* table, std::uint32_t atom) noexcept {
    constexpr std::uint32_t kAtomPinSuccess = 0;
    constexpr std::uint32_t kAtomPinBadParameter = 0xC000000D;
    constexpr std::uint32_t kAtomPinBadHandle = 0xC0000008;
    AtomTable* atoms = atom_table_of(table);
    if (atoms == nullptr) {
        return kAtomPinBadHandle;
    }
    if (atom < kAtomFirst) {
        return kAtomPinBadParameter;
    }
    for (AtomEntry& entry : atoms->entries) {
        if (entry.atom == atom) {
            // Pinning raises the reference count without a matching delete:
            // the entry stays in the table for the life of the table.
            if (entry.refs != 0xFFFFFFFFu) {
                ++entry.refs;
            }
            return kAtomPinSuccess;
        }
    }
    return kAtomPinBadHandle;
}

extern "C" __attribute__((ms_abi)) void* nr1_RtlCreateAtomTable(
    std::uint32_t flags, std::uint32_t buckets) noexcept {
    (void)flags;
    // No flag bits are defined for callers, so none are checked; the bucket
    // count only shapes lookup cost and Windows' default applies when the
    // caller passes zero.
    if (buckets == 0) {
        buckets = 37;
    }
    (void)buckets;
    void* raw = heap_alloc(0, sizeof(AtomTable));
    if (raw == nullptr) {
        set_last_error(kErrorNotEnoughMemory);
        return nullptr;
    }
    auto* table = new (raw) AtomTable;
    table->entries.push_back(AtomEntry{kAtomFirst, 1, std::u16string()});
    atom_tables().push_back(table);
    set_last_error(0);
    return table;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDestroyAtomTable(
    void* table) noexcept {
    AtomTable* atoms = atom_table_of(table);
    if (atoms == nullptr) {
        return kStatusInvalidHandle;
    }
    auto& tables = atom_tables();
    for (std::size_t i = 0; i < tables.size(); ++i) {
        if (tables[i] == atoms) {
            tables.erase(tables.begin() + static_cast<std::ptrdiff_t>(i));
            break;
        }
    }
    atoms->magic = 0;
    atoms->~AtomTable();
    heap_free(atoms);
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddAtomToAtomTable(
    void* table, const char16_t* name, std::uint32_t* atom_out) noexcept {
    AtomTable* atoms = atom_table_of(table);
    if (atoms == nullptr) {
        return kStatusInvalidHandle;
    }
    if (name == nullptr) {
        return kStatusInvalidParameter;
    }
    std::size_t chars = 0;
    while (name[chars] != u'\0') {
        ++chars;
    }
    if (chars > kMaxAtomNameChars) {
        return kStatusInvalidParameter;
    }
    const std::u16string_view text(name, chars);
    for (AtomEntry& entry : atoms->entries) {
        if (entry.name == text) {
            if (entry.refs != 0xFFFFFFFFu) {
                ++entry.refs;
            }
            if (atom_out != nullptr) {
                *atom_out = entry.atom;
            }
            return kStatusSuccess;
        }
    }
    if (atoms->next_atom > 0xFFFFu) {
        // The atom value is a 16-bit quantity starting at 0xC000: when the
        // table has handed out every value there is no new atom to add.
        return kStatusInsufficientResources;
    }
    atoms->entries.push_back(AtomEntry{atoms->next_atom, 1, std::u16string(text)});
    if (atom_out != nullptr) {
        *atom_out = atoms->next_atom;
    }
    ++atoms->next_atom;
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDeleteAtomFromAtomTable(
    void* table, std::uint32_t atom) noexcept {
    AtomTable* atoms = atom_table_of(table);
    if (atoms == nullptr) {
        return kStatusInvalidHandle;
    }
    if (atom < kAtomFirst) {
        return kStatusInvalidParameter;
    }
    if (atom == kAtomFirst) {
        // The pinned atom backs the empty string every table carries;
        // deleting it would leave a table that cannot answer "".
        return kStatusInvalidParameter;
    }
    for (std::size_t i = 0; i < atoms->entries.size(); ++i) {
        if (atoms->entries[i].atom == atom) {
            if (--atoms->entries[i].refs == 0) {
                atoms->entries.erase(atoms->entries.begin() +
                                     static_cast<std::ptrdiff_t>(i));
            }
            return kStatusSuccess;
        }
    }
    return kStatusInvalidHandle;
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlEmptyAtomTable(
    void* table, std::uint32_t include_pinned) noexcept {
    AtomTable* atoms = atom_table_of(table);
    if (atoms == nullptr) {
        return kStatusInvalidHandle;
    }
    if (include_pinned != 0) {
        atoms->entries.clear();
        atoms->next_atom = kAtomFirst;
    } else {
        std::vector<AtomEntry> kept;
        for (AtomEntry& entry : atoms->entries) {
            if (entry.atom == kAtomFirst) {
                kept.push_back(std::move(entry));
            }
        }
        atoms->entries = std::move(kept);
    }
    return kStatusSuccess;
}

namespace {

// ===========================================================================
// Vectored handler registration
// ===========================================================================
//
// Registration is a real list insert: first-handler goes to the front, the
// rest append, in the order Windows dispatches them. What this slice does
// not do is dispatch -- the exception machinery that walks these lists is
// the SEH layer's, and registration here only maintains the order a
// dispatcher would walk.

struct VectoredList {
    std::uint64_t magic;
    std::vector<void*> handlers;
};

constexpr std::uint64_t kVectoredMagic = 0x4F43435645485431ULL;  // "OCCVEHT1"

VectoredList& vectored_exception_list() noexcept {
    static VectoredList list{kVectoredMagic, {}};
    return list;
}

VectoredList& vectored_continue_list() noexcept {
    static VectoredList list{kVectoredMagic, {}};
    return list;
}

[[nodiscard]] void* vectored_add(VectoredList& list, std::uint32_t first,
                                 void* handler) noexcept {
    if (handler == nullptr) {
        return nullptr;
    }
    if (first != 0) {
        list.handlers.insert(list.handlers.begin(), handler);
    } else {
        list.handlers.push_back(handler);
    }
    // The token is the handler itself, not the list node Windows returns.
    // Removal is not part of this slice; when it lands it must accept this
    // token form or the two must change together.
    return handler;
}

}  // namespace

extern "C" __attribute__((ms_abi)) void* nr1_RtlAddVectoredExceptionHandler(
    std::uint32_t first, void* handler) noexcept {
    return vectored_add(vectored_exception_list(), first, handler);
}

extern "C" __attribute__((ms_abi)) void* nr1_RtlAddVectoredContinueHandler(
    std::uint32_t first, void* handler) noexcept {
    return vectored_add(vectored_continue_list(), first, handler);
}

extern "C" bool occ_vectored_remove(void* handler, bool is_continue) noexcept {
    if (handler == nullptr) {
        return false;
    }
    VectoredList& list = is_continue ? vectored_continue_list()
                                     : vectored_exception_list();
    for (std::size_t i = 0; i < list.handlers.size(); ++i) {
        if (list.handlers[i] == handler) {
            list.handlers.erase(list.handlers.begin() +
                                static_cast<std::ptrdiff_t>(i));
            return true;
        }
    }
    return false;
}

// ===========================================================================
// Remaining answers
// ===========================================================================

extern "C" __attribute__((ms_abi)) void nr1_RtlAssert(
    const void* failed_assertion, const void* file_name,
    std::uint32_t line_number, const char* message) noexcept {
    (void)failed_assertion;
    (void)file_name;
    (void)line_number;
    (void)message;
    // RtlAssert is the checked-build assertion; the free build ships it as
    // a no-op, and this runtime is the free build.
}

extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlCaptureStackBackTrace(
    std::uint32_t frames_to_skip, std::uint32_t frames_to_capture,
    void** back_trace, std::uint32_t* back_trace_hash) noexcept {
    (void)frames_to_skip;
    (void)frames_to_capture;
    (void)back_trace;
    if (back_trace_hash != nullptr) {
        *back_trace_hash = 0;
    }
    // Unwinding the guest's frames needs the frame metadata the translated
    // code does not carry; zero frames captured is the honest count, not a
    // stand-in for a stack this runtime cannot describe.
    return 0;
}

extern "C" __attribute__((ms_abi)) void nr1_RtlExitUserProcess(
    std::int32_t status) noexcept {
    // The exit is the process layer's; ntdll's exit and kernel32's end in
    // the same place.
    k32_ExitProcess(static_cast<std::uint32_t>(status));
}

extern "C" __attribute__((ms_abi)) void nr1_RtlExitUserThread(
    std::int32_t status) noexcept {
    // The guest runs one thread: exiting it exits the process, which is
    // what Windows does with the last thread too.
    k32_ExitProcess(static_cast<std::uint32_t>(status));
}

// ===========================================================================
// Refusals
// ===========================================================================
//
// Each refusal names the subsystem that is missing. A refusal with a reason
// is worth more than an answer this runtime cannot stand behind.

namespace {

// ---- RXact: transactional registry. The transaction log and the apply
// path belong to a registry implementation this slice is not given.
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAbortRXact(
    void* rxact_context) noexcept {
    (void)rxact_context;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddActionToRXact(
    void* rxact_context, std::uint32_t operation_key, void* key_name,
    std::uint32_t disposition, void* new_value) noexcept {
    (void)rxact_context;
    (void)operation_key;
    (void)key_name;
    (void)disposition;
    (void)new_value;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddAttributeActionToRXact(
    void* rxact_context, std::uint32_t operation_key, void* key_name,
    std::uint32_t disposition, void* attribute_flags, void* new_value) noexcept {
    (void)rxact_context;
    (void)operation_key;
    (void)key_name;
    (void)disposition;
    (void)attribute_flags;
    (void)new_value;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlApplyRXact(
    void* rxact_context) noexcept {
    (void)rxact_context;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlApplyRXactNoFlush(
    void* rxact_context) noexcept {
    (void)rxact_context;
    return refuse();
}

// ---- Activation contexts: the manifest store and its refcounts.
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlActivateActivationContext(
    std::uint32_t unused, void* handle, void* cookie) noexcept {
    (void)unused;
    (void)handle;
    (void)cookie;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlActivateActivationContextEx(
    std::uint32_t flags, void* teb, void* handle, void* cookie) noexcept {
    (void)flags;
    (void)teb;
    (void)handle;
    (void)cookie;
    return refuse();
}

extern "C" __attribute__((ms_abi)) void
nr1_RtlActivateActivationContextUnsafeFast(void* cookie,
                                           void* handle) noexcept {
    // Void return: there is no channel, and the activation state it would
    // change does not exist. The refusal shows up at the next real
    // activation-context call, which fails with a status.
    (void)cookie;
    (void)handle;
}

extern "C" __attribute__((ms_abi)) void
nr1_RtlDeactivateActivationContextUnsafeFast(std::uint32_t unused,
                                             void* cookie) noexcept {
    (void)unused;
    (void)cookie;
}

extern "C" __attribute__((ms_abi)) std::int32_t
nr1_RtlDeactivateActivationContext(std::uint32_t unused,
                                   void* cookie) noexcept {
    (void)unused;
    (void)cookie;
    return refuse();
}

extern "C" __attribute__((ms_abi)) void nr1_RtlAddRefActivationContext(
    void* handle) noexcept {
    (void)handle;
    // The refcount belongs to an activation context this runtime never
    // created; there is nothing to add to.
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCreateActivationContext(
    void* return_handle, void* activation_context_data) noexcept {
    (void)return_handle;
    (void)activation_context_data;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t
nr1_RtlFindActivationContextSectionGuid(std::uint32_t flags,
                                        const void* section_guid,
                                        std::uint32_t section_index,
                                        void* buffer) noexcept {
    (void)flags;
    (void)section_guid;
    (void)section_index;
    (void)buffer;
    return refuse();
}

// ---- Object ACEs. The SID inside an OBJECT_TYPE ACE is stored in a
// compressed form whose exact encoding needs a reference this file did not
// have; a guess here would build ACEs the guest's access checks read wrong.
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddAccessAllowedObjectAce(
    void* acl, std::uint32_t revision, std::uint32_t flags,
    std::uint32_t mask, const void* object_type, const void* inherited_type,
    const void* sid) noexcept {
    (void)acl;
    (void)revision;
    (void)flags;
    (void)mask;
    (void)object_type;
    (void)inherited_type;
    (void)sid;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddAccessDeniedObjectAce(
    void* acl, std::uint32_t revision, std::uint32_t flags,
    std::uint32_t mask, const void* object_type, const void* inherited_type,
    const void* sid) noexcept {
    (void)acl;
    (void)revision;
    (void)flags;
    (void)mask;
    (void)object_type;
    (void)inherited_type;
    (void)sid;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAddAuditAccessObjectAce(
    void* acl, std::uint32_t revision, std::uint32_t flags,
    std::uint32_t mask, const void* object_type, const void* inherited_type,
    const void* sid, std::uint32_t success, std::uint32_t failure) noexcept {
    (void)acl;
    (void)revision;
    (void)flags;
    (void)mask;
    (void)object_type;
    (void)inherited_type;
    (void)sid;
    (void)success;
    (void)failure;
    return refuse();
}

// ---- Privileges: the token and privilege store is not this slice's.
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlAdjustPrivilege(
    std::uint32_t privilege, std::uint8_t enable, std::uint32_t current_thread,
    std::uint8_t* previous) noexcept {
    (void)privilege;
    (void)enable;
    (void)current_thread;
    (void)previous;
    return refuse();
}

// ---- RTL_HANDLE_TABLE: the handle table allocator and its entries.
extern "C" __attribute__((ms_abi)) void* nr1_RtlAllocateHandle(
    void* handle_table, std::uint32_t* index) noexcept {
    (void)handle_table;
    (void)index;
    return refuse_handle();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDestroyHandleTable(
    void* handle_table) noexcept {
    (void)handle_table;
    return refuse();
}

// ---- Compression: LZNT1 and the Xpress engines are real decompressors,
// not stubs to fake.
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCompressBuffer(
    std::uint16_t format, const void* source, std::uint32_t source_length,
    void* destination, std::uint32_t destination_length,
    std::uint32_t chunk_size, std::uint32_t* final_size,
    void* workspace) noexcept {
    (void)format;
    (void)source;
    (void)source_length;
    (void)destination;
    (void)destination_length;
    (void)chunk_size;
    (void)final_size;
    (void)workspace;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDecompressBuffer(
    std::uint16_t format, void* destination, std::uint32_t destination_length,
    const void* source, std::uint32_t source_length,
    std::uint32_t* final_size) noexcept {
    (void)format;
    (void)destination;
    (void)destination_length;
    (void)source;
    (void)source_length;
    (void)final_size;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDecompressFragment(
    std::uint16_t format, void* destination, std::uint32_t destination_length,
    const void* source, std::uint32_t source_length,
    std::uint32_t fragment_offset, std::uint32_t* final_size,
    void* workspace) noexcept {
    (void)format;
    (void)destination;
    (void)destination_length;
    (void)source;
    (void)source_length;
    (void)fragment_offset;
    (void)final_size;
    (void)workspace;
    return refuse();
}

// ---- Security descriptors this slice cannot build without the
// inheritance machinery or the named-pipe defaults.
extern "C" __attribute__((ms_abi)) std::int32_t
nr1_RtlConvertToAutoInheritSecurityObject(const void* parent_descriptor,
                                          const void* descriptor,
                                          void* new_descriptor, void* object_type,
                                          std::uint8_t is_directory,
                                          void** generic_mapping) noexcept {
    (void)parent_descriptor;
    (void)descriptor;
    (void)new_descriptor;
    (void)object_type;
    (void)is_directory;
    (void)generic_mapping;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCreateAndSetSD(
    void* object, void* security_quality_of_service,
    std::uint32_t owner_identifier, std::uint32_t group_identifier,
    void** new_descriptor) noexcept {
    (void)object;
    (void)security_quality_of_service;
    (void)owner_identifier;
    (void)group_identifier;
    (void)new_descriptor;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCreateUserSecurityObject(
    void* security_quality_of_service, std::uint32_t owner,
    std::uint32_t group, std::uint32_t access, void* acl,
    void** new_descriptor) noexcept {
    (void)security_quality_of_service;
    (void)owner;
    (void)group;
    (void)access;
    (void)acl;
    (void)new_descriptor;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDeleteSecurityObject(
    void** descriptor) noexcept {
    (void)descriptor;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDefaultNpAcl(
    std::uint32_t grant_access, void** acl) noexcept {
    (void)grant_access;
    (void)acl;
    return refuse();
}

// ---- Environments and process parameters: the RTL environment block and
// PEB parameter layouts, with their string tables.
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCreateEnvironment(
    std::uint32_t flags, void** environment) noexcept {
    (void)flags;
    (void)environment;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDestroyEnvironment(
    void* environment) noexcept {
    (void)environment;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCreateProcessParameters(
    void** process_parameters, const void* image_path_name,
    const void* dll_path, const void* current_directory, const void* command_line,
    void* title, void* desktop, void* shell_info, void* runtime_data,
    void* window_flags) noexcept {
    (void)process_parameters;
    (void)image_path_name;
    (void)dll_path;
    (void)current_directory;
    (void)command_line;
    (void)title;
    (void)desktop;
    (void)shell_info;
    (void)runtime_data;
    (void)window_flags;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCreateProcessParametersEx(
    void** process_parameters, const void* image_path_name,
    const void* dll_path, const void* current_directory, const void* command_line,
    void* title, void* desktop, void* shell_info, void* runtime_data,
    void* window_flags, std::uint32_t flags) noexcept {
    (void)process_parameters;
    (void)image_path_name;
    (void)dll_path;
    (void)current_directory;
    (void)command_line;
    (void)title;
    (void)desktop;
    (void)shell_info;
    (void)runtime_data;
    (void)window_flags;
    (void)flags;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDestroyProcessParameters(
    void* process_parameters) noexcept {
    (void)process_parameters;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDeNormalizeProcessParams(
    void* process_parameters) noexcept {
    (void)process_parameters;
    return refuse();
}

// ---- Property sets: the property storage subsystem.
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCreatePropertySet(
    void* property_set_context, void** property_set) noexcept {
    (void)property_set_context;
    (void)property_set;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlClosePropertySet(
    void* property_set) noexcept {
    (void)property_set;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlEnumerateProperties(
    void* property_set, std::uint32_t property_id, void* property_context,
    std::uint32_t* count, void* property_ids, void* property_values) noexcept {
    (void)property_set;
    (void)property_id;
    (void)property_context;
    (void)count;
    (void)property_ids;
    (void)property_values;
    return refuse();
}

// ---- Debug buffers: the query-debug-buffer shape carries an event pair
// and thread list this runtime does not model.
extern "C" __attribute__((ms_abi)) void* nr1_RtlCreateQueryDebugBuffer(
    std::uint32_t size, std::uint32_t event_pair) noexcept {
    (void)size;
    (void)event_pair;
    return refuse_handle();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDestroyQueryDebugBuffer(
    void* buffer) noexcept {
    (void)buffer;
    return refuse();
}

// ---- The RTL registry API (driver-side, query-table driven). The registry
// domain speaks the advapi32 shapes; this one is a different contract and
// forwarding the two together would guess at the query-table semantics.
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCheckRegistryKey(
    std::uint32_t relative_to, const char16_t* path) noexcept {
    (void)relative_to;
    (void)path;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCreateRegistryKey(
    std::uint32_t relative_to, const char16_t* path) noexcept {
    (void)relative_to;
    (void)path;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDeleteRegistryValue(
    std::uint32_t relative_to, const char16_t* path,
    const char16_t* value_name) noexcept {
    (void)relative_to;
    (void)path;
    (void)value_name;
    return refuse();
}

// ---- Service SIDs and capability SIDs are hashes of a name (SHA-1 and
// SHA-256 respectively). The hash algorithms are the whole answer and are
// not implemented here; a wrong subauthority is a SID that grants nothing
// or everything, which is worse than a refusal.
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCreateServiceSid(
    const void* service_name, std::uint32_t service_name_length,
    void* service_sid, std::uint32_t* service_sid_length) noexcept {
    (void)service_name;
    (void)service_name_length;
    (void)service_sid;
    (void)service_sid_length;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t
nr1_RtlDeriveCapabilitySidsFromName(const char16_t* name,
                                    void* package_sid,
                                    void* capability_sid) noexcept {
    (void)name;
    (void)package_sid;
    (void)capability_sid;
    return refuse();
}

// ---- Tag heaps: the tag name table and its per-tag accounting.
extern "C" __attribute__((ms_abi)) void* nr1_RtlCreateTagHeap(
    void* heap, std::uint32_t flags, const char16_t* tag_prefix,
    const char16_t* tag_names) noexcept {
    (void)heap;
    (void)flags;
    (void)tag_prefix;
    (void)tag_names;
    return refuse_handle();
}

// ---- Timer queues and waits: the thread pool they run on does not exist
// in this runtime, and a timer that never fires is a hung guest, not a
// stub.
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCreateTimer(
    void* timer_queue, void** timer, void* callback, void* parameter,
    std::uint64_t due_time, std::uint32_t period, std::uint32_t flags) noexcept {
    (void)timer_queue;
    (void)timer;
    (void)callback;
    (void)parameter;
    (void)due_time;
    (void)period;
    (void)flags;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCreateTimerQueue() noexcept {
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDeleteTimer(
    void* timer_queue, void* timer, void* completion_event) noexcept {
    (void)timer_queue;
    (void)timer;
    (void)completion_event;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDeleteTimerQueueEx(
    void* timer_queue, void* completion_event) noexcept {
    (void)timer_queue;
    (void)completion_event;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDeregisterWait(
    void* wait_handle) noexcept {
    (void)wait_handle;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDeregisterWaitEx(
    void* wait_handle, void* completion_event) noexcept {
    (void)wait_handle;
    (void)completion_event;
    return refuse();
}

// ---- Generic tables: the splay-tree and AVL entry points are one
// subsystem, and a table the caller cannot insert into is not worth
// half-serving; the insert calls are outside this slice.
extern "C" __attribute__((ms_abi)) void nr1_RtlDelete(void* table,
                                                      void* element) noexcept {
    (void)table;
    (void)element;
}

extern "C" __attribute__((ms_abi)) void nr1_RtlDeleteNoSplay(
    void* element, void* table) noexcept {
    (void)element;
    (void)table;
}

extern "C" __attribute__((ms_abi)) void* nr1_RtlDeleteElementGenericTable(
    void* table, void* element) noexcept {
    (void)table;
    (void)element;
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void* nr1_RtlDeleteElementGenericTableAvl(
    void* table, void* element) noexcept {
    (void)table;
    (void)element;
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void* nr1_RtlEnumerateGenericTable(
    void* table, std::uint32_t restart) noexcept {
    (void)table;
    (void)restart;
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void*
nr1_RtlEnumerateGenericTableWithoutSplaying(void* table,
                                            std::uint32_t* restart) noexcept {
    (void)table;
    (void)restart;
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void*
nr1_RtlEnumerateGenericTableWithoutSplayingAvl(
    void* table, std::uint32_t* restart) noexcept {
    (void)table;
    (void)restart;
    return nullptr;
}

// ---- VM range lists.
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDeleteRange(
    void* range_list, std::uint64_t start, std::uint64_t end) noexcept {
    (void)range_list;
    (void)start;
    (void)end;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlDeleteOwnersRanges(
    void* range_list, void* owner) noexcept {
    (void)range_list;
    (void)owner;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlFindRange(
    const void* range_list, std::uint64_t low, std::uint64_t high,
    std::uint32_t length, std::uint32_t alignment, std::uint32_t flags,
    void* owner, const void* exclude_list, std::uint64_t* found) noexcept {
    (void)range_list;
    (void)low;
    (void)high;
    (void)length;
    (void)alignment;
    (void)flags;
    (void)owner;
    (void)exclude_list;
    (void)found;
    return refuse();
}

// ---- Timezone cutover rules: the transition-date arithmetic the Windows
// timezone model uses, which the docs describe loosely enough that a guess
// would be off by an hour twice a year.
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCutoverTimeToSystemTime(
    const void* cutover_time, void* system_time, std::uint32_t year,
    std::uint32_t this_year_in_cutover_month) noexcept {
    (void)cutover_time;
    (void)system_time;
    (void)year;
    (void)this_year_in_cutover_month;
    return refuse();
}

// ---- Message tables: an MC-format parse of a PE resource section.
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlFindMessage(
    const void* base, std::uint32_t type, std::uint32_t language,
    std::uint32_t message_id, void** message_entry) noexcept {
    (void)base;
    (void)type;
    (void)language;
    (void)message_id;
    (void)message_entry;
    return refuse();
}

// ---- Path search: the extension-candidate order and the return length
// semantics need a reference this file did not have; a search that checks
// the wrong candidate order finds the wrong file first.
extern "C" __attribute__((ms_abi)) std::uint32_t nr1_RtlDosSearchPath_U(
    const char16_t* path, const char16_t* file, const char16_t* extension,
    char16_t* result) noexcept {
    (void)path;
    (void)file;
    (void)extension;
    (void)result;
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

// ---- Relative NT names: the answer is coupled to the current directory's
// NT handle, and this slice has no truthful containing-directory to report.
extern "C" __attribute__((ms_abi)) std::uint32_t
nr1_RtlDosPathNameToRelativeNtPathName_U(const char16_t* dos, void* nt_name,
                                         std::uint32_t* file_part,
                                         void* relative_name) noexcept {
    (void)dos;
    (void)nt_name;
    (void)file_part;
    (void)relative_name;
    return refuse_boolean();
}

extern "C" __attribute__((ms_abi)) std::int32_t
nr1_RtlDosPathNameToRelativeNtPathName_U_WithStatus(
    const char16_t* dos, void* nt_name, std::uint32_t* file_part,
    void* relative_name) noexcept {
    (void)dos;
    (void)nt_name;
    (void)file_part;
    (void)relative_name;
    return refuse();
}

// ---- The magic-divisor divide: the magic-shift convention needs the
// reference; the sign handling around it is where a guess would be wrong
// for exactly half of the inputs.
extern "C" __attribute__((ms_abi)) std::uint64_t nr1_RtlExtendedMagicDivide(
    std::uint64_t value, std::uint64_t magic_divisor,
    std::int32_t shift) noexcept {
    (void)value;
    (void)magic_divisor;
    (void)shift;
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

// ---- Process and thread creation: a second process or thread needs the
// scheduler this runtime does not carry, and a user stack must come from a
// reservation the memory layer owns, not a number this file invents.
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCreateUserProcess(
    const void* image_file_name, std::uint32_t attributes,
    void* process_parameters, void* debug_port, void* exception_port,
    void* section_handle, void* process_handle_out, void* thread_handle_out,
    void* client_id, void* environment) noexcept {
    (void)image_file_name;
    (void)attributes;
    (void)process_parameters;
    (void)debug_port;
    (void)exception_port;
    (void)section_handle;
    (void)process_handle_out;
    (void)thread_handle_out;
    (void)client_id;
    (void)environment;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCreateUserStack(
    std::uint64_t commit, std::uint64_t reserve, std::uint32_t zero_bits,
    std::uint32_t page_size, std::uint32_t reservation_granularity,
    void* initial_teb) noexcept {
    (void)commit;
    (void)reserve;
    (void)zero_bits;
    (void)page_size;
    (void)reservation_granularity;
    (void)initial_teb;
    return refuse();
}

extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlCreateUserThread(
    void* process, void* thread_security_descriptor,
    std::uint8_t create_suspended, std::uint32_t zero_bits,
    std::uint64_t maximum_stack_size, std::uint64_t initial_stack_size,
    void* start_routine, void* start_parameter, void* thread_handle,
    void* client_id) noexcept {
    (void)process;
    (void)thread_security_descriptor;
    (void)create_suspended;
    (void)zero_bits;
    (void)maximum_stack_size;
    (void)initial_stack_size;
    (void)start_routine;
    (void)start_parameter;
    (void)thread_handle;
    (void)client_id;
    return refuse();
}

// ---- Checked-build timing dump; no debug channel here.
extern "C" __attribute__((ms_abi)) void nr1_RtlDebugPrintTimes() noexcept {
    // The free build's answer is silence.
}

// ---- UI-list conversion: a format with no documented consumer contract.
extern "C" __attribute__((ms_abi)) std::int32_t nr1_RtlConvertUiListToApiList(
    const void* ui_list, void** api_list) noexcept {
    (void)ui_list;
    (void)api_list;
    return refuse();
}

}  // namespace

// ===========================================================================
// Registration
// ===========================================================================

void add_ntdll_rtl_mem1(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    // Real implementations.
    e("RtlAbsoluteToSelfRelativeSD",
      reinterpret_cast<void*>(&nr1_RtlAbsoluteToSelfRelativeSD));
    e("RtlAcquirePebLock", reinterpret_cast<void*>(&nr1_RtlAcquirePebLock));
    e("RtlAcquireResourceExclusive",
      reinterpret_cast<void*>(&nr1_RtlAcquireResourceExclusive));
    e("RtlAcquireResourceShared",
      reinterpret_cast<void*>(&nr1_RtlAcquireResourceShared));
    e("RtlAcquireSRWLockExclusive",
      reinterpret_cast<void*>(&nr1_RtlAcquireSRWLockExclusive));
    e("RtlAcquireSRWLockShared",
      reinterpret_cast<void*>(&nr1_RtlAcquireSRWLockShared));
    e("RtlAddAccessAllowedAce",
      reinterpret_cast<void*>(&nr1_RtlAddAccessAllowedAce));
    e("RtlAddAccessAllowedAceEx",
      reinterpret_cast<void*>(&nr1_RtlAddAccessAllowedAceEx));
    e("RtlAddAccessDeniedAce",
      reinterpret_cast<void*>(&nr1_RtlAddAccessDeniedAce));
    e("RtlAddAccessDeniedAceEx",
      reinterpret_cast<void*>(&nr1_RtlAddAccessDeniedAceEx));
    e("RtlAddAce", reinterpret_cast<void*>(&nr1_RtlAddAce));
    e("RtlAddAtomToAtomTable",
      reinterpret_cast<void*>(&nr1_RtlAddAtomToAtomTable));
    e("RtlAddAuditAccessAce",
      reinterpret_cast<void*>(&nr1_RtlAddAuditAccessAce));
    e("RtlAddAuditAccessAceEx",
      reinterpret_cast<void*>(&nr1_RtlAddAuditAccessAceEx));
    e("RtlAddMandatoryAce", reinterpret_cast<void*>(&nr1_RtlAddMandatoryAce));
    e("RtlAddProcessTrustLabelAce",
      reinterpret_cast<void*>(&nr1_RtlAddProcessTrustLabelAce));
    e("RtlAddVectoredContinueHandler",
      reinterpret_cast<void*>(&nr1_RtlAddVectoredContinueHandler));
    e("RtlAddVectoredExceptionHandler",
      reinterpret_cast<void*>(&nr1_RtlAddVectoredExceptionHandler));
    e("RtlAddressInSectionTable",
      reinterpret_cast<void*>(&nr1_RtlAddressInSectionTable));
    e("RtlAllocateAndInitializeSid",
      reinterpret_cast<void*>(&nr1_RtlAllocateAndInitializeSid));
    e("RtlAllocateHeap", reinterpret_cast<void*>(&nr1_RtlAllocateHeap));
    e("RtlAreAllAccessesGranted",
      reinterpret_cast<void*>(&nr1_RtlAreAllAccessesGranted));
    e("RtlAreAnyAccessesGranted",
      reinterpret_cast<void*>(&nr1_RtlAreAnyAccessesGranted));
    e("RtlAreBitsClear", reinterpret_cast<void*>(&nr1_RtlAreBitsClear));
    e("RtlAreBitsSet", reinterpret_cast<void*>(&nr1_RtlAreBitsSet));
    e("RtlAssert", reinterpret_cast<void*>(&nr1_RtlAssert));
    e("RtlBarrier", reinterpret_cast<void*>(&nr1_RtlBarrier));
    e("RtlCaptureStackBackTrace",
      reinterpret_cast<void*>(&nr1_RtlCaptureStackBackTrace));
    e("RtlClearAllBits", reinterpret_cast<void*>(&nr1_RtlClearAllBits));
    e("RtlClearBits", reinterpret_cast<void*>(&nr1_RtlClearBits));
    e("RtlCompactHeap", reinterpret_cast<void*>(&nr1_RtlCompactHeap));
    e("RtlComputeCrc32", reinterpret_cast<void*>(&nr1_RtlComputeCrc32));
    e("RtlConvertExclusiveToShared",
      reinterpret_cast<void*>(&nr1_RtlConvertExclusiveToShared));
    e("RtlConvertLongToLargeInteger",
      reinterpret_cast<void*>(&nr1_RtlConvertLongToLargeInteger));
    e("RtlConvertSharedToExclusive",
      reinterpret_cast<void*>(&nr1_RtlConvertSharedToExclusive));
    e("RtlConvertUlongToLargeInteger",
      reinterpret_cast<void*>(&nr1_RtlConvertUlongToLargeInteger));
    e("RtlCreateAcl", reinterpret_cast<void*>(&nr1_RtlCreateAcl));
    e("RtlCreateAtomTable", reinterpret_cast<void*>(&nr1_RtlCreateAtomTable));
    e("RtlCreateHeap", reinterpret_cast<void*>(&nr1_RtlCreateHeap));
    e("RtlCreateSecurityDescriptor",
      reinterpret_cast<void*>(&nr1_RtlCreateSecurityDescriptor));
    e("RtlDecodePointer", reinterpret_cast<void*>(&nr1_RtlDecodePointer));
    e("RtlDecodeSystemPointer",
      reinterpret_cast<void*>(&nr1_RtlDecodeSystemPointer));
    e("RtlDeleteAce", reinterpret_cast<void*>(&nr1_RtlDeleteAce));
    e("RtlDeleteAtomFromAtomTable",
      reinterpret_cast<void*>(&nr1_RtlDeleteAtomFromAtomTable));
    e("RtlDeleteBarrier", reinterpret_cast<void*>(&nr1_RtlDeleteBarrier));
    e("RtlDeleteCriticalSection",
      reinterpret_cast<void*>(&nr1_RtlDeleteCriticalSection));
    e("RtlDeleteResource", reinterpret_cast<void*>(&nr1_RtlDeleteResource));
    e("RtlDestroyAtomTable",
      reinterpret_cast<void*>(&nr1_RtlDestroyAtomTable));
    e("RtlDestroyHeap", reinterpret_cast<void*>(&nr1_RtlDestroyHeap));
    e("RtlDetermineDosPathNameType_U",
      reinterpret_cast<void*>(&nr1_RtlDetermineDosPathNameType_U));
    e("RtlDllShutdownInProgress",
      reinterpret_cast<void*>(&nr1_RtlDllShutdownInProgress));
    e("RtlDoesFileExists_U",
      reinterpret_cast<void*>(&nr1_RtlDoesFileExists_U));
    e("RtlDosPathNameToNtPathName_U",
      reinterpret_cast<void*>(&nr1_RtlDosPathNameToNtPathName_U));
    e("RtlDosPathNameToNtPathName_U_WithStatus",
      reinterpret_cast<void*>(&nr1_RtlDosPathNameToNtPathName_U_WithStatus));
    e("RtlDumpResource", reinterpret_cast<void*>(&nr1_RtlDumpResource));
    e("RtlEmptyAtomTable", reinterpret_cast<void*>(&nr1_RtlEmptyAtomTable));
    e("RtlEncodePointer", reinterpret_cast<void*>(&nr1_RtlEncodePointer));
    e("RtlEncodeSystemPointer",
      reinterpret_cast<void*>(&nr1_RtlEncodeSystemPointer));
    e("RtlEnlargedIntegerMultiply",
      reinterpret_cast<void*>(&nr1_RtlEnlargedIntegerMultiply));
    e("RtlEnlargedUnsignedDivide",
      reinterpret_cast<void*>(&nr1_RtlEnlargedUnsignedDivide));
    e("RtlEnlargedUnsignedMultiply",
      reinterpret_cast<void*>(&nr1_RtlEnlargedUnsignedMultiply));
    e("RtlEnterCriticalSection",
      reinterpret_cast<void*>(&nr1_RtlEnterCriticalSection));
    e("RtlEnumProcessHeaps",
      reinterpret_cast<void*>(&nr1_RtlEnumProcessHeaps));
    e("RtlEqualComputerName",
      reinterpret_cast<void*>(&nr1_RtlEqualComputerName));
    e("RtlEqualDomainName", reinterpret_cast<void*>(&nr1_RtlEqualDomainName));
    e("RtlEqualLuid", reinterpret_cast<void*>(&nr1_RtlEqualLuid));
    e("RtlEqualPrefixSid", reinterpret_cast<void*>(&nr1_RtlEqualPrefixSid));
    e("RtlEqualSid", reinterpret_cast<void*>(&nr1_RtlEqualSid));
    e("RtlExitUserProcess", reinterpret_cast<void*>(&nr1_RtlExitUserProcess));
    e("RtlExitUserThread", reinterpret_cast<void*>(&nr1_RtlExitUserThread));
    e("RtlExtendHeap", reinterpret_cast<void*>(&nr1_RtlExtendHeap));
    e("RtlExtendedIntegerMultiply",
      reinterpret_cast<void*>(&nr1_RtlExtendedIntegerMultiply));
    e("RtlExtendedLargeIntegerDivide",
      reinterpret_cast<void*>(&nr1_RtlExtendedLargeIntegerDivide));
    e("RtlFindClearBits", reinterpret_cast<void*>(&nr1_RtlFindClearBits));
    e("RtlFindClearBitsAndSet",
      reinterpret_cast<void*>(&nr1_RtlFindClearBitsAndSet));
    e("RtlFindClearRuns", reinterpret_cast<void*>(&nr1_RtlFindClearRuns));
    e("RtlFindExportedRoutineByName",
      reinterpret_cast<void*>(&nr1_RtlFindExportedRoutineByName));
    e("RtlFindLastBackwardRunClear",
      reinterpret_cast<void*>(&nr1_RtlFindLastBackwardRunClear));
    e("RtlFindLastBackwardRunSet",
      reinterpret_cast<void*>(&nr1_RtlFindLastBackwardRunSet));
    e("RtlFindLeastSignificantBit",
      reinterpret_cast<void*>(&nr1_RtlFindLeastSignificantBit));
    e("RtlFindLongestRunClear",
      reinterpret_cast<void*>(&nr1_RtlFindLongestRunClear));
    e("RtlFindLongestRunSet",
      reinterpret_cast<void*>(&nr1_RtlFindLongestRunSet));
    e("RtlFindMostSignificantBit",
      reinterpret_cast<void*>(&nr1_RtlFindMostSignificantBit));
    e("RtlFindNextForwardRunClear",
      reinterpret_cast<void*>(&nr1_RtlFindNextForwardRunClear));
    e("RtlFindNextForwardRunSet",
      reinterpret_cast<void*>(&nr1_RtlFindNextForwardRunSet));
    // Refusals.
    e("RtlAbortRXact", reinterpret_cast<void*>(&nr1_RtlAbortRXact));
    e("RtlActivateActivationContext",
      reinterpret_cast<void*>(&nr1_RtlActivateActivationContext));
    e("RtlActivateActivationContextEx",
      reinterpret_cast<void*>(&nr1_RtlActivateActivationContextEx));
    e("RtlActivateActivationContextUnsafeFast",
      reinterpret_cast<void*>(&nr1_RtlActivateActivationContextUnsafeFast));
    e("RtlAddAccessAllowedObjectAce",
      reinterpret_cast<void*>(&nr1_RtlAddAccessAllowedObjectAce));
    e("RtlAddAccessDeniedObjectAce",
      reinterpret_cast<void*>(&nr1_RtlAddAccessDeniedObjectAce));
    e("RtlAddActionToRXact", reinterpret_cast<void*>(&nr1_RtlAddActionToRXact));
    e("RtlAddAttributeActionToRXact",
      reinterpret_cast<void*>(&nr1_RtlAddAttributeActionToRXact));
    e("RtlAddAuditAccessObjectAce",
      reinterpret_cast<void*>(&nr1_RtlAddAuditAccessObjectAce));
    e("RtlAddRefActivationContext",
      reinterpret_cast<void*>(&nr1_RtlAddRefActivationContext));
    e("RtlAdjustPrivilege", reinterpret_cast<void*>(&nr1_RtlAdjustPrivilege));
    e("RtlAllocateHandle", reinterpret_cast<void*>(&nr1_RtlAllocateHandle));
    e("RtlApplyRXact", reinterpret_cast<void*>(&nr1_RtlApplyRXact));
    e("RtlApplyRXactNoFlush",
      reinterpret_cast<void*>(&nr1_RtlApplyRXactNoFlush));
    e("RtlCheckRegistryKey",
      reinterpret_cast<void*>(&nr1_RtlCheckRegistryKey));
    e("RtlClosePropertySet",
      reinterpret_cast<void*>(&nr1_RtlClosePropertySet));
    e("RtlCompressBuffer", reinterpret_cast<void*>(&nr1_RtlCompressBuffer));
    e("RtlConvertToAutoInheritSecurityObject",
      reinterpret_cast<void*>(&nr1_RtlConvertToAutoInheritSecurityObject));
    e("RtlConvertUiListToApiList",
      reinterpret_cast<void*>(&nr1_RtlConvertUiListToApiList));
    e("RtlCreateActivationContext",
      reinterpret_cast<void*>(&nr1_RtlCreateActivationContext));
    e("RtlCreateAndSetSD", reinterpret_cast<void*>(&nr1_RtlCreateAndSetSD));
    e("RtlCreateEnvironment",
      reinterpret_cast<void*>(&nr1_RtlCreateEnvironment));
    e("RtlCreateProcessParameters",
      reinterpret_cast<void*>(&nr1_RtlCreateProcessParameters));
    e("RtlCreateProcessParametersEx",
      reinterpret_cast<void*>(&nr1_RtlCreateProcessParametersEx));
    e("RtlCreatePropertySet",
      reinterpret_cast<void*>(&nr1_RtlCreatePropertySet));
    e("RtlCreateQueryDebugBuffer",
      reinterpret_cast<void*>(&nr1_RtlCreateQueryDebugBuffer));
    e("RtlCreateRegistryKey",
      reinterpret_cast<void*>(&nr1_RtlCreateRegistryKey));
    e("RtlCreateServiceSid",
      reinterpret_cast<void*>(&nr1_RtlCreateServiceSid));
    e("RtlCreateTagHeap", reinterpret_cast<void*>(&nr1_RtlCreateTagHeap));
    e("RtlCreateTimer", reinterpret_cast<void*>(&nr1_RtlCreateTimer));
    e("RtlCreateTimerQueue", reinterpret_cast<void*>(&nr1_RtlCreateTimerQueue));
    e("RtlCreateUserProcess",
      reinterpret_cast<void*>(&nr1_RtlCreateUserProcess));
    e("RtlCreateUserSecurityObject",
      reinterpret_cast<void*>(&nr1_RtlCreateUserSecurityObject));
    e("RtlCreateUserStack", reinterpret_cast<void*>(&nr1_RtlCreateUserStack));
    e("RtlCreateUserThread", reinterpret_cast<void*>(&nr1_RtlCreateUserThread));
    e("RtlCutoverTimeToSystemTime",
      reinterpret_cast<void*>(&nr1_RtlCutoverTimeToSystemTime));
    e("RtlDeNormalizeProcessParams",
      reinterpret_cast<void*>(&nr1_RtlDeNormalizeProcessParams));
    e("RtlDeactivateActivationContext",
      reinterpret_cast<void*>(&nr1_RtlDeactivateActivationContext));
    e("RtlDeactivateActivationContextUnsafeFast",
      reinterpret_cast<void*>(&nr1_RtlDeactivateActivationContextUnsafeFast));
    e("RtlDebugPrintTimes",
      reinterpret_cast<void*>(&nr1_RtlDebugPrintTimes));
    e("RtlDecompressBuffer",
      reinterpret_cast<void*>(&nr1_RtlDecompressBuffer));
    e("RtlDecompressFragment",
      reinterpret_cast<void*>(&nr1_RtlDecompressFragment));
    e("RtlDefaultNpAcl", reinterpret_cast<void*>(&nr1_RtlDefaultNpAcl));
    e("RtlDelete", reinterpret_cast<void*>(&nr1_RtlDelete));
    e("RtlDeleteElementGenericTable",
      reinterpret_cast<void*>(&nr1_RtlDeleteElementGenericTable));
    e("RtlDeleteElementGenericTableAvl",
      reinterpret_cast<void*>(&nr1_RtlDeleteElementGenericTableAvl));
    e("RtlDeleteNoSplay", reinterpret_cast<void*>(&nr1_RtlDeleteNoSplay));
    e("RtlDeleteOwnersRanges",
      reinterpret_cast<void*>(&nr1_RtlDeleteOwnersRanges));
    e("RtlDeleteRange", reinterpret_cast<void*>(&nr1_RtlDeleteRange));
    e("RtlDeleteRegistryValue",
      reinterpret_cast<void*>(&nr1_RtlDeleteRegistryValue));
    e("RtlDeleteSecurityObject",
      reinterpret_cast<void*>(&nr1_RtlDeleteSecurityObject));
    e("RtlDeleteTimer", reinterpret_cast<void*>(&nr1_RtlDeleteTimer));
    e("RtlDeleteTimerQueueEx",
      reinterpret_cast<void*>(&nr1_RtlDeleteTimerQueueEx));
    e("RtlDeregisterWait", reinterpret_cast<void*>(&nr1_RtlDeregisterWait));
    e("RtlDeregisterWaitEx",
      reinterpret_cast<void*>(&nr1_RtlDeregisterWaitEx));
    e("RtlDeriveCapabilitySidsFromName",
      reinterpret_cast<void*>(&nr1_RtlDeriveCapabilitySidsFromName));
    e("RtlDestroyEnvironment",
      reinterpret_cast<void*>(&nr1_RtlDestroyEnvironment));
    e("RtlDestroyHandleTable",
      reinterpret_cast<void*>(&nr1_RtlDestroyHandleTable));
    e("RtlDestroyProcessParameters",
      reinterpret_cast<void*>(&nr1_RtlDestroyProcessParameters));
    e("RtlDestroyQueryDebugBuffer",
      reinterpret_cast<void*>(&nr1_RtlDestroyQueryDebugBuffer));
    e("RtlDosPathNameToRelativeNtPathName_U",
      reinterpret_cast<void*>(&nr1_RtlDosPathNameToRelativeNtPathName_U));
    e("RtlDosPathNameToRelativeNtPathName_U_WithStatus",
      reinterpret_cast<void*>(
          &nr1_RtlDosPathNameToRelativeNtPathName_U_WithStatus));
    e("RtlDosSearchPath_U", reinterpret_cast<void*>(&nr1_RtlDosSearchPath_U));
    e("RtlEnumerateGenericTable",
      reinterpret_cast<void*>(&nr1_RtlEnumerateGenericTable));
    e("RtlEnumerateGenericTableWithoutSplaying",
      reinterpret_cast<void*>(&nr1_RtlEnumerateGenericTableWithoutSplaying));
    e("RtlEnumerateGenericTableWithoutSplayingAvl",
      reinterpret_cast<void*>(&nr1_RtlEnumerateGenericTableWithoutSplayingAvl));
    e("RtlEnumerateProperties",
      reinterpret_cast<void*>(&nr1_RtlEnumerateProperties));
    e("RtlExtendedMagicDivide",
      reinterpret_cast<void*>(&nr1_RtlExtendedMagicDivide));
    e("RtlFindActivationContextSectionGuid",
      reinterpret_cast<void*>(&nr1_RtlFindActivationContextSectionGuid));
    e("RtlFindMessage", reinterpret_cast<void*>(&nr1_RtlFindMessage));
    e("RtlFindRange", reinterpret_cast<void*>(&nr1_RtlFindRange));
}

}  // namespace occ::runtime::winabi

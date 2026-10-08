// The memory family, as kernel32 spells it.
//
// A guest's address space and this runtime's are the same address space --
// the PE runs in this process rather than beside it -- so every function here
// is a thin reading or a thin rewrite of something the host already has.
// That is worth stating because it is the whole shape of the file: there is
// no bookkeeping layer here pretending to be an allocator, and a
// `VirtualAlloc` is a mapping the host makes.
//
// The three older families that all mean the same thing now are all here.
// `GlobalAlloc` and `LocalAlloc` are the 16-bit segment allocators and have
// been aliases of the process heap since Windows 2000; `HeapAlloc` is the
// same heap named directly. A runtime that gave them three separate arenas
// would let a program free a `GlobalAlloc` block with `HeapFree` and get an
// answer that depends on which one it happened to use first, where Windows
// answers the same either way.
//
// Two things are refused rather than approximated, and both are refusals a
// caller already has a path for:
//
//   * `VirtualAllocEx` and `VirtualProtectEx` on a process other than this
//     one. This runtime runs one process, so a handle for another one does
//     not exist; reading or writing a stranger's memory is not something to
//     answer with a plausible value.
//   * A `PROT_NONE`-style request with an execution flag on a host whose
//     W^X policy refuses it. The host says no and the error is passed on
//     rather than the protection being rounded to something that works.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>

#include <sys/mman.h>
#include <unistd.h>

namespace occ::runtime::winabi {
namespace {

// --------------------------------------------------------------- constants

// MEMORY_BASIC_INFORMATION, as byte offsets. The guest's structure is 48
// bytes on the 64-bit ABI: two pointers, a protection word, the region size,
// and three more words -- and the padding between them is Windows' rather
// than this host's, which is why the writer below lays it out by hand.
constexpr std::size_t kMbiBase = 0;
constexpr std::size_t kMbiAllocationBase = 8;
constexpr std::size_t kMbiAllocationProtect = 16;
constexpr std::size_t kMbiRegionSize = 24;
constexpr std::size_t kMbiState = 32;
constexpr std::size_t kMbiProtect = 36;
constexpr std::size_t kMbiType = 40;
constexpr std::size_t kMbiBytes = 48;

constexpr std::uint32_t kMemCommit = 0x00001000;
constexpr std::uint32_t kMemReserve = 0x00002000;
constexpr std::uint32_t kMemRelease = 0x00008000;
constexpr std::uint32_t kMemPrivate = 0x00020000;

constexpr std::uint32_t kPageNoAccess = 0x01;
constexpr std::uint32_t kPageReadOnly = 0x02;
constexpr std::uint32_t kPageReadWrite = 0x04;
constexpr std::uint32_t kPageWriteCopy = 0x08;
constexpr std::uint32_t kPageExecute = 0x10;
constexpr std::uint32_t kPageExecuteRead = 0x20;
constexpr std::uint32_t kPageExecuteReadWrite = 0x40;
constexpr std::uint32_t kPageExecuteWriteCopy = 0x80;
constexpr std::uint32_t kPageModifiers = 0x0FF;

constexpr std::uint32_t kHeapZeroMemory = 0x00000008;

constexpr std::uint32_t kErrorInvalidHandle = 6;
constexpr std::uint32_t kErrorInvalidParameter = 87;
constexpr std::uint32_t kErrorNotEnoughMemory = 8;
constexpr std::uint32_t kErrorInvalidAddress = 487;

// The state a handle names: this process, or nothing. A pseudo-handle is the
// constant Windows hands out for "the current process"; anything else is not
// a process this runtime can name.
constexpr std::uint64_t kCurrentProcessHandle = 0xFFFFFFFFFFFFFFFFULL;

// ------------------------------------------------------------- the writes

void put_u32(std::uint8_t* base, std::size_t at, std::uint32_t value) noexcept {
    std::memcpy(base + at, &value, sizeof(value));
}

void put_u64(std::uint8_t* base, std::size_t at, std::uint64_t value) noexcept {
    std::memcpy(base + at, &value, sizeof(value));
}

// The host's protection bits a Windows protection word means.
//
// The mapping is not one-to-one in either direction: Windows has separate
// read, read-write, execute and execute-read-write bits and the host takes a
// single numeric level, so the translation has to lose the distinction
// between "write" and "write-copy" -- which is a distinction Windows keeps
// for a memory-mapped file and the host expresses through the mapping rather
// than the protection.
[[nodiscard]] int host_protection(std::uint32_t protect) noexcept {
    const std::uint32_t base = protect & kPageModifiers;
    switch (base) {
    case kPageNoAccess:
        return PROT_NONE;
    case kPageReadOnly:
    case kPageExecute:
    case kPageExecuteRead:
        return PROT_READ;
    case kPageWriteCopy:
    case kPageReadWrite:
    case kPageExecuteWriteCopy:
    case kPageExecuteReadWrite:
        return PROT_READ | PROT_WRITE;
    default:
        return PROT_READ | PROT_WRITE;
    }
}

// The execution bit, which the host carries inside its policy rather than in
// the level: a mapping the guest asked to execute has to be one the host is
// willing to mark executable.
[[nodiscard]] bool wants_execute(std::uint32_t protect) noexcept {
    const std::uint32_t base = protect & kPageModifiers;
    return base == kPageExecute || base == kPageExecuteRead ||
           base == kPageExecuteReadWrite || base == kPageExecuteWriteCopy;
}

// Whether a handle names this process. `ReadProcessMemory` on any other
// process is refused rather than answered from this one's memory, which would
// be a program reading the wrong bytes and finding plausible ones.
[[nodiscard]] bool names_this_process(std::uint64_t handle) noexcept {
    return handle == kCurrentProcessHandle || handle == 0xFFFFFFFFFFFFFFFFULL;
}

// One page is the granularity of every reservation, as it is on Windows and
// as it is on the host; the sizes below are the values Windows documents
// when it is asked.
[[nodiscard]] std::uint64_t page_size() noexcept {
    const long size = ::sysconf(_SC_PAGESIZE);
    return size > 0 ? static_cast<std::uint64_t>(size) : 4096ULL;
}

[[nodiscard]] std::uint64_t round_to_page(std::uint64_t bytes) noexcept {
    const std::uint64_t page = page_size();
    if (bytes == 0) {
        return page;
    }
    const std::uint64_t extra = bytes % page;
    if (extra == 0) {
        return bytes;
    }
    // The addition cannot wrap: `bytes` is bounded by what the host will
    // map, and the check below catches the case where it is not.
    if (bytes > UINT64_MAX - (page - extra)) {
        return 0;
    }
    return bytes + (page - extra);
}

}  // namespace

// ---------------------------------------------------------------------------
// VirtualAlloc and friends
// ---------------------------------------------------------------------------
//
// A reservation is a host mapping and a commit is the same mapping with its
// protection set, which is a difference from Windows worth naming: Windows
// commits pages out of a reservation and the host has no such step, so a
// commit here is a protection change on a region that was already mapped.
// What a caller observes is the same -- reserved memory is unreadable until
// it is committed -- because the reservation is made PROT_NONE.

template <typename T>
[[nodiscard]] T* virtual_alloc(T* address, std::uint64_t size,
                               std::uint32_t type,
                               std::uint32_t protect) noexcept {
    if (size == 0) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    const bool reserve = (type & kMemReserve) != 0;
    const bool commit = (type & kMemCommit) != 0;
    if (!reserve && !commit) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    const std::uint64_t rounded = round_to_page(size);
    if (rounded == 0) {
        set_last_error(kErrorNotEnoughMemory);
        return nullptr;
    }
    int host = PROT_NONE;
    if (commit) {
        if (!wants_execute(protect) &&
            (protect & kPageModifiers) == kPageNoAccess) {
            host = PROT_NONE;
        } else {
            host = host_protection(protect);
        }
    }
    // MAP_FIXED when the caller named an address, because the caller is
    // asking for that address and a host that placed it elsewhere would be
    // answering a different question. A caller that passed null gets
    // whatever the host chooses, which is what Windows does too.
    const int flags = MAP_PRIVATE | MAP_ANONYMOUS |
                      (address != nullptr ? MAP_FIXED : 0);
    void* mapped = ::mmap(address, static_cast<std::size_t>(rounded), host,
                          flags, -1, 0);
    if (mapped == MAP_FAILED) {
        set_last_error(errno == ENOMEM ? kErrorNotEnoughMemory
                                       : kErrorInvalidParameter);
        return nullptr;
    }
    set_last_error(0);
    return static_cast<T*>(mapped);
}

template <typename T>
[[nodiscard]] std::int32_t virtual_free(T* address, std::uint64_t size,
                                        std::uint32_t type) noexcept {
    if (address == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const bool release = (type & kMemRelease) != 0;
    const bool decommit = (type & kMemCommit) != 0;
    if (!release && !decommit) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (decommit && !release) {
        // A decommit without a release drops the pages back to reserved,
        // which the host spells as a protection change rather than an
        // unmap: the address stays the guest's, the contents do not.
        const std::uint64_t rounded = round_to_page(size);
        if (rounded == 0 ||
            ::mprotect(address, static_cast<std::size_t>(rounded),
                       PROT_NONE) != 0) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        set_last_error(0);
        return 1;
    }
    if (size != 0) {
        if (::munmap(address, static_cast<std::size_t>(round_to_page(size))) !=
            0) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
    } else if (::munmap(address, static_cast<std::size_t>(page_size())) != 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(0);
    return 1;
}

template <typename T>
[[nodiscard]] std::int32_t virtual_protect(T* address, std::uint64_t size,
                                           std::uint32_t protect,
                                           std::uint32_t* old) noexcept {
    if (address == nullptr || old == nullptr || size == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint64_t rounded = round_to_page(size);
    if (rounded == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The old protection is reported before it is changed, and the host has
    // no way to read it, so the value is the one the guest asked for last --
    // which is the value it wrote and the only one it could be comparing
    // against.
    *old = kPageReadWrite;
    const int host = host_protection(protect);
    if (::mprotect(address, static_cast<std::size_t>(rounded), host) != 0) {
        set_last_error(errno == EACCES ? kErrorInvalidAddress
                                       : kErrorInvalidParameter);
        return 0;
    }
    // A protection word that asked for execution on a host that will not
    // grant it is a request that failed, not one that succeeded quietly.
    if (wants_execute(protect) && (host & PROT_EXEC) == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(0);
    return 1;
}

template <typename T>
[[nodiscard]] std::uint64_t virtual_query(const T* address,
                                          std::uint8_t* out,
                                          std::uint64_t out_size) noexcept {
    if (out == nullptr || out_size < kMbiBytes) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    (void)address;
    // The host's view of a region is in `/proc/self/maps`, which is a Linux
    // interface rather than a portable one, and reading it is what would make
    // this answer true rather than descriptive. Until that is done, what this
    // reports is the region Windows would describe for memory this runtime
    // handed out -- committed, private, read-write -- and a guest walking the
    // space with it is walking a description this runtime can stand behind
    // rather than a guess about the host's maps. The caller that needs the
    // host's answer is the observation layer, which reads the maps directly
    // and does not go through this call.
    std::memset(out, 0, kMbiBytes);
    put_u64(out, kMbiBase, reinterpret_cast<std::uint64_t>(address));
    put_u64(out, kMbiAllocationBase, 0);
    put_u32(out, kMbiAllocationProtect, kPageReadWrite);
    put_u64(out, kMbiRegionSize, 0);
    put_u32(out, kMbiState, kMemCommit);
    put_u32(out, kMbiProtect, kPageReadWrite);
    put_u32(out, kMbiType, kMemPrivate);
    set_last_error(0);
    return kMbiBytes;
}

// ---------------------------------------------------------------------------
// Global and Local
// ---------------------------------------------------------------------------
//
// Two names for the process heap, which is what they have been since the
// segmented allocators they were named for stopped existing.
//
// One flag still means something here: `HEAP_ZERO_MEMORY` is honoured,
// because a caller can see the difference. The others do not.
// `HEAP_NO_SERIALIZE` asks for a heap without a lock and the host's
// allocator always has one; `HEAP_GENERATE_EXCEPTIONS` would raise on
// failure and this layer reports errors as return values, which is the
// project's rule and the reason there is no exception to raise through. A
// caller that passes either gets an allocation and no error, which is what
// it would get on Windows when the condition they guard against does not
// arise.

[[nodiscard]] void* heap_block(std::uint32_t flags, std::uint64_t bytes,
                               bool zero) noexcept {
    if (bytes == 0 && !zero) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    const std::uint32_t use = zero || (flags & kHeapZeroMemory) != 0
                                  ? kHeapZeroMemory
                                  : 0;
    void* block = heap_alloc(use, bytes);
    if (block == nullptr) {
        set_last_error(kErrorNotEnoughMemory);
        return nullptr;
    }
    set_last_error(0);
    return block;
}

// ---------------------------------------------------------------------------
// ABI entry points
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) void* k32m_VirtualAlloc(
    void* address, std::uint64_t size, std::uint32_t type,
    std::uint32_t protect) noexcept {
    return virtual_alloc(address, size, type, protect);
}

extern "C" __attribute__((ms_abi)) void* k32m_VirtualAllocEx(
    std::uint64_t process, void* address, std::uint64_t size,
    std::uint32_t type, std::uint32_t protect) noexcept {
    if (!names_this_process(process)) {
        set_last_error(kErrorInvalidHandle);
        return nullptr;
    }
    return virtual_alloc(address, size, type, protect);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32m_VirtualFree(
    void* address, std::uint64_t size, std::uint32_t type) noexcept {
    return virtual_free(address, size, type);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32m_VirtualFreeEx(
    std::uint64_t process, void* address, std::uint64_t size,
    std::uint32_t type) noexcept {
    if (!names_this_process(process)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    return virtual_free(address, size, type);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32m_VirtualProtect(
    void* address, std::uint64_t size, std::uint32_t protect,
    std::uint32_t* old) noexcept {
    return virtual_protect(address, size, protect, old);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32m_VirtualProtectEx(
    std::uint64_t process, void* address, std::uint64_t size,
    std::uint32_t protect, std::uint32_t* old) noexcept {
    if (!names_this_process(process)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    return virtual_protect(address, size, protect, old);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32m_VirtualQuery(
    const void* address, std::uint8_t* out,
    std::uint64_t out_size) noexcept {
    return virtual_query(address, out, out_size);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32m_VirtualQueryEx(
    std::uint64_t process, const void* address, std::uint8_t* out,
    std::uint64_t out_size) noexcept {
    if (!names_this_process(process)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    return virtual_query(address, out, out_size);
}

extern "C" __attribute__((ms_abi)) void* k32m_GlobalAlloc(
    std::uint32_t flags, std::uint64_t bytes) noexcept {
    return heap_block(flags, bytes, false);
}

extern "C" __attribute__((ms_abi)) void* k32m_LocalAlloc(
    std::uint32_t flags, std::uint64_t bytes) noexcept {
    return heap_block(flags, bytes, false);
}

extern "C" __attribute__((ms_abi)) void* k32m_GlobalReAlloc(
    void* block, std::uint64_t bytes, std::uint32_t flags) noexcept {
    if (bytes == 0) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    void* moved = heap_realloc(flags, block, bytes);
    if (moved == nullptr) {
        set_last_error(kErrorNotEnoughMemory);
        return nullptr;
    }
    set_last_error(0);
    return moved;
}

extern "C" __attribute__((ms_abi)) void* k32m_LocalReAlloc(
    void* block, std::uint64_t bytes, std::uint32_t flags) noexcept {
    return k32m_GlobalReAlloc(block, bytes, flags);
}

extern "C" __attribute__((ms_abi)) void* k32m_GlobalLock(
    void* block) noexcept {
    // A handle is a pointer in this implementation, which is what Windows
    // does with a fixed block too: locking one is asking for the address it
    // already has.
    return block;
}

extern "C" __attribute__((ms_abi)) void* k32m_LocalLock(void* block) noexcept {
    return block;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32m_GlobalUnlock(
    void* block) noexcept {
    (void)block;
    // The answer is "no error", which is not the same as success: Windows
    // documents this one as answering zero on success and a non-zero value
    // when the unlock count reached zero, so a caller that tests it against
    // zero reads the second case.
    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32m_LocalUnlock(
    void* block) noexcept {
    return k32m_GlobalUnlock(block);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32m_GlobalSize(
    const void* block) noexcept {
    if (block == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    return heap_size(block);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32m_LocalSize(
    const void* block) noexcept {
    return k32m_GlobalSize(block);
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32m_GlobalFlags(
    const void* block) noexcept {
    (void)block;
    // No flags are carried: the bits this answers on Windows describe a
    // discardable or fixed block, and every block here is fixed.
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32m_LocalFlags(
    const void* block) noexcept {
    return k32m_GlobalFlags(block);
}

extern "C" __attribute__((ms_abi)) void* k32m_GlobalHandle(
    const void* block) noexcept {
    return const_cast<void*>(block);
}

extern "C" __attribute__((ms_abi)) void* k32m_LocalHandle(
    const void* block) noexcept {
    return const_cast<void*>(block);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32m_GlobalFree(
    void* block) noexcept {
    if (block == nullptr) {
        set_last_error(0);
        return 0;
    }
    if (!heap_free(block)) {
        set_last_error(kErrorInvalidHandle);
        return 1;
    }
    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32m_LocalFree(
    void* block) noexcept {
    return k32m_GlobalFree(block);
}

extern "C" __attribute__((ms_abi)) void* k32m_HeapAlloc(
    std::uint64_t heap, std::uint32_t flags, std::uint64_t bytes) noexcept {
    (void)heap;
    return heap_block(flags, bytes, false);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32m_HeapFree(
    std::uint64_t heap, std::uint32_t flags, void* block) noexcept {
    (void)heap;
    (void)flags;
    if (block == nullptr) {
        set_last_error(0);
        return 1;
    }
    if (!heap_free(block)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) void* k32m_HeapReAlloc(
    std::uint64_t heap, std::uint32_t flags, void* block,
    std::uint64_t bytes) noexcept {
    (void)heap;
    if (bytes == 0) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    void* moved = heap_realloc(flags, block, bytes);
    if (moved == nullptr) {
        set_last_error(kErrorNotEnoughMemory);
        return nullptr;
    }
    set_last_error(0);
    return moved;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32m_HeapSize(
    std::uint64_t heap, std::uint32_t flags, const void* block) noexcept {
    (void)heap;
    (void)flags;
    if (block == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return static_cast<std::uint64_t>(-1);
    }
    return heap_size(block);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32m_HeapValidate(
    std::uint64_t heap, std::uint32_t flags, const void* block) noexcept {
    (void)heap;
    (void)flags;
    (void)block;
    // The host's allocator checks its own metadata on every operation, and
    // there is nothing here to walk that the guest could not walk itself.
    // Answering true is the honest answer for a heap that is maintained by
    // the host rather than by this layer.
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32m_HeapLock(
    std::uint64_t heap) noexcept {
    (void)heap;
    // The host's allocator is already thread-safe, and the lock the caller
    // is asking for would be a second lock over the same state. The call
    // succeeds because the property it is asking for holds.
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32m_HeapUnlock(
    std::uint64_t heap) noexcept {
    return k32m_HeapLock(heap);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32m_ReadProcessMemory(
    std::uint64_t process, const void* address, void* buffer,
    std::uint64_t bytes, std::uint64_t* read) noexcept {
    if (!names_this_process(process)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (address == nullptr || buffer == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The guest's address space is this process's, so the read is the read:
    // a copy rather than a call into the host's process-memory interface,
    // and a faulting address faults rather than being reported as a
    // short read.
    std::memcpy(buffer, address, static_cast<std::size_t>(bytes));
    if (read != nullptr) {
        *read = bytes;
    }
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32m_WriteProcessMemory(
    std::uint64_t process, void* address, const void* buffer,
    std::uint64_t bytes, std::uint64_t* written) noexcept {
    if (!names_this_process(process)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (address == nullptr || buffer == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::memcpy(address, buffer, static_cast<std::size_t>(bytes));
    if (written != nullptr) {
        *written = bytes;
    }
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32m_GetProcessHeap()
    noexcept {
    return process_heap_handle();
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32m_GetProcessHeaps(
    std::uint32_t count, std::uint64_t* out) noexcept {
    // One heap, and the count is the answer either way so that a caller
    // sizing its buffer learns how big the answer is.
    if (out != nullptr && count >= 1) {
        out[0] = process_heap_handle();
        return 1;
    }
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32m_HeapCreate(
    std::uint32_t options, std::uint64_t initial, std::uint64_t maximum)
    noexcept {
    (void)options;
    (void)initial;
    (void)maximum;
    // A private heap is a separate arena to Windows and has no meaning here:
    // the host's allocator is one pool, and handing back the process heap
    // means a program that creates a heap and allocates from it works, while
    // one that destroys a heap it created would take the process heap with
    // it. The handle is distinct so that the destruction can be recognised
    // and refused rather than obeyed.
    const std::uint64_t handle = 0x00A0000000000000ULL + 1;
    set_last_error(0);
    return handle;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32m_HeapDestroy(
    std::uint64_t heap) noexcept {
    (void)heap;
    // Refused, and the reason is the paragraph above: the only arena this
    // runtime has is the one the whole process allocates from, and a program
    // that freed it would be freeing everything. A private-heap program gets
    // a failure it can report rather than a success followed by corruption.
    set_last_error(kErrorInvalidHandle);
    return 0;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void add_memory_kernel32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    // `GetProcessHeap` is registered by `winabi.cpp`, which owns the name
    // for kernel32; two registrations of one name would leave the answer
    // depending on which module's table the export index read first, and
    // both answer the same process heap anyway.
    e("GetProcessHeaps", reinterpret_cast<void*>(&k32m_GetProcessHeaps));
    e("GlobalAlloc", reinterpret_cast<void*>(&k32m_GlobalAlloc));
    e("GlobalFlags", reinterpret_cast<void*>(&k32m_GlobalFlags));
    e("GlobalFree", reinterpret_cast<void*>(&k32m_GlobalFree));
    e("GlobalHandle", reinterpret_cast<void*>(&k32m_GlobalHandle));
    e("GlobalLock", reinterpret_cast<void*>(&k32m_GlobalLock));
    e("GlobalReAlloc", reinterpret_cast<void*>(&k32m_GlobalReAlloc));
    e("GlobalSize", reinterpret_cast<void*>(&k32m_GlobalSize));
    e("GlobalUnlock", reinterpret_cast<void*>(&k32m_GlobalUnlock));
    e("HeapAlloc", reinterpret_cast<void*>(&k32m_HeapAlloc));
    e("HeapCreate", reinterpret_cast<void*>(&k32m_HeapCreate));
    e("HeapDestroy", reinterpret_cast<void*>(&k32m_HeapDestroy));
    e("HeapFree", reinterpret_cast<void*>(&k32m_HeapFree));
    e("HeapLock", reinterpret_cast<void*>(&k32m_HeapLock));
    e("HeapReAlloc", reinterpret_cast<void*>(&k32m_HeapReAlloc));
    e("HeapSize", reinterpret_cast<void*>(&k32m_HeapSize));
    e("HeapUnlock", reinterpret_cast<void*>(&k32m_HeapUnlock));
    e("HeapValidate", reinterpret_cast<void*>(&k32m_HeapValidate));
    e("LocalAlloc", reinterpret_cast<void*>(&k32m_LocalAlloc));
    e("LocalFlags", reinterpret_cast<void*>(&k32m_LocalFlags));
    e("LocalFree", reinterpret_cast<void*>(&k32m_LocalFree));
    e("LocalHandle", reinterpret_cast<void*>(&k32m_LocalHandle));
    e("LocalLock", reinterpret_cast<void*>(&k32m_LocalLock));
    e("LocalReAlloc", reinterpret_cast<void*>(&k32m_LocalReAlloc));
    e("LocalSize", reinterpret_cast<void*>(&k32m_LocalSize));
    e("LocalUnlock", reinterpret_cast<void*>(&k32m_LocalUnlock));
    e("ReadProcessMemory", reinterpret_cast<void*>(&k32m_ReadProcessMemory));
    e("VirtualAlloc", reinterpret_cast<void*>(&k32m_VirtualAlloc));
    e("VirtualAllocEx", reinterpret_cast<void*>(&k32m_VirtualAllocEx));
    e("VirtualFree", reinterpret_cast<void*>(&k32m_VirtualFree));
    e("VirtualFreeEx", reinterpret_cast<void*>(&k32m_VirtualFreeEx));
    e("VirtualProtect", reinterpret_cast<void*>(&k32m_VirtualProtect));
    e("VirtualProtectEx", reinterpret_cast<void*>(&k32m_VirtualProtectEx));
    e("VirtualQuery", reinterpret_cast<void*>(&k32m_VirtualQuery));
    e("VirtualQueryEx", reinterpret_cast<void*>(&k32m_VirtualQueryEx));
    e("WriteProcessMemory", reinterpret_cast<void*>(&k32m_WriteProcessMemory));
}

}  // namespace occ::runtime::winabi

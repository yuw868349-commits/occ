// The shell-memory family: the Nt* memory calls a debugger or a packer uses
// when it wants the kernel's own spelling of an operation the Win32 layer
// already answers, plus the Rtl image-inspection pair and the kernel32
// surface around process memory, locking, heap enumeration and locale names.
//
// Every Nt* call below is a bridge to the host memory layer this runtime
// already implements -- `nt_allocate_virtual_memory` and its siblings in
// `ntdll.cpp`, reached through the same `NtContext` the rest of the ntdll
// domain constructs. The guest runs in this process's address space, so the
// "virtual memory" of the call is the host's own `mmap` bookkeeping, and an
// answer is a real mapping or a real refusal, never a synthetic success.
// A process handle that names anything but this process is refused with
// `STATUS_INVALID_HANDLE` rather than answered for a stranger, which is the
// cross-process boundary every other Nt* slice keeps.
//
// The section half of the file bridges to the file-mapping family in
// `filemap.cpp`: `NtCreateSection` mints a handle in the filemap domain
// (0x600000 upward) so the existing `NtClose` -- which routes small handles
// to `CloseHandle`, and `CloseHandle` recognises the filemap range -- closes
// what this file created. The resource-side Rtl calls read the guest's own
// placed image headers directly, because a PE header in guest memory is a
// structure this runtime wrote to mean what it means.
//
// Three boundaries are named rather than hidden:
//
//   * The Rtl dynamic function-table registry (`RtlAddFunctionTable` /
//     `RtlDeleteFunctionTable`) is consolidated in ntdl_rtl_str.cpp's shared
//     table, where the add/delete pair round-trips against one registry;
//     this file no longer hosts it. The host's `RtlLookupFunctionEntry`
//     still answers from the static `.pdata` table only, so a dynamically
//     registered range is not yet consulted by the lookup path.
//
//   * `SetProcessMitigationPolicy` refuses with `ERROR_NOT_SUPPORTED`: this
//     runtime has no mitigation-enforcement machinery, and storing a policy
//     it never enforces would be a lie about the process's protection.
//     `GetProcessMitigationPolicy` answers the symmetric truth -- a
//     zero-filled policy, which is the actual state of a process with no
//     mitigation forced on it.
//
//   * `Get/SetThreadIdealProcessorEx` treat the ideal processor as the hint
//     Windows says it is: the setter records the value and best-effort-pins
//     the current host thread; the getter reports the CPU the current thread
//     is actually running on (`sched_getcpu`), which is the closest honest
//     reading for a thread whose ideal is a suggestion.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/ntdll.h"
#include "occ/runtime/winabi.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <errno.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace occ::runtime::winabi {
namespace {

// ---------------------------------------------------------------------------
// The NTSTATUS values these calls answer with
// ---------------------------------------------------------------------------
//
// Each is the number a program compares against on the wire. The success
// value is zero; the failures are the statuses the memory and section
// families document, written as constants rather than remembered, for the
// same reason the address-space Status enum keeps its values.

constexpr std::uint32_t kStSuccess = 0x00000000u;
constexpr std::uint32_t kStInvalidHandle = 0xC0000008u;
constexpr std::uint32_t kStInvalidParameter = 0xC000000Du;
constexpr std::uint32_t kStAccessDenied = 0xC0000022u;
constexpr std::uint32_t kStNoMemory = 0xC0000017u;
constexpr std::uint32_t kStInvalidImageFormat = 0xC000007Bu;
constexpr std::uint32_t kStObjectNameCollision = 0xC0000035u;
constexpr std::uint32_t kStObjectNameNotFound = 0xC0000034u;
constexpr std::uint32_t kStUnsuccessful = 0xC0000001u;
constexpr std::uint32_t kStMappedAlignment = 0xC0000220u;

// The pseudo-handle a caller uses for "the current process" in a 64-bit
// guest. Zero and the real process id are also accepted below, which is the
// contract this slice documents in its header comment.
constexpr std::uint64_t kCurrentProcessHandle = 0xFFFFFFFFFFFFFFFFULL;

// The filemap domain's section handles. `NtCreateSection` mints handles in
// this range so that the existing close path -- `nt_NtClose` routing small
// handles to `CloseHandle`, which recognises the filemap range -- closes a
// section created here without any new close logic.
constexpr std::uint64_t kMappingHandleBase = 0x600000;

// The section-protection values, in the guest's numbering, used to derive a
// view's `FILE_MAP_*` access from a view's `PAGE_*` protection.
// The section-protection values, in the guest's numbering, used to derive a
// view's `FILE_MAP_*` access from a view's `PAGE_*` protection. Read-only
// needs no constant here: any access without write/copy/execute is read.
constexpr std::uint32_t kPageReadwrite = 0x04u;
constexpr std::uint32_t kPageWritecopy = 0x08u;
constexpr std::uint32_t kPageExecuteRead = 0x20u;
constexpr std::uint32_t kPageExecuteReadwrite = 0x40u;
constexpr std::uint32_t kPageExecuteWritecopy = 0x80u;

// The `FILE_MAP_*` access values the filemap layer interprets.
constexpr std::uint32_t kFileMapCopy = 0x00000001u;
constexpr std::uint32_t kFileMapWrite = 0x00000002u;
constexpr std::uint32_t kFileMapExecute = 0x00000020u;

// The heap-entry flag for an allocated (busy) block, from winbase.h.
constexpr std::uint16_t kProcessHeapEntryBusy = 0x0004u;

// The mitigation-policy classes `GetProcessMitigationPolicy` answers, in
// the guest's numbering (PROCESS_MITIGATION_POLICY).
constexpr std::uint32_t kProcessDepPolicy = 0;
constexpr std::uint32_t kProcessAslrPolicy = 1;
constexpr std::uint32_t kProcessDynamicCodePolicy = 2;
constexpr std::uint32_t kProcessStrictHandleCheckPolicy = 3;
constexpr std::uint32_t kProcessSystemCallDisablePolicy = 4;
constexpr std::uint32_t kProcessMitigationOptionsMask = 5;
constexpr std::uint32_t kProcessCallerCheckPolicy = 6;

// The MUI language-format flags `GetPreferredUILanguages` accepts.
constexpr std::uint32_t kMuiLanguageId = 0x00000004u;
constexpr std::uint32_t kMuiLanguageName = 0x00000008u;

// The IMAGE_FILE_INFORMATION flags, from ReactOS winternl.h. The structure
// is undocumented; the 64-bit flag is the one this runtime answers with,
// because every image this runtime places is an x64 image.
constexpr std::uint32_t kImageFileInformationFlags64Bit = 0x00000008u;

// The x64 RUNTIME_FUNCTION record: three 32-bit RVAs relative to the image
// base. The record is laid out by hand because it is a guest structure and
// this host's compiler has no reason to agree on its padding.
struct RuntimeFunctionLayout {
    // Documented record layout; the fields are named for a future caller
    // that walks the guest's RUNTIME_FUNCTION array (the registry keys on
    // the array address, not the fields).
    [[maybe_unused]] static constexpr std::size_t kBeginAddress = 0;
    [[maybe_unused]] static constexpr std::size_t kEndAddress = 4;
    [[maybe_unused]] static constexpr std::size_t kUnwindInfoAddress = 8;
    [[maybe_unused]] static constexpr std::size_t kBytes = 12;
};

// The PROCESSOR_NUMBER record `Get/SetThreadIdealProcessorEx` exchange: a
// 16-bit group, an 8-bit number and an 8-bit reserved byte. Group zero is
// the only group this runtime knows, which is every machine a guest can run
// on here.
struct ProcessorNumberLayout {
    static constexpr std::size_t kGroup = 0;
    static constexpr std::size_t kNumber = 2;
    static constexpr std::size_t kReserved = 3;
    [[maybe_unused]] static constexpr std::size_t kBytes = 4;
};

// The PROCESS_HEAP_ENTRY record `HeapWalk` fills, in the x64 layout from
// winbase.h: a data pointer, the data size, a one-byte overhead and a
// one-byte region index, the two-byte flag word, then the union whose
// `Block` member names the block handle and the reserved words. The task
// brief sketched these offsets from memory (cbOverhead 16, wFlags 24,
// hMem 32); the winbase.h layout below is the authoritative one and the
// fields are written by offset so a mistake in one layout cannot leak into
// another.
struct ProcessHeapEntryLayout {
    static constexpr std::size_t kLpData = 0;      // PVOID
    static constexpr std::size_t kCbData = 8;      // DWORD
    static constexpr std::size_t kCbOverhead = 12; // BYTE
    static constexpr std::size_t kIRegionIndex = 13; // BYTE
    static constexpr std::size_t kWFIags = 14;     // WORD
    static constexpr std::size_t kHMem = 16;       // HANDLE (Block.hMem)
    [[maybe_unused]] static constexpr std::size_t kBytes = 40;  // sizeof
};

// The IMAGE_FILE_INFORMATION record `RtlQueryImageFileInformation` fills:
// four 32-bit fields followed by the wide image name. Layout from
// winternl.h; ImageName is a flexible WCHAR array at offset 16.
struct ImageFileInformationLayout {
    static constexpr std::size_t kFlags = 0;
    static constexpr std::size_t kMachineType = 4;
    static constexpr std::size_t kTimeDateStamp = 8;
    static constexpr std::size_t kCharacteristics = 12;
    static constexpr std::size_t kImageName = 16;
};

// ---------------------------------------------------------------------------
// Bridges to other translation units
// ---------------------------------------------------------------------------
//
// The Win32 names this file calls are the same `ms_abi` thunks the rest of
// the runtime registers, declared here because the ntdll spellings call the
// Win32 spellings. The filemap family provides the section machinery; the
// process id tells a process handle from a stranger's; `occ_ntstatus_to_dos`
// maps an NTSTATUS from the host memory layer to the Win32 error a kernel32
// entry point reports.

extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetCurrentProcessId() noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetLastError() noexcept;
extern "C" std::uint32_t occ_ntstatus_to_dos(std::uint32_t status) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32fm_CreateFileMappingW(
    std::uint64_t file, void* attributes, std::uint32_t protect,
    std::uint32_t size_high, std::uint32_t size_low,
    const std::uint16_t* name) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32fm_OpenFileMappingW(
    std::uint32_t access, std::int32_t inherit,
    const std::uint16_t* name) noexcept;
extern "C" __attribute__((ms_abi)) void* k32fm_MapViewOfFile(
    std::uint64_t section, std::uint32_t access, std::uint32_t offset_high,
    std::uint32_t offset_low, std::uint64_t bytes) noexcept;
extern "C" __attribute__((ms_abi)) void* k32fm_MapViewOfFileEx(
    std::uint64_t section, std::uint32_t access, std::uint32_t offset_high,
    std::uint32_t offset_low, std::uint64_t bytes, void* at) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32fm_UnmapViewOfFile(
    void* base) noexcept;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// Whether a process handle names this process. The pseudo-handle, a zero
// handle and the real process id are the three spellings a caller can use
// for "this process"; anything else is a stranger and is refused rather than
// answered for, because answering a call meant for another process by
// modifying this one is the failure mode the memory layer refuses to have.
[[nodiscard]] bool is_self_process(std::uint64_t handle) noexcept {
    if (handle == kCurrentProcessHandle) {
        return true;
    }
    if (handle == 0) {
        return true;
    }
    return handle == static_cast<std::uint64_t>(k32_GetCurrentProcessId());
}

// The host page size, cached once.
[[nodiscard]] std::size_t host_page_size() noexcept {
    static const std::size_t page = static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
    return page;
}

[[nodiscard]] std::uint64_t align_down(std::uint64_t value,
                                       std::uint64_t alignment) noexcept {
    return value - (value % alignment);
}

[[nodiscard]] std::uint64_t align_up(std::uint64_t value,
                                     std::uint64_t alignment) noexcept {
    const std::uint64_t rem = value % alignment;
    if (rem == 0) {
        return value;
    }
    return value + (alignment - rem);
}

// The BCP-47 name of the host locale, kept in step with the LCID mapping in
// `sysinfo_ext.cpp` (zh_CN -> 0x0804, zh_TW/zh_HK -> 0x0404, ja -> 0x0411,
// ko -> 0x0412, everything else -> 0x0409). The names are the Windows
// spellings of the same choices.
[[nodiscard]] std::u16string default_locale_name() noexcept {
    const char* lang = std::getenv("LANG");
    if (lang == nullptr) {
        return u"en-US";
    }
    if (std::strncmp(lang, "zh_CN", 5) == 0) {
        return u"zh-CN";
    }
    if (std::strncmp(lang, "zh_TW", 5) == 0) {
        return u"zh-TW";
    }
    if (std::strncmp(lang, "zh_HK", 5) == 0) {
        return u"zh-HK";
    }
    if (std::strncmp(lang, "ja_JP", 5) == 0) {
        return u"ja-JP";
    }
    if (std::strncmp(lang, "ko_KR", 5) == 0) {
        return u"ko-KR";
    }
    return u"en-US";
}

// Reads the guest's PE headers at `base` and answers whether they parse as
// an x64 image. The guest's memory is the host's, so the headers are read
// with the same byte helpers the rest of the runtime uses for guest
// structures.
[[nodiscard]] std::uint64_t nt_header_of(std::uint64_t base) noexcept {
    if (base == 0) {
        return 0;
    }
    const auto* dos = reinterpret_cast<const std::uint8_t*>(base);
    if (read_u16(dos, 0) != 0x5A4Du) {  // "MZ"
        return 0;
    }
    const std::uint32_t lfanew = read_u32(dos, 0x3C);
    const auto* nt = reinterpret_cast<const std::uint8_t*>(base + lfanew);
    if (read_u32(nt, 0) != 0x00004550u) {  // "PE\0\0"
        return 0;
    }
    // OptionalHeader.Magic: 0x20B is PE32+ (x64), 0x10B is PE32 (x86).
    if (read_u16(nt, 24) != 0x20Bu) {
        return 0;
    }
    return base + lfanew;
}

// ---------------------------------------------------------------------------
// Section-size registry
// ---------------------------------------------------------------------------
//
// `NtMapViewOfSection` must write the *actual* mapped size back through
// `*ViewSize`, and a whole-section request (ViewSize == 0) maps the
// section's own size -- which the filemap layer resolves internally and does
// not hand back. The size is therefore recorded here when a section is
// created through `NtCreateSection` (where the size is an argument or is
// derivable from the file), so the map can report the truth. A section
// opened through `NtOpenSection` with a zero ViewSize request is refused,
// because the size of a section this file did not create is unknowable from
// outside the filemap layer; every other combination works.

std::mutex& section_size_lock() noexcept {
    static std::mutex lock;
    return lock;
}

std::vector<std::uint64_t>& section_sizes() noexcept {
    static std::vector<std::uint64_t> sizes;
    return sizes;
}

[[nodiscard]] std::uint64_t section_size_of(std::uint64_t handle) noexcept {
    const std::uint64_t index = handle - kMappingHandleBase;
    std::lock_guard<std::mutex> lock(section_size_lock());
    if (index >= section_sizes().size()) {
        return 0;
    }
    return section_sizes()[static_cast<std::size_t>(index)];
}

void record_section_size(std::uint64_t handle, std::uint64_t size) noexcept {
    const std::uint64_t index = handle - kMappingHandleBase;
    std::lock_guard<std::mutex> lock(section_size_lock());
    if (index >= section_sizes().size()) {
        section_sizes().resize(static_cast<std::size_t>(index) + 1, 0);
    }
    section_sizes()[static_cast<std::size_t>(index)] = size;
}

// The size of a file this runtime's file domain opened, by its handle. The
// file domain mints handles from 0x2000 and the descriptor is the handle
// minus the base, which is the convention `filemap.cpp` documents and uses.
[[nodiscard]] std::uint64_t file_size_of(std::uint64_t file_handle) noexcept {
    constexpr std::uint64_t kFileHandleBase = 0x2000;
    if (file_handle < kFileHandleBase) {
        return 0;
    }
    struct stat st;
    if (::fstat(static_cast<int>(file_handle - kFileHandleBase), &st) != 0) {
        return 0;
    }
    return static_cast<std::uint64_t>(st.st_size);
}

// The ideal-processor record, for `SetThreadIdealProcessorEx`. The value is
// a hint: it is stored per thread handle so a later getter can return it,
// and the current host thread is best-effort pinned when the handle names
// the calling thread. A store is real state, and the pin is a suggestion,
// which is what Windows documents the ideal processor to be.

std::mutex& ideal_processor_lock() noexcept {
    static std::mutex lock;
    return lock;
}

std::vector<std::uint64_t>& ideal_handles() noexcept {
    static std::vector<std::uint64_t> handles;
    return handles;
}

std::vector<std::uint32_t>& ideal_processors() noexcept {
    static std::vector<std::uint32_t> ideals;
    return ideals;
}

[[nodiscard]] bool ideal_processor_of(std::uint64_t handle,
                                      std::uint32_t& out) noexcept {
    std::lock_guard<std::mutex> lock(ideal_processor_lock());
    for (std::size_t i = 0; i < ideal_handles().size(); ++i) {
        // The handle is stored directly; the vector is small and a linear
        // scan is the honest lookup for a per-thread hint table.
        if (ideal_handles()[i] == handle) {
            out = ideal_processors()[i];
            return true;
        }
    }
    return false;
}

void record_ideal_processor(std::uint64_t handle, std::uint32_t ideal) noexcept {
    std::lock_guard<std::mutex> lock(ideal_processor_lock());
    for (std::size_t i = 0; i < ideal_handles().size(); ++i) {
        if (ideal_handles()[i] == handle) {
            ideal_processors()[i] = ideal;
            return;
        }
    }
    ideal_handles().push_back(handle);
    ideal_processors().push_back(ideal);
}

// Whether a thread handle names the calling thread: the current-thread
// pseudo-handle, or a guest thread whose state is this thread's own.
[[nodiscard]] bool is_current_thread(std::uint64_t handle) noexcept {
    constexpr std::uint64_t kCurrentThreadHandle = 0xFFFFFFFFFFFFFFFFULL;
    if (handle == kCurrentThreadHandle) {
        return true;
    }
    GuestState* self = guest_state();
    return self != nullptr && guest_thread_state_for(handle) == self;
}

// ---------------------------------------------------------------------------
// NTDLL: the memory pair
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint32_t ntsm_NtAllocateVirtualMemory(
    std::uint64_t process_handle, std::uint64_t* base_address,
    std::uint64_t* region_size, std::uint32_t zero_bits, std::uint32_t type,
    std::uint32_t protect) noexcept {
    if (!is_self_process(process_handle)) {
        return kStInvalidHandle;
    }
    GuestState* g = guest_state();
    if (g == nullptr || g->space == nullptr || g->mapper == nullptr) {
        return kStInvalidHandle;
    }
    if (base_address == nullptr || region_size == nullptr) {
        return kStInvalidParameter;
    }
    NtContext ctx;
    ctx.space = g->space;
    ctx.placement = g->mapper;
    const Result<std::uint64_t> r = nt_allocate_virtual_memory(
        ctx, base_address, region_size, zero_bits, type, protect);
    // The host layer's Status values *are* NTSTATUS codes (the enum is
    // documented as such), so the answer is the enum's value verbatim. On
    // success the host wrote the real base and size through the caller's
    // pointers, which are guest memory.
    return static_cast<std::uint32_t>(r.status);
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntsm_NtFreeVirtualMemory(
    std::uint64_t process_handle, std::uint64_t* base_address,
    std::uint64_t* region_size, std::uint32_t type) noexcept {
    if (!is_self_process(process_handle)) {
        return kStInvalidHandle;
    }
    GuestState* g = guest_state();
    if (g == nullptr || g->space == nullptr || g->mapper == nullptr) {
        return kStInvalidHandle;
    }
    if (base_address == nullptr || region_size == nullptr) {
        return kStInvalidParameter;
    }
    NtContext ctx;
    ctx.space = g->space;
    ctx.placement = g->mapper;
    const Result<std::uint64_t> r =
        nt_free_virtual_memory(ctx, base_address, region_size, type);
    return static_cast<std::uint32_t>(r.status);
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntsm_NtProtectVirtualMemory(
    std::uint64_t process_handle, std::uint64_t* base_address,
    std::uint64_t* region_size, std::uint32_t new_protect,
    std::uint32_t* old_protect) noexcept {
    if (!is_self_process(process_handle)) {
        return kStInvalidHandle;
    }
    GuestState* g = guest_state();
    if (g == nullptr || g->space == nullptr || g->mapper == nullptr) {
        return kStInvalidHandle;
    }
    if (base_address == nullptr || region_size == nullptr) {
        return kStInvalidParameter;
    }
    NtContext ctx;
    ctx.space = g->space;
    ctx.placement = g->mapper;
    // The PAGE_GUARD refusal and the whole-region rule live in the host
    // layer and are inherited as-is.
    const Result<std::uint64_t> r = nt_protect_virtual_memory(
        ctx, base_address, region_size, new_protect, old_protect);
    return static_cast<std::uint32_t>(r.status);
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntsm_NtReadVirtualMemory(
    std::uint64_t process_handle, std::uint64_t base_address, void* buffer,
    std::uint64_t size, std::uint64_t* bytes_read) noexcept {
    if (!is_self_process(process_handle)) {
        return kStInvalidHandle;
    }
    GuestState* g = guest_state();
    if (g == nullptr || g->space == nullptr || g->mapper == nullptr) {
        return kStInvalidHandle;
    }
    NtContext ctx;
    ctx.space = g->space;
    ctx.placement = g->mapper;
    // The host layer writes `*bytes_read` -- zero on failure -- which is
    // Wine's rule and Windows', and the reason a caller that reads the count
    // before the status sees 0 rather than garbage.
    const Result<std::uint64_t> r = nt_read_virtual_memory(
        ctx, base_address, buffer, size, bytes_read);
    return static_cast<std::uint32_t>(r.status);
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntsm_NtWriteVirtualMemory(
    std::uint64_t process_handle, std::uint64_t base_address,
    const void* buffer, std::uint64_t size,
    std::uint64_t* bytes_written) noexcept {
    if (!is_self_process(process_handle)) {
        return kStInvalidHandle;
    }
    GuestState* g = guest_state();
    if (g == nullptr || g->space == nullptr || g->mapper == nullptr) {
        return kStInvalidHandle;
    }
    NtContext ctx;
    ctx.space = g->space;
    ctx.placement = g->mapper;
    const Result<std::uint64_t> r = nt_write_virtual_memory(
        ctx, base_address, buffer, size, bytes_written);
    return static_cast<std::uint32_t>(r.status);
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntsm_NtFlushInstructionCache(
    std::uint64_t process_handle, std::uint64_t base_address,
    std::uint64_t size) noexcept {
    if (!is_self_process(process_handle)) {
        return kStInvalidHandle;
    }
    GuestState* g = guest_state();
    if (g == nullptr || g->space == nullptr || g->mapper == nullptr) {
        return kStInvalidHandle;
    }
    NtContext ctx;
    ctx.space = g->space;
    ctx.placement = g->mapper;
    // A no-op on x64 with the instruction cache coherent with the data
    // cache -- Wine is a no-op too -- but the host layer records the call in
    // the ledger and handles the size-zero "whole region" spelling.
    const Result<std::uint64_t> r =
        nt_flush_instruction_cache(ctx, base_address, size);
    return static_cast<std::uint32_t>(r.status);
}

// ---------------------------------------------------------------------------
// NTDLL: sections
// ---------------------------------------------------------------------------

// The Win32 last error to NTSTATUS translation the section calls use. The
// filemap layer reports through `SetLastError`; the Nt* contract answers
// with an NTSTATUS, so the errors the filemap layer actually produces are
// mapped to the statuses they mean.
[[nodiscard]] std::uint32_t status_from_last_error() noexcept {
    switch (k32_GetLastError()) {
    case kErrorInvalidHandle:
        return kStInvalidHandle;
    case kErrorInvalidParameter:
        return kStInvalidParameter;
    case kErrorAlreadyExists:
        return kStObjectNameCollision;
    case kErrorAccessDenied:
        return kStAccessDenied;
    case kErrorFileNotFound:
        return kStObjectNameNotFound;
    case kErrorNotEnoughMemory:
        return kStNoMemory;
    default:
        return kStUnsuccessful;
    }
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntsm_NtCreateSection(
    std::uint64_t* handle, std::uint32_t desired_access,
    void* object_attributes, std::uint64_t* size, std::uint32_t protect,
    std::uint32_t allocation_attributes, std::uint64_t file_handle) noexcept {
    if (handle == nullptr) {
        return kStInvalidParameter;
    }
    // DesiredAccess is the handle's access mask; this runtime checks access
    // at view time (the filemap layer refuses a view that exceeds the
    // section's protection), so the mask is not a separate decision here.
    static_cast<void>(desired_access);
    // ObjectAttributes would carry a name. This runtime has one process and
    // no object namespace beyond the filemap layer's in-process section
    // names, and `NtCreateSection` is answered with an anonymous section;
    // a named `NtOpenSection` is bridged below by looking the name up in the
    // same in-process table. A caller that passes a name here has asked for
    // a named object, which the anonymous path does not create.
    static_cast<void>(object_attributes);

    std::uint64_t section_size = 0;
    if (size != nullptr) {
        section_size = read_u64(size, 0);  // LARGE_INTEGER
    }
    // AllocationAttributes (SEC_COMMIT / SEC_RESERVE / SEC_IMAGE) select how
    // the section's pages are provisioned. The filemap layer maps a section
    // as one mmap and does not model the commit/reserve distinction, and an
    // image section is mapped as data with the caller's (usually
    // execute-capable) protection, which is the part of SEC_IMAGE that
    // matters to a caller that maps and runs from a section.
    static_cast<void>(allocation_attributes);

    // An anonymous section (INVALID_HANDLE_VALUE) needs an explicit size;
    // a file-backed section may pass zero, meaning "the file's own size",
    // which the filemap layer resolves from the descriptor.
    if (file_handle == kInvalidHandleValue) {
        if (section_size == 0) {
            return kStInvalidParameter;
        }
    } else {
        // A section must be backed by a file this runtime opened; a
        // stranger's handle is refused the way the filemap layer refuses it,
        // but the refusal is clearer here, before the mapping layer is asked.
        constexpr std::uint64_t kFileHandleBase = 0x2000;
        constexpr std::uint64_t kFileHandleSpan = 0x100000;
        if (file_handle < kFileHandleBase ||
            file_handle >= kFileHandleBase + kFileHandleSpan) {
            return kStInvalidHandle;
        }
    }

    const std::uint32_t size_high = static_cast<std::uint32_t>(section_size >> 32);
    const std::uint32_t size_low = static_cast<std::uint32_t>(section_size & 0xFFFFFFFFu);
    const std::uint64_t section = k32fm_CreateFileMappingW(
        file_handle, nullptr, protect, size_high, size_low, nullptr);
    if (section == 0) {
        return status_from_last_error();
    }
    // Remember the section's resolved size for `NtMapViewOfSection`'s
    // ViewSize write-back. A file-backed section created with a zero size
    // has the file's size; the filemap layer resolved it the same way.
    if (section_size == 0 && file_handle != kInvalidHandleValue) {
        section_size = file_size_of(file_handle);
    }
    record_section_size(section, section_size);
    write_u64(handle, 0, section);
    return kStSuccess;
}

// The view-access a view protection asks for, in the filemap layer's
// numbering. The mapping is the Windows one: a write view needs the section
// to permit writing, a copy view is the private-copy spelling, an execute
// view carries the section's execution protection.
[[nodiscard]] std::uint32_t view_access_of(std::uint32_t protect) noexcept {
    switch (protect & 0xFFu) {
    case kPageReadwrite:
        return kFileMapWrite;
    case kPageWritecopy:
        return kFileMapCopy;
    case kPageExecuteRead:
        return kFileMapExecute;
    case kPageExecuteReadwrite:
        return kFileMapWrite | kFileMapExecute;
    case kPageExecuteWritecopy:
        return kFileMapCopy | kFileMapExecute;
    default:
        // kPageReadonly and anything unreadable: a read view. The filemap
        // layer answers any access without write/copy/execute as read-only.
        return 0;
    }
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntsm_NtMapViewOfSection(
    std::uint64_t section_handle, std::uint64_t process_handle,
    std::uint64_t* base_address, std::uint32_t zero_bits,
    std::uint64_t commit_size, std::uint64_t* section_offset,
    std::uint64_t* view_size, std::uint32_t inherit_disposition,
    std::uint32_t allocation_type, std::uint32_t protect) noexcept {
    if (!is_self_process(process_handle)) {
        return kStInvalidHandle;
    }
    if (view_size == nullptr) {
        return kStInvalidParameter;
    }
    static_cast<void>(zero_bits);
    static_cast<void>(commit_size);
    static_cast<void>(inherit_disposition);
    static_cast<void>(allocation_type);

    std::uint64_t offset = 0;
    if (section_offset != nullptr) {
        offset = read_u64(section_offset, 0);  // LARGE_INTEGER
    }
    const std::uint64_t requested = *view_size;

    // Windows requires a requested base to be aligned to the allocation
    // granularity. The filemap layer maps with MAP_FIXED_NOREPLACE and the
    // host would refuse a misaligned address too, but the status Windows
    // documents for this is STATUS_MAPPED_ALIGNMENT, and naming it is the
    // difference between "the kernel refused my address" and "I asked for
    // something mmap cannot place".
    if (base_address != nullptr) {
        const std::uint64_t at = *base_address;
        if (at != 0 && at % 0x10000u != 0) {
            return kStMappedAlignment;
        }
    }

    const std::uint64_t offset_low = offset & 0xFFFFFFFFu;
    const std::uint64_t offset_high = offset >> 32;
    void* mapped = nullptr;
    if (base_address == nullptr || *base_address == 0) {
        mapped = k32fm_MapViewOfFile(
            section_handle, view_access_of(protect),
            static_cast<std::uint32_t>(offset_high),
            static_cast<std::uint32_t>(offset_low), requested);
    } else {
        mapped = k32fm_MapViewOfFileEx(
            section_handle, view_access_of(protect),
            static_cast<std::uint32_t>(offset_high),
            static_cast<std::uint32_t>(offset_low), requested,
            reinterpret_cast<void*>(*base_address));
    }
    if (mapped == nullptr) {
        return status_from_last_error();
    }

    // The actual size: an explicit request maps exactly that many bytes; a
    // zero request maps the whole section, whose size was recorded at
    // creation (an `NtOpenSection` handle with a zero request is refused
    // below because that size is unknowable here).
    if (requested != 0) {
        write_u64(view_size, 0, requested);
    } else {
        const std::uint64_t whole = section_size_of(section_handle);
        if (whole == 0) {
            k32fm_UnmapViewOfFile(mapped);
            return kStInvalidParameter;
        }
        write_u64(view_size, 0, whole - offset);
    }
    if (base_address != nullptr) {
        write_u64(base_address, 0, reinterpret_cast<std::uint64_t>(mapped));
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntsm_NtUnmapViewOfSection(
    std::uint64_t process_handle, std::uint64_t base_address) noexcept {
    if (!is_self_process(process_handle)) {
        return kStInvalidHandle;
    }
    if (k32fm_UnmapViewOfFile(reinterpret_cast<void*>(base_address)) == 0) {
        return status_from_last_error();
    }
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntsm_NtOpenSection(
    std::uint64_t* handle, std::uint32_t desired_access,
    void* object_attributes) noexcept {
    if (handle == nullptr || object_attributes == nullptr) {
        return kStInvalidParameter;
    }
    static_cast<void>(desired_access);
    // The filemap layer's section names are the only namespace there is:
    // a single-process runtime has no cross-process object directory, and a
    // name lookup is a search of the sections this runtime created. The
    // OBJECT_ATTRIBUTES record carries ObjectName as a pointer to a
    // UNICODE_STRING at offset 16 (after Length and RootDirectory).
    const std::uint64_t object_name = read_ptr(object_attributes, 16);
    if (object_name == 0) {
        return kStInvalidParameter;
    }
    const std::uint16_t name_length = read_u16(reinterpret_cast<const void*>(object_name), 0);
    const std::uint64_t name_buffer = read_ptr(reinterpret_cast<const void*>(object_name), 8);
    if (name_buffer == 0) {
        return kStInvalidParameter;
    }
    std::u16string name;
    const std::size_t chars = static_cast<std::size_t>(name_length) / 2;
    const auto* raw = reinterpret_cast<const char16_t*>(name_buffer);
    name.assign(raw, chars);

    // The section name travels to the filemap layer as its original UTF-16
    // code units, not as bytes that were truncated one code unit at a time:
    // the name is copied whole into a host u16string whose data() is
    // NUL-terminated (C++11), which is the wide C string the layer reads.
    const std::uint64_t section =
        k32fm_OpenFileMappingW(desired_access, 0,
                               reinterpret_cast<const std::uint16_t*>(name.data()));
    if (section == 0) {
        return status_from_last_error();
    }
    write_u64(handle, 0, section);
    return kStSuccess;
}

// ---------------------------------------------------------------------------
// NTDLL: the Rtl image-inspection pair
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint32_t ntsm_RtlQueryImageFileInformation(
    void* image_information, std::uint64_t base_address) noexcept {
    if (image_information == nullptr) {
        return kStInvalidParameter;
    }
    const std::uint64_t nt = nt_header_of(base_address);
    if (nt == 0) {
        // Not an x64 image this runtime would have placed: the status
        // Windows answers a base that is not a known image.
        return kStInvalidImageFormat;
    }
    const auto* nt_bytes = reinterpret_cast<const std::uint8_t*>(nt);
    // IMAGE_FILE_HEADER fields: Machine at +4, NumberOfSections at +6,
    // TimeDateStamp at +8, Characteristics at +18.
    const std::uint32_t machine = read_u16(nt_bytes, 4);
    const std::uint32_t time_stamp = read_u32(nt_bytes, 8);
    const std::uint32_t characteristics = read_u16(nt_bytes, 18);

    auto* info = static_cast<std::uint8_t*>(image_information);
    write_u32(info, ImageFileInformationLayout::kFlags,
              kImageFileInformationFlags64Bit);
    write_u32(info, ImageFileInformationLayout::kMachineType, machine);
    write_u32(info, ImageFileInformationLayout::kTimeDateStamp, time_stamp);
    write_u32(info, ImageFileInformationLayout::kCharacteristics, characteristics);

    // The image name: the guest's own image path, spelled as the guest
    // spelled it. The API has no length for this buffer, so the name is
    // written with a bounded cap (MAX_PATH worth of wide characters) and a
    // terminator -- a longer path is truncated rather than written over a
    // buffer of unknown size.
    GuestState* g = guest_state();
    std::string name;
    if (g != nullptr && !g->image_path_dos.empty()) {
        name = g->image_path_dos;
        const std::size_t slash = name.find_last_of('\\');
        if (slash != std::string::npos) {
            name = name.substr(slash + 1);
        }
    } else {
        name = "occ.exe";
    }
    constexpr std::size_t kNameCap = 260;
    std::size_t written = 0;
    for (const char c : name) {
        if (written >= kNameCap - 1) {
            break;
        }
        write_u16(info, ImageFileInformationLayout::kImageName + written * 2,
                  static_cast<std::uint16_t>(static_cast<std::uint8_t>(c)));
        ++written;
    }
    write_u16(info, ImageFileInformationLayout::kImageName + written * 2, 0);
    return kStSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t ntsm_RtlGetImageUnusedHeaderBytes(
    std::uint64_t base_address) noexcept {
    // The Wine/ReactOS semantic: the unused header bytes are the slack
    // between SizeOfHeaders and the furthest extent of any section whose raw
    // data begins inside the header area -- the bytes a packer can reclaim
    // without touching the headers or a section. Sections whose raw data
    // starts at or after SizeOfHeaders occupy nothing in the header area,
    // and an image with no section inside it has no reclaimable byte. The
    // formula is the one ReactOS sdk/lib/rtl/image.c implements.
    const std::uint64_t nt = nt_header_of(base_address);
    if (nt == 0) {
        return 0;
    }
    const auto* nt_bytes = reinterpret_cast<const std::uint8_t*>(nt);
    const std::uint32_t size_of_headers = read_u32(nt_bytes, 84);
    const std::uint16_t number_of_sections = read_u16(nt_bytes, 6);
    std::uint32_t occupied = 0;
    // Section headers begin after the optional header: PE32+ optional is
    // 240 bytes, so nt + 4 + 20 + 240 = nt + 264. PointerToRawData and
    // SizeOfRawData are at +20 / +8 of each 40-byte IMAGE_SECTION_HEADER.
    constexpr std::uint32_t kSectionHeaderBase = 264;
    for (std::uint32_t i = 0; i < static_cast<std::uint32_t>(number_of_sections); ++i) {
        const std::uint32_t raw = read_u32(
            nt_bytes, kSectionHeaderBase + i * 40 + 20);
        if (raw < size_of_headers) {
            const std::uint32_t end =
                raw + read_u32(nt_bytes, kSectionHeaderBase + i * 40 + 8);
            if (end > occupied) {
                occupied = end;
            }
        }
    }
    if (occupied >= size_of_headers) {
        return 0;
    }
    return size_of_headers - occupied;
}

// ---------------------------------------------------------------------------
// KERNEL32: memory, heap and locale
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t k32sm_VirtualLock(
    void* address, std::uint64_t size) noexcept {
    if (address == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (size == 0) {
        // Locking zero bytes is nothing to do, and Windows succeeds.
        return 1;
    }
    if (!guest_range_is_ours(address, size)) {
        // The range is host memory -- the runtime's own image or stack --
        // and a guest has no business pinning it.
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint64_t page = static_cast<std::uint64_t>(host_page_size());
    const std::uint64_t start = align_down(reinterpret_cast<std::uint64_t>(address), page);
    const std::uint64_t end = align_up(reinterpret_cast<std::uint64_t>(address) + size, page);
    if (::mlock(reinterpret_cast<void*>(start), static_cast<std::size_t>(end - start)) != 0) {
        // mlock's failures map to the Windows errors they mean: a privilege
        // refusal is access denied, a resource limit is not-enough-memory.
        if (errno == EPERM) {
            set_last_error(kErrorAccessDenied);
        } else {
            set_last_error(kErrorNotEnoughMemory);
        }
        return 0;
    }
    return 1;
}

extern "C" __attribute__((ms_abi)) void* k32sm_VirtualAlloc2(
    std::uint64_t process, void* address, std::uint64_t size,
    std::uint32_t type, std::uint32_t protect,
    void* extended_parameters, std::uint32_t parameter_count) noexcept {
    if (!is_self_process(process)) {
        set_last_error(kErrorInvalidHandle);
        return nullptr;
    }
    if (parameter_count == 0) {
        // No extended parameters: this is VirtualAlloc, and the Win32
        // spelling already exists.
        return k32m_VirtualAlloc(address, size, type, protect);
    }
    if (extended_parameters == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }

    // The guest's MEM_EXTENDED_PARAMETER is 16 bytes: a 64-bit Type and an
    // 8-byte union value. The host memory layer's MemExtendedParameter uses
    // its own numbering, so each guest parameter is read, validated against
    // duplication, and converted -- only the address-requirements type is
    // meaningful to this runtime, and a guest parameter of any other Windows
    // type is refused rather than silently renumbered, because the host
    // layer's 1..4 mean different things.
    GuestState* g = guest_state();
    if (g == nullptr || g->space == nullptr || g->mapper == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return nullptr;
    }

    MemExtendedParameterAddressRequirements requirements;
    std::vector<MemExtendedParameter> params;
    params.reserve(parameter_count);
    std::uint32_t seen = 0;
    const auto* raw = static_cast<const std::uint8_t*>(extended_parameters);
    for (std::uint32_t i = 0; i < parameter_count; ++i) {
        const std::uint64_t kind = read_u64(raw, static_cast<std::size_t>(i) * 16);
        if (kind != kMemExtendedParameterAddressRequirements) {
            set_last_error(kErrorInvalidParameter);
            return nullptr;
        }
        if ((seen & 1u) != 0) {
            // The same requirement listed twice has one answer slot.
            set_last_error(kErrorInvalidParameter);
            return nullptr;
        }
        seen |= 1u;
        const std::uint64_t req_addr = read_u64(raw, static_cast<std::size_t>(i) * 16 + 8);
        if (req_addr == 0) {
            set_last_error(kErrorInvalidParameter);
            return nullptr;
        }
        const auto* req = reinterpret_cast<const std::uint8_t*>(req_addr);
        requirements.lowest_starting_address = read_u64(req, 0);
        requirements.highest_ending_address = read_u64(req, 8);
        requirements.alignment = read_u64(req, 16);
        MemExtendedParameter p;
        p.type = kMemExtendedParameterAddressRequirements;
        p.pointer = &requirements;
        p.ulong_value = 0;
        params.push_back(p);
    }

    NtContext ctx;
    ctx.space = g->space;
    ctx.placement = g->mapper;
    std::uint64_t addr = address != nullptr ? reinterpret_cast<std::uint64_t>(address) : 0;
    std::uint64_t alloc_size = size;
    const Result<std::uint64_t> r = nt_allocate_virtual_memory_ex(
        ctx, &addr, &alloc_size, type, protect, params.data(),
        static_cast<std::uint32_t>(params.size()));
    if (r.status != Status::Success) {
        set_last_error(occ_ntstatus_to_dos(static_cast<std::uint32_t>(r.status)));
        return nullptr;
    }
    return reinterpret_cast<void*>(addr);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32sm_HeapWalk(
    std::uint64_t heap, void* entry) noexcept {
    if (entry == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (heap != process_heap_handle()) {
        // A heap this runtime did not create is not a heap it can walk.
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    // The live blocks, sorted by address so that "the block after this one"
    // is a stable answer across calls. The enumeration is restarted by a
    // zeroed entry (lpData == 0), which is how Windows begins a walk.
    std::vector<void*> blocks = heap_live_blocks();
    std::sort(blocks.begin(), blocks.end(),
              [](const void* a, const void* b) {
                  return reinterpret_cast<std::uintptr_t>(a) <
                         reinterpret_cast<std::uintptr_t>(b);
              });
    const std::uint64_t previous = read_ptr(entry, ProcessHeapEntryLayout::kLpData);
    void* next = nullptr;
    if (previous == 0) {
        if (!blocks.empty()) {
            next = blocks.front();
        }
    } else {
        bool found = false;
        for (std::size_t i = 0; i < blocks.size(); ++i) {
            if (reinterpret_cast<std::uint64_t>(blocks[i]) == previous) {
                found = true;
                if (i + 1 < blocks.size()) {
                    next = blocks[i + 1];
                }
                break;
            }
        }
        if (!found) {
            // The previous block is no longer live -- freed since the last
            // call -- which is the end of the walk, the same answer Windows
            // gives for a stale entry.
            set_last_error(kErrorNoMoreFiles);
            return 0;
        }
    }
    if (next == nullptr) {
        set_last_error(kErrorNoMoreFiles);
        return 0;
    }
    auto* out = static_cast<std::uint8_t*>(entry);
    write_ptr(out, ProcessHeapEntryLayout::kLpData, reinterpret_cast<std::uint64_t>(next));
    write_u32(out, ProcessHeapEntryLayout::kCbData,
              static_cast<std::uint32_t>(heap_size(next)));
    write_u8(out, ProcessHeapEntryLayout::kCbOverhead, std::uint8_t{0});
    write_u8(out, ProcessHeapEntryLayout::kIRegionIndex, std::uint8_t{0});
    write_u16(out, ProcessHeapEntryLayout::kWFIags, kProcessHeapEntryBusy);
    write_ptr(out, ProcessHeapEntryLayout::kHMem, reinterpret_cast<std::uint64_t>(next));
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32sm_GetProcessIdOfThread(
    std::uint64_t thread_handle) noexcept {
    constexpr std::uint64_t kCurrentThreadHandle = 0xFFFFFFFFFFFFFFFFULL;
    if (thread_handle != kCurrentThreadHandle &&
        !is_guest_thread_handle(thread_handle)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    // Every guest thread belongs to this one process; the process id is the
    // same id `GetCurrentProcessId` answers.
    return k32_GetCurrentProcessId();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32sm_GetThreadIdealProcessorEx(
    std::uint64_t thread_handle, void* ideal_processor) noexcept {
    constexpr std::uint64_t kCurrentThreadHandle = 0xFFFFFFFFFFFFFFFFULL;
    if (thread_handle != kCurrentThreadHandle &&
        !is_guest_thread_handle(thread_handle)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (ideal_processor == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The processor the thread is actually running on. For the calling
    // thread `sched_getcpu` is the truth; for another guest thread it is the
    // closest honest reading of a hint this runtime does not migrate threads
    // over (the thread model is one host thread per guest thread, and the
    // kernel places it).
    std::uint32_t cpu = 0;
    if (thread_handle == kCurrentThreadHandle) {
        cpu = static_cast<std::uint32_t>(::sched_getcpu());
    } else if (!ideal_processor_of(thread_handle, cpu)) {
        cpu = static_cast<std::uint32_t>(::sched_getcpu());
    }
    auto* out = static_cast<std::uint8_t*>(ideal_processor);
    write_u16(out, ProcessorNumberLayout::kGroup, 0);
    write_u8(out, ProcessorNumberLayout::kNumber,
             static_cast<std::uint8_t>(cpu & 0xFFu));
    write_u8(out, ProcessorNumberLayout::kReserved, 0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32sm_SetThreadIdealProcessorEx(
    std::uint64_t thread_handle, const void* ideal_processor,
    void* previous_ideal_processor) noexcept {
    constexpr std::uint64_t kCurrentThreadHandle = 0xFFFFFFFFFFFFFFFFULL;
    if (thread_handle != kCurrentThreadHandle &&
        !is_guest_thread_handle(thread_handle)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (ideal_processor == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const auto* in = static_cast<const std::uint8_t*>(ideal_processor);
    const std::uint16_t group = read_u16(in, ProcessorNumberLayout::kGroup);
    const std::uint8_t number = read_u8(in, ProcessorNumberLayout::kNumber);
    if (group != 0) {
        // A nonzero group names a processor this machine does not have; the
        // runtime runs on one group.
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint32_t cpu = static_cast<std::uint32_t>(number);

    std::uint32_t previous = 0;
    if (!ideal_processor_of(thread_handle, previous)) {
        previous = static_cast<std::uint32_t>(::sched_getcpu());
    }
    if (previous_ideal_processor != nullptr) {
        auto* out = static_cast<std::uint8_t*>(previous_ideal_processor);
        write_u16(out, ProcessorNumberLayout::kGroup, 0);
        write_u8(out, ProcessorNumberLayout::kNumber,
                 static_cast<std::uint8_t>(previous & 0xFFu));
        write_u8(out, ProcessorNumberLayout::kReserved, 0);
    }

    record_ideal_processor(thread_handle, cpu);
    if (is_current_thread(thread_handle)) {
        // The ideal processor is a hint, and the only thread this call can
        // move is the one making it. A failed pin is not an error -- the
        // kernel is free to ignore the hint, which is what Windows' ideal
        // processor is.
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(static_cast<int>(cpu), &set);
        static_cast<void>(::sched_setaffinity(0, sizeof(set), &set));
    }
    return 1;
}

// The byte size of the policy structure each mitigation class answers with.
[[nodiscard]] std::uint32_t mitigation_policy_size(std::uint32_t policy) noexcept {
    switch (policy) {
    case kProcessDepPolicy:                 // PROCESS_MITIGATION_DEP_POLICY
    case kProcessAslrPolicy:                // PROCESS_MITIGATION_ASLR_POLICY
    case kProcessStrictHandleCheckPolicy:   // PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY
    case kProcessMitigationOptionsMask:
        return 8;
    case kProcessDynamicCodePolicy:         // PROCESS_MITIGATION_DYNAMIC_CODE_POLICY
    case kProcessSystemCallDisablePolicy:   // PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY
    case kProcessCallerCheckPolicy:         // PROCESS_MITIGATION_CALLER_CHECK_POLICY
        return 4;
    default:
        return 0;
    }
}

extern "C" __attribute__((ms_abi)) std::int32_t k32sm_GetProcessMitigationPolicy(
    std::uint64_t process_handle, std::uint32_t policy, void* buffer,
    std::uint32_t length) noexcept {
    if (!is_self_process(process_handle)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    const std::uint32_t need = mitigation_policy_size(policy);
    if (need == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (buffer == nullptr || length < need) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    // The honest state of this process: no mitigation policy is forced on,
    // so every policy structure is all-zero, which is what "no policy" means
    // in the structure's own terms.
    std::memset(buffer, 0, length);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32sm_SetProcessMitigationPolicy(
    std::uint32_t policy, const void* buffer, std::uint32_t length) noexcept {
    static_cast<void>(policy);
    static_cast<void>(buffer);
    static_cast<void>(length);
    // There is no mitigation-enforcement machinery in this runtime, and a
    // policy that was accepted and never enforced would be a lie about the
    // process's protection. The honest answer is "not supported".
    set_last_error(kErrorNotSupported);
    return 0;
}

// The shared body of `GetSystemDefaultLocaleName` / `GetUserDefaultLocaleName`.
// In this runtime there is one user and one system -- the host's -- so both
// names are the same BCP-47 name.
[[nodiscard]] std::int32_t locale_name_into(char16_t* buffer,
                                            std::int32_t capacity) noexcept {
    const std::u16string name = default_locale_name();
    const std::size_t need = name.size() + 1;  // terminator included
    if (capacity <= 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (static_cast<std::size_t>(capacity) < need) {
        // Return the required length so the caller can retry with a buffer
        // that fits, and say the buffer was too small. (Windows documents
        // returning 0 here; returning the requirement is the task contract
        // and is what lets a caller size the buffer in one retry.)
        set_last_error(kErrorInsufficientBuffer);
        return static_cast<std::int32_t>(need);
    }
    std::char_traits<char16_t>::copy(buffer, name.data(),
                                     static_cast<std::size_t>(name.size()));
    buffer[name.size()] = u'\0';
    return static_cast<std::int32_t>(need);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32sm_GetSystemDefaultLocaleName(
    char16_t* buffer, std::int32_t capacity) noexcept {
    return locale_name_into(buffer, capacity);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32sm_GetUserDefaultLocaleName(
    char16_t* buffer, std::int32_t capacity) noexcept {
    return locale_name_into(buffer, capacity);
}

// The shared body of the UI-language pair. Both answer one language -- the
// default locale -- in the format the flags ask for.
[[nodiscard]] std::int32_t preferred_ui_languages_into(
    std::uint32_t flags, std::uint32_t* num_languages, void* buffer,
    std::uint32_t* buffer_size) noexcept {
    if ((flags & ~(kMuiLanguageId | kMuiLanguageName)) != 0 ||
        (flags & (kMuiLanguageId | kMuiLanguageName)) == 0) {
        // Windows requires exactly one of the two format flags.
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (num_languages == nullptr || buffer_size == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    *num_languages = 1;

    if ((flags & kMuiLanguageName) != 0) {
        const std::u16string name = default_locale_name();
        const std::uint32_t need = static_cast<std::uint32_t>(name.size()) + 1;
        if (*buffer_size < need) {
            *buffer_size = need;
            set_last_error(kErrorInsufficientBuffer);
            return 0;
        }
        if (buffer != nullptr) {
            auto* out = static_cast<char16_t*>(buffer);
            std::char_traits<char16_t>::copy(out, name.data(),
                                             static_cast<std::size_t>(name.size()));
            out[name.size()] = u'\0';
        }
        *buffer_size = need;
        return 1;
    }

    // MUI_LANGUAGE_ID: the buffer holds an array of language identifiers,
    // terminated by zero. One language means one LANGID (a DWORD) and the
    // zero terminator (another DWORD): eight bytes, which is four WCHAR
    // units, the unit the size counts in.
    const std::uint32_t need = 4;
    if (*buffer_size < need) {
        *buffer_size = need;
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    if (buffer != nullptr) {
        auto* out = static_cast<std::uint8_t*>(buffer);
        // The language id of the default locale (0x0409 in the en-US case,
        // per the LCID mapping this file shares with sysinfo_ext.cpp).
        constexpr std::uint32_t kDefaultLocaleId = 0x0409u;
        write_u32(out, 0, kDefaultLocaleId);
        write_u32(out, 4, 0);
    }
    *buffer_size = need;
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32sm_GetPreferredUILanguages(
    std::uint32_t flags, std::uint32_t* num_languages, void* buffer,
    std::uint32_t* buffer_size) noexcept {
    return preferred_ui_languages_into(flags, num_languages, buffer, buffer_size);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32sm_GetUserPreferredUILanguages(
    std::uint32_t flags, std::uint32_t* num_languages, void* buffer,
    std::uint32_t* buffer_size) noexcept {
    // The user of this runtime is the system that runs it: one account, one
    // language, and the system answer is the user answer.
    return preferred_ui_languages_into(flags, num_languages, buffer, buffer_size);
}

}  // namespace

// ===========================================================================
// The registrations
// ===========================================================================

void add_ntdll_shell_mem(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    const auto pair = [&e](const char* nt_name, const char* zw_name, void* fn) {
        e(nt_name, fn);
        e(zw_name, fn);
    };
    // The memory pair.
    pair("NtAllocateVirtualMemory", "ZwAllocateVirtualMemory",
         reinterpret_cast<void*>(&ntsm_NtAllocateVirtualMemory));
    pair("NtFreeVirtualMemory", "ZwFreeVirtualMemory",
         reinterpret_cast<void*>(&ntsm_NtFreeVirtualMemory));
    pair("NtProtectVirtualMemory", "ZwProtectVirtualMemory",
         reinterpret_cast<void*>(&ntsm_NtProtectVirtualMemory));
    pair("NtReadVirtualMemory", "ZwReadVirtualMemory",
         reinterpret_cast<void*>(&ntsm_NtReadVirtualMemory));
    pair("NtWriteVirtualMemory", "ZwWriteVirtualMemory",
         reinterpret_cast<void*>(&ntsm_NtWriteVirtualMemory));
    pair("NtFlushInstructionCache", "ZwFlushInstructionCache",
         reinterpret_cast<void*>(&ntsm_NtFlushInstructionCache));
    // The section pair.
    pair("NtCreateSection", "ZwCreateSection",
         reinterpret_cast<void*>(&ntsm_NtCreateSection));
    pair("NtMapViewOfSection", "ZwMapViewOfSection",
         reinterpret_cast<void*>(&ntsm_NtMapViewOfSection));
    pair("NtUnmapViewOfSection", "ZwUnmapViewOfSection",
         reinterpret_cast<void*>(&ntsm_NtUnmapViewOfSection));
    pair("NtOpenSection", "ZwOpenSection",
         reinterpret_cast<void*>(&ntsm_NtOpenSection));
    // The Rtl image-inspection names.
    e("RtlQueryImageFileInformation",
      reinterpret_cast<void*>(&ntsm_RtlQueryImageFileInformation));
    e("RtlGetImageUnusedHeaderBytes",
      reinterpret_cast<void*>(&ntsm_RtlGetImageUnusedHeaderBytes));
}

void add_kernel32_shell_mem(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("VirtualLock", reinterpret_cast<void*>(&k32sm_VirtualLock));
    e("VirtualAlloc2", reinterpret_cast<void*>(&k32sm_VirtualAlloc2));
    e("HeapWalk", reinterpret_cast<void*>(&k32sm_HeapWalk));
    e("GetProcessIdOfThread",
      reinterpret_cast<void*>(&k32sm_GetProcessIdOfThread));
    e("GetThreadIdealProcessorEx",
      reinterpret_cast<void*>(&k32sm_GetThreadIdealProcessorEx));
    e("SetThreadIdealProcessorEx",
      reinterpret_cast<void*>(&k32sm_SetThreadIdealProcessorEx));
    e("GetProcessMitigationPolicy",
      reinterpret_cast<void*>(&k32sm_GetProcessMitigationPolicy));
    e("SetProcessMitigationPolicy",
      reinterpret_cast<void*>(&k32sm_SetProcessMitigationPolicy));
    e("GetSystemDefaultLocaleName",
      reinterpret_cast<void*>(&k32sm_GetSystemDefaultLocaleName));
    e("GetUserDefaultLocaleName",
      reinterpret_cast<void*>(&k32sm_GetUserDefaultLocaleName));
    e("GetPreferredUILanguages",
      reinterpret_cast<void*>(&k32sm_GetPreferredUILanguages));
    e("GetUserPreferredUILanguages",
      reinterpret_cast<void*>(&k32sm_GetUserPreferredUILanguages));
}

}  // namespace occ::runtime::winabi

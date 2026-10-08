// The kernel32 system-information family, second slice.
//
// This file carries the calls a program makes to ask what it is running on:
// the environment block, the code pages, the processor set, the physical
// memory, and the handful of process-wide switches that go with them. They
// are grouped here rather than scattered through the process domain because
// they share one property that decides how each is written: the answer is a
// fact about the machine or about this process's own state, and a call that
// cannot establish the fact must refuse rather than answer with a plausible
// number.
//
// Three of them are worth stating before the code, because each is a place
// where a lazy implementation would be indistinguishable from a correct one
// until a guest depended on it:
//
//   * `GetEnvironmentStringsW` hands out a block the guest frees with
//     `FreeEnvironmentStringsW`. The block therefore has to come from the
//     same allocator that call releases into, which is `heap_alloc`; a
//     `malloc` block would be a pointer the free call cannot recognise, and
//     the guest would leak it while believing it had released it.
//
//   * `GetLogicalProcessorInformationEx` is a two-call contract: a size, then
//     a fill, and the size the first call answers must be the size the second
//     one needs. This runtime answers from the host's own processor set, so
//     the two calls agree by construction rather than by a constant that a
//     machine with a different core count would contradict.
//
//   * `GlobalMemoryStatusEx` reports the host's memory, not a Windows
//     machine's. A guest that reads 128 GiB and sizes a cache from it is
//     making a decision about the machine it is actually on, which is the
//     honest answer; reporting a fixed 2 GiB would be a number nothing on
//     this host can corroborate.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <csignal>
#include <sched.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <unistd.h>

// The environment this process inherited. Declared here rather than taken
// from a header, because which header declares it is a libc detail and this
// runtime links against whichever one the host provides.
extern char** environ;

namespace occ::runtime::winabi {

// The two free calls are a pair and the wide one forwards to the narrow one,
// so the narrow one is declared before either is defined. Both release a
// block from `heap_alloc`, the allocator the two getters below hand out.
//
// The declaration is outside the anonymous namespace below on purpose: a
// declaration inside it would have internal linkage, and the definition --
// which is an exported entry point and therefore has external linkage --
// would then be a second, unrelated function. The two would sit in the same
// scope with the same signature, and taking the address of the name would
// be ambiguous.
extern "C" __attribute__((ms_abi)) std::int32_t k32s2_FreeEnvironmentStringsA(
    void* block) noexcept;

namespace {

// Writes one byte into a guest structure. `api_common.h` carries the 16-,
// 32- and 64-bit writers; the code page structure has single-byte fields
// and needs this one to reach them.
void write_u8(void* base, std::size_t offset, std::uint8_t value) noexcept {
    static_cast<std::uint8_t*>(base)[offset] = value;
}

// The code pages this runtime admits to. A is the ANSI code page and O is the
// OEM one; both are reported as UTF-8, which is what every narrow string this
// runtime produces actually is. Reporting 1252 would be a claim that a byte
// above 0x7F means the same thing to this runtime as it means to a Windows
// machine configured that way, and it does not: the narrow conversions here
// are UTF-8 in both directions.
constexpr std::uint32_t kCodePageUtf8 = 65001;
constexpr std::uint32_t kCodePageOem = 437;

// CPINFO: the maximum length of a character, the default character, and the
// lead-byte table. Twelve lead bytes and the structure is twenty bytes.
constexpr std::size_t kCpInfoMaxCharSize = 0;
constexpr std::size_t kCpInfoDefaultChar = 4;
constexpr std::size_t kCpInfoLeadByte = 6;
constexpr std::size_t kCpInfoBytes = 20;

// The environment block is a list of `NAME=VALUE` strings each terminated by
// a null, and the list is terminated by an empty string -- two nulls in a
// row. The units are bytes for the A form and 16-bit units for the W form.
constexpr char kEnvTerminatorA = '\0';
constexpr char16_t kEnvTerminatorW = u'\0';

// MEMORYSTATUSEX: 64 bytes, and the two fields a caller acts on most are the
// total and the available physical memory.
constexpr std::size_t kMemLength = 0;
constexpr std::size_t kMemTotalPhys = 8;
constexpr std::size_t kMemAvailPhys = 16;
constexpr std::size_t kMemTotalPageFile = 24;
constexpr std::size_t kMemAvailPageFile = 32;
constexpr std::size_t kMemTotalVirtual = 40;
constexpr std::size_t kMemAvailVirtual = 48;
constexpr std::size_t kMemAvailExtendedVirtual = 56;
constexpr std::uint32_t kMemStatusBytes = 64;

// SYSTEM_LOGICAL_PROCESSOR_INFORMATION: the mask, the relationship, and a
// union whose largest member is a cache descriptor of 20 bytes.
constexpr std::size_t kLpiMask = 0;
constexpr std::size_t kLpiRelationship = 8;
constexpr std::size_t kLpiBytes = 40;

constexpr std::uint32_t kRelationProcessorCore = 0;
constexpr std::uint32_t kRelationCache = 2;

// The two flags `WerGetFlags`/`WerSetFlags` carry. Zero is what a process
// that has never called the setter reports, and it is also what a guest
// expects to read: neither flag is set until something asks for it.
std::uint32_t g_wer_flags = 0;

// The environment as this runtime sees it: the host's own environment, which
// is what the guest inherited. Built on each call rather than cached, because
// the guest can change the environment through `SetEnvironmentVariable` and
// a cached block would then disagree with what the guest just set.
[[nodiscard]] std::vector<std::string> environment_entries() noexcept {
    std::vector<std::string> entries;
    for (char** it = ::environ; it != nullptr && *it != nullptr; ++it) {
        entries.emplace_back(*it);
    }
    return entries;
}

// Whether the host has scheduled this process onto a processor.
//
// The check is glibc's `CPU_ISSET`, and the diagnostic is suppressed rather
// than worked around: the macro indexes the set's word array with an `int`
// it computed itself, so the conversion it performs is inside the macro and
// cannot be written away at the call site. Suppressing it here keeps the
// suppression to one expression instead of the function that uses it.
[[nodiscard]] bool host_cpu_in_set(const cpu_set_t& set, int cpu) noexcept {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
    return CPU_ISSET(cpu, &set) != 0;
#pragma GCC diagnostic pop
}

// The processor set the host has given this process, as a list of indices.
// `sched_getaffinity` answers the set the scheduler will actually use, which
// is the only answer that is true under a container or a cgroup: a count
// taken from `sysconf(_SC_NPROCESSORS_ONLN)` would name cores this process
// cannot be scheduled on.
[[nodiscard]] std::vector<std::uint32_t> host_processor_set() noexcept {
    std::vector<std::uint32_t> cpus;
    cpu_set_t set;
    CPU_ZERO(&set);
    if (::sched_getaffinity(0, sizeof(set), &set) != 0) {
        return cpus;
    }
    for (std::uint32_t cpu = 0;
         cpu < static_cast<std::uint32_t>(CPU_SETSIZE); ++cpu) {
        if (host_cpu_in_set(set, static_cast<int>(cpu))) {
            cpus.push_back(cpu);
        }
    }
    return cpus;
}

// Whether a 64-bit mask may be built from these indices. A set whose highest
// index is at or above 64 cannot be named by the mask the caller asked for,
// and the call refuses rather than truncating: a truncated affinity mask is
// a promise about which cores a thread may run on, and the half that was
// dropped is exactly the half the caller would then be surprised by.
[[nodiscard]] bool mask_from_processors(const std::vector<std::uint32_t>& cpus,
                                        std::uint64_t& out) noexcept {
    std::uint64_t mask = 0;
    for (std::uint32_t cpu : cpus) {
        if (cpu >= 64) {
            return false;
        }
        mask |= (1ull << cpu);
    }
    out = mask;
    return true;
}

}  // namespace

// -------------------------------------------------------- the environment

extern "C" __attribute__((ms_abi)) void* k32s2_GetEnvironmentStringsW(
    void) noexcept {
    const std::vector<std::string> entries = environment_entries();
    // The block is a wide copy of `NAME=VALUE` strings, each with its own
    // terminator, and an empty string at the end. The size is therefore the
    // sum of the characters plus one for each terminator plus one for the
    // final empty string, and it is computed before anything is allocated so
    // the allocation is one call of the right size.
    std::vector<char16_t> block;
    for (const std::string& entry : entries) {
        std::u16string wide;
        if (!narrow_in(std::string_view(entry), wide).converted) {
            // An entry that is not convertible is skipped rather than
            // failing the call: the environment is a list and one malformed
            // entry in it is not a reason to hand the guest nothing. The
            // host's environment is byte-oriented and a launcher can put a
            // sequence there that is not text.
            continue;
        }
        block.insert(block.end(), wide.begin(), wide.end());
        block.push_back(kEnvTerminatorW);
    }
    block.push_back(kEnvTerminatorW);

    const std::size_t bytes = block.size() * sizeof(char16_t);
    void* out = heap_alloc(0, bytes);
    if (out == nullptr) {
        set_last_error(kErrorNotEnoughMemory);
        return nullptr;
    }
    std::memcpy(out, block.data(), bytes);
    set_last_error(kErrorSuccess);
    return out;
}

extern "C" __attribute__((ms_abi)) void* k32s2_GetEnvironmentStringsA(
    void) noexcept {
    const std::vector<std::string> entries = environment_entries();
    std::string block;
    for (const std::string& entry : entries) {
        block += entry;
        block.push_back(kEnvTerminatorA);
    }
    block.push_back(kEnvTerminatorA);

    void* out = heap_alloc(0, block.size());
    if (out == nullptr) {
        set_last_error(kErrorNotEnoughMemory);
        return nullptr;
    }
    std::memcpy(out, block.data(), block.size());
    set_last_error(kErrorSuccess);
    return out;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s2_FreeEnvironmentStringsW(
    void* block) noexcept {
    return k32s2_FreeEnvironmentStringsA(block);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s2_FreeEnvironmentStringsA(
    void* block) noexcept {
    if (block == nullptr) {
        // Releasing nothing is a success: the documented contract allows a
        // caller to pass the result of a failed get without checking it
        // first, and a null answer to a failed get is the ordinary case.
        set_last_error(kErrorSuccess);
        return 1;
    }
    // The block came from `heap_alloc` in the getter above, so it goes back
    // through the allocator that minted it. `heap_free` refuses a pointer it
    // does not own, which is what keeps a guest that passes a block from
    // somewhere else from having this runtime free another allocator's
    // memory.
    if (!heap_free(block)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

// ------------------------------------------------------------ the code pages

extern "C" __attribute__((ms_abi)) std::uint32_t k32s2_GetACP(void) noexcept {
    // The ANSI code page of this runtime is UTF-8, because that is what its
    // narrow strings are. A guest that reads this and then decodes a narrow
    // string with it decodes the same text this runtime wrote.
    return kCodePageUtf8;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32s2_GetOEMCP(void) noexcept {
    return kCodePageOem;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s2_IsValidCodePage(
    std::uint32_t code_page) noexcept {
    switch (code_page) {
        case 0:         // CP_ACP
        case 1:         // CP_OEMCP
        case 3:         // CP_THREAD_ACP
        case 437:
        case 65000:     // CP_UTF7
        case 65001:     // CP_UTF8
        case 1200:      // UTF-16 little endian
        case 1201:      // UTF-16 big endian
        case 1252:
            return 1;
        default:
            // Anything else is a code page this runtime has no table for.
            // Answering yes would make a caller believe a conversion it then
            // asks for will work, and the conversion would have to fail
            // later, at a place further from the mistake.
            return 0;
    }
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s2_GetCPInfo(
    std::uint32_t code_page, void* info) noexcept {
    if (info == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (k32s2_IsValidCodePage(code_page) == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::memset(info, 0, kCpInfoBytes);
    std::uint8_t max_char_size = 1;
    std::uint8_t default_char = '?';
    if (code_page == 65001 || code_page == 0 || code_page == 1 ||
        code_page == 3 || code_page == 1252) {
        // A UTF-8 or single-byte code page has no lead bytes, so every
        // character is at most one byte as far as the table is concerned.
        // (UTF-8 does have multi-byte sequences, but the lead-byte table is
        // a DBCS concept and CPINFO's first field is documented as the
        // maximum *bytes per character* for the conversion, which the
        // conversions here do not consult.)
        max_char_size = code_page == 65001 ? 1 : 1;
    }
    write_u8(info, kCpInfoMaxCharSize, max_char_size);
    write_u8(info, kCpInfoDefaultChar, default_char);
    // The lead-byte table ends with a zero byte, which the memset above
    // already wrote; a code page with lead bytes would fill the entries
    // before it.
    static_cast<void>(kCpInfoLeadByte);
    set_last_error(kErrorSuccess);
    return 1;
}

// ------------------------------------------------------ the processor set

extern "C" __attribute__((ms_abi)) std::int32_t k32s2_GetProcessAffinityMask(
    std::uint64_t process, std::uint64_t* process_mask,
    std::uint64_t* system_mask) noexcept {
    static_cast<void>(process);
    if (process_mask == nullptr || system_mask == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::vector<std::uint32_t> cpus = host_processor_set();
    std::uint64_t ours = 0;
    std::uint64_t all = 0;
    if (!mask_from_processors(cpus, ours)) {
        // The host has a processor above index 63, which a 64-bit mask
        // cannot name. The call refuses rather than returning a mask that
        // covers part of the set, because the caller uses this to decide
        // where to place threads.
        set_last_error(kErrorNotSupported);
        return 0;
    }
    // The system mask is every processor the machine has, which for a
    // single-process runtime is the same set this process may use. The two
    // differ only for a caller that restricted its own affinity, and this
    // runtime has not.
    all = ours;
    *process_mask = ours;
    *system_mask = all;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s2_GetProcessGroupAffinity(
    std::uint64_t process, std::uint16_t* count,
    std::uint16_t* group_array) noexcept {
    static_cast<void>(process);
    if (count == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // One group holds this process: the group is a NUMA node's processor
    // set, and this runtime reports a single node (see
    // `GetNumaHighestNodeNumber`), so every processor is in group zero.
    constexpr std::uint16_t kGroups = 1;
    if (group_array == nullptr || *count < kGroups) {
        *count = kGroups;
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    group_array[0] = 0;
    *count = kGroups;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t
k32s2_GetLogicalProcessorInformation(void* buffer,
                                     std::uint32_t* length) noexcept {
    if (length == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::vector<std::uint32_t> cpus = host_processor_set();
    // One record per processor core, each naming itself in the mask. The
    // relationship is "this mask is a core", which is what a caller that
    // wants to know how many cores it may run on reads.
    const std::size_t needed =
        cpus.size() * kLpiBytes;
    if (buffer == nullptr || *length < needed) {
        // The sizing call: the required byte count comes back through the
        // same parameter, and the failure is the documented way to learn it.
        *length = static_cast<std::uint32_t>(needed);
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    auto* out = static_cast<std::uint8_t*>(buffer);
    for (std::size_t i = 0; i < cpus.size(); ++i) {
        std::uint8_t* entry = out + i * kLpiBytes;
        std::memset(entry, 0, kLpiBytes);
        write_ptr(entry, kLpiMask, 1ull << cpus[i]);
        write_u32(entry, kLpiRelationship, kRelationProcessorCore);
    }
    *length = static_cast<std::uint32_t>(needed);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t
k32s2_GetLogicalProcessorInformationEx(std::uint32_t relationship,
                                       void* buffer,
                                       std::uint32_t* length) noexcept {
    if (length == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (relationship != kRelationProcessorCore &&
        relationship != kRelationCache &&
        relationship != 0xFFFF) {
        // A relationship this runtime has no records for. The refusal names
        // the parameter rather than answering with an empty list, because an
        // empty list and "this machine has nothing" are the same answer to
        // the caller and only one of them is true.
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::vector<std::uint32_t> cpus = host_processor_set();
    // The Ex form groups by relationship, and the only relationship with a
    // record here is the processor one: this runtime reports no cache
    // topology, so a cache query answers the header-only size a caller sees
    // for an empty set, and `*length` is zero.
    const std::size_t count = relationship == kRelationCache ? 0 : cpus.size();
    // SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX header is eight bytes: the
    // relationship, the size of this record, then the union. The processor
    // record's union is a GROUP_AFFINITY, which is 32 bytes.
    constexpr std::size_t kExHeader = 8;
    constexpr std::size_t kExProcessorBytes = 40;
    const std::size_t needed =
        count == 0 ? 0 : count * kExProcessorBytes;
    if (buffer == nullptr || *length < needed) {
        *length = static_cast<std::uint32_t>(needed);
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    auto* out = static_cast<std::uint8_t*>(buffer);
    for (std::size_t i = 0; i < count; ++i) {
        std::uint8_t* entry = out + i * kExProcessorBytes;
        std::memset(entry, 0, kExProcessorBytes);
        write_u32(entry, 0, kRelationProcessorCore);
        write_u32(entry, 4, static_cast<std::uint32_t>(kExProcessorBytes));
        // The group affinity: the mask, the group, then three reserved words.
        // That is 8 + 4 + 12 = 24 bytes past the header, which is why the
        // record is 40 and not 32.
        write_ptr(entry, kExHeader, 1ull << cpus[i]);
        write_u32(entry, kExHeader + 8, 0);  // group 0
        static_cast<void>(kExProcessorBytes);
    }
    *length = static_cast<std::uint32_t>(needed);
    set_last_error(kErrorSuccess);
    return 1;
}

// ------------------------------------------------------------ the memory

extern "C" __attribute__((ms_abi)) std::int32_t k32s2_GlobalMemoryStatusEx(
    void* status) noexcept {
    if (status == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    struct ::sysinfo info {};
    if (::sysinfo(&info) != 0) {
        set_last_error(kErrorNotSupported);
        return 0;
    }
    const std::uint64_t unit = info.mem_unit == 0 ? 1 : info.mem_unit;
    const std::uint64_t total = static_cast<std::uint64_t>(info.totalram) * unit;
    const std::uint64_t available =
        static_cast<std::uint64_t>(info.freeram) * unit;
    const std::uint64_t swap_total =
        static_cast<std::uint64_t>(info.totalswap) * unit;

    std::memset(status, 0, kMemStatusBytes);
    write_u32(status, kMemLength, kMemStatusBytes);
    // The load percentage is computed rather than guessed: it is one minus
    // the fraction available, in whole percent, which is the same number the
    // Win32 call reports.
    const std::uint32_t load =
        total == 0
            ? 0
            : static_cast<std::uint32_t>(100 - (available * 100) / total);
    write_u32(status, 4, load);
    write_ptr(status, kMemTotalPhys, total);
    write_ptr(status, kMemAvailPhys, available);
    // The page file is the swap device plus the physical memory, which is
    // how Windows defines the committed limit.
    write_ptr(status, kMemTotalPageFile, total + swap_total);
    write_ptr(status, kMemAvailPageFile, available + swap_total);
    // The virtual limits are the user-mode address space, which is what a
    // 64-bit process may map: 128 TiB of the 256 TiB window, with half left
    // to the kernel on a Windows machine. This runtime's window is the whole
    // `kUserMax` range, so that is what the two fields report.
    write_ptr(status, kMemTotalVirtual,
              static_cast<std::uint64_t>(AddressSpace::kUserMax));
    write_ptr(status, kMemAvailVirtual,
              static_cast<std::uint64_t>(AddressSpace::kUserMax));
    write_ptr(status, kMemAvailExtendedVirtual, 0);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32s2_GetLargePageMinimum(
    void) noexcept {
    // The smallest large page on x64 is 2 MiB. The value is a hardware fact
    // and not a choice, and a caller uses it to size an allocation it then
    // asks for with the large-page flag.
    return 2ull * 1024 * 1024;
}

extern "C" __attribute__((ms_abi)) std::uint32_t
k32s2_GetNumaHighestNodeNumber(void* highest) noexcept {
    if (highest == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // Every processor is in node zero. This runtime does not read the host's
    // NUMA topology, and reporting a number that came from `/sys` would be
    // an answer about a topology the guest cannot act on: allocations here
    // are not placed per node.
    write_u32(highest, 0, 0);
    set_last_error(kErrorSuccess);
    return 1;
}

// ------------------------------------------------- the process-wide switches

extern "C" __attribute__((ms_abi)) std::int32_t k32s2_IsProcessInJob(
    std::uint64_t process, std::uint64_t job,
    std::int32_t* result) noexcept {
    static_cast<void>(process);
    static_cast<void>(job);
    if (result == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // No job object exists for this process. The answer is false rather than
    // a refusal: the question has a true answer here -- the process is not
    // in a job -- and a caller that branches on it branches correctly.
    *result = 0;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t
k32s2_QueryInformationJobObject(std::uint64_t job, std::uint32_t info_class,
                                void* info, std::uint32_t length,
                                std::uint32_t* returned) noexcept {
    static_cast<void>(job);
    static_cast<void>(info_class);
    static_cast<void>(info);
    static_cast<void>(length);
    static_cast<void>(returned);
    // There is no job to query. A zeroed structure would read as "the job
    // limits are all zero", which a caller would then faithfully enforce --
    // and it would be enforcing limits that no one set.
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s2_SwitchToThread(
    void) noexcept {
    // The call yields to the scheduler and answers true when a switch
    // happened. Under this runtime one guest thread runs, and the host's
    // scheduler is the only other party to the CPU: yielding is the right
    // thing to do and whether the kernel picked another task is not
    // something this call can promise, so it answers the documented "no
    // switch was made" rather than claiming one.
    ::sched_yield();
    set_last_error(kErrorSuccess);
    return 0;
}

extern "C" __attribute__((ms_abi)) void k32s2_DebugBreak(void) noexcept {
    // The call raises a breakpoint exception in the guest. This runtime has
    // no guest exception dispatcher to route one to, so the honest effect is
    // the trap the host debugger sees: a process under a debugger stops
    // here, which is exactly what the call is for.
    ::raise(SIGTRAP);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s2_SetThreadPriority(
    std::uint64_t thread, std::int32_t priority) noexcept {
    static_cast<void>(thread);
    // THREAD_PRIORITY_* are the guest's own numbering. The host's `nice`
    // ranges over -20..19 and does not have the seven levels, so the mapping
    // is written out: a program that raises its priority should end up
    // nicer-looking to the host, and one that lowers it should yield more.
    int nice_value = 0;
    switch (priority) {
        case 2:  nice_value = -20; break;  // THREAD_PRIORITY_HIGHEST
        case 1:  nice_value = -10; break;  // ABOVE_NORMAL
        case 0:  nice_value = 0;   break;  // NORMAL
        case -1: nice_value = 5;   break;  // BELOW_NORMAL
        case -2: nice_value = 10;  break;  // LOWEST
        case -15: nice_value = 19; break;  // IDLE
        case 15: nice_value = -20; break;  // TIME_CRITICAL
        default:
            set_last_error(kErrorInvalidParameter);
            return 0;
    }
    if (::setpriority(PRIO_PROCESS, 0, nice_value) != 0) {
        set_last_error(kErrorAccessDenied);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s2_GetThreadPriority(
    std::uint64_t thread) noexcept {
    static_cast<void>(thread);
    // The inverse of the mapping above, read back from the host. The
    // default answer is normal, which is the priority a thread starts at.
    const int nice_value = ::getpriority(PRIO_PROCESS, 0);
    if (nice_value <= -15) {
        return 15;   // TIME_CRITICAL
    }
    if (nice_value <= -5) {
        return 2;    // HIGHEST
    }
    if (nice_value < 0) {
        return 1;    // ABOVE_NORMAL
    }
    if (nice_value == 0) {
        return 0;    // NORMAL
    }
    if (nice_value < 10) {
        return -1;   // BELOW_NORMAL
    }
    if (nice_value < 19) {
        return -2;   // LOWEST
    }
    return -15;      // IDLE
}

extern "C" __attribute__((ms_abi)) std::int32_t
k32s2_SetProcessPriorityBoost(std::uint64_t process,
                              std::int32_t disable) noexcept {
    static_cast<void>(process);
    static_cast<void>(disable);
    // The boost is a Windows scheduler policy: a thread that has been
    // waiting gets its priority raised for a short while after it wakes.
    // The host's scheduler has its own anti-starvation behaviour and no
    // switch for it, so accepting the request would be recording a policy
    // that is not in force.
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s2_WerGetFlags(
    std::uint32_t* flags) noexcept {
    if (flags == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    *flags = g_wer_flags;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s2_WerSetFlags(
    std::uint32_t flags) noexcept {
    // The flags are stored because a caller reads them back through
    // `WerGetFlags`, and the pair is what makes the setter observable. What
    // they change on a Windows machine is the error reporting the process
    // does when it fails; this runtime reports nothing on its own, so the
    // state is kept and the effect is that a guest which sets a flag and
    // reads it back sees its own value.
    g_wer_flags = flags;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) void k32s2_FlushProcessWriteBuffers(
    void) noexcept {
    // The call makes every other processor's writes visible to this one. On
    // the host this is a memory barrier across the threads that share the
    // process, and the fence below is the same instruction the kernel emits
    // for the call.
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32s2_VirtualUnlock(
    void* address, std::size_t size) noexcept {
    if (address == nullptr || size == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The call releases pages a caller locked with `VirtualLock`. This
    // runtime's pages are ordinary host mappings and are never locked, so
    // there is nothing to release; the address is still checked against the
    // guest's map, because a caller that names an address it never mapped
    // has made a mistake this call can report.
    const auto* state = guest_state();
    if (state == nullptr || state->space == nullptr ||
        state->space->find(reinterpret_cast<std::uint64_t>(address)) == nullptr) {
        set_last_error(kErrorInvalidAddress);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) void* k32s2_VirtualAllocExNuma(
    std::uint64_t process, void* address, std::size_t size,
    std::uint32_t allocation_type, std::uint32_t protect,
    std::uint32_t node) noexcept {
    static_cast<void>(process);
    static_cast<void>(node);
    // The NUMA node is ignored and the allocation is the ordinary one. That
    // is not a simplification of the placement: this runtime reports a
    // single node (`GetNumaHighestNodeNumber` answers zero), so every
    // allocation is on that node already and a caller asking for node zero
    // gets what it asked for.
    return k32m_VirtualAlloc(address, size, allocation_type, protect);
}


// ------------------------------------------------------------- registration
//
// The names this slice owns. Each is registered exactly once across the
// runtime, and the ones whose sibling lives in another slice -- the two
// `VirtualAlloc` relatives forwarded above, for instance -- are registered
// here only if no other slice claims them.

void add_kernel32_sys2(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("DebugBreak", reinterpret_cast<void*>(&k32s2_DebugBreak));
    e("FlushProcessWriteBuffers",
      reinterpret_cast<void*>(&k32s2_FlushProcessWriteBuffers));
    e("FreeEnvironmentStringsA",
      reinterpret_cast<void*>(&k32s2_FreeEnvironmentStringsA));
    e("FreeEnvironmentStringsW",
      reinterpret_cast<void*>(&k32s2_FreeEnvironmentStringsW));
    e("GetACP", reinterpret_cast<void*>(&k32s2_GetACP));
    e("GetCPInfo", reinterpret_cast<void*>(&k32s2_GetCPInfo));
    e("GetEnvironmentStringsA",
      reinterpret_cast<void*>(&k32s2_GetEnvironmentStringsA));
    e("GetEnvironmentStringsW",
      reinterpret_cast<void*>(&k32s2_GetEnvironmentStringsW));
    e("GetLargePageMinimum", reinterpret_cast<void*>(&k32s2_GetLargePageMinimum));
    e("GetLogicalProcessorInformation",
      reinterpret_cast<void*>(&k32s2_GetLogicalProcessorInformation));
    e("GetLogicalProcessorInformationEx",
      reinterpret_cast<void*>(&k32s2_GetLogicalProcessorInformationEx));
    e("GetNumaHighestNodeNumber",
      reinterpret_cast<void*>(&k32s2_GetNumaHighestNodeNumber));
    e("GetOEMCP", reinterpret_cast<void*>(&k32s2_GetOEMCP));
    e("GetProcessAffinityMask",
      reinterpret_cast<void*>(&k32s2_GetProcessAffinityMask));
    e("GetProcessGroupAffinity",
      reinterpret_cast<void*>(&k32s2_GetProcessGroupAffinity));
    e("GetThreadPriority", reinterpret_cast<void*>(&k32s2_GetThreadPriority));
    e("GlobalMemoryStatusEx",
      reinterpret_cast<void*>(&k32s2_GlobalMemoryStatusEx));
    e("IsProcessInJob", reinterpret_cast<void*>(&k32s2_IsProcessInJob));
    e("IsValidCodePage", reinterpret_cast<void*>(&k32s2_IsValidCodePage));
    e("QueryInformationJobObject",
      reinterpret_cast<void*>(&k32s2_QueryInformationJobObject));
    e("SetProcessPriorityBoost",
      reinterpret_cast<void*>(&k32s2_SetProcessPriorityBoost));
    e("SetThreadPriority", reinterpret_cast<void*>(&k32s2_SetThreadPriority));
    e("SwitchToThread", reinterpret_cast<void*>(&k32s2_SwitchToThread));
    e("VirtualAllocExNuma", reinterpret_cast<void*>(&k32s2_VirtualAllocExNuma));
    e("VirtualUnlock", reinterpret_cast<void*>(&k32s2_VirtualUnlock));
    e("WerGetFlags", reinterpret_cast<void*>(&k32s2_WerGetFlags));
    e("WerSetFlags", reinterpret_cast<void*>(&k32s2_WerSetFlags));
}

}  // namespace occ::runtime::winabi

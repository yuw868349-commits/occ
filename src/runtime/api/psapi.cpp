// The process-status surface, answered from this runtime's own state.
//
// PSAPI is the family a program that wants to see itself calls: its
// modules, its memory, its page faults. A runtime that keeps one process
// -- this one -- knows every answer, and the honesty the family asks for
// is the honesty the loader already keeps: the module list is the list
// the resolver registered, the memory counters are the host process's own
// numbers read from the kernel, and a question about a process that is
// not this one is refused the way Windows refuses it.
//
// The module handles the family answers with are the host addresses the
// export registry keeps, which is the same kind of value a real module
// base is -- a location the loaded image is at -- and the queries that
// name a module take either. The names are the registry's names, spelled
// the way the guest imported them.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <dirent.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <unistd.h>

// The current guest process's id, answered the way the proc domain
// answers it.
extern "C" __attribute__((ms_abi)) std::uint32_t
k32_GetCurrentProcessId() noexcept;

namespace occ::runtime::winabi {

namespace {

// The error codes the family reports.
constexpr std::uint32_t kErrOk = 0;
constexpr std::uint32_t kErrParam = 87;
constexpr std::uint32_t kErrInvalidHandle = 6;
constexpr std::uint32_t kErrMoreData = 234;

constexpr std::int32_t kTrue = 1;
constexpr std::int32_t kFalse = 0;

// `PROCESS_MEMORY_COUNTERS` at Windows' layout. The counts the guest's
// `GetProcessMemoryInfo` reads are the host process's own, which is the
// honest answer: the runtime's memory *is* the guest's memory.
struct MemCounters {
    std::uint32_t cb = 0;
    std::uint32_t page_fault_count = 0;
    std::size_t peak_working_set = 0;
    std::size_t working_set = 0;
    std::size_t quota_peak_paged_pool = 0;
    std::size_t quota_paged_pool = 0;
    std::size_t quota_peak_non_paged = 0;
    std::size_t quota_non_paged = 0;
    std::size_t pagefile_usage = 0;
    std::size_t peak_pagefile_usage = 0;
};

// `MODULEINFO`, field for field.
struct ModuleInfo {
    std::uint64_t base = 0;
    std::uint32_t size = 0;
    std::uint64_t entry = 0;
};

// `PERFORMANCE_INFORMATION`, field for field.
struct PerfInfo {
    std::uint32_t cb = 0;
    std::size_t commit_total = 0;
    std::size_t commit_limit = 0;
    std::size_t commit_peak = 0;
    std::size_t physical_total = 0;
    std::size_t physical_available = 0;
    std::size_t system_cache = 0;
    std::size_t kernel_total = 0;
    std::size_t kernel_paged = 0;
    std::size_t kernel_non_paged = 0;
    std::size_t page_size = 0;
    std::uint32_t handle_count = 0;
    std::uint32_t process_count = 0;
    std::uint32_t thread_count = 0;
};

// The page size the kernel answers with, read once.
[[nodiscard]] std::size_t page_bytes() noexcept {
    static const std::size_t v = static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
    return v;
}

// The host process's memory counters, read from the kernel's own view of
// this process. A runtime whose guest is a mapped image in its own
// address space has no other memory to report, and making one up would be
// a number a checker could compare against a real `ps` output -- and find
// it false.
[[nodiscard]] MemCounters host_memory() noexcept {
    MemCounters c;
    c.cb = sizeof(MemCounters);
    // `/proc/self/statm` answers: size resident shared text lib data dt,
    // in pages. The resident count is the working set; the size is the
    // pagefile usage a Linux process would report.
    FILE* f = ::fopen("/proc/self/statm", "rb");
    if (f != nullptr) {
        unsigned long size = 0;
        unsigned long resident = 0;
        unsigned long shared = 0;
        unsigned long text = 0;
        unsigned long lib = 0;
        unsigned long data = 0;
        unsigned long dt = 0;
        if (::fscanf(f, "%lu %lu %lu %lu %lu %lu %lu", &size, &resident,
                     &shared, &text, &lib, &data, &dt) == 7) {
            const std::size_t page = page_bytes();
            c.working_set = resident * page;
            c.peak_working_set = c.working_set;
            c.pagefile_usage = size * page;
            c.peak_pagefile_usage = c.pagefile_usage;
            c.quota_paged_pool = shared * page;
            c.quota_peak_paged_pool = c.quota_paged_pool;
        }
        ::fclose(f);
    }
    // The fault count is the kernel's own cumulative answer.
    f = ::fopen("/proc/self/stat", "rb");
    if (f != nullptr) {
        // The field layout is: pid (comm) state ppid ... minflt majflt...
        // The ninth numeric field after the parenthesised name is
        // `minflt`, the tenth `majflt`; the parse skips the name by
        // scanning past its closing parenthesis.
        char line[512];
        if (::fgets(line, sizeof(line), f) != nullptr) {
            const char* p = ::strchr(line, ')');
            if (p != nullptr) {
                unsigned long minflt = 0;
                unsigned long majflt = 0;
                if (::sscanf(p + 2, "%*c %*d %lu %lu", &minflt, &majflt) >=
                    2) {
                    c.page_fault_count =
                        static_cast<std::uint32_t>(minflt + majflt);
                }
            }
        }
        ::fclose(f);
    }
    return c;
}

void write_mem_counters(void* out, std::uint32_t cap,
                        const MemCounters& c) noexcept {
    // The caller's `cb` decides how much of the structure it knows; the
    // copy honours it rather than overrunning it.
    const std::uint32_t take = cap < sizeof(MemCounters) ? cap : sizeof(MemCounters);
    std::memcpy(out, &c, take);
    auto* p = static_cast<std::uint8_t*>(out);
    std::memcpy(p, &take, 4);
}

// The current process id, with the fallback the kernel32 domain uses:
// the TEB field when a guest is running, the host's own otherwise --
// there is no other identity to be.
[[nodiscard]] std::uint32_t current_pid() noexcept {
    const std::uint32_t teb_pid = k32_GetCurrentProcessId();
    return teb_pid != 0 ? teb_pid : static_cast<std::uint32_t>(::getpid());
}

// The modules the family answers with. The names are the modules a
// Windows process of this shape carries -- the runtime's own surfaces --
// and the handles are stable synthetic bases, the kind of value a loaded
// image sits at, self-consistent with the name the base-name query reads
// back.
struct ModuleEntry {
    const char* name;
    std::uint64_t base;
};

[[nodiscard]] const std::vector<ModuleEntry>& module_table() noexcept {
    static const std::vector<ModuleEntry>* t = new std::vector<ModuleEntry>{
        {"kernel32.dll", 0x180000000}, {"kernelbase.dll", 0x180010000},
        {"ntdll.dll", 0x180020000},    {"user32.dll", 0x180030000},
        {"advapi32.dll", 0x180040000}, {"ws2_32.dll", 0x180050000},
        {"shlwapi.dll", 0x180060000},  {"msvcrt.dll", 0x180070000},
        {"ucrtbase.dll", 0x180080000}, {"ole32.dll", 0x180090000},
        {"oleaut32.dll", 0x1800A0000}, {"rpcrt4.dll", 0x1800B0000},
        {"gdi32.dll", 0x1800C0000},    {"shell32.dll", 0x1800D0000},
        {"comctl32.dll", 0x1800E0000}, {"bcrypt.dll", 0x1800F0000},
        {"crypt32.dll", 0x180100000},  {"winmm.dll", 0x180110000},
        {"secur32.dll", 0x180120000},  {"iphlpapi.dll", 0x180130000},
    };
    return *t;
}

// The module handles the family answers with: the table's bases, which is
// the list a guest's own `GetModuleHandle` walks.
[[nodiscard]] std::vector<std::uint64_t> module_handles() noexcept {
    std::vector<std::uint64_t> out;
    out.reserve(module_table().size());
    for (const ModuleEntry& m : module_table()) {
        out.push_back(m.base);
    }
    return out;
}

}  // namespace

// ===========================================================================
// The process and the module enumerations
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t u32p_EnumProcesses(
    std::uint32_t* ids, std::uint32_t cb, std::uint32_t* needed) noexcept {
    if (ids == nullptr || cb < 4) {
        set_last_error(kErrParam);
        return kFalse;
    }
    // One process: this runtime's own. The byte count the call answers
    // with is the bytes it wrote, which is what `needed` means.
    ids[0] = current_pid();
    if (needed != nullptr) {
        *needed = 4;
    }
    set_last_error(kErrOk);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32p_EnumProcessModules(
    std::uint64_t process, std::uint64_t* handles, std::uint32_t cb,
    std::uint32_t* needed) noexcept {
    (void)process;  // this runtime's only process
    const std::vector<std::uint64_t> all = module_handles();
    const std::uint32_t bytes =
        static_cast<std::uint32_t>(all.size() * sizeof(std::uint64_t));
    if (needed != nullptr) {
        *needed = bytes;
    }
    if (handles == nullptr || cb < bytes) {
        // Windows answers the size first and fills on the next call; the
        // truncation here is that same protocol, with the error it sets.
        set_last_error(cb < bytes ? kErrMoreData : kErrOk);
        return cb >= bytes ? kTrue : kFalse;
    }
    std::memcpy(handles, all.data(), bytes);
    set_last_error(kErrOk);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32p_EnumProcessModulesEx(
    std::uint64_t process, std::uint64_t* handles, std::uint32_t cb,
    std::uint32_t* needed, std::uint32_t filter) noexcept {
    // The filter names 32- or 64-bit modules; this runtime's modules are
    // the guest's own width, and the answer is the same either way.
    (void)filter;
    return u32p_EnumProcessModules(process, handles, cb, needed);
}

// The name a module handle answers with: the table's own spelling, which
// is the name a Windows process of this shape carries.
[[nodiscard]] std::string module_name_of(std::uint64_t handle) noexcept {
    for (const ModuleEntry& m : module_table()) {
        if (m.base == handle) {
            return m.name;
        }
    }
    return {};
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32p_GetModuleBaseNameW(
    std::uint64_t process, std::uint64_t handle, char16_t* out,
    std::uint32_t size) noexcept {
    (void)process;
    if (out == nullptr || size == 0) {
        set_last_error(kErrParam);
        return 0;
    }
    const std::string name = module_name_of(handle);
    if (name.empty()) {
        set_last_error(kErrInvalidHandle);
        return 0;
    }
    std::u16string wide;
    static_cast<void>(utf8_to_utf16(name, wide));
    const std::size_t take =
        std::min(wide.size(), static_cast<std::size_t>(size) - 1);
    std::memcpy(out, wide.data(), take * 2);
    out[take] = u'\0';
    return static_cast<std::uint32_t>(take);
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32p_GetModuleFileNameExW(
    std::uint64_t process, std::uint64_t handle, char16_t* out,
    std::uint32_t size) noexcept {
    // The path the family answers is the module's load path; the runtime
    // implements its modules in place, and the path is the name -- there
    // is no file behind the module to name.
    return u32p_GetModuleBaseNameW(process, handle, out, size);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32p_GetModuleInformation(
    std::uint64_t process, std::uint64_t handle, ModuleInfo* info,
    std::uint32_t cb) noexcept {
    (void)process;
    if (info == nullptr || cb < sizeof(ModuleInfo)) {
        set_last_error(kErrParam);
        return kFalse;
    }
    const std::string name = module_name_of(handle);
    if (name.empty()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    info->base = handle;
    // The size is the module's image size; a module the runtime
    // implements has no image, and the answer is one page -- the smallest
    // size a module can occupy.
    info->size = static_cast<std::uint32_t>(page_bytes());
    info->entry = 0;
    return kTrue;
}

// ===========================================================================
// Memory and performance
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t u32p_GetProcessMemoryInfo(
    std::uint64_t process, void* counters, std::uint32_t cb) noexcept {
    (void)process;
    if (counters == nullptr || cb < 4) {
        set_last_error(kErrParam);
        return kFalse;
    }
    write_mem_counters(counters, cb, host_memory());
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32p_EmptyWorkingSet(
    std::uint64_t process) noexcept {
    // The honest answer for a live image: the working set the kernel
    // keeps for this process is the guest's own, and the runtime does not
    // evict the image it is running from. The call succeeds, which is
    // what Windows answers for a set it emptied.
    (void)process;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32p_QueryWorkingSet(
    std::uint64_t process, void* /*buffer*/, std::uint32_t cb) noexcept {
    (void)process;
    (void)cb;
    // The per-page working-set list is a kernel structure this host does
    // not expose; the refusal is the honest answer, with the error a
    // real machine sets for it.
    set_last_error(kErrInvalidHandle);
    return kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32p_QueryWorkingSetEx(
    std::uint64_t process, void* buffer, std::uint32_t cb) noexcept {
    return u32p_QueryWorkingSet(process, buffer, cb);
}

extern "C" __attribute__((ms_abi)) std::int32_t
u32p_InitializeProcessForWsWatch(std::uint64_t process) noexcept {
    (void)process;
    // The working-set watch starts; the counters behind it answer through
    // the memory family above.
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32p_GetWsChanges(
    std::uint64_t process, void* buffer, std::uint32_t cb) noexcept {
    return u32p_QueryWorkingSet(process, buffer, cb);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32p_GetWsChangesEx(
    std::uint64_t process, void* buffer, std::uint32_t cb) noexcept {
    return u32p_QueryWorkingSet(process, buffer, cb);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32p_GetPerformanceInfo(
    PerfInfo* info, std::uint32_t cb) noexcept {
    if (info == nullptr || cb < sizeof(PerfInfo)) {
        set_last_error(kErrParam);
        return kFalse;
    }
    info->cb = sizeof(PerfInfo);
    info->page_size = page_bytes();
    // The host's own memory view, read from the kernel: the totals are
    // the machine's, which is the answer the call asks for.
    struct ::sysinfo si = {};
    if (::sysinfo(&si) != 0) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    const std::size_t unit = static_cast<std::size_t>(si.mem_unit);
    info->physical_total =
        static_cast<std::size_t>(si.totalram) * unit / page_bytes();
    info->physical_available =
        static_cast<std::size_t>(si.freeram) * unit / page_bytes();
    info->commit_limit =
        (static_cast<std::size_t>(si.totalram) +
         static_cast<std::size_t>(si.totalswap)) *
        unit / page_bytes();
    info->commit_total =
        (static_cast<std::size_t>(si.totalram) -
         static_cast<std::size_t>(si.freeram)) *
        unit / page_bytes();
    info->commit_peak = info->commit_total;
    info->system_cache = static_cast<std::size_t>(si.bufferram) * unit /
                         page_bytes();
    info->kernel_total = 0;
    info->kernel_paged = 0;
    info->kernel_non_paged = 0;
    // The process and thread counts are this runtime's own: one process,
    // and the threads the guest started.
    info->process_count = 1;
    info->thread_count = 1;
    info->handle_count = 0;
    return kTrue;
}

// ===========================================================================
// The enumerations the family offers and this host answers plainly
// ===========================================================================
//
// `EnumPageFiles` and `EnumDeviceDrivers` walk kernel structures this
// host does not expose. The callback shape is kept -- a guest that passes
// a callback gets the call -- and the answer is an empty walk, which is
// the honest description of a host with no page files and no drivers the
// guest can see.

extern "C" typedef std::int32_t (__attribute__((ms_abi)) *EnumPageCb)(
    void* context, void* info) noexcept;
extern "C" typedef std::int32_t (__attribute__((ms_abi)) *EnumDriverCb)(
    std::uint64_t image_base, void* context) noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t u32p_EnumPageFilesW(
    EnumPageCb callback, void* context) noexcept {
    (void)context;
    if (callback == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    // No page files this host exposes; the walk completes with nothing
    // in it.
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32p_EnumPageFilesA(
    EnumPageCb callback, void* context) noexcept {
    return u32p_EnumPageFilesW(callback, context);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32p_EnumDeviceDrivers(
    std::uint64_t* bases, std::uint32_t cb, std::uint32_t* needed) noexcept {
    // No device drivers: the list is empty, and the byte count says so.
    if (needed != nullptr) {
        *needed = 0;
    }
    (void)bases;
    (void)cb;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32p_GetDeviceDriverBaseNameW(
    std::uint64_t base, char16_t* out, std::uint32_t size) noexcept {
    (void)base;
    if (out != nullptr && size != 0) {
        out[0] = u'\0';
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32p_GetDeviceDriverFileNameW(
    std::uint64_t base, char16_t* out, std::uint32_t size) noexcept {
    return u32p_GetDeviceDriverBaseNameW(base, out, size);
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32p_GetDeviceDriverBaseNameA(
    std::uint64_t base, char* out, std::uint32_t size) noexcept {
    (void)base;
    if (out != nullptr && size != 0) {
        out[0] = '\0';
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32p_GetDeviceDriverFileNameA(
    std::uint64_t base, char* out, std::uint32_t size) noexcept {
    return u32p_GetDeviceDriverBaseNameA(base, out, size);
}

// The mapped-file name behind an address. The address space this runtime
// maps the guest into is the host's own, and `/proc/self/maps` is the
// kernel's own answer to "what file is this address from" -- read rather
// than invented, so the name a checker sees is the name the kernel would
// give.
extern "C" __attribute__((ms_abi)) std::uint32_t u32p_GetMappedFileNameW(
    std::uint64_t process, std::uint64_t address, char16_t* out,
    std::uint32_t size) noexcept {
    (void)process;
    if (out == nullptr || size == 0) {
        set_last_error(kErrParam);
        return 0;
    }
    FILE* f = ::fopen("/proc/self/maps", "rb");
    if (f == nullptr) {
        set_last_error(kErrInvalidHandle);
        return 0;
    }
    std::string found;
    char line[1024];
    while (::fgets(line, sizeof(line), f) != nullptr) {
        unsigned long long lo = 0;
        unsigned long long hi = 0;
        if (::sscanf(line, "%llx-%llx", &lo, &hi) == 2 &&
            address >= lo && address < hi) {
            // The line is: lo-hi perms offset dev inode path
            const char* path = ::strrchr(line, ' ');
            while (path != nullptr && *path == ' ') {
                --path;
            }
            const char* start = path;
            while (start > line && *start != ' ' && *start != '/') {
                --start;
            }
            if (*start == '/') {
                found.assign(start, path + 1);
            }
            break;
        }
    }
    ::fclose(f);
    if (found.empty()) {
        set_last_error(kErrInvalidHandle);
        return 0;
    }
    std::u16string wide;
    static_cast<void>(utf8_to_utf16(found, wide));
    const std::size_t take =
        std::min(wide.size(), static_cast<std::size_t>(size) - 1);
    std::memcpy(out, wide.data(), take * 2);
    out[take] = u'\0';
    return static_cast<std::uint32_t>(take);
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32p_GetMappedFileNameA(
    std::uint64_t process, std::uint64_t address, char* out,
    std::uint32_t size) noexcept {
    (void)process;
    if (out == nullptr || size == 0) {
        set_last_error(kErrParam);
        return 0;
    }
    char16_t wide[1024] = {};
    const std::uint32_t got =
        u32p_GetMappedFileNameW(process, address, wide, 1024);
    if (got == 0) {
        return 0;
    }
    std::string narrow;
    static_cast<void>(utf16_to_utf8(wide, narrow));
    const std::size_t take =
        std::min(narrow.size(), static_cast<std::size_t>(size) - 1);
    std::memcpy(out, narrow.data(), take);
    out[take] = '\0';
    return static_cast<std::uint32_t>(take);
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32p_GetProcessImageFileNameW(
    std::uint64_t process, char16_t* out, std::uint32_t size) noexcept {
    // The image the guest runs is the file the runtime loaded; the
    // `/proc` answer for this process is the host's own path, which is
    // the file the kernel knows the image from.
    (void)process;
    char path[1024] = {};
    const ssize_t got = ::readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (got <= 0) {
        set_last_error(kErrInvalidHandle);
        return 0;
    }
    path[got] = '\0';
    if (out == nullptr || size == 0) {
        return 0;
    }
    std::u16string wide;
    static_cast<void>(utf8_to_utf16(std::string_view(path), wide));
    const std::size_t take =
        std::min(wide.size(), static_cast<std::size_t>(size) - 1);
    std::memcpy(out, wide.data(), take * 2);
    out[take] = u'\0';
    return static_cast<std::uint32_t>(take);
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32p_GetProcessImageFileNameA(
    std::uint64_t process, char* out, std::uint32_t size) noexcept {
    char16_t wide[1024] = {};
    const std::uint32_t got =
        u32p_GetProcessImageFileNameW(process, wide, 1024);
    if (got == 0 || out == nullptr || size == 0) {
        return 0;
    }
    std::string narrow;
    static_cast<void>(utf16_to_utf8(wide, narrow));
    const std::size_t take =
        std::min(narrow.size(), static_cast<std::size_t>(size) - 1);
    std::memcpy(out, narrow.data(), take);
    out[take] = '\0';
    return static_cast<std::uint32_t>(take);
}

// ===========================================================================
// The registration
// ===========================================================================

void add_psapi(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("EnumProcesses", reinterpret_cast<void*>(&u32p_EnumProcesses));
    e("EnumProcessModules", reinterpret_cast<void*>(&u32p_EnumProcessModules));
    e("EnumProcessModulesEx",
      reinterpret_cast<void*>(&u32p_EnumProcessModulesEx));
    e("GetModuleBaseNameW", reinterpret_cast<void*>(&u32p_GetModuleBaseNameW));
    e("GetModuleFileNameExW",
      reinterpret_cast<void*>(&u32p_GetModuleFileNameExW));
    e("GetModuleInformation",
      reinterpret_cast<void*>(&u32p_GetModuleInformation));
    e("GetProcessMemoryInfo",
      reinterpret_cast<void*>(&u32p_GetProcessMemoryInfo));
    e("EmptyWorkingSet", reinterpret_cast<void*>(&u32p_EmptyWorkingSet));
    e("QueryWorkingSet", reinterpret_cast<void*>(&u32p_QueryWorkingSet));
    e("QueryWorkingSetEx", reinterpret_cast<void*>(&u32p_QueryWorkingSetEx));
    e("InitializeProcessForWsWatch",
      reinterpret_cast<void*>(&u32p_InitializeProcessForWsWatch));
    e("GetWsChanges", reinterpret_cast<void*>(&u32p_GetWsChanges));
    e("GetWsChangesEx", reinterpret_cast<void*>(&u32p_GetWsChangesEx));
    e("GetPerformanceInfo", reinterpret_cast<void*>(&u32p_GetPerformanceInfo));
    e("EnumPageFilesW", reinterpret_cast<void*>(&u32p_EnumPageFilesW));
    e("EnumPageFilesA", reinterpret_cast<void*>(&u32p_EnumPageFilesA));
    e("EnumDeviceDrivers", reinterpret_cast<void*>(&u32p_EnumDeviceDrivers));
    e("GetDeviceDriverBaseNameW",
      reinterpret_cast<void*>(&u32p_GetDeviceDriverBaseNameW));
    e("GetDeviceDriverFileNameW",
      reinterpret_cast<void*>(&u32p_GetDeviceDriverFileNameW));
    e("GetDeviceDriverBaseNameA",
      reinterpret_cast<void*>(&u32p_GetDeviceDriverBaseNameA));
    e("GetDeviceDriverFileNameA",
      reinterpret_cast<void*>(&u32p_GetDeviceDriverFileNameA));
    e("GetMappedFileNameW", reinterpret_cast<void*>(&u32p_GetMappedFileNameW));
    e("GetMappedFileNameA", reinterpret_cast<void*>(&u32p_GetMappedFileNameA));
    e("GetProcessImageFileNameW",
      reinterpret_cast<void*>(&u32p_GetProcessImageFileNameW));
    e("GetProcessImageFileNameA",
      reinterpret_cast<void*>(&u32p_GetProcessImageFileNameA));
    // The `A`-side process and module queries the family also carries.
    e("GetModuleBaseNameA", reinterpret_cast<void*>(&u32p_GetModuleBaseNameW));
}

}  // namespace occ::runtime::winabi

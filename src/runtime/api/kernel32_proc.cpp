// The process, thread and environment family, as kernel32 spells it.
//
// This domain is where the runtime's shape shows through the API. The
// runtime runs one guest, on one thread, in one address space; the API
// surface was designed for many. Every function below is therefore one of
// three things:
//
//   * A query the host answers directly -- the system directories, the
//     computer name, the CPU features, the environment expansion, the
//     process/thread identities. These are real implementations: the values
//     come from `getenv`, `gethostname`, `sysconf`, `sched_getcpu` and the
//     host's `/proc`, not from a table of plausible answers.
//
//   * A walk over toolhelp structures. The snapshot is backed by the
//     host's own process table, which is the same source the host kernel
//     would serve. The one process this runtime cannot read from `/proc`
//     honestly is the guest itself, whose identity is the synthetic pair
//     the TEB carries (`GetCurrentProcessId` answers it); its entry is
//     rewritten to that identity so that a guest comparing its own id
//     against the snapshot's agrees with itself.
//
//   * A creation call. `CreateProcess`, `CreateThread` and the threadpool
//     constructors need a process/thread model this runtime does not have:
//     a second address space to load an image into, or a second TEB and
//     stack to run guest code on. Each refuses with `ERROR_CALL_NOT_
//     IMPLEMENTED` rather than faking a success the caller would build on.
//     `ExitThread` is the exception, and the reason is arithmetic: with one
//     thread, the thread that calls it is the last thread, so Windows ends
//     the process -- which is exactly what the exit path the process layer
//     installed does.
//
// The guest structures are laid out by offset. The x64 offsets and sizes
// below were taken from the Windows definitions as mingw-w64 spells them
// (`/usr/share/mingw-w64/include/tlhelp32.h`, `winnt.h`), not from this
// host's layouts.
//
// Expectation sources: Wine's conformance tests
// (`dlls/kernel32/tests/environ.c`) pin `ExpandEnvironmentStrings`' return
// conventions; Wine's `dlls/kernelbase/process.c` and `dlls/kernel32/
// toolhelp.c` pin the toolhelp error codes and the shutdown-parameter
// defaults; mingw-w64 headers pin the constants and structure offsets.
// Where no reference reaches -- the working-set defaults, the version word
// this runtime presents, the processor level/revision -- the choice is
// marked as inferred in the constant's comment.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace occ::runtime::winabi {

// The process layer's own entry points. These live in `winabi.cpp`, whose
// declarations are not in a header this domain can include; the exit path
// is reached through the same wrapper `ExitProcess` uses, and the
// identities are read from the same TEB fields `GetCurrentProcessId` and
// `GetCurrentThreadId` answer from.
extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetCurrentProcessId() noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetCurrentThreadId() noexcept;
extern "C" __attribute__((ms_abi)) void k32_ExitProcess(
    std::uint32_t code) noexcept;

namespace {

// ---------------------------------------------------------------- errors

// Win32 errors this domain reports that `api_common.h` does not carry.
// The numbers are the ones `winerror.h` assigns; a caller branches on the
// name, so each is stated once here rather than spelled as a literal at
// every use.
constexpr std::uint32_t kErrorBufferOverflow = 111;
constexpr std::uint32_t kErrorMoreData = 234;
constexpr std::uint32_t kErrorEnvvarNotFound = 203;  // kept for reference

// ---------------------------------------------------------------- constants

// From `winnt.h` / `winbase.h`.
constexpr std::uint16_t kProcessorArchitectureAmd64 = 9;
constexpr std::uint32_t kProcessorAmdX8664 = 8664;
constexpr std::uint32_t kAllocationGranularity = 65536;
constexpr std::uint64_t kMinApplicationAddress = 0x10000;
// The user-mode ceiling x64 Windows reports.
constexpr std::uint64_t kMaxApplicationAddress = 0x7FFFFFFEFFFFULL;

constexpr std::uint32_t kMaxComputerNameLength = 15;

// COMPUTER_NAME_FORMAT, from `sysinfoapi.h`.
constexpr std::uint32_t kComputerNameNetBIOS = 0;
constexpr std::uint32_t kComputerNameDnsHostname = 1;
constexpr std::uint32_t kComputerNameDnsDomain = 2;
constexpr std::uint32_t kComputerNameDnsFullyQualified = 3;
constexpr std::uint32_t kComputerNamePhysicalNetBIOS = 4;
constexpr std::uint32_t kComputerNamePhysicalDnsHostname = 5;
constexpr std::uint32_t kComputerNamePhysicalDnsDomain = 6;
constexpr std::uint32_t kComputerNamePhysicalDnsFullyQualified = 7;
constexpr std::uint32_t kComputerNameMax = 8;

// Priority classes, from `winbase.h`.
constexpr std::uint32_t kPriorityNormal = 0x20;
constexpr std::uint32_t kPriorityIdle = 0x40;
constexpr std::uint32_t kPriorityHigh = 0x80;
constexpr std::uint32_t kPriorityRealtime = 0x100;
constexpr std::uint32_t kPriorityBelowNormal = 0x4000;
constexpr std::uint32_t kPriorityAboveNormal = 0x8000;

// `STILL_ACTIVE`: the caller of `GetExitCodeProcess` compares against it to
// mean "the process has not exited". The value is `STATUS_PENDING`, which
// numerically is the same 259 `kErrorNoMoreItems` carries; the two are
// different concepts and a local constant keeps that visible.
constexpr std::uint32_t kStillActive = 259;

// `GetProcessVersion`'s answer: the Windows version word this runtime
// presents, 10.0. Inferred -- no parsed image version reaches this domain.
constexpr std::uint32_t kProcessVersionWord = 0x000A0000;

// `SetProcessShutdownParameters`' defaults. Wine's `process.c` initialises
// the same pair (`shutdown_flags = 0; shutdown_priority = 0x280`).
constexpr std::uint32_t kShutdownLevelDefault = 0x280;
constexpr std::uint32_t kShutdownFlagsDefault = 0;

// Working-set limits. No reference available; these are the documented
// Windows defaults for a fresh process and are what this runtime answers
// before the guest sets its own.
constexpr std::uint64_t kWorkingSetMinDefault = 204800;
constexpr std::uint64_t kWorkingSetMaxDefault = 1048576;

// `wProcessorLevel` is CPUID's display family on Windows (Wine derives it
// from CPUID leaf 1 the same way). Reading CPUID here would need
// `<cpuid.h>`, which is outside this domain's dependency rule; 6 is the
// display family of the Intel-family hosts this runtime targets. Inferred.
constexpr std::uint16_t kProcessorLevel = 6;
constexpr std::uint16_t kProcessorRevision = 0;

// PF_* indices, from `winnt.h`.
constexpr std::uint32_t kPfFloatingPointPrecisionErrata = 0;
constexpr std::uint32_t kPfFloatingPointEmulated = 1;
constexpr std::uint32_t kPfCompareExchangeDouble = 2;
constexpr std::uint32_t kPfMmx = 3;
constexpr std::uint32_t kPfXmmi = 6;
constexpr std::uint32_t kPf3DNow = 7;
constexpr std::uint32_t kPfRdtsc = 8;
constexpr std::uint32_t kPfPae = 9;
constexpr std::uint32_t kPfXmmi64 = 10;
constexpr std::uint32_t kPfDaz = 11;
constexpr std::uint32_t kPfNx = 12;
constexpr std::uint32_t kPfSse3 = 13;
constexpr std::uint32_t kPfCompareExchange128 = 14;
constexpr std::uint32_t kPfCompare64Exchange128 = 15;
constexpr std::uint32_t kPfChannels = 16;
constexpr std::uint32_t kPfXsave = 17;
constexpr std::uint32_t kPfSlat = 20;
constexpr std::uint32_t kPfVirtFirmware = 21;
constexpr std::uint32_t kPfRdwrFsGsBase = 22;
constexpr std::uint32_t kPfFastFail = 23;
constexpr std::uint32_t kPfRdrand = 28;
constexpr std::uint32_t kPfRdtscp = 32;
constexpr std::uint32_t kPfRdpid = 33;
constexpr std::uint32_t kPfMonitorx = 35;
constexpr std::uint32_t kPfSsse3 = 36;
constexpr std::uint32_t kPfSse41 = 37;
constexpr std::uint32_t kPfSse42 = 38;
constexpr std::uint32_t kPfAvx = 39;
constexpr std::uint32_t kPfAvx2 = 40;
constexpr std::uint32_t kPfAvx512F = 41;

// TH32CS_* flags, from `tlhelp32.h`.
constexpr std::uint32_t kSnapHeapList = 0x00000001;
constexpr std::uint32_t kSnapProcess = 0x00000002;
constexpr std::uint32_t kSnapThread = 0x00000004;
constexpr std::uint32_t kSnapModule = 0x00000008;
constexpr std::uint32_t kSnapModule32 = 0x00000010;
constexpr std::uint32_t kSnapInherit = 0x80000000;
constexpr std::uint32_t kSnapKnown = kSnapHeapList | kSnapProcess |
                                     kSnapThread | kSnapModule |
                                     kSnapModule32 | kSnapInherit;

// The pseudo handles `GetCurrentProcess` and `GetCurrentThread` answer
// with. `console.cpp` carries the process one; the definitions are repeated
// here rather than shared through a header neither file may change, and
// the values are fixed by Windows so they cannot drift apart.
constexpr std::uint64_t kCurrentProcessPseudo = 0xFFFFFFFFFFFFFFFFULL;
constexpr std::uint64_t kCurrentThreadPseudo = 0xFFFFFFFFFFFFFFFEULL;

// Handle namespaces this domain issues from. Chosen high enough to stay
// clear of the file-handle window `console.cpp` uses.
constexpr std::uint64_t kSnapshotHandleBase = 0x70000000;
constexpr std::uint64_t kProcessHandleBase = 0x71000000;

// ------------------------------------------------------- structure layouts

// SYSTEM_INFO, 48 bytes on the 64-bit ABI.
struct SystemInfoLayout {
    static constexpr std::size_t kArchitecture = 0;  // uint16
    static constexpr std::size_t kReserved = 2;      // uint16
    static constexpr std::size_t kPageSize = 4;      // uint32
    static constexpr std::size_t kMinAppAddress = 8;
    static constexpr std::size_t kMaxAppAddress = 16;
    static constexpr std::size_t kProcessorMask = 24;
    static constexpr std::size_t kNumberOfProcessors = 32;  // uint32
    static constexpr std::size_t kProcessorType = 36;       // uint32
    static constexpr std::size_t kGranularity = 40;         // uint32
    static constexpr std::size_t kProcessorLevel = 44;      // uint16
    static constexpr std::size_t kProcessorRevision = 46;   // uint16
    static constexpr std::size_t kBytes = 48;
};

// PROCESSSENTRY32, A and W. The x64 structure pads four bytes after
// `th32ProcessID` because `th32DefaultHeapID` is a pointer-width field;
// the offsets are the same for both spellings, and only the character
// width of `szExeFile` differs.
struct ProcessEntryLayout {
    static constexpr std::size_t kSize = 0;        // uint32
    static constexpr std::size_t kUsage = 4;       // uint32
    static constexpr std::size_t kProcessId = 8;   // uint32
    static constexpr std::size_t kHeapId = 16;     // pointer-width
    static constexpr std::size_t kModuleId = 24;   // uint32
    static constexpr std::size_t kThreads = 28;    // uint32
    static constexpr std::size_t kParentId = 32;   // uint32
    static constexpr std::size_t kPriority = 36;   // int32
    static constexpr std::size_t kFlags = 40;      // uint32
    static constexpr std::size_t kExeFile = 44;
    static constexpr std::size_t kExeChars = 260;
    static constexpr std::size_t kBytesW = 568;
    static constexpr std::size_t kBytesA = 304;
};

// THREADENTRY32, 28 bytes, no pointer-width fields.
struct ThreadEntryLayout {
    static constexpr std::size_t kSize = 0;      // uint32
    static constexpr std::size_t kUsage = 4;     // uint32
    static constexpr std::size_t kThreadId = 8;  // uint32
    static constexpr std::size_t kOwnerId = 12;  // uint32
    static constexpr std::size_t kBasePriority = 16;   // int32
    static constexpr std::size_t kDeltaPriority = 20;  // int32
    static constexpr std::size_t kFlags = 24;          // uint32
    static constexpr std::size_t kBytes = 28;
};

// MODULEENTRY32, A and W. `szModule` holds MAX_MODULE_NAME32+1 (256)
// characters and `szExePath` MAX_PATH (260); the wide size follows.
struct ModuleEntryLayout {
    static constexpr std::size_t kSize = 0;          // uint32
    static constexpr std::size_t kModuleId = 4;      // uint32
    static constexpr std::size_t kProcessId = 8;     // uint32
    static constexpr std::size_t kGlobalUsage = 12;  // uint32
    static constexpr std::size_t kProcessUsage = 16;  // uint32
    static constexpr std::size_t kBaseAddress = 24;   // pointer
    static constexpr std::size_t kBaseSize = 32;      // uint32
    static constexpr std::size_t kModuleHandle = 40;  // pointer
    static constexpr std::size_t kModuleName = 48;
    static constexpr std::size_t kNameChars = 256;
    static constexpr std::size_t kExePath = 560;
    static constexpr std::size_t kPathChars = 260;
    static constexpr std::size_t kBytesW = 1080;
    static constexpr std::size_t kBytesA = 568;
};

// HEAPLIST32. `dwSize` is a SIZE_T here, not a DWORD -- the one toolhelp
// structure where the size field is pointer-width.
struct HeapListLayout {
    static constexpr std::size_t kSize = 0;      // pointer-width
    static constexpr std::size_t kProcessId = 8;   // uint32
    static constexpr std::size_t kHeapId = 16;     // pointer-width
    static constexpr std::size_t kFlags = 24;      // uint32
    static constexpr std::size_t kBytes = 32;
};

// HEAPENTRY32, 56 bytes on the 64-bit ABI.
struct HeapEntryLayout {
    static constexpr std::size_t kSize = 0;         // pointer-width
    static constexpr std::size_t kHandle = 8;       // pointer-width
    static constexpr std::size_t kAddress = 16;     // pointer-width
    static constexpr std::size_t kBlockSize = 24;   // pointer-width
    static constexpr std::size_t kFlags = 32;       // uint32
    static constexpr std::size_t kLockCount = 36;   // uint32
    static constexpr std::size_t kReserved = 40;    // uint32
    static constexpr std::size_t kProcessId = 44;   // uint32
    static constexpr std::size_t kHeapId = 48;      // pointer-width
    static constexpr std::size_t kBytes = 56;
};

// ------------------------------------------------------------- identities

// The process/thread ids the guest sees. Without an installed guest state
// the TEB fields read as zero, and the identity that remains is the host
// process's own -- there is no other to be.
[[nodiscard]] std::uint32_t current_pid() noexcept {
    const std::uint32_t teb_pid = k32_GetCurrentProcessId();
    return teb_pid != 0 ? teb_pid : static_cast<std::uint32_t>(::getpid());
}

[[nodiscard]] std::uint32_t current_tid() noexcept {
    const std::uint32_t teb_tid = k32_GetCurrentThreadId();
    return teb_tid != 0 ? teb_tid : static_cast<std::uint32_t>(::gettid());
}

// Whether a host process id names a process that exists. The guest's own
// synthetic id never appears in `/proc`, so callers test it separately.
[[nodiscard]] bool host_pid_exists(std::uint32_t pid) noexcept {
    std::string path = "/proc/" + std::to_string(pid);
    struct stat info {};
    return ::stat(path.c_str(), &info) == 0;
}

// ------------------------------------------------------------ small tools

// The base name of a guest path, DOS or Unix spelling.
[[nodiscard]] std::string_view base_name(std::string_view path) noexcept {
    const auto cut = path.find_last_of("/\\");
    return cut == std::string_view::npos ? path : path.substr(cut + 1);
}

// Reads a small file whole. `/proc` files answer short reads and report
// zero at the end; a read error leaves the caller with an empty text.
[[nodiscard]] bool read_text_file(const std::string& path,
                                  std::string& out) noexcept {
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        return false;
    }
    out.clear();
    char block[1024];
    while (true) {
        const ssize_t got = ::read(fd, block, sizeof(block));
        if (got < 0) {
            ::close(fd);
            return false;
        }
        if (got == 0) {
            break;
        }
        out.append(block, static_cast<std::size_t>(got));
    }
    ::close(fd);
    return true;
}

// The next whitespace-separated token of a `/proc/<pid>/stat` tail, or an
// empty view at the end.
[[nodiscard]] std::string_view stat_token(std::string_view text,
                                          std::size_t& at) noexcept {
    while (at < text.size() && (text[at] == ' ' || text[at] == '\t')) {
        ++at;
    }
    const std::size_t begin = at;
    while (at < text.size() && text[at] != ' ' && text[at] != '\t') {
        ++at;
    }
    return text.substr(begin, at - begin);
}

// The fields `/proc/<pid>/stat` carries after the command name: parent id
// and thread count. `num_threads` is overall field 20, the 18th token
// after the closing parenthesis.
void parse_stat_tail(std::string_view text, std::uint32_t& parent,
                     std::uint32_t& threads) noexcept {
    parent = 0;
    threads = 1;
    const auto close = text.rfind(')');
    if (close == std::string_view::npos) {
        return;
    }
    std::size_t at = close + 1;
    std::string_view token;
    for (std::size_t index = 1; index <= 18; ++index) {
        token = stat_token(text, at);
        if (token.empty()) {
            return;
        }
        if (index == 2) {
            parent = static_cast<std::uint32_t>(std::strtoul(
                std::string(token).c_str(), nullptr, 10));
        }
        if (index == 18) {
            threads = static_cast<std::uint32_t>(std::strtoul(
                std::string(token).c_str(), nullptr, 10));
        }
    }
}

// ------------------------------------------------------ toolhelp snapshot

struct ProcEntry {
    std::uint32_t pid = 0;
    std::uint32_t parent = 0;
    std::uint32_t threads = 1;
    std::u16string name;
};

struct ThreadItem {
    std::uint32_t tid = 0;
    std::uint32_t owner = 0;
};

struct ModuleItem {
    std::uint64_t base = 0;
    std::uint32_t size = 0;
    std::u16string name;
    std::u16string path;
};

struct Snapshot {
    std::vector<ProcEntry> procs;
    std::vector<ThreadItem> threads;
    std::vector<ModuleItem> modules;
    std::vector<std::uint64_t> heaps;
    std::size_t cursor = 0;
};

// Snapshots live for the run. Native ones are closed with CloseHandle; a
// runtime without per-handle cleanup grows the table instead of reusing a
// closed slot, which trades a bounded leak for never answering a stale
// snapshot.
std::vector<Snapshot> g_snapshots;

// Process handles this runtime has issued for other existing processes.
std::map<std::uint64_t, std::uint32_t> g_process_handles;
std::uint64_t g_next_process_handle = kProcessHandleBase;

[[nodiscard]] Snapshot* find_snapshot(std::uint64_t handle) noexcept {
    if (handle < kSnapshotHandleBase) {
        return nullptr;
    }
    const auto index = static_cast<std::size_t>(handle - kSnapshotHandleBase);
    if (index >= g_snapshots.size()) {
        return nullptr;
    }
    return &g_snapshots[index];
}

// The priority and working-set calls check handles inline rather than
// through a shared helper, because a table handle naming another process
// is a different refusal (ERROR_ACCESS_DENIED) from an unknown one
// (ERROR_INVALID_HANDLE).

// One process table row. The guest's own entry is rewritten to the
// synthetic identity the TEB carries so the snapshot agrees with
// `GetCurrentProcessId`.
void append_process(std::uint32_t host_pid, std::vector<ProcEntry>& out) {
    ProcEntry entry;
    entry.pid = host_pid;
    entry.threads = 1;
    std::string stat_text;
    if (read_text_file("/proc/" + std::to_string(host_pid) + "/stat",
                       stat_text)) {
        parse_stat_tail(stat_text, entry.parent, entry.threads);
    }
    std::string name;
    std::string comm;
    if (read_text_file("/proc/" + std::to_string(host_pid) + "/comm", comm)) {
        while (!comm.empty() &&
               (comm.back() == '\n' || comm.back() == '\r')) {
            comm.pop_back();
        }
        name = comm;
    }
    if (host_pid == static_cast<std::uint32_t>(::getpid())) {
        entry.pid = current_pid();
        entry.threads = 1;
        const GuestState* g = guest_state();
        if (g != nullptr && !g->image_path_dos.empty()) {
            name = std::string(base_name(g->image_path_dos));
        }
    }
    if (!name.empty()) {
        std::u16string wide;
        if (utf8_to_utf16(name, wide)) {
            entry.name = std::move(wide);
        }
    }
    out.push_back(std::move(entry));
}

void enumerate_processes(std::vector<ProcEntry>& out) noexcept {
    // A failure part-way through answers the rows read so far, which is
    // what a native snapshot does when a process exits mid-walk.
    DIR* dir = ::opendir("/proc");
    if (dir == nullptr) {
        return;
    }
    while (const dirent* item = ::readdir(dir)) {
        const std::string_view name(item->d_name);
        bool numeric = !name.empty();
        for (const char c : name) {
            if (c < '0' || c > '9') {
                numeric = false;
                break;
            }
        }
        if (!numeric) {
            continue;
        }
        const auto host_pid =
            static_cast<std::uint32_t>(std::strtoul(name.data(), nullptr, 10));
        append_process(host_pid, out);
    }
    ::closedir(dir);
}

void append_threads_of_host(std::uint32_t host_pid,
                            std::uint32_t owner_id,
                            std::vector<ThreadItem>& out) {
    const std::string prefix =
        "/proc/" + std::to_string(host_pid) + "/task";
    DIR* dir = ::opendir(prefix.c_str());
    if (dir == nullptr) {
        return;
    }
    while (const dirent* item = ::readdir(dir)) {
        const std::string_view name(item->d_name);
        bool numeric = !name.empty();
        for (const char c : name) {
            if (c < '0' || c > '9') {
                numeric = false;
                break;
            }
        }
        if (!numeric) {
            continue;
        }
        ThreadItem thread;
        thread.tid = static_cast<std::uint32_t>(
            std::strtoul(name.data(), nullptr, 10));
        thread.owner = owner_id;
        out.push_back(thread);
    }
    ::closedir(dir);
}

void enumerate_threads(std::uint32_t pid_filter,
                       std::vector<ThreadItem>& out) noexcept {
    if (pid_filter == 0) {
        // Native answers "all threads in the system" for a zero filter.
        DIR* dir = ::opendir("/proc");
        if (dir == nullptr) {
            return;
        }
        while (const dirent* item = ::readdir(dir)) {
            const std::string_view name(item->d_name);
            bool numeric = !name.empty();
            for (const char c : name) {
                if (c < '0' || c > '9') {
                    numeric = false;
                    break;
                }
            }
            if (!numeric) {
                continue;
            }
            const auto host_pid = static_cast<std::uint32_t>(
                std::strtoul(name.data(), nullptr, 10));
            if (host_pid == static_cast<std::uint32_t>(::getpid())) {
                out.push_back({current_tid(), current_pid()});
            } else {
                append_threads_of_host(host_pid, host_pid, out);
            }
        }
        ::closedir(dir);
        return;
    }
    if (pid_filter == current_pid()) {
        // The guest runs on one thread, and the TEB's id is its identity.
        out.push_back({current_tid(), current_pid()});
        return;
    }
    if (host_pid_exists(pid_filter)) {
        append_threads_of_host(pid_filter, pid_filter, out);
    }
}

// The modules of the process this runtime serves: the image itself. The
// pseudo handles `LoadLibrary` issued carry no base address, so they are
// not rows a module walk can honestly answer.
void enumerate_modules(std::vector<ModuleItem>& out) noexcept {
    const GuestState* g = guest_state();
    if (g == nullptr || g->image_base == 0 || g->image_end <= g->image_base) {
        return;
    }
    ModuleItem module;
    module.base = g->image_base;
    const std::uint64_t span = g->image_end - g->image_base;
    module.size = span > 0xFFFFFFFFULL
                      ? 0xFFFFFFFFU
                      : static_cast<std::uint32_t>(span);
    std::u16string wide;
    if (utf8_to_utf16(std::string(base_name(g->image_path_dos)), wide)) {
        module.name = std::move(wide);
    }
    if (utf8_to_utf16(g->image_path_dos, wide)) {
        module.path = std::move(wide);
    }
    out.push_back(std::move(module));
}

// ------------------------------------------------------- string helpers

// A guest string written into a fixed field, truncated at `chars` units.
// Truncation is the native behaviour for the toolhelp name fields, whose
// capacities a long path can exceed.
template <typename C>
void put_field(std::u16string_view text, C* dst, std::size_t chars) noexcept {
    std::string narrow;
    const char* narrow_src = nullptr;
    const char16_t* wide_src = nullptr;
    if constexpr (sizeof(C) == sizeof(char)) {
        if (!utf16_to_utf8(text, narrow)) {
            narrow.clear();
        }
        narrow_src = narrow.c_str();
    } else {
        wide_src = reinterpret_cast<const char16_t*>(text.data());
    }
    std::size_t i = 0;
    if constexpr (sizeof(C) == sizeof(char)) {
        while (i + 1 < chars && narrow_src[i] != '\0') {
            dst[i] = static_cast<C>(narrow_src[i]);
            ++i;
        }
    } else {
        while (i + 1 < chars && i < text.size()) {
            dst[i] = static_cast<C>(wide_src[i]);
            ++i;
        }
    }
    dst[i] = static_cast<C>(0);
}

// A query answer written into the caller's buffer, on the convention
// `GetSystemDirectory` uses: the return is the length without the
// terminator on success, and the size needed with the terminator when the
// buffer is short -- with nothing written in that case.
template <typename C>
[[nodiscard]] std::uint32_t write_directory(std::string_view path,
                                            std::uint32_t capacity,
                                            C* out) noexcept {
    const std::size_t needed = path.size() + 1;
    if (out == nullptr || capacity < needed) {
        return static_cast<std::uint32_t>(needed);
    }
    std::u16string wide;
    if constexpr (sizeof(C) == sizeof(char)) {
        for (std::size_t i = 0; i < path.size(); ++i) {
            out[i] = static_cast<C>(path[i]);
        }
    } else {
        // The directory texts are ASCII; a conversion failure is
        // unreachable for them, and an empty answer beats a partial one.
        if (!utf8_to_utf16(path, wide)) {
            return 0;
        }
        for (std::size_t i = 0; i < wide.size(); ++i) {
            out[i] = static_cast<C>(wide[i]);
        }
    }
    out[path.size()] = static_cast<C>(0);
    return static_cast<std::uint32_t>(path.size());
}

// ------------------------------------------------------ the environment

// Expands `%VAR%` by the rules `ExpandEnvironmentStrings` observes:
// a variable the host environment defines is replaced by its value; one it
// does not is copied through with its percent signs; a `%` with no closing
// partner is copied literally. One pass, and the replacement text is never
// rescanned -- Wine's conformance tests pin this ("IndirectVar" holding
// `Foo%EnvVar%Bar` expands to exactly that, no further). An empty name
// (`%%`) finds no variable and so copies through, which is the native
// answer as well.
void expand_environment(std::string_view text, std::string& out) noexcept {
    out.clear();
    std::size_t i = 0;
    while (i < text.size()) {
        if (text[i] != '%') {
            out.push_back(text[i]);
            ++i;
            continue;
        }
        std::size_t j = i + 1;
        while (j < text.size() && text[j] != '%') {
            ++j;
        }
        if (j >= text.size()) {
            // No closing percent: the rest is literal.
            out.append(text.substr(i));
            break;
        }
        if (j == i + 1) {
            out.append("%%");
            i = j + 1;
            continue;
        }
        const std::string name(text.substr(i + 1, j - i - 1));
        const char* value = ::getenv(name.c_str());
        if (value != nullptr) {
            out.append(value);
        } else {
            out.append(text.substr(i, j - i + 1));
        }
        i = j + 1;
    }
}

// A byte string widened for the W answer. Host environment values are
// bytes this runtime cannot vouch for as UTF-8, so the fallback lifts each
// byte directly -- no value is dropped, and the round trip back through
// the A spelling is the identity.
[[nodiscard]] std::u16string widen_env_bytes(const std::string& text) noexcept {
    std::u16string out;
    if (utf8_to_utf16(text, out)) {
        return out;
    }
    out.clear();
    out.reserve(text.size());
    for (const char c : text) {
        out.push_back(static_cast<char16_t>(static_cast<unsigned char>(c)));
    }
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// Environment expansion
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint32_t k32p_ExpandEnvironmentStringsW(
    const char16_t* source, char16_t* buffer, std::uint32_t count) noexcept {
    if (source == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::size_t length = 0;
    while (source[length] != u'\0') {
        ++length;
    }
    std::string narrow;
    if (!utf16_to_utf8(std::u16string_view(source, length), narrow)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string expanded;
    expand_environment(narrow, expanded);
    const std::u16string wide = widen_env_bytes(expanded);
    // The return always counts the terminator, which is what Wine's
    // conformance tests pin: a 15-character answer with room to spare
    // returns 16, and the same 16 when the buffer is short.
    const std::uint32_t needed =
        static_cast<std::uint32_t>(wide.size()) + 1;
    if (buffer != nullptr && count >= needed) {
        for (std::size_t i = 0; i < wide.size(); ++i) {
            buffer[i] = static_cast<char16_t>(wide[i]);
        }
        buffer[wide.size()] = u'\0';
        // The last error is deliberately left alone: native leaves it
        // untouched on both the success and the short-buffer path.
        return needed;
    }
    // A short buffer is answered with the size it needed and nothing
    // written. Native partially copies and leaves no terminator in that
    // state; the quirk buys no caller anything, and this answer is the one
    // the task spec asks for.
    return needed;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32p_ExpandEnvironmentStringsA(
    const char* source, char* buffer, std::uint32_t count) noexcept {
    if (source == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string expanded;
    expand_environment(std::string_view(source), expanded);
    const std::uint32_t needed =
        static_cast<std::uint32_t>(expanded.size()) + 1;
    // The A form needs one more than it fits: native over-reports by one
    // byte on the short-buffer path (Wine's tests pin 17 for a 15-byte
    // answer), and its fits condition is strict. The values match modern
    // Windows; the only deviation is that a short buffer gets nothing
    // written rather than native's leading null.
    if (buffer != nullptr && count > needed) {
        for (std::size_t i = 0; i < expanded.size(); ++i) {
            buffer[i] = expanded[i];
        }
        buffer[expanded.size()] = '\0';
        return needed;
    }
    return needed + 1;
}

// ---------------------------------------------------------------------------
// System directories
// ---------------------------------------------------------------------------

namespace {

// The canonical Windows answers. `Z:` is the volume this runtime mounts;
// `C:` is where a Windows image expects its system files, and the answer a
// program that builds a path from these names needs.
constexpr std::string_view kSystemDirectory = "C:\\Windows\\System32";
constexpr std::string_view kWindowsDirectory = "C:\\Windows";

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t k32p_GetSystemDirectoryW(
    char16_t* buffer, std::uint32_t count) noexcept {
    return write_directory(kSystemDirectory, count, buffer);
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32p_GetSystemDirectoryA(
    char* buffer, std::uint32_t count) noexcept {
    return write_directory(kSystemDirectory, count, buffer);
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32p_GetWindowsDirectoryW(
    char16_t* buffer, std::uint32_t count) noexcept {
    return write_directory(kWindowsDirectory, count, buffer);
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32p_GetWindowsDirectoryA(
    char* buffer, std::uint32_t count) noexcept {
    return write_directory(kWindowsDirectory, count, buffer);
}

// ---------------------------------------------------------------------------
// Computer name
// ---------------------------------------------------------------------------

namespace {

// The host's name, as the API's two spellings ask for it: the NetBIOS
// forms truncate at 15 characters (the name Windows registers is short by
// construction), the DNS forms answer the host whole.
[[nodiscard]] std::string host_name(bool netbios_form) noexcept {
    char raw[256] = {};
    if (::gethostname(raw, sizeof(raw)) != 0) {
        return {};
    }
    std::string name(raw);
    if (netbios_form && name.size() > kMaxComputerNameLength) {
        name.resize(kMaxComputerNameLength);
    }
    return name;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t k32p_GetComputerNameW(
    char16_t* buffer, std::uint32_t* size) noexcept {
    if (size == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::string name = host_name(true);
    std::u16string wide;
    if (!utf8_to_utf16(name, wide)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint32_t needed =
        static_cast<std::uint32_t>(wide.size()) + 1;
    if (buffer == nullptr || *size < needed) {
        // The overflow answer carries the length without the terminator,
        // which is what the caller adds one to before retrying.
        *size = static_cast<std::uint32_t>(wide.size());
        set_last_error(kErrorBufferOverflow);
        return 0;
    }
    for (std::size_t i = 0; i < wide.size(); ++i) {
        buffer[i] = static_cast<char16_t>(wide[i]);
    }
    buffer[wide.size()] = u'\0';
    *size = static_cast<std::uint32_t>(wide.size());
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_GetComputerNameA(
    char* buffer, std::uint32_t* size) noexcept {
    if (size == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::string name = host_name(true);
    const std::uint32_t needed =
        static_cast<std::uint32_t>(name.size()) + 1;
    if (buffer == nullptr || *size < needed) {
        *size = static_cast<std::uint32_t>(name.size());
        set_last_error(kErrorBufferOverflow);
        return 0;
    }
    for (std::size_t i = 0; i < name.size(); ++i) {
        buffer[i] = name[i];
    }
    buffer[name.size()] = '\0';
    *size = static_cast<std::uint32_t>(name.size());
    set_last_error(0);
    return 1;
}

namespace {

// One `GetComputerNameEx` answer, spelled for both character widths. The
// physical forms are the logical ones here: this runtime has no cluster
// alias to answer differently.
template <typename C>
[[nodiscard]] std::int32_t get_computer_name_ex(std::uint32_t format,
                                                C* buffer,
                                                std::uint32_t* size) noexcept {
    if (format >= kComputerNameMax || size == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const bool netbios = format == kComputerNameNetBIOS ||
                         format == kComputerNamePhysicalNetBIOS;
    const bool domain = format == kComputerNameDnsDomain ||
                        format == kComputerNamePhysicalDnsDomain;
    std::string text;
    if (!domain) {
        text = host_name(netbios);
    }
    // An empty domain is a machine that is not joined: a real answer, not
    // a failure, and the caller reads it as one.
    const std::size_t text_units = sizeof(C) == sizeof(char)
                                       ? text.size()
                                       : [&] {
                                             std::u16string wide;
                                             if (!utf8_to_utf16(text, wide)) {
                                                 return std::size_t{0};
                                             }
                                             return wide.size();
                                         }();
    const std::uint32_t needed =
        static_cast<std::uint32_t>(text_units) + 1;
    if (buffer == nullptr || *size < needed) {
        // The Ex form's overflow answer includes the terminator and names
        // ERROR_MORE_DATA, which is not the error `GetComputerName` uses
        // for the same state -- the difference is native behaviour a
        // caller branches on.
        *size = needed;
        set_last_error(kErrorMoreData);
        return 0;
    }
    std::u16string wide;
    if constexpr (sizeof(C) == sizeof(char)) {
        for (std::size_t i = 0; i < text.size(); ++i) {
            buffer[i] = static_cast<C>(text[i]);
        }
    } else {
        if (!utf8_to_utf16(text, wide)) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        for (std::size_t i = 0; i < wide.size(); ++i) {
            buffer[i] = static_cast<C>(wide[i]);
        }
    }
    buffer[text_units] = static_cast<C>(0);
    *size = static_cast<std::uint32_t>(text_units);
    set_last_error(0);
    return 1;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t k32p_GetComputerNameExW(
    std::uint32_t format, char16_t* buffer, std::uint32_t* size) noexcept {
    return get_computer_name_ex(format, buffer, size);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_GetComputerNameExA(
    std::uint32_t format, char* buffer, std::uint32_t* size) noexcept {
    return get_computer_name_ex(format, buffer, size);
}

// ---------------------------------------------------------------------------
// System information and the processor
// ---------------------------------------------------------------------------

namespace {

void fill_system_info(void* out) noexcept {
    const long page_size = ::sysconf(_SC_PAGESIZE);
    long processors = ::sysconf(_SC_NPROCESSORS_ONLN);
    if (processors < 1) {
        processors = 1;
    }
    std::uint64_t mask = 0;
    if (processors >= 64) {
        mask = ~std::uint64_t(0);
    } else {
        mask = (std::uint64_t(1) << processors) - 1;
    }
    write_u16(out, SystemInfoLayout::kArchitecture,
              kProcessorArchitectureAmd64);
    write_u16(out, SystemInfoLayout::kReserved, 0);
    write_u32(out, SystemInfoLayout::kPageSize,
              static_cast<std::uint32_t>(page_size));
    write_ptr(out, SystemInfoLayout::kMinAppAddress, kMinApplicationAddress);
    write_ptr(out, SystemInfoLayout::kMaxAppAddress, kMaxApplicationAddress);
    write_ptr(out, SystemInfoLayout::kProcessorMask, mask);
    write_u32(out, SystemInfoLayout::kNumberOfProcessors,
              static_cast<std::uint32_t>(processors));
    write_u32(out, SystemInfoLayout::kProcessorType, kProcessorAmdX8664);
    write_u32(out, SystemInfoLayout::kGranularity, kAllocationGranularity);
    write_u16(out, SystemInfoLayout::kProcessorLevel, kProcessorLevel);
    write_u16(out, SystemInfoLayout::kProcessorRevision, kProcessorRevision);
}

}  // namespace

extern "C" __attribute__((ms_abi)) void k32p_GetSystemInfo(void* out) noexcept {
    if (out == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return;
    }
    fill_system_info(out);
}

extern "C" __attribute__((ms_abi)) void k32p_GetNativeSystemInfo(
    void* out) noexcept {
    // The guest is always the native architecture here: there is no WOW64
    // layer for it to differ from.
    if (out == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return;
    }
    fill_system_info(out);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_IsProcessorFeaturePresent(
    std::uint32_t feature) noexcept {
    // The x86 features are answered from the compiler's CPU feature probe;
    // a feature this runtime has no probe for answers "absent", which is
    // what native answers for an index it does not know either.
    __builtin_cpu_init();
    switch (feature) {
    case kPfFloatingPointPrecisionErrata:
    case kPfFloatingPointEmulated:
        return 0;
    case kPfCompareExchangeDouble:
        // `cmpxchg8b` is baseline on x86-64.
        return 1;
    case kPfMmx:
        return __builtin_cpu_supports("mmx") ? 1 : 0;
    case kPfXmmi:
        return __builtin_cpu_supports("sse") ? 1 : 0;
    case kPf3DNow:
        return 0;
    case kPfRdtsc:
        return 1;
    case kPfPae:
        // Long mode's page tables are PAE's; there is no x86-64 host
        // without it.
        return 1;
    case kPfXmmi64:
        return __builtin_cpu_supports("sse2") ? 1 : 0;
    case kPfDaz:
    case kPfCompareExchange128:
    case kPfCompare64Exchange128:
    case kPfChannels:
    case kPfSlat:
    case kPfVirtFirmware:
    case kPfRdtscp:
    case kPfRdpid:
    case kPfMonitorx:
        return 0;
    case kPfNx:
        // No-execute paging is part of long mode and the host kernel
        // enforces it.
        return 1;
    case kPfSse3:
        return __builtin_cpu_supports("sse3") ? 1 : 0;
    case kPfXsave:
        return __builtin_cpu_supports("xsave") ? 1 : 0;
    case kPfRdwrFsGsBase:
        return __builtin_cpu_supports("fsgsbase") ? 1 : 0;
    case kPfFastFail:
        // `__fastfail` is a software protocol any guest can use.
        return 1;
    case kPfRdrand:
        return __builtin_cpu_supports("rdrnd") ? 1 : 0;
    case kPfSsse3:
        return __builtin_cpu_supports("ssse3") ? 1 : 0;
    case kPfSse41:
        return __builtin_cpu_supports("sse4.1") ? 1 : 0;
    case kPfSse42:
        return __builtin_cpu_supports("sse4.2") ? 1 : 0;
    case kPfAvx:
        return __builtin_cpu_supports("avx") ? 1 : 0;
    case kPfAvx2:
        return __builtin_cpu_supports("avx2") ? 1 : 0;
    case kPfAvx512F:
        return __builtin_cpu_supports("avx512f") ? 1 : 0;
    default:
        return 0;
    }
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32p_GetCurrentProcessorNumber() noexcept {
    const int cpu = ::sched_getcpu();
    return cpu < 0 ? 0 : static_cast<std::uint32_t>(cpu);
}

extern "C" __attribute__((ms_abi)) void k32p_GetCurrentProcessorNumberEx(
    void* out) noexcept {
    // PROCESSOR_NUMBER: a 16-bit group, an 8-bit number, an 8-bit
    // reserved byte. This runtime answers group 0; a host with more than
    // 256 logical processors would truncate, and no such host serves a
    // guest here.
    if (out == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return;
    }
    const int cpu = ::sched_getcpu();
    auto* bytes = static_cast<std::uint8_t*>(out);
    bytes[0] = 0;  // group
    bytes[1] = 0;  // high byte of the number field
    bytes[2] = cpu < 0 ? 0 : static_cast<std::uint8_t>(cpu & 0xFF);
    bytes[3] = 0;  // reserved
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_FlushInstructionCache(
    std::uint64_t handle, const void* base, std::uint64_t size) noexcept {
    // The host compiler's own cache maintenance covers the guest's code:
    // a guest that writes instructions has done so through this process's
    // memory, and the builtin is the only answer the host ABI has. Native
    // returns success unconditionally on x86, whose caches are coherent
    // for software's purposes.
    (void)handle;
    __builtin___clear_cache(
        const_cast<char*>(static_cast<const char*>(base)),
        const_cast<char*>(static_cast<const char*>(base) +
                          static_cast<std::size_t>(size)));
    set_last_error(0);
    return 1;
}

// ---------------------------------------------------------------------------
// Process handles and their attributes
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint64_t k32p_OpenProcess(
    std::uint32_t access, std::int32_t inherit, std::uint32_t pid) noexcept {
    // The access rights and the inherit flag describe a security model
    // this runtime has nothing to enforce against; every handle it issues
    // is as strong as the caller's own process.
    (void)access;
    (void)inherit;
    if (pid == 0 || (pid != current_pid() && !host_pid_exists(pid))) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (pid == current_pid()) {
        return kCurrentProcessPseudo;
    }
    const std::uint64_t handle = g_next_process_handle++;
    g_process_handles.emplace(handle, pid);
    return handle;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32p_GetProcessId(
    std::uint64_t handle) noexcept {
    if (handle == kCurrentProcessPseudo) {
        return current_pid();
    }
    const auto it = g_process_handles.find(handle);
    if (it == g_process_handles.end()) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    return it->second;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_GetExitCodeProcess(
    std::uint64_t handle, std::uint32_t* code) noexcept {
    if (code == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (handle != kCurrentProcessPseudo &&
        g_process_handles.find(handle) == g_process_handles.end()) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    // The process that could record an exit code is the process that is
    // gone; for as long as the guest can ask, the answer is "still
    // running".
    *code = kStillActive;
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32p_GetProcessVersion(
    std::uint32_t pid) noexcept {
    if (pid != 0 && pid != current_pid() && !host_pid_exists(pid)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The version word is the one this runtime presents, and it is the
    // same for every image it would load, which is why other processes'
    // ids answer it too.
    return kProcessVersionWord;
}

namespace {

// The priority class this runtime serves. One process, one class: the
// value is stored rather than read back from the host scheduler, because
// the guest's class is what a guest sets and reads, and mapping it onto
// `setpriority` would answer a different question.
std::uint32_t g_priority_class = kPriorityNormal;

std::uint32_t g_shutdown_level = kShutdownLevelDefault;
std::uint32_t g_shutdown_flags = kShutdownFlagsDefault;

std::uint64_t g_working_set_min = kWorkingSetMinDefault;
std::uint64_t g_working_set_max = kWorkingSetMaxDefault;

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t k32p_GetPriorityClass(
    std::uint64_t handle) noexcept {
    if (handle == kCurrentProcessPseudo) {
        set_last_error(0);
        return g_priority_class;
    }
    const auto it = g_process_handles.find(handle);
    if (it == g_process_handles.end()) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    // Another process's class is one this runtime cannot read.
    set_last_error(kErrorAccessDenied);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_SetPriorityClass(
    std::uint64_t handle, std::uint32_t priority) noexcept {
    if (handle != kCurrentProcessPseudo &&
        g_process_handles.find(handle) == g_process_handles.end()) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (handle != kCurrentProcessPseudo) {
        set_last_error(kErrorAccessDenied);
        return 0;
    }
    switch (priority) {
    case kPriorityNormal:
    case kPriorityIdle:
    case kPriorityHigh:
    case kPriorityRealtime:
    case kPriorityBelowNormal:
    case kPriorityAboveNormal:
        g_priority_class = priority;
        set_last_error(0);
        return 1;
    default:
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_GetProcessShutdownParameters(
    std::uint32_t* level, std::uint32_t* flags) noexcept {
    if (level == nullptr || flags == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    *level = g_shutdown_level;
    *flags = g_shutdown_flags;
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_SetProcessShutdownParameters(
    std::uint32_t level, std::uint32_t flags) noexcept {
    // The relative order among shutdown callbacks is a fact only the
    // process's own exit walk could honour; the values are recorded, and
    // the guest's exit path is the single one the process layer installed.
    g_shutdown_level = level;
    g_shutdown_flags = flags;
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_GetProcessWorkingSetSize(
    std::uint64_t handle, std::uint64_t* minimum,
    std::uint64_t* maximum) noexcept {
    if (minimum == nullptr || maximum == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (handle != kCurrentProcessPseudo) {
        if (g_process_handles.find(handle) == g_process_handles.end()) {
            set_last_error(kErrorInvalidHandle);
        } else {
            set_last_error(kErrorAccessDenied);
        }
        return 0;
    }
    *minimum = g_working_set_min;
    *maximum = g_working_set_max;
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_SetProcessWorkingSetSize(
    std::uint64_t handle, std::uint64_t minimum, std::uint64_t maximum) noexcept {
    if (handle != kCurrentProcessPseudo) {
        if (g_process_handles.find(handle) == g_process_handles.end()) {
            set_last_error(kErrorInvalidHandle);
        } else {
            set_last_error(kErrorAccessDenied);
        }
        return 0;
    }
    if (minimum > maximum) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The all-ones pair is the "trim my working set" request. The values
    // are stored, and no trim is performed: this runtime's memory belongs
    // to one address space whose pages the guest manages through the
    // virtual-memory calls instead.
    g_working_set_min = minimum;
    g_working_set_max = maximum;
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_ProcessIdToSessionId(
    std::uint32_t pid, std::uint32_t* session) noexcept {
    if (session == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (pid == 0 || (pid != current_pid() && !host_pid_exists(pid))) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // Every process this runtime can name is in its one session, which is
    // session 0 -- the session a service-session-less Windows also
    // answers for its own console processes.
    *session = 0;
    set_last_error(0);
    return 1;
}

// ---------------------------------------------------------------------------
// Toolhelp
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint64_t k32p_CreateToolhelp32Snapshot(
    std::uint32_t flags, std::uint32_t pid) noexcept {
    if (flags == 0 || (flags & ~kSnapKnown) != 0) {
        set_last_error(kErrorInvalidParameter);
        return kInvalidHandleValue;
    }
    Snapshot snapshot;
    if ((flags & kSnapHeapList) != 0) {
        if (pid != 0 && pid != current_pid()) {
            set_last_error(kErrorAccessDenied);
            return kInvalidHandleValue;
        }
        snapshot.heaps.push_back(process_heap_handle());
    }
    if ((flags & kSnapProcess) != 0) {
        enumerate_processes(snapshot.procs);
    }
    if ((flags & kSnapThread) != 0) {
        enumerate_threads(pid, snapshot.threads);
    }
    if ((flags & (kSnapModule | kSnapModule32)) != 0) {
        if (pid != 0 && pid != current_pid()) {
            set_last_error(kErrorInvalidParameter);
            return kInvalidHandleValue;
        }
        enumerate_modules(snapshot.modules);
    }
    g_snapshots.push_back(std::move(snapshot));
    return kSnapshotHandleBase +
           static_cast<std::uint64_t>(g_snapshots.size() - 1);
}

namespace {

// The fills for each entry kind. Counters the host has no per-row answer
// for (the module usage counts, the thread priority) carry the values a
// freshly started native process shows; they are stated here rather than
// guessed per call.

void fill_process(void* entry, const ProcEntry& item, bool wide) noexcept {
    write_u32(entry, ProcessEntryLayout::kUsage, 0);
    write_u32(entry, ProcessEntryLayout::kProcessId, item.pid);
    write_ptr(entry, ProcessEntryLayout::kHeapId, 0);
    write_u32(entry, ProcessEntryLayout::kModuleId, 0);
    write_u32(entry, ProcessEntryLayout::kThreads, item.threads);
    write_u32(entry, ProcessEntryLayout::kParentId, item.parent);
    write_u32(entry, ProcessEntryLayout::kPriority, kPriorityNormal);
    write_u32(entry, ProcessEntryLayout::kFlags, 0);
    const std::size_t chars =
        wide ? ProcessEntryLayout::kBytesW - ProcessEntryLayout::kExeFile
             : ProcessEntryLayout::kBytesA - ProcessEntryLayout::kExeFile;
    if (wide) {
        put_field(item.name,
                  reinterpret_cast<char16_t*>(
                      static_cast<std::uint8_t*>(entry) +
                      ProcessEntryLayout::kExeFile),
                  chars / 2);
    } else {
        put_field(item.name,
                  static_cast<char*>(entry) + ProcessEntryLayout::kExeFile,
                  chars);
    }
}

void fill_thread(void* entry, const ThreadItem& item) noexcept {
    write_u32(entry, ThreadEntryLayout::kUsage, 0);
    write_u32(entry, ThreadEntryLayout::kThreadId, item.tid);
    write_u32(entry, ThreadEntryLayout::kOwnerId, item.owner);
    // A freshly started native thread's base priority, stated once here.
    constexpr std::uint32_t kThreadBasePriority = 8;
    write_u32(entry, ThreadEntryLayout::kBasePriority, kThreadBasePriority);
    write_u32(entry, ThreadEntryLayout::kDeltaPriority, 0);
    write_u32(entry, ThreadEntryLayout::kFlags, 0);
}

void fill_module(void* entry, const ModuleItem& item, bool wide) noexcept {
    write_u32(entry, ModuleEntryLayout::kModuleId, 0);
    write_u32(entry, ModuleEntryLayout::kProcessId, current_pid());
    write_u32(entry, ModuleEntryLayout::kGlobalUsage, 1);
    write_u32(entry, ModuleEntryLayout::kProcessUsage, 1);
    write_ptr(entry, ModuleEntryLayout::kBaseAddress, item.base);
    write_u32(entry, ModuleEntryLayout::kBaseSize, item.size);
    write_ptr(entry, ModuleEntryLayout::kModuleHandle, item.base);
    if (wide) {
        put_field(item.name,
                  reinterpret_cast<char16_t*>(
                      static_cast<std::uint8_t*>(entry) +
                      ModuleEntryLayout::kModuleName),
                  ModuleEntryLayout::kNameChars);
        put_field(item.path,
                  reinterpret_cast<char16_t*>(
                      static_cast<std::uint8_t*>(entry) +
                      ModuleEntryLayout::kExePath),
                  ModuleEntryLayout::kPathChars);
    } else {
        put_field(item.name,
                  static_cast<char*>(entry) + ModuleEntryLayout::kModuleName,
                  ModuleEntryLayout::kNameChars);
        put_field(item.path,
                  static_cast<char*>(entry) + ModuleEntryLayout::kExePath,
                  ModuleEntryLayout::kPathChars);
    }
}

// The walk every First/Next pair shares: validate the handle, the entry's
// declared size, and the position, then fill and advance. The declared
// size check is the lower bound Wine's toolhelp checks; the filled-in
// `dwSize` is the structure's own size, which is what native writes.
template <typename ItemT>
[[nodiscard]] bool toolhelp_next(std::uint64_t handle, void* entry,
                                 std::size_t struct_bytes,
                                 std::vector<ItemT> Snapshot::* items,
                                 void (*fill)(void*, const ItemT&)) noexcept {
    if (entry == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return false;
    }
    Snapshot* snapshot = find_snapshot(handle);
    if (snapshot == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return false;
    }
    if (read_u32(entry, 0) < struct_bytes) {
        set_last_error(kErrorInsufficientBuffer);
        return false;
    }
    const std::vector<ItemT>& list = snapshot->*items;
    if (snapshot->cursor >= list.size()) {
        set_last_error(kErrorNoMoreFiles);
        return false;
    }
    fill(entry, list[snapshot->cursor]);
    write_u32(entry, 0, static_cast<std::uint32_t>(struct_bytes));
    ++snapshot->cursor;
    set_last_error(0);
    return true;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t k32p_Process32FirstW(
    std::uint64_t handle, void* entry) noexcept {
    Snapshot* snapshot = find_snapshot(handle);
    if (snapshot != nullptr) {
        snapshot->cursor = 0;
    }
    return toolhelp_next<ProcEntry>(
               handle, entry, ProcessEntryLayout::kBytesW, &Snapshot::procs,
               [](void* e, const ProcEntry& item) {
                   fill_process(e, item, true);
               })
               ? 1
               : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_Process32NextW(
    std::uint64_t handle, void* entry) noexcept {
    return toolhelp_next<ProcEntry>(
               handle, entry, ProcessEntryLayout::kBytesW, &Snapshot::procs,
               [](void* e, const ProcEntry& item) {
                   fill_process(e, item, true);
               })
               ? 1
               : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_Process32FirstA(
    std::uint64_t handle, void* entry) noexcept {
    Snapshot* snapshot = find_snapshot(handle);
    if (snapshot != nullptr) {
        snapshot->cursor = 0;
    }
    return toolhelp_next<ProcEntry>(
               handle, entry, ProcessEntryLayout::kBytesA, &Snapshot::procs,
               [](void* e, const ProcEntry& item) {
                   fill_process(e, item, false);
               })
               ? 1
               : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_Process32NextA(
    std::uint64_t handle, void* entry) noexcept {
    return toolhelp_next<ProcEntry>(
               handle, entry, ProcessEntryLayout::kBytesA, &Snapshot::procs,
               [](void* e, const ProcEntry& item) {
                   fill_process(e, item, false);
               })
               ? 1
               : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_Thread32First(
    std::uint64_t handle, void* entry) noexcept {
    Snapshot* snapshot = find_snapshot(handle);
    if (snapshot != nullptr) {
        snapshot->cursor = 0;
    }
    return toolhelp_next<ThreadItem>(handle, entry, ThreadEntryLayout::kBytes,
                                     &Snapshot::threads, fill_thread)
               ? 1
               : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_Thread32Next(
    std::uint64_t handle, void* entry) noexcept {
    return toolhelp_next<ThreadItem>(handle, entry, ThreadEntryLayout::kBytes,
                                     &Snapshot::threads, fill_thread)
               ? 1
               : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_Module32FirstW(
    std::uint64_t handle, void* entry) noexcept {
    Snapshot* snapshot = find_snapshot(handle);
    if (snapshot != nullptr) {
        snapshot->cursor = 0;
    }
    return toolhelp_next<ModuleItem>(
               handle, entry, ModuleEntryLayout::kBytesW, &Snapshot::modules,
               [](void* e, const ModuleItem& item) {
                   fill_module(e, item, true);
               })
               ? 1
               : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_Module32NextW(
    std::uint64_t handle, void* entry) noexcept {
    return toolhelp_next<ModuleItem>(
               handle, entry, ModuleEntryLayout::kBytesW, &Snapshot::modules,
               [](void* e, const ModuleItem& item) {
                   fill_module(e, item, true);
               })
               ? 1
               : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_Module32FirstA(
    std::uint64_t handle, void* entry) noexcept {
    Snapshot* snapshot = find_snapshot(handle);
    if (snapshot != nullptr) {
        snapshot->cursor = 0;
    }
    return toolhelp_next<ModuleItem>(
               handle, entry, ModuleEntryLayout::kBytesA, &Snapshot::modules,
               [](void* e, const ModuleItem& item) {
                   fill_module(e, item, false);
               })
               ? 1
               : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_Module32NextA(
    std::uint64_t handle, void* entry) noexcept {
    return toolhelp_next<ModuleItem>(
               handle, entry, ModuleEntryLayout::kBytesA, &Snapshot::modules,
               [](void* e, const ModuleItem& item) {
                   fill_module(e, item, false);
               })
               ? 1
               : 0;
}

namespace {

// The heap-list walk is its own because `dwSize` there is pointer-width.
[[nodiscard]] bool heap_list_next(std::uint64_t handle, void* entry) noexcept {
    if (entry == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return false;
    }
    Snapshot* snapshot = find_snapshot(handle);
    if (snapshot == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return false;
    }
    if (read_ptr(entry, HeapListLayout::kSize) < HeapListLayout::kBytes) {
        set_last_error(kErrorInsufficientBuffer);
        return false;
    }
    if (snapshot->cursor >= snapshot->heaps.size()) {
        set_last_error(kErrorNoMoreFiles);
        return false;
    }
    write_ptr(entry, HeapListLayout::kSize, HeapListLayout::kBytes);
    write_u32(entry, HeapListLayout::kProcessId, current_pid());
    write_ptr(entry, HeapListLayout::kHeapId,
              snapshot->heaps[snapshot->cursor]);
    write_u32(entry, HeapListLayout::kFlags, 0);
    ++snapshot->cursor;
    set_last_error(0);
    return true;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t k32p_Heap32ListFirst(
    std::uint64_t handle, void* entry) noexcept {
    Snapshot* snapshot = find_snapshot(handle);
    if (snapshot != nullptr) {
        snapshot->cursor = 0;
    }
    return heap_list_next(handle, entry) ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_Heap32ListNext(
    std::uint64_t handle, void* entry) noexcept {
    return heap_list_next(handle, entry) ? 1 : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_Heap32First(
    void* entry, std::uint32_t pid, std::uint64_t heap_id) noexcept {
    (void)pid;
    (void)heap_id;
    if (entry == nullptr ||
        read_ptr(entry, HeapEntryLayout::kSize) < HeapEntryLayout::kBytes) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // Block-level enumeration needs a recorded block table, which this
    // runtime's heap does not keep. An empty answer is the same one
    // native gives for a heap with no blocks.
    set_last_error(kErrorNoMoreFiles);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_Heap32Next(
    void* entry) noexcept {
    if (entry == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(kErrorNoMoreFiles);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_Toolhelp32ReadProcessMemory(
    std::uint32_t pid, const void* base, void* buffer, std::uint64_t size,
    std::uint64_t* read) noexcept {
    if (read != nullptr) {
        *read = 0;
    }
    if (size != 0 && (base == nullptr || buffer == nullptr)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The guest's address space is this process's, so a read of its own
    // id is a copy. Another process's memory belongs to a different
    // address space this runtime has no window into.
    if (pid != 0 && pid != current_pid() &&
        pid != static_cast<std::uint32_t>(::getpid())) {
        set_last_error(kErrorAccessDenied);
        return 0;
    }
    if (size != 0) {
        std::memcpy(buffer, base, static_cast<std::size_t>(size));
    }
    if (read != nullptr) {
        *read = size;
    }
    set_last_error(0);
    return 1;
}

// ---------------------------------------------------------------------------
// Thread creation and management
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint64_t k32p_CreateThread(
    void* attributes, std::uint64_t stack_size, std::uint64_t start,
    void* parameter, std::uint32_t flags, std::uint32_t* thread_id) noexcept {
    // A second guest thread needs its own TEB, its own TLS slots and its
    // own stack inside the address space, and a scheduler for the guest's
    // fault and exception state. The runtime runs one guest thread by
    // design; a stub that returned a handle would hand the caller a thread
    // that never runs.
    (void)attributes;
    (void)stack_size;
    (void)start;
    (void)parameter;
    (void)flags;
    (void)thread_id;
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32p_OpenThread(
    std::uint32_t access, std::int32_t inherit, std::uint32_t tid) noexcept {
    (void)access;
    (void)inherit;
    if (tid == 0 || tid != current_tid()) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return kCurrentThreadPseudo;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_GetExitCodeThread(
    std::uint64_t handle, std::uint32_t* code) noexcept {
    if (code == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (handle != kCurrentThreadPseudo) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    *code = kStillActive;
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32p_SuspendThread(
    std::uint64_t handle) noexcept {
    // The one guest thread is the thread that would do the suspending;
    // suspending it wedges the process, and there is no second thread to
    // suspend instead. `(DWORD)-1` is the failure answer.
    (void)handle;
    set_last_error(kErrorCallNotImplemented);
    return 0xFFFFFFFFU;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32p_ResumeThread(
    std::uint64_t handle) noexcept {
    (void)handle;
    set_last_error(kErrorCallNotImplemented);
    return 0xFFFFFFFFU;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_TerminateThread(
    std::uint64_t handle, std::uint32_t code) noexcept {
    // Killing the guest's only thread is killing the guest, and
    // `TerminateThread`'s contract (the thread dies wherever it stands,
    // holding its locks) has no honest implementation without a thread
    // model. A guest that wants to end the process has `ExitProcess`.
    (void)handle;
    (void)code;
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

extern "C" __attribute__((ms_abi)) void k32p_ExitThread(
    std::uint32_t code) noexcept {
    // The guest runs on one thread, so the thread calling `ExitThread` is
    // the last thread, and Windows ends a process whose last thread
    // exits. The exit path is the same one `ExitProcess` uses.
    k32_ExitProcess(code);
    __builtin_unreachable();
}

// ---------------------------------------------------------------------------
// Threadpool creation
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint64_t k32p_CreateThreadpool(
    void* reserved) noexcept {
    // The threadpool family needs the pool itself: worker threads, a
    // timer and a callback environment. None exist without the thread
    // model `CreateThread`'s refusal describes.
    (void)reserved;
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32p_CreateThreadpoolWork(
    std::uint64_t callback, void* environment,
    std::uint64_t align_environment) noexcept {
    (void)callback;
    (void)environment;
    (void)align_environment;
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32p_CreateThreadpoolIo(
    std::uint64_t file, std::uint64_t callback, void* context,
    std::uint64_t environment) noexcept {
    (void)file;
    (void)callback;
    (void)context;
    (void)environment;
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32p_CreateThreadpoolCleanupGroup() noexcept {
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

// ---------------------------------------------------------------------------
// Process creation
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t k32p_CreateProcessW(
    const char16_t* application, char16_t* command_line, void* process_attributes,
    void* thread_attributes, std::int32_t inherit_handles, std::uint32_t flags,
    void* environment, const char16_t* current_directory,
    const void* startup_info, void* process_information) noexcept {
    // A child process needs a second address space, a load of the image
    // into it, a TEB/PEB pair, and a parent-child relationship the handle
    // table can express. The runtime loads one image into one space; a
    // success here would hand the caller a PROCESS_INFORMATION it could
    // not use for anything.
    (void)application;
    (void)command_line;
    (void)process_attributes;
    (void)thread_attributes;
    (void)inherit_handles;
    (void)flags;
    (void)environment;
    (void)current_directory;
    (void)startup_info;
    (void)process_information;
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_CreateProcessA(
    const char* application, char* command_line, void* process_attributes,
    void* thread_attributes, std::int32_t inherit_handles, std::uint32_t flags,
    void* environment, const char* current_directory,
    const void* startup_info, void* process_information) noexcept {
    (void)application;
    (void)command_line;
    (void)process_attributes;
    (void)thread_attributes;
    (void)inherit_handles;
    (void)flags;
    (void)environment;
    (void)current_directory;
    (void)startup_info;
    (void)process_information;
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_CreateProcessAsUserW(
    std::uint64_t token, const char16_t* application, char16_t* command_line,
    void* process_attributes, void* thread_attributes,
    std::int32_t inherit_handles, std::uint32_t flags, void* environment,
    const char16_t* current_directory, const void* startup_info,
    void* process_information) noexcept {
    (void)token;
    (void)application;
    (void)command_line;
    (void)process_attributes;
    (void)thread_attributes;
    (void)inherit_handles;
    (void)flags;
    (void)environment;
    (void)current_directory;
    (void)startup_info;
    (void)process_information;
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_CreateProcessAsUserA(
    std::uint64_t token, const char* application, char* command_line,
    void* process_attributes, void* thread_attributes,
    std::int32_t inherit_handles, std::uint32_t flags, void* environment,
    const char* current_directory, const void* startup_info,
    void* process_information) noexcept {
    (void)token;
    (void)application;
    (void)command_line;
    (void)process_attributes;
    (void)thread_attributes;
    (void)inherit_handles;
    (void)flags;
    (void)environment;
    (void)current_directory;
    (void)startup_info;
    (void)process_information;
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_CreateProcessInternalW(
    const char16_t* application, char16_t* command_line,
    void* process_attributes, void* thread_attributes,
    std::int32_t inherit_handles, std::uint32_t flags, void* environment,
    const char16_t* current_directory, const void* startup_info,
    void* process_information, void* new_token) noexcept {
    (void)application;
    (void)command_line;
    (void)process_attributes;
    (void)thread_attributes;
    (void)inherit_handles;
    (void)flags;
    (void)environment;
    (void)current_directory;
    (void)startup_info;
    (void)process_information;
    (void)new_token;
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32p_CreateProcessInternalA(
    const char* application, char* command_line, void* process_attributes,
    void* thread_attributes, std::int32_t inherit_handles, std::uint32_t flags,
    void* environment, const char* current_directory,
    const void* startup_info, void* process_information,
    void* new_token) noexcept {
    (void)application;
    (void)command_line;
    (void)process_attributes;
    (void)thread_attributes;
    (void)inherit_handles;
    (void)flags;
    (void)environment;
    (void)current_directory;
    (void)startup_info;
    (void)process_information;
    (void)new_token;
    set_last_error(kErrorCallNotImplemented);
    return 0;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void add_kernel32_proc(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CreateProcessA", reinterpret_cast<void*>(&k32p_CreateProcessA));
    e("CreateProcessAsUserA",
      reinterpret_cast<void*>(&k32p_CreateProcessAsUserA));
    e("CreateProcessAsUserW",
      reinterpret_cast<void*>(&k32p_CreateProcessAsUserW));
    e("CreateProcessInternalA",
      reinterpret_cast<void*>(&k32p_CreateProcessInternalA));
    e("CreateProcessInternalW",
      reinterpret_cast<void*>(&k32p_CreateProcessInternalW));
    e("CreateProcessW", reinterpret_cast<void*>(&k32p_CreateProcessW));
    e("CreateThread", reinterpret_cast<void*>(&k32p_CreateThread));
    e("CreateThreadpool", reinterpret_cast<void*>(&k32p_CreateThreadpool));
    e("CreateThreadpoolCleanupGroup",
      reinterpret_cast<void*>(&k32p_CreateThreadpoolCleanupGroup));
    e("CreateThreadpoolIo", reinterpret_cast<void*>(&k32p_CreateThreadpoolIo));
    e("CreateThreadpoolWork",
      reinterpret_cast<void*>(&k32p_CreateThreadpoolWork));
    e("CreateToolhelp32Snapshot",
      reinterpret_cast<void*>(&k32p_CreateToolhelp32Snapshot));
    e("ExitThread", reinterpret_cast<void*>(&k32p_ExitThread));
    e("ExpandEnvironmentStringsA",
      reinterpret_cast<void*>(&k32p_ExpandEnvironmentStringsA));
    e("ExpandEnvironmentStringsW",
      reinterpret_cast<void*>(&k32p_ExpandEnvironmentStringsW));
    e("FlushInstructionCache",
      reinterpret_cast<void*>(&k32p_FlushInstructionCache));
    e("GetComputerNameA", reinterpret_cast<void*>(&k32p_GetComputerNameA));
    e("GetComputerNameExA", reinterpret_cast<void*>(&k32p_GetComputerNameExA));
    e("GetComputerNameExW", reinterpret_cast<void*>(&k32p_GetComputerNameExW));
    e("GetComputerNameW", reinterpret_cast<void*>(&k32p_GetComputerNameW));
    e("GetCurrentProcessorNumber",
      reinterpret_cast<void*>(&k32p_GetCurrentProcessorNumber));
    e("GetCurrentProcessorNumberEx",
      reinterpret_cast<void*>(&k32p_GetCurrentProcessorNumberEx));
    e("GetExitCodeProcess", reinterpret_cast<void*>(&k32p_GetExitCodeProcess));
    e("GetExitCodeThread", reinterpret_cast<void*>(&k32p_GetExitCodeThread));
    e("GetNativeSystemInfo",
      reinterpret_cast<void*>(&k32p_GetNativeSystemInfo));
    e("GetPriorityClass", reinterpret_cast<void*>(&k32p_GetPriorityClass));
    e("GetProcessId", reinterpret_cast<void*>(&k32p_GetProcessId));
    e("GetProcessShutdownParameters",
      reinterpret_cast<void*>(&k32p_GetProcessShutdownParameters));
    e("GetProcessVersion", reinterpret_cast<void*>(&k32p_GetProcessVersion));
    e("GetProcessWorkingSetSize",
      reinterpret_cast<void*>(&k32p_GetProcessWorkingSetSize));
    e("GetSystemDirectoryA",
      reinterpret_cast<void*>(&k32p_GetSystemDirectoryA));
    e("GetSystemDirectoryW",
      reinterpret_cast<void*>(&k32p_GetSystemDirectoryW));
    e("GetSystemInfo", reinterpret_cast<void*>(&k32p_GetSystemInfo));
    e("GetWindowsDirectoryA",
      reinterpret_cast<void*>(&k32p_GetWindowsDirectoryA));
    e("GetWindowsDirectoryW",
      reinterpret_cast<void*>(&k32p_GetWindowsDirectoryW));
    e("Heap32First", reinterpret_cast<void*>(&k32p_Heap32First));
    e("Heap32ListFirst", reinterpret_cast<void*>(&k32p_Heap32ListFirst));
    e("Heap32ListNext", reinterpret_cast<void*>(&k32p_Heap32ListNext));
    e("Heap32Next", reinterpret_cast<void*>(&k32p_Heap32Next));
    e("IsProcessorFeaturePresent",
      reinterpret_cast<void*>(&k32p_IsProcessorFeaturePresent));
    e("Module32First", reinterpret_cast<void*>(&k32p_Module32FirstA));
    e("Module32FirstW", reinterpret_cast<void*>(&k32p_Module32FirstW));
    e("Module32Next", reinterpret_cast<void*>(&k32p_Module32NextA));
    e("Module32NextW", reinterpret_cast<void*>(&k32p_Module32NextW));
    e("OpenProcess", reinterpret_cast<void*>(&k32p_OpenProcess));
    e("OpenThread", reinterpret_cast<void*>(&k32p_OpenThread));
    e("Process32First", reinterpret_cast<void*>(&k32p_Process32FirstA));
    e("Process32FirstW", reinterpret_cast<void*>(&k32p_Process32FirstW));
    e("Process32Next", reinterpret_cast<void*>(&k32p_Process32NextA));
    e("Process32NextW", reinterpret_cast<void*>(&k32p_Process32NextW));
    e("ProcessIdToSessionId",
      reinterpret_cast<void*>(&k32p_ProcessIdToSessionId));
    e("ResumeThread", reinterpret_cast<void*>(&k32p_ResumeThread));
    e("SetPriorityClass", reinterpret_cast<void*>(&k32p_SetPriorityClass));
    e("SetProcessShutdownParameters",
      reinterpret_cast<void*>(&k32p_SetProcessShutdownParameters));
    e("SetProcessWorkingSetSize",
      reinterpret_cast<void*>(&k32p_SetProcessWorkingSetSize));
    e("SuspendThread", reinterpret_cast<void*>(&k32p_SuspendThread));
    e("TerminateThread", reinterpret_cast<void*>(&k32p_TerminateThread));
    e("Thread32First", reinterpret_cast<void*>(&k32p_Thread32First));
    e("Thread32Next", reinterpret_cast<void*>(&k32p_Thread32Next));
    e("Toolhelp32ReadProcessMemory",
      reinterpret_cast<void*>(&k32p_Toolhelp32ReadProcessMemory));
}

}  // namespace occ::runtime::winabi

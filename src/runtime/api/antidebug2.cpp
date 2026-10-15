// The anti-debug and machine-presentation surface, second slice.
//
// The first slice (ntdll_antidebug.cpp) answers the questions an anti-debug
// checker actually asks: is a debugger attached, is the kernel debugger on,
// is this process its own debugger. This slice carries the calls that sit on
// the same shelf -- the debug-filter queries, the exception raise/continue
// pair, the thread suspend/resume and APC primitives, the timer-resolution
// queries -- and the handful of machine-presentation calls a checker or a
// probe reaches for beside them: the WOW64 questions, the DEP policy, the
// process times, the volume and locale queries.
//
// The shape of the answers follows the domain's rule. A call that this
// runtime can answer from its own machinery is answered for real:
// `NtSuspendThread`/`NtResumeThread` bridge the guest-thread table,
// `NtRaiseException` and `NtContinue` ride the SEH dispatch the raise path
// already owns, `NtTestAlert` and `NtDelayExecution` service the real APC
// queues, and the disk and locale queries read the host's actual filesystem
// and locale. A call whose contract names a subsystem this runtime does not
// have is refused with the subsystem named at the refusal, never answered
// with a plausible value: `NtWaitForDebugEvent` answers the status a process
// without a debug port gets, `NtSystemDebugControl` answers access denied
// the way a caller without the kernel-debug privilege gets, `Wow64*` refuses
// because there is no WOW64 layer, and `SetProcessDEPPolicy` fails the way
// it fails on any 64-bit Windows.
//
// The one contract in this file that has no public documentation --
// `GetProcessorInformation`, an undocumented kernel32 export probed by
// unpackers -- is implemented under a documented assumption (see the
// function's comment and the search result cited there), filled from real
// host CPU data rather than from a constant.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/dos_path.h"
#include "occ/runtime/guest_module.h"
#include "occ/runtime/seh.h"
#include "occ/runtime/winabi.h"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

namespace occ::runtime::winabi {

// The entry points from other translation units this file bridges to. The
// `extern "C"` ms_abi declarations follow the ldr_ext.cpp precedent: the
// functions are exported entries of other domains, and each is declared here
// rather than pulled from a header so that a signature change in the owning
// file is caught by the linker rather than silently re-read.

// The guest-thread bridge: suspending and resuming a guest thread by its
// handle, owned by guest_thread.cpp. Both answer `kWaitFailed` for a handle
// the table does not recognise.
[[nodiscard]] std::uint32_t resume_guest_thread(std::uint64_t handle,
                                                 std::uint32_t* previous) noexcept;
[[nodiscard]] std::uint32_t suspend_guest_thread(std::uint64_t handle) noexcept;

// The version record the A spelling fills, which the W spelling reuses for
// the four version numbers before spelling the service-pack string itself.
extern "C" __attribute__((ms_abi)) std::int32_t k32si_GetVersionExA(
    std::uint8_t* info) noexcept;

// The product-type table, owned by the Rtl memory slice.
extern "C" __attribute__((ms_abi)) std::int32_t nr2_RtlGetProductInfo(
    std::uint32_t major, std::uint32_t minor, std::uint8_t spor,
    std::uint8_t product_type, std::uint32_t* product) noexcept;

// The temporary-name maker, owned by proc_ext.cpp.
extern "C" __attribute__((ms_abi)) std::uint32_t k32pe_GetTempFileNameA(
    const char* path, const char* prefix, std::uint32_t unique,
    char* out) noexcept;

// The module query, owned by kernel32_ctx2.cpp, which carries the decision
// for both spellings.
extern "C" __attribute__((ms_abi)) std::int32_t k32c2_GetModuleHandleExW(
    std::uint32_t flags, const char16_t* name, void** module) noexcept;

// The context restore the continue path ends in; it does not return.
extern "C" __attribute__((ms_abi, noreturn)) void k32c2_SetThreadContext(
    std::uint64_t thread, const void* context) noexcept;

// The process-termination path the unhandled-raise ends in.
extern "C" __attribute__((ms_abi)) void k32_ExitProcess(
    std::uint32_t code) noexcept;

// The process and thread ids the handle checks compare against.
extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetCurrentProcessId() noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetCurrentThreadId() noexcept;

namespace {

// ---------------------------------------------------------------------------
// The NT statuses this file answers with
// ---------------------------------------------------------------------------
//
// An NTSTATUS is a 32-bit value whose top bits carry the severity; the names
// below are the subset the answers use, spelled the way the rest of the Rtl
// surface spells them.

using Ntstatus = std::uint32_t;

constexpr Ntstatus kStSuccess = 0x00000000;
constexpr Ntstatus kStAlarmed = 0x00000101;       // STATUS_ALERTED
constexpr Ntstatus kStUnsuccessful = 0xC0000001;
constexpr Ntstatus kStNotImplemented = 0xC0000002;
constexpr Ntstatus kStInvalidParameter = 0xC000000D;
constexpr Ntstatus kStInvalidHandle = 0xC0000008;
constexpr Ntstatus kStAccessDenied = 0xC0000022;
// STATUS_PORT_NOT_SET: the answer a process without a debug port receives,
// which is the shape "there is no debugger here" takes.
constexpr Ntstatus kStPortNotSet = 0xC0000353;

// The sentinel the guest-thread bridge answers for a handle it does not
// know. It is the Win32 `WAIT_FAILED` value, and no legitimate previous
// suspend count can reach it, so the mapping to the NT invalid-handle status
// is unambiguous.
constexpr std::uint32_t kWaitFailed = 0xFFFFFFFFu;

// The process this runtime serves, for the calls that ask "which process am
// I". The same rule the first anti-debug slice uses: the all-ones pseudo
// handle and the current process id both name this process, anything else is
// refused rather than silently treated as self.
[[nodiscard]] bool is_self_process(std::uint64_t handle) noexcept {
    constexpr std::uint64_t kCurrentProcess = ~std::uint64_t{0};
    if (handle == kCurrentProcess) {
        return true;
    }
    if (handle == 0) {
        return false;
    }
    return handle == static_cast<std::uint64_t>(k32_GetCurrentProcessId());
}

// Whether a handle names the calling thread: the all-ones-minus-one pseudo
// handle and the current thread id. The guest-thread table keeps no public
// handle-to-host-tid mapping, and the thread-local clocks below can only be
// read for the caller, so the calling thread is the boundary every thread
// query in this file draws.
[[nodiscard]] bool is_current_thread(std::uint64_t handle) noexcept {
    constexpr std::uint64_t kCurrentThread = ~std::uint64_t{1};  // NtCurrentThread()
    if (handle == kCurrentThread) {
        return true;
    }
    if (handle == 0) {
        return false;
    }
    return handle == static_cast<std::uint64_t>(k32_GetCurrentThreadId());
}

// ---------------------------------------------------------------------------
// Host reading: files, the clock, the processor set
// ---------------------------------------------------------------------------

// Reads a whole small file, the way the /proc and /sys queries need to. A
// file that cannot be opened is simply absent to this runtime.
[[nodiscard]] bool read_file(const char* path, std::string& out) noexcept {
    const int fd = ::open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    std::string data;
    char chunk[4096];
    for (;;) {
        const ::ssize_t got = ::read(fd, chunk, sizeof(chunk));
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            ::close(fd);
            return false;
        }
        if (got == 0) {
            break;
        }
        data.append(chunk, static_cast<std::size_t>(got));
    }
    ::close(fd);
    out = std::move(data);
    return true;
}

// The FILETIME of the host process's start. The guest begins when the host
// process begins, and the machine's own record of that moment is
// /proc/self/stat (field 22: start time in clock ticks since boot) and
// /proc/stat (`btime`: the boot epoch). A host without those files falls
// back to "now", which is the smallest lie a runtime without a start record
// can tell and is what `GetProcessTimes` reports for creation in that case.
[[nodiscard]] std::uint64_t process_start_filetime() noexcept {
    constexpr std::uint64_t kSeconds1601To1970 = 134774ULL * 86400ULL;
    constexpr std::uint64_t kTicksPerSecond = 10000000ULL;
    const long hz = ::sysconf(_SC_CLK_TCK);
    if (hz <= 0) {
        return 0;
    }
    std::string stat;
    if (!read_file("/proc/self/stat", stat)) {
        return 0;
    }
    // The comm field may contain spaces and parentheses, so the parse starts
    // after the last ')' and counts the 20 fields that precede starttime
    // (the fields are state, ppid, pgrp, session, tty_nr, tpgid, flags,
    // minflt, cminflt, majflt, cmajflt, utime, stime, cutime, cstime,
    // priority, nice, num_threads, itrealvalue, then starttime).
    const std::size_t close = stat.rfind(')');
    if (close == std::string::npos) {
        return 0;
    }
    std::uint64_t start_ticks = 0;
    {
        std::size_t pos = close + 1;
        for (int field = 0; field < 20; ++field) {
            while (pos < stat.size() && (stat[pos] == ' ' || stat[pos] == '\t')) {
                ++pos;
            }
            const std::size_t begin = pos;
            while (pos < stat.size() && stat[pos] != ' ' && stat[pos] != '\t') {
                ++pos;
            }
            if (field == 19) {
                char* end = nullptr;
                const unsigned long long value =
                    std::strtoull(stat.c_str() + begin, &end, 10);
                if (end == stat.c_str() + begin) {
                    return 0;
                }
                start_ticks = static_cast<std::uint64_t>(value);
            }
        }
    }
    std::string stat_boot;
    if (!read_file("/proc/stat", stat_boot)) {
        return 0;
    }
    std::uint64_t btime = 0;
    {
        const std::size_t mark = stat_boot.find("btime ");
        if (mark == std::string::npos) {
            return 0;
        }
        char* end = nullptr;
        const unsigned long long value =
            std::strtoull(stat_boot.c_str() + mark + 6, &end, 10);
        if (end == stat_boot.c_str() + mark + 6) {
            return 0;
        }
        btime = static_cast<std::uint64_t>(value);
    }
    const std::uint64_t epoch = btime + start_ticks / static_cast<std::uint64_t>(hz);
    return (epoch + kSeconds1601To1970) * kTicksPerSecond;
}

// A `struct timeval` as the 100-nanosecond ticks a FILETIME or a duration
// count carries.
[[nodiscard]] std::uint64_t ticks_from_timeval(const struct timeval& tv) noexcept {
    return static_cast<std::uint64_t>(tv.tv_sec) * 10000000ULL +
           static_cast<std::uint64_t>(tv.tv_usec) * 10ULL;
}

// The current real time as a FILETIME, or zero when the clock cannot be
// read. The 1601-to-1970 offset is the one every clock conversion in this
// runtime carries.
[[nodiscard]] std::uint64_t now_ticks_or_zero() noexcept {
    constexpr std::uint64_t kSeconds1601To1970 = 134774ULL * 86400ULL;
    constexpr std::uint64_t kTicksPerSecond = 10000000ULL;
    struct timespec ts {};
    if (::clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return (static_cast<std::uint64_t>(ts.tv_sec) + kSeconds1601To1970) *
               kTicksPerSecond +
           static_cast<std::uint64_t>(ts.tv_nsec) / 100ULL;
}

// Sleeps a number of milliseconds in bounded chunks, so a long wait is
// still interruptible and the arithmetic stays in range.
void sleep_ms_loop(std::uint64_t ms) noexcept {
    constexpr std::uint64_t kChunkMs = 1000000ULL;
    while (ms > 0) {
        const std::uint64_t chunk = ms > kChunkMs ? kChunkMs : ms;
        struct timespec ts {};
        ts.tv_sec = static_cast<time_t>(chunk / 1000ULL);
        ts.tv_nsec = static_cast<long>(chunk % 1000ULL) * 1000000L;
        while (::nanosleep(&ts, &ts) != 0 && errno == EINTR) {
        }
        ms -= chunk;
    }
}

// The mask a `cpu_set_t` carries, as a 64-bit word, refusing a set whose
// highest member is at or above 64: such a set cannot be named in the word a
// caller reads, and a mask that dropped the high half would be a promise
// about which cores a thread may run on that the scheduler would contradict.
[[nodiscard]] bool mask_from_cpu_set(const cpu_set_t& set, std::uint64_t& out) noexcept {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
    for (std::uint32_t cpu = 64; cpu < static_cast<std::uint32_t>(CPU_SETSIZE); ++cpu) {
        if (CPU_ISSET(static_cast<int>(cpu), &set) != 0) {
            return false;
        }
    }
    std::uint64_t mask = 0;
    for (std::uint32_t cpu = 0; cpu < 64; ++cpu) {
        if (CPU_ISSET(static_cast<int>(cpu), &set) != 0) {
            mask |= (std::uint64_t{1} << cpu);
        }
    }
#pragma GCC diagnostic pop
    out = mask;
    return true;
}

// The host's reported CPU clock, from the first `cpu MHz` line of
// /proc/cpuinfo. A machine that does not report it answers zero, which is
// what a caller treats as "unknown".
[[nodiscard]] std::uint32_t host_cpuinfo_mhz() noexcept {
    std::string info;
    if (!read_file("/proc/cpuinfo", info)) {
        return 0;
    }
    const std::size_t mark = info.find("cpu MHz");
    if (mark == std::string::npos) {
        return 0;
    }
    const char* cursor = info.c_str() + mark + 8;
    while (*cursor == ':' || *cursor == ' ' || *cursor == '\t') {
        ++cursor;
    }
    char* end = nullptr;
    const double mhz = std::strtod(cursor, &end);
    if (end == cursor || mhz <= 0.0 || mhz >= 4294967296.0) {
        return 0;
    }
    return static_cast<std::uint32_t>(mhz + 0.5);
}

// The LCID the locale queries answer with, mirroring the mapping
// sysinfo_ext.cpp owns so the two views of "what locale is this" agree.
// A locale the mapping does not name is answered with the US id, which is
// the default a Windows installation without a regional setting uses.
[[nodiscard]] std::uint32_t host_lcid() noexcept {
    const char* lang = std::getenv("LANG");
    if (lang == nullptr) {
        return 0x0409;
    }
    if (std::strncmp(lang, "zh_CN", 5) == 0) {
        return 0x0804;
    }
    if (std::strncmp(lang, "zh_TW", 5) == 0 || std::strncmp(lang, "zh_HK", 5) == 0) {
        return 0x0404;
    }
    if (std::strncmp(lang, "ja_JP", 5) == 0) {
        return 0x0411;
    }
    if (std::strncmp(lang, "ko_KR", 5) == 0) {
        return 0x0412;
    }
    if (std::strncmp(lang, "en_", 3) == 0 || std::strncmp(lang, "C", 1) == 0) {
        return 0x0409;
    }
    return 0x0409;
}

// ---------------------------------------------------------------------------
// The locale-answer table
// ---------------------------------------------------------------------------

// The LOCALE_* constants this file answers. The set is the common one a
// probe reads; the values are the documented numbers.
constexpr std::uint32_t kLocIlanguage = 0x1;
constexpr std::uint32_t kLocSlanguage = 0x2;
constexpr std::uint32_t kLocSabbrevLang = 0x3;
constexpr std::uint32_t kLocNativeLang = 0x4;
constexpr std::uint32_t kLocScountry = 0x6;
constexpr std::uint32_t kLocSabbrevCtry = 0x7;
constexpr std::uint32_t kLocIdefaultCountry = 0xA;
constexpr std::uint32_t kLocScurrency = 0x14;
constexpr std::uint32_t kLocIntlSymbol = 0x2C;
constexpr std::uint32_t kLocIso639 = 0x59;
constexpr std::uint32_t kLocIso3166 = 0x5A;
constexpr std::uint32_t kLocSEngLanguage = 0x1001;
constexpr std::uint32_t kLocSEngCountry = 0x1002;
constexpr std::uint32_t kLocIdefaultCodePage = 0x1003;
constexpr std::uint32_t kLocIdefaultAnsiCodePage = 0x1004;

struct LocaleRow {
    std::uint32_t lc_type;
    std::string_view text;
};

// The answers for the five locales the host mapping can present. Each row
// is the Windows spelling of one LCType for that locale; a row this table
// lacks is a question this runtime has no NLS data to answer, and the query
// is refused rather than answered with another locale's text.
[[nodiscard]] std::string_view locale_answer(std::uint32_t lcid,
                                             std::uint32_t lc_type) noexcept {
    static const LocaleRow kEnUs[] = {
        {kLocIlanguage, "409"},
        {kLocSlanguage, "English (United States)"},
        {kLocSabbrevLang, "ENG"},
        {kLocNativeLang, "English"},
        {kLocScountry, "United States"},
        {kLocSabbrevCtry, "USA"},
        {kLocIdefaultCountry, "1"},
        {kLocScurrency, "$"},
        {kLocIntlSymbol, "USD"},
        {kLocIso639, "en"},
        {kLocIso3166, "US"},
        {kLocSEngLanguage, "English"},
        {kLocSEngCountry, "United States"},
        {kLocIdefaultCodePage, "65001"},
        {kLocIdefaultAnsiCodePage, "65001"},
    };
    static const LocaleRow kZhCn[] = {
        {kLocIlanguage, "804"},
        {kLocSlanguage, "Chinese (China)"},
        {kLocSabbrevLang, "CHS"},
        {kLocNativeLang, "Chinese"},
        {kLocScountry, "China"},
        {kLocSabbrevCtry, "CHN"},
        {kLocIdefaultCountry, "86"},
        {kLocScurrency, "\xC2\xA5"},  // UTF-8 for U+00A5 YEN SIGN
        {kLocIntlSymbol, "CNY"},
        {kLocIso639, "zh"},
        {kLocIso3166, "CN"},
        {kLocSEngLanguage, "Chinese (Simplified)"},
        {kLocSEngCountry, "China"},
        {kLocIdefaultCodePage, "65001"},
        {kLocIdefaultAnsiCodePage, "65001"},
    };
    static const LocaleRow kZhTw[] = {
        {kLocIlanguage, "404"},
        {kLocSlanguage, "Chinese (Taiwan)"},
        {kLocSabbrevLang, "CHT"},
        {kLocNativeLang, "Chinese"},
        {kLocScountry, "Taiwan"},
        {kLocSabbrevCtry, "TWN"},
        {kLocIdefaultCountry, "886"},
        {kLocScurrency, "NT$"},
        {kLocIntlSymbol, "TWD"},
        {kLocIso639, "zh"},
        {kLocIso3166, "TW"},
        {kLocSEngLanguage, "Chinese (Traditional)"},
        {kLocSEngCountry, "Taiwan"},
        {kLocIdefaultCodePage, "65001"},
        {kLocIdefaultAnsiCodePage, "65001"},
    };
    static const LocaleRow kJaJp[] = {
        {kLocIlanguage, "411"},
        {kLocSlanguage, "Japanese"},
        {kLocSabbrevLang, "JPN"},
        {kLocNativeLang, "Japanese"},
        {kLocScountry, "Japan"},
        {kLocSabbrevCtry, "JPN"},
        {kLocIdefaultCountry, "81"},
        {kLocScurrency, "\xC2\xA5"},
        {kLocIntlSymbol, "JPY"},
        {kLocIso639, "ja"},
        {kLocIso3166, "JP"},
        {kLocSEngLanguage, "Japanese"},
        {kLocSEngCountry, "Japan"},
        {kLocIdefaultCodePage, "65001"},
        {kLocIdefaultAnsiCodePage, "65001"},
    };
    static const LocaleRow kKoKr[] = {
        {kLocIlanguage, "412"},
        {kLocSlanguage, "Korean"},
        {kLocSabbrevLang, "KOR"},
        {kLocNativeLang, "Korean"},
        {kLocScountry, "Korea"},
        {kLocSabbrevCtry, "KOR"},
        {kLocIdefaultCountry, "82"},
        {kLocScurrency, "\xE2\x82\xA9"},  // UTF-8 for U+20A9 WON SIGN
        {kLocIntlSymbol, "KRW"},
        {kLocIso639, "ko"},
        {kLocIso3166, "KR"},
        {kLocSEngLanguage, "Korean"},
        {kLocSEngCountry, "Korea"},
        {kLocIdefaultCodePage, "65001"},
        {kLocIdefaultAnsiCodePage, "65001"},
    };
    const LocaleRow* table = nullptr;
    std::size_t count = 0;
    switch (lcid) {
        case 0x0409:
            table = kEnUs;
            count = sizeof(kEnUs) / sizeof(kEnUs[0]);
            break;
        case 0x0804:
            table = kZhCn;
            count = sizeof(kZhCn) / sizeof(kZhCn[0]);
            break;
        case 0x0404:
            table = kZhTw;
            count = sizeof(kZhTw) / sizeof(kZhTw[0]);
            break;
        case 0x0411:
            table = kJaJp;
            count = sizeof(kJaJp) / sizeof(kJaJp[0]);
            break;
        case 0x0412:
            table = kKoKr;
            count = sizeof(kKoKr) / sizeof(kKoKr[0]);
            break;
        default:
            return {};
    }
    for (std::size_t i = 0; i < count; ++i) {
        if (table[i].lc_type == lc_type) {
            return table[i].text;
        }
    }
    return {};
}

// ---------------------------------------------------------------------------
// The volume model
// ---------------------------------------------------------------------------

// The host path a DOS volume path stands on. `Z:` is the mounted drive and
// maps to the host root; the presented `C:` system drive has no separate
// backing, so both answer from the host root filesystem -- which is the same
// filesystem every guest file actually lives on.
[[nodiscard]] std::string volume_host_path(std::string_view root) noexcept {
    std::string host = from_dos_path(root);
    if (host.size() >= 2 && host[1] == ':') {
        std::string rest;
        if (host.size() >= 3 && (host[2] == '\\' || host[2] == '/')) {
            rest = host.substr(3);
        }
        host = "/" + rest;
    }
    if (host.empty()) {
        host = "/";
    }
    return host;
}

// The volume statistics behind a DOS path. A path that names a file or a
// nonexistent subtree still names a volume; the host root answers for it
// the way the drive root would, so a deep path under an unmapped drive is
// not refused for the wrong reason.
[[nodiscard]] bool volume_statvfs(std::string_view root,
                                  struct statvfs& out) noexcept {
    if (root.empty()) {
        return false;
    }
    const std::string host = volume_host_path(root);
    if (::statvfs(host.c_str(), &out) == 0) {
        return true;
    }
    return ::statvfs("/", &out) == 0;
}

// The volume serial number: Windows mints it from the volume's creation
// time; this runtime has no volume to create, so the stable per-machine id
// is the host's machine-id, hashed (FNV-1a). A host without a machine-id
// falls back to the hostname and pid, which is stable for the run.
[[nodiscard]] std::uint32_t stable_volume_serial() noexcept {
    std::string id;
    if (read_file("/etc/machine-id", id)) {
        while (!id.empty() && (id.back() == '\n' || id.back() == '\r' || id.back() == ' ')) {
            id.pop_back();
        }
    }
    if (id.empty()) {
        char hostname[256] = {};
        if (::gethostname(hostname, sizeof(hostname)) != 0) {
            hostname[0] = '\0';
        }
        id = std::string(hostname) + ":" + std::to_string(::getpid());
    }
    std::uint32_t hash = 2166136261u;
    for (char ch : id) {
        hash ^= static_cast<std::uint8_t>(ch);
        hash *= 16777619u;
    }
    return hash;
}

// ---------------------------------------------------------------------------
// Small structure writers
// ---------------------------------------------------------------------------

// CPINFOEX: MaxCharSize at 0, DefaultChar[2] at 4, LeadByte[12] at 6,
// UnicodeDefaultChar at 18, CodePage at 20, and the code-page name at 24.
// The A record ends at 284 bytes, the W record at 544.
constexpr std::size_t kCpInfoExBytesA = 284;
constexpr std::size_t kCpInfoExBytesW = 544;

void fill_cpinfoex(void* buffer, bool wide_name) noexcept {
    std::memset(buffer, 0, wide_name ? kCpInfoExBytesW : kCpInfoExBytesA);
    write_u32(buffer, 0, 3);        // MaxCharSize: a UTF-8 character is at most 3 bytes
    write_u8(buffer, 4, 0x3F);      // DefaultChar: '?'
    write_u16(buffer, 18, 0xFFFD);  // UnicodeDefaultChar: the replacement character
    write_u32(buffer, 20, 65001);   // CodePage: the runtime's only ANSI page
    constexpr const char* kName = "utf-8";
    if (wide_name) {
        constexpr char16_t kWideName[] = u"utf-8";
        for (std::size_t i = 0; i < 5; ++i) {
            write_u16(buffer, 24 + i * 2, kWideName[i]);
        }
    } else {
        std::memcpy(static_cast<std::uint8_t*>(buffer) + 24, kName, 6);
    }
}

}  // namespace

// ===========================================================================
// NTDLL
// ===========================================================================

// Returns the state of one kernel debug filter. This runtime has no kernel
// debug filtering enabled at all, so every filter reads the way an
// un-enabled filter reads on Windows: FALSE, with STATUS_SUCCESS -- the
// answer a machine running without `bcdedit /debug on` gives.
extern "C" __attribute__((ms_abi)) Ntstatus ntad2_NtQueryDebugFilterState(
    std::uint32_t filter_id, std::uint32_t* answer) noexcept {
    if (answer == nullptr) {
        return kStInvalidParameter;
    }
    static_cast<void>(filter_id);
    *answer = 0;
    return kStSuccess;
}

// Kernel debug control needs the kernel-debug privilege and a kernel
// debugger to address; this runtime has neither, and Windows answers exactly
// this status to a caller without the privilege -- which is what a normal
// process is.
extern "C" __attribute__((ms_abi)) Ntstatus ntad2_NtSystemDebugControl(
    std::uint32_t control_code, const void* input_buffer,
    std::uint32_t input_length, void* output_buffer,
    std::uint32_t output_length, std::uint32_t* return_length) noexcept {
    static_cast<void>(control_code);
    static_cast<void>(input_buffer);
    static_cast<void>(input_length);
    static_cast<void>(output_buffer);
    static_cast<void>(output_length);
    static_cast<void>(return_length);
    return kStAccessDenied;
}

// Suspends a guest thread by its handle, bridging the guest-thread table
// that owns the operation. The bridge answers WAIT_FAILED for a handle it
// does not recognise, which is the NT invalid-handle answer, and the
// previous suspend count it returns is written back to the caller.
extern "C" __attribute__((ms_abi)) Ntstatus ntad2_NtSuspendThread(
    std::uint64_t thread, std::uint32_t* previous_count) noexcept {
    const std::uint32_t rc = suspend_guest_thread(thread);
    if (rc == kWaitFailed) {
        return kStInvalidHandle;
    }
    if (previous_count != nullptr) {
        *previous_count = rc;
    }
    return kStSuccess;
}

// The inverse of the suspend: the bridge releases the thread and reports
// the count it released from. The same invalid-handle mapping applies.
extern "C" __attribute__((ms_abi)) Ntstatus ntad2_NtResumeThread(
    std::uint64_t thread, std::uint32_t* previous_count) noexcept {
    std::uint32_t before = 0;
    const std::uint32_t rc = resume_guest_thread(thread, &before);
    if (rc == kWaitFailed) {
        return kStInvalidHandle;
    }
    if (previous_count != nullptr) {
        *previous_count = before;
    }
    return kStSuccess;
}

// Raises the exception the caller's record and context describe, by running
// the same SEH search pass `RaiseException` runs. The second-chance pass
// differs from the first only in the debugger notification, and this runtime
// has no debugger to notify, so both chances dispatch to the same walk --
// the honest shape of a process with no debugger attached. A frame that
// resumes continues at the record's context; an exception nobody caught
// reaches the unhandled filter and then ends the process with the
// exception's code, exactly as the raise path ends it.
extern "C" __attribute__((ms_abi)) Ntstatus ntad2_NtRaiseException(
    const void* record, const void* context, std::uint32_t first_chance) noexcept {
    if (record == nullptr || context == nullptr) {
        return kStInvalidParameter;
    }
    GuestState* guest = guest_state();
    if (guest == nullptr) {
        return kStUnsuccessful;
    }
    static_cast<void>(first_chance);
    auto* rec = static_cast<std::uint8_t*>(const_cast<void*>(record));
    auto* ctx = static_cast<std::uint8_t*>(const_cast<void*>(context));
    const bool resume = seh::dispatch(
        rec, ctx, reinterpret_cast<const std::uint8_t*>(guest->pdata_va),
        static_cast<std::size_t>(guest->pdata_bytes),
        seh::UnwindRange{guest->xdata_va, guest->xdata_bytes},
        guest->image_base, guest->image_end, guest->stack_low,
        guest->stack_high);
    if (resume) {
        // A filter answered EXCEPTION_CONTINUE_EXECUTION: the interrupted
        // code resumes at the record's context and this call never returns.
        seh::seh_restore_context(ctx);
    }
    if (guest->unhandled_filter != 0) {
        // Windows gives the unhandled-exception filter its say before the
        // process ends; the record-and-context pair it receives is the
        // EXCEPTION_POINTERS block, and a filter answering
        // EXCEPTION_CONTINUE_EXECUTION resumes at the exception point.
        alignas(8) const void* pointers[2] = {record, context};
        const void* pep = static_cast<const void*>(&pointers[0]);
        const auto tell = reinterpret_cast<std::int32_t(
            __attribute__((ms_abi))*)(const void*)>(guest->unhandled_filter);
        if (tell(pep) == 0) {
            seh::seh_restore_context(ctx);
        }
    }
    const std::uint32_t code = read_u32(rec, 0);
    k32_ExitProcess(code);
    __builtin_unreachable();
}

// Continues at the supplied context, exactly as `SetThreadContext`'s
// restore does; the call does not return to its caller. An alertable
// continuation first services the pending APCs, the way any alertable
// boundary does.
extern "C" __attribute__((ms_abi)) Ntstatus ntad2_NtContinue(
    const void* context, std::uint32_t test_alert) noexcept {
    if (context == nullptr) {
        return kStInvalidParameter;
    }
    if (test_alert != 0) {
        GuestState* self = guest_state();
        if (self != nullptr) {
            (void)run_pending_apcs(*self);
        }
    }
    k32c2_SetThreadContext(0, context);
    __builtin_unreachable();
}

// The relative-wait half of the alertable sleep family. A negative 100ns
// interval is a relative wait and is converted to milliseconds; a
// non-negative one completes immediately. An alertable wait services the
// APC queue before and during the wait and answers STATUS_ALERTED when an
// APC ran, mirroring the poll-sleep loop `SleepEx` owns.
extern "C" __attribute__((ms_abi)) Ntstatus ntad2_NtDelayExecution(
    std::uint32_t alertable, const std::int64_t* delay_interval) noexcept {
    if (delay_interval == nullptr) {
        return kStInvalidParameter;
    }
    GuestState* self = guest_state();
    if (self == nullptr) {
        return kStUnsuccessful;
    }
    const std::int64_t interval = *delay_interval;
    if (interval >= 0) {
        if (alertable != 0) {
            (void)run_pending_apcs(*self);
        }
        return kStSuccess;
    }
    // The negation is done on the value plus one so the most negative
    // interval cannot overflow, and the result is a count of 100ns ticks.
    const std::uint64_t ticks =
        static_cast<std::uint64_t>(-(interval + 1)) + 1;
    const std::uint64_t ms = ticks / 10000ULL;
    if (alertable == 0) {
        sleep_ms_loop(ms);
        return kStSuccess;
    }
    if (run_pending_apcs(*self)) {
        return kStAlarmed;
    }
    constexpr std::uint64_t kApcPollMs = 16;
    std::uint64_t remaining = ms;
    while (remaining > 0) {
        const std::uint64_t step =
            remaining > kApcPollMs ? kApcPollMs : remaining;
        sleep_ms_loop(step);
        remaining -= step;
        if (run_pending_apcs(*self)) {
            return kStAlarmed;
        }
    }
    return kStSuccess;
}

// Tests the alert queue without waiting: runs any pending APC and answers
// STATUS_ALERTED when one ran, STATUS_SUCCESS otherwise.
extern "C" __attribute__((ms_abi)) Ntstatus ntad2_NtTestAlert(void) noexcept {
    GuestState* self = guest_state();
    if (self == nullptr) {
        return kStUnsuccessful;
    }
    return run_pending_apcs(*self) ? kStAlarmed : kStSuccess;
}

// Waits for a debug event on a debug object. This runtime is the debuggee,
// not the debugger: it has no debug object and no event source to wait on.
// Windows answers a wait on an absent debug port with STATUS_PORT_NOT_SET,
// which is the honest shape of "there is no debugger here to be the other
// end", and the first anti-debug slice answers the same family of questions
// the same way.
extern "C" __attribute__((ms_abi)) Ntstatus ntad2_NtWaitForDebugEvent(
    std::uint64_t debug_object, std::uint32_t alertable,
    const std::int64_t* timeout, void* debug_event) noexcept {
    static_cast<void>(debug_object);
    static_cast<void>(alertable);
    static_cast<void>(timeout);
    static_cast<void>(debug_event);
    return kStPortNotSet;
}

// Removes a debug object from a process. The process carries no debug port,
// so the removal answers the status a debugger sees when it removes an
// object that was never attached.
extern "C" __attribute__((ms_abi)) Ntstatus ntad2_NtRemoveProcessDebug(
    std::uint64_t process, std::uint64_t debug_object) noexcept {
    static_cast<void>(process);
    static_cast<void>(debug_object);
    return kStPortNotSet;
}

// Prints a formatted line to the host's standard error, the way a kernel
// debug print reaches a visible stream. The format is the guest's own, so
// the formatting runs through the host_vformat bridge the CRT layer owns,
// which understands the guest's ms-slot arguments.
extern "C" __attribute__((ms_abi)) std::uint32_t ntad2_DbgPrint(
    const char* format, ...) noexcept {
    if (format == nullptr) {
        return 0;
    }
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, format);
    void* slots = nullptr;
    __builtin_memcpy(&slots, &ap, sizeof(slots));
    std::string line = "DbgPrint: ";
    line += format;
    const int written = host_vfprintf(::stderr, line.c_str(), slots);
    __builtin_ms_va_end(ap);
    return written < 0 ? 0 : static_cast<std::uint32_t>(written);
}

// The filtered spelling of the same print. This runtime keeps no debug
// filter levels, so every level prints: a filter that dropped a line would
// be inventing a filtering policy the host does not have.
extern "C" __attribute__((ms_abi)) std::uint32_t ntad2_DbgPrintEx(
    std::uint32_t component_id, std::uint32_t level, const char* format,
    ...) noexcept {
    static_cast<void>(component_id);
    static_cast<void>(level);
    if (format == nullptr) {
        return 0;
    }
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, format);
    void* slots = nullptr;
    __builtin_memcpy(&slots, &ap, sizeof(slots));
    std::string line = "DbgPrintEx: ";
    line += format;
    const int written = host_vfprintf(::stderr, line.c_str(), slots);
    __builtin_ms_va_end(ap);
    return written < 0 ? 0 : static_cast<std::uint32_t>(written);
}

// Whether a handler address is legal for the exception dispatcher. Windows
// accepts a handler in a mapped image or in the system range; here the
// guest's code is the image itself, the unwind tables' data ranges, and any
// region the address space maps for the guest. A null handler is legal in a
// filter list -- the dispatch skips it and keeps searching -- so it answers
// valid rather than making the search treat it as corruption.
extern "C" __attribute__((ms_abi)) std::uint8_t ntad2_RtlIsValidHandler(
    const void* handler) noexcept {
    if (handler == nullptr) {
        return 1;
    }
    GuestState* g = guest_state();
    if (g == nullptr) {
        return 1;
    }
    const std::uint64_t address = reinterpret_cast<std::uint64_t>(handler);
    if (address >= g->image_base && address < g->image_end) {
        return 1;
    }
    if (g->pdata_bytes != 0 && address >= g->pdata_va) {
        const std::uint64_t off = address - g->pdata_va;
        if (off < g->pdata_bytes) {
            return 1;
        }
    }
    if (g->xdata_bytes != 0 && address >= g->xdata_va) {
        const std::uint64_t off = address - g->xdata_va;
        if (off < g->xdata_bytes) {
            return 1;
        }
    }
    if (guest_range_is_ours(handler, 1)) {
        return 1;
    }
    return 0;
}

// The timer resolution, in 100ns units. Linux exposes a single resolution
// through `clock_getres`, so the Windows three-field answer collapses to it:
// the host has no separate adjustable and fixed ranges, and current is the
// same value the clock actually runs at.
extern "C" __attribute__((ms_abi)) Ntstatus ntad2_NtQueryTimerResolution(
    std::uint32_t* min_res, std::uint32_t* max_res,
    std::uint32_t* current) noexcept {
    if (min_res == nullptr || max_res == nullptr || current == nullptr) {
        return kStInvalidParameter;
    }
    struct timespec ts {};
    if (::clock_getres(CLOCK_MONOTONIC, &ts) != 0) {
        return kStUnsuccessful;
    }
    std::uint64_t units =
        static_cast<std::uint64_t>(ts.tv_sec) * 10000000ULL +
        static_cast<std::uint64_t>(ts.tv_nsec) / 100ULL;
    if (units == 0) {
        units = 1;
    }
    const std::uint32_t value = static_cast<std::uint32_t>(units);
    *min_res = value;
    *max_res = value;
    *current = value;
    return kStSuccess;
}

// Linux has no per-process timer-resolution control: the timer resolution
// is a machine property the kernel sets, not a value a process may change.
// A success here would be a claim about state a later query would
// contradict, so the call is refused, and `actual` is left unwritten --
// which is what the NT contract does on failure.
extern "C" __attribute__((ms_abi)) Ntstatus ntad2_NtSetTimerResolution(
    std::uint32_t requested, std::uint32_t set,
    std::uint32_t* actual) noexcept {
    static_cast<void>(requested);
    static_cast<void>(set);
    static_cast<void>(actual);
    return kStNotImplemented;
}

// ===========================================================================
// KERNEL32
// ===========================================================================

// Whether the process is a WOW64 (32-bit) process. The guest is pure x64
// with no WOW64 layer, so the answer is the one Windows gives a 64-bit
// process: yes it answered, and no it is not WOW64.
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_IsWow64Process(
    std::uint64_t process, std::uint32_t* wow64_process) noexcept {
    if (wow64_process == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (!is_self_process(process)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    *wow64_process = 0;
    set_last_error(kErrorSuccess);
    return 1;
}

// The two-machine spelling: the process machine is IMAGE_FILE_MACHINE_UNKNOWN
// (0) because the guest is the native architecture, and the native machine
// is IMAGE_FILE_MACHINE_AMD64 (0x8664).
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_IsWow64Process2(
    std::uint64_t process, std::uint16_t* process_machine,
    std::uint16_t* native_machine) noexcept {
    if (process_machine == nullptr || native_machine == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (!is_self_process(process)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    *process_machine = 0;          // IMAGE_FILE_MACHINE_UNKNOWN
    *native_machine = 0x8664;      // IMAGE_FILE_MACHINE_AMD64
    set_last_error(kErrorSuccess);
    return 1;
}

// The WOW64 context pair. There is no WOW64 layer in this runtime and no
// 32-bit thread: a WOW64 CONTEXT cannot be produced for a thread that has
// none. Windows on a 64-bit machine refuses the same request for a 64-bit
// thread, and mapping a 64-bit CONTEXT into the WOW64 layout would be
// inventing a 32-bit thread state that does not exist.
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_Wow64GetThreadContext(
    std::uint64_t thread, void* wow64_context) noexcept {
    static_cast<void>(thread);
    static_cast<void>(wow64_context);
    set_last_error(kErrorInvalidFunction);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_Wow64SetThreadContext(
    std::uint64_t thread, const void* wow64_context) noexcept {
    static_cast<void>(thread);
    static_cast<void>(wow64_context);
    set_last_error(kErrorInvalidFunction);
    return 0;
}

// The process DEP policy. Modern Windows has DEP always on, and this
// runtime has no DEP switch to expose; the answer is the one a real machine
// gives: enabled, and not permanent.
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetProcessDEPPolicy(
    std::uint64_t process, std::uint32_t* flags,
    std::uint32_t* permanent) noexcept {
    if (flags == nullptr || permanent == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (!is_self_process(process)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    *flags = 1;  // PROCESS_DEP_ENABLE
    *permanent = 0;
    set_last_error(kErrorSuccess);
    return 1;
}

// On 64-bit Windows DEP cannot be disabled, and this call always fails with
// ERROR_ACCESS_DENIED. The runtime is a 64-bit process and answers the same
// way: honouring the flag would be claiming a protection the machine does
// not drop.
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_SetProcessDEPPolicy(
    std::uint32_t dw_flags) noexcept {
    static_cast<void>(dw_flags);
    set_last_error(kErrorAccessDenied);
    return 0;
}

// The process times: creation from the host process's start (read from the
// machine's own /proc record), kernel and user from getrusage's real split,
// and exit time zero, which is what a live process reports on Windows.
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetProcessTimes(
    std::uint64_t process, void* creation, void* exit_time, void* kernel,
    void* user) noexcept {
    if (creation == nullptr || exit_time == nullptr || kernel == nullptr ||
        user == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (!is_self_process(process)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    const std::uint64_t start = process_start_filetime();
    // A machine without a /proc start record answers "now", which keeps the
    // creation time sane rather than zero.
    write_u64(creation, 0, start != 0 ? start : now_ticks_or_zero());
    // A live process has not exited; Windows reports zero for it.
    write_u64(exit_time, 0, 0);
    struct rusage usage {};
    if (::getrusage(RUSAGE_SELF, &usage) != 0) {
        write_u64(kernel, 0, 0);
        write_u64(user, 0, 0);
    } else {
        write_u64(kernel, 0, ticks_from_timeval(usage.ru_stime));
        write_u64(user, 0, ticks_from_timeval(usage.ru_utime));
    }
    set_last_error(kErrorSuccess);
    return 1;
}

// Sets the calling thread's affinity mask. The guest-thread table keeps no
// public handle-to-host-tid mapping, so the calling thread is the only one
// whose mask this process may change; any other handle is refused with
// ERROR_ACCESS_DENIED. The mask is validated against the thread's allowed
// set (a bit outside it is refused the way Windows refuses a bit outside
// the system mask), and the previous mask is the call's return value, as
// Windows returns it.
extern "C" __attribute__((ms_abi)) std::uint64_t k32ad2_SetThreadAffinityMask(
    std::uint64_t thread, std::uint64_t mask) noexcept {
    if (!is_current_thread(thread)) {
        set_last_error(kErrorAccessDenied);
        return 0;
    }
    if (mask == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    if (::sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
        set_last_error(kErrorInvalidFunction);
        return 0;
    }
    std::uint64_t previous = 0;
    if (!mask_from_cpu_set(allowed, previous)) {
        set_last_error(kErrorNotSupported);
        return 0;
    }
    if ((mask & ~previous) != 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    cpu_set_t wanted;
    CPU_ZERO(&wanted);
    for (std::uint32_t cpu = 0; cpu < 64; ++cpu) {
        if ((mask & (std::uint64_t{1} << cpu)) != 0) {
            CPU_SET(static_cast<int>(cpu), &wanted);
        }
    }
    if (::sched_setaffinity(0, sizeof(wanted), &wanted) != 0) {
        set_last_error(kErrorAccessDenied);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return previous;
}

// The process's affinity, which is the same call as the thread's with the
// process as the target. Linux's `sched_setaffinity` takes a thread id and
// the main thread *is* the process, so the same two syscalls serve both --
// which is the shape Windows has as well, where a process's affinity is the
// main thread's until other threads are created.
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_SetProcessAffinityMask(
    std::uint64_t process, std::uint64_t mask) noexcept {
    // The pseudo handle is what a program passes for its own process, and
    // the process id is the other spelling of the same thing. Anything else
    // names a process this runtime has no handle to.
    constexpr std::uint64_t kCurrentProcess = 0xFFFFFFFFFFFFFFFFULL;
    if (process != kCurrentProcess &&
        process != static_cast<std::uint64_t>(::getpid())) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (mask == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    if (::sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
        set_last_error(kErrorInvalidFunction);
        return 0;
    }
    std::uint64_t previous = 0;
    if (!mask_from_cpu_set(allowed, previous)) {
        set_last_error(kErrorNotSupported);
        return 0;
    }
    if ((mask & ~previous) != 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    cpu_set_t wanted;
    CPU_ZERO(&wanted);
    for (std::uint32_t cpu = 0; cpu < 64; ++cpu) {
        if ((mask & (std::uint64_t{1} << cpu)) != 0) {
            CPU_SET(static_cast<int>(cpu), &wanted);
        }
    }
    if (::sched_setaffinity(0, sizeof(wanted), &wanted) != 0) {
        set_last_error(kErrorAccessDenied);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

// The thread's CPU consumption as a cycle-time stand-in. Linux exposes no
// per-thread cycle counter; the thread's CPU time in 100ns units is the
// honest value a caller can compare and act on. Only the calling thread can
// be answered (see the thread-query boundary above).
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_QueryThreadCycleTime(
    std::uint64_t thread, std::uint64_t* cycles) noexcept {
    if (cycles == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (!is_current_thread(thread)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    struct timespec ts {};
    if (::clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0) {
        set_last_error(kErrorInvalidFunction);
        return 0;
    }
    *cycles = static_cast<std::uint64_t>(ts.tv_sec) * 10000000ULL +
              static_cast<std::uint64_t>(ts.tv_nsec) / 100ULL;
    set_last_error(kErrorSuccess);
    return 1;
}

// The machine's idle CPU time, summed over every per-CPU line of /proc/stat
// and converted to 100ns ticks. The iowait field counts as idle -- it is
// time the CPU was idle with pending IO -- which is how Windows folds it.
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_QueryIdleProcessorCycleTime(
    std::uint64_t* cycle_time) noexcept {
    if (cycle_time == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string stat;
    if (!read_file("/proc/stat", stat)) {
        set_last_error(kErrorInvalidFunction);
        return 0;
    }
    std::uint64_t idle_jiffies = 0;
    std::size_t pos = 0;
    while (pos < stat.size()) {
        const std::size_t eol = stat.find('\n', pos);
        const std::size_t line_end =
            eol == std::string::npos ? stat.size() : eol;
        const std::string_view line(stat.data() + pos, line_end - pos);
        pos = eol == std::string::npos ? stat.size() : eol + 1;
        // A per-CPU line starts with "cpu" and a digit; the aggregate
        // "cpu " line would double-count the whole machine and is skipped.
        if (line.size() < 5 || line.substr(0, 3) != "cpu") {
            continue;
        }
        if (line[3] < '0' || line[3] > '9') {
            continue;
        }
        // Fields after "cpuN": user nice system idle iowait; idle is the
        // fourth token, iowait the fifth.
        std::uint64_t values[6] = {};
        std::size_t token_begin = 4;
        int token = 0;
        while (token < 6 && token_begin < line.size()) {
            while (token_begin < line.size() &&
                   (line[token_begin] == ' ' || line[token_begin] == '\t')) {
                ++token_begin;
            }
            const std::size_t begin = token_begin;
            while (token_begin < line.size() &&
                   line[token_begin] != ' ' && line[token_begin] != '\t') {
                ++token_begin;
            }
            if (begin == token_begin) {
                break;
            }
            char* end = nullptr;
            const unsigned long long value =
                std::strtoull(line.data() + begin, &end, 10);
            if (end == line.data() + begin) {
                break;
            }
            values[static_cast<std::size_t>(token)] =
                static_cast<std::uint64_t>(value);
            ++token;
        }
        if (token >= 5) {
            idle_jiffies += values[3] + values[4];
        }
    }
    // One jiffy is 10 ms, which is 100000 hundred-nanosecond ticks.
    *cycle_time = idle_jiffies * 100000ULL;
    set_last_error(kErrorSuccess);
    return 1;
}

// The W spelling of the version record. The A fill owns the four version
// numbers; its record shares offsets 0..16 with the W record, and it writes
// only its own 148-byte contract, so the W record is handed to it as the
// source of the same numbers and the service-pack string is then spelled in
// UTF-16.
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetVersionExW(
    void* info) noexcept {
    if (info == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // OSVERSIONINFOW is 276 bytes (20 + 128 UTF-16 units); the caller sets
    // the size field before the call, and a smaller record is refused.
    constexpr std::uint32_t kOviBytesW = 276;
    constexpr std::size_t kOviCsd = 20;
    const std::uint32_t size = read_u32(info, 0);
    if (size < kOviBytesW) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    auto* bytes = static_cast<std::uint8_t*>(info);
    if (k32si_GetVersionExA(bytes) == 0) {
        return 0;
    }
    // The A fill cleared 128 bytes of the service-pack string; the W record
    // carries 256, so the rest is cleared here and the size is written back
    // unchanged, as Windows leaves it.
    std::memset(bytes + kOviCsd, 0, kOviBytesW - kOviCsd);
    write_u32(info, 0, kOviBytesW);
    set_last_error(kErrorSuccess);
    return 1;
}

// Enumerates the firmware-table identifiers of one provider set. Only the
// SMBIOS set is answerable -- the same provider the firmware query owns --
// and the RSMB set contains exactly one table (the SMBIOS blob, id 0), so
// the enumeration is one 32-bit id. A host without a DMI blob has no table
// to enumerate, which is the answer a machine without firmware tables gets.
extern "C" __attribute__((ms_abi)) std::uint32_t k32ad2_EnumSystemFirmwareTables(
    std::uint32_t provider, void* buffer, std::uint32_t size) noexcept {
    constexpr std::uint32_t kProviderSmbios = 0x52534D42u;  // 'RSMB'
    if (provider != kProviderSmbios) {
        set_last_error(kErrorInvalidFunction);
        return 0;
    }
    struct stat st {};
    if (::stat("/sys/firmware/dmi/tables/DMI", &st) != 0 || st.st_size <= 0) {
        set_last_error(kErrorInvalidFunction);
        return 0;
    }
    constexpr std::uint32_t kNeeded = 4;
    if (buffer == nullptr || size < kNeeded) {
        set_last_error(kErrorInsufficientBuffer);
        return kNeeded;
    }
    write_u32(buffer, 0, 0);
    set_last_error(kErrorSuccess);
    return kNeeded;
}

// The product type for an OS version. The product table lives with the Rtl
// spelling, which owns the version rule; this call reports its answer as
// BOOL. A version the table predates answers FALSE without a meaningful
// error, exactly as Windows answers an unsupported version.
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetProductInfo(
    std::uint32_t major, std::uint32_t minor, std::uint32_t sp_major,
    std::uint32_t sp_minor, std::uint32_t* product) noexcept {
    if (product == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::int32_t ok = nr2_RtlGetProductInfo(
        major, minor, static_cast<std::uint8_t>(sp_major),
        static_cast<std::uint8_t>(sp_minor), product);
    if (ok == 0) {
        set_last_error(kErrorSuccess);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

// The locale-query pair. The W spelling owns the table and writes UTF-16;
// the A spelling answers the same table in UTF-8, which is this runtime's
// narrow encoding -- converting through the W form would be a round trip of
// the text rather than a decision. An LCType the table has no row for is
// refused with ERROR_INVALID_PARAMETER, the answer Windows gives for a
// locale question it has no NLS data for.
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetLocaleInfoW(
    std::uint32_t locale, std::uint32_t lc_type, char16_t* buffer,
    std::uint32_t capacity) noexcept {
    // Windows substitutes the user default (0) and the system default
    // (0x800) before consulting any locale table.
    std::uint32_t lcid = locale;
    if (locale == 0 || locale == 0x800) {
        lcid = host_lcid();
    }
    const std::string_view answer = locale_answer(lcid, lc_type);
    if (answer.empty()) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string wide;
    if (!narrow_in(answer, wide).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::size_t units = wide.size() + 1;
    if (capacity == 0) {
        return static_cast<std::int32_t>(units);
    }
    if (capacity < units) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    for (std::size_t i = 0; i < wide.size(); ++i) {
        buffer[i] = wide[i];
    }
    buffer[wide.size()] = u'\0';
    set_last_error(kErrorSuccess);
    return static_cast<std::int32_t>(units);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetLocaleInfoA(
    std::uint32_t locale, std::uint32_t lc_type, char* buffer,
    std::uint32_t capacity) noexcept {
    std::uint32_t lcid = locale;
    if (locale == 0 || locale == 0x800) {
        lcid = host_lcid();
    }
    const std::string_view answer = locale_answer(lcid, lc_type);
    if (answer.empty()) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::size_t bytes = answer.size() + 1;
    if (capacity == 0) {
        return static_cast<std::int32_t>(bytes);
    }
    if (capacity < bytes) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    std::memcpy(buffer, answer.data(), answer.size());
    buffer[answer.size()] = '\0';
    set_last_error(kErrorSuccess);
    return static_cast<std::int32_t>(bytes);
}

// The locale ids. The guest has no profile to carry a separate user locale,
// so the user default and the system default are the same value, read from
// the host's LANG exactly as `GetSystemDefaultLCID` reads it.
extern "C" __attribute__((ms_abi)) std::uint32_t k32ad2_GetUserDefaultLCID(
    void) noexcept {
    return host_lcid();
}

extern "C" __attribute__((ms_abi)) std::uint16_t
k32ad2_GetUserDefaultLangID(void) noexcept {
    return static_cast<std::uint16_t>(host_lcid() & 0xFFFFu);
}

extern "C" __attribute__((ms_abi)) std::uint16_t
k32ad2_GetSystemDefaultLangID(void) noexcept {
    return static_cast<std::uint16_t>(host_lcid() & 0xFFFFu);
}

// The active processors of a processor group. This runtime presents one
// group holding every processor, matching the single-NUMA-node model the
// processor queries present; group 0 and the all-groups pseudo-number
// answer with the online count, any other group is empty.
extern "C" __attribute__((ms_abi)) std::uint32_t k32ad2_GetActiveProcessorCount(
    std::uint16_t group_number) noexcept {
    if (group_number != 0 && group_number != 0xFFFFu) {
        return 0;
    }
    const long n = ::sysconf(_SC_NPROCESSORS_ONLN);
    return n < 1 ? 1 : static_cast<std::uint32_t>(n);
}

// `GetProcessorInformation` is an undocumented kernel32 export -- a search
// of the public documentation surfaces only `GetLogicalProcessorInformation`
// and `GetLogicalProcessorInformationEx` (Microsoft Learn:
// https://learn.microsoft.com/zh-cn/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlogicalprocessorinformation)
// and no `GetProcessorInformation` contract anywhere. The structure below is
// therefore this file's documented assumption, modeled on
// SYSTEM_PROCESSOR_INFORMATION (NtQuerySystemInformation class 1) extended
// with the online processor count -- the shape a probe for basic CPU facts
// most plausibly reads -- and every field is filled from real host data:
//
//   u32 ProcessorCount        (offset 0)  sysconf(_SC_NPROCESSORS_ONLN)
//   u16 ProcessorArchitecture (offset 4)  9  (PROCESSOR_ARCHITECTURE_AMD64)
//   u16 ProcessorLevel        (offset 6)  6  (the runtime's presented family)
//   u16 ProcessorRevision     (offset 8)  0x3F00 (the presented revision)
//   u16 Reserved              (offset 10)
//   u64 ProcessorMask         (offset 12)  one bit per online processor
//   u32 ProcessorFeatureBits  (offset 20)  0 (none reported)
//   u32 MaxClockMHz           (offset 24)  /proc/cpuinfo, else 0
//   u32 Reserved              (offset 28)
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetProcessorInformation(
    void* buffer) noexcept {
    if (buffer == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const long n = ::sysconf(_SC_NPROCESSORS_ONLN);
    const std::uint64_t count =
        n < 1 ? 1ull : static_cast<std::uint64_t>(n);
    write_u32(buffer, 0, static_cast<std::uint32_t>(count));
    write_u16(buffer, 4, 9);
    write_u16(buffer, 6, 6);
    write_u16(buffer, 8, 0x3F00);
    write_u16(buffer, 10, 0);
    std::uint64_t mask = 0;
    if (count >= 64) {
        mask = ~std::uint64_t{0};
    } else {
        mask = (std::uint64_t{1} << count) - 1;
    }
    write_u64(buffer, 12, mask);
    write_u32(buffer, 20, 0);
    write_u32(buffer, 24, host_cpuinfo_mhz());
    write_u32(buffer, 28, 0);
    set_last_error(kErrorSuccess);
    return 1;
}

// The SysWOW64 directory, the sibling of the system directory in the same
// C: machine model `GetSystemDirectoryA` presents. The W spelling owns the
// text and the A spelling converts; both report the length including the
// terminating null, the convention `GetSystemDirectoryA` uses here.
extern "C" __attribute__((ms_abi)) std::uint32_t
k32ad2_GetSystemWow64DirectoryW(char16_t* buffer, std::uint32_t capacity) noexcept {
    const std::u16string text = u"C:\\Windows\\SysWOW64";
    const std::size_t units = text.size() + 1;
    if (buffer == nullptr || capacity < units) {
        return static_cast<std::uint32_t>(units);
    }
    for (std::size_t i = 0; i < text.size(); ++i) {
        buffer[i] = text[i];
    }
    buffer[text.size()] = u'\0';
    set_last_error(kErrorSuccess);
    return static_cast<std::uint32_t>(units);
}

extern "C" __attribute__((ms_abi)) std::uint32_t
k32ad2_GetSystemWow64DirectoryA(char* buffer, std::uint32_t capacity) noexcept {
    char16_t wide[64];
    const std::uint32_t units = k32ad2_GetSystemWow64DirectoryW(wide, 64);
    const std::u16string w(wide, units - 1);
    std::string narrow;
    if (!narrow_out(w, narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::size_t bytes = narrow.size() + 1;
    if (buffer == nullptr || capacity < bytes) {
        return static_cast<std::uint32_t>(bytes);
    }
    std::memcpy(buffer, narrow.data(), narrow.size());
    buffer[narrow.size()] = '\0';
    set_last_error(kErrorSuccess);
    return static_cast<std::uint32_t>(bytes);
}

// The search helper both spellings of `SearchPath` share: the candidate
// directory list, the extension rule, and the existence test on the host.
[[nodiscard]] std::string search_path_find(const char* path,
                                           const std::string& file_name,
                                           const std::string& extension) noexcept {
    // A file name that is already a full path is tested directly; Windows
    // ignores lpPath for one.
    if (file_name.size() >= 2 && file_name[1] == ':') {
        const std::string host = from_dos_path(file_name);
        struct stat st {};
        if (::stat(host.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            return file_name;
        }
        return {};
    }
    if (file_name.size() >= 2 && file_name[0] == '\\' && file_name[1] == '\\') {
        const std::string host = from_dos_path(file_name);
        struct stat st {};
        if (::stat(host.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            return file_name;
        }
        return {};
    }
    // The name the search tries: the extension is appended only when the
    // file name has none, which is the Windows rule.
    std::string candidate = file_name;
    if (!extension.empty() && file_name.find('.') == std::string::npos) {
        if (extension[0] == '.') {
            candidate += extension;
        } else {
            candidate += ".";
            candidate += extension;
        }
    }
    // The candidate directories, as host paths. An explicit lpPath names its
    // own list (split on ';', the DOS list separator); a null lpPath falls
    // back to the application directory, the current directory, and the
    // environment PATH, which is the Windows order.
    std::vector<std::string> dirs;
    if (path != nullptr && *path != '\0') {
        std::string_view list(path);
        std::size_t start = 0;
        for (;;) {
            const std::size_t semi = list.find(';', start);
            const std::string_view piece =
                semi == std::string_view::npos
                    ? list.substr(start)
                    : list.substr(start, semi - start);
            if (!piece.empty()) {
                dirs.push_back(from_dos_path(piece));
            }
            if (semi == std::string_view::npos) {
                break;
            }
            start = semi + 1;
        }
    } else {
        GuestState* g = guest_state();
        if (g != nullptr) {
            std::string dir = g->image_path_dos;
            const std::size_t slash = dir.find_last_of("/\\");
            if (slash != std::string::npos) {
                dir.resize(slash);
            }
            if (!dir.empty()) {
                dirs.push_back(from_dos_path(dir));
            }
        }
        dirs.emplace_back(".");
        const char* env_path = std::getenv("PATH");
        if (env_path != nullptr) {
            std::string_view list(env_path);
            std::size_t start = 0;
            for (;;) {
                const std::size_t colon = list.find(':', start);
                const std::string_view piece =
                    colon == std::string_view::npos
                        ? list.substr(start)
                        : list.substr(start, colon - start);
                if (!piece.empty()) {
                    dirs.emplace_back(piece);
                }
                if (colon == std::string_view::npos) {
                    break;
                }
                start = colon + 1;
            }
        }
    }
    for (const std::string& dir : dirs) {
        std::string host =
            dir.empty() ? candidate : dir + "/" + candidate;
        struct stat st {};
        if (::stat(host.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            // The answer is spelled the DOS way, so the caller sees the path
            // it could pass to another Windows call.
            return to_dos_path(host);
        }
    }
    return {};
}

// Searches for a file the way `SearchPath` does. The W spelling owns the
// decision; it returns the full path (spelled the DOS way), the file-name
// pointer into the caller's buffer, and the length including the
// terminating null, which is the count contract this file reports.
extern "C" __attribute__((ms_abi)) std::uint32_t k32ad2_SearchPathW(
    const char16_t* path, const char16_t* file_name, const char16_t* extension,
    char16_t* buffer, std::uint32_t buffer_length,
    char16_t** file_part) noexcept {
    if (file_name == nullptr || buffer == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string narrow_path;
    if (path != nullptr &&
        !narrow_out(std::u16string_view(path), narrow_path).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string narrow_name;
    if (!narrow_out(std::u16string_view(file_name), narrow_name).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string narrow_ext;
    if (extension != nullptr &&
        !narrow_out(std::u16string_view(extension), narrow_ext).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::string found =
        search_path_find(path != nullptr ? narrow_path.c_str() : nullptr,
                         narrow_name, narrow_ext);
    if (found.empty()) {
        set_last_error(kErrorFileNotFound);
        return 0;
    }
    std::u16string wide;
    if (!narrow_in(found, wide).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::size_t units = wide.size() + 1;
    if (buffer_length < units) {
        set_last_error(kErrorInsufficientBuffer);
        return static_cast<std::uint32_t>(units);
    }
    for (std::size_t i = 0; i < wide.size(); ++i) {
        buffer[i] = wide[i];
    }
    buffer[wide.size()] = u'\0';
    if (file_part != nullptr) {
        const std::size_t sep = wide.find_last_of(u"\\/");
        *file_part = buffer +
                     (sep == std::u16string::npos ? 0 : sep + 1);
    }
    set_last_error(kErrorSuccess);
    return static_cast<std::uint32_t>(units);
}

// The A spelling: the inputs are converted to wide, the W decision runs,
// and the answer is converted back to UTF-8 -- which is the direction the A
// contract names.
extern "C" __attribute__((ms_abi)) std::uint32_t k32ad2_SearchPathA(
    const char* path, const char* file_name, const char* extension,
    char* buffer, std::uint32_t buffer_length, char** file_part) noexcept {
    if (file_name == nullptr || buffer == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string wide_path;
    if (path != nullptr &&
        !narrow_in(std::string_view(path), wide_path).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string wide_name;
    if (!narrow_in(std::string_view(file_name), wide_name).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string wide_ext;
    if (extension != nullptr &&
        !narrow_in(std::string_view(extension), wide_ext).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    char16_t wide_out[2048];
    char16_t* wide_part = nullptr;
    const std::uint32_t result = k32ad2_SearchPathW(
        path != nullptr ? wide_path.c_str() : nullptr, wide_name.c_str(),
        extension != nullptr ? wide_ext.c_str() : nullptr, wide_out, 2048,
        &wide_part);
    if (result == 0) {
        return 0;  // the W call set the error
    }
    std::u16string wide_found(wide_out);
    std::string narrow;
    if (!narrow_out(wide_found, narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::size_t bytes = narrow.size() + 1;
    if (buffer_length < bytes) {
        set_last_error(kErrorInsufficientBuffer);
        return static_cast<std::uint32_t>(bytes);
    }
    std::memcpy(buffer, narrow.data(), narrow.size());
    buffer[narrow.size()] = '\0';
    if (file_part != nullptr) {
        const std::size_t sep = narrow.find_last_of("\\/");
        *file_part = buffer + (sep == std::string::npos ? 0 : sep + 1);
    }
    set_last_error(kErrorSuccess);
    return static_cast<std::uint32_t>(bytes);
}

// The drive enumeration: the presented system drive C: and the mounted host
// root Z:, each as a two-character root followed by a null, and the list
// closed by an empty string -- 9 units in total, which is also the count
// reported. A buffer that is too small is answered with the required size
// and nothing written, which is the documented contract.
extern "C" __attribute__((ms_abi)) std::uint32_t k32ad2_GetLogicalDriveStringsA(
    char* buffer, std::uint32_t size) noexcept {
    constexpr std::uint32_t kNeeded = 9;  // "C:\0Z:\0\0"
    if (buffer == nullptr || size < kNeeded) {
        return kNeeded;
    }
    std::memcpy(buffer, "C:\\", 4);
    std::memcpy(buffer + 4, "Z:\\", 4);
    buffer[8] = '\0';
    set_last_error(kErrorSuccess);
    return kNeeded;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32ad2_GetLogicalDriveStringsW(
    char16_t* buffer, std::uint32_t size) noexcept {
    constexpr std::uint32_t kNeeded = 9;
    if (buffer == nullptr || size < kNeeded) {
        return kNeeded;
    }
    constexpr char16_t kDrives[] = u"C:\\";
    constexpr char16_t kDrives2[] = u"Z:\\";
    for (std::size_t i = 0; i < 3; ++i) {
        buffer[i] = kDrives[i];
    }
    for (std::size_t i = 0; i < 3; ++i) {
        buffer[4 + i] = kDrives2[i];
    }
    buffer[8] = u'\0';
    set_last_error(kErrorSuccess);
    return kNeeded;
}

// The kind of drive a root path names. The drive model has two members --
// C: the presented system drive and Z: the mounted host root -- and both are
// fixed disks; any other root is a drive this runtime has no answer for.
extern "C" __attribute__((ms_abi)) std::uint32_t k32ad2_GetDriveTypeW(
    const char16_t* root) noexcept {
    if (root == nullptr) {
        return 1;  // DRIVE_NO_ROOT_DIR
    }
    char16_t letter = root[0];
    if (letter >= u'a' && letter <= u'z') {
        letter = static_cast<char16_t>(letter - u'a' + u'A');
    }
    if (letter == u'C' || letter == u'Z') {
        return 3;  // DRIVE_FIXED
    }
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32ad2_GetDriveTypeA(
    const char* root) noexcept {
    if (root == nullptr) {
        return 1;
    }
    char letter = root[0];
    if (letter >= 'a' && letter <= 'z') {
        letter = static_cast<char>(letter - 'a' + 'A');
    }
    if (letter == 'C' || letter == 'Z') {
        return 3;
    }
    return 1;
}

// The shared disk-space arithmetic: the host's real allocation counts,
// expressed in the cluster unit a guest reads. The presented cluster is
// 4096 bytes (8 sectors of 512), the shape NTFS presents, and the host
// counts are converted into that unit by division rather than assumed.
[[nodiscard]] std::int32_t disk_free_space_common(
    const char* root, std::uint32_t* sectors, std::uint32_t* bytes_per_sector,
    std::uint32_t* free_clusters, std::uint32_t* total_clusters) noexcept {
    struct statvfs buf {};
    if (!volume_statvfs(root == nullptr ? "" : root, buf)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    constexpr std::uint64_t kCluster = 4096;
    *sectors = 8;
    *bytes_per_sector = 512;
    const std::uint64_t frsize = static_cast<std::uint64_t>(buf.f_frsize);
    const std::uint64_t free_bytes =
        static_cast<std::uint64_t>(buf.f_bavail) * frsize;
    const std::uint64_t total_bytes =
        static_cast<std::uint64_t>(buf.f_blocks) * frsize;
    *free_clusters = static_cast<std::uint32_t>(free_bytes / kCluster);
    *total_clusters = static_cast<std::uint32_t>(total_bytes / kCluster);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetDiskFreeSpaceA(
    const char* root, std::uint32_t* sectors, std::uint32_t* bytes_per_sector,
    std::uint32_t* free_clusters, std::uint32_t* total_clusters) noexcept {
    if (sectors == nullptr || bytes_per_sector == nullptr ||
        free_clusters == nullptr || total_clusters == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return disk_free_space_common(root, sectors, bytes_per_sector,
                                  free_clusters, total_clusters);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetDiskFreeSpaceW(
    const char16_t* root, std::uint32_t* sectors,
    std::uint32_t* bytes_per_sector, std::uint32_t* free_clusters,
    std::uint32_t* total_clusters) noexcept {
    if (sectors == nullptr || bytes_per_sector == nullptr ||
        free_clusters == nullptr || total_clusters == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string narrow;
    if (root == nullptr ||
        !narrow_out(std::u16string_view(root), narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return disk_free_space_common(narrow.c_str(), sectors, bytes_per_sector,
                                  free_clusters, total_clusters);
}

// The extended disk-space query: the three byte counts from the same host
// statistics. The output pointers are optional, as Windows allows a caller
// to ask for only some of the three.
[[nodiscard]] std::int32_t disk_free_space_ex_common(
    const char* root, std::uint64_t* free_available, std::uint64_t* total,
    std::uint64_t* total_free) noexcept {
    struct statvfs buf {};
    if (!volume_statvfs(root == nullptr ? "" : root, buf)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint64_t frsize = static_cast<std::uint64_t>(buf.f_frsize);
    if (free_available != nullptr) {
        *free_available = static_cast<std::uint64_t>(buf.f_bavail) * frsize;
    }
    if (total != nullptr) {
        *total = static_cast<std::uint64_t>(buf.f_blocks) * frsize;
    }
    if (total_free != nullptr) {
        *total_free = static_cast<std::uint64_t>(buf.f_bfree) * frsize;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetDiskFreeSpaceExA(
    const char* root, std::uint64_t* free_available, std::uint64_t* total,
    std::uint64_t* total_free) noexcept {
    return disk_free_space_ex_common(root, free_available, total, total_free);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetDiskFreeSpaceExW(
    const char16_t* root, std::uint64_t* free_available, std::uint64_t* total,
    std::uint64_t* total_free) noexcept {
    std::string narrow;
    if (root == nullptr ||
        !narrow_out(std::u16string_view(root), narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return disk_free_space_ex_common(narrow.c_str(), free_available, total,
                                     total_free);
}

// The volume information for a root. The host statistics validate the root
// and supply the counts; the volume name is empty (the host root carries no
// label), the serial is a stable hash of the host machine-id, the maximum
// component length is the NTFS 255, and the flags describe the host's ext4
// semantics -- case-sensitive and case-preserving names, unicode, hard
// links and extended attributes -- while the file-system type is the NTFS
// this runtime presents.
[[nodiscard]] std::int32_t volume_info_common(
    const std::string& root, void* name, std::uint32_t name_units,
    std::uint32_t* serial, std::uint32_t* max_len, std::uint32_t* flags,
    void* fs_type, std::uint32_t fs_units, bool wide) noexcept {
    struct statvfs buf {};
    if (!volume_statvfs(root, buf)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (name != nullptr) {
        if (name_units == 0) {
            set_last_error(kErrorInsufficientBuffer);
            return 0;
        }
        if (wide) {
            auto* out = static_cast<char16_t*>(name);
            out[0] = u'\0';
        } else {
            auto* out = static_cast<char*>(name);
            out[0] = '\0';
        }
    }
    if (serial != nullptr) {
        *serial = stable_volume_serial();
    }
    if (max_len != nullptr) {
        *max_len = 255;
    }
    if (flags != nullptr) {
        // FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES |
        // FILE_UNICODE_ON_DISK | FILE_SUPPORTS_HARD_LINKS |
        // FILE_SUPPORTS_EXTENDED_ATTRIBUTES.
        *flags = 0x00000001u | 0x00000002u | 0x00000004u |
                 0x00400000u | 0x00800000u;
    }
    constexpr const char* kNtfs = "NTFS";
    constexpr std::size_t kNtfsLen = 4;
    if (fs_type != nullptr) {
        if (fs_units <= kNtfsLen) {
            set_last_error(kErrorInsufficientBuffer);
            return 0;
        }
        if (wide) {
            auto* out = static_cast<char16_t*>(fs_type);
            for (std::size_t i = 0; i < kNtfsLen; ++i) {
                out[i] = static_cast<char16_t>(kNtfs[i]);
            }
            out[kNtfsLen] = u'\0';
        } else {
            auto* out = static_cast<char*>(fs_type);
            std::memcpy(out, kNtfs, kNtfsLen);
            out[kNtfsLen] = '\0';
        }
    }
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetVolumeInformationA(
    const char* root, char* name, std::uint32_t name_len,
    std::uint32_t* serial, std::uint32_t* max_len, std::uint32_t* flags,
    char* fs_type, std::uint32_t fs_type_len) noexcept {
    return volume_info_common(root == nullptr ? "" : root, name, name_len,
                              serial, max_len, flags, fs_type, fs_type_len,
                              false);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetVolumeInformationW(
    const char16_t* root, char16_t* name, std::uint32_t name_len,
    std::uint32_t* serial, std::uint32_t* max_len, std::uint32_t* flags,
    char16_t* fs_type, std::uint32_t fs_type_len) noexcept {
    std::string narrow;
    if (root == nullptr ||
        !narrow_out(std::u16string_view(root), narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return volume_info_common(narrow, name, name_len, serial, max_len, flags,
                              fs_type, fs_type_len, true);
}

// The W spelling of the temporary-name maker: the inputs are converted to
// narrow, the A call that owns the file creation runs, and the generated
// name is converted back. The number the A call chose is the answer.
extern "C" __attribute__((ms_abi)) std::uint32_t k32ad2_GetTempFileNameW(
    const char16_t* path, const char16_t* prefix, std::uint32_t unique,
    char16_t* buffer) noexcept {
    if (path == nullptr || buffer == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string narrow_path;
    if (!narrow_out(std::u16string_view(path), narrow_path).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string narrow_prefix;
    if (prefix != nullptr &&
        !narrow_out(std::u16string_view(prefix), narrow_prefix).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string out_narrow;
    out_narrow.resize(2048);
    const std::uint32_t number = k32pe_GetTempFileNameA(
        narrow_path.c_str(),
        narrow_prefix.empty() ? nullptr : narrow_prefix.c_str(), unique,
        out_narrow.data());
    if (number == 0) {
        return 0;  // the A call set the error
    }
    const std::size_t len = std::strlen(out_narrow.data());
    std::u16string wide;
    if (!narrow_in(std::string_view(out_narrow.data(), len), wide).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The W contract requires a MAX_PATH buffer for the result; the temp
    // path is bounded by the input path plus the 3-char prefix, six digits
    // and ".tmp", so it fits.
    for (std::size_t i = 0; i < wide.size(); ++i) {
        buffer[i] = wide[i];
    }
    buffer[wide.size()] = u'\0';
    set_last_error(kErrorSuccess);
    return number;
}

// The A spelling of the module query. When FROM_ADDRESS is set the "name"
// is really an address and is handed through untouched; otherwise it is
// converted to wide and the W call that owns the decision runs.
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetModuleHandleExA(
    std::uint32_t flags, const char* name, void** module) noexcept {
    if (module == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    constexpr std::uint32_t kFromAddress = 0x4u;
    if ((flags & kFromAddress) != 0) {
        return k32c2_GetModuleHandleExW(
            flags, reinterpret_cast<const char16_t*>(name), module);
    }
    std::u16string wide;
    if (name != nullptr) {
        if (!narrow_in(std::string_view(name), wide).converted) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
    }
    return k32c2_GetModuleHandleExW(
        flags, wide.empty() ? nullptr : wide.c_str(), module);
}

// The code-page-info-ex pair. The only ANSI code page this runtime carries
// is UTF-8, so CP_ACP, CP_OEMCP, CP_THREAD_ACP and CP_UTF8 all answer the
// UTF-8 record and every other page is refused with ERROR_INVALID_PARAMETER
// -- the answer a conversion this runtime does not have would earn later
// anyway. The signature is the real Windows one: `dwFlags` must be zero,
// and there is no separate name-length parameter.
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetCPInfoExW(
    std::uint32_t code_page, std::uint32_t flags, void* buffer) noexcept {
    if (flags != 0 || buffer == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    switch (code_page) {
        case 0:     // CP_ACP
        case 1:     // CP_OEMCP
        case 3:     // CP_THREAD_ACP
        case 65001: // CP_UTF8
            break;
        default:
            set_last_error(kErrorInvalidParameter);
            return 0;
    }
    fill_cpinfoex(buffer, true);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetCPInfoExA(
    std::uint32_t code_page, std::uint32_t flags, void* buffer) noexcept {
    if (flags != 0 || buffer == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    switch (code_page) {
        case 0:
        case 1:
        case 3:
        case 65001:
            break;
        default:
            set_last_error(kErrorInvalidParameter);
            return 0;
    }
    fill_cpinfoex(buffer, false);
    set_last_error(kErrorSuccess);
    return 1;
}

// The process window station. user32_windows.cpp keeps windows and classes
// but no window-station object and no handle namespace for one; a headless
// runtime has no station to return, and handing out a value here would be
// an object the guest could then try to open or close that does not exist.
extern "C" __attribute__((ms_abi)) std::uint64_t k32ad2_GetProcessWindowStation(
    void) noexcept {
    set_last_error(kErrorNotSupported);
    return 0;
}

// The session the process runs in. The guest is a thread of this host
// process, so the host's session is the honest answer; `getsid` reads it,
// and a host without a session (a container) reports 0, which is also the
// service answer Windows gives a non-interactive process.
extern "C" __attribute__((ms_abi)) std::uint32_t k32ad2_GetProcessSessionId(
    void) noexcept {
    const pid_t sid = ::getsid(0);
    return sid < 0 ? 0 : static_cast<std::uint32_t>(sid);
}

// ===========================================================================
// USER32
// ===========================================================================

// The keyboard layouts, as HKLs. One layout exists, the US one whose
// language id matches the LCID the locale queries answer; its HKL value is
// 0x04090409. Each HKL is a pointer-sized word, which is how the caller
// sizes its array.
extern "C" __attribute__((ms_abi)) std::int32_t u32ad2_GetKeyboardLayoutList(
    std::uint32_t num_entries, void* layouts) noexcept {
    if (num_entries == 0) {
        // A size query: the number of layouts available.
        return 1;
    }
    if (layouts == nullptr) {
        return 0;
    }
    write_u64(layouts, 0, 0x04090409ull);
    return 1;
}

// The keyboard type, answered the way a modern 64-bit Windows answers: an
// enhanced 101/102-key keyboard with twelve function keys.
extern "C" __attribute__((ms_abi)) std::uint32_t u32ad2_GetKeyboardType(
    std::uint32_t type_id) noexcept {
    switch (type_id) {
        case 0:
            return 4;  // enhanced 101/102-key
        case 1:
            return 0;  // no separate function-key block
        case 2:
            return 12;  // twelve function keys
        default:
            return 0;
    }
}

// ===========================================================================
// The registration
// ===========================================================================

void add_ntdll_antidebug2(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    const auto pair = [&e](const char* nt, const char* zw, void* fn) {
        e(nt, fn);
        e(zw, fn);
    };
    // The debug-filter and kernel-debug-control pair.
    pair("NtQueryDebugFilterState", "ZwQueryDebugFilterState",
         reinterpret_cast<void*>(&ntad2_NtQueryDebugFilterState));
    pair("NtSystemDebugControl", "ZwSystemDebugControl",
         reinterpret_cast<void*>(&ntad2_NtSystemDebugControl));
    // The thread suspension pair.
    pair("NtSuspendThread", "ZwSuspendThread",
         reinterpret_cast<void*>(&ntad2_NtSuspendThread));
    pair("NtResumeThread", "ZwResumeThread",
         reinterpret_cast<void*>(&ntad2_NtResumeThread));
    // The exception raise/continue pair.
    pair("NtRaiseException", "ZwRaiseException",
         reinterpret_cast<void*>(&ntad2_NtRaiseException));
    pair("NtContinue", "ZwContinue",
         reinterpret_cast<void*>(&ntad2_NtContinue));
    // The alertable-wait pair.
    pair("NtDelayExecution", "ZwDelayExecution",
         reinterpret_cast<void*>(&ntad2_NtDelayExecution));
    pair("NtTestAlert", "ZwTestAlert",
         reinterpret_cast<void*>(&ntad2_NtTestAlert));
    // The debug-object pair: a process without a debug port.
    pair("NtWaitForDebugEvent", "ZwWaitForDebugEvent",
         reinterpret_cast<void*>(&ntad2_NtWaitForDebugEvent));
    pair("NtRemoveProcessDebug", "ZwRemoveProcessDebug",
         reinterpret_cast<void*>(&ntad2_NtRemoveProcessDebug));
    // The timer-resolution pair.
    pair("NtQueryTimerResolution", "ZwQueryTimerResolution",
         reinterpret_cast<void*>(&ntad2_NtQueryTimerResolution));
    pair("NtSetTimerResolution", "ZwSetTimerResolution",
         reinterpret_cast<void*>(&ntad2_NtSetTimerResolution));
    // The single-name entries: the debug prints and the handler validity
    // query have no Zw twin.
    e("DbgPrint", reinterpret_cast<void*>(&ntad2_DbgPrint));
    e("DbgPrintEx", reinterpret_cast<void*>(&ntad2_DbgPrintEx));
    e("RtlIsValidHandler", reinterpret_cast<void*>(&ntad2_RtlIsValidHandler));
}

void add_kernel32_antidebug2(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    // The WOW64 and DEP policy pair.
    e("IsWow64Process", reinterpret_cast<void*>(&k32ad2_IsWow64Process));
    e("IsWow64Process2", reinterpret_cast<void*>(&k32ad2_IsWow64Process2));
    e("Wow64GetThreadContext",
      reinterpret_cast<void*>(&k32ad2_Wow64GetThreadContext));
    e("Wow64SetThreadContext",
      reinterpret_cast<void*>(&k32ad2_Wow64SetThreadContext));
    e("GetProcessDEPPolicy",
      reinterpret_cast<void*>(&k32ad2_GetProcessDEPPolicy));
    e("SetProcessDEPPolicy",
      reinterpret_cast<void*>(&k32ad2_SetProcessDEPPolicy));
    // The process and processor queries.
    e("GetProcessTimes", reinterpret_cast<void*>(&k32ad2_GetProcessTimes));
    e("SetProcessAffinityMask",
      reinterpret_cast<void*>(&k32ad2_SetProcessAffinityMask));
    e("SetThreadAffinityMask",
      reinterpret_cast<void*>(&k32ad2_SetThreadAffinityMask));
    e("QueryThreadCycleTime",
      reinterpret_cast<void*>(&k32ad2_QueryThreadCycleTime));
    e("QueryIdleProcessorCycleTime",
      reinterpret_cast<void*>(&k32ad2_QueryIdleProcessorCycleTime));
    e("GetActiveProcessorCount",
      reinterpret_cast<void*>(&k32ad2_GetActiveProcessorCount));
    e("GetProcessorInformation",
      reinterpret_cast<void*>(&k32ad2_GetProcessorInformation));
    // The system-information queries.
    e("GetVersionExW", reinterpret_cast<void*>(&k32ad2_GetVersionExW));
    e("EnumSystemFirmwareTables",
      reinterpret_cast<void*>(&k32ad2_EnumSystemFirmwareTables));
    e("GetProductInfo", reinterpret_cast<void*>(&k32ad2_GetProductInfo));
    // The locale family.
    e("GetLocaleInfoA", reinterpret_cast<void*>(&k32ad2_GetLocaleInfoA));
    e("GetLocaleInfoW", reinterpret_cast<void*>(&k32ad2_GetLocaleInfoW));
    e("GetUserDefaultLCID",
      reinterpret_cast<void*>(&k32ad2_GetUserDefaultLCID));
    e("GetUserDefaultLangID",
      reinterpret_cast<void*>(&k32ad2_GetUserDefaultLangID));
    e("GetSystemDefaultLangID",
      reinterpret_cast<void*>(&k32ad2_GetSystemDefaultLangID));
    // The path and volume family.
    e("GetSystemWow64DirectoryA",
      reinterpret_cast<void*>(&k32ad2_GetSystemWow64DirectoryA));
    e("GetSystemWow64DirectoryW",
      reinterpret_cast<void*>(&k32ad2_GetSystemWow64DirectoryW));
    e("SearchPathA", reinterpret_cast<void*>(&k32ad2_SearchPathA));
    e("SearchPathW", reinterpret_cast<void*>(&k32ad2_SearchPathW));
    e("GetLogicalDriveStringsA",
      reinterpret_cast<void*>(&k32ad2_GetLogicalDriveStringsA));
    e("GetLogicalDriveStringsW",
      reinterpret_cast<void*>(&k32ad2_GetLogicalDriveStringsW));
    e("GetDriveTypeA", reinterpret_cast<void*>(&k32ad2_GetDriveTypeA));
    e("GetDriveTypeW", reinterpret_cast<void*>(&k32ad2_GetDriveTypeW));
    e("GetDiskFreeSpaceA",
      reinterpret_cast<void*>(&k32ad2_GetDiskFreeSpaceA));
    e("GetDiskFreeSpaceW",
      reinterpret_cast<void*>(&k32ad2_GetDiskFreeSpaceW));
    e("GetDiskFreeSpaceExA",
      reinterpret_cast<void*>(&k32ad2_GetDiskFreeSpaceExA));
    e("GetDiskFreeSpaceExW",
      reinterpret_cast<void*>(&k32ad2_GetDiskFreeSpaceExW));
    e("GetVolumeInformationA",
      reinterpret_cast<void*>(&k32ad2_GetVolumeInformationA));
    e("GetVolumeInformationW",
      reinterpret_cast<void*>(&k32ad2_GetVolumeInformationW));
    e("GetTempFileNameW",
      reinterpret_cast<void*>(&k32ad2_GetTempFileNameW));
    e("GetModuleHandleExA",
      reinterpret_cast<void*>(&k32ad2_GetModuleHandleExA));
    e("GetCPInfoExA", reinterpret_cast<void*>(&k32ad2_GetCPInfoExA));
    e("GetCPInfoExW", reinterpret_cast<void*>(&k32ad2_GetCPInfoExW));
    // The station and session.
    e("GetProcessWindowStation",
      reinterpret_cast<void*>(&k32ad2_GetProcessWindowStation));
    e("GetProcessSessionId",
      reinterpret_cast<void*>(&k32ad2_GetProcessSessionId));
}

void add_user32_antidebug2(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("GetKeyboardLayoutList",
      reinterpret_cast<void*>(&u32ad2_GetKeyboardLayoutList));
    e("GetKeyboardType", reinterpret_cast<void*>(&u32ad2_GetKeyboardType));
}

}  // namespace occ::runtime::winabi

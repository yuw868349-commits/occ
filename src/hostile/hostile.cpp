// Implementation of the hostile hardening contract (see hostile.h).

#include "occ/hostile/hostile.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <string_view>

namespace occ::hostile {

namespace {

// NT global-flag bits a debugger sets on the target: the heap debugging
// trio plus tagging/creation-checking and the stack-trace / page-allocation
// flags that detectors probe.
constexpr std::uint32_t kHeapTailCheck = 0x10;
constexpr std::uint32_t kHeapFreeCheck = 0x20;
constexpr std::uint32_t kHeapValidate = 0x40;
constexpr std::uint32_t kHeapTagCheck = 0x80;
constexpr std::uint32_t kHeapCreateCheck = 0x100;
constexpr std::uint32_t kHeapPageAllocs = 0x02000000;
constexpr std::uint32_t kUserStackTrace = 0x1000000;

constexpr std::uint32_t kDebuggerNtGlobalFlagMask =
    kHeapTailCheck | kHeapFreeCheck | kHeapValidate | kHeapTagCheck |
    kHeapCreateCheck | kHeapPageAllocs | kUserStackTrace;

// The same set lives on the heap header's Flags word.
constexpr std::uint32_t kHeapDebugMask =
    kHeapTailCheck | kHeapFreeCheck | kHeapValidate | kHeapTagCheck |
    kHeapCreateCheck;

} // namespace

PebPatches compute_peb_patches() noexcept {
    PebPatches out;
    // PEB.BeingDebugged (x64 PEB +0x02, 1 byte): the classic readable
    // probe; clearing it means writing zero, i.e. masking out all bits.
    out.patches.push_back({0x02, 1, 0xFF, false});
    // PEB.NtGlobalFlag (x64 PEB +0x68, 4 bytes): strip the debugger heap
    // bits the loader sets under a debugger.
    out.patches.push_back({0x68, 4, kDebuggerNtGlobalFlagMask, false});
    // PEB.ProcessHeap (x64 PEB +0x30, 8 bytes): the heap pointer itself
    // is left alone; this entry only marks that heap patches below are
    // conditional on the pointer resolving to a real header.
    out.patches.push_back({0x30, 8, 0, true});
    // HEAP.Flags (heap header +0x70): clear the debugger heap bits,
    // leaving the loader's GROWABLE bit.
    out.patches.push_back({0x70, 4, kHeapDebugMask, true});
    // HEAP.ForceFlags (heap header +0x74): a debugger sets nonzero force
    // flags; zero is the clean value.
    out.patches.push_back({0x74, 4, 0xFFFFFFFF, true});
    out.needs_heap = true;
    return out;
}

ClockModel::ClockModel(std::uint64_t qpc0, std::uint64_t ms0,
                       std::uint64_t qpc_per_ms) noexcept
    : qpc0_(qpc0), ms0_(ms0),
      slope_num_(qpc_per_ms), slope_den_(1), valid_(true) {}

ClockModel ClockModel::calibrate(std::uint64_t qpc_a, std::uint64_t ms_a,
                                 std::uint64_t qpc_b,
                                 std::uint64_t ms_b) noexcept {
    ClockModel m(qpc_a, ms_a, 1);
    if (qpc_b <= qpc_a || ms_b <= ms_a) {
        m.valid_ = false; // refuse a zero/negative elapsed window
        return m;
    }
    const std::uint64_t dq = qpc_b - qpc_a;
    const std::uint64_t dm = ms_b - ms_a;
    // slope = dq / dm ticks per ms, kept as a fraction.
    m.slope_num_ = dq;
    m.slope_den_ = dm;
    m.valid_ = true;
    return m;
}

std::uint64_t ClockModel::now_ms(std::uint64_t qpc) const noexcept {
    if (!valid_ || qpc < qpc0_) {
        return ms0_;
    }
    const std::uint64_t el = qpc - qpc0_;
    // el * slope_num / slope_den, computed in 128-bit to avoid overflow
    // on long uptimes.
    // slope = slope_num_/slope_den_ ticks per ms, so elapsed ms is
    // el / slope = el * slope_den_ / slope_num_.
    const __uint128_t scaled =
        (static_cast<__uint128_t>(el) * slope_den_) / slope_num_;
    return ms0_ + static_cast<std::uint64_t>(scaled);
}

std::uint64_t ClockModel::qpc_for(std::uint64_t ms) const noexcept {
    if (!valid_ || ms < ms0_) {
        return qpc0_;
    }
    const __uint128_t el =
        (static_cast<__uint128_t>(ms - ms0_) * slope_num_) / slope_den_;
    return qpc0_ + static_cast<std::uint64_t>(el);
}

QueryAnswer answer_process_info(std::uint32_t info_class,
                                std::uint64_t query_arg) noexcept {
    (void)query_arg;
    switch (info_class) {
    case 7: // ProcessDebugPort: zero means no debugger.
        return {0, 0, true};
    case 8: // ProcessDebugObjectHandle: a null handle.
        return {0, 0, true};
    case 30: // ProcessDebugFlags: 1 == "not debugged" (inverted bit).
        return {0, 1, true};
    default:
        // No opinion; the caller passes the real answer through.
        return {0, 0, false};
    }
}

QueryAnswer answer_system_info(std::uint32_t info_class) noexcept {
    if (info_class == 34) { // KernelDebuggerInformation
        // Both the debugger-enabled and debugger-present booleans are
        // false; the output is a single zero dword.
        return {0, 0, true};
    }
    return {0, 0, false};
}

Plan build_plan(const Config& cfg) noexcept {
    Plan p;
    if (cfg.answer_debug_queries) {
        p.replace_answers.push_back("ntdll.NtQueryInformationProcess");
        p.replace_answers.push_back("ntdll.NtQuerySystemInformation");
        p.replace_answers.push_back("kernel32.IsDebuggerPresent");
        p.replace_answers.push_back("kernel32.CheckRemoteDebuggerPresent");
    }
    if (cfg.hide_peb) {
        p.peb_patches = compute_peb_patches();
        p.has_peb_patches = true;
    }
    if (cfg.uniform_time) {
        p.clock = ClockModel(0, 0, 10000); // 10 MHz default, calibrate later
        p.has_clock = true;
    }
    if (cfg.hide_environment) {
        // The environment fingerprint answer is data-driven through
        // environment_hidden(); the plan only marks the surface on.
        // (No API names: the integration consults environment_hidden()
        // on the relevant opens/creates.)
    }
    if (cfg.trap_policy) {
        p.traps = TrapPolicy{}; // defaults: deliver to guest, honest answer
    }
    return p;
}

// ---------------------------------------------------------------------------
// Extended surfaces
// ---------------------------------------------------------------------------

QueryAnswer answer_thread_info(std::uint32_t info_class) noexcept {
    // ThreadHideFromDebugger (0x11): an undebugged thread has no hide
    // flag, so the query reports "not hidden" with success.
    if (info_class ==
        static_cast<std::uint32_t>(ThreadInfoClass::kHideFromDebugger)) {
        return {0, 0, true};
    }
    return {0, 0, false};
}

QueryAnswer answer_set_thread_info(std::uint32_t info_class) noexcept {
    // Setting ThreadHideFromDebugger succeeds; the hide flag is what the
    // API surface claims. (The hostile layer computes answers; the
    // integration decides whether the guest's own hide request is
    // honored or simply acknowledged.)
    if (info_class ==
        static_cast<std::uint32_t>(ThreadInfoClass::kHideFromDebugger)) {
        return {0, 0, true};
    }
    return {0, 0, false};
}

TimeAnswers clock_reads(const ClockModel& model, std::uint64_t host_qpc,
                        std::uint64_t host_ms) noexcept {
    TimeAnswers a;
    // The uptime clocks come from the model: one monotonic slope, so
    // GetTickCount/GetTickCount64/QueryPerformanceCounter can never
    // disagree with each other.
    a.tick_count64_ms = model.now_ms(host_qpc);
    a.tick_count_ms = a.tick_count64_ms;
    a.qpc = host_qpc;
    // RDTSC is the raw counter; on any modern host QPC is derived from
    // it, so the low dword of the model's qpc is the honest read.
    a.rdtsc = static_cast<std::uint32_t>(host_qpc & 0xFFFFFFFFull);
    // The wall clock (FileTime) is the Unix-epoch host sample shifted to
    // the 1601-01-01 epoch and scaled to 100 ns ticks. The shift is
    // 11644473600 seconds between the two epochs.
    const std::uint64_t ft_100ns =
        (host_ms + 11644473600000ull) * 10000ull;
    a.system_time_ft = ft_100ns;
    return a;
}

namespace {

// The analyst fingerprint table, one entry per named tool/object. Each
// comment names the tool; entries without a reliable public source are
// deliberately absent (an invented fingerprint is worse than none: a
// guest probing a name that never existed learns nothing, while a wrong
// answer teaches it the hiding scheme).
const Fingerprint kFingerprints[] = {
    // Window classes debuggers/analysts create.
    {FingerprintKind::kWindowClass, "OLLYDBG"},          // OllyDbg
    {FingerprintKind::kWindowClass, "ID"},               // IDA
    {FingerprintKind::kWindowClass, "WinDbgFrameClass"}, // WinDbg
    {FingerprintKind::kWindowClass, "x64dbg"},
    {FingerprintKind::kWindowClass, "x32dbg"},
    // Mutexes debugging tools create (probed by CreateMutex/OpenMutex
    // with a name, and by checking whether the mutex already exists).
    {FingerprintKind::kMutex, "ollydbg"},   // OllyDbg
    {FingerprintKind::kMutex, "x64dbg"},
    {FingerprintKind::kMutex, "x32dbg"},
    {FingerprintKind::kMutex, "WinDbg"},    // WinDbg (DbgX)
    {FingerprintKind::kMutex, "SyserDbg"},  // Syser kernel debugger
    {FingerprintKind::kMutex, "TitanHide"}, // TitanHide (a hiding tool
                                            // that itself fingerprints)
    {FingerprintKind::kMutex, "TsDebug"},   // TitanHide's older mutex
    // Kernel-mode analyst drivers (probed via CreateFile of the device
    // path, or service-name queries).
    {FingerprintKind::kDriver, "Syser"},    // Syser.sys
    {FingerprintKind::kDriver, "TitanHide"},
    // Registry keys left by analyst installers.
    {FingerprintKind::kRegistryKey, "Software\\OLLYDBG"},    // OllyDbg
    {FingerprintKind::kRegistryKey, "Software\\x64dbg"},
    // Analyst processes a self-defending guest scans for by name.
    {FingerprintKind::kProcessName, "ollydbg.exe"},
    {FingerprintKind::kProcessName, "x64dbg.exe"},
    {FingerprintKind::kProcessName, "x32dbg.exe"},
    {FingerprintKind::kProcessName, "windbg.exe"},
    {FingerprintKind::kProcessName, "ida.exe"},
    {FingerprintKind::kProcessName, "ida64.exe"},
    {FingerprintKind::kProcessName, "idaq.exe"},
    {FingerprintKind::kProcessName, "idaq64.exe"},
    {FingerprintKind::kProcessName, "cdb.exe"},    // WinDbg console
    {FingerprintKind::kProcessName, "ntsd.exe"},   // WinDbg symbol server
    {FingerprintKind::kProcessName, "cheatengine-x86_64.exe"},
    {FingerprintKind::kProcessName, "processhacker.exe"},
};

// The analyst module names recognized in an address map. Kept separate
// from the process table because a map names the image file, not the
// process.
constexpr const char* kMapAnalystNames[] = {
    "ollydbg", "x64dbg", "x32dbg", "windbg", "ida", "idaq",
    "gdb", "radare2", "winedbg", "cheatengine",
};

bool name_matches(std::string_view name, std::string_view fp) noexcept {
    // Exact, case-insensitive on the printable-ASCII subset.
    if (name.size() != fp.size()) {
        return false;
    }
    for (std::size_t i = 0; i < name.size(); ++i) {
        char a = name[i];
        char b = fp[i];
        if (a >= 'A' && a <= 'Z') {
            a = static_cast<char>(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = static_cast<char>(b - 'A' + 'a');
        }
        if (a != b) {
            return false;
        }
    }
    return true;
}

std::uint32_t parse_u32(std::string_view s) noexcept {
    std::uint32_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') {
            break;
        }
        const std::uint64_t nv =
            static_cast<std::uint64_t>(v) * 10ull +
            static_cast<std::uint64_t>(c - '0');
        if (nv > 0xFFFFFFFFull) {
            return 0xFFFFFFFFu;
        }
        v = static_cast<std::uint32_t>(nv);
    }
    return v;
}

std::string_view field_after_close_paren(std::string_view s,
                                         std::size_t skip) noexcept {
    // /proc/self/stat: `pid (comm) state ppid ...`. The comm may contain
    // spaces and parentheses, so the split starts after the last ')'.
    const std::size_t close = s.rfind(')');
    if (close == std::string_view::npos) {
        return {};
    }
    std::size_t pos = close + 1;
    std::size_t skipped = 0;
    while (pos < s.size()) {
        while (pos < s.size() &&
               (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n')) {
            ++pos;
        }
        const std::size_t start = pos;
        while (pos < s.size() && s[pos] != ' ' && s[pos] != '\t' &&
               s[pos] != '\n') {
            ++pos;
        }
        if (skipped == skip) {
            return s.substr(start, pos - start);
        }
        ++skipped;
        if (skipped > skip) {
            break;
        }
    }
    return {};
}

} // namespace

const std::vector<Fingerprint>& fingerprint_table() noexcept {
    static const std::vector<Fingerprint> table(
        std::begin(kFingerprints), std::end(kFingerprints));
    return table;
}

bool environment_hidden(std::string_view name,
                        FingerprintKind kind) noexcept {
    for (const Fingerprint& fp : kFingerprints) {
        if (fp.kind == kind && name_matches(name, fp.name)) {
            return true;
        }
    }
    return false;
}

bool environment_hidden(std::string_view name) noexcept {
    for (const Fingerprint& fp : kFingerprints) {
        if (name_matches(name, fp.name)) {
            return true;
        }
    }
    return false;
}

TrapDisposition policy_for(const TrapPolicy& policy,
                           TrapKind kind) noexcept {
    switch (kind) {
    case TrapKind::kInt3:
        return policy.int3;
    case TrapKind::kSingleStep:
        return policy.single_step;
    case TrapKind::kBreakpointFault:
        return policy.breakpoint_fault;
    case TrapKind::kInt2D:
        // The honest undebugged behavior for int 0x2D is the same as for
        // int 3: the exception reaches the guest's handler.
        return policy.int3;
    case TrapKind::kIllegalInstruction:
        // UD2 and friends are delivered to the guest's own handler.
        return policy.int3;
    case TrapKind::kPrivilegedInstruction:
        // Anti-VM ring-0 probes trap and are delivered to the guest;
        // faking success here would teach the guest the hiding scheme.
        return policy.int3;
    }
    return policy.int3;
}

DebugRegisters undebugged_dr() noexcept {
    DebugRegisters dr;
    // DR6: no pending debug exception. DR7: no enabled breakpoints.
    // DR0-DR3: no addresses. All zero is the canonical clean image.
    dr.dr6 = 0;
    dr.dr7 = 0;
    return dr;
}

std::vector<BreakpointHit> scan_breakpoints(const std::uint8_t* bytes,
                                            std::size_t n,
                                            const std::uint8_t* pristine)
    noexcept {
    std::vector<BreakpointHit> hits;
    if (bytes == nullptr || n == 0) {
        return hits;
    }
    for (std::size_t i = 0; i < n; ++i) {
        if (bytes[i] != 0xCC) {
            continue;
        }
        BreakpointHit hit;
        hit.offset = i;
        if (pristine != nullptr) {
            hit.original = pristine[i];
            hit.original_known = true;
        }
        hits.push_back(hit);
    }
    return hits;
}

HostProbe probe_host(std::string_view status_text,
                     std::string_view stat_text,
                     std::string_view maps_text) noexcept {
    HostProbe p;
    // TracerPid: field of /proc/self/status, "TracerPid:\t<pid>".
    constexpr std::string_view kTracer = "TracerPid:";
    const std::size_t tp = status_text.find(kTracer);
    if (tp != std::string_view::npos) {
        std::size_t pos = tp + kTracer.size();
        while (pos < status_text.size() &&
               (status_text[pos] == ' ' || status_text[pos] == '\t' ||
                status_text[pos] == ':')) {
            ++pos;
        }
        const std::size_t start = pos;
        while (pos < status_text.size() &&
               status_text[pos] >= '0' && status_text[pos] <= '9') {
            ++pos;
        }
        const std::string_view val = status_text.substr(start, pos - start);
        p.tracer_pid = parse_u32(val);
        p.traced = p.tracer_pid != 0;
    }
    // /proc/self/stat: field 4 after the comm is the parent pid.
    const std::string_view ppid = field_after_close_paren(stat_text, 1);
    if (!ppid.empty()) {
        p.parent_pid = parse_u32(ppid);
    }
    // The address map: any line naming an analyst image marks the map.
    for (std::string_view name : kMapAnalystNames) {
        std::size_t at = 0;
        while ((at = maps_text.find(name, at)) != std::string_view::npos) {
            // A name inside a longer unrelated word (e.g. "x64dbghelper")
            // is still an analyst image; no boundary test is applied.
            p.analyst_in_maps = true;
            break;
        }
    }
    return p;
}

} // namespace occ::hostile

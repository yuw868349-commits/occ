// Implementation of the hostile hardening contract (see hostile.h).

#include "occ/hostile/hostile.h"

#include <algorithm>
#include <cstdint>
#include <cstring>

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

// Analyst fingerprints probed by name. Kept deliberately short and
// documented; every entry is a window class, mutex, pipe or registry key
// a debugging/analysis tool leaves behind and a packed binary tests for.
constexpr const char* kEnvironmentFingerprints[] = {
    "OLLYDBG",       // OllyDbg window class
    "ollydbg",       // OllyDbg mutex
    "x64dbg",        // x64dbg mutex / window
    "x32dbg",
    "WinDbg",        // WinDbg window class
    "windbg",
    "ID",            // IDA window class ("ID" is the actual class)
    "Syser",         // Syser kernel debugger mutex
    "SyserDbg",
    "TsDebug",       // TitanHide mutex (a hiding tool that itself is a
                     // fingerprint when present)
};

bool name_is_fingerprint(std::string_view name) noexcept {
    // Exact, case-insensitive on the printable-ASCII subset. The table is
    // short and linear scans are fine at this frequency (name probes are
    // rare and cheap).
    for (const char* fp : kEnvironmentFingerprints) {
        const std::size_t fl = std::strlen(fp);
        if (name.size() != fl) {
            continue;
        }
        bool eq = true;
        for (std::size_t i = 0; i < fl; ++i) {
            char a = name[i];
            char b = fp[i];
            if (a >= 'A' && a <= 'Z') {
                a = static_cast<char>(a - 'A' + 'a');
            }
            if (b >= 'A' && b <= 'Z') {
                b = static_cast<char>(b - 'A' + 'a');
            }
            if (a != b) {
                eq = false;
                break;
            }
        }
        if (eq) {
            return true;
        }
    }
    return false;
}

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

bool environment_hidden(std::string_view name) noexcept {
    return name_is_fingerprint(name);
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

} // namespace occ::hostile

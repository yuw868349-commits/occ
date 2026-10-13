// The anti-analysis engine for a guest the analyst cannot trace.
//
// The PE runtime's guest is native code this process runs in-process, so
// there is no tracer between the analyst and the guest: the only vantage
// point is the guest's own view. A guest that was written to defend
// itself looks at the debugger-shaped objects a normal Windows process
// would have, and the purpose of this module is to make those objects
// answer the way an undebugged process would.
//
// The surfaces a self-defending guest probes, and what this module does
// about each, are the five below. Everything here is a computation with a
// testable input and output; nothing here pokes memory it does not own,
// and the caller (the integration point) decides which computed answer is
// actually wired into the runtime's API surface.
//
//   * PEB fields. BeingDebugged (PEB+0x02), NtGlobalFlag (PEB+0x68) and
//     the ProcessHeap's Flags/ForceFlags are the classic readable probes.
//     `compute_peb_patches` answers the byte/word/dword patches that clear
//     them, as offsets, widths and masks -- the offsets are structure
//     facts, the masks are the anti-detection constants, and the caller
//     applies them to the PEB image it owns.
//
//   * Debug queries. NtQueryInformationProcess classes 7 (DebugPort),
//     8 (DebugObjectHandle) and 30 (DebugFlags), and
//     NtQuerySystemInformation's KernelDebuggerInformation, are answered
//     by `answer_process_info` / `answer_system_info` with the NTSTATUS
//     and output an undebugged process would produce. A class this module
//     does not model is passed through untouched -- refusing to guess is
//     part of the contract.
//
//   * Time. GetTickCount and QueryPerformanceCounter must agree with each
//     other and with the wall clock, or a guest that reads two clocks and
//     compares them detects the lie. `ClockModel` is one monotonic linear
//     model: calibrated from two (qpc, wall-ms) samples, every time API
//     reads from it, so no two clocks can disagree.
//
//   * Environment fingerprints. Debugger window classes, mutexes, pipes
//     and registry keys are probed by name. `environment_hidden` carries
//     the fingerprint table and answers "not found" for any of them; the
//     table is data, not logic, and is kept deliberately short and
//     documented.
//
//   * The trap surface. A guest that installs a vectored/SEH handler and
//     executes int3, or that sets TF, observes the exception. `TrapPolicy`
//     names what the integration should do per trap kind (deliver to the
//     guest's SEH, ignore, or fault); this module does not execute
//     exceptions, it states the policy a guest-visible runtime must adopt
//     for its probes to see the honest answer.
//
// The assembled result is `Plan`: the list of API names whose answers the
// integration should replace, the PEB patches to apply, the clock model
// to install, and the trap policy. A plan is data; wiring it into the
// api_hook surface and the PEB image is the integration's job.

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

namespace occ::hostile {

// Which surfaces to harden. Every surface is independently selectable so
// an integration can harden exactly what its scenario exposes.
struct Config {
    bool hide_peb = true;
    bool uniform_time = true;
    bool answer_debug_queries = true;
    bool hide_environment = true;
    bool trap_policy = true;
};

// A monotonic linear clock shared by every time-reading API.
//
// The model is `wall_ms(qpc) = ms0 + (qpc - qpc0) * slope`, where slope
// is the host QPC frequency in ticks per millisecond. Two samples are
// enough to calibrate a slope when the host frequency is unknown;
// `calibrate` computes it from the samples, and every later read goes
// through the same model, so two different time APIs cannot diverge.
class ClockModel {
public:
    // Builds a model from a single sample and an assumed frequency.
    // `qpc_per_ms` is the host QPC ticks per millisecond; the Windows
    // default is 10'000 (10 MHz), but the caller may calibrate.
    ClockModel(std::uint64_t qpc0, std::uint64_t ms0,
               std::uint64_t qpc_per_ms) noexcept;

    // Calibrates from two samples taken at different moments. The slope
    // is the observed ratio; a zero elapsed-qpc (two samples from the
    // same instant) is refused and the model is left uncalibrated, which
    // the caller can detect through `valid()`.
    static ClockModel calibrate(std::uint64_t qpc_a, std::uint64_t ms_a,
                                std::uint64_t qpc_b,
                                std::uint64_t ms_b) noexcept;

    [[nodiscard]] bool valid() const noexcept { return valid_; }

    // The wall-clock milliseconds the model reads at the given qpc.
    [[nodiscard]] std::uint64_t now_ms(std::uint64_t qpc) const noexcept;

    // The qpc the model reads for the given wall time (the inverse).
    [[nodiscard]] std::uint64_t qpc_for(std::uint64_t ms) const noexcept;

private:
    std::uint64_t qpc0_ = 0;
    std::uint64_t ms0_ = 0;
    std::uint64_t slope_num_ = 1;  // qpc per ms, as a fraction
    std::uint64_t slope_den_ = 1;
    bool valid_ = false;
};

// The patches that make a PEB read like an undebugged process.
//
// The offsets are the x64 PEB layout: BeingDebugged at +0x02 (1 byte),
// NtGlobalFlag at +0x68 (4 bytes), ProcessHeap at +0x30 (8 bytes) with
// the heap's Flags at +0x70 and ForceFlags at +0x74. The masks clear the
// bits a debugger sets. Offsets and widths are structure facts; the mask
// values are the documented anti-detection constants and are asserted in
// the tests.
struct Patch {
    std::uint64_t offset = 0;
    std::uint8_t width = 0;  // 1, 2 or 4
    std::uint32_t mask = 0;  // bits to clear (applied as `& ~mask`)
    bool optional = false;   // heap patches are conditional on the heap
                             // pointer being present
};

struct PebPatches {
    std::vector<Patch> patches;
    // Whether the caller must first resolve ProcessHeap from the PEB
    // (the heap pointer may be null in a freshly mapped image).
    bool needs_heap = true;
};

// Computes the patches for a hardened PEB. The result is independent of
// any particular image; the caller applies it to the PEB it owns.
[[nodiscard]] PebPatches compute_peb_patches() noexcept;

// The answer to a debug-shaped query: an NTSTATUS and an output value.
struct QueryAnswer {
    std::uint32_t status = 0;  // NTSTATUS, 0 = STATUS_SUCCESS
    std::uint64_t out = 0;     // the value the guest should read
    bool modeled = false;      // false when this module has no opinion
};

// Answers NtQueryInformationProcess for the debug query classes.
//
// Class 7 (ProcessDebugPort) answers 0 with success; class 8
// (ProcessDebugObjectHandle) answers a null handle; class 30
// (ProcessDebugFlags) answers 1 (no debugger). Anything else is
// `modeled = false` and must be passed through.
[[nodiscard]] QueryAnswer answer_process_info(std::uint32_t info_class,
                                              std::uint64_t query_arg) noexcept;

// Answers NtQuerySystemInformation class 34 (KernelDebuggerInformation):
// the debugger-enabled and debugger-present flags are both false. Other
// classes are passed through.
[[nodiscard]] QueryAnswer answer_system_info(std::uint32_t info_class) noexcept;

// Whether the given name (window class, mutex, pipe or key name) is a
// known analyst fingerprint and should read as "not found".
//
// The table lives in the implementation and is deliberately short: the
// objects a debugging tool creates that a packed binary probes by name.
// The comparison is exact and case-insensitive on the printable ASCII
// subset.
[[nodiscard]] bool environment_hidden(std::string_view name) noexcept;

// What the guest-visible runtime should do when the guest executes a
// trap. The three answers are: deliver the exception to the guest's own
// handler (the honest undebugged behavior), swallow it, or fault.
enum class TrapDisposition {
    kDeliverToGuest,
    kSwallow,
    kFault,
};

// The trap policy for one trap kind.
struct TrapPolicy {
    TrapDisposition int3 = TrapDisposition::kDeliverToGuest;
    TrapDisposition single_step = TrapDisposition::kDeliverToGuest;
    TrapDisposition breakpoint_fault = TrapDisposition::kFault;
};

// The assembled hardening plan: what the integration replaces, patches
// and installs.
struct Plan {
    // API names (module-qualified) whose answers the integration should
    // replace with the hostile answers. Empty when the corresponding
    // surface is off.
    std::vector<std::string_view> replace_answers;

    PebPatches peb_patches;
    bool has_peb_patches = false;

    ClockModel clock{0, 0, 10000};
    bool has_clock = false;

    TrapPolicy traps;
};

// Builds the plan for a configuration. The result is data; the caller
// wires it into its API surface and PEB image.
[[nodiscard]] Plan build_plan(const Config& cfg) noexcept;

// ---------------------------------------------------------------------------
// Extended surfaces (ScyllaHide-class coverage)
// ---------------------------------------------------------------------------

// The process-information classes this module models. Everything else is
// passed through with `modeled = false`; refusing to guess is the
// contract.
enum class ProcessInfoClass : std::uint32_t {
    kHandleCount = 4,        // NtQueryInformationProcess ProcessHandleCount
    kDebugPort = 7,          // ProcessDebugPort
    kDebugObjectHandle = 8,  // ProcessDebugObjectHandle
    kWow64Information = 26,  // ProcessWow64Information
    kDebugFlags = 30,        // ProcessDebugFlags
    kIoCounters = 36,        // ProcessIoCounters (read as zero I/O)
};

// The thread-information classes this module models. Class 0x11 is
// ThreadHideFromDebugger, the hide flag a packer sets on its own thread.
enum class ThreadInfoClass : std::uint32_t {
    kHideFromDebugger = 0x11,
};

// Answers NtQueryInformationThread for the hide-from-debugger class: an
// undebugged thread reports "not hidden". Other classes pass through.
[[nodiscard]] QueryAnswer answer_thread_info(
    std::uint32_t info_class) noexcept;

// Answers NtSetInformationThread for the hide-from-debugger class: the
// hide request succeeds. Other classes pass through.
[[nodiscard]] QueryAnswer answer_set_thread_info(
    std::uint32_t info_class) noexcept;

// One coherent read of every time-visible surface, all derived from the
// same ClockModel so no two clocks can disagree. The integration feeds
// one host (qpc, wall-ms) sample and this module answers everything.
struct TimeAnswers {
    std::uint64_t tick_count_ms = 0;    // GetTickCount (32-bit at caller)
    std::uint64_t tick_count64_ms = 0;  // GetTickCount64
    std::uint64_t qpc = 0;              // QueryPerformanceCounter
    std::uint64_t system_time_ft = 0;   // GetSystemTimeAsFileTime (100ns
                                        // ticks since 1601-01-01)
    std::uint32_t rdtsc = 0;            // RDTSC low dword
};

// Derives the coherent time answers from the model. `host_ms` is the
// wall clock in Unix-epoch milliseconds that corresponds to `host_qpc`.
[[nodiscard]] TimeAnswers clock_reads(const ClockModel& model,
                                      std::uint64_t host_qpc,
                                      std::uint64_t host_ms) noexcept;

// The kind of an analyst fingerprint. A self-defending guest probes
// several namespaces; answering "not found" in the wrong namespace is
// itself a fingerprint, so each entry carries its kind.
enum class FingerprintKind : std::uint8_t {
    kWindowClass,
    kMutex,
    kPipe,
    kDriver,
    kRegistryKey,
    kProcessName,
    kModuleName,
    kFilePath,
};

struct Fingerprint {
    FingerprintKind kind;
    std::string_view name;
};

// The documented analyst fingerprint table, as data. Every entry is a
// name a debugging or analysis tool leaves in a namespace a packed
// binary probes. The table is intentionally curated: each entry has a
// comment naming the tool, so growth stays reviewable.
[[nodiscard]] const std::vector<Fingerprint>& fingerprint_table() noexcept;

// Whether the name is a known fingerprint of the given kind (the exact
// and case-insensitive comparison lives in the implementation).
[[nodiscard]] bool environment_hidden(std::string_view name,
                                      FingerprintKind kind) noexcept;

// The trap kinds a self-defending guest can execute. The policy per kind
// is data; the integration acts on it.
enum class TrapKind : std::uint8_t {
    kInt3,
    kSingleStep,
    kBreakpointFault,
    kInt2D,                 // int 0x2D, the old anti-debug trap
    kIllegalInstruction,    // 0x0F 0x0B etc. (UD2 family)
    kPrivilegedInstruction, // anti-VM ring-0 probes from user mode
};

// The trap policy for one trap kind. An undebugged process gets the
// exception delivered to its own handler; a debugger swallows it. The
// honest default is delivery; integration chooses otherwise per surface.
[[nodiscard]] TrapDisposition policy_for(const TrapPolicy& policy,
                                         TrapKind kind) noexcept;

// The debug registers as an undebugged process sees them: no hardware
// breakpoints and no pending debug status.
struct DebugRegisters {
    std::uint64_t dr0 = 0;
    std::uint64_t dr1 = 0;
    std::uint64_t dr2 = 0;
    std::uint64_t dr3 = 0;
    std::uint64_t dr6 = 0;
    std::uint64_t dr7 = 0;
};

// The canonical "no debugger" debug-register image. DR6 is zero (no
// pending debug exception) and DR7 is zero (no enabled breakpoints).
[[nodiscard]] DebugRegisters undebugged_dr() noexcept;

// A software breakpoint found in an image: an int3 (0xCC) at an offset,
// with the byte that was there before (unavailable in a pure scan, so
// `original` carries 0xCC and `original_known` is false unless the
// caller supplies the pristine image).
struct BreakpointHit {
    std::uint64_t offset = 0;
    std::uint8_t original = 0xCC;
    bool original_known = false;
};

// Scans a byte range for int3 software breakpoints. The scan is
// offset-based and reports every 0xCC; the integration decides which
// hits are its own traps versus planted ones. When `pristine` is
// non-null and covers the same range, `original` is the pristine byte at
// each hit (what the debugger overwrote).
[[nodiscard]] std::vector<BreakpointHit> scan_breakpoints(
    const std::uint8_t* bytes, std::size_t n,
    const std::uint8_t* pristine = nullptr) noexcept;

// The host-side view an integration can act on: is this process itself
// under a tracer, who is the parent, and does the address map contain an
// analyst's image. This is computed from the text of /proc/self/status,
// /proc/self/stat and /proc/self/maps -- parsing is pure so the tests
// can exercise every field without a real procfs.
struct HostProbe {
    bool traced = false;             // TracerPid != 0
    std::uint32_t tracer_pid = 0;
    std::uint32_t parent_pid = 0;    // from stat field 4
    bool analyst_in_maps = false;    // a known analyst image mapped
};

// Parses the host's procfs text. Each argument may be empty; missing
// fields read as the safe value (not traced, parent 0).
[[nodiscard]] HostProbe probe_host(std::string_view status_text,
                                   std::string_view stat_text,
                                   std::string_view maps_text) noexcept;

}  // namespace occ::hostile

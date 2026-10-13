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

}  // namespace occ::hostile

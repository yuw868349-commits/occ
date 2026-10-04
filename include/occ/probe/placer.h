#pragma once

// Placing the probes an engine asked for.
//
// A ProbeRequest names a module and a symbol. A uprobe needs a path and a
// file offset. This is the step between them, and it is a separate unit
// because it is where the two failures that matter both live:
//
//   - The module may not be the one the engine expected. A request names a
//     library, and the library on disk is found by the dynamic linker at a
//     per-run path; the engine resolved one at plan time and this resolves
//     it again, and the two can disagree if the host changed underneath.
//
//   - The symbol's address is not the offset. A symbol table gives a virtual
//     address, a uprobe line wants a file offset, and the segment that maps
//     the address has a different offset again. A probe placed at the virtual
//     address is a probe at a byte nobody chose, and the kernel accepts it if
//     that byte is inside the file.
//
// So a placement is a sequence with a verdict per step, and the outcome is
// reported as events and as a summary rather than as an errno: a run that
// placed nine of ten probes has to say which one it missed, because the
// output otherwise has a silent hole that looks like a target that never made
// that call.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "occ/engine/engine.h"
#include "occ/observer/event.h"
#include "occ/observer/uprobe.h"

namespace occ::obs {

// What happened to one placement.
enum class PlacementOutcome : std::uint8_t {
    // The probe is registered and subscribed.
    Attached,
    // The module could not be found or read.
    ModuleMissing,
    // The module was read and is not an ELF this build understands.
    ModuleUnreadable,
    // The symbol is not in the module's dynamic symbol table, or is there
    // and is not a defined function at a non-zero address. An import with
    // the right name is in the table and has no body to probe, which is why
    // this is not the same as "not found".
    SymbolMissing,
    // The symbol's address is in a part of a segment that the file does not
    // back -- the zero tail of a bss-like mapping. There is no byte to place
    // a breakpoint on.
    NoFileOffset,
    // The kernel refused the registration or the subscription. The detail
    // from the probe layer says which.
    KernelRefused,
};

[[nodiscard]] const char* placement_outcome_name(
    PlacementOutcome o) noexcept;

// One placement's result, for the report.
struct Placement {
    std::string label;
    std::string symbol;
    std::string module;
    PlacementOutcome outcome = PlacementOutcome::Attached;
    // The file offset the probe was placed at. Zero when it was not placed,
    // and also when it genuinely is zero -- which is why the outcome is the
    // thing to test rather than the offset.
    std::uint64_t offset = 0;
    // The probe layer's own sentence when the kernel refused.
    std::string detail;
};

// Places probes and keeps the resulting layer alive.
//
// The layer is held by value and is not copyable, so a Placer owns the
// probes it placed. A caller that lets one go clears the probes, which is the
// behaviour a run wants: the tracefs events a run created are removed when
// the run's observation ends.
class ProbePlacer {
public:
    ProbePlacer() = default;
    explicit ProbePlacer(std::string tracefs_root)
        : probes_(std::move(tracefs_root)) {}
    ProbePlacer(const ProbePlacer&) = delete;
    ProbePlacer& operator=(const ProbePlacer&) = delete;

    // Places every request. Writes a probe_attached event per request, with
    // ok true or false, and appends the outcome to `out`.
    //
    // Returns how many were attached. The caller gets the count rather than
    // a bool because "some" is the interesting case: a run with no probes is
    // a coarser run, and a run with nine of ten is one whose output has a
    // hole the caller should report.
    //
    // `events` may be null, in which case nothing is written and only the
    // summary is produced.
    std::size_t place(const std::vector<engine::ProbeRequest>& requests,
                      std::vector<Placement>& out, Writer* events) noexcept;

    // The probes that are attached, for the polling loop.
    [[nodiscard]] const Uprobes& layer() const noexcept { return probes_; }
    [[nodiscard]] Uprobes& layer() noexcept { return probes_; }

    // Where the tracefs root resolved to, empty when it never resolved
    // because no placement got that far.
    [[nodiscard]] const std::string& tracefs_root() const noexcept {
        return root_;
    }

    // Why no probe could be placed at all, empty when the layer resolved a
    // tracefs. Set on the first placement, because a layer that never
    // resolved a root has nothing to say about any individual probe.
    [[nodiscard]] const std::string& unavailable_reason() const noexcept {
        return unavailable_reason_;
    }

private:
    // Turns one request into a path and an offset, or a reason it could not.
    Placement resolve(const engine::ProbeRequest& request) noexcept;

    Uprobes probes_;
    std::string root_;
    std::string unavailable_reason_;
};

// Finds a module on the loader's path.
//
// A request's module with a slash in it is used as given; a bare name is
// searched for on the paths the dynamic linker uses. The search order is the
// loader's: LD_LIBRARY_PATH first, then the default directories. The
// environment is consulted because a run that set it did so to change which
// library is found, and placing a probe in a different copy from the one that
// will be loaded is a probe that never fires.
//
// Returns an empty string when nothing matches.
[[nodiscard]] std::string find_module(std::string_view module) noexcept;

} // namespace occ::obs

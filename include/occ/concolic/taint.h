// Forward taint tracking over the concolic program model.
//
// Taint analysis asks which program inputs can influence a value. Here
// every input carries a label (its input ordinal); the engine walks the
// program's blocks and statements forward, and the taint of a state is
// the union of the labels of every input reachable in the state's
// defining expression, computed with `DAG::inputs_of` against the
// program's own input table. Only inputs that were explicitly marked
// tainted contribute a label: an unmarked input, however deep it sits in
// an expression, adds nothing, which is what makes "this value does not
// depend on x" a reportable fact rather than an omission.
//
// Three kinds of sink are collected:
//
//   - branch conditions: every conditioned edge is a sink, labelled with
//     the inputs the condition reaches;
//   - memory writes: every assignment to a declared cell is a sink,
//     labelled with the inputs the written value reaches;
//   - argument sinks: states the caller designates (a function argument,
//     a syscall parameter, an output buffer) are sinks, labelled with
//     their taint at the end of the analysis.
//
// The report also carries the propagation chain: for every marked label,
// every assignment whose right-hand side reaches that label, so a reader
// can follow "label x: y <- (x ^ 0x3f) [block 0, stmt 0]" from input to
// sink. This is a forward dataflow over the model's straight-line
// statements; it is exact for the model, and the model's boundaries (no
// dynamic memory indexing, no aliasing) are the report's boundaries,
// stated in the report rather than hidden.
//
// The engine shares the interpreter's walk with `conc::run` structurally
// but is purely symbolic: it tracks each state's defining expression to
// ask `inputs_of`, and never evaluates concretely.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "occ/concolic/program.h"

namespace occ::concolic {

namespace expr = occ::devirt::expr;

// One sink's taint. `labels` are input ordinals, ascending, restricted to
// the inputs that were marked tainted.
struct SinkReport {
    enum class Kind : std::uint8_t { Branch, Memory, Argument };
    Kind kind = Kind::Branch;
    std::string name;             // branch: "block <id> edge <k>"; else the state name
    std::uint32_t block = 0;      // Branch: the block; else unused
    std::uint32_t edge = 0;       // Branch: the edge index; else unused
    expr::Id expr = expr::kNoId;  // the tainted expression
    std::vector<std::uint32_t> labels;
};

// One step of a propagation chain: assignment `stmt` of `block` wrote
// `dst <- src`, and `src` reaches input `label`.
struct ChainEntry {
    std::uint32_t label = 0;
    std::uint32_t block = 0;
    std::uint32_t stmt = 0;
    std::string dst;
    expr::Id src = expr::kNoId;
};

// The per-state taint, for queries and the report.
struct StateTaint {
    std::string name;
    std::vector<std::uint32_t> labels;
};

struct TaintReport {
    std::vector<SinkReport> sinks;
    std::vector<ChainEntry> chains;
    std::vector<StateTaint> states;
    std::string error;  // non-empty when the analysis could not run
};

// Forward taint engine over a Program. `analyze` walks the program once
// and returns the full report; the engine is one-shot per construction.
class TaintEngine {
public:
    explicit TaintEngine(const Program& prog) : prog_(prog) {}

    // Marks input `ordinal` as tainted. Out-of-range ordinals are
    // ignored (the report then says what was asked).
    void mark_input(std::uint32_t ordinal);

    // Marks the input that state `name` holds (the state must be a
    // declared symbolic input; otherwise the mark is a no-op).
    void mark_state(const std::string& name);

    // Designates `state` as an argument-class sink, reported with its
    // final taint.
    void add_sink(const std::string& state);

    [[nodiscard]] TaintReport analyze();

    [[nodiscard]] const Program& program() const noexcept { return prog_; }

private:
    const Program& prog_;
    std::vector<bool> enabled_;
    std::vector<std::string> sink_states_;
};

// A human-readable rendering of the taint report: every sink and its
// labels, the propagation chains, and the states the analysis left
// clean.
[[nodiscard]] std::string report_text(const Program& prog,
                                      const TaintReport& report);

}  // namespace occ::concolic

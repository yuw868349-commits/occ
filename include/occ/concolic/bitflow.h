// Bit-precise taint flow over the concolic program model.
//
// The state-level taint engine (`TaintEngine`) answers "which inputs can
// influence this value?" -- a set of input labels per state. This engine
// answers the strictly stronger question "which *bits* of which inputs
// can influence which *bits* of this value?", the way a production
// bit-level taint tracker (Triton-style) does.
//
// The representation is a sparse per-node dependency table: for every
// DAG node, a sorted list of (input label -> output-bit mask). Bit 0 of
// the mask is the node result's lowest bit; a set bit k means "bit k of
// the result can depend on this input". The analysis is a backward,
// bit-precise dataflow over the DAG:
//
//   - a node's flow is computed from its operands' flows by the exact
//     bit semantics of the operation, not by evaluating anything;
//   - additive ops (Add/Sub/Mul) use the carry/partial-product
//     discipline: result bit i can depend on operand bits 0..i, which is
//     the prefix-or transform of the operand mask;
//   - shifts with a constant amount shift the mask; a symbolic shift
//     amount conservatively makes every output bit depend on every bit
//     of both operands;
//   - Select makes each output bit depend on the condition's low bit and
//     on the corresponding bit of both arms;
//   - comparisons (1-bit results) make the single result bit depend on
//     every bit of both operands;
//   - widths above 64 bits are handled conservatively as full-dependency
//     (the mask saturates), so the analysis is sound at any width.
//
// The flow is an over-approximation: a reported dependency is real or
// conservative, never under-reported, which is the contract taint
// analysis needs (a sink that could depend on secret data must be
// reported). The mask granularity is 1 bit, so under-reporting would
// mean missing a bit the input genuinely can influence; the prefix and
// shift rules are the exact worst cases, not approximations.
//
// Memory is handled the same way as the state-level engine: static
// cells are named states, and a write to a cell is a sink whose flow is
// the written expression's flow. Dynamic (computed-address) memory is
// the symbolic-memory extension's territory and is out of scope here;
// the report says so, matching the model's declared boundary.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "occ/concolic/program.h"

namespace occ::concolic {

namespace expr = occ::devirt::expr;

// One input label's contribution to an expression's output bits. `mask`
// bit k set means output bit k can depend on this input. Masks are
// saturated (all ones) for widths >= 64 and for conservative rules.
struct LabelBits {
    std::uint32_t label = 0;
    std::uint64_t mask = 0;
};

// The flow of one value: every tainted input that reaches it, with the
// exact output-bit mask. Sorted by label; a label appears at most once.
using BitFlow = std::vector<LabelBits>;

// One sink's bit-level taint, mirroring TaintReport::SinkReport.
struct BitSink {
    enum class Kind : std::uint8_t { Branch, Memory, Argument };
    Kind kind = Kind::Branch;
    std::string name;             // branch: "block <id> edge <k>"; else the state name
    std::uint32_t block = 0;      // Branch: the block; else unused
    std::uint32_t edge = 0;       // Branch: the edge index; else unused
    expr::Id expr = expr::kNoId;  // the tainted expression
    BitFlow flow;                 // which input labels, and which bits
};

// One state's final bit-level taint.
struct BitStateFlow {
    std::string name;
    BitFlow flow;
};

struct BitFlowReport {
    std::vector<BitSink> sinks;
    std::vector<BitStateFlow> states;
    std::string error;  // non-empty when the analysis could not run
};

// Bit-precise taint engine. `analyze` walks the program once; the
// per-node flows are memoized on the DAG, so asking the same expression
// twice costs nothing. The engine is one-shot per construction.
class BitFlowEngine {
public:
    explicit BitFlowEngine(const Program& prog) : prog_(prog) {}

    // Marks input `ordinal` as tainted. Out-of-range ordinals are
    // ignored.
    void mark_input(std::uint32_t ordinal);

    // Marks the input that state `name` holds (the state must be a
    // declared symbolic input; otherwise the mark is a no-op).
    void mark_state(const std::string& name);

    // Designates `state` as an argument-class sink.
    void add_sink(const std::string& state);

    // The bit-level flow of a DAG expression: which marked input labels
    // reach it, and which output bits each can influence. Cheap and
    // memoized; callable before or after `analyze`.
    [[nodiscard]] BitFlow expr_flow(expr::Id id);

    // The bit-level flow of a state's defining expression.
    [[nodiscard]] BitFlow state_flow(const std::string& name);

    // Whether input `label` reaches `name`'s value at all.
    [[nodiscard]] bool tainted_by(const std::string& name,
                                  std::uint32_t label);

    // Which bits of `name`'s value input `label` can influence.
    [[nodiscard]] std::uint64_t bits_tainted_by(const std::string& name,
                                                std::uint32_t label);

    [[nodiscard]] BitFlowReport analyze();

    [[nodiscard]] const Program& program() const noexcept { return prog_; }

private:
    // Computes (with memoization) the bit flow of DAG node `id`.
    [[nodiscard]] BitFlow flow_of(expr::Id id);

    // The flow of a state's defining expression: the last statement that
    // wrote it, or its declared init when never written.
    [[nodiscard]] BitFlow expr_flow_latest(const std::string& name,
                                           std::size_t state_idx);

    const Program& prog_;
    std::vector<bool> enabled_;
    std::vector<std::string> sink_states_;
    // flow cache, indexed by node id; kNoId entries mean "not computed".
    std::vector<std::pair<bool, BitFlow>> cache_;
};

// A human-readable rendering of the bit-level report: every sink with
// its per-label bit masks, and the per-state flows.
[[nodiscard]] std::string bit_report_text(const Program& prog,
                                          const BitFlowReport& report);

// Renders a bit mask as a compact "bits" range list: 0xff -> "0-7",
// 0x11 -> "0,4", 0 -> "none".
[[nodiscard]] std::string bit_range_text(std::uint64_t mask);

}  // namespace occ::concolic

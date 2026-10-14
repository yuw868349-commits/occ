// Bit-precise taint flow: implementation.

#include "occ/concolic/bitflow.h"

#include <algorithm>
#include <cstddef>
#include <utility>

namespace occ::concolic {

namespace {

// The saturated mask for a width: all ones for widths >= 64.
std::uint64_t conc_full_mask(unsigned width) {
    if (width >= 64) {
        return ~std::uint64_t{0};
    }
    return (std::uint64_t{1} << width) - 1;
}

// The low-bit prefix-or transform: given the operand's per-bit
// dependency mask, returns the mask in which bit i is set iff the
// operand has any dependency in bits 0..i. This is the exact carry /
// partial-product dependency rule for Add, Sub and Mul: result bit i
// depends on operand bits 0..i.
std::uint64_t conc_prefix_or(std::uint64_t mask) {
    mask |= mask << 1;
    mask |= mask << 2;
    mask |= mask << 4;
    mask |= mask << 8;
    mask |= mask << 16;
    mask |= mask << 32;
    return mask;
}

// Merges `extra` into `flow`: labels sort ascending, duplicate labels
// OR their masks. `flow` must already be sorted by label.
void conc_merge_flow(BitFlow& flow, const BitFlow& extra) {
    for (const LabelBits& lb : extra) {
        auto it = std::lower_bound(
            flow.begin(), flow.end(), lb.label,
            [](const LabelBits& a, std::uint32_t label) {
                return a.label < label;
            });
        if (it != flow.end() && it->label == lb.label) {
            it->mask |= lb.mask;
        } else {
            flow.insert(it, lb);
        }
    }
}

// Applies a mask transform to every entry of a flow. When `shrink` is
// true the entry's mask is AND-ed with `m`; otherwise it is OR-ed.
void conc_transform_flow(BitFlow& flow, std::uint64_t m, bool shrink) {
    for (LabelBits& lb : flow) {
        lb.mask = shrink ? (lb.mask & m) : (lb.mask | m);
    }
}

// Maps every entry's mask to the saturated full mask (used when an
// operation makes every result bit depend on every operand bit).
void conc_full_flow(BitFlow& flow, unsigned width) {
    const std::uint64_t full = conc_full_mask(width);
    for (LabelBits& lb : flow) {
        lb.mask = full;
    }
}

// True when `b` is a compile-time constant shift amount.
bool conc_const_shift(const expr::DAG& dag, expr::Id b, unsigned* amount) {
    if (b == expr::kNoId || !dag.valid(b) || dag.node(b).op != expr::Op::Const) {
        return false;
    }
    *amount = static_cast<unsigned>(dag.const_value(b) & 0x3F);
    return true;
}

}  // namespace

void BitFlowEngine::mark_input(std::uint32_t ordinal) {
    if (ordinal >= prog_.num_inputs()) {
        return;  // out of range: nothing to mark
    }
    if (ordinal >= enabled_.size()) {
        enabled_.resize(static_cast<std::size_t>(ordinal) + 1, false);
    }
    enabled_[ordinal] = true;
}

void BitFlowEngine::mark_state(const std::string& name) {
    for (const InputDecl& d : prog_.inputs) {
        if (d.state == name) {
            mark_input(d.ordinal);
            return;
        }
    }
    // Not a declared symbolic input: nothing to mark.
}

void BitFlowEngine::add_sink(const std::string& state) {
    sink_states_.push_back(state);
}

BitFlow BitFlowEngine::expr_flow(expr::Id id) {
    if (id == expr::kNoId || !prog_.dag.valid(id)) {
        return {};
    }
    return flow_of(id);
}

BitFlow BitFlowEngine::flow_of(expr::Id id) {
    if (cache_.size() <= id) {
        cache_.resize(static_cast<std::size_t>(id) + 1,
                      std::make_pair(false, BitFlow{}));
    }
    if (cache_[id].first) {
        return cache_[id].second;
    }

    const expr::Node& n = prog_.dag.node(id);
    BitFlow out;
    switch (n.op) {
    case expr::Op::Const:
        break;  // constants depend on nothing

    case expr::Op::Input: {
        const std::uint32_t ord = static_cast<std::uint32_t>(n.imm);
        if (ord < enabled_.size() && enabled_[ord]) {
            out.push_back(LabelBits{ord, conc_full_mask(n.width)});
        }
        break;
    }

    case expr::Op::Not:
        // Bit i of ~x depends on bit i of x: identical masks.
        out = flow_of(n.a);
        break;

    case expr::Op::Neg:
        // Bit i of -x depends on bits 0..i of x (inversion plus the
        // carry chain of the +1): prefix-or.
        out = flow_of(n.a);
        for (LabelBits& lb : out) {
            lb.mask = conc_prefix_or(lb.mask);
        }
        break;

    case expr::Op::Resize: {
        out = flow_of(n.a);
        if (n.width < prog_.dag.node(n.a).width) {
            conc_transform_flow(out, conc_full_mask(n.width), true);
        }
        // Widening zero-extends: high bits depend on nothing, so the
        // mask is unchanged; truncation masks to the new width.
        break;
    }

    case expr::Op::And:
    case expr::Op::Or:
    case expr::Op::Xor: {
        // Bit i of the result depends on bit i of both operands: the
        // union of the per-bit masks. With a constant operand, only the
        // bits the constant lets through can carry a dependency: And
        // keeps bits where the constant has 1s, Or keeps bits where it
        // has 0s, Xor keeps every bit (x ^ c still depends on x).
        BitFlow bflow = flow_of(n.b);
        if (prog_.dag.is_const(n.a)) {
            const std::uint64_t m = prog_.dag.const_value(n.a) &
                                    conc_full_mask(n.width);
            out.clear();
            for (LabelBits& lb : bflow) {
                lb.mask = n.op == expr::Op::And
                              ? (lb.mask & m)
                              : n.op == expr::Op::Or
                                    ? (lb.mask & ~m & conc_full_mask(n.width))
                                    : lb.mask;
            }
            out = std::move(bflow);
        } else if (prog_.dag.is_const(n.b)) {
            const std::uint64_t m = prog_.dag.const_value(n.b) &
                                    conc_full_mask(n.width);
            out = flow_of(n.a);
            for (LabelBits& lb : out) {
                lb.mask = n.op == expr::Op::And
                              ? (lb.mask & m)
                              : n.op == expr::Op::Or
                                    ? (lb.mask & ~m & conc_full_mask(n.width))
                                    : lb.mask;
            }
        } else {
            out = flow_of(n.a);
            conc_merge_flow(out, bflow);
        }
        break;
    }

    case expr::Op::Add:
    case expr::Op::Sub:
    case expr::Op::Mul: {
        // The carry / partial-product chain: result bit i depends on
        // operand bits 0..i of both operands.
        out = flow_of(n.a);
        for (LabelBits& lb : out) {
            lb.mask = conc_prefix_or(lb.mask);
        }
        BitFlow bflow = flow_of(n.b);
        for (LabelBits& lb : bflow) {
            lb.mask = conc_prefix_or(lb.mask);
        }
        conc_merge_flow(out, bflow);
        break;
    }

    case expr::Op::Shl:
    case expr::Op::Shr:
    case expr::Op::Sar: {
        out = flow_of(n.a);
        unsigned amount = 0;
        if (conc_const_shift(prog_.dag, n.b, &amount)) {
            // Constant amount: bit i of the result depends on bit
            // i-amount (Shl) or i+amount (Shr/Sar) of the operand.
            if (n.op == expr::Op::Shl) {
                for (LabelBits& lb : out) {
                    lb.mask = lb.mask << amount;
                }
            } else {
                for (LabelBits& lb : out) {
                    lb.mask = lb.mask >> amount;
                }
            }
        } else {
            // Symbolic amount: every result bit can depend on every bit
            // of the value and of the amount.
            conc_full_flow(out, n.width);
            BitFlow amt = flow_of(n.b);
            conc_full_flow(amt, n.width);
            conc_merge_flow(out, amt);
        }
        break;
    }

    case expr::Op::Select: {
        // Bit i of the result depends on the condition's bit 0 and on
        // bit i of both arms.
        BitFlow cflow = flow_of(n.c);
        for (LabelBits& lb : cflow) {
            // The condition is 1-bit; if it depends on an input at all,
            // that input can flip the whole selection, so every result
            // bit may depend on it.
            lb.mask = conc_full_mask(n.width);
        }
        out = cflow;
        conc_merge_flow(out, flow_of(n.a));
        conc_merge_flow(out, flow_of(n.b));
        break;
    }

    case expr::Op::CmpEQ:
    case expr::Op::CmpULT:
    case expr::Op::CmpSLT: {
        // The 1-bit comparison result depends on every bit of both
        // operands.
        out = flow_of(n.a);
        conc_full_flow(out, 1);
        BitFlow bflow = flow_of(n.b);
        conc_full_flow(bflow, 1);
        conc_merge_flow(out, bflow);
        break;
    }
    }

    // Drop labels that the mark set does not enable (a conservative
    // carry can pull a label through an expression the state-level
    // engine would not see; only enabled labels are reported).
    out.erase(std::remove_if(out.begin(), out.end(),
                             [this](const LabelBits& lb) {
                                 return lb.label >= enabled_.size() ||
                                        !enabled_[lb.label];
                             }),
              out.end());
    cache_[id] = std::make_pair(true, out);
    return out;
}

BitFlow BitFlowEngine::state_flow(const std::string& name) {
    const std::size_t idx = prog_.state_index(name);
    if (idx >= prog_.states.size()) {
        return {};
    }
    return expr_flow_latest(name, idx);
}

BitFlow BitFlowEngine::expr_flow_latest(const std::string& name,
                                        std::size_t state_idx) {
    // The state's defining expression is the last statement that wrote
    // it (or its declared init). Walk the program forward.
    expr::Id current = prog_.states[state_idx].init;
    for (const Block& b : prog_.blocks) {
        for (const Stmt& st : b.stmts) {
            if (st.dst == name) {
                current = st.src;
            }
        }
    }
    return expr_flow(current);
}

bool BitFlowEngine::tainted_by(const std::string& name,
                               std::uint32_t label) {
    const BitFlow flow = state_flow(name);
    for (const LabelBits& lb : flow) {
        if (lb.label == label && lb.mask != 0) {
            return true;
        }
    }
    return false;
}

std::uint64_t BitFlowEngine::bits_tainted_by(const std::string& name,
                                             std::uint32_t label) {
    const BitFlow flow = state_flow(name);
    for (const LabelBits& lb : flow) {
        if (lb.label == label) {
            return lb.mask;
        }
    }
    return 0;
}

BitFlowReport BitFlowEngine::analyze() {
    BitFlowReport out;
    if (!prog_.valid()) {
        out.error = prog_.error;
        return out;
    }
    enabled_.resize(prog_.num_inputs(), false);

    // Per-state flows, computed as the last write's expression flow.
    // The cache warms lazily on first ask.
    std::vector<BitFlow> state_flow_final(prog_.states.size());
    std::vector<expr::Id> state_expr(prog_.states.size(), expr::kNoId);
    for (std::size_t i = 0; i < prog_.states.size(); ++i) {
        state_expr[i] = prog_.states[i].init;
    }
    for (const Block& b : prog_.blocks) {
        for (const Stmt& st : b.stmts) {
            const std::size_t idx = prog_.state_index(st.dst);
            if (idx < state_expr.size()) {
                state_expr[idx] = st.src;
            }
        }
    }

    // Memory-write sinks: every assignment to a declared cell.
    for (const Block& b : prog_.blocks) {
        for (const Stmt& st : b.stmts) {
            const std::size_t idx = prog_.state_index(st.dst);
            if (idx >= prog_.states.size()) {
                continue;
            }
            const bool is_cell = prog_.states[idx].cell;
            if (!is_cell) {
                continue;
            }
            const BitFlow flow = expr_flow(st.src);
            if (flow.empty()) {
                continue;
            }
            BitSink sink;
            sink.kind = BitSink::Kind::Memory;
            sink.name = st.dst;
            sink.expr = st.src;
            sink.flow = flow;
            out.sinks.push_back(std::move(sink));
        }
    }

    // Branch sinks: every conditioned edge.
    for (const Block& b : prog_.blocks) {
        for (std::size_t e = 0; e < b.edges.size(); ++e) {
            if (b.edges[e].cond == expr::kNoId) {
                continue;
            }
            const BitFlow flow = expr_flow(b.edges[e].cond);
            if (flow.empty()) {
                continue;
            }
            BitSink sink;
            sink.kind = BitSink::Kind::Branch;
            sink.name = "block " + std::to_string(b.id) + " edge " +
                        std::to_string(e);
            sink.block = b.id;
            sink.edge = static_cast<std::uint32_t>(e);
            sink.expr = b.edges[e].cond;
            sink.flow = flow;
            out.sinks.push_back(std::move(sink));
        }
    }

    // Argument sinks.
    for (const std::string& name : sink_states_) {
        const std::size_t idx = prog_.state_index(name);
        if (idx >= prog_.states.size()) {
            out.error = "add_sink: unknown state " + name;
            continue;
        }
        const BitFlow flow = expr_flow(state_expr[idx]);
        if (flow.empty()) {
            continue;
        }
        BitSink sink;
        sink.kind = BitSink::Kind::Argument;
        sink.name = name;
        sink.expr = state_expr[idx];
        sink.flow = flow;
        out.sinks.push_back(std::move(sink));
    }

    // Per-state flows for the report.
    for (std::size_t i = 0; i < prog_.states.size(); ++i) {
        BitStateFlow sf;
        sf.name = prog_.states[i].name;
        sf.flow = expr_flow(state_expr[i]);
        out.states.push_back(std::move(sf));
    }
    return out;
}

std::string bit_range_text(std::uint64_t mask) {
    if (mask == 0) {
        return "none";
    }
    std::string out;
    bool first = true;
    std::size_t i = 0;
    while (i < 64) {
        if ((mask & (std::uint64_t{1} << i)) == 0) {
            ++i;
            continue;
        }
        std::size_t j = i;
        while (j + 1 < 64 && (mask & (std::uint64_t{1} << (j + 1))) != 0) {
            ++j;
        }
        if (!first) {
            out += ",";
        }
        first = false;
        if (i == j) {
            out += std::to_string(i);
        } else {
            out += std::to_string(i) + "-" + std::to_string(j);
        }
        i = j + 1;
    }
    return out;
}

std::string bit_report_text(const Program& prog, const BitFlowReport& report) {
    std::string out;
    out += "=== concolic bit-taint report ===\n";
    if (!report.error.empty()) {
        out += "error: " + report.error + "\n";
        return out;
    }

    out += "inputs: ";
    for (std::size_t i = 0; i < prog.inputs.size(); ++i) {
        if (i != 0) {
            out += ", ";
        }
        out += prog.inputs[i].sym + "(" + std::to_string(prog.inputs[i].width) +
               "b)";
    }
    out += "\n";

    std::size_t tainted = 0;
    for (const BitSink& sink : report.sinks) {
        const char* kind = sink.kind == BitSink::Kind::Branch
                               ? "branch"
                               : sink.kind == BitSink::Kind::Memory
                                     ? "memory"
                                     : "argument";
        out += "sink [" + std::string(kind) + "] " + sink.name + ": ";
        if (sink.flow.empty()) {
            out += "clean\n";
            continue;
        }
        ++tainted;
        out += "tainted by";
        for (std::size_t i = 0; i < sink.flow.size(); ++i) {
            const LabelBits& lb = sink.flow[i];
            const std::string* name = nullptr;
            for (const InputDecl& d : prog.inputs) {
                if (d.ordinal == lb.label) {
                    name = &d.sym;
                    break;
                }
            }
            out += (i == 0 ? " " : ", ");
            out += (name != nullptr ? *name : "input#" + std::to_string(lb.label));
            out += " bits " + bit_range_text(lb.mask);
        }
        out += "\n";
    }

    out += "state taint:\n";
    for (const BitStateFlow& sf : report.states) {
        out += "  " + sf.name + ": ";
        if (sf.flow.empty()) {
            out += "clean\n";
            continue;
        }
        for (std::size_t i = 0; i < sf.flow.size(); ++i) {
            const LabelBits& lb = sf.flow[i];
            const std::string* name = nullptr;
            for (const InputDecl& d : prog.inputs) {
                if (d.ordinal == lb.label) {
                    name = &d.sym;
                    break;
                }
            }
            out += (i == 0 ? "" : ", ");
            out += (name != nullptr ? *name : "input#" + std::to_string(lb.label)) +
                   " bits " + bit_range_text(lb.mask);
        }
        out += "\n";
    }

    out += "summary: " + std::to_string(tainted) + "/" +
           std::to_string(report.sinks.size()) + " sinks tainted\n";
    out += "note: bit masks are exact per-bit dependencies; dynamic "
           "(computed-address) memory is outside this model, so all claims "
           "cover static addressing only.\n";
    return out;
}

}  // namespace occ::concolic

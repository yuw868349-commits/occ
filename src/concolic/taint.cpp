// Forward taint tracking and its report rendering.

#include "occ/concolic/taint.h"

#include <algorithm>
#include <cstddef>

namespace occ::concolic {

namespace {

// Renders a label set by the input symbols it names. Labels are input
// ordinals; the name is the DAG symbol, which is what a reader of a
// report wants to see.
std::string conc_label_text(const Program& prog,
                            const std::vector<std::uint32_t>& labels) {
    std::string out = "{";
    for (std::size_t i = 0; i < labels.size(); ++i) {
        if (i != 0) {
            out += ", ";
        }
        const std::uint32_t ord = labels[i];
        const std::string* name = nullptr;
        for (const InputDecl& d : prog.inputs) {
            if (d.ordinal == ord) {
                name = &d.sym;
                break;
            }
        }
        out += name != nullptr ? *name : ("input#" + std::to_string(ord));
    }
    out += "}";
    return out;
}

bool conc_contains(const std::vector<std::uint32_t>& labels,
                   std::uint32_t label) {
    for (const std::uint32_t l : labels) {
        if (l == label) {
            return true;
        }
    }
    return false;
}

}  // namespace

void TaintEngine::mark_input(std::uint32_t ordinal) {
    if (ordinal >= prog_.num_inputs()) {
        return;  // out of range: nothing to mark
    }
    if (ordinal >= enabled_.size()) {
        enabled_.resize(static_cast<std::size_t>(ordinal) + 1, false);
    }
    enabled_[ordinal] = true;
}

void TaintEngine::mark_state(const std::string& name) {
    for (const InputDecl& d : prog_.inputs) {
        if (d.state == name) {
            mark_input(d.ordinal);
            return;
        }
    }
    // Not a declared symbolic input: nothing to mark.
}

void TaintEngine::add_sink(const std::string& state) {
    sink_states_.push_back(state);
}

TaintReport TaintEngine::analyze() {
    TaintReport out;
    if (!prog_.valid()) {
        out.error = prog_.error;
        return out;
    }
    enabled_.resize(prog_.num_inputs(), false);

    // Per-state taint and defining expression, in declaration order. The
    // taint of a state is the union of the marked labels its expression
    // reaches; the expression itself is tracked so `inputs_of` can be
    // asked and the report can print what a sink depends on.
    std::vector<std::vector<std::uint32_t>> state_taint(prog_.states.size());
    std::vector<expr::Id> state_expr(prog_.states.size(), expr::kNoId);

    // Seed: an input state's initial expression is its input node, whose
    // ordinal is exactly that state's label when marked.
    for (std::size_t i = 0; i < prog_.states.size(); ++i) {
        state_expr[i] = prog_.states[i].init;
        if (prog_.states[i].init == expr::kNoId) {
            continue;
        }
        for (const unsigned ord : prog_.dag.inputs_of(prog_.states[i].init)) {
            if (ord < enabled_.size() && enabled_[ord]) {
                state_taint[i].push_back(static_cast<std::uint32_t>(ord));
            }
        }
    }

    // Walk every block and statement, propagating labels forward and
    // recording the chain and the memory-write sinks along the way.
    for (const Block& b : prog_.blocks) {
        for (std::size_t s = 0; s < b.stmts.size(); ++s) {
            const Stmt& st = b.stmts[s];
            const std::size_t idx = prog_.state_index(st.dst);
            if (idx >= state_taint.size()) {
                continue;  // cannot happen: add_stmt declares the state
            }
            state_expr[idx] = st.src;
            const bool is_cell = prog_.states[idx].cell;

            // Every marked label the source expression reaches flows into
            // the destination -- and is recorded as a chain step.
            std::vector<std::uint32_t> carried;
            for (const unsigned ord : prog_.dag.inputs_of(st.src)) {
                if (ord < enabled_.size() && enabled_[ord]) {
                    const std::uint32_t label = static_cast<std::uint32_t>(ord);
                    if (!conc_contains(carried, label)) {
                        carried.push_back(label);
                        out.chains.push_back(
                            ChainEntry{label, b.id, static_cast<std::uint32_t>(s),
                                       st.dst, st.src});
                    }
                }
            }
            for (const std::uint32_t label : carried) {
                if (!conc_contains(state_taint[idx], label)) {
                    state_taint[idx].push_back(label);
                }
            }

            if (is_cell && !carried.empty()) {
                SinkReport sink;
                sink.kind = SinkReport::Kind::Memory;
                sink.name = st.dst;
                sink.expr = st.src;
                sink.labels = carried;
                out.sinks.push_back(std::move(sink));
            }
        }
    }

    // Branch sinks: every conditioned edge, labelled by the inputs its
    // condition reaches.
    for (const Block& b : prog_.blocks) {
        for (std::size_t e = 0; e < b.edges.size(); ++e) {
            if (b.edges[e].cond == expr::kNoId) {
                continue;
            }
            std::vector<std::uint32_t> labels;
            for (const unsigned ord : prog_.dag.inputs_of(b.edges[e].cond)) {
                if (ord < enabled_.size() && enabled_[ord]) {
                    const std::uint32_t label = static_cast<std::uint32_t>(ord);
                    if (!conc_contains(labels, label)) {
                        labels.push_back(label);
                    }
                }
            }
            SinkReport sink;
            sink.kind = SinkReport::Kind::Branch;
            sink.name = "block " + std::to_string(b.id) + " edge " +
                        std::to_string(e);
            sink.block = b.id;
            sink.edge = static_cast<std::uint32_t>(e);
            sink.expr = b.edges[e].cond;
            sink.labels = std::move(labels);
            out.sinks.push_back(std::move(sink));
        }
    }

    // Argument sinks: the caller-designated states, reported with their
    // final taint and defining expression.
    for (const std::string& name : sink_states_) {
        const std::size_t idx = prog_.state_index(name);
        if (idx >= state_taint.size()) {
            out.error = "add_sink: unknown state " + name;
            continue;
        }
        SinkReport sink;
        sink.kind = SinkReport::Kind::Argument;
        sink.name = name;
        sink.expr = state_expr[idx];
        sink.labels = state_taint[idx];
        out.sinks.push_back(std::move(sink));
    }

    // Order every list deterministically (labels are appended in input
    // order already, but chains interleave labels).
    for (SinkReport& sink : out.sinks) {
        std::sort(sink.labels.begin(), sink.labels.end());
    }
    std::sort(out.chains.begin(), out.chains.end(),
              [](const ChainEntry& a, const ChainEntry& b) {
                  if (a.label != b.label) {
                      return a.label < b.label;
                  }
                  if (a.block != b.block) {
                      return a.block < b.block;
                  }
                  return a.stmt < b.stmt;
              });
    for (std::size_t i = 0; i < prog_.states.size(); ++i) {
        std::sort(state_taint[i].begin(), state_taint[i].end());
        out.states.push_back(StateTaint{prog_.states[i].name, state_taint[i]});
    }
    return out;
}

std::string report_text(const Program& prog, const TaintReport& report) {
    std::string out;
    out += "=== concolic taint report ===\n";
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

    std::size_t tainted_sinks = 0;
    for (const SinkReport& sink : report.sinks) {
        const char* kind = sink.kind == SinkReport::Kind::Branch
                               ? "branch"
                               : sink.kind == SinkReport::Kind::Memory
                                     ? "memory"
                                     : "argument";
        out += "sink [" + std::string(kind) + "] " + sink.name + ": ";
        if (sink.labels.empty()) {
            out += "clean\n";
            continue;
        }
        ++tainted_sinks;
        out += "tainted by " +
               conc_label_text(prog, sink.labels) + "  (" +
               prog.dag.pretty(sink.expr) + ")\n";
    }

    out += "propagation:\n";
    if (report.chains.empty()) {
        out += "  (no marked label flows through any assignment)\n";
    }
    for (const ChainEntry& c : report.chains) {
        out += "  label " + conc_label_text(prog, {c.label}) + ": " + c.dst +
               " <- " + prog.dag.pretty(c.src) + " [block " +
               std::to_string(c.block) + ", stmt " + std::to_string(c.stmt) +
               "]\n";
    }

    out += "state taint:\n";
    for (const StateTaint& st : report.states) {
        out += "  " + st.name + ": " + conc_label_text(prog, st.labels) + "\n";
    }

    out += "summary: " + std::to_string(tainted_sinks) + "/" +
           std::to_string(report.sinks.size()) + " sinks tainted, " +
           std::to_string(report.chains.size()) + " chain steps\n";
    out += "note: dynamically indexed memory (loads/stores through computed "
           "addresses) is unsupported in this model; every cell is a named "
           "state variable, so the taint claims cover only static addressing.\n";
    return out;
}

}  // namespace occ::concolic

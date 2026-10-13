// The concolic program model: construction and the concrete interpreter.

#include "occ/concolic/program.h"

namespace occ::concolic {

namespace {

// Every builder failure funnels through here: record the first error and
// keep going (later calls no-op against an invalid program, which keeps a
// partially built program inspectable instead of half-written).
void conc_fail(Program& prog, const std::string& why) {
    if (prog.error.empty()) {
        prog.error = why;
    }
}

}  // namespace

std::uint32_t Program::add_block() {
    if (!valid()) {
        return 0;
    }
    const std::uint32_t id = static_cast<std::uint32_t>(blocks.size());
    Block b;
    b.id = id;
    blocks.push_back(std::move(b));
    return id;
}

void Program::add_stmt(std::uint32_t block, const std::string& dst,
                       expr::Id src) {
    if (!valid()) {
        return;
    }
    if (block >= blocks.size()) {
        conc_fail(*this, "add_stmt: unknown block " + std::to_string(block));
        return;
    }
    if (!dag.valid(src)) {
        conc_fail(*this, "add_stmt: invalid source expression for " + dst);
        return;
    }
    if (state_index(dst) == states.size()) {
        StateVar v;
        v.name = dst;
        v.width = dag.width(src);
        v.init = expr::kNoId;
        v.cell = false;
        states.push_back(std::move(v));
    }
    Stmt s;
    s.dst = dst;
    s.src = src;
    blocks[block].stmts.push_back(std::move(s));
}

void Program::add_edge(std::uint32_t block, std::uint32_t target,
                       expr::Id cond) {
    if (!valid()) {
        return;
    }
    if (block >= blocks.size()) {
        conc_fail(*this, "add_edge: unknown block " + std::to_string(block));
        return;
    }
    if (target >= blocks.size()) {
        conc_fail(*this, "add_edge: unknown target " + std::to_string(target));
        return;
    }
    if (cond != expr::kNoId) {
        if (!dag.valid(cond) || dag.width(cond) != 1) {
            conc_fail(*this,
                      "add_edge: condition must be a 1-bit expression");
            return;
        }
    }
    Edge e;
    e.cond = cond;
    e.target = target;
    blocks[block].edges.push_back(std::move(e));
}

expr::Id Program::add_input(const std::string& state, const std::string& sym,
                            unsigned width) {
    if (!valid()) {
        return expr::kNoId;
    }
    if (state_index(state) != states.size()) {
        conc_fail(*this, "add_input: duplicate state " + state);
        return expr::kNoId;
    }
    for (const InputDecl& d : inputs) {
        if (d.sym == sym) {
            conc_fail(*this, "add_input: duplicate input symbol " + sym);
            return expr::kNoId;
        }
    }
    const expr::Id id = dag.input(sym, width);
    if (!dag.valid(id)) {
        conc_fail(*this, "add_input: DAG rejected input " + sym);
        return expr::kNoId;
    }
    StateVar v;
    v.name = state;
    v.width = width;
    v.init = id;
    v.cell = false;
    states.push_back(std::move(v));

    InputDecl d;
    d.state = state;
    d.sym = sym;
    d.width = width;
    d.ordinal = static_cast<std::uint32_t>(dag.node(id).imm);
    inputs.push_back(std::move(d));
    return id;
}

void Program::declare_state(const std::string& name, unsigned width,
                            expr::Id init) {
    if (!valid()) {
        return;
    }
    if (state_index(name) != states.size()) {
        conc_fail(*this, "declare_state: duplicate state " + name);
        return;
    }
    StateVar v;
    v.name = name;
    v.width = width;
    v.init = init;
    v.cell = false;
    states.push_back(std::move(v));
}

void Program::declare_cell(const std::string& name, unsigned width) {
    if (!valid()) {
        return;
    }
    if (state_index(name) != states.size()) {
        conc_fail(*this, "declare_cell: duplicate state " + name);
        return;
    }
    StateVar v;
    v.name = name;
    v.width = width;
    v.init = expr::kNoId;  // a cell starts at zero
    v.cell = true;
    states.push_back(std::move(v));
}

std::size_t Program::state_index(const std::string& name) const {
    for (std::size_t i = 0; i < states.size(); ++i) {
        if (states[i].name == name) {
            return i;
        }
    }
    return states.size();
}

// ------------------------------------------------------------------- run

RunResult run(const Program& prog,
              const std::vector<std::uint64_t>& concrete_inputs,
              std::size_t max_steps) {
    RunResult out;
    if (!prog.valid()) {
        out.status = RunResult::Status::NoEdge;
        return out;
    }

    // Bind every state to its initial value. Inputs bind by ordinal
    // through the DAG; missing entries read as zero by evaluate's own
    // semantics.
    std::vector<std::uint64_t> state_value(prog.states.size(), 0);
    for (std::size_t i = 0; i < prog.states.size(); ++i) {
        state_value[i] =
            prog.dag.evaluate(prog.states[i].init, concrete_inputs);
    }

    // `steps` counts block visits; the cap is checked before each visit,
    // so a run that completes within the cap reports Halt and one whose
    // cap would be exceeded stops early and reports Pruned with the
    // prefix it did visit.
    std::uint32_t cur = prog.entry;
    while (true) {
        if (out.steps >= max_steps) {
            out.status = RunResult::Status::Pruned;
            break;
        }
        if (cur >= prog.blocks.size()) {
            out.status = RunResult::Status::NoEdge;
            break;
        }
        out.blocks.push_back(cur);
        ++out.steps;
        const Block& b = prog.blocks[cur];

        for (const Stmt& s : b.stmts) {
            const std::size_t idx = prog.state_index(s.dst);
            if (idx < state_value.size()) {
                state_value[idx] = prog.dag.evaluate(s.src, concrete_inputs);
            }
        }

        if (b.edges.empty()) {
            out.status = RunResult::Status::Halt;
            break;
        }

        RunResult::Decision d;
        d.block = cur;
        d.chosen = 0;
        d.taken = false;
        bool taken = false;
        for (std::size_t e = 0; e < b.edges.size(); ++e) {
            const Edge& edge = b.edges[e];
            RunResult::EdgeEval ev;
            ev.cond = edge.cond;
            ev.value = edge.cond == expr::kNoId ||
                       prog.dag.evaluate(edge.cond, concrete_inputs) != 0;
            d.edges.push_back(ev);
            if (!taken && ev.value) {
                taken = true;
                d.chosen = static_cast<std::uint32_t>(e);
            }
        }
        d.taken = taken;
        out.decisions.push_back(std::move(d));
        if (!taken) {
            // No edge's condition held and no unconditional edge exists:
            // the program shape does not cover this input. Said, not
            // guessed at.
            out.status = RunResult::Status::NoEdge;
            break;
        }
        cur = b.edges[d.chosen].target;
    }

    for (std::size_t i = 0; i < prog.states.size(); ++i) {
        out.final_state.emplace_back(prog.states[i].name, state_value[i]);
    }
    return out;
}

}  // namespace occ::concolic

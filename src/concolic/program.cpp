// The concolic program model: construction and the concrete interpreter.

#include "occ/concolic/program.h"

#include <algorithm>

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

expr::Id Program::current_expr(const std::string& name) const {
    const std::size_t idx = state_index(name);
    if (idx >= states.size()) {
        return expr::kNoId;
    }
    expr::Id current = states[idx].init;
    for (const Block& b : blocks) {
        for (const Stmt& st : b.stmts) {
            // Every statement that names `dst` (plain assignment, load,
            // or conditional store) gives the state its new value.
            if (st.dst == name) {
                current = st.src;
            }
        }
    }
    return current;
}

namespace {

// Parses the address out of a cell name of the family form
// `base[0x1234]`; returns false when the name is not of that shape.
bool conc_parse_cell_addr(const std::string& name, const std::string& base,
                          std::uint64_t* addr) {
    const std::string prefix = base + "[";
    if (name.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    const std::size_t open = prefix.size();
    const std::size_t close = name.find(']', open);
    if (close == std::string::npos || close == open ||
        close != name.size() - 1) {
        return false;
    }
    const std::string body = name.substr(open, close - open);
    // Plain unsigned decimal or 0x-hex, nothing else (so "mem[idx]" is
    // rejected loudly instead of guessed).
    std::uint64_t v = 0;
    if (body.size() > 2 && body[0] == '0' &&
        (body[1] == 'x' || body[1] == 'X')) {
        for (std::size_t i = 2; i < body.size(); ++i) {
            const char c = body[i];
            unsigned d = 0;
            if (c >= '0' && c <= '9') {
                d = static_cast<unsigned>(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                d = static_cast<unsigned>(c - 'a') + 10;
            } else if (c >= 'A' && c <= 'F') {
                d = static_cast<unsigned>(c - 'A') + 10;
            } else {
                return false;
            }
            v = (v << 4) | static_cast<std::uint64_t>(d);
        }
    } else {
        if (body.empty()) {
            return false;
        }
        for (const char c : body) {
            if (c < '0' || c > '9') {
                return false;
            }
            v = v * 10 + static_cast<std::uint64_t>(c - '0');
        }
    }
    *addr = v;
    return true;
}

// The cell's value at `width`: its current expression, or zero when it
// has never been written.
expr::Id conc_cell_value(Program& prog, const std::string& name,
                         unsigned width) {
    const expr::Id cur = prog.current_expr(name);
    if (cur == expr::kNoId) {
        return prog.dag.constant(0, width);
    }
    return prog.dag.resize(cur, width);
}

}  // namespace

std::vector<std::pair<std::uint64_t, std::string>> Program::cell_family(
    const std::string& base) const {
    std::vector<std::pair<std::uint64_t, std::string>> out;
    for (const StateVar& s : states) {
        if (!s.cell) {
            continue;
        }
        std::uint64_t addr = 0;
        if (conc_parse_cell_addr(s.name, base, &addr)) {
            out.push_back(std::make_pair(addr, s.name));
        }
    }
    std::sort(out.begin(), out.end(),
              [](const std::pair<std::uint64_t, std::string>& a,
                 const std::pair<std::uint64_t, std::string>& b) {
                  return a.first < b.first;
              });
    return out;
}

void Program::add_load(std::uint32_t block, const std::string& dst,
                       expr::Id addr, const std::string& base,
                       unsigned width) {
    if (!valid()) {
        return;
    }
    if (block >= blocks.size()) {
        conc_fail(*this, "add_load: unknown block " + std::to_string(block));
        return;
    }
    if (!dag.valid(addr)) {
        conc_fail(*this, "add_load: invalid address expression");
        return;
    }
    const std::vector<std::pair<std::uint64_t, std::string>> cells =
        cell_family(base);
    expr::Id chain = dag.constant(0, width);
    const unsigned addr_width = dag.width(addr);
    for (std::size_t i = cells.size(); i > 0; --i) {
        const std::uint64_t caddr = cells[i - 1].first;
        const expr::Id cell_val =
            conc_cell_value(*this, cells[i - 1].second, width);
        const expr::Id eq =
            dag.cmp_eq(addr, dag.constant(caddr, addr_width));
        chain = dag.select(eq, cell_val, chain);
    }
    // Declare the destination at the load width, then assign the chain.
    if (state_index(dst) == states.size()) {
        StateVar v;
        v.name = dst;
        v.width = width;
        v.init = expr::kNoId;
        v.cell = false;
        states.push_back(std::move(v));
    }
    Stmt s;
    s.kind = Stmt::Kind::Load;
    s.dst = dst;
    s.addr = addr;
    s.base = base;
    s.src = chain;
    blocks[block].stmts.push_back(std::move(s));
}

void Program::add_store(std::uint32_t block, const std::string& base,
                        expr::Id addr, expr::Id value) {
    if (!valid()) {
        return;
    }
    if (block >= blocks.size()) {
        conc_fail(*this, "add_store: unknown block " + std::to_string(block));
        return;
    }
    if (!dag.valid(addr) || !dag.valid(value)) {
        conc_fail(*this, "add_store: invalid address or value expression");
        return;
    }
    const std::vector<std::pair<std::uint64_t, std::string>> cells =
        cell_family(base);
    if (cells.empty()) {
        conc_fail(*this, "add_store: no cells in family " + base);
        return;
    }
    const unsigned addr_width = dag.width(addr);
    for (const auto& cell : cells) {
        const std::uint64_t caddr = cell.first;
        const StateVar& sv = states[state_index(cell.second)];
        const expr::Id stored =
            dag.resize(value, sv.width != 0 ? sv.width : 64);
        const expr::Id old_val =
            conc_cell_value(*this, cell.second, sv.width != 0 ? sv.width : 64);
        const expr::Id eq =
            dag.cmp_eq(addr, dag.constant(caddr, addr_width));
        const expr::Id new_val = dag.select(eq, stored, old_val);
        Stmt s;
        s.kind = Stmt::Kind::Store;
        s.dst = cell.second;
        s.addr = addr;
        s.base = base;
        s.src = new_val;
        blocks[block].stmts.push_back(std::move(s));
    }
}

}  // namespace occ::concolic

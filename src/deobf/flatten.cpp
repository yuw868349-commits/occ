// Control-flow flattening recovery: find the dispatcher, propagate the
// state constant, resolve the edges.
//
// The pass is syntactic only where it has to be (the dispatcher's edges
// must be equality tests of one input against constants, possibly
// disguised as `(state ^ key) == c`) and proof-based everywhere else:
// the state value that reaches a block's outgoing edge is propagated
// through the block's assignments, and an edge to the dispatcher is
// retargeted only when that propagated value is a constant that the
// dispatcher's case table actually contains. A block whose exit state is
// unknown -- because it does not assign the state variable, or assigns
// it an expression that depends on the entry value -- leaves its edge
// unresolved and the recovery reports a partial result instead of
// guessing a successor.
//
// Blocks that do not assign the state at all are a real OLLVM shape only
// when the state's entry value is itself a constant (a case target
// re-dispatching with an unchanged state); resolving those needs a
// fixpoint over the case table that this pass deliberately does not
// attempt in its first version. The unresolved list names them; the
// "do not guess" rule wins over a slightly more complete recovery.

#include "occ/deobf/flatten.h"

#include <algorithm>
#include <cstdio>
#include <limits>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace occ::deobf {

bool deobf_normalize_case(const LiftedFunc& func, devirt::expr::Id cond,
                          CaseTest& out) {
    if (!func.dag.valid(cond) || func.dag.node(cond).op != devirt::expr::Op::CmpEQ) {
        return false;
    }
    const devirt::expr::Node& n = func.dag.node(cond);
    const devirt::expr::Id sides[2] = {n.a, n.b};

    // Classify one side: either a constant, or the state input (possibly
    // xored with a constant key). At most one side may be the state.
    bool have_state = false;
    std::uint32_t ordinal = 0;
    std::uint64_t key = 0;
    std::uint64_t constant = 0;
    bool have_const = false;

    const auto classify = [&](devirt::expr::Id side) -> bool {
        if (!func.dag.valid(side)) {
            return false;
        }
        const devirt::expr::Node& s = func.dag.node(side);
        if (s.op == devirt::expr::Op::Const) {
            constant = s.imm;
            have_const = true;
            return true;
        }
        if (s.op == devirt::expr::Op::Input) {
            if (have_state) {
                return false;  // two state sides is not a case test
            }
            ordinal = static_cast<std::uint32_t>(s.imm);
            key = 0;
            have_state = true;
            return true;
        }
        if (s.op == devirt::expr::Op::Xor) {
            if (have_state) {
                return false;
            }
            if (!func.dag.valid(s.a) || !func.dag.valid(s.b)) {
                return false;
            }
            const devirt::expr::Node& xa = func.dag.node(s.a);
            const devirt::expr::Node& xb = func.dag.node(s.b);
            if (xa.op == devirt::expr::Op::Input && xb.op == devirt::expr::Op::Const) {
                ordinal = static_cast<std::uint32_t>(xa.imm);
                key = xb.imm;
                have_state = true;
                return true;
            }
            if (xb.op == devirt::expr::Op::Input && xa.op == devirt::expr::Op::Const) {
                ordinal = static_cast<std::uint32_t>(xb.imm);
                key = xa.imm;
                have_state = true;
                return true;
            }
            return false;
        }
        return false;  // anything else: not a case test
    };

    if (!classify(sides[0]) || !classify(sides[1])) {
        return false;
    }
    if (!have_state || !have_const) {
        return false;
    }

    // `(state ^ key) == c` means `state == c ^ key`, with the comparison
    // masked to the state's width (a careless author may have compared
    // against a wide constant; only the low bits can ever match).
    const unsigned state_width = [&] {
        for (const devirt::expr::Id side : sides) {
            if (!func.dag.valid(side)) {
                continue;
            }
            const devirt::expr::Node& s = func.dag.node(side);
            if (s.op == devirt::expr::Op::Input && s.imm == ordinal) {
                return s.width;
            }
            if (s.op == devirt::expr::Op::Xor) {
                for (const devirt::expr::Id c : {s.a, s.b}) {
                    if (func.dag.valid(c) &&
                        func.dag.node(c).op == devirt::expr::Op::Input &&
                        func.dag.node(c).imm == ordinal) {
                        return func.dag.node(c).width;
                    }
                }
            }
        }
        return 64u;
    }();
    std::uint64_t mask = std::numeric_limits<std::uint64_t>::max();
    if (state_width < 64) {
        mask = (std::uint64_t{1} << state_width) - 1;
    }
    out.state_ordinal = ordinal;
    out.value = (constant ^ key) & mask;
    out.key = key;
    out.xor_variant = key != 0;
    char buf[128];
    if (out.xor_variant) {
        std::snprintf(buf, sizeof(buf), "(state ^ 0x%llx) == 0x%llx",
                      static_cast<unsigned long long>(key),
                      static_cast<unsigned long long>(constant));
    } else {
        std::snprintf(buf, sizeof(buf), "state == 0x%llx",
                      static_cast<unsigned long long>(constant));
    }
    out.rendered = buf;
    return true;
}

namespace {

// The propagated value of a block's state variable at its exit: the last
// expression assigned to the state name, which must be a constant for the
// edge to resolve.
bool exit_state_constant(const LiftedFunc& func, const Block& block,
                         const std::string& state_name, std::uint64_t& value) {
    std::unordered_map<std::string, devirt::expr::Id> latest;
    for (const Assign& a : block.assigns) {
        latest[a.dst] = a.value;
    }
    const auto it = latest.find(state_name);
    if (it == latest.end()) {
        return false;  // state untouched: the entry value, unknown here
    }
    const devirt::expr::Id v = it->second;
    if (!func.dag.valid(v) || !func.dag.is_const(v)) {
        return false;
    }
    value = func.dag.const_value(v);
    return true;
}

}  // namespace

LiftedFunc recover_flattening(const LiftedFunc& func,
                              const FlattenOptions& options,
                              FlattenResult& out) {
    // -------------------------------------------------- dispatcher hunt
    std::uint32_t dispatcher = std::numeric_limits<std::uint32_t>::max();
    std::size_t best_edges = 0;
    std::vector<CaseTest> best_tests;

    for (const Block& block : func.blocks) {
        if (block.edges.size() < options.min_dispatcher_edges) {
            continue;
        }
        std::vector<CaseTest> tests;
        // Every edge must test the *same* state variable: the ordinal set
        // is a single-element invariant, not a per-edge uniqueness check
        // (repeats are exactly what a dispatcher looks like).
        std::optional<std::uint32_t> ordinal_seen;
        std::unordered_set<std::uint64_t> values;
        bool all_cases = true;
        for (const Edge& e : block.edges) {
            CaseTest t;
            if (!deobf_normalize_case(func, e.cond, t)) {
                all_cases = false;
                break;
            }
            if (ordinal_seen.has_value()) {
                if (*ordinal_seen != t.state_ordinal) {
                    all_cases = false;  // two different state variables
                    break;
                }
            } else {
                ordinal_seen = t.state_ordinal;
            }
            if (!values.insert(t.value).second) {
                all_cases = false;  // duplicate case value
                break;
            }
            tests.push_back(std::move(t));
        }
        if (!all_cases) {
            continue;
        }
        // Deterministic tie-break: the largest dispatcher wins; on equal
        // size, the lowest block id (blocks are visited in id order).
        if (block.edges.size() > best_edges) {
            best_edges = block.edges.size();
            dispatcher = block.id;
            best_tests = std::move(tests);
        }
    }

    if (dispatcher == std::numeric_limits<std::uint32_t>::max()) {
        out.recognized = false;
        out.unresolved.push_back(
            "no block has >= " +
            std::to_string(options.min_dispatcher_edges) +
            " edges that are all equality tests of one input against "
            "distinct constants");
        out.func = func;
        return out.func;
    }

    // The case table: state value -> target. The test vector was built in
    // edge order, so the pairing with the dispatcher's edges is
    // positional.
    std::unordered_map<std::uint64_t, std::uint32_t> cases;
    const Block& dispatch_block = func.blocks[dispatcher];
    for (std::size_t i = 0; i < best_tests.size(); ++i) {
        cases[best_tests[i].value] = dispatch_block.edges[i].target;
    }

    // The name the dispatcher tests: the DAG's own record of the input.
    const std::vector<std::string>& names = func.dag.input_names();
    const std::uint32_t ordinal = best_tests[0].state_ordinal;
    std::string state_name = "state";
    if (ordinal < names.size()) {
        state_name = names[ordinal];
    }

    FlattenStep identified;
    identified.what = "dispatcher identified";
    identified.block = dispatcher;
    identified.detail = "state variable \"" + state_name + "\", " +
                        std::to_string(best_tests.size()) + " cases";
    out.steps.push_back(std::move(identified));
    out.dispatcher = dispatcher;
    out.state_name = state_name;
    out.state_ordinal = ordinal;
    out.cases.reserve(best_tests.size());
    for (const CaseTest& t : best_tests) {
        out.cases.emplace_back(t.value, cases[t.value]);
    }

    // ------------------------------------------- propagate and resolve
    std::size_t edges_into_dispatcher = 0;
    std::size_t unresolved_count = 0;

    LiftedFunc work = func;
    for (Block& block : work.blocks) {
        if (block.id == dispatcher) {
            continue;
        }
        std::uint64_t state_value = 0;
        const bool known =
            exit_state_constant(work, block, state_name, state_value);
        for (Edge& e : block.edges) {
            if (e.target != dispatcher) {
                continue;
            }
            ++edges_into_dispatcher;
            FlattenStep s;
            s.block = block.id;
            s.old_target = e.target;
            if (known) {
                const auto case_it = cases.find(state_value);
                if (case_it != cases.end()) {
                    s.what = "edge retargeted";
                    e.target = case_it->second;
                    s.new_target = e.target;
                    char buf[64];
                    std::snprintf(buf, sizeof(buf), "state=0x%llx",
                                  static_cast<unsigned long long>(state_value));
                    s.detail = buf;
                    out.steps.push_back(std::move(s));
                } else {
                    s.what = "edge unresolved";
                    s.resolved = false;
                    char buf[32];
                    std::snprintf(buf, sizeof(buf), "state=0x%llx",
                                  static_cast<unsigned long long>(state_value));
                    s.detail = std::string(buf) + " has no dispatcher case";
                    out.steps.push_back(std::move(s));
                    ++unresolved_count;
                }
            } else {
                s.what = "edge unresolved";
                s.resolved = false;
                s.detail = "block exit state is not a constant";
                out.steps.push_back(std::move(s));
                ++unresolved_count;
            }
        }
    }

    // --------------------------------------------------------- rebuild
    if (unresolved_count != 0 || edges_into_dispatcher == 0) {
        // Partial (or vacuous) recovery: keep the dispatcher, name what
        // blocked, return an unchanged copy.
        out.recognized = false;
        for (const FlattenStep& s : out.steps) {
            if (!s.resolved) {
                out.unresolved.push_back(s.detail);
            }
        }
        if (edges_into_dispatcher == 0) {
            out.unresolved.push_back(
                "no ordinary block branches to the dispatcher; nothing to "
                "resolve");
        }
        out.func = func;
        return out.func;
    }

    // Renumber the surviving blocks, remap every edge. The DAG is copied
    // as-is; node ids stay valid in the copy. Iterates `work`, the copy
    // whose edges were retargeted above -- the original `func` still
    // points at the dispatcher. The remap is built in one pass over all
    // surviving blocks and applied in a second, so forward references
    // (an edge to a block that has not been renumbered yet) resolve.
    std::unordered_map<std::uint32_t, std::uint32_t> remap;
    for (const Block& block : work.blocks) {
        if (block.id == dispatcher) {
            continue;
        }
        remap[block.id] = static_cast<std::uint32_t>(remap.size());
    }
    LiftedFunc recovered;
    recovered.dag = func.dag;
    recovered.state_vars = func.state_vars;
    for (const Block& block : work.blocks) {
        if (block.id == dispatcher) {
            continue;
        }
        const std::uint32_t new_id = remap[block.id];
        Block nb;
        nb.id = new_id;
        nb.label = block.label;
        nb.assigns = block.assigns;
        for (const Edge& e : block.edges) {
            const auto it = remap.find(e.target);
            if (it == remap.end()) {
                // A dangling edge (only possible for the dispatcher, which
                // should have been fully resolved above). Drop it and say
                // so rather than emit a broken CFG.
                out.unresolved.push_back("dropped dangling edge from block " +
                                         std::to_string(block.id));
                continue;
            }
            Edge ne = e;
            ne.target = it->second;
            nb.edges.push_back(std::move(ne));
        }
        recovered.blocks.push_back(std::move(nb));
    }
    const auto entry_it = remap.find(func.entry);
    if (entry_it == remap.end()) {
        out.unresolved.push_back("entry block was the dispatcher");
        out.recognized = false;
        out.func = func;
        return out.func;
    }
    recovered.entry = entry_it->second;
    out.recognized = true;
    out.func = std::move(recovered);
    return out.func;
}

}  // namespace occ::deobf

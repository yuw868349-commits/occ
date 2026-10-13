// Opaque predicate elimination: prove edge conditions constant, cut the
// dead edges.
//
// The pass asks one question per 1-bit edge condition -- "is this edge
// always taken?" / "is this edge never taken?" -- and lets the
// equivalence layer answer with a method and a certificate. The layer
// order (ring, then SAT) is inherited from `devirt::bb::prove_equivalent`: the
// ring normalizer decides constants and ring identities with no search,
// and the CDCL path decides the bitwise shapes OLLVM emits. The answer
// is a proof, not a pattern match: a predicate shape this file has never
// seen is still eliminated if the layers can prove it constant.
//
// The structural rules and the "exactly one edge taken per execution"
// assumption they rest on are documented in opaque.h. The conservative
// choices are deliberate: a constant-true edge in a multi-way block is
// reported with its proof but not forced unless the caller opts in,
// because forcing would delete the other cases on the strength of an
// exclusivity assumption about a switch this pass cannot see.

#include "occ/deobf/opaque.h"

#include <cstdio>
#include <unordered_map>
#include <utility>

namespace occ::deobf {

namespace {

// The verdict for one condition, per question direction. The two bits
// are independent: asking "is it constant false?" first must not poison
// the later "is it constant true?" query -- they are different
// propositions and each deserves its own proof attempt.
struct Verdict {
    bool proven_true = false;
    bool proven_false = false;
};

// Asks the equivalence layer whether `cond` is constant. Records the
// answering method and its statistics into `step` for the report.
bool prove_constant(devirt::expr::DAG& dag, devirt::expr::Id cond, bool want_true,
                    bool want_proof, OpaqueStep& step) {
    const devirt::expr::Id target = dag.constant(want_true ? 1u : 0u, 1);
    const devirt::bb::Equivalence e =
        devirt::bb::prove_equivalent(dag, cond, target, want_proof);
    if (!e.equal) {
        return false;
    }
    step.method = e.method;
    step.conflicts = e.conflicts;
    step.propagations = e.propagations;
    if (e.method == devirt::bb::Method::Ring) {
        step.evidence = e.witness;
    } else {
        char buf[96];
        std::snprintf(buf, sizeof(buf), "conflicts=%llu propagations=%llu",
                      static_cast<unsigned long long>(e.conflicts),
                      static_cast<unsigned long long>(e.propagations));
        step.evidence = buf;
        if (want_proof) {
            step.evidence += " drup_lines=";
            step.evidence +=
                std::to_string(static_cast<unsigned long long>(e.proof.size()));
        }
    }
    return true;
}

// Removes edge `idx` from the block, recording the deletion as a step.
void delete_edge(LiftedFunc& func, Block& block, std::size_t idx,
                 OpaqueResult& out) {
    OpaqueStep s;
    s.block = block.id;
    s.edge = static_cast<std::uint32_t>(idx);
    s.cond = func.dag.pretty(block.edges[idx].cond);
    s.constant_false = true;
    s.action = "deleted";
    out.steps.push_back(std::move(s));
    ++out.edges_deleted;
    block.edges.erase(block.edges.begin() +
                      static_cast<std::ptrdiff_t>(idx));
}

}  // namespace

LiftedFunc eliminate_opaque(const LiftedFunc& func,
                            const OpaqueOptions& options,
                            OpaqueResult& out) {
    LiftedFunc cleaned = func;

    // Verdict cache: condition node id -> proven value.
    std::unordered_map<devirt::expr::Id, Verdict> verdicts;

    const auto ask = [&](std::uint32_t block_id, std::size_t edge_idx,
                          devirt::expr::Id cond, bool want_true) -> bool {
        if (cond == devirt::expr::kNoId) {
            return false;
        }
        Verdict& v = verdicts[cond];
        bool& slot = want_true ? v.proven_true : v.proven_false;
        if (slot) {
            return true;
        }
        OpaqueStep scratch;
        scratch.block = block_id;
        scratch.edge = static_cast<std::uint32_t>(edge_idx);
        scratch.cond = cleaned.dag.pretty(cond);
        if (prove_constant(cleaned.dag, cond, want_true,
                           options.want_proof, scratch)) {
            slot = true;
            // Record the proof of the constant condition itself, with the
            // method that produced it.
            scratch.constant_true = want_true;
            scratch.constant_false = !want_true;
            scratch.action = "proven constant";
            out.steps.push_back(std::move(scratch));
        }
        ++out.conditions_inspected;
        return slot;
    };

    // Each block converges: deletion shrinks the edge set, which can turn
    // a multi-way block into a two-way one and unlock the force rule.
    // The loop terminates because every iteration that changes anything
    // strictly removes an edge or strips a condition.
    for (Block& block : cleaned.blocks) {
        bool changed = true;
        while (changed) {
            changed = false;
            // R1: delete provably-dead edges.
            for (std::size_t i = block.edges.size(); i > 0; --i) {
                const std::size_t idx = i - 1;
                const Edge& e = block.edges[idx];
                if (e.cond == devirt::expr::kNoId) {
                    continue;
                }
                if (options.prove_always_false &&
                    ask(block.id, idx, e.cond, /*want_true=*/false)) {
                    delete_edge(cleaned, block, idx, out);
                    changed = true;
                }
            }
            if (block.edges.empty()) {
                break;  // an exit block; nothing left to decide
            }
            // A single surviving edge is unconditional by construction.
            if (block.edges.size() == 1 && block.edges[0].cond != devirt::expr::kNoId) {
                OpaqueStep s;
                s.block = block.id;
                s.edge = 0;
                s.cond = cleaned.dag.pretty(block.edges[0].cond);
                s.constant_true = true;
                s.method = devirt::bb::Method::Ring;
                s.action = "sole edge made unconditional";
                block.edges[0].cond = devirt::expr::kNoId;
                out.steps.push_back(std::move(s));
                ++out.edges_forced;
                changed = true;
                continue;
            }
            // R2: the OLLVM branch shape -- two edges, one provably
            // always taken. The other edge dies, the true one is forced.
            if (block.edges.size() == 2) {
                bool forced = false;
                for (std::size_t i = 0; i < 2 && !forced; ++i) {
                    const Edge& e = block.edges[i];
                    if (e.cond != devirt::expr::kNoId && options.prove_always_true &&
                        ask(block.id, i, e.cond, /*want_true=*/true)) {
                        const std::size_t other = i == 0 ? 1 : 0;
                        OpaqueStep del;
                        del.block = block.id;
                        del.edge = static_cast<std::uint32_t>(other);
                        del.cond = cleaned.dag.pretty(block.edges[other].cond);
                        del.constant_false = true;
                        del.method = devirt::bb::Method::Ring;
                        del.action = "deleted (other side of always-true)";
                        out.steps.push_back(std::move(del));
                        block.edges.erase(
                            block.edges.begin() +
                            static_cast<std::ptrdiff_t>(other));
                        ++out.edges_deleted;

                        OpaqueStep f;
                        f.block = block.id;
                        f.edge = static_cast<std::uint32_t>(i < other ? i : 0);
                        f.cond = cleaned.dag.pretty(e.cond);
                        f.constant_true = true;
                        f.method = devirt::bb::Method::Ring;
                        f.action = "forced unconditional (always-true)";
                        block.edges[i < other ? i : 0].cond = devirt::expr::kNoId;
                        out.steps.push_back(std::move(f));
                        ++out.edges_forced;
                        forced = true;
                        changed = true;
                    }
                }
                if (forced) {
                    continue;
                }
            }
            // R3: multi-way blocks. A constant-true edge is evidence only
            // unless the caller opts into the exclusivity reading.
            if (block.edges.size() >= 3 && options.prove_always_true) {
                bool forced = false;
                for (std::size_t i = 0; i < block.edges.size(); ++i) {
                    Edge& e = block.edges[i];
                    if (e.cond != devirt::expr::kNoId &&
                        ask(block.id, i, e.cond, true)) {
                        if (!options.force_multiway) {
                            OpaqueStep s;
                            s.block = block.id;
                            s.cond = cleaned.dag.pretty(e.cond);
                            s.constant_true = true;
                            s.action = "proven constant-true; multi-way "
                                       "block, not forced";
                            out.steps.push_back(std::move(s));
                            changed = false;
                            break;
                        }
                        forced = true;
                        changed = true;
                        break;
                    }
                }
                if (forced) {
                    // Delete every other edge, force this one. Re-derive
                    // the index: the loop above found the first
                    // constant-true edge.
                    for (std::size_t i = block.edges.size(); i > 0; --i) {
                        const std::size_t idx = i - 1;
                        if (block.edges[idx].cond == devirt::expr::kNoId ||
                            !verdicts[block.edges[idx].cond].proven_true) {
                            delete_edge(cleaned, block, idx, out);
                        }
                    }
                    for (Edge& e : block.edges) {
                        if (e.cond != devirt::expr::kNoId) {
                            OpaqueStep f;
                            f.block = block.id;
                            f.cond = cleaned.dag.pretty(e.cond);
                            f.constant_true = true;
                            f.method = devirt::bb::Method::Ring;
                            f.action = "forced unconditional (always-true)";
                            e.cond = devirt::expr::kNoId;
                            out.steps.push_back(std::move(f));
                            ++out.edges_forced;
                            break;
                        }
                    }
                    continue;
                }
            }
            if (!changed) {
                break;
            }
        }
    }

    out.func = cleaned;
    return out.func;
}

}  // namespace occ::deobf

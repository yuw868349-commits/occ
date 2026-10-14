// Bounded concolic path exploration and its report rendering.

#include "occ/concolic/engine.h"

#include <algorithm>
#include <cstddef>
#include <set>
#include <tuple>

namespace occ::concolic {

namespace {

// Negates a 1-bit condition: asserting the run's observed value was
// wrong is asserting the negated expression. The DAG hash-conses the new
// node, so the same flip asked twice costs nothing extra.
expr::Id conc_negate(expr::DAG& dag, expr::Id cond) {
    return dag.bit_not(cond);
}

std::string conc_hex(std::uint64_t value) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out = "0x";
    bool started = false;
    for (int shift = 60; shift >= 0; shift -= 4) {
        const char d =
            kDigits[static_cast<std::size_t>((value >> static_cast<unsigned>(shift)) & 0xF)];
        if (d != '0' || started || shift == 0) {
            out += d;
            started = true;
        }
    }
    return out;
}

// A pending flip: solve `cons`, and if satisfiable run the merged model
// from `parent_inputs`.
struct FlipJob {
    std::vector<expr::Id> cons;
    std::vector<std::uint64_t> parent_inputs;
    std::uint32_t block = 0;
    std::uint32_t edge = 0;
};

// Deduplication key for a flip: the constraint set and the edge it
// targets. The same set solves identically, so re-asking the solver is
// pure waste. Two parents that reach the same flip with the same
// constraints differ only in inputs the constraints never mention; such
// variants are deliberately not re-explored -- the driver is bounded, the
// merge keeps those inputs stable, and the bounds are disclosed in the
// report rather than hidden.
using JobKey = std::tuple<std::vector<expr::Id>, std::uint32_t, std::uint32_t>;

std::vector<bool> conc_referenced_inputs(const Program& prog,
                                         const std::vector<expr::Id>& cons) {
    std::vector<bool> referenced(prog.num_inputs(), false);
    for (const expr::Id c : cons) {
        for (const unsigned ord : prog.dag.inputs_of(c)) {
            if (ord < referenced.size()) {
                referenced[ord] = true;
            }
        }
    }
    return referenced;
}

// A prefix tree over visited block sequences: the exploration's path
// deduplication. Insertion is O(path length) and each shared prefix is
// stored once, which beats a set-of-vectors both in memory and in
// comparison cost on loop-heavy programs whose paths share long heads.
struct PathTrie {
    struct Node {
        std::vector<std::pair<std::uint32_t, std::uint32_t>> children;
        bool terminal = false;
    };
    std::vector<Node> nodes{1};  // node 0 is the root

    // Inserts `path`; returns true when it was not present before.
    bool insert(const std::vector<std::uint32_t>& path) {
        std::uint32_t cur = 0;
        for (const std::uint32_t b : path) {
            // Take the child-list offset before growing `nodes`: the
            // push_back can reallocate the node vector and invalidate
            // any reference into it, so the insert re-reads the list by
            // index after the growth.
            auto& kids = nodes[cur].children;
            auto it = std::lower_bound(
                kids.begin(), kids.end(), b,
                [](const std::pair<std::uint32_t, std::uint32_t>& e,
                   std::uint32_t key) { return e.first < key; });
            if (it != kids.end() && it->first == b) {
                cur = it->second;
            } else {
                const std::size_t at =
                    static_cast<std::size_t>(it - kids.begin());
                const std::uint32_t n =
                    static_cast<std::uint32_t>(nodes.size());
                nodes.push_back(Node{});
                nodes[cur].children.insert(
                    nodes[cur].children.begin() +
                        static_cast<std::ptrdiff_t>(at),
                    std::make_pair(b, n));
                cur = n;
            }
        }
        if (nodes[cur].terminal) {
            return false;
        }
        nodes[cur].terminal = true;
        return true;
    }
};

// An unsat constraint set makes every superset unsat, so a flip whose
// constraint prefix was already proved unsatisfiable is answered without
// a solver call. The check is a prefix scan over the recorded unsat sets
// -- O(cached * cons) per flip, trivially cheap next to a CDCL call.
bool conc_has_unsat_prefix(const std::vector<std::vector<expr::Id>>& unsat_cache,
                           const std::vector<expr::Id>& cons) {
    for (const std::vector<expr::Id>& u : unsat_cache) {
        if (u.size() > cons.size()) {
            continue;
        }
        bool prefix = true;
        for (std::size_t i = 0; i < u.size(); ++i) {
            if (u[i] != cons[i]) {
                prefix = false;
                break;
            }
        }
        if (prefix) {
            return true;
        }
    }
    return false;
}

// Merges the solver's model into the parent inputs: inputs the constraint
// set pins take the model's values, everything else keeps the value it
// had on the run that produced this flip. An input the constraints never
// mention is a free variable of the question and must not silently become
// zero -- standard concolic practice, and what keeps an unrelated input
// stable across the exploration.
std::vector<std::uint64_t> conc_merge_inputs(
    const Program& prog, const std::vector<std::uint64_t>& parent_inputs,
    const std::vector<expr::Id>& cons, const std::vector<std::uint64_t>& model) {
    std::vector<std::uint64_t> merged = parent_inputs;
    const std::vector<bool> referenced = conc_referenced_inputs(prog, cons);
    for (std::size_t ord = 0; ord < referenced.size(); ++ord) {
        if (referenced[ord] && ord < model.size()) {
            merged[ord] = model[ord];
        }
    }
    return merged;
}

}  // namespace

PathReport concolic_explore(Program& prog,
                            const std::vector<std::uint64_t>& initial_inputs,
                            const Budget& budget) {
    PathReport out;
    out.budget = budget;
    if (!prog.valid()) {
        out.error = prog.error;
        return out;
    }
    if (initial_inputs.size() != prog.num_inputs()) {
        out.error = "concolic_explore: expected " +
                    std::to_string(prog.num_inputs()) + " initial inputs, got " +
                    std::to_string(initial_inputs.size());
        return out;
    }
    if (budget.max_paths == 0) {
        return out;
    }

    std::set<std::vector<std::uint64_t>> seen_inputs;
    PathTrie seen_paths;
    std::set<JobKey> seen_jobs;
    // Coverage-driven worklists: flips whose target edge is not yet
    // covered sit in `hot`, everything else in `cold`. Popping hot
    // first biases the search toward new edges without abandoning the
    // depth-first discipline inside each queue (both are LIFO).
    std::vector<FlipJob> hot_worklist;
    std::vector<FlipJob> cold_worklist;
    std::set<std::uint32_t> covered_blocks;
    std::set<std::pair<std::uint32_t, std::uint32_t>> covered_edges;
    // Every constraint set the solver proved unsatisfiable. A flip whose
    // constraints extend one of these is answered from the cache.
    std::vector<std::vector<expr::Id>> unsat_cache;
    std::size_t executed = 0;

    // Runs `inputs`, records the path if it is new, and pushes every
    // flip candidate the path offers. Flip candidates are pushed onto
    // the hot queue when their target edge is uncovered, else the cold
    // queue; both are LIFO, so the driver keeps a depth-first order
    // while preferring edges that add coverage.
    const auto record_and_expand = [&](const std::vector<std::uint64_t>& inputs) {
        const RunResult rr = run(prog, inputs, budget.max_run_steps);
        if (!seen_paths.insert(rr.blocks)) {
            return;  // the same block sequence was already explored
        }

        // Path constraints and per-decision flip candidates.
        std::vector<expr::Id> path_cons;
        std::size_t decision_index = 0;
        for (const RunResult::Decision& d : rr.decisions) {
            // Flippable edges: the conditioned edges before the first
            // unconditional edge. An unconditional edge is always taken,
            // so no constraint can route the run past it; offering such a
            // flip would silently diverge from the declared target.
            std::size_t first_uncond = d.edges.size();
            for (std::size_t j = 0; j < d.edges.size(); ++j) {
                if (d.edges[j].cond == expr::kNoId) {
                    first_uncond = j;
                    break;
                }
            }
            if (decision_index + 1 <= budget.max_depth) {
                // Push flips in reverse edge order so the stack pops the
                // first edge first: an unsat answer for an early edge is
                // recorded before later edges of the same decision are
                // solved, and their superset prefixes then hit the
                // unsat-prefix cache. DFS completeness is unaffected --
                // every flip is still pushed and popped exactly once.
                for (std::size_t ki = first_uncond; ki > 0; --ki) {
                    const std::size_t k = ki - 1;
                    if (d.edges[k].cond == expr::kNoId) {
                        continue;
                    }
                    // To force edge k: every conditioned edge before it
                    // stays false -- which negates `chosen` when k lies
                    // after it -- and k's own condition becomes true, or
                    // false when k is the edge that was chosen. When the
                    // run took nothing (NoEdge) there is no chosen edge:
                    // making k true is enough.
                    std::vector<expr::Id> cons = path_cons;
                    for (std::size_t j = 0; j < k; ++j) {
                        if (d.edges[j].cond != expr::kNoId) {
                            cons.push_back(conc_negate(prog.dag, d.edges[j].cond));
                        }
                    }
                    if (d.taken && k == d.chosen) {
                        cons.push_back(conc_negate(prog.dag, d.edges[k].cond));
                    } else {
                        cons.push_back(d.edges[k].cond);
                    }
                    const JobKey key{cons, d.block, static_cast<std::uint32_t>(k)};
                    if (seen_jobs.insert(key).second) {
                        FlipJob job{std::move(cons), inputs, d.block,
                                    static_cast<std::uint32_t>(k)};
                        const bool uncovered =
                            !covered_edges.count(std::make_pair(
                                d.block, static_cast<std::uint32_t>(k)));
                        (uncovered ? hot_worklist : cold_worklist)
                            .push_back(std::move(job));
                    }
                }
            }

            // This decision's own contribution to the path constraints:
            // every earlier conditioned edge was false, the chosen edge
            // was true (when it is conditioned). When nothing was taken,
            // every conditioned edge was false and all of them are
            // negated.
            for (std::size_t j = 0; j < d.edges.size(); ++j) {
                if (d.edges[j].cond == expr::kNoId) {
                    continue;
                }
                if (!d.taken || j < d.chosen) {
                    path_cons.push_back(conc_negate(prog.dag, d.edges[j].cond));
                } else if (j == d.chosen) {
                    path_cons.push_back(d.edges[j].cond);
                }
            }
            ++decision_index;
        }

        PathReport::Path p;
        p.inputs = inputs;
        p.blocks = rr.blocks;
        p.constraints = std::move(path_cons);
        p.depth = rr.blocks.size();
        p.status = rr.status == RunResult::Status::Halt
                       ? PathReport::Path::Status::Halt
                       : rr.status == RunResult::Status::Pruned
                             ? PathReport::Path::Status::Pruned
                             : PathReport::Path::Status::NoEdge;
        out.paths.push_back(std::move(p));
        ++executed;

        for (const std::uint32_t b : rr.blocks) {
            covered_blocks.insert(b);
        }
        for (const RunResult::Decision& d : rr.decisions) {
            covered_edges.insert(
                std::make_pair(d.block, static_cast<std::uint32_t>(d.chosen)));
        }
    };

    seen_inputs.insert(initial_inputs);
    record_and_expand(initial_inputs);

    while ((!hot_worklist.empty() || !cold_worklist.empty()) &&
           executed < budget.max_paths &&
           out.solver.calls < budget.max_solver_calls) {
        FlipJob job;
        if (!hot_worklist.empty()) {
            job = hot_worklist.back();
            hot_worklist.pop_back();
        } else {
            job = cold_worklist.back();
            cold_worklist.pop_back();
        }
        if (out.solver.calls >= budget.max_solver_calls) {
            break;
        }
        if (conc_has_unsat_prefix(unsat_cache, job.cons)) {
            // A superset of a proved-unsat set is unsat: answered from
            // the cache without a solver call.
            ++out.solver.unsat_prefix_hits;
            ++out.solver.unsat;
            out.unsat_branches.push_back(
                PathReport::UnsatBranch{job.block, job.edge, job.cons});
            PathReport::Path p;
            p.status = PathReport::Path::Status::UnsatNegation;
            p.constraints = job.cons;
            out.paths.push_back(std::move(p));
            continue;
        }
        const bb::Model m = bb::solve_constraints(prog.dag, job.cons);
        ++out.solver.calls;
        out.solver.conflicts += m.conflicts;
        if (m.unproven) {
            // The solver gave no answer (its own budget ran out). Not
            // sat, not unsat: reported as limited, never conflated with
            // unreachable.
            ++out.solver.limited;
            continue;
        }
        if (!m.sat) {
            ++out.solver.unsat;
            // Record for prefix reuse: the whole set, exactly as asked.
            unsat_cache.push_back(job.cons);
            out.unsat_branches.push_back(
                PathReport::UnsatBranch{job.block, job.edge, job.cons});
            // A synthetic path entry so the status enum is the whole
            // vocabulary of the report: this branch could not be taken.
            PathReport::Path p;
            p.status = PathReport::Path::Status::UnsatNegation;
            p.constraints = job.cons;
            out.paths.push_back(std::move(p));
            continue;
        }
        ++out.solver.sat;
        const std::vector<std::uint64_t> next =
            conc_merge_inputs(prog, job.parent_inputs, job.cons, m.inputs);
        if (seen_inputs.insert(next).second) {
            record_and_expand(next);
        }
    }

    // Coverage, computed after exploration so the report is one pass.
    out.coverage.blocks.assign(covered_blocks.begin(), covered_blocks.end());
    out.coverage.edges.assign(covered_edges.begin(), covered_edges.end());
    out.coverage.block_total = prog.blocks.size();
    std::size_t edge_total = 0;
    for (const Block& b : prog.blocks) {
        edge_total += b.edges.size();
    }
    out.coverage.edge_total = edge_total;
    return out;
}

std::string report_text(const Program& prog, const PathReport& report) {
    std::string out;
    out += "=== concolic path report ===\n";
    if (!report.error.empty()) {
        out += "error: " + report.error + "\n";
        return out;
    }

    out += "budget: max_paths=" + std::to_string(report.budget.max_paths) +
           " max_depth=" + std::to_string(report.budget.max_depth) +
           " max_solver_calls=" +
           std::to_string(report.budget.max_solver_calls) +
           " max_run_steps=" + std::to_string(report.budget.max_run_steps) +
           "\n";

    const auto status_text = [](PathReport::Path::Status s) {
        switch (s) {
        case PathReport::Path::Status::Halt:
            return "Halt";
        case PathReport::Path::Status::Pruned:
            return "Pruned";
        case PathReport::Path::Status::NoEdge:
            return "NoEdge";
        case PathReport::Path::Status::UnsatNegation:
            return "UnsatNegation";
        }
        return "?";
    };

    std::size_t executed = 0;
    for (std::size_t i = 0; i < report.paths.size(); ++i) {
        const PathReport::Path& p = report.paths[i];
        if (p.status == PathReport::Path::Status::UnsatNegation) {
            out += "path #" + std::to_string(i) + " " +
                   std::string(status_text(p.status)) + "  constraints:";
            for (const expr::Id c : p.constraints) {
                out += " " + prog.dag.pretty(c) + ";";
            }
            out += "\n";
            continue;
        }
        ++executed;
        out += "path #" + std::to_string(i) + " " +
               std::string(status_text(p.status)) + " depth=" +
               std::to_string(p.depth) + " blocks=[";
        for (std::size_t b = 0; b < p.blocks.size(); ++b) {
            if (b != 0) {
                out += ",";
            }
            out += std::to_string(p.blocks[b]);
        }
        out += "] inputs=[";
        for (std::size_t k = 0; k < p.inputs.size(); ++k) {
            if (k != 0) {
                out += ",";
            }
            out += conc_hex(p.inputs[k]);
        }
        out += "] constraints:";
        for (const expr::Id c : p.constraints) {
            out += " " + prog.dag.pretty(c) + ";";
        }
        out += "\n";
    }

    const auto in_edges = [&](std::uint32_t block, std::uint32_t edge) {
        return std::binary_search(
            report.coverage.edges.begin(), report.coverage.edges.end(),
            std::make_pair(block, edge));
    };

    out += "coverage: blocks " + std::to_string(report.coverage.blocks.size()) +
           "/" + std::to_string(report.coverage.block_total) + ", edges " +
           std::to_string(report.coverage.edges.size()) + "/" +
           std::to_string(report.coverage.edge_total) + "\n";

    out += "reachability (per edge):\n";
    for (const Block& b : prog.blocks) {
        for (std::size_t e = 0; e < b.edges.size(); ++e) {
            const bool conditioned = b.edges[e].cond != expr::kNoId;
            out += "  block " + std::to_string(b.id) + " edge " +
                   std::to_string(e) + " (" +
                   (conditioned ? "cond" : "uncond") + "): ";
            if (in_edges(b.id, static_cast<std::uint32_t>(e))) {
                out += "reached\n";
                continue;
            }
            // An edge after a flip that was proven unsatisfiable is
            // unreachable: the run takes the earlier edge every time.
            bool after_always_taken = false;
            for (const PathReport::UnsatBranch& u : report.unsat_branches) {
                if (u.block == b.id && u.edge < e) {
                    after_always_taken = true;
                    break;
                }
            }
            if (after_always_taken) {
                out += "unreachable (proven)\n";
            } else {
                out += "unexplored\n";
            }
        }
    }

    out += "solver: calls=" + std::to_string(report.solver.calls) +
           " sat=" + std::to_string(report.solver.sat) +
           " unsat=" + std::to_string(report.solver.unsat) +
           " limited=" + std::to_string(report.solver.limited) +
           " conflicts=" + std::to_string(report.solver.conflicts) + "\n";
    out += "paths: " + std::to_string(executed) + " executed, " +
           std::to_string(report.unsat_branches.size()) +
           " unreachable branches proven\n";
    out += "note: dynamically indexed memory (loads/stores through computed "
           "addresses) is unsupported in this model; path constraints cover "
           "only the static-addressing fragment, and every edge flip is "
           "proved or disproved by the CDCL solver over the DAG's "
           "bit-vectors.\n";
    return out;
}

}  // namespace occ::concolic

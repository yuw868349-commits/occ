// Concolic path exploration over the program model.
//
// A concolic execution runs the program concretely while *collecting* the
// conditions that decided every branch, and uses those conditions to find
// inputs that take the program somewhere else. Concretely: a run yields a
// path -- the visited blocks and the decisions taken -- and each decision
// is a 1-bit expression whose truth value the run observed. Flipping a
// decision means asking the SAT layer (`bb::solve_constraints`, which
// bit-blasts the DAG into CNF and runs CDCL) for an input that satisfies
// the prefix of decisions up to that point with the flipped decision
// negated. A satisfying model is concrete input for a new run; an
// unsatisfiable flip proves that branch unreachable under that prefix and
// is reported as such.
//
// The search is a bounded DFS over the decision tree: each path's flip
// candidates are pushed in order and popped last-first, so deeper
// decisions are tried before shallower ones. The bounds are the honest
// part of the exploration -- a decision tree is exponential in general,
// and a loop whose exit depends on an unconstrained input makes even one
// run non-terminating:
//
//   kMaxPaths       64   distinct executed paths before exploration stops.
//                        The 8/16-bit programs this module targets have at
//                        most a few dozen reachable paths; 64 covers them
//                        and bounds worst-case breadth.
//   kMaxDepth       32   a flip whose prefix already covers 32 decisions is
//                        not pushed. Deeper paths that a shallower flip
//                        still reaches are recorded; only their own flips
//                        are skipped. Prevents exponential deepening on
//                        loop-heavy programs.
//   kMaxSolverCalls 256  one per flip. Each call solves a CNF over 64-bit
//                        inputs at most -- small and fast -- but the cap
//                        bounds total wall time regardless of path count.
//   kMaxRunSteps    4096 per run (program.h). A loop on an unconstrained
//                        input cannot be followed forever.
//
// Two redundancies are suppressed so the budget buys new information:
// a candidate input vector already run is skipped, and a candidate path
// (same visited-block sequence) already recorded is not re-recorded. The
// report still accounts for every solver call, so the budget's spending
// is visible.
//
// The flip rule deserves spelling out, because it is the heart of the
// driver. At a decision the run chose edge `chosen` because every earlier
// edge was false and `chosen`'s condition was true (an unconditional edge
// is always chosen). To force the run to take conditioned edge k instead,
// assert that every conditioned edge before k is false -- that includes
// `chosen` when k lies after it -- and assert k's own condition true, or,
// when k is the chosen edge itself, assert its condition false. Edges
// after k are unconstrained: the run stops at the first true edge. An
// edge is flippable only when no unconditional edge precedes it, since an
// unconditional edge is always taken first and no constraint can change
// that; such edges are not offered as flip targets. The run's own path
// constraints are recorded the same way: every earlier conditioned edge
// negated, the chosen edge asserted.
//
// Reports (`report_text`) render each path with its inputs, block
// sequence, constraints and status, then the coverage counts and the
// per-edge reachability summary (reached / proven unreachable /
// unexplored). The unsupported corners of the model -- dynamically
// indexed memory -- are stated in the report as well, so a reader never
// mistakes a model boundary for an analysis result.

#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "occ/concolic/program.h"
#include "occ/devirt/bitblast.h"

namespace occ::concolic {

namespace expr = occ::devirt::expr;
namespace bb = occ::devirt::bb;

// Exploration budgets; see the file comment for the rationale.
inline constexpr std::size_t kMaxPaths = 64;
inline constexpr std::size_t kMaxDepth = 32;
inline constexpr std::uint64_t kMaxSolverCalls = 256;

struct Budget {
    std::size_t max_paths = kMaxPaths;
    std::size_t max_depth = kMaxDepth;
    std::uint64_t max_solver_calls = kMaxSolverCalls;
    std::size_t max_run_steps = kMaxRunSteps;
};

struct PathReport {
    struct Path {
        enum class Status : std::uint8_t {
            // The run reached a terminal block: the program halted on
            // this input. (The design brief's "Reached" -- a run that
            // completes -- is exactly this state in this model.)
            Halt,
            // The run exceeded its step budget; `blocks` is a real prefix.
            Pruned,
            // The run stopped because every edge condition was false and
            // no edge was taken.
            NoEdge,
            // A synthetic entry for a flip the solver proved unsatisfiable:
            // `constraints` is the attempted set, `blocks` is empty.
            UnsatNegation,
        };
        Status status = Status::Halt;
        std::vector<std::uint64_t> inputs;    // the run's concrete inputs
        std::vector<std::uint32_t> blocks;    // visited block ids
        std::vector<expr::Id> constraints;    // asserted-true 1-bit exprs
        std::size_t depth = 0;                // blocks visited (0 for UnsatNegation)
    };

    // An unsatisfiable flip: forcing `edge` of `block` under `constraints`
    // has no satisfying input, so that branch is unreachable from that
    // prefix. The same (block, edge) may appear with different prefixes.
    struct UnsatBranch {
        std::uint32_t block = 0;
        std::uint32_t edge = 0;
        std::vector<expr::Id> constraints;
    };

    struct Coverage {
        std::vector<std::uint32_t> blocks;  // reached block ids, ascending
        // reached (block, edge) pairs, ascending
        std::vector<std::pair<std::uint32_t, std::uint32_t>> edges;
        std::size_t block_total = 0;
        std::size_t edge_total = 0;
    };

    struct SolverStats {
        std::uint64_t calls = 0;        // solve_constraints invocations
        std::uint64_t sat = 0;          // calls answered with a model
        std::uint64_t unsat = 0;        // calls proved unsatisfiable
        std::uint64_t limited = 0;      // calls answered "unproven" (budget)
        std::uint64_t conflicts = 0;    // CDCL conflicts across all calls
    };

    Budget budget;
    std::vector<Path> paths;
    std::vector<UnsatBranch> unsat_branches;
    Coverage coverage;
    SolverStats solver;
    std::string error;  // non-empty when exploration could not run
};

// Explores the program's paths from `initial_inputs` under `budget`.
// `initial_inputs` must have exactly `prog.num_inputs()` entries; any
// other length is an error (reported in `report.error`). The DAG grows
// during exploration (negated conditions are new nodes), hence the
// non-const program reference.
[[nodiscard]] PathReport concolic_explore(
    Program& prog, const std::vector<std::uint64_t>& initial_inputs,
    const Budget& budget = {});

// A human-readable rendering of the path report: each path's inputs,
// block sequence, constraints and status; the coverage counts; the
// per-edge reachability summary; the solver statistics; and the model
// limitations that bound the claims.
[[nodiscard]] std::string report_text(const Program& prog,
                                      const PathReport& report);

}  // namespace occ::concolic

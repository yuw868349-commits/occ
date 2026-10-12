// The CDCL SAT solver the de-virtualizer is built on.
//
// Everything below the report layer reduces to a satisfiability question.
// "Are these two handler expressions equal on every input?" is a miter:
// encode both, assert their outputs differ, and ask whether that is
// satisfiable. "Which input reaches this virtual branch?" is the same
// question with the branch's path constraint in place. "Is the rebuilt
// code equivalent to the virtual stream?" is the miter again, one
// function at a time. The de-virtualizer therefore needs a real solver,
// not a truth-table evaluator: the inputs are 64-bit, and 2^64 is not a
// table.
//
// This is a full production CDCL engine, MiniSat's architecture complete:
//
//   - Two watched literals per clause, with lazy blocker literals on the
//     watch lists (the MiniSat 2.2 refinement).
//   - First-UIP conflict analysis with learning and non-chronological
//     backjumping.
//   - Recursive clause minimization (the `ccmin` pass): a learned clause
//     literal whose reason's literals are all already covered is removed.
//     This is where most of the pruning comes from on the formulas this
//     project generates, because handler expressions learn very wide
//     clauses and every removed literal is a faster propagation.
//   - VSIDS with a binary heap, activity decay (0.95) and rescaling at
//     1e100 -- both the decay and the rescale are load-bearing at scale:
//     without the decay the search does not shift toward the conflict
//     region, without the rescale the doubles saturate and every
//     variable ties.
//   - Phase saving: the last polarity each variable held is the polarity
//     the next decision tries first.
//   - Luby restarts with the standard unit run: the restart sequence is
//     1,1,2,1,1,2,4,... times a base interval, which is the sequence
//     that is optimal for the universal restart strategy.
//   - Literal block distance (LBD) on every learned clause, and a clause
//     database reduction policy driven by it: clauses are sorted by
//     (LBD, activity), the half that is worst is deleted, binary clauses
//     and clauses with LBD <= 2 are never deleted. Learnt clause
//     activities are bumped on use, as in MiniSat.
//   - DRUP proof logging, additions and deletions both: a deletion is a
//     `d` line. A trace with deletions is still independently checkable
//     (the checker maintains a live clause set), and it is the form the
//     certificate layer wants, because the certificate then accounts for
//     everything the solver did, not just what it learned.
//
// Variables are 0-based at the API; literals are `2 * var + sign` with
// sign 1 meaning negated. Internal literals are the same encoding, so
// watch lists and the heap index off them directly.

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace occ::devirt::sat {

using Var = std::uint32_t;
using Lit = std::int32_t;

// The "no literal" sentinel. Literals are non-negative, so -1 cannot
// collide.
inline constexpr Lit kUndef = -1;

[[nodiscard]] constexpr Lit mk_lit(Var v, bool negated) {
    return static_cast<Lit>((v << 1) | (negated ? 1u : 0u));
}
[[nodiscard]] constexpr Var lit_var(Lit l) {
    return static_cast<Var>(static_cast<std::uint32_t>(l) >> 1);
}
[[nodiscard]] constexpr bool lit_negated(Lit l) { return (l & 1) != 0; }
[[nodiscard]] constexpr Lit lit_negate(Lit l) { return l ^ 1; }

// A binary heap ordered by variable activity, with an insertion index so
// activity bumps can sift in place. This is MiniSat's `VarOrderHeap`
// without the polymorphic order: one comparator, inline. The activity
// array is passed in rather than stored so the heap never holds a stale
// view of it.
class VarHeap {
public:
    void grow(Var v);
    void insert(Var v, const std::vector<std::uint64_t>& activity);
    [[nodiscard]] bool empty() const noexcept { return heap_.empty(); }
    [[nodiscard]] Var pop(const std::vector<std::uint64_t>& activity);
    void bump(Var v, const std::vector<std::uint64_t>& activity);
    void rebuild(const std::vector<std::uint64_t>& activity);
    [[nodiscard]] bool contains(Var v) const noexcept {
        return v < pos_.size() && pos_[v] >= 0;
    }

private:
    void sift_up(std::size_t i, const std::vector<std::uint64_t>& activity);
    void sift_down(std::size_t i, const std::vector<std::uint64_t>& activity);

    std::vector<Var> heap_;
    std::vector<std::int32_t> pos_;
};

class Solver {
public:
    enum class Status : std::uint8_t { Sat, Unsat };

    Solver();

    // -- construction --------------------------------------------------

    [[nodiscard]] Var new_var();
    [[nodiscard]] Var num_vars() const noexcept {
        return static_cast<Var>(assigns_.size());
    }

    // Adds a clause. Tautologies are dropped, duplicates folded, unit and
    // empty clauses take effect immediately. Call before `solve`; adding
    // after a solve is supported but resets the trail.
    void add_clause(std::span<const Lit> clause);

    // -- solving -------------------------------------------------------

    // Solves under the assumptions (may be empty). Learned clauses are
    // retained between calls. On Unsat with non-empty assumptions, the
    // contradictory subset is recorded.
    Status solve(std::span<const Lit> assumptions = {});

    // The model's value for a variable; only meaningful after Sat.
    [[nodiscard]] bool value(Var v) const noexcept {
        return assigns_[v] > 0;
    }

    // Whether the variable has a value in the current assignment. A Sat
    // answer leaves every variable assigned -- `pick_branch_lit` only
    // reports exhaustion once no unassigned variable remains -- so this
    // exists to state that invariant where a caller depends on it (the
    // model-completeness check in the tests, and the certificate layer
    // reading a model as a total function).
    [[nodiscard]] bool assigned(Var v) const noexcept {
        return assigns_[v] != 0;
    }

    // The live clause set: every non-deleted clause, in literal form.
    // This is what the certificate layer exports alongside a DRUP trace,
    // because a trace is only checkable against the formula it refutes.
    [[nodiscard]] std::vector<std::vector<Lit>> clause_list() const;

    // The failed assumptions of the last Unsat call, as variable numbers.
    [[nodiscard]] const std::vector<Var>& failed() const noexcept {
        return failed_;
    }

    // -- diagnostics ---------------------------------------------------

    [[nodiscard]] std::uint64_t conflicts() const noexcept {
        return conflicts_;
    }
    [[nodiscard]] std::uint64_t propagations() const noexcept {
        return propagations_;
    }
    [[nodiscard]] std::uint64_t decisions() const noexcept {
        return decisions_;
    }
    [[nodiscard]] std::uint64_t learnt_count() const noexcept {
        return learnt_count_;
    }
    [[nodiscard]] std::uint64_t deleted_count() const noexcept {
        return deleted_count_;
    }

    // -- certificates --------------------------------------------------

    // Records the DRUP proof of unsatisfiability. The pointer must
    // outlive the solver's use. Lines are appended as they are derived:
    // additions as literal lists, deletions as `d` lines, and a final `0`
    // line when the empty clause is learned.
    void enable_proof(std::vector<std::string>* out) noexcept {
        proof_ = out;
    }

private:
    struct Clause {
        std::uint32_t start = 0;  // index into arena_
        std::uint32_t size = 0;
        bool learnt = false;
        bool deleted = false;
        // LBD is only carried for learned clauses; 0 means "not set".
        std::uint32_t lbd = 0;
        // Learned-clause activity, bumped when the clause is used in
        // conflict analysis. Original clauses do not carry one.
        double activity = 0.0;
    };

    [[nodiscard]] Lit* clause_lits(std::uint32_t ci) noexcept {
        return arena_.data() + clauses_[ci].start;
    }
    [[nodiscard]] const Lit* clause_lits(std::uint32_t ci) const noexcept {
        return arena_.data() + clauses_[ci].start;
    }

    // A watch-list entry: the clause plus a lazily maintained blocker --
    // a literal from the clause that was true the last time the entry was
    // inspected. A satisfied blocker short-circuits the clause visit,
    // which is most of the propagation cost saved (MiniSat 2.2).
    struct Watcher {
        std::uint32_t clause = 0;
        Lit blocker = kUndef;
    };

    // -- propagation and analysis --------------------------------------

    [[nodiscard]] std::uint32_t propagate();
    void analyze(std::uint32_t confl, std::vector<Lit>& out_learnt,
                 std::int32_t& out_backjump);
    // The final-conflict analysis for a failed assumption: walks the
    // trail from the contradictory literal back to the assumptions and
    // fills `failed_` with the involved ones.
    void analyze_final(Lit p);
    // The recursive minimization pass; answers whether `lit` (at the
    // given abstraction depth) is redundant in the clause being
    // minimized.
    [[nodiscard]] bool lit_redundant(Lit lit, std::uint32_t abstract_levels);
    void minimize_learnt(std::vector<Lit>& learnt);
    void enqueue(Lit l, std::uint32_t reason);
    void new_decision_level();
    void backtrack(std::int32_t level);
    [[nodiscard]] Lit pick_branch_lit();
    [[nodiscard]] std::int8_t value_lit(Lit l) const noexcept {
        const std::int8_t a = assigns_[lit_var(l)];
        if (a == 0) {
            return 0;
        }
        return lit_negated(l) ? static_cast<std::int8_t>(-a) : a;
    }
    [[nodiscard]] static std::uint32_t abstract_level(
        std::int32_t level) noexcept {
        return std::uint32_t{1} << static_cast<std::uint32_t>(level & 31);
    }

    // -- database management -------------------------------------------

    [[nodiscard]] std::uint32_t attach_clause(const std::vector<Lit>& lits,
                                              bool learnt);
    [[nodiscard]] std::uint32_t compute_lbd(const std::vector<Lit>& lits);
    void bump_clause_activity(std::uint32_t ci);
    void decay_clause_activity();
    void reduce_db();
    // Removes one watch-list entry; used by reduce_db before a clause is
    // deleted, so no later propagate walks a dead clause.
    void detach_watch(Lit watch_lit, std::uint32_t ci);

    // -- restarts ------------------------------------------------------

    [[nodiscard]] std::uint32_t luby(std::uint32_t i) const noexcept;
    void bump_restart_interval() noexcept;

    // -- proof ---------------------------------------------------------

    void proof_add(const std::vector<Lit>& lits);
    void proof_delete(const Lit* lits, std::uint32_t size);
    void proof_empty() ;
    [[nodiscard]] std::string proof_clause_line(const Lit* lits,
                                                std::uint32_t size) const;

    std::vector<Clause> clauses_;
    // Unit and empty clauses, which constrain the search without living
    // in the arena: `clause_list` appends them so the exported formula is
    // the one the solver actually used -- a unit clause that only ever
    // reached `enqueue` is still an input clause of the formula a DRUP
    // trace is checked against.
    std::vector<std::vector<Lit>> input_extra_;
    std::vector<Lit> arena_;
    std::vector<std::vector<Watcher>> watches_;  // indexed by internal lit
    std::vector<std::int8_t> assigns_;                 // 0 / 1 / -1
    std::vector<std::int32_t> level_;
    std::vector<std::uint32_t> reason_;  // clause index + 1; 0 = decision
    std::vector<std::uint64_t> activity_;
    std::vector<std::int8_t> phase_;
    std::vector<Lit> trail_;
    std::vector<std::uint32_t> trail_lim_;
    std::vector<std::uint8_t> seen_;
    // Working state for the recursive minimization pass. Copied from the
    // original learnt clause and extended by every literal the pass
    // visits, so the final sweep clears every `seen` bit exactly once.
    std::vector<Lit> analyze_stack_;
    std::vector<Lit> analyze_toclear_;
    VarHeap order_heap_;

    std::uint32_t qhead_ = 0;
    std::int32_t decision_level_ = 0;
    bool ok_ = true;

    // Integer VSIDS scoring: activity is a monotone counter and the bump
    // size grows by 5% per conflict. Integer scores rescale exactly (a
    // right shift) where doubles drift and saturate; the ordering they
    // induce is the one that matters and it is preserved by the shift.
    std::uint64_t var_inc_ = 1;
    double clause_inc_ = 1.0;    // learned-clause bump size
    double clause_decay_ = 0.999;

    std::uint64_t conflicts_ = 0;
    std::uint64_t propagations_ = 0;
    std::uint64_t decisions_ = 0;
    std::uint64_t learnt_count_ = 0;
    std::uint64_t deleted_count_ = 0;
    std::uint64_t conflicts_at_restart_ = 0;
    std::uint32_t restart_index_ = 0;
    std::uint32_t restart_base_ = 100;
    // Clause deletion skips the first several restarts (MiniSat keeps all
    // learned clauses early, when every one of them is still teaching).
    std::uint32_t reduce_skip_ = 3;

    std::vector<Var> failed_;
    std::vector<std::string>* proof_ = nullptr;
    bool proof_done_ = false;
};

}  // namespace occ::devirt::sat
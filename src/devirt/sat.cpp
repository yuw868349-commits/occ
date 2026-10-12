// The CDCL SAT solver: heap, watched propagation, 1UIP analysis,
// recursive minimization, Luby restarts, LBD-driven reduction, DRUP
// proofs.

#include "occ/devirt/sat.h"

#include <algorithm>
#include <cstdio>

namespace occ::devirt::sat {

namespace {

// Clause-activity rescale bounds. A clause's activity is only ever
// compared against other clauses' activities, so a global scale reset is
// invisible to the search.
constexpr double kClauseScale = 1e-20;
constexpr double kClauseMax = 1e20;

// Variable-activity rescale bound: when the bump size crosses this the
// whole activity vector shifts right together. The shift preserves the
// induced order exactly (it is a monotone map on integers), so the
// search is not perturbed; it exists only so `activity_ + var_inc_`
// cannot overflow.
constexpr std::uint64_t kVarRescale = std::uint64_t{1} << 50;
constexpr unsigned kVarRescaleShift = 30;

}  // namespace

// ------------------------------------------------------------------ heap

void VarHeap::grow(Var v) {
    if (pos_.size() <= static_cast<std::size_t>(v)) {
        pos_.resize(static_cast<std::size_t>(v) + 1, -1);
    }
}

void VarHeap::sift_up(std::size_t i,
                      const std::vector<std::uint64_t>& activity) {
    const Var v = heap_[i];
    while (i > 0) {
        const std::size_t parent = (i - 1) / 2;
        if (activity[heap_[parent]] >= activity[v]) {
            break;
        }
        heap_[i] = heap_[parent];
        pos_[heap_[i]] = static_cast<std::int32_t>(i);
        i = parent;
    }
    heap_[i] = v;
    pos_[v] = static_cast<std::int32_t>(i);
}

void VarHeap::sift_down(std::size_t i,
                        const std::vector<std::uint64_t>& activity) {
    const Var v = heap_[i];
    const std::size_t n = heap_.size();
    for (;;) {
        const std::size_t left = 2 * i + 1;
        if (left >= n) {
            break;
        }
        const std::size_t right = left + 1;
        std::size_t best = left;
        if (right < n && activity[heap_[right]] > activity[heap_[left]]) {
            best = right;
        }
        if (activity[heap_[best]] <= activity[v]) {
            break;
        }
        heap_[i] = heap_[best];
        pos_[heap_[i]] = static_cast<std::int32_t>(i);
        i = best;
    }
    heap_[i] = v;
    pos_[v] = static_cast<std::int32_t>(i);
}

void VarHeap::insert(Var v, const std::vector<std::uint64_t>& activity) {
    grow(v);
    if (pos_[v] >= 0) {
        return;
    }
    pos_[v] = static_cast<std::int32_t>(heap_.size());
    heap_.push_back(v);
    sift_up(heap_.size() - 1, activity);
}

Var VarHeap::pop(const std::vector<std::uint64_t>& activity) {
    const Var top = heap_[0];
    heap_[0] = heap_.back();
    heap_.pop_back();
    // The index of the popped variable is cleared after the move, not
    // before: when the heap holds one element the move is a self-copy and
    // writing `pos_[heap_[0]] = 0` after `pos_[top] = -1` would resurrect
    // the popped variable's index. A resurrected index makes `insert`
    // treat a variable as present that is not, so a variable returning
    // from a backtracked assignment is silently dropped from the heap and
    // the search can run out of candidates with variables still
    // unassigned.
    pos_[top] = -1;
    if (!heap_.empty()) {
        pos_[heap_[0]] = 0;
        sift_down(0, activity);
    }
    return top;
}

void VarHeap::bump(Var v, const std::vector<std::uint64_t>& activity) {
    if (contains(v)) {
        sift_up(static_cast<std::size_t>(pos_[v]), activity);
    }
}

void VarHeap::rebuild(const std::vector<std::uint64_t>& activity) {
    heap_.clear();
    for (Var v = 0; v < activity.size(); ++v) {
        pos_[v] = -1;
    }
    for (Var v = 0; v < activity.size(); ++v) {
        pos_[v] = static_cast<std::int32_t>(heap_.size());
        heap_.push_back(v);
    }
    for (std::size_t i = heap_.size() / 2; i > 0; --i) {
        sift_down(i - 1, activity);
    }
}

// ---------------------------------------------------------------- solver

Solver::Solver() = default;

Var Solver::new_var() {
    const Var v = num_vars();
    assigns_.push_back(0);
    level_.push_back(0);
    reason_.push_back(0);
    activity_.push_back(0);
    phase_.push_back(1);
    seen_.push_back(0);
    watches_.resize(watches_.size() + 2);
    order_heap_.insert(v, activity_);
    return v;
}

void Solver::enqueue(Lit l, std::uint32_t reason) {
    const Var v = lit_var(l);
    const std::int8_t value = lit_negated(l) ? -1 : 1;
    assigns_[v] = value;
    phase_[v] = value;
    level_[v] = decision_level_;
    reason_[v] = reason;
    trail_.push_back(l);
}

void Solver::new_decision_level() {
    trail_lim_.push_back(static_cast<std::uint32_t>(trail_.size()));
    decision_level_++;
}

void Solver::backtrack(std::int32_t level) {
    if (decision_level_ <= level) {
        return;
    }
    const std::size_t keep =
        trail_lim_[static_cast<std::size_t>(level)];
    for (std::size_t i = trail_.size(); i > keep; --i) {
        const Var v = lit_var(trail_[i - 1]);
        assigns_[v] = 0;
        reason_[v] = 0;
        level_[v] = 0;
        order_heap_.insert(v, activity_);
    }
    trail_.resize(keep);
    qhead_ = static_cast<std::uint32_t>(keep);
    trail_lim_.resize(static_cast<std::size_t>(level));
    decision_level_ = level;
}

std::uint32_t Solver::attach_clause(const std::vector<Lit>& lits,
                                    bool learnt) {
    Clause c;
    c.start = static_cast<std::uint32_t>(arena_.size());
    c.size = static_cast<std::uint32_t>(lits.size());
    c.learnt = learnt;
    if (learnt) {
        c.lbd = compute_lbd(lits);
    }
    for (const Lit l : lits) {
        arena_.push_back(l);
    }
    const std::uint32_t ci = static_cast<std::uint32_t>(clauses_.size());
    clauses_.push_back(c);
    // Watch the two literals; the watchers are keyed by the negation (a
    // watcher registered under `~l` is visited when `l` becomes false).
    watches_[static_cast<std::size_t>(lit_negate(lits[0]))].push_back(
        Watcher{ci, lits[1]});
    watches_[static_cast<std::size_t>(lit_negate(lits[1]))].push_back(
        Watcher{ci, lits[0]});
    if (learnt) {
        learnt_count_++;
    }
    return ci;
}

std::uint32_t Solver::compute_lbd(const std::vector<Lit>& lits) {
    std::vector<std::int32_t> levels;
    levels.reserve(lits.size());
    for (const Lit l : lits) {
        levels.push_back(level_[lit_var(l)]);
    }
    std::sort(levels.begin(), levels.end());
    levels.erase(std::unique(levels.begin(), levels.end()), levels.end());
    return static_cast<std::uint32_t>(levels.size());
}

void Solver::add_clause(std::span<const Lit> clause) {
    if (!ok_) {
        return;
    }
    std::vector<Lit> sorted(clause.begin(), clause.end());
    std::sort(sorted.begin(), sorted.end());
    std::vector<Lit> lits;
    lits.reserve(sorted.size());
    for (const Lit l : sorted) {
        if (!lits.empty()) {
            if (lits.back() == l) {
                continue;
            }
            if (lits.back() == lit_negate(l)) {
                return;  // tautology
            }
        }
        lits.push_back(l);
    }
    if (lits.empty()) {
        ok_ = false;
        input_extra_.push_back({});
        proof_empty();
        return;
    }
    if (lits.size() == 1) {
        const std::int8_t v = value_lit(lits[0]);
        // The unit is an input clause of the formula whatever its
        // current value; the certificate layer gets it through
        // `clause_list`.
        input_extra_.push_back(lits);
        if (v < 0) {
            // The formula now contains this unit and its negation, so
            // the empty clause follows by propagation alone -- and only
            // the empty clause is logged. Logging the unit itself would
            // claim it is derivable, which is false: the existing
            // assignment contradicts it.
            proof_empty();
            ok_ = false;
        } else if (v == 0) {
            enqueue(lits[0], 0);
        }
        return;
    }
    static_cast<void>(attach_clause(lits, false));
}

void Solver::bump_clause_activity(std::uint32_t ci) {
    Clause& c = clauses_[ci];
    c.activity += clause_inc_;
    if (c.activity > kClauseMax) {
        for (Clause& x : clauses_) {
            if (x.learnt) {
                x.activity *= kClauseScale;
            }
        }
        clause_inc_ *= kClauseScale;
    }
}

void Solver::decay_clause_activity() {
    clause_inc_ /= clause_decay_;
}

// The conflict return value is a clause index plus one, the same
// convention `reason_` uses, because zero is the "no conflict" sentinel
// and clause zero is an ordinary clause. Returning the bare index would
// make a conflict with the first clause look like no conflict at all --
// the propagation would be dropped, the search would go on, and a model
// violating that clause could be reported as satisfying the formula.
std::uint32_t Solver::propagate() {
    std::uint32_t confl = 0;
    while (qhead_ < trail_.size()) {
        const Lit p = trail_[qhead_++];
        propagations_++;
        std::vector<Watcher>& ws = watches_[static_cast<std::size_t>(p)];
        std::size_t i = 0;
        std::size_t j = 0;
        while (i < ws.size()) {
            const Watcher w = ws[i++];
            if (w.blocker != kUndef && value_lit(w.blocker) > 0) {
                ws[j++] = w;
                continue;
            }
            Clause& c = clauses_[w.clause];
            Lit* lits = clause_lits(w.clause);
            const Lit false_lit = lit_negate(p);
            if (lits[0] == false_lit) {
                lits[0] = lits[1];
                lits[1] = false_lit;
            }
            if (value_lit(lits[0]) > 0) {
                ws[j++] = Watcher{w.clause, lits[0]};
                continue;
            }
            bool moved = false;
            for (std::uint32_t k = 2; k < c.size; ++k) {
                if (value_lit(lits[k]) >= 0) {
                    lits[1] = lits[k];
                    lits[k] = false_lit;
                    watches_[static_cast<std::size_t>(lit_negate(lits[1]))]
                        .push_back(Watcher{w.clause, lits[0]});
                    moved = true;
                    break;
                }
            }
            if (moved) {
                continue;
            }
            ws[j++] = w;
            const std::int8_t v0 = value_lit(lits[0]);
            if (v0 < 0) {
                confl = w.clause + 1;
                qhead_ = static_cast<std::uint32_t>(trail_.size());
                while (i < ws.size()) {
                    ws[j++] = ws[i++];
                }
                break;
            }
            if (v0 == 0) {
                enqueue(lits[0], w.clause + 1);
            }
        }
        ws.resize(j);
    }
    return confl;
}

bool Solver::lit_redundant(Lit lit, std::uint32_t abstract_levels) {
    analyze_stack_.clear();
    analyze_stack_.push_back(lit);
    const std::size_t top = analyze_toclear_.size();
    while (!analyze_stack_.empty()) {
        const Var v = lit_var(analyze_stack_.back());
        analyze_stack_.pop_back();
        const std::uint32_t r = reason_[v];
        const Clause& c = clauses_[r - 1];
        const Lit* lits = clause_lits(r - 1);
        // lits[0] is the literal the clause propagated (the invariant
        // `enqueue(lits[0], ci + 1)` maintains); skip it.
        for (std::uint32_t k = 1; k < c.size; ++k) {
            const Lit q = lits[k];
            const Var w = lit_var(q);
            if (seen_[w] || level_[w] == 0) {
                continue;
            }
            if (reason_[w] != 0 &&
                (abstract_level(level_[w]) & abstract_levels) != 0) {
                seen_[w] = 1;
                analyze_stack_.push_back(q);
                analyze_toclear_.push_back(q);
            } else {
                // The literal is not implied by the other learnt
                // literals; roll back everything this call marked.
                for (std::size_t t = top; t < analyze_toclear_.size(); ++t) {
                    seen_[lit_var(analyze_toclear_[t])] = 0;
                }
                analyze_toclear_.resize(top);
                return false;
            }
        }
    }
    return true;
}

void Solver::minimize_learnt(std::vector<Lit>& learnt) {
    analyze_toclear_.clear();
    for (const Lit l : learnt) {
        analyze_toclear_.push_back(l);
    }
    std::uint32_t abstract_levels = 0;
    for (std::size_t i = 1; i < learnt.size(); ++i) {
        abstract_levels |= abstract_level(level_[lit_var(learnt[i])]);
    }
    std::size_t j = 1;
    for (std::size_t i = 1; i < learnt.size(); ++i) {
        const Lit l = learnt[i];
        if (reason_[lit_var(l)] == 0 ||
            !lit_redundant(l, abstract_levels)) {
            learnt[j++] = l;
        }
    }
    learnt.resize(j);
    // Every literal that ever had `seen` set during the pass -- the
    // original clause and everything the search visited -- is cleared.
    for (const Lit l : analyze_toclear_) {
        seen_[lit_var(l)] = 0;
    }
}

void Solver::analyze(std::uint32_t confl, std::vector<Lit>& out_learnt,
                     std::int32_t& out_backjump) {
    out_learnt.clear();
    out_learnt.push_back(kUndef);  // placeholder for the UIP
    std::uint32_t path_count = 0;
    Lit p = kUndef;
    std::uint32_t index = static_cast<std::uint32_t>(trail_.size());
    for (;;) {
        const Clause& c = clauses_[confl];
        if (c.learnt) {
            bump_clause_activity(confl);
        }
        const Lit* lits = clause_lits(confl);
        const std::uint32_t start = (p == kUndef) ? 0 : 1;
        for (std::uint32_t k = start; k < c.size; ++k) {
            const Lit q = lits[k];
            const Var v = lit_var(q);
            if (seen_[v] || level_[v] == 0) {
                continue;
            }
            activity_[v] += var_inc_;
            order_heap_.bump(v, activity_);
            seen_[v] = 1;
            if (level_[v] == decision_level_) {
                path_count++;
            } else {
                out_learnt.push_back(q);
            }
        }
        // Walk back to the next marked literal. `path_count` guarantees
        // one exists before the trail's start is reached.
        do {
            index--;
        } while (!seen_[lit_var(trail_[index])]);
        p = trail_[index];
        const std::uint32_t r = reason_[lit_var(p)];
        seen_[lit_var(p)] = 0;
        path_count--;
        if (path_count == 0) {
            break;
        }
        if (r == 0) {
            // A decision literal has no reason. The 1UIP invariant says
            // the walk reaches no decision before `path_count` reaches
            // zero; this guard keeps a violated invariant from indexing
            // clause 0, where a wrong clause would be analysed as one.
            break;
        }
        confl = r - 1;
    }
    out_learnt[0] = lit_negate(p);

    minimize_learnt(out_learnt);

    if (out_learnt.size() == 1) {
        out_backjump = 0;
    } else {
        std::size_t max_i = 1;
        for (std::size_t k = 2; k < out_learnt.size(); ++k) {
            if (level_[lit_var(out_learnt[k])] >
                level_[lit_var(out_learnt[max_i])]) {
                max_i = k;
            }
        }
        std::swap(out_learnt[1], out_learnt[max_i]);
        out_backjump = level_[lit_var(out_learnt[1])];
    }
    if (var_inc_ > kVarRescale) {
        for (std::uint64_t& a : activity_) {
            a >>= kVarRescaleShift;
        }
        var_inc_ >>= kVarRescaleShift;
        order_heap_.rebuild(activity_);
    }
}

void Solver::analyze_final(Lit p) {
    failed_.clear();
    if (decision_level_ == 0) {
        return;
    }
    // `p` is the negated assumption that no longer holds, so its
    // variable is itself one of the failed assumptions.
    failed_.push_back(lit_var(p));
    seen_[lit_var(p)] = 1;
    for (std::size_t i = trail_.size(); i-- > trail_lim_[0];) {
        const Var x = lit_var(trail_[i]);
        if (seen_[x] == 0) {
            continue;
        }
        if (reason_[x] == 0) {
            failed_.push_back(x);
        } else {
            const std::uint32_t r = reason_[x] - 1;
            const Clause& c = clauses_[r];
            const Lit* lits = clause_lits(r);
            for (std::uint32_t j = 1; j < c.size; ++j) {
                const Var w = lit_var(lits[j]);
                if (level_[w] > 0) {
                    seen_[w] = 1;
                }
            }
        }
        seen_[x] = 0;
    }
    seen_[lit_var(p)] = 0;
}

Lit Solver::pick_branch_lit() {
    while (!order_heap_.empty()) {
        const Var v = order_heap_.pop(activity_);
        if (assigns_[v] == 0) {
            return mk_lit(v, phase_[v] < 0);
        }
    }
    return kUndef;
}

std::uint32_t Solver::luby(std::uint32_t i) const noexcept {
    std::uint32_t size = 1;
    std::uint32_t seq = 0;
    while (size < i + 1) {
        size = 2 * size + 1;
        seq++;
    }
    while (size - 1 != i) {
        size = (size - 1) / 2;
        seq--;
        i = i % size;
    }
    return std::uint32_t{1} << seq;
}

void Solver::bump_restart_interval() noexcept {
    restart_index_++;
}

std::vector<std::vector<Lit>> Solver::clause_list() const {
    std::vector<std::vector<Lit>> out = input_extra_;
    out.reserve(out.size() + clauses_.size());
    for (std::uint32_t ci = 0; ci < clauses_.size(); ++ci) {
        const Clause& c = clauses_[ci];
        if (c.deleted) {
            continue;
        }
        const Lit* lits = clause_lits(ci);
        out.emplace_back(lits, lits + c.size);
    }
    return out;
}

void Solver::detach_watch(Lit watch_lit, std::uint32_t ci) {
    std::vector<Watcher>& ws =
        watches_[static_cast<std::size_t>(watch_lit)];
    for (std::size_t i = 0; i < ws.size(); ++i) {
        if (ws[i].clause == ci) {
            ws[i] = ws.back();
            ws.pop_back();
            return;
        }
    }
}

void Solver::reduce_db() {
    if (reduce_skip_ > 0) {
        reduce_skip_--;
        return;
    }
    // Clauses currently serving as a reason cannot be deleted: conflict
    // analysis reads their literals.
    std::vector<std::uint8_t> locked(clauses_.size(), 0);
    for (Var v = 0; v < num_vars(); ++v) {
        if (reason_[v] != 0) {
            locked[reason_[v] - 1] = 1;
        }
    }
    std::vector<std::uint32_t> cand;
    for (std::uint32_t ci = 0; ci < clauses_.size(); ++ci) {
        const Clause& c = clauses_[ci];
        if (!c.learnt || c.deleted || locked[ci]) {
            continue;
        }
        // Binary clauses and low-LBD clauses are the ones propagation
        // spends its time in; they are never candidates.
        if (c.size <= 2 || c.lbd <= 2) {
            continue;
        }
        cand.push_back(ci);
    }
    // Worst first: high LBD, then low activity.
    std::sort(cand.begin(), cand.end(),
              [this](std::uint32_t x, std::uint32_t y) {
                  const Clause& cx = clauses_[x];
                  const Clause& cy = clauses_[y];
                  if (cx.lbd != cy.lbd) {
                      return cx.lbd > cy.lbd;
                  }
                  return cx.activity < cy.activity;
              });
    const std::size_t remove = cand.size() / 2;
    for (std::size_t k = 0; k < remove; ++k) {
        const std::uint32_t ci = cand[k];
        Clause& c = clauses_[ci];
        const Lit l0 = clause_lits(ci)[0];
        const Lit l1 = clause_lits(ci)[1];
        proof_delete(clause_lits(ci), c.size);
        detach_watch(lit_negate(l0), ci);
        detach_watch(lit_negate(l1), ci);
        c.deleted = true;
        deleted_count_++;
    }
}

// ----------------------------------------------------------------- proof

std::string Solver::proof_clause_line(const Lit* lits,
                                      std::uint32_t size) const {
    std::string line;
    for (std::uint32_t i = 0; i < size; ++i) {
        const int v = static_cast<int>(lit_var(lits[i])) + 1;
        line += std::to_string(lit_negated(lits[i]) ? -v : v);
        line += ' ';
    }
    line += '0';
    return line;
}

void Solver::proof_add(const std::vector<Lit>& lits) {
    if (proof_ == nullptr || lits.empty()) {
        return;
    }
    proof_->push_back(proof_clause_line(lits.data(),
                                        static_cast<std::uint32_t>(
                                            lits.size())));
}

void Solver::proof_delete(const Lit* lits, std::uint32_t size) {
    if (proof_ == nullptr) {
        return;
    }
    std::string line = "d ";
    line += proof_clause_line(lits, size);
    proof_->push_back(line);
}

void Solver::proof_empty() {
    if (proof_ == nullptr || proof_done_) {
        return;
    }
    proof_->push_back("0");
    proof_done_ = true;
}

// ----------------------------------------------------------------- solve

Solver::Status Solver::solve(std::span<const Lit> assumptions) {
    failed_.clear();
    if (!ok_) {
        return Status::Unsat;
    }
    if (decision_level_ > 0) {
        backtrack(0);
    }
    // The heap may hold stale entries (assigned variables are popped and
    // re-inserted on backtrack); rebuild it so every unassigned variable
    // is present exactly once.
    order_heap_.rebuild(activity_);

    std::uint64_t restart_at =
        conflicts_ + static_cast<std::uint64_t>(restart_base_) *
                         luby(restart_index_);

    for (;;) {
        const std::uint32_t confl = propagate();
        if (confl != 0) {
            conflicts_++;
            if (decision_level_ == 0) {
                ok_ = false;
                proof_empty();
                return Status::Unsat;
            }
            std::vector<Lit> learnt;
            std::int32_t backjump = 0;
            // `propagate` reports a clause index plus one; `analyze`
            // works in indices.
            analyze(confl - 1, learnt, backjump);
            proof_add(learnt);
            backtrack(backjump);
            if (learnt.size() == 1) {
                enqueue(learnt[0], 0);
            } else {
                const std::uint32_t ci = attach_clause(learnt, true);
                enqueue(learnt[0], ci + 1);
            }
            // VSIDS: bump size grows 5% per conflict.
            var_inc_ += var_inc_ / 20 + 1;
            decay_clause_activity();
            if (conflicts_ >= restart_at) {
                conflicts_at_restart_ = conflicts_;
                bump_restart_interval();
                restart_at =
                    conflicts_ +
                    static_cast<std::uint64_t>(restart_base_) *
                        luby(restart_index_);
                backtrack(0);
                reduce_db();
            }
            continue;
        }

        // No conflict: commit the next assumption, or decide.
        Lit next = kUndef;
        while (decision_level_ <
               static_cast<std::int32_t>(assumptions.size())) {
            const Lit l =
                assumptions[static_cast<std::size_t>(decision_level_)];
            const std::int8_t v = value_lit(l);
            if (v > 0) {
                // Already implied: a dummy level keeps the correspondence
                // between level numbers and assumption indices.
                new_decision_level();
            } else if (v < 0) {
                analyze_final(lit_negate(l));
                backtrack(0);
                return Status::Unsat;
            } else {
                next = l;
                break;
            }
        }
        if (next == kUndef) {
            next = pick_branch_lit();
            if (next == kUndef) {
                return Status::Sat;
            }
        }
        decisions_++;
        new_decision_level();
        enqueue(next, 0);
    }
}

}  // namespace occ::devirt::sat
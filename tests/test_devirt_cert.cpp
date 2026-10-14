// Certificate layer tests, plus the SAT-budget tests that share the
// standalone source set.
//
// The certificate half: a synthetic Report is checked for its counts and
// its rendering, and `cfg_certificate` is run over three scenarios --
// a complete CFG (every reachable handler proven, every edge inside the
// reachable set: `complete()` holds, every step is Proven), a CFG with a
// missing outcome (the handler is reported Unproven, never skipped, and
// `unverified()` names it), and a CFG with a dangling edge (flagged by
// the certificate instead of being trusted).
//
// The budget half: the solver's Interrupted state is exercised directly
// on a hand-built inconsistent core, and the bit-blaster's three entry
// points are run with tiny budgets. The fixed points of the contract:
// a budget-exhausted answer is `unproven` (with `equal`/`sat` false but
// meaningless), never a "different" or "unsat" verdict, and a default
// `Budget{}` behaves exactly as before -- the word-level layer answers
// and no cap is armed.

#include "occ/devirt/bitblast.h"
#include "occ/devirt/cert.h"
#include "occ/devirt/expr.h"
#include "occ/devirt/sat.h"

#include <cstdio>
#include <string>
#include <utility>
#include <vector>

using namespace occ::devirt;

namespace {

int failures = 0;
int checks = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

// -------------------------------------------------------- certificate

void test_report_counts_and_render() {
    cert::Report r;
    r.steps.push_back(cert::Step{
        "handler 0x1000 equals its reconstruction",
        cert::Step::Status::Proven, "drup trace (42 lines)", {0x1000}});
    r.steps.push_back(cert::Step{
        "handler 0x1010 equals its reconstruction",
        cert::Step::Status::Unproven, "proof budget exhausted", {0x1010}});
    r.steps.push_back(cert::Step{
        "handler 0x1020 equals its reconstruction",
        cert::Step::Status::Refuted, "counterexample: x = 7", {0x1020}});
    r.steps.push_back(cert::Step{
        "handler 0x1030 has a model",
        cert::Step::Status::Unmodeled, "model incomplete", {0x1030}});
    check(r.proven() == 1, "proven() counts the proven step");
    check(r.unproven() == 1, "unproven() counts the unproven step");
    check(r.refuted() == 1, "refuted() counts the refuted step");
    check(r.unmodeled() == 1, "unmodeled() counts the unmodeled step");
    const std::string text = r.render();
    check(text.find("proven: 1, unproven: 1, refuted: 1, unmodeled: 1") !=
              std::string::npos,
          "render() totals the statuses");
    check(text.find("0x1000") != std::string::npos &&
              text.find("counterexample: x = 7") != std::string::npos,
          "render() shows the claims and evidence");
}

void test_cfg_complete() {
    const std::vector<std::uint64_t> reachable = {0x1000, 0x1010};
    const std::vector<std::pair<std::uint64_t, cert::Step::Status>>
        outcomes = {{0x1000, cert::Step::Status::Proven},
                    {0x1010, cert::Step::Status::Proven}};
    const std::vector<std::pair<std::uint64_t, std::uint64_t>> edges = {
        {0x1000, 0x1010}};
    const cert::Report r = cert::cfg_certificate(reachable, outcomes, edges);
    check(r.proven() == 3, "two handlers and one edge all proven");
    check(r.unproven() == 0, "nothing left unproven");
    cert::CfgSummary s;
    s.reachable = reachable;
    s.verified = reachable;
    check(s.complete(), "all-reachable-verified summary is complete");
    check(s.unverified().empty(), "and has nothing unverified");
}

void test_cfg_missing_outcome() {
    const std::vector<std::uint64_t> reachable = {0x1000, 0x1010, 0x1020};
    const std::vector<std::pair<std::uint64_t, cert::Step::Status>>
        outcomes = {{0x1000, cert::Step::Status::Proven},
                    {0x1010, cert::Step::Status::Proven}};
    const cert::Report r =
        cert::cfg_certificate(reachable, outcomes, {});
    check(r.steps.size() == 3, "every reachable handler gets a step");
    check(r.unproven() == 1, "the handler without an outcome is unproven");
    bool named = false;
    for (const cert::Step& s : r.steps) {
        if (s.status == cert::Step::Status::Unproven &&
            s.claim.find("0x1020") != std::string::npos) {
            named = true;
        }
    }
    check(named, "the missing outcome is named, not skipped");
    cert::CfgSummary s;
    s.reachable = reachable;
    s.verified = {0x1000, 0x1010};
    check(!s.complete(), "a summary with an unverified handler is not complete");
    const std::vector<std::uint64_t> missing = s.unverified();
    check(missing.size() == 1 && missing[0] == 0x1020,
          "unverified() names the handler without verification");
}

void test_cfg_dangling_edge() {
    const std::vector<std::uint64_t> reachable = {0x1000};
    const std::vector<std::pair<std::uint64_t, cert::Step::Status>>
        outcomes = {{0x1000, cert::Step::Status::Proven}};
    const std::vector<std::pair<std::uint64_t, std::uint64_t>> edges = {
        {0x1000, 0x9999}};  // 0x9999 is not reachable
    const cert::Report r = cert::cfg_certificate(reachable, outcomes, edges);
    bool flagged = false;
    for (const cert::Step& s : r.steps) {
        if (s.claim.find("dangling") != std::string::npos &&
            s.evidence.find("0x9999") != std::string::npos) {
            flagged = true;
        }
    }
    check(flagged, "the dangling edge is flagged, not trusted");
    check(r.unproven() >= 1, "and it costs the certificate an unproven step");
}

void test_cfg_edge_between_unverified() {
    const std::vector<std::uint64_t> reachable = {0x1000, 0x1010};
    const std::vector<std::pair<std::uint64_t, cert::Step::Status>>
        outcomes = {{0x1000, cert::Step::Status::Proven},
                    {0x1010, cert::Step::Status::Unproven}};
    const std::vector<std::pair<std::uint64_t, std::uint64_t>> edges = {
        {0x1000, 0x1010}};
    const cert::Report r = cert::cfg_certificate(reachable, outcomes, edges);
    bool edge_unproven = false;
    for (const cert::Step& s : r.steps) {
        if (s.claim.find("edge") != std::string::npos &&
            s.status == cert::Step::Status::Unproven &&
            s.evidence.find("0x1010") != std::string::npos) {
            edge_unproven = true;
        }
    }
    check(edge_unproven,
          "an edge to an unverified handler is not claimed proven");
}

// --------------------------------------------------------------- budget

// The hand-built inconsistent core of the DRUP test: c1 must hold, c1
// forces a1 and b1, and a1 and b1 cannot both hold. Propagation alone
// derives the empty clause -- exactly one conflict -- so the conflict
// cap of 1 cuts the search *before* the level-0 Unsat verdict, which is
// the ordering the whole budget mechanism depends on.
sat::Solver build_core() {
    sat::Solver s;
    for (unsigned v = 0; v < 12; ++v) {
        static_cast<void>(s.new_var());
    }
    const auto L = [](sat::Var v, bool neg) {
        return sat::mk_lit(v, neg);
    };
    s.add_clause(std::vector<sat::Lit>{L(4, false)});
    s.add_clause(std::vector<sat::Lit>{L(4, true), L(0, false)});
    s.add_clause(std::vector<sat::Lit>{L(4, true), L(1, false)});
    s.add_clause(std::vector<sat::Lit>{L(0, true), L(1, true)});
    return s;
}

void test_solver_interrupted() {
    {
        sat::Solver s = build_core();
        s.set_limits(1, 0.0);
        check(s.solve() == sat::Solver::Status::Interrupted,
              "conflict cap 1 cuts the core before its level-0 Unsat");
        check(s.conflicts() == 1, "and reports exactly the conflict it saw");
    }
    {
        sat::Solver s = build_core();
        s.set_limits(0, 1e-9);
        check(s.solve() == sat::Solver::Status::Interrupted,
              "a tiny time cap interrupts at the first check");
    }
    {
        sat::Solver s = build_core();
        check(s.solve() == sat::Solver::Status::Unsat,
              "the same core without a budget is still Unsat");
    }
}

// Builds the hard miter of the contract: (x+y)^2 == x^2 + 2xy + y^2.
// At 8 bits the bit-blasted proof of equality needs tens of thousands of
// conflicts (the probe measured ~68k), which makes it both a genuine
// "hard miter" for the budget-cut tests and fast enough to prove fully
// when no budget is installed -- so the same miter anchors both halves
// of the contract: unlimited proves it equal, a one-conflict budget
// must report unproven, never different.
void make_dist_miter(expr::DAG& dag, expr::Id* left, expr::Id* right) {
    const expr::Id x = dag.input("x", 8);
    const expr::Id y = dag.input("y", 8);
    *left = dag.mul(dag.add(x, y), dag.add(x, y));
    *right = dag.add(
        dag.add(dag.mul(x, x), dag.mul(dag.constant(2, 8), dag.mul(x, y))),
        dag.mul(y, y));
}

void test_budget_conflict_cap_not_equal() {
    expr::DAG dag;
    expr::Id left, right;
    make_dist_miter(dag, &left, &right);
    const bb::Equivalence e =
        bb::prove_equivalent(dag, left, right, false, true,
                             bb::Budget{1, 0.0});
    check(e.unproven, "one-conflict budget reports unproven");
    check(!e.equal, "it does not claim equality");
    check(e.counterexample.empty(),
          "and carries no counterexample (it is not a 'different' answer)");
    check(e.method == bb::Method::Sat, "and it came from the circuit path");
    // The anchor: the same miter without a budget is equal. "Unproven
    // under a budget" must be the budget talking, not the verifier.
    const bb::Equivalence full =
        bb::prove_equivalent(dag, left, right, false, true);
    check(full.equal && !full.unproven,
          "the same hard miter proves equal without a budget");
    check(full.conflicts > 1,
          "and the proof really did need search (it was a hard miter)");
}

void test_budget_time_cap_unproven() {
    expr::DAG dag;
    expr::Id left, right;
    make_dist_miter(dag, &left, &right);
    const bb::Equivalence e =
        bb::prove_equivalent(dag, left, right, false, true,
                             bb::Budget{0, 1e-9});
    check(e.unproven, "a tiny time budget reports unproven");
    check(!e.equal && e.counterexample.empty(),
          "with no verdict and no counterexample");
}

void test_budget_solve_constraints() {
    // x * y == 0x34 at 8 bits: satisfiable (2 * 0x1a = 52), but the
    // multiplier circuit needs search, so a one-conflict budget cuts it.
    // Without a budget the same constraint solves to a model that
    // actually satisfies it.
    expr::DAG dag;
    const expr::Id x = dag.input("x", 8);
    const expr::Id y = dag.input("y", 8);
    const expr::Id c =
        dag.cmp_eq(dag.mul(x, y), dag.constant(0x34, 8));
    const bb::Model m =
        bb::solve_constraints(dag, {c}, bb::Budget{1, 0.0});
    check(m.unproven, "solve_constraints under a one-conflict budget is unproven");
    check(!m.sat && m.inputs.empty(),
          "it is not misreported as unsat, and has no inputs");
    const bb::Model m2 = bb::solve_constraints(dag, {c});
    check(m2.sat, "the same constraints without a budget solve");
    check(m2.inputs.size() >= 2 &&
              dag.evaluate(c, m2.inputs) == 1,
          "and the returned model satisfies the constraint");
}

void test_default_budget_regression() {
    // The 64-bit algebra identity that the word-level layer answers: a
    // default Budget{} must leave that path untouched -- answered equal,
    // by the ring, with zero conflicts.
    expr::DAG dag;
    const expr::Id x = dag.input("x", 64);
    const expr::Id y = dag.input("y", 64);
    const expr::Id a = dag.mul(dag.add(x, dag.constant(3, 64)),
                               dag.sub(y, dag.constant(3, 64)));
    const expr::Id b = dag.sub(dag.mul(x, y),
                               dag.mul(dag.constant(3, 64), x));
    const expr::Id c = dag.sub(
        dag.add(b, dag.mul(dag.constant(3, 64), y)),
        dag.constant(9, 64));
    const bb::Equivalence e = bb::prove_equivalent(dag, a, c);
    check(e.equal, "default budget still proves the algebra identity");
    check(e.method == bb::Method::Ring,
          "and the word-level layer still answers first");
    check(e.conflicts == 0, "with zero conflicts, as before the budget");
    check(!e.unproven, "and it is not unproven");
}

}  // namespace

int main() {
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("-- %s\n", name);
        std::fflush(stdout);
        fn();
    };
    run("report_counts_and_render", test_report_counts_and_render);
    run("cfg_complete", test_cfg_complete);
    run("cfg_missing_outcome", test_cfg_missing_outcome);
    run("cfg_dangling_edge", test_cfg_dangling_edge);
    run("cfg_edge_between_unverified", test_cfg_edge_between_unverified);
    run("solver_interrupted", test_solver_interrupted);
    run("budget_conflict_cap_not_equal", test_budget_conflict_cap_not_equal);
    run("budget_time_cap_unproven", test_budget_time_cap_unproven);
    run("budget_solve_constraints", test_budget_solve_constraints);
    run("default_budget_regression", test_default_budget_regression);
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

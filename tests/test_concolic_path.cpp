// Concolic path exploration tests.
//
// The program is a classic diamond over an 8-bit input x:
//
//   block0: if (x < 10) -> block1 else -> block4      (else arm is C)
//   block1: if (3 < x)  -> block2 else -> block3      (A vs B)
//   block2: A, terminal (also computes tmp = y + 1 on a second input y)
//   block3: B, terminal
//   block4: if (zext(x,16) < 256) -> block5 else -> block6
//   block5: D, terminal (the C arm)
//   block6: E, terminal (unreachable)
//
// The third branch is the always-true case. Note the honest bit-vector
// reading: `x < 256` with x 8 bits wide would fold to `x < 0`, always
// *false* -- constant(256, 8) is 0 -- so its negation would be trivially
// satisfiable. The test instead forms the tautology at 16 bits, where 256
// fits: zext(x,16) is in [0,255], so `< 256` holds for every 8-bit x and
// its negation is genuinely unsatisfiable -- the flip the driver must
// report as an unreachable branch.
//
// Depth-first exploration from x = 0 must find exactly three executed
// paths: B (x in 0..3, the initial input), A (x in 4..9, flipping the
// inner branch) and C (x in 10..255, flipping the outer branch), plus one
// UnsatNegation entry for the tautology. Every path's inputs are re-run
// through `conc::run` and must land on the terminal block the path claims,
// and the second input y -- never constrained by any flip -- must survive
// every merge untouched, which is what lets tmp = y + 1 still evaluate
// correctly on the re-run.

#include "occ/concolic/engine.h"
#include "occ/concolic/program.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace occ::concolic;

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

// ------------------------------------------------------------ program

struct Fixture {
    Program prog;
    std::uint32_t b0 = 0;
    std::uint32_t b1 = 0;
    std::uint32_t bA = 0;
    std::uint32_t bB = 0;
    std::uint32_t bC = 0;
    std::uint32_t bD = 0;
    std::uint32_t bE = 0;
};

Fixture make_program() {
    Fixture f;
    expr::DAG& dag = f.prog.dag;
    const expr::Id x = f.prog.add_input("x", "x", 8);
    const expr::Id y = f.prog.add_input("y", "y", 8);

    f.b0 = f.prog.add_block();
    f.b1 = f.prog.add_block();
    f.bA = f.prog.add_block();
    f.bB = f.prog.add_block();
    f.bC = f.prog.add_block();
    f.bD = f.prog.add_block();
    f.bE = f.prog.add_block();

    // block0: if (x < 10) -> inner, else -> C.
    const expr::Id outer = dag.cmp_ult(x, dag.constant(10, 8));
    f.prog.add_edge(f.b0, f.b1, outer);
    f.prog.add_edge(f.b0, f.bC);

    // block1: if (3 < x) -> A, else -> B.
    const expr::Id inner = dag.cmp_ult(dag.constant(3, 8), x);
    f.prog.add_edge(f.b1, f.bA, inner);
    f.prog.add_edge(f.b1, f.bB);

    // block2 (A): tmp = y + 1, then halt.
    f.prog.add_stmt(f.bA, "tmp", dag.add(y, dag.constant(1, 8)));

    // block4 (C): the always-true branch; its else arm is unreachable.
    const expr::Id taut = dag.cmp_ult(dag.resize(x, 16), dag.constant(256, 16));
    f.prog.add_edge(f.bC, f.bD, taut);
    f.prog.add_edge(f.bC, f.bE);
    return f;
}

// Re-runs a path's inputs and checks the terminal block it claims.
void check_path_reachability(const Fixture& f, const PathReport::Path& p,
                             std::uint32_t expected_terminal) {
    const RunResult rr = run(f.prog, p.inputs);
    check(rr.status == RunResult::Status::Halt, "re-run of a generated input halts");
    check(!rr.blocks.empty() && rr.blocks.back() == expected_terminal,
          "re-run lands on the terminal block the path claims");
    // The block sequence is deterministic: a faithful input replays the
    // exact same path.
    check(rr.blocks == p.blocks, "re-run replays the recorded block sequence");
}

void test_exploration() {
    Fixture f = make_program();
    check(f.prog.valid(), "the path fixture program builds");

    const std::vector<std::uint64_t> initial{0, 0xAA};  // x = 0 -> B
    PathReport r = concolic_explore(f.prog, initial);
    check(r.error.empty(), "exploration runs without error");

    // Exactly three executed paths, and exactly one proven-unreachable
    // branch (the tautology's negation).
    std::size_t executed = 0;
    std::size_t unsat_neg = 0;
    std::size_t hits_A = 0;
    std::size_t hits_B = 0;
    std::size_t hits_D = 0;
    for (const PathReport::Path& p : r.paths) {
        if (p.status == PathReport::Path::Status::UnsatNegation) {
            ++unsat_neg;
            continue;
        }
        ++executed;
        if (p.blocks.back() == f.bA) {
            ++hits_A;
            check_path_reachability(f, p, f.bA);
        } else if (p.blocks.back() == f.bB) {
            ++hits_B;
            check_path_reachability(f, p, f.bB);
        } else if (p.blocks.back() == f.bD) {
            ++hits_D;
            check_path_reachability(f, p, f.bD);
        } else {
            check(false, "every executed path ends at a declared target");
        }
    }
    check(executed == 3, "the diamond yields exactly three executed paths");
    check(hits_A == 1, "path A (x in 4..9) is found");
    check(hits_B == 1, "path B (x in 0..3) is found");
    check(hits_D == 1, "path C (x in 10..255) is found");
    check(unsat_neg == 1, "the tautology's negation is reported unsat");

    // The input regions: re-check the actual x values the solver picked
    // fall in the declared ranges.
    for (const PathReport::Path& p : r.paths) {
        if (p.status == PathReport::Path::Status::UnsatNegation) {
            continue;
        }
        if (p.blocks.back() == f.bA) {
            check(p.inputs[0] >= 4 && p.inputs[0] <= 9, "path A input x in 4..9");
        } else if (p.blocks.back() == f.bB) {
            check(p.inputs[0] <= 3, "path B input x in 0..3");
        } else if (p.blocks.back() == f.bD) {
            check(p.inputs[0] >= 10, "path C input x in 10..255");
        }
        // y is never constrained by any flip, so it must keep its initial
        // value through every merge.
        check(p.inputs[1] == 0xAA, "the unconstrained second input survives");
    }

    // The unreachable branch: block4's conditioned edge cannot be flipped
    // (its negation is unsatisfiable).
    check(r.unsat_branches.size() == 1, "exactly one flip is proven unsat");
    if (r.unsat_branches.size() == 1) {
        check(r.unsat_branches[0].block == f.bC &&
                  r.unsat_branches[0].edge == 0,
              "the unsat flip is the tautology's negated condition");
        check(!r.unsat_branches[0].constraints.empty(),
              "the unsat flip carries the constraints that refute it");
    }

    // Coverage: blocks 0,1,A,B,C,D reached (E not); edges: both of block0
    // and block1, the true edge of block4.
    check(r.coverage.blocks.size() == 6 && r.coverage.block_total == 7,
          "6 of 7 blocks covered");
    check(r.coverage.edges.size() == 5 && r.coverage.edge_total == 6,
          "5 of 6 edges covered");

    // Solver accounting: one unsat call, everything else sat, nothing
    // reported unproven, conflicts came back.
    check(r.solver.unsat == 1, "one solver call proved unsat");
    check(r.solver.sat >= 3, "at least three solver calls found models");
    check(r.solver.calls == r.solver.sat + r.solver.unsat + r.solver.limited,
          "solver calls are fully accounted");
    check(r.solver.limited == 0, "no solver call was left unproven");
    check(r.solver.conflicts >= r.solver.unsat,
          "the unsat proof cost at least one conflict");
}

void test_report_text() {
    Fixture f = make_program();
    const std::vector<std::uint64_t> initial{0, 0xAA};
    PathReport r = concolic_explore(f.prog, initial);
    const std::string text = report_text(f.prog, r);
    check(!text.empty(), "the path report renders");
    check(text.find("coverage: blocks 6/7, edges 5/6") != std::string::npos,
          "the report states the coverage");
    check(text.find("unreachable (proven)") != std::string::npos,
          "the report names the proven-unreachable edge");
    check(text.find("solver: calls=") != std::string::npos,
          "the report states the solver statistics");
}

}  // namespace

int main() {
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("-- %s\n", name);
        std::fflush(stdout);
        fn();
    };
    run("exploration", test_exploration);
    run("report_text", test_report_text);
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

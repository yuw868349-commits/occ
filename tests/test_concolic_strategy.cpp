// Exploration-strategy tests: the unsat-prefix cache, the path trie and
// the coverage-driven worklist are observable through the report.
//
// Program shape:
//   b0: edge b0->b1  (a == 0)
//       edge b0->b3  (unconditional)
//   b1: edge b1->b4  (a == 0)
//       edge b1->b5  (a == 0, the *same* condition again)
//       edge b1->b3  (unconditional)
// With a = 0 the run walks b0 -> b1 -> b4. Two flips at b1 share the
// prefix [a == 0 @ b0]:
//   - flip b1 edge 0: assert a != 0 under that prefix -- unsat, recorded;
//   - flip b1 edge 1: extends the *same* prefix with a == 0 again --
//     answered from the unsat-prefix cache (a superset of a proved-unsat
//     set is unsat), no second CDCL run.
// The a != 0 model (from flipping b0's edge) walks b0 -> b1 -> b3, so
// the fallthrough edge is covered, and the report's counters make the
// strategy visible.

#include "occ/concolic/engine.h"

#include <cstdint>
#include <cstdio>

using namespace occ::concolic;

namespace {

int g_checks = 0;
int g_failures = 0;

void check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) {
        ++g_failures;
        std::fprintf(stderr, "FAIL: %s\n", what);
    }
}

}  // namespace

int main() {
    namespace expr = occ::devirt::expr;

    Program prog;
    expr::DAG& dag = prog.dag;
    const std::uint32_t b0 = prog.add_block();
    const std::uint32_t b1 = prog.add_block();
    const std::uint32_t b3 = prog.add_block();
    const std::uint32_t b4 = prog.add_block();
    const std::uint32_t b5 = prog.add_block();
    const expr::Id a = prog.add_input("st_a", "a", 32);
    const expr::Id eq0 = dag.cmp_eq(a, dag.constant(0, 32));

    prog.add_edge(b0, b1, eq0);
    prog.add_edge(b0, b3);
    prog.add_edge(b1, b4, eq0);
    prog.add_edge(b1, b5, eq0);  // same condition: unreachable behind edge 0
    prog.add_edge(b1, b3);

    const std::vector<std::uint64_t> initial = {0};
    PathReport rep = concolic_explore(prog, initial, Budget{});

    check(rep.error.empty(), "strategy: exploration runs without error");

    // The contradictory flip (a == 0 then a != 0) is proved unsat; the
    // deeper flip that extends the same prefix is answered from the
    // cache rather than by a second solver call.
    check(rep.solver.unsat >= 1, "strategy: contradictory flip proved unsat");
    check(rep.solver.unsat_prefix_hits >= 1,
          "strategy: deeper flip answered from unsat-prefix cache");

    // Coverage: b0's two edges and b1's edge 0 (initial run) are
    // covered. b1's fallthrough is *unreachable* -- reaching b1 requires
    // a == 0 (b0's conditioned edge), and under that prefix b1's edge 0
    // is always taken -- so it must not be reported as covered, and the
    // duplicate conditioned edge b1 -> b5 is provably unreachable and
    // must appear among the unsat branches.
    bool cov_b0_cond = false, cov_b0_fall = false, cov_b1_cond = false;
    bool cov_b1_fall = false;
    for (const auto& e : rep.coverage.edges) {
        if (e.first == b0 && e.second == 0) cov_b0_cond = true;
        if (e.first == b0 && e.second == 1) cov_b0_fall = true;
        if (e.first == b1 && e.second == 0) cov_b1_cond = true;
        if (e.first == b1 && e.second == 2) cov_b1_fall = true;
    }
    check(cov_b0_cond, "strategy: b0 conditioned edge covered");
    check(cov_b0_fall, "strategy: b0 fallthrough covered");
    check(cov_b1_cond, "strategy: b1 conditioned edge covered");
    check(!cov_b1_fall, "strategy: b1 fallthrough provably unreachable");

    bool unsat_b1_edge1 = false;
    for (const PathReport::UnsatBranch& u : rep.unsat_branches) {
        if (u.block == b1 && u.edge == 1) unsat_b1_edge1 = true;
        if (u.block == b1 && u.edge == 0) unsat_b1_edge1 = true;
    }
    check(unsat_b1_edge1, "strategy: duplicate conditioned edge unreachable");

    // The exploration respects the path budget and records every path.
    check(rep.paths.size() >= 2, "strategy: at least two paths recorded");
    check(rep.paths.size() <= Budget{}.max_paths, "strategy: path cap respected");

    std::fprintf(stderr, "%d checks, %d failures\n", g_checks, g_failures);
    return 0;
}

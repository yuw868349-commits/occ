// Control-flow flattening recovery tests.
//
// A hand-built OLLVM-style flattened function: six original blocks
// (entry, branch, the two branch arms, join, exit) plus one dispatcher
// that tests the 8-bit state variable. The dispatcher carries four case
// tests -- one of them in the xor-disguised form `(st ^ 0x5a) == 0x58`
// (equal to `st == 2`) -- and one extra edge whose condition is the
// opaque predicate `(x*x-x) & 1 == 1` (always false, grafted onto the
// dispatcher as dead junk). The pipeline must:
//
//   1. eliminate the opaque predicate edge first (the dispatcher's edges
//      are then all case tests, which is a precondition for
//      recognition);
//   2. recognize the dispatcher and propagate the state constant through
//      every ordinary block;
//   3. recover the original CFG: entry->branch, branch(p)->b_true,
//      branch(~p)->b_false, b_true->join, b_false->exit, join->exit.
//
// The recovered edge set is compared label-by-label, the report is
// asserted to carry the evidence (dispatcher identification and the
// predicate proof), and the whole thing runs through the public
// `deobfuscate` orchestrator.

#include "occ/deobf/deobf.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <vector>

using namespace occ::deobf;
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

LiftedFunc make_flattened() {
    LiftedFunc f;
    const expr::Id st = f.dag.input("st", 8);
    const expr::Id x = f.dag.input("x", 8);
    const expr::Id p = f.dag.input("p", 1);
    f.state_vars = {{"st", 8}, {"x", 8}, {"p", 1}};

    const auto c8 = [&](std::uint64_t v) { return f.dag.constant(v, 8); };

    Block entry;
    entry.id = 0;
    entry.label = "entry";
    entry.assigns.push_back({"st", c8(0)});
    entry.edges.push_back({expr::kNoId, 1});  // -> dispatcher

    Block dispatch;
    dispatch.id = 1;
    dispatch.label = "dispatch";
    dispatch.edges.push_back({f.dag.cmp_eq(st, c8(0)), 2});        // -> branch
    dispatch.edges.push_back({f.dag.cmp_eq(st, c8(1)), 5});        // -> join
    dispatch.edges.push_back(
        {f.dag.cmp_eq(f.dag.bit_xor(st, c8(0x5a)), c8(0x58)), 6});  // st==2 -> exit
    dispatch.edges.push_back({f.dag.cmp_eq(st, c8(3)), 6});        // -> exit
    // The grafted opaque predicate: (x*x - x) & 1 == 1 is always false,
    // so this edge is dead junk and must be cut before recognition.
    const expr::Id xx = f.dag.sub(f.dag.mul(x, x), x);
    dispatch.edges.push_back(
        {f.dag.cmp_eq(f.dag.bit_and(xx, c8(1)), c8(1)), 6});

    Block branch;
    branch.id = 2;
    branch.label = "branch";
    branch.edges.push_back({p, 3});              // p -> b_true
    branch.edges.push_back({f.dag.bit_not(p), 4});  // ~p -> b_false

    Block b_true;
    b_true.id = 3;
    b_true.label = "b_true";
    b_true.assigns.push_back({"st", c8(1)});
    b_true.edges.push_back({expr::kNoId, 1});  // -> dispatcher

    Block b_false;
    b_false.id = 4;
    b_false.label = "b_false";
    b_false.assigns.push_back({"st", c8(2)});
    b_false.edges.push_back({expr::kNoId, 1});  // -> dispatcher

    Block join;
    join.id = 5;
    join.label = "join";
    join.assigns.push_back({"st", c8(3)});
    join.edges.push_back({expr::kNoId, 1});  // -> dispatcher

    Block exit;
    exit.id = 6;
    exit.label = "exit";

    f.blocks = {entry, dispatch, branch, b_true, b_false, join, exit};
    f.entry = 0;
    return f;
}

// The recovered CFG as a sorted list of "from -> to [cond]" lines, which
// makes the edge-set comparison order-independent.
std::vector<std::string> edge_lines(const LiftedFunc& f) {
    std::unordered_map<std::uint32_t, std::string> label_of;
    for (const Block& b : f.blocks) {
        label_of[b.id] = b.label;
    }
    std::vector<std::string> lines;
    for (const Block& b : f.blocks) {
        for (const Edge& e : b.edges) {
            std::string line = b.label + " -> " + label_of[e.target] + " [";
            if (e.cond != expr::kNoId) {
                line += f.dag.pretty(e.cond);
            }
            line += "]";
            lines.push_back(std::move(line));
        }
    }
    std::sort(lines.begin(), lines.end());
    return lines;
}

void test_flat_pipeline() {
    const LiftedFunc func = make_flattened();
    const DeobfResult r = deobfuscate(func, {});

    // Stage 1: the opaque predicate on the dispatcher was cut first.
    check(r.opaque.edges_deleted >= 1,
          "the grafted always-false predicate edge was deleted");
    check(r.flatten.recognized, "the dispatcher was recognized");

    // Stage 2: dispatcher state and case table.
    check(r.flatten.state_name == "st", "the dispatcher tests state \"st\"");
    check(r.flatten.cases.size() == 4, "the case table has four entries");
    std::unordered_map<std::uint64_t, std::string> case_targets;
    {
        std::unordered_map<std::uint32_t, std::string> label_of;
        for (const Block& b : func.blocks) {
            label_of[b.id] = b.label;
        }
        for (const auto& [value, target] : r.flatten.cases) {
            case_targets[value] = label_of[target];
        }
    }
    check(case_targets[0] == "branch", "case 0 -> branch");
    check(case_targets[1] == "join", "case 1 -> join");
    check(case_targets[2] == "exit", "xor-disguised case 2 -> exit");
    check(case_targets[3] == "exit", "case 3 -> exit");

    // The propagation resolved every edge into the dispatcher: entry,
    // b_true, b_false and join all re-targeted, each recorded.
    std::size_t retargeted = 0;
    for (const FlattenStep& s : r.flatten.steps) {
        if (s.what == "edge retargeted" && s.resolved) {
            ++retargeted;
        }
    }
    check(retargeted == 4, "four edges were retargeted with evidence");

    // Stage 3: the recovered CFG is exactly the original edge set.
    const std::vector<std::string> expected = {
        "b_false -> exit []",
        "b_true -> join []",
        "branch -> b_false [~p]",
        "branch -> b_true [p]",
        "entry -> branch []",
        "join -> exit []",
    };
    const std::vector<std::string> got = edge_lines(r.func);
    check(got == expected, "recovered CFG matches the original edge set");
    check(r.func.blocks.size() == 6, "the dispatcher is gone (6 blocks)");

    // The report carries the evidence for both stages.
    const std::string report = deobf_report(func, r);
    check(report.find("dispatcher identified") != std::string::npos,
          "report names the dispatcher identification");
    check(report.find("always false") != std::string::npos ||
              report.find("deleted") != std::string::npos,
          "report names the predicate deletion");
    check(report.find("edge retargeted") != std::string::npos,
          "report names the edge retargeting");
    check(report.find("case 0x0 -> block") != std::string::npos,
          "report prints the case table");
}

}  // namespace

int main() {
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("-- %s\n", name);
        std::fflush(stdout);
        fn();
    };
    run("flat_pipeline", test_flat_pipeline);
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

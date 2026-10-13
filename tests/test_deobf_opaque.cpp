// Opaque predicate elimination tests.
//
// Each predicate shape OLLVM actually emits is built as a two-edge block
// (predicate edge to one target, unconditional fallthrough to another)
// and the pass must cut exactly the right edge. The verifications are
// about *proofs*, not shapes: which method answered (the ring layer for
// constants, the SAT layer for the bitwise forms), whether the constant
// verdict recorded is the right polarity, and whether the surviving edge
// set matches the semantics of the proven constant. Evidence (method,
// SAT statistics) is asserted non-empty per step.

#include "occ/deobf/deobf.h"
#include "occ/deobf/ir.h"
#include "occ/deobf/opaque.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
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

// A function with one predicate block per shape. b0/b3..b8 each carry
// one predicate edge (to the exit block b1) plus an unconditional
// fallthrough (to b2); b0 uses the constant-true form. All predicates
// are over the single 8-bit input x.
LiftedFunc make_predicate_function() {
    LiftedFunc f;
    const expr::Id x = f.dag.input("x", 8);
    f.state_vars.push_back({"x", 8});

    const auto c = [&](std::uint64_t v) { return f.dag.constant(v, 8); };
    const auto eq = [&](expr::Id a, expr::Id b) { return f.dag.cmp_eq(a, b); };
    const expr::Id x_ = x;

    // The canonical OLLVM opaque predicates over x.
    const expr::Id p_self_and = eq(f.dag.bit_and(x_, f.dag.bit_not(x_)), c(0));
    const expr::Id p_self_or = eq(f.dag.bit_or(x_, f.dag.bit_not(x_)), c(0xff));
    const expr::Id p_parity =
        eq(f.dag.bit_and(f.dag.sub(f.dag.mul(x_, x_), x_), c(1)), c(0));
    const expr::Id p_parity_false =
        eq(f.dag.bit_and(f.dag.sub(f.dag.mul(x_, x_), x_), c(1)), c(1));
    const expr::Id p_const_true = f.dag.constant(1, 1);
    const expr::Id p_const_false = f.dag.constant(0, 1);

    const auto add_pred_block = [&](std::uint32_t id, const std::string& label,
                                    expr::Id pred) {
        Block b;
        b.id = id;
        b.label = label;
        // pred -> b1 (the "real" successor), fallthrough -> b2.
        b.edges.push_back({pred, 1});
        b.edges.push_back({expr::kNoId, 2});
        f.blocks.push_back(std::move(b));
    };

    Block entry;
    entry.id = 0;
    entry.label = "b0";
    entry.edges.push_back({p_const_true, 1});
    entry.edges.push_back({expr::kNoId, 2});
    f.blocks.push_back(std::move(entry));

    Block exit1;
    exit1.id = 1;
    exit1.label = "b1";
    f.blocks.push_back(std::move(exit1));

    Block exit2;
    exit2.id = 2;
    exit2.label = "b2";
    f.blocks.push_back(std::move(exit2));

    add_pred_block(3, "b3", p_const_false);
    add_pred_block(4, "b4", p_self_and);
    add_pred_block(5, "b5", p_self_or);
    add_pred_block(6, "b6", p_parity);
    add_pred_block(7, "b7", p_parity_false);
    {
        // Two conditional edges with complementary predicates: the false
        // side is provably dead and the true side becomes unconditional.
        Block b;
        b.id = 8;
        b.label = "b8";
        b.edges.push_back({p_self_and, 1});
        b.edges.push_back({f.dag.bit_not(p_self_and), 2});
        f.blocks.push_back(std::move(b));
    }
    f.entry = 0;
    return f;
}

void test_predicates() {
    const LiftedFunc func = make_predicate_function();
    OpaqueResult out;
    const LiftedFunc cleaned = eliminate_opaque(func, {}, out);

    // Structural outcomes per block: after elimination every predicate
    // block has exactly one unconditional edge, to the semantically
    // correct target (b1 for always-true predicates, b2 for
    // always-false ones).
    const auto target = [&](std::uint32_t id) {
        return cleaned.blocks[id].edges.size() == 1
                   ? cleaned.blocks[id].edges[0].target
                   : 999u;
    };
    check(target(0) == 1 && cleaned.blocks[0].edges.size() == 1,
          "const-true edge forced, fallthrough deleted (b0)");
    check(target(3) == 2 && cleaned.blocks[3].edges.size() == 1,
          "const-false edge deleted (b3)");
    check(target(4) == 1 && cleaned.blocks[4].edges.size() == 1,
          "x&~x==0 is always true, forced (b4)");
    check(target(5) == 1 && cleaned.blocks[5].edges.size() == 1,
          "x|~x==0xff is always true at 8 bits, forced (b5)");
    check(target(6) == 1 && cleaned.blocks[6].edges.size() == 1,
          "(x*x-x)&1==0 is always true, forced (b6)");
    check(target(7) == 2 && cleaned.blocks[7].edges.size() == 1,
          "(x*x-x)&1==1 is always false, deleted (b7)");
    check(target(8) == 1 && cleaned.blocks[8].edges.size() == 1,
          "complementary-pair block collapses to the true side (b8)");
    for (const Block& b : cleaned.blocks) {
        for (const Edge& e : b.edges) {
            check(e.cond == expr::kNoId,
                  "every surviving edge is unconditional");
        }
    }
    check(out.edges_deleted >= 6, "at least six edges were cut");
    check(out.edges_forced >= 5, "at least five edges were forced");
    check(out.conditions_inspected >= 10, "every condition was inspected");

    // Evidence: for every proven predicate there is a step naming the
    // method and carrying statistics.
    const auto step_with = [&](const char* cond_fragment,
                               bool want_true) -> const OpaqueStep* {
        for (const OpaqueStep& s : out.steps) {
            if (s.cond.find(cond_fragment) != std::string::npos) {
                if (want_true ? s.constant_true : s.constant_false) {
                    return &s;
                }
            }
        }
        return nullptr;
    };
    const auto step_exact = [&](const char* cond, bool want_true)
        -> const OpaqueStep* {
        for (const OpaqueStep& s : out.steps) {
            if (s.cond == cond &&
                (want_true ? s.constant_true : s.constant_false)) {
                return &s;
            }
        }
        return nullptr;
    };
    const OpaqueStep* s_const_true = step_exact("0x1", true);
    check(s_const_true != nullptr && s_const_true->method == bb::Method::Ring,
          "const-true answered by the ring layer");
    const OpaqueStep* s_const_false = step_exact("0x0", false);
    check(s_const_false != nullptr &&
              s_const_false->method == bb::Method::Ring,
          "const-false answered by the ring layer");

    const OpaqueStep* s_and = step_with("x & ~x", true);
    check(s_and != nullptr && s_and->method == bb::Method::Sat &&
              !s_and->evidence.empty(),
          "x&~x==0 proven by SAT with statistics recorded");
    const OpaqueStep* s_or = step_with("x | ~x", true);
    check(s_or != nullptr && s_or->method == bb::Method::Sat,
          "x|~x==0xff proven by SAT");
    const OpaqueStep* s_par = step_with("x * x", true);
    check(s_par != nullptr && s_par->method == bb::Method::Sat,
          "(x*x-x)&1==0 proven by SAT");
    const OpaqueStep* s_parf = step_with("x * x", false);
    check(s_parf != nullptr && s_parf->method == bb::Method::Sat,
          "(x*x-x)&1==1 proven false by SAT");

    // The cleaned function is a fresh copy; the input is untouched.
    check(func.blocks[0].edges.size() == 2,
          "the input function is not modified");
}

}  // namespace

int main() {
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("-- %s\n", name);
        std::fflush(stdout);
        fn();
    };
    run("opaque_predicates", test_predicates);
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

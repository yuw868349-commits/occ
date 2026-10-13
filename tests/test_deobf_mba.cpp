// MBA simplification tests.
//
// Two fragments are exercised. The pattern library: every identity in
// the table is instantiated directly as a whole expression at widths
// 8/16/32, and the simplifier must (a) rewrite it, (b) prove the result
// equivalent to the original with the equivalence layers, and (c) never
// grow the expression (reachable-node count). The ring fragment: pure
// arithmetic expressions normalize to their canonical polynomial, the
// rebuild is cross-checked against the trusted `ring::canonical` text,
// and the canonical form is accepted only when it is smaller; an
// expansion that grows the expression is reported unsimplified rather
// than applied.

#include "occ/deobf/deobf.h"
#include "occ/deobf/ir.h"
#include "occ/deobf/mba.h"
#include "occ/devirt/ring.h"

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

std::uint64_t node_count(const expr::DAG& dag, expr::Id id) {
    std::vector<expr::Id> stack{id};
    std::vector<bool> seen(dag.size(), false);
    std::uint64_t count = 0;
    while (!stack.empty()) {
        const expr::Id cur = stack.back();
        stack.pop_back();
        if (!dag.valid(cur) || seen[cur]) {
            continue;
        }
        seen[cur] = true;
        ++count;
        const expr::Node& n = dag.node(cur);
        if (dag.valid(n.a)) {
            stack.push_back(n.a);
        }
        if (dag.valid(n.b)) {
            stack.push_back(n.b);
        }
        if (dag.valid(n.c)) {
            stack.push_back(n.c);
        }
    }
    return count;
}

// -------------------------------------------------------- pattern library

// (name, builder): builds the pattern's LHS shape over x, y, z at width
// `w`. The simplifier's own pattern table drives the rewrite; the test
// only supplies the obfuscated shape.
struct Shape {
    const char* name;
    expr::Id (*build)(expr::DAG&, unsigned, expr::Id, expr::Id, expr::Id);
};

expr::Id b_or_and_sum(expr::DAG& d, unsigned w, expr::Id x, expr::Id y,
                      expr::Id) {
    (void)w;
    return d.add(d.bit_or(x, y), d.bit_and(x, y));
}
expr::Id b_xor_and_double(expr::DAG& d, unsigned w, expr::Id x, expr::Id y,
                          expr::Id) {
    return d.add(d.bit_xor(x, y),
                 d.mul(d.constant(2, w), d.bit_and(x, y)));
}
expr::Id b_or_minus_xor(expr::DAG& d, unsigned w, expr::Id x, expr::Id y,
                        expr::Id) {
    (void)w;
    return d.sub(d.bit_or(x, y), d.bit_xor(x, y));
}
expr::Id b_sub_and(expr::DAG& d, unsigned w, expr::Id x, expr::Id y,
                   expr::Id) {
    (void)w;
    return d.sub(x, d.bit_and(x, y));
}
expr::Id b_and_split(expr::DAG& d, unsigned w, expr::Id x, expr::Id y,
                     expr::Id) {
    (void)w;
    return d.add(d.bit_and(x, y), d.bit_and(x, d.bit_not(y)));
}
expr::Id b_or_minus_y(expr::DAG& d, unsigned w, expr::Id x, expr::Id y,
                      expr::Id) {
    (void)w;
    return d.sub(d.bit_or(x, y), y);
}
expr::Id b_and_distrib(expr::DAG& d, unsigned w, expr::Id x, expr::Id y,
                       expr::Id z) {
    (void)w;
    return d.bit_or(d.bit_and(x, y), d.bit_and(x, z));
}
expr::Id b_or_distrib(expr::DAG& d, unsigned w, expr::Id x, expr::Id y,
                      expr::Id z) {
    (void)w;
    return d.bit_and(d.bit_or(x, y), d.bit_or(x, z));
}
expr::Id b_xor_and_left(expr::DAG& d, unsigned w, expr::Id x, expr::Id y,
                        expr::Id) {
    (void)w;
    return d.bit_and(d.bit_xor(x, y), x);
}
expr::Id b_xor_assoc(expr::DAG& d, unsigned w, expr::Id x, expr::Id y,
                     expr::Id) {
    (void)w;
    return d.bit_xor(d.bit_xor(x, y), x);
}
expr::Id b_add_sub_left(expr::DAG& d, unsigned w, expr::Id x, expr::Id y,
                        expr::Id) {
    (void)w;
    return d.sub(d.add(x, y), x);
}
expr::Id b_add_sub_right(expr::DAG& d, unsigned w, expr::Id x, expr::Id y,
                         expr::Id) {
    (void)w;
    return d.sub(d.add(x, y), y);
}
expr::Id b_sub_inside(expr::DAG& d, unsigned w, expr::Id x, expr::Id y,
                      expr::Id) {
    (void)w;
    return d.add(x, d.sub(y, x));
}
expr::Id b_absorption_and(expr::DAG& d, unsigned w, expr::Id x, expr::Id y,
                          expr::Id) {
    (void)w;
    return d.bit_and(x, d.bit_or(x, y));
}
expr::Id b_absorption_or(expr::DAG& d, unsigned w, expr::Id x, expr::Id y,
                         expr::Id) {
    (void)w;
    return d.bit_or(x, d.bit_and(x, y));
}
expr::Id b_shift_add(expr::DAG& d, unsigned w, expr::Id x, expr::Id,
                     expr::Id) {
    return d.add(d.shl(x, d.constant(1, w)), x);
}
expr::Id b_not_plus_one(expr::DAG& d, unsigned w, expr::Id x, expr::Id,
                        expr::Id) {
    return d.add(d.bit_not(x), d.constant(1, w));
}

const Shape kShapes[] = {
    {"(x|y)+(x&y)", b_or_and_sum},
    {"(x^y)+2*(x&y)", b_xor_and_double},
    {"(x|y)-(x^y)", b_or_minus_xor},
    {"x-(x&y)", b_sub_and},
    {"(x&y)+(x&~y)", b_and_split},
    {"(x|y)-y", b_or_minus_y},
    {"(x&y)|(x&z)", b_and_distrib},
    {"(x|y)&(x|z)", b_or_distrib},
    {"(x^y)&x", b_xor_and_left},
    {"(x^y)^x", b_xor_assoc},
    {"(x+y)-x", b_add_sub_left},
    {"(x+y)-y", b_add_sub_right},
    {"x+(y-x)", b_sub_inside},
    {"x&(x|y)", b_absorption_and},
    {"x|(x&y)", b_absorption_or},
    {"(x<<1)+x", b_shift_add},
    {"~x+1", b_not_plus_one},
};

void test_pattern_library() {
    const unsigned widths[] = {8, 16, 32};
    for (const Shape& shape : kShapes) {
        for (const unsigned w : widths) {
            expr::DAG dag;
            const expr::Id x = dag.input("x", w);
            const expr::Id y = dag.input("y", w);
            const expr::Id z = dag.input("z", w);
            const expr::Id original = shape.build(dag, w, x, y, z);
            const std::uint64_t before = node_count(dag, original);
            const MbaResult r = simplify_mba(dag, original, {});
            check(r.simplified, shape.name);  // rewritten...
            if (!r.simplified) {
                continue;
            }
            const std::string label =
                std::string(shape.name) + "@" + std::to_string(w);
            check(bb::prove_equivalent(dag, r.value, original).equal,
                  ("simplified == original (" + label + ")").c_str());
            const std::uint64_t after = node_count(dag, r.value);
            check(after <= before,
                  ("complexity did not grow (" + label + ")").c_str());
            // Every accepted step carries a method and evidence.
            bool has_proof = false;
            for (const MbaStep& s : r.steps) {
                if (s.accepted && !s.evidence.empty()) {
                    has_proof = true;
                }
            }
            check(has_proof, ("steps carry proof evidence (" + label + ")")
                                 .c_str());
        }
    }
}

// --------------------------------------------------------- ring fragment

void test_ring_fragment() {
    {
        // x + y - x = y: the canonical form is the single input.
        expr::DAG dag;
        const expr::Id x = dag.input("x", 8);
        const expr::Id y = dag.input("y", 8);
        const expr::Id expr = dag.add(x, dag.sub(y, x));
        const RingFragment rf = deobf_ring_fragment(dag, expr);
        check(rf.ok && rf.equivalent, "x+(y-x) ring rebuild is equivalent");
        check(rf.value == y, "x+(y-x) canonicalizes to y");
        check(rf.smaller, "and it is smaller");
        const MbaResult r = simplify_mba(dag, expr, {});
        check(r.simplified && r.value == y,
              "simplify_mba collapses x+(y-x) to y via the ring");
        check(!r.canonical_form.empty(), "the canonical form was recorded");
        check(r.canonical_form == occ::devirt::ring::canonical(dag, y).form,
              "the canonical text matches the trusted normalizer");
    }
    {
        // x + x + x = 3x: coefficient folding.
        expr::DAG dag;
        const expr::Id x = dag.input("x", 8);
        const expr::Id expr = dag.add(dag.add(x, x), x);
        const MbaResult r = simplify_mba(dag, expr, {});
        check(r.simplified,
              "x+x+x simplifies");
        check(bb::prove_equivalent(dag, r.value, expr).equal,
              "x+x+x simplified form is equivalent");
    }
    {
        // x*y - (y*x + 5) = -5 = 251 at width 8.
        expr::DAG dag;
        const expr::Id x = dag.input("x", 8);
        const expr::Id y = dag.input("y", 8);
        const expr::Id expr =
            dag.sub(dag.mul(x, y), dag.add(dag.mul(y, x), dag.constant(5, 8)));
        const MbaResult r = simplify_mba(dag, expr, {});
        check(r.simplified && r.value == dag.constant(251, 8),
              "x*y-(y*x+5) folds to the constant 251");
    }
    {
        // The expansion direction: (x+3)*(y-3) has a bigger canonical
        // expansion, so simplify_mba must refuse to grow the expression
        // and report unsimplified; the fragment still computes the
        // equivalent canonical form (that is its verification value).
        expr::DAG dag;
        const expr::Id x = dag.input("x", 8);
        const expr::Id y = dag.input("y", 8);
        const expr::Id expr =
            dag.mul(dag.add(x, dag.constant(3, 8)),
                    dag.sub(y, dag.constant(3, 8)));
        const RingFragment rf = deobf_ring_fragment(dag, expr);
        check(rf.ok && rf.equivalent,
              "(x+3)*(y-3) rebuild is ring-equivalent");
        check(!rf.smaller, "but the expansion is bigger, as expected");
        check(rf.form == occ::devirt::ring::canonical(dag, expr).form,
              "fragment form agrees with the trusted normalizer");
        const MbaResult r = simplify_mba(dag, expr, {});
        check(!r.simplified && r.unsimplified,
              "simplify_mba refuses to grow the expression");
        check(r.value == expr, "the original is kept");
    }
}

// -------------------------------------------------------------- pass level

void test_pass_over_function() {
    LiftedFunc f;
    const expr::Id x = f.dag.input("x", 8);
    const expr::Id y = f.dag.input("y", 8);
    f.state_vars = {{"x", 8}, {"y", 8}};
    Block b;
    b.id = 0;
    b.label = "b0";
    b.assigns.push_back({"v", f.dag.add(f.dag.bit_or(x, y),
                                        f.dag.bit_and(x, y))});
    f.blocks.push_back(std::move(b));
    f.entry = 0;

    MbaPassResult out;
    LiftedFunc cleaned = simplify_mba_pass(f, {}, out);
    check(out.expressions_simplified == 1, "the assignment was simplified");
    check(out.expressions_unsimplified == 0,
          "no other expression was left behind");
    check(cleaned.blocks[0].assigns[0].dst == "v",
          "the destination name survived");
    check(bb::prove_equivalent(cleaned.dag, cleaned.blocks[0].assigns[0].value,
                               f.dag.add(x, y))
              .equal,
          "the rewritten assignment is x+y");
}

}  // namespace

int main() {
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("-- %s\n", name);
        std::fflush(stdout);
        fn();
    };
    run("pattern_library", test_pattern_library);
    run("ring_fragment", test_ring_fragment);
    run("pass_over_function", test_pass_over_function);
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

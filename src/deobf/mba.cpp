// MBA simplification: ring-fragment canonicalization plus a proven
// pattern library.
//
// The ring fragment reimplements the word-level normalizer's algebra
// (see ring.cpp for the full width discipline; this file mirrors it
// exactly so the two expansions agree) over the fragment the spec
// assigns it -- constants, inputs, add, sub, mul, neg and zero-extending
// resizes. Everything else becomes an opaque atom, and the rebuilt
// canonical form is accepted only when `ring::prove_equal` confirms it
// -- the trusted normalizer checks the untrusted expansion, which is
// what makes the fragment sound without re-deriving the algebra.
//
// The pattern library is a table of identities over the
// boolean/arithmetic overlap, each with a justification comment. A
// pattern is matched structurally (commutative operators try both
// orders, with bindings rolled back on failure), its two sides are
// instantiated with the matched subexpressions at the target's width,
// and the rewrite is applied only when `devirt::bb::prove_equivalent` proves the
// instantiation equal -- ring first, then SAT. Two gates stand between a
// match and a rewrite:
//
//   - the rewrite must not grow the expression (reachable-node count),
//     so "simplification" never means "bigger";
//   - the proof must actually succeed; an identity whose instantiation
//     is not equivalent is reported, never applied.
//
// The bottom-up pass iterates to a fixpoint; the non-growing gate makes
// termination argumentative and the iteration cap backs it up.

#include "occ/deobf/mba.h"

#include <algorithm>
#include <cstdio>
#include <map>
#include <unordered_map>
#include <utility>
#include <vector>

#include "occ/devirt/ring.h"

namespace occ::deobf {

namespace {

constexpr std::size_t kMaxTerms = 4096;    // as ring.cpp
constexpr std::size_t kMaxFactors = 64;    // as ring.cpp
constexpr std::size_t kMaxDepth = 4096;    // as ring.cpp

std::uint64_t mask_of(unsigned width) {
    if (width >= 64) {
        return ~std::uint64_t{0};
    }
    return (std::uint64_t{1} << width) - 1;
}

// -------------------------------------------------------- ring fragment

using Terms = std::map<std::vector<devirt::expr::Id>, std::uint64_t>;

struct Form {
    unsigned width = 0;
    bool ok = false;
    Terms terms;
};

struct Normalizer {
    const devirt::expr::DAG* dag = nullptr;
    std::unordered_map<devirt::expr::Id, Form> memo;

    Form atom(devirt::expr::Id id, unsigned width) {
        Form f;
        f.width = width;
        f.ok = true;
        f.terms[std::vector<devirt::expr::Id>{id}] = 1;
        return f;
    }

    Form normalize(devirt::expr::Id id, unsigned depth) {
        if (!dag->valid(id)) {
            return Form{};
        }
        const devirt::expr::Node& n = dag->node(id);
        if (const auto it = memo.find(id); it != memo.end()) {
            return it->second;
        }
        if (depth > kMaxDepth) {
            return atom(id, n.width);
        }
        const std::uint64_t m = mask_of(n.width);
        const auto finish = [&](Form f) {
            if (f.ok) {
                memo.emplace(id, f);
            }
            return f;
        };

        switch (n.op) {
        case devirt::expr::Op::Const: {
            Form f;
            f.width = n.width;
            f.ok = true;
            if ((n.imm & m) != 0) {
                f.terms[std::vector<devirt::expr::Id>{}] = n.imm & m;
            }
            return finish(f);
        }
        case devirt::expr::Op::Input: {
            Form f;
            f.width = n.width;
            f.ok = true;
            f.terms[std::vector<devirt::expr::Id>{id}] = 1;
            return finish(f);
        }
        case devirt::expr::Op::Add:
        case devirt::expr::Op::Sub:
        case devirt::expr::Op::Mul: {
            const Form a = normalize(n.a, depth + 1);
            const Form b = normalize(n.b, depth + 1);
            if (!a.ok || !b.ok || a.width != n.width || b.width != n.width) {
                return atom(id, n.width);
            }
            Form f;
            f.width = n.width;
            f.ok = true;
            if (n.op == devirt::expr::Op::Add || n.op == devirt::expr::Op::Sub) {
                f.terms = a.terms;
                for (const auto& [key, coef] : b.terms) {
                    std::uint64_t& slot = f.terms[key];
                    slot = (n.op == devirt::expr::Op::Add ? slot + coef
                                                  : slot - coef) &
                           m;
                    if (slot == 0) {
                        f.terms.erase(key);
                    }
                }
                return finish(f);
            }
            if (a.terms.size() * b.terms.size() > kMaxTerms * 4) {
                return Form{};
            }
            for (const auto& [ka, ca] : a.terms) {
                for (const auto& [kb, cb] : b.terms) {
                    std::vector<devirt::expr::Id> key;
                    key.reserve(ka.size() + kb.size());
                    std::merge(ka.begin(), ka.end(), kb.begin(), kb.end(),
                               std::back_inserter(key));
                    if (key.size() > kMaxFactors) {
                        return Form{};
                    }
                    std::uint64_t& slot = f.terms[key];
                    slot = (slot + ca * cb) & m;
                    if (slot == 0) {
                        f.terms.erase(key);
                    }
                    if (f.terms.size() > kMaxTerms) {
                        return Form{};
                    }
                }
            }
            return finish(f);
        }
        case devirt::expr::Op::Neg: {
            const Form a = normalize(n.a, depth + 1);
            if (!a.ok || a.width != n.width) {
                return atom(id, n.width);
            }
            Form f;
            f.width = n.width;
            f.ok = true;
            for (const auto& [key, coef] : a.terms) {
                const std::uint64_t negated = (0 - coef) & m;
                if (negated != 0) {
                    f.terms[key] = negated;
                }
            }
            return finish(f);
        }
        case devirt::expr::Op::Resize: {
            const Form inner = normalize(n.a, depth + 1);
            if (!inner.ok) {
                return Form{};
            }
            const unsigned inner_width = dag->width(n.a);
            if (inner_width < n.width) {
                // Zero extension of a constant is that constant at the
                // wider width; zero extension of anything else is an atom
                // the ring cannot relate (same rule as ring.cpp).
                if (inner.terms.size() == 1 &&
                    inner.terms.begin()->first.empty()) {
                    Form f;
                    f.width = n.width;
                    f.ok = true;
                    const std::uint64_t value = inner.terms.begin()->second;
                    if (value != 0) {
                        f.terms[std::vector<devirt::expr::Id>{}] = value;
                    }
                    return finish(f);
                }
                return atom(id, n.width);
            }
            return atom(id, n.width);  // truncation: a mod reduction
        }
        default:
            // Bitwise ops, comparisons, selects, shifts: atoms.
            return atom(id, n.width);
        }
    }
};

// Rebuilds the canonical DAG for a term list: monomials sorted by (factor
// count descending, factor ids ascending), each scaled by its
// coefficient, folded together with additions. Deterministic by
// construction; hash-consing deduplicates the shared atoms.
devirt::expr::Id rebuild_terms(devirt::expr::DAG& dag, const Terms& terms, unsigned width) {
    if (terms.empty()) {
        return dag.constant(0, width);
    }
    std::vector<std::pair<std::vector<devirt::expr::Id>, std::uint64_t>> sorted;
    sorted.reserve(terms.size());
    for (const auto& [key, coef] : terms) {
        sorted.emplace_back(key, coef);
    }
    std::sort(sorted.begin(), sorted.end(),
              [](const auto& lhs, const auto& rhs) {
                  if (lhs.first.size() != rhs.first.size()) {
                      return lhs.first.size() > rhs.first.size();
                  }
                  return lhs.first < rhs.first;
              });
    devirt::expr::Id acc = devirt::expr::kNoId;
    for (const auto& [key, coef] : sorted) {
        devirt::expr::Id mono = devirt::expr::kNoId;
        for (const devirt::expr::Id f : key) {
            mono = mono == devirt::expr::kNoId ? f : dag.mul(mono, f);
        }
        if (mono == devirt::expr::kNoId) {
            mono = dag.constant(1, width);
        }
        devirt::expr::Id term = mono;
        if (coef != 1) {
            term = dag.mul(mono, dag.constant(coef, width));
        }
        acc = acc == devirt::expr::kNoId ? term : dag.add(acc, term);
    }
    return acc;
}

// Reachable-node count, used as the "complexity" a simplification may
// not increase.
std::uint64_t count_nodes(const devirt::expr::DAG& dag, devirt::expr::Id id) {
    std::vector<devirt::expr::Id> stack{id};
    std::vector<bool> seen(dag.size(), false);
    std::uint64_t count = 0;
    while (!stack.empty()) {
        const devirt::expr::Id cur = stack.back();
        stack.pop_back();
        if (!dag.valid(cur) || seen[cur]) {
            continue;
        }
        seen[cur] = true;
        ++count;
        const devirt::expr::Node& n = dag.node(cur);
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

// A pattern is a template over named placeholder inputs, built once in a
// scratch DAG at a fixed width (8). Matching is structural and ignores
// template widths; the instantiated sides are rebuilt at the target
// expression's width, so a width mismatch between the template and the
// target never leaks into the rewrite -- and even if it did, the
// equivalence proof would reject the rewrite.
struct Pattern {
    const char* name;
    unsigned num_inputs;
    devirt::expr::Id lhs;   // template node ids, valid in the set's DAG
    devirt::expr::Id rhs;
    const char* justification;
};

struct PatternSet {
    devirt::expr::DAG dag;
    std::vector<Pattern> patterns;
};

devirt::expr::Id tpl_input(devirt::expr::DAG& dag, unsigned idx) {
    return dag.input("p" + std::to_string(idx), 8);
}

// Builds the pattern templates once. The templates are pure data after
// construction; the set owns the DAG their node ids live in.
const PatternSet& pattern_set() {
    static const PatternSet set = [] {
        PatternSet s;
        devirt::expr::DAG& t = s.dag;
        const devirt::expr::Id x = tpl_input(t, 0);
        const devirt::expr::Id y = tpl_input(t, 1);
        const devirt::expr::Id z = tpl_input(t, 2);
        const devirt::expr::Id c1 = t.constant(1, 8);
        const devirt::expr::Id c2 = t.constant(2, 8);
        const devirt::expr::Id c3 = t.constant(3, 8);

        const auto P = [&](const char* name, unsigned n, devirt::expr::Id lhs,
                           devirt::expr::Id rhs, const char* why) {
            s.patterns.push_back(Pattern{name, n, lhs, rhs, why});
        };

        P("or_and_sum", 2, t.add(t.bit_or(x, y), t.bit_and(x, y)),
          t.add(x, y),
          "x|y = (x^y) + (x&y) because x^y and x&y occupy disjoint bits, "
          "and x+y = (x^y) + 2*(x&y)");
        P("xor_and_double", 2,
          t.add(t.bit_xor(x, y), t.mul(c2, t.bit_and(x, y))), t.add(x, y),
          "the standard decomposition: x+y = (x^y) + 2*(x&y)");
        P("or_minus_xor", 2, t.sub(t.bit_or(x, y), t.bit_xor(x, y)),
          t.bit_and(x, y),
          "x|y = (x^y) + (x&y) over disjoint bits; subtract (x^y)");
        P("sub_and", 2, t.sub(x, t.bit_and(x, y)), t.bit_and(x, t.bit_not(y)),
          "x - (x&y): the bits of x that y also has are subtracted away; "
          "no borrows because x&y is a subset of x");
        P("and_split", 2, t.add(t.bit_and(x, y), t.bit_and(x, t.bit_not(y))),
          x, "the bits of x partitioned by y cover x");
        P("or_minus_y", 2, t.sub(t.bit_or(x, y), y),
          t.bit_and(x, t.bit_not(y)), "x|y - y removes y's bits; x&~y is left");
        P("and_distrib", 3, t.bit_or(t.bit_and(x, y), t.bit_and(x, z)),
          t.bit_and(x, t.bit_or(y, z)), "bitwise distributivity");
        P("or_distrib", 3, t.bit_and(t.bit_or(x, y), t.bit_or(x, z)),
          t.bit_or(x, t.bit_and(y, z)), "bitwise dual distributivity");
        P("xor_and_left", 2, t.bit_and(t.bit_xor(x, y), x),
          t.bit_and(x, t.bit_not(y)),
          "(x^y)&x keeps x's bits except where y also sets them");
        P("xor_assoc", 2, t.bit_xor(t.bit_xor(x, y), x), y,
          "xor is associative and an involution");
        P("add_sub_left", 2, t.sub(t.add(x, y), x), y, "ring cancellation");
        P("add_sub_right", 2, t.sub(t.add(x, y), y), x, "ring cancellation");
        P("sub_inside", 2, t.add(x, t.sub(y, x)), y,
          "x + (y - x) = y in every ring");
        P("absorption_and", 2, t.bit_and(x, t.bit_or(x, y)), x,
          "x & (x|y) = x");
        P("absorption_or", 2, t.bit_or(x, t.bit_and(x, y)), x,
          "x | (x&y) = x");
        P("shift_add", 2, t.add(t.shl(x, c1), x), t.mul(c3, x),
          "(x<<1) + x = 3x in Z/2^w");
        P("not_plus_one", 1, t.add(t.bit_not(x), c1), t.neg(x),
          "~x + 1 = -x in two's complement");
        return s;
    }();
    return set;
}

// Structural matching. `binds` maps placeholder ordinal -> target node;
// every placeholder must bind consistently. Commutative binary nodes try
// the mirrored child order when the natural one fails, rolling the
// partial bindings back first so the next attempt starts clean.
bool match_node(const devirt::expr::DAG& tpl, devirt::expr::Id pid, const devirt::expr::DAG& tgt,
                devirt::expr::Id tid, std::vector<devirt::expr::Id>& binds) {
    if (!tpl.valid(pid) || !tgt.valid(tid)) {
        return false;
    }
    const devirt::expr::Node& p = tpl.node(pid);
    const devirt::expr::Node& t = tgt.node(tid);
    if (p.op == devirt::expr::Op::Input) {
        const std::size_t idx = static_cast<std::size_t>(p.imm);
        if (idx >= binds.size()) {
            return false;
        }
        if (binds[idx] != devirt::expr::kNoId) {
            return binds[idx] == tid;
        }
        binds[idx] = tid;
        return true;
    }
    if (p.op != t.op) {
        return false;
    }
    if (p.op == devirt::expr::Op::Const) {
        return p.imm == t.imm;
    }
    if (p.op == devirt::expr::Op::Resize) {
        if (p.width != t.width) {
            return false;
        }
        return match_node(tpl, p.a, tgt, t.a, binds);
    }
    // Unary.
    if (p.b == devirt::expr::kNoId && p.c == devirt::expr::kNoId) {
        return match_node(tpl, p.a, tgt, t.a, binds);
    }
    // Select: children are ordered.
    if (p.c != devirt::expr::kNoId) {
        const std::vector<devirt::expr::Id> saved = binds;
        if (match_node(tpl, p.a, tgt, t.a, binds) &&
            match_node(tpl, p.b, tgt, t.b, binds) &&
            match_node(tpl, p.c, tgt, t.c, binds)) {
            return true;
        }
        binds = saved;
        return false;
    }
    // Binary. Commutative operators retry with the children exchanged.
    const bool comm = p.op == devirt::expr::Op::Add || p.op == devirt::expr::Op::Mul ||
                      p.op == devirt::expr::Op::And || p.op == devirt::expr::Op::Or ||
                      p.op == devirt::expr::Op::Xor || p.op == devirt::expr::Op::CmpEQ;
    const std::vector<devirt::expr::Id> saved = binds;
    if (match_node(tpl, p.a, tgt, t.a, binds) &&
        match_node(tpl, p.b, tgt, t.b, binds)) {
        return true;
    }
    binds = saved;
    if (comm && match_node(tpl, p.a, tgt, t.b, binds) &&
        match_node(tpl, p.b, tgt, t.a, binds)) {
        return true;
    }
    binds = saved;
    return false;
}

// Rebuilds a template node with the bindings substituted, at `width`
// (the target root's width, so template constants scale with the target).
devirt::expr::Id rebuild(const devirt::expr::DAG& tpl, devirt::expr::Id tid, devirt::expr::DAG& out,
                 const std::vector<devirt::expr::Id>& binds, unsigned width) {
    if (!tpl.valid(tid)) {
        return devirt::expr::kNoId;
    }
    const devirt::expr::Node& n = tpl.node(tid);
    if (n.op == devirt::expr::Op::Const) {
        return out.constant(n.imm, width);
    }
    if (n.op == devirt::expr::Op::Input) {
        const std::size_t idx = static_cast<std::size_t>(n.imm);
        return idx < binds.size() ? binds[idx] : devirt::expr::kNoId;
    }
    if (n.op == devirt::expr::Op::Resize) {
        const devirt::expr::Id inner = rebuild(tpl, n.a, out, binds, width);
        return inner == devirt::expr::kNoId ? devirt::expr::kNoId : out.resize(inner, n.width);
    }
    if (n.op == devirt::expr::Op::Select) {
        const devirt::expr::Id a = rebuild(tpl, n.a, out, binds, width);
        const devirt::expr::Id b = rebuild(tpl, n.b, out, binds, width);
        const devirt::expr::Id c = rebuild(tpl, n.c, out, binds, width);
        if (a == devirt::expr::kNoId || b == devirt::expr::kNoId || c == devirt::expr::kNoId) {
            return devirt::expr::kNoId;
        }
        return out.select(c, a, b);
    }
    if (n.b == devirt::expr::kNoId && n.c == devirt::expr::kNoId) {
        const devirt::expr::Id a = rebuild(tpl, n.a, out, binds, width);
        return a == devirt::expr::kNoId ? devirt::expr::kNoId : out.unary(n.op, a);
    }
    const devirt::expr::Id a = rebuild(tpl, n.a, out, binds, width);
    const devirt::expr::Id b = rebuild(tpl, n.b, out, binds, width);
    if (a == devirt::expr::kNoId || b == devirt::expr::kNoId) {
        return devirt::expr::kNoId;
    }
    return out.binary(n.op, a, b);
}

// Post-order over the reachable nodes of `root` (children before their
// parents), deduplicated. The stack discipline pushes a node's children
// before the node itself completes, so a node is appended only after
// every child was appended, even when subexpressions are shared.
std::vector<devirt::expr::Id> postorder(const devirt::expr::DAG& dag, devirt::expr::Id root) {
    std::vector<devirt::expr::Id> order;
    std::vector<bool> seen(dag.size(), false);
    std::vector<bool> done(dag.size(), false);
    std::vector<devirt::expr::Id> stack{root};
    while (!stack.empty()) {
        const devirt::expr::Id cur = stack.back();
        if (!dag.valid(cur) || done[cur]) {
            stack.pop_back();
            continue;
        }
        const devirt::expr::Node& n = dag.node(cur);
        devirt::expr::Id child = devirt::expr::kNoId;
        if (dag.valid(n.a) && !seen[n.a]) {
            child = n.a;
        } else if (dag.valid(n.b) && !seen[n.b]) {
            child = n.b;
        } else if (dag.valid(n.c) && !seen[n.c]) {
            child = n.c;
        }
        if (child != devirt::expr::kNoId) {
            seen[child] = true;
            stack.push_back(child);
            continue;
        }
        done[cur] = true;
        order.push_back(cur);
        stack.pop_back();
    }
    return order;
}

// Rebuilds `root` applying every substitution in `subst` (children
// first, so rewrites compose: a replacement that itself contains a
// rewritten node is rewritten again on the way down).
devirt::expr::Id rewrite_root(devirt::expr::DAG& dag, devirt::expr::Id root,
                      const std::unordered_map<devirt::expr::Id, devirt::expr::Id>& subst) {
    std::unordered_map<devirt::expr::Id, devirt::expr::Id> memo;
    const auto rec = [&](auto&& self, devirt::expr::Id id) -> devirt::expr::Id {
        const auto it = subst.find(id);
        if (it != subst.end()) {
            return self(self, it->second);
        }
        const auto mi = memo.find(id);
        if (mi != memo.end()) {
            return mi->second;
        }
        if (!dag.valid(id)) {
            return id;
        }
        const devirt::expr::Node& n = dag.node(id);
        const devirt::expr::Id a = dag.valid(n.a) ? self(self, n.a) : n.a;
        const devirt::expr::Id b = dag.valid(n.b) ? self(self, n.b) : n.b;
        const devirt::expr::Id c = dag.valid(n.c) ? self(self, n.c) : n.c;
        devirt::expr::Id out = id;
        if (n.op == devirt::expr::Op::Resize) {
            out = dag.resize(a, n.width);
        } else if (n.op == devirt::expr::Op::Select) {
            out = dag.select(c, a, b);
        } else if (n.b == devirt::expr::kNoId && n.c == devirt::expr::kNoId) {
            out = (a == n.a) ? id : dag.unary(n.op, a);
        } else {
            out = (a == n.a && b == n.b) ? id : dag.binary(n.op, a, b);
        }
        memo.emplace(id, out);
        return out;
    };
    return rec(rec, root);
}

}  // namespace

RingFragment deobf_ring_fragment(devirt::expr::DAG& dag, devirt::expr::Id id) {
    RingFragment out;
    if (!dag.valid(id)) {
        return out;
    }
    Normalizer nz;
    nz.dag = &dag;
    const Form f = nz.normalize(id, 0);
    out.ok = f.ok;
    if (!f.ok) {
        return out;
    }
    out.form = occ::devirt::ring::canonical(dag, id).form;
    const devirt::expr::Id rebuilt = rebuild_terms(dag, f.terms, dag.width(id));
    out.value = rebuilt;
    out.equivalent = occ::devirt::ring::prove_equal(dag, rebuilt, id) ==
                     occ::devirt::ring::Verdict::Equal;
    out.smaller = count_nodes(dag, rebuilt) <= count_nodes(dag, id);
    return out;
}

MbaResult simplify_mba(devirt::expr::DAG& dag, devirt::expr::Id id, const MbaOptions& options) {
    MbaResult r;
    r.value = id;
    if (!dag.valid(id)) {
        r.unsimplified = true;
        r.note = "invalid expression";
        return r;
    }

    // ------------------------------------------------ ring fragment
    if (options.enable_ring) {
        const RingFragment rf = deobf_ring_fragment(dag, id);
        r.ring_ok = rf.ok;
        if (rf.ok) {
            r.canonical_form = rf.form;
        }
        if (rf.ok && rf.value != id && rf.value != devirt::expr::kNoId &&
            rf.equivalent && rf.smaller) {
            MbaStep s;
            s.from = dag.pretty(id);
            s.to = dag.pretty(rf.value);
            s.kind = "ring";
            s.method = devirt::bb::Method::Ring;
            s.nodes_before = count_nodes(dag, id);
            s.nodes_after = count_nodes(dag, rf.value);
            s.evidence = "ring canonical form: " + rf.form;
            r.steps.push_back(std::move(s));
            r.value = rf.value;
            r.simplified = true;
        } else if (rf.ok && !rf.equivalent) {
            r.note += "ring rebuild not equivalent; rejected. ";
        }
    }

    // ------------------------------------------------- pattern library
    if (options.enable_patterns) {
        const PatternSet& set = pattern_set();
        devirt::expr::Id cur = r.value;
        for (std::size_t round = 0; round < options.max_iterations; ++round) {
            const std::vector<devirt::expr::Id> order = postorder(dag, cur);
            std::unordered_map<devirt::expr::Id, devirt::expr::Id> subst;
            bool any = false;
            for (const devirt::expr::Id node : order) {
                if (count_nodes(dag, node) > options.max_pattern_subexpr_nodes) {
                    continue;  // heuristic: keep the SAT queries small
                }
                for (const Pattern& pat : set.patterns) {
                    std::vector<devirt::expr::Id> binds(pat.num_inputs, devirt::expr::kNoId);
                    if (!match_node(set.dag, pat.lhs, dag, node, binds)) {
                        continue;
                    }
                    const unsigned w = dag.width(node);
                    const devirt::expr::Id lhs_inst =
                        rebuild(set.dag, pat.lhs, dag, binds, w);
                    const devirt::expr::Id rhs_inst =
                        rebuild(set.dag, pat.rhs, dag, binds, w);
                    if (lhs_inst == devirt::expr::kNoId || rhs_inst == devirt::expr::kNoId) {
                        continue;
                    }
                    const devirt::bb::Equivalence e =
                        devirt::bb::prove_equivalent(dag, lhs_inst, rhs_inst);
                    if (!e.equal) {
                        continue;
                    }
                    const std::uint64_t before = count_nodes(dag, lhs_inst);
                    const std::uint64_t after = count_nodes(dag, rhs_inst);
                    if (after > before) {
                        MbaStep rejected;
                        rejected.from = dag.pretty(lhs_inst);
                        rejected.to = dag.pretty(rhs_inst);
                        rejected.kind = std::string("pattern:") + pat.name;
                        rejected.method = e.method;
                        rejected.nodes_before = before;
                        rejected.nodes_after = after;
                        rejected.accepted = false;
                        rejected.evidence =
                            "proven equivalent but grows the expression";
                        r.steps.push_back(std::move(rejected));
                        continue;
                    }
                    subst[node] = rhs_inst;
                    MbaStep s;
                    s.from = dag.pretty(lhs_inst);
                    s.to = dag.pretty(rhs_inst);
                    s.kind = std::string("pattern:") + pat.name;
                    s.method = e.method;
                    s.nodes_before = before;
                    s.nodes_after = after;
                    s.conflicts = e.conflicts;
                    s.propagations = e.propagations;
                    if (e.method == devirt::bb::Method::Ring) {
                        s.evidence = e.witness;
                    } else {
                        char buf[96];
                        std::snprintf(
                            buf, sizeof(buf), "conflicts=%llu propagations=%llu",
                            static_cast<unsigned long long>(e.conflicts),
                            static_cast<unsigned long long>(e.propagations));
                        s.evidence = buf;
                    }
                    r.steps.push_back(std::move(s));
                    any = true;
                    break;  // one rewrite per node per round
                }
            }
            if (!any) {
                break;
            }
            const devirt::expr::Id next = rewrite_root(dag, cur, subst);
            if (next == cur) {
                break;  // structural no-op
            }
            cur = next;
            r.value = cur;
            r.simplified = true;
        }
    }

    r.unsimplified = !r.simplified;
    if (r.unsimplified && r.note.empty() && options.enable_patterns) {
        r.note = "no proven simplification found";
    }
    return r;
}

LiftedFunc simplify_mba_pass(const LiftedFunc& func, const MbaOptions& options,
                             MbaPassResult& out) {
    LiftedFunc work = func;
    for (Block& block : work.blocks) {
        for (Assign& assign : block.assigns) {
            if (!work.dag.valid(assign.value)) {
                continue;
            }
            MbaResult mr = simplify_mba(work.dag, assign.value, options);
            for (MbaStep& s : mr.steps) {
                s.block = block.id;
                s.dst = assign.dst;
                out.steps.push_back(std::move(s));
            }
            if (mr.simplified) {
                assign.value = mr.value;
                ++out.expressions_simplified;
            } else {
                ++out.expressions_unsimplified;
            }
        }
    }
    out.func = work;
    return out.func;
}

}  // namespace occ::deobf

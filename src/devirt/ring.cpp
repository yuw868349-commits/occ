// The ring normalizer: bit-vector expressions as polynomials over Z/2^w.
//
// The implementation is a canonical form and nothing else: every node
// normalizes to a polynomial (a map from a monomial to a coefficient,
// coefficients folded modulo the node's width), and two nodes are
// proven equal when their forms are the same. There is no search, no
// saturation loop and no rule set to get wrong -- the algebra is the
// ring's, and the only thing that can end a normalization early is the
// expansion budget.
//
// Monomials are multisets of atom ids: a factor list kept sorted, with
// repetition carrying the exponent (`[x x y]` is x^2*y). Over a ring
// that is exactly what multiplication produces -- no division, so no
// need for a field and none of the normal-form problems that come with
// one. Coefficients are unsigned and wrap, which is how the machine's
// arithmetic behaves.
//
// The width discipline is the delicate part and it is worth stating
// plainly, because getting it wrong makes the normalizer claim
// equalities that are false:
//
//   - A polynomial belongs to a width. It says "this value, modulo
//     2^w". The same terms at a different width are a different
//     statement: `x*y` at width 8 is `(x*y) mod 256`, at width 64 it is
//     the product itself, and for x = y = 200 those are different
//     numbers. Widths are therefore part of the canonical form.
//   - Arithmetic nodes are normalized only when their operands are at
//     the same width as the node, which is the shape the DAG's builder
//     produces. An operand at another width turns the node into an
//     atom instead of a silently wrong term.
//   - A zero-extending resize has the same value as its operand, so two
//     zero-extension chains compare by their operands; a truncating
//     resize is a mod-2^w reduction, which the ring at the wider width
//     cannot express, so it becomes an atom.
//   - Constants are compared as numbers, which is what makes
//     `zext(5) == 5` decidable even though the two sides live at
//     different widths.

#include "occ/devirt/ring.h"

#include <algorithm>
#include <cstdio>
#include <iterator>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace occ::devirt::ring {

namespace {

// The expansion budget. A product of sums doubles the number of terms,
// so an expression like ((a+b)*(c+d))^32 can expand past any bound; the
// normalizer gives up rather than take exponential time or memory, and
// giving up is sound because it only ever means "hand this to the SAT
// layer".
constexpr std::size_t kMaxTerms = 4096;
constexpr std::size_t kMaxFactors = 64;

std::uint64_t mask_of(unsigned width) {
    if (width >= 64) {
        return ~std::uint64_t{0};
    }
    return (std::uint64_t{1} << width) - 1;
}

// One polynomial: monomial -> coefficient. The empty monomial is the
// constant term. Coefficients are kept non-zero, so the representation
// of a polynomial is unique.
using Terms = std::map<std::vector<expr::Id>, std::uint64_t>;

struct Form {
    unsigned width = 0;
    bool ok = false;
    Terms terms;
};

struct Normalizer {
    const expr::DAG* dag = nullptr;
    std::unordered_map<expr::Id, Form> memo;

    Form atom(expr::Id id, unsigned width) {
        Form f;
        f.width = width;
        f.ok = true;
        f.terms[std::vector<expr::Id>{id}] = 1;
        return f;
    }

    Form normalize(expr::Id id, unsigned depth) {
        if (!dag->valid(id)) {
            return Form{};
        }
        const expr::Node& n = dag->node(id);
        if (const auto it = memo.find(id); it != memo.end()) {
            return it->second;
        }
        // A pathological depth becomes an atom rather than a stack
        // overflow; the DAG is a user input as far as this file is
        // concerned.
        if (depth > 4096) {
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
        case expr::Op::Const: {
            Form f;
            f.width = n.width;
            f.ok = true;
            if ((n.imm & m) != 0) {
                f.terms[std::vector<expr::Id>{}] = n.imm & m;
            }
            return finish(f);
        }
        case expr::Op::Add:
        case expr::Op::Sub:
        case expr::Op::Mul: {
            const Form a = normalize(n.a, depth + 1);
            const Form b = normalize(n.b, depth + 1);
            if (!a.ok || !b.ok || a.width != n.width || b.width != n.width) {
                return atom(id, n.width);
            }
            Form f;
            f.width = n.width;
            f.ok = true;
            if (n.op == expr::Op::Add || n.op == expr::Op::Sub) {
                f.terms = a.terms;
                for (const auto& [key, coef] : b.terms) {
                    std::uint64_t& slot = f.terms[key];
                    slot = (n.op == expr::Op::Add ? slot + coef : slot - coef) &
                           m;
                    if (slot == 0) {
                        f.terms.erase(key);
                    }
                }
                return finish(f);
            }
            // Multiplication: every pair of terms multiplies, monomials
            // merge into sorted factor lists, coefficients fold modulo
            // 2^w. The budget is checked as the product grows, because a
            // product of two wide sums is where the term count doubles.
            if (a.terms.size() * b.terms.size() > kMaxTerms * 4) {
                return Form{};  // budget: refuse, do not guess
            }
            for (const auto& [ka, ca] : a.terms) {
                for (const auto& [kb, cb] : b.terms) {
                    std::vector<expr::Id> key;
                    key.reserve(ka.size() + kb.size());
                    std::merge(ka.begin(), ka.end(), kb.begin(), kb.end(),
                               std::back_inserter(key));
                    if (key.size() > kMaxFactors) {
                        return Form{};  // budget
                    }
                    std::uint64_t& slot = f.terms[key];
                    slot = (slot + ca * cb) & m;
                    if (slot == 0) {
                        f.terms.erase(key);
                    }
                    if (f.terms.size() > kMaxTerms) {
                        return Form{};  // budget
                    }
                }
            }
            return finish(f);
        }
        case expr::Op::Neg: {
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
        case expr::Op::Resize: {
            const Form inner = normalize(n.a, depth + 1);
            if (!inner.ok) {
                return Form{};
            }
            const unsigned inner_width = dag->width(n.a);
            if (inner_width < n.width) {
                // Zero extension preserves the value. A constant stays a
                // number at the wider width; anything with atoms is only
                // equal to something at the inner width, which is a
                // different polynomial, so it stays opaque here and the
                // comparison below is the one that peels the extension.
                if (inner.terms.size() == 1 &&
                    inner.terms.begin()->first.empty()) {
                    Form f;
                    f.width = n.width;
                    f.ok = true;
                    const std::uint64_t value = inner.terms.begin()->second;
                    if (value != 0) {
                        f.terms[std::vector<expr::Id>{}] = value;
                    }
                    return finish(f);
                }
                return atom(id, n.width);
            }
            // Truncation: a mod-2^w reduction, not a ring operation.
            return atom(id, n.width);
        }
        case expr::Op::Shl: {
            const expr::Node& shift = dag->node(n.b);
            if (shift.op != expr::Op::Const) {
                return atom(id, n.width);
            }
            const std::uint64_t amount = shift.imm;
            const Form a = normalize(n.a, depth + 1);
            if (!a.ok || a.width != n.width) {
                return atom(id, n.width);
            }
            if (amount >= n.width) {
                Form f;
                f.width = n.width;
                f.ok = true;
                return finish(f);  // shifted out completely
            }
            const std::uint64_t scale = (std::uint64_t{1} << amount) & m;
            Form f;
            f.width = n.width;
            f.ok = true;
            for (const auto& [key, coef] : a.terms) {
                const std::uint64_t scaled = (coef * scale) & m;
                if (scaled != 0) {
                    f.terms[key] = scaled;
                }
            }
            return finish(f);
        }
        default:
            // Bitwise operations, comparisons, selects, variable shifts:
            // values the ring cannot decompose.
            return atom(id, n.width);
        }
    }
};

std::string term_text(const expr::DAG& dag,
                      const std::vector<expr::Id>& key) {
    std::string out;
    for (const expr::Id f : key) {
        if (!out.empty()) {
            out += '*';
        }
        out += dag.dump(f);
    }
    return out;
}

std::string poly_text(const expr::DAG& dag, const Form& f) {
    std::string out = "w" + std::to_string(f.width) + " [";
    bool first = true;
    for (const auto& [key, coef] : f.terms) {
        if (!first) {
            out += " + ";
        }
        first = false;
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      static_cast<unsigned long long>(coef));
        out += buf;
        if (!key.empty()) {
            out += '*';
            out += term_text(dag, key);
        }
    }
    if (first) {
        out += "0x0";
    }
    out += ']';
    return out;
}

std::uint64_t poly_value(const Form& f) {
    // Only meaningful for a constant polynomial -- the callers check
    // `is_constant` first. The constant term is the empty monomial.
    return f.terms.empty() ? 0 : f.terms.begin()->second;
}

bool is_constant(const Form& f) {
    return f.terms.empty() ||
           (f.terms.size() == 1 && f.terms.begin()->first.empty());
}

bool zext_inner(const expr::DAG& dag, expr::Id id, expr::Id* inner) {
    if (!dag.valid(id)) {
        return false;
    }
    const expr::Node& n = dag.node(id);
    if (n.op != expr::Op::Resize || !dag.valid(n.a)) {
        return false;
    }
    if (dag.width(n.a) >= n.width) {
        return false;  // a truncation, not an extension
    }
    *inner = n.a;
    return true;
}

}  // namespace

Canonical canonical(const expr::DAG& dag, expr::Id id) {
    Normalizer nz;
    nz.dag = &dag;
    const Form f = nz.normalize(id, 0);
    Canonical out;
    out.ok = f.ok;
    if (f.ok) {
        out.form = poly_text(dag, f);
    }
    return out;
}

Verdict prove_equal(const expr::DAG& dag, expr::Id a, expr::Id b,
                    std::string* witness) {
    if (a == b) {
        if (witness != nullptr && dag.valid(a)) {
            Normalizer nz;
            nz.dag = &dag;
            const Form f = nz.normalize(a, 0);
            *witness = f.ok ? "left=" + poly_text(dag, f) +
                                  "; right=" + poly_text(dag, f)
                            : std::string();
        }
        return Verdict::Equal;
    }

    // The comparison walks zero-extension chains: `zext(x)` equals
    // `zext(y)` exactly when x equals y, and the extension itself
    // carries no information. The walk is bounded by the nesting the
    // DAG can express, and each step removes one resize node, so it
    // terminates.
    expr::Id left = a;
    expr::Id right = b;
    for (;;) {
        Normalizer nz;
        nz.dag = &dag;
        const Form fa = nz.normalize(left, 0);
        const Form fb = nz.normalize(right, 0);
        if (!fa.ok || !fb.ok) {
            return Verdict::Unknown;  // budget spent
        }
        if (fa.width == fb.width && fa.terms == fb.terms) {
            if (witness != nullptr) {
                *witness = "left=" + poly_text(dag, fa) +
                           "; right=" + poly_text(dag, fb);
            }
            return Verdict::Equal;
        }
        if (is_constant(fa) && is_constant(fb) &&
            poly_value(fa) == poly_value(fb)) {
            if (witness != nullptr) {
                *witness = "left=" + poly_text(dag, fa) +
                           "; right=" + poly_text(dag, fb);
            }
            return Verdict::Equal;
        }
        expr::Id inner_a = expr::kNoId;
        expr::Id inner_b = expr::kNoId;
        if (!zext_inner(dag, left, &inner_a) ||
            !zext_inner(dag, right, &inner_b)) {
            return Verdict::Unknown;
        }
        left = inner_a;
        right = inner_b;
    }
}

}  // namespace occ::devirt::ring
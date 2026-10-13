// MBA (mixed boolean-arithmetic) expression simplification.
//
// An MBA obfuscation is an arithmetic expression made to look expensive
// by mixing boolean operations into it -- OLLVM's `Substitution` pass
// rewrites `x + y` as `(x | y) + (x & y)`, `x + y` as `(x ^ y) + 2*(x &
// y)`, and similar. The simplifier reverses that in two fragments:
//
//   Ring fragment. An expression built from constants, inputs, add,
//   sub, mul, neg and zero-extending resizes is a polynomial over
//   Z/2^w. It is expanded into a coefficient table (monomial -> nonzero
//   coefficient, coefficients folded mod 2^w, exactly the arithmetic
//   the machine performs), and the table is rebuilt into a canonical
//   DAG expression: monomials sorted by (factor count descending, then
//   factor ids ascending), each term scaled by its coefficient, and the
//   terms folded together in that order. The rebuild is *checked*
//   against the original with the ring layer's own normalizer
//   (`ring::prove_equal` must say Equal), so the fragment's expansion
//   code is cross-validated rather than trusted. The canonical form is
//   the fragment's notion of "simplest"; a replacement is accepted only
//   when it is provably equivalent *and* does not grow the expression
//   (reachable-node count), because an expanded product of sums can
//   legitimately grow, and growth is never a simplification.
//
//   Pattern library. A hand-written set of identities covering the
//   boolean/arithmetic overlap -- the OLLVM rewrite targets plus the
//   absorption, distribution and cancellation forms. Each pattern is a
//   template over placeholder inputs; matching is structural and
//   commutative for the commutative operators. A candidate rewrite is
//   accepted only after `devirt::bb::prove_equivalent` proves the instantiated
//   sides equal (ring first, SAT second), and only when it does not
//   grow the expression. The library is applied bottom-up to a
//   fixpoint; each accepted rewrite strictly does not increase the node
//   count, so the iteration terminates, and a hard iteration cap backs
//   that up.
//
// Everything that is tried and cannot be proven -- an identity the ring
// cannot see and the SAT layer cannot finish, a pattern whose
// instantiation is not equivalent -- is reported unproven/unsimplified,
// never applied. The pass's only commitments are the ones it proved.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "occ/devirt/bitblast.h"

#include "occ/deobf/ir.h"

namespace occ::deobf {

struct MbaOptions {
    bool enable_ring = true;
    bool enable_patterns = true;
    // Pattern matching walks the expression bottom-up; a subexpression
    // larger than this is not pattern-tried (heuristic: pattern matches
    // over huge subtrees cost a SAT query per candidate and rarely
    // rewrite at the top). Ring fragment still runs on the whole
    // expression.
    std::size_t max_pattern_subexpr_nodes = 40;
    // Cap on the bottom-up fixpoint rounds. Termination is guaranteed by
    // the non-growing rule; the cap is a backstop, not the argument.
    std::size_t max_iterations = 64;
};

// One accepted (or rejected) rewrite, for the report. `block` and `dst`
// place the rewrite: which block the expression lived in and which state
// variable it was assigned to.
struct MbaStep {
    std::uint32_t block = 0;
    std::string dst;
    std::string from;         // pretty() before
    std::string to;           // pretty() after
    std::string kind;         // "ring" or "pattern:<name>"
    devirt::bb::Method method = devirt::bb::Method::Sat;  // how equivalence was proven
    std::uint64_t nodes_before = 0;
    std::uint64_t nodes_after = 0;
    std::uint64_t conflicts = 0;
    std::uint64_t propagations = 0;
    std::string evidence;     // ring witness / SAT stats / note
    bool accepted = true;
};

// The result of simplifying one expression.
struct MbaResult {
    devirt::expr::Id value = devirt::expr::kNoId;   // the simplified expression
    std::vector<MbaStep> steps;
    bool simplified = false;        // value differs from the input
    bool ring_ok = false;           // the ring fragment ran to completion
    std::string canonical_form;     // ring canonical text when computed
    bool unsimplified = false;      // nothing could be proven smaller
    std::string note;               // why, when unsimplified
};

// The ring fragment alone: expands `id` into its coefficient table and
// rebuilds the canonical DAG. `equivalent` is true only when
// `ring::prove_equal(rebuilt, id)` answered Equal. `smaller` compares
// reachable-node counts; the caller decides whether to adopt.
struct RingFragment {
    devirt::expr::Id value = devirt::expr::kNoId;
    bool ok = false;          // expansion within budget
    bool equivalent = false;  // ring::prove_equal confirmed
    bool smaller = false;     // rebuilt does not grow the expression
    std::string form;         // canonical polynomial text
};
[[nodiscard]] RingFragment deobf_ring_fragment(devirt::expr::DAG& dag, devirt::expr::Id id);

// Simplifies one expression: ring fragment, then the pattern library to
// a fixpoint, each step proven and recorded. `dag` is grown with the
// rebuilt nodes; the original expression's nodes are never removed (the
// DAG is immutable), so `value` is the new root.
[[nodiscard]] MbaResult simplify_mba(devirt::expr::DAG& dag, devirt::expr::Id id,
                                     const MbaOptions& options);

// Applies `simplify_mba` to every assignment value of `func` (a copy is
// returned; `func` is not modified). Steps are tagged with the block id
// and the destination name they came from.
struct MbaPassResult {
    std::vector<MbaStep> steps;
    std::size_t expressions_simplified = 0;
    std::size_t expressions_unsimplified = 0;
    LiftedFunc func;
};
[[nodiscard]] LiftedFunc simplify_mba_pass(const LiftedFunc& func,
                                           const MbaOptions& options,
                                           MbaPassResult& out);

}  // namespace occ::deobf

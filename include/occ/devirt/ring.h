// Word-level normalization: the ring of bit-vectors, over Z/2^w.
//
// The bit-blaster answers "are these two expressions equal on every
// input" with a SAT query over a circuit, and that answer costs what the
// circuit costs. For arithmetic it costs a great deal: multiplier
// equivalence is the textbook hard instance for a CDCL solver, it climbs
// steeply with width, and a 64-bit handler that computes an address as
// `(x + 3) * (y - 3)` is ordinary virtual-machine code.
//
// This layer answers the same question without a circuit. A bit-vector
// expression built from constants, addition, subtraction, negation and
// multiplication is a polynomial over the ring Z/2^w, and polynomials
// have a canonical form: expand, collect like monomials, fold the
// coefficients modulo 2^w. Two expressions are equal when their
// canonical forms are the same polynomial -- for every input, at once,
// by the ring axioms rather than by search. The canonical form of
// `(x + 3) * (y - 3)` and of `x*y - 3*x + 3*y - 9` is the same
// polynomial, found by expanding a handful of terms, and it does not
// matter whether the expressions are 8 bits wide or 64.
//
// Where the fragment ends, the normalization is still defined: any
// operation outside the ring -- a bitwise operation, a comparison, a
// shift by a computed amount, a truncating resize -- becomes an opaque
// atom, an unknown value that the ring cannot relate to anything else.
// Two expressions that are equal become equal canonical forms even with
// atoms in them; two expressions whose difference is invisible to the
// ring stay "unknown" and are handed to the SAT solver, which is the
// only layer that can relate atoms to each other.
//
// The result is not just a yes: the canonical form itself is the
// certificate. Checking it means recomputing the normalization of both
// sides and comparing -- a procedure with no search in it, cheap enough
// to run on a verifier that trusts nothing.
//
// Soundness rests on the widths being the DAG's widths. Every operation
// is normalized at its own width and its coefficients are folded
// modulo 2^w, which is exactly the arithmetic the DAG's evaluation
// performs; a zero-extending resize is the identity in the wider ring
// and normalizes to its operand, while a truncating one is not
// representable and becomes an atom. The normalizer therefore never
// claims an equality the expressions do not have; when it cannot see
// one, it says so and the SAT layer is asked.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "occ/devirt/expr.h"

namespace occ::devirt::ring {

// What the ring normalizer could decide about `a == b`.
enum class Verdict : std::uint8_t {
    // The canonical forms are the same polynomial. Equal on every input.
    Equal,
    // The normalizer cannot see an equality: the expressions differ in
    // an atom the ring cannot relate, or the expansion budget was
    // reached. Says nothing about the actual answer.
    Unknown,
};

// The canonical form of `id`, as a printable polynomial over the DAG's
// atoms. `ok` is false when the expansion budget was exceeded, in which
// case the text is empty and no conclusion may be drawn from it.
struct Canonical {
    bool ok = false;
    std::string form;
};

// Normalizes one expression. The form is canonical: two expressions with
// equal values in the ring produce the same text.
[[nodiscard]] Canonical canonical(const expr::DAG& dag, expr::Id id);

// Decides `a == b` by normalization. When the verdict is Equal and
// `witness` is not null, the two canonical forms are written to it as
// "left=<form>; right=<form>" -- the certificate a checker recomputes.
[[nodiscard]] Verdict prove_equal(const expr::DAG& dag, expr::Id a,
                                  expr::Id b, std::string* witness = nullptr);

}  // namespace occ::devirt::ring
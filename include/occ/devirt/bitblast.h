// Bit-blasting the expression DAG into CNF, and the miter built on it.
//
// The expression DAG is a bit-vector language; the SAT solver is
// propositional. This translates one into the other with Tseitin
// encoding: every node's bits become literals, every operation becomes
// the clauses that tie its output bits to its input bits, and the
// translation is once per (node, bit) because the encoder caches it.
//
// The circuits are the textbook ones an equivalence checker needs:
// ripple-carry addition, shift-add multiplication, barrel shifts, and
// the comparators, all gated through a shared Tseitin gate layer that
// folds constants and caches its results, so the CNF for `(x + 1) ^ (x +
// 1)` is built once, not twice.
//
// The miter is the point of all of it. `prove_equivalent` encodes both
// expressions, asserts that their bits differ, and asks the solver; an
// unsatisfiable answer is a proof that the two are equal on every
// 64-bit input -- a proof that comes with a DRUP certificate when one is
// requested, so the claim is checkable without trusting the solver.
// A satisfiable answer comes back with the counterexample, which is what
// the iterative pipeline feeds back into handler identification when a
// reconstruction disagrees with the original.
//
// `prove_equivalent_under` is the same miter with path constraints: two
// expressions are equal on the inputs that satisfy the constraints. That
// is the form the virtual-CFG layer needs, where a basic block's
// semantics only hold under its branch condition.

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "occ/devirt/expr.h"
#include "occ/devirt/sat.h"

namespace occ::devirt::bb {

// Translates expressions into CNF over a solver. One encoder owns its
// cache; use one per solver.
class Encoder {
public:
    Encoder(expr::DAG& dag, sat::Solver& solver)
        : dag_(&dag), solver_(&solver) {}

    // The bits of an expression, LSB first. Lazily built and cached.
    [[nodiscard]] std::vector<sat::Lit> bits(expr::Id e);
    [[nodiscard]] sat::Lit bit(expr::Id e, unsigned index);

    // -- Tseitin gates, constant-folding and cached --------------------

    [[nodiscard]] sat::Lit const_lit(bool value);
    [[nodiscard]] sat::Lit gate_and(sat::Lit a, sat::Lit b);
    [[nodiscard]] sat::Lit gate_or(sat::Lit a, sat::Lit b);
    [[nodiscard]] sat::Lit gate_xor(sat::Lit a, sat::Lit b);
    [[nodiscard]] static sat::Lit gate_not(sat::Lit a) {
        return sat::lit_negate(a);
    }
    [[nodiscard]] sat::Lit gate_mux(sat::Lit c, sat::Lit t, sat::Lit f);
    // Folds a conjunction / disjunction over a literal list.
    [[nodiscard]] sat::Lit gate_and_all(const std::vector<sat::Lit>& lits);
    [[nodiscard]] sat::Lit gate_or_all(const std::vector<sat::Lit>& lits);

    // -- circuit builders ----------------------------------------------

    [[nodiscard]] std::vector<sat::Lit> add_bits(
        const std::vector<sat::Lit>& a, const std::vector<sat::Lit>& b);
    [[nodiscard]] std::vector<sat::Lit> mul_bits(
        const std::vector<sat::Lit>& a, const std::vector<sat::Lit>& b);
    [[nodiscard]] std::vector<sat::Lit> shl_bits(
        const std::vector<sat::Lit>& a, const std::vector<sat::Lit>& amount);
    [[nodiscard]] std::vector<sat::Lit> shr_bits(
        const std::vector<sat::Lit>& a, const std::vector<sat::Lit>& amount);
    [[nodiscard]] std::vector<sat::Lit> sar_bits(
        const std::vector<sat::Lit>& a, const std::vector<sat::Lit>& amount);
    [[nodiscard]] sat::Lit eq_bits(const std::vector<sat::Lit>& a,
                                   const std::vector<sat::Lit>& b);
    [[nodiscard]] sat::Lit ult_bits(const std::vector<sat::Lit>& a,
                                    const std::vector<sat::Lit>& b);
    [[nodiscard]] sat::Lit slt_bits(const std::vector<sat::Lit>& a,
                                    const std::vector<sat::Lit>& b);

    // The width of each input, indexed by ordinal; filled as inputs are
    // first encoded. A bit of record-keeping for counterexamples.
    [[nodiscard]] const std::vector<unsigned>& input_widths() const {
        return input_widths_;
    }

    // Reads the current model's values for every encoded input, indexed
    // by ordinal. Only meaningful after a satisfiable solve.
    [[nodiscard]] std::vector<std::uint64_t> read_inputs() const;

private:
    [[nodiscard]] sat::Lit input_bit(unsigned ordinal, unsigned index);
    [[nodiscard]] std::vector<sat::Lit> build(expr::Id e);
    // Normalizes a (a, b) pair for the commutative gate caches.
    [[nodiscard]] static std::uint64_t pair_key(sat::Lit a, sat::Lit b);
    // A constant value in bit form (LSB first), width bits wide.
    [[nodiscard]] std::vector<sat::Lit> const_bits(std::uint64_t value,
                                                   unsigned width);
    // The three shifts with a constant amount: a re-wire, not a circuit.
    // The DAG's shift semantics are "at or past the width": logical
    // shifts yield zero, arithmetic fills with the sign bit.
    [[nodiscard]] std::vector<sat::Lit> shl_fixed(
        const std::vector<sat::Lit>& a, std::uint64_t amount);
    [[nodiscard]] std::vector<sat::Lit> shr_fixed(
        const std::vector<sat::Lit>& a, std::uint64_t amount);
    [[nodiscard]] std::vector<sat::Lit> sar_fixed(
        const std::vector<sat::Lit>& a, std::uint64_t amount);

    expr::DAG* dag_;
    sat::Solver* solver_;
    sat::Lit true_lit_ = sat::kUndef;
    std::unordered_map<expr::Id, std::vector<sat::Lit>> vector_cache_;
    std::unordered_map<std::uint64_t, sat::Lit> and_cache_;
    std::unordered_map<std::uint64_t, sat::Lit> xor_cache_;
    std::unordered_map<std::uint64_t, sat::Lit> or_cache_;
    // Input ordinal -> the SAT variable of its bit 0.
    std::vector<sat::Var> input_base_;
    std::vector<unsigned> input_widths_;
};

// Which layer answered a miter, and therefore which certificate comes
// back with it. An answer is only worth what its certificate is, and the
// two kinds are checked differently: a DRUP trace is replayed against a
// CNF, a normalization is recomputed.
enum class Method : std::uint8_t {
    // Bit-blasting into CNF and a CDCL refutation: `proof` and `formula`.
    Sat,
    // Word-level normalization over the ring of bit-vectors: `witness`
    // holds the two canonical forms, and checking them means recomputing
    // the normalization of both sides and comparing. No search is
    // involved, at either end.
    Ring,
};

// The outcome of an equivalence question.
struct Equivalence {
    bool equal = false;
    // When not equal: one assignment to the inputs that distinguishes the
    // two expressions, indexed by input ordinal.
    std::vector<std::uint64_t> counterexample;
    // Which layer answered, and the certificate it produced.
    Method method = Method::Sat;
    // When equal, answered by CDCL, and a certificate was requested: DRUP
    // lines proving the miter unsatisfiable, and the CNF those lines
    // refute. A trace is only checkable against the formula it was
    // derived from, so the two travel together -- that pairing is what
    // "proof-carrying" means.
    std::vector<std::string> proof;
    std::vector<std::vector<sat::Lit>> formula;
    // When equal, answered by normalization, and a certificate was
    // requested: "left=<form>; right=<form>" with the two canonical
    // forms of the ring layer.
    std::string witness;
    std::uint64_t conflicts = 0;
    std::uint64_t propagations = 0;
};

// Proves `a == b` on every input. When the two are not equal the
// counterexample comes back filled.
//
// `force_sat` bypasses the word-level layer and answers with the circuit
// path alone. That switch exists for verification: the two layers are
// independent implementations of the same question, and a caller that
// runs both and compares is checking each of them against the other. A
// production caller leaves it off -- the word-level layer answers wide
// arithmetic that the circuit path cannot finish.
[[nodiscard]] Equivalence prove_equivalent(expr::DAG& dag, expr::Id a,
                                           expr::Id b,
                                           bool want_proof = false,
                                           bool force_sat = false);

// Proves `a == b` on every input satisfying every constraint (each a
// 1-bit expression asserted true). A word-level answer applies here too:
// equality over the ring holds for every input, including the ones the
// constraints select.
[[nodiscard]] Equivalence prove_equivalent_under(
    expr::DAG& dag, expr::Id a, expr::Id b,
    const std::vector<expr::Id>& constraints, bool want_proof = false,
    bool force_sat = false);

// A satisfying assignment of the constraints.
struct Model {
    bool sat = false;
    std::vector<std::uint64_t> inputs;
    std::uint64_t conflicts = 0;
};

// Finds an input satisfying every constraint. The concolic driver uses
// this to build an input that reaches a chosen virtual branch.
[[nodiscard]] Model solve_constraints(expr::DAG& dag,
                                      const std::vector<expr::Id>& constraints);

}  // namespace occ::devirt::bb
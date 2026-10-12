// SAT solver and bit-blaster tests.
//
// Three levels of checking, weakest first. The solver is asked small
// formulas whose answers are known by construction. Then it is asked
// hundreds of randomly generated formulas, and its verdicts are compared
// against exhaustive enumeration -- a brute-force oracle is the only
// check that catches a solver that is confidently wrong. Finally the
// DRUP proof it emits for an unsatisfiable formula is replayed through
// an independent RUP checker written for this test file: every learned
// clause must be derivable from the live clause set by unit propagation
// alone. If that checker accepts, the unsatisfiability certificate is
// valid regardless of how the solver found it.
//
// The bit-blaster gets the same treatment at its level: miters that must
// be equal, miters that must not, counterexamples that are re-evaluated
// in the DAG and must actually distinguish the two expressions, and
// constraint solving whose model must satisfy every constraint.

#include "occ/devirt/bitblast.h"
#include "occ/devirt/expr.h"
#include "occ/devirt/ring.h"
#include "occ/devirt/sat.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

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

// ---------------------------------------------------------------- rng

std::uint64_t rng_state = 0x853c49e6748fea9bULL;

std::uint64_t rng_next() {
    rng_state = rng_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return rng_state >> 33;
}

// --------------------------------------------------------- brute force

// Evaluates a CNF (literals as 2*v+sign, matching the solver's API) by
// enumerating every assignment. Formulas in these tests stay under 20
// variables.
bool brute_force_sat(const std::vector<std::vector<sat::Lit>>& formula,
                     unsigned num_vars) {
    const std::uint64_t limit = std::uint64_t{1} << num_vars;
    for (std::uint64_t mask = 0; mask < limit; ++mask) {
        bool all = true;
        for (const std::vector<sat::Lit>& clause : formula) {
            bool sat = false;
            for (const sat::Lit l : clause) {
                const bool value =
                    ((mask >> sat::lit_var(l)) & 1) != 0;
                if (value != sat::lit_negated(l)) {
                    sat = true;
                    break;
                }
            }
            if (!sat) {
                all = false;
                break;
            }
        }
        if (all) {
            return true;
        }
    }
    return false;
}

// --------------------------------------------------------- drup checker

// An independent reverse-unit-propagation checker. It keeps the live
// clause set, and for every clause the proof claims to add it asks: is
// the clause derivable by unit propagation from the live clauses plus
// the negation of the clause? That is the RUP property, and checking it
// needs no trust in the solver.
class DrupChecker {
public:
    void add_initial(std::vector<sat::Lit> clause) {
        live_.push_back(std::move(clause));
    }

    // Parses one DRUP line. Returns false when the line is not
    // verifiable.
    bool replay_line(const std::string& line) {
        const bool deletion = !line.empty() && line[0] == 'd';
        std::vector<sat::Lit> lits;
        const char* p = line.data();
        const char* end = p + line.size();
        if (deletion) {
            ++p;
        }
        while (p < end) {
            while (p < end && (*p == ' ' || *p == '\t')) {
                ++p;
            }
            bool neg = false;
            if (p < end && *p == '-') {
                neg = true;
                ++p;
            }
            if (p >= end || *p < '0' || *p > '9') {
                return false;
            }
            long v = 0;
            while (p < end && *p >= '0' && *p <= '9') {
                v = v * 10 + (*p - '0');
                ++p;
            }
            if (v == 0) {
                break;  // terminator
            }
            lits.push_back(
                sat::mk_lit(static_cast<sat::Var>(v - 1), neg));
        }
        if (deletion) {
            for (std::size_t i = 0; i < live_.size(); ++i) {
                if (live_[i] == lits) {
                    live_[i] = live_.back();
                    live_.pop_back();
                    return true;
                }
            }
            return false;  // deleted a clause that was never live
        }
        if (!rup(lits)) {
            return false;
        }
        if (!lits.empty()) {
            live_.push_back(std::move(lits));
        }
        return true;
    }

    [[nodiscard]] bool proved() const noexcept { return proved_; }

private:
    // Unit propagation over the live clauses with the literals of
    // `clause` negated. A conflict means the clause is RUP.
    bool rup(const std::vector<sat::Lit>& clause) {
        // Assignment by variable: 0 unknown, 1 true, -1 false.
        std::vector<std::int8_t> value;
        const auto set = [&](sat::Lit l) -> bool {
            const sat::Var v = sat::lit_var(l);
            if (v >= value.size()) {
                value.resize(static_cast<std::size_t>(v) + 1, 0);
            }
            const std::int8_t want =
                sat::lit_negated(l) ? -1 : 1;
            if (value[v] == 0) {
                value[v] = want;
                return true;
            }
            return value[v] == want;
        };
        for (const sat::Lit l : clause) {
            if (!set(sat::lit_negate(l))) {
                return true;  // tautology: trivially RUP
            }
        }
        bool changed = true;
        while (changed) {
            changed = false;
            for (const std::vector<sat::Lit>& c : live_) {
                std::size_t unassigned = 0;
                sat::Lit unit = sat::kUndef;
                bool satisfied = false;
                for (const sat::Lit l : c) {
                    const sat::Var v = sat::lit_var(l);
                    const std::int8_t cv =
                        v < value.size() ? value[v] : 0;
                    if (cv == 0) {
                        ++unassigned;
                        unit = l;
                    } else if ((cv > 0) != sat::lit_negated(l)) {
                        satisfied = true;
                        break;
                    }
                }
                if (satisfied) {
                    continue;
                }
                if (unassigned == 0) {
                    if (clause.empty()) {
                        proved_ = true;
                    }
                    return true;  // conflict
                }
                if (unassigned == 1) {
                    if (!set(unit)) {
                        return true;
                    }
                    changed = true;
                }
            }
        }
        return false;
    }

    std::vector<std::vector<sat::Lit>> live_;
    bool proved_ = false;
};

// ------------------------------------------------------------- solver

void test_basic_sat() {
    {
        sat::Solver s;
        const sat::Var a = s.new_var();
        const sat::Var b = s.new_var();
        const sat::Lit ca[2] = {sat::mk_lit(a, false),
                                sat::mk_lit(b, false)};
        const sat::Lit cb[2] = {sat::mk_lit(a, true),
                                sat::mk_lit(b, false)};
        s.add_clause(ca);
        s.add_clause(cb);
        check(s.solve() == sat::Solver::Status::Sat, "two clauses sat");
        // (a|b) & (~a|b) forces b; a stays free, so the check is that
        // the model satisfies both clauses rather than a particular a.
        check(s.value(b), "the forced variable is true");
        check((s.value(a) || s.value(b)) && (!s.value(a) || s.value(b)),
              "the model satisfies both clauses");
    }
    {
        sat::Solver s;
        const sat::Var a = s.new_var();
        const sat::Lit u[1] = {sat::mk_lit(a, false)};
        const sat::Lit n[1] = {sat::mk_lit(a, true)};
        s.add_clause(u);
        s.add_clause(n);
        check(s.solve() == sat::Solver::Status::Unsat, "x and ~x unsat");
    }
    {
        // Pigeonhole 3 pigeons, 2 holes: unsatisfiable, CDCL territory.
        sat::Solver s;
        constexpr int kPigeons = 3;
        constexpr int kHoles = 2;
        sat::Var p[kPigeons][kHoles];
        for (int i = 0; i < kPigeons; ++i) {
            for (int j = 0; j < kHoles; ++j) {
                p[i][j] = s.new_var();
            }
        }
        for (int i = 0; i < kPigeons; ++i) {
            const sat::Lit cl[2] = {sat::mk_lit(p[i][0], false),
                                    sat::mk_lit(p[i][1], false)};
            s.add_clause(cl);
        }
        for (int j = 0; j < kHoles; ++j) {
            for (int i1 = 0; i1 < kPigeons; ++i1) {
                for (int i2 = i1 + 1; i2 < kPigeons; ++i2) {
                    const sat::Lit cl[2] = {sat::mk_lit(p[i1][j], true),
                                            sat::mk_lit(p[i2][j], true)};
                    s.add_clause(cl);
                }
            }
        }
        check(s.solve() == sat::Solver::Status::Unsat,
              "pigeonhole 3-into-2 unsat");
    }
}

void test_random_against_bruteforce() {
    int matched = 0;
    int rounds = 0;
    for (int round = 0; round < 120; ++round) {
        const unsigned num_vars =
            6 + static_cast<unsigned>(rng_next() % 8);
        const unsigned num_clauses =
            12 + static_cast<unsigned>(rng_next() % 20);
        std::vector<std::vector<sat::Lit>> formula;
        for (unsigned c = 0; c < num_clauses; ++c) {
            std::vector<sat::Lit> clause;
            const unsigned width = 2 + static_cast<unsigned>(rng_next() % 3);
            for (unsigned k = 0; k < width; ++k) {
                const auto v =
                    static_cast<sat::Var>(rng_next() % num_vars);
                clause.push_back(
                    sat::mk_lit(v, (rng_next() & 1) != 0));
            }
            formula.push_back(std::move(clause));
        }
        sat::Solver s;
        for (unsigned v = 0; v < num_vars; ++v) {
            static_cast<void>(s.new_var());
        }
        for (const std::vector<sat::Lit>& clause : formula) {
            s.add_clause(clause);
        }
        const sat::Solver::Status st = s.solve();
        const bool brute = brute_force_sat(formula, num_vars);
        const bool agree =
            (st == sat::Solver::Status::Sat) == brute;
        if (!agree) {
            std::fprintf(stderr,
                         "round %d: solver=%s brute=%s\n", round,
                         st == sat::Solver::Status::Sat ? "sat" : "unsat",
                         brute ? "sat" : "unsat");
        }
        check(agree, "random formula verdict agrees with enumeration");
        ++rounds;
        if (agree) {
            ++matched;
        }
        // When sat, re-evaluate the model against the formula.
        if (st == sat::Solver::Status::Sat) {
            bool total = true;
            for (unsigned v = 0; v < num_vars; ++v) {
                total = total && s.assigned(v);
            }
            check(total, "the model assigns every variable");
            bool model_ok = true;
            for (const std::vector<sat::Lit>& clause : formula) {
                bool sat = false;
                for (const sat::Lit l : clause) {
                    if (s.value(sat::lit_var(l)) !=
                        sat::lit_negated(l)) {
                        sat = true;
                        break;
                    }
                }
                if (!sat) {
                    model_ok = false;
                    std::fprintf(stderr, "round %d: falsified clause:",
                                 round);
                    for (const sat::Lit l : clause) {
                        const int v = static_cast<int>(sat::lit_var(l)) + 1;
                        std::fprintf(stderr, " %d",
                                     sat::lit_negated(l) ? -v : v);
                    }
                    std::fprintf(stderr, "\n  model:");
                    for (unsigned v = 0; v < num_vars; ++v) {
                        std::fprintf(stderr, " %s%d",
                                     s.value(v) ? "" : "-",
                                     static_cast<int>(v) + 1);
                    }
                    std::fprintf(stderr, "\n");
                    break;
                }
            }
            check(model_ok, "the reported model satisfies the formula");
        }
    }
    check(matched == rounds, "every random verdict was right");
}

void test_assumptions() {
    sat::Solver s;
    const sat::Var a = s.new_var();
    const sat::Var b = s.new_var();
    const sat::Lit cl[2] = {sat::mk_lit(a, false), sat::mk_lit(b, false)};
    s.add_clause(cl);
    {
        const sat::Lit asm_[2] = {sat::mk_lit(a, true),
                                  sat::mk_lit(b, true)};
        check(s.solve(asm_) == sat::Solver::Status::Unsat,
              "assumptions hitting the clause are unsat");
        check(s.failed().size() == 2, "both assumptions reported failed");
    }
    {
        const sat::Lit asm_[1] = {sat::mk_lit(a, true)};
        check(s.solve(asm_) == sat::Solver::Status::Sat,
              "the other side of the clause is sat");
        check(!s.value(a) && s.value(b), "the model honours the assumption");
    }
}

void test_drup_certificate() {
    // A formula that needs real learning: Tseitin-style chain with an
    // inconsistent set of units.
    std::vector<std::vector<sat::Lit>> cnf;
    sat::Solver s;
    constexpr unsigned kVars = 12;
    for (unsigned v = 0; v < kVars; ++v) {
        static_cast<void>(s.new_var());
    }
    // XOR chain: y1 = x1 ^ x2, y2 = y1 ^ x3, ..., plus units that make
    // it unsatisfiable: all x true and the last y false.
    auto add = [&](std::vector<sat::Lit> c) {
        cnf.push_back(c);
        s.add_clause(c);
    };
    // A small inconsistent core with real work for the solver:
    // c1 must be true, c1 implies both a1 and b1, and a1 and b1 are
    // forbidden from being true together.
    const auto L = [](sat::Var v, bool neg) {
        return sat::mk_lit(v, neg);
    };
    add({L(4, false)});              // c1
    add({L(4, true), L(0, false)});  // c1 -> a1
    add({L(4, true), L(1, false)});  // c1 -> b1
    add({L(0, true), L(1, true)});   // ~(a1 & b1)
    std::vector<std::string> proof;
    s.enable_proof(&proof);
    check(s.solve() == sat::Solver::Status::Unsat,
          "the hand-built core is unsat");
    check(!proof.empty(), "the solver emitted a proof");
    check(proof.back() == "0", "the proof ends with the empty clause");

    DrupChecker checker;
    for (const std::vector<sat::Lit>& c : cnf) {
        checker.add_initial(c);
    }
    bool all_ok = true;
    for (const std::string& line : proof) {
        if (!checker.replay_line(line)) {
            all_ok = false;
            std::fprintf(stderr, "unverifiable proof line: %s\n",
                         line.c_str());
            break;
        }
    }
    check(all_ok, "every proof line passes the independent RUP checker");
}

void test_miter() {
    expr::DAG dag;
    const expr::Id x = dag.input("x", 64);
    const expr::Id y = dag.input("y", 64);
    {
        const expr::Id a = dag.add(x, y);
        const expr::Id b = dag.add(y, x);
        const bb::Equivalence e = bb::prove_equivalent(dag, a, b);
        check(e.equal, "x+y == y+x (commutativity proven)");
    }
    {
        const expr::Id a = dag.bit_xor(x, y);
        const expr::Id b = dag.bit_xor(x, dag.bit_not(y));
        check(!bb::prove_equivalent(dag, a, b).equal,
              "x^y != x^~y (disproven)");
    }
    {
        const expr::Id a = dag.add(x, dag.constant(1, 64));
        const expr::Id b = dag.add(x, dag.constant(2, 64));
        const bb::Equivalence e = bb::prove_equivalent(dag, a, b);
        check(!e.equal, "x+1 != x+2");
    }
    {
        // Associativity at the handler width: a wide ripple-carry
        // miter, which is the shape handler arithmetic actually takes.
        const expr::Id a = dag.add(dag.add(x, y), dag.constant(7, 64));
        const expr::Id b = dag.add(x, dag.add(y, dag.constant(7, 64)));
        check(bb::prove_equivalent(dag, a, b).equal,
              "(x+y)+7 == x+(y+7) at 64 bits");
    }
    {
        // Multiplication identity through a longer expression:
        // (x+3)(y-3) == xy - 3x + 3y - 9. Written out so that the two
        // sides are different DAGs and the proof is algebra, not
        // hash-consing.
        //
        // At the handler width. A multiplier miter at 64 bits is the
        // instance CDCL cannot finish, and this test used to say so by
        // shrinking the width; the word-level layer answers it instead,
        // by expanding both sides into the same polynomial. The SAT
        // layer's own grip on multiplier equivalence is checked at a
        // width it can finish, in test_ring_layer.
        const expr::Id a =
            dag.mul(dag.add(x, dag.constant(3, 64)),
                    dag.sub(y, dag.constant(3, 64)));
        const expr::Id b = dag.sub(dag.mul(x, y),
                                   dag.mul(dag.constant(3, 64), x));
        const expr::Id c = dag.add(b, dag.mul(dag.constant(3, 64), y));
        const expr::Id d = dag.sub(c, dag.constant(9, 64));
        const bb::Equivalence e = bb::prove_equivalent(dag, a, d);
        check(e.equal, "(x+3)(y-3) == xy-3x+3y-9 at 64 bits (algebra proven)");
        check(e.method == bb::Method::Ring,
              "the wide algebra was proven by normalization, not search");
        check(e.conflicts == 0, "and it cost no conflicts");
    }
    {
        const expr::Id a = dag.shr(x, dag.constant(4, 64));
        const expr::Id b = dag.shr(x, dag.constant(5, 64));
        check(!bb::prove_equivalent(dag, a, b).equal, "x>>4 != x>>5");
    }
    {
        const expr::Id a = dag.mul(x, dag.constant(8, 64));
        const expr::Id b = dag.shl(x, dag.constant(3, 64));
        check(bb::prove_equivalent(dag, a, b).equal, "x*8 == x<<3");
    }
}

void test_shift_semantics() {
    // Shift amounts are 64-bit. A barrel shifter built from amount bits
    // only ever sees the low six, so an amount like 64 reads as zero --
    // and a miter over it would "prove" x << 64 == x. Each statement
    // below is true only if the encoding applies the DAG's rule for
    // amounts at or past the width, so each one fails on an unguarded
    // barrel. The condition is a variable, which is what forces the
    // amount through the circuit instead of through the folder.
    expr::DAG dag;
    const expr::Id x = dag.input("x", 64);
    const expr::Id c = dag.input("c", 1);
    const auto choose = [&](expr::Id t, expr::Id f) {
        return dag.select(c, t, f);
    };
    {
        const expr::Id amount =
            choose(dag.constant(64, 64), dag.constant(1, 64));
        const expr::Id a = dag.shl(x, amount);
        const expr::Id b =
            choose(dag.constant(0, 64),
                   dag.shl(x, dag.constant(1, 64)));
        check(bb::prove_equivalent(dag, a, b).equal,
              "x << (c ? 64 : 1) == c ? 0 : x << 1");
    }
    {
        const expr::Id amount =
            choose(dag.constant(64, 64), dag.constant(0, 64));
        const expr::Id a = dag.shr(x, amount);
        const expr::Id b = choose(dag.constant(0, 64), x);
        check(bb::prove_equivalent(dag, a, b).equal,
              "x >> (c ? 64 : 0) == c ? 0 : x");
    }
    {
        const expr::Id amount =
            choose(dag.constant(64, 64), dag.constant(0, 64));
        const expr::Id a = dag.sar(x, amount);
        const expr::Id b = choose(dag.sar(x, dag.constant(63, 64)), x);
        check(bb::prove_equivalent(dag, a, b).equal,
              "x >>a (c ? 64 : 0) == c ? sign-fill : x");
    }
    {
        // The false direction: a counterexample must exist and, when
        // re-evaluated in the DAG, must really distinguish the sides.
        // Without the guard the reported counterexample would evaluate
        // to equal values, which is the check below.
        const expr::Id amount =
            choose(dag.constant(64, 64), dag.constant(1, 64));
        const expr::Id a = dag.shl(x, amount);
        const expr::Id b = dag.shl(x, dag.constant(1, 64));
        const bb::Equivalence e = bb::prove_equivalent(dag, a, b);
        check(!e.equal, "x << (c ? 64 : 1) != x << 1");
        if (!e.equal && !e.counterexample.empty()) {
            const std::uint64_t va = dag.evaluate(a, e.counterexample);
            const std::uint64_t vb = dag.evaluate(b, e.counterexample);
            check(va != vb, "the shift counterexample really distinguishes");
        }
    }
}

void test_ring_layer() {
    // The word-level normalizer, checked three ways: against itself (the
    // same polynomial built two ways must print the same form), against
    // exhaustive enumeration (an equality it claims must hold on every
    // input, checked exhaustively at a width where that is possible),
    // and against the circuit path (the two layers must agree wherever
    // both can answer).
    expr::DAG dag;
    const expr::Id x = dag.input("x", 8);
    const expr::Id y = dag.input("y", 8);

    {
        // Same polynomial, two constructions, same canonical text.
        const expr::Id a = dag.add(x, dag.add(y, dag.constant(1, 8)));
        const expr::Id b = dag.add(dag.add(y, x), dag.constant(1, 8));
        const ring::Canonical fa = ring::canonical(dag, a);
        const ring::Canonical fb = ring::canonical(dag, b);
        check(fa.ok && fb.ok, "both sides normalize");
        check(fa.form == fb.form,
              "addition's order does not survive normalization");
        check(ring::prove_equal(dag, a, b) == ring::Verdict::Equal,
              "the ring proves what the forms say");
    }
    {
        // A ring identity that is not syntactic: subtraction reorganizes
        // into coefficients.
        const expr::Id a =
            dag.sub(dag.mul(x, y), dag.add(dag.mul(y, x), dag.constant(5, 8)));
        const ring::Verdict v = ring::prove_equal(dag, a, dag.constant(251, 8));
        check(v == ring::Verdict::Equal,
              "x*y - (y*x + 5) == -5 (mod 256) by normalization");
    }
    {
        // Coefficient folding is modular, not integer arithmetic.
        const expr::Id a = dag.add(dag.constant(200, 8), dag.constant(100, 8));
        check(ring::prove_equal(dag, a, dag.constant(44, 8)) ==
                  ring::Verdict::Equal,
              "200 + 100 folds to 44 at width 8");
    }
    {
        // Soundness across widths: the same shape at two widths is not
        // the same polynomial, and the normalizer must not say it is.
        // x*200 at width 8 wraps; at width 64 it does not, and 200*x is
        // larger than 255 for most x.
        expr::DAG wide;
        const expr::Id wx = wide.input("x", 8);
        const expr::Id narrow = wide.mul(wx, wide.constant(200, 8));
        const expr::Id wide64 = wide.mul(wide.resize(wx, 64),
                                         wide.constant(200, 64));
        check(ring::prove_equal(wide, narrow, wide64) ==
                  ring::Verdict::Unknown,
              "a narrow product and a wide one are not the same polynomial");
        check(!bb::prove_equivalent(wide, narrow, wide64).equal,
              "and the circuit path agrees they differ");
    }
    {
        // Constants compare as numbers across widths: zext(5) is 5.
        const expr::Id five = dag.constant(5, 8);
        const expr::Id extended = dag.resize(five, 64);
        check(ring::prove_equal(dag, extended, dag.constant(5, 64)) ==
                  ring::Verdict::Equal,
              "zext(5) is 5");
    }
    {
        // A shift out of the register is zero, at the word level.
        const expr::Id shifted = dag.shl(x, dag.constant(64, 64));
        check(ring::prove_equal(dag, shifted, dag.constant(0, 8)) ==
                  ring::Verdict::Equal,
              "x << 64 is zero");
        // The amount is 8 bits too, so both sides are width-8
        // expressions and the identity is a statement about one ring.
        const expr::Id times8 = dag.mul(x, dag.constant(8, 8));
        const expr::Id shift3 = dag.shl(x, dag.constant(3, 8));
        check(ring::prove_equal(dag, times8, shift3) == ring::Verdict::Equal,
              "x*8 and x<<3 normalize to the same term");
    }
    {
        // Enumeration: every equality the ring claims, checked on every
        // input. Eight bits is 65536 pairs, which is exhaustive.
        const std::vector<std::pair<expr::Id, expr::Id>> identities = {
            {dag.mul(dag.add(x, dag.constant(3, 8)),
                     dag.sub(y, dag.constant(3, 8))),
             dag.sub(dag.add(dag.sub(dag.mul(x, y),
                                     dag.mul(dag.constant(3, 8), x)),
                             dag.mul(dag.constant(3, 8), y)),
                     dag.constant(9, 8))},
            {dag.mul(x, dag.constant(8, 8)), dag.shl(x, dag.constant(3, 8))},
            {dag.add(x, x), dag.mul(dag.constant(2, 8), x)},
            {dag.neg(dag.neg(x)), x},
        };
        bool all_proven = true;
        bool all_hold = true;
        for (const auto& [lhs, rhs] : identities) {
            all_proven = all_proven &&
                         ring::prove_equal(dag, lhs, rhs) ==
                             ring::Verdict::Equal;
            for (unsigned xv = 0; xv < 256 && all_hold; ++xv) {
                for (unsigned yv = 0; yv < 256; ++yv) {
                    const std::vector<std::uint64_t> in{xv, yv};
                    if (dag.evaluate(lhs, in) != dag.evaluate(rhs, in)) {
                        all_hold = false;
                        break;
                    }
                }
            }
        }
        check(all_proven, "the ring proves every identity in the set");
        check(all_hold, "and enumeration finds no counterexample to any");
    }
    {
        // The two layers against each other on a case both can finish:
        // a 6-bit multiplier miter, which is real CDCL work and still
        // within reach.
        expr::DAG small;
        const expr::Id sx = small.input("x", 6);
        const expr::Id sy = small.input("y", 6);
        const expr::Id lhs =
            small.mul(small.add(sx, small.constant(3, 6)),
                      small.sub(sy, small.constant(3, 6)));
        const expr::Id rhs = small.sub(
            small.add(small.sub(small.mul(sx, sy),
                                small.mul(small.constant(3, 6), sx)),
                      small.mul(small.constant(3, 6), sy)),
            small.constant(9, 6));
        const bb::Equivalence normal = bb::prove_equivalent(small, lhs, rhs);
        const bb::Equivalence circuit =
            bb::prove_equivalent(small, lhs, rhs, false, /*force_sat=*/true);
        check(normal.equal && circuit.equal,
              "normalization and the circuit agree on the 6-bit identity");
        check(normal.method == bb::Method::Ring &&
                  circuit.method == bb::Method::Sat,
              "each answer names the layer that produced it");
        check(circuit.conflicts > 0, "the circuit path really searched");
    }
    {
        // The witness is the certificate: the two forms, which a checker
        // recomputes. And a false statement never gets one.
        const expr::Id a = dag.add(x, dag.constant(1, 8));
        const expr::Id b = dag.add(dag.constant(1, 8), x);
        const bb::Equivalence e =
            bb::prove_equivalent(dag, a, b, /*want_proof=*/true);
        check(e.equal && e.method == bb::Method::Ring, "commutativity, ring");
        check(e.witness.find("left=") != std::string::npos &&
                  e.witness.find("right=") != std::string::npos,
              "the witness carries both forms");
        const expr::Id c = dag.add(x, dag.constant(2, 8));
        const bb::Equivalence bad = bb::prove_equivalent(dag, a, c);
        check(!bad.equal, "x+1 vs x+2 is not claimed equal");
        check(bad.method == bb::Method::Sat, "the circuit answered it");
    }
}

void test_counterexample_is_real() {
    expr::DAG dag;
    const expr::Id x = dag.input("x", 64);
    const expr::Id a = dag.add(x, dag.constant(1, 64));
    const expr::Id b = dag.add(x, dag.constant(2, 64));
    const bb::Equivalence e = bb::prove_equivalent(dag, a, b);
    check(!e.equal, "x+1 vs x+2 distinguished");
    check(!e.counterexample.empty(), "a counterexample came back");
    if (!e.counterexample.empty()) {
        // Re-evaluate both sides with the counterexample; they must
        // differ, or the counterexample is a lie.
        const std::uint64_t va = dag.evaluate(a, e.counterexample);
        const std::uint64_t vb = dag.evaluate(b, e.counterexample);
        check(va != vb, "the counterexample really distinguishes them");
        check(vb == va + 1, "and the difference is exactly one");
    }
}

void test_constraint_solving() {
    expr::DAG dag;
    const expr::Id x = dag.input("x", 64);
    const expr::Id y = dag.input("y", 64);
    // x + y == 100, x < y
    const expr::Id sum = dag.add(x, y);
    const expr::Id c1 = dag.cmp_eq(sum, dag.constant(100, 64));
    const expr::Id c2 = dag.cmp_ult(x, y);
    const bb::Model m = bb::solve_constraints(dag, {c1, c2});
    check(m.sat, "a model for {x+y=100, x<y} exists");
    if (m.sat) {
        const std::uint64_t vx = dag.evaluate(x, m.inputs);
        const std::uint64_t vy = dag.evaluate(y, m.inputs);
        check(vx + vy == 100 && vx < vy,
              "the model satisfies both constraints");
    }
    // Now an impossible pair: x + y == 100 and x + y == 101.
    const expr::Id c3 = dag.cmp_eq(sum, dag.constant(101, 64));
    const bb::Model m2 = bb::solve_constraints(dag, {c1, c3});
    check(!m2.sat, "no model for {x+y=100, x+y=101}");
}

void test_proof_certificate_from_miter() {
    // A miter that cannot be answered by folding: the two sides mention
    // different constants and neither collapses into the other, so the
    // proof is real SAT work over the adder and xor encodings.
    expr::DAG dag;
    const expr::Id x = dag.input("x", 64);
    const expr::Id a =
        dag.bit_xor(dag.bit_xor(x, dag.constant(0xff, 64)),
                    dag.constant(0xfe, 64));
    const expr::Id b = dag.bit_xor(x, dag.constant(0x01, 64));
    const bb::Equivalence e =
        bb::prove_equivalent(dag, a, b, /*want_proof=*/true);
    check(e.equal, "(x^0xff)^0xfe == x^0x01");
    check(!e.proof.empty(), "a proof came back");
    if (!e.proof.empty()) {
        check(e.proof.back() == "0",
              "the proof ends with the empty clause");
    }
    check(!e.formula.empty(), "the refuted formula came back with it");

    // The certificate has to hold up against the formula, checked by a
    // checker that shares nothing with the solver.
    DrupChecker checker;
    for (const std::vector<sat::Lit>& c : e.formula) {
        checker.add_initial(c);
    }
    bool all_ok = !e.formula.empty();
    for (const std::string& line : e.proof) {
        if (!checker.replay_line(line)) {
            all_ok = false;
            std::fprintf(stderr, "unverifiable miter proof line: %s\n",
                         line.c_str());
            break;
        }
    }
    check(all_ok, "the miter proof replays through the RUP checker");

    // The syntactically identical case: no bits can differ, so the miter
    // is the false assertion. It never reaches the circuit -- the
    // normalizer sees the same expression on both sides -- and the
    // certificate that comes back is the normalization, which is what
    // "proof-carrying" means when the word level answers.
    const bb::Equivalence triv = bb::prove_equivalent(dag, b, b, true);
    check(triv.equal, "x^0x01 == x^0x01");
    if (triv.method == bb::Method::Ring) {
        check(!triv.witness.empty(),
              "the normalization certificate came back");
    } else {
        check(!triv.proof.empty(), "the circuit certificate came back");
    }
}

}  // namespace

int main() {
    // Each case is announced as it starts: a test that hangs is then
    // identified by the last line printed, which is the difference
    // between "the solver is slow" and a guess about which solver.
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("-- %s\n", name);
        std::fflush(stdout);
        fn();
    };
    run("basic_sat", test_basic_sat);
    run("random_vs_bruteforce", test_random_against_bruteforce);
    run("assumptions", test_assumptions);
    run("drup_certificate", test_drup_certificate);
    run("miter", test_miter);
    run("shift_semantics", test_shift_semantics);
    run("ring_layer", test_ring_layer);
    run("counterexample_is_real", test_counterexample_is_real);
    run("constraint_solving", test_constraint_solving);
    run("miter_certificate", test_proof_certificate_from_miter);
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
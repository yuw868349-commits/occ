// The bit-blaster: expression DAG to CNF, miter equivalence.

#include "occ/devirt/bitblast.h"

#include <algorithm>
#include <cstring>

#include "occ/devirt/ring.h"

namespace occ::devirt::bb {

namespace {

std::uint32_t lit_bits(sat::Lit l) {
    return static_cast<std::uint32_t>(l);
}

}  // namespace

std::uint64_t Encoder::pair_key(sat::Lit a, sat::Lit b) {
    const std::uint32_t x = lit_bits(a);
    const std::uint32_t y = lit_bits(b);
    const std::uint32_t lo = x < y ? x : y;
    const std::uint32_t hi = x < y ? y : x;
    return (static_cast<std::uint64_t>(lo) << 32) | hi;
}

sat::Lit Encoder::const_lit(bool value) {
    if (true_lit_ == sat::kUndef) {
        const sat::Var v = solver_->new_var();
        true_lit_ = sat::mk_lit(v, false);
        const sat::Lit unit = true_lit_;
        solver_->add_clause(std::span<const sat::Lit>(&unit, 1));
    }
    return value ? true_lit_ : sat::lit_negate(true_lit_);
}

sat::Lit Encoder::gate_and(sat::Lit a, sat::Lit b) {
    if (a == b) {
        return a;
    }
    if (a == sat::lit_negate(b)) {
        return const_lit(false);
    }
    if (true_lit_ != sat::kUndef) {
        if (a == true_lit_) {
            return b;
        }
        if (b == true_lit_) {
            return a;
        }
        if (a == sat::lit_negate(true_lit_) ||
            b == sat::lit_negate(true_lit_)) {
            return const_lit(false);
        }
    }
    const std::uint64_t key = pair_key(a, b);
    if (const auto it = and_cache_.find(key); it != and_cache_.end()) {
        return it->second;
    }
    const sat::Var v = solver_->new_var();
    const sat::Lit z = sat::mk_lit(v, false);
    const sat::Lit na = sat::lit_negate(a);
    const sat::Lit nb = sat::lit_negate(b);
    {
        const sat::Lit cl[3] = {na, nb, z};
        solver_->add_clause(cl);
    }
    {
        const sat::Lit cl[2] = {a, sat::lit_negate(z)};
        solver_->add_clause(cl);
    }
    {
        const sat::Lit cl[2] = {b, sat::lit_negate(z)};
        solver_->add_clause(cl);
    }
    and_cache_.emplace(key, z);
    return z;
}

sat::Lit Encoder::gate_or(sat::Lit a, sat::Lit b) {
    if (a == b) {
        return a;
    }
    if (a == sat::lit_negate(b)) {
        return const_lit(true);
    }
    if (true_lit_ != sat::kUndef) {
        if (a == true_lit_ || b == true_lit_) {
            return const_lit(true);
        }
        if (a == sat::lit_negate(true_lit_)) {
            return b;
        }
        if (b == sat::lit_negate(true_lit_)) {
            return a;
        }
    }
    const std::uint64_t key = pair_key(a, b);
    if (const auto it = or_cache_.find(key); it != or_cache_.end()) {
        return it->second;
    }
    const sat::Var v = solver_->new_var();
    const sat::Lit z = sat::mk_lit(v, false);
    const sat::Lit na = sat::lit_negate(a);
    const sat::Lit nb = sat::lit_negate(b);
    {
        const sat::Lit cl[3] = {a, b, sat::lit_negate(z)};
        solver_->add_clause(cl);
    }
    {
        const sat::Lit cl[2] = {na, z};
        solver_->add_clause(cl);
    }
    {
        const sat::Lit cl[2] = {nb, z};
        solver_->add_clause(cl);
    }
    or_cache_.emplace(key, z);
    return z;
}

sat::Lit Encoder::gate_xor(sat::Lit a, sat::Lit b) {
    if (a == b) {
        return const_lit(false);
    }
    if (a == sat::lit_negate(b)) {
        return const_lit(true);
    }
    if (true_lit_ != sat::kUndef) {
        if (a == true_lit_) {
            return sat::lit_negate(b);
        }
        if (b == true_lit_) {
            return sat::lit_negate(a);
        }
        if (a == sat::lit_negate(true_lit_)) {
            return b;
        }
        if (b == sat::lit_negate(true_lit_)) {
            return a;
        }
    }
    const std::uint64_t key = pair_key(a, b);
    if (const auto it = xor_cache_.find(key); it != xor_cache_.end()) {
        return it->second;
    }
    const sat::Var v = solver_->new_var();
    const sat::Lit z = sat::mk_lit(v, false);
    const sat::Lit na = sat::lit_negate(a);
    const sat::Lit nb = sat::lit_negate(b);
    const sat::Lit nz = sat::lit_negate(z);
    {
        const sat::Lit cl[3] = {na, nb, nz};
        solver_->add_clause(cl);
    }
    {
        const sat::Lit cl[3] = {a, b, nz};
        solver_->add_clause(cl);
    }
    {
        const sat::Lit cl[3] = {a, nb, z};
        solver_->add_clause(cl);
    }
    {
        const sat::Lit cl[3] = {na, b, z};
        solver_->add_clause(cl);
    }
    xor_cache_.emplace(key, z);
    return z;
}

sat::Lit Encoder::gate_mux(sat::Lit c, sat::Lit t, sat::Lit f) {
    if (t == f) {
        return t;
    }
    if (t == sat::lit_negate(f)) {
        // c ? t : ~t == c XNOR t == ~(c XOR t). The operand here is `t`,
        // not `f`: `~ (c XOR f)` is XNOR of c with ~t, which is c XOR t,
        // the opposite branch. A mux whose two arms are complements is
        // what a select with constant branches compiles to -- a shift
        // amount written `c ? 64 : 1`, for instance -- so picking the
        // wrong arm there silently rewires a whole handler.
        return sat::lit_negate(gate_xor(c, t));
    }
    return gate_or(gate_and(c, t), gate_and(sat::lit_negate(c), f));
}

sat::Lit Encoder::gate_and_all(const std::vector<sat::Lit>& lits) {
    sat::Lit acc = const_lit(true);
    for (const sat::Lit l : lits) {
        acc = gate_and(acc, l);
        if (true_lit_ != sat::kUndef && acc == sat::lit_negate(true_lit_)) {
            return acc;
        }
    }
    return acc;
}

sat::Lit Encoder::gate_or_all(const std::vector<sat::Lit>& lits) {
    sat::Lit acc = const_lit(false);
    for (const sat::Lit l : lits) {
        acc = gate_or(acc, l);
    }
    return acc;
}

sat::Lit Encoder::input_bit(unsigned ordinal, unsigned index) {
    if (ordinal >= input_base_.size()) {
        input_base_.resize(static_cast<std::size_t>(ordinal) + 1, 0);
        input_widths_.resize(static_cast<std::size_t>(ordinal) + 1, 0);
    }
    // The caller (`build`, the Input case) allocates the ordinal's bits
    // before the first call here; base stores +1 so 0 means unallocated.
    const sat::Var base = input_base_[ordinal];
    const sat::Var v = static_cast<sat::Var>(base - 1 + index);
    return sat::mk_lit(v, false);
}

std::vector<std::uint64_t> Encoder::read_inputs() const {
    std::vector<std::uint64_t> out(input_widths_.size(), 0);
    for (std::size_t ord = 0; ord < input_widths_.size(); ++ord) {
        if (input_base_[ord] == 0) {
            continue;
        }
        std::uint64_t value = 0;
        for (unsigned i = 0; i < input_widths_[ord] && i < 64; ++i) {
            const sat::Var v =
                static_cast<sat::Var>(input_base_[ord] - 1 + i);
            if (solver_->value(v)) {
                value |= std::uint64_t{1} << i;
            }
        }
        out[ord] = value;
    }
    return out;
}

std::vector<sat::Lit> Encoder::add_bits(const std::vector<sat::Lit>& a,
                                        const std::vector<sat::Lit>& b) {
    const std::size_t w = a.size();
    std::vector<sat::Lit> out(w, sat::kUndef);
    sat::Lit carry = const_lit(false);
    for (std::size_t i = 0; i < w; ++i) {
        const sat::Lit ab = gate_xor(a[i], b[i]);
        out[i] = gate_xor(ab, carry);
        const sat::Lit c1 = gate_and(a[i], b[i]);
        const sat::Lit c2 = gate_and(carry, ab);
        carry = gate_or(c1, c2);
    }
    return out;
}

std::vector<sat::Lit> Encoder::mul_bits(const std::vector<sat::Lit>& a,
                                        const std::vector<sat::Lit>& b) {
    const std::size_t w = a.size();
    std::vector<sat::Lit> acc(w, const_lit(false));
    for (std::size_t i = 0; i < w; ++i) {
        std::vector<sat::Lit> partial(w, const_lit(false));
        for (std::size_t k = i; k < w; ++k) {
            partial[k] = gate_and(a[k - i], b[i]);
        }
        acc = add_bits(acc, partial);
    }
    return acc;
}

std::vector<sat::Lit> Encoder::const_bits(std::uint64_t value,
                                         unsigned width) {
    std::vector<sat::Lit> out(width, sat::kUndef);
    for (unsigned i = 0; i < width; ++i) {
        out[i] = const_lit(((value >> i) & 1) != 0);
    }
    return out;
}

// The fixed-amount shifts. The amount is known, so the result is a
// re-wire: every output bit names an input bit or a constant. The DAG's
// semantics put a shift at or past the width on the same footing as any
// other out-of-range amount -- logical shifts yield zero, arithmetic
// fills with the sign bit -- and these three functions are where that
// rule is applied for constant amounts.
std::vector<sat::Lit> Encoder::shl_fixed(const std::vector<sat::Lit>& a,
                                         std::uint64_t amount) {
    const std::size_t w = a.size();
    std::vector<sat::Lit> out(w, sat::kUndef);
    for (std::size_t i = 0; i < w; ++i) {
        out[i] = (amount < w && i >= amount) ? a[i - amount]
                                             : const_lit(false);
    }
    return out;
}

std::vector<sat::Lit> Encoder::shr_fixed(const std::vector<sat::Lit>& a,
                                         std::uint64_t amount) {
    const std::size_t w = a.size();
    std::vector<sat::Lit> out(w, sat::kUndef);
    for (std::size_t i = 0; i < w; ++i) {
        out[i] = (amount < w && i + amount < w) ? a[i + amount]
                                                : const_lit(false);
    }
    return out;
}

std::vector<sat::Lit> Encoder::sar_fixed(const std::vector<sat::Lit>& a,
                                         std::uint64_t amount) {
    const std::size_t w = a.size();
    std::vector<sat::Lit> out(w, sat::kUndef);
    if (w == 0) {
        return out;
    }
    const sat::Lit sign = a[w - 1];
    for (std::size_t i = 0; i < w; ++i) {
        out[i] = (amount < w && i + amount < w) ? a[i + amount] : sign;
    }
    return out;
}

std::vector<sat::Lit> Encoder::shl_bits(
    const std::vector<sat::Lit>& a, const std::vector<sat::Lit>& amount) {
    const std::size_t w = a.size();
    if (amount.empty()) {
        return a;
    }
    std::vector<sat::Lit> cur = a;
    const unsigned layers = 6;  // log2(64), enough for any 64-bit amount
    for (unsigned k = 0; k < layers; ++k) {
        const std::size_t shift = std::size_t{1} << k;
        if (shift >= w) {
            break;
        }
        if (k >= amount.size()) {
            break;  // amount cannot set a bit this high: nothing changes
        }
        const sat::Lit c = amount[k];
        std::vector<sat::Lit> next(w, sat::kUndef);
        for (std::size_t i = 0; i < w; ++i) {
            const sat::Lit shifted =
                i >= shift ? cur[i - shift] : const_lit(false);
            next[i] = gate_mux(c, shifted, cur[i]);
        }
        cur = std::move(next);
    }
    // The barrel consumes six amount bits, which covers amounts below
    // the width and nothing else. An amount at or past the width is not
    // "amount modulo 64": it is a shift of the whole register out, and
    // the answer is zero. Without this guard the encoding would be wrong
    // exactly where a VM's shift handlers are most likely to be probed
    // -- amounts like 64 and 0x40 -- and a miter would "prove" an
    // equality that does not hold.
    const sat::Lit in_range = ult_bits(amount, const_bits(w, 7));
    for (std::size_t i = 0; i < w; ++i) {
        cur[i] = gate_mux(in_range, cur[i], const_lit(false));
    }
    return cur;
}

std::vector<sat::Lit> Encoder::shr_bits(
    const std::vector<sat::Lit>& a, const std::vector<sat::Lit>& amount) {
    const std::size_t w = a.size();
    if (amount.empty()) {
        return a;
    }
    std::vector<sat::Lit> cur = a;
    const unsigned layers = 6;
    for (unsigned k = 0; k < layers; ++k) {
        const std::size_t shift = std::size_t{1} << k;
        if (shift >= w) {
            break;
        }
        if (k >= amount.size()) {
            break;
        }
        const sat::Lit c = amount[k];
        std::vector<sat::Lit> next(w, sat::kUndef);
        for (std::size_t i = 0; i < w; ++i) {
            const sat::Lit shifted =
                i + shift < w ? cur[i + shift] : const_lit(false);
            next[i] = gate_mux(c, shifted, cur[i]);
        }
        cur = std::move(next);
    }
    // Out-of-range amounts shift everything out: the result is zero.
    const sat::Lit in_range = ult_bits(amount, const_bits(w, 7));
    for (std::size_t i = 0; i < w; ++i) {
        cur[i] = gate_mux(in_range, cur[i], const_lit(false));
    }
    return cur;
}

std::vector<sat::Lit> Encoder::sar_bits(
    const std::vector<sat::Lit>& a, const std::vector<sat::Lit>& amount) {
    const std::size_t w = a.size();
    if (amount.empty() || w == 0) {
        return a;
    }
    const sat::Lit sign = a[w - 1];
    std::vector<sat::Lit> cur = a;
    const unsigned layers = 6;
    for (unsigned k = 0; k < layers; ++k) {
        const std::size_t shift = std::size_t{1} << k;
        if (shift >= w) {
            break;
        }
        if (k >= amount.size()) {
            break;
        }
        const sat::Lit c = amount[k];
        std::vector<sat::Lit> next(w, sat::kUndef);
        for (std::size_t i = 0; i < w; ++i) {
            const sat::Lit shifted = i + shift < w ? cur[i + shift] : sign;
            next[i] = gate_mux(c, shifted, cur[i]);
        }
        cur = std::move(next);
    }
    // Out-of-range amounts fill with the sign bit, at every position.
    const sat::Lit in_range = ult_bits(amount, const_bits(w, 7));
    for (std::size_t i = 0; i < w; ++i) {
        cur[i] = gate_mux(in_range, cur[i], sign);
    }
    return cur;
}

sat::Lit Encoder::eq_bits(const std::vector<sat::Lit>& a,
                          const std::vector<sat::Lit>& b) {
    const std::size_t w = std::max(a.size(), b.size());
    sat::Lit acc = const_lit(true);
    for (std::size_t i = 0; i < w; ++i) {
        const sat::Lit xa = i < a.size() ? a[i] : const_lit(false);
        const sat::Lit xb = i < b.size() ? b[i] : const_lit(false);
        acc = gate_and(acc, gate_not(gate_xor(xa, xb)));
    }
    return acc;
}

sat::Lit Encoder::ult_bits(const std::vector<sat::Lit>& a,
                           const std::vector<sat::Lit>& b) {
    const std::size_t w = std::max(a.size(), b.size());
    sat::Lit lt = const_lit(false);
    sat::Lit eq = const_lit(true);
    for (std::size_t i = w; i-- > 0;) {
        const sat::Lit xa = i < a.size() ? a[i] : const_lit(false);
        const sat::Lit xb = i < b.size() ? b[i] : const_lit(false);
        const sat::Lit less = gate_and(gate_not(xa), xb);
        lt = gate_or(lt, gate_and(eq, less));
        eq = gate_and(eq, gate_not(gate_xor(xa, xb)));
    }
    return lt;
}

sat::Lit Encoder::slt_bits(const std::vector<sat::Lit>& a,
                           const std::vector<sat::Lit>& b) {
    const std::size_t w = std::max(a.size(), b.size());
    if (w == 0) {
        return const_lit(false);
    }
    const sat::Lit xa_sign = a.size() == w ? a[w - 1] : const_lit(false);
    const sat::Lit xb_sign = b.size() == w ? b[w - 1] : const_lit(false);
    // Different signs: the negative one is smaller. Same signs: the
    // unsigned comparison is the signed one.
    const sat::Lit diff = gate_and(xa_sign, gate_not(xb_sign));
    const sat::Lit same = gate_not(gate_xor(xa_sign, xb_sign));
    return gate_or(diff, gate_and(same, ult_bits(a, b)));
}

std::vector<sat::Lit> Encoder::bits(expr::Id e) {
    if (const auto it = vector_cache_.find(e); it != vector_cache_.end()) {
        return it->second;
    }
    std::vector<sat::Lit> out = build(e);
    vector_cache_.emplace(e, out);
    return out;
}

sat::Lit Encoder::bit(expr::Id e, unsigned index) {
    const std::vector<sat::Lit> b = bits(e);
    if (index < b.size()) {
        return b[index];
    }
    return const_lit(false);
}

std::vector<sat::Lit> Encoder::build(expr::Id e) {
    const expr::Node& n = dag_->node(e);
    using Op = expr::Op;
    switch (n.op) {
    case Op::Const: {
        std::vector<sat::Lit> out(n.width, sat::kUndef);
        for (unsigned i = 0; i < n.width; ++i) {
            out[i] = const_lit(((n.imm >> i) & 1) != 0);
        }
        return out;
    }
    case Op::Input: {
        const unsigned ord = static_cast<unsigned>(n.imm);
        if (ord >= input_base_.size()) {
            input_base_.resize(static_cast<std::size_t>(ord) + 1, 0);
            input_widths_.resize(static_cast<std::size_t>(ord) + 1, 0);
        }
        if (input_base_[ord] == 0) {
            input_widths_[ord] = n.width;
            const sat::Var base = solver_->new_var();
            for (unsigned i = 1; i < n.width; ++i) {
                static_cast<void>(solver_->new_var());
            }
            input_base_[ord] = base + 1;  // +1: zero means unallocated
        }
        std::vector<sat::Lit> out(n.width, sat::kUndef);
        for (unsigned i = 0; i < n.width; ++i) {
            out[i] = input_bit(ord, i);
        }
        return out;
    }
    case Op::Resize: {
        const std::vector<sat::Lit> inner = bits(n.a);
        std::vector<sat::Lit> out(n.width, sat::kUndef);
        for (unsigned i = 0; i < n.width; ++i) {
            out[i] = i < inner.size() ? inner[i] : const_lit(false);
        }
        return out;
    }
    case Op::Add:
        return add_bits(bits(n.a), bits(n.b));
    case Op::Sub: {
        const std::vector<sat::Lit> nb = bits(n.b);
        std::vector<sat::Lit> inv(nb.size(), sat::kUndef);
        for (std::size_t i = 0; i < nb.size(); ++i) {
            inv[i] = gate_not(nb[i]);
        }
        std::vector<sat::Lit> one(nb.size(), const_lit(false));
        if (!one.empty()) {
            one[0] = const_lit(true);
        }
        return add_bits(bits(n.a), add_bits(inv, one));
    }
    case Op::Mul:
        return mul_bits(bits(n.a), bits(n.b));
    case Op::And:
    case Op::Or:
    case Op::Xor: {
        const std::vector<sat::Lit> a = bits(n.a);
        const std::vector<sat::Lit> b = bits(n.b);
        const std::size_t w = std::min(a.size(), b.size());
        std::vector<sat::Lit> out(n.width, sat::kUndef);
        for (std::size_t i = 0; i < out.size(); ++i) {
            if (i < w) {
                out[i] = n.op == Op::And   ? gate_and(a[i], b[i])
                         : n.op == Op::Or  ? gate_or(a[i], b[i])
                                           : gate_xor(a[i], b[i]);
            } else {
                // Past the operands' width both are zero-extended; the
                // result of & and | is zero, ^ is zero too. The DAG's
                // width discipline makes this unreachable in practice.
                out[i] = const_lit(false);
            }
        }
        return out;
    }
    case Op::Not: {
        const std::vector<sat::Lit> a = bits(n.a);
        std::vector<sat::Lit> out(n.width, sat::kUndef);
        for (unsigned i = 0; i < n.width; ++i) {
            out[i] = i < a.size() ? gate_not(a[i]) : const_lit(true);
        }
        return out;
    }
    case Op::Neg: {
        const std::vector<sat::Lit> a = bits(n.a);
        std::vector<sat::Lit> inv(a.size(), sat::kUndef);
        for (std::size_t i = 0; i < a.size(); ++i) {
            inv[i] = gate_not(a[i]);
        }
        std::vector<sat::Lit> one(a.size(), const_lit(false));
        if (!one.empty()) {
            one[0] = const_lit(true);
        }
        return add_bits(inv, one);
    }
    case Op::Shl:
        // A constant amount is the common case by far -- handler
        // expressions shift by literals like 8, 32 or 64 -- and it is a
        // re-wire. Only a computed amount pays for a barrel.
        if (dag_->is_const(n.b)) {
            return shl_fixed(bits(n.a), dag_->const_value(n.b));
        }
        return shl_bits(bits(n.a), bits(n.b));
    case Op::Shr:
        if (dag_->is_const(n.b)) {
            return shr_fixed(bits(n.a), dag_->const_value(n.b));
        }
        return shr_bits(bits(n.a), bits(n.b));
    case Op::Sar:
        if (dag_->is_const(n.b)) {
            return sar_fixed(bits(n.a), dag_->const_value(n.b));
        }
        return sar_bits(bits(n.a), bits(n.b));
    case Op::Select: {
        const std::vector<sat::Lit> c = bits(n.c);
        const std::vector<sat::Lit> a = bits(n.a);
        const std::vector<sat::Lit> b = bits(n.b);
        const sat::Lit cond = c.empty() ? const_lit(false) : c[0];
        std::vector<sat::Lit> out(n.width, sat::kUndef);
        for (unsigned i = 0; i < n.width; ++i) {
            const sat::Lit xa = i < a.size() ? a[i] : const_lit(false);
            const sat::Lit xb = i < b.size() ? b[i] : const_lit(false);
            out[i] = gate_mux(cond, xa, xb);
        }
        return out;
    }
    case Op::CmpEQ:
        return {eq_bits(bits(n.a), bits(n.b))};
    case Op::CmpULT:
        return {ult_bits(bits(n.a), bits(n.b))};
    case Op::CmpSLT:
        return {slt_bits(bits(n.a), bits(n.b))};
    }
    return {};
}

// ----------------------------------------------------------------- miter

Equivalence prove_equivalent(expr::DAG& dag, expr::Id a, expr::Id b,
                             bool want_proof, bool force_sat) {
    return prove_equivalent_under(dag, a, b, {}, want_proof, force_sat);
}

Equivalence prove_equivalent_under(expr::DAG& dag, expr::Id a, expr::Id b,
                                   const std::vector<expr::Id>& constraints,
                                   bool want_proof, bool force_sat) {
    Equivalence out;
    // The word-level layer goes first. A polynomial identity is decided
    // by normalizing both sides -- no circuit, no search -- while the
    // same question asked of the circuit path is a multiplier miter,
    // which is the instance CDCL is worst at and which climbs steeply
    // with width. The answer here is unconditional, so the constraints
    // do not weaken it: equal over the ring means equal under them too.
    if (!force_sat) {
        const ring::Verdict verdict =
            ring::prove_equal(dag, a, b, want_proof ? &out.witness : nullptr);
        if (verdict == ring::Verdict::Equal) {
            out.equal = true;
            out.method = Method::Ring;
            return out;
        }
    }
    sat::Solver solver;
    Encoder enc(dag, solver);
    if (want_proof) {
        solver.enable_proof(&out.proof);
    }
    for (const expr::Id c : constraints) {
        const std::vector<sat::Lit> cb = enc.bits(c);
        if (!cb.empty()) {
            const sat::Lit unit = cb[0];
            solver.add_clause(std::span<const sat::Lit>(&unit, 1));
        }
    }
    const std::vector<sat::Lit> ba = enc.bits(a);
    const std::vector<sat::Lit> bbits = enc.bits(b);
    const std::size_t w = std::max(ba.size(), bbits.size());
    std::vector<sat::Lit> diffs;
    for (std::size_t i = 0; i < w; ++i) {
        const sat::Lit xa = i < ba.size() ? ba[i] : enc.const_lit(false);
        const sat::Lit xb =
            i < bbits.size() ? bbits[i] : enc.const_lit(false);
        if (xa == xb) {
            continue;
        }
        if (xa == sat::lit_negate(xb)) {
            diffs.push_back(enc.const_lit(true));
            break;
        }
        diffs.push_back(enc.gate_xor(xa, xb));
    }
    // The miter assertion: some output bit differs from its counterpart.
    // When no bit can differ, the assertion is the false constant --
    // asserted all the same, so the solver reaches its answer through
    // the same path it takes for any other miter. That is what makes a
    // requested certificate a refutation of a formula that exists rather
    // than an empty trace for a question nobody posed: the trace, the
    // formula it refutes, and the answer all come from one solve.
    const sat::Lit differ =
        diffs.empty() ? enc.const_lit(false) : enc.gate_or_all(diffs);
    solver.add_clause(std::span<const sat::Lit>(&differ, 1));
    if (want_proof) {
        // Captured after every clause has been added and before the
        // solve, because the solve deletes clauses: this is the formula
        // as the solver received it, which is exactly the set a DRUP
        // checker starts from.
        out.formula = solver.clause_list();
    }
    const sat::Solver::Status st = solver.solve();
    out.conflicts = solver.conflicts();
    out.propagations = solver.propagations();
    if (st == sat::Solver::Status::Unsat) {
        out.equal = true;
        out.counterexample.clear();
    } else {
        out.equal = false;
        out.proof.clear();
        out.formula.clear();
        out.counterexample = enc.read_inputs();
    }
    return out;
}

Model solve_constraints(expr::DAG& dag,
                        const std::vector<expr::Id>& constraints) {
    Model out;
    sat::Solver solver;
    Encoder enc(dag, solver);
    for (const expr::Id c : constraints) {
        const std::vector<sat::Lit> cb = enc.bits(c);
        if (!cb.empty()) {
            const sat::Lit unit = cb[0];
            solver.add_clause(std::span<const sat::Lit>(&unit, 1));
        }
    }
    const sat::Solver::Status st = solver.solve();
    out.conflicts = solver.conflicts();
    if (st == sat::Solver::Status::Sat) {
        out.sat = true;
        out.inputs = enc.read_inputs();
    }
    return out;
}

}  // namespace occ::devirt::bb
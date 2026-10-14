// The expression DAG: construction with folding and hash-consing.

#include "occ/devirt/expr.h"

#include <cstdio>
#include <cstring>

namespace occ::devirt::expr {

namespace {

std::uint64_t mask_of(unsigned width) {
    if (width >= 64) {
        return ~std::uint64_t{0};
    }
    return (std::uint64_t{1} << width) - 1;
}

// The number of bits `op` needs from its operands before the result width
// is applied. Comparisons produce one bit; everything else keeps the
// operand width.
unsigned result_width(Op op, unsigned a_width, unsigned b_width) {
    switch (op) {
    case Op::CmpEQ:
    case Op::CmpULT:
    case Op::CmpSLT:
        return 1;
    case Op::Not:
    case Op::Neg:
        return a_width;
    case Op::Resize:
        return b_width;  // b is unused; the caller sets the width directly
    default:
        return a_width > b_width ? a_width : b_width;
    }
}

const char* op_name(Op op) {
    switch (op) {
    case Op::Const:  return "const";
    case Op::Input:  return "input";
    case Op::Add:    return "add";
    case Op::Sub:    return "sub";
    case Op::Mul:    return "mul";
    case Op::And:    return "and";
    case Op::Or:     return "or";
    case Op::Xor:    return "xor";
    case Op::Shl:    return "shl";
    case Op::Shr:    return "shr";
    case Op::Sar:    return "sar";
    case Op::Not:    return "not";
    case Op::Neg:    return "neg";
    case Op::Resize: return "resize";
    case Op::Select: return "select";
    case Op::CmpEQ:  return "eq";
    case Op::CmpULT: return "ult";
    case Op::CmpSLT: return "slt";
    }
    return "?";
}

const char* op_infix(Op op) {
    switch (op) {
    case Op::Add:   return " + ";
    case Op::Sub:   return " - ";
    case Op::Mul:   return " * ";
    case Op::And:   return " & ";
    case Op::Or:    return " | ";
    case Op::Xor:   return " ^ ";
    case Op::Shl:   return " << ";
    case Op::Shr:   return " >> ";
    case Op::Sar:   return " >>a ";
    case Op::CmpEQ: return " == ";
    case Op::CmpULT:return " <u ";
    case Op::CmpSLT:return " <s ";
    default:        return nullptr;
    }
}

}  // namespace

Id DAG::constant(std::uint64_t value, unsigned width) {
    Node n;
    n.op = Op::Const;
    n.width = width == 0 ? 64 : width;
    n.imm = value & mask_of(n.width);
    return intern(std::move(n));
}

Id DAG::input(const std::string& name, unsigned width) {
    // An input with the same name and width is the same input -- handlers
    // that read the same stack slot across dispatches must collapse to
    // one symbol. The lookup goes through the ordinal-to-node table: the
    // i-th input is not the i-th node, because constants and operations
    // take node ids of their own, and reading `nodes_[i]` here would
    // return whatever node happened to be created i-th.
    const unsigned w = width == 0 ? 64 : width;
    for (std::size_t i = 0; i < input_names_.size(); ++i) {
        if (input_names_[i] == name && nodes_[input_nodes_[i]].width == w) {
            return input_nodes_[i];
        }
    }
    Node n;
    n.op = Op::Input;
    n.width = w;
    n.imm = input_names_.size();
    n.name = name;
    input_names_.push_back(name);
    const Id id = static_cast<Id>(nodes_.size());
    nodes_.push_back(std::move(n));
    input_nodes_.push_back(id);
    pool_.emplace(dump(id), id);
    return id;
}

Id DAG::binary(Op op, Id a, Id b) {
    if (!valid(a) || !valid(b)) {
        return kNoId;
    }
    Node n;
    n.op = op;
    n.a = a;
    n.b = b;
    n.width = result_width(op, nodes_[a].width, nodes_[b].width);
    return intern(std::move(n));
}

Id DAG::unary(Op op, Id a) {
    if (!valid(a)) {
        return kNoId;
    }
    Node n;
    n.op = op;
    n.a = a;
    n.width = nodes_[a].width;
    return intern(std::move(n));
}

Id DAG::resize(Id a, unsigned width) {
    if (!valid(a) || width == 0) {
        return kNoId;
    }
    if (nodes_[a].width == width) {
        return a;
    }
    Node n;
    n.op = Op::Resize;
    n.a = a;
    n.width = width;
    return intern(std::move(n));
}

Id DAG::select(Id c, Id a, Id b) {
    if (!valid(c) || !valid(a) || !valid(b)) {
        return kNoId;
    }
    Node n;
    n.op = Op::Select;
    n.c = c;
    n.a = a;
    n.b = b;
    n.width = nodes_[a].width > nodes_[b].width ? nodes_[a].width
                                                : nodes_[b].width;
    return intern(std::move(n));
}

Id DAG::intern(Node n) {
    // Constant folding and the trivial identities run before the pool so
    // that a folded node never enters it.
    const Id folded = simplify(n);
    if (folded != kNoId) {
        return folded;
    }
    // Operand widths must agree for the non-comparison operations: fold
    // the mismatch by widening the narrower operand. The interpreter
    // passes the concrete expressions through `resize` itself, but a
    // hand-built expression (a rule's right-hand side) should not have
    // to.
    if (n.op != Op::Const && n.op != Op::Input && n.op != Op::Resize &&
        n.op != Op::Select) {
        const bool cmp = n.op == Op::CmpEQ || n.op == Op::CmpULT ||
                         n.op == Op::CmpSLT;
        const unsigned target = cmp ? 0 : n.width;
        if (!cmp && valid(n.a) && valid(n.b)) {
            if (nodes_[n.a].width < target) {
                n.a = resize(n.a, target);
            }
            if (nodes_[n.b].width < target) {
                n.b = resize(n.b, target);
            }
        }
    }
    const std::string key = [&] {
        std::string k = op_name(n.op);
        k += ':';
        k += std::to_string(n.width);
        k += ':';
        k += std::to_string(n.imm);
        k += ':';
        k += std::to_string(n.a);
        k += ':';
        k += std::to_string(n.b);
        k += ':';
        k += std::to_string(n.c);
        return k;
    }();
    if (const auto it = pool_.find(key); it != pool_.end()) {
        return it->second;
    }
    const Id id = static_cast<Id>(nodes_.size());
    nodes_.push_back(std::move(n));
    pool_.emplace(key, id);
    return id;
}

Id DAG::simplify(Node n) {
    const auto is_const = [this](Id id, std::uint64_t* value) {
        if (valid(id) && nodes_[id].op == Op::Const) {
            *value = nodes_[id].imm;
            return true;
        }
        return false;
    };
    std::uint64_t ca = 0;
    std::uint64_t cb = 0;
    const bool a_const = is_const(n.a, &ca);
    const bool b_const = is_const(n.b, &cb);
    const unsigned w = n.width;
    const std::uint64_t m = mask_of(w);

    // Identity and annihilation rules first, so x^0 collapses even when x
    // is not constant.
    switch (n.op) {
    case Op::Add:
        if (b_const && cb == 0) return n.a;
        if (a_const && ca == 0) return n.b;
        break;
    case Op::Sub:
        if (b_const && cb == 0) return n.a;
        if (n.a == n.b) return constant(0, w);
        break;
    case Op::Mul:
        if (b_const && cb == 1) return n.a;
        if (a_const && ca == 1) return n.b;
        if ((a_const && ca == 0) || (b_const && cb == 0)) {
            return constant(0, w);
        }
        break;
    case Op::And:
        if (b_const && cb == m) return n.a;
        if (a_const && ca == m) return n.b;
        if ((a_const && ca == 0) || (b_const && cb == 0)) {
            return constant(0, w);
        }
        if (n.a == n.b) return n.a;
        break;
    case Op::Or:
        if (b_const && cb == 0) return n.a;
        if (a_const && ca == 0) return n.b;
        if (n.a == n.b) return n.a;
        break;
    case Op::Xor:
        if (b_const && cb == 0) return n.a;
        if (a_const && ca == 0) return n.b;
        if (n.a == n.b) return constant(0, w);
        break;
    case Op::Shl:
    case Op::Shr:
    case Op::Sar:
        if (b_const && cb == 0) return n.a;
        if (a_const && ca == 0) return constant(0, w);
        break;
    case Op::Not:
        // ~~x folds through the pool: the inner not is hash-consed.
        if (valid(n.a) && nodes_[n.a].op == Op::Not) {
            return nodes_[n.a].a;
        }
        break;
    case Op::Neg:
        if (valid(n.a) && nodes_[n.a].op == Op::Neg) {
            return nodes_[n.a].a;
        }
        break;
    case Op::Resize:
        // A chain of resizes folds only when each step narrows: x cut to
        // 32 bits and then to 16 is x cut to 16, but x cut to 32 bits and
        // then widened back to 64 is *not* x -- the widening zeroes the
        // bits the narrowing removed, and folding that step away would
        // hand back those bits as if they had survived.
        if (valid(n.a) && nodes_[n.a].op == Op::Resize &&
            nodes_[n.a].width >= w) {
            return resize(nodes_[n.a].a, w);
        }
        break;
    case Op::Select:
        if (valid(n.c) && nodes_[n.c].op == Op::Const) {
            return nodes_[n.c].imm != 0 ? n.a : n.b;
        }
        if (n.a == n.b) return n.a;
        break;
    default:
        break;
    }

    // Constant folding.
    if (a_const && (b_const || n.b == kNoId) && n.op != Op::Const &&
        n.op != Op::Input) {
        switch (n.op) {
        case Op::Add:   return constant((ca + cb) & m, w);
        case Op::Sub:   return constant((ca - cb) & m, w);
        case Op::Mul:   return constant((ca * cb) & m, w);
        case Op::And:   return constant(ca & cb, w);
        case Op::Or:    return constant(ca | cb, w);
        case Op::Xor:   return constant(ca ^ cb, w);
        case Op::Shl:
            return cb >= w ? constant(0, w)
                           : constant((ca << cb) & m, w);
        case Op::Shr:
            return cb >= w ? constant(0, w) : constant(ca >> cb, w);
        case Op::Sar: {
            if (cb >= w) {
                const bool neg = (ca >> (w - 1)) & 1;
                return constant(neg ? m : 0, w);
            }
            const std::uint64_t sign = (w < 64 && ((ca >> (w - 1)) & 1))
                                           ? (m & ~((std::uint64_t{1} << cb) - 1))
                                           : 0;
            return constant((ca >> cb) | sign, w);
        }
        case Op::Not:   return constant(~ca & m, w);
        case Op::Neg:   return constant((~ca + 1) & m, w);
        case Op::CmpEQ: return constant(ca == cb ? 1 : 0, 1);
        case Op::CmpULT:
            return constant(((ca & m) < (cb & m)) ? 1 : 0, 1);
        case Op::CmpSLT: {
            const std::uint64_t sa = ca & m;
            const std::uint64_t sb = cb & m;
            const bool na = w < 64 ? (sa >> (w - 1)) & 1 : (sa >> 63) & 1;
            const bool nb = w < 64 ? (sb >> (w - 1)) & 1 : (sb >> 63) & 1;
            bool less = false;
            if (na != nb) {
                less = na;
            } else {
                less = sa < sb;
            }
            return constant(less ? 1 : 0, 1);
        }
        case Op::Resize: break;
        case Op::Select: break;
        default: break;
        }
    }
    return kNoId;
}

std::string DAG::dump(Id id) const {
    if (!valid(id)) {
        return "?";
    }
    const Node& n = nodes_[id];
    switch (n.op) {
    case Op::Const: {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      static_cast<unsigned long long>(n.imm));
        return std::string("(const ") + buf + ")";
    }
    case Op::Input:
        return "(input " + n.name + ")";
    case Op::Resize:
        return "(resize " + dump(n.a) + " " + std::to_string(n.width) + ")";
    case Op::Select:
        return "(select " + dump(n.c) + " " + dump(n.a) + " " + dump(n.b) +
               ")";
    case Op::Not:
        return "(not " + dump(n.a) + ")";
    case Op::Neg:
        return "(neg " + dump(n.a) + ")";
    default: {
        std::string out = "(";
        out += op_name(n.op);
        out += ' ';
        out += dump(n.a);
        out += ' ';
        out += dump(n.b);
        out += ')';
        return out;
    }
    }
}

std::string DAG::pretty(Id id) const {
    if (!valid(id)) {
        return "?";
    }
    const Node& n = nodes_[id];
    switch (n.op) {
    case Op::Const: {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      static_cast<unsigned long long>(n.imm));
        return buf;
    }
    case Op::Input:
        return n.name;
    case Op::Resize: {
        // `a` may be absent when a model leans on a value the walk could
        // not name; a resize of nothing is nothing, and saying so is
        // better than reading past the node table for a width.
        if (!valid(n.a)) {
            return "?";
        }
        if (nodes_[n.a].width > n.width) {
            return "(" + std::to_string(n.width) + ")" + pretty(n.a);
        }
        return pretty(n.a);
    }
    case Op::Select:
        return pretty(n.c) + " ? " + pretty(n.a) + " : " + pretty(n.b);
    case Op::Not:
        return "~" + pretty(n.a);
    case Op::Neg:
        return "-" + pretty(n.a);
    default: {
        const char* infix = op_infix(n.op);
        if (infix != nullptr) {
            return "(" + pretty(n.a) + infix + pretty(n.b) + ")";
        }
        return op_name(n.op);
    }
    }
}

std::uint64_t DAG::evaluate(Id id,
                            const std::vector<std::uint64_t>& inputs) const {
    if (!valid(id)) {
        return 0;
    }
    const Node& n = nodes_[id];
    const std::uint64_t m = mask_of(n.width);
    switch (n.op) {
    case Op::Const:
        return n.imm & m;
    case Op::Input:
        return n.imm < inputs.size() ? inputs[n.imm] & m : 0;
    case Op::Add:
        return (evaluate(n.a, inputs) + evaluate(n.b, inputs)) & m;
    case Op::Sub:
        return (evaluate(n.a, inputs) - evaluate(n.b, inputs)) & m;
    case Op::Mul:
        return (evaluate(n.a, inputs) * evaluate(n.b, inputs)) & m;
    case Op::And:
        return evaluate(n.a, inputs) & evaluate(n.b, inputs);
    case Op::Or:
        return evaluate(n.a, inputs) | evaluate(n.b, inputs);
    case Op::Xor:
        return evaluate(n.a, inputs) ^ evaluate(n.b, inputs);
    case Op::Shl: {
        const std::uint64_t s = evaluate(n.b, inputs);
        if (s >= n.width) {
            return 0;
        }
        return (evaluate(n.a, inputs) << s) & m;
    }
    case Op::Shr: {
        const std::uint64_t s = evaluate(n.b, inputs);
        if (s >= n.width) {
            return 0;
        }
        return (evaluate(n.a, inputs) & m) >> s;
    }
    case Op::Sar: {
        const std::uint64_t s = evaluate(n.b, inputs);
        const std::uint64_t v = evaluate(n.a, inputs) & m;
        const bool neg = (v >> (n.width - 1)) & 1;
        // A shift at or past the width fills with the sign bit -- the
        // same answer the folder gives (`cb >= w` there), which is what
        // keeps the two implementations of the semantics in step.
        if (s >= n.width) {
            return neg ? m : 0;
        }
        if (!neg) {
            return v >> s;
        }
        const std::uint64_t fill =
            s == 0 ? 0 : (m & ~((std::uint64_t{1} << s) - 1));
        return (v >> s) | fill;
    }
    case Op::Not:
        return ~evaluate(n.a, inputs) & m;
    case Op::Neg:
        return (~evaluate(n.a, inputs) + 1) & m;
    case Op::Resize:
        return evaluate(n.a, inputs) & m;
    case Op::Select:
        return evaluate(n.c, inputs) != 0 ? evaluate(n.a, inputs) & m
                                          : evaluate(n.b, inputs) & m;
    case Op::CmpEQ:
        return evaluate(n.a, inputs) == evaluate(n.b, inputs) ? 1 : 0;
    case Op::CmpULT:
        return evaluate(n.a, inputs) < evaluate(n.b, inputs) ? 1 : 0;
    case Op::CmpSLT: {
        const std::uint64_t v = evaluate(n.a, inputs);
        const std::uint64_t u = evaluate(n.b, inputs);
        // Mixed widths compare as the narrower operand zero-extended, so
        // the sign bit lives at the wider operand's top -- the same place
        // `slt_bits` reads it. Reading it at the left operand's width
        // would call a zero-extended negative-looking value positive.
        const unsigned bw = nodes_[n.a].width > nodes_[n.b].width
                                ? nodes_[n.a].width
                                : nodes_[n.b].width;
        const bool na = (v >> (bw - 1)) & 1;
        const bool nb = (u >> (bw - 1)) & 1;
        if (na != nb) {
            return na ? 1 : 0;
        }
        return v < u ? 1 : 0;
    }
    }
    return 0;
}

std::vector<unsigned> DAG::inputs_of(Id id) const {
    std::vector<unsigned> out;
    std::vector<Id> stack{id};
    std::vector<bool> seen(nodes_.size(), false);
    while (!stack.empty()) {
        const Id cur = stack.back();
        stack.pop_back();
        if (!valid(cur) || seen[cur]) {
            continue;
        }
        seen[cur] = true;
        const Node& n = nodes_[cur];
        if (n.op == Op::Input) {
            out.push_back(static_cast<unsigned>(n.imm));
            continue;
        }
        if (valid(n.a)) stack.push_back(n.a);
        if (valid(n.b)) stack.push_back(n.b);
        if (valid(n.c)) stack.push_back(n.c);
    }
    return out;
}

}  // namespace occ::devirt::expr
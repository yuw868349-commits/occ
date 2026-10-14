// The expression DAG the de-virtualizer reasons in.
//
// A virtualized function is a program for a machine that does not exist:
// its instruction stream is a sequence of handler invocations, and each
// handler moves values between the virtual stack, the bytecode cursor and
// scratch registers. To recover the original logic, the values have to be
// given names and the operations given shape -- which is what this DAG
// is: an SSA expression over bit-vectors, where every node is either a
// constant, an input (a virtual-stack slot, a bytecode word), or an
// operation on other nodes.
//
// The DAG is hash-consed: constructing the same operation on the same
// operands twice returns the same node. That is not a micro-optimization
// -- it is what lets the simplifier and the e-graph below reason about
// equality without a separate canonicalization pass. Constant folding and
// the algebraically trivial identities (x+0, x^0, x&0, x*1, ~~x) are
// applied at construction, so a fold never has to be re-run.
//
// Widths are carried per node because a virtual machine mixes widths
// freely -- VMProtect handlers load a byte with `mov al,[rsi]` and add it
// to a 64-bit stack slot in one dispatch. Every operation requires its
// operands to share the node's width; the builder zero-extends or
// truncates explicitly through `resize`, which is where the width
// discipline lives.
//
// The DAG is deliberately not a graph of pointers: nodes live in a
// vector, an expression is an index, and the owner is a single object.
// That keeps it trivially copyable into a certificate, printable to
// pseudo-code, and bit-blastable into the SAT solver without an
// ownership story.

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace occ::devirt::expr {

// An expression is an index into the DAG's node list.
using Id = std::uint32_t;
inline constexpr Id kNoId = 0xFFFFFFFFu;

enum class Op : std::uint8_t {
    Const,     // width-bit constant, `imm`
    Input,     // a named input; `imm` is the input's ordinal
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    Shr,       // logical shift right
    Sar,       // arithmetic shift right
    Not,
    Neg,
    Resize,    // zero-extend or truncate `a` to the node's width
    Select,    // c ? a : b (c is 1-bit)
    CmpEQ,     // a == b, result is 1-bit
    CmpULT,    // a < b unsigned, 1-bit
    CmpSLT,    // a < b signed, 1-bit
};

struct Node {
    Op op = Op::Const;
    unsigned width = 64;
    std::uint64_t imm = 0;   // Const value; Input ordinal
    Id a = kNoId;
    Id b = kNoId;
    Id c = kNoId;
    // Input nodes: the name is kept beside the node so a report can say
    // "st0" rather than "input #4".
    std::string name;
};

// What a run bound each input to, as a trace supplies it. `known` is the
// part that matters: a value of zero and an input the trace never carried
// are the same number, and only the flag tells them apart -- which is the
// difference between a value the machine held and one nothing observed.
struct Bindings {
    std::vector<std::uint64_t> values;
    std::vector<bool> known;

    [[nodiscard]] bool has(unsigned ordinal) const noexcept {
        return ordinal < known.size() && known[ordinal];
    }
    [[nodiscard]] std::uint64_t value(unsigned ordinal) const noexcept {
        return ordinal < values.size() ? values[ordinal] : 0;
    }
};

class DAG {
public:
    DAG() = default;

    [[nodiscard]] std::size_t size() const noexcept { return nodes_.size(); }
    [[nodiscard]] const Node& node(Id id) const { return nodes_[id]; }
    [[nodiscard]] bool valid(Id id) const noexcept {
        return id < nodes_.size();
    }

    // -- construction --------------------------------------------------

    [[nodiscard]] Id constant(std::uint64_t value, unsigned width);
    [[nodiscard]] Id input(const std::string& name, unsigned width);

    [[nodiscard]] Id binary(Op op, Id a, Id b);
    [[nodiscard]] Id unary(Op op, Id a);
    [[nodiscard]] Id resize(Id a, unsigned width);
    [[nodiscard]] Id select(Id c, Id a, Id b);
    // Convenience wrappers with the operand-width discipline applied.
    [[nodiscard]] Id add(Id a, Id b) { return binary(Op::Add, a, b); }
    [[nodiscard]] Id sub(Id a, Id b) { return binary(Op::Sub, a, b); }
    [[nodiscard]] Id mul(Id a, Id b) { return binary(Op::Mul, a, b); }
    [[nodiscard]] Id bit_and(Id a, Id b) { return binary(Op::And, a, b); }
    [[nodiscard]] Id bit_or(Id a, Id b) { return binary(Op::Or, a, b); }
    [[nodiscard]] Id bit_xor(Id a, Id b) { return binary(Op::Xor, a, b); }
    [[nodiscard]] Id shl(Id a, Id b) { return binary(Op::Shl, a, b); }
    [[nodiscard]] Id shr(Id a, Id b) { return binary(Op::Shr, a, b); }
    [[nodiscard]] Id sar(Id a, Id b) { return binary(Op::Sar, a, b); }
    [[nodiscard]] Id bit_not(Id a) { return unary(Op::Not, a); }
    [[nodiscard]] Id neg(Id a) { return unary(Op::Neg, a); }
    [[nodiscard]] Id cmp_eq(Id a, Id b) { return binary(Op::CmpEQ, a, b); }
    [[nodiscard]] Id cmp_ult(Id a, Id b) { return binary(Op::CmpULT, a, b); }
    [[nodiscard]] Id cmp_slt(Id a, Id b) { return binary(Op::CmpSLT, a, b); }

    // -- reading -------------------------------------------------------

    [[nodiscard]] unsigned width(Id id) const {
        return valid(id) ? nodes_[id].width : 0;
    }
    [[nodiscard]] bool is_const(Id id) const {
        return valid(id) && nodes_[id].op == Op::Const;
    }
    [[nodiscard]] std::uint64_t const_value(Id id) const {
        return valid(id) ? nodes_[id].imm : 0;
    }
    // The names of the inputs, in ordinal order.
    [[nodiscard]] const std::vector<std::string>& input_names() const {
        return input_names_;
    }

    // A canonical textual form, used for CSE keys and for reports. It is
    // an s-expression: `(add x (const 4))`.
    [[nodiscard]] std::string dump(Id id) const;

    // Pseudo-code form on one line: `rax + 4`, `st0 ^ 0xff`. Prefer this
    // for any user-facing output.
    [[nodiscard]] std::string pretty(Id id) const;

    // The same pseudo-code with the inputs the trace pinned down replaced
    // by the values they held. An input the trace did not bind keeps its
    // name, so one string says both what the run fixed and what it left
    // open. A value is printed at the input's own width, because a
    // thirty-two-bit slot that held `0x41` did not hold
    // `0x0000000000000041` -- the width is part of what was observed.
    [[nodiscard]] std::string pretty_bound(Id id,
                                           const Bindings& bound) const;

    // -- evaluation ----------------------------------------------------
    //
    // Evaluate the expression with the inputs bound to the given values.
    // Used by the difference tests and by the truth-table learner; the
    // SAT path proves equivalence without evaluating.
    [[nodiscard]] std::uint64_t evaluate(
        Id id, const std::vector<std::uint64_t>& inputs) const;

    // Every input ordinal reachable from `id`, in first-use order.
    [[nodiscard]] std::vector<unsigned> inputs_of(Id id) const;

private:
    // The two halves of `evaluate`: the recursive walk, and the memo that
    // keeps a shared node from being walked twice.
    [[nodiscard]] std::uint64_t evaluate_memo(
        Id id, const std::vector<std::uint64_t>& inputs,
        std::vector<std::uint64_t>& memo, std::vector<char>& done) const;
    [[nodiscard]] std::uint64_t evaluate_raw(
        Id id, const std::vector<std::uint64_t>& inputs,
        std::vector<std::uint64_t>& memo, std::vector<char>& done) const;
    // The one walk both renderings are: the pseudo-code form, with the
    // inputs either named or replaced by the values a trace bound, and a
    // budget that stops it. A graph shared by two parents would otherwise
    // be printed twice, and twice again, and a printer that can hang on
    // the program it describes is not one a report can use.
    void render_into(Id id, const Bindings* bound, std::size_t* budget,
                     std::string* out) const;
    [[nodiscard]] Id intern(Node n);
    [[nodiscard]] Id simplify(Node n);

    std::vector<Node> nodes_;
    std::vector<std::string> input_names_;
    // The node id of each input, in ordinal order. A separate table
    // because a node id and an input ordinal are not the same number:
    // constants and operations occupy node ids too, so the i-th input is
    // not necessarily the i-th node.
    std::vector<Id> input_nodes_;
    // Hash-consing table: key is (op, width, imm, a, b, c) folded into a
    // string through the canonical dump. A string key is not the fastest
    // possible choice and it is the one that cannot go wrong: the DAG is
    // small (thousands of nodes for a whole virtualized function) and the
    // key is unambiguous by construction.
    std::unordered_map<std::string, Id> pool_;
};

}  // namespace occ::devirt::expr
#include "occ/devirt/solve.h"

#include <algorithm>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "occ/devirt/bitblast.h"

namespace occ::devirt::lift {

namespace {

// The memory is kept in eight-byte cells, the unit a machine writes in
// and the unit the trace reads. A virtual stack pointer is not kept
// aligned -- a handler pushes a word as readily as a qword -- so a
// one-byte store can land in the middle of a cell, and a cell is what has
// to be composed to answer a read that crosses one.
constexpr unsigned kCellBits = 64;
constexpr std::uint64_t kCellMask = ~std::uint64_t{7};

// How deep a "must be zero" split follows before it gives up and leaves
// the rest to the solver. A split that runs away would be a bug in the
// walk, not a property of the program, so the cap is a guard and not a
// policy.
constexpr unsigned kMaxSplitDepth = 4096;

// The bytes a solve may choose, one expression input per byte. A region
// is declared by address and length; each byte's name is its index in the
// declaration order, which is what a report prints and what a caller
// reads the answer back under.
class FreeBytes {
public:
    FreeBytes(expr::DAG& dag, const std::vector<UnknownRegion>& regions)
        : dag_(&dag), regions_(regions) {
        std::uint64_t index = 0;
        for (const UnknownRegion& r : regions) {
            for (std::uint64_t k = 0; k < r.size; ++k, ++index) {
                char name[24];
                std::snprintf(name, sizeof(name), "in[%llu]",
                              static_cast<unsigned long long>(index));
                const expr::Id id = dag_->input(name, 8);
                by_va_[r.va + k] = id;
                index_of_[static_cast<unsigned>(dag_->node(id).imm)] = index;
            }
        }
    }

    [[nodiscard]] bool covers(std::uint64_t va) const {
        return by_va_.find(va) != by_va_.end();
    }
    [[nodiscard]] expr::Id at(std::uint64_t va) const {
        return by_va_.at(va);
    }
    [[nodiscard]] bool is_free(unsigned ordinal) const {
        return index_of_.find(ordinal) != index_of_.end();
    }
    [[nodiscard]] std::size_t byte_count() const { return by_va_.size(); }

    // The values the search chose, cut back into the regions they were
    // declared as. `values` is indexed by input ordinal, which is not the
    // same number as a byte's place in the declaration.
    [[nodiscard]] std::vector<std::vector<std::uint8_t>> gather(
        const std::vector<std::uint64_t>& values) const {
        std::vector<std::vector<std::uint8_t>> out;
        for (const UnknownRegion& r : regions_) {
            std::vector<std::uint8_t> bytes(r.size, 0);
            for (std::uint64_t k = 0; k < r.size; ++k) {
                const expr::Id id = at(r.va + k);
                const auto ordinal = static_cast<unsigned>(dag_->node(id).imm);
                bytes[k] = static_cast<std::uint8_t>(
                    ordinal < values.size() ? values[ordinal] & 0xffu : 0u);
            }
            out.push_back(std::move(bytes));
        }
        return out;
    }

private:
    expr::DAG* dag_;
    std::vector<UnknownRegion> regions_;
    std::map<std::uint64_t, expr::Id> by_va_;
    std::map<unsigned, std::uint64_t> index_of_;
};

// A substituted expression that reaches no input at all is a number, and
// this is how the replay reads it. Not the DAG's own `is_const`: the
// builder folds the identities that involve a zero or a one, so a sum of
// two constants is still a node -- and a sum of two constants is a
// number, which is what an address has to be before the replay can point
// at a cell.
[[nodiscard]] bool constant_value(const expr::DAG& dag, expr::Id id,
                                  std::uint64_t* out) {
    if (!dag.valid(id)) {
        return false;
    }
    if (dag.is_const(id)) {
        *out = dag.const_value(id);
        return true;
    }
    if (!dag.inputs_of(id).empty()) {
        return false;
    }
    const std::vector<std::uint64_t> none;
    *out = dag.evaluate(id, none);
    return true;
}

// Whether an expression is a number, whichever way it was built. The
// DAG's own `is_const` recognizes only a node that was born a constant;
// this recognizes one that has become one, which is what a substituted
// expression is whenever every input under it was bound.
[[nodiscard]] bool is_ground(const expr::DAG& dag, expr::Id id) {
    return dag.valid(id) && dag.inputs_of(id).empty();
}

// An expression with every input replaced by what the row bound it to.
//
// This is the whole of the replay: a handler's model is written over the
// inputs it was lifted with -- the two pointers, the slots, the bytecode
// words -- and running it for a row means saying what those were. The
// rebuild goes through the DAG's own constructors, so the result is
// hash-consed like any other expression and two rows that computed the
// same thing share a node instead of a shape.
[[nodiscard]] expr::Id substitute(expr::DAG& dag, expr::Id id,
                                  const std::vector<expr::Id>& binding) {
    if (!dag.valid(id)) {
        return expr::kNoId;
    }
    const expr::Node n = dag.node(id);
    if (n.op == expr::Op::Const) {
        return id;
    }
    if (n.op == expr::Op::Input) {
        const auto ordinal = static_cast<unsigned>(n.imm);
        if (ordinal >= binding.size() || binding[ordinal] == expr::kNoId) {
            return id;
        }
        const expr::Id bound = binding[ordinal];
        return dag.width(bound) == n.width ? bound : dag.resize(bound, n.width);
    }
    const expr::Id a = substitute(dag, n.a, binding);
    const expr::Id b = substitute(dag, n.b, binding);
    const expr::Id c = substitute(dag, n.c, binding);
    switch (n.op) {
    case expr::Op::Resize:
        return dag.resize(a, n.width);
    case expr::Op::Not:
    case expr::Op::Neg:
        return dag.unary(n.op, a);
    case expr::Op::Select:
        return dag.select(c, a, b);
    default: {
        const expr::Id built = dag.binary(n.op, a, b);
        // A rebuilt node takes its width from its operands, which are the
        // same widths the original's were; the test costs nothing and
        // covers the case where a builder's rule and the original's width
        // disagree, which would silently truncate an expression.
        return dag.width(built) == n.width ? built : dag.resize(built, n.width);
    }
    }
}

// The machine's memory as the replay walks it: what the program wrote,
// over what the run recorded.
//
// A read answers with the written bytes where they cover it and their own
// bytes where they do not. That is what makes a one-byte store over a
// recorded cell mean what it means on the machine -- the other seven
// bytes keep the value the run had -- instead of discarding the half the
// store did not touch. It is the rule the conformance check's shadow
// follows, for the same reason, with expressions instead of numbers.
class ReplayMemory {
public:
    ReplayMemory(expr::DAG* dag, const FreeBytes* free_bytes,
                 CodeReader code_bytes, void* code_ctx)
        : dag_(dag),
          free_bytes_(free_bytes),
          code_bytes_(code_bytes),
          code_ctx_(code_ctx) {}

    // `width` bits at `va`, as an expression.
    [[nodiscard]] expr::Id read(std::uint64_t va, unsigned width) {
        const unsigned bytes = width / 8;
        if (bytes == 0 || bytes > 8) {
            return dag_->constant(0, width);
        }
        const std::uint64_t cell_va = va & kCellMask;
        const unsigned shift = static_cast<unsigned>((va - cell_va) * 8);
        const unsigned mask_bits = bytes * 8;
        expr::Id out = cell(cell_va);
        if (shift != 0) {
            out = dag_->shr(out, dag_->constant(shift, kCellBits));
        }
        if (mask_bits < kCellBits) {
            const std::uint64_t mask = (std::uint64_t{1} << mask_bits) - 1;
            out = dag_->bit_and(out, dag_->constant(mask, kCellBits));
        }
        // A read that crosses a cell boundary is composed from both
        // cells: eight bytes is a cell, and a read of whatever width at
        // whatever address is not obliged to be.
        if (shift != 0 && shift + mask_bits > kCellBits) {
            const unsigned low_bits = kCellBits - shift;
            const unsigned high_bits = mask_bits - low_bits;
            const expr::Id high =
                read(cell_va + 8, high_bits < 8 ? 8 : high_bits);
            const expr::Id lifted = dag_->shl(
                dag_->resize(high, kCellBits),
                dag_->constant(low_bits, kCellBits));
            out = dag_->bit_or(out, lifted);
        }
        return dag_->resize(out, width);
    }

    // Writes `bytes` bytes of `value` at `va`, leaving every byte the
    // write does not reach as it was.
    void write(std::uint64_t va, expr::Id value, unsigned bytes) {
        if (bytes == 0 || bytes > 8) {
            return;
        }
        const expr::Id widened = dag_->resize(value, kCellBits);
        std::uint64_t at = va;
        unsigned left = bytes;
        while (left > 0) {
            const std::uint64_t cell_va = at & kCellMask;
            const unsigned shift =
                static_cast<unsigned>((at - cell_va) * 8);
            const unsigned take = std::min<unsigned>(
                left, static_cast<unsigned>(8 - shift / 8));
            const std::uint64_t field =
                (take == 8) ? ~std::uint64_t{0}
                            : ((std::uint64_t{1} << (take * 8)) - 1);
            const std::uint64_t mask = field << shift;
            const expr::Id pieces =
                dag_->shl(widened, dag_->constant(shift, kCellBits));
            const expr::Id keep = dag_->bit_and(
                cell(cell_va), dag_->constant(~mask, kCellBits));
            cells_[cell_va] = dag_->bit_or(
                keep, dag_->bit_and(pieces, dag_->constant(mask, kCellBits)));
            at += take;
            left -= take;
        }
    }

    // A store whose address the replay could not fix to a number. Nothing
    // can be said about which cells it covered, so it is counted and left
    // out rather than guessed at: a wrong answer here would look like a
    // right one.
    void note_symbolic_store() { ++symbolic_stores_; }
    [[nodiscard]] std::size_t symbolic_stores() const {
        return symbolic_stores_;
    }
    [[nodiscard]] std::size_t unrecorded() const { return unrecorded_; }

private:
    // The eight bytes at a cell's address as one expression: the
    // program's own value where it wrote the cell, otherwise the eight
    // bytes the run recorded.
    [[nodiscard]] expr::Id cell(std::uint64_t cell_va) {
        const auto it = cells_.find(cell_va);
        if (it != cells_.end()) {
            return it->second;
        }
        expr::Id out = dag_->constant(0, kCellBits);
        for (unsigned k = 0; k < 8; ++k) {
            const expr::Id b = recorded_byte(cell_va + k);
            out = dag_->bit_or(
                out, dag_->shl(dag_->resize(b, kCellBits),
                               dag_->constant(8ull * k, kCellBits)));
        }
        return out;
    }

    // One byte of the run's own record, or the free byte that stands in
    // for it, or a variable of its own when the run recorded nothing.
    //
    // The order is the whole rule: a byte the program wrote is the
    // program's, a byte the caller declared unknown is the caller's --
    // the declaration overrides what the run had, because that is what
    // declaring it means -- a byte the run recorded is the run's, and a
    // byte nothing reaches is a variable that is counted so a solution
    // leaning on one can be reported as leaning on it.
    [[nodiscard]] expr::Id recorded_byte(std::uint64_t va) {
        const auto written = cells_.find(va & kCellMask);
        if (written != cells_.end()) {
            return dag_->resize(
                dag_->shr(written->second,
                          dag_->constant((va & 7) * 8, kCellBits)),
                8);
        }
        if (free_bytes_ != nullptr && free_bytes_->covers(va)) {
            return free_bytes_->at(va);
        }
        if (code_bytes_ != nullptr) {
            std::uint64_t v = 0;
            if (code_bytes_(code_ctx_, va, 8, &v)) {
                return dag_->constant(v & 0xffu, 8);
            }
        }
        char name[40];
        std::snprintf(name, sizeof(name), "unrecorded[0x%llx]",
                      static_cast<unsigned long long>(va));
        ++unrecorded_;
        return dag_->input(name, 8);
    }

    expr::DAG* dag_;
    const FreeBytes* free_bytes_;
    CodeReader code_bytes_;
    void* code_ctx_;
    std::map<std::uint64_t, expr::Id> cells_;
    std::size_t symbolic_stores_ = 0;
    std::size_t unrecorded_ = 0;
};

// A constraint the goals turned into: `lhs == rhs`, at `lhs`'s width.
struct Constraint {
    expr::Id lhs = expr::kNoId;
    std::uint64_t rhs = 0;
};

// The "must be zero" question, pushed through the operations that carry
// it.
//
// A bitwise operation is bit for bit, so narrowing one distributes over
// it: the low bits of `a | b` are the low bits of each, and both have to
// be zero. A widening is exact. A mask that keeps every bit being asked
// about is not being asked about, and can be dropped. Each step is an
// equivalence at the width the question is asked at -- not a heuristic --
// so what the solver is handed afterwards is the same question in smaller
// pieces rather than a weaker one. Nothing here looks at what the program
// is or where it came from: the pieces fall out of the algebra.
//
// The reason it is worth doing: a machine that accumulates its result
// from independent pieces -- an `or` of one comparison per byte, which is
// what a checker of a fixed-length input compiles to -- hands the solver
// one small question per piece instead of one question about all of them
// at once, and the difference is between milliseconds and a budget spent.
void split_zero(expr::DAG& dag, expr::Id id, std::vector<Constraint>* out,
                unsigned depth) {
    if (depth > kMaxSplitDepth || !dag.valid(id)) {
        out->push_back(Constraint{id, 0});
        return;
    }
    const expr::Node n = dag.node(id);
    if (n.op == expr::Op::Or) {
        split_zero(dag, n.a, out, depth + 1);
        split_zero(dag, n.b, out, depth + 1);
        return;
    }
    if (n.op == expr::Op::Resize) {
        const unsigned inner = dag.width(n.a);
        if (n.width >= inner) {
            split_zero(dag, n.a, out, depth + 1);
            return;
        }
        const expr::Node& in = dag.node(n.a);
        const std::uint64_t low =
            (n.width == 64) ? ~std::uint64_t{0}
                            : ((std::uint64_t{1} << n.width) - 1);
        if (in.op == expr::Op::And) {
            // A constant operand that keeps every bit being asked about
            // is not being asked about: what it masks away is above the
            // width the question is at.
            for (int side = 0; side < 2; ++side) {
                const expr::Id c = side == 0 ? in.a : in.b;
                const expr::Id other = side == 0 ? in.b : in.a;
                if (dag.is_const(c) && (dag.const_value(c) & low) == low) {
                    split_zero(dag, dag.resize(other, n.width), out,
                               depth + 1);
                    return;
                }
            }
        }
        if (in.op == expr::Op::Or) {
            const expr::Id a = dag.resize(in.a, n.width);
            const expr::Id b = dag.resize(in.b, n.width);
            split_zero(dag, dag.bit_or(a, b), out, depth + 1);
            return;
        }
        // An `and` or an `xor` of two nonzero halves can still be zero,
        // so pushing the narrowing through one would change the question.
    }
    out->push_back(Constraint{id, 0});
}

// The values an expression reaches, split into the ones the caller
// declared and the ones no run recorded.
struct Support {
    bool free = false;
    bool unrecorded = false;
    std::vector<unsigned> free_ordinals;
};

[[nodiscard]] Support support_of(const expr::DAG& dag,
                                 const FreeBytes& free_bytes,
                                 std::size_t model_inputs, expr::Id id) {
    Support s;
    for (const unsigned o : dag.inputs_of(id)) {
        if (free_bytes.is_free(o)) {
            s.free = true;
            s.free_ordinals.push_back(o);
        } else if (o >= model_inputs) {
            s.unrecorded = true;
        }
    }
    return s;
}

// ---------------------------------------------------------------- goals

// How deep a goal's tree may be read before the reader calls it a
// runaway. The parser already caps its own descent; this is the second
// gate, for a tree built by something other than the parser.
constexpr unsigned kMaxGoalDepth = 256;

// What a goal's leaves are resolved against: the state the replay ended
// in. It is deliberately the same objects the replay itself used and not
// a copy -- a goal reads the register file out of the very memory model
// the program wrote, so "the state the last dispatch left behind" means
// one thing in this file rather than two.
struct GoalContext {
    expr::DAG* dag = nullptr;
    ReplayMemory* memory = nullptr;
    std::uint64_t final_stack = 0;
    unsigned regfile_width = 64;
    std::uint64_t code_base = 0;
    bool have_code = false;
    const Row* last = nullptr;
    std::size_t* unrecorded = nullptr;
    // The first address the goal read, for the report: a caller that
    // named a slot by displacement wants to see where the machine put it.
    std::uint64_t address = 0;
    bool have_address = false;
    std::string error;
};

// `x != 0`, as a one-bit value. The machine's comparisons are its own
// arithmetic; a logical connective is not an operation it has, so the
// connectives are built out of the comparisons it does have.
[[nodiscard]] expr::Id truth_of(expr::DAG& dag, expr::Id x) {
    return dag.bit_not(dag.cmp_eq(x, dag.constant(0, dag.width(x))));
}

[[nodiscard]] expr::Id lower_goal(const GoalNode& n, GoalContext* ctx,
                                  unsigned want, unsigned depth) {
    if (depth > kMaxGoalDepth) {
        ctx->error = "the goal nests too deeply to read";
        return expr::kNoId;
    }
    expr::DAG& dag = *ctx->dag;
    const auto lower = [&](const GoalNode& kid, unsigned w) {
        return lower_goal(kid, ctx, w, depth + 1);
    };
    // A leaf that names a place has to name it by a number: the replay
    // can only read memory it can point at, and an address built out of
    // the unknown is a question about a place, not a question about what
    // is in one. Saying which -- rather than reading address zero -- is
    // the difference between a wrong answer and no answer.
    const auto lower_address = [&](const GoalNode& index,
                                   std::uint64_t* out) {
        const expr::Id id = lower(index, 0);
        if (id == expr::kNoId || !constant_value(dag, id, out)) {
            ctx->error = "the address in '" + render_goal(index) +
                         "' is not a number the replay can point at";
            return false;
        }
        return true;
    };
    switch (n.kind) {
    case GoalNode::Kind::Const:
        return dag.constant(n.imm, want != 0 ? want : 64u);

    case GoalNode::Kind::Register: {
        const unsigned width = want != 0 ? want : 64u;
        std::uint64_t v = 0;
        if (ctx->last != nullptr && row_register(*ctx->last, n.name, &v)) {
            return dag.constant(v, width);
        }
        // The trace did not carry it. Its name is kept and it is counted,
        // the same rule the replay follows for a register it had to
        // invent: a goal built on one is a candidate and not a fact.
        if (ctx->unrecorded != nullptr) {
            ++(*ctx->unrecorded);
        }
        return dag.input("unrecorded[" + n.name + "]", width);
    }

    case GoalNode::Kind::Regfile: {
        std::uint64_t off = 0;
        if (!lower_address(n.kids[0], &off)) {
            return expr::kNoId;
        }
        const std::uint64_t addr =
            ctx->final_stack + static_cast<std::uint64_t>(off);
        if (!ctx->have_address) {
            ctx->address = addr;
            ctx->have_address = true;
        }
        return ctx->memory->read(addr, ctx->regfile_width);
    }

    case GoalNode::Kind::Code: {
        std::uint64_t off = 0;
        if (!lower_address(n.kids[0], &off)) {
            return expr::kNoId;
        }
        if (!ctx->have_code) {
            ctx->error = "code[...] needs the buffer's base, and the trace "
                         "carried no register holding it";
            return expr::kNoId;
        }
        return ctx->memory->read(ctx->code_base + off, 8);
    }

    case GoalNode::Kind::Memory: {
        std::uint64_t addr = 0;
        if (!lower_address(n.kids[0], &addr)) {
            return expr::kNoId;
        }
        if (!ctx->have_address) {
            ctx->address = addr;
            ctx->have_address = true;
        }
        return ctx->memory->read(addr,
                                 n.imm != 0 ? static_cast<unsigned>(n.imm)
                                            : 64u);
    }

    case GoalNode::Kind::Not:
        return dag.bit_not(lower(n.kids[0], want));
    case GoalNode::Kind::Neg:
        return dag.neg(lower(n.kids[0], want));
    case GoalNode::Kind::LogNot: {
        const expr::Id x = lower(n.kids[0], 0);
        if (x == expr::kNoId) {
            return expr::kNoId;
        }
        return dag.bit_not(truth_of(dag, x));
    }

    case GoalNode::Kind::LogAnd:
    case GoalNode::Kind::LogOr: {
        const expr::Id a = lower(n.kids[0], 0);
        const expr::Id b = lower(n.kids[1], 0);
        if (a == expr::kNoId || b == expr::kNoId) {
            return expr::kNoId;
        }
        const expr::Id ta = truth_of(dag, a);
        const expr::Id tb = truth_of(dag, b);
        return n.kind == GoalNode::Kind::LogAnd ? dag.bit_and(ta, tb)
                                                : dag.bit_or(ta, tb);
    }

    case GoalNode::Kind::Eq:
    case GoalNode::Kind::Ne:
    case GoalNode::Kind::Ult:
    case GoalNode::Kind::Ule:
    case GoalNode::Kind::Slt:
    case GoalNode::Kind::Sle: {
        expr::Id a = lower(n.kids[0], 0);
        if (a == expr::kNoId) {
            return expr::kNoId;
        }
        // Comparisons need their operands at one width, and the machine's
        // own compare is what the widths have to be for the answer to
        // mean the same thing the machine would have meant.
        expr::Id b = lower(n.kids[1], dag.width(a));
        if (b == expr::kNoId) {
            return expr::kNoId;
        }
        const unsigned w = dag.width(a) > dag.width(b) ? dag.width(a)
                                                       : dag.width(b);
        a = dag.resize(a, w);
        b = dag.resize(b, w);
        switch (n.kind) {
        case GoalNode::Kind::Eq:  return dag.cmp_eq(a, b);
        case GoalNode::Kind::Ne:
            return dag.bit_not(dag.cmp_eq(a, b));
        case GoalNode::Kind::Ult: return dag.cmp_ult(a, b);
        case GoalNode::Kind::Ule: return dag.bit_not(dag.cmp_ult(b, a));
        case GoalNode::Kind::Slt: return dag.cmp_slt(a, b);
        default:                  return dag.bit_not(dag.cmp_slt(b, a));
        }
    }

    default: {
        expr::Id a = lower(n.kids[0], 0);
        if (a == expr::kNoId) {
            return expr::kNoId;
        }
        expr::Id b = lower(n.kids[1], dag.width(a));
        if (b == expr::kNoId) {
            return expr::kNoId;
        }
        const unsigned w = dag.width(a) > dag.width(b) ? dag.width(a)
                                                       : dag.width(b);
        a = dag.resize(a, w);
        b = dag.resize(b, w);
        switch (n.kind) {
        case GoalNode::Kind::Add: return dag.add(a, b);
        case GoalNode::Kind::Sub: return dag.sub(a, b);
        case GoalNode::Kind::Mul: return dag.mul(a, b);
        case GoalNode::Kind::And: return dag.bit_and(a, b);
        case GoalNode::Kind::Or:  return dag.bit_or(a, b);
        case GoalNode::Kind::Xor: return dag.bit_xor(a, b);
        case GoalNode::Kind::Shl: return dag.shl(a, b);
        default:                  return dag.shr(a, b);
        }
    }
    }
}

}  // namespace

SolveResult solve(Model& model, const std::vector<Handler>& handlers,
                  const std::vector<Row>& rows,
                  const std::vector<std::size_t>& handler_of_row,
                  CodeReader code_bytes, void* code_ctx,
                  const SolveOptions& options, const Handler* dispatcher) {
    SolveResult out;
    if (rows.empty() || handler_of_row.empty()) {
        out.reason = "the trace has no dispatch to replay";
        return out;
    }
    if (options.unknown.empty()) {
        out.reason = "no unknown region was declared, so there is nothing "
                     "for the solve to choose";
        return out;
    }
    if (options.goals.empty()) {
        out.reason = "no goal was declared, so there is nothing to satisfy";
        return out;
    }

    expr::DAG& dag = model.dag;
    FreeBytes free_bytes(dag, options.unknown);

    ReplayMemory memory(&dag, &free_bytes, code_bytes, code_ctx);
    const std::string& stack_reg = model.convention.stack;
    const std::string& cursor_reg = model.convention.cursor;

    // The binding of the model's inputs for one row, as expressions over
    // the free bytes. The same order the conformance check binds them in:
    // ordinal order, because a load's address is built out of the inputs
    // that come before it.
    std::vector<expr::Id> binding(model.inputs.size(), expr::kNoId);
    std::uint64_t final_stack = 0;

    // What a handler's model is read with: the pointers the interpreter
    // carried when the handler was entered, and the row its registers
    // come from.
    const auto bind_inputs = [&](const Row& row, std::uint64_t stack,
                                 bool have_stack, std::uint64_t cursor,
                                 bool have_cursor) {
        for (std::size_t k = 0; k < model.inputs.size(); ++k) {
            const Model::Input& in = model.inputs[k];
            expr::Id value = expr::kNoId;
            switch (in.kind) {
            case Model::Input::Kind::Slot:
                if (have_stack) {
                    value = memory.read(
                        stack + static_cast<std::uint64_t>(in.disp),
                        in.width);
                }
                break;
            case Model::Input::Kind::Code:
                if (have_cursor) {
                    value = memory.read(
                        cursor + static_cast<std::uint64_t>(in.disp),
                        in.width);
                }
                break;
            case Model::Input::Kind::Image:
                value = memory.read(in.va, in.width);
                break;
            case Model::Input::Kind::Reg: {
                std::uint64_t v = 0;
                if (row_register(row, in.name, &v)) {
                    value = dag.constant(v, in.width);
                } else {
                    char name[48];
                    std::snprintf(name, sizeof(name), "unrecorded[%s]",
                                  in.name.c_str());
                    value = dag.input(name, in.width);
                    ++out.unrecorded_variables;
                }
                break;
            }
            case Model::Input::Kind::Load: {
                const expr::Id addr = substitute(dag, in.addr, binding);
                std::uint64_t at = 0;
                if (constant_value(dag, addr, &at)) {
                    value = memory.read(at, in.width);
                } else {
                    // An address no row fixed: the byte it names is not
                    // one the run read at a place the replay can point at.
                    char name[48];
                    std::snprintf(name, sizeof(name),
                                  "unrecorded[load@%u]",
                                  static_cast<unsigned>(k));
                    value = dag.input(name, in.width);
                    ++out.unrecorded_variables;
                }
                break;
            }
            case Model::Input::Kind::Unknown: {
                char name[48];
                std::snprintf(name, sizeof(name), "unrecorded[%s]",
                              in.name.c_str());
                value = dag.input(name, in.width);
                ++out.unrecorded_variables;
                break;
            }
            }
            binding[k] = value;
        }
    };

    // The writes a handler performs, in the order the model lists them:
    // the order the bytes end up in.
    const auto apply_writes = [&](const Handler& h, std::uint64_t stack,
                                  bool have_stack) {
        for (const Handler::Write& wr : h.writes) {
            const unsigned bytes = wr.width / 8;
            if (bytes == 0 || bytes > 8) {
                continue;
            }
            const expr::Id value = substitute(dag, wr.value, binding);
            if (value == expr::kNoId) {
                continue;
            }
            std::uint64_t addr = 0;
            if (wr.to_slot) {
                if (!have_stack) {
                    continue;
                }
                addr = stack + static_cast<std::uint64_t>(wr.disp);
            } else {
                const expr::Id where = substitute(dag, wr.addr, binding);
                if (!constant_value(dag, where, &addr)) {
                    memory.note_symbolic_store();
                    continue;
                }
            }
            memory.write(addr, dag.resize(value, wr.width), bytes);
        }
    };

    // The path the run took, as constraints on the unknown: one per
    // dispatch whose target depended on it. The trace walked this path
    // and only this one; remembering it as a condition is what makes
    // "could the machine have gone elsewhere" a question with an answer,
    // because the alternative has to be consistent with everything the
    // run did reach.
    std::vector<Constraint> path;
    // The successors a dispatch could have taken, as the words the
    // machine reads out of its own table. The table is program data and
    // does not move with the input, so every word in it is a value some
    // run would read -- and the ones this run read are the ones we have.
    // Enumerating the table itself would need to know where it ends;
    // enumerating what was seen does not, and every entry is one the
    // machine really uses.
    std::vector<std::uint64_t> candidates;
    for (const Row& r : rows) {
        if (r.target != 0) {
            candidates.push_back(r.target);
        }
    }
    std::sort(candidates.begin(), candidates.end());
    candidates.erase(std::unique(candidates.begin(), candidates.end()),
                     candidates.end());

    const std::size_t rows_to_play = std::min(rows.size(),
                                              handler_of_row.size());
    for (std::size_t i = 0; i < rows_to_play; ++i) {
        const std::size_t hi = handler_of_row[i];
        if (hi >= handlers.size()) {
            ++out.rows_skipped;
            continue;
        }
        const Handler& h = handlers[hi];
        const Row& prev = rows[i];
        ++out.rows_played;

        std::uint64_t stack = 0;
        const bool have_stack = row_register(prev, stack_reg, &stack);
        std::uint64_t cursor = 0;
        const bool have_cursor = row_register(prev, cursor_reg, &cursor);

        bind_inputs(prev, stack, have_stack, cursor, have_cursor);
        apply_writes(h, stack, have_stack);

        // The base the goals are read from: the value the stack register
        // carried at this row. It is the base every slot access of the run
        // was measured from, and the state the trace observed; the model's
        // own prediction of where the handler left the pointer is a claim
        // about a next step that, for the last row, never came. An engine
        // whose epilogue moves the register -- a return that pops its
        // frame -- would otherwise read the goals from past the machine's
        // own memory. When the trace did not carry the register, the
        // prediction is all there is and is used as such.
        std::uint64_t carried = 0;
        if (row_register(prev, stack_reg, &carried)) {
            final_stack = carried;
        } else if (h.rbp_new != expr::kNoId) {
            const expr::Id moved = substitute(dag, h.rbp_new, binding);
            std::uint64_t where = 0;
            if (constant_value(dag, moved, &where)) {
                final_stack = where;
            }
        }

        // Where this handler goes next.
        //
        // Until now the replay took the handler sequence from the trace
        // and never asked the model what it thought; the dispatcher's own
        // target is the one prediction about control flow the model can
        // make, and it is the one a single trace cannot otherwise check.
        // A target that comes out as a number is compared with the word
        // the run read out of the same table -- agreement is a check on
        // the model, disagreement is a defect in it -- and a target that
        // leans on the unknown is a branch, which is the one thing a path
        // followed by a run cannot enumerate.
        const auto look_ahead = [&](const Handler& who) {
            if (who.transfer != Handler::Transfer::Dispatch ||
                who.target_expr == expr::kNoId) {
                return;
            }
            const expr::Id target = substitute(dag, who.target_expr, binding);
            if (target == expr::kNoId) {
                return;
            }
            BranchPoint bp;
            bp.seq = prev.seq;
            bp.handler_va = who.va;
            bp.condition = render(model, target);
            bp.observed = prev.target;
            std::uint64_t fixed = 0;
            if (constant_value(dag, target, &fixed)) {
                ++out.targets_resolved;
                bp.computed = fixed;
                bp.observed_matches_model = fixed == prev.target;
                if (bp.observed_matches_model) {
                    return;
                }
            } else {
                ++out.targets_symbolic;
                bp.symbolic = true;
            }
            if (options.explore && bp.symbolic) {
                // Which of the machine's handlers this edge could lead to,
                // asked as a question about the unknown: the alternative
                // has to agree with every branch the run already took, or
                // it is not an alternative on this path.
                for (const std::uint64_t c : candidates) {
                    sat::Solver probe;
                    probe.set_limits(options.max_conflicts, options.max_seconds);
                    bb::Encoder enc(dag, probe);
                    for (const Constraint& p : path) {
                        const expr::Id rhs =
                            dag.constant(p.rhs, dag.width(p.lhs));
                        const sat::Lit unit[1] = {
                            enc.eq_bits(enc.bits(p.lhs), enc.bits(rhs))};
                        probe.add_clause(unit);
                    }
                    const expr::Id want = dag.constant(c, dag.width(target));
                    const sat::Lit unit[1] = {
                        enc.eq_bits(enc.bits(target), enc.bits(want))};
                    probe.add_clause(unit);
                    BranchPoint::Edge edge;
                    edge.target = c;
                    edge.reachable =
                        probe.solve() == sat::Solver::Status::Sat;
                    bp.edges.push_back(edge);
                }
            }
            out.branches.push_back(std::move(bp));
        };
        look_ahead(h);
        if (dispatcher != nullptr) {
            look_ahead(*dispatcher);
        }

        // The dispatcher is the engine's own code, and running it here is
        // what turns a handler's jump into the next handler. Its model is
        // the same kind of model the handlers have and is replayed the
        // same way; what it adds is that the sequence of handlers stops
        // being something read out of the trace and becomes something the
        // model says.
        if (dispatcher != nullptr && prev.target != 0) {
            // The dispatcher has already run when the trace recorded this
            // row -- the word it read is in the row -- so the constraint
            // its edge puts on the unknown is "this is what it computed".
            const expr::Id target =
                substitute(dag, dispatcher->target_expr, binding);
            if (target != expr::kNoId && !is_ground(dag, target)) {
                path.push_back(Constraint{target, prev.target});
            }
        }
    }

    const unsigned goal_width =
        model.convention.regfile_width != 0 ? model.convention.regfile_width
                                            : 64u;
    std::vector<Constraint> constraints;
    {
        GoalContext ctx;
        ctx.dag = &dag;
        ctx.memory = &memory;
        ctx.final_stack = final_stack;
        ctx.regfile_width = goal_width;
        ctx.last = rows_to_play != 0 ? &rows[rows_to_play - 1] : nullptr;
        ctx.unrecorded = &out.unrecorded_variables;
        // Where the bytecode buffer lives: the register the layout
        // inference named, read off the last row. It is the same value a
        // handler's own reads went through, and naming it here rather
        // than in the caller keeps `code[i]` meaning one thing.
        if (!model.convention.code.empty() && ctx.last != nullptr) {
            ctx.have_code = row_register(*ctx.last, model.convention.code,
                                         &ctx.code_base);
        }
        for (const GoalNode& g : options.goals) {
            out.goal_text.push_back(render_goal(g));
            ctx.address = 0;
            ctx.have_address = false;
            const expr::Id root = lower_goal(g, &ctx, 0, 0);
            out.goal_addresses.push_back(ctx.have_address ? ctx.address : 0);
            if (root == expr::kNoId) {
                out.unmet.push_back(ctx.error.empty()
                                        ? "the goal could not be read"
                                        : ctx.error);
                continue;
            }
            // A condition that came out as a comparison is a constraint
            // between the two things compared, and saying it that way --
            // rather than as "this one-bit value is set" -- is what lets
            // the split below see the shape of the question. `x == 0`
            // where x is an `or` of independent pieces is a small
            // question per piece; the same fact written as a comparison
            // of a comparison is one large one.
            const expr::Node n = dag.node(root);
            if (n.op == expr::Op::CmpEQ) {
                std::uint64_t c = 0;
                if (constant_value(dag, n.b, &c)) {
                    constraints.push_back(Constraint{n.a, c});
                    continue;
                }
                if (constant_value(dag, n.a, &c)) {
                    constraints.push_back(Constraint{n.b, c});
                    continue;
                }
            }
            constraints.push_back(Constraint{root, 1});
        }
    }
    if (!out.unmet.empty()) {
        out.reason = "a goal could not be read against the state the run "
                     "left behind";
        return out;
    }

    // The split is worth having at every width: a goal that says "this
    // must be zero" is the one shape whose parts can be asked separately,
    // and a machine whose result is accumulated from independent pieces
    // hands the solver one small question per piece instead of one large
    // question about all of them.
    {
        std::vector<Constraint> split;
        for (const Constraint& c : constraints) {
            if (c.rhs == 0) {
                split_zero(dag, c.lhs, &split, 0);
            } else {
                split.push_back(c);
            }
        }
        constraints = std::move(split);
    }

    // Which constraints the unknown has nothing to do with. One of those
    // is a statement about the run rather than about the input -- "the
    // state the trace left behind cannot satisfy this step" -- and saying
    // that is worth more than a bare unsatisfiable, because it names the
    // step and the fix (a run whose input reached further).
    std::vector<Constraint> open;
    std::vector<unsigned> reached_free;
    bool reached_unrecorded = false;
    for (const Constraint& c : constraints) {
        const Support s =
            support_of(dag, free_bytes, model.inputs.size(), c.lhs);
        if (s.unrecorded) {
            reached_unrecorded = true;
        }
        for (const unsigned o : s.free_ordinals) {
            if (std::find(reached_free.begin(), reached_free.end(), o) ==
                reached_free.end()) {
                reached_free.push_back(o);
            }
        }
        if (!s.free) {
            const std::vector<std::uint64_t> zeros(dag.input_names().size(),
                                                   0);
            const std::uint64_t got = dag.evaluate(c.lhs, zeros);
            if (got != c.rhs) {
                if (out.unmet.size() < options.failures_shown) {
                    const std::string shown = render(model, c.lhs);
                    char b[512];
                    std::snprintf(b, sizeof(b),
                                  "a step the run fixed evaluates to 0x%llx "
                                  "and has to be 0x%llx; no unknown byte "
                                  "reaches it. expr: %.200s",
                                  static_cast<unsigned long long>(got),
                                  static_cast<unsigned long long>(c.rhs),
                                  shown.c_str());
                    out.unmet.emplace_back(b);
                }
            }
            continue;
        }
        open.push_back(c);
    }
    out.variables = reached_free.size();
    out.unrecorded_used = reached_unrecorded ? 1u : 0u;
    if (!out.unmet.empty()) {
        out.reason = "the run's own state cannot satisfy the goal, so no "
                     "choice of the unknown bytes can";
        return out;
    }

    sat::Solver solver;
    solver.set_limits(options.max_conflicts, options.max_seconds);
    bb::Encoder encoder(dag, solver);
    for (const Constraint& c : open) {
        const expr::Id rhs = dag.constant(c.rhs, dag.width(c.lhs));
        const sat::Lit eq =
            encoder.eq_bits(encoder.bits(c.lhs), encoder.bits(rhs));
        const sat::Lit unit[1] = {eq};
        solver.add_clause(unit);
    }
    const sat::Solver::Status status = solver.solve();
    out.clauses = solver.clause_list().size();
    out.conflicts = solver.conflicts();
    out.decisions = solver.decisions();
    if (status == sat::Solver::Status::Unsat) {
        out.reason = "the goals and the trace's own state are not "
                     "satisfiable together";
        return out;
    }
    if (status != sat::Solver::Status::Sat) {
        out.reason = "the search ran out of its budget before deciding";
        return out;
    }

    std::vector<std::uint64_t> values = encoder.read_inputs();
    out.region_bytes = free_bytes.gather(values);
    out.unrecorded_variables += memory.unrecorded();
    out.symbolic_stores = memory.symbolic_stores();

    // The answer is checked against the expressions the constraints were
    // built from, by evaluating them. The circuit and the evaluation are
    // two roads to the same number, so agreement between them is evidence
    // that neither the encoding nor the extraction went wrong -- and
    // disagreement is reported as a failure to answer rather than as an
    // answer.
    std::vector<std::uint64_t> full(dag.input_names().size(), 0);
    for (std::size_t k = 0; k < full.size() && k < values.size(); ++k) {
        full[k] = values[k];
    }
    for (const Constraint& c : constraints) {
        const std::uint64_t got = dag.evaluate(c.lhs, full);
        if (dag.width(c.lhs) < 64) {
            const std::uint64_t mask =
                (std::uint64_t{1} << dag.width(c.lhs)) - 1;
            if ((got & mask) != (c.rhs & mask)) {
                out.reason = "the search's answer does not satisfy the "
                             "constraints it was given, so it is not "
                             "reported as one";
                return out;
            }
            continue;
        }
        if (got != c.rhs) {
            out.reason = "the search's answer does not satisfy the "
                         "constraints it was given, so it is not reported "
                         "as one";
            return out;
        }
    }
    out.solved = true;
    return out;
}

}  // namespace occ::devirt::lift

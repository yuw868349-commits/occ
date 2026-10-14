// Rebuilding a lifted VM handler as linear code, and certifying the rebuild.
//
// The lift layer (lift.h/lift.cpp) turns one handler into a *model*: an SSA
// expression DAG over the virtual machine's inputs, plus the handler's
// claimed effects -- every write it performs, the new virtual stack pointer
// and bytecode cursor, and the control transfer. A model is a description,
// not a program: it says what the handler did, in expressions, and nothing
// about how to do it again.
//
// This layer is the "rebuild engine"'s output stage. `rebuild` selects
// instructions -- straight-line x86-64-shaped IR -- that recompute the
// model's effects from the entry state: load the stack slots and bytecode
// words the effects lean on, fold constants into immediate operands, share
// every DAG node exactly once through the hash-consed DAG ids (a node that
// two writes both need is materialized once), and drop every node no effect
// reaches. It is deliberately not an optimizer: instruction selection over
// expression DAGs is NP-hard, and a VM handler's effects are a handful of
// expressions, so a direct bottom-up materialization is both correct and
// readable. The IR is not required to look like the original handler; it is
// required to compute the same effects, which is a claim the next layer
// proves.
//
// `verify` is the certificate for that claim. It symbolically simulates the
// IR with a small interpreter: registers hold DAG expressions, the initial
// register file is the model's entry state, memory reads resolve to the
// model's slot/code/image/load inputs (or to an earlier IR store, when the
// IR writes and then reads back), and each instruction rebuilds the DAG node
// its semantics call for. The simulated effects -- the value each store
// leaves in its cell, rbp/rsi afterwards, the jump target -- are then
// compared against the model's claimed effects one miter at a time, ring
// layer first (it answers pure arithmetic without search) and the SAT
// bit-blaster second. A negative answer carries a counterexample; a budget
// that runs out carries "unproven", which the caller must not read as
// "different". `ok` is true only when every miter was proved equal.
//
// Boundaries, stated so nothing is guessed at:
//  - The IR's arithmetic semantics are the DAG's: shifts at or past the
//    operand width yield zero (logical) or sign-fill (arithmetic), and the
//    simulator builds the very DAG nodes those semantics define. Generated
//    code only shifts by literal amounts, where x86 hardware agrees; a
//    symbolic shift amount past the width would be flagged by the miter,
//    not silently accepted.
//  - Registers are 64-bit in the IR; sub-64-bit DAG nodes are materialized
//    by masking after a 64-bit operation, so a register always holds the
//    zero-extended value. Memory operands carry their access width and reads
//    zero-extend.
//  - A `select` (a branch the lift walk could not decide, merged under its
//    condition) is expanded branchlessly -- (a & -c) | (b & ~-c) -- and a
//    comparison is expanded into arithmetic; the expansions are exact for
//    the 1-bit conditions the DAG produces and the miter proves them.
//  - `Cmp`/`Jcc` in hand-built IR have no flag model here (the flag state is
//    not one of the effects the certificate claims), so the simulator treats
//    them as effect-free and the certificate only claims the effects it can
//    compare; rebuild never emits them.
//  - A write or effect whose expression the model could not compute (kNoId)
//    is reported as unproven by verify, never waved through: the rebuild
//    cannot reproduce what the model cannot name.
//  - The temp register pool excludes every register that is an entry input
//    of the model and rbp/rsi/rsp (the VM's own pointers), so a temp never
//    clobbers a live entry value; on exhaustion the oldest temp is evicted
//    and its cached node recomputed on demand (a linear-scan allocator, more
//    instructions, same semantics).

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "occ/devirt/bitblast.h"
#include "occ/devirt/expr.h"
#include "occ/devirt/lift.h"

namespace occ::devirt::codegen {

// One operand of the linear IR. `kind` decides which fields are live:
//   Reg  -> `reg` (a 64-bit register)
//   Imm  -> `imm` (a zero-extended constant)
//   Slot -> memory at [rbp + disp] (the entry-relative virtual stack)
//   Mem  -> memory at [reg + disp], or at the absolute address `disp`
//           when `reg` is empty (an image byte)
// `width` is the access width in bits (memory operands).
struct Operand {
    enum class Kind : std::uint8_t { None, Reg, Imm, Slot, Mem };
    Kind kind = Kind::None;
    std::string reg;        // Reg/Mem base
    std::uint64_t imm = 0;  // Imm
    std::int64_t disp = 0;  // Slot/Mem displacement
    unsigned width = 64;
};

// One instruction of the linear IR. Operand use per op:
//   Mov  dst <- a        (register dst zero-extends a memory/imm source)
//   Add/Sub/Mul/And/Or/Xor/Shl/Shr/Sar  dst <- dst <op> a
//   Not/Neg  dst <- <op> dst
//   Lea  dst <- &a       (a is a memory operand; the address, not the load)
//   Cmp  flags <- a vs a  (flags not modeled; effect-free for the certificate)
//   Jmp  transfer <- a    (the jump target)
//   Jcc  a is the 1-bit condition, dst the target; not emitted by rebuild
//   Ret/Call  transfer, Call's target in a
struct Insn {
    enum class Op : std::uint8_t {
        Mov, Add, Sub, Mul, And, Or, Xor, Shl, Shr, Sar, Not, Neg, Lea,
        Cmp, Jmp, Jcc, Ret, Call,
    };
    Op op = Op::Mov;
    Operand dst, a, b;  // 按 op 使用；Jcc 的 a 是 1-bit 条件表达式
};

// A rebuilt handler: the linear IR plus the model effects it must reproduce
// (copied from the lift Handler, verbatim -- they are the claim the IR is
// checked against, so verify reads them from here, not from the handler).
struct Function {
    std::uint64_t va = 0;
    bool modeled = false;
    std::vector<Insn> insns;
    expr::Id rbp_new = expr::kNoId;
    expr::Id rsi_new = expr::kNoId;
    std::vector<lift::Handler::Write> writes;
    lift::Handler::Transfer transfer = lift::Handler::Transfer::Unknown;
    expr::Id target_expr = expr::kNoId;
};

struct Options {
    bool emit_comments = true;
};

// Instruction selection: bottom-up materialization of every effect
// expression of `h` (write values and addresses, rbp/rsi, the dispatch
// target) over `model`'s DAG, with constant folding into immediate operands,
// common-subexpression elimination through the DAG ids (a node is
// materialized into a register once), and dead-code elimination (only nodes
// reachable from an effect are emitted). The resulting IR recomputes the
// model's effects from the entry state; see the file comment for the
// boundaries of what is expressible.
[[nodiscard]] Function rebuild(const lift::Model& model, const lift::Handler& h,
                               const Options& options = {});

// Renders the function as readable x86-64 assembly text: a comment header
// naming the handler VA and its claimed effects, then one instruction per
// line.
[[nodiscard]] std::string emit_asm(const Function& f, const Options& options = {});

// The result of certifying a rebuild: one item per equivalence question
// ("write 0 value: ... == ... [Ring]"), failures that distinguish "proved
// different" from "could not be proved", and the solver conflict counts.
struct Check {
    bool ok = false;
    std::vector<std::string> items;
    std::vector<std::string> failures;
    std::uint64_t miters = 0;
    std::uint64_t conflicts = 0;
};

// Symbolically simulates `f`'s IR over the model's entry state and proves,
// one miter at a time (ring first, then bit-blasted SAT, under `budget`),
// that every IR effect equals the claimed effect:
//   - every write: the value the IR leaves in the cell (byte-composed for
//     partial stores) equals the model's write value, and the address is the
//     same entry-relative slot or computed address;
//   - rbp/rsi after the IR equal rbp_new/rsi_new;
//   - for a Dispatch, the IR's jump target equals target_expr.
// A claimed write the IR never performs, an IR store no claim accounts for,
// a missing or diverging transfer, and any expression the model could not
// compute are all failures. ok is true only when no failure was recorded.
[[nodiscard]] Check verify(const lift::Model& model, const lift::Handler& h,
                           const Function& f, const bb::Budget& budget = {});

}  // namespace occ::devirt::codegen

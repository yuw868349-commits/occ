// The semantic recognition layer: from handler models back to virtual
// instructions.
//
// The lift layer turns one handler of the interpreter into a symbolic
// model -- how it moves the virtual stack pointer, the bytecode cursor,
// what it writes into the stack slots, and where it dispatches. That is
// the *effect* of the handler, but it is not yet the *instruction* the
// handler implements. A handler that does "slot 0 += slot 1; rbp += 8"
// is a virtual `add`; a handler that moves a byte of the bytecode into
// the top slot and advances the cursor is a virtual push of an
// immediate; a handler that reads a bytecode word, decrypts it and
// jumps there is the virtual machine's dispatch. This layer names those
// effects.
//
// `recover` walks the handlers in order and matches each model against
// semantic patterns -- a stack-slot write whose value is an addition of
// two slot reads is an Add; a stack write whose value comes from the
// bytecode is a Push; a dispatch target that is an expression over the
// bytecode is a decrypted Jmp. The matching is deliberately structural
// over the model's own kinds (Slot / Code / Image / Reg / Load /
// Unknown), never over machine-code bytes: the same handler written
// differently lifts to the same VInsn.
//
// The layer is honest by construction. A model that could not be
// completed (lift's `modeled == false`) is reported as Unknown with the
// lift's reason. A model whose effect does not match any pattern is
// reported as Unknown with a note saying why, and is counted in
// `unrecognized` -- never guessed. A model that is inexact -- a handler
// with junk the lift could not model, so part of its state became
// unknowns -- is counted in `unmodeled` and its approximation is
// spelled out in the note. Where the layer cannot know something (the
// plaintext of a decrypted dispatch target, because no image bytes are
// available here), it says so rather than fabricating a constant.
//
// `fold_encrypted` is the companion that *can* produce those constants
// when the caller has the bytes: it evaluates a DAG expression whose
// leaves are Code or Image inputs against a `lift::CodeReader` and
// interns the result as a Const node. The reader binding convention is
// stated in its own comment below.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "occ/devirt/expr.h"
#include "occ/devirt/lift.h"

namespace occ::devirt::semlib {

// One operand of a recognized virtual instruction. `disp` is relative
// to the entry pointer (Slot) or the entry cursor (Code), matching the
// lift model's own displacement convention; `id` is the DAG node the
// operand came from, so a certificate can refer back to the model.
struct Operand {
    enum class Kind : std::uint8_t {
        None,
        Slot,   // a virtual stack slot; `disp` from the entry rbp
        Code,   // a bytecode word; `disp` from the entry rsi
        Imm,    // a constant (a folded decryption result, an immediate)
        Reg,    // a host register value
        Mem,    // a value read through a computed address (`id` is the
                // address expression when known)
    };
    Kind kind = Kind::None;
    std::int64_t disp = 0;   // Slot/Code displacement
    std::uint64_t imm = 0;   // Imm value
    std::string reg;         // Reg name
    unsigned width = 64;
    expr::Id id = expr::kNoId;
};

// One recognized virtual instruction.
struct VInsn {
    enum class Op : std::uint8_t {
        Push, Pop, Mov, Lea, Add, Sub, Adc, Sbb, And, Or, Xor,
        Not, Neg, Shl, Shr, Sar, Inc, Dec, Cmp, Test,
        Jcc, Jmp, Call, Ret, Unknown,
    };
    Op op = Op::Unknown;
    std::vector<Operand> operands;
    std::uint64_t src_va = 0;  // the handler this came from
    // True when some operand is a constant obtained by decrypting a
    // Code/Image value (or, without bytes, when the effect is a
    // decryption of one -- the plaintext then being what fold_encrypted
    // would produce).
    bool decrypted = false;
    // Why this instruction is Unknown, or what approximation was taken.
    std::string note;
};

// The recovered stream: one VInsn per recognized effect, in handler
// order, plus the honesty counters.
struct Stream {
    std::vector<VInsn> insns;
    std::vector<std::string> notes;
    // Handlers whose model is inexact (the lift walked with
    // unmodellable instructions, or could not complete the walk).
    std::uint64_t unmodeled = 0;
    // Handlers whose main effect could not be mapped to a virtual
    // opcode (reported as Unknown, never guessed).
    std::uint64_t unrecognized = 0;

    [[nodiscard]] std::string render() const;
};

// Recovers the virtual instruction stream from a set of handler models.
// `handlers` must all belong to `model` (same DAG and input table).
// The recognition is semantic; anything not matched becomes an Unknown
// instruction with a note, and is counted in `unrecognized`. Because no
// image reader is available here, a decrypted dispatch target is
// reported as the decryption expression with `decrypted == true`, not
// as a constant -- the constant is produced by `fold_encrypted` where
// the bytecode bytes are known.
[[nodiscard]] Stream recover(const lift::Model& model,
                             const std::vector<lift::Handler>& handlers);

// The lift layer's image reader type, reused to bind byte values.
using CodeReader = lift::CodeReader;

// Folds a decryption expression to a plaintext constant. `id` is an
// expression over the DAG whose leaves include Code or Image inputs
// (a handler that reads a bytecode word, rotates it, xors a mask, ...);
// this evaluates it against the bytes a reader provides and interns the
// result as a Const node in the DAG, which is returned. If any input
// cannot be bound -- the reader is null, the input is a register or a
// stack slot or an unknown -- nothing is claimed and kNoId is returned.
//
// Reader binding: for an Image input (named `img[0x...]`, carrying its
// absolute image address) the reader is called with that address. For a
// Code input (named `code[+d]` / `code[-d]`) the reader is called with
// the *displacement* `d` as the address: the displacement is the only
// address information the DAG carries, and the caller's context is
// expected to know the current cursor, so a reader bound to a cursor
// that adds its own base to the passed value reads exactly the byte the
// handler would have read. With a null reader neither kind binds.
[[nodiscard]] expr::Id fold_encrypted(const expr::DAG& dag, expr::Id id,
                                      CodeReader reader, void* ctx);

}  // namespace occ::devirt::semlib

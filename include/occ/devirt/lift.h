// Lifting a VM handler into a model of the virtual machine it drives.
//
// A code-virtualizing packer ships an interpreter whose handlers are
// ordinary native code. Each handler is a small micro-program: it moves
// values between the virtual stack, the bytecode cursor and the host
// registers, and the packer wraps it in junk instructions that are
// semantically inert. The dispatcher hands control to a handler per
// virtual instruction and takes it back when the handler jumps out.
//
// What the de-virtualizer needs from a handler is not its instruction
// text but its *effect*: how it moves the virtual stack pointer, how it
// advances the bytecode cursor, what it leaves in the stack slots, and
// where it goes next. That effect is recovered here by abstract
// interpretation of the decoded micro-program over a symbolic virtual
// state.
//
// The state is symbolic because the values are not known at analysis
// time, and it is expressed over `expr::DAG` because that is the IR the
// equivalence layers consume:
//
//   st[+d]    the virtual stack slot at stack+d
//   code[+d]  the bytecode byte(s) at cursor+d -- the instruction operand
//             a handler fetches and (in this engine) decrypts
//   reg:name  a host register the engine's own prologue left behind
//
// which two registers play "stack" and "cursor" is the engine's choice,
// recorded in `Convention`. The default -- rbp for the virtual stack,
// rsi for the bytecode cursor, r12 for the handler table, rdi for the
// engine's own stack base -- is the convention this engine's trace
// records. Setting `Model::convention` to another assignment makes the
// same abstract interpreter classify `[stack+d]` accesses as slots and
// `[cursor+d]` accesses as bytecode, and makes the conformance check bind
// the two roles to the Row fields those register names sample.
//
// A handler that does `mov rax, [rbp+0x8]; add [rbp+0x0], rax; add rbp,
// 8; jmp rcx` summarizes to "slot 0 += slot 1; rbp += 8", which is what
// a virtual `add` instruction is. The host-register noise, the junk and
// the encryption rotation are all folded away by construction.
//
// The model is then *checked against the trace*, which is the part that
// makes it trustworthy rather than plausible. The trace records rbp, rsi
// and the three cells the tracer read around the stack pointer at every
// dispatch, so for every dispatch the previous row's values are a
// concrete input to the handler's model and this row's values are the
// expected output. The virtual stack pointer is not kept eight-aligned --
// a handler pushes a word as readily as a qword -- so the tracer reads
// the *aligned* cells containing it and the checker composes the
// comparison out of bytes, over a shadow of the stack the trace's own
// observations keep grounded. When the convention moves the stack role to
// another register, the trace's st0/st1/st2 cells are the aligned cells
// around *that* register's value, and the checker reads them from the Row
// field that register names. A prediction whose inputs are all known is
// evaluated in the DAG and compared; a mismatch is a model error and is
// reported as one, per dispatch, with both numbers. Predictions that
// depend on a value the trace does not carry -- an unknown of the model's
// own, a load from an address the trace never observed, a register the
// convention names but the trace does not sample -- are counted as
// unverifiable rather than silently counted as correct; the conformance
// report says which is which.
//
// Nothing here trusts the decoder to be complete: an instruction whose
// form the decoder does not render is reported as such, and what it can
// no longer be shown not to touch -- registers, flags, the host stack,
// the memory the model was tracking -- becomes an unknown of its own, so
// the walk goes on without any prediction resting on a stale value. A
// branch whose condition cannot be reduced is not guessed at either:
// both edges are walked and the arms merged under the condition, which
// is what a `select` in these expressions is. The model is therefore
// exact in the sense that it never claims more than it knows; what it
// could not determine is an input the checker cannot bind -- counted
// unverifiable -- or a note. It is only *not exact* -- `modeled` false --
// when the walk itself could not be completed: a loop it cannot follow,
// an arm that could not be walked, a budget spent, arms that end too
// differently to be merged.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "occ/devirt/expr.h"
#include "occ/inspect/disasm.h"

namespace occ::devirt::lift {

// The register assignment the virtual machine was built on. The handler
// model hangs off the registers these roles name:
//
//   stack   the virtual stack pointer -- `[stack+d]` accesses are slots
//   cursor  the bytecode cursor       -- `[cursor+d]` accesses are code
//   table   the handler-table base    -- what the dispatcher's tail indexes
//   engine  the engine's stack base
//
// The trace samples five physical registers by name (rsi/rbp/rdi/rsp/r12);
// a convention whose stack or cursor names one of them is bindable from a
// Row, and a convention that names anything else simply cannot be bound --
// the conformance check counts the predictions that lean on it as
// unverifiable rather than assuming a value. The default is the
// convention this engine's own trace records. st0/st1/st2 in a Row are
// the aligned cells *around the stack pointer*, so under a permuted
// convention a trace must be constructed with its cells around the
// permuted stack register.
struct Convention {
    std::string stack = "rbp";    // virtual stack pointer
    std::string cursor = "rsi";   // bytecode cursor
    std::string table = "r12";    // handler table base
    std::string engine = "rdi";   // engine stack base
    bool operator==(const Convention&) const = default;
};
inline const Convention kDefaultConvention{};

// One decoded instruction with its operands in structured form. The
// mnemonic and the operand kinds come from the inspector's decoder; the
// operand shapes are parsed from its Intel-syntax rendering, which is
// this repository's own (registers carry their width in their name,
// memory operands print as `[rbp+0x10]`, `[rsi]`, `[rip+0x20]`).
struct Operand {
    enum class Kind : std::uint8_t { None, Reg, Mem, Imm };
    Kind kind = Kind::None;
    // Reg: the register name. Mem: the base and index registers, scale
    // and displacement. Width is in bits (64/32/16/8), 0 when the form
    // does not pin it down.
    std::string reg;
    std::string base;
    std::string index;
    int scale = 1;
    std::int64_t disp = 0;
    std::uint64_t imm = 0;
    unsigned width = 64;
    // An immediate that the encoding sign-extends to the operand width
    // (`add rax, 0xffffffff`, `sub rsp, 0x18`); without this the value
    // would be a large positive number instead of a small negative one.
    bool imm_signed = false;

    [[nodiscard]] bool is_mem_of(const char* base_reg) const {
        return kind == Kind::Mem && base == base_reg && index.empty();
    }
};

struct Insn {
    std::uint64_t va = 0;
    unsigned length = 0;
    std::string mnemonic;
    inspect::InsnKind kind = inspect::InsnKind::Other;
    std::uint64_t target = 0;
    std::vector<Operand> operands;
    // False when the instruction's effect could not be modelled; the
    // interpreter then treats its destinations as unknown and records
    // why.
    bool modeled = false;
    std::string reason;
};

// Decodes one instruction of a handler. `bytes` is the image mapped at
// `va`; `available` is how many bytes are readable from there.
[[nodiscard]] bool decode_insn(const std::uint8_t* bytes,
                               std::size_t available, std::uint64_t va,
                               Insn& out) noexcept;

// ---------------------------------------------------------------- state

// A value in the symbolic state: an unknown, a constant, or an expression
// over the model's inputs.
struct Value {
    enum class Kind : std::uint8_t { Unknown, Const, Sym };
    Kind kind = Kind::Unknown;
    std::uint64_t imm = 0;
    expr::Id id = expr::kNoId;
};

// The DAG the models are built over, together with a *typed* record of
// every input in it. The record is what lets the trace check bind real
// numbers to the inputs: an input knows whether it stands for a stack
// slot, a byte of the bytecode, a byte of the image, or a host register,
// and each kind is bound from a different place in the trace.
//
// Inputs are deduplicated: reading `[rbp+0x8]` in two handlers is one
// input, not two, which is what makes the models comparable across
// handlers.
struct Model {
    struct Input {
        enum class Kind : std::uint8_t {
            Slot, Code, Image, Reg, Load, Unknown,
        };
        Kind kind = Kind::Reg;
        std::string name;
        std::int64_t disp = 0;   // Slot and Code: displacement from the entry pointer
        std::uint64_t va = 0;    // Image: the address of the byte
        unsigned width = 64;     // bits
        // Load: the address the byte was read from, as an expression over
        // the inputs already in the DAG. The model cannot know what lives
        // at a computed address -- but it can say which address it read,
        // and the checker can look that byte up in the trace's own memory.
        expr::Id addr = expr::kNoId;
        // The node id of this input in the DAG. Not the ordinal: other
        // nodes take ids too, so a caller that fed the index here would
        // name some other node.
        expr::Id id = expr::kNoId;
    };

    expr::DAG dag;
    std::vector<Input> inputs;  // in ordinal order: inputs[i] is ordinal i

    // The register assignment this model was lifted under. `summarize`
    // classifies `[stack+d]` as slot accesses and `[cursor+d]` as
    // bytecode, and names the entry stack/cursor inputs after the
    // convention's registers; `check_trace` binds those roles to the Row
    // fields the registers sample. Defaults to the engine's own
    // convention, so a default-constructed model behaves exactly as it
    // always has.
    Convention convention = kDefaultConvention;

    [[nodiscard]] expr::Id input_slot(std::int64_t disp);
    [[nodiscard]] expr::Id input_code(std::int64_t disp, unsigned width);
    [[nodiscard]] expr::Id input_image(std::uint64_t va, unsigned width);
    [[nodiscard]] expr::Id input_reg(const std::string& reg);
    // A value read through a computed address -- `mov rax, [rcx]` with
    // rcx off the stack. Deduplicated by the address expression and the
    // width: the same address read again is the same value.
    [[nodiscard]] expr::Id input_load(expr::Id addr, unsigned width);
    // A value the model cannot know -- a register an unmodelled
    // instruction clobbered, the flags a handler was entered with, a
    // byte behind an address it cannot name. Keeping it as a fresh
    // unbound input rather than as a hole means the values built out of
    // it are still expressions: a partial write over an unknown register
    // keeps the half it did not touch, and the trace check counts the
    // predictions that lean on it as unverifiable.
    [[nodiscard]] expr::Id input_unknown(const std::string& hint);
};

// A model of one handler's effect on the virtual machine.
struct Handler {
    std::uint64_t va = 0;
    // False only when the walk could not be completed: a loop it cannot
    // follow, an instruction it cannot decode, a budget spent, a branch
    // whose arms could not both be walked or could not be merged. False
    // means the model is not claimed exact. True does not mean
    // omniscient: an instruction the decoder does not render, an address
    // the model cannot name, a branch it cannot decide are all handled
    // conservatively -- the values become unknowns of their own and the
    // trace check counts the predictions that lean on them as
    // unverifiable -- and each is listed in `notes`.
    bool modeled = false;
    std::string reason;

    // The virtual stack pointer and bytecode cursor as expressions over
    // the state inputs (typically "st + 8" for a pop), or kNoId when the
    // handler leaves them unknown -- a jump handler that takes the cursor
    // from a stack slot produces an expression here, not a delta.
    expr::Id rbp_new = expr::kNoId;
    expr::Id rsi_new = expr::kNoId;

    // Every write the handler performs on memory, in the order it
    // performs them. A write goes either to a virtual stack slot, at a
    // displacement from the entry pointer, or through an address the
    // handler computed -- `mov [rax], rdx` with rax off the stack, which
    // is exactly what a virtual store is. The computed address is kept
    // as an expression, so the effect is expressible instead of opaque.
    // A value of kNoId means the model could not compute what was
    // written, which is different from no write at all: the conformance
    // checker needs to tell the two apart.
    struct Write {
        bool to_slot = true;
        std::int64_t disp = 0;        // to_slot: from the entry stack pointer
        expr::Id addr = expr::kNoId;  // !to_slot: the computed address
        expr::Id value = expr::kNoId;
        unsigned width = 64;
    };
    std::vector<Write> writes;

    // The control transfer the handler ends with.
    enum class Transfer : std::uint8_t {
        // Falls into the next handler with the cursor advanced; nothing
        // observed.
        Unknown,
        // The dispatcher takes over: the handler jumped to a computed
        // address (the next virtual instruction).
        Dispatch,
        // A return to the VM's caller.
        Return,
        // A call out of the VM (the engine's call-out stub).
        Call,
    };
    Transfer transfer = Transfer::Unknown;
    // For Dispatch: the expression the jump target was computed from
    // (the decrypted bytecode word, in this engine), when it is known.
    expr::Id target_expr = expr::kNoId;

    // What the walk met and handled -- an instruction the decoder does
    // not render, an address it could not name, a branch it could not
    // decide -- each with the address it came from.
    std::vector<std::string> notes;
};

// Summarizes the handler at `va` from the bytes mapped at it. The walk
// follows the handler's control flow -- internal jumps, and both edges of
// a branch whose condition cannot be reduced -- and stops when control
// leaves it (the dispatcher jump, a return, a call).
//
// `bytes` is the image mapped at `window_va`, and the walk may follow
// the handler's internal jumps anywhere inside that window: a VMProtect
// handler is a chain of small blocks scattered through the code
// section, chained by direct jumps, so a bytes-to-`va` view would stop
// the walk at the first jump that goes backwards. Pass a window the
// whole section and the chain is walked to its exit. `va` stays the
// handler's entry point.
//
// `max_instructions` covers the handler and every arm a branch forks
// into: a diamond costs what it costs.
//
// The model's `convention` member selects which registers play the
// stack and cursor roles; the default convention reproduces the
// engine's own behavior.
[[nodiscard]] Handler summarize(Model& model, const std::uint8_t* bytes,
                                std::size_t available, std::uint64_t window_va,
                                std::uint64_t va,
                                std::size_t max_instructions = 96);

// ------------------------------------------------------------ conformance

// One dispatch's worth of ground truth, as the tracer recorded it. The
// five sampled registers are named after the default convention's roles;
// under a permuted `Convention` the stack and cursor roles read the Row
// fields those registers name instead. st0/st1/st2 are the three cells
// the tracer read around the *stack pointer* -- under the default
// convention the aligned cells containing rbp; under a permuted one, the
// aligned cells containing whatever register the convention names as
// stack -- so a permuted trace must place its cells around the permuted
// stack register.
struct Row {
    std::uint64_t seq = 0;
    std::uint64_t rsi = 0;   // bytecode cursor (default convention)
    std::uint64_t rbp = 0;   // virtual stack pointer (default convention)
    std::uint64_t rdi = 0;   // the engine's stack base pointer
    std::uint64_t rsp = 0;
    // The engine's handler-table base. It is what the dispatcher's own
    // tail indexes, so a model that reached the tail can compute the next
    // handler from it.
    std::uint64_t r12 = 0;
    // The three cells the tracer read around the stack pointer. The
    // virtual stack pointer is not kept eight-aligned (a handler pushes
    // a word or a dword as readily as a qword), so the tracer reads the
    // cells at `stack & ~7` -- the aligned cells *containing* the pointer,
    // not the pointer itself. The checker composes its comparison out of
    // bytes for exactly that reason.
    std::uint64_t st0 = 0;
    std::uint64_t st1 = 0;
    std::uint64_t st2 = 0;
    // What the dispatcher read out of its handler table for this step.
    // Whether that value is the handler's own address or a rotated form of
    // it is a property of the VM family, not of the trace -- see
    // resolve_handler.
    std::uint64_t target = 0;
};

// A dispatch row's `target` is the word the dispatcher read out of its
// handler table, and two VM families produce that word two ways. A
// hand-rolled VM stores the handler's address directly; VMP 3 stores it
// rotated left by ten and rotates it back before jumping. The trace
// records the word before that decision, so which family wrote it cannot
// be read off the trace alone.
//
// `target_is_code` is the caller's answer to "does this value point at
// file-backed bytes in the image under analysis". The address the
// dispatcher jumped to is the one with code behind it, so a target that
// already points at code is taken as the address, and only a target with
// nothing behind it is rotated. A value the image cannot place at all
// keeps the rotated form, which is what the de-virtualizer produced
// before it could tell the two families apart -- so a word the image
// cannot resolve still reports exactly as it did before.
[[nodiscard]] std::uint64_t resolve_handler(std::uint64_t target,
                                            bool target_is_code);

struct Conformance {
    std::uint64_t checked = 0;    // predictions evaluated and equal
    std::uint64_t mismatched = 0;
    std::uint64_t unverifiable = 0;  // predictions with unknown inputs
    // Dispatches to a handler whose model is incomplete. Its predictions
    // are still checked -- an incomplete model is a disclosed one, not a
    // discarded one -- so this counts alongside the other three, it does
    // not replace them.
    std::uint64_t unmodeled = 0;
    // The first few mismatches, spelled out.
    std::vector<std::string> failures;
    // Where the mismatches came from: the handlers the models are wrong
    // for, worst first, so the report says which models need attention
    // rather than only that some do.
    struct PerHandler {
        std::uint64_t va = 0;
        std::uint64_t count = 0;
    };
    std::vector<PerHandler> worst_handlers;
    [[nodiscard]] double rate() const noexcept {
        const std::uint64_t total = checked + mismatched;
        return total == 0 ? 0.0
                          : static_cast<double>(checked) /
                                static_cast<double>(total);
    }
};

// Checks a model against a trace. A row records the virtual state at one
// dispatch, so the handler that row names runs from that row's state and
// produces the next row's state -- the check is between adjacent rows,
// with the earlier row's values bound to the model's inputs. The model's
// `convention` member selects which Row field supplies the stack and
// cursor roles; under the default convention the behavior is exactly the
// engine's original one.
//
// The virtual stack is compared byte by byte rather than slot by slot.
// The trace's cells are the aligned ones containing the stack pointer and
// the model's regions are the addresses the handler actually touched, so
// the two overlap at arbitrary offsets; composing the comparison out of
// bytes is what makes an unaligned push checkable instead of a false
// mismatch. The comparison runs over a shadow of the stack bytes: the
// trace's cells seed it, each handler's model applies what it says it
// wrote, and every observed cell is compared against it and then adopted,
// so a wrong model is caught against ground truth that stays grounded.
//
// A prediction is evaluated lazily through the `select`s a merged branch
// produced: the condition first, then only the arm the condition chooses,
// when the trace binds the condition. The arm that did not run is not
// needed, and whatever the model left unknown in it cannot make the
// prediction unverifiable.
//
// `handler_of_row[i]` is the index into `handlers` of the handler row i
// dispatched to. `rows` must have at least two entries.
//
// `code_bytes` supplies bytes of the image at a virtual address, which is
// what binds the bytecode and rip-relative inputs; leave it null and
// those predictions are counted unverifiable rather than checked.
using CodeReader = bool (*)(void* ctx, std::uint64_t va, unsigned width,
                            std::uint64_t* out);

[[nodiscard]] Conformance check_trace(
    Model& model, const std::vector<Handler>& handlers,
    const std::vector<Row>& rows,
    const std::vector<std::size_t>& handler_of_row, CodeReader code_bytes,
    void* code_ctx);

// The recovered expression for a slot write, rendered for a report.
[[nodiscard]] std::string render(const Model& model, expr::Id id);

}  // namespace occ::devirt::lift

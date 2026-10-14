// The semantic recognition layer: handler models to virtual
// instructions. See semlib.h for the design; this file is the pattern
// matcher and the decryption folder.
//
// Recognition is write-driven first: a handler's *distinctive* effect is
// what it writes to the virtual stack (or what it dispatches to), and
// the recognized instruction is named from the shape of the written
// value -- an addition of two slot reads is an Add, a value that comes
// out of the bytecode is a Push, a widened slot read is a Mov. A handler
// that writes nothing and dispatches to a decrypted bytecode word is a
// Jmp. Everything the matcher cannot name becomes an Unknown with a
// reason, counted in `unrecognized`; it never fabricates an opcode.
//
// The dispatch tail (`jmp rcx` back to the dispatcher) is not an
// instruction of its own -- every handler ends with it -- so a dispatch
// target that is a bare host register is ignored by the matcher. Only a
// target the model computes out of bytecode (or a constant target) names
// a Jmp.

#include "occ/devirt/semlib.h"

#include <cstdio>
#include <cstring>

namespace occ::devirt::semlib {

namespace {

// ------------------------------------------------------------ helpers

// The signed constant delta of `id` relative to the base register input
// `base`, when `id` is exactly `base`, `base + k` or `base - k` with `k`
// constant. Anything else -- a computed expression, an unknown, kNoId --
// is not a constant delta and returns false.
bool const_delta(const expr::DAG& dag, expr::Id base, expr::Id id,
                 std::int64_t* delta) {
    if (id == expr::kNoId || base == expr::kNoId) {
        return false;
    }
    if (id == base) {
        *delta = 0;
        return true;
    }
    const expr::Node& n = dag.node(id);
    if (n.op == expr::Op::Add && (n.a == base || n.b == base)) {
        const expr::Id other = n.a == base ? n.b : n.a;
        if (dag.is_const(other)) {
            *delta = static_cast<std::int64_t>(dag.const_value(other));
            return true;
        }
        return false;
    }
    if (n.op == expr::Op::Sub && n.a == base && dag.is_const(n.b)) {
        *delta = -static_cast<std::int64_t>(dag.const_value(n.b));
        return true;
    }
    return false;
}

// A *clobbered* delta: `unknown + k`, where the base was overwritten by
// an unmodellable instruction so the lift left an Unknown where the
// register used to be. The increment is still visible, so the note can
// say "approximately +k over an unknown".
bool approx_delta(const expr::DAG& dag, expr::Id id,
                  std::int64_t* delta) {
    if (id == expr::kNoId) {
        return false;
    }
    const expr::Node& n = dag.node(id);
    if (n.op == expr::Op::Add && dag.is_const(n.b) &&
        dag.node(n.a).op == expr::Op::Input) {
        *delta = static_cast<std::int64_t>(dag.const_value(n.b));
        return true;
    }
    if (n.op == expr::Op::Add && dag.is_const(n.a) &&
        dag.node(n.b).op == expr::Op::Input) {
        *delta = static_cast<std::int64_t>(dag.const_value(n.a));
        return true;
    }
    return false;
}

// Appends "label +k" / "label ~+k (over unknown)" / "label unknown" to
// the note, with a "; " separator when something is already there. A
// known zero delta is the handler doing nothing to the pointer and is
// not worth a note.
void append_delta(std::string& note, const char* label, bool known,
                  bool approx, std::int64_t delta) {
    char b[96];
    if (!known) {
        std::snprintf(b, sizeof(b), "; %s unknown", label);
    } else if (approx) {
        std::snprintf(b, sizeof(b), "; %s ~%+lld (over unknown)", label,
                      static_cast<long long>(delta));
    } else if (delta != 0) {
        std::snprintf(b, sizeof(b), "; %s %+lld", label,
                      static_cast<long long>(delta));
    } else {
        return;
    }
    note += b;
}

// Appends "; text" when something is already there, else "text".
void append_piece(std::string& note, const std::string& piece) {
    if (!note.empty()) {
        note += "; ";
    }
    note += piece;
}

// The model input at a DAG input ordinal; null when out of range.
const lift::Model::Input* input_at(const lift::Model& model,
                                   unsigned ord) {
    if (ord < model.inputs.size()) {
        return &model.inputs[ord];
    }
    return nullptr;
}

// Classifies a DAG *input leaf* (by ordinal) as an Operand.
Operand classify_leaf(const lift::Model& model, unsigned ord) {
    Operand out;
    const lift::Model::Input* in = input_at(model, ord);
    if (in == nullptr) {
        return out;
    }
    out.id = in->id;
    out.width = in->width;
    switch (in->kind) {
    case lift::Model::Input::Kind::Slot:
        out.kind = Operand::Kind::Slot;
        out.disp = in->disp;
        break;
    case lift::Model::Input::Kind::Code:
        out.kind = Operand::Kind::Code;
        out.disp = in->disp;
        break;
    case lift::Model::Input::Kind::Image:
        // An image byte is a constant of the image, but its value is not
        // in the model; it cannot be named numerically here.
        out.kind = Operand::Kind::Imm;
        out.imm = 0;
        break;
    case lift::Model::Input::Kind::Reg:
        out.kind = Operand::Kind::Reg;
        out.reg = in->name;
        break;
    case lift::Model::Input::Kind::Load:
        out.kind = Operand::Kind::Mem;
        out.id = in->addr;
        break;
    case lift::Model::Input::Kind::Unknown:
        out.kind = Operand::Kind::None;
        break;
    }
    return out;
}

// Classifies a DAG node as an Operand. A constant is an Imm; an input is
// classified by its own kind; an expression is classified by its first
// input leaf (an expression over the bytecode reads as its Code leaf,
// and so on). The `note` receives a remark when the classification is
// approximate (an image byte whose value is unbound).
Operand classify(const lift::Model& model, expr::Id id,
                 std::string* note) {
    Operand out;
    out.id = id;
    if (id == expr::kNoId) {
        return out;
    }
    const expr::DAG& dag = model.dag;
    const expr::Node& n = dag.node(id);
    if (n.op == expr::Op::Const) {
        out.kind = Operand::Kind::Imm;
        out.imm = dag.const_value(id);
        out.width = n.width;
        return out;
    }
    if (n.op == expr::Op::Input) {
        const unsigned ord = static_cast<unsigned>(n.imm);
        const lift::Model::Input* in = input_at(model, ord);
        if (in != nullptr && in->kind == lift::Model::Input::Kind::Image &&
            note != nullptr) {
            char b[80];
            std::snprintf(b, sizeof(b),
                          "image byte @ 0x%llx (value not bound)",
                          static_cast<unsigned long long>(in->va));
            append_piece(*note, b);
        }
        return classify_leaf(model, ord);
    }
    const std::vector<unsigned> ords = dag.inputs_of(id);
    if (ords.empty()) {
        // A constant expression: evaluate it with no inputs.
        out.kind = Operand::Kind::Imm;
        out.imm = dag.evaluate(id, {});
        out.width = n.width;
        return out;
    }
    return classify_leaf(model, ords[0]);
}

// Whether every input leaf of `id` is a Code or Image input -- the
// signature of a value that comes out of the bytecode or the image.
bool leaves_are_code_or_image(const lift::Model& model, expr::Id id) {
    const std::vector<unsigned> ords = model.dag.inputs_of(id);
    if (ords.empty()) {
        return false;
    }
    for (const unsigned ord : ords) {
        const lift::Model::Input* in = input_at(model, ord);
        if (in == nullptr ||
            (in->kind != lift::Model::Input::Kind::Code &&
             in->kind != lift::Model::Input::Kind::Image)) {
            return false;
        }
    }
    return true;
}

// Whether `id` is a *decryption* of bytecode: a nontrivial operation
// (not just a widen, not a bare read) over Code/Image leaves. This is
// what sets `VInsn::decrypted`.
bool is_decrypt_expression(const lift::Model& model, expr::Id id) {
    if (id == expr::kNoId) {
        return false;
    }
    const expr::Node& n = model.dag.node(id);
    switch (n.op) {
    case expr::Op::Input:
    case expr::Op::Select:
    case expr::Op::CmpEQ:
    case expr::Op::CmpULT:
    case expr::Op::CmpSLT:
    case expr::Op::Const:
        return false;
    case expr::Op::Resize:
        return is_decrypt_expression(model, n.a);
    default:
        break;
    }
    return leaves_are_code_or_image(model, id);
}

// ----------------------------------------------------- instruction names

const char* op_name(VInsn::Op op) {
    switch (op) {
    case VInsn::Op::Push:    return "push";
    case VInsn::Op::Pop:     return "pop";
    case VInsn::Op::Mov:     return "mov";
    case VInsn::Op::Lea:     return "lea";
    case VInsn::Op::Add:     return "add";
    case VInsn::Op::Sub:     return "sub";
    case VInsn::Op::Adc:     return "adc";
    case VInsn::Op::Sbb:     return "sbb";
    case VInsn::Op::And:     return "and";
    case VInsn::Op::Or:      return "or";
    case VInsn::Op::Xor:     return "xor";
    case VInsn::Op::Not:     return "not";
    case VInsn::Op::Neg:     return "neg";
    case VInsn::Op::Shl:     return "shl";
    case VInsn::Op::Shr:     return "shr";
    case VInsn::Op::Sar:     return "sar";
    case VInsn::Op::Inc:     return "inc";
    case VInsn::Op::Dec:     return "dec";
    case VInsn::Op::Cmp:     return "cmp";
    case VInsn::Op::Test:    return "test";
    case VInsn::Op::Jcc:     return "jcc";
    case VInsn::Op::Jmp:     return "jmp";
    case VInsn::Op::Call:    return "call";
    case VInsn::Op::Ret:     return "ret";
    case VInsn::Op::Unknown: return "unknown";
    }
    return "?";
}

std::string operand_text(const Operand& o) {
    char b[64];
    switch (o.kind) {
    case Operand::Kind::Slot:
        std::snprintf(b, sizeof(b), "vst[%+lld]",
                      static_cast<long long>(o.disp));
        return b;
    case Operand::Kind::Code:
        std::snprintf(b, sizeof(b), "code[%+lld]",
                      static_cast<long long>(o.disp));
        return b;
    case Operand::Kind::Imm:
        std::snprintf(b, sizeof(b), "0x%llx",
                      static_cast<unsigned long long>(o.imm));
        return b;
    case Operand::Kind::Reg:
        return o.reg;
    case Operand::Kind::Mem:
        return "mem[...]";
    case Operand::Kind::None:
        break;
    }
    return "?";
}

// Maps a DAG ALU op to its virtual opcode; Unknown when it has none.
VInsn::Op alu_op(expr::Op op) {
    switch (op) {
    case expr::Op::Add: return VInsn::Op::Add;
    case expr::Op::Sub: return VInsn::Op::Sub;
    case expr::Op::And: return VInsn::Op::And;
    case expr::Op::Or:  return VInsn::Op::Or;
    case expr::Op::Xor: return VInsn::Op::Xor;
    case expr::Op::Not: return VInsn::Op::Not;
    case expr::Op::Neg: return VInsn::Op::Neg;
    case expr::Op::Shl: return VInsn::Op::Shl;
    case expr::Op::Shr: return VInsn::Op::Shr;
    case expr::Op::Sar: return VInsn::Op::Sar;
    default:            return VInsn::Op::Unknown;
    }
}

// ------------------------------------------------- write recognition

// Names one stack write. `ok` is false when the written value has a
// shape the matcher does not name.
bool recognize_write(const lift::Model& model,
                     const lift::Handler::Write& wr, VInsn& v) {
    const expr::DAG& dag = model.dag;
    const expr::Id val = wr.value;
    if (val == expr::kNoId) {
        return false;
    }
    const expr::Node& n = dag.node(val);
    const expr::Op op = n.op;

    // Destination, for the note.
    std::string dest;
    if (wr.to_slot) {
        char b[48];
        std::snprintf(b, sizeof(b), "vst[%+lld]",
                      static_cast<long long>(wr.disp));
        dest = b;
    } else {
        dest = "mem[...]";
    }

    // 1. A binary ALU on the written value (an addition of two slots is
    //    the virtual add). `x + 1` reads as an Inc, `x - 1` as a Dec.
    if (op == expr::Op::Add || op == expr::Op::Sub ||
        op == expr::Op::And || op == expr::Op::Or ||
        op == expr::Op::Xor) {
        if (op == expr::Op::Add &&
            (dag.is_const(n.a) || dag.is_const(n.b))) {
            const bool const_b = dag.is_const(n.b);
            const expr::Id other = const_b ? n.a : n.b;
            const std::uint64_t k =
                const_b ? dag.const_value(n.b) : dag.const_value(n.a);
            if (k == 1 && !dag.is_const(other)) {
                v.op = VInsn::Op::Inc;
                v.operands.push_back(classify(model, other, &v.note));
                append_piece(v.note, "-> " + dest);
                return true;
            }
        }
        if (op == expr::Op::Sub && dag.is_const(n.b) &&
            dag.const_value(n.b) == 1 && !dag.is_const(n.a)) {
            v.op = VInsn::Op::Dec;
            v.operands.push_back(classify(model, n.a, &v.note));
            append_piece(v.note, "-> " + dest);
            return true;
        }
        v.op = alu_op(op);
        v.operands.push_back(classify(model, n.a, &v.note));
        v.operands.push_back(classify(model, n.b, &v.note));
        append_piece(v.note, "-> " + dest);
        return true;
    }
    // 2. A unary ALU.
    if (op == expr::Op::Not || op == expr::Op::Neg ||
        op == expr::Op::Shl || op == expr::Op::Shr ||
        op == expr::Op::Sar) {
        v.op = alu_op(op);
        v.operands.push_back(classify(model, n.a, &v.note));
        append_piece(v.note, "-> " + dest);
        return true;
    }
    // 3. A value that comes out of the bytecode or the image: the
    //    virtual push of an immediate. A decryption over code marks
    //    `decrypted`.
    if (leaves_are_code_or_image(model, val)) {
        v.op = VInsn::Op::Push;
        v.operands.push_back(classify(model, val, &v.note));
        v.decrypted = is_decrypt_expression(model, val);
        append_piece(v.note, "-> " + dest);
        return true;
    }
    // 4. A bare input or a widened input: a data movement (slot to
    //    slot, register to slot).
    if (op == expr::Op::Input || op == expr::Op::Resize) {
        v.op = VInsn::Op::Mov;
        v.operands.push_back(classify(model, val, &v.note));
        append_piece(v.note, "-> " + dest);
        return true;
    }
    // 5. A comparison result written to the stack.
    if (op == expr::Op::CmpEQ || op == expr::Op::CmpULT ||
        op == expr::Op::CmpSLT) {
        v.op = VInsn::Op::Cmp;
        v.operands.push_back(classify(model, n.a, &v.note));
        v.operands.push_back(classify(model, n.b, &v.note));
        append_piece(v.note, "-> " + dest);
        return true;
    }
    return false;
}

}  // namespace

// -------------------------------------------------------------- recover

Stream recover(const lift::Model& model,
               const std::vector<lift::Handler>& handlers) {
    Stream out;

    // The entry pointers, for delta recognition. A handler's rbp_new /
    // rsi_new is read relative to these register inputs.
    const lift::Model::Input* rbp_in = nullptr;
    const lift::Model::Input* rsi_in = nullptr;
    for (const lift::Model::Input& in : model.inputs) {
        if (in.kind != lift::Model::Input::Kind::Reg) {
            continue;
        }
        if (in.name == "rbp") {
            rbp_in = &in;
        } else if (in.name == "rsi") {
            rsi_in = &in;
        }
    }
    const expr::Id rbp_id = rbp_in != nullptr ? rbp_in->id : expr::kNoId;
    const expr::Id rsi_id = rsi_in != nullptr ? rsi_in->id : expr::kNoId;
    const expr::DAG& dag = model.dag;

    for (const lift::Handler& h : handlers) {
        // A model the lift could not complete is reported as Unknown with
        // the lift's own reason; it is not a candidate for recognition.
        if (!h.modeled) {
            ++out.unmodeled;
            VInsn u;
            u.src_va = h.va;
            u.op = VInsn::Op::Unknown;
            u.note = h.reason.empty() ? "handler walk not settled" : h.reason;
            out.insns.push_back(std::move(u));
            ++out.unrecognized;
            char b[64];
            std::snprintf(b, sizeof(b), "handler 0x%llx: model incomplete",
                          static_cast<unsigned long long>(h.va));
            out.notes.emplace_back(b);
            continue;
        }

        // Caveats from the walk (unmodellable instructions, an address
        // the model could not name): the model is inexact, which is
        // counted and reported, never hidden.
        std::string note;
        if (!h.notes.empty()) {
            ++out.unmodeled;
            note = h.notes[0];
        }

        // Stack-pointer and cursor deltas, as best the model says.
        std::int64_t stack_delta = 0;
        bool stack_known = false;
        bool stack_approx = false;
        if (const_delta(dag, rbp_id, h.rbp_new, &stack_delta)) {
            stack_known = true;
        } else if (h.rbp_new != expr::kNoId &&
                   approx_delta(dag, h.rbp_new, &stack_delta)) {
            stack_known = true;
            stack_approx = true;
        }
        std::int64_t cursor_delta = 0;
        bool cursor_known = false;
        bool cursor_approx = false;
        if (const_delta(dag, rsi_id, h.rsi_new, &cursor_delta)) {
            cursor_known = true;
        } else if (h.rsi_new != expr::kNoId &&
                   approx_delta(dag, h.rsi_new, &cursor_delta)) {
            cursor_known = true;
            cursor_approx = true;
        }

        // This handler's recognized instructions: the effects (writes)
        // first, then the control transfer.
        std::vector<VInsn> emitted;

        // 1. A dispatch the model computes out of the bytecode names a
        //    Jmp. A constant target is a plain Jmp; a decryption is a
        //    decrypted Jmp (the plaintext needs fold_encrypted and the
        //    image bytes, which recover does not carry). The dispatcher's
        //    bare-register tail (`jmp rcx`) is not an instruction.
        if (h.transfer == lift::Handler::Transfer::Dispatch &&
            h.target_expr != expr::kNoId) {
            const expr::Node& tn = dag.node(h.target_expr);
            VInsn j;
            j.src_va = h.va;
            if (tn.op == expr::Op::Const) {
                j.op = VInsn::Op::Jmp;
                j.operands.push_back(classify(model, h.target_expr, &j.note));
                emitted.push_back(std::move(j));
            } else if (tn.op != expr::Op::Input &&
                       is_decrypt_expression(model, h.target_expr)) {
                j.op = VInsn::Op::Jmp;
                j.decrypted = true;
                j.operands.push_back(classify(model, h.target_expr, &j.note));
                append_piece(j.note,
                             "dispatch target is a decrypted bytecode word "
                             "(plaintext via fold_encrypted)");
                emitted.push_back(std::move(j));
            } else if (tn.op != expr::Op::Input) {
                // A computed target that is not a bytecode decryption:
                // report it honestly as a Jmp to the expression.
                j.op = VInsn::Op::Jmp;
                j.operands.push_back(classify(model, h.target_expr, &j.note));
                append_piece(j.note,
                             "dispatch target not recognized as decryption");
                emitted.push_back(std::move(j));
            }
        }

        // 2. Stack writes: one virtual instruction per write, named from
        //    the shape of the written value.
        for (const lift::Handler::Write& wr : h.writes) {
            VInsn wv;
            wv.src_va = h.va;
            if (wr.value == expr::kNoId) {
                ++out.unmodeled;
                wv.op = VInsn::Op::Unknown;
                wv.note = "write value unknown to the model";
                emitted.push_back(std::move(wv));
                ++out.unrecognized;
                continue;
            }
            if (recognize_write(model, wr, wv)) {
                emitted.push_back(std::move(wv));
                continue;
            }
            // An un-named write shape: Unknown, with the expression text
            // so nothing is silently dropped.
            wv.op = VInsn::Op::Unknown;
            wv.note = "write value has no recognized shape: " +
                      dag.pretty(wr.value);
            emitted.push_back(std::move(wv));
            ++out.unrecognized;
        }

        // 3. Nothing at all was recognized (a handler that only clobbers
        //    registers, for instance): Unknown with the deltas.
        if (emitted.empty()) {
            ++out.unrecognized;
            VInsn u;
            u.src_va = h.va;
            u.op = VInsn::Op::Unknown;
            append_delta(note, "vsp", stack_known, stack_approx, stack_delta);
            append_delta(note, "cursor", cursor_known, cursor_approx,
                         cursor_delta);
            u.note = note.empty() ? "no recognized virtual effect" : note;
            out.insns.push_back(std::move(u));
            continue;
        }

        // Attach the deltas to every named instruction of this handler.
        for (VInsn& x : emitted) {
            if (x.op != VInsn::Op::Unknown) {
                append_delta(x.note, "vsp", stack_known, stack_approx,
                             stack_delta);
                append_delta(x.note, "cursor", cursor_known, cursor_approx,
                             cursor_delta);
            }
        }
        for (VInsn& x : emitted) {
            out.insns.push_back(std::move(x));
        }
    }
    return out;
}

// --------------------------------------------------------- fold_encrypted

namespace {

// Parses `img[0x<hex>]`. Returns false on any shape mismatch.
bool parse_img_va(const std::string& name, std::uint64_t* va) {
    if (name.rfind("img[0x", 0) != 0) {
        return false;
    }
    const char* p = name.c_str() + 6;
    std::uint64_t v = 0;
    for (; *p != '\0' && *p != ']'; ++p) {
        const char c = *p;
        unsigned d;
        if (c >= '0' && c <= '9') {
            d = static_cast<unsigned>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            d = static_cast<unsigned>(c - 'a') + 10;
        } else if (c >= 'A' && c <= 'F') {
            d = static_cast<unsigned>(c - 'A') + 10;
        } else {
            return false;
        }
        v = v * 16 + d;
    }
    if (*p != ']') {
        return false;
    }
    *va = v;
    return true;
}

// Parses `code[<signed>]` (`code[+8]`, `code[-1]`). Returns false on any
// shape mismatch.
bool parse_code_disp(const std::string& name, std::int64_t* disp) {
    if (name.rfind("code[", 0) != 0) {
        return false;
    }
    const char* p = name.c_str() + 5;
    bool neg = false;
    if (*p == '+') {
        ++p;
    } else if (*p == '-') {
        neg = true;
        ++p;
    }
    if (*p == '\0') {
        return false;
    }
    std::int64_t v = 0;
    for (; *p != '\0' && *p != ']'; ++p) {
        if (*p < '0' || *p > '9') {
            return false;
        }
        v = v * 10 + static_cast<std::int64_t>(*p - '0');
    }
    if (*p != ']') {
        return false;
    }
    *disp = neg ? -v : v;
    return true;
}

}  // namespace

expr::Id fold_encrypted(const expr::DAG& dag, expr::Id id,
                        CodeReader reader, void* ctx) {
    if (!dag.valid(id)) {
        return expr::kNoId;
    }
    // A constant is already its own plaintext.
    if (dag.node(id).op == expr::Op::Const) {
        return id;
    }
    // A null reader can bind nothing -- no bytes, and no cursor for the
    // Code inputs -- so any expression with inputs cannot be folded.
    if (reader == nullptr) {
        return expr::kNoId;
    }

    // Collect every input ordinal the expression touches and bind each
    // one from the reader. Any input that is not a Code or Image leaf --
    // a register, a slot, an unknown, a computed load -- makes the whole
    // fold impossible, because the model cannot know its value.
    const std::vector<unsigned> ords = dag.inputs_of(id);
    std::size_t width_span = 0;
    for (const unsigned ord : ords) {
        width_span = width_span > static_cast<std::size_t>(ord) + 1
                         ? width_span
                         : static_cast<std::size_t>(ord) + 1;
    }
    std::vector<std::uint64_t> binding(width_span, 0);
    for (const unsigned ord : ords) {
        // Find the input node by ordinal. The DAG keeps input names next
        // to the nodes, so a scan is the public way to reach them.
        const expr::Node* in = nullptr;
        for (expr::Id i = 0; i < dag.size(); ++i) {
            const expr::Node& cand = dag.node(i);
            if (cand.op == expr::Op::Input && cand.imm == ord) {
                in = &cand;
                break;
            }
        }
        if (in == nullptr) {
            return expr::kNoId;
        }
        std::uint64_t value = 0;
        bool ok = false;
        std::uint64_t img_va = 0;
        std::int64_t code_disp = 0;
        if (parse_img_va(in->name, &img_va)) {
            // Image inputs carry their absolute image address.
            ok = reader(ctx, img_va, in->width, &value);
        } else if (parse_code_disp(in->name, &code_disp)) {
            // The displacement is cursor-relative: the caller's reader is
            // expected to know the cursor and add its own base.
            ok = reader(ctx, static_cast<std::uint64_t>(code_disp),
                        in->width, &value);
        } else {
            return expr::kNoId;  // a non-bytecode leaf
        }
        if (!ok) {
            return expr::kNoId;  // the reader could not supply the bytes
        }
        binding[ord] = value;
    }

    const std::uint64_t folded = dag.evaluate(id, binding);
    // Intern the plaintext. The reference is const by contract, but the
    // DAG object is never const at any call site (it is the model's own
    // DAG, being built by the caller), so interning through const_cast is
    // defined behavior and gives the caller a usable Const node.
    expr::DAG& mut = const_cast<expr::DAG&>(dag);
    return mut.constant(folded, dag.width(id));
}

// --------------------------------------------------------------- render

std::string Stream::render() const {
    std::string text;
    char b[80];
    for (const VInsn& v : insns) {
        std::snprintf(b, sizeof(b), "0x%llx: %s",
                      static_cast<unsigned long long>(v.src_va),
                      op_name(v.op));
        text += b;
        for (const Operand& o : v.operands) {
            text += ' ';
            text += operand_text(o);
        }
        if (v.decrypted) {
            text += " (decrypted)";
        }
        if (!v.note.empty()) {
            text += "  ; ";
            text += v.note;
        }
        text += '\n';
    }
    for (const std::string& n : notes) {
        text += "note: ";
        text += n;
        text += '\n';
    }
    std::snprintf(b, sizeof(b), "unmodeled: %llu, unrecognized: %llu\n",
                  static_cast<unsigned long long>(unmodeled),
                  static_cast<unsigned long long>(unrecognized));
    text += b;
    return text;
}

}  // namespace occ::devirt::semlib

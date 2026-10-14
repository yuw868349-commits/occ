// Lifting a VM handler into a model of the virtual machine (see lift.h).
//
// Two layers of decoding are in play and it is worth being explicit
// about why. The inspector's decoder (`inspect/disasm.h`) owns the
// *length* of an instruction and its mnemonic: it validates that there is
// an instruction there at all and says how many bytes it occupies. What
// it does not publish is the operand *shape* -- which operand is the
// destination, what a memory operand's base, index and displacement are,
// what width the access has -- and that shape is exactly what an
// abstract interpreter consumes. This file derives it, on top of the
// inspector's answer, for the integer instruction families a VM handler
// is made of. It never computes a length of its own: the inspector's
// length is authoritative and every immediate and displacement is read
// inside it. A form this file does not model does not become a guess --
// it marks the handler's model incomplete, and the report says so.
//
// The interpreter is a straightforward abstract interpreter over a
// register file of `Value`s and a byte-granular map of the virtual
// stack. Byte-granular because the junk overlaps its own accesses: a
// qword is stored at one displacement and a dword read at another that
// shares four of its bytes, and a cell-granular file would hand back the
// entry value for the overlapping half -- a stale number that looks
// right. Two design points are worth stating.
//
// An instruction the decoder does not render does not abort the walk. It
// marks the model incomplete and goes on, because the trace check that
// follows is what decides whether the recovered effect is right, and a
// model that gave up at the first `cpuid` in the junk would never reach
// the effect that matters. What such an instruction can no longer be
// shown not to touch becomes an "unknown of its own": a fresh unbound
// input, so that everything built out of it stays an expression -- a
// partial write keeps the half it did not write -- and the trace check
// counts the predictions that lean on it as unverifiable instead of
// evaluating a stale number as if it were known.
//
// A value read through a computed address is a load input keyed by the
// address expression. The model cannot know what lives at the address,
// but it can say which address it read, and the checker can look those
// bytes up in the memory the trace itself observed.
//
// A branch the model cannot decide forks: both edges are walked from the
// state the branch saw, and the arms are merged with a select on the
// condition. Nothing is guessed and nothing is dropped -- a value only
// one arm wrote is, in the other, what was there, which is a load at the
// same address -- and the checker, which can evaluate the condition,
// follows the arm that actually ran.

#include "occ/devirt/lift.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace occ::devirt::lift {

namespace {

const char* const kReg64[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp",
                                "rsi", "rdi", "r8",  "r9",  "r10", "r11",
                                "r12", "r13", "r14", "r15"};

// ------------------------------------------------------- shape decoding

struct Shape {
    bool ok = false;
    enum class Op : std::uint8_t {
        None, Mov, Movzx, Movsx, Lea, Add, Adc, Sub, Sbb, And, Or, Xor,
        Cmp, Test, Inc, Dec, Not, Neg, Shl, Shr, Sar, Rol, Ror, Rcl, Rcr,
        Imul, Xchg, Cmov, Setcc, Push, Pop, Nop, Cwde, Cdq, Pushf, Popf,
        Clc, Stc, Cmc, Cld, Std, Jmp, Jcc, Call, Ret, Leave, Hlt, Int3,
        Bt, Bts, Btr, Btc, Bsf, Bsr, Bswap, Shld, Shrd, Xadd,
    };
    Op op = Op::None;
    unsigned cond = 0xF;
    unsigned width = 64;
    Operand dst;
    Operand src;
    bool has_dst = false;
    bool has_src = false;
    bool indirect = false;
    // The double-shift forms (shld/shrd) carry their count as a third
    // operand: a literal imm8 in `count`, or CL when `count_is_cl`.
    std::uint8_t count = 0;
    bool count_is_cl = false;
    inspect::InsnKind kind = inspect::InsnKind::Other;
};

struct ByteReader {
    const std::uint8_t* b = nullptr;
    std::size_t n = 0;
    std::size_t at = 0;
    [[nodiscard]] bool have(std::size_t k) const { return at + k <= n; }
    std::uint8_t u8() { return b[at++]; }
    std::uint16_t u16() {
        const std::uint16_t v =
            static_cast<std::uint16_t>(b[at] | (b[at + 1] << 8));
        at += 2;
        return v;
    }
    std::uint32_t u32() {
        std::uint32_t v = 0;
        std::memcpy(&v, b + at, 4);
        at += 4;
        return v;
    }
    std::uint64_t u64() {
        std::uint64_t v = 0;
        std::memcpy(&v, b + at, 8);
        at += 8;
        return v;
    }
};

struct Prefix {
    bool rex_any = false;
    bool rex_w = false;
    bool rex_r = false;
    bool rex_x = false;
    bool rex_b = false;
    bool operand16 = false;
};

// The 8-bit register numbers 4..7 name ah/ch/dh/bh when no REX prefix is
// present -- the high bytes of rax/rcx/rdx/rbx -- and spl/bpl/sil/dil
// (the low bytes of rsp/rbp/rsi/rdi) when one is. Folding the two into
// "rsp..rdi" would make `mov dh, ah` read and write rsi, which is how a
// junk handler's scratch byte wanders into the cursor.
const char* const kHighBytes[4] = {"ah", "ch", "dh", "bh"};
const char* const kHighParents[4] = {"rax", "rcx", "rdx", "rbx"};

// Maps an 8-bit register number to its name, honouring the high-byte
// rule. Returns kReg64[n] for everything else.
const char* reg8_name(unsigned index, const Prefix& px) {
    const unsigned n = index & 15;
    if (n >= 4 && n <= 7 && !px.rex_any) {
        return kHighBytes[n - 4];
    }
    return kReg64[n];
}

// The ModRM byte has already been consumed; this reads the memory form
// that follows it. A rip-relative operand keeps its *effective address*
// in `disp`, because for this layer the displacement and the address are
// the same number: the operand names one byte of the image.
Operand read_rm(ByteReader& r, std::uint8_t modrm, const Prefix& px,
                unsigned width, std::uint64_t va, unsigned length) {
    Operand o;
    const std::uint8_t mod = static_cast<std::uint8_t>(modrm >> 6);
    const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 7);
    if (mod == 3) {
        o.kind = Operand::Kind::Reg;
        const unsigned index =
            static_cast<unsigned>(rm | (px.rex_b ? 8 : 0));
        o.reg = width == 8 ? reg8_name(index, px) : kReg64[index];
        o.width = width;
        return o;
    }
    o.kind = Operand::Kind::Mem;
    o.width = width;
    std::uint8_t base = static_cast<std::uint8_t>(rm | (px.rex_b ? 8 : 0));
    bool has_base = true;
    std::int64_t disp = 0;
    if (rm == 4) {
        const std::uint8_t sib = r.u8();
        const unsigned scale = 1u << (sib >> 6);
        const std::uint8_t index =
            static_cast<std::uint8_t>(((sib >> 3) & 7) | (px.rex_x ? 8 : 0));
        if (((sib >> 3) & 7) != 4 || px.rex_x) {
            o.index = kReg64[static_cast<std::size_t>(index)];
        }
        o.scale = static_cast<int>(scale);
        if ((sib & 7) == 5 && mod == 0) {
            has_base = false;
            disp = r.u32();
        } else {
            base = static_cast<std::uint8_t>((sib & 7) | (px.rex_b ? 8 : 0));
        }
    } else if (rm == 5 && mod == 0) {
        std::uint32_t d = r.u32();
        std::int32_t sd = 0;
        std::memcpy(&sd, &d, 4);
        o.base = "rip";
        o.disp = static_cast<std::int64_t>(va) +
                 static_cast<std::int64_t>(length) + sd;
        return o;
    }
    if (mod == 1) {
        disp = static_cast<std::int8_t>(r.u8());
    } else if (mod == 2) {
        std::uint32_t d = r.u32();
        std::int32_t sd = 0;
        std::memcpy(&sd, &d, 4);
        disp = sd;
    }
    if (has_base) {
        o.base = kReg64[static_cast<std::size_t>(base)];
    }
    o.disp = disp;
    return o;
}

const Shape::Op kAlu[8] = {Shape::Op::Add, Shape::Op::Or,  Shape::Op::Adc,
                           Shape::Op::Sbb, Shape::Op::And, Shape::Op::Sub,
                           Shape::Op::Xor, Shape::Op::Cmp};
const Shape::Op kShift[8] = {Shape::Op::Rol, Shape::Op::Ror, Shape::Op::Rcl,
                             Shape::Op::Rcr, Shape::Op::Shl, Shape::Op::Shr,
                             Shape::Op::Shl, Shape::Op::Sar};

void decode_shape(const std::uint8_t* bytes, std::size_t available,
                  unsigned length, std::uint64_t va, Shape& s) {
    if (length == 0 || available < length) {
        return;
    }
    ByteReader r{bytes, available, 0};
    Prefix px;
    for (;;) {
        if (!r.have(1)) {
            return;
        }
        const std::uint8_t p = r.b[r.at];
        if (p == 0x66) {
            px.operand16 = true;
        } else if (p == 0x67 || p == 0xF0 || p == 0xF2 || p == 0xF3 ||
                   p == 0x2E || p == 0x36 || p == 0x3E || p == 0x26 ||
                   p == 0x64 || p == 0x65) {
            // Segment, repeat and lock prefixes do not change the shape
            // this layer models.
        } else if (p >= 0x40 && p <= 0x4F) {
            px.rex_any = true;
            px.rex_w = (p & 8) != 0;
            px.rex_r = (p & 4) != 0;
            px.rex_x = (p & 2) != 0;
            px.rex_b = (p & 1) != 0;
        } else {
            break;
        }
        ++r.at;
    }
    if (!r.have(1)) {
        return;
    }
    const std::uint8_t op1 = bytes[r.at];
    const unsigned op_width = px.rex_w ? 64 : (px.operand16 ? 16 : 32);
    const auto reg_op = [&](std::uint8_t index, unsigned width) {
        Operand o;
        o.kind = Operand::Kind::Reg;
        o.reg = width == 8 ? reg8_name(index, px)
                           : kReg64[static_cast<std::size_t>(index & 15)];
        o.width = width;
        return o;
    };
    const auto imm_op = [&](std::uint64_t v, unsigned width, bool is_signed) {
        Operand o;
        o.kind = Operand::Kind::Imm;
        o.imm = v;
        o.width = width;
        o.imm_signed = is_signed;
        return o;
    };
    // Sign-extension of an immediate to the operand width: x86 does it
    // for every group-1 immediate form and for the sign-extending pushes.
    const auto sign_fit = [&](std::uint64_t v, unsigned from, unsigned to) {
        if (from >= to) {
            return v;
        }
        std::int64_t sv = 0;
        if (from == 8) {
            sv = static_cast<std::int8_t>(v);
        } else if (from == 16) {
            sv = static_cast<std::int16_t>(v);
        } else {
            sv = static_cast<std::int32_t>(v);
        }
        return static_cast<std::uint64_t>(sv);
    };

    if (op1 < 0x40) {
        const unsigned sub = (op1 >> 3) & 7;
        const unsigned form = op1 & 7;
        if (form < 6) {
            const bool al_form = form == 4 || form == 5;
            const unsigned width = (form & 1) != 0 ? op_width : 8;
            s.op = kAlu[sub];
            if (al_form) {
                ++r.at;
                const std::uint64_t raw = width == 8 ? r.u8()
                                         : width == 16 ? r.u16()
                                                       : r.u32();
                const unsigned imm_width = width == 8 ? 8u : width;
                s.dst = reg_op(0, width);
                s.src = imm_op(imm_width < width ? sign_fit(raw, imm_width, width)
                                                 : raw,
                               imm_width, imm_width < width);
            } else {
                ++r.at;
                const std::uint8_t modrm = r.u8();
                const Operand rm = read_rm(r, modrm, px, width, va, length);
                const Operand reg =
                    reg_op(static_cast<std::uint8_t>(((modrm >> 3) & 7) |
                                                     (px.rex_r ? 8 : 0)),
                           width);
                if ((op1 & 2) != 0) {
                    s.dst = reg;
                    s.src = rm;
                } else {
                    s.dst = rm;
                    s.src = reg;
                }
            }
            s.has_dst = s.has_src = true;
            s.width = width;
            s.ok = true;
            return;
        }
    }

    switch (op1) {
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F: {
        ++r.at;
        const bool push = op1 < 0x58;
        s.op = push ? Shape::Op::Push : Shape::Op::Pop;
        s.dst = reg_op(static_cast<std::uint8_t>((op1 & 7) |
                                                 (px.rex_b ? 8 : 0)),
                       64);
        s.has_dst = true;
        s.ok = true;
        return;
    }
    case 0x68:
    case 0x6A: {
        ++r.at;
        s.op = Shape::Op::Push;
        const std::uint64_t raw = op1 == 0x68 ? r.u32() : r.u8();
        s.dst = imm_op(sign_fit(raw, op1 == 0x68 ? 32u : 8u, 64), 64, true);
        s.has_dst = true;
        s.ok = true;
        return;
    }
    case 0x69:
    case 0x6B:
        // imul r, r/m, imm carries a third operand this layer does not
        // model. Leaving it unmodelled is the honest answer: modelling
        // it as the two-operand form would compute the wrong product.
        return;
    case 0x70: case 0x71: case 0x72: case 0x73:
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
        ++r.at;
        s.op = Shape::Op::Jcc;
        s.cond = op1 & 15;
        s.kind = inspect::InsnKind::Jcc;
        const std::int8_t rel = static_cast<std::int8_t>(r.u8());
        s.dst = imm_op(static_cast<std::uint64_t>(
                           static_cast<std::int64_t>(va + length) + rel),
                       64, true);
        s.has_dst = true;
        s.ok = true;
        return;
    }
    case 0x80:
    case 0x81:
    case 0x83: {
        ++r.at;
        const std::uint8_t modrm = r.u8();
        const unsigned width = op1 == 0x80 ? 8 : op_width;
        s.op = kAlu[(modrm >> 3) & 7];
        // The immediate is a byte for 80/83 and an operand-sized word
        // for 81, and in both cases x86 sign-extends it to the operand
        // width -- `sub rsi, 0xffffffffffffffff` is a byte -1 in the 83
        // form and a dword -1 in the 81 form, and both are -1.
        const unsigned imm_width =
            op1 == 0x83 ? 8u : (width == 8 ? 8u : (width == 16 ? 16u : 32u));
        const std::uint64_t raw = imm_width == 8 ? r.u8()
                                  : imm_width == 16 ? r.u16()
                                                    : r.u32();
        const std::uint64_t imm = imm_width < width ? sign_fit(raw, imm_width, width) : raw;
        s.dst = read_rm(r, modrm, px, width, va, length);
        s.src = imm_op(imm, width, imm_width < width);
        s.has_dst = s.has_src = true;
        s.width = width;
        s.ok = true;
        return;
    }
    case 0x84:
    case 0x85:
    case 0x86:
    case 0x87:
    case 0x88: case 0x89: case 0x8A: case 0x8B: {
        ++r.at;
        const std::uint8_t modrm = r.u8();
        const unsigned width = (op1 & 1) != 0 ? op_width : 8;
        if (op1 == 0x84 || op1 == 0x85) {
            s.op = Shape::Op::Test;
        } else if (op1 == 0x86 || op1 == 0x87) {
            s.op = Shape::Op::Xchg;
        } else {
            s.op = Shape::Op::Mov;
        }
        const Operand rm = read_rm(r, modrm, px, width, va, length);
        const Operand reg =
            reg_op(static_cast<std::uint8_t>(((modrm >> 3) & 7) |
                                             (px.rex_r ? 8 : 0)),
                   width);
        if (op1 == 0x88 || op1 == 0x8A) {
            // The byte forms: 88 is r/m <- r, 8A is r <- r/m.
            if (op1 == 0x8A) {
                s.dst = reg;
                s.src = rm;
            } else {
                s.dst = rm;
                s.src = reg;
            }
        } else if ((op1 & 2) != 0) {
            s.dst = reg;
            s.src = rm;
        } else {
            s.dst = rm;
            s.src = reg;
        }
        s.has_dst = s.has_src = true;
        s.width = width;
        s.ok = true;
        return;
    }
    case 0x8D: {
        ++r.at;
        const std::uint8_t modrm = r.u8();
        s.op = Shape::Op::Lea;
        s.dst = reg_op(static_cast<std::uint8_t>(((modrm >> 3) & 7) |
                                                 (px.rex_r ? 8 : 0)),
                       op_width);
        s.src = read_rm(r, modrm, px, op_width, va, length);
        s.has_dst = s.has_src = true;
        s.width = op_width;
        s.ok = true;
        return;
    }
    case 0x8F: {
        ++r.at;
        const std::uint8_t modrm = r.u8();
        s.op = Shape::Op::Pop;
        s.dst = read_rm(r, modrm, px, 64, va, length);
        s.has_dst = true;
        s.ok = true;
        return;
    }
    case 0x90:
        ++r.at;
        s.op = Shape::Op::Nop;
        s.ok = true;
        return;
    case 0x98:
        ++r.at;
        s.op = Shape::Op::Cwde;
        s.width = px.rex_w ? 64 : 32;
        s.ok = true;
        return;
    case 0x99:
        ++r.at;
        s.op = Shape::Op::Cdq;
        s.width = px.rex_w ? 64 : 32;
        s.ok = true;
        return;
    case 0x9C:
        ++r.at;
        s.op = Shape::Op::Pushf;
        s.ok = true;
        return;
    case 0x9D:
        ++r.at;
        s.op = Shape::Op::Popf;
        s.ok = true;
        return;
    case 0xA8:
    case 0xA9: {
        ++r.at;
        const unsigned width = (op1 & 1) != 0 ? op_width : 8;
        s.op = Shape::Op::Test;
        const unsigned imm_width =
            width == 8 ? 8u : (width == 16 ? 16u : 32u);
        const std::uint64_t raw = imm_width == 8 ? r.u8()
                                  : imm_width == 16 ? r.u16()
                                                    : r.u32();
        s.dst = reg_op(0, width);
        s.src = imm_op(imm_width < width ? sign_fit(raw, imm_width, width)
                                         : raw,
                       width, imm_width < width);
        s.has_dst = s.has_src = true;
        s.width = width;
        s.ok = true;
        return;
    }
    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7: {
        ++r.at;
        s.op = Shape::Op::Mov;
        s.dst = reg_op(static_cast<std::uint8_t>((op1 & 7) |
                                                 (px.rex_b ? 8 : 0)),
                       8);
        s.src = imm_op(r.u8(), 8, false);
        s.has_dst = s.has_src = true;
        s.width = 8;
        s.ok = true;
        return;
    }
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
        ++r.at;
        s.op = Shape::Op::Mov;
        s.dst = reg_op(static_cast<std::uint8_t>((op1 & 7) |
                                                 (px.rex_b ? 8 : 0)),
                       op_width);
        const std::uint64_t imm =
            px.rex_w ? r.u64() : (op_width == 16 ? r.u16() : r.u32());
        s.src = imm_op(imm, op_width, false);
        s.has_dst = s.has_src = true;
        s.width = op_width;
        s.ok = true;
        return;
    }
    case 0xC0:
    case 0xC1: {
        ++r.at;
        const std::uint8_t modrm = r.u8();
        const unsigned width = (op1 & 1) != 0 ? op_width : 8;
        s.op = kShift[(modrm >> 3) & 7];
        const std::uint64_t imm = r.u8();
        s.dst = read_rm(r, modrm, px, width, va, length);
        s.src = imm_op(imm, 8, false);
        s.has_dst = s.has_src = true;
        s.width = width;
        s.ok = s.op != Shape::Op::None;
        return;
    }
    case 0xC6:
    case 0xC7: {
        ++r.at;
        const std::uint8_t modrm = r.u8();
        const unsigned width = op1 == 0xC6 ? 8 : op_width;
        s.op = Shape::Op::Mov;
        const unsigned imm_width = width == 8 ? 8u : (width == 16 ? 16u : 32u);
        const std::uint64_t raw = imm_width == 8 ? r.u8()
                                  : imm_width == 16 ? r.u16()
                                                    : r.u32();
        s.dst = read_rm(r, modrm, px, width, va, length);
        s.src = imm_op(imm_width < width ? sign_fit(raw, imm_width, width) : raw,
                       imm_width, imm_width < width);
        s.has_dst = s.has_src = true;
        s.width = width;
        s.ok = true;
        return;
    }
    case 0xC9:
        ++r.at;
        s.op = Shape::Op::Leave;
        s.ok = true;
        return;
    case 0xCC:
        ++r.at;
        s.op = Shape::Op::Int3;
        s.ok = true;
        return;
    case 0xD0:
    case 0xD1:
    case 0xD2:
    case 0xD3: {
        ++r.at;
        const std::uint8_t modrm = r.u8();
        const unsigned width = (op1 & 1) != 0 ? op_width : 8;
        s.op = kShift[(modrm >> 3) & 7];
        s.dst = read_rm(r, modrm, px, width, va, length);
        if (op1 == 0xD0 || op1 == 0xD1) {
            s.src = imm_op(1, 8, false);
        } else {
            s.src = reg_op(1, 8);  // cl
        }
        s.has_dst = s.has_src = true;
        s.width = width;
        s.ok = s.op != Shape::Op::None;
        return;
    }
    case 0xE8:
    case 0xE9: {
        ++r.at;
        std::int32_t rel = 0;
        std::memcpy(&rel, r.b + r.at, 4);
        s.op = op1 == 0xE8 ? Shape::Op::Call : Shape::Op::Jmp;
        s.kind = op1 == 0xE8 ? inspect::InsnKind::Call
                             : inspect::InsnKind::Jmp;
        s.dst = imm_op(static_cast<std::uint64_t>(
                           static_cast<std::int64_t>(va + length) + rel),
                       64, true);
        s.has_dst = true;
        s.ok = true;
        return;
    }
    case 0xEB: {
        ++r.at;
        const std::int8_t rel = static_cast<std::int8_t>(r.u8());
        s.op = Shape::Op::Jmp;
        s.kind = inspect::InsnKind::Jmp;
        s.dst = imm_op(static_cast<std::uint64_t>(
                           static_cast<std::int64_t>(va + length) + rel),
                       64, true);
        s.has_dst = true;
        s.ok = true;
        return;
    }
    case 0xF4:
        ++r.at;
        s.op = Shape::Op::Hlt;
        s.ok = true;
        return;
    case 0xF5:
        ++r.at;
        s.op = Shape::Op::Cmc;
        s.ok = true;
        return;
    case 0xF8:
        ++r.at;
        s.op = Shape::Op::Clc;
        s.ok = true;
        return;
    case 0xF9:
        ++r.at;
        s.op = Shape::Op::Stc;
        s.ok = true;
        return;
    case 0xFC:
        ++r.at;
        s.op = Shape::Op::Cld;
        s.ok = true;
        return;
    case 0xFD:
        ++r.at;
        s.op = Shape::Op::Std;
        s.ok = true;
        return;
    case 0xC2:
    case 0xC3:
        ++r.at;
        s.op = Shape::Op::Ret;
        s.kind = inspect::InsnKind::Ret;
        s.ok = true;
        return;
    case 0xFE:
    case 0xFF: {
        ++r.at;
        const std::uint8_t modrm = r.u8();
        const unsigned width = op1 == 0xFE ? 8 : op_width;
        const unsigned sub = (modrm >> 3) & 7;
        if (op1 == 0xFE) {
            if (sub > 1) {
                return;
            }
            s.op = sub == 0 ? Shape::Op::Inc : Shape::Op::Dec;
            s.dst = read_rm(r, modrm, px, width, va, length);
            s.has_dst = true;
            s.width = width;
            s.ok = true;
            return;
        }
        switch (sub) {
        case 0:
        case 1:
            s.op = sub == 0 ? Shape::Op::Inc : Shape::Op::Dec;
            s.dst = read_rm(r, modrm, px, width, va, length);
            s.has_dst = true;
            s.width = width;
            s.ok = true;
            return;
        case 2:
        case 3:
            s.op = Shape::Op::Call;
            s.kind = inspect::InsnKind::Call;
            s.dst = read_rm(r, modrm, px, 64, va, length);
            s.has_dst = true;
            s.indirect = true;
            s.ok = true;
            return;
        case 4:
        case 5:
            s.op = Shape::Op::Jmp;
            s.kind = inspect::InsnKind::Jmp;
            s.dst = read_rm(r, modrm, px, 64, va, length);
            s.has_dst = true;
            s.indirect = true;
            s.ok = true;
            return;
        case 6:
            s.op = Shape::Op::Push;
            s.dst = read_rm(r, modrm, px, 64, va, length);
            s.has_dst = true;
            s.ok = true;
            return;
        default:
            return;
        }
    }
    case 0xF6:
    case 0xF7: {
        ++r.at;
        const std::uint8_t modrm = r.u8();
        const unsigned width = op1 == 0xF6 ? 8 : op_width;
        const unsigned sub = (modrm >> 3) & 7;
        if (sub == 0 || sub == 1) {
            // test r/m, imm8/immz: the flags of an `and` with no write.
            s.op = Shape::Op::Test;
            s.dst = read_rm(r, modrm, px, width, va, length);
            const unsigned imm_width =
                width == 8 ? 8u : (width == 16 ? 16u : 32u);
            const std::uint64_t raw = imm_width == 8 ? r.u8()
                                      : imm_width == 16 ? r.u16()
                                                        : r.u32();
            s.src = imm_op(imm_width < width ? sign_fit(raw, imm_width, width)
                                             : raw,
                           width, imm_width < width);
            s.has_dst = s.has_src = true;
            s.width = width;
            s.ok = true;
            return;
        }
        if (sub != 2 && sub != 3) {
            return;
        }
        s.op = sub == 2 ? Shape::Op::Not : Shape::Op::Neg;
        s.dst = read_rm(r, modrm, px, width, va, length);
        s.has_dst = true;
        s.width = width;
        s.ok = true;
        return;
    }
    default:
        break;
    }

    if (op1 == 0x0F && r.have(2)) {
        const std::uint8_t op2 = bytes[r.at + 1];
        r.at += 2;
        switch (op2) {
        case 0x05:
            s.op = Shape::Op::Hlt;
            s.kind = inspect::InsnKind::Syscall;
            return;
        case 0x1F:
            s.op = Shape::Op::Nop;
            s.ok = true;
            return;
        case 0x80: case 0x81: case 0x82: case 0x83:
        case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8D: case 0x8E: case 0x8F: {
            s.op = Shape::Op::Jcc;
            s.cond = op2 & 15;
            s.kind = inspect::InsnKind::Jcc;
            std::int32_t rel = 0;
            std::memcpy(&rel, bytes + r.at, 4);
            s.dst = imm_op(static_cast<std::uint64_t>(
                               static_cast<std::int64_t>(va + length) + rel),
                           64, true);
            s.has_dst = true;
            s.ok = true;
            return;
        }
        case 0x40: case 0x41: case 0x42: case 0x43:
        case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4A: case 0x4B:
        case 0x4C: case 0x4D: case 0x4E: case 0x4F:
        case 0x90: case 0x91: case 0x92: case 0x93:
        case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99: case 0x9A: case 0x9B:
        case 0x9C: case 0x9D: case 0x9E: case 0x9F: {
            const std::uint8_t modrm = bytes[r.at];
            const bool is_set = op2 >= 0x90;
            const unsigned width = is_set ? 8 : op_width;
            s.op = is_set ? Shape::Op::Setcc : Shape::Op::Cmov;
            s.cond = op2 & 15;
            ++r.at;
            if (is_set) {
                s.dst = read_rm(r, modrm, px, width, va, length);
                s.has_dst = true;
            } else {
                s.dst = reg_op(static_cast<std::uint8_t>(((modrm >> 3) & 7) |
                                                         (px.rex_r ? 8 : 0)),
                               width);
                s.src = read_rm(r, modrm, px, width, va, length);
                s.has_dst = s.has_src = true;
            }
            s.width = width;
            s.ok = true;
            return;
        }
        case 0xA3:
        case 0xAB:
        case 0xB3:
        case 0xBB: {
            // bt / bts / btr / btc with the bit index in a register.
            const std::uint8_t modrm = bytes[r.at];
            s.op = op2 == 0xA3 ? Shape::Op::Bt
                 : op2 == 0xAB ? Shape::Op::Bts
                 : op2 == 0xB3 ? Shape::Op::Btr
                               : Shape::Op::Btc;
            ++r.at;
            s.dst = read_rm(r, modrm, px, op_width, va, length);
            s.src = reg_op(static_cast<std::uint8_t>(((modrm >> 3) & 7) |
                                                     (px.rex_r ? 8 : 0)),
                           op_width);
            s.has_dst = s.has_src = true;
            s.width = op_width;
            s.ok = true;
            return;
        }
        case 0xA4:
        case 0xA5:
        case 0xAC:
        case 0xAD: {
            // shld / shrd r/m, r, imm8 (A4/AC) or CL (A5/AD).
            const std::uint8_t modrm = bytes[r.at];
            s.op = (op2 == 0xA4 || op2 == 0xA5) ? Shape::Op::Shld
                                                : Shape::Op::Shrd;
            ++r.at;
            s.dst = read_rm(r, modrm, px, op_width, va, length);
            s.src = reg_op(static_cast<std::uint8_t>(((modrm >> 3) & 7) |
                                                     (px.rex_r ? 8 : 0)),
                           op_width);
            s.has_dst = s.has_src = true;
            s.width = op_width;
            if (op2 == 0xA4 || op2 == 0xAC) {
                s.count = r.u8();
            } else {
                s.count_is_cl = true;
            }
            s.ok = true;
            return;
        }
        case 0xBA: {
            // bt / bts / btr / btc r/m, imm8: the /4../7 group.
            const std::uint8_t modrm = bytes[r.at];
            const std::uint8_t sub = (modrm >> 3) & 7;
            if (sub < 4) {
                return;
            }
            s.op = sub == 4 ? Shape::Op::Bt
                 : sub == 5 ? Shape::Op::Bts
                 : sub == 6 ? Shape::Op::Btr
                            : Shape::Op::Btc;
            ++r.at;
            s.dst = read_rm(r, modrm, px, op_width, va, length);
            s.src = imm_op(r.u8(), 8, false);
            s.has_dst = s.has_src = true;
            s.width = op_width;
            s.ok = true;
            return;
        }
        case 0xBC:
        case 0xBD: {
            // bsf / bsr: the source is scanned bit by bit, so the model
            // is a select chain over the bits, built in the interpreter.
            const std::uint8_t modrm = bytes[r.at];
            s.op = op2 == 0xBC ? Shape::Op::Bsf : Shape::Op::Bsr;
            s.dst = reg_op(static_cast<std::uint8_t>(((modrm >> 3) & 7) |
                                                     (px.rex_r ? 8 : 0)),
                           op_width);
            ++r.at;
            s.src = read_rm(r, modrm, px, op_width, va, length);
            s.has_dst = s.has_src = true;
            s.width = op_width;
            s.ok = true;
            return;
        }
        case 0xC0:
        case 0xC1: {
            // xadd r/m, r: exchange, add, and leave the original value
            // in the register.
            const std::uint8_t modrm = bytes[r.at];
            const unsigned width = op2 == 0xC0 ? 8u : op_width;
            s.op = Shape::Op::Xadd;
            ++r.at;
            s.dst = read_rm(r, modrm, px, width, va, length);
            s.src = reg_op(static_cast<std::uint8_t>(((modrm >> 3) & 7) |
                                                     (px.rex_r ? 8 : 0)),
                           width);
            s.has_dst = s.has_src = true;
            s.width = width;
            s.ok = true;
            return;
        }
        case 0xC8: case 0xC9: case 0xCA: case 0xCB:
        case 0xCC: case 0xCD: case 0xCE: case 0xCF: {
            // bswap r32 / r64: no ModRM, the register is in the low
            // three bits of the opcode.
            s.op = Shape::Op::Bswap;
            s.dst = reg_op(static_cast<std::uint8_t>((op2 & 7) |
                                                     (px.rex_b ? 8 : 0)),
                           px.rex_w ? 64u : 32u);
            s.has_dst = true;
            s.width = px.rex_w ? 64u : 32u;
            s.ok = true;
            return;
        }
        case 0xAF: {
            const std::uint8_t modrm = bytes[r.at];
            s.op = Shape::Op::Imul;
            s.dst = reg_op(static_cast<std::uint8_t>(((modrm >> 3) & 7) |
                                                     (px.rex_r ? 8 : 0)),
                           op_width);
            ++r.at;
            s.src = read_rm(r, modrm, px, op_width, va, length);
            s.has_dst = s.has_src = true;
            s.width = op_width;
            s.ok = true;
            return;
        }
        case 0xB6:
        case 0xB7:
        case 0xBE:
        case 0xBF: {
            const std::uint8_t modrm = bytes[r.at];
            const bool is_movzx = op2 == 0xB6 || op2 == 0xB7;
            const unsigned src_width = (op2 == 0xB6 || op2 == 0xBE) ? 8 : 16;
            s.op = is_movzx ? Shape::Op::Movzx : Shape::Op::Movsx;
            s.dst = reg_op(static_cast<std::uint8_t>(((modrm >> 3) & 7) |
                                                     (px.rex_r ? 8 : 0)),
                           op_width);
            ++r.at;
            s.src = read_rm(r, modrm, px, src_width, va, length);
            s.has_dst = s.has_src = true;
            s.width = op_width;
            s.ok = true;
            return;
        }
        default:
            return;
        }
    }
}

// ------------------------------------------------------- model inputs

}  // namespace

expr::Id Model::input_slot(std::int64_t disp) {
    for (std::size_t i = 0; i < inputs.size(); ++i) {
        if (inputs[i].kind == Input::Kind::Slot && inputs[i].disp == disp &&
            inputs[i].width == 64) {
            return inputs[i].id;
        }
    }
    char b[40];
    std::snprintf(b, sizeof(b), "vst[%+lld]", static_cast<long long>(disp));
    Input in;
    in.kind = Input::Kind::Slot;
    in.name = b;
    in.disp = disp;
    in.width = 64;
    in.id = dag.input(in.name, in.width);
    inputs.push_back(in);
    return in.id;
}

expr::Id Model::input_code(std::int64_t disp, unsigned width) {
    for (std::size_t i = 0; i < inputs.size(); ++i) {
        if (inputs[i].kind == Input::Kind::Code && inputs[i].disp == disp &&
            inputs[i].width == width) {
            return inputs[i].id;
        }
    }
    char b[40];
    std::snprintf(b, sizeof(b), "code[%+lld]", static_cast<long long>(disp));
    Input in;
    in.kind = Input::Kind::Code;
    in.name = b;
    in.disp = disp;
    in.width = width;
    in.id = dag.input(in.name, in.width);
    inputs.push_back(in);
    return in.id;
}

expr::Id Model::input_image(std::uint64_t va, unsigned width) {
    for (std::size_t i = 0; i < inputs.size(); ++i) {
        if (inputs[i].kind == Input::Kind::Image && inputs[i].va == va &&
            inputs[i].width == width) {
            return inputs[i].id;
        }
    }
    char b[40];
    std::snprintf(b, sizeof(b), "img[0x%llx]",
                  static_cast<unsigned long long>(va));
    Input in;
    in.kind = Input::Kind::Image;
    in.name = b;
    in.va = va;
    in.width = width;
    in.id = dag.input(in.name, in.width);
    inputs.push_back(in);
    return in.id;
}

expr::Id Model::input_reg(const std::string& reg) {
    for (std::size_t i = 0; i < inputs.size(); ++i) {
        if (inputs[i].kind == Input::Kind::Reg && inputs[i].name == reg) {
            return inputs[i].id;
        }
    }
    Input in;
    in.kind = Input::Kind::Reg;
    in.name = reg;
    in.width = 64;
    in.id = dag.input(in.name, in.width);
    inputs.push_back(in);
    return in.id;
}

expr::Id Model::input_load(expr::Id addr, unsigned width) {
    for (std::size_t i = 0; i < inputs.size(); ++i) {
        if (inputs[i].kind == Input::Kind::Load && inputs[i].addr == addr &&
            inputs[i].width == width) {
            return inputs[i].id;
        }
    }
    Input in;
    in.kind = Input::Kind::Load;
    in.addr = addr;
    in.width = width;
    // The name is the address as the report renders it -- or the slot it
    // is, when the address is the register file indexed. The machine
    // thinks in slots, so the model reads the way the machine does.
    in.name = address_label(*this, addr, width);
    in.id = dag.input(in.name, in.width);
    inputs.push_back(in);
    return in.id;
}

expr::Id Model::input_unknown(const std::string& hint) {
    Input in;
    in.kind = Input::Kind::Unknown;
    in.width = 64;
    char b[64];
    std::snprintf(b, sizeof(b), "unk[%s]#%zu", hint.c_str(), inputs.size());
    in.name = b;
    in.id = dag.input(in.name, in.width);
    inputs.push_back(in);
    return in.id;
}

namespace {

// ------------------------------------------------------------ values

enum class BinOp { Add, Sub, And, Or, Xor, Mul, Shl, Shr, Sar };
enum class CmpOp { Eq, Ult, Slt };

Value mk_value(expr::DAG& dag, expr::Id id) {
    Value v;
    if (id == expr::kNoId) {
        return v;
    }
    const expr::Node& n = dag.node(id);
    if (n.op == expr::Op::Const) {
        v.kind = Value::Kind::Const;
        v.imm = n.imm;
        return v;
    }
    v.kind = Value::Kind::Sym;
    v.id = id;
    return v;
}

Value value_const(std::uint64_t v) {
    Value out;
    out.kind = Value::Kind::Const;
    out.imm = v;
    return out;
}

std::uint64_t width_mask(unsigned width) {
    return width >= 64 ? ~std::uint64_t{0}
                       : (std::uint64_t{1} << width) - 1;
}

// The eight-byte-aligned displacement a stack access's bytes belong to;
// the virtual stack is addressed a byte at a time, so an access at any
// displacement is the norm, not the exception.
std::int64_t aligned_displacement(std::int64_t d) {
    return d >= 0 ? (d / 8) * 8 : -(((-d) + 7) / 8) * 8;
}

// The abstract machine: a register file, the virtual stack's bytes, the
// bytecode words it has read, the flags, and the arithmetic over them.
struct Machine {
    Model* m = nullptr;
    std::map<std::string, Value> regs;
    std::map<std::int64_t, Value> code;
    Value flags[6];  // cf zf sf of pf af
    // True when the walk met something that could have written memory the
    // model does not track: an instruction the decoder does not render, a
    // store through an address it cannot name. Everything the model held
    // about the stack is dropped and every byte read from then on that no
    // later write put there is an unknown of its own. An approximation,
    // but one that only ever turns known into unknown -- it never claims
    // a byte it has no right to.
    bool memory_tainted = false;
    std::map<std::int64_t, expr::Id> tainted_bytes;

    // `incomplete` says the model is not claimed exact. Only a hazard --
    // something that stops the walk or cannot be expressed -- sets it.
    // Everything else is a note: the walk continued and what it could not
    // determine became unknown values, which the checker counts as
    // unverifiable rather than letting them pass for known.
    bool incomplete = false;
    struct Note {
        std::string text;
        bool blocking = false;
    };
    std::vector<Note> notes;
    // The bare reasons, for telling whether one has been recorded already;
    // `notes` carries the same strings with the address attached.
    std::vector<std::string> note_keys;
    // The instruction the notes are about; set by the walk before each
    // step so a note names the address it came from rather than being an
    // anonymous complaint.
    std::uint64_t cur_va = 0;

    // The entry values of the two pointers the virtual state hangs off,
    // remembered so a slot displacement can be understood relative to
    // the entry rbp.
    expr::Id entry_rbp = expr::kNoId;
    expr::Id entry_rsi = expr::kNoId;

    [[nodiscard]] expr::Id id_of(const Value& v) {
        switch (v.kind) {
        case Value::Kind::Unknown:
            return expr::kNoId;
        case Value::Kind::Const:
            return m->dag.constant(v.imm, 64);
        case Value::Kind::Sym:
            return v.id;
        }
        return expr::kNoId;
    }

    // A fresh unbound input standing for a value the model cannot know.
    // Every use makes its own, so two unknowns are never mistaken for
    // the same one.
    [[nodiscard]] Value unknown_value(const std::string& hint) {
        return mk_value(m->dag, m->input_unknown(hint));
    }

    [[nodiscard]] Value trunc(const Value& v, unsigned width) {
        if (v.kind == Value::Kind::Unknown || width >= 64) {
            return v;
        }
        if (v.kind == Value::Kind::Const) {
            return value_const(v.imm & width_mask(width));
        }
        return mk_value(m->dag, m->dag.resize(v.id, width));
    }

    [[nodiscard]] Value zext(const Value& v, unsigned width) {
        if (v.kind == Value::Kind::Unknown) {
            return v;
        }
        return mk_value(m->dag, m->dag.resize(id_of(v), width));
    }

    [[nodiscard]] Value bin(BinOp op, unsigned width, const Value& a,
                            const Value& b) {
        if (a.kind == Value::Kind::Unknown || b.kind == Value::Kind::Unknown) {
            return Value{};
        }
        const Value x = trunc(a, width);
        const Value y = trunc(b, width);
        const expr::Id xi = id_of(x);
        const expr::Id yi = id_of(y);
        expr::Id r = expr::kNoId;
        switch (op) {
        case BinOp::Add: r = m->dag.add(xi, yi); break;
        case BinOp::Sub: r = m->dag.sub(xi, yi); break;
        case BinOp::And: r = m->dag.bit_and(xi, yi); break;
        case BinOp::Or:  r = m->dag.bit_or(xi, yi); break;
        case BinOp::Xor: r = m->dag.bit_xor(xi, yi); break;
        case BinOp::Mul: r = m->dag.mul(xi, yi); break;
        case BinOp::Shl: r = m->dag.shl(xi, yi); break;
        case BinOp::Shr: r = m->dag.shr(xi, yi); break;
        case BinOp::Sar: r = m->dag.sar(xi, yi); break;
        }
        return mk_value(m->dag, m->dag.resize(r, width));
    }

    [[nodiscard]] Value cmp(CmpOp op, unsigned width, const Value& a,
                            const Value& b) {
        if (a.kind == Value::Kind::Unknown || b.kind == Value::Kind::Unknown) {
            return Value{};
        }
        const Value x = trunc(a, width);
        const Value y = trunc(b, width);
        const expr::Id xi = id_of(x);
        const expr::Id yi = id_of(y);
        switch (op) {
        case CmpOp::Eq:  return mk_value(m->dag, m->dag.cmp_eq(xi, yi));
        case CmpOp::Ult: return mk_value(m->dag, m->dag.cmp_ult(xi, yi));
        case CmpOp::Slt: return mk_value(m->dag, m->dag.cmp_slt(xi, yi));
        }
        return Value{};
    }

    [[nodiscard]] Value neg_of(unsigned width, const Value& a) {
        if (a.kind == Value::Kind::Unknown) {
            return Value{};
        }
        return mk_value(m->dag, m->dag.resize(
                                    m->dag.neg(id_of(trunc(a, width))), width));
    }

    [[nodiscard]] Value not_of(unsigned width, const Value& a) {
        if (a.kind == Value::Kind::Unknown) {
            return Value{};
        }
        return mk_value(
            m->dag,
            m->dag.resize(m->dag.bit_not(id_of(trunc(a, width))), width));
    }

    [[nodiscard]] Value bit(unsigned width, const Value& a, unsigned index) {
        if (a.kind == Value::Kind::Unknown) {
            return Value{};
        }
        const expr::Id shifted =
            m->dag.shr(id_of(trunc(a, width)), m->dag.constant(index, width));
        return mk_value(m->dag, m->dag.resize(shifted, 1));
    }

    [[nodiscard]] Value rotate(unsigned width, const Value& a,
                               unsigned amount, bool right) {
        const unsigned k = amount % width;
        if (k == 0) {
            return trunc(a, width);
        }
        if (a.kind == Value::Kind::Unknown) {
            return Value{};
        }
        const Value x = trunc(a, width);
        const Value kk = value_const(k);
        const Value ww = value_const(width - k);
        if (!right) {
            return bin(BinOp::Or, width, bin(BinOp::Shl, width, x, kk),
                       bin(BinOp::Shr, width, x, ww));
        }
        return bin(BinOp::Or, width, bin(BinOp::Shr, width, x, kk),
                   bin(BinOp::Shl, width, x, ww));
    }

    // A rotate whose amount is not known at analysis time. The result is
    // exactly expressible after all: the hardware masks the count to the
    // width's bit count, and the two shifts a rotate is made of compose
    // with a symbolic amount as readily as with a literal one. A masked
    // count of zero shifts by zero and by the full width, and the second
    // of those folds to zero, so the zero case needs no select.
    [[nodiscard]] Value rotate_by(unsigned width, const Value& a,
                                  const Value& count, bool right) {
        if (a.kind == Value::Kind::Unknown ||
            count.kind == Value::Kind::Unknown) {
            return Value{};
        }
        const Value x = trunc(a, width);
        const Value k = bin(BinOp::And, width, trunc(count, width),
                            value_const(width - 1));
        const Value back = bin(BinOp::Sub, width, value_const(width), k);
        if (right) {
            return bin(BinOp::Or, width, bin(BinOp::Shr, width, x, k),
                       bin(BinOp::Shl, width, x, back));
        }
        return bin(BinOp::Or, width, bin(BinOp::Shl, width, x, k),
                   bin(BinOp::Shr, width, x, back));
    }

    // One bit of an rcl/rcr: the value and the carry after a single
    // step, which is the ring the instruction rotates through unrolled
    // one bit at a time.
    void rotate_carry_step(unsigned width, bool left, Value* x, Value* cf) {
        const Value edge = bit(width, *x, left ? width - 1 : 0);
        if (left) {
            *x = bin(BinOp::Or, width,
                     bin(BinOp::Shl, width, *x, value_const(1)),
                     zext(*cf, width));
        } else {
            *x = bin(BinOp::Or, width,
                     bin(BinOp::Shr, width, *x, value_const(1)),
                     bin(BinOp::Shl, width, zext(*cf, width),
                         value_const(width - 1)));
        }
        *cf = edge;
    }

    // The value and the carry after an rcl/rcr whose count may be
    // computed. The count is masked by the caller. The instruction
    // rotates through a ring one bit wider than the operand -- the carry
    // is a bit of it -- and `width + 1` steps of the unrolled form come
    // back to where they started, so stepping the masked count of times
    // is exact for every count. A computed count selects between the
    // arms, one per count the mask can produce.
    void rotate_carry(unsigned width, bool left, const Value& x,
                      const Value& cf, const Value& masked, bool symbolic,
                      Value* out_x, Value* out_cf) {
        Value vx = trunc(x, width);
        Value vcf = trunc(cf, 1);
        if (!symbolic) {
            const unsigned n = static_cast<unsigned>(masked.imm);
            for (unsigned step = 0; step < n; ++step) {
                rotate_carry_step(width, left, &vx, &vcf);
            }
            *out_x = vx;
            *out_cf = vcf;
            return;
        }
        Value accx = vx;
        Value accf = vcf;
        const unsigned mask = width == 64 ? 0x3F : 0x1F;
        for (unsigned arm = 1; arm <= mask; ++arm) {
            rotate_carry_step(width, left, &vx, &vcf);
            const Value cond = cmp(CmpOp::Eq, 8, masked, value_const(arm));
            accx = select_of(width, cond, vx, accx);
            accf = select_of(1, cond, vcf, accf);
        }
        *out_x = accx;
        *out_cf = accf;
    }

    // shld/shrd with the count in hand, masked by the caller. Below the
    // operand width the value is the pair shift the manual defines; at
    // and above it the hardware keeps shifting, the source operand's
    // bits arriving from the other side -- behaviour the manual calls
    // undefined but which the trace was written by, so that branch is
    // modelled too rather than noted away. The count mask keeps the
    // 32- and 64-bit forms inside the defined range; only the 16-bit
    // form can reach the second branch.
    [[nodiscard]] Value double_shift(unsigned width, bool left,
                                     const Value& a, const Value& b,
                                     const Value& count) {
        if (a.kind == Value::Kind::Unknown ||
            b.kind == Value::Kind::Unknown ||
            count.kind == Value::Kind::Unknown) {
            return Value{};
        }
        const Value x = trunc(a, width);
        const Value y = trunc(b, width);
        const Value k = trunc(count, width);
        const Value ww = value_const(width);
        const Value over = bin(BinOp::Sub, width, k, ww);      // k - width
        const Value under = bin(BinOp::Sub, width, ww, k);     // width - k
        const Value twice =
            bin(BinOp::Sub, width, value_const(2 * width), k); // 2w - k
        Value below;
        Value above;
        if (left) {
            below = bin(BinOp::Or, width, bin(BinOp::Shl, width, x, k),
                        bin(BinOp::Shr, width, y, under));
            above = bin(BinOp::Or, width, bin(BinOp::Shl, width, y, over),
                        bin(BinOp::Shr, width, x, twice));
        } else {
            below = bin(BinOp::Or, width, bin(BinOp::Shr, width, x, k),
                        bin(BinOp::Shl, width, y, under));
            above = bin(BinOp::Or, width, bin(BinOp::Shr, width, y, over),
                        bin(BinOp::Shl, width, x, twice));
        }
        return select_of(width, cmp(CmpOp::Ult, width, k, ww), below, above);
    }

    // `c ? a : b` at `width`. The condition is resized to a bit and the
    // arms to the width, so a one-bit test and a 64-bit value can select
    // each other.
    [[nodiscard]] Value select_of(unsigned width, const Value& c,
                                  const Value& a, const Value& b) {
        if (c.kind == Value::Kind::Unknown || a.kind == Value::Kind::Unknown ||
            b.kind == Value::Kind::Unknown) {
            return Value{};
        }
        if (c.kind == Value::Kind::Const) {
            return trunc(c.imm != 0 ? a : b, width);
        }
        const expr::Id ci = m->dag.resize(id_of(c), 1);
        const expr::Id ai = m->dag.resize(id_of(a), width);
        const expr::Id bi = m->dag.resize(id_of(b), width);
        return mk_value(m->dag, m->dag.resize(m->dag.select(ci, ai, bi), width));
    }

    [[nodiscard]] Value sign_extend(unsigned src_width, const Value& a) {
        if (a.kind == Value::Kind::Unknown) {
            return Value{};
        }
        if (src_width >= 64) {
            return a;
        }
        const std::uint64_t sign_bit = std::uint64_t{1} << (src_width - 1);
        const Value x = trunc(a, src_width);
        const Value xm =
            bin(BinOp::Xor, 64, zext(x, 64), value_const(sign_bit));
        return bin(BinOp::Sub, 64, xm, value_const(sign_bit));
    }

    [[nodiscard]] Value reg_read(const std::string& name) {
        const auto it = regs.find(name);
        if (it != regs.end()) {
            return it->second;
        }
        const Value v = mk_value(m->dag, m->input_reg(name));
        regs[name] = v;
        // The two pointers the virtual state hangs off are the registers
        // the model's convention assigns to the stack and the cursor.
        // Reading either one for the first time names it as the entry
        // value the slot and code displacements are relative to.
        if (name == m->convention.stack) {
            entry_rbp = id_of(v);
        } else if (name == m->convention.cursor) {
            entry_rsi = id_of(v);
        }
        return v;
    }

    void reg_write(const std::string& name, const Value& v) { regs[name] = v; }

    // The virtual stack's bytes, displacement by displacement. Byte
    // granular because the accesses overlap at arbitrary offsets -- the
    // junk writes a qword at one displacement and reads a dword at
    // another that shares four of its bytes -- and a read through one
    // access has to see what a write through the other left there. A
    // cell-granular file cannot: it would hand back the entry value for
    // the overlapping half, which is a stale number that looks right.
    //
    // Each byte remembers where it came from: the value it was cut out
    // of and its index in it. The provenance is what lets a cell be
    // reported as "(the bytes that were there, low half) and (this value,
    // shifted in)" instead of as eight separate shift-and-mask terms.
    struct StackByte {
        Value v;
        expr::Id src = expr::kNoId;
        unsigned off = 0;
    };
    std::map<std::int64_t, StackByte> stack_bytes;

    // The index-th byte of a value, as an eight-bit value.
    [[nodiscard]] Value byte_of(const Value& v, unsigned index) {
        if (v.kind == Value::Kind::Unknown) {
            return Value{};
        }
        const Value x = trunc(v, 64);
        if (index == 0) {
            return trunc(x, 8);
        }
        return trunc(
            mk_value(m->dag, m->dag.shr(id_of(x),
                                       m->dag.constant(8u * index, 64))),
            8);
    }

    [[nodiscard]] Value byte_read(std::int64_t disp) {
        expr::Id src = expr::kNoId;
        unsigned off = 0;
        byte_source(disp, &src, &off);
        return byte_of(mk_value(m->dag, src), off);
    }

    // Where a byte came from: the value it is a byte of, and its index
    // in that value. A byte no write put there is the entry byte -- unless
    // something since then could have written memory, in which case it is
    // an unknown of its own, one per displacement so two reads of it at
    // least agree.
    void byte_source(std::int64_t disp, expr::Id* src, unsigned* off) {
        const auto it = stack_bytes.find(disp);
        if (it != stack_bytes.end()) {
            *src = it->second.src;
            *off = it->second.off;
            return;
        }
        if (memory_tainted) {
            const auto known = tainted_bytes.find(disp);
            if (known != tainted_bytes.end()) {
                *src = known->second;
            } else {
                const Value v = unknown_value("byte");
                *src = id_of(v);
                tainted_bytes.emplace(disp, *src);
            }
            *off = 0;
            return;
        }
        const std::int64_t base = aligned_displacement(disp);
        *src = m->input_slot(base);
        *off = static_cast<unsigned>(disp - base);
    }

    // Something on this path could have written memory the model does not
    // track. What it held about the stack is no longer trustworthy, so
    // none of it is kept.
    void taint_memory() {
        memory_tainted = true;
        stack_bytes.clear();
    }

    void byte_write(std::int64_t disp, const Value& v, expr::Id src,
                    unsigned off) {
        StackByte b;
        b.v = trunc(v, 8);
        b.src = src;
        b.off = off;
        stack_bytes[disp] = b;
    }

    // The value of a run of stack bytes, as an expression: runs of bytes
    // that came from the same place are one term rather than one term per
    // byte, so a read that meets bytes a write put there gets that
    // write's value back -- a whole cell reads as the expression that was
    // stored, not as a byte-by-byte reconstruction of it.
    [[nodiscard]] Value range_read(std::int64_t disp, unsigned width) {
        Value acc = value_const(0);
        const unsigned count = width / 8;
        for (unsigned i = 0; i < count;) {
            expr::Id src = expr::kNoId;
            unsigned off = 0;
            byte_source(disp + static_cast<std::int64_t>(i), &src, &off);
            unsigned len = 1;
            while (i + len < count) {
                expr::Id s2 = expr::kNoId;
                unsigned o2 = 0;
                byte_source(disp + static_cast<std::int64_t>(i + len), &s2,
                            &o2);
                if (s2 != src || o2 != off + len) {
                    break;
                }
                ++len;
            }
            Value term = trunc(mk_value(m->dag, src), 8 * (off + len));
            if (off != 0) {
                term = bin(BinOp::Shr, 8 * (off + len), term,
                           value_const(8u * off));
            }
            term = zext(term, 64);
            if (i != 0) {
                term = bin(BinOp::Shl, 64, term, value_const(8u * i));
            }
            acc = bin(BinOp::Or, 64, acc, term);
            i += len;
        }
        return acc;
    }

    [[nodiscard]] Value mem_read(std::int64_t disp, unsigned width) {
        return range_read(disp, width);
    }

    void mem_write(std::int64_t disp, unsigned width, const Value& v) {
        const expr::Id src = id_of(v);
        for (unsigned i = 0; i < width / 8; ++i) {
            byte_write(disp + i, byte_of(v, i), src, i);
        }
    }

    // A read through an address that is not one of the forms the model
    // places: `mov rax, [rcx]` with rcx off the stack. The value becomes
    // a load input keyed by the address expression, so the model says
    // exactly what it read and from where, and the trace check can look
    // the bytes up. An address the model cannot even name leaves the
    // value an unknown of its own.
    [[nodiscard]] Value load_read(const Value& addr, unsigned width) {
        if (addr.kind == Value::Kind::Unknown) {
            return unknown_value("mem");
        }
        return mk_value(m->dag, m->input_load(id_of(addr), width));
    }

    [[nodiscard]] Value code_read(std::int64_t disp, unsigned width) {
        const auto it = code.find(disp);
        if (it != code.end() && it->second.kind != Value::Kind::Unknown) {
            return it->second;
        }
        // The bytecode is byte-addressed and read at whatever width the
        // instruction asks for, so the value is composed out of 8-bit
        // inputs, little endian. That is what makes a dword read and a
        // qword read of the same bytes agree, and what lets the trace
        // check bind both from the image bytes.
        Value acc = value_const(0);
        for (unsigned i = 0; i < width / 8; ++i) {
            const Value byte =
                mk_value(m->dag, m->input_code(disp + static_cast<std::int64_t>(i), 8));
            const Value wide = zext(byte, 64);
            const Value shifted =
                i == 0 ? wide
                       : bin(BinOp::Shl, 64, wide, value_const(8u * i));
            acc = bin(BinOp::Or, 64, acc, shifted);
        }
        code[disp] = acc;
        return acc;
    }

    [[nodiscard]] Value image_read(std::uint64_t va, unsigned width) {
        const auto it = code.find(-static_cast<std::int64_t>(va) - 2);
        if (it != code.end() && it->second.kind != Value::Kind::Unknown) {
            return it->second;
        }
        Value acc = value_const(0);
        for (unsigned i = 0; i < width / 8; ++i) {
            const Value byte =
                mk_value(m->dag, m->input_image(va + i, 8));
            const Value wide = zext(byte, 64);
            const Value shifted =
                i == 0 ? wide
                       : bin(BinOp::Shl, 64, wide, value_const(8u * i));
            acc = bin(BinOp::Or, 64, acc, shifted);
        }
        code[-static_cast<std::int64_t>(va) - 2] = acc;
        return acc;
    }

    // Records what the walk met, once per kind. A note is informational: the
    // walk handled it -- by turning a value into an unknown of its own, by
    // following both edges of a branch -- and the model is still exact in
    // the sense that it never claims more than it knows. A hazard is
    // different: it means the model is not claimed exact, because the walk
    // could not get through or the result could not be expressed.
    void record(const std::string& why, bool blocking) {
        if (blocking) {
            incomplete = true;
        }
        for (const std::string& n : note_keys) {
            if (n == why) {
                return;
            }
        }
        note_keys.push_back(why);
        char b[192];
        std::snprintf(b, sizeof(b), "%s @ 0x%llx", why.c_str(),
                      static_cast<unsigned long long>(cur_va));
        notes.push_back(Note{b, blocking});
    }

    void note(const std::string& why) { record(why, false); }

    void hazard(const std::string& why) { record(why, true); }

    // Takes on the notes another state collected -- the arm of a branch
    // that is now part of this model -- once each.
    void absorb_notes(const Machine& other) {
        for (std::size_t i = 0; i < other.notes.size(); ++i) {
            const std::string& key = other.note_keys[i];
            bool have = false;
            for (const std::string& mine : note_keys) {
                if (mine == key) {
                    have = true;
                    break;
                }
            }
            if (have) {
                continue;
            }
            note_keys.push_back(key);
            notes.push_back(other.notes[i]);
            if (other.notes[i].blocking) {
                incomplete = true;
            }
        }
    }

    // The displacement of an `[rbp+d]` operand relative to the *entry*
    // rbp, so two handlers' writes to the same slot land in the same
    // place. False when rbp has been moved in a way this layer cannot
    // follow.
    [[nodiscard]] bool rbp_slot_disp(std::int64_t disp, std::int64_t* out) {
        const Value cur = reg_read(m->convention.stack);
        const expr::Id cid = id_of(cur);
        if (entry_rbp != expr::kNoId && cid == entry_rbp) {
            *out = disp;
            return true;
        }
        if (cid == expr::kNoId) {
            return false;
        }
        const expr::Node& n = m->dag.node(cid);
        if (n.op == expr::Op::Add && n.a == entry_rbp &&
            m->dag.is_const(n.b)) {
            *out = disp + static_cast<std::int64_t>(m->dag.const_value(n.b));
            return true;
        }
        if (n.op == expr::Op::Sub && n.a == entry_rbp &&
            m->dag.is_const(n.b)) {
            *out = disp - static_cast<std::int64_t>(m->dag.const_value(n.b));
            return true;
        }
        return false;
    }

    [[nodiscard]] bool rsi_cursor_disp(std::int64_t disp, std::int64_t* out) {
        const Value cur = reg_read(m->convention.cursor);
        const expr::Id cid = id_of(cur);
        if (entry_rsi != expr::kNoId && cid == entry_rsi) {
            *out = disp;
            return true;
        }
        if (cid == expr::kNoId) {
            return false;
        }
        const expr::Node& n = m->dag.node(cid);
        if (n.op == expr::Op::Add && n.a == entry_rsi &&
            m->dag.is_const(n.b)) {
            *out = disp + static_cast<std::int64_t>(m->dag.const_value(n.b));
            return true;
        }
        // `sub rsi, 0xffffffffffffffff` is an increment spelled the other
        // way, and the junk uses both spellings.
        if (n.op == expr::Op::Sub && n.a == entry_rsi &&
            m->dag.is_const(n.b)) {
            *out = disp - static_cast<std::int64_t>(m->dag.const_value(n.b));
            return true;
        }
        return false;
    }
};

// The flags after an ALU-shaped operation. `res` is the result, already
// truncated to the operation's width.
void set_flags_arith(Machine& mc, Shape::Op op, unsigned width,
                     const Value& a, const Value& b, const Value& res) {
    const Value zero = value_const(0);
    mc.flags[1] = mc.cmp(CmpOp::Eq, width, res, zero);  // zf
    mc.flags[2] = mc.bit(width, res, width - 1);        // sf
    const Value sa = mc.bit(width, a, width - 1);
    const Value sb = mc.bit(width, b, width - 1);
    const Value sr = mc.bit(width, res, width - 1);
    switch (op) {
    case Shape::Op::Add:
    case Shape::Op::Adc:
        mc.flags[0] = mc.cmp(CmpOp::Ult, width, res, a);  // cf
        mc.flags[3] = mc.bin(BinOp::And, 1,
                             mc.cmp(CmpOp::Eq, 1, sa, sb),
                             mc.cmp(CmpOp::Eq, 1, sr, sb));  // of
        break;
    case Shape::Op::Sub:
    case Shape::Op::Sbb:
    case Shape::Op::Cmp:
        mc.flags[0] = mc.cmp(CmpOp::Ult, width, a, b);
        mc.flags[3] = mc.bin(BinOp::And, 1,
                             mc.bin(BinOp::Xor, 1, sa, sb),
                             mc.bin(BinOp::Xor, 1, sa, sr));
        break;
    case Shape::Op::Inc:
    case Shape::Op::Dec:
        // CF is untouched by inc/dec; OF is defined but nothing here
        // reads it, so it is left as an unknown of its own rather than
        // as a hole -- a later instruction that does read it then still
        // produces an expression instead of swallowing the value.
        mc.flags[3] = mc.unknown_value("of");
        break;
    case Shape::Op::And:
    case Shape::Op::Or:
    case Shape::Op::Xor:
    case Shape::Op::Test:
        mc.flags[0] = zero;
        mc.flags[3] = zero;
        break;
    case Shape::Op::Not:
        // not writes no flags at all.
        break;
    case Shape::Op::Neg:
        mc.flags[0] = mc.cmp(CmpOp::Ult, width, zero, a);
        mc.flags[3] = mc.bin(BinOp::And, 1,
                             mc.bin(BinOp::Xor, 1, value_const(0), sa),
                             mc.bin(BinOp::Xor, 1, value_const(0), sr));
        break;
    default:
        break;
    }
}

Value condition_value(Machine& mc, unsigned cond) {
    Value cf = mc.flags[0];
    const Value zf = mc.flags[1];
    const Value sf = mc.flags[2];
    const Value of = mc.flags[3];
    const auto not1 = [&](const Value& v) { return mc.not_of(1, v); };
    const auto either = [&](const Value& a, const Value& b) {
        return mc.bin(BinOp::Or, 1, a, b);
    };
    switch (cond & 15) {
    case 0x0: return of;                       // o
    case 0x1: return not1(of);                 // no
    case 0x2: return cf;                       // b / c / nae
    case 0x3: return not1(cf);                 // ae / nb / nc
    case 0x4: return zf;                       // e / z
    case 0x5: return not1(zf);                 // ne / nz
    case 0x6: return either(cf, zf);           // be / na
    case 0x7: return not1(either(cf, zf));     // a / nbe
    case 0x8: return sf;                       // s
    case 0x9: return not1(sf);                 // ns
    case 0xA: return mc.flags[4];              // p / pe
    case 0xB: return not1(mc.flags[4]);        // np / po
    case 0xC: return mc.bin(BinOp::Xor, 1, sf, of);            // l / nge
    case 0xD: return not1(mc.bin(BinOp::Xor, 1, sf, of));      // ge / nl
    case 0xE: return either(zf, mc.bin(BinOp::Xor, 1, sf, of));  // le / ng
    default:  return not1(either(zf, mc.bin(BinOp::Xor, 1, sf, of)));  // g
    }
}

// The interpreter: one handler's micro-program, walked with the forks a
// `jcc` produces resolved by merging the two arms back together under the
// branch's own condition.
struct Runner {
    Machine mc;
    const std::uint8_t* bytes = nullptr;
    std::size_t available = 0;
    std::uint64_t base_va = 0;
    // The window's base: bytes[0] maps at this address, and the walk may
    // jump anywhere inside [window_va, window_va + available). A packed
    // handler chains blocks that are scattered through the code section,
    // so the window is a section, not the handler's own bytes.
    std::uint64_t window_va = 0;

    // The host stack, for push/pop. VMProtect's junk saves and restores
    // registers through it (`push rbx ... pop rbx`), so a model that
    // drops the values loses effects that travel through the stack. An
    // entry is a value, or the flags when it came from pushf. When a
    // branch's two arms leave different stacks, the content is unknown
    // rather than guessed: pops then yield unknowns of their own.
    struct HostSlot {
        bool flags = false;
        Value v;
        Value flags_vals[6];
    };
    std::vector<HostSlot> host_stack;
    bool host_unknown = false;

    // The instruction budget is for the whole handler including every arm
    // a branch forks into, not per path: a diamond cannot be walked for
    // free, and a budget that did not count the arms would not bound the
    // work.
    // Where the handlers hand control back (see summarize). The walk
    // stops at the first of these it reaches; null when the caller gave
    // none, so a self-contained handler walks exactly as before.
    const std::vector<std::uint64_t>* boundary = nullptr;
    std::size_t steps = 0;
    std::size_t step_budget = 0;
    // A handler whose branches nest deeper than this is not followed
    // further: the arms would have to be merged pair by pair, and past a
    // point the expression is larger than it is useful.
    static constexpr unsigned kMaxForkDepth = 12;

    // Where one walked path ended.
    struct Exit {
        bool settled = false;
        Handler::Transfer transfer = Handler::Transfer::Unknown;
        expr::Id target = expr::kNoId;
    };

    struct OperandRead {
        bool ok = false;
        Value v;
    };

    // 0..3 for ah/ch/dh/bh, or ~0u for every other register.
    [[nodiscard]] static unsigned high_byte_index(const std::string& name) {
        for (unsigned i = 0; i < 4; ++i) {
            if (name == kHighBytes[i]) {
                return i;
            }
        }
        return 0xFFFFFFFFu;
    }

    // The slot an `[rbp+d]` access belongs to. The virtual register file
    // is addressed a byte at a time, so an access may sit anywhere; this
    // is the eight-byte cell containing it, which is what the inputs are
    // keyed by.
    [[nodiscard]] static std::int64_t slot_floor(std::int64_t d) {
        return aligned_displacement(d);
    }

    // Writes an unknown to whatever the operand names. Used where the
    // decode knows the destination but the value effect is not modelled:
    // leaving the old value in place would let a later instruction read
    // a stale number and look correct, which is worse than unknown.
    void poison(const Operand& o, unsigned width) {
        if (o.kind == Operand::Kind::Reg) {
            mc.reg_write(o.reg, mc.unknown_value(o.reg));
            return;
        }
        if (o.kind == Operand::Kind::Mem &&
            o.base == mc.m->convention.stack && o.index.empty()) {
            std::int64_t slot = 0;
            if (mc.rbp_slot_disp(o.disp, &slot)) {
                for (unsigned i = 0; i < width / 8; ++i) {
                    // One byte, one fresh unknown: the bytes the model
                    // cannot name still have to be *something*, so that
                    // the bytes around them keep their values.
                    const Value b = mc.unknown_value("byte");
                    mc.byte_write(slot + i, b, mc.id_of(b), 0);
                }
            }
        }
    }

    [[nodiscard]] OperandRead read_operand(const Operand& o, unsigned width) {
        OperandRead r;
        switch (o.kind) {
        case Operand::Kind::Reg: {
            const unsigned hi = high_byte_index(o.reg);
            if (hi != 0xFFFFFFFFu) {
                const Value parent = mc.reg_read(kHighParents[hi]);
                const Value shifted =
                    mc.bin(BinOp::Shr, 64, parent, value_const(8));
                r.ok = true;
                r.v = mc.trunc(shifted, 8);
                return r;
            }
            const Value raw = mc.reg_read(o.reg);
            r.ok = true;
            r.v = width >= 64 ? raw : mc.trunc(raw, width);
            return r;
        }
        case Operand::Kind::Imm: {
            r.ok = true;
            r.v = value_const(o.imm & width_mask(width));
            return r;
        }
        case Operand::Kind::Mem: {
            if (o.base == "rip") {
                r.ok = true;
                r.v = mc.image_read(static_cast<std::uint64_t>(o.disp), width);
                return r;
            }
            if (o.base == mc.m->convention.stack && o.index.empty()) {
                std::int64_t slot = 0;
                if (mc.rbp_slot_disp(o.disp, &slot)) {
                    r.ok = true;
                    r.v = mc.mem_read(slot, width);
                    return r;
                }
                // The pointer is no longer a form the slot file names --
                // a branch merged two different movements into it, or an
                // unmodelled instruction clobbered it. The access is
                // still a load at an address the model can write down, so
                // it falls through to the general form below rather than
                // giving up on the byte.
            }
            if (o.base == mc.m->convention.cursor && o.index.empty()) {
                std::int64_t off = 0;
                if (mc.rsi_cursor_disp(o.disp, &off)) {
                    r.ok = true;
                    r.v = mc.code_read(off, width);
                    return r;
                }
                // Same: a cursor the model cannot place is still an
                // address, and the trace's image is where its bytes
                // would come from.
            }
            // Any other memory: the host stack, a table, a computed address.
            // A read through a computed address is a load the model can
            // name even though it cannot know the byte; a read through an
            // address it cannot name leaves the value unknown, which is
            // safe: the trace check reports the predictions that depend
            // on it as unverifiable rather than checking them.
            const Value addr = effective_address(o);
            r.ok = addr.kind != Value::Kind::Unknown;
            r.v = mc.load_read(addr, width);
            return r;
        }
        case Operand::Kind::None:
            break;
        }
        return r;
    }

    // Writes the model could not place in a slot: kept as expressions
    // (the address as well as the value), because a store through a
    // computed address is a real effect -- a virtual store -- even when
    // the address is not a form the slot file names.
    std::vector<Handler::Write> mem_writes;

    // The address an operand names, as an expression. The rip-relative
    // form is an address in the image, which for this layer is a
    // constant.
    [[nodiscard]] Value effective_address(const Operand& o) {
        if (o.base == "rip" || (o.base.empty() && o.index.empty())) {
            return value_const(static_cast<std::uint64_t>(o.disp));
        }
        Value base = o.base.empty() ? value_const(0) : mc.reg_read(o.base);
        if (!o.index.empty()) {
            Value idx = mc.reg_read(o.index);
            if (o.scale != 1) {
                idx = mc.bin(BinOp::Mul, 64, idx,
                             value_const(static_cast<std::uint64_t>(o.scale)));
            }
            base = mc.bin(BinOp::Add, 64, base, idx);
        }
        return mc.bin(BinOp::Add, 64, base,
                      value_const(static_cast<std::uint64_t>(o.disp)));
    }

    void write_operand(const Operand& o, unsigned width, const Value& v) {
        switch (o.kind) {
        case Operand::Kind::Reg: {
            const unsigned hi = high_byte_index(o.reg);
            if (hi != 0xFFFFFFFFu) {
                // ah/ch/dh/bh are bits 8..15 of the parent register; the
                // write leaves the other bits alone.
                const Value old = mc.reg_read(kHighParents[hi]);
                const Value narrow = mc.trunc(v, 8);
                const Value kept = mc.bin(BinOp::And, 64, old,
                                          value_const(~0xFF00ULL));
                const Value placed = mc.bin(BinOp::Shl, 64,
                                            mc.zext(narrow, 64),
                                            value_const(8));
                mc.reg_write(kHighParents[hi],
                             mc.bin(BinOp::Or, 64, kept, placed));
                return;
            }
            const Value old = mc.reg_read(o.reg);
            Value stored = v;
            if (width < 32) {
                // Sub-width writes keep the rest of the register. The
                // blend needs the old value; a register the model cannot
                // name is an unknown of its own (never a hole), so the
                // blend stays an expression.
                const Value narrow = mc.trunc(v, width);
                const Value kept = mc.bin(
                    BinOp::And, 64, old, value_const(~width_mask(width)));
                stored = mc.bin(BinOp::Or, 64, kept, mc.zext(narrow, 64));
            } else if (width == 32) {
                stored = mc.zext(mc.trunc(v, 32), 64);
            } else {
                stored = mc.trunc(v, 64);
            }
            mc.reg_write(o.reg, stored);
            return;
        }
        case Operand::Kind::Mem: {
            if (o.base == mc.m->convention.stack && o.index.empty()) {
                std::int64_t slot = 0;
                if (mc.rbp_slot_disp(o.disp, &slot)) {
                    mc.mem_write(slot, width, v);
                    return;
                }
                // The pointer is not a form the slot file names, but the
                // write is still a store at an address the model can
                // write down: it is recorded as a computed-address write
                // below rather than hidden.
            }
            // A write through an address that is not a slot: a virtual store
            // (`mov [rax], rdx` with rax off the stack). The effect is a
            // real one and both halves of it are expressions, so it is
            // recorded rather than noted away. An address the model
            // cannot name is the one case that stays approximate: the
            // write could have landed anywhere, so nothing the model held
            // about memory is kept.
            Handler::Write mw;
            mw.to_slot = false;
            mw.width = width;
            const Value addr = effective_address(o);
            mw.addr = mc.id_of(addr);
            mw.value = mc.id_of(v);
            mem_writes.push_back(mw);
            if (addr.kind == Value::Kind::Unknown) {
                mc.note("a store through an address the model cannot name");
                mc.taint_memory();
            }
            return;
        }
        case Operand::Kind::Imm:
        case Operand::Kind::None:
            return;
        }
    }

    // Merges the arm that took a branch -- the state machine, its writes and
    // its host stack -- into the state the fall-through arm left, under the
    // branch's condition. Every value the two arms disagree about becomes
    // `cond ? taken : fall`, so the model says what happens whichever way
    // the branch goes; the checker, which can evaluate the condition from
    // the trace, follows the arm that actually ran and never leans on the
    // other one's unknowns.
    void merge_arm(Machine& taken_state,
                   const std::vector<Handler::Write>& taken_writes,
                   const std::vector<HostSlot>& taken_stack, bool taken_host,
                   const Exit& taken_exit, const Exit& fall_exit,
                   const Value& cond) {
        expr::DAG& dag = mc.m->dag;
        const auto entry_value = [&](const Machine& m,
                                     const std::string& name) {
            const auto it = m.regs.find(name);
            if (it != m.regs.end()) {
                return it->second;
            }
            return mk_value(dag, m.m->input_reg(name));
        };

        // Registers: the union of what either arm touched. One arm leaving
        // a register alone means its value is the one the handler was
        // entered with, which is exactly what the other arm's `regs` entry
        // is compared against.
        std::vector<std::string> names;
        for (const auto& [name, value] : mc.regs) {
            names.push_back(name);
        }
        for (const auto& [name, value] : taken_state.regs) {
            if (mc.regs.find(name) == mc.regs.end()) {
                names.push_back(name);
            }
        }
        for (const std::string& name : names) {
            const Value a = entry_value(taken_state, name);
            const Value b = entry_value(mc, name);
            mc.reg_write(name, mc.select_of(64, cond, a, b));
        }
        // The two arms were entered together, so the pointers the handler was
        // entered with are the same inputs in both. An arm that never read
        // one -- because the first thing it did was clobber it -- names it
        // now, so the displacements below are comparable across the two.
        const auto name_entry = [](Machine& m) {
            if (m.entry_rbp == expr::kNoId) {
                m.entry_rbp = m.m->input_reg(m.m->convention.stack);
            }
            if (m.entry_rsi == expr::kNoId) {
                m.entry_rsi = m.m->input_reg(m.m->convention.cursor);
            }
        };
        name_entry(mc);
        name_entry(taken_state);
        if (mc.entry_rbp != taken_state.entry_rbp ||
            mc.entry_rsi != taken_state.entry_rsi) {
            mc.hazard("the two arms of a branch disagree about the entry");
            return;
        }

        // Flags.
        for (int i = 0; i < 6; ++i) {
            mc.flags[i] =
                mc.select_of(1, cond, taken_state.flags[i], mc.flags[i]);
        }

        // The stack's bytes. A byte only one arm wrote is, in the other
        // arm, what was already there -- which the byte's own source says,
        // so the merge is the same select either way.
        std::vector<std::int64_t> disps;
        for (const auto& [disp, byte] : mc.stack_bytes) {
            disps.push_back(disp);
        }
        for (const auto& [disp, byte] : taken_state.stack_bytes) {
            if (mc.stack_bytes.find(disp) == mc.stack_bytes.end()) {
                disps.push_back(disp);
            }
        }
        for (const std::int64_t disp : disps) {
            const Value a = taken_state.byte_read(disp);
            const Value b = mc.byte_read(disp);
            const Value merged = mc.select_of(8, cond, a, b);
            const auto ia = taken_state.stack_bytes.find(disp);
            const auto ib = mc.stack_bytes.find(disp);
            const bool same_source =
                ia != taken_state.stack_bytes.end() &&
                ib != mc.stack_bytes.end() && ia->second.src == ib->second.src &&
                ia->second.off == ib->second.off;
            if (same_source) {
                mc.byte_write(disp, merged, ib->second.src, ib->second.off);
            } else {
                // The byte is the select itself and comes from no single
                // value; it is its own one-byte source.
                mc.byte_write(disp, merged, mc.id_of(merged), 0);
            }
        }
        mc.memory_tainted =
            mc.memory_tainted || taken_state.memory_tainted;
        for (const auto& [disp, id] : taken_state.tainted_bytes) {
            mc.tainted_bytes.emplace(disp, id);
        }

        // The host stack: merges entry by entry when the arms agree about
        // its shape, and becomes unknown when they do not.
        const bool same_shape =
            !taken_host && !host_unknown &&
            taken_stack.size() == host_stack.size();
        bool shape_ok = same_shape;
        if (same_shape) {
            for (std::size_t i = 0; i < host_stack.size(); ++i) {
                if (taken_stack[i].flags != host_stack[i].flags) {
                    shape_ok = false;
                    break;
                }
            }
        }
        if (!shape_ok) {
            host_stack.clear();
            host_unknown = true;
            mc.note("the two arms of a branch left different host stacks");
        } else {
            for (std::size_t i = 0; i < host_stack.size(); ++i) {
                const HostSlot& a = taken_stack[i];
                HostSlot& b = host_stack[i];
                if (a.flags) {
                    for (int j = 0; j < 6; ++j) {
                        b.flags_vals[j] = mc.select_of(
                            1, cond, a.flags_vals[j], b.flags_vals[j]);
                    }
                } else {
                    b.v = mc.select_of(64, cond, a.v, b.v);
                }
            }
        }

        // The stores through computed addresses: the same address written
        // by both arms is one write of a selected value; an address only
        // one arm wrote is a write of the value *or* of the byte the other
        // arm left there -- a load of the same address, which the checker
        // binds from the memory the handler was entered with.
        const auto same_write = [](const Handler::Write& a,
                                   const Handler::Write& b) {
            return !a.to_slot && !b.to_slot && a.addr == b.addr &&
                   a.width == b.width;
        };
        std::vector<Handler::Write> merged;
        for (const Handler::Write& fw : mem_writes) {
            const Handler::Write* tw = nullptr;
            for (const Handler::Write& candidate : taken_writes) {
                if (same_write(fw, candidate)) {
                    tw = &candidate;
                    break;
                }
            }
            Handler::Write w = fw;
            const Value fall_value = mk_value(dag, fw.value);
            const Value at = mk_value(dag, fw.addr);
            if (tw != nullptr) {
                w.value = mc.id_of(mc.select_of(
                    w.width, cond, mk_value(dag, tw->value), fall_value));
            } else {
                const Value was = mc.load_read(at, w.width);
                w.value = mc.id_of(
                    mc.select_of(w.width, cond, was, fall_value));
            }
            merged.push_back(w);
        }
        for (const Handler::Write& tw : taken_writes) {
            bool have = false;
            for (const Handler::Write& fw : mem_writes) {
                if (same_write(fw, tw)) {
                    have = true;
                    break;
                }
            }
            if (have) {
                continue;
            }
            Handler::Write w = tw;
            const Value taken_value = mk_value(dag, tw.value);
            const Value at = mk_value(dag, tw.addr);
            const Value was = mc.load_read(at, w.width);
            w.value =
                mc.id_of(mc.select_of(w.width, cond, taken_value, was));
            merged.push_back(w);
        }
        mem_writes = std::move(merged);

        // The arms' notes are the merged model's notes: an objection one
        // arm raised is an objection to the model, whether or not the
        // other arm ran into it.
        mc.absorb_notes(taken_state);
        (void)taken_exit;
        (void)fall_exit;
    }

    // Walks from `va` until control leaves the handler. A branch whose
    // condition cannot be reduced forks: both edges are walked from the
    // state the branch saw, and the arms are merged under the condition.
    Exit explore(std::uint64_t va, std::vector<std::uint64_t> visited,
                 unsigned depth) {
        for (;;) {
            // The handlers of a VM that keeps one dispatcher all tail
            // into it; reaching that entry is where this handler ends.
            // Stopping here is what keeps the dispatcher's own branches
            // -- one arm returning, one dispatching by construction --
            // out of the handler's model, and the transfer it ends with
            // is the dispatch the hand-back is.
            if (boundary != nullptr) {
                for (const std::uint64_t b : *boundary) {
                    if (b == va) {
                        return Exit{true, Handler::Transfer::Dispatch,
                                    expr::kNoId};
                    }
                }
            }
            if (steps >= step_budget) {
                mc.hazard("instruction budget exhausted");
                return Exit{};
            }
            ++steps;
            if (va < window_va || va - window_va >= available) {
                mc.hazard("handler ran outside the bytes it was given");
                return Exit{};
            }
            for (const std::uint64_t seen : visited) {
                if (seen == va) {
                    mc.hazard("the handler's block chain loops");
                    return Exit{};
                }
            }
            visited.push_back(va);
            mc.cur_va = va;
            const std::uint8_t* p = bytes + (va - window_va);
            const std::size_t avail = available - (va - window_va);
            Insn insn;
            if (!decode_insn(p, avail, va, insn)) {
                mc.hazard("undecodable instruction");
                return Exit{};
            }
            Shape sh;
            decode_shape(p, avail, insn.length, va, sh);
            const unsigned len = insn.length;
            if (!sh.ok) {
                if (sh.op == Shape::Op::Hlt &&
                    insn.kind == inspect::InsnKind::Syscall) {
                    // The engine's call-out stub. What it does to memory
                    // and the registers is the engine's business, so
                    // nothing the model held is kept; the transfer is the
                    // handler's whole remaining effect.
                    mc.note("engine call-out");
                    mc.taint_memory();
                    return Exit{true, Handler::Transfer::Call, expr::kNoId};
                }
                mc.note("unmodelled instruction: " + insn.mnemonic);
                if (insn.kind == inspect::InsnKind::Jmp ||
                    insn.kind == inspect::InsnKind::Jcc ||
                    insn.kind == inspect::InsnKind::Ret ||
                    insn.kind == inspect::InsnKind::Call) {
                    const Handler::Transfer transfer =
                        insn.kind == inspect::InsnKind::Ret
                            ? Handler::Transfer::Return
                        : insn.kind == inspect::InsnKind::Call
                            ? Handler::Transfer::Call
                            : Handler::Transfer::Unknown;
                    if (transfer == Handler::Transfer::Unknown) {
                        mc.hazard("unmodelled branch ends the walk");
                        return Exit{};
                    }
                    return Exit{true, transfer, expr::kNoId};
                }
                // Nothing is known about what the instruction writes, so
                // nothing keeps its old value: every register -- the two
                // virtual pointers included, since it could move those as
                // readily as any other -- every flag, the host stack, and
                // the memory the model was tracking all become unknowns
                // of their own. The walk goes on; the note says what
                // happened; and no prediction leans on a value that is
                // no longer known.
                for (const char* const name : kReg64) {
                    mc.reg_write(name, mc.unknown_value(name));
                }
                static const char* const flag_names[6] = {"cf", "zf", "sf",
                                                          "of", "pf", "af"};
                for (int i = 0; i < 6; ++i) {
                    mc.flags[i] = mc.unknown_value(flag_names[i]);
                }
                host_stack.clear();
                host_unknown = true;
                mc.taint_memory();
                va += len;
                continue;
            }

            const unsigned w = sh.width;
            switch (sh.op) {
            case Shape::Op::Nop:
                break;
            case Shape::Op::Int3:
            case Shape::Op::Hlt:
                mc.hazard("halt-like instruction ends the walk");
                return Exit{};
            case Shape::Op::Cmc:
                mc.flags[0] = mc.not_of(1, mc.flags[0]);
                break;
            case Shape::Op::Clc:
                mc.flags[0] = value_const(0);
                break;
            case Shape::Op::Stc:
                mc.flags[0] = value_const(1);
                break;
            case Shape::Op::Cld:
            case Shape::Op::Std:
                break;
            case Shape::Op::Push: {
                // The value goes onto the host stack; a later pop can
                // bring it back, which is how the junk moves values.
                HostSlot slot;
                if (sh.has_dst) {
                    const OperandRead src = read_operand(sh.dst, 64);
                    slot.v = src.ok ? src.v : Value{};
                }
                host_stack.push_back(slot);
                break;
            }
            case Shape::Op::Pop: {
                Value v;
                if (!host_stack.empty()) {
                    v = host_stack.back().v;
                    host_stack.pop_back();
                } else if (host_unknown) {
                    // The stack's contents were dropped -- an unmodelled
                    // instruction, or arms that left different stacks --
                    // so what comes off it is an unknown of its own
                    // rather than a stale value.
                    v = mc.unknown_value("stack");
                }
                if (sh.has_dst) {
                    write_operand(sh.dst, 64, v);
                }
                break;
            }
            case Shape::Op::Pushf: {
                HostSlot slot;
                slot.flags = true;
                for (int i = 0; i < 6; ++i) {
                    slot.flags_vals[i] = mc.flags[i];
                }
                host_stack.push_back(slot);
                break;
            }
            case Shape::Op::Popf: {
                if (!host_stack.empty() && host_stack.back().flags) {
                    for (int i = 0; i < 6; ++i) {
                        mc.flags[i] = host_stack.back().flags_vals[i];
                    }
                    host_stack.pop_back();
                } else {
                    // The flags come from the state the handler was
                    // entered with, which the model does not carry:
                    // every flag is an unknown of its own from here on.
                    static const char* const names[6] = {"cf", "zf", "sf",
                                                         "of", "pf", "af"};
                    for (int i = 0; i < 6; ++i) {
                        mc.flags[i] = mc.unknown_value(names[i]);
                    }
                }
                break;
            }
            case Shape::Op::Cwde: {
                const Value rax = mc.reg_read("rax");
                const unsigned src = w == 64 ? 32 : 16;
                mc.reg_write("rax", mc.sign_extend(src, rax));
                break;
            }
            case Shape::Op::Cdq: {
                const Value rax = mc.reg_read("rax");
                const unsigned src = w == 64 ? 32 : 16;
                mc.reg_write(w == 64 ? "rdx" : "rdx",
                             mc.sign_extend(src, rax));
                break;
            }
            case Shape::Op::Leave: {
                // The frame is gone, and with it every claim about where
                // the virtual stack is: the pointer becomes an unknown of
                // its own and the memory the model was tracking is
                // dropped, so the accesses after this one turn into loads
                // and stores at addresses it can still write down.
                mc.reg_write("rsp", mc.unknown_value("rsp"));
                mc.reg_write("rbp", mc.unknown_value("rbp"));
                const bool stack_gone =
                    mc.m->convention.stack == "rbp" ||
                    mc.m->convention.stack == "rsp";
                mc.note(stack_gone
                             ? "leave: the virtual stack pointer is gone"
                             : "leave: the host frame is gone, the virtual "
                               "stack pointer survives");
                mc.taint_memory();
                break;
            }
            case Shape::Op::Mov: {
                const OperandRead src = read_operand(sh.src, w);
                write_operand(sh.dst, w, src.v);
                break;
            }
            case Shape::Op::Movzx: {
                const OperandRead src = read_operand(sh.src, sh.src.width);
                write_operand(sh.dst, w, mc.zext(src.v, w));
                break;
            }
            case Shape::Op::Movsx: {
                const OperandRead src = read_operand(sh.src, sh.src.width);
                write_operand(sh.dst, w,
                              mc.sign_extend(sh.src.width, src.v));
                break;
            }
            case Shape::Op::Lea: {
                const Operand& mem = sh.src;
                if (mem.kind != Operand::Kind::Mem) {
                    mc.note("lea without a memory operand");
                    poison(sh.dst, w);
                    break;
                }
                write_operand(sh.dst, w, effective_address(mem));
                break;
            }
            case Shape::Op::Add:
            case Shape::Op::Adc:
            case Shape::Op::Sub:
            case Shape::Op::Sbb:
            case Shape::Op::And:
            case Shape::Op::Or:
            case Shape::Op::Xor: {
                const OperandRead a = read_operand(sh.dst, w);
                const OperandRead b = read_operand(sh.src, w);
                Value res = mc.bin(sh.op == Shape::Op::Add ||
                                           sh.op == Shape::Op::Adc
                                       ? BinOp::Add
                                   : sh.op == Shape::Op::Sub ||
                                           sh.op == Shape::Op::Sbb
                                       ? BinOp::Sub
                                   : sh.op == Shape::Op::And ? BinOp::And
                                   : sh.op == Shape::Op::Or  ? BinOp::Or
                                                             : BinOp::Xor,
                                   w, a.v, b.v);
                if (sh.op == Shape::Op::Adc || sh.op == Shape::Op::Sbb) {
                    const Value carry = mc.zext(mc.flags[0], w);
                    res = mc.bin(sh.op == Shape::Op::Adc ? BinOp::Add
                                                         : BinOp::Sub,
                                 w, res, carry);
                }
                set_flags_arith(mc, sh.op, w, a.v, b.v, res);
                write_operand(sh.dst, w, res);
                break;
            }
            case Shape::Op::Cmp: {
                const OperandRead a = read_operand(sh.dst, w);
                const OperandRead b = read_operand(sh.src, w);
                const Value res = mc.bin(BinOp::Sub, w, a.v, b.v);
                set_flags_arith(mc, Shape::Op::Cmp, w, a.v, b.v, res);
                break;
            }
            case Shape::Op::Test: {
                const OperandRead a = read_operand(sh.dst, w);
                const OperandRead b = read_operand(sh.src, w);
                const Value res = mc.bin(BinOp::And, w, a.v, b.v);
                set_flags_arith(mc, Shape::Op::Test, w, a.v, b.v, res);
                break;
            }
            case Shape::Op::Inc:
            case Shape::Op::Dec: {
                const OperandRead a = read_operand(sh.dst, w);
                const Value one = value_const(1);
                const Value res =
                    mc.bin(sh.op == Shape::Op::Inc ? BinOp::Add : BinOp::Sub,
                           w, a.v, one);
                set_flags_arith(mc, sh.op, w, a.v, one, res);
                write_operand(sh.dst, w, res);
                break;
            }
            case Shape::Op::Not: {
                const OperandRead a = read_operand(sh.dst, w);
                write_operand(sh.dst, w, mc.not_of(w, a.v));
                break;
            }
            case Shape::Op::Neg: {
                const OperandRead a = read_operand(sh.dst, w);
                set_flags_arith(mc, Shape::Op::Neg, w, a.v, value_const(0),
                                mc.neg_of(w, a.v));
                write_operand(sh.dst, w, mc.neg_of(w, a.v));
                break;
            }
            case Shape::Op::Shl:
            case Shape::Op::Shr:
            case Shape::Op::Sar:
            case Shape::Op::Rol:
            case Shape::Op::Ror: {
                const OperandRead a = read_operand(sh.dst, w);
                const OperandRead b = read_operand(sh.src, 8);
                if (sh.op == Shape::Op::Rol || sh.op == Shape::Op::Ror) {
                    // The count is masked to the width's bit count, which
                    // is also what the two-shift form below needs, so a
                    // literal and a computed count take the same road.
                    const unsigned k =
                        b.v.kind == Value::Kind::Const
                            ? static_cast<unsigned>(b.v.imm) & (w - 1)
                            : 0;
                    const Value rolled =
                        b.v.kind == Value::Kind::Const
                            ? mc.rotate(w, a.v, k, sh.op == Shape::Op::Ror)
                            : mc.rotate_by(w, a.v, b.v,
                                           sh.op == Shape::Op::Ror);
                    write_operand(sh.dst, w, rolled);
                    // CF is the bit that comes round: the top bit for a
                    // left rotate, the bottom one for a right rotate --
                    // and the old CF when the masked count is zero. The
                    // rest of the flags are left as they were, which is
                    // what x86 leaves them as.
                    const Value zero = value_const(0);
                    const Value kk = b.v.kind == Value::Kind::Const
                                         ? Value{}
                                         : mc.bin(BinOp::And, w,
                                                  mc.trunc(b.v, w),
                                                  value_const(w - 1));
                    const Value edge =
                        mc.bit(w, rolled, sh.op == Shape::Op::Rol ? 0 : w - 1);
                    if (b.v.kind == Value::Kind::Const) {
                        mc.flags[0] = k == 0 ? mc.flags[0] : edge;
                    } else {
                        mc.flags[0] = mc.select_of(
                            1, mc.cmp(CmpOp::Eq, w, kk, zero), mc.flags[0],
                            edge);
                    }
                    break;
                }
                const Value res =
                    mc.bin(sh.op == Shape::Op::Shl ? BinOp::Shl
                            : sh.op == Shape::Op::Shr ? BinOp::Shr
                                                      : BinOp::Sar,
                           w, a.v, b.v);
                set_flags_arith(mc, sh.op, w, a.v, b.v, res);
                write_operand(sh.dst, w, res);
                break;
            }
            case Shape::Op::Rcl:
            case Shape::Op::Rcr: {
                const OperandRead a = read_operand(sh.dst, w);
                const OperandRead b = read_operand(sh.src, 8);
                const unsigned mask = w == 64 ? 0x3F : 0x1F;
                const bool left = sh.op == Shape::Op::Rcl;
                // The carry is a bit of the ring the value rotates
                // through, so an unknown carry or an unknown count makes
                // the result unknown: the destination is poisoned rather
                // than left holding a stale number.
                if (a.v.kind == Value::Kind::Unknown ||
                    b.v.kind == Value::Kind::Unknown ||
                    mc.flags[0].kind == Value::Kind::Unknown) {
                    poison(sh.dst, w);
                    mc.flags[0] = mc.unknown_value("cf");
                    break;
                }
                const bool symbolic = b.v.kind != Value::Kind::Const;
                const Value masked =
                    symbolic
                        ? mc.bin(BinOp::And, 8, mc.trunc(b.v, 8),
                                 value_const(mask))
                        : value_const(static_cast<unsigned>(b.v.imm) & mask);
                Value x;
                Value cf;
                mc.rotate_carry(w, left, a.v, mc.flags[0], masked, symbolic,
                                &x, &cf);
                write_operand(sh.dst, w, x);
                mc.flags[0] = cf;
                // OF is defined by rcl/rcr only for a count of one and
                // is left undefined otherwise; an unknown of its own is
                // the honest value for it either way here.
                mc.flags[3] = mc.unknown_value("of");
                break;
            }
            case Shape::Op::Imul: {
                const OperandRead a = read_operand(sh.dst, w);
                const OperandRead b = read_operand(sh.src, w);
                write_operand(sh.dst, w, mc.bin(BinOp::Mul, w, a.v, b.v));
                break;
            }
            case Shape::Op::Xchg: {
                const OperandRead a = read_operand(sh.dst, w);
                const OperandRead b = read_operand(sh.src, w);
                write_operand(sh.dst, w, b.v);
                write_operand(sh.src, w, a.v);
                break;
            }
            case Shape::Op::Bt:
            case Shape::Op::Bts:
            case Shape::Op::Btr:
            case Shape::Op::Btc: {
                const OperandRead a = read_operand(sh.dst, w);
                const OperandRead idx = read_operand(sh.src, w);
                const Value i = mc.bin(BinOp::And, w, idx.v,
                                       value_const(w - 1));
                // CF is the bit the index names, extracted with a
                // variable shift; the other flags are undefined on x86
                // and are left as they were.
                mc.flags[0] = mc.trunc(mc.bin(BinOp::Shr, w, a.v, i), 1);
                if (sh.op != Shape::Op::Bt) {
                    const Value one = mc.bin(BinOp::Shl, w, value_const(1), i);
                    Value v;
                    if (sh.op == Shape::Op::Bts) {
                        v = mc.bin(BinOp::Or, w, a.v, one);
                    } else if (sh.op == Shape::Op::Btr) {
                        v = mc.bin(BinOp::And, w, a.v, mc.not_of(w, one));
                    } else {
                        v = mc.bin(BinOp::Xor, w, a.v, one);
                    }
                    write_operand(sh.dst, w, v);
                }
                break;
            }
            case Shape::Op::Bsf:
            case Shape::Op::Bsr: {
                // The index of the first set bit, built as a select chain
                // that walks the bits in the order leaving the wanted one
                // last; a set bit replaces the result as it passes. The
                // all-zero input leaves 0, which x86 calls undefined.
                const OperandRead a = read_operand(sh.src, w);
                const bool forward = sh.op == Shape::Op::Bsf;
                Value res = value_const(0);
                for (unsigned k = 0; k < w; ++k) {
                    const unsigned at = forward ? (w - 1 - k) : k;
                    res = mc.select_of(w, mc.bit(w, a.v, at),
                                       value_const(at), res);
                }
                write_operand(sh.dst, w, res);
                mc.flags[1] = mc.cmp(CmpOp::Eq, w, a.v, value_const(0));
                break;
            }
            case Shape::Op::Bswap: {
                const OperandRead a = read_operand(sh.dst, w);
                Value acc = value_const(0);
                for (unsigned k = 0; k < w / 8; ++k) {
                    const Value shifted = mc.bin(
                        BinOp::Shr, w, a.v,
                        value_const(8 * (w / 8 - 1 - k)));
                    const Value byte =
                        mc.bin(BinOp::And, w, shifted, value_const(0xFF));
                    const Value placed =
                        k == 0 ? byte
                               : mc.bin(BinOp::Shl, w, byte,
                                        value_const(8 * k));
                    acc = mc.bin(BinOp::Or, w, acc, placed);
                }
                write_operand(sh.dst, w, acc);
                break;
            }
            case Shape::Op::Shld:
            case Shape::Op::Shrd: {
                const OperandRead a = read_operand(sh.dst, w);
                const OperandRead b = read_operand(sh.src, w);
                // The hardware masks the count: five bits below the
                // 64-bit form, six in it. CL is the only computed count
                // the encoding offers, so that is the case this handles.
                const std::uint64_t mask = w == 64 ? 0x3F : 0x1F;
                const Value count =
                    sh.count_is_cl
                        ? mc.bin(BinOp::And, 8,
                                 mc.trunc(mc.reg_read("rcx"), 8),
                                 value_const(mask))
                        : value_const(sh.count & mask);
                if (count.kind == Value::Kind::Unknown) {
                    // A count the model lost track of makes the result
                    // unknown: the destination is poisoned rather than
                    // left holding a stale number, and the carry with it.
                    poison(sh.dst, w);
                    mc.flags[0] = mc.unknown_value("cf");
                    break;
                }
                const bool left = sh.op == Shape::Op::Shld;
                const Value v = mc.double_shift(w, left, a.v, b.v, count);
                write_operand(sh.dst, w, v);
                const bool is_const = count.kind == Value::Kind::Const;
                const unsigned n =
                    is_const ? static_cast<unsigned>(count.imm) : 0;
                if (is_const && n == 0) {
                    // A count of zero changes nothing at all, the flags
                    // included; the write above put back the same value.
                    break;
                }
                // The flags: ZF and SF follow the result; PF and OF are
                // undefined, so each is an unknown of its own. CF is the
                // bit last shifted out -- a literal for a literal count,
                // and for a computed one the same variable shift the
                // value uses, since below the 16-bit form the mask keeps
                // the count inside the defined range.
                mc.flags[1] = mc.cmp(CmpOp::Eq, w, v, value_const(0));
                mc.flags[2] = mc.bit(w, v, w - 1);
                mc.flags[3] = mc.unknown_value("of");
                mc.flags[4] = mc.unknown_value("pf");
                if (is_const) {
                    mc.flags[0] =
                        n < w ? mc.bit(w, mc.trunc(a.v, w),
                                       left ? w - n : n - 1)
                              : mc.unknown_value("cf");
                } else if (w >= 32) {
                    const Value k = mc.trunc(count, w);
                    const Value idx = left
                                          ? mc.bin(BinOp::Sub, w,
                                                   value_const(w), k)
                                          : mc.bin(BinOp::Sub, w, k,
                                                   value_const(1));
                    mc.flags[0] = mc.trunc(
                        mc.bin(BinOp::Shr, w, mc.trunc(a.v, w), idx), 1);
                } else {
                    mc.flags[0] = mc.unknown_value("cf");
                }
                break;
            }
            case Shape::Op::Xadd: {
                const OperandRead a = read_operand(sh.dst, w);
                const OperandRead b = read_operand(sh.src, w);
                const Value res = mc.bin(BinOp::Add, w, a.v, b.v);
                write_operand(sh.dst, w, res);
                write_operand(sh.src, w, a.v);
                set_flags_arith(mc, Shape::Op::Add, w, a.v, b.v, res);
                break;
            }
            case Shape::Op::Setcc: {
                const Value cond = condition_value(mc, sh.cond);
                write_operand(sh.dst, 8, mc.zext(cond, 8));
                break;
            }
            case Shape::Op::Cmov: {
                const Value cond = condition_value(mc, sh.cond);
                if (cond.kind == Value::Kind::Const) {
                    if (cond.imm != 0) {
                        const OperandRead src = read_operand(sh.src, w);
                        write_operand(sh.dst, w, src.v);
                    }
                } else {
                    // The condition is a value the model holds but cannot
                    // reduce: the destination is the source or its old
                    // self, which is exactly a select.
                    const OperandRead src = read_operand(sh.src, w);
                    const OperandRead old = read_operand(sh.dst, w);
                    write_operand(sh.dst, w,
                                  mc.select_of(w, cond, src.v, old.v));
                }
                break;
            }
            case Shape::Op::Jmp: {
                if (!sh.indirect) {
                    va = sh.dst.imm;
                    continue;
                }
                const OperandRead t = read_operand(sh.dst, 64);
                return Exit{true, Handler::Transfer::Dispatch,
                            mc.id_of(t.v)};
            }
            case Shape::Op::Call:
                return Exit{true, Handler::Transfer::Call, expr::kNoId};
            case Shape::Op::Ret:
                return Exit{true, Handler::Transfer::Return, expr::kNoId};
            case Shape::Op::Jcc: {
                const Value cond = condition_value(mc, sh.cond);
                if (cond.kind == Value::Kind::Const) {
                    va = cond.imm != 0 ? sh.dst.imm : va + len;
                    continue;
                }
                if (depth >= kMaxForkDepth) {
                    mc.hazard("branches nested past what the walk follows");
                    return Exit{};
                }
                // The condition is a value the model holds but cannot
                // reduce, so *both* edges are walked, from the state the
                // branch saw, and the arms are merged back together under
                // the condition. The model then holds whichever way the
                // branch goes; the trace check evaluates the condition
                // and follows the arm that ran, so nothing rests on the
                // arm that did not.
                const Machine at_branch = mc;
                const std::vector<Handler::Write> writes_at_branch =
                    mem_writes;
                const bool host_at_branch = host_unknown;

                const Exit taken_exit =
                    explore(sh.dst.imm, visited, depth + 1);
                Machine taken_state = mc;
                const std::vector<Handler::Write> taken_writes = mem_writes;
                const std::vector<HostSlot> taken_stack = host_stack;
                const bool taken_host = host_unknown;

                mc = at_branch;
                mem_writes = writes_at_branch;
                host_unknown = host_at_branch;
                const Exit fall_exit = explore(va + len, visited, depth + 1);

                if (!taken_exit.settled && !fall_exit.settled) {
                    // Both arms failed and each has said so.
                    return Exit{};
                }
                if (!taken_exit.settled) {
                    // The arm that took the branch could not be walked,
                    // and there is no state to merge: what the model
                    // recovered is the fall-through arm's, and it says so.
                    mc.hazard("one arm of a branch could not be walked");
                    return Exit{};
                }
                if (!fall_exit.settled) {
                    mc.hazard("one arm of a branch could not be walked");
                    return Exit{};
                }
                if (taken_exit.transfer != fall_exit.transfer) {
                    mc.hazard("the two arms of a branch end differently");
                    return Exit{};
                }
                merge_arm(taken_state, taken_writes, taken_stack, taken_host,
                          taken_exit, fall_exit, cond);
                return Exit{
                    true, fall_exit.transfer,
                    merge_target(cond, taken_exit.target, fall_exit.target)};
            }
            case Shape::Op::None:
                break;
            }
            va += len;
        }
    }

    // The expression for "the branch's target": the taken arm's when the
    // condition holds, the fall-through arm's otherwise. kNoId when
    // neither arm named one, which stays kNoId.
    [[nodiscard]] expr::Id merge_target(const Value& cond, expr::Id taken,
                                        expr::Id fall) {
        if (taken == expr::kNoId) {
            return fall;
        }
        if (fall == expr::kNoId) {
            return taken;
        }
        return mc.id_of(mc.select_of(
            64, cond, mk_value(mc.m->dag, taken), mk_value(mc.m->dag, fall)));
    }
};

}  // namespace

// --------------------------------------------------------- entry points

bool decode_insn(const std::uint8_t* bytes, std::size_t available,
                 std::uint64_t va, Insn& out) noexcept {
    inspect::Decoded dec;
    const std::uint32_t len = inspect::x64_decode(bytes, available, va, dec);
    if (len == 0) {
        return false;
    }
    out = Insn{};
    out.va = va;
    out.length = len;
    out.mnemonic = dec.mnemonic != nullptr ? dec.mnemonic : "?";
    out.kind = dec.kind;
    if (dec.has_branch_target) {
        out.target = dec.branch_target;
    }
    Shape sh;
    decode_shape(bytes, available, len, va, sh);
    out.modeled = sh.ok;
    if (sh.ok) {
        if (sh.has_dst) {
            out.operands.push_back(sh.dst);
        }
        if (sh.has_src) {
            out.operands.push_back(sh.src);
        }
    } else {
        out.reason = "unmodelled encoding: " + out.mnemonic;
    }
    return true;
}

Handler summarize(Model& model, const std::uint8_t* bytes,
                  std::size_t available, std::uint64_t window_va,
                  std::uint64_t va, std::size_t max_instructions,
                  const std::vector<std::uint64_t>& boundary) {
    Handler h;
    h.va = va;
    Runner run;
    run.mc.m = &model;
    run.bytes = bytes;
    run.available = available;
    run.base_va = va;
    run.window_va = window_va;
    run.boundary = &boundary;
    // The budget covers the handler and every arm a branch forks into: a
    // diamond cannot be walked for free. A straight-line handler still
    // gets several times its own length.
    run.step_budget = max_instructions * 16;
    // The flags a handler is entered with are whatever the dispatcher's
    // own tail left: not knowable from the handler alone, and not the
    // same from one dispatch site to the next, so each is an input of
    // its own rather than a hole.
    for (Value& f : run.mc.flags) {
        f = run.mc.unknown_value("flags");
    }
    const Runner::Exit exit =
        run.explore(va, std::vector<std::uint64_t>{}, 0);
    if (exit.settled) {
        h.transfer = exit.transfer;
        h.target_expr = exit.target;
    } else {
        h.transfer = Handler::Transfer::Unknown;
    }

    h.modeled = !run.mc.incomplete;
    h.reason = "modelled";
    for (const Machine::Note& n : run.mc.notes) {
        h.notes.push_back(n.text);
        if (n.blocking) {
            if (h.reason == "modelled") {
                h.reason = n.text;
            }
        }
    }
    if (!h.modeled && h.reason == "modelled") {
        h.reason = "incomplete";
    }
    // rbp and rsi as expressions: reading them here gives their entry
    // input when the handler never touched them, which is the honest
    // statement that the pointer is unchanged.
    h.rbp_new = run.mc.id_of(run.mc.reg_read(model.convention.stack));
    h.rsi_new = run.mc.id_of(run.mc.reg_read(model.convention.cursor));
    // The handler's writes to the virtual stack, one entry per eight-byte
    // cell it touched: the cell's final value, composed out of the bytes
    // the handler left there and the entry bytes it did not touch. The
    // machine keeps bytes; this is the view the report and the checker
    // work in.
    std::vector<std::int64_t> cells;
    for (const auto& [disp, value] : run.mc.stack_bytes) {
        (void)value;
        const std::int64_t cell = aligned_displacement(disp);
        if (std::find(cells.begin(), cells.end(), cell) == cells.end()) {
            cells.push_back(cell);
        }
    }
    for (const std::int64_t cell : cells) {
        // The cell's final value: the runs of bytes it is made of, with
        // a run that is a whole source reading as that source.
        Handler::Write sw;
        sw.to_slot = true;
        sw.disp = cell;
        sw.value = run.mc.id_of(run.mc.range_read(cell, 64));
        h.writes.push_back(sw);
    }
    // The stores through computed addresses follow. A slot write is the
    // slot's final value, and in the handlers this layer sees the
    // computed store is the exit effect, so the order is the order the
    // bytes end up in.
    for (const Handler::Write& mw : run.mem_writes) {
        h.writes.push_back(mw);
    }
    return h;
}

namespace {

// The binding of a model's inputs for one dispatch.
struct Binder {
    std::vector<std::uint64_t> values;
    std::vector<char> bound;

    explicit Binder(const Model& m) {
        values.assign(m.inputs.size(), 0);
        bound.assign(m.inputs.size(), 0);
    }

    void bind(unsigned ordinal, std::uint64_t value) {
        values[ordinal] = value;
        bound[ordinal] = 1;
    }

    [[nodiscard]] bool all_bound(const std::vector<unsigned>& ordinals) {
        for (const unsigned o : ordinals) {
            if (o >= bound.size() || bound[o] == 0) {
                return false;
            }
        }
        return true;
    }
};

// The virtual stack's bytes, as far as they are known: seeded from the
// trace's cells, updated by the models' writes, adopted from every
// observation. Byte granular because the model's regions and the trace's
// cells both sit at whatever offsets the stack pointer happens to hold --
// a handler pops a word as readily as a qword -- so the two overlap at
// arbitrary offsets and only the bytes can be compared.
struct Shadow {
    std::map<std::uint64_t, std::uint8_t> bytes;

    [[nodiscard]] bool read(std::uint64_t addr, std::uint64_t* out) const {
        return readn(addr, 8, out);
    }

    // `count` bytes, when every one of them is known.
    [[nodiscard]] bool readn(std::uint64_t addr, unsigned count,
                             std::uint64_t* out) const {
        if (count == 0 || count > 8) {
            return false;
        }
        std::uint64_t v = 0;
        for (unsigned i = 0; i < count; ++i) {
            const auto it = bytes.find(addr + i);
            if (it == bytes.end()) {
                return false;
            }
            v |= static_cast<std::uint64_t>(it->second) << (8 * i);
        }
        *out = v;
        return true;
    }

    void write(std::uint64_t addr, std::uint64_t v, unsigned count = 8) {
        for (unsigned i = 0; i < count; ++i) {
            bytes[addr + i] = static_cast<std::uint8_t>(v >> (8 * i));
        }
    }

    // A value the model could not compute must not leave the old bytes
    // standing: a stale number is one that looks right.
    void forget(std::uint64_t addr, unsigned count = 8) {
        for (unsigned i = 0; i < count; ++i) {
            bytes.erase(addr + i);
        }
    }

    // A write whose address is not even a name: it could have landed
    // anywhere, so nothing about the stack's bytes is known from here on.
    void clear() { bytes.clear(); }

    // The cells the tracer read at a dispatch: the aligned cells
    // containing the pointer, not the pointer's own byte range. Which
    // cells those are is the caller's answer -- the tracer records two
    // windows, one around rbp and one around rsp, because which of them
    // is the virtual stack is a question about the model.
    void adopt(std::uint64_t stack, const std::vector<std::uint64_t>& cells) {
        const std::uint64_t base = stack & ~std::uint64_t{7};
        for (std::size_t k = 0; k < cells.size(); ++k) {
            write(base + 8 * static_cast<std::uint64_t>(k), cells[k]);
        }
    }
};

// Which Row field carries the value of a convention register. The trace
// samples five physical registers by name (rsi/rbp/rdi/rsp/r12); a
// convention whose stack or cursor names one of them reads that field.
// A convention that names anything else reads the general table, and only
// where the trace says it carried that register -- a zero in a field the
// trace never wrote is not a value the machine held, and binding it would
// be a fabricated prediction rather than an unverifiable one.
struct TraceField {
    const Convention& conv;
    [[nodiscard]] bool stack(const Row& r, std::uint64_t* out) const {
        return pick(r, conv.stack, out);
    }
    [[nodiscard]] bool cursor(const Row& r, std::uint64_t* out) const {
        return pick(r, conv.cursor, out);
    }
    // The value a named register held at this row. The five registers the
    // tracer has always carried are read from their own fields -- a Row
    // built before the extension has them and nowhere else -- and every
    // other register comes from the table, where the row's presence mask
    // is what separates a register the trace recorded from one it did not.
    static bool pick(const Row& r, const std::string& name,
                     std::uint64_t* out) {
        return row_register(r, name, out);
    }

    // The cells the trace read around the convention's stack register.
    // The tracer records two windows -- around rbp and around rsp -- since
    // which of them is the virtual stack is the model's question to
    // answer and not the tracer's. A convention that names rsp reads that
    // window when the trace carried it; anything else is a trace built to
    // describe the convention, and its cells are the three the trace
    // carries. A window the trace did not read yields no cells at all,
    // which leaves the shadow unseeded there instead of seeded with a zero
    // the machine never wrote.
    [[nodiscard]] std::vector<std::uint64_t> slot_cells(const Row& r) const {
        if (conv.stack == "rsp") {
            if (!r.rt_present) {
                return {};
            }
            return std::vector<std::uint64_t>(r.rt.begin(), r.rt.end());
        }
        return std::vector<std::uint64_t>{r.st0, r.st1, r.st2};
    }
};

// One expression as a run saw it. A value the trace determined completely
// prints as the number it was -- there is nothing left to say about it --
// and one it left partly open keeps its shape with the values substituted,
// so the open part stays visible instead of being folded into a claim the
// run never made. Both the report's stream and the address labels read
// through this, which is why a slot index the run fixed prints as
// `vst[3]` rather than as the arithmetic that arrived there.
[[nodiscard]] std::string bound_text(const Model& model, expr::Id id,
                                     const expr::Bindings& bound) {
    if (id == expr::kNoId) {
        return "?";
    }
    for (const unsigned o : model.dag.inputs_of(id)) {
        if (!bound.has(o)) {
            return model.dag.pretty_bound(id, bound);
        }
    }
    std::vector<std::uint64_t> values(model.inputs.size(), 0);
    for (std::size_t k = 0; k < values.size() && k < bound.values.size();
         ++k) {
        values[k] = bound.values[k];
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx",
                  static_cast<unsigned long long>(
                      model.dag.evaluate(id, values)));
    return buf;
}

}  // namespace

std::uint64_t resolve_handler(std::uint64_t target, bool target_is_code) {
    if (target_is_code) {
        // The table held the handler's address; the dispatcher jumped to
        // it as read.
        return target;
    }
    // The table held it rotated left by ten. The rotate is written out
    // rather than shifted through a helper because the word is 64 bits
    // wide and the two halves meet at the top: `<< 10` alone would drop
    // the high ten bits, and the rotate is the whole point.
    return (target << 10) | (target >> 54);
}

Layout infer_layout(const std::vector<HandlerBytes>& handlers) {
    struct Tally {
        std::size_t accesses = 0;
        unsigned width = 0;
    };
    std::map<std::string, Tally> files;          // element wider than a byte
    std::map<std::string, std::size_t> buffers;  // element is a byte
    for (const HandlerBytes& h : handlers) {
        if (h.bytes == nullptr || h.available == 0) {
            continue;
        }
        std::uint64_t at = h.va;
        for (std::size_t i = 0; i < 128 && at - h.va < h.available; ++i) {
            Insn insn;
            if (!decode_insn(h.bytes + (at - h.va), h.available - (at - h.va),
                             at, insn)) {
                break;
            }
            for (const Operand& o : insn.operands) {
                // An indexed access is what tells either apart from a
                // stack: the offset is a value the machine holds, not one
                // the instruction spells.
                if (o.kind != Operand::Kind::Mem || o.index.empty()) {
                    continue;
                }
                if (o.base.empty() || o.base == "rip") {
                    continue;
                }
                const unsigned element = static_cast<unsigned>(o.scale) * 8u;
                if (element <= 8) {
                    // Steps of a byte walk a stream -- the bytecode, a
                    // string -- so the base is a buffer, not a file.
                    ++buffers[o.base];
                    continue;
                }
                Tally& t = files[o.base];
                if (t.width == 0) {
                    t.width = element;
                }
                ++t.accesses;
            }
            // The scan follows the handler to where it leaves: a
            // conditional branch's fall-through is still the handler, and
            // an unconditional jump, a return or a call is where it ends.
            if (insn.kind == inspect::InsnKind::Jcc) {
                at += insn.length;
                continue;
            }
            if (insn.kind == inspect::InsnKind::Jmp ||
                insn.kind == inspect::InsnKind::Ret ||
                insn.kind == inspect::InsnKind::Call) {
                break;
            }
            at += insn.length;
        }
    }
    Layout best;
    std::size_t found = 0;
    for (const auto& [base, t] : files) {
        if (t.accesses > found) {
            found = t.accesses;
            best.regfile = base;
            best.regfile_width = t.width;
        }
    }
    found = 0;
    for (const auto& [base, n] : buffers) {
        if (n > found) {
            found = n;
            best.code = base;
        }
    }
    return best;
}

bool row_register(const Row& r, const std::string& name, std::uint64_t* out) {
    if (name == "rbp") {
        *out = r.rbp;
        return true;
    }
    if (name == "rsi") {
        *out = r.rsi;
        return true;
    }
    if (name == "rdi") {
        *out = r.rdi;
        return true;
    }
    if (name == "rsp") {
        *out = r.rsp;
        return true;
    }
    if (name == "r12") {
        *out = r.r12;
        return true;
    }
    for (std::size_t i = 0; i < 16; ++i) {
        if (name == kRowGprNames[i]) {
            if ((r.gpr_present & (std::uint32_t{1} << i)) == 0) {
                return false;
            }
            *out = r.gpr[i];
            return true;
        }
    }
    return false;
}

Conformance check_trace(Model& model, const std::vector<Handler>& handlers,
                        const std::vector<Row>& rows,
                        const std::vector<std::size_t>& handler_of_row,
                        CodeReader code_bytes, void* code_ctx,
                        std::vector<InstantiatedRow>* instantiated) {
    Conformance out;
    std::map<std::uint64_t, std::uint64_t> failures_by_handler;
    Shadow shadow;
    const TraceField tf{model.convention};
    if (!rows.empty()) {
        const std::vector<std::uint64_t> cells = tf.slot_cells(rows[0]);
        std::uint64_t stack = 0;
        if (!cells.empty() && tf.stack(rows[0], &stack)) {
            shadow.adopt(stack, cells);
        }
    }
    // One expression as the run saw it: a value the trace determined
    // completely prints as the number it was, and one it left partly open
    // keeps its shape with the values substituted in.
    const auto instantiate = [&model](expr::Id id,
                                      const expr::Bindings& b) {
        return bound_text(model, id, b);
    };

    // The walk covers every row, including the last: a dispatch with no
    // successor is still a dispatch the run took, and a report of the
    // stream that stopped one short would be a report that dropped the
    // engine's final step. What the row after it supplied -- the observed
    // registers, the cells to compare against -- is what is absent, so
    // those comparisons are the ones the walk skips.
    for (std::size_t i = 0; i < rows.size(); ++i) {
        if (i >= handler_of_row.size()) {
            break;
        }
        const std::size_t hi = handler_of_row[i];
        if (hi >= handlers.size()) {
            ++out.unmodeled;
            continue;
        }
        const Handler& h = handlers[hi];
        const Row& prev = rows[i];
        // Whether the trace says what happened after this row. The last
        // row of a trace has nothing after it, and a caller may also leave
        // the last row's own handler unnamed -- `handler_of_row` needs an
        // entry for a row the walk descends into, and the row nothing
        // descends into is not one.
        const bool has_next = i + 1 < rows.size();
        const Row& cur = has_next ? rows[i + 1] : prev;

        Binder b(model);
        const auto binding_of = [&]() {
            std::vector<std::uint64_t> binding(model.inputs.size(), 0);
            for (std::size_t k = 0; k < model.inputs.size(); ++k) {
                if (b.bound[k] != 0) {
                    binding[k] = b.values[k];
                }
            }
            return binding;
        };
        // Which inputs a prediction actually needs. A select -- which is
        // what a merged branch produces -- needs the condition's inputs
        // and then only the arm the condition chooses, when the trace
        // binds the condition. The arm that did not run is not needed,
        // and the unknowns the model left in it must not make the
        // prediction unverifiable: it never happened.
        const auto needed_inputs = [&](expr::Id id) {
            std::vector<unsigned> out;
            std::map<expr::Id, char> seen;
            const auto walk = [&](auto&& self, expr::Id at) -> void {
                if (at == expr::kNoId || seen.count(at) != 0) {
                    return;
                }
                seen[at] = 1;
                const expr::Node& n = model.dag.node(at);
                if (n.op == expr::Op::Input) {
                    out.push_back(static_cast<unsigned>(n.imm));
                    return;
                }
                if (n.op == expr::Op::Const) {
                    return;
                }
                if (n.op == expr::Op::Select) {
                    self(self, n.c);
                    if (b.all_bound(model.dag.inputs_of(n.c))) {
                        const std::vector<std::uint64_t> binding =
                            binding_of();
                        const std::uint64_t c =
                            model.dag.evaluate(n.c, binding);
                        self(self, (c & 1) != 0 ? n.a : n.b);
                    } else {
                        self(self, n.a);
                        self(self, n.b);
                    }
                    return;
                }
                self(self, n.a);
                self(self, n.b);
                self(self, n.c);
            };
            walk(walk, id);
            return out;
        };
        // Evaluates an expression with what the trace has bound so far.
        // False when some input it needs is not known.
        const auto eval = [&](expr::Id id, std::uint64_t* value) {
            if (id == expr::kNoId) {
                return false;
            }
            if (!b.all_bound(needed_inputs(id))) {
                return false;
            }
            const std::vector<std::uint64_t> binding = binding_of();
            *value = model.dag.evaluate(id, binding);
            return true;
        };
        for (std::size_t k = 0; k < model.inputs.size(); ++k) {
            const Model::Input& in = model.inputs[k];
            const auto ord = static_cast<unsigned>(k);
            switch (in.kind) {
            case Model::Input::Kind::Reg: {
                // Every general register the trace carries, by name: a
                // model that names a bytecode buffer in r8 or a file index
                // in r11 is bound from the same place the two pointers
                // always were.
                std::uint64_t v = 0;
                if (TraceField::pick(prev, in.name, &v)) {
                    b.bind(ord, v);
                }
                break;
            }
            case Model::Input::Kind::Slot: {
                // A slot read is the memory the handler was entered
                // with: whatever the shadow knows before this handler's
                // own writes are applied. The base is the Row field the
                // convention's stack register samples; a convention that
                // names an unsampled register leaves the slot unbound.
                std::uint64_t base = 0;
                if (!tf.stack(prev, &base)) {
                    break;
                }
                std::uint64_t v = 0;
                const std::uint64_t addr =
                    base + static_cast<std::uint64_t>(in.disp);
                if (shadow.read(addr, &v)) {
                    b.bind(ord, v);
                }
                break;
            }
            case Model::Input::Kind::Code: {
                if (code_bytes == nullptr) {
                    break;
                }
                std::uint64_t base = 0;
                if (!tf.cursor(prev, &base)) {
                    break;
                }
                std::uint64_t v = 0;
                const std::uint64_t addr =
                    base + static_cast<std::uint64_t>(in.disp);
                if (code_bytes(code_ctx, addr, in.width, &v)) {
                    b.bind(ord, v);
                }
                break;
            }
            case Model::Input::Kind::Image: {
                if (code_bytes == nullptr) {
                    break;
                }
                std::uint64_t v = 0;
                if (code_bytes(code_ctx, in.va, in.width, &v)) {
                    b.bind(ord, v);
                }
                break;
            }
            case Model::Input::Kind::Load: {
                // A value the handler read through a computed address:
                // the address is in the model's own DAG, so it can be
                // evaluated with what the trace has bound, and the bytes
                // then looked up. The virtual stack is where a handler's
                // own values live; the image is where its two tables do
                // (the bytecode is read through the image reader too, and
                // the dispatcher's handler table is part of it). The deps
                // are earlier inputs -- the address was built out of
                // values the handler already held -- so the loop's order
                // does.
                std::uint64_t at = 0;
                if (!eval(in.addr, &at)) {
                    break;
                }
                std::uint64_t v = 0;
                if (shadow.readn(at, in.width / 8, &v)) {
                    b.bind(ord, v);
                } else if (code_bytes != nullptr &&
                           code_bytes(code_ctx, at, in.width, &v)) {
                    b.bind(ord, v);
                }
                break;
            }
            case Model::Input::Kind::Unknown:
                // A value the model declared it cannot know: there is
                // nothing in the trace to bind it from, so everything
                // that depends on it stays unverifiable. That is what
                // makes it honest rather than a guess.
                break;
            }
        }

        // Scores one prediction against the trace.
        const auto record = [&](const std::string& what, bool known,
                                std::uint64_t got, std::uint64_t observed) {
            if (!known) {
                ++out.unverifiable;
                return;
            }
            if (got == observed) {
                ++out.checked;
                return;
            }
            ++out.mismatched;
            std::fprintf(stderr, "[mismatch] %s model=0x%llx trace=0x%llx\n",
                         what.c_str(),
                         static_cast<unsigned long long>(got),
                         static_cast<unsigned long long>(observed));
            ++failures_by_handler[h.va];
            if (out.failures.size() < 8) {
                char buf[192];
                std::snprintf(buf, sizeof(buf),
                              "#%llu handler 0x%llx %s: model 0x%llx "
                              "trace 0x%llx",
                              static_cast<unsigned long long>(prev.seq),
                              static_cast<unsigned long long>(h.va),
                              what.c_str(),
                              static_cast<unsigned long long>(got),
                              static_cast<unsigned long long>(observed));
                out.failures.emplace_back(buf);
            }
        };

        if (!h.modeled) {
            ++out.unmodeled;
        }
        if (has_next) {
            // The pointers are compared against the next row's value of
            // the register the convention assigns to each role, not
            // against fixed Row fields: under a permuted convention the
            // stack pointer lives in whatever field the stack register
            // samples, and a convention that names an unsampled register
            // makes the prediction unverifiable rather than wrong.
            std::uint64_t v = 0;
            const bool known = eval(h.rbp_new, &v);
            std::uint64_t want = 0;
            const bool want_known = tf.stack(cur, &want);
            record("rbp", known && want_known, v, want);
        }
        if (has_next) {
            std::uint64_t v = 0;
            const bool known = eval(h.rsi_new, &v);
            std::uint64_t want = 0;
            const bool want_known = tf.cursor(cur, &want);
            record("rsi", known && want_known, v, want);
        }
        // Where the handler goes next. The trace's next row says which
        // handler ran next, and the model's jump target should name the
        // same one: this is the half of a handler's effect that says what
        // virtual instruction follows.
        if (has_next && h.transfer == Handler::Transfer::Dispatch) {
            const std::size_t next = handler_of_row[i + 1];
            if (next < handlers.size()) {
                std::uint64_t v = 0;
                const bool known = eval(h.target_expr, &v);
                record("next handler", known, v, handlers[next].va);
            }
        }

        // Apply what the model says it wrote; what it could not compute
        // becomes unknown bytes rather than a stale value, and a write it
        // cannot even place leaves nothing known at all.
        for (const Handler::Write& wr : h.writes) {
            std::uint64_t addr = 0;
            bool placed = true;
            if (wr.to_slot) {
                placed = tf.stack(prev, &addr);
                if (placed) {
                    addr += static_cast<std::uint64_t>(wr.disp);
                }
            } else {
                placed = eval(wr.addr, &addr);
            }
            if (!placed) {
                shadow.clear();
                continue;
            }
            const unsigned count = wr.width / 8;
            std::uint64_t v = 0;
            if (eval(wr.value, &v)) {
                shadow.write(addr, v, count);
            } else {
                shadow.forget(addr, count);
            }
        }

        // The cells the tracer observed at the next dispatch, against
        // the shadow the model left behind -- then adopted from the
        // trace, so the comparison stays grounded on ground truth. The
        // window is the one the convention's stack register is read
        // around, which is why the tracer records both. A row with no
        // successor has no observation to compare against and none to
        // adopt; the shadow still holds the state the row was entered
        // with, which is what its instantiation is read from.
        if (has_next) {
            std::uint64_t cur_stack = 0;
            std::uint64_t prev_stack = 0;
            const bool cur_ok = tf.stack(cur, &cur_stack);
            const bool prev_ok = tf.stack(prev, &prev_stack);
            const std::uint64_t base =
                cur_ok ? (cur_stack & ~std::uint64_t{7}) : 0;
            const std::vector<std::uint64_t> cells = tf.slot_cells(cur);
            for (std::size_t k = 0; k < cells.size(); ++k) {
                const std::uint64_t addr =
                    base + 8 * static_cast<std::uint64_t>(k);
                const std::int64_t disp =
                    prev_ok ? static_cast<std::int64_t>(addr) -
                                  static_cast<std::int64_t>(prev_stack)
                            : 0;
                std::uint64_t got = 0;
                const bool known = shadow.read(addr, &got);
                record("vst[" + std::to_string(disp) + "]", known, got,
                       cells[k]);
            }
            if (cur_ok && !cells.empty()) {
                shadow.adopt(cur_stack, cells);
            }
        }

        // The row as the run saw it. The binding is complete here -- every
        // input of the model has had its turn -- so what is rendered is
        // the step the machine took, not the schema it took it from.
        if (instantiated != nullptr) {
            InstantiatedRow row;
            row.seq = prev.seq;
            row.handler_va = h.va;
            expr::Bindings bound;
            bound.values = b.values;
            bound.known.assign(b.bound.size(), false);
            // What the row's own effects reach. The machine registers
            // every flag a handler might have read, and most handlers read
            // none: counting those as unpinned would say every row is
            // partly unknown for a reason that has nothing to do with the
            // row. Only the inputs the effects actually name are the
            // question "did the run pin this step down".
            std::vector<unsigned> reached;
            const auto reach = [&](expr::Id id) {
                if (id == expr::kNoId) {
                    return;
                }
                for (const unsigned o : model.dag.inputs_of(id)) {
                    if (std::find(reached.begin(), reached.end(), o) ==
                        reached.end()) {
                        reached.push_back(o);
                    }
                }
            };
            for (const Handler::Write& wr : h.writes) {
                reach(wr.value);
                if (!wr.to_slot) {
                    reach(wr.addr);
                }
            }
            reach(h.target_expr);
            row.inputs_total = static_cast<unsigned>(reached.size());
            for (std::size_t k = 0; k < b.bound.size(); ++k) {
                bound.known[k] = b.bound[k] != 0;
            }
            for (const unsigned o : reached) {
                if (bound.has(o)) {
                    ++row.inputs_bound;
                }
            }
            for (const Handler::Write& wr : h.writes) {
                const std::string value = instantiate(wr.value, bound);
                if (wr.to_slot) {
                    row.writes.push_back("vst[" + std::to_string(wr.disp) +
                                         "] = " + value);
                } else {
                    row.writes.push_back(
                        address_label(model, wr.addr, wr.width, &bound) +
                        " = " + value);
                }
            }
            if (h.target_expr != expr::kNoId) {
                row.transfer = instantiate(h.target_expr, bound);
            }
            instantiated->push_back(std::move(row));
        }
    }
    out.worst_handlers.reserve(failures_by_handler.size());
    for (const auto& [va, count] : failures_by_handler) {
        out.worst_handlers.push_back(Conformance::PerHandler{va, count});
    }
    std::sort(out.worst_handlers.begin(), out.worst_handlers.end(),
              [](const Conformance::PerHandler& a,
                 const Conformance::PerHandler& b) {
                  if (a.count != b.count) {
                      return a.count > b.count;
                  }
                  return a.va < b.va;
              });
    return out;
}

void TraceMemory::add(std::uint64_t va, std::vector<std::uint8_t> bytes) {
    if (bytes.empty()) {
        return;
    }
    // A trace the tracer wrote holds each window once, so the windows do
    // not overlap. Two that do are a hand-built reader's doing, and the
    // record fed second is the later read of those bytes: it wins wherever
    // it covers, so an earlier window is cut back to the parts of itself
    // this record does not reach rather than dropped whole or left to
    // shadow the newer bytes.
    const std::uint64_t from = va;
    const std::uint64_t to = va + bytes.size();
    std::vector<Window> kept;
    kept.reserve(windows.size() + 2);
    for (Window& w : windows) {
        const std::uint64_t wfrom = w.va;
        const std::uint64_t wto = w.va + w.bytes.size();
        if (wto <= from || wfrom >= to) {
            kept.push_back(std::move(w));
            continue;
        }
        if (wfrom < from) {
            kept.push_back(Window{
                wfrom, std::vector<std::uint8_t>(
                           w.bytes.begin(),
                           w.bytes.begin() + static_cast<std::ptrdiff_t>(
                                                  from - wfrom))});
        }
        if (wto > to) {
            kept.push_back(Window{
                to, std::vector<std::uint8_t>(
                        w.bytes.begin() + static_cast<std::ptrdiff_t>(to - wfrom),
                        w.bytes.end())});
        }
    }
    kept.push_back(Window{va, std::move(bytes)});
    std::sort(kept.begin(), kept.end(),
              [](const Window& a, const Window& b) { return a.va < b.va; });
    windows = std::move(kept);
}

bool TraceMemory::read(std::uint64_t va, unsigned width,
                       std::uint64_t* out) const {
    if (va == 0 || width == 0 || width % 8 != 0) {
        return false;
    }
    const std::size_t n = width / 8;
    if (n > 8) {
        return false;
    }
    for (const Window& w : windows) {
        // The windows are sorted, so the first one that starts above the
        // read ends the search: no later window can cover it either.
        if (va < w.va) {
            break;
        }
        if (va - w.va > w.bytes.size() || n > w.bytes.size() - (va - w.va)) {
            continue;
        }
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < n; ++i) {
            v |= static_cast<std::uint64_t>(w.bytes[va - w.va + i])
                 << (8 * i);
        }
        *out = v;
        return true;
    }
    return false;
}

std::string render(const Model& model, expr::Id id,
                   const expr::Bindings* bound) {
    if (id == expr::kNoId) {
        return "?";
    }
    return bound != nullptr ? model.dag.pretty_bound(id, *bound)
                            : model.dag.pretty(id);
}

namespace {

// The name of the operation a handler performs, from the top of the value
// it wrote. A resize only changes the width, so it is stepped through:
// the operation under it is the one that names the effect.
const char* effect_op_name(expr::Op op) {
    switch (op) {
        case expr::Op::Add: return "add";
        case expr::Op::Sub: return "sub";
        case expr::Op::Mul: return "imul";
        case expr::Op::And: return "and";
        case expr::Op::Or: return "or";
        case expr::Op::Xor: return "xor";
        case expr::Op::Shl: return "shl";
        case expr::Op::Shr: return "shr";
        case expr::Op::Sar: return "sar";
        case expr::Op::Not: return "not";
        case expr::Op::Neg: return "neg";
        case expr::Op::Select: return "select";
        case expr::Op::CmpEQ: return "eq";
        case expr::Op::CmpULT: return "lt";
        case expr::Op::CmpSLT: return "slt";
        case expr::Op::Const:
        case expr::Op::Input:
        case expr::Op::Resize:
            break;
    }
    return "mov";
}

const char* transfer_name(Handler::Transfer t) {
    switch (t) {
        case Handler::Transfer::Dispatch: return "dispatch";
        case Handler::Transfer::Return: return "return";
        case Handler::Transfer::Call: return "call";
        case Handler::Transfer::Unknown: break;
    }
    return "";
}

}  // namespace

std::string effect_label(const Model& model, const Handler& handler) {
    std::string label;
    // A handler is one virtual instruction, so it has one effect. The
    // first cell it wrote is the one that names it: the later writes are
    // the rest of the same slot's bytes, or the pointer's own move.
    if (!handler.writes.empty()) {
        expr::Id id = handler.writes.front().value;
        while (model.dag.valid(id)) {
            const expr::Op op = model.dag.node(id).op;
            if (op != expr::Op::Resize) {
                label = effect_op_name(op);
                break;
            }
            id = model.dag.node(id).a;
        }
        if (label.empty()) {
            label = "mov";
        }
    }
    // Where it goes, when the handler itself decided that.
    const char* const t = transfer_name(handler.transfer);
    if (*t != '\0') {
        if (!label.empty()) {
            label += " -> ";
        }
        label += t;
    }
    return label.empty() ? std::string("?") : label;
}

namespace {

// Steps through the resizes a width change wraps an access in: `(32)(...)`
// is the same value at a different width, and it is the value that indexes
// the file.
expr::Id strip_resize(const Model& model, expr::Id id) {
    while (model.dag.valid(id) && model.dag.node(id).op == expr::Op::Resize) {
        id = model.dag.node(id).a;
    }
    return id;
}

// The index of an access whose address is `base + index*scale`, when
// `base` is the register the caller named and the step matches what it
// walks: one byte for a stream, more for a file of elements. kNoId when
// the address is not of that form -- and then the model has an address,
// not a slot, which is a different thing and has to read as one.
expr::Id indexed_by(const Model& model, expr::Id addr,
                    const std::string& base, bool bytes) {
    if (base.empty() || !model.dag.valid(addr)) {
        return expr::kNoId;
    }
    const expr::Node& n = model.dag.node(addr);
    if (n.op != expr::Op::Add) {
        return expr::kNoId;
    }
    const auto is_base = [&](expr::Id id) {
        return model.dag.valid(id) &&
               model.dag.node(id).op == expr::Op::Input &&
               model.dag.node(id).name == base;
    };
    const auto stepped = [&](expr::Id step_side,
                             expr::Id index_side) -> expr::Id {
        if (!model.dag.is_const(step_side)) {
            return expr::kNoId;
        }
        const std::uint64_t step = model.dag.const_value(step_side);
        if ((bytes && step != 1) || (!bytes && step <= 1)) {
            return expr::kNoId;
        }
        return strip_resize(model, index_side);
    };
    const auto scaled = [&](expr::Id id) -> expr::Id {
        if (!model.dag.valid(id)) {
            return expr::kNoId;
        }
        const expr::Node& m = model.dag.node(id);
        if (m.op == expr::Op::Mul) {
            // The step is the constant half and the index is the other.
            const expr::Id a = stepped(m.b, m.a);
            return a != expr::kNoId ? a : stepped(m.a, m.b);
        }
        // A step of one is folded away -- `base + index*1` simplifies to
        // `base + index` -- so a bare index is how a byte stream's access
        // arrives here. A file of wider elements never does: its step is
        // not one, and the multiply survives.
        return bytes ? strip_resize(model, id) : expr::kNoId;
    };
    if (is_base(n.a)) {
        return scaled(n.b);
    }
    if (is_base(n.b)) {
        return scaled(n.a);
    }
    return expr::kNoId;
}

std::string clipped(const std::string& text) {
    return text.size() <= 40 ? text : text.substr(0, 37) + "...";
}

}  // namespace

std::string address_label(const Model& model, expr::Id addr, unsigned width,
                          const expr::Bindings* bound) {
    // One rendering rule for the whole label: with a binding, an index the
    // run fixed prints as the number it was, so the label says `vst[3]`
    // and not the arithmetic that arrived there.
    const auto text = [&](expr::Id id) {
        return bound != nullptr ? bound_text(model, id, *bound)
                                : model.dag.pretty(id);
    };
    expr::Id index = indexed_by(model, addr, model.convention.regfile, false);
    if (index != expr::kNoId) {
        return "vst[" + clipped(text(index)) + "]";
    }
    index = indexed_by(model, addr, model.convention.code, true);
    if (index != expr::kNoId) {
        return "code[" + clipped(text(index)) + "]";
    }
    char b[16];
    std::snprintf(b, sizeof(b), "mem%u[", width);
    return std::string(b) + clipped(text(addr)) + "]";
}

}  // namespace occ::devirt::lift
// A self-contained interpreter for x86-64 integer code.
//
// The design is in the header; this file is the operand decoder and the
// execution loop. The length decoder is `dbi`'s; everything below a
// length -- prefixes, operands, effects, flags -- is here.
//
// The execution model is a small step loop: decode a length, parse the
// instruction's shape, apply its effect to the register file and the
// memory image, advance rip. The flag semantics are computed per
// operation width, because x86 flags are width-dependent and a 32-bit add
// that carries must not set the 64-bit carry. The stack is just memory
// with RSP moving; call pushes the return address and ret pops one.
//
// Two decisions deserve the reader's attention:
//
//   * The address-size prefix (67) is refused. 64-bit compiler code
//     almost never emits it, and getting it wrong misaddresses memory;
//     a refusal names itself instead.
//   * A control transfer that leaves the interpreted region is reported
//     as a normal end with the target in `cpu.rip`. The caller owns what
//     happens next -- this runtime's usual answer is to interpret the
//     target region too, or to refuse. Stopping at the region edge is
//     the honest default: interpreting bytes the caller did not name as
//     code is the caller's decision, not this module's.

#include "occ/emu/emu.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace occ::emu {

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

bool Memory::load(std::uint64_t addr, void* dst, std::size_t n) const noexcept {
    if (n == 0) {
        return true;
    }
    if (addr < base) {
        return false;
    }
    const std::uint64_t off = addr - base;
    if (off > bytes.size() || n > bytes.size() - static_cast<std::size_t>(off)) {
        return false;
    }
    std::memcpy(dst, bytes.data() + static_cast<std::size_t>(off), n);
    return true;
}

bool Memory::store(std::uint64_t addr, const void* src,
                   std::size_t n) noexcept {
    if (n == 0) {
        return true;
    }
    if (addr < base) {
        return false;
    }
    const std::uint64_t off = addr - base;
    if (off > bytes.size() || n > bytes.size() - static_cast<std::size_t>(off)) {
        return false;
    }
    std::memcpy(bytes.data() + static_cast<std::size_t>(off), src, n);
    return true;
}

// ---------------------------------------------------------------------------
// Instruction shape
// ---------------------------------------------------------------------------

namespace {

// Prefixes, re-read here for the semantics (the length decoder already
// consumed them; this is a second read of the same bytes, which is
// cheaper than threading a struct through).
struct Pre {
    bool rex_w = false;
    bool rex_b = false;
    bool rex_x = false;
    bool rex_r = false;
    bool p66 = false;
    bool f3 = false;
    bool f2 = false;
};

[[nodiscard]] Pre parse_prefixes(const std::uint8_t* p, std::size_t avail,
                                 std::size_t& n) noexcept {
    Pre pre;
    n = 0;
    for (;;) {
        if (n >= avail) {
            break;
        }
        const std::uint8_t b = p[n];
        if (b == 0x66) {
            pre.p66 = true;
        } else if (b == 0xF3) {
            pre.f3 = true;
        } else if (b == 0xF2) {
            pre.f2 = true;
        } else if (b == 0x67) {
            // The address-size prefix: see the header. Refused by the
            // caller; here it is merely noted by being consumed.
        } else if (b >= 0x40 && b <= 0x4F) {
            pre.rex_w = (b & 0x08) != 0;
            pre.rex_r = (b & 0x04) != 0;
            pre.rex_x = (b & 0x02) != 0;
            pre.rex_b = (b & 0x01) != 0;
        } else {
            break;
        }
        ++n;
    }
    return pre;
}

// An operand resolved to a value (register or memory or immediate).
struct Operand {
    // For a register operand, the register index plus `wide` (64-bit);
    // for memory, the computed address; for immediate, the value.
    std::uint64_t val = 0;
    std::uint8_t reg = 0; // Register index when `is_reg`.
    bool is_reg = false;
    bool wide = false; // 64-bit operand (REX.W).
    bool is_mem = false; // Memory operand; `val` is the address.
    bool is_imm = false;
};

// The ModRM/SIB addressing that every memory form shares. `regext` names
// the register field (REX.R applied), `rmext` the r/m field (REX.B
// applied).
struct Addr {
    bool is_reg = false;
    std::uint8_t reg = 0; // The register field, REX.R applied.
    std::uint8_t rm = 0; // The r/m register, REX.B applied.
    bool has_sib = false;
    std::uint8_t sib_scale = 0;
    std::uint8_t sib_index = 0;
    std::uint8_t sib_base = 0;
    bool rip_rel = false;
    std::int64_t disp = 0;
    std::uint32_t extra = 0; // Bytes consumed after the ModRM byte.
};

// Parses the ModRM/SIB/displacement of a memory or register operand.
// `at` points at the ModRM byte; returns false on an impossible encoding.
// The displacement is parsed but not resolved: RIP-relative targets are
// resolved against the following instruction by the caller.
[[nodiscard]] bool parse_modrm(const std::uint8_t* p, std::size_t avail,
                               std::size_t at, const Pre& pre,
                               Addr& a) noexcept {
    if (at >= avail) {
        return false;
    }
    const std::uint8_t m = p[at];
    const std::uint32_t mod = (m >> 6) & 3;
    const std::uint32_t regf = (m >> 3) & 7;
    const std::uint32_t rm = m & 7;
    a.reg = static_cast<std::uint8_t>(regf | (pre.rex_r ? 8 : 0));
    a.rm = static_cast<std::uint8_t>(rm | (pre.rex_b ? 8 : 0));
    std::size_t at2 = at + 1;
    if (mod == 3) {
        a.is_reg = true;
        a.extra = 1;
        return true;
    }
    a.is_reg = false;
    if (rm == 4) {
        // SIB.
        if (at2 >= avail) {
            return false;
        }
        const std::uint8_t s = p[at2];
        ++at2;
        a.has_sib = true;
        a.sib_scale = static_cast<std::uint8_t>(1u << ((s >> 6) & 3));
        const std::uint32_t index = (s >> 3) & 7;
        const std::uint32_t base = s & 7;
        a.sib_index = static_cast<std::uint8_t>(index | (pre.rex_x ? 8 : 0));
        a.sib_base = static_cast<std::uint8_t>(base | (pre.rex_b ? 8 : 0));
        if (mod == 0 && base == 5) {
            // disp32 with no base register.
            if (at2 + 4 > avail) {
                return false;
            }
            std::int32_t d = 0;
            std::memcpy(&d, p + at2, 4);
            at2 += 4;
            a.disp = d;
        } else if (mod == 1) {
            if (at2 >= avail) {
                return false;
            }
            a.disp = static_cast<std::int8_t>(p[at2]);
            ++at2;
        } else if (mod == 2) {
            if (at2 + 4 > avail) {
                return false;
            }
            std::int32_t d = 0;
            std::memcpy(&d, p + at2, 4);
            at2 += 4;
            a.disp = d;
        }
    } else if (mod == 0 && rm == 5) {
        // RIP-relative.
        if (at2 + 4 > avail) {
            return false;
        }
        std::int32_t d = 0;
        std::memcpy(&d, p + at2, 4);
        at2 += 4;
        a.rip_rel = true;
        a.disp = d;
    } else {
        if (mod == 1) {
            if (at2 >= avail) {
                return false;
            }
            a.disp = static_cast<std::int8_t>(p[at2]);
            ++at2;
        } else if (mod == 2) {
            if (at2 + 4 > avail) {
                return false;
            }
            std::int32_t d = 0;
            std::memcpy(&d, p + at2, 4);
            at2 += 4;
            a.disp = d;
        }
    }
    a.extra = static_cast<std::uint32_t>(at2 - at);
    return true;
}

// Resolves an addressing form to an address. `next_rip` is the address
// of the following instruction, used for RIP-relative addressing.
[[nodiscard]] bool resolve_addr(const Addr& a, const Cpu& cpu,
                                std::uint64_t next_rip, std::uint64_t base,
                                std::uint64_t& out) noexcept {
    (void)base; // Guest addresses are absolute; the image is already
                // mapped at `base`, so register/imm values are absolute.
    if (a.rip_rel) {
        out = static_cast<std::uint64_t>(
            static_cast<std::int64_t>(next_rip) + a.disp);
        return true;
    }
    std::uint64_t addr = 0;
    if (a.has_sib) {
        addr = cpu.reg[a.sib_base];
        if (a.sib_index != 4) { // rsp as index means "none".
            addr += cpu.reg[a.sib_index] * a.sib_scale;
        }
    } else {
        addr = cpu.reg[a.rm];
    }
    out = static_cast<std::uint64_t>(
        static_cast<std::int64_t>(addr) + a.disp);
    return true;
}

// The signed/unsigned flag updates for an addition or subtraction of the
// given width. `result` is the truncated result; `wide` selects 64-bit.
struct Flags {
    std::uint32_t bits = 0;
};

[[nodiscard]] std::uint8_t parity_of(std::uint8_t v) noexcept {
    // Even parity sets PF. A fold is honest here: four shifts and three
    // xors beat a hand-written 256-entry table that is easy to mistype.
    v ^= v >> 4;
    v ^= v >> 2;
    v ^= v >> 1;
    return (v & 1) == 0 ? 1 : 0;
}

// Computes the flags an add/sub-family operation sets. `lhs`, `rhs` and
// `res` are the (possibly untruncated) operands; `carry_in` is 1 for
// adc/sbb. The borrow and carry are computed on the masked values, which
// is what the hardware's widths agree on.
[[nodiscard]] std::uint32_t add_flags(std::uint64_t lhs, std::uint64_t rhs,
                                      std::uint64_t res, unsigned bits,
                                      bool is_sub, unsigned carry_in) noexcept {
    std::uint32_t f = 0;
    const std::uint64_t mask = (bits == 64) ? ~std::uint64_t{0}
                                            : ((std::uint64_t{1} << bits) - 1);
    const unsigned sign = bits - 1;
    const bool l = (lhs >> sign) & 1;
    const bool r = (rhs >> sign) & 1;
    const bool s = (res >> sign) & 1;
    const std::uint64_t lm = lhs & mask;
    const std::uint64_t rm = rhs & mask;
    if (is_sub) {
        const std::uint64_t rd = (rm + carry_in) & mask;
        const bool borrow = lm < rd;
        f |= borrow ? kFlagCF : 0;
        const bool ov = (l != r) && (s != l);
        f |= ov ? kFlagOF : 0;
    } else {
        const std::uint64_t sm = (lm + rm + carry_in) & mask;
        const bool carry = sm < lm || (carry_in != 0 && sm == lm && rm == mask);
        f |= carry ? kFlagCF : 0;
        const bool ov = (l == r) && (s != l);
        f |= ov ? kFlagOF : 0;
    }
    const std::uint8_t low = static_cast<std::uint8_t>(res);
    f |= (res & mask) == 0 ? kFlagZF : 0;
    f |= s != 0 ? kFlagSF : 0;
    f |= parity_of(low) ? kFlagPF : 0;
    // AF: carry out of bit 3.
    const bool a = ((lhs ^ rhs ^ res) & 0x10) != 0;
    f |= a ? kFlagAF : 0;
    return f;
}

// The width an operand decodes to: bytes and a mask.
struct Width {
    unsigned bytes = 4;
    unsigned bits = 32;
    std::uint64_t mask = 0xFFFFFFFFull;
};

[[nodiscard]] Width width_of(const Pre& pre, bool byte_form) noexcept {
    Width w;
    if (byte_form) {
        w.bytes = 1;
        w.bits = 8;
        w.mask = 0xFF;
        return w;
    }
    if (pre.rex_w) {
        w.bytes = 8;
        w.bits = 64;
        w.mask = ~std::uint64_t{0};
        return w;
    }
    if (pre.p66) {
        w.bytes = 2;
        w.bits = 16;
        w.mask = 0xFFFF;
        return w;
    }
    return w;
}

// Reads a register, honoring the operand width (the upper bits of a
// 32-bit read are cleared by the hardware; the interpreter honors that).
[[nodiscard]] std::uint64_t read_reg(const Cpu& cpu, std::uint8_t idx,
                                     const Width& w) noexcept {
    return cpu.reg[idx] & w.mask;
}

// The effective address of the r/m operand, or the register value.
struct Eff {
    bool is_reg = false;
    std::uint8_t reg = 0;
    std::uint64_t addr = 0;
};

[[nodiscard]] bool eff_of(const Addr& a, const Cpu& cpu,
                          std::uint64_t next_rip, std::uint64_t base,
                          Eff& e) noexcept {
    if (a.is_reg) {
        e.is_reg = true;
        e.reg = a.rm; // The r/m field with REX.B applied.
        return true;
    }
    return resolve_addr(a, cpu, next_rip, base, e.addr);
}

} // namespace

// ---------------------------------------------------------------------------
// The interpreter
// ---------------------------------------------------------------------------

namespace {

struct EmuState {
    const std::uint8_t* code = nullptr;
    std::size_t size = 0;
    std::uint64_t base = 0;
    Cpu* cpu = nullptr;
    Memory* mem = nullptr;
    const char* detail = nullptr;
};

// Loads an operand of the given width from memory.
[[nodiscard]] bool load_operand(EmuState& s, const Eff& e, const Width& w,
                                std::uint64_t& out) noexcept {
    if (e.is_reg) {
        out = read_reg(*s.cpu, e.reg, w);
        return true;
    }
    if (!s.mem->load(e.addr, &out, w.bytes)) {
        s.detail = "load outside the memory image";
        return false;
    }
    out &= w.mask;
    return true;
}

// Stores a value of the given width.
[[nodiscard]] bool store_operand(EmuState& s, const Eff& e, const Width& w,
                                 std::uint64_t v) noexcept {
    if (e.is_reg) {
        if (w.bytes < 8) {
            // Upper bits of the register are preserved by the hardware
            // for 8/16-bit writes and cleared for 32-bit writes.
            if (w.bytes == 4) {
                s.cpu->reg[e.reg] = v & w.mask;
            } else {
                const std::uint64_t keep = ~w.mask;
                s.cpu->reg[e.reg] = (s.cpu->reg[e.reg] & keep) | (v & w.mask);
            }
        } else {
            s.cpu->reg[e.reg] = v;
        }
        return true;
    }
    return s.mem->store(e.addr, &v, w.bytes);
}

// The condition code test for the Jcc/setcc/CMOVcc family.
[[nodiscard]] bool test_cond(std::uint32_t cc, const Cpu& cpu) noexcept {
    const std::uint32_t f = cpu.rflags;
    switch (cc & 0x0E) {
    case 0x00: // o
        return (f & kFlagOF) != 0;
    case 0x02: // b/c/nae
        return (f & kFlagCF) != 0;
    case 0x04: // z/e
        return (f & kFlagZF) != 0;
    case 0x06: // be/na
        return (f & (kFlagCF | kFlagZF)) != 0;
    case 0x08: // s
        return (f & kFlagSF) != 0;
    case 0x0A: // p/pe
        return (f & kFlagPF) != 0;
    case 0x0C: // l/nge
        return ((f & kFlagSF) != 0) != ((f & kFlagOF) != 0);
    case 0x0E: // le/ng
        return ((f & kFlagSF) != 0) != ((f & kFlagOF) != 0) ||
               (f & kFlagZF) != 0;
    default:
        return false;
    }
}

// The branch taken form of a condition: cc & 1 selects the negated test.
[[nodiscard]] bool cond_taken(std::uint32_t cc, const Cpu& cpu) noexcept {
    const bool base = test_cond(cc & 0xFE, cpu);
    return ((cc & 1) != 0) ? !base : base;
}

// Executes one instruction at `at` (offset into the region). Returns
// true when the instruction was recognized and executed; false when it
// was refused (with `out.stop` set and `out.halt` naming the reason).
struct ExecOut {
    bool stop = false;
    Halt halt = Halt::None;
    std::uint32_t len = 0;
    // Whether the instruction set rip itself (a taken branch, call, jmp
    // or ret). The run loop advances rip by the length only when this is
    // false; "the target equals the current rip" is a legitimate taken
    // branch (a jmp to itself), so equality cannot be the test.
    bool transferred = false;
};

[[nodiscard]] bool execute_one(EmuState& s, std::size_t at,
                               ExecOut& out) noexcept {
    const std::uint8_t* p = s.code + at;
    const std::size_t avail = s.size - at;
    dbi::DecodedInsn di;
    if (!dbi::decode_insn(p, avail, di)) {
        s.detail = "instruction outside the interpreted family";
        out.stop = true;
        out.halt = Halt::Unknown;
        return false;
    }
    out.len = di.len;
    const std::uint64_t rip = s.base + at;
    std::size_t pren = 0;
    const Pre pre = parse_prefixes(p, avail, pren);
    if (pren + 1 > avail) {
        s.detail = "truncated instruction";
        out.stop = true;
        out.halt = Halt::Unknown;
        return false;
    }
    // Reject the address-size prefix: see the header.
    {
        std::size_t q = 0;
        while (q < pren) {
            if (p[q] == 0x67) {
                s.detail = "address-size prefix refused";
                out.stop = true;
                out.halt = Halt::Unknown;
                return false;
            }
            ++q;
        }
    }
    const std::uint8_t op1 = p[pren];
    const std::size_t after_op1 = pren + 1;
    const std::uint64_t next_rip = rip + di.len;

    // Resolves the ModRM operand, or reports none.
    const auto modrm = [&](Addr& a, std::size_t base_at) -> bool {
        return parse_modrm(p, avail, base_at, pre, a);
    };

    // The one-operand r/m form (memory or register).
    const auto eff = [&](const Addr& a, Eff& e) -> bool {
        return eff_of(a, *s.cpu, next_rip, s.base, e);
    };

    Width w;
    const auto setw = [&](bool byte) { w = width_of(pre, byte); };

    // ------------------------------------------------------------------
    // The opcode families. Each returns true when it handled the
    // instruction (including a control transfer); false means "not this
    // family".
    // ------------------------------------------------------------------

    // ALU r/m, r (00-3F): the eight operations in the order add, or,
    // adc, sbb, and, sub, xor, cmp; op&0x38 selects, op&7 selects the
    // form (00 r/m8,r8 01 r/m,r 02 r8,r/m8 03 r,r/m 04 al,imm 05 eax,imm
    // 06-07 push/popp es -- not in 64-bit mode). Only 00-03 and 04-05
    // are interpreted.
    auto alu_rm_r = [&](std::uint8_t op) -> bool {
        const std::uint32_t group = (op >> 3) & 7;
        const std::uint32_t form = op & 7;
        if (form > 3) {
            return false;
        }
        const bool byte = (form == 0 || form == 2);
        setw(byte);
        Addr a;
        Eff a_eff;
        if (!modrm(a, after_op1)) {
            return false;
        }
        if (!eff(a, a_eff)) {
            s.detail = "bad addressing";
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        std::uint64_t lhs = 0;
        std::uint64_t rhs = 0;
        if (form == 0 || form == 1) {
            // r/m op r: lhs = r/m, rhs = reg.
            if (!load_operand(s, a_eff, w, lhs) ||
                !load_operand(s, Eff{true, a.reg, 0}, w, rhs)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
        } else {
            // r op r/m: lhs = reg, rhs = r/m.
            if (!load_operand(s, Eff{true, a.reg, 0}, w, lhs) ||
                !load_operand(s, a_eff, w, rhs)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
        }
        std::uint64_t res = 0;
        switch (group) {
        case 0: // add
            res = (lhs + rhs) & w.mask;
            s.cpu->rflags = add_flags(lhs, rhs, res, w.bits, false, 0);
            break;
        case 1: // or
            res = (lhs | rhs) & w.mask;
            s.cpu->rflags = (res == 0 ? kFlagZF : 0) |
                            ((res >> (w.bits - 1)) ? kFlagSF : 0) |
                            (parity_of(static_cast<std::uint8_t>(res))
                                ? kFlagPF
                                : 0);
            break;
        case 2: // adc
            res = (lhs + rhs + ((s.cpu->rflags & kFlagCF) ? 1 : 0)) & w.mask;
            s.cpu->rflags = add_flags(lhs, rhs, res, w.bits, false,
                                      (s.cpu->rflags & kFlagCF) ? 1 : 0);
            break;
        case 3: // sbb
            res = (lhs - rhs - ((s.cpu->rflags & kFlagCF) ? 1 : 0)) & w.mask;
            s.cpu->rflags = add_flags(lhs, rhs, res, w.bits, true,
                                      (s.cpu->rflags & kFlagCF) ? 1 : 0);
            break;
        case 4: // and
            res = (lhs & rhs) & w.mask;
            s.cpu->rflags = (res == 0 ? kFlagZF : 0) |
                            ((res >> (w.bits - 1)) ? kFlagSF : 0) |
                            (parity_of(static_cast<std::uint8_t>(res))
                                ? kFlagPF
                                : 0);
            break;
        case 5: // sub
            res = (lhs - rhs) & w.mask;
            s.cpu->rflags = add_flags(lhs, rhs, res, w.bits, true, 0);
            break;
        case 6: // xor
            res = (lhs ^ rhs) & w.mask;
            s.cpu->rflags = (res == 0 ? kFlagZF : 0) |
                            ((res >> (w.bits - 1)) ? kFlagSF : 0) |
                            (parity_of(static_cast<std::uint8_t>(res))
                                ? kFlagPF
                                : 0);
            break;
        case 7: // cmp: same as sub but no store.
            res = (lhs - rhs) & w.mask;
            s.cpu->rflags = add_flags(lhs, rhs, res, w.bits, true, 0);
            break;
        }
        if (group != 7) {
            if (!store_operand(s, a_eff, w, res)) {
                s.detail = "store outside the memory image";
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
        }
        return true;
    };

    // ALU r/m, imm (80-83) and test (F6 /0).
    auto alu_rm_imm = [&](std::uint8_t op) -> bool {
        Addr a;
        if (!modrm(a, after_op1)) {
            return false;
        }
        const bool byte = (op == 0x80 || op == 0x82 || op == 0xF6);
        setw(byte);
        Eff a_eff;
        if (!eff(a, a_eff)) {
            return false;
        }
        const std::uint32_t regf = a.reg & 7;
        std::uint64_t lhs = 0;
        if (!load_operand(s, a_eff, w, lhs)) {
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        // The immediate follows the ModRM/SIB/disp bytes.
        const std::size_t imm_at = after_op1 + a.extra;
        if (imm_at >= avail) {
            return false;
        }
        std::uint64_t rhs = 0;
        if (op == 0x83) {
            // 83 always uses a sign-extended imm8, at every operand
            // width (including the 16-bit form, where imm8 sign-extends
            // to 16 bits).
            if (imm_at >= avail) {
                return false;
            }
            rhs = static_cast<std::uint64_t>(
                static_cast<std::int64_t>(static_cast<std::int8_t>(p[imm_at])));
        } else if (w.bytes == 1) {
            rhs = p[imm_at];
        } else if (w.bytes == 2) {
            if (imm_at + 2 > avail) {
                return false;
            }
            std::memcpy(&rhs, p + imm_at, 2);
        } else if (w.bytes == 4 || w.bytes == 8) {
            if (imm_at + 4 > avail) {
                return false;
            }
            std::int32_t v = 0;
            std::memcpy(&v, p + imm_at, 4);
            // imm32 sign-extended; the mask truncates it back to the
            // operand width.
            rhs = static_cast<std::uint64_t>(v) & w.mask;
        } else {
            rhs = 0;
        }
        rhs &= w.mask;
        std::uint64_t res = 0;
        switch (regf) {
        case 0: // add
            res = (lhs + rhs) & w.mask;
            s.cpu->rflags = add_flags(lhs, rhs, res, w.bits, false, 0);
            break;
        case 1: // or
            res = (lhs | rhs) & w.mask;
            s.cpu->rflags = (res == 0 ? kFlagZF : 0) |
                            ((res >> (w.bits - 1)) ? kFlagSF : 0) |
                            (parity_of(static_cast<std::uint8_t>(res))
                                ? kFlagPF
                                : 0);
            break;
        case 2: // adc
            res = (lhs + rhs + ((s.cpu->rflags & kFlagCF) ? 1 : 0)) & w.mask;
            s.cpu->rflags = add_flags(lhs, rhs, res, w.bits, false,
                                      (s.cpu->rflags & kFlagCF) ? 1 : 0);
            break;
        case 3: // sbb
            res = (lhs - rhs - ((s.cpu->rflags & kFlagCF) ? 1 : 0)) & w.mask;
            s.cpu->rflags = add_flags(lhs, rhs, res, w.bits, true,
                                      (s.cpu->rflags & kFlagCF) ? 1 : 0);
            break;
        case 4: // and
            res = (lhs & rhs) & w.mask;
            s.cpu->rflags = (res == 0 ? kFlagZF : 0) |
                            ((res >> (w.bits - 1)) ? kFlagSF : 0) |
                            (parity_of(static_cast<std::uint8_t>(res))
                                ? kFlagPF
                                : 0);
            break;
        case 5: // sub
            res = (lhs - rhs) & w.mask;
            s.cpu->rflags = add_flags(lhs, rhs, res, w.bits, true, 0);
            break;
        case 6: // xor
            res = (lhs ^ rhs) & w.mask;
            s.cpu->rflags = (res == 0 ? kFlagZF : 0) |
                            ((res >> (w.bits - 1)) ? kFlagSF : 0) |
                            (parity_of(static_cast<std::uint8_t>(res))
                                ? kFlagPF
                                : 0);
            break;
        case 7: // cmp
            res = (lhs - rhs) & w.mask;
            s.cpu->rflags = add_flags(lhs, rhs, res, w.bits, true, 0);
            break;
        }
        if (regf != 7) {
            if (!store_operand(s, a_eff, w, res)) {
                s.detail = "store outside the memory image";
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
        }
        return true;
    };

    // ALU al/eax, imm (04/05/0C/0D/14/15/1C/1D/24/25/2C/2D/34/35/3C/3D).
    auto alu_acc_imm = [&](std::uint8_t op) -> bool {
        const bool byte = (op & 1) == 0;
        setw(byte);
        const std::uint32_t group = (op >> 3) & 7;
        const std::size_t imm_at = after_op1;
        std::uint64_t rhs = 0;
        if (w.bytes == 1) {
            if (imm_at >= avail) {
                return false;
            }
            rhs = p[imm_at];
        } else if (w.bytes == 4) {
            if (imm_at + 4 > avail) {
                return false;
            }
            std::int32_t v = 0;
            std::memcpy(&v, p + imm_at, 4);
            rhs = static_cast<std::uint64_t>(v) & w.mask;
        } else if (w.bytes == 2) {
            if (imm_at + 2 > avail) {
                return false;
            }
            std::memcpy(&rhs, p + imm_at, 2);
        } else {
            return false;
        }
        const std::uint64_t lhs = read_reg(*s.cpu, RAX, w);
        std::uint64_t res = 0;
        switch (group) {
        case 0: // add
            res = (lhs + rhs) & w.mask;
            s.cpu->rflags = add_flags(lhs, rhs, res, w.bits, false, 0);
            break;
        case 1: // or
            res = (lhs | rhs) & w.mask;
            s.cpu->rflags = (res == 0 ? kFlagZF : 0) |
                            ((res >> (w.bits - 1)) ? kFlagSF : 0) |
                            (parity_of(static_cast<std::uint8_t>(res))
                                ? kFlagPF
                                : 0);
            break;
        case 2: // adc
            res = (lhs + rhs + ((s.cpu->rflags & kFlagCF) ? 1 : 0)) & w.mask;
            s.cpu->rflags = add_flags(lhs, rhs, res, w.bits, false,
                                      (s.cpu->rflags & kFlagCF) ? 1 : 0);
            break;
        case 3: // sbb
            res = (lhs - rhs - ((s.cpu->rflags & kFlagCF) ? 1 : 0)) & w.mask;
            s.cpu->rflags = add_flags(lhs, rhs, res, w.bits, true,
                                      (s.cpu->rflags & kFlagCF) ? 1 : 0);
            break;
        case 4: // and
            res = (lhs & rhs) & w.mask;
            s.cpu->rflags = (res == 0 ? kFlagZF : 0) |
                            ((res >> (w.bits - 1)) ? kFlagSF : 0) |
                            (parity_of(static_cast<std::uint8_t>(res))
                                ? kFlagPF
                                : 0);
            break;
        case 5: // sub
            res = (lhs - rhs) & w.mask;
            s.cpu->rflags = add_flags(lhs, rhs, res, w.bits, true, 0);
            break;
        case 6: // xor
            res = (lhs ^ rhs) & w.mask;
            s.cpu->rflags = (res == 0 ? kFlagZF : 0) |
                            ((res >> (w.bits - 1)) ? kFlagSF : 0) |
                            (parity_of(static_cast<std::uint8_t>(res))
                                ? kFlagPF
                                : 0);
            break;
        case 7: // cmp
            res = (lhs - rhs) & w.mask;
            s.cpu->rflags = add_flags(lhs, rhs, res, w.bits, true, 0);
            break;
        }
        if (group != 7) {
            s.cpu->reg[RAX] =
                (s.cpu->reg[RAX] & ~w.mask) | (res & w.mask);
        }
        return true;
    };

    // Test (84/85) and xchg (86/87), mov (88-8B).
    // Handled inline below by the main switch.

    // Shifts (D0-D3, C0/C1): the four operations rol, ror, shl/sal, shr,
    // sar per reg field; count is imm8 (C0/C1), 1 (D0/D1), or cl
    // (D2/D3).
    auto shift_rm = [&](std::uint8_t op, std::uint32_t regf) -> bool {
        const bool byte = (op == 0xD0 || op == 0xD2 || op == 0xC0);
        setw(byte);
        Addr a;
        if (!modrm(a, after_op1)) {
            return false;
        }
        Eff a_eff;
        if (!eff(a, a_eff)) {
            return false;
        }
        std::uint64_t lhs = 0;
        if (!load_operand(s, a_eff, w, lhs)) {
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        std::uint64_t cnt = 0;
        if (op == 0xC0 || op == 0xC1) {
            const std::size_t imm_at = after_op1 + a.extra;
            if (imm_at >= avail) {
                return false;
            }
            cnt = p[imm_at];
        } else if (op == 0xD2 || op == 0xD3) {
            cnt = s.cpu->reg[RCX] & 0xFF;
        } else {
            cnt = 1;
        }
        const unsigned bits = w.bits;
        std::uint64_t v = lhs;
        std::uint64_t res = v;
        // All flags survive a zero-count shift; CF is set or cleared by
        // the non-zero cases.
        std::uint32_t nf = s.cpu->rflags;
        const std::uint64_t top =
            (bits == 64) ? (std::uint64_t{1} << 63)
                         : (std::uint64_t{1} << (bits - 1));
        if (regf == 0) { // rol
            const unsigned m = static_cast<unsigned>(cnt % bits);
            res = (v << m) | (v >> (bits - m));
            if (m) {
                nf = (nf & ~kFlagCF) | ((res & 1) ? kFlagCF : 0);
            }
        } else if (regf == 1) { // ror
            const unsigned m = static_cast<unsigned>(cnt % bits);
            res = (v >> m) | (v << (bits - m));
            if (m) {
                nf = (nf & ~kFlagCF) | ((res & top) ? kFlagCF : 0);
            }
        } else if (regf == 4 || regf == 5) { // shl/sal (4), shr (5)
            const bool left = (regf == 4);
            if (cnt >= bits) {
                res = 0;
                if (cnt == bits) {
                    nf = (nf & ~kFlagCF) |
                         ((left ? (v & 1) : (v & top)) ? kFlagCF : 0);
                } else {
                    nf &= ~kFlagCF;
                }
            } else if (cnt != 0) {
                if (left) {
                    const bool last = ((v >> (bits - cnt)) & 1) != 0;
                    res = (v << cnt) & w.mask;
                    nf = (nf & ~kFlagCF) | (last ? kFlagCF : 0);
                } else {
                    const bool last = ((v >> (cnt - 1)) & 1) != 0;
                    res = (v >> cnt) & w.mask;
                    nf = (nf & ~kFlagCF) | (last ? kFlagCF : 0);
                }
            }
        } else if (regf == 7) { // sar
            if (cnt >= bits) {
                const bool sign = (v & top) != 0;
                res = sign ? w.mask : 0;
                nf &= ~kFlagCF;
            } else if (cnt != 0) {
                const bool last = ((v >> (cnt - 1)) & 1) != 0;
                const std::int64_t sv = static_cast<std::int64_t>(v);
                res = static_cast<std::uint64_t>(sv >> cnt) & w.mask;
                nf = (nf & ~kFlagCF) | (last ? kFlagCF : 0);
            }
        } else {
            return false;
        }
        res &= w.mask;
        nf |= (res == 0) ? kFlagZF : 0;
        nf |= ((res >> (bits - 1)) & 1) ? kFlagSF : 0;
        nf |= parity_of(static_cast<std::uint8_t>(res)) ? kFlagPF : 0;
        s.cpu->rflags = nf;
        if (!store_operand(s, a_eff, w, res)) {
            s.detail = "store outside the memory image";
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        return true;
    };

    // F6/F7: test /0, not /2, neg /3, mul /4, imul /5, div /6, idiv /7.
    auto f6f7 = [&](std::uint8_t op) -> bool {
        const bool byte = (op == 0xF6);
        setw(byte);
        Addr a;
        if (!modrm(a, after_op1)) {
            return false;
        }
        Eff a_eff;
        if (!eff(a, a_eff)) {
            return false;
        }
        std::uint64_t lhs = 0;
        if (!load_operand(s, a_eff, w, lhs)) {
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        const std::uint32_t regf = a.reg & 7;
        if (regf == 0) { // test r/m, imm
            const std::size_t imm_at = after_op1 + a.extra;
            if (imm_at >= avail) {
                return false;
            }
            std::uint64_t rhs = 0;
            if (w.bytes == 1) {
                rhs = p[imm_at];
            } else if (w.bytes == 2) {
                if (imm_at + 2 > avail) {
                    return false;
                }
                std::memcpy(&rhs, p + imm_at, 2);
            } else if (w.bytes == 4 || w.bytes == 8) {
                // F7 /0 uses imm32 (sign-extended; the mask truncates).
                if (imm_at + 4 > avail) {
                    return false;
                }
                std::int32_t v = 0;
                std::memcpy(&v, p + imm_at, 4);
                rhs = static_cast<std::uint64_t>(v) & w.mask;
            }
            const std::uint64_t res = (lhs & rhs) & w.mask;
            s.cpu->rflags = (res == 0 ? kFlagZF : 0) |
                            ((res >> (w.bits - 1)) ? kFlagSF : 0) |
                            (parity_of(static_cast<std::uint8_t>(res))
                                ? kFlagPF
                                : 0);
            return true;
        }
        if (regf == 2) { // not
            const std::uint64_t res = (~lhs) & w.mask;
            if (!store_operand(s, a_eff, w, res)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            return true;
        }
        if (regf == 3) { // neg
            const std::uint64_t res = (0 - lhs) & w.mask;
            s.cpu->rflags = add_flags(std::uint64_t{0}, lhs, res, w.bits, true,
                                      0);
            if (!store_operand(s, a_eff, w, res)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            return true;
        }
        if (regf == 4 || regf == 5) { // mul / imul (unsigned / signed)
            const std::uint64_t rv = read_reg(*s.cpu, RAX, w);
            std::uint64_t lo = 0;
            bool ov = false;
            if (regf == 4) {
                lo = (rv * lhs) & w.mask;
                if (w.bytes == 1) {
                    ov = (lo >> 8) != 0;
                } else if (w.bytes == 2) {
                    ov = (lo >> 16) != 0;
                } else if (w.bytes == 4) {
                    ov = (lo >> 32) != 0;
                } else {
                    // 64x64 -> 128: check the high half.
                    const unsigned __int128 prod =
                        static_cast<unsigned __int128>(rv) * lhs;
                    const std::uint64_t hi =
                        static_cast<std::uint64_t>(prod >> 64);
                    ov = hi != 0;
                }
            } else {
                const std::int64_t a64 = static_cast<std::int64_t>(rv);
                const std::int64_t b64 = static_cast<std::int64_t>(lhs);
                const __int128 prod = static_cast<__int128>(a64) * b64;
                lo = static_cast<std::uint64_t>(prod) & w.mask;
                // Overflow when the high half is not the sign extension.
                if (w.bytes == 8) {
                    const std::uint64_t hi = static_cast<std::uint64_t>(
                        static_cast<unsigned __int128>(prod) >> 64);
                    const std::uint64_t sign = (lo >> 63) ? ~std::uint64_t{0}
                                                          : 0;
                    ov = hi != sign;
                } else if (w.bytes == 4) {
                    const std::int32_t lo32 = static_cast<std::int32_t>(lo);
                    ov = static_cast<std::int64_t>(a64) *
                             static_cast<std::int64_t>(b64) !=
                         static_cast<std::int64_t>(lo32);
                } else {
                    ov = false;
                }
            }
            s.cpu->reg[RAX] = lo;
            if (w.bytes == 8) {
                s.cpu->rflags = (lo == 0 ? kFlagZF : 0) |
                                ((lo >> 63) ? kFlagSF : 0) |
                                (ov ? kFlagOF | kFlagCF : 0) |
                                parity_of(static_cast<std::uint8_t>(lo))
                                    ? kFlagPF
                                    : 0;
            } else {
                s.cpu->rflags = (lo == 0 ? kFlagZF : 0) |
                                ((lo >> (w.bits - 1)) ? kFlagSF : 0) |
                                (ov ? kFlagOF | kFlagCF : 0) |
                                parity_of(static_cast<std::uint8_t>(lo))
                                    ? kFlagPF
                                    : 0;
            }
            return true;
        }
        if (regf == 6 || regf == 7) { // div / idiv
            const std::uint64_t rv = read_reg(*s.cpu, RAX, w);
            std::uint64_t divisor = lhs;
            if (divisor == 0) {
                s.detail = "divide by zero";
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            if (regf == 6) {
                s.cpu->reg[RAX] = (rv / divisor) & w.mask;
                if (w.bytes == 8) {
                    s.cpu->reg[RDX] = rv % divisor;
                } else {
                    s.cpu->reg[RDX] = (rv % divisor) & w.mask;
                }
            } else {
                const std::int64_t dv = static_cast<std::int64_t>(rv);
                const std::int64_t ds = static_cast<std::int64_t>(divisor);
                const std::int64_t q = dv / ds;
                const std::int64_t r = dv % ds;
                s.cpu->reg[RAX] = static_cast<std::uint64_t>(q) & w.mask;
                s.cpu->reg[RDX] = static_cast<std::uint64_t>(r) & w.mask;
            }
            return true;
        }
        return false;
    };

    // IMUL: 69 (imm32), 6B (imm8), 0F AF (r, r/m). The ModRM position
    // differs between the single-byte forms and 0F AF, so the caller
    // passes it.
    auto imul_rm = [&](std::uint8_t op, std::size_t modrm_at) -> bool {
        setw(false);
        Addr a;
        if (!modrm(a, modrm_at)) {
            return false;
        }
        Eff a_eff;
        if (!eff(a, a_eff)) {
            return false;
        }
        std::uint64_t rhs = 0;
        if (!load_operand(s, a_eff, w, rhs)) {
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        const std::uint64_t lhs = read_reg(*s.cpu, a.reg, w);
        std::uint64_t imm = 0;
        if (op == 0x6B) {
            const std::size_t imm_at = after_op1 + a.extra;
            if (imm_at >= avail) {
                return false;
            }
            imm = static_cast<std::uint64_t>(
                static_cast<std::int64_t>(static_cast<std::int8_t>(p[imm_at])));
        } else if (op == 0x69) {
            const std::size_t imm_at = after_op1 + a.extra;
            if (imm_at + 4 > avail) {
                return false;
            }
            std::int32_t v = 0;
            std::memcpy(&v, p + imm_at, 4);
            imm = static_cast<std::uint64_t>(v);
        }
        const std::int64_t a64 = static_cast<std::int64_t>(lhs);
        const std::int64_t b64 = static_cast<std::int64_t>(rhs);
        const std::int64_t i64 = static_cast<std::int64_t>(imm);
        const __int128 prod = static_cast<__int128>(a64) * (op == 0xAF ? b64 : i64);
        const std::uint64_t res = static_cast<std::uint64_t>(prod) & w.mask;
        s.cpu->reg[a.reg] = res;
        const std::uint64_t hi = static_cast<std::uint64_t>(
            static_cast<unsigned __int128>(prod) >> 64);
        const std::uint64_t sign = (res >> 63) ? ~std::uint64_t{0} : 0;
        const bool ov = hi != sign;
        s.cpu->rflags = (res == 0 ? kFlagZF : 0) |
                        ((res >> 63) ? kFlagSF : 0) |
                        (ov ? kFlagOF | kFlagCF : 0) | (parity_of(static_cast<std::uint8_t>(res)) ? kFlagPF : 0);
        return true;
    };

    // movzx/movsx (0F B6/B7/BE/BF), bsf/bsr (0F BC/BD), popcnt
    // (F3 0F B8).
    auto two_byte_conv = [&](std::uint8_t op, std::size_t modrm_at) -> bool {
        Addr a;
        if (!modrm(a, modrm_at)) {
            return false;
        }
        Eff a_eff;
        if (!eff(a, a_eff)) {
            return false;
        }
        Width sw;
        if (op == 0xB6 || op == 0xBE) {
            sw = width_of(pre, true);
        } else if (op == 0xB7 || op == 0xBF) {
            sw = width_of(Pre{false, false, false, false, true, false, false},
                          false);
        } else {
            sw = width_of(pre, false);
        }
        std::uint64_t src = 0;
        if (!load_operand(s, a_eff, sw, src)) {
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        if (op == 0xB6 || op == 0xB7) {
            s.cpu->reg[a.reg] = src; // zero extend
        } else if (op == 0xBE || op == 0xBF) {
            // Sign extend from the source width.
            const unsigned sb = sw.bits;
            const bool sign = (src >> (sb - 1)) & 1;
            s.cpu->reg[a.reg] = sign
                                    ? (src | ~((std::uint64_t{1} << sb) - 1))
                                    : src;
        } else if (op == 0xBC || op == 0xBD) { // bsf / bsr
            if (src == 0) {
                s.cpu->rflags |= kFlagZF;
            } else {
                s.cpu->rflags &= ~kFlagZF;
                if (op == 0xBC) {
                    unsigned i = 0;
                    while ((src & (std::uint64_t{1} << i)) == 0) {
                        ++i;
                    }
                    s.cpu->reg[a.reg] = i;
                } else {
                    unsigned i = 63;
                    while ((src & (std::uint64_t{1} << i)) == 0) {
                        --i;
                    }
                    s.cpu->reg[a.reg] = i;
                }
            }
        } else if (op == 0xB8 && pre.f3) { // popcnt
            unsigned c = 0;
            for (unsigned i = 0; i < 64; ++i) {
                c += (src >> i) & 1;
            }
            const Width pw = width_of(pre, false);
            if (pw.bytes == 8) {
                s.cpu->reg[a.reg] = c;
            } else if (pw.bytes == 4) {
                // A 32-bit write zero-extends into the 64-bit register.
                s.cpu->reg[a.reg] = static_cast<std::uint32_t>(c);
            } else {
                const std::uint64_t keep = ~std::uint64_t{0xFFFF};
                s.cpu->reg[a.reg] =
                    (s.cpu->reg[a.reg] & keep) | (c & 0xFFFF);
            }
            s.cpu->rflags &=
                ~(kFlagCF | kFlagOF | kFlagSF | kFlagAF | kFlagZF | kFlagPF);
            if (c == 0) {
                s.cpu->rflags |= kFlagZF;
            }
            if (parity_of(static_cast<std::uint8_t>(c)) != 0) {
                s.cpu->rflags |= kFlagPF;
            }
        } else {
            return false;
        }
        return true;
    };

    // The single-byte switch. Each `return true` means handled.
    switch (op1) {
    case 0x04:
    case 0x05:
    case 0x0C:
    case 0x0D:
    case 0x14:
    case 0x15:
    case 0x1C:
    case 0x1D:
    case 0x24:
    case 0x25:
    case 0x2C:
    case 0x2D:
    case 0x34:
    case 0x35:
    case 0x3C:
    case 0x3D:
        return alu_acc_imm(op1);

    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x18:
    case 0x19:
    case 0x1A:
    case 0x1B:
    case 0x20:
    case 0x21:
    case 0x22:
    case 0x23:
    case 0x28:
    case 0x29:
    case 0x2A:
    case 0x2B:
    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33:
    case 0x38:
    case 0x39:
    case 0x3A:
    case 0x3B:
        return alu_rm_r(op1);

    case 0x80:
    case 0x81:
    case 0x82:
    case 0x83:
        return alu_rm_imm(op1);

    case 0x84:
    case 0x85: { // test r/m, r
        const bool byte = (op1 == 0x84);
        setw(byte);
        Addr a2;
        if (!modrm(a2, after_op1)) {
            return false;
        }
        Eff e2;
        if (!eff(a2, e2)) {
            return false;
        }
        std::uint64_t l = 0;
        std::uint64_t r = 0;
        if (!load_operand(s, e2, w, l) ||
            !load_operand(s, Eff{true, a2.reg, 0}, w, r)) {
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        const std::uint64_t res = (l & r) & w.mask;
        s.cpu->rflags = (res == 0 ? kFlagZF : 0) |
                        ((res >> (w.bits - 1)) ? kFlagSF : 0) | (parity_of(static_cast<std::uint8_t>(res)) ? kFlagPF : 0);
        return true;
    }
    case 0x86:
    case 0x87: { // xchg r/m, r
        const bool byte = (op1 == 0x86);
        setw(byte);
        Addr a2;
        if (!modrm(a2, after_op1)) {
            return false;
        }
        Eff e2;
        if (!eff(a2, e2)) {
            return false;
        }
        std::uint64_t l = 0;
        std::uint64_t r = 0;
        if (!load_operand(s, e2, w, l) ||
            !load_operand(s, Eff{true, a2.reg, 0}, w, r)) {
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        if (!store_operand(s, e2, w, r) ||
            !store_operand(s, Eff{true, a2.reg, 0}, w, l)) {
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        return true;
    }
    case 0x88:
    case 0x89: // mov r/m, r
    case 0x8A:
    case 0x8B: { // mov r, r/m
        const bool byte = (op1 == 0x88 || op1 == 0x8A);
        setw(byte);
        Addr a2;
        if (!modrm(a2, after_op1)) {
            return false;
        }
        Eff e2;
        if (!eff(a2, e2)) {
            return false;
        }
        std::uint64_t v = 0;
        if (op1 == 0x88 || op1 == 0x89) {
            if (!load_operand(s, Eff{true, a2.reg, 0}, w, v)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            if (!store_operand(s, e2, w, v)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
        } else {
            if (!load_operand(s, e2, w, v)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            if (!store_operand(s, Eff{true, a2.reg, 0}, w, v)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
        }
        return true;
    }
    case 0x8D: { // lea r, m
        Addr a2;
        if (!modrm(a2, after_op1)) {
            return false;
        }
        std::uint64_t addr = 0;
        if (!resolve_addr(a2, *s.cpu, next_rip, s.base, addr)) {
            return false;
        }
        setw(false);
        s.cpu->reg[a2.reg] = addr & w.mask;
        return true;
    }
    case 0x8F: { // pop r/m
        Addr a2;
        if (!modrm(a2, after_op1)) {
            return false;
        }
        Eff e2;
        if (!eff(a2, e2)) {
            return false;
        }
        std::uint64_t v = 0;
        const std::uint64_t sp = s.cpu->reg[RSP];
        if (!s.mem->load(sp, &v, 8)) {
            s.detail = "pop outside the memory image";
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        s.cpu->reg[RSP] = sp + 8;
        setw(false);
        if (!store_operand(s, e2, w, v)) {
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        return true;
    }
    case 0x90: // nop
        return true;
    case 0x91:
    case 0x92:
    case 0x93:
    case 0x94:
    case 0x95:
    case 0x96:
    case 0x97: { // xchg reg, rax
        const std::uint8_t r = static_cast<std::uint8_t>(op1 - 0x90 + RAX);
        const std::uint64_t t = s.cpu->reg[RAX];
        s.cpu->reg[RAX] = s.cpu->reg[r];
        s.cpu->reg[r] = t;
        return true;
    }
    case 0x98: // cdqe
        s.cpu->reg[RAX] = static_cast<std::uint64_t>(
            static_cast<std::int64_t>(static_cast<std::int32_t>(
                s.cpu->reg[RAX] & 0xFFFFFFFF)));
        return true;
    case 0x99: // cqo
        s.cpu->reg[RDX] = (s.cpu->reg[RAX] >> 63) ? ~std::uint64_t{0} : 0;
        return true;
    case 0x9C: // pushfq
        return false; // not in the integer family's common use
    case 0x9D: // popfq
        return false;
    case 0xA8:
    case 0xA9: { // test al/eax, imm
        setw(op1 == 0xA8);
        const std::size_t imm_at = after_op1;
        std::uint64_t imm = 0;
        if (w.bytes == 1) {
            imm = p[imm_at];
        } else if (w.bytes == 4) {
            std::memcpy(&imm, p + imm_at, 4);
        }
        const std::uint64_t lhs = read_reg(*s.cpu, RAX, w);
        const std::uint64_t res = (lhs & imm) & w.mask;
        s.cpu->rflags = (res == 0 ? kFlagZF : 0) |
                        ((res >> (w.bits - 1)) ? kFlagSF : 0) | (parity_of(static_cast<std::uint8_t>(res)) ? kFlagPF : 0);
        return true;
    }
    case 0xB0:
    case 0xB1:
    case 0xB2:
    case 0xB3:
    case 0xB4:
    case 0xB5:
    case 0xB6:
    case 0xB7: { // mov r8, imm8
        const std::uint8_t r = static_cast<std::uint8_t>(op1 - 0xB0);
        if (after_op1 >= avail) {
            return false;
        }
        const std::uint8_t v = p[after_op1];
        const std::uint64_t keep = ~std::uint64_t{0xFF};
        s.cpu->reg[r] = (s.cpu->reg[r] & keep) | v;
        return true;
    }
    case 0xB8:
    case 0xB9:
    case 0xBA:
    case 0xBB:
    case 0xBC:
    case 0xBD:
    case 0xBE:
    case 0xBF: { // mov r, imm
        const std::uint8_t r = static_cast<std::uint8_t>(op1 - 0xB8);
        if (pre.rex_w) {
            if (after_op1 + 8 > avail) {
                return false;
            }
            std::memcpy(&s.cpu->reg[r], p + after_op1, 8);
        } else if (pre.p66) {
            if (after_op1 + 2 > avail) {
                return false;
            }
            std::uint16_t v = 0;
            std::memcpy(&v, p + after_op1, 2);
            const std::uint64_t keep = ~std::uint64_t{0xFFFF};
            s.cpu->reg[r] = (s.cpu->reg[r] & keep) | v;
        } else {
            if (after_op1 + 4 > avail) {
                return false;
            }
            std::int32_t v = 0;
            std::memcpy(&v, p + after_op1, 4);
            // A 32-bit write zero-extends into the 64-bit register; the
            // cast to uint32_t is the hardware's behavior.
            s.cpu->reg[r] = static_cast<std::uint64_t>(
                static_cast<std::uint32_t>(v));
        }
        return true;
    }
    case 0xC0:
    case 0xC1:
    case 0xD0:
    case 0xD1:
    case 0xD2:
    case 0xD3: {
        Addr a2;
        if (!modrm(a2, after_op1)) {
            return false;
        }
        return shift_rm(op1, a2.reg & 7);
    }
    case 0xC2: { // ret imm16
        if (after_op1 + 2 > avail) {
            return false;
        }
        std::uint16_t n = 0;
        std::memcpy(&n, p + after_op1, 2);
        std::uint64_t ret = 0;
        const std::uint64_t sp = s.cpu->reg[RSP];
        if (!s.mem->load(sp, &ret, 8)) {
            s.detail = "ret outside the memory image";
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        s.cpu->reg[RSP] = sp + 8 + n;
        s.cpu->rip = ret;
        out.transferred = true;
        if (ret < s.base || ret >= s.base + s.size) {
            // Returning out of the interpreted region is a named end.
            out.stop = true;
            out.halt = Halt::Ret;
        }
        return true;
    }
    case 0xC3: { // ret
        std::uint64_t ret = 0;
        const std::uint64_t sp = s.cpu->reg[RSP];
        if (!s.mem->load(sp, &ret, 8)) {
            s.detail = "ret outside the memory image";
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        s.cpu->reg[RSP] = sp + 8;
        s.cpu->rip = ret;
        out.transferred = true;
        if (ret < s.base || ret >= s.base + s.size) {
            out.stop = true;
            out.halt = Halt::Ret;
        }
        return true;
    }
    case 0xC6:
    case 0xC7: { // mov r/m, imm
        const bool byte = (op1 == 0xC6);
        setw(byte);
        Addr a2;
        if (!modrm(a2, after_op1)) {
            return false;
        }
        Eff e2;
        if (!eff(a2, e2)) {
            return false;
        }
        const std::size_t imm_at = after_op1 + a2.extra;
        std::uint64_t imm = 0;
        if (w.bytes == 1) {
            if (imm_at >= avail) {
                return false;
            }
            imm = p[imm_at];
        } else if (w.bytes == 2) {
            if (imm_at + 2 > avail) {
                return false;
            }
            std::memcpy(&imm, p + imm_at, 2);
        } else if (w.bytes == 4) {
            if (imm_at + 4 > avail) {
                return false;
            }
            std::memcpy(&imm, p + imm_at, 4);
        } else if (w.bytes == 8) {
            // C7 with REX.W stores imm32 sign-extended to 64.
            if (imm_at + 4 > avail) {
                return false;
            }
            std::int32_t v = 0;
            std::memcpy(&v, p + imm_at, 4);
            imm = static_cast<std::uint64_t>(v);
        }
        if (!store_operand(s, e2, w, imm)) {
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        return true;
    }
    case 0xE8: { // call rel32
        if (after_op1 + 4 > avail) {
            return false;
        }
        std::int32_t d = 0;
        std::memcpy(&d, p + after_op1, 4);
        const std::uint64_t target = static_cast<std::uint64_t>(
            static_cast<std::int64_t>(next_rip) + d);
        const std::uint64_t sp = s.cpu->reg[RSP] - 8;
        if (!s.mem->store(sp, &next_rip, 8)) {
            s.detail = "call stack outside the memory image";
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        s.cpu->reg[RSP] = sp;
        if (target < s.base || target >= s.base + s.size) {
            // Escaped the region: report a normal end with the target set.
            s.cpu->rip = target;
            out.stop = true;
            out.halt = Halt::None;
            out.transferred = true;
            return true;
        }
        s.cpu->rip = target;
        out.transferred = true;
        return true;
    }
    case 0xE9: { // jmp rel32
        if (after_op1 + 4 > avail) {
            return false;
        }
        std::int32_t d = 0;
        std::memcpy(&d, p + after_op1, 4);
        s.cpu->rip = static_cast<std::uint64_t>(
            static_cast<std::int64_t>(next_rip) + d);
        out.transferred = true;
        return true;
    }
    case 0xEB: { // jmp rel8
        if (after_op1 >= avail) {
            return false;
        }
        const std::int8_t d = static_cast<std::int8_t>(p[after_op1]);
        s.cpu->rip = static_cast<std::uint64_t>(
            static_cast<std::int64_t>(next_rip) + d);
        out.transferred = true;
        return true;
    }
    case 0xF4: // hlt
        out.stop = true;
        out.halt = Halt::Hlt;
        return true;
    case 0xF6:
    case 0xF7:
        return f6f7(op1);
    case 0xFE:
    case 0xFF: { // inc/dec (FE, FF/0, FF/1), call/jmp r/m (FF/2, FF/4)
        Addr a2;
        if (!modrm(a2, after_op1)) {
            return false;
        }
        const std::uint32_t regf = a2.reg & 7;
        if (op1 == 0xFE) {
            if (regf != 0 && regf != 1) {
                return false;
            }
            setw(true);
            Eff e2;
            if (!eff(a2, e2)) {
                return false;
            }
            std::uint64_t v = 0;
            if (!load_operand(s, e2, w, v)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            const std::uint64_t res = (regf == 0 ? v + 1 : v - 1) & w.mask;
            const std::uint32_t keep = s.cpu->rflags & kFlagCF;
            const std::uint64_t top =
                (w.bits == 64) ? (std::uint64_t{1} << 63)
                               : (std::uint64_t{1} << (w.bits - 1));
            const bool ov = ((v ^ res) & top) != 0;
            const std::uint32_t nf =
                (res == 0 ? kFlagZF : 0) |
                ((res >> (w.bits - 1)) ? kFlagSF : 0) |
                (parity_of(static_cast<std::uint8_t>(res)) ? kFlagPF : 0) |
                (ov ? kFlagOF : 0) | keep;
            s.cpu->rflags = nf;
            if (!store_operand(s, e2, w, res)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            return true;
        }
        if (regf == 0 || regf == 1) { // inc/dec r/m
            setw(false);
            Eff e2;
            if (!eff(a2, e2)) {
                return false;
            }
            std::uint64_t v = 0;
            if (!load_operand(s, e2, w, v)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            const std::uint64_t res = (regf == 0 ? v + 1 : v - 1) & w.mask;
            const std::uint64_t top =
                (w.bits == 64) ? (std::uint64_t{1} << 63)
                               : (std::uint64_t{1} << (w.bits - 1));
            const bool ov = ((v ^ res) & top) != 0;
            const std::uint32_t nf =
                (res == 0 ? kFlagZF : 0) |
                ((res >> (w.bits - 1)) ? kFlagSF : 0) |
                (parity_of(static_cast<std::uint8_t>(res)) ? kFlagPF : 0) |
                (ov ? kFlagOF : 0);
            s.cpu->rflags = (s.cpu->rflags & kFlagCF) | nf;
            if (!store_operand(s, e2, w, res)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            return true;
        }
        if (regf == 2) { // call r/m
            Eff e2;
            if (!eff(a2, e2)) {
                return false;
            }
            std::uint64_t target = 0;
            if (!load_operand(s, e2, Width{8, 64, ~std::uint64_t{0}}, target)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            const std::uint64_t sp = s.cpu->reg[RSP] - 8;
            if (!s.mem->store(sp, &next_rip, 8)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            s.cpu->reg[RSP] = sp;
            s.cpu->rip = target;
            out.transferred = true;
            return true;
        }
        if (regf == 4) { // jmp r/m
            Eff e2;
            if (!eff(a2, e2)) {
                return false;
            }
            std::uint64_t target = 0;
            if (!load_operand(s, e2, Width{8, 64, ~std::uint64_t{0}}, target)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            s.cpu->rip = target;
            out.transferred = true;
            return true;
        }
        return false;
    }
    case 0x63: { // movsxd r64, r/m32
        Addr a2;
        if (!modrm(a2, after_op1)) {
            return false;
        }
        Eff e2;
        if (!eff(a2, e2)) {
            return false;
        }
        std::uint64_t v = 0;
        if (!load_operand(s, e2, Width{4, 32, 0xFFFFFFFF}, v)) {
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        s.cpu->reg[a2.reg] = static_cast<std::uint64_t>(
            static_cast<std::int64_t>(static_cast<std::int32_t>(v)));
        return true;
    }
    case 0x69: // imul r, r/m, imm32
    case 0x6B: // imul r, r/m, imm8
        return imul_rm(op1, after_op1);
    case 0x68: // push imm32 (sign-extended)
    case 0x6A: { // push imm8 (sign-extended)
        std::uint64_t v = 0;
        if (op1 == 0x6A) {
            if (after_op1 >= avail) {
                return false;
            }
            v = static_cast<std::uint64_t>(
                static_cast<std::int64_t>(static_cast<std::int8_t>(p[after_op1])));
        } else {
            if (after_op1 + 4 > avail) {
                return false;
            }
            std::int32_t i = 0;
            std::memcpy(&i, p + after_op1, 4);
            v = static_cast<std::uint64_t>(i);
        }
        const std::uint64_t sp = s.cpu->reg[RSP] - 8;
        if (!s.mem->store(sp, &v, 8)) {
            s.detail = "push outside the memory image";
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        s.cpu->reg[RSP] = sp;
        return true;
    }
    case 0x50:
    case 0x51:
    case 0x52:
    case 0x53:
    case 0x54:
    case 0x55:
    case 0x56:
    case 0x57: { // push r64
        const std::uint8_t r = static_cast<std::uint8_t>(op1 - 0x50);
        const std::uint64_t v = s.cpu->reg[r];
        const std::uint64_t sp = s.cpu->reg[RSP] - 8;
        if (!s.mem->store(sp, &v, 8)) {
            s.detail = "push outside the memory image";
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        s.cpu->reg[RSP] = sp;
        return true;
    }
    case 0x58:
    case 0x59:
    case 0x5A:
    case 0x5B:
    case 0x5C:
    case 0x5D:
    case 0x5E:
    case 0x5F: { // pop r64
        const std::uint8_t r = static_cast<std::uint8_t>(op1 - 0x58);
        std::uint64_t v = 0;
        const std::uint64_t sp = s.cpu->reg[RSP];
        if (!s.mem->load(sp, &v, 8)) {
            s.detail = "pop outside the memory image";
            out.stop = true;
            out.halt = Halt::Fault;
            return true;
        }
        s.cpu->reg[RSP] = sp + 8;
        s.cpu->reg[r] = v;
        return true;
    }
    case 0x70:
    case 0x71:
    case 0x72:
    case 0x73:
    case 0x74:
    case 0x75:
    case 0x76:
    case 0x77:
    case 0x78:
    case 0x79:
    case 0x7A:
    case 0x7B:
    case 0x7C:
    case 0x7D:
    case 0x7E:
    case 0x7F: { // jcc rel8
        if (after_op1 >= avail) {
            return false;
        }
        const std::int8_t d = static_cast<std::int8_t>(p[after_op1]);
        if (cond_taken(op1 - 0x70, *s.cpu)) {
            s.cpu->rip = static_cast<std::uint64_t>(
                static_cast<std::int64_t>(next_rip) + d);
            out.transferred = true;
        }
        return true;
    }
    case 0x0F: {
        // The two-byte opcode.
        if (after_op1 >= avail) {
            return false;
        }
        const std::uint8_t op2 = p[after_op1];
        const std::size_t at2 = after_op1 + 1;
        if (op2 >= 0x40 && op2 <= 0x4F) { // cmovcc
            Addr a2;
            if (!modrm(a2, at2)) {
                return false;
            }
            Eff e2;
            if (!eff(a2, e2)) {
                return false;
            }
            setw(false);
            std::uint64_t v = 0;
            if (!load_operand(s, e2, w, v)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            if (cond_taken(op2 - 0x40, *s.cpu)) {
                s.cpu->reg[a2.reg] = v;
            }
            return true;
        }
        if (op2 >= 0x80 && op2 <= 0x8F) { // jcc rel32
            if (at2 + 4 > avail) {
                return false;
            }
            std::int32_t d = 0;
            std::memcpy(&d, p + at2, 4);
            if (cond_taken(op2 - 0x80, *s.cpu)) {
                s.cpu->rip = static_cast<std::uint64_t>(
                    static_cast<std::int64_t>(next_rip) + d);
                out.transferred = true;
            }
            return true;
        }
        if (op2 >= 0x90 && op2 <= 0x9F) { // setcc
            Addr a2;
            if (!modrm(a2, at2)) {
                return false;
            }
            Eff e2;
            if (!eff(a2, e2)) {
                return false;
            }
            const std::uint8_t v =
                cond_taken(op2 - 0x90, *s.cpu) ? 1 : 0;
            if (!store_operand(s, e2, Width{1, 8, 0xFF}, v)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            return true;
        }
        if (op2 >= 0xC8 && op2 <= 0xCF) { // bswap
            const std::uint8_t r = static_cast<std::uint8_t>(op2 - 0xC8);
            const std::uint64_t v = s.cpu->reg[r];
            std::uint64_t o = 0;
            for (unsigned i = 0; i < 8; ++i) {
                o |= ((v >> (i * 8)) & 0xFF) << ((7 - i) * 8);
            }
            s.cpu->reg[r] = o;
            return true;
        }
        switch (op2) {
        case 0x05: // syscall
            out.stop = true;
            out.halt = Halt::Syscall;
            return true;
        case 0x1E: // multibyte nop
        case 0x1F: // nop with ModRM
            return true;
        case 0xA2: // cpuid
            return true;
        case 0xA3: // bt r/m, r
        case 0xAB: // bts r/m, r
        case 0xB3: // btr r/m, r
        case 0xBB: // btc r/m, r
        case 0xBA: { // bt/bts/btr/btc r/m, imm8 (also 0F BA /4-/7)
            const bool imm_form = (op2 == 0xBA);
            Addr a2;
            if (!modrm(a2, at2)) {
                return false;
            }
            const std::uint32_t regf = a2.reg & 7;
            if (imm_form && (regf < 4 || regf > 7)) {
                return false;
            }
            Eff e2;
            if (!eff(a2, e2)) {
                return false;
            }
            setw(false);
            std::uint64_t bit = 0;
            if (imm_form) {
                const std::size_t imm_at = at2 + a2.extra;
                if (imm_at >= avail) {
                    return false;
                }
                bit = p[imm_at];
            } else {
                bit = read_reg(*s.cpu, a2.reg, w);
            }
            std::uint64_t base = 0;
            if (!load_operand(s, e2, w, base)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            const unsigned b = static_cast<unsigned>(bit % w.bits);
            const std::uint64_t mask1 = std::uint64_t{1} << b;
            const bool was = (base & mask1) != 0;
            const std::uint64_t group =
                imm_form ? regf - 4 : ((op2 >> 3) & 7) - 4;
            std::uint64_t res = base;
            if (group == 0) { // bt
                // reads only
            } else if (group == 1) { // bts
                res = base | mask1;
            } else if (group == 2) { // btr
                res = base & ~mask1;
            } else { // btc
                res = base ^ mask1;
            }
            s.cpu->rflags = (was ? kFlagCF : 0);
            if (group != 0) {
                if (!store_operand(s, e2, w, res)) {
                    out.stop = true;
                    out.halt = Halt::Fault;
                    return true;
                }
            }
            return true;
        }
        case 0xA4: // shld r/m, r, imm8
        case 0xAC: // shrd r/m, r, imm8
        case 0xA5: // shld r/m, r (cl)
        case 0xAD: { // shrd r/m, r (cl)
            Addr a2;
            if (!modrm(a2, at2)) {
                return false;
            }
            Eff e2;
            if (!eff(a2, e2)) {
                return false;
            }
            setw(false);
            std::uint64_t dst = 0;
            if (!load_operand(s, e2, w, dst)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            const std::uint64_t src = read_reg(*s.cpu, a2.reg, w);
            std::uint64_t cnt = 0;
            if (op2 == 0xA4 || op2 == 0xAC) {
                const std::size_t imm_at = at2 + a2.extra;
                if (imm_at >= avail) {
                    return false;
                }
                cnt = p[imm_at];
            } else {
                cnt = s.cpu->reg[RCX] & 0xFF;
            }
            const unsigned bits = w.bits;
            const bool right = (op2 == 0xAC || op2 == 0xAD);
            std::uint64_t res = dst;
            std::uint32_t nf = s.cpu->rflags;
            if (cnt >= bits) {
                // Behavior with an out-of-range count is
                // implementation-defined on real hardware; name it and
                // keep the destination unchanged with CF cleared.
                nf &= ~kFlagCF;
            } else if (cnt != 0) {
                if (right) {
                    const bool last = ((dst >> (cnt - 1)) & 1) != 0;
                    res = ((dst >> cnt) | (src << (bits - cnt))) & w.mask;
                    nf = (nf & ~kFlagCF) | (last ? kFlagCF : 0);
                } else {
                    const bool last = ((dst >> (bits - cnt)) & 1) != 0;
                    res = ((dst << cnt) | (src >> (bits - cnt))) & w.mask;
                    nf = (nf & ~kFlagCF) | (last ? kFlagCF : 0);
                }
                nf |= (res == 0) ? kFlagZF : 0;
                nf |= ((res >> (bits - 1)) & 1) ? kFlagSF : 0;
                nf |= parity_of(static_cast<std::uint8_t>(res)) ? kFlagPF : 0;
                s.cpu->rflags = nf;
            } else {
                // count zero: flags unchanged
            }
            if (!store_operand(s, e2, w, res)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            return true;
        }
        case 0xAF:
            return imul_rm(0xAF, at2);
        case 0xB0:
        case 0xB1: { // cmpxchg r/m, r
            const bool byte = (op2 == 0xB0);
            setw(byte);
            Addr a2;
            if (!modrm(a2, at2)) {
                return false;
            }
            Eff e2;
            if (!eff(a2, e2)) {
                return false;
            }
            std::uint64_t dst = 0;
            if (!load_operand(s, e2, w, dst)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            const std::uint64_t acc = read_reg(*s.cpu, RAX, w);
            const std::uint64_t src = read_reg(*s.cpu, a2.reg, w);
            const std::uint64_t res = (acc - dst) & w.mask;
            s.cpu->rflags = add_flags(acc, dst, res, w.bits, true, 0);
            if (res == 0) {
                if (!store_operand(s, e2, w, src)) {
                    out.stop = true;
                    out.halt = Halt::Fault;
                    return true;
                }
            } else {
                s.cpu->reg[RAX] = dst;
            }
            return true;
        }
        case 0xB6:
        case 0xB7:
        case 0xBC:
        case 0xBD:
        case 0xBE:
        case 0xBF:
            return two_byte_conv(op2, at2);
        case 0xB8:
            return pre.f3 ? two_byte_conv(op2, at2) : false;
        case 0xC0:
        case 0xC1: { // xadd r/m, r
            const bool byte = (op2 == 0xC0);
            setw(byte);
            Addr a2;
            if (!modrm(a2, at2)) {
                return false;
            }
            Eff e2;
            if (!eff(a2, e2)) {
                return false;
            }
            std::uint64_t dst = 0;
            if (!load_operand(s, e2, w, dst)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            const std::uint64_t src = read_reg(*s.cpu, a2.reg, w);
            const std::uint64_t res = (dst + src) & w.mask;
            s.cpu->rflags = add_flags(dst, src, res, w.bits, false, 0);
            if (!store_operand(s, e2, w, res)) {
                out.stop = true;
                out.halt = Halt::Fault;
                return true;
            }
            s.cpu->reg[a2.reg] = dst;
            return true;
        }
        default:
            return false;
        }
    }
    default:
        return false;
    }
}

} // namespace

// ---------------------------------------------------------------------------
// Public entry
// ---------------------------------------------------------------------------

RunResult run(const std::uint8_t* code, std::size_t size, std::uint64_t base,
              Cpu& cpu, Memory& mem, std::size_t max_steps, StepHook hook,
              void* hook_ctx) noexcept {
    RunResult r;
    EmuState s;
    // Instructions are fetched from the memory image itself, never from a
    // separate code pointer: a self-modifying program must observe its own
    // stores. The `code` argument is therefore only a caller-side alias
    // check for the image base and is not used for fetching.
    s.code = mem.bytes.data();
    (void)code;
    s.size = size;
    s.base = base;
    s.cpu = &cpu;
    s.mem = &mem;
    if (cpu.rip < base || cpu.rip >= base + size) {
        r.why = Halt::None;
        r.rip = cpu.rip;
        r.detail = "entry outside the interpreted region";
        return r;
    }
    std::size_t steps = 0;
    for (;;) {
        const std::uint64_t rip = cpu.rip;
        if (rip < base || rip >= base + size) {
            r.why = Halt::None;
            r.rip = rip;
            r.steps = steps;
            return r;
        }
        const std::size_t at = static_cast<std::size_t>(rip - base);
        ExecOut eo;
        if (!execute_one(s, at, eo)) {
            // The interpreter refused the instruction. The reason is
            // already in `s.detail` unless a handler returned false
            // without saying why; name it.
            if (s.detail == nullptr) {
                s.detail = "instruction outside the interpreted family";
            }
            eo.stop = true;
            eo.halt = Halt::Unknown;
        }
        // The step is observed (counted, visible to the hook) even when
        // it is the stopping instruction, so a hook sees the whole run.
        ++steps;
        if (hook != nullptr) {
            const StepInfo si{rip, eo.len};
            if (!hook(si, hook_ctx)) {
                r.why = Halt::None;
                r.rip = cpu.rip;
                r.steps = steps;
                return r;
            }
        }
        if (eo.stop) {
            r.why = eo.halt;
            r.rip = cpu.rip;
            r.steps = steps;
            r.detail = s.detail;
            return r;
        }
        if (steps >= max_steps) {
            r.why = Halt::Budget;
            r.rip = cpu.rip;
            r.steps = steps;
            return r;
        }
        // Advance the program counter. A transfer that was taken set
        // rip already (a taken branch, call, jmp or ret -- including one
        // whose target happens to be the current rip, which is a jmp to
        // itself and must not be double-advanced). Anything else fell
        // through and advances by the instruction length.
        if (!eo.transferred) {
            cpu.rip = rip + eo.len;
        }
    }
}

} // namespace occ::emu

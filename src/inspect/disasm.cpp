// The x64 instruction length decoder, and the linear disassembly built on
// it.
//
// The length is the load-bearing part. A byte stream has no instruction
// boundaries; recovering them is the whole of what makes bytes disassemble
// at all, and it is what a hook detector needs -- `CreateProcessW` is
// hooked when the first bytes of its prologue are a jump, and "the first
// bytes" means knowing where the real instructions they overwrite ended.
// An imprecise decoder produces lengths that are plausible and wrong,
// which is worse than none.
//
// The decoder implements the instruction encoding the manual defines:
// legacy prefixes, REX, the one- and two-byte opcode maps with their ModRM
// and immediate rules, VEX and EVEX as they change the same rules, and
// ModRM/SIB displacement arithmetic. The invalid-in-64-bit opcodes (the
// 32-bit-only pushes and the far calls) are refused rather than guessed at,
// because a length for an instruction that cannot exist is a lie about
// where the next one starts.
//
// What it does not do is name every instruction -- the mnemonic table
// covers the integer and common SSE opcodes and reports the rest as their
// opcode bytes, because a wrong name is worse than an honest gap. The
// lengths are the part intended to be complete.

#include "occ/inspect/disasm.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

namespace occ::inspect {
namespace {

// The opcode tables' shape. One byte per opcode entry, encoding what
// follows the opcode byte.
enum : std::uint8_t {
    kNoModrm = 0x80,   // the opcode names its operands alone
    kHasModrm = 0x01,  // a ModRM byte follows (the default encoding)
    kImm8 = 0x02,      // an 8-bit immediate follows
    kImmZ = 0x04,      // an immediate sized by the operand size: 2 or 4
    kImmV = 0x08,      // moffs, sized by 66/REX.W: 2, 4 or 8
    kImmP = 0x10,      // an 8-byte immediate under REX.W (the movabs group)
    kImm16F = 0x20,    // a fixed 16-bit immediate, unaffected by 66
    kInvalid64 = 0x40, // not an instruction in 64-bit mode
};

// The one-byte opcode map. The default -- an all-zero entry -- is a ModRM
// instruction with no immediate, which is most of the map. X marks the
// opcodes that cannot exist in 64-bit mode, refused rather than guessed.
constexpr std::uint8_t kOp1[256] = {
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kInvalid64, kInvalid64, kInvalid64, kInvalid64,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kInvalid64, kInvalid64, kImm8, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kInvalid64, kInvalid64, kInvalid64, kHasModrm,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kInvalid64, kInvalid64, kImm8, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kInvalid64, kInvalid64, kImm8, kHasModrm,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kInvalid64, kInvalid64, kImm8, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kInvalid64, kInvalid64, kImm8, kHasModrm,
    kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64,
    kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm,
    kInvalid64, kInvalid64, kHasModrm, kHasModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kImmZ, kHasModrm, kImm8, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kInvalid64, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm,
    kImmV, kImmV, kImmV, kImmV, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kImm8, kImmZ, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm,
    kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ,
    kHasModrm, kHasModrm, kImm16F, kNoModrm, kNoModrm, kNoModrm, kHasModrm, kHasModrm, kImmP, kNoModrm, kImm16F, kNoModrm, kNoModrm, kImm8, kInvalid64, kNoModrm,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kInvalid64, kInvalid64, kInvalid64, kNoModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImmZ, kImmZ, kInvalid64, kImm8, kNoModrm, kNoModrm, kNoModrm, kNoModrm,
    kInvalid64, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
};

// The two-byte opcode map (0F xx). The same encoding of the entries; the
// immediates of 70-73, BA and C2/C4/C5/C6 are carried by op2_has_imm8
// below.
constexpr std::uint8_t kOp2[256] = {
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kNoModrm, kHasModrm, kNoModrm, kNoModrm, kNoModrm, kInvalid64, kNoModrm, kInvalid64, kHasModrm, kInvalid64, kInvalid64,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kInvalid64, kNoModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kImmZ, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kNoModrm, kNoModrm, kNoModrm, kHasModrm, kHasModrm, kHasModrm, kInvalid64, kInvalid64, kNoModrm, kNoModrm, kNoModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kInvalid64, kInvalid64, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
};

// The two-byte opcodes whose ModRM is followed by an 8-bit immediate.
[[nodiscard]] bool op2_has_imm8(std::uint8_t op) noexcept {
    switch (op) {
    case 0x70:
    case 0x71:
    case 0x72:
    case 0x73:
    case 0xBA:
    case 0xC2:
    case 0xC4:
    case 0xC5:
    case 0xC6:
        return true;
    default:
        return false;
    }
}

// How many bytes a ModRM-encoded instruction's addressing costs, read off
// the ModRM byte and, when the rm field calls for it, the SIB byte that
// follows: displacement arithmetic and the SIB's own base rule. The SIB
// rule is the one that costs real bytes in real code -- `mov rax,
// gs:[0x58]`, the TLS read every compiled program opens with, is a ModRM
// with a SIB whose base field is five, and a decoder that treats that base
// like a register loses the four displacement bytes behind it.
struct AddressingCost {
    std::uint8_t bytes;
};

[[nodiscard]] AddressingCost modrm_cost(std::uint8_t modrm, std::uint8_t sib,
                                        bool has_sib, bool address16) {
    const std::uint8_t mod = (modrm >> 6) & 0x3u;
    const std::uint8_t rm = modrm & 0x7u;
    AddressingCost cost{0};
    if (mod == 3) {
        return cost;  // register-to-register: no addressing bytes.
    }
    if (address16) {
        if (mod == 0 && rm == 6) {
            cost.bytes = 2;
        } else if (mod == 1) {
            cost.bytes = 1;
        } else if (mod == 2) {
            cost.bytes = 2;
        }
        return cost;
    }
    if (rm == 4) {
        cost.bytes = 1;  // the SIB itself
        if (mod == 1) {
            cost.bytes += 1;
        } else if (mod == 2) {
            cost.bytes += 4;
        } else if (mod == 0 && (sib & 0x7u) == 5) {
            // A SIB base of five with no displacement reads its address
            // from a disp32 that follows the SIB, not from any register.
            cost.bytes += 4;
        }
        return cost;
    }
    if (mod == 0 && rm == 5) {
        cost.bytes = 4;  // rip-relative or absolute disp32.
    } else if (mod == 1) {
        cost.bytes = 1;
    } else if (mod == 2) {
        cost.bytes = 4;
    }
    static_cast<void>(has_sib);
    return cost;
}

}  // namespace

// Decodes one instruction's length, or 0 when the bytes are not an
// instruction this decoder accepts -- including the opcodes that cannot
// exist in 64-bit mode, where a length would be a lie about where the next
// instruction starts.
std::uint32_t x64_instruction_length(const std::uint8_t* bytes,
                                     std::size_t available) noexcept {
    std::size_t i = 0;
    bool operand16 = false;
    bool address16 = false;  // the 67 prefix, and 66 alone does not touch it
    bool rex_w = false;
    bool has_vex_or_evex = false;
    std::uint8_t vex_opmap = 0;

    // The prefix walk. Legacy prefixes may repeat; REX must be the last
    // prefix before the opcode; VEX/EVEX replace REX and the legacy group.
    while (i < available) {
        const std::uint8_t b = bytes[i];
        if (b == 0x66) {
            operand16 = true;
            ++i;
        } else if (b == 0x67) {
            // The address-size prefix: on 64 it narrows 64-bit addressing to
            // the 32-bit forms, which is the table this decoder already
            // walks -- so there is nothing to record.
            ++i;
        } else if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
                   b == 0x64 || b == 0x65 || b == 0xF2 || b == 0xF3) {
            ++i;
        } else if (b >= 0x40 && b <= 0x4F) {
            rex_w = (b & 0x8) != 0;
            ++i;
            break;  // REX is the last prefix.
        } else if (b == 0xC4 || b == 0xC5) {
            has_vex_or_evex = true;
            if (b == 0xC5) {
                if (i + 2 > available) {
                    return 0;
                }
                vex_opmap = 0x0F;
                i += 2;
            } else {
                if (i + 3 > available) {
                    return 0;
                }
                const std::uint8_t m = bytes[i + 1] & 0x1F;
                vex_opmap =
                    m == 1 ? 0x0F : (m == 2 ? 0x38 : (m == 3 ? 0x3A : 0));
                i += 3;
            }
            break;
        } else if (b == 0x62) {
            has_vex_or_evex = true;
            if (i + 4 > available) {
                return 0;
            }
            const std::uint8_t m = bytes[i + 1] & 0x7;
            vex_opmap = m == 1 ? 0x0F : (m == 2 ? 0x38 : (m == 3 ? 0x3A : 0));
            i += 4;
            break;
        } else {
            break;
        }
    }
    if (i >= available) {
        return 0;
    }

    const std::uint8_t op1 = bytes[i++];
    std::uint8_t opcode_map = 0;
    std::uint8_t op = op1;

    if (op1 == 0x0F && !has_vex_or_evex) {
        if (i >= available) {
            return 0;
        }
        if (bytes[i] == 0x38 || bytes[i] == 0x3A) {
            // The three-byte maps are ModRM-dominated; the handful with
            // immediates are carried by the same rule below.
            opcode_map = bytes[i];
            i += 1;
            op = bytes[i++];
        } else {
            opcode_map = 0x0F;
            op = bytes[i++];
        }
    } else if (has_vex_or_evex) {
        opcode_map = vex_opmap;
    }

    std::uint8_t rules = 0;
    if (opcode_map == 0) {
        rules = kOp1[op];
    } else if (opcode_map == 0x0F) {
        rules = kOp2[op];
    } else {
        // The three-byte maps: ModRM-shaped throughout, with an immediate
        // where the two-byte map's immediate opcodes carry one.
        rules = kHasModrm;
    }

    // The FPU map (D8-DF) encodes pairs in the ModRM's reg field; every
    // entry carries the ModRM byte and none carries an immediate.
    if (op1 >= 0xD8 && op1 <= 0xDF) {
        rules = kHasModrm;
    }

    const bool invalid = (rules & kInvalid64) != 0;
    if (invalid) {
        return 0;
    }
    const bool has_modrm = (rules & kHasModrm) != 0;

    std::size_t length = i;
    if (has_modrm) {
        if (i >= available) {
            return 0;
        }
        const std::uint8_t modrm = bytes[i++];
        ++length;
        const bool addressing16 = address16;
        // The SIB byte, when the rm field asks for one, is read here: its
        // base rule decides whether a displacement follows, and the caller
        // below cannot see it without this read.
        const bool needs_sib =
            !address16 && ((modrm & 0x7u) == 4) && ((modrm >> 6) != 3);
        const std::uint8_t sib =
            (needs_sib && i < available) ? bytes[i] : 0;
        const AddressingCost cost =
            modrm_cost(modrm, sib, needs_sib, addressing16);
        if (length + cost.bytes > available) {
            return 0;
        }
        length += cost.bytes;

        // The group opcodes that carry an immediate inside their reg field.
        std::size_t imm = 0;
        if (opcode_map == 0) {
            switch (op1) {
            case 0x69:
                imm = operand16 ? 2 : 4;
                break;
            case 0x6B:
                imm = 1;
                break;
            case 0x80:
            case 0xC0:
            case 0xC1:
            case 0xC6:
                imm = 1;
                break;
            case 0x81:
            case 0xC7:
                imm = operand16 ? 2 : 4;
                break;
            case 0x83:
                imm = 1;
                break;
            case 0xF6:
                if (((modrm >> 3) & 0x7u) <= 1) {
                    imm = 1;
                }
                break;
            case 0xF7:
                if (((modrm >> 3) & 0x7u) <= 1) {
                    imm = operand16 ? 2 : 4;
                }
                break;
            default:
                break;
            }
        } else if (opcode_map == 0x0F) {
            if (op2_has_imm8(op) || op == 0x71 || op == 0x72 || op == 0x73) {
                imm = 1;
            }
        }
        if (length + imm > available) {
            return 0;
        }
        length += imm;
        return static_cast<std::uint32_t>(length);
    }

    // The no-ModRM forms: their immediate, sized by the operand prefixes.
    // The Z-sized group is 2 or 4 bytes by operand size, except the B8+
    // register-immediate group under REX.W, which is the 8-byte movabs.
    std::size_t imm = 0;
    if ((rules & kImm8) != 0) {
        imm = 1;
    } else if ((rules & kImm16F) != 0) {
        // The return-with-immediate forms take a fixed 16 bits, whatever
        // the operand-size prefix says -- their stack pop does not shrink.
        imm = 2;
    } else if ((rules & kImmZ) != 0) {
        imm = (rex_w && op1 >= 0xB8 && op1 <= 0xBF) ? 8
                                                    : (operand16 ? 2 : 4);
    } else if ((rules & kImmV) != 0) {
        imm = rex_w ? 8 : (operand16 ? 2 : 4);
    } else if ((rules & kImmP) != 0) {
        imm = 8;
    }
    // C8 is enter, whose two immediates -- 16 bits of frame size and 8 bits
    // of nesting level -- are one encoding with three bytes.
    if (op1 == 0xC8) {
        imm = 3;
    }
    if (length + imm > available) {
        return 0;
    }
    length += imm;
    return static_cast<std::uint32_t>(length);
}

// The mnemonic for the common opcodes, as a lookup that answers null for
// anything this table does not name.
[[nodiscard]] const char* mnemonic_for(const std::uint8_t* bytes,
                                       std::size_t available) noexcept {
    std::size_t i = 0;
    std::uint8_t op = 0;
    bool op2 = false;
    bool f2f3 = false;
    while (i < available) {
        const std::uint8_t b = bytes[i];
        if (b == 0xF2 || b == 0xF3) {
            f2f3 = true;
            ++i;
        } else if (b == 0x66 || b == 0x67 || b == 0x2E || b == 0x36 ||
                   b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) {
            ++i;
        } else if (b >= 0x40 && b <= 0x4F) {
            ++i;
            break;
        } else if (b == 0xC4 || b == 0xC5) {
            return "vex";
        } else if (b == 0x62) {
            return "evex";
        } else {
            break;
        }
    }
    if (i >= available) {
        return nullptr;
    }
    op = bytes[i++];
    if (op == 0x0F && i < available) {
        op2 = true;
        op = bytes[i++];
        if ((op == 0x38 || op == 0x3A) && i < available) {
            op = bytes[i++];
        }
    }

    if (!op2) {
        switch (op) {
        case 0x00: case 0x01: case 0x02: case 0x03:
            return "add";
        case 0x08: case 0x09: case 0x0A: case 0x0B:
            return "or";
        case 0x10: case 0x11: case 0x12: case 0x13:
            return "adc";
        case 0x18: case 0x19: case 0x1A: case 0x1B:
            return "sbb";
        case 0x20: case 0x21: case 0x22: case 0x23:
            return "and";
        case 0x28: case 0x29: case 0x2A: case 0x2B:
            return "sub";
        case 0x30: case 0x31: case 0x32: case 0x33:
            return "xor";
        case 0x38: case 0x39: case 0x3A: case 0x3B:
            return "cmp";
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
            return "push";
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            return "pop";
        case 0x63: return "movsxd";
        case 0x68: case 0x6A: return "push";
        case 0x69: case 0x6B: return "imul";
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            return "jcc";
        case 0x80: case 0x81: case 0x83: return "grp1";
        case 0x84: case 0x85: return "test";
        case 0x86: case 0x87: return "xchg";
        case 0x88: case 0x89: case 0x8A: case 0x8B:
            return "mov";
        case 0x8D: return "lea";
        case 0x90: return "nop";
        case 0x98: return "cwde";
        case 0x99: return "cdq";
        case 0xA8: case 0xA9: return "test";
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            return "mov";
        case 0xC0: case 0xC1: case 0xD0: case 0xD1:
        case 0xD2: case 0xD3:
            return "shift";
        case 0xC2: case 0xC3: return "ret";
        case 0xC6: case 0xC7: return "mov";
        case 0xC9: return "leave";
        case 0xCC: return "int3";
        case 0xE8: return "call";
        case 0xE9: case 0xEB: return "jmp";
        case 0xF6: case 0xF7: return "grp3";
        case 0xFE: case 0xFF: return "grp5";
        default:
            return nullptr;
        }
    }
    switch (op) {
    case 0x05: return "syscall";
    case 0x0B: return "ud2";
    case 0x10: return f2f3 ? "sse_mov" : "sse";
    case 0x11: return "sse_mov";
    case 0x12: case 0x13: case 0x14: case 0x15:
    case 0x16: case 0x17:
        return "sse";
    case 0x18: case 0x19: case 0x1A: case 0x1B:
    case 0x1C: case 0x1D: case 0x1E: case 0x1F:
        return "nop";
    case 0x28: case 0x29: return "sse_mov";
    case 0x2A: return "sse_cvt";
    case 0x2E: case 0x2F: return "ucomis";
    case 0x31: return "rdtsc";
    case 0x40: case 0x41: case 0x42: case 0x43:
    case 0x44: case 0x45: case 0x46: case 0x47:
    case 0x48: case 0x49: case 0x4A: case 0x4B:
    case 0x4C: case 0x4D: case 0x4E: case 0x4F:
        return "cmovcc";
    case 0x51: return "sse_sqrt";
    case 0x54: case 0x55: case 0x56: case 0x57:
        return "sse_logic";
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        return "sse_arith";
    case 0x60: case 0x61: case 0x62: case 0x6C:
    case 0x6D: case 0x6E: case 0x6F:
        return "sse_pack";
    case 0x70: return "pshufd";
    case 0x7E: case 0x7F: return "sse_mov";
    case 0x80: case 0x81: case 0x82: case 0x83:
    case 0x84: case 0x85: case 0x86: case 0x87:
    case 0x88: case 0x89: case 0x8A: case 0x8B:
    case 0x8C: case 0x8D: case 0x8E: case 0x8F:
        return "jcc";
    case 0x90: case 0x91: case 0x92: case 0x93:
    case 0x94: case 0x95: case 0x96: case 0x97:
    case 0x98: case 0x99: case 0x9A: case 0x9B:
    case 0x9C: case 0x9D: case 0x9E: case 0x9F:
        return "setcc";
    case 0xA2: return "cpuid";
    case 0xA3: case 0xAB: case 0xB3: case 0xBB:
        return "bt";
    case 0xAF: return "imul";
    case 0xB0: case 0xB1: return "cmpxchg";
    case 0xB6: case 0xB7: return "movzx";
    case 0xBC: case 0xBD: return "bsf";
    case 0xBE: case 0xBF: return "movsx";
    case 0xC0: case 0xC1: return "xadd";
    case 0xC8: case 0xC9: case 0xCA: case 0xCB:
    case 0xCC: case 0xCD: case 0xCE: case 0xCF:
        return "bswap";
    case 0xD4: case 0xD6: return "sse_pack";
    case 0xEF: return "pxor";
    default:
        return nullptr;
    }
}

// The bytes as hex, lowercase, space separated -- the same spelling every
// disassembler prints, so the output can be diffed against one.
[[nodiscard]] std::string hex_bytes(const std::uint8_t* bytes,
                                    std::size_t count) {
    static const char* const digits = "0123456789abcdef";
    std::string out;
    out.reserve(count * 3);
    for (std::size_t i = 0; i < count; ++i) {
        if (i != 0) {
            out += ' ';
        }
        out += digits[bytes[i] >> 4];
        out += digits[bytes[i] & 0xF];
    }
    return out;
}

std::string x64_disassemble_json(ByteSpan bytes, std::uint64_t base_va,
                                 std::uint32_t max_instructions) {
    // The document is written by hand rather than through the JSON writer
    // the report uses, because every string here is generated from hex
    // digits and a fixed mnemonic table -- nothing needs escaping, and the
    // disassembler does not need to reach into the other file for it.
    std::string out;
    out.reserve(4 * 1024);
    out += "{\"base_va\":\"0x";
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llx",
                  static_cast<unsigned long long>(base_va));
    out += buf;
    out += "\",\"instructions\":[";

    const auto* data = static_cast<const std::uint8_t*>(bytes.data());
    std::size_t offset = 0;
    std::uint32_t decoded = 0;
    std::uint32_t invalid = 0;
    bool first = true;
    while (offset < bytes.size() && decoded < max_instructions) {
        if (!first) {
            out += ',';
        }
        first = false;
        const std::uint32_t length =
            x64_instruction_length(data + offset, bytes.size() - offset);

        out += "{\"va\":\"0x";
        std::snprintf(buf, sizeof(buf), "%llx",
                      static_cast<unsigned long long>(base_va + offset));
        out += buf;
        out += "\",\"bytes\":\"";

        if (length == 0) {
            // An undecodable byte: reported as data and skipped, which is
            // how a linear sweep crosses data embedded in code without
            // inventing instructions.
            out += hex_bytes(data + offset, 1);
            out += "\",\"mnemonic\":\".byte\",\"invalid\":true}";
            ++invalid;
            ++offset;
        } else {
            out += hex_bytes(data + offset, length);
            out += "\"";
            const char* mnemonic = mnemonic_for(data + offset, length);
            if (mnemonic != nullptr) {
                out += ",\"mnemonic\":\"";
                out += mnemonic;
                out += "\"";
            }
            out += ",\"length\":";
            std::snprintf(buf, sizeof(buf), "%u", length);
            out += buf;
            out += '}';
            offset += length;
        }
        ++decoded;
    }

    out += "],\"decoded\":";
    std::snprintf(buf, sizeof(buf), "%u", decoded);
    out += buf;
    out += ",\"undecodable\":";
    std::snprintf(buf, sizeof(buf), "%u", invalid);
    out += buf;
    out += ",\"consumed\":";
    std::snprintf(buf, sizeof(buf), "%llu",
                  static_cast<unsigned long long>(offset));
    out += buf;
    out += '}';
    return out;
}

}  // namespace occ::inspect

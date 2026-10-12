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
#include <cstring>
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
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kImm8, kImmZ, kInvalid64, kInvalid64, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kImm8, kImmZ, kInvalid64, kInvalid64,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kImm8, kImmZ, kImm8, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kImm8, kImmZ, kInvalid64, kHasModrm,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kImm8, kImmZ, kImm8, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kImm8, kImmZ, kImm8, kHasModrm,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kImm8, kImmZ, kImm8, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kImm8, kImmZ, kImm8, kHasModrm,
    kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64, kInvalid64,
    kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm,
    kInvalid64, kInvalid64, kHasModrm, kHasModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kImmZ, kHasModrm, kImm8, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kInvalid64, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm,
    kImmV, kImmV, kImmV, kImmV, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kImm8, kImmZ, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm,
    kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ, kImmZ,
    kHasModrm, kHasModrm, kImm16F, kNoModrm, kNoModrm, kNoModrm, kHasModrm, kHasModrm, kImmP, kNoModrm, kImm16F, kNoModrm, kNoModrm, kImm8, kInvalid64, kNoModrm,
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kInvalid64, kInvalid64, kInvalid64, kNoModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm,
    kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImm8, kImmZ, kImmZ, kInvalid64, kImm8, kNoModrm, kNoModrm, kNoModrm, kNoModrm,
    kInvalid64, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kHasModrm, kHasModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kHasModrm, kHasModrm,
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
    kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kHasModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm, kNoModrm,
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
    // The double shifts carry the count either as an imm8 (A4/AC) or in
    // CL (A5/AD), and only the first pair has a byte to read here.
    case 0xA4:
    case 0xAC:
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
            // The map byte and the opcode are two reads, and the check
            // above only proves the first one: a 0F 38 that ends the
            // buffer has a map with no opcode after it, and reading the
            // opcode unchecked is the read past the end.
            if (i >= available) {
                return 0;
            }
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
        case 0x9C: return "pushf";
        case 0x9D: return "popf";
        case 0x9E: return "sahf";
        case 0x9F: return "lahf";
        case 0xA4: case 0xA5: return "movs";
        case 0xA6: case 0xA7: return "cmps";
        case 0xAA: case 0xAB: return "stos";
        case 0xAC: case 0xAD: return "lods";
        case 0xAE: case 0xAF: return "scas";
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
        case 0xE0: case 0xE1: case 0xE2: case 0xE3:
            return "loop";
        case 0xE8: return "call";
        case 0xE9: case 0xEB: return "jmp";
        case 0xF4: return "hlt";
        case 0xF5: return "cmc";
        case 0xF6: case 0xF7: return "grp3";
        case 0xF8: return "clc";
        case 0xF9: return "stc";
        case 0xFA: return "cli";
        case 0xFB: return "sti";
        case 0xFC: return "cld";
        case 0xFD: return "std";
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

// The names the group opcodes resolve to, by the /digit their reg field
// carries. These are the real mnemonics: `grp1` was the decoder's honest
// admission that it had not read the reg field, and reading it is the
// difference between a length decoder and a semantic one.
[[nodiscard]] const char* group1_name(std::uint8_t reg) noexcept {
    static const char* const names[8] = {"add", "or",  "adc", "sbb",
                                         "and", "sub", "xor", "cmp"};
    return names[reg & 7];
}

[[nodiscard]] const char* group3_name(std::uint8_t reg) noexcept {
    // The grp3 encoding: /0 and /1 are both test (one reads an immediate),
    // then not, neg, and the four arithmetic pairs.
    static const char* const names[8] = {"test", "test", "not", "neg",
                                         "mul",  "imul", "div", "idiv"};
    return names[reg & 7];
}

[[nodiscard]] const char* shift_name(std::uint8_t reg) noexcept {
    static const char* const names[8] = {"rol", "ror", "rcl", "rcr",
                                         "shl", "shr", "sal", "sar"};
    return names[reg & 7];
}

[[nodiscard]] const char* jcc_name(std::uint8_t cc) noexcept {
    static const char* const names[16] = {
        "jo",  "jno", "jb",  "jae", "je",  "jne", "jbe", "ja",
        "js",  "jns", "jp",  "jnp", "jl",  "jge", "jle", "jg"};
    return names[cc & 15];
}

// The cmov and set spellings put the condition after the family, and the
// two families use the same sixteen conditions.
[[nodiscard]] const char* condition_suffix(std::uint8_t cc) noexcept {
    static const char* const names[16] = {
        "o",  "no", "b",  "ae", "e",  "ne", "be", "a",
        "s",  "ns", "p",  "np", "l",  "ge", "le", "g"};
    return names[cc & 15];
}

// -- the register tables -----------------------------------------------------
//
// Sixteen entries each, indexed by the three reg/rm bits plus the REX
// extension bit. The 8-bit table has the split the manual defines: with a
// REX prefix present the high-byte names are gone and spl/bpl/sil/dil
// replace them, which is why the table is chosen by whether a REX walked
// past, not by the instruction alone.

const char* const kReg64[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp",
                                "rsi", "rdi", "r8",  "r9",  "r10", "r11",
                                "r12", "r13", "r14", "r15"};
const char* const kReg32[16] = {"eax", "ecx", "edx", "ebx", "esp", "ebp",
                                "esi", "edi", "r8d", "r9d", "r10d", "r11d",
                                "r12d", "r13d", "r14d", "r15d"};
const char* const kReg16[16] = {"ax", "cx", "dx", "bx", "sp", "bp",
                                "si", "di", "r8w", "r9w", "r10w", "r11w",
                                "r12w", "r13w", "r14w", "r15w"};
const char* const kReg8Rex[16] = {"al", "cl", "dl", "bl", "spl", "bpl",
                                  "sil", "dil", "r8b", "r9b", "r10b", "r11b",
                                  "r12b", "r13b", "r14b", "r15b"};
const char* const kReg8[8] = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"};

[[nodiscard]] const char* reg_name(std::uint8_t index, int size,
                                   bool rex_present) noexcept {
    switch (size) {
    case 8:
        return kReg64[index & 15];
    case 4:
        return kReg32[index & 15];
    case 2:
        return kReg16[index & 15];
    case 1:
        return rex_present ? kReg8Rex[index & 15] : kReg8[index & 7];
    default:
        return "?";
    }
}

// The renderer. It writes into `out` -- the caller's fixed buffer -- and
// answers false when the form is one it does not cover, in which case the
// caller leaves the operands empty. An operand line this decoder is unsure
// of is worse than no line.
struct OperandWriter {
    char* out;
    std::size_t cap;
    std::size_t used = 0;

    bool put(const char* text) {
        while (*text != '\0') {
            if (used + 1 >= cap) {
                return false;
            }
            out[used++] = *text++;
        }
        out[used] = '\0';
        return true;
    }
    bool put_hex(std::uint64_t value) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      static_cast<unsigned long long>(value));
        return put(buf);
    }
    bool put_char(char c) {
        if (used + 1 >= cap) {
            return false;
        }
        out[used++] = c;
        out[used] = '\0';
        return true;
    }
};

// One memory operand: base + index*scale + displacement, in the order the
// Intel syntax prints them. `rip_relative` collapses the whole form to
// [rip+disp] -- the encoding's own meaning, and the shape every image
// analysis starts from.
[[nodiscard]] bool render_memory(OperandWriter& w, std::uint8_t base,
                                 std::uint8_t index, int scale, bool rex,
                                 bool rip_relative, std::int64_t disp,
                                 bool has_disp) {
    if (!w.put_char('[')) {
        return false;
    }
    if (rip_relative) {
        if (!w.put("rip")) {
            return false;
        }
        if (has_disp) {
            if (!w.put_char(disp < 0 ? '-' : '+')) {
                return false;
            }
            if (!w.put_hex(static_cast<std::uint64_t>(
                    disp < 0 ? -disp : disp))) {
                return false;
            }
        }
        return w.put_char(']');
    }
    bool wrote = false;
    if (base != 0xFF) {  // 0xFF is the "no base" sentinel
        if (!w.put(reg_name(base, 8, rex))) {
            return false;
        }
        wrote = true;
    }
    if (index != 0xFF) {
        if (wrote && !w.put_char('+')) {
            return false;
        }
        if (!w.put(reg_name(index, 8, rex))) {
            return false;
        }
        if (scale != 1) {
            char s[8];
            std::snprintf(s, sizeof(s), "*%d", scale);
            if (!w.put(s)) {
                return false;
            }
        }
        wrote = true;
    }
    if (has_disp) {
        if (disp != 0 || !wrote) {
            if (wrote && !w.put_char(disp < 0 ? '-' : '+')) {
                return false;
            }
            if (!w.put_hex(
                    static_cast<std::uint64_t>(disp < 0 ? -disp : disp))) {
                return false;
            }
        }
    }
    return w.put_char(']');
}

// The facts the semantic layer needs about one instruction's operands: the
// two register indexes, the memory form, the immediate. Filled by the
// renderer's own walk.
struct OpFacts {
    std::uint8_t reg = 0;        // the reg field, REX.R extended
    std::uint8_t rm = 0;         // the rm field, REX.B extended
    std::uint8_t base = 0xFF;    // memory base register, or 0xFF
    std::uint8_t index = 0xFF;   // memory index, or 0xFF
    int scale = 1;
    std::int64_t disp = 0;
    bool has_disp = false;
    bool rip_relative = false;
    bool is_register = false;    // mod == 3
};

[[nodiscard]] bool read_facts(const std::uint8_t* bytes, std::size_t at,
                              std::uint8_t modrm, std::uint8_t rex,
                              bool address16, OpFacts& facts) {
    facts.reg = static_cast<std::uint8_t>(((modrm >> 3) & 7) |
                                          ((rex & 0x4) != 0 ? 8 : 0));
    const std::uint8_t mod = static_cast<std::uint8_t>(modrm >> 6);
    facts.rm = static_cast<std::uint8_t>((modrm & 7) | ((rex & 0x1) != 0 ? 8 : 0));
    if (mod == 3) {
        facts.is_register = true;
        return true;
    }
    if (!address16 && (modrm & 7) == 5 && mod == 0) {
        // rip-relative, or -- with a SIB in front of it -- absolute disp32.
        // The SIB case is decided by the caller, which knows whether a SIB
        // byte is present; the facts below are the no-SIB reading.
        facts.rip_relative = true;
        facts.has_disp = true;
        std::int32_t d = 0;
        std::memcpy(&d, bytes + at, 4);
        facts.disp = d;
        return true;
    }
    if (!address16 && (modrm & 7) == 4) {
        // SIB addressing. The SIB byte sits at `at`.
        const std::uint8_t sib = bytes[at];
        const std::uint8_t sib_base = sib & 7;
        const std::uint8_t sib_index = (sib >> 3) & 7;
        const std::uint8_t sib_scale = (sib >> 6) & 3;
        facts.scale = 1 << sib_scale;
        const std::size_t disp_at = at + 1;
        if (sib_base == 5 && mod == 0) {
            facts.base = 0xFF;
            facts.has_disp = true;
            std::int32_t d = 0;
            std::memcpy(&d, bytes + disp_at, 4);
            facts.disp = d;
        } else {
            facts.base = static_cast<std::uint8_t>(
                sib_base | ((rex & 0x1) != 0 ? 8 : 0));
            if (sib_index != 4) {
                facts.index = static_cast<std::uint8_t>(
                    sib_index | ((rex & 0x2) != 0 ? 8 : 0));
            }
            if (mod == 1) {
                facts.has_disp = true;
                facts.disp = static_cast<std::int8_t>(bytes[disp_at]);
            } else if (mod == 2) {
                facts.has_disp = true;
                std::int32_t d = 0;
                std::memcpy(&d, bytes + disp_at, 4);
                facts.disp = d;
            }
        }
        return true;
    }
    // The plain forms: base is rm, displacement sized by mod.
    facts.base = facts.rm;
    facts.has_disp = mod != 3;
    if (mod == 1) {
        facts.disp = static_cast<std::int8_t>(bytes[at]);
    } else if (mod == 2) {
        std::int32_t d = 0;
        std::memcpy(&d, bytes + at, 4);
        facts.disp = d;
    }
    return true;
}

// The immediate's signed value, widened. Rendered unsigned in hex, which
// is the convention for immediates; the caller that wants the signed
// reading has the bytes.
[[nodiscard]] std::uint64_t read_immediate(const std::uint8_t* bytes,
                                           std::size_t at,
                                           std::size_t size) noexcept {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < size && i < 8; ++i) {
        v |= static_cast<std::uint64_t>(bytes[at + i]) << (i * 8);
    }
    return v;
}

std::uint32_t x64_decode(const std::uint8_t* bytes, std::size_t available,
                         std::uint64_t va, Decoded& out) noexcept {
    out = Decoded{};

    // The length decoder is the authority on where the instruction ends.
    // The semantic walk below re-derives the positions it needs -- the
    // ModRM byte, the SIB, the displacement, the immediate -- from the same
    // prefix and opcode rules; a disagreement between the two walks would
    // be a decoder bug, and the decode tests compare them on every case.
    const std::uint32_t length = x64_instruction_length(bytes, available);
    if (length == 0) {
        return 0;
    }
    out.length = length;

    // The prefix walk again, this time keeping what the semantics need.
    std::size_t i = 0;
    bool operand16 = false;
    bool address16 = false;
    bool f2 = false;
    bool f3 = false;
    std::uint8_t rex = 0;
    bool rex_present = false;
    std::uint8_t opcode_map = 0;
    while (i < available) {
        const std::uint8_t b = bytes[i];
        if (b == 0x66) {
            operand16 = true;
            ++i;
        } else if (b == 0x67) {
            address16 = true;
            ++i;
        } else if (b == 0xF2) {
            f2 = true;
            ++i;
        } else if (b == 0xF3) {
            f3 = true;
            ++i;
        } else if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
                   b == 0x64 || b == 0x65) {
            ++i;
        } else if (b >= 0x40 && b <= 0x4F) {
            rex = b;
            rex_present = true;
            ++i;
            break;
        } else if (b == 0xC4 || b == 0xC5 || b == 0x62) {
            // VEX and EVEX instructions are named by their tables and not
            // rendered operand-by-operand here; the mnemonic layer below
            // answers "vex"/"evex" for them and the operands stay empty.
            out.mnemonic = (b == 0x62) ? "evex" : "vex";
            return length;
        } else {
            break;
        }
    }

    const std::uint8_t op1 = bytes[i++];
    std::uint8_t op = op1;
    if (op1 == 0x0F && i < available) {
        opcode_map = 0x0F;
        op = bytes[i++];
        if ((op == 0x38 || op == 0x3A) && i < available) {
            opcode_map = op;
            op = bytes[i++];
        }
    }

    std::uint8_t modrm = 0;
    bool has_modrm = false;
    // Which forms carry a ModRM: the default for the one- and two-byte
    // maps, minus the no-ModRM forms the length decoder's own table names.
    if (opcode_map == 0) {
        const std::uint8_t rules = kOp1[op1];
        has_modrm = (rules & (kHasModrm | kNoModrm)) == kHasModrm;
    } else if (opcode_map == 0x0F) {
        const std::uint8_t rules = kOp2[op];
        has_modrm = (rules & (kHasModrm | kNoModrm)) == kHasModrm;
    } else {
        has_modrm = true;
    }
    if (op1 >= 0xD8 && op1 <= 0xDF) {
        has_modrm = true;
    }

    OpFacts facts;
    std::size_t after_modrm = i;
    std::size_t imm_at = 0;
    std::size_t imm_size = 0;
    if (has_modrm) {
        modrm = bytes[i++];
        after_modrm = i;
        out.has_modrm = true;
        out.modrm = modrm;
        out.reg_field = (modrm >> 3) & 7;
        // Walk the addressing, to find where the immediate would start.
        // The SIB/displacement arithmetic repeats the length decoder's
        // rules -- that is the point: the same walk, one more consumer.
        const std::uint8_t mod = static_cast<std::uint8_t>(modrm >> 6);
        std::size_t disp_size = 0;
        if (!address16 && (modrm & 7) == 4 && mod != 3) {
            const std::uint8_t sib =
                (i < available) ? bytes[i] : 0;
            ++i;  // the SIB byte
            if (mod == 1) {
                disp_size = 1;
            } else if (mod == 2) {
                disp_size = 4;
            } else if ((sib & 7) == 5) {
                disp_size = 4;
            }
        } else if (mod != 3) {
            if (!address16 && (modrm & 7) == 5 && mod == 0) {
                disp_size = 4;
            } else if (mod == 1) {
                disp_size = 1;
            } else if (mod == 2) {
                disp_size = 4;
            } else if (address16 && mod == 0 && (modrm & 7) == 6) {
                disp_size = 2;
            }
        }
        i += disp_size;
        imm_at = i;

        // The immediates, by the same rule set the length decoder uses.
        if (opcode_map == 0) {
            switch (op1) {
            case 0x69:
                imm_size = operand16 ? 2 : 4;
                break;
            case 0x6B:
                imm_size = 1;
                break;
            case 0x80:
            case 0xC0:
            case 0xC1:
            case 0xC6:
                imm_size = 1;
                break;
            case 0x81:
            case 0xC7:
                imm_size = operand16 ? 2 : 4;
                break;
            case 0x83:
                imm_size = 1;
                break;
            case 0xF6:
                if (out.reg_field <= 1) {
                    imm_size = 1;
                }
                break;
            case 0xF7:
                if (out.reg_field <= 1) {
                    imm_size = operand16 ? 2 : 4;
                }
                break;
            default:
                break;
            }
        } else if (opcode_map == 0x0F) {
            if (op2_has_imm8(op) || op == 0x71 || op == 0x72 ||
                op == 0x73) {
                imm_size = 1;
            }
        }
        (void)read_facts(bytes, after_modrm, modrm, rex, address16, facts);
    } else {
        // The no-ModRM forms' immediates.
        const std::uint8_t rules =
            opcode_map == 0 ? kOp1[op1] : kOp2[op];
        if ((rules & kImm8) != 0) {
            imm_size = 1;
        } else if ((rules & kImm16F) != 0) {
            imm_size = 2;
        } else if ((rules & kImmZ) != 0) {
            imm_size = (rex_present && (rex & 0x8) != 0 && op1 >= 0xB8 &&
                        op1 <= 0xBF)
                           ? 8
                           : (operand16 ? 2 : 4);
        } else if ((rules & kImmV) != 0) {
            imm_size = (rex_present && (rex & 0x8) != 0) ? 8
                                                         : (operand16 ? 2 : 4);
        } else if ((rules & kImmP) != 0) {
            imm_size = 8;
        }
        if (op1 == 0xC8) {
            imm_size = 3;
        }
        imm_at = i;
    }
    if (imm_size != 0 && imm_at + imm_size <= available) {
        out.has_immediate = true;
        out.immediate = read_immediate(bytes, imm_at, imm_size);
    }

    // The rip-relative target: mod 0 with rm 5 and no SIB is the form, and
    // its displacement is signed 32 relative to the *next* instruction.
    if (has_modrm && !address16) {
        const std::uint8_t mod = static_cast<std::uint8_t>(modrm >> 6);
        const bool has_sib = (modrm & 7) == 4 && mod != 3;
        if (mod == 0 && (modrm & 7) == 5 && !has_sib) {
            std::int32_t d = 0;
            std::memcpy(&d, bytes + after_modrm, 4);
            out.has_rip_target = true;
            out.rip_target =
                va + static_cast<std::uint64_t>(length) +
                static_cast<std::uint64_t>(d);
        }
    }

    // -- the mnemonic, and the shapes that make it resolve ---------------
    OperandWriter w{out.operands, Decoded::kOperandsSize};

    // Operand size, for the forms that render. Byte ops are their own
    // family; everything else sizes by REX.W and 66.
    const bool rex_w = rex_present && (rex & 0x8) != 0;
    const int size = rex_w ? 8 : (operand16 ? 2 : 4);

    // Renders "reg, r/m" or "r/m, reg" with the memory operand from the
    // facts. Answers false when the renderer could not finish.
    const auto render_rm_reg = [&](bool rm_first, const char* name) {
        if (!w.put(name) || !w.put_char(' ')) {
            return false;
        }
        const char* first =
            reg_name(rm_first ? facts.rm : facts.reg, size, rex_present);
        const char* second =
            reg_name(rm_first ? facts.reg : facts.rm, size, rex_present);
        if (facts.is_register) {
            return w.put(first) && w.put(", ") && w.put(second);
        }
        if (!w.put(second) || !w.put(", ")) {
            return false;
        }
        return render_memory(w, facts.base, facts.index, facts.scale,
                             rex_present, facts.rip_relative, facts.disp,
                             facts.has_disp);
    };

    // The signed displacement of a rel8/rel32 branch, resolved to a target.
    const auto branch = [&](InsnKind kind, std::int64_t rel) {
        out.kind = kind;
        out.has_branch_target = true;
        out.branch_target =
            va + static_cast<std::uint64_t>(length) + static_cast<std::uint64_t>(rel);
    };

    if (opcode_map == 0x0F) {
        switch (op) {
        case 0x05:
            out.mnemonic = "syscall";
            out.kind = InsnKind::Syscall;
            return length;
        case 0x0B:
            out.mnemonic = "ud2";
            return length;
        case 0x1E:
            if (f3 && out.has_modrm && out.modrm == 0xFA) {
                out.mnemonic = "endbr64";
                return length;
            }
            out.mnemonic = "nop";
            return length;
        case 0x10: case 0x11:
            out.mnemonic = f2 ? "movsd" : (f3 ? "movss"
                                              : (operand16 ? "movupd"
                                                           : "movups"));
            return length;
        case 0x28: case 0x29:
            out.mnemonic = operand16 ? "movapd" : "movaps";
            return length;
        case 0x1F:
            out.mnemonic = "nop";
            return length;
        case 0x31:
            out.mnemonic = "rdtsc";
            return length;
        case 0xA2:
            out.mnemonic = "cpuid";
            return length;
        case 0x80: case 0x81: case 0x82: case 0x83:
        case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8D: case 0x8E: case 0x8F: {
            out.mnemonic = jcc_name(op & 15);
            if (imm_at >= 4) {
                std::int32_t rel = 0;
                std::memcpy(&rel, bytes + imm_at, 4);
                branch(InsnKind::Jcc, rel);
            }
            return length;
        }
        case 0x90: case 0x91: case 0x92: case 0x93:
        case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99: case 0x9A: case 0x9B:
        case 0x9C: case 0x9D: case 0x9E: case 0x9F: {
            static char set_names[16][8];
            static bool built = false;
            if (!built) {
                for (int c = 0; c < 16; ++c) {
                    std::snprintf(set_names[c], sizeof(set_names[c]),
                                  "set%s",
                                  condition_suffix(static_cast<std::uint8_t>(c)));
                }
                built = true;
            }
            out.mnemonic = set_names[op & 15];
            return length;
        }
        case 0x40: case 0x41: case 0x42: case 0x43:
        case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4A: case 0x4B:
        case 0x4C: case 0x4D: case 0x4E: case 0x4F: {
            static char cmov_names[16][10];
            static bool built = false;
            if (!built) {
                for (int c = 0; c < 16; ++c) {
                    std::snprintf(cmov_names[c], sizeof(cmov_names[c]),
                                  "cmov%s",
                                  condition_suffix(static_cast<std::uint8_t>(c)));
                }
                built = true;
            }
            out.mnemonic = cmov_names[op & 15];
            return length;
        }
        case 0xAF:
            out.mnemonic = "imul";
            if (out.has_modrm) {
                (void)render_rm_reg(false, "imul");
            }
            return length;
        case 0xB6: case 0xB7:
            out.mnemonic = "movzx";
            return length;
        case 0xBE: case 0xBF:
            out.mnemonic = "movsx";
            return length;
        case 0xBC: case 0xBD:
            out.mnemonic = (op == 0xBC) ? "bsf" : "bsr";
            return length;
        case 0xB0: case 0xB1:
            out.mnemonic = "cmpxchg";
            return length;
        case 0xC0: case 0xC1:
            out.mnemonic = "xadd";
            return length;
        case 0xC8: case 0xC9: case 0xCA: case 0xCB:
        case 0xCC: case 0xCD: case 0xCE: case 0xCF:
            out.mnemonic = "bswap";
            return length;
        case 0xA3: case 0xAB: case 0xB3: case 0xBB:
            out.mnemonic = "bt";
            return length;
        default:
            // The opcodes this switch does not name fall through to the
            // older table, which names the common SSE families. The two
            // layers compose: the switch owns the shapes whose mnemonic
            // needs operand facts, the table owns the ones that do not.
            out.mnemonic = mnemonic_for(bytes, available);
            return length;
        }
    }

    // The one-byte map.
    if (op1 < 0x40 && (op1 & 7) <= 3) {
        static const char* const names[8] = {"add", "or",  "adc", "sbb",
                                             "and", "sub", "xor", "cmp"};
        out.mnemonic = names[op1 >> 3];
        if (has_modrm) {
            // The byte forms are the ones whose low bits name an 8-bit
            // operand: op&7 == 0 writes r/m8, op&7 == 2 reads r8,r/m8. The
            // other two -- 01 and 03 -- are the word/dword/qword forms the
            // operand-size prefix and REX.W size, which is why `mov rbp,
            // rsp` (89) and `mov spl, bpl` (88) share one reg field.
            const bool byte_op = (op1 & 7) == 0 || (op1 & 7) == 2;
            const int op_size = byte_op ? 1 : size;
            const auto render = [&](bool rm_first) {
                if (!w.put(out.mnemonic) || !w.put_char(' ')) {
                    return false;
                }
                const char* r = reg_name(facts.reg, op_size, rex_present);
                const char* m =
                    facts.is_register
                        ? reg_name(facts.rm, op_size, rex_present)
                        : nullptr;
                if (facts.is_register) {
                    return rm_first ? (w.put(m) && w.put(", ") && w.put(r))
                                    : (w.put(r) && w.put(", ") && w.put(m));
                }
                if (rm_first) {
                    if (!w.put(r) || !w.put(", ")) {
                        return false;
                    }
                    return render_memory(w, facts.base, facts.index,
                                         facts.scale, rex_present,
                                         facts.rip_relative, facts.disp,
                                         facts.has_disp);
                }
                if (!w.put(m) || !w.put(", ")) {
                    return false;
                }
                return render_memory(w, facts.base, facts.index, facts.scale,
                                     rex_present, facts.rip_relative,
                                     facts.disp, facts.has_disp);
            };
            // The direction bit decides which way the operands read.
            (void)render((op1 & 2) != 0);
        }
        return length;
    }

    switch (op1) {
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
        out.mnemonic = "push";
        w.put("push ") && w.put(reg_name(op1 - 0x50, 8, false));
        return length;
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        out.mnemonic = "pop";
        w.put("pop ") && w.put(reg_name(op1 - 0x58, 8, false));
        return length;
    case 0x63:
        out.mnemonic = "movsxd";
        return length;
    case 0x68:
        out.mnemonic = "push";
        w.put("push ") && w.put_hex(out.immediate);
        return length;
    case 0x6A:
        out.mnemonic = "push";
        w.put("push ") && w.put_hex(out.immediate);
        return length;
    case 0x69: case 0x6B:
        out.mnemonic = "imul";
        return length;
    case 0x70: case 0x71: case 0x72: case 0x73:
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        out.mnemonic = jcc_name(op1 & 15);
        if (imm_at < available) {
            branch(InsnKind::Jcc,
                   static_cast<std::int8_t>(bytes[imm_at]));
        }
        return length;
    case 0x80: case 0x81: case 0x83:
        out.mnemonic = group1_name(out.reg_field);
        if (has_modrm && out.has_immediate) {
            // 0x80 is the byte group; 0x81 and 0x83 size by the prefixes,
            // which is what puts rsp into `sub rsp, 0x20` and not spl.
            const int op_size = (op1 == 0x80) ? 1 : size;
            if (w.put(out.mnemonic) && w.put_char(' ')) {
                if (facts.is_register) {
                    w.put(reg_name(facts.rm, op_size, rex_present));
                } else {
                    (void)render_memory(w, facts.base, facts.index,
                                        facts.scale, rex_present,
                                        facts.rip_relative, facts.disp,
                                        facts.has_disp);
                }
                w.put(", ") && w.put_hex(out.immediate);
            }
        }
        return length;
    case 0x84: case 0x85:
        out.mnemonic = "test";
        return length;
    case 0x86: case 0x87:
        out.mnemonic = "xchg";
        return length;
    case 0x88: case 0x89: case 0x8A: case 0x8B:
        out.mnemonic = "mov";
        if (has_modrm) {
            // 88 and 8A are the byte forms; 89 and 8B size by the
            // prefixes. The distinction is the low bit, not the pair.
            const bool byte_op = (op1 == 0x88) || (op1 == 0x8A);
            const int op_size = byte_op ? 1 : size;
            const auto render = [&](bool rm_first) {
                if (!w.put("mov ")) {
                    return false;
                }
                const char* r = reg_name(facts.reg, op_size, rex_present);
                const char* m =
                    facts.is_register
                        ? reg_name(facts.rm, op_size, rex_present)
                        : nullptr;
                if (facts.is_register) {
                    return rm_first ? (w.put(m) && w.put(", ") && w.put(r))
                                    : (w.put(r) && w.put(", ") && w.put(m));
                }
                if (rm_first) {
                    if (!w.put(r) || !w.put(", ")) {
                        return false;
                    }
                    return render_memory(w, facts.base, facts.index,
                                         facts.scale, rex_present,
                                         facts.rip_relative, facts.disp,
                                         facts.has_disp);
                }
                if (!w.put(m) || !w.put(", ")) {
                    return false;
                }
                return render_memory(w, facts.base, facts.index, facts.scale,
                                     rex_present, facts.rip_relative,
                                     facts.disp, facts.has_disp);
            };
            (void)render((op1 & 2) != 0);
        }
        return length;
    case 0x8D:
        out.mnemonic = "lea";
        if (has_modrm) {
            if (w.put("lea ") &&
                w.put(reg_name(facts.reg, 8, rex_present)) &&
                w.put(", ")) {
                (void)render_memory(w, facts.base, facts.index, facts.scale,
                                    rex_present, facts.rip_relative,
                                    facts.disp, facts.has_disp);
            }
        }
        return length;
    case 0x90:
        out.mnemonic = "nop";
        return length;
    case 0x98:
        out.mnemonic = "cwde";
        return length;
    case 0x99:
        out.mnemonic = "cdq";
        return length;
    case 0xA8: case 0xA9:
        out.mnemonic = "test";
        return length;
    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        out.mnemonic = "mov";
        w.put("mov ") && w.put(reg_name(op1 - 0xB0, 1, rex_present)) &&
            w.put(", ") && w.put_hex(out.immediate);
        return length;
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        out.mnemonic = "mov";
        w.put("mov ") &&
            w.put(reg_name(op1 - 0xB8, rex_w ? 8 : size, rex_present)) &&
            w.put(", ") && w.put_hex(out.immediate);
        return length;
    case 0xC0: case 0xC1: case 0xD0: case 0xD1:
    case 0xD2: case 0xD3:
        out.mnemonic = shift_name(out.reg_field);
        return length;
    case 0xC2:
        out.mnemonic = "ret";
        out.kind = InsnKind::Ret;
        return length;
    case 0xC3:
        out.mnemonic = "ret";
        out.kind = InsnKind::Ret;
        return length;
    case 0xC6: case 0xC7:
        out.mnemonic = "mov";
        if (has_modrm && out.has_immediate) {
            const int op_size = (op1 == 0xC6) ? 1 : size;
            // The "mov r/m, imm" form: render from a clean writer so the
            // operand text starts at the mnemonic, whatever earlier cases
            // left in the buffer.
            out.operands[0] = '\0';
            OperandWriter w2{out.operands, Decoded::kOperandsSize};
            if (w2.put("mov ")) {
                if (facts.is_register) {
                    w2.put(reg_name(facts.rm, op_size, rex_present));
                } else {
                    (void)render_memory(w2, facts.base, facts.index,
                                        facts.scale, rex_present,
                                        facts.rip_relative, facts.disp,
                                        facts.has_disp);
                }
                w2.put(", ") && w2.put_hex(out.immediate);
            }
        }
        return length;
    case 0xC9:
        out.mnemonic = "leave";
        return length;
    case 0xCC:
        out.mnemonic = "int3";
        return length;
    case 0xE8:
        out.mnemonic = "call";
        if (imm_at + 4 <= available) {
            std::int32_t rel = 0;
            std::memcpy(&rel, bytes + imm_at, 4);
            branch(InsnKind::Call, rel);
            w.put("call ") && w.put_hex(out.branch_target);
        }
        return length;
    case 0xE9:
        out.mnemonic = "jmp";
        out.kind = InsnKind::Jmp;
        if (imm_at + 4 <= available) {
            std::int32_t rel = 0;
            std::memcpy(&rel, bytes + imm_at, 4);
            out.has_branch_target = true;
            out.branch_target = va + length +
                                static_cast<std::uint64_t>(rel);
            w.put("jmp ") && w.put_hex(out.branch_target);
        }
        return length;
    case 0xEB:
        out.mnemonic = "jmp";
        out.kind = InsnKind::Jmp;
        if (imm_at < available) {
            out.has_branch_target = true;
            out.branch_target =
                va + static_cast<std::uint64_t>(length) +
                static_cast<std::uint64_t>(
                    static_cast<std::int8_t>(bytes[imm_at]));
            w.put("jmp ") && w.put_hex(out.branch_target);
        }
        return length;
    case 0xF6: case 0xF7:
        out.mnemonic = group3_name(out.reg_field);
        if (out.mnemonic == nullptr) {
            // /7 of the grp3 encoding is not named by this decoder; the
            // group's own name is the honest answer.
            out.mnemonic = "grp3";
        }
        return length;
    case 0xFE: case 0xFF: {
        switch (out.reg_field) {
        case 0:
            out.mnemonic = "inc";
            break;
        case 1:
            out.mnemonic = "dec";
            break;
        case 2:
            out.mnemonic = "call";
            out.kind = InsnKind::Call;
            break;
        case 3:
            out.mnemonic = "lcall";
            break;
        case 4:
            out.mnemonic = "jmp";
            out.kind = InsnKind::Jmp;
            break;
        case 5:
            out.mnemonic = "ljmp";
            break;
        case 6:
            out.mnemonic = "push";
            break;
        default:
            out.mnemonic = (op1 == 0xFE) ? "grp5" : "grp5";
            break;
        }
        if (has_modrm) {
            const int op_size = (op1 == 0xFE) ? 1 : 8;
            if (w.put(out.mnemonic) && w.put_char(' ')) {
                if (facts.is_register) {
                    w.put(reg_name(facts.rm, op_size, rex_present));
                } else {
                    (void)render_memory(w, facts.base, facts.index,
                                        facts.scale, rex_present,
                                        facts.rip_relative, facts.disp,
                                        facts.has_disp);
                }
            }
        }
        return length;
    }
    default:
        out.mnemonic = mnemonic_for(bytes, available);
        return length;
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
            Decoded insn;
            (void)x64_decode(data + offset, bytes.size() - offset,
                             base_va + offset, insn);
            if (insn.mnemonic != nullptr) {
                out += ",\"mnemonic\":\"";
                out += insn.mnemonic;
                out += "\"";
            }
            if (insn.operands[0] != '\0') {
                out += ",\"operands\":\"";
                out += insn.operands;
                out += "\"";
            }
            if (insn.kind != InsnKind::Other) {
                static const char* const kinds[] = {
                    "other", "call", "jmp", "jcc", "ret", "syscall"};
                out += ",\"kind\":\"";
                out += kinds[static_cast<int>(insn.kind)];
                out += "\"";
            }
            if (insn.has_branch_target) {
                out += ",\"target\":\"0x";
                std::snprintf(buf, sizeof(buf), "%llx",
                              static_cast<unsigned long long>(
                                  insn.branch_target));
                out += buf;
                out += "\"";
            }
            if (insn.has_rip_target) {
                out += ",\"rip_target\":\"0x";
                std::snprintf(buf, sizeof(buf), "%llx",
                              static_cast<unsigned long long>(
                                  insn.rip_target));
                out += buf;
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

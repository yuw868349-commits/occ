// Dynamic binary instrumentation: block splitting, edge coverage and a
// load-time rewriter.
//
// The design is in the header; this file is the decoder, the splitter and
// the rewriter working it out.
//
// The decoder is deliberately narrow. It answers two questions per
// instruction -- how long it is and whether it transfers control -- for
// the integer instruction family a 64-bit compiler emits, and refuses
// everything else (floating point, the x87 stack, most system and
// vector instructions, and the VEX/EVEX encodings). A refusal is not a
// degradation of the rewrite: it is the honest answer that this rewriter
// cannot prove it saw every byte of a region, and an unproven region is
// left alone rather than half-rewritten. The table below is written to be
// read as a table; each entry names the byte pattern it covers and the
// reason the pattern is in the common family.
//
// The rewriter's contract with the probe is one crossing per block head.
// Every block begins with a 37-byte stub that preserves every register and
// the flags, calls the probe with the block's id, restores everything, and
// then runs the block's own instructions. The probe derives the edge from
// (last, id), so the first crossing into the region records an edge from
// block zero -- the entry probe sees `last == 0` and the region's entry
// block id is 1, so the first edge is (0, 1) and collisions with real
// edges are what the map's hash accepts. The entry block id is 1 by
// construction: block 0 is the pseudo-block the probe's `last` starts at.
//
// Stack alignment is documented rather than solved. A Windows function
// entry has rsp % 16 == 8 (the caller's call pushed eight bytes), and
// compiler code keeps that alignment through a function body, so a block
// head normally sees rsp % 16 == 8. The stub pushes five quadwords
// (pushfq plus four pushes), which moves rsp by 40 bytes and leaves
// rsp % 16 == 0 at the probe's call in that normal case. A block entered
// with rsp % 16 == 0 calls the probe misaligned; the probe is a short
// function that touches no stack-aligned state, so the misalignment is
// harmless in practice, and forcing alignment for both cases is impossible
// (the two cases need odd and even push counts respectively).
//
// Relocation rules, in the order the rewriter applies them:
//
//   * A control transfer whose target is a block start in the region is
//     re-encoded toward the copy. An 8-bit displacement that no longer
//     fits grows to 32 bits (Jcc 70-7F -> 0F 8x; JMP EB -> E9).
//   * A transfer whose target lies inside a block (not at its start) is a
//     refusal: the rewriter cannot prove the target decodes to the same
//     instruction stream in the copy, and a wrong answer is worse than no
//     answer.
//   * A CALL or JMP whose target lies outside the region is turned into
//     an absolute transfer to the original target address (movabs r11,
//     target; call/jmp r11). The target code still executes -- it is the
//     original image, which the rewrite never touched -- it just runs
//     without coverage. This is the honest trade: correctness of the
//     transfer, and coverage that stops at the region's edge.
//   * An indirect transfer (FF /2, FF /4) and a RET are copied unchanged:
//     their targets are absolute addresses resolved at run time and need
//     no relocation.
//   * A RIP-relative memory operand is relocated so that it still names
//     the original absolute target (inside the region or not). The
//     displacement is recomputed from the new position of the following
//     instruction.
//   * Immediate operands that happen to contain addresses (movabs rax,
//     <addr>) are copied unchanged: an immediate is data, and the data of
//     the original image remains valid.

#include "occ/dbi/dbi.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

namespace occ::dbi {

namespace {

// ---------------------------------------------------------------------------
// The length decoder
// ---------------------------------------------------------------------------

// Prefix groups. Group 3 (66) and group 4 (REX) are the only ones that
// change length arithmetic, and REX must be the last prefix, which the
// loop below enforces by treating a REX byte as the end of the prefix
// run.
enum : std::uint8_t {
    kPrefixLock = 0xF0,
    kPrefixRep = 0xF2,
    kPrefixRepNe = 0xF3,
    kPrefix66 = 0x66,
    kPrefix67 = 0x67,
    kPrefix2E = 0x2E,
    kPrefix36 = 0x36,
    kPrefix3E = 0x3E,
    kPrefix26 = 0x26,
    kPrefix64 = 0x64,
    kPrefix65 = 0x65,
    kRexMin = 0x40,
    kRexMax = 0x4F,
    kTwoByte = 0x0F,
};

// Whether a byte is a recognized legacy prefix (not REX; REX is handled
// separately because it must terminate the prefix run).
[[nodiscard]] bool is_legacy_prefix(std::uint8_t b) noexcept {
    switch (b) {
    case kPrefixLock:
    case kPrefixRep:
    case kPrefixRepNe:
    case kPrefix66:
    case kPrefix67:
    case kPrefix2E:
    case kPrefix36:
    case kPrefix3E:
    case kPrefix26:
    case kPrefix64:
    case kPrefix65:
        return true;
    default:
        return false;
    }
}

// Whether a single-byte opcode has a ModRM byte after it.
[[nodiscard]] bool opcode_has_modrm(std::uint8_t op) noexcept {
    // Grouped by the arithmetic families, then by the odd members that
    // still take a ModRM.
    if (op <= 0x3F) {
        // 00-3F is the ALU r/m, r family -- with one exception: the
        // accumulator-immediate forms 04/05/0C/0D/14/15/1C/1D/24/25/
        // 2C/2D/34/35/3C/3D (add/or/adc/sbb/and/sub/xor/cmp al|eax,
        // imm) take no ModRM. The decoder must not consume the immediate
        // as a ModRM byte; the length is resolved by opcode_imm_size.
        switch (op) {
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
            return false;
        default:
            return true;
        }
    }
    switch (op) {
    case 0x62: // bound (the 64-bit form is a trap, but the encoding
               // shape is still ModRM).
    case 0x63: // movsxd r64, r/m32.
    case 0x69: // imul r, r/m, imm32.
    case 0x6B: // imul r, r/m, imm8.
    case 0x80: // ALU r/m8, imm8.
    case 0x81: // ALU r/m, imm16/32.
    case 0x82: // ALU r/m8, imm8 (deprecated but still decoded).
    case 0x83: // ALU r/m, imm8 sign-extended.
    case 0x84: // test r/m8, r8.
    case 0x85: // test r/m, r.
    case 0x86: // xchg r/m8, r8.
    case 0x87: // xchg r/m, r.
    case 0x88: // mov r/m8, r8.
    case 0x89: // mov r/m, r.
    case 0x8A: // mov r8, r/m8.
    case 0x8B: // mov r, r/m.
    case 0x8D: // lea r, m.
    case 0x8F: // pop r/m.
    case 0xC0: // shift r/m8, imm8.
    case 0xC1: // shift r/m, imm8.
    case 0xC6: // mov r/m8, imm8.
    case 0xC7: // mov r/m, imm16/32.
    case 0xD0: // shift r/m8, 1.
    case 0xD1: // shift r/m, 1.
    case 0xD2: // shift r/m8, cl.
    case 0xD3: // shift r/m, cl.
    case 0xF6: // test/not/neg/mul/imul/div/idiv r/m.
    case 0xF7: // the 32/64-bit form of the same.
    case 0xFE: // inc/dec r/m8.
    case 0xFF: // inc/dec/call/jmp/push r/m.
        return true;
    default:
        return false;
    }
}

// Whether a two-byte opcode (0F xx) has a ModRM byte after it. The 0F
// space is mostly vector instructions, which this decoder refuses anyway;
// the entries here are the integer family members a compiler emits.
[[nodiscard]] bool opcode0f_has_modrm(std::uint8_t op) noexcept {
    switch (op) {
    case 0x01: // lgdt/lidt/sgdt/... (system; shape is ModRM).
    case 0x10: // movups/movss (vector shape, refused later; length is
               // still ModRM).
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x14:
    case 0x15:
    case 0x16:
    case 0x17:
    case 0x1E: // nop with ModRM (multibyte nop: 0F 1F /0).
    case 0x1F:
    case 0x40: // cmovcc.
    case 0x41:
    case 0x42:
    case 0x43:
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x48:
    case 0x49:
    case 0x4A:
    case 0x4B:
    case 0x4C:
    case 0x4D:
    case 0x4E:
    case 0x4F:
    case 0x90: // setcc.
    case 0x91:
    case 0x92:
    case 0x93:
    case 0x94:
    case 0x95:
    case 0x96:
    case 0x97:
    case 0x98:
    case 0x99:
    case 0x9A:
    case 0x9B:
    case 0x9C:
    case 0x9D:
    case 0x9E:
    case 0x9F:
    case 0xA3: // bt r/m, r.
    case 0xA4: // shld r/m, r, imm8.
    case 0xA5: // shld r/m, r.
    case 0xA6: // cmpxchg (r/m8 form).
    case 0xA7:
    case 0xAB: // bts r/m, r.
    case 0xAC: // shrd r/m, r, imm8.
    case 0xAD: // shrd r/m, r.
    case 0xAE: // fxsave/fxrstor/... (ModRM shape).
    case 0xAF: // imul r, r/m.
    case 0xB0: // cmpxchg r/m8, r8.
    case 0xB1:
    case 0xB2: // lss (ModRM shape).
    case 0xB3: // btr r/m, r.
    case 0xB6: // movzx r, r/m8.
    case 0xB7: // movzx r, r/m16.
    case 0xB8: // popcnt (F3-prefixed) / a form of jmpe; shape is ModRM.
    case 0xB9: // ud1 (ModRM shape).
    case 0xBA: // bt/bts/btr/btc r/m, imm8.
    case 0xBB: // btc r/m, r.
    case 0xBC: // bsf / tzcnt (F3-prefixed).
    case 0xBD: // bsr / lzcnt (F3-prefixed).
    case 0xBE: // movsx r, r/m8.
    case 0xBF: // movsx r, r/m16.
    case 0xC0: // xadd r/m8, r8.
    case 0xC1: // xadd r/m, r.
    case 0xC7: // xbegin (ModRM shape).
        return true;
    default:
        return false;
    }
}

// The immediate size, in bytes, for a single-byte opcode, or 0 when the
// instruction takes no immediate (or the immediate size depends on the
// ModRM, which the caller resolves separately).
[[nodiscard]] std::uint32_t opcode_imm_size(std::uint8_t op,
                                            bool rex_w) noexcept {
    if (op >= 0x70 && op <= 0x7F) {
        return 1; // Jcc rel8.
    }
    switch (op) {
    case 0x04:
    case 0x0C:
    case 0x14:
    case 0x1C:
    case 0x24:
    case 0x2C:
    case 0x34:
    case 0x3C:
        return 1; // ALU al, imm8.
    case 0x05:
    case 0x0D:
    case 0x15:
    case 0x1D:
    case 0x25:
    case 0x2D:
    case 0x35:
    case 0x3D:
        return 4; // ALU eax, imm32 (narrows to imm16 under 66).
    case 0x6A: // push imm8.
    case 0x6B: // imul r, r/m, imm8.
    case 0x80:
    case 0x82:
    case 0x83: // ALU r/m, imm8.
    case 0xA8: // test al, imm8.
    case 0xB0:
    case 0xB1:
    case 0xB2:
    case 0xB3:
    case 0xB4:
    case 0xB5:
    case 0xB6:
    case 0xB7: // mov r8, imm8.
    case 0xC0:
    case 0xC1: // shift r/m, imm8.
    case 0xC6: // mov r/m8, imm8.
    case 0xD4: // aam imm8.
    case 0xD5: // aad imm8.
    case 0xE4: // in al, imm8.
    case 0xE5: // in eax, imm8.
    case 0xE6: // out imm8, al.
    case 0xE7: // out imm8, eax.
    case 0xEB: // jmp rel8.
        return 1;
    case 0x68: // push imm16/32.
        return 2; // 66 narrows it; the caller resolves via prefix66.
    case 0x69: // imul r, r/m, imm32.
    case 0x81: // ALU r/m, imm32.
    case 0xA9: // test eax, imm32.
    case 0xC7: // mov r/m, imm32.
    case 0xE8: // call rel32.
    case 0xE9: // jmp rel32.
        return 4;
    case 0xB8: // mov r32/r64, imm32/imm64.
    case 0xB9:
    case 0xBA:
    case 0xBB:
    case 0xBC:
    case 0xBD:
    case 0xBE:
    case 0xBF:
        return rex_w ? 8 : 4;
    case 0xC2: // ret imm16.
    case 0xC8: // enter imm16, imm8.
    case 0xCA: // retf imm16.
        return 2;
    default:
        return 0;
    }
}

// The immediate size for a two-byte opcode. The 0F space has few
// immediates in the integer family; the conditional jumps carry their
// rel32 displacement as one.
[[nodiscard]] std::uint32_t opcode0f_imm_size(std::uint8_t op) noexcept {
    if (op >= 0x80 && op <= 0x8F) {
        return 4; // Jcc rel32.
    }
    switch (op) {
    case 0xA4: // shld r/m, r, imm8.
    case 0xAC: // shrd r/m, r, imm8.
    case 0xBA: // bt/bts/btr/btc r/m, imm8.
        return 1;
    case 0xC8: // bswap: no immediate.
    default:
        return 0;
    }
}

// Whether a two-byte opcode is in the family this decoder accepts (the
// integer family). Everything else -- the vector space 0F 20-8F with the
// exceptions handled in opcode0f_has_modrm, the x87 space D8-DF, the
// decimal space -- is refused.
[[nodiscard]] bool opcode0f_accepted(std::uint8_t op) noexcept {
    switch (op) {
    case 0x01:
    case 0x05: // syscall.
    case 0x06: // clts.
    case 0x08: // invd.
    case 0x09: // wbinvd.
    case 0x0B: // ud2.
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x14:
    case 0x15:
    case 0x16:
    case 0x17:
    case 0x1E:
    case 0x1F: // nop family.
    case 0x20: // mov to/from control registers (ModRM; rare but integer).
    case 0x21:
    case 0x22:
    case 0x23:
    case 0x30: // wrmsr.
    case 0x31: // rdtsc.
    case 0x32: // rdmsr.
    case 0x33: // rdpmc.
    case 0x34: // sysenter.
    case 0x35: // sysexit.
    case 0x40:
    case 0x41:
    case 0x42:
    case 0x43:
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x48:
    case 0x49:
    case 0x4A:
    case 0x4B:
    case 0x4C:
    case 0x4D:
    case 0x4E:
    case 0x4F: // cmovcc.
    case 0x80:
    case 0x81:
    case 0x82:
    case 0x83:
    case 0x84:
    case 0x85:
    case 0x86:
    case 0x87:
    case 0x88:
    case 0x89:
    case 0x8A:
    case 0x8B:
    case 0x8C:
    case 0x8D:
    case 0x8E:
    case 0x8F: // jcc rel32.
    case 0x90:
    case 0x91:
    case 0x92:
    case 0x93:
    case 0x94:
    case 0x95:
    case 0x96:
    case 0x97:
    case 0x98:
    case 0x99:
    case 0x9A:
    case 0x9B:
    case 0x9C:
    case 0x9D:
    case 0x9E:
    case 0x9F: // setcc.
    case 0xA0: // push fs.
    case 0xA1: // pop fs.
    case 0xA2: // cpuid.
    case 0xA3:
    case 0xA4:
    case 0xA5:
    case 0xA6:
    case 0xA7: // shld/shrd/cmpxchg family.
    case 0xA8: // push gs.
    case 0xA9: // pop gs.
    case 0xAB:
    case 0xAC:
    case 0xAD:
    case 0xAE:
    case 0xAF:
    case 0xB0:
    case 0xB1:
    case 0xB2:
    case 0xB3:
    case 0xB6:
    case 0xB7:
    case 0xB8:
    case 0xB9:
    case 0xBA:
    case 0xBB:
    case 0xBC:
    case 0xBD:
    case 0xBE:
    case 0xBF:
    case 0xC0:
    case 0xC1: // xadd.
    case 0xC2: // cmpxchg r/m, r (the non-vector form; the vector form of
              // the same opcode is refused by the ModRM table below? no --
              // 0F C2 is cmpxchg only without a VEX; the vector form is
              // 0F C2 with a ModRM; both take the same bytes, so the
              // length is the same either way).
    case 0xC3: // movnti (ModRM).
    case 0xC7: // xbegin.
    case 0xC8:
    case 0xC9:
    case 0xCA:
    case 0xCB:
    case 0xCC:
    case 0xCD:
    case 0xCE:
    case 0xCF: // bswap r32/r64.
        return true;
    default:
        return false;
    }
}

// Decodes the ModRM/SIB/displacement part of an instruction. Returns the
// byte length of that part, or -1 on an impossible encoding.
[[nodiscard]] std::int64_t decode_modrm(const std::uint8_t* p,
                                        std::size_t avail, bool& rip_rel,
                                        std::uint32_t& disp_offset) noexcept {
    if (avail < 1) {
        return -1;
    }
    const std::uint8_t m = p[0];
    const std::uint32_t mod = (m >> 6) & 3;
    const std::uint32_t rm = m & 7;
    std::uint32_t extra = 1; // The ModRM byte itself.
    if (mod != 3 && rm == 4) {
        // SIB follows.
        if (avail < extra + 1) {
            return -1;
        }
        const std::uint8_t sib = p[extra];
        const std::uint32_t base = sib & 7;
        ++extra;
        if (mod == 0 && base == 5) {
            // disp32 with no base register. Not RIP-relative.
            extra += 4;
        } else if (mod == 1) {
            extra += 1;
        } else if (mod == 2) {
            extra += 4;
        }
        return static_cast<std::int64_t>(extra);
    }
    if (mod == 0 && rm == 5) {
        // RIP-relative: disp32 names the target from the next instruction.
        rip_rel = true;
        disp_offset = extra; // Relative to the ModRM byte; the caller
                             // adds the ModRM position within the
                             // instruction.
        extra += 4;
        return static_cast<std::int64_t>(extra);
    }
    if (mod == 1) {
        extra += 1;
    } else if (mod == 2) {
        extra += 4;
    }
    return static_cast<std::int64_t>(extra);
}

// The branch classification for an opcode. Returns the kind and, for the
// relative forms, the displacement size and the position of the
// displacement.
enum class BranchShape {
    None,
    Jcc8, // 70-7F, displacement rel8.
    Jcc32, // 0F 80-8F, displacement rel32.
    Jmp8, // EB.
    Jmp32, // E9.
    Call32, // E8.
    IndirectCall, // FF /2.
    IndirectJmp, // FF /4.
    Ret, // C2/C3/CA/CB.
};

[[nodiscard]] BranchShape shape_for(std::uint8_t op, bool two_byte,
                                    const std::uint8_t* p,
                                    std::size_t avail) noexcept {
    if (!two_byte) {
        if (op >= 0x70 && op <= 0x7F) {
            return BranchShape::Jcc8;
        }
        switch (op) {
        case 0xE8:
            return BranchShape::Call32;
        case 0xE9:
            return BranchShape::Jmp32;
        case 0xEB:
            return BranchShape::Jmp8;
        case 0xC2:
        case 0xC3:
        case 0xCA:
        case 0xCB:
            return BranchShape::Ret;
        case 0xFF:
            // FF /2 is call r/m, FF /4 is jmp r/m. The ModRM is the byte
            // after the opcode.
            if (avail >= 1) {
                const std::uint32_t reg = (p[0] >> 3) & 7;
                if (reg == 2) {
                    return BranchShape::IndirectCall;
                }
                if (reg == 4) {
                    return BranchShape::IndirectJmp;
                }
            }
            return BranchShape::None;
        default:
            return BranchShape::None;
        }
    }
    if (op >= 0x80 && op <= 0x8F) {
        return BranchShape::Jcc32;
    }
    return BranchShape::None;
}

} // namespace

// ---------------------------------------------------------------------------
// Public decoding
// ---------------------------------------------------------------------------

bool decode_insn(const std::uint8_t* p, std::size_t avail,
                 DecodedInsn& out) noexcept {
    if (avail == 0) {
        return false;
    }
    std::size_t at = 0;
    bool rex_w = false;
    bool prefix66 = false;
    // Prefix run. REX must terminate it.
    for (;;) {
        if (at >= avail) {
            return false;
        }
        const std::uint8_t b = p[at];
        if (is_legacy_prefix(b)) {
            prefix66 = prefix66 || (b == kPrefix66);
            ++at;
            continue;
        }
        if (b >= kRexMin && b <= kRexMax) {
            rex_w = (b & 0x08) != 0;
            ++at;
            break; // REX terminates the prefix run.
        }
        break;
    }
    if (at >= avail) {
        return false;
    }
    const std::size_t prefix_len = at;
    std::uint8_t op = p[at];
    ++at;
    bool two_byte = false;
    if (op == kTwoByte) {
        if (at >= avail) {
            return false;
        }
        two_byte = true;
        op = p[at];
        ++at;
    }
    // Accept the opcode.
    const bool accepted =
        two_byte ? opcode0f_accepted(op) : (op < 0x40 || op > 0x4F);
    if (!accepted) {
        return false;
    }
    // The branch shape, read before the ModRM/imm bytes so the lengths
    // add up in the same order the bytes appear. `op` holds the real
    // opcode whether the instruction is one- or two-byte prefixed.
    const BranchShape shape =
        shape_for(op, two_byte, p + at, avail - at);
    // ModRM.
    bool rip_rel = false;
    std::uint32_t modrm_disp_off = 0;
    const bool has_modrm =
        two_byte ? opcode0f_has_modrm(op) : opcode_has_modrm(op);
    if (has_modrm) {
        if (at >= avail) {
            return false;
        }
        const std::int64_t extra =
            decode_modrm(p + at, avail - at, rip_rel, modrm_disp_off);
        if (extra < 0) {
            return false;
        }
        at += static_cast<std::size_t>(extra);
    }
    // Immediate.
    std::uint32_t imm = two_byte ? opcode0f_imm_size(op)
                                 : opcode_imm_size(op, rex_w);
    if (imm == 4 && prefix66) {
        // ALU r/m, imm16 under 66: the immediate is 16 bits, not 32.
        // 69/81/A9/C7 are the members that take imm32 and narrow under
        // 66; the shift-imm8 and push-imm members are unaffected.
        imm = 2;
    }
    if (at + imm > avail) {
        return false;
    }
    at += imm;
    // Assemble the answer.
    DecodedInsn d;
    d.len = static_cast<std::uint32_t>(at);
    d.rip_relative = rip_rel;
    if (rip_rel) {
        // The ModRM byte sits after the opcode, which is after the prefix
        // run; the displacement begins modrm_disp_off bytes after it.
        const std::size_t modrm_pos =
            prefix_len + 1 + (two_byte ? 1 : 0);
        d.disp_offset = static_cast<std::uint32_t>(modrm_pos + modrm_disp_off);
    }
    switch (shape) {
    case BranchShape::Jcc8:
    case BranchShape::Jmp8:
        d.branch = BranchKind::Rel8;
        // The displacement is the instruction's last byte.
        if (d.len >= 1) {
            const std::int8_t v = static_cast<std::int8_t>(p[d.len - 1]);
            d.disp = v;
        }
        break;
    case BranchShape::Jcc32:
    case BranchShape::Jmp32:
    case BranchShape::Call32:
        d.branch = BranchKind::Rel32;
        if (d.len >= 4) {
            std::int32_t v = 0;
            std::memcpy(&v, p + d.len - 4, 4);
            d.disp = v;
        }
        break;
    case BranchShape::IndirectCall:
        d.branch = BranchKind::Indirect;
        break;
    case BranchShape::IndirectJmp:
        d.branch = BranchKind::Indirect;
        break;
    case BranchShape::Ret:
        d.branch = BranchKind::Ret;
        break;
    case BranchShape::None:
        d.branch = BranchKind::None;
        break;
    }
    out = d;
    return true;
}

// ---------------------------------------------------------------------------
// Block splitting
// ---------------------------------------------------------------------------

bool split_blocks(const std::uint8_t* code, std::size_t size,
                  std::uint64_t base, std::vector<Block>& out) noexcept {
    out.clear();
    (void)base; // Kept in the signature for the caller's bookkeeping; the
                // split itself only needs the byte stream.
    if (size == 0) {
        return true;
    }
    // Find every block start. A start is the region's first byte, the byte
    // after a terminating transfer (an unconditional jump, a return, an
    // indirect transfer), or the target of any relative branch or call.
    // The scan has to distinguish an unconditional jump (no fallthrough)
    // from a call or a conditional jump (fallthrough), which the
    // BranchKind alone does not carry, so the opcode's first byte is read
    // here -- one source of truth is the byte stream itself.
    std::vector<bool> is_start(size, false);
    is_start[0] = true;
    std::size_t at = 0;
    bool terminated = false;
    while (at < size) {
        if (terminated) {
            is_start[at] = true;
            terminated = false;
        }
        DecodedInsn d;
        if (!decode_insn(code + at, size - at, d)) {
            out.clear();
            return false; // A region that half-decodes is refused whole.
        }
        if (d.branch == BranchKind::Rel8 || d.branch == BranchKind::Rel32) {
            const std::int64_t target =
                static_cast<std::int64_t>(at + d.len) + d.disp;
            if (target >= 0 && target < static_cast<std::int64_t>(size)) {
                is_start[static_cast<std::size_t>(target)] = true;
            }
            // EB is the unconditional short jump, E9 the near jump; both
            // terminate their block. E8 (call) and the conditional jumps
            // fall through.
            const std::uint8_t first = code[at];
            const bool unconditional = (first == 0xEB) || (first == 0xE9);
            if (unconditional) {
                terminated = true;
            }
        } else if (d.branch == BranchKind::Ret ||
                   d.branch == BranchKind::Indirect) {
            terminated = true;
        }
        at += d.len;
    }
    // Collect the starts in order and build the blocks between them.
    std::vector<std::size_t> starts;
    starts.reserve(size / 8 + 1);
    for (std::size_t i = 0; i < size; ++i) {
        if (is_start[i]) {
            starts.push_back(i);
        }
    }
    for (std::size_t i = 0; i < starts.size(); ++i) {
        const std::size_t begin = starts[i];
        const std::size_t end = (i + 1 < starts.size()) ? starts[i + 1] : size;
        Block b;
        b.offset = static_cast<std::uint32_t>(begin);
        b.size = static_cast<std::uint32_t>(end - begin);
        b.entry = (begin == 0);
        std::size_t at2 = begin;
        while (at2 < end) {
            DecodedInsn d;
            if (!decode_insn(code + at2, size - at2, d)) {
                out.clear();
                return false;
            }
            const std::uint8_t first = code[at2];
            if (d.branch == BranchKind::Rel8 ||
                d.branch == BranchKind::Rel32) {
                const std::int64_t target =
                    static_cast<std::int64_t>(at2 + d.len) + d.disp;
                if (target >= 0 && target < static_cast<std::int64_t>(size)) {
                    b.targets.push_back(static_cast<std::uint32_t>(target));
                }
                const bool unconditional = (first == 0xEB) || (first == 0xE9);
                if (unconditional) {
                    b.ends_transfer = true;
                }
            } else if (d.branch == BranchKind::Ret ||
                       d.branch == BranchKind::Indirect) {
                b.ends_transfer = true;
            }
            at2 += d.len;
        }
        out.push_back(b);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

Coverage global_coverage;

void default_probe(std::uint32_t block_id) noexcept {
    const std::uint64_t from = global_coverage.last;
    const std::uint64_t to = block_id;
    const std::uint32_t s = Coverage::slot(from, to);
    if (global_coverage.map[s] < 0xFF) {
        if (global_coverage.map[s] == 0) {
            ++global_coverage.edges;
        }
        ++global_coverage.map[s];
    }
    ++global_coverage.hits;
    global_coverage.last = to;
}

// ---------------------------------------------------------------------------
// Rewriting
// ---------------------------------------------------------------------------

namespace {

// The per-block instrumentation stub, emitted before the block's own
// instructions. The layout and its alignment note are in the header
// (kStubLen); this function only assembles the bytes.

void emit_stub(std::vector<std::uint8_t>& code, std::uint64_t probe,
               std::uint32_t block_id) noexcept {
    const std::uint8_t stub[kStubLen] = {
        0x9C,                // pushfq
        0x57,                // push rdi
        0x41, 0x53,          // push r11
        0x41, 0x52,          // push r10
        0x50,                // push rax
        0x53,                // push rbx
        0x51,                // push rcx
        0x49, 0xBB,          // movabs r11, ...
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xBF,          // movabs rdi, ...
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x41, 0xFF, 0xD3,    // call r11
        0x59,                // pop rcx
        0x5B,                // pop rbx
        0x58,                // pop rax
        0x41, 0x5A,          // pop r10
        0x41, 0x5B,          // pop r11
        0x5F,                // pop rdi
        0x9D,                // popfq
    };
    std::uint8_t buf[kStubLen];
    std::memcpy(buf, stub, kStubLen);
    // The movabs r11, imm64 immediate begins at byte 11 (after the two
    // opcode bytes at 9-10); the movabs rdi, imm64 immediate at byte 21.
    std::memcpy(buf + 11, &probe, 8);
    std::memcpy(buf + 21, &block_id, 4);
    code.insert(code.end(), buf, buf + kStubLen);
}

// A control transfer whose target lies outside the region is emitted as
// movabs r11, target; call/jmp r11, so that the copy still reaches the
// original code. `op` is 0xE8-style: emit_call chooses call or jmp.
void emit_abs_transfer(std::vector<std::uint8_t>& code, std::uint64_t target,
                       bool call) noexcept {
    code.push_back(0x49);
    code.push_back(0xBB);
    const std::uint8_t* tp = reinterpret_cast<const std::uint8_t*>(&target);
    code.insert(code.end(), tp, tp + 8);
    if (call) {
        code.push_back(0x41);
        code.push_back(0xFF);
        code.push_back(0xD3); // call r11
    } else {
        code.push_back(0x41);
        code.push_back(0xFF);
        code.push_back(0xE3); // jmp r11
    }
}

// Reads a little-endian 32-bit signed value. Used by the relocation pass
// to recover the original RIP-relative displacement.
[[nodiscard]] std::int32_t read_le32(const std::uint8_t* p) noexcept {
    std::int32_t v = 0;
    std::memcpy(&v, p, 4);
    return v;
}

} // namespace

bool instrument(const std::uint8_t* code, std::size_t size,
                std::uint64_t base, const std::vector<Block>& blocks,
                Instrumented& out, const char** why,
                CoverageFn probe) noexcept {
    out.code.clear();
    out.blocks.clear();
    out.block_count = 0;
    if (blocks.empty()) {
        if (why) {
            *why = "empty region";
        }
        return false;
    }
    if (probe == nullptr) {
        probe = default_probe;
    }
    // The probe address, as a value the stub can load.
    const std::uint64_t probe_addr =
        reinterpret_cast<std::uint64_t>(reinterpret_cast<void*>(probe));
    // The block-start map: original offset -> offset in the copy
    // (including the stub). Filled by a first pass that only measures, so
    // that a transfer targeting a later block sees a settled address
    // while the copy is being written.
    std::vector<std::uint64_t> new_start(size, 0);
    std::vector<bool> is_block_start(size, false);
    for (const Block& b : blocks) {
        if (b.offset >= size) {
            if (why) {
                *why = "block offset out of range";
            }
            return false;
        }
        is_block_start[b.offset] = true;
    }
    // The length the rewritten copy of one instruction will occupy. Short
    // branches grow to their 32-bit forms, and an out-of-region transfer
    // becomes a 13-byte absolute move-plus-transfer.
    const auto rewritten_len = [&](std::size_t at,
                                   const DecodedInsn& d) -> std::uint32_t {
        if (d.branch == BranchKind::Rel8 || d.branch == BranchKind::Rel32) {
            const std::int64_t target_off =
                static_cast<std::int64_t>(at + d.len) + d.disp;
            const bool outside = target_off < 0 ||
                                 target_off >= static_cast<std::int64_t>(size);
            if (outside) {
                return 13;
            }
            if (!is_block_start[static_cast<std::size_t>(target_off)]) {
                // Checked here, during measurement, so that the refusal
                // happens before any bytes are written.
                return d.len; // The pass below refuses; see rewritten_len's
                              // caller. This value is never used.
            }
            const std::uint8_t first = code[at];
            if (first >= 0x70 && first <= 0x7F) {
                return 6; // Jcc rel8 -> 0F 8x rel32.
            }
            if (first == 0xEB) {
                return 5; // JMP rel8 -> E9 rel32.
            }
            if (first == 0x0F) {
                return 6; // Jcc rel32 keeps its shape.
            }
            return 5; // E8/E9 keep their shape.
        }
        return d.len;
    };
    // Pass 1: measure. The block-start offsets in the copy are decided
    // here and every transfer's target is checked for block-start
    // membership before anything is emitted.
    std::uint64_t cursor = 0;
    for (const Block& b : blocks) {
        new_start[b.offset] = cursor;
        cursor += kStubLen;
        std::size_t at = b.offset;
        const std::size_t end = b.offset + b.size;
        while (at < end) {
            DecodedInsn d;
            if (!decode_insn(code + at, end - at, d)) {
                if (why) {
                    *why = "instruction refused to decode";
                }
                return false;
            }
            if (d.branch == BranchKind::Rel8 || d.branch == BranchKind::Rel32) {
                const std::int64_t target_off =
                    static_cast<std::int64_t>(at + d.len) + d.disp;
                if (target_off >= 0 &&
                    target_off < static_cast<std::int64_t>(size) &&
                    !is_block_start[static_cast<std::size_t>(target_off)]) {
                    if (why) {
                        *why = "jump into the middle of a block";
                    }
                    return false;
                }
            }
            cursor += rewritten_len(at, d);
            at += d.len;
        }
    }
    // Pass 2: emit. All block-start addresses are now settled, so every
    // transfer can be re-targeted toward the copy.
    cursor = 0;
    for (const Block& b : blocks) {
        // Block ids run from 1 so that the probe's initial `last == 0`
        // names a real first crossing (0, 1) instead of a self-loop.
        emit_stub(out.code, probe_addr,
                  static_cast<std::uint32_t>(out.blocks.size() + 1));
        cursor += kStubLen;
        std::size_t at = b.offset;
        const std::size_t end = b.offset + b.size;
        while (at < end) {
            DecodedInsn d;
            if (!decode_insn(code + at, end - at, d)) {
                if (why) {
                    *why = "instruction refused to decode";
                }
                return false;
            }
            const std::uint8_t first = code[at];
            const std::uint64_t new_insn_off = cursor;
            if (d.branch == BranchKind::Rel8 || d.branch == BranchKind::Rel32) {
                const std::int64_t target_off =
                    static_cast<std::int64_t>(at + d.len) + d.disp;
                if (target_off < 0 ||
                    target_off >= static_cast<std::int64_t>(size)) {
                    // Outside the region: absolute transfer to the
                    // original address.
                    const bool call = (first == 0xE8);
                    emit_abs_transfer(out.code,
                                      base + static_cast<std::uint64_t>(target_off),
                                      call);
                    cursor += 13;
                    at += d.len;
                    continue;
                }
                const std::uint64_t target_new =
                    new_start[static_cast<std::size_t>(target_off)];
                if (first >= 0x70 && first <= 0x7F) {
                    // Jcc rel8 -> 0F 8x rel32 (+4 bytes).
                    const std::int64_t delta =
                        static_cast<std::int64_t>(target_new -
                                                  (new_insn_off + 6));
                    out.code.push_back(0x0F);
                    out.code.push_back(first);
                    const std::int32_t dv = static_cast<std::int32_t>(delta);
                    const std::uint8_t* dp =
                        reinterpret_cast<const std::uint8_t*>(&dv);
                    out.code.insert(out.code.end(), dp, dp + 4);
                    cursor += 6;
                    at += d.len;
                    continue;
                }
                if (first == 0xEB) {
                    // JMP rel8 -> E9 rel32 (+3 bytes).
                    const std::int64_t delta =
                        static_cast<std::int64_t>(target_new -
                                                  (new_insn_off + 5));
                    out.code.push_back(0xE9);
                    const std::int32_t dv = static_cast<std::int32_t>(delta);
                    const std::uint8_t* dp =
                        reinterpret_cast<const std::uint8_t*>(&dv);
                    out.code.insert(out.code.end(), dp, dp + 4);
                    cursor += 5;
                    at += d.len;
                    continue;
                }
                if (first == 0xE9 || first == 0xE8) {
                    // rel32 stays rel32.
                    const std::int64_t delta =
                        static_cast<std::int64_t>(target_new -
                                                  (new_insn_off + 5));
                    out.code.push_back(first);
                    const std::int32_t dv = static_cast<std::int32_t>(delta);
                    const std::uint8_t* dp =
                        reinterpret_cast<const std::uint8_t*>(&dv);
                    out.code.insert(out.code.end(), dp, dp + 4);
                    cursor += 5;
                    at += d.len;
                    continue;
                }
                // Jcc rel32: 0F 8x rel32.
                const std::int64_t delta =
                    static_cast<std::int64_t>(target_new -
                                              (new_insn_off + 6));
                out.code.push_back(0x0F);
                out.code.push_back(code[at + 1]);
                const std::int32_t dv = static_cast<std::int32_t>(delta);
                const std::uint8_t* dp =
                    reinterpret_cast<const std::uint8_t*>(&dv);
                out.code.insert(out.code.end(), dp, dp + 4);
                cursor += 6;
                at += d.len;
                continue;
            }
            // Copy the instruction, relocating a RIP-relative operand.
            if (d.rip_relative) {
                // The original target address: the position of the next
                // instruction in the original region plus the displaced
                // displacement.
                const std::int64_t next_orig =
                    static_cast<std::int64_t>(base + at + d.len);
                const std::int64_t orig_target =
                    next_orig +
                    static_cast<std::int32_t>(
                        read_le32(code + at + d.disp_offset));
                const std::uint64_t new_next = new_insn_off + d.len;
                const std::int64_t new_disp =
                    static_cast<std::int64_t>(orig_target) -
                    static_cast<std::int64_t>(new_next);
                // A RIP displacement is 32 bits; a target that moved more
                // than that away cannot be reached and the region is
                // refused rather than silently wrong.
                if (new_disp < std::numeric_limits<std::int32_t>::min() ||
                    new_disp > std::numeric_limits<std::int32_t>::max()) {
                    if (why) {
                        *why = "RIP-relative target out of 32-bit reach";
                    }
                    return false;
                }
                std::vector<std::uint8_t> buf;
                buf.assign(code + at, code + at + d.len);
                const std::int32_t nd = static_cast<std::int32_t>(new_disp);
                std::memcpy(buf.data() + d.disp_offset, &nd, 4);
                out.code.insert(out.code.end(), buf.begin(), buf.end());
                cursor += d.len;
                at += d.len;
                continue;
            }
            out.code.insert(out.code.end(), code + at, code + at + d.len);
            cursor += d.len;
            at += d.len;
        }
        Instrumented::RewrittenBlock rb;
        rb.orig_offset = b.offset;
        rb.new_offset = static_cast<std::uint32_t>(new_start[b.offset]);
        rb.size = static_cast<std::uint32_t>(cursor - new_start[b.offset]);
        out.blocks.push_back(rb);
    }
    // The entry block is the one at offset 0.
    if (!is_block_start[0]) {
        if (why) {
            *why = "region has no entry block";
        }
        return false;
    }
    out.entry = static_cast<std::uint32_t>(new_start[0]);
    out.block_count = static_cast<std::uint32_t>(blocks.size());
    return true;
}

} // namespace occ::dbi

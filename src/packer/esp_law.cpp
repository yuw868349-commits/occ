// ESP-law unpacking: implementation.
//
// Decoder scope (what a decryption loop uses): mov/lea/push/pop, the
// ALU group (add/or/adc/sbb/and/sub/xor/cmp) with register, memory and
// immediate forms, shifts (rol/ror/rcl/rcr/shl/shr/sar via group 2),
// group 3 (test/not/neg/mul/imul/div), test, inc/dec, jcc/jmp/call/ret,
// nop, int3, xchg, movzx/movsx, movsxd, cdq/cqo, pushad/popad and
// pushf/popf for 32-bit wrappers. Anything outside stops the run with a
// precise reason. The decoder resolves prefixes (REX, operand-size 66,
// address-size 67), ModRM, SIB and displacements, so memory operands
// are computed the way the hardware computes them.

#include "occ/packer/esp_law.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace occ::packer::esp_law {

namespace {

// ------------------------------------------------------------------ PE view

std::uint32_t conc_le32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint16_t conc_le16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0] |
                                      (static_cast<std::uint16_t>(p[1]) << 8));
}

struct PeSec {
    std::string name;
    std::uint32_t va = 0;
    std::uint32_t vsize = 0;
    std::uint32_t raw = 0;
    std::uint32_t rawsize = 0;
    std::uint32_t chars = 0;
};

struct PeView {
    bool ok = false;
    std::string error;
    std::uint32_t entry_rva = 0;
    std::uint32_t image_size = 0;
    std::vector<PeSec> sections;
};

PeView conc_pe_view(const std::uint8_t* bytes, std::size_t size) {
    PeView v;
    if (size < 0x40 || bytes[0] != 'M' || bytes[1] != 'Z') {
        v.error = "not a DOS image";
        return v;
    }
    const std::uint32_t e_lfanew = conc_le32(bytes + 0x3C);
    if (e_lfanew + 0x18 > size) {
        v.error = "truncated PE header";
        return v;
    }
    const std::uint8_t* pe = bytes + e_lfanew;
    if (pe[0] != 'P' || pe[1] != 'E' || pe[2] != 0 || pe[3] != 0) {
        v.error = "missing PE signature";
        return v;
    }
    const std::uint16_t nsec = conc_le16(pe + 6);
    const std::uint16_t opt_size = conc_le16(pe + 20);
    if (e_lfanew + 24 + opt_size > size) {
        v.error = "truncated optional header";
        return v;
    }
    const std::uint8_t* opt = pe + 24;
    const std::uint16_t magic = conc_le16(opt);
    if (magic != 0x10B && magic != 0x20B) {
        v.error = "unsupported optional-header magic";
        return v;
    }
    v.entry_rva = conc_le32(opt + 16);
    v.image_size = conc_le32(opt + 56);
    const std::uint8_t* sec = opt + opt_size;
    if (e_lfanew + 24 + opt_size + static_cast<std::size_t>(nsec) * 40 >
        size) {
        v.error = "truncated section table";
        return v;
    }
    for (std::uint16_t i = 0; i < nsec; ++i) {
        const std::uint8_t* s = sec + static_cast<std::size_t>(i) * 40;
        PeSec secv;
        char name[9] = {0};
        std::memcpy(name, s, 8);
        secv.name = name;
        secv.vsize = conc_le32(s + 8);
        secv.va = conc_le32(s + 12);
        secv.rawsize = conc_le32(s + 16);
        secv.raw = conc_le32(s + 20);
        secv.chars = conc_le32(s + 36);
        v.sections.push_back(secv);
    }
    v.ok = true;
    return v;
}

// ----------------------------------------------------------------- decoder

struct Decoded {
    enum class Kind : std::uint8_t {
        Unsupported,
        Nop,
        Mov,
        Lea,
        Push,
        Pop,
        Pushad,     // 0x60 / 0x61 (32-bit wrappers)
        Pushf,      // 0x9C / 0x9D
        AluImm,     // group 1, immediate form
        AluRm,      // group 1, register/memory form
        Shift,      // group 2
        Test,
        NotNeg,
        MulDiv,     // group 3
        IncDec,     // group 4/5
        Call,
        Jmp,
        Jcc,
        Ret,
        Xchg,
        Movzx,
        Movsx,
        Cqo,
    };

    Kind kind = Kind::Unsupported;
    std::size_t len = 0;
    bool op64 = false;
    bool mem = false;
    bool rip_rel = false;
    std::int32_t disp = 0;
    std::size_t disp_len = 0;
    std::uint64_t imm = 0;
    std::size_t imm_len = 0;
    int reg = -1;         // ModRM.reg (REX.R applied)
    int rm_reg = -1;      // rm as register (mem == false)
    bool to_rm = false;   // mov direction: true writes the rm operand
    bool byte_op = false; // 8-bit operation (no REX.W, no 0x66)
    bool rex_present = false;  // any REX prefix seen (byte-reg high/low)
    int base = -1;
    int index = -1;
    std::uint8_t scale = 0;
    int alu = 0;          // group opcode
    int cc = 0;
    bool cond_jump = false;
    bool is_call = false;
    bool is_ret = false;
    std::uint64_t rel_target = 0;
    bool direct_branch = false;
};

bool conc_byte(const std::uint8_t* code, std::size_t avail, std::size_t at,
               std::uint8_t* out) {
    if (at >= avail) {
        return false;
    }
    *out = code[at];
    return true;
}

bool conc_decode(const std::uint8_t* code, std::size_t avail,
                 std::uint64_t base, Decoded& d) {
    d = Decoded{};
    std::size_t p = 0;
    bool rex = false, rex_w = false, rex_r = false, rex_x = false,
         rex_b = false;
    bool op16 = false;
    while (p < avail) {
        const std::uint8_t b = code[p];
        if (b >= 0x40 && b <= 0x4F) {
            rex = true;
            rex_w = (b & 8) != 0;
            rex_r = (b & 4) != 0;
            rex_x = (b & 2) != 0;
            rex_b = (b & 1) != 0;
            ++p;
        } else if (b == 0x66) {
            op16 = true;
            ++p;
        } else if (b == 0x67) {
            ++p;  // address-size prefix: 32-bit addressing is the default
        } else if (b == 0xF3 || b == 0xF2 || b == 0xF0) {
            ++p;
        } else {
            break;
        }
    }
    std::uint8_t op = 0;
    if (!conc_byte(code, avail, p, &op)) {
        return false;
    }
    ++p;
    const bool w64 = rex_w;
    d.rex_present = rex;

    auto modrm_at = [&](std::size_t at, int* mod, int* regf, int* rm,
                        bool* ok) {
        std::uint8_t m = 0;
        *ok = conc_byte(code, avail, at, &m);
        if (!*ok) {
            return;
        }
        *mod = (m >> 6) & 3;
        *regf = static_cast<int>((m >> 3) & 7);
        *rm = static_cast<int>(m & 7);
    };

    // Resolves the rm operand. On return, `at` points past modrm/sib/disp.
    auto resolve_rm = [&](std::size_t& at, int mod, int rm, bool* ok) {
        *ok = true;
        d.rm_reg = rm | (rex_b ? 8 : 0);
        if (mod == 3) {
            d.mem = false;
            return;
        }
        d.mem = true;
        d.base = -1;
        d.index = -1;
        d.scale = 0;
        if (rm == 4) {
            std::uint8_t sib = 0;
            if (!conc_byte(code, avail, at, &sib)) {
                *ok = false;
                return;
            }
            ++at;
            d.scale = static_cast<std::uint8_t>(1u << ((sib >> 6) & 3));
            const int idx = static_cast<int>((sib >> 3) & 7);
            const int bse = static_cast<int>(sib & 7);
            d.index = (idx == 4) ? -1 : (idx | (rex_x ? 8 : 0));
            d.base = (bse == 5 && mod == 0) ? -1 : (bse | (rex_b ? 8 : 0));
            if (mod == 0 && bse == 5) {
                if (at + 4 > avail) {
                    *ok = false;
                    return;
                }
                d.disp = static_cast<std::int32_t>(conc_le32(code + at));
                d.disp_len = 4;
                at += 4;
            }
        } else if (rm == 5 && mod == 0) {
            d.rip_rel = true;
            d.base = -1;
            if (at + 4 > avail) {
                *ok = false;
                return;
            }
            d.disp = static_cast<std::int32_t>(conc_le32(code + at));
            d.disp_len = 4;
            at += 4;
        } else {
            d.base = rm | (rex_b ? 8 : 0);
        }
        if (mod == 1) {
            std::uint8_t d8 = 0;
            if (!conc_byte(code, avail, at, &d8)) {
                *ok = false;
                return;
            }
            d.disp = static_cast<std::int8_t>(d8);
            d.disp_len = 1;
            ++at;
        } else if (mod == 2) {
            if (at + 4 > avail) {
                *ok = false;
                return;
            }
            d.disp = static_cast<std::int32_t>(conc_le32(code + at));
            d.disp_len = 4;
            at += 4;
        }
    };

    auto read_imm = [&](std::size_t& at, std::size_t n, bool* ok) {
        *ok = at + n <= avail;
        if (!*ok) {
            return;
        }
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < n; ++i) {
            v |= static_cast<std::uint64_t>(code[at + i]) << (8 * i);
        }
        d.imm = v;
        d.imm_len = n;
        at += n;
    };

    auto branch_target = [&](std::size_t at, bool rel32, bool* ok) {
        *ok = at + (rel32 ? 4 : 1) <= avail;
        if (!*ok) {
            return;
        }
        const std::int64_t off =
            rel32 ? static_cast<std::int32_t>(conc_le32(code + at))
                  : static_cast<std::int8_t>(code[at]);
        // The displacement is relative to the end of the instruction:
        // p is already past the opcode, and the disp itself follows.
        d.rel_target =
            base + static_cast<std::uint64_t>(p + (rel32 ? 4 : 1)) +
            static_cast<std::uint64_t>(off);
        d.direct_branch = true;
        d.len = at + (rel32 ? 4 : 1);
    };

    if (op == 0x0F) {
        std::uint8_t op2 = 0;
        if (!conc_byte(code, avail, p, &op2)) {
            return false;
        }
        ++p;
        if (op2 >= 0x80 && op2 <= 0x8F) {
            d.kind = Decoded::Kind::Jcc;
            d.cc = op2 & 0x0F;
            d.cond_jump = true;
            bool ok = false;
            branch_target(p, true, &ok);
            d.len = p + 4;
            return ok;
        }
        if (op2 == 0x1F) {
            // Multi-byte nop: skip the modrm-shaped tail.
            std::uint8_t m = 0;
            if (!conc_byte(code, avail, p, &m)) {
                return false;
            }
            ++p;
            d.kind = Decoded::Kind::Nop;
            int mod = (m >> 6) & 3, rm = m & 7;
            std::size_t at = p;
            bool ok = false;
            resolve_rm(at, mod, rm, &ok);
            if (!ok) {
                return false;
            }
            d.len = at;
            return true;
        }
        if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF) {
            d.kind = (op2 == 0xB6 || op2 == 0xB7) ? Decoded::Kind::Movzx
                                                  : Decoded::Kind::Movsx;
            int mod = 0, regf = 0, rm = 0;
            bool ok = false;
            modrm_at(p, &mod, &regf, &rm, &ok);
            if (!ok) {
                return false;
            }
            ++p;
            d.reg = regf | (rex_r ? 8 : 0);
            resolve_rm(p, mod, rm, &ok);
            if (!ok) {
                return false;
            }
            // Source width side channel for the stepper's movsx.
            d.imm_len = (op2 == 0xB7 || op2 == 0xBF) ? 2 : 1;
            d.len = p;
            return true;
        }
        if (op2 == 0xAF) {
            int mod = 0, regf = 0, rm = 0;
            bool ok = false;
            modrm_at(p, &mod, &regf, &rm, &ok);
            if (!ok) {
                return false;
            }
            ++p;
            d.kind = Decoded::Kind::MulDiv;
            d.reg = regf | (rex_r ? 8 : 0);
            resolve_rm(p, mod, rm, &ok);
            if (!ok) {
                return false;
            }
            d.len = p;
            return true;
        }
        d.kind = Decoded::Kind::Unsupported;
        d.len = p;
        return false;
    }

    if (op >= 0x70 && op <= 0x7F) {
        d.kind = Decoded::Kind::Jcc;
        d.cc = op & 0x0F;
        d.cond_jump = true;
        bool ok = false;
        branch_target(p, false, &ok);
        d.len = p + 1;
        return ok;
    }
    if (op == 0x60 || op == 0x61) {
        d.kind = Decoded::Kind::Pushad;
        d.alu = op == 0x60 ? 0 : 1;  // 0 = pushad, 1 = popad
        d.len = p;
        return true;
    }
    if (op >= 0x50 && op <= 0x57) {
        d.kind = Decoded::Kind::Push;
        d.rm_reg = static_cast<int>(op & 7) | (rex_b ? 8 : 0);
        d.len = p;
        return true;
    }
    if (op >= 0x58 && op <= 0x5F) {
        d.kind = Decoded::Kind::Pop;
        d.rm_reg = static_cast<int>(op & 7) | (rex_b ? 8 : 0);
        d.len = p;
        return true;
    }
    if (op == 0x6A || op == 0x68) {
        d.kind = Decoded::Kind::Push;
        bool ok = false;
        read_imm(p, op == 0x6A ? 1 : (w64 ? 4 : (op16 ? 2 : 4)), &ok);
        if (!ok) {
            return false;
        }
        d.len = p;
        return true;
    }
    if ((op >= 0x80 && op <= 0x83) || op == 0xC6 || op == 0xC7) {
        const bool group1 = op <= 0x83;
        int mod = 0, regf = 0, rm = 0;
        bool ok = false;
        modrm_at(p, &mod, &regf, &rm, &ok);
        if (!ok) {
            return false;
        }
        ++p;
        d.kind = group1 ? Decoded::Kind::AluImm : Decoded::Kind::Mov;
        d.alu = regf;
        d.to_rm = !group1;  // C6/C7 write the rm operand
        d.reg = -1;
        resolve_rm(p, mod, rm, &ok);
        if (!ok) {
            return false;
        }
        const std::size_t imm_n =
            group1 ? (op == 0x83 ? 1 : (w64 ? 4 : (op16 ? 2 : 4)))
                   : (w64 ? 4 : (op16 ? 2 : 4));
        read_imm(p, imm_n, &ok);
        if (!ok) {
            return false;
        }
        d.len = p;
        return true;
    }
    if (op == 0x88 || op == 0x89 || op == 0x8A || op == 0x8B) {
        d.kind = Decoded::Kind::Mov;
        int mod = 0, regf = 0, rm = 0;
        bool ok = false;
        modrm_at(p, &mod, &regf, &rm, &ok);
        if (!ok) {
            return false;
        }
        ++p;
        d.reg = regf | (rex_r ? 8 : 0);
        d.to_rm = (op == 0x88 || op == 0x89);
        d.byte_op = (op == 0x88 || op == 0x8A);
        resolve_rm(p, mod, rm, &ok);
        if (!ok) {
            return false;
        }
        d.len = p;
        return true;
    }
    // Immediate ALU on AL/AX/EAX/RAX: 04/05 add, 0C/0D or, 14/15 adc,
    // 1C/1D sbb, 24/25 and, 2C/2D sub, 34/35 xor, 3C/3D cmp.
    if (op == 0x04 || op == 0x05 || op == 0x0C || op == 0x0D ||
        op == 0x14 || op == 0x15 || op == 0x1C || op == 0x1D ||
        op == 0x24 || op == 0x25 || op == 0x2C || op == 0x2D ||
        op == 0x34 || op == 0x35 || op == 0x3C || op == 0x3D) {
        d.kind = Decoded::Kind::AluImm;
        d.alu = static_cast<int>((op - 0x04) >> 3);
        d.rm_reg = 0;  // AL/AX/EAX/RAX
        d.byte_op = (op & 1) == 0;  // even member: imm8/AL form
        bool ok = false;
        read_imm(p, d.byte_op ? 1 : (w64 ? 4 : (op16 ? 2 : 4)), &ok);
        if (!ok) {
            return false;
        }
        d.len = p;
        return true;
    }
    if (op == 0x8D) {
        d.kind = Decoded::Kind::Lea;
        int mod = 0, regf = 0, rm = 0;
        bool ok = false;
        modrm_at(p, &mod, &regf, &rm, &ok);
        if (!ok) {
            return false;
        }
        ++p;
        d.reg = regf | (rex_r ? 8 : 0);
        resolve_rm(p, mod, rm, &ok);
        if (!ok) {
            return false;
        }
        d.len = p;
        return true;
    }
    if (op == 0x8F) {
        d.kind = Decoded::Kind::Pop;
        int mod = 0, regf = 0, rm = 0;
        bool ok = false;
        modrm_at(p, &mod, &regf, &rm, &ok);
        if (!ok) {
            return false;
        }
        ++p;
        resolve_rm(p, mod, rm, &ok);
        if (!ok) {
            return false;
        }
        d.len = p;
        return true;
    }
    if (op == 0x90) {
        d.kind = Decoded::Kind::Nop;
        d.len = p;
        return true;
    }
    if (op >= 0x91 && op <= 0x97) {
        d.kind = Decoded::Kind::Xchg;
        d.reg = static_cast<int>(op & 7) | (rex_b ? 8 : 0);
        d.rm_reg = 0;
        d.len = p;
        return true;
    }
    if (op == 0x99) {
        d.kind = Decoded::Kind::Cqo;
        d.len = p;
        return true;
    }
    if (op == 0x9C || op == 0x9D) {
        d.kind = Decoded::Kind::Pushf;
        d.alu = op == 0x9C ? 0 : 1;
        d.len = p;
        return true;
    }
    if (op == 0xA8 || op == 0xA9) {
        d.kind = Decoded::Kind::Test;
        d.rm_reg = 0;
        bool ok = false;
        read_imm(p, w64 ? 4 : (op16 ? 2 : 4), &ok);
        if (!ok) {
            return false;
        }
        d.len = p;
        return true;
    }
    if (op >= 0xB0 && op <= 0xB7) {
        d.kind = Decoded::Kind::Mov;
        d.rm_reg = static_cast<int>(op & 7) | (rex_b ? 8 : 0);
        d.to_rm = true;
        d.byte_op = true;
        bool ok = false;
        read_imm(p, 1, &ok);
        if (!ok) {
            return false;
        }
        d.len = p;
        return true;
    }
    if (op >= 0xB8 && op <= 0xBF) {
        d.kind = Decoded::Kind::Mov;
        d.rm_reg = static_cast<int>(op & 7) | (rex_b ? 8 : 0);
        d.to_rm = true;
        bool ok = false;
        read_imm(p, w64 ? 8 : (op16 ? 2 : 4), &ok);
        if (!ok) {
            return false;
        }
        d.len = p;
        return true;
    }
    if (op == 0xC3) {
        d.kind = Decoded::Kind::Ret;
        d.is_ret = true;
        d.len = p;
        return true;
    }
    if (op == 0xC2) {
        d.kind = Decoded::Kind::Ret;
        d.is_ret = true;
        bool ok = false;
        read_imm(p, 2, &ok);
        if (!ok) {
            return false;
        }
        d.len = p;
        return true;
    }
    if ((op >= 0xC0 && op <= 0xC1) || (op >= 0xD0 && op <= 0xD3)) {
        d.kind = Decoded::Kind::Shift;
        int mod = 0, regf = 0, rm = 0;
        bool ok = false;
        modrm_at(p, &mod, &regf, &rm, &ok);
        if (!ok) {
            return false;
        }
        ++p;
        d.alu = regf;
        resolve_rm(p, mod, rm, &ok);
        if (!ok) {
            return false;
        }
        if (op == 0xC0 || op == 0xC1) {
            read_imm(p, 1, &ok);
            if (!ok) {
                return false;
            }
        }
        d.len = p;
        return true;
    }
    if (op == 0xCC || op == 0xCD) {
        d.kind = Decoded::Kind::Nop;
        if (op == 0xCD) {
            bool ok = false;
            read_imm(p, 1, &ok);
            if (!ok) {
                return false;
            }
        }
        d.len = p;
        return true;
    }
    if (op == 0xE8 || op == 0xE9 || op == 0xEB) {
        d.kind = op == 0xE8 ? Decoded::Kind::Call
                 : op == 0xE9 ? Decoded::Kind::Jmp
                              : Decoded::Kind::Jmp;
        d.is_call = (op == 0xE8);
        bool ok = false;
        if (op == 0xEB) {
            branch_target(p, false, &ok);
            d.len = p + 1;
            return ok;
        }
        branch_target(p, true, &ok);
        d.len = p + 4;
        return ok;
    }
    if (op == 0xF6 || op == 0xF7) {
        int mod = 0, regf = 0, rm = 0;
        bool ok = false;
        modrm_at(p, &mod, &regf, &rm, &ok);
        if (!ok) {
            return false;
        }
        ++p;
        d.alu = regf;
        resolve_rm(p, mod, rm, &ok);
        if (!ok) {
            return false;
        }
        if (regf == 0) {
            d.kind = Decoded::Kind::Test;
            if (op == 0xF6) {
                read_imm(p, 1, &ok);
            } else if (!w64) {
                read_imm(p, op16 ? 2 : 4, &ok);
            }
            if (!ok) {
                return false;
            }
        } else if (regf == 2) {
            d.kind = Decoded::Kind::NotNeg;
        } else if (regf == 3) {
            d.kind = Decoded::Kind::NotNeg;
        } else if (regf >= 4 && regf <= 7) {
            d.kind = Decoded::Kind::MulDiv;
        } else {
            d.kind = Decoded::Kind::Unsupported;
            d.len = p;
            return false;
        }
        d.len = p;
        return true;
    }
    if (op == 0xFE || op == 0xFF) {
        int mod = 0, regf = 0, rm = 0;
        bool ok = false;
        modrm_at(p, &mod, &regf, &rm, &ok);
        if (!ok) {
            return false;
        }
        ++p;
        const int g = regf;
        if (op == 0xFE && (g == 0 || g == 1)) {
            d.kind = Decoded::Kind::IncDec;
            d.alu = g;
        } else if (op == 0xFF && g == 0) {
            d.kind = Decoded::Kind::IncDec;
            d.alu = 0;
        } else if (op == 0xFF && g == 1) {
            d.kind = Decoded::Kind::IncDec;
            d.alu = 1;
        } else if (op == 0xFF && g == 2) {
            d.kind = Decoded::Kind::Call;
            d.is_call = true;
        } else if (op == 0xFF && g == 4) {
            d.kind = Decoded::Kind::Jmp;
        } else if (op == 0xFF && g == 6) {
            d.kind = Decoded::Kind::Push;
        } else {
            d.kind = Decoded::Kind::Unsupported;
            d.len = p;
            return false;
        }
        resolve_rm(p, mod, rm, &ok);
        if (!ok) {
            return false;
        }
        d.len = p;
        return true;
    }
    if (op == 0x63 && rex_w) {
        d.kind = Decoded::Kind::Movsx;
        int mod = 0, regf = 0, rm = 0;
        bool ok = false;
        modrm_at(p, &mod, &regf, &rm, &ok);
        if (!ok) {
            return false;
        }
        ++p;
        d.reg = regf | (rex_r ? 8 : 0);
        resolve_rm(p, mod, rm, &ok);
        if (!ok) {
            return false;
        }
        d.len = p;
        return true;
    }
    d.kind = Decoded::Kind::Unsupported;
    d.len = p;
    return false;
}

// ------------------------------------------------------------------ machine

struct Machine {
    std::uint64_t regs[16] = {0};
    std::uint64_t rflags = 0;  // CF=0 ZF=6 SF=7 OF=11
    std::vector<std::uint8_t> mem;
    std::uint64_t rsp0 = 0;
    // SMC collector: writes that land inside the image (below image_end)
    // are recorded; stack and out-of-image writes are not, which is the
    // same discrimination analyze_smc applies to a runtime write stream.
    std::vector<SMCWrite>* smc = nullptr;
    std::uint64_t image_end = 0;
    std::uint64_t current_rip = 0;

    static constexpr std::size_t kRax = 0, kRcx = 1, kRdx = 2;
    static constexpr std::size_t kRsp = 4;

    bool in_range(std::uint64_t va, std::size_t n) const {
        return va + n <= mem.size();
    }
    bool read(std::uint64_t va, void* out, std::size_t n) const {
        if (!in_range(va, n)) {
            return false;
        }
        std::memcpy(out, mem.data() + va, n);
        return true;
    }
    bool write(std::uint64_t va, const void* in, std::size_t n) {
        if (!in_range(va, n)) {
            return false;
        }
        std::memcpy(mem.data() + va, in, n);
        if (smc != nullptr && va < image_end) {
            SMCWrite w;
            w.write_va = va;
            w.rip = current_rip;
            w.size = n;
            smc->push_back(w);
        }
        return true;
    }

    void set_zf(bool z) {
        rflags = z ? (rflags | (1u << 6)) : (rflags & ~(1u << 6));
    }
    void set_sf(std::uint64_t v, unsigned bits) {
        const bool s = ((v >> (bits - 1)) & 1) != 0;
        rflags = s ? (rflags | (1u << 7)) : (rflags & ~(1u << 7));
    }
    void set_cf(bool c) {
        rflags = c ? (rflags | 1u) : (rflags & ~1u);
    }
    void set_of(bool o) {
        rflags = o ? (rflags | (1u << 11)) : (rflags & ~(1u << 11));
    }
    bool zf() const { return (rflags >> 6) & 1; }
    bool sf() const { return (rflags >> 7) & 1; }
    bool cf() const { return rflags & 1; }
    bool of() const { return (rflags >> 11) & 1; }
};

// ------------------------------------------------------------------ stepper

// Computes the effective address of the rm memory operand.
// `rip` and `len` are needed for rip-relative addressing.
bool conc_eff_addr(const Machine& m, const Decoded& d, std::uint64_t rip,
                   std::uint64_t* out) {
    std::uint64_t a = 0;
    if (d.rip_rel) {
        a = rip + d.len + static_cast<std::uint64_t>(
                               static_cast<std::int64_t>(d.disp));
    } else {
        if (d.base >= 0) {
            a += m.regs[static_cast<std::size_t>(d.base)];
        }
        if (d.index >= 0) {
            a += m.regs[static_cast<std::size_t>(d.index)] * d.scale;
        }
        a += static_cast<std::uint64_t>(static_cast<std::int64_t>(d.disp));
    }
    *out = a;
    return true;
}

// Reads the rm operand (register or memory) into `out`.
bool conc_read_rm(const Machine& m, const Decoded& d, std::uint64_t rip,
                  std::uint64_t& out) {
    if (!d.mem) {
        out = m.regs[static_cast<std::size_t>(d.rm_reg)];
        return true;
    }
    std::uint64_t a = 0;
    if (!conc_eff_addr(m, d, rip, &a)) {
        return false;
    }
    const std::size_t n = d.byte_op ? 1 : (d.op64 ? 8 : 4);
    return m.read(a, &out, n);
}

// Writes a value into a register with the instruction's width semantics:
// 32-bit writes zero-extend, 16/8-bit writes preserve the upper bits.
void conc_write_reg(Machine& m, std::size_t idx, unsigned bits,
                    std::uint64_t val) {
    if (bits == 64) {
        m.regs[idx] = val;
    } else if (bits == 32) {
        m.regs[idx] = (m.regs[idx] & ~std::uint64_t(0xFFFFFFFFu)) |
                      (val & 0xFFFFFFFFu);
    } else if (bits == 16) {
        m.regs[idx] = (m.regs[idx] & ~std::uint64_t(0xFFFF)) |
                      (val & 0xFFFF);
    } else {  // 8
        m.regs[idx] = (m.regs[idx] & ~std::uint64_t(0xFF)) | (val & 0xFF);
    }
}

// 8-bit register write: REX-present indexes 4-7 are SPL/BPL/SIL/DIL
// (low byte); without REX they are AH/CH/DH/BH (bits 8-15). The caller
// passes `high_byte` when the instruction had no REX prefix and the
// index is 4-7.
void conc_write_reg8(Machine& m, std::size_t idx, bool high_byte,
                     std::uint64_t val) {
    const std::uint64_t low = val & 0xFF;
    if (high_byte) {
        m.regs[idx] = (m.regs[idx] & ~std::uint64_t(0xFF00)) |
                      (low << 8);
    } else {
        m.regs[idx] = (m.regs[idx] & ~std::uint64_t(0xFF)) | low;
    }
}

std::uint64_t conc_mask(unsigned bits) {
    return bits == 64 ? ~std::uint64_t(0)
                      : ((std::uint64_t(1) << bits) - 1);
}

bool conc_jcc_taken(const Machine& m, int cc) {
    switch (cc) {
        case 0x0: return m.of();                        // jo
        case 0x1: return !m.of();                       // jno
        case 0x2: return m.cf();                        // jb
        case 0x3: return !m.cf();                       // jae
        case 0x4: return m.zf();                        // je
        case 0x5: return !m.zf();                       // jne
        case 0x6: return m.cf() || m.zf();              // jbe
        case 0x7: return !m.cf() && !m.zf();            // ja
        case 0x8: return m.sf();                        // js
        case 0x9: return !m.sf();                       // jns
        case 0xA: return m.of() == m.sf();              // jp (parity unused)
        case 0xB: return m.of() != m.sf();              // jnp
        case 0xC: return m.sf() != m.of();              // jl
        case 0xD: return m.sf() == m.of();              // jge
        case 0xE: return m.zf() || (m.sf() != m.of());  // jle
        case 0xF: return !m.zf() && (m.sf() == m.of()); // jg
        default: return false;
    }
}

// ALU helper: applies group-1 op `alu` to a and b, updates flags, returns
// the result (and whether the instruction writes flags only, i.e. cmp).
bool conc_alu_apply(Machine& m, int alu, std::uint64_t a, std::uint64_t b,
                    unsigned bits, std::uint64_t& res) {
    const std::uint64_t mask = conc_mask(bits);
    const std::uint64_t aw = a & mask, bw = b & mask;
    switch (alu) {
        case 0:    // add
        case 2: {  // adc
            const std::uint64_t cin = (alu == 2 && m.cf()) ? 1 : 0;
            const std::uint64_t sum = aw + bw + cin;
            res = sum & mask;
            m.set_cf(sum > mask);
            m.set_of(((aw & bw) | ((aw ^ bw) & ~res)) >> (bits - 1) & 1);
            break;
        }
        case 1: {  // or
            res = aw | bw;
            m.set_cf(false);
            m.set_of(false);
            break;
        }
        case 4: {  // and
            res = aw & bw;
            m.set_cf(false);
            m.set_of(false);
            break;
        }
        case 3:    // sbb
        case 5: {  // sub
            const std::uint64_t bin = (alu == 3 && m.cf()) ? 1 : 0;
            res = (aw - bw - bin) & mask;
            m.set_cf(aw < (bw + bin));
            m.set_of(((aw ^ bw) & (aw ^ res)) >> (bits - 1) & 1);
            break;
        }
        case 6: {  // xor
            res = aw ^ bw;
            m.set_cf(false);
            m.set_of(false);
            break;
        }
        case 7: {  // cmp
            res = (aw - bw) & mask;
            m.set_cf(aw < bw);
            m.set_of(((aw ^ bw) & (aw ^ res)) >> (bits - 1) & 1);
            break;
        }
        default:
            return false;
    }
    m.set_zf(res == 0);
    m.set_sf(res, bits);
    return true;
}

// Executes one decoded instruction. `rip` is the instruction's address;
// on return `rip` is advanced per the semantics. Returns:
//   0 running, 1 stop (ret/transfer out handled by caller), 2 error.
// `oep_target` is set when a transfer happened with a balanced stack.
enum class StepOutcome : std::uint8_t { Ok, Error, Transfer, ApiCall };

struct StepResult {
    StepOutcome outcome = StepOutcome::Ok;
    bool balanced_transfer = false;
    std::uint64_t transfer_target = 0;
    std::string api_note;
};

StepResult conc_step(Machine& m, const Decoded& d, std::uint64_t& rip,
                     std::uint64_t image_end, EspLawResult& result,
                     bool& balanced) {
    StepResult sr;
    const unsigned bits = d.op64 ? 64 : 32;
    const std::uint64_t mask = conc_mask(bits);
    const std::uint64_t next = rip + d.len;

    switch (d.kind) {
        case Decoded::Kind::Nop:
            rip = next;
            return sr;
        case Decoded::Kind::Cqo: {
            m.regs[Machine::kRdx] = (m.regs[Machine::kRax] >> 63) != 0
                                        ? mask
                                        : 0;
            rip = next;
            return sr;
        }
        case Decoded::Kind::Pushad: {
            // pushad pushes eax,ecx,edx,ebx,esp,ebp,esi,edi (esp = value
            // before the pushad).
            if (d.alu == 0) {
                const std::uint64_t esp_before = m.regs[Machine::kRsp];
                std::uint64_t vals[8];
                vals[0] = m.regs[0];
                vals[1] = m.regs[1];
                vals[2] = m.regs[2];
                vals[3] = m.regs[3];
                vals[4] = esp_before;
                vals[5] = m.regs[5];
                vals[6] = m.regs[6];
                vals[7] = m.regs[7];
                for (int i = 7; i >= 0; --i) {
                    m.regs[Machine::kRsp] -= 4;
                    if (!m.write(m.regs[Machine::kRsp], &vals[i], 4)) {
                        sr.outcome = StepOutcome::Error;
                        result.error = "pushad: stack write out of range";
                        return sr;
                    }
                }
            } else {
                std::uint64_t vals[8];
                for (int i = 0; i < 8; ++i) {
                    if (!m.read(m.regs[Machine::kRsp], &vals[i], 4)) {
                        sr.outcome = StepOutcome::Error;
                        result.error = "popad: stack read out of range";
                        return sr;
                    }
                    m.regs[Machine::kRsp] += 4;
                }
                m.regs[0] = vals[0];
                m.regs[1] = vals[1];
                m.regs[2] = vals[2];
                m.regs[3] = vals[3];
                // esp is not restored by popad.
                m.regs[5] = vals[5];
                m.regs[6] = vals[6];
                m.regs[7] = vals[7];
            }
            rip = next;
            return sr;
        }
        case Decoded::Kind::Pushf: {
            if (d.alu == 0) {
                m.regs[Machine::kRsp] -= 8;
                if (!m.write(m.regs[Machine::kRsp], &m.rflags, 8)) {
                    sr.outcome = StepOutcome::Error;
                    result.error = "pushf: stack write out of range";
                    return sr;
                }
            } else {
                std::uint64_t v = 0;
                if (!m.read(m.regs[Machine::kRsp], &v, 8)) {
                    sr.outcome = StepOutcome::Error;
                    result.error = "popf: stack read out of range";
                    return sr;
                }
                m.rflags = v;
                m.regs[Machine::kRsp] += 8;
            }
            rip = next;
            return sr;
        }
        case Decoded::Kind::Push: {
            std::uint64_t v = 0;
            if (d.imm_len != 0) {
                v = d.imm;
            } else {
                // register or memory rm
                if (d.mem) {
                    if (!conc_read_rm(m, d, rip, v)) {
                        sr.outcome = StepOutcome::Error;
                        result.error = "push: memory read out of range";
                        return sr;
                    }
                } else {
                    v = m.regs[static_cast<std::size_t>(d.rm_reg)];
                }
            }
            const std::size_t n = d.op64 ? 8 : 4;
            m.regs[Machine::kRsp] -= n;
            if (!m.write(m.regs[Machine::kRsp], &v, n)) {
                sr.outcome = StepOutcome::Error;
                result.error = "push: stack write out of range";
                return sr;
            }
            rip = next;
            return sr;
        }
        case Decoded::Kind::Pop: {
            if (d.mem) {
                std::uint64_t a = 0;
                if (!conc_eff_addr(m, d, rip, &a)) {
                    sr.outcome = StepOutcome::Error;
                    return sr;
                }
                std::uint64_t v = 0;
                const std::size_t n = d.op64 ? 8 : 4;
                if (!m.read(m.regs[Machine::kRsp], &v, n)) {
                    sr.outcome = StepOutcome::Error;
                    result.error = "pop: stack read out of range";
                    return sr;
                }
                if (!m.write(a, &v, n)) {
                    sr.outcome = StepOutcome::Error;
                    result.error = "pop: destination write out of range";
                    return sr;
                }
                m.regs[Machine::kRsp] += n;
            } else {
                std::uint64_t v = 0;
                const std::size_t n = d.op64 ? 8 : 4;
                if (!m.read(m.regs[Machine::kRsp], &v, n)) {
                    sr.outcome = StepOutcome::Error;
                    result.error = "pop: stack read out of range";
                    return sr;
                }
                m.regs[Machine::kRsp] += n;
                conc_write_reg(m, static_cast<std::size_t>(d.rm_reg),
                               d.op64 ? 64 : 32, v);
            }
            rip = next;
            return sr;
        }
        case Decoded::Kind::Mov: {
            const std::size_t n = d.byte_op ? 1 : (d.op64 ? 8 : 4);
            if (d.to_rm) {
                std::uint64_t src = 0;
                if (d.imm_len != 0) {
                    src = d.imm;
                } else {
                    src = m.regs[static_cast<std::size_t>(d.reg)];
                }
                if (d.mem) {
                    std::uint64_t a = 0;
                    if (!conc_eff_addr(m, d, rip, &a)) {
                        sr.outcome = StepOutcome::Error;
                        return sr;
                    }
                    if (!m.write(a, &src, n)) {
                        sr.outcome = StepOutcome::Error;
                        result.error = "mov: destination write out of range";
                        return sr;
                    }
                } else {
                    if (d.byte_op) {
                        conc_write_reg8(m, static_cast<std::size_t>(d.rm_reg),
                                        !d.rex_present && d.rm_reg >= 4 &&
                                            d.rm_reg <= 7,
                                        src);
                    } else {
                        conc_write_reg(m, static_cast<std::size_t>(d.rm_reg),
                                       d.op64 ? 64 : 32, src);
                    }
                }
            } else {
                std::uint64_t v = 0;
                if (d.mem) {
                    if (!conc_read_rm(m, d, rip, v)) {
                        sr.outcome = StepOutcome::Error;
                        result.error = "mov: memory read out of range";
                        return sr;
                    }
                } else {
                    v = m.regs[static_cast<std::size_t>(d.rm_reg)];
                }
                if (d.byte_op) {
                    conc_write_reg8(m, static_cast<std::size_t>(d.reg),
                                    !d.rex_present && d.reg >= 4 &&
                                        d.reg <= 7,
                                    v);
                } else {
                    conc_write_reg(m, static_cast<std::size_t>(d.reg),
                                   d.op64 ? 64 : 32, v);
                }
            }
            rip = next;
            return sr;
        }
        case Decoded::Kind::Lea: {
            std::uint64_t a = 0;
            if (!conc_eff_addr(m, d, rip, &a)) {
                sr.outcome = StepOutcome::Error;
                return sr;
            }
            conc_write_reg(m, static_cast<std::size_t>(d.reg),
                           d.op64 ? 64 : 32, a);
            rip = next;
            return sr;
        }
        case Decoded::Kind::AluImm:
        case Decoded::Kind::AluRm: {
            std::uint64_t a = 0;
            if (d.mem) {
                if (!conc_read_rm(m, d, rip, a)) {
                    sr.outcome = StepOutcome::Error;
                    result.error = "alu: memory read out of range";
                    return sr;
                }
            } else {
                a = m.regs[static_cast<std::size_t>(d.rm_reg)];
            }
            // Immediate form: rm op immediate. Register form: rm op reg.
            std::uint64_t rhs =
                d.kind == Decoded::Kind::AluImm
                    ? d.imm
                    : m.regs[static_cast<std::size_t>(d.reg)];
            const unsigned abits = d.byte_op ? 8 : bits;
            std::uint64_t res = 0;
            if (!conc_alu_apply(m, d.alu, a, rhs, abits, res)) {
                sr.outcome = StepOutcome::Error;
                result.error = "alu: unsupported op";
                return sr;
            }
            if (d.alu == 7) {  // cmp: flags only
                rip = next;
                return sr;
            }
            if (d.mem) {
                std::uint64_t addr = 0;
                if (!conc_eff_addr(m, d, rip, &addr)) {
                    sr.outcome = StepOutcome::Error;
                    return sr;
                }
                const std::size_t n = d.byte_op ? 1 : (d.op64 ? 8 : 4);
                if (!m.write(addr, &res, n)) {
                    sr.outcome = StepOutcome::Error;
                    result.error = "alu: destination write out of range";
                    return sr;
                }
            } else {
                if (d.byte_op) {
                    conc_write_reg8(m, static_cast<std::size_t>(d.rm_reg),
                                    !d.rex_present && d.rm_reg >= 4 &&
                                        d.rm_reg <= 7,
                                    res);
                } else {
                    conc_write_reg(m, static_cast<std::size_t>(d.rm_reg),
                                   bits, res);
                }
            }
            rip = next;
            return sr;
        }
        case Decoded::Kind::Test: {
            std::uint64_t a = 0;
            if (d.mem) {
                if (!conc_read_rm(m, d, rip, a)) {
                    sr.outcome = StepOutcome::Error;
                    result.error = "test: memory read out of range";
                    return sr;
                }
            } else {
                a = m.regs[static_cast<std::size_t>(d.rm_reg)];
            }
            const std::uint64_t t = a & d.imm;
            m.set_zf(t == 0);
            m.set_sf(t, bits);
            m.set_cf(false);
            m.set_of(false);
            rip = next;
            return sr;
        }
        case Decoded::Kind::NotNeg: {
            std::uint64_t a = 0;
            if (d.mem) {
                if (!conc_read_rm(m, d, rip, a)) {
                    sr.outcome = StepOutcome::Error;
                    result.error = "not/neg: memory read out of range";
                    return sr;
                }
            } else {
                a = m.regs[static_cast<std::size_t>(d.rm_reg)];
            }
            std::uint64_t res = 0;
            if (d.alu == 2) {  // not
                res = (~a) & mask;
            } else {  // neg
                res = (0 - a) & mask;
                m.set_cf(a != 0);
                m.set_of(res == (std::uint64_t(1) << (bits - 1)));
            }
            m.set_zf(res == 0);
            m.set_sf(res, bits);
            if (d.mem) {
                std::uint64_t addr = 0;
                if (!conc_eff_addr(m, d, rip, &addr)) {
                    sr.outcome = StepOutcome::Error;
                    return sr;
                }
                const std::size_t n = d.op64 ? 8 : 4;
                if (!m.write(addr, &res, n)) {
                    sr.outcome = StepOutcome::Error;
                    result.error = "not/neg: destination write out of range";
                    return sr;
                }
            } else {
                conc_write_reg(m, static_cast<std::size_t>(d.rm_reg), bits,
                               res);
            }
            rip = next;
            return sr;
        }
        case Decoded::Kind::MulDiv: {
            // mul rm: rdx:rax = rax * rm (unsigned, truncated to 2*width).
            // imul reg, rm: treat as truncated signed multiply into reg.
            std::uint64_t a = 0;
            if (d.mem) {
                if (!conc_read_rm(m, d, rip, a)) {
                    sr.outcome = StepOutcome::Error;
                    result.error = "mul: memory read out of range";
                    return sr;
                }
            } else {
                a = m.regs[static_cast<std::size_t>(d.rm_reg)];
            }
            if (d.reg >= 0 && d.alu >= 4 && d.alu <= 7 && d.imm_len == 0 &&
                !d.mem) {
                // 0F AF form: reg = reg * rm (signed), width-truncated.
                const std::uint64_t rv = m.regs[static_cast<std::size_t>(
                    d.reg)];
                const std::uint64_t prod = (rv * a) & mask;
                conc_write_reg(m, static_cast<std::size_t>(d.reg), bits,
                               prod);
                m.set_zf(prod == 0);
                m.set_sf(prod, bits);
            } else {
                // mul: rdx:rax = rax * rm.
                const std::uint64_t prod = m.regs[Machine::kRax] * a;
                m.regs[Machine::kRax] = prod & mask;
                m.regs[Machine::kRdx] =
                    (prod >> bits) & mask;
            }
            rip = next;
            return sr;
        }
        case Decoded::Kind::IncDec: {
            std::uint64_t a = 0;
            if (d.mem) {
                if (!conc_read_rm(m, d, rip, a)) {
                    sr.outcome = StepOutcome::Error;
                    result.error = "inc/dec: memory read out of range";
                    return sr;
                }
            } else {
                a = m.regs[static_cast<std::size_t>(d.rm_reg)];
            }
            const bool inc = d.alu == 0;
            const std::uint64_t res =
                inc ? ((a + 1) & mask) : ((a - 1) & mask);
            m.set_zf(res == 0);
            m.set_sf(res, bits);
            m.set_of(res == (std::uint64_t(1) << (bits - 1)));
            if (d.mem) {
                std::uint64_t addr = 0;
                if (!conc_eff_addr(m, d, rip, &addr)) {
                    sr.outcome = StepOutcome::Error;
                    return sr;
                }
                const std::size_t n = d.op64 ? 8 : 4;
                if (!m.write(addr, &res, n)) {
                    sr.outcome = StepOutcome::Error;
                    result.error = "inc/dec: destination write out of range";
                    return sr;
                }
            } else {
                conc_write_reg(m, static_cast<std::size_t>(d.rm_reg), bits,
                               res);
            }
            rip = next;
            return sr;
        }
        case Decoded::Kind::Shift: {
            std::uint64_t a = 0;
            if (d.mem) {
                if (!conc_read_rm(m, d, rip, a)) {
                    sr.outcome = StepOutcome::Error;
                    result.error = "shift: memory read out of range";
                    return sr;
                }
            } else {
                a = m.regs[static_cast<std::size_t>(d.rm_reg)];
            }
            const std::uint64_t cnt =
                d.imm_len != 0 ? (d.imm & 0x3F)
                               : (m.regs[Machine::kRcx] & 0x3F);
            std::uint64_t res = a & mask;
            if (cnt != 0) {
                const unsigned sh = static_cast<unsigned>(cnt);
                switch (d.alu) {
                    case 4:  // shl
                        m.set_cf(sh <= bits &&
                                 ((a >> (bits - sh)) & 1) != 0);
                        res = (a << sh) & mask;
                        break;
                    case 5:  // shr
                        m.set_cf(sh <= bits &&
                                 ((a >> (sh - 1)) & 1) != 0);
                        res = (a >> sh) & mask;
                        break;
                    case 6:  // sal (== shl)
                    case 7: {  // sar
                        const bool neg = ((a >> (bits - 1)) & 1) != 0;
                        m.set_cf(sh <= bits &&
                                 ((a >> (sh - 1)) & 1) != 0);
                        if (d.alu == 7 || d.alu == 6) {
                            res = ((a >> sh) | (neg ? ~mask << (bits - sh)
                                                    : 0)) &
                                  mask;
                        }
                        break;
                    }
                    case 0:  // rol
                        m.set_cf(((a >> (bits - (sh % bits))) & 1) != 0);
                        res = ((a << sh) | (a >> (bits - sh))) & mask;
                        break;
                    case 1:  // ror
                        m.set_cf(((a >> ((sh - 1) % bits)) & 1) != 0);
                        res = ((a >> sh) | (a << (bits - sh))) & mask;
                        break;
                    default:
                        sr.outcome = StepOutcome::Error;
                        result.error = "shift: rcl/rcr not supported";
                        return sr;
                }
            }
            m.set_zf(res == 0);
            m.set_sf(res, bits);
            if (d.mem) {
                std::uint64_t addr = 0;
                if (!conc_eff_addr(m, d, rip, &addr)) {
                    sr.outcome = StepOutcome::Error;
                    return sr;
                }
                const std::size_t n = d.op64 ? 8 : 4;
                if (!m.write(addr, &res, n)) {
                    sr.outcome = StepOutcome::Error;
                    result.error = "shift: destination write out of range";
                    return sr;
                }
            } else {
                conc_write_reg(m, static_cast<std::size_t>(d.rm_reg), bits,
                               res);
            }
            rip = next;
            return sr;
        }
        case Decoded::Kind::Xchg: {
            std::uint64_t a = m.regs[static_cast<std::size_t>(d.rm_reg)];
            m.regs[static_cast<std::size_t>(d.rm_reg)] =
                m.regs[static_cast<std::size_t>(d.reg)];
            m.regs[static_cast<std::size_t>(d.reg)] = a;
            rip = next;
            return sr;
        }
        case Decoded::Kind::Movzx:
        case Decoded::Kind::Movsx: {
            std::uint64_t v = 0;
            if (d.mem) {
                if (!conc_read_rm(m, d, rip, v)) {
                    sr.outcome = StepOutcome::Error;
                    result.error = "movzx/movsx: memory read out of range";
                    return sr;
                }
            } else {
                v = m.regs[static_cast<std::size_t>(d.rm_reg)];
            }
            if (d.kind == Decoded::Kind::Movzx) {
                conc_write_reg(m, static_cast<std::size_t>(d.reg),
                               d.op64 ? 64 : 32, v & 0xFF);
            } else {
                // movsx: B6/BE widen the low byte, B7/BF the low word,
                // and 0x63 (movsxd, REX.W) widens the low dword. The
                // decoder marks the source width in d.imm_len as a side
                // channel: B6/BE set 1, B7/BF set 2, 0x63 leaves it 0.
                std::uint64_t ex = 0;
                if (d.op64 && d.imm_len == 0) {
                    ex = static_cast<std::uint64_t>(
                        static_cast<std::int64_t>(
                            static_cast<std::int32_t>(v & 0xFFFFFFFFu)));
                } else if (d.imm_len == 2) {
                    ex = static_cast<std::uint64_t>(
                        static_cast<std::int64_t>(
                            static_cast<std::int16_t>(v & 0xFFFF)));
                } else {
                    ex = static_cast<std::uint64_t>(
                        static_cast<std::int64_t>(
                            static_cast<std::int8_t>(v & 0xFF)));
                }
                conc_write_reg(m, static_cast<std::size_t>(d.reg), 64, ex);
            }
            rip = next;
            return sr;
        }
        case Decoded::Kind::Jcc: {
            const bool taken = conc_jcc_taken(m, d.cc);
            if (taken) {
                if (balanced && d.rel_target != next) {
                    sr.balanced_transfer = true;
                    sr.transfer_target = d.rel_target;
                    sr.outcome = StepOutcome::Transfer;
                    return sr;
                }
                rip = d.rel_target;
            } else {
                rip = next;
            }
            return sr;
        }
        case Decoded::Kind::Jmp: {
            std::uint64_t target = 0;
            if (d.direct_branch) {
                target = d.rel_target;
            } else {
                if (d.mem) {
                    if (!conc_read_rm(m, d, rip, target)) {
                        sr.outcome = StepOutcome::Error;
                        result.error = "jmp: memory read out of range";
                        return sr;
                    }
                } else {
                    target = m.regs[static_cast<std::size_t>(d.rm_reg)];
                }
            }
            if (balanced && target != next) {
                sr.balanced_transfer = true;
                sr.transfer_target = target;
                sr.outcome = StepOutcome::Transfer;
                return sr;
            }
            rip = target;
            return sr;
        }
        case Decoded::Kind::Call: {
            std::uint64_t target = 0;
            if (d.direct_branch) {
                target = d.rel_target;
            } else {
                if (d.mem) {
                    if (!conc_read_rm(m, d, rip, target)) {
                        sr.outcome = StepOutcome::Error;
                        result.error = "call: memory read out of range";
                        return sr;
                    }
                } else {
                    target = m.regs[static_cast<std::size_t>(d.rm_reg)];
                }
            }
            if (balanced && target != next) {
                sr.balanced_transfer = true;
                sr.transfer_target = target;
                sr.outcome = StepOutcome::Transfer;
                return sr;
            }
            if (target < image_end) {
                // In-image call: push the return address and enter.
                const std::size_t n = 8;
                m.regs[Machine::kRsp] -= n;
                const std::uint64_t ret_addr = next;
                if (!m.write(m.regs[Machine::kRsp], &ret_addr, n)) {
                    sr.outcome = StepOutcome::Error;
                    result.error = "call: stack write out of range";
                    return sr;
                }
                rip = target;
            } else {
                // Out-of-image call: stub it (record, return 0). The
                // stack pointer is left untouched -- the call is treated
                // as if the API ran and returned, which is what a
                // caller-cleanup ABI does -- so an ESP-law run that
                // observes the stub does not see a phantom imbalance.
                ApiCall ac;
                ac.at_rva = rip;
                ac.target = target;
                ac.ret_rax = 0;
                ac.note = "out-of-image call stubbed";
                result.api_calls.push_back(ac);
                m.regs[Machine::kRax] = 0;
                rip = next;
                sr.outcome = StepOutcome::ApiCall;
            }
            return sr;
        }
        case Decoded::Kind::Ret: {
            std::uint64_t target = 0;
            if (!m.read(m.regs[Machine::kRsp], &target, 8)) {
                sr.outcome = StepOutcome::Error;
                result.error = "ret: stack read out of range";
                return sr;
            }
            m.regs[Machine::kRsp] += 8;
            if (d.imm_len != 0) {
                m.regs[Machine::kRsp] += d.imm & 0xFFFF;
            }
            if (balanced) {
                sr.balanced_transfer = true;
                sr.transfer_target = target;
                sr.outcome = StepOutcome::Transfer;
                return sr;
            }
            rip = target;
            return sr;
        }
        case Decoded::Kind::Unsupported:
            sr.outcome = StepOutcome::Error;
            result.error = "unsupported instruction";
            return sr;
    }
    return sr;
}

// ------------------------------------------------------------------ analyze

}  // namespace

EspLawResult analyze(const std::uint8_t* bytes, std::size_t size,
                     std::size_t max_steps) noexcept {
    EspLawResult result;
    result.max_steps = max_steps;
    const PeView view = conc_pe_view(bytes, size);
    if (!view.ok) {
        result.error = view.error;
        return result;
    }
    if (view.entry_rva >= view.image_size) {
        result.error = "entry point outside the image";
        return result;
    }
    if (view.sections.empty()) {
        result.error = "image has no sections";
        return result;
    }

    const std::uint64_t image_end = view.image_size;

    // Build the machine. The image maps at VA 0 with RVA == VA; the stack
    // lives at the top of the simulated space.
    Machine m;
    const std::size_t kMemSize = 0x2000000;  // 32 MiB
    m.mem.assign(kMemSize, 0);
    const std::uint64_t kStackBase = 0x1FF0000;
    m.rsp0 = kStackBase - 8;
    m.regs[Machine::kRsp] = m.rsp0;
    m.smc = &result.smc;
    m.image_end = image_end;

    // Copy headers and section raw data into the space.
    const std::uint32_t e_lfanew = conc_le32(bytes + 0x3C);
    const std::size_t header_size =
        static_cast<std::size_t>(e_lfanew) + 24 +
        conc_le16(bytes + e_lfanew + 20) +
        static_cast<std::size_t>(view.sections.size()) * 40;
    if (header_size <= size) {
        std::memcpy(m.mem.data(), bytes, header_size);
    }
    for (const PeSec& s : view.sections) {
        if (s.raw + s.rawsize <= size && s.va + s.rawsize <= kMemSize) {
            std::memcpy(m.mem.data() + s.va, bytes + s.raw, s.rawsize);
        }
    }
    // The ESP-law loop. `visited` records every address executed so a
    // balanced-stack transfer counts as the OEP only when it lands on a
    // *new* address: the decryption loop's own jumps bounce between
    // already-seen addresses, and the popad/jmp that ends the wrapper
    // targets the OEP, which nothing executed before.
    std::uint64_t rip = view.entry_rva;
    bool balanced = false;
    result.steps = 0;
    std::vector<std::uint64_t> visited;
    visited.push_back(rip);

    while (result.steps < max_steps) {
        if (rip >= image_end) {
            result.reason = "instruction pointer left the image without a "
                            "balanced-stack transfer";
            return result;
        }
        Decoded d;
        m.current_rip = rip;
        if (!conc_decode(m.mem.data() + rip,
                         static_cast<std::size_t>(image_end - rip), rip, d)) {
            result.reason = "unsupported instruction at rva " +
                            std::to_string(rip) + " after " +
                            std::to_string(result.steps) + " steps";
            return result;
        }
        ++result.steps;

        const StepResult sr = conc_step(m, d, rip, image_end, result, balanced);
        if (sr.outcome == StepOutcome::Error) {
            result.reason = "stopped at rva " + std::to_string(rip) + ": " +
                            result.error;
            return result;
        }
        if (m.regs[Machine::kRsp] == m.rsp0) {
            balanced = true;
        }
        if (sr.outcome == StepOutcome::Transfer) {
            const std::uint64_t target = sr.transfer_target;
            bool seen = false;
            for (const std::uint64_t v : visited) {
                if (v == target) {
                    seen = true;
                    break;
                }
            }
            if (target < image_end && !seen) {
                // A balanced-stack transfer to a never-executed image
                // address: the OEP.
                result.ok = true;
                result.oep_rva = target;
                result.reason = "balanced-stack transfer to OEP";
                break;
            }
            if (target < image_end) {
                // A loop-back (already seen): follow.
                rip = target;
                continue;
            }
            result.reason = "transfer to an invalid or out-of-image target "
                            "at rva " + std::to_string(target);
            return result;
        }
        if (rip < image_end) {
            visited.push_back(rip);
        }
    }

    if (!result.ok) {
        result.reason = result.steps >= max_steps
                            ? "step cap reached (" +
                                  std::to_string(max_steps) +
                                  ") before a balanced OEP transfer"
                            : (result.reason.empty() ? "run ended without "
                                                       "an OEP"
                                                     : result.reason);
        return result;
    }

    // Assemble the decrypted image: original file bytes, with every
    // section's raw area replaced by the memory the loop left behind.
    result.image.assign(bytes, bytes + size);
    for (const PeSec& s : view.sections) {
        const std::size_t n =
            s.rawsize < s.vsize ? s.rawsize : s.vsize;
        if (s.raw + n <= result.image.size() &&
            s.va + n <= m.mem.size()) {
            std::memcpy(result.image.data() + s.raw, m.mem.data() + s.va, n);
        }
    }
    result.writes = result.smc.size();
    return result;
}

}  // namespace occ::packer::esp_law

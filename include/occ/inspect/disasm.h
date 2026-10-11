// The x64 length decoder's interface, and the semantic decoder built on
// it. The length is the load-bearing part; the semantics -- the real
// mnemonic, the operands as the Intel syntax writes them, the branch and
// rip-relative targets -- are what turns a byte stream into something a
// caller can reason about. See disasm.cpp for what the decoder covers and
// what it deliberately does not name.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "occ/util/span.h"

namespace occ::inspect {

// The length of the instruction at `bytes`, or 0 when the bytes are not an
// instruction this decoder accepts or the stream ends mid-instruction.
[[nodiscard]] std::uint32_t x64_instruction_length(
    const std::uint8_t* bytes, std::size_t available) noexcept;

// What one instruction is, beyond its length. `mnemonic` is the resolved
// name -- `add`, `cmp`, `je`, `call` -- and never a group placeholder: the
// grp1/grp3/grp5 encodings are answered with the name their reg field
// selects, which is the name the instruction reference prints. `operands`
// is the Intel-syntax rendering, sized for the longest form this decoder
// renders; an instruction the renderer does not cover carries an empty
// string rather than a wrong one.
enum class InsnKind : std::uint8_t {
    Other,
    Call,
    Jmp,
    Jcc,
    Ret,
    Syscall,
};

struct Decoded {
    std::uint32_t length = 0;  // 0 when the bytes are not decodable
    InsnKind kind = InsnKind::Other;
    const char* mnemonic = nullptr;
    // The ModRM byte's fields, when the instruction has one. `reg_field`
    // is the /digit the group opcodes dispatch on.
    bool has_modrm = false;
    std::uint8_t modrm = 0;
    std::uint8_t reg_field = 0;
    // A direct call, jump or conditional jump's resolved target. Valid
    // only when `has_branch_target`.
    bool has_branch_target = false;
    std::uint64_t branch_target = 0;
    // A rip-relative memory operand's resolved linear address -- the
    // `lea rax, [rip+0xff6]` that points at data, or the
    // `call [rip+0x28]` that points into the import table.
    bool has_rip_target = false;
    std::uint64_t rip_target = 0;
    // The instruction's immediate, when it carries one this decoder reads.
    bool has_immediate = false;
    std::uint64_t immediate = 0;
    // The Intel-syntax operand text. Empty when the renderer does not
    // cover the form; never partially rendered.
    static constexpr std::size_t kOperandsSize = 112;
    char operands[kOperandsSize] = {};
};

// Decodes one instruction, filling `out` and returning its length, or 0
// when the bytes are not decodable (leaving `out.length` at 0). `va` is
// the instruction's own virtual address, needed to resolve the
// relative forms to absolute targets.
[[nodiscard]] std::uint32_t x64_decode(const std::uint8_t* bytes,
                                       std::size_t available,
                                       std::uint64_t va,
                                       Decoded& out) noexcept;

// Linear disassembly from `bytes`: one JSON document of decoded
// instructions, each with its virtual address, its bytes, its length, the
// mnemonic and the operands. Undecodable bytes are reported as `.byte` and
// stepped over, which is how a sweep crosses embedded data.
[[nodiscard]] std::string x64_disassemble_json(ByteSpan bytes,
                                               std::uint64_t base_va,
                                               std::uint32_t max_instructions);

}  // namespace occ::inspect

// The x64 length decoder's interface. The disassembly is built on it and
// exposed beside it; see disasm.cpp for what the decoder covers and what it
// deliberately does not name.

#pragma once

#include <cstdint>
#include <string>

#include "occ/util/span.h"

namespace occ::inspect {

// The length of the instruction at `bytes`, or 0 when the bytes are not an
// instruction this decoder accepts or the stream ends mid-instruction.
[[nodiscard]] std::uint32_t x64_instruction_length(
    const std::uint8_t* bytes, std::size_t available) noexcept;

// Linear disassembly from `bytes`: one JSON document of decoded
// instructions, each with its virtual address, its bytes, its length and
// the mnemonic the decoder's table carries (omitted for opcodes the table
// does not name). Undecodable bytes are reported as `.byte` and stepped
// over, which is how a sweep crosses embedded data.
[[nodiscard]] std::string x64_disassemble_json(ByteSpan bytes,
                                               std::uint64_t base_va,
                                               std::uint32_t max_instructions);

}  // namespace occ::inspect

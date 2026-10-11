// The static analysis surface: functions, cross-references, control flow
// and call names, read from the file and reported without running it.
//
// The disassembler names instructions; this file answers the questions the
// instruction stream alone cannot. Which code reaches this string? Which
// function calls which? Where are the function boundaries? Each answer is
// computed from structures the image itself carries -- the .pdata function
// table, the import address table, the rip-relative encodings -- so every
// claim in the report is checkable against the sections beside it.
//
// Everything here is a reader: the image is parsed as it lies on disk,
// malformed structures are skipped rather than repaired, and the caps --
// on functions walked, on xref origins listed -- are reported in the
// document, so a truncated answer is known to be one.

#pragma once

#include <cstdint>
#include <string>

#include "occ/parser/pe.h"
#include "occ/util/span.h"

namespace occ::inspect {

// Produces the analysis document for one image. The bytes must be the
// whole file; `image` must be its parse. Answers an empty string when the
// parse failed -- the caller reports that through the parse's own error.
//
// The document carries, in one nesting:
//   functions   the .pdata table, walked: boundaries, sizes, instruction
//               and basic-block counts, and the calls each function makes
//   xrefs       every cross-reference the executable sections hold,
//               grouped by target and labeled with what the target is
//   callgraph   the caller-to-callee edges, with import and thunk names
//               resolved where the image's own tables resolve them
//   signatures  the names the image gives itself: import jump thunks read
//               their targets' names off the IAT, and the structural
//               stamps -- endbr64 prologues, xor-zero returns -- are
//               counted as the compiler fingerprints they are
[[nodiscard]] std::string analyze_pe_json(const parser::PeImage& image,
                                          ByteSpan bytes);

}  // namespace occ::inspect

// ESP-law unpacking: stack-balance detection of the original entry point.
//
// The classic ESP trick (OllyDbg's "ESP law") rests on a regularity of
// packed images: the wrapper's entry point saves the register state
// (`pushad` or a push sequence), runs the decryption loop, restores the
// state (`popad` / pops), and transfers to the original entry point.
// Because the pushes and pops balance, the stack pointer returns to its
// entry-time value exactly when the wrapper's work is done -- so the
// OEP is the first control transfer that happens while the stack is
// balanced and leaves the wrapper region.
//
// This module automates the trick *offline*: it decodes the entry-point
// instruction stream, executes it on a small in-process machine (regs,
// flags, a flat simulated address space), and watches three signals:
//
//   - stack balance: RSP returns to its entry-time value;
//   - a control transfer (indirect jmp/call, or ret) executed at a
//     balanced stack;
//   - the transfer's target leaving the mapped image's entry region,
//     which is the OEP.
//
// The machine executes only the instruction subset a decryption loop
// actually uses (moves, lea, arithmetic, shifts, pushes/pops, calls,
// jcc/jmp, ret, nop, xchg, movzx/sx, not/neg); anything else stops the
// run and the report says exactly where and why, because a decoder that
// silently skips an instruction would fabricate a "successful" unpack.
// Calls that leave the image are stubbed (recorded, return value zero):
// a real unpacker resolves imports with the runtime; this module's job
// is the loop that decrypts, not the loader that binds. Every write the
// loop performs is recorded as an SMC event, so the module feeds
// `analyze_smc` the same shape of evidence a runtime watch would produce.
//
// The result carries the decrypted image (original headers plus every
// section as the loop left it), the OEP RVA when one was found, the
// step and write counts, the API calls observed, and the stop reason.
// When no OEP is found the reason says so (step cap, unsupported
// instruction, transfer with no stable target) and the caller can fall
// back to the runtime path; this module never guesses an OEP.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "occ/packer/packer.h"

namespace occ::packer::esp_law {

// One observed API call: the instruction's address and its stub outcome.
struct ApiCall {
    std::uint64_t at_rva = 0;    // RVA of the call instruction
    std::uint64_t target = 0;    // the call's target address
    std::uint64_t ret_rax = 0;   // the value the stub left in RAX
    std::string note;            // why it was treated as an API call
};

// The ESP-law unpack result.
struct EspLawResult {
    bool ok = false;
    std::string error;           // non-empty when the run could not start
    std::string reason;          // why the run stopped (balanced/OEP/cap/unsupported)
    std::uint64_t oep_rva = 0;   // detected original entry point (0 = none)
    std::size_t steps = 0;       // instructions executed
    std::size_t writes = 0;      // data writes the loop performed
    std::size_t max_steps = 0;   // the cap that applied
    std::vector<ApiCall> api_calls;
    std::vector<SMCWrite> smc;   // write events, analysable by analyze_smc
    std::vector<std::uint8_t> image;  // decrypted image (headers + sections)
};

// Runs the ESP-law analysis over a PE image given as file bytes.
//
// `bytes`/`size` bound the image; the entry RVA comes from the headers.
// The simulated address space maps the image at VA 0 (RVA == VA), a
// simplification the module states in its report; the decrypted `image`
// is returned as a standalone byte buffer so a caller can hand it to
// whatever writes files, without depending on how the runtime maps.
// `max_steps` caps the loop count (default 250 000 -- enough for a
// several-hundred-KB unpack loop, bounded so a misread never spins).
[[nodiscard]] EspLawResult analyze(const std::uint8_t* bytes,
                                   std::size_t size,
                                   std::size_t max_steps = 250000) noexcept;

// ------------------------------------------------------------ offline unpack

// The offline half of the unpack pipeline: what the image is, and what
// its wrapper's own loop leaves behind.
struct OfflineUnpack {
    packer::Report analysis;  // what the image is, from its file bytes
    bool ran = false;         // whether the ESP-law loop ran
    std::string skip_reason;  // non-empty exactly when `ran` is false
    EspLawResult law;         // the loop's outcome; valid only when `ran`
    std::string text;         // the merged human-readable report
};

// Composes the two offline analyses in the order an unpacker asks them:
// identify first, so the report opens with what the image is and with
// what confidence, then the ESP-law loop, gated on that answer.
//
// The gate is a refusal to guess, not a fast path. An image the
// identifier calls unpacked has no wrapper to run, and running the loop
// anyway would report a step cap as a finding rather than as the
// absence of a wrapper; so the loop runs only when the identifier's
// verdict is "packed", at either confidence. An image identified as
// unpacked is reported as such with the loop's absence stated plainly,
// and an image the identifier could not parse is reported with its
// parse error and no loop. Nothing here upgrades a low-confidence
// signal into a verdict, which is the same rule identify follows.
[[nodiscard]] OfflineUnpack offline_unpack(const std::uint8_t* bytes,
                                           std::size_t size) noexcept;

// Reads a file and runs `offline_unpack` over it. A file that cannot be
// read produces a report whose `analysis.valid` is false and whose error
// says which failure it was.
[[nodiscard]] OfflineUnpack offline_unpack_file(
    const std::string& path) noexcept;

// Renders an OfflineUnpack as human-readable text: the identification
// report, the gate decision with its reason, and -- when the loop ran --
// its outcome, the OEP, and the step and write counts.
[[nodiscard]] std::string offline_report_text(
    const OfflineUnpack& result) noexcept;

}  // namespace occ::packer::esp_law

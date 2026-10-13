// The packer module: what wraps a PE, where it decrypts itself, and how
// the runtime hands back a file that no longer needs the wrapper.
//
// Three analyses live here, and they are the three questions an unpacker
// asks of an image, in the order it asks them.
//
// The first is identification, and it is deliberately offline: given the
// bytes of a PE -- the file, or a running image mapped in this process --
// it answers what packer, if any, the image was built with, and why.
// Every answer is a weighted sum of independent observations: a section
// whose name is a known packer's (UPX0, .themida, .vmp0...), a section
// whose Shannon entropy is too high to be compiled code, a virtual size
// far larger than the file bytes that back it, an import table that is
// nearly empty or built around LoadLibrary/GetProcAddress, an entry
// point that opens with a stub idiom. No single observation is trusted:
// anyone can name a section UPX1, so a name hit without high entropy is
// reported as the contradiction it is, and a candidate whose evidence
// disagrees with itself is marked low-confidence rather than smoothed
// over. The thresholds are spelled out in the implementation, with the
// rationale each one stands on, because a heuristic whose number is
// unexplained is a heuristic that cannot be argued with.
//
// The second is self-modifying code detection, and it is the consumer of
// the runtime's write records rather than an observer of its own. This
// module cannot arm page-protection watches -- the machinery for that
// lives in occ::runtime::memwatch, and changing it is outside this
// module's file boundary. What it does is say what a set of write events
// *means*: a write that lands in an executable section is a write-to-exec
// finding; many writes into one section, or several into one page, are
// the shape a decryption loop leaves; a write into a data section is
// recorded but not alarmed. The wiring is one line's worth of plumbing
// -- the fault handler's memwatch::service_write records (fault_address,
// rip) and a runtime integrator hands those records to analyze_smc -- and
// the comment in analyze_smc names exactly where that line would go.
//
// The third is the unpack pipeline, and it is the runtime's own moment:
// it needs the guest image mapped in this process, because that is the
// only place the decrypted bytes exist. It identifies the mapped image,
// dumps it with occ::runtime::image_dump (which rewrites the file layout
// so every section lands at its full virtual size), and writes the
// import-slot report with occ::runtime::iat_rebuild (which names the
// slots the packed code resolved at run time), then merges the three
// into one human-readable text. The offline analyses above are the ones
// that work without a running guest; unpack is the point where this
// module touches the runtime's own APIs, and it is honest about that
// dependency rather than pretending a file buffer would be enough.
//
// The not-guessing rule that runs through the other modules holds here
// too: a section with an unrecognized name and ordinary entropy is not
// called packed, an import directory that cannot be read is reported as
// unreadable rather than empty, and a confidence below the stated line
// is printed as low rather than hidden. What cannot be proven is labeled
// unknown; what can be said is said with its evidence attached, so a
// reader can weigh the same facts the scorer did.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "occ/runtime/iat_rebuild.h"
#include "occ/runtime/image_dump.h"

namespace occ::packer {

// ------------------------------------------------------------------ identify

// One observation in a candidate's favour (or against it). `weight` is the
// signed contribution to the candidate's score -- inconsistency evidence
// is negative on purpose, so a candidate that contradicts itself scores
// lower, not higher, for having been noticed.
struct Evidence {
    enum class Kind : std::uint8_t {
        // A section name matched the known-packer table.
        SectionName,
        // A section's Shannon entropy cleared the high bar (>= 7.0 bits).
        HighEntropy,
        // A section's virtual size far exceeds its file bytes.
        SizeDisparity,
        // The import table combines LoadLibrary* and GetProcAddress.
        ImportAnomaly,
        // The image imports almost nothing (or has no import directory).
        ImportMinimal,
        // The entry point opens with a packer stub idiom.
        EntryPattern,
        // A named section's entropy contradicts the packer it claims.
        Inconsistency,
    };
    Kind kind = Kind::SectionName;
    // What the observation was about: a section name, "imports", "entry".
    std::string subject;
    double weight = 0.0;
    std::string note;
};

// One section of the image, as the analysis saw it. Entropy is in bits per
// byte over the bytes this view of the image can read (0..8); a section
// with no readable bytes reports 0 and says so in the report's notes.
struct SectionStat {
    std::string name;
    std::uint32_t rva = 0;
    std::uint32_t vsize = 0;
    std::uint32_t rawsize = 0;
    double entropy = 0.0;
    std::uint32_t characteristics = 0;
};

// A packer the image may be wrapped in, with the confidence the evidence
// supports and the evidence itself. `low_confidence` is the flag a caller
// checks when a downstream decision needs to refuse to guess: it is set
// when the score stays under the low bar or when the candidate's own
// evidence contradicts itself, and a caller that ignores it is making a
// choice the report has already flagged.
struct Candidate {
    std::string name;  // "UPX", "Themida", "unknown (generic packer)"...
    // The raw weighted sum of the evidence, before clamping: the number
    // a reader can recompute from the evidence list. Confidence is this
    // value clamped to 0..1.
    double score = 0.0;
    double confidence = 0.0;  // clamped to 0..1
    std::vector<Evidence> evidence;
    bool low_confidence = false;
};

// The whole answer to "is this image packed, and with what".
//
// `valid` is false only when the image was not a readable PE; everything
// the analysis could still say -- the parse error, the sections it did
// read -- is in `error` and `notes` rather than dropped.
struct Report {
    bool valid = false;
    std::string error;
    std::string format;    // "PE32" or "PE32+", empty when unparsable
    std::uint16_t machine = 0;
    std::uint32_t entry_rva = 0;
    std::vector<SectionStat> sections;
    std::vector<Candidate> candidates;  // best first
    std::string verdict;   // "unpacked" / "packed (high confidence): UPX" / ...
    std::vector<std::string> notes;
};

// Identifies a PE from its file bytes. `size` bounds every read, so a
// truncated or damaged file is refused cleanly instead of read past.
[[nodiscard]] Report identify(const std::uint8_t* bytes,
                              std::size_t size) noexcept;

// Identifies a PE from a mapped image. The image is trusted to be mapped
// the way the runtime maps it (headers at base, sections at base+rva, at
// least SizeOfImage bytes), the same trust iat_rebuild and image_dump
// take; a caller with a bounded buffer should use the byte overload.
[[nodiscard]] Report identify(std::uint64_t image_base) noexcept;

// Reads a file and identifies it. False in the report means the file
// could not be read or was not a PE; the error says which.
[[nodiscard]] Report identify_file(const std::string& path) noexcept;

// ----------------------------------------------------------------------- SMC

// One recorded write into (or near) the image. `size` is the write width
// when the recorder knew it and 0 when it did not -- the analysis never
// guesses a width from 0.
struct SMCWrite {
    std::uint64_t write_va = 0;
    std::uint64_t rip = 0;   // the instruction that wrote, 0 if unknown
    std::size_t size = 0;
};

enum class SMCKind : std::uint8_t {
    WriteToExec,  // a write landed in an executable section
    DecryptLoop,  // repeated writes: the shape a decryption loop leaves
    DataWrite,    // a write into a data section: recorded, not alarmed
};

struct SMCEvidence {
    SMCKind kind = SMCKind::WriteToExec;
    std::uint64_t target_va = 0;  // the address written
    std::uint64_t rip = 0;        // the instruction that wrote
    std::string section;          // the section the write landed in
    std::string note;
};

struct SMCReport {
    std::vector<SMCEvidence> findings;
    std::vector<std::string> notes;
    std::size_t total_writes = 0;
};

// Classifies a list of write events against the image's section layout.
//
// This is the consumer of the runtime's write records. The runtime's
// memwatch arm records a watched store as (fault_address, rip) inside
// memwatch::service_write; an integrator that forwards those records here
// -- the OCC_MEMWATCH path, whose plumbing lives in occ::runtime and is
// outside this module's boundary -- gets the SMC picture for free. The
// image parameter supplies the section layout only; the analysis reads
// no section bytes, so either a file buffer or a mapped image works as
// long as its headers are at `image` and its write addresses are
// absolute guest VAs (image_base + rva), which is what the runtime
// records.
[[nodiscard]] SMCReport analyze_smc(const std::uint8_t* image,
                                    std::size_t size,
                                    std::uint64_t image_base,
                                    const std::vector<SMCWrite>& writes) noexcept;

// The mapped-image form of analyze_smc, for a runtime that holds only the
// base. The image is trusted to be mapped, like the identify overload.
[[nodiscard]] SMCReport analyze_smc(std::uint64_t image_base,
                                    const std::vector<SMCWrite>& writes) noexcept;

// A static hint that an image may modify its own code: a section that is
// both writable and executable (RWX). No write events are needed -- the
// section's characteristics are the evidence. A result here is a reason
// to arm the runtime watch over that section, not a finding on its own.
struct SMCHint {
    std::string section;
    std::uint32_t rva = 0;
    std::uint32_t vsize = 0;
    std::uint32_t characteristics = 0;
    std::string note;
};

[[nodiscard]] std::vector<SMCHint> static_smc_hints(const std::uint8_t* image,
                                                    std::size_t size) noexcept;
[[nodiscard]] std::vector<SMCHint> static_smc_hints(
    std::uint64_t image_base) noexcept;

// ------------------------------------------------------------------ unpack

// The result of the runtime unpack pipeline: the identification of the
// mapped image, whether the dump and the IAT report were written, where
// they went, and a merged human-readable text covering all three.
struct UnpackResult {
    Report analysis;
    bool dump_ok = false;
    bool iat_ok = false;
    std::string dump_path;
    std::string report_path;
    std::string text;
};

// Runs the unpack pipeline over a mapped guest image.
//
// This is a runtime wiring point, and only that: it requires the guest
// image mapped in this process, because image_dump reads the decrypted
// bytes that exist only in the mapping and iat_rebuild reads the slots
// the run filled. The offline analyses (identify, analyze_smc,
// static_smc_hints) work without a running guest; this function is where
// the module calls the runtime's own dump and rebuild APIs, in order:
// identify first (so the text report opens with what the image is),
// then image_dump::dump (the repaired file), then iat_rebuild::report
// (the import-slot names), and the merged text is built last. `regs` is
// passed through to the dump for the OEP register state when the caller
// captured it.
[[nodiscard]] UnpackResult unpack(
    std::uint64_t image_base, const std::string& dump_path,
    const std::string& report_path,
    const occ::runtime::image_dump::EntryRegs* regs = nullptr) noexcept;

// Renders a Report as human-readable text: the section table with
// entropies, each candidate with its evidence and confidence, and the
// verdict.
[[nodiscard]] std::string report_text(const Report& report) noexcept;

}  // namespace occ::packer

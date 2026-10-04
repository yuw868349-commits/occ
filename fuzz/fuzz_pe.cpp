// Harness: PE image reader over arbitrary bytes.
//
// The PE reader is the newest parser in occ and the only one whose input
// comes from a coordinate system the file does not state plainly. An ELF
// program header names a file offset and a vaddr; a PE names an RVA, and
// turning an RVA into a file offset requires finding a section, comparing
// against two different sizes (VirtualSize and SizeOfRawData), and
// distinguishing three outcomes that all fit in a bool if you are careless:
// a real file offset, a region that exists only in memory, and nowhere at
// all.
//
// So the invariants below are about that conversion. A parser that survives
// without crashing but maps an RVA to an offset outside the file has still
// produced a lie, and `pe_engine` hands those offsets to a loader.
//
// The seeds matter more here than for the ELF harness. A fuzzer starts by
// broadening what it already reaches, and the PE reader's first three gates
// are the MZ signature, e_lfanew pointing at a PE signature, and the optional
// header's magic. An input of zeros reaches none of them, so the corpus has
// to contain files that get past each.

#include "occ/parser/detect.h"
#include "occ/parser/pe.h"
#include "occ/util/span.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

using occ::ByteSpan;
using occ::parser::PeImage;
using occ::parser::PeSection;

ByteSpan as_span(const uint8_t* data, std::size_t size) noexcept {
    return ByteSpan{data, size};
}

// The invariants a parsed PE has to satisfy whatever the input was.
//
// Each of these is a claim the rest of occ relies on. pe_engine resolves
// imports through this reader, and an offset that lands outside the file is a
// read of somebody else's memory.

// A section's ends, and the range they describe.
//
// virtual_end and raw_end are the reader's own saturating additions; the
// checks here are on the values as reported, because a saturating addition
// that saturates has still produced a range nobody can map.
bool section_is_sane(const PeSection& s, std::size_t file_size) noexcept {
    // A section that starts after it ends. Reachable when virtual_address +
    // virtual_size wrapped in 32-bit arithmetic and the reader did not widen
    // before adding: the end comes out below the start and the section
    // covers nothing, or worse, covers everything.
    if (s.virtual_end() < s.virtual_address) {
        return false;
    }

    // Same question for the file extent. A raw_offset + raw_size that wraps
    // produces an end below the start, and the section claims file data that
    // begins after it ends.
    if (s.raw_size != 0) {
        if (s.raw_end() < s.raw_offset) {
            return false;
        }
        // And the file extent has to be inside the file. The reader checks
        // this while parsing, so reaching it here would mean the check and
        // the reported value disagree.
        if (s.raw_offset > file_size) {
            return false;
        }
        if (static_cast<std::size_t>(file_size) - s.raw_offset < s.raw_size) {
            return false;
        }
    }

    // A section with no raw data is a legitimate thing -- .bss, and the
    // padding sections a linker emits. Its raw extent is then empty and
    // nothing more is true of it.
    return true;
}

// Every claim the reader makes, checked against the input it was given.
bool invariants_hold(const PeImage& image, std::size_t file_size) noexcept {
    // A failed parse reports nothing. A caller checks ok() and then trusts
    // the rest, so a failed parse that still carries sections is the worst
    // outcome available: not a crash, and not readable either.
    if (!image.ok()) {
        return image.sections().empty() && image.imports().empty();
    }

    // A parsed image has sections. A PE with none cannot be mapped, and one
    // that parsed successfully without them has accepted a header it should
    // have refused.
    if (image.sections().empty()) {
        return false;
    }

    for (const PeSection& s : image.sections()) {
        if (!section_is_sane(s, file_size)) {
            return false;
        }
    }

    // Every RVA the reader will convert has to convert consistently. The
    // header region is the interesting case: an RVA below SizeOfHeaders is
    // already a file offset, so it resolves without consulting any section,
    // and a reader that forgot that would report it as unmapped.
    if (image.headers_size() != 0 && image.headers_size() <= file_size) {
        std::uint64_t off = 0;
        if (!image.to_file_offset(0, off) || off != 0) {
            return false;
        }
    }

    // An import name is a name the file stated. An empty one is a string with
    // no bytes in it, which read_cstring refuses -- so an empty name here
    // means a descriptor was read whose Name field pointed at something that
    // is not a string.
    for (const std::string& name : image.imports()) {
        if (name.empty()) {
            return false;
        }
        // A name longer than any real one is the same defect seen from the
        // other side: read_cstring caps at 512 and discards rather than
        // truncating, so nothing this long should have survived.
        if (name.size() > 512) {
            return false;
        }
    }

    // The import directory is either absent or it resolved to something.
    // A directory that resolved and produced no names is fine -- a table can
    // legitimately be empty -- but the two are told apart by the reader, and
    // a caller branching on this needs them to agree.
    return true;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data,
                                      std::size_t size) noexcept {
    const ByteSpan bytes = as_span(data, size);

    // Detection first: detect_bytes reads near the front of the file, and a
    // corpus entry that reaches the PE reader is a seed for this.
    const auto detection = occ::parser::detect_bytes(bytes);
    (void)occ::parser::format_name(detection.format);

    const PeImage image = PeImage::parse(bytes);

    // Touch every accessor even on a failed parse. An accessor that reads
    // uninitialised state is a finding in itself, and a fuzzer that only
    // calls the accessors on success never reaches one.
    (void)image.ok();
    (void)image.error();
    (void)image.error_detail();
    (void)image.kind();
    (void)image.is_dll();
    (void)image.is_pe32_plus();
    (void)image.machine();
    (void)image.machine_raw();
    (void)image.subsystem();
    (void)image.subsystem_raw();
    (void)image.entry_rva();
    (void)image.entry_va();
    (void)image.image_base();
    (void)image.image_size();
    (void)image.headers_size();
    (void)image.section_alignment();
    (void)image.file_alignment();
    (void)image.optional_header_size();
    (void)image.section_count();
    (void)image.dynamic_base();
    (void)image.nx_compat();
    (void)image.high_entropy_va();
    (void)image.has_seh();
    (void)image.reloc_rva();
    (void)image.reloc_size();

    if (!invariants_hold(image, size)) {
        // An invariant failure is a bug, not a crash, so it has to abort
        // rather than return: returning would let the fuzzer record the
        // input as uninteresting and move on.
        __builtin_trap();
    }

    // The conversion itself, over a spread of RVAs chosen from the input.
    //
    // Calling to_file_offset at a few fixed values would only test the
    // values chosen. Taking them from the file instead means the fuzzer
    // supplies the RVAs: an RVA that lands in zero fill, in a gap, past the
    // last section, or nowhere near any of them. Sixteen is enough to cover
    // the four regions several times over and costs nothing next to the
    // parse.
    std::uint64_t off = 0;
    bool zero_filled = false;
    for (std::size_t i = 0; i < size && i < 16; ++i) {
        // Two bytes at a time, read little-endian, so the values are spread
        // across the 16-bit range rather than clustered at zero.
        const std::uint64_t rva =
            static_cast<std::uint64_t>(data[i]) |
            (i + 1 < size
                 ? static_cast<std::uint64_t>(data[i + 1]) << 8
                 : 0);

        const bool as_offset = image.to_file_offset(rva, off);
        // Whatever to_file_offset said, the offset it produced has to be a
        // real place in the file. This is the claim pe_engine relies on and
        // the one a conversion bug breaks: an offset inside the file for an
        // RVA that is not, or past the end for one that is.
        if (as_offset && off >= size) {
            __builtin_trap();
        }

        const bool resolved = image.resolve_rva(rva, off, zero_filled);
        // resolve_rva is the wider question, so it succeeds wherever
        // to_file_offset does -- and it says which kind of answer it is. A
        // success that is not zero fill has to be a file offset inside the
        // file; a zero fill has no offset at all, so an offset there is a
        // fabricated location.
        if (resolved && !zero_filled && off >= size) {
            __builtin_trap();
        }
        if (resolved && zero_filled && off != 0) {
            __builtin_trap();
        }
        if (!resolved && zero_filled) {
            __builtin_trap();
        }
    }

    return 0;
}
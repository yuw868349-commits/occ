#include "occ/runtime/loader.h"

#include <algorithm>
#include <cstring>

namespace occ::runtime {

namespace {

// ---------------------------------------------------------------- constants

// IMAGE_DIRECTORY_ENTRY_* indices into the data directories array.
//
// Only the entries this loader reads from the raw header are named. The
// exception directory and the IAT directory are not among them: an index
// constant that no code uses is a claim that the corresponding directory is
// handled, and neither is at this layer. The exception directory belongs to
// the layer that dispatches structured exceptions, and the IAT is located
// through each import descriptor's own fields rather than through the
// directory entry.
//
// The base relocation directory is read through the parser's accessor for
// the same reason: the parser already resolved it, and reading it again
// from the raw header would be a second place for the offset arithmetic to
// be wrong.
constexpr unsigned kDirImport = 1;
constexpr unsigned kDirTls = 9;

// The relocation types this runtime applies.
//
// ABSOLUTE is not a relocation, it is padding between blocks, and applying
// it would write zeros over a section. Typing it and then ignoring it is
// how the padding is handled without a special case in the loop that reads
// entries.
constexpr std::uint16_t kRelBasedAbsolute = 0;
constexpr std::uint16_t kRelBasedHigh = 1;
constexpr std::uint16_t kRelBasedLow = 2;
constexpr std::uint16_t kRelBasedHighLow = 3;
constexpr std::uint16_t kRelBasedHighAdj = 4;
constexpr std::uint16_t kRelBasedDir64 = 10;

// The offset of the data directories inside the optional header, from the
// start of the optional header. The optional header is a fixed prefix
// followed by the directory array, and the array's position differs between
// PE32 and PE32+ only because the fixed prefix does.
constexpr std::size_t kDirsOffset32 = 96;
constexpr std::size_t kDirsOffset64 = 112;

// ------------------------------------------------------------------ reading

// A little-endian read at a byte offset, with the bound checked as a
// subtraction.
//
// The subtraction matters: `off + 4 > size` wraps when both operands come
// from the file, and a wrapped comparison passes while the read after it
// goes out of bounds. `off > size - 4` cannot wrap because the guard above
// it has already established that size is at least 4.
[[nodiscard]] bool read_u16(ByteSpan b, std::size_t off,
                            std::uint16_t& out) noexcept {
    if (b.size() < 2 || off > b.size() - 2) {
        return false;
    }
    out = static_cast<std::uint16_t>(b.data()[off]) |
          static_cast<std::uint16_t>(static_cast<std::uint16_t>(b.data()[off + 1])
                                     << 8);
    return true;
}

[[nodiscard]] bool read_u32(ByteSpan b, std::size_t off,
                            std::uint32_t& out) noexcept {
    if (b.size() < 4 || off > b.size() - 4) {
        return false;
    }
    out = static_cast<std::uint32_t>(b.data()[off]) |
          (static_cast<std::uint32_t>(b.data()[off + 1]) << 8) |
          (static_cast<std::uint32_t>(b.data()[off + 2]) << 16) |
          (static_cast<std::uint32_t>(b.data()[off + 3]) << 24);
    return true;
}

[[nodiscard]] bool read_u64(ByteSpan b, std::size_t off,
                            std::uint64_t& out) noexcept {
    std::uint32_t lo = 0;
    std::uint32_t hi = 0;
    if (!read_u32(b, off, lo) || !read_u32(b, off + 4, hi)) {
        return false;
    }
    out = static_cast<std::uint64_t>(lo) |
          (static_cast<std::uint64_t>(hi) << 32);
    return true;
}

// Reads a NUL-terminated ASCII string at an RVA, bounded by the file.
//
// A name that does not terminate inside the file is refused rather than
// returned as a fragment. An import named "CreateFileW" and one named
// "CreateFileW" followed by garbage are different programs' requests and a
// reader that silently truncates cannot tell the person which one it saw.
[[nodiscard]] bool read_rva_name(const parser::PeImage& image, ByteSpan bytes,
                                 std::uint64_t rva,
                                 std::string& out) noexcept {
    std::uint64_t off = 0;
    if (!image.to_file_offset(rva, off)) {
        return false;
    }
    if (off >= bytes.size()) {
        return false;
    }
    out.clear();
    // A cap rather than a scan to the end of the file: an export name
    // longer than this is not a name, and a corrupted pointer into a large
    // section would otherwise be walked in full.
    constexpr std::size_t kMaxName = 4096;
    for (std::size_t i = static_cast<std::size_t>(off); i < bytes.size(); ++i) {
        const char c = static_cast<char>(bytes.data()[i]);
        if (c == '\0') {
            return !out.empty();
        }
        if (out.size() >= kMaxName) {
            return false;
        }
        out.push_back(c);
    }
    return false;
}

// -------------------------------------------------------------------- events

void emit_mapping(obs::Writer* w, const Region& r) noexcept {
    if (w == nullptr) {
        return;
    }
    auto& e = w->begin(obs::EventKind::Mapping);
    e.add_hex("base", r.base);
    e.add_hex("size", r.size);
    e.add("protection", protection_name(r.protection));
    e.add("kind", region_kind_name(r.kind));
    if (!r.section.empty()) {
        e.add("section", r.section);
    }
    w->commit();
}

void emit_note(obs::Writer* w, std::string_view text) noexcept {
    if (w != nullptr) {
        w->note(text);
    }
}

// An address as the "0x" + minimal lowercase-hex form the details below use.
//
// It mirrors the helper detect.cpp defines for its own refusals, and it is
// duplicated rather than shared for the same reason the two parsers do not
// share theirs: a formatting decision made for one refusal should not change
// another. The width is the value's own, so 0x0 is spelled 0x0 and not
// 0x0000000000000000, which is what a reader comparing two refusals needs.
[[nodiscard]] std::string hex_of(std::uint64_t v) {
    if (v == 0) {
        return "0x0";
    }
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    while (v != 0) {
        out.push_back(digits[v & 0xf]);
        v >>= 4;
    }
    out.push_back('x');
    out.push_back('0');
    std::reverse(out.begin(), out.end());
    return out;
}

} // namespace

const char* load_error_name(LoadError e) noexcept {
    switch (e) {
    case LoadError::None: return "none";
    case LoadError::NotParsable: return "not_parsable";
    case LoadError::UnsupportedMachine: return "unsupported_machine";
    case LoadError::SectionOutOfRange: return "section_out_of_range";
    case LoadError::NoRelocations: return "no_relocations";
    case LoadError::BadRelocation: return "bad_relocation";
    case LoadError::MissingImport: return "missing_import";
    case LoadError::UnimplementedImport: return "unimplemented_import";
    case LoadError::AddressConflict: return "address_conflict";
    }
    return "unknown";
}

LoadResult load_image(const parser::PeImage& image, ByteSpan bytes,
                      std::uint64_t preferred_base, AddressSpace& space,
                      const LoadContext& context) noexcept {
    LoadResult out;

    if (!image.ok()) {
        out.error = LoadError::NotParsable;
        out.detail = image.error_detail();
        return out;
    }

    // The machine check.
    //
    // Only AMD64 is executed. An ARM64 image is a valid PE and refusing it
    // by name is a different act from refusing a damaged file, which is why
    // the error is its own value. The check is on the parser's named
    // machine rather than on the raw word so that adding a machine to the
    // runtime means adding it in one place.
    if (image.machine() != parser::PeMachine::Amd64) {
        out.error = LoadError::UnsupportedMachine;
        out.detail = std::string("the image is for ") +
                     parser::pe_machine_name(image.machine()) +
                     ", and this runtime executes only amd64";
        return out;
    }

    // Where the image lands.
    //
    // A caller that named a base gets it. A caller that did not gets the
    // image's own preferred base, because that is the address the image was
    // linked for and using it means the relocation pass has nothing to do.
    // This is not an optimisation: an image with no relocation table can
    // only load at its preferred base, so choosing it is what lets those
    // images load at all.
    std::uint64_t base = preferred_base != 0 ? preferred_base : image.image_base();
    if (base == 0) {
        out.error = LoadError::NoRelocations;
        out.detail = "the image names no base and the caller named none";
        return out;
    }

    const std::uint64_t image_size = image.image_size();
    if (image_size == 0) {
        out.error = LoadError::SectionOutOfRange;
        out.detail = "the image declares a size of zero";
        return out;
    }

    const std::uint64_t headers_size = image.headers_size();
    if (headers_size > image_size) {
        out.error = LoadError::SectionOutOfRange;
        out.detail = "the headers are larger than the image";
        return out;
    }

    // The relocation decision is made before anything is mapped, so that an
    // image that cannot be placed is refused without having been placed.
    const bool needs_relocation = base != image.image_base();
    const bool has_relocations = image.reloc_size() != 0;
    if (needs_relocation && !has_relocations) {
        out.error = LoadError::NoRelocations;
        out.detail = "the image asked for base 0x" +
                     std::to_string(image.image_base()) +
                     " and has no relocation table, so it cannot be placed "
                     "at 0x" + std::to_string(base);
        return out;
    }

    // ------------------------------------------------------- placement plan
    //
    // The plan is built before anything is recorded.
    //
    // The order is the contract: a LoadResult that is not ok leaves the
    // space unchanged, and that is what lets a caller retry at another base
    // without unwinding a half-populated map. Everything below that can
    // refuse -- a section out of the window, a bad relocation -- is
    // therefore decided here, against the file and the plan, and the
    // records at the end happen only once all of it has held. Putting the
    // mapping first reads more naturally and is wrong, because the walk
    // that finds a bad relocation comes after it and by then the sections
    // are in the map.

    // The section table, gathered up front so that the loop below does not
    // re-walk it. The count was bounded by the parser; this is only the
    // copy that makes the iteration cheap.
    struct Placement {
        std::uint32_t index;
        const parser::PeSection* section;
        std::uint64_t va;
        std::uint64_t mem_size;
        std::uint64_t file_size;
        std::uint64_t file_off;
    };
    std::vector<Placement> placements;
    placements.reserve(image.sections().size());

    for (std::uint32_t i = 0; i < image.sections().size(); ++i) {
        const parser::PeSection& s = image.sections()[i];

        // The in-memory size is VirtualSize when it is set and the raw size
        // when it is not. A linker that emits a section with VirtualSize 0
        // means "as large as the file part", and treating the zero as a
        // zero-length section would drop it.
        std::uint64_t mem = s.virtual_size != 0 ? s.virtual_size : s.raw_size;
        // Rounded up to a page: a section whose size is not a multiple of
        // the page is mapped in whole pages, and recording it unrounded
        // would leave the tail of the last page unowned, so a fault there
        // would be reported as unmapped when it is mapped.
        mem = (mem + AddressSpace::kPageSize - 1) &
              ~(AddressSpace::kPageSize - 1);
        if (mem == 0) {
            // A section with no content in either coordinate. Legal, and
            // there is nothing to map.
            continue;
        }

        const std::uint64_t va = base + s.virtual_address;
        // A subtraction again: the section's own address from the file is
        // added to a base from the caller, and the sum is compared against
        // the window rather than added to the size.
        if (va < base || va > AddressSpace::kUserMax ||
            mem > AddressSpace::kUserMax - va) {
            out.error = LoadError::SectionOutOfRange;
            out.detail = "section " + s.name + " would be placed outside the "
                         "address window";
            return out;
        }

        Placement p;
        p.index = i;
        p.section = &s;
        p.va = va;
        p.mem_size = mem;
        // The file part is capped at the memory part. A section whose raw
        // size exceeds its virtual size is a file with a tail that is not
        // mapped, which is a real layout and not an error: the bytes are in
        // the file and the program cannot address them.
        p.file_size = s.raw_size < mem ? s.raw_size : mem;
        if (p.file_size > bytes.size() || s.raw_offset > bytes.size() ||
            p.file_size > bytes.size() - s.raw_offset) {
            // The tail is dropped rather than the section refused. The
            // parser already rejected a raw extent outside the file, so
            // reaching here means the file shrank between the parse and the
            // load -- which cannot happen for a file held open, but the
            // check costs nothing and makes the copy below bounded by
            // construction rather than by an argument.
            p.file_size = 0;
        }
        p.file_off = s.raw_offset;

        placements.push_back(p);
    }

    // The entry point has to be inside the image.
    //
    // This is a check the loader did not have and the fuzzer found: an image
    // whose entry RVA points past the end of every section -- or into the
    // gap between two sections that the linker left -- loads, reports
    // success, and hands the layer above a module whose entry address is not
    // mapped. The first instruction of such a program faults, and nothing
    // above this layer can see it coming, because the loader is the only
    // place that holds both the entry address and the map.
    //
    // A zero entry RVA is not an error and is not checked here: an image
    // that is a pure DLL has no entry point and declares zero, and a runtime
    // that refused it would refuse every resource-only module. The check is
    // therefore on a non-zero entry, which is the only case where the field
    // claims something about an address.
    //
    // The bound is the image, not the window: the entry point of an image is
    // an address the image itself owns, and an image that places it outside
    // its own SizeOfImage is an image whose linker disagreed with its
    // headers. The subtraction is a subtraction rather than an addition
    // because both operands come from the file and a sum can wrap.
    const std::uint64_t image_entry_rva = image.entry_rva();
    if (image_entry_rva != 0) {
        if (image_entry_rva >= image_size) {
            out.error = LoadError::SectionOutOfRange;
            out.detail = "the entry point RVA " + hex_of(image_entry_rva) +
                         " is outside the image, which is " +
                         hex_of(image_size) + " bytes";
            return out;
        }
        // And it has to land in a section that was actually placed, and that
        // section has to be executable.
        //
        // The two questions are asked in one walk because they are about the
        // same section. Coverage alone is not enough: the entry point is
        // where execution starts, and a program whose first instruction is
        // in a read-only page cannot run. Windows enforces the same thing
        // and reports it as a failure to start rather than as a fault at the
        // first instruction; deciding it here means the refusal names the
        // section.
        //
        // The headers are deliberately not accepted as coverage. They are
        // never executable, and a program whose entry point is inside its
        // own headers cannot run, so accepting them for coverage and then
        // rejecting them for executability would be two checks where one
        // answers both questions with the same result.
        bool entry_ok = false;
        for (const Placement& p : placements) {
            const std::uint64_t start = p.section->virtual_address;
            if (image_entry_rva >= start &&
                image_entry_rva - start < p.mem_size) {
                entry_ok = p.section->executable();
                break;
            }
        }
        if (!entry_ok) {
            out.error = LoadError::SectionOutOfRange;
            out.detail = "the entry point RVA " + hex_of(image_entry_rva) +
                         " is not in an executable section";
            return out;
        }
    }

    // No two of the regions this load will record may overlap.
    //
    // The address space refuses overlapping records, but a refusal from
    // there is reported as a conflict with the caller's space and this is a
    // fact about the file: the image's own sections overlap, or a section
    // starts inside the headers. Refusing it here means the message names
    // the file and the header check upstream is not needed, and it also
    // means the batch handed to record_batch() is already known to be
    // internally disjoint.
    //
    // The sections are sorted by address once, so the check is the same
    // adjacent comparison the address space uses rather than a quadratic
    // scan. The sort is on a copy of the indices, so the placements vector
    // keeps the file's order for the report.
    //
    // A section that starts at an address below the headers' end overlaps
    // them, and that is checked by comparing each section's start against
    // headers_size. A section with VirtualAddress 0 -- which a malformed
    // image can declare, and the fuzzer produced one -- lands there and is
    // refused, which is the right answer because the headers occupy that
    // address.
    {
        std::vector<std::size_t> order;
        order.reserve(placements.size());
        for (std::size_t i = 0; i < placements.size(); ++i) {
            order.push_back(i);
        }
        std::sort(order.begin(), order.end(),
                  [&placements](std::size_t a, std::size_t b) {
                      return placements[a].section->virtual_address <
                             placements[b].section->virtual_address;
                  });
        std::uint64_t furthest_end = headers_size;
        for (const std::size_t i : order) {
            const Placement& p = placements[i];
            const std::uint64_t start = p.section->virtual_address;
            if (start < furthest_end) {
                out.error = LoadError::SectionOutOfRange;
                out.detail = "section " + p.section->name +
                             " at RVA " + hex_of(start) +
                             " overlaps the headers or an earlier section";
                return out;
            }
            furthest_end = start + p.mem_size;
        }
    }

    // -------------------------------------------------------- relocations
    //
    // Walked before anything is recorded, for the reason stated above: this
    // is the pass that can refuse an image, and it only reads the file.

    LoadedModule module;
    module.base = base;
    module.size = image_size;
    module.entry_va = base + image.entry_rva();

    if (needs_relocation) {
        const std::uint64_t reloc_end =
            image.reloc_rva() + image.reloc_size();
        std::uint64_t cursor = image.reloc_rva();

        while (cursor + 8 <= reloc_end) {
            // Each block is a page address and a block size, followed by
            // 16-bit entries. The size covers the header, so a block whose
            // size is less than its header is a block that would loop
            // forever; refusing it is what keeps the walk bounded.
            std::uint64_t block_off = 0;
            if (!image.to_file_offset(cursor, block_off) ||
                block_off + 8 > bytes.size()) {
                out.error = LoadError::BadRelocation;
                out.detail = "a relocation block header is outside the file";
                return out;
            }
            std::uint32_t page_rva = 0;
            std::uint32_t block_size = 0;
            (void)read_u32(bytes, static_cast<std::size_t>(block_off),
                           page_rva);
            (void)read_u32(bytes, static_cast<std::size_t>(block_off) + 4,
                           block_size);
            if (block_size < 8) {
                out.error = LoadError::BadRelocation;
                out.detail = "a relocation block declares a size smaller "
                             "than its own header";
                return out;
            }
            ++module.relocation_blocks;

            const std::uint32_t entries = (block_size - 8) / 2;
            for (std::uint32_t i = 0; i < entries; ++i) {
                std::uint16_t entry = 0;
                const std::uint64_t entry_rva = cursor + 8 + 2ULL * i;
                std::uint64_t entry_off = 0;
                if (!image.to_file_offset(entry_rva, entry_off) ||
                    !read_u16(bytes, static_cast<std::size_t>(entry_off),
                              entry)) {
                    out.error = LoadError::BadRelocation;
                    out.detail = "a relocation entry is outside the file";
                    return out;
                }
                const std::uint16_t type = entry >> 12;
                const std::uint16_t offset = entry & 0x0FFFU;
                if (type == kRelBasedAbsolute) {
                    // Padding, not a relocation. Applying it would write
                    // zero over whatever is there.
                    continue;
                }
                const std::uint64_t rva = page_rva + offset;
                if (rva > image_size - 8 && type == kRelBasedDir64) {
                    out.error = LoadError::BadRelocation;
                    out.detail = "a DIR64 relocation points outside the image";
                    return out;
                }
                switch (type) {
                case kRelBasedDir64:
                    module.relocations_applied += 1;
                    break;
                case kRelBasedHigh:
                case kRelBasedLow:
                case kRelBasedHighLow:
                case kRelBasedHighAdj:
                    // The 32-bit forms. They exist in 64-bit images for
                    // fields the linker knew would stay in the low 4 GiB,
                    // and a runtime that ignored them would leave those
                    // fields pointing at the old base. Counted and applied
                    // by the mapping layer with the rest.
                    module.relocations_applied += 1;
                    break;
                default:
                    out.error = LoadError::BadRelocation;
                    out.detail = "relocation type " +
                                 std::to_string(type) +
                                 " is not one this runtime applies";
                    return out;
                }
            }
            cursor += block_size;
        }
    }

    // ------------------------------------------------------------- mapping
    //
    // Reached only when every check above has held. From here on nothing
    // refuses except the address space itself reporting an overlap with a
    // region that was already there before this call, which is a fact about
    // the caller's space rather than about the file.

    // The whole image is recorded in one operation: the headers, then one
    // region per section, in that order.
    //
    // It is one operation and not a loop of record() calls because record()
    // commits as it goes, and this function's contract says a load that is
    // not ok leaves the space unchanged. A file whose fourth section
    // overlaps its first -- or overlaps a region the caller had already
    // mapped -- is refused at the fourth call, by which point the headers
    // and three sections are in the map. The fuzzer found exactly that: the
    // first sample it produced recorded the headers and then refused a
    // section, and the space kept the headers.
    //
    // record_batch() checks every candidate against the existing map and
    // against the others before inserting any of them, so the state after a
    // refusal is the state before the call.
    //
    // The headers go first because the order is what the failure message
    // names when it is the headers that could not be placed, and because a
    // reader of the file reaches them first.
    std::vector<AddressSpace::Candidate> batch;
    batch.reserve(placements.size() + 1);
    {
        // The whole header area is recorded rather than only the parsed
        // part, because a program can read the DOS stub and the section
        // table and a region that stopped at the parsed fields would report
        // a fault in a page that is really there.
        AddressSpace::Candidate h;
        h.base = base;
        h.size = headers_size;
        h.protection = PageProtection::ReadOnly;
        h.kind = RegionKind::Image;
        h.section = ".headers";
        h.section_index = 0;
        batch.push_back(std::move(h));
    }
    for (const Placement& p : placements) {
        AddressSpace::Candidate c;
        c.base = p.va;
        c.size = p.mem_size;
        c.protection = PageProtection::ReadOnly;
        // The order of these tests is Windows' own precedence: write-implies-
        // read and execute-implies-read, and a section that is both
        // executable and writable gets the combined value rather than one
        // of the two. Reading them in the other order produces a
        // read-execute section from a read-write-execute one.
        const bool w = p.section->writable();
        const bool x = p.section->executable();
        if (w && x) {
            c.protection = PageProtection::ExecuteReadWrite;
        } else if (x) {
            c.protection = PageProtection::ExecuteRead;
        } else if (w) {
            c.protection = PageProtection::ReadWrite;
        }
        c.kind = RegionKind::Image;
        c.section = p.section->name;
        c.section_index = p.index;
        batch.push_back(std::move(c));
    }

    const auto rec = space.record_batch(batch);
    if (!rec.ok()) {
        // A conflict is a fact about the caller's space and not about the
        // file, which is why it is a different error from the ones the plan
        // above produces. The batch is all-or-nothing, so there is nothing
        // to undo here.
        out.error = LoadError::AddressConflict;
        out.detail = "the image could not be recorded: " +
                     std::string(status_name(rec.status));
        return out;
    }

    // The image is recorded in the space before the contents are placed, so
    // that the placement is a change to a map that already exists. A caller
    // that abandons the load between the two sees a map describing an image
    // with no bytes in it, which is a state a reader can recognise; the
    // alternative order leaves bytes at addresses the map does not mention.
    emit_note(context.events, "image mapped at 0x" + std::to_string(base) +
                                  " with " +
                                  std::to_string(placements.size()) +
                                  " sections");

    for (const Placement& p : placements) {
        const Region* r = space.find(p.va);
        if (r != nullptr) {
            emit_mapping(context.events, *r);
        }
    }

    if (needs_relocation) {
        // The delta is base minus preferred base, as a byte offset.
        //
        // It is computed in unsigned arithmetic and reinterpreted, not by
        // casting each address to int64_t and subtracting. Both operands are
        // uint64_t taken from a caller and from the file, and the file's
        // preferred base can be any 64-bit value; the cast of such a value
        // to int64_t is implementation-defined in the negative half, and the
        // subtraction of the two is signed overflow -- undefined behaviour,
        // which UBSan reported on the loader fuzz harness. Unsigned
        // subtraction of two 64-bit values is total: it wraps modulo 2^64,
        // and the two's-complement reinterpretation of that result is
        // precisely the signed byte offset. No branch is needed and none is
        // UB.
        const std::uint64_t delta = base - image.image_base();
        if (context.events != nullptr) {
            auto& e = context.events->begin(obs::EventKind::Note);
            e.add("text", std::string_view{"relocations applied"});
            e.add_hex("delta", delta);
            e.add("blocks", static_cast<std::uint64_t>(module.relocation_blocks));
            e.add("entries", module.relocations_applied);
            context.events->commit();
        }
    }

    // ------------------------------------------------------ import lookup

    // The import directory.
    //
    // Each descriptor names a DLL, an array of name thunks, and an array of
    // address thunks the loader fills in. The two arrays start out holding
    // the same values -- an RVA to a hint/name entry -- and it is the
    // second one that the program reads at runtime. Keeping them distinct
    // is what makes a second load of the same image idempotent: writing
    // resolved addresses into the name array would make the next reader see
    // an address where it expected a name.
    const auto& sections = image.sections();
    std::uint64_t import_rva = 0;
    std::uint32_t import_size = 0;
    {
        // The directory array is read from the raw optional header, which
        // the parser exposes as a size but not as an offset. The offset is
        // the fixed prefix's length, which differs between the two magic
        // values, so the pointer arithmetic is done here where the constant
        // that names it lives.
        const std::size_t dirs_off =
            image.is_pe32_plus() ? kDirsOffset64 : kDirsOffset32;
        const std::size_t import_entry =
            dirs_off + 8 * static_cast<std::size_t>(kDirImport);
        std::uint64_t opt_off = 0;
        // The optional header's file offset is the COFF header's plus its
        // size, and the parser records the latter. Recovering the former
        // needs e_lfanew, which is at 0x3C of the DOS header, so it is read
        // from the file rather than guessed.
        std::uint32_t lfanew = 0;
        if (read_u32(bytes, 0x3C, lfanew)) {
            opt_off = static_cast<std::uint64_t>(lfanew) + 4U + 20U;
        }
        // The order is an RVA and then a size, which is the opposite of
        // what the field names suggest to a reader who is thinking of the
        // table as (size, address). Reading them the other way round
        // produces an RVA that is really the table's size -- a small
        // number -- and a walk at that address finds zeros and reports no
        // imports, so the file loads and the report is silently empty.
        std::uint32_t rva32 = 0;
        if (opt_off != 0 &&
            read_u32(bytes, static_cast<std::size_t>(opt_off + import_entry),
                     rva32) &&
            read_u32(bytes,
                     static_cast<std::size_t>(opt_off + import_entry + 4),
                     import_size)) {
            import_rva = rva32;
        }
    }

    if (import_rva != 0 && import_size != 0) {
        const std::uint64_t import_end = import_rva + import_size;
        std::uint64_t desc_rva = import_rva;
        // The descriptor array is terminated by an all-zero entry, and the
        // directory's own size is the other bound. Both are honoured: a
        // directory that claims more descriptors than it has is a file that
        // would otherwise be walked into whatever follows.
        while (desc_rva + 20 <= import_end) {
            std::uint64_t desc_off = 0;
            if (!image.to_file_offset(desc_rva, desc_off) ||
                desc_off + 20 > bytes.size()) {
                break;
            }
            std::uint32_t name_rva = 0;
            std::uint32_t iat_rva = 0;
            std::uint32_t thunk_rva = 0;
            (void)read_u32(bytes, static_cast<std::size_t>(desc_off + 12),
                           name_rva);
            (void)read_u32(bytes, static_cast<std::size_t>(desc_off + 16),
                           iat_rva);
            (void)read_u32(bytes, static_cast<std::size_t>(desc_off), thunk_rva);

            if (name_rva == 0 && iat_rva == 0 && thunk_rva == 0) {
                break;
            }

            std::string dll;
            if (!read_rva_name(image, bytes, name_rva, dll)) {
                break;
            }

            // The name thunk array is the one that still holds names. It is
            // absent in an image that was already bound, in which case the
            // IAT array holds the names -- a real and legal layout.
            std::uint64_t names_cursor = thunk_rva != 0 ? thunk_rva : iat_rva;
            std::uint64_t iat_cursor = iat_rva != 0 ? iat_rva : thunk_rva;

            // A bound, because a malformed thunk array has no terminator
            // and the walk would run into the next section. The limit is
            // the size of the image in entries; an image with more imports
            // than it has bytes is not an image.
            const std::uint64_t max_entries = image_size / 8;
            for (std::uint64_t i = 0; i < max_entries; ++i) {
                std::uint64_t entry_off = 0;
                if (!image.to_file_offset(names_cursor + 8 * i,
                                          entry_off) ||
                    entry_off + 8 > bytes.size()) {
                    break;
                }
                std::uint64_t value = 0;
                (void)read_u64(bytes, static_cast<std::size_t>(entry_off),
                               value);
                if (value == 0) {
                    break;
                }

                ResolvedImport imp;
                imp.dll = dll;
                imp.iat_va = base + iat_cursor + 8 * i;
                constexpr std::uint64_t kOrdinalFlag = 0x8000000000000000ULL;
                if ((value & kOrdinalFlag) != 0) {
                    imp.by_ordinal = true;
                    imp.name = "#" + std::to_string(value & 0xFFFFU);
                } else if (!read_rva_name(image, bytes, value + 2, imp.name)) {
                    // A hint/name entry is a 16-bit hint followed by the
                    // name, so the name starts two bytes in. A name that
                    // will not read ends the array rather than the load:
                    // the entries before it are real imports and dropping
                    // them would understate what the image needs.
                    break;
                }

                if (context.resolve != nullptr) {
                    std::uint16_t ordinal = 0;
                    if (imp.by_ordinal) {
                        ordinal = static_cast<std::uint16_t>(
                            value & 0xFFFFU);
                    }
                    imp.target_va = context.resolve(
                        context.resolver_state, dll, imp.name, ordinal,
                        imp.by_ordinal);
                    imp.resolved = imp.target_va != 0;
                }

                if (context.events != nullptr) {
                    auto& e = context.events->begin(obs::EventKind::Import);
                    e.add("dll", dll);
                    e.add("name", imp.name);
                    e.add_hex("iat", imp.iat_va);
                    e.add_hex("target", imp.target_va);
                    e.add("resolved", imp.resolved);
                    e.add("by_ordinal", imp.by_ordinal);
                    context.events->commit();
                }

                module.imports.push_back(std::move(imp));
            }

            desc_rva += 20;
        }
    }

    // ----------------------------------------------------------------- TLS

    {
        std::size_t dirs_off = image.is_pe32_plus() ? kDirsOffset64
                                                    : kDirsOffset32;
        std::size_t tls_entry = dirs_off + 8 * static_cast<std::size_t>(kDirTls);
        std::uint32_t lfanew = 0;
        std::uint64_t opt_off = 0;
        if (read_u32(bytes, 0x3C, lfanew)) {
            opt_off = static_cast<std::uint64_t>(lfanew) + 4U + 20U;
        }
        std::uint32_t tls_rva = 0;
        if (opt_off != 0 &&
            read_u32(bytes,
                     static_cast<std::size_t>(opt_off + tls_entry), tls_rva) &&
            tls_rva != 0) {
            // The directory's first two fields are the start and end of the
            // template that has to be copied into each thread's TLS block.
            // Only the size is taken here; the copy happens at thread
            // creation, which is a later milestone and a different layer.
            std::uint64_t tls_off = 0;
            std::uint32_t start = 0;
            std::uint32_t end = 0;
            if (image.to_file_offset(tls_rva, tls_off) &&
                read_u32(bytes, static_cast<std::size_t>(tls_off), start) &&
                read_u32(bytes, static_cast<std::size_t>(tls_off) + 4, end) &&
                end >= start) {
                module.tls_directory_va = base + tls_rva;
                module.tls_template_size = end - start;
                if (context.events != nullptr) {
                    auto& e = context.events->begin(obs::EventKind::Note);
                    e.add("text", std::string_view{"tls directory"});
                    e.add_hex("directory", module.tls_directory_va);
                    e.add_hex("template_size", module.tls_template_size);
                    context.events->commit();
                }
            }
        }
    }

    // -------------------------------------------------------------- result

    // What this function does not do, and why: it does not copy the section
    // contents into memory and it does not write the resolved import
    // addresses into the IAT. Both of those need writable mapped memory,
    // which belongs to the layer that owns the host mapping rather than to
    // the layer that decides what goes where. The division is what lets
    // `occ check` load an image -- header parse, section placement,
    // relocation count, import walk -- without mapping a byte, and it is
    // why this function can report an image's shape without being able to
    // run it.
    (void)sections;

    out.ok = true;
    out.error = LoadError::None;
    out.module = std::move(module);
    return out;
}

} // namespace occ::runtime

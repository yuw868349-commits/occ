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

// ------------------------------------------------------- writing the memory

// Little-endian stores at an address in mapped memory.
//
// These have no bounds check, which is the thing a reader is most likely to
// object to, so the reason is worth one paragraph. The address is derived
// from an RVA that the placement plan already checked is inside the image,
// and the image's regions are the only things this process can make, so the
// store lands in one of them. A check here would be a second place where the
// same question is answered, and it would answer it with less information:
// the caller's check is against the map, which is the authority, while a
// check here would be against the arithmetic.
//
// The value is written through a byte pointer rather than a reinterpret_cast
// to a wider type because the address is only 4-byte or 8-byte aligned if
// the relocation says so, and a store through a misaligned wide pointer is
// undefined even on x86 where it works. The byte loop has no such
// requirement and the cost is four or eight stores on a path that runs tens
// of thousands of times per image.
void store_u16(std::uint64_t va, std::uint16_t v) noexcept {
    auto* p = reinterpret_cast<std::uint8_t*>(va);
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
}

void store_u32(std::uint64_t va, std::uint32_t v) noexcept {
    auto* p = reinterpret_cast<std::uint8_t*>(va);
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
    p[2] = static_cast<std::uint8_t>(v >> 16);
    p[3] = static_cast<std::uint8_t>(v >> 24);
}

void store_u64(std::uint64_t va, std::uint64_t v) noexcept {
    store_u32(va, static_cast<std::uint32_t>(v));
    store_u32(va + 4, static_cast<std::uint32_t>(v >> 32));
}

// What went wrong when a relocation could not be written.
struct RelocFailure {
    bool failed = false;
    std::uint64_t rva = 0;
    const char* what = "";
};

// Reads a 16-bit field out of mapped memory.
//
// Byte at a time for the reason the loaders below do their arithmetic in a
// wider type and store back narrow: the address is only guaranteed to be
// aligned to whatever the linker emitted, and a narrow load at an odd address
// is a fault on some architectures and undefined on all of them.
[[nodiscard]] std::uint16_t load_u16_at(std::uint64_t va) noexcept {
    const auto* p = reinterpret_cast<const std::uint8_t*>(va);
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[0]) |
                                   static_cast<std::uint16_t>(
                                       static_cast<std::uint16_t>(p[1]) << 8)));
}

// Applies one relocation of the given type at `va`.
//
// The five types the format defines, each writing the form the linker emitted
// rather than a normalized 64-bit form. A runtime that wrote all of them as
// DIR64 would corrupt every 32-bit field in the image, and one that wrote them
// all as 32-bit would truncate a real pointer; the type is the whole of what
// distinguishes them.
//
// The 16-bit types -- HIGH, LOW and HIGHADJ -- are 16-bit types. They
// relocate a *half* of an address, on the machines whose instructions could
// not hold a 32-bit absolute address in one operand (MIPS, Alpha, IA64's
// predecessors). Reading and writing 32 bits at those addresses corrupts the
// neighbouring field, and the arithmetic below is the Windows Research
// Kernel's, which is the authority: the format description in the PE
// specification is a sentence long and does not say what the arithmetic is.
//
// `adjustment` carries HIGHADJ's second value, which lives in the *next
// relocation entry* rather than in the image. The caller reads it and passes
// it here because the entry walk is where the file is being read; see
// HIGHADJ below for why it cannot come from the image.
[[nodiscard]] RelocFailure apply_one(std::uint64_t va, std::uint16_t type,
                                     std::uint64_t delta,
                                     std::int16_t adjustment) noexcept {
    RelocFailure f;
    switch (type) {
    case kRelBasedHigh: {
        // The 16-bit field is the high half of a 32-bit address. The low half
        // is not in this entry, so the arithmetic has to pretend the field is
        // the whole address, shift the field up to where it belongs, add the
        // delta, and shift back down -- which discards exactly the delta's
        // low 16 bits and keeps the field's own low half out of the result.
        //
        // The shifts are on a signed 32-bit value because the sum is meant to
        // be interpreted as one: a field of 0xFFFF shifted up is negative,
        // and an unsigned shift would bring zeros into the top half and make
        // the addition wrap differently. This is `LONG Temp` in the kernel's
        // LdrProcessRelocationBlock.
        std::int32_t temp = static_cast<std::int32_t>(
                                static_cast<std::uint32_t>(load_u16_at(va))
                                << 16);
        temp += static_cast<std::int32_t>(static_cast<std::uint32_t>(delta));
        store_u16(va, static_cast<std::uint16_t>(temp >> 16));
        return f;
    }
    case kRelBasedLow: {
        // The 16-bit field is the low half of an address. It moves by the
        // whole delta and wraps within its own 16 bits, which is what the
        // field's width means -- the machine reading it sign-extends, so the
        // wrap is not an accident but the encoding.
        //
        // Wine skips this in 64-bit builds. That is a defensible reading of
        // "no amd64 linker emits LOW", and this runtime does not emit relocs
        // either -- but skipping it here would be a claim about what a file
        // may contain rather than about what the type means, and a loader
        // that refuses a file it could place is not more faithful than one
        // that places it wrong. The kernel applies it unconditionally, and so
        // does this.
        const std::uint16_t field = load_u16_at(va);
        store_u16(va, static_cast<std::uint16_t>(
                           static_cast<std::uint32_t>(field) +
                           static_cast<std::uint32_t>(delta)));
        return f;
    }
    case kRelBasedHighLow: {
        // A 32-bit field moves by the whole delta, with wraparound. The delta
        // is truncated to 32 bits first because the field is 32 bits: adding a
        // 64-bit delta to a 32-bit field would be a different operation, and
        // a linker that emitted a HIGHLOW in a 64-bit image emitted it
        // against an address it knew would stay in the low 4 GiB.
        std::uint32_t v = 0;
        const auto* p = reinterpret_cast<const std::uint8_t*>(va);
        v = static_cast<std::uint32_t>(p[0]) |
            (static_cast<std::uint32_t>(p[1]) << 8) |
            (static_cast<std::uint32_t>(p[2]) << 16) |
            (static_cast<std::uint32_t>(p[3]) << 24);
        v += static_cast<std::uint32_t>(delta);
        store_u32(va, v);
        return f;
    }
    case kRelBasedHighAdj: {
        // The one relocation that is not a relocation of the address it
        // names, and the only one whose correctness depends on a value that
        // is not in the image at all.
        //
        // A MIPS immediate is a signed 16-bit field, and an address assembled
        // from two of them needs the high half adjusted when the low half is
        // negative: 0x0000_7FFF plus a base is 0x0000_8000-ish, and the
        // carry has to go somewhere. HIGHADJ is how the linker says where.
        //
        // The kernel's arithmetic, which is the whole of the specification
        // that matters here:
        //
        //     Temp = field << 16;      // the 16-bit high half, as an address
        //     Temp += adjustment;      // the carry the linker recorded
        //     Temp += Diff;            // this load's delta
        //     Temp += 0x8000;          // rounding
        //     field = Temp >> 16;
        //
        // Three parts of that are load-bearing and none is decoration.
        //
        // The adjustment comes from the *next relocation entry*, not from the
        // image. An entry is 16 bits of type and offset with no room for a
        // value, so the adjustment is stored as a second entry whose own
        // offset field is meaningless and whose 16 bits are the number. That
        // is why this entry consumes two slots and why the caller has to
        // read it -- and it is why an implementation that reads the
        // adjustment out of the bytes *after* the field in the image is
        // reading whatever that code happens to be: on the machines that emit
        // HIGHADJ, the instruction at the relocated address is a pair of
        // immediates, so the bytes after the high half are the low half --
        // the wrong number entirely.
        //
        // The adjustment is signed. The linker emits the carry as a negative
        // number when the low half was negative, and reading it as unsigned
        // turns a subtraction of 8 into an addition of 65528.
        //
        // The 0x8000 is a rounding term and not an offset. The low half is
        // signed, so adding it to the high half alone is ambiguous at the
        // halfway point; the kernel adds half of the low half's range and
        // then discards the low half by shifting, which rounds the total
        // toward the value the assembler's sign extension would have
        // produced. An implementation that omits it is off by one on every
        // field whose low half is in [0x0000, 0x8000) -- a third of them --
        // and only on those, which is the worst possible way to be wrong.
        //
        // There is no second-entry bookkeeping here and no "already applied"
        // flag: the kernel checks a bit in the *offset* field
        // (LDRP_RELOCATION_FINAL) because the Windows loader can be asked to
        // relocate an image twice and the second pass would add the delta
        // again. This loader relocates exactly once per load, from the file's
        // bytes, and places the result at an address the caller was given --
        // there is no second pass to defend against, and adding a bit to an
        // entry would mutate the file's image for a caller that did not ask
        // for that.
        std::int32_t temp = static_cast<std::int32_t>(
                                static_cast<std::uint32_t>(load_u16_at(va))
                                << 16);
        temp += static_cast<std::int32_t>(adjustment);
        temp += static_cast<std::int32_t>(static_cast<std::uint32_t>(delta));
        temp += 0x8000;
        store_u16(va, static_cast<std::uint16_t>(temp >> 16));
        return f;
    }
    case kRelBasedDir64: {
        // The only type this runtime sees in practice on amd64, and the only
        // one whose field is as wide as the address it holds.
        std::uint64_t out = 0;
        for (int i = 7; i >= 0; --i) {
            out = (out << 8) |
                  static_cast<std::uint64_t>(
                      reinterpret_cast<const std::uint8_t*>(va)[i]);
        }
        out += delta;
        store_u64(va, out);
        return f;
    }
    default:
        f.failed = true;
        f.rva = va;
        f.what = "a relocation type this runtime does not apply";
        return f;
    }
}

// Undoes a placement: unmaps every region the batch recorded.
//
// The undo is by base address, from the batch rather than from the space,
// because the space may have been given more regions by a later step of a
// load that is not this one. Reverse order, so that a partial undo leaves
// the regions that were mapped first in the state that a reader would expect
// to still be there -- and because for an image whose sections were adjacent,
// the highest section is the one a reader looks at first.
//
// A failure here is not reported over the failure that caused it. A munmap
// of an address this function just mapped cannot fail on a sane kernel, and
// a caller that was told "the load failed" cannot act differently on the
// second failure, so surfacing it would replace a message that names the
// cause with one that names a consequence.
void rollback_placement(Mapper& m,
                        const std::vector<AddressSpace::Candidate>& batch) noexcept {
    for (auto it = batch.rbegin(); it != batch.rend(); ++it) {
        (void)m.unmap(it->base);
    }
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
    case LoadError::MappingRefused: return "mapping_refused";
    case LoadError::RelocationNotWritable: return "relocation_not_writable";
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
        out.detail = "the image asked for base " +
                     hex_of(image.image_base()) +
                     " and has no relocation table, so it cannot be placed "
                     "at " + hex_of(base);
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

                // HIGHADJ's adjustment is the next entry, and this entry
                // therefore covers two slots. Skip the second here so that
                // the walk below counts one relocation rather than two -- and
                // so that a block whose HIGHADJ is its last entry, with no
                // adjustment slot after it, is refused here, before anything
                // is mapped. That is the check this pass exists for; the
                // adjustment's *value* is the write pass's business, and
                // reading it here would mean holding a number this pass has
                // no use for.
                //
                // The adjustment is the entry's own 16 bits, not its offset
                // field: the linker spends a whole entry on a number that
                // does not fit in an entry's 12-bit offset, and the type
                // nibble of that second entry says nothing.
                if (type == kRelBasedHighAdj) {
                    if (i + 1 >= entries) {
                        out.error = LoadError::BadRelocation;
                        out.detail = "a HIGHADJ relocation is the last entry "
                                     "in its block and has no adjustment slot";
                        return out;
                    }
                    ++i;
                }

                switch (type) {
                case kRelBasedDir64:
                    module.relocations_applied += 1;
                    break;
                case kRelBasedHigh:
                case kRelBasedLow:
                case kRelBasedHighLow:
                case kRelBasedHighAdj:
                    // The 16- and 32-bit forms. They exist in 64-bit images
                    // for fields the linker knew would stay in the low 4 GiB,
                    // or -- for the 16-bit ones -- on the machines whose
                    // instructions held half an address each. A runtime that
                    // ignored them would leave those fields pointing at the
                    // old base.
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
        //
        // The value is computed once and used twice below -- once for the
        // recorded region and once for the final protection after the
        // placement -- because a load that recorded one protection and
        // applied another would be a map that lies about its own memory, and
        // the whole point of computing it from the section's flags is that
        // the two readings cannot disagree.
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

    // The two modes diverge here, and the divergence is one line wide.
    //
    // Without a mapper the call is record_batch and nothing else, which is
    // the whole of what this function used to do. With one, the same
    // candidates go through map_batch, which maps and records as one
    // operation, and then the bytes are written.
    //
    // What is *not* different is that the plan above already ran. An image
    // that would be refused by the window check, by the overlap check, by
    // the relocation walk or by the entry-point check is refused before
    // either call, so adding a mapper cannot turn a refusal into a
    // placement. It can only add new failures of its own -- the kernel
    // refusing an address the plan accepted, which is what MappingRefused is
    // for.
    Mapper* placement = context.placement;

    if (placement == nullptr) {
        const auto rec = space.record_batch(batch);
        if (!rec.ok()) {
            // A conflict is a fact about the caller's space and not about
            // the file, which is why it is a different error from the ones
            // the plan above produces. The batch is all-or-nothing, so there
            // is nothing to undo here.
            out.error = LoadError::AddressConflict;
            out.detail = "the image could not be recorded: " +
                         std::string(status_name(rec.status));
            return out;
        }
    } else {
        // The same batch, through the mapper.
        //
        // Every region goes in as read-write, whatever the section's flags
        // say, and the flags are applied afterwards. The alternative --
        // mapping each section with its final protection -- cannot work:
        // a relocation routinely names an address in a read-only section,
        // because a read-only section is full of pointers to the image's own
        // functions and those pointers are exactly what a relocation
        // rewrites. A loader that mapped the final protections first would
        // fault on its own relocation pass, on a perfectly ordinary image.
        //
        // Windows avoids the problem by mapping the whole image committed
        // and read-write, writing the relocations, and then protecting each
        // section, and the order here is that order. The window in which a
        // read-only section is writable is the same window Windows has, and
        // it is why the final protect is a separate step that is checked
        // rather than assumed: an image that is placed and whose protection
        // was never applied is an image whose .text is writable, and a
        // runtime that reports success there is reporting something false.
        std::vector<Mapper::Candidate> to_map;
        to_map.reserve(batch.size());
        for (AddressSpace::Candidate& c : batch) {
            to_map.push_back(Mapper::Candidate{c.base, c.size,
                                                PageProtection::ReadWrite,
                                                c.kind, c.section,
                                                c.section_index});
        }

        const Result<std::uint64_t> mapped = placement->map_batch(to_map);
        if (!mapped.ok()) {
            // map_batch is all-or-nothing in both directions: it unmapped
            // everything it had mapped before reporting this, so there is
            // nothing to undo here and the space is as it was.
            out.error = (mapped.status == Status::ConflictingAddresses)
                            ? LoadError::AddressConflict
                            : LoadError::MappingRefused;
            out.detail = "the image could not be mapped: " +
                         std::string(status_name(mapped.status));
            if (placement->last_failure().error != 0) {
                out.detail += " (errno " +
                              std::to_string(placement->last_failure().error) +
                              ")";
            }
            return out;
        }
    }

    // The image is recorded in the space before the contents are placed, so
    // that the placement is a change to a map that already exists. A caller
    // that abandons the load between the two sees a map describing an image
    // with no bytes in it, which is a state a reader can recognise; the
    // alternative order leaves bytes at addresses the map does not mention.
    emit_note(context.events, "image mapped at " + hex_of(base) +
                                  " with " +
                                  std::to_string(placements.size()) +
                                  " sections");

    for (const Placement& p : placements) {
        const Region* r = space.find(p.va);
        if (r != nullptr) {
            emit_mapping(context.events, *r);
        }
    }

    // ------------------------------------------------------------- contents
    //
    // The file's bytes, into the memory. Below the record, above the
    // relocations, and below the IAT -- the order the header of this file
    // gives and the order the operations require: a relocation rewrites a
    // value that has to be in memory, and the IAT holds addresses that have
    // to be relocated too if the image moved.

    if (placement != nullptr) {
        // The headers.
        //
        // Bounded by both the file and the region, because the region's size
        // is the parsed header size and the file can be shorter -- the
        // loader already handles that case for sections by dropping the
        // uncovered tail, and the headers need the same treatment rather
        // than a memcpy of a length the file may not have.
        {
            const Region* h = space.find(base);
            if (h == nullptr) {
                out.error = LoadError::AddressConflict;
                out.detail = "the header region was not recorded";
                rollback_placement(*placement, batch);
                return out;
            }
            const std::uint64_t copy =
                (headers_size < static_cast<std::uint64_t>(bytes.size()))
                    ? headers_size
                    : static_cast<std::uint64_t>(bytes.size());
            std::memcpy(reinterpret_cast<void*>(base), bytes.data(),
                        static_cast<std::size_t>(copy));
            // The part of the header region the file does not cover. The
            // mapping is anonymous and the kernel zeroes anonymous pages, so
            // this is already zero and the memset is not needed -- which is
            // worth stating because a reader looking for the zero fill will
            // not find one here, and the reason it is safe is that this
            // runtime maps anonymous memory and nothing else.
        }

        // The sections.
        for (const Placement& p : placements) {
            if (p.file_size != 0) {
                // Bounded by construction: the plan clamped file_size to
                // bytes.size() - raw_offset, so the read below is in range
                // by arithmetic rather than by a check here. The subtraction
                // is the reason the plan used that form.
                if (p.file_off > static_cast<std::uint64_t>(bytes.size()) ||
                    p.file_size >
                        static_cast<std::uint64_t>(bytes.size()) - p.file_off) {
                    out.error = LoadError::SectionOutOfRange;
                    out.detail = "section " + p.section->name +
                                 " names bytes outside the file";
                    rollback_placement(*placement, batch);
                    return out;
                }
                std::memcpy(reinterpret_cast<void*>(p.va),
                            bytes.data() + static_cast<std::size_t>(p.file_off),
                            static_cast<std::size_t>(p.file_size));
            }
            // The zero tail: a section whose virtual extent exceeds its raw
            // size. The mapping is anonymous and zero, so again there is
            // nothing to do, and the reason is the same one as above.
        }
    }

    // The delta is base minus preferred base, as a byte offset.
    //
    // It is computed in unsigned arithmetic and reinterpreted, not by casting
    // each address to int64_t and subtracting. Both operands are uint64_t
    // taken from a caller and from the file, and the file's preferred base
    // can be any 64-bit value; the cast of such a value to int64_t is
    // implementation-defined in the negative half, and the subtraction of the
    // two is signed overflow -- undefined behaviour, which UBSan reported on
    // the loader fuzz harness. Unsigned subtraction of two 64-bit values is
    // total: it wraps modulo 2^64, and the two's-complement reinterpretation
    // of that result is precisely the signed byte offset. No branch is
    // needed and none is UB.
    const std::uint64_t delta = base - image.image_base();

    if (needs_relocation && placement != nullptr) {
        // The second walk over the relocations, which writes them.
        //
        // The walk above is the one that can refuse, and it runs before
        // anything is mapped, so a file with a bad relocation never reaches
        // this point. This one therefore does not validate the block
        // structure -- every bound it would check was checked already, from
        // the same bytes, moments ago -- and does only the work that needs
        // memory to exist. Splitting it this way is what keeps the contract
        // that a refused load leaves nothing behind: all of the refusals are
        // in the first walk and none are in this one, so this walk cannot
        // fail halfway and leave a half-relocated image mapped.
        //
        // The one thing it does check is that each entry's address is
        // covered by a region, because the plan's check is against the
        // image's size and the image's size is not the set of addresses that
        // exist: a section's virtual extent is rounded up to a page, the
        // gap between two sections is not mapped at all, and a relocation
        // naming that gap is a file the plan accepted and this walk cannot
        // satisfy. That is what RelocationNotWritable is for.
        const std::uint64_t reloc_end = image.reloc_rva() + image.reloc_size();
        std::uint64_t walk = image.reloc_rva();

        while (walk + 8 <= reloc_end) {
            std::uint64_t block_off = 0;
            if (!image.to_file_offset(walk, block_off) ||
                block_off + 8 > bytes.size()) {
                // Unreachable given the walk above held on the same bytes.
                // Bounded anyway, because "unreachable" is a claim about the
                // past and this is a loop over a file.
                out.error = LoadError::BadRelocation;
                out.detail = "a relocation block header is outside the file";
                rollback_placement(*placement, batch);
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
                rollback_placement(*placement, batch);
                return out;
            }

            const std::uint32_t entries = (block_size - 8) / 2;
            for (std::uint32_t i = 0; i < entries; ++i) {
                std::uint16_t entry = 0;
                const std::uint64_t entry_rva = walk + 8 + 2ULL * i;
                std::uint64_t entry_off = 0;
                if (!image.to_file_offset(entry_rva, entry_off) ||
                    !read_u16(bytes, static_cast<std::size_t>(entry_off),
                              entry)) {
                    out.error = LoadError::BadRelocation;
                    out.detail = "a relocation entry is outside the file";
                    rollback_placement(*placement, batch);
                    return out;
                }
                const std::uint16_t type = entry >> 12;
                const std::uint16_t offset = entry & 0x0FFFU;
                if (type == kRelBasedAbsolute) {
                    continue;
                }

                // The same two-slot walk as the pass above, and for the same
                // reason: the adjustment is the next entry, and reading it
                // here rather than in the plan would mean reading the file a
                // second time for a value the plan already had in hand. The
                // plan validated that the slot exists, so this cannot fail --
                // and it is still written as a read that reports failure,
                // because a loop over a file bounded by a claim about a past
                // walk is the shape that turns a wrong claim into a fault.
                std::int16_t adjustment = 0;
                if (type == kRelBasedHighAdj) {
                    std::uint64_t adj_off = 0;
                    if (!image.to_file_offset(walk + 8 + 2ULL * (i + 1),
                                             adj_off) ||
                        !read_u16(bytes, static_cast<std::size_t>(adj_off),
                                  entry)) {
                        out.error = LoadError::BadRelocation;
                        out.detail = "a HIGHADJ adjustment slot is outside "
                                     "the file";
                        rollback_placement(*placement, batch);
                        return out;
                    }
                    adjustment = static_cast<std::int16_t>(entry);
                    ++i;
                }

                const std::uint64_t rva = page_rva + offset;
                const std::uint64_t va = base + rva;

                // Coverage and writability, checked against the map rather
                // than against the image's arithmetic.
                //
                // The region's own containment test is the authority, and a
                // relocation into the gap between two sections is the case it
                // exists for: the plan's check is against SizeOfImage, and
                // the image's size includes gaps that were never mapped.
                //
                // The writability half cannot fail here -- every region went
                // in as read-write and nothing has protected any of them yet
                // -- and it is checked anyway, because the check costs one
                // comparison and the thing it guards is a write to a page
                // that would fault. A loader that arrived here with a
                // read-only region in its own map has a placement bug, and
                // it should report that rather than fault inside apply_one.
                const Region* target = space.find(va);
                if (target == nullptr) {
                    out.error = LoadError::RelocationNotWritable;
                    out.detail = "a relocation at RVA " + hex_of(rva) +
                                 " names an address the image does not cover";
                    rollback_placement(*placement, batch);
                    return out;
                }
                if ((protection_to_prot(target->protection) & PROT_WRITE) ==
                    0) {
                    out.error = LoadError::RelocationNotWritable;
                    out.detail = "a relocation at RVA " + hex_of(rva) +
                                 " names read-only memory";
                    rollback_placement(*placement, batch);
                    return out;
                }
                const RelocFailure applied =
                    apply_one(va, type, delta, adjustment);
                if (applied.failed) {
                    out.error = LoadError::BadRelocation;
                    out.detail = applied.what;
                    rollback_placement(*placement, batch);
                    return out;
                }
            }
            walk += block_size;
        }
    }

    if (needs_relocation) {
        if (context.events != nullptr) {
            auto& e = context.events->begin(obs::EventKind::Note);
            e.add("text", std::string_view{"relocations applied"});
            e.add_hex("delta", delta);
            e.add("blocks", static_cast<std::uint64_t>(module.relocation_blocks));
            e.add("entries", module.relocations_applied);
            e.add("written", placement != nullptr);
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

                // The IAT slot has to be inside something this load mapped,
                // and this is the check the loader did not have.
                //
                // The address above is computed from the file's RVA, and the
                // only thing bounded so far is that the *name* array could be
                // read. A malformed directory -- and the corpus has one --
                // therefore produces an IAT at an address nothing covers, and
                // the load reports success while handing the layer above a
                // module that will store its imports into unmapped memory. The
                // program faults on the store, before its first instruction,
                // which is the same shape of failure as an unmapped entry
                // point and is decided here for the same reason: this is the
                // only layer holding both the address and the map.
                //
                // What counts as covered is the batch that was just recorded,
                // not the section list alone. The headers are a mapped
                // region and an import table is allowed to live in them --
                // the parser resolves an RVA below SizeOfHeaders as a file
                // offset precisely because the format puts things there. A
                // check that walked the sections alone would refuse images
                // whose imports are real, and the unit tests hold exactly
                // such an image.
                //
                // An entry that fails this is skipped rather than refused.
                // The failure is local to one import: the other descriptors
                // in the array are real, and a load that refused the whole
                // image because one thunk pointed outside it would refuse
                // images that run. What the caller needs is the ones that
                // are real, with the ones that are not left out.
                bool slot_mapped = imp.iat_va >= base &&
                                   imp.iat_va - base < headers_size;
                for (const Placement& p : placements) {
                    if (slot_mapped) {
                        break;
                    }
                    if (imp.iat_va >= p.va &&
                        imp.iat_va - p.va < p.mem_size) {
                        slot_mapped = true;
                    }
                }
                if (!slot_mapped) {
                    continue;
                }

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

                // The IAT store.
                //
                // Written after the relocations and not before, and the order
                // is the whole reason this walk is where it is. The IAT of a
                // relocated image holds RVAs until the relocation pass runs
                // and absolute addresses after it, so an IAT written before
                // the relocations would be rewritten by them into
                // address+delta -- a value that is the address of an import
                // plus a displacement, which points into the middle of
                // whatever it names. The three stores therefore run in the
                // order the header of this file gives: bytes, then
                // relocations, then the IAT.
                //
                // Only when there was a resolver. Without one the slot keeps
                // the RVA the file held, which is what `occ check` wants to
                // see and what a caller that resolved nothing can act on: a
                // program that reads an unresolved IAT reads a small
                // number and faults, where a slot holding zero is a program
                // that reads null and calls it -- which is a different
                // failure with a different cause, and hiding it behind a
                // resolved-looking zero is the thing this avoids.
                if (placement != nullptr && imp.resolved) {
                    // The slot was checked for coverage above, which is the
                    // check that matters: this is a raw store at an address
                    // computed from a file's RVA, and the coverage test is
                    // what makes it safe. The test above walked placements
                    // rather than the space, and the space now holds
                    // exactly those regions plus the headers.
                    const Region* slot = space.find(imp.iat_va);
                    if (slot == nullptr) {
                        out.error = LoadError::RelocationNotWritable;
                        out.detail = "the IAT slot for " + dll + "!" +
                                     imp.name +
                                     " is not in a region this load made";
                        rollback_placement(*placement, batch);
                        return out;
                    }
                    if ((protection_to_prot(slot->protection) & PROT_WRITE) ==
                        0) {
                        out.error = LoadError::RelocationNotWritable;
                        out.detail = "the IAT slot for " + dll + "!" +
                                     imp.name + " is read-only";
                        rollback_placement(*placement, batch);
                        return out;
                    }
                    store_u64(imp.iat_va, imp.target_va);
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

    // --------------------------------------------------- final protections
    //
    // The last step of a placement, and the one that makes the image what the
    // file said it is.
    //
    // Everything above ran with every region writable, because a relocation
    // can name an address in any section including a read-only one, and
    // because the IAT is frequently in a section the linker marked
    // read-only. This step is what takes that permission away, and it is
    // separate rather than folded into the mapping for the reason stated at
    // the mapping: a read-only section full of pointers into the image is
    // ordinary, and a loader that applied the final protections first could
    // not write its own relocations.
    //
    // Windows has the same window and closes it the same way. The window is
    // why the result is checked rather than assumed: an image that is placed
    // and never protected is an image whose .text is writable, and a loader
    // that reported success there is reporting something false. The
    // check is the only thing between "the placement finished" and "the
    // image is loaded".
    if (placement != nullptr) {
        // Headers first, then the sections in the order they were placed.
        // The order is the order a failure message names them in, and the
        // headers are read-only in every image so this is the first place a
        // refusal could occur.
        for (const AddressSpace::Candidate& c : batch) {
            const Result<std::uint32_t> applied =
                placement->protect(c.base, c.protection);
            if (!applied.ok()) {
                out.error = LoadError::MappingRefused;
                out.detail = "the protection of " + c.section + " at 0x" +
                             hex_of(c.base) + " could not be set: " +
                             std::string(status_name(applied.status));
                rollback_placement(*placement, batch);
                return out;
            }
            if (context.events != nullptr) {
                const Region* r = space.find(c.base);
                if (r != nullptr) {
                    emit_mapping(context.events, *r);
                }
            }
        }
        // The counter the caller reads is now true of memory rather than of
        // a plan: every entry was written.
        for (ResolvedImport& imp : module.imports) {
            if (!imp.resolved) {
                continue;
            }
            imp.iat_written = true;
        }
    }

    // -------------------------------------------------------------- result

    (void)sections;

    out.ok = true;
    out.error = LoadError::None;
    out.module = std::move(module);
    return out;
}

// ------------------------------------------------------- placing with retry

std::uint64_t choose_base_below(void*, const parser::PeImage& image,
                                std::uint64_t failed_base,
                                std::uint32_t) noexcept {
    // The state and the attempt count are named in the header's declaration
    // and left unnamed here: a deterministic scan carries none and has no
    // use for either, since the only thing that stops it is the window.

    // The lowest base this policy will offer.
    //
    // A base is legal when it is at or above the window's floor, and the
    // lowest such base is the window's floor itself -- `kUserMin` already is
    // a whole number of granularies. The image's size does not enter into it.
    // The floor answers "how far down may I step", and the answer does not
    // depend on how big the thing being stepped down towards is; what the
    // size decides is whether the image fits *at all*, which is the second
    // half of this check.
    //
    // This used to be `kUserMin + round_up(size - 1, kGranularity)`, on the
    // reasoning that the floor is "the first base where base + size still
    // fits". That formula is not that base. It adds the image's own size to
    // the window floor, which puts the floor at least one granularity too
    // high for every image smaller than a granularity -- and it did so
    // silently, because a scan that stops one step early still returns a
    // plausible-looking answer. The cost was a policy that reported "no base
    // was free" about a space with a free base in it: the loop stepped down
    // to kUserMin, was refused by this comparison, and told the caller there
    // was nowhere left to try. A case in tests/test_placement.cpp found it,
    // and found it by computing the floor itself rather than by asking this
    // function -- the two disagreed by exactly one granularity.
    const std::uint64_t size = image.image_size();
    if (size == 0) {
        return 0;
    }
    const std::uint64_t lowest =
        AddressSpace::round_up(AddressSpace::kUserMin, AddressSpace::kGranularity);

    // Whether the image fits at that base. It does not for an image larger
    // than the window, and then there is nothing for this policy to offer at
    // any base -- every answer would be a base the loader refuses. Saying so
    // once here is cheaper than handing out sixty-four of them.
    if (size > AddressSpace::kUserMax - lowest) {
        return 0;
    }

    // The scan steps down by the granularity.
    //
    // Two bounds, and the second one is not decoration. `kUserMin` is the
    // bottom of the window a base has to be in, and the subtraction below
    // wraps: a base one granularity under it produces a number at the very
    // top of the address space, and the loop would then walk *up* through
    // the whole window handing out bases it had already tried. The guard is
    // on the *base* rather than on the result, because the two forms agree
    // everywhere except at the bottom -- `kUserMin` is exactly one
    // granularity, so the unguarded step at the floor lands on zero, which
    // is harmless, and only the step below it wraps.
    //
    // The upper guard is the other half of the same problem from the other
    // direction, and it was missing until a case in tests/test_placement.cpp
    // named a base below the window. A caller is entitled to name any
    // address at all, including one this runtime would never have produced,
    // and `failed_base` here is whatever the previous answer was. Once a
    // single unguarded step produces a value above `kUserMax`, every
    // subsequent step stays above it -- the subtraction makes the number
    // smaller, but "smaller" is still astronomically large -- and the policy
    // answered with 0xffffffffffc00000, a base the loader would then try to
    // map and fail on, having spent an attempt to learn what one comparison
    // could have said. A scan that cannot continue says so, whatever the
    // reason.
    if (failed_base < AddressSpace::kUserMin + AddressSpace::kGranularity ||
        failed_base > AddressSpace::kUserMax) {
        return 0;
    }
    const std::uint64_t next = failed_base - AddressSpace::kGranularity;

    if (next < lowest) {
        return 0;
    }
    return next;
}

LoadResult load_image_retrying(const parser::PeImage& image, ByteSpan bytes,
                               std::uint64_t preferred_base,
                               AddressSpace& space,
                               const LoadContext& context,
                               BaseRetry* report) noexcept {
    LoadResult out;
    BaseRetry local{};

    // The attempt cap. It exists so that a caller with a pathological space
    // gets an answer rather than a long wait, and 64 is far above any real
    // process: an image whose preferred base is taken is placed within two
    // or three tries, because the space above a base is not usually full.
    // The number is a constant rather than a field because a caller that
    // wants a different one wants a different policy, and `BaseChooser` is
    // how a caller supplies one.
    constexpr std::uint32_t kMaxAttempts = 64;

    std::uint64_t base = preferred_base;
    std::uint32_t attempts = 0;
    const BaseChooser choose =
        context.base_chooser != nullptr ? context.base_chooser
                                        : ::occ::runtime::choose_base_below;

    while (true) {
        ++attempts;
        const std::uint64_t tried_base =
            base != 0 ? base : image.image_base();
        local.tried.push_back(tried_base);

        out = load_image(image, bytes, base, space, context);

        if (out.ok) {
            local.error = LoadError::None;
            local.detail.clear();
            local.attempts = attempts;
            if (report != nullptr) {
                *report = std::move(local);
            }
            return out;
        }

        // Only a placement conflict is retried. Everything else is a fact
        // about the file or about this runtime, and no other base would
        // change it -- a bad relocation is bad at every address, and an
        // image this machine does not execute is not going to be executed by
        // moving it. Retrying them would replace a refusal that names the
        // problem with a refusal that names the wrong one.
        if (out.error != LoadError::AddressConflict) {
            local.error = out.error;
            local.detail = std::move(out.detail);
            local.attempts = attempts;
            if (report != nullptr) {
                *report = std::move(local);
            }
            return out;
        }

        if (attempts >= kMaxAttempts) {
            // The cap is reached rather than the space being full, and the
            // message says which, because "it tried 64 addresses" and "there
            // was nowhere to put it" call for different responses from the
            // person reading them.
            local.error = out.error;
            local.detail = "the image was still in the way after " +
                           std::to_string(attempts) + " bases";
            local.attempts = attempts;
            if (report != nullptr) {
                *report = std::move(local);
            }
            return out;
        }

        // The next base. A chooser that returns zero has run out, and that
        // is a fact about the space rather than about the image, so the
        // error stays AddressConflict and the detail says the search ended.
        //
        // It says so *in addition to* what the last attempt said, rather
        // than instead of it. Substituting the attempt's own detail here --
        // which is what an earlier version did, falling back to a sentence
        // about the search only when the attempt had nothing to say -- is
        // how a caller ends up reading "that address is taken" as the whole
        // story when the truth is "I have nowhere left to try", and those
        // two call for opposite responses: one looks for the module that
        // took the address, the other for a bigger space. An earlier
        // version of this file had the same defect in the form of four
        // details that spelled an address in decimal after a "0x".
        const std::uint64_t next =
            choose(context.base_chooser_state, image, tried_base, attempts);
        if (next == 0) {
            local.error = out.error;
            local.detail = "no base was free for the image";
            if (!out.detail.empty()) {
                local.detail += ": ";
                local.detail += out.detail;
            }
            local.attempts = attempts;
            if (report != nullptr) {
                *report = std::move(local);
            }
            return out;
        }

        // A chooser that returns a base that was already tried would spin.
        // The cap above would stop it, but the caller would get a report
        // saying it tried 64 addresses when it tried two, and the report is
        // the thing a person reads to decide what went wrong. Checked
        // against the bases actually used, not against a count, because a
        // chooser is free to skip and a count would refuse a legitimate
        // scan.
        bool already = false;
        for (const std::uint64_t b : local.tried) {
            if (b == next) {
                already = true;
                break;
            }
        }
        if (already) {
            local.error = out.error;
            local.detail = "the base chooser returned " +
                           hex_of(next) +
                           ", which had already been tried";
            local.attempts = attempts;
            if (report != nullptr) {
                *report = std::move(local);
            }
            return out;
        }

        base = next;
    }
}

} // namespace occ::runtime

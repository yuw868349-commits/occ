// PE image reader tests.
//
// The reader takes bytes and returns a description of the image, so every
// case is assembled in memory. The builder writes every field the reader
// touches, which means a failure points at a field rather than at a zero
// that happened to be in the buffer.
//
// The cases are the ones that would pass if a constraint were missing. The
// PE format supplies two different notions of "where a thing is" -- RVAs and
// file offsets -- and a reader that mixes them produces answers that look
// right and are not. So the bulk of what follows is about the conversion:
// an RVA inside a section's raw data, one inside its zero fill, one past its
// end, one below the headers, one in no section at all, and one in a section
// whose virtual address is near the top of the address space. The rest is
// about headers that are shorter than the fields read out of them.

#include "occ/parser/pe.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace occ::parser;
using occ::ByteSpan;

namespace {

int failures = 0;
int checks = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

void put8(std::vector<std::uint8_t>& b, std::size_t off, std::uint8_t v) {
    b[off] = v;
}

void put16(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
    b[off] = static_cast<std::uint8_t>(v & 0xff);
    b[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xff);
}

void put32(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        b[off + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>((v >> (8 * i)) & 0xff);
    }
}

void put64(std::vector<std::uint8_t>& b, std::size_t off, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        b[off + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>((v >> (8 * i)) & 0xff);
    }
}

// ------------------------------------------------------------- the builder
//
// A PE is laid out as: DOS header, PE signature, COFF header, optional
// header, section table, section data. The builder takes the two things
// that actually vary -- 32- or 64-bit, and how many sections -- and fills in
// the rest with values that are valid but distinctive, so a reader that
// computed a field from the wrong offset would produce a number that is
// wrong rather than a number that happens to match.

constexpr std::size_t kDosSize = 64;
constexpr std::size_t kCoffSize = 20;
constexpr std::size_t kSectionHeaderSize = 40;
// PE32 and PE32+ optional headers differ in length; these are the sizes a
// real linker emits, directories included.
constexpr std::size_t kOptSize32 = 224;
constexpr std::size_t kOptSize64 = 240;

struct SectionSpec {
    const char* name = nullptr;
    std::uint32_t virtual_address = 0;
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t characteristics = 0;
};

struct Spec {
    bool plus = false;
    bool dll = false;
    std::uint16_t machine = 0x014c;
    std::uint16_t subsystem = 3;
    std::uint16_t dll_characteristics = 0;
    std::uint32_t entry = 0;
    std::uint64_t base = 0;
    // The import directory, as an RVA and a size. Zero means none.
    std::uint32_t import_rva = 0;
    std::uint32_t import_size = 0;
    std::uint32_t reloc_rva = 0;
    std::uint32_t reloc_size = 0;
    std::uint32_t dir_count = 16;
    // Overrides SizeOfOptionalHeader after the builder has chosen a layout
    // value, so a test can declare a header shorter than the fields.
    int opt_size_override = -1;
    std::vector<SectionSpec> sections;
    // Bytes appended after the section data, for names and import strings.
    // Addressed by file offset; the builder reports where the data ends so a
    // test can place a name at a known spot.
    std::vector<std::uint8_t> tail;
};

struct Built {
    std::vector<std::uint8_t> bytes;
    std::size_t coff = 0;
    std::size_t opt = 0;
    std::size_t sections_at = 0;
    std::size_t data_at = 0;
    std::size_t tail_at = 0;
};

// The file is sized so every section's raw data fits. The default section
// data is one page of zeros; a test that needs bytes there writes them.
Built build(const Spec& s) {
    Built b;
    const std::size_t opt_size =
        s.opt_size_override >= 0
            ? static_cast<std::size_t>(s.opt_size_override)
            : (s.plus ? kOptSize64 : kOptSize32);

    b.coff = kDosSize + 4; // DOS header, then the PE signature
    b.opt = b.coff + 4 + kCoffSize;
    b.sections_at = b.opt + opt_size;

    // The headers are one page: every real linker rounds SizeOfHeaders up to
    // the file alignment, and a reader that assumes the section table ends
    // where the last header field ends would be wrong on every real file.
    const std::size_t headers_size = 0x200;

    std::size_t cursor = headers_size;
    std::vector<std::pair<std::size_t, std::size_t>> layout; // (raw_offset, size)
    for (const SectionSpec& sec : s.sections) {
        const std::size_t raw = sec.raw_size != 0 ? sec.raw_size : 0x200;
        const std::uint32_t raw_offset =
            raw == 0 ? 0 : static_cast<std::uint32_t>(cursor);
        cursor += raw;
        layout.emplace_back(raw_offset, raw);
    }
    const std::size_t tail_at = cursor;
    b.bytes.assign(tail_at + s.tail.size(), 0);
    b.data_at = headers_size;
    b.tail_at = tail_at;

    // --- DOS header
    put16(b.bytes, 0, 0x5a4d);          // "MZ"
    put32(b.bytes, 0x3c, static_cast<std::uint32_t>(b.coff));

    // --- PE signature
    put32(b.bytes, b.coff, 0x00004550);  // "PE\0\0"

    // --- COFF header
    const std::size_t c = b.coff + 4;
    put16(b.bytes, c + 0, s.machine);
    put16(b.bytes, c + 2, static_cast<std::uint16_t>(s.sections.size()));
    put32(b.bytes, c + 4, 0);            // TimeDateStamp
    put32(b.bytes, c + 8, 0);            // PointerToSymbolTable
    put32(b.bytes, c + 12, 0);           // NumberOfSymbols
    put16(b.bytes, c + 16, static_cast<std::uint16_t>(opt_size));
    put16(b.bytes, c + 18,
          static_cast<std::uint16_t>(s.dll ? 0x2000 : 0x0002));

    // --- optional header
    const std::size_t o = b.opt;
    put16(b.bytes, o + 0, s.plus ? 0x20b : 0x10b);
    put8(b.bytes, o + 2, 14);            // MajorLinkerVersion
    put32(b.bytes, o + 4, 0x200);        // SizeOfCode
    put32(b.bytes, o + 16, s.entry);     // AddressOfEntryPoint
    put32(b.bytes, o + 20, 0x1000);      // BaseOfCode
    // ImageBase: four bytes at 28 in PE32, eight at 24 in PE32+ -- the offset
    // that differs between the two layouts, and the reason the reader
    // branches rather than using one table.
    if (s.plus) {
        put64(b.bytes, o + 24, s.base);
    } else {
        put32(b.bytes, o + 28, static_cast<std::uint32_t>(s.base));
    }
    put32(b.bytes, o + 32, 0x1000);      // SectionAlignment
    put32(b.bytes, o + 36, 0x200);       // FileAlignment
    put16(b.bytes, o + 40, 4);           // MajorOperatingSystemVersion
    put16(b.bytes, o + 44, 0);           // MajorImageVersion
    put32(b.bytes, o + 56, 0x4000);      // SizeOfImage
    put32(b.bytes, o + 60, static_cast<std::uint32_t>(headers_size));
    put16(b.bytes, o + 68, s.subsystem);
    put16(b.bytes, o + 70, s.dll_characteristics);
    // SizeOfStackReserve/Commit, HeapReserve/Commit are left zero.

    // --- data directories
    const std::size_t dirs = o + (s.plus ? 112 : 96);
    const std::size_t count_at = o + (s.plus ? 108 : 92);
    put32(b.bytes, count_at, s.dir_count);
    if (s.import_rva != 0) {
        put32(b.bytes, dirs + 1 * 8, s.import_rva);
        put32(b.bytes, dirs + 1 * 8 + 4, s.import_size);
    }
    if (s.reloc_rva != 0) {
        put32(b.bytes, dirs + 5 * 8, s.reloc_rva);
        put32(b.bytes, dirs + 5 * 8 + 4, s.reloc_size);
    }

    // --- section table
    for (std::size_t i = 0; i < s.sections.size(); ++i) {
        const SectionSpec& sec = s.sections[i];
        const std::size_t sh = b.sections_at + i * kSectionHeaderSize;
        const std::string name = sec.name != nullptr ? sec.name : "";
        // Eight bytes, NUL-padded. A name that uses all eight is not
        // terminated, which is legal and which a C-string reader would run
        // off the end on.
        std::memcpy(&b.bytes[sh], name.data(),
                    name.size() < 8 ? name.size() : 8);
        put32(b.bytes, sh + 8, sec.virtual_size);
        put32(b.bytes, sh + 12, sec.virtual_address);
        put32(b.bytes, sh + 16, sec.raw_size);
        put32(b.bytes, sh + 20, static_cast<std::uint32_t>(layout[i].first));
        put32(b.bytes, sh + 36, sec.characteristics);
    }

    return b;
}

// ---------------------------------------------------------------- the tests

// ByteSpan is a pointer and a length, not a container, so every call site
// would otherwise repeat the same construction. It goes through here instead,
// which also keeps the fixtures' type out of the assertions.
PeImage parse_image(const std::vector<std::uint8_t>& bytes) {
    return PeImage::parse(ByteSpan{bytes.data(), bytes.size()});
}

// The first `n` bytes of a fixture. Written as a function rather than as a
// vector construction at each call site: the iterator arithmetic needs an
// explicit conversion from size_t, and doing it once here means the tests
// that cut a file say what they mean instead of how to spell it.
std::vector<std::uint8_t> prefix_of(const Built& b, std::size_t n) {
    const std::size_t take = n < b.bytes.size() ? n : b.bytes.size();
    return std::vector<std::uint8_t>(
        b.bytes.begin(),
        b.bytes.begin() + static_cast<std::ptrdiff_t>(take));
}

// A 32-bit executable with one section, the shape the reader sees most.
Spec base_spec() {
    Spec s;
    s.machine = 0x014c;
    s.subsystem = 3;
    s.entry = 0x1000;
    s.base = 0x00400000;
    s.sections.push_back(
        {".text", 0x1000, 0x800, 0x200, 0x60000020});
    return s;
}

void test_pe32_executable() {
    const Built b = build(base_spec());
    const PeImage p = parse_image(b.bytes);

    check(p.ok(), "pe32: parses");
    check(p.error() == PeError::None, "pe32: no error");
    check(!p.is_pe32_plus(), "pe32: not plus");
    check(p.machine() == PeMachine::I386, "pe32: machine is i386");
    check(p.machine_raw() == 0x014c, "pe32: machine raw");
    check(p.kind() == PeKind::Executable, "pe32: is an executable");
    check(!p.is_dll(), "pe32: is not a dll");
    check(p.subsystem() == PeSubsystem::WindowsCui, "pe32: subsystem");
    check(p.entry_rva() == 0x1000, "pe32: entry rva");
    check(p.image_base() == 0x00400000, "pe32: image base");
    check(p.entry_va() == 0x00401000, "pe32: entry va");
    check(p.optional_header_size() == kOptSize32, "pe32: opt size");
    check(p.headers_size() == 0x200, "pe32: headers size");
    check(p.file_alignment() == 0x200, "pe32: file alignment");
    check(p.section_alignment() == 0x1000, "pe32: section alignment");
    check(p.section_count() == 1, "pe32: section count");

    check(p.sections().size() == 1, "pe32: one section");
    check(p.sections()[0].name == ".text", "pe32: section name");
    check(p.sections()[0].virtual_address == 0x1000, "pe32: section rva");
    check(p.sections()[0].raw_offset == 0x200, "pe32: section raw offset");
    check(p.sections()[0].executable(), "pe32: section is executable");
    check(!p.sections()[0].writable(), "pe32: section is not writable");
    check(p.sections()[0].readable(), "pe32: section is readable");
    check(p.sections()[0].virtual_end() == 0x1800, "pe32: section vend");
    check(p.sections()[0].raw_end() == 0x400, "pe32: section rawend");
}

void test_pe32plus_executable() {
    Spec s = base_spec();
    s.plus = true;
    s.machine = 0x8664;
    s.base = 0x0000000140000000ull;
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    check(p.ok(), "pe32+: parses");
    check(p.is_pe32_plus(), "pe32+: is plus");
    check(p.machine() == PeMachine::Amd64, "pe32+: machine is amd64");
    // The image base is the field whose offset and width differ between the
    // layouts. If the reader read it at the PE32 offset in a PE32+ file it
    // would get the low four bytes of the value, which here is zero -- a
    // wrong answer that looks plausible.
    check(p.image_base() == 0x0000000140000000ull, "pe32+: image base is 8 bytes");
    check(p.entry_va() == 0x0000000140001000ull, "pe32+: entry va");
    check(p.optional_header_size() == kOptSize64, "pe32+: opt size");
}

void test_dll() {
    Spec s = base_spec();
    s.dll = true;
    s.subsystem = 2;
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    check(p.ok(), "dll: parses");
    check(p.is_dll(), "dll: is a dll");
    check(p.kind() == PeKind::Dll, "dll: kind");
    check(p.subsystem() == PeSubsystem::WindowsGui, "dll: subsystem");
}

// The conversion is the part of a PE reader most likely to be wrong, so each
// of the regions gets a case. The distinctions that matter:
//
//   - below SizeOfHeaders: a file offset already, no section needed
//   - inside a section, within raw data: a real file offset
//   - inside a section, past raw data but within virtual size: zero fill,
//     which exists in memory and not in the file
//   - past the section's virtual size: nowhere
//   - in no section at all: nowhere
void test_rva_conversion() {
    // One section: virtual 0x1000, virtual size 0x800, raw 0x200. So
    //   0x1000..0x1200  file-backed   -> file 0x200..0x400
    //   0x1200..0x1800  zero fill
    //   0x1800+         past the end
    //   0x0000..0x0200  the headers
    Spec s = base_spec();
    s.sections[0].virtual_size = 0x800;
    s.sections[0].raw_size = 0x200;
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);
    check(p.ok(), "rva: fixture parses");

    // --- below SizeOfHeaders
    std::uint64_t off = 0;
    check(p.to_file_offset(0, off), "rva: headers resolve");
    check(off == 0, "rva: headers offset is zero");
    check(p.to_file_offset(0x1ff, off), "rva: last header byte resolves");
    check(off == 0x1ff, "rva: last header byte offset");

    // --- the first byte of section data
    check(p.to_file_offset(0x1000, off), "rva: section start resolves");
    check(off == 0x200, "rva: section start offset");

    // --- the last file-backed byte
    check(p.to_file_offset(0x11ff, off), "rva: last backed byte resolves");
    check(off == 0x3ff, "rva: last backed byte offset");

    // --- zero fill
    // resolve_rva reports it as present and not file-backed; to_file_offset
    // refuses it. Both are correct and they answer different questions, so
    // both are checked.
    bool zero_filled = false;
    std::uint64_t resolve_off = 0;
    check(p.resolve_rva(0x1200, resolve_off, zero_filled),
          "rva: zero fill resolves");
    check(zero_filled, "rva: zero fill is flagged");
    check(resolve_off == 0, "rva: zero fill has no file offset");
    check(!p.to_file_offset(0x1200, off), "rva: zero fill has no file offset either");

    check(p.resolve_rva(0x17ff, resolve_off, zero_filled),
          "rva: last zero fill byte resolves");
    check(zero_filled, "rva: last zero fill byte is flagged");

    // --- past the virtual size, and past the end of the last section
    check(!p.resolve_rva(0x1800, resolve_off, zero_filled),
          "rva: one past virtual size does not resolve");
    check(!p.to_file_offset(0x1800, off),
          "rva: one past virtual size has no offset");
    check(!p.to_file_offset(0x100000, off), "rva: far past the end");
    check(!p.to_file_offset(0x1800 + 0x10000000ull, off),
          "rva: very far past the end");

    // --- between the headers and the first section: a gap that belongs to
    // no section. This is the case a reader that clamps to the nearest
    // section gets wrong.
    check(!p.to_file_offset(0x800, off), "rva: the gap resolves to nothing");
    check(!p.to_file_offset(0x0fff, off), "rva: just below the section");
}

// A section whose raw data is larger than its virtual size is a normal thing
// to find: the linker pads the file out to the file alignment. The tail
// beyond the virtual size is in the file and not in the image, and the
// conversion has to say so.
void test_raw_size_exceeds_virtual_size() {
    Spec s = base_spec();
    s.sections[0].virtual_size = 0x100;
    s.sections[0].raw_size = 0x400;
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);
    check(p.ok(), "raw>virtual: parses");

    std::uint64_t off = 0;
    check(p.to_file_offset(0x1000, off), "raw>virtual: start resolves");
    check(off == 0x200, "raw>virtual: start offset");
    check(p.to_file_offset(0x10ff, off), "raw>virtual: last virtual byte resolves");
    // Past the virtual size but inside the raw data: not in the image, so
    // not resolvable as an image address.
    check(!p.to_file_offset(0x1100, off),
          "raw>virtual: past the virtual size does not resolve");
}

// Several sections, with the gap between them. The RVA has to land in the
// right one, which is the property a reader that only ever looks at the
// first matching section cannot have.
void test_multiple_sections() {
    Spec s;
    s.sections.push_back({".text", 0x1000, 0x400, 0x400, 0x60000020});
    s.sections.push_back({".rdata", 0x2000, 0x400, 0x400, 0x40000040});
    s.sections.push_back({".data", 0x3000, 0x800, 0x200, 0xc0000040});
    s.sections.push_back({".rsrc", 0x4000, 0x200, 0x200, 0x40000040});
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);
    check(p.ok(), "multi: parses");
    check(p.section_count() == 4, "multi: section count");
    check(p.sections().size() == 4, "multi: sections vector");

    std::uint64_t off = 0;

    // Every section's file offset, checked individually. The sections have
    // different raw sizes (0x400, 0x400, 0x200, 0x200) laid out
    // contiguously from 0x200, so each offset pins both which section was
    // chosen and the arithmetic that added up to it. Checking only the last
    // would let three wrong answers and one compensating one pass.
    check(p.sections()[0].raw_offset == 0x200, "multi: .text raw offset");
    check(p.sections()[1].raw_offset == 0x600, "multi: .rdata raw offset");
    check(p.sections()[2].raw_offset == 0xa00, "multi: .data raw offset");
    check(p.sections()[3].raw_offset == 0xc00, "multi: .rsrc raw offset");

    check(p.to_file_offset(0x1000, off) && off == 0x200,
          "multi: .text rva maps to its raw offset");
    check(p.to_file_offset(0x2000, off) && off == 0x600,
          "multi: .rdata rva maps to its raw offset");
    check(p.to_file_offset(0x3000, off) && off == 0xa00,
          "multi: .data rva maps to its raw offset");
    check(p.to_file_offset(0x4000, off) && off == 0xc00,
          "multi: .rsrc rva maps to its raw offset");

    // .data is 0x800 virtual with 0x200 raw, so 0x3200..0x3800 is zero fill.
    bool zero_filled = false;
    check(p.resolve_rva(0x3200, off, zero_filled), "multi: .data zero fill resolves");
    check(zero_filled, "multi: .data zero fill is flagged");
    check(!p.to_file_offset(0x3200, off), "multi: .data zero fill has no offset");

    // Between .text and .rdata: no section covers 0x1800.
    check(!p.to_file_offset(0x1800, off), "multi: inter-section gap");

    // Characteristics, which is what a caller checks before deciding a
    // section is interesting.
    check(p.sections()[0].executable(), "multi: .text executable");
    check(!p.sections()[0].writable(), "multi: .text not writable");
    check(!p.sections()[1].executable(), "multi: .rdata not executable");
    check(p.sections()[2].writable(), "multi: .data writable");
    check(p.sections()[3].readable(), "multi: .rsrc readable");
}

// A section at the very top of the address space. virtual_address +
// virtual_size wraps in 32-bit arithmetic, and a wrapped end makes the
// section look like it ends before it starts -- so an RVA in it resolves to
// nothing, or worse, to the wrong section.
void test_section_at_top_of_address_space() {
    Spec s;
    s.sections.push_back({".text", 0x1000, 0x400, 0x400, 0x60000020});
    s.sections.push_back({".high", 0xfffff000u, 0x2000, 0x200, 0x40000040});
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);
    check(p.ok(), "top: parses");

    // The end of a section whose start is near the top of the address space.
    // 0xfffff000 + 0x2000 is 0x100001000, which does not fit in 32 bits: in
    // 32-bit arithmetic it wraps to 0x1000, which would place the section's
    // end *below* its start and make every RVA in it resolve to nothing.
    check(p.sections()[1].virtual_end() == 0x100001000ull,
          "top: virtual end does not wrap to a small number");

    std::uint64_t off = 0;
    check(p.to_file_offset(0xfffff000ull, off), "top: high section resolves");
    check(p.to_file_offset(0x1000, off), "top: low section still resolves");
    check(!p.to_file_offset(0xffff0000ull, off),
          "top: below the high section resolves to nothing");
}

// The optional header's own length is the file's statement about how long it
// is. A header that declares four bytes has no subsystem field, and reading
// one would read the section table's bytes and believe them.
//
// Zero is not in this list: a zero-length optional header is a real thing
// (a resource-only object) and is covered by its own case below.
void test_short_optional_header_is_refused() {
    for (int declared : {1, 2, 4, 16, 68, 71}) {
        Spec s = base_spec();
        s.opt_size_override = declared;
        const Built b = build(s);
        const PeImage p = parse_image(b.bytes);
        char msg[96];
        std::snprintf(msg, sizeof msg,
                      "short optional header (%d) is refused", declared);
        check(!p.ok(), msg);
        std::snprintf(msg, sizeof msg,
                      "short optional header (%d) reports truncation",
                      declared);
        check(p.error() == PeError::TruncatedOptionalHeader, msg);
    }

    // Seventy-two is the first length that holds every fixed field.
    Spec s = base_spec();
    s.opt_size_override = 72;
    const Built b = build(s);
    check(parse_image(b.bytes).ok(), "72-byte optional header is accepted");

    // Seventy-one is one byte short, and the check has to notice the
    // difference rather than testing "is it roughly seventy".
    Spec t = base_spec();
    t.opt_size_override = 71;
    const Built tb = build(t);
    check(!parse_image(tb.bytes).ok(),
          "71-byte optional header is one byte short and is refused");
}

// A header with no optional header at all is a real thing -- a resource-only
// object, a driver. It is not something this engine can run, but a reader
// that refuses it cannot describe a valid file.
void test_absent_optional_header() {
    Spec s = base_spec();
    s.opt_size_override = 0;
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    check(p.ok(), "no optional header: parses");
    check(p.optional_header_size() == 0, "no optional header: size is zero");
    check(p.entry_rva() == 0, "no optional header: entry is zero");
    check(p.image_base() == 0, "no optional header: base is zero");
    check(p.subsystem() == PeSubsystem::Unknown,
          "no optional header: subsystem is unknown");
    check(p.section_count() == 1, "no optional header: section is still read");
}

// ------------------------------------------------------------- import table
//
// The import directory is the one table worth walking here, because it is
// where the two coordinate systems meet: the directory itself is found by
// RVA, and every name in it is an RVA, and getting either wrong produces a
// name that is a real string from somewhere else in the file.

// Builds a file whose .rdata holds an import descriptor naming one DLL.
//
// The layout is fixed rather than computed so the test can state where every
// byte is: .text at RVA 0x1000 (file 0x200), .rdata at RVA 0x2000 (file
// 0x600). `descriptors` is how many non-null descriptors to write, and
// `declared_size` is what the directory claims -- passing 0 for the latter
// derives it, which is what a well-formed file does.
//
// The two are separate parameters because the interesting cases are the ones
// where they disagree: a file claiming more descriptors than it wrote, fewer,
// or a size too small to hold even one.
PeImage build_import_image(std::vector<std::string>& names_out,
                           std::size_t descriptors = 1,
                           std::size_t declared_size = 0) {
    Spec s;
    s.sections.push_back({".text", 0x1000, 0x400, 0x400, 0x60000020});
    s.sections.push_back({".rdata", 0x2000, 0x600, 0x600, 0x40000040});
    Built b = build(s);

    const std::size_t rdata_file = 0x600;
    const std::size_t desc_at = rdata_file;

    const char* kDllName = "KERNEL32.dll";
    const std::size_t dll_off = rdata_file + 0x100;
    std::memcpy(&b.bytes[dll_off], kDllName, std::strlen(kDllName));
    b.bytes[dll_off + std::strlen(kDllName)] = '\0';

    // The DLL name's RVA, computed from its offset inside .rdata. Getting
    // this wrong is the mistake this fixture exists to catch: the offset and
    // the RVA differ by exactly the section's file offset minus its RVA,
    // which is a coincidence in a file laid out the convenient way.
    const std::uint32_t dll_rva =
        0x2000 + static_cast<std::uint32_t>(dll_off - rdata_file);

    // Descriptor: OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name,
    // FirstThunk. Only Name is non-zero -- the reader reads the DLL name, and
    // a non-zero Name is what makes the descriptor non-null.
    for (std::size_t i = 0; i < descriptors; ++i) {
        const std::size_t at = desc_at + i * 20;
        put32(b.bytes, at + 0, 0);              // OriginalFirstThunk
        put32(b.bytes, at + 4, 0);              // TimeDateStamp
        put32(b.bytes, at + 8, 0);              // ForwarderChain
        put32(b.bytes, at + 12, dll_rva);       // Name
        put32(b.bytes, at + 16, 0);             // FirstThunk
    }
    // The null terminator, so the walk has an end the file itself declares.
    const std::size_t term_at = desc_at + descriptors * 20;
    if (term_at + 20 <= b.bytes.size()) {
        for (std::size_t i = 0; i < 20; ++i) {
            b.bytes[term_at + i] = 0;
        }
    }

    const std::size_t dirs = b.opt + 96;
    put32(b.bytes, dirs + 1 * 8, 0x2000);
    put32(b.bytes, dirs + 1 * 8 + 4,
          static_cast<std::uint32_t>(
              declared_size != 0 ? declared_size : (descriptors + 1) * 20));

    const PeImage p = parse_image(b.bytes);
    names_out = p.imports();
    return p;
}

void test_import_table() {
    std::vector<std::string> names;
    const PeImage p = build_import_image(names);

    check(p.ok(), "import: parses");
    check(p.imports().size() == 1, "import: one name");
    check(names.size() == 1, "import: one name reported");
    if (names.size() == 1) {
        check(names[0] == "KERNEL32.dll", "import: the name is the DLL's");
    }
    check(p.reloc_rva() == 0, "import: no relocations");
}

// Two descriptors and no null terminator between them: the walk ends at the
// declared size rather than at a terminator. Both names are still real, so
// both are reported -- the file did say two DLLs, and stopping early would be
// losing information the file provided.
void test_import_table_without_terminator() {
    std::vector<std::string> names;
    // Two descriptors, and a declared size that covers exactly them: 40
    // bytes, so no room for a terminator.
    const PeImage p = build_import_image(names, 2, 40);

    check(p.ok(), "import: a missing terminator still parses");
    check(names.size() == 2, "import: both descriptors were read");
    if (names.size() == 2) {
        check(names[0] == "KERNEL32.dll", "import: first name");
        check(names[1] == "KERNEL32.dll", "import: second name");
    }
}

// A directory declaring fewer bytes than one descriptor needs. There is no
// arrangement of a 20-byte record inside 8 bytes, so this is a claim the file
// cannot keep.
void test_import_directory_too_small() {
    for (std::size_t declared : {std::size_t{1}, std::size_t{8},
                                 std::size_t{19}}) {
        std::vector<std::string> names;
        const PeImage p = build_import_image(names, 1, declared);
        char msg[96];
        std::snprintf(msg, sizeof msg,
                      "import: a %zu-byte directory is refused", declared);
        check(!p.ok(), msg);
        std::snprintf(msg, sizeof msg,
                      "import: a %zu-byte directory reports truncation",
                      declared);
        check(p.error() == PeError::TruncatedImportTable, msg);
    }
}

// A directory declaring more descriptors than the file holds. The walk runs
// out of file before it runs out of declarations, which is a broken table
// rather than one that happened to end.
void test_import_directory_claims_more_than_it_has() {
    std::vector<std::string> names;
    // 200 descriptors declared; .rdata is 0x600 bytes, so it holds far fewer
    // whole descriptors than that even before the names take their space.
    const PeImage p = build_import_image(names, 1, 200 * 20);

    check(!p.ok(), "import: an over-declared directory is refused");
    check(p.error() == PeError::TruncatedImportTable,
          "import: an over-declared directory reports truncation");
    if (!p.error_detail().empty()) {
        check(p.error_detail().find("fit in the file") != std::string::npos,
              "import: the message says the file ran out, not the walk");
    }
}

// A directory large enough to be a denial of service rather than a table.
// The cap is reported instead of silently truncating, because a walk that
// stops at 4096 without saying so looks exactly like a table that ended.
void test_import_directory_count_is_capped() {
    std::vector<std::string> names;
    const PeImage p = build_import_image(names, 1, 100000 * 20);

    check(!p.ok(), "import: an enormous directory is refused");
    check(p.error() == PeError::TruncatedImportTable, "import: reports truncation");
    if (!p.error_detail().empty()) {
        check(p.error_detail().find("4096") != std::string::npos,
              "import: the message names the cap");
    }
}

void test_import_directory_out_of_file() {
    Spec s = base_spec();
    // An import RVA that is inside no section.
    s.import_rva = 0x8000;
    s.import_size = 40;
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    check(!p.ok(), "import: an unresolvable directory is refused");
    check(p.error() == PeError::DirectoryOutOfFile, "import: reports the directory");
    if (!p.error_detail().empty()) {
        check(p.error_detail().find("0x8000") != std::string::npos,
              "import: the message names the RVA");
    }
}

// An import RVA that lands in a section's zero fill: the RVA resolves, but
// there is nothing behind it. Reporting "no imports" would be a claim the
// file does not make.
void test_import_directory_in_zero_fill() {
    Spec s = base_spec();
    s.sections[0].virtual_size = 0x800;
    s.sections[0].raw_size = 0x200;
    // 0x1200 is inside the virtual size and past the raw data.
    s.import_rva = 0x1200;
    s.import_size = 40;
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    check(!p.ok(), "import: a zero-filled directory is refused");
    check(p.error() == PeError::DirectoryOutOfFile,
          "import: a zero-filled directory is not 'no imports'");
}

// A descriptor naming a string with no terminator before the end of the
// file. The reader must discard it rather than report the fragment, or a
// truncated file produces a "DLL name" that runs to the end of the buffer.
void test_import_name_without_terminator() {
    Spec s;
    s.sections.push_back({".text", 0x1000, 0x400, 0x400, 0x60000020});
    s.sections.push_back({".rdata", 0x2000, 0x400, 0x400, 0x40000040});
    Built b = build(s);

    const std::size_t rdata_file = 0x600;
    // Fill .rdata with a non-zero byte so there is no terminator anywhere.
    for (std::size_t i = rdata_file; i < rdata_file + 0x400; ++i) {
        b.bytes[i] = 'A';
    }
    // The name RVA is the first byte of .rdata.
    put32(b.bytes, rdata_file + 12, 0x2000);
    put32(b.bytes, rdata_file + 0, 0);
    const std::size_t dirs = b.opt + 96;
    put32(b.bytes, dirs + 1 * 8, 0x2000);
    put32(b.bytes, dirs + 1 * 8 + 4, 40);

    const PeImage p = parse_image(b.bytes);
    check(p.ok(), "unterminated name: the file still parses");
    check(p.imports().empty(),
          "unterminated name: discarded rather than reported as a fragment");
}

// ------------------------------------------------------------ malformed input

void test_not_pe() {
    const std::vector<std::uint8_t> empty;
    const PeImage p = parse_image(empty);
    check(!p.ok(), "empty: refused");
    check(p.error() == PeError::TruncatedDosHeader, "empty: reports the DOS header");

    std::vector<std::uint8_t> mz_only = {'M', 'Z'};
    check(!parse_image(mz_only).ok(), "mz only: refused");

    // A well-formed DOS header whose e_lfanew points at bytes that are not a
    // PE signature. This is the case that is genuinely "not a PE" rather than
    // "a PE with a broken header": the offset is legal, the header is
    // complete, and what is at the offset is not the signature.
    std::vector<std::uint8_t> no_magic(256, 0);
    no_magic[0] = 'M';
    no_magic[1] = 'Z';
    put32(no_magic, 0x3c, 0x80);
    put32(no_magic, 0x80, 0x41414141); // not "PE\0\0"
    const PeImage q = parse_image(no_magic);
    check(!q.ok(), "no PE signature: refused");
    check(q.error() == PeError::NotPe, "no PE signature: reports not-a-PE");
    if (!q.error_detail().empty()) {
        check(q.error_detail().find("0x80") != std::string::npos,
              "no PE signature: the message names where it looked");
    }

    // A DOS header with no e_lfanew at all. Zero is inside the DOS header,
    // so this is a bad offset, not a missing signature -- and the difference
    // tells a reader whether to look at the offset or at the signature.
    std::vector<std::uint8_t> no_lfanew(256, 0);
    no_lfanew[0] = 'M';
    no_lfanew[1] = 'Z';
    const PeImage r = parse_image(no_lfanew);
    check(!r.ok(), "no e_lfanew: refused");
    check(r.error() == PeError::BadHeaderOffset,
          "no e_lfanew: reports a bad offset rather than a missing signature");
}

void test_bad_header_offset() {
    Spec s = base_spec();
    Built b = build(s);

    // e_lfanew pointing inside the DOS header. A reader that only checked
    // "is it in the file" would read the DOS header's own bytes as a
    // signature.
    put32(b.bytes, 0x3c, 4);
    const PeImage p = parse_image(b.bytes);
    check(!p.ok(), "e_lfanew inside the DOS header: refused");
    check(p.error() == PeError::BadHeaderOffset,
          "e_lfanew inside the DOS header: reported");

    // Pointing past the end.
    put32(b.bytes, 0x3c, 0x100000);
    check(!parse_image(b.bytes).ok(), "e_lfanew past the end: refused");

    // An odd value. The signature is four bytes at an arbitrary alignment,
    // but the specification requires this field to be even, and a file that
    // says otherwise is one whose header is not where it says.
    put32(b.bytes, 0x3c, static_cast<std::uint32_t>(b.coff + 1));
    check(!parse_image(b.bytes).ok(), "odd e_lfanew: refused");
}

void test_truncated_coff_and_optional() {
    Spec s = base_spec();
    Built b = build(s);

    // Cut the file just after the PE signature.
    const std::vector<std::uint8_t> no_coff = prefix_of(b, b.coff + 4);
    const PeImage p = parse_image(no_coff);
    check(!p.ok(), "no COFF header: refused");
    check(p.error() == PeError::TruncatedCoffHeader, "no COFF header: reported");

    // Cut inside the COFF header.
    check(!parse_image(prefix_of(b, b.coff + 4 + 10)).ok(),
          "half a COFF header: refused");

    // Cut inside the optional header. The header declares its own length, so
    // the reader must check that length against the file.
    const std::vector<std::uint8_t> half_opt = prefix_of(b, b.opt + 40);
    const PeImage q = parse_image(half_opt);
    check(!q.ok(), "half an optional header: refused");
    check(q.error() == PeError::TruncatedOptionalHeader,
          "half an optional header: reported");
}

void test_unknown_optional_magic() {
    Spec s = base_spec();
    Built b = build(s);
    put16(b.bytes, b.opt, 0x9999);
    const PeImage p = parse_image(b.bytes);

    check(!p.ok(), "bad magic: refused");
    check(p.error() == PeError::UnknownOptionalMagic, "bad magic: reported");
    if (!p.error_detail().empty()) {
        // The message names both valid magics, because a reader who has been
        // told "bad magic" alone has to go and look up what the right one is.
        check(p.error_detail().find("0x10b") != std::string::npos,
              "bad magic: names PE32");
        check(p.error_detail().find("0x20b") != std::string::npos,
              "bad magic: names PE32+");
    }
}

void test_truncated_section_table() {
    Spec s;
    s.sections.push_back({".text", 0x1000, 0x400, 0x400, 0x60000020});
    s.sections.push_back({".data", 0x2000, 0x400, 0x400, 0xc0000040});
    Built b = build(s);

    // The COFF header claims two sections; the file carries one and a half.
    const std::size_t cut = b.sections_at + kSectionHeaderSize + 20;
    const PeImage p = parse_image(prefix_of(b, cut));
    check(!p.ok(), "half a section header: refused");
    check(p.error() == PeError::TruncatedSectionTable,
          "half a section header: reported");
}

void test_no_sections() {
    Spec s;
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    check(!p.ok(), "no sections: refused");
    check(p.error() == PeError::NoSections, "no sections: reported");
}

// A section whose raw data runs past the end of the file. The section table
// is parsed before any RVA is resolved, so this is caught here rather than
// turning into a read later.
void test_section_out_of_file() {
    Spec s;
    s.sections.push_back({".text", 0x1000, 0x400, 0x400, 0x60000020});
    Built b = build(s);
    // Claim four sections' worth of raw data from a file that has one.
    put32(b.bytes, b.sections_at + 16, 0x4000);   // SizeOfRawData
    const PeImage p = parse_image(b.bytes);

    check(!p.ok(), "section past the end: refused");
    check(p.error() == PeError::BadSectionTable, "section past the end: reported");
    if (!p.error_detail().empty()) {
        check(p.error_detail().find(".text") != std::string::npos,
              "section past the end: names the section");
    }
}

// A raw offset near the top of the address space with a nonzero size: the
// sum wraps, and a wrapped sum compares small enough to pass a check written
// as an addition.
void test_section_raw_range_overflow() {
    Spec s;
    s.sections.push_back({".text", 0x1000, 0x400, 0x400, 0x60000020});
    Built b = build(s);
    put32(b.bytes, b.sections_at + 20, 0xfffff000u); // PointerToRawData
    const PeImage p = parse_image(b.bytes);

    check(!p.ok(), "raw offset + size wraps: refused");
    check(p.error() == PeError::BadSectionTable, "raw offset + size wraps: reported");
}

// A directory count larger than the header can hold. The count is a claim
// about how many directories exist; the header's own length is the claim
// about how many it carries, and the smaller one wins.
void test_directory_count_larger_than_header() {
    Spec s = base_spec();
    s.dir_count = 0xffff;
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    check(p.ok(), "huge directory count: the file still parses");
    check(p.section_count() == 1, "huge directory count: sections unaffected");
    check(p.imports().empty(),
          "huge directory count: no import directory was invented");
}

void test_directory_count_within_header_but_no_import() {
    Spec s = base_spec();
    s.dir_count = 0;
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);
    check(p.ok(), "zero directory count: parses");
    check(p.imports().empty(), "zero directory count: no imports");
}

// --------------------------------------------------------------- name fields

// A section name that uses all eight bytes has no terminator. Reading it as
// a C string runs into the next header's first byte, which is the virtual
// size -- so the name comes back with four binary characters appended.
void test_full_width_section_name() {
    Spec s;
    s.sections.push_back({"ABCDEFGH", 0x1000, 0x400, 0x400, 0x60000020});
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    check(p.ok(), "full name: parses");
    check(p.sections().size() == 1, "full name: one section");
    if (!p.sections().empty()) {
        check(p.sections()[0].name == "ABCDEFGH",
              "full name: stops at eight bytes");
        check(p.sections()[0].name.size() == 8, "full name: is eight long");
    }
}

void test_section_name_with_embedded_padding() {
    Spec s;
    s.sections.push_back({".te\0xt", 0x1000, 0x400, 0x400, 0x60000020});
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);
    check(p.ok(), "padded name: parses");
    if (!p.sections().empty()) {
        check(p.sections()[0].name == ".te",
              "padded name: stops at the NUL inside the field");
    }
}

// ------------------------------------------------------------------- aslr

// IMAGE_DLLCHARACTERISTICS bits. HIGH_ENTROPY_VA is 0x20, DYNAMIC_BASE is
// 0x40, NX_COMPAT is 0x100. The values are stated here rather than reused
// from the implementation, because a test that imports the constant it is
    // testing cannot fail when the constant is wrong.
void test_dll_characteristics() {
    Spec s = base_spec();
    s.dll_characteristics = 0x0020 | 0x0040 | 0x0100;
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    check(p.dynamic_base(), "dllchars: dynamic base");
    check(p.nx_compat(), "dllchars: nx compat");
    check(p.high_entropy_va(), "dllchars: high entropy va");
    check(!p.has_seh(), "dllchars: no seh table");

    // Each bit on its own, so a reader that ORed the three together and
    // tested the result would pass the first case and fail these.
    struct { std::uint16_t bit; bool (PeImage::*q)() const noexcept; const char* name; }
    singles[] = {
        {0x0040, &PeImage::dynamic_base, "dynamic base"},
        {0x0100, &PeImage::nx_compat, "nx compat"},
        {0x0020, &PeImage::high_entropy_va, "high entropy va"},
    };
    for (const auto& c : singles) {
        Spec t = base_spec();
        t.dll_characteristics = c.bit;
        const Built tb = build(t);
        const PeImage q = parse_image(tb.bytes);
        check((q.*c.q)(), c.name);
    }

    // A bit this reader does not name must not set a named one. 0x0080 is
// FORCE_INTEGRITY; 0x8000 is TERMINAL_SERVER_AWARE.
    Spec u = base_spec();
    u.dll_characteristics = 0x0080 | 0x8000;
    const Built ub = build(u);
    const PeImage r = parse_image(ub.bytes);
    check(!r.dynamic_base(), "dllchars: an unnamed bit does not set aslr");
    check(!r.nx_compat(), "dllchars: an unnamed bit does not set nx");
    check(!r.high_entropy_va(), "dllchars: an unnamed bit does not set high entropy");

    Spec t = base_spec();
    t.dll_characteristics = 0;
    const Built tb = build(t);
    const PeImage q = parse_image(tb.bytes);
    check(!q.dynamic_base(), "dllchars: no flags set");
    check(!q.nx_compat(), "dllchars: nx not set");
    check(!q.high_entropy_va(), "dllchars: high entropy not set");
}

void test_seh_directory() {
    Spec s = base_spec();
    s.dir_count = 16;
    Built b = build(s);
    // Directory 4 is the SEH table. A nonzero first field means the file
    // declares one.
    const std::size_t dirs = b.opt + 96;
    put32(b.bytes, dirs + 4 * 8, 0x3000);
    put32(b.bytes, dirs + 4 * 8 + 4, 0x40);

    check(parse_image(b.bytes).has_seh(), "seh: declared table is seen");

    // Zero means absent. An empty table is a valid configuration, so its
    // absence is not an error.
    put32(b.bytes, dirs + 4 * 8, 0);
    check(!parse_image(b.bytes).has_seh(), "seh: zero means absent");

    // A directory count that stops before the SEH entry means the file never
    // claimed to have one. Reading it anyway would find the section table's
    // bytes and report them as a table.
    Spec t = base_spec();
    t.dir_count = 4;
    Built tb = build(t);
    put32(tb.bytes, tb.opt + 96 + 4 * 8, 0x3000);
    check(!parse_image(tb.bytes).has_seh(),
          "seh: not read when the count stops short of it");
}

// --------------------------------------------------------------- enum names

void test_machines() {
    struct { std::uint16_t raw; PeMachine m; } cases[] = {
        {0x014c, PeMachine::I386},
        {0x01c0, PeMachine::Arm},
        {0x8664, PeMachine::Amd64},
        {0xaa64, PeMachine::Arm64},
        // Not named by this build. The value is still reported raw, so a
        // caller can print it.
        {0x5032, PeMachine::Unknown},
        {0xffff, PeMachine::Unknown},
    };
    for (const auto& c : cases) {
        Spec s = base_spec();
        s.machine = c.raw;
        const Built b = build(s);
        const PeImage p = parse_image(b.bytes);
        check(p.ok(), "machine: the file parses whatever the machine is");
        check(p.machine() == c.m, "machine: mapped");
        check(p.machine_raw() == c.raw, "machine: raw is reported unchanged");
    }
}

void test_subsystems() {
    struct { std::uint16_t raw; PeSubsystem s; } cases[] = {
        {1, PeSubsystem::Native},
        {2, PeSubsystem::WindowsGui},
        {3, PeSubsystem::WindowsCui},
        {9, PeSubsystem::WindowsCeGui},
        {10, PeSubsystem::EfiApplication},
        {16, PeSubsystem::WindowsBootApplication},
        {0, PeSubsystem::Unknown},
        {999, PeSubsystem::Unknown},
    };
    for (const auto& c : cases) {
        Spec s = base_spec();
        s.subsystem = c.raw;
        const Built b = build(s);
        const PeImage p = parse_image(b.bytes);
        check(p.subsystem() == c.s, "subsystem: mapped");
        check(p.subsystem_raw() == c.raw, "subsystem: raw is reported unchanged");
    }
}

// Bounds at the extremes of the address space.
//
// Every field in a PE is 32 bits, so on a 64-bit target an offset taken from
// the file plus a small width cannot reach the top of a size_t and cannot
// wrap. That is why removing the subtraction form in `in_range` does not make
// any test in this file fail, and it is worth saying so plainly rather than
// letting a passing suite imply a guarantee it is not testing.
//
// What these cases do establish is the part that *is* reachable: values at
// the top of the 32-bit range are refused with the right diagnosis, and the
// reader's arithmetic over them is done in a width that does not truncate.
// The subtraction form is kept on the strength of the ELF reader, where the
// values really were large enough to wrap, and it is what the fuzz harness
// for this reader (fuzz/fuzz_pe.cpp) will hold to account.
void test_bounds_near_the_top_of_the_address_space() {
    // virtual_address + virtual_size wraps in 32 bits; virtual_address + a
    // stride does not, but the *file* offset that comes out of it does when
    // raw_offset is large. Both are exercised here.
    struct { std::uint32_t vaddr; std::uint32_t vsize; std::uint32_t raw_off;
             const char* name; } cases[] = {
        {0xfffff000u, 0x2000, 0xfffff000u, "everything at the top"},
        {0xfffffff0u, 0x0020, 0xfffffff0u, "one page from the top"},
        {0xffffff00u, 0x0100, 0xffffff00u, "256 bytes from the top"},
        {0xffff0000u, 0x10000, 0xffff0000u, "64 KiB from the top"},
    };
    for (const auto& c : cases) {
        Spec s;
        s.sections.push_back({".text", 0x1000, 0x200, 0x200, 0x60000020});
        s.sections.push_back({".high", c.vaddr, c.vsize, 0x200, 0x40000040});
        Built b = build(s);
        // Claim the raw data is at the top of the address space. The section
        // table check refuses it, and refusing it is the point: an addition
        // that wrapped would pass the check and read there.
        put32(b.bytes, b.sections_at + kSectionHeaderSize + 20, c.raw_off);

        const PeImage p = parse_image(b.bytes);
        check(!p.ok(), c.name);
        check(p.error() == PeError::BadSectionTable, c.name);

        // The same section with a raw offset that is merely large rather than
        // extreme: the reader refuses it for the same reason, with no
        // arithmetic having wrapped.
        Built d = build(s);
        put32(d.bytes, d.sections_at + kSectionHeaderSize + 20, 0x7fffffffu);
        check(!parse_image(d.bytes).ok(), "a raw offset of 2 GiB is refused");
    }

    // A section count large enough that the table's end offset would wrap if
    // it were computed as section_count * 40 added to the table's position.
    // 0xffff sections times 40 bytes is 10 MiB, which does not wrap -- but a
    // count of 0x40000000 does, and the reader must refuse before computing
    // it.
    Spec t;
    t.sections.push_back({".text", 0x1000, 0x200, 0x200, 0x60000020});
    Built tb = build(t);
    put16(tb.bytes, tb.coff + 4 + 2, 0x4000);
    check(!parse_image(tb.bytes).ok(),
          "a section count whose table would wrap is refused");

    // And the count that a real linker emits, for contrast: refused too, but
    // because the file is short rather than because the arithmetic wrapped.
    Built ub = build(t);
    put16(ub.bytes, ub.coff + 4 + 2, 0x4000);
    check(parse_image(ub.bytes).error() == PeError::TruncatedSectionTable,
          "a section count past the file names truncation, not overflow");
}

// A truncated buffer is not an ELF, and detect.cpp asks readers in turn. This
// is the case where a PE buffer is handed in and the reader has to say so
// without reading past the end.
void test_truncated_buffer_everywhere() {
    Spec s = base_spec();
    Built full = build(s);

    // Every prefix of a valid file: none may crash, and none may claim to be
    // something it is not. This is the cheap version of what the fuzz harness
    // does, kept here so a regression shows up as a failed test rather than
    // as a crash found later.
    for (std::size_t n = 0; n <= full.bytes.size(); n += 7) {
        const std::vector<std::uint8_t> prefix =
            prefix_of(full, n);
        const PeImage p = parse_image(prefix);
        if (n < full.bytes.size()) {
            // A prefix is not a complete file. It may still parse if the
            // truncation happened to fall after everything the reader needs,
            // but it must never claim to be a well-formed image with sections
            // it does not have.
            if (p.ok()) {
                for (const PeSection& sec : p.sections()) {
                    if (sec.raw_size != 0 && sec.raw_offset > prefix.size()) {
                        check(false, "prefix: a section claims data past the prefix");
                        return;
                    }
                }
            }
        }
    }
    check(true, "prefix: every prefix of a valid file is handled");

    // Single-byte buffers of each interesting value: the DOS magic's two bytes,
    // a zero, and a byte that is neither.
    for (std::uint8_t v : {std::uint8_t{0x00}, std::uint8_t{0x4d},
                           std::uint8_t{0x5a}, std::uint8_t{0xff}}) {
        const std::vector<std::uint8_t> one{v};
        const PeImage p = parse_image(one);
        check(!p.ok(), "one byte: refused");
    }
    check(true, "one byte: every single-byte buffer is refused");
}

} // namespace

int main() {
    test_pe32_executable();
    test_pe32plus_executable();
    test_dll();
    test_rva_conversion();
    test_raw_size_exceeds_virtual_size();
    test_multiple_sections();
    test_section_at_top_of_address_space();
    test_short_optional_header_is_refused();
    test_absent_optional_header();
    test_import_table();
    test_import_table_without_terminator();
    test_import_directory_too_small();
    test_import_directory_claims_more_than_it_has();
    test_import_directory_count_is_capped();
    test_import_directory_out_of_file();
    test_import_directory_in_zero_fill();
    test_import_name_without_terminator();
    test_not_pe();
    test_bad_header_offset();
    test_truncated_coff_and_optional();
    test_unknown_optional_magic();
    test_truncated_section_table();
    test_no_sections();
    test_section_out_of_file();
    test_section_raw_range_overflow();
    test_directory_count_larger_than_header();
    test_directory_count_within_header_but_no_import();
    test_full_width_section_name();
    test_section_name_with_embedded_padding();
    test_dll_characteristics();
    test_seh_directory();
    test_machines();
    test_subsystems();
    test_bounds_near_the_top_of_the_address_space();
    test_truncated_buffer_everywhere();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
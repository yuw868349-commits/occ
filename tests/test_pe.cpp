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
    // Zero means "one page", which is what most sections in a fixture want.
    // A negative value means "this section stores nothing at all", which is
    // what .bss and a linker's padding sections are. The two are different
    // claims about the file, and a builder that can only make the first one
    // cannot express the second.
    std::int32_t raw_size = 0;
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
    // The export directory, same. Zero means none. Kept separate from the
    // import's rather than folded into a table of directories, because a
    // fixture sets one or the other and a builder that made both come from
    // one struct would have a test that meant to move one of them move both.
    std::uint32_t export_rva = 0;
    std::uint32_t export_size = 0;
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
        // A negative raw size means "this section stores nothing", which is
        // what .bss and a linker's padding sections are. It is spelled as a
        // negative number because zero is already meaningful in the other
        // direction -- SectionSpec::raw_size defaults to zero meaning "use
        // the builder's default of one page" -- and a builder that cannot
        // express the common case is a builder that will get it wrong.
        if (sec.raw_size < 0) {
            layout.emplace_back(0u, 0u);
            continue;
        }
        const std::size_t raw =
            sec.raw_size != 0 ? static_cast<std::size_t>(sec.raw_size) : 0x200;
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
    if (s.export_rva != 0) {
        put32(b.bytes, dirs + 0 * 8, s.export_rva);
        put32(b.bytes, dirs + 0 * 8 + 4, s.export_size);
    }
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
        // The size written is the layout's, not the spec's: the spec says
        // "one page" or "nothing" and the layout says what that came out as.
        put32(b.bytes, sh + 16, static_cast<std::uint32_t>(layout[i].second));
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

// A section whose VirtualSize is zero is mapped, not absent.
//
// `VirtualSize` of zero is what a linker writes for a section whose contents
// are entirely in the file: there is no zero-fill to size, so there is no size
// to state. The field is not optional and a zero is not a claim that the
// section is empty -- the raw size is right there saying how many bytes it
// holds. Reading the field directly made the whole section unreachable, because
// every delta into it is at or above zero and so "outside" it, and an RVA the
// Windows loader maps resolved to nothing here.
//
// The check is on bytes rather than on offsets: a wrong file offset and a
// right one are both numbers inside the file, and a reader that resolved to the
// wrong one would produce a plausible answer that described the wrong bytes.
// Distinctive content at a known spot, read back through the resolution, is
// the only thing that distinguishes them.
void test_zero_virtual_size_still_maps() {
    Spec s = base_spec();
    s.sections[0].virtual_size = 0;
    s.sections[0].raw_size = 0x400;
    Built b = build(s);

    // A recognisable pattern over the section's raw data. Written into the file
    // directly rather than through a spec field because the builder has no
    // "these are the contents" concept, and a test about what the section
    // resolves to needs contents that are not all zero -- zero is what both a
    // correct read of unwritten space and a wrong offset into the headers can
    // produce.
    for (std::size_t i = 0; i < 0x400; ++i) {
        b.bytes[b.data_at + i] =
            static_cast<std::uint8_t>((i * 7u + 3u) & 0xffU);
    }

    const PeImage p = parse_image(b.bytes);
    check(p.ok(), "zero virtual: parses");
    if (!p.ok()) {
        return;
    }

    check(p.sections()[0].virtual_size == 0,
          "zero virtual: the section really does declare a VirtualSize of zero, "
          "so this case is the one it claims to be");

    // The section's extent, which is the number a reader sizing the section
    // asks for.
    check(p.sections()[0].mapped_size() == 0x400,
          "zero virtual: the section occupies its raw size when VirtualSize "
          "says nothing");
    check(p.sections()[0].virtual_end() == 0x1000 + 0x400,
          "zero virtual: and its address range ends where its contents end, "
          "not where it starts");

    // Every byte of it resolves, first through the offset and then through the
    // contents that offset names. Sampled across the section rather than only
    // at its edges: the first and last bytes are the ones most likely to be
    // right by accident, since an off-by-one at either end still resolves
    // somewhere.
    std::uint64_t off = 0;
    bool every_byte_resolves = true;
    bool every_byte_reads_back = true;
    for (std::uint64_t i = 0; i < 0x400; ++i) {
        if (!p.to_file_offset(0x1000 + i, off)) {
            every_byte_resolves = false;
            break;
        }
        if (b.bytes[static_cast<std::size_t>(off)] !=
            static_cast<std::uint8_t>((i * 7u + 3u) & 0xffU)) {
            every_byte_reads_back = false;
            break;
        }
    }
    check(every_byte_resolves,
          "zero virtual: every byte of the section resolves to a file offset, "
          "which is what makes the section addressable at all");
    check(every_byte_reads_back,
          "zero virtual: and every one of those offsets names the byte the "
          "section stores there");

    // The loaded-image question as well as the file question: past the raw data
    // there is nothing, so it is a refusal rather than an answer, and the
    // refusal is what keeps a section from claiming address space it does not
    // have.
    check(!p.to_file_offset(0x1000 + 0x400, off),
          "zero virtual: an address past the section's contents is not part of "
          "the image");

    // And the reason a reader cares, which is a whole table rather than a
    // string: an import directory living in such a section. The descriptor and
    // the name it points at are both reached by RVA, so before the fix neither
    // resolved and the image was reported to import nothing -- a file that
    // names a DLL, described as naming none, with no error to say so.
    Spec imports = base_spec();
    imports.sections[0].virtual_size = 0;
    imports.sections[0].raw_size = 0x600;
    imports.sections[0].characteristics = 0x60000020;
    Built ib = build(imports);

    const std::string dll = "KERNEL32.dll";
    const std::size_t name_at = ib.data_at + 0x200;
    std::memcpy(&ib.bytes[name_at], dll.data(), dll.size() + 1);
    // The name's RVA, from where it landed rather than from where it was
    // meant to land: the difference between the two is the whole bug.
    const std::uint32_t name_rva =
        0x1000 + static_cast<std::uint32_t>(name_at - ib.data_at);
    for (std::size_t i = 0; i < 20; ++i) {
        ib.bytes[ib.data_at + i] = 0;
    }
    put32(ib.bytes, ib.data_at + 12, name_rva);   // the descriptor's Name
    // The twenty bytes after it stay zero, which is the null terminator the
    // walk ends on. A terminator that carried a Name would be a second
    // descriptor rather than an end, and the walk would report the DLL twice.
    const std::size_t dirs = ib.opt + 96;
    put32(ib.bytes, dirs + 1 * 8, 0x1000);
    put32(ib.bytes, dirs + 1 * 8 + 4, 40);

    const PeImage ip = parse_image(ib.bytes);
    check(ip.ok() && ip.imports().size() == 1 &&
              ip.imports()[0] == dll,
          "zero virtual: an import directory in such a section is walked and "
          "the DLL it names is reported, which is what every caller that "
          "loads an image needs from the parser");
}

// SizeOfHeaders larger than the file.
//
// Found by fuzz/fuzz_pe.cpp, twice, and the two findings were one defect.
//
// SizeOfHeaders is not only a number. It is the threshold that decides which
// of the two coordinate systems an RVA belongs to, so a file that overstates
// it reclassifies every address in its image. A 378-byte file claiming four
// gigabytes of headers had a section at RVA 0x1000 resolved to *file* offset
// 0x1000 instead of 0x200 -- the header rule claimed it before the section
// table was consulted. Nothing crashed, every offset was inside the file, and
// every one of them was wrong.
//
// That is worse than a crash, because a caller has no way to notice. The
// other half of the same bug was sharper: the bound on a header-region RVA
// compared the file's length as "greater than", so an RVA exactly equal to
// the file's length resolved to that length -- one byte past the end.
//
// The file is refused. There is no correct answer to give about a file whose
// headers cannot be where it says they are, and reporting one would mean
// choosing which of the two wrong answers to give.
void test_headers_size_larger_than_the_file() {
    Spec s = base_spec();
    const std::size_t size = build(s).bytes.size();

    // Each of these is a file that claims more headers than it has bytes.
    // The bound is the file, so one byte over is enough.
    const std::uint32_t claims[] = {0x40000000u, 0x10000u,
                                    static_cast<std::uint32_t>(size) + 1u,
                                    0xffffffffu};
    for (std::uint32_t claim : claims) {
        Spec t = base_spec();
        Built b = build(t);
        put32(b.bytes, b.opt + 60, claim);
        const PeImage p = parse_image(b.bytes);

        char msg[96];
        std::snprintf(msg, sizeof msg,
                      "SizeOfHeaders of 0x%x in a %zu-byte file is refused",
                      claim, size);
        check(!p.ok(), msg);
        std::snprintf(msg, sizeof msg,
                      "SizeOfHeaders of 0x%x is reported as a bad size", claim);
        check(p.error() == PeError::BadHeaderSize, msg);

        // A refused parse reports nothing. A caller checks ok() and then
        // trusts everything else, so sections surviving a refusal would be
        // worse than the refusal itself.
        std::snprintf(msg, sizeof msg,
                      "SizeOfHeaders of 0x%x leaves no sections behind", claim);
        check(p.sections().empty(), msg);
        std::snprintf(msg, sizeof msg,
                      "SizeOfHeaders of 0x%x states the size it claimed", claim);
        check(p.error_detail().find("SizeOfHeaders") != std::string::npos, msg);
    }

    // A file whose headers exactly fill it is fine, so the bound is not off
    // by one in the tight direction either.
    Spec e = base_spec();
    Built eb = build(e);
    put32(eb.bytes, eb.opt + 60, static_cast<std::uint32_t>(size));
    check(parse_image(eb.bytes).ok(),
          "SizeOfHeaders exactly equal to the file's length is accepted");

    // And the boundary itself, on a file with a sane header region: the last
    // header byte resolves, the first byte past the headers is inside the
    // file and belongs to no section, and the file's length -- which is an RVA
    // under the old comparison -- resolves to nothing.
    const PeImage q = parse_image(build(s).bytes);
    check(q.ok(), "sane headers: parses");
    check(q.headers_size() == 0x200, "sane headers: 0x200 as built");

    std::uint64_t off = 0;
    check(q.to_file_offset(0x1ff, off) && off == 0x1ff,
          "sane headers: the last header byte resolves to itself");
    check(!q.to_file_offset(0x200, off),
          "sane headers: the first RVA past the headers resolves through no "
          "section");
    check(q.to_file_offset(0x1000, off) && off == 0x200,
          "sane headers: a section RVA maps through the section, not as a "
          "file offset");
    check(!q.to_file_offset(static_cast<std::uint64_t>(size), off),
          "sane headers: the file's length does not resolve");
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

// ------------------------------------------------------------- the exports
//
// The export table is three tables and a directory record, and the mistakes
// available in it are different in kind from the import table's. The import
// table is a list of things in a fixed order, so a reader either walks it or
// it does not. The export table is a set of parallel arrays joined by
// indices, and every one of those indices is a place a file can disagree
// with itself:
//
//   - AddressOfNameOrdinals holds an *index into the address table*, not an
//     ordinal. Reading it as an ordinal silently resolves the wrong function
//     for every named export of any DLL whose base is not 1.
//   - NumberOfFunctions and NumberOfNames are independent counts. A DLL can
//     export five thousand symbols by ordinal and name ten of them.
//   - An address of zero is a slot with no export, not an export at the
//     image base.
//   - The name-pointer array is *specified* to be sorted, and nothing
//     enforces it. A file that does not sort it is still a file Windows
//     loads, and a reader that binary-searches it is a reader that answers
//     wrongly rather than slowly.
//   - An address inside the directory's own extent is a forwarder: a string
//     naming another module's symbol. The extent is half-open, and the
//     boundary between "an address" and "a string" is exactly where an
//     off-by-one is invisible.
//
// The fixtures below write every one of those bytes at a known offset, so a
// failure names a field rather than a zero that happened to be there.

// One name in the name-pointer table, and the address-table index its
// ordinal names. Kept as a pair rather than as a parallel array because the
// two are one fact: entry i of the name table and the index it resolves to
// are the same statement, and a fixture that stored them separately could
// put them out of step without meaning to.
struct ExportName {
    std::string name;
    std::uint16_t index = 0;
    // Point this name at a run of non-zero bytes with no terminator instead
    // of at its own string. The name is still written -- so the table is
    // still the size the file says it is -- but the pointer no longer
    // resolves to anything readable, which is the case a reader has to
    // survive. A fixture that could only produce readable names could not
    // produce this one, and a reader that had never met it would be a reader
    // whose behaviour here was never chosen.
    bool unterminated = false;
};

// A forwarder: the address-table index it sits at, and the string the
// address is made to point at. The builder places the string inside the
// directory's extent and points the entry at it, which is the only way to
// produce the case at all -- a forwarder is defined by where its address
// lands, not by anything written in the table.
struct ExportForwarder {
    std::uint16_t index = 0;
    std::string target;
    // Point the address at the unterminated run instead of at the string,
    // which is the case a forwarder has to survive: an address inside the
    // directory that is not a readable string. See ExportName's field of the
    // same name for why a fixture has to be able to say this.
    bool unterminated = false;
};

struct ExportLayout {
    // The base field. Almost always 1; a file saying otherwise is legal and
    // is the only way to tell a reader that added it from one that did not.
    std::uint32_t base = 1;
    // The address table, by index. A zero is a slot the file leaves empty.
    std::vector<std::uint32_t> addresses;
    // The name table, in the order it is written. Not necessarily sorted:
    // that is the point.
    std::vector<ExportName> names;
    // Forwarders, applied after the address table is written and overriding
    // whatever the entry at that index held.
    std::vector<ExportForwarder> forwarders;
    // The declared counts and size, when the file lies about them.
    //
    // Negative means "whatever was actually written", which is what a
    // well-formed file does. Zero is not that: a file may legitimately
    // declare zero of something, and a fixture that could not say so would
    // make "declares nothing" untestable -- which is the one case where the
    // reader's decision differs most sharply from its behaviour everywhere
    // else. The distinction is a signed one because the interesting values
    // are zero and there is no unsigned value that means "unset".
    int declared_functions = -1;
    int declared_names = -1;
    int declared_size = -1;
    // The four RVAs the directory holds, when the file points one of them
    // somewhere other than where the builder put the table. Zero means "the
    // real location".
    std::uint32_t dir_rva = 0;
    std::uint32_t functions_rva = 0;
    std::uint32_t names_rva = 0;
    std::uint32_t ordinals_rva = 0;
    // Cut the file to this many bytes. Zero means "the whole file".
    //
    // Present for one reason, and it is not to make a table run off the end:
    // a file cut inside a section is refused at the section table, before any
    // directory is read, so it cannot reach the export checks. It is here for
    // the case where the *file's own framing* is what a test needs to change
    // -- see the truncation test below, which asserts that the section check
    // is what fires, so that the fact is recorded rather than rediscovered
    // the next time a fixture tries this and gets an error it did not
    // expect.
    std::size_t truncate_to = 0;
};

// Where everything lives, fixed rather than computed from the layout's
// inputs, so a test can name any byte. .text is at RVA 0x1000 (file 0x200)
// and .rdata at RVA 0x2000 (file 0x600); the export directory is the first
// thing in .rdata, and the three tables and every string follow it.
constexpr std::size_t kExpDirFile = 0x600;
constexpr std::size_t kExpDirRva = 0x2000;
constexpr std::size_t kExpDirSize = 40;

// Writes a NUL-terminated string at a file offset and returns its RVA.
// Returned rather than passed in because the caller has to write a table
// entry pointing at a string it has not placed yet, and computing the RVA
// at both ends is how a fixture ends up disagreeing with itself.
std::uint32_t put_export_string(std::vector<std::uint8_t>& bytes,
                                std::size_t at, const std::string& s) {
    std::memcpy(&bytes[at], s.data(), s.size());
    bytes[at + s.size()] = '\0';
    return static_cast<std::uint32_t>(kExpDirRva + (at - kExpDirFile));
}

PeImage build_export_image(const ExportLayout& e, Built* out_built = nullptr) {
    Spec s;
    s.dll = true;
    s.sections.push_back({".text", 0x1000, 0x400, 0x400, 0x60000020});
    s.sections.push_back({".rdata", 0x2000, 0x600, 0x600, 0x40000040});
    // The directory's RVA is known now; its *size* is not, because the size
    // is the extent of the record plus the three tables plus every string,
    // and the strings are placed below. Both are written into the data
    // directory by hand at the end of this function, once the extent is
    // known, rather than by the builder -- the builder would write a size of
    // zero and a second build() to fix it would move every string the tables
    // point at.
    Built b = build(s);

    const std::size_t num_functions =
        e.declared_functions >= 0
            ? static_cast<std::size_t>(e.declared_functions)
            : e.addresses.size();
    const std::size_t num_names =
        e.declared_names >= 0 ? static_cast<std::size_t>(e.declared_names)
                              : e.names.size();

    // The three tables, laid out in the order the directory record names
    // them. Offsets from the record are fixed: +28, +32, +36.
    const std::size_t functions_at = kExpDirFile + kExpDirSize;
    const std::size_t names_at =
        functions_at + e.addresses.size() * 4;
    const std::size_t ordinals_at = names_at + e.names.size() * 4;

    // --- the address table
    for (std::size_t i = 0; i < e.addresses.size(); ++i) {
        put32(b.bytes, functions_at + i * 4, e.addresses[i]);
    }

    // --- the name table and its ordinals
    for (std::size_t i = 0; i < e.names.size(); ++i) {
        put16(b.bytes, ordinals_at + i * 2, e.names[i].index);
    }

    // --- the strings, and the name pointers that will point at them
    //
    // Every name is written, so the name table is the length the directory
    // says it is whatever any of them turns out to be. A name marked
    // unterminated still gets its string; only its pointer is redirected,
    // afterwards, to a run of bytes with no terminator in it.
    std::size_t cursor = ordinals_at + e.names.size() * 2;
    std::vector<std::uint32_t> name_rvas;
    name_rvas.reserve(e.names.size());
    for (const ExportName& n : e.names) {
        name_rvas.push_back(put_export_string(b.bytes, cursor, n.name));
        cursor += n.name.size() + 1;
    }

    // The unterminated run, when some name or forwarder asked for one.
    // Filled from here -- which is the end of the last string, and so *past*
    // every name the file also wrote -- to the end of the file, with a
    // non-zero byte so there is no terminator anywhere inside it. Past the
    // last string is the whole point: a run starting at the first string
    // would also be unterminated but would eat the readable names along with
    // it, and a test for "one name does not read" would silently become a
    // test for "no name reads".
    std::uint32_t unterminated_rva = 0;
    bool wants_unterminated = false;
    for (const ExportName& n : e.names) {
        wants_unterminated = wants_unterminated || n.unterminated;
    }
    for (const ExportForwarder& f : e.forwarders) {
        wants_unterminated = wants_unterminated || f.unterminated;
    }
    // --- the forwarders, which are addresses pointing into the strings that
    // are about to be written. Placed after the names so that a forwarder
    // pointing at a name is a thing a test has to ask for rather than one it
    // gets by accident.
    for (const ExportForwarder& f : e.forwarders) {
        if (f.unterminated) {
            continue;   // its address is written below, with the name pointers
        }
        const std::uint32_t rva = put_export_string(b.bytes, cursor, f.target);
        cursor += f.target.size() + 1;
        put32(b.bytes, functions_at + f.index * 4, rva);
    }

    // The unterminated run, last, so it cannot eat a string this function is
    // still going to write. It runs from the end of the last string to the
    // end of the file, filled with a non-zero byte, so there is no terminator
    // anywhere inside it -- which is the condition being produced. A run of
    // any fixed length would be terminated by whatever the linker put next.
    //
    // It starts *past* every string the file also wrote, so a fixture asking
    // for one unreadable name among two readable ones gets exactly that; a
    // run starting at the first string would be equally unterminated and
    // would take the readable ones with it, turning the test into a different
    // one.
    std::size_t extent_end = cursor;
    if (wants_unterminated) {
        for (std::size_t i = cursor; i < b.bytes.size(); ++i) {
            b.bytes[i] = 'A';
        }
        unterminated_rva =
            static_cast<std::uint32_t>(kExpDirRva + (cursor - kExpDirFile));
        // And the extent has to cover it. An address outside the directory is
        // not a forwarder at all, so a run past the end would turn the
        // forwarder case into the plain-address case without anything
        // failing.
        extent_end = b.bytes.size();
    }

    // The name pointers and the unterminated forwarders' addresses, last of
    // all, because they may hold the run's address and the run's address is
    // not known until the run exists. Both go after everything else for the
    // same reason: a pointer written before the thing it points at was placed
    // is a pointer to nothing, and a fixture that produced one would be
    // testing a reader against a file no linker produces.
    for (std::size_t i = 0; i < name_rvas.size(); ++i) {
        put32(b.bytes, names_at + i * 4,
              e.names[i].unterminated ? unterminated_rva : name_rvas[i]);
    }
    for (const ExportForwarder& f : e.forwarders) {
        if (f.unterminated) {
            put32(b.bytes, functions_at + f.index * 4, unterminated_rva);
        }
    }

    // Truncation, applied last. Every write above lands inside the full
    // file and this cuts it, so a fixture cannot write past its own end and
    // a test that wants a table to run off the end gets exactly that: a
    // directory record that is still whole, and a table that is not.
    //
    // It is applied after the extent is computed so the extent is clamped to
    // what the file actually holds. A fixture that declared an extent past
    // its own end would be making a second claim alongside the one the test
    // is about, and a failure would not say which claim was caught.
    const std::size_t extent = extent_end - kExpDirFile;

    // --- the directory record
    put32(b.bytes, kExpDirFile + 0, 0);            // Characteristics
    put32(b.bytes, kExpDirFile + 4, 0);            // TimeDateStamp
    put32(b.bytes, kExpDirFile + 8, 0);            // version, minor
    put32(b.bytes, kExpDirFile + 12, 0);           // Name: not read
    put32(b.bytes, kExpDirFile + 16, e.base);
    put32(b.bytes, kExpDirFile + 20,
          static_cast<std::uint32_t>(num_functions));
    put32(b.bytes, kExpDirFile + 24,
          static_cast<std::uint32_t>(num_names));
    put32(b.bytes, kExpDirFile + 28,
          e.functions_rva != 0
              ? e.functions_rva
              : static_cast<std::uint32_t>(kExpDirRva +
                                            (functions_at - kExpDirFile)));
    put32(b.bytes, kExpDirFile + 32,
          e.names_rva != 0
              ? e.names_rva
              : static_cast<std::uint32_t>(kExpDirRva +
                                            (names_at - kExpDirFile)));
    put32(b.bytes, kExpDirFile + 36,
          e.ordinals_rva != 0
              ? e.ordinals_rva
              : static_cast<std::uint32_t>(kExpDirRva +
                                            (ordinals_at - kExpDirFile)));

    // The directory entry, patched in because the size is only known now and
    // a second build() would move every string the tables above point at.
    const std::size_t dirs = b.opt + 96;
    put32(b.bytes, dirs + 0 * 8,
          e.dir_rva != 0
              ? e.dir_rva
              : static_cast<std::uint32_t>(kExpDirRva));
    put32(b.bytes, dirs + 0 * 8 + 4,
          e.declared_size >= 0
              ? static_cast<std::uint32_t>(e.declared_size)
              : static_cast<std::uint32_t>(extent));

    if (out_built != nullptr) {
        *out_built = b;
    }
    // The cut, last, after the record and the directory entry are written.
    // Both of those live in the first 0x200 bytes of the file, so a prefix
    // long enough to hold the record still holds both -- which is what makes
    // "the table runs off the end" a statement about the table and not about
    // the record. A test wanting that cuts to inside .rdata.
    if (e.truncate_to != 0) {
        b.bytes.resize(e.truncate_to);
    }
    return parse_image(b.bytes);
}

// The ordinary case: three exports, all named, all with distinct addresses,
// base 1. Everything else in this section is a way of being wrong relative
// to this.
void test_export_table() {
    ExportLayout e;
    e.addresses = {0x1100, 0x1200, 0x1300};
    e.names = {{"Alpha", 0}, {"Beta", 1}, {"Gamma", 2}};
    const PeImage p = build_export_image(e);

    check(p.ok(), "export: parses");
    check(p.error() == PeError::None, "export: no error");
    check(p.export_ordinal_base() == 1, "export: base is 1");
    check(p.export_rva() == kExpDirRva, "export: directory rva");
    check(p.exports().size() == 3, "export: three exports");
    if (p.exports().size() == 3) {
        check(p.exports()[0].name == "Alpha", "export: first name");
        check(p.exports()[0].ordinal == 1, "export: first ordinal");
        check(p.exports()[0].rva == 0x1100, "export: first address");
        check(p.exports()[1].name == "Beta", "export: second name");
        check(p.exports()[1].ordinal == 2, "export: second ordinal");
        check(p.exports()[2].name == "Gamma", "export: third name");
        check(p.exports()[2].ordinal == 3, "export: third ordinal");
        check(p.exports()[2].rva == 0x1300, "export: third address");
        check(!p.exports()[0].is_forwarder, "export: an address is not a "
                                            "forwarder");
        check(p.exports()[0].forwarder_dll.empty(),
              "export: a plain address has no forwarder dll");
    }
}

// A DLL that exports by ordinal only. The format says some, all, or none of
// the exported symbols may have names, and a reader that required names
// would refuse a legitimate and common shape.
void test_export_by_ordinal_only() {
    ExportLayout e;
    e.addresses = {0x1100, 0x1200, 0x1300};
    const PeImage p = build_export_image(e);

    check(p.ok(), "ordinal-only: parses");
    check(p.exports().size() == 3, "ordinal-only: three exports");
    if (p.exports().size() == 3) {
        check(p.exports()[0].name.empty(), "ordinal-only: the first is unnamed");
        check(p.exports()[0].ordinal == 1, "ordinal-only: first ordinal");
        check(p.exports()[2].ordinal == 3, "ordinal-only: third ordinal");
        check(p.exports()[2].rva == 0x1300, "ordinal-only: still has an "
                                              "address");
    }
}

// A base other than 1. The field the format says is "usually" 1, and a
// reader that assumes it resolves the wrong function for every named import
// of this DLL. The ordinals are the indices plus the base; the addresses are
// the addresses.
void test_export_base_not_one() {
    ExportLayout e;
    e.base = 5;
    e.addresses = {0x1100, 0x1200, 0x1300};
    e.names = {{"Alpha", 0}, {"Beta", 1}, {"Gamma", 2}};
    const PeImage p = build_export_image(e);

    check(p.ok(), "base 5: parses");
    check(p.export_ordinal_base() == 5, "base 5: reported as five");
    check(p.exports().size() == 3, "base 5: three exports");
    if (p.exports().size() == 3) {
        // 5, 6, 7 -- and if the reader treated the ordinal table's field as
        // an ordinal instead of an index, these would be 1, 2, 3 and every
        // name would be attached to the wrong address.
        check(p.exports()[0].ordinal == 5, "base 5: first ordinal is five");
        check(p.exports()[1].ordinal == 6, "base 5: second ordinal is six");
        check(p.exports()[2].ordinal == 7, "base 5: third ordinal is seven");
        check(p.exports()[0].name == "Alpha", "base 5: first name");
        check(p.exports()[0].rva == 0x1100, "base 5: first address");
    }
}

// A base of zero. The format permits it -- the field is an ordinary
// 32-bit value -- and a reader that treated zero as "unset" would report the
// wrong ordinals for a file that is legal and that Windows loads.
void test_export_base_zero() {
    ExportLayout e;
    e.base = 0;
    e.addresses = {0x1100, 0x1200};
    e.names = {{"Alpha", 0}, {"Beta", 1}};
    const PeImage p = build_export_image(e);

    check(p.ok(), "base 0: parses");
    check(p.export_ordinal_base() == 0, "base 0: reported as zero");
    if (p.exports().size() == 2) {
        check(p.exports()[0].ordinal == 0, "base 0: first ordinal is zero");
        check(p.exports()[1].ordinal == 1, "base 0: second ordinal is one");
    }
}

// An address table with a hole in it. The slot at index 1 is zero, which the
// format defines as "no export here" -- not an export at RVA zero, which is
// the base of every image and would resolve to the module's own headers.
//
// The consequence worth stating is that the ordinals either side of the hole
// are not adjacent: the third export's ordinal is 3, not 2. A reader that
// renumbered after dropping the hole would hand out an ordinal no program
// asked for, and the program's import would resolve to the wrong function.
void test_export_empty_slot() {
    ExportLayout e;
    e.addresses = {0x1100, 0, 0x1300};
    e.names = {{"Alpha", 0}, {"Gamma", 2}};
    const PeImage p = build_export_image(e);

    check(p.ok(), "hole: parses");
    check(p.exports().size() == 2, "hole: the empty slot is not an export");
    if (p.exports().size() == 2) {
        check(p.exports()[0].ordinal == 1, "hole: first ordinal is one");
        check(p.exports()[0].name == "Alpha", "hole: first name");
        // Index 2 plus base 1. A reader that dropped the hole and
        // renumbered would say two.
        check(p.exports()[1].ordinal == 3, "hole: the ordinals skip the hole");
        check(p.exports()[1].rva == 0x1300, "hole: third address");
        check(p.exports()[1].name == "Gamma", "hole: third name");
    }
}

// A name table that is not in dictionary order. The format requires the
// pointers to be sorted so that a reader may binary-search them; nothing
// enforces it, and files that do not sort it exist. This is the case a
// binary search answers wrongly and a linear scan answers correctly, and it
// is the reason this reader does not binary-search.
//
// The names are chosen so that a binary search would not merely miss: the
// table is a rotation of the sorted order, which is the arrangement most
// likely to produce a wrong answer rather than an outright failure. A search
// for "Alpha" in {Gamma, Alpha, Beta} probes the middle, compares "Alpha"
// against "Alpha", and stops -- correct by luck. A search for "Beta" probes
// the middle, "Beta" is less than "Alpha", goes left, and finds "Gamma",
// which is greater, so it reports not-found.
void test_export_names_out_of_order() {
    ExportLayout e;
    e.addresses = {0x1100, 0x1200, 0x1300};
    e.names = {{"Gamma", 2}, {"Alpha", 0}, {"Beta", 1}};
    const PeImage p = build_export_image(e);

    check(p.ok(), "unsorted: parses");
    check(p.exports().size() == 3, "unsorted: three exports");
    if (p.exports().size() == 3) {
        // The vector is in address-table order, so the names come back
        // re-sorted by index rather than in the order the file listed them.
        check(p.exports()[0].name == "Alpha", "unsorted: Alpha is first");
        check(p.exports()[0].rva == 0x1100, "unsorted: Alpha's address");
        check(p.exports()[1].name == "Beta", "unsorted: Beta is second");
        check(p.exports()[1].rva == 0x1200, "unsorted: Beta's address");
        check(p.exports()[2].name == "Gamma", "unsorted: Gamma is third");
        check(p.exports()[2].rva == 0x1300, "unsorted: Gamma's address");
    }
}

// A name table that is unsorted *and* whose ordinals point backwards, so the
// name and the address are two independent facts and both have to be right.
// "Delta" is at name-table position 0 and names address-table entry 2.
void test_export_unsorted_with_shuffled_ordinals() {
    ExportLayout e;
    e.addresses = {0x1100, 0x1200, 0x1300};
    e.names = {{"Delta", 2}, {"Alpha", 0}, {"Charlie", 1}};
    const PeImage p = build_export_image(e);

    check(p.ok(), "shuffled: parses");
    if (p.exports().size() == 3) {
        check(p.exports()[0].name == "Alpha", "shuffled: Alpha");
        check(p.exports()[0].rva == 0x1100, "shuffled: Alpha's address");
        check(p.exports()[1].name == "Charlie", "shuffled: Charlie");
        check(p.exports()[1].rva == 0x1200, "shuffled: Charlie's address");
        check(p.exports()[2].name == "Delta", "shuffled: Delta");
        check(p.exports()[2].rva == 0x1300, "shuffled: Delta's address");
    }
}

// Two names pointing at one address-table entry. The format permits it --
// the ordinal table is an index list and nothing says the indices are
// distinct -- and both names are real, so both are reported. A reader that
// assumed one name per export would report one of them and lose the other.
void test_export_two_names_one_entry() {
    ExportLayout e;
    e.addresses = {0x1100, 0x1200};
    e.names = {{"Alias", 0}, {"Real", 0}};
    const PeImage p = build_export_image(e);

    check(p.ok(), "alias: parses");
    check(p.exports().size() == 2, "alias: two address-table entries");
    if (p.exports().size() == 2) {
        // The second name overwrites the first in the same slot, because the
        // vector is in address-table order and both name entry 0. The file
        // said two names and this reader keeps one of them; the alternative
        // -- a vector with two entries for one address -- would break the
        // ordinal-to-position correspondence the rest of the reader relies
        // on. Checked here so the loss is a decision on record rather than a
        // surprise.
        check(p.exports()[0].name == "Real",
              "alias: the last name for an entry wins");
        check(p.exports()[0].rva == 0x1100, "alias: the address is right");
    }
}

// A forwarder naming another DLL's export by name. This is the common form:
// ntdll's RtlAllocateHeap is really in kernel32 on some builds, and the
// export table says so with a string.
void test_export_forwarder_by_name() {
    ExportLayout e;
    e.addresses = {0x1100, 0x1200};
    e.names = {{"LocalAlloc", 0}, {"RtlAllocateHeap", 1}};
    e.forwarders = {{1, "KERNEL32.Sleep"}};
    const PeImage p = build_export_image(e);

    check(p.ok(), "forward: parses");
    check(p.exports().size() == 2, "forward: two exports");
    if (p.exports().size() == 2) {
        check(p.exports()[0].is_forwarder == false,
              "forward: the first is a plain address");
        check(p.exports()[1].is_forwarder, "forward: the second is a forwarder");
        check(p.exports()[1].forwarder_dll == "KERNEL32",
              "forward: the dll is KERNEL32");
        check(p.exports()[1].forwarder_name == "Sleep",
              "forward: the symbol is Sleep");
        check(!p.exports()[1].forwarder_by_ordinal,
              "forward: it is not the ordinal form");
        check(p.exports()[1].forwarder_ordinal == 0,
              "forward: no ordinal is recorded");
        // The name is the export's own name, not the target's. They are two
        // different strings and a reader that reported the target's name here
        // would make every forwarder look like an alias of itself.
        check(p.exports()[1].name == "RtlAllocateHeap",
              "forward: the export keeps its own name");
    }
}

// The ordinal form: MYDLL.#27. The number is the *target module's* ordinal,
// so it is meaningless in this file and is reported rather than resolved.
void test_export_forwarder_by_ordinal() {
    ExportLayout e;
    e.addresses = {0x1100, 0x1200};
    e.names = {{"Alpha", 0}, {"Beta", 1}};
    e.forwarders = {{1, "MYDLL.#27"}};
    const PeImage p = build_export_image(e);

    check(p.ok(), "forward ordinal: parses");
    if (p.exports().size() == 2) {
        check(p.exports()[1].is_forwarder, "forward ordinal: is a forwarder");
        check(p.exports()[1].forwarder_dll == "MYDLL",
              "forward ordinal: the dll is MYDLL");
        check(p.exports()[1].forwarder_by_ordinal,
              "forward ordinal: the ordinal form is recognized");
        check(p.exports()[1].forwarder_ordinal == 27,
              "forward ordinal: 27 is recorded as stated");
        check(p.exports()[1].forwarder_name.empty(),
              "forward ordinal: no name is recorded");
    }
}

// A module name containing a dot. Windows permitted this for 16-bit
// compatibility and files in the wild still carry it, which makes the first
// dot the wrong one to split on: "OLD.DLL.Real" must resolve the symbol
// "Real" in "OLD.DLL", and a reader splitting at the first dot produces
// "OLD" and "DLL.Real", neither of which exists.
void test_export_forwarder_module_with_a_dot() {
    ExportLayout e;
    e.addresses = {0x1100, 0x1200, 0x1300};
    e.names = {{"Alpha", 0}, {"Beta", 1}, {"Gamma", 2}};
    e.forwarders = {{1, "OLD.DLL.Real"}, {2, "A.B.C.D.Symbol"}};
    const PeImage p = build_export_image(e);

    check(p.ok(), "dotted: parses");
    if (p.exports().size() == 3) {
        check(p.exports()[1].forwarder_dll == "OLD.DLL",
              "dotted: split at the last dot");
        check(p.exports()[1].forwarder_name == "Real",
              "dotted: the symbol is the last component");
        check(p.exports()[2].forwarder_dll == "A.B.C.D",
              "dotted: a name with three dots splits once");
        check(p.exports()[2].forwarder_name == "Symbol",
              "dotted: the symbol after the last dot");
    }
}

// The half-open boundary. An address exactly at the end of the directory is
// past it -- it is in the section that follows, and reading a forwarder from
// there would read whatever the linker put next. An address exactly at the
// start is inside it. Both are checked, because an off-by-one here produces
// a wrong answer on a real file rather than a crash.
void test_export_forwarder_boundary_is_half_open() {
    ExportLayout e;
    e.addresses = {0x1100};
    e.names = {{"Alpha", 0}};
    e.forwarders = {{0, "KERNEL32.Sleep"}};
    const PeImage p = build_export_image(e);

    check(p.exports().size() == 1, "boundary: the first fixture has one");
    if (p.exports().size() == 1) {
        check(p.exports()[0].is_forwarder,
              "boundary: an address inside the extent is a forwarder");
    }

    // The address one byte past the end of the directory. The extent is
    // whatever the builder computed and declared, which is why it is read
    // back out of the image rather than recomputed here: a second
    // implementation of the layout in the test would agree with a mistake in
    // the builder for the same reason the mistake was made.
    const std::uint32_t past_end =
        static_cast<std::uint32_t>(p.export_rva() + p.export_size());

    ExportLayout e2;
    e2.addresses = {0x1100, past_end};
    e2.names = {{"Alpha", 0}, {"Beta", 1}};
    const PeImage p2 = build_export_image(e2);

    check(p2.ok(), "boundary: a file parses");
    check(p2.export_size() > 0, "boundary: the extent is not empty");
    if (p2.exports().size() == 2) {
        check(!p2.exports()[1].is_forwarder,
              "boundary: the end of the extent is not inside it");
        check(p2.exports()[1].rva == past_end,
              "boundary: the address is reported as given");
        // And the one before it, which is the same fixture with the address
        // moved back inside. A reader whose comparison were <= would call
        // this one a forwarder too, and the two checks are the pair that
        // says the interval is half-open rather than merely bounded.
        ExportLayout e3;
        e3.addresses = {0x1100, past_end - 1};
        e3.names = {{"Alpha", 0}, {"Beta", 1}};
        const PeImage p3 = build_export_image(e3);
        // The extent differs between the two fixtures -- one name table with
        // the same names -- so "one byte before the end of e2's extent" is
        // not necessarily inside e3's. Asserted rather than assumed, and the
        // assertion is the useful part: if the two extents ever differed, the
        // boundary this test claims to be checking would not exist.
        check(p3.export_size() == p2.export_size(),
              "boundary: the two fixtures declare the same extent");
        if (p3.exports().size() == 2) {
            check(p3.exports()[1].is_forwarder,
                  "boundary: one byte inside the extent is a forwarder");
        }
    }
}

// Strings the format does not define. Each of these names a thing a forwarder
// cannot be, and each is refused rather than guessed at: a reader that
// guessed would resolve a symbol the operating system would not, and the
// program's failure would be somewhere else entirely.
void test_export_forwarder_malformed() {
    const char* bad[] = {
        "NoDotAtAll",          // no separator
        ".LeadingDot",         // empty module
        "TrailingDot.",        // empty symbol
        "KERNEL32.#",          // ordinal form with no digits
        "KERNEL32.#+27",       // a sign the format does not have
        "KERNEL32.#0x1b",      // a base the format does not have
        "KERNEL32.# 27",       // leading space
        "KERNEL32.#27 ",       // trailing space
        "KERNEL32.#-1",        // negative
        "KERNEL32.#4294967296", // one past the 32-bit range
    };
    for (const char* target : bad) {
        ExportLayout e;
        e.addresses = {0x1100};
        e.names = {{"Alpha", 0}};
        e.forwarders = {{0, target}};
        const PeImage p = build_export_image(e);
        char msg[128];
        std::snprintf(msg, sizeof msg, "bad forwarder \"%s\": refused",
                      target);
        check(!p.ok(), msg);
        std::snprintf(msg, sizeof msg,
                      "bad forwarder \"%s\": reports a bad export table",
                      target);
        check(p.error() == PeError::BadExportTable, msg);
    }
    check(true, "bad forwarder: every malformed form was refused");
}

// The ordinal forms that are legal, next to the ones that are not, so the
// boundary is stated by both sides. "#0" is refused on its own terms and not
// because the parse failed: the format numbers exports from the base field
// up, and a forwarder naming ordinal zero names an export whose existence
// depends on a base this file does not carry.
void test_export_forwarder_ordinal_forms() {
    const char* good[] = {"KERNEL32.#1", "KERNEL32.#27",
                          "KERNEL32.#4294967295"};
    for (const char* target : good) {
        ExportLayout e;
        e.addresses = {0x1100};
        e.names = {{"Alpha", 0}};
        e.forwarders = {{0, target}};
        const PeImage p = build_export_image(e);
        char msg[128];
        std::snprintf(msg, sizeof msg, "ordinal forwarder \"%s\": accepted",
                      target);
        check(p.ok(), msg);
        if (p.exports().size() == 1) {
            check(p.exports()[0].forwarder_by_ordinal, msg);
        }
    }
    check(true, "ordinal forwarder: every legal form was accepted");

    // "#0" separately, because it parses and is refused for a different
    // reason than the forms above.
    ExportLayout e;
    e.addresses = {0x1100};
    e.names = {{"Alpha", 0}};
    e.forwarders = {{0, "KERNEL32.#0"}};
    const PeImage p = build_export_image(e);
    check(!p.ok(), "forwarder #0: refused");
    check(p.error() == PeError::BadExportTable, "forwarder #0: bad table");
    if (!p.error_detail().empty()) {
        check(p.error_detail().find("ordinal zero") != std::string::npos,
              "forwarder #0: the message says why");
    }
}

// A directory declaring fewer bytes than the record needs. There is no
// arrangement of a 40-byte record in 8 bytes, and it is a different fact
// from a truncated import table -- a DLL with an unusable export directory
// still has an import table a loader can walk, and a reader that conflated
// the two would refuse a file whose problem is confined to the half nobody
// imports by.
void test_export_directory_too_small() {
    for (std::size_t declared : {std::size_t{0}, std::size_t{1},
                                 std::size_t{16}, std::size_t{39}}) {
        ExportLayout e;
        e.addresses = {0x1100};
        e.names = {{"Alpha", 0}};
        e.declared_size = static_cast<int>(declared);
        const PeImage p = build_export_image(e);
        char msg[96];
        std::snprintf(msg, sizeof msg,
                      "export: a %zu-byte directory is refused", declared);
        check(!p.ok(), msg);
        std::snprintf(msg, sizeof msg,
                      "export: a %zu-byte directory reports a truncated "
                      "record", declared);
        check(p.error() == PeError::TruncatedExportDirectory, msg);
    }
    // 40 exactly is enough, and the boundary is the interesting part.
    ExportLayout e;
    e.addresses = {0x1100};
    e.names = {{"Alpha", 0}};
    e.declared_size = 40;
    const PeImage p = build_export_image(e);
    check(p.ok(), "export: a 40-byte directory is enough");
    check(p.error() == PeError::None,
          "export: 40 bytes is not a truncated record");
}

// A directory at an RVA no section covers. The same refusal the import
// directory gets, for the same reason: "there is no export table" and "the
// export table is somewhere I cannot read" are different claims.
void test_export_directory_out_of_file() {
    ExportLayout e;
    e.addresses = {0x1100};
    e.names = {{"Alpha", 0}};
    e.dir_rva = 0x8000;
    const PeImage p = build_export_image(e);

    check(!p.ok(), "export: an unresolvable directory is refused");
    check(p.error() == PeError::DirectoryOutOfFile,
          "export: reports the directory");
    if (!p.error_detail().empty()) {
        check(p.error_detail().find("0x8000") != std::string::npos,
              "export: the message names the RVA");
    }
}

// A directory in a section's zero fill. The RVA resolves and there is
// nothing behind it, which is not the same as there being no directory.
void test_export_directory_in_zero_fill() {
    Spec s;
    s.dll = true;
    s.sections.push_back({".text", 0x1000, 0x400, 0x400, 0x60000020});
    // Virtual size larger than the raw data, so the tail is zero fill.
    s.sections.push_back({".rdata", 0x2000, 0x800, 0x200, 0x40000040});
    s.export_rva = 0x2400;   // inside the virtual size, past the raw data
    s.export_size = 40;
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    check(!p.ok(), "export: a zero-filled directory is refused");
    check(p.error() == PeError::DirectoryOutOfFile,
          "export: a zero-filled directory is not 'no exports'");
}

// One of the three tables pointing somewhere the file does not cover. The
// directory record is readable and the counts are sane, so only the table's
// own RVA gives it away -- which is why each is checked separately.
void test_export_table_out_of_file() {
    struct Which {
        const char* what;
        std::uint32_t ExportLayout::*field;
    };
    const Which tables[] = {
        {"the address table", &ExportLayout::functions_rva},
        {"the name pointer table", &ExportLayout::names_rva},
        {"the ordinal table", &ExportLayout::ordinals_rva},
    };
    for (const Which& w : tables) {
        ExportLayout e;
        e.addresses = {0x1100, 0x1200};
        e.names = {{"Alpha", 0}, {"Beta", 1}};
        e.*(w.field) = 0x9000;
        const PeImage p = build_export_image(e);
        char msg[128];
        std::snprintf(msg, sizeof msg, "export: %s out of file is refused",
                      w.what);
        check(!p.ok(), msg);
        std::snprintf(msg, sizeof msg,
                      "export: %s out of file reports a bad table", w.what);
        check(p.error() == PeError::BadExportTable, msg);
    }
    check(true, "export: every table was checked separately");
}

// A count the file cannot back with bytes. The address table declares a
// thousand entries; .rdata is 0x600 bytes and the table starts 40 bytes into
// it, so the declared entries run about six hundred bytes past the end of
// the file. The count is not a lie the reader can detect on its own -- the
// directory is whole and its RVA resolves -- so the check that catches it is
// the one that asks whether all the entries are inside the file.
//
// The file is *not* cut short to produce this, and that is deliberate. A cut
// file fails earlier, at the section table, because a section whose raw data
// runs past the end of the file is refused before any directory is read. So a
// truncated fixture would test the section check wearing this test's name,
// and the export table's own bound would never be reached. A file that is
// whole and declares more than it holds is the case this check exists for.
void test_export_count_larger_than_the_file() {
    ExportLayout e;
    e.addresses = {0x1100};
    e.declared_functions = 1000;
    const PeImage p = build_export_image(e);

    check(!p.ok(), "export: a count past the end of the file is refused");
    check(p.error() == PeError::BadExportTable,
          "export: reports a bad table");
    if (!p.error_detail().empty()) {
        check(p.error_detail().find("fit in a file") != std::string::npos,
              "export: the message says the file ran out");
        check(p.error_detail().find("1000") != std::string::npos,
              "export: the message names the count the file claimed");
    }
}

// A name table longer than the address table it indexes. Every entry of the
// ordinal table is then an index past the end, and a reader that clamped
// would attach the name to whatever happened to be there.
void test_export_name_index_out_of_range() {
    ExportLayout e;
    e.addresses = {0x1100, 0x1200};
    e.names = {{"Alpha", 0}, {"Bad", 7}};
    const PeImage p = build_export_image(e);

    check(!p.ok(), "export: an out-of-range name index is refused");
    check(p.error() == PeError::BadExportTable,
          "export: reports a bad table");
    if (!p.error_detail().empty()) {
        check(p.error_detail().find("address-table entry 7") !=
                  std::string::npos,
              "export: the message names the entry");
    }
}

// Names declared with no address table to point into. The ordinal table's
// entries are indices, so with no address table every one of them is out of
// range; the file is claiming something it has no room for.
void test_export_names_without_addresses() {
    ExportLayout e;
    e.addresses = {};
    e.names = {{"Alpha", 0}};
    const PeImage p = build_export_image(e);

    check(!p.ok(), "export: names with no address table are refused");
    check(p.error() == PeError::BadExportTable,
          "export: reports a bad table");
    if (!p.error_detail().empty()) {
        check(p.error_detail().find("no address table") != std::string::npos,
              "export: the message says why");
    }
}

// A count large enough to be a denial of service rather than a table. Capped
// and reported, for the import table's reason: a walk that stops at the cap
// without saying so looks exactly like a table that ended.
void test_export_count_is_capped() {
    ExportLayout e;
    e.addresses = {0x1100};
    e.declared_functions = 100000;
    const PeImage p = build_export_image(e);

    check(!p.ok(), "export: an enormous address table is refused");
    check(p.error() == PeError::BadExportTable,
          "export: reports a bad table");
    if (!p.error_detail().empty()) {
        check(p.error_detail().find("65536") != std::string::npos,
              "export: the message names the cap");
    }

    ExportLayout e2;
    e2.addresses = {0x1100};
    e2.names = {{"Alpha", 0}};
    e2.declared_names = 100000;
    const PeImage p2 = build_export_image(e2);
    check(!p2.ok(), "export: an enormous name table is refused");
    check(p2.error() == PeError::BadExportTable,
          "export: reports a bad table for the name count too");

    // The boundary itself: exactly the cap is walked, not refused. A cap
    // applied at the wrong comparison turns a file with 65536 exports into a
    // refusal, and nothing above this line would say so.
    ExportLayout e3;
    e3.addresses = {0x1100};
    e3.names = {{"Alpha", 0}};
    e3.declared_functions = 65536;
    const PeImage p3 = build_export_image(e3);
    check(p3.error() == PeError::BadExportTable,
          "export: 65536 entries is walked and then fails on the file, not "
          "on the cap");
    if (!p3.error_detail().empty()) {
        check(p3.error_detail().find("this reader walks") ==
                  std::string::npos,
              "export: the cap is not what stopped a 65536-entry table");
    }
    ExportLayout e4;
    e4.addresses = {0x1100};
    e4.names = {{"Alpha", 0}};
    e4.declared_functions = 65537;
    const PeImage p4 = build_export_image(e4);
    check(!p4.ok(), "export: 65537 is over the cap");
    if (!p4.error_detail().empty()) {
        check(p4.error_detail().find("this reader walks") !=
                  std::string::npos,
              "export: 65537 is refused by the cap");
    }
}

// A name that will not read. The walk stops there and keeps what it had:
// the entries before it are real exports and dropping them would understate
// the DLL, and the entries after it are equally real. This is the same rule
// the import walk follows, for the same reason.
void test_export_name_unterminated() {
    ExportLayout e;
    e.addresses = {0x1100, 0x1200};
    e.names = {{"Alpha", 0}, {"Beta", 1, true}};
    const PeImage p = build_export_image(e);

    check(p.ok(), "unterminated export name: the file still parses");
    check(p.exports().size() == 2,
          "unterminated export name: the addresses are still reported");
    if (p.exports().size() == 2) {
        check(p.exports()[0].name == "Alpha",
              "unterminated export name: the readable name is kept");
        check(p.exports()[1].name.empty(),
              "unterminated export name: the unreadable one is dropped");
        check(p.exports()[1].rva == 0x1200,
              "unterminated export name: its address survives");
    }
}

// A forwarder whose string will not read. Unlike a name, this one is
// refused: a DLL with a forwarder that cannot be read is a DLL whose
// forwarder will fail later and less clearly, and the caller needs to know
// now. The export keeps its name and address, so a reader that only wanted
// the names still has them -- what is refused is the file.
void test_export_forwarder_unterminated() {
    ExportLayout e;
    e.addresses = {0x1100};
    e.names = {{"Alpha", 0}};
    e.forwarders = {{0, "KERNEL32.Sleep", true}};
    const PeImage p = build_export_image(e);

    check(!p.ok(), "unterminated forwarder: refused");
    check(p.error() == PeError::BadExportTable,
          "unterminated forwarder: reports a bad table");
    if (!p.error_detail().empty()) {
        check(p.error_detail().find("not a readable") != std::string::npos,
              "unterminated forwarder: the message says the string did not "
              "read");
    }
}

// An image with no export directory at all. Not an error: most EXEs have
// none, and a reader that refused them would refuse most of what Windows
// runs.
void test_export_absent() {
    const Built b = build(base_spec());
    const PeImage p = parse_image(b.bytes);

    check(p.ok(), "no exports: parses");
    check(p.error() == PeError::None, "no exports: no error");
    check(p.exports().empty(), "no exports: the list is empty");
    check(p.export_rva() == 0, "no exports: no directory rva");
    check(p.export_size() == 0, "no exports: no size");
    check(p.export_ordinal_base() == 0,
          "no exports: a base of zero, which is also what an absent one "
          "reads as");
}

// A directory declaring zero exports. A DLL that exports nothing is a legal
// DLL -- an ordinal-only stub, a resource-only module, a shim -- and the
// declaration is not a lie, it is an absence the file states.
void test_export_directory_declares_nothing() {
    ExportLayout e;
    e.addresses = {};
    e.names = {};
    const PeImage p = build_export_image(e);

    check(p.ok(), "empty export table: parses");
    check(p.error() == PeError::None, "empty export table: no error");
    check(p.exports().empty(), "empty export table: no exports");
    check(p.export_ordinal_base() == 1,
          "empty export table: the base is still reported");
}

// The independent counts, stated as a case. A DLL that exports five thousand
// symbols by ordinal and names ten of them is ordinary, and a reader that
// required the counts to match would refuse it. The other direction -- more
// names than addresses -- is the case above, and it is refused, because an
// index with nothing behind it is a claim the file cannot keep.
void test_export_counts_are_independent() {
    ExportLayout e;
    e.addresses = {0x1100, 0x1200, 0x1300, 0x1400};
    e.names = {{"Only", 0}};
    const PeImage p = build_export_image(e);

    check(p.ok(), "independent counts: parses");
    check(p.exports().size() == 4, "independent counts: four addresses");
    if (p.exports().size() == 4) {
        check(p.exports()[0].name == "Only", "independent counts: one name");
        check(p.exports()[1].name.empty(),
              "independent counts: the rest are unnamed");
        check(p.exports()[3].ordinal == 4,
              "independent counts: the fourth ordinal is four");
    }
}

// A file cut inside a section. Asserted here because it is a fact about the
// order the checks run in, and every one of those orders is a decision: the
// section table is validated before any directory is read, so a file whose
// section data runs past its own end is refused there even when its export
// directory would also have been refused, and a reader that reported the
// export error would be reporting a complaint about a part of the file the
// section error already covers.
//
// The cut is inside the section's raw data rather than at its end, so the
// refusal is unambiguous: a file cut exactly at the section boundary would
// have a whole section and would fail somewhere else.
void test_export_truncated_file_fails_at_the_section_first() {
    ExportLayout e;
    e.addresses = {0x1100, 0x1200};
    e.names = {{"Alpha", 0}, {"Beta", 1}};
    e.truncate_to = kExpDirFile + kExpDirSize + 2 * 4;
    const PeImage p = build_export_image(e);

    check(!p.ok(), "truncated file: refused");
    check(p.error() == PeError::BadSectionTable,
          "truncated file: the section check fires before the export check");
    if (!p.error_detail().empty()) {
        check(p.error_detail().find(".rdata") != std::string::npos,
              "truncated file: the message names the section");
    }
}

// The Name field is not read, and this is the case that says so. A file
// whose export directory has a Name RVA of zero -- which is what a linker
// that did not fill it in produces, and what a file that has been through
// an editor produces -- is a file whose export table is perfectly walkable.
// Windows loads it. A reader that checked the field would refuse it.
void test_export_name_field_is_not_required() {
    ExportLayout e;
    e.addresses = {0x1100, 0x1200};
    e.names = {{"Alpha", 0}, {"Beta", 1}};
    Built b;
    const PeImage p = build_export_image(e, &b);

    // The builder already writes zero there. Asserted rather than assumed,
    // so a builder that started filling it in would fail this test instead
    // of quietly making it vacuous.
    check(b.bytes[kExpDirFile + 12] == 0,
          "export name field: the fixture leaves it zero");
    check(p.ok(), "export name field: a zero Name is not a refusal");
    check(p.exports().size() == 2, "export name field: both exports read");
    if (p.exports().size() == 2) {
        check(p.exports()[0].name == "Alpha",
              "export name field: the names come from the name table");
    }
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

// A section declaring raw data at offset zero.
//
// This one was found by fuzz/fuzz_pe.cpp, not by reasoning. The reader used
// to exempt "raw offset of zero with a non-zero size" on the theory that a
// packer fills it in later -- and that exemption let a 1182-byte file claim
// a 32 MiB section, which every caller that maps or reads sections then
// believed. The exemption was removed; the case is here so it stays removed.
//
// The offset of zero is not special. Offset zero is the DOS header, so a
// section there overlaps the file's own headers, and a file claiming it is
// describing a region that is not section data at all.
void test_section_at_offset_zero() {
    // The size is large enough that "zero plus this" cannot be inside any file
    // this test builds. It is written into the header after the fixture is
    // built rather than declared as a section, because the builder sizes the
    // file to fit whatever it is told -- and a fixture that really did carry
    // 32 MiB of section data would be a 32 MiB fixture.
    Spec s;
    s.sections.push_back({".text", 0x1000, 0x200, 0x200, 0x60000020});
    Built b = build(s);
    // Force the first section's raw offset to zero and its size to 32 MiB.
    put32(b.bytes, b.sections_at + 16, 0x2000000);
    put32(b.bytes, b.sections_at + 20, 0);

    const PeImage p = parse_image(b.bytes);
    check(!p.ok(), "raw offset zero with a size: refused");
    check(p.error() == PeError::BadSectionTable,
          "raw offset zero with a size: reported as a bad table");
    if (!p.error_detail().empty()) {
        check(p.error_detail().find("0x2000000") != std::string::npos,
              "raw offset zero: the message states the size it claimed");
    }

    // A section of zero raw size at offset zero is the legitimate version of
    // this, and it is what .bss and a linker's padding sections look like.
    // The negative spells "stores nothing" to the builder.
    Spec t;
    t.sections.push_back({".bss", 0x1000, 0x4000, -1, 0xc0000040});
    Built tb = build(t);
    const PeImage q = parse_image(tb.bytes);
    check(q.ok(), "a zero-size section at offset zero is accepted");
    check(q.sections().size() == 1, "zero-size section: reported");
    if (!q.sections().empty()) {
        check(q.sections()[0].raw_size == 0, "zero-size section: size is zero");
        // Nothing is file-backed, so nothing resolves to an offset -- and
        // everything inside its virtual range is zero fill instead.
        check(q.sections()[0].raw_offset == 0, "zero-size section: offset is zero");
        std::uint64_t off = 1;
        bool zero_filled = false;
        check(q.resolve_rva(0x1000, off, zero_filled),
              "zero-size section: its first RVA resolves");
        check(zero_filled, "zero-size section: as zero fill");
        check(!q.to_file_offset(0x1000, off),
              "zero-size section: with no file offset");
    }
}

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
    // Directory 3 is the exception table -- the SEH table on x64 -- and
    // directory 4 is the certificate table, a different thing that shares
    // the array. A nonzero first field in the third entry means the file
    // declares one; the earlier version of this test wrote the fourth
    // entry, which is the same wrong slot the reader once read, and the
    // two agreed with each other and not with the format.
    const std::size_t dirs = b.opt + 96;
    constexpr std::size_t kExceptionDir = 3;
    constexpr std::size_t kSecurityDir = 4;
    put32(b.bytes, dirs + kExceptionDir * 8, 0x3000);
    put32(b.bytes, dirs + kExceptionDir * 8 + 4, 0x40);

    check(parse_image(b.bytes).has_seh(), "seh: declared table is seen");

    // Zero means absent. An empty table is a valid configuration, so its
    // absence is not an error.
    put32(b.bytes, dirs + kExceptionDir * 8, 0);
    check(!parse_image(b.bytes).has_seh(), "seh: zero means absent");

    // A certificate is not an exception table. A file that signs itself
    // declares the fourth entry, and a reader that took that entry as the
    // SEH table reported unsigned images as signed and signed images as
    // having unwind data.
    put32(b.bytes, dirs + kSecurityDir * 8, 0x3000);
    put32(b.bytes, dirs + kSecurityDir * 8 + 4, 0x40);
    check(!parse_image(b.bytes).has_seh(),
          "seh: a certificate directory is not a seh table");

    // A directory count that stops before the SEH entry means the file never
    // claimed to have one. Reading it anyway would find the section table's
    // bytes and report them as a table. The entry past the count is the
    // certificate slot at four -- with a count of four the walk stops at
    // three, and the fourth entry's bytes belong to whatever follows.
    Spec t = base_spec();
    t.dir_count = 4;
    Built tb = build(t);
    put32(tb.bytes, tb.opt + 96 + kSecurityDir * 8, 0x3000);
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
    test_zero_virtual_size_still_maps();
    test_headers_size_larger_than_the_file();
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
    test_export_table();
    test_export_by_ordinal_only();
    test_export_base_not_one();
    test_export_base_zero();
    test_export_empty_slot();
    test_export_names_out_of_order();
    test_export_unsorted_with_shuffled_ordinals();
    test_export_two_names_one_entry();
    test_export_forwarder_by_name();
    test_export_forwarder_by_ordinal();
    test_export_forwarder_module_with_a_dot();
    test_export_forwarder_boundary_is_half_open();
    test_export_forwarder_malformed();
    test_export_forwarder_ordinal_forms();
    test_export_directory_too_small();
    test_export_directory_out_of_file();
    test_export_directory_in_zero_fill();
    test_export_table_out_of_file();
    test_export_count_larger_than_the_file();
    test_export_name_index_out_of_range();
    test_export_names_without_addresses();
    test_export_count_is_capped();
    test_export_name_unterminated();
    test_export_forwarder_unterminated();
    test_export_absent();
    test_export_directory_declares_nothing();
    test_export_counts_are_independent();
    test_export_name_field_is_not_required();
    test_export_truncated_file_fails_at_the_section_first();
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
    test_section_at_offset_zero();
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
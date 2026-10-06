// Address space and image loader tests.
//
// Two layers are under test here and they are tested separately, because
// they fail differently. An address space that records a region it should
// have refused produces a map that disagrees with the memory, and an image
// loader that maps a section it should have refused produces a program that
// faults at an address the file named. Neither is visible from the other.
//
// Every case below is written as the case that would pass if a constraint
// were missing. That is the standard these tests are held to: a test that
// passes both with and against the code is not a test, and the comment on
// each one says which constraint it is pinning down.
//
// The fixture builder is the one from test_pe.cpp, repeated rather than
// shared. A shared builder would mean a change made for one test's
// convenience silently changes what the other one is testing, and the
// duplication here is a few dozen lines of arithmetic against a format that
// does not change.

#include "occ/parser/pe.h"
#include "occ/runtime/address_space.h"
#include "occ/runtime/loader.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <unistd.h>
#include <vector>

using namespace occ::parser;
using namespace occ::runtime;
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

// Defined far below with the fixtures that map. Declared here because the
// loader cases reach it before its definition, and the file is organized
// around the loader rather than around the helper.
std::uint64_t claim_a_base(std::uint64_t bytes) noexcept;

// ---------------------------------------------------------- PE fixture

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

constexpr std::size_t kDosSize = 64;
constexpr std::size_t kCoffSize = 20;
constexpr std::size_t kSectionHeaderSize = 40;
constexpr std::size_t kOptSize32 = 224;
constexpr std::size_t kOptSize64 = 240;

// IMAGE_SCN_*. The three bits a section's protection is derived from.
constexpr std::uint32_t kScnExecute = 0x20000000;
constexpr std::uint32_t kScnRead = 0x40000000;
constexpr std::uint32_t kScnWrite = 0x80000000;

struct SectionSpec {
    const char* name = nullptr;
    std::uint32_t virtual_address = 0;
    std::uint32_t virtual_size = 0;
    // Zero means "one page of file data"; negative means "no file data at
    // all", which is what .bss is. The distinction is load-bearing for the
    // loader: a section with no file part still occupies address space.
    std::int32_t raw_size = 0;
    std::uint32_t characteristics = 0;
};

struct Spec {
    bool plus = true;
    bool dll = false;
    std::uint16_t machine = 0x8664; // AMD64
    std::uint16_t subsystem = 3;
    std::uint32_t entry = 0x1000;
    // A constant, and deliberately so. Only the fixtures that *really* map --
    // the TLS ones, which hand a `Mapper` to `load_image` -- may not name a
    // fixed address, because AddressSanitizer reserves 4 GiB through 128 TiB
    // and that is every address a 64-bit PE can be based in below kUserMax.
    // Those ask the kernel instead; see claim_a_base. The fixtures that pass
    // an empty LoadContext make no mapping at all, so for them a fixed base
    // costs nothing and says something: a test that only reads a ledger does
    // not care where the image would have gone, and one that varies the base
    // per fixture would be varying something it does not observe.
    std::uint64_t base = 0x0000000140000000ull;
    // Overrides SizeOfImage after the builder has computed one. -1 means
    // "no override", and it is -1 rather than 0 because 0 is a value a
    // fixture may legitimately want to write: an image that declares a size
    // of zero is exactly the case one of the tests is about, and a sentinel
    // of 0 makes that case unexpressible. The two other zero-means-default
    // fields in this struct have the same hazard and are documented where
    // they are declared.
    std::int64_t image_size_override = -1;
    // Overrides SizeOfHeaders. -1 means "no override", for the same reason.
    std::int64_t headers_size_override = -1;
    // Truncates the finished file to this many bytes. -1 means "no
    // truncation", for the same reason the other two overrides do. It exists
    // because a header can *reach* a field it does not *contain*: the
    // optional header's declared size can cover the data directory array
    // while the file stops in the middle of it, and every reader that takes
    // the file's word for where the array ends then reads past the end. No
    // other knob produces that shape -- a smaller image size changes what the
    // loader believes about the extent, a smaller header size changes what
    // the parser believes, and neither makes the bytes stop existing.
    std::int64_t truncate_to = -1;
    // The optional header's own declared size, in bytes. Zero means the
    // layout's natural size, which is what every linker emits: 240 for PE32+
    // with all sixteen directories, 224 for PE32.
    //
    // It is a parameter because it is a *claim* the file makes about itself
    // and the reader is supposed to check, and no other knob makes a false
    // one. A header can declare an optional header that ends before its own
    // data directory array does, which says the array is not there; every
    // offset computed from the fixed layout then names a byte the file never
    // claimed to have. The parser checks this -- it reads only where the
    // header reaches and clamps the directory count to what fits -- and a
    // reader that takes the fixed layout instead reads wherever the file
    // happens to end, or past it.
    std::uint32_t optional_size = 0;
    // The relocation directory, as an RVA and a size. Zero means none. The
    // RVA has to point at the tail, whose file offset the builder reports
    // as Built::tail_at -- a tail sits in no section, so a fixture that
    // wants a directory there raises SizeOfHeaders to cover it.
    std::uint32_t reloc_rva = 0;
    std::uint32_t reloc_size = 0;
    std::vector<SectionSpec> sections;
    // Real bytes to write inside a named section, keyed by the section's
    // index in `sections`. See the note in build().
    std::vector<std::pair<std::size_t, std::vector<std::uint8_t>>>
        section_content;
    // Bytes appended after the section data, for a relocation table.
    std::vector<std::uint8_t> tail;
    // The TLS directory, as the data-directory entry names it: an RVA and a
    // size. Zero means the image declares no TLS at all, which is the case
    // for every fixture that does not set it and is itself worth testing.
    std::uint32_t tls_rva = 0;
    std::uint32_t tls_size = 0;
    // NumberOfRvaAndSizes. Sixteen unless a fixture says otherwise, which is
    // what every linker emits and what the reader therefore assumes; a fixture
    // that sets it lower writes a data directory array that stops early, and
    // one that sets it higher writes a header that claims directories the
    // file does not carry. Both are legal encodings and both are shapes a
    // file can disagree with itself about, so the field is a parameter rather
    // than a constant. The TLS entry is number 9, so a count of 8 is the
    // smallest value that leaves the loader's own directory unreachable while
    // keeping the eight before it.
    std::uint32_t directory_count = 16;
    // Overwrites the directory's own fields, for the fixtures that need a
    // specific one to be wrong. A nullopt means "derive from the section the
    // TLS RVA lands in", which is what a real linker's output looks like and
    // what every well-formed fixture wants. Set, these replace the derived
    // values field by field -- and a fixture that sets one and not the others
    // gets a directory with a real field next to a fabricated one, which is
    // a shape no linker emits and which is exactly what several of the
    // malformed cases need.
    struct TlsFields {
        std::uint32_t start = 0;
        std::uint32_t end = 0;
        std::uint32_t index = 0;
        std::uint32_t zero_fill = 0;
        std::uint32_t callbacks = 0;
        std::uint32_t characteristics = 0;
        bool have_callbacks_field = true;
    };
    std::optional<TlsFields> tls_fields;
    // The virtual address of the section the TLS template lives in, used to
    // derive the template's start and end when `tls_fields` is not given.
    // Zero means "derive from the first readable section", which is what
    // makes the common case a two-field spec.
    std::uint32_t tls_template_rva = 0;
    std::uint32_t tls_template_size = 0;
    // Real bytes for the callback array, written into the section at
    // `tls_callbacks_rva`. Nullopt means the array is a single null
    // terminator, which is what a module with no callbacks has.
    std::optional<std::vector<std::uint8_t>> tls_callback_bytes;
    std::uint32_t tls_callbacks_rva = 0;
};

struct Built {
    std::vector<std::uint8_t> bytes;
    std::size_t tail_at = 0;
};

Built build(const Spec& s) {
    Built b;
    const std::size_t opt_size = s.plus ? kOptSize64 : kOptSize32;
    const std::size_t coff = kDosSize + 4;
    const std::size_t opt = coff + 4 + kCoffSize;
    // The section table starts where the optional header *says* it starts,
    // which is what a reader uses and not what the layout would have put
    // there. A fixture that shortens the optional header therefore moves the
    // table with it -- and that is the point: the file's claim and the
    // layout's expectation are two different numbers, and a fixture can
    // only disagree with itself by disagreeing about one of them.
    const std::size_t declared_opt =
        s.optional_size != 0 ? s.optional_size : opt_size;
    const std::size_t sections_at = opt + declared_opt;
    const std::size_t headers_size = 0x200;

    std::size_t cursor = headers_size;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> layout;
    for (const SectionSpec& sec : s.sections) {
        if (sec.raw_size < 0) {
            layout.emplace_back(0u, 0u);
            continue;
        }
        const std::uint32_t raw =
            sec.raw_size != 0 ? static_cast<std::uint32_t>(sec.raw_size) : 0x200;
        layout.emplace_back(static_cast<std::uint32_t>(cursor), raw);
        cursor += raw;
    }
    b.tail_at = cursor;
    b.bytes.assign(b.tail_at + s.tail.size(), 0);
    if (!s.tail.empty()) {
        std::memcpy(&b.bytes[b.tail_at], s.tail.data(), s.tail.size());
    }

    // A section with no content of the file's own is a section of zeros,
    // which is what .bss is and what most fixtures want. But a fixture that
    // places real bytes in a section -- a relocation table, an import
    // table -- needs them inside that section, and the only way to say so
    // is 4-byte field writes below. This hook lets a spec name the bytes of
    // one section by index so that the section's declared raw extent really
    // contains them.
    for (const auto& [index, content] : s.section_content) {
        if (index >= layout.size() || layout[index].second < content.size()) {
            continue;
        }
        const std::size_t at = layout[index].first;
        if (at + content.size() <= b.bytes.size()) {
            std::memcpy(&b.bytes[at], content.data(), content.size());
        }
    }

    put16(b.bytes, 0, 0x5a4d);
    put32(b.bytes, 0x3c, static_cast<std::uint32_t>(coff));
    put32(b.bytes, coff, 0x00004550);

    const std::size_t c = coff + 4;
    put16(b.bytes, c + 0, s.machine);
    put16(b.bytes, c + 2, static_cast<std::uint16_t>(s.sections.size()));
    put16(b.bytes, c + 16,
          static_cast<std::uint16_t>(s.optional_size != 0
                                         ? s.optional_size
                                         : opt_size));
    put16(b.bytes, c + 18,
          static_cast<std::uint16_t>(s.dll ? 0x2000 : 0x0002));

    const std::size_t o = opt;
    put16(b.bytes, o + 0, s.plus ? 0x20b : 0x10b);
    b.bytes[o + 2] = 14;                       // MajorLinkerVersion
    put32(b.bytes, o + 4, 0x200);              // SizeOfCode
    put32(b.bytes, o + 16, s.entry);           // AddressOfEntryPoint
    put32(b.bytes, o + 20, 0x1000);            // BaseOfCode
    if (s.plus) {
        put64(b.bytes, o + 24, s.base);
    } else {
        put32(b.bytes, o + 28, static_cast<std::uint32_t>(s.base));
    }
    put32(b.bytes, o + 32, 0x1000);            // SectionAlignment
    put32(b.bytes, o + 36, 0x200);             // FileAlignment
    put16(b.bytes, o + 40, 4);                 // MajorOperatingSystemVersion
    // SizeOfImage must cover every section's extent, because the loader
    // checks the headers against it. The builder computes it rather than
    // taking a value, so a test that wants a bad one overrides it.
    std::uint32_t image_size = 0x2000;
    for (const SectionSpec& sec : s.sections) {
        std::uint32_t vsz =
            sec.virtual_size != 0 ? sec.virtual_size
                                  : (sec.raw_size > 0
                                         ? static_cast<std::uint32_t>(sec.raw_size)
                                         : 0);
        vsz = (vsz + 0xfff) & ~0xfffu;
        const std::uint32_t end = sec.virtual_address + vsz;
        if (end > image_size) {
            image_size = end;
        }
    }
    put32(b.bytes, o + 56,
          s.image_size_override >= 0
              ? static_cast<std::uint32_t>(s.image_size_override)
              : image_size);
    put32(b.bytes, o + 60,
          s.headers_size_override >= 0
              ? static_cast<std::uint32_t>(s.headers_size_override)
              : headers_size);
    put16(b.bytes, o + 68, s.subsystem);
    put16(b.bytes, o + 70, 0x0160);            // ASLR | NX | high-entropy

    const std::size_t dirs = o + (s.plus ? 112 : 96);
    const std::size_t count_at = o + (s.plus ? 108 : 92);
    put32(b.bytes, count_at, s.directory_count);
    if (s.reloc_rva != 0) {
        put32(b.bytes, dirs + 5 * 8, s.reloc_rva);
        put32(b.bytes, dirs + 5 * 8 + 4, s.reloc_size);
    }
    // The TLS directory is entry 9. Written even when `tls_size` is 0,
    // because the loader looks at the RVA and not at the size -- and a
    // fixture that wanted a zero size with a real RVA is expressing "a
    // directory the header claims no bytes for", which is a case worth
    // being able to write.
    if (s.tls_rva != 0) {
        put32(b.bytes, dirs + 9 * 8, s.tls_rva);
        put32(b.bytes, dirs + 9 * 8 + 4, s.tls_size);
    }

    for (std::size_t i = 0; i < s.sections.size(); ++i) {
        const SectionSpec& sec = s.sections[i];
        const std::size_t sh = sections_at + i * kSectionHeaderSize;
        const std::string name = sec.name != nullptr ? sec.name : "";
        std::memcpy(&b.bytes[sh], name.data(),
                    name.size() < 8 ? name.size() : 8);
        put32(b.bytes, sh + 8, sec.virtual_size);
        put32(b.bytes, sh + 12, sec.virtual_address);
        put32(b.bytes, sh + 16, layout[i].second);
        put32(b.bytes, sh + 20, layout[i].first);
        put32(b.bytes, sh + 36, sec.characteristics);
    }

    // ---------------------------------------------------------- TLS directory
    //
    // The directory is nine DWORDs on PE32+ and five on PE32, and the fields
    // are *virtual addresses* -- the image base plus an RVA -- because the
    // loader reads them out of the mapped image and there the addresses have
    // to be real. A fixture that wrote RVAs here would produce a directory
    // that looks right in a hex dump and describes memory at 0x1000, which
    // is where the DOS header lives. Every field below is therefore
    // `s.base + rva`, and `s.base` is the same base the section headers were
    // laid out against.
    if (s.tls_rva != 0) {
        // Where the directory's own bytes live in the file. The RVA has to
        // resolve through the parser, and the parser resolves it through the
        // sections -- so the directory is written into the raw part of
        // whichever section contains it, using the same offset arithmetic
        // `section_content` uses. The section is found by asking which one
        // covers the RVA, and a fixture whose `tls_rva` lands in no section
        // gets no directory written at all, which is itself a case worth
        // having: the loader then finds the RVA unresolvable and refuses,
        // rather than reading whatever bytes happened to be at the file
        // offset the arithmetic produced.
        std::size_t host = s.sections.size();
        std::size_t host_file_at = 0;
        for (std::size_t i = 0; i < s.sections.size(); ++i) {
            const std::uint32_t va = s.sections[i].virtual_address;
            const std::uint32_t vsz = s.sections[i].virtual_size;
            if (s.tls_rva >= va && s.tls_rva < va + vsz) {
                host = i;
                host_file_at = layout[i].first + (s.tls_rva - va);
                break;
            }
        }
        if (host < s.sections.size() &&
            host_file_at + 24 <= b.bytes.size()) {
            // The template's bounds default to the first section, so the
            // common fixture -- "this image has TLS" -- is two fields rather
            // than six. A fixture that sets `tls_fields` says all of them,
            // because a directory with one fabricated field and five derived
            // ones is a shape no linker emits.
            Spec::TlsFields f;
            if (s.tls_fields.has_value()) {
                f = *s.tls_fields;
            } else {
                const std::uint32_t tva = s.tls_template_rva != 0
                                              ? s.tls_template_rva
                                              : 0x1000;
                // Encoded the way a linker would encode it for this base.
                //
                // The fields are 32 bits, so a base at or above 4 GiB cannot
                // be written as a virtual address at all -- `base + tva`
                // truncated to 32 bits is a number that means nothing. Every
                // modern linker emits the RVA form for a 64-bit image, and
                // it is the only form that survives the image moving. A base
                // that fits in 32 bits gets the VA form, which is what the
                // specification describes and what the low-base fixtures
                // below exercise.
                //
                // The choice is made here, in the fixture, rather than
                // papered over in the loader: a fixture that wrote a
                // truncated VA and expected the loader to guess would be
                // testing the guess instead of the format.
                const bool va_fits =
                    s.base + tva + s.tls_template_size <= 0xFFFFFFFFull;
                const std::uint64_t enc = va_fits ? s.base : 0;
                f.start = static_cast<std::uint32_t>(enc + tva);
                f.end = static_cast<std::uint32_t>(
                    enc + tva + s.tls_template_size);
                f.index = static_cast<std::uint32_t>(enc + 0x2000);
                f.zero_fill = s.tls_template_size;
                f.callbacks = 0;
            }
            // The fields are written as 32-bit even on PE32+. That is not a
            // simplification: the structure really is five DWORDs there, and
            // a PE32 fixture that wrote eight-byte fields would have the
            // loader read its own padding. The last four bytes of a PE32+
            // directory are the callback field, and a PE32 image leaves them
            // out of the structure entirely -- which the loader's
            // `have_callbacks_field` records and one of the tests pins down.
            put32(b.bytes, host_file_at + 0, f.start);
            put32(b.bytes, host_file_at + 4, f.end);
            put32(b.bytes, host_file_at + 8, f.index);
            put32(b.bytes, host_file_at + 12, f.zero_fill);
            put32(b.bytes, host_file_at + 16, f.characteristics);
            // The sixth DWORD is written for a PE32 image too, and this is
            // the whole point of writing it: those four bytes are *not* part
            // of a PE32 directory, so whatever a linker happened to leave
            // after the structure is sitting there in the file, and a loader
            // that reads six DWORDs from a PE32 image will believe it. A
            // fixture that left the bytes zero could not tell those two
            // loaders apart -- which is exactly why this write is
            // unconditional while the loader's read is not. A real PE32
            // image has whatever follows the directory, and a fixture that
            // does not put anything there is not describing one.
            put32(b.bytes, host_file_at + 20, f.callbacks);

            // The callback array, when the fixture gave one. Written into
            // the file at the RVA the directory names, through the same
            // section lookup, because an array the loader cannot reach is an
            // array no fixture could test.
            if (s.tls_callback_bytes.has_value() &&
                !s.tls_callback_bytes->empty()) {
                std::size_t arr = s.sections.size();
                std::size_t arr_file_at = 0;
                for (std::size_t i = 0; i < s.sections.size(); ++i) {
                    const std::uint32_t va = s.sections[i].virtual_address;
                    const std::uint32_t vsz = s.sections[i].virtual_size;
                    if (s.tls_callbacks_rva >= va &&
                        s.tls_callbacks_rva + 1 < va + vsz) {
                        arr = i;
                        arr_file_at =
                            layout[i].first + (s.tls_callbacks_rva - va);
                        break;
                    }
                }
                if (arr < s.sections.size() &&
                    arr_file_at + s.tls_callback_bytes->size() <=
                        b.bytes.size()) {
                    std::memcpy(&b.bytes[arr_file_at],
                                s.tls_callback_bytes->data(),
                                s.tls_callback_bytes->size());
                }
            }
        }
    }

    // The truncation, last, so that everything above was written into a file
    // that was then shortened -- which is the only order that produces the
    // shape this is for. Truncating first and then writing would put the
    // headers back.
    if (s.truncate_to >= 0) {
        const std::size_t keep =
            static_cast<std::size_t>(s.truncate_to) < b.bytes.size()
                ? static_cast<std::size_t>(s.truncate_to)
                : b.bytes.size();
        b.bytes.resize(keep);
        // The section layout the builder computed described the whole file,
        // and a reader of the truncated one will not agree with it. The
        // offsets are kept because `Built` exposes them for fixtures that
        // want to say where something *was*; nothing reads them as offsets
        // into the shortened file.
    }

    return b;
}

PeImage parse_image(const std::vector<std::uint8_t>& bytes) {
    return PeImage::parse(ByteSpan{bytes.data(), bytes.size()});
}

// What an ordinal-import resolver records when it is called. A named
// struct rather than a pair of captured locals because the resolver is a
// plain function pointer and has nowhere else to put what it learns.
struct OrdinalSeen {
    std::uint16_t ordinal = 0;
    bool by_ordinal = false;
    bool called = false;
};

// A relocation block: PageRVA, BlockSize, then entries.
std::vector<std::uint8_t> reloc_block(std::uint32_t page_rva,
                                      std::vector<std::uint16_t> entries) {
    std::vector<std::uint8_t> out(8 + entries.size() * 2, 0);
    put32(out, 0, page_rva);
    put32(out, 4, static_cast<std::uint32_t>(out.size()));
    for (std::size_t i = 0; i < entries.size(); ++i) {
        put16(out, 8 + i * 2, entries[i]);
    }
    return out;
}

// A spec whose relocation table is a real section.
//
// A linker puts the table in a section named .reloc and the directory points
// at that section's virtual address. A fixture that instead put the table
// outside every section would be relying on the headers region to resolve
// it, which is an arrangement no real file uses -- and the loader's walk
// resolves RVAs through the parser, so the fixture has to be shaped the way
// the parser expects or it is testing the fixture rather than the loader.
//
// The builder places a section's raw data at an offset it computes and the
// tail immediately after the last section. So for the table to be where the
// section says it is, it has to be the section's own raw data -- and the
// builder writes only zeros there. The table is therefore passed as the
// section's raw bytes by way of the tail with the offsets made to agree:
// `raw_size` is the table's length, the tail is the table, and the builder
// puts the tail at exactly the offset the section declares because the
// table is the last thing in the file.
Spec reloc_spec(const std::vector<std::uint8_t>& table,
                std::uint32_t reloc_virtual_address = 0x2000,
                std::int64_t image_size = 0x4000) {
    Spec s;
    s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                          kScnExecute | kScnRead});
    // The table's raw size is its real length rather than a page, so the
    // section's file part is exactly the table. The bytes go in through
    // section_content, which writes them at the offset the layout chose --
    // the tail would not do, because it sits after the last section and a
    // section that declares a raw offset does not read from there.
    s.sections.push_back({".reloc", reloc_virtual_address,
                          static_cast<std::uint32_t>(table.size()),
                          static_cast<std::int32_t>(table.size()), 0x42000040});
    s.section_content.emplace_back(std::size_t{1}, table);
    s.reloc_rva = reloc_virtual_address;
    s.reloc_size = static_cast<std::uint32_t>(table.size());
    s.image_size_override = image_size;
    return s;
}

// ----------------------------------------------------------- the record

// The window check.
//
// `base + size > kUserMax` is the obvious form and it is the bug this case
// exists to catch: a base near the top of the window plus a size makes the
// sum wrap, the wrapped sum compares as small, and a region that leaves the
// address space is recorded. A record() written that way passes every case
// whose addresses are small and fails this one.
void test_record_window_check_does_not_wrap() {
    // The window is `base >= kUserMin && base + size <= kUserMax`, and the
    // comparison is written as a subtraction. The last region that fits
    // ends exactly at kUserMax, and this is the case that pins down that
    // the bound is inclusive: a check written as `>=` would refuse it.
    AddressSpace sp;
    const std::uint64_t top = AddressSpace::kUserMax - 0x10000;
    const auto inside = sp.record(top, 0x10000, PageProtection::ReadWrite,
                                  RegionKind::Private);
    check(inside.ok(), "record: a region ending exactly at the maximum is accepted");

    // One granule further and it no longer fits. The two cases together
    // say where the boundary is rather than only that there is one.
    AddressSpace sp_edge;
    const auto past = sp_edge.record(top + 0x1000, 0x10000,
                                     PageProtection::ReadWrite,
                                     RegionKind::Private);
    check(!past.ok(), "record: a region one page past that is refused");

    AddressSpace sp2;
    const auto beyond = sp2.record(top, 0x100000, PageProtection::ReadWrite,
                                   RegionKind::Private);
    check(!beyond.ok(), "record: a region past the maximum is refused");
    check(beyond.status == Status::InvalidAddress,
          "record: the refusal is STATUS_INVALID_ADDRESS");

    // kUserMax + 1 - size, chosen so that base + size wraps to a small
    // number. With an addition-based check this records successfully: the
    // wrapped sum compares as small and passes.
    AddressSpace sp3;
    const std::uint64_t wrapping = AddressSpace::kUserMax - 0xFFF + 1;
    const auto wrapped = sp3.record(wrapping, 0x1000, PageProtection::ReadWrite,
                                    RegionKind::Private);
    check(!wrapped.ok(), "record: a base whose sum with the size wraps is refused");
    check(sp3.regions().empty(),
          "record: a refused region leaves the space unchanged");

    // A size that reaches past the top on its own, without wrapping the
    // arithmetic: this is the case where the subtraction form and a
    // 64-bit addition agree, and it pins down that the check is not merely
    // checking the base.
    AddressSpace sp4;
    const auto too_big = sp4.record(0x10000, AddressSpace::kUserMax,
                                    PageProtection::ReadWrite,
                                    RegionKind::Private);
    check(!too_big.ok(), "record: a size larger than the window is refused");

    // The case the wrapping form misses most easily: a base at the very
    // top and a size that carries the sum past 2^64.
    AddressSpace sp5;
    const auto high = sp5.record(AddressSpace::kUserMax - 0xFFF, 0x2000,
                                 PageProtection::ReadWrite,
                                 RegionKind::Private);
    check(!high.ok(), "record: a base at the top with a size that carries is refused");
}

void test_record_alignment_and_zero_size() {
    AddressSpace sp;
    const auto zero = sp.record(0x10000, 0, PageProtection::ReadWrite,
                                RegionKind::Private);
    check(!zero.ok(), "record: a zero size is refused");
    check(zero.status == Status::InvalidParameter,
          "record: the zero-size refusal is STATUS_INVALID_PARAMETER");

    const auto below = sp.record(0, 0x1000, PageProtection::ReadWrite,
                                 RegionKind::Private);
    check(!below.ok(), "record: an address below the user minimum is refused");

    // A page-aligned base that is not granularity-aligned is accepted.
    //
    // This is the case that found a bug: record() used to demand 64 KiB
    // alignment of every region, which made it unable to represent a PE at
    // all -- the section alignment every real linker uses is 4 KiB, so the
    // second section of every image sat at a 4 KiB-but-not-64 KiB address
    // and was refused. The 64 KiB rule belongs to the allocator, and the
    // allocator applies it by rounding down. So this must be accepted here
    // and the rounding must be available as its own operation.
    const auto page_aligned = sp.record(0x11000, 0x1000,
                                        PageProtection::ExecuteRead,
                                        RegionKind::Image, ".text", 0);
    check(page_aligned.ok(),
          "record: a page-aligned but not granularity-aligned base is accepted");
    check(sp.find(0x11000) != nullptr, "record: and it is findable");

    // The rounding helpers are what the allocator layer uses, and each is
    // checked in both directions -- a round_up that returned its input and
    // a round_down that returned its input are both wrong and both would
    // pass a one-directional check.
    check(AddressSpace::granularity_round_down(0x1FFFF) == 0x10000,
          "round: granularity_round_down rounds down");
    check(AddressSpace::granularity_round_down(0x20000) == 0x20000,
          "round: granularity_round_down leaves an aligned address alone");
    check(AddressSpace::page_round_up(0x1001) == 0x2000,
          "round: page_round_up rounds up");
    check(AddressSpace::page_round_up(0x1000) == 0x1000,
          "round: page_round_up leaves a page-aligned size alone");
    check(AddressSpace::is_granular(0x20000), "round: is_granular accepts");
    check(!AddressSpace::is_granular(0x11000), "round: is_granular rejects");
    check(AddressSpace::is_page_aligned(0x11000), "round: is_page_aligned accepts");
    check(!AddressSpace::is_page_aligned(0x11001), "round: is_page_aligned rejects");
}

// The overlap check only looks at the region before and the region at the
// insertion point. That is sufficient because the vector is ordered and
// non-overlapping -- which is the invariant this case is really about. A
// record() that checked only the next region would accept a new region that
// straddles the previous one, and the map would then describe two regions
// occupying the same bytes.
void test_record_overlap_detection() {
    AddressSpace sp;
    check(sp.record(0x10000, 0x10000, PageProtection::ReadWrite,
                    RegionKind::Private).ok(), "overlap: first region");
    check(sp.record(0x30000, 0x10000, PageProtection::ReadWrite,
                    RegionKind::Private).ok(), "overlap: third region");

    // Wholly inside the first: caught by the previous-region test, because
    // lower_bound lands on the third region and the one before it is the
    // first.
    const auto inside_prev =
        sp.record(0x10000, 0x10000, PageProtection::ReadOnly, RegionKind::Private);
    check(!inside_prev.ok(), "overlap: a region identical to an existing one");
    check(inside_prev.status == Status::ConflictingAddresses,
          "overlap: the refusal is STATUS_CONFLICTING_ADDRESSES");

    // Straddling the first region from below: the new region starts before
    // it and ends inside it. The next-region test alone cannot see this
    // because lower_bound lands on the first region and its base is above
    // the new base -- so this is the case the previous-region test exists
    // for.
    AddressSpace sp2;
    check(sp2.record(0x20000, 0x10000, PageProtection::ReadWrite,
                     RegionKind::Private).ok(), "overlap: second region");
    const auto straddle_below =
        sp2.record(0x10000, 0x20000, PageProtection::ReadWrite,
                   RegionKind::Private);
    check(!straddle_below.ok(),
          "overlap: a region ending inside the next one is refused");

    // Straddling from above: starts inside an existing region and ends
    // past it. This is the case the next-region test exists for.
    AddressSpace sp3;
    check(sp3.record(0x10000, 0x10000, PageProtection::ReadWrite,
                     RegionKind::Private).ok(), "overlap: base region");
    const auto straddle_above =
        sp3.record(0x18000, 0x18000, PageProtection::ReadWrite,
                   RegionKind::Private);
    check(!straddle_above.ok(),
          "overlap: a region starting inside an existing one is refused");

    // Adjacent, not overlapping. The check is `>` and not `>=`, and a
    // record() that used `>=` would refuse every section of an image,
    // because image sections are contiguous.
    AddressSpace sp4;
    check(sp4.record(0x10000, 0x10000, PageProtection::ReadWrite,
                     RegionKind::Private).ok(), "overlap: first of two adjacent");
    check(sp4.record(0x20000, 0x10000, PageProtection::ReadWrite,
                     RegionKind::Private).ok(), "overlap: second of two adjacent");
    check(sp4.regions().size() == 2, "overlap: both adjacent regions kept");
}

// Insertion order is not address order and regions() is documented as
// address order. A record() that appended would return the regions in the
// order they were made, which is a map that reads as a history.
void test_record_keeps_regions_in_address_order() {
    AddressSpace sp;
    check(sp.record(0x50000, 0x10000, PageProtection::ReadWrite,
                    RegionKind::Private).ok(), "order: insert high");
    check(sp.record(0x10000, 0x10000, PageProtection::ReadWrite,
                    RegionKind::Private).ok(), "order: insert low");
    check(sp.record(0x30000, 0x10000, PageProtection::ReadWrite,
                    RegionKind::Private).ok(), "order: insert middle");

    const auto& r = sp.regions();
    check(r.size() == 3, "order: three regions");
    check(r[0].base == 0x10000, "order: lowest first");
    check(r[1].base == 0x30000, "order: middle second");
    check(r[2].base == 0x50000, "order: highest last");

    // find() is the same comparison as the insert, so a lookup of every
    // region's own base has to succeed. A find() that used the wrong
    // comparison returns nullptr for a region that is present.
    for (const Region& reg : r) {
        check(sp.find(reg.base) == &reg, "order: find returns the region itself");
        check(sp.find(reg.end() - 1) == &reg, "order: find returns the last byte");
    }
    check(sp.find(0x20000) == nullptr, "order: find in a gap returns nothing");
    check(sp.find(0x60000) == nullptr, "order: find past the end returns nothing");
    check(sp.find(0xFFFF) == nullptr, "order: find below everything returns nothing");
}

void test_bytes_of_kind_and_high_water() {
    AddressSpace sp;
    check(sp.record(0x10000, 0x10000, PageProtection::ReadOnly,
                    RegionKind::Image, ".text", 0).ok(), "kinds: image");
    check(sp.record(0x20000, 0x20000, PageProtection::ReadWrite,
                    RegionKind::Private).ok(), "kinds: private");
    check(sp.record(0x40000, 0x10000, PageProtection::ReadWrite,
                    RegionKind::Stack).ok(), "kinds: stack");

    check(sp.bytes_of_kind(RegionKind::Image) == 0x10000,
          "kinds: image bytes");
    check(sp.bytes_of_kind(RegionKind::Private) == 0x20000,
          "kinds: private bytes");
    check(sp.bytes_of_kind(RegionKind::Stack) == 0x10000, "kinds: stack bytes");
    check(sp.bytes_of_kind(RegionKind::Mapped) == 0, "kinds: absent kind is zero");
    check(sp.high_water() == 0x50000, "kinds: high water is the highest end");
    check(sp.allocation_count() == 3, "kinds: allocation count");

    AddressSpace empty;
    check(empty.high_water() == 0, "kinds: an empty space has no high water");
}

void test_protection_names() {
    check(std::string(protection_name(PageProtection::ReadOnly)) ==
              "PAGE_READONLY",
          "protection: PAGE_READONLY");
    check(std::string(protection_name(PageProtection::ExecuteReadWrite)) ==
              "PAGE_EXECUTE_READWRITE",
          "protection: PAGE_EXECUTE_READWRITE");

    // The modifier bits are flags on a protection, not protections of their
    // own. A name that ignored them would print PAGE_EXECUTE_READWRITE for
    // a guarded page, and the guard is the part a reader of a fault report
    // needs.
    const auto guarded = static_cast<PageProtection>(
        static_cast<std::uint32_t>(PageProtection::ExecuteReadWrite) |
        static_cast<std::uint32_t>(PageProtection::Guard));
    check(std::string(protection_name(guarded)) ==
              "PAGE_EXECUTE_READWRITE|GUARD",
          "protection: the guard bit is named");

    const auto everything = static_cast<PageProtection>(
        static_cast<std::uint32_t>(PageProtection::ReadWrite) |
        static_cast<std::uint32_t>(PageProtection::Guard) |
        static_cast<std::uint32_t>(PageProtection::NoCache) |
        static_cast<std::uint32_t>(PageProtection::WriteCombine));
    check(std::string(protection_name(everything)) ==
              "PAGE_READWRITE|GUARD|NOCACHE|WRITECOMBINE",
          "protection: all three modifier bits are named in order");

    // The base extraction is what everything else keys off, and it has to
    // drop the modifier bits and nothing else.
    check(protection_base(guarded) == 0x40,
          "protection: the base of a guarded value");
    check(protection_base(PageProtection::WriteCombine) == 0x00,
          "protection: a modifier alone has no base");

    check(std::string(region_kind_name(RegionKind::Image)) == "image",
          "protection: image kind name");
    check(std::string(status_name(Status::ConflictingAddresses)) ==
              "STATUS_CONFLICTING_ADDRESSES",
          "protection: status name");

    // ok() is signed: every failure is a high bit, which is the whole
    // reason NTSTATUS is signed. A check written as `status == 0` would
    // pass, and one written as an unsigned comparison would treat every
    // failure as a success.
    check(ok(Status::Success), "protection: success is ok");
    check(!ok(Status::InvalidParameter), "protection: a failure is not ok");
    check(!ok(Status::NoMemory), "protection: NO_MEMORY is not ok");
}

// ------------------------------------------------------------ the loader

void test_loader_refuses_a_non_image() {
    const std::vector<std::uint8_t> not_a_pe{0x00, 0x01, 0x02, 0x03};
    const PeImage p = parse_image(not_a_pe);
    AddressSpace sp;
    const auto r = load_image(p, ByteSpan{not_a_pe.data(), not_a_pe.size()},
                              0, sp, LoadContext{});
    check(!r.ok, "loader: a non-PE is refused");
    check(r.error == LoadError::NotParsable,
          "loader: the refusal is not_parsable");
    // The parser's own reason is carried through rather than translated.
    check(!r.detail.empty(), "loader: the refusal carries the parser's reason");
    check(sp.regions().empty(), "loader: a refused load leaves the space empty");
}

// The machine check has its own error value and not a generic refusal,
// because "this is an ARM64 image" calls for a different action from "this
// file is damaged". A loader that folded them together would produce a
// message that sends the reader to look at the file's integrity.
void test_loader_refuses_another_machine() {
    Spec s;
    s.plus = true;
    s.machine = 0xaa64; // ARM64
    s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                          kScnExecute | kScnRead});
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp,
                              LoadContext{});
    check(!r.ok, "loader: an ARM64 image is refused");
    check(r.error == LoadError::UnsupportedMachine,
          "loader: the refusal is unsupported_machine");
    check(r.detail.find("arm64") != std::string::npos,
          "loader: the refusal names the machine it saw");
    check(sp.regions().empty(), "loader: nothing is mapped for a refused machine");
}

// The relocation decision.
//
// An image that gets the base it asked for has nothing to relocate, so it
// loads whether or not it has a relocation table. An image that is asked
// for another base with no table cannot be fixed up and has to be refused
// -- and this is the failure Wine has to accommodate and this runtime
// reports, which is why it has its own error value.
// The relocation decision.
//
// An image that gets the base it asked for has nothing to relocate, so it
// loads whether or not it has a relocation table. An image that is asked
// for another base with no table cannot be fixed up and has to be refused
// -- and this is the failure Wine has to accommodate and this runtime
// reports, which is why it has its own error value rather than being folded
// into a generic "cannot load".
void test_loader_relocation_requirement() {
    Spec s;
    s.base = 0x0000000140000000ull;
    s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                          kScnExecute | kScnRead});
    // No reloc directory.
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    const auto at_preferred =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp,
                   LoadContext{});
    check(at_preferred.ok,
          "reloc: an image with no relocations loads at its preferred base");

    AddressSpace sp2;
    const auto elsewhere =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()},
                   0x0000000180000000ull, sp2, LoadContext{});
    check(!elsewhere.ok, "reloc: the same image at another base is refused");
    check(elsewhere.error == LoadError::NoRelocations,
          "reloc: the refusal is no_relocations");
    check(sp2.regions().empty(),
          "reloc: a refused rebase leaves the space empty");
    // The refusal says which base the image wanted and which it got, because
    // those two numbers are the whole content of the finding.
    check(elsewhere.detail.find("40000000") != std::string::npos ||
              elsewhere.detail.find("0x") != std::string::npos,
          "reloc: the refusal names the bases involved");

    // The same image with a relocation table loads at the other base. This
    // is the pair that pins the constraint down: without the table the
    // refusal above must happen, and with it the load must succeed.
    const std::vector<std::uint8_t> table = reloc_block(0x1000, {0xA010, 0x0010});
    const Spec r = reloc_spec(table);
    const Built rb = build(r);
    const PeImage rp = parse_image(rb.bytes);
    check(rp.ok(), "reloc: the rebasable fixture parses");
    check(rp.reloc_size() != 0, "reloc: the rebasable fixture has a table");
    check(rp.reloc_rva() == 0x2000, "reloc: the table's directory is its section");

    AddressSpace sp3;
    const auto rebased =
        load_image(rp, ByteSpan{rb.bytes.data(), rb.bytes.size()},
                   0x0000000180000000ull, sp3, LoadContext{});
    check(rebased.ok, "reloc: a rebasable image loads at another base");
    // The block holds one DIR64 entry and one ABSOLUTE entry. Only the
    // first is a relocation: ABSOLUTE is padding between blocks, and
    // counting it would overstate what the image needs and imply that a
    // file could be "relocated" by writing zeros over its sections.
    check(rebased.module.relocations_applied == 1,
          "reloc: one DIR64 is counted and the ABSOLUTE padding is not");
    check(rebased.module.relocation_blocks == 1,
          "reloc: one relocation block is counted");
    check(rebased.module.base == 0x0000000180000000ull,
          "reloc: the module reports the base it was given");
    check(rebased.module.entry_va == 0x0000000180001000ull,
          "reloc: the entry address follows the new base");
    // Both sections are mapped at the new base. A loader that relocated but
    // mapped at the old base, or the reverse, would pass the counts above.
    check(sp3.find(0x0000000180001000ull) != nullptr,
          "reloc: the text section is at the new base");
    check(sp3.find(0x0000000180002000ull) != nullptr,
          "reloc: the reloc section is at the new base");
    check(sp3.find(0x0000000140001000ull) == nullptr,
          "reloc: nothing is left at the old base");
}

void test_loader_refuses_a_damaged_relocation_block() {
    // Three shapes of a broken relocation table, each refused by a
    // different bound in the walk. A walk without the block-size check
    // reads the entries of a sized-too-small block past the end of it; one
    // without the entry bound walks past the image.
    //
    // (a) A block whose declared size is smaller than its own header.
    {
        std::vector<std::uint8_t> table(8, 0);
        put32(table, 0, 0x1000);
        put32(table, 4, 4); // smaller than the 8-byte header
        const Built b = build(reloc_spec(table));
        const PeImage p = parse_image(b.bytes);
        check(p.ok(), "reloc: the short-block fixture parses");

        AddressSpace sp;
        const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()},
                                  0x180000000ull, sp, LoadContext{});
        check(!r.ok, "reloc: a block smaller than its header is refused");
        check(r.error == LoadError::BadRelocation,
              "reloc: the refusal is bad_relocation");
        check(sp.regions().empty(),
              "reloc: a refused relocation leaves the space empty");
    }

    // (b) A DIR64 entry whose target is past the end of the image. The
    // address is the page RVA plus the 12-bit offset, and a page RVA near
    // the top of the image with a large offset lands outside it -- which is
    // the case a loader without the check would happily apply, writing to
    // an address that is not in the image.
    {
        // The image is 0x4000 bytes, so a page at 0x3FF0 with an offset of
        // 0xFFF is past its end.
        const std::vector<std::uint8_t> table = reloc_block(0x3FF0, {0xAFFF});
        const Built b = build(reloc_spec(table, 0x2000, 0x4000));
        const PeImage p = parse_image(b.bytes);
        check(p.ok(), "reloc: the past-the-end fixture parses");

        AddressSpace sp;
        const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()},
                                  0x180000000ull, sp, LoadContext{});
        check(!r.ok, "reloc: a DIR64 past the image is refused");
        check(r.error == LoadError::BadRelocation,
              "reloc: the refusal is bad_relocation");
    }

    // (c) A relocation type this runtime does not apply. The refusal names
    // the type rather than reporting a generic failure, because "this file
    // needs a relocation I do not implement" and "this file is damaged" are
    // different findings and call for different actions.
    {
        const std::vector<std::uint8_t> table = reloc_block(0x1000, {0x5010});
        const Built b = build(reloc_spec(table));
        const PeImage p = parse_image(b.bytes);
        check(p.ok(), "reloc: the unknown-type fixture parses");

        AddressSpace sp;
        const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()},
                                  0x180000000ull, sp, LoadContext{});
        check(!r.ok, "reloc: an unhandled relocation type is refused");
        check(r.error == LoadError::BadRelocation,
              "reloc: the refusal is bad_relocation");
        check(r.detail.find("type 5") != std::string::npos,
              "reloc: the refusal names the type it saw");
    }
}


// A relocation whose field does not fit where it names.
// `space.find(va)` answers one question -- is the byte at `va` mapped -- and
// the loader used to treat that as the answer to the question that matters,
// which is whether the *field* is mapped. The two differ by the field's
// width minus one, and the gap is not hypothetical: the address comes out of
// a file, and a file is free to name the last byte of a region.
//
// Reaching the region check needs a `Mapper`, because the write pass only
// runs when the loader is actually placing the image. Without one the loader
// runs the plan and stops, and the plan's bound is against SizeOfImage --
// which cannot see a section gap and cannot see a field that leaves a region
// while staying inside the image. The fixtures here therefore map.
void test_loader_refuses_a_relocation_that_overruns_its_region() {
    // A DIR64 at the last byte of the image.
    //
    // .text is one page at 0x1000 and .reloc is the table. The image is
    // 0x2000. An RVA of 0x1FFF is the image's last byte, so the field's
    // first byte is inside the image and its last seven are not.
    //
    // This is the plan's case, and it is the plan that refuses it: the plan
    // bounds an RVA by SizeOfImage, and the bound is against the field's
    // width rather than a fixed eight. A plan that used the DIR64 width for
    // every type would refuse a HIGH at the same address, which fits; one
    // that used one byte would admit this. The region check behind it is
    // what catches a field that leaves a *region* while staying inside the
    // image, which is the case below.
    //
    // The image is asked for at a base other than its own, because the write
    // pass only runs when the image has to move -- an image placed where it
    // asked to be has no delta and nothing to write. The plan runs either
    // way, so this fixture would take the same path at either base; the
    // second one needs the move and is written to be explicit about it.
    {
        const std::uint64_t load_at = claim_a_base(0x4000);
        const std::vector<std::uint8_t> table = reloc_block(0x1000, {0xAFFF});
        Spec s = reloc_spec(table, 0x2000, 0x2000);
        const Built b = build(s);
        const PeImage p = parse_image(b.bytes);
        check(p.ok(), "reloc-width: the overrun fixture parses");

        AddressSpace sp;
        Mapper m(sp);
        LoadContext ctx;
        ctx.placement = &m;

        const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()},
                                  load_at, sp, ctx);
        check(!r.ok, "reloc-width: a DIR64 whose field leaves the image is "
                     "refused");
        check(r.error == LoadError::BadRelocation,
              "reloc-width: the plan refuses it as a bad relocation");
        check(r.detail.find("64-bit") != std::string::npos,
              "reloc-width: the refusal names the field's width");
        check(r.detail.find("outside the image") != std::string::npos,
              "reloc-width: and says the field leaves the image");
    }

    // A relocation into a section gap, which is the case the region check
    // exists for and the plan check cannot see.
    //
    // Sections are mapped whole pages, so the space between two of them is
    // open only when they are more than a page apart. This fixture puts
    // .text at 0x1000 and .reloc at 0x3000, leaving 0x2000 to 0x3000 mapped
    // by nothing, and names an RVA inside it while SizeOfImage covers it.
    {
        const std::uint64_t load_at = claim_a_base(0x4000);
        const std::vector<std::uint8_t> table = reloc_block(0x2000, {0xA100});
        Spec s = reloc_spec(table, 0x3000, 0x4000);
        const Built b = build(s);
        const PeImage p = parse_image(b.bytes);
        check(p.ok(), "reloc-width: the gap fixture parses");

        AddressSpace sp;
        Mapper m(sp);
        LoadContext ctx;
        ctx.placement = &m;

        const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()},
                                  load_at, sp, ctx);
        check(!r.ok, "reloc-width: a relocation into a gap between the mapped "
                     "regions and the declared image is refused");
        check(r.error == LoadError::RelocationNotWritable,
              "reloc-width: the gap refusal names the missing bytes");
        check(r.detail.find("does not cover") != std::string::npos,
              "reloc-width: the gap refusal says the region does not cover "
              "the field");
    }

    // The width is the field's, not a constant.
    //
    // A 32-bit relocation at the last four bytes of a region fits, and a
    // check that used the DIR64 width for every type would refuse it. The
    // converse -- a DIR64 at the same address -- is the first case above.
    {
        const std::uint64_t load_at = claim_a_base(0x4000);
        // RVA 0x1FFC is four bytes wide and ends exactly at 0x2000. HIGHLOW
        // is type 3, so the entry's high nibble is 3.
        const std::vector<std::uint8_t> table = reloc_block(0x1000, {0x3FFC});
        Spec s = reloc_spec(table, 0x2000, 0x2000);
        const Built b = build(s);
        const PeImage p = parse_image(b.bytes);
        check(p.ok(), "reloc-width: the fitting-field fixture parses");

        AddressSpace sp;
        Mapper m(sp);
        LoadContext ctx;
        ctx.placement = &m;

        const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()},
                                  load_at, sp, ctx);
        check(r.ok, "reloc-width: a 32-bit field that ends at the region's "
                    "last byte is accepted");
        check(r.module.relocations_applied == 1,
              "reloc-width: and it is counted as applied");
    }
}

// The section range check.
//
// A section whose address leaves the window has to be refused, and the
// refusal has to happen before anything is recorded. section's
// virtual_address is added to a base from the caller, so this is the second
// place in the codebase where a sum of two chosen numbers is compared
// against a limit.
void test_loader_refuses_a_section_out_of_range() {
    Spec s;
    s.base = AddressSpace::kUserMax - 0x1FFFF;
    s.sections.push_back({".text", 0x1000, 0x100000, 0x200,
                          kScnExecute | kScnRead});
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp,
                              LoadContext{});
    check(!r.ok, "loader: a section past the address window is refused");
    check(r.error == LoadError::SectionOutOfRange,
          "loader: the refusal is section_out_of_range");

    // A zero image size is the same error reached through a different
    // field, and it is refused rather than treated as a header-only image:
    // an image with no size has no sections and no entry point.
    Spec z;
    z.image_size_override = 0;
    z.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                          kScnExecute | kScnRead});
    const Built zb = build(z);
    const PeImage zp = parse_image(zb.bytes);
    AddressSpace sp2;
    const auto zr = load_image(zp, ByteSpan{zb.bytes.data(), zb.bytes.size()},
                               0, sp2, LoadContext{});
    check(!zr.ok, "loader: an image declaring size zero is refused");
    check(zr.error == LoadError::SectionOutOfRange,
          "loader: the zero-size refusal is section_out_of_range");

    // Headers larger than the image: the header region would not fit inside
    // the thing it describes. SizeOfHeaders must stay within the file for
    // the parser to accept it, so the fixture makes the image small rather
    // than the headers large -- the two are the same claim about the loaded
    // image, and only one of them is a well-formed file.
    Spec h;
    h.image_size_override = 0x100;
    h.headers_size_override = 0x200;
    h.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                          kScnExecute | kScnRead});
    const Built hb = build(h);
    const PeImage hp = parse_image(hb.bytes);
    check(hp.ok(), "loader: the small-image fixture parses");
    check(hp.headers_size() > hp.image_size(),
          "loader: the fixture really does have headers past the image");
    AddressSpace sp3;
    const auto hr = load_image(hp, ByteSpan{hb.bytes.data(), hb.bytes.size()},
                               0, sp3, LoadContext{});
    check(!hr.ok, "loader: headers larger than the image are refused");
    check(hr.error == LoadError::SectionOutOfRange,
          "loader: the header-size refusal is section_out_of_range");
}

// The protection a section is mapped with, and the order the tests are
// made in.
//
// Windows' precedence is write-implies-read and execute-implies-read, and a
// section that is both executable and writable gets the combined value. A
// loader that tested execute before the combination would map a JIT
// region as read-execute, and the program would fault on its first write.
void test_loader_section_protections() {
    Spec s;
    s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                          kScnExecute | kScnRead});
    s.sections.push_back({".data", 0x2000, 0x1000, 0x200,
                          kScnRead | kScnWrite});
    s.sections.push_back({".rwx", 0x3000, 0x1000, 0x200,
                          kScnExecute | kScnRead | kScnWrite});
    s.sections.push_back({".rdata", 0x4000, 0x1000, 0x200, kScnRead});
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp,
                              LoadContext{});
    check(r.ok, "protection: the fixture loads");

    const Region* text = sp.find(0x140001000 + 0x10);
    const Region* data = sp.find(0x140002000 + 0x10);
    const Region* rwx = sp.find(0x140003000 + 0x10);
    const Region* rdata = sp.find(0x140004000 + 0x10);

    check(text != nullptr, "protection: the executable section is mapped");
    check(data != nullptr, "protection: the writable section is mapped");
    check(rwx != nullptr, "protection: the read-write-execute section is mapped");
    check(rdata != nullptr, "protection: the read-only section is mapped");

    if (text != nullptr) {
        check(text->protection == PageProtection::ExecuteRead,
              "protection: execute+read becomes PAGE_EXECUTE_READ");
        check(text->executable, "protection: an executable section is marked so");
        check(text->kind == RegionKind::Image, "protection: a section is an image region");
        check(text->section == ".text", "protection: the section name is kept");
    }
    if (data != nullptr) {
        check(data->protection == PageProtection::ReadWrite,
              "protection: read+write becomes PAGE_READWRITE");
        check(!data->executable, "protection: a data section is not executable");
    }
    if (rwx != nullptr) {
        // The combination case. A loader whose test order put execute first
        // would answer PAGE_EXECUTE_READ here and the write would fault.
        check(rwx->protection == PageProtection::ExecuteReadWrite,
              "protection: read+write+execute becomes PAGE_EXECUTE_READWRITE");
        check(rwx->executable, "protection: a writable executable is marked so");
    }
    if (rdata != nullptr) {
        check(rdata->protection == PageProtection::ReadOnly,
              "protection: read alone becomes PAGE_READONLY");
    }

    // The headers are recorded as their own region and are read-only. They
    // are a region rather than omitted because a program reads the DOS stub
    // and the section table, and a map that did not mention them would
    // report a fault in a page that is really there.
    const Region* headers = sp.find(0x140000000 + 0x10);
    check(headers != nullptr, "protection: the headers are mapped");
    if (headers != nullptr) {
        check(headers->protection == PageProtection::ReadOnly,
              "protection: the headers are read-only");
        check(headers->section == ".headers",
              "protection: the header region is named");
    }

    check(r.module.base == 0x140000000ull, "protection: the module base");
    check(r.module.entry_va == 0x140001000ull, "protection: the entry address");
    check(r.module.size == p.image_size(), "protection: the module size");
}

// A section with no file data still occupies address space. .bss is the
// common case and a loader that dropped it would leave the program's
// uninitialised globals unmapped.
void test_loader_maps_a_section_with_no_file_data() {
    Spec s;
    s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                          kScnExecute | kScnRead});
    s.sections.push_back({".bss", 0x2000, 0x2000, -1, kScnRead | kScnWrite});
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp,
                              LoadContext{});
    check(r.ok, "bss: the fixture loads");

    const Region* bss = sp.find(0x140002000 + 0x100);
    check(bss != nullptr, "bss: a section with no file data is still mapped");
    if (bss != nullptr) {
        check(bss->size == 0x2000, "bss: its whole virtual size is mapped");
        check(bss->protection == PageProtection::ReadWrite,
              "bss: it is writable");
    }
}

// Sections are mapped page-rounded. A section whose virtual size is not a
// multiple of the page is mapped in whole pages, so a region recorded
// unrounded would leave the tail of its last page unowned -- and a fault
// there would be reported as unmapped when it is mapped.
void test_loader_rounds_section_sizes_to_the_page() {
    Spec s;
    s.sections.push_back({".text", 0x1000, 0xF8, 0x200,
                          kScnExecute | kScnRead});
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp,
                              LoadContext{});
    check(r.ok, "rounding: the fixture loads");

    const Region* text = sp.find(0x140001000);
    check(text != nullptr, "rounding: the section is mapped");
    if (text != nullptr) {
        check(text->size == 0x1000,
              "rounding: a 0xF8-byte section occupies a whole page");
        // The last byte of the rounded region has to be found by the map,
        // which is the property the rounding exists for.
        check(sp.find(0x140001000 + 0xFFF) == text,
              "rounding: the last byte of the page is inside the region");
    }
}

// The imports.
//
// The loader walks the import directory and reports every entry with the
// DLL, the name, and the IAT slot. With no resolver it records the names
// and leaves the addresses zero -- which is what lets `occ check` describe
// an image without an implementation of the API existing.
void test_loader_walks_imports() {
    // This image keeps its whole import table in the headers, below
    // SizeOfHeaders, where the parser resolves an RVA as a file offset. It is
    // the shape a linker produces and the one a slot-coverage check has to
    // agree with: a loader that demanded every slot be inside a section
    // would refuse this image, and refusing it would be wrong. The companion
    // is test_loader_drops_an_import_whose_slot_is_unmapped, which is the
    // other direction.
    // One import descriptor and two hint/name entries, placed in the tail
    // the builder appends after the section data. The loader resolves RVAs
    // through the parser, and a tail is in no section -- so the fixture
    // raises SizeOfHeaders to cover the tail, which makes every offset in
    // it a valid RVA that resolves to its own file offset. That is the
    // shape a real file uses to put a directory in the headers, and it is
    // the only arrangement this builder can express.
    const std::size_t tail_at = 0x400; // headers (0x200) then one page of .text

    std::vector<std::uint8_t> tail(0x200, 0);
    const std::uint32_t name0 = 0x10;  // hint + "CreateFileW"
    const std::uint32_t name1 = 0x28;  // hint + "NtClose"
    const std::uint32_t dll_at = 0x40; // "kernel32.dll"
    const std::uint32_t thunk_at = 0x60;
    const std::uint32_t iat_at = 0x80;
    const std::uint32_t desc_at = 0xA0;

    put16(tail, name0, 0);
    std::memcpy(&tail[name0 + 2], "CreateFileW", 12);
    put16(tail, name1, 0);
    std::memcpy(&tail[name1 + 2], "NtClose", 8);
    std::memcpy(&tail[dll_at], "kernel32.dll", 13);

    // The name-thunk array and the IAT array both start out holding RVAs to
    // the hint/name entries. Keeping them as two arrays is what makes a
    // second load idempotent: writing resolved addresses into the name
    // array is the classic bug, and the loader reads the two apart.
    const std::uint32_t thunk_base =
        static_cast<std::uint32_t>(tail_at + thunk_at);
    const std::uint32_t iat_base = static_cast<std::uint32_t>(tail_at + iat_at);
    put64(tail, thunk_at + 0, static_cast<std::uint64_t>(tail_at + name0));
    put64(tail, thunk_at + 8, static_cast<std::uint64_t>(tail_at + name1));
    put64(tail, thunk_at + 16, 0);
    put64(tail, iat_at + 0, static_cast<std::uint64_t>(tail_at + name0));
    put64(tail, iat_at + 8, static_cast<std::uint64_t>(tail_at + name1));
    put64(tail, iat_at + 16, 0);

    put32(tail, desc_at + 0, thunk_base);
    put32(tail, desc_at + 12, static_cast<std::uint32_t>(tail_at + dll_at));
    put32(tail, desc_at + 16, iat_base);
    // The 20 zero bytes after the descriptor are its array's terminator.

    Spec s;
    s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                          kScnExecute | kScnRead});
    // SizeOfHeaders has to cover the whole tail, not merely reach it. The
    // parser treats an RVA below SizeOfHeaders as a file offset and
    // searches the sections otherwise -- so a table that sits exactly at
    // the boundary is in no section and resolves to nothing. The mistake
    // is easy to make because "the headers end where the sections begin"
    // reads as true, and the header region is exclusive at its end.
    s.headers_size_override =
        static_cast<std::uint32_t>(tail_at + tail.size());
    s.image_size_override = 0x10000;
    s.tail = tail;

    Built b = build(s);
    // The import directory entry is written into the optional header here.
    // Spec's builder has no field for it because only this test and the
    // ordinal case need one, and a field that existed for every fixture
    // would be a field every fixture could get wrong. The order is an RVA
    // then a size.
    const std::size_t coff = kDosSize + 4;
    const std::size_t opt = coff + 4 + kCoffSize;
    const std::size_t dirs = opt + 112;
    put32(b.bytes, dirs + 1 * 8, static_cast<std::uint32_t>(tail_at + desc_at));
    put32(b.bytes, dirs + 1 * 8 + 4, 40);

    const PeImage p = parse_image(b.bytes);
    check(p.ok(), "imports: the fixture parses");

    AddressSpace sp;
    const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp,
                              LoadContext{});
    check(r.ok, "imports: the fixture loads");
    check(r.module.imports.size() == 2, "imports: two imports are walked");

    if (r.module.imports.size() == 2) {
        check(r.module.imports[0].dll == "kernel32.dll",
              "imports: the DLL name is read");
        check(r.module.imports[0].name == "CreateFileW",
              "imports: the first name is read past its hint");
        check(r.module.imports[1].name == "NtClose",
              "imports: the second name is read");
        // The IAT slot is reported as an address. A loader that reported
        // the RVA would name a place in the file rather than a place in
        // the process, and the two are the same number only when the base
        // is zero.
        check(r.module.imports[0].iat_va == 0x140000000ull + iat_base,
              "imports: the IAT slot is an address, not an RVA");
        // With no resolver the address stays zero and the import is
        // reported unresolved rather than dropped -- which is what lets
        // `occ check` describe an image that cannot be run yet.
        check(!r.module.imports[0].resolved,
              "imports: an import with no resolver is unresolved");
        check(r.module.imports[0].target_va == 0,
              "imports: an unresolved import has no target");
    }

    // The same fixture with a resolver. The only thing that changed is the
    // context, so any difference in the output is attributable to it.
    AddressSpace sp2;
    LoadContext ctx;
    ctx.resolve = [](void*, const std::string&, const std::string& name,
                     std::uint16_t, bool) noexcept -> std::uint64_t {
        // A distinctive address per name, so a loader that reused one
        // resolver answer for every import would be caught here.
        return name == "CreateFileW" ? 0x7FFE0001ull : 0x7FFE0002ull;
    };
    const auto rr = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0,
                               sp2, ctx);
    check(rr.ok, "imports: the fixture loads with a resolver");
    if (rr.module.imports.size() == 2) {
        check(rr.module.imports[0].resolved,
              "imports: a resolved import says so");
        check(rr.module.imports[0].target_va == 0x7FFE0001ull,
              "imports: the resolved address is the resolver's answer");
        check(rr.module.imports[1].target_va == 0x7FFE0002ull,
              "imports: two imports get two answers");
        check(rr.module.imports[0].name == r.module.imports[0].name,
              "imports: resolving does not change the name");
    }
}

// An import by ordinal is a different fact from one by name and the record
// says which it is. A loader that read the ordinal flag as part of the name
// would produce a name of garbage.
// An import by ordinal is a different fact from one by name and the record
// says which it is. A loader that read the ordinal flag as part of the name
// would produce a name of garbage and an address that resolves to nothing.
void test_loader_reads_an_ordinal_import() {
    const std::size_t tail_at = 0x400;

    std::vector<std::uint8_t> tail(0x200, 0);
    const std::uint32_t dll_at = 0x40;
    const std::uint32_t thunk_at = 0x60;
    const std::uint32_t iat_at = 0x80;
    const std::uint32_t desc_at = 0xA0;

    std::memcpy(&tail[dll_at], "ntdll.dll", 10);

    const std::uint32_t thunk_base = static_cast<std::uint32_t>(tail_at + thunk_at);
    const std::uint32_t iat_base = static_cast<std::uint32_t>(tail_at + iat_at);
    // The high bit set means the low sixteen bits are an ordinal.
    put64(tail, thunk_at + 0, 0x8000000000000037ull); // ordinal 0x37
    put64(tail, thunk_at + 8, 0);
    put64(tail, iat_at + 0, 0x8000000000000037ull);
    put64(tail, iat_at + 8, 0);

    put32(tail, desc_at + 0, thunk_base);
    put32(tail, desc_at + 12, static_cast<std::uint32_t>(tail_at + dll_at));
    put32(tail, desc_at + 16, iat_base);

    Spec s;
    s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                          kScnExecute | kScnRead});
    s.headers_size_override =
        static_cast<std::uint32_t>(tail_at + tail.size());
    s.image_size_override = 0x10000;
    s.tail = tail;

    Built b = build(s);
    const std::size_t coff = kDosSize + 4;
    const std::size_t opt = coff + 4 + kCoffSize;
    const std::size_t dirs = opt + 112;
    put32(b.bytes, dirs + 1 * 8, static_cast<std::uint32_t>(tail_at + desc_at));
    put32(b.bytes, dirs + 1 * 8 + 4, 40);

    const PeImage p = parse_image(b.bytes);
    AddressSpace sp;
    const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp,
                              LoadContext{});
    check(r.ok, "ordinal: the fixture loads");
    check(r.module.imports.size() == 1, "ordinal: one import is walked");
    if (r.module.imports.size() == 1) {
        check(r.module.imports[0].by_ordinal, "ordinal: the flag is set");
        check(r.module.imports[0].name == "#55",
              "ordinal: the ordinal is rendered as text");
        check(r.module.imports[0].dll == "ntdll.dll", "ordinal: the DLL is named");
    }

    // The ordinal reaches the resolver as an ordinal, which is what a
    // runtime that keys on one needs. A loader that passed zero would look
    // up ordinal 0 for every import, and one that cleared the flag would
    // make every ordinal import look like a name.
    AddressSpace sp2;
    OrdinalSeen seen;
    LoadContext ctx;
    ctx.resolver_state = &seen;
    ctx.resolve = [](void* state, const std::string&, const std::string&,
                     std::uint16_t ordinal, bool by_ordinal) noexcept
        -> std::uint64_t {
        auto* into = static_cast<OrdinalSeen*>(state);
        into->ordinal = ordinal;
        into->by_ordinal = by_ordinal;
        into->called = true;
        return 0x1000;
    };
    const auto rr = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0,
                               sp2, ctx);
    check(rr.ok, "ordinal: the fixture loads with a resolver");
    check(seen.called, "ordinal: the resolver is called");
    check(seen.by_ordinal, "ordinal: the resolver is told it is an ordinal");
    check(seen.ordinal == 0x37, "ordinal: the ordinal value reaches the resolver");
}

// An IAT slot whose eight bytes do not fit in the region it names.
//
// The slot address comes from the import descriptor's FirstThunk, which is
// the file's to choose, and the loader writes the resolved address there as
// a 64-bit value. A slot at the last four bytes of a region passes a check
// made against its first byte and then takes eight -- four past the end.
//
// The slot is placed at the end of a writable `.data` section rather than in
// the headers, for two reasons. The write is the point, and the header region
// is read-only, so a slot there would be refused for the wrong reason and the
// width would not be what was tested. And the header region is whatever
// SizeOfHeaders says, rounded to a page, which makes its end a moving target
// that grows with the fixture.
//
// `.data` is mapped whole pages at 0x2000, so its last mapped byte is 0x2FFF
// whatever the file says its size is.
void test_loader_refuses_an_iat_slot_that_overruns_its_region() {
    // The layout is fixed by the sections, and the builder puts a tail
    // immediately after their file parts. Two sections of 0x200 raw bytes
    // after a 0x200 header area put the tail at 0x600. The names and the
    // descriptor are addressed by RVAs that, below SizeOfHeaders, are file
    // offsets -- so this constant has to agree with the layout, and the
    // checks below are what say whether it does.
    const std::uint32_t tail_rva = 0x600;

    std::vector<std::uint8_t> tail(0x200, 0);
    const std::uint32_t name0 = 0x10;
    const std::uint32_t dll_at = 0x40;
    const std::uint32_t thunk_at = 0x60;
    // Five bytes from the end of `.data`: 0x2000..0x3000 mapped, so 0x2FFB
    // has five bytes of room and the DWORD takes eight.
    const std::uint32_t iat_rva = 0x2FFB;
    const std::uint32_t desc_at = 0xA0;

    put16(tail, name0, 0);
    std::memcpy(&tail[name0 + 2], "CreateFileW", 12);
    std::memcpy(&tail[dll_at], "kernel32.dll", 13);

    put64(tail, thunk_at + 0, static_cast<std::uint64_t>(tail_rva + name0));
    put64(tail, thunk_at + 8, 0);
    put32(tail, desc_at + 0, tail_rva + thunk_at);   // OriginalFirstThunk
    put32(tail, desc_at + 12, tail_rva + dll_at);    // Name
    put32(tail, desc_at + 16, iat_rva);              // FirstThunk, into .data

    Spec s;
    s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                          kScnExecute | kScnRead});
    // A writable section, so the write is not refused as read-only before the
    // width is ever considered.
    s.sections.push_back({".data", 0x2000, 0x1000, 0x200, kScnRead | kScnWrite});
    s.headers_size_override =
        tail_rva + static_cast<std::uint32_t>(tail.size());
    s.image_size_override = 0x10000;
    s.tail = tail;

    Built b = build(s);
    check(b.tail_at == tail_rva,
          "iat-width: the layout put the tail where the fixture assumes");

    const std::size_t coff = kDosSize + 4;
    const std::size_t opt = coff + 4 + kCoffSize;
    const std::size_t dirs = opt + 112;
    put32(b.bytes, dirs + 1 * 8, tail_rva + desc_at);
    put32(b.bytes, dirs + 1 * 8 + 4, 40);

    const PeImage p = parse_image(b.bytes);
    check(p.ok(), "iat-width: the fixture parses");
    check(p.imports().size() == 1,
          "iat-width: the fixture's import descriptor is read");

    // The resolving path is the one that writes, so it is the one that has to
    // refuse. Without a resolver the slot keeps the file's RVA and nothing
    // lands, which is why the first load below succeeds and says so.
    AddressSpace sp;
    LoadContext plain;
    const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0,
                              sp, plain);
    check(r.ok, "iat-width: an unresolved load does not write and so does not "
                "care where the slot is");

    AddressSpace sp2;
    Mapper m2(sp2);
    LoadContext ctx;
    ctx.placement = &m2;
    ctx.resolve = [](void*, const std::string&, const std::string&,
                     std::uint16_t, bool) noexcept -> std::uint64_t {
        return 0x7FFE0001ull;
    };
    const auto rr = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0,
                               sp2, ctx);
    check(!rr.ok, "iat-width: a resolving load refuses a slot with no room "
                  "for its eight bytes");
    check(rr.error == LoadError::RelocationNotWritable,
          "iat-width: the refusal names the missing bytes");
    check(rr.detail.find("eight bytes") != std::string::npos,
          "iat-width: the refusal says the width is what is missing");
}

// Loading twice at the same base is refused by the address space rather
// than producing a second overlapping map. This is what makes a loader
// that is retried safe: the second attempt reports a conflict instead of
// silently doubling the map.
void test_loader_refuses_a_second_load_at_the_same_base() {
    Spec s;
    s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                          kScnExecute | kScnRead});
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    const auto first =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp,
                   LoadContext{});
    check(first.ok, "twice: the first load succeeds");

    const auto second =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp,
                   LoadContext{});
    check(!second.ok, "twice: the second load at the same base is refused");
    check(second.error == LoadError::AddressConflict,
          "twice: the refusal is address_conflict");
    check(sp.regions().size() == 2,
          "twice: the space still holds exactly the first load's regions");
}

// The atomicity contract.
//
// load_image's documented promise is that a result that is not ok leaves the
// space unchanged, so a caller can retry at another base without unwinding a
// half-populated map. The promise is easy to state and easy to break: the
// natural order -- map the sections, then apply the relocations -- breaks it
// for every failure in the relocation pass, because by then the map is
// populated. This case is the one that caught exactly that, and it uses a
// space that already holds a region so that a stray record would also be
// visible as a conflict on the retry.
void test_a_refused_load_leaves_the_space_alone() {
    // A fixture whose relocation table is refused after the sections have
    // been planned.
    std::vector<std::uint8_t> table(8, 0);
    put32(table, 0, 0x1000);
    put32(table, 4, 4); // a block smaller than its own header
    const Built b = build(reloc_spec(table));
    const PeImage p = parse_image(b.bytes);

    // A space with an unrelated region in it, so that "unchanged" means
    // exactly that and not "empty".
    AddressSpace sp;
    check(sp.record(0x10000, 0x10000, PageProtection::ReadWrite,
                    RegionKind::Private).ok(), "atomic: the pre-existing region");
    const std::size_t before = sp.regions().size();
    const std::uint64_t allocations_before = sp.allocation_count();
    const std::uint64_t high_water_before = sp.high_water();

    const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()},
                              0x180000000ull, sp, LoadContext{});
    check(!r.ok, "atomic: the load is refused");
    check(sp.regions().size() == before,
          "atomic: no region was added by a refused load");
    check(sp.allocation_count() == allocations_before,
          "atomic: the allocation count did not move");
    check(sp.high_water() == high_water_before,
          "atomic: the high water did not move");
    check(sp.find(0x180000000ull) == nullptr,
          "atomic: nothing was recorded at the base that was asked for");

    // And the retry at a good base succeeds, which is the property the
    // contract exists for: a caller that tries the preferred base, fails,
    // and tries another address must not be blocked by the first attempt's
    // leftovers.
    const Built good = build(reloc_spec(reloc_block(0x1000, {0xA010})));
    const PeImage gp = parse_image(good.bytes);
    const auto ok = load_image(gp, ByteSpan{good.bytes.data(), good.bytes.size()},
                               0x180000000ull, sp, LoadContext{});
    check(ok.ok, "atomic: the retry after a refusal succeeds");
    check(sp.find(0x180001000ull) != nullptr,
          "atomic: and it really did map the image");
}

// The entry point has to be inside an executable section, and the loader has
// to refuse an image whose entry point is not.
//
// This is the check the loader did not have and the loader fuzz harness
// found. The three cases below are the three shapes the finding took, and
// each one is a module that loads, reports success, and faults at its first
// instruction -- which nothing above the loader can see coming.
//
// Every case is written so that it fails if the entry-point check is removed
// and the load is allowed to succeed, which is what makes it a regression
// test rather than a description.
void test_loader_refuses_an_unrunnable_entry_point() {
    // (a) The entry RVA is past the end of every section. The image declares
    //     a size that does not cover it.
    {
        Spec s;
        s.entry = 0x3000;
        s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                              kScnExecute | kScnRead});
        const Built b = build(s);
        const PeImage p = parse_image(b.bytes);
        check(p.ok(), "entry: (a) the fixture parses");

        AddressSpace sp;
        const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()},
                                  0, sp, LoadContext{});
        check(!r.ok, "entry: (a) an entry past the image is refused");
        check(r.error == LoadError::SectionOutOfRange,
              "entry: (a) refused as out of range");
        check(sp.regions().empty(),
              "entry: (a) nothing was mapped by the refusal");
    }

    // (b) The entry RVA is inside the image but in the gap between two
    //     sections, so it is not covered by any of them.
    //
    //     The gap has to be real, and finding that out is why this case is
    //     worth writing down: a section's size is rounded up to a page, so
    //     an entry point just past a section's declared VirtualSize is
    //     still inside the section's mapped region. .text below covers
    //     [0x1000, 0x2000) after rounding, and .data starts at 0x3000, so
    //     the gap is [0x2000, 0x3000) and 0x2800 is inside it.
    {
        Spec s;
        s.entry = 0x2800;
        s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                              kScnExecute | kScnRead});
        s.sections.push_back({".data", 0x3000, 0x1000, 0x200,
                              kScnRead | kScnWrite});
        const Built b = build(s);
        const PeImage p = parse_image(b.bytes);

        AddressSpace sp;
        const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()},
                                  0, sp, LoadContext{});
        check(!r.ok, "entry: (b) an entry in a gap is refused");
        check(sp.regions().empty(), "entry: (b) nothing was mapped");
    }

    // (c) The entry RVA is inside a section, but that section is not
    //     executable. This is the case the fuzzer actually produced: a
    //     section with characteristics zero is mapped read-only, and a
    //     program that starts there faults on its first instruction.
    {
        Spec s;
        s.entry = 0x1000;
        s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                              kScnRead | kScnWrite}); // no execute bit
        const Built b = build(s);
        const PeImage p = parse_image(b.bytes);

        AddressSpace sp;
        const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()},
                                  0, sp, LoadContext{});
        check(!r.ok, "entry: (c) an entry in a non-executable section is refused");
        check(r.error == LoadError::SectionOutOfRange,
              "entry: (c) refused as out of range");
        check(sp.regions().empty(), "entry: (c) nothing was mapped");
    }

    // And the counterpart: a zero entry RVA is not an error. A resource-only
    // DLL declares zero and has no entry point at all, so a loader that
    // refused it would refuse every such module.
    {
        Spec s;
        s.dll = true;
        s.entry = 0;
        s.sections.push_back({".data", 0x1000, 0x1000, 0x200,
                              kScnRead | kScnWrite});
        const Built b = build(s);
        const PeImage p = parse_image(b.bytes);

        AddressSpace sp;
        const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()},
                                  0, sp, LoadContext{});
        check(r.ok, "entry: a DLL with no entry point loads");
    }
}

// An image whose own sections overlap is refused by the loader and not by
// the address space.
//
// The distinction matters for the message: an overlap between two regions
// the caller had already mapped is a fact about the space, and an overlap
// between two sections of one file is a fact about the file. The loader
// checks the file's own layout before it records anything, so the refusal
// names the section and the address rather than reporting a conflict with
// something the caller cannot see.
//
// This is the second finding from the loader fuzz harness: a section at
// VirtualAddress zero lands inside the headers, and the file that produced
// it loaded a headers region and then failed a section, leaving the headers
// behind. That the space is untouched afterwards is asserted by
// test_a_refused_load_leaves_the_space_alone; what is asserted here is that
// the refusal is a file error and not a space error.
void test_loader_refuses_overlapping_sections() {
    // (a) A section that starts inside the headers. VirtualAddress zero is
    //     legal in the format and unusable: the headers are there.
    {
        Spec s;
        s.entry = 0x1000;
        s.sections.push_back({".a", 0x0000, 0x1000, 0x200,
                              kScnExecute | kScnRead});
        s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                              kScnExecute | kScnRead});
        const Built b = build(s);
        const PeImage p = parse_image(b.bytes);

        AddressSpace sp;
        const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()},
                                  0, sp, LoadContext{});
        check(!r.ok, "overlap: a section inside the headers is refused");
        check(r.error == LoadError::SectionOutOfRange,
              "overlap: and it is a file error, not a space conflict");
        check(sp.regions().empty(),
              "overlap: and the space is untouched, headers included");
    }

    // (b) Two sections that overlap each other.
    {
        Spec s;
        s.entry = 0x1000;
        s.sections.push_back({".text", 0x1000, 0x2000, 0x200,
                              kScnExecute | kScnRead});
        s.sections.push_back({".data", 0x2000, 0x1000, 0x200,
                              kScnRead | kScnWrite});
        const Built b = build(s);
        const PeImage p = parse_image(b.bytes);

        AddressSpace sp;
        const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()},
                                  0, sp, LoadContext{});
        check(!r.ok, "overlap: two overlapping sections are refused");
        check(r.error == LoadError::SectionOutOfRange,
              "overlap: reported as a file error");
        check(sp.regions().empty(), "overlap: the space is untouched");
    }

    // (c) Sections that touch but do not overlap are accepted. Two 4 KiB
    //     sections at 0x1000 and 0x2000 do not overlap and must load, so
    //     that the overlap check is not a proximity check.
    {
        Spec s;
        s.entry = 0x1000;
        s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                              kScnExecute | kScnRead});
        s.sections.push_back({".data", 0x2000, 0x1000, 0x200,
                              kScnRead | kScnWrite});
        const Built b = build(s);
        const PeImage p = parse_image(b.bytes);

        AddressSpace sp;
        const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()},
                                  0, sp, LoadContext{});
        check(r.ok, "overlap: adjacent sections are not overlapping");
        check(sp.regions().size() == 3,
              "overlap: the headers and both sections are mapped");
    }
}

// The batch record is all-or-nothing.
//
// The loader records the headers and every section in one call, and the
// point of the call is that it cannot half-commit: a batch whose last
// candidate conflicts leaves the space with exactly the regions it had
// before. A caller that used a loop of single record() calls would have the
// first candidates in the map by the time the last one was refused, which is
// how the fuzzer's second finding appeared.
void test_record_batch_is_all_or_nothing() {
    // A batch of three regions where the last overlaps a region that is
    // already mapped. Nothing may be recorded.
    {
        AddressSpace sp;
        check(sp.record(0x50000, 0x1000, PageProtection::ReadOnly,
                        RegionKind::Private).ok(),
              "batch: the pre-existing region");
        const std::size_t before = sp.regions().size();
        const std::uint64_t allocs = sp.allocation_count();

        std::vector<AddressSpace::Candidate> batch;
        AddressSpace::Candidate a;
        a.base = 0x10000;
        a.size = 0x1000;
        a.protection = PageProtection::ReadOnly;
        a.kind = RegionKind::Image;
        batch.push_back(a);
        AddressSpace::Candidate c = a;
        c.base = 0x20000;
        batch.push_back(c);
        AddressSpace::Candidate d = a;
        d.base = 0x50000; // overlaps the region already there
        batch.push_back(d);

        const auto r = sp.record_batch(batch);
        check(!r.ok(), "batch: the conflicting batch is refused");
        check(r.status == Status::ConflictingAddresses,
              "batch: reported as a conflict");
        check(sp.regions().size() == before,
              "batch: none of the batch was recorded");
        check(sp.allocation_count() == allocs,
              "batch: the allocation count did not move");
        check(sp.find(0x10000) == nullptr,
              "batch: the first candidate is not in the map either");
        check(sp.find(0x20000) == nullptr,
              "batch: nor the second");
    }

    // A batch whose candidates overlap each other is refused the same way.
    // This is the case a per-candidate check against the existing map alone
    // would miss.
    {
        AddressSpace sp;
        std::vector<AddressSpace::Candidate> batch;
        AddressSpace::Candidate a;
        a.base = 0x10000;
        a.size = 0x2000;
        a.protection = PageProtection::ReadOnly;
        a.kind = RegionKind::Image;
        batch.push_back(a);
        AddressSpace::Candidate b = a;
        b.base = 0x11000; // inside the first
        batch.push_back(b);

        const auto r = sp.record_batch(batch);
        check(!r.ok(), "batch: candidates that overlap each other are refused");
        check(sp.regions().empty(), "batch: and nothing was recorded");
    }

    // A batch that is fine is recorded in full and in address order.
    {
        AddressSpace sp;
        std::vector<AddressSpace::Candidate> batch;
        for (std::uint64_t base : {0x30000ull, 0x10000ull, 0x20000ull}) {
            AddressSpace::Candidate c;
            c.base = base;
            c.size = 0x1000;
            c.protection = PageProtection::ReadOnly;
            c.kind = RegionKind::Image;
            batch.push_back(c);
        }
        const auto r = sp.record_batch(batch);
        check(r.ok(), "batch: a clean batch is accepted");
        check(r.value == 3, "batch: and reports three regions");
        check(sp.regions().size() == 3, "batch: three regions are in the map");
        check(sp.regions()[0].base == 0x10000 &&
                  sp.regions()[1].base == 0x20000 &&
                  sp.regions()[2].base == 0x30000,
              "batch: and they are in address order regardless of input order");
    }

    // An empty batch succeeds and changes nothing. A caller that has an
    // image with no sections and no headers is not an error case.
    {
        AddressSpace sp;
        const auto r = sp.record_batch({});
        check(r.ok(), "batch: an empty batch succeeds");
        check(r.value == 0, "batch: and records nothing");
    }
}

// The events.
//
// Every mapping, every import, and the relocation summary leave through the
// writer. A loader that mapped silently would be a loader whose work is
// invisible in the stream, and the stream is the product.
void test_loader_emits_events() {
    Spec s;
    s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                          kScnExecute | kScnRead});
    s.sections.push_back({".data", 0x2000, 0x1000, 0x200,
                          kScnRead | kScnWrite});
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    int fd[2] = {-1, -1};
    if (::pipe(fd) != 0) {
        check(false, "events: pipe");
        return;
    }
    occ::obs::Writer w;
    w.attach(fd[1]);

    AddressSpace sp;
    const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp,
                              LoadContext{nullptr, nullptr, &w});
    check(r.ok, "events: the fixture loads");
    check(w.events_written() >= 2, "events: a mapping event per section");

    ::close(fd[1]);
    std::string all;
    char buffer[4096];
    for (;;) {
        const ssize_t n = ::read(fd[0], buffer, sizeof(buffer));
        if (n <= 0) {
            break;
        }
        all.append(buffer, static_cast<std::size_t>(n));
    }
    ::close(fd[0]);

    // The event kind is the first field, so a consumer can dispatch before
    // parsing the rest.
    check(all.find("\"kind\":\"mapping\"") != std::string::npos,
          "events: a mapping event is emitted");
    check(all.find("\"section\":\".text\"") != std::string::npos,
          "events: the mapping names its section");
    check(all.find("\"protection\":\"PAGE_EXECUTE_READ\"") != std::string::npos,
          "events: the mapping names its protection");
    check(all.find("\"base\":\"0x140001000\"") != std::string::npos,
          "events: the mapping carries the address");
}

// ------------------------------------------------------ the real fixture
//
// The tests above are built from a builder, which means they test the
// loader against this project's idea of what a PE is. This case loads a
// real file: the hand-written PE64 built by mkpe.py, 2560 bytes, one
// section, two named imports, no relocation table. It is the only case here
// whose bytes were not produced by the code under test's neighbour, and it
// is the reason the loader's output can be compared against Wine's.

bool read_file(const char* path, std::vector<std::uint8_t>& out) {
    FILE* f = std::fopen(path, "rb");
    if (f == nullptr) {
        return false;
    }
    std::uint8_t buffer[4096];
    std::size_t n = 0;
    while ((n = std::fread(buffer, 1, sizeof(buffer), f)) > 0) {
        out.insert(out.end(), buffer, buffer + n);
    }
    std::fclose(f);
    return !out.empty();
}

void test_loads_the_handwritten_pe() {
    // The fixture is optional. It lives outside the repository because it is
    // a build product rather than a source, and a test that fails when a
    // scratch file is missing would report the environment as a defect. The
    // case is skipped and says so.
    const char* candidates[] = {
        "/tmp/pe/hello.exe",
        "tests/fixtures/hello.exe",
    };
    std::vector<std::uint8_t> bytes;
    const char* found = nullptr;
    for (const char* path : candidates) {
        if (read_file(path, bytes)) {
            found = path;
            break;
        }
    }
    if (found == nullptr) {
        std::fprintf(stderr,
                     "SKIP handwritten PE: no fixture at /tmp/pe/hello.exe\n");
        return;
    }

    const PeImage p = parse_image(bytes);
    check(p.ok(), "handwritten: parses");
    check(p.machine() == PeMachine::Amd64, "handwritten: it is amd64");
    check(p.image_base() == 0x140000000ull, "handwritten: the image base");
    check(p.entry_rva() == 0x1000, "handwritten: the entry RVA");
    check(p.reloc_size() == 0, "handwritten: it has no relocation table");
    check(p.imports().size() == 1, "handwritten: it imports one DLL");
    check(!p.imports().empty() && p.imports()[0] == "ntdll.dll",
          "handwritten: the imported DLL is ntdll");

    AddressSpace sp;
    const auto r = load_image(p, ByteSpan{bytes.data(), bytes.size()}, 0, sp,
                              LoadContext{});
    check(r.ok, "handwritten: loads");
    if (!r.ok) {
        std::fprintf(stderr, "  load failed: %s (%s)\n",
                     load_error_name(r.error), r.detail.c_str());
        return;
    }

    check(r.module.base == 0x140000000ull, "handwritten: mapped at its base");
    check(r.module.entry_va == 0x140001000ull, "handwritten: the entry address");
    check(r.module.size == 0x2000, "handwritten: the image size");
    check(r.module.relocations_applied == 0,
          "handwritten: nothing was relocated, because nothing needed to be");

    // The two imports, by name, in the order the import directory lists
    // them. This is the property that ties the loader's output to what the
    // file actually says, and it is checked against values read out of the
    // file by hand rather than against the loader's own output.
    check(r.module.imports.size() == 2, "handwritten: two imports");
    if (r.module.imports.size() == 2) {
        check(r.module.imports[0].dll == "ntdll.dll",
              "handwritten: import 0's DLL");
        check(r.module.imports[0].name == "NtCreateFile",
              "handwritten: import 0's name");
        check(r.module.imports[0].iat_va == 0x1400010b0ull,
              "handwritten: import 0's IAT slot");
        check(r.module.imports[1].name == "NtTerminateProcess",
              "handwritten: import 1's name");
        check(r.module.imports[1].iat_va == 0x1400010b8ull,
              "handwritten: import 1's IAT slot");
        check(!r.module.imports[0].by_ordinal, "handwritten: both are by name");
        check(!r.module.imports[1].by_ordinal, "handwritten: both are by name");
        check(!r.module.imports[0].resolved,
              "handwritten: nothing resolved, because no resolver was given");
    }

    // The map: the headers plus one section, contiguous, read-only then
    // read-execute. Every section of the file has to appear.
    check(sp.regions().size() == 2, "handwritten: two regions, headers and text");
    if (sp.regions().size() == 2) {
        check(sp.regions()[0].base == 0x140000000ull,
              "handwritten: the headers come first");
        check(sp.regions()[0].size == 0x800,
              "handwritten: the headers are 0x800 bytes");
        check(sp.regions()[1].base == 0x140001000ull,
              "handwritten: the text section follows");
        check(sp.regions()[1].size == 0x1000,
              "handwritten: text's 0xF8 bytes occupy a page");
        check(sp.regions()[1].protection == PageProtection::ExecuteRead,
              "handwritten: text is read-execute");
    }

    // And the entry point is inside a mapped, executable region. This is the
    // question the whole layer exists to answer, and it is asked of the map
    // rather than of the parser.
    const Region* at_entry = sp.find(r.module.entry_va);
    check(at_entry != nullptr, "handwritten: the entry point is mapped");
    if (at_entry != nullptr) {
        check(at_entry->protection == PageProtection::ExecuteRead,
              "handwritten: the entry point is executable");
        check(at_entry->section == ".text",
              "handwritten: the entry point is in .text");
    }
}

// An import whose IAT slot falls outside everything the load mapped is left
// out of the module rather than reported at an address that cannot be
// written.
//
// The loader computes the slot from the file's RVA and used to record it
// without asking whether anything covered it. A directory pointing past every
// section therefore produced a module that reported success and would have
// stored its own imports into unmapped memory -- a fault before the program's
// first instruction, from a load that said it worked.
//
// The shape is the one the fuzz corpus produced: a real, readable import
// table whose IAT array is addressed past the end of everything the load
// placed. The names stay where the parser can read them, because a table that
// could not be read produces no imports at all and would exercise nothing --
// the point is a slot that reads and then cannot be written.
void test_loader_drops_an_import_whose_slot_is_unmapped() {
    std::vector<std::uint8_t> tail(0x200, 0);
    const std::uint32_t name0 = 0x10;  // hint + "CreateFileW"
    const std::uint32_t dll_at = 0x40;  // "kernel32.dll"
    const std::uint32_t thunk_at = 0x60;
    const std::uint32_t iat_at = 0x80;
    const std::uint32_t desc_at = 0xA0;
    const std::size_t tail_at = 0x400;

    put16(tail, name0, 0);
    std::memcpy(&tail[name0 + 2], "CreateFileW", 12);
    std::memcpy(&tail[dll_at], "kernel32.dll", 13);

    const std::uint32_t thunk_base =
        static_cast<std::uint32_t>(tail_at + thunk_at);
    // The IAT array is the thing moved out of the map. It goes to 0x8000:
    // inside the image's declared size, so nothing else refuses the load
    // first, and past the end of the only section, so nothing covers it.
    const std::uint32_t iat_base = 0x8000;

    // One entry, and then the terminator. A second entry would be walked the
    // same way and dropped the same way; one is enough to make the claim and
    // keeps the failure attributable to the slot rather than to a count.
    put64(tail, thunk_at + 0, static_cast<std::uint64_t>(tail_at + name0));
    put64(tail, thunk_at + 8, 0);
    put64(tail, iat_at + 0, static_cast<std::uint64_t>(tail_at + name0));
    put64(tail, iat_at + 8, 0);

    put32(tail, desc_at + 0, thunk_base);
    put32(tail, desc_at + 12, static_cast<std::uint32_t>(tail_at + dll_at));
    put32(tail, desc_at + 16, iat_base);

    Spec s;
    s.sections.push_back({".text", 0x1000, 0x200, 0x200,
                          kScnExecute | kScnRead});
    // SizeOfHeaders covers the whole tail, so the descriptor, the names and
    // the thunk array are all at RVAs the parser resolves as file offsets --
    // inside the header region the load maps. Only the IAT is outside it.
    s.headers_size_override =
        static_cast<std::uint32_t>(tail_at + tail.size());
    s.image_size_override = 0x10000;
    s.tail = tail;

    Built b = build(s);
    const std::size_t coff = kDosSize + 4;
    const std::size_t opt = coff + 4 + kCoffSize;
    const std::size_t dirs = opt + 112;
    put32(b.bytes, dirs + 1 * 8, static_cast<std::uint32_t>(tail_at + desc_at));
    put32(b.bytes, dirs + 1 * 8 + 4, 40);

    const PeImage p = parse_image(b.bytes);
    check(p.ok(), "unmapped slot: the fixture parses");

    AddressSpace sp;
    const auto r = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp,
                              LoadContext{});
    // The load is not refused. The sections are well formed and the image is
    // real; refusing it would refuse images that run. What changes is what
    // the module reports.
    check(r.ok, "unmapped slot: the load still succeeds");

    check(r.module.imports.empty(),
          "unmapped slot: no import is reported at an address that is not mapped");

    // The claim is about the address space and not only about the count. An
    // import recorded at an address the space does not contain is the defect
    // this test exists for, and a count alone would also be satisfied by a
    // loader that reported one at a stray address.
    for (const auto& imp : r.module.imports) {
        check(sp.find(imp.iat_va) != nullptr,
              "unmapped slot: every reported slot is inside the map");
    }
}


// ----------------------------------------------------------------- TLS tests
//
// Four rules these are written to, each of which is a rule about how to
// write the test rather than about TLS:
//
//   * **Nothing is checked against the loader's own output.** Every
//     assertion about what the loader *did* reads the mapped memory back and
//     compares it to something computed from the fixture. A test that
//     compares `module.tls.template_va` to the value it expected
//     `module.tls.template_va` to be is a test that passes when both are
//     wrong in the same way, and the field under test is the one place in
//     the loader where "wrong in the same way" is the expected failure --
//     see the relocation case below.
//
//   * **The expected value is derived from the fixture, not from the
//     expression under test.** A floor computed with the same arithmetic the
//     policy uses is a mirror, not a check. Every number below comes either
//     from the spec the test wrote or from `ImageBase` plus a literal.
//
//   * **A read of an address the loader never mapped happens in a forked
//     child.** A test that segfaults is a test that reports "no output" and
//     looks like a pass in a log. These read only mapped addresses; the one
//     case that would read an unmapped one is written to check the refusal
//     instead of provoking the fault.
//
//   * **The fixture builder is repeated, not shared.** Same reasoning as
//     the file header says: a helper shared with the tests above would let a
//     change made for one of them change what the others measure.

// Where a TLS-bearing fixture puts things. Chosen so the template lands
// inside .text (which every fixture here has) and the directory inside a
// second section, because a directory in the same section as the template is
// a shape no linker emits and would hide a bug where the two overlap.
constexpr std::uint32_t kTlsTemplateRva = 0x1100;
constexpr std::uint32_t kTlsDirRva = 0x3000;
constexpr std::uint32_t kTlsIndexRva = 0x2000;   // .data's first byte
constexpr std::uint32_t kTlsCallbacksRva = 0x3080;
constexpr std::uint32_t kTlsImageSize = 0x4000;

// A base for a fixture that will really be mapped.
//
// The obvious implementation is a constant, and it is wrong in a way that
// only shows up in a sanitized build. A `Mapper` does not unmap when it is
// destroyed, so these fixtures need distinct addresses from each other, and
// distinct is not the same as free: AddressSanitizer reserves a contiguous
// span from 4 GiB to 128 TiB for its shadow memory and its allocator's
// arenas, which is the entire range a 64-bit PE can be based in, because
// `AddressSpace::kUserMax` is 0x7FFFFFFEFFFF. Every hard-coded base in the
// 0x140000000 neighbourhood -- the natural place to put a 64-bit image, and
// where the first version of every fixture here put one -- is inside it. The
// failure is not a clean report either: the load comes back
// STATUS_CONFLICTING_ADDRESSES, and the tests then read memory that was
// never mapped, which is a SEGV inside the sanitizer's own memcpy with a
// stack that names the test rather than the cause.
//
// So the base is asked for rather than named. The kernel is the authority on
// what is free, it is the same authority `Mapper` itself defers to with
// MAP_FIXED_NOREPLACE, and asking costs one mapping which is handed straight
// back. The reservation is released before returning, and the release is
// checked: a probe that could not give back what it took has not found a
// free range, it has moved one, and returning the address anyway would hand
// the caller somewhere it cannot map.
//
// Released, though, means the *next* caller gets the same answer -- the
// kernel's search is deterministic about where a mapping of a given size
// lands, and every caller here asks for the same size. Two fixtures that
// asked in sequence would be handed one address, and since a `Mapper` does
// not unmap, the second load would come back
// STATUS_CONFLICTING_ADDRESSES at an address the first one had certified as
// free. That is the failure this function exists to prevent, reintroduced by
// the function itself.
//
// So the answers are made distinct by hand rather than by luck. Each claim
// is taken at the kernel's answer and then advanced by a fixed stride before
// the next one is asked for, which keeps every base inside a range the
// kernel has already said is mappable and keeps them off each other's toes.
// The stride is a whole number of pages and larger than any image in this file
// (the largest declares 0x5000), so two claims cannot overlap however the pages
// between them are arranged.
//
// The first claim is the kernel's own answer. Every one after it is the
// previous answer plus the stride, and each is checked to be inside the user
// window before it is handed out. A caller that gets zero has to report that
// rather than proceed, which is why every call site here checks.
//
// And every one of them is verified against the kernel before it is handed out,
// not just the first. The stride makes the claims distinct from *each other*;
// it says nothing about the rest of the process. A stride-stepped address can
// land on the C library, on a sanitizer's shadow, or on anything else the
// program has already mapped -- and the first claim is not exempt either, since
// the kernel is free to answer with an address inside the shared-library range,
// which is exactly the range the addresses after it also fall in. Only a
// verified claim is known to be free, and a verification is one map and one
// unmap.
std::uint64_t claim_a_base(std::uint64_t bytes) noexcept {
    // 1 MiB: a whole number of pages, and larger than any image in this file
    // (the largest declares 0x5000), so no two claims can overlap and no
    // claim can run into the next one's first page.
    constexpr std::uint64_t kStride = 0x100000;
    // How far the search may walk before it gives up. It is a bound on the
    // walk rather than on a count of claims so that a file which grew past the
    // window gets zero and reports it, rather than wrapping back to the first
    // candidate and colliding with a fixture still holding that one.
    constexpr std::uint64_t kMaxSteps = 4096;
    static std::uint64_t next = 0;
    static std::uint64_t steps = 0;

    if (next == 0) {
        AddressSpace probe_space;
        Mapper probe(probe_space);
        const Result<std::uint64_t> r =
            probe.map(0, bytes, PageProtection::NoAccess, RegionKind::Private);
        if (!r.ok()) {
            return 0;
        }
        // Given back before returning, and the result checked: a probe that
        // could not release what it took has not found a free range, it has
        // moved one.
        const Result<std::uint64_t> released = probe.unmap(r.value);
        if (!released.ok()) {
            return 0;
        }
        next = r.value;
    }

    // Each candidate is mapped *at* the address, not merely absent from some
    // list: MAP_FIXED_NOREPLACE refuses an occupied address instead of
    // replacing what is there, so a candidate that turns out to be taken comes
    // back as a failure and the walk moves on. Probing by mapping over
    // something would be the defect this whole file exists to catch.
    for (; steps < kMaxSteps; ++steps) {
        if (next == 0 || bytes > AddressSpace::kUserMax - next) {
            return 0;
        }
        const std::uint64_t candidate = next;
        next += kStride;
        ++steps;

        AddressSpace probe_space;
        Mapper probe(probe_space);
        const Result<std::uint64_t> r =
            probe.map(candidate, bytes, PageProtection::NoAccess,
                      RegionKind::Private);
        if (!r.ok()) {
            continue;
        }
        // Released, and the release checked, for the reason the first probe
        // checks it: a claim that could not be given back has not found a
        // free range, it has taken one.
        const Result<std::uint64_t> released = probe.unmap(candidate);
        if (!released.ok()) {
            return 0;
        }
        return candidate;
    }
    return 0;
}

// An address as the loader spells it: 0x, lowercase, no leading zeros.
//
// The spelling is load-bearing in both directions. A test that formatted the
// same value differently from the loader would fail against correct code and
// pass against a loader that printed something else entirely, which is the
// opposite of what an assertion on a message is for. And "no leading zeros"
// is not a style choice: `0x1ca001100` and `0x01ca001100` are the same
// address, so a `find` on a padded form would miss a correct detail and a
// find on an unpadded one is what a reader of the detail will also be doing.
std::string hex_address(std::uint64_t v) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    while (v != 0) {
        out.push_back(digits[v & 0xf]);
        v >>= 4;
    }
    if (out.empty()) {
        out = "0";
    }
    out.push_back('x');
    out.push_back('0');
    std::reverse(out.begin(), out.end());
    return out;
}

// A spec with a .tls section carrying the directory, a .data section with
// room for the index DWORD, and a template inside .text.
//
// The three sections are the three places the format puts the three things:
// the template is ordinary initialized data, the index is a writable DWORD,
// and the directory is a structure. A fixture that put the index in .text
// would be testing a read-only section's refusal instead of TLS, and a
// fixture with no .data at all cannot express the writable-index case.
//
// `base` is a parameter rather than a constant, and the reason is in
// claim_a_base above: it has to be an address nothing is mapped at, and the
// set of such addresses depends on the build. A default of zero means "ask
// the kernel", which is what every caller below wants -- the ones that pass
// an explicit base are the ones that are *about* a particular address, and
// each of those says which and why.
Spec a_tls_spec(std::uint32_t template_size = 0x40,
                std::uint64_t base = 0) {
    Spec s;
    s.base = base != 0 ? base : claim_a_base(kTlsImageSize);
    s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                          kScnExecute | kScnRead});
    s.sections.push_back({".data", 0x2000, 0x1000, 0x200, kScnRead | kScnWrite});
    s.sections.push_back({".tls", kTlsDirRva, 0x1000, 0x200,
                          kScnRead | kScnWrite});
    s.image_size_override = kTlsImageSize;
    s.tls_rva = kTlsDirRva;
    s.tls_template_rva = kTlsTemplateRva;
    s.tls_template_size = template_size;
    return s;
}

// Fills the template with a recognisable pattern.
//
// The pattern is at 64 KiB granularity on purpose. The point of these tests
// is that the block is copied from the *mapped* image, and a byte pattern
// that survives relocation is one the file and the memory cannot both
// produce: if the loader read the template from the file, the copy would
// hold the linked bytes, and if it read from memory it holds the relocated
// ones. The fixture writes the pattern at the *linked* addresses, so the
// two are the same until the image moves -- see the relocation case.
void fill_template(std::vector<std::uint8_t>& bytes, std::uint32_t template_size,
                   std::uint8_t seed) {
    // Find .text's raw offset the way the builder does: 0x200 of headers,
    // then .text's raw part, so .text's file part starts at 0x200.
    constexpr std::size_t kTextRaw = 0x200;
    for (std::uint32_t i = 0; i < template_size; ++i) {
        bytes[kTextRaw + (kTlsTemplateRva - 0x1000) + i] =
            static_cast<std::uint8_t>(seed + i);
    }
}

// A spec whose TLS directory is encoded as *virtual addresses*, which is
// what the specification describes and what a linker emits for an image
// based below 4 GiB.
//
// This fixture exists because of a mutant that survived, and the reason it
// survived is worth recording. Every other TLS fixture here uses a base
// above 4 GiB, and such an image *cannot* carry virtual addresses in a
// 32-bit field -- so every one of them encodes the directory as RVAs. And
// for an RVA-encoded directory, reading it out of the file and reading it
// out of the mapping produce the same answer: the relocation pass does not
// touch these four fields, precisely because they are not pointers it
// knows about, so both copies are identical. A loader that read the file
// would pass every RVA fixture in this file.
//
// Which means the RVA fixtures do not test the thing the whole layer is
// for. This one does: a low base, VA encoding, and a load that moves the
// image anyway. Here the file's copy says 0x401100 and the mapped image
// says 0x150001100, and a loader that read the file hands every thread a
// template full of addresses into memory nothing is mapped at.
Spec a_va_encoded_spec(std::uint32_t template_size = 0x20) {
    Spec s;
    // Low enough that `base + rva` fits in the directory's 32-bit fields --
    // that is the whole point of this fixture -- and high enough that
    // nothing else in this process has mapped it. 0x2A000000 rather than
    // the more obvious 0x00400000, which turned out to be taken: a
    // `Mapper` does not unmap when it dies, so every base this file uses is
    // spent for the life of the process and only a per-runner inspection of
    // /proc/self/maps would say which.
    s.base = 0x2A000000ull;
    s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                          kScnExecute | kScnRead});
    s.sections.push_back({".data", 0x2000, 0x1000, 0x200, kScnRead | kScnWrite});
    s.sections.push_back({".tls", kTlsDirRva, 0x1000, 0x200,
                          kScnRead | kScnWrite});
    s.image_size_override = 0x5000;
    s.tls_rva = kTlsDirRva;
    s.tls_fields = [&] {
        Spec::TlsFields f;
        // Virtual addresses, because the base is below 4 GiB and they fit.
        f.start = static_cast<std::uint32_t>(s.base + kTlsTemplateRva);
        f.end = static_cast<std::uint32_t>(s.base + kTlsTemplateRva +
                                           template_size);
        f.index = static_cast<std::uint32_t>(s.base + kTlsIndexRva);
        f.zero_fill = 0;
        f.callbacks = 0;
        return f;
    }();
    s.tls_template_rva = kTlsTemplateRva;
    s.tls_template_size = template_size;
    return s;
}

// A relocation table, as a section the builder can place. Split out because
// four fixtures below need one and a copy of the twelve lines in each of
// them would be four places to forget to update.
void give_a_reloc_table(Spec& s, std::uint32_t page_rva,
                        std::vector<std::uint16_t> entries) {
    const std::vector<std::uint8_t> table = reloc_block(page_rva, entries);
    s.sections.push_back({".reloc", 0x4000,
                          static_cast<std::uint32_t>(table.size()),
                          static_cast<std::int32_t>(table.size()),
                          0x42000040});
    s.section_content.emplace_back(std::size_t{3}, table);
    s.reloc_rva = 0x4000;
    s.reloc_size = static_cast<std::uint32_t>(table.size());
    s.image_size_override = 0x5000;
}

// Reads a mapped DWORD. The only way these tests learn what the loader
// wrote, and deliberately the only way: a helper that also knew the
// expected value would be a helper the mutation harness could not point at
// the difference between "wrote the slot" and "wrote something".
std::uint32_t mapped_u32(const AddressSpace& sp, std::uint64_t va) {
    // `sp` is taken and not used on purpose. The address is read raw
    // because the test is asserting about the memory rather than about the
    // ledger -- but taking the space keeps the call sites honest, because a
    // reader can then see that these addresses came out of a load rather
    // than out of arithmetic, and an address that is not in the space would
    // fault here rather than quietly reading something else.
    (void)sp;
    std::uint32_t v = 0;
    std::memcpy(&v, reinterpret_cast<const void*>(va), sizeof v);
    return v;
}

std::uint64_t mapped_u64(const AddressSpace& sp, std::uint64_t va) {
    (void)sp;
    std::uint64_t v = 0;
    std::memcpy(&v, reinterpret_cast<const void*>(va), sizeof v);
    return v;
}

std::vector<std::uint8_t> mapped_bytes(const AddressSpace& sp, std::uint64_t va,
                                       std::size_t n) {
    (void)sp;
    std::vector<std::uint8_t> out(n);
    if (n != 0) {
        std::memcpy(out.data(), reinterpret_cast<const void*>(va), n);
    }
    return out;
}

// An image with no TLS directory reports none, and that is not a failure.
//
// The assertion that matters is the one about the table: a module with no
// TLS must not consume a slot, or every image in a process would shift the
// slot numbers of the images that do have TLS, and a module's slot number is
// written into its own image where nothing rewrites it.
void test_tls_absent_directory_is_not_a_refusal() {
    // Built by hand rather than through a_tls_spec because the point of the
    // case is an image with no .tls section at all, and giving it one and
    // then not using it would say nothing. The base still has to be one
    // nothing is mapped at, because this case does real mapping -- see the
    // note on Spec::base for why that is not a constant.
    Spec s;
    s.base = claim_a_base(0x2000);
    s.sections.push_back({".text", 0x1000, 0x1000, 0x200,
                          kScnExecute | kScnRead});
    s.image_size_override = 0x2000;
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    Mapper m(sp);
    LoadContext ctx;
    TlsTable table;
    ctx.placement = &m;
    ctx.tls = &table;

    const LoadResult r =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
    check(r.ok, "no TLS: the image still loads");
    check(r.module.has_tls == false, "no TLS: the module says it has none");
    check(r.module.tls.template_va == 0, "no TLS: the record is zeroed");
    check(table.modules.empty(), "no TLS: no slot was consumed");
    check(table.slots_allocated == 0, "no TLS: the high-water mark stayed at 0");
}

// A directory that is present and entirely zero is also "no TLS".
//
// This is Wine's check and it is a real case rather than a formality: a
// linker that reserved the directory slot for a module whose TLS was
// optimised away leaves nine zero DWORDs behind, and a loader that treated
// that as a module with TLS would give it a slot and write a slot number
// into an `AddressOfIndex` of zero -- which is the image base, so the write
// would land on the DOS header.
void test_tls_all_zero_directory_is_no_tls() {
    Spec s = a_tls_spec(0x40);
    s.tls_fields = Spec::TlsFields{};   // every field zero
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    Mapper m(sp);
    LoadContext ctx;
    TlsTable table;
    ctx.placement = &m;
    ctx.tls = &table;

    const LoadResult r =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
    check(r.ok, "all-zero directory: the image still loads");
    check(r.module.has_tls == false,
          "all-zero directory: nine zero DWORDs are not TLS");
    check(table.modules.empty(),
          "all-zero directory: no slot, so nothing can be indexed");
    // The load must not have written a slot number anywhere. The first
    // DWORD of the image is the DOS signature, and an `AddressOfIndex` of
    // zero resolves to it, so this is the assertion that catches the bug
    // this case exists for.
    check(mapped_u32(sp, s.base) == 0x5a4d,
          "all-zero directory: the DOS header was not written over");
}

// A directory with a template gets a slot, and the slot number is written
// into the image.
//
// The slot assertion is deliberately about the *number in memory* and not
// about `module.tls.index`. A loader that allocated slot 0 and wrote 7 would
// pass an index assertion and produce a program that reads 7 and indexes
// another module's block.
void test_tls_writes_the_slot_into_the_image() {
    Spec s = a_tls_spec(0x40);
    Built b = build(s);
    fill_template(b.bytes, 0x40, 0x10);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    Mapper m(sp);
    LoadContext ctx;
    TlsTable table;
    ctx.placement = &m;
    ctx.tls = &table;

    const LoadResult r =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
    check(r.ok, "tls: the image loads");
    check(r.module.has_tls, "tls: the module says it has some");

    // The first module in an empty table is slot 0. Stated as a property of
    // the table rather than as the literal 0 so that the reason it is 0 is
    // visible: the search starts at `modules.size()`, which is 0.
    check(table.modules.size() == 1, "tls: exactly one module took a slot");
    check(mapped_u32(sp, s.base + kTlsIndexRva) == 0,
          "tls: the index field in the image holds slot 0");
    check(mapped_u32(sp, s.base + kTlsIndexRva) ==
              static_cast<std::uint32_t>(table.modules[0].index),
          "tls: what the image holds is what the table says");
    check(table.slots_allocated == 1, "tls: the high-water mark is 1");
}

// The template is copied per thread, and the copy comes from the mapping.
//
// This is the case the whole "read out of memory" rule exists for, and it
// is checked by moving the image. A load at the linked base cannot tell the
// two sources apart: the file's bytes and the mapped bytes are the same
// bytes. A load *anywhere else* can, because relocation rewrote the
// pointers inside the template -- and the fixture's template is full of
// addresses, so a copy from the file would be full of addresses into a base
// nothing is mapped at.
//
// The assertions read the block that was actually built.
void test_tls_template_is_copied_from_the_mapping() {
    // A template of eight bytes that look like a pointer into the image, so
    // that a relocation has something to rewrite.
    constexpr std::uint32_t kSize = 8;
    // The fill the fixture's directory declares, spelled out here because
    // the assertion two dozen lines down is stated in terms of it.
    constexpr std::uint32_t kFill = 8;
    Spec s = a_tls_spec(kSize);
    s.image_size_override = kTlsImageSize;
    // The relocation table, for the reason test_tls_frees_and_reuses_a_slot
    // gives: this fixture places the image away from its linked base, and a
    // loader that cannot rewrite pointers refuses to do that. One HIGHLOW
    // at the template's first word, which is the word the block's contents
    // are asserted on.
    {
        const std::vector<std::uint8_t> table = reloc_block(0x1000, {0x3100});
        s.sections.push_back({".reloc", 0x4000,
                              static_cast<std::uint32_t>(table.size()),
                              static_cast<std::int32_t>(table.size()),
                              0x42000040});
        s.section_content.emplace_back(std::size_t{3}, table);
        s.reloc_rva = 0x4000;
        s.reloc_size = static_cast<std::uint32_t>(table.size());
        s.image_size_override = 0x5000;
    }
    Built b = build(s);

    // The template holds, at the linked base, the address of .text.
    // 0x1000 is .text's RVA.
    {
        const std::size_t kTextRaw = 0x200;
        put64(b.bytes, kTextRaw + (kTlsTemplateRva - 0x1000), s.base + 0x1000);
    }
    const PeImage p = parse_image(b.bytes);

    // Load somewhere that is not the linked base. The destination is asked
    // for rather than named: the linked base is now whatever the kernel said
    // was free, so a constant that used to be nowhere near it can land on
    // it, and a load at the linked base would relocate nothing while every
    // assertion below went on passing. The delta is asserted to be non-zero
    // for that reason, and it is the only thing that makes this fixture a
    // test of relocation rather than of the copy.
    const std::uint64_t kMoved = claim_a_base(0x5000);
    check(kMoved != 0 && kMoved != s.base,
          "moved: a free range that is not the linked base, so the image "
          "really moves");
    AddressSpace sp;
    Mapper m(sp);
    LoadContext ctx;
    TlsTable table;
    ctx.placement = &m;
    ctx.tls = &table;

    const LoadResult r =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, kMoved, sp, ctx);
    check(r.ok, "moved: the image loads away from its linked base");
    check(r.module.base == kMoved, "moved: the base is the one asked for");

    // Now build a thread's block and read it back.
    TlsBlock block;
    const TlsResult t =
        build_tls_block(table, 0, sp, m, &block);
    check(t.ok, "moved: the thread's block was built");
    // Sixteen, not eight: the fixture's directory declares a zero fill as
    // well as a template, and a block is the template *plus* the fill. The
    // expected number is written as the sum of the two the spec declared
    // rather than as the size of one of them, because "the block is the
    // template" is exactly the mistake a loader that forgot the fill would
    // make, and asserting it here would have hidden that.
    check(block.size == kSize + kFill,
          "moved: the block is the template plus the zero fill");
    check(block.address != 0, "moved: the block has an address");

    if (block.address != 0) {
        // The pointer inside the copy must name where .text ended up, not
        // where it was linked. This single comparison is the whole test.
        const std::uint64_t copied = mapped_u64(sp, block.address);
        check(copied == kMoved + 0x1000,
              "moved: the copied pointer names the mapped .text, not the "
              "linked one");
        check(copied != s.base + 0x1000,
              "moved: and is demonstrably not the linked address");
    }
}

// A block is the template plus zero fill, and the fill is zeros.
//
// Asserted by reading both halves back, because a loader that sized the
// block right and filled it wrong produces a program that works until the
// first thread writes to its TLS -- which is the kind of bug that is
// reported as "my program crashes sometimes".
void test_tls_block_appends_zero_fill() {
    constexpr std::uint32_t kTemplate = 0x20;
    constexpr std::uint32_t kFill = 0x18;
    Spec s = a_tls_spec(kTemplate);
    s.tls_fields = [&] {
        Spec::TlsFields f;
        f.start = kTlsTemplateRva;
        f.end = kTlsTemplateRva + kTemplate;
        f.index = kTlsIndexRva;
        f.zero_fill = kFill;
        f.callbacks = 0;
        return f;
    }();
    Built b = build(s);
    fill_template(b.bytes, kTemplate, 0x40);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    Mapper m(sp);
    LoadContext ctx;
    TlsTable table;
    ctx.placement = &m;
    ctx.tls = &table;

    const LoadResult r =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
    check(r.ok, "zero fill: the image loads");

    TlsBlock block;
    const TlsResult t = build_tls_block(table, 0, sp, m, &block);
    check(t.ok, "zero fill: the block was built");
    check(block.size == kTemplate + kFill,
          "zero fill: the block is template plus fill");

    if (block.address != 0) {
        const std::vector<std::uint8_t> got =
            mapped_bytes(sp, block.address, block.size);
        bool template_ok = true;
        for (std::uint32_t i = 0; i < kTemplate; ++i) {
            if (got[i] != static_cast<std::uint8_t>(0x40 + i)) {
                template_ok = false;
            }
        }
        check(template_ok, "zero fill: the template half is the template");

        bool fill_ok = true;
        for (std::size_t i = kTemplate; i < got.size(); ++i) {
            if (got[i] != 0) {
                fill_ok = false;
            }
        }
        check(fill_ok, "zero fill: the fill half is zeros");
    }
}

// A freed slot is reused, and the reuse does not renumber anybody.
//
// The property that makes this worth testing is the second half. Slot
// numbers are written into images; erasing an entry from the middle of the
// table would move every later module's slot by one and leave their images
// holding numbers that now mean something else. So the free leaves a hole,
// and the next module takes the hole.
void test_tls_frees_and_reuses_a_slot() {
    // Three loads of the same image at three bases, which means three loads
    // away from the image's linked base, which means the image needs a
    // relocation table -- a loader that cannot rewrite pointers refuses to
    // place an image anywhere but where it was linked, and refuses correctly.
    //
    // The table is a real one, built by reloc_block below and given its own
    // section, because a fixture that faked the relocation count would be
    // testing the fake. What it relocates is the TLS template's eight bytes:
    // they hold a pointer into .text, and that pointer is what proves the
    // block was copied from the mapping. The slot DWORD is deliberately *not*
    // in the table -- the loader writes it after relocation, and a fixture
    // that also relocated it would have two writers and a value that depends
    // on which ran last.
    Spec s = a_tls_spec(0x20);
    {
        // One HIGHLOW at RVA 0x1100, the template's first word.
        //
        // The entry packs a 4-bit type in the high nibble and a 12-bit
        // offset in the low one, so 0x3100 is type 3
        // (IMAGE_REL_BASED_HIGHLOW) at offset 0x100 -- which within this
        // block's page of 0x1000 is RVA 0x1100. Writing 0x3003 instead
        // would be type 3 at offset 3, RVA 0x1003, which is a different
        // four bytes of the same section and relocates a word nobody looks
        // at. The image still loads, the relocation count is still 1, and
        // the template still comes out unrelocated: a fixture with a
        // plausible-looking relocation that points somewhere else is worse
        // than one with no relocation at all, because it looks like it is
        // testing the thing.
        const std::vector<std::uint8_t> table =
            reloc_block(0x1000, {0x3100});
        s.sections.push_back({".reloc", 0x4000,
                              static_cast<std::uint32_t>(table.size()),
                              static_cast<std::int32_t>(table.size()),
                              0x42000040});
        s.section_content.emplace_back(std::size_t{3}, table);
        s.reloc_rva = 0x4000;
        s.reloc_size = static_cast<std::uint32_t>(table.size());
        s.image_size_override = 0x5000;
    }
    Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    Mapper m(sp);
    LoadContext ctx;
    TlsTable table;
    ctx.placement = &m;
    ctx.tls = &table;

    // Three loads of the same image at three bases. A second load at the
    // same base is refused, so the bases differ. None of them is the linked
    // base, which is what makes the relocation table necessary and what
    // makes this fixture about slots rather than about placement.
    // The three bases come from claim_a_base, not from constants. Two things
    // make constants wrong here. The obvious one is that a fixed address is
    // only free on a build with a quiet address space -- an ASan build of
    // this same file has the whole range from 4 GiB up to 1 TiB occupied, and
    // every 64-bit PE's preferred base lives in there. The subtle one is
    // that even a base which reads as free in a probe is not free here: this
    // file has thirteen other TLS fixtures, a Mapper does not unmap when it
    // dies, and a base reused across two fixtures gets EEXIST from
    // MAP_FIXED_NOREPLACE, which the loader reports as a placement conflict
    // and which reads like a defect in the image rather than a collision in
    // the test file. Asking the kernel is the only source of addresses that
    // are free by construction, and the stride inside claim_a_base is what
    // makes two calls in one process return two answers.
    //
    // 0x5000 is the SizeOfImage the spec declares above.
    const std::uint64_t kBases[3] = {claim_a_base(0x5000),
                                     claim_a_base(0x5000),
                                     claim_a_base(0x5000)};
    check(kBases[0] != kBases[1] && kBases[1] != kBases[2] &&
              kBases[0] != kBases[2],
          "reuse: the three claims returned three distinct addresses");
    for (std::uint64_t base : kBases) {
        const LoadResult r = load_image(
            p, ByteSpan{b.bytes.data(), b.bytes.size()}, base, sp, ctx);
        check(r.ok, "reuse: each load succeeds");
    }
    check(table.modules.size() == 3, "reuse: three slots were handed out");
    check(table.slots_allocated == 3, "reuse: the high-water mark is 3");

    // Free the middle one. The table has to be edited the way the loader
    // frees a slot, which is by zeroing the entry -- that is the contract
    // `load_tls`'s reuse search relies on, and a test that used a different
    // mechanism would not be testing the search.
    table.modules[1] = TlsModule{};

    // The next load takes the hole rather than appending. Its base is a
    // fourth claim rather than a fourth constant, for the same reason: it
    // has to be somewhere the kernel will hand out, and it has to be
    // different from the three above or the load is refused for colliding
    // with one of them instead of being about the slot.
    const LoadResult r = load_image(
        p, ByteSpan{b.bytes.data(), b.bytes.size()}, claim_a_base(0x5000), sp,
        ctx);
    check(r.ok, "reuse: the load after the free succeeds");
    check(table.modules.size() == 3,
          "reuse: the table did not grow, so the hole was taken");
    check(table.slots_allocated == 3,
          "reuse: the high-water mark did not move, because no new slot was "
          "allocated");
    check(r.module.tls.index == 1, "reuse: the new module took slot 1");
    // And the two live modules kept theirs.
    check(mapped_u32(sp, kBases[0] + kTlsIndexRva) == 0,
          "reuse: the first module still reads slot 0");
    check(mapped_u32(sp, kBases[2] + kTlsIndexRva) == 2,
          "reuse: the third module still reads slot 2, not 1");
}

// A PE32 module has no callback field, and reading one anyway is how a
// 32-bit image ends up calling whatever followed the structure.
//
// The PE32 structure is five DWORDs. The loader's `have_callbacks_field` is
// what stops the sixth DWORD from being read as a callback address, and the
// way to observe that is to put a *recognisable* value at offset 20 -- the
// slot a PE32+ directory would use -- and check that no callback appears.
void test_tls_pe32_has_no_callback_field() {
    Spec s = a_tls_spec(0x20);
    s.plus = false;
    // A PE32 image's base has to fit in 32 bits, because every address in
    // the TLS directory is a 32-bit field. That is not a limit chosen here;
    // see the note on read_tls_directory_from_space in loader.cpp. So this
    // one fixture cannot use a 64-bit base, and it does not need to: nothing
    // else in the TLS suite maps at a 32-bit address.
    s.base = 0x2C000000ull;
    s.image_size_override = kTlsImageSize;
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);
    check(p.is_pe32_plus() == false, "pe32: the fixture really is 32-bit");

    AddressSpace sp;
    Mapper m(sp);
    LoadContext ctx;
    TlsTable table;
    ctx.placement = &m;
    ctx.tls = &table;

    const LoadResult r =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
    check(r.ok, "pe32: the image loads");
    check(r.module.has_tls, "pe32: TLS is still TLS on a 32-bit image");
    check(r.module.tls.callbacks_va == 0,
          "pe32: no callback field means no callback array");
}

// A template that ends before it starts is refused, and the refusal names
// the field.
//
// The check is `end < start` and not `end == start`, because a zero-length
// template is legal and is the other half of the empty-directory test. A
// loader that refused `end <= start` would refuse every module whose TLS is
// only a zero fill, which is a real and common shape.
void test_tls_refuses_a_reversed_template() {
    Spec s = a_tls_spec(0x20);
    s.tls_fields = [&] {
        Spec::TlsFields f;
        f.start = kTlsTemplateRva + 0x40;
        f.end = kTlsTemplateRva;
        f.index = kTlsIndexRva;
        f.zero_fill = 0x10;   // so the empty-directory check does not fire
        f.callbacks = 0;
        return f;
    }();
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    Mapper m(sp);
    LoadContext ctx;
    TlsTable table;
    ctx.placement = &m;
    ctx.tls = &table;

    const LoadResult r =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
    check(!r.ok, "reversed: the load is refused");
    check(r.error == LoadError::TlsRefused,
          "reversed: refused as a TLS problem, not as a placement one");
    check(r.detail.find("before it starts") != std::string::npos,
          "reversed: the detail says the template ends before it starts");
    check(table.modules.empty(),
          "reversed: a refused directory consumed no slot");
}

// A template pointing outside the image is refused.
//
// Three separate escapes are covered by three fixtures, because they fail
// for different reasons and a loader that guarded one would pass a test that
// only exercised that one: below the base, past the end, and an index field
// whose four bytes run off the end.
void test_tls_refuses_a_template_outside_the_image() {
    // A field that lands outside the image under either reading. The
    // subtraction the loader does would otherwise wrap into a huge RVA that
    // passes every bounds test.
    {
        Spec s = a_tls_spec(0x20);
        s.tls_fields = [&] {
            Spec::TlsFields f;
            // Beyond the end of the image under *either* reading, which is
            // what makes this the case worth having.
            //
            // An earlier version of this fixture wrote 0x1000 and called it
            // "below the base". That was true when the loader read every
            // field as a virtual address, and it stopped being true the
            // moment the loader learned that a field which lands outside the
            // image is an RVA -- 0x1000 is a perfectly good RVA, it names
            // .text, and the load that was supposed to be refused succeeded.
            // The fixture was testing the old rule and had to be rewritten
            // rather than adjusted, which is the honest outcome: a test that
            // stops testing what it was written for is worse than no test.
            //
            // 0x9000 is past SizeOfImage (0x5000 here) as an RVA, and as a
            // virtual address it is below a base of 0x148000000 as well, so
            // neither reading places it inside the image.
            f.start = 0x9000;
            f.end = 0x9040;
            f.index = kTlsIndexRva;
            f.zero_fill = 0;
            f.callbacks = 0;
            return f;
        }();
        const Built b = build(s);
        const PeImage p = parse_image(b.bytes);
        AddressSpace sp;
        Mapper m(sp);
        LoadContext ctx;
        TlsTable table;
        ctx.placement = &m;
        ctx.tls = &table;
        const LoadResult r = load_image(
            p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
        check(!r.ok, "outside: a template no reading places is refused");
        check(r.detail.find("below the image base") != std::string::npos ||
                  r.detail.find("leaves the image") != std::string::npos,
              "outside: the detail says which way it failed");
    }
    // Past the end. The image ends at base + 0x4000 and the template starts
    // near the end, so the template's *last byte* is outside even though its
    // first is inside. A loader that checked only the start would pass this.
    {
        Spec s = a_tls_spec(0x20);
        s.tls_fields = [&] {
            Spec::TlsFields f;
            f.start = static_cast<std::uint32_t>(s.base + 0x3F00);
            f.end = static_cast<std::uint32_t>(s.base + 0x4100);
            f.index = kTlsIndexRva;
            f.zero_fill = 0;
            f.callbacks = 0;
            return f;
        }();
        const Built b = build(s);
        const PeImage p = parse_image(b.bytes);
        AddressSpace sp;
        Mapper m(sp);
        LoadContext ctx;
        TlsTable table;
        ctx.placement = &m;
        ctx.tls = &table;
        const LoadResult r = load_image(
            p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
        check(!r.ok, "past-end: a template overrunning the image is refused");
        check(r.detail.find("leaves the image") != std::string::npos,
              "past-end: the detail says the template leaves the image");
    }
}

// The index field has to be writable, because the loader is about to write
// it.
//
// The image is mapped writable during the load and given its final
// protections afterwards, so a file whose index lands in .text would be
// refused here rather than faulting. The fixture puts the index in .text on
// purpose -- that is the shape a hand-written or hostile file has, and the
// shape a loader that writes first and asks later has.
void test_tls_refuses_an_index_that_is_not_writable() {
    Spec s = a_tls_spec(0x20);
    s.sections[0].virtual_address = 0x1000;
    // The index goes into .text, which is read+execute and not writable.
    s.tls_fields = [&] {
        Spec::TlsFields f;
        f.start = kTlsTemplateRva;
        f.end = kTlsTemplateRva + 0x20;
        f.index = 0x1400;   // inside .text, which is not writable
        f.zero_fill = 0;
        f.callbacks = 0;
        return f;
    }();
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    Mapper m(sp);
    LoadContext ctx;
    TlsTable table;
    ctx.placement = &m;
    ctx.tls = &table;

    const LoadResult r =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
    check(!r.ok, "read-only index: the load is refused");
    check(r.error == LoadError::TlsRefused,
          "read-only index: refused as a TLS problem");
    // The refusal has to give the slot back, or every failed load would
    // grow the table by one and the reuse search would skip the entries
    // forever. This is the assertion that case is really about.
    // The entry is *zeroed*, not erased, and the difference is the whole
    // point of the design: erasing an entry from the middle of the table
    // would move every later module's slot down by one, and a module's slot
    // number is written into its own image where nothing rewrites it. So the
    // table keeps its length and the freed entry reads as empty -- which is
    // exactly what the reuse search looks for.
    //
    // An earlier version of this asserted `table.modules.empty()`, on the
    // reasonable-sounding grounds that a load that consumed nothing should
    // leave nothing behind. It fails against an implementation that frees
    // correctly, which is the wrong way round: the assertion described a
    // different (and worse) policy rather than the policy in the code.
    check(table.modules.size() == 1,
          "read-only index: the table kept its length, because erasing an "
          "entry would renumber the modules after it");
    check(table.modules[0].template_va == 0 &&
              table.modules[0].template_size == 0 &&
              table.modules[0].zero_fill == 0 &&
              table.modules[0].callbacks_va == 0,
          "read-only index: and the entry the failed load took was zeroed, so "
          "the reuse search will offer it again");
    check(table.slots_allocated == 0,
          "read-only index: and the high-water mark went back with it");
}

// A TLS index whose four bytes do not fit in the region it names.
//
// `AddressOfIndex` is the file's to choose and the loader writes a DWORD
// there. A directory that names the second-to-last byte of a writable
// section passes a check made against the first byte only, and the write
// that follows lands two bytes past the region. The check has to be against
// the field, and the case that separates the two is an index at the region's
// end rather than inside it.
//
// The section is `.data`, mapped whole pages: it is declared 0x1000 at
// 0x2000, so its last mapped byte is 0x2FFF. An index of 0x2FFE has two of
// its four bytes inside and two outside.
void test_tls_refuses_an_index_whose_field_does_not_fit() {
    Spec s = a_tls_spec(0x20);
    s.sections[0].virtual_address = 0x1000;
    // .data is 0x2000..0x3000 and writable. The index goes at its end.
    s.tls_fields = [&] {
        Spec::TlsFields f;
        f.start = kTlsTemplateRva;
        f.end = kTlsTemplateRva + 0x20;
        f.index = 0x2FFE;   // two bytes of the DWORD fall past .data
        f.zero_fill = 0;
        f.callbacks = 0;
        return f;
    }();
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    Mapper m(sp);
    LoadContext ctx;
    TlsTable table;
    ctx.placement = &m;
    ctx.tls = &table;

    const LoadResult r =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
    check(!r.ok, "short index field: the load is refused");
    check(r.error == LoadError::TlsRefused,
          "short index field: refused as a TLS problem");
    check(r.detail.find("four bytes") != std::string::npos,
          "short index field: the refusal says the field's width is what is "
          "missing, not the address");
    check(table.slots_allocated == 0,
          "short index field: and no slot number is left behind");

    // The same address with the field inside the region loads, which is what
    // makes this a test of the width rather than of the address. 0x2FFC is
    // four bytes ending exactly at 0x3000.
    Spec ok_spec = a_tls_spec(0x20);
    ok_spec.sections[0].virtual_address = 0x1000;
    ok_spec.tls_fields = [&] {
        Spec::TlsFields f;
        f.start = kTlsTemplateRva;
        f.end = kTlsTemplateRva + 0x20;
        f.index = 0x2FFC;   // ends at the region's last byte
        f.zero_fill = 0;
        f.callbacks = 0;
        return f;
    }();
    const Built ok_b = build(ok_spec);
    const PeImage ok_p = parse_image(ok_b.bytes);
    check(ok_p.ok(), "short index field: the fitting fixture parses");

    AddressSpace ok_sp;
    Mapper ok_m(ok_sp);
    LoadContext ok_ctx;
    TlsTable ok_table;
    ok_ctx.placement = &ok_m;
    ok_ctx.tls = &ok_table;

    const LoadResult ok_r = load_image(
        ok_p, ByteSpan{ok_b.bytes.data(), ok_b.bytes.size()}, 0, ok_sp, ok_ctx);
    check(ok_r.ok, "short index field: an index whose four bytes end at the "
                   "region's last byte is accepted");
    check(ok_table.slots_allocated == 1,
          "short index field: and it is given a slot");
}

// Without a mapper the directory is still read and still reported.
//
// This is `occ check`'s path and it is the reason the file-reading branch
// exists at all. The distinction that matters: nothing is *written*, and the
// load does not fail for the absence of a mapper -- it fails or succeeds on
// the same grounds it would with one.
void test_tls_without_a_mapper_decides_without_writing() {
    Spec s = a_tls_spec(0x20);
    Built b = build(s);
    fill_template(b.bytes, 0x20, 0x80);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    Mapper m(sp);   // never placed in the context; used only for its counter
    LoadContext ctx;
    TlsTable table;
    ctx.tls = &table;
    // ctx.placement stays null. The counter is read off a mapper that was
    // never used, which is exactly the point: it has made no syscalls and
    // its zero says so.

    const LoadResult r =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
    check(r.ok, "no mapper: the load still succeeds");
    check(r.module.has_tls, "no mapper: the directory is still read");
    check(table.modules.size() == 1, "no mapper: a slot is still allocated");
    // Not `regions().empty()`. A load with no mapper still calls
    // `record_batch`, so the ledger *does* describe every section -- the
    // ledger records what the load decided, and deciding is most of the
    // work. What did not happen is a syscall, and the counter is what says
    // so. This assertion was originally `regions().empty()` and it failed
    // against code that was right, which is the useful kind of failure: it
    // is what forced the distinction between the ledger and the mapping to
    // be written down rather than assumed, and the same confusion had just
    // cost a segfault in `load_tls`.
    check(m.syscalls_made() == 0,
          "no mapper: and not one syscall was made, because nothing was "
          "asked to be mapped");
}

// A refused load leaves the space exactly as it was -- with no mapper too.
//
// This is the defect the fuzzer found, and the reason a unit test had not is
// worth recording before the test itself. Every unit test that reaches a
// refusal *after* the image is recorded supplies a mapper, because that is
// what the interesting assertions need, and a mapper's rollback did work. The
// path with no mapper is `occ check` -- a load that decides everything and
// stores nothing -- and it had no case of its own here at all.
//
// What made it expensive was a comment that was right about its subject and
// wrong about its consequence. "A refusal with no mapper has nothing to roll
// back -- nothing was mapped" is true of the kernel and false of the ledger.
// A load with no mapper still calls `record_batch`, so it still put every
// section in the space. The refusal then left a space describing an image
// whose bytes were never placed, which is a state a caller has no way to tell
// from a successful load, and which the loader's own contract says cannot
// happen.
//
// The refusal used here is the one the fuzzer's seed produces: a data
// directory array that stops before the TLS entry. Any refusal after the
// record would do, and the assertions below are about the rollback rather than
// about which check refused -- so they are written to hold for all of them.
void test_a_refused_load_leaves_the_space_as_it_was() {
    Spec s = a_tls_spec(0x20);
    // The file stops inside the data directory array, before the TLS entry.
    //
    // The header still declares sixteen directories, so every offset in it is
    // an offset the loader is told to read -- and one of those offsets is past
    // the end of the file. The parser is careful about this (it reads only
    // where the optional header reaches, and clamps the count to what the
    // header can hold), so the load proceeds; the loader is not, because on
    // the no-mapper path it goes to the file for the directory rather than to
    // a mapping that does not exist. That refusal is the one this test needs,
    // and it happens *after* the image has been recorded in the space.
    //
    // Which is why the fixture is a truncated file rather than a file with a
    // short array. Both reach the same refusal, and the truncated one is the
    // shape the fuzzer produced: a declared size and a real length that
    // disagree, which is the disagreement this path is about.
    s.optional_size = 0x60;
    s.truncate_to = 0x120;
    // One section, because that is what fits: with the optional header
    // declared as 0x60 bytes the table starts at 0xf8, and a 40-byte header
    // ends exactly at 0x120. Three sections would need 0x170 and the file
    // would be cut inside the table rather than after it, which is a
    // different shape -- the parser refuses that one, and a fixture that
    // could not parse would test nothing.
    s.sections.resize(1);
    // And the one section has no raw data. The file is cut at 0x120, which is
    // exactly where the headers end, so there is no room for section content
    // -- and a reader that insisted on having some would refuse the file
    // before the loader reached the directory. A section with a raw size of
    // zero needs no bytes, which is what lets the headers and the truncation
    // be the whole file. This is the shape the fuzzer's seed has: its one
    // section declares a raw size of zero and a raw offset of nonsense, and
    // the parser accepts it because a section with nothing to read has nothing
    // to check.
    s.sections[0].raw_size = -1;
    // SizeOfHeaders agrees with the truncation, so the file's own claim about
    // where the headers end is true. Every field read so far has been about a
    // claim that disagrees with the bytes; this one has to agree, or the
    // parser refuses the file for a different reason and the loader never
    // reaches the directory this test is about.
    s.headers_size_override = 0x120;
    Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    // The fixture has to be what the test needs before the conclusion means
    // anything: a file that parses, and a TLS entry that is past its end.
    check(p.ok(), "rollback: the fixture parses");
    check(b.bytes.size() == 0x120,
          "rollback: and it really is the length the fixture asked for");

    AddressSpace sp;
    // A region the caller already had, so "as it was" is a statement about a
    // space with something in it rather than about an empty one.
    const Result<std::uint64_t> seeded =
        sp.record(0x10000, 0x10000, PageProtection::ReadWrite,
                  RegionKind::Private);
    check(seeded.ok(), "rollback: the caller had a region of its own");
    const std::size_t regions_before = sp.regions().size();
    const std::uint64_t water_before = sp.high_water();

    LoadContext ctx;
    TlsTable table;
    ctx.tls = &table;
    // ctx.placement stays null. That is the whole point: this is the path the
    // other cases in this file cannot reach.

    const LoadResult r =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
    check(!r.ok, "rollback: the load is refused");
    check(r.error == LoadError::TlsRefused,
          "rollback: refused over the TLS directory rather than something else");

    // The assertion. The region count and the high water are the two things
    // "as it was" is a statement about; the allocation count is deliberately
    // not one of them, and `AddressSpace::remove` says why in its own
    // comment -- the count is a replay sequence number, and a region that was
    // recorded and then forgotten still consumed one.
    check(sp.regions().size() == regions_before,
          "rollback: the space has the same number of regions it started "
          "with, so the record was taken back");
    check(sp.high_water() == water_before,
          "rollback: and the same high water, so nothing was left above the "
          "caller's own region");
    // The ledger's own view, which is stronger than the count: the image's
    // sections are named, and a name that survived the refusal is a region a
    // reader would go and look at.
    bool any_from_the_image = false;
    for (const Region& region : sp.regions()) {
        if (region.section == ".tls" || region.section == ".data" ||
            region.section == ".text") {
            any_from_the_image = true;
        }
    }
    check(!any_from_the_image,
          "rollback: and no region left over from the image, which is the "
          "distinction a count alone would miss -- a rollback that forgot one "
          "section of four would satisfy the count");

    // And with a mapper the same refusal still rolls back, because the fix
    // made the rollback a choice between two kinds rather than a guard on one
    // of them. The mapper's own counter is what says the kernel saw an unmap.
    {
        AddressSpace sp2;
        Mapper m2(sp2);
        LoadContext ctx2;
        TlsTable table2;
        ctx2.placement = &m2;
        ctx2.tls = &table2;
        const std::size_t before2 = sp2.regions().size();
        const LoadResult r2 = load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()},
                                         0, sp2, ctx2);
        check(!r2.ok, "rollback: refused the same way with a mapper");
        check(sp2.regions().size() == before2,
              "rollback: and the mapped placement was given back too");
    }
}

// A callback array is walked to its terminator, and the terminator is not
// a callback.
//
// The array is read out of the space, which is the same reason the template
// is: its entries are addresses in the image. A callback at the linked base
// would be an address nothing is mapped at, and a loader that read the file
// would produce a block whose callbacks all point into the void.
void test_tls_reads_the_callback_array_to_its_terminator() {
    constexpr std::uint32_t kTemplate = 0x20;
    Spec s = a_tls_spec(kTemplate);
    // Three callbacks and the null terminator: sixteen bytes of array.
    //
    // The image is moved, and the destination is asked for rather than
    // named, for the reason claim_a_base gives. It has to be *different* from
    // the linked base -- that is what makes it a relocation rather than a
    // load -- and it has to be free, and those two requirements pull in
    // opposite directions once the addresses are fixed. A claim that landed
    // on the linked base would produce a fixture in which nothing moves and
    // every assertion below still passed, which is the worst of both.
    const std::uint64_t moved = claim_a_base(0x5000);
    check(moved != 0 && moved != s.base,
          "callbacks: a second free range, distinct from the linked base, "
          "for the image to be moved into");
    std::vector<std::uint8_t> array;
    for (int i = 0; i < 3; ++i) {
        // Addresses inside the image, so they are addresses relocation would
        // have a chance to rewrite if the loader were reading the file.
        // The linked address, which is what a linker emits. The loader must
        // relocate it; a copy from the file would leave it at the linked
        // value and the assertion below is what notices.
        const std::uint64_t fn = s.base + 0x1100 + static_cast<std::uint64_t>(i) * 0x10;
        for (int k = 0; k < 8; ++k) {
            array.push_back(static_cast<std::uint8_t>((fn >> (8 * k)) & 0xff));
        }
    }
    array.resize(array.size() + 8, 0);   // the terminator

    s.tls_fields = [&] {
        Spec::TlsFields f;
        f.start = kTlsTemplateRva;
        f.end = kTlsTemplateRva + kTemplate;
        f.index = kTlsIndexRva;
        f.zero_fill = 0;
        f.callbacks = kTlsCallbacksRva;
        return f;
    }();
    s.tls_callbacks_rva = kTlsCallbacksRva;
    s.tls_callback_bytes = array;
    // The callback array holds three addresses into .text, and this fixture
    // moves the image, so those three addresses have to be relocated. The
    // loader reads the array out of the mapping, so a copy taken from the
    // file would hold the linked addresses and the assertions below -- which
    // compare against the mapped ones -- would catch it.
    {
        std::vector<std::uint16_t> entries;
        for (int i = 0; i < 3; ++i) {
            // Type 3 (HIGHLOW) in the high nibble, and the offset of the
            // i-th callback's eight bytes within its page. The array is at
            // 0x3080, so the three words are at 0x3080, 0x3088 and 0x3090;
            // 0x3080 is the page base, so its offset is 0x080 and the
            // others are 0x088 and 0x090.
            entries.push_back(static_cast<std::uint16_t>(
                0x3000u | (0x080u + static_cast<std::uint32_t>(i) * 8u)));
        }
        const std::vector<std::uint8_t> table =
            reloc_block(0x3000, entries);
        s.sections.push_back({".reloc", 0x4000,
                              static_cast<std::uint32_t>(table.size()),
                              static_cast<std::int32_t>(table.size()),
                              0x42000040});
        s.section_content.emplace_back(std::size_t{3}, table);
        s.reloc_rva = 0x4000;
        s.reloc_size = static_cast<std::uint32_t>(table.size());
        s.image_size_override = 0x5000;
    }

    Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    Mapper m(sp);
    LoadContext ctx;
    TlsTable table;
    ctx.placement = &m;
    ctx.tls = &table;

    const LoadResult r = load_image(
        p, ByteSpan{b.bytes.data(), b.bytes.size()}, moved, sp, ctx);
    check(r.ok, "callbacks: the image loads");
    check(r.module.tls.callbacks_va != 0,
          "callbacks: the directory's callback field was read");

    TlsBlock block;
    const TlsResult t = build_tls_block(table, 0, sp, m, &block);
    check(t.ok, "callbacks: the block was built");
    check(block.callbacks.size() == 3,
          "callbacks: three callbacks, and the terminator is not a fourth");
    if (block.callbacks.size() == 3) {
        // The first entry, read back out of the mapping rather than out of
        // the loader's report. If the array were read from the file this
        // would be the linked address; it has to be the mapped one.
        check(block.callbacks[0] == moved + 0x1100,
              "callbacks: the first entry names the mapped image");
        check(block.callbacks[0] != s.base + 0x1100,
              "callbacks: and is not the linked address");
        check(block.callbacks[2] == moved + 0x1120,
              "callbacks: the third entry is the third one");
    }
}

// Callbacks are called in order, and the first refusal ends the walk.
//
// The point of stopping is that a callback which returned false has said
// the load failed; calling the rest would run initialisers for a module
// that is not going to be loaded. The count is therefore the assertion --
// three callbacks where the second refuses means exactly two calls, and a
// loader that ignored the return value would make three.
struct CallbackWalk {
    std::vector<std::uint64_t> seen;
    std::uint64_t module = 0;
    TlsReason reason = TlsReason::ThreadAttach;
    // The callback whose ordinal in `seen` refuses. -1 means none do.
    int refuse_at = -1;
    std::uint32_t reserve = 0;
};

bool recording_callback(void* state, std::uint64_t callback,
                        std::uint64_t module, TlsReason reason) noexcept {
    auto& w = *static_cast<CallbackWalk*>(state);
    w.module = module;
    w.reason = reason;
    const int ordinal = static_cast<int>(w.seen.size());
    w.seen.push_back(callback);
    (void)w.reserve;
    return w.refuse_at < 0 || ordinal != w.refuse_at;
}

void test_tls_callbacks_stop_at_the_first_refusal() {
    TlsBlock block;
    block.callbacks = {0x1000, 0x2000, 0x3000};

    // All three succeed.
    {
        CallbackWalk w;
        w.refuse_at = -1;
        const TlsResult r =
            call_tls_callbacks(block, recording_callback, &w, 0xAAAA,
                               TlsReason::ThreadAttach);
        check(r.ok, "callbacks: three successes are a success");
        check(w.seen.size() == 3, "callbacks: all three were called");
        if (w.seen.size() == 3) {
            check(w.seen[0] == 0x1000 && w.seen[1] == 0x2000 &&
                      w.seen[2] == 0x3000,
                  "callbacks: in the order the array lists them");
        }
        check(w.module == 0xAAAA, "callbacks: the module base is passed");
        check(w.reason == TlsReason::ThreadAttach, "callbacks: so is the reason");
    }
    // The second refuses.
    {
        CallbackWalk w;
        w.refuse_at = 1;
        const TlsResult r =
            call_tls_callbacks(block, recording_callback, &w, 0xBBBB,
                               TlsReason::ProcessDetach);
        check(!r.ok, "callbacks: a refusal is a failure");
        check(r.error == TlsError::CallbackFailed,
              "callbacks: reported as a callback failure");
        check(r.detail.find("process_detach") != std::string::npos,
              "callbacks: the detail names the reason it was called for");
        check(w.seen.size() == 2,
              "callbacks: the third was not called after the second refused");
    }
    // No callbacks at all is a success, not a vacuous failure.
    {
        CallbackWalk w;
        TlsBlock none;
        const TlsResult r =
            call_tls_callbacks(none, recording_callback, &w, 0, TlsReason::ThreadAttach);
        check(r.ok, "callbacks: an empty array is nothing to do");
        check(w.seen.empty(), "callbacks: and calls nothing");
    }
    // No invoker is also nothing to do, and is *not* reported as a failure:
    // a caller that cannot call into the image has not been told its
    // callbacks refused, and a runtime that said so would be inventing a
    // module's failure.
    {
        CallbackWalk w;
        const TlsResult r =
            call_tls_callbacks(block, nullptr, &w, 0, TlsReason::ThreadAttach);
        check(r.ok, "callbacks: no invoker is not a refusal");
        check(w.seen.empty(), "callbacks: and calls nothing");
    }
}

// A freed block is gone from the space, and the ledger agrees.
//
// Both halves, because they can disagree: an unmap that removed the memory
// but not the ledger leaves a region nothing is mapped at, and a test that
// only asked "is the address still readable" would pass while the ledger
// described memory the kernel no longer has.
void test_tls_free_releases_the_block() {
    Spec s = a_tls_spec(0x20);
    Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    Mapper m(sp);
    LoadContext ctx;
    TlsTable table;
    ctx.placement = &m;
    ctx.tls = &table;

    const LoadResult r =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
    check(r.ok, "free: the image loads");

    TlsBlock block;
    const TlsResult t = build_tls_block(table, 0, sp, m, &block);
    check(t.ok, "free: the block was built");
    check(block.address != 0, "free: and it has an address");
    const std::uint64_t addr = block.address;
    const std::uint32_t before = static_cast<std::uint32_t>(sp.regions().size());

    free_tls_block(m, block);

    check(sp.find(addr) == nullptr,
          "free: the block's address is in no region afterwards");
    check(sp.regions().size() == before - 1,
          "free: and the ledger lost exactly one region");

    // A block with no address is a module with no template and no fill.
    // Freeing it is a no-op, not a crash and not a refusal.
    TlsBlock none;
    free_tls_block(m, none);
    check(sp.regions().size() == before - 1,
          "free: freeing an empty block changed nothing");
}

// A VA-encoded directory read out of the mapping, and what happens when the
// image it came from has moved.
//
// This is the case the whole "read the directory out of memory" rule is
// about, and the one every other fixture in this file structurally cannot
// express. See `a_va_encoded_spec` for why: a base above 4 GiB forces the
// RVA encoding, and under the RVA encoding the file's copy and the mapped
// copy are byte-identical, so a loader that read the file would pass them
// all.
//
// The finding is a real limitation of the format rather than of this
// runtime, and the test says so rather than papering over it:
//
//   * A VA-encoded directory names addresses in terms of the image's
//     *linked* base. Those four fields are not in the relocation table --
//     which is exactly why reading the file's copy is wrong -- so a
//     VA-encoded directory is stale the instant the image moves, and no
//     amount of reading it from the right place can fix it.
//
//   * Reading it from the mapping does not help either, because the mapping
//     holds the same four un-relocated bytes the file did.
//
//   * So an image that is VA-encoded *and* placed away from its linked base
//     has a TLS directory that describes nothing, and the only correct
//     answer is to refuse the load.
//
// Wine's answer is worse and worth naming: it reads the same stale field,
// believes it, and hands every thread a template full of addresses into
// whatever the program has mapped at the *linked* base -- which for an ASLR
// image is nothing at all, and the first thread to touch its TLS faults
// somewhere with no relationship to TLS. This runtime refuses the load
// instead, and says which field went wrong.
//
// The test is therefore two cases at once: the load at the linked base
// succeeds and the block is right, and the moved load is refused with a
// detail that names the template. The first is what makes the second a
// statement about movement rather than about the fixture.
void test_tls_va_encoded_directory_survives_only_where_it_is_true() {
    constexpr std::uint32_t kSize = 0x20;
    Spec s = a_va_encoded_spec(kSize);
    Built b = build(s);
    put64(b.bytes, 0x200 + (kTlsTemplateRva - 0x1000), s.base + 0x1000);
    const PeImage p = parse_image(b.bytes);

    // At the linked base: the directory is true, and everything works.
    {
        AddressSpace sp;
        Mapper m(sp);
        LoadContext ctx;
        TlsTable table;
        ctx.placement = &m;
        ctx.tls = &table;

        const LoadResult r = load_image(
            p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
        check(r.ok, "va-linked: the image loads at the base it was linked at");
        if (r.ok) {
            check(r.module.tls.template_va == s.base + kTlsTemplateRva,
                  "va-linked: the template is where the directory says");
            check(r.module.tls.template_va == 0x2A001100,
                  "va-linked: which is the address the file holds, because "
                  "the image did not move");

            TlsBlock block;
            const TlsResult t = build_tls_block(table, 0, sp, m, &block);
            check(t.ok, "va-linked: the block was built");
            check(block.size == kSize, "va-linked: at the declared size");
            if (block.address != 0) {
                check(mapped_u64(sp, block.address) == s.base + 0x1000,
                      "va-linked: and the template inside it is the linked "
                      "pointer, unrelocated, which is correct here");
            }
        }
    }

    // Moved: the directory is stale and the load is refused.
    {
        // Where "moved" is. Not a constant, for the reason in claim_a_base:
        // an address that reads as free on a quiet build can be occupied on a
        // sanitized one, and a load refused for colliding with something
        // would be refused as a placement conflict rather than as the TLS
        // problem this case is about -- three assertions silently testing
        // nothing, each reporting as a TLS failure. 0x5000 is the SizeOfImage
        // give_a_reloc_table's section layout implies.
        const std::uint64_t kMoved = claim_a_base(0x5000);
        check(kMoved != s.base,
              "va-moved: the kernel gave an address other than the linked "
              "one, so the image really does move");

        Spec moved_spec = a_va_encoded_spec(kSize);
        give_a_reloc_table(moved_spec, 0x1000, {0x3100});
        Built mb = build(moved_spec);
        put64(mb.bytes, 0x200 + (kTlsTemplateRva - 0x1000), s.base + 0x1000);
        const PeImage mp = parse_image(mb.bytes);

        AddressSpace sp;
        Mapper m(sp);
        LoadContext ctx;
        TlsTable table;
        ctx.placement = &m;
        ctx.tls = &table;

        const LoadResult r = load_image(
            mp, ByteSpan{mb.bytes.data(), mb.bytes.size()}, kMoved, sp, ctx);
        check(!r.ok,
              "va-moved: a stale VA directory refuses the load rather than "
              "handing out addresses into nothing");
        if (!r.ok) {
            check(r.error == LoadError::TlsRefused,
                  "va-moved: refused as a TLS problem");
            check(r.detail.find("leaves the image") != std::string::npos,
                  "va-moved: and the detail says the template is nowhere "
                  "near the image it is supposed to be in");

            // The refusal has to name the *resolved* address, which is the
            // one the loader decided on -- the moved base plus the field read
            // as an RVA -- and not the field's raw value. A detail that said
            // "0x2a001100" would be describing the file rather than the
            // decision, and the decision is the thing a reader needs.
            //
            // The expected value is computed rather than written down, and
            // the reason is a scar. The first version of this assertion held
            // a literal "1ca001100", derived by adding 0x1a0000000 to
            // 0x2a001100 by hand; it was wrong by a hex digit, twice, and
            // only printing the loader's own detail settled it. A literal here
            // is a second place to be wrong, and it is wrong *silently* -- a
            // sum that comes out wrong does not fail, it just produces a
            // different number, and the assertion then reports a defect in
            // the loader that is not there.
            //
            // What the computation must not do is read the value back out of
            // the loader. `kMoved` is the base this test chose and the field
            // is the one this test wrote into the file, so their sum is a
            // fact about the fixture, settled before load_image was called.
            //
            // The field is `base + kTlsTemplateRva` -- the directory's start
            // -- and it is worth being explicit about which number that is,
            // because the first attempt at this line used the wrong one. The
            // file also holds a *pointer* at the template's first eight
            // bytes, written above as `s.base + 0x1000`: that is the
            // template's payload, the thing a thread reads out of its block,
            // and it is not an address the loader ever resolves. The address
            // the detail names comes from the directory's start field, and
            // the two differ by 0x100.
            const std::uint64_t field = s.base + kTlsTemplateRva;
            const std::uint64_t expected = kMoved + field;
            // Read as an RVA the field is inside the image; the sum is not.
            // That difference is the evidence the moved base was the one
            // used -- read against the *linked* base the field would fall
            // inside the image, nothing would be refused, and there would be
            // no detail to assert on at all.
            check(field - s.base == kTlsTemplateRva &&
                      field - s.base < 0x5000 && expected - kMoved == field &&
                      expected > kMoved + 0x5000,
                  "va-moved: (the field is inside the image and the resolved "
                  "address is outside it, so only the moved base can have "
                  "produced the address the loader names)");
            check(r.detail.find(hex_address(expected)) != std::string::npos,
                  "va-moved: the detail names the address the loader "
                  "resolved, not the raw field");
        }
        // No slot was taken, and the reason is worth stating because it is a
        // design choice rather than an accident: the template, callback and
        // index bounds are all checked *before* a slot is allocated, so a
        // directory this runtime cannot build never reaches the table. The
        // refusals that happen after the allocation -- the index not being
        // writable, in `commit_tls_index` -- are the ones that have to give
        // a slot back, and test_tls_refuses_an_index_that_is_not_writable
        // is the case for that.
        check(table.modules.empty(),
              "va-moved: no slot was taken, because the directory is checked "
              "before a slot is allocated");
        check(table.slots_allocated == 0,
              "va-moved: and the high-water mark never moved");
    }
}

// A block whose template is not in memory is a failure, and the mapping the
// attempt made is handed back.
//
// The case exists because a mutant that removed the unmap survived. Nothing
// in the suite built a block from a template the loader could not read, so
// the only path into `refuse` was never taken -- and the lambda it lives in
// is the only thing standing between a caller that got a failure and a
// region the ledger describes.
//
// The template here names an address inside the image, so the directory is
// accepted and the slot is written, and then the *unmapping* of the image
// takes the template away underneath it. That is a real sequence a real
// caller can produce -- a module unloaded while a thread still has a block
// half-built -- and it is the only way to reach the path from the outside.
// The block must never be able to stand in for the template.
//
// This is the test for a defect that was in the code and is now not, and the
// reason it is worth a case of its own is that the version with the defect
// passed every other test in this file -- including the one above, which
// looks like it covers exactly this ground.
//
// The defect: `build_tls_block` asked the kernel for a page to put the
// thread's block on, and only then read the template out of the space. The
// kernel chooses the address, and it is free to choose the template's own.
// When it does, the new mapping *covers* the template, so the space says the
// template is mapped, the copy succeeds, and what gets copied is a page of
// zeros out of the block that was just allocated. The call reports success.
// Every thread of that program then has a TLS template full of zeroes where
// the module's own pointers should be, and nothing in any report says why.
//
// It was found by a test that unmaped the template's section and expected a
// refusal. The refusal did not come -- and the reason it did not was that the
// test had made the same assumption the code did, and the kernel had put the
// block back on top of what the test had removed. The fix is the order:
// check what will be read before mapping anything that could cover it.
//
// What this case pins down is that order, and it does it by asserting on the
// one thing an order can be observed through: a template that is not mapped
// is refused, and refused with a detail that names the address. A build that
// mapped first could still fail correctly *if* the kernel happened not to
// overlap this time, so the assertion that would catch the regression is the
// one that does not depend on where the kernel put anything -- the refusal,
// The address a fixture is given has to be one nothing is mapped at.
//
// This is a test of the test file's own address allocator rather than of the
// loader, and it is here because everything else in this file depends on it
// being true. Fifteen fixtures take a base from claim_a_base, and a base that
// is already mapped does not produce an obvious failure: the load is refused
// with STATUS_CONFLICTING_ADDRESSES, which is a correct answer to a correct
// question, and the fixture's own subject -- the template, the callback array,
// the slot, the index -- is never reached. The refusal then reads as a defect
// in whichever constraint that fixture was written to pin down.
//
// So the allocator is pinned down directly. An occupied hole in the middle of
// the walk has to be stepped over, and the step has to be visible: an
// allocator that trusted its own stride would hand out an address it had
// never asked the kernel about, and the first fixture to map there would be
// the one to fail, at a point far from the cause.
void test_a_claim_steps_over_an_address_something_else_took() {
    // Two claims to find the walk, and the hole to occupy: the address one
    // stride after the first claim. If the allocator skipped occupied
    // addresses it steps over this one and keeps its distance; if it trusted
    // the stride it hands this address out and the load below collides.
    const std::uint64_t first = claim_a_base(0x2000);
    const std::uint64_t second = claim_a_base(0x2000);
    check(first != 0 && second != 0,
          "claim: the allocator produced two addresses to work with");
    if (first == 0 || second == 0) {
        return;
    }
    check(second == first + 0x100000,
          "claim: (and the second is one stride past the first, which is the "
          "distance this test's conclusion rests on)");

    // Occupy a whole stride-step, so the next claim has to cross it. The
    // mapping is made on a Mapper of its own and is deliberately *not* given
    // back: a `Mapper` does not unmap when it dies, so it stays occupied for
    // the rest of the process, which is what the allocator has to see.
    const std::uint64_t hole = first + 3 * 0x100000;
    AddressSpace squatter_space;
    Mapper squatter(squatter_space);
    const Result<std::uint64_t> took =
        squatter.map(hole, 0x1000, PageProtection::NoAccess,
                     RegionKind::Private);
    check(took.ok() && took.value == hole,
          "claim: the test took the address one stride into the walk");
    if (!took.ok()) {
        return;
    }

    // Walk forward to the claim that would have collided. Each claim here is
    // 0x2000, so the three claims after `second` are the ones that step over
    // `hole`; the fourth is the one an untrusting allocator would hand out
    // from the wrong side of it.
    const std::uint64_t third = claim_a_base(0x2000);
    const std::uint64_t fourth = claim_a_base(0x2000);
    const std::uint64_t fifth = claim_a_base(0x2000);
    check(third != 0 && fourth != 0 && fifth != 0,
          "claim: the walk continued past the occupied address");
    if (third == 0 || fourth == 0 || fifth == 0) {
        return;
    }
    check(third != hole && fourth != hole && fifth != hole,
          "claim: none of the three claims after the hole is the hole itself");
    check(fifth > hole,
          "claim: (and the walk went past it rather than stalling, so the "
          "occupied address cost a step and not the allocator)");

    // And the address really is unusable, so the check above is not vacuous:
    // mapping it the way a loader would has to fail.
    AddressSpace late_space;
    Mapper late(late_space);
    const Result<std::uint64_t> collided =
        late.map(hole, 0x2000, PageProtection::ReadWrite, RegionKind::Image);
    check(!collided.ok(),
          "claim: (and the hole is genuinely occupied -- a load there is "
          "refused, which is the failure the allocator is avoiding)");
    if (!collided.ok()) {
        check(collided.status == Status::ConflictingAddresses,
              "claim: refused for the reason a collision is refused, not for "
              "some other one");
    }
}


// every time, for an address the loader can name.
void test_tls_a_block_cannot_stand_in_for_the_template() {
    constexpr std::uint32_t kSize = 0x20;
    Spec s = a_tls_spec(kSize, claim_a_base(kTlsImageSize));
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    Mapper m(sp);
    LoadContext ctx;
    TlsTable table;
    ctx.placement = &m;
    ctx.tls = &table;

    const LoadResult r = load_image(
        p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
    check(r.ok, "overlap: the image loads");
    if (!r.ok) {
        return;
    }

    // Take the template away, and then make sure the *only* thing the loader
    // could read is whatever it maps for itself. The unmapped gap between the
    // headers and .data is what makes this more than a section removal: there
    // is a page-sized hole in the image, so a block mapped at a
    // kernel-chosen address has somewhere it can land that is neither the
    // template nor nothing.
    const std::size_t before = sp.regions().size();
    const std::uint64_t tva = table.modules[0].template_va;
    const Region* home = sp.find(tva);
    check(home != nullptr, "overlap: the template is in a region to begin with");
    if (home == nullptr) {
        return;
    }
    const std::string home_name = home->section;
    const std::uint64_t home_base = home->base;
    check(m.unmap(home_base).ok(), "overlap: that region was unmapped");
    check(sp.find(tva) == nullptr,
          "overlap: so the template is now in no region at all");

    // Build the block. The refusal has to come from the template being
    // unreadable, which is a different failure from every other one this
    // function can report and is the only one that means "the image and the
    // process disagree about where its data is".
    TlsBlock block;
    const TlsResult t = build_tls_block(table, 0, sp, m, &block);
    check(!t.ok,
          "overlap: a template that is not mapped is refused, whatever the "
          "kernel offers for the block");
    check(t.error == TlsError::MalformedDirectory,
          "overlap: as a malformed directory rather than as a memory failure");
    check(block.address == 0 && block.size == 0,
          "overlap: and the caller is handed nothing at all, not a block "
          "full of the zeros that caused this");

    // The detail has to name the address, because "a template is not mapped"
    // without the address is a sentence that could have come from any of the
    // several ways this goes wrong, and the address is the one that says
    // which. The literal is the fixture's own, not the loader's formatting.
    check(t.detail.find("is not in memory this process mapped") !=
              std::string::npos,
          "overlap: and the detail says the memory is the problem, which is "
          "the one a block-overlap cannot be mistaken for");
    check(home_name == ".text",
          "overlap: (the region that went away was a section, so this is the "
          "case it claims to be)");

    // And the space is unchanged: the refusal happened before anything was
    // mapped, so there is no block to give back and nothing to count. The
    // count is taken before the unmap and one is subtracted, so the assertion
    // is about the *change* rather than about a number the fixture happens
    // to produce.
    check(sp.regions().size() == before - 1,
          "overlap: the space lost exactly the region this test unmapped and "
          "gained nothing, because nothing was mapped");
}

void test_tls_a_failed_block_gives_its_mapping_back() {
    constexpr std::uint32_t kSize = 0x20;
    Spec s = a_tls_spec(kSize);
    Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    AddressSpace sp;
    Mapper m(sp);
    LoadContext ctx;
    TlsTable table;
    ctx.placement = &m;
    ctx.tls = &table;

    const LoadResult r = load_image(
        p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
    check(r.ok, "failed-block: the image loads");
    if (!r.ok) {
        return;
    }
    const std::uint32_t regions_before =
        static_cast<std::uint32_t>(sp.regions().size());

    // Pull the template out from under the loader, and unmap *the region the
    // template is actually in* rather than a section base computed from
    // `s.base`. The address the loader will read is the one the directory
    // resolved to, and asking the space which region covers it is the only
    // way to name the right one. A base is page-aligned, so `s.base + 0x1000`
    // is a section start only by coincidence -- with a base that was a page
    // boundary plus an offset it was, and with a kernel-chosen one it landed
    // inside the headers, which are still mapped. The unmap then succeeded,
    // the template stayed readable, and the case passed without ever being
    // the case it claims to be. The headers staying mapped is deliberate and
    // is what keeps the space occupied, so that the mapping this function
    // makes is the only thing that can be counted.
    const Region* home = sp.find(table.modules[0].template_va);
    check(home != nullptr,
          "failed-block: the template is inside a region, so there is one to "
          "remove");
    if (home == nullptr) {
        return;
    }
    // The name is read *before* the unmap, not after. `Mapper::unmap`
    // removes the region from the space, so the pointer this lookup returned
    // is dangling the moment the call returns -- and reading it afterwards is
    // a use-after-free that happens to work, which is the worst kind. The
    // first version of this read `home->section` to name the region in the
    // assertion message, and it was only noticed because the block that
    // follows stopped failing for a reason nobody could explain.
    const std::string home_name = home->section;
    const std::uint64_t home_base = home->base;
    const Result<std::uint64_t> pulled = m.unmap(home_base);
    check(pulled.ok(), "failed-block: the template's own region was unmapped");
    check(home_name != ".headers",
          "failed-block: and it was a section rather than the headers, "
          "which is what makes removing it a removal of the template");
    const std::uint32_t without_template =
        static_cast<std::uint32_t>(sp.regions().size());

    TlsBlock block;
    const TlsResult t = build_tls_block(table, 0, sp, m, &block);
    check(!t.ok, "failed-block: a template that is not mapped is a failure");
    check(t.error == TlsError::MalformedDirectory,
          "failed-block: reported as a malformed directory");
    check(block.address == 0,
          "failed-block: the caller is handed no address");
    check(block.size == 0, "failed-block: and no size");

    // The count is the assertion. The block's own mapping was made and then
    // unmade, so the space is where it started -- and "where it started" is
    // a number the test knows without looking at the block, which is what
    // makes it a check rather than a restatement.
    check(sp.regions().size() == without_template,
          "failed-block: the mapping the attempt made was handed back, so the "
          "space is unchanged by it");
    check(regions_before == without_template + 1,
          "failed-block: (and the only region that went away is the one this "
          "test unmapped)");
}

// A PE32 directory with a non-zero sixth DWORD.
//
// The fifth-and-shorter structure is the whole reason this case is separate
// from the PE32+ one: a 32-bit module has no callback field, and the six
// bytes after its fifth DWORD belong to something else in the file. A
// fixture whose sixth DWORD is zero cannot tell the two readings apart --
// which is why the first version of the PE32 test survived the mutant that
// reads the field anyway.
//
// So the sixth DWORD here is a recognisable address, and the assertion is
// that no callback appeared.
void test_tls_pe32_ignores_the_word_after_its_directory() {
    Spec s = a_va_encoded_spec(0x20);
    s.plus = false;
    s.base = 0x2B000000ull;
    s.sections[1].characteristics = kScnRead | kScnWrite;
    s.image_size_override = 0x5000;
    s.tls_fields = [&] {
        Spec::TlsFields f;
        f.start = static_cast<std::uint32_t>(s.base + kTlsTemplateRva);
        f.end = static_cast<std::uint32_t>(s.base + kTlsTemplateRva + 0x20);
        f.index = static_cast<std::uint32_t>(s.base + kTlsIndexRva);
        f.zero_fill = 0;
        // The callback field, set on a PE32 image. A PE32 directory has no
        // such field, so this DWORD is *not* part of the structure -- it is
        // whatever the linker put after it. Setting it to a real address is
        // what makes the fixture able to tell a loader that reads six DWORDs
        // from one that reads five.
        f.callbacks = static_cast<std::uint32_t>(s.base + 0x1500);
        f.have_callbacks_field = false;
        return f;
    }();
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);
    check(p.is_pe32_plus() == false, "pe32-word: the fixture is 32-bit");

    AddressSpace sp;
    Mapper m(sp);
    LoadContext ctx;
    TlsTable table;
    ctx.placement = &m;
    ctx.tls = &table;

    const LoadResult r = load_image(
        p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
    check(r.ok, "pe32-word: the image loads");
    if (!r.ok) {
        return;
    }
    check(r.module.tls.callbacks_va == 0,
          "pe32-word: the word after a PE32 directory is not a callback "
          "field, however plausible it looks");

    TlsBlock block;
    const TlsResult t = build_tls_block(table, 0, sp, m, &block);
    check(t.ok, "pe32-word: the block was built");
    check(block.callbacks.empty(),
          "pe32-word: and no callback came from the sixth DWORD");
}

// The directory is read out of the mapping, and this is the test that can
// actually tell the two sources apart.
//
// Every other TLS fixture leaves the question open, and it is worth being
// honest about why. The TLS directory's four address fields are 32-bit
// virtual addresses, and the base relocation table does not cover them --
// which is the whole reason a VA-encoded directory goes stale when an image
// moves, and the reason
// test_tls_va_encoded_directory_survives_only_where_it_is_true exists. The
// consequence for testing is that a TLS directory inside a mapped image is
// byte-for-byte the directory in the file, so a loader that read the file
// would answer identically on every fixture built so far. A suite made of
// those can be entirely green against a loader that reads the wrong one, and
// that is a fact about the suite rather than about the code. No number of
// further fixtures of the same shape would change it.
//
// What separates the two is a case where the sources do not agree about what
// exists. The file ends where the linker's raw data ends; the mapping
// continues to the section's virtual size, and the tail of that gap is zero
// fill -- real address space the program can read, holding no bytes the file
// ever had. A directory placed there is a directory the file cannot produce
// and the mapping can, and the two readers must disagree about it in
// opposite directions:
//
//   * the file reader refuses by name, because `to_file_offset` declines a
//     zero-filled RVA rather than hand back an offset into bytes that are
//     not there;
//   * the mapping reader reads six zero DWORDs, sees a directory whose every
//     field is zero, and concludes -- correctly -- that this module has no
//     TLS template.
//
// The second is the interesting half, because "all zero" is the one pattern
// this loader treats as the absence of a feature rather than as an error, and
// a file reader can never reach that conclusion for a directory at all: it
// would have failed three lines earlier. So a load that succeeds here with no
// TLS is a statement about the mapping, and it is the assertion that
// separates the two readers.
void test_tls_directory_is_read_from_the_mapping_not_the_file() {
    // A .tls section whose raw data is one DWORD and whose virtual size is a
    // full page, with the directory at offset 0x40 -- past the raw data,
    // inside the zero fill. The builder writes the section's file data at its
    // raw offset, so the four bytes at 0x40 exist in the file only as the
    // gap between one section's raw part and the next, and they are zero
    // there because a vector initialised to zero is zero.
    constexpr std::uint32_t kRaw = 4;
    // 0x14E000000 rather than the 0x14D000000 used elsewhere in this file:
    // a `Mapper` does not unmap when it is destroyed, so a base is spent
    // once it is used and this file has a fixture at 0x14D.
    Spec s = a_tls_spec(0x20);
    s.sections[2].raw_size = kRaw;
    s.sections[2].virtual_size = 0x1000;
    s.tls_rva = kTlsDirRva + 0x40;
    const Built b = build(s);
    const PeImage p = parse_image(b.bytes);

    // The fixture has to be what it claims before its conclusion means
    // anything, and both halves of the claim are checked rather than assumed.
    check(p.is_pe32_plus(), "src: the fixture is 64-bit");
    {
        std::uint64_t off = 0;
        bool zero_filled = true;
        const bool resolved = p.resolve_rva(s.tls_rva, off, zero_filled);
        check(resolved && zero_filled,
              "src: the directory's RVA resolves, and resolves to zero fill "
              "-- which is the premise the whole test rests on");
        check(!p.to_file_offset(s.tls_rva, off),
              "src: and the file has no offset for it, so a reader of the "
              "file could only have refused");
    }

    AddressSpace sp;
    Mapper m(sp);
    LoadContext ctx;
    TlsTable table;
    ctx.placement = &m;
    ctx.tls = &table;

    const LoadResult r = load_image(
        p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, sp, ctx);
    // A mapped reader reads six zero DWORDs and concludes the module has no
    // TLS. The load succeeds, which is the part that distinguishes the
    // sources: a file reader fails here, because the directory it cannot
    // reach is not an absent directory but an unreadable one.
    check(r.ok, "src: a mapped reader reads the zero fill and finds no TLS, "
                "rather than refusing a directory the file cannot hold");
    if (!r.ok) {
        return;
    }
    check(!r.module.has_tls,
          "src: and the module reports no TLS, because every field of a "
          "zero directory is zero");
    check(table.modules.empty(),
          "src: no slot was taken, because a module with no template does "
          "not get one");
    check(table.slots_allocated == 0,
          "src: and the high-water mark never moved");
}

// The names in the enums are the names in the reports.
//
// Small, and easy to skip, and it is the kind of thing that rots: a value
// added to an enum without a case is caught by -Werror=switch, but a case
// that returns the wrong string is caught by nothing at all.
void test_tls_error_names_cover_their_enums() {
    check(std::string{tls_error_name(TlsError::None)} == "none",
          "names: TlsError::None");
    check(std::string{tls_error_name(TlsError::MalformedDirectory)} ==
              "malformed_directory",
          "names: TlsError::MalformedDirectory");
    check(std::string{tls_error_name(TlsError::TooLarge)} == "too_large",
          "names: TlsError::TooLarge");
    check(std::string{tls_error_name(TlsError::CallbackFailed)} ==
              "callback_failed",
          "names: TlsError::CallbackFailed");
    check(std::string{tls_error_name(TlsError::OutOfMemory)} == "out_of_memory",
          "names: TlsError::OutOfMemory");

    check(std::string{tls_reason_name(TlsReason::ProcessDetach)} ==
              "process_detach",
          "names: TlsReason::ProcessDetach");
    check(std::string{tls_reason_name(TlsReason::ThreadAttach)} ==
              "thread_attach",
          "names: TlsReason::ThreadAttach");
    check(std::string{tls_reason_name(TlsReason::ThreadDetach)} ==
              "thread_detach",
          "names: TlsReason::ThreadDetach");
    check(std::string{tls_reason_name(TlsReason::ProcessAttach)} ==
              "process_attach",
          "names: TlsReason::ProcessAttach");

    // The values are a contract with the images, not an implementation
    // detail: a callback compiled against Windows switches on these numbers.
    check(static_cast<std::uint32_t>(TlsReason::ProcessDetach) == 0,
          "names: DLL_PROCESS_DETACH is 0");
    check(static_cast<std::uint32_t>(TlsReason::ThreadAttach) == 1,
          "names: DLL_THREAD_ATTACH is 1");
    check(static_cast<std::uint32_t>(TlsReason::ThreadDetach) == 2,
          "names: DLL_THREAD_DETACH is 2");
    check(static_cast<std::uint32_t>(TlsReason::ProcessAttach) == 3,
          "names: DLL_PROCESS_ATTACH is 3");
}


} // namespace


int main() {
    test_record_window_check_does_not_wrap();
    test_record_alignment_and_zero_size();
    test_record_overlap_detection();
    test_record_keeps_regions_in_address_order();
    test_bytes_of_kind_and_high_water();
    test_protection_names();

    test_loader_refuses_a_non_image();
    test_loader_refuses_another_machine();
    test_loader_relocation_requirement();
    test_loader_refuses_a_damaged_relocation_block();
    test_loader_refuses_a_relocation_that_overruns_its_region();
    test_loader_refuses_a_section_out_of_range();
    test_loader_section_protections();
    test_loader_maps_a_section_with_no_file_data();
    test_loader_rounds_section_sizes_to_the_page();
    test_loader_walks_imports();
    test_loader_refuses_an_iat_slot_that_overruns_its_region();
    test_loader_reads_an_ordinal_import();
    test_loader_drops_an_import_whose_slot_is_unmapped();
    test_loader_refuses_a_second_load_at_the_same_base();
    test_a_refused_load_leaves_the_space_alone();
    test_loader_refuses_an_unrunnable_entry_point();
    test_loader_refuses_overlapping_sections();
    test_record_batch_is_all_or_nothing();
    test_loader_emits_events();

    test_loads_the_handwritten_pe();

    test_tls_absent_directory_is_not_a_refusal();
    test_tls_all_zero_directory_is_no_tls();
    test_tls_writes_the_slot_into_the_image();
    test_tls_template_is_copied_from_the_mapping();
    test_tls_block_appends_zero_fill();
    test_tls_frees_and_reuses_a_slot();
    test_tls_pe32_has_no_callback_field();
    test_tls_refuses_a_reversed_template();
    test_tls_refuses_a_template_outside_the_image();
    test_tls_refuses_an_index_that_is_not_writable();
    test_tls_refuses_an_index_whose_field_does_not_fit();
    test_tls_without_a_mapper_decides_without_writing();
    test_a_refused_load_leaves_the_space_as_it_was();
    test_tls_reads_the_callback_array_to_its_terminator();
    test_tls_callbacks_stop_at_the_first_refusal();
    test_tls_free_releases_the_block();
    test_tls_va_encoded_directory_survives_only_where_it_is_true();
    test_tls_a_block_cannot_stand_in_for_the_template();
    test_tls_a_failed_block_gives_its_mapping_back();
    test_tls_pe32_ignores_the_word_after_its_directory();
    test_tls_directory_is_read_from_the_mapping_not_the_file();
    test_tls_error_names_cover_their_enums();
    test_a_claim_steps_over_an_address_something_else_took();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

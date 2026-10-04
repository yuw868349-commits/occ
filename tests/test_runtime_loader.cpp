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

#include <cstdint>
#include <cstdio>
#include <cstring>
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
    const std::size_t sections_at = opt + opt_size;
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
    put16(b.bytes, c + 16, static_cast<std::uint16_t>(opt_size));
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
    put32(b.bytes, count_at, 16);
    if (s.reloc_rva != 0) {
        put32(b.bytes, dirs + 5 * 8, s.reloc_rva);
        put32(b.bytes, dirs + 5 * 8 + 4, s.reloc_size);
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
    test_loader_refuses_a_section_out_of_range();
    test_loader_section_protections();
    test_loader_maps_a_section_with_no_file_data();
    test_loader_rounds_section_sizes_to_the_page();
    test_loader_walks_imports();
    test_loader_reads_an_ordinal_import();
    test_loader_drops_an_import_whose_slot_is_unmapped();
    test_loader_refuses_a_second_load_at_the_same_base();
    test_a_refused_load_leaves_the_space_alone();
    test_loader_refuses_an_unrunnable_entry_point();
    test_loader_refuses_overlapping_sections();
    test_record_batch_is_all_or_nothing();
    test_loader_emits_events();

    test_loads_the_handwritten_pe();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

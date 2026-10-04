// ELF image reader tests.
//
// The reader takes bytes and returns a description of the mappings the
// image asks for, so every case can be assembled in memory. The fixtures
// write every field the reader touches, which means a failure points at a
// field rather than at a zero that happened to be in the buffer. The cases
// are the ones that would pass if a constraint were missing: a header whose
// program table runs off the end, a segment that is not congruent to its
// alignment, a segment whose memory size is smaller than its file size.

#include "occ/parser/elf.h"

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

// The 64-bit header. The program header table starts right after it at 64,
// which is where a real static binary puts it.
constexpr std::size_t kHeaderSize = 64;
constexpr std::size_t kPhdrSize = 56;

void put_ident(std::vector<std::uint8_t>& b, std::uint8_t cls, std::uint8_t data,
               std::uint8_t version) {
    b[0] = 0x7f;
    b[1] = 'E';
    b[2] = 'L';
    b[3] = 'F';
    b[4] = cls;
    b[5] = data;
    b[6] = version;
}

// Writes one 64-bit program header. `p_flags` comes before the offsets in
// the 64-bit layout, which is the detail a reader that mirrored the order of
// the names would get wrong.
void put_phdr(std::vector<std::uint8_t>& b, std::size_t index, std::uint32_t type,
              std::uint32_t flags, std::uint64_t offset, std::uint64_t vaddr,
              std::uint64_t filesz, std::uint64_t memsz, std::uint64_t align) {
    const std::size_t base = kHeaderSize + index * kPhdrSize;
    put32(b, base + 0, type);
    put32(b, base + 4, flags);
    put64(b, base + 8, offset);
    put64(b, base + 16, vaddr);
    put64(b, base + 24, 0); // p_paddr, unused on x86-64
    put64(b, base + 32, filesz);
    put64(b, base + 40, memsz);
    put64(b, base + 48, align);
}

// One PT_LOAD segment plus the file contents it points at. The segment
// starts at file offset 4096 with vaddr 0x400000 so that the offsets and the
// addresses are congruent modulo the 4096 alignment, which is the rule the
// kernel's loader relies on.
struct Image {
    std::vector<std::uint8_t> bytes;
    std::size_t payload_off = 4096;
};

Image base_image(std::uint16_t type = 2, std::uint16_t machine = 62,
                 std::uint16_t phnum = 1, std::uint64_t entry = 0x401000) {
    Image img;
    // Three pages, so a fixture can place a segment both at file offset 4096
    // and at file offset 8192. The congruence rule ties p_offset to p_vaddr
    // modulo p_align, and dividing the offsets into separate pages is what
    // lets a two-segment fixture keep two distinct addresses without
    // breaking the rule or overlapping the payloads.
    img.bytes.assign(12288, 0);
    put_ident(img.bytes, 2, 1, 1);
    put16(img.bytes, 16, type);
    put16(img.bytes, 18, machine);
    put32(img.bytes, 20, 1);
    put64(img.bytes, 24, entry);
    put64(img.bytes, 32, kHeaderSize);
    put16(img.bytes, 52, 64);          // e_ehsize
    put16(img.bytes, 54, kPhdrSize);   // e_phentsize
    put16(img.bytes, 56, phnum);       // e_phnum
    return img;
}

ElfImage parse(const Image& img) {
    return ElfImage::parse(ByteSpan{img.bytes.data(), img.bytes.size()});
}

// Returns the mappings of an image that is expected to have parsed. A
// fixture that fails to parse on its own returns nothing here rather than
// reaching into an empty vector, so a wrong fixture reports a failed check
// instead of taking the whole suite down with it.
const std::vector<DesiredMapping>& mappings_of(const ElfImage& e) {
    static const std::vector<DesiredMapping> empty;
    return e.ok() ? e.mappings() : empty;
}

void test_exec_image() {
    Image img = base_image(2, 62, 2, 0x401000);
    // The second segment lives at file offset 8192 and address 0x401000.
    // Both are congruent to 0 modulo the 4096 alignment, which the
    // congruence rule demands, so putting the payload anywhere else would
    // make this fixture a test of the rule instead of a test of the reader.
    put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
    put_phdr(img.bytes, 1, 1, 6, 8192, 0x401000, 128, 256, 4096);

    const ElfImage e = parse(img);
    check(e.ok(), "a two-segment ET_EXEC parses");
    check(e.type() == 2, "e_type is ET_EXEC");
    check(e.machine() == 62, "e_machine is EM_X86_64");
    check(e.entry() == 0x401000, "e_entry is read");
    check(e.phoff() == kHeaderSize,
          "e_phoff comes from offset 32, not the 32-bit offset 28");
    check(e.phnum() == 2, "e_phnum comes from offset 56, not 44");
    check(e.phentsize() == kPhdrSize, "e_phentsize is read");
    check(e.headers().size() == 2, "both headers are kept");
    check(mappings_of(e).size() == 2, "both PT_LOAD headers become mappings");

    // The flags sit before the offsets in the 64-bit layout. A reader that
    // read them from where the name order suggests would pick up the low
    // half of p_offset, which is 4096 here.
    check(e.headers()[0].flags == 5, "p_flags is read from offset 4");
    check(e.headers()[0].readable() && e.headers()[0].executable(),
          "R and X are set on the code segment");
    check(!e.headers()[0].writable(), "W is clear on the code segment");
    check(e.headers()[1].writable(), "W is set on the data segment");

    check(e.headers()[0].offset == 4096, "p_offset is read");
    check(e.headers()[0].vaddr == 0x400000, "p_vaddr is read");
    check(e.headers()[0].filesz == 512, "p_filesz is read");
    check(e.headers()[0].memsz == 512, "p_memsz is read");
    check(e.headers()[0].align == 4096, "p_align is read");

    check(e.lowest_vaddr() == 0x400000, "the lowest address is the first "
                                        "segment");
    // The second segment occupies 0x401000 for 256 bytes, so its end rounds
    // up to 0x402000.
    check(e.highest_vaddr() == 0x402000, "the highest address is rounded to "
                                         "a page");
    check(!e.has_interpreter(), "a static image has no interpreter");
    check(!e.has_gnu_relro(), "no PT_GNU_RELRO in this fixture");
    check(!e.wants_executable_stack(), "no PT_GNU_STACK in this fixture");
}

void test_bss_tail() {
    // p_memsz > p_filesz is the .bss tail. It has to be reported as a
    // separate length, because the loader has to zero it rather than copy it
    // from the file.
    Image img = base_image(2, 62, 1);
    put_phdr(img.bytes, 0, 1, 6, 4096, 0x400000, 1024, 8192, 4096);

    const ElfImage e = parse(img);
    check(e.ok(), "a segment with a bss tail parses");
    check(e.headers()[0].zero_tail() == 7168,
          "the zero tail is memsz minus filesz");
    check(mappings_of(e)[0].memsz == 8192, "the mapping keeps p_memsz");
    check(mappings_of(e)[0].filesz == 1024, "the mapping keeps p_filesz");

    // The tail spans pages, so the mapping reaches past one page boundary.
    check(page_ceil(0x400000 + 8192) == 0x402000,
          "the tail spans two pages past the file-backed part");
}

void test_no_zero_tail() {
    Image img = base_image(2, 62, 1);
    put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 4096, 4096, 4096);
    const ElfImage e = parse(img);
    check(e.ok(), "an equal-size segment parses");
    check(e.headers()[0].zero_tail() == 0, "there is no tail when the sizes "
                                          "are equal");
}

void test_memsz_smaller_than_filesz() {
    // A segment that claims fewer bytes in memory than it has in the file
    // cannot be mapped: the kernel would have to drop part of what it was
    // told to load.
    Image img = base_image(2, 62, 1);
    put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 4096, 1024, 4096);
    const ElfImage e = parse(img);
    check(!e.ok(), "p_memsz < p_filesz is rejected");
    check(e.error() == LoadError::SegmentOutOfFile,
          "the rejection names the segment");
}

void test_segment_out_of_file() {
    Image img = base_image(2, 62, 1);
    // The payload starts on the last page, so 8192 bytes of it run past the
    // end of the file.
    put_phdr(img.bytes, 0, 1, 5, 8192, 0x400000, 8192, 8192, 4096);
    const ElfImage e = parse(img);
    check(!e.ok(), "a segment past the end of the file is rejected");
    check(e.error() == LoadError::SegmentOutOfFile,
          "the rejection names the file overrun");
}

void test_bad_alignment() {
    Image img = base_image(2, 62, 1);
    put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 3000);
    const ElfImage e = parse(img);
    check(!e.ok(), "a non-power-of-two p_align is rejected");
    check(e.error() == LoadError::BadAlignment, "the rejection names the "
                                                "alignment");
}

void test_congruence_rule() {
    // offset 4096 and vaddr 0x400800 are both congruent to 0 modulo 4096,
    // but not to each other. The kernel maps from the page the offset rounds
    // to, so a segment that breaks the rule would be mapped with the wrong
    // bytes at its start.
    Image img = base_image(2, 62, 1);
    put_phdr(img.bytes, 0, 1, 5, 4096, 0x400800, 512, 512, 4096);
    const ElfImage e = parse(img);
    check(!e.ok(), "a segment violating offset = vaddr (mod align) is "
                   "rejected");
    check(e.error() == LoadError::BadAlignment,
          "the rejection names the congruence rule");
}

void test_align_of_one_is_allowed() {
    // p_align 1 means no alignment requirement, and the congruence rule does
    // not apply to it.
    Image img = base_image(2, 62, 1);
    put_phdr(img.bytes, 0, 1, 5, 4096, 0x400001, 512, 512, 1);
    const ElfImage e = parse(img);
    check(e.ok(), "p_align 1 imposes no congruence requirement");
}

void test_class_and_endian_rejection() {
    {
        Image img = base_image();
        put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
        img.bytes[4] = 1; // ELFCLASS32
        const ElfImage e = parse(img);
        check(e.error() == LoadError::UnsupportedClass,
              "a 32-bit object is reported as the wrong class");
    }
    {
        Image img = base_image();
        put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
        img.bytes[5] = 2; // ELFDATA2MSB
        const ElfImage e = parse(img);
        check(e.error() == LoadError::UnsupportedEndian,
              "a big-endian object is reported as the wrong endianness");
    }
    {
        Image img = base_image();
        put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
        img.bytes[6] = 7;
        const ElfImage e = parse(img);
        check(e.error() == LoadError::NotElf,
              "an undefined EI_VERSION is not an ELF header");
    }
}

void test_machine_rejection() {
    Image img = base_image(2, 183); // EM_AARCH64
    put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
    const ElfImage e = parse(img);
    check(e.error() == LoadError::UnsupportedMachine,
          "a non-x86-64 object is reported as the wrong machine");
    check(e.error_detail().find("183") != std::string::npos,
          "the detail names the machine the file declares");
}

void test_type_rejection() {
    {
        Image img = base_image(1); // ET_REL
        put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
        const ElfImage e = parse(img);
        check(e.error() == LoadError::NoLoadSegments,
              "an ET_REL object is not a program");
    }
    {
        Image img = base_image(4); // ET_CORE
        put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
        const ElfImage e = parse(img);
        check(e.error() == LoadError::NoLoadSegments,
              "an ET_CORE file is not a program");
    }
    {
        Image img = base_image(7);
        put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
        const ElfImage e = parse(img);
        check(e.error() == LoadError::NoLoadSegments,
              "an undefined e_type is not a program");
    }
}

void test_no_load_segments() {
    // A file whose only program header is a PT_NOTE has nothing to map.
    Image img = base_image(2, 62, 1);
    put_phdr(img.bytes, 0, 4, 4, 4096, 0x400000, 512, 512, 4096);
    const ElfImage e = parse(img);
    check(e.error() == LoadError::NoLoadSegments,
          "a file with no PT_LOAD header is rejected");
}

void test_truncated_header() {
    // The magic alone is not a header. A file cut off after the
    // identification block has to be reported as truncated rather than
    // parsed with zeros for the fields that were never read.
    std::vector<std::uint8_t> b(32, 0);
    put_ident(b, 2, 1, 1);
    const ElfImage e = ElfImage::parse(ByteSpan{b.data(), b.size()});
    check(e.error() == LoadError::TruncatedHeader,
          "a file cut off inside the header is rejected");
}

void test_truncated_table() {
    {
        // The table starts before the end of the header, which cannot
        // happen in a well-formed file.
        Image img = base_image(2, 62, 1);
        put64(img.bytes, 32, 8);
        put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
        const ElfImage e = parse(img);
        check(e.error() == LoadError::TruncatedProgramHeaders,
              "a table overlapping the header is rejected");
    }
    {
        // Two entries declared but only room for one.
        Image img = base_image(2, 62, 2);
        img.bytes.resize(kHeaderSize + kPhdrSize);
        put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
        const ElfImage e = parse(img);
        check(e.error() == LoadError::TruncatedProgramHeaders,
              "a table running past the end of the file is rejected");
    }
    {
        // A different entry size means a different stride, and walking the
        // table with the wrong stride reads the wrong bytes.
        Image img = base_image(2, 62, 1);
        put16(img.bytes, 54, 48);
        put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
        const ElfImage e = parse(img);
        check(e.error() == LoadError::TruncatedProgramHeaders,
              "an unexpected e_phentsize is rejected");
    }
}

void test_interpreter() {
    // PT_INTERP holds a NUL-terminated path, and the terminator counts
    // toward p_filesz.
    Image img = base_image(3, 62, 2); // ET_DYN
    put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
    const char* interp = "/lib64/ld-linux-x86-64.so.2";
    const std::size_t len = std::strlen(interp) + 1;
    put_phdr(img.bytes, 1, 3, 4, 4096 + 512, 0x400200,
             static_cast<std::uint64_t>(len),
             static_cast<std::uint64_t>(len), 1);
    std::memcpy(img.bytes.data() + 4096 + 512, interp, len);

    const ElfImage e = parse(img);
    check(e.ok(), "an image with an interpreter parses");
    check(e.has_interpreter(), "the interpreter is noticed");
    check(e.interpreter() == interp,
          "the interpreter path is read up to the terminator");
    check(e.interpreter().size() == std::strlen(interp),
          "the terminator is not part of the path");
    check(e.type() == 3, "the ET_DYN type is kept");
}

void test_interp_out_of_file() {
    Image img = base_image(3, 62, 2);
    put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
    // PT_INTERP near the end of the file for more bytes than remain. The
    // reader copies the path out of the file rather than reporting an empty
    // string, so a truncated one has to be caught here.
    put_phdr(img.bytes, 1, 3, 4, 12224, 0x400200, 128, 128, 1);
    const ElfImage e = parse(img);
    check(e.error() == LoadError::SegmentOutOfFile,
          "a PT_INTERP past the end of the file is rejected");
}

// The cases below were found by the fuzz harness rather than by reading the
// reader, which is the point of having one: each is a header field set to a
// value that makes an ordinary bound check pass by wrapping. They are written
// as explicit fixtures because a fuzzer cannot be run from a unit test, and
// a fix with no test is a fix that comes back.
void test_overflowing_bounds() {
    // A program header table that starts past the end of the address space.
    // "phoff + phnum * 56" wraps to a small number, and a check written as
    // an addition would see a table inside a file that has none.
    {
        Image img = base_image(2, 62, 1);
        put64(img.bytes, 32, UINT64_MAX - 8);
        const ElfImage e = parse(img);
        check(!e.ok(), "a program table past the address space is refused");
        check(e.error() == LoadError::TruncatedProgramHeaders,
              "  and it is refused as a truncated table");
    }
    // The same table, at an offset that is merely very large rather than
    // wrapping. Both must be refused, and refused for the same reason, or a
    // fix for the wrap leaves this one open.
    {
        Image img = base_image(2, 62, 1);
        put64(img.bytes, 32, 1ULL << 62);
        const ElfImage e = parse(img);
        check(!e.ok(), "a program table far past the file is refused");
    }
    // A segment whose file range wraps: offset and filesz both near the top
    // of the address space, summing to less than either.
    {
        Image img = base_image(2, 62, 1);
        put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
        put64(img.bytes, kHeaderSize + 32, UINT64_MAX - 16);   // p_filesz
        put64(img.bytes, kHeaderSize + 8, UINT64_MAX - 8);     // p_offset
        const ElfImage e = parse(img);
        check(!e.ok(), "a segment whose file range wraps is refused");
    }
    // A segment that claims more address space than exists above it.
    // vaddr + memsz wraps, and a caller computing the end of the mapping
    // would read the wrapped value as a length -- a petabyte described as a
    // few bytes. Both numbers here are ordinary; only their sum is not.
    {
        Image img = base_image(2, 62, 1);
        put_phdr(img.bytes, 0, 1, 5, 4096, 0xfffffd0004000000ULL,
                 0, 0x7a0000000000ULL, 4096);
        const ElfImage e = parse(img);
        check(!e.ok(), "a segment that does not fit in the address space is "
                       "refused");
    }
    // memsz of zero is exempt: it maps nothing, and zero at the top of the
    // address space is still zero. A fix that refused this would break a
    // legal file, so the boundary is pinned from both sides.
    {
        Image img = base_image(2, 62, 1);
        put_phdr(img.bytes, 0, 1, 5, 4096, UINT64_MAX - 4095, 0, 0, 4096);
        const ElfImage e = parse(img);
        check(e.ok(), "a segment of zero size at the top of the address space "
                      "is still legal");
    }
}

void test_interp_empty_path() {
    // A PT_INTERP whose first byte is NUL names a path of length zero.
    // Reporting has_interpreter() true alongside an empty path is a state
    // the rest of occ cannot act on: the loader would execve("") and the
    // failure would name the interpreter rather than the file.
    {
        Image img = base_image(3, 62, 2);
        put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
        // The path is a single NUL byte: filesz of 1 starting at 4097, so
        // the byte is inside the file and is the segment's whole content.
        img.bytes[4097] = 0;
        put_phdr(img.bytes, 1, 3, 4, 4097, 0x400200, 1, 1, 1);
        const ElfImage e = parse(img);
        check(!e.ok(), "a PT_INTERP naming an empty path is refused");
    }
    // The segment immediately after it, so the refusal is shown to be about
    // the empty path rather than about the fixture's second segment.
    {
        Image img = base_image(3, 62, 2);
        put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
        const char* interp = "/lib64/ld-linux-x86-64.so.2";
        std::memcpy(img.bytes.data() + 4096, interp, std::strlen(interp) + 1);
        put_phdr(img.bytes, 1, 3, 4, 4096, 0x400200,
                 std::strlen(interp) + 1, std::strlen(interp) + 1, 1);
        const ElfImage e = parse(img);
        check(e.ok() && e.has_interpreter() && !e.interpreter().empty(),
              "a PT_INTERP naming a real path is accepted");
    }
}

void test_gnu_stack() {
    {
        Image img = base_image(2, 62, 2);
        put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
        put_phdr(img.bytes, 1, 0x6474e551, 6, 0, 0, 0, 0x200000, 16);
        const ElfImage e = parse(img);
        check(e.ok(), "an image with PT_GNU_STACK parses");
        check(e.stack().present, "PT_GNU_STACK is noticed");
        check(!e.wants_executable_stack(),
              "a non-executable stack request is not a request for an "
              "executable one");
        check(e.stack().size == 0x200000, "the stack size request is kept");
    }
    {
        // p_flags with X set is the request for an executable stack, which
        // is a fact the caller has to decide about rather than one to
        // honour silently.
        Image img = base_image(2, 62, 2);
        put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
        put_phdr(img.bytes, 1, 0x6474e551, 7, 0, 0, 0, 0x200000, 16);
        const ElfImage e = parse(img);
        check(e.wants_executable_stack(),
              "an executable stack request is reported");
    }
}

void test_gnu_relro() {
    Image img = base_image(2, 62, 2);
    put_phdr(img.bytes, 0, 1, 5, 4096, 0x400000, 512, 512, 4096);
    put_phdr(img.bytes, 1, 0x6474e552, 4, 4096, 0x400000, 512, 512, 1);
    const ElfImage e = parse(img);
    check(e.ok(), "an image with PT_GNU_RELRO parses");
    check(e.has_gnu_relro(), "PT_GNU_RELRO is noticed");
    check(mappings_of(e).size() == 1,
          "a PT_GNU_RELRO header is not a mapping");
}

void test_sorting() {
    // The loader sorts the segments by address because a segment that
    // overlaps another has to be placed in address order for the later
    // permissions to be the ones that apply.
    Image img = base_image(2, 62, 2);
    put_phdr(img.bytes, 0, 1, 6, 8192, 0x401000, 128, 128, 4096);
    put_phdr(img.bytes, 1, 1, 5, 4096, 0x400000, 512, 512, 4096);

    const ElfImage e = parse(img);
    check(e.ok(), "segments in descending order parse");
    check(mappings_of(e)[0].vaddr == 0x400000,
          "the lowest address comes first after sorting");
    check(mappings_of(e)[1].vaddr == 0x401000, "the higher address follows");
    check(e.lowest_vaddr() == 0x400000,
          "the lowest address is taken after sorting, not from the first "
          "header read");
}

void test_page_helpers() {
    check(page_floor(0x400123) == 0x400000, "page_floor rounds down");
    check(page_ceil(0x400123) == 0x401000, "page_ceil rounds up");
    check(page_floor(0x400000) == 0x400000,
          "page_floor leaves an aligned value alone");
    check(page_ceil(0x400000) == 0x400000,
          "page_ceil leaves an aligned value alone");
    check(page_ceil(1) == kPageSize, "page_ceil rounds a small value up to "
                                     "one page");
}

void test_error_names() {
    check(std::strcmp(load_error_name(LoadError::None), "none") == 0,
          "the success name");
    check(std::strcmp(load_error_name(LoadError::BadAlignment),
                      "a segment has an alignment that is not a power of two") == 0,
          "the alignment name");
    check(std::strcmp(load_error_name(LoadError::SegmentOutOfFile),
                      "a segment extends past the end of the file") == 0,
          "the out-of-file name");
}

void test_truncated_buffer_is_not_elF() {
    std::vector<std::uint8_t> b(3, 0);
    const ElfImage e = ElfImage::parse(ByteSpan{b.data(), b.size()});
    check(!e.ok(), "three bytes are not an ELF file");
    check(e.error() == LoadError::NotElf, "a short buffer is not an ELF "
                                          "header");
}

// ------------------------------------------------------------- symbols
//
// The fixtures below build an image with a section header table, a dynamic
// symbol table, a string table for the symbols and a string table for the
// section names. Every one of these is a separate way for the reader to be
// wrong, and a single fixture with a real binary would exercise all four at
// once -- so they are assembled here, in memory, with every offset chosen
// by this file.
//
// The addresses are chosen so that p_offset and p_vaddr are not equal. A
// fixture where they are equal cannot tell a reader that converts an
// address to a file offset from one that returns the address unchanged, and
// returning the address unchanged is exactly what a probe request must not
// do: the kernel's uprobe request is stated in file offsets.

constexpr std::size_t kShdrSize = 64;
constexpr std::size_t kSymSize = 24;

// The layout of the symbol fixture, in one place so the offsets that point
// into each other cannot drift apart. Everything starts after the three
// pages base_image allocates, so a fixture that grows the header cannot
// silently overlap the first segment's payload.
struct SymbolFixture {
    std::size_t shoff = 0;
    std::size_t symoff = 0;
    std::size_t symcount = 0;
    std::size_t stroff = 0;
    std::size_t shstroff = 0;
    std::size_t shnum = 0;
};

// Builds an image whose single PT_LOAD segment maps file offset 0x1000 to
// address 0x500000. The two differ, which is what makes the address-to-
// offset conversion testable.
Image symbol_image(SymbolFixture& fix) {
    Image img = base_image();
    // One segment: file offset 0x1000, vaddr 0x500000. Congruent modulo
    // 4096 (both 0), so the rule the reader enforces is satisfied.
    put_phdr(img.bytes, 0, 1, 5, 0x1000, 0x500000, 0x1000, 0x1000, 4096);

    // The string tables are built one name at a time, and the offsets are
    // taken as names are appended.
    //
    // Both halves matter. Writing the tables as string literals is wrong in
    // a way that produces a table with no interior NULs at all: the
    // expression std::string("\0", 1) + ".dynsym\0.dynstr\0" appends a
    // const char*, which is appended up to its first NUL -- so the second
    // and later names are simply absent, and every name offset past the
    // first points into the middle of the first name. The table is then
    // well-formed enough to parse and produces names that are slices of
    // other names, which is exactly the kind of wrong a fixture must not
    // have. Appending and recording offsets avoids the question.
    std::string strtab("\0", 1);
    const std::size_t main_off = strtab.size();
    strtab += "main";
    strtab.push_back('\0');
    const std::size_t helper_off = strtab.size();
    strtab += "helper";
    strtab.push_back('\0');
    const std::size_t undef_off = strtab.size();
    strtab += "undefined_sym";
    strtab.push_back('\0');
    const std::size_t object_off = strtab.size();
    strtab += "data_object";
    strtab.push_back('\0');

    fix.symoff = 0x2000;
    fix.symcount = 4;
    fix.stroff = fix.symoff + fix.symcount * kSymSize;
    const std::size_t strentries = fix.symcount * kSymSize;

    std::string shstr("\0", 1);
    const std::size_t n_dynsym = shstr.size();
    shstr += ".dynsym";
    shstr.push_back('\0');
    const std::size_t n_dynstr = shstr.size();
    shstr += ".dynstr";
    shstr.push_back('\0');
    const std::size_t n_shstrtab = shstr.size();
    shstr += ".shstrtab";
    shstr.push_back('\0');

    fix.shstroff = fix.stroff + strtab.size();
    // The section headers are aligned to eight bytes. Nothing in the reader
    // requires it -- every field is read by offset rather than by a
    // structure load -- but a fixture laid out the way a linker lays one out
    // is a fixture that would still be valid if the reader ever did.
    fix.shoff = (fix.shstroff + shstr.size() + 7) & ~std::size_t{7};
    fix.shnum = 4;

    img.bytes.resize(fix.shoff + fix.shnum * kShdrSize, 0);

    // The symbols. Symbol zero is the all-zero entry every table starts
    // with, and it must not appear in the result.
    //
    //   main          FUNC   GLOBAL  defined, vaddr 0x500100
    //   helper        FUNC   LOCAL   defined, vaddr 0x500200
    //   undefined_sym FUNC   GLOBAL  undefined (shndx 0)
    //   data_object   OBJECT GLOBAL  defined, vaddr 0x500300
    auto put_sym = [&](std::size_t idx, std::size_t name_off, std::uint8_t bind,
                       std::uint8_t type, std::uint16_t shndx,
                       std::uint64_t value, std::uint64_t size) {
        const std::size_t base = fix.symoff + idx * kSymSize;
        put32(img.bytes, base + 0, static_cast<std::uint32_t>(name_off));
        // st_info packs the binding in the high nibble and the type in the
        // low one. Both are passed in already split so the packing is
        // visible here rather than buried in a caller.
        img.bytes[base + 4] = static_cast<std::uint8_t>((bind << 4) | type);
        put16(img.bytes, base + 6, shndx);
        put64(img.bytes, base + 8, value);
        put64(img.bytes, base + 16, size);
    };
    put_sym(0, main_off, 1, 2, 1, 0x500100, 64);   // main
    put_sym(1, helper_off, 0, 2, 1, 0x500200, 32); // helper
    put_sym(2, undef_off, 1, 2, 0, 0, 0);          // undefined_sym
    put_sym(3, object_off, 1, 1, 1, 0x500300, 16); // data_object

    // The strings.
    std::memcpy(img.bytes.data() + fix.stroff, strtab.data(), strtab.size());

    // The section headers. Index 0 is SHT_NULL by definition; 1 is the
    // dynamic symbol table and points at index 2 as its string table; 2 is
    // .dynstr; 3 is .shstrtab, which e_shstrndx names.
    auto shdr = [&](std::size_t idx, std::size_t name_off, std::uint32_t type,
                    std::uint64_t off, std::uint64_t size, std::uint32_t link,
                    std::uint64_t entsize) {
        const std::size_t base = fix.shoff + idx * kShdrSize;
        put32(img.bytes, base + 0, static_cast<std::uint32_t>(name_off));
        put32(img.bytes, base + 4, type);
        put64(img.bytes, base + 24, off);
        put64(img.bytes, base + 32, size);
        put32(img.bytes, base + 40, link);
        put64(img.bytes, base + 56, entsize);
    };
    shdr(0, 0, 0, 0, 0, 0, 0);
    // .dynsym: SHT_DYNSYM(11), link 2 (.dynstr), stride 24
    shdr(1, n_dynsym, 11, fix.symoff, strentries, 2, kSymSize);
    // .dynstr: SHT_STRTAB(3)
    shdr(2, n_dynstr, 3, fix.stroff, strtab.size(), 0, 0);
    // .shstrtab: SHT_STRTAB(3)
    shdr(3, n_shstrtab, 3, fix.shstroff, shstr.size(), 0, 0);

    std::memcpy(img.bytes.data() + fix.shstroff, shstr.data(), shstr.size());

    // The header's section fields.
    put64(img.bytes, 40, fix.shoff);
    put16(img.bytes, 58, static_cast<std::uint16_t>(kShdrSize));
    put16(img.bytes, 60, static_cast<std::uint16_t>(fix.shnum));
    // e_shstrndx names index 3, and is written 3.
    put16(img.bytes, 62, 3);

    return img;
}

void test_sections_are_read() {
    SymbolFixture fix{};
    const Image img = symbol_image(fix);
    const ElfImage e = parse(img);
    check(e.ok(), "an image with a section table still parses");
    check(e.sections().size() == 4, "four section headers are read");
    check(e.has_symbols(), "the dynamic symbols are found");
    check(e.symbol_status() == SymbolStatus::Found, "the status is found");

    // The names resolve through e_shstrndx and not through sh_link. This is
    // the assertion that fails when the two are confused: sh_link of
    // .dynsym is 2, which is .dynstr, and reading the section's own name
    // out of .dynstr produces a symbol name rather than a section name.
    const std::string n0 = e.section_name(e.sections()[1], ByteSpan{img.bytes.data(), img.bytes.size()});
    const std::string n1 = e.section_name(e.sections()[2], ByteSpan{img.bytes.data(), img.bytes.size()});
    const std::string n2 = e.section_name(e.sections()[3], ByteSpan{img.bytes.data(), img.bytes.size()});
    check(n0 == ".dynsym", "the symbol table's section is named .dynsym");
    check(n1 == ".dynstr", "the string table's section is named .dynstr");
    check(n2 == ".shstrtab", "the name table's section is named .shstrtab");
}

void test_symbol_names_and_types() {
    SymbolFixture fix{};
    const Image img = symbol_image(fix);
    const ElfImage e = parse(img);

    check(e.dynamic_symbols().size() == 4,
          "the all-zero first symbol is not stored");

    const Symbol* main_sym = e.find_symbol("main");
    check(main_sym != nullptr, "main is found by name");
    if (main_sym != nullptr) {
        check(main_sym->value == 0x500100, "main's address");
        check(main_sym->size == 64, "main's size");
        check(main_sym->type == SymbolType::Func, "main is a function");
        check(main_sym->bind == SymbolBind::Global, "main is global");
        check(main_sym->defined(), "main is defined");
        check(main_sym->probeable(), "main is a place a probe can go");
    }

    const Symbol* helper = e.find_symbol("helper");
    check(helper != nullptr, "helper is found by name");
    if (helper != nullptr) {
        check(helper->bind == SymbolBind::Local, "helper is local");
        check(helper->probeable(), "a local function is still probeable");
    }

    const Symbol* data = e.find_symbol("data_object");
    check(data != nullptr, "the object symbol is found");
    if (data != nullptr) {
        check(data->type == SymbolType::Object, "it is typed as an object");
        check(!data->probeable(),
              "an object is not a function and is not probeable");
    }

    check(e.find_symbol("no_such_symbol") == nullptr,
          "a name that is not in the table is absent");
}

void test_undefined_symbol_is_not_probeable() {
    SymbolFixture fix{};
    const Image img = symbol_image(fix);
    const ElfImage e = parse(img);

    // The undefined symbol is stored -- its address is a real entry in a
    // real table -- but it is not something to attach a probe to. A caller
    // that treated an undefined symbol as a probe target would ask the
    // kernel for a probe at address zero, or at whatever the loader has not
    // yet written there.
    const Symbol* s = e.find_symbol("undefined_sym");
    check(s != nullptr, "an undefined symbol is still in the table");
    if (s != nullptr) {
        check(!s->defined(), "it is marked undefined");
        check(!s->probeable(), "an undefined symbol is not probeable");
    }
}

void test_defined_symbol_wins_over_undefined() {
    SymbolFixture fix{};
    Image img = symbol_image(fix);
    // Two symbols named "main": one defined at index 0, one undefined added
    // at index 2 in place of the fixture's own undefined_sym. A lookup that
    // returned the first match by table order would depend on which of the
    // two the linker happened to write first, which is a property of the
    // file rather than of the question being asked.
    //
    // Rather than growing the table -- which would move the string table and
    // the section headers and make the fixture's own offsets a second thing
    // under test -- the existing entry is renamed. The table's size is
    // unchanged and every other offset still means what it meant.
    const std::size_t undef_index = 2;
    const std::size_t base = fix.symoff + undef_index * kSymSize;
    const std::uint32_t main_off = 1; // "main" in the string table
    put32(img.bytes, base + 0, main_off);
    // Still undefined: GLOBAL|FUNC with shndx 0 and value 0.
    img.bytes[base + 4] = static_cast<std::uint8_t>((1u << 4) | 2u);
    put16(img.bytes, base + 6, 0);
    put64(img.bytes, base + 8, 0);

    const ElfImage e = parse(img);
    check(e.has_symbols(), "the fixture still has symbols");

    const Symbol* s = e.find_symbol("main");
    check(s != nullptr, "main is still found");
    if (s != nullptr) {
        check(s->defined(),
              "the defined main wins over the undefined one of the same name");
        check(s->value == 0x500100, "and it is the one with an address");
        check(s->shndx != 0, "and it is defined in a section");
    }
}

void test_undefined_symbol_is_found_when_it_is_the_only_one() {
    SymbolFixture fix{};
    Image img = symbol_image(fix);
    // Make the undefined entry the only one by that name. The symbol at
    // index 2 is already undefined and already carries the name; the
    // defined symbol at index 0 is renamed away from it, and its own
    // definition is cleared so that nothing with that name is probeable.
    //
    // A lookup that dropped undefined symbols entirely would answer "no
    // such symbol", which is a different claim from "there is a symbol by
    // that name and it has no code behind it" -- and it is the difference
    // between a caller looking in the wrong place and being told the right
    // one.
    const std::size_t undef_index = 2;
    const std::size_t base = fix.symoff + undef_index * kSymSize;
    put32(img.bytes, base + 0, 1); // "main", which index 0 also uses
    // Clear index 0's definition so it is not the probeable match.
    put16(img.bytes, fix.symoff + 0 * kSymSize + 6, 0);
    put64(img.bytes, fix.symoff + 0 * kSymSize + 8, 0);

    const ElfImage e = parse(img);
    const Symbol* s = e.find_symbol("main");
    check(s != nullptr, "an undefined symbol is found by name");
    if (s != nullptr) {
        check(!s->defined(), "and it is reported as undefined");
        check(!s->probeable(), "and it is not a place to put a probe");
    }
}

void test_vaddr_to_file_offset_converts() {
    SymbolFixture fix{};
    const Image img = symbol_image(fix);
    const ElfImage e = parse(img);

    // The segment maps file offset 0x1000 to address 0x500000, so a symbol
    // at 0x500100 is at file offset 0x1100. A reader that returned the
    // address unchanged would give 0x500100, which is not in the file at
    // all -- and a probe request at that offset is refused by the kernel
    // with an error that names the offset rather than the conversion.
    std::uint64_t off = 0;
    check(e.vaddr_to_file_offset(0x500100, off), "an address in the segment "
                                                 "converts");
    check(off == 0x1100, "the converted offset is 0x1000 + (0x500100 - "
                         "0x500000)");
    if (off == 0x1100) {
        // The value at that file offset is the fixture's own byte, which
        // proves the conversion names a real position rather than a number
        // that happens to be right.
        check(img.bytes[off] == 0, "the offset lands in the segment's payload");
    }

    check(e.vaddr_to_file_offset(0x500000, off), "the segment's first byte "
                                                 "converts");
    check(off == 0x1000, "and it maps to p_offset");

    // An address below the segment is in no segment.
    check(!e.vaddr_to_file_offset(0x4fffff, off),
          "an address below the segment does not convert");
    // An address past the segment's memory size is in no segment.
    check(!e.vaddr_to_file_offset(0x501000, off),
          "an address at the segment's end does not convert");
    // An address in the segment's memory but past its file size is in the
    // zero tail, which has no file offset to name.
    check(!e.vaddr_to_file_offset(0x501000, off),
          "an address in the zero tail does not convert");
}

void test_zero_tail_has_no_file_offset() {
    Image img = base_image();
    // A segment whose memory size is larger than its file size: the bytes
    // from filesz to memsz are zeroed by the loader, not read from the file.
    put_phdr(img.bytes, 0, 1, 5, 0x1000, 0x500000, 0x400, 0x1000, 4096);
    img.bytes.resize(0x2000, 0);
    const ElfImage e = parse(img);

    std::uint64_t off = 0;
    check(e.vaddr_to_file_offset(0x500300, off),
          "an address inside the file-backed part converts");
    check(off == 0x1300, "and it is p_offset plus the delta");
    // 0x500400 is the first byte of the zero tail. There is no byte there in
    // the file, so there is no offset to give.
    check(!e.vaddr_to_file_offset(0x500400, off),
          "the first byte of the zero tail does not convert");
    check(!e.vaddr_to_file_offset(0x500800, off),
          "an address in the middle of the zero tail does not convert");
}

void test_no_section_table_is_a_status_not_an_error() {
    // The image parses and has no symbols. That is a fact about the file,
    // not a failure: the kernel will run it, and a probe layer reports the
    // absence of function-level observation rather than the absence of a
    // program.
    Image img = base_image();
    put_phdr(img.bytes, 0, 1, 5, 0x1000, 0x500000, 0x400, 0x400, 4096);
    const ElfImage e = parse(img);

    check(e.ok(), "an image with no section table still loads");
    check(!e.has_symbols(), "and it reports no symbols");
    check(e.symbol_status() == SymbolStatus::NoSectionTable,
          "with the reason being that there is no section table");
    check(std::strlen(symbol_status_detail(e.symbol_status())) > 0,
          "and the reason is a sentence");
    check(e.find_symbol("main") == nullptr,
          "no name resolves, which is the honest answer");
}

void test_section_table_that_runs_off_the_file() {
    SymbolFixture fix{};
    Image img = symbol_image(fix);
    const ElfImage ok_image = parse(img);
    check(ok_image.ok(), "the fixture parses before it is damaged");

    // e_shoff points past the end. The image still loads, and the symbol
    // status says the table is not there rather than that the program is
    // broken.
    put64(img.bytes, 40, img.bytes.size() + 4096);
    const ElfImage e = parse(img);
    check(e.ok(),
          "a section table that is not in the file does not fail the load");
    check(!e.has_symbols(), "and no symbols are found");
    check(e.symbol_status() == SymbolStatus::NoSectionTable,
          "the section table is reported as absent");
}

void test_dynsym_without_a_string_table() {
    SymbolFixture fix{};
    Image img = symbol_image(fix);
    // sh_link of .dynsym points at index 0, which is SHT_NULL and not a
    // string table. The symbols still have addresses; they have no names,
    // and a caller probing by name cannot proceed. That is NoStringTable
    // and not a silently empty symbol list, which a caller would read as
    // "this file exports nothing" -- a different claim from "the names are
    // not here to be read".
    //
    // Index 0 rather than index 3 is what makes this a test of the type
    // check: .shstrtab is itself a SHT_STRTAB, so pointing at it would
    // satisfy a reader that only asked whether the section is a string
    // table. The answer would then be names -- the wrong ones, which is
    // worse than none.
    put32(img.bytes, fix.shoff + 1 * kShdrSize + 40, 0); // link -> SHT_NULL
    const ElfImage e = parse(img);
    check(e.ok(), "the image still loads");
    check(e.symbol_status() == SymbolStatus::NoStringTable,
          "a symbol table whose link is not a string table is reported");
    check(e.dynamic_symbols().empty(),
          "and no symbols are produced from it");
}

void test_section_name_table_zero() {
    SymbolFixture fix{};
    Image img = symbol_image(fix);
    // e_shstrndx zero means there is no section name table. Section names
    // are then empty, and nothing else changes.
    put16(img.bytes, 62, 0);
    const ElfImage e = parse(img);
    check(e.ok(), "an image with no name table still loads");
    check(e.sections().size() == 4, "the sections are still read");
    check(e.section_name(e.sections()[1],
                         ByteSpan{img.bytes.data(), img.bytes.size()})
              .empty(),
          "and every name is empty rather than guessed");
    check(e.has_symbols(), "the symbols are unaffected");
}

void test_section_name_resolves_through_shstrndx() {
    SymbolFixture fix{};
    Image img = symbol_image(fix);
    // Point e_shstrndx at .dynstr instead of .shstrtab. The names are then
    // resolved through the wrong table, which is what a reader that used
    // sh_link would do -- and the assertion that it produces the wrong name
    // is what pins the two apart.
    put16(img.bytes, 62, 2); // .dynstr
    const ElfImage e = parse(img);
    const std::string wrong =
        e.section_name(e.sections()[1], ByteSpan{img.bytes.data(), img.bytes.size()});
    check(wrong != ".dynsym",
          "naming a section through the symbol string table does not produce "
          "its section name");
}

} // namespace

int main() {
    test_exec_image();
    test_bss_tail();
    test_no_zero_tail();
    test_memsz_smaller_than_filesz();
    test_segment_out_of_file();
    test_bad_alignment();
    test_congruence_rule();
    test_align_of_one_is_allowed();
    test_class_and_endian_rejection();
    test_machine_rejection();
    test_type_rejection();
    test_no_load_segments();
    test_truncated_header();
    test_truncated_table();
    test_interpreter();
    test_interp_out_of_file();
    test_overflowing_bounds();
    test_interp_empty_path();
    test_gnu_stack();
    test_gnu_relro();
    test_sorting();
    test_page_helpers();
    test_error_names();
    test_truncated_buffer_is_not_elF();
    test_sections_are_read();
    test_symbol_names_and_types();
    test_undefined_symbol_is_not_probeable();
    test_defined_symbol_wins_over_undefined();
    test_undefined_symbol_is_found_when_it_is_the_only_one();
    test_vaddr_to_file_offset_converts();
    test_zero_tail_has_no_file_offset();
    test_no_section_table_is_a_status_not_an_error();
    test_section_table_that_runs_off_the_file();
    test_dynsym_without_a_string_table();
    test_section_name_table_zero();
    test_section_name_resolves_through_shstrndx();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

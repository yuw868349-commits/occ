// Format detection tests.
//
// Detection is pure: it takes bytes and returns a verdict, so every case can
// be built in memory. The cases below are chosen so that each one would fail
// if a specific constraint were dropped from the detector -- a magic alone
// is not enough for any format, and the tests supply both the near miss and
// the real match.

#include "occ/parser/detect.h"

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

Detection run(const std::vector<std::uint8_t>& b) {
    return detect_bytes(ByteSpan{b.data(), b.size()});
}

// Builds an ELF64 header. Every field the detector reads is written, so a
// failure names a real field rather than a zero that happened to be there.
std::vector<std::uint8_t> elf64(std::uint16_t type, std::uint16_t machine,
                                std::uint16_t phnum, std::uint64_t phoff) {
    std::vector<std::uint8_t> b(128, 0);
    b[0] = 0x7f;
    b[1] = 'E';
    b[2] = 'L';
    b[3] = 'F';
    b[4] = 2; // ELFCLASS64
    b[5] = 1; // ELFDATA2LSB
    b[6] = 1; // EV_CURRENT
    b[7] = 0; // ELFOSABI_SYSV
    put16(b, 16, type);
    put16(b, 18, machine);
    put32(b, 20, 1);
    put64(b, 24, 0x401000);
    put64(b, 32, phoff);
    put16(b, 56, phnum);
    put16(b, 52, 64);  // e_ehsize
    put16(b, 54, 56);  // e_phentsize
    return b;
}

void test_elf64() {
    const auto b = elf64(2, 62, 11, 64);
    const Detection d = run(b);

    check(d.format == Format::Elf, "a valid ELF64 executable is detected");
    check(d.elf_class == ElfClass::Elf64, "the class is read");
    check(d.elf_endian == ElfEndian::Little, "the endianness is read");
    check(d.elf_type == ElfType::Exec, "e_type is read");
    check(d.elf_machine == ElfMachine::X86_64, "e_machine is read");
    check(!d.bare_program_header, "a real ELF header is not a bare program "
                                  "header");

    // The program header table offset has to come from the 64-bit field.
    // Reading the 32-bit offset instead lands on e_entry, which the fixture
    // sets to a value that is not 64, so the two are distinguishable.
    bool mentions_64 = false;
    for (const auto& e : d.evidence) {
        if (e.find("0x40") != std::string::npos &&
            e.find("segments") != std::string::npos) {
            mentions_64 = true;
        }
    }
    check(mentions_64, "the program header offset is read from the 64-bit "
                       "field");
}

void test_elf32_offsets() {
    // A 32-bit header has e_phoff at 28 and e_phnum at 44. Writing the same
    // numbers to the 64-bit locations and reading them back would produce a
    // wrong table, so this case is the one that catches a shared constant.
    std::vector<std::uint8_t> b(128, 0);
    b[0] = 0x7f;
    b[1] = 'E';
    b[2] = 'L';
    b[3] = 'F';
    b[4] = 1; // ELFCLASS32
    b[5] = 1;
    b[6] = 1;
    put16(b, 16, 2);
    put16(b, 18, 3); // EM_386
    put32(b, 20, 1);
    put32(b, 24, 0x8048000);
    put32(b, 28, 52); // e_phoff
    put16(b, 44, 5);  // e_phnum
    put16(b, 56, 0);  // a value at the 64-bit location, to be ignored

    const Detection d = run(b);
    check(d.format == Format::Elf, "a 32-bit ELF is detected");
    check(d.elf_class == ElfClass::Elf32, "the 32-bit class is read");
    check(d.elf_machine == ElfMachine::X86, "EM_386 is read");

    bool found = false;
    for (const auto& e : d.evidence) {
        if (e.find("e_phnum = 5") != std::string::npos) {
            found = true;
        }
    }
    check(found, "the 32-bit program header count comes from offset 44");
}

void test_elf_ident_rejection() {
    // A file whose identification block is invalid is not an ELF file, no
    // matter that the magic matches. Each field is tested on its own.
    auto b = elf64(2, 62, 1, 64);
    b[4] = 7; // an undefined class
    check(run(b).format == Format::Unknown,
          "an undefined EI_CLASS is rejected");

    b = elf64(2, 62, 1, 64);
    b[5] = 9; // an undefined data encoding
    check(run(b).format == Format::Unknown,
          "an undefined EI_DATA is rejected");

    b = elf64(2, 62, 1, 64);
    b[6] = 2; // an undefined version
    check(run(b).format == Format::Unknown,
          "an undefined EI_VERSION is rejected");

    // A file that is shorter than a header but has the magic is reported as
    // an ELF whose header could not be read, not as a different format.
    std::vector<std::uint8_t> tiny{0x7f, 'E', 'L', 'F', 2, 1, 1, 0};
    const Detection d = run(tiny);
    check(d.format == Format::Unknown || d.format == Format::Elf,
          "a truncated ELF is not misclassified as another format");
}

void test_bare_program_header() {
    // An Android OAT file begins with a program header: p_type = PT_LOAD.
    std::vector<std::uint8_t> b(64, 0);
    put32(b, 0, 1); // PT_LOAD
    put32(b, 4, 5); // PF_R | PF_X

    const Detection d = run(b);
    check(d.format == Format::Elf, "a bare program header is an ELF container");
    check(d.bare_program_header, "the bare-program-header layout is flagged");
    check(d.elf_class == ElfClass::Elf64, "the implied class is 64-bit");

    // p_flags above 7 is not a valid combination and the file is therefore
    // not treated as a program header.
    put32(b, 4, 0x40000000);
    check(!run(b).bare_program_header,
          "a program header with impossible flags is not accepted");
}

void test_apk() {
    // A real Android package starts with a local file header whose name is
    // AndroidManifest.xml, stored uncompressed.
    const char* name = "AndroidManifest.xml";
    const std::size_t name_len = std::strlen(name);
    std::vector<std::uint8_t> b(30 + name_len + 64, 0);
    put32(b, 0, 0x04034b50);
    put16(b, 4, 20);  // version needed
    put16(b, 6, 0);   // flags
    put16(b, 8, 0);   // method: stored
    put32(b, 18, 1024);
    put16(b, 26, static_cast<std::uint16_t>(name_len));
    std::memcpy(b.data() + 30, name, name_len);

    const Detection d = run(b);
    check(d.format == Format::Apk, "an APK is detected from its first member");
    check(!d.evidence.empty(), "the detection carries evidence");

    // The same member deflated is not a valid package, because a reader has
    // to be able to reach the manifest without inflating anything.
    put16(b, 8, 8);
    check(run(b).format == Format::Zip,
          "a deflated manifest is a zip rather than a package");

    // A zip whose first member is something else is not a package.
    const char* other = "classes.dex";
    const std::size_t other_len = std::strlen(other);
    std::vector<std::uint8_t> c(30 + other_len + 64, 0);
    put32(c, 0, 0x04034b50);
    put16(c, 8, 0);
    put16(c, 26, static_cast<std::uint16_t>(other_len));
    std::memcpy(c.data() + 30, other, other_len);
    check(run(c).format == Format::Zip,
          "a zip whose first member is not the manifest is not a package");
}

void test_macho() {
    // Both byte orders of the 32-bit magic, so a detector that only checks
    // one order is caught.
    for (std::uint32_t magic : {0xfeedfaceU, 0xcefaedfeU}) {
        std::vector<std::uint8_t> b(64, 0);
        put32(b, 0, magic);
        check(run(b).format == Format::MachO, "a Mach-O magic is detected");
    }

    // The little-endian 64-bit magic 0xfeedfacf is the reverse of the ELF
    // magic only in one byte position, so this is the case that catches an
    // ELF check placed before the Mach-O check.
    std::vector<std::uint8_t> b(64, 0);
    put32(b, 0, 0xfeedfacfU);
    check(run(b).format == Format::MachO,
          "a 64-bit Mach-O is not mistaken for an ELF");
}

void test_pe() {
    std::vector<std::uint8_t> b(256, 0);
    b[0] = 'M';
    b[1] = 'Z';
    put32(b, 0x3c, 0x80);
    b[0x80] = 'P';
    b[0x81] = 'E';
    b[0x82] = 0;
    b[0x83] = 0;

    check(run(b).format == Format::Pe, "a PE image is detected");

    // An MZ stub without a PE header is a DOS executable, which is a
    // different format and has no engine either, but the two must not be
    // conflated because the message a user needs is different.
    put32(b, 0x3c, 0);
    check(run(b).format == Format::Unknown,
          "a DOS stub without a PE header is not a PE image");
}

// Builds a zip with a real central directory.
//
// Written rather than checked in as a binary because every field the reader
// uses has to be settable independently: the cases below are the ones where
// one field disagrees with another, and a fixture with a single fixed layout
// cannot produce those. The pieces are the ones a real archiver emits -- a
// local header, a central directory record, an EOCD -- with the sizes the
// record declares and the sizes the buffer actually has both under the
// test's control.
struct ZipBuilder {
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> central;
    std::size_t count = 0;

    void add_local(const std::string& name, std::uint16_t method,
                   std::uint32_t size) {
        const std::size_t at = bytes.size();
        bytes.resize(at + 30 + name.size());
        put32(bytes, at, 0x04034b50);
        put16(bytes, at + 4, 20);
        put16(bytes, at + 8, method);
        put32(bytes, at + 18, size);
        put32(bytes, at + 22, size);
        put16(bytes, at + 26, static_cast<std::uint16_t>(name.size()));
        std::memcpy(bytes.data() + at + 30, name.data(), name.size());
        if (method == 0) {
            bytes.resize(at + 30 + name.size() + size, 0);
        }
    }

    // Adds a central directory record. Separate from add_local because the
    // cases below need them to disagree.
    //
    // `comment_len` is what the record declares in its header;
    // `comment_alloc` is how many bytes are actually written, and defaults to
    // the declared length. Setting it lower builds a record that claims more
    // variable-length data than exists -- the shape a truncated or hostile
    // directory has, and the one that separates a reader that adds the three
    // lengths before comparing them from one that compares the name alone.
    void add_central(const std::string& name, std::uint16_t method,
                     std::uint32_t comp, std::uint32_t uncomp,
                     std::uint16_t name_len_override = 0,
                     std::uint16_t extra_len = 0,
                     std::uint16_t comment_len = 0,
                     std::uint16_t comment_alloc = 0xFFFF) {
        const std::size_t alloc_comment =
            comment_alloc == 0xFFFF ? comment_len : comment_alloc;
        const std::size_t at = central.size();
        central.resize(at + 46 + name.size() + extra_len + alloc_comment);
        put32(central, at, 0x02014b50);
        put16(central, at + 4, 20);
        put16(central, at + 6, 20);
        put16(central, at + 8, 0);
        put16(central, at + 10, method);
        put32(central, at + 20, comp);
        put32(central, at + 24, uncomp);
        put16(central, at + 28,
              name_len_override != 0
                  ? name_len_override
                  : static_cast<std::uint16_t>(name.size()));
        put16(central, at + 30, extra_len);
        put16(central, at + 32, comment_len);
        std::memcpy(central.data() + at + 46, name.data(), name.size());
        ++count;
    }

    // Finishes the archive. The overrides are what the malformed cases need:
    // a record can claim a directory at an offset or of a size the file does
    // not have, and those are the cases a reader has to survive.
    std::vector<std::uint8_t> finish(
        std::uint64_t count_override = 0,
        std::uint32_t cd_size_override = 0,
        std::uint32_t cd_offset_override = 0,
        std::size_t comment_bytes = 0,
        bool omit_eocd = false) {
        std::vector<std::uint8_t> out = bytes;
        const std::uint32_t cd_offset = static_cast<std::uint32_t>(out.size());
        out.insert(out.end(), central.begin(), central.end());
        if (omit_eocd) {
            return out;
        }
        const std::size_t at = out.size();
        out.resize(at + 22 + comment_bytes);
        put32(out, at, 0x06054b50);
        put16(out, at + 4, 0);
        put16(out, at + 6, 0);
        put16(out, at + 8, count_override != 0
                             ? static_cast<std::uint16_t>(count_override)
                             : static_cast<std::uint16_t>(count));
        put16(out, at + 10, static_cast<std::uint16_t>(count));
        put32(out, at + 12, cd_size_override != 0
                                ? cd_size_override
                                : static_cast<std::uint32_t>(central.size()));
        put32(out, at + 16, cd_offset_override != 0
                                ? cd_offset_override
                                : cd_offset);
        return out;
    }
};

// The member list of a detection, as one string per member. Used where a test
// compares the whole list rather than one field of it.
std::string member_names(const std::vector<ZipMemberInfo>& all) {
    std::string s;
    for (const ZipMemberInfo& m : all) {
        s += m.name;
        s += ";";
    }
    return s;
}

void test_zip_central_directory() {
    ZipBuilder z;
    z.add_local("AndroidManifest.xml", 0, 18);
    z.add_local("classes.dex", 8, 900);
    z.add_central("AndroidManifest.xml", 0, 18, 18);
    z.add_central("classes.dex", 8, 300, 900);
    const std::vector<std::uint8_t> good = z.finish();

    std::vector<ZipMemberInfo> all;
    check(read_zip_members(ByteSpan{good.data(), good.size()}, all),
          "a well-formed central directory is read");
    check(all.size() == 2, "both members are read");
    if (all.size() == 2) {
        // The two sizes are both read, and both are read from the record
        // rather than from the local header. A reader that took them from
        // the local header would get the same numbers here, which is why the
        // deflated member is the interesting one: its two sizes differ, so
        // picking the wrong one is visible.
        check(all[0].name == "AndroidManifest.xml" && all[0].stored,
              "the manifest is read as stored");
        check(!all[1].stored && all[1].compressed_size == 300 &&
                  all[1].uncompressed_size == 900,
              "a deflated member's two sizes come from the directory");
    }

    // Reused across calls, which is the case the clearing at the top of the
    // reader exists for. Without it a caller walking several archives would
    // see the previous archive's members prepended to this one's.
    all.clear();
    check(read_zip_members(ByteSpan{good.data(), good.size()}, all) &&
              all.size() == 2,
          "a second read into the same vector replaces rather than appends");

    // The report list, which is what a package's answer is built from.
    const std::vector<ZipMemberInfo> shown = zip_report_members(all);
    check(shown.size() == 1 && shown[0].name == "AndroidManifest.xml",
          "only the manifest is reported when there are no libraries");

    ZipBuilder libs;
    libs.add_local("AndroidManifest.xml", 0, 18);
    libs.add_central("AndroidManifest.xml", 0, 18, 18);
    libs.add_central("res/layout/main.xml", 8, 10, 20);
    libs.add_central("lib/arm64-v8a/libfoo.so", 0, 4096, 4096);
    libs.add_central("lib/x86_64/libfoo.so", 0, 4096, 4096);
    libs.add_central("assets/intro.mp4", 8, 900000, 900000);
    const std::vector<std::uint8_t> libbed = libs.finish();

    std::vector<ZipMemberInfo> lib_all;
    (void)read_zip_members(ByteSpan{libbed.data(), libbed.size()}, lib_all);
    check(lib_all.size() == 5, "every member of a mixed archive is read");

    const std::vector<ZipMemberInfo> lib_shown = zip_report_members(lib_all);
    check(member_names(lib_shown) ==
              "AndroidManifest.xml;lib/arm64-v8a/libfoo.so;lib/x86_64/libfoo.so;",
          "the report is the manifest then the libraries, and nothing else");
    check(lib_shown.size() < lib_all.size(),
          "a bounded report is smaller than the archive for a package with "
          "resources in it");

    // The detection carries the list, not only the evidence. This is the
    // field an engine reads, so a test that only checked evidence would pass
    // with the plumbing between them missing.
    const Detection d = run(libbed);
    check(d.format == Format::Apk, "an archive with the manifest first is a package");
    check(d.zip_members.size() == 5,
          "the detection carries every member the directory named");
}

void test_zip_malformed() {
    // Each case below is a file whose fields disagree. None of them may read
    // outside the buffer, and none of them may be reported as a package with
    // members it does not have. The assertions are about the outcome rather
    // than about not crashing: a reader that walked off the end of a
    // std::vector would not be caught by a test that only checked the return
    // value, which is why the cases are built to be readable-if-correct and
    // silent-if-wrong.

    // A name length that runs past the record. The record declares 400 bytes
    // of name and the directory does not have them, so the walk must stop
    // without copying 400 bytes from wherever they are.
    {
        ZipBuilder z;
        z.add_local("AndroidManifest.xml", 0, 18);
        z.add_central("AndroidManifest.xml", 0, 18, 18, 400);
        const std::vector<std::uint8_t> b = z.finish();
        std::vector<ZipMemberInfo> m;
        const bool ok = read_zip_members(ByteSpan{b.data(), b.size()}, m);
        check(!ok || m[0].name.size() == 19,
              "a name length past the record does not produce a long name");
    }

    // A name length that fits the file but not the directory. The record
    // claims 30 name bytes inside a 46-byte record, and the name it really
    // has is 19 -- so the reader must either refuse this record or read the
    // 19 bytes it can see, and must not carry on from a wrong offset.
    {
        ZipBuilder z;
        z.add_local("AndroidManifest.xml", 0, 18);
        z.add_central("AndroidManifest.xml", 0, 18, 18, 30);
        const std::vector<std::uint8_t> b = z.finish();
        std::vector<ZipMemberInfo> m;
        (void)read_zip_members(ByteSpan{b.data(), b.size()}, m);
        for (const ZipMemberInfo& e : m) {
            check(e.name.size() <= 30, "a name never exceeds its declared length");
        }
    }

    // A record whose name fits and whose comment does not, followed by what
    // would have been a real second record.
    //
    // This is the case the sum of the three lengths exists for, and asking
    // about the name alone would not catch it. The record declares a
    // 100-byte comment but only 27 of those bytes exist, so its name is
    // entirely present while the record as a whole runs off the end of the
    // directory. A reader that checked only the name accepts it, starts the
    // next record 100 bytes late inside the missing comment, finds no magic
    // there and stops -- and the archive is reported as holding one member
    // rather than two. Nothing crashes and nothing looks wrong, which is why
    // the assertion is on the count and not on the first name.
    {
        ZipBuilder z;
        z.add_local("AndroidManifest.xml", 0, 18);
        z.add_central("AndroidManifest.xml", 0, 18, 18);
        // Declares a 100-byte comment, allocates 27. The record is short by
        // 73 bytes, and the second record starts immediately after what was
        // actually written.
        z.add_central("AndroidManifest.xml", 0, 18, 18, 0, 0, 100, 27);
        const std::vector<std::uint8_t> b = z.finish();
        std::vector<ZipMemberInfo> m;
        (void)read_zip_members(ByteSpan{b.data(), b.size()}, m);
        check(m.size() == 1,
              "a record whose comment overruns the directory is refused");
        if (m.size() == 1) {
            check(m[0].name == "AndroidManifest.xml",
                  "and the member before it is still read");
        }

        // The same two records with the comment fully present, which is what
        // makes the case above a defect in the length check rather than a
        // property of the fixture.
        ZipBuilder ok;
        ok.add_local("AndroidManifest.xml", 0, 18);
        ok.add_central("AndroidManifest.xml", 0, 18, 18);
        ok.add_central("lib/x86_64/libbar.so", 0, 16, 16);
        const std::vector<std::uint8_t> good = ok.finish();
        std::vector<ZipMemberInfo> gm;
        (void)read_zip_members(ByteSpan{good.data(), good.size()}, gm);
        check(gm.size() == 2, "the same two members read when nothing overruns");
    }

    // A directory offset past the end of the file. The subtraction in the
    // bounds check is what makes this safe: adding cd_offset + cd_size would
    // not overflow here, but the offset alone is already out of range.
    {
        ZipBuilder z;
        z.add_local("AndroidManifest.xml", 0, 18);
        z.add_central("AndroidManifest.xml", 0, 18, 18);
        const std::vector<std::uint8_t> b = z.finish(0, 0, 0xFFFFFF00u);
        std::vector<ZipMemberInfo> m;
        check(!read_zip_members(ByteSpan{b.data(), b.size()}, m) && m.empty(),
              "a central directory past the end of the file is not read");
    }

    // A directory size that runs past the end of the file from a valid
    // offset. The offset points at a real record, so the magic matches; the
    // size is what says how far the walk may go, and it is a lie.
    {
        ZipBuilder z;
        z.add_local("AndroidManifest.xml", 0, 18);
        z.add_central("AndroidManifest.xml", 0, 18, 18);
        const std::vector<std::uint8_t> b = z.finish(0, 0x7FFFFFFFu);
        std::vector<ZipMemberInfo> m;
        (void)read_zip_members(ByteSpan{b.data(), b.size()}, m);
        for (const ZipMemberInfo& e : m) {
            check(e.name == "AndroidManifest.xml",
                  "a lying directory size does not produce invented members");
        }
    }

    // A count far larger than the directory holds. The walk stops when the
    // records run out, which is the correct answer: the members that were
    // read are real and the ones that were not are not reported.
    {
        ZipBuilder z;
        z.add_local("AndroidManifest.xml", 0, 18);
        z.add_central("AndroidManifest.xml", 0, 18, 18);
        const std::vector<std::uint8_t> b = z.finish(60000);
        std::vector<ZipMemberInfo> m;
        (void)read_zip_members(ByteSpan{b.data(), b.size()}, m);
        check(m.size() == 1,
              "a count larger than the directory yields the members that exist");
    }

    // A count that is not a plausible member count at all. The bound is
    // above 65535 because the field is 16 bits, so this is the one count the
    // format cannot express -- which means the case is a file whose count
    // field was written by something that did not write a zip, and the
    // reader has to decline rather than walk looking.
    {
        ZipBuilder z;
        z.add_local("AndroidManifest.xml", 0, 18);
        z.add_central("AndroidManifest.xml", 0, 18, 18);
        std::vector<std::uint8_t> b = z.finish();
        const std::size_t eocd = b.size() - 22;
        put16(b, eocd + 10, 0xFFFF);
        std::vector<ZipMemberInfo> m;
        (void)read_zip_members(ByteSpan{b.data(), b.size()}, m);
        check(m.size() <= 1, "a maximal count does not invent members");
    }

    // No EOCD at all: a streamed archive, which is a real thing a producer
    // can write. The first member is still readable and the detection still
    // calls it a package, but there is no list to report and nothing may be
    // invented to fill it.
    {
        ZipBuilder z;
        z.add_local("AndroidManifest.xml", 0, 18);
        const std::vector<std::uint8_t> b = z.finish(0, 0, 0, 0, true);
        std::vector<ZipMemberInfo> m;
        check(!read_zip_members(ByteSpan{b.data(), b.size()}, m) && m.empty(),
              "a streamed archive has no member list to read");
        const Detection d = run(b);
        check(d.format == Format::Apk,
              "a streamed archive with the manifest first is still a package");
        check(d.zip_members.empty(), "and it reports no members rather than none "
                                     "of the right ones");
    }

    // An archive comment, which is ordinary and is the reason the EOCD is
    // searched for rather than assumed to be the last 22 bytes.
    {
        ZipBuilder z;
        z.add_local("AndroidManifest.xml", 0, 18);
        z.add_central("AndroidManifest.xml", 0, 18, 18);
        const std::vector<std::uint8_t> b = z.finish(0, 0, 0, 900);
        std::vector<ZipMemberInfo> m;
        check(read_zip_members(ByteSpan{b.data(), b.size()}, m) &&
                  m.size() == 1 && m[0].name == "AndroidManifest.xml",
              "a 900-byte archive comment does not hide the directory");
    }

    // A comment longer than the format allows. The search window is the whole
    // legal range, so an EOCD beyond it is not found -- and a file that pads
    // 100 KB past its end of central directory is not a zip this reader can
    // locate, which it says by returning nothing.
    {
        ZipBuilder z;
        z.add_local("AndroidManifest.xml", 0, 18);
        z.add_central("AndroidManifest.xml", 0, 18, 18);
        std::vector<std::uint8_t> b = z.finish();
        b.resize(b.size() + 100000, 0);
        std::vector<ZipMemberInfo> m;
        check(!read_zip_members(ByteSpan{b.data(), b.size()}, m),
              "padding past the legal comment range hides the directory "
              "rather than being scanned through");
    }

    // A file with no local header but a valid directory. The format is still
    // a zip and the directory is still readable, but detection stops at the
    // first member, so this is a zip occ does not name -- and the reader
    // called directly still returns the list, because the reader's contract
    // is about the directory rather than about detection.
    {
        ZipBuilder z;
        z.add_central("AndroidManifest.xml", 0, 18, 18);
        const std::vector<std::uint8_t> b = z.finish();
        std::vector<ZipMemberInfo> m;
        check(read_zip_members(ByteSpan{b.data(), b.size()}, m) &&
                  m.size() == 1,
              "a directory is readable without a local header");
        check(run(b).format != Format::Apk,
              "but such a file is not reported as a package, because nothing "
              "established what its first member is");
    }

    // Every prefix of a real archive. This is the case that would catch a
    // reader whose walk depended on a later byte being present, and it is the
    // one a fuzzer would find eventually; running it here means the suite
    // says so rather than leaving it to chance.
    {
        ZipBuilder z;
        z.add_local("AndroidManifest.xml", 0, 18);
        z.add_central("AndroidManifest.xml", 0, 18, 18);
        z.add_central("lib/arm64-v8a/libfoo.so", 0, 4096, 4096);
        const std::vector<std::uint8_t> full = z.finish();
        for (std::size_t n = 0; n <= full.size(); n += 7) {
            std::vector<ZipMemberInfo> m;
            (void)read_zip_members(ByteSpan{full.data(), n}, m);
            for (const ZipMemberInfo& e : m) {
                check(e.name == "AndroidManifest.xml" ||
                          e.name == "lib/arm64-v8a/libfoo.so",
                      "a prefix of an archive yields only its real members");
            }
        }
    }
}

void test_zip_report_bound() {
    // The cap is on the report, not on the reader, and the two being
    // different is the point: the reader's list is the archive's, and the
    // report is an answer.
    ZipBuilder z;
    z.add_local("AndroidManifest.xml", 0, 18);
    z.add_central("AndroidManifest.xml", 0, 18, 18);
    for (int i = 0; i < 100; ++i) {
        z.add_central("lib/arm64-v8a/lib" + std::to_string(i) + ".so", 0, 16,
                      16);
    }
    const std::vector<std::uint8_t> b = z.finish();

    std::vector<ZipMemberInfo> all;
    (void)read_zip_members(ByteSpan{b.data(), b.size()}, all);
    check(all.size() == 101, "the reader is not bounded by the report's cap");

    const std::vector<ZipMemberInfo> shown = zip_report_members(all);
    check(shown.size() == 32, "the report is capped");
    check(shown.front().name == "AndroidManifest.xml",
          "and the cap is applied after the manifest, not before it");

    // The detection says what it left out. A package with more libraries than
    // the cap prints them all and reads as a complete list, which is the one
    // way a bounded report can mislead.
    const Detection d = run(b);
    bool said_more = false;
    for (const std::string& e : d.evidence) {
        if (e.find("and 69 more") != std::string::npos) {
            said_more = true;
        }
    }
    check(said_more, "a truncated report says how much it left out");
}

void test_unknown() {
    std::vector<std::uint8_t> b{0x23, 0x21, 0x2f, 0x62, 0x69, 0x6e, 0x2f};
    const Detection d = run(b);
    check(d.format == Format::Unknown, "a shell script is not a known format");
    check(!d.evidence.empty(), "an unknown file still explains itself");

    std::vector<std::uint8_t> empty{};
    check(run(empty).format == Format::Unknown, "an empty file is unknown");
}

void test_engine_names() {
    check(std::strcmp(format_name(Format::Elf), "elf") == 0,
          "the ELF format name");
    check(std::strcmp(format_name(Format::Apk), "apk") == 0,
          "the APK format name");
    check(std::strcmp(elf_machine_name(ElfMachine::X86_64), "x86-64") == 0,
          "the x86-64 machine name");
    check(std::strcmp(elf_class_name(ElfClass::Elf64), "64-bit") == 0,
          "the 64-bit class name");
    check(std::strcmp(elf_type_name(ElfType::Dyn), "shared object or pie") == 0,
          "the Dyn type name");
}

} // namespace

int main() {
    test_elf64();
    test_elf32_offsets();
    test_elf_ident_rejection();
    test_bare_program_header();
    test_apk();
    test_zip_central_directory();
    test_zip_malformed();
    test_zip_report_bound();
    test_macho();
    test_pe();
    test_unknown();
    test_engine_names();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

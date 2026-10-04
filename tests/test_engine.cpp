// Engine dispatch tests.
//
// The dispatch layer is where a format becomes a process, and the failure
// modes are specific: a format routed to the wrong engine runs a target the
// isolation was not designed for, and a format routed nowhere produces a
// refusal that names a file rather than a reason. So the cases below are
// about the mapping and about the sentences, and about the property that
// makes both checkable -- that `occ check` and `occ run` cannot disagree,
// because there is only one table.
//
// The fixtures are written to disk because load() takes a path. That is a
// deliberate constraint of the interface rather than an accident: an engine
// that could be handed bytes would be an engine that could be handed bytes
// from somewhere other than the file the caller named, and the path is what
// appears in the event stream and in the container's exec.

#include "occ/engine/engine.h"

#include "occ/observer/event.h"
#include "occ/observer/ntdll_probes.h"
#include "occ/parser/detect.h"
#include "occ/parser/elf.h"
#include "occ/util/fs.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <sys/stat.h>

#include <unistd.h>

using namespace occ;
using occ::engine::Engine;
using occ::engine::EngineKind;
using occ::engine::EngineRequest;
using occ::engine::LaunchPlan;
using occ::engine::LoadedImage;
using occ::parser::Format;

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

constexpr std::size_t kElfHeaderSize = 64;
constexpr std::size_t kPhdrSize = 56;

// A minimal 64-bit little-endian x86-64 executable: an identification
// block, a header, and one PT_LOAD. The segment's file offset and vaddr
// are both page-multiples, which is the congruence rule the kernel's
// loader relies on and the reader checks.
std::vector<std::uint8_t> make_elf(std::uint16_t machine,
                                    std::uint16_t type,
                                    std::uint8_t elf_class = 2,
                                    std::uint8_t elf_data = 1) {
    std::vector<std::uint8_t> b(4096 + 512, 0);
    b[0] = 0x7f;
    b[1] = 'E';
    b[2] = 'L';
    b[3] = 'F';
    b[4] = elf_class;
    b[5] = elf_data;
    b[6] = 1;

    const bool wide = elf_class == 2;
    const std::size_t need = wide ? kElfHeaderSize : 52;
    if (b.size() < need) {
        return b;
    }
    put16(b, 16, type);
    put16(b, 18, machine);
    if (wide) {
        put64(b, 24, 0x19f0);         // e_entry
        put64(b, 32, kElfHeaderSize); // e_phoff
        put64(b, 40, 0);              // e_shoff
        put32(b, 48, 0);              // e_flags
        put16(b, 52, kElfHeaderSize); // e_ehsize
        put16(b, 54, 56);             // e_phentsize
        put16(b, 56, 1);              // e_phnum
        put16(b, 58, 64);             // e_shentsize
        put16(b, 60, 0);              // e_shnum
        put16(b, 62, 0);              // e_shstrndx
    } else {
        put32(b, 24, 0x19f0);         // e_entry
        put32(b, 28, 52);             // e_phoff
        put32(b, 32, 0);              // e_shoff
        put32(b, 36, 0);              // e_flags
        put16(b, 40, 52);             // e_ehsize
        put16(b, 42, 32);             // e_phentsize
        put16(b, 44, 1);              // e_phnum
        put16(b, 46, 40);             // e_shentsize
        put16(b, 48, 0);              // e_shnum
        put16(b, 50, 0);              // e_shstrndx
    }

    // One PT_LOAD covering the whole file. Written little-endian
    // unconditionally: the fixtures that need a big-endian image are
    // refused at the detection or at the class check before the program
    // header is walked, so a big-endian table would never be read and
    // writing one correctly would be untested code.
    const std::size_t ph = wide ? kElfHeaderSize : 52;
    const std::size_t phsz = wide ? kPhdrSize : 32;
    put32(b, ph + 0, 1); // p_type = PT_LOAD
    put32(b, ph + 4, 5); // p_flags = R+X
    // The sizes are the file's length, which is a size_t. Narrowing is
    // explicit and the value is small: a fixture of a few kilobytes whose
    // segment claims to cover all of it.
    const auto total = static_cast<std::uint32_t>(b.size());
    if (wide) {
        put64(b, ph + 8, 0);            // p_offset
        put64(b, ph + 16, 0x400000);    // p_vaddr
        put64(b, ph + 24, 0x400000);    // p_paddr
        put64(b, ph + 32, total);       // p_filesz
        put64(b, ph + 40, total);       // p_memsz
        put64(b, ph + 48, 0x1000);      // p_align
    } else {
        put32(b, ph + 4, 0);
        put32(b, ph + 8, 0x1000);       // p_vaddr, congruent with the offset
        put32(b, ph + 12, 0x1000);      // p_paddr
        put32(b, ph + 16, total);       // p_filesz
        put32(b, ph + 20, total);       // p_memsz
        put32(b, ph + 24, 5);
        put32(b, ph + 28, 0x1000);      // p_flags
    }
    (void)phsz;
    return b;
}

// A minimal PE32+ executable: DOS stub, PE signature, COFF header, and an
// optional header with no sections beyond one. Built the same way as the
// ELF fixtures so that a failure points at a field.
std::vector<std::uint8_t> make_pe(std::uint16_t machine,
                                  std::uint16_t characteristics = 0x0002) {
    const std::uint32_t lfanew = 0x80;
    const std::uint32_t opt_size = 240;
    const std::size_t headers = 0x200;

    std::vector<std::uint8_t> b(headers + 0x200, 0);
    b[0] = 'M';
    b[1] = 'Z';
    put32(b, 0x3c, lfanew);

    std::size_t o = lfanew;
    b[o] = 'P';
    b[o + 1] = 'E';
    b[o + 2] = 0;
    b[o + 3] = 0;
    o += 4;

    put16(b, o + 0, machine);
    put16(b, o + 2, 1);      // NumberOfSections
    put32(b, o + 16, opt_size); // SizeOfOptionalHeader
    put16(b, o + 18, characteristics);
    o += 20;

    put16(b, o + 0, 0x20b);  // PE32+ magic
    b[o + 2] = 14;           // MajorLinkerVersion
    put32(b, o + 16, 0x1000);        // AddressOfEntryPoint
    put64(b, o + 24, 0x140000000);   // ImageBase
    put32(b, o + 32, 0x1000);        // SectionAlignment
    put32(b, o + 36, 0x200);         // FileAlignment
    put32(b, o + 56, 0x2000);        // SizeOfImage
    put32(b, o + 60, static_cast<std::uint32_t>(headers)); // SizeOfHeaders
    put32(b, o + 108, 16);           // NumberOfRvaAndSizes
    o += opt_size;

    // One section: .text, executable, at RVA 0x1000.
    b[o + 0] = '.';
    b[o + 1] = 't';
    b[o + 2] = 'e';
    b[o + 3] = 'x';
    b[o + 4] = 't';
    put32(b, o + 8, 0x200);      // VirtualSize
    put32(b, o + 12, 0x1000);    // VirtualAddress
    put32(b, o + 16, 0x200);     // SizeOfRawData
    put32(b, o + 20, headers);   // PointerToRawData
    put32(b, o + 36, 0x60000020); // CODE | EXECUTE | READ
    return b;
}

// A writer whose sink is a pipe, so the tests read back the exact bytes a
// consumer would see.
struct Captured {
    int fd_[2] = {-1, -1};
    obs::Writer writer;

    Captured() {
        if (::pipe(fd_) != 0) {
            std::fprintf(stderr, "pipe failed\n");
            return;
        }
        writer.attach(fd_[1]);
    }

    ~Captured() {
        if (fd_[0] >= 0) {
            ::close(fd_[0]);
        }
        if (fd_[1] >= 0) {
            ::close(fd_[1]);
        }
    }

    Captured(const Captured&) = delete;
    Captured& operator=(const Captured&) = delete;

    // Closes the write end first so the read terminates. Without that the
    // read blocks forever waiting for a writer that is still open, and a
    // test that hangs is worse than a test that fails: it looks like a
    // problem with the code under test rather than with the harness. The
    // writer is left attached to a closed descriptor afterwards, which is
    // the same state test_event's harness uses.
    [[nodiscard]] std::string read() {
        if (fd_[1] >= 0) {
            ::close(fd_[1]);
            fd_[1] = -1;
        }
        std::string out;
        char buf[4096];
        for (;;) {
            const ssize_t n = ::read(fd_[0], buf, sizeof(buf));
            if (n <= 0) {
                break;
            }
            out.append(buf, static_cast<std::size_t>(n));
        }
        return out;
    }
};

// A file that exists for the duration of a test and is removed after.
struct TempFile {
    std::string path;
    bool wrote = false;

    TempFile() {
        char tmpl[] = "/tmp/occ_test_engine_XXXXXX";
        const int fd = ::mkstemp(tmpl);
        if (fd < 0) {
            return;
        }
        ::close(fd);
        path = tmpl;
    }

    ~TempFile() {
        if (wrote && !path.empty()) {
            (void)::unlink(path.c_str());
        }
    }

    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;

    bool write(const std::vector<std::uint8_t>& bytes) {
        if (path.empty()) {
            return false;
        }
        FILE* f = std::fopen(path.c_str(), "wb");
        if (f == nullptr) {
            return false;
        }
        const size_t n = std::fwrite(bytes.data(), 1, bytes.size(), f);
        std::fclose(f);
        wrote = n == bytes.size();
        return wrote;
    }

    bool write_text(const char* text) {
        std::vector<std::uint8_t> b;
        for (const char* p = text; *p != '\0'; ++p) {
            b.push_back(static_cast<std::uint8_t>(*p));
        }
        return write(b);
    }
};

// ------------------------------------------------------------- dispatch

void test_every_format_has_a_decision() {
    // The property the whole layer rests on: every value of Format reaches
    // a decision, and the decision is either an engine or a stated absence.
    // A new Format that fell through both would return an engine for
    // nothing or nothing for a file that has one, and neither shows up
    // until someone runs that format.
    for (int i = 0; static_cast<Format>(i) != Format::Unknown; ++i) {
        const Format f = static_cast<Format>(i);
        if (f == Format::Unknown) {
            continue;
        }
        const Engine* e = engine::engine_for(f);
        if (f == Format::MachO || f == Format::Zip) {
            check(e == nullptr,
                  "a format with no engine in this build routes nowhere");
        } else {
            check(e != nullptr, "a format with an engine routes to it");
        }
    }

    check(engine::engine_for(Format::Unknown) == nullptr,
          "the unknown format routes nowhere");
    check(engine::engine_for(Format::MachO) == nullptr,
          "Mach-O routes nowhere");
    check(engine::engine_for(Format::Zip) == nullptr,
          "a plain zip routes nowhere");
}

void test_dispatch_is_by_format_not_by_name() {
    // The extension is not consulted, and the fixture is deliberately given
    // a name that says nothing about its contents. A detector that looked
    // at the name would classify this as whatever the extension implies.
    TempFile f;
    check(f.write(make_elf(62, 2)), "the ELF fixture was written");
    if (!f.wrote) {
        return;
    }

    // Renamed to something that claims to be a package.
    const std::string renamed = f.path + ".apk";
    check(::rename(f.path.c_str(), renamed.c_str()) == 0,
          "the fixture was renamed to a misleading extension");
    f.path = renamed;

    const parser::Detection d = parser::detect_file(f.path);
    check(d.format == Format::Elf, "the content decides the format");
    const Engine* e = engine::engine_for(d);
    check(e != nullptr && std::strcmp(e->name(), "exe") == 0,
          "an ELF named .apk goes to the exe engine");
}

void test_engines_are_the_declared_ones() {
    // The registry is what `occ check` enumerates, so its contents are part
    // of the interface rather than an implementation detail.
    const std::vector<const Engine*>& all = engine::engines();
    check(all.size() == 3, "three engines are registered");

    bool saw_elf = false;
    bool saw_pe = false;
    bool saw_apk = false;
    for (const Engine* e : all) {
        check(e != nullptr, "no null engine in the registry");
        if (e == nullptr) {
            continue;
        }
        check(std::strlen(e->name()) > 0, "every engine has a name");
        switch (e->kind()) {
        case EngineKind::Elf:
            saw_elf = true;
            check(std::strcmp(e->name(), "exe") == 0,
                  "the ELF engine is named exe");
            break;
        case EngineKind::Pe:
            saw_pe = true;
            check(std::strcmp(e->name(), "pe") == 0,
                  "the PE engine is named pe");
            break;
        case EngineKind::Apk:
            saw_apk = true;
            check(std::strcmp(e->name(), "apk") == 0,
                  "the APK engine is named apk");
            break;
        }
    }
    check(saw_elf && saw_pe && saw_apk,
          "the registry names all three engines");

    // The accessors and the registry must be the same objects. A caller
    // holding elf_engine() and a caller holding engines()[0] have to reach
    // the same engine, or the two disagree about which one is in use.
    check(&engine::elf_engine() == all[0], "elf_engine is the first entry");
    check(&engine::pe_engine() == all[1], "pe_engine is the second entry");
    check(&engine::apk_engine() == all[2], "apk_engine is the third entry");
}

void test_dispatch_returns_the_engine_that_claims_the_format() {
    // Every format with an engine routes to the one whose kind matches it.
    //
    // This is the assertion the whole registry exists to make possible, and
    // it was found missing by mutation: changing the table so that an ELF
    // routed to the PE engine passed every other test in this file. The
    // reason it went unnoticed is that the other tests ask an engine
    // directly -- "does the exe engine refuse a 32-bit object" -- and never
    // ask which engine a format reaches. Those are different questions and
    // only one of them was being asked.
    //
    // The check is on the engine's own kind rather than on its name, so an
    // engine that was renamed would not need this test changed. A name
    // check here would be a second thing to keep in step with the rename.
    struct Expectation {
        Format format;
        EngineKind kind;
        const char* what;
    };

    const Expectation table[] = {
        {Format::Elf, EngineKind::Elf, "an ELF reaches the ELF engine"},
        {Format::Pe, EngineKind::Pe, "a PE reaches the PE engine"},
        {Format::Apk, EngineKind::Apk, "an APK reaches the APK engine"},
    };

    for (const Expectation& e : table) {
        const Engine* got = engine::engine_for(e.format);
        check(got != nullptr, e.what);
        if (got == nullptr) {
            continue;
        }
        check(got->kind() == e.kind, e.what);
    }

    // And the identity holds: the engine a format reaches is the same
    // object the named accessor returns. Without this, an engine could be
    // reachable by two routes and the two could be different instances,
    // which for a stateless engine is harmless and for a stateful one is a
    // bug waiting for the first piece of state.
    check(engine::engine_for(Format::Elf) == &engine::elf_engine(),
          "the ELF route and elf_engine are one engine");
    check(engine::engine_for(Format::Pe) == &engine::pe_engine(),
          "the PE route and pe_engine are one engine");
    check(engine::engine_for(Format::Apk) == &engine::apk_engine(),
          "the APK route and apk_engine are one engine");
}

void test_detection_and_format_dispatch_agree() {
    // engine_for(Detection) is a convenience over engine_for(Format), and a
    // convenience that could disagree with the function it wraps is worse
    // than no convenience at all: a caller would have no way to tell which
    // of the two it was getting.
    parser::Detection d;
    d.format = Format::Pe;
    check(engine::engine_for(d) == engine::engine_for(Format::Pe),
          "the detection overload routes by the detection's format");

    d.format = Format::MachO;
    check(engine::engine_for(d) == nullptr,
          "a format with no engine routes nowhere through either overload");
}

void test_kind_names() {
    check(std::strcmp(engine::engine_kind_name(EngineKind::Elf), "elf") == 0,
          "EngineKind::Elf names itself");
    check(std::strcmp(engine::engine_kind_name(EngineKind::Pe), "pe") == 0,
          "EngineKind::Pe names itself");
    check(std::strcmp(engine::engine_kind_name(EngineKind::Apk), "apk") == 0,
          "EngineKind::Apk names itself");
}

// ------------------------------------------------------------- preflight

void test_elf_preflight_agrees_with_the_reader() {
    const Engine& exe = engine::elf_engine();

    parser::Detection good;
    good.format = Format::Elf;
    good.elf_class = parser::ElfClass::Elf64;
    good.elf_endian = parser::ElfEndian::Little;
    good.elf_machine = parser::ElfMachine::X86_64;
    good.elf_type = parser::ElfType::Exec;
    check(exe.preflight(good).empty(), "a 64-bit x86-64 executable passes");

    // Each refusal names the specific fact rather than the format, because
    // the format is what the caller already knows.
    parser::Detection d = good;
    d.elf_class = parser::ElfClass::Elf32;
    check(exe.preflight(d).find("32-bit") != std::string::npos,
          "a 32-bit object is refused as 32-bit");

    d = good;
    d.elf_endian = parser::ElfEndian::Big;
    check(exe.preflight(d).find("big-endian") != std::string::npos,
          "a big-endian object is refused as big-endian");

    d = good;
    d.elf_machine = parser::ElfMachine::AArch64;
    check(exe.preflight(d).find("aarch64") != std::string::npos,
          "an aarch64 object names its machine in the refusal");

    d = good;
    d.elf_type = parser::ElfType::Rel;
    check(exe.preflight(d).find("relocatable") != std::string::npos,
          "a relocatable object is refused as relocatable");

    d = good;
    d.elf_type = parser::ElfType::Core;
    check(exe.preflight(d).find("core") != std::string::npos,
          "a core file is refused as a core file");

    d = good;
    d.bare_program_header = true;
    check(exe.preflight(d).find("OAT") != std::string::npos,
          "a bare program header is named as an OAT image");

    // A shared object is a legitimate target and must not be refused: it is
    // ET_DYN, which is both a PIE and a library, and a refusal here would
    // take out every position-independent executable on the host.
    d = good;
    d.elf_type = parser::ElfType::Dyn;
    check(exe.preflight(d).empty(), "a shared object is not refused");
}

void test_other_engines_do_not_refuse_elf() {
    // A PE given an ELF detection must not produce a refusal about ELF.
    // The dispatch means this cannot happen, and the test is here because
    // the guarantee is worth having written down: a caller that reaches an
    // engine directly gets the engine's own answer, and the answer names
    // the format the engine handles rather than the one it was handed.
    parser::Detection d;
    d.format = Format::Elf;
    d.elf_class = parser::ElfClass::Elf64;
    d.elf_endian = parser::ElfEndian::Little;
    d.elf_machine = parser::ElfMachine::X86_64;
    d.elf_type = parser::ElfType::Exec;

    check(engine::pe_engine().preflight(d).empty(),
          "the PE engine does not judge an ELF detection");
    check(engine::apk_engine().preflight(d).empty(),
          "the APK engine does not judge an ELF detection");
}

void test_apk_preflight_defers_to_the_plan() {
    // The APK engine reads the package and reports it, then declines to run
    // it. A preflight that refused would stop the read, and the read is the
    // part that works -- so the refusal happens after the facts are in, and
    // preflight says nothing.
    parser::Detection d;
    d.format = Format::Apk;
    check(engine::apk_engine().preflight(d).empty(),
          "the APK engine does not refuse at preflight");
}

void test_pe_preflight_defers_to_the_headers() {
    // A PE's runnability depends on its machine field and on what the host
    // has, neither of which a detection carries. Refusing here would be
    // guessing.
    parser::Detection d;
    d.format = Format::Pe;
    check(engine::pe_engine().preflight(d).empty(),
          "the PE engine does not refuse at preflight");
}

// ------------------------------------------------------------------ load

void test_elf_load_reports_the_image() {
    TempFile f;
    check(f.write(make_elf(62, 2)), "the ELF fixture was written");
    if (!f.wrote) {
        return;
    }

    Captured cap;
    const LoadedImage image = engine::elf_engine().load(f.path, &cap.writer);
    const std::string stream = cap.read();

    check(image.ok, "a well-formed ELF loads");
    check(image.format == Format::Elf, "the format is reported as ELF");
    check(image.entry == 0x19f0, "the entry point is reported");
    check(image.region_count == 1, "one PT_LOAD means one region");
    check(image.address_bits == 64, "an ELF64 image reports 64 bits");
    check(image.error.empty(), "a successful load has no error text");

    check(stream.find("\"kind\":\"image_loaded\"") != std::string::npos,
          "an image_loaded event was written");
    check(stream.find("\"engine\":\"exe\"") != std::string::npos,
          "the event names the engine that produced it");
    check(stream.find("\"ok\":true") != std::string::npos,
          "the event reports success");
    check(stream.find("\"kind\":\"mapping\"") != std::string::npos,
          "a mapping event was written for the loadable segment");

    // The image_loaded event has to come before the mapping events: a
    // consumer reading top to bottom has to learn what the image is before
    // it learns how it is laid out.
    const std::size_t image_at = stream.find("image_loaded");
    const std::size_t mapping_at = stream.find("\"kind\":\"mapping\"");
    check(image_at < mapping_at, "image_loaded precedes mapping");
}

void test_elf_load_of_a_missing_file_is_reported_not_silent() {
    // A file that cannot be read is an event with ok false. Silence would
    // leave a consumer counting targets one short with nothing to say why.
    Captured cap;
    const LoadedImage image =
        engine::elf_engine().load("/nonexistent/occ/engine/test", &cap.writer);
    const std::string stream = cap.read();

    check(!image.ok, "a missing file does not load");
    check(image.error.find("could not be read") != std::string::npos,
          "the refusal names the read failure");
    check(stream.find("\"ok\":false") != std::string::npos,
          "an unreadable file still produces an image_loaded event");
    check(stream.find("\"kind\":\"image_loaded\"") != std::string::npos,
          "the event is present rather than skipped");
}

void test_elf_load_of_a_malformed_file_reports_the_reader_error() {
    // A file the reader rejects must carry the reader's own name for the
    // reason, so that a refusal and a parse failure cannot disagree.
    TempFile f;
    // A valid identification block and a header that claims a program
    // header table past the end of the file.
    std::vector<std::uint8_t> b = make_elf(62, 2);
    put64(b, 32, 0x100000); // e_phoff, far beyond the file
    check(f.write(b), "the malformed fixture was written");
    if (!f.wrote) {
        return;
    }

    Captured cap;
    const LoadedImage image = engine::elf_engine().load(f.path, &cap.writer);
    const std::string stream = cap.read();

    check(!image.ok, "a file with an out-of-range table does not load");
    check(!image.error.empty(), "the refusal carries the reader's reason");
    check(stream.find("\"error\":") != std::string::npos,
          "the event carries an error field");
    check(stream.find("\"kind\":\"mapping\"") == std::string::npos,
          "no mapping event for an image that did not load");
}

void test_pe_load_reports_sections_and_imports() {
    TempFile f;
    check(f.write(make_pe(0x8664)), "the PE fixture was written");
    if (!f.wrote) {
        return;
    }

    Captured cap;
    const LoadedImage image = engine::pe_engine().load(f.path, &cap.writer);
    const std::string stream = cap.read();

    check(image.ok, "a well-formed PE loads");
    check(image.format == Format::Pe, "the format is reported as PE");
    check(image.address_bits == 64, "a PE32+ image reports 64 bits");
    check(image.entry == 0x140001000,
          "the entry is reported as a virtual address, not an RVA");
    check(image.region_count == 1, "one section means one region");

    check(stream.find("\"kind\":\"section\"") != std::string::npos,
          "a section event was written");
    check(stream.find("\"name\":\".text\"") != std::string::npos,
          "the section event names the section");
    check(stream.find("\"executable\":true") != std::string::npos,
          "the section's executable bit is reported");
    check(stream.find("\"kind\":\"mapping\"") == std::string::npos,
          "a section is not reported as a mapping");
}

void test_pe32_reports_32_bits() {
    // The bit count decides which loader runs the image, so a PE32 has to
    // report 32 rather than defaulting to whatever the PE32+ path does.
    TempFile f;
    std::vector<std::uint8_t> b = make_pe(0x014c);
    // Rewrite the magic to PE32 and move the base field to its 32-bit
    // offset. The fixture is built for PE32+ so only the magic and the base
    // differ between the two layouts in the fields this reader needs.
    const std::uint32_t lfanew = 0x80;
    put16(b, lfanew + 4 + 20, 0x10b);          // PE32 magic
    put32(b, lfanew + 4 + 20 + 28, 0x400000);   // ImageBase at the PE32 offset
    check(f.write(b), "the PE32 fixture was written");
    if (!f.wrote) {
        return;
    }

    const LoadedImage image = engine::pe_engine().load(f.path, nullptr);
    check(image.ok, "a well-formed PE32 loads");
    if (image.ok) {
        check(image.address_bits == 32, "a PE32 image reports 32 bits");
    }
}

void test_load_without_a_writer_writes_nothing_and_still_answers() {
    // The null writer is the `occ check` path: a caller that wants the
    // facts without a stream. It has to get the same answer as one with a
    // stream, or the two disagree about the same file.
    TempFile f;
    check(f.write(make_pe(0x8664)), "the PE fixture was written");
    if (!f.wrote) {
        return;
    }

    const LoadedImage with = engine::pe_engine().load(f.path, nullptr);
    const LoadedImage without = engine::pe_engine().load(f.path, nullptr);
    check(with.ok == without.ok, "two loads of one file agree");
    check(with.entry == without.entry, "two loads report the same entry");
    check(with.region_count == without.region_count,
          "two loads report the same region count");
}

void test_apk_load_reads_the_package_and_reports_no_regions() {
    // An APK is a zip. The engine reports it as a readable package with no
    // entry point and no sections, because those are the facts: a zip has
    // neither an entry point nor a section table. Reporting ok true here
    // is not a claim that it can be run -- that is the plan's answer, and it
    // is a refusal.
    TempFile f;
    // A local file header naming AndroidManifest.xml, stored.
    std::vector<std::uint8_t> b(64, 0);
    put32(b, 0, 0x04034b50);
    put16(b, 4, 20);   // version needed
    put16(b, 8, 0);    // method 0 = stored
    put32(b, 18, 0);   // compressed size
    put32(b, 22, 0);   // uncompressed size
    put16(b, 26, 19);  // name length
    put16(b, 28, 0);   // extra length
    const char* name = "AndroidManifest.xml";
    for (int i = 0; i < 19; ++i) {
        b[30 + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>(name[i]);
    }
    check(f.write(b), "the APK fixture was written");
    if (!f.wrote) {
        return;
    }

    check(parser::detect_file(f.path).format == Format::Apk,
          "the fixture is detected as an APK");

    Captured cap;
    const LoadedImage image = engine::apk_engine().load(f.path, &cap.writer);
    const std::string stream = cap.read();

    check(image.ok, "a package is readable");
    check(image.entry == 0, "a package has no entry point");
    check(image.region_count == 0, "a package has no sections");
    check(stream.find("\"format\":\"apk\"") != std::string::npos,
          "the event names the format");
}

// A package with a central directory, so the member list is readable and the
// engine has something to report.
//
// The fixture above has a local header and nothing else, which is enough to
// be detected as a package and not enough to name a member list. This one is
// a whole archive: a local header, a central directory naming a manifest and
// two native libraries, and an end-of-central-directory record. It is the
// shape `occ run` sees on a real APK, and it is the case the engine's
// reporting exists for.
std::vector<std::uint8_t> apk_with_members() {
    std::vector<std::uint8_t> b;

    auto local = [&b](const char* name, std::uint16_t method,
                      std::uint32_t size) {
        const std::size_t n = std::strlen(name);
        const std::size_t at = b.size();
        b.resize(at + 30 + n + (method == 0 ? size : 0));
        put32(b, at, 0x04034b50);
        put16(b, at + 4, 20);
        put16(b, at + 8, method);
        put32(b, at + 18, size);
        put32(b, at + 22, size);
        put16(b, at + 26, static_cast<std::uint16_t>(n));
        std::memcpy(b.data() + at + 30, name, n);
    };
    auto central = [&b](const char* name, std::uint16_t method,
                        std::uint32_t comp, std::uint32_t uncomp) {
        const std::size_t n = std::strlen(name);
        const std::size_t at = b.size();
        b.resize(at + 46 + n);
        put32(b, at, 0x02014b50);
        put16(b, at + 4, 20);
        put16(b, at + 6, 20);
        put16(b, at + 10, method);
        put32(b, at + 20, comp);
        put32(b, at + 24, uncomp);
        put16(b, at + 28, static_cast<std::uint16_t>(n));
        std::memcpy(b.data() + at + 46, name, n);
    };

    local("AndroidManifest.xml", 0, 18);
    central("AndroidManifest.xml", 0, 18, 18);
    central("lib/arm64-v8a/libfoo.so", 0, 4096, 4096);
    central("lib/x86_64/libfoo.so", 8, 300, 900);
    // Two members that are neither, so the bounded report has something to
    // leave out. A real package is mostly made of these.
    central("classes.dex", 8, 40000, 120000);
    central("res/layout/main.xml", 8, 900, 2400);

    // The EOCD, with the directory's real extent. Measured rather than
    // tracked: the records above are appended to one buffer, so the
    // directory is everything from the first central header to here.
    const std::size_t first_central = 30 + 19 + 18;
    const std::uint32_t cd_size =
        static_cast<std::uint32_t>(b.size() - first_central);
    const std::size_t at = b.size();
    b.resize(at + 22);
    put32(b, at, 0x06054b50);
    put16(b, at + 8, 5);
    put16(b, at + 10, 5);
    put32(b, at + 12, cd_size);
    put32(b, at + 16, static_cast<std::uint32_t>(first_central));
    return b;
}

void test_apk_load_reports_the_package_members() {
    // The engine's own comment says the reporting is kept because the
    // manifest and the library list are facts about the file, and its
    // refusal tells the caller to extract a library from under lib/. These
    // assertions are what make that comment true: an engine that reported
    // nothing would still pass every other test here, because ok, entry and
    // region_count are all the same as before.
    TempFile f;
    const std::vector<std::uint8_t> b = apk_with_members();
    check(f.write(b), "the package fixture with a directory was written");
    if (!f.wrote) {
        return;
    }

    const parser::Detection d = parser::detect_file(f.path);
    check(d.format == Format::Apk, "the fixture is detected as an APK");
    check(d.zip_members.size() == 5,
          "detection read the five members the directory names");

    Captured cap;
    const LoadedImage image = engine::apk_engine().load(f.path, &cap.writer);
    const std::string stream = cap.read();

    check(image.ok, "the package is readable");
    check(stream.find("\"members\":5") != std::string::npos,
          "the load event carries the member count");
    check(stream.find("\"package_member\":\"AndroidManifest.xml\"") !=
              std::string::npos,
          "the manifest is reported");
    check(stream.find("\"package_member\":\"lib/arm64-v8a/libfoo.so\"") !=
              std::string::npos,
          "a native library is reported");

    // Both sizes and the stored flag, because the pair is what tells a
    // caller whether reading a member means inflating anything. The
    // arm64 library is stored and the x86 one is not, so a reader can see
    // that the two are reported differently rather than both coming from one
    // field.
    check(stream.find("\"uncompressed_size\":4096,\"compressed_size\":4096") !=
              std::string::npos,
          "a stored member reports equal sizes");
    check(stream.find("\"uncompressed_size\":900,\"compressed_size\":300") !=
              std::string::npos,
          "a deflated member reports both sizes");
    check(stream.find("\"stored\":true") != std::string::npos,
          "the stored flag is reported");
    check(stream.find("\"method\":8") != std::string::npos,
          "the compression method is reported");

    // One event per member, not one array. Asserted by counting rather than
    // by looking, because the shape of the stream is the claim: a consumer
    // tailing a run can act on a member as it arrives.
    // Counted on the whole key rather than on the bare word: the omitted
    // member event carries "package_members_omitted", which contains
    // "package_member" as a substring and would be counted as a fourth
    // member. That is the kind of assertion that passes for the wrong
    // reason, so it is written to count only the key.
    std::size_t member_events = 0;
    for (std::size_t at2 = stream.find("\"package_member\":");
         at2 != std::string::npos;
         at2 = stream.find("\"package_member\":", at2 + 1)) {
        ++member_events;
    }
    check(member_events == 3,
          "one event per reported member, and not one per archive member");

    // The report is bounded and says what it left out, so a package with
    // more libraries than the cap does not read as a complete list. The
    // fixture's dex and resources are the omitted members here.
    check(stream.find("\"package_members_omitted\":2") != std::string::npos,
          "the omitted member count is reported");
}

void test_apk_load_of_a_package_with_no_directory_reports_no_members() {
    // A streamed zip: the manifest is there, so it is a package, and there is
    // no central directory to name anything else. The count must be zero
    // rather than absent, and nothing may be invented to fill the report.
    TempFile f;
    std::vector<std::uint8_t> b(64, 0);
    put32(b, 0, 0x04034b50);
    put16(b, 4, 20);
    put16(b, 8, 0);
    put16(b, 26, 19);
    const char* name = "AndroidManifest.xml";
    for (int i = 0; i < 19; ++i) {
        b[30 + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>(name[i]);
    }
    check(f.write(b), "the streamed fixture was written");
    if (!f.wrote) {
        return;
    }

    Captured cap;
    const LoadedImage image = engine::apk_engine().load(f.path, &cap.writer);
    const std::string stream = cap.read();

    check(image.ok, "a package with no directory is still readable");
    check(stream.find("\"members\":0") != std::string::npos,
          "a package with no central directory reports no members");
    check(stream.find("package_member") == std::string::npos,
          "and reports none of them rather than none of the right ones");
}

// ------------------------------------------------------------------ plan

void test_elf_plan_runs_the_target_itself() {
    // The whole point of the exe engine: the program is the target, and the
    // argv is the caller's. An engine that wrapped this in anything would
    // change what /proc/self/cmdline says to the target.
    TempFile f;
    check(f.write(make_elf(62, 2)), "the ELF fixture was written");
    if (!f.wrote) {
        return;
    }

    const LoadedImage image = engine::elf_engine().load(f.path, nullptr);
    check(image.ok, "the fixture loads");
    if (!image.ok) {
        return;
    }

    EngineRequest request;
    request.path = f.path;
    request.argv = {f.path, "one", "two"};

    const LaunchPlan plan = engine::elf_engine().plan(request, image);
    check(plan.refusal.empty(), "the exe engine does not refuse an ELF");
    check(plan.program == fs::absolute_path(f.path),
          "the program is the resolved target");
    check(plan.argv.size() == 3, "the argv is passed through unchanged");
    check(plan.argv[0] == f.path, "argv[0] is the target as the caller named it");
    check(plan.argv[1] == "one" && plan.argv[2] == "two",
          "the caller's arguments survive");
    check(plan.env.empty(), "the exe engine adds no environment");
    check(plan.binds.empty(), "the exe engine adds no binds");
    check(plan.scratch_dir.empty(), "the exe engine needs no scratch space");
    check(plan.degradations.empty(), "the exe engine degrades nothing");
}

void test_plan_of_a_failed_load_refuses() {
    // A plan for an image that did not load is a refusal naming the load
    // error, never a program. A plan that produced a program here would be
    // an exec of a file the engine just said it could not read.
    LoadedImage image;
    image.ok = false;
    image.error = "the header is truncated";

    EngineRequest request;
    request.path = "/tmp/whatever";

    const LaunchPlan exe = engine::elf_engine().plan(request, image);
    check(!exe.refusal.empty(), "the exe engine refuses a failed load");
    check(exe.refusal.find("the header is truncated") != std::string::npos,
          "the refusal names the reader's reason");
    check(exe.program.empty(), "a refused plan has no program");

    const LaunchPlan pe = engine::pe_engine().plan(request, image);
    check(!pe.refusal.empty(), "the PE engine refuses a failed load");
    check(pe.program.empty(), "a refused PE plan has no program");

    const LaunchPlan apk = engine::apk_engine().plan(request, image);
    check(!apk.refusal.empty(), "the APK engine refuses a failed load");
}

void test_apk_plan_refuses_with_an_actionable_reason() {
    // The APK engine's whole contribution. It has to name what is missing
    // and what to do instead, because a refusal that only says "no" leaves
    // the user with a package they cannot use and no next step.
    TempFile f;
    std::vector<std::uint8_t> b(64, 0);
    put32(b, 0, 0x04034b50);
    put16(b, 8, 0);
    put16(b, 26, 19);
    const char* name = "AndroidManifest.xml";
    for (int i = 0; i < 19; ++i) {
        b[30 + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>(name[i]);
    }
    check(f.write(b), "the APK fixture was written");
    if (!f.wrote) {
        return;
    }

    const LoadedImage image = engine::apk_engine().load(f.path, nullptr);
    EngineRequest request;
    request.path = f.path;
    request.argv = {f.path};

    const LaunchPlan plan = engine::apk_engine().plan(request, image);
    check(!plan.refusal.empty(), "the APK engine refuses to run a package");
    check(plan.refusal.find("Android") != std::string::npos,
          "the refusal says what is missing");
    check(plan.refusal.find("lib/") != std::string::npos,
          "the refusal says what to do instead");
    check(plan.program.empty(), "a refused plan has no program");
}

void test_pe_plan_needs_a_scratch_directory() {
    // A Wine prefix is a directory tree the loader writes on first use. An
    // engine that invented a location outside the run's lifetime would
    // leave a wineserver's registry behind, so a run with nowhere to put
    // one is refused rather than given a default.
    TempFile f;
    check(f.write(make_pe(0x8664)), "the PE fixture was written");
    if (!f.wrote) {
        return;
    }

    const LoadedImage image = engine::pe_engine().load(f.path, nullptr);
    if (!image.ok) {
        check(false, "the PE fixture loads");
        return;
    }

    EngineRequest request;
    request.path = f.path;
    request.argv = {f.path};

    const LaunchPlan plan = engine::pe_engine().plan(request, image);
    if (plan.refusal.empty()) {
        // This host has Wine. Then the plan is a real one and the scratch
        // directory was not needed, which is a legitimate outcome; the
        // property to check is that the refusal, if any, is about Wine and
        // not about the prefix.
        check(plan.program.find("wine") != std::string::npos,
              "a PE run execs a Wine loader, not the image");
        check(plan.argv.size() >= 2, "the target is among the loader's arguments");
        check(plan.argv[1] == fs::absolute_path(f.path),
              "the loader is given the target's resolved path");
        check(plan.argv[0] == plan.program, "argv[0] is the loader");
        bool has_prefix = false;
        bool has_debug = false;
        for (const std::string& e : plan.env) {
            if (e.rfind("WINEPREFIX=", 0) == 0) {
                has_prefix = true;
                check(e.find("/occ") != std::string::npos ||
                          e.find("scratch") != std::string::npos,
                      "the prefix is inside the run's scratch space");
            }
            if (e == "WINEDEBUG=-all") {
                has_debug = true;
            }
        }
        check(has_prefix, "the loader is given a prefix");
        check(has_debug, "the loader's own diagnostics are suppressed");
        check(!plan.binds.empty(),
              "the loader's libraries are bound into the container");
        return;
    }

    // No Wine on this host, which is the case in most containers. The
    // refusal has to name the missing thing rather than failing later in
    // the dynamic linker.
    check(plan.refusal.find("Wine") != std::string::npos,
          "the refusal names Wine as the missing piece");
    check(plan.program.empty(), "a refused plan has no program");
}

// A copy of the ntdll with one symbol's section index cleared.
//
// The engine drops a symbol that is not probeable, and on a real ntdll every
// symbol in the table is a defined function -- so that branch is unreachable
// from a real file and would be untested. This makes it reachable the way it
// happens in the world: a Wine whose version has the name but not a body for
// it, which is what an import with a definition elsewhere looks like.
//
// The patch is one field of one symbol entry: st_shndx, which is what says
// which section holds the symbol's body, cleared to zero. Zero is SHN_UNDEF,
// which is exactly how the linker marks a name that is referred to and not
// defined here.
bool write_ntdll_with_undefined_symbol(const std::string& src,
                                       const std::string& dst,
                                       const std::string& symbol) {
    auto bytes = fs::read_file_bytes(src);
    if (!bytes || bytes->empty()) {
        return false;
    }
    std::vector<std::uint8_t> data = *bytes;

    const parser::ElfImage image =
        parser::ElfImage::parse(ByteSpan{data.data(), data.size()});
    if (!image.ok() || !image.has_symbols()) {
        return false;
    }

    // The name offset is looked for in the dynamic string table, which is
    // the one the dynamic symbol entries index into -- and not any other
    // string table in the file. A file has a .strtab as well, its offsets
    // are into a different table, and searching the wrong one produces a
    // number that matches no symbol in this table at all.
    //
    // The table is reached through the dynsym section's link rather than by
    // picking the first STRTAB in the file, because which STRTAB is the
    // right one is exactly the fact that has to be got right.
    const parser::SectionHeader* dynsym = nullptr;
    for (const parser::SectionHeader& s : image.sections()) {
        if (s.type == static_cast<std::uint32_t>(parser::SectionType::Dynsym)) {
            dynsym = &s;
            break;
        }
    }
    if (dynsym == nullptr || dynsym->link >= image.sections().size()) {
        return false;
    }
    const parser::SectionHeader& strtab = image.sections()[dynsym->link];
    if (strtab.type != static_cast<std::uint32_t>(parser::SectionType::Strtab)) {
        return false;
    }

    std::size_t name_off = std::string::npos;
    for (std::uint64_t i = 0; i + symbol.size() < strtab.size; ++i) {
        const std::uint64_t at = strtab.offset + i;
        if (at + symbol.size() + 1 > data.size()) {
            break;
        }
        if (std::memcmp(data.data() + at, symbol.data(), symbol.size()) == 0 &&
            data[at + symbol.size()] == 0) {
            name_off = static_cast<std::size_t>(i);
            break;
        }
    }
    if (name_off == std::string::npos) {
        return false;
    }

    const std::uint64_t stride = dynsym->entsize == 0 ? 24 : dynsym->entsize;
    for (std::uint64_t off = 0; off + stride <= dynsym->size; off += stride) {
        const std::uint64_t at = dynsym->offset + off;
        if (at + stride > data.size()) {
            break;
        }
        const std::uint32_t st_name =
            static_cast<std::uint32_t>(data[at]) |
            (static_cast<std::uint32_t>(data[at + 1]) << 8) |
            (static_cast<std::uint32_t>(data[at + 2]) << 16) |
            (static_cast<std::uint32_t>(data[at + 3]) << 24);
        if (st_name != name_off) {
            continue;
        }
        // st_shndx is a 16-bit field at offset 6 of the entry.
        data[at + 6] = 0;
        data[at + 7] = 0;
        const std::string out(reinterpret_cast<const char*>(data.data()),
                              data.size());
        return fs::write_file(dst, out);
    }
    return false;
}

// A Wine installation assembled from what the host actually has.
//
// A host can have Wine's libraries and not Wine's loader -- a distribution's
// runtime-only package is exactly that -- and on such a host the PE engine
// refuses for a reason that is correct and that hides everything after it.
// The probe path is what this exercise is about, so the loader is supplied
// here: a directory with an executable named wine64, and a lib directory
// beside it holding a link to the real ntdll when one is installed.
//
// This is not a mock of Wine. Nothing here fakes Wine's behaviour: the
// engine only looks for a file and checks the executable bit, and the ntdll
// that gets symbol-resolved is the host's real one.
struct SyntheticWine {
    std::string root;
    std::string bin_dir;
    std::string lib_dir;
    bool ok = false;

    SyntheticWine() = default;
    SyntheticWine(const SyntheticWine&) = delete;
    SyntheticWine& operator=(const SyntheticWine&) = delete;
    SyntheticWine(SyntheticWine&& o) noexcept { *this = std::move(o); }
    SyntheticWine& operator=(SyntheticWine&& o) noexcept {
        if (this != &o) {
            if (!root.empty()) {
                (void)fs::remove_tree(root);
            }
            root = std::move(o.root);
            bin_dir = std::move(o.bin_dir);
            lib_dir = std::move(o.lib_dir);
            ok = o.ok;
            o.ok = false;
        }
        return *this;
    }
    ~SyntheticWine() {
        if (!root.empty()) {
            (void)fs::remove_tree(root);
        }
    }
};

// The real ntdll, if this host has one.
std::string real_ntdll() {
    for (const char* dir : {"/usr/lib/x86_64-linux-gnu/wine/x86_64-unix",
                            "/usr/lib64/wine/x86_64-unix",
                            "/usr/lib/wine/x86_64-unix"}) {
        for (const char* name : {"ntdll.so", "ntdll.dll.so"}) {
            const std::string p = std::string(dir) + "/" + name;
            if (fs::exists(p)) {
                return p;
            }
        }
    }
    return {};
}

SyntheticWine make_synthetic_wine(const char* undefined_symbol = nullptr) {
    SyntheticWine out;
    char tmpl[] = "/tmp/occ_engine_wine_XXXXXX";
    if (::mkdtemp(tmpl) == nullptr) {
        return out;
    }
    out.root = tmpl;
    out.bin_dir = out.root + "/bin";
    out.lib_dir = out.root + "/lib/wine";
    if (!fs::mkdir_p(out.bin_dir, 0700) || !fs::mkdir_p(out.lib_dir, 0700)) {
        return out;
    }

    // A program named wine64 that is executable. The engine checks the
    // executable bit and nothing else, so a shell script is as good as a
    // binary here -- and a shell script is what a distribution's shim is.
    const std::string loader = out.bin_dir + "/wine64";
    if (!fs::write_file(loader, "#!/bin/sh\nexit 0\n")) {
        return out;
    }
    if (::chmod(loader.c_str(), 0755) != 0) {
        return out;
    }

    // The library directory has to be found under the loader's tree, which
    // is <root>/lib/wine when the loader is <root>/bin/wine64.
    const std::string unix_dir = out.lib_dir + "/x86_64-unix";
    if (!fs::mkdir_p(unix_dir, 0700)) {
        return out;
    }
    const std::string ntdll = real_ntdll();
    if (!ntdll.empty()) {
        // A copy rather than a link, because the engine reads the file and
        // a dangling link would make this host look like one with no ntdll.
        const std::string dst = unix_dir + "/ntdll.so";
        if (undefined_symbol != nullptr) {
            if (!write_ntdll_with_undefined_symbol(ntdll, dst,
                                                   undefined_symbol)) {
                return out;
            }
        } else {
            auto bytes = fs::read_file_bytes(ntdll);
            if (!bytes || bytes->empty()) {
                return out;
            }
            const std::string content(
                reinterpret_cast<const char*>(bytes->data()), bytes->size());
            if (!fs::write_file(dst, content)) {
                return out;
            }
        }
    }

    out.ok = true;
    return out;
}

// The probe plan, against a Wine assembled from this host's own libraries.
//
// The loader is named through OCC_WINE_LOADER rather than through PATH,
// because the engine caches its search in a function-local static: a test
// that changed PATH after another PE plan had run would be reading a cached
// answer and testing nothing. Naming the loader explicitly is also what the
// variable exists for -- a caller that wants a particular installation of
// several says which.
void test_pe_plan_requests_the_ntdll_probes() {
    const SyntheticWine wine = make_synthetic_wine();
    if (!wine.ok) {
        return;
    }
    if (real_ntdll().empty()) {
        std::fprintf(stderr, "note: no Wine ntdll on this host; the probe "
                             "planning check was skipped\n");
        return;
    }

    TempFile f;
    check(f.write(make_pe(0x8664)), "the PE fixture was written");
    if (!f.wrote) {
        return;
    }

    const LoadedImage image = engine::pe_engine().load(f.path, nullptr);
    if (!image.ok) {
        check(false, "the PE fixture loads");
        return;
    }

    const std::string loader = wine.bin_dir + "/wine64";
    if (::setenv("OCC_WINE_LOADER", loader.c_str(), 1) != 0) {
        return;
    }
    // The loader the plan reports has to be the one that was named, not
    // whichever one a PATH search would have found.
    const struct EnvGuard {
        ~EnvGuard() { (void)::unsetenv("OCC_WINE_LOADER"); }
    } guard;

    EngineRequest request;
    request.path = f.path;
    request.argv = {f.path};
    request.scratch_dir = wine.root + "/scratch";
    (void)fs::mkdir_p(request.scratch_dir, 0700);

    const LaunchPlan plan = engine::pe_engine().plan(request, image);

    // The loader is found now, so the plan is real and the probes are the
    // thing under test.
    if (!plan.refusal.empty()) {
        std::fprintf(stderr, "note: the synthetic Wine was refused: %s\n",
                     plan.refusal.c_str());
        return;
    }

    check(!plan.probes.empty(),
          "a PE plan against a Wine with a real ntdll asks for probes");
    if (plan.probes.empty()) {
        for (const std::string& d : plan.degradations) {
            std::fprintf(stderr, "  degradation: %s\n", d.c_str());
        }
        return;
    }

    bool saw_a_named_argument = false;
    for (const engine::ProbeRequest& p : plan.probes) {
        check(!p.module.empty(), "every probe names a module");
        check(!p.symbol.empty(), "every probe names a symbol");
        check(!p.label.empty(), "every probe has a label to report under");
        check(p.symbol.starts_with("Nt") || p.symbol.starts_with("Zw") ||
                  p.symbol.starts_with("Rtl") || p.symbol.starts_with("Ldr"),
              "every probe is on an ntdll entry point");

        // The argument names travel with the request, because the engine's
        // table is the only thing that knows them and the probe layer is
        // where they are read back off a hit. A request that dropped them
        // would produce hits with values and no names, which is a report
        // nobody can read -- and the loss would be silent, because a probe
        // with no names is a perfectly valid probe.
        if (!p.arg_names[0].empty()) {
            saw_a_named_argument = true;
        }
    }
    check(saw_a_named_argument,
          "the table's argument names reach the plan's probe requests");

    // The module is Wine's Unix-side ntdll, which is the ELF with the
    // bodies -- not the PE ntdll.dll, where the same names are thunks.
    check(plan.probes[0].module.find("ntdll") != std::string::npos,
          "the probes are in a file named ntdll");
    check(plan.probes[0].module.find(".so") != std::string::npos,
          "and it is the shared object rather than the PE image");
    check(plan.probes[0].module.find("x86_64-unix") != std::string::npos ||
              plan.probes[0].module.find("i386-unix") != std::string::npos,
          "and it is the Unix-side build");

    // Every probe in the table that this ntdll exports should have been
    // requested. The count is the table's, or less when this Wine lacks
    // some of the symbols -- and less is only allowed with a degradation
    // saying so.
    check(plan.probes.size() <= obs::ntdll_probe_count(),
          "no more probes were requested than the table holds");
    check(plan.probes.size() > 0, "and at least one was");
}

// A Wine whose ntdll has a name that is not a body.
//
// The engine has to drop it and say so. A name that is exported and undefined
// is what a version difference looks like: the symbol table has it, the
// address is zero or belongs to another module, and placing a probe on it
// produces a kernel refusal that names an offset rather than the mismatch that
// caused it.
//
// This runs against a second Wine because the loader is named per call rather
// than cached, which is what makes two installations reachable in one process.
void test_pe_plan_drops_a_symbol_with_no_body() {
    const char* const target = "NtClose";
    SyntheticWine wine = make_synthetic_wine(target);
    if (!wine.ok) {
        std::fprintf(stderr, "note: the patched ntdll could not be built\n");
        return;
    }
    if (real_ntdll().empty()) {
        return;
    }

    TempFile f;
    if (!f.write(make_pe(0x8664)) || !f.wrote) {
        return;
    }
    const LoadedImage image = engine::pe_engine().load(f.path, nullptr);
    if (!image.ok) {
        return;
    }

    const std::string loader = wine.bin_dir + "/wine64";
    if (::setenv("OCC_WINE_LOADER", loader.c_str(), 1) != 0) {
        return;
    }
    const struct EnvGuard {
        ~EnvGuard() { (void)::unsetenv("OCC_WINE_LOADER"); }
    } guard;

    EngineRequest request;
    request.path = f.path;
    request.argv = {f.path};
    request.scratch_dir = wine.root + "/scratch";
    (void)fs::mkdir_p(request.scratch_dir, 0700);

    const LaunchPlan plan = engine::pe_engine().plan(request, image);
    if (!plan.refusal.empty()) {
        return;
    }

    // The patched symbol is not in the requests, and everything else is.
    bool patched_requested = false;
    for (const engine::ProbeRequest& p : plan.probes) {
        if (p.symbol == target) {
            patched_requested = true;
        }
    }
    check(!patched_requested,
          "a symbol whose section index is cleared is not requested");

    // The count is one short of the table, which is what makes the drop
    // visible rather than inferred from a shorter list.
    check(plan.probes.size() == obs::ntdll_probe_count() - 1,
          "exactly one probe is missing from the request list");

    // And it is said out loud. A run that placed some of its probes and did
    // not name the one it missed has a hole nobody can see.
    bool said_so = false;
    for (const std::string& d : plan.degradations) {
        if (d.find(target) != std::string::npos) {
            said_so = true;
        }
    }
    check(said_so,
          "and the degradation names the symbol this Wine does not define");
}

void test_pe_plan_does_not_repeat_the_target() {
    // The caller's argv[0] is the target. The loader is given the target
    // once. Handing it twice produces a loader that treats the second copy
    // as the first argument to the program, which is a silent behaviour
    // change rather than an error.
    TempFile f;
    check(f.write(make_pe(0x8664)), "the PE fixture was written");
    if (!f.wrote) {
        return;
    }

    const LoadedImage image = engine::pe_engine().load(f.path, nullptr);
    if (!image.ok) {
        return;
    }

    EngineRequest request;
    request.path = f.path;
    request.argv = {f.path, "--flag", "value"};

    const LaunchPlan plan = engine::pe_engine().plan(request, image);
    if (!plan.refusal.empty()) {
        return; // no Wine here; the argv was never built
    }

    check(plan.argv.size() == 4, "loader, target, and two arguments");
    int occurrences = 0;
    for (const std::string& a : plan.argv) {
        if (a == fs::absolute_path(f.path)) {
            ++occurrences;
        }
    }
    check(occurrences == 1, "the target appears exactly once in the argv");
    check(plan.argv[2] == "--flag" && plan.argv[3] == "value",
          "the caller's arguments follow the target");
}

} // namespace

int main() {
    // First, and deliberately so. The engine caches its Wine search in a
    // function-local static, and this test is the one that names a loader
    // explicitly -- so it has to run before any other PE plan has populated
    // that cache. A test that ran later would read the cached answer and
    // assert nothing.
    test_pe_plan_requests_the_ntdll_probes();
    test_pe_plan_drops_a_symbol_with_no_body();

    test_every_format_has_a_decision();
    test_dispatch_is_by_format_not_by_name();
    test_engines_are_the_declared_ones();
    test_dispatch_returns_the_engine_that_claims_the_format();
    test_detection_and_format_dispatch_agree();
    test_kind_names();
    test_elf_preflight_agrees_with_the_reader();
    test_other_engines_do_not_refuse_elf();
    test_apk_preflight_defers_to_the_plan();
    test_pe_preflight_defers_to_the_headers();
    test_elf_load_reports_the_image();
    test_elf_load_of_a_missing_file_is_reported_not_silent();
    test_elf_load_of_a_malformed_file_reports_the_reader_error();
    test_pe_load_reports_sections_and_imports();
    test_pe32_reports_32_bits();
    test_load_without_a_writer_writes_nothing_and_still_answers();
    test_apk_load_reads_the_package_and_reports_no_regions();
    test_apk_load_reports_the_package_members();
    test_apk_load_of_a_package_with_no_directory_reports_no_members();
    test_elf_plan_runs_the_target_itself();
    test_plan_of_a_failed_load_refuses();
    test_apk_plan_refuses_with_an_actionable_reason();
    test_pe_plan_needs_a_scratch_directory();
    test_pe_plan_does_not_repeat_the_target();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

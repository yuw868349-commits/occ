// The placement layer: does the loaded image have the file's bytes in it.
//
// The tests in test_runtime_loader.cpp cover the decisions -- where an image
// goes, what it refuses, what it would import. They assert the map, the
// counts, and the module's own fields, and every one of those is a statement
// about what the loader decided. None of them is a statement about memory,
// because until this layer existed there was no memory to look at: the loader
// computed the address of every relocation and wrote none of them.
//
// So this file has one rule, and it is the same rule test_mapper.cpp is held
// to, applied one layer up: a claim that a byte was placed is proved by
// reading that byte back out of the mapped address and comparing it with the
// file. A loader that recorded regions, reported success, and left every page
// zero would pass every test in test_runtime_loader.cpp. It would fail the
// first case here, and the failure would name the section.
//
// The comparisons are against the file rather than against the loader's
// output for a reason that matters more than it looks: the loader's own
// reporting is what is under test, so checking its output against itself
// would agree with a loader that misplaced everything as long as it misplaced
// it consistently. The bytes in the file are the independent witness.
//
// The protections are checked by faulting in a forked child, by the same
// mechanism test_mapper.cpp uses and for the same reason: a read-only section
// that is read-write passes every field comparison above and is the failure
// this layer is most able to produce.
//
// The fixture is repeated from test_runtime_loader.cpp rather than shared,
// for the reason given there: a shared builder would mean a change made for
// one test's convenience silently changes what the other one is testing.

#include "occ/parser/pe.h"
#include "occ/runtime/address_space.h"
#include "occ/runtime/loader.h"
#include "occ/runtime/mapper.h"

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
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
constexpr std::size_t kOptSize64 = 240;
constexpr std::size_t kHeadersSize = 0x200;

constexpr std::uint32_t kScnExecute = 0x20000000;
constexpr std::uint32_t kScnRead = 0x40000000;
constexpr std::uint32_t kScnWrite = 0x80000000;

// The relocation types, so the fixture below can emit them.
constexpr std::uint16_t kRelHigh = 1;
constexpr std::uint16_t kRelLow = 2;
constexpr std::uint16_t kRelHighLow = 3;
constexpr std::uint16_t kRelHighAdj = 4;
constexpr std::uint16_t kRelDir64 = 10;

struct Reloc {
    std::uint16_t offset = 0; // the low 12 bits
    std::uint16_t type = 0;
    // Set when this entry is not a relocation at all.
    //
    // HIGHADJ spends its second entry on an adjustment, and that entry is not
    // a type and an offset: it is a raw signed 16-bit number, all sixteen bits
    // of which are the value. Expressing it through `offset` cannot work --
    // the offset field is twelve bits wide, and -8 in twelve bits is 0xFF8,
    // which is +4088 read as unsigned. So an entry written this way goes into
    // the block verbatim, and the flag is what says so.
    bool raw = false;
    std::uint16_t raw_value = 0;
};

// One relocation block, ready to append to a spec's tail.
//
// A block is a page RVA, a size covering the header, and then 16-bit entries
// of a 4-bit type and a 12-bit offset. The builder needs the block because a
// relocation directory has to point at something, and pointing it at a hand-
// written byte array means every field is written by code above rather than
// by a constant that could be wrong in a way nothing would notice.
std::vector<std::uint8_t> reloc_block(std::uint32_t page_rva,
                                       const std::vector<Reloc>& relocs) {
    const std::uint32_t size =
        static_cast<std::uint32_t>(8 + 2 * relocs.size());
    std::vector<std::uint8_t> b(size, 0);
    put32(b, 0, page_rva);
    put32(b, 4, size);
    for (std::size_t i = 0; i < relocs.size(); ++i) {
        const std::uint16_t entry =
            relocs[i].raw
                ? relocs[i].raw_value
                : static_cast<std::uint16_t>(
                      (static_cast<std::uint16_t>(relocs[i].type) << 12) |
                      (relocs[i].offset & 0x0FFF));
        put16(b, 8 + 2 * i, entry);
    }
    return b;
}

struct SectionSpec {
    const char* name = nullptr;
    std::uint32_t virtual_address = 0;
    std::uint32_t virtual_size = 0;
    std::int32_t raw_size = 0; // 0 = one page, negative = no file data
    std::uint32_t characteristics = 0;
};

struct Spec {
    bool dll = false;
    std::uint32_t entry = 0x1000;
    std::uint64_t base = 0x0000000140000000ull;
    std::vector<SectionSpec> sections;
    // Bytes written inside a section, keyed by its index. The hook exists
    // because a fixture that places real bytes in a section -- an import
    // table, a relocation target -- needs them inside the section's declared
    // raw extent rather than in the tail.
    std::vector<std::pair<std::size_t, std::vector<std::uint8_t>>>
        section_content;
    std::vector<std::uint8_t> tail;
    std::uint32_t reloc_rva = 0;
    std::uint32_t reloc_size = 0;
};

struct Built {
    std::vector<std::uint8_t> bytes;
    // The file offset of each section's data, so a case can compare what was
    // written against what the file held at the same offset.
    std::vector<std::size_t> section_file_offset;
    // The file offset of the section table itself.
    //
    // Recorded rather than recomputed at each use, because the offset is an
    // arithmetic chain over four constants and getting it wrong produces a
    // comparison against the wrong 40 bytes -- which in this fixture is a
    // region of zeros, so the comparison fails without saying what moved. The
    // first version of the headers case spelled the chain out and left out the
    // PE signature's four bytes; it read the last 40 bytes of the optional
    // header's directory array, which are zero, and reported that the section
    // table was not in memory.
    std::size_t section_table_at = 0;
    std::size_t tail_at = 0;
};

Built build(const Spec& s) {
    Built b;
    const std::size_t coff = kDosSize + 4;
    const std::size_t opt = coff + 4 + kCoffSize;
    const std::size_t sections_at = opt + kOptSize64;
    b.section_table_at = sections_at;

    std::size_t cursor = kHeadersSize;
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

    b.section_file_offset.reserve(layout.size());
    for (const auto& l : layout) {
        b.section_file_offset.push_back(l.first);
    }
    for (const auto& [index, content] : s.section_content) {
        if (index >= layout.size() ||
            layout[index].second < content.size()) {
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
    // The COFF header. Machine, section count, optional-header size and the
    // two characteristics. All four are load-bearing and none of them is
    // optional: the loader reads the machine and refuses anything but amd64
    // by name, reads the section count to bound its own walk, and reads the
    // optional header's size to find the section table -- so a builder that
    // omits one produces an image refused for a reason that has nothing to
    // do with the case under test.
    put16(b.bytes, c + 0, 0x8664); // IMAGE_FILE_MACHINE_AMD64
    put16(b.bytes, c + 2, static_cast<std::uint16_t>(s.sections.size()));
    put16(b.bytes, c + 16, static_cast<std::uint16_t>(kOptSize64));
    put16(b.bytes, c + 18,
          static_cast<std::uint16_t>(s.dll ? 0x2000 : 0x0002));

    const std::size_t o = c + kCoffSize;
    put16(b.bytes, o, 0x020b); // PE32+
    put32(b.bytes, o + 16, s.entry);
    put64(b.bytes, o + 24, s.base);
    put32(b.bytes, o + 20, 0x1000); // BaseOfCode
    put32(b.bytes, o + 32, 0x1000); // SectionAlignment
    put32(b.bytes, o + 36, 0x200);  // FileAlignment
    // The directory count. The loader reads the import and relocation
    // directories out of the array without checking the count, so this is
    // not what makes those reads safe -- the reads are bounds-checked
    // against the file -- but a zero here is a header no linker emits and a
    // parser may legitimately refuse, so it is written as 16 like a real one.
    put32(b.bytes, o + 108, 16);

    // SizeOfImage and SizeOfHeaders, in the two optional-header fields the
    // loader reads them out of.
    std::uint32_t image_size = 0;
    for (std::size_t i = 0; i < s.sections.size(); ++i) {
        const SectionSpec& sec = s.sections[i];
        const std::uint64_t mem =
            sec.virtual_size != 0 ? sec.virtual_size
                                  : (sec.raw_size > 0
                                         ? static_cast<std::uint64_t>(sec.raw_size)
                                         : 0x200u);
        const std::uint64_t end =
            (static_cast<std::uint64_t>(sec.virtual_address) + mem + 0xFFF) &
            ~0xFFFULL;
        if (end > image_size) {
            image_size = static_cast<std::uint32_t>(end);
        }
    }
    put32(b.bytes, o + 56, image_size);
    put32(b.bytes, o + 60, static_cast<std::uint32_t>(kHeadersSize));

    // The section table.
    std::size_t at = sections_at;
    for (std::size_t i = 0; i < s.sections.size(); ++i) {
        const SectionSpec& sec = s.sections[i];
        std::memset(&b.bytes[at], 0, 40);
        // The name field is eight bytes, and a name shorter than that has to
        // be copied by its own length and padded with the zeros the memset
        // just wrote.
        //
        // The obvious `memcpy(dst, sec.name, 8)` reads eight bytes from a
        // string literal that may be shorter: ".text" is six including its
        // terminator, so the copy runs two bytes past the literal. Under an
        // ordinary build it picks up whatever the linker placed next and
        // writes it into the section table, which is a fixture that produces
        // a different file on a different toolchain and a bug that no
        // assertion looks at. The sanitized build is what found it, and it
        // found it by refusing to read the two bytes rather than by noticing
        // the file was wrong -- which is the only way this class of mistake
        // can be caught, since the value it produces is not wrong in any way
        // a comparison would notice.
        const std::size_t name_len =
            (sec.name != nullptr) ? std::strlen(sec.name) : 0;
        if (name_len > 8) {
            // A linker refuses a longer name rather than truncating it, and a
            // fixture that silently truncated one would be testing a file no
            // tool produces.
            std::fprintf(stderr, "SKIP: section name '%s' is longer than 8 "
                                 "bytes\n",
                         sec.name);
            b.bytes.clear();
            return b;
        }
        std::memcpy(&b.bytes[at], sec.name, name_len);
        put32(b.bytes, at + 8, sec.virtual_size);
        put32(b.bytes, at + 12, sec.virtual_address);
        const std::uint32_t raw =
            sec.raw_size < 0
                ? 0u
                : (sec.raw_size != 0 ? static_cast<std::uint32_t>(sec.raw_size)
                                     : 0x200u);
        put32(b.bytes, at + 16, raw);
        put32(b.bytes, at + 20, layout[i].first);
        put32(b.bytes, at + 36, sec.characteristics);
        at += 40;
    }

    // The relocation directory, in the fixed prefix's directory array. The
    // offset is the array's own start for PE32+, which is the constant the
    // loader also computes.
    if (s.reloc_rva != 0) {
        put32(b.bytes, o + 112 + 8 * 5, s.reloc_rva);
        put32(b.bytes, o + 112 + 8 * 5 + 4, s.reloc_size);
    }
    return b;
}

// A base nothing is mapped at, for a fixture that will place at one.
//
// Asked of the kernel rather than written down, because a written-down base
// is an assumption about what else the process has mapped and this file
// places images at addresses in the range where a runtime's own shared
// libraries live. The first version used 0x140000000 -- a perfectly ordinary
// image base, and inside this binary's own mapping -- and every case failed
// with STATUS_CONFLICTING_ADDRESSES at an address nothing in the case chose
// badly. The address is found the same way test_mapper.cpp finds one, and
// the same reason applies: a fixed address is a claim about the process that
// stops being true the moment the process is different.
//
// The probe maps and gives back, and the release is checked, because a probe
// that cannot release what it took has not found a free range.
std::uint64_t a_free_base(std::uint64_t bytes) noexcept {
    AddressSpace probe_space;
    Mapper probe(probe_space);
    const Result<std::uint64_t> r =
        probe.map(0, bytes, PageProtection::NoAccess, RegionKind::Private);
    if (!r.ok()) {
        return 0;
    }
    const Result<std::uint64_t> released = probe.unmap(r.value);
    return released.ok() ? r.value : 0;
}

// ------------------------------------------------- reading mapped memory

std::uint64_t load_u64(std::uint64_t va) {
    std::uint64_t v = 0;
    const auto* p = reinterpret_cast<const std::uint8_t*>(va);
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | static_cast<std::uint64_t>(p[i]);
    }
    return v;
}

std::uint32_t load_u32(std::uint64_t va) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(va);
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint16_t load_u16(std::uint64_t va) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(va);
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(p[0]) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[1]) << 8));
}

// One byte at a time, and defined here rather than with the wider loads
// above because it is used in a loop: the zero-tail case below reads 768
// bytes, and a uint64 load in that loop would read eight times more memory
// than the loop asks about, which on a page boundary is a fault the loop
// did not cause.
std::uint8_t load_u8(std::uint64_t va) {
    return *reinterpret_cast<const std::uint8_t*>(va);
}

// Whether the bytes at the mapped address are the bytes the file held at
// `file_off`, for `n` bytes.
//
// Compared against the file and not against the loader's own idea of what it
// wrote, because the loader's idea is what is under test.
bool memory_holds_file(const std::vector<std::uint8_t>& file, std::size_t off,
                       std::uint64_t va, std::size_t n) {
    if (off + n > file.size()) {
        return false;
    }
    return std::memcmp(reinterpret_cast<const void*>(va), file.data() + off,
                       n) == 0;
}

// ------------------------------------------------ faulting in a child

// The mechanism is test_mapper.cpp's and for the same reason: the parent
// needs to know where the child faulted, and only the child can say. A wait
// status cannot distinguish a protection that worked from an address that was
// never mapped, which is the whole question here.
volatile sig_atomic_t report_fd = -1;

struct Observation {
    int signal_number = 0;
    std::uint64_t address = 0;
};

void on_fault(int sig, siginfo_t* info, void*) noexcept {
    if (report_fd < 0) {
        ::_exit(90);
    }
    Observation o;
    o.signal_number = sig;
    o.address = (info != nullptr && info->si_addr != nullptr)
                    ? static_cast<std::uint64_t>(
                          reinterpret_cast<std::uintptr_t>(info->si_addr))
                    : 0;
    const ssize_t n = ::write(report_fd, &o, sizeof(o));
    (void)n;
    ::_exit(0);
}

void install_fault_handler() noexcept {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    (void)::sigaction(SIGSEGV, &sa, nullptr);
    (void)::sigaction(SIGBUS, &sa, nullptr);
}

int child_touch(void* at) noexcept {
    auto* p = static_cast<volatile std::uint8_t*>(at);
    const std::uint8_t v = *p;
    static volatile std::uint8_t sink;
    sink = static_cast<std::uint8_t>(sink + v);
    return 0;
}

int child_write(void* at) noexcept {
    auto* p = static_cast<volatile std::uint8_t*>(at);
    *p = 0x11;
    return 0;
}

struct ChildOutcome {
    int exit_code = 0;
    bool completed = false;
    std::vector<Observation> faults;
};

ChildOutcome run_in_child(int (*body)(void*), void* arg) noexcept {
    ChildOutcome out;
    int fds[2] = {-1, -1};
    if (::pipe2(fds, O_CLOEXEC) != 0) {
        out.exit_code = -1;
        return out;
    }
    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(fds[0]);
        ::close(fds[1]);
        out.exit_code = -1;
        return out;
    }
    if (pid == 0) {
        ::close(fds[0]);
        report_fd = fds[1];
        install_fault_handler();
        ::_exit(body(arg));
    }
    ::close(fds[1]);
    for (;;) {
        Observation o;
        const ssize_t n = ::read(fds[0], &o, sizeof(o));
        if (n != static_cast<ssize_t>(sizeof(o))) {
            break;
        }
        out.faults.push_back(o);
    }
    ::close(fds[0]);
    int status = 0;
    (void)::waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        out.exit_code = WEXITSTATUS(status);
        out.completed = (out.exit_code == 0);
    } else {
        out.exit_code = -1;
    }
    return out;
}

bool faulted_at(const ChildOutcome& c, std::uint64_t addr) noexcept {
    for (const Observation& o : c.faults) {
        if (o.address == addr) {
            return true;
        }
    }
    return false;
}

// --------------------------------------------------------- the resolver

// A resolver that hands out a fixed address per name, so a test can predict
// the IAT's contents rather than reading back whatever it was given.
//
// The address is derived from the name rather than counted up, so two
// resolvers for two tests cannot collide by accident and so a case that
// resolves "A" and a case that resolves "B" produce different values --
// which is what makes a test that checks the IAT actually able to fail.
std::uint64_t fake_export_base = 0;

std::uint64_t resolve_fake(void* state, const std::string& dll,
                           const std::string& name, std::uint16_t ordinal,
                           bool by_ordinal) noexcept {
    (void)state;
    (void)dll;
    const std::uint64_t base = *static_cast<const std::uint64_t*>(
        &fake_export_base);
    if (by_ordinal) {
        return base + 0x10000 + ordinal;
    }
    // A hash of the name, so distinct names get distinct addresses and a
    // case can predict the value without a table.
    std::uint64_t h = 1469598103934665603ull;
    for (const char c : name) {
        h ^= static_cast<std::uint64_t>(static_cast<std::uint8_t>(c));
        h *= 1099511628211ull;
    }
    return base + 0x20000 + (h & 0xffff);
}

// The value the resolver above will return for `name`, computed the same way
// so a test can state the expected IAT contents without calling it twice.
std::uint64_t expected_export_for(const std::string& name) noexcept {
    std::uint64_t h = 1469598103934665603ull;
    for (const char c : name) {
        h ^= static_cast<std::uint64_t>(static_cast<std::uint8_t>(c));
        h *= 1099511628211ull;
    }
    return fake_export_base + 0x20000 + (h & 0xffff);
}

// ------------------------------------------------------------ the cases

// The headers' bytes are in memory.
//
// The least interesting case in the file and the one that would be missing
// first: a placement that mapped the regions and wrote only the sections
// would satisfy every relocation and import assertion below and would have a
// header page full of zeroes, and a program reads its own headers.
void test_the_headers_are_copied() {
    Spec s;
    s.entry = 0x1000;
    s.base = a_free_base(0x10000);
    s.sections = {{".text", 0x1000, 0x200, 0x200,
                   kScnRead | kScnExecute}};
    const Built b = build(s);
    if (s.base == 0) {
        std::fprintf(stderr, "SKIP headers: no free base\n");
        return;
    }

    AddressSpace space;
    Mapper m(space);
    LoadContext ctx;
    ctx.placement = &m;

    const PeImage p = PeImage::parse(ByteSpan{b.bytes.data(), b.bytes.size()});
    const LoadResult r =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, space, ctx);
    check(r.ok, "headers: loads and places");
    if (!r.ok) {
        std::fprintf(stderr, "  %s (%s)\n", load_error_name(r.error),
                     r.detail.c_str());
        return;
    }

    // The MZ signature, read out of the mapping. Two bytes rather than the
    // whole header, because the signature is the part a program and a reader
    // both look at first and the part a zero page cannot fake.
    check(memory_holds_file(b.bytes, 0, s.base, 2),
          "headers: the MZ signature is in memory");
    // And the section table, which is at a fixed offset and is the part that
    // tells a program what it is. The offset comes from the builder rather
    // than from a chain of constants spelled out here -- see Built's comment
    // for what a wrong one of those costs.
    check(memory_holds_file(b.bytes, b.section_table_at,
                            s.base + b.section_table_at, 40),
          "headers: the section table is in memory");
}

// A section's file bytes are in memory, and the part the file does not cover
// is zero.
void test_section_bytes_are_copied() {
    // A .text with real content, and a .data whose virtual size exceeds its
    // raw size so there is a tail for the zero fill to apply to.
    std::vector<std::uint8_t> text(0x100);
    for (std::size_t i = 0; i < text.size(); ++i) {
        text[i] = static_cast<std::uint8_t>((i * 7 + 3) & 0xff);
    }
    std::vector<std::uint8_t> data(0x80);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::uint8_t>((i * 11 + 5) & 0xff);
    }

    Spec s;
    s.entry = 0x1000;
    s.sections = {
        {".text", 0x1000, 0x200, 0x200, kScnRead | kScnExecute},
        // VirtualSize 0x400, raw 0x80: 0x380 bytes the file does not cover.
        {".data", 0x2000, 0x400, static_cast<std::int32_t>(data.size()),
         kScnRead | kScnWrite},
    };
    s.section_content = {{0, text}, {1, data}};
    s.base = a_free_base(0x10000);
    const Built b = build(s);
    if (s.base == 0) {
        std::fprintf(stderr, "SKIP sections: no free base\n");
        return;
    }

    AddressSpace space;
    Mapper m(space);
    LoadContext ctx;
    ctx.placement = &m;

    const PeImage p = PeImage::parse(ByteSpan{b.bytes.data(), b.bytes.size()});
    const LoadResult r =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, space, ctx);
    check(r.ok, "sections: loads and places");
    if (!r.ok) {
        std::fprintf(stderr, "  %s (%s)\n", load_error_name(r.error),
                     r.detail.c_str());
        return;
    }

    check(memory_holds_file(b.bytes, b.section_file_offset[0], s.base + 0x1000,
                            text.size()),
          "sections: .text's bytes are in memory");
    check(memory_holds_file(b.bytes, b.section_file_offset[1], s.base + 0x2000,
                            data.size()),
          "sections: .data's bytes are in memory");

    // The zero tail. A .bss's whole content, and the part of a .data that
    // exceeds its raw size, are both this: the mapping is anonymous and the
    // kernel gives zeros, and a loader that wrote the file's bytes over the
    // whole virtual extent would put file content where there was none.
    //
    // Checked as "all zero" rather than "equal to nothing", because the
    // failure this catches is a tail that holds the previous image's bytes
    // or the file's -- both of which are non-zero in the first 8 bytes of a
    // pattern and neither of which is a specific value to compare against.
    bool tail_is_zero = true;
    for (std::uint64_t va = s.base + 0x2000 + data.size(); va < s.base + 0x2400;
         ++va) {
        if (load_u8(va) != 0) {
            tail_is_zero = false;
            break;
        }
    }
    check(tail_is_zero,
          "sections: the part of .data the file does not cover is zero");
}

// A section with no file data at all is mapped and is entirely zero.
//
// This is .bss, and it is the case where a loader that copies raw_size bytes
// and leaves the rest alone is accidentally right -- the mapping is anonymous
// -- and a loader that rounded the mapping to the *raw* size is not, because
// the section's address space is its virtual size and a program that indexes
// into the tail has to find zeros rather than a fault.
void test_a_section_with_no_file_data_is_mapped_and_zero() {
    Spec s;
    s.entry = 0x1000;
    s.sections = {
        {".text", 0x1000, 0x200, 0x200, kScnRead | kScnExecute},
        // raw_size negative: no file data at all, virtual size two pages.
        {".bss", 0x2000, 0x2000, -1, kScnRead | kScnWrite},
    };
    s.base = a_free_base(0x10000);
    const Built b = build(s);
    if (s.base == 0) {
        std::fprintf(stderr, "SKIP bss: no free base\n");
        return;
    }

    AddressSpace space;
    Mapper m(space);
    LoadContext ctx;
    ctx.placement = &m;

    const PeImage p = PeImage::parse(ByteSpan{b.bytes.data(), b.bytes.size()});
    const LoadResult r =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, space, ctx);
    check(r.ok, "bss: loads and places");
    if (!r.ok) {
        return;
    }

    // The region exists, and it is the virtual size rounded to a page, not
    // the raw size. This is the assertion the ledger-only loader could not
    // make meaningfully, because there the region existed on paper.
    const Region* bss = space.find(s.base + 0x2000);
    check(bss != nullptr, "bss: the region exists");
    check(bss != nullptr && bss->size == 0x2000,
          "bss: the region is the virtual size, not the raw size");
    check(bss != nullptr && bss->section == ".bss", "bss: named in the map");

    // And it is real, writable, zero memory. A fork because the last part
    // writes, and a write to a page that is not there is a child that dies.
    const ChildOutcome c =
        run_in_child(child_write, reinterpret_cast<void*>(s.base + 0x3000));
    check(c.completed, "bss: the second page is writable memory");
    check(load_u8(s.base + 0x2000) == 0,
          "bss: the first byte is zero");
    check(load_u8(s.base + 0x3fff) == 0,
          "bss: the last byte is zero");
}

// A relocation is written, and the value written is the file's value plus the
// delta.
void test_relocations_are_written() {
    // One DIR64 at a known offset in .text, whose file value is a small
    // number standing in for a preferred-base address. After placement at a
    // different base the memory holds value + delta, and the assertion says
    // so with the arithmetic spelled out rather than comparing against
    // whatever the loader reported.
    constexpr std::uint64_t kPreferredPointer = 0x140002000ull;
    constexpr std::uint16_t kOffset = 0x40; // .text + 0x40

    std::vector<std::uint8_t> text(0x200, 0);
    put64(text, kOffset, kPreferredPointer);

    Spec s;
    s.entry = 0x1000;
    // The base in the file is a number, not an address, and it is not where
    // the image will go: the load below is told a different base, and the
    // difference between the two is the delta these relocations exist to
    // apply. Conflating them -- setting s.base to the address the image is
    // placed at -- produces a fixture whose delta is zero, and a zero delta
    // makes every relocation assertion pass against a loader that wrote
    // nothing at all.
    s.base = 0x0000000140000000ull;
    s.sections = {
        {".text", 0x1000, 0x200, 0x200, kScnRead | kScnExecute},
    };
    s.section_content = {{0, text}};
    // The relocation directory, in the tail, pointing at .text's page.
    const std::vector<std::uint8_t> block =
        reloc_block(0x1000, {{kOffset, kRelDir64}});
    s.tail = block;
    // The directory is inside .text, not in the tail. A relocation directory
    // has to be readable through the image's own RVA mapping, and the tail
    // after the last section belongs to no section -- so a fixture that puts
    // the directory there produces an image whose relocations the loader
    // cannot find, and the refusal is "a relocation block header is outside
    // the file", which is a true statement about a file no linker emits.
    //
    // RVA 0x1080 is inside .text (0x1000 to 0x1200 virtual, one page), so
    // the directory is mapped with the rest of the section.
    s.reloc_rva = 0x1080;
    s.reloc_size = static_cast<std::uint32_t>(block.size());
    // The directory's bytes go into the section's file content, which is
    // where the loader reads them from.
    s.section_content = {{0, {}}};
    {
        // Rebuild the section content with text plus the directory at 0x80.
        std::vector<std::uint8_t> content = text;
        content.resize(0x200, 0);
        std::memcpy(&content[0x80], block.data(), block.size());
        s.section_content = {{0, content}};
    }
    const Built b = build(s);
    // Placed at a base the file did not ask for, which is the only situation
    // in which a relocation exists to be applied.
    const std::uint64_t kChosenBase = a_free_base(0x10000);
    if (kChosenBase == 0) {
        std::fprintf(stderr, "SKIP reloc: no free base\n");
        return;
    }

    AddressSpace space;
    Mapper m(space);
    LoadContext ctx;
    ctx.placement = &m;

    const PeImage p = PeImage::parse(ByteSpan{b.bytes.data(), b.bytes.size()});
    const LoadResult r = load_image(
        p, ByteSpan{b.bytes.data(), b.bytes.size()}, kChosenBase, space, ctx);
    check(r.ok, "reloc: loads and places at a new base");
    if (!r.ok) {
        std::fprintf(stderr, "  %s (%s)\n", load_error_name(r.error),
                     r.detail.c_str());
        return;
    }

    check(r.module.relocations_applied == 1,
          "reloc: one relocation was reported");
    check(r.module.base == kChosenBase, "reloc: the module is at the new base");

    // The value in memory, computed here rather than read from the loader.
    //
    // The `volatile` is the same precaution the type case takes, and for the
    // same reason: an expectation built from the same constants the loader
    // used is a value the optimizer may treat as an alias for what it is
    // comparing against, and an assertion that has been optimized into
    // reading its own answer tests nothing.
    const std::uint64_t delta = kChosenBase - 0x0000000140000000ull;
    volatile std::uint64_t want = kPreferredPointer + delta;
    const std::uint64_t got = load_u64(kChosenBase + 0x1000 + kOffset);
    check(got == want, "reloc: the DIR64 in memory is the file value plus the "
                       "delta");
    if (got != want) {
        std::fprintf(stderr, "  got 0x%llx want 0x%llx\n",
                     static_cast<unsigned long long>(got),
                     static_cast<unsigned long long>(want));
    }

    // And it is not the file's value, which is the check that would fail if
    // the loader reported success and wrote nothing.
    check(got != kPreferredPointer,
          "reloc: the value changed, so something was written");
}

// The five types, each written in its own shape rather than all of them
// normalized to DIR64, and each in the *width the format gives it*.
//
// The width is the part this case exists for. HIGH, LOW and HIGHADJ are
// 16-bit types -- they were invented for machines whose instructions held half
// an address each -- and an implementation that reads and writes 32 bits at
// their addresses corrupts the neighbouring field. The first version of this
// case wrote all four fields as 32-bit values, and it passed against an
// implementation that was wrong in three separate ways at once: a 32-bit HIGH,
// a LOW that was a no-op, and a HIGHADJ whose adjustment came from the bytes
// after the field in the image rather than from the entry that carries it.
// Every assertion below is stated in the field's own width, so a widening of
// any of them changes what the assertion reads.
void test_every_relocation_type_is_written_in_its_own_form() {
    constexpr std::uint16_t kOff = 0x40;
    // HIGHADJ's adjustment, as a signed 16-bit value.
    //
    // The value is chosen, and the choice is load-bearing in a way that took
    // a mutation to find. Two 16-bit adjustments can differ by at most 65535,
    // and the result the loader keeps is the *high* half of a 32-bit sum -- so
    // a difference smaller than 0x10000 cannot change that high half unless it
    // crosses a 16-bit boundary on the way. The delta cannot supply that
    // boundary: both the preferred base and the placement base are page
    // aligned, so the delta's low 16 bits are zero and the whole of the
    // comparison lives in the adjustment.
    //
    // -32768 is the value that puts the sum across the boundary. The kernel's
    // arithmetic is `Temp = field << 16; Temp += adjustment; Temp += Diff;
    // Temp += 0x8000`, and with Diff's low half zero:
    //
    //   adjustment -32768:  0x8000 + 0x8000 = 0x10000, carries -> field + 1
    //   adjustment      0:  0x0000 + 0x8000 = 0x8000, no carry -> field
    //
    // so an implementation that read the adjustment from anywhere other than
    // the entry lands on `field` and the field it should have produced is
    // `field + 1`. The first version of this case used -8, which adds 0x8000
    // to 0x7FF8 and carries nothing; against a wrong source it produced a
    // different low half of the sum and the *same* high half, and a mutation
    // that moved the adjustment out of the entry passed every assertion here.
    //
    // A second thing this value catches: it is the most negative int16 there
    // is, so a loader that read the entry's bits as unsigned added 32768
    // instead of subtracting 32768 -- a sign error of 65536, which is one
    // whole carry, and lands two fields off rather than one.
    constexpr std::int16_t kAdjustment = -32768;
    // A second HIGHADJ, with an adjustment chosen against the *other* way to
    // read one.
    //
    // One constant cannot cover both mistakes, and -32768 covers only one of
    // them. It was picked so that a zero-extended adjustment lands a whole
    // field away: 0x8000 read as unsigned is +32768 rather than -32768, a sign
    // error of 65536, which is exactly one carry. But masking the sign bit off
    // instead -- `adj & 0x7FFF` -- turns -32768 into 0, and 0x7FFF's complement
    // of the rounding term is the same 0x8000 the correct -32768 produces, so
    // the two agree on the high half and the mutation passes. Measured, not
    // argued: `static_cast<std::uint16_t>(adj) & 0x7FFF` escaped every
    // assertion in this file when this was the only HIGHADJ.
    //
    // -1 is the value that separates them. Read correctly it subtracts one and
    // the sum sits just below the rounding term; masked to 15 bits it becomes
    // 0x7FFF, which is a difference of 32768 -- half the range, and here it
    // straddles the boundary the first one straddles in the other direction.
    // Together the two fields pin all three readings: the entry's bits as
    // signed, as unsigned, and as unsigned with the sign bit cleared.
    constexpr std::int16_t kAdjustment2 = -1;
    // The 16 bits immediately *after* each HIGHADJ's field: the low half of
    // the immediate pair, on the machines that emit this type.
    //
    // Given values that carry nothing when 0x8000 is added, so that "read
    // the adjustment from the image" and "read it from the second entry" reach
    // different high halves. See the note above on why this took a mutation to
    // find: with the bytes left at zero, and with an adjustment of -8, both
    // sources computed the same answer and the case could not tell them apart.
    constexpr std::uint16_t kLowHalf = 0x0100;
    constexpr std::uint16_t kLowHalf2 = 0x0050;

    std::vector<std::uint8_t> text(0x200, 0);
    // Four fields the linker emitted, each starting at a value the arithmetic
    // below can predict. The two 16-bit ones are written as 16-bit values, and
    // the bytes after each of them hold a distinguishable pattern so that a
    // 32-bit read of either field would see a value nothing here predicts.
    put16(text, kOff + 0x00, 0xABCDu);        // HIGH
    put16(text, kOff + 0x02, 0x1357u);        // ... and the half after it
    put32(text, kOff + 0x08, 0x00001234u);    // HIGHLOW
    put16(text, kOff + 0x10, 0x5678u);        // HIGHADJ's field
    put16(text, kOff + 0x12, kLowHalf);       // the low half of the pair
    put16(text, kOff + 0x1C, 0x9F3Du);        // the second HIGHADJ's field
    put16(text, kOff + 0x1E, kLowHalf2);      // ... and its low half
    put16(text, kOff + 0x18, 0xFEDCu);        // LOW
    put16(text, kOff + 0x1A, 0xBEEFu);        // ... and the half after it

    Spec s;
    s.entry = 0x1000;
    s.sections = {{".text", 0x1000, 0x200, 0x200, kScnRead | kScnExecute}};
    s.section_content = {{0, text}};
    // The block, in the order the assertions below read it. Each HIGHADJ is two
    // entries: the first names the field, and the second carries the
    // adjustment as a raw signed 16-bit value -- 0x8000 for -32768 and 0xFFFF
    // for -1, which are the encodings a linker emits and which cannot be
    // expressed as a type and a twelve-bit offset. That second entry's type
    // nibble is not to be interpreted and its offset is not to be relocated:
    // it is a number.
    const std::vector<std::uint8_t> block = reloc_block(
        0x1000, {{kOff + 0x00, kRelHigh},
                 {kOff + 0x08, kRelHighLow},
                 {kOff + 0x10, kRelHighAdj},
                 {0, 0, true, static_cast<std::uint16_t>(kAdjustment)},
                 {kOff + 0x18, kRelLow},
                 {kOff + 0x1C, kRelHighAdj},
                 {0, 0, true, static_cast<std::uint16_t>(kAdjustment2)}});
    {
        std::vector<std::uint8_t> content = text;
        content.resize(0x200, 0);
        std::memcpy(&content[0x80], block.data(), block.size());
        s.section_content = {{0, content}};
    }
    s.reloc_rva = 0x1080;
    s.reloc_size = static_cast<std::uint32_t>(block.size());
    // The file's base, which is a number and not an address anything is
    // mapped at. See the same note in test_relocations_are_written: setting
    // this to the placement address would make the delta zero and the four
    // assertions below would agree with a loader that wrote nothing.
    s.base = 0x0000000140000000ull;
    const Built b = build(s);
    const std::uint64_t kChosenBase = a_free_base(0x10000);
    if (kChosenBase == 0) {
        std::fprintf(stderr, "SKIP types: no free base\n");
        return;
    }

    AddressSpace space;
    Mapper m(space);
    LoadContext ctx;
    ctx.placement = &m;

    const PeImage p = PeImage::parse(ByteSpan{b.bytes.data(), b.bytes.size()});
    const LoadResult r = load_image(
        p, ByteSpan{b.bytes.data(), b.bytes.size()}, kChosenBase, space, ctx);
    check(r.ok, "types: loads and places at a new base");
    if (!r.ok) {
        std::fprintf(stderr, "  %s (%s)\n", load_error_name(r.error),
                     r.detail.c_str());
        return;
    }

    // A delta whose top 16 bits are non-zero, so HIGH has something to do.
    // The placement base comes from the kernel and the file's base is
    // 0x140000000, so the delta is a full 64-bit displacement whose sign and
    // magnitude are whatever the kernel's answer made them -- which is the
    // point. A fixture that pinned both ends to chosen constants would be
    // asserting arithmetic about numbers it chose, and the case a HIGH bug
    // needs is one where the delta does not fit in 16 bits by any accident of
    // layout.
    const std::uint64_t delta = kChosenBase - 0x0000000140000000ull;
    const std::int32_t delta32 = static_cast<std::int32_t>(delta);
    const std::uint64_t text_va = kChosenBase + 0x1000;

    // Each expected value is the kernel's arithmetic on this case's inputs,
    // written out rather than folded into a constant, because a folded
    // constant is a number this file chose and would agree with an
    // implementation that chose the same wrong number.
    //
    // HIGH: `Temp = (field << 16) + delta; field = Temp >> 16`. The field
    // moves by the delta's high half and keeps its own low half; the two
    // halves of the field are read and written as one 16-bit value.
    {
        volatile std::int32_t temp =
            static_cast<std::int32_t>(static_cast<std::uint32_t>(0xABCDu)
                                      << 16);
        temp += delta32;
        check(load_u16(text_va + kOff) ==
                  static_cast<std::uint16_t>(temp >> 16),
              "types: HIGH added the delta's high half to a 16-bit field");
        // The bytes after the field hold the pattern, unchanged. A 32-bit
        // implementation would write the field's new value over the low half,
        // and a HIGHADJ that read its adjustment from the image would have
        // consumed this value instead of the entry's.
        check(load_u16(text_va + kOff + 0x02) == 0x1357u,
              "types: HIGH wrote 16 bits and left the next field alone");
    }

    // HIGHLOW: a 32-bit field moves by the whole delta, with wraparound.
    {
        volatile std::uint32_t v = 0x00001234u;
        v += static_cast<std::uint32_t>(delta32);
        check(load_u32(text_va + kOff + 0x08) == v,
              "types: HIGHLOW added the whole delta to a 32-bit field");
    }

    // HIGHADJ: the kernel's five steps, in its order. The adjustment is the
    // second entry's own 16 bits -- not the bytes after the field -- and it is
    // signed; and the 0x8000 is a rounding term whose absence is invisible on
    // half the inputs and wrong on the rest, which is why the value below is
    // computed rather than chosen.
    //
    // The expected values go through `volatile` on purpose. An assertion that
    // computes its expectation with the same arithmetic the loader uses, from
    // constants, and then compares it against a load from the mapped address is
    // one the optimizer is entitled to fold: the field in memory *is* the thing
    // the expression re-derives, and a compiler that proves the two agree by
    // re-reading it has proved nothing.
    //
    // It did exactly that here, and the measurement is worth writing down
    // because the failure is invisible. The mutation was HIGHADJ's adjustment
    // read out of the bytes after the field in the image instead of out of the
    // second relocation entry -- which is what this runtime's own original
    // code did, and wrong here by a wide margin. With the expectation computed
    // in a plain local, that mutation passed all 74 checks in this file. With
    // the expectation accumulated through a `volatile`, the same mutation fails
    // two of them -- with no diagnostic print in the loader, and with no LTO in
    // the build to excuse it. The only difference between those two runs is
    // the `volatile`.
    //
    // A first attempt at diagnosing this put an fprintf in the loader's own
    // HIGHADJ branch, after which the mutation was caught, and it was easy to
    // conclude the print had fixed the assertion. It had not. The print was
    // only the second, weaker half of the effect; `volatile` is the half that
    // works on its own, and the control run is what separates the two.
    //
    // Hence the rule, for this file and for the ones beside it: an expected
    // value derived from the same arithmetic as the code under test is a
    // *value*, and `volatile` is how it says so. The alternative -- making the
    // loader noisy so the compiler cannot see through the test -- buys a green
    // run with a print left in production code, and that is a worse defect than
    // a folded assertion, because it looks like a fix.
    auto expected_field = [](std::uint16_t initial, std::int16_t adj,
                             std::int32_t addend, std::int32_t rounding) {
        volatile std::int32_t t =
            static_cast<std::int32_t>(static_cast<std::uint32_t>(initial)
                                      << 16);
        t += adj;
        t += addend;
        t += rounding;
        return static_cast<std::uint16_t>(t >> 16);
    };

    {
        const std::uint16_t want =
            expected_field(0x5678u, kAdjustment, delta32, 0x8000);
        check(load_u16(text_va + kOff + 0x10) == want,
              "types: HIGHADJ added the adjustment, the delta, and the "
              "rounding");
        // The 0x8000 on its own. A runtime that did the other three steps and
        // forgot this one produces a field exactly one lower whenever the sum's
        // low half falls in [0, 0x8000) -- a third of all inputs, and invisible
        // on the rest. Whether this particular delta lands in that third is
        // not something the fixture gets to choose -- the base comes from the
        // kernel -- so the assertion is conditional on it: where the two
        // candidates differ, the value must be the rounded one.
        const std::uint16_t unrounded =
            expected_field(0x5678u, kAdjustment, delta32, 0);
        if (static_cast<std::uint32_t>(
                static_cast<std::int32_t>(0x5678u << 16) + kAdjustment +
                delta32) < 0x8000u) {
            check(load_u16(text_va + kOff + 0x10) != unrounded,
                  "types: HIGHADJ's rounding term moved the field by one");
        } else {
            // The other two thirds, stated so that the case does not read as
            // though it had asserted something here. A loader with no
            // rounding term agrees with this on these inputs, and the case
            // above is where it is caught.
            check(load_u16(text_va + kOff + 0x10) == want,
                  "types: HIGHADJ matches the kernel where rounding agrees");
        }
        // The low half of the immediate pair is untouched. It is not the
        // adjustment -- that came from the second entry -- and it is not the
        // field's new value either, so this fails both a 32-bit write and an
        // implementation that took the adjustment from the image.
        check(load_u16(text_va + kOff + 0x12) == kLowHalf,
              "types: HIGHADJ wrote 16 bits and left the next field alone");
    }

    // The second HIGHADJ, whose adjustment is -1 rather than -32768. The two
    // assertions are the same shape and they are not redundant: the first
    // field's adjustment is the one value that a 15-bit mask cannot distinguish
    // from the correct reading, and this field's is the one that a 15-bit mask
    // moves by half the range. Between them the two fields fail every wrong
    // reading of the adjustment that was measured -- as unsigned, as unsigned
    // with the sign bit cleared, and as unsigned with the sign bit kept but the
    // value taken from the image instead of the entry.
    {
        const std::uint16_t want =
            expected_field(0x9F3Du, kAdjustment2, delta32, 0x8000);
        check(load_u16(text_va + kOff + 0x1C) == want,
              "types: a second HIGHADJ read its adjustment as signed");
        check(load_u16(text_va + kOff + 0x1E) == kLowHalf2,
              "types: the second HIGHADJ wrote 16 bits and stopped");
    }

    // LOW: a 16-bit field moves by the whole delta and wraps inside its own
    // 16 bits.
    {
        volatile std::uint32_t v = 0xFEDCu;
        v += static_cast<std::uint32_t>(delta32);
        check(load_u16(text_va + kOff + 0x18) ==
                  static_cast<std::uint16_t>(v),
              "types: LOW added the delta to a 16-bit field");
        check(load_u16(text_va + kOff + 0x1A) == 0xBEEFu,
              "types: LOW wrote 16 bits and left the next field alone");
    }

    // And the module counted five relocations from seven entries, because each
    // HIGHADJ's second entry is its adjustment rather than a relocation of its
    // own. A loader that counted seven applied the delta to the adjustments'
    // own type nibbles -- which on this fixture are 0xF, an unknown relocation
    // type, so the mistake would be refused rather than applied; with the type
    // nibbles clear it would be applied to whatever the low thirteen bits
    // named, which on a real image is a field of code.
    check(r.module.relocations_applied == 5,
          "types: seven entries were five relocations");
}

// An import's address is written into its IAT slot, and the value is the one
// the resolver returned.
void test_the_iat_is_written() {
    // A .text with an import directory in a writable section, because the
    // IAT has to be writable and a real linker puts it in one.
    //
    // The layout inside the section, at fixed offsets:
    //   0x00  descriptor 0 (20 bytes)
    //   0x20  name thunk 0, name thunk 1, terminator (24 bytes)
    //   0x40  IAT slot 0, slot 1, terminator (24 bytes)
    //   0x60  hint/name 0 (2 + "Alpha\0" = 8)
    //   0x70  hint/name 1 (2 + "Beta\0" = 6)
    //   0x80  "kernel32.dll\0"
    std::vector<std::uint8_t> idata(0x200, 0);
    // Every RVA here is absolute, and that is the whole subtlety of this
    // fixture: an import descriptor's fields are RVAs, not offsets within the
    // section that happens to hold the descriptor. The first version wrote
    // them as section offsets -- OriginalFirstThunk = 0x20 when the table
    // lives at RVA 0x2000 -- and the loader went looking for a name thunk at
    // RVA 0x20, which is inside the DOS header, found nothing, and reported
    // an image with no imports rather than a fixture with a bug. Both halves
    // of that are bad: the fixture was wrong and the report was empty, which
    // is the failure mode a checker has to be hardest about.
    constexpr std::uint32_t kIdata = 0x2000;
    put32(idata, 0x00, kIdata + 0x20);   // OriginalFirstThunk
    put32(idata, 0x04, 0);               // TimeDateStamp
    put32(idata, 0x08, 0);               // ForwarderChain
    put32(idata, 0x0C, kIdata + 0x80);   // Name
    put32(idata, 0x10, kIdata + 0x40);   // FirstThunk, the IAT
    // The two name thunks, as RVAs to hint/name entries.
    put64(idata, 0x20, kIdata + 0x60);
    put64(idata, 0x28, kIdata + 0x70);
    put64(idata, 0x30, 0);
    // The IAT starts holding the same RVAs, which is what the file holds
    // before a loader fills it.
    put64(idata, 0x40, kIdata + 0x60);
    put64(idata, 0x48, kIdata + 0x70);
    put64(idata, 0x50, 0);
    // Hint/name entries: a 16-bit hint then the name.
    put16(idata, 0x60, 0);
    std::memcpy(&idata[0x62], "Alpha", 6);
    put16(idata, 0x70, 0);
    std::memcpy(&idata[0x72], "Beta", 5);
    std::memcpy(&idata[0x80], "kernel32.dll", 13);

    Spec s;
    s.entry = 0x1000;
    // Placed at the image's own base, so there is no delta and no relocation
    // to confuse the IAT with. The base is a free one because a fixture that
    // loaded at 0x140000000 would be asserting that this binary does not
    // already have something mapped there.
    s.base = a_free_base(0x10000);
    s.sections = {
        {".text", 0x1000, 0x200, 0x200, kScnRead | kScnExecute},
        {".idata", 0x2000, 0x200, 0x200, kScnRead | kScnWrite},
    };
    s.section_content = {{1, idata}};
    const Built b = build(s);
    if (s.base == 0) {
        std::fprintf(stderr, "SKIP iat: no free base\n");
        return;
    }

    // The import directory itself, in the optional header. The loader reads
    // it from the raw header rather than through the parser, so the fixture
    // has to write it there.
    Built mut = b;
    const std::size_t coff = kDosSize + 4;
    const std::size_t opt = coff + 4 + kCoffSize;
    put32(mut.bytes, opt + 112 + 8 * 1, 0x2000);
    put32(mut.bytes, opt + 112 + 8 * 1 + 4, 0x200);

    fake_export_base = 0x0000000070000000ull;
    AddressSpace space;
    Mapper m(space);
    LoadContext ctx;
    ctx.placement = &m;
    ctx.resolver_state = nullptr;
    ctx.resolve = resolve_fake;

    const PeImage p = PeImage::parse(ByteSpan{mut.bytes.data(), mut.bytes.size()});
    const LoadResult r = load_image(
        p, ByteSpan{mut.bytes.data(), mut.bytes.size()}, 0, space, ctx);
    check(r.ok, "iat: loads and places");
    if (!r.ok) {
        std::fprintf(stderr, "  %s (%s)\n", load_error_name(r.error),
                     r.detail.c_str());
        return;
    }

    check(r.module.imports.size() == 2, "iat: two imports resolved");
    if (r.module.imports.size() != 2) {
        return;
    }

    // Every address below is stated as an offset from the base rather than as
    // the constant 0x140000000, because the base is now whatever the kernel
    // gave and a literal would silently read a different image's memory.
    const std::uint64_t iat = s.base + 0x2000 + 0x40;
    check(load_u64(iat) == expected_export_for("Alpha"),
          "iat: slot 0 holds the address the resolver returned for Alpha");
    check(load_u64(iat + 8) == expected_export_for("Beta"),
          "iat: slot 1 holds the address the resolver returned for Beta");
    // The terminator is still a terminator. A loader that filled the IAT by
    // walking until it hit something else would write past the array.
    check(load_u64(iat + 16) == 0, "iat: the terminator is still a terminator");

    // The name thunks are untouched. They share their values with the IAT in
    // the file and they must stop sharing them here, or a second load of the
    // same image would read addresses where it expected names -- which is the
    // idempotence the loader's own comment promises.
    check(load_u64(s.base + 0x2000 + 0x20) == 0x2000 + 0x60,
          "iat: the name thunk array still holds the first name's RVA");

    // And the field says the slot was written, not merely that the import
    // resolved. The two are different claims and a caller asking whether the
    // program can call the function needs the second.
    check(r.module.imports[0].resolved, "iat: import 0 is marked resolved");
    check(r.module.imports[0].iat_written,
          "iat: import 0 says its slot was written");
    check(r.module.imports[1].iat_written,
          "iat: import 1 says its slot was written");
}

// An import that resolved nothing leaves its slot alone, and says so.
//
// The alternative -- writing a zero -- turns a program's "call the resolved
// address" into "call null", which is a different failure with a different
// cause, and a loader that hides that behind a resolved-looking zero is
// making a program debuggable in the wrong way.
void test_an_unresolved_import_leaves_its_slot_alone() {
    // Absolute RVAs, for the reason given in test_the_iat_is_written: the
    // fields of an import descriptor are RVAs and not offsets within the
    // section holding it.
    constexpr std::uint32_t kIdata = 0x2000;
    std::vector<std::uint8_t> idata(0x200, 0);
    put32(idata, 0x00, kIdata + 0x20);
    put32(idata, 0x0C, kIdata + 0x80);
    put32(idata, 0x10, kIdata + 0x40);
    put64(idata, 0x20, kIdata + 0x60);
    put64(idata, 0x28, 0);
    put64(idata, 0x30, 0);
    put64(idata, 0x40, kIdata + 0x60);
    put64(idata, 0x48, 0);
    put16(idata, 0x60, 0);
    std::memcpy(&idata[0x62], "Alpha", 6);
    std::memcpy(&idata[0x80], "kernel32.dll", 13);

    Spec s;
    s.entry = 0x1000;
    s.base = a_free_base(0x10000);
    s.sections = {
        {".text", 0x1000, 0x200, 0x200, kScnRead | kScnExecute},
        {".idata", 0x2000, 0x200, 0x200, kScnRead | kScnWrite},
    };
    s.section_content = {{1, idata}};
    Built mut = build(s);
    const std::size_t coff = kDosSize + 4;
    const std::size_t opt = coff + 4 + kCoffSize;
    put32(mut.bytes, opt + 112 + 8 * 1, 0x2000);
    put32(mut.bytes, opt + 112 + 8 * 1 + 4, 0x200);
    if (s.base == 0) {
        std::fprintf(stderr, "SKIP unresolved: no free base\n");
        return;
    }

    AddressSpace space;
    Mapper m(space);
    LoadContext ctx;
    ctx.placement = &m;
    // No resolver: the image's imports are recorded and not resolved, which
    // is what `occ check` does and what a caller with no implementation yet
    // does.

    const PeImage p =
        PeImage::parse(ByteSpan{mut.bytes.data(), mut.bytes.size()});
    const LoadResult r = load_image(
        p, ByteSpan{mut.bytes.data(), mut.bytes.size()}, 0, space, ctx);
    check(r.ok, "unresolved: loads and places");
    if (!r.ok) {
        return;
    }
    check(r.module.imports.size() == 1, "unresolved: the import is recorded");
    if (r.module.imports.empty()) {
        return;
    }
    check(!r.module.imports[0].resolved, "unresolved: it is not resolved");
    check(!r.module.imports[0].iat_written,
          "unresolved: it says its slot was not written");
    // The slot holds what the file held. This is the assertion that
    // distinguishes "left alone" from "written with zero", and it is the
    // difference between a program that reads 0x60 and one that reads 0.
    check(load_u64(s.base + 0x2000 + 0x40) == 0x2000 + 0x60,
          "unresolved: the slot still holds the file's RVA");
}

// The protections are applied after the writes, which is the only order that
// works, and this is the check that it happened.
void test_the_final_protections_are_applied() {
    std::vector<std::uint8_t> text(0x200, 0);
    put64(text, 0x40, 0x140002000ull);
    std::vector<std::uint8_t> data(0x200, 0);

    Spec s;
    s.entry = 0x1000;
    // A number in a header. The load is placed elsewhere, so there is a delta
    // and the relocation below has something to do -- which this case needs,
    // because its subject is what happens to a region *after* the writes, and
    // an image with no relocations never opens the read-write window that
    // closing it is about.
    s.base = 0x0000000140000000ull;
    s.sections = {
        {".text", 0x1000, 0x200, 0x200, kScnRead | kScnExecute},
        {".data", 0x2000, 0x200, 0x200, kScnRead | kScnWrite},
    };
    s.section_content = {{0, text}, {1, data}};
    const std::vector<std::uint8_t> block =
        reloc_block(0x1000, {{0x40, kRelDir64}});
    {
        // The directory inside .text, because a directory has to be readable
        // through the image's own RVA mapping. The tail after the last section
        // belongs to no section, and a fixture that puts it there produces an
        // image whose relocations the loader cannot find at all.
        std::vector<std::uint8_t> content = text;
        content.resize(0x200, 0);
        std::memcpy(&content[0x80], block.data(), block.size());
        s.section_content = {{0, content}, {1, data}};
    }
    s.reloc_rva = 0x1080;
    s.reloc_size = static_cast<std::uint32_t>(block.size());
    const Built b = build(s);

    AddressSpace space;
    Mapper m(space);
    LoadContext ctx;
    ctx.placement = &m;

    const PeImage p = PeImage::parse(ByteSpan{b.bytes.data(), b.bytes.size()});
    const std::uint64_t kChosenBase = a_free_base(0x10000);
    if (kChosenBase == 0) {
        std::fprintf(stderr, "SKIP protect: no free base\n");
        return;
    }
    const LoadResult r = load_image(
        p, ByteSpan{b.bytes.data(), b.bytes.size()}, kChosenBase, space, ctx);
    check(r.ok, "protect: loads and places");
    if (!r.ok) {
        std::fprintf(stderr, "  %s (%s)\n", load_error_name(r.error),
                     r.detail.c_str());
        return;
    }

    // The ledger says the right things.
    const Region* t = space.find(kChosenBase + 0x1000);
    const Region* d = space.find(kChosenBase + 0x2000);
    const Region* h = space.find(kChosenBase);
    check(t != nullptr && t->protection == PageProtection::ExecuteRead,
          "protect: .text is read-execute in the ledger");
    check(d != nullptr && d->protection == PageProtection::ReadWrite,
          "protect: .data is read-write in the ledger");
    check(h != nullptr && h->protection == PageProtection::ReadOnly,
          "protect: the headers are read-only in the ledger");
    check(t != nullptr && t->protection_changes == 1,
          "protect: .text's protection changed once");

    // And the kernel says the same things, which is the part a ledger-only
    // loader could not produce. .text must not be writable: it is mapped
    // read-write for the relocation and read-execute when the load is done,
    // and a loader that never closed that window has produced an image whose
    // code page can be written by anything that finds the address.
    const ChildOutcome write_text =
        run_in_child(child_write, reinterpret_cast<void*>(kChosenBase + 0x1000));
    check(faulted_at(write_text, kChosenBase + 0x1000),
          "protect: .text faults on write, so the window was closed");
    const ChildOutcome read_text =
        run_in_child(child_touch, reinterpret_cast<void*>(kChosenBase + 0x1000));
    check(read_text.completed, "protect: .text is still readable");

    // .data is writable, which is the other half: a loader that made
    // everything read-only to be safe would pass the check above.
    const ChildOutcome write_data =
        run_in_child(child_write, reinterpret_cast<void*>(kChosenBase + 0x2000));
    check(write_data.completed, "protect: .data is writable");

    // The headers too. A loader that left them writable would let a program
    // rewrite its own section table.
    const ChildOutcome write_headers =
        run_in_child(child_write, reinterpret_cast<void*>(kChosenBase));
    check(faulted_at(write_headers, kChosenBase),
          "protect: the headers fault on write");
}

// A load without a mapper still makes every decision and stores nothing.
//
// This is `occ check`'s mode, and it is a contract rather than a fallback:
// a checker that mapped every file it looked at would be a runtime with a
// file browser attached. Asserted here because the placement work touched
// this path -- the batch is built once and goes to two different places --
// and a change that made the no-mapper path map anyway would be invisible
// everywhere else.
void test_a_load_without_a_mapper_maps_nothing() {
    Spec s;
    s.entry = 0x1000;
    // A base nothing is mapped at, chosen so that the read in the child below
    // is a read of an address that genuinely has nothing there. With a
    // hardcoded base the child might be reading this binary's own mapping and
    // the assertion would be about the wrong memory.
    s.base = a_free_base(0x10000);
    s.sections = {{".text", 0x1000, 0x200, 0x200, kScnRead | kScnExecute}};
    const Built b = build(s);
    if (s.base == 0) {
        std::fprintf(stderr, "SKIP no mapper: no free base\n");
        return;
    }

    AddressSpace space;
    // No mapper. The default LoadContext, which is exactly what `occ check`
    // passes.
    const PeImage p = PeImage::parse(ByteSpan{b.bytes.data(), b.bytes.size()});
    const LoadResult r =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, space,
                   LoadContext{});
    check(r.ok, "no mapper: still loads");
    check(r.module.base == s.base, "no mapper: still decides the base");
    check(space.regions().size() == 2,
          "no mapper: the ledger has the regions, as it always did");

    // And there is no memory at the image's base. Read it in a child, because
    // a read of an unmapped address in this process is a process that died.
    //
    // The base came from the kernel and was given back, so this child is
    // reading an address that had nothing mapped a moment ago -- which is
    // exactly the claim. A hardcoded base could not make it: the address
    // might be inside this binary or inside a sanitized build's shadow
    // memory, and a child that read either would report nothing wrong.
    const ChildOutcome absent =
        run_in_child(child_touch, reinterpret_cast<void*>(s.base));
    check(faulted_at(absent, s.base),
          "no mapper: the image's base faults, so nothing was placed there");

    // And what makes the two modes differ is not visible in anything the
    // loader returns, which is the whole reason the check above is a fork
    // rather than a field comparison. The ledger is the same either way: the
    // same regions, at the same addresses, with the same protections.
    //
    // What is *not* the same is the count. A placed region went in as
    // read-write and was protected afterwards, so its ledger entry records
    // one protection change; an unplaced one was recorded once with its final
    // value and records none. A loader that quietly mapped anyway would show
    // a non-zero count here, which is a weaker signal than the fault above
    // but names the mechanism rather than the symptom.
    check(space.regions()[0].protection == PageProtection::ReadOnly,
          "no mapper: the recorded protections are the section's own");
    for (const Region& reg : space.regions()) {
        check(reg.protection_changes == 0,
              "no mapper: no region was protected after the fact");
    }
}

// A placement that fails leaves nothing behind.
//
// The contract this file's whole header claims, in the case that is hardest
// to get right: a mapping that succeeded and a later step that failed has to
// be undone, or the space is left holding memory the map does not describe.
// The case chosen is a relocation that names an address no region covers --
// the plan accepts it (the RVA is inside the image) and the write cannot
// satisfy it (the address is in a gap between sections).
void test_a_failed_placement_leaves_nothing_behind() {
    // Two sections with a gap between them, and a relocation into the gap.
    // The gap is inside SizeOfImage because the second section's virtual
    // address is what makes the image that size, so the plan's image-size
    // check passes; the gap itself is mapped by nobody.
    std::vector<std::uint8_t> text(0x200, 0);
    put64(text, 0x40, 0x140002000ull);

    Spec s;
    s.entry = 0x1000;
    s.base = 0x0000000140000000ull;
    s.sections = {
        {".text", 0x1000, 0x200, 0x200, kScnRead | kScnExecute},
        {".data", 0x4000, 0x200, 0x200, kScnRead | kScnWrite},
    };
    // A relocation at RVA 0x3000, which is between .text (ends 0x1200) and
    // .data (starts 0x4000). The gap is inside SizeOfImage because .data's
    // virtual address is what makes the image that size, so the plan's
    // image-size check passes; the gap itself is mapped by nobody.
    const std::vector<std::uint8_t> block =
        reloc_block(0x3000, {{0x00, kRelDir64}});
    // The directory itself is inside .text, because a directory has to be
    // readable through the image's own RVA mapping; the tail after the last
    // section belongs to no section. What the *entries* name is somewhere
    // else entirely.
    {
        std::vector<std::uint8_t> content = text;
        content.resize(0x200, 0);
        std::memcpy(&content[0x80], block.data(), block.size());
        s.section_content = {{0, content}};
    }
    s.reloc_rva = 0x1080;
    s.reloc_size = static_cast<std::uint32_t>(block.size());
    const Built b = build(s);

    AddressSpace space;
    Mapper m(space);
    LoadContext ctx;
    ctx.placement = &m;

    const PeImage p = PeImage::parse(ByteSpan{b.bytes.data(), b.bytes.size()});
    const std::uint64_t kChosenBase = a_free_base(0x10000);
    if (kChosenBase == 0) {
        std::fprintf(stderr, "SKIP gap: no free base\n");
        return;
    }
    const LoadResult r = load_image(
        p, ByteSpan{b.bytes.data(), b.bytes.size()}, kChosenBase, space, ctx);
    check(!r.ok, "gap: the load is refused");
    check(r.error == LoadError::RelocationNotWritable,
          "gap: the refusal names the relocation, not the file's shape");
    if (!r.ok) {
        std::fprintf(stderr, "  %s (%s)\n", load_error_name(r.error),
                     r.detail.c_str());
    }

    // Nothing in the ledger.
    check(space.regions().empty(),
          "gap: the ledger is empty after the refused placement");
    check(space.find(kChosenBase) == nullptr,
          "gap: no region at the image base");

    // And nothing in the kernel. The headers and .text were mapped before the
    // relocation walk found the gap, and if the rollback did not unmap them
    // this child reads a page that a reader of the ledger would say is not
    // there.
    const ChildOutcome gone =
        run_in_child(child_touch, reinterpret_cast<void*>(kChosenBase + 0x1000));
    check(faulted_at(gone, kChosenBase + 0x1000),
          "gap: the regions mapped before the failure were unmapped");
}

// A refused image is refused before anything is mapped, in the placing mode
// too.
//
// The contract is that every decision is made before the first byte is
// placed, and the placing mode is where it is easiest to lose: the plan runs,
// then map_batch, then the writes, and a refactor that moved any of the
// checks after the mapping would still pass every case that loads an image
// that is *valid*. The only cases that catch it are the ones that load an
// image that is not.
void test_a_refused_image_is_never_mapped() {
    // An entry point outside every section: refused by the plan.
    Spec s;
    s.entry = 0x9000; // past .text, in no section at all
    s.sections = {{".text", 0x1000, 0x200, 0x200, kScnRead | kScnExecute}};
    const Built b = build(s);

    AddressSpace space;
    Mapper m(space);
    LoadContext ctx;
    ctx.placement = &m;

    const PeImage p = PeImage::parse(ByteSpan{b.bytes.data(), b.bytes.size()});
    const LoadResult r =
        load_image(p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, space, ctx);
    check(!r.ok, "bad entry: refused");
    check(r.error == LoadError::SectionOutOfRange,
          "bad entry: refused for the entry point, not for the mapping");

    // The syscall counter is the witness that no mapping was attempted. A
    // ledger check alone would pass against a loader that mapped, then
    // unmapped, then reported the refusal -- which is a loader that did the
    // work and undid it, and the difference is one a reader of a
    // constrained system cares about.
    check(m.syscalls_made() == 0,
          "bad entry: no mapping syscall was made at all");
    check(space.regions().empty(), "bad entry: the ledger is untouched");
}

// A second load at the same base is refused, and the first one is intact.
//
// The placing mode's version of a conflict. The batch is all-or-nothing and
// so is map_batch, so the second load's refusal cannot have disturbed the
// first -- but the first's *memory* is the thing that matters here, and a
// rollback that unmapped too much would take it with it.
void test_a_second_placement_at_the_same_base_leaves_the_first_intact() {
    std::vector<std::uint8_t> text(0x200, 0);
    for (std::size_t i = 0; i < text.size(); ++i) {
        text[i] = static_cast<std::uint8_t>((i * 13 + 7) & 0xff);
    }

    Spec s;
    s.entry = 0x1000;
    // A free base, so the second load's conflict is against the *first load's*
    // mapping rather than against something this binary already had there.
    s.base = a_free_base(0x10000);
    s.sections = {{".text", 0x1000, 0x200, 0x200, kScnRead | kScnExecute}};
    s.section_content = {{0, text}};
    const Built b = build(s);
    if (s.base == 0) {
        std::fprintf(stderr, "SKIP twice: no free base\n");
        return;
    }

    AddressSpace space;
    Mapper m(space);
    LoadContext ctx;
    ctx.placement = &m;

    const PeImage p = PeImage::parse(ByteSpan{b.bytes.data(), b.bytes.size()});
    const LoadResult first = load_image(
        p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, space, ctx);
    check(first.ok, "twice: the first load succeeds");
    if (!first.ok) {
        return;
    }

    const std::uint64_t syscalls_after_first = m.syscalls_made();
    const LoadResult second = load_image(
        p, ByteSpan{b.bytes.data(), b.bytes.size()}, 0, space, ctx);
    check(!second.ok, "twice: the second load at the same base is refused");
    check(second.error == LoadError::AddressConflict,
          "twice: the refusal is a conflict");

    // The first load's memory is intact -- read back and compared with the
    // file. This is the assertion a rollback bug would break, and it is the
    // reason the second load's failure has to be checked against the first
    // load's *content* rather than against the region count.
    check(memory_holds_file(b.bytes, b.section_file_offset[0], s.base + 0x1000,
                            text.size()),
          "twice: the first load's section still holds the file's bytes");
    check(space.regions().size() == 2,
          "twice: the second load did not grow the ledger");
    // And the second load's map_batch mapped nothing at all, so nothing had
    // to be undone: the count did not move by more than the rollback of an
    // empty attempt.
    check(m.syscalls_made() == syscalls_after_first,
          "twice: the refused placement made no syscall it had to undo");
}

} // namespace

int main() {
    test_the_headers_are_copied();
    test_section_bytes_are_copied();
    test_a_section_with_no_file_data_is_mapped_and_zero();
    test_relocations_are_written();
    test_every_relocation_type_is_written_in_its_own_form();
    test_the_iat_is_written();
    test_an_unresolved_import_leaves_its_slot_alone();
    test_the_final_protections_are_applied();
    test_a_load_without_a_mapper_maps_nothing();
    test_a_failed_placement_leaves_nothing_behind();
    test_a_refused_image_is_never_mapped();
    test_a_second_placement_at_the_same_base_leaves_the_first_intact();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

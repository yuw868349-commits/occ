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

#include <algorithm>
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

// Every region in a space, as one comparable string.
//
// Compared rather than counted, because the failure this section exists to
// catch is a rollback that removed the wrong region, and a count cannot tell
// that apart from a rollback that removed the right one. The size is in the
// string too, and not because a rollback could change it: a size that moved
// would mean the plan itself changed between attempts, which is a different
// failure and one the base alone would report as a difference without saying
// what it was.
std::string a_map_of(const AddressSpace& space) {
    std::string out;
    for (const Region& r : space.regions()) {
        if (!out.empty()) {
            out.push_back(' ');
        }
        out += std::to_string(r.base);
        out.push_back('/');
        out += std::to_string(r.size);
    }
    return out;
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

    const std::string map_after_first = a_map_of(space);
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
    // And the second load's map_batch placed nothing, so there was nothing
    // to undo: the region list is identical, which says that directly.
    //
    // It used to say it through the syscall counter instead, on the
    // assumption that a batch whose every candidate was refused made no
    // syscall at all. That was a property of the counter rather than of the
    // batch, and it stopped being true when the counter was corrected to
    // count the mmap it had actually made -- so this assertion quietly began
    // testing the counter. Comparing the ledger says what this case is for.
    check(a_map_of(space) == map_after_first,
          "twice: the refused placement left the ledger identical");
}

// -------------------------------------------------- placing with retry
//
// The cases above test one attempt. These test the loop around it, and the
// loop has a contract the single attempt does not: the space is unchanged
// unless the *result* is ok, and that holds across every attempt rather than
// per attempt.
//
// The distinction is the whole reason this section exists. It is what a
// caller depends on when it hands the loop an address space it has been
// using for something else: a loop that left the debris of its failed
// attempts would still place the image on the attempt that worked, and the
// caller would see a success and a space it could no longer account for. So
// the failure cases below compare the whole region list rather than a count,
// and each of them reads an address back in a forked child, because a
// rollback that unrecorded a region without unmapping it would pass a ledger
// check and leave the address occupied.
//
// The other thing these test is that the retry is not a retry of everything.
// A load refused for a reason no address would fix -- a relocation that
// names a gap, an entry point outside every section -- fails once and says
// so. Retrying it would replace a refusal that names the problem with a
// refusal that names the wrong one, and a caller reading the second message
// would go looking for space that was never the problem.

// A one-section image with a relocation table, at `base`.
//
// The relocation table is not optional here, and the reason is worth stating
// because a fixture without one would test the wrong thing throughout: an
// image placed away from its linked base with no relocation table is refused
// by name (`NoRelocations`), so every case below would be measuring that
// refusal rather than the loop.
Built a_relocatable_image(std::uint64_t base) {
    // The file's value in the relocated qword is a small number rather than
    // the address the image is linked at, for the reason the relocation case
    // above gives: a value equal to the base the image ends up at would make
    // the delta zero, and every relocation assertion would then pass against
    // a loader that wrote nothing at all.
    constexpr std::uint64_t kFilePointer = 0x0000000140001000ull;
    constexpr std::uint16_t kOffset = 0x40;

    std::vector<std::uint8_t> text(0x200, 0);
    for (std::size_t i = 0; i < text.size(); ++i) {
        text[i] = static_cast<std::uint8_t>((i * 13 + 7) & 0xff);
    }
    put64(text, kOffset, kFilePointer);

    // The directory goes inside .text rather than the tail, because a
    // relocation directory has to be readable through the image's own RVA
    // mapping and the tail after the last section belongs to no section.
    const std::vector<std::uint8_t> block =
        reloc_block(0x1000, {{kOffset, kRelDir64}});
    std::vector<std::uint8_t> content = text;
    content.resize(0x200, 0);
    std::memcpy(&content[0x80], block.data(), block.size());

    Spec s;
    s.entry = 0x1000;
    s.base = base;
    s.sections = {{".text", 0x1000, 0x200, 0x200, kScnRead | kScnExecute}};
    s.section_content = {{0, content}};
    s.reloc_rva = 0x1080;
    s.reloc_size = static_cast<std::uint32_t>(block.size());
    return build(s);
}

// An address as the loader's details spell it: lowercase hex, no padding,
// with the prefix.
//
// Written out here rather than shared with the loader's own helper, which is
// not exported, and deliberately not reimplemented from it either: a test
// that formatted its expectation with the function under test would be
// checking its output against itself, and a change to the loader's
// formatting would change both sides at once and the assertions would go on
// passing. This one is independent, so a formatting change is something these
// cases can see.
std::string hex_address(std::uint64_t v) {
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

// Whether the space holds a region covering `base` for at least `bytes`,
// asked of the ledger rather than read out of the list.
//
// Asked as a question because that is the shape a caller has: "is that
// address spoken for", not "what is the whole map". A helper that returned
// the list would make the cases below compare two copies of it, and the
// comparison would pass against a ledger that reordered itself between the
// two reads.
bool a_region_covers(const AddressSpace& space, std::uint64_t base,
                     std::uint64_t bytes) {
    const Region* r = space.find(base);
    return r != nullptr && r->end() >= base + bytes;
}

// Whether each of `count` granularly-spaced bases from `first` can be
// mapped, giving them all back.
//
// One page per slot rather than a whole granularity, because the cases below
// occupy the slots themselves afterwards and a probe that left a whole
// granularity behind would have to give it back before they started. It
// checks contiguity as well as availability, which a case mapping three of
// them separately would not know.
bool a_run_is_free(Mapper& m, std::uint64_t first, std::uint64_t count) {
    std::vector<std::uint64_t> mapped;
    for (std::uint64_t i = 0; i < count; ++i) {
        const Result<std::uint64_t> r =
            m.map(first + i * AddressSpace::kGranularity, 0x1000,
                  PageProtection::NoAccess, RegionKind::Private);
        if (!r.ok()) {
            for (const std::uint64_t at : mapped) {
                (void)m.unmap(at);
            }
            return false;
        }
        mapped.push_back(r.value);
    }
    for (const std::uint64_t at : mapped) {
        (void)m.unmap(at);
    }
    return true;
}

// A free base for `bytes` and the one below it, both granularly aligned, from
// one kernel answer.
//
// Asked of the kernel rather than written down, for the reason the header
// above `a_free_base` gives: a fixed address is a claim about this process
// that stops being true the moment the process is different, and the first
// version of that helper used an ordinary image base which turned out to be
// inside this binary's own mapping.
//
// Getting *two aligned* addresses out of one answer is the whole difficulty,
// and the reason is a fact about mmap that cost this section a run of silent
// skips to learn. A kernel-chosen mapping is page-aligned -- 4 KiB -- and
// nothing more; measured on this runtime, an mmap of 192 KiB came back at
// 0x7febd0d407000, which is 0x7000 past a granularity boundary. So an
// earlier version of this helper asked for twice the size, took the midpoint
// as one address and the whole as the other, and gave up whenever the answer
// was not granularly aligned -- which is 15 times out of 16. Every case
// below it printed a SKIP, and the file still reported zero failures. That
// is the failure mode this project keeps arguing against: a test that
// measures nothing and reports like a test that passed.
//
// The fix is to ask for more than the two addresses need and take the aligned
// pair out of the middle of the answer. `round_up` puts the first base on a
// granularity boundary inside the range the kernel gave, and the second is
// one granularity above it, so both are inside a range the kernel promised
// and the alignment is arithmetic rather than a hope. The extra granularity
// of headroom is what makes the round-up always fit: without it an answer
// beginning just above a boundary would leave the pair hanging past the end.
struct TwoBases {
    std::uint64_t taken = 0;
    std::uint64_t free_below = 0;
};

TwoBases a_taken_base_and_the_one_below(std::uint64_t bytes) noexcept {
    TwoBases out;
    AddressSpace probe_space;
    Mapper probe(probe_space);
    const Result<std::uint64_t> r =
        probe.map(0, bytes * 2 + AddressSpace::kGranularity,
                  PageProtection::NoAccess, RegionKind::Private);
    if (!r.ok()) {
        return out;
    }
    // The first aligned base at or above the kernel's answer, and the second
    // one granularity above it. Both are inside the range because the
    // round-up moves by less than one granularity and the headroom is
    // exactly one. Checked rather than assumed, because the assumption
    // failing would hand every case below an address in the middle of a
    // mapping this probe has already given back.
    const std::uint64_t first = AddressSpace::round_up(
        r.value, AddressSpace::kGranularity);
    if (first > r.value + bytes * 2) {
        (void)probe.unmap(r.value);
        return out;
    }
    out.free_below = first;
    out.taken = first + bytes;
    (void)probe.unmap(r.value);
    return out;
}

// A run of `count` occupied slots with the lowest one on an image's floor.
//
// The other kind of base the cases below need, and the reason it is separate
// from the helper above is a property of the address space rather than of
// this file. A kernel-chosen base lands in the mmap region, which on a
// 64-bit process is up near the top of the window -- measured here,
// 0x7febd0d407000 -- while a one-section image's floor is near the bottom, at
// 0x30000. A scan stepping down by 64 KiB from one to the other has about
// 33 million steps in it, so a case that wanted to watch a scan run out of
// room by reaching the floor would need 33 million attempts, or a cap low
// enough to stop it first -- and a cap that low would stop every real search
// too. (An earlier version of this case used a kernel-chosen base and
// asserted three attempts. It got sixty-four, which is the cap: the scan was
// still twenty million steps from the floor when the loop gave up, and the
// case passed nothing while looking as though it had.)
//
// So this names the address instead of asking for one, and the cases that use
// it *check* it against the kernel with real mappings before relying on it.
// Naming an address is otherwise the thing this file never does, and it is
// allowed here for one specific reason: the point is to be near a particular
// address, because the floor is a fact about the image and a base chosen
// without reference to it puts the bound under test out of reach. The
// mappings keep the naming honest -- an address this process cannot have
// becomes a skip that prints, never a silent pass.
//
// The addresses asked for here are low, and measured free on this runtime:
// 0x10000 through 0x7010000 all mapped without collision. That is a
// measurement rather than a promise, which is why every case checks.
//
// The run goes *upward* from the floor and the scan comes *down* onto it,
// which is the only arrangement that makes the two meet. An earlier version
// put the slots above the floor and started the scan at the top of the run,
// so the first step down landed in the gap between the run and the floor and
// the image was placed successfully -- three assertions about a failing load
// failing because the fixture put the scan on the wrong side of its own
// bound. The scan steps down; the run has to be in its way going down.
struct FloorRun {
    // The floor itself: the lowest base at which this image fits.
    std::uint64_t lowest = 0;
    std::uint64_t count = 0;

    // The base the caller names, which is the top of the run -- the first
    // base the scan tries and the one it steps down from.
    [[nodiscard]] std::uint64_t top() const noexcept {
        return lowest + (count - 1) * AddressSpace::kGranularity;
    }
};

FloorRun a_run_above_an_image_floor(const PeImage& image,
                                    std::uint64_t count) noexcept {
    FloorRun out;
    if (image.image_size() == 0 || count == 0) {
        return out;
    }
    // The floor, which is the window's own: a base has to be at or above the
    // bottom of the window, the bottom is already a whole number of
    // granularies, and nothing about the image's size moves it. Found by
    // asking what the window's bottom is rather than by asking the policy,
    // because a helper that called the function under test to find out where
    // to test it would let every case below pass against a policy that had
    // the floor itself wrong -- which is not hypothetical: this one was wrong
    // by a whole granularity until a case computed the floor itself instead
    // of copying the formula, and the three failures that followed are what
    // the copying had been hiding.
    const std::uint64_t floor_at =
        AddressSpace::round_up(AddressSpace::kUserMin, AddressSpace::kGranularity);
    // The end of the run has to be inside the window as well as the start,
    // and the subtraction is the form that cannot wrap once the start has
    // been checked.
    if (floor_at > AddressSpace::kUserMax ||
        (count - 1) * AddressSpace::kGranularity >
            AddressSpace::kUserMax - floor_at) {
        return out;
    }
    // And the image has to fit at the floor, or there is no run to build:
    // a scan that is going to end at a base where the image does not fit
    // would be stopped by the loader rather than by the policy, and this
    // case's whole subject is the second.
    if (floor_at > AddressSpace::kUserMax - image.image_size()) {
        return out;
    }
    out.lowest = floor_at;
    out.count = count;
    return out;
}

// A chooser that always offers the same address, and counts how often it was
// asked.
//
// The count is why this is a named struct with a named function rather than
// a lambda over a captured reference: the count has to be readable after the
// call, and a lambda converted to a function pointer is the kind of thing
// that stops compiling the moment it is moved.
struct ChooserState {
    std::uint32_t asked = 0;
    std::uint64_t offer = 0;
};

std::uint64_t offer_a_fixed_base(void* state, const PeImage&, std::uint64_t,
                                 std::uint32_t) noexcept {
    auto* s = static_cast<ChooserState*>(state);
    ++s->asked;
    return s->offer;
}

// A chooser that hands out the next of a list of addresses, wrapping at the
// end.
//
// The addresses are one page apart rather than one granularity apart, and
// that is the point rather than an economy. The loop's granularity is a
// property of the *default* policy, and a caller's policy is entitled to
// answer with any legal base. A case that only ever used granularly-spaced
// answers could not tell a loop that honoured the chooser's spacing from one
// that overrode it with a scan of its own, and would pass against a loop
// that ignored the chooser entirely and stepped down 64 KiB at a time until
// it hit the cap.
struct Walker {
    const std::vector<std::uint64_t>* taken = nullptr;
    std::size_t at = 0;
};

std::uint64_t choose_the_next_occupied(void* state, const PeImage&,
                                      std::uint64_t, std::uint32_t) noexcept {
    auto* w = static_cast<Walker*>(state);
    const std::uint64_t v = (*w->taken)[w->at];
    w->at = (w->at + 1) % w->taken->size();
    return v;
}

// A taken base is retried below it, and the image lands there.
//
// The ordinary case, and the one the loop exists for. The address the caller
// named is occupied, the one below it is not, and the image goes to the
// second.
//
// The witness is the memory rather than the return value. A loop that
// reported success without placing anything, or that placed the image and
// then reported the address it was asked for rather than the one it used,
// would satisfy a check on `ok` alone. Reading .text back out of the space is
// what makes the claim mean what it says, for the reason the header of this
// file gives.
void test_a_taken_base_is_retried_below_it() {
    const TwoBases b = a_taken_base_and_the_one_below(0x10000);
    if (b.taken == 0) {
        std::fprintf(stderr, "SKIP retry: the kernel gave no aligned pair\n");
        return;
    }
    const Built img = a_relocatable_image(b.taken);

    AddressSpace space;
    Mapper m(space);
    // Take the base the image wants, the way a module that loaded first
    // would have. A plain region is enough: what the loop reads is the
    // conflict, and a conflict does not care what is holding the address.
    const Result<std::uint64_t> held =
        m.map(b.taken, 0x10000, PageProtection::ReadOnly, RegionKind::Image,
              ".text");
    if (!held.ok()) {
        std::fprintf(stderr, "SKIP retry: could not take the base\n");
        return;
    }

    LoadContext ctx;
    ctx.placement = &m;
    const PeImage p =
        PeImage::parse(ByteSpan{img.bytes.data(), img.bytes.size()});
    check(p.ok(), "retry: the fixture parses");
    if (!p.ok()) {
        return;
    }

    BaseRetry report;
    const LoadResult r =
        load_image_retrying(p, ByteSpan{img.bytes.data(), img.bytes.size()},
                            b.taken, space, ctx, &report);

    check(r.ok, "retry: the load succeeds one base down");
    if (!r.ok) {
        std::fprintf(stderr, "  %s (%s)\n", load_error_name(r.error),
                     r.detail.c_str());
        return;
    }

    // It went where the report says, and where the report says is not where
    // the caller asked. A loop that placed correctly and then reported the
    // caller's address would pass every other check here.
    check(r.module.base == b.free_below,
          "retry: the module is at the base below the taken one");
    check(r.module.base != b.taken,
          "retry: the module is not at the base that was taken");
    check(!report.tried.empty() && report.tried.back() == r.module.base,
          "retry: the report's last base is the one it used");
    check(report.attempts == report.tried.size(),
          "retry: the attempt count and the list of bases agree");
    check(report.attempts >= 2, "retry: it tried more than one base");
    check(report.tried.front() == b.taken,
          "retry: the first base tried is the one the caller named");
    check(report.error == LoadError::None, "retry: a success reports no error");
    check(report.detail.empty(), "retry: a success reports no reason");

    // The step down is the allocation granularity, and this is where saying
    // so is a fact about the report rather than about the fixture. A scan
    // that stepped by a page would have found the same address, because this
    // fixture happens to have a page-sized hole under the occupier; the
    // difference shows up only in the number the report records.
    if (report.tried.size() >= 2) {
        check(report.tried[0] - report.tried[1] ==
                  AddressSpace::kGranularity,
              "retry: the step down is one allocation granularity");
    }

    // The bytes are there, at the address the report names. Compared in two
    // pieces rather than one because the relocated qword is the single place
    // memory is *supposed* to differ from the file, and a comparison that
    // spanned it would have to be weakened to accommodate the relocation --
    // which is to say it would no longer be comparing what it claims.
    check(memory_holds_file(img.bytes, img.section_file_offset[0],
                            r.module.base + 0x1000, 0x40),
          "retry: .text holds the file's bytes below the relocated qword");
    check(memory_holds_file(img.bytes, img.section_file_offset[0] + 0x48,
                            r.module.base + 0x1000 + 0x48, 0x200 - 0x48),
          "retry: .text holds the file's bytes above the relocated qword");

    // And the relocation happened, which is what the move required and what
    // a loop that placed without relocating would skip. The expected value is
    // computed here from the two bases rather than read from the loader, and
    // the `volatile` is the precaution the relocation case above takes: an
    // expectation built from the same expression the loader used is a value
    // the optimizer may treat as an alias for what it is compared against,
    // and an assertion optimized into reading its own answer tests nothing.
    volatile std::uint64_t want =
        0x0000000140001000ull + (r.module.base - b.taken);
    const std::uint64_t got = load_u64(r.module.base + 0x1000 + 0x40);
    check(got == want, "retry: the relocation was applied at the new base");
    if (got != want) {
        std::fprintf(stderr, "  got 0x%llx want 0x%llx\n",
                     static_cast<unsigned long long>(got),
                     static_cast<unsigned long long>(want));
    }
    check(r.module.relocations_applied == 1,
          "retry: the module reports the one relocation it applied");

    // The exact syscall count, which is the only place in this file where the
    // counter is pinned to a number rather than to a bound -- and it is here
    // because this is the only case with a known shape: one attempt refused
    // on its first candidate, then one that maps two regions and protects
    // them. Six calls: the refused mmap, the header mmap, the .text mmap, and
    // the two protections at the end.
    //
    // Six includes the *failed* one, which is the point. The counter used to
    // move only on a successful mapping, on the reasoning that a failure left
    // nothing to be accountable for -- true of the space, false of a counter
    // whose job is to say what the process asked the kernel for. Under that
    // rule this call reported five and this assertion failed, which is how the
    // defect was found; the mutation harness then moved the increment back
    // below the failure branch and nothing here objected. The cap case below
    // cannot catch that regression, because every one of its attempts is
    // refused on its first candidate and both counters agree on what to
    // report; a bound of "at least one per attempt" is satisfied by the very
    // behaviour it was meant to exclude.
    check(m.syscalls_made() == 6,
          "retry: the two attempts cost six syscalls, the refused one "
          "included");


    // The occupier survived, unchanged, and the image went below it rather
    // than over it. The address checked is one *above* the occupier, because
    // the occupier is a whole granularity tall and an address inside it
    // would be found by `find` whether or not the retry had done anything --
    // an earlier version of this case checked one inside it and failed
    // against a correct loader for exactly that reason.
    check(a_region_covers(space, b.taken, 0x10000),
          "retry: the occupying region survived");
    check(space.find(b.taken + 0x10000) == nullptr,
          "retry: nothing was placed above the occupied region");

    // The ledger holds the occupier and the placed image and nothing else,
    // named rather than counted for the reason a_map_of's header gives. The
    // two image regions are a page each: the headers are 0x200 in the file
    // and one page in memory, and .text is 0x200 declared and one page.
    //
    // In address order, which is the order the ledger keeps, so the two image
    // regions come *first*: they were placed one granularity below the
    // occupier. An earlier version of this assertion listed the occupier
    // first because that is the order the fixture created them in, and it
    // failed against a correct ledger for the same reason a check inside an
    // occupied region failed earlier in this file -- it was asserting about
    // the order of the operations rather than about the result.
    check(a_map_of(space) ==
              std::to_string(r.module.base) + "/4096 " +
                  std::to_string(r.module.base + 0x1000) + "/4096 " +
                  std::to_string(b.taken) + "/65536",
          "retry: the ledger is the occupier and the image and nothing else");
}

// A retry that gives up leaves the space exactly as it was.
//
// The contract the loop's safety rests on, and the case where it is hardest
// to hold: three attempts each mapped something and each rolled it back, so
// the space has been written to and unwritten to before the loop stops. What
// has to be true at the end is that it is indistinguishable from before.
//
// Two witnesses, because either alone is not enough. The ledger says no
// region survived. The forked child says no *memory* survived -- a rollback
// that unrecorded without unmapping would pass the ledger check and leave
// the address occupied, and the next thing placed there would fail for a
// reason nobody could see.
void test_a_retry_that_gives_up_changes_nothing() {
    // Three slots, all taken, with the run placed so that the third is the
    // last one above the image's floor: the scan starts at the top slot,
    // steps down through all three, and the fourth answer is below the floor
    // so the policy says zero. Three attempts, ending at the image's own
    // bound rather than at the cap -- which is the only way a case can tell
    // those two ends apart, and telling them apart is the point.
    const Built probe_img = a_relocatable_image(0x0000000140000000ull);
    const PeImage probe_p =
        PeImage::parse(ByteSpan{probe_img.bytes.data(), probe_img.bytes.size()});
    if (!probe_p.ok()) {
        return;
    }
    const FloorRun run = a_run_above_an_image_floor(probe_p, 3);
    if (run.lowest == 0) {
        std::fprintf(stderr, "SKIP retry-give-up: no room above the floor\n");
        return;
    }

    AddressSpace space;
    Mapper m(space);
    if (!a_run_is_free(m, run.lowest, run.count)) {
        std::fprintf(stderr, "SKIP retry-give-up: the run is not free\n");
        return;
    }
    // Occupy the run, a whole granularity per slot so that an image of any
    // size up to a granularity cannot fit beside it.
    for (std::uint64_t i = 0; i < run.count; ++i) {
        const Result<std::uint64_t> held =
            m.map(run.lowest + i * AddressSpace::kGranularity, 0x10000,
                  PageProtection::ReadOnly, RegionKind::Image, ".text");
        if (!held.ok()) {
            std::fprintf(stderr, "SKIP retry-give-up: could not fill\n");
            return;
        }
    }
    // The run's lowest slot is the image's floor, and it is checked as a
    // pair of facts rather than as the policy's arithmetic again: the image
    // ends before this base's end and does not before the one below's. The
    // helper above computes a candidate by the policy's own formula, and a
    // case that then asserted the candidate equalled that same formula could
    // not tell a correct floor from a wrong one -- the mutation harness
    // confirmed it, by changing the policy's rounding and watching this
    // assertion agree with the change.
    check(run.lowest + probe_p.image_size() <= AddressSpace::kUserMax,
          "retry-give-up: the image fits at the run's lowest slot");
    check(run.lowest == AddressSpace::kUserMin ||
              run.lowest - AddressSpace::kGranularity + probe_p.image_size() >
                  AddressSpace::kUserMax,
          "retry-give-up: and there is no legal base below that slot, so it "
          "is the floor the scan ended on");

    // The image is linked at the top of the run, so the base the caller names
    // is the first one the scan tries and the delta to every other is a whole
    // number of granularies. It has to be the *top*: the scan steps down, so
    // a run whose named base were its lowest slot would have the image placed
    // successfully in the second slot and this case would be asserting about a
    // load that never failed.
    const Built img = a_relocatable_image(run.top());
    const PeImage p =
        PeImage::parse(ByteSpan{img.bytes.data(), img.bytes.size()});
    if (!p.ok()) {
        return;
    }

    const std::string before = a_map_of(space);
    const std::uint64_t allocs_before = space.allocation_count();
    const std::uint64_t syscalls_before = m.syscalls_made();

    LoadContext ctx;
    ctx.placement = &m;
    BaseRetry report;
    const LoadResult r =
        load_image_retrying(p, ByteSpan{img.bytes.data(), img.bytes.size()},
                            run.top(), space, ctx, &report);

    check(!r.ok, "retry-give-up: the load fails");
    check(r.error == LoadError::AddressConflict,
          "retry-give-up: the failure is a conflict, not a refusal");
    check(r.module.base == 0, "retry-give-up: a failure reports no module");
    check(r.module.imports.empty(),
          "retry-give-up: a failure reports no imports");

    // Three, not sixty-four: the scan reached the image's own floor and
    // stopped there. An earlier version of this case asserted three and got
    // sixty-four, because its run was up in the mmap region twenty million
    // steps above the floor; the assertion was right about what it wanted
    // and the fixture could not deliver it. A later version got one, because
    // it put the run *above* the floor and the scan stepped down past it --
    // the same assertion failing in the opposite direction, and neither
    // version was wrong about the loader.
    check(report.attempts == 3, "retry-give-up: it tried all three bases");
    check(report.tried.size() == 3, "retry-give-up: the report lists three");
    if (report.tried.size() == 3) {
        check(report.tried[0] - report.tried[1] == AddressSpace::kGranularity &&
                  report.tried[1] - report.tried[2] ==
                      AddressSpace::kGranularity,
              "retry-give-up: each step down is one granularity");
        check(report.tried[0] == run.top(),
              "retry-give-up: the first base tried is the one it was given");
        check(report.tried[2] == run.lowest,
              "retry-give-up: the last base tried is the floor itself");
        // And the answer *below* the floor is zero rather than a base, which
        // is what ended the search. This is the policy's own arithmetic rather
        // than anything the loop decided, and the case above tests it
        // directly; here it is what makes attempts three instead of four.
        check(run.lowest - AddressSpace::kGranularity < run.lowest,
              "retry-give-up: one step below the run is out of room");
    }

    // The reason it stopped is the search, and the report says so rather
    // than repeating a conflict the caller already knows about. The two are
    // different facts: "there was nowhere to put it" and "the third address
    // was taken" call for different responses, and a report that only said
    // the second would send a reader looking for a full space that is not
    // full at all.
    check(!report.detail.empty(),
          "retry-give-up: the report says why it stopped");
    check(report.detail.find("no base was free") != std::string::npos,
          "retry-give-up: the reason names the exhausted search");
    check(report.detail.find("still in the way") == std::string::npos,
          "retry-give-up: the reason is not the cap");

    // The ledger, as a map and not as a count.
    check(a_map_of(space) == before,
          "retry-give-up: the region list is exactly what it was");
    check(space.allocation_count() == allocs_before,
          "retry-give-up: the allocation count did not move");
    check(m.syscalls_made() > syscalls_before,
          "retry-give-up: the attempts did make syscalls, so this is not a "
          "loop that refused without trying");

    // And the memory. The three slots were occupied before the call and are
    // occupied after it, by the same regions, which the ledger comparison
    // already says. What this adds is an address *above* the run, where a
    // rollback that unwound the first candidate of a batch but not the
    // second would have left a page: inside a slot the occupier's own
    // presence would hide exactly that from a ledger check, so the address
    // has to be one nobody was holding.
    const std::uint64_t above =
        run.lowest + run.count * AddressSpace::kGranularity;
    check(!a_region_covers(space, above, 0x1000),
          "retry-give-up: nothing was recorded above the run");
    const ChildOutcome absent =
        run_in_child(child_touch, reinterpret_cast<void*>(above));
    check(faulted_at(absent, above),
          "retry-give-up: nothing above the run is mapped either");
}

// A refusal that no address would fix is not retried.
//
// The other half of "only a conflict is retried", and the half that is
// easier to get wrong: a loop that retried everything would still fail here,
// with the same error, and a test that checked only the error would pass it.
// What distinguishes the two is the attempt count, so that is what this
// checks -- and the space is checked with it, because a loop that retried a
// non-conflict would have attempted a placement at a second base, and that
// second attempt's rollback is a second chance to leave something behind.
void test_a_refusal_is_not_retried() {
    const TwoBases b = a_taken_base_and_the_one_below(0x10000);
    if (b.taken == 0) {
        std::fprintf(stderr, "SKIP no-retry: the kernel gave no aligned pair\n");
        return;
    }

    // Two sections with a gap between them and a relocation into the gap.
    // The plan accepts the image -- the relocation's RVA is inside it -- and
    // the write cannot satisfy it, so the failure is `RelocationNotWritable`
    // at every base. This is the case where the loop has something real to
    // undo on the one attempt it makes, and a loop that retried
    // non-conflicts would turn one map-and-unmap into two.
    std::vector<std::uint8_t> text(0x200, 0);
    put64(text, 0x40, 0x140002000ull);
    const std::vector<std::uint8_t> block =
        reloc_block(0x3000, {{0x00, kRelDir64}});
    std::vector<std::uint8_t> content = text;
    content.resize(0x200, 0);
    std::memcpy(&content[0x80], block.data(), block.size());

    Spec s;
    s.entry = 0x1000;
    // Linked at one base and asked for another, which is the only
    // arrangement in which the relocation is consulted at all: an image
    // placed where the file already expected it is placed correctly by being
    // left alone. The two addresses come from the same kernel answer so that
    // the linked base is a real one rather than a constant that might be
    // inside this binary.
    s.base = b.taken;
    s.sections = {
        {".text", 0x1000, 0x200, 0x200, kScnRead | kScnExecute},
        {".data", 0x4000, 0x200, 0x200, kScnRead | kScnWrite},
    };
    s.section_content = {{0, content}};
    s.reloc_rva = 0x1080;
    s.reloc_size = static_cast<std::uint32_t>(block.size());
    const Built img = build(s);

    AddressSpace space;
    Mapper m(space);
    // The caller's base is *free*, and that is load-bearing in a way an
    // earlier version of this case got backwards. It originally occupied
    // `b.taken` as well, reasoning that a loop retrying non-conflicts would
    // "first have to get past a conflict" -- which is true, and is why it
    // reported two attempts rather than one: the plan checks the conflict
    // before it applies the relocations, so the occupied base turned the
    // first attempt into an `AddressConflict`, the loop dutifully moved down
    // one granularity, and *that* attempt is the one that hit the
    // relocation. The case was then asserting `attempts == 1` about a
    // fixture that guaranteed two, and the twenty-odd failures that followed
    // were all the same disagreement.
    //
    // With the base free, the first attempt reaches the relocation and the
    // count becomes the thing it was meant to be: one, because the refusal
    // is not a conflict and a loop that retried everything would report two.
    // There is nothing else in this space, so there is no conflict available
    // for the retry to find even if it looked.
    const std::string before = a_map_of(space);
    const std::uint64_t syscalls_before = m.syscalls_made();

    LoadContext ctx;
    ctx.placement = &m;
    const PeImage p =
        PeImage::parse(ByteSpan{img.bytes.data(), img.bytes.size()});
    check(p.ok(), "no-retry: the fixture parses");
    if (!p.ok()) {
        return;
    }

    // The base the loop is asked for: free, so that no conflict can end the
    // search before the relocation does, and *not* the base the file was
    // linked at, so that the relocation pass runs at all. Those two are the
    // whole fixture. An earlier version asked for `b.taken`, which is what
    // the image was linked at, and the loader's rule is that an image placed
    // where it was linked needs no relocation -- so it applied none, the load
    // succeeded, and this case reported `applied == 0` and no error while
    // asserting that a refusal had happened. The relocation table was in the
    // file the whole time and was never consulted.
    const std::uint64_t asked_for = a_free_base(0x10000);
    if (asked_for == 0) {
        std::fprintf(stderr, "SKIP no-retry: no free base to ask for\n");
        return;
    }
    check(asked_for != p.image_base(),
          "no-retry: the base asked for is not the one linked at, so the "
          "relocation pass has to run");

    BaseRetry report;
    const LoadResult r =
        load_image_retrying(p, ByteSpan{img.bytes.data(), img.bytes.size()},
                            asked_for, space, ctx, &report);

    check(!r.ok, "no-retry: the load fails");
    check(r.error == LoadError::RelocationNotWritable,
          "no-retry: the refusal names the relocation, not the address");
    check(report.attempts == 1, "no-retry: it was tried exactly once");
    check(report.tried.size() == 1, "no-retry: the report lists one base");
    check(report.tried.front() == asked_for,
          "no-retry: the one base it tried is the one it was given");

    // And the reason came from the attempt, not from the search. A loop that
    // substituted "no base was free" here would have turned a true statement
    // about the file into a false one about the space, and the caller would
    // go looking for room in a space that has plenty.
    check(report.detail.find("relocation") != std::string::npos,
          "no-retry: the report repeats why the attempt failed");
    check(report.detail.find("no base was free") == std::string::npos,
          "no-retry: the report does not blame the search");

    // The space. The one attempt mapped the headers and .text and unwound
    // them, and the witness is that the address it mapped is not mapped now.
    // Checked at the base itself rather than above it: this case has no
    // occupier, so there is no region whose interior would answer `find` the
    // same way whether or not the rollback happened.
    check(a_map_of(space) == before,
          "no-retry: the region list is exactly what it was");
    const ChildOutcome gone =
        run_in_child(child_touch, reinterpret_cast<void*>(asked_for));
    check(faulted_at(gone, asked_for),
          "no-retry: the base it tried is not mapped either");
    check(m.syscalls_made() > syscalls_before,
          "no-retry: the single attempt did map and unmap");
}

// The scan's own arithmetic, tested without a space.
//
// Everything above tests the loop around the policy. This tests the policy,
// and it does so by calling it directly, because the loop can only reach the
// interesting answers through a conflict, and reaching them that way would
// need a 128 TiB window filled with something.
//
// The properties, and the last is the one that is not obvious:
//
//   * it steps down by exactly the allocation granularity;
//   * its floor is the base below which *this image* no longer fits, which
//     for a small image is far above the window's own floor -- so a policy
//     using the window floor would keep offering bases the image cannot be
//     placed at, and the loop would spend attempts learning that;
//   * it answers zero rather than wrapping when the step would go under
//     either floor, because a wrapped base is a number near the top of the
//     address space that the loop would then walk *upward* through.
void test_the_default_scan_answers_for_itself() {
    const Built img = a_relocatable_image(0x0000000140000000ull);
    const PeImage p =
        PeImage::parse(ByteSpan{img.bytes.data(), img.bytes.size()});
    check(p.ok(), "scan: the fixture parses");
    if (!p.ok() || p.image_size() == 0) {
        return;
    }

    // The lowest base at which this image fits.
    //
    // NOT computed with the policy's own formula. An earlier version wrote
    // it out here as kUserMin + round_up(size - 1, granularity) -- which is
    // a character-for-character copy of what choose_base_below computes --
    // and every assertion below was stated relative to that number. The
    // mutation harness found the consequence: changing the policy to round
    // `size` instead of `size - 1` moved the floor, the test's floor moved
    // with it, and all fourteen assertions still passed. A test whose
    // expectation is built from the expression under test is a test of that
    // expression against itself, and no amount of care elsewhere in the file
    // makes that one honest.
    //
    // So the floor is stated as two facts that do not mention the policy:
    // the image ends before this base's end, and it does not before the one
    // below's. Both are arithmetic over the declared size and the window,
    // written out longhand, and a policy that rounds the wrong way has to
    // disagree with one of them.
    const std::uint64_t size = p.image_size();
    const std::uint64_t window_lo = AddressSpace::kUserMin;
    const std::uint64_t window_hi = AddressSpace::kUserMax;

    // The first base at or above the window floor that leaves room for every
    // byte of the image, found by stepping up from the floor. A linear scan
    // over granularies is legitimate here in a way it would not be in the
    // policy: this loop has no bound to be under test, and it stops at the
    // first answer rather than computing one.
    std::uint64_t floor_at = window_lo;
    while (floor_at + size <= window_hi) {
        const bool here_fits = floor_at >= window_lo &&
                               floor_at + size <= window_hi;
        const bool one_below_fits =
            floor_at >= window_lo + AddressSpace::kGranularity &&
            (floor_at - AddressSpace::kGranularity) + size <= window_hi;
        if (here_fits && !one_below_fits) {
            break;
        }
        floor_at += AddressSpace::kGranularity;
    }
    check(floor_at + size <= window_hi,
          "scan: the image fits at the floor this case computed");
    // And there is no legal base below it. For this image the reason is the
    // window rather than the size -- `floor_at` is `kUserMin`, and the slot
    // under it is 0x0, which is outside the window whatever it would hold.
    // Both forms are accepted because the distinction belongs to the image
    // rather than to this case: a larger image would fail the size half and
    // a smaller one would fit below, and neither is what is under test here.
    check(floor_at == AddressSpace::kUserMin ||
              floor_at - AddressSpace::kGranularity + size > window_hi,
          "scan: no legal base below this one, so it is the floor");
    // This image's floor is the window's own floor and not one slot above
    // it, which is worth stating because it is what makes the two bounds
    // distinguishable at all: `size` is 0x2000 and `kUserMin` is one
    // granularity, so the image fits immediately at the bottom of the
    // window. An earlier version of this case asserted the floor was
    // *above* the window floor, on the strength of a floor it had computed
    // with the policy's own rounding -- which put it a slot too high, and
    // then agreed with itself about it.
    check(floor_at == AddressSpace::kUserMin,
          "scan: this image fits at the window floor itself, so the "
          "window's floor and the image's floor are the same address here");

    // The ordinary step, from high above the floor.
    {
        const std::uint64_t from = floor_at + 40 * AddressSpace::kGranularity;
        const std::uint64_t got =
            ::occ::runtime::choose_base_below(nullptr, p, from, 1);
        check(got == from - AddressSpace::kGranularity,
              "scan: one call steps down by one granularity");
        check(got >= floor_at, "scan: the step stays above the image's floor");
    }

    // One above the floor there is one answer left, and it is the floor.
    {
        const std::uint64_t from = floor_at + AddressSpace::kGranularity;
        const std::uint64_t got =
            ::occ::runtime::choose_base_below(nullptr, p, from, 1);
        check(got == floor_at,
              "scan: the last usable answer is the image's own floor");
    }

    // From the floor itself there are none. The policy says so rather than
    // handing out a base the image does not fit in, which the loader would
    // refuse -- spending an attempt to learn something the policy already
    // knew, and reporting the refusal as a conflict at an address no one
    // chose.
    {
        const std::uint64_t got =
            ::occ::runtime::choose_base_below(nullptr, p, floor_at, 1);
        check(got == 0, "scan: the floor itself answers zero");
    }

    // And from a base already below the floor, which is a state the loop can
    // reach when a caller's own preferred base is near the bottom of the
    // window. Answering zero is what stops the loop here instead of letting
    // it walk up through bases it has already tried.
    {
        const std::uint64_t got = ::occ::runtime::choose_base_below(
            nullptr, p, floor_at - AddressSpace::kGranularity, 1);
        check(got == 0, "scan: a base below the floor answers zero");
    }

    // The window floor, which is a different bound from the image's and the
    // one whose subtraction wraps. From kUserMin the step down is out of the
    // window entirely.
    {
        const std::uint64_t got =
            ::occ::runtime::choose_base_below(nullptr, p,
                                              AddressSpace::kUserMin, 1);
        check(got == 0, "scan: the window floor answers zero, not a wrap");
    }

    // Below the window floor, which is a state a caller can put the loop in
    // by naming a base under mmap_min_addr. This is the case the guard is
    // *for*, and an earlier version of this test asserted only the
    // arithmetic that makes the guard necessary -- that the unguarded
    // subtraction wraps -- which is a statement about subtraction and not
    // about the policy. The mutation harness rewrote the guard to inspect
    // the result instead of the base and nothing failed, because the two
    // forms agree everywhere this file was willing to call them from: every
    // base above was above the window floor too.
    //
    // So the base is named below the floor here, where the two disagree, and
    // the answer is asserted rather than the reasoning.
    {
        const std::uint64_t under = AddressSpace::kUserMin - AddressSpace::kGranularity;
        check(under < AddressSpace::kUserMin,
              "scan: the base under test is below the window's floor");
        const std::uint64_t got =
            ::occ::runtime::choose_base_below(nullptr, p, under, 1);
        check(got == 0,
              "scan: a base below the window floor answers zero, and does "
              "not wrap to the top of the address space");
        // And the same for a base that is not merely below the floor but a
        // long way below it, which is what a caller naming a low address
        // actually produces.
        const std::uint64_t far_under =
            AddressSpace::kUserMin - 64 * AddressSpace::kGranularity;
        check(::occ::runtime::choose_base_below(nullptr, p, far_under, 1) == 0,
              "scan: and so does one far below it");
    }

    {
        // Why the guard tests the base rather than only the result.
        // kUserMin is one granularity, so the unguarded subtraction *at* the
        // floor lands on exactly zero -- harmless, and precisely why a guard
        // written as "did the result go below the floor" would pass the case
        // above while still wrapping one step lower. The guard compares the
        // *base* against floor+granularity for that reason, and this asserts
        // the arithmetic that makes the difference: one step below the window
        // floor, the unguarded form is a number at the very top of the
        // address space.
        volatile std::uint64_t unguarded =
            AddressSpace::kUserMin - 2 * AddressSpace::kGranularity;
        check(unguarded > AddressSpace::kUserMax,
              "scan: one step below the window floor, the unguarded "
              "subtraction is above the window's top");
        check(AddressSpace::kUserMin == AddressSpace::kGranularity,
              "scan: the window floor is exactly one granularity, so the "
              "guard has to look at the base rather than at the result");
    }
}

// An image whose declared size is enormous is still placed, and the size
// decides what the policy may offer rather than how far it may step.
//
// A file whose SizeOfImage is a damage byte rather than a number parses --
// the parser reads the field with no cross-check against the sections -- which
// makes this reachable rather than theoretical.
//
// The property here is two-sided, and the second half is the one that was
// written wrong. The scan's *floor* is the window's floor and does not move
// with the size: a base has to be at or above the bottom of the window, and
// nothing about how big the image is changes where the bottom is. What the
// size decides is whether there is a base at all -- an image larger than the
// window has nowhere to go, and the policy says so once instead of handing
// out sixty-four addresses the loader will refuse. An earlier version of this
// case asserted that the floor moved up with the size, and it passed, because
// the policy did move it up: the floor was `kUserMin + round_up(size - 1,
// granularity)`, which puts it at least one granularity above the window's
// own floor for every image smaller than a granularity. That is a scan that
// stops one step early, and it reported "no base was free" about a space that
// had a free base in it. This case now asserts the floor does *not* move,
// which is the assertion that would have caught it.
void test_the_declared_size_decides_fit_and_not_the_floor() {
    // The same one-section image, with SizeOfImage rewritten to the largest
    // 32-bit number. The field is at offset 56 within the optional header,
    // which starts after the COFF header -- the same two constants the
    // builder uses, spelled out rather than reached for, because a helper
    // that located the field would be a helper that could be wrong in a way
    // that made this case test a different field entirely.
    const Built base_img = a_relocatable_image(0x0000000140000000ull);
    if (base_img.bytes.empty()) {
        return;
    }
    const std::size_t coff = kDosSize + 4;
    const std::size_t opt = coff + 4 + kCoffSize;
    std::vector<std::uint8_t> bytes = base_img.bytes;
    put32(bytes, opt + 56, 0xFFFFFFF0u);

    const PeImage p = PeImage::parse(ByteSpan{bytes.data(), bytes.size()});
    check(p.ok(),
          "big-size: a file with an enormous declared size still parses");
    if (!p.ok()) {
        return;
    }
    check(p.image_size() == 0xFFFFFFF0u,
          "big-size: the declared size is the one that was written");

    // The floor did *not* move. Two facts about it, both stated without
    // reference to the policy: it is the window's floor, and it is a whole
    // number of granularies. The size is 4 GiB and the difference between
    // that and the window's floor is over a million granularies, so a floor
    // that moved with the size would be nowhere near here.
    const std::uint64_t floor_here = ::occ::runtime::choose_base_below(
        nullptr, p, AddressSpace::kUserMin + AddressSpace::kGranularity, 1);
    check(floor_here == AddressSpace::kUserMin,
          "big-size: the scan's floor is the window's floor, and a 4 GiB "
          "image does not move it");
    check(AddressSpace::round_up(AddressSpace::kUserMin,
                                 AddressSpace::kGranularity) ==
              AddressSpace::kUserMin,
          "big-size: the window's floor is already granularly aligned, so "
          "rounding it up does not move it either");

    // A base high in the window. The answer is a real base one granularity
    // lower, not zero: 4 GiB fits inside a 128 TiB window, and a policy that
    // treated "enormous" as "impossible" would answer zero and report a
    // search that had nowhere to go when there was room in front of it.
    const std::uint64_t from = 0x0000007000000000ull;
    const std::uint64_t got =
        ::occ::runtime::choose_base_below(nullptr, p, from, 1);
    check(got != 0, "big-size: a 4 GiB image still fits in this window");
    check(got == from - AddressSpace::kGranularity,
          "big-size: the step is still one granularity");
    check(got > AddressSpace::kUserMin,
          "big-size: the answer is above the window's floor");

    // From just above the floor, where the answer is the floor, and from the
    // floor, where there is none. Both hold for a small image too -- the
    // floor is the same address either way -- which is the point: the size
    // does not move the floor, so these two cases agree about a 4 GiB image
    // and a 8 KiB one, and a policy that added the size to the window floor
    // would disagree with both.
    {
        const std::uint64_t one_above = AddressSpace::kUserMin +
                                        AddressSpace::kGranularity;
        check(::occ::runtime::choose_base_below(nullptr, p, one_above, 1) ==
                  AddressSpace::kUserMin,
              "big-size: one above the floor, the floor is the answer");
        check(::occ::runtime::choose_base_below(
                  nullptr, p, AddressSpace::kUserMin, 1) == 0,
              "big-size: at the floor, the answer is zero");
    }

    // The bound the declared size cannot reach, stated rather than left
    // implicit. The field is 32 bits and the user window is 47, so no PE32+
    // file can produce an image that does not fit. A reader might reasonably
    // assume such an image was handled; it is worth saying that it is not
    // merely unhandled but unreachable, and that what refuses a section range
    // leaving the window is the loader's own check -- which this policy never
    // has to make, because it never offers a base that low.
    check(AddressSpace::kUserMax - AddressSpace::kUserMin > 0xFFFFFFF0ull,
          "big-size: the window is wider than any 32-bit declared size, so "
          "an unfittable image cannot come from a PE32+ SizeOfImage");
}

// A caller-supplied chooser is asked, and the default is used when none is.
//
// Two facts about the seam. The first is that it is consulted at all, and
// exactly once per failure -- a caller that counts its attempts has to see
// the same number the report does, or the count is a claim about something
// other than the search.
//
// The second is the one a caller relies on when it installs nothing: a null
// `base_chooser` is not "no policy" but "the deterministic scan", so a
// caller that only wants a conflict resolved gets a scan without having to
// know that the policy exists.
void test_the_chooser_is_the_seam_it_is_documented_to_be() {
    const TwoBases b = a_taken_base_and_the_one_below(0x10000);
    if (b.taken == 0) {
        std::fprintf(stderr, "SKIP seam: the kernel gave no aligned pair\n");
        return;
    }
    const Built img = a_relocatable_image(b.taken);
    const PeImage p =
        PeImage::parse(ByteSpan{img.bytes.data(), img.bytes.size()});
    if (!p.ok()) {
        return;
    }

    // A base for the chooser to offer, found the same way and for the same
    // reason as every other free base in this file: a written-down address is
    // a claim about this process that stops being true when the process is
    // different.
    const std::uint64_t offered = a_free_base(0x10000);
    if (offered == 0) {
        std::fprintf(stderr, "SKIP seam: no free base to offer\n");
        return;
    }

    // The chooser is consulted, once, and the load lands where it said.
    {
        AddressSpace space;
        Mapper m(space);
        const Result<std::uint64_t> held =
            m.map(b.taken, 0x10000, PageProtection::ReadOnly,
                  RegionKind::Image, ".text");
        if (!held.ok()) {
            std::fprintf(stderr, "SKIP seam: could not take\n");
            return;
        }
        ChooserState state;
        state.offer = offered;
        LoadContext ctx;
        ctx.placement = &m;
        ctx.base_chooser = offer_a_fixed_base;
        ctx.base_chooser_state = &state;

        BaseRetry report;
        const LoadResult r = load_image_retrying(
            p, ByteSpan{img.bytes.data(), img.bytes.size()}, b.taken, space,
            ctx, &report);
        check(state.asked == 1, "seam: the chooser was asked exactly once");
        check(r.ok, "seam: the load landed where the chooser said");
        if (r.ok) {
            check(r.module.base == offered,
                  "seam: the module is at the chooser's base");
        }
        check(report.attempts == report.tried.size(),
              "seam: the chooser's count and the report's count agree");
    }

    // And with no chooser, the deterministic scan answers for itself: an
    // occupied base, the same image, no policy installed, and the load lands
    // one granularity down. That address is not one any other policy in this
    // file produces, so the assertion is about the default specifically
    // rather than about placement in general.
    //
    // Its own pair of bases, asked of the kernel again, because the first
    // block's Mapper is not destroyed at the end of that block and does not
    // unmap what it mapped: a Mapper is a ledger plus a set of syscalls, not
    // an owner, and a space is a description of mappings rather than a thing
    // that releases them. Reusing the first block's address here therefore
    // failed to map -- correctly, since the kernel still had it -- and an
    // earlier version of this case printed a SKIP that read like a pass. (The
    // check that did run said the default scan was never reached, which is
    // the more expensive way to learn the same thing.)
    {
        const TwoBases d = a_taken_base_and_the_one_below(0x10000);
        if (d.taken == 0) {
            std::fprintf(stderr, "SKIP seam: no second aligned pair\n");
            return;
        }
        AddressSpace space;
        Mapper m(space);
        const Result<std::uint64_t> held =
            m.map(d.taken, 0x10000, PageProtection::ReadOnly,
                  RegionKind::Image, ".text");
        if (!held.ok()) {
            std::fprintf(stderr, "SKIP seam: could not take (default)\n");
            return;
        }
        // The image is linked at the base this block occupies, not at the one
        // the first block used, so the scan below steps down from *this*
        // base and the relocation delta is computed from this one.
        const Built local_img = a_relocatable_image(d.taken);
        const PeImage local_p = PeImage::parse(
            ByteSpan{local_img.bytes.data(), local_img.bytes.size()});
        LoadContext ctx;
        ctx.placement = &m;
        check(ctx.base_chooser == nullptr,
              "seam: a fresh context installs no chooser");
        check(ctx.base_chooser_state == nullptr,
              "seam: and no state for one");
        if (!local_p.ok()) {
            return;
        }
        BaseRetry report;
        const LoadResult r = load_image_retrying(
            local_p, ByteSpan{local_img.bytes.data(), local_img.bytes.size()},
            d.taken, space, ctx, &report);
        check(r.ok, "seam: the default policy placed the image");
        if (r.ok) {
            check(r.module.base == d.free_below,
                  "seam: the default scan stepped down by the granularity");
        }
    }
}

// A plain load does not consult the chooser.
//
// The seam has a rule about who may use it: load_image_retrying is the only
// thing that consults it. A plain load_image names its base and takes it or
// fails, because a caller that named a base and silently received a
// different one has a bug -- and a retry loop would hide that bug rather than
// fix it, which is the failure mode and not the remedy.
void test_a_plain_load_ignores_the_chooser() {
    const TwoBases b = a_taken_base_and_the_one_below(0x10000);
    if (b.taken == 0) {
        std::fprintf(stderr, "SKIP plain: no aligned pair\n");
        return;
    }
    const Built img = a_relocatable_image(b.taken);
    const std::uint64_t offered = a_free_base(0x10000);
    if (offered == 0) {
        std::fprintf(stderr, "SKIP plain: no free base to offer\n");
        return;
    }

    AddressSpace space;
    Mapper m(space);
    const Result<std::uint64_t> held =
        m.map(b.taken, 0x10000, PageProtection::ReadOnly, RegionKind::Image,
              ".text");
    if (!held.ok()) {
        std::fprintf(stderr, "SKIP plain: could not take\n");
        return;
    }

    ChooserState state;
    state.offer = offered;
    LoadContext ctx;
    ctx.placement = &m;
    // A chooser that would hand out a perfectly good base. If load_image
    // consulted it, the load would succeed; it must not.
    ctx.base_chooser = offer_a_fixed_base;
    ctx.base_chooser_state = &state;

    const PeImage p =
        PeImage::parse(ByteSpan{img.bytes.data(), img.bytes.size()});
    if (!p.ok()) {
        return;
    }

    const std::string before = a_map_of(space);
    const LoadResult r =
        load_image(p, ByteSpan{img.bytes.data(), img.bytes.size()}, b.taken,
                   space, ctx);
    check(!r.ok, "plain: the load at the taken base fails");
    check(r.error == LoadError::AddressConflict,
          "plain: it fails with a conflict");
    check(state.asked == 0, "plain: the chooser was never consulted");
    check(!a_region_covers(space, offered, 0x1000),
          "plain: nothing was placed at the chooser's base");
    check(a_map_of(space) == before, "plain: the space is exactly what it was");
}

// A chooser that says "no more" ends the search, and says why.
//
// The third way the loop stops. A policy that runs out of candidates --
// because it is random and the window is large, or because it has a list --
// answers zero, and zero has to mean "no more" rather than "try base zero",
// which is a base the loader cannot use at all and would refuse as an
// address outside the window.
void test_a_chooser_that_says_no_ends_the_search() {
    const TwoBases b = a_taken_base_and_the_one_below(0x10000);
    if (b.taken == 0) {
        std::fprintf(stderr, "SKIP chooser-no: no aligned pair\n");
        return;
    }
    const Built img = a_relocatable_image(b.taken);

    AddressSpace space;
    Mapper m(space);
    const Result<std::uint64_t> held =
        m.map(b.taken, 0x10000, PageProtection::ReadOnly, RegionKind::Image,
              ".text");
    if (!held.ok()) {
        std::fprintf(stderr, "SKIP chooser-no: could not take\n");
        return;
    }
    const std::string before = a_map_of(space);

    LoadContext ctx;
    ctx.placement = &m;
    ctx.base_chooser = [](void*, const PeImage&, std::uint64_t,
                          std::uint32_t) noexcept -> std::uint64_t {
        return 0;
    };
    ctx.base_chooser_state = nullptr;

    const PeImage p =
        PeImage::parse(ByteSpan{img.bytes.data(), img.bytes.size()});
    if (!p.ok()) {
        return;
    }

    BaseRetry report;
    const LoadResult r =
        load_image_retrying(p, ByteSpan{img.bytes.data(), img.bytes.size()},
                            b.taken, space, ctx, &report);

    check(!r.ok, "chooser-no: the search ends");
    check(r.error == LoadError::AddressConflict,
          "chooser-no: the failure is still a conflict");
    check(report.attempts == 1, "chooser-no: it tried once and stopped");
    check(report.tried.size() == 1, "chooser-no: the report lists one base");
    check(report.detail.find("no base was free") != std::string::npos,
          "chooser-no: the report says the search ended");
    check(a_map_of(space) == before,
          "chooser-no: the region list is exactly what it was");
}

// A chooser that hands back a base already tried is stopped.
//
// The fourth way the loop stops, and the one that exists because a policy is
// a function pointer and a function pointer can be wrong. A chooser that
// always answered with the same base would otherwise spin until the cap, and
// the report would then say it tried 64 addresses when it tried one -- and
// that report is what a person reads to decide what went wrong.
void test_a_chooser_that_repeats_a_base_is_stopped() {
    const TwoBases b = a_taken_base_and_the_one_below(0x10000);
    if (b.taken == 0) {
        std::fprintf(stderr, "SKIP chooser-repeat: no aligned pair\n");
        return;
    }
    const Built img = a_relocatable_image(b.taken);

    AddressSpace space;
    Mapper m(space);
    const Result<std::uint64_t> held =
        m.map(b.taken, 0x10000, PageProtection::ReadOnly, RegionKind::Image,
              ".text");
    if (!held.ok()) {
        std::fprintf(stderr, "SKIP chooser-repeat: could not take\n");
        return;
    }
    const std::string before = a_map_of(space);

    LoadContext ctx;
    ctx.placement = &m;
    // Always the caller's own base, which the loop has already tried.
    ctx.base_chooser = [](void*, const PeImage&, std::uint64_t failed_base,
                          std::uint32_t) noexcept -> std::uint64_t {
        return failed_base;
    };

    const PeImage p =
        PeImage::parse(ByteSpan{img.bytes.data(), img.bytes.size()});
    if (!p.ok()) {
        return;
    }

    BaseRetry report;
    const LoadResult r =
        load_image_retrying(p, ByteSpan{img.bytes.data(), img.bytes.size()},
                            b.taken, space, ctx, &report);

    check(!r.ok, "chooser-repeat: the search ends");
    check(r.error == LoadError::AddressConflict,
          "chooser-repeat: the failure is still a conflict");
    // One, not two. The loop asks the chooser for a second base, is handed
    // one it has already tried, and stops *before* attempting it -- so one
    // attempt was made and one address was placed at. This case originally
    // asserted two, on the reading that the second base was "tried and
    // rejected". It was not tried; a repeat is caught by asking, which is
    // the whole point of catching it, and a loop that placed at an address it
    // had already unwound would be doing the wasted work the check exists to
    // avoid. The count is therefore the number of placements attempted, and
    // it agrees with the list because nothing was appended.
    check(report.attempts == 1,
          "chooser-repeat: it stopped before the second attempt, not at the cap");
    check(report.tried.size() == 1, "chooser-repeat: the report lists one base");
    if (report.tried.size() == 1) {
        check(report.tried[0] == b.taken,
              "chooser-repeat: the base it tried is the one it was given");
    }

    // The message names the base, because a report that said only "a base
    // repeated" leaves the reader to work out which chooser was installed,
    // and the base is the one piece of that answer the reader can check
    // against the ledger in front of them. And it is in hexadecimal, because
    // that is how every other address in these details is written: a decimal
    // one here would be read as a different number from the one the ledger
    // shows. (Four details in the loader had exactly that defect until this
    // section was written -- "0x" followed by std::to_string -- and this
    // assertion is one of the things that found them.)
    check(report.detail.find("already been tried") != std::string::npos,
          "chooser-repeat: the report says the base had been tried");
    check(report.detail.find(hex_address(b.taken)) != std::string::npos,
          "chooser-repeat: the report names the base in hexadecimal");
    check(a_map_of(space) == before,
          "chooser-repeat: the region list is exactly what it was");
}

// The attempt cap stops a search that cannot end on its own.
//
// The loop's other bound, and the one that exists because the first bound is
// not always the one that fires. A space where every base conflicts is not
// something a test can build by occupying addresses -- the window is 128 TiB
// -- so this case supplies a chooser that answers with a fresh,
// never-tried, always-conflicting base, forever. Without the cap that is a
// hang; with it, the loop stops and says which bound it hit, and that is the
// fact a caller needs: "it tried 64 addresses" and "there was nowhere to put
// it" are different sentences and only the first is true here.
void test_the_attempt_cap_stops_a_search_that_cannot_end() {
    const TwoBases b = a_taken_base_and_the_one_below(0x10000);
    if (b.taken == 0) {
        std::fprintf(stderr, "SKIP cap: the kernel gave no aligned pair\n");
        return;
    }
    const Built img = a_relocatable_image(b.taken);

    AddressSpace space;
    Mapper m(space);
    // The caller's base and then a run of occupied pages below it for the
    // chooser to walk. Sixty-four of them, which is the cap, so the run is
    // exactly long enough to keep the loop going to the cap and not one
    // answer longer: were the cap raised, the walk would wrap and this case
    // would report a bound it did not hit.
    //
    // Sixty-four *pages*, so the run spans 256 KiB. An earlier version wrote
    // the loop bound as 0x10000, which is one granularity and sixteen pages,
    // and asserted the count was sixty-four: it got sixteen, and the twenty
    // failures that followed were one real disagreement reported seventeen
    // times. A run that has to be a given length has to be counted, not
    // guessed at from a constant that means something else.
    constexpr std::size_t kPages = 64;
    constexpr std::uint64_t kPageSize = 0x1000;
    const std::uint64_t run_bytes = kPages * kPageSize;
    if (b.taken < run_bytes) {
        std::fprintf(stderr, "SKIP cap: the taken base is too low\n");
        return;
    }
    std::vector<std::uint64_t> taken;
    taken.reserve(kPages);
    for (std::size_t i = 0; i < kPages; ++i) {
        taken.push_back(b.taken - static_cast<std::uint64_t>(i) * kPageSize);
    }
    for (const std::uint64_t at : taken) {
        const Result<std::uint64_t> held =
            m.map(at, kPageSize, PageProtection::ReadOnly, RegionKind::Image,
                  ".text");
        if (!held.ok()) {
            std::fprintf(stderr, "SKIP cap: could not take the run\n");
            return;
        }
    }
    check(taken.size() == kPages, "cap: the run is 64 occupied pages");

    Walker walker;
    walker.taken = &taken;
    // Starting at the *second* entry, because the first one is the base the
    // caller named and the loop has already tried it. A walker started at
    // zero answers the first question with the base that is already in
    // `report.tried`, the loop stops on its repeat check before it makes a
    // second attempt, and the cap this case exists to reach is never
    // reached -- one attempt, reported as a search that ended immediately.
    walker.at = 1;

    LoadContext ctx;
    ctx.placement = &m;
    ctx.base_chooser = choose_the_next_occupied;
    ctx.base_chooser_state = &walker;

    const PeImage p =
        PeImage::parse(ByteSpan{img.bytes.data(), img.bytes.size()});
    if (!p.ok()) {
        return;
    }

    const std::string before = a_map_of(space);
    const std::uint64_t allocs_before = space.allocation_count();
    const std::uint64_t syscalls_before = m.syscalls_made();

    BaseRetry report;
    const LoadResult r =
        load_image_retrying(p, ByteSpan{img.bytes.data(), img.bytes.size()},
                            taken.front(), space, ctx, &report);

    check(!r.ok, "cap: the search ends");
    check(r.error == LoadError::AddressConflict,
          "cap: the failure is still a conflict");
    check(report.attempts == 64, "cap: it stopped at 64 attempts");
    check(report.tried.size() == 64, "cap: the report lists 64 bases");
    check(report.attempts == report.tried.size(),
          "cap: the attempt count and the list agree");

    // Every base it tried is one the chooser produced, and no two are the
    // same. Both halves matter: the first says the loop did not override the
    // policy with a scan of its own, and the second says the cap is what
    // stopped it rather than the repeat check. A loop that stopped early on a
    // repeat would report a small count; one that scanned would report 64
    // addresses a granularity apart, none of which the chooser offered.
    bool all_chosen = true;
    bool all_distinct = true;
    for (std::size_t i = 0; i < report.tried.size(); ++i) {
        if (std::find(taken.begin(), taken.end(), report.tried[i]) ==
            taken.end()) {
            all_chosen = false;
        }
        for (std::size_t j = i + 1; j < report.tried.size(); ++j) {
            if (report.tried[i] == report.tried[j]) {
                all_distinct = false;
            }
        }
    }
    check(all_chosen, "cap: every base tried is one the chooser produced");
    check(all_distinct, "cap: no base was tried twice");

    // The bound it hit is the cap, and the report says so rather than
    // claiming the search ran out -- a chooser was willing to keep going, so
    // "no base was free" would be false.
    check(report.detail.find("no base was free") == std::string::npos,
          "cap: the report does not claim the search ran out");
    check(report.detail.find("still in the way") != std::string::npos,
          "cap: the report names the cap");

    // And the space is still exactly what it was, after 64 attempts each of
    // which mapped a region and unmapped it again.
    check(a_map_of(space) == before,
          "cap: the region list is exactly what it was after 64 attempts");
    check(space.allocation_count() == allocs_before,
          "cap: the allocation count did not move");
    check(m.syscalls_made() > syscalls_before,
          "cap: the attempts did make syscalls");
    // At least one syscall per attempt, and no more than a small multiple:
    // each attempt maps the header region first and is refused there, so it
    // costs one call and unwinds nothing. An earlier version asserted *more
    // than* sixty-four, on the theory that every attempt mapped and unmapped
    // a whole batch -- and got exactly sixty-four, because a conflict on the
    // first candidate never reaches the second. The bound was a guess about
    // the batch's shape wearing the loop's name, and the number it asserted
    // was the number it should have been given.
    //
    // At least one syscall per attempt: sixty-four attempts that each asked
    // the kernel a question cost at least sixty-four calls.
    //
    // This is deliberately a lower bound and not an equality. An earlier
    // version asserted *more* than one per attempt, on the theory that each
    // one mapped and unwound a whole batch, and got exactly sixty-four --
    // every attempt here is refused on its first candidate, so there is
    // nothing to unwind and the guess was about the batch's shape rather
    // than about the loop. It then asserted *at least* one, which is what a
    // counter skipping failed mmaps also produces, and the mutation harness
    // duly rewrote the counter to skip them and the check passed. The check
    // that distinguishes the two is in the retry case above, where one
    // attempt succeeds and the exact count can be accounted for; this one
    // says only that the attempts happened, which is what this case is for.
    check(m.syscalls_made() >= syscalls_before + report.attempts,
          "cap: every attempt reached the kernel");
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

    test_a_taken_base_is_retried_below_it();
    test_a_retry_that_gives_up_changes_nothing();
    test_a_refusal_is_not_retried();
    test_the_default_scan_answers_for_itself();
    test_the_declared_size_decides_fit_and_not_the_floor();
    test_the_chooser_is_the_seam_it_is_documented_to_be();
    test_a_plain_load_ignores_the_chooser();
    test_a_chooser_that_says_no_ends_the_search();
    test_a_chooser_that_repeats_a_base_is_stopped();
    test_the_attempt_cap_stops_a_search_that_cannot_end();

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

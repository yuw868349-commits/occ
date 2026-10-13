// Self-modifying-code analysis tests.
//
// The image here is a synthetic mapped-layout PE: headers at offset 0 and
// each section at its own RVA, exactly as the runtime maps a guest, so a
// write address of image_base + rva lands in the section the test intends.
// The write records themselves are the shape memwatch's service_write
// would produce -- (fault_address, rip) -- fed in as plain data, which is
// the whole of the analysis contract: this module consumes records, it
// does not arm watches.
//
// The cases exercise the classification's four answers: a write into an
// executable section is a WriteToExec finding; eight writes into one
// executable section plus four into a page are the DecryptLoop shape at
// both granularities; a write into a data section is a DataWrite record,
// not an alarm; and an RWX section is a static hint with no write events
// at all.

#include "occ/packer/packer.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using occ::packer::SMCKind;
using occ::packer::SMCEvidence;
using occ::packer::SMCHint;
using occ::packer::SMCReport;
using occ::packer::SMCWrite;

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

// ---------------------------------------------------------- pe (mapped)

constexpr std::uint32_t kSecRead = 0x40000000;
constexpr std::uint32_t kSecWrite = 0x80000000;
constexpr std::uint32_t kSecExec = 0x20000000;
constexpr std::uint32_t kSecCode = 0x00000020;
constexpr std::uint32_t kSecInit = 0x00000040;

constexpr std::uint32_t kPe32PlusMagic = 0x20B;
constexpr std::uint32_t kSectionAlign = 0x1000;
constexpr std::uint32_t kImageSize = 0x4000;

void wr16(std::vector<std::uint8_t>& b, std::size_t at, std::uint16_t v) {
    b[at] = static_cast<std::uint8_t>(v);
    b[at + 1] = static_cast<std::uint8_t>(v >> 8);
}

void wr32(std::vector<std::uint8_t>& b, std::size_t at, std::uint32_t v) {
    b[at] = static_cast<std::uint8_t>(v);
    b[at + 1] = static_cast<std::uint8_t>(v >> 8);
    b[at + 2] = static_cast<std::uint8_t>(v >> 16);
    b[at + 3] = static_cast<std::uint8_t>(v >> 24);
}

// A mapped-layout PE32+ with three sections: .text (RX) at 0x1000, .data
// (RW) at 0x2000, and .xcode (RWX) at 0x3000. Section bytes are laid at
// their RVA inside the buffer, the way the runtime maps an image.
struct MappedPe {
    std::vector<std::uint8_t> buffer;
    std::uint64_t image_base = 0;
};

[[nodiscard]] MappedPe build_mapped_pe() {
    MappedPe m;
    m.buffer.assign(kImageSize, 0);
    std::vector<std::uint8_t>& out = m.buffer;

    out[0] = 'M';
    out[1] = 'Z';
    wr32(out, 0x3C, 0x40);
    wr32(out, 0x40, 0x00004550);
    wr16(out, 0x44, 0x8664);
    wr16(out, 0x46, 3);  // three sections
    wr16(out, 0x54, 0xF0);

    const std::size_t opt = 0x58;
    wr16(out, opt + 0x00, static_cast<std::uint16_t>(kPe32PlusMagic));
    wr32(out, opt + 0x10, 0x1000);  // entry at .text
    wr32(out, opt + 0x20, kSectionAlign);
    wr32(out, opt + 0x24, 0x200);
    wr32(out, opt + 0x38, kImageSize);
    wr32(out, opt + 0x3C, 0x400);

    const std::size_t table = opt + 0xF0;
    struct SecSpec {
        const char* name;
        std::uint32_t rva;
        std::uint32_t vsize;
        std::uint32_t chars;
    };
    const SecSpec secs[] = {
        {".text", 0x1000, 0x1000, kSecRead | kSecExec | kSecCode | kSecInit},
        {".data", 0x2000, 0x1000, kSecRead | kSecWrite | kSecInit},
        {".xcode", 0x3000, 0x1000,
         kSecRead | kSecWrite | kSecExec | kSecCode | kSecInit},
    };
    for (std::size_t i = 0; i < 3; ++i) {
        const std::size_t e = table + i * 40;
        const SecSpec& s = secs[i];
        std::memcpy(out.data() + e, s.name, 8);
        wr32(out, e + 0x08, s.vsize);
        wr32(out, e + 0x0C, s.rva);
        wr32(out, e + 0x10, s.vsize);
        wr32(out, e + 0x14, s.rva);  // raw pointer == rva in a mapped view
        wr32(out, e + 0x24, s.chars);
    }
    m.image_base = reinterpret_cast<std::uint64_t>(out.data());
    return m;
}

// ------------------------------------------------------------- helpers

[[nodiscard]] bool has_kind(const SMCReport& r, SMCKind kind) {
    for (const SMCEvidence& f : r.findings) {
        if (f.kind == kind) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool has_kind_in_section(const SMCReport& r, SMCKind kind,
                                       const std::string& section) {
    for (const SMCEvidence& f : r.findings) {
        if (f.kind == kind && f.section == section) {
            return true;
        }
    }
    return false;
}

// --------------------------------------------------------------- tests

void test_write_classification() {
    const MappedPe m = build_mapped_pe();
    const std::uint64_t base = m.image_base;

    std::vector<SMCWrite> writes;
    // One isolated write into .text: the write-to-exec finding.
    writes.push_back(SMCWrite{base + 0x1000 + 0x10, base + 0x1234, 1});
    // The decryption-loop shape: eight writes into .text within one page.
    for (std::uint32_t i = 0; i < 8; ++i) {
        writes.push_back(
            SMCWrite{base + 0x1000 + 0x20 + i * 4, base + 0x1300, 1});
    }
    // A write into .data: recorded, not alarmed.
    writes.push_back(SMCWrite{base + 0x2000 + 0x08, base + 0x2345, 4});
    // A write below the base and one past the last section: neither is a
    // section write; both become notes.
    writes.push_back(SMCWrite{base - 0x1000, base + 0x100, 1});
    writes.push_back(SMCWrite{base + 0x5000, base + 0x1500, 1});

    const SMCReport r =
        occ::packer::analyze_smc(m.buffer.data(), m.buffer.size(), base,
                                 writes);
    check(r.total_writes == 12, "smc: all writes counted");
    check(has_kind_in_section(r, SMCKind::WriteToExec, ".text"),
          "smc: write-to-exec finding in .text");
    check(has_kind(r, SMCKind::DecryptLoop),
          "smc: decrypt-loop finding present");
    check(has_kind_in_section(r, SMCKind::DataWrite, ".data"),
          "smc: data-write record in .data");
    bool saw_below = false;
    bool saw_unmapped = false;
    for (const std::string& n : r.notes) {
        if (n.find("below the image base") != std::string::npos) {
            saw_below = true;
        }
        if (n.find("lands in no section") != std::string::npos) {
            saw_unmapped = true;
        }
    }
    check(saw_below, "smc: below-base write is a note");
    check(saw_unmapped, "smc: unmapped write is a note");
    // The decrypt-loop note carries the count and the threshold.
    bool loop_noted = false;
    for (const SMCEvidence& f : r.findings) {
        if (f.kind == SMCKind::DecryptLoop &&
            f.note.find("writes") != std::string::npos) {
            loop_noted = true;
        }
    }
    check(loop_noted, "smc: decrypt-loop note spells the count");
}

void test_static_hints() {
    const MappedPe m = build_mapped_pe();
    const std::vector<SMCHint> hints =
        occ::packer::static_smc_hints(m.buffer.data(), m.buffer.size());
    check(hints.size() == 1, "smc: exactly one RWX section hinted");
    if (hints.size() == 1) {
        check(hints[0].section == ".xcode",
              "smc: the hinted section is .xcode");
        check(hints[0].rva == 0x3000, "smc: hint carries the section RVA");
    }
    // The mapped-image overload answers the same question.
    const std::vector<SMCHint> hints_mapped =
        occ::packer::static_smc_hints(m.image_base);
    check(hints_mapped.size() == 1,
          "smc: mapped-overload hint agrees with the buffer overload");
}

}  // namespace

int main() {
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("-- %s\n", name);
        std::fflush(stdout);
        fn();
    };
    run("write_classification", test_write_classification);
    run("static_hints", test_static_hints);
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

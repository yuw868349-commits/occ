// Packer-identification tests over self-constructed PE files.
//
// The builder at the bottom of this file assembles a real PE32+ file in
// memory -- DOS stub, e_lfanew, PE signature, COFF header, optional
// header, section table, and a working import directory when the test
// asks for one -- with sections placed at file offsets and virtual
// addresses the way a linker would. The four cases then ask the offline
// identify() the four questions it must answer honestly:
//
//   (1) a UPX-shaped file -- UPX0/UPX1 section names, a high-entropy
//       compressed payload section, a stub import table built around
//       LoadLibraryA/GetProcAddress, and a pushad-then-jmp entry -- must
//       come back as UPX with confidence above the high line;
//   (2) a file with no known section names but a high-entropy executable
//       section and almost no imports must come back as the generic
//       "unknown (generic packer)" candidate at least at medium
//       confidence;
//   (3) a clean file -- ordinary section name, code-like entropy, four
//       normal imports, a normal entry -- must come back unpacked with
//       no candidates at all;
//   (4) the counterexample the scorer exists for: a section named UPX1
//       whose bytes measure as ordinary data must come back as a
//       low-confidence UPX candidate, with the name/entropy contradiction
//       spelled out in its evidence, not smoothed over.

#include "occ/packer/packer.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using occ::packer::Candidate;
using occ::packer::Evidence;
using occ::packer::Report;
using occ::packer::SectionStat;

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

// ---------------------------------------------------------------- rng

std::uint64_t rng_state = 0x853c49e6748fea9bULL;

std::uint8_t rng_byte() {
    rng_state = rng_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return static_cast<std::uint8_t>(rng_state >> 56);
}

// ---------------------------------------------------------- pe builder

// Section characteristics, as the PE format defines them, named rather
// than written as numbers in each test.
constexpr std::uint32_t kSecRead = 0x40000000;
constexpr std::uint32_t kSecWrite = 0x80000000;
constexpr std::uint32_t kSecExec = 0x20000000;
constexpr std::uint32_t kSecCode = 0x00000020;
constexpr std::uint32_t kSecInit = 0x00000040;
constexpr std::uint32_t kSecExecRead =
    kSecRead | kSecExec | kSecCode | kSecInit;
constexpr std::uint32_t kSecExecWriteRead =
    kSecRead | kSecWrite | kSecExec | kSecCode | kSecInit;
constexpr std::uint32_t kSecDataRead = kSecRead | kSecInit;

constexpr std::uint32_t kPe32PlusMagic = 0x20B;
constexpr std::uint32_t kFileAlign = 0x200;
constexpr std::uint32_t kSectionAlign = 0x1000;
constexpr std::uint32_t kHeadersSize = 0x400;
constexpr std::uint32_t kFirstRva = 0x1000;
constexpr std::uint64_t kImageBase = 0x140000000ULL;

[[nodiscard]] std::uint32_t align_up(std::uint32_t v, std::uint32_t unit) {
    return ((v + unit - 1) / unit) * unit;
}

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

// One import DLL with its functions, for the builder's import directory.
struct ImportDll {
    std::string dll;
    std::vector<std::string> funcs;
};

// Builds a minimal but structurally valid PE32+ file: DOS stub, PE
// signature, COFF header, PE32+ optional header with a 16-entry data
// directory, and one section table entry per section, with raw bytes
// placed at file offsets and virtual addresses starting at 0x1000.
class PeBuilder {
public:
    PeBuilder& section(std::string name, std::vector<std::uint8_t> bytes,
                       std::uint32_t vsize, std::uint32_t chars) {
        SectionSpec spec;
        spec.name = std::move(name);
        spec.bytes = std::move(bytes);
        spec.vsize = vsize;
        spec.chars = chars;
        specs_.push_back(std::move(spec));
        return *this;
    }

    PeBuilder& imports(std::vector<ImportDll> imps) {
        imps_ = std::move(imps);
        return *this;
    }

    // The entry stub bytes are prepended to the first section, which the
    // tests keep executable; the entry point RVA is that section's RVA.
    PeBuilder& entry(std::vector<std::uint8_t> bytes) {
        entry_ = std::move(bytes);
        return *this;
    }

    std::vector<std::uint8_t> build() {
        // The working section list, with entry bytes folded into the
        // first section so the file carries the stub at its start.
        std::vector<Sec> secs;
        for (std::size_t i = 0; i < specs_.size(); ++i) {
            Sec s;
            s.name = specs_[i].name;
            s.bytes = specs_[i].bytes;
            s.vsize = specs_[i].vsize;
            s.chars = specs_[i].chars;
            secs.push_back(std::move(s));
        }
        if (!entry_.empty() && !secs.empty()) {
            std::vector<std::uint8_t> merged = entry_;
            merged.insert(merged.end(), secs[0].bytes.begin(),
                          secs[0].bytes.end());
            secs[0].bytes = std::move(merged);
        }
        if (secs.empty()) {
            return std::vector<std::uint8_t>();
        }

        // Virtual addresses: 0x1000, then one section-aligned step per
        // section. The entry point names the first section's RVA.
        std::uint32_t rva = kFirstRva;
        std::uint32_t entry_rva = 0;
        for (std::size_t i = 0; i < secs.size(); ++i) {
            secs[i].rva = rva;
            if (i == 0) {
                entry_rva = rva;
            }
            rva = align_up(rva + secs[i].vsize, kSectionAlign);
        }

        // The import directory, as a .idata section appended after the
        // user's sections. Its content needs its own RVA, so the layout
        // is computed before the bytes are.
        std::uint32_t import_dir_rva = 0;
        std::uint32_t import_dir_size = 0;
        if (!imps_.empty()) {
            std::vector<std::uint8_t> idata =
                build_idata(rva, import_dir_rva, import_dir_size);
            Sec s;
            s.name = ".idata";
            s.bytes = std::move(idata);
            s.vsize = static_cast<std::uint32_t>(s.bytes.size());
            s.chars = kSecDataRead;
            s.rva = rva;
            secs.push_back(std::move(s));
        }

        // File offsets: headers first, then each section's bytes aligned
        // to the file alignment.
        std::uint32_t cursor = kHeadersSize;
        for (Sec& s : secs) {
            s.rawptr = align_up(cursor, kFileAlign);
            cursor = s.rawptr + static_cast<std::uint32_t>(s.bytes.size());
        }
        const std::uint32_t file_size = align_up(cursor, kFileAlign);

        std::vector<std::uint8_t> out(static_cast<std::size_t>(file_size), 0);

        // DOS header: 'MZ' and e_lfanew pointing at the PE signature.
        out[0] = 'M';
        out[1] = 'Z';
        wr32(out, 0x3C, 0x40);

        // PE signature, then the COFF header.
        wr32(out, 0x40, 0x00004550);
        wr16(out, 0x44, 0x8664);  // machine: AMD64
        wr16(out, 0x46, static_cast<std::uint16_t>(secs.size()));
        wr16(out, 0x54, 0xF0);  // size of optional header
        wr16(out, 0x56, 0x0022);  // characteristics: executable, large-address

        // The PE32+ optional header.
        const std::size_t opt = 0x58;
        wr16(out, opt + 0x00, static_cast<std::uint16_t>(kPe32PlusMagic));
        wr32(out, opt + 0x10, entry_rva);
        wr32(out, opt + 0x18,
             static_cast<std::uint32_t>(kImageBase & 0xFFFFFFFFULL));
        wr32(out, opt + 0x1C, static_cast<std::uint32_t>(kImageBase >> 32));
        wr32(out, opt + 0x20, kSectionAlign);
        wr32(out, opt + 0x24, kFileAlign);
        // SizeOfImage: the aligned end of the last section.
        const Sec& last = secs.back();
        wr32(out, opt + 0x38, align_up(last.rva + last.vsize, kSectionAlign));
        wr32(out, opt + 0x3C, kHeadersSize);
        // The data directory: 16 entries; the import table is entry 1.
        wr32(out, opt + 0x70 + 8, import_dir_rva);
        wr32(out, opt + 0x70 + 12, import_dir_size);

        // The section table.
        const std::size_t table = opt + 0xF0;
        for (std::size_t i = 0; i < secs.size(); ++i) {
            const Sec& s = secs[i];
            const std::size_t e = table + i * 40;
            std::memcpy(out.data() + e, s.name.c_str(),
                        s.name.size() < 8 ? s.name.size() : 8);
            wr32(out, e + 0x08, s.vsize);
            wr32(out, e + 0x0C, s.rva);
            wr32(out, e + 0x10, static_cast<std::uint32_t>(s.bytes.size()));
            wr32(out, e + 0x14, s.rawptr);
            wr32(out, e + 0x24, s.chars);
            if (!s.bytes.empty()) {
                std::memcpy(out.data() + s.rawptr, s.bytes.data(),
                            s.bytes.size());
            }
        }
        return out;
    }

private:
    struct SectionSpec {
        std::string name;
        std::vector<std::uint8_t> bytes;
        std::uint32_t vsize = 0;
        std::uint32_t chars = 0;
    };
    struct Sec {
        std::string name;
        std::vector<std::uint8_t> bytes;
        std::uint32_t vsize = 0;
        std::uint32_t chars = 0;
        std::uint32_t rva = 0;
        std::uint32_t rawptr = 0;
    };
    std::vector<SectionSpec> specs_;
    std::vector<ImportDll> imps_;
    std::vector<std::uint8_t> entry_;

    // Builds the .idata section: an array of import descriptors (one per
    // DLL plus the zero terminator), a thunk array and an IAT per DLL,
    // the DLL names, and a hint/name entry per function. The import
    // directory names the descriptor array's RVA and size.
    std::vector<std::uint8_t> build_idata(std::uint32_t idata_rva,
                                          std::uint32_t& dir_rva,
                                          std::uint32_t& dir_size) {
        const std::size_t ndll = imps_.size();
        struct DllLayout {
            std::size_t int_off = 0;
            std::size_t iat_off = 0;
            std::size_t name_off = 0;
            std::vector<std::size_t> hint_offs;
        };
        std::vector<DllLayout> layout(ndll);

        std::size_t cursor = (ndll + 1) * 20;  // descriptors + terminator
        for (std::size_t i = 0; i < ndll; ++i) {
            layout[i].int_off = cursor;
            cursor += (imps_[i].funcs.size() + 1) * 8;
            layout[i].iat_off = cursor;
            cursor += (imps_[i].funcs.size() + 1) * 8;
        }
        for (std::size_t i = 0; i < ndll; ++i) {
            layout[i].name_off = cursor;
            cursor += imps_[i].dll.size() + 1;
            for (const std::string& f : imps_[i].funcs) {
                layout[i].hint_offs.push_back(cursor);
                cursor += 2 + f.size() + 1;
                cursor = (cursor + 1) & ~static_cast<std::size_t>(1);
            }
        }

        std::vector<std::uint8_t> out(static_cast<std::size_t>(cursor), 0);
        dir_rva = idata_rva;
        dir_size = static_cast<std::uint32_t>((ndll + 1) * 20);

        const auto rva_of = [idata_rva](std::size_t off) -> std::uint32_t {
            return static_cast<std::uint32_t>(
                static_cast<std::uint64_t>(idata_rva) + off);
        };
        for (std::size_t i = 0; i < ndll; ++i) {
            const std::size_t desc = i * 20;
            wr32(out, desc + 0x00, rva_of(layout[i].int_off));
            wr32(out, desc + 0x0C, rva_of(layout[i].name_off));
            wr32(out, desc + 0x10, rva_of(layout[i].iat_off));
            std::memcpy(out.data() + layout[i].name_off, imps_[i].dll.c_str(),
                        imps_[i].dll.size() + 1);
            for (std::size_t j = 0; j < imps_[i].funcs.size(); ++j) {
                const std::size_t hint = layout[i].hint_offs[j];
                wr32(out, layout[i].int_off + j * 8, rva_of(hint));
                wr32(out, layout[i].iat_off + j * 8, rva_of(hint));
                std::memcpy(out.data() + hint + 2, imps_[i].funcs[j].c_str(),
                            imps_[i].funcs[j].size() + 1);
            }
        }
        return out;
    }
};

// ------------------------------------------------------------- helpers

// Fills a buffer with uniformly random bytes: the compressed-payload
// stand-in, whose entropy reads ~8.0 bits/byte.
void fill_random(std::vector<std::uint8_t>& b) {
    for (std::uint8_t& x : b) {
        x = rng_byte();
    }
}

// Fills a buffer by repeating one short pattern: the ordinary-data
// stand-in, whose entropy stays far below the high bar.
void fill_pattern(std::vector<std::uint8_t>& b, const std::uint8_t* pat,
                  std::size_t pat_len) {
    for (std::size_t i = 0; i < b.size(); ++i) {
        b[i] = pat[i % pat_len];
    }
}

[[nodiscard]] bool has_evidence(const Candidate& c, Evidence::Kind kind) {
    for (const Evidence& ev : c.evidence) {
        if (ev.kind == kind) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool has_candidate(const Report& r, const std::string& name) {
    for (const Candidate& c : r.candidates) {
        if (c.name == name) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool has_section(const Report& r, const std::string& name) {
    for (const SectionStat& s : r.sections) {
        if (s.name == name) {
            return true;
        }
    }
    return false;
}

// --------------------------------------------------------------- tests

void test_upx_shape() {
    std::vector<std::uint8_t> payload(0x800);
    fill_random(payload);
    std::vector<std::uint8_t> stub = {
        0x60,                 // pushad
        0xE9, 0x00, 0, 0, 0,  // jmp rel32
    };
    std::vector<ImportDll> imps;
    imps.push_back(ImportDll{"KERNEL32.dll",
                             {"LoadLibraryA", "GetProcAddress"}});
    const std::vector<std::uint8_t> file =
        PeBuilder()
            .section("UPX1", payload, 0x4000, kSecExecRead)
            .section("UPX0", std::vector<std::uint8_t>(), 0x4000,
                     kSecExecWriteRead)
            .imports(imps)
            .entry(stub)
            .build();

    const Report r = occ::packer::identify(file.data(), file.size());
    check(r.valid, "upx: image parsed");
    // Three sections: UPX0, UPX1, and the .idata section the builder adds
    // for the import directory.
    check(r.sections.size() == 3, "upx: three sections reported");
    check(has_section(r, "UPX0") && has_section(r, "UPX1"),
          "upx: both sections present");
    check(!r.candidates.empty() && r.candidates[0].name == "UPX",
          "upx: first candidate is UPX");
    check(r.candidates[0].confidence >= 0.60,
          "upx: confidence clears the high line");
    check(!r.candidates[0].low_confidence,
          "upx: candidate not marked low-confidence");
    check(has_evidence(r.candidates[0], Evidence::Kind::SectionName),
          "upx: section-name evidence present");
    check(has_evidence(r.candidates[0], Evidence::Kind::HighEntropy),
          "upx: high-entropy evidence present");
    check(has_evidence(r.candidates[0], Evidence::Kind::SizeDisparity),
          "upx: size-disparity evidence present");
    check(has_evidence(r.candidates[0], Evidence::Kind::ImportAnomaly),
          "upx: import-anomaly evidence present");
    check(has_evidence(r.candidates[0], Evidence::Kind::EntryPattern),
          "upx: entry-pattern evidence present");
    check(r.verdict.find("packed") != std::string::npos,
          "upx: verdict says packed");
    for (const SectionStat& s : r.sections) {
        if (s.name == "UPX1") {
            check(s.entropy >= 7.0,
                  "upx: UPX1 entropy clears the high bar");
        }
        if (s.name == "UPX0") {
            check(s.rawsize == 0 && s.vsize == 0x4000,
                  "upx: UPX0 is zero-file-bytes with a large virtual size");
        }
    }
}

// The dotted spelling: what UPX's own writer emits. Every other packer
// family in the table is listed by the name it actually writes, and UPX
// was the outlier -- a table entry of "UPX0" with no leading dot missed
// every real UPX binary, whose sections are named .upx0/.upx1/.upx2.
// This test is the regression guard for that: the same shape as
// test_upx_shape, spelled the way the packer spells it.
void test_upx_dotted_shape() {
    std::vector<std::uint8_t> payload(0x800);
    fill_random(payload);
    std::vector<std::uint8_t> stub = {
        0x60,                 // pushad
        0xE9, 0x00, 0, 0, 0,  // jmp rel32
    };
    std::vector<ImportDll> imps;
    imps.push_back(ImportDll{"KERNEL32.dll",
                             {"LoadLibraryA", "GetProcAddress"}});
    const std::vector<std::uint8_t> file =
        PeBuilder()
            .section(".upx1", payload, 0x4000, kSecExecRead)
            .section(".upx0", std::vector<std::uint8_t>(), 0x4000,
                     kSecExecWriteRead)
            .imports(imps)
            .entry(stub)
            .build();

    const Report r = occ::packer::identify(file.data(), file.size());
    check(r.valid, "upx dotted: image parsed");
    check(r.sections.size() == 3, "upx dotted: three sections reported");
    check(has_section(r, ".upx0") && has_section(r, ".upx1"),
          "upx dotted: both sections present");
    check(!r.candidates.empty() && r.candidates[0].name == "UPX",
          "upx dotted: first candidate is UPX");
    check(r.candidates[0].confidence >= 0.60,
          "upx dotted: confidence clears the high line");
    check(!r.candidates[0].low_confidence,
          "upx dotted: candidate not marked low-confidence");
    check(has_evidence(r.candidates[0], Evidence::Kind::SectionName),
          "upx dotted: section-name evidence present");
    check(has_evidence(r.candidates[0], Evidence::Kind::HighEntropy),
          "upx dotted: high-entropy evidence present");
    check(has_evidence(r.candidates[0], Evidence::Kind::SizeDisparity),
          "upx dotted: size-disparity evidence present");
    check(r.verdict.find("packed") != std::string::npos,
          "upx dotted: verdict says packed");
    // Both spellings must land on the same candidate, not two: a binary
    // carrying .upx0 and .upx1 is one UPX image, and the scorer that
    // split them would halve the evidence for it.
    std::size_t upx_candidates = 0;
    for (const Candidate& c : r.candidates) {
        if (c.name == "UPX") {
            ++upx_candidates;
        }
    }
    check(upx_candidates == 1, "upx dotted: one UPX candidate, not two");
}

void test_generic_packer() {
    std::vector<std::uint8_t> payload(0x800);
    fill_random(payload);
    std::vector<std::uint8_t> entry = {0x55, 0x48, 0x89, 0xE5};  // push rbp; mov rbp,rsp
    std::vector<ImportDll> imps;
    imps.push_back(ImportDll{"KERNEL32.dll", {"GetProcAddress"}});
    const std::vector<std::uint8_t> file =
        PeBuilder()
            .section(".text", payload, 0x4000, kSecExecRead)
            .imports(imps)
            .entry(entry)
            .build();

    const Report r = occ::packer::identify(file.data(), file.size());
    check(r.valid, "generic: image parsed");
    check(!r.candidates.empty() &&
              r.candidates[0].name == "unknown (generic packer)",
          "generic: generic candidate is first");
    check(r.candidates[0].confidence >= 0.40,
          "generic: confidence is at least medium");
    check(has_evidence(r.candidates[0], Evidence::Kind::HighEntropy),
          "generic: high-entropy evidence present");
    check(r.verdict.find("packed") != std::string::npos,
          "generic: verdict says packed");
}

void test_clean_pe() {
    static const std::uint8_t kPattern[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x90,
        0xC3};
    std::vector<std::uint8_t> code(0x1000);
    fill_pattern(code, kPattern, sizeof(kPattern));
    std::vector<std::uint8_t> entry = {0x55, 0x48, 0x89, 0xE5};
    std::vector<ImportDll> imps;
    imps.push_back(ImportDll{
        "KERNEL32.dll",
        {"WriteFile", "ReadFile", "CreateFileW", "GetModuleHandleA"}});
    const std::vector<std::uint8_t> file =
        PeBuilder()
            .section(".text", code, 0x1000, kSecExecRead)
            .imports(imps)
            .entry(entry)
            .build();

    const Report r = occ::packer::identify(file.data(), file.size());
    check(r.valid, "clean: image parsed");
    check(r.candidates.empty(), "clean: no candidates at all");
    check(r.verdict == "unpacked", "clean: verdict is unpacked");
    check(!r.sections.empty() && r.sections[0].entropy < 7.0,
          "clean: .text entropy stays below the high bar");
}

void test_name_entropy_contradiction() {
    // A section literally named UPX1 whose bytes are pure NOP padding:
    // the name says packer, the bytes say ordinary data. The scorer must
    // present the contradiction, not pick a side.
    std::vector<std::uint8_t> nops(0x1000, 0x90);
    std::vector<std::uint8_t> code(0x1000);
    static const std::uint8_t kPattern[] = {0x48, 0x89, 0x5C, 0x24,
                                            0x08, 0x57, 0x48, 0x83,
                                            0xEC, 0x20, 0x90, 0xC3};
    fill_pattern(code, kPattern, sizeof(kPattern));
    std::vector<std::uint8_t> entry = {0x55, 0x48, 0x89, 0xE5};
    std::vector<ImportDll> imps;
    imps.push_back(ImportDll{
        "KERNEL32.dll",
        {"WriteFile", "ReadFile", "CreateFileW", "GetModuleHandleA"}});
    const std::vector<std::uint8_t> file =
        PeBuilder()
            .section(".text", code, 0x1000, kSecExecRead)
            .section("UPX1", nops, 0x1000, kSecExecRead)
            .imports(imps)
            .entry(entry)
            .build();

    const Report r = occ::packer::identify(file.data(), file.size());
    check(r.valid, "contradiction: image parsed");
    check(has_candidate(r, "UPX"), "contradiction: UPX candidate present");
    const Candidate& c = r.candidates[0];
    check(c.confidence < 0.40,
          "contradiction: confidence stays below the low line");
    check(c.low_confidence, "contradiction: candidate flagged low-confidence");
    check(has_evidence(c, Evidence::Kind::Inconsistency),
          "contradiction: inconsistency evidence present");
    check(r.verdict.find("unpacked") != std::string::npos,
          "contradiction: verdict does not claim packed");
}

void test_identify_file() {
    static const std::uint8_t kPattern[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x90,
        0xC3};
    std::vector<std::uint8_t> code(0x1000);
    fill_pattern(code, kPattern, sizeof(kPattern));
    std::vector<std::uint8_t> entry = {0x55, 0x48, 0x89, 0xE5};
    std::vector<ImportDll> imps;
    imps.push_back(ImportDll{
        "KERNEL32.dll",
        {"WriteFile", "ReadFile", "CreateFileW", "GetModuleHandleA"}});
    const std::vector<std::uint8_t> file =
        PeBuilder()
            .section(".text", code, 0x1000, kSecExecRead)
            .imports(imps)
            .entry(entry)
            .build();

    std::FILE* f = std::fopen("/tmp/test_packer_clean.dll", "wb");
    check(f != nullptr, "identify_file: can open the scratch file");
    if (f == nullptr) {
        return;
    }
    const std::size_t written =
        std::fwrite(file.data(), 1, file.size(), f);
    std::fclose(f);
    check(written == file.size(), "identify_file: scratch file written");

    const Report r = occ::packer::identify_file("/tmp/test_packer_clean.dll");
    check(r.valid, "identify_file: image parsed");
    check(r.candidates.empty(), "identify_file: no candidates");
    check(r.verdict == "unpacked", "identify_file: verdict is unpacked");
}

}  // namespace

int main() {
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("-- %s\n", name);
        std::fflush(stdout);
        fn();
    };
    run("upx_shape", test_upx_shape);
    run("upx_dotted_shape", test_upx_dotted_shape);
    run("generic_packer", test_generic_packer);
    run("clean_pe", test_clean_pe);
    run("name_entropy_contradiction", test_name_entropy_contradiction);
    run("identify_file", test_identify_file);
    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

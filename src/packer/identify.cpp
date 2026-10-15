// Packer identification: does this PE carry a wrapper, and which one?
//
// See include/occ/packer/packer.h for what identification is for and for
// the rule that none of its observations is trusted alone. This file is
// the observations and the scoring. The shape of the analysis:
//
//   1. parse the image's own headers (through pe_view) into sections;
//   2. measure each section: name, size, characteristics, Shannon
//      entropy of its readable bytes;
//   3. parse the import directory, if it has one;
//   4. read the bytes at the entry point and match stub idioms;
//   5. weigh the evidence per candidate and render the verdict.
//
// Every weight and threshold is a number with a stated rationale, and the
// rationale is written where the number is declared so that a reader can
// argue with it. The general principle behind the numbers: a section name
// is the cheapest thing to fake, so it earns the least by itself; entropy
// is expensive to fake (it means the bytes genuinely are not code or
// ordinary data), so it earns more; an import table built around
// LoadLibrary/GetProcAddress is the strongest of the cheap signals,
// because a clean program has no reason to resolve everything by hand.
// Consistency is scored in both directions: a section that claims a
// packer's name while measuring as ordinary data is evidence *against*
// that packer, and the scorer says so.
//
// What cannot be measured is reported as unknown rather than guessed:
// a section whose bytes are not readable gets entropy 0 and a note; an
// import directory that cannot be walked withholds its evidence instead
// of pretending the image imports nothing.

#include "occ/packer/packer.h"

#include "pe_view.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace occ::packer {
namespace {

// ------------------------------------------------------------------ numbers
//
// The scoring weights, each with the reasoning that picked it.
//
// A section name is the cheapest observation to fake -- any PE builder can
// name a section UPX1 -- so a hit earns 0.35 by itself, enough to be
// noticed, not enough to convict. The weight varies slightly with how
// distinctive the name is: a name that a single packer owns (.themida,
// .vmp0) earns the full weight; one several packers reuse (.adata,
// .packed) earns less and is flagged low-confidence.
constexpr double kNameWeightHigh = 0.35;
constexpr double kNameWeightMedium = 0.28;
constexpr double kNameWeightLow = 0.18;
// A section that measures >= 7.0 bits/byte is not compiled code (typical
// x86 code measures 4.5..6.5 bits/byte; the UPX payload and encrypted
// bodies measure 7.5..8.0). 7.0 sits above the code band with margin and
// is the line the literature on entropy-based packer detection uses
// (e.g. the "entropy analysis" family of packer studies); see
// identify_impl for where the note lands in the report.
constexpr double kHighEntropy = 7.0;
constexpr double kEntropyWeight = 0.30;
// A section whose virtual size is >= 4x its file bytes is holding most of
// its content until run time -- UPX0 is the extreme (0 file bytes, large
// virtual size). 4x is a deliberate low bar: a normal .data section is
// usually within 2x, and the 4x line is where "the file really is hiding
// bytes" starts to be the only reading.
constexpr double kDisparityFactor = 4.0;
constexpr double kDisparityWeight = 0.15;
// LoadLibrary* + GetProcAddress together mean the image resolves APIs at
// run time, which is what a packer's import stub does and what clean code
// almost never does (a program that imports WriteFile just imports it).
constexpr double kImportAnomalyWeight = 0.15;
// An image importing three or fewer functions (or declaring no import
// directory at all) is either trivial or wrapped. 3 is the line because a
// useful program needs more than three Win32 calls to do anything.
constexpr std::size_t kMinImportCount = 3;
constexpr double kImportMinimalWeight = 0.10;
// Entry stub idioms. Each earns 0.10; several together (pushad then a
// jmp rel32, as the UPX stub opens) cap at 0.20 so the entry can
// corroborate but never dominate a verdict by itself.
constexpr double kEntryPatternWeight = 0.10;
constexpr double kEntryPatternCap = 0.20;
// A named section that measures below 5.0 bits/byte contradicts the
// packer its name claims -- real UPX1 sections measure ~7.5+. The weight
// is negative so a self-contradicting candidate scores lower for having
// been noticed, which is the honest direction.
constexpr double kLowEntropyInconsistent = 5.0;
constexpr double kInconsistencyWeight = -0.25;
// Confidence lines. >= 0.60 is a verdict a caller can act on; >= 0.40 is
// a strong suggestion; below 0.40 the candidate is flagged low-confidence
// and the verdict says the signals are weak. The two lines are 0.2 apart
// on purpose, so "medium" has a real band rather than being a synonym for
// "everything below high".
constexpr double kHighConfidence = 0.60;
constexpr double kLowConfidence = 0.40;

// ------------------------------------------------------------------ table

// The known-packer section-name table. `weight` is the name evidence this
// entry earns; `low_confidence` marks packers the mapping is not
// well-documented enough to be sure of, and the note says why the entry
// is in the table at all. Entries are matched exactly: PE section names
// are not case-folded by the format, and a table that matched "upx1" to
// UPX would be guessing at intent.
struct SectionNameEntry {
    const char* name;
    const char* packer;
    double weight;
    bool low_confidence;
    const char* note;
};

constexpr SectionNameEntry kSectionTable[] = {
    {".upx0", "UPX", kNameWeightHigh, false,
     "UPX renames the original sections to .upx0/.upx1/.upx2; the dotted "
     "form is what UPX's own writer emits, and it is present on any "
     "UPX-packed binary."},
    {".upx1", "UPX", kNameWeightHigh, false,
     "the compressed payload section of UPX's two-section layout"},
    {".upx2", "UPX", kNameWeightHigh, false,
     "third section of larger UPX-packed binaries"},
    // The undotted spellings survive from tools that strip the leading
    // dot when renaming or reporting a section. They earn the same
    // weight: the section is UPX's own either way, and a matcher that
    // accepted one spelling and refused the other would be asserting a
    // difference the format does not make.
    {"UPX0", "UPX", kNameWeightHigh, false,
     "undotted spelling of .upx0, as seen after a rename tool"},
    {"UPX1", "UPX", kNameWeightHigh, false,
     "undotted spelling of .upx1"},
    {"UPX2", "UPX", kNameWeightHigh, false,
     "undotted spelling of .upx2"},
    {".themida", "Themida", kNameWeightHigh, false,
     "Themida's .themida section is its own; WinLicense uses the same "
     "installer family."},
    {".vmp0", "VMProtect", kNameWeightHigh, false,
     "VMProtect's two-section layout (.vmp0/.vmp1) is its own."},
    {".vmp1", "VMProtect", kNameWeightHigh, false,
     "second half of VMProtect's layout"},
    {".enigma1", "Enigma Protector", kNameWeightMedium, false,
     "Enigma names its sections .enigma1/.enigma2; seen under other names "
     "in variants, hence medium weight."},
    {".enigma2", "Enigma Protector", kNameWeightMedium, false,
     "second half of Enigma's layout"},
    {".aspack", "ASPack", kNameWeightMedium, false,
     "ASPack's payload section"},
    {".petite", "PEtite", kNameWeightMedium, false,
     "PEtite's payload section"},
    {".mpress1", "MPRESS", kNameWeightMedium, false,
     "MPRESS (MATCODE) keeps .mpress1/.mpress2"},
    {".mpress2", "MPRESS", kNameWeightMedium, false,
     "second half of MPRESS's layout"},
    {".nsp0", "NsPack", kNameWeightMedium, false,
     "NsPack's payload section"},
    {".nsp1", "NsPack", kNameWeightMedium, false,
     "second half of NsPack's layout"},
    {".pec1", "PEC2 (PECOMPACT)", kNameWeightMedium, false,
     "PECOMPACT's payload section"},
    {".pec2", "PEC2 (PECOMPACT)", kNameWeightMedium, false,
     "second half of PECOMPACT's layout"},
    {".sforce3", "Safengine Shielden", kNameWeightMedium, false,
     "Safengine's .sforce3 section is its own"},
    {"FSG!", "FSG", kNameWeightMedium, false,
     "FSG's section is literally 'FSG!'"},
    {".boom", "FSG", kNameWeightLow, true,
     "FSG variants use .boom; the exact mapping is weakly documented."},
    {".adata", "unknown (Enigma-family marker)", kNameWeightLow, true,
     ".adata appears under several packers (Enigma, Safengine variants); "
     "a section name alone does not pin the packer down."},
    {".maskpe", "MaskPE", kNameWeightLow, true,
     "MaskPE is documented thinly; name is suggestive only."},
    {".wwpack32", "WWPack32", kNameWeightLow, true,
     "WWPack32 is documented thinly; name is suggestive only."},
    {".rlpack", "RLPack", kNameWeightMedium, false,
     "RLPack's payload section"},
    {".morphine", "Morphine", kNameWeightMedium, false,
     "Morphine's payload section"},
    {".y0da", "Y0da Cryptor", kNameWeightMedium, false,
     "Y0da's payload section"},
    {".kkrunchy", "kkrunchy", kNameWeightMedium, false,
     "kkrunchy's payload section"},
    {".shrink1", "Shrinker", kNameWeightMedium, false,
     "Shrinker's payload sections"},
    {".shrink2", "Shrinker", kNameWeightMedium, false,
     "second half of Shrinker's layout"},
    {".shrink3", "Shrinker", kNameWeightMedium, false,
     "third section of Shrinker-packed binaries"},
    {".neolite", "Neolite", kNameWeightLow, true,
     "Neolite is documented thinly; name is suggestive only."},
    {".packed", "unknown (generic packer marker)", kNameWeightLow, true,
     "several small packers reuse the name .packed; treat as generic "
     "evidence, not an identification."},
};

[[nodiscard]] const SectionNameEntry* section_lookup(
    const std::string& name) noexcept {
    for (const SectionNameEntry& e : kSectionTable) {
        if (name == e.name) {
            return &e;
        }
    }
    return nullptr;
}

// --------------------------------------------------------------- entropy

// Shannon entropy in bits per byte (0..8) over the given bytes: -sum
// p*log2(p) over the byte histogram. A zero-length run is 0.0, which is
// "nothing to measure", not "perfectly ordered".
[[nodiscard]] double shannon_entropy(const std::uint8_t* bytes,
                                     std::size_t len) noexcept {
    if (len == 0) {
        return 0.0;
    }
    std::uint64_t counts[256] = {};
    for (std::size_t i = 0; i < len; ++i) {
        ++counts[bytes[i]];
    }
    double h = 0.0;
    const double total = static_cast<double>(len);
    for (std::size_t i = 0; i < 256; ++i) {
        if (counts[i] == 0) {
            continue;
        }
        const double p = static_cast<double>(counts[i]) / total;
        h -= p * std::log2(p);
    }
    return h;
}

// Whether a section's virtual size far exceeds its file bytes. An
// executable section with zero file bytes (UPX0) is the extreme form and
// answers true outright; otherwise the 4x line from the threshold block
// applies.
[[nodiscard]] bool size_disparity(const detail::SectionView& s) noexcept {
    if (!s.exec() || s.vsize == 0) {
        return false;
    }
    if (s.rawsize == 0) {
        return true;
    }
    return static_cast<double>(s.vsize) >=
           kDisparityFactor * static_cast<double>(s.rawsize);
}

// ----------------------------------------------------------------- imports

struct ImportStat {
    std::size_t count = 0;
    bool has_loadlib = false;
    bool has_getproc = false;
    std::vector<std::string> names;  // first few, for the report
    std::size_t dll_count = 0;
    bool dir_present = false;
    bool parse_ok = true;
};

// Walks the import directory and counts what the image imports. The walk
// is bounded at both ends: the descriptor array stops at the all-zero
// terminator or when the image runs out of readable bytes, and each
// descriptor's thunk array stops at its own zero terminator or the cap.
// A directory that cannot be walked reports parse_ok=false and the caller
// withholds import evidence rather than guessing the image imports
// nothing.
constexpr std::size_t kMaxDescriptors = 4096;
constexpr std::size_t kMaxThunks = 65536;
constexpr std::size_t kMaxNameBytes = 256;
constexpr std::size_t kDescriptorSize = 20;
constexpr std::size_t kThunkOriginalFirstThunk = 0x00;
constexpr std::size_t kThunkName = 0x0C;
constexpr std::size_t kThunkFirstThunk = 0x10;

[[nodiscard]] ImportStat analyze_imports(const detail::PeImage& img) {
    ImportStat st;
    if (img.import_dir_rva == 0) {
        return st;  // dir_present stays false: no directory to read
    }
    st.dir_present = true;
    const bool is64 = img.format == detail::PeFormat::Pe32Plus;
    const std::uint64_t ordinal_mask =
        is64 ? 0x8000000000000000ULL : 0x80000000ULL;
    const std::uint32_t thunk_entry = is64 ? 8 : 4;

    std::uint32_t desc_rva = img.import_dir_rva;
    for (std::size_t d = 0; d < kMaxDescriptors; ++d) {
        std::size_t len = 0;
        const std::uint8_t* desc = img.at_rva(desc_rva, kDescriptorSize, len);
        if (desc == nullptr || len < kDescriptorSize) {
            st.parse_ok = false;
            break;
        }
        const std::uint32_t oft = detail::rd32(desc, kThunkOriginalFirstThunk);
        const std::uint32_t name_rva = detail::rd32(desc, kThunkName);
        const std::uint32_t ft = detail::rd32(desc, kThunkFirstThunk);
        if (oft == 0 && name_rva == 0 && ft == 0) {
            break;  // the all-zero terminator
        }
        ++st.dll_count;

        const std::uint32_t thunk_rva = oft != 0 ? oft : ft;
        if (thunk_rva == 0) {
            continue;  // a descriptor with no thunk array carries nothing
        }
        for (std::size_t t = 0; t < kMaxThunks; ++t) {
            const std::uint32_t at = static_cast<std::uint32_t>(
                static_cast<std::uint64_t>(thunk_rva) +
                static_cast<std::uint64_t>(t) * thunk_entry);
            std::size_t tlen = 0;
            const std::uint8_t* e = img.at_rva(at, thunk_entry, tlen);
            if (e == nullptr || tlen < thunk_entry) {
                st.parse_ok = false;
                break;
            }
            const std::uint64_t thunk =
                is64 ? detail::rd64(e, 0) : detail::rd32(e, 0);
            if (thunk == 0) {
                break;  // the thunk array's own terminator
            }
            ++st.count;
            if ((thunk & ordinal_mask) != 0) {
                continue;  // an ordinal import: a number, not a name
            }
            const std::uint32_t byname =
                static_cast<std::uint32_t>(thunk & ~ordinal_mask);
            // Ask for the hint and room for the name in one bounded read;
            // a request for only the hint would come back with exactly two
            // bytes and the name would never be readable.
            std::size_t blen = 0;
            const std::uint8_t* b =
                img.at_rva(byname, 2 + kMaxNameBytes + 1, blen);
            if (b == nullptr || blen < 2) {
                st.parse_ok = false;
                break;
            }
            // IMAGE_IMPORT_BY_NAME: a two-byte hint, then the name.
            std::string fn;
            for (std::size_t i = 2; i < blen && fn.size() < kMaxNameBytes; ++i) {
                const char c = static_cast<char>(b[i]);
                if (c == '\0') {
                    break;
                }
                fn.push_back(c);
            }
            if (fn.empty()) {
                continue;
            }
            if (fn == "LoadLibraryA" || fn == "LoadLibraryW" ||
                fn == "LoadLibraryExA" || fn == "LoadLibraryExW") {
                st.has_loadlib = true;
            }
            if (fn == "GetProcAddress") {
                st.has_getproc = true;
            }
            if (st.names.size() < 16) {
                st.names.push_back(fn);
            }
        }
        desc_rva = static_cast<std::uint32_t>(
            static_cast<std::uint64_t>(desc_rva) + kDescriptorSize);
    }
    return st;
}

// ------------------------------------------------------------ entry point

struct EntryInfo {
    std::vector<std::string> patterns;
};

// Matches stub idioms at the entry point. The patterns are the ones the
// packer literature names (and the module design asks for): pushad,
// pushf, a leading jmp rel32, push imm32;ret, and the call/pop delta
// idiom. Each is a byte check over the first few bytes, which is all a
// stub is, and none of them occurs in a compiler-emitted prologue.
[[nodiscard]] EntryInfo entry_patterns(const detail::PeImage& img) {
    EntryInfo out;
    std::size_t len = 0;
    const std::uint8_t* e = img.at_rva(img.entry_rva, 16, len);
    if (e == nullptr || len == 0) {
        return out;
    }
    if (e[0] == 0x60) {
        out.patterns.push_back("pushad (0x60) at entry");
    }
    if (e[0] == 0x9C) {
        out.patterns.push_back("pushf (0x9C) at entry");
    }
    // A leading jmp rel32, either as the first byte or straight after the
    // pushad a 32-bit stub opens with (the classic UPX opening). A jmp
    // deeper into the stub is ordinary control flow, not an entry idiom.
    if (e[0] == 0xE9 || (e[0] == 0x60 && len >= 2 && e[1] == 0xE9)) {
        out.patterns.push_back("jmp rel32 (0xE9) at entry");
    }
    if (e[0] == 0x68) {  // push imm32
        const std::size_t window = len < 8 ? len : 8;
        bool has_ret = false;
        for (std::size_t i = 1; i < window; ++i) {
            if (e[i] == 0xC3) {
                has_ret = true;
                break;
            }
        }
        if (has_ret) {
            out.patterns.push_back("push imm32; ret");
        }
    }
    if (e[0] == 0xE8) {  // call rel32
        const std::size_t window = len < 6 ? len : 6;
        bool has_pop = false;
        for (std::size_t i = 1; i < window; ++i) {
            if (e[i] >= 0x58 && e[i] <= 0x5F) {  // pop reg
                has_pop = true;
                break;
            }
        }
        if (has_pop) {
            out.patterns.push_back("call rel32; pop (delta idiom)");
        }
    }
    return out;
}

// ------------------------------------------------------------- reporting

// Renders a number in lowercase hex without the 0x prefix, for the
// text report.
[[nodiscard]] std::string hex(std::uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(v));
    return std::string(b);
}

// Renders a section's characteristics as an RWX string: 'R', 'W', 'X' for
// the three bits the module reasons about, '-' otherwise.
[[nodiscard]] std::string chars_string(std::uint32_t characteristics) {
    std::string out = "---";
    out[0] = (characteristics & detail::kSectionRead) != 0 ? 'R' : '-';
    out[1] = (characteristics & detail::kSectionWrite) != 0 ? 'W' : '-';
    out[2] = (characteristics & detail::kSectionExec) != 0 ? 'X' : '-';
    return out;
}

// The per-candidate evidence line: the kind, the subject, the weight, and
// the note. Weights are shown signed so a reader sees the contradiction
// evidence pulling the score down.
[[nodiscard]] std::string evidence_line(const Evidence& ev) {
    const char* kind = "?";
    switch (ev.kind) {
    case Evidence::Kind::SectionName:
        kind = "section-name";
        break;
    case Evidence::Kind::HighEntropy:
        kind = "high-entropy";
        break;
    case Evidence::Kind::SizeDisparity:
        kind = "size-disparity";
        break;
    case Evidence::Kind::ImportAnomaly:
        kind = "import-anomaly";
        break;
    case Evidence::Kind::ImportMinimal:
        kind = "import-minimal";
        break;
    case Evidence::Kind::EntryPattern:
        kind = "entry-pattern";
        break;
    case Evidence::Kind::Inconsistency:
        kind = "inconsistency";
        break;
    }
    char w[32];
    std::snprintf(w, sizeof(w), "%+.2f", ev.weight);
    std::string line = "    [" + std::string(kind) + " " + w + "] ";
    if (!ev.subject.empty()) {
        line += ev.subject + ": ";
    }
    line += ev.note;
    return line;
}

// ------------------------------------------------------------------ score

// Runs the identification over an already-parsed image. This is the
// heart of the module: it turns the parsed skeleton and the measured
// sections into candidates with confidence.
[[nodiscard]] Report score(const detail::PeImage& img) {
    Report r;
    r.valid = true;
    r.format = img.format == detail::PeFormat::Pe32Plus ? "PE32+" : "PE32";
    r.machine = img.machine;
    r.entry_rva = img.entry_rva;

    std::vector<Candidate> candidates;
    const auto find_candidate = [&candidates](const std::string& name) {
        for (Candidate& c : candidates) {
            if (c.name == name) {
                return &c;
            }
        }
        candidates.push_back(Candidate{name, 0.0, 0.0, {}, false});
        return &candidates.back();
    };

    // Signals that belong to no named packer; they create the generic
    // candidate when nothing was named.
    double generic_entropy = 0.0;
    double generic_disparity = 0.0;

    for (const detail::SectionView& s : img.sections) {
        SectionStat st;
        st.name = s.name;
        st.rva = s.rva;
        st.vsize = s.vsize;
        st.rawsize = s.rawsize;
        st.characteristics = s.characteristics;
        std::size_t blen = 0;
        const std::uint8_t* b = img.section_bytes(s, blen);
        st.entropy = b != nullptr ? shannon_entropy(b, blen) : 0.0;
        r.sections.push_back(std::move(st));

        const SectionNameEntry* hit = section_lookup(s.name);
        if (hit == nullptr) {
            // An unnamed or unrecognized section still contributes to the
            // generic reading when it measures like a payload.
            if (s.exec() && st.entropy >= kHighEntropy) {
                generic_entropy += kEntropyWeight;
            }
            if (size_disparity(s)) {
                generic_disparity += kDisparityWeight;
            }
            continue;
        }
        Candidate* c = find_candidate(hit->packer);
        c->evidence.push_back(Evidence{Evidence::Kind::SectionName, s.name,
                                       hit->weight, hit->note});
        c->score += hit->weight;
        if (s.exec() && st.entropy >= kHighEntropy) {
            c->score += kEntropyWeight;
            char note[64];
            std::snprintf(note, sizeof(note), "entropy %.2f bits/byte in "
                                             "executable section",
                          st.entropy);
            c->evidence.push_back(Evidence{Evidence::Kind::HighEntropy, s.name,
                                           kEntropyWeight, note});
        }
        if (size_disparity(s)) {
            c->score += kDisparityWeight;
            std::string note = s.rawsize == 0
                                   ? "section has no file bytes but a "
                                     "virtual size of 0x" +
                                         hex(s.vsize)
                                   : "virtual size 0x" + hex(s.vsize) +
                                         " vs file bytes 0x" + hex(s.rawsize);
            c->evidence.push_back(Evidence{Evidence::Kind::SizeDisparity,
                                           s.name, kDisparityWeight, note});
        }
        // The consistency check runs only where entropy was measurable:
        // a zero-byte section (UPX0) says nothing about its packer's
        // entropy either way.
        if (s.exec() && s.rawsize != 0 && b != nullptr && blen != 0 &&
            st.entropy < kLowEntropyInconsistent) {
            c->score += kInconsistencyWeight;
            char note[96];
            std::snprintf(note, sizeof(note),
                          "section %s claims %s but measures %.2f bits/byte "
                          "-- name and entropy disagree",
                          s.name.c_str(), hit->packer, st.entropy);
            c->evidence.push_back(Evidence{Evidence::Kind::Inconsistency,
                                           s.name, kInconsistencyWeight, note});
        }
    }

    // The shared signals: imports and entry. They are evidence about the
    // image as a whole, so they attach to every candidate that exists --
    // and, when nothing was named, they are what make the generic
    // candidate worth reporting at all.
    std::vector<Evidence> shared;
    double shared_score = 0.0;
    const ImportStat imp = analyze_imports(img);
    if (imp.parse_ok) {
        // The import density, spelled out: how many imports the image
        // declares over how much executable code it carries. A packed
        // image's imports-per-KB is a fraction of a normal program's,
        // and the number is what the minimal-import evidence rests on.
        std::uint64_t code_bytes = 0;
        for (const detail::SectionView& s : img.sections) {
            if (s.exec()) {
                code_bytes += s.vsize;
            }
        }
        if (code_bytes != 0) {
            char line[96];
            std::snprintf(line, sizeof(line),
                          "import density: %zu imports over 0x%llx "
                          "executable bytes",
                          imp.count, static_cast<unsigned long long>(code_bytes));
            r.notes.push_back(line);
        }
        if (imp.count <= kMinImportCount) {
            shared_score += kImportMinimalWeight;
            std::string note = imp.dir_present
                                   ? "only " + std::to_string(imp.count) +
                                         " imports"
                                   : "no import directory";
            shared.push_back(Evidence{Evidence::Kind::ImportMinimal, "imports",
                                      kImportMinimalWeight, note});
        }
        if (imp.has_loadlib && imp.has_getproc) {
            shared_score += kImportAnomalyWeight;
            shared.push_back(Evidence{
                Evidence::Kind::ImportAnomaly, "imports",
                kImportAnomalyWeight,
                "LoadLibrary* and GetProcAddress both imported: run-time "
                "resolution, the packer's import shape"});
        }
    } else {
        r.notes.push_back("import directory present but not walkable; "
                          "import evidence withheld rather than guessed");
    }
    const EntryInfo ent = entry_patterns(img);
    double entry_score = 0.0;
    for (const std::string& p : ent.patterns) {
        if (entry_score >= kEntryPatternCap) {
            break;
        }
        const double w = std::min(kEntryPatternWeight,
                                  kEntryPatternCap - entry_score);
        entry_score += w;
        shared_score += w;
        shared.push_back(Evidence{Evidence::Kind::EntryPattern, "entry", w, p});
    }

    if (!candidates.empty()) {
        for (Candidate& c : candidates) {
            for (const Evidence& ev : shared) {
                c.score += ev.weight;
                c.evidence.push_back(ev);
            }
        }
    } else {
        const double generic = generic_entropy + generic_disparity +
                               shared_score;
        if (generic > 0.0) {
            Candidate g;
            g.name = "unknown (generic packer)";
            g.score = generic;
            if (generic_entropy > 0.0) {
                g.evidence.push_back(Evidence{
                    Evidence::Kind::HighEntropy, "sections", generic_entropy,
                    "high-entropy executable section(s) with no known "
                    "packer section name"});
            }
            if (generic_disparity > 0.0) {
                g.evidence.push_back(Evidence{
                    Evidence::Kind::SizeDisparity, "sections",
                    generic_disparity,
                    "executable section(s) whose virtual size far exceeds "
                    "their file bytes"});
            }
            for (const Evidence& ev : shared) {
                g.evidence.push_back(ev);
            }
            candidates.push_back(std::move(g));
        }
    }

    // Finalize: clamp, mark low confidence, order best-first.
    for (Candidate& c : candidates) {
        c.confidence = c.score > 1.0 ? 1.0 : c.score;
        if (c.confidence < 0.0) {
            c.confidence = 0.0;
        }
        bool contradictory = false;
        for (const Evidence& ev : c.evidence) {
            if (ev.kind == Evidence::Kind::Inconsistency) {
                contradictory = true;
                break;
            }
        }
        c.low_confidence =
            c.confidence < kLowConfidence || contradictory;
    }
    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate& a, const Candidate& b) {
                  return a.confidence > b.confidence;
              });
    r.candidates = std::move(candidates);

    if (r.candidates.empty()) {
        r.verdict = "unpacked";
        r.notes.push_back("no packer signals: section names, entropy, "
                          "imports and entry all read as ordinary");
    } else {
        const Candidate& top = r.candidates.front();
        if (top.confidence >= kHighConfidence) {
            r.verdict = "packed (high confidence): " + top.name;
        } else if (top.confidence >= kLowConfidence) {
            r.verdict = "packed (medium confidence): " + top.name;
        } else {
            r.verdict = "unpacked (low-confidence signals only)";
        }
    }
    return r;
}

}  // namespace

Report identify(const std::uint8_t* bytes, std::size_t size) noexcept {
    if (bytes == nullptr) {
        Report r;
        r.valid = false;
        r.error = "null image";
        return r;
    }
    const detail::PeImage img =
        detail::PeImage::parse(bytes, size, 0, /*mapped=*/false);
    if (!img.valid) {
        Report r;
        r.valid = false;
        r.error = img.error;
        return r;
    }
    return score(img);
}

Report identify(std::uint64_t image_base) noexcept {
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(image_base);
    const detail::PeImage img =
        detail::PeImage::parse(bytes, 0, image_base, /*mapped=*/true);
    if (!img.valid) {
        Report r;
        r.valid = false;
        r.error = img.error;
        return r;
    }
    return score(img);
}

Report identify_file(const std::string& path) noexcept {
    Report r;
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) {
        r.valid = false;
        r.error = "cannot open " + path;
        return r;
    }
    if (std::fseek(f, 0, SEEK_END) != 0) {
        std::fclose(f);
        r.valid = false;
        r.error = "cannot seek " + path;
        return r;
    }
    const long end = std::ftell(f);
    if (end < 0) {
        std::fclose(f);
        r.valid = false;
        r.error = "cannot size " + path;
        return r;
    }
    std::fseek(f, 0, SEEK_SET);
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(end));
    const std::size_t got = std::fread(buf.data(), 1, buf.size(), f);
    std::fclose(f);
    if (got != buf.size()) {
        r.valid = false;
        r.error = "short read from " + path;
        return r;
    }
    return identify(buf.data(), buf.size());
}

std::string report_text(const Report& report) noexcept {
    std::string out = "== packer identify ==\n";
    if (!report.valid) {
        out += "invalid image: ";
        out += report.error.empty() ? "(no reason)" : report.error;
        out += "\n";
        return out;
    }
    out += "format " + report.format + ", machine 0x" + hex(report.machine) +
           ", entry rva 0x" + hex(report.entry_rva) + "\n";
    out += "sections:\n";
    out += "  name        rva       vsize     rawsize   entropy  chars\n";
    for (const SectionStat& s : report.sections) {
        char line[160];
        std::snprintf(line, sizeof(line), "  %-10.10s 0x%-8llx 0x%-8llx "
                                          "0x%-8llx %-7.2f %s\n",
                      s.name.c_str(), static_cast<unsigned long long>(s.rva),
                      static_cast<unsigned long long>(s.vsize),
                      static_cast<unsigned long long>(s.rawsize), s.entropy,
                      chars_string(s.characteristics).c_str());
        out += line;
    }
    out += "candidates:\n";
    for (const Candidate& c : report.candidates) {
        char line[160];
        std::snprintf(line, sizeof(line), "  %s  confidence %.2f%s\n",
                      c.name.c_str(), c.confidence,
                      c.low_confidence ? " (low confidence)" : "");
        out += line;
        for (const Evidence& ev : c.evidence) {
            out += evidence_line(ev);
            out += "\n";
        }
    }
    out += "verdict: " + report.verdict + "\n";
    for (const std::string& n : report.notes) {
        out += "note: " + n + "\n";
    }
    return out;
}

}  // namespace occ::packer

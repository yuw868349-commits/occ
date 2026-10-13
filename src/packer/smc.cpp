// Self-modifying code analysis: what the runtime's write records mean.
//
// See include/occ/packer/packer.h for the place of this analysis in the
// module and for the wiring note: the records come from the runtime's
// memwatch, whose plumbing lives in occ::runtime and is not touched here.
// This file is the classification itself, which needs no runtime: given
// the image's section layout and a list of (write_va, rip) records, it
// says which writes landed in executable code, which data, and where the
// repeated writes have the shape of a decryption loop.
//
// The thresholds here are the ones that separate "a program that patches
// two bytes once" from "a loop that decrypts a region": 8 writes into a
// single section, or 4 writes into one 4K page. Both are deliberately
// permissive rather than strict. 4 in a page is four stores -- a loop
// touching one byte per iteration reaches it almost immediately, and a
// program doing four unrelated stores in one page is a program the
// analyst will want to look at anyway. 8 per section is the same line at
// section granularity, for a loop wide enough to span pages. The report
// carries the counts, so a reader can tighten the lines without rerunning
// the analysis.

#include "occ/packer/packer.h"

#include "pe_view.h"

#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace occ::packer {
namespace {

// The decryption-loop thresholds, with the rationale above.
constexpr std::size_t kDecryptSectionWrites = 8;  // per section
constexpr std::size_t kDecryptPageWrites = 4;     // per 4K page
constexpr std::uint64_t kDecryptWindow = 4096;    // the page window

// Renders a number in lowercase hex for notes.
[[nodiscard]] std::string hex(std::uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(v));
    return std::string(b);
}

// The shared classification core. `img` supplies the section layout; the
// writes are absolute guest addresses, converted through the image base.
[[nodiscard]] SMCReport classify(const detail::PeImage& img,
                                 const std::vector<SMCWrite>& writes) {
    SMCReport out;
    out.total_writes = writes.size();
    if (!img.valid) {
        out.notes.push_back("image headers unreadable: " + img.error);
        return out;
    }

    std::vector<std::size_t> per_section(img.sections.size(), 0);
    // Writes per (section, page): the page is the absolute write address
    // divided by the window, so two sections never share a page bucket.
    std::map<std::pair<std::size_t, std::uint64_t>, std::size_t> per_page;

    for (const SMCWrite& w : writes) {
        if (img.image_base_va == 0 || w.write_va < img.image_base_va) {
            out.notes.push_back("write at 0x" + hex(w.write_va) +
                                " is below the image base; not classified");
            continue;
        }
        const std::uint64_t rva = w.write_va - img.image_base_va;

        // The section whose virtual range covers the write. A section
        // with no virtual size covers nothing.
        std::size_t idx = img.sections.size();
        for (std::size_t i = 0; i < img.sections.size(); ++i) {
            const detail::SectionView& s = img.sections[i];
            if (s.vsize != 0 && rva >= static_cast<std::uint64_t>(s.rva) &&
                rva < static_cast<std::uint64_t>(s.rva) + s.vsize) {
                idx = i;
                break;
            }
        }
        if (idx == img.sections.size()) {
            out.notes.push_back("write at 0x" + hex(w.write_va) +
                                " (rva 0x" + hex(rva) +
                                ") lands in no section; not classified");
            continue;
        }
        const detail::SectionView& s = img.sections[idx];
        ++per_section[idx];
        ++per_page[{idx, w.write_va / kDecryptWindow}];

        if (s.exec()) {
            out.findings.push_back(SMCEvidence{
                SMCKind::WriteToExec, w.write_va, w.rip, s.name,
                "write into executable section " +
                    (s.name.empty() ? std::string("<anon>") : s.name)});
        } else {
            out.findings.push_back(SMCEvidence{
                SMCKind::DataWrite, w.write_va, w.rip, s.name,
                "write into data section " +
                    (s.name.empty() ? std::string("<anon>") : s.name)});
        }
    }

    // The decryption-loop shape, at both granularities. The section-level
    // finding fires once per section with its total; the page-level one
    // fires per page, because several hot pages in one section is a
    // different observation from one.
    for (std::size_t i = 0; i < img.sections.size(); ++i) {
        const detail::SectionView& s = img.sections[i];
        if (!s.exec() || per_section[i] < kDecryptSectionWrites) {
            continue;
        }
        out.findings.push_back(SMCEvidence{
            SMCKind::DecryptLoop, img.image_base_va + s.rva, 0, s.name,
            std::to_string(per_section[i]) + " writes into executable "
            "section " +
                (s.name.empty() ? std::string("<anon>") : s.name) +
                " (>= " + std::to_string(kDecryptSectionWrites) +
                "): the decryption-loop shape"});
    }
    for (const auto& [key, n] : per_page) {
        const std::size_t idx = key.first;
        if (idx >= img.sections.size() || !img.sections[idx].exec() ||
            n < kDecryptPageWrites) {
            continue;
        }
        const detail::SectionView& s = img.sections[idx];
        out.findings.push_back(SMCEvidence{
            SMCKind::DecryptLoop, key.second * kDecryptWindow, 0, s.name,
            std::to_string(n) + " writes within one 4K page (>= " +
                std::to_string(kDecryptPageWrites) + "): the "
                "decryption-loop shape"});
    }
    return out;
}

}  // namespace

SMCReport analyze_smc(const std::uint8_t* image, std::size_t size,
                      std::uint64_t image_base,
                      const std::vector<SMCWrite>& writes) noexcept {
    const detail::PeImage img =
        detail::PeImage::parse(image, size, image_base, /*mapped=*/false);
    return classify(img, writes);
}

SMCReport analyze_smc(std::uint64_t image_base,
                      const std::vector<SMCWrite>& writes) noexcept {
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(image_base);
    const detail::PeImage img =
        detail::PeImage::parse(bytes, 0, image_base, /*mapped=*/false);
    return classify(img, writes);
}

std::vector<SMCHint> static_smc_hints(const std::uint8_t* image,
                                      std::size_t size) noexcept {
    const detail::PeImage img =
        detail::PeImage::parse(image, size, 0, /*mapped=*/false);
    std::vector<SMCHint> out;
    if (!img.valid) {
        return out;
    }
    for (const detail::SectionView& s : img.sections) {
        if (!s.exec() || !s.writable()) {
            continue;
        }
        SMCHint h;
        h.section = s.name;
        h.rva = s.rva;
        h.vsize = s.vsize;
        h.characteristics = s.characteristics;
        h.note = "RWX section: writable and executable at once, a "
                 "potential self-modifying-code target";
        out.push_back(std::move(h));
    }
    return out;
}

std::vector<SMCHint> static_smc_hints(std::uint64_t image_base) noexcept {
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(image_base);
    return static_smc_hints(bytes, 0);
}

}  // namespace occ::packer

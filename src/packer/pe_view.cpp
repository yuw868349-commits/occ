// The mechanics of the internal PE view: parse the skeleton every pass
// needs, and answer RVA-to-bytes in whichever layout the caller has.
//
// See pe_view.h for what the two layouts are and why they read bytes
// differently. This file is the reading itself, with every offset spelled
// against the PE format's own layout.

#include "pe_view.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace occ::packer::detail {

std::uint16_t rd16(const std::uint8_t* p, std::size_t at) noexcept {
    return static_cast<std::uint16_t>(p[at]) |
           static_cast<std::uint16_t>(p[at + 1] << 8);
}

std::uint32_t rd32(const std::uint8_t* p, std::size_t at) noexcept {
    return static_cast<std::uint32_t>(p[at]) |
           (static_cast<std::uint32_t>(p[at + 1]) << 8) |
           (static_cast<std::uint32_t>(p[at + 2]) << 16) |
           (static_cast<std::uint32_t>(p[at + 3]) << 24);
}

std::uint64_t rd64(const std::uint8_t* p, std::size_t at) noexcept {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | p[at + static_cast<std::size_t>(i)];
    }
    return v;
}

namespace {

// The optional-header layout offsets this module reads, shared between
// the PE32 (magic 0x10B) and PE32+ (magic 0x20B) layouts. The fields this
// module cares about -- entry RVA, sizes, the section table position --
// sit at the same offsets in both; only the data directory does not, and
// its offset is chosen below by the magic.
constexpr std::size_t kOptionalEntryRvaOff = 0x10;
constexpr std::size_t kOptionalSizeOfImageOff = 0x38;
constexpr std::size_t kOptionalSizeOfHeadersOff = 0x3C;
// The data directory: PE32's starts at 0x60 because its ImageBase is four
// bytes, PE32+'s at 0x70 because its ImageBase is eight. The import table
// is the second eight-byte entry of the directory.
constexpr std::size_t kDirsPe32 = 0x60;
constexpr std::size_t kDirsPe32Plus = 0x70;
constexpr std::size_t kDirEntrySize = 8;
constexpr std::size_t kImportDirIndex = 1;
// The COFF header sits after the four-byte PE signature. Its fields below
// are offsets *from the COFF header's own start*; the signature is added
// where the fields are read, so the offsets stay the format's own.
constexpr std::size_t kCoffMachineOff = 0x00;
constexpr std::size_t kCoffSectionCountOff = 0x02;
constexpr std::size_t kCoffOptionalSizeOff = 0x10;
constexpr std::size_t kCoffSize = 20;
constexpr std::size_t kPeSignatureSize = 4;
constexpr std::size_t kE_lfanewOff = 0x3C;

// Reads a section's name: up to eight bytes, cut at the first NUL. A
// section whose name field is all NULs -- a linker-generated name is not
// the only way -- comes out empty, and a caller that needs to distinguish
// "anonymous" from "named" checks the string.
[[nodiscard]] std::string section_name(const std::uint8_t* p,
                                       std::size_t at) noexcept {
    std::string out;
    out.reserve(8);
    for (std::size_t i = 0; i < 8; ++i) {
        const char c = static_cast<char>(p[at + i]);
        if (c == '\0') {
            break;
        }
        out.push_back(c);
    }
    return out;
}

}  // namespace

PeImage PeImage::parse(const std::uint8_t* bytes, std::size_t size,
                       std::uint64_t image_base_va, bool mapped) noexcept {
    PeImage img;
    img.base = bytes;
    img.limit = size;
    img.image_base_va = image_base_va;
    img.mapped = mapped;
    if (bytes == nullptr) {
        img.error = "null image";
        return img;
    }

    // Header reads are bounded by the buffer when one was given; without
    // one (the mapped runtime form) they trust the mapping the way the
    // runtime's own readers do. Once SizeOfImage is known it becomes the
    // bound for section reads in mapped mode.
    const std::size_t header_limit =
        size == 0 ? static_cast<std::size_t>(-1) : size;
    const auto have = [header_limit](std::size_t at,
                                     std::size_t need) noexcept -> bool {
        return at <= header_limit && need <= header_limit - at;
    };

    if (!have(0, 2) || rd16(bytes, 0) != 0x5A4D) {  // 'MZ'
        img.error = "no MZ header";
        return img;
    }
    if (!have(kE_lfanewOff, 4)) {
        img.error = "e_lfanew out of range";
        return img;
    }
    const std::uint32_t pe_at = rd32(bytes, kE_lfanewOff);
    if (!have(pe_at, kPeSignatureSize) ||
        rd32(bytes, pe_at) != 0x00004550) {  // "PE\0\0"
        img.error = "no PE signature at e_lfanew";
        return img;
    }
    if (!have(pe_at + kPeSignatureSize + kCoffSize, kCoffSize)) {
        img.error = "COFF header truncated";
        return img;
    }
    const std::size_t coff =
        static_cast<std::size_t>(pe_at) + kPeSignatureSize;
    img.machine = rd16(bytes, coff + kCoffMachineOff);
    img.section_count = rd16(bytes, coff + kCoffSectionCountOff);
    const std::uint16_t optional_size =
        rd16(bytes, coff + kCoffOptionalSizeOff);

    // The optional header follows the COFF header: e_lfanew + signature +
    // COFF size. The signature is part of that arithmetic, and forgetting
    // it lands the reader four bytes too early -- in the COFF
    // characteristics, which look nothing like an optional-header magic.
    const std::size_t optional =
        static_cast<std::size_t>(pe_at) + kPeSignatureSize + kCoffSize;
    if (!have(optional, 2)) {
        img.error = "optional header truncated";
        return img;
    }
    const std::uint16_t magic = rd16(bytes, optional);
    if (magic == 0x20B) {
        img.format = PeFormat::Pe32Plus;
    } else if (magic == 0x10B) {
        img.format = PeFormat::Pe32;
    } else {
        img.error = "optional header magic is neither PE32 nor PE32+";
        return img;
    }
    // The fields below sit within the first 0x3C bytes of the optional
    // header in both layouts; an optional header smaller than that cannot
    // carry them.
    const std::size_t need_optional = 0x3C + 4;
    if (optional_size < need_optional || !have(optional, need_optional)) {
        img.error = "optional header too small for the fields needed";
        return img;
    }
    img.entry_rva = rd32(bytes, optional + kOptionalEntryRvaOff);
    img.image_size = rd32(bytes, optional + kOptionalSizeOfImageOff);
    img.size_of_headers = rd32(bytes, optional + kOptionalSizeOfHeadersOff);

    // In mapped mode the image's own SizeOfImage bounds section reads;
    // in buffer mode the buffer size does, and the file may be larger
    // than SizeOfImage but never smaller than the headers.
    if (mapped) {
        img.limit = static_cast<std::size_t>(img.image_size);
    }

    const std::size_t section_table = optional + optional_size;
    if (!have(section_table,
              static_cast<std::size_t>(img.section_count) * kSectionEntrySize)) {
        img.error = "section table truncated";
        return img;
    }
    for (std::uint16_t i = 0; i < img.section_count; ++i) {
        const std::size_t entry = section_table +
                                  static_cast<std::size_t>(i) * kSectionEntrySize;
        SectionView s;
        s.name = section_name(bytes, entry + kSectionNameOff);
        s.vsize = rd32(bytes, entry + kSectionVirtualSizeOff);
        s.rva = rd32(bytes, entry + kSectionVirtualAddressOff);
        s.rawsize = rd32(bytes, entry + kSectionRawSizeOff);
        s.rawptr = rd32(bytes, entry + kSectionRawPointerOff);
        s.characteristics = rd32(bytes, entry + kSectionCharacteristicsOff);
        img.sections.push_back(std::move(s));
    }

    // The data directory, and within it the import directory. A directory
    // RVA of zero is the format's way of saying "no such directory"; it is
    // kept as zero and the import analysis treats it as absent rather than
    // trying to read whatever lives at RVA 0.
    if (optional_size >= (img.format == PeFormat::Pe32Plus ? 0x70 : 0x60) +
                             kDirEntrySize * (kImportDirIndex + 1)) {
        const std::size_t dirs =
            optional + (img.format == PeFormat::Pe32Plus ? kDirsPe32Plus
                                                         : kDirsPe32);
        const std::size_t imp = dirs + kImportDirIndex * kDirEntrySize;
        img.import_dir_rva = rd32(bytes, imp);
        img.import_dir_size = rd32(bytes, imp + 4);
    }
    // A directory entry outside the header area still reads fine from a
    // file buffer, but it names a location the image does not cover; the
    // import analysis's own at_rva calls refuse it when that happens.

    img.valid = true;
    return img;
}

const std::uint8_t* PeImage::at_rva(std::uint32_t rva, std::size_t need,
                                    std::size_t& len) const noexcept {
    len = 0;
    if (!valid) {
        return nullptr;
    }
    if (mapped) {
        if (static_cast<std::uint64_t>(rva) >= limit) {
            return nullptr;
        }
        const std::size_t available = limit - static_cast<std::size_t>(rva);
        len = need < available ? need : available;
        return base + static_cast<std::size_t>(rva);
    }
    // File layout: find the section whose virtual range covers the RVA and
    // translate through its raw pointer. The virtual range is [rva,
    // rva+vsize); a section with no virtual size covers nothing, whatever
    // its raw fields say.
    for (const SectionView& s : sections) {
        if (s.vsize == 0 || rva < s.rva ||
            static_cast<std::uint64_t>(rva) >=
                static_cast<std::uint64_t>(s.rva) + s.vsize) {
            continue;
        }
        const std::uint64_t off =
            static_cast<std::uint64_t>(rva) - s.rva + s.rawptr;
        if (off >= limit) {
            return nullptr;
        }
        const std::size_t available = limit - static_cast<std::size_t>(off);
        len = need < available ? need : available;
        return base + static_cast<std::size_t>(off);
    }
    return nullptr;
}

const std::uint8_t* PeImage::section_bytes(const SectionView& s,
                                           std::size_t& len) const noexcept {
    len = 0;
    if (!valid || s.vsize == 0) {
        return nullptr;
    }
    if (mapped) {
        if (static_cast<std::uint64_t>(s.rva) >= limit) {
            return nullptr;
        }
        const std::size_t available =
            limit - static_cast<std::size_t>(s.rva);
        len = static_cast<std::size_t>(s.vsize) < available
                  ? static_cast<std::size_t>(s.vsize)
                  : available;
        return base + static_cast<std::size_t>(s.rva);
    }
    if (static_cast<std::uint64_t>(s.rawptr) >= limit) {
        return nullptr;
    }
    const std::size_t available = limit - static_cast<std::size_t>(s.rawptr);
    len = static_cast<std::size_t>(s.rawsize) < available
              ? static_cast<std::size_t>(s.rawsize)
              : available;
    return base + static_cast<std::size_t>(s.rawptr);
}

}  // namespace occ::packer::detail

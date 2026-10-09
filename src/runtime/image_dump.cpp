// Dumping the guest's image back out as a PE file.
//
// See the header for why the bytes are only here. This file is the
// mechanics: read the image's own headers, lay the sections out at their
// full virtual size, patch the section table to say where each landed,
// and write it out.

#include "occ/runtime/image_dump.h"

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace occ::runtime::image_dump {
namespace {

[[nodiscard]] std::uint16_t rd16(const std::uint8_t* p,
                                 std::size_t at) noexcept {
    return static_cast<std::uint16_t>(p[at]) |
           static_cast<std::uint16_t>(p[at + 1] << 8);
}

[[nodiscard]] std::uint32_t rd32(const std::uint8_t* p,
                                 std::size_t at) noexcept {
    return static_cast<std::uint32_t>(p[at]) |
           (static_cast<std::uint32_t>(p[at + 1]) << 8) |
           (static_cast<std::uint32_t>(p[at + 2]) << 16) |
           (static_cast<std::uint32_t>(p[at + 3]) << 24);
}

void wr32(std::uint8_t* p, std::size_t at, std::uint32_t v) noexcept {
    p[at] = static_cast<std::uint8_t>(v);
    p[at + 1] = static_cast<std::uint8_t>(v >> 8);
    p[at + 2] = static_cast<std::uint8_t>(v >> 16);
    p[at + 3] = static_cast<std::uint8_t>(v >> 24);
}

[[nodiscard]] std::uint64_t align_up(std::uint64_t value,
                                     std::uint64_t unit) noexcept {
    if (unit == 0) {
        return value;
    }
    return ((value + unit - 1) / unit) * unit;
}

// The section table entry, as offsets. Named so the layout is stated once
// rather than spelled as numbers in three places.
constexpr std::size_t kSectionSize = 40;
constexpr std::size_t kSectionVirtualSize = 0x08;
constexpr std::size_t kSectionVirtualAddress = 0x0C;
constexpr std::size_t kSectionRawSize = 0x10;
constexpr std::size_t kSectionRawPointer = 0x14;

}  // namespace

bool enabled() noexcept {
    static const bool on = [] {
        const char* value = ::getenv("OCC_DUMP_IMAGE");
        return value != nullptr && value[0] != '\0';
    }();
    return on;
}

std::string path() {
    const char* value = ::getenv("OCC_DUMP_IMAGE");
    return value != nullptr ? std::string(value) : std::string();
}

bool dump(std::uint64_t image_base, const std::string& out_path) noexcept {
    const auto* img = reinterpret_cast<const std::uint8_t*>(image_base);
    if (img == nullptr) {
        std::fprintf(stderr, "occ dump: no image to dump\n");
        return false;
    }
    if (rd16(img, 0) != 0x5A4D) {  // 'M'
        std::fprintf(stderr, "occ dump: no MZ at the image base\n");
        return false;
    }
    const std::uint32_t pe_at = rd32(img, 0x3C);
    if (rd32(img, pe_at) != 0x00004550) {  // "PE\0\0"
        std::fprintf(stderr, "occ dump: no PE signature at e_lfanew\n");
        return false;
    }

    const std::uint16_t section_count = rd16(img, pe_at + 6);
    const std::uint16_t optional_size = rd16(img, pe_at + 20);
    const std::size_t optional = static_cast<std::size_t>(pe_at) + 24;
    const std::uint16_t magic = rd16(img, optional);
    if (magic != 0x20B) {
        // A PE32 dump is a different layout and would be written wrong by
        // this code rather than refused by it, so it is refused here.
        std::fprintf(stderr,
                     "occ dump: only PE32+ is dumped; this image says 0x%x\n",
                     static_cast<unsigned>(magic));
        return false;
    }
    const std::uint32_t file_align = rd32(img, optional + 0x24);
    const std::uint32_t size_of_headers = rd32(img, optional + 0x3C);
    const std::size_t section_table =
        optional + static_cast<std::size_t>(optional_size);

    // The header area has to hold the section table whatever the header
    // says: the size in the optional header is the linker's, and a file
    // whose table lands past it would lose the entries this code is about
    // to patch.
    const std::uint64_t headers_bytes =
        align_up(section_table + static_cast<std::size_t>(section_count) *
                                    kSectionSize > size_of_headers
                     ? section_table +
                           static_cast<std::size_t>(section_count) * kSectionSize
                     : size_of_headers,
                 file_align == 0 ? 0x200 : file_align);

    std::vector<std::uint8_t> out(static_cast<std::size_t>(headers_bytes), 0);
    std::memcpy(out.data(), img, static_cast<std::size_t>(headers_bytes));

    std::uint64_t cursor = headers_bytes;
    for (std::uint16_t i = 0; i < section_count; ++i) {
        const std::size_t entry =
            section_table + static_cast<std::size_t>(i) * kSectionSize;
        const std::uint32_t virtual_size = rd32(img, entry + kSectionVirtualSize);
        const std::uint32_t virtual_address =
            rd32(img, entry + kSectionVirtualAddress);
        if (virtual_size == 0) {
            // A section with no virtual size still takes an entry; it
            // simply carries no bytes, and its file fields say so.
            wr32(out.data(), entry + kSectionRawSize, 0);
            wr32(out.data(), entry + kSectionRawPointer, 0);
            continue;
        }

        // The bytes as the guest holds them -- this is the whole point of
        // the dump, since the file's copy is the encrypted one.
        const std::uint8_t* source = img + virtual_address;
        const std::uint64_t raw_size = align_up(virtual_size, file_align == 0
                                                                ? 0x200
                                                                : file_align);
        out.resize(static_cast<std::size_t>(cursor + raw_size), 0);
        std::memcpy(out.data() + cursor, source, virtual_size);
        wr32(out.data(), entry + kSectionRawSize,
             static_cast<std::uint32_t>(raw_size));
        wr32(out.data(), entry + kSectionRawPointer,
             static_cast<std::uint32_t>(cursor));
        cursor += raw_size;
    }

    std::FILE* file = std::fopen(out_path.c_str(), "wb");
    if (file == nullptr) {
        std::fprintf(stderr, "occ dump: cannot open %s for writing\n",
                     out_path.c_str());
        return false;
    }
    const std::size_t written =
        std::fwrite(out.data(), 1, out.size(), file);
    std::fclose(file);
    if (written != out.size()) {
        std::fprintf(stderr, "occ dump: short write to %s\n", out_path.c_str());
        return false;
    }
    std::fprintf(stderr,
                 "occ dump: wrote %s (%zu bytes, %u sections mapped at their "
                 "virtual size)\n",
                 out_path.c_str(), out.size(),
                 static_cast<unsigned>(section_count));
    return true;
}

}  // namespace occ::runtime::image_dump

// Naming the addresses a running image calls through.
//
// See the header for what this is for and why the scan can be this simple.
// This file is the mechanics: parse the image's own headers, walk the
// executable sections looking for the two rip-relative forms, and answer
// each candidate by reading the slot and asking the registry what it holds.

#include "occ/runtime/iat_rebuild.h"

#include "occ/runtime/api_hook.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

namespace occ::runtime::iat_rebuild {
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

[[nodiscard]] std::uint64_t rd64(const std::uint8_t* p,
                                 std::size_t at) noexcept {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | p[at + static_cast<std::size_t>(i)];
    }
    return v;
}

constexpr std::size_t kSectionSize = 40;
constexpr std::size_t kSectionVirtualSize = 0x08;
constexpr std::size_t kSectionVirtualAddress = 0x0C;
constexpr std::size_t kSectionCharacteristics = 0x24;
constexpr std::uint32_t kSectionExecute = 0x20000000;

}  // namespace

bool report(std::uint64_t image_base, const std::string& out_path) noexcept {
    const auto* img = reinterpret_cast<const std::uint8_t*>(image_base);
    if (img == nullptr || rd16(img, 0) != 0x5A4D) {
        std::fprintf(stderr, "occ iat: no image to scan\n");
        return false;
    }
    const std::uint32_t pe_at = rd32(img, 0x3C);
    if (rd32(img, pe_at) != 0x00004550) {
        std::fprintf(stderr, "occ iat: no PE signature at e_lfanew\n");
        return false;
    }
    const std::uint16_t section_count = rd16(img, pe_at + 6);
    const std::uint16_t optional_size = rd16(img, pe_at + 20);
    const std::size_t optional = static_cast<std::size_t>(pe_at) + 24;
    const std::uint32_t size_of_image = rd32(img, optional + 0x38);
    const std::size_t section_table =
        optional + static_cast<std::size_t>(optional_size);
    const std::uint64_t image_end = image_base + size_of_image;

    // Every slot the code names, keyed by the slot's own address so a slot
    // reached from several call sites is reported once.
    std::map<std::uint64_t, std::uint64_t> slots;

    for (std::uint16_t i = 0; i < section_count; ++i) {
        const std::size_t entry =
            section_table + static_cast<std::size_t>(i) * kSectionSize;
        if ((rd32(img, entry + kSectionCharacteristics) & kSectionExecute) == 0) {
            continue;
        }
        const std::uint32_t virtual_size = rd32(img, entry + kSectionVirtualSize);
        const std::uint32_t virtual_address =
            rd32(img, entry + kSectionVirtualAddress);
        if (virtual_size < 6) {
            continue;
        }
        const std::uint8_t* code = img + virtual_address;
        const std::uint64_t code_va = image_base + virtual_address;

        for (std::uint64_t off = 0; off + 6 <= virtual_size; ++off) {
            if (code[off] != 0xFF) {
                continue;
            }
            const std::uint8_t modrm = code[off + 1];
            // 0x15 is `call [rip+disp32]`; 0x25 is `jmp [rip+disp32]`.
            if (modrm != 0x15 && modrm != 0x25) {
                continue;
            }
            const std::int32_t disp = static_cast<std::int32_t>(
                rd32(code, static_cast<std::size_t>(off) + 2));
            // The displacement is signed and the sum is not, so the two
            // directions are spelled separately: adding a negative to an
            // address would compile to the same value but reads as a
            // conversion the compiler is right to question.
            const std::int64_t signed_disp = static_cast<std::int64_t>(disp);
            const std::uint64_t target =
                signed_disp >= 0
                    ? code_va + off + 6 + static_cast<std::uint64_t>(signed_disp)
                    : code_va + off + 6 -
                          static_cast<std::uint64_t>(-signed_disp);
            if (target < image_base || target + 8 > image_end) {
                continue;
            }
            slots.emplace(target, 0);
        }
    }

    // Resolve each slot and keep the ones that name something. A slot
    // holding zero was never filled -- the image declared it and did not
    // use it -- and a slot naming nothing registered is reported as
    // unwritten rather than dropped, because "there is a call here and we
    // cannot say to what" is a fact about the image.
    std::vector<std::pair<std::uint64_t, std::string>> named;
    std::vector<std::uint64_t> unnamed;
    for (auto& [slot_va, value] : slots) {
        const std::uint64_t offset = slot_va - image_base;
        value = rd64(img, static_cast<std::size_t>(offset));
        if (value == 0) {
            unnamed.push_back(slot_va);
            continue;
        }
        const char* name = api_hook::name_for_address(value);
        if (name == nullptr) {
            unnamed.push_back(slot_va);
            continue;
        }
        named.emplace_back(slot_va, std::string(name));
    }

    std::FILE* file = std::fopen(out_path.c_str(), "wb");
    if (file == nullptr) {
        std::fprintf(stderr, "occ iat: cannot open %s for writing\n",
                     out_path.c_str());
        return false;
    }
    std::fprintf(file,
                 "# import slots rebuilt from the running image\n"
                 "# image base 0x%llx, size 0x%x, %u sections examined\n"
                 "# %zu slots reached by rip-relative call or jump, "
                 "%zu named\n\n",
                 static_cast<unsigned long long>(image_base), size_of_image,
                 static_cast<unsigned>(section_count), slots.size(),
                 named.size());
    for (const auto& [slot_va, name] : named) {
        std::fprintf(file, "0x%llx\t%s\n",
                     static_cast<unsigned long long>(slot_va), name.c_str());
    }
    if (!unnamed.empty()) {
        std::fprintf(file, "\n# slots whose value names nothing registered:\n");
        for (std::uint64_t slot_va : unnamed) {
            std::fprintf(file, "0x%llx\t?\n",
                         static_cast<unsigned long long>(slot_va));
        }
    }
    std::fclose(file);

    std::fprintf(stderr,
                 "occ iat: wrote %s (%zu slots, %zu named)\n", out_path.c_str(),
                 slots.size(), named.size());
    return true;
}

}  // namespace occ::runtime::iat_rebuild

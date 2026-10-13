// Internal PE parsing shared by the packer module's passes.
//
// This is not a PE parser in the sense src/parser is: it reads exactly the
// fields the packer analyses need -- the DOS/COFF/optional header skeleton,
// the section table, the import data directory -- and it answers exactly
// one question the analyses keep asking: given an RVA, where are the bytes
// and how many are there? The two callers of that question are the two
// shapes of input the module accepts:
//
//   * a file buffer: section bytes live at PointerToRawData, so an RVA is
//     translated through the section whose virtual range contains it;
//   * a mapped image: section bytes live at base + VirtualAddress, so an
//     RVA is an offset from the base, bounded by SizeOfImage -- the same
//     trust the runtime's own readers (iat_rebuild, image_dump) take.
//
// The bounds discipline differs between the two on purpose. A file buffer
// has a known size and every read checks against it, because the file is
// untrusted input and a truncated one must be refused, not read past. A
// mapped image has no size a caller can hand us reliably -- the mapping
// came from the runtime, which allocated at least SizeOfImage bytes -- so
// header reads trust the mapping the way iat_rebuild does, and section
// reads bound themselves by SizeOfImage, which is the extent the mapping
// actually covers. A caller that holds a bounded buffer in mapped layout
// should pass its size and the bounds apply to section reads too.
//
// Nothing here infers. A field that cannot be read because the structure
// is truncated is an error with the field's name; an RVA that no section
// covers answers null; a section with no readable bytes answers a zero
// length, not a guess at where the bytes should have been.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace occ::packer::detail {

// The section characteristics this module reasons about, as named
// constants rather than magic numbers.
constexpr std::uint32_t kSectionRead = 0x40000000;
constexpr std::uint32_t kSectionWrite = 0x80000000;
constexpr std::uint32_t kSectionExec = 0x20000000;

// One section table entry, decoded. The layout offsets below match the
// PE format; they are stated once here rather than spelled in each pass.
constexpr std::size_t kSectionEntrySize = 40;
constexpr std::size_t kSectionNameOff = 0x00;
constexpr std::size_t kSectionVirtualSizeOff = 0x08;
constexpr std::size_t kSectionVirtualAddressOff = 0x0C;
constexpr std::size_t kSectionRawSizeOff = 0x10;
constexpr std::size_t kSectionRawPointerOff = 0x14;
constexpr std::size_t kSectionCharacteristicsOff = 0x24;

struct SectionView {
    std::string name;
    std::uint32_t rva = 0;
    std::uint32_t vsize = 0;
    std::uint32_t rawsize = 0;
    std::uint32_t rawptr = 0;
    std::uint32_t characteristics = 0;

    [[nodiscard]] bool exec() const noexcept {
        return (characteristics & kSectionExec) != 0;
    }
    [[nodiscard]] bool writable() const noexcept {
        return (characteristics & kSectionWrite) != 0;
    }
    [[nodiscard]] bool readable() const noexcept {
        return (characteristics & kSectionRead) != 0;
    }
};

enum class PeFormat : std::uint8_t { None, Pe32, Pe32Plus };

// A parsed PE, together with the machinery for answering "bytes at RVA".
//
// `base` is the start of the MZ header. `limit` is the number of bytes
// readable from `base` in the *section-read* sense: SizeOfImage for a
// mapped image, the buffer size for a file. `image_base_va` is the guest
// virtual address of `base`, used to turn absolute guest addresses (the
// ones memwatch records) back into RVAs; it is 0 for a pure file view,
// where the caller does the conversion.
struct PeImage {
    const std::uint8_t* base = nullptr;
    std::size_t limit = 0;
    std::uint64_t image_base_va = 0;
    bool mapped = false;  // rva -> base+rva (true) or rawptr translation (false)

    bool valid = false;
    std::string error;
    PeFormat format = PeFormat::None;
    std::uint16_t machine = 0;
    std::uint16_t section_count = 0;
    std::uint32_t entry_rva = 0;
    std::uint32_t image_size = 0;
    std::uint32_t size_of_headers = 0;
    std::uint32_t import_dir_rva = 0;
    std::uint32_t import_dir_size = 0;
    std::vector<SectionView> sections;

    // Parses the headers and section table at `bytes`. In mapped mode the
    // headers are trusted (pass size 0 to trust fully; pass the buffer
    // size to bound section reads), and section bytes are read at
    // base+rva. In buffer mode every read is bounded by `size` and
    // section bytes are read at their raw pointers.
    [[nodiscard]] static PeImage parse(const std::uint8_t* bytes,
                                       std::size_t size,
                                       std::uint64_t image_base_va,
                                       bool mapped) noexcept;

    // The readable bytes at `rva`, bounded by `need`; null when the RVA
    // names nothing readable. `len` receives how many bytes are actually
    // available (<= need; 0 with a null return is "nothing here", not "a
    // zero-length region").
    [[nodiscard]] const std::uint8_t* at_rva(std::uint32_t rva,
                                             std::size_t need,
                                             std::size_t& len) const noexcept;

    // The readable bytes of a section, in this view's layout, with the
    // same len convention as at_rva.
    [[nodiscard]] const std::uint8_t* section_bytes(
        const SectionView& s, std::size_t& len) const noexcept;
};

// The little-endian readers, one byte at a time the way the runtime does
// it, so no unaligned load and no host-endianness question arises.
[[nodiscard]] std::uint16_t rd16(const std::uint8_t* p,
                                 std::size_t at) noexcept;
[[nodiscard]] std::uint32_t rd32(const std::uint8_t* p,
                                 std::size_t at) noexcept;
[[nodiscard]] std::uint64_t rd64(const std::uint8_t* p,
                                 std::size_t at) noexcept;

}  // namespace occ::packer::detail

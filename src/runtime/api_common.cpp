// The conversions the API families share, defined once.
//
// `api_common.h` declares what these are for; this file is their
// definition. Splitting them is the point: the declarations live in the
// header every family includes, so a family sees one error-code list and
// one set of buffer rules, and the definitions live in one translation unit
// so that there is one implementation to be right about.

#include "occ/runtime/api_common.h"

namespace occ::runtime::winabi {

AnsiResult narrow_in(std::string_view text, std::u16string& out) noexcept {
    std::u16string wide;
    if (!utf8_to_utf16(text, wide)) {
        out.clear();
        return {false, kEInvalidArg};
    }
    out = std::move(wide);
    return {true, kSOk};
}

AnsiResult narrow_out(std::u16string_view text, std::string& out) noexcept {
    std::string narrow;
    if (!utf16_to_utf8(text, narrow)) {
        out.clear();
        return {false, kEInvalidArg};
    }
    out = std::move(narrow);
    return {true, kSOk};
}

std::size_t narrow_length(std::u16string_view text) noexcept {
    std::string scratch;
    if (!narrow_out(text, scratch).converted) {
        return 0;
    }
    return scratch.size() + 1;
}

std::size_t required_capacity(std::u16string_view text) noexcept {
    return text.size() + 1;
}

bool fits(std::u16string_view text, std::size_t capacity) noexcept {
    return capacity > text.size();
}

std::size_t required_capacity(std::string_view text) noexcept {
    return text.size() + 1;
}

bool fits(std::string_view text, std::size_t capacity) noexcept {
    return capacity > text.size();
}

std::uint32_t read_u32(const void* base, std::size_t offset) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(base);
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        value |= static_cast<std::uint32_t>(bytes[offset + i])
                 << (8 * i);
    }
    return value;
}

void write_u32(void* base, std::size_t offset,
               std::uint32_t value) noexcept {
    auto* bytes = static_cast<std::uint8_t*>(base);
    for (std::size_t i = 0; i < 4; ++i) {
        bytes[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
}

std::uint64_t read_ptr(const void* base, std::size_t offset) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(base);
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(bytes[offset + i])
                 << (8 * i);
    }
    return value;
}

void write_ptr(void* base, std::size_t offset,
               std::uint64_t value) noexcept {
    auto* bytes = static_cast<std::uint8_t*>(base);
    for (std::size_t i = 0; i < 8; ++i) {
        bytes[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
}

std::uint16_t read_u16(const void* base, std::size_t offset) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(base);
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(
        bytes[offset]) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(
                                       bytes[offset + 1])
                                   << 8));
}

void write_u16(void* base, std::size_t offset,
               std::uint16_t value) noexcept {
    auto* bytes = static_cast<std::uint8_t*>(base);
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

std::uint8_t read_u8(const void* base, std::size_t offset) noexcept {
    return static_cast<const std::uint8_t*>(base)[offset];
}

void write_u8(void* base, std::size_t offset, std::uint8_t value) noexcept {
    static_cast<std::uint8_t*>(base)[offset] = value;
}

std::uint64_t read_u64(const void* base, std::size_t offset) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(base);
    std::uint64_t value = 0;
    for (std::size_t k = 0; k < 8; ++k) {
        value |= static_cast<std::uint64_t>(bytes[offset + k]) << (k * 8);
    }
    return value;
}

void write_u64(void* base, std::size_t offset, std::uint64_t value) noexcept {
    auto* bytes = static_cast<std::uint8_t*>(base);
    for (std::size_t k = 0; k < 8; ++k) {
        bytes[offset + k] = static_cast<std::uint8_t>(value >> (k * 8));
    }
}

}  // namespace occ::runtime::winabi

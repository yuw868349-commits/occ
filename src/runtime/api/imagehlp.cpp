// The image checksum pair: `CheckSumMappedFile` and `MapFileAndCheckSumA`,
// which answer the question a patcher or a packer asks about its own output
// -- is the file's checksum the one its headers claim?
//
// The checksum is the one Windows computes: a folded sum of the image's
// 16-bit words, the file length folded in, and the result carried to a
// 16-bit value. The header half is read from the PE optional header's
// `CheckSum` field, at the same offset the loader reads. Both spellings
// work on the same bytes; the mapped spelling takes bytes that are already
// in the address space, and the file spelling reads the file itself.

#include "occ/runtime/api_common.h"
#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace occ::runtime::winabi {
namespace {

// The PE markers, as they appear in the image. `e_lfanew` at 0x3C names the
// NT headers, whose signature is the four bytes `PE\0\0`.
constexpr std::uint16_t kDosMagic = 0x5A4D;  // 'MZ'
constexpr std::uint32_t kPeSignature = 0x00004550u;  // 'PE\0\0'
constexpr std::size_t kELfanew = 0x3C;
constexpr std::size_t kNtSignature = 0;
constexpr std::size_t kNtOptional = 0x18;  // file header is 20 bytes

// The `CheckSum` field of the optional header. The optional header's fields
// before it -- magic, linker version, sizes -- total 0x40 bytes on both
// the 32-bit and 64-bit spellings.
constexpr std::size_t kOptionalCheckSum = 0x40;

// The status codes `MapFileAndCheckSumA` answers with. Success is zero.
constexpr std::uint32_t kChecksumSuccess = 0;
constexpr std::uint32_t kChecksumOpenFailed = 1;

// The folded word-sum Windows computes. Each 16-bit word is added and the
// carry is folded back into the low half, so the accumulator never grows;
// the file length is then folded in the same way, and the last fold makes
// the answer 16 bits.
[[nodiscard]] std::uint16_t compute_checksum(const std::uint8_t* base,
                                             std::size_t size) noexcept {
    std::uint32_t sum = 0;
    std::size_t remaining = size;
    const std::uint8_t* p = base;
    while (remaining >= 2) {
        std::uint16_t word = 0;
        std::memcpy(&word, p, 2);
        sum += word;
        sum = (sum >> 16) + (sum & 0xFFFFu);
        p += 2;
        remaining -= 2;
    }
    if (remaining != 0) {
        sum += *p;
    }
    sum += static_cast<std::uint32_t>(size);
    sum = (sum >> 16) + (sum & 0xFFFFu);
    return static_cast<std::uint16_t>(sum + (sum >> 16));
}

// Reads the `CheckSum` field of a PE's optional header, when the bytes at
// `base` are a PE at all. A buffer that is not a PE answers with the
// "not an image" refusal, which is what the caller's null answer means.
[[nodiscard]] bool header_checksum(const std::uint8_t* base,
                                   std::size_t size,
                                   std::uint32_t& out) noexcept {
    if (base == nullptr || size < kELfanew + 4) {
        return false;
    }
    std::uint16_t magic = 0;
    std::memcpy(&magic, base, 2);
    if (magic != kDosMagic) {
        return false;
    }
    std::uint32_t lfanew = 0;
    std::memcpy(&lfanew, base + kELfanew, 4);
    if (lfanew + 0x18 + 0x40 + 4 > size) {
        return false;
    }
    std::uint32_t signature = 0;
    std::memcpy(&signature, base + lfanew + kNtSignature, 4);
    if (signature != kPeSignature) {
        return false;
    }
    std::memcpy(&out, base + lfanew + kNtOptional + kOptionalCheckSum, 4);
    return true;
}

}  // namespace

// The mapped spelling: the image is already in the address space, the
// header checksum is read out of it, and the whole-image checksum is
// computed over it. Answers the image base, or null for bytes that are not
// an image.
extern "C" __attribute__((ms_abi)) void* k32ih_CheckSumMappedFile(
    void* base, std::uint32_t length, std::uint32_t* header_sum,
    std::uint32_t* checksum) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(base);
    if (base == nullptr || header_sum == nullptr || checksum == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    std::uint32_t hdr = 0;
    if (!header_checksum(bytes, length, hdr)) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    *header_sum = hdr;
    *checksum = compute_checksum(bytes, length);
    set_last_error(0);
    return base;
}

// The file spelling: the file is read and the same computation runs over
// its bytes. Answers the status code, with the two sums written through.
extern "C" __attribute__((ms_abi)) std::uint32_t k32ih_MapFileAndCheckSumA(
    const char* filename, std::uint32_t* header_sum,
    std::uint32_t* checksum) noexcept {
    if (filename == nullptr || header_sum == nullptr || checksum == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return kChecksumOpenFailed;
    }
    const int fd = ::open(filename, O_RDONLY);
    if (fd < 0) {
        set_last_error(kErrorFileNotFound);
        return kChecksumOpenFailed;
    }
    struct stat st;
    if (::fstat(fd, &st) != 0 || st.st_size <= 0) {
        ::close(fd);
        set_last_error(kErrorFileNotFound);
        return kChecksumOpenFailed;
    }
    std::string data;
    data.resize(static_cast<std::size_t>(st.st_size));
    const ::ssize_t got = ::read(fd, data.data(), data.size());
    ::close(fd);
    if (got <= 0) {
        set_last_error(kErrorFileNotFound);
        return kChecksumOpenFailed;
    }
    data.resize(static_cast<std::size_t>(got));
    const auto* bytes =
        reinterpret_cast<const std::uint8_t*>(data.data());
    std::uint32_t hdr = 0;
    if (!header_checksum(bytes, data.size(), hdr)) {
        set_last_error(kErrorInvalidParameter);
        return kChecksumOpenFailed;
    }
    *header_sum = hdr;
    *checksum = compute_checksum(bytes, data.size());
    set_last_error(0);
    return kChecksumSuccess;
}

void add_dbghelp_imagehlp(ExportList& out) {
    const auto e = [](const char* n, void* fn) {
        HostExport entry;
        entry.name = n;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        return entry;
    };
    out.push_back(e("CheckSumMappedFile",
                    reinterpret_cast<void*>(&k32ih_CheckSumMappedFile)));
    out.push_back(e("MapFileAndCheckSumA",
                    reinterpret_cast<void*>(&k32ih_MapFileAndCheckSumA)));
}

}  // namespace occ::runtime::winabi

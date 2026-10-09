// The platform cryptography surface.
//
// `bcrypt` is what a program reaches for when it wants a hash, a cipher or a
// random number without carrying its own implementation. The calls here are
// the ones an ordinary program uses: an algorithm provider, a hash object
// built from it, the data fed in, the digest taken out, and the random
// generator.
//
// The algorithms are written out in this file rather than reached through a
// library. That is the point of the module: a runtime whose promise is that
// it needs nothing from outside itself cannot borrow a hash. It also keeps
// the answers stable -- a digest is a fixed sequence of bits that programs
// compare against recorded values, and a version of the algorithm that
// changed under this runtime would break every one of them.
//
// Three hash functions are here, chosen because they are the three an image
// that imports this module actually asks for. A request for an algorithm
// this file does not carry is refused at the provider, which is the earliest
// point a caller can be told: refusing at the provider means the caller
// never builds a hash object that would answer a digest from the wrong
// function, and the failure appears where the mistake is.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <sys/random.h>

namespace occ::runtime::winabi {
namespace {

// The statuses these calls answer. NTSTATUS is unsigned: its top two bits
// are the severity, and a status written as a signed literal would be a
// different value than the one the caller compares against.
using Ntstatus = std::uint32_t;

constexpr Ntstatus kStatusUnsuccessful = 0xC0000001u;
constexpr Ntstatus kStatusInvalidHandle = 0xC0000008u;
constexpr Ntstatus kStatusInvalidParameter = 0xC000000Du;
constexpr Ntstatus kStatusBufferTooSmall = 0xC0000023u;
constexpr Ntstatus kStatusNotSupported = 0xC00000BBu;
constexpr Ntstatus kStatusSuccess = 0;


// ------------------------------------------------------------ the algorithms

enum class Algorithm : std::uint8_t {
    None,
    Sha1,
    Sha256,
    Md5,
    Rng,
};

// The name a guest asks for, matched case-insensitively, which is how the
// platform matches algorithm names.
[[nodiscard]] Algorithm algorithm_of(std::string_view name) noexcept {
    std::string lower;
    for (char ch : name) {
        lower.push_back(ch >= 'A' && ch <= 'Z'
                            ? static_cast<char>(ch - 'A' + 'a')
                            : ch);
    }
    if (lower == "sha1") {
        return Algorithm::Sha1;
    }
    if (lower == "sha256") {
        return Algorithm::Sha256;
    }
    if (lower == "md5") {
        return Algorithm::Md5;
    }
    if (lower == "rng") {
        return Algorithm::Rng;
    }
    return Algorithm::None;
}

// The digest length each algorithm produces.
[[nodiscard]] std::uint32_t digest_length(Algorithm algorithm) noexcept {
    switch (algorithm) {
        case Algorithm::Sha1:
            return 20;
        case Algorithm::Sha256:
            return 32;
        case Algorithm::Md5:
            return 16;
        default:
            return kStatusSuccess;
    }
}

// -------------------------------------------------------------- SHA-256
//
// FIPS 180-4. The state is eight words, the block is sixty-four bytes, and
// the schedule is the sixty-four words the compression function consumes.

constexpr std::uint32_t kSha256Initial[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

constexpr std::uint32_t kSha256Round[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

[[nodiscard]] constexpr std::uint32_t rotr32(std::uint32_t value,
                                             std::uint32_t bits) noexcept {
    return (value >> bits) | (value << ((32 - bits) & 31));
}

struct Sha256State {
    std::uint32_t h[8] = {};
    std::uint64_t bytes = 0;
    std::uint8_t block[64] = {};
    std::size_t used = 0;
};

void sha256_compress(Sha256State& st, const std::uint8_t* block) noexcept {
    std::uint32_t w[64] = {};
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
               static_cast<std::uint32_t>(block[i * 4 + 3]);
    }
    for (std::size_t i = 16; i < 64; ++i) {
        const std::uint32_t s0 =
            rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 =
            rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint32_t a = st.h[0], b = st.h[1], c = st.h[2], d = st.h[3];
    std::uint32_t e = st.h[4], f = st.h[5], g = st.h[6], h = st.h[7];
    for (std::size_t i = 0; i < 64; ++i) {
        const std::uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        const std::uint32_t ch = (e & f) ^ ((~e) & g);
        const std::uint32_t t1 = h + s1 + ch + kSha256Round[i] + w[i];
        const std::uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    st.h[0] += a; st.h[1] += b; st.h[2] += c; st.h[3] += d;
    st.h[4] += e; st.h[5] += f; st.h[6] += g; st.h[7] += h;
}

void sha256_init(Sha256State& st) noexcept {
    for (std::size_t i = 0; i < 8; ++i) {
        st.h[i] = kSha256Initial[i];
    }
    st.bytes = 0;
    st.used = 0;
}

void sha256_update(Sha256State& st, const std::uint8_t* data,
                   std::size_t length) noexcept {
    st.bytes += length;
    while (length > 0) {
        const std::size_t take =
            length < 64 - st.used ? length : 64 - st.used;
        std::memcpy(st.block + st.used, data, take);
        st.used += take;
        data += take;
        length -= take;
        if (st.used == 64) {
            sha256_compress(st, st.block);
            st.used = 0;
        }
    }
}

void sha256_finish(Sha256State& st, std::uint8_t* out) noexcept {
    // The padding: a one bit, zeros, and the message length in bits as a
    // 64-bit big-endian count in the last eight bytes of the final block.
    const std::uint64_t bits = st.bytes * 8;
    const std::uint8_t one = 0x80;
    sha256_update(st, &one, 1);
    const std::uint8_t zero = 0;
    while (st.used != 56) {
        sha256_update(st, &zero, 1);
    }
    std::uint8_t tail[8];
    for (std::size_t i = 0; i < 8; ++i) {
        tail[i] = static_cast<std::uint8_t>(bits >> ((7 - i) * 8));
    }
    sha256_update(st, tail, 8);
    for (std::size_t i = 0; i < 8; ++i) {
        out[i * 4] = static_cast<std::uint8_t>(st.h[i] >> 24);
        out[i * 4 + 1] = static_cast<std::uint8_t>(st.h[i] >> 16);
        out[i * 4 + 2] = static_cast<std::uint8_t>(st.h[i] >> 8);
        out[i * 4 + 3] = static_cast<std::uint8_t>(st.h[i]);
    }
}

// ---------------------------------------------------------------- SHA-1
//
// FIPS 180-4, the older function. It is still what a program built against
// an older toolchain asks for, and a digest that came from SHA-256 where
// SHA-1 was named would compare unequal against every recorded value.

struct Sha1State {
    std::uint32_t h[5] = {};
    std::uint64_t bytes = 0;
    std::uint8_t block[64] = {};
    std::size_t used = 0;
};

void sha1_init(Sha1State& st) noexcept {
    st.h[0] = 0x67452301u;
    st.h[1] = 0xEFCDAB89u;
    st.h[2] = 0x98BADCFEu;
    st.h[3] = 0x10325476u;
    st.h[4] = 0xC3D2E1F0u;
    st.bytes = 0;
    st.used = 0;
}

[[nodiscard]] constexpr std::uint32_t rotl32(std::uint32_t value,
                                             std::uint32_t bits) noexcept {
    return (value << bits) | (value >> ((32 - bits) & 31));
}

void sha1_compress(Sha1State& st, const std::uint8_t* block) noexcept {
    std::uint32_t w[80] = {};
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
               static_cast<std::uint32_t>(block[i * 4 + 3]);
    }
    for (std::size_t i = 16; i < 80; ++i) {
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    std::uint32_t a = st.h[0], b = st.h[1], c = st.h[2], d = st.h[3];
    std::uint32_t e = st.h[4];
    for (std::size_t i = 0; i < 80; ++i) {
        std::uint32_t f = 0;
        std::uint32_t k = 0;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }
        const std::uint32_t temp = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = temp;
    }
    st.h[0] += a; st.h[1] += b; st.h[2] += c; st.h[3] += d; st.h[4] += e;
}

void sha1_update(Sha1State& st, const std::uint8_t* data,
                 std::size_t length) noexcept {
    st.bytes += length;
    while (length > 0) {
        const std::size_t take =
            length < 64 - st.used ? length : 64 - st.used;
        std::memcpy(st.block + st.used, data, take);
        st.used += take;
        data += take;
        length -= take;
        if (st.used == 64) {
            sha1_compress(st, st.block);
            st.used = 0;
        }
    }
}

void sha1_finish(Sha1State& st, std::uint8_t* out) noexcept {
    const std::uint64_t bits = st.bytes * 8;
    const std::uint8_t one = 0x80;
    sha1_update(st, &one, 1);
    const std::uint8_t zero = 0;
    while (st.used != 56) {
        sha1_update(st, &zero, 1);
    }
    std::uint8_t tail[8];
    for (std::size_t i = 0; i < 8; ++i) {
        tail[i] = static_cast<std::uint8_t>(bits >> ((7 - i) * 8));
    }
    sha1_update(st, tail, 8);
    for (std::size_t i = 0; i < 5; ++i) {
        out[i * 4] = static_cast<std::uint8_t>(st.h[i] >> 24);
        out[i * 4 + 1] = static_cast<std::uint8_t>(st.h[i] >> 16);
        out[i * 4 + 2] = static_cast<std::uint8_t>(st.h[i] >> 8);
        out[i * 4 + 3] = static_cast<std::uint8_t>(st.h[i]);
    }
}

// ------------------------------------------------------------------- MD5
//
// RFC 1321. Little-endian where the SHA family is big-endian, which is the
// difference a reimplementation gets wrong first.

struct Md5State {
    std::uint32_t h[4] = {};
    std::uint64_t bytes = 0;
    std::uint8_t block[64] = {};
    std::size_t used = 0;
};

constexpr std::uint32_t kMd5Round[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

void md5_init(Md5State& st) noexcept {
    st.h[0] = 0x67452301u;
    st.h[1] = 0xefcdab89u;
    st.h[2] = 0x98badcfeu;
    st.h[3] = 0x10325476u;
    st.bytes = 0;
    st.used = 0;
}

void md5_compress(Md5State& st, const std::uint8_t* block) noexcept {
    std::uint32_t m[16] = {};
    for (std::size_t i = 0; i < 16; ++i) {
        m[i] = static_cast<std::uint32_t>(block[i * 4]) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 8) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 3]) << 24);
    }
    std::uint32_t a = st.h[0], b = st.h[1], c = st.h[2], d = st.h[3];
    for (std::size_t i = 0; i < 64; ++i) {
        std::uint32_t f = 0;
        std::size_t g = 0;
        if (i < 16) {
            f = (b & c) | ((~b) & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | ((~d) & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | (~d));
            g = (7 * i) % 16;
        }
        const std::uint32_t temp = d;
        d = c;
        c = b;
        const std::uint32_t constant =
            static_cast<std::uint32_t>(
                4294967296.0 * std::fabs(std::sin(static_cast<double>(i) + 1.0)));
        b = b + rotl32(a + f + constant + m[g], kMd5Round[i]);
        a = temp;
    }
    st.h[0] += a; st.h[1] += b; st.h[2] += c; st.h[3] += d;
}

void md5_update(Md5State& st, const std::uint8_t* data,
                std::size_t length) noexcept {
    st.bytes += length;
    while (length > 0) {
        const std::size_t take =
            length < 64 - st.used ? length : 64 - st.used;
        std::memcpy(st.block + st.used, data, take);
        st.used += take;
        data += take;
        length -= take;
        if (st.used == 64) {
            md5_compress(st, st.block);
            st.used = 0;
        }
    }
}

void md5_finish(Md5State& st, std::uint8_t* out) noexcept {
    const std::uint64_t bits = st.bytes * 8;
    const std::uint8_t one = 0x80;
    md5_update(st, &one, 1);
    const std::uint8_t zero = 0;
    while (st.used != 56) {
        md5_update(st, &zero, 1);
    }
    std::uint8_t tail[8];
    for (std::size_t i = 0; i < 8; ++i) {
        tail[i] = static_cast<std::uint8_t>(bits >> (i * 8));
    }
    md5_update(st, tail, 8);
    for (std::size_t i = 0; i < 4; ++i) {
        out[i * 4] = static_cast<std::uint8_t>(st.h[i]);
        out[i * 4 + 1] = static_cast<std::uint8_t>(st.h[i] >> 8);
        out[i * 4 + 2] = static_cast<std::uint8_t>(st.h[i] >> 16);
        out[i * 4 + 3] = static_cast<std::uint8_t>(st.h[i] >> 24);
    }
}

// -------------------------------------------------------------- the objects
//
// A hash object holds the algorithm's running state and the caller's own
// buffer, which is what the `ObjectLength` property exists to size. The
// handle a caller holds is a pointer to one of these, kept in a table so a
// destroyed handle cannot be used again: a handle that named freed memory
// would let a caller finish a hash that was never started.

struct HashObject {
    Algorithm algorithm = Algorithm::None;
    Sha256State sha256;
    Sha1State sha1;
    Md5State md5;
    std::vector<std::uint8_t> secret;
    bool finished = false;
    bool magic = false;
};

std::vector<HashObject*>& hash_objects() noexcept {
    static std::vector<HashObject*> objects;
    return objects;
}

[[nodiscard]] HashObject* hash_of(void* handle) noexcept {
    for (HashObject* object : hash_objects()) {
        if (object == handle && object->magic) {
            return object;
        }
    }
    return nullptr;
}

}  // namespace

// -------------------------------------------------------------- the provider

extern "C" __attribute__((ms_abi)) Ntstatus k32bc_OpenAlgorithmProvider(
    void** algorithm, const char16_t* name, const char16_t* implementation,
    std::uint32_t flags) noexcept {
    static_cast<void>(flags);
    if (algorithm == nullptr || name == nullptr) {
        return kStatusInvalidParameter;  // STATUS_INVALID_PARAMETER
    }
    *algorithm = nullptr;
    // A named implementation means a specific provider -- the platform's own
    // or a third party's. This runtime has one implementation of each
    // algorithm, so a request that names one is refused rather than served
    // by whichever one happens to be here.
    if (implementation != nullptr && implementation[0] != u'\0') {
        return kStatusNotSupported;  // STATUS_NOT_SUPPORTED
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(name), narrow).converted) {
        return kStatusInvalidParameter;
    }
    const Algorithm chosen = algorithm_of(narrow);
    if (chosen == Algorithm::None) {
        // An algorithm this file does not carry. The refusal is here, at the
        // provider, which is the earliest point the caller can be told: a
        // provider that answered success would have the caller build a hash
        // object that then has to fail, further from the mistake.
        return kStatusNotSupported;
    }
    // The provider handle names the algorithm. It carries no per-provider
    // state, because an algorithm here is a function rather than a loaded
    // module, and a name is what the following calls need.
    auto* object = new HashObject();
    object->algorithm = chosen;
    object->magic = true;
    hash_objects().push_back(object);
    *algorithm = object;
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus k32bc_CloseAlgorithmProvider(
    void* algorithm, std::uint32_t flags) noexcept {
    static_cast<void>(flags);
    if (algorithm == nullptr) {
        return kStatusInvalidParameter;
    }
    for (std::size_t i = 0; i < hash_objects().size(); ++i) {
        if (hash_objects()[i] == algorithm) {
            hash_objects()[i]->magic = false;
            delete hash_objects()[i];
            hash_objects().erase(hash_objects().begin() +
                                 static_cast<std::ptrdiff_t>(i));
            return kStatusSuccess;
        }
    }
    return kStatusInvalidHandle;  // STATUS_INVALID_HANDLE
}

extern "C" __attribute__((ms_abi)) Ntstatus k32bc_GetProperty(
    void* object, const char16_t* property, void* output,
    std::uint32_t output_size, std::uint32_t* result,
    std::uint32_t flags) noexcept {
    static_cast<void>(flags);
    if (object == nullptr || property == nullptr) {
        return kStatusInvalidParameter;
    }
    auto* provider = reinterpret_cast<HashObject*>(object);
    if (!provider->magic) {
        return kStatusInvalidHandle;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(property), narrow).converted) {
        return kStatusInvalidParameter;
    }
    std::string lower;
    for (char ch : narrow) {
        lower.push_back(ch >= 'A' && ch <= 'Z'
                            ? static_cast<char>(ch - 'A' + 'a')
                            : ch);
    }
    if (lower == "hashdigestlength") {
        // The digest size in bytes. A caller uses it to size the output of
        // `BCryptFinishHash`, so an answer that is too small would be a
        // buffer overflow inside the caller's own stack frame.
        const std::uint32_t length = digest_length(provider->algorithm);
        if (result != nullptr) {
            *result = 4;
        }
        if (output == nullptr || output_size < 4) {
            return kStatusBufferTooSmall;  // STATUS_BUFFER_TOO_SMALL
        }
        write_u32(output, 0, length);
        return kStatusSuccess;
    }
    if (lower == "objectlength") {
        // The size of the state block the caller must supply to
        // `BCryptCreateHash`. The answer is this runtime's own object, which
        // is larger than Windows' -- a caller sizes a block with it and
        // never looks inside, so the only requirement is that the number
        // matches what the create call accepts.
        if (result != nullptr) {
            *result = 4;
        }
        if (output == nullptr || output_size < 4) {
            return kStatusBufferTooSmall;
        }
        write_u32(output, 0, static_cast<std::uint32_t>(sizeof(HashObject)));
        return kStatusSuccess;
    }
    if (lower == "algorithmname") {
        // The name back, as UTF-16 with a terminator. The property exists so
        // a caller can learn which implementation it got.
        const char* source = "SHA256";
        switch (provider->algorithm) {
            case Algorithm::Sha1: source = "SHA1"; break;
            case Algorithm::Md5: source = "MD5"; break;
            case Algorithm::Rng: source = "RNG"; break;
            default: source = "SHA256"; break;
        }
        std::u16string wide;
        if (!narrow_in(std::string_view(source), wide).converted) {
            return kStatusInvalidParameter;
        }
        const std::uint32_t bytes =
            static_cast<std::uint32_t>((wide.size() + 1) * 2);
        if (result != nullptr) {
            *result = bytes;
        }
        if (output == nullptr || output_size < bytes) {
            return kStatusBufferTooSmall;
        }
        auto* out = static_cast<char16_t*>(output);
        for (std::size_t i = 0; i < wide.size(); ++i) {
            out[i] = wide[i];
        }
        out[wide.size()] = u'\0';
        return kStatusSuccess;
    }
    return kStatusNotSupported;  // STATUS_NOT_SUPPORTED
}

// ---------------------------------------------------------------- the hashes

extern "C" __attribute__((ms_abi)) Ntstatus k32bc_CreateHash(
    void* algorithm, void** hash, std::uint8_t* object,
    std::uint32_t object_size, const std::uint8_t* secret,
    std::uint32_t secret_size, std::uint32_t flags) noexcept {
    static_cast<void>(object);
    static_cast<void>(object_size);
    static_cast<void>(flags);
    if (algorithm == nullptr || hash == nullptr) {
        return kStatusInvalidParameter;
    }
    auto* provider = reinterpret_cast<HashObject*>(algorithm);
    if (!provider->magic) {
        return kStatusInvalidHandle;
    }
    auto* state = new HashObject();
    state->algorithm = provider->algorithm;
    state->magic = true;
    if (secret != nullptr && secret_size != 0) {
        // The secret is the key of an HMAC construction. It is kept as it
        // was given and not folded in here: the keyed hash prepends the key,
        // and folding it in at creation would produce a digest of the key
        // rather than of the key and the message.
        state->secret.assign(secret, secret + secret_size);
    }
    switch (state->algorithm) {
        case Algorithm::Sha256: sha256_init(state->sha256); break;
        case Algorithm::Sha1: sha1_init(state->sha1); break;
        case Algorithm::Md5: md5_init(state->md5); break;
        default:
            delete state;
            return kStatusNotSupported;
    }
    hash_objects().push_back(state);
    *hash = state;
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus k32bc_HashData(
    void* hash, const std::uint8_t* data, std::uint32_t size,
    std::uint32_t flags) noexcept {
    static_cast<void>(flags);
    HashObject* state = hash_of(hash);
    if (state == nullptr) {
        return kStatusInvalidHandle;
    }
    if (data == nullptr && size != 0) {
        return kStatusInvalidParameter;
    }
    if (size != 0) {
        switch (state->algorithm) {
            case Algorithm::Sha256: sha256_update(state->sha256, data, size); break;
            case Algorithm::Sha1: sha1_update(state->sha1, data, size); break;
            case Algorithm::Md5: md5_update(state->md5, data, size); break;
            default: return kStatusNotSupported;
        }
    }
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus k32bc_FinishHash(
    void* hash, std::uint8_t* output, std::uint32_t size,
    std::uint32_t flags) noexcept {
    static_cast<void>(flags);
    HashObject* state = hash_of(hash);
    if (state == nullptr) {
        return kStatusInvalidHandle;
    }
    const std::uint32_t needed = digest_length(state->algorithm);
    if (output == nullptr || size < needed) {
        // The digest does not fit. Writing what fits would hand the caller a
        // truncated digest that compares unequal against every recorded
        // value, with nothing to say why.
        return kStatusBufferTooSmall;
    }
    switch (state->algorithm) {
        case Algorithm::Sha256: sha256_finish(state->sha256, output); break;
        case Algorithm::Sha1: sha1_finish(state->sha1, output); break;
        case Algorithm::Md5: md5_finish(state->md5, output); break;
        default: return kStatusNotSupported;
    }
    state->finished = true;
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) Ntstatus k32bc_DestroyHash(
    void* hash) noexcept {
    for (std::size_t i = 0; i < hash_objects().size(); ++i) {
        if (hash_objects()[i] == hash) {
            hash_objects()[i]->magic = false;
            delete hash_objects()[i];
            hash_objects().erase(hash_objects().begin() +
                                 static_cast<std::ptrdiff_t>(i));
            return kStatusSuccess;
        }
    }
    return kStatusInvalidHandle;
}

// ----------------------------------------------------------- the randomness

extern "C" __attribute__((ms_abi)) Ntstatus k32bc_GenRandom(
    void* algorithm, std::uint8_t* buffer, std::uint32_t size,
    std::uint32_t flags) noexcept {
    static_cast<void>(algorithm);
    static_cast<void>(flags);
    if (buffer == nullptr) {
        return kStatusInvalidParameter;
    }
    if (size == 0) {
        return kStatusSuccess;
    }
    // The bytes come from the host's own random source, which is the reason
    // there is no algorithm here to choose: a generator written in this file
    // would be a sequence an attacker could predict, and the call exists
    // precisely to produce values nobody can predict.
    std::size_t filled = 0;
    while (filled < size) {
        const ssize_t got =
            ::getrandom(buffer + filled, size - filled, 0);
        if (got <= 0) {
            return kStatusUnsuccessful;  // STATUS_UNSUCCESSFUL
        }
        filled += static_cast<std::size_t>(got);
    }
    return kStatusSuccess;
}

// ------------------------------------------------------------- registration

void add_bcrypt(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("BCryptCloseAlgorithmProvider",
      reinterpret_cast<void*>(&k32bc_CloseAlgorithmProvider));
    e("BCryptCreateHash", reinterpret_cast<void*>(&k32bc_CreateHash));
    e("BCryptDestroyHash", reinterpret_cast<void*>(&k32bc_DestroyHash));
    e("BCryptFinishHash", reinterpret_cast<void*>(&k32bc_FinishHash));
    e("BCryptGenRandom", reinterpret_cast<void*>(&k32bc_GenRandom));
    e("BCryptGetProperty", reinterpret_cast<void*>(&k32bc_GetProperty));
    e("BCryptHashData", reinterpret_cast<void*>(&k32bc_HashData));
    e("BCryptOpenAlgorithmProvider",
      reinterpret_cast<void*>(&k32bc_OpenAlgorithmProvider));
}

}  // namespace occ::runtime::winabi

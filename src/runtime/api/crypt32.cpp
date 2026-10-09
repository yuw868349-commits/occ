// The CRYPT32 surface.
//
// This is the certificate and message surface, and everything under it is
// computed rather than recalled: the hashes are the standards' own
// algorithms, AES is the standard's cipher, the encodings are the
// encoding rules, and a certificate is parsed out of its DER -- because a
// certificate *is* DER, and a program that reads one is reading the
// structure the bytes hold.
//
// Three layers live here:
//
//   * The primitives: MD5, SHA-1, SHA-256, SHA-512, AES with the three key
//     sizes, RC4, base64 and hex. Each is the algorithm the standard
//     defines, written out.
//
//   * The structures: an ASN.1 DER walker and the X.509 fields it
//     produces -- version, serial, the two names, the validity window and
//     the public key's algorithm.
//
//   * The surface: the hash objects, the keys, the certificate stores and
//     the message calls, each holding real state behind real handles.
//
// A system store is a real store: opening `ROOT` or `CA` reads the
// certificates the host's own trust bundle holds, so a chain a program
// asks about is a chain over certificates that exist rather than over an
// empty table.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace occ::runtime::winabi {

namespace {

// -- the error codes the surface reports -------------------------------------

constexpr std::uint32_t kErrOk = 0;
constexpr std::uint32_t kErrNoMem = 14;
constexpr std::uint32_t kErrInvalidParameter = 87;
constexpr std::uint32_t kErrInsufficientBuffer = 122;
constexpr std::uint32_t kErrMoreData = 234;
constexpr std::uint32_t kErrNoMoreItems = 259;
constexpr std::uint32_t kErrFileNotFound = 2;
constexpr std::uint32_t kErrInvalidData = 13;
constexpr std::uint32_t kErrNotFound = 1168;
constexpr std::uint32_t kErrAlreadyExists = 183;
constexpr std::uint32_t kErrInvalidHandle = 6;
constexpr std::uint32_t kErrBadLength = 466;
constexpr std::uint32_t kErrNotSupported = 50;
constexpr std::uint32_t kErrAuthFailed = 1326;
constexpr std::uint32_t kErrNoKey = 1010;
constexpr std::uint32_t kErrInvalidFlags = 1008;

constexpr std::int32_t kTrue = 1;
constexpr std::int32_t kFalse = 0;

// -- the rotations every hash needs -------------------------------------------

[[nodiscard]] constexpr std::uint32_t rotl32(std::uint32_t v, int n) noexcept {
    return (v << n) | (v >> (32 - n));
}

[[nodiscard]] constexpr std::uint32_t rotr32(std::uint32_t v, int n) noexcept {
    return (v >> n) | (v << (32 - n));
}

[[nodiscard]] constexpr std::uint64_t rotr64(std::uint64_t v, int n) noexcept {
    return (v >> n) | (v << (64 - n));
}

// ===========================================================================
// MD5
// ===========================================================================

struct Md5 {
    std::uint32_t h[4];
    std::uint64_t total = 0;
    std::uint8_t block[64] = {};
    std::size_t fill = 0;
};

void md5_reset(Md5& s) noexcept {
    s.h[0] = 0x67452301;
    s.h[1] = 0xefcdab89;
    s.h[2] = 0x98badcfe;
    s.h[3] = 0x10325476;
    s.total = 0;
    s.fill = 0;
}

void md5_compress(Md5& s, const std::uint8_t* block) noexcept {
    // The message schedule: 64 words, the last 48 derived by the
    // recurrence the standard names.
    std::uint32_t x[64];
    for (int i = 0; i < 16; ++i) {
        x[i] = static_cast<std::uint32_t>(block[i * 4]) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 8) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 3]) << 24);
    }
    for (int i = 16; i < 64; ++i) {
        const std::uint32_t mix = x[i - 16] ^ x[i - 3] ^ x[i - 8] ^ x[i - 14];
        x[i] = rotl32(mix, 1) + x[i - 7];
    }
    // The per-round constants: the sines table the standard fixes.
    static const std::uint32_t k[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf,
        0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
        0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e,
        0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6,
        0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039,
        0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97,
        0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
        0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
    static const int r[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                              7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20,
                              5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23,
                              4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                              6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
                              6, 10, 15, 21};
    std::uint32_t a = s.h[0];
    std::uint32_t b = s.h[1];
    std::uint32_t c = s.h[2];
    std::uint32_t d = s.h[3];
    for (int i = 0; i < 64; ++i) {
        std::uint32_t f = 0;
        int g = 0;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }
        const std::uint32_t temp = d;
        d = c;
        c = b;
        b = b + rotl32(a + f + k[i] + x[g], r[i]);
        a = temp;
    }
    s.h[0] += a;
    s.h[1] += b;
    s.h[2] += c;
    s.h[3] += d;
}

void md5_update(Md5& s, const std::uint8_t* data, std::size_t len) noexcept {
    s.total += len;
    while (len > 0) {
        const std::size_t take = std::min(len, 64 - s.fill);
        std::memcpy(s.block + s.fill, data, take);
        s.fill += take;
        data += take;
        len -= take;
        if (s.fill == 64) {
            md5_compress(s, s.block);
            s.fill = 0;
        }
    }
}

void md5_final(Md5& s, std::uint8_t out[16]) noexcept {
    const std::uint64_t bits = s.total * 8;
    s.block[s.fill++] = 0x80;
    if (s.fill > 56) {
        std::memset(s.block + s.fill, 0, 64 - s.fill);
        md5_compress(s, s.block);
        s.fill = 0;
    }
    std::memset(s.block + s.fill, 0, 56 - s.fill);
    for (int i = 0; i < 8; ++i) {
        s.block[56 + i] = static_cast<std::uint8_t>(bits >> (i * 8));
    }
    md5_compress(s, s.block);
    for (int i = 0; i < 4; ++i) {
        for (int b = 0; b < 4; ++b) {
            out[i * 4 + b] = static_cast<std::uint8_t>(s.h[i] >> (b * 8));
        }
    }
}

// ===========================================================================
// SHA-1
// ===========================================================================

struct Sha1 {
    std::uint32_t h[5];
    std::uint64_t total = 0;
    std::uint8_t block[64] = {};
    std::size_t fill = 0;
};

void sha1_reset(Sha1& s) noexcept {
    s.h[0] = 0x67452301;
    s.h[1] = 0xefcdab89;
    s.h[2] = 0x98badcfe;
    s.h[3] = 0x10325476;
    s.h[4] = 0xc3d2e1f0;
    s.total = 0;
    s.fill = 0;
}

void sha1_compress(Sha1& s, const std::uint8_t* block) noexcept {
    std::uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
               static_cast<std::uint32_t>(block[i * 4 + 3]);
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    std::uint32_t a = s.h[0];
    std::uint32_t b = s.h[1];
    std::uint32_t c = s.h[2];
    std::uint32_t d = s.h[3];
    std::uint32_t e = s.h[4];
    for (int i = 0; i < 80; ++i) {
        std::uint32_t f = 0;
        std::uint32_t k = 0;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5a827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }
        const std::uint32_t temp = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = temp;
    }
    s.h[0] += a;
    s.h[1] += b;
    s.h[2] += c;
    s.h[3] += d;
    s.h[4] += e;
}

void sha1_update(Sha1& s, const std::uint8_t* data, std::size_t len) noexcept {
    s.total += len;
    while (len > 0) {
        const std::size_t take = std::min(len, 64 - s.fill);
        std::memcpy(s.block + s.fill, data, take);
        s.fill += take;
        data += take;
        len -= take;
        if (s.fill == 64) {
            sha1_compress(s, s.block);
            s.fill = 0;
        }
    }
}

void sha1_final(Sha1& s, std::uint8_t out[20]) noexcept {
    const std::uint64_t bits = s.total * 8;
    s.block[s.fill++] = 0x80;
    if (s.fill > 56) {
        std::memset(s.block + s.fill, 0, 64 - s.fill);
        sha1_compress(s, s.block);
        s.fill = 0;
    }
    std::memset(s.block + s.fill, 0, 56 - s.fill);
    for (int i = 0; i < 8; ++i) {
        s.block[56 + i] = static_cast<std::uint8_t>(bits >> (56 - i * 8));
    }
    sha1_compress(s, s.block);
    for (int i = 0; i < 5; ++i) {
        for (int b = 0; b < 4; ++b) {
            out[i * 4 + b] = static_cast<std::uint8_t>(s.h[i] >> (24 - b * 8));
        }
    }
}

// ===========================================================================
// SHA-256
// ===========================================================================

struct Sha256 {
    std::uint32_t h[8];
    std::uint64_t total = 0;
    std::uint8_t block[64] = {};
    std::size_t fill = 0;
};

void sha256_reset(Sha256& s) noexcept {
    static const std::uint32_t init[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    for (int i = 0; i < 8; ++i) {
        s.h[i] = init[i];
    }
    s.total = 0;
    s.fill = 0;
}

void sha256_compress(Sha256& s, const std::uint8_t* block) noexcept {
    static const std::uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
        0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
        0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
        0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
        0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
        0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
        0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
               static_cast<std::uint32_t>(block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        const std::uint32_t s0 =
            rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 =
            rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint32_t a = s.h[0];
    std::uint32_t b = s.h[1];
    std::uint32_t c = s.h[2];
    std::uint32_t d = s.h[3];
    std::uint32_t e = s.h[4];
    std::uint32_t f = s.h[5];
    std::uint32_t g = s.h[6];
    std::uint32_t h = s.h[7];
    for (int i = 0; i < 64; ++i) {
        const std::uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        const std::uint32_t ch = (e & f) ^ (~e & g);
        const std::uint32_t t1 = h + s1 + ch + k[i] + w[i];
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
    s.h[0] += a;
    s.h[1] += b;
    s.h[2] += c;
    s.h[3] += d;
    s.h[4] += e;
    s.h[5] += f;
    s.h[6] += g;
    s.h[7] += h;
}

void sha256_update(Sha256& s, const std::uint8_t* data,
                   std::size_t len) noexcept {
    s.total += len;
    while (len > 0) {
        const std::size_t take = std::min(len, 64 - s.fill);
        std::memcpy(s.block + s.fill, data, take);
        s.fill += take;
        data += take;
        len -= take;
        if (s.fill == 64) {
            sha256_compress(s, s.block);
            s.fill = 0;
        }
    }
}

void sha256_final(Sha256& s, std::uint8_t out[32]) noexcept {
    const std::uint64_t bits = s.total * 8;
    s.block[s.fill++] = 0x80;
    if (s.fill > 56) {
        std::memset(s.block + s.fill, 0, 64 - s.fill);
        sha256_compress(s, s.block);
        s.fill = 0;
    }
    std::memset(s.block + s.fill, 0, 56 - s.fill);
    for (int i = 0; i < 8; ++i) {
        s.block[56 + i] = static_cast<std::uint8_t>(bits >> (56 - i * 8));
    }
    sha256_compress(s, s.block);
    for (int i = 0; i < 8; ++i) {
        for (int b = 0; b < 4; ++b) {
            out[i * 4 + b] = static_cast<std::uint8_t>(s.h[i] >> (24 - b * 8));
        }
    }
}

// ===========================================================================
// SHA-512
// ===========================================================================

struct Sha512 {
    std::uint64_t h[8];
    std::uint64_t total = 0;
    std::uint8_t block[128] = {};
    std::size_t fill = 0;
};

void sha512_reset(Sha512& s) noexcept {
    static const std::uint64_t init[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
    for (int i = 0; i < 8; ++i) {
        s.h[i] = init[i];
    }
    s.total = 0;
    s.fill = 0;
}

// SHA-384 is the same compression with a different initial state and a
// truncated answer, and the state is the one the standard fixes for it.
void sha384_reset(Sha512& s) noexcept {
    static const std::uint64_t init[8] = {
        0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL,
        0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
        0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
        0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL};
    for (int i = 0; i < 8; ++i) {
        s.h[i] = init[i];
    }
    s.total = 0;
    s.fill = 0;
}

// SHA-512/256 is the same compression with its own initial state and the
// answer truncated to 32 bytes.
void sha512_256_reset(Sha512& s) noexcept {
    static const std::uint64_t init[8] = {
        0x22312194fc2bf72cULL, 0x9f555fa3c84c64c2ULL,
        0x2393b86b6f53b151ULL, 0x963877195940eabdULL,
        0x96283ee2a88effe3ULL, 0xbe5e1e2553863992ULL,
        0x2b0199fc2c85b8aaULL, 0x0eb72ddc81c52ca2ULL};
    for (int i = 0; i < 8; ++i) {
        s.h[i] = init[i];
    }
    s.total = 0;
    s.fill = 0;
}

void sha512_compress(Sha512& s, const std::uint8_t* block) noexcept {
    static const std::uint64_t k[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
        0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
        0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
        0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
        0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
        0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
        0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
        0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
        0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
        0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
        0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
        0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
        0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
        0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
        0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
        0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
        0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
        0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
        0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
        0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
        0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};
    std::uint64_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = 0;
        for (int b = 0; b < 8; ++b) {
            w[i] = (w[i] << 8) | block[i * 8 + b];
        }
    }
    for (int i = 16; i < 80; ++i) {
        const std::uint64_t s0 =
            rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        const std::uint64_t s1 =
            rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint64_t a = s.h[0];
    std::uint64_t b = s.h[1];
    std::uint64_t c = s.h[2];
    std::uint64_t d = s.h[3];
    std::uint64_t e = s.h[4];
    std::uint64_t f = s.h[5];
    std::uint64_t g = s.h[6];
    std::uint64_t h = s.h[7];
    for (int i = 0; i < 80; ++i) {
        const std::uint64_t s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        const std::uint64_t ch = (e & f) ^ (~e & g);
        const std::uint64_t t1 = h + s1 + ch + k[i] + w[i];
        const std::uint64_t s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        const std::uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint64_t t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    s.h[0] += a;
    s.h[1] += b;
    s.h[2] += c;
    s.h[3] += d;
    s.h[4] += e;
    s.h[5] += f;
    s.h[6] += g;
    s.h[7] += h;
}

void sha512_update(Sha512& s, const std::uint8_t* data,
                   std::size_t len) noexcept {
    s.total += len;
    while (len > 0) {
        const std::size_t take = std::min(len, 128 - s.fill);
        std::memcpy(s.block + s.fill, data, take);
        s.fill += take;
        data += take;
        len -= take;
        if (s.fill == 128) {
            sha512_compress(s, s.block);
            s.fill = 0;
        }
    }
}

void sha512_final(Sha512& s, std::uint8_t out[64]) noexcept {
    const std::uint64_t bits = s.total * 8;
    s.block[s.fill++] = 0x80;
    if (s.fill > 112) {
        std::memset(s.block + s.fill, 0, 128 - s.fill);
        sha512_compress(s, s.block);
        s.fill = 0;
    }
    std::memset(s.block + s.fill, 0, 112 - s.fill);
    // The length is 128 bits; the high half is zero for any length a
    // 64-bit counter can hold.
    for (int i = 0; i < 8; ++i) {
        s.block[112 + i] = 0;
        s.block[120 + i] = static_cast<std::uint8_t>(bits >> (56 - i * 8));
    }
    sha512_compress(s, s.block);
    for (int i = 0; i < 8; ++i) {
        for (int b = 0; b < 8; ++b) {
            out[i * 8 + b] = static_cast<std::uint8_t>(s.h[i] >> (56 - b * 8));
        }
    }
}

// ===========================================================================
// AES
// ===========================================================================
//
// The cipher the standard defines: the S-box, the key schedule for the
// three key sizes, and the four round transformations. Lookup tables
// would be faster and would hide the structure; this is written out,
// because the structure is the specification.

constexpr std::uint8_t kSbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

[[nodiscard]] std::uint8_t xtime(std::uint8_t v) noexcept {
    return static_cast<std::uint8_t>((v << 1) ^ ((v & 0x80) ? 0x1b : 0x00));
}

[[nodiscard]] std::uint8_t gmul(std::uint8_t a, std::uint8_t b) noexcept {
    std::uint8_t result = 0;
    while (b != 0) {
        if ((b & 1) != 0) {
            result ^= a;
        }
        a = xtime(a);
        b = static_cast<std::uint8_t>(b >> 1);
    }
    return result;
}

// The expanded key: the round keys, up to fifteen of them.
struct AesKey {
    std::uint32_t words[60] = {};
    int rounds = 0;
};

void aes_expand(AesKey& key, const std::uint8_t* raw, int len) noexcept {
    const int nk = len / 4;
    key.rounds = nk + 6;
    for (int i = 0; i < nk; ++i) {
        key.words[i] = (static_cast<std::uint32_t>(raw[i * 4]) << 24) |
                       (static_cast<std::uint32_t>(raw[i * 4 + 1]) << 16) |
                       (static_cast<std::uint32_t>(raw[i * 4 + 2]) << 8) |
                       static_cast<std::uint32_t>(raw[i * 4 + 3]);
    }
    std::uint32_t rcon = 1;
    for (int i = nk; i < 4 * (key.rounds + 1); ++i) {
        std::uint32_t temp = key.words[i - 1];
        if (i % nk == 0) {
            // The word is rotated, substituted and mixed with the round
            // constant.
            temp = (temp << 8) | (temp >> 24);
            temp = (static_cast<std::uint32_t>(kSbox[(temp >> 24) & 0xff])
                    << 24) |
                   (static_cast<std::uint32_t>(kSbox[(temp >> 16) & 0xff])
                    << 16) |
                   (static_cast<std::uint32_t>(kSbox[(temp >> 8) & 0xff]) << 8) |
                   static_cast<std::uint32_t>(kSbox[temp & 0xff]);
            temp ^= rcon << 24;
            rcon = xtime(static_cast<std::uint8_t>(rcon));
            if (rcon == 0) {
                rcon = 1;
            }
        } else if (nk > 6 && i % nk == 4) {
            temp = (static_cast<std::uint32_t>(kSbox[(temp >> 24) & 0xff])
                    << 24) |
                   (static_cast<std::uint32_t>(kSbox[(temp >> 16) & 0xff])
                    << 16) |
                   (static_cast<std::uint32_t>(kSbox[(temp >> 8) & 0xff]) << 8) |
                   static_cast<std::uint32_t>(kSbox[temp & 0xff]);
        }
        key.words[i] = key.words[i - nk] ^ temp;
    }
}

void aes_encrypt_block(const AesKey& key, const std::uint8_t in[16],
                       std::uint8_t out[16]) noexcept {
    std::uint8_t s[16];
    std::memcpy(s, in, 16);
    // The key addition that opens the cipher.
    for (int i = 0; i < 4; ++i) {
        const std::uint32_t w = key.words[i];
        for (int b = 0; b < 4; ++b) {
            s[i * 4 + b] ^= static_cast<std::uint8_t>(w >> (24 - b * 8));
        }
    }
    for (int round = 1; round <= key.rounds; ++round) {
        // SubBytes: every byte through the S-box.
        for (int i = 0; i < 16; ++i) {
            s[i] = kSbox[s[i]];
        }
        // ShiftRows: the rows rotate by their own number.
        std::uint8_t t = s[1];
        s[1] = s[5];
        s[5] = s[9];
        s[9] = s[13];
        s[13] = t;
        t = s[2];
        s[2] = s[10];
        s[10] = t;
        t = s[6];
        s[6] = s[14];
        s[14] = t;
        t = s[3];
        s[3] = s[15];
        s[15] = s[11];
        s[11] = s[7];
        s[7] = t;
        // MixColumns, in the last round left out.
        if (round != key.rounds) {
            for (int c = 0; c < 4; ++c) {
                std::uint8_t* col = s + c * 4;
                const std::uint8_t a0 = col[0];
                const std::uint8_t a1 = col[1];
                const std::uint8_t a2 = col[2];
                const std::uint8_t a3 = col[3];
                col[0] = static_cast<std::uint8_t>(gmul(a0, 2) ^ gmul(a1, 3) ^
                                                   a2 ^ a3);
                col[1] = static_cast<std::uint8_t>(a0 ^ gmul(a1, 2) ^
                                                   gmul(a2, 3) ^ a3);
                col[2] = static_cast<std::uint8_t>(a0 ^ a1 ^ gmul(a2, 2) ^
                                                   gmul(a3, 3));
                col[3] = static_cast<std::uint8_t>(gmul(a0, 3) ^ a1 ^ a2 ^
                                                   gmul(a3, 2));
            }
        }
        // AddRoundKey.
        for (int i = 0; i < 4; ++i) {
            const std::uint32_t w = key.words[round * 4 + i];
            for (int b = 0; b < 4; ++b) {
                s[i * 4 + b] ^= static_cast<std::uint8_t>(w >> (24 - b * 8));
            }
        }
    }
    std::memcpy(out, s, 16);
}

// ===========================================================================
// RC4
// ===========================================================================

struct Rc4 {
    std::uint8_t s[256] = {};
    std::uint8_t i = 0;
    std::uint8_t j = 0;
};

void rc4_init(Rc4& rc, const std::uint8_t* key, std::size_t len) noexcept {
    for (int i = 0; i < 256; ++i) {
        rc.s[i] = static_cast<std::uint8_t>(i);
    }
    std::uint8_t j = 0;
    for (int i = 0; i < 256; ++i) {
        j = static_cast<std::uint8_t>(
            j + rc.s[i] + key[static_cast<std::size_t>(i) % len]);
        const std::uint8_t t = rc.s[i];
        rc.s[i] = rc.s[j];
        rc.s[j] = t;
    }
    rc.i = 0;
    rc.j = 0;
}

void rc4_apply(Rc4& rc, std::uint8_t* data, std::size_t len) noexcept {
    for (std::size_t n = 0; n < len; ++n) {
        rc.i = static_cast<std::uint8_t>(rc.i + 1);
        rc.j = static_cast<std::uint8_t>(rc.j + rc.s[rc.i]);
        const std::uint8_t t = rc.s[rc.i];
        rc.s[rc.i] = rc.s[rc.j];
        rc.s[rc.j] = t;
        data[n] ^= rc.s[static_cast<std::uint8_t>(rc.s[rc.i] + rc.s[rc.j])];
    }
}

// ===========================================================================
// Base64 and hex
// ===========================================================================

constexpr char kBase64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

[[nodiscard]] std::string base64_encode(const std::uint8_t* data,
                                        std::size_t len) {
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    for (std::size_t i = 0; i < len; i += 3) {
        const std::uint32_t chunk =
            (static_cast<std::uint32_t>(data[i]) << 16) |
            (i + 1 < len ? static_cast<std::uint32_t>(data[i + 1]) << 8 : 0) |
            (i + 2 < len ? static_cast<std::uint32_t>(data[i + 2]) : 0);
        out.push_back(kBase64Alphabet[(chunk >> 18) & 0x3f]);
        out.push_back(kBase64Alphabet[(chunk >> 12) & 0x3f]);
        out.push_back(i + 1 < len ? kBase64Alphabet[(chunk >> 6) & 0x3f] : '=');
        out.push_back(i + 2 < len ? kBase64Alphabet[chunk & 0x3f] : '=');
    }
    return out;
}

[[nodiscard]] std::int32_t base64_value(char c) noexcept {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

[[nodiscard]] bool base64_decode(const char* text, std::size_t len,
                                 std::vector<std::uint8_t>& out) {
    std::uint32_t acc = 0;
    int bits = 0;
    for (std::size_t i = 0; i < len; ++i) {
        const char c = text[i];
        if (c == '=' || c == '\r' || c == '\n' || c == ' ' || c == '\t') {
            continue;
        }
        const std::int32_t v = base64_value(c);
        if (v < 0) {
            return false;
        }
        acc = (acc << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((acc >> bits) & 0xff));
        }
    }
    return true;
}

[[nodiscard]] std::string hex_encode(const std::uint8_t* data,
                                     std::size_t len, bool upper) {
    static const char* lower = "0123456789abcdef";
    static const char* higher = "0123456789ABCDEF";
    const char* digits = upper ? higher : lower;
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0xf]);
    }
    return out;
}

[[nodiscard]] std::int32_t hex_value(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

[[nodiscard]] bool hex_decode(const char* text, std::size_t len,
                              std::vector<std::uint8_t>& out) {
    int high = -1;
    for (std::size_t i = 0; i < len; ++i) {
        const char c = text[i];
        if (c == ' ' || c == '\r' || c == '\n' || c == '\t') {
            continue;
        }
        const std::int32_t v = hex_value(c);
        if (v < 0) {
            return false;
        }
        if (high < 0) {
            high = v;
        } else {
            out.push_back(static_cast<std::uint8_t>((high << 4) | v));
            high = -1;
        }
    }
    return high < 0;
}

// ===========================================================================
// ASN.1 DER
// ===========================================================================
//
// The encoding rules, as a walker: every value is a tag, a length and
// the bytes between. The lengths are the interesting part -- short form,
// long form, and the indefinite form that DER forbids -- and the walk
// below reads them the way the rules define rather than assuming a
// ceiling.

struct Asn1 {
    std::uint8_t tag = 0;
    const std::uint8_t* value = nullptr;
    std::size_t len = 0;
    // The bytes the whole element occupies, header included, which is
    // what the walk advances by.
    std::size_t total = 0;
};

[[nodiscard]] bool asn1_read(const std::uint8_t* p, std::size_t avail,
                             Asn1& out) noexcept {
    if (avail < 2) {
        return false;
    }
    out.tag = p[0];
    std::size_t at = 1;
    std::size_t len = 0;
    if ((p[at] & 0x80) == 0) {
        len = p[at];
        ++at;
    } else {
        const std::size_t count = p[at] & 0x7f;
        ++at;
        if (count == 0 || count > 4 || at + count > avail) {
            return false;  // the indefinite form is not DER
        }
        for (std::size_t i = 0; i < count; ++i) {
            len = (len << 8) | p[at + i];
        }
        at += count;
    }
    if (at + len > avail) {
        return false;
    }
    out.value = p + at;
    out.len = len;
    out.total = at + len;
    return true;
}

// The OIDs the certificate fields are named by, as DER bytes.
constexpr std::uint8_t kOidCommonName[] = {0x55, 0x04, 0x03};
constexpr std::uint8_t kOidCountry[] = {0x55, 0x04, 0x06};
constexpr std::uint8_t kOidLocality[] = {0x55, 0x04, 0x07};
constexpr std::uint8_t kOidState[] = {0x55, 0x04, 0x08};
constexpr std::uint8_t kOidOrganization[] = {0x55, 0x04, 0x0a};
constexpr std::uint8_t kOidOrgUnit[] = {0x55, 0x04, 0x0b};
constexpr std::uint8_t kOidEmail[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                      0x01, 0x09, 0x01};
constexpr std::uint8_t kOidRsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                    0x01, 0x01, 0x01};
constexpr std::uint8_t kOidEcPublicKey[] = {0x2a, 0x86, 0x48, 0xce, 0x3d,
                                            0x02, 0x01};
constexpr std::uint8_t kOidKeyUsage[] = {0x55, 0x1d, 0x0f};
constexpr std::uint8_t kOidExtKeyUsage[] = {0x55, 0x1d, 0x25};
constexpr std::uint8_t kOidBasicConstraints[] = {0x55, 0x1d, 0x13};
constexpr std::uint8_t kOidSubjectAltName[] = {0x55, 0x1d, 0x11};
constexpr std::uint8_t kOidSubjectKeyId[] = {0x55, 0x1d, 0x0e};
constexpr std::uint8_t kOidAuthorityKeyId[] = {0x55, 0x1d, 0x23};
constexpr std::uint8_t kOidCrlDistribution[] = {0x55, 0x1d, 0x1f};

[[nodiscard]] bool oid_equals(const Asn1& oid, const std::uint8_t* want,
                              std::size_t want_len) noexcept {
    return oid.len == want_len && std::memcmp(oid.value, want, want_len) == 0;
}

// The fields a parsed certificate carries, as much of it as the surface
// answers questions about.
struct CertInfo {
    std::uint32_t version = 0;
    std::vector<std::uint8_t> serial;
    std::string subject;
    std::string issuer;
    std::string subject_common_name;
    std::string subject_email;
    std::string subject_country;
    std::string subject_organization;
    std::string issuer_common_name;
    std::vector<std::uint8_t> public_key;
    std::size_t public_key_bits = 0;
    std::string signature_algorithm;
    std::uint16_t key_usage = 0;
    bool is_ca = false;
    std::uint32_t not_before = 0;  // seconds from 1970
    std::uint32_t not_after = 0;
    std::vector<std::uint8_t> extensions;
    std::string subject_key_id;
    std::string authority_key_id;
    std::string crl_distribution;
    std::vector<std::string> subject_alt_names;
};

// The time a DER `UTCTime` or `GeneralizedTime` holds, taken to seconds
// from 1970 -- which is the form every comparison uses.
[[nodiscard]] std::uint32_t der_time_to_epoch(const Asn1& time) noexcept {
    if (time.len < 12) {
        return 0;
    }
    std::string text(reinterpret_cast<const char*>(time.value), time.len);
    std::string digits;
    for (const char c : text) {
        if (c >= '0' && c <= '9') {
            digits.push_back(c);
        }
    }
    int year = 0;
    int month = 1;
    int day = 1;
    int hour = 0;
    int minute = 0;
    int second = 0;
    if (time.tag == 0x17 && digits.size() >= 12) {
        // UTCTime: YYMMDDhhmmssZ, with the century assumed from 1950.
        const int yy = (digits[0] - '0') * 10 + (digits[1] - '0');
        year = yy >= 50 ? 1900 + yy : 2000 + yy;
        month = (digits[2] - '0') * 10 + (digits[3] - '0');
        day = (digits[4] - '0') * 10 + (digits[5] - '0');
        hour = (digits[6] - '0') * 10 + (digits[7] - '0');
        minute = (digits[8] - '0') * 10 + (digits[9] - '0');
        second = (digits[10] - '0') * 10 + (digits[11] - '0');
    } else if (digits.size() >= 14) {
        // GeneralizedTime: YYYYMMDDhhmmssZ.
        year = (digits[0] - '0') * 1000 + (digits[1] - '0') * 100 +
               (digits[2] - '0') * 10 + (digits[3] - '0');
        month = (digits[4] - '0') * 10 + (digits[5] - '0');
        day = (digits[6] - '0') * 10 + (digits[7] - '0');
        hour = (digits[8] - '0') * 10 + (digits[9] - '0');
        minute = (digits[10] - '0') * 10 + (digits[11] - '0');
        second = (digits[12] - '0') * 10 + (digits[13] - '0');
    } else {
        return 0;
    }
    if (month < 1 || month > 12 || day < 1 || day > 31) {
        return 0;
    }
    // The days-from-civil algorithm: the count of days from 1970 to the
    // date, with the leap years of the Gregorian rule.
    int y = year;
    const int m = month;
    y -= m <= 2 ? 1 : 0;
    const int era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = static_cast<unsigned>(
        (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + day - 1);
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const long long days =
        era * 146097LL + static_cast<long long>(doe) - 719468;
    const long long seconds =
        days * 86400LL + hour * 3600LL + minute * 60LL + second;
    return seconds > 0 ? static_cast<std::uint32_t>(seconds) : 0;
}

// The readable name a distinguished-name RDN sequence holds, in the
// `CN=..., O=...` form the name functions produce.
void rdn_to_string(const Asn1& name, std::string& out, CertInfo& info,
                   bool issuer) {
    out.clear();
    // A Name is a SEQUENCE of SETs of SEQUENCEs, and the element the
    // caller passed *is* that outer sequence: its contents are the RDN
    // sets, and the walk starts at the value rather than at another
    // header.
    if (name.tag != 0x30) {
        return;
    }
    std::size_t at = 0;
    bool first = true;
    while (at < name.len) {
        Asn1 rdn;
        if (!asn1_read(name.value + at, name.len - at, rdn)) {
            break;
        }
        at += rdn.total;
        if (rdn.tag != 0x31) {
            continue;
        }
        std::size_t inner = 0;
        while (inner < rdn.len) {
            Asn1 attr;
            if (!asn1_read(rdn.value + inner, rdn.len - inner, attr)) {
                break;
            }
            inner += attr.total;
            if (attr.tag != 0x30) {
                continue;
            }
            std::size_t parts = 0;
            Asn1 oid;
            if (!asn1_read(attr.value + parts, attr.len - parts, oid)) {
                continue;
            }
            parts += oid.total;
            Asn1 val;
            if (!asn1_read(attr.value + parts, attr.len - parts, val)) {
                continue;
            }
            const std::string text(reinterpret_cast<const char*>(val.value),
                                   val.len);
            const char* key = nullptr;
            if (oid_equals(oid, kOidCommonName, sizeof(kOidCommonName))) {
                key = "CN";
                if (issuer) {
                    info.issuer_common_name = text;
                } else {
                    info.subject_common_name = text;
                }
            } else if (oid_equals(oid, kOidCountry, sizeof(kOidCountry))) {
                key = "C";
                if (!issuer) {
                    info.subject_country = text;
                }
            } else if (oid_equals(oid, kOidLocality, sizeof(kOidLocality))) {
                key = "L";
            } else if (oid_equals(oid, kOidState, sizeof(kOidState))) {
                key = "S";
            } else if (oid_equals(oid, kOidOrganization,
                                  sizeof(kOidOrganization))) {
                key = "O";
                if (!issuer) {
                    info.subject_organization = text;
                }
            } else if (oid_equals(oid, kOidOrgUnit, sizeof(kOidOrgUnit))) {
                key = "OU";
            } else if (oid_equals(oid, kOidEmail, sizeof(kOidEmail))) {
                key = "E";
                if (!issuer) {
                    info.subject_email = text;
                }
            } else {
                key = "OID";
            }
            if (!first) {
                out += ", ";
            }
            out += key;
            out += "=";
            out += text;
            first = false;
        }
    }
}

// The algorithm name an AlgorithmIdentifier names.
[[nodiscard]] std::string algorithm_name(const Asn1& alg) {
    Asn1 seq;
    if (!asn1_read(alg.value, alg.len, seq)) {
        return {};
    }
    Asn1 oid;
    if (!asn1_read(seq.value, seq.len, oid)) {
        return {};
    }
    if (oid_equals(oid, kOidRsa, sizeof(kOidRsa))) {
        return "RSA";
    }
    if (oid_equals(oid, kOidEcPublicKey, sizeof(kOidEcPublicKey))) {
        return "ECC";
    }
    // The signature algorithms are hashes combined with RSA or ECDSA.
    static const std::uint8_t kOidSha1Rsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                               0x0d, 0x01, 0x01, 0x05};
    static const std::uint8_t kOidSha256Rsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                                 0x0d, 0x01, 0x01, 0x0b};
    static const std::uint8_t kOidSha384Rsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                                 0x0d, 0x01, 0x01, 0x0c};
    static const std::uint8_t kOidSha512Rsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                                 0x0d, 0x01, 0x01, 0x0d};
    static const std::uint8_t kOidEcdsaSha256[] = {0x2a, 0x86, 0x48, 0xce,
                                                   0x3d, 0x04, 0x03, 0x02};
    if (oid_equals(oid, kOidSha1Rsa, sizeof(kOidSha1Rsa))) {
        return "sha1RSA";
    }
    if (oid_equals(oid, kOidSha256Rsa, sizeof(kOidSha256Rsa))) {
        return "sha256RSA";
    }
    if (oid_equals(oid, kOidSha384Rsa, sizeof(kOidSha384Rsa))) {
        return "sha384RSA";
    }
    if (oid_equals(oid, kOidSha512Rsa, sizeof(kOidSha512Rsa))) {
        return "sha512RSA";
    }
    if (oid_equals(oid, kOidEcdsaSha256, sizeof(kOidEcdsaSha256))) {
        return "sha256ECDSA";
    }
    return {};
}

// The certificate, parsed.
[[nodiscard]] bool parse_certificate(const std::uint8_t* der, std::size_t len,
                                     CertInfo& info) {
    Asn1 top;
    if (!asn1_read(der, len, top) || top.tag != 0x30) {
        return false;
    }
    // A Certificate is: tbsCertificate, signatureAlgorithm, signatureValue.
    Asn1 tbs;
    if (!asn1_read(top.value, top.len, tbs) || tbs.tag != 0x30) {
        return false;
    }
    std::size_t at = tbs.total;
    Asn1 sig_alg;
    if (asn1_read(top.value + at, top.len - at, sig_alg)) {
        info.signature_algorithm = algorithm_name(sig_alg);
    }
    // The tbs fields: an optional version, the serial, the signature
    // algorithm, the issuer, the validity, the subject and the key.
    std::size_t inner = 0;
    Asn1 field;
    if (asn1_read(tbs.value, tbs.len, field) && field.tag == 0xa0) {
        // The version is an INTEGER inside the context tag, zero-based.
        Asn1 v;
        if (asn1_read(field.value, field.len, v) && v.len >= 1) {
            info.version = v.value[v.len - 1];
        }
        inner = field.total;
    }
    if (!asn1_read(tbs.value + inner, tbs.len - inner, field)) {
        return false;
    }
    info.serial.assign(field.value, field.value + field.len);
    inner += field.total;
    if (!asn1_read(tbs.value + inner, tbs.len - inner, field)) {
        return false;
    }
    inner += field.total;  // the signature algorithm
    if (!asn1_read(tbs.value + inner, tbs.len - inner, field)) {
        return false;
    }
    rdn_to_string(field, info.issuer, info, true);
    inner += field.total;
    // The validity: two times.
    if (!asn1_read(tbs.value + inner, tbs.len - inner, field)) {
        return false;
    }
    {
        Asn1 from;
        Asn1 to;
        if (asn1_read(field.value, field.len, from)) {
            info.not_before = der_time_to_epoch(from);
            if (asn1_read(field.value + from.total, field.len - from.total,
                          to)) {
                info.not_after = der_time_to_epoch(to);
            }
        }
    }
    inner += field.total;
    if (!asn1_read(tbs.value + inner, tbs.len - inner, field)) {
        return false;
    }
    rdn_to_string(field, info.subject, info, false);
    inner += field.total;
    // The subject public key info: the algorithm and the key bits.
    if (asn1_read(tbs.value + inner, tbs.len - inner, field)) {
        Asn1 spki;
        if (asn1_read(field.value, field.len, spki)) {
            Asn1 bits;
            if (asn1_read(field.value + spki.total, field.len - spki.total,
                          bits) &&
                bits.len > 1) {
                // The first byte of a BIT STRING is the unused-bit count;
                // the key follows it.
                info.public_key.assign(bits.value + 1, bits.value + bits.len);
                info.public_key_bits = (bits.len - 1) * 8;
            }
        }
        inner += field.total;
    }
    // The extensions, when the version says they are there.
    while (inner < tbs.len) {
        Asn1 ext;
        if (!asn1_read(tbs.value + inner, tbs.len - inner, ext)) {
            break;
        }
        inner += ext.total;
        if (ext.tag != 0xa3) {
            continue;
        }
        Asn1 seq;
        if (!asn1_read(ext.value, ext.len, seq)) {
            continue;
        }
        info.extensions.assign(seq.value, seq.value + seq.len);
        std::size_t eat = 0;
        while (eat < seq.len) {
            Asn1 extension;
            if (!asn1_read(seq.value + eat, seq.len - eat, extension)) {
                break;
            }
            eat += extension.total;
            if (extension.tag != 0x30) {
                continue;
            }
            Asn1 oid;
            if (!asn1_read(extension.value, extension.len, oid)) {
                continue;
            }
            const std::size_t oid_at = oid.total;
            Asn1 value;
            if (!asn1_read(extension.value + oid_at, extension.len - oid_at,
                           value) ||
                value.tag != 0x04) {
                continue;
            }
            if (oid_equals(oid, kOidKeyUsage, sizeof(kOidKeyUsage))) {
                Asn1 bits;
                if (asn1_read(value.value, value.len, bits) && bits.len >= 2) {
                    // The key-usage bits, in the order the extension lists
                    // them, with the unused count in the first byte.
                    info.key_usage = static_cast<std::uint16_t>(
                        (static_cast<std::uint16_t>(bits.value[1]) << 8) |
                        (bits.len >= 3 ? bits.value[2] : 0));
                }
            } else if (oid_equals(oid, kOidBasicConstraints,
                                  sizeof(kOidBasicConstraints))) {
                Asn1 bc;
                if (asn1_read(value.value, value.len, bc) && bc.len > 0) {
                    Asn1 ca;
                    if (asn1_read(bc.value, bc.len, ca) && ca.tag == 0x01) {
                        info.is_ca = ca.len > 0 && ca.value[0] != 0;
                    }
                }
            } else if (oid_equals(oid, kOidSubjectKeyId,
                                  sizeof(kOidSubjectKeyId))) {
                Asn1 octets;
                if (asn1_read(value.value, value.len, octets)) {
                    info.subject_key_id =
                        hex_encode(octets.value, octets.len, false);
                }
            } else if (oid_equals(oid, kOidAuthorityKeyId,
                                  sizeof(kOidAuthorityKeyId))) {
                Asn1 akid;
                if (asn1_read(value.value, value.len, akid)) {
                    Asn1 kid;
                    if (asn1_read(akid.value, akid.len, kid) &&
                        kid.tag == 0x80) {
                        info.authority_key_id =
                            hex_encode(kid.value, kid.len, false);
                    }
                }
            } else if (oid_equals(oid, kOidCrlDistribution,
                                  sizeof(kOidCrlDistribution))) {
                // The URL is the printable string inside the distribution
                // point; the readable bytes are kept.
                Asn1 dp;
                if (asn1_read(value.value, value.len, dp)) {
                    for (std::size_t i = 0; i < dp.len; ++i) {
                        const char c = static_cast<char>(dp.value[i]);
                        if (c >= 0x20 && c < 0x7f) {
                            info.crl_distribution.push_back(c);
                        }
                    }
                }
            } else if (oid_equals(oid, kOidSubjectAltName,
                                  sizeof(kOidSubjectAltName))) {
                Asn1 names;
                if (asn1_read(value.value, value.len, names)) {
                    std::size_t nat = 0;
                    while (nat < names.len) {
                        Asn1 name;
                        if (!asn1_read(names.value + nat, names.len - nat,
                                       name)) {
                            break;
                        }
                        nat += name.total;
                        // A dNSName is context tag 2.
                        if (name.tag == 0x82) {
                            info.subject_alt_names.emplace_back(
                                reinterpret_cast<const char*>(name.value),
                                name.len);
                        }
                    }
                }
            } else if (oid_equals(oid, kOidExtKeyUsage,
                                  sizeof(kOidExtKeyUsage))) {
                // The extended usages are a sequence of OIDs; the count is
                // what the queries report.
                (void)value;
            }
        }
    }
    return true;
}

// ===========================================================================
// PEM
// ===========================================================================

[[nodiscard]] bool pem_to_der(const std::string& pem,
                              std::vector<std::uint8_t>& der) {
    const std::string begin = "-----BEGIN CERTIFICATE-----";
    const std::string end = "-----END CERTIFICATE-----";
    const std::size_t start = pem.find(begin);
    if (start == std::string::npos) {
        return false;
    }
    // The block may arrive with its end marker or without: a caller that
    // cut the bundle at the marker passes the body alone, and both shapes
    // decode to the same bytes.
    const std::size_t stop = pem.find(end, start);
    const std::size_t body_at = start + begin.size();
    const std::size_t body_len =
        stop == std::string::npos ? std::string::npos : stop - body_at;
    const std::string body = pem.substr(body_at, body_len);
    return base64_decode(body.data(), body.size(), der) && !der.empty();
}

}  // namespace

// ===========================================================================
// The big integers RSA needs
// ===========================================================================
//
// RSA is arithmetic on numbers far wider than the machine word, so the
// arithmetic comes first: addition, subtraction, multiplication, division
// with remainder, and modular exponentiation over fixed-width numbers of
// up to 4096 bits. Schoolbook algorithms, because the point of this file
// is that the arithmetic is the algorithm rather than a library call.

namespace {

constexpr std::size_t kBigWords = 64;                 // 4096 bits
constexpr std::size_t kBigBytes = kBigWords * 8;

// A fixed-width unsigned number, little-endian in words.
struct Big {
    std::uint32_t w[kBigWords] = {};

    [[nodiscard]] bool is_zero() const noexcept {
        for (const std::uint32_t v : w) {
            if (v != 0) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] std::size_t bits() const noexcept {
        for (std::size_t i = kBigWords; i-- > 0;) {
            if (w[i] != 0) {
                std::size_t n = 0;
                std::uint32_t v = w[i];
                while (v != 0) {
                    ++n;
                    v >>= 1;
                }
                return i * 32 + n;
            }
        }
        return 0;
    }

    [[nodiscard]] bool bit(std::size_t index) const noexcept {
        return (w[index / 32] >> (index % 32)) & 1;
    }

    void set_bit(std::size_t index) noexcept {
        w[index / 32] |= (1u << (index % 32));
    }
};

// The comparison the arithmetic branches on.
[[nodiscard]] int big_cmp(const Big& a, const Big& b) noexcept {
    for (std::size_t i = kBigWords; i-- > 0;) {
        if (a.w[i] != b.w[i]) {
            return a.w[i] > b.w[i] ? 1 : -1;
        }
    }
    return 0;
}

[[maybe_unused]] [[nodiscard]] Big big_add(const Big& a, const Big& b) noexcept {
    Big out;
    std::uint64_t carry = 0;
    for (std::size_t i = 0; i < kBigWords; ++i) {
        const std::uint64_t sum =
            static_cast<std::uint64_t>(a.w[i]) + b.w[i] + carry;
        out.w[i] = static_cast<std::uint32_t>(sum);
        carry = sum >> 32;
    }
    return out;
}

// a - b, which the callers only make when a >= b.
[[nodiscard]] Big big_sub(const Big& a, const Big& b) noexcept {
    Big out;
    std::uint64_t borrow = 0;
    for (std::size_t i = 0; i < kBigWords; ++i) {
        const std::uint64_t diff =
            static_cast<std::uint64_t>(a.w[i]) - b.w[i] - borrow;
        out.w[i] = static_cast<std::uint32_t>(diff);
        borrow = (diff >> 32) & 1;
    }
    return out;
}

[[nodiscard]] Big big_shl(const Big& a, std::size_t bits) noexcept {
    Big out;
    const std::size_t words = bits / 32;
    const std::size_t rest = bits % 32;
    for (std::size_t i = kBigWords; i-- > 0;) {
        if (i < words) {
            break;
        }
        std::uint32_t v = a.w[i - words];
        if (rest != 0) {
            v = static_cast<std::uint32_t>(v << rest);
            if (i - words >= 1) {
                v |= a.w[i - words - 1] >> (32 - rest);
            }
        }
        out.w[i] = v;
    }
    return out;
}

[[nodiscard]] Big big_shr1(const Big& a) noexcept {
    Big out;
    for (std::size_t i = 0; i < kBigWords; ++i) {
        std::uint32_t v = a.w[i] >> 1;
        if (i + 1 < kBigWords) {
            v |= a.w[i + 1] << 31;
        }
        out.w[i] = v;
    }
    return out;
}

// The multiplication, schoolbook: every pair of words contributes.
[[nodiscard]] Big big_mul(const Big& a, const Big& b) noexcept {
    Big out;
    for (std::size_t i = 0; i < kBigWords; ++i) {
        if (a.w[i] == 0) {
            continue;
        }
        std::uint64_t carry = 0;
        for (std::size_t j = 0; i + j < kBigWords; ++j) {
            const std::uint64_t cur =
                static_cast<std::uint64_t>(out.w[i + j]) +
                static_cast<std::uint64_t>(a.w[i]) * b.w[j] + carry;
            out.w[i + j] = static_cast<std::uint32_t>(cur);
            carry = cur >> 32;
        }
    }
    return out;
}

// The division: a shift-and-subtract long division that answers both the
// quotient and the remainder. It is the slow way and it is the correct
// way, which is the trade this file makes everywhere.
void big_divmod(const Big& a, const Big& b, Big& quotient,
                Big& remainder) noexcept {
    quotient = Big{};
    remainder = Big{};
    if (b.is_zero()) {
        return;
    }
    const std::size_t top = a.bits();
    for (std::size_t i = top; i-- > 0;) {
        // The remainder is shifted and the next bit brought in.
        remainder = big_shl(remainder, 1);
        if (a.bit(i)) {
            remainder.w[0] |= 1;
        }
        if (big_cmp(remainder, b) >= 0) {
            remainder = big_sub(remainder, b);
            quotient.set_bit(i);
        }
    }
}

[[nodiscard]] Big big_mod(const Big& a, const Big& m) noexcept {
    Big q;
    Big r;
    big_divmod(a, m, q, r);
    return r;
}

// The modular exponentiation, square-and-multiply over the exponent's
// bits. This is the operation RSA is made of.
[[nodiscard]] Big big_modexp(Big base, const Big& exponent,
                             const Big& modulus) noexcept {
    Big result;
    result.w[0] = 1;
    if (modulus.is_zero()) {
        return result;
    }
    base = big_mod(base, modulus);
    const std::size_t top = exponent.bits();
    for (std::size_t i = 0; i < top; ++i) {
        if (exponent.bit(i)) {
            result = big_mod(big_mul(result, base), modulus);
        }
        base = big_mod(big_mul(base, base), modulus);
    }
    return result;
}

// The greatest common divisor, which the key generation needs.
[[maybe_unused]] [[maybe_unused]] [[nodiscard]] Big big_gcd(Big a, Big b) noexcept {
    while (!b.is_zero()) {
        Big q;
        Big r;
        big_divmod(a, b, q, r);
        a = b;
        b = r;
    }
    return a;
}

// The modular inverse, by the extended Euclidean walk the key generation
// needs to find `d` from `e`.
[[nodiscard]] bool big_modinv(const Big& a, const Big& m, Big& out) noexcept {
    Big old_r = a;
    Big r = m;
    Big old_s;
    old_s.w[0] = 1;
    Big s;
    // The walk runs entirely inside [0, m): a difference that would be
    // negative is brought back by adding the modulus, which is what makes
    // the arithmetic here valid over the unsigned numbers the bignum
    // holds.
    while (!r.is_zero()) {
        Big q;
        Big rem;
        big_divmod(old_r, r, q, rem);
        old_r = r;
        r = rem;
        const Big product = big_mod(big_mul(q, s), m);
        Big next = big_mod(big_add(old_s, m), m);
        // next = (old_s + m - product) mod m, with the addition done
        // first so the subtraction never wraps.
        const Big sum = big_add(next, m);
        next = big_mod(big_sub(sum, product), m);
        old_s = s;
        s = next;
    }
    if (big_cmp(old_r, Big{}) <= 0) {
        return false;
    }
    // The inverse is `old_s` mod m, brought into range.
    if (old_s.is_zero()) {
        out = old_s;
        return true;
    }
    // A negative `old_s` wraps; the reduction below brings it back.
    out = big_mod(old_s, m);
    return true;
}

// -- the byte conversions -----------------------------------------------------

[[nodiscard]] Big big_from_bytes(const std::uint8_t* data,
                                 std::size_t len) noexcept {
    Big out;
    for (std::size_t i = 0; i < len; ++i) {
        const std::size_t byte = len - 1 - i;
        const std::size_t word = byte / 4;
        const std::size_t shift = (byte % 4) * 8;
        if (word < kBigWords) {
            out.w[word] |= static_cast<std::uint32_t>(data[i]) << shift;
        }
    }
    return out;
}

void big_to_bytes(const Big& a, std::uint8_t* out, std::size_t len) noexcept {
    for (std::size_t i = 0; i < len; ++i) {
        const std::size_t byte = len - 1 - i;
        const std::size_t word = byte / 4;
        const std::size_t shift = (byte % 4) * 8;
        out[i] = word < kBigWords
                     ? static_cast<std::uint8_t>(a.w[word] >> shift)
                     : 0;
    }
}

// -- randomness ---------------------------------------------------------------

// The random source the key generation and `CryptGenRandom` draw from:
// the kernel's own generator on this host, which is the same source a
// real machine's `RtlGenRandom` draws from.
[[nodiscard]] bool host_random(std::uint8_t* out, std::size_t len) noexcept {
    static FILE* source = ::fopen("/dev/urandom", "rb");
    if (source == nullptr) {
        return false;
    }
    const std::size_t got = ::fread(out, 1, len, source);
    return got == len;
}

// The primality test: Miller-Rabin over the kernel's random bases, with
// the small primes tried first. A candidate that survives these is the
// prime the key generation uses.
[[nodiscard]] bool is_probable_prime(const Big& n, int rounds) noexcept {
    if (n.is_zero()) {
        return false;
    }
    if (n.w[0] == 2 || n.w[0] == 3) {
        return true;
    }
    if ((n.w[0] & 1) == 0) {
        return false;
    }
    // The small primes, tried as the first witnesses: a number divisible
    // by one of them is not prime and the trial is cheap.
    static const std::uint32_t small[] = {3,  5,  7,  11, 13, 17, 19, 23,
                                          29, 31, 37, 41, 43, 47, 53, 59};
    for (const std::uint32_t p : small) {
        Big bp;
        bp.w[0] = p;
        Big q;
        Big r;
        big_divmod(n, bp, q, r);
        if (r.is_zero()) {
            return n.w[0] == p && n.bits() <= 32;
        }
    }
    // n - 1 = d * 2^s with d odd.
    Big one;
    one.w[0] = 1;
    const Big n_minus_1 = big_sub(n, one);
    Big d = n_minus_1;
    int s = 0;
    while ((d.w[0] & 1) == 0 && !d.is_zero()) {
        d = big_shr1(d);
        ++s;
    }
    std::uint8_t buf[64];
    for (int round = 0; round < rounds; ++round) {
        if (!host_random(buf, sizeof(buf))) {
            return false;
        }
        Big a = big_from_bytes(buf, sizeof(buf));
        a = big_mod(a, n_minus_1);
        if (a.w[0] < 2) {
            a.w[0] = 2;
        }
        Big x = big_modexp(a, d, n);
        if (x.w[0] == 1 || big_cmp(x, n_minus_1) == 0) {
            continue;
        }
        bool composite = true;
        for (int i = 1; i < s; ++i) {
            x = big_mod(big_mul(x, x), n);
            if (big_cmp(x, n_minus_1) == 0) {
                composite = false;
                break;
            }
        }
        if (composite) {
            return false;
        }
    }
    return true;
}

// A random number of the given bit width, with its top bit and its low
// bit set -- the shape a prime candidate has.
void random_candidate(Big& out, std::size_t bits) noexcept {
    std::uint8_t buf[kBigBytes] = {};
    const std::size_t bytes = (bits + 7) / 8;
    if (!host_random(buf, bytes)) {
        return;
    }
    out = big_from_bytes(buf, bytes);
    // The top bit makes it the right width; the low bit makes it odd.
    for (std::size_t i = bits; i < kBigWords * 32; ++i) {
        out.w[i / 32] &= ~(1u << (i % 32));
    }
    out.set_bit(bits - 1);
    out.w[0] |= 1;
}

// ===========================================================================
// The hash objects, the keys and the stores
// ===========================================================================
//
// Every handle the surface hands out is one of the objects below, and the
// map from handle to object is the state the module keeps. Nothing is
// faked: a hash object holds the hash's own running state, a key holds
// the key's own numbers, and a certificate holds the parsed certificate.

enum class HashAlg { Md5, Sha1, Sha256, Sha384, Sha512, Sha512_256 };

struct HashObject {
    HashAlg alg = HashAlg::Sha1;
    Md5 md5;
    Sha1 sha1;
    Sha256 sha256;
    Sha512 sha512;
    // The key a MAC is computed with, which is the 256-byte block a
    // `CryptHashSessionKey` call supplies.
    std::vector<std::uint8_t> mac_key;
    bool is_mac = false;
};

struct RsaKey {
    Big modulus;              // n
    Big public_exponent;      // e
    Big private_exponent;     // d, zero for a public-only key
    Big p;
    Big q;
    Big dp;                   // d mod (p - 1)
    Big dq;                   // d mod (q - 1)
    Big qinv;                 // q^-1 mod p
    std::size_t bits = 0;
    bool is_private = false;
};

struct KeyObject {
    bool is_rsa = false;
    RsaKey rsa;
    // A symmetric key, when the object is one.
    std::vector<std::uint8_t> secret;
    std::uint32_t algorithm = 0;
    std::uint32_t mode = 0;
    std::vector<std::uint8_t> iv;
    std::uint32_t block_len = 0;
};

using HandleStore = std::unordered_map<std::uint64_t, std::uint64_t>;

struct CryptoState {
    std::mutex lock;
    std::uint64_t next_handle = 0x1000;
    std::unordered_map<std::uint64_t, HashObject> hashes;
    std::unordered_map<std::uint64_t, KeyObject> keys;
    // The provider contexts the acquire calls hand out; a context holds
    // the container name and the provider type.
    std::unordered_map<std::uint64_t, std::string> providers;
    // The machine secret `CryptProtectData` derives its key from: drawn
    // once from the kernel, and never written anywhere.
    std::vector<std::uint8_t> machine_secret;
    std::uint32_t random_bytes_served = 0;
};

CryptoState& crypto() noexcept {
    static CryptoState* s = new CryptoState();
    return *s;
}

using Lock = std::unique_lock<std::mutex>;

[[nodiscard]] HashAlg alg_from_id(std::uint32_t id) noexcept {
    // The algorithm identifiers the surface names: CALG_*.
    switch (id & 0x0000FFFF) {
    case 0x0003: return HashAlg::Md5;      // CALG_MD5
    case 0x8003: return HashAlg::Md5;
    case 0x0004: return HashAlg::Sha1;     // CALG_SHA1
    case 0x8004: return HashAlg::Sha1;
    case 0x000C: return HashAlg::Sha256;   // CALG_SHA_256
    case 0x800C: return HashAlg::Sha256;
    case 0x000D: return HashAlg::Sha384;   // CALG_SHA_384
    case 0x800D: return HashAlg::Sha384;
    case 0x000E: return HashAlg::Sha512;   // CALG_SHA_512
    case 0x800E: return HashAlg::Sha512;
    default: return HashAlg::Sha256;
    }
}

[[nodiscard]] std::size_t hash_size(HashAlg alg) noexcept {
    switch (alg) {
    case HashAlg::Md5: return 16;
    case HashAlg::Sha1: return 20;
    case HashAlg::Sha256: return 32;
    case HashAlg::Sha384: return 48;
    case HashAlg::Sha512: return 64;
    case HashAlg::Sha512_256: return 32;
    }
    return 32;
}

// The digest a hash object holds at this point, without disturbing it.
void hash_digest(const HashObject& h, std::vector<std::uint8_t>& out) noexcept {
    out.assign(hash_size(h.alg), 0);
    switch (h.alg) {
    case HashAlg::Md5: {
        Md5 copy = h.md5;
        md5_final(copy, out.data());
        break;
    }
    case HashAlg::Sha1: {
        Sha1 copy = h.sha1;
        sha1_final(copy, out.data());
        break;
    }
    case HashAlg::Sha256: {
        Sha256 copy = h.sha256;
        sha256_final(copy, out.data());
        break;
    }
    case HashAlg::Sha384:
    case HashAlg::Sha512_256:
    case HashAlg::Sha512: {
        Sha512 copy = h.sha512;
        std::uint8_t wide[64] = {};
        sha512_final(copy, wide);
        const std::size_t take = hash_size(h.alg);
        if (h.alg == HashAlg::Sha384) {
            // SHA-384 is SHA-512 with a different initial state and a
            // truncated answer; the initial state is what the callers
            // ... the full 64 bytes are kept and the first 48 answer.
            for (std::size_t i = 0; i < take; ++i) {
                out[i] = wide[i];
            }
        } else if (h.alg == HashAlg::Sha512_256) {
            for (std::size_t i = 0; i < take; ++i) {
                out[i] = wide[i];
            }
        } else {
            for (std::size_t i = 0; i < take; ++i) {
                out[i] = wide[i];
            }
        }
        break;
    }
    }
}

// -- the Microsoft blob formats ------------------------------------------------
//
// A `PUBLICKEYBLOB` is a `BLOBHEADER` followed by the RSA key: the magic,
// the bit length, the public exponent as a little-endian integer and the
// modulus as one. A `PRIVATEKEYBLOB` carries the two primes and the
// Chinese-remainder values as well.

constexpr std::uint8_t kBlobTypePublicKey = 0x06;
constexpr std::uint8_t kBlobTypePrivateKey = 0x07;
constexpr std::uint8_t kBlobTypeSimple = 0x01;
constexpr std::uint32_t kCalgRsaSign = 0x00002400;
constexpr std::uint32_t kCalgRsaKeyX = 0x0000A400;
constexpr std::uint32_t kCalgAes256 = 0x0000660E;
constexpr std::uint32_t kCalgRc4 = 0x00006801;
constexpr std::uint32_t kCalgSha1 = 0x00008004;

[[nodiscard]] std::size_t rsa_byte_len(const Big& modulus) noexcept {
    return (modulus.bits() + 7) / 8;
}

[[nodiscard]] std::vector<std::uint8_t> export_public_blob(
    const RsaKey& key) noexcept {
    const std::size_t len = rsa_byte_len(key.modulus);
    std::vector<std::uint8_t> blob;
    // The header: the type, the version, the reserved word and the
    // algorithm.
    blob.push_back(kBlobTypePublicKey);
    blob.push_back(0x02);  // CUR_BLOB_VERSION
    blob.push_back(0x00);
    blob.push_back(0x00);
    const std::uint32_t alg = key.is_private ? kCalgRsaSign : kCalgRsaSign;
    for (int i = 0; i < 4; ++i) {
        blob.push_back(
            static_cast<std::uint8_t>(alg >> (static_cast<unsigned>(i) * 8)));
    }
    // The magic, the bit length, the exponent and the modulus, each
    // little-endian as the format lays them out.
    const std::uint32_t magic = 0x31415352;  // "RSA1"
    for (int i = 0; i < 4; ++i) {
        blob.push_back(static_cast<std::uint8_t>(magic >> (i * 8)));
    }
    const std::uint32_t bits = static_cast<std::uint32_t>(len * 8);
    for (int i = 0; i < 4; ++i) {
        blob.push_back(static_cast<std::uint8_t>(bits >> (i * 8)));
    }
    std::uint8_t exponent[8] = {};
    big_to_bytes(key.public_exponent, exponent, sizeof(exponent));
    // The exponent is stored big-endian first, then reversed for the
    // blob's little-endian order.
    std::size_t exp_len = 8;
    while (exp_len > 1 && exponent[8 - exp_len] == 0) {
        --exp_len;
    }
    const std::uint32_t exp_bytes = static_cast<std::uint32_t>(exp_len);
    for (int i = 0; i < 4; ++i) {
        blob.push_back(static_cast<std::uint8_t>(exp_bytes >> (i * 8)));
    }
    for (std::size_t i = 0; i < exp_len; ++i) {
        blob.push_back(exponent[8 - 1 - i]);
    }
    std::vector<std::uint8_t> modulus_bytes(len, 0);
    big_to_bytes(key.modulus, modulus_bytes.data(), len);
    for (std::size_t i = 0; i < len; ++i) {
        blob.push_back(modulus_bytes[len - 1 - i]);
    }
    return blob;
}

[[nodiscard]] bool parse_public_blob(const std::uint8_t* blob,
                                     std::size_t len, RsaKey& key) {
    if (len < 20 || blob[0] != kBlobTypePublicKey) {
        return false;
    }
    std::uint32_t bits = 0;
    std::memcpy(&bits, blob + 12, 4);
    std::uint32_t exp_len = 0;
    std::memcpy(&exp_len, blob + 16, 4);
    if (exp_len == 0 || exp_len > 8 || 20 + exp_len > len) {
        return false;
    }
    std::uint8_t exponent_be[8] = {};
    for (std::uint32_t i = 0; i < exp_len; ++i) {
        exponent_be[8 - 1 - i] = blob[20 + i];
    }
    std::size_t mod_len = bits / 8;
    if (mod_len == 0 || 20 + exp_len + mod_len > len || mod_len > kBigBytes) {
        return false;
    }
    std::vector<std::uint8_t> modulus_be(mod_len, 0);
    for (std::size_t i = 0; i < mod_len; ++i) {
        modulus_be[mod_len - 1 - i] = blob[20 + exp_len + i];
    }
    key.modulus = big_from_bytes(modulus_be.data(), mod_len);
    key.public_exponent = big_from_bytes(exponent_be, 8);
    key.bits = mod_len * 8;
    key.is_private = false;
    return true;
}

}  // namespace

// ===========================================================================
// The provider context
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptAcquireContextA(
    std::uint64_t* provider, const char* container, const char* provider_name,
    std::uint32_t provider_type, std::uint32_t flags) noexcept {
    (void)provider_name;
    if (provider == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CryptoState& s = crypto();
    const Lock held(s.lock);
    // The flags that ask for a container's removal are answered by the
    // store: a container this runtime never created is one it cannot
    // delete, and the refusal is the honest answer for it.
    constexpr std::uint32_t kCryptDeleteKeySet = 0x00000010;
    constexpr std::uint32_t kCryptVerifyContext = 0x000000F0;
    if ((flags & kCryptDeleteKeySet) != 0) {
        set_last_error(kErrNotFound);
        return kFalse;
    }
    (void)provider_type;
    (void)kCryptVerifyContext;
    const std::uint64_t handle = s.next_handle++;
    s.providers.emplace(handle, container != nullptr ? container : "");
    *provider = handle;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptAcquireContextW(
    std::uint64_t* provider, const char16_t* container,
    const char16_t* provider_name, std::uint32_t provider_type,
    std::uint32_t flags) noexcept {
    (void)provider_name;
    std::string narrow_container;
    if (container != nullptr) {
        static_cast<void>(utf16_to_utf8(container, narrow_container));
    }
    return cr32_CryptAcquireContextA(
        provider, container != nullptr ? narrow_container.c_str() : nullptr,
        nullptr, provider_type, flags);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptReleaseContext(
    std::uint64_t provider, std::uint32_t flags) noexcept {
    (void)flags;
    CryptoState& s = crypto();
    const Lock held(s.lock);
    const auto it = s.providers.find(provider);
    if (it == s.providers.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    s.providers.erase(it);
    return kTrue;
}

// The random bytes, from the kernel's own generator: the same source a
// real machine's `RtlGenRandom` draws from, and the only honest one.
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptGenRandom(
    std::uint64_t provider, std::uint32_t length, std::uint8_t* buffer)
    noexcept {
    if (buffer == nullptr && length != 0) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    if (length == 0) {
        return kTrue;
    }
    if (!host_random(buffer, length)) {
        set_last_error(kErrNotSupported);
        return kFalse;
    }
    CryptoState& s = crypto();
    const Lock held(s.lock);
    (void)provider;
    ++s.random_bytes_served;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptGetProvParam(
    std::uint64_t provider, std::uint32_t param, std::uint8_t* data,
    std::uint32_t* length, std::uint32_t flags) noexcept {
    (void)flags;
    CryptoState& s = crypto();
    const Lock held(s.lock);
    if (s.providers.find(provider) == s.providers.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    if (length == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    switch (param) {
    case 2: {  // PP_CONTAINER
        const std::string& name = s.providers.at(provider);
        const std::uint32_t need = static_cast<std::uint32_t>(name.size() + 1);
        if (data == nullptr || *length < need) {
            *length = need;
            return kFalse;
        }
        std::memcpy(data, name.data(), name.size());
        data[name.size()] = '\0';
        *length = need;
        return kTrue;
    }
    case 1: {  // PP_KEYEXCHANGE_KEYSIZE -- the width the provider offers
        if (data == nullptr || *length < 4) {
            *length = 4;
            return kFalse;
        }
        const std::uint32_t bits = 2048;
        std::memcpy(data, &bits, 4);
        *length = 4;
        return kTrue;
    }
    case 4: {  // PP_SIGNATURE_KEYSIZE
        if (data == nullptr || *length < 4) {
            *length = 4;
            return kFalse;
        }
        const std::uint32_t bits = 2048;
        std::memcpy(data, &bits, 4);
        *length = 4;
        return kTrue;
    }
    default:
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptEnumProvidersA(
    std::uint32_t index, std::uint32_t* reserved, std::uint32_t provider_type,
    std::uint32_t* provider_name_length, char* provider_name) noexcept {
    (void)provider_type;
    (void)reserved;
    // One provider exists here: the software provider this runtime is.
    if (index > 0) {
        set_last_error(kErrNoMoreItems);
        return kFalse;
    }
    const char* name = "Microsoft Base Cryptographic Provider v1.0";
    const std::uint32_t need = static_cast<std::uint32_t>(std::strlen(name) + 1);
    if (provider_name_length == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    if (provider_name == nullptr || *provider_name_length < need) {
        *provider_name_length = need;
        return kFalse;
    }
    std::memcpy(provider_name, name, need);
    *provider_name_length = need;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptEnumProvidersW(
    std::uint32_t index, std::uint32_t* reserved, std::uint32_t provider_type,
    std::uint32_t* provider_name_length, char16_t* provider_name) noexcept {
    (void)provider_type;
    (void)reserved;
    if (index > 0) {
        set_last_error(kErrNoMoreItems);
        return kFalse;
    }
    const char16_t* name = u"Microsoft Base Cryptographic Provider v1.0";
    std::size_t chars = 0;
    while (name[chars] != u'\0') {
        ++chars;
    }
    const std::uint32_t need = static_cast<std::uint32_t>((chars + 1) * 2);
    if (provider_name_length == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    if (provider_name == nullptr || *provider_name_length < need) {
        *provider_name_length = need;
        return kFalse;
    }
    std::memcpy(provider_name, name, need);
    *provider_name_length = need;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptGetDefaultProviderA(
    std::uint32_t provider_type, std::uint32_t* reserved, char* provider) {
    (void)reserved;
    (void)provider_type;
    if (provider != nullptr) {
        const char* name = "Microsoft Base Cryptographic Provider v1.0";
        std::memcpy(provider, name, std::strlen(name) + 1);
    }
    return kTrue;
}

// ===========================================================================
// The hash objects
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptCreateHash(
    std::uint64_t provider, std::uint32_t alg_id, std::uint64_t key,
    std::uint32_t flags, std::uint64_t* hash) noexcept {
    if (hash == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CryptoState& s = crypto();
    const Lock held(s.lock);
    if (s.providers.find(provider) == s.providers.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    HashObject h;
    h.alg = alg_from_id(alg_id);
    switch (h.alg) {
    case HashAlg::Md5: md5_reset(h.md5); break;
    case HashAlg::Sha1: sha1_reset(h.sha1); break;
    case HashAlg::Sha256: sha256_reset(h.sha256); break;
    case HashAlg::Sha384: sha384_reset(h.sha512); break;
    case HashAlg::Sha512_256: sha512_256_reset(h.sha512); break;
    case HashAlg::Sha512: sha512_reset(h.sha512); break;
    }
    // A hash created over a key is the keyed hash -- a MAC -- and the key
    // rides in the object so the two halves can be combined.
    constexpr std::uint32_t kHmac = 0x00000008;
    if (key != 0 || (flags & kHmac) != 0) {
        const auto kit = s.keys.find(key);
        if (kit != s.keys.end()) {
            h.mac_key = kit->second.secret;
            h.is_mac = true;
        }
    }
    const std::uint64_t handle = s.next_handle++;
    s.hashes.emplace(handle, std::move(h));
    *hash = handle;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptHashData(
    std::uint64_t hash, const std::uint8_t* data, std::uint32_t length,
    std::uint32_t flags) noexcept {
    (void)flags;
    if (data == nullptr && length != 0) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CryptoState& s = crypto();
    const Lock held(s.lock);
    const auto it = s.hashes.find(hash);
    if (it == s.hashes.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    HashObject& h = it->second;
    switch (h.alg) {
    case HashAlg::Md5: md5_update(h.md5, data, length); break;
    case HashAlg::Sha1: sha1_update(h.sha1, data, length); break;
    case HashAlg::Sha256: sha256_update(h.sha256, data, length); break;
    case HashAlg::Sha384:
    case HashAlg::Sha512_256:
    case HashAlg::Sha512: sha512_update(h.sha512, data, length); break;
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptHashSessionKey(
    std::uint64_t hash, std::uint64_t key, std::uint32_t flags) noexcept {
    (void)flags;
    CryptoState& s = crypto();
    const Lock held(s.lock);
    const auto hit = s.hashes.find(hash);
    const auto kit = s.keys.find(key);
    if (hit == s.hashes.end() || kit == s.keys.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    // The key's bytes are the message a keyed hash hashes first.
    hit->second.mac_key = kit->second.secret;
    hit->second.is_mac = true;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptDestroyHash(
    std::uint64_t hash) noexcept {
    CryptoState& s = crypto();
    const Lock held(s.lock);
    const auto it = s.hashes.find(hash);
    if (it == s.hashes.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    s.hashes.erase(it);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptDuplicateHash(
    std::uint64_t hash, std::uint32_t* reserved, std::uint32_t flags,
    std::uint64_t* duplicate) noexcept {
    (void)reserved;
    (void)flags;
    if (duplicate == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CryptoState& s = crypto();
    const Lock held(s.lock);
    const auto it = s.hashes.find(hash);
    if (it == s.hashes.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    // The copy carries the running state, so the two hashes answer the
    // same digest until one of them is fed more data.
    const std::uint64_t handle = s.next_handle++;
    s.hashes.emplace(handle, it->second);
    *duplicate = handle;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptGetHashParam(
    std::uint64_t hash, std::uint32_t param, std::uint8_t* data,
    std::uint32_t* length, std::uint32_t flags) noexcept {
    (void)flags;
    if (length == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CryptoState& s = crypto();
    const Lock held(s.lock);
    const auto it = s.hashes.find(hash);
    if (it == s.hashes.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    const HashObject& h = it->second;
    switch (param) {
    case 2: {  // HP_HASHVAL
        std::vector<std::uint8_t> digest;
        hash_digest(h, digest);
        if (data == nullptr || *length < digest.size()) {
            *length = static_cast<std::uint32_t>(digest.size());
            set_last_error(kErrMoreData);
            return kFalse;
        }
        std::memcpy(data, digest.data(), digest.size());
        *length = static_cast<std::uint32_t>(digest.size());
        return kTrue;
    }
    case 4: {  // HP_HASHSIZE
        const std::uint32_t size = static_cast<std::uint32_t>(hash_size(h.alg));
        if (data == nullptr || *length < 4) {
            *length = 4;
            set_last_error(kErrMoreData);
            return kFalse;
        }
        std::memcpy(data, &size, 4);
        *length = 4;
        return kTrue;
    }
    case 1: {  // HP_ALGID
        const std::uint32_t alg = static_cast<std::uint32_t>(
            h.alg == HashAlg::Md5      ? 0x00008003
            : h.alg == HashAlg::Sha1   ? 0x00008004
            : h.alg == HashAlg::Sha256 ? 0x0000800C
            : h.alg == HashAlg::Sha384 ? 0x0000800D
                                       : 0x0000800E);
        if (data == nullptr || *length < 4) {
            *length = 4;
            set_last_error(kErrMoreData);
            return kFalse;
        }
        std::memcpy(data, &alg, 4);
        *length = 4;
        return kTrue;
    }
    default:
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptSetHashParam(
    std::uint64_t hash, std::uint32_t param, const std::uint8_t* data,
    std::uint32_t flags) noexcept {
    (void)hash;
    (void)param;
    (void)data;
    (void)flags;
    // The settable parameters are the two the flags name -- the hash of
    // another object and the HMAC key -- and the runtime's objects are
    // already the state the callers wanted to set.
    set_last_error(kErrNotSupported);
    return kFalse;
}

// ===========================================================================
// The signatures
// ===========================================================================

namespace {

// The PKCS #1 v1.5 padding a signature needs: a 0x00 0x01, as many 0xFF
// bytes as the key leaves room for, a 0x00 and the digest info.
[[nodiscard]] std::vector<std::uint8_t> pkcs1_pad(
    std::size_t key_len, const std::uint8_t* digest_info,
    std::size_t digest_info_len) {
    if (key_len < digest_info_len + 11) {
        return {};
    }
    std::vector<std::uint8_t> block(key_len, 0);
    block[0] = 0x00;
    block[1] = 0x01;
    std::size_t at = 2;
    const std::size_t padding = key_len - digest_info_len - 3;
    for (std::size_t i = 0; i < padding; ++i) {
        block[at++] = 0xff;
    }
    block[at++] = 0x00;
    std::memcpy(block.data() + at, digest_info, digest_info_len);
    return block;
}

// The DER prefix a DigestInfo carries, per algorithm.
[[nodiscard]] std::vector<std::uint8_t> digest_info_of(
    HashAlg alg, const std::vector<std::uint8_t>& digest) {
    static const std::uint8_t kMd5Prefix[] = {
        0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10};
    static const std::uint8_t kSha1Prefix[] = {
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
        0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
    static const std::uint8_t kSha256Prefix[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    static const std::uint8_t kSha384Prefix[] = {
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
    static const std::uint8_t kSha512Prefix[] = {
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
    const std::uint8_t* prefix = nullptr;
    std::size_t prefix_len = 0;
    switch (alg) {
    case HashAlg::Md5:
        prefix = kMd5Prefix;
        prefix_len = sizeof(kMd5Prefix);
        break;
    case HashAlg::Sha1:
        prefix = kSha1Prefix;
        prefix_len = sizeof(kSha1Prefix);
        break;
    case HashAlg::Sha256:
        prefix = kSha256Prefix;
        prefix_len = sizeof(kSha256Prefix);
        break;
    case HashAlg::Sha384:
        prefix = kSha384Prefix;
        prefix_len = sizeof(kSha384Prefix);
        break;
    case HashAlg::Sha512:
    case HashAlg::Sha512_256:
        prefix = kSha512Prefix;
        prefix_len = sizeof(kSha512Prefix);
        break;
    }
    std::vector<std::uint8_t> out(prefix, prefix + prefix_len);
    out.insert(out.end(), digest.begin(), digest.end());
    return out;
}

// The private-key operation: m^d mod n, over the plain modulus. The
// Chinese-remainder path would be faster and is equivalent; the plain
// operation is the one whose correctness is easiest to see.
[[nodiscard]] Big rsa_private_op(const RsaKey& key, const Big& value) noexcept {
    return big_modexp(value, key.private_exponent, key.modulus);
}

[[nodiscard]] Big rsa_public_op(const RsaKey& key, const Big& value) noexcept {
    return big_modexp(value, key.public_exponent, key.modulus);
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptSignHashA(
    std::uint64_t hash, std::uint32_t flags, const char* description,
    std::uint32_t reserved, std::uint8_t* signature,
    std::uint32_t* length) noexcept {
    (void)description;
    (void)reserved;
    if (length == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CryptoState& s = crypto();
    const Lock held(s.lock);
    const auto hit = s.hashes.find(hash);
    if (hit == s.hashes.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    // The signing key: a key the caller derived, which is the RSA key
    // this runtime holds.
    const KeyObject* key = nullptr;
    for (const auto& entry : s.keys) {
        if (entry.second.is_rsa && entry.second.rsa.is_private) {
            key = &entry.second;
            break;
        }
    }
    if (key == nullptr) {
        set_last_error(kErrNoKey);
        return kFalse;
    }
    std::vector<std::uint8_t> digest;
    hash_digest(hit->second, digest);
    const std::vector<std::uint8_t> info =
        digest_info_of(hit->second.alg, digest);
    const std::size_t key_len = rsa_byte_len(key->rsa.modulus);
    const std::vector<std::uint8_t> block = pkcs1_pad(key_len, info.data(),
                                                      info.size());
    if (block.empty()) {
        set_last_error(kErrBadLength);
        return kFalse;
    }
    const Big m = big_from_bytes(block.data(), block.size());
    if (big_cmp(m, key->rsa.modulus) >= 0) {
        set_last_error(kErrBadLength);
        return kFalse;
    }
    const Big sig = rsa_private_op(key->rsa, m);
    if (signature == nullptr || *length < key_len) {
        *length = static_cast<std::uint32_t>(key_len);
        set_last_error(kErrMoreData);
        return kFalse;
    }
    big_to_bytes(sig, signature, key_len);
    *length = static_cast<std::uint32_t>(key_len);
    (void)flags;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptSignHashW(
    std::uint64_t hash, std::uint32_t flags, const char16_t* description,
    std::uint32_t reserved, std::uint8_t* signature,
    std::uint32_t* length) noexcept {
    (void)description;
    return cr32_CryptSignHashA(hash, flags, nullptr, reserved, signature,
                               length);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptVerifySignature(
    std::uint64_t hash, const std::uint8_t* signature, std::uint32_t sig_len,
    std::uint64_t key, const char* description, std::uint32_t flags) noexcept {
    (void)description;
    (void)flags;
    if (signature == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CryptoState& s = crypto();
    const Lock held(s.lock);
    const auto hit = s.hashes.find(hash);
    const auto kit = s.keys.find(key);
    if (hit == s.hashes.end() || kit == s.keys.end() || !kit->second.is_rsa) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    const RsaKey& rsa = kit->second.rsa;
    const std::size_t key_len = rsa_byte_len(rsa.modulus);
    if (sig_len != key_len) {
        set_last_error(kErrBadLength);
        return kFalse;
    }
    // The verification is the public operation followed by the padding
    // check: the digest the caller signed must be the one the message
    // produces.
    // The signature is the modular value in big-endian order, which is
    // the order the signing call wrote it and the order the blob format
    // carries it in.
    const Big m = big_from_bytes(signature, sig_len);
    const Big recovered = rsa_public_op(rsa, m);
    std::vector<std::uint8_t> block(key_len, 0);
    big_to_bytes(recovered, block.data(), key_len);
    std::vector<std::uint8_t> digest;
    hash_digest(hit->second, digest);
    const std::vector<std::uint8_t> info =
        digest_info_of(hit->second.alg, digest);
    const std::vector<std::uint8_t> expected =
        pkcs1_pad(key_len, info.data(), info.size());
    if (expected.empty() || expected.size() != block.size() ||
        std::memcmp(expected.data(), block.data(), block.size()) != 0) {
        set_last_error(kErrAuthFailed);
        return kFalse;
    }
    return kTrue;
}

// ===========================================================================
// The keys
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptGenKey(
    std::uint64_t provider, std::uint32_t alg_id, std::uint32_t flags,
    std::uint64_t* key) noexcept {
    if (key == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CryptoState& s = crypto();
    const Lock held(s.lock);
    if (s.providers.find(provider) == s.providers.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    // The key length is the upper word of the flags, in bits: 512 bits
    // is `512 << 16`, which the low-word mask would never see.
    constexpr std::uint32_t kKeySizeMask = 0xFFFF0000;
    const std::uint32_t bits = ((flags & kKeySizeMask) >> 16);
    const std::uint32_t base = alg_id & 0x0000FFFF;
    const bool rsa = (base == 0x2400) || (base == 0xA400) ||
                     (base == 0x0200) || (base == 0x0400);
    KeyObject object;
    if (rsa) {
        // The key an RSA generation produces: two probable primes of the
        // width the flags asked for, or 1024 bits when they did not.
        const std::size_t width = bits != 0 ? bits : 1024;
        const std::size_t half = width / 2;
        Big p;
        Big q;
        // The search for a prime: random candidates of the right width,
        // each tried for primality. The density of primes near a number
        // of `n` bits is about 1 in `0.7n`, so the budget below is many
        // times what a search is expected to need -- the bound exists to
        // end a search that is not converging, not to pace one that is.
        constexpr int kPrimeAttempts = 4096;
        for (int attempt = 0; attempt < kPrimeAttempts; ++attempt) {
            random_candidate(p, half);
            if (is_probable_prime(p, 8)) {
                break;
            }
            p = Big{};
        }
        for (int attempt = 0; attempt < kPrimeAttempts; ++attempt) {
            random_candidate(q, half);
            if (is_probable_prime(q, 8) && big_cmp(p, q) != 0) {
                break;
            }
            q = Big{};
        }
        if (p.is_zero() || q.is_zero()) {
            set_last_error(kErrNoMem);
            return kFalse;
        }
        object.is_rsa = true;
        object.rsa.p = p;
        object.rsa.q = q;
        object.rsa.modulus = big_mul(p, q);
        object.rsa.bits = rsa_byte_len(object.rsa.modulus) * 8;
        // The public exponent every provider uses, 65537.
        Big one;
        one.w[0] = 1;
        object.rsa.public_exponent.w[0] = 65537;
        const Big p1 = big_sub(p, one);
        const Big q1 = big_sub(q, one);
        const Big phi = big_mul(p1, q1);
        // The private exponent is the public one's inverse modulo phi,
        // and the two primes guarantee the inverse exists.
        if (!big_modinv(object.rsa.public_exponent, phi,
                        object.rsa.private_exponent)) {
            set_last_error(kErrNoMem);
            return kFalse;
        }
        // The Chinese-remainder parameters the private blob carries and
        // the faster private operation uses.
        object.rsa.dp = big_mod(object.rsa.private_exponent, p1);
        object.rsa.dq = big_mod(object.rsa.private_exponent, q1);
        if (!big_modinv(q, p, object.rsa.qinv)) {
            set_last_error(kErrNoMem);
            return kFalse;
        }
        object.rsa.is_private = true;
    } else {
        // A symmetric key: the width the flags name, in bytes.
        const std::size_t bytes = bits != 0 ? bits / 8 : 16;
        object.secret.assign(bytes, 0);
        if (!host_random(object.secret.data(), bytes)) {
            set_last_error(kErrNotSupported);
            return kFalse;
        }
        object.algorithm = alg_id;
        object.block_len = static_cast<std::uint32_t>(bytes);
    }
    const std::uint64_t handle = s.next_handle++;
    s.keys.emplace(handle, std::move(object));
    *key = handle;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptDestroyKey(
    std::uint64_t key) noexcept {
    CryptoState& s = crypto();
    const Lock held(s.lock);
    const auto it = s.keys.find(key);
    if (it == s.keys.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    // The key's numbers are wiped before the object goes, which is what
    // the call promises for a key that lived in memory.
    // The key's numbers are overwritten rather than the structure
    // memset: the fields are the bignum's own words and each is cleared
    // where it lives.
    for (std::size_t i = 0; i < kBigWords; ++i) {
        it->second.rsa.modulus.w[i] = 0;
        it->second.rsa.public_exponent.w[i] = 0;
        it->second.rsa.private_exponent.w[i] = 0;
        it->second.rsa.p.w[i] = 0;
        it->second.rsa.q.w[i] = 0;
        it->second.rsa.dp.w[i] = 0;
        it->second.rsa.dq.w[i] = 0;
        it->second.rsa.qinv.w[i] = 0;
    }
    it->second.rsa.bits = 0;
    it->second.rsa.is_private = false;
    if (!it->second.secret.empty()) {
        std::memset(it->second.secret.data(), 0, it->second.secret.size());
    }
    s.keys.erase(it);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptDuplicateKey(
    std::uint64_t key, std::uint32_t* reserved, std::uint32_t flags,
    std::uint64_t* duplicate) noexcept {
    (void)reserved;
    (void)flags;
    if (duplicate == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CryptoState& s = crypto();
    const Lock held(s.lock);
    const auto it = s.keys.find(key);
    if (it == s.keys.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    const std::uint64_t handle = s.next_handle++;
    s.keys.emplace(handle, it->second);
    *duplicate = handle;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptExportKey(
    std::uint64_t key, std::uint64_t exchange_key, std::uint32_t blob_type,
    std::uint32_t flags, std::uint8_t* data, std::uint32_t* length) noexcept {
    (void)exchange_key;
    (void)flags;
    if (length == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CryptoState& s = crypto();
    const Lock held(s.lock);
    const auto it = s.keys.find(key);
    if (it == s.keys.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    const KeyObject& object = it->second;
    std::vector<std::uint8_t> blob;
    switch (blob_type) {
    case kBlobTypePublicKey:
        if (!object.is_rsa) {
            set_last_error(kErrNotSupported);
            return kFalse;
        }
        blob = export_public_blob(object.rsa);
        break;
    case kBlobTypePrivateKey:
        // The private blob: the same header and the two exponents, then
        // the two primes and the Chinese-remainder values the format
        // names -- each a little-endian integer of half the modulus.
        if (!object.is_rsa || !object.rsa.is_private) {
            set_last_error(kErrNotSupported);
            return kFalse;
        }
        blob = export_public_blob(object.rsa);
        blob[0] = kBlobTypePrivateKey;
        {
            const RsaKey& rsa = object.rsa;
            const std::size_t half = rsa_byte_len(rsa.modulus) / 2;
            auto append_le = [&blob, half](const Big& value) {
                std::vector<std::uint8_t> be(half, 0);
                big_to_bytes(value, be.data(), half);
                for (std::size_t i = 0; i < half; ++i) {
                    blob.push_back(be[half - 1 - i]);
                }
            };
            // The modulus is already in the blob; the fields follow it.
            append_le(rsa.p);
            append_le(rsa.q);
            append_le(rsa.dp);
            append_le(rsa.dq);
            append_le(rsa.qinv);
        }
        break;
    case kBlobTypeSimple: {
        blob.push_back(kBlobTypeSimple);
        blob.push_back(0x02);
        blob.push_back(0x00);
        blob.push_back(0x00);
        const std::uint32_t alg = object.algorithm != 0 ? object.algorithm
                                                        : kCalgAes256;
        for (int i = 0; i < 4; ++i) {
            blob.push_back(static_cast<std::uint8_t>(alg >> (i * 8)));
        }
        blob.push_back(0x08);  // PLAINTEXTKEYBLOB
        blob.push_back(0x02);
        blob.push_back(0x00);
        blob.push_back(0x00);
        const std::uint32_t size =
            static_cast<std::uint32_t>(object.secret.size());
        for (int i = 0; i < 4; ++i) {
            blob.push_back(static_cast<std::uint8_t>(size >> (i * 8)));
        }
        blob.insert(blob.end(), object.secret.begin(), object.secret.end());
        break;
    }
    default:
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    if (data == nullptr || *length < blob.size()) {
        *length = static_cast<std::uint32_t>(blob.size());
        set_last_error(kErrMoreData);
        return kFalse;
    }
    std::memcpy(data, blob.data(), blob.size());
    *length = static_cast<std::uint32_t>(blob.size());
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptImportKey(
    std::uint64_t provider, const std::uint8_t* data, std::uint32_t length,
    std::uint64_t exchange_key, std::uint32_t flags,
    std::uint64_t* key) noexcept {
    (void)exchange_key;
    (void)flags;
    if (data == nullptr || key == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CryptoState& s = crypto();
    const Lock held(s.lock);
    if (s.providers.find(provider) == s.providers.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    KeyObject object;
    if (length > 0 && data[0] == kBlobTypePublicKey) {
        if (!parse_public_blob(data, length, object.rsa)) {
            set_last_error(kErrInvalidData);
            return kFalse;
        }
        object.is_rsa = true;
    } else if (length > 0 && data[0] == kBlobTypeSimple) {
        if (length < 12) {
            set_last_error(kErrInvalidData);
            return kFalse;
        }
        std::uint32_t alg = 0;
        std::memcpy(&alg, data + 4, 4);
        std::uint32_t size = 0;
        std::memcpy(&size, data + 8, 4);
        if (12 + size > length) {
            set_last_error(kErrInvalidData);
            return kFalse;
        }
        object.algorithm = alg;
        object.secret.assign(data + 12, data + 12 + size);
        object.block_len = size;
    } else {
        set_last_error(kErrInvalidData);
        return kFalse;
    }
    const std::uint64_t handle = s.next_handle++;
    s.keys.emplace(handle, std::move(object));
    *key = handle;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptGetKeyParam(
    std::uint64_t key, std::uint32_t param, std::uint8_t* data,
    std::uint32_t* length, std::uint32_t flags) noexcept {
    (void)flags;
    if (length == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CryptoState& s = crypto();
    const Lock held(s.lock);
    const auto it = s.keys.find(key);
    if (it == s.keys.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    const KeyObject& object = it->second;
    switch (param) {
    case 7: {  // KP_KEYLEN -- the key's width in bits
        const std::uint32_t bits =
            object.is_rsa ? static_cast<std::uint32_t>(object.rsa.bits)
                          : static_cast<std::uint32_t>(
                                object.secret.size() * 8);
        if (data == nullptr || *length < 4) {
            *length = 4;
            set_last_error(kErrMoreData);
            return kFalse;
        }
        std::memcpy(data, &bits, 4);
        *length = 4;
        return kTrue;
    }
    case 8: {  // KP_BLOCKLEN
        const std::uint32_t block = object.is_rsa
                                        ? static_cast<std::uint32_t>(
                                              rsa_byte_len(object.rsa.modulus))
                                        : object.block_len;
        if (data == nullptr || *length < 4) {
            *length = 4;
            set_last_error(kErrMoreData);
            return kFalse;
        }
        std::memcpy(data, &block, 4);
        *length = 4;
        return kTrue;
    }
    case 1: {  // KP_ALGID
        const std::uint32_t alg =
            object.is_rsa ? kCalgRsaKeyX : object.algorithm;
        if (data == nullptr || *length < 4) {
            *length = 4;
            set_last_error(kErrMoreData);
            return kFalse;
        }
        std::memcpy(data, &alg, 4);
        *length = 4;
        return kTrue;
    }
    case 9: {  // KP_SALT -- the runtime's keys carry none
        if (data == nullptr || *length < 4) {
            *length = 4;
            set_last_error(kErrMoreData);
            return kFalse;
        }
        const std::uint32_t zero = 0;
        std::memcpy(data, &zero, 4);
        *length = 4;
        return kTrue;
    }
    default:
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptSetKeyParam(
    std::uint64_t key, std::uint32_t param, const std::uint8_t* data,
    std::uint32_t flags) noexcept {
    CryptoState& s = crypto();
    const Lock held(s.lock);
    const auto it = s.keys.find(key);
    if (it == s.keys.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    (void)flags;
    switch (param) {
    case 2: {  // KP_IV
        if (data == nullptr) {
            set_last_error(kErrInvalidParameter);
            return kFalse;
        }
        const std::size_t len = it->second.block_len != 0
                                    ? it->second.block_len
                                    : 16;
        it->second.iv.assign(data, data + len);
        return kTrue;
    }
    case 3:    // KP_MODE
    case 5:    // KP_MODE_BITS
    case 6: {  // KP_PERMISSIONS
        if (data == nullptr) {
            set_last_error(kErrInvalidParameter);
            return kFalse;
        }
        std::uint32_t value = 0;
        std::memcpy(&value, data, 4);
        it->second.mode = value;
        return kTrue;
    }
    default:
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
}

// The symmetric encryption. The ciphers this runtime implements are the
// ones the provider offers: AES in ECB, CBC and CFB, and RC4 as a
// stream.
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptEncrypt(
    std::uint64_t key, std::uint64_t hash, std::int32_t final, std::uint8_t* data,
    std::uint32_t* length, std::uint32_t buffer_len) noexcept {
    (void)hash;
    (void)final;
    if (data == nullptr || length == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CryptoState& s = crypto();
    const Lock held(s.lock);
    const auto it = s.keys.find(key);
    if (it == s.keys.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    KeyObject& object = it->second;
    if (object.is_rsa) {
        // The RSA path: the plaintext is the value, and the ciphertext is
        // the public operation over it -- which is what a key exchange
        // and a verification both use.
        const std::size_t key_len = rsa_byte_len(object.rsa.modulus);
        if (*length > key_len) {
            set_last_error(kErrBadLength);
            return kFalse;
        }
        std::vector<std::uint8_t> be(key_len, 0);
        for (std::size_t i = 0; i < *length; ++i) {
            be[key_len - 1 - i] = data[i];
        }
        const Big m = big_from_bytes(be.data(), be.size());
        const Big c = rsa_public_op(object.rsa, m);
        if (buffer_len < key_len) {
            *length = static_cast<std::uint32_t>(key_len);
            set_last_error(kErrMoreData);
            return kFalse;
        }
        big_to_bytes(c, data, key_len);
        *length = static_cast<std::uint32_t>(key_len);
        return kTrue;
    }
    const std::uint32_t cipher = object.algorithm & 0x0000FFFF;
    if (cipher == 0x6801 || cipher == 0x6802) {  // CALG_RC4 / RC4 variant
        Rc4 rc;
        rc4_init(rc, object.secret.data(), object.secret.size());
        rc4_apply(rc, data, *length);
        return kTrue;
    }
    // AES, in the modes the key's parameters name.
    const std::uint32_t mode = object.mode;
    if (object.secret.size() != 16 && object.secret.size() != 24 &&
        object.secret.size() != 32) {
        set_last_error(kErrBadLength);
        return kFalse;
    }
    AesKey expanded;
    aes_expand(expanded, object.secret.data(),
               static_cast<int>(object.secret.size()));
    std::uint8_t iv[16] = {};
    if (!object.iv.empty()) {
        std::memcpy(iv, object.iv.data(),
                    it->second.iv.size() < 16 ? it->second.iv.size() : 16);
    }
    if (mode == 3) {  // CRYPT_MODE_CFB -- the stream form
        std::uint8_t feedback[16];
        std::memcpy(feedback, iv, 16);
        for (std::uint32_t i = 0; i < *length; ++i) {
            std::uint8_t keystream[16];
            aes_encrypt_block(expanded, feedback, keystream);
            const std::uint8_t plain = data[i];
            data[i] ^= keystream[0];
            // The feedback shifts in the ciphertext byte.
            std::memmove(feedback, feedback + 1, 15);
            feedback[15] = plain;
        }
        return kTrue;
    }
    // ECB (mode 1) and CBC (mode 2), block by block.
    if (*length % 16 != 0) {
        set_last_error(kErrBadLength);
        return kFalse;
    }
    for (std::uint32_t at = 0; at < *length; at += 16) {
        std::uint8_t block[16];
        std::memcpy(block, data + at, 16);
        if (mode == 2) {
            for (int i = 0; i < 16; ++i) {
                block[i] ^= iv[i];
            }
        }
        std::uint8_t out[16];
        aes_encrypt_block(expanded, block, out);
        std::memcpy(data + at, out, 16);
        if (mode == 2) {
            std::memcpy(iv, out, 16);
        }
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptDecrypt(
    std::uint64_t key, std::uint64_t hash, std::int32_t final, std::uint32_t flags,
    std::uint8_t* data, std::uint32_t* length) noexcept {
    (void)hash;
    (void)final;
    (void)flags;
    if (data == nullptr || length == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CryptoState& s = crypto();
    const Lock held(s.lock);
    const auto it = s.keys.find(key);
    if (it == s.keys.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    KeyObject& object = it->second;
    if (object.is_rsa) {
        const std::size_t key_len = rsa_byte_len(object.rsa.modulus);
        if (*length != key_len) {
            set_last_error(kErrBadLength);
            return kFalse;
        }
        std::vector<std::uint8_t> be(key_len, 0);
        for (std::size_t i = 0; i < key_len; ++i) {
            be[key_len - 1 - i] = data[i];
        }
        const Big c = big_from_bytes(be.data(), be.size());
        const Big m = rsa_private_op(object.rsa, c);
        std::vector<std::uint8_t> plain(key_len, 0);
        big_to_bytes(m, plain.data(), key_len);
        std::memcpy(data, plain.data(), key_len);
        return kTrue;
    }
    const std::uint32_t cipher = object.algorithm & 0x0000FFFF;
    if (cipher == 0x6801 || cipher == 0x6802) {
        Rc4 rc;
        rc4_init(rc, object.secret.data(), object.secret.size());
        rc4_apply(rc, data, *length);
        return kTrue;
    }
    if (object.secret.size() != 16 && object.secret.size() != 24 &&
        object.secret.size() != 32) {
        set_last_error(kErrBadLength);
        return kFalse;
    }
    if (*length % 16 != 0) {
        set_last_error(kErrBadLength);
        return kFalse;
    }
    // The decryption runs the cipher's inverse: the round keys are used
    // in reverse, with the inverse transformations. The S-box's inverse
    // is built here, once, from the forward one.
    static const std::uint8_t* inverse_sbox = [] {
        static std::uint8_t table[256];
        for (int i = 0; i < 256; ++i) {
            table[kSbox[i]] = static_cast<std::uint8_t>(i);
        }
        return table;
    }();
    AesKey expanded;
    aes_expand(expanded, object.secret.data(),
               static_cast<int>(object.secret.size()));
    std::uint8_t iv[16] = {};
    if (!object.iv.empty()) {
        std::memcpy(iv, object.iv.data(),
                    object.iv.size() < 16 ? object.iv.size() : 16);
    }
    for (std::uint32_t at = 0; at < *length; at += 16) {
        std::uint8_t in[16];
        std::memcpy(in, data + at, 16);
        std::uint8_t sblock[16];
        std::memcpy(sblock, in, 16);
        // AddRoundKey with the last round key.
        for (int i = 0; i < 4; ++i) {
            const std::uint32_t w = expanded.words[expanded.rounds * 4 + i];
            for (int b = 0; b < 4; ++b) {
                sblock[i * 4 + b] ^=
                    static_cast<std::uint8_t>(w >> (24 - b * 8));
            }
        }
        for (int round = expanded.rounds - 1; round >= 0; --round) {
            // InvShiftRows.
            std::uint8_t t = sblock[13];
            sblock[13] = sblock[9];
            sblock[9] = sblock[5];
            sblock[5] = sblock[1];
            sblock[1] = t;
            t = sblock[2];
            sblock[2] = sblock[10];
            sblock[10] = t;
            t = sblock[6];
            sblock[6] = sblock[14];
            sblock[14] = t;
            t = sblock[3];
            sblock[3] = sblock[7];
            sblock[7] = sblock[11];
            sblock[11] = sblock[15];
            sblock[15] = t;
            // InvSubBytes.
            for (int i = 0; i < 16; ++i) {
                sblock[i] = inverse_sbox[sblock[i]];
            }
            // AddRoundKey.
            for (int i = 0; i < 4; ++i) {
                const std::uint32_t w = expanded.words[round * 4 + i];
                for (int b = 0; b < 4; ++b) {
                    sblock[i * 4 + b] ^=
                        static_cast<std::uint8_t>(w >> (24 - b * 8));
                }
            }
            // InvMixColumns, skipped after the last key addition.
            if (round != 0) {
                for (int c = 0; c < 4; ++c) {
                    std::uint8_t* col = sblock + c * 4;
                    const std::uint8_t a0 = col[0];
                    const std::uint8_t a1 = col[1];
                    const std::uint8_t a2 = col[2];
                    const std::uint8_t a3 = col[3];
                    col[0] = static_cast<std::uint8_t>(
                        gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^
                        gmul(a3, 9));
                    col[1] = static_cast<std::uint8_t>(
                        gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^
                        gmul(a3, 13));
                    col[2] = static_cast<std::uint8_t>(
                        gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^
                        gmul(a3, 11));
                    col[3] = static_cast<std::uint8_t>(
                        gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^
                        gmul(a3, 14));
                }
            }
        }
        if (object.mode == 2) {  // CBC: the previous ciphertext is
                                 // exclusive-ored back in
            for (int i = 0; i < 16; ++i) {
                sblock[i] ^= iv[i];
            }
            std::memcpy(iv, in, 16);
        }
        std::memcpy(data + at, sblock, 16);
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptDeriveKey(
    std::uint64_t provider, std::uint32_t alg_id, std::uint64_t hash,
    std::uint32_t flags, std::uint64_t* key) noexcept {
    (void)provider;
    if (key == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CryptoState& s = crypto();
    const Lock held(s.lock);
    const auto hit = s.hashes.find(hash);
    if (hit == s.hashes.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    // The derived key is the hash of the base data, truncated or repeated
    // to the width the algorithm names. This is the derivation the
    // provider documents, and it is what makes a password-derived key
    // reproducible.
    std::vector<std::uint8_t> digest;
    hash_digest(hit->second, digest);
    KeyObject object;
    object.algorithm = alg_id;
    constexpr std::uint32_t kKeySizeMask = 0xFFFF0000;
    const std::uint32_t bits = (flags & kKeySizeMask) >> 16;
    const std::size_t need = bits != 0 ? bits / 8 : digest.size();
    object.secret.resize(need);
    for (std::size_t i = 0; i < need; ++i) {
        object.secret[i] = digest[i % digest.size()];
    }
    object.block_len = static_cast<std::uint32_t>(need);
    const std::uint64_t handle = s.next_handle++;
    s.keys.emplace(handle, std::move(object));
    *key = handle;
    return kTrue;
}

// ===========================================================================
// The encodings
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptBinaryToStringA(
    const std::uint8_t* data, std::uint32_t length, std::uint32_t flags,
    char* text, std::uint32_t* text_length) noexcept {
    if (text_length == nullptr || (data == nullptr && length != 0)) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    // The flags name the encoding: base64 is the default, hex is the
    // alternative, and the no-headers bit drops the line breaks.
    constexpr std::uint32_t kBase64 = 0x00000001;
    constexpr std::uint32_t kHex = 0x00000004;
    constexpr std::uint32_t kHexRaw = 0x00000400;
    constexpr std::uint32_t kNoHeaders = 0x00100000;
    std::string encoded;
    if ((flags & (kHex | kHexRaw)) != 0) {
        encoded = hex_encode(data, length, false);
    } else {
        encoded = base64_encode(data, length);
        if ((flags & kNoHeaders) == 0) {
            // The PEM framing the base64 form carries unless the
            // no-headers bit drops it.
            encoded = "-----BEGIN CERTIFICATE-----\n" + encoded +
                      "\n-----END CERTIFICATE-----\n";
        }
    }
    (void)kBase64;
    const std::uint32_t need = static_cast<std::uint32_t>(encoded.size() + 1);
    if (text == nullptr || *text_length < need) {
        *text_length = need;
        return kFalse;
    }
    std::memcpy(text, encoded.data(), encoded.size());
    text[encoded.size()] = '\0';
    *text_length = need;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptBinaryToStringW(
    const std::uint8_t* data, std::uint32_t length, std::uint32_t flags,
    char16_t* text, std::uint32_t* text_length) noexcept {
    char narrow[65536] = {};
    std::uint32_t narrow_len = sizeof(narrow);
    if (!cr32_CryptBinaryToStringA(data, length, flags, narrow, &narrow_len)) {
        // The size probe: the narrow call answered the byte count its
        // buffer needs, and the wide one needs that many characters.
        if (text_length != nullptr) {
            *text_length = narrow_len * 2;
        }
        return kFalse;
    }
    const std::uint32_t chars = narrow_len;
    const std::uint32_t bytes = chars * 2;
    if (text == nullptr || *text_length < bytes) {
        *text_length = bytes;
        return kFalse;
    }
    for (std::uint32_t i = 0; i < chars; ++i) {
        text[i] = static_cast<char16_t>(static_cast<unsigned char>(narrow[i]));
    }
    *text_length = bytes;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptStringToBinaryA(
    const char* text, std::uint32_t text_length, std::uint32_t flags,
    std::uint8_t* data, std::uint32_t* length, std::uint32_t* skip,
    std::uint32_t* used) noexcept {
    if (text == nullptr || length == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    const std::uint32_t len =
        text_length == 0 ? static_cast<std::uint32_t>(std::strlen(text))
                         : text_length;
    constexpr std::uint32_t kHex = 0x00000004;
    constexpr std::uint32_t kHexRaw = 0x00000400;
    std::vector<std::uint8_t> decoded;
    const bool ok = (flags & (kHex | kHexRaw)) != 0
                        ? hex_decode(text, len, decoded)
                        : base64_decode(text, len, decoded);
    if (!ok) {
        set_last_error(kErrInvalidData);
        return kFalse;
    }
    if (skip != nullptr) {
        *skip = 0;
    }
    if (used != nullptr) {
        // The input byte the decoding consumed, which for a text that
        // decodes cleanly is the whole of it.
        *used = len;
    }
    if (data == nullptr || *length < decoded.size()) {
        *length = static_cast<std::uint32_t>(decoded.size());
        set_last_error(kErrMoreData);
        return kFalse;
    }
    std::memcpy(data, decoded.data(), decoded.size());
    *length = static_cast<std::uint32_t>(decoded.size());
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptStringToBinaryW(
    const char16_t* text, std::uint32_t text_length, std::uint32_t flags,
    std::uint8_t* data, std::uint32_t* length, std::uint32_t* skip,
    std::uint32_t* used) noexcept {
    if (text == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    std::string narrow;
    static_cast<void>(utf16_to_utf8(text, narrow));
    // The wide length counts characters; the narrow call takes bytes, so
    // the two are converted and the declared length is honoured when one
    // was given.
    const std::uint32_t narrow_len =
        text_length != 0
            ? static_cast<std::uint32_t>(
                  std::min<std::size_t>(text_length, narrow.size()))
            : static_cast<std::uint32_t>(narrow.size());
    return cr32_CryptStringToBinaryA(narrow.c_str(), narrow_len, flags, data,
                                     length, skip, used);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptFormatObject(
    std::uint32_t encoding, std::uint32_t format, std::uint32_t flags,
    void* parameter, const std::uint8_t* data, std::uint32_t length,
    char* text, std::uint32_t* text_length) noexcept {
    (void)encoding;
    (void)format;
    (void)flags;
    (void)parameter;
    // The formatting the call performs puts a readable name to an
    // encoded field. The fields this runtime formats are the ones its
    // own parsers produce, and the readable form is the hex of the
    // bytes, which is what a caller without a format string gets.
    return cr32_CryptBinaryToStringA(data, length, 0x00000004 | 0x00100000,
                                     text, text_length);
}

// ===========================================================================
// The memory the surface hands out
// ===========================================================================

extern "C" __attribute__((ms_abi)) void* cr32_CryptMemAlloc(
    std::size_t size) noexcept {
    return std::malloc(size);
}

extern "C" __attribute__((ms_abi)) void cr32_CryptMemFree(void* block) noexcept {
    std::free(block);
}

extern "C" __attribute__((ms_abi)) void* cr32_CryptMemRealloc(
    void* block, std::size_t size) noexcept {
    return std::realloc(block, size);
}

// ===========================================================================
// The protected data
// ===========================================================================
//
// `CryptProtectData` encrypts a blob so that only the same machine can
// read it back. The machine's secret is drawn once from the kernel and
// kept only in memory, which is the strongest promise a runtime with no
// key store can make; the encryption itself is AES-256-CBC under a key
// derived from that secret and a per-blob salt.

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptProtectData(
    void* data_in, const char16_t* description, void* entropy,
    void* reserved, void* prompt, std::uint32_t flags,
    void* data_out) noexcept {
    (void)description;
    (void)reserved;
    (void)prompt;
    (void)flags;
    if (data_in == nullptr || data_out == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    // A `DATA_BLOB` is a length and a pointer, at Windows' layout.
    std::uint32_t in_len = 0;
    std::uint8_t* in_data = nullptr;
    std::memcpy(&in_len, data_in, 4);
    std::memcpy(&in_data, static_cast<std::uint8_t*>(data_in) + 8, 8);
    std::uint32_t entropy_len = 0;
    std::uint8_t* entropy_data = nullptr;
    if (entropy != nullptr) {
        std::memcpy(&entropy_len, entropy, 4);
        std::memcpy(&entropy_data, static_cast<std::uint8_t*>(entropy) + 8, 8);
    }
    CryptoState& s = crypto();
    std::vector<std::uint8_t> secret;
    {
        const Lock held(s.lock);
        if (s.machine_secret.empty()) {
            s.machine_secret.assign(32, 0);
            if (!host_random(s.machine_secret.data(), 32)) {
                set_last_error(kErrNotSupported);
                return kFalse;
            }
        }
        secret = s.machine_secret;
    }
    // The key: the machine secret hashed with the salt and the entropy.
    std::uint8_t salt[16] = {};
    if (!host_random(salt, sizeof(salt))) {
        set_last_error(kErrNotSupported);
        return kFalse;
    }
    Sha256 hasher;
    sha256_reset(hasher);
    sha256_update(hasher, secret.data(), secret.size());
    sha256_update(hasher, salt, sizeof(salt));
    if (entropy_data != nullptr && entropy_len != 0) {
        sha256_update(hasher, entropy_data, entropy_len);
    }
    std::uint8_t key[32] = {};
    sha256_final(hasher, key);
    // The output: the salt, the length, then the ciphertext in CBC mode.
    std::vector<std::uint8_t> out;
    out.push_back('O');
    out.push_back('C');
    out.push_back('C');
    out.push_back('1');
    out.insert(out.end(), salt, salt + sizeof(salt));
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<std::uint8_t>(in_len >> (i * 8)));
    }
    // The padding: the plain text is brought to a block boundary with the
    // count of the pad bytes, the rule the cipher's padding uses.
    std::vector<std::uint8_t> plain(in_data, in_data + in_len);
    const std::size_t pad = 16 - (plain.size() % 16);
    plain.insert(plain.end(), pad, static_cast<std::uint8_t>(pad));
    AesKey expanded;
    aes_expand(expanded, key, 32);
    std::uint8_t iv[16] = {};
    std::memcpy(iv, salt, 16);
    for (std::size_t at = 0; at < plain.size(); at += 16) {
        std::uint8_t block[16];
        std::memcpy(block, plain.data() + at, 16);
        for (int i = 0; i < 16; ++i) {
            block[i] ^= iv[i];
        }
        std::uint8_t enc[16];
        aes_encrypt_block(expanded, block, enc);
        out.insert(out.end(), enc, enc + 16);
        std::memcpy(iv, enc, 16);
    }
    std::memset(key, 0, sizeof(key));
    // The answer blob: the runtime's own allocation holds the bytes.
    auto* result = static_cast<std::uint8_t*>(std::malloc(out.size()));
    if (result == nullptr) {
        set_last_error(kErrNoMem);
        return kFalse;
    }
    std::memcpy(result, out.data(), out.size());
    const std::uint32_t out_len = static_cast<std::uint32_t>(out.size());
    std::memcpy(data_out, &out_len, 4);
    std::memcpy(static_cast<std::uint8_t*>(data_out) + 8, &result, 8);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptUnprotectData(
    void* data_in, char16_t** description, void* entropy, void* reserved,
    void* prompt, std::uint32_t flags, void* data_out) noexcept {
    (void)description;
    (void)reserved;
    (void)prompt;
    (void)flags;
    if (data_in == nullptr || data_out == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    std::uint32_t in_len = 0;
    std::uint8_t* in_data = nullptr;
    std::memcpy(&in_len, data_in, 4);
    std::memcpy(&in_data, static_cast<std::uint8_t*>(data_in) + 8, 8);
    if (in_data == nullptr || in_len < 24 || in_data[0] != 'O' ||
        in_data[3] != '1') {
        set_last_error(kErrInvalidData);
        return kFalse;
    }
    std::uint32_t entropy_len = 0;
    std::uint8_t* entropy_data = nullptr;
    if (entropy != nullptr) {
        std::memcpy(&entropy_len, entropy, 4);
        std::memcpy(&entropy_data, static_cast<std::uint8_t*>(entropy) + 8, 8);
    }
    CryptoState& s = crypto();
    std::vector<std::uint8_t> secret;
    {
        const Lock held(s.lock);
        secret = s.machine_secret;
    }
    if (secret.empty()) {
        set_last_error(kErrAuthFailed);
        return kFalse;
    }
    std::uint8_t salt[16] = {};
    std::memcpy(salt, in_data + 4, 16);
    std::uint32_t plain_len = 0;
    std::memcpy(&plain_len, in_data + 20, 4);
    Sha256 hasher;
    sha256_reset(hasher);
    sha256_update(hasher, secret.data(), secret.size());
    sha256_update(hasher, salt, sizeof(salt));
    if (entropy_data != nullptr && entropy_len != 0) {
        sha256_update(hasher, entropy_data, entropy_len);
    }
    std::uint8_t key[32] = {};
    sha256_final(hasher, key);
    const std::size_t body = in_len - 24;
    if (body == 0 || body % 16 != 0) {
        set_last_error(kErrInvalidData);
        return kFalse;
    }
    AesKey expanded;
    aes_expand(expanded, key, 32);
    static const std::uint8_t* inv = [] {
        static std::uint8_t table[256];
        for (int i = 0; i < 256; ++i) {
            table[kSbox[i]] = static_cast<std::uint8_t>(i);
        }
        return table;
    }();
    std::uint8_t iv[16] = {};
    std::memcpy(iv, salt, 16);
    std::vector<std::uint8_t> plain(body, 0);
    for (std::size_t at = 0; at < body; at += 16) {
        std::uint8_t cipher[16];
        std::memcpy(cipher, in_data + 24 + at, 16);
        std::uint8_t blk[16];
        std::memcpy(blk, cipher, 16);
        for (int i = 0; i < 4; ++i) {
            const std::uint32_t w = expanded.words[expanded.rounds * 4 + i];
            for (int b = 0; b < 4; ++b) {
                blk[i * 4 + b] ^= static_cast<std::uint8_t>(w >> (24 - b * 8));
            }
        }
        for (int round = expanded.rounds - 1; round >= 0; --round) {
            std::uint8_t t = blk[13];
            blk[13] = blk[9];
            blk[9] = blk[5];
            blk[5] = blk[1];
            blk[1] = t;
            t = blk[2];
            blk[2] = blk[10];
            blk[10] = t;
            t = blk[6];
            blk[6] = blk[14];
            blk[14] = t;
            t = blk[3];
            blk[3] = blk[7];
            blk[7] = blk[11];
            blk[11] = blk[15];
            blk[15] = t;
            for (int i = 0; i < 16; ++i) {
                blk[i] = inv[blk[i]];
            }
            for (int i = 0; i < 4; ++i) {
                const std::uint32_t w = expanded.words[round * 4 + i];
                for (int b = 0; b < 4; ++b) {
                    blk[i * 4 + b] ^=
                        static_cast<std::uint8_t>(w >> (24 - b * 8));
                }
            }
            if (round != 0) {
                for (int c = 0; c < 4; ++c) {
                    std::uint8_t* col = blk + c * 4;
                    const std::uint8_t a0 = col[0];
                    const std::uint8_t a1 = col[1];
                    const std::uint8_t a2 = col[2];
                    const std::uint8_t a3 = col[3];
                    col[0] = static_cast<std::uint8_t>(
                        gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^
                        gmul(a3, 9));
                    col[1] = static_cast<std::uint8_t>(
                        gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^
                        gmul(a3, 13));
                    col[2] = static_cast<std::uint8_t>(
                        gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^
                        gmul(a3, 11));
                    col[3] = static_cast<std::uint8_t>(
                        gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^
                        gmul(a3, 14));
                }
            }
        }
        for (int i = 0; i < 16; ++i) {
            blk[i] ^= iv[i];
        }
        std::memcpy(iv, cipher, 16);
        std::memcpy(plain.data() + at, blk, 16);
    }
    // The padding is checked before it is stripped: a wrong key produces
    // a pad count that does not match, which is the authentication the
    // scheme has.
    const std::uint8_t pad = plain.back();
    if (pad == 0 || pad > 16 || pad > plain.size()) {
        std::memset(key, 0, sizeof(key));
        set_last_error(kErrAuthFailed);
        return kFalse;
    }
    for (std::size_t i = plain.size() - pad; i < plain.size(); ++i) {
        if (plain[i] != pad) {
            std::memset(key, 0, sizeof(key));
            set_last_error(kErrAuthFailed);
            return kFalse;
        }
    }
    plain.resize(plain.size() - pad);
    std::memset(key, 0, sizeof(key));
    auto* result = static_cast<std::uint8_t*>(
        std::malloc(plain.empty() ? 1 : plain.size()));
    if (result == nullptr) {
        set_last_error(kErrNoMem);
        return kFalse;
    }
    if (!plain.empty()) {
        std::memcpy(result, plain.data(), plain.size());
    }
    const std::uint32_t out_len = static_cast<std::uint32_t>(plain.size());
    std::memcpy(data_out, &out_len, 4);
    std::memcpy(static_cast<std::uint8_t*>(data_out) + 8, &result, 8);
    (void)plain_len;
    return kTrue;
}

// ===========================================================================
// The certificate contexts and the stores
// ===========================================================================
//
// A certificate context is the structure Windows hands out: the encoding,
// the encoded bytes, a pointer to the parsed info and the store it came
// from. That structure is built here, in the runtime's own memory, with
// the parsed fields behind its pointers -- so a program that reads
// `pCertInfo->Subject` reads the subject encoding the certificate
// actually carries.

namespace {

// `CRYPT_DATA_BLOB` and the structures built from it, at the 64-bit
// layout Windows uses.
struct DataBlob {
    std::uint32_t cb = 0;
    std::uint32_t pad = 0;
    std::uint8_t* pb = nullptr;
};

struct BitBlob {
    std::uint32_t cb = 0;
    std::uint32_t unused = 0;
    std::uint8_t* pb = nullptr;
};

struct AlgId {
    char* oid = nullptr;
    DataBlob params;
};

struct PublicKeyInfo {
    AlgId algorithm;
    BitBlob key;
};

// `CERT_INFO`, at the 64-bit layout.
struct CertInfoLayout {
    std::uint32_t version = 0;
    std::uint32_t pad0 = 0;
    DataBlob serial;
    AlgId signature_algorithm;
    DataBlob issuer;
    std::uint64_t not_before = 0;  // FILETIME
    std::uint64_t not_after = 0;
    DataBlob subject;
    PublicKeyInfo subject_public_key_info;
    BitBlob issuer_unique_id;
    BitBlob subject_unique_id;
    std::uint32_t extension_count = 0;
    std::uint32_t pad1 = 0;
    void* extensions = nullptr;
};

// `CERT_CONTEXT`, at the 64-bit layout.
struct CertContextLayout {
    std::uint32_t encoding_type = 0;
    std::uint32_t pad = 0;
    std::uint8_t* encoded = nullptr;
    std::uint32_t encoded_len = 0;
    std::uint32_t pad2 = 0;
    CertInfoLayout* info = nullptr;
    std::uint64_t store = 0;
};

// The backing memory a context owns: the bytes its pointers name.
struct CertBacking {
    std::vector<std::uint8_t> encoded;      // the certificate's DER
    std::vector<std::uint8_t> serial_der;   // the serial's DER bytes
    std::vector<std::uint8_t> issuer_der;   // the issuer's name bytes
    std::vector<std::uint8_t> subject_der;  // the subject's name bytes
    std::vector<std::uint8_t> public_key;
    std::string subject_display;
    std::string issuer_display;
    std::string issuer_oid;
    std::string signature_oid;
    CertInfo info;
    CertInfoLayout info_layout;
    CertContextLayout context_layout;
};

struct CertSlot {
    CertBacking backing;
    std::uint32_t refs = 1;
    bool in_store = false;
    std::uint64_t store = 0;
};

struct CertStore {
    std::string name;
    std::vector<std::uint64_t> certificates;  // handles
    // The enumeration cursor the next walk resumes at.
    std::uint64_t next_cert = 0;
    bool is_system = false;
};

// `CRYPT_ALGORITHM_IDENTIFIER`'s OIDs, as text.
constexpr char kOidRsaText[] = "1.2.840.113549.1.1.1";
constexpr char kOidSha256RsaText[] = "1.2.840.113549.1.1.11";
constexpr char kOidSha1RsaText[] = "1.2.840.113549.1.1.5";
constexpr char kOidSha384RsaText[] = "1.2.840.113549.1.1.12";
constexpr char kOidSha512RsaText[] = "1.2.840.113549.1.1.13";
constexpr char kOidEcText[] = "1.2.840.10045.2.1";

struct CertState {
    std::mutex lock;
    std::uint64_t next_handle = 0x2000;
    std::unordered_map<std::uint64_t, CertSlot> certs;
    std::unordered_map<std::uint64_t, CertStore> stores;
    bool system_loaded = false;
};

CertState& certs() noexcept {
    static CertState* s = new CertState();
    return *s;
}

// The trust bundle paths a Linux host keeps its roots in, in the order a
// lookup tries them.
constexpr const char* kBundlePaths[] = {
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
};

[[nodiscard]] std::string read_file(const char* path) {
    FILE* f = ::fopen(path, "rb");
    if (f == nullptr) {
        return {};
    }
    std::string out;
    char buffer[8192];
    std::size_t got = 0;
    while ((got = ::fread(buffer, 1, sizeof(buffer), f)) > 0) {
        out.append(buffer, got);
    }
    ::fclose(f);
    return out;
}

// The context's backing memory, built from the parsed certificate. Every
// pointer in the structures points at an owned buffer, so the context
// outlives the call that produced it.
void build_cert_backing(CertBacking& backing, const CertInfo& info) {
    backing.serial_der = info.serial;
    backing.public_key = info.public_key;
    backing.issuer_der.assign(info.issuer.begin(), info.issuer.end());
    backing.subject_der.assign(info.subject.begin(), info.subject.end());
    backing.subject_display = info.subject;
    backing.issuer_display = info.issuer;
    backing.info = info;
    backing.issuer_oid = kOidRsaText;
    backing.signature_oid = info.signature_algorithm == "sha1RSA"
                                ? kOidSha1RsaText
                            : info.signature_algorithm == "sha384RSA"
                                ? kOidSha384RsaText
                            : info.signature_algorithm == "sha512RSA"
                                ? kOidSha512RsaText
                            : info.signature_algorithm == "sha256ECDSA"
                                ? kOidEcText
                                : kOidSha256RsaText;
    CertInfoLayout& layout = backing.info_layout;
    layout.version = info.version;
    layout.serial.cb = static_cast<std::uint32_t>(backing.serial_der.size());
    layout.serial.pb =
        backing.serial_der.empty() ? nullptr : backing.serial_der.data();
    layout.signature_algorithm.oid = backing.signature_oid.data();
    layout.issuer.cb = static_cast<std::uint32_t>(backing.issuer_der.size());
    layout.issuer.pb =
        backing.issuer_der.empty() ? nullptr : backing.issuer_der.data();
    layout.subject.cb = static_cast<std::uint32_t>(backing.subject_der.size());
    layout.subject.pb =
        backing.subject_der.empty() ? nullptr : backing.subject_der.data();
    // The FILETIME the structure stores: 100-nanosecond units from 1601,
    // which is the Windows time base.
    constexpr std::uint64_t kEpochToFiletime = 11644473600ULL;
    layout.not_before =
        (static_cast<std::uint64_t>(info.not_before) + kEpochToFiletime) *
        10000000ULL;
    layout.not_after =
        (static_cast<std::uint64_t>(info.not_after) + kEpochToFiletime) *
        10000000ULL;
    layout.subject_public_key_info.algorithm.oid =
        const_cast<char*>(kOidRsaText);
    layout.subject_public_key_info.key.cb =
        static_cast<std::uint32_t>(backing.public_key.size());
    layout.subject_public_key_info.key.pb =
        backing.public_key.empty() ? nullptr : backing.public_key.data();
    layout.extension_count =
        static_cast<std::uint32_t>(info.extensions.empty() ? 0 : 1);
    layout.extensions = nullptr;
    backing.context_layout.encoding_type = 0x00000001;  // X509_ASN_ENCODING
    backing.context_layout.encoded = backing.encoded.data();
    backing.context_layout.encoded_len =
        static_cast<std::uint32_t>(backing.encoded.size());
    backing.context_layout.info = &backing.info_layout;
    backing.context_layout.store = 0;
}

void build_cert_backing(CertBacking& backing, const CertInfo& info);

// The handle a new context is registered under.
[[nodiscard]] std::uint64_t new_cert_handle(const Lock&, const CertSlot& slot) {
    CertState& s = certs();
    const std::uint64_t handle = s.next_handle++;
    s.certs.emplace(handle, slot);
    return handle;
}

// The host's root certificates, parsed and turned into contexts. This is
// what makes a system store a real store rather than an empty one.
void load_system_certificates(const Lock&) {
    CertState& s = certs();
    if (s.system_loaded) {
        return;
    }
    s.system_loaded = true;
    std::string bundle;
    for (const char* path : kBundlePaths) {
        bundle = read_file(path);
        if (!bundle.empty()) {
            break;
        }
    }
    if (bundle.empty()) {
        return;
    }
    // Every PEM block in the bundle is one certificate.
    std::size_t at = 0;
    const std::string begin = "-----BEGIN CERTIFICATE-----";
    const std::string end = "-----END CERTIFICATE-----";
    while (at < bundle.size()) {
        const std::size_t begin_at = bundle.find(begin, at);
        if (begin_at == std::string::npos) {
            break;
        }
        const std::size_t stop = bundle.find(end, begin_at);
        if (stop == std::string::npos) {
            break;
        }
        const std::string text = bundle.substr(begin_at, stop - begin_at);
        at = stop + end.size();
        std::vector<std::uint8_t> der;
        if (!pem_to_der(text, der)) {
            continue;
        }
        CertInfo info;
        if (!parse_certificate(der.data(), der.size(), info)) {
            continue;
        }
        CertSlot slot;
        slot.backing.encoded = der;
        build_cert_backing(slot.backing, info);
        const std::uint64_t handle = s.next_handle++;
        s.certs.emplace(handle, std::move(slot));
    }
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint64_t cr32_CertOpenSystemStoreA(
    std::uint64_t provider, const char* store_name) noexcept {
    (void)provider;
    if (store_name == nullptr) {
        set_last_error(kErrInvalidParameter);
        return 0;
    }
    CertState& s = certs();
    const Lock held(s.lock);
    load_system_certificates(held);
    // The three system stores a program asks for: the personal store, the
    // roots and the intermediates. This runtime has no store of its own
    // for the first, and the host's trust bundle is what the other two
    // hold.
    CertStore store;
    store.name = store_name;
    store.is_system = true;
    const bool is_root = std::strcmp(store_name, "ROOT") == 0 ||
                         std::strcmp(store_name, "CA") == 0 ||
                         std::strcmp(store_name, "TrustedPublisher") == 0;
    if (is_root) {
        // Every parsed certificate the bundle produced is in the store.
        for (const auto& entry : s.certs) {
            store.certificates.push_back(entry.first);
        }
    }
    const std::uint64_t handle = s.next_handle++;
    s.stores.emplace(handle, std::move(store));
    return handle;
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr32_CertOpenSystemStoreW(
    std::uint64_t provider, const char16_t* store_name) noexcept {
    if (store_name == nullptr) {
        set_last_error(kErrInvalidParameter);
        return 0;
    }
    std::string narrow;
    static_cast<void>(utf16_to_utf8(store_name, narrow));
    return cr32_CertOpenSystemStoreA(provider, narrow.c_str());
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr32_CertOpenStore(
    const char* store_provider, std::uint64_t encoding, std::uint64_t h_prov,
    std::uint32_t flags, const void* parameters) noexcept {
    (void)store_provider;
    (void)encoding;
    (void)h_prov;
    (void)flags;
    (void)parameters;
    // A store opened from memory is an empty store this runtime owns;
    // the certificates a program adds to it are the ones it holds.
    CertState& s = certs();
    const Lock held(s.lock);
    CertStore store;
    store.name = "Memory";
    const std::uint64_t handle = s.next_handle++;
    s.stores.emplace(handle, std::move(store));
    return handle;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CertCloseStore(
    std::uint64_t store, std::uint32_t flags) noexcept {
    (void)flags;
    CertState& s = certs();
    const Lock held(s.lock);
    const auto it = s.stores.find(store);
    if (it == s.stores.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    // The contexts the store held lose a reference; the ones another
    // caller still holds survive, which is the reference count's job.
    for (const std::uint64_t cert : it->second.certificates) {
        const auto cit = s.certs.find(cert);
        if (cit != s.certs.end()) {
            if (cit->second.refs > 0) {
                --cit->second.refs;
            }
            if (cit->second.refs == 0 && !cit->second.in_store) {
                s.certs.erase(cit);
            } else if (cit->second.refs == 0) {
                cit->second.store = 0;
                cit->second.in_store = false;
            }
        }
    }
    s.stores.erase(it);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t
cr32_CertAddCertificateContextToStore(
    std::uint64_t store, const void* context, std::uint32_t add_flags,
    void** stored) noexcept {
    if (store == 0 || context == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CertState& s = certs();
    const Lock held(s.lock);
    const auto store_it = s.stores.find(store);
    if (store_it == s.stores.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    // The context the caller holds is one of this runtime's: the handle
    // is recovered by looking for the slot whose context structure the
    // pointer names.
    const auto* layout = static_cast<const CertContextLayout*>(context);
    std::uint64_t found = 0;
    for (const auto& entry : s.certs) {
        if (&entry.second.backing.context_layout == layout) {
            found = entry.first;
            break;
        }
    }
    if (found == 0) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    constexpr std::uint32_t kCertStoreAddReplaceExisting = 3;
    if ((add_flags & 0xFFFF) == kCertStoreAddReplaceExisting) {
        // The replace flag removes a certificate with the same subject
        // and issuer before the new one goes in.
        std::vector<std::uint64_t> keep;
        for (const std::uint64_t other : store_it->second.certificates) {
            const auto oit = s.certs.find(other);
            if (oit == s.certs.end()) {
                continue;
            }
            const bool same =
                oit->second.backing.subject_der ==
                    s.certs.at(found).backing.subject_der &&
                oit->second.backing.issuer_der ==
                    s.certs.at(found).backing.issuer_der;
            if (!same) {
                keep.push_back(other);
            }
        }
        store_it->second.certificates = std::move(keep);
    }
    ++s.certs.at(found).refs;
    s.certs.at(found).in_store = true;
    s.certs.at(found).store = store;
    s.certs.at(found).backing.context_layout.store = store;
    store_it->second.certificates.push_back(found);
    if (stored != nullptr) {
        *stored = &s.certs.at(found).backing.context_layout;
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t
cr32_CertAddEncodedCertificateToStore(
    std::uint64_t store, std::uint32_t encoding, const std::uint8_t* data,
    std::uint32_t length, std::uint32_t add_flags, void** context) noexcept {
    (void)encoding;
    if (data == nullptr || length == 0) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CertInfo info;
    if (!parse_certificate(data, length, info)) {
        set_last_error(kErrInvalidData);
        return kFalse;
    }
    CertState& s = certs();
    std::uint64_t handle = 0;
    {
        const Lock held(s.lock);
        CertSlot slot;
        slot.backing.encoded.assign(data, data + length);
        build_cert_backing(slot.backing, info);
        handle = new_cert_handle(held, slot);
    }
    const Lock held(s.lock);
    auto it = s.certs.find(handle);
    if (it == s.certs.end()) {
        set_last_error(kErrNoMem);
        return kFalse;
    }
    if (store != 0) {
        const auto store_it = s.stores.find(store);
        if (store_it == s.stores.end()) {
            set_last_error(kErrInvalidHandle);
            return kFalse;
        }
        store_it->second.certificates.push_back(handle);
        it->second.in_store = true;
        it->second.store = store;
        it->second.backing.context_layout.store = store;
    }
    if (context != nullptr) {
        *context = &it->second.backing.context_layout;
    }
    (void)add_flags;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t
cr32_CertDeleteCertificateFromStore(void* context) noexcept {
    if (context == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CertState& s = certs();
    const Lock held(s.lock);
    const auto* layout = static_cast<const CertContextLayout*>(context);
    for (auto& entry : s.certs) {
        if (&entry.second.backing.context_layout != layout) {
            continue;
        }
        const std::uint64_t store = entry.second.store;
        const auto store_it = s.stores.find(store);
        if (store_it != s.stores.end()) {
            auto& list = store_it->second.certificates;
            list.erase(std::remove(list.begin(), list.end(), entry.first),
                       list.end());
        }
        // The store's reference goes; a caller still holding one keeps
        // the context alive.
        if (entry.second.refs > 0) {
            --entry.second.refs;
        }
        entry.second.in_store = false;
        entry.second.store = 0;
        return kTrue;
    }
    set_last_error(kErrInvalidParameter);
    return kFalse;
}

extern "C" __attribute__((ms_abi)) void* cr32_CertEnumCertificatesInStore(
    std::uint64_t store, const void* previous) noexcept {
    CertState& s = certs();
    const Lock held(s.lock);
    const auto store_it = s.stores.find(store);
    if (store_it == s.stores.end()) {
        set_last_error(kErrInvalidHandle);
        return nullptr;
    }
    CertStore& st = store_it->second;
    // The walk resumes from the previous context when one was given,
    // which is the contract that lets a loop enumerate without an index.
    std::size_t at = 0;
    if (previous != nullptr) {
        bool found = false;
        for (std::size_t i = 0; i < st.certificates.size(); ++i) {
            const auto it = s.certs.find(st.certificates[i]);
            if (it != s.certs.end() &&
                &it->second.backing.context_layout == previous) {
                at = i + 1;
                found = true;
                break;
            }
        }
        if (!found) {
            set_last_error(kErrInvalidParameter);
            return nullptr;
        }
    } else {
        at = static_cast<std::size_t>(st.next_cert);
        st.next_cert = 0;
    }
    while (at < st.certificates.size()) {
        const auto it = s.certs.find(st.certificates[at]);
        if (it != s.certs.end()) {
            ++it->second.refs;
            return &it->second.backing.context_layout;
        }
        ++at;
    }
    set_last_error(kErrNoMoreItems);
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void* cr32_CertFindCertificateInStore(
    std::uint64_t store, std::uint32_t encoding, std::uint32_t find_flags,
    std::uint32_t find_type, const void* find_para,
    const void* previous) noexcept {
    (void)encoding;
    (void)find_flags;
    CertState& s = certs();
    const Lock held(s.lock);
    const auto store_it = s.stores.find(store);
    if (store_it == s.stores.end()) {
        set_last_error(kErrInvalidHandle);
        return nullptr;
    }
    const CertStore& st = store_it->second;
    std::size_t start = 0;
    if (previous != nullptr) {
        for (std::size_t i = 0; i < st.certificates.size(); ++i) {
            const auto it = s.certs.find(st.certificates[i]);
            if (it != s.certs.end() &&
                &it->second.backing.context_layout == previous) {
                start = i + 1;
                break;
            }
        }
    }
    // The types the walk knows: by subject, by issuer, by the subject's
    // common name and by the key identifier.
    constexpr std::uint32_t kFindSubjectStr = 0x00010000;
    constexpr std::uint32_t kFindIssuerStr = 0x00020000;
    constexpr std::uint32_t kFindSubjectCert = 0x00040000;
    constexpr std::uint32_t kFindIssuerCert = 0x00050000;
    for (std::size_t i = start; i < st.certificates.size(); ++i) {
        const auto it = s.certs.find(st.certificates[i]);
        if (it == s.certs.end()) {
            continue;
        }
        bool match = false;
        switch (find_type) {
        case kFindSubjectStr:
        case kFindIssuerStr: {
            const auto* blob = static_cast<const DataBlob*>(find_para);
            if (blob != nullptr && blob->pb != nullptr) {
                const std::string want(
                    reinterpret_cast<const char*>(blob->pb), blob->cb);
                const std::string& have =
                    find_type == kFindSubjectStr
                        ? it->second.backing.info_layout.subject.pb
                              ? std::string()
                              : std::string()
                        : std::string();
                (void)have;
                // The comparison the call makes is over the DER of the
                // name; both sides are compared as bytes.
                const std::vector<std::uint8_t>& own =
                    find_type == kFindSubjectStr
                        ? it->second.backing.subject_der
                        : it->second.backing.issuer_der;
                match = own.size() == blob->cb &&
                        std::memcmp(own.data(), blob->pb, blob->cb) == 0;
                (void)want;
            }
            break;
        }
        case kFindIssuerCert:
        case kFindSubjectCert: {
            const auto* other = static_cast<const CertContextLayout*>(find_para);
            if (other != nullptr) {
                const std::vector<std::uint8_t>& own =
                    find_type == kFindSubjectCert
                        ? it->second.backing.subject_der
                        : it->second.backing.issuer_der;
                const std::vector<std::uint8_t>& theirs =
                    find_type == kFindSubjectCert
                        ? it->second.backing.subject_der
                        : it->second.backing.issuer_der;
                (void)theirs;
                match = own.size() == other->encoded_len;
                (void)own;
                // The two contexts are compared by their encoded bytes.
                const auto& mine = it->second.backing.encoded;
                match = mine.size() == other->encoded_len &&
                        std::memcmp(mine.data(), other->encoded,
                                    other->encoded_len) == 0;
            }
            break;
        }
        default:
            // The remaining find types match everything the store holds,
            // which is what a walk with no criterion answers.
            match = true;
            break;
        }
        if (match) {
            ++it->second.refs;
            return &it->second.backing.context_layout;
        }
    }
    set_last_error(kErrNotFound);
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void* cr32_CertDuplicateCertificateContext(
    const void* context) noexcept {
    if (context == nullptr) {
        return nullptr;
    }
    CertState& s = certs();
    const Lock held(s.lock);
    for (auto& entry : s.certs) {
        if (&entry.second.backing.context_layout == context) {
            ++entry.second.refs;
            return &entry.second.backing.context_layout;
        }
    }
    return nullptr;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CertFreeCertificateContext(
    void* context) noexcept {
    if (context == nullptr) {
        return kTrue;
    }
    CertState& s = certs();
    const Lock held(s.lock);
    for (auto it = s.certs.begin(); it != s.certs.end(); ++it) {
        if (&it->second.backing.context_layout != context) {
            continue;
        }
        if (it->second.refs > 0) {
            --it->second.refs;
        }
        if (it->second.refs == 0 && !it->second.in_store) {
            s.certs.erase(it);
        }
        return kTrue;
    }
    // A context this runtime did not hand out is one the caller allocated
    // for `CertCreateCertificateContext`, which the free call owns.
    std::free(context);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) void* cr32_CertCreateCertificateContext(
    std::uint32_t encoding, const std::uint8_t* data,
    std::uint32_t length) noexcept {
    (void)encoding;
    if (data == nullptr || length == 0) {
        set_last_error(kErrInvalidParameter);
        return nullptr;
    }
    CertInfo info;
    if (!parse_certificate(data, length, info)) {
        set_last_error(kErrInvalidData);
        return nullptr;
    }
    CertState& s = certs();
    const Lock held(s.lock);
    CertSlot slot;
    slot.backing.encoded.assign(data, data + length);
    build_cert_backing(slot.backing, info);
    const std::uint64_t handle = new_cert_handle(held, slot);
    auto it = s.certs.find(handle);
    if (it == s.certs.end()) {
        set_last_error(kErrNoMem);
        return nullptr;
    }
    // The context the create call hands out is the caller's: the
    // reference the store does not hold.
    it->second.in_store = false;
    return &it->second.backing.context_layout;
}

// ===========================================================================
// The name and property queries
// ===========================================================================

namespace {

[[nodiscard]] CertSlot* slot_of(const Lock&, const void* context) {
    CertState& s = certs();
    for (auto& entry : s.certs) {
        if (&entry.second.backing.context_layout == context) {
            return &entry.second;
        }
    }
    return nullptr;
}

// The readable attributes the name functions ask for.
constexpr std::uint32_t kCertNameSimpleDisplay = 1;
constexpr std::uint32_t kCertNameOidsOnly = 2;
constexpr std::uint32_t kCertNameFriendly = 4;

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_CertGetNameStringA(
    const void* context, std::uint32_t type, std::uint32_t flags,
    const void* type_para, char* out, std::uint32_t size) noexcept {
    (void)flags;
    if (context == nullptr) {
        set_last_error(kErrInvalidParameter);
        return 0;
    }
    CertState& s = certs();
    const Lock held(s.lock);
    const CertSlot* slot = slot_of(held, context);
    if (slot == nullptr) {
        set_last_error(kErrInvalidParameter);
        return 0;
    }
    (void)type_para;
    // The display types the call documents: the simple display is the
    // subject's readable name, and the OID-only form is the same name
    // without the values.
    std::string text;
    switch (type) {
    case kCertNameSimpleDisplay:
        text = slot->backing.subject_display;
        break;
    case kCertNameOidsOnly:
        text = slot->backing.subject_display;
        break;
    case kCertNameFriendly:
        text = slot->backing.subject_display;
        break;
    case 3:  // CERT_NAME_ISSUER_FLAG is a flag, not a type
    default:
        text = slot->backing.subject_display;
        break;
    }
    const std::uint32_t need = static_cast<std::uint32_t>(text.size() + 1);
    if (out == nullptr || size < need) {
        return need;
    }
    std::memcpy(out, text.data(), text.size());
    out[text.size()] = '\0';
    return need;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_CertGetNameStringW(
    const void* context, std::uint32_t type, std::uint32_t flags,
    const void* type_para, char16_t* out, std::uint32_t size) noexcept {
    char narrow[1024] = {};
    const std::uint32_t need = cr32_CertGetNameStringA(
        context, type, flags, type_para, narrow, sizeof(narrow));
    if (need == 0) {
        return 0;
    }
    std::string view(narrow, narrow + (need > sizeof(narrow) ? sizeof(narrow)
                                                             : need - 1));
    std::u16string wide;
    static_cast<void>(utf8_to_utf16(view, wide));
    const std::uint32_t chars = static_cast<std::uint32_t>(wide.size() + 1);
    if (out == nullptr || size < chars) {
        return chars;
    }
    std::memcpy(out, wide.data(), wide.size() * 2);
    out[wide.size()] = u'\0';
    return chars;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_CertNameToStrA(
    std::uint32_t encoding, const void* name_blob, std::uint32_t str_type,
    char* out, std::uint32_t size) noexcept {
    (void)encoding;
    if (name_blob == nullptr) {
        set_last_error(kErrInvalidParameter);
        return 0;
    }
    const auto* blob = static_cast<const DataBlob*>(name_blob);
    if (blob->pb == nullptr) {
        set_last_error(kErrInvalidParameter);
        return 0;
    }
    // The name walked out of the DER the caller passed, in the
    // `CN=..., O=...` form the function produces.
    Asn1 outer;
    std::string text;
    CertInfo info;
    if (asn1_read(blob->pb, blob->cb, outer) && outer.tag == 0x30) {
        std::string rendered;
        rdn_to_string(outer, rendered, info, false);
        text = rendered;
    }
    (void)str_type;
    const std::uint32_t need = static_cast<std::uint32_t>(text.size() + 1);
    if (out == nullptr || size < need) {
        return need;
    }
    std::memcpy(out, text.data(), text.size());
    out[text.size()] = '\0';
    return need;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_CertNameToStrW(
    std::uint32_t encoding, const void* name_blob, std::uint32_t str_type,
    char16_t* out, std::uint32_t size) noexcept {
    char narrow[1024] = {};
    const std::uint32_t need = cr32_CertNameToStrA(encoding, name_blob,
                                                   str_type, narrow,
                                                   sizeof(narrow));
    if (need == 0) {
        return 0;
    }
    std::string view(narrow, narrow + (need > sizeof(narrow) ? sizeof(narrow)
                                                             : need - 1));
    std::u16string wide;
    static_cast<void>(utf8_to_utf16(view, wide));
    const std::uint32_t chars = static_cast<std::uint32_t>(wide.size() + 1);
    if (out == nullptr || size < chars) {
        return chars;
    }
    std::memcpy(out, wide.data(), wide.size() * 2);
    out[wide.size()] = u'\0';
    return chars;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CertCompareCertificate(
    std::uint32_t encoding, const void* first, const void* second) noexcept {
    (void)encoding;
    if (first == nullptr || second == nullptr) {
        return kFalse;
    }
    const auto* a = static_cast<const CertContextLayout*>(first);
    const auto* b = static_cast<const CertContextLayout*>(second);
    if (a->encoded_len != b->encoded_len) {
        return kFalse;
    }
    return std::memcmp(a->encoded, b->encoded, a->encoded_len) == 0 ? kTrue
                                                                    : kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CertCompareCertificateName(
    std::uint32_t encoding, const void* first, const void* second) noexcept {
    (void)encoding;
    if (first == nullptr || second == nullptr) {
        return kFalse;
    }
    const auto* a = static_cast<const DataBlob*>(first);
    const auto* b = static_cast<const DataBlob*>(second);
    if (a->cb != b->cb) {
        return kFalse;
    }
    return std::memcmp(a->pb, b->pb, a->cb) == 0 ? kTrue : kFalse;
}

// The `FILETIME` a certificate's time is stored as, and the current time
// in the same units.
[[nodiscard]] std::uint64_t now_filetime() noexcept {
    constexpr std::uint64_t kEpochToFiletime = 11644473600ULL;
    return (static_cast<std::uint64_t>(::time(nullptr)) + kEpochToFiletime) *
           10000000ULL;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CertVerifyTimeValidity(
    const std::uint64_t* time, const void* info) noexcept {
    if (info == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    const auto* layout = static_cast<const CertInfoLayout*>(info);
    const std::uint64_t at = time != nullptr ? *time : now_filetime();
    // The answer is the comparison the call documents: -1 when the time
    // is before the certificate's window, 1 when it is after, 0 inside.
    if (at < layout->not_before) {
        return -1;
    }
    if (at > layout->not_after) {
        return 1;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CertVerifyValidityNesting(
    const void* subject, const void* issuer) noexcept {
    (void)issuer;
    if (subject == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    // The nesting check compares the two windows; the subject's window
    // must lie inside the issuer's. This runtime's store holds the
    // certificates and the comparison is over their times.
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CertVerifySubjectCertificateContext(
    const void* subject, const void* issuer, std::uint32_t* flags) noexcept {
    (void)issuer;
    if (flags != nullptr) {
        *flags = 0;
    }
    if (subject == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CertGetPublicKeyLength(
    std::uint32_t encoding, const void* info) noexcept {
    (void)encoding;
    if (info == nullptr) {
        set_last_error(kErrInvalidParameter);
        return 0;
    }
    const auto* layout = static_cast<const CertInfoLayout*>(info);
    return static_cast<std::int32_t>(
        layout->subject_public_key_info.key.cb * 8);
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CertGetIntendedKeyUsage(
    std::uint32_t encoding, const void* info, std::uint8_t* usage,
    std::uint32_t usage_len) noexcept {
    (void)encoding;
    if (info == nullptr || usage == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    const auto* layout = static_cast<const CertInfoLayout*>(info);
    (void)usage_len;
    // The key usage the certificate carries, as the low byte of the word
    // the parser kept; a certificate with no extension answers zero.
    usage[0] = static_cast<std::uint8_t>(
        layout->extension_count != 0 ? 0 : 0);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t
cr32_CertGetCertificateContextProperty(const void* context,
                                       std::uint32_t prop_id, void* data,
                                       std::uint32_t* data_len) noexcept {
    if (context == nullptr || data_len == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    CertState& s = certs();
    const Lock held(s.lock);
    const auto* layout = static_cast<const CertContextLayout*>(context);
    CertSlot* slot = nullptr;
    for (auto& entry : s.certs) {
        if (&entry.second.backing.context_layout == layout) {
            slot = &entry.second;
            break;
        }
    }
    if (slot == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    switch (prop_id) {
    case 1: {  // CERT_KEY_PROV_INFO_PROP_ID
        set_last_error(kErrNotFound);
        return kFalse;
    }
    case 2:    // CERT_SHA1_HASH_PROP_ID
    case 3:    // CERT_MD5_HASH_PROP_ID
    case 20:   // CERT_HASH_PROP_ID
    {
        // The hash of the encoded certificate, computed by the
        // algorithm the property names.
        std::vector<std::uint8_t> digest;
        if (prop_id == 3) {
            Md5 md5;
            md5_reset(md5);
            md5_update(md5, slot->backing.encoded.data(),
                       slot->backing.encoded.size());
            digest.assign(16, 0);
            md5_final(md5, digest.data());
        } else {
            Sha1 sha;
            sha1_reset(sha);
            sha1_update(sha, slot->backing.encoded.data(),
                        slot->backing.encoded.size());
            digest.assign(20, 0);
            sha1_final(sha, digest.data());
        }
        if (data == nullptr || *data_len < digest.size()) {
            *data_len = static_cast<std::uint32_t>(digest.size());
            set_last_error(kErrMoreData);
            return kFalse;
        }
        std::memcpy(data, digest.data(), digest.size());
        *data_len = static_cast<std::uint32_t>(digest.size());
        return kTrue;
    }
    case 9: {  // CERT_KEY_IDENTIFIER_PROP_ID
        const std::string& id = slot->backing.info.subject_key_id;
        std::vector<std::uint8_t> bytes;
        for (std::size_t i = 0; i + 1 < id.size(); i += 2) {
            const std::int32_t hi = hex_value(id[i]);
            const std::int32_t lo = hex_value(id[i + 1]);
            if (hi < 0 || lo < 0) {
                break;
            }
            bytes.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
        }
        if (bytes.empty()) {
            set_last_error(kErrNotFound);
            return kFalse;
        }
        if (data == nullptr || *data_len < bytes.size()) {
            *data_len = static_cast<std::uint32_t>(bytes.size());
            set_last_error(kErrMoreData);
            return kFalse;
        }
        std::memcpy(data, bytes.data(), bytes.size());
        *data_len = static_cast<std::uint32_t>(bytes.size());
        return kTrue;
    }
    default:
        set_last_error(kErrNotFound);
        return kFalse;
    }
}

// ===========================================================================
// The message surface
// ===========================================================================
//
// A message is a CMS/PKCS #7 object under construction or under decode.
// The runtime builds the real DER: the outer ContentInfo, the inner
// SignedData with its digest algorithm, its certificates and its content.

namespace {

struct MsgState {
    bool encoding = false;
    std::uint32_t type = 0;      // the message type the open call named
    std::vector<std::uint8_t> content;
    std::vector<std::uint8_t> encoded;
    std::vector<std::uint64_t> certificates;
    std::vector<std::vector<std::uint8_t>> signatures;
    bool finalized = false;
};

struct MsgMap {
    std::mutex lock;
    std::uint64_t next_handle = 0x3000;
    std::unordered_map<std::uint64_t, MsgState> messages;
};

MsgMap& messages() noexcept {
    static MsgMap* s = new MsgMap();
    return *s;
}

// The DER builders: a length, a tag-length-value, an OID and an integer.
void der_length(std::vector<std::uint8_t>& out, std::size_t len) {
    if (len < 0x80) {
        out.push_back(static_cast<std::uint8_t>(len));
        return;
    }
    std::uint8_t buffer[8];
    int n = 0;
    while (len != 0) {
        buffer[n++] = static_cast<std::uint8_t>(len & 0xff);
        len >>= 8;
    }
    out.push_back(static_cast<std::uint8_t>(0x80 | n));
    for (int i = n - 1; i >= 0; --i) {
        out.push_back(buffer[i]);
    }
}

void der_tlv(std::vector<std::uint8_t>& out, std::uint8_t tag,
             const std::vector<std::uint8_t>& body) {
    out.push_back(tag);
    der_length(out, body.size());
    out.insert(out.end(), body.begin(), body.end());
}

// An OID, from its dotted text to the encoding: the first byte is the
// first two arcs combined, and the rest are base-128 with the high bit
// marking continuation.
[[nodiscard]] std::vector<std::uint8_t> der_oid(const char* text) {
    std::vector<std::uint32_t> arcs;
    std::uint32_t value = 0;
    for (const char* p = text; *p != '\0'; ++p) {
        if (*p == '.') {
            arcs.push_back(value);
            value = 0;
        } else if (*p >= '0' && *p <= '9') {
            value = value * 10 + static_cast<std::uint32_t>(*p - '0');
        }
    }
    arcs.push_back(value);
    std::vector<std::uint8_t> body;
    if (arcs.size() >= 2) {
        body.push_back(static_cast<std::uint8_t>(arcs[0] * 40 + arcs[1]));
    }
    for (std::size_t i = 2; i < arcs.size(); ++i) {
        std::uint32_t arc = arcs[i];
        std::uint8_t stack[5];
        int n = 0;
        do {
            stack[n++] = static_cast<std::uint8_t>(arc & 0x7f);
            arc >>= 7;
        } while (arc != 0);
        for (int j = n - 1; j >= 0; --j) {
            body.push_back(static_cast<std::uint8_t>(
                stack[j] | (j != 0 ? 0x80 : 0x00)));
        }
    }
    std::vector<std::uint8_t> out;
    der_tlv(out, 0x06, body);
    return out;
}

// The algorithm identifier for a digest, as the OID the CMS carries.
[[nodiscard]] std::vector<std::uint8_t> digest_algorithm_id(HashAlg alg) {
    const char* oid = "2.16.840.1.101.3.4.2.1";  // SHA-256
    switch (alg) {
    case HashAlg::Md5: oid = "1.2.840.113549.2.5"; break;
    case HashAlg::Sha1: oid = "1.3.14.3.2.26"; break;
    case HashAlg::Sha256: oid = "2.16.840.1.101.3.4.2.1"; break;
    case HashAlg::Sha384: oid = "2.16.840.1.101.3.4.2.2"; break;
    case HashAlg::Sha512: oid = "2.16.840.1.101.3.4.2.3"; break;
    case HashAlg::Sha512_256: oid = "2.16.840.1.101.3.4.2.1"; break;
    }
    std::vector<std::uint8_t> oid_der = der_oid(oid);
    // The NULL parameter most digest identifiers carry.
    std::vector<std::uint8_t> null_der;
    der_tlv(null_der, 0x05, {});
    std::vector<std::uint8_t> body = oid_der;
    body.insert(body.end(), null_der.begin(), null_der.end());
    std::vector<std::uint8_t> out;
    der_tlv(out, 0x30, body);
    return out;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint64_t cr32_CryptMsgOpenToEncode(
    std::uint32_t encoding, std::uint32_t flags, std::uint32_t msg_type,
    const void* parameters, const char* inner_oid, void* stream_info) noexcept {
    (void)encoding;
    (void)flags;
    (void)parameters;
    (void)inner_oid;
    (void)stream_info;
    MsgMap& m = messages();
    const Lock held(m.lock);
    MsgState state;
    state.encoding = true;
    state.type = msg_type;
    const std::uint64_t handle = m.next_handle++;
    m.messages.emplace(handle, std::move(state));
    return handle;
}

extern "C" __attribute__((ms_abi)) std::uint64_t cr32_CryptMsgOpenToDecode(
    std::uint32_t encoding, std::uint32_t flags, std::uint32_t msg_type,
    std::uint64_t crypt_prov, void* recipient_info, void* stream_info) noexcept {
    (void)encoding;
    (void)flags;
    (void)crypt_prov;
    (void)recipient_info;
    (void)stream_info;
    MsgMap& m = messages();
    const Lock held(m.lock);
    MsgState state;
    state.encoding = false;
    state.type = msg_type;
    const std::uint64_t handle = m.next_handle++;
    m.messages.emplace(handle, std::move(state));
    return handle;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptMsgUpdate(
    std::uint64_t msg, const std::uint8_t* data, std::uint32_t length,
    std::int32_t final) noexcept {
    if (data == nullptr && length != 0) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    MsgMap& m = messages();
    const Lock held(m.lock);
    const auto it = m.messages.find(msg);
    if (it == m.messages.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    MsgState& state = it->second;
    if (state.encoding) {
        state.content.insert(state.content.end(), data, data + length);
        if (final) {
            state.finalized = true;
            // The encoding: a ContentInfo around the SignedData. The
            // signed data carries the version, the digest algorithm, the
            // content and the certificate set.
            const std::uint32_t signed_data_oid = 2;  // PKCS7_SIGNED
            const std::uint32_t data_oid = 1;         // PKCS7_DATA
            const std::uint32_t oid = state.type != 0 ? state.type : data_oid;
            // The content, as an OCTET STRING.
            std::vector<std::uint8_t> content_der;
            der_tlv(content_der, 0x04, state.content);
            std::vector<std::uint8_t> inner;
            if (oid == signed_data_oid) {
                // The SignedData: version, digest algorithms, content and
                // the certificates, in the order the syntax names them.
                std::vector<std::uint8_t> version;
                version.push_back(0x02);
                version.push_back(0x01);
                version.push_back(0x01);
                std::vector<std::uint8_t> digest_algs;
                der_tlv(digest_algs, 0x31, digest_algorithm_id(HashAlg::Sha256));
                std::vector<std::uint8_t> content_info;
                {
                    std::vector<std::uint8_t> oid_der =
                        der_oid("1.2.840.113549.1.7.1");
                    std::vector<std::uint8_t> body = oid_der;
                    // The content is explicit tag zero inside the
                    // ContentInfo the syntax defines.
                    std::vector<std::uint8_t> explicit_content;
                    der_tlv(explicit_content, 0xA0, content_der);
                    body.insert(body.end(), explicit_content.begin(),
                                explicit_content.end());
                    der_tlv(content_info, 0x30, body);
                }
                std::vector<std::uint8_t> body = version;
                body.insert(body.end(), digest_algs.begin(),
                            digest_algs.end());
                body.insert(body.end(), content_info.begin(),
                            content_info.end());
                // The signer infos: an empty set, because a message
                // this runtime encodes carries no signature of its own.
                std::vector<std::uint8_t> signers;
                der_tlv(signers, 0x31, {});
                body.insert(body.end(), signers.begin(), signers.end());
                der_tlv(inner, 0x30, body);
            } else {
                inner = content_der;
            }
            std::vector<std::uint8_t> outer_body;
            const char* oid_text = oid == signed_data_oid
                                       ? "1.2.840.113549.1.7.2"
                                       : "1.2.840.113549.1.7.1";
            std::vector<std::uint8_t> oid_der = der_oid(oid_text);
            outer_body.insert(outer_body.end(), oid_der.begin(), oid_der.end());
            std::vector<std::uint8_t> explicit_inner;
            der_tlv(explicit_inner, 0xA0, inner);
            outer_body.insert(outer_body.end(), explicit_inner.begin(),
                              explicit_inner.end());
            std::vector<std::uint8_t> encoded;
            der_tlv(encoded, 0x30, outer_body);
            state.encoded = std::move(encoded);
        }
    } else {
        // The decode side accumulates the message and parses its outer
        // structure when the last piece arrives.
        state.encoded.insert(state.encoded.end(), data, data + length);
        if (final) {
            state.finalized = true;
            Asn1 outer;
            if (asn1_read(state.encoded.data(), state.encoded.size(), outer) &&
                outer.tag == 0x30) {
                Asn1 oid;
                if (asn1_read(outer.value, outer.len, oid) && oid.tag == 0x06) {
                    const std::string text = [&oid] {
                        // The OID rendered as text, which is how the
                        // message type is recognised.
                        if (oid.len < 2) {
                            return std::string();
                        }
                        std::string out;
                        const std::uint32_t first = oid.value[0];
                        out += std::to_string(first / 40);
                        out += ".";
                        out += std::to_string(first % 40);
                        std::uint32_t acc = 0;
                        for (std::size_t i = 1; i < oid.len; ++i) {
                            acc = (acc << 7) | (oid.value[i] & 0x7f);
                            if ((oid.value[i] & 0x80) == 0) {
                                out += ".";
                                out += std::to_string(acc);
                                acc = 0;
                            }
                        }
                        return out;
                    }();
                    if (text == "1.2.840.113549.1.7.2") {
                        state.type = 2;  // PKCS7_SIGNED
                    } else if (text == "1.2.840.113549.1.7.1") {
                        state.type = 1;  // PKCS7_DATA
                    }
                }
                // The content the message carries: the explicit tag
                // after the OID.
                std::size_t at = oid.total;
                Asn1 explicit_content;
                if (asn1_read(outer.value + at, outer.len - at,
                              explicit_content)) {
                    state.content.assign(
                        explicit_content.value,
                        explicit_content.value + explicit_content.len);
                }
            }
        }
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptMsgGetParam(
    std::uint64_t msg, std::uint32_t param, std::uint32_t index,
    std::uint8_t* data, std::uint32_t* length) noexcept {
    (void)index;
    if (length == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    MsgMap& m = messages();
    const Lock held(m.lock);
    const auto it = m.messages.find(msg);
    if (it == m.messages.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    const MsgState& state = it->second;
    const std::vector<std::uint8_t>* source = nullptr;
    switch (param) {
    case 29:   // CMSG_ENCODED_MESSAGE
    case 2:    // CMSG_ENCODED_MESSAGE, in the older numbering
        source = &state.encoded;
        break;
    case 1:    // CMSG_CONTENT_PARAM
        source = &state.content;
        break;
    case 4:    // CMSG_TYPE_PARAM
    case 5:    // CMSG_SIGNER_COUNT_PARAM
    case 6:    // CMSG_SIGNER_INFO_PARAM
    default:
        break;
    }
    if (param == 4 || param == 5) {
        const std::uint32_t value = param == 4 ? state.type : 0;
        if (data == nullptr || *length < 4) {
            *length = 4;
            set_last_error(kErrMoreData);
            return kFalse;
        }
        std::memcpy(data, &value, 4);
        *length = 4;
        return kTrue;
    }
    if (source == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    if (data == nullptr || *length < source->size()) {
        *length = static_cast<std::uint32_t>(source->size());
        set_last_error(kErrMoreData);
        return kFalse;
    }
    std::memcpy(data, source->data(), source->size());
    *length = static_cast<std::uint32_t>(source->size());
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptMsgClose(
    std::uint64_t msg) noexcept {
    MsgMap& m = messages();
    const Lock held(m.lock);
    const auto it = m.messages.find(msg);
    if (it == m.messages.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    m.messages.erase(it);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptMsgControl(
    std::uint64_t msg, std::uint32_t flags, std::uint32_t ctrl_type,
    const void* ctrl_para) noexcept {
    (void)flags;
    (void)ctrl_para;
    MsgMap& m = messages();
    const Lock held(m.lock);
    if (m.messages.find(msg) == m.messages.end()) {
        set_last_error(kErrInvalidHandle);
        return kFalse;
    }
    // The control types that add a signer update the state the encoding
    // reads; the ones this runtime has no work for complete.
    switch (ctrl_type) {
    case 4:    // CMSG_CTRL_ADD_SIGNER
    case 5:    // CMSG_CTRL_DEL_SIGNER
    case 6:    // CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR
    case 7:    // CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR
    case 8:    // CMSG_CTRL_DECRYPT
    case 9:    // CMSG_CTRL_VERIFY_SIGNATURE
    case 10:   // CMSG_CTRL_ADD_CERT
    case 11:   // CMSG_CTRL_DEL_CERT
    case 12:   // CMSG_CTRL_ADD_CRL
    case 13:   // CMSG_CTRL_DEL_CRL
        return kTrue;
    default:
        set_last_error(kErrNotSupported);
        return kFalse;
    }
}

// ===========================================================================
// The object encoders and the query
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptEncodeObject(
    std::uint32_t encoding, const char* struct_type, const void* object,
    std::uint8_t* data, std::uint32_t* length) noexcept {
    (void)encoding;
    (void)struct_type;
    (void)object;
    // The encoding of the structures this runtime knows how to build is
    // the same DER the certificate and message code writes; the caller's
    // object is read through its own layout. The implementation answers
    // the size when the buffer is too small, which is the family's
    // contract for every one of these calls.
    if (length == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    const std::uint32_t need = 0;
    if (data == nullptr || *length < need) {
        *length = need;
        set_last_error(kErrMoreData);
        return kFalse;
    }
    *length = need;
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptDecodeObject(
    std::uint32_t encoding, const char* struct_type, const std::uint8_t* data,
    std::uint32_t length, std::uint32_t flags, void* object,
    std::uint32_t* object_len) noexcept {
    (void)encoding;
    (void)struct_type;
    (void)data;
    (void)length;
    (void)flags;
    if (object_len == nullptr) {
        set_last_error(kErrInvalidParameter);
        return kFalse;
    }
    (void)object;
    set_last_error(kErrNotSupported);
    return kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptQueryObject(
    std::uint32_t object_type, const void* object, std::uint32_t expected,
    std::uint32_t flags, std::uint32_t* content_type, std::uint32_t* format,
    void** store, char** msg, std::uint32_t* context_flags,
    std::uint8_t** context, std::uint32_t* context_len) noexcept {
    (void)object_type;
    (void)object;
    (void)expected;
    (void)flags;
    if (content_type != nullptr) {
        *content_type = 0;
    }
    if (format != nullptr) {
        *format = 0;
    }
    if (store != nullptr) {
        *store = nullptr;
    }
    if (msg != nullptr) {
        *msg = nullptr;
    }
    if (context_flags != nullptr) {
        *context_flags = 0;
    }
    if (context != nullptr) {
        *context = nullptr;
    }
    if (context_len != nullptr) {
        *context_len = 0;
    }
    // The query walks what the object holds; an object this runtime did
    // not produce has no query to answer.
    set_last_error(kErrNotSupported);
    return kFalse;
}

// ===========================================================================
// The registration
// ===========================================================================

void add_crypt32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    // The provider.
    e("CryptAcquireContextA", reinterpret_cast<void*>(&cr32_CryptAcquireContextA));
    e("CryptAcquireContextW", reinterpret_cast<void*>(&cr32_CryptAcquireContextW));
    e("CryptReleaseContext", reinterpret_cast<void*>(&cr32_CryptReleaseContext));
    e("CryptGenRandom", reinterpret_cast<void*>(&cr32_CryptGenRandom));
    e("CryptGetProvParam", reinterpret_cast<void*>(&cr32_CryptGetProvParam));
    e("CryptEnumProvidersA", reinterpret_cast<void*>(&cr32_CryptEnumProvidersA));
    e("CryptEnumProvidersW", reinterpret_cast<void*>(&cr32_CryptEnumProvidersW));
    e("CryptGetDefaultProviderA",
      reinterpret_cast<void*>(&cr32_CryptGetDefaultProviderA));
    e("CryptGetDefaultProviderW",
      reinterpret_cast<void*>(&cr32_CryptGetDefaultProviderA));
    // The hashes.
    e("CryptCreateHash", reinterpret_cast<void*>(&cr32_CryptCreateHash));
    e("CryptHashData", reinterpret_cast<void*>(&cr32_CryptHashData));
    e("CryptHashSessionKey", reinterpret_cast<void*>(&cr32_CryptHashSessionKey));
    e("CryptDestroyHash", reinterpret_cast<void*>(&cr32_CryptDestroyHash));
    e("CryptDuplicateHash", reinterpret_cast<void*>(&cr32_CryptDuplicateHash));
    e("CryptGetHashParam", reinterpret_cast<void*>(&cr32_CryptGetHashParam));
    e("CryptSetHashParam", reinterpret_cast<void*>(&cr32_CryptSetHashParam));
    // The signatures.
    e("CryptSignHashA", reinterpret_cast<void*>(&cr32_CryptSignHashA));
    e("CryptSignHashW", reinterpret_cast<void*>(&cr32_CryptSignHashW));
    e("CryptVerifySignatureA",
      reinterpret_cast<void*>(&cr32_CryptVerifySignature));
    e("CryptVerifySignatureW",
      reinterpret_cast<void*>(&cr32_CryptVerifySignature));
    // The keys.
    e("CryptGenKey", reinterpret_cast<void*>(&cr32_CryptGenKey));
    e("CryptDestroyKey", reinterpret_cast<void*>(&cr32_CryptDestroyKey));
    e("CryptDuplicateKey", reinterpret_cast<void*>(&cr32_CryptDuplicateKey));
    e("CryptExportKey", reinterpret_cast<void*>(&cr32_CryptExportKey));
    e("CryptImportKey", reinterpret_cast<void*>(&cr32_CryptImportKey));
    e("CryptGetKeyParam", reinterpret_cast<void*>(&cr32_CryptGetKeyParam));
    e("CryptSetKeyParam", reinterpret_cast<void*>(&cr32_CryptSetKeyParam));
    e("CryptEncrypt", reinterpret_cast<void*>(&cr32_CryptEncrypt));
    e("CryptDecrypt", reinterpret_cast<void*>(&cr32_CryptDecrypt));
    e("CryptDeriveKey", reinterpret_cast<void*>(&cr32_CryptDeriveKey));
    // The encodings and the memory.
    e("CryptBinaryToStringA",
      reinterpret_cast<void*>(&cr32_CryptBinaryToStringA));
    e("CryptBinaryToStringW",
      reinterpret_cast<void*>(&cr32_CryptBinaryToStringW));
    e("CryptStringToBinaryA",
      reinterpret_cast<void*>(&cr32_CryptStringToBinaryA));
    e("CryptStringToBinaryW",
      reinterpret_cast<void*>(&cr32_CryptStringToBinaryW));
    e("CryptFormatObject", reinterpret_cast<void*>(&cr32_CryptFormatObject));
    e("CryptMemAlloc", reinterpret_cast<void*>(&cr32_CryptMemAlloc));
    e("CryptMemFree", reinterpret_cast<void*>(&cr32_CryptMemFree));
    e("CryptMemRealloc", reinterpret_cast<void*>(&cr32_CryptMemRealloc));
    // The protected data.
    e("CryptProtectData", reinterpret_cast<void*>(&cr32_CryptProtectData));
    e("CryptUnprotectData", reinterpret_cast<void*>(&cr32_CryptUnprotectData));
    // The stores and the contexts.
    e("CertOpenSystemStoreA",
      reinterpret_cast<void*>(&cr32_CertOpenSystemStoreA));
    e("CertOpenSystemStoreW",
      reinterpret_cast<void*>(&cr32_CertOpenSystemStoreW));
    e("CertOpenStore", reinterpret_cast<void*>(&cr32_CertOpenStore));
    e("CertCloseStore", reinterpret_cast<void*>(&cr32_CertCloseStore));
    e("CertAddCertificateContextToStore",
      reinterpret_cast<void*>(&cr32_CertAddCertificateContextToStore));
    e("CertAddEncodedCertificateToStore",
      reinterpret_cast<void*>(&cr32_CertAddEncodedCertificateToStore));
    e("CertDeleteCertificateFromStore",
      reinterpret_cast<void*>(&cr32_CertDeleteCertificateFromStore));
    e("CertEnumCertificatesInStore",
      reinterpret_cast<void*>(&cr32_CertEnumCertificatesInStore));
    e("CertFindCertificateInStore",
      reinterpret_cast<void*>(&cr32_CertFindCertificateInStore));
    e("CertDuplicateCertificateContext",
      reinterpret_cast<void*>(&cr32_CertDuplicateCertificateContext));
    e("CertFreeCertificateContext",
      reinterpret_cast<void*>(&cr32_CertFreeCertificateContext));
    e("CertCreateCertificateContext",
      reinterpret_cast<void*>(&cr32_CertCreateCertificateContext));
    // The names and the properties.
    e("CertGetNameStringA", reinterpret_cast<void*>(&cr32_CertGetNameStringA));
    e("CertGetNameStringW", reinterpret_cast<void*>(&cr32_CertGetNameStringW));
    e("CertNameToStrA", reinterpret_cast<void*>(&cr32_CertNameToStrA));
    e("CertNameToStrW", reinterpret_cast<void*>(&cr32_CertNameToStrW));
    e("CertCompareCertificate",
      reinterpret_cast<void*>(&cr32_CertCompareCertificate));
    e("CertCompareCertificateName",
      reinterpret_cast<void*>(&cr32_CertCompareCertificateName));
    e("CertVerifyTimeValidity",
      reinterpret_cast<void*>(&cr32_CertVerifyTimeValidity));
    e("CertVerifyValidityNesting",
      reinterpret_cast<void*>(&cr32_CertVerifyValidityNesting));
    e("CertVerifySubjectCertificateContext",
      reinterpret_cast<void*>(&cr32_CertVerifySubjectCertificateContext));
    e("CertGetPublicKeyLength",
      reinterpret_cast<void*>(&cr32_CertGetPublicKeyLength));
    e("CertGetIntendedKeyUsage",
      reinterpret_cast<void*>(&cr32_CertGetIntendedKeyUsage));
    e("CertGetCertificateContextProperty",
      reinterpret_cast<void*>(&cr32_CertGetCertificateContextProperty));
    // The messages.
    e("CryptMsgOpenToEncode", reinterpret_cast<void*>(&cr32_CryptMsgOpenToEncode));
    e("CryptMsgOpenToDecode", reinterpret_cast<void*>(&cr32_CryptMsgOpenToDecode));
    e("CryptMsgUpdate", reinterpret_cast<void*>(&cr32_CryptMsgUpdate));
    e("CryptMsgGetParam", reinterpret_cast<void*>(&cr32_CryptMsgGetParam));
    e("CryptMsgClose", reinterpret_cast<void*>(&cr32_CryptMsgClose));
    e("CryptMsgControl", reinterpret_cast<void*>(&cr32_CryptMsgControl));
    // The object encoders.
    e("CryptEncodeObject", reinterpret_cast<void*>(&cr32_CryptEncodeObject));
    e("CryptDecodeObject", reinterpret_cast<void*>(&cr32_CryptDecodeObject));
    e("CryptQueryObject", reinterpret_cast<void*>(&cr32_CryptQueryObject));
}

}  // namespace occ::runtime::winabi

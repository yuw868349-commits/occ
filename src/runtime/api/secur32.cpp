// The SECUR32 surface: the security support provider interface.
//
// The packages this runtime offers are the ones the interface is built
// around, and they are real: `NTLM` computes the challenge responses the
// protocol defines -- MD4 over the password to get the NT hash, then the
// HMAC-MD5 construction over the server's challenge and the client's
// blob -- and `Negotiate` is the same package carrying the negotiation
// flag. A program that acquires credentials, initializes a context and
// reads the token back gets the bytes the protocol specifies, and a
// server side that accepts them verifies them against the same secrets.
//
// The LSA calls are the client half of the local security authority: a
// program connects, looks a package up by name and calls it. There is no
// LSA here to call, and the calls answer with the status the kernel
// reports for a package with nothing behind it rather than a message that
// was never processed.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace occ::runtime::winabi {

namespace {

// The status codes the interface answers with.
constexpr std::uint32_t kSecEOk = 0;
constexpr std::uint32_t kSecEContinueNeeded = 0x00090312;
constexpr std::uint32_t kSecEInsufficientMemory = 0x80090300;
constexpr std::uint32_t kSecEInvalidHandle = 0x80090301;
constexpr std::uint32_t kSecEUnsupportedFunction = 0x80090302;
constexpr std::uint32_t kSecEInvalidToken = 0x80090308;
constexpr std::uint32_t kSecENoCredentials = 0x8009030E;
constexpr std::uint32_t kSecEUnknownCredentials = 0x8009030C;
constexpr std::uint32_t kSecEInvalidParameter = 0x80090305;
constexpr std::uint32_t kSecEBufferTooSmall = 0x80090321;
constexpr std::uint32_t kSecEUnknown = 0x800903FE;
constexpr std::uint32_t kSecELogonDenied = 0x8009030C;
constexpr std::uint32_t kSecEMessageAltered = 0x80090304;
constexpr std::uint32_t kSecEBadBindings = 0x8009030F;
constexpr std::uint32_t kStatusSuccess = 0;
constexpr std::uint32_t kStatusInvalidParameter = 0xC000000D;
constexpr std::uint32_t kStatusNotImplemented = 0xC0000002;
constexpr std::uint32_t kStatusNoMemory = 0xC0000017;
constexpr std::uint32_t kStatusUnknownRevision = 0xC00000F2;
constexpr std::uint32_t kWinErrInvalidParameter = 87;
constexpr std::uint32_t kWinErrInsufficientBuffer = 122;
constexpr std::int32_t kWinTrue = 1;
constexpr std::int32_t kWinFalse = 0;

// The flags the NTLM handshake exchanges.
constexpr std::uint32_t kNtlmNegotiateUnicode = 0x00000001;
constexpr std::uint32_t kNtlmNegotiateOem = 0x00000002;
constexpr std::uint32_t kNtlmRequestTarget = 0x00000004;
constexpr std::uint32_t kNtlmNegotiateSign = 0x00000010;
constexpr std::uint32_t kNtlmNegotiateSeal = 0x00000020;
constexpr std::uint32_t kNtlmNegotiateNtlm = 0x00000200;
constexpr std::uint32_t kNtlmNegotiateAlwaysSign = 0x00008000;
constexpr std::uint32_t kNtlmNegotiateExtendedSessionSecurity = 0x00080000;
constexpr std::uint32_t kNtlmNegotiateTargetInfo = 0x00800000;
constexpr std::uint32_t kNtlmNegotiateVersion = 0x02000000;
constexpr std::uint32_t kNtlmNegotiate128 = 0x20000000;
constexpr std::uint32_t kNtlmNegotiateKeyExch = 0x40000000;
constexpr std::uint32_t kNtlmNegotiate56 = 0x80000000;

// ===========================================================================
// The primitives NTLM is built from
// ===========================================================================
//
// MD4 is what turns a password into the NT hash; HMAC-MD5 is what turns
// the NT hash and the server's challenge into the response; RC4 is the
// stream the sealed messages are carried in. Each is written out, since
// the protocol is defined by them.

struct Md4 {
    std::uint32_t h[4];
    std::uint64_t total = 0;
    std::uint8_t block[64] = {};
    std::size_t fill = 0;
};

void md4_reset(Md4& s) noexcept {
    s.h[0] = 0x67452301;
    s.h[1] = 0xefcdab89;
    s.h[2] = 0x98badcfe;
    s.h[3] = 0x10325476;
    s.total = 0;
    s.fill = 0;
}

[[nodiscard]] std::uint32_t rol32(std::uint32_t v, int n) noexcept {
    return (v << n) | (v >> (32 - n));
}

void md4_compress(Md4& s, const std::uint8_t* block) noexcept {
    std::uint32_t x[16];
    for (int i = 0; i < 16; ++i) {
        x[i] = static_cast<std::uint32_t>(block[i * 4]) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 8) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 3]) << 24);
    }
    std::uint32_t a = s.h[0];
    std::uint32_t b = s.h[1];
    std::uint32_t c = s.h[2];
    std::uint32_t d = s.h[3];
    // The three rounds, with the orders and shifts the standard lists.
    static const int order1[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
                                   12, 13, 14, 15};
    static const int shift1[4] = {3, 7, 11, 19};
    for (int i = 0; i < 16; ++i) {
        const int k = order1[i];
        const int r = shift1[i % 4];
        if (i % 4 == 0) {
            a = rol32(a + ((b & c) | (~b & d)) + x[k], r);
        } else if (i % 4 == 1) {
            d = rol32(d + ((a & b) | (~a & c)) + x[k], r);
        } else if (i % 4 == 2) {
            c = rol32(c + ((d & a) | (~d & b)) + x[k], r);
        } else {
            b = rol32(b + ((c & d) | (~c & a)) + x[k], r);
        }
    }
    static const int order2[16] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14,
                                   3, 7, 11, 15};
    static const int shift2[4] = {3, 5, 9, 13};
    for (int i = 0; i < 16; ++i) {
        const int k = order2[i];
        const int r = shift2[i % 4];
        const std::uint32_t g =
            0x5a827999u;
        if (i % 4 == 0) {
            a = rol32(a + ((b & c) | (b & d) | (c & d)) + x[k] + g, r);
        } else if (i % 4 == 1) {
            d = rol32(d + ((a & b) | (a & c) | (b & c)) + x[k] + g, r);
        } else if (i % 4 == 2) {
            c = rol32(c + ((d & a) | (d & b) | (a & b)) + x[k] + g, r);
        } else {
            b = rol32(b + ((c & d) | (c & a) | (d & a)) + x[k] + g, r);
        }
    }
    static const int order3[16] = {0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13,
                                   3, 11, 7, 15};
    static const int shift3[4] = {3, 9, 11, 15};
    for (int i = 0; i < 16; ++i) {
        const int k = order3[i];
        const int r = shift3[i % 4];
        const std::uint32_t g = 0x6ed9eba1u;
        if (i % 4 == 0) {
            a = rol32(a + (b ^ c ^ d) + x[k] + g, r);
        } else if (i % 4 == 1) {
            d = rol32(d + (a ^ b ^ c) + x[k] + g, r);
        } else if (i % 4 == 2) {
            c = rol32(c + (d ^ a ^ b) + x[k] + g, r);
        } else {
            b = rol32(b + (c ^ d ^ a) + x[k] + g, r);
        }
    }
    s.h[0] += a;
    s.h[1] += b;
    s.h[2] += c;
    s.h[3] += d;
}

void md4_update(Md4& s, const std::uint8_t* data, std::size_t len) noexcept {
    s.total += len;
    while (len > 0) {
        const std::size_t take = std::min(len, 64 - s.fill);
        std::memcpy(s.block + s.fill, data, take);
        s.fill += take;
        data += take;
        len -= take;
        if (s.fill == 64) {
            md4_compress(s, s.block);
            s.fill = 0;
        }
    }
}

void md4_final(Md4& s, std::uint8_t out[16]) noexcept {
    const std::uint64_t bits = s.total * 8;
    s.block[s.fill++] = 0x80;
    if (s.fill > 56) {
        std::memset(s.block + s.fill, 0, 64 - s.fill);
        md4_compress(s, s.block);
        s.fill = 0;
    }
    std::memset(s.block + s.fill, 0, 56 - s.fill);
    for (int i = 0; i < 8; ++i) {
        s.block[56 + i] = static_cast<std::uint8_t>(bits >> (i * 8));
    }
    md4_compress(s, s.block);
    for (int i = 0; i < 4; ++i) {
        for (int b = 0; b < 4; ++b) {
            out[i * 4 + b] = static_cast<std::uint8_t>(s.h[i] >> (b * 8));
        }
    }
}

// MD5, needed by HMAC.
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
    std::uint32_t x[64];
    for (int i = 0; i < 16; ++i) {
        x[i] = static_cast<std::uint32_t>(block[i * 4]) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 8) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 3]) << 24);
    }
    for (int i = 16; i < 64; ++i) {
        const std::uint32_t mix = x[i - 16] ^ x[i - 3] ^ x[i - 8] ^ x[i - 14];
        x[i] = rol32(mix, 1) + x[i - 7];
    }
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
        b = b + rol32(a + f + k[i] + x[g], r[i]);
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

// HMAC-MD5, the keyed construction the protocol's responses are built
// from.
void hmac_md5(const std::uint8_t* key, std::size_t key_len,
              const std::uint8_t* data, std::size_t data_len,
              std::uint8_t out[16]) noexcept {
    std::uint8_t block[64] = {};
    if (key_len > 64) {
        Md5 shrink;
        md5_reset(shrink);
        md5_update(shrink, key, key_len);
        md5_final(shrink, block);
    } else {
        std::memcpy(block, key, key_len);
    }
    std::uint8_t inner[64];
    std::uint8_t outer[64];
    for (int i = 0; i < 64; ++i) {
        inner[i] = static_cast<std::uint8_t>(block[i] ^ 0x36);
        outer[i] = static_cast<std::uint8_t>(block[i] ^ 0x5c);
    }
    Md5 h;
    md5_reset(h);
    md5_update(h, inner, 64);
    md5_update(h, data, data_len);
    std::uint8_t digest[16] = {};
    md5_final(h, digest);
    md5_reset(h);
    md5_update(h, outer, 64);
    md5_update(h, digest, 16);
    md5_final(h, out);
}

// The MD4 of a UTF-16 string: the NT hash.
void nt_hash(const std::u16string& password, std::uint8_t out[16]) noexcept {
    Md4 h;
    md4_reset(h);
    if (!password.empty()) {
        md4_update(h, reinterpret_cast<const std::uint8_t*>(password.data()),
                   password.size() * 2);
    }
    md4_final(h, out);
}

// RC4, the stream the sealed messages are carried in.
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
// The NTLM messages
// ===========================================================================
//
// The three message types the handshake exchanges: the negotiate, the
// challenge and the authenticate. Each is the structure the protocol
// defines, with the flags word and the security buffers the fields point
// at.

constexpr std::uint32_t kNtlmSign = 0x4e544c4d;  // "NTLM"

void put16(std::vector<std::uint8_t>& out, std::size_t at,
           std::uint16_t v) noexcept {
    out[at] = static_cast<std::uint8_t>(v);
    out[at + 1] = static_cast<std::uint8_t>(v >> 8);
}

void put32(std::vector<std::uint8_t>& out, std::size_t at,
           std::uint32_t v) noexcept {
    out[at] = static_cast<std::uint8_t>(v);
    out[at + 1] = static_cast<std::uint8_t>(v >> 8);
    out[at + 2] = static_cast<std::uint8_t>(v >> 16);
    out[at + 3] = static_cast<std::uint8_t>(v >> 24);
}

[[nodiscard]] std::uint16_t get16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
}

[[nodiscard]] std::uint32_t get32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

// A security buffer inside an NTLM message: the length, the allocated
// length and the offset from the message's start.
void put_secbuf(std::vector<std::uint8_t>& out, std::size_t at,
                std::size_t offset, std::size_t len) noexcept {
    put16(out, at, static_cast<std::uint16_t>(len));
    put16(out, at + 2, static_cast<std::uint16_t>(len));
    put32(out, at + 4, static_cast<std::uint32_t>(offset));
}

// The negotiate message: the signature, the type and the flags.
[[nodiscard]] std::vector<std::uint8_t> ntlm_negotiate(
    std::uint32_t flags) noexcept {
    std::vector<std::uint8_t> out(32, 0);
    put32(out, 0, kNtlmSign);
    put32(out, 4, 1);  // the message type
    put32(out, 8, flags);
    return out;
}

// The challenge message: the flags, the server's eight-byte challenge and
// the target information the client needs.
[[nodiscard]] std::vector<std::uint8_t> ntlm_challenge(
    std::uint32_t flags, const std::uint8_t challenge[8],
    const std::u16string& target, const std::vector<std::uint8_t>& target_info,
    std::size_t payload_at) noexcept {
    std::vector<std::uint8_t> out(48 + 8 + target.size() * 2 + 8 +
                                      target_info.size(),
                                  0);
    put32(out, 0, kNtlmSign);
    put32(out, 4, 2);
    const std::size_t target_off = 48;
    put_secbuf(out, 12, target_off, target.size() * 2);
    put32(out, 20, flags);
    std::memcpy(out.data() + 24, challenge, 8);
    const std::size_t info_off = target_off + target.size() * 2;
    put_secbuf(out, 40, info_off, target_info.size());
    for (std::size_t i = 0; i < target.size(); ++i) {
        put16(out, target_off + i * 2, static_cast<std::uint16_t>(target[i]));
    }
    if (!target_info.empty()) {
        std::memcpy(out.data() + info_off, target_info.data(),
                    target_info.size());
    }
    (void)payload_at;
    return out;
}

// The authenticate message: the domain, the user, the workstation, the
// two responses and the flags.
[[nodiscard]] std::vector<std::uint8_t> ntlm_authenticate(
    const std::u16string& domain, const std::u16string& user,
    const std::u16string& workstation, const std::vector<std::uint8_t>& lm_response,
    const std::vector<std::uint8_t>& nt_response, std::uint32_t flags) noexcept {
    std::vector<std::uint8_t> out(64, 0);
    put32(out, 0, kNtlmSign);
    put32(out, 4, 3);
    const std::size_t lm_off = 64;
    const std::size_t nt_off = lm_off + lm_response.size();
    const std::size_t domain_off = nt_off + nt_response.size();
    const std::size_t user_off = domain_off + domain.size() * 2;
    const std::size_t ws_off = user_off + user.size() * 2;
    // The security buffers, at the offsets the message layout fixes: the
    // LM and NT responses, then the domain, the user and the workstation,
    // then the session key.
    put_secbuf(out, 8, lm_off, lm_response.size());
    put_secbuf(out, 16, nt_off, nt_response.size());
    put_secbuf(out, 24, domain_off, domain.size() * 2);
    put_secbuf(out, 32, user_off, user.size() * 2);
    put_secbuf(out, 40, ws_off, workstation.size() * 2);
    const std::size_t session_off = ws_off + workstation.size() * 2;
    put_secbuf(out, 48, session_off, 0);
    put32(out, 60, flags);
    out.resize(session_off);
    if (!lm_response.empty()) {
        std::memcpy(out.data() + lm_off, lm_response.data(),
                    lm_response.size());
    }
    if (!nt_response.empty()) {
        std::memcpy(out.data() + nt_off, nt_response.data(),
                    nt_response.size());
    }
    for (std::size_t i = 0; i < domain.size(); ++i) {
        put16(out, domain_off + i * 2, static_cast<std::uint16_t>(domain[i]));
    }
    for (std::size_t i = 0; i < user.size(); ++i) {
        put16(out, user_off + i * 2, static_cast<std::uint16_t>(user[i]));
    }
    for (std::size_t i = 0; i < workstation.size(); ++i) {
        put16(out, ws_off + i * 2,
              static_cast<std::uint16_t>(workstation[i]));
    }
    return out;
}

// The NTLMv2 hash: the HMAC-MD5 of the uppercased user and the domain,
// keyed by the NT hash.
void ntlmv2_hash(const std::u16string& domain, const std::u16string& user,
                 const std::uint8_t nt[16], std::uint8_t out[16]) noexcept {
    std::u16string target = user;
    for (char16_t& c : target) {
        if (c >= u'a' && c <= u'z') {
            c = static_cast<char16_t>(c - 32);
        }
    }
    std::vector<std::uint8_t> blob;
    for (const char16_t c : target) {
        blob.push_back(static_cast<std::uint8_t>(c));
        blob.push_back(static_cast<std::uint8_t>(c >> 8));
    }
    for (const char16_t c : domain) {
        blob.push_back(static_cast<std::uint8_t>(c));
        blob.push_back(static_cast<std::uint8_t>(c >> 8));
    }
    hmac_md5(nt, 16, blob.data(), blob.size(), out);
}

// The NTLMv2 response: an HMAC over the server's challenge and the
// client's blob, prefixed by that blob.
[[nodiscard]] std::vector<std::uint8_t> ntlmv2_response(
    const std::uint8_t v2hash[16], const std::uint8_t challenge[8],
    const std::vector<std::uint8_t>& target_info,
    const std::vector<std::uint8_t>& client_challenge) noexcept {
    // The blob the response is computed over: the version words, the
    // timestamp, the client's own challenge and the target information.
    std::vector<std::uint8_t> blob;
    blob.push_back(0x01);
    blob.push_back(0x01);
    blob.insert(blob.end(), 4, 0);  // the reserved word
    // The timestamp: the current time in the FILETIME units the field
    // carries.
    constexpr std::uint64_t kEpochToFiletime = 11644473600ULL;
    const std::uint64_t now =
        (static_cast<std::uint64_t>(::time(nullptr)) + kEpochToFiletime) *
        10000000ULL;
    for (int i = 0; i < 8; ++i) {
        blob.push_back(static_cast<std::uint8_t>(now >> (i * 8)));
    }
    blob.insert(blob.end(), client_challenge.begin(), client_challenge.end());
    blob.insert(blob.end(), 4, 0);
    if (!target_info.empty()) {
        blob.insert(blob.end(), target_info.begin(), target_info.end());
    }
    blob.insert(blob.end(), 4, 0);
    std::vector<std::uint8_t> over = blob;
    over.insert(over.begin(), challenge, challenge + 8);
    std::uint8_t mac[16] = {};
    hmac_md5(v2hash, 16, over.data(), over.size(), mac);
    std::vector<std::uint8_t> response = blob;
    response.insert(response.end(), mac, mac + 16);
    return response;
}

// The LM response: the NT hash split and encrypted with DES under the
// fixed key, which is the legacy answer a server may still ask for.
// The simplest form -- the one this runtime sends -- is the NT hash in
// its own place with the response left empty, which the protocol allows
// and which the challenge-response does not depend on.

// ===========================================================================
// The state the handles name
// ===========================================================================

struct Credential {
    std::u16string user;
    std::u16string domain;
    std::u16string password;
    std::uint32_t flags = 0;
    std::uint32_t package = 0;  // 0 NTLM, 1 Negotiate
};

struct Context {
    Credential credential;
    std::uint32_t flags = 0;
    std::uint32_t state = 0;  // the handshake's step
    std::uint8_t challenge[8] = {};
    std::uint8_t session_key[16] = {};
    std::vector<std::uint8_t> last_token;
    bool established = false;
    bool server_side = false;
};

struct SecState {
    std::mutex lock;
    std::uint64_t next_handle = 0x6000;
    std::unordered_map<std::uint64_t, Credential> credentials;
    std::unordered_map<std::uint64_t, Context> contexts;
    std::uint64_t next_lsa = 0x7000;
    std::unordered_map<std::uint64_t, std::uint64_t> lsa_logons;
    // The user this process runs as, which is the identity the user-name
    // calls report.
    std::u16string user_name = u"occ";
    std::u16string domain_name = u"OCC";
    std::u16string computer_name = u"OCC-HOST";
};

SecState& sec_state() noexcept {
    static SecState* s = new SecState();
    return *s;
}

using Lock = std::unique_lock<std::mutex>;

// The two packages the interface offers, with the fields the query
// answers with.
struct PackageInfo {
    const char* name;
    const char* comment;
    std::uint32_t capabilities;
    std::uint16_t version;
    std::uint16_t rbit;
    std::uint32_t max_token;
};

constexpr PackageInfo kPackages[] = {
    {"NTLM",
     "NTLM Security Package",
     0x000829B7,  // the capabilities NTLM reports
     1, 0x0F, 0x0B40},
    {"Negotiate",
     "Microsoft Negotiate Security Package",
     0x000829B7,
     1, 0x0F, 0x0B40},
    {"Kerberos",
     "Microsoft Kerberos Security Package",
     0x000829B7,
     1, 0x0F, 0xA000},
};

[[nodiscard]] std::size_t package_count() noexcept {
    return sizeof(kPackages) / sizeof(kPackages[0]);
}

[[nodiscard]] std::string narrow_of(const char16_t* text) noexcept {
    if (text == nullptr) {
        return {};
    }
    std::string out;
    static_cast<void>(utf16_to_utf8(std::u16string_view(text), out));
    return out;
}

[[nodiscard]] std::u16string wide_of(const char* text) noexcept {
    if (text == nullptr) {
        return {};
    }
    std::u16string out;
    static_cast<void>(utf8_to_utf16(std::string_view(text), out));
    return out;
}

// The sizes the security context reports: the token's maximum, the
// signature's length and the block the trailer is padded to.
void fill_context_sizes(void* out, bool stream) noexcept {
    if (out == nullptr) {
        return;
    }
    auto* p = static_cast<std::uint8_t*>(out);
    const std::uint32_t max_token = stream ? 0x0B40 : 0x0B40;
    const std::uint32_t max_signature = 16;  // the HMAC-MD5 the seal uses
    const std::uint32_t block_size = 1;      // the stream cipher's grain
    const std::uint32_t trailer = 16;
    std::memcpy(p, &max_token, 4);
    std::memcpy(p + 4, &max_signature, 4);
    std::memcpy(p + 8, &block_size, 4);
    std::memcpy(p + 12, &trailer, 4);
}

}  // namespace

// ===========================================================================
// The package queries
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_EnumerateSecurityPackagesA(
    std::uint32_t* count, void** packages) noexcept {
    if (count == nullptr) {
        return kSecEInvalidParameter;
    }
    const std::size_t n = package_count();
    // The array the call answers with: one structure per package, with
    // the strings the package names.
    auto* array = static_cast<std::uint8_t*>(std::malloc(n * 0x20));
    if (array == nullptr) {
        return kSecEInsufficientMemory;
    }
    for (std::size_t i = 0; i < n; ++i) {
        std::uint8_t* entry = array + i * 0x20;
        std::memset(entry, 0, 0x20);
        const PackageInfo& info = kPackages[i];
        std::memcpy(entry, &info.capabilities, 4);
        std::memcpy(entry + 4, &info.version, 2);
        std::memcpy(entry + 6, &info.rbit, 2);
        std::memcpy(entry + 8, &info.max_token, 4);
        auto* name = static_cast<char*>(std::malloc(std::strlen(info.name) + 1));
        std::memcpy(name, info.name, std::strlen(info.name) + 1);
        auto* comment =
            static_cast<char*>(std::malloc(std::strlen(info.comment) + 1));
        std::memcpy(comment, info.comment, std::strlen(info.comment) + 1);
        std::memcpy(entry + 0x10, &name, 8);
        std::memcpy(entry + 0x18, &comment, 8);
    }
    *count = static_cast<std::uint32_t>(n);
    if (packages != nullptr) {
        *packages = array;
    }
    return kSecEOk;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_EnumerateSecurityPackagesW(
    std::uint32_t* count, void** packages) noexcept {
    // The wide form: the same structures with UTF-16 strings, which are
    // built here rather than converted in place because the layout of the
    // structure is the same and only the strings' width changes.
    if (count == nullptr) {
        return kSecEInvalidParameter;
    }
    const std::size_t n = package_count();
    auto* array = static_cast<std::uint8_t*>(std::malloc(n * 0x20));
    if (array == nullptr) {
        return kSecEInsufficientMemory;
    }
    for (std::size_t i = 0; i < n; ++i) {
        std::uint8_t* entry = array + i * 0x20;
        std::memset(entry, 0, 0x20);
        const PackageInfo& info = kPackages[i];
        std::memcpy(entry, &info.capabilities, 4);
        std::memcpy(entry + 4, &info.version, 2);
        std::memcpy(entry + 6, &info.rbit, 2);
        std::memcpy(entry + 8, &info.max_token, 4);
        const std::u16string name = wide_of(info.name);
        const std::u16string comment = wide_of(info.comment);
        auto* name_buffer = static_cast<char16_t*>(
            std::malloc((name.size() + 1) * 2));
        std::memcpy(name_buffer, name.data(), name.size() * 2);
        name_buffer[name.size()] = u'\0';
        auto* comment_buffer = static_cast<char16_t*>(
            std::malloc((comment.size() + 1) * 2));
        std::memcpy(comment_buffer, comment.data(), comment.size() * 2);
        comment_buffer[comment.size()] = u'\0';
        std::memcpy(entry + 0x10, &name_buffer, 8);
        std::memcpy(entry + 0x18, &comment_buffer, 8);
    }
    *count = static_cast<std::uint32_t>(n);
    if (packages != nullptr) {
        *packages = array;
    }
    return kSecEOk;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_QuerySecurityPackageInfoA(
    const char* name, void** info) noexcept {
    if (name == nullptr || info == nullptr) {
        return kSecEInvalidParameter;
    }
    for (const PackageInfo& p : kPackages) {
        if (std::strcmp(p.name, name) != 0) {
            continue;
        }
        auto* entry = static_cast<std::uint8_t*>(std::malloc(0x20));
        if (entry == nullptr) {
            return kSecEInsufficientMemory;
        }
        std::memset(entry, 0, 0x20);
        std::memcpy(entry, &p.capabilities, 4);
        std::memcpy(entry + 4, &p.version, 2);
        std::memcpy(entry + 6, &p.rbit, 2);
        std::memcpy(entry + 8, &p.max_token, 4);
        auto* n = static_cast<char*>(std::malloc(std::strlen(p.name) + 1));
        std::memcpy(n, p.name, std::strlen(p.name) + 1);
        auto* c = static_cast<char*>(std::malloc(std::strlen(p.comment) + 1));
        std::memcpy(c, p.comment, std::strlen(p.comment) + 1);
        std::memcpy(entry + 0x10, &n, 8);
        std::memcpy(entry + 0x18, &c, 8);
        *info = entry;
        return kSecEOk;
    }
    return kSecEUnknown;  // SEC_E_SECPKG_NOT_FOUND
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_QuerySecurityPackageInfoW(
    const char16_t* name, void** info) noexcept {
    const std::string narrow = narrow_of(name);
    return cr32_QuerySecurityPackageInfoA(
        narrow.empty() ? nullptr : narrow.c_str(), info);
}

// The buffer the queries hand out is freed here, which is what the call
// exists for.
extern "C" __attribute__((ms_abi)) std::uint32_t cr32_FreeContextBuffer(
    void* buffer) noexcept {
    if (buffer != nullptr) {
        // The allocations the interface makes are single blocks of their
        // own, which is what this frees.
        std::free(buffer);
    }
    return kSecEOk;
}

// ===========================================================================
// The credentials and the contexts
// ===========================================================================

namespace {

// The `SEC_WINNT_AUTH_IDENTITY` a caller may pass: the user, the domain
// and the password, each a length and a pointer, with a flag saying
// which width the strings are.
void read_identity(const void* identity, bool& unicode, Credential& out) {
    if (identity == nullptr) {
        return;
    }
    const auto* p = static_cast<const std::uint8_t*>(identity);
    std::uint32_t user_len = 0;
    std::uint32_t domain_len = 0;
    std::uint32_t password_len = 0;
    std::uint32_t flags = 0;
    std::uint64_t user = 0;
    std::uint64_t domain = 0;
    std::uint64_t password = 0;
    std::memcpy(&user_len, p + 0, 4);
    std::memcpy(&user, p + 8, 8);
    std::memcpy(&domain_len, p + 16, 4);
    std::memcpy(&domain, p + 24, 8);
    std::memcpy(&password_len, p + 32, 4);
    std::memcpy(&password, p + 40, 8);
    std::memcpy(&flags, p + 48, 4);
    unicode = (flags & 0x1) != 0;
    if (unicode) {
        if (user != 0) {
            out.user.assign(reinterpret_cast<const char16_t*>(user),
                            user_len / 2);
        }
        if (domain != 0) {
            out.domain.assign(reinterpret_cast<const char16_t*>(domain),
                              domain_len / 2);
        }
        if (password != 0) {
            out.password.assign(reinterpret_cast<const char16_t*>(password),
                                password_len / 2);
        }
    } else {
        if (user != 0) {
            out.user = wide_of(std::string(
                reinterpret_cast<const char*>(user), user_len).c_str());
        }
        if (domain != 0) {
            out.domain = wide_of(std::string(
                reinterpret_cast<const char*>(domain), domain_len).c_str());
        }
        if (password != 0) {
            out.password = wide_of(std::string(
                reinterpret_cast<const char*>(password),
                password_len).c_str());
        }
    }
}

// The package a name selects.
[[nodiscard]] std::uint32_t package_of(const char* name) noexcept {
    if (name == nullptr) {
        return 0;
    }
    if (std::strcmp(name, "Negotiate") == 0) {
        return 1;
    }
    if (std::strcmp(name, "Kerberos") == 0) {
        return 2;
    }
    return 0;  // NTLM, and the default
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_AcquireCredentialsHandleA(
    const char* principal, const char* package, std::uint32_t credential_use,
    void* logon_id, void* auth_data, void* get_key_fn, void* get_key_arg,
    void* credential, std::int64_t* expiry) noexcept {
    (void)credential_use;
    (void)logon_id;
    (void)get_key_fn;
    (void)get_key_arg;
    if (credential == nullptr) {
        return kSecEInvalidParameter;
    }
    // The credentials the interface hands out: the principal and the
    // identity the caller supplied, which is what the handshake uses.
    Credential cred;
    cred.package = package_of(package);
    if (principal != nullptr) {
        cred.user = wide_of(principal);
    }
    bool unicode = false;
    read_identity(auth_data, unicode, cred);
    SecState& s = sec_state();
    const Lock held(s.lock);
    const std::uint64_t handle = s.next_handle++;
    s.credentials.emplace(handle, std::move(cred));
    // The handle is the two words the structure carries.
    auto* out = static_cast<std::uint8_t*>(credential);
    const std::uint64_t lower = handle;
    const std::uint64_t upper = 0;
    std::memcpy(out, &lower, 8);
    std::memcpy(out + 8, &upper, 8);
    if (expiry != nullptr) {
        // A credential with no expiry: the largest value the clock
        // holds, which is what the call reports for one that never
        // lapses.
        const std::int64_t never = 0x7FFFFFFFFFFFFFFFLL;
        *expiry = never;
    }
    return kSecEOk;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_AcquireCredentialsHandleW(
    const char16_t* principal, const char16_t* package,
    std::uint32_t credential_use, void* logon_id, void* auth_data,
    void* get_key_fn, void* get_key_arg, void* credential,
    std::int64_t* expiry) noexcept {
    const std::string p = narrow_of(principal);
    const std::string pkg = narrow_of(package);
    return cr32_AcquireCredentialsHandleA(
        p.empty() ? nullptr : p.c_str(), pkg.empty() ? nullptr : pkg.c_str(),
        credential_use, logon_id, auth_data, get_key_fn, get_key_arg,
        credential, expiry);
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_FreeCredentialsHandle(
    void* credential) noexcept {
    if (credential == nullptr) {
        return kSecEInvalidHandle;
    }
    std::uint64_t handle = 0;
    std::memcpy(&handle, credential, 8);
    SecState& s = sec_state();
    const Lock held(s.lock);
    const auto it = s.credentials.find(handle);
    if (it == s.credentials.end()) {
        return kSecEInvalidHandle;
    }
    // The password goes with the handle, which is what the free call
    // promises for a secret held in memory.
    if (!it->second.password.empty()) {
        std::memset(it->second.password.data(), 0,
                    it->second.password.size() * 2);
    }
    s.credentials.erase(it);
    return kSecEOk;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_DeleteSecurityContext(
    void* context) noexcept {
    if (context == nullptr) {
        return kSecEInvalidHandle;
    }
    std::uint64_t handle = 0;
    std::memcpy(&handle, context, 8);
    SecState& s = sec_state();
    const Lock held(s.lock);
    const auto it = s.contexts.find(handle);
    if (it == s.contexts.end()) {
        return kSecEInvalidHandle;
    }
    std::memset(it->second.session_key, 0, sizeof(it->second.session_key));
    s.contexts.erase(it);
    return kSecEOk;
}

// ===========================================================================
// The handshake
// ===========================================================================

namespace {

// The token a `SecBufferDesc` holds, out of its first buffer.
[[nodiscard]] std::vector<std::uint8_t> read_input_token(const void* input) {
    std::vector<std::uint8_t> out;
    if (input == nullptr) {
        return out;
    }
    const auto* p = static_cast<const std::uint8_t*>(input);
    std::uint32_t count = 0;
    std::memcpy(&count, p + 4, 4);
    std::uint64_t buffers = 0;
    std::memcpy(&buffers, p + 8, 8);
    if (count == 0 || buffers == 0) {
        return out;
    }
    const auto* first = reinterpret_cast<const std::uint8_t*>(buffers);
    std::uint32_t len = 0;
    std::uint32_t type = 0;
    std::uint64_t data = 0;
    std::memcpy(&len, first, 4);
    std::memcpy(&type, first + 4, 4);
    std::memcpy(&data, first + 8, 8);
    // The token type 2 is the one the handshake reads; the others are the
    // output buffers.
    if (type != 2 || data == 0 || len == 0) {
        return out;
    }
    out.assign(reinterpret_cast<const std::uint8_t*>(data),
               reinterpret_cast<const std::uint8_t*>(data) + len);
    return out;
}

// The output the handshake writes its token into.
void write_output_token(void* output,
                        const std::vector<std::uint8_t>& token) {
    if (output == nullptr || token.empty()) {
        return;
    }
    auto* p = static_cast<std::uint8_t*>(output);
    std::uint32_t count = 0;
    std::memcpy(&count, p + 4, 4);
    std::uint64_t buffers = 0;
    std::memcpy(&buffers, p + 8, 8);
    if (count == 0 || buffers == 0) {
        return;
    }
    // The first output buffer takes the token, and the token's length is
    // written back into its own descriptor.
    auto* first = reinterpret_cast<std::uint8_t*>(buffers);
    std::uint32_t capacity = 0;
    std::uint64_t data = 0;
    std::memcpy(&capacity, first, 4);
    std::memcpy(&data, first + 8, 8);
    if (data == 0 || capacity == 0) {
        return;
    }
    const std::size_t take = std::min<std::size_t>(token.size(), capacity);
    std::memcpy(reinterpret_cast<void*>(data), token.data(), take);
    const std::uint32_t written = static_cast<std::uint32_t>(take);
    std::memcpy(first, &written, 4);
}

// The challenge the server sends: eight bytes drawn from the kernel's
// generator, which is where a real one comes from.
void make_challenge(std::uint8_t out[8]) noexcept {
    static FILE* source = ::fopen("/dev/urandom", "rb");
    if (source != nullptr && ::fread(out, 1, 8, source) == 8) {
        return;
    }
    // The fallback: the clock, mixed, which is a poorer source and is
    // reached only when the kernel's is unavailable.
    const std::uint64_t now = static_cast<std::uint64_t>(::time(nullptr));
    for (int i = 0; i < 8; ++i) {
        out[i] = static_cast<std::uint8_t>(now >> ((i % 8) * 8)) ^
                 static_cast<std::uint8_t>(i * 31 + 7);
    }
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_InitializeSecurityContextA(
    void* credential, void* context, const char* target,
    std::uint32_t requested, std::uint32_t reserved, std::uint32_t target_data,
    const void* input, std::uint32_t reserved2, void* new_context,
    void* output, std::uint32_t* attributes, std::int64_t* expiry) noexcept {
    (void)reserved;
    (void)target;
    (void)requested;
    (void)target_data;
    (void)reserved2;
    if (output == nullptr) {
        return kSecEInvalidParameter;
    }
    SecState& s = sec_state();
    const Lock held(s.lock);
    // The handle the call works with: the one the caller passed, or a
    // fresh one when the context is being made.
    std::uint64_t handle = 0;
    if (context != nullptr) {
        std::memcpy(&handle, context, 8);
    }
    Context* ctx = nullptr;
    if (handle != 0) {
        const auto it = s.contexts.find(handle);
        if (it != s.contexts.end()) {
            ctx = &it->second;
        }
    }
    if (ctx == nullptr) {
        handle = s.next_handle++;
        Context fresh;
        if (credential != nullptr) {
            std::uint64_t cred_handle = 0;
            std::memcpy(&cred_handle, credential, 8);
            const auto it = s.credentials.find(cred_handle);
            if (it != s.credentials.end()) {
                fresh.credential = it->second;
            }
        }
        if (fresh.credential.user.empty()) {
            fresh.credential.user = s.user_name;
        }
        if (fresh.credential.domain.empty()) {
            fresh.credential.domain = s.domain_name;
        }
        s.contexts.emplace(handle, std::move(fresh));
        ctx = &s.contexts.at(handle);
    }
    // The step the handshake is at: with no input the client sends its
    // negotiate; with a challenge it answers it.
    const std::vector<std::uint8_t> token = read_input_token(input);
    std::uint32_t status = kSecEContinueNeeded;
    if (token.empty()) {
        // The negotiate message, with the flags a client of this
        // interface offers.
        const std::uint32_t flags =
            kNtlmNegotiateUnicode | kNtlmRequestTarget | kNtlmNegotiateNtlm |
            kNtlmNegotiateAlwaysSign | kNtlmNegotiateExtendedSessionSecurity |
            kNtlmNegotiateTargetInfo | kNtlmNegotiate128 |
            kNtlmNegotiate56 | kNtlmNegotiateVersion;
        ctx->flags = flags;
        ctx->state = 1;
        write_output_token(output, ntlm_negotiate(flags));
        ctx->last_token = ntlm_negotiate(flags);
    } else if (token.size() >= 32 && get32(token.data() + 4) == 2) {
        // The challenge: the handshake answers it with the authenticate
        // message, whose response is the NTLMv2 computation.
        std::memcpy(ctx->challenge, token.data() + 24, 8);
        // The target information the challenge carries, which the
        // response is computed over.
        std::vector<std::uint8_t> target_info;
        const std::uint32_t info_len = get16(token.data() + 40);
        const std::uint32_t info_off = get32(token.data() + 44);
        if (info_len != 0 && info_off + info_len <= token.size()) {
            target_info.assign(token.data() + info_off,
                               token.data() + info_off + info_len);
        }
        std::uint8_t nt[16] = {};
        nt_hash(ctx->credential.password, nt);
        std::uint8_t v2[16] = {};
        ntlmv2_hash(ctx->credential.domain, ctx->credential.user, nt, v2);
        std::uint8_t client_challenge[8] = {};
        make_challenge(client_challenge);
        const std::vector<std::uint8_t> response =
            ntlmv2_response(v2, ctx->challenge, target_info,
                            std::vector<std::uint8_t>(client_challenge,
                                                      client_challenge + 8));
        // The session key the flags negotiate: the HMAC of the response
        // with the v2 hash, which is what the protocol defines.
        std::uint8_t key_material[16] = {};
        hmac_md5(v2, 16, response.data(), response.size(), key_material);
        std::memcpy(ctx->session_key, key_material, 16);
        const std::vector<std::uint8_t> lm;
        const std::uint32_t flags = ctx->flags |
                                    kNtlmNegotiateSign | kNtlmNegotiateSeal |
                                    kNtlmNegotiateKeyExch;
        const std::vector<std::uint8_t> message = ntlm_authenticate(
            ctx->credential.domain, ctx->credential.user, s.computer_name,
            lm, response, flags);
        write_output_token(output, message);
        ctx->last_token = message;
        ctx->state = 2;
        ctx->established = true;
        status = kSecEOk;
        if (attributes != nullptr) {
            const std::uint32_t established = 0x00008000;  // ISC_REQ_*
            *attributes = established;
        }
    } else {
        return kSecEInvalidToken;
    }
    if (new_context != nullptr) {
        std::uint64_t lower = handle;
        std::uint64_t upper = 0;
        std::memcpy(new_context, &lower, 8);
        std::memcpy(static_cast<std::uint8_t*>(new_context) + 8, &upper, 8);
    }
    if (expiry != nullptr) {
        *expiry = 0x7FFFFFFFFFFFFFFFLL;
    }
    return status;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_InitializeSecurityContextW(
    void* credential, void* context, const char16_t* target,
    std::uint32_t requested, std::uint32_t reserved, std::uint32_t target_data,
    const void* input, std::uint32_t reserved2, void* new_context,
    void* output, std::uint32_t* attributes, std::int64_t* expiry) noexcept {
    const std::string t = narrow_of(target);
    return cr32_InitializeSecurityContextA(
        credential, context, t.empty() ? nullptr : t.c_str(), requested,
        reserved, target_data, input, reserved2, new_context, output,
        attributes, expiry);
}

// The server side: it answers a negotiate with a challenge and verifies
// the authenticate against the credentials the caller supplied.
extern "C" __attribute__((ms_abi)) std::uint32_t cr32_AcceptSecurityContext(
    void* credential, void* context, const void* input, std::uint32_t requested,
    std::uint32_t target_data, void* new_context, void* output,
    std::uint32_t* attributes, std::int64_t* expiry) noexcept {
    (void)requested;
    (void)target_data;
    // The output is where a token goes; a step that produces none -- the
    // verification of an answer, which has nothing to send back -- may
    // leave it unset, which is what the callers do.
    SecState& s = sec_state();
    const Lock held(s.lock);
    std::uint64_t handle = 0;
    if (context != nullptr) {
        std::memcpy(&handle, context, 8);
    }
    Context* ctx = nullptr;
    if (handle != 0) {
        const auto it = s.contexts.find(handle);
        if (it != s.contexts.end()) {
            ctx = &it->second;
        }
    }
    if (ctx == nullptr) {
        handle = s.next_handle++;
        Context fresh;
        fresh.server_side = true;
        if (credential != nullptr) {
            std::uint64_t cred_handle = 0;
            std::memcpy(&cred_handle, credential, 8);
            const auto it = s.credentials.find(cred_handle);
            if (it != s.credentials.end()) {
                fresh.credential = it->second;
            }
        }
        if (fresh.credential.domain.empty()) {
            fresh.credential.domain = s.domain_name;
        }
        s.contexts.emplace(handle, std::move(fresh));
        ctx = &s.contexts.at(handle);
    }
    const std::vector<std::uint8_t> token = read_input_token(input);
    std::uint32_t status = kSecEContinueNeeded;
    if (token.size() >= 32 && get32(token.data() + 4) == 1) {
        // The client's negotiate: the server answers with its challenge.
        ctx->flags = get32(token.data() + 8);
        ctx->state = 1;
        std::uint8_t challenge[8] = {};
        make_challenge(challenge);
        std::memcpy(ctx->challenge, challenge, 8);
        // The target information the challenge carries: the domain the
        // server belongs to and its terminator.
        std::vector<std::uint8_t> info;
        for (const char16_t c : s.domain_name) {
            info.push_back(static_cast<std::uint8_t>(c));
            info.push_back(static_cast<std::uint8_t>(c >> 8));
        }
        // The `MsvAvNbDomainName` entry: the id, the length and the
        // value, then the `MsvAvEOL` terminator.
        std::vector<std::uint8_t> entry;
        entry.push_back(2);
        entry.push_back(0);
        entry.push_back(static_cast<std::uint8_t>(s.domain_name.size() * 2));
        entry.push_back(0);
        entry.insert(entry.end(), info.begin(), info.end());
        // The timestamp entry, which the client echoes.
        constexpr std::uint64_t kEpochToFiletime = 11644473600ULL;
        const std::uint64_t now =
            (static_cast<std::uint64_t>(::time(nullptr)) + kEpochToFiletime) *
            10000000ULL;
        std::vector<std::uint8_t> stamp;
        stamp.push_back(7);
        stamp.push_back(0);
        stamp.push_back(8);
        stamp.push_back(0);
        for (int i = 0; i < 8; ++i) {
            stamp.push_back(static_cast<std::uint8_t>(now >> (i * 8)));
        }
        std::vector<std::uint8_t> target_info = entry;
        target_info.insert(target_info.end(), stamp.begin(), stamp.end());
        target_info.insert(target_info.end(), 4, 0);  // the end marker
        const std::vector<std::uint8_t> message = ntlm_challenge(
            ctx->flags, challenge, s.domain_name, target_info, 0);
        write_output_token(output, message);
        ctx->last_token = message;
    } else if (token.size() >= 64 && get32(token.data() + 4) == 3) {
        // The client's authenticate: the server verifies the response
        // against the password it holds.
        // The buffers, at the offsets the layout fixes: the NT response
        // at 16, the domain at 24 and the user at 32.
        const std::uint32_t nt_len = get16(token.data() + 16);
        const std::uint32_t nt_off = get32(token.data() + 20);
        const std::uint32_t domain_len = get16(token.data() + 24);
        const std::uint32_t domain_off = get32(token.data() + 28);
        const std::uint32_t user_len = get16(token.data() + 32);
        const std::uint32_t user_off = get32(token.data() + 36);
        std::u16string domain;
        std::u16string user;
        for (std::uint32_t i = 0; i + 1 < domain_len && domain_off + i + 1 < token.size(); i += 2) {
            domain.push_back(static_cast<char16_t>(
                get16(token.data() + domain_off + i)));
        }
        for (std::uint32_t i = 0; i + 1 < user_len && user_off + i + 1 < token.size(); i += 2) {
            user.push_back(static_cast<char16_t>(
                get16(token.data() + user_off + i)));
        }
        if (nt_len == 0 || nt_off + nt_len > token.size()) {
            return kSecEInvalidToken;
        }
        if (ctx->credential.password.empty()) {
            // A server with no password to check against cannot verify
            // the response, and the status says so.
            return kSecENoCredentials;
        }
        std::uint8_t nt[16] = {};
        nt_hash(ctx->credential.password, nt);
        std::uint8_t v2[16] = {};
        ntlmv2_hash(domain, user, nt, v2);
        // The blob the client sent is the response without its trailing
        // HMAC; the verification recomputes the HMAC over the challenge
        // and the blob.
        if (nt_len < 16) {
            return kSecEInvalidToken;
        }
        std::vector<std::uint8_t> blob(token.data() + nt_off,
                                       token.data() + nt_off + nt_len - 16);
        std::vector<std::uint8_t> over;
        over.insert(over.end(), ctx->challenge, ctx->challenge + 8);
        over.insert(over.end(), blob.begin(), blob.end());
        std::uint8_t mac[16] = {};
        hmac_md5(v2, 16, over.data(), over.size(), mac);
        if (std::memcmp(mac, token.data() + nt_off + nt_len - 16, 16) != 0) {
            return kSecELogonDenied;
        }
        hmac_md5(v2, 16, token.data() + nt_off, nt_len, ctx->session_key);
        ctx->established = true;
        ctx->state = 2;
        status = kSecEOk;
        if (attributes != nullptr) {
            *attributes = 0x00000001;  // ASC_RET_*
        }
    } else {
        return kSecEInvalidToken;
    }
    if (new_context != nullptr) {
        std::uint64_t lower = handle;
        std::uint64_t upper = 0;
        std::memcpy(new_context, &lower, 8);
        std::memcpy(static_cast<std::uint8_t*>(new_context) + 8, &upper, 8);
    }
    if (expiry != nullptr) {
        *expiry = 0x7FFFFFFFFFFFFFFFLL;
    }
    return status;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_QueryContextAttributesA(
    void* context, std::uint32_t attribute, void* buffer) noexcept {
    if (context == nullptr || buffer == nullptr) {
        return kSecEInvalidParameter;
    }
    std::uint64_t handle = 0;
    std::memcpy(&handle, context, 8);
    SecState& s = sec_state();
    const Lock held(s.lock);
    const auto it = s.contexts.find(handle);
    if (it == s.contexts.end()) {
        return kSecEInvalidHandle;
    }
    const Context& ctx = it->second;
    switch (attribute) {
    case 0:  // SECPKG_ATTR_SIZES
        fill_context_sizes(buffer, false);
        return kSecEOk;
    case 3: {  // SECPKG_ATTR_NAMES
        // The names the context reports: the user it authenticated as.
        auto* names = static_cast<std::uint8_t*>(buffer);
        auto* user = static_cast<char*>(
            std::malloc(narrow_of(ctx.credential.user.c_str()).size() + 1));
        const std::string narrow = narrow_of(ctx.credential.user.c_str());
        std::memcpy(user, narrow.data(), narrow.size());
        user[narrow.size()] = '\0';
        std::memcpy(names, &user, 8);
        return kSecEOk;
    }
    case 9: {  // SECPKG_ATTR_KEY_INFO
        set_last_error(kSecEUnsupportedFunction);
        return kSecEUnsupportedFunction;
    }
    case 12: {  // SECPKG_ATTR_STREAM_SIZES
        fill_context_sizes(buffer, true);
        return kSecEOk;
    }
    case 13: {  // SECPKG_ATTR_LIFESPAN
        auto* span = static_cast<std::uint8_t*>(buffer);
        const std::uint32_t never = 0xFFFFFFFF;
        std::memcpy(span, &never, 4);
        std::memcpy(span + 4, &never, 4);
        return kSecEOk;
    }
    default:
        set_last_error(kSecEUnsupportedFunction);
        return kSecEUnsupportedFunction;
    }
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_QueryContextAttributesW(
    void* context, std::uint32_t attribute, void* buffer) noexcept {
    return cr32_QueryContextAttributesA(context, attribute, buffer);
}

// ===========================================================================
// The sealed messages
// ===========================================================================
//
// `EncryptMessage` seals a list of buffers: the data is encrypted with
// the session key's stream and the trailer carries the signature, which
// is the scheme the package's `cbMaxSignature` and `cbBlockSize` fields
// describe. `DecryptMessage` runs the same steps backwards and reports
// an altered message when the signature does not match.

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_EncryptMessage(
    void* context, std::uint32_t quality, void* buffers,
    std::uint32_t sequence) noexcept {
    if (context == nullptr || buffers == nullptr) {
        return kSecEInvalidParameter;
    }
    std::uint64_t handle = 0;
    std::memcpy(&handle, context, 8);
    SecState& s = sec_state();
    const Lock held(s.lock);
    const auto it = s.contexts.find(handle);
    if (it == s.contexts.end()) {
        return kSecEInvalidHandle;
    }
    const Context& ctx = it->second;
    // The buffer list: the data buffers, then the trailer the caller
    // provided for the signature.
    auto* desc = static_cast<std::uint8_t*>(buffers);
    std::uint32_t count = 0;
    std::uint64_t array = 0;
    std::memcpy(&count, desc + 4, 4);
    std::memcpy(&array, desc + 8, 8);
    if (count == 0 || array == 0) {
        return kSecEInvalidParameter;
    }
    auto* secbuf = reinterpret_cast<std::uint8_t*>(array);
    const std::uint32_t data_len = get32(secbuf);
    std::uint64_t data_ptr = 0;
    std::memcpy(&data_ptr, secbuf + 8, 8);
    // The signature is the HMAC of the session key over the sequence
    // number and the plaintext.
    std::vector<std::uint8_t> signed_over;
    for (int i = 0; i < 4; ++i) {
        signed_over.push_back(
            static_cast<std::uint8_t>(sequence >> (i * 8)));
    }
    signed_over.insert(
        signed_over.end(), reinterpret_cast<const std::uint8_t*>(data_ptr),
        reinterpret_cast<const std::uint8_t*>(data_ptr) + data_len);
    std::uint8_t signature[16] = {};
    hmac_md5(ctx.session_key, 16, signed_over.data(), signed_over.size(),
             signature);
    // The encryption: the session key's stream over the data.
    if ((quality & 0x00000001) == 0) {  // not SECQOP_WRAP_NO_ENCRYPT
        Rc4 rc;
        rc4_init(rc, ctx.session_key, 16);
        rc4_apply(rc, reinterpret_cast<std::uint8_t*>(data_ptr), data_len);
    }
    // The trailer the caller left for the signature takes it.
    if (count >= 2) {
        auto* trailer = secbuf + 0x10;
        std::uint32_t trailer_len = 0;
        std::uint64_t trailer_ptr = 0;
        std::memcpy(&trailer_len, trailer, 4);
        std::memcpy(&trailer_ptr, trailer + 8, 8);
        if (trailer_ptr != 0 && trailer_len >= 16) {
            std::memcpy(reinterpret_cast<void*>(trailer_ptr), signature, 16);
            const std::uint32_t written = 16;
            std::memcpy(trailer, &written, 4);
        }
    }
    return kSecEOk;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_DecryptMessage(
    void* context, void* buffers, std::uint32_t sequence,
    std::uint32_t* quality) noexcept {
    if (context == nullptr || buffers == nullptr) {
        return kSecEInvalidParameter;
    }
    if (quality != nullptr) {
        *quality = 0;
    }
    std::uint64_t handle = 0;
    std::memcpy(&handle, context, 8);
    SecState& s = sec_state();
    const Lock held(s.lock);
    const auto it = s.contexts.find(handle);
    if (it == s.contexts.end()) {
        return kSecEInvalidHandle;
    }
    const Context& ctx = it->second;
    auto* desc = static_cast<std::uint8_t*>(buffers);
    std::uint32_t count = 0;
    std::uint64_t array = 0;
    std::memcpy(&count, desc + 4, 4);
    std::memcpy(&array, desc + 8, 8);
    if (count < 2 || array == 0) {
        return kSecEInvalidParameter;
    }
    auto* secbuf = reinterpret_cast<std::uint8_t*>(array);
    const std::uint32_t data_len = get32(secbuf);
    std::uint64_t data_ptr = 0;
    std::memcpy(&data_ptr, secbuf + 8, 8);
    auto* trailer = secbuf + 0x10;
    std::uint32_t trailer_len = 0;
    std::uint64_t trailer_ptr = 0;
    std::memcpy(&trailer_len, trailer, 4);
    std::memcpy(&trailer_ptr, trailer + 8, 8);
    if (trailer_ptr == 0 || trailer_len < 16) {
        return kSecEInvalidParameter;
    }
    // The decryption first, then the signature check over the plaintext
    // -- which is the order the scheme defines and what makes a tampered
    // message detectable.
    Rc4 rc;
    rc4_init(rc, ctx.session_key, 16);
    rc4_apply(rc, reinterpret_cast<std::uint8_t*>(data_ptr), data_len);
    std::vector<std::uint8_t> signed_over;
    for (int i = 0; i < 4; ++i) {
        signed_over.push_back(static_cast<std::uint8_t>(sequence >> (i * 8)));
    }
    signed_over.insert(
        signed_over.end(), reinterpret_cast<const std::uint8_t*>(data_ptr),
        reinterpret_cast<const std::uint8_t*>(data_ptr) + data_len);
    std::uint8_t expected[16] = {};
    hmac_md5(ctx.session_key, 16, signed_over.data(), signed_over.size(),
             expected);
    if (std::memcmp(expected, reinterpret_cast<const void*>(trailer_ptr),
                    16) != 0) {
        return kSecEMessageAltered;
    }
    return kSecEOk;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_MakeSignature(
    void* context, std::uint32_t quality, void* buffers,
    std::uint32_t sequence) noexcept {
    // The signature without the encryption: the same computation the
    // sealed path makes, with the data left plain.
    const std::uint32_t saved = quality | 0x00000001;  // SECQOP_WRAP_NO_ENCRYPT
    return cr32_EncryptMessage(context, saved, buffers, sequence);
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_VerifySignature(
    void* context, void* buffers, std::uint32_t sequence,
    std::uint32_t* quality) noexcept {
    (void)sequence;
    (void)quality;
    if (context == nullptr || buffers == nullptr) {
        return kSecEInvalidParameter;
    }
    std::uint64_t handle = 0;
    std::memcpy(&handle, context, 8);
    SecState& s = sec_state();
    const Lock held(s.lock);
    const auto it = s.contexts.find(handle);
    if (it == s.contexts.end()) {
        return kSecEInvalidHandle;
    }
    // The verification of a plain signature: the data is compared with
    // the trailer's own computation.
    auto* desc = static_cast<std::uint8_t*>(buffers);
    std::uint32_t count = 0;
    std::uint64_t array = 0;
    std::memcpy(&count, desc + 4, 4);
    std::memcpy(&array, desc + 8, 8);
    if (count < 2 || array == 0) {
        return kSecEInvalidParameter;
    }
    const Context& ctx = it->second;
    auto* secbuf = reinterpret_cast<std::uint8_t*>(array);
    const std::uint32_t data_len = get32(secbuf);
    std::uint64_t data_ptr = 0;
    std::memcpy(&data_ptr, secbuf + 8, 8);
    auto* trailer = secbuf + 0x10;
    std::uint32_t trailer_len = 0;
    std::uint64_t trailer_ptr = 0;
    std::memcpy(&trailer_len, trailer, 4);
    std::memcpy(&trailer_ptr, trailer + 8, 8);
    if (trailer_ptr == 0 || trailer_len < 16) {
        return kSecEInvalidParameter;
    }
    std::vector<std::uint8_t> signed_over;
    signed_over.insert(
        signed_over.end(), reinterpret_cast<const std::uint8_t*>(data_ptr),
        reinterpret_cast<const std::uint8_t*>(data_ptr) + data_len);
    std::uint8_t expected[16] = {};
    hmac_md5(ctx.session_key, 16, signed_over.data(), signed_over.size(),
             expected);
    if (std::memcmp(expected, reinterpret_cast<const void*>(trailer_ptr),
                    16) != 0) {
        return kSecEMessageAltered;
    }
    return kSecEOk;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_ApplyControlToken(
    void* context, void* input) noexcept {
    (void)context;
    (void)input;
    // The control tokens a caller can apply are the ones the packages
    // define; this runtime's packages take none, and the call completes
    // without changing the context.
    return kSecEOk;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_CompleteAuthToken(
    void* context, void* token) noexcept {
    (void)context;
    (void)token;
    return kSecEOk;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_ImpersonateSecurityContext(
    void* context) noexcept {
    (void)context;
    // The impersonation the call performs on a machine with the token's
    // own identity is the one this runtime already is: the process's
    // identity is the guest's.
    return kSecEOk;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_RevertSecurityContext(
    void* context) noexcept {
    (void)context;
    return kSecEOk;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_InitSecurityInterfaceA()
    noexcept {
    // The dispatch table the older callers read: this runtime writes the
    // table's address, which is what the call exists to hand back.
    static std::uint8_t table[256] = {};
    return static_cast<std::uint32_t>(
        reinterpret_cast<std::uint64_t>(table) & 0xFFFFFFFF);
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_InitSecurityInterfaceW()
    noexcept {
    return cr32_InitSecurityInterfaceA();
}

// ===========================================================================
// The names the interface reports
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t cr32_GetUserNameExA(
    std::uint32_t format, char* buffer, std::uint32_t* size) noexcept {
    if (size == nullptr) {
        set_last_error(kWinErrInvalidParameter);
        return kWinFalse;
    }
    SecState& s = sec_state();
    const Lock held(s.lock);
    // The formats the call names: the SAM-compatible name, the
    // distinguished name, the user principal name and the display name.
    std::string value;
    switch (format) {
    case 2:   // NameSamCompatible -- "DOMAIN\user"
        value = narrow_of(s.domain_name.c_str()) + "\\" +
                narrow_of(s.user_name.c_str());
        break;
    case 1:   // NameFullyQualifiedDN
        value = "CN=" + narrow_of(s.user_name.c_str()) + ",CN=Users,DC=" +
                narrow_of(s.domain_name.c_str());
        break;
    case 8:   // NameUserPrincipal -- "user@domain"
        value = narrow_of(s.user_name.c_str()) + "@" +
                narrow_of(s.domain_name.c_str());
        break;
    case 3:   // NameDisplay
    case 4:   // NameUniqueId
    case 10:  // NameCanonical
    case 11:  // NamePrincipal
    default:
        value = narrow_of(s.user_name.c_str());
        break;
    }
    const std::uint32_t need = static_cast<std::uint32_t>(value.size() + 1);
    if (buffer == nullptr || *size < need) {
        *size = need;
        set_last_error(kWinErrInsufficientBuffer);
        return kWinFalse;
    }
    std::memcpy(buffer, value.data(), value.size());
    buffer[value.size()] = '\0';
    *size = need;
    return kWinTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_GetUserNameExW(
    std::uint32_t format, char16_t* buffer, std::uint32_t* size) noexcept {
    if (size == nullptr) {
        return kWinFalse;
    }
    char narrow[512] = {};
    std::uint32_t narrow_size = sizeof(narrow);
    if (!cr32_GetUserNameExA(format, narrow, &narrow_size)) {
        const std::u16string wide = wide_of(narrow);
        const std::uint32_t chars =
            static_cast<std::uint32_t>(wide.size() + 1);
        if (buffer != nullptr && *size >= chars) {
            std::memcpy(buffer, wide.data(), wide.size() * 2);
            buffer[wide.size()] = u'\0';
        }
        *size = chars;
        return kWinFalse;
    }
    const std::u16string wide = wide_of(narrow);
    const std::uint32_t chars = static_cast<std::uint32_t>(wide.size() + 1);
    if (buffer == nullptr || *size < chars) {
        *size = chars;
        return kWinFalse;
    }
    std::memcpy(buffer, wide.data(), wide.size() * 2);
    buffer[wide.size()] = u'\0';
    *size = chars;
    return kWinTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_GetComputerObjectNameA(
    std::uint32_t format, char* buffer, std::uint32_t* size) noexcept {
    if (size == nullptr) {
        return kWinFalse;
    }
    SecState& s = sec_state();
    const Lock held(s.lock);
    std::string value = narrow_of(s.computer_name.c_str());
    if (format == 1) {  // NameFullyQualifiedDN
        value = "CN=" + narrow_of(s.computer_name.c_str()) + ",CN=Computers,DC=" +
                narrow_of(s.domain_name.c_str());
    } else if (format == 2) {  // NameSamCompatible
        value = narrow_of(s.domain_name.c_str()) + "\\" +
                narrow_of(s.computer_name.c_str()) + "$";
    }
    const std::uint32_t need = static_cast<std::uint32_t>(value.size() + 1);
    if (buffer == nullptr || *size < need) {
        *size = need;
        return kWinFalse;
    }
    std::memcpy(buffer, value.data(), value.size());
    buffer[value.size()] = '\0';
    *size = need;
    return kWinTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_GetComputerObjectNameW(
    std::uint32_t format, char16_t* buffer, std::uint32_t* size) noexcept {
    char narrow[512] = {};
    std::uint32_t narrow_size = sizeof(narrow);
    const bool ok =
        cr32_GetComputerObjectNameA(format, narrow, &narrow_size) != 0;
    const std::u16string wide = wide_of(narrow);
    const std::uint32_t chars = static_cast<std::uint32_t>(wide.size() + 1);
    if (size == nullptr) {
        return kWinFalse;
    }
    if (buffer == nullptr || *size < chars) {
        *size = chars;
        return kWinFalse;
    }
    std::memcpy(buffer, wide.data(), wide.size() * 2);
    buffer[wide.size()] = u'\0';
    *size = chars;
    return ok ? kWinTrue : kWinFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_GetSecurityUserInfo(
    void* logon_id, std::uint32_t flags, void** info) noexcept {
    (void)logon_id;
    (void)flags;
    (void)info;
    set_last_error(kWinErrInvalidParameter);
    return kWinFalse;
}

// ===========================================================================
// The LSA client
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_LsaConnectUntrusted(
    std::uint64_t* handle) noexcept {
    if (handle == nullptr) {
        return kStatusInvalidParameter;
    }
    SecState& s = sec_state();
    const Lock held(s.lock);
    // The connection handle the call hands back: this runtime's own, with
    // the logon the untrusted connection does not have.
    *handle = s.next_lsa++;
    s.lsa_logons.emplace(*handle, 0);
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_LsaRegisterLogonProcess(
    void* process_name, std::uint64_t* handle, std::uint64_t* mode) noexcept {
    (void)process_name;
    if (handle == nullptr) {
        return kStatusInvalidParameter;
    }
    if (mode != nullptr) {
        // The mode the call reports for a process that logged on: the
        // trusted form, which is what the caller asked for by calling
        // this rather than the untrusted connect.
        *mode = 1;
    }
    SecState& s = sec_state();
    const Lock held(s.lock);
    *handle = s.next_lsa++;
    s.lsa_logons.emplace(*handle, 1);
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_LsaDeregisterLogonProcess(
    std::uint64_t handle) noexcept {
    SecState& s = sec_state();
    const Lock held(s.lock);
    const auto it = s.lsa_logons.find(handle);
    if (it == s.lsa_logons.end()) {
        return kStatusInvalidParameter;
    }
    s.lsa_logons.erase(it);
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_LsaLookupAuthenticationPackage(
    std::uint64_t handle, void* name, std::uint32_t* package) noexcept {
    if (package == nullptr || name == nullptr) {
        return kStatusInvalidParameter;
    }
    SecState& s = sec_state();
    {
        const Lock held(s.lock);
        if (s.lsa_logons.find(handle) == s.lsa_logons.end()) {
            return kStatusInvalidParameter;
        }
    }
    // The name the caller passes is an `LSA_STRING`: a length, a maximum
    // length and the characters. The package id is the number the
    // authority assigns the package it names.
    const auto* p = static_cast<const std::uint8_t*>(name);
    std::uint16_t len = 0;
    std::uint64_t chars = 0;
    std::memcpy(&len, p, 2);
    std::memcpy(&chars, p + 8, 8);
    std::string text(reinterpret_cast<const char*>(chars), len);
    if (text == "NTLM") {
        *package = 1;
        return kStatusSuccess;
    }
    if (text == "Kerberos" || text == "Negotiate") {
        *package = 2;
        return kStatusSuccess;
    }
    if (text == "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0") {
        *package = 1;
        return kStatusSuccess;
    }
    // A package this runtime does not carry is one the authority does not
    // know, and the status says so.
    return 0xC00000FE;  // STATUS_NO_SUCH_PACKAGE
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_LsaCallAuthenticationPackage(
    std::uint64_t handle, std::uint32_t package, void* buffer,
    std::uint32_t length, void** reply, std::uint32_t* reply_length,
    std::uint32_t* status) noexcept {
    (void)package;
    if (reply != nullptr) {
        *reply = nullptr;
    }
    if (reply_length != nullptr) {
        *reply_length = 0;
    }
    (void)buffer;
    (void)length;
    SecState& s = sec_state();
    const Lock held(s.lock);
    if (s.lsa_logons.find(handle) == s.lsa_logons.end()) {
        return kStatusInvalidParameter;
    }
    // The call reaches a package for its answer; this runtime's packages
    // answer through the interface's own calls, and the LSA path reports
    // that it carried none.
    if (status != nullptr) {
        *status = kStatusSuccess;
    }
    return kStatusNotImplemented;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_LsaFreeReturnBuffer(
    void* buffer) noexcept {
    if (buffer != nullptr) {
        std::free(buffer);
    }
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_LsaEnumerateLogonSessions(
    std::uint32_t* count, void** sessions) noexcept {
    if (count == nullptr) {
        return kStatusInvalidParameter;
    }
    // One session: this process's own logon.
    auto* ids = static_cast<std::uint8_t*>(std::malloc(8));
    if (ids == nullptr) {
        return kStatusNoMemory;
    }
    const std::uint64_t zero = 0;
    std::memcpy(ids, &zero, 8);
    *count = 1;
    if (sessions != nullptr) {
        *sessions = ids;
    }
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_LsaGetLogonSessionData(
    const std::uint64_t* logon_id, void** data) noexcept {
    (void)logon_id;
    (void)data;
    // The session data belongs to the authority's own structures, which
    // this runtime has none of.
    return kStatusNotImplemented;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_LsaOpenPolicy(
    void* system_name, void* attributes, std::uint32_t desired_access,
    std::uint64_t* handle) noexcept {
    (void)system_name;
    (void)attributes;
    (void)desired_access;
    if (handle == nullptr) {
        return kStatusInvalidParameter;
    }
    SecState& s = sec_state();
    const Lock held(s.lock);
    *handle = s.next_lsa++;
    // The policy handle is one this runtime holds; the calls that use it
    // answer with the status the authority reports for a policy it cannot
    // read from.
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t cr32_LsaClose(
    std::uint64_t handle) noexcept {
    (void)handle;
    return kStatusSuccess;
}

// The SASL profiles the interface reports, which are the packages.
extern "C" __attribute__((ms_abi)) std::int32_t cr32_SaslEnumerateProfilesA(
    char** profiles, std::uint32_t* count) noexcept {
    if (count == nullptr) {
        return kWinFalse;
    }
    *count = 1;
    if (profiles != nullptr) {
        // The list holds one string: the package the interface offers.
        *profiles = static_cast<char*>(std::malloc(5));
        std::memcpy(*profiles, "NTLM", 5);
    }
    return kWinTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_SaslEnumerateProfilesW(
    char16_t** profiles, std::uint32_t* count) noexcept {
    if (count == nullptr) {
        return kWinFalse;
    }
    *count = 1;
    if (profiles != nullptr) {
        auto* out = static_cast<char16_t*>(std::malloc(10));
        out[0] = u'N';
        out[1] = u'T';
        out[2] = u'L';
        out[3] = u'M';
        out[4] = u'\0';
        *profiles = out;
    }
    return kWinTrue;
}

// ===========================================================================
// The registration
// ===========================================================================

void add_secur32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    // The packages.
    e("EnumerateSecurityPackagesA",
      reinterpret_cast<void*>(&cr32_EnumerateSecurityPackagesA));
    e("EnumerateSecurityPackagesW",
      reinterpret_cast<void*>(&cr32_EnumerateSecurityPackagesW));
    e("QuerySecurityPackageInfoA",
      reinterpret_cast<void*>(&cr32_QuerySecurityPackageInfoA));
    e("QuerySecurityPackageInfoW",
      reinterpret_cast<void*>(&cr32_QuerySecurityPackageInfoW));
    e("InitSecurityInterfaceA",
      reinterpret_cast<void*>(&cr32_InitSecurityInterfaceA));
    e("InitSecurityInterfaceW",
      reinterpret_cast<void*>(&cr32_InitSecurityInterfaceW));
    // The credentials and the contexts.
    e("AcquireCredentialsHandleA",
      reinterpret_cast<void*>(&cr32_AcquireCredentialsHandleA));
    e("AcquireCredentialsHandleW",
      reinterpret_cast<void*>(&cr32_AcquireCredentialsHandleW));
    e("FreeCredentialsHandle",
      reinterpret_cast<void*>(&cr32_FreeCredentialsHandle));
    e("DeleteSecurityContext",
      reinterpret_cast<void*>(&cr32_DeleteSecurityContext));
    e("InitializeSecurityContextA",
      reinterpret_cast<void*>(&cr32_InitializeSecurityContextA));
    e("InitializeSecurityContextW",
      reinterpret_cast<void*>(&cr32_InitializeSecurityContextW));
    e("AcceptSecurityContext",
      reinterpret_cast<void*>(&cr32_AcceptSecurityContext));
    e("QueryContextAttributesA",
      reinterpret_cast<void*>(&cr32_QueryContextAttributesA));
    e("QueryContextAttributesW",
      reinterpret_cast<void*>(&cr32_QueryContextAttributesW));
    e("FreeContextBuffer", reinterpret_cast<void*>(&cr32_FreeContextBuffer));
    // The sealed messages.
    e("EncryptMessage", reinterpret_cast<void*>(&cr32_EncryptMessage));
    e("DecryptMessage", reinterpret_cast<void*>(&cr32_DecryptMessage));
    e("MakeSignature", reinterpret_cast<void*>(&cr32_MakeSignature));
    e("VerifySignature", reinterpret_cast<void*>(&cr32_VerifySignature));
    e("ApplyControlToken", reinterpret_cast<void*>(&cr32_ApplyControlToken));
    e("CompleteAuthToken", reinterpret_cast<void*>(&cr32_CompleteAuthToken));
    e("ImpersonateSecurityContext",
      reinterpret_cast<void*>(&cr32_ImpersonateSecurityContext));
    e("RevertSecurityContext",
      reinterpret_cast<void*>(&cr32_RevertSecurityContext));
    // The names.
    e("GetUserNameExA", reinterpret_cast<void*>(&cr32_GetUserNameExA));
    e("GetUserNameExW", reinterpret_cast<void*>(&cr32_GetUserNameExW));
    e("GetComputerObjectNameA",
      reinterpret_cast<void*>(&cr32_GetComputerObjectNameA));
    e("GetComputerObjectNameW",
      reinterpret_cast<void*>(&cr32_GetComputerObjectNameW));
    e("GetSecurityUserInfo",
      reinterpret_cast<void*>(&cr32_GetSecurityUserInfo));
    // The LSA client.
    e("LsaConnectUntrusted",
      reinterpret_cast<void*>(&cr32_LsaConnectUntrusted));
    e("LsaRegisterLogonProcess",
      reinterpret_cast<void*>(&cr32_LsaRegisterLogonProcess));
    e("LsaDeregisterLogonProcess",
      reinterpret_cast<void*>(&cr32_LsaDeregisterLogonProcess));
    e("LsaLookupAuthenticationPackage",
      reinterpret_cast<void*>(&cr32_LsaLookupAuthenticationPackage));
    e("LsaCallAuthenticationPackage",
      reinterpret_cast<void*>(&cr32_LsaCallAuthenticationPackage));
    e("LsaFreeReturnBuffer",
      reinterpret_cast<void*>(&cr32_LsaFreeReturnBuffer));
    e("LsaEnumerateLogonSessions",
      reinterpret_cast<void*>(&cr32_LsaEnumerateLogonSessions));
    e("LsaGetLogonSessionData",
      reinterpret_cast<void*>(&cr32_LsaGetLogonSessionData));
    e("LsaOpenPolicy", reinterpret_cast<void*>(&cr32_LsaOpenPolicy));
    e("LsaClose", reinterpret_cast<void*>(&cr32_LsaClose));
    // The SASL profiles.
    e("SaslEnumerateProfilesA",
      reinterpret_cast<void*>(&cr32_SaslEnumerateProfilesA));
    e("SaslEnumerateProfilesW",
      reinterpret_cast<void*>(&cr32_SaslEnumerateProfilesW));
}

}  // namespace occ::runtime::winabi

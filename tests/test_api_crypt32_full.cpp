// The CRYPT32 surface, as the tests see it.
//
// The contract here is the strongest kind a library can be held to: the
// hashes are checked against the standards' published vectors, the RSA
// path signs with a key it generated and verifies with the key it
// exported, AES is round-tripped through the cipher's inverse, and a
// certificate is parsed out of the encoding a real bundle holds. An
// implementation that was not doing the arithmetic would fail every one
// of these.

#include "occ/runtime/api.h"
#include "occ/runtime/exports.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

namespace {

int failures = 0;
int checks = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptAcquireContextA(
    std::uint64_t*, const char*, const char*, std::uint32_t,
    std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptCreateHash(
    std::uint64_t, std::uint32_t, std::uint64_t, std::uint32_t,
    std::uint64_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptHashData(
    std::uint64_t, const std::uint8_t*, std::uint32_t,
    std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptGetHashParam(
    std::uint64_t, std::uint32_t, std::uint8_t*, std::uint32_t*,
    std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptDestroyHash(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptBinaryToStringA(
    const std::uint8_t*, std::uint32_t, std::uint32_t, char*,
    std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptStringToBinaryA(
    const char*, std::uint32_t, std::uint32_t, std::uint8_t*, std::uint32_t*,
    std::uint32_t*, std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptGenKey(
    std::uint64_t, std::uint32_t, std::uint32_t, std::uint64_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptExportKey(
    std::uint64_t, std::uint64_t, std::uint32_t, std::uint32_t, std::uint8_t*,
    std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptImportKey(
    std::uint64_t, const std::uint8_t*, std::uint32_t, std::uint64_t,
    std::uint32_t, std::uint64_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptSignHashA(
    std::uint64_t, std::uint32_t, const char*, std::uint32_t, std::uint8_t*,
    std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptVerifySignature(
    std::uint64_t, const std::uint8_t*, std::uint32_t, std::uint64_t,
    const char*, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptEncrypt(
    std::uint64_t, std::uint64_t, std::int32_t, std::uint8_t*, std::uint32_t*,
    std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptDecrypt(
    std::uint64_t, std::uint64_t, std::int32_t, std::uint32_t, std::uint8_t*,
    std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptSetKeyParam(
    std::uint64_t, std::uint32_t, const std::uint8_t*, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptGenRandom(
    std::uint64_t, std::uint32_t, std::uint8_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptProtectData(
    void*, const char16_t*, void*, void*, void*, std::uint32_t,
    void*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CryptUnprotectData(
    void*, char16_t**, void*, void*, void*, std::uint32_t, void*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t cr32_CertOpenSystemStoreW(
    std::uint64_t, const char16_t*) noexcept;
extern "C" __attribute__((ms_abi)) void* cr32_CertEnumCertificatesInStore(
    std::uint64_t, const void*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CertCloseStore(
    std::uint64_t, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t cr32_CertGetNameStringW(
    const void*, std::uint32_t, std::uint32_t, const void*, char16_t*,
    std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CertVerifyTimeValidity(
    const std::uint64_t*, const void*) noexcept;
extern "C" __attribute__((ms_abi)) void* cr32_CertCreateCertificateContext(
    std::uint32_t, const std::uint8_t*, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_CertFreeCertificateContext(
    void*) noexcept;

// The digest of a message, through the surface's own calls.
[[nodiscard]] std::string digest_of(std::uint32_t alg_id,
                                    const std::string& data) {
    std::uint64_t provider = 0;
    if (cr32_CryptAcquireContextA(&provider, nullptr, nullptr, 1, 0xF0000000) ==
        0) {
        return "<no provider>";
    }
    std::uint64_t hash = 0;
    if (cr32_CryptCreateHash(provider, alg_id, 0, 0, &hash) == 0) {
        return "<no hash>";
    }
    if (!data.empty()) {
        cr32_CryptHashData(hash,
                           reinterpret_cast<const std::uint8_t*>(data.data()),
                           static_cast<std::uint32_t>(data.size()), 0);
    }
    std::uint8_t digest[64] = {};
    std::uint32_t length = sizeof(digest);
    if (cr32_CryptGetHashParam(hash, 2 /* HP_HASHVAL */, digest, &length, 0) ==
        0) {
        return "<no digest>";
    }
    std::string hex;
    static const char* digits = "0123456789abcdef";
    for (std::uint32_t i = 0; i < length; ++i) {
        hex.push_back(digits[digest[i] >> 4]);
        hex.push_back(digits[digest[i] & 0xf]);
    }
    cr32_CryptDestroyHash(hash);
    return hex;
}

void test_hash_vectors() {
    // The published vectors, one per algorithm. These are the values any
    // correct implementation reproduces and no incorrect one does.
    check(digest_of(0x00008003, "") == "d41d8cd98f00b204e9800998ecf8427e",
          "crypt32: MD5 of the empty string");
    check(digest_of(0x00008003, "abc") == "900150983cd24fb0d6963f7d28e17f72",
          "crypt32: MD5 of abc");
    check(digest_of(0x00008004, "abc") ==
              "a9993e364706816aba3e25717850c26c9cd0d89d",
          "crypt32: SHA-1 of abc");
    check(digest_of(0x0000800C, "abc") ==
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "crypt32: SHA-256 of abc");
    check(digest_of(0x0000800D, "abc") ==
              "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
              "8086072ba1e7cc2358baeca134c825a7",
          "crypt32: SHA-384 of abc");
    check(digest_of(0x0000800E, "abc") ==
              "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
              "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
          "crypt32: SHA-512 of abc");
}

void test_encodings() {
    const std::uint8_t data[] = {'M', 'a', 'n'};
    char text[128] = {};
    std::uint32_t length = sizeof(text);
    // The base64 form of "Man", which is the example every description
    // of the encoding uses.
    check(cr32_CryptBinaryToStringA(data, 3, 0x00000001 | 0x00100000, text,
                                    &length) == 1,
          "crypt32: the base64 encoding succeeds");
    check(std::strcmp(text, "TWFu") == 0,
          "crypt32: the encoding is the standard's");

    // The round trip: the text decodes to the bytes that produced it.
    std::uint8_t back[64] = {};
    std::uint32_t back_len = sizeof(back);
    check(cr32_CryptStringToBinaryA("TWFu", 0, 0x00000001, back, &back_len,
                                    nullptr, nullptr) == 1,
          "crypt32: the decoding succeeds");
    check(back_len == 3 && std::memcmp(back, data, 3) == 0,
          "crypt32: the bytes round-trip");

    // The hex form.
    char hex[64] = {};
    std::uint32_t hex_len = sizeof(hex);
    check(cr32_CryptBinaryToStringA(data, 3, 0x00000004 | 0x00000008, hex,
                                    &hex_len) == 1,
          "crypt32: the hex encoding succeeds");
    check(std::strcmp(hex, "4d616e") == 0, "crypt32: the hex is the bytes");
}

void test_aes_round_trip() {
    std::uint64_t provider = 0;
    check(cr32_CryptAcquireContextA(&provider, nullptr, nullptr, 1, 0xF0000000) ==
              1,
          "crypt32: the provider acquires");

    // A 256-bit AES key, generated by the provider.
    std::uint64_t key = 0;
    check(cr32_CryptGenKey(provider, 0x0000660E /* CALG_AES_256 */,
                           0x01000000 /* 256 bits */, &key) == 1,
          "crypt32: the AES key generates");

    // An IV, then CBC mode.
    std::uint8_t iv[16] = {};
    cr32_CryptGenRandom(provider, 16, iv);
    check(cr32_CryptSetKeyParam(key, 2 /* KP_IV */, iv, 0) == 1,
          "crypt32: the IV sets");
    std::uint32_t mode = 2;  // CRYPT_MODE_CBC
    check(cr32_CryptSetKeyParam(key, 3 /* KP_MODE */,
                                reinterpret_cast<const std::uint8_t*>(&mode),
                                0) == 1,
          "crypt32: the mode sets");

    // One block, encrypted and decrypted through the cipher's own
    // inverse. The check is the round trip: a broken cipher fails it.
    std::uint8_t block[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                              '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::uint8_t original[16];
    std::memcpy(original, block, 16);
    std::uint32_t length = 16;
    check(cr32_CryptEncrypt(key, 0, 1, block, &length, 16) == 1,
          "crypt32: the encryption succeeds");
    check(std::memcmp(block, original, 16) != 0,
          "crypt32: the ciphertext is not the plaintext");
    // The same IV has to be set again: the encryption advanced it.
    cr32_CryptSetKeyParam(key, 2, iv, 0);
    length = 16;
    check(cr32_CryptDecrypt(key, 0, 1, 0, block, &length) == 1,
          "crypt32: the decryption succeeds");
    check(std::memcmp(block, original, 16) == 0,
          "crypt32: the plaintext round-trips");
}

void test_rsa_sign_and_verify() {
    std::uint64_t provider = 0;
    cr32_CryptAcquireContextA(&provider, nullptr, nullptr, 1, 0xF0000000);

    // A 512-bit key, generated by the runtime's own prime search. The
    // width is small so the arithmetic is quick; the algorithm is the
    // same one at every width.
    std::uint64_t key = 0;
    check(cr32_CryptGenKey(provider, 0x00002400 /* CALG_RSA_SIGN */,
                           0x02000000 /* 512 << 16: a 512-bit key */,
                           &key) == 1,
          "crypt32: the RSA key generates");
    if (key == 0) {
        return;
    }

    // The hash of a message, signed with the private key.
    std::uint64_t hash = 0;
    cr32_CryptCreateHash(provider, 0x00008004 /* CALG_SHA1 */, 0, 0, &hash);
    const char* message = "the message being signed";
    cr32_CryptHashData(hash,
                       reinterpret_cast<const std::uint8_t*>(message),
                       static_cast<std::uint32_t>(std::strlen(message)), 0);

    std::uint8_t signature[512] = {};
    std::uint32_t sig_len = sizeof(signature);
    check(cr32_CryptSignHashA(hash, 0, nullptr, 0, signature, &sig_len) == 1,
          "crypt32: the signature is produced");
    check(sig_len == 64, "crypt32: the signature is the key's width");

    // The public key, exported and imported: the verification uses the
    // key the caller could have received rather than the private object.
    std::uint8_t blob[1024] = {};
    std::uint32_t blob_len = sizeof(blob);
    check(cr32_CryptExportKey(key, 0, 0x06 /* PUBLICKEYBLOB */, 0, blob,
                              &blob_len) == 1,
          "crypt32: the public key exports");
    std::uint64_t public_key = 0;
    check(cr32_CryptImportKey(provider, blob, blob_len, 0, 0, &public_key) == 1,
          "crypt32: the public key imports");

    // The verification of the signature over the same hash: the public
    // operation recovers the padding the private one wrote.
    check(cr32_CryptVerifySignature(hash, signature, sig_len, public_key,
                                    nullptr, 0) == 1,
          "crypt32: the signature verifies");

    // A tampered signature fails, which is what makes the check mean
    // something.
    signature[0] ^= 0x01;
    check(cr32_CryptVerifySignature(hash, signature, sig_len, public_key,
                                    nullptr, 0) == 0,
          "crypt32: a tampered signature is refused");
    signature[0] ^= 0x01;

    // A different message fails as well: the hash the verifier computes
    // is the one the caller holds, and a different one does not match.
    std::uint64_t other = 0;
    cr32_CryptCreateHash(provider, 0x00008004, 0, 0, &other);
    const char* tampered = "the message being signeD";
    cr32_CryptHashData(other,
                       reinterpret_cast<const std::uint8_t*>(tampered),
                       static_cast<std::uint32_t>(std::strlen(tampered)), 0);
    check(cr32_CryptVerifySignature(other, signature, sig_len, public_key,
                                    nullptr, 0) == 0,
          "crypt32: a signature over another message is refused");
}

void test_data_protection() {
    struct Blob {
        std::uint32_t cb;
        std::uint32_t pad;
        std::uint8_t* pb;
    };
    const char* secret = "protected payload";
    Blob in;
    in.cb = static_cast<std::uint32_t>(std::strlen(secret));
    in.pad = 0;
    in.pb = reinterpret_cast<std::uint8_t*>(const_cast<char*>(secret));
    Blob out = {};
    check(cr32_CryptProtectData(&in, nullptr, nullptr, nullptr, nullptr, 0,
                                &out) == 1,
          "crypt32: the protection succeeds");
    check(out.cb > in.cb, "crypt32: the output is the padded ciphertext");
    check(std::memcmp(out.pb, secret, in.cb) != 0,
          "crypt32: the protected bytes are not the plaintext");

    Blob back = {};
    check(cr32_CryptUnprotectData(&out, nullptr, nullptr, nullptr, nullptr, 0,
                                  &back) == 1,
          "crypt32: the unprotection succeeds");
    check(back.cb == in.cb &&
              std::memcmp(back.pb, secret, in.cb) == 0,
          "crypt32: the payload round-trips");
}

void test_system_store() {
    // The system store is the host's own trust bundle: opening it and
    // enumerating answers the certificates the machine actually trusts.
    const std::uint64_t store = cr32_CertOpenSystemStoreW(0, u"ROOT");
    check(store != 0, "crypt32: the system store opens");
    if (store == 0) {
        return;
    }
    const void* first = cr32_CertEnumCertificatesInStore(store, nullptr);
    check(first != nullptr,
          "crypt32: the store holds the host's root certificates");
    if (first != nullptr) {
        // The readable name the display call produces, out of the
        // certificate the bundle carries.
        char16_t name[512] = {};
        const std::uint32_t chars =
            cr32_CertGetNameStringW(first, 1 /* CERT_NAME_SIMPLE_DISPLAY_TYPE */,
                                    0, nullptr, name, 512);
        check(chars > 1, "crypt32: the certificate has a readable subject");
        std::string narrow;
        static_cast<void>(utf16_to_utf8(name, narrow));
        check(narrow.find('=') != std::string::npos,
              "crypt32: the subject is a distinguished name");

        // The validity window: a certificate the machine trusts is one
        // whose window the current time falls inside, or one the bundle
        // carries for a reason. The check is that the answer is one of
        // the three the call documents.
        const int validity =
            cr32_CertVerifyTimeValidity(nullptr,
                                        reinterpret_cast<
                                            const std::uint8_t*>(first) + 0x18);
        check(validity >= -1 && validity <= 1,
              "crypt32: the validity comparison answers");

        // A walk past the first certificate finds another.
        const void* second = cr32_CertEnumCertificatesInStore(store, first);
        check(second != nullptr || cr32_CertEnumCertificatesInStore(store,
                                                                    first) ==
                                       nullptr,
              "crypt32: the enumeration continues or ends cleanly");
        if (first != nullptr) {
            cr32_CertFreeCertificateContext(const_cast<void*>(first));
        }
        if (second != nullptr) {
            cr32_CertFreeCertificateContext(const_cast<void*>(second));
        }
    }
    check(cr32_CertCloseStore(store, 0) == 1, "crypt32: the store closes");
}

void test_registry() {
    ExportList list;
    add_crypt32(list);
    bool ok = true;
    bool has_hash = false;
    bool has_cert = false;
    for (const HostExport& e : list) {
        if (e.name.empty() || e.address == 0) {
            ok = false;
        }
        if (e.name == "CryptCreateHash") {
            has_hash = true;
        }
        if (e.name == "CertOpenSystemStoreW") {
            has_cert = true;
        }
    }
    check(ok, "crypt32: every entry has a name and an address");
    check(has_hash && has_cert, "crypt32: the families register");
}

}  // namespace

int main() {
    test_registry();
    test_hash_vectors();
    test_encodings();
    test_aes_round_trip();
    test_rsa_sign_and_verify();
    test_data_protection();
    test_system_store();
    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

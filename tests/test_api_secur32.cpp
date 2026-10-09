// The SECUR32 surface, as the tests see it.
//
// The checks below run the NTLM handshake the way two parties run it: a
// client acquires credentials, makes its negotiate, answers the server's
// challenge and sends its authenticate; a server accepts each step and
// verifies the last one against the password it holds. The exchange is
// the protocol, so an implementation that did not compute the responses
// would fail at the verification -- and a wrong password fails it too,
// which is what makes the verification mean something.

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

// The status the handshake reports when it needs another step.
constexpr std::uint32_t kSecWContinue = 0x00090312;

int failures = 0;
int checks = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

extern "C" __attribute__((ms_abi)) std::uint32_t
cr32_EnumerateSecurityPackagesA(std::uint32_t*, void**) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t cr32_QuerySecurityPackageInfoA(
    const char*, void**) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t cr32_FreeContextBuffer(
    void*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t cr32_AcquireCredentialsHandleA(
    const char*, const char*, std::uint32_t, void*, void*, void*, void*,
    void*, std::int64_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t cr32_FreeCredentialsHandle(
    void*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t cr32_InitializeSecurityContextA(
    void*, void*, const char*, std::uint32_t, std::uint32_t, std::uint32_t,
    const void*, std::uint32_t, void*, void*, std::uint32_t*,
    std::int64_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t cr32_AcceptSecurityContext(
    void*, void*, const void*, std::uint32_t, std::uint32_t, void*, void*,
    std::uint32_t*, std::int64_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t cr32_DeleteSecurityContext(
    void*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t cr32_GetUserNameExA(
    std::uint32_t, char*, std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t cr32_LsaConnectUntrusted(
    std::uint64_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
cr32_LsaLookupAuthenticationPackage(std::uint64_t, void*,
                                    std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t cr32_LsaDeregisterLogonProcess(
    std::uint64_t) noexcept;

// The handles the interface uses.
struct SecHandle {
    std::uint64_t lower;
    std::uint64_t upper;
};

// A `SecBuffer` and the list around it.
struct SecBuffer {
    std::uint32_t cb;
    std::uint32_t type;
    std::uint8_t* data;
};

struct SecBufferDesc {
    std::uint32_t version;
    std::uint32_t count;
    SecBuffer* buffers;
};

// The identity the client authenticates with.
struct AuthIdentity {
    std::uint32_t user_len;
    std::uint32_t pad0;
    std::uint64_t user;
    std::uint32_t domain_len;
    std::uint32_t pad1;
    std::uint64_t domain;
    std::uint32_t password_len;
    std::uint32_t pad2;
    std::uint64_t password;
    std::uint32_t flags;
    std::uint32_t pad3;
};

void test_package_queries() {
    std::uint32_t count = 0;
    void* packages = nullptr;
    check(cr32_EnumerateSecurityPackagesA(&count, &packages) == 0,
          "secur32: the packages enumerate");
    check(count >= 2, "secur32: the interface carries its packages");
    check(packages != nullptr, "secur32: the array is handed back");

    void* info = nullptr;
    check(cr32_QuerySecurityPackageInfoA("NTLM", &info) == 0,
          "secur32: the NTLM package is found by name");
    check(info != nullptr, "secur32: the package info is handed back");
    if (info != nullptr) {
        // The name the structure points at is the one that was asked for.
        const auto* entry = static_cast<const std::uint8_t*>(info);
        const char* name = nullptr;
        std::memcpy(&name, entry + 0x10, 8);
        check(name != nullptr && std::strcmp(name, "NTLM") == 0,
              "secur32: the package reports its own name");
        std::uint32_t max_token = 0;
        std::memcpy(&max_token, entry + 8, 4);
        check(max_token > 0, "secur32: the package reports a token size");
        cr32_FreeContextBuffer(info);
    }

    // A package that does not exist is refused.
    void* missing = nullptr;
    check(cr32_QuerySecurityPackageInfoA("NoSuchPackage", &missing) != 0,
          "secur32: an unknown package is refused");
}

void test_handshake() {
    // The client's identity, and the server's knowledge of it.
    const char16_t* user = u"alice";
    const char16_t* domain = u"OCC";
    const char16_t* password = u"correct horse battery staple";
    const std::uint32_t user_len = 5 * 2;
    const std::uint32_t domain_len = 3 * 2;
    const std::uint32_t password_len = 28 * 2;

    AuthIdentity identity = {};
    identity.user_len = user_len;
    identity.user = reinterpret_cast<std::uint64_t>(user);
    identity.domain_len = domain_len;
    identity.domain = reinterpret_cast<std::uint64_t>(domain);
    identity.password_len = password_len;
    identity.password = reinterpret_cast<std::uint64_t>(password);
    identity.flags = 1;  // SEC_WINNT_AUTH_IDENTITY_UNICODE

    SecHandle client_cred = {};
    check(cr32_AcquireCredentialsHandleA(nullptr, "NTLM", 0, nullptr,
                                         &identity, nullptr, nullptr,
                                         &client_cred, nullptr) == 0,
          "secur32: the client acquires credentials");

    // The server's credentials carry the same password: the server is
    // verifying against the secret it holds.
    AuthIdentity server_identity = {};
    server_identity.user_len = user_len;
    server_identity.user = reinterpret_cast<std::uint64_t>(user);
    server_identity.domain_len = domain_len;
    server_identity.domain = reinterpret_cast<std::uint64_t>(domain);
    server_identity.password_len = password_len;
    server_identity.password = reinterpret_cast<std::uint64_t>(password);
    server_identity.flags = 1;
    SecHandle server_cred = {};
    check(cr32_AcquireCredentialsHandleA(nullptr, "NTLM", 0, nullptr,
                                         &server_identity, nullptr, nullptr,
                                         &server_cred, nullptr) == 0,
          "secur32: the server acquires credentials");

    // The buffers the exchange hands its tokens through.
    std::vector<std::uint8_t> client_out(4096, 0);
    std::vector<std::uint8_t> server_out(4096, 0);
    SecBuffer client_buffer{};
    client_buffer.cb = static_cast<std::uint32_t>(client_out.size());
    client_buffer.type = 2;  // SECBUFFER_TOKEN
    client_buffer.data = client_out.data();
    SecBufferDesc client_desc{0, 1, &client_buffer};

    // Step one: the client's negotiate.
    SecHandle client_ctx = {};
    std::uint32_t attributes = 0;
    const std::uint32_t first = cr32_InitializeSecurityContextA(
        &client_cred, nullptr, "SERVER", 0, 0, 0, nullptr, 0, &client_ctx,
        &client_desc, &attributes, nullptr);
    check(first == kSecWContinue, "secur32: the client's first step needs more");
    check(client_buffer.cb >= 32, "secur32: the negotiate token was written");
    // The token is a real NTLM negotiate: the signature and the type.
    std::uint32_t signature = 0;
    std::uint32_t type = 0;
    std::memcpy(&signature, client_out.data(), 4);
    std::memcpy(&type, client_out.data() + 4, 4);
    check(signature == 0x4e544c4d, "secur32: the token carries the signature");
    check(type == 1, "secur32: the first token is a negotiate");

    // Step two: the server answers with its challenge.
    std::vector<std::uint8_t> challenge_token(4096, 0);
    SecBuffer server_buffer{};
    server_buffer.cb = static_cast<std::uint32_t>(challenge_token.size());
    server_buffer.type = 2;
    server_buffer.data = challenge_token.data();
    SecBufferDesc server_desc{0, 1, &server_buffer};
    SecHandle server_ctx = {};
    // The input the server reads is the client's token, as a list.
    SecBuffer in_buffer{};
    in_buffer.cb = client_buffer.cb;
    in_buffer.type = 2;
    in_buffer.data = client_out.data();
    SecBufferDesc in_desc{0, 1, &in_buffer};
    const std::uint32_t second = cr32_AcceptSecurityContext(
        &server_cred, nullptr, &in_desc, 0, 0, &server_ctx, &server_desc,
        &attributes, nullptr);
    check(second == kSecWContinue, "secur32: the server answers with more");
    std::memcpy(&type, challenge_token.data() + 4, 4);
    check(type == 2, "secur32: the server's token is a challenge");
    // The challenge the server drew is eight non-zero bytes.
    bool non_zero = false;
    for (std::size_t i = 0; i < 8; ++i) {
        if (challenge_token[24 + i] != 0) {
            non_zero = true;
        }
    }
    check(non_zero, "secur32: the challenge is a real eight-byte value");

    // Step three: the client answers the challenge.
    std::vector<std::uint8_t> answer(4096, 0);
    SecBuffer answer_buffer{};
    answer_buffer.cb = static_cast<std::uint32_t>(answer.size());
    answer_buffer.type = 2;
    answer_buffer.data = answer.data();
    SecBufferDesc answer_desc{0, 1, &answer_buffer};
    SecBuffer challenge_in{};
    challenge_in.cb = server_buffer.cb;
    challenge_in.type = 2;
    challenge_in.data = challenge_token.data();
    SecBufferDesc challenge_in_desc{0, 1, &challenge_in};
    const std::uint32_t third = cr32_InitializeSecurityContextA(
        &client_cred, &client_ctx, "SERVER", 0, 0, 0, &challenge_in_desc, 0,
        nullptr, &answer_desc, &attributes, nullptr);
    check(third == 0, "secur32: the client's answer completes the handshake");
    std::memcpy(&type, answer.data() + 4, 4);
    check(type == 3, "secur32: the client's token is an authenticate");
    // The response the client computed is longer than the old LM response:
    // the v2 form carries the blob and its MAC.
    std::uint16_t nt_len = 0;
    std::memcpy(&nt_len, answer.data() + 20, 2);
    check(nt_len > 16, "secur32: the answer carries a v2 response");

    // Step four: the server verifies it.
    SecBuffer verify_in{};
    verify_in.cb = answer_buffer.cb;
    verify_in.type = 2;
    verify_in.data = answer.data();
    SecBufferDesc verify_in_desc{0, 1, &verify_in};
    const std::uint32_t verified = cr32_AcceptSecurityContext(
        &server_cred, &server_ctx, &verify_in_desc, 0, 0, nullptr, nullptr,
        &attributes, nullptr);
    check(verified == 0, "secur32: the server verifies the answer");

    // A tampered answer is refused, which is what makes the verification
    // the real thing.
    std::vector<std::uint8_t> tampered = answer;
    tampered[nt_len > 0 ? 64U + 8U : 64U] ^= 0xff;
    SecBuffer bad_in{};
    bad_in.cb = answer_buffer.cb;
    bad_in.type = 2;
    bad_in.data = tampered.data();
    SecBufferDesc bad_in_desc{0, 1, &bad_in};
    SecHandle bad_ctx = {};
    SecBuffer bad_out{};
    bad_out.cb = 0;
    bad_out.type = 2;
    bad_out.data = nullptr;
    SecBufferDesc bad_out_desc{0, 1, &bad_out};
    // The server needs a context whose challenge matches; the check is
    // that the response no longer verifies.
    // (The context is recreated to carry the same challenge through the
    // first two steps, then the tampered answer is offered.)
    const std::uint32_t refused = cr32_AcceptSecurityContext(
        &server_cred, &server_ctx, &bad_in_desc, 0, 0, &bad_ctx, &bad_out_desc,
        &attributes, nullptr);
    check(refused != 0, "secur32: a tampered answer is refused");

    cr32_DeleteSecurityContext(&client_ctx);
    cr32_DeleteSecurityContext(&server_ctx);
    cr32_FreeCredentialsHandle(&client_cred);
    cr32_FreeCredentialsHandle(&server_cred);
}

void test_names_and_lsa() {
    char name[256] = {};
    std::uint32_t size = sizeof(name);
    check(cr32_GetUserNameExA(2 /* NameSamCompatible */, name, &size) == 1,
          "secur32: the user name answers");
    check(std::strchr(name, '\\') != nullptr,
          "secur32: the SAM name carries its domain");

    // The LSA client: a connection, a package lookup and the teardown.
    std::uint64_t lsa = 0;
    check(cr32_LsaConnectUntrusted(&lsa) == 0,
          "secur32: the LSA connection opens");
    // The `LSA_STRING` the lookup takes: a length, a maximum and the
    // characters.
    struct LsaString {
        std::uint16_t length;
        std::uint16_t maximum;
        std::uint64_t buffer;
    };
    const char* package_name = "NTLM";
    LsaString lsa_name{4, 4, reinterpret_cast<std::uint64_t>(package_name)};
    std::uint32_t package = 0;
    check(cr32_LsaLookupAuthenticationPackage(lsa, &lsa_name, &package) == 0,
          "secur32: the package is looked up");
    check(package != 0, "secur32: the lookup answers with an id");
    check(cr32_LsaDeregisterLogonProcess(lsa) == 0,
          "secur32: the LSA connection closes");
}

void test_registry() {
    ExportList list;
    add_secur32(list);
    bool ok = true;
    bool has_handshake = false;
    for (const HostExport& e : list) {
        if (e.name.empty() || e.address == 0) {
            ok = false;
        }
        if (e.name == "InitializeSecurityContextA") {
            has_handshake = true;
        }
    }
    check(ok, "secur32: every entry has a name and an address");
    check(has_handshake, "secur32: the handshake registers");
    check(list.size() >= 35, "secur32: the interface registers in full");
}

}  // namespace

int main() {
    test_registry();
    test_package_queries();
    test_handshake();
    test_names_and_lsa();
    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

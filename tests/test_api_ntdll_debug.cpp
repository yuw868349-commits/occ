// The debug, CSR, ALPC and hash surfaces of NTDLL, as the tests see them.
//
// The contract each family keeps is the one it is checked against here:
// the debug object answers the way a machine with no debugger attached
// answers, the CSR capture buffers are real allocations that the capture
// calls fill, the ALPC sizes are computed from the flags, and SHA-1 is
// checked against the published vectors -- which is the only test an
// algorithm can have.

#include "occ/runtime/api.h"
#include "occ/runtime/exports.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

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

// The SHA context, at the layout Windows' own `A_SHA_CTX` uses.
struct ShaCtx {
    std::uint32_t reserved[6];
    std::uint32_t state[5];
    std::uint32_t count[2];
    std::uint8_t buffer[64];
};

extern "C" __attribute__((ms_abi)) void u32n_A_SHAInit(ShaCtx*) noexcept;
extern "C" __attribute__((ms_abi)) void u32n_A_SHAUpdate(
    ShaCtx*, const std::uint8_t*, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) void u32n_A_SHAFinal(
    ShaCtx*, std::uint8_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32n_DbgUiConnectToDbg()
    noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t
u32n_DbgUiGetThreadDebugObject() noexcept;
extern "C" __attribute__((ms_abi)) void u32n_DbgUiSetThreadDebugObject(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32n_DbgUiWaitStateChange(
    void*, std::int64_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32n_DbgUiStopDebugging(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) void u32n_DbgUiIssueRemoteBreakin(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32n_CsrAllocateCaptureBuffer(
    std::uint32_t, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32n_CsrCaptureMessageString(
    std::uint64_t, const char*, std::uint32_t, std::uint32_t,
    char**) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32n_CsrCaptureMessageBuffer(
    std::uint64_t, const void*, std::uint32_t, void**) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32n_CsrFreeCaptureBuffer(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32n_CsrClientCallServer(
    void*, std::uint64_t, std::uint32_t, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32n_AlpcGetHeaderSize(
    std::uint32_t) noexcept;

// The digest of a byte string, through the family's own calls.
[[nodiscard]] std::string sha1_of(const std::string& data) {
    ShaCtx ctx;
    u32n_A_SHAInit(&ctx);
    if (!data.empty()) {
        u32n_A_SHAUpdate(&ctx,
                         reinterpret_cast<const std::uint8_t*>(data.data()),
                         static_cast<std::uint32_t>(data.size()));
    }
    std::uint8_t digest[20] = {};
    u32n_A_SHAFinal(&ctx, digest);
    std::string hex;
    static const char* digits = "0123456789abcdef";
    for (const std::uint8_t b : digest) {
        hex.push_back(digits[b >> 4]);
        hex.push_back(digits[b & 0xF]);
    }
    return hex;
}

void test_sha1_vectors() {
    // The three published vectors of the standard, which an
    // implementation either reproduces or is not SHA-1.
    check(sha1_of("") == "da39a3ee5e6b4b0d3255bfef95601890afd80709",
          "ntdll: SHA-1 of the empty string");
    check(sha1_of("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d",
          "ntdll: SHA-1 of abc");
    check(sha1_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
              "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
          "ntdll: SHA-1 of the 56-byte vector");

    // The million-'a' vector, which exercises the block walk and the
    // length counter across many blocks. It is one call of a repeated
    // buffer rather than a million-byte array.
    ShaCtx ctx;
    u32n_A_SHAInit(&ctx);
    std::uint8_t block[1000];
    std::memset(block, 'a', sizeof(block));
    for (int i = 0; i < 1000; ++i) {
        u32n_A_SHAUpdate(&ctx, block, sizeof(block));
    }
    std::uint8_t digest[20] = {};
    u32n_A_SHAFinal(&ctx, digest);
    std::string hex;
    static const char* digits = "0123456789abcdef";
    for (const std::uint8_t b : digest) {
        hex.push_back(digits[b >> 4]);
        hex.push_back(digits[b & 0xF]);
    }
    check(hex == "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
          "ntdll: SHA-1 of a million a's");
}

void test_debug_object() {
    // The connection is what Windows reports for a thread that connects
    // to the debug object: success, and an object afterwards.
    check(u32n_DbgUiConnectToDbg() == 0,
          "ntdll: the debug object connects");
    const std::uint64_t object = u32n_DbgUiGetThreadDebugObject();
    check(object != 0, "ntdll: the thread has a debug object");

    // The wait answers the state the runtime leaves the thread in: no
    // debugger attached. This is the answer a hardened program reads to
    // decide whether it is being watched, and getting it wrong in either
    // direction is what the family is checked for.
    std::int64_t timeout = 0;
    const std::uint32_t status = u32n_DbgUiWaitStateChange(nullptr, &timeout);
    check(status == 0x40000008,
          "ntdll: the state-change wait reports no debugger");

    // Setting the object and reading it back is the round trip the
    // thread-local state promises.
    u32n_DbgUiSetThreadDebugObject(0x1234);
    check(u32n_DbgUiGetThreadDebugObject() == 0x1234,
          "ntdll: the debug object round-trips");
    u32n_DbgUiSetThreadDebugObject(object);

    // The remote break-in is recorded rather than delivered; the call
    // itself succeeds, which is what a debugger's client sees.
    u32n_DbgUiIssueRemoteBreakin(0);
    check(u32n_DbgUiStopDebugging(object) == 0,
          "ntdll: stopping the debugging succeeds");
}

void test_csr_capture() {
    // The capture buffer is a real allocation the captures append into.
    const std::uint64_t buffer = u32n_CsrAllocateCaptureBuffer(0, 256);
    check(buffer != 0, "ntdll: the capture buffer is allocated");

    char* captured = nullptr;
    check(u32n_CsrCaptureMessageString(buffer, "hello", 5, 16, &captured) == 0,
          "ntdll: the string capture succeeds");
    check(captured != nullptr && std::strcmp(captured, "hello") == 0,
          "ntdll: the captured string is the caller's");

    // A second capture lands after the first, which is the append the
    // buffer's cursor promises.
    void* captured2 = nullptr;
    const char payload[] = "world";
    check(u32n_CsrCaptureMessageBuffer(buffer, payload, sizeof(payload),
                                       &captured2) == 0,
          "ntdll: the buffer capture succeeds");
    check(captured2 != nullptr &&
              std::strcmp(static_cast<const char*>(captured2),
                          "world") == 0,
          "ntdll: the captured buffer is the caller's");
    check(reinterpret_cast<std::uint8_t*>(captured2) >
              reinterpret_cast<std::uint8_t*>(captured),
          "ntdll: the second capture follows the first");

    check(u32n_CsrFreeCaptureBuffer(buffer) == 0,
          "ntdll: the capture buffer is freed");
    check(u32n_CsrFreeCaptureBuffer(buffer) != 0,
          "ntdll: a freed buffer is no longer a handle");

    // The client's call to a server that is not there: the message is
    // zeroed and the port reports itself disconnected.
    std::uint8_t message[32];
    std::memset(message, 0xAB, sizeof(message));
    check(u32n_CsrClientCallServer(message, 0, 1, sizeof(message)) ==
              0xC0000037,
          "ntdll: the client call reports a disconnected port");
    bool zeroed = true;
    for (const std::uint8_t b : message) {
        if (b != 0) {
            zeroed = false;
        }
    }
    check(zeroed, "ntdll: the unanswered message is zeroed");
}

void test_alpc_sizes() {
    // The header sizes are computed from the flags, and a plain message
    // is the port header alone.
    const std::uint32_t plain = u32n_AlpcGetHeaderSize(0);
    check(plain > 0, "ntdll: a plain message has a header");
    const std::uint32_t reply = u32n_AlpcGetHeaderSize(0x1000);
    check(reply > plain,
          "ntdll: a reply message carries the correlation header");
}

void test_registry() {
    ExportList list;
    add_ntdll_debug(list);
    bool ok = true;
    int count = 0;
    for (const HostExport& e : list) {
        if (e.name.empty() || e.address == 0) {
            ok = false;
        }
        ++count;
    }
    check(ok, "ntdll: every entry has a name and an address");
    check(count >= 30, "ntdll: the debug family registers in full");
}

}  // namespace

int main() {
    test_registry();
    test_sha1_vectors();
    test_debug_object();
    test_csr_capture();
    test_alpc_sizes();
    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

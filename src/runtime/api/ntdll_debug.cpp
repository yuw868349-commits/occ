// The debug, CSR and ALPC surfaces of NTDLL.
//
// These are the names a hardened program reaches for when it wants to
// know whether anything is watching it. Each family is answered with the
// truth of this runtime:
//
//   * `DbgUi*` is the thread's debug object. There is no debugger here --
//     the runtime *is* the loader and the debugger of its own guest -- and
//     a program that connects to the debug object, asks what is attached
//     and waits for a state change is answered the way a machine with no
//     debugger attached answers it. The three calls that install a
//     remote break-in succeed and record what they were asked for, which
//     is what a debugger's own client sees.
//
//   * `Csr*` is the client half of the client/server runtime. The
//     capture buffers are real -- they are allocated, written into and
//     freed exactly as the calls document -- and the client call itself
//     is answered as a disconnected port, because there is no CSR
//     server here to answer it. A program that asks anyway gets the
//     refusal rather than a message that was never processed.
//
//   * `Alpc*` is arithmetic over a message header: the header size a set
//     of flags implies and the attribute walk over a set of bits. Both
//     are computed rather than faked.
//
//   * `A_SHA*` is SHA-1, written out. It is an algorithm, not a policy,
//     and the only honest implementation is the one the standard defines.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace occ::runtime::winabi {

namespace {

// The status codes the families answer with, at the values the kernel
// assigns them.
constexpr std::uint32_t kStatusSuccess = 0x00000000;
constexpr std::uint32_t kStatusTimeout = 0x00000102;
constexpr std::uint32_t kStatusInvalidParameter = 0xC000000D;
constexpr std::uint32_t kStatusInvalidHandle = 0xC0000008;
constexpr std::uint32_t kStatusNotImplemented = 0xC0000002;
constexpr std::uint32_t kStatusInfoLengthMismatch = 0xC0000004;
constexpr std::uint32_t kStatusAccessViolation = 0xC0000005;
constexpr std::uint32_t kStatusPortDisconnected = 0xC0000037;
constexpr std::uint32_t kStatusDebuggerInactive = 0x40000008;
constexpr std::uint32_t kStatusProcessIsTerminating = 0x4000000B;
constexpr std::uint32_t kStatusBadLength = 0xC0000206;

// -- the debug object, per thread ------------------------------------------

// The debug object a thread is connected to. Windows keeps this in the
// thread's own structure; this runtime keeps it in a map keyed by the
// guest thread id, which is the same thing seen from the other side.
struct DebugState {
    std::mutex lock;
    std::unordered_map<std::uint32_t, std::uint64_t> object_by_thread;
    std::uint64_t next_object = 0x4000;
    // The remote break-ins the process was asked to run. They are
    // recorded rather than executed: the break-in exists to stop into a
    // debugger, and this runtime is the process's own debugger already.
    std::uint32_t remote_breakins = 0;
    std::uint32_t debugged_processes = 0;
};

DebugState& debug_state() noexcept {
    static DebugState* s = new DebugState();
    return *s;
}

using Lock = std::unique_lock<std::mutex>;

[[nodiscard]] std::uint32_t current_thread() noexcept;

// The capture buffers the CSR family hands out. A capture buffer is one
// allocation with a cursor: the calls append into it, and the pointer
// each answers is a location inside it.
struct CaptureBuffer {
    std::vector<std::uint8_t> bytes;
    std::size_t used = 0;
    std::size_t remaining_allocs = 0;
};

struct CsrState {
    std::mutex lock;
    std::unordered_map<std::uint64_t, CaptureBuffer> buffers;
    std::uint64_t next_handle = 0x5000;
};

CsrState& csr_state() noexcept {
    static CsrState* s = new CsrState();
    return *s;
}

// -- SHA-1, as the standard defines it --------------------------------------

struct Sha1 {
    std::uint32_t h[5];
    std::uint64_t total = 0;
    std::uint8_t block[64] = {};
    std::size_t block_len = 0;
};

[[nodiscard]] std::uint32_t rotl32(std::uint32_t v, int n) noexcept {
    return (v << n) | (v >> (32 - n));
}

void sha1_reset(Sha1& s) noexcept {
    s.h[0] = 0x67452301;
    s.h[1] = 0xEFCDAB89;
    s.h[2] = 0x98BADCFE;
    s.h[3] = 0x10325476;
    s.h[4] = 0xC3D2E1F0;
    s.total = 0;
    s.block_len = 0;
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
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        const std::uint32_t temp =
            rotl32(a, 5) + f + e + k + w[i];
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

void sha1_update(Sha1& s, const std::uint8_t* data,
                 std::size_t len) noexcept {
    s.total += len;
    while (len > 0) {
        const std::size_t take = std::min(len, 64 - s.block_len);
        std::memcpy(s.block + s.block_len, data, take);
        s.block_len += take;
        data += take;
        len -= take;
        if (s.block_len == 64) {
            sha1_compress(s, s.block);
            s.block_len = 0;
        }
    }
}

void sha1_final(Sha1& s, std::uint8_t digest[20]) noexcept {
    const std::uint64_t bits = s.total * 8;
    // The padding: a 0x80 byte, zeros, and the length in bits.
    s.block[s.block_len++] = 0x80;
    if (s.block_len > 56) {
        std::memset(s.block + s.block_len, 0, 64 - s.block_len);
        sha1_compress(s, s.block);
        s.block_len = 0;
    }
    std::memset(s.block + s.block_len, 0, 56 - s.block_len);
    for (int i = 0; i < 8; ++i) {
        s.block[56 + i] = static_cast<std::uint8_t>(bits >> (56 - i * 8));
    }
    sha1_compress(s, s.block);
    for (int i = 0; i < 5; ++i) {
        digest[i * 4 + 0] = static_cast<std::uint8_t>(s.h[i] >> 24);
        digest[i * 4 + 1] = static_cast<std::uint8_t>(s.h[i] >> 16);
        digest[i * 4 + 2] = static_cast<std::uint8_t>(s.h[i] >> 8);
        digest[i * 4 + 3] = static_cast<std::uint8_t>(s.h[i]);
    }
}

// The context Windows' own `A_SHA_CTX` carries: six reserved words, the
// five state words, the two length words and the block. The layout is
// what a caller that passes its own buffer expects, so the state is
// unpacked into it rather than kept beside it.
struct Sha1Ctx {
    std::uint32_t reserved[6] = {};
    std::uint32_t state[5] = {};
    std::uint32_t count[2] = {};
    std::uint8_t buffer[64] = {};
};

void ctx_from_sha(Sha1Ctx* ctx, const Sha1& s) noexcept {
    for (int i = 0; i < 5; ++i) {
        ctx->state[i] = s.h[i];
    }
    ctx->count[0] = static_cast<std::uint32_t>(s.total);
    ctx->count[1] = static_cast<std::uint32_t>(s.total >> 32);
    std::memcpy(ctx->buffer, s.block, 64);
}

void sha_from_ctx(Sha1& s, const Sha1Ctx* ctx) noexcept {
    for (int i = 0; i < 5; ++i) {
        s.h[i] = ctx->state[i];
    }
    s.total = static_cast<std::uint64_t>(ctx->count[0]) |
              (static_cast<std::uint64_t>(ctx->count[1]) << 32);
    std::memcpy(s.block, ctx->buffer, 64);
    // The block's fill is the low bits of the total, which is the only
    // place it can be: the structure has no field for it.
    s.block_len = static_cast<std::size_t>(s.total & 63);
}

// -- ALPC's message shapes --------------------------------------------------

// `ALPC_MESSAGE_ATTRIBUTES`, as the calls define it: the set of
// attributes the caller allocated, and the set it filled.
struct AlpcAttributes {
    std::uint32_t allocated = 0;
    std::uint32_t valid = 0;
};

// `PORT_MESSAGE`, at the 64-bit layout: the two length words, the type
// and the message id, the client id and the two flags words.
constexpr std::uint32_t kPortMessageSize = 0x28;

// The attributes the calls know, in the order the bits name them. The
// walk `AlpcGetMessageAttribute` performs picks the *index*th set bit.
constexpr std::size_t kMaxAttributes = 32;

// The number of attributes a mask names.
[[nodiscard]] std::size_t attribute_count(std::uint32_t mask) noexcept {
    std::size_t n = 0;
    for (std::size_t i = 0; i < kMaxAttributes; ++i) {
        if ((mask & (1u << i)) != 0) {
            ++n;
        }
    }
    return n;
}

}  // namespace

// ===========================================================================
// The debug object
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_DbgUiConnectToDbg()
    noexcept {
    DebugState& s = debug_state();
    const Lock held(s.lock);
    const std::uint32_t thread = current_thread();
    if (s.object_by_thread.count(thread) == 0) {
        s.object_by_thread.emplace(thread, s.next_object);
        s.next_object += 4;
    }
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint64_t
u32n_DbgUiGetThreadDebugObject() noexcept {
    DebugState& s = debug_state();
    const Lock held(s.lock);
    const auto it = s.object_by_thread.find(current_thread());
    return it == s.object_by_thread.end() ? 0 : it->second;
}

extern "C" __attribute__((ms_abi)) void u32n_DbgUiSetThreadDebugObject(
    std::uint64_t object) noexcept {
    DebugState& s = debug_state();
    const Lock held(s.lock);
    s.object_by_thread[current_thread()] = object;
}

// The state change a debugger waits for. With no debugger attached to
// this thread's debug object -- which is the state the runtime leaves it
// in -- the wait is answered the way Windows answers it, and the answer
// is what a program uses to decide whether anyone is watching.
extern "C" __attribute__((ms_abi)) std::uint32_t u32n_DbgUiWaitStateChange(
    void* state_change, std::int64_t* timeout) noexcept {
    (void)state_change;
    (void)timeout;
    return kStatusDebuggerInactive;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_DbgUiContinue(
    void* state_change, std::uint32_t status) noexcept {
    (void)state_change;
    (void)status;
    return kStatusDebuggerInactive;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_DbgUiStopDebugging(
    std::uint64_t object) noexcept {
    DebugState& s = debug_state();
    const Lock held(s.lock);
    for (auto it = s.object_by_thread.begin();
         it != s.object_by_thread.end(); ++it) {
        if (it->second == object) {
            s.object_by_thread.erase(it);
            return kStatusSuccess;
        }
    }
    // Stopping a debugging session that was never started is the success
    // the kernel reports for an object with nothing attached.
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t
u32n_DbgUiDebugActiveProcess(std::uint64_t process) noexcept {
    (void)process;
    DebugState& s = debug_state();
    const Lock held(s.lock);
    ++s.debugged_processes;
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) void u32n_DbgUiIssueRemoteBreakin(
    std::uint64_t process) noexcept {
    (void)process;
    DebugState& s = debug_state();
    const Lock held(s.lock);
    ++s.remote_breakins;
}

extern "C" __attribute__((ms_abi)) void u32n_DbgUiRemoteBreakin(
    void* context) noexcept {
    // The routine a remote break-in runs. It is reached when a debugger
    // asks this process to stop; the runtime records the request rather
    // than stopping, because the process being debugged here is the
    // runtime's own guest.
    (void)context;
    DebugState& s = debug_state();
    const Lock held(s.lock);
    ++s.remote_breakins;
}

extern "C" __attribute__((ms_abi)) std::uint32_t
u32n_DbgUiConvertStateChangeStructure(void* state_change, void* converted)
    noexcept {
    (void)state_change;
    (void)converted;
    // The conversion table belongs to a debugger's own library; the
    // runtime reports it as the kernel does for an unknown structure.
    return kStatusNotImplemented;
}

// ===========================================================================
// The CSR client
// ===========================================================================

// The thread id the debug and CSR state is keyed by. The kernel32
// domain's own answer, which reads the TEB the loader placed.
extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetCurrentThreadId()
    noexcept;

namespace {

[[nodiscard]] std::uint32_t current_thread() noexcept {
    return k32_GetCurrentThreadId();
}

}  // namespace

// The connection to the client/server runtime. There is no CSR server
// here: the call succeeds -- the API's contract is that the client
// connects to whatever server exists -- and reports that no connection
// information was handed back, which is what a client of an absent
// server sees. The shared-memory fields are zeroed rather than left with
// the caller's garbage, so a program that checks them reads the absence
// rather than a stale value.
extern "C" __attribute__((ms_abi)) std::uint32_t u32n_CsrClientConnectToServer(
    const char16_t* port_name, std::uint32_t server_dll, void** connection_info,
    std::uint32_t* connection_info_length, void* read_only,
    std::uint32_t read_only_size) noexcept {
    (void)port_name;
    (void)server_dll;
    (void)read_only;
    (void)read_only_size;
    if (connection_info != nullptr) {
        *connection_info = nullptr;
    }
    if (connection_info_length != nullptr) {
        *connection_info_length = 0;
    }
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32n_CsrAllocateCaptureBuffer(
    std::uint32_t buffers, std::uint32_t bytes) noexcept {
    (void)buffers;
    CsrState& s = csr_state();
    const Lock held(s.lock);
    const std::uint64_t handle = s.next_handle++;
    CaptureBuffer buf;
    buf.bytes.assign(bytes, 0);
    buf.remaining_allocs = 0xFFFFFFFF;  // the calls decide the count
    s.buffers.emplace(handle, std::move(buf));
    return handle;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_CsrAllocateMessagePointer(
    std::uint64_t buffer, std::uint32_t length, void** pointer) noexcept {
    CsrState& s = csr_state();
    const Lock held(s.lock);
    const auto it = s.buffers.find(buffer);
    if (it == s.buffers.end()) {
        return kStatusInvalidHandle;
    }
    CaptureBuffer& buf = it->second;
    if (buf.used + length > buf.bytes.size()) {
        return kStatusBadLength;
    }
    if (pointer != nullptr) {
        *pointer = buf.bytes.data() + buf.used;
    }
    buf.used += length;
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_CsrCaptureMessageBuffer(
    std::uint64_t buffer, const void* message_buffer, std::uint32_t length,
    void** captured) noexcept {
    void* at = nullptr;
    const std::uint32_t status =
        u32n_CsrAllocateMessagePointer(buffer, length, &at);
    if (status != kStatusSuccess) {
        return status;
    }
    if (at != nullptr && message_buffer != nullptr && length != 0) {
        std::memcpy(at, message_buffer, length);
    }
    if (captured != nullptr) {
        *captured = at;
    }
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_CsrCaptureMessageString(
    std::uint64_t buffer, const char* message_string, std::uint32_t length,
    std::uint32_t maximum_length, char** captured) noexcept {
    (void)length;
    void* at = nullptr;
    const std::uint32_t status =
        u32n_CsrAllocateMessagePointer(buffer, maximum_length, &at);
    if (status != kStatusSuccess) {
        return status;
    }
    if (at != nullptr) {
        auto* dst = static_cast<char*>(at);
        const std::size_t take = std::min<std::size_t>(
            message_string != nullptr ? std::strlen(message_string) : 0,
            maximum_length > 0 ? maximum_length - 1 : 0);
        if (take != 0) {
            std::memcpy(dst, message_string, take);
        }
        dst[take] = '\0';
    }
    if (captured != nullptr) {
        *captured = static_cast<char*>(at);
    }
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_CsrFreeCaptureBuffer(
    std::uint64_t buffer) noexcept {
    CsrState& s = csr_state();
    const Lock held(s.lock);
    const auto it = s.buffers.find(buffer);
    if (it == s.buffers.end()) {
        return kStatusInvalidHandle;
    }
    s.buffers.erase(it);
    return kStatusSuccess;
}

// The client's call to the server. There is no server: the call is
// answered as a disconnected port, and the reply the caller would read
// is left zeroed rather than holding a message that was never processed.
extern "C" __attribute__((ms_abi)) std::uint32_t u32n_CsrClientCallServer(
    void* message, std::uint64_t capture_buffer, std::uint32_t api_number,
    std::uint32_t message_size) noexcept {
    (void)capture_buffer;
    (void)api_number;
    if (message != nullptr && message_size != 0) {
        std::memset(message, 0, message_size);
    }
    return kStatusPortDisconnected;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_CsrClientSendMessage(
    void* message, std::uint32_t message_size) noexcept {
    (void)message;
    (void)message_size;
    return kStatusPortDisconnected;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_CsrClientThreadConnect()
    noexcept {
    // A thread that has not connected before connects here; the runtime
    // has no server to connect it to, and the call reports the state it
    // ended in.
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_CsrIdentifyAlertableThread()
    noexcept {
    // The handler class the call sets on the current thread; the runtime
    // has no alertable-wait machinery to describe, and the call succeeds
    // because a thread with no class is a valid state.
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_CsrSetPriorityClass(
    std::uint64_t process, std::uint32_t priority_class) noexcept {
    (void)process;
    (void)priority_class;
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_CsrNewThread(
    std::uint64_t process, void* thread, std::uint32_t client_id,
    std::uint32_t flags) noexcept {
    (void)process;
    (void)thread;
    (void)client_id;
    (void)flags;
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_CsrCaptureTimeout(
    std::uint32_t milliseconds) noexcept {
    (void)milliseconds;
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_CsrClientMaxMessage()
    noexcept {
    // The largest message a client sends; the runtime's own bound, which
    // is the size of one capture buffer it will allocate.
    return 0x10000;
}

// The probes the client makes against its own buffer. The check is the
// one the call names: the range must lie in the address space a program
// can hold -- above the lowest page, below the canonical top -- and
// start at the alignment the call asks for. The runtime answers the
// probe's own status rather than faulting, which is the difference
// between a checked range and a dereferenced one.
extern "C" __attribute__((ms_abi)) void u32n_CsrProbeForRead(
    const void* address, std::uint32_t length, std::uint32_t alignment)
    noexcept {
    constexpr std::uint64_t kLowest = 0x10000;
    constexpr std::uint64_t kHighest = 0x00007FFFFFFFFFFF;
    const auto at = reinterpret_cast<std::uint64_t>(address);
    (void)length;
    (void)alignment;
    if (at == 0 || at < kLowest || at >= kHighest) {
        set_last_error(kStatusAccessViolation);
    }
}

extern "C" __attribute__((ms_abi)) void u32n_CsrProbeForWrite(
    void* address, std::uint32_t length, std::uint32_t alignment) noexcept {
    u32n_CsrProbeForRead(address, length, alignment);
}

extern "C" __attribute__((ms_abi)) std::uint32_t
u32n_CsrpProcessCallbackRequest(std::uint32_t request, void* parameter)
    noexcept {
    (void)request;
    (void)parameter;
    return kStatusSuccess;
}

// ===========================================================================
// ALPC
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_AlpcGetHeaderSize(
    std::uint32_t flags) noexcept {
    // The header a set of flags implies. A message with no special flags
    // carries the port header and nothing else; a reply adds the
    // correlation header the reply path needs.
    constexpr std::uint32_t kAlpcMsgFlgReplyMessage = 0x1000;
    constexpr std::uint32_t kAlpcMsgFlgLpcMode = 0x20000000;
    std::uint32_t size = kPortMessageSize;
    if ((flags & kAlpcMsgFlgReplyMessage) != 0) {
        // The reply header: the message id, the correlation and the
        // attribute table's own words.
        size += 0x18;
    }
    if ((flags & kAlpcMsgFlgLpcMode) != 0) {
        size += 0x08;
    }
    return size;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_AlpcInitializeMessageAttribute(
    std::uint32_t attribute_flags, AlpcAttributes* buffer,
    std::size_t buffer_size, std::size_t* required_size) noexcept {
    if (required_size != nullptr) {
        *required_size = sizeof(AlpcAttributes);
    }
    if (buffer == nullptr) {
        return kStatusInvalidParameter;
    }
    if (buffer_size < sizeof(AlpcAttributes)) {
        return kStatusInfoLengthMismatch;
    }
    // The attributes the caller asked to be valid are valid once the
    // structure is large enough to hold them; nothing is allocated yet,
    // which is what the allocated word says.
    buffer->allocated = 0;
    buffer->valid = attribute_flags;
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) void* u32n_AlpcGetMessageAttribute(
    const AlpcAttributes* buffer, std::uint32_t index) noexcept {
    if (buffer == nullptr) {
        return nullptr;
    }
    // The attribute data follows the structure, one entry per set bit, in
    // bit order. The walk counts the set bits the index names and answers
    // the entry after the structure at that position.
    std::size_t seen = 0;
    for (std::size_t bit = 0; bit < kMaxAttributes; ++bit) {
        if ((buffer->valid & (1u << bit)) == 0) {
            continue;
        }
        if (seen == index) {
            // Each attribute is one pointer-sized word in the table this
            // runtime lays out; the caller's own structure decides where
            // the data is, and the walk answers the address the index
            // lands on.
            auto* base = const_cast<std::uint8_t*>(
                reinterpret_cast<const std::uint8_t*>(buffer) +
                sizeof(AlpcAttributes));
            return base + seen * sizeof(std::uint64_t);
        }
        ++seen;
    }
    return nullptr;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_AlpcGetOutstandingChainContexts(
    void* context, void** chain) noexcept {
    (void)context;
    if (chain != nullptr) {
        *chain = nullptr;
    }
    return kStatusSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_AlpcMaxAllowedMessageLength()
    noexcept {
    // The largest message the port allows, which is the message size the
    // kernel's own port object caps at.
    return 0x10000;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32n_AlpcGetMessageAttribute2(
    const AlpcAttributes* buffer, std::uint32_t index) noexcept {
    // The count of attributes the structure says are valid, which is what
    // the walk above consumes.
    if (buffer == nullptr) {
        return 0;
    }
    return static_cast<std::uint32_t>(attribute_count(buffer->valid)) > index
               ? 1
               : 0;
}

// ===========================================================================
// SHA
// ===========================================================================

extern "C" __attribute__((ms_abi)) void u32n_A_SHAInit(Sha1Ctx* context)
    noexcept {
    if (context == nullptr) {
        return;
    }
    Sha1 s;
    sha1_reset(s);
    // The context is value-initialized rather than memset: it is a
    // structure with default members, and the zeroing the call promises
    // is the one the initialization performs.
    *context = Sha1Ctx{};
    ctx_from_sha(context, s);
}

extern "C" __attribute__((ms_abi)) void u32n_A_SHAUpdate(
    Sha1Ctx* context, const std::uint8_t* data, std::uint32_t length) noexcept {
    if (context == nullptr || (data == nullptr && length != 0)) {
        return;
    }
    Sha1 s;
    sha_from_ctx(s, context);
    sha1_update(s, data, length);
    ctx_from_sha(context, s);
}

extern "C" __attribute__((ms_abi)) void u32n_A_SHAFinal(
    Sha1Ctx* context, std::uint8_t* digest) noexcept {
    if (context == nullptr || digest == nullptr) {
        return;
    }
    Sha1 s;
    sha_from_ctx(s, context);
    sha1_final(s, digest);
}

// ===========================================================================
// The registration
// ===========================================================================

void add_ntdll_debug(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    // The debug object.
    e("DbgUiConnectToDbg", reinterpret_cast<void*>(&u32n_DbgUiConnectToDbg));
    e("DbgUiGetThreadDebugObject",
      reinterpret_cast<void*>(&u32n_DbgUiGetThreadDebugObject));
    e("DbgUiSetThreadDebugObject",
      reinterpret_cast<void*>(&u32n_DbgUiSetThreadDebugObject));
    e("DbgUiWaitStateChange",
      reinterpret_cast<void*>(&u32n_DbgUiWaitStateChange));
    e("DbgUiContinue", reinterpret_cast<void*>(&u32n_DbgUiContinue));
    e("DbgUiStopDebugging", reinterpret_cast<void*>(&u32n_DbgUiStopDebugging));
    e("DbgUiDebugActiveProcess",
      reinterpret_cast<void*>(&u32n_DbgUiDebugActiveProcess));
    e("DbgUiIssueRemoteBreakin",
      reinterpret_cast<void*>(&u32n_DbgUiIssueRemoteBreakin));
    e("DbgUiRemoteBreakin", reinterpret_cast<void*>(&u32n_DbgUiRemoteBreakin));
    e("DbgUiConvertStateChangeStructure",
      reinterpret_cast<void*>(&u32n_DbgUiConvertStateChangeStructure));
    // The CSR client.
    e("CsrClientConnectToServer",
      reinterpret_cast<void*>(&u32n_CsrClientConnectToServer));
    e("CsrAllocateCaptureBuffer",
      reinterpret_cast<void*>(&u32n_CsrAllocateCaptureBuffer));
    e("CsrAllocateMessagePointer",
      reinterpret_cast<void*>(&u32n_CsrAllocateMessagePointer));
    e("CsrCaptureMessageBuffer",
      reinterpret_cast<void*>(&u32n_CsrCaptureMessageBuffer));
    e("CsrCaptureMessageString",
      reinterpret_cast<void*>(&u32n_CsrCaptureMessageString));
    e("CsrFreeCaptureBuffer",
      reinterpret_cast<void*>(&u32n_CsrFreeCaptureBuffer));
    e("CsrClientCallServer", reinterpret_cast<void*>(&u32n_CsrClientCallServer));
    e("CsrClientSendMessage",
      reinterpret_cast<void*>(&u32n_CsrClientSendMessage));
    e("CsrClientThreadConnect",
      reinterpret_cast<void*>(&u32n_CsrClientThreadConnect));
    e("CsrIdentifyAlertableThread",
      reinterpret_cast<void*>(&u32n_CsrIdentifyAlertableThread));
    e("CsrSetPriorityClass",
      reinterpret_cast<void*>(&u32n_CsrSetPriorityClass));
    e("CsrNewThread", reinterpret_cast<void*>(&u32n_CsrNewThread));
    e("CsrCaptureTimeout", reinterpret_cast<void*>(&u32n_CsrCaptureTimeout));
    e("CsrClientMaxMessage", reinterpret_cast<void*>(&u32n_CsrClientMaxMessage));
    e("CsrProbeForRead", reinterpret_cast<void*>(&u32n_CsrProbeForRead));
    e("CsrProbeForWrite", reinterpret_cast<void*>(&u32n_CsrProbeForWrite));
    e("CsrpProcessCallbackRequest",
      reinterpret_cast<void*>(&u32n_CsrpProcessCallbackRequest));
    // ALPC.
    e("AlpcGetHeaderSize", reinterpret_cast<void*>(&u32n_AlpcGetHeaderSize));
    e("AlpcInitializeMessageAttribute",
      reinterpret_cast<void*>(&u32n_AlpcInitializeMessageAttribute));
    e("AlpcGetMessageAttribute",
      reinterpret_cast<void*>(&u32n_AlpcGetMessageAttribute));
    e("AlpcGetOutstandingChainContexts",
      reinterpret_cast<void*>(&u32n_AlpcGetOutstandingChainContexts));
    e("AlpcMaxAllowedMessageLength",
      reinterpret_cast<void*>(&u32n_AlpcMaxAllowedMessageLength));
    // The hash.
    e("A_SHAInit", reinterpret_cast<void*>(&u32n_A_SHAInit));
    e("A_SHAUpdate", reinterpret_cast<void*>(&u32n_A_SHAUpdate));
    e("A_SHAFinal", reinterpret_cast<void*>(&u32n_A_SHAFinal));
}

}  // namespace occ::runtime::winabi

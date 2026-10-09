// The WinSock surface: the sockets, the addresses, and the names.
//
// A Windows program that talks to the network reaches it through three
// layers, and this file carries all three. The bottom layer is the Berkeley
// socket calls -- `socket`, `connect`, `send`, `recv`, `select` -- which
// arrived in Winsock already named the way Unix names them and carry an
// ordinal from that ancestry: the first twenty-three ordinals of
// `ws2_32.dll` are that set, in the order the Berkeley header lists them,
// and a program that imports by ordinal is asking for one of those. The
// middle layer adds the Windows-shaped calls on top of the same sockets,
// which is where the handle-typed `SOCKET` lives. The top layer is name
// resolution, which turns a name into addresses.
//
// The translation between the guest's structures and the host's is the
// whole of the work in the lower two layers, and it is done by hand rather
// than by a cast. The two agree about the port, which is big-endian in both,
// and disagree about the order of every other field: `SOCKADDR_IN6` puts the
// flow-info before the address where the host puts it after, `fd_set` is a
// counted array of handles where the host's is a bitmap, and `timeval` holds
// two 32-bit fields where the host's holds two 64-bit ones. A cast between
// any of those pairs would compile, would work on the machine it was written
// on, and would be wrong on the first structure whose field order differed.
//
// Name resolution is delegated to the host's own resolver, and the socket
// calls to the host's own sockets. A resolver written here would have to
// carry a DNS client, a hosts-file reader and a cache of its own, and its
// answers would be a second opinion about a name the host has already been
// told how to resolve -- through its own configuration, which is the only
// place that knows. The same argument holds for the sockets themselves: the
// host's are the ones that reach the host's interfaces.
//
// What is not here, and why:
//
//   * The asynchronous message family -- `WSAAsyncSelect` and the six
//     `WSAAsyncGet*` calls -- delivers its result as a window message. This
//     runtime has no window procedure to deliver to, and answering without
//     one would leave a caller waiting for a message that cannot come.
//
//   * The namespace service provider family -- `WSALookupService*`,
//     `WSAInstallServiceClass*`, the `WSC*` set -- is the pluggable
//     directory layer, which on Windows is a set of registered providers
//     reachable through the registry. There is no registry store of
//     providers here, and inventing one would report a service the machine
//     does not have.
//
// Both are refused by name rather than by omission, so that a caller gets
// the error code the contract defines for an unsupported request instead of
// an import that fails to resolve.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/objects.h"
#include "occ/runtime/winabi.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

namespace occ::runtime::winabi {
namespace {

// --------------------------------------------------------------- the values
//
// Every number a guest passes in or reads back. They are written here rather
// than taken from a header because the host's numbers are the host's: the
// guest's `SO_REUSEADDR` is 4 and this machine's is 2, and a runtime that
// used one for the other would set a different option than the caller asked
// for.

// The socket handle base. A guest handle has to be distinguishable from
// every other handle this runtime mints, and it has to be distinguishable
// from `INVALID_SOCKET`, which is the all-ones value.
//
// The three ranges this runtime hands out are laid out so that they cannot
// meet: files start at 0x2000 and run for a megabyte, objects start at
// 0x200000, and sockets start here. The ranges are the whole of the
// distinction -- a socket passed to a file call has to miss the file range
// so that the call refuses it rather than reading the descriptor that
// happens to carry the same number.
constexpr std::uint64_t kSocketBase = 0x400000;
constexpr std::uint64_t kSocketSpan = 0x100000;
constexpr std::uint64_t kInvalidSocket = ~std::uint64_t(0);

// The address families and socket types, in the values a guest passes.
[[maybe_unused]] constexpr std::int32_t kAfUnspec = 0;
constexpr std::int32_t kAfInet = 2;
constexpr std::int32_t kAfInet6 = 23;
constexpr std::int32_t kSockStream = 1;
constexpr std::int32_t kSockDgram = 2;
constexpr std::int32_t kSockRaw = 3;

// The protocol numbers the two families use for the two stream types.
constexpr std::int32_t kIpprotoTcp = 6;
constexpr std::int32_t kIpprotoUdp = 17;

// The socket options, in the guest's numbering. The level is `SOL_SOCKET`
// for the first block, which Windows spells 0xFFFF, and the protocol number
// itself for the second.
constexpr std::int32_t kGuestSolSocket = 0xFFFF;
constexpr std::int32_t kGuestSoDebug = 0x0001;
constexpr std::int32_t kGuestSoAcceptConn = 0x0002;
constexpr std::int32_t kGuestSoReuseAddr = 0x0004;
constexpr std::int32_t kGuestSoKeepAlive = 0x0008;
constexpr std::int32_t kGuestSoDontRoute = 0x0010;
constexpr std::int32_t kGuestSoBroadcast = 0x0020;
constexpr std::int32_t kGuestSoLinger = 0x0080;
constexpr std::int32_t kGuestSoOobInline = 0x0100;
constexpr std::int32_t kGuestSoSndBuf = 0x1001;
constexpr std::int32_t kGuestSoRcvBuf = 0x1002;
constexpr std::int32_t kGuestSoSndLowAt = 0x1003;
constexpr std::int32_t kGuestSoRcvLowAt = 0x1004;
constexpr std::int32_t kGuestSoSndTimeo = 0x1005;
constexpr std::int32_t kGuestSoRcvTimeo = 0x1006;
constexpr std::int32_t kGuestSoError = 0x1007;
constexpr std::int32_t kGuestSoType = 0x1008;
constexpr std::int32_t kGuestTcpNoDelay = 0x0001;

// The control codes `ioctlsocket` answers. Only the three the contract
// defines are carried; the vendor-specific ones are refused below.
constexpr std::int32_t kGuestFionBio =
    static_cast<std::int32_t>(0x8004667Eu);
constexpr std::int32_t kGuestFionRead =
    static_cast<std::int32_t>(0x4004667Fu);
constexpr std::int32_t kGuestSiocAtMark =
    static_cast<std::int32_t>(0x40047307u);

// The message flags `recv`, `send` and their WSA forms take. Only the one
// whose two numbers differ is converted; the rest are the same bit in both
// headers and travel as they are.
constexpr std::int32_t kGuestMsgOob = 0x1;
constexpr std::int32_t kGuestMsgPeek = 0x2;
constexpr std::int32_t kGuestMsgDontRoute = 0x4;
constexpr std::int32_t kGuestMsgWaitAll = 0x8;

// The network event bits `WSAEventSelect` reports. They are also the bits
// `WSAEnumNetworkEvents` hands back and the ones `FD_ISSET` is a part of.
constexpr std::int32_t kFdRead = 0x01;
constexpr std::int32_t kFdWrite = 0x02;
constexpr std::int32_t kFdOob = 0x04;
constexpr std::int32_t kFdAccept = 0x08;
[[maybe_unused]] constexpr std::int32_t kFdConnect = 0x10;
constexpr std::int32_t kFdClose = 0x20;

// The `poll` events, in both numberings. The host's are a bitmap with the
// readable and writable bits in the low nibble; the guest's put the normal
// reads and writes above the errors.
constexpr std::int16_t kGuestPollRdnorm = 0x0100;
constexpr std::int16_t kGuestPollBand = 0x0200;
constexpr std::int16_t kGuestPollPri = 0x0400;
constexpr std::int16_t kGuestPollWrnorm = 0x0010;
constexpr std::int16_t kGuestPollWrband = 0x0020;
constexpr std::int16_t kGuestPollErr = 0x0001;
constexpr std::int16_t kGuestPollHup = 0x0002;
constexpr std::int16_t kGuestPollNval = 0x0004;

// The error codes this surface answers. They are the WinSock ones, which are
// not the Win32 ones: a caller here tests `WSAEWOULDBLOCK` and not
// `ERROR_IO_PENDING`, and answering with the wrong set would send it down
// the wrong branch.
constexpr std::int32_t kWsaIntr = 10004;
constexpr std::int32_t kWsaBadFile = 10009;
constexpr std::int32_t kWsaAccess = 10013;
constexpr std::int32_t kWsaFault = 10014;
constexpr std::int32_t kWsaInvalidArgument = 10022;
constexpr std::int32_t kWsaTooManyOpenFiles = 10024;
constexpr std::int32_t kWsaWouldBlock = 10035;
constexpr std::int32_t kWsaInProgress = 10036;
constexpr std::int32_t kWsaAlready = 10037;
constexpr std::int32_t kWsaNotSocket = 10038;
constexpr std::int32_t kWsaDestAddrRequired = 10039;
constexpr std::int32_t kWsaMessageSize = 10040;
constexpr std::int32_t kWsaProtocolType = 10041;
constexpr std::int32_t kWsaNoProtocolOption = 10042;
constexpr std::int32_t kWsaProtocolNotSupported = 10043;
constexpr std::int32_t kWsaSocketTypeNotSupported = 10044;
constexpr std::int32_t kWsaOperationNotSupported = 10045;
constexpr std::int32_t kWsaFamilyNotSupported = 10047;
constexpr std::int32_t kWsaAddressInUse = 10048;
constexpr std::int32_t kWsaAddressNotAvailable = 10049;
constexpr std::int32_t kWsaNetworkDown = 10050;
constexpr std::int32_t kWsaNetworkUnreachable = 10051;
constexpr std::int32_t kWsaNetworkReset = 10052;
constexpr std::int32_t kWsaConnectionAborted = 10053;
constexpr std::int32_t kWsaConnectionReset = 10054;
constexpr std::int32_t kWsaNoBufferSpace = 10055;
constexpr std::int32_t kWsaAlreadyConnected = 10056;
constexpr std::int32_t kWsaNotConnected = 10057;
constexpr std::int32_t kWsaShutdown = 10058;
constexpr std::int32_t kWsaTimedOut = 10060;
constexpr std::int32_t kWsaConnectionRefused = 10061;
constexpr std::int32_t kWsaHostDown = 10064;
constexpr std::int32_t kWsaHostUnreachable = 10065;
constexpr std::int32_t kWsaNotInitialised = 10093;
constexpr std::int32_t kWsaHostNotFound = 11001;
[[maybe_unused]] constexpr std::int32_t kWsaTryAgain = 11002;
[[maybe_unused]] constexpr std::int32_t kWsaNoRecovery = 11003;
constexpr std::int32_t kWsaNoData = 11004;

// The status `WSAWaitForMultipleEvents` answers with. They are the Win32
// wait codes, because that call is the synchronization one in Winsock
// clothing, and a caller compares its result against `WSA_WAIT_TIMEOUT`
// which is `WAIT_TIMEOUT`.
constexpr std::uint32_t kWsaWaitEvent0 = 0;
constexpr std::uint32_t kWsaWaitTimeout = 258;
constexpr std::uint32_t kWsaWaitFailed = 0xFFFFFFFFu;
constexpr std::uint32_t kWsaInfinite = 0xFFFFFFFFu;

// --------------------------------------------------------- the layouts
//
// The guest's structures, field by field. Each offset is written out and
// named because the whole of this file is the business of getting them
// right, and an offset written as a number in the middle of a function is
// the kind of thing that reads correctly and is not.

// SOCKADDR_IN is sixteen bytes: family, port (network order), address,
// eight bytes of padding. SOCKADDR_IN6 is twenty-eight: family, port, flow
// info, sixteen bytes of address, scope id.
constexpr std::size_t kSockaddrFamily = 0;
constexpr std::size_t kSockaddrPort = 2;
constexpr std::size_t kSockaddrAddr4 = 4;
constexpr std::size_t kSockaddrInBytes = 16;
constexpr std::size_t kSockaddrFlowInfo = 4;
constexpr std::size_t kSockaddrAddr6 = 8;
constexpr std::size_t kSockaddrScopeId = 24;
constexpr std::size_t kSockaddrIn6Bytes = 28;

// ADDRINFOW, the structure the resolver fills. `ai_addrlen` is a size, the
// two strings are pointers, and the address is a pointer to a SOCKADDR the
// caller frees through the same call that frees the list.
constexpr std::size_t kAddrInfoFlags = 0;
constexpr std::size_t kAddrInfoFamily = 4;
constexpr std::size_t kAddrInfoSockType = 8;
constexpr std::size_t kAddrInfoProtocol = 12;
constexpr std::size_t kAddrInfoAddrLen = 16;
constexpr std::size_t kAddrInfoCanonName = 24;
constexpr std::size_t kAddrInfoAddr = 32;
constexpr std::size_t kAddrInfoNext = 40;
constexpr std::size_t kAddrInfoBytes = 48;

// SOCKET_ADDRESS_LIST, the structure `SIO_ADDRESS_LIST_QUERY` fills.
//
// The count comes first, then four bytes of padding to bring the entries to
// their alignment, then one SOCKET_ADDRESS per address. Each entry is a
// pointer to a SOCKADDR -- which points into this same buffer, just past
// the entries -- followed by the length of that SOCKADDR and four bytes of
// padding. The entry is not the address; it is a reference to one, and a
// guest that read the pointer as the address itself would read a number.
constexpr std::size_t kAddressListCount = 0;
constexpr std::size_t kAddressListEntries = 8;
constexpr std::size_t kSocketAddressBytes = 16;
constexpr std::size_t kSocketAddressPointer = 0;
constexpr std::size_t kSocketAddressLength = 8;

// fd_set, as the guest lays it out: a count, four bytes of padding, and
// that many SOCKETs. The host's is a bitmap of 1024 descriptors, so the two
// have nothing in common beyond the name and every crossing between them is
// a conversion rather than a copy.
constexpr std::size_t kGuestFdSetCount = 0;
constexpr std::size_t kGuestFdSetArray = 8;
constexpr std::size_t kGuestFdSetLimit = 64;

// timeval, as the guest lays it out: two 32-bit fields. The host's are
// 64-bit, so a timeout that crossed unchanged would be read as a different
// number of seconds -- and a small one, because the high half of the
// seconds field would land on the microseconds.
constexpr std::size_t kGuestTimevalSeconds = 0;
constexpr std::size_t kGuestTimevalMicroseconds = 4;
[[maybe_unused]] constexpr std::size_t kGuestTimevalBytes = 8;
// WSABUF, as the guest lays it out: a length, four bytes of padding, and a
// pointer. The padding is the part that matters: a runtime that read the
// pointer at offset four would read the padding and the low half of the
// pointer as one address.
constexpr std::size_t kWsaBufLength = 0;
constexpr std::size_t kWsaBufBuffer = 8;
constexpr std::size_t kWsaBufBytes = 16;

// WSAPOLLFD: the socket, the events asked about, the events that happened.
constexpr std::size_t kPollFdSocket = 0;
constexpr std::size_t kPollFdEvents = 8;
constexpr std::size_t kPollFdRevents = 10;
constexpr std::size_t kPollFdBytes = 16;

// WSANETWORKEVENTS: the bits that happened, then one error code per bit.
constexpr std::size_t kNetworkEventsBits = 0;
[[maybe_unused]] constexpr std::size_t kNetworkEventsErrors = 8;
[[maybe_unused]] constexpr std::size_t kNetworkEventsSlots = 10;
constexpr std::size_t kNetworkEventsBytes = 48;

// WSADATA, which `WSAStartup` fills. The two version fields, two limits, a
// vendor pointer that this runtime leaves null, and two fixed-length
// strings.
constexpr std::size_t kWsaDataVersion = 0;
constexpr std::size_t kWsaDataHighVersion = 2;
constexpr std::size_t kWsaDataMaxSockets = 4;
constexpr std::size_t kWsaDataMaxUdp = 6;
constexpr std::size_t kWsaDataVendor = 8;
constexpr std::size_t kWsaDataDescription = 16;
constexpr std::size_t kWsaDataStatus = 273;

// The version this runtime reports: Winsock 2.2, which is what every
// program built this century asks for and what the calls above implement.
constexpr std::uint16_t kWinsockVersion = 0x0202;
constexpr std::uint16_t kWinsockMaxSockets = 0;
constexpr std::uint16_t kWinsockMaxUdpDatagram = 65535;

// The process's use of Winsock. Windows requires `WSAStartup` before any
// other call and refuses the rest until it has been made, which is a real
// check and not a formality: a program that skipped it would have a
// different bug on this runtime than on Windows, and the kind that takes a
// day to find.
std::atomic<std::int32_t> g_winsock_users {0};

// ------------------------------------------------------------ the errors

// The host's error, as the WinSock code that means the same thing. The two
// sets are not the same size: the guest distinguishes a network that is
// down from one that is unreachable from one that has been reset, and so
// does the host, but the numbers were chosen by different committees and
// several of the host's errors have no counterpart at all. The unpaired
// ones fall to the general failure rather than to a code that would send
// the caller down a branch about a condition that did not happen.
[[nodiscard]] std::int32_t wsa_error_from_errno(int error) noexcept {
    switch (error) {
        case 0:
            return 0;
        case EINTR:
            return kWsaIntr;
        case EBADF:
            return kWsaNotSocket;
        case EACCES:
        case EPERM:
            return kWsaAccess;
        case EFAULT:
            return kWsaFault;
        case EINVAL:
            return kWsaInvalidArgument;
        case EMFILE:
        case ENFILE:
            return kWsaTooManyOpenFiles;
        case EWOULDBLOCK:
            return kWsaWouldBlock;
        case EINPROGRESS:
            return kWsaInProgress;
        case EALREADY:
            return kWsaAlready;
        case ENOTSOCK:
            return kWsaNotSocket;
        case EDESTADDRREQ:
            return kWsaDestAddrRequired;
        case EMSGSIZE:
            return kWsaMessageSize;
        case EPROTOTYPE:
            return kWsaProtocolType;
        case ENOPROTOOPT:
            return kWsaNoProtocolOption;
        case EPROTONOSUPPORT:
            return kWsaProtocolNotSupported;
        case ESOCKTNOSUPPORT:
        case EPFNOSUPPORT:
            return kWsaSocketTypeNotSupported;
        case EOPNOTSUPP:
            return kWsaOperationNotSupported;
        case EAFNOSUPPORT:
            return kWsaFamilyNotSupported;
        case EADDRINUSE:
            return kWsaAddressInUse;
        case EADDRNOTAVAIL:
            return kWsaAddressNotAvailable;
        case ENETDOWN:
            return kWsaNetworkDown;
        case ENETUNREACH:
            return kWsaNetworkUnreachable;
        case ENETRESET:
            return kWsaNetworkReset;
        case ECONNABORTED:
            return kWsaConnectionAborted;
        case ECONNRESET:
            return kWsaConnectionReset;
        case ENOBUFS:
        case ENOMEM:
            return kWsaNoBufferSpace;
        case EISCONN:
            return kWsaAlreadyConnected;
        case ENOTCONN:
            return kWsaNotConnected;
        case ESHUTDOWN:
            return kWsaShutdown;
        case ETIMEDOUT:
            return kWsaTimedOut;
        case ECONNREFUSED:
            return kWsaConnectionRefused;
        case EHOSTDOWN:
            return kWsaHostDown;
        case EHOSTUNREACH:
            return kWsaHostUnreachable;
        case EIO:
            return kWsaBadFile;
        default:
            break;
    }
    return kWsaFault;
}

// The failure the caller just ran into, left where `WSAGetLastError` reads
// it. Every call below that reached the host and was refused by it ends
// here, so that the code a guest reads is the translation of the host's
// reason rather than a per-call guess.
[[nodiscard]] std::int32_t socket_failure() noexcept {
    const std::int32_t code = wsa_error_from_errno(errno);
    set_last_error(static_cast<std::uint32_t>(code));
    return code;
}

// A failure this runtime detected itself, with the code it already knows.
[[nodiscard]] std::int32_t socket_failure_code(std::int32_t code) noexcept {
    set_last_error(static_cast<std::uint32_t>(code));
    return code;
}

// ------------------------------------------------------------ the addresses

// Whether the handle names a socket this runtime opened.
//
// The check is the range and nothing else: a descriptor minted here is the
// range test's whole answer, because the other ranges cannot produce a
// value inside this one.
[[nodiscard]] bool socket_descriptor_of(std::uint64_t handle,
                                        int& fd) noexcept {
    if (handle < kSocketBase || handle >= kSocketBase + kSocketSpan) {
        return false;
    }
    fd = static_cast<int>(handle - kSocketBase);
    return true;
}

// The handle a freshly opened descriptor is presented as.
[[nodiscard]] std::uint64_t socket_handle_of(int fd) noexcept {
    return kSocketBase + static_cast<std::uint64_t>(fd);
}

// The family the guest asked for, as the host names it, or zero when the
// guest asked for a family this runtime does not carry. Every call that
// takes a family goes through here so that a family is spelled the same way
// at each.
[[nodiscard]] int host_family_of(std::int32_t guest_family) noexcept {
    if (guest_family == kAfInet) {
        return AF_INET;
    }
    if (guest_family == kAfInet6) {
        return AF_INET6;
    }
    return 0;
}

// How many bytes the guest form of an address of this family takes, or zero
// for a family this runtime cannot represent.
[[nodiscard]] std::size_t guest_address_bytes(int family) noexcept {
    if (family == AF_INET) {
        return kSockaddrInBytes;
    }
    if (family == AF_INET6) {
        return kSockaddrIn6Bytes;
    }
    return 0;
}

// A Windows address turned into the host's. Returns the family the host
// understood, or zero for an address this runtime cannot represent.
[[nodiscard]] int to_host_address(const void* address, std::size_t length,
                                  sockaddr_storage& out,
                                  socklen_t& out_length) noexcept {
    if (address == nullptr) {
        return 0;
    }
    const auto* bytes = static_cast<const std::uint8_t*>(address);
    const std::uint16_t family =
        static_cast<std::uint16_t>(read_u16(bytes, kSockaddrFamily));

    if (family == static_cast<std::uint16_t>(kAfInet)) {
        if (length < kSockaddrInBytes) {
            return 0;
        }
        auto* in4 = reinterpret_cast<sockaddr_in*>(&out);
        std::memset(in4, 0, sizeof(*in4));
        in4->sin_family = AF_INET;
        // The port is network order in both, so it travels as it is. The
        // address is four bytes either way and also travels unchanged; the
        // padding after it is the guest's and is not read.
        in4->sin_port = static_cast<in_port_t>(read_u16(bytes, kSockaddrPort));
        std::memcpy(&in4->sin_addr, bytes + kSockaddrAddr4, 4);
        out_length = sizeof(sockaddr_in);
        return AF_INET;
    }

    if (family == static_cast<std::uint16_t>(kAfInet6)) {
        if (length < kSockaddrIn6Bytes) {
            return 0;
        }
        auto* in6 = reinterpret_cast<sockaddr_in6*>(&out);
        std::memset(in6, 0, sizeof(*in6));
        in6->sin6_family = AF_INET6;
        in6->sin6_port = static_cast<in_port_t>(read_u16(bytes, kSockaddrPort));
        // The flow-info comes before the address in the guest's layout and
        // after it in the host's, which is the whole reason this is written
        // field by field.
        in6->sin6_flowinfo = read_u32(bytes, kSockaddrFlowInfo);
        std::memcpy(&in6->sin6_addr, bytes + kSockaddrAddr6, 16);
        in6->sin6_scope_id = read_u32(bytes, kSockaddrScopeId);
        out_length = sizeof(sockaddr_in6);
        return AF_INET6;
    }

    // An address family this runtime does not carry -- a Unix socket, an
    // infrared address, an AppKit one. Zero says so, and the caller turns it
    // into the refusal the guest's own error codes name.
    return 0;
}

// The host's address turned into a guest's. `capacity` is the room the
// caller left, which is the value it passed in through the length pointer.
[[nodiscard]] std::size_t from_host_address(const sockaddr_storage& address,
                                            void* out,
                                            std::size_t capacity) noexcept {
    if (out == nullptr) {
        return 0;
    }
    auto* bytes = static_cast<std::uint8_t*>(out);

    if (address.ss_family == AF_INET) {
        if (capacity < kSockaddrInBytes) {
            return 0;
        }
        const auto* in4 = reinterpret_cast<const sockaddr_in*>(&address);
        std::memset(bytes, 0, kSockaddrInBytes);
        write_u16(bytes, kSockaddrFamily, static_cast<std::uint16_t>(kAfInet));
        write_u16(bytes, kSockaddrPort, in4->sin_port);
        std::memcpy(bytes + kSockaddrAddr4, &in4->sin_addr, 4);
        return kSockaddrInBytes;
    }

    if (address.ss_family == AF_INET6) {
        if (capacity < kSockaddrIn6Bytes) {
            return 0;
        }
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(&address);
        std::memset(bytes, 0, kSockaddrIn6Bytes);
        write_u16(bytes, kSockaddrFamily,
                  static_cast<std::uint16_t>(kAfInet6));
        write_u16(bytes, kSockaddrPort, in6->sin6_port);
        write_u32(bytes, kSockaddrFlowInfo, in6->sin6_flowinfo);
        std::memcpy(bytes + kSockaddrAddr6, &in6->sin6_addr, 16);
        write_u32(bytes, kSockaddrScopeId, in6->sin6_scope_id);
        return kSockaddrIn6Bytes;
    }

    return 0;
}

// The host's address handed back to the guest through the pair of
// parameters `getpeername`, `getsockname` and `accept` share: a buffer and
// a length that is the buffer's room on the way in and the address's size
// on the way out.
//
// A caller that left too little room gets the size it needed written back
// and a refusal, which is the contract for this out-parameter -- and the
// reason the failure is a `false` here rather than a silent truncation,
// which would hand the caller a shorter address that describes a different
// machine.
[[nodiscard]] bool write_address_out(const sockaddr_storage& address,
                                     void* name, std::int32_t* length) noexcept {
    if (name == nullptr || length == nullptr) {
        return true;
    }
    const std::int32_t given = *length;
    const std::size_t capacity =
        given < 0 ? 0 : static_cast<std::size_t>(given);
    const std::size_t written = from_host_address(address, name, capacity);
    if (written == 0) {
        *length = static_cast<std::int32_t>(guest_address_bytes(address.ss_family));
        return false;
    }
    *length = static_cast<std::int32_t>(written);
    return true;
}

// Whether `WSAStartup` has been called. Every entry point below that uses a
// socket goes through here first, because the contract says so and because
// a program that skipped the call has a real bug that this runtime should
// report the same way the platform reports it.
[[nodiscard]] bool winsock_ready() noexcept {
    return g_winsock_users.load(std::memory_order_relaxed) > 0;
}

// ------------------------------------------------------------- the fd sets

// The guest's `fd_set` read into the host's, with the largest descriptor
// seen. `select` needs that largest value plus one, because the host's call
// takes a count where the guest's takes nothing -- the guest's `nfds` is
// ignored by Windows, and a runtime that passed the guest's number along
// would watch the wrong descriptors.
[[nodiscard]] bool read_fd_set(const void* set, ::fd_set& out,
                               int& max_fd) noexcept {
    FD_ZERO(&out);
    if (set == nullptr) {
        return true;
    }
    const auto* bytes = static_cast<const std::uint8_t*>(set);
    const std::uint32_t count = read_u32(bytes, kGuestFdSetCount);
    if (count > kGuestFdSetLimit) {
        return false;
    }
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::uint64_t handle =
            read_u64(bytes, kGuestFdSetArray + i * sizeof(std::uint64_t));
        int fd = 0;
        if (!socket_descriptor_of(handle, fd)) {
            // A handle that is not a socket. Windows ignores it here and
            // reports it through `WSAEnumNetworkEvents` instead; ignoring it
            // is what keeps a caller that passes a stale handle from
            // watching a descriptor the host has already given away.
            continue;
        }
        FD_SET(fd, &out);
        if (fd > max_fd) {
            max_fd = fd;
        }
    }
    return true;
}

// The host's answer written back into the guest's set. Only the descriptors
// the guest asked about survive, because the guest's structure is a list
// and the host's is a bitmap: the two cannot be copied over each other, and
// this walk is what makes the result a list again.
void write_fd_set(void* set, const ::fd_set& result,
                  const std::uint8_t* original) noexcept {
    if (set == nullptr || original == nullptr) {
        return;
    }
    auto* bytes = static_cast<std::uint8_t*>(set);
    const std::uint32_t count = read_u32(original, kGuestFdSetCount);
    const std::uint32_t bounded =
        count > kGuestFdSetLimit ? static_cast<std::uint32_t>(kGuestFdSetLimit)
                                 : count;
    std::uint32_t kept = 0;
    for (std::uint32_t i = 0; i < bounded; ++i) {
        const std::size_t at = kGuestFdSetArray + i * sizeof(std::uint64_t);
        const std::uint64_t handle = read_u64(original, at);
        int fd = 0;
        if (!socket_descriptor_of(handle, fd)) {
            continue;
        }
        if (!FD_ISSET(fd, &result)) {
            continue;
        }
        write_u64(bytes, kGuestFdSetArray + kept * sizeof(std::uint64_t),
                  handle);
        ++kept;
    }
    write_u32(bytes, kGuestFdSetCount, kept);
}

// The guest's timeout read into the host's. A null pointer means "wait
// forever", which is a different thing from a timeout of zero and is kept
// different all the way to the host's call.
[[nodiscard]] bool read_timeout(const void* timeout, ::timeval& out) noexcept {
    if (timeout == nullptr) {
        return false;
    }
    const auto* bytes = static_cast<const std::uint8_t*>(timeout);
    const std::int32_t seconds =
        static_cast<std::int32_t>(read_u32(bytes, kGuestTimevalSeconds));
    const std::int32_t microseconds =
        static_cast<std::int32_t>(read_u32(bytes, kGuestTimevalMicroseconds));
    out.tv_sec = seconds < 0 ? 0 : seconds;
    out.tv_usec = microseconds < 0 ? 0 : microseconds;
    return true;
}

// The milliseconds a socket option carries, as the host's `timeval`. The
// two surfaces disagree about how a receive timeout is spelled: the guest
// passes a count of milliseconds, the host takes a structure, and a runtime
// that handed the count over unchanged would set a timeout of a few
// microseconds and a program that expected to block would spin instead.
[[nodiscard]] bool milliseconds_to_timeval(const void* value,
                                           ::timeval& out) noexcept {
    if (value == nullptr) {
        return false;
    }
    const std::uint32_t milliseconds = read_u32(value, 0);
    out.tv_sec = static_cast<time_t>(milliseconds / 1000u);
    out.tv_usec = static_cast<long>(milliseconds % 1000u) * 1000L;
    return true;
}

// The reverse, for a socket option being read back.
void timeval_to_milliseconds(const ::timeval& value, void* out) noexcept {
    const std::uint64_t total = static_cast<std::uint64_t>(value.tv_sec) * 1000u +
                                static_cast<std::uint64_t>(value.tv_usec) / 1000u;
    write_u32(out, 0, total > 0xFFFFFFFFu ? 0xFFFFFFFFu
                                          : static_cast<std::uint32_t>(total));
}

}  // namespace

// ----------------------------------------------------- the Berkeley layer
//
// The first twenty-three ordinals, in the order the Berkeley header lists
// them. Each of these is a thin conversion and nothing else: the call the
// host makes is the same call, and the work here is turning the guest's
// parameters into the host's and the host's answer back.

extern "C" __attribute__((ms_abi)) std::uint64_t k32ws_socket(
    std::int32_t family, std::int32_t type, std::int32_t protocol) noexcept {
    if (!winsock_ready()) {
        set_last_error(kWsaNotInitialised);
        return kInvalidSocket;
    }

    const int host_family = host_family_of(family);
    if (host_family == 0) {
        set_last_error(kWsaFamilyNotSupported);
        return kInvalidSocket;
    }

    int host_type = 0;
    switch (type) {
        case kSockStream:
            host_type = SOCK_STREAM;
            break;
        case kSockDgram:
            host_type = SOCK_DGRAM;
            break;
        case kSockRaw:
            host_type = SOCK_RAW;
            break;
        default:
            set_last_error(kWsaSocketTypeNotSupported);
            return kInvalidSocket;
    }

    // A zero protocol means "the one that goes with this type", which the
    // host's own call resolves the same way. Resolving it here rather than
    // passing the zero along keeps the two from disagreeing about a raw
    // socket, where the host would refuse the zero.
    const int host_protocol =
        protocol != 0 ? protocol : (type == kSockStream ? kIpprotoTcp
                                                        : kIpprotoUdp);

    const int fd = ::socket(host_family, host_type, host_protocol);
    if (fd < 0) {
        static_cast<void>(socket_failure());
        return kInvalidSocket;
    }

    set_last_error(0);
    return socket_handle_of(fd);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_bind(
    std::uint64_t socket, const void* name, std::int32_t name_length) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }

    sockaddr_storage address {};
    socklen_t address_length = 0;
    const std::size_t given =
        name_length <= 0 ? 0 : static_cast<std::size_t>(name_length);
    if (to_host_address(name, given, address, address_length) == 0) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    if (::bind(fd, reinterpret_cast<const sockaddr*>(&address),
               address_length) != 0) {
        return socket_failure();
    }

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_listen(
    std::uint64_t socket, std::int32_t backlog) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }

    // The host's backlog and the guest's are the same idea with the same
    // limit, and a negative one is what the guest writes for "the largest
    // the system allows".
    if (::listen(fd, backlog < 0 ? SOMAXCONN : backlog) != 0) {
        return socket_failure();
    }

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32ws_accept(
    std::uint64_t socket, void* name, std::int32_t* name_length) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        set_last_error(kWsaNotSocket);
        return kInvalidSocket;
    }

    sockaddr_storage address {};
    socklen_t address_length = sizeof(address);
    const int accepted = ::accept(fd, reinterpret_cast<sockaddr*>(&address),
                                  &address_length);
    if (accepted < 0) {
        static_cast<void>(socket_failure());
        return kInvalidSocket;
    }

    if (!write_address_out(address, name, name_length)) {
        // The address did not fit the caller's buffer. The connection has
        // already been established, so it is closed rather than handed out
        // with the wrong address attached to it.
        ::close(accepted);
        static_cast<void>(socket_failure_code(kWsaFault));
        return kInvalidSocket;
    }

    set_last_error(0);
    return socket_handle_of(accepted);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_connect(
    std::uint64_t socket, const void* name, std::int32_t name_length) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }

    sockaddr_storage address {};
    socklen_t address_length = 0;
    const std::size_t given =
        name_length <= 0 ? 0 : static_cast<std::size_t>(name_length);
    if (to_host_address(name, given, address, address_length) == 0) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    if (::connect(fd, reinterpret_cast<const sockaddr*>(&address),
                  address_length) != 0) {
        return socket_failure();
    }

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_closesocket(
    std::uint64_t socket) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }

    // Closing is the one call that cannot be retried. A descriptor the host
    // has already given away is not closed a second time, because the
    // number may by now belong to something else.
    if (::close(fd) != 0) {
        // The host refuses a descriptor it does not own. That is not a
        // failure the guest can act on, and the contract calls it a
        // successful close of a socket that was already gone.
        set_last_error(0);
        return 0;
    }

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_getsockname(
    std::uint64_t socket, void* name, std::int32_t* name_length) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }

    sockaddr_storage address {};
    socklen_t address_length = sizeof(address);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&address),
                      &address_length) != 0) {
        return socket_failure();
    }

    if (!write_address_out(address, name, name_length)) {
        return socket_failure_code(kWsaFault);
    }

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_getpeername(
    std::uint64_t socket, void* name, std::int32_t* name_length) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }

    sockaddr_storage address {};
    socklen_t address_length = sizeof(address);
    if (::getpeername(fd, reinterpret_cast<sockaddr*>(&address),
                      &address_length) != 0) {
        return socket_failure();
    }

    if (!write_address_out(address, name, name_length)) {
        return socket_failure_code(kWsaFault);
    }

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_shutdown(
    std::uint64_t socket, std::int32_t how) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }

    // The guest's numbers: zero stops reading, one stops writing, two stops
    // both. The host's structure carries them in the same order under the
    // same names, so only the bounds are checked here.
    if (how < SHUT_RD || how > SHUT_RDWR) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    if (::shutdown(fd, how) != 0) {
        return socket_failure();
    }

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_ioctlsocket(
    std::uint64_t socket, std::int32_t command, void* argument) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }

    // Setting the blocking mode. Both surfaces take a 32-bit flag where
    // non-zero means non-blocking, so the value travels and only the
    // request number is translated -- and the request number is the one
    // place where the two numberings have nothing in common.
    if (command == kGuestFionBio) {
        if (argument == nullptr) {
            return socket_failure_code(kWsaFault);
        }
        const std::uint32_t non_blocking = read_u32(argument, 0);
        const int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags < 0) {
            return socket_failure();
        }
        const int updated = non_blocking != 0 ? (flags | O_NONBLOCK)
                                              : (flags & ~O_NONBLOCK);
        if (::fcntl(fd, F_SETFL, updated) != 0) {
            return socket_failure();
        }
        set_last_error(0);
        return 0;
    }

    // How many bytes can be read without blocking. The answer is a 32-bit
    // count in both surfaces, so the request number is again the whole of
    // the translation.
    if (command == kGuestFionRead) {
        if (argument == nullptr) {
            return socket_failure_code(kWsaFault);
        }
        int available = 0;
        if (::ioctl(fd, FIONREAD, &available) != 0) {
            return socket_failure();
        }
        write_u32(argument, 0, static_cast<std::uint32_t>(available));
        set_last_error(0);
        return 0;
    }

    // Whether the read position is at the out-of-band mark. The answer is a
    // flag in both, and the request numbers differ.
    if (command == kGuestSiocAtMark) {
        if (argument == nullptr) {
            return socket_failure_code(kWsaFault);
        }
        int at_mark = 0;
        if (::ioctl(fd, SIOCATMARK, &at_mark) != 0) {
            return socket_failure();
        }
        write_u32(argument, 0, at_mark != 0 ? 1u : 0u);
        set_last_error(0);
        return 0;
    }

    // Every other request: the routing table, the interface list, the
    // binding cache. They are Windows' own additions to the interface, and
    // answering one with a plausible empty buffer would report a machine
    // with no routes rather than a runtime that cannot say.
    return socket_failure_code(kWsaInvalidArgument);
}

// ---------------------------------------------------------- the byte order
//
// Four calls that are the whole of the difference between the two machines'
// idea of a number on the wire. The host has the same operations under the
// same names, but calling them would be calling them through the host's
// headers for a value the guest assembled -- and on a little-endian host
// the two are the same swap either way, so the implementations are written
// out rather than borrowed.

extern "C" __attribute__((ms_abi)) std::uint32_t k32ws_htonl(
    std::uint32_t value) noexcept {
    return __builtin_bswap32(value);
}

extern "C" __attribute__((ms_abi)) std::uint16_t k32ws_htons(
    std::uint16_t value) noexcept {
    return __builtin_bswap16(value);
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32ws_ntohl(
    std::uint32_t value) noexcept {
    // The swap is its own inverse, so the two names are two spellings of
    // one operation. They are kept apart because a caller reads the name as
    // documentation of which direction the value is travelling.
    return __builtin_bswap32(value);
}

extern "C" __attribute__((ms_abi)) std::uint16_t k32ws_ntohs(
    std::uint16_t value) noexcept {
    return __builtin_bswap16(value);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSAHtonl(
    std::uint64_t socket, std::uint32_t host_value,
    std::uint32_t* network_value) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }
    if (network_value == nullptr) {
        return socket_failure_code(kWsaFault);
    }
    write_u32(network_value, 0, __builtin_bswap32(host_value));
    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSAHtons(
    std::uint64_t socket, std::uint16_t host_value,
    std::uint16_t* network_value) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }
    if (network_value == nullptr) {
        return socket_failure_code(kWsaFault);
    }
    write_u16(network_value, 0, __builtin_bswap16(host_value));
    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSANtohl(
    std::uint64_t socket, std::uint32_t network_value,
    std::uint32_t* host_value) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }
    if (host_value == nullptr) {
        return socket_failure_code(kWsaFault);
    }
    write_u32(host_value, 0, __builtin_bswap32(network_value));
    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSANtohs(
    std::uint64_t socket, std::uint16_t network_value,
    std::uint16_t* host_value) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }
    if (host_value == nullptr) {
        return socket_failure_code(kWsaFault);
    }
    write_u16(host_value, 0, __builtin_bswap16(network_value));
    set_last_error(0);
    return 0;
}

// ------------------------------------------------ the textual addresses
//
// The two conversions between an address and the text a person types.
// `inet_addr` and `inet_ntoa` are the old pair, with the awkward calling
// conventions of their age: one takes a string and answers a number in
// network order, the other takes an address by value and answers a pointer
// into storage the caller does not own.

extern "C" __attribute__((ms_abi)) std::uint32_t k32ws_inet_addr(
    const char* text) noexcept {
    if (text == nullptr) {
        set_last_error(kWsaInvalidArgument);
        return 0xFFFFFFFFu;
    }

    // The older spelling accepts the short forms -- "127.1", "0x7f.1" --
    // which is a property a caller may be relying on, and the host's
    // `inet_aton` has the same acceptance.
    ::in_addr parsed {};
    if (::inet_aton(text, &parsed) == 0) {
        set_last_error(kWsaInvalidArgument);
        return 0xFFFFFFFFu;
    }

    // The address is already in network order, which is what this function
    // promises to answer: it is the address as it would go on the wire, in
    // a 32-bit word.
    set_last_error(0);
    return parsed.s_addr;
}

extern "C" __attribute__((ms_abi)) char* k32ws_inet_ntoa(
    std::uint32_t address) noexcept {
    // The buffer is the caller's to read and this runtime's to own, which
    // is why it is thread-local: two threads formatting two addresses at
    // once must not overwrite each other's answer.
    thread_local char text[16] {};

    ::in_addr value {};
    value.s_addr = address;
    if (::inet_ntop(AF_INET, &value, text, sizeof(text)) == nullptr) {
        set_last_error(kWsaInvalidArgument);
        return nullptr;
    }

    set_last_error(0);
    return text;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_inet_pton(
    std::int32_t family, const char* text, void* address) noexcept {
    if (text == nullptr || address == nullptr) {
        return 0;
    }
    const int host_family = host_family_of(family);
    if (host_family == 0) {
        set_last_error(kWsaFamilyNotSupported);
        return -1;
    }

    // The host's call answers exactly what the guest's does: one for a
    // parsed address, zero for text that is not one, and minus one for a
    // family it does not know.
    const int parsed = ::inet_pton(host_family, text, address);
    if (parsed < 0) {
        static_cast<void>(socket_failure());
        return -1;
    }
    set_last_error(0);
    return parsed;
}

extern "C" __attribute__((ms_abi)) const char* k32ws_inet_ntop(
    std::int32_t family, const void* address, char* text,
    std::size_t text_bytes) noexcept {
    if (address == nullptr || text == nullptr) {
        return nullptr;
    }
    const int host_family = host_family_of(family);
    if (host_family == 0) {
        set_last_error(kWsaFamilyNotSupported);
        return nullptr;
    }
    if (::inet_ntop(host_family, address, text,
                    static_cast<socklen_t>(text_bytes)) == nullptr) {
        static_cast<void>(socket_failure());
        return nullptr;
    }
    set_last_error(0);
    return text;
}

extern "C" __attribute__((ms_abi)) const char16_t* k32ws_InetNtopW(
    std::int32_t family, const void* address, char16_t* text,
    std::size_t text_chars) noexcept {
    if (address == nullptr || text == nullptr) {
        return nullptr;
    }
    const int host_family = host_family_of(family);
    if (host_family == 0) {
        set_last_error(kWsaFamilyNotSupported);
        return nullptr;
    }

    // The host writes the text as bytes; the guest reads it as characters.
    // The exchange happens in the smaller space and is widened into the
    // caller's, because the largest an address can be written is 46
    // characters and a heap allocation for that would be a heap allocation
    // per call.
    char narrow[64] {};
    if (::inet_ntop(host_family, address, narrow, sizeof(narrow)) == nullptr) {
        static_cast<void>(socket_failure());
        return nullptr;
    }

    std::size_t at = 0;
    while (narrow[at] != '\0') {
        if (at + 1 >= text_chars) {
            // The caller's buffer cannot hold the text and its terminator.
            // The refusal is the share of the contract that says the size
            // is in characters.
            static_cast<void>(socket_failure_code(kWsaInvalidArgument));
            return nullptr;
        }
        text[at] = static_cast<char16_t>(
            static_cast<unsigned char>(narrow[at]));
        ++at;
    }
    text[at] = u'\0';
    set_last_error(0);
    return text;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_InetPtonW(
    std::int32_t family, const char16_t* text, void* address) noexcept {
    if (text == nullptr || address == nullptr) {
        return 0;
    }
    const int host_family = host_family_of(family);
    if (host_family == 0) {
        set_last_error(kWsaFamilyNotSupported);
        return -1;
    }

    // The exchange here is the other way round, and the narrow form is
    // built first for the same reason.
    char narrow[64] {};
    std::size_t at = 0;
    while (text[at] != u'\0') {
        if (at + 1 >= sizeof(narrow)) {
            set_last_error(kWsaInvalidArgument);
            return 0;
        }
        const char16_t unit = text[at];
        if (unit > 0x7F) {
            // An address is ASCII. A wider character is not one, and the
            // contract's answer for text that is not an address is zero.
            set_last_error(0);
            return 0;
        }
        narrow[at] = static_cast<char>(unit);
        ++at;
    }
    narrow[at] = '\0';

    const int parsed = ::inet_pton(host_family, narrow, address);
    if (parsed < 0) {
        static_cast<void>(socket_failure());
        return -1;
    }
    set_last_error(0);
    return parsed;
}

// --------------------------------------------------------- the socket options
//
// The two surfaces agree about what a socket option is and disagree about
// every number involved: the level, the option, and for two of them the
// shape of the value. The translation is a table rather than a formula,
// because the numbers were chosen independently and there is no relation
// between them to compute.

// The host's level and option for a guest's pair, or false when this
// runtime does not carry that option.
[[nodiscard]] bool host_socket_option(std::int32_t level, std::int32_t option,
                                      int& host_level,
                                      int& host_option) noexcept {
    if (level == kGuestSolSocket) {
        host_level = SOL_SOCKET;
        switch (option) {
            case kGuestSoDebug:
                host_option = SO_DEBUG;
                return true;
            case kGuestSoAcceptConn:
                host_option = SO_ACCEPTCONN;
                return true;
            case kGuestSoReuseAddr:
                host_option = SO_REUSEADDR;
                return true;
            case kGuestSoKeepAlive:
                host_option = SO_KEEPALIVE;
                return true;
            case kGuestSoDontRoute:
                host_option = SO_DONTROUTE;
                return true;
            case kGuestSoBroadcast:
                host_option = SO_BROADCAST;
                return true;
            case kGuestSoLinger:
                host_option = SO_LINGER;
                return true;
            case kGuestSoOobInline:
                host_option = SO_OOBINLINE;
                return true;
            case kGuestSoSndBuf:
                host_option = SO_SNDBUF;
                return true;
            case kGuestSoRcvBuf:
                host_option = SO_RCVBUF;
                return true;
            case kGuestSoSndLowAt:
                host_option = SO_SNDLOWAT;
                return true;
            case kGuestSoRcvLowAt:
                host_option = SO_RCVLOWAT;
                return true;
            case kGuestSoSndTimeo:
                host_option = SO_SNDTIMEO;
                return true;
            case kGuestSoRcvTimeo:
                host_option = SO_RCVTIMEO;
                return true;
            case kGuestSoError:
                host_option = SO_ERROR;
                return true;
            case kGuestSoType:
                host_option = SO_TYPE;
                return true;
            default:
                return false;
        }
    }

    // `TCP_NODELAY` is the one protocol-level option a program sets for
    // latency, and its number is the same in both headers. The rest of the
    // protocol options are refused rather than guessed at, because a wrong
    // option number here is a socket that behaves differently for reasons
    // nothing in the program explains.
    if (level == kIpprotoTcp && option == kGuestTcpNoDelay) {
        host_level = IPPROTO_TCP;
        host_option = TCP_NODELAY;
        return true;
    }

    return false;
}

// Whether a guest option carries its value as a count of milliseconds,
// which the host spells as a structure.
[[nodiscard]] bool option_is_timeout(std::int32_t level,
                                     std::int32_t option) noexcept {
    return level == kGuestSolSocket &&
           (option == kGuestSoSndTimeo || option == kGuestSoRcvTimeo);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_setsockopt(
    std::uint64_t socket, std::int32_t level, std::int32_t option,
    const void* value, std::int32_t value_bytes) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }
    if (value == nullptr || value_bytes < 0) {
        return socket_failure_code(kWsaFault);
    }

    int host_level = 0;
    int host_option = 0;
    if (!host_socket_option(level, option, host_level, host_option)) {
        return socket_failure_code(kWsaNoProtocolOption);
    }

    if (option_is_timeout(level, option)) {
        if (static_cast<std::size_t>(value_bytes) < 4) {
            return socket_failure_code(kWsaInvalidArgument);
        }
        ::timeval timeout {};
        static_cast<void>(milliseconds_to_timeval(value, timeout));
        if (::setsockopt(fd, host_level, host_option, &timeout,
                         sizeof(timeout)) != 0) {
            return socket_failure();
        }
        set_last_error(0);
        return 0;
    }

    if (::setsockopt(fd, host_level, host_option, value,
                     static_cast<socklen_t>(value_bytes)) != 0) {
        return socket_failure();
    }

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_getsockopt(
    std::uint64_t socket, std::int32_t level, std::int32_t option,
    void* value, std::int32_t* value_bytes) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }
    if (value == nullptr || value_bytes == nullptr) {
        return socket_failure_code(kWsaFault);
    }

    int host_level = 0;
    int host_option = 0;
    if (!host_socket_option(level, option, host_level, host_option)) {
        return socket_failure_code(kWsaNoProtocolOption);
    }

    const std::int32_t given = *value_bytes;
    if (given < 0) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    if (option_is_timeout(level, option)) {
        if (given < 4) {
            *value_bytes = 4;
            return socket_failure_code(kWsaFault);
        }
        ::timeval timeout {};
        socklen_t timeout_bytes = sizeof(timeout);
        if (::getsockopt(fd, host_level, host_option, &timeout,
                         &timeout_bytes) != 0) {
            return socket_failure();
        }
        timeval_to_milliseconds(timeout, value);
        *value_bytes = 4;
        set_last_error(0);
        return 0;
    }

    socklen_t host_bytes = static_cast<socklen_t>(given);
    if (::getsockopt(fd, host_level, host_option, value, &host_bytes) != 0) {
        return socket_failure();
    }
    *value_bytes = static_cast<std::int32_t>(host_bytes);

    set_last_error(0);
    return 0;
}

// ------------------------------------------------------------- the transfer
//
// Sending and receiving, in the four shapes the Berkeley layer defines. The
// flags travel through a conversion because one of them -- the wait-for-all
// bit -- sits in a different place in the two headers, and a value copied
// across unchanged would ask the host for a flag it does not have.

// The guest's message flags as the host's.
[[nodiscard]] int host_message_flags(std::int32_t flags) noexcept {
    int host = 0;
    if ((flags & kGuestMsgOob) != 0) {
        host |= MSG_OOB;
    }
    if ((flags & kGuestMsgPeek) != 0) {
        host |= MSG_PEEK;
    }
    if ((flags & kGuestMsgDontRoute) != 0) {
        host |= MSG_DONTROUTE;
    }
    if ((flags & kGuestMsgWaitAll) != 0) {
        host |= MSG_WAITALL;
    }
    return host;
}

// The flags a call answered with, as the guest's. Only the bits this
// runtime understands survive, so that a caller comparing against a bit it
// knows cannot be told about one it does not.
[[nodiscard]] std::int32_t guest_message_flags(int host) noexcept {
    std::int32_t guest = 0;
    if ((host & MSG_OOB) != 0) {
        guest |= kGuestMsgOob;
    }
    if ((host & MSG_PEEK) != 0) {
        guest |= kGuestMsgPeek;
    }
    if ((host & MSG_DONTROUTE) != 0) {
        guest |= kGuestMsgDontRoute;
    }
    return guest;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_send(
    std::uint64_t socket, const void* data, std::int32_t bytes,
    std::int32_t flags) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }
    if (data == nullptr && bytes > 0) {
        return socket_failure_code(kWsaFault);
    }
    if (bytes < 0) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    // A zero-length send is a successful send of nothing on both surfaces,
    // and the host is not asked about it because a null buffer with a zero
    // count is not a pointer the host accepts.
    if (bytes == 0) {
        set_last_error(0);
        return 0;
    }

    const ssize_t sent = ::send(fd, data, static_cast<std::size_t>(bytes),
                                host_message_flags(flags));
    if (sent < 0) {
        return socket_failure();
    }

    set_last_error(0);
    return static_cast<std::int32_t>(sent);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_recv(
    std::uint64_t socket, void* data, std::int32_t bytes,
    std::int32_t flags) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }
    if (data == nullptr && bytes > 0) {
        return socket_failure_code(kWsaFault);
    }
    if (bytes < 0) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    if (bytes == 0) {
        // Reading into nothing is a successful read of nothing, but a
        // connected stream that has been closed reports it here, which is
        // how a caller learns the peer is gone.
        char probe = 0;
        const ssize_t read =
            ::recv(fd, &probe, 0, host_message_flags(flags) | MSG_PEEK);
        if (read == 0) {
            set_last_error(0);
            return 0;
        }
        if (read < 0 && errno != EWOULDBLOCK) {
            return socket_failure();
        }
        set_last_error(0);
        return 0;
    }

    const ssize_t read = ::recv(fd, data, static_cast<std::size_t>(bytes),
                                host_message_flags(flags));
    if (read < 0) {
        return socket_failure();
    }

    set_last_error(0);
    return static_cast<std::int32_t>(read);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_sendto(
    std::uint64_t socket, const void* data, std::int32_t bytes,
    std::int32_t flags, const void* to, std::int32_t to_length) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }
    if (data == nullptr && bytes > 0) {
        return socket_failure_code(kWsaFault);
    }
    if (bytes < 0) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    sockaddr_storage address {};
    socklen_t address_length = 0;
    const std::size_t given =
        to_length <= 0 ? 0 : static_cast<std::size_t>(to_length);
    const int family = to_host_address(to, given, address, address_length);

    // A datagram can be sent without a destination when the socket has been
    // connected, and the contract says so by allowing a null address.
    const bool has_destination = family != 0;
    if (to != nullptr && !has_destination) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    if (bytes == 0) {
        set_last_error(0);
        return 0;
    }

    const ssize_t sent = ::sendto(
        fd, data, static_cast<std::size_t>(bytes), host_message_flags(flags),
        has_destination ? reinterpret_cast<const sockaddr*>(&address) : nullptr,
        has_destination ? address_length : 0);
    if (sent < 0) {
        return socket_failure();
    }

    set_last_error(0);
    return static_cast<std::int32_t>(sent);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_recvfrom(
    std::uint64_t socket, void* data, std::int32_t bytes, std::int32_t flags,
    void* from, std::int32_t* from_length) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }
    if (data == nullptr && bytes > 0) {
        return socket_failure_code(kWsaFault);
    }
    if (bytes < 0) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    sockaddr_storage address {};
    socklen_t address_length = sizeof(address);
    const ssize_t read = ::recvfrom(
        fd, data, static_cast<std::size_t>(bytes), host_message_flags(flags),
        reinterpret_cast<sockaddr*>(&address), &address_length);
    if (read < 0) {
        return socket_failure();
    }

    if (!write_address_out(address, from, from_length)) {
        return socket_failure_code(kWsaFault);
    }

    set_last_error(0);
    return static_cast<std::int32_t>(read);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_select(
    std::int32_t nfds, void* read_set, void* write_set, void* except_set,
    const void* timeout) noexcept {
    // The first parameter is the one Windows documents and ignores: the
    // host's call takes the count of descriptors to watch, and the guest's
    // takes a number that every caller sets to zero. The host's count is
    // computed below from the descriptors themselves, which is the only
    // honest source for it.
    static_cast<void>(nfds);

    if (read_set == nullptr && write_set == nullptr && except_set == nullptr) {
        // A wait on nothing at all. The contract calls this an invalid
        // argument rather than a sleep of the requested length, and a
        // runtime that slept would look like a hang to the caller.
        return socket_failure_code(kWsaInvalidArgument);
    }

    int max_fd = -1;
    ::fd_set host_read;
    ::fd_set host_write;
    ::fd_set host_except;

    if (!read_fd_set(read_set, host_read, max_fd) ||
        !read_fd_set(write_set, host_write, max_fd) ||
        !read_fd_set(except_set, host_except, max_fd)) {
        // A set claiming more descriptors than the structure holds. The
        // caller's memory is not walked past its end for a number it wrote.
        return socket_failure_code(kWsaInvalidArgument);
    }

    ::timeval host_timeout {};
    const bool waiting = read_timeout(timeout, host_timeout);

    const int ready = ::select(
        max_fd + 1, read_set != nullptr ? &host_read : nullptr,
        write_set != nullptr ? &host_write : nullptr,
        except_set != nullptr ? &host_except : nullptr,
        waiting ? &host_timeout : nullptr);
    if (ready < 0) {
        return socket_failure();
    }

    // The sets are written back through the guest's originals, because the
    // guest's structure is a list and the host's answer is a bitmap: the
    // descriptors that survived are the ones that were in the list and are
    // set in the bitmap.
    write_fd_set(read_set, host_read, static_cast<const std::uint8_t*>(read_set));
    write_fd_set(write_set, host_write,
                 static_cast<const std::uint8_t*>(write_set));
    write_fd_set(except_set, host_except,
                 static_cast<const std::uint8_t*>(except_set));

    // The timeout is written back too, with what is left of it: a caller
    // that loops on `select` uses the leftover to bound the whole wait, and
    // a runtime that left the original value there would loop for a full
    // timeout each time.
    if (waiting && timeout != nullptr) {
        write_u32(const_cast<void*>(timeout), kGuestTimevalSeconds,
                  static_cast<std::uint32_t>(host_timeout.tv_sec));
        write_u32(const_cast<void*>(timeout), kGuestTimevalMicroseconds,
                  static_cast<std::uint32_t>(host_timeout.tv_usec));
    }

    set_last_error(0);
    return ready;
}

// ------------------------------------------------------------ the process
//
// `WSAStartup` and the four calls around it. They are the process-level
// part of Winsock: the version negotiation, the use count, and the error
// code a caller reads between calls.

// The refusal for a version this runtime does not implement. It is a
// separate code from the general failure because the contract gives it one
// and a caller turns it into a message about the library rather than about
// the call.
constexpr std::int32_t kWsaVersionNotSupported = 10092;

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSAStartup(
    std::uint16_t requested, void* data) noexcept {
    if (data == nullptr) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    // The request is a major version in the low byte and a minor in the
    // high one, which is the opposite of how the bytes read and is the
    // reason the two are pulled apart rather than compared as a number: as
    // a number, a request for 2.0 would sort below one for 1.1.
    const std::uint16_t major = requested & 0x00FFu;
    const std::uint16_t minor = static_cast<std::uint16_t>(requested >> 8);
    if (major < 1 || (major == 1 && minor < 1) || major > 2) {
        return socket_failure_code(kWsaVersionNotSupported);
    }

    // The structure as the guest lays it out: two versions, two limits, a
    // vendor pointer this runtime leaves null, and two fixed-length
    // strings. The whole of it is cleared first, so that the bytes past the
    // strings are zeros rather than whatever the caller's stack held.
    std::memset(data, 0, kWsaDataStatus + 129);

    // The version granted is the one asked for when it is 1.1, and 2.2 when
    // the caller asked for any 2.x -- the contract's rule is that the answer
    // is the highest the runtime supports that is not above the request.
    const std::uint16_t granted = major == 1 ? 0x0101 : kWinsockVersion;
    write_u16(data, kWsaDataVersion, granted);
    write_u16(data, kWsaDataHighVersion, kWinsockVersion);
    write_u16(data, kWsaDataMaxSockets, kWinsockMaxSockets);
    write_u16(data, kWsaDataMaxUdp, kWinsockMaxUdpDatagram);
    write_ptr(data, kWsaDataVendor, 0);

    const std::string_view description = "occ WinSock 2.2";
    for (std::size_t i = 0; i < description.size(); ++i) {
        write_u8(data, kWsaDataDescription + i,
                 static_cast<std::uint8_t>(description[i]));
    }
    const std::string_view status = "Running";
    for (std::size_t i = 0; i < status.size(); ++i) {
        write_u8(data, kWsaDataStatus + i, static_cast<std::uint8_t>(status[i]));
    }

    g_winsock_users.fetch_add(1, std::memory_order_relaxed);
    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSACleanup() noexcept {
    // The count is decremented only when there is one to decrement. A
    // caller that cleans up more often than it starts up is making a
    // mistake the contract answers with a code, and a runtime that let the
    // count go negative would then refuse every later `socket` for a reason
    // that is not about the caller at all.
    std::int32_t current = g_winsock_users.load(std::memory_order_relaxed);
    for (;;) {
        if (current <= 0) {
            return socket_failure_code(kWsaNotInitialised);
        }
        if (g_winsock_users.compare_exchange_weak(current, current - 1,
                                                  std::memory_order_relaxed)) {
            break;
        }
    }

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSAIsBlocking() noexcept {
    // Whether a blocking call is in progress on this thread. This runtime's
    // calls do not go through a hook, so the question has one answer, and
    // it is the same answer Windows gives for a thread that is not inside
    // one of the hookable calls.
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws___WSAFDIsSet(
    std::uint64_t socket, const void* set) noexcept {
    if (set == nullptr) {
        return 0;
    }
    const auto* bytes = static_cast<const std::uint8_t*>(set);
    const std::uint32_t count = read_u32(bytes, kGuestFdSetCount);
    const std::uint32_t bounded =
        count > kGuestFdSetLimit ? static_cast<std::uint32_t>(kGuestFdSetLimit)
                                 : count;
    for (std::uint32_t i = 0; i < bounded; ++i) {
        const std::uint64_t entry =
            read_u64(bytes, kGuestFdSetArray + i * sizeof(std::uint64_t));
        if (entry == socket) {
            return 1;
        }
    }
    return 0;
}

// ------------------------------------------------------------- the events
//
// The event half of the asynchronous model: an event object a caller waits
// on, and the association between a socket and the event that says what
// happened to it.
//
// The objects themselves are this runtime's own event objects -- the same
// ones `CreateEventW` makes -- because a `WSAEVENT` is a waitable handle on
// Windows too, and a caller passes one to `WaitForSingleObject` after
// getting it here. A second implementation would be a second kind of
// event, and the two would not wake each other's waiters.
//
// The association is watched by a thread this file starts on the first use.
// It polls the associated descriptors and sets the event when one of the
// conditions the caller asked about has happened, which is what the
// contract describes -- the difference being that Windows learns about it
// from the stack and this runtime has to look. Twenty milliseconds is the
// interval: short enough that a program polling in a loop does not measure
// it, long enough that an idle program does not burn a core.

extern "C" __attribute__((ms_abi)) std::uint64_t k32_CreateEventW(
    std::uint64_t attributes, std::int32_t manual_reset,
    std::int32_t initial_state, const char16_t* name) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32_CloseHandle(
    std::uint64_t handle) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32_SetEvent(
    std::uint64_t handle) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32_ResetEvent(
    std::uint64_t handle) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32_WaitForSingleObject(
    std::uint64_t handle, std::uint32_t milliseconds) noexcept;
extern "C" __attribute__((ms_abi)) void k32_SetLastError(
    std::uint32_t error) noexcept;

namespace {

// One socket's association with one event, and what has happened to it
// since the last time the caller asked.
struct EventSelect {
    int fd = 0;
    std::uint64_t event = 0;
    std::int32_t mask = 0;
    std::int32_t fired = 0;
    bool listening = false;
};

std::mutex& bindings_mutex() noexcept {
    static std::mutex guard;
    return guard;
}

std::vector<EventSelect>& bindings() noexcept {
    static std::vector<EventSelect> table;
    return table;
}

std::atomic<bool> g_watcher_started {false};

void sleep_milliseconds(std::uint32_t milliseconds) noexcept {
    timespec request {};
    request.tv_sec = static_cast<time_t>(milliseconds / 1000u);
    request.tv_nsec = static_cast<long>(milliseconds % 1000u) * 1000000L;
    while (::nanosleep(&request, &request) < 0 && errno == EINTR) {
        // Restart with what is left: the signal consumed part of the wait.
    }
}

// The bits a poll result stands for, translated into the network events the
// contract names.
[[nodiscard]] std::int32_t network_events_of(const ::pollfd& probe,
                                             bool listening) noexcept {
    std::int32_t bits = 0;
    const short failed = POLLERR | POLLHUP | POLLNVAL;
    if ((probe.revents & (POLLIN | POLLRDNORM | failed)) != 0) {
        // On a listening socket the same condition means a connection is
        // waiting rather than data is waiting, which is the one place where
        // the meaning of a readable descriptor depends on the socket.
        bits |= listening ? kFdAccept : kFdRead;
    }
    if ((probe.revents & (POLLOUT | POLLWRNORM | POLLERR)) != 0) {
        bits |= kFdWrite;
    }
    if ((probe.revents & POLLPRI) != 0) {
        bits |= kFdOob;
    }
    if ((probe.revents & failed) != 0) {
        bits |= kFdClose;
    }
    return bits;
}

// The watching thread. It runs for the life of the process once started: a
// program that has stopped associating sockets still has its events, and
// stopping and restarting the thread would be a state machine with no
// purpose.
void* event_watcher(void* unused) noexcept {
    static_cast<void>(unused);
    for (;;) {
        {
            const std::lock_guard<std::mutex> guard(bindings_mutex());
            for (EventSelect& entry : bindings()) {
                ::pollfd probe {};
                probe.fd = entry.fd;
                probe.events = POLLIN | POLLOUT | POLLPRI | POLLERR | POLLHUP |
                               POLLNVAL;
                if (::poll(&probe, 1, 0) <= 0) {
                    continue;
                }
                const std::int32_t bits = network_events_of(probe, entry.listening);
                const std::int32_t fresh = bits & entry.mask & ~entry.fired;
                if (fresh == 0) {
                    continue;
                }
                // The bits are recorded before the event is set, so that a
                // waiter woken by the event finds them already there.
                entry.fired |= fresh;
                static_cast<void>(objects::set_event(entry.event));
            }
        }
        sleep_milliseconds(20);
    }
    return nullptr;
}

// The watcher's start, once. A failure to start it leaves the associations
// recorded and unserved, which is what a program that never sees its event
// would have to diagnose; the alternative -- refusing the association --
// would take the error to the caller at the moment it asked for the socket
// rather than at the moment it needed it.
void start_event_watcher() noexcept {
    bool expected = false;
    if (!g_watcher_started.compare_exchange_strong(expected, true)) {
        return;
    }
    pthread_t thread {};
    if (pthread_create(&thread, nullptr, &event_watcher, nullptr) == 0) {
        pthread_detach(thread);
    }
}

// The association for a descriptor, or null.
[[nodiscard]] EventSelect* find_binding(int fd) noexcept {
    for (EventSelect& entry : bindings()) {
        if (entry.fd == fd) {
            return &entry;
        }
    }
    return nullptr;
}

// Whether this socket is one a caller is listening on, which changes the
// meaning of a readable descriptor.
[[nodiscard]] bool socket_is_listening(int fd) noexcept {
    int accepting = 0;
    socklen_t bytes = sizeof(accepting);
    if (::getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &bytes) != 0) {
        return false;
    }
    return accepting != 0;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint64_t k32ws_WSACreateEvent() noexcept {
    return k32_CreateEventW(0, 1, 0, nullptr);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSACloseEvent(
    std::uint64_t event) noexcept {
    {
        const std::lock_guard<std::mutex> guard(bindings_mutex());
        std::vector<EventSelect>& table = bindings();
        for (std::size_t i = 0; i < table.size(); ++i) {
            if (table[i].event != event) {
                continue;
            }
            table.erase(table.begin() + static_cast<std::ptrdiff_t>(i));
            break;
        }
    }
    return k32_CloseHandle(event);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSASetEvent(
    std::uint64_t event) noexcept {
    return k32_SetEvent(event);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSAResetEvent(
    std::uint64_t event) noexcept {
    return k32_ResetEvent(event);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSAEventSelect(
    std::uint64_t socket, std::uint64_t event, std::int32_t mask) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }
    if (mask != 0 && event == 0) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    // The socket is put into non-blocking mode, which is the part of this
    // call a program actually depends on: the model is "the event tells
    // you, and then you read without blocking".
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        static_cast<void>(::fcntl(fd, F_SETFL, flags | O_NONBLOCK));
    }

    {
        const std::lock_guard<std::mutex> guard(bindings_mutex());
        EventSelect* existing = find_binding(fd);
        if (mask == 0) {
            // A mask of zero ends the association, which is how a caller
            // takes a socket back out of the model.
            if (existing != nullptr) {
                std::vector<EventSelect>& table = bindings();
                for (std::size_t i = 0; i < table.size(); ++i) {
                    if (table[i].fd == fd) {
                        table.erase(table.begin() +
                                    static_cast<std::ptrdiff_t>(i));
                        break;
                    }
                }
            }
            set_last_error(0);
            return 0;
        }

        if (existing == nullptr) {
            EventSelect fresh;
            fresh.fd = fd;
            fresh.event = event;
            fresh.mask = mask;
            fresh.fired = 0;
            fresh.listening = socket_is_listening(fd);
            bindings().push_back(fresh);
        } else {
            existing->event = event;
            existing->mask = mask;
            // The bits that were recorded for a mask the caller has now
            // changed are dropped, because a caller that narrowed its
            // interest did not ask to hear about the old one on the next
            // enquiry.
            existing->fired &= mask;
            existing->listening = socket_is_listening(fd);
        }
    }

    start_event_watcher();
    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSAEnumNetworkEvents(
    std::uint64_t socket, std::uint64_t event, void* events) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }

    // The event is reset first, so that anything that happens between this
    // moment and the caller's next wait sets it again rather than being
    // folded into an event that is about to be cleared.
    if (event != 0) {
        static_cast<void>(k32_ResetEvent(event));
    }

    std::int32_t fired = 0;
    {
        const std::lock_guard<std::mutex> guard(bindings_mutex());
        EventSelect* entry = find_binding(fd);
        if (entry != nullptr) {
            fired = entry->fired;
            entry->fired = 0;
        }
    }

    if (events != nullptr) {
        std::memset(events, 0, kNetworkEventsBytes);
        write_u32(events, kNetworkEventsBits,
                  static_cast<std::uint32_t>(fired));
    }

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32ws_WSAWaitForMultipleEvents(
    std::uint32_t count, const std::uint64_t* events, std::int32_t wait_all,
    std::uint32_t timeout, std::int32_t alertable) noexcept {
    static_cast<void>(alertable);
    if (count == 0 || count > 64 || events == nullptr) {
        set_last_error(kWsaInvalidArgument);
        return kWsaWaitFailed;
    }

    // The wait is a poll over the event objects, because this runtime has
    // no single wait that spans them: each is asked about in turn, and the
    // whole is retried until the timeout runs out. A millisecond between
    // rounds keeps a caller that is waiting on a slow event from spinning.
    std::uint64_t waited = 0;
    for (;;) {
        std::uint32_t signalled = 0;
        for (std::uint32_t i = 0; i < count; ++i) {
            if (objects::wait_one(events[i], 0) ==
                objects::WaitOutcome::Signalled) {
                ++signalled;
                if (wait_all == 0) {
                    set_last_error(0);
                    return kWsaWaitEvent0 + i;
                }
            }
        }
        if (wait_all != 0 && signalled == count) {
            set_last_error(0);
            return kWsaWaitEvent0;
        }

        if (timeout != kWsaInfinite && waited >= timeout) {
            set_last_error(0);
            return kWsaWaitTimeout;
        }

        sleep_milliseconds(1);
        ++waited;
    }
}

// --------------------------------------------------------- the WSA transfer
//
// The same transfer as above, in the shape that carries a scatter-gather
// list and an overlapped structure. The list is the part that needed new
// code: a `WSABUF` array sends one message from several buffers, and the
// host's equivalent is the vectored call.

// One call's worth of the guest's buffers, gathered into the host's
// scatter-gather form. The pointers are the guest's own -- this runtime and
// the guest share an address space, so a buffer the guest named is a buffer
// the host can write to.
[[nodiscard]] bool gather_buffers(const void* buffers,
                                  std::uint32_t count,
                                  std::vector<::iovec>& out) noexcept {
    out.clear();
    if (count == 0) {
        return true;
    }
    if (buffers == nullptr || count > 1024) {
        return false;
    }
    out.reserve(count);
    const auto* base = static_cast<const std::uint8_t*>(buffers);
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::uint8_t* entry = base + i * kWsaBufBytes;
        ::iovec slice {};
        slice.iov_base =
            reinterpret_cast<void*>(read_ptr(entry, kWsaBufBuffer));
        slice.iov_len = read_u32(entry, kWsaBufLength);
        out.push_back(slice);
    }
    return true;
}

// The overlapped structure told how a call ended.
//
// The call has already completed by the time this runs -- this runtime's
// sockets are blocking, so the answer is in hand -- and what is left is to
// leave it where the contract says a completed operation leaves it, and to
// set the event the caller attached to the structure. A caller that waits
// on that event rather than on the call finds it already signalled, which
// is the correct description of an operation that has finished.
void complete_overlapped(void* overlapped, std::uint32_t bytes,
                         std::uint32_t error) noexcept {
    if (overlapped == nullptr) {
        return;
    }
    write_u32(overlapped, OverlappedLayout::kInternal, error);
    write_u32(overlapped, OverlappedLayout::kInternalHigh, bytes);
    const std::uint64_t event = read_ptr(overlapped, OverlappedLayout::kEvent);
    if (event != 0) {
        static_cast<void>(objects::set_event(event));
    }
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSARecv(
    std::uint64_t socket, const void* buffers, std::uint32_t buffer_count,
    std::uint32_t* received, std::uint32_t* flags, void* overlapped,
    void* completion) noexcept {
    // The completion routine is the third way an operation reports itself
    // done. This runtime completes in the caller's thread, so the routine
    // has nothing to be deferred to, and the call's own answer carries the
    // result; a routine that was promised a later call would never get one.
    static_cast<void>(completion);

    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }

    std::vector<::iovec> slices;
    if (!gather_buffers(buffers, buffer_count, slices)) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    ::msghdr message {};
    message.msg_iov = slices.empty() ? nullptr : slices.data();
    message.msg_iovlen = slices.size();

    const std::int32_t guest_flags =
        flags == nullptr ? 0 : static_cast<std::int32_t>(read_u32(flags, 0));
    const ssize_t read =
        ::recvmsg(fd, &message, host_message_flags(guest_flags));
    if (read < 0) {
        const std::int32_t code = socket_failure();
        complete_overlapped(overlapped, 0, static_cast<std::uint32_t>(code));
        return -1;
    }

    if (received != nullptr) {
        write_u32(received, 0, static_cast<std::uint32_t>(read));
    }
    if (flags != nullptr) {
        write_u32(flags, 0,
                  static_cast<std::uint32_t>(guest_message_flags(message.msg_flags)
                                             | (guest_flags & kGuestMsgPeek)));
    }
    complete_overlapped(overlapped, static_cast<std::uint32_t>(read), 0);

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSASend(
    std::uint64_t socket, const void* buffers, std::uint32_t buffer_count,
    std::uint32_t* sent, std::uint32_t flags, void* overlapped,
    void* completion) noexcept {
    static_cast<void>(completion);

    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }

    std::vector<::iovec> slices;
    if (!gather_buffers(buffers, buffer_count, slices)) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    ::msghdr message {};
    message.msg_iov = slices.empty() ? nullptr : slices.data();
    message.msg_iovlen = slices.size();

    const ssize_t written = ::sendmsg(
        fd, &message, host_message_flags(static_cast<std::int32_t>(flags)));
    if (written < 0) {
        const std::int32_t code = socket_failure();
        complete_overlapped(overlapped, 0, static_cast<std::uint32_t>(code));
        return -1;
    }

    if (sent != nullptr) {
        write_u32(sent, 0, static_cast<std::uint32_t>(written));
    }
    complete_overlapped(overlapped, static_cast<std::uint32_t>(written), 0);

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSARecvFrom(
    std::uint64_t socket, const void* buffers, std::uint32_t buffer_count,
    std::uint32_t* received, std::uint32_t* flags, void* from,
    std::int32_t* from_length, void* overlapped, void* completion) noexcept {
    static_cast<void>(completion);

    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }

    std::vector<::iovec> slices;
    if (!gather_buffers(buffers, buffer_count, slices)) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    sockaddr_storage address {};
    socklen_t address_length = sizeof(address);
    ::msghdr message {};
    message.msg_iov = slices.empty() ? nullptr : slices.data();
    message.msg_iovlen = slices.size();
    message.msg_name = &address;
    message.msg_namelen = address_length;

    const std::int32_t guest_flags =
        flags == nullptr ? 0 : static_cast<std::int32_t>(read_u32(flags, 0));
    const ssize_t read =
        ::recvmsg(fd, &message, host_message_flags(guest_flags));
    if (read < 0) {
        const std::int32_t code = socket_failure();
        complete_overlapped(overlapped, 0, static_cast<std::uint32_t>(code));
        return -1;
    }

    if (received != nullptr) {
        write_u32(received, 0, static_cast<std::uint32_t>(read));
    }
    if (flags != nullptr) {
        write_u32(flags, 0,
                  static_cast<std::uint32_t>(guest_message_flags(message.msg_flags)
                                             | (guest_flags & kGuestMsgPeek)));
    }
    if (!write_address_out(address, from, from_length)) {
        return socket_failure_code(kWsaFault);
    }
    complete_overlapped(overlapped, static_cast<std::uint32_t>(read), 0);

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSASendTo(
    std::uint64_t socket, const void* buffers, std::uint32_t buffer_count,
    std::uint32_t* sent, std::uint32_t flags, const void* to,
    std::int32_t to_length, void* overlapped, void* completion) noexcept {
    static_cast<void>(completion);

    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }

    std::vector<::iovec> slices;
    if (!gather_buffers(buffers, buffer_count, slices)) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    sockaddr_storage address {};
    socklen_t address_length = 0;
    const std::size_t given =
        to_length <= 0 ? 0 : static_cast<std::size_t>(to_length);
    const int family = to_host_address(to, given, address, address_length);
    if (to != nullptr && family == 0) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    ::msghdr message {};
    message.msg_iov = slices.empty() ? nullptr : slices.data();
    message.msg_iovlen = slices.size();
    if (family != 0) {
        message.msg_name = &address;
        message.msg_namelen = address_length;
    }

    const ssize_t written = ::sendmsg(
        fd, &message, host_message_flags(static_cast<std::int32_t>(flags)));
    if (written < 0) {
        const std::int32_t code = socket_failure();
        complete_overlapped(overlapped, 0, static_cast<std::uint32_t>(code));
        return -1;
    }

    if (sent != nullptr) {
        write_u32(sent, 0, static_cast<std::uint32_t>(written));
    }
    complete_overlapped(overlapped, static_cast<std::uint32_t>(written), 0);

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSAGetOverlappedResult(
    std::uint64_t socket, const void* overlapped, std::uint32_t* transferred,
    std::int32_t wait, std::uint32_t* flags) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }
    static_cast<void>(fd);
    if (overlapped == nullptr || transferred == nullptr) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    // The event is waited on when the caller asked to wait, which is the
    // whole of the difference between the two forms of the call: one
    // reports the operation now, the other waits for it first.
    if (wait != 0) {
        const std::uint64_t event =
            read_ptr(overlapped, OverlappedLayout::kEvent);
        if (event != 0) {
            static_cast<void>(k32_WaitForSingleObject(event, kWsaInfinite));
        }
    }

    const std::uint32_t status =
        static_cast<std::uint32_t>(read_u32(overlapped, OverlappedLayout::kInternal));
    const std::uint32_t bytes = static_cast<std::uint32_t>(
        read_u32(overlapped, OverlappedLayout::kInternalHigh));
    write_u32(transferred, 0, bytes);
    if (flags != nullptr) {
        write_u32(flags, 0, 0);
    }

    if (status != 0) {
        set_last_error(status);
        return 0;
    }

    set_last_error(0);
    return 1;
}

// -------------------------------------------------------------- the poll
//
// `WSAPoll` was added to Winsock to fix what `select` cannot express, and
// its structure is the host's `pollfd` with the fields in a different order
// and a socket where the host has a descriptor.

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSAPoll(
    void* entries, std::uint32_t count, std::int32_t timeout) noexcept {
    if (entries == nullptr || count == 0 || count > 1024) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    auto* base = static_cast<std::uint8_t*>(entries);
    std::vector<::pollfd> probes(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::size_t at = i * kPollFdBytes;
        const std::uint64_t handle = read_u64(base, at + kPollFdSocket);
        int fd = 0;
        if (!socket_descriptor_of(handle, fd)) {
            return socket_failure_code(kWsaNotSocket);
        }
        probes[i].fd = fd;
        probes[i].events = 0;

        const auto wanted = static_cast<std::uint16_t>(
            read_u16(base, at + kPollFdEvents));
        // The host's bits are few and the guest's are many, and the mapping
        // is a set of conditionals because the two group the conditions
        // differently: a normal read is one bit here and the same bit as
        // "readable" there.
        if ((wanted & (kGuestPollRdnorm | kGuestPollBand)) != 0) {
            probes[i].events |= POLLIN;
        }
        if ((wanted & kGuestPollPri) != 0) {
            probes[i].events |= POLLPRI;
        }
        if ((wanted & (kGuestPollWrnorm | kGuestPollWrband)) != 0) {
            probes[i].events |= POLLOUT;
        }
        // The three error conditions are reported by the host whether they
        // were asked about or not, so there is nothing to set for them here;
        // they are read out of the result below.
        write_u16(base, at + kPollFdRevents, 0);
    }

    const int ready = ::poll(probes.data(), probes.size(), timeout);
    if (ready < 0) {
        return socket_failure();
    }

    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint16_t guest = 0;
        const short host = probes[i].revents;
        if ((host & (POLLIN | POLLRDNORM)) != 0) {
            guest |= kGuestPollRdnorm;
        }
        if ((host & POLLPRI) != 0) {
            guest |= kGuestPollPri;
        }
        if ((host & (POLLOUT | POLLWRNORM)) != 0) {
            guest |= kGuestPollWrnorm;
        }
        if ((host & POLLERR) != 0) {
            guest |= kGuestPollErr;
        }
        if ((host & POLLHUP) != 0) {
            guest |= kGuestPollHup;
        }
        if ((host & POLLNVAL) != 0) {
            guest |= kGuestPollNval;
        }
        write_u16(base, i * kPollFdBytes + kPollFdRevents, guest);
    }

    set_last_error(0);
    return ready;
}

// ------------------------------------------------------------ the variants
//
// `WSASocketA` and `WSAAccept` are the two calls where the Windows-shaped
// layer adds something the Berkeley one does not have. `WSASocketA` is the
// narrow spelling of a call that is already here; `WSAAccept` is a
// conditional acceptance, where the guest decides whether to take a
// connection by running its own code.

extern "C" __attribute__((ms_abi)) std::uint64_t k32ws_WSASocketW(
    std::int32_t family, std::int32_t type, std::int32_t protocol,
    void* protocol_info, std::uint32_t group, std::uint32_t flags) noexcept {
    // The three settings this layer adds over the Berkeley call. They
    // describe a protocol chain, a socket group, and the flags that ask for
    // an overlapped or handle-less socket. This runtime opens a blocking
    // socket with a handle in every case, so a caller that asked for one of
    // the other behaviours gets the plain socket and finds out from its
    // first overlapped call, rather than being refused a socket it can use
    // for everything else.
    static_cast<void>(protocol_info);
    static_cast<void>(group);
    static_cast<void>(flags);
    return k32ws_socket(family, type, protocol);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32ws_WSASocketA(
    std::int32_t family, std::int32_t type, std::int32_t protocol,
    void* protocol_info, std::uint32_t group, std::uint32_t flags) noexcept {
    // The narrow spelling of the same call. There is nothing in the
    // parameters to convert -- they are all numbers -- so this is the wide
    // one under another name.
    return k32ws_WSASocketW(family, type, protocol, protocol_info, group, flags);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSAConnect(
    std::uint64_t socket, const void* name, std::int32_t name_length,
    void* caller_data, std::uint32_t caller_length, void* callee_data,
    std::uint32_t* callee_length) noexcept {
    // The caller's own connection data. The layer this call belongs to
    // carries it into the connection request itself; the host's call has no
    // room for it, so it is left where the caller put it rather than being
    // reported as sent.
    static_cast<void>(caller_data);
    static_cast<void>(caller_length);

    if (k32ws_connect(socket, name, name_length) != 0) {
        return -1;
    }

    if (callee_data != nullptr && callee_length != nullptr) {
        // The peer's own response data. A stream socket has none, and the
        // zero length says so rather than leaving the caller's capacity in
        // the out-parameter as though it had been filled.
        *callee_length = 0;
    }

    set_last_error(0);
    return 0;
}

// The type a `WSAAccept` condition routine has. It is the guest's own code,
// called from here, so the attribute matters: without it the call would be
// made with the host's convention and the guest would read its arguments
// out of the wrong registers.
using ConditionProc = std::int32_t(__attribute__((ms_abi))*)(
    void* caller_id, void* caller_data, void* socket_qos, void* group_qos,
    void* callee_id, void* callee_data, std::uint32_t* group,
    std::uint64_t callback_data);

// What a condition routine answers with. A rejection throws the connection
// away and the call looks at the next one; a deferral leaves it in the
// queue and reports that there is nothing to hand back yet.
constexpr std::int32_t kCfAccept = 0;
constexpr std::int32_t kCfReject = 1;
constexpr std::int32_t kCfDefer = 2;

extern "C" __attribute__((ms_abi)) std::uint64_t k32ws_WSAAccept(
    std::uint64_t socket, void* name, std::int32_t* name_length,
    void* condition, std::uint64_t callback_data) noexcept {
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        set_last_error(kWsaNotSocket);
        return kInvalidSocket;
    }

    if (condition == nullptr) {
        return k32ws_accept(socket, name, name_length);
    }

    const auto decide = reinterpret_cast<ConditionProc>(condition);
    for (;;) {
        sockaddr_storage address {};
        socklen_t address_length = sizeof(address);
        const int accepted = ::accept(fd, reinterpret_cast<sockaddr*>(&address),
                                      &address_length);
        if (accepted < 0) {
            static_cast<void>(socket_failure());
            return kInvalidSocket;
        }

        // The caller's address, as the condition routine reads it: a
        // WSABUF whose pointer is the address and whose length is its size.
        // The guest's own structure, laid out here because the routine is
        // guest code and reads what a guest would have been given.
        std::uint8_t caller_id[kWsaBufBytes] {};
        std::uint8_t address_copy[kSockaddrIn6Bytes] {};
        const std::size_t address_bytes =
            from_host_address(address, address_copy, sizeof(address_copy));
        write_u32(caller_id, kWsaBufLength,
                  static_cast<std::uint32_t>(address_bytes));
        write_ptr(caller_id, kWsaBufBuffer,
                  reinterpret_cast<std::uint64_t>(address_copy));

        std::uint32_t group = 0;
        const std::int32_t verdict =
            decide(caller_id, nullptr, nullptr, nullptr, nullptr, nullptr,
                   &group, callback_data);

        if (verdict == kCfAccept) {
            if (!write_address_out(address, name, name_length)) {
                ::close(accepted);
                static_cast<void>(socket_failure_code(kWsaFault));
                return kInvalidSocket;
            }
            set_last_error(0);
            return socket_handle_of(accepted);
        }

        // A rejection and a deferral both leave this runtime holding a
        // connection the guest did not take, so both close it. They differ
        // in what the caller is told: a rejection means "keep looking" and
        // a deferral means "ask again later".
        ::close(accepted);
        if (verdict == kCfDefer) {
            static_cast<void>(socket_failure_code(kWsaWouldBlock));
            return kInvalidSocket;
        }
        if (verdict != kCfReject) {
            // A routine that answered with something that is not one of the
            // three answers. The contract has no meaning for it, and
            // treating it as a rejection would hand the caller a connection
            // the routine did not agree to.
            static_cast<void>(socket_failure_code(kWsaInvalidArgument));
            return kInvalidSocket;
        }
    }
}

// ------------------------------------------------------------- the control
//
// `WSAIoctl` is the escape hatch of the socket layer: one call with a
// hundred numbered requests behind it. The requests a program makes in
// ordinary work are the two that ask about the machine's own addressing --
// `SIO_ADDRESS_LIST_QUERY` for the addresses it can send from, and
// `SIO_GET_INTERFACE_LIST` for the interfaces those addresses are on --
// and those two are carried. The rest are refused by number rather than
// answered with an empty buffer, because an empty answer to "which routes
// do you have" reads as a machine with none.

// One local address, in the host's form, gathered for the list below.
struct LocalAddress {
    sockaddr_storage address {};
    std::size_t bytes = 0;
};

// The addresses this machine can send from, filtered to one family. An
// interface that is down carries no address; one that is up carries the
// address a program would bind to, which is the only useful answer.
[[nodiscard]] std::vector<LocalAddress> local_addresses(int family) noexcept {
    std::vector<LocalAddress> gathered;
    ::ifaddrs* interfaces = nullptr;
    if (::getifaddrs(&interfaces) != 0) {
        return gathered;
    }
    for (::ifaddrs* it = interfaces; it != nullptr; it = it->ifa_next) {
        if (it->ifa_addr == nullptr) {
            continue;
        }
        if (it->ifa_addr->sa_family != family) {
            continue;
        }
        if ((it->ifa_flags & IFF_UP) == 0) {
            continue;
        }
        const std::size_t bytes = guest_address_bytes(it->ifa_addr->sa_family);
        if (bytes == 0) {
            continue;
        }
        LocalAddress entry;
        std::memcpy(&entry.address, it->ifa_addr,
                    family == AF_INET ? sizeof(sockaddr_in)
                                      : sizeof(sockaddr_in6));
        entry.bytes = bytes;
        gathered.push_back(entry);
    }
    ::freeifaddrs(interfaces);
    return gathered;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSAIoctl(
    std::uint64_t socket, std::uint32_t code, void* in_buffer,
    std::uint32_t in_size, void* out_buffer, std::uint32_t out_size,
    std::uint32_t* returned, void* overlapped,
    void* completion_routine) noexcept {
    // The two halves of the asynchronous form, which a blocking socket does
    // not use: the overlapped structure and the routine that would be
    // called when it completed. A request that asks for a non-blocking
    // answer is refused below rather than answered as though it had
    // finished.
    static_cast<void>(in_buffer);
    static_cast<void>(in_size);
    static_cast<void>(overlapped);
    static_cast<void>(completion_routine);

    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }
    if (returned != nullptr) {
        *returned = 0;
    }

    // `SIO_ADDRESS_LIST_QUERY`: the addresses this machine can send from.
    // It is the query an ordinary program makes -- it is how a server
    // decides which interface to bind and how a client picks a source
    // address. The comparison reads the function byte alone, because the
    // vendor tag above it is the same for every Winsock code and a guest
    // built against an older header may not set the direction bit; the
    // function is the part that identifies the request.
    constexpr std::uint32_t kAddressListQuery = 0x48000016u;
    constexpr std::uint32_t kControlFunctionMask = 0x000000FFu;
    if ((code & kControlFunctionMask) ==
        (kAddressListQuery & kControlFunctionMask)) {
        if (out_buffer == nullptr) {
            return socket_failure_code(kWsaInvalidArgument);
        }

        // The family the socket was opened for decides which addresses
        // belong in the answer. `getsockname` answers it even for a socket
        // that was never bound, because the family is fixed at creation.
        sockaddr_storage self {};
        socklen_t self_length = sizeof(self);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&self),
                          &self_length) != 0) {
            return socket_failure();
        }
        const std::size_t self_bytes = guest_address_bytes(self.ss_family);
        if (self_bytes == 0) {
            return socket_failure_code(kWsaFamilyNotSupported);
        }

        std::vector<LocalAddress> local = local_addresses(self.ss_family);
        if (local.empty()) {
            // A machine whose interfaces could not be read, or that has
            // none of this family, still has the socket's own address, and
            // one entry is the honest answer -- an empty list would say the
            // machine can send from nowhere.
            LocalAddress entry;
            entry.address = self;
            entry.bytes = self_bytes;
            local.push_back(entry);
        }

        // What the answer costs: the header, one entry per address, and the
        // addresses themselves, which sit past the entries and are what the
        // entries point at.
        std::size_t payload = 0;
        for (const LocalAddress& entry : local) {
            payload += entry.bytes;
        }
        const std::size_t needed = kAddressListEntries +
                                   local.size() * kSocketAddressBytes +
                                   payload;

        if (out_size < needed) {
            // The caller's buffer is too small. The size it would have
            // needed is handed back, which is how the request is meant to
            // be used: ask with nothing, then ask again with the answer.
            if (returned != nullptr) {
                *returned = static_cast<std::uint32_t>(needed);
            }
            return socket_failure_code(kWsaFault);
        }

        auto* bytes = static_cast<std::uint8_t*>(out_buffer);
        std::memset(bytes, 0, needed);
        write_u32(bytes, kAddressListCount,
                  static_cast<std::uint32_t>(local.size()));

        std::size_t address_at =
            kAddressListEntries + local.size() * kSocketAddressBytes;
        for (std::size_t i = 0; i < local.size(); ++i) {
            const std::size_t entry_at =
                kAddressListEntries + i * kSocketAddressBytes;
            void* const destination = bytes + address_at;
            const std::size_t written = from_host_address(
                local[i].address, destination, local[i].bytes);
            if (written == 0) {
                // The family was checked before the entry was gathered, so
                // this cannot happen; the refusal is here because a silent
                // zero-length entry would be read as an address of no kind.
                return socket_failure_code(kWsaFamilyNotSupported);
            }
            write_ptr(bytes, entry_at + kSocketAddressPointer,
                      reinterpret_cast<std::uint64_t>(destination));
            write_u32(bytes, entry_at + kSocketAddressLength,
                      static_cast<std::uint32_t>(written));
            address_at += written;
        }

        if (returned != nullptr) {
            *returned = static_cast<std::uint32_t>(needed);
        }
        set_last_error(0);
        return 0;
    }

    // Every other control code selects a behaviour this runtime's sockets do
    // not have: the non-blocking modes, the keep-alive tuning, the
    // completion notification, the routing table. Answering with a
    // zero-length success would leave the caller believing the socket had
    // the property it asked for.
    return socket_failure_code(kWsaInvalidArgument);
}

// ------------------------------------------------------- the name resolution
//
// The host's resolver, and the three structures the older calls hand their
// answers back in. The lists a result is made of are allocated out of this
// runtime's arena, because the call that frees them is this runtime's and
// the address has to be one it recognises.

namespace {

// One node of the guest's resolver list, freed through the chain it is
// linked into. The node, the address it points at and the canonical name
// when there is one are one allocation, so that freeing the node frees
// everything the node names.
void free_addrinfo_chain(void* head) noexcept {
    void* current = head;
    while (current != nullptr) {
        auto* node = static_cast<std::uint8_t*>(current);
        void* next = reinterpret_cast<void*>(read_ptr(node, kAddrInfoNext));
        static_cast<void>(heap_free(current));
        current = next;
    }
}

// The host's list turned into the guest's. `wide` says which spelling of the
// canonical name the caller asked for, because the two calls that reach
// here differ only in that.
[[nodiscard]] void* build_addrinfo_chain(const ::addrinfo* first,
                                         bool wide) noexcept {
    void* head = nullptr;
    void* tail = nullptr;

    for (const ::addrinfo* it = first; it != nullptr; it = it->ai_next) {
        const std::size_t address_bytes = guest_address_bytes(it->ai_family);
        if (address_bytes == 0) {
            // An address family this runtime does not carry. The node is
            // skipped rather than represented as something it is not.
            continue;
        }

        const char* canonical = it->ai_canonname;
        const std::size_t canonical_chars =
            canonical == nullptr ? 0 : std::strlen(canonical) + 1;
        const std::size_t canonical_bytes =
            wide ? canonical_chars * sizeof(char16_t) : canonical_chars;

        const std::size_t block_bytes =
            kAddrInfoBytes + address_bytes + canonical_bytes;
        auto* block = static_cast<std::uint8_t*>(heap_alloc(0, block_bytes));
        if (block == nullptr) {
            // Out of room partway through. What was built is released
            // through the same walk the free call uses, so the caller is
            // left with nothing rather than with a partial list it cannot
            // tell from a complete one.
            free_addrinfo_chain(head);
            return nullptr;
        }
        std::memset(block, 0, block_bytes);

        sockaddr_storage storage {};
        std::memcpy(&storage, it->ai_addr, it->ai_addrlen);
        void* const address = block + kAddrInfoBytes;
        const std::size_t written =
            from_host_address(storage, address, address_bytes);

        write_u32(block, kAddrInfoFlags,
                  static_cast<std::uint32_t>(it->ai_flags));
        write_u32(block, kAddrInfoFamily,
                  static_cast<std::uint32_t>(it->ai_family));
        write_u32(block, kAddrInfoSockType,
                  static_cast<std::uint32_t>(it->ai_socktype));
        write_u32(block, kAddrInfoProtocol,
                  static_cast<std::uint32_t>(it->ai_protocol));
        write_u32(block, kAddrInfoAddrLen, static_cast<std::uint32_t>(written));
        write_ptr(block, kAddrInfoAddr,
                  reinterpret_cast<std::uint64_t>(address));

        if (canonical_chars != 0) {
            // The name is placed after the address, which is two-byte
            // aligned because the header is forty-eight bytes and every
            // address this runtime carries is an even number of them.
            auto* name = block + kAddrInfoBytes + address_bytes;
            if (wide) {
                for (std::size_t i = 0; i < canonical_chars; ++i) {
                    write_u16(name, i * sizeof(char16_t),
                              static_cast<std::uint16_t>(
                                  static_cast<unsigned char>(canonical[i])));
                }
            } else {
                std::memcpy(name, canonical, canonical_chars);
            }
            write_ptr(block, kAddrInfoCanonName,
                      reinterpret_cast<std::uint64_t>(name));
        }

        if (tail != nullptr) {
            write_ptr(tail, kAddrInfoNext,
                      reinterpret_cast<std::uint64_t>(block));
        } else {
            head = block;
        }
        tail = block;
    }

    return head;
}

// The restrictions a guest placed on a search, as the host's hints. A zero
// in any field means "any", which is the host's own convention as well, so
// the structure is left at zero and the host fills the freedom in.
void read_search_hints(const void* hints, ::addrinfo& out, bool& present) noexcept {
    present = false;
    if (hints == nullptr) {
        return;
    }
    const std::int32_t family =
        static_cast<std::int32_t>(read_u32(hints, kAddrInfoFamily));
    const std::int32_t sock_type =
        static_cast<std::int32_t>(read_u32(hints, kAddrInfoSockType));
    const std::int32_t protocol =
        static_cast<std::int32_t>(read_u32(hints, kAddrInfoProtocol));

    const int host_family = host_family_of(family);
    out.ai_family = host_family == 0 ? AF_UNSPEC : host_family;

    if (sock_type == kSockStream) {
        out.ai_socktype = SOCK_STREAM;
    } else if (sock_type == kSockDgram) {
        out.ai_socktype = SOCK_DGRAM;
    }
    if (protocol != 0) {
        out.ai_protocol = protocol;
    }
    present = true;
}

// The one search both the wide and the narrow call make. The two differ in
// how the strings arrive and in how the answer is spelled; the question put
// to the host is the same one.
[[nodiscard]] std::int32_t resolve_names(const std::string& node,
                                         const std::string& service,
                                         const void* hints, bool wide,
                                         void** result) noexcept {
    if (result == nullptr) {
        return socket_failure_code(kWsaInvalidArgument);
    }
    *result = nullptr;

    ::addrinfo host_hints {};
    bool use_hints = false;
    read_search_hints(hints, host_hints, use_hints);

    ::addrinfo* first = nullptr;
    const int status = ::getaddrinfo(
        node.empty() ? nullptr : node.c_str(),
        service.empty() ? nullptr : service.c_str(),
        use_hints ? &host_hints : nullptr, &first);
    if (status != 0) {
        // The two failures a caller distinguishes: a name that does not
        // exist, and a name that exists with no address of the kind asked
        // for. The host's codes carry the distinction and it is kept.
        const bool missing = status == EAI_NONAME || status == EAI_NODATA;
        return socket_failure_code(missing ? kWsaHostNotFound : kWsaNoData);
    }

    void* chain = build_addrinfo_chain(first, wide);
    ::freeaddrinfo(first);

    if (chain == nullptr) {
        // Either the name resolved to nothing this runtime can represent,
        // or the arena ran out. Both leave the caller with no list, and the
        // contract's code for "the name yielded no address here" covers
        // both without pretending to be the other.
        return socket_failure_code(kWsaNoData);
    }

    *result = chain;
    set_last_error(0);
    return 0;
}

// The storage the older name calls answer with. Those calls hand back a
// pointer into memory the caller does not own and must not free, and the
// pointer stays valid until the next call of the same kind -- so the
// storage is thread-local, which is the only way two threads can ask two
// questions at once and each read its own answer.
struct NameStorage {
    std::deque<std::string> strings;
    std::deque<std::vector<std::uint8_t>> addresses;
    std::vector<char*> alias_pointers;
    std::vector<char*> address_pointers;

    // The three structures, in the guest's layout rather than the host's.
    // They are not the same: the guest's `hostent` puts the address list
    // after the two lengths where some hosts put it before, and the whole
    // point of this file is not to assume otherwise.
    alignas(8) std::uint8_t host_entity[32] {};
    alignas(8) std::uint8_t service_entity[32] {};
    alignas(8) std::uint8_t protocol_entity[24] {};

    // The text a `gethostname` or a `getservbyname` answers with, and the
    // wide form of it.
    char narrow[256] {};
    char16_t wide[256] {};
};

thread_local NameStorage g_name_storage;

// The storage emptied, which every call through it does first: a caller
// reading a stale pointer from the previous call would read a string that
// describes a different host.
void reset_name_storage() noexcept {
    g_name_storage.strings.clear();
    g_name_storage.addresses.clear();
    g_name_storage.alias_pointers.clear();
    g_name_storage.address_pointers.clear();
}

// A string held in the storage, and the pointer to its first byte. The
// containers are `deque` because their elements do not move as the
// container grows, and a pointer handed to the guest has to keep pointing
// at the same characters as later names are added.
[[nodiscard]] char* store_string(std::string_view text) noexcept {
    g_name_storage.strings.emplace_back(text);
    std::string& held = g_name_storage.strings.back();
    return held.empty() ? const_cast<char*>("") : &held[0];
}

// The offsets inside the three structures. They are the guest's, and the
// guest's differ from one another in where the trailing fields sit.
constexpr std::size_t kHostName = 0;
constexpr std::size_t kHostAliases = 8;
constexpr std::size_t kHostAddrType = 16;
constexpr std::size_t kHostAddrLength = 18;
constexpr std::size_t kHostAddrList = 24;

constexpr std::size_t kServiceName = 0;
constexpr std::size_t kServiceAliases = 8;
constexpr std::size_t kServicePort = 16;
constexpr std::size_t kServiceProtocol = 24;

constexpr std::size_t kProtocolName = 0;
constexpr std::size_t kProtocolAliases = 8;
constexpr std::size_t kProtocolNumber = 16;

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_GetAddrInfoW(
    const char16_t* node, const char16_t* service, const void* hints,
    void** result) noexcept {
    std::string node_name;
    if (node != nullptr && node[0] != u'\0') {
        if (!narrow_out(std::u16string_view(node), node_name).converted) {
            return socket_failure_code(kWsaInvalidArgument);
        }
    }
    std::string service_name;
    if (service != nullptr && service[0] != u'\0') {
        if (!narrow_out(std::u16string_view(service), service_name).converted) {
            return socket_failure_code(kWsaInvalidArgument);
        }
    }
    return resolve_names(node_name, service_name, hints, true, result);
}

extern "C" __attribute__((ms_abi)) void k32ws_FreeAddrInfoW(void* list) noexcept {
    free_addrinfo_chain(list);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_getaddrinfo(
    const char* node, const char* service, const void* hints,
    void** result) noexcept {
    // The narrow spelling. The caller's own strings are already in the form
    // the host's resolver takes, so nothing is converted on the way in; the
    // answer is still built in the guest's layout, because the two
    // structures order their last four fields differently and a pointer to
    // the host's list would have the guest reading the address where the
    // canonical name is.
    const std::string node_name = node == nullptr ? std::string() : std::string(node);
    const std::string service_name =
        service == nullptr ? std::string() : std::string(service);
    return resolve_names(node_name, service_name, hints, false, result);
}

extern "C" __attribute__((ms_abi)) void k32ws_freeaddrinfo(void* list) noexcept {
    free_addrinfo_chain(list);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_getnameinfo(
    const void* address, std::int32_t address_length, char* host,
    std::uint32_t host_bytes, char* service, std::uint32_t service_bytes,
    std::int32_t flags) noexcept {
    if (address == nullptr) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    sockaddr_storage storage {};
    socklen_t storage_length = 0;
    const std::size_t given =
        address_length <= 0 ? 0 : static_cast<std::size_t>(address_length);
    if (to_host_address(address, given, storage, storage_length) == 0) {
        return socket_failure_code(kWsaFamilyNotSupported);
    }

    // The host's call wants both buffers or neither in some shapes, so the
    // absent ones are given a scratch buffer of one byte and the results
    // are dropped rather than asked for.
    char scratch[1] {};
    const int status = ::getnameinfo(
        reinterpret_cast<const sockaddr*>(&storage), storage_length,
        host != nullptr ? host : scratch, host != nullptr ? host_bytes : 0,
        service != nullptr ? service : scratch,
        service != nullptr ? service_bytes : 0, flags);
    if (status != 0) {
        const bool missing = status == EAI_NONAME || status == EAI_NODATA;
        return socket_failure_code(missing ? kWsaHostNotFound : kWsaNoData);
    }

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_GetNameInfoW(
    const void* address, std::int32_t address_length, char16_t* host,
    std::uint32_t host_chars, char16_t* service, std::uint32_t service_chars,
    std::int32_t flags) noexcept {
    if (address == nullptr || host == nullptr || service == nullptr) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    // The host answers in bytes and the caller reads characters, so the
    // exchange happens in the smaller of the two spaces and is widened
    // afterwards. A name is at most 1025 bytes, which is what the two
    // buffers below are.
    char narrow_host[1025] {};
    char narrow_service[33] {};
    const std::uint32_t host_bytes =
        host_chars > sizeof(narrow_host) ? static_cast<std::uint32_t>(
                                               sizeof(narrow_host))
                                         : host_chars;
    const std::uint32_t service_bytes =
        service_chars > sizeof(narrow_service)
            ? static_cast<std::uint32_t>(sizeof(narrow_service))
            : service_chars;

    const std::int32_t status = k32ws_getnameinfo(
        address, address_length, narrow_host, host_bytes, narrow_service,
        service_bytes, flags);
    if (status != 0) {
        return status;
    }

    for (std::size_t i = 0; i < host_chars; ++i) {
        host[i] = static_cast<char16_t>(static_cast<unsigned char>(narrow_host[i]));
        if (narrow_host[i] == '\0') {
            break;
        }
    }
    for (std::size_t i = 0; i < service_chars; ++i) {
        service[i] =
            static_cast<char16_t>(static_cast<unsigned char>(narrow_service[i]));
        if (narrow_service[i] == '\0') {
            break;
        }
    }

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) const char16_t* k32ws_GetHostNameW(
    char16_t* name, std::int32_t chars) noexcept {
    if (name == nullptr || chars <= 0) {
        set_last_error(kWsaInvalidArgument);
        return nullptr;
    }

    char narrow[256] {};
    if (::gethostname(narrow, sizeof(narrow) - 1) != 0) {
        static_cast<void>(socket_failure());
        return nullptr;
    }

    std::size_t at = 0;
    while (narrow[at] != '\0' && at + 1 < static_cast<std::size_t>(chars)) {
        name[at] = static_cast<char16_t>(static_cast<unsigned char>(narrow[at]));
        ++at;
    }
    if (narrow[at] != '\0') {
        // The host's name does not fit the caller's buffer. The contract
        // answers with the buffer's size rather than a truncation, so that
        // a caller can retry with room.
        set_last_error(kWsaInvalidArgument);
        return nullptr;
    }
    name[at] = u'\0';

    set_last_error(0);
    return name;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_gethostname(
    char* name, std::int32_t bytes) noexcept {
    if (name == nullptr || bytes <= 0) {
        return socket_failure_code(kWsaInvalidArgument);
    }
    if (::gethostname(name, static_cast<std::size_t>(bytes)) != 0) {
        return socket_failure();
    }
    // The host's call does not promise a terminator when the name exactly
    // fills the buffer, and the guest's call does.
    name[bytes - 1] = '\0';
    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) void* k32ws_gethostbyname(
    const char* name) noexcept {
    if (name == nullptr) {
        set_last_error(kWsaInvalidArgument);
        return nullptr;
    }

    reset_name_storage();
    const ::hostent* found = ::gethostbyname(name);
    if (found == nullptr || found->h_addr_list == nullptr) {
        set_last_error(kWsaHostNotFound);
        return nullptr;
    }
    if (found->h_addrtype != AF_INET) {
        set_last_error(kWsaNoData);
        return nullptr;
    }

    // The host's answer is copied field by field into storage this runtime
    // owns, because the host's own storage is rewritten by the next
    // resolver call and the contract here promises the caller an answer
    // that lasts until the next one of these.
    char* const host_name = store_string(
        found->h_name == nullptr ? std::string_view() : found->h_name);

    if (found->h_aliases != nullptr) {
        for (char** alias = found->h_aliases; *alias != nullptr; ++alias) {
            g_name_storage.alias_pointers.push_back(store_string(*alias));
        }
    }
    g_name_storage.alias_pointers.push_back(nullptr);

    for (char** address = found->h_addr_list; *address != nullptr; ++address) {
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(found->h_length));
        std::memcpy(bytes.data(), *address, bytes.size());
        g_name_storage.addresses.push_back(std::move(bytes));
        g_name_storage.address_pointers.push_back(
            reinterpret_cast<char*>(g_name_storage.addresses.back().data()));
    }
    g_name_storage.address_pointers.push_back(nullptr);

    std::uint8_t* entity = g_name_storage.host_entity;
    std::memset(entity, 0, sizeof(g_name_storage.host_entity));
    write_ptr(entity, kHostName, reinterpret_cast<std::uint64_t>(host_name));
    write_ptr(entity, kHostAliases,
              reinterpret_cast<std::uint64_t>(
                  g_name_storage.alias_pointers.data()));
    write_u16(entity, kHostAddrType,
              static_cast<std::uint16_t>(found->h_addrtype));
    write_u16(entity, kHostAddrLength,
              static_cast<std::uint16_t>(found->h_length));
    write_ptr(entity, kHostAddrList,
              reinterpret_cast<std::uint64_t>(
                  g_name_storage.address_pointers.data()));

    set_last_error(0);
    return entity;
}

extern "C" __attribute__((ms_abi)) void* k32ws_gethostbyaddr(
    const void* address, std::int32_t bytes, std::int32_t family) noexcept {
    if (address == nullptr || bytes != 4) {
        set_last_error(kWsaInvalidArgument);
        return nullptr;
    }
    const int host_family = host_family_of(family);
    if (host_family == 0) {
        set_last_error(kWsaFamilyNotSupported);
        return nullptr;
    }

    reset_name_storage();
    ::in_addr value {};
    std::memcpy(&value, address, sizeof(value));
    const ::hostent* found =
        ::gethostbyaddr(&value, sizeof(value), host_family);
    if (found == nullptr || found->h_addr_list == nullptr) {
        set_last_error(kWsaHostNotFound);
        return nullptr;
    }

    char* const host_name = store_string(
        found->h_name == nullptr ? std::string_view() : found->h_name);
    if (found->h_aliases != nullptr) {
        for (char** alias = found->h_aliases; *alias != nullptr; ++alias) {
            g_name_storage.alias_pointers.push_back(store_string(*alias));
        }
    }
    g_name_storage.alias_pointers.push_back(nullptr);

    for (char** entry = found->h_addr_list; *entry != nullptr; ++entry) {
        std::vector<std::uint8_t> octets(
            static_cast<std::size_t>(found->h_length));
        std::memcpy(octets.data(), *entry, octets.size());
        g_name_storage.addresses.push_back(std::move(octets));
        g_name_storage.address_pointers.push_back(
            reinterpret_cast<char*>(g_name_storage.addresses.back().data()));
    }
    g_name_storage.address_pointers.push_back(nullptr);

    std::uint8_t* entity = g_name_storage.host_entity;
    std::memset(entity, 0, sizeof(g_name_storage.host_entity));
    write_ptr(entity, kHostName, reinterpret_cast<std::uint64_t>(host_name));
    write_ptr(entity, kHostAliases,
              reinterpret_cast<std::uint64_t>(
                  g_name_storage.alias_pointers.data()));
    write_u16(entity, kHostAddrType,
              static_cast<std::uint16_t>(found->h_addrtype));
    write_u16(entity, kHostAddrLength,
              static_cast<std::uint16_t>(found->h_length));
    write_ptr(entity, kHostAddrList,
              reinterpret_cast<std::uint64_t>(
                  g_name_storage.address_pointers.data()));

    set_last_error(0);
    return entity;
}

extern "C" __attribute__((ms_abi)) void* k32ws_getservbyname(
    const char* name, const char* protocol) noexcept {
    if (name == nullptr) {
        set_last_error(kWsaInvalidArgument);
        return nullptr;
    }

    reset_name_storage();
    const ::servent* found =
        ::getservbyname(name, protocol == nullptr ? nullptr : protocol);
    if (found == nullptr) {
        set_last_error(kWsaNoData);
        return nullptr;
    }

    char* const service_name = store_string(
        found->s_name == nullptr ? std::string_view() : found->s_name);
    if (found->s_aliases != nullptr) {
        for (char** alias = found->s_aliases; *alias != nullptr; ++alias) {
            g_name_storage.alias_pointers.push_back(store_string(*alias));
        }
    }
    g_name_storage.alias_pointers.push_back(nullptr);
    char* const protocol_name = store_string(
        found->s_proto == nullptr ? std::string_view() : found->s_proto);

    std::uint8_t* entity = g_name_storage.service_entity;
    std::memset(entity, 0, sizeof(g_name_storage.service_entity));
    write_ptr(entity, kServiceName,
              reinterpret_cast<std::uint64_t>(service_name));
    write_ptr(entity, kServiceAliases,
              reinterpret_cast<std::uint64_t>(
                  g_name_storage.alias_pointers.data()));
    write_u16(entity, kServicePort, static_cast<std::uint16_t>(found->s_port));
    write_ptr(entity, kServiceProtocol,
              reinterpret_cast<std::uint64_t>(protocol_name));

    set_last_error(0);
    return entity;
}

extern "C" __attribute__((ms_abi)) void* k32ws_getservbyport(
    std::int32_t port, const char* protocol) noexcept {
    reset_name_storage();
    // The port arrives in host order and the host's call takes it in network
    // order, which is the one conversion this call makes.
    const ::servent* found = ::getservbyport(
        static_cast<int>(__builtin_bswap16(static_cast<std::uint16_t>(port))),
        protocol == nullptr ? nullptr : protocol);
    if (found == nullptr) {
        set_last_error(kWsaNoData);
        return nullptr;
    }

    char* const service_name = store_string(
        found->s_name == nullptr ? std::string_view() : found->s_name);
    if (found->s_aliases != nullptr) {
        for (char** alias = found->s_aliases; *alias != nullptr; ++alias) {
            g_name_storage.alias_pointers.push_back(store_string(*alias));
        }
    }
    g_name_storage.alias_pointers.push_back(nullptr);
    char* const protocol_name = store_string(
        found->s_proto == nullptr ? std::string_view() : found->s_proto);

    std::uint8_t* entity = g_name_storage.service_entity;
    std::memset(entity, 0, sizeof(g_name_storage.service_entity));
    write_ptr(entity, kServiceName,
              reinterpret_cast<std::uint64_t>(service_name));
    write_ptr(entity, kServiceAliases,
              reinterpret_cast<std::uint64_t>(
                  g_name_storage.alias_pointers.data()));
    write_u16(entity, kServicePort, static_cast<std::uint16_t>(found->s_port));
    write_ptr(entity, kServiceProtocol,
              reinterpret_cast<std::uint64_t>(protocol_name));

    set_last_error(0);
    return entity;
}

extern "C" __attribute__((ms_abi)) void* k32ws_getprotobyname(
    const char* name) noexcept {
    if (name == nullptr) {
        set_last_error(kWsaInvalidArgument);
        return nullptr;
    }

    reset_name_storage();
    const ::protoent* found = ::getprotobyname(name);
    if (found == nullptr) {
        set_last_error(kWsaNoData);
        return nullptr;
    }

    char* const protocol_name = store_string(
        found->p_name == nullptr ? std::string_view() : found->p_name);
    if (found->p_aliases != nullptr) {
        for (char** alias = found->p_aliases; *alias != nullptr; ++alias) {
            g_name_storage.alias_pointers.push_back(store_string(*alias));
        }
    }
    g_name_storage.alias_pointers.push_back(nullptr);

    std::uint8_t* entity = g_name_storage.protocol_entity;
    std::memset(entity, 0, sizeof(g_name_storage.protocol_entity));
    write_ptr(entity, kProtocolName,
              reinterpret_cast<std::uint64_t>(protocol_name));
    write_ptr(entity, kProtocolAliases,
              reinterpret_cast<std::uint64_t>(
                  g_name_storage.alias_pointers.data()));
    write_u16(entity, kProtocolNumber,
              static_cast<std::uint16_t>(found->p_proto));

    set_last_error(0);
    return entity;
}

extern "C" __attribute__((ms_abi)) void* k32ws_getprotobynumber(
    std::int32_t number) noexcept {
    reset_name_storage();
    const ::protoent* found = ::getprotobynumber(number);
    if (found == nullptr) {
        set_last_error(kWsaNoData);
        return nullptr;
    }

    char* const protocol_name = store_string(
        found->p_name == nullptr ? std::string_view() : found->p_name);
    if (found->p_aliases != nullptr) {
        for (char** alias = found->p_aliases; *alias != nullptr; ++alias) {
            g_name_storage.alias_pointers.push_back(store_string(*alias));
        }
    }
    g_name_storage.alias_pointers.push_back(nullptr);

    std::uint8_t* entity = g_name_storage.protocol_entity;
    std::memset(entity, 0, sizeof(g_name_storage.protocol_entity));
    write_ptr(entity, kProtocolName,
              reinterpret_cast<std::uint64_t>(protocol_name));
    write_ptr(entity, kProtocolAliases,
              reinterpret_cast<std::uint64_t>(
                  g_name_storage.alias_pointers.data()));
    write_u16(entity, kProtocolNumber,
              static_cast<std::uint16_t>(found->p_proto));

    set_last_error(0);
    return entity;
}

// --------------------------------------------------- the textual forms
//
// Two conversions between an address and the text a person would type. They
// are the same conversion the two old calls above make, wrapped for an
// address of either family: the text carries a port, which is the part that
// makes the answer something a caller can hand to `connect`.

namespace {

// The text of an address, as the guest spells it: a bracketed address for
// the sixteeen-byte family, a bare one for the four-byte family, and the
// port after a colon in both. Windows brackets the longer address because
// the colons inside it would otherwise be read as the port separator.
[[nodiscard]] bool address_to_text(const sockaddr_storage& address,
                                   std::string& out) noexcept {
    char host[128] {};
    char service[32] {};
    const int status = ::getnameinfo(
        reinterpret_cast<const sockaddr*>(&address),
        address.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6),
        host, sizeof(host), service, sizeof(service),
        NI_NUMERICHOST | NI_NUMERICSERV);
    if (status != 0) {
        return false;
    }

    out.clear();
    if (address.ss_family == AF_INET6) {
        out.push_back('[');
        out.append(host);
        out.push_back(']');
    } else {
        out.append(host);
    }
    out.push_back(':');
    out.append(service);
    return true;
}

// The address the text names, which is the reverse walk. The brackets are
// stripped first because the host's parser does not know about them and
// would read them as part of the address.
[[nodiscard]] bool text_to_address(std::string_view text, int family,
                                   sockaddr_storage& out,
                                   socklen_t& out_length) noexcept {
    std::string host;
    std::string service;

    const std::size_t open = text.find('[');
    const std::size_t close = text.find(']');
    if (open != std::string_view::npos && close != std::string_view::npos &&
        close > open) {
        host.assign(text.substr(open + 1, close - open - 1));
        if (close + 1 < text.size() && text[close + 1] == ':') {
            service.assign(text.substr(close + 2));
        }
    } else {
        const std::size_t colon = text.rfind(':');
        if (colon == std::string_view::npos) {
            host.assign(text);
        } else {
            host.assign(text.substr(0, colon));
            service.assign(text.substr(colon + 1));
        }
    }

    ::addrinfo hints {};
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

    ::addrinfo* first = nullptr;
    const int status =
        ::getaddrinfo(host.empty() ? nullptr : host.c_str(),
                      service.empty() ? nullptr : service.c_str(), &hints,
                      &first);
    if (status != 0 || first == nullptr) {
        return false;
    }

    std::memcpy(&out, first->ai_addr, first->ai_addrlen);
    out_length = static_cast<socklen_t>(first->ai_addrlen);
    ::freeaddrinfo(first);
    return true;
}

// The same two conversions for the wide spellings.
[[nodiscard]] bool widen_text(const std::string& narrow, char16_t* wide,
                              std::size_t capacity,
                              std::size_t& written) noexcept {
    written = 0;
    for (std::size_t i = 0; i < narrow.size(); ++i) {
        if (written + 1 >= capacity) {
            return false;
        }
        wide[written++] =
            static_cast<char16_t>(static_cast<unsigned char>(narrow[i]));
    }
    wide[written] = u'\0';
    return true;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSAAddressToStringA(
    const void* address, std::uint32_t address_bytes, void* protocol_info,
    char* text, std::uint32_t* text_bytes) noexcept {
    static_cast<void>(protocol_info);
    if (address == nullptr || text == nullptr || text_bytes == nullptr) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    sockaddr_storage storage {};
    socklen_t storage_length = 0;
    if (to_host_address(address, address_bytes, storage, storage_length) == 0) {
        return socket_failure_code(kWsaFamilyNotSupported);
    }

    std::string rendered;
    if (!address_to_text(storage, rendered)) {
        return socket_failure_code(kWsaNoData);
    }

    const std::uint32_t capacity = *text_bytes;
    if (capacity < rendered.size() + 1) {
        // The caller's buffer cannot hold the text and its terminator. The
        // size it needed is written back, which is how this call is meant
        // to be used.
        *text_bytes = static_cast<std::uint32_t>(rendered.size() + 1);
        return socket_failure_code(kWsaFault);
    }

    std::memcpy(text, rendered.data(), rendered.size());
    text[rendered.size()] = '\0';
    *text_bytes = static_cast<std::uint32_t>(rendered.size() + 1);

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSAAddressToStringW(
    const void* address, std::uint32_t address_bytes, void* protocol_info,
    char16_t* text, std::uint32_t* text_chars) noexcept {
    static_cast<void>(protocol_info);
    if (address == nullptr || text == nullptr || text_chars == nullptr) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    sockaddr_storage storage {};
    socklen_t storage_length = 0;
    if (to_host_address(address, address_bytes, storage, storage_length) == 0) {
        return socket_failure_code(kWsaFamilyNotSupported);
    }

    std::string rendered;
    if (!address_to_text(storage, rendered)) {
        return socket_failure_code(kWsaNoData);
    }

    // The count the caller gives is in characters, which for the wide form
    // is what the buffer holds.
    std::size_t written = 0;
    if (!widen_text(rendered, text, *text_chars, written)) {
        *text_chars = static_cast<std::uint32_t>(rendered.size() + 1);
        return socket_failure_code(kWsaFault);
    }
    *text_chars = static_cast<std::uint32_t>(written + 1);

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSAStringToAddressA(
    const char* text, std::int32_t family, void* protocol_info,
    void* address, std::int32_t* address_bytes) noexcept {
    static_cast<void>(protocol_info);
    if (text == nullptr || address == nullptr || address_bytes == nullptr) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    const int host_family = host_family_of(family);
    if (host_family == 0) {
        return socket_failure_code(kWsaFamilyNotSupported);
    }

    sockaddr_storage storage {};
    socklen_t storage_length = 0;
    if (!text_to_address(text, host_family, storage, storage_length)) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    const std::int32_t given = *address_bytes;
    const std::size_t capacity = given < 0 ? 0 : static_cast<std::size_t>(given);
    const std::size_t written =
        from_host_address(storage, address, capacity);
    if (written == 0) {
        *address_bytes =
            static_cast<std::int32_t>(guest_address_bytes(storage.ss_family));
        return socket_failure_code(kWsaFault);
    }
    *address_bytes = static_cast<std::int32_t>(written);

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSAStringToAddressW(
    const char16_t* text, std::int32_t family, void* protocol_info,
    void* address, std::int32_t* address_bytes) noexcept {
    static_cast<void>(protocol_info);
    if (text == nullptr || address == nullptr || address_bytes == nullptr) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    // The address text is ASCII, so the exchange is a narrowing rather than
    // a code page conversion, and a character outside that range is text
    // that is not an address.
    std::string narrow;
    for (std::size_t i = 0; text[i] != u'\0'; ++i) {
        if (text[i] > 0x7F) {
            return socket_failure_code(kWsaInvalidArgument);
        }
        narrow.push_back(static_cast<char>(text[i]));
    }

    return k32ws_WSAStringToAddressA(narrow.c_str(), family, nullptr, address,
                                     address_bytes);
}

// --------------------------------------------------------- the duplicates
//
// `WSADuplicateSocket` exists so that one process can hand a socket to
// another. Between two processes on this runtime it cannot work, because a
// descriptor number means nothing outside the process that opened it and
// there is no socket table here to pass a reference through. Within one
// process it can, and does: the protocol-info block carries the descriptor
// and `WSASocketW` reads it back.

// The offsets inside `WSAPROTOCOL_INFOW` that this runtime fills. The
// structure is much larger than these; the rest is left zero, which is what
// a caller that is looking at its own socket rather than at the provider
// list will read anyway.
constexpr std::size_t kProtocolServiceFlags = 0;
constexpr std::size_t kProtocolFamily = 76;
constexpr std::size_t kProtocolMaxAddress = 80;
constexpr std::size_t kProtocolMinAddress = 84;
constexpr std::size_t kProtocolType = 88;
constexpr std::size_t kProtocolNumberField = 92;
constexpr std::size_t kProtocolByteOrder = 100;
constexpr std::size_t kProtocolMessageSize = 108;
constexpr std::size_t kProtocolReserved = 112;
constexpr std::size_t kProtocolBytes = 632;

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSADuplicateSocketW(
    std::uint64_t socket, std::uint32_t process, void* info) noexcept {
    static_cast<void>(process);
    int fd = 0;
    if (!socket_descriptor_of(socket, fd)) {
        return socket_failure_code(kWsaNotSocket);
    }
    if (info == nullptr) {
        return socket_failure_code(kWsaInvalidArgument);
    }

    // The family, the type and the protocol are read back off the socket so
    // that the receiving side can rebuild one that behaves the same.
    int family = 0;
    socklen_t family_bytes = sizeof(family);
    int type = 0;
    socklen_t type_bytes = sizeof(type);
    int protocol = 0;
    socklen_t protocol_bytes = sizeof(protocol);
    if (::getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &family, &family_bytes) != 0 ||
        ::getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_bytes) != 0 ||
        ::getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol,
                     &protocol_bytes) != 0) {
        return socket_failure();
    }

    std::memset(info, 0, kProtocolBytes);
    write_u32(info, kProtocolServiceFlags, 0x00000001u);
    write_u32(info, kProtocolFamily, static_cast<std::uint32_t>(family));
    write_u32(info, kProtocolMaxAddress,
              static_cast<std::uint32_t>(family == AF_INET6 ? kSockaddrIn6Bytes
                                                            : kSockaddrInBytes));
    write_u32(info, kProtocolMinAddress, 16);
    write_u32(info, kProtocolType, static_cast<std::uint32_t>(type));
    write_u32(info, kProtocolNumberField,
              static_cast<std::uint32_t>(protocol));
    write_u32(info, kProtocolByteOrder, 0);
    write_u32(info, kProtocolMessageSize, 0);
    write_u32(info, kProtocolReserved, static_cast<std::uint32_t>(fd));

    set_last_error(0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSADuplicateSocketA(
    std::uint64_t socket, std::uint32_t process, void* info) noexcept {
    return k32ws_WSADuplicateSocketW(socket, process, info);
}

// ---------------------------------------------- the two disconnects
//
// `WSARecvDisconnect` and `WSASendDisconnect` are `shutdown` with a
// different name and an optional buffer that carries closing data. The
// buffer is dropped: the host's call has no room for it, and a stream
// socket has no closing data to carry.

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSARecvDisconnect(
    std::uint64_t socket, void* buffer) noexcept {
    static_cast<void>(buffer);
    return k32ws_shutdown(socket, SHUT_RD);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32ws_WSASendDisconnect(
    std::uint64_t socket, const void* buffer) noexcept {
    static_cast<void>(buffer);
    return k32ws_shutdown(socket, SHUT_WR);
}

// --------------------------------------------------------- the refusals
//
// The calls this runtime does not carry. Each is registered so that an
// import of it resolves and the call reports the code the contract defines
// for a request the provider does not support -- which is what a program
// checks for -- rather than failing to load at all.
//
// The three shapes are the three return types in the families below: a
// count or a handle that is zero when it failed, a signed result that is
// minus one, and nothing.

namespace {

[[nodiscard]] std::int32_t refuse_failure() noexcept {
    set_last_error(kWsaOperationNotSupported);
    return -1;
}

[[nodiscard]] std::uint64_t refuse_handle() noexcept {
    set_last_error(kWsaOperationNotSupported);
    return 0;
}

void refuse_void() noexcept {
    set_last_error(kWsaOperationNotSupported);
}

}  // namespace

// ------------------------------------------------------------- registration

void add_ws2_32(ExportList& out) {
    const auto e = [&out](const char* name, std::uint32_t ordinal, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.ordinal = ordinal;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };

    // The Berkeley layer, with the ordinals they have carried since Winsock
    // was a wrapper around a Unix library. A program built against an older
    // import library names these by number, which is why the ordinals are
    // part of the table rather than an afterthought.
    e("accept", 1, reinterpret_cast<void*>(&k32ws_accept));
    e("bind", 2, reinterpret_cast<void*>(&k32ws_bind));
    e("closesocket", 3, reinterpret_cast<void*>(&k32ws_closesocket));
    e("connect", 4, reinterpret_cast<void*>(&k32ws_connect));
    e("getpeername", 5, reinterpret_cast<void*>(&k32ws_getpeername));
    e("getsockname", 6, reinterpret_cast<void*>(&k32ws_getsockname));
    e("getsockopt", 7, reinterpret_cast<void*>(&k32ws_getsockopt));
    e("htonl", 8, reinterpret_cast<void*>(&k32ws_htonl));
    e("htons", 9, reinterpret_cast<void*>(&k32ws_htons));
    e("ioctlsocket", 10, reinterpret_cast<void*>(&k32ws_ioctlsocket));
    e("inet_addr", 11, reinterpret_cast<void*>(&k32ws_inet_addr));
    e("inet_ntoa", 12, reinterpret_cast<void*>(&k32ws_inet_ntoa));
    e("listen", 13, reinterpret_cast<void*>(&k32ws_listen));
    e("ntohl", 14, reinterpret_cast<void*>(&k32ws_ntohl));
    e("ntohs", 15, reinterpret_cast<void*>(&k32ws_ntohs));
    e("recv", 16, reinterpret_cast<void*>(&k32ws_recv));
    e("recvfrom", 17, reinterpret_cast<void*>(&k32ws_recvfrom));
    e("select", 18, reinterpret_cast<void*>(&k32ws_select));
    e("send", 19, reinterpret_cast<void*>(&k32ws_send));
    e("sendto", 20, reinterpret_cast<void*>(&k32ws_sendto));
    e("setsockopt", 21, reinterpret_cast<void*>(&k32ws_setsockopt));
    e("shutdown", 22, reinterpret_cast<void*>(&k32ws_shutdown));
    e("socket", 23, reinterpret_cast<void*>(&k32ws_socket));

    // The older name lookups, which answer with a structure rather than a
    // list and are still what a program built against Winsock 1.1 uses.
    e("gethostbyaddr", 51, reinterpret_cast<void*>(&k32ws_gethostbyaddr));
    e("gethostbyname", 52, reinterpret_cast<void*>(&k32ws_gethostbyname));
    e("getprotobyname", 53, reinterpret_cast<void*>(&k32ws_getprotobyname));
    e("getprotobynumber", 54, reinterpret_cast<void*>(&k32ws_getprotobynumber));
    e("getservbyname", 55, reinterpret_cast<void*>(&k32ws_getservbyname));
    e("getservbyport", 56, reinterpret_cast<void*>(&k32ws_getservbyport));
    e("gethostname", 57, reinterpret_cast<void*>(&k32ws_gethostname));

    // The process-level calls, in the same ordinal block.
    e("WSAGetLastError", 111, reinterpret_cast<void*>(&k32_GetLastError));
    e("WSASetLastError", 112, reinterpret_cast<void*>(&k32_SetLastError));
    e("WSAIsBlocking", 114, reinterpret_cast<void*>(&k32ws_WSAIsBlocking));
    e("WSAStartup", 115, reinterpret_cast<void*>(&k32ws_WSAStartup));
    e("WSACleanup", 116, reinterpret_cast<void*>(&k32ws_WSACleanup));
    e("__WSAFDIsSet", 151, reinterpret_cast<void*>(&k32ws___WSAFDIsSet));

    // The Windows-shaped layer, by name.
    e("WSAAccept", 0, reinterpret_cast<void*>(&k32ws_WSAAccept));
    e("WSACloseEvent", 0, reinterpret_cast<void*>(&k32ws_WSACloseEvent));
    e("WSAConnect", 0, reinterpret_cast<void*>(&k32ws_WSAConnect));
    e("WSACreateEvent", 0, reinterpret_cast<void*>(&k32ws_WSACreateEvent));
    e("WSAEnumNetworkEvents", 0,
      reinterpret_cast<void*>(&k32ws_WSAEnumNetworkEvents));
    e("WSAEventSelect", 0, reinterpret_cast<void*>(&k32ws_WSAEventSelect));
    e("WSAGetOverlappedResult", 0,
      reinterpret_cast<void*>(&k32ws_WSAGetOverlappedResult));
    e("WSAHtonl", 0, reinterpret_cast<void*>(&k32ws_WSAHtonl));
    e("WSAHtons", 0, reinterpret_cast<void*>(&k32ws_WSAHtons));
    e("WSAIoctl", 0, reinterpret_cast<void*>(&k32ws_WSAIoctl));
    e("WSANtohl", 0, reinterpret_cast<void*>(&k32ws_WSANtohl));
    e("WSANtohs", 0, reinterpret_cast<void*>(&k32ws_WSANtohs));
    e("WSAPoll", 0, reinterpret_cast<void*>(&k32ws_WSAPoll));
    e("WSARecv", 0, reinterpret_cast<void*>(&k32ws_WSARecv));
    e("WSARecvDisconnect", 0,
      reinterpret_cast<void*>(&k32ws_WSARecvDisconnect));
    e("WSARecvFrom", 0, reinterpret_cast<void*>(&k32ws_WSARecvFrom));
    e("WSAResetEvent", 0, reinterpret_cast<void*>(&k32ws_WSAResetEvent));
    e("WSASend", 0, reinterpret_cast<void*>(&k32ws_WSASend));
    e("WSASendDisconnect", 0,
      reinterpret_cast<void*>(&k32ws_WSASendDisconnect));
    e("WSASendTo", 0, reinterpret_cast<void*>(&k32ws_WSASendTo));
    e("WSASetEvent", 0, reinterpret_cast<void*>(&k32ws_WSASetEvent));
    e("WSASocketA", 0, reinterpret_cast<void*>(&k32ws_WSASocketA));
    e("WSASocketW", 0, reinterpret_cast<void*>(&k32ws_WSASocketW));
    e("WSAWaitForMultipleEvents", 0,
      reinterpret_cast<void*>(&k32ws_WSAWaitForMultipleEvents));
    e("WSADuplicateSocketA", 0,
      reinterpret_cast<void*>(&k32ws_WSADuplicateSocketA));
    e("WSADuplicateSocketW", 0,
      reinterpret_cast<void*>(&k32ws_WSADuplicateSocketW));

    // Name resolution and the textual addresses.
    e("GetAddrInfoW", 0, reinterpret_cast<void*>(&k32ws_GetAddrInfoW));
    e("FreeAddrInfoW", 0, reinterpret_cast<void*>(&k32ws_FreeAddrInfoW));
    e("getaddrinfo", 0, reinterpret_cast<void*>(&k32ws_getaddrinfo));
    e("freeaddrinfo", 0, reinterpret_cast<void*>(&k32ws_freeaddrinfo));
    e("getnameinfo", 0, reinterpret_cast<void*>(&k32ws_getnameinfo));
    e("GetNameInfoW", 0, reinterpret_cast<void*>(&k32ws_GetNameInfoW));
    e("GetHostNameW", 0, reinterpret_cast<void*>(&k32ws_GetHostNameW));
    e("InetNtopW", 0, reinterpret_cast<void*>(&k32ws_InetNtopW));
    e("InetPtonW", 0, reinterpret_cast<void*>(&k32ws_InetPtonW));
    e("inet_ntop", 0, reinterpret_cast<void*>(&k32ws_inet_ntop));
    e("inet_pton", 0, reinterpret_cast<void*>(&k32ws_inet_pton));
    e("WSAAddressToStringA", 0,
      reinterpret_cast<void*>(&k32ws_WSAAddressToStringA));
    e("WSAAddressToStringW", 0,
      reinterpret_cast<void*>(&k32ws_WSAAddressToStringW));
    e("WSAStringToAddressA", 0,
      reinterpret_cast<void*>(&k32ws_WSAStringToAddressA));
    e("WSAStringToAddressW", 0,
      reinterpret_cast<void*>(&k32ws_WSAStringToAddressW));

    // The message-based asynchronous family. Its result arrives as a window
    // message, and this runtime has no window procedure to deliver one to;
    // a call that answered without one would leave the caller waiting for a
    // message that cannot come.
    e("WSAAsyncSelect", 101, reinterpret_cast<void*>(&refuse_failure));
    e("WSAAsyncGetHostByAddr", 102, reinterpret_cast<void*>(&refuse_handle));
    e("WSAAsyncGetHostByName", 103, reinterpret_cast<void*>(&refuse_handle));
    e("WSAAsyncGetProtoByNumber", 104,
      reinterpret_cast<void*>(&refuse_handle));
    e("WSAAsyncGetProtoByName", 105, reinterpret_cast<void*>(&refuse_handle));
    e("WSAAsyncGetServByPort", 106, reinterpret_cast<void*>(&refuse_handle));
    e("WSAAsyncGetServByName", 107, reinterpret_cast<void*>(&refuse_handle));
    e("WSACancelAsyncRequest", 108, reinterpret_cast<void*>(&refuse_failure));
    e("WSASetBlockingHook", 109, reinterpret_cast<void*>(&refuse_handle));
    e("WSAUnhookBlockingHook", 110, reinterpret_cast<void*>(&refuse_failure));
    e("WSACancelBlockingCall", 113, reinterpret_cast<void*>(&refuse_failure));

    // The namespace service provider family. It is the pluggable directory
    // layer, which on Windows is a set of registered providers reachable
    // through the registry; there is no such store here, and an answer
    // invented for it would report a service the machine does not have.
    e("WSAEnumNameSpaceProvidersA", 0,
      reinterpret_cast<void*>(&refuse_failure));
    e("WSAEnumNameSpaceProvidersW", 0,
      reinterpret_cast<void*>(&refuse_failure));
    e("WSAGetServiceClassInfoA", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSAGetServiceClassInfoW", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSAGetServiceClassNameByClassIdA", 0,
      reinterpret_cast<void*>(&refuse_failure));
    e("WSAGetServiceClassNameByClassIdW", 0,
      reinterpret_cast<void*>(&refuse_failure));
    e("WSAInstallServiceClassA", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSAInstallServiceClassW", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSALookupServiceBeginA", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSALookupServiceBeginW", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSALookupServiceEnd", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSALookupServiceNextA", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSALookupServiceNextW", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSARemoveServiceClass", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSASetServiceA", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSASetServiceW", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSCDeinstallProvider", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSCEnableNSProvider", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSCEnumProtocols", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSCEnumProtocols32", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSCGetApplicationCategory", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSCGetProviderInfo", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSCGetProviderPath", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSCInstallNameSpace", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSCInstallProvider", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSCInstallProvider64_32", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSCSetApplicationCategory", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSCUnInstallNameSpace", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSCUpdateProvider", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSCWriteNameSpaceOrder", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSCWriteProviderOrder", 0, reinterpret_cast<void*>(&refuse_failure));

    // The parts of the same layers that have no state to answer from: the
    // provider list, the quality-of-service negotiation, the name-based
    // connect. Each needs a subsystem -- the provider registry, the QoS
    // reservation, the window message -- that this runtime does not carry.
    e("WSAEnumProtocolsA", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSAEnumProtocolsW", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSAProviderConfigChange", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSANSPIoctl", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSAGetQOSByName", 0, reinterpret_cast<void*>(&refuse_handle));
    e("WSAJoinLeaf", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WSAConnectByNameA", 0, reinterpret_cast<void*>(&refuse_handle));
    e("WSAConnectByNameW", 0, reinterpret_cast<void*>(&refuse_handle));
    e("WSApSetPostRoutine", 0, reinterpret_cast<void*>(&refuse_failure));
    e("WPUCompleteOverlappedRequest", 0,
      reinterpret_cast<void*>(&refuse_failure));
    e("GetAddrInfoExCancel", 0, reinterpret_cast<void*>(&refuse_failure));
    e("GetAddrInfoExOverlappedResult", 0,
      reinterpret_cast<void*>(&refuse_failure));
    e("GetAddrInfoExW", 0, reinterpret_cast<void*>(&refuse_failure));
    e("FreeAddrInfoEx", 0, reinterpret_cast<void*>(&refuse_void));
    e("FreeAddrInfoExW", 0, reinterpret_cast<void*>(&refuse_void));
    e("WSASendMsg", 0, reinterpret_cast<void*>(&refuse_failure));
}

}  // namespace occ::runtime::winabi

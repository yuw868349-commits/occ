#include "occ/observer/transport.h"

#include "occ/observer/session.h"

#include "occ/syscall/errno.h"
#include "occ/syscall/syscall.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

namespace occ::obs {

namespace {

// The address a listener binds. Loopback rather than the wildcard address,
// because a socket a debugger uses to read and write a traced process's
// memory is a capability, and a capability should not be reachable from off
// the machine by default.
constexpr std::uint32_t kLoopbackV4 = 0x0100007f; // 127.0.0.1, network order

// The socket address layout the kernel expects. Written out rather than
// included because <netinet/in.h> drags in a libc the rest of this project
// does not use, and because the byte order is the part that has to be right.
struct SockAddrIn {
    std::uint16_t family;
    std::uint16_t port;
    std::uint32_t addr;
    std::uint8_t zero[8];
};

constexpr std::uint16_t kAfInet = 2;
constexpr int kSockStream = 1;
constexpr int kSockCloexec = 0x80000;

// The one poll event this file asks for, written out for the same reason the
// socket address above is: <poll.h> is a libc header and the value is a
// single bit. POLLIN is 0x0001, and it is also what comes back in revents
// when there is a connection to take.
constexpr short kPollIn = 0x0001;

// Big endian in the address, which is the one field whose byte order is not
// the target's: the kernel reads a port as network order whatever the
// machine it runs on does with integers.
[[nodiscard]] std::uint16_t to_be16(std::uint16_t v) noexcept {
    return static_cast<std::uint16_t>((v >> 8) | (v << 8));
}

// Packs a port for the kernel. Zero means "any free port", which is how a
// caller avoids a collision without asking the operator to pick one.
[[nodiscard]] std::uint16_t sin_port(std::uint16_t port) noexcept {
    return to_be16(port);
}

[[nodiscard]] std::uint16_t from_be16(std::uint16_t v) noexcept {
    return to_be16(v);
}

} // namespace

// ------------------------------------------------------------------ Listener

bool Listener::accept(Connection& out, int timeout_ms) noexcept {
    if (fd_ < 0) {
        return false;
    }
    // Waiting for readiness first is what makes the timeout real. A blocking
    // accept cannot be given a deadline, and a run that asked for a debugger
    // port would then sit here forever when nobody connects.
    sys::PollFd pfd{};
    pfd.fd = fd_;
    pfd.events = kPollIn;
    pfd.revents = 0;
    const auto ready = sys::poll(&pfd, 1, timeout_ms);
    if (ready.failed() || ready.value == 0) {
        return false;
    }

    // Readiness is not the same answer as readability. poll reports an error
    // on the listening socket -- a revoked capability, a descriptor closed
    // under us -- by setting POLLERR or POLLHUP in revents, and it reports
    // them *without* POLLIN. Calling accept4 anyway turns one failure into a
    // second one, and the second is the one the caller sees, so the error
    // that explains it is the one that gets reported. Returning here keeps
    // the first cause and skips a syscall that cannot succeed.
    if ((pfd.revents & kPollIn) == 0) {
        return false;
    }

    const auto fd = sys::accept4(fd_, nullptr, nullptr, kSockCloexec);
    if (fd.failed()) {
        return false;
    }
    out.adopt(static_cast<int>(fd.value));
    return true;
}

Listener::~Listener() noexcept { close(); }

Listener::Listener(Listener&& other) noexcept
    : fd_(other.fd_), port_(other.port_) {
    other.fd_ = -1;
    other.port_ = 0;
}

Listener& Listener::operator=(Listener&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.fd_;
        port_ = other.port_;
        other.fd_ = -1;
        other.port_ = 0;
    }
    return *this;
}

bool Listener::open(std::uint16_t port, std::string& error) noexcept {
    close();

    const auto sock = sys::socket(kAfInet, kSockStream | kSockCloexec, 0);
    if (sock.failed()) {
        // `error`, not `value`. A failed Result carries the negative of the
        // errno in `value` -- classify() builds it as Result{raw, -raw} --
        // so reading the number out of `value` hands strerror a negative
        // errno and the message names the wrong failure or none at all.
        error = std::string{"cannot create a socket: "} +
                util::strerror(sock.error);
        return false;
    }
    fd_ = static_cast<int>(sock.value);

    // The three fields have three different byte orders, which is the whole
    // reason this structure is written out. sin_family is the address family
    // as a host-order number -- 2 for AF_INET -- and swapping its bytes makes
    // it 512, which the kernel rejects with an address-family error that
    // looks like a policy refusal rather than a mistake. sin_port and
    // sin_addr are in network order.
    SockAddrIn addr{};
    addr.family = kAfInet;
    addr.port = sin_port(port);
    addr.addr = kLoopbackV4;

    const auto bound = sys::bind(fd_, &addr, sizeof(addr));
    if (bound.failed()) {
        // The two failures here call for different responses from whoever
        // asked for the port, so they are named rather than reported as a
        // single "bind failed".
        //
        // The comparison is against the positive errno in `error`. Reading
        // the number out of `value` gives its negation, and a comparison
        // between that and kEaddrinuse can never be true -- the branch is
        // still compiled, still looks like it handles the busy port, and
        // never runs. A busy port would then be reported as "cannot bind the
        // port: Invalid argument", which is the kind of message that sends
        // an operator looking at the wrong thing.
        const int err = bound.error;
        error = err == sys::kEaddrinuse
                    ? "the port is already in use by another session"
                    : std::string{"cannot bind the port: "} + util::strerror(err);
        close();
        return false;
    }

    // Read the port back, because a request for zero is answered by the
    // kernel and the caller has to be told which one it got.
    SockAddrIn chosen{};
    unsigned int chosen_len = sizeof(chosen);
    if (sys::getsockname(fd_, &chosen, &chosen_len).ok() && chosen_len >= 8) {
        port_ = from_be16(chosen.port);
    } else {
        port_ = port;
    }

    const auto listening = sys::listen(fd_, 1);
    if (listening.failed()) {
        error = std::string{"cannot listen: "} +
                util::strerror(listening.error);
        close();
        return false;
    }
    return true;
}

void Listener::close() noexcept {
    if (fd_ >= 0) {
        (void)sys::close(fd_);
        fd_ = -1;
    }
    port_ = 0;
}

// ---------------------------------------------------------------- Connection

Connection::~Connection() noexcept { close(); }

Connection::Connection(Connection&& other) noexcept
    : fd_(other.fd_), decoder_(std::move(other.decoder_)) {
    other.fd_ = -1;
}

Connection& Connection::operator=(Connection&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.fd_;
        decoder_ = std::move(other.decoder_);
        other.fd_ = -1;
    }
    return *this;
}

void Connection::adopt(int fd) noexcept {
    close();
    fd_ = fd;
}

void Connection::close() noexcept {
    if (fd_ >= 0) {
        (void)sys::close(fd_);
        fd_ = -1;
    }
    decoder_ = PacketDecoder{};
}

bool Connection::pump() noexcept {
    if (fd_ < 0) {
        return false;
    }
    char buf[4096];
    const auto got = sys::read(fd_, buf, sizeof(buf));
    if (got.ok()) {
        if (got.value == 0) {
            return false; // the peer closed
        }
        decoder_.feed(buf, static_cast<std::size_t>(got.value));
        return true;
    }
    // A read that would block means there is nothing yet, which is not a
    // failure: the caller waits for readiness and comes back. EAGAIN is
    // checked alongside EINTR because the two arrive by different routes and
    // both mean "nothing was transferred, and nothing is wrong". The
    // descriptor is blocking today, so EAGAIN cannot be produced by this
    // socket as it stands -- and a caller may set O_NONBLOCK on it, which is
    // the caller's right and which would turn this function's answer to a
    // moment of quiet into "the peer closed" if only EINTR were handled.
    if (got.error == sys::kEintr || got.error == sys::kEagain) {
        return true;
    }
    return false;
}

bool Connection::flush_ack() noexcept {
    if (fd_ < 0 || !decoder_.needs_ack()) {
        return true;
    }
    const char ack = decoder_.pending_ack();
    // A single byte, written directly: going through send_packet would frame
    // an acknowledgement, and an acknowledgement is not a packet.
    //
    // The acknowledgement is cleared only once it has been written. Clearing
    // it first and writing second loses it on any failure that is not
    // EINTR: the decoder has already forgotten it, so flush_ack() returns
    // true on the next call without a byte having left the process, and the
    // client waits for a '+' that will never come. The order below means a
    // failure leaves the acknowledgement pending, so the caller that
    // retries -- or the caller that reports the failure -- has something to
    // retry or report.
    const auto wrote = sys::write(fd_, &ack, 1);
    if (wrote.failed()) {
        // EINTR is the one failure that carries no information: the signal
        // arrived before any byte was transferred, and the same write can be
        // tried again. Returning false here is still the correct answer,
        // because this call transferred nothing -- the previous version
        // returned true, which told the caller the byte was on its way when
        // it had not been written at all.
        return false;
    }
    decoder_.clear_ack();
    return true;
}

bool Connection::has_packet() const noexcept {
    return decoder_.has_packet() && !decoder_.retransmit_requested();
}

bool Connection::retransmit_requested() const noexcept {
    return decoder_.retransmit_requested();
}

void Connection::clear_retransmit() noexcept { decoder_.clear_retransmit(); }

const std::string& Connection::last_packet() const noexcept {
    return decoder_.last_packet();
}

bool Connection::take_packet(std::string& out) noexcept {
    if (!decoder_.has_packet()) {
        return false;
    }
    Packet p = decoder_.take();
    // A packet whose checksum failed has no usable payload. It is dropped
    // rather than handed on, because a command read out of a corrupt packet
    // is a command nobody sent: resuming a process, or writing its memory,
    // on the strength of a transmission error is the worst thing a debugger
    // stub can do. The decoder has already recorded the retransmission.
    if (!p.checksum_ok) {
        out.clear();
        return false;
    }
    out.assign(p.data);
    return true;
}

bool Connection::send_packet(std::string_view payload) noexcept {
    if (fd_ < 0) {
        return false;
    }
    const std::string framed = encode_packet(payload);
    std::size_t sent = 0;
    while (sent < framed.size()) {
        const auto wrote =
            sys::write(fd_, framed.data() + sent, framed.size() - sent);
        if (wrote.failed()) {
            if (wrote.value == -sys::kEintr) {
                continue;
            }
            return false;
        }
        sent += static_cast<std::size_t>(wrote.value);
    }
    return true;
}

bool Connection::wait_readable(int timeout_ms) noexcept {
    if (fd_ < 0) {
        return false;
    }
    // POLLIN is 0x0001. It is the only event that matters here: the reply to
    // a packet is written immediately and never waited on, and a debugger
    // that goes quiet is noticed by the timeout rather than by an event.
    sys::PollFd pfd{};
    pfd.fd = fd_;
    pfd.events = 0x0001;
    pfd.revents = 0;
    const auto ready = sys::poll(&pfd, 1, timeout_ms);
    return ready.ok() && ready.value > 0;
}

// The serve loop lives in session.cpp, next to the tracee loop it has to
// interleave with. This file is only the transport: a place to bind, accept,
// and move bytes. Splitting it that way keeps the socket handling testable
// without a process and keeps the loop that owns the tracee in one place.

} // namespace occ::obs

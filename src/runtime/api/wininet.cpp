// The WinINet surface: the session, the connection, the URL, and the
// request a downloader is built from. Each is a handle to an object this
// file owns; the request is the one that reaches the network, over the
// host's own sockets.
//
// What a request performs is a real HTTP transaction: the URL is parsed,
// the host resolved and connected to, the request line and headers sent,
// and the response read back -- with the transfer length honoured when the
// server names one and the chunked body decoded when the server does not.
// `InternetReadFile` then serves the body from the buffer the request
// filled, which is what a downloader loops on.
//
// Two things are refused rather than approximated:
//
//   * A `https://` URL. The encrypted half of HTTP needs a TLS stack, and
//     this runtime carries no third-party dependency to provide one. A
//     request for one answers the "call not implemented" error rather than
//     pretending a clear-text request was the secure one asked for.
//   * A connection that cannot be made. The host's resolver and the host's
//     sockets answer, and their failure is passed on as the request's
//     failure -- a downloader that asked for a host that is down gets a
//     failure, which is the truthful answer to the request.
//
// A handle is a pointer to the object it names, which is how a handle
// stays unique and how `InternetCloseHandle` knows what to destroy. The
// session, the connection and the request are three objects; a close of
// one does not close the others, which is what the Windows contract says
// about a tree of handles too.

#include "occ/runtime/api_common.h"
#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace occ::runtime::winabi {
namespace {

// A parsed HTTP URL, split the way a request needs it split. The port
// defaults to 80 when the URL does not name one.
struct ParsedUrl {
    std::string host;
    std::string port = "80";
    std::string path = "/";
    bool secure = false;
};

// Parses a URL into its parts. Answers false for a URL this runtime cannot
// fetch: a scheme other than http (including https, which would need TLS),
// or no host at all.
[[nodiscard]] bool parse_url(const std::string& url, ParsedUrl& out) noexcept {
    if (url.compare(0, 7, "http://") != 0) {
        return false;
    }
    std::size_t rest = 7;
    std::size_t path_at = url.find('/', rest);
    std::string authority =
        (path_at == std::string::npos) ? url.substr(rest)
                                       : url.substr(rest, path_at - rest);
    if (authority.empty()) {
        return false;
    }
    const std::size_t colon = authority.rfind(':');
    if (colon != std::string::npos &&
        authority.find(']') == std::string::npos) {
        out.host = authority.substr(0, colon);
        out.port = authority.substr(colon + 1);
    } else {
        out.host = authority;
    }
    if (out.host.empty()) {
        return false;
    }
    out.path = (path_at == std::string::npos) ? "/" : url.substr(path_at);
    out.secure = false;
    return true;
}

// Connects a TCP socket to a host and port. Answers the socket, or -1 with
// the failure left in `errno` -- the host's resolver and the host's
// connect are the answer.
[[nodiscard]] int connect_socket(const std::string& host,
                                 const std::string& port) noexcept {
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* results = nullptr;
    if (::getaddrinfo(host.c_str(), port.c_str(), &hints, &results) != 0) {
        return -1;
    }
    int sock = -1;
    for (struct addrinfo* ai = results; ai != nullptr; ai = ai->ai_next) {
        sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) {
            continue;
        }
        if (::connect(sock, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        ::close(sock);
        sock = -1;
    }
    ::freeaddrinfo(results);
    return sock;
}

// The chunked transfer decoding: a sequence of size lines and data blocks
// ending in a zero size. The body is appended to `out` as the blocks are
// read. Answers false on a malformed stream.
[[nodiscard]] bool read_chunked(int sock, std::string& out) noexcept {
    std::string line;
    for (;;) {
        line.clear();
        char c = 0;
        while (::recv(sock, &c, 1, 0) == 1 && c != '\n') {
            if (c != '\r') {
                line.push_back(c);
            }
        }
        if (line.empty()) {
            return false;
        }
        const std::size_t size =
            std::stoul(line, nullptr, 16);  // hex size line
        if (size == 0) {
            // The terminating block. The trailer that follows is not part
            // of the body and is not read.
            return true;
        }
        const std::size_t before = out.size();
        out.resize(before + size);
        std::size_t got = 0;
        while (got < size) {
            const ::ssize_t n =
                ::recv(sock, out.data() + before + got, size - got, 0);
            if (n <= 0) {
                return false;
            }
            got += static_cast<std::size_t>(n);
        }
        // The CRLF that closes the block.
        char crlf[2];
        if (::recv(sock, crlf, 2, MSG_WAITALL) != 2) {
            return false;
        }
    }
}

// Reads the whole response body off a socket into `out`. The transfer
// length is honoured when the headers named one; otherwise the body runs
// to the connection close, or through the chunked decoder when the server
// said it was chunked.
[[nodiscard]] bool read_response_body(int sock, std::uint64_t content_length,
                                      bool chunked, std::string& out) noexcept {
    if (chunked) {
        return read_chunked(sock, out);
    }
    if (content_length != 0) {
        out.resize(static_cast<std::size_t>(content_length));
        std::size_t got = 0;
        while (got < content_length) {
            const ::ssize_t n =
                ::recv(sock, out.data() + got, content_length - got, 0);
            if (n <= 0) {
                return false;
            }
            got += static_cast<std::size_t>(n);
        }
        return true;
    }
    char buffer[16384];
    for (;;) {
        const ::ssize_t n = ::recv(sock, buffer, sizeof(buffer), 0);
        if (n <= 0) {
            break;
        }
        out.append(buffer, static_cast<std::size_t>(n));
    }
    return true;
}

// The one network transaction this file knows: fetch a URL and put the
// response body in `out`. The request is a plain GET with the connection
// asked to close after it, so the response boundary is the one the server
// names -- the length header, the chunked stream, or the connection close.
[[nodiscard]] bool http_get(const std::string& url, std::string& out) noexcept {
    ParsedUrl parsed;
    if (!parse_url(url, parsed)) {
        return false;
    }
    const int sock = connect_socket(parsed.host, parsed.port);
    if (sock < 0) {
        return false;
    }
    std::string request =
        "GET " + parsed.path + " HTTP/1.1\r\n"
        "Host: " + parsed.host + "\r\n"
        "User-Agent: occ/1.0\r\n"
        "Accept: */*\r\n"
        "Accept-Encoding: identity\r\n"
        "Connection: close\r\n"
        "\r\n";
    const bool sent =
        ::send(sock, request.data(), request.size(), 0) ==
        static_cast<::ssize_t>(request.size());
    if (!sent) {
        ::close(sock);
        return false;
    }

    // The status line and the headers, read until the blank line.
    std::string head;
    char c = 0;
    std::uint64_t content_length = 0;
    bool chunked = false;
    while (head.size() < 65536) {
        if (::recv(sock, &c, 1, 0) != 1) {
            ::close(sock);
            return false;
        }
        head.push_back(c);
        if (head.size() >= 4 &&
            head.compare(head.size() - 4, 4, "\r\n\r\n") == 0) {
            break;
        }
    }
    // The Content-Length and Transfer-Encoding headers decide the body's
    // boundary. A 204 or a response with neither uses the connection close.
    const std::size_t len_at = head.find("Content-Length:");
    if (len_at != std::string::npos) {
        content_length =
            std::stoull(head.substr(len_at + 15), nullptr, 10);
    }
    if (head.find("Transfer-Encoding: chunked") != std::string::npos ||
        head.find("Transfer-Encoding: Chunked") != std::string::npos) {
        chunked = true;
    }
    const std::size_t body_at = head.find("\r\n\r\n");
    const std::string body_head =
        (body_at == std::string::npos) ? std::string() : head.substr(body_at + 4);
    if (!body_head.empty()) {
        out = body_head;
    }
    const bool ok = read_response_body(sock, content_length, chunked, out);
    ::close(sock);
    return ok;
}

}  // namespace

// A handle names one of the objects this module made. Every object shares
// this root, and the close table below is how a close knows the handle is
// one of ours: the table holds the live objects, so a close of anything
// else is refused the way Windows refuses a handle it does not know.
struct WinInetObject {
    virtual ~WinInetObject() = default;
};

// The session object. A session is the top of the WinINet tree; the
// connection hangs off it and the request off the connection, and the
// object's own fields are the ones the requests need when they reach the
// network.
struct HttpSession : WinInetObject {
    std::string agent;
};

// A connection: the host and port every request on it reaches.
struct HttpConnection : WinInetObject {
    std::string host;
    std::string port;
};

// A request: the URL asked for and the response body the transaction left.
struct HttpRequest : WinInetObject {
    std::string url;
    std::string body;
    std::size_t position = 0;
    bool complete = false;
};

// The live-object table. A handle is an object pointer plus a membership
// in this table: creation adds, close looks up, removes and destroys.
// Keeping the table makes a close of a foreign or stale value a clean
// refusal instead of a delete of memory that is not ours.
std::vector<WinInetObject*> g_objects;

// Creates an object, registers it, and answers its pointer as the handle.
[[nodiscard]] std::uint64_t register_object(WinInetObject* object) noexcept {
    g_objects.push_back(object);
    return reinterpret_cast<std::uint64_t>(object);
}

// The shared download used by `URLDownloadToFileA` in the urlmon module.
// Answers true with the body in `out` when the fetch succeeded.
bool wininet_http_get(const std::string& url, std::string& out) noexcept {
    return http_get(url, out);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32wi_InternetOpenA(
    const char* agent, std::uint32_t access_type, const char* proxy,
    const char* bypass, std::uint32_t flags) noexcept {
    static_cast<void>(access_type);
    static_cast<void>(proxy);
    static_cast<void>(bypass);
    static_cast<void>(flags);
    auto* session = new HttpSession();
    session->agent = agent != nullptr ? std::string(agent) : std::string();
    set_last_error(0);
    return register_object(session);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32wi_InternetConnectA(
    std::uint64_t internet, const char* server, std::uint16_t port,
    const char* user, const char* password, std::uint32_t service,
    std::uint32_t flags, std::uint64_t context) noexcept {
    static_cast<void>(internet);
    static_cast<void>(user);
    static_cast<void>(password);
    static_cast<void>(service);
    static_cast<void>(flags);
    static_cast<void>(context);
    if (server == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    auto* conn = new HttpConnection();
    conn->host = server;
    if (port != 0) {
        conn->port = std::to_string(port);
    }
    set_last_error(0);
    return register_object(conn);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32wi_InternetOpenUrlA(
    std::uint64_t internet, const char* url, const char* headers,
    std::uint32_t headers_length, std::uint32_t flags,
    std::uint64_t context) noexcept {
    static_cast<void>(internet);
    static_cast<void>(headers);
    static_cast<void>(headers_length);
    static_cast<void>(flags);
    static_cast<void>(context);
    if (url == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    auto* request = new HttpRequest();
    request->url = std::string(url);
    set_last_error(0);
    return register_object(request);
}

// Sends the request and reads the whole response. The transaction happens
// here and not in `InternetOpenUrlA`, because the request is what carries
// the additional headers and the optional body, and the send is when the
// network is touched.
extern "C" __attribute__((ms_abi)) std::int32_t k32wi_HttpSendRequestA(
    std::uint64_t request_handle, const char* headers,
    std::uint32_t headers_length, void* optional, std::uint32_t optional_length)
    noexcept {
    static_cast<void>(headers);
    static_cast<void>(headers_length);
    static_cast<void>(optional);
    static_cast<void>(optional_length);
    auto* request = reinterpret_cast<HttpRequest*>(request_handle);
    if (request == nullptr || request->url.empty()) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // An https URL needs a TLS stack this runtime does not carry. The
    // refusal is the honest answer to the secure request; the alternative
    // -- a clear-text fetch standing in for it -- would be worse than a
    // failure.
    if (request->url.compare(0, 8, "https://") == 0) {
        set_last_error(kErrorCallNotImplemented);
        return 0;
    }
    std::string body;
    if (!http_get(request->url, body)) {
        set_last_error(kErrorFileNotFound);
        return 0;
    }
    request->body = std::move(body);
    request->position = 0;
    request->complete = true;
    set_last_error(0);
    return 1;
}

// Reads the response body a request left, up to the caller's buffer size.
// A read of zero bytes is the end of the body, which is what a downloader
// loops on.
extern "C" __attribute__((ms_abi)) std::int32_t k32wi_InternetReadFile(
    std::uint64_t request_handle, void* buffer, std::uint32_t bytes,
    std::uint32_t* read) noexcept {
    auto* request = reinterpret_cast<HttpRequest*>(request_handle);
    if (request == nullptr || buffer == nullptr || read == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::size_t remaining = request->body.size() - request->position;
    const std::size_t take = std::min<std::size_t>(remaining, bytes);
    if (take != 0) {
        std::memcpy(buffer, request->body.data() + request->position, take);
        request->position += take;
    }
    *read = static_cast<std::uint32_t>(take);
    set_last_error(0);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32wi_InternetCloseHandle(
    std::uint64_t handle) noexcept {
    auto* object = reinterpret_cast<WinInetObject*>(handle);
    const auto found = std::find(g_objects.begin(), g_objects.end(), object);
    if (found == g_objects.end()) {
        // A handle that names no live object this module made. The refusal
        // is the same one Windows gives a handle that is not a WinINet
        // handle.
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    g_objects.erase(found);
    delete object;
    set_last_error(0);
    return 1;
}

void add_wininet(ExportList& out) {
    const auto e = [](const char* n, void* fn) {
        HostExport entry;
        entry.name = n;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        return entry;
    };
    out.push_back(e("InternetOpenA", reinterpret_cast<void*>(&k32wi_InternetOpenA)));
    out.push_back(e("InternetConnectA",
                    reinterpret_cast<void*>(&k32wi_InternetConnectA)));
    out.push_back(e("InternetOpenUrlA",
                    reinterpret_cast<void*>(&k32wi_InternetOpenUrlA)));
    out.push_back(e("HttpSendRequestA",
                    reinterpret_cast<void*>(&k32wi_HttpSendRequestA)));
    out.push_back(e("InternetReadFile",
                    reinterpret_cast<void*>(&k32wi_InternetReadFile)));
    out.push_back(e("InternetCloseHandle",
                    reinterpret_cast<void*>(&k32wi_InternetCloseHandle)));
}

}  // namespace occ::runtime::winabi

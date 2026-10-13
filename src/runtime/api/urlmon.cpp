// The urlmon surface: `URLDownloadToFileA`, the one-call download a
// loader or an updater uses instead of building the WinINet tree.
//
// The download is the same fetch the WinINet module performs -- the shared
// `http_get` is this file's engine too -- and the only new work is the
// landing: the URL's body is written to the file the caller named, with the
// DOS path translated to the host path the way every file name in this
// runtime travels. The answer is the HRESULT the call documents: `S_OK`
// for a file that landed, `INET_E_DOWNLOAD_FAILURE` for a fetch that did
// not, and the failure of the file write is the download's failure too --
// a caller that asked for a file where one cannot be written is answered
// with the failure, which is what "download to file" means.

#include "occ/runtime/api_common.h"
#include "occ/runtime/api.h"
#include "occ/runtime/dos_path.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <string>

#include <fcntl.h>
#include <unistd.h>

namespace occ::runtime::winabi {

// The download engine, provided by the WinINet module: a GET of `url` with
// the response body in `out`.
bool wininet_http_get(const std::string& url, std::string& out) noexcept;

namespace {

// The HRESULTs this call answers with. Success is zero; the failure is the
// one the URL moniker documents for a download that could not be made.
constexpr std::uint32_t kHrOk = 0;
constexpr std::uint32_t kHrDownloadFailure = 0x800C0008u;  // INET_E_DOWNLOAD_FAILURE

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t k32um_URLDownloadToFileA(
    std::uint64_t caller, const char* url, const char* filename,
    std::uint32_t reserved, std::uint64_t callback) noexcept {
    static_cast<void>(caller);
    static_cast<void>(reserved);
    static_cast<void>(callback);
    if (url == nullptr || filename == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return kHrDownloadFailure;
    }
    std::string body;
    if (!wininet_http_get(std::string(url), body)) {
        set_last_error(kErrorFileNotFound);
        return kHrDownloadFailure;
    }
    // The file name travels as a DOS path, the way every name a guest
    // writes travels; the translation is the host path the file is made
    // at.
    const std::string host_path = from_dos_path(filename);
    const int fd = ::open(host_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) {
        set_last_error(kErrorAccessDenied);
        return kHrDownloadFailure;
    }
    std::size_t written = 0;
    while (written < body.size()) {
        const ::ssize_t n =
            ::write(fd, body.data() + written, body.size() - written);
        if (n <= 0) {
            ::close(fd);
            set_last_error(kErrorAccessDenied);
            return kHrDownloadFailure;
        }
        written += static_cast<std::size_t>(n);
    }
    ::close(fd);
    set_last_error(0);
    return kHrOk;
}

void add_urlmon(ExportList& out) {
    HostExport entry;
    entry.name = "URLDownloadToFileA";
    entry.address = reinterpret_cast<std::uint64_t>(&k32um_URLDownloadToFileA);
    out.push_back(entry);
}

}  // namespace occ::runtime::winabi

// The process-and-file extensions a launcher reaches for: the legacy
// `WinExec` that starts a program without the `CreateProcess` contract, and
// the temporary-name maker that a program builds scratch files from.
//
// `CreateProcess` is refused by this runtime -- its contract carries
// handles, a process-information block and an environment the single
// process model cannot answer -- but `WinExec` carries none of that: it
// starts a command and answers a small number. That smaller contract can be
// fulfilled truly, by starting the command on the host. The command runs as
// a host process, which is what "started" means here; the caller that
// needed the started program to share this runtime's address space asked
// for something `CreateProcess` would have to refuse anyway.
//
// `GetTempFileNameA` is the file half of the pair. It names a file that is
// guaranteed not to exist, creates it, and hands the name back; the caller
// that wanted a path without a file asks for the variant and the file is
// still what the call means on Windows.

#include "occ/runtime/api_common.h"
#include "occ/runtime/api.h"
#include "occ/runtime/dos_path.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace occ::runtime::winabi {
namespace {

// A `WinExec` answer above this value means "started"; below it, the value
// is the error. The boundary is the one Windows documents.
constexpr std::uint32_t kWinExecOkFloor = 32;

// The suffix of a temporary name, and the number of random characters the
// unique half contributes.
constexpr const char* kTempSuffix = ".tmp";

// Whether a file exists at a path, which is what "unique" is tested
// against: the name has to name nothing yet.
[[nodiscard]] bool path_exists(const std::string& path) noexcept {
    struct stat st;
    return ::stat(path.c_str(), &st) == 0;
}

}  // namespace

// Starts a command line on the host and answers the success value. The
// show-window hint is not modelled: the started process is a host process
// and its window state is the host's to decide, which is the honest answer
// to a hint this runtime cannot hand across.
extern "C" __attribute__((ms_abi)) std::uint32_t k32pe_WinExec(
    const char* command, std::uint32_t show) noexcept {
    static_cast<void>(show);
    if (command == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const pid_t pid = ::fork();
    if (pid < 0) {
        set_last_error(kErrorNotEnoughMemory);
        return 0;
    }
    if (pid == 0) {
        // The child. The command is a command line, which the shell is the
        // thing that interprets; execvp of the shell with the line is what
        // "run this command" means on the host.
        ::execl("/bin/sh", "sh", "-c", command,
                static_cast<char*>(nullptr));
        ::_exit(127);
    }
    // The parent does not wait: `WinExec` returns as soon as the command is
    // started, and the started process runs on. Reaping it is the host's
    // business, and a child that outlives its parent is adopted by init.
    set_last_error(0);
    return kWinExecOkFloor;
}

// Names a temporary file that does not exist and creates it. A zero
// `uUnique` asks the call to choose the number; a non-zero one asks for
// that number specifically, and the call answers the number it used.
extern "C" __attribute__((ms_abi)) std::uint32_t k32pe_GetTempFileNameA(
    const char* path, const char* prefix, std::uint32_t unique,
    char* out) noexcept {
    if (path == nullptr || out == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The directory is a DOS path -- `Z:\tmp` or `C:\tmp` -- and the host
    // file is made at the host path it names. A path with no drive is
    // returned as written by the translation, which is what a caller that
    // names a host path directly asks for.
    std::string base = from_dos_path(std::string(path));
    while (!base.empty() && (base.back() == '\\' || base.back() == '/')) {
        base.pop_back();
    }
    if (base.empty()) {
        set_last_error(kErrorPathNotFound);
        return 0;
    }
    std::string pre;
    if (prefix != nullptr) {
        pre = std::string(prefix);
        if (pre.size() > 3) {
            pre.resize(3);
        }
    }
    // The number the call answers with: the caller's when it named one, and
    // a fresh one otherwise. The search is sequential from a seed that
    // changes per call, which is what a single process can do without a
    // global uniqueness service.
    std::uint32_t number = unique;
    if (number == 0) {
        const std::uint32_t seed =
            static_cast<std::uint32_t>(::getpid() ^ (::getpid() << 16));
        number = seed != 0 ? seed : 1;
    }
    for (std::uint32_t probe = 0; probe < 65536; ++probe) {
        const std::uint32_t candidate = (number + probe) & 0xFFFFu;
        char digits[8];
        std::snprintf(digits, sizeof(digits), "%04X", candidate);
        std::string name = base + "/" + pre + digits + kTempSuffix;
        if (path_exists(name)) {
            if (unique != 0) {
                // The caller named a number that is taken. Windows refuses
                // rather than searching past it.
                set_last_error(kErrorFileExists);
                return 0;
            }
            continue;
        }
        const int fd = ::open(name.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (fd < 0) {
            if (errno == EEXIST) {
                continue;
            }
            set_last_error(kErrorAccessDenied);
            return 0;
        }
        ::close(fd);
        std::strcpy(out, name.c_str());
        set_last_error(0);
        return candidate;
    }
    set_last_error(kErrorFileExists);
    return 0;
}

void add_kernel32_proc_ext(ExportList& out) {
    const auto e = [](const char* n, void* fn) {
        HostExport entry;
        entry.name = n;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        return entry;
    };
    out.push_back(e("WinExec", reinterpret_cast<void*>(&k32pe_WinExec)));
    out.push_back(e("GetTempFileNameA",
                    reinterpret_cast<void*>(&k32pe_GetTempFileNameA)));
}

}  // namespace occ::runtime::winabi

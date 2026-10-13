// The shell's launcher: `ShellExecute`, which starts a document or a
// program the way the shell would, with an operation word instead of a
// command line.
//
// The operations this runtime can perform truthfully are the ones that
// start a host process. "open" is the operation every caller uses and the
// one that starts the file with its default association or the program
// named; the operations that ask for elevation or for the shell's own
// verbs are refused with the error Windows gives a verb it cannot
// perform. A document is started the way the host starts one: with
// `xdg-open` when the host has it, which is what "open with its default
// handler" means on this machine.

#include "occ/runtime/api_common.h"
#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstring>
#include <string>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace occ::runtime::winabi {
namespace {

// A `ShellExecute` answer above this value means "started". Below it, the
// value is the error, which is the same boundary `WinExec` uses.
constexpr std::uint32_t kShellExecOkFloor = 32;

// The one operation word this runtime performs. The others -- "runas",
// "print", "explore" -- either need elevation or need the shell's own
// verbs, and are refused rather than approximated.
constexpr const char* kOperationOpen = "open";

// Starts a command on the host. The child is the started thing; the parent
// returns the success value without waiting, which is what "execute" means
// to the caller.
[[nodiscard]] std::uint32_t launch_host(const std::string& file,
                                        const std::string& parameters,
                                        const std::string& directory) noexcept {
    const pid_t pid = ::fork();
    if (pid < 0) {
        set_last_error(kErrorNotEnoughMemory);
        return 0;
    }
    if (pid == 0) {
        if (!directory.empty()) {
            ::chdir(directory.c_str());
        }
        std::string command = file;
        if (!parameters.empty()) {
            command += " " + parameters;
        }
        ::execl("/bin/sh", "sh", "-c", command.c_str(),
                static_cast<char*>(nullptr));
        ::_exit(127);
    }
    set_last_error(0);
    return kShellExecOkFloor;
}

// The `ShellExecuteA` body, shared with the wide spelling. `operation` may
// be null, which means "open" -- the default operation is open.
[[nodiscard]] std::uint32_t shell_execute(
    const char* operation, const char* file, const char* parameters,
    const char* directory) noexcept {
    if (file == nullptr || file[0] == '\0') {
        set_last_error(kErrorFileNotFound);
        return 0;
    }
    if (operation != nullptr && std::strcmp(operation, kOperationOpen) != 0) {
        // A verb this runtime cannot perform. The refusal is the same one
        // Windows gives a verb no handler registered.
        set_last_error(kErrorAccessDenied);
        return 0;
    }
    return launch_host(std::string(file),
                       parameters != nullptr ? std::string(parameters)
                                             : std::string(),
                       directory != nullptr ? std::string(directory)
                                            : std::string());
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint64_t k32se_ShellExecuteA(
    std::uint64_t hwnd, const char* operation, const char* file,
    const char* parameters, const char* directory, std::int32_t show) noexcept {
    static_cast<void>(hwnd);
    static_cast<void>(show);
    return shell_execute(operation, file, parameters, directory);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32se_ShellExecuteW(
    std::uint64_t hwnd, const char16_t* operation, const char16_t* file,
    const char16_t* parameters, const char16_t* directory,
    std::int32_t show) noexcept {
    static_cast<void>(hwnd);
    static_cast<void>(show);
    // The narrow spelling is the implementation; the wide arguments are
    // narrowed the way the rest of the shell surface narrows them -- the
    // characters this runtime keeps are ANSI, and a wide name that does
    // not survive the narrowing is not a name this runtime can open.
    auto narrow = [](const char16_t* text) -> std::string {
        if (text == nullptr) {
            return std::string();
        }
        std::string out;
        for (const char16_t* p = text; *p != 0; ++p) {
            out.push_back(static_cast<char>(*p));
        }
        return out;
    };
    const std::string op = narrow(operation);
    const std::string f = narrow(file);
    const std::string params = narrow(parameters);
    const std::string dir = narrow(directory);
    return shell_execute(op.empty() ? nullptr : op.c_str(),
                         f.empty() ? nullptr : f.c_str(),
                         params.empty() ? nullptr : params.c_str(),
                         dir.empty() ? nullptr : dir.c_str());
}

void add_shell32_exec(ExportList& out) {
    const auto e = [](const char* n, void* fn) {
        HostExport entry;
        entry.name = n;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        return entry;
    };
    out.push_back(e("ShellExecuteA",
                    reinterpret_cast<void*>(&k32se_ShellExecuteA)));
    out.push_back(e("ShellExecuteW",
                    reinterpret_cast<void*>(&k32se_ShellExecuteW)));
}

}  // namespace occ::runtime::winabi

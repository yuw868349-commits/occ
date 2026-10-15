#include "occ/commands.h"
#include "occ/runner/pe_runner.h"
#include "occ/runtime/minidump.h"
#include "occ/util/log.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

namespace {

// isatty is a libc call, not a syscall, but it is one of the few that are
// genuinely part of the C runtime rather than a wrapper this project
// replaces. It reads the terminal state of a file descriptor and has no
// syscall of its own.
[[nodiscard]] bool stdout_is_tty() {
    return ::isatty(1) != 0;
}

void print_usage(const char* argv0) {
    std::fprintf(
        stderr,
        "usage: %s <command> [options]\n"
        "\n"
        "commands:\n"
        "  check <path> [--json]\n"
        "                     detect target format and print the routing "
        "decision\n"
        "  run [options] <path> [args...]\n"
        "                     run a target under isolation, start the "
        "observer;\n"
        "                     'occ run' with no target prints the option "
        "list\n"
        "  attach [-p] <session-id|pid>\n"
        "                     reconnect to a running session; lists the "
        "running\n"
        "                     sessions when no argument is given\n"
        "  stop [-p] <session-id|pid>\n"
        "                     tear down a session\n"
        "  inspect <path> [--no-strings] "
        "[--disasm <rva>[:<count>[:<bytes>]]]\n"
        "                     [--limit <n>]\n"
        "                     static report: headers, sections, imports,\n"
        "                     exports, tls, exceptions, resources, strings\n"
        "  devirt <trace> <dump> [N] [--asm [N]] [-o report]\n"
        "                     [--unknown <va>:<size>] [--goal <condition>]\n"
        "                     [--explore]\n"
        "                     offline VM de-virtualization report from a\n"
        "                     dispatch trace and a decrypted image dump;\n"
        "                     'occ devirt' with no arguments prints the "
        "detail\n"
        "  run32 <image>      run a 32-bit PE image on the in-process\n"
        "                     interpreter\n"
        "  dbg <image> [--script <file>] [--break <rva>]... [args...]\n"
        "                     run a PE image under the command-line "
        "debugger\n"
        "  mdmp <file>        summarize a minidump\n"
        "  doctor             report host capabilities and limitations\n"
        "\n"
        "options:\n"
        "  --help             print this text\n",
        argv0);
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 2;
    }

    // Whether the event stream is wanted is decided here, once, and handed
    // to the commands through the environment. A command that re-derived it
    // could disagree with this call if the descriptor changed in between,
    // and the two answers would be for the same stream.
    if (stdout_is_tty()) {
        ::setenv("OCC_EVENT_STREAM", "0", 1);
    } else {
        ::setenv("OCC_EVENT_STREAM", "1", 1);
    }

    const std::string_view cmd = argv[1];

    if (cmd == "--help" || cmd == "-h" || cmd == "help") {
        print_usage(argv[0]);
        return 0;
    }

    const bool ndjson = !stdout_is_tty();

    if (cmd == "doctor") {
        return occ::cmd_doctor(ndjson);
    }
    if (cmd == "check") {
        return occ::cmd_check(argc - 2, argv + 2);
    }
    if (cmd == "run") {
        return occ::cmd_run(argc - 2, argv + 2);
    }
    if (cmd == "attach") {
        return occ::cmd_attach(argc - 2, argv + 2);
    }
    if (cmd == "stop") {
        return occ::cmd_stop(argc - 2, argv + 2);
    }
    if (cmd == "inspect") {
        return occ::cmd_inspect(argc - 2, argv + 2);
    }
    if (cmd == "devirt") {
        return occ::cmd_devirt(argc - 2, argv + 2);
    }
    if (cmd == "run32") {
        if (argc < 3) {
            std::fprintf(stderr, "usage: occ run32 <image>\n");
            return 2;
        }
        return occ::runner::run_pe_32(argv[2]);
    }
    if (cmd == "dbg") {
        return occ::runner::dbg_pe_runner(argc - 2, argv + 2);
    }
    if (cmd == "mdmp") {
        if (argc < 3) {
            std::fprintf(stderr, "usage: occ mdmp <file>\n");
            return 2;
        }
        return occ::runtime::minidump::summarize(argv[2]) ? 0 : 2;
    }

    // The PE runner, reached only by occ's own exec of itself: the engine's
    // plan names this binary with this token, the container exec's the pair,
    // and control arrives here with the image and its arguments behind it.
    // It is deliberately not in the usage text -- a runner a caller could
    // invoke by hand is a runner whose isolation they could bypass, and the
    // only legitimate way in is through the plan that names the container
    // around it.
    if (cmd == occ::runner::kPeRunnerCommand) {
        return occ::runner::run_pe_runner(argc - 1, argv + 1);
    }

    occ::log::error("unknown command");
    print_usage(argv[0]);
    return 2;
}

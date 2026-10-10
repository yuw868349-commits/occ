#include "occ/runner/pe_runner.h"

#include "occ/inspect/disasm.h"
#include "occ/parser/pe.h"
#include "occ/runtime/exports.h"
#include "occ/runtime/guestdbg.h"
#include "occ/runtime/iat_rebuild.h"
#include "occ/runtime/minidump.h"
#include "occ/runtime/i386.h"
#include "occ/runtime/image_dump.h"
#include "occ/runtime/pe_process.h"
#include "occ/runtime/winabi.h"
#include "occ/util/fs.h"

#include <pthread.h>

#include <atomic>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <unistd.h>

extern "C" char** environ;

namespace occ::runner {

namespace {

// Prints one diagnostic line and answers the exit code a misuse deserves.
// Two is what `occ run` answers for a bad command line, and a runner that
// cannot start the image it was handed is reporting a bad command line at
// one remove: the parent planned it, and the parent's plan was wrong.
int runner_failure(const char* what, const std::string& detail) noexcept {
    std::fprintf(stderr, "occ %s: %s: %s\n", kPeRunnerCommand, what,
                 detail.c_str());
    return 2;
}

// The resolver the loader calls, which is the registry. The signature is
// `ProcessOptions::resolve`'s exactly -- the loader's own typedef, with the
// `const std::string&` parameters it was declared with -- because a member
// function taking `string_view` cannot sit in that pointer and a converting
// wrapper would be a second signature to keep in step with the first.
// Whether the run records the APIs the guest resolves.
//
// A packed image resolves what it needs at run time -- the import table it
// shipped with is encrypted, empty, or both -- so the list of names it asks
// for, in the order it asks, is the first thing a reader wants and the
// thing no static report can give: the names are not in the file. This is
// the guest-side counterpart of the observer's probes, and it exists
// because the observer cannot see this process's guest at all -- `ptrace`
// does not reach code the runtime runs in-process.
[[nodiscard]] bool api_trace_enabled() noexcept {
    static const bool enabled = [] {
        const char* value = ::getenv("OCC_API_TRACE");
        return value != nullptr && value[0] != '\0';
    }();
    return enabled;
}

std::uint64_t resolve_thunk(void* state, const std::string& dll,
                            const std::string& name, std::uint16_t ordinal,
                            bool by_ordinal) noexcept {
    auto* registry = static_cast<runtime::ExportRegistry*>(state);
    if (registry == nullptr) {
        return 0;
    }
    // The hint travels as zero: the registry verifies any hint against the
    // name before it believes it, so zero is merely "no better guess".
    const runtime::ExportLookup found =
        by_ordinal ? registry->find_by_ordinal(dll, ordinal)
                   : registry->find_by_name(dll, name, 0);
    if (api_trace_enabled()) {
        // The ordinal form names the request the way the guest made it: a
        // resolver reached by ordinal did not supply the name, and printing
        // one would invent the answer the guest never wrote.
        if (by_ordinal) {
            std::fprintf(stderr, "occ api: %s!#%u -> 0x%llx%s\n", dll.c_str(),
                         static_cast<unsigned>(ordinal),
                         static_cast<unsigned long long>(found.address),
                         found.address == 0 ? " (unresolved)" : "");
        } else {
            std::fprintf(stderr, "occ api: %s!%s -> 0x%llx%s\n", dll.c_str(),
                         name.c_str(),
                         static_cast<unsigned long long>(found.address),
                         found.address == 0 ? " (unresolved)" : "");
        }
    }
    return found.address;
}

} // namespace

namespace {

// The registry the built process resolves through. A file-scope pointer
// rather than a member of the session, because the process's resolver
// state points into it and both runners want the same lifetime rule: the
// registry outlives the guest.
std::unique_ptr<runtime::ExportRegistry> g_session_registry;

// Everything a session needs before the guest can run: the image parsed,
// the registry built, the process assembled. Both the plain run and the
// debug session want exactly this, which is why it is one function rather
// than a second copy of a hundred lines that would drift.
struct Session {
    std::unique_ptr<runtime::PeProcess> process;
    std::string error;
    bool ok() const noexcept { return process != nullptr; }
};

[[nodiscard]] Session build_session(const std::string& image_path,
                                    const std::vector<std::string>& guest_args) {
    Session session;

    auto bytes = fs::read_file_bytes(image_path);
    if (!bytes || bytes->empty()) {
        session.error = "the image could not be read: " + image_path;
        return session;
    }
    const ByteSpan span{bytes->data(), bytes->size()};

    const parser::PeImage image = parser::PeImage::parse(span);
    if (!image.ok()) {
        session.error =
            "the image is not a PE this runtime can load: " +
            std::string(parser::pe_error_name(image.error())) + ": " +
            image.error_detail();
        return session;
    }

    // The registry answers from the host implementations in `runtime/winabi`:
    // every KERNEL32 and msvcrt export the import table names is a host
    // function reached through a function call, which is the whole of the
    // difference between this and a loader that resolves imports into a
    // second copy of the API. There is no image side to these modules -- the
    // registry's own rule is that the host table is preferred over whatever
    // the file's export directory names, and there is no file export
    // directory to prefer it over.
    auto registry = std::make_unique<runtime::ExportRegistry>();
    runtime::winabi::register_host_modules(*registry);
    // The session keeps the registry alive past the process's build, because
    // the process's resolver points into it and the guest resolves imports
    // for as long as it runs.
    g_session_registry = std::move(registry);

    // The paths and the command line are the DOS forms the guest expects:
    // the image under the `Z:` drive the runtime maps the host's root onto,
    // and the arguments quoted by the Microsoft rules so that the split the
    // CRT performs on them returns exactly what the caller passed. argv[0]
    // is the image path, which is what a program on Windows sees and what
    // `args.exe` prints first.
    const std::string dos_path = runtime::winabi::to_dos_path(
        fs::absolute_path(image_path));

    runtime::ProcessOptions options;
    options.command_line = runtime::winabi::build_command_line(
        dos_path, guest_args);
    options.image_path = dos_path;
    // The heap list is built by the loader, which is the layer that knows
    // where in the guest's address space the process heap was placed. The
    // runner does not name it here: a handle spelled before the process
    // exists would be a second answer to a question the loader answers once.
    // The environment, unchanged: the caller's entries, the runner's
    // defaults, and nothing the runner invents. A Windows program reads its
    // environment through the PEB, and the PEB is built from these strings.
    for (char** e = environ; *e != nullptr; ++e) {
        options.environment.emplace_back(*e);
    }
    // The per-user directories a Windows program assumes exist. The
    // container's environment has no `LOCALAPPDATA` -- it names Linux
    // paths and Linux variables -- and a program that asks for its cache
    // directory gets "not defined" from Windows when the variable is
    // missing, which is the state the runner's defaults would leave every
    // guest in. The paths are the ones a single-user Windows install
    // spells, and the DOS-path layer resolves them onto the sandbox's
    // own storage.
    const char* kWindowsStandardVariables[] = {
        "LOCALAPPDATA=C:\\Users\\User\\AppData\\Local",
        "APPDATA=C:\\Users\\User\\AppData\\Roaming",
        "USERPROFILE=C:\\Users\\User",
        "HOMEDRIVE=C:",
        "HOMEPATH=\\Users\\User",
        "SYSTEMROOT=C:\\Windows",
        "windir=C:\\Windows",
        "TEMP=C:\\Users\\User\\AppData\\Local\\Temp",
        "TMP=C:\\Users\\User\\AppData\\Local\\Temp",
        "PROGRAMFILES=C:\\Program Files",
        "COMMONPROGRAMFILES=C:\\Program Files\\Common Files",
        "NUMBER_OF_PROCESSORS=8",
        "PROCESSOR_ARCHITECTURE=AMD64",
        "OS=Windows_NT",
    };
    for (const char* variable : kWindowsStandardVariables) {
        options.environment.emplace_back(variable);
    }
    options.resolver_state = g_session_registry.get();
    options.resolve = &resolve_thunk;

    runtime::ProcessImage failure;
    session.process =
        runtime::PeProcess::build(image, span, options, &failure);
    if (session.process == nullptr || !session.process->ok()) {
        session.process.reset();
        session.error = failure.detail.empty()
                            ? std::string(runtime::process_error_name(
                                  failure.error))
                            : failure.detail;
    }
    return session;
}

} // namespace

int run_pe_runner(int argc, char** argv) noexcept {
    if (argc < 2 || argv[1] == nullptr || argv[1][0] == '\0') {
        std::fprintf(stderr, "usage: occ %s <image> [arguments...]\n",
                     kPeRunnerCommand);
        return 2;
    }
    const std::string image_path = argv[1];
    std::vector<std::string> guest_args;
    guest_args.reserve(static_cast<std::size_t>(argc > 2 ? argc - 2 : 0));
    for (int i = 2; i < argc; ++i) {
        guest_args.emplace_back(argv[i]);
    }

    Session session = build_session(image_path, guest_args);
    if (!session.ok()) {
        return runner_failure("the image could not be built into a process",
                              session.error);
    }
    runtime::PeProcess* const process = session.process.get();

    // --- the run -----------------------------------------------------------

    const runtime::RunOutcome outcome = runtime::run_pe_process(*process);

    // The image as the run left it. For a program that decrypts itself --
    // which is the whole reason to ask for this -- the state that matters
    // exists only here: the file's copy of the payload is the encrypted
    // one, and the mapping is the only place the decrypted bytes were ever
    // together. Taken before the exit below, because after it there is
    // nothing to read.
    if (runtime::image_dump::enabled()) {
        const std::uint64_t base = process->image().module.base;
        const std::string out = runtime::image_dump::path();
        static_cast<void>(runtime::image_dump::dump(base, out));
        // The dump has the bytes; this says what they call. Written beside
        // the image so that the two travel together and a reader of one
        // has the other's answer to hand.
        static_cast<void>(runtime::iat_rebuild::report(base, out + ".iat.txt"));
    }

    // A fault the guest's own filter declined never gets here -- the process
    // is dead by the signal and the parent sees that. This is the fault the
    // filter accepted, and it is reported rather than swallowed: a program
    // that ended in an access violation should say so somewhere a person
    // reads, and stderr is where the event stream is not.
    if (!outcome.exited) {
        std::fprintf(stderr,
                     "occ %s: the guest ended in a fault (signal %d) at "
                     "address 0x%llx\n",
                     kPeRunnerCommand, outcome.signal,
                     static_cast<unsigned long long>(outcome.fault_address));
    }

    ::fflush(nullptr);
    // The guest's exit code, narrowed the way a Unix exit status is. The
    // parent's reap reads the narrowed value; the wide value was the guest's
    // and only the guest could have wanted all of it.
    ::_exit(static_cast<int>(outcome.exit_code & 0xFFu));
}

// ------------------------------------------------------------ the debugger

namespace {

// The guest thread's result, and the flag that says it is in. The driving
// thread polls these from its REPL; the guest thread writes them once,
// when run_pe_process returns.
::pthread_t g_guest_thread;
std::atomic<bool> g_guest_started{false};
std::atomic<bool> g_guest_finished{false};
runtime::RunOutcome g_guest_outcome{};

void* guest_thread_main(void* arg) noexcept {
    auto* process = static_cast<runtime::PeProcess*>(arg);
    g_guest_outcome = runtime::run_pe_process(*process);
    g_guest_finished.store(true, std::memory_order_seq_cst);
    return nullptr;
}

// Starts the guest on a thread with a stack big enough to be the guest's
// own -- the image names an initial stack, but the thread's stack is what
// the runtime's host side lives on while the guest runs, and a default
// pthread stack is thinner than a Windows program's habits.
[[nodiscard]] bool start_guest(runtime::PeProcess* process) noexcept {
    if (g_guest_started.exchange(true)) {
        return true;  // already started
    }
    ::pthread_attr_t attr;
    ::pthread_attr_init(&attr);
    ::pthread_attr_setstacksize(&attr, 64ULL * 1024 * 1024);
    const int made = ::pthread_create(&g_guest_thread, &attr,
                                      guest_thread_main, process);
    ::pthread_attr_destroy(&attr);
    return made == 0;
}

// Waits until the guest is either stopped at a breakpoint or finished.
// Polling, because the two states live on the other side of an atomic
// and there is nothing to block on that belongs to both threads.
void wait_for_event() noexcept {
    while (!g_guest_finished.load(std::memory_order_seq_cst) &&
           !runtime::guestdbg::guest_stopped()) {
        ::usleep(2000);
    }
}

// One hexdump line, in the form a reader can line up against a listing.
void hexdump(std::uint64_t address, const std::uint8_t* data,
             std::size_t bytes) noexcept {
    for (std::size_t row = 0; row < bytes; row += 16) {
        std::fprintf(stdout, "  %012llx  ",
                     static_cast<unsigned long long>(address + row));
        for (std::size_t i = 0; i < 16; ++i) {
            if (row + i < bytes) {
                std::fprintf(stdout, "%02x ", data[row + i]);
            } else {
                std::fprintf(stdout, "   ");
            }
            if (i == 7) {
                std::fprintf(stdout, " ");
            }
        }
        std::fprintf(stdout, " |");
        for (std::size_t i = 0; i < 16 && row + i < bytes; ++i) {
            const std::uint8_t c = data[row + i];
            std::fputc(c >= 0x20 && c < 0x7F ? c : '.', stdout);
        }
        std::fprintf(stdout, "|\n");
    }
}

// The registers a `regs` command names, in the order the guest thinks of
// them. The indices are the gregs order; naming them here once keeps the
// print honest about which number is which.
struct RegName {
    const char* name;
    int index;
};
constexpr RegName kRegNames[] = {
    {"rip", REG_RIP},   {"rsp", REG_RSP},  {"rbp", REG_RBP},
    {"rax", REG_RAX},   {"rbx", REG_RBX},  {"rcx", REG_RCX},
    {"rdx", REG_RDX},   {"rsi", REG_RSI},  {"rdi", REG_RDI},
    {"r8", REG_R8},     {"r9", REG_R9},    {"r10", REG_R10},
    {"r11", REG_R11},   {"r12", REG_R12},  {"r13", REG_R13},
    {"r14", REG_R14},   {"r15", REG_R15},  {"efl", REG_EFL},
};

// Waits for the guest after a start or a release, and reports what it
// came back as: a stop, with the reason and the rip; or an exit, with the
// code; or a fault, with the signal. Answers false when the session
// should end -- the guest is gone and the commands that read its state
// have nothing left to read.
[[nodiscard]] bool report_event() noexcept {
    wait_for_event();
    if (runtime::guestdbg::guest_stopped()) {
        const auto& stop = runtime::guestdbg::current_stop();
        if (stop.breakpoint != 0) {
            std::fprintf(stdout, "stop: breakpoint at 0x%llx\n",
                         static_cast<unsigned long long>(stop.breakpoint));
        } else {
            std::fprintf(stdout, "stop: step at 0x%llx\n",
                         static_cast<unsigned long long>(stop.rip));
        }
        return true;
    }
    if (g_guest_finished.load(std::memory_order_seq_cst)) {
        if (g_guest_outcome.exited) {
            std::fprintf(stdout, "exit: %d\n", g_guest_outcome.exit_code);
        } else {
            std::fprintf(stdout, "fault: signal %d at 0x%llx\n",
                         g_guest_outcome.signal,
                         static_cast<unsigned long long>(
                             g_guest_outcome.fault_address));
        }
        return false;
    }
    return true;
}

}  // namespace

int dbg_pe_runner(int argc, char** argv) noexcept {
    std::string image_path;
    std::vector<std::string> guest_args;
    std::vector<std::uint64_t> initial_breaks;
    const char* script_path = nullptr;
    for (int i = 0; i < argc; ++i) {
        const char* a = argv[i];
        if (std::strcmp(a, "--script") == 0 && i + 1 < argc) {
            script_path = argv[++i];
        } else if ((std::strcmp(a, "--break") == 0 ||
                    std::strcmp(a, "-b") == 0) &&
                   i + 1 < argc) {
            initial_breaks.push_back(
                std::strtoull(argv[++i], nullptr, 0));
        } else if (image_path.empty()) {
            image_path = a;
        } else {
            guest_args.emplace_back(a);
        }
    }
    if (image_path.empty()) {
        std::fprintf(stderr,
                     "usage: occ dbg <image> [--script <file>] "
                     "[--break <rva>]... [arguments...]\n");
        return 2;
    }

    // The debugger switches the runtime into its debugging shape before
    // anything reads it: the fault handler consults this once per trap.
    // stdout goes unbuffered with it: a session that dies in the guest's
    // signal path takes its buffered answers with it otherwise, and the
    // transcript up to the death is the part worth keeping.
    ::setenv("OCC_DEBUG_ACTIVE", "1", 1);
    ::setvbuf(stdout, nullptr, _IONBF, 0);

    Session session = build_session(image_path, guest_args);
    if (!session.ok()) {
        std::fprintf(stderr, "occ dbg: %s\n", session.error.c_str());
        return 2;
    }
    const std::uint64_t base = session.process->image().module.base;
    std::fprintf(stdout, "image at 0x%llx, entry rva 0x%llx\n",
                 static_cast<unsigned long long>(base),
                 static_cast<unsigned long long>(
                     session.process->image().entry_point - base));

    // The breakpoints the command line named, before the guest runs --
    // the usual way in, because a first stop is the point of the session.
    for (const std::uint64_t rva : initial_breaks) {
        if (!runtime::guestdbg::set_breakpoint(base + rva)) {
            std::fprintf(stderr,
                         "occ dbg: cannot arm a breakpoint at rva "
                         "0x%llx\n",
                         static_cast<unsigned long long>(rva));
        }
    }

    // The command source: a script, or the terminal. A script is the
    // session a person can keep -- the same commands, replayed against a
    // fixed image, answer the same questions.
    std::FILE* input = stdin;
    if (script_path != nullptr) {
        input = std::fopen(script_path, "r");
        if (input == nullptr) {
            std::fprintf(stderr, "occ dbg: cannot read the script %s\n",
                         script_path);
            return 2;
        }
    }

    char line[512];
    bool guest_ended = false;
    while (!guest_ended) {
        if (script_path == nullptr) {
            std::fprintf(stdout, "occ dbg> ");
            std::fflush(stdout);
        }
        if (std::fgets(line, sizeof(line), input) == nullptr) {
            break;
        }
        // Comments and blanks are the script's punctuation, not commands.
        char* text = line;
        while (*text == ' ' || *text == '\t') {
            ++text;
        }
        if (*text == '#' || *text == '\n' || *text == '\0') {
            continue;
        }
        char cmd[32] = {};
        unsigned long long a = 0;
        unsigned long long b = 0;
        const int fields = std::sscanf(text, "%31s %llx %llx", cmd,
                                       &a, &b);
        if (fields <= 0) {
            continue;
        }

        if (std::strcmp(cmd, "quit") == 0 || std::strcmp(cmd, "q") == 0) {
            break;
        }
        if (std::strcmp(cmd, "break") == 0 || std::strcmp(cmd, "b") == 0) {
            if (fields < 2) {
                std::fprintf(stdout, "break: needs an rva\n");
            } else if (runtime::guestdbg::set_breakpoint(base + a)) {
                std::fprintf(stdout, "breakpoint at 0x%llx\n",
                             static_cast<unsigned long long>(base + a));
            } else {
                std::fprintf(stdout, "breakpoint at rva 0x%llx: the "
                                     "bytes are not readable\n",
                             static_cast<unsigned long long>(a));
            }
            continue;
        }
        if (std::strcmp(cmd, "delete") == 0 ||
            std::strcmp(cmd, "del") == 0) {
            if (fields < 2) {
                std::fprintf(stdout, "delete: needs an rva\n");
            } else {
                static_cast<void>(runtime::guestdbg::clear_breakpoint(base + a));
            }
            continue;
        }
        if (std::strcmp(cmd, "breaks") == 0) {
            const std::size_t count = runtime::guestdbg::breakpoint_count();
            for (std::size_t i = 0; i < count; ++i) {
                const auto info = runtime::guestdbg::breakpoint_at(i);
                std::fprintf(stdout, "  0x%llx (replaced 0x%02x)\n",
                             static_cast<unsigned long long>(info.address),
                             info.displaced);
            }
            if (count == 0) {
                std::fprintf(stdout, "  (none)\n");
            }
            continue;
        }
        if (std::strcmp(cmd, "run") == 0 || std::strcmp(cmd, "r") == 0 ||
            std::strcmp(cmd, "continue") == 0 ||
            std::strcmp(cmd, "c") == 0) {
            if (!g_guest_started.load()) {
                if (!start_guest(session.process.get())) {
                    std::fprintf(stderr, "occ dbg: the guest thread could "
                                         "not start\n");
                    return 2;
                }
            } else if (runtime::guestdbg::guest_stopped()) {
                runtime::guestdbg::release(false);
            } else {
                std::fprintf(stdout, "the guest is already running\n");
                continue;
            }
            guest_ended = !report_event();
            continue;
        }
        if (std::strcmp(cmd, "step") == 0 || std::strcmp(cmd, "s") == 0) {
            if (!runtime::guestdbg::guest_stopped()) {
                std::fprintf(stdout,
                             "step: the guest is not stopped\n");
                continue;
            }
            runtime::guestdbg::release(true);
            guest_ended = !report_event();
            continue;
        }
        if (std::strcmp(cmd, "regs") == 0) {
            if (!runtime::guestdbg::guest_stopped()) {
                std::fprintf(stdout, "regs: the guest is not stopped\n");
                continue;
            }
            const auto& stop = runtime::guestdbg::current_stop();
            for (const RegName& reg : kRegNames) {
                // The rip a stop names is the breakpoint's address, one
                // below the rip the kernel saved; the stop's own field is
                // the answer, and the raw slot would print the byte after
                // the trap as if the guest were executing there.
                const std::uint64_t value =
                    reg.index == REG_RIP ? stop.rip : stop.regs[reg.index];
                std::fprintf(stdout, "  %-4s 0x%016llx%s", reg.name,
                             static_cast<unsigned long long>(value),
                             (reg.index == REG_RSP || reg.index == REG_RDI)
                                 ? "\n"
                                 : "   ");
            }
            std::fprintf(stdout, "\n");
            continue;
        }
        if (std::strcmp(cmd, "x") == 0) {
            if (fields < 2) {
                std::fprintf(stdout, "x: needs an rva (and a length)\n");
                continue;
            }
            const std::uint64_t length = fields >= 3 ? b : 64;
            std::uint8_t buffer[512];
            const std::uint64_t address = base + a;
            const std::size_t got = runtime::guestdbg::read_memory(
                address, buffer,
                length < sizeof(buffer) ? static_cast<std::size_t>(length)
                                        : sizeof(buffer));
            if (got == 0) {
                std::fprintf(stdout, "x: 0x%llx is not readable\n",
                             static_cast<unsigned long long>(address));
            } else {
                hexdump(address, buffer, got);
            }
            continue;
        }
        if (std::strcmp(cmd, "mdmp") == 0) {
            if (!runtime::guestdbg::guest_stopped()) {
                std::fprintf(stdout, "mdmp: the guest is not stopped\n");
                continue;
            }
            if (fields < 2) {
                std::fprintf(stdout, "mdmp: needs a path\n");
                continue;
            }
            const auto& stop = runtime::guestdbg::current_stop();
            runtime::minidump::Context ctx{};
            for (int i = 0; i < NGREG; ++i) {
                ctx.regs[i] = stop.regs[i];
            }
            ctx.regs[REG_RIP] = stop.rip;
            ctx.valid = true;
            const std::string p(text + std::strlen(cmd) + 1);
            static_cast<void>(runtime::minidump::write(
                p, base, session.process->image().module.size, ctx,
                0x80000003, stop.rip, image_path.c_str()));
            continue;
        }
        if (std::strcmp(cmd, "disas") == 0) {
            if (fields < 2) {
                std::fprintf(stdout,
                             "disas: needs an rva (and a count)\n");
                continue;
            }
            const std::uint64_t count = fields >= 3 ? b : 8;
            std::uint8_t buffer[256];
            const std::uint64_t address = base + a;
            const std::size_t got = runtime::guestdbg::read_memory(
                address, buffer, sizeof(buffer));
            if (got < 16) {
                std::fprintf(stdout, "disas: 0x%llx is not readable\n",
                             static_cast<unsigned long long>(address));
                continue;
            }
            std::fputs(occ::inspect::x64_disassemble_json(
                           occ::ByteSpan{buffer, got}, address,
                           static_cast<std::uint32_t>(count))
                           .c_str(),
                       stdout);
            continue;
        }
        std::fprintf(stdout,
                     "unknown command: %s (break, delete, breaks, "
                     "run, continue, step, regs, x, disas, quit)\n",
                     cmd);
    }

    if (script_path != nullptr) {
        std::fclose(input);
    }
    // A guest still running is a thread the process exit will collect; a
    // guest parked in its handler is likewise. The session ends here
    // either way, and the exit code is the guest's when there is one.
    return g_guest_finished.load(std::memory_order_seq_cst)
               ? (g_guest_outcome.exited
                      ? g_guest_outcome.exit_code & 0xFF
                      : 133)
               : 0;
}

// ------------------------------------------------- the 32-bit interpreter

namespace {

// The interpreter's host seam, first mile: the calls a CRT-less 32-bit
// image makes. ExitProcess is the run's exit; the console family goes
// through the same host implementations the 64-bit guest reaches, with
// the 32-bit stack's words widened into the host convention. Everything
// else is named as unhosted -- which is the interpreter's way of growing:
// each refusal names the call, and the next oracle needs it.
bool i386_host_call(void* state, const char* dll, const char* name,
                    runtime::i386::Machine& m,
                    runtime::i386::Memory& mem) noexcept {
    (void)state;
    const std::uint32_t esp = m.regs[runtime::i386::Machine::kEsp];
    const std::uint32_t arg1 = mem.read32(esp + 4);
    const std::uint32_t arg2 = mem.read32(esp + 8);
    if (std::strcmp(dll, "KERNEL32.dll") == 0 &&
        std::strcmp(name, "ExitProcess") == 0) {
        m.exit_code = arg1;
        m.halted = true;
        return true;
    }
    if (std::strcmp(dll, "KERNEL32.dll") == 0 &&
        std::strcmp(name, "GetStdHandle") == 0) {
        m.esp_adjust = 4;  // stdcall: the one argument
        // The handles the runtime's console answers: output first, error
        // second, input third -- the Windows numbers.
        m.regs[runtime::i386::Machine::kEax] =
            arg1 == 0xFFFFFFF5u ? 0x1001
                                : (arg1 == 0xFFFFFFF6u ? 0x1000 : 0x1002);
        m.esp_adjust = 4;
        return true;
    }
    if (std::strcmp(dll, "KERNEL32.dll") == 0 &&
        std::strcmp(name, "WriteFile") == 0) {
        // (handle, buffer, bytes, *written, overlapped) -- the bytes go to
        // stdout raw, whatever they encode; the written count is stored.
        std::uint32_t len = mem.read32(m.regs[runtime::i386::Machine::kEsp] + 12);
        std::uint32_t buf = arg2;
        while (len != 0) {
            const std::uint8_t ch = mem.read8(buf++);
            std::fputc(ch, stdout);
            --len;
        }
        const std::uint32_t written_at = mem.read32(m.regs[runtime::i386::Machine::kEsp] + 16);
        if (written_at != 0) {
            mem.write32(written_at, mem.read32(m.regs[runtime::i386::Machine::kEsp] + 12));
        }
        m.regs[runtime::i386::Machine::kEax] = 1;
        m.esp_adjust = 20;  // stdcall: five arguments
        return true;
    }
    return false;
}

bool i386_resolve(void*, const char*, const char*) noexcept {
    // Every import is servable as a magic: the host seam answers or the
    // run says which call it could not.
    return true;
}

}  // namespace

[[nodiscard]] int run_pe_32(const char* image_path) noexcept {
    auto bytes = fs::read_file_bytes(image_path);
    if (!bytes || bytes->empty()) {
        std::fprintf(stderr, "occ run32: the image could not be read\n");
        return 2;
    }
    runtime::i386::Machine machine;
    std::string fault;
    const bool done = runtime::i386::run(
        bytes->data(), bytes->size(), image_path, &i386_resolve, nullptr,
        &i386_host_call, nullptr, machine, 50000000, &fault);
    if (!done) {
        std::fprintf(stderr, "occ run32: the interpreter stopped: %s\n",
                     fault.c_str());
        std::fflush(nullptr);
        return 2;
    }
    std::fflush(nullptr);
    return static_cast<int>(machine.exit_code & 0xFFu);
}

}  // namespace occ::runner

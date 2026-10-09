#include "occ/runner/pe_runner.h"

#include "occ/parser/pe.h"
#include "occ/runtime/exports.h"
#include "occ/runtime/iat_rebuild.h"
#include "occ/runtime/image_dump.h"
#include "occ/runtime/pe_process.h"
#include "occ/runtime/winabi.h"
#include "occ/util/fs.h"

#include <cstdio>
#include <cstdlib>
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

    // --- the image --------------------------------------------------------

    auto bytes = fs::read_file_bytes(image_path);
    if (!bytes || bytes->empty()) {
        return runner_failure("the image could not be read", image_path);
    }
    const ByteSpan span{bytes->data(), bytes->size()};

    const parser::PeImage image = parser::PeImage::parse(span);
    if (!image.ok()) {
        return runner_failure("the image is not a PE this runtime can load",
                              std::string(parser::pe_error_name(image.error())) +
                                  ": " + image.error_detail());
    }

    // --- the API the guest imports ----------------------------------------

    // The registry answers from the host implementations in `runtime/winabi`:
    // every KERNEL32 and msvcrt export the import table names is a host
    // function reached through a function call, which is the whole of the
    // difference between this and a loader that resolves imports into a
    // second copy of the API. There is no image side to these modules -- the
    // registry's own rule is that the host table is preferred over whatever
    // the file's export directory names, and there is no file export
    // directory to prefer it over.
    runtime::ExportRegistry registry;
    runtime::winabi::register_host_modules(registry);

    // --- the process -------------------------------------------------------

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
    // The environment the container handed this process, unchanged: the
    // caller's `--env` entries, the runner's defaults, and nothing the
    // runner invents. A Windows program reads its environment through the
    // PEB, and the PEB is built from these strings.
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
    options.resolver_state = &registry;
    options.resolve = &resolve_thunk;

    runtime::ProcessImage failure;
    std::unique_ptr<runtime::PeProcess> process =
        runtime::PeProcess::build(image, span, options, &failure);
    if (process == nullptr || !process->ok()) {
        return runner_failure(
            "the image could not be built into a process",
            failure.detail.empty() ? std::string(runtime::process_error_name(
                                         failure.error))
                                   : failure.detail);
    }

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

} // namespace occ::runner

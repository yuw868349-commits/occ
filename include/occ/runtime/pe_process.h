#pragma once

// A Windows process built by this runtime, rather than by a kernel.
//
// This is the difference between `occ` as a launcher for somebody else's
// Windows implementation and `occ` as the implementation. Everything below
// this header -- the address space, the ledger, the loader, the mapper --
// already existed and was already tested; what did not exist was anything
// that put a PE into that machinery and started it. `occ run` found Wine,
// built a prefix, and handed the file over, so the runtime described above
// was reachable from `occ check` and from the test suite and from nowhere
// else. The set of behaviours this project knows to be more correct than
// Wine's was, in the crudest sense, unused.
//
// So this type is the join. It owns the pieces a Windows process is made
// of -- an address space, an image mapped into it, a stack, a TEB, a PEB --
// and it produces the one thing the runner needs back: a thread that is
// standing at the image's entry point with a stack under it.
//
// What it deliberately does not own is the Windows API. A program calls
// `WriteFile` because mingw's import table has an entry for it, and that
// entry has to name an address in this process. Resolving those addresses
// is the next layer up (`occ::runtime::exports` plus the `nt_*` family), and
// the seam between the two is `LoadContext::resolve`: this header asks the
// question "where is kernel32!WriteFile" and somebody else answers.
//
// The name is `PeProcess` and not `Process` because the ELF path in
// `runner/run.cpp` is a real process on a real kernel, and calling this one
// a process would invite a reader to assume the kernel is involved. It is
// not. There is no fork, no execve, and no kernel state; there is a stack
// this file allocated and a jump this file performs.

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "occ/parser/pe.h"
#include "occ/runtime/address_space.h"
#include "occ/runtime/loader.h"
#include "occ/runtime/mapper.h"

namespace occ::runtime {

// How the process is laid out, in the terms a caller decides.
//
// Every field has a default that is right for a console program started
// with no arguments, because that is the overwhelming majority of what a
// CLI tool runs and a caller that has to fill in five fields to start
// `hello.exe` will fill in the wrong ones.
struct ProcessOptions {
    // The command line as Windows sees it: one string, already joined, with
    // the program name first.
    //
    // Not a vector, and that is the point. Windows does not give a program
    // an argv; it gives it a command line, and the program splits it with
    // `CommandLineToArgvW` if it wants one. mingw's `main` does exactly
    // that, which is why `args.exe` above prints the arguments it was
    // handed. A runtime that carried a vector here and re-joined it on the
    // way in would be answering a question the program is about to ask --
    // and answering it differently, because the split and the join are not
    // inverses. `occ` passes the line through untouched and lets the
    // program do what a program on Windows does.
    std::string command_line;

    // The image path as Windows sees it, in NT form (`\??\...`) or the DOS
    // form the caller used. It goes into the PEB's `ImagePathName` and is
    // what a program that re-executes itself reads back.
    std::string image_path;

    // The program's environment, already `KEY=VALUE` and already sorted the
    // way Windows sorts it. Empty means "inherit nothing", which is a
    // legitimate choice for a container run and deliberately not spelled as
    // a null pointer.
    std::vector<std::string> environment;

    // The stack, in bytes, reserved and then committed in full.
    //
    // Windows reserves a growable stack and commits it on demand against a
    // guard page; a runtime that commits the whole thing up front is not
    // wrong, it is merely spending address space the program may never
    // touch. One megabyte is the default for the same reason it is
    // Windows': it is the size the linker records when a program does not
    // say, and a program that recurses deeply expects at least that.
    std::uint64_t stack_reserve = 1024 * 1024;
    std::uint64_t stack_commit = 4 * 1024;

    // A directory to resolve the image's own name against, for a program
    // that asks for its current directory during startup. Empty means the
    // host's current directory, which is what a caller who did not think
    // about it wants.
    std::string current_directory;

    // The process's heaps, as the PEB's heap list carries them.
    //
    // Handles rather than addresses, in the order a program enumerating
    // them sees. Supplied rather than discovered because a handle belongs to
    // the layer that implements the heap functions, and this type does not;
    // empty leaves the PEB's field null, which a program reads as "this
    // process has no heaps" rather than as "the list is empty".
    std::vector<std::uint64_t> process_heaps;

    // The events to write to, or nullptr. The same writer the loader takes,
    // for the reason the loader takes one: a run that cannot be observed is
    // a run whose failures are reported as a fault address and nothing else.
    obs::Writer* events = nullptr;

    // Where imports resolve to, and the state their resolver needs.
    //
    // Copied from `LoadContext` rather than a `LoadContext` itself because
    // this is the part of a load this type owns: the loader's other knobs
    // (a base chooser, a TLS table) are decisions about the *image*, and
    // this type makes them rather than passing them through.
    void* resolver_state = nullptr;
    std::uint64_t (*resolve)(void* state, const std::string& dll,
                             const std::string& name, std::uint16_t ordinal,
                             bool by_ordinal) noexcept = nullptr;
};

// Why a process could not be built.
//
// Enumerated rather than a status code because these are all different
// problems with different fixes, and a caller that reports one of them as
// "the process failed to start" has thrown away the only useful part.
enum class ProcessError : std::uint8_t {
    None,
    // The file could not be read, or is not a PE, or the loader refused it.
    // The loader's own detail is carried in `detail` rather than
    // re-expressed here: it knows more about why than this enum can.
    ImageRejected,
    // The image is for a machine this runtime does not execute.
    UnsupportedMachine,
    // The image is a DLL. A DLL is loaded into something; it is not started.
    NotAnExecutable,
    // The image is for the subsystem this runtime does not have. A GUI
    // program that never creates a window still runs, so this is checked
    // lazily -- see the comment on `subsystem` handling in the source.
    UnsupportedSubsystem,
    // A stack, a TEB or the image could not be placed. The address space was
    // too full for what was asked.
    OutOfAddressSpace,
    // A `mprotect` or a mapping the plan covered was refused by the kernel.
    // Distinct from the one above because the address space had room and the
    // kernel said no anyway, which is a host limitation rather than a full
    // space.
    HostRefused,
};

[[nodiscard]] const char* process_error_name(ProcessError e) noexcept;

// What was built, and what it cost.
struct ProcessImage {
    bool ok = false;
    ProcessError error = ProcessError::None;
    std::string detail;

    // The image, mapped and relocated and with its IAT written.
    LoadedModule module{};

    // Every region the process owns, in the order they were placed. Reported
    // because a caller that wants to describe the process -- `occ run`
    // writing an event, a debugger listing the address space -- needs the
    // whole list and not a summary of it.
    struct RegionRecord {
        std::uint64_t base = 0;
        std::uint64_t size = 0;
        RegionKind kind = RegionKind::Private;
        PageProtection protection = PageProtection::NoAccess;
        std::string what;
    };
    std::vector<RegionRecord> regions;

    // Where the entry point ended up, and the value the thread's stack
    // pointer must hold when the jump happens. Both are absolute and both
    // are what the assembler stub below consumes.
    std::uint64_t entry_point = 0;
    std::uint64_t initial_stack_pointer = 0;

    // The image's own exports, at absolute addresses. `GetProcAddress` on
    // the image's module answers from here, and the run hands the table to
    // the guest state. An image that exports nothing leaves it empty.
    struct ExportRecord {
        std::string name;
        std::uint32_t ordinal = 0;
        std::uint64_t address = 0;
        bool is_forwarder = false;
        std::uint64_t forwarder_text = 0;
    };
    std::vector<ExportRecord> own_exports;

    // The exception directory, mapped. A raise inside the guest walks this
    // table to find each frame's unwind information; an image with no
    // exception directory leaves both zero, which the walk reads as "no
    // frame has unwind information" -- the leaf-function rule.
    std::uint64_t pdata_va = 0;
    std::uint64_t pdata_bytes = 0;

    // The unwind data the exception directory's rows point into. The rows
    // are guest bytes, so an `unwind_rva` in one of them is a number the
    // guest chose; the walk bounds every read of a header and of the code
    // slots that follow it by this range, because a row pointing outside
    // the section is a crafted image rather than an unwind this runtime
    // should follow off the end of a mapping.
    std::uint64_t xdata_va = 0;
    std::uint64_t xdata_bytes = 0;

    // The TEB and the PEB, as addresses in this space.
    std::uint64_t teb = 0;
    std::uint64_t peb = 0;
};

// A built process, owned.
//
// The address space is held by value and the mapper points at it, which is
// why this type is not copyable and is not movable: a moved `PeProcess`
// would leave a mapper pointing at the old location's address space, and the
// bug that produces is a mapper writing into a destroyed ledger with no
// diagnostic until the memory is reused. That is the kind of mistake a type
// should make impossible rather than document, so the move operations are
// deleted.
//
// The cost of deleting them is that a factory cannot return one by value,
// and the builder has to return a pointer instead. That is the honest
// shape: the type's identity is tied to the address of its own address
// space, which is a property of where it lives, and a pointer is how a C++
// type says "this thing has a location".
class PeProcess {
public:
    PeProcess(const PeProcess&) = delete;
    PeProcess& operator=(const PeProcess&) = delete;
    PeProcess(PeProcess&&) = delete;
    PeProcess& operator=(PeProcess&&) = delete;

    // Build a process from a parsed image.
    //
    // The bytes are taken as a span rather than as a path because the caller
    // may have got them from anywhere -- a file, a pipe, an embedded
    // resource -- and a builder that opened a file would be a builder a
    // caller with bytes in hand cannot use.
    //
    // A null result is a build that failed, and the reason is in `image()`
    // on the record -- except that a null pointer has no `image()`, so the
    // failure record is returned through `failure` instead. One out-parameter
    // is the price of the deleion above and it is paid once, here, rather
    // than by every caller.
    [[nodiscard]] static std::unique_ptr<PeProcess> build(
        const parser::PeImage& image, ByteSpan bytes,
        const ProcessOptions& options, ProcessImage* failure) noexcept;

    [[nodiscard]] bool ok() const noexcept { return image_.ok; }
    [[nodiscard]] const ProcessImage& image() const noexcept { return image_; }
    [[nodiscard]] AddressSpace& space() noexcept { return space_; }
    [[nodiscard]] const AddressSpace& space() const noexcept { return space_; }
    [[nodiscard]] Mapper& mapper() noexcept { return mapper_; }

    // The options the process was built from, read-only. `run_pe_process`
    // reads the command line and the environment out of here because the
    // thunks answer `__getmainargs` and `GetCommandLineA` from the same text
    // the PEB holds: one source, three views, no chance to disagree. It is
    // const for the same reason the run reads anything mid-flight -- the
    // guest is living on these strings, and a caller rewriting them during
    // the run would be rewriting the guest's world under its feet.
    [[nodiscard]] const ProcessOptions& options() const noexcept {
        return options_;
    }

private:
    PeProcess() noexcept = default;

    AddressSpace space_;
    Mapper mapper_{space_};
    ProcessImage image_{};
    ProcessOptions options_{};
};

// Start the built process and run it to completion.
//
// This is the only part of the design that has to be assembly, and the
// assembly is eight instructions: load the TEB into the thread's segment
// base, set the stack pointer, align it, and the jump. The alignment is not
// optional -- Windows' ABI requires 16-byte alignment at the call, and a
// stack that arrives 8 bytes off makes every SSE spill in the target a
// misaligned access, which is an exception rather than a warning.
//
// Returns the program's exit code. A program that faults is reported
// through `outcome` rather than by a C++ exception, because this project is
// built `-fno-exceptions` and that is not a limitation to route around.
struct RunOutcome {
    // True when the program reached `ExitProcess`. False when it faulted,
    // and `fault_address` and `signal` then say where.
    bool exited = false;
    std::uint32_t exit_code = 0;
    std::uint64_t fault_address = 0;
    int signal = 0;
    std::string detail;
};

[[nodiscard]] RunOutcome run_pe_process(PeProcess& process) noexcept;

} // namespace occ::runtime

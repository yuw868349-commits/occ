#pragma once

// The host side of the Win32 and MSVCRT imports a guest reaches for.
//
// The loader resolves an import by asking a registry, and the registry can
// answer from two kinds of module: an image it has mapped, whose exports are
// addresses inside that image, and a module that is *implemented* rather
// than loaded -- whose exports are addresses in the host's own address
// space. This file is the second kind. Wine's equivalent is the whole of its
// `dlls/kernel32` and `dlls/msvcrt`; the difference is that those run the
// guest's calls through a thunks-and-wineserver boundary, and this runs them
// through a function call, because the guest and the implementation share
// one address space and one libc.
//
// **How a guest call reaches a host function.** The guest is Microsoft x64
// ABI; the host is System V. A thunk carrying `__attribute__((ms_abi))` is
// compiled to be *called* by the guest's convention and to *call* the host's
// -- the compiler emits the register shuffles, the shadow space and the
// variadic register saves, and there is no hand-written assembly anywhere in
// this layer. The same mechanism answers the data imports: `_fmode` and
// friends are addresses of variables, and a variable has no calling
// convention to translate.
//
// **The stdio objects are the host's own.** A guest that prints calls
// `vfprintf` with a `FILE*` it obtained from `__iob_func`, and the `FILE*`
// that answers must be one the host's `vfprintf` accepts. It is: the iob
// table this file hands out holds the host's `stdin`, `stdout` and `stderr`
// behind a translation window small enough to be recognised, so the guest's
// stream objects and the host's are the same objects. Buffering, exit-time
// flush and everything else `stdio` does is therefore the host libc's own
// behaviour, and a program that prints does exactly what it would print
// through that libc directly.
//
// **The one place the two ABIs cannot be bridged by a declaration is the
// variadic forward.** `vfprintf` receives a `va_list`, which is a pointer
// into the *caller's* argument save area under the Microsoft convention and
// a 24-byte descriptor under the System V one. The bridge is format-driven:
// the format string says what each argument is, each argument is read out of
// the guest's save area, and a System V descriptor is built around them so
// the host's own `vfprintf` consumes the call unchanged. `host_vfprintf` is
// that bridge, and its correctness is tested per conversion rather than
// trusted.

#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include "occ/runtime/exports.h"

namespace occ::runtime {

class AddressSpace;
class Mapper;

namespace winabi {

// --------------------------------------------------------------------------
// The guest execution state
// --------------------------------------------------------------------------

// Everything a host-implemented export needs to know about the guest it is
// serving.
//
// One per running guest, installed before `enter_guest` jumps into the image
// and read by every thunk through `guest_state()`. The process runs the
// guest on one thread -- the design has one TEB, one stack and one entry --
// so a thread-local pointer is the whole of the dispatch and there is no
// handle-passing ceremony in any thunk signature.
struct GuestState {
    // The address space the guest lives in. `VirtualProtect` and
    // `VirtualQuery` answer from the same ledger the loader used, which is
    // what makes a protect the guest performed visible to a query it does
    // afterwards.
    AddressSpace* space = nullptr;
    Mapper* mapper = nullptr;

    // The guest's control blocks. Thunks that simulate TEB state -- the last
    // error at 0x68, the TLS slots at 0x1480 -- read and write through these
    // rather than through the segment base, because the host's own code runs
    // with the kernel's GS base and must not reach for the guest's.
    std::uint64_t teb = 0;
    std::uint64_t peb = 0;
    std::uint64_t image_base = 0;

    // The command line and what it parses to. Built once, before the guest
    // starts, so that `GetCommandLineA`, `GetCommandLineW` and
    // `__getmainargs` all answer from the same text: three views of one
    // string rather than three parses that could disagree.
    std::string command_line;
    // The same line as UTF-16, which is what `GetCommandLineW` returns and
    // what the PEB's `CommandLine` buffer holds.
    std::u16string command_line_u16;
    // The image's DOS path, which `GetModuleFileName` answers with. Kept as
    // its own string rather than re-derived from the command line, because
    // the first argument of a command line is not always the image path --
    // a caller can hand a guest a line whose first token is a launcher.
    std::string image_path_dos;
    std::vector<std::string> arguments;

    // The C form of the arguments, pointing into `arguments`, and the
    // environment as a null-terminated table pointing into storage that
    // lives as long as the state does.
    std::vector<const char*> argv_table;
    std::vector<const char*> env_table;

    // The iob table: three `FILE` slots the guest indexes the way MSVCRT
    // indexes `_iob`. Each holds the host's own stream object, so the
    // guest's `stdout` and the host's are one object; `iob_base` is how a
    // stream pointer the guest passes is recognised as a table position.
    std::FILE* iob[3] = {nullptr, nullptr, nullptr};
    std::uint64_t iob_base = 0;

    // The `_onexit` and `atexit` registrations, in registration order. The
    // table is walked in reverse when the guest exits, which is the order
    // Windows gives them, and lives here so that a second guest in the same
    // process starts with an empty list rather than the last one's.
    std::vector<std::uint64_t> onexit_list;
    std::vector<std::uint64_t> atexit_list;

    // The `__setusermatherr` callback, recorded because a program that asks
    // to be told about a math error has asked for an observable thing, even
    // though no current guest path reaches it.
    std::uint64_t matherr = 0;

    // The guest's `SetUnhandledExceptionFilter` callback, or zero. The fault
    // handler reads this before deciding that a fault is unhandled.
    std::uint64_t unhandled_filter = 0;

    // What killed the guest, when something did. Filled by the fault
    // handler, read by the code that reports the run.
    bool faulted = false;
    int fault_signal = 0;
    std::uint64_t fault_address = 0;

    // What `__set_app_type` was told, recorded because the value is observable
    // state on Windows and a runtime that drops it drops a fact.
    std::uint32_t app_type = 0;
};

// The state the thunks serve, or nullptr before the guest has been installed.
[[nodiscard]] GuestState* guest_state() noexcept;

// Installs, or clears with nullptr. Not idempotent by design: a caller that
// installs over an existing state has a lifecycle bug, and the non-idempotent
// form is the one a debug build can assert about.
void set_guest_state(GuestState* state) noexcept;

// The exit path the process layer provides. A guest that calls `ExitProcess`,
// `exit` or `abort`, or whose fault the exception filter declined, ends by
// leaving through this -- the jump that returns to `run_pe_process`. Before
// it is installed the only exit available is the process's own.
using TerminateFn = void(std::uint32_t code) noexcept;
void install_terminate_path(TerminateFn* fn) noexcept;

// --------------------------------------------------------------------------
// Module registration
// --------------------------------------------------------------------------

// Registers the modules a guest imports and this runtime implements:
// `KERNEL32.dll` and `msvcrt.dll`, under the spellings the import tables use.
//
// The registry is the caller's and outlives the run. Re-registering replaces,
// which is `ExportRegistry::add`'s own rule and is what a second call with a
// grown table should do.
void register_host_modules(ExportRegistry& registry);

// --------------------------------------------------------------------------
// Command line and path forms
// --------------------------------------------------------------------------

// The DOS path a guest sees for a Unix path: a `Z:` drive, because the drive
// is where Wine puts the host's `/`, and backslash separators, because those
// are what a Windows path is spelled with. `/root/x/args.exe` becomes
// `Z:\root\x\args.exe`. A path that is already DOS-shaped -- one that does
// not start with `/` -- is returned unchanged, because guessing twice about
// one string is how a path grows a second drive letter.
[[nodiscard]] std::string to_dos_path(std::string_view unix_path);

// Builds the command line a guest would have received: the program path
// first, then the arguments, each quoted when and only when the Microsoft
// rules require it. `split_command_line` of this output returns the input,
// which is the round trip that makes the two functions testable against
// each other rather than against a hope.
[[nodiscard]] std::string build_command_line(
    const std::string& program, const std::vector<std::string>& args);

// Splits a command line by the Microsoft rules: whitespace separates unless
// inside quotes; `2n` backslashes followed by a quote are `n` backslashes and
// a quote toggle; `2n+1` are `n` backslashes and a literal quote; a run of
// backslashes not followed by a quote is itself. This is the rule
// `CommandLineToArgvW` implements and the one `__getmainargs` must match,
// because a program that prints its `argv` is printing this parse.
[[nodiscard]] std::vector<std::string> split_command_line(
    std::string_view command_line);

// --------------------------------------------------------------------------
// Text conversion
// --------------------------------------------------------------------------

// UTF-8 to UTF-16 and back. Both are total over the encoding: a malformed
// input reports failure rather than silently producing a replacement
// character, because a runtime that rewrites a program's strings has
// rewritten the program's data. Surrogate pairs are handled in both
// directions, and a lone surrogate is the malformed case it is in UTF-8.
[[nodiscard]] bool utf8_to_utf16(std::string_view text,
                                 std::u16string& out) noexcept;
[[nodiscard]] bool utf16_to_utf8(std::u16string_view text,
                                 std::string& out) noexcept;

// --------------------------------------------------------------------------
// The stdio bridge
// --------------------------------------------------------------------------

// Prints through the host's `vfprintf`, taking the arguments from the guest's
// save area.
//
// `ms_slots` points at the first variadic argument of the guest call, one
// 8-byte slot per argument: an `int` argument occupies the low half of its
// slot, a pointer or `long long` the whole slot, a `double` the bit pattern
// of its value. The format is parsed to learn what each slot holds, the
// `*` widths and precisions are folded into the text, and a System V
// descriptor is assembled so the host's `vfprintf` runs unmodified.
//
// Returns what `vfprintf` returns, and -1 for a format this bridge does not
// fully understand: guessing a conversion's type is how a slot cursor goes
// wrong and every argument after it lands in the wrong parameter.
int host_vfprintf(std::FILE* stream, const char* fmt,
                  const void* ms_slots) noexcept;

// Maps a stream pointer the guest passes -- an address inside the iob table
// this state hands out -- to the host `FILE*` it means. Anything outside the
// table is already a host pointer and goes through unchanged.
[[nodiscard]] std::FILE* translate_stream(const GuestState& state,
                                          std::uint64_t stream) noexcept;

// --------------------------------------------------------------------------
// The heap
// --------------------------------------------------------------------------

// `HeapAlloc` and friends.
//
// Every block carries a 16-byte header recording the size the guest asked
// for, because `HeapSize` answers with the *requested* size on Windows and
// the host's `malloc_usable_size` answers with something larger. A runtime
// that forwards `HeapSize` to the usable size reports a size the guest never
// asked for, and a program that allocates 100 bytes and prints the size
// prints 112 or 104 depending on the allocator's rounding -- which is
// exactly the failure that makes a heap test lie.
void* heap_alloc(std::uint32_t flags, std::uint64_t bytes) noexcept;
void* heap_realloc(std::uint32_t flags, void* block,
                   std::uint64_t bytes) noexcept;
[[nodiscard]] std::uint64_t heap_size(const void* block) noexcept;
bool heap_free(void* block) noexcept;

}  // namespace winabi

}  // namespace occ::runtime

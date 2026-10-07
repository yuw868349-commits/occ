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
#include <cstdlib>
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

// The format without the stream: the same rebuild and descriptor assembly
// `host_vfprintf` runs, delivered into `text` with no text-mode expansion,
// which is what the buffer spellings -- `sprintf` and friends -- answer
// through, because a buffer has no mode and a newline in one stays a
// newline. Returns what `vfprintf` returns, and -1 for a format this
// bridge does not translate.
int host_vformat(std::string& text, const char* fmt,
                 const void* ms_slots) noexcept;

// Maps a stream pointer the guest passes -- an address inside the iob table
// this state hands out -- to the host `FILE*` it means. Anything outside the
// table is already a host pointer and goes through unchanged.
[[nodiscard]] std::FILE* translate_stream(const GuestState& state,
                                          std::uint64_t stream) noexcept;

// --------------------------------------------------------------------------
// The CRT's computational face
// --------------------------------------------------------------------------
//
// The string, conversion, sorting and random functions the guest calls by
// name. These are the thunks themselves: Microsoft ABI entry points, the
// same addresses the registry hands a guest's import. A host caller --
// a test, or a tool that trusts the same answers the guest gets -- reaches
// them directly, and the compiler bridges the convention on the way in,
// which is exactly what a guest's `call [iat]` does.

// The comparison a sort or search calls back with is guest code: a
// Microsoft ABI function pointer, which the host's own qsort cannot
// spell. The sort walks through a bridge; the search calls it directly.
using GuestCompare = std::int32_t (__attribute__((ms_abi))*)(
    const void*, const void*) noexcept;

// The quotient/remainder pairs the guest spells. The 8-byte pair rides
// one register under the Microsoft ABI, the 16-byte pair goes through a
// hidden pointer, and the compiler spells both on each side of a call.
struct LdivPair {
    std::int32_t quot;
    std::int32_t rem;
};
struct LldivPair {
    std::int64_t quot;
    std::int64_t rem;
};

extern "C" __attribute__((ms_abi)) char* cr_strcpy(char* target,
                                                   const char* source) noexcept;
extern "C" __attribute__((ms_abi)) char* cr_strncpy(
    char* target, const char* source, std::uint64_t n) noexcept;
extern "C" __attribute__((ms_abi)) char* cr_strcat(char* target,
                                                   const char* source) noexcept;
extern "C" __attribute__((ms_abi)) char* cr_strncat(
    char* target, const char* source, std::uint64_t n) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_strcmp(
    const char* a, const char* b) noexcept;
extern "C" __attribute__((ms_abi)) char* cr_strchr(const char* text,
                                                   std::int32_t c) noexcept;
extern "C" __attribute__((ms_abi)) char* cr_strrchr(const char* text,
                                                    std::int32_t c) noexcept;
extern "C" __attribute__((ms_abi)) char* cr_strstr(
    const char* haystack, const char* needle) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t cr_strspn(
    const char* text, const char* accept) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t cr_strcspn(
    const char* text, const char* reject) noexcept;
extern "C" __attribute__((ms_abi)) char* cr_strpbrk(
    const char* text, const char* accept) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t cr_strnlen(
    const char* text, std::uint64_t limit) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr__stricmp(
    const char* a, const char* b) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr__strnicmp(
    const char* a, const char* b, std::uint64_t n) noexcept;
extern "C" __attribute__((ms_abi)) char* cr__strupr(char* text) noexcept;
extern "C" __attribute__((ms_abi)) char* cr__strlwr(char* text) noexcept;
extern "C" __attribute__((ms_abi)) void* cr_memmove(void* target,
                                                    const void* source,
                                                    std::uint64_t bytes) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_memcmp(
    const void* a, const void* b, std::uint64_t bytes) noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t cr_atoi(
    const char* text) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_atol(
    const char* text) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t cr__atoi64(
    const char* text) noexcept;
extern "C" __attribute__((ms_abi)) double cr_atof(const char* text) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_strtol(
    const char* text, char** end, std::int32_t base) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t cr_strtoul(
    const char* text, char** end, std::int32_t base) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t cr_strtoll(
    const char* text, char** end, std::int32_t base) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t cr_strtoull(
    const char* text, char** end, std::int32_t base) noexcept;
extern "C" __attribute__((ms_abi)) double cr_strtod(const char* text,
                                                    char** end) noexcept;
extern "C" __attribute__((ms_abi)) char* cr_itoa(std::int32_t value,
                                                 char* buffer,
                                                 std::int32_t base) noexcept;
extern "C" __attribute__((ms_abi)) char* cr__itoa(std::int32_t value,
                                                  char* buffer,
                                                  std::int32_t base) noexcept;
extern "C" __attribute__((ms_abi)) char* cr_ltoa(std::int32_t value,
                                                 char* buffer,
                                                 std::int32_t base) noexcept;
extern "C" __attribute__((ms_abi)) char* cr__ltoa(std::int32_t value,
                                                  char* buffer,
                                                  std::int32_t base) noexcept;
extern "C" __attribute__((ms_abi)) char* cr_ultoa(std::uint32_t value,
                                                  char* buffer,
                                                  std::int32_t base) noexcept;
extern "C" __attribute__((ms_abi)) char* cr__ultoa(std::uint32_t value,
                                                   char* buffer,
                                                   std::int32_t base) noexcept;
extern "C" __attribute__((ms_abi)) char* cr__i64toa(std::int64_t value,
                                                    char* buffer,
                                                    std::int32_t base) noexcept;
extern "C" __attribute__((ms_abi)) char* cr__ui64toa(std::uint64_t value,
                                                     char* buffer,
                                                     std::int32_t base) noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t cr_isalpha(
    std::int32_t c) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_isalnum(
    std::int32_t c) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_isdigit(
    std::int32_t c) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_isxdigit(
    std::int32_t c) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_isspace(
    std::int32_t c) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_isupper(
    std::int32_t c) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_islower(
    std::int32_t c) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_ispunct(
    std::int32_t c) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_isprint(
    std::int32_t c) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_isgraph(
    std::int32_t c) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_iscntrl(
    std::int32_t c) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_tolower(
    std::int32_t c) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_toupper(
    std::int32_t c) noexcept;

extern "C" __attribute__((ms_abi)) void cr_qsort(
    void* base, std::uint64_t count, std::uint64_t size,
    GuestCompare compare) noexcept;
extern "C" __attribute__((ms_abi)) void* cr_bsearch(
    const void* key, const void* base, std::uint64_t count,
    std::uint64_t size, GuestCompare compare) noexcept;

extern "C" __attribute__((ms_abi)) void cr_srand(std::uint32_t seed) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_rand() noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t cr_abs(
    std::int32_t value) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t cr_labs(
    std::int64_t value) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t cr_llabs(
    std::int64_t value) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t cr__abs64(
    std::int64_t value) noexcept;
extern "C" __attribute__((ms_abi)) div_t cr_div(std::int32_t n,
                                                std::int32_t d) noexcept;
extern "C" __attribute__((ms_abi)) LdivPair cr_ldiv(std::int32_t n,
                                                    std::int32_t d) noexcept;
extern "C" __attribute__((ms_abi)) LldivPair cr_lldiv(
    std::int64_t n, std::int64_t d) noexcept;

extern "C" __attribute__((ms_abi)) char16_t* cr_wcscpy(
    char16_t* target, const char16_t* source) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* cr_wcsncpy(
    char16_t* target, const char16_t* source, std::uint64_t n) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* cr_wcscat(
    char16_t* target, const char16_t* source) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* cr_wcsncat(
    char16_t* target, const char16_t* source, std::uint64_t n) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_wcscmp(
    const char16_t* a, const char16_t* b) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_wcsncmp(
    const char16_t* a, const char16_t* b, std::uint64_t n) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* cr_wcschr(
    const char16_t* text, std::uint32_t c) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* cr_wcsrchr(
    const char16_t* text, std::uint32_t c) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* cr_wcsstr(
    const char16_t* haystack, const char16_t* needle) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* cr_wcsdup(
    const char16_t* text) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t cr_wcslen(
    const char16_t* text) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t cr_wcsnlen(
    const char16_t* text, std::uint64_t limit) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t cr_mbstowcs(
    char16_t* target, const char* source, std::uint64_t units) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t cr_wcstombs(
    char* target, const char16_t* source, std::uint64_t bytes) noexcept;

// The buffer spellings of printf: the same format the stream spellings
// run, with no text mode after it -- a buffer has no mode. The C99 and
// Microsoft snprintf spellings differ in the one place C99 improved on
// the contract: a text that fills its count leaves no terminator under
// `_snprintf`, and both answer with the whole text's length.
extern "C" __attribute__((ms_abi)) std::int32_t cr_vsprintf(
    char* buffer, const char* fmt, void* ms_slots) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_sprintf(
    char* buffer, const char* fmt, ...) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_vsnprintf(
    char* buffer, std::uint64_t count, const char* fmt,
    void* ms_slots) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_snprintf(
    char* buffer, std::uint64_t count, const char* fmt, ...) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr__vsnprintf(
    char* buffer, std::uint64_t count, const char* fmt,
    void* ms_slots) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr__snprintf(
    char* buffer, std::uint64_t count, const char* fmt, ...) noexcept;

// user32's simplified printf: integers and text, no floating point, and a
// wide spelling whose `%s` reads a UTF-16 string from the slot.
extern "C" __attribute__((ms_abi)) std::int32_t cr_wsprintfA(
    char* buffer, const char* fmt, ...) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_wsprintfW(
    char16_t* buffer, const char16_t* fmt, ...) noexcept;

// The file spellings: DOS paths in, host files underneath, and the text
// mode the Windows CRT reads and writes files through in both directions.
extern "C" __attribute__((ms_abi)) void* cr_fopen(
    const char* path, const char* mode) noexcept;
extern "C" __attribute__((ms_abi)) void* cr__wfopen(
    const char16_t* path, const char16_t* mode) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_fclose(
    void* stream) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t cr_fread(
    void* buffer, std::uint64_t size, std::uint64_t count,
    void* stream) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t cr_fwrite(
    const void* buffer, std::uint64_t size, std::uint64_t count,
    void* stream) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_fgetc(
    void* stream) noexcept;
extern "C" __attribute__((ms_abi)) char* cr_fgets(
    char* buffer, std::int32_t count, void* stream) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_fputc(
    std::int32_t c, void* stream) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_fseek(
    void* stream, std::int64_t offset, std::int32_t origin) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_fseeki64(
    void* stream, std::int64_t offset, std::int32_t origin) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t cr_ftell(
    void* stream) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t cr_ftelli64(
    void* stream) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_fflush(
    void* stream) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_feof(void* stream) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_ferror(
    void* stream) noexcept;
extern "C" __attribute__((ms_abi)) void cr_clearerr(void* stream) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_setvbuf(
    void* stream, char* buffer, std::int32_t mode, std::uint64_t size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_ungetc(
    std::int32_t c, void* stream) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_rename(
    const char* from, const char* to) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_remove(
    const char* path) noexcept;
extern "C" __attribute__((ms_abi)) void* cr_tmpfile() noexcept;

// The calendar: the guest's `time_t` is the host's own 64-bit spelling,
// and the `struct tm` the calendar calls bridge through is the nine ints
// both sides spell it with. `clock` is Windows' -- wall time in
// thousandths of a second since the process started, wrapping with its
// 32-bit answer.
extern "C" __attribute__((ms_abi)) std::int64_t cr_time(
    std::int64_t* store) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_clock() noexcept;
extern "C" __attribute__((ms_abi)) void* cr_localtime(
    const std::int64_t* timer) noexcept;
extern "C" __attribute__((ms_abi)) void* cr_gmtime(
    const std::int64_t* timer) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t cr_mktime(
    void* broken_down) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t cr__mkgmtime(
    void* broken_down) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t cr_strftime(
    char* buffer, std::uint64_t max, const char* format,
    const void* broken_down) noexcept;
extern "C" __attribute__((ms_abi)) double cr_difftime(std::int64_t later,
                                                      std::int64_t earlier) noexcept;
extern "C" __attribute__((ms_abi)) char* cr_ctime(
    const std::int64_t* timer) noexcept;
extern "C" __attribute__((ms_abi)) char* cr_asctime(
    const void* broken_down) noexcept;

// The environment: `getenv` reads the merged truth -- the table the
// startup was handed with every `_putenv` and every
// `SetEnvironmentVariable` applied -- and the setting calls rebuild it.
extern "C" __attribute__((ms_abi)) char* cr_getenv(
    const char* name) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr__putenv(
    const char* text) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr__putenv_s(
    const char* name, const char* value) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetEnvironmentVariableA(
    const char* name, char* buffer, std::uint32_t size) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetEnvironmentVariableW(
    const char16_t* name, char16_t* buffer, std::uint32_t size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32_SetEnvironmentVariableA(
    const char* name, const char* value) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32_SetEnvironmentVariableW(
    const char16_t* name, const char16_t* value) noexcept;

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

// The C runtime, shared by every module that exports it.
//
// A domain contributes the names of one area to a module's export list. It
// owns its file, its test, and nothing else: the module it belongs to is
// built from it in `runtime/api/modules.cpp`, so adding a name here is
// adding a line to a list and never a change somewhere else that has to
// agree with this one.
//
// The expected value for anything written here comes from the reference
// rather than from memory. Build a Windows program with the cross compiler,
// run it under `wine64`, and let it answer; then assert the answer in
// `tests/test_api_crt.cpp`. An assertion written from memory encodes the
// author's belief and passes while the implementation is wrong, which is
// what the reference exists to prevent.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/seh.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <utility>
#include <vector>

namespace occ::runtime::winabi {

// The classic runtime's math, buffering and locale face, defined below
// and declared here because the registration list that names them sits
// above their definitions.
extern "C" __attribute__((ms_abi)) double cr_exp(double value) noexcept;
extern "C" __attribute__((ms_abi)) double cr_tanh(double value) noexcept;
extern "C" __attribute__((ms_abi)) int cr_setvbuf(
    void* stream, char* buffer, int mode, std::uint64_t size) noexcept;
extern "C" __attribute__((ms_abi)) void cr___lconv_init() noexcept;
extern char** g_acmdln;


// A guest's `void (*)(void)`: the calling convention is the platform's
// default one, which on x64 is the same convention every other function
// here uses.
using GuestPvfv = void (*)(void);

// The initialisers that can report a failure. `_initterm` runs the plain
// ones and `_initterm_e` runs these, which answer an error code and stop the
// walk -- two different function types, which is why there are two aliases
// rather than one with a cast at the call.
using GuestInitFn = std::int32_t (*)(void);

// The declarations of the UCRT entry points this file defines below.
// They are here because the export list is built above them, and a
// list that named a function before its definition would not compile.
// The two facilities the startup block reaches for, and the one entry
// point whose declaration the extraction above missed because it was the
// first in the block.
extern "C" __attribute__((ms_abi)) void k32_ExitProcess(
    std::uint32_t code) noexcept;
extern "C" __attribute__((ms_abi)) void* k32s2_GetEnvironmentStringsW(
    void) noexcept;
// The line the loader gave the image. The argument vector is built from it
// here rather than from the host's own arguments, because the two are not
// the same line: the guest's was assembled for a Windows program, with the
// program path first and Microsoft's quoting rules applied.
extern "C" __attribute__((ms_abi)) const char* k32_GetCommandLineA() noexcept;
extern "C" __attribute__((ms_abi)) void cr_ucrt_set_app_type(
    std::int32_t type) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_configure_wide_argv(
    std::int32_t mode) noexcept;
extern "C" __attribute__((ms_abi)) int* cr_ucrt_p_argc() noexcept;
extern "C" __attribute__((ms_abi)) char16_t*** cr_ucrt_p_wargv() noexcept;
extern "C" __attribute__((ms_abi)) int* cr_ucrt_p_commode() noexcept;
extern "C" __attribute__((ms_abi)) int cr_ucrt_set_fmode(int mode) noexcept;
extern "C" __attribute__((ms_abi)) int cr_ucrt_configthreadlocale( int type) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_initterm_e( GuestInitFn* first, GuestInitFn* last) noexcept;
extern "C" __attribute__((ms_abi)) void cr_ucrt_crt_atexit( GuestPvfv function) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_initialize_onexit_table( void* table) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_register_onexit_function( void* table, GuestPvfv function) noexcept;
extern "C" __attribute__((ms_abi)) void* cr_ucrt_get_initial_wide_environment( void) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_initialize_wide_environment( void) noexcept;
extern "C" __attribute__((ms_abi)) void cr_ucrt_exit(std::uint32_t code) noexcept;
extern "C" __attribute__((ms_abi)) void cr_ucrt_exit_no_atexit( std::uint32_t code) noexcept;
extern "C" __attribute__((ms_abi)) void cr_ucrt_terminate(void) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_set_new_mode( int mode) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_callnewh( std::size_t size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_seh_filter_exe( std::uint32_t code, void* record) noexcept;
extern "C" __attribute__((ms_abi)) void cr_ucrt_register_tls_atexit( void* callback) noexcept;
extern "C" __attribute__((ms_abi)) double cr_ucrt_ceil(double value) noexcept;
extern "C" __attribute__((ms_abi)) double cr_ucrt_pow(double base, double power) noexcept;
extern "C" __attribute__((ms_abi)) double cr_ucrt_modf(double value, double* integral) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_strcpy_s( char* destination, std::size_t size, const char* source) noexcept;

// Registers the C runtime's exports.
//
// One list, because the C runtime is one library presented under
// several module names: a program built against the Universal CRT
// imports `ucrtbase.dll` and one built against an older toolchain
// imports `msvcrt.dll`, and both call the same functions. A second
// copy of this list for each name would be a second place for the
// two to disagree about what the runtime provides.
void add_crt_exports(ExportList& out) {
    const auto e = [](const char* n, void* fn) {
        HostExport entry;
        entry.name = n;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        return entry;
    };
    const auto d = [](const char* n, void* var) {
        HostExport entry;
        entry.name = n;
        entry.address = reinterpret_cast<std::uint64_t>(var);
        return entry;
    };
    out = {
        e("__getmainargs", reinterpret_cast<void*>(&cr___getmainargs)),
        d("__initenv", &g_initenv),
        e("__iob_func", reinterpret_cast<void*>(&cr___iob_func)),
        e("__set_app_type", reinterpret_cast<void*>(&cr___set_app_type)),
        e("__setusermatherr", reinterpret_cast<void*>(&cr___setusermatherr)),
        e("__C_specific_handler",
          reinterpret_cast<void*>(&seh::seh_C_specific_handler)),
        e("___lc_codepage_func",
          reinterpret_cast<void*>(&cr___lc_codepage_func)),
        e("___mb_cur_max_func",
          reinterpret_cast<void*>(&cr___mb_cur_max_func)),
        e("_amsg_exit", reinterpret_cast<void*>(&cr__amsg_exit)),
        e("_abs64", reinterpret_cast<void*>(&cr__abs64)),
        e("_atoi64", reinterpret_cast<void*>(&cr__atoi64)),
        e("_cexit", reinterpret_cast<void*>(&cr__cexit)),
        d("_commode", &g_commode),
        e("_ctime64", reinterpret_cast<void*>(&cr_ctime)),
        e("_errno", reinterpret_cast<void*>(&cr__errno)),
        d("_environ", &g_environ_ptr),
        e("_fmode", &g_fmode),
        e("_gmtime64", reinterpret_cast<void*>(&cr_gmtime)),
        e("_i64toa", reinterpret_cast<void*>(&cr__i64toa)),
        e("_initterm", reinterpret_cast<void*>(&cr__initterm)),
        e("_itoa", reinterpret_cast<void*>(&cr__itoa)),
        e("_lock", reinterpret_cast<void*>(&cr__lock)),
        e("_ltoa", reinterpret_cast<void*>(&cr__ltoa)),
        e("_localtime64", reinterpret_cast<void*>(&cr_localtime)),
        e("_mkgmtime", reinterpret_cast<void*>(&cr__mkgmtime)),
        e("_mkgmtime64", reinterpret_cast<void*>(&cr__mkgmtime)),
        e("_mktime64", reinterpret_cast<void*>(&cr_mktime)),
        e("_onexit", reinterpret_cast<void*>(&cr__onexit)),
        e("_putenv", reinterpret_cast<void*>(&cr__putenv)),
        e("_putenv_s", reinterpret_cast<void*>(&cr__putenv_s)),
        e("_stricmp", reinterpret_cast<void*>(&cr__stricmp)),
        e("_strlwr", reinterpret_cast<void*>(&cr__strlwr)),
        e("_strnicmp", reinterpret_cast<void*>(&cr__strnicmp)),
        e("_strupr", reinterpret_cast<void*>(&cr__strupr)),
        e("_snprintf", reinterpret_cast<void*>(&cr__snprintf)),
        e("_time64", reinterpret_cast<void*>(&cr_time)),
        e("_ui64toa", reinterpret_cast<void*>(&cr__ui64toa)),
        e("_ultoa", reinterpret_cast<void*>(&cr__ultoa)),
        e("_unlock", reinterpret_cast<void*>(&cr__unlock)),
        e("_vsnprintf", reinterpret_cast<void*>(&cr__vsnprintf)),
        e("_wfopen", reinterpret_cast<void*>(&cr__wfopen)),
        e("abs", reinterpret_cast<void*>(&cr_abs)),
        e("asctime", reinterpret_cast<void*>(&cr_asctime)),
        e("atexit", reinterpret_cast<void*>(&cr_atexit)),
        e("atof", reinterpret_cast<void*>(&cr_atof)),
        e("atoi", reinterpret_cast<void*>(&cr_atoi)),
        e("atol", reinterpret_cast<void*>(&cr_atol)),
        e("abort", reinterpret_cast<void*>(&cr_abort)),
        e("bsearch", reinterpret_cast<void*>(&cr_bsearch)),
        e("calloc", reinterpret_cast<void*>(&cr_calloc)),
        e("clock", reinterpret_cast<void*>(&cr_clock)),
        e("ctime", reinterpret_cast<void*>(&cr_ctime)),
        e("difftime", reinterpret_cast<void*>(&cr_difftime)),
        e("div", reinterpret_cast<void*>(&cr_div)),
        e("exit", reinterpret_cast<void*>(&cr_exit)),
        e("memchr", reinterpret_cast<void*>(&cr_memchr)),
        e("realloc", reinterpret_cast<void*>(&cr_realloc)),
        e("fclose", reinterpret_cast<void*>(&cr_fclose)),
        e("feof", reinterpret_cast<void*>(&cr_feof)),
        e("ferror", reinterpret_cast<void*>(&cr_ferror)),
        e("fflush", reinterpret_cast<void*>(&cr_fflush)),
        e("fgetc", reinterpret_cast<void*>(&cr_fgetc)),
        e("fgets", reinterpret_cast<void*>(&cr_fgets)),
        e("fopen", reinterpret_cast<void*>(&cr_fopen)),
        e("fprintf", reinterpret_cast<void*>(&cr_fprintf)),
        e("fputc", reinterpret_cast<void*>(&cr_fputc)),
        e("fputs", reinterpret_cast<void*>(&cr_fputs)),
        e("fread", reinterpret_cast<void*>(&cr_fread)),
        e("free", reinterpret_cast<void*>(&cr_free)),
        e("_read", reinterpret_cast<void*>(&cr__read)),
        e("fseek", reinterpret_cast<void*>(&cr_fseek)),
        e("fseeki64", reinterpret_cast<void*>(&cr_fseeki64)),
        e("ftell", reinterpret_cast<void*>(&cr_ftell)),
        e("ftelli64", reinterpret_cast<void*>(&cr_ftelli64)),
        e("fwrite", reinterpret_cast<void*>(&cr_fwrite)),
        e("getc", reinterpret_cast<void*>(&cr_getc)),
        e("getchar", reinterpret_cast<void*>(&cr_getchar)),
        e("getenv", reinterpret_cast<void*>(&cr_getenv)),
        e("gmtime", reinterpret_cast<void*>(&cr_gmtime)),
        e("isalnum", reinterpret_cast<void*>(&cr_isalnum)),
        e("isalpha", reinterpret_cast<void*>(&cr_isalpha)),
        e("iscntrl", reinterpret_cast<void*>(&cr_iscntrl)),
        e("isdigit", reinterpret_cast<void*>(&cr_isdigit)),
        e("isgraph", reinterpret_cast<void*>(&cr_isgraph)),
        e("islower", reinterpret_cast<void*>(&cr_islower)),
        e("isprint", reinterpret_cast<void*>(&cr_isprint)),
        e("ispunct", reinterpret_cast<void*>(&cr_ispunct)),
        e("isspace", reinterpret_cast<void*>(&cr_isspace)),
        e("isupper", reinterpret_cast<void*>(&cr_isupper)),
        e("isxdigit", reinterpret_cast<void*>(&cr_isxdigit)),
        e("itoa", reinterpret_cast<void*>(&cr_itoa)),
        e("labs", reinterpret_cast<void*>(&cr_labs)),
        e("ldiv", reinterpret_cast<void*>(&cr_ldiv)),
        e("lldiv", reinterpret_cast<void*>(&cr_lldiv)),
        e("localtime", reinterpret_cast<void*>(&cr_localtime)),
        e("localeconv", reinterpret_cast<void*>(&cr_localeconv)),
        e("malloc", reinterpret_cast<void*>(&cr_malloc)),
        e("mbstowcs", reinterpret_cast<void*>(&cr_mbstowcs)),
        e("memcmp", reinterpret_cast<void*>(&cr_memcmp)),
        e("memcpy", reinterpret_cast<void*>(&cr_memcpy)),
        e("memmove", reinterpret_cast<void*>(&cr_memmove)),
        e("memset", reinterpret_cast<void*>(&cr_memset)),
        e("mktime", reinterpret_cast<void*>(&cr_mktime)),
        e("putc", reinterpret_cast<void*>(&cr_putc)),
        e("putchar", reinterpret_cast<void*>(&cr_putchar)),
        e("putenv", reinterpret_cast<void*>(&cr__putenv)),
        e("puts", reinterpret_cast<void*>(&cr_puts)),
        e("qsort", reinterpret_cast<void*>(&cr_qsort)),
        e("rand", reinterpret_cast<void*>(&cr_rand)),
        e("srand", reinterpret_cast<void*>(&cr_srand)),
        e("signal", reinterpret_cast<void*>(&cr_signal)),
        e("strcat", reinterpret_cast<void*>(&cr_strcat)),
        e("strchr", reinterpret_cast<void*>(&cr_strchr)),
        e("strcmp", reinterpret_cast<void*>(&cr_strcmp)),
        e("strcspn", reinterpret_cast<void*>(&cr_strcspn)),
        e("strerror", reinterpret_cast<void*>(&cr_strerror)),
        e("strftime", reinterpret_cast<void*>(&cr_strftime)),
        e("strlen", reinterpret_cast<void*>(&cr_strlen)),
        e("strncat", reinterpret_cast<void*>(&cr_strncat)),
        e("strncmp", reinterpret_cast<void*>(&cr_strncmp)),
        e("strncpy", reinterpret_cast<void*>(&cr_strncpy)),
        e("strnlen", reinterpret_cast<void*>(&cr_strnlen)),
        e("strpbrk", reinterpret_cast<void*>(&cr_strpbrk)),
        e("strrchr", reinterpret_cast<void*>(&cr_strrchr)),
        e("strspn", reinterpret_cast<void*>(&cr_strspn)),
        e("strstr", reinterpret_cast<void*>(&cr_strstr)),
        e("strtod", reinterpret_cast<void*>(&cr_strtod)),
        e("strtol", reinterpret_cast<void*>(&cr_strtol)),
        e("strtoll", reinterpret_cast<void*>(&cr_strtoll)),
        e("strtoul", reinterpret_cast<void*>(&cr_strtoul)),
        e("strtoull", reinterpret_cast<void*>(&cr_strtoull)),
        e("time", reinterpret_cast<void*>(&cr_time)),
        e("tolower", reinterpret_cast<void*>(&cr_tolower)),
        e("toupper", reinterpret_cast<void*>(&cr_toupper)),
        e("vfprintf", reinterpret_cast<void*>(&cr_vfprintf)),
        e("wcschr", reinterpret_cast<void*>(&cr_wcschr)),
        e("wcscmp", reinterpret_cast<void*>(&cr_wcscmp)),
        e("wcscpy", reinterpret_cast<void*>(&cr_wcscpy)),
        e("wcsdup", reinterpret_cast<void*>(&cr_wcsdup)),
        e("wcslen", reinterpret_cast<void*>(&cr_wcslen)),
        e("wcsncat", reinterpret_cast<void*>(&cr_wcsncat)),
        e("wcsncmp", reinterpret_cast<void*>(&cr_wcsncmp)),
        e("wcsncpy", reinterpret_cast<void*>(&cr_wcsncpy)),
        e("wcsnlen", reinterpret_cast<void*>(&cr_wcsnlen)),
        e("wcsrchr", reinterpret_cast<void*>(&cr_wcsrchr)),
        e("wcsstr", reinterpret_cast<void*>(&cr_wcsstr)),
        e("wcstombs", reinterpret_cast<void*>(&cr_wcstombs)),
        // The UCRT startup protocol, and the three calls the startup's own
        // arithmetic pulls in.
        e("_set_app_type", reinterpret_cast<void*>(&cr_ucrt_set_app_type)),
        e("__p___argc", reinterpret_cast<void*>(&cr_ucrt_p_argc)),
        e("__p___wargv", reinterpret_cast<void*>(&cr_ucrt_p_wargv)),
        e("__p__commode", reinterpret_cast<void*>(&cr_ucrt_p_commode)),
        e("_set_fmode", reinterpret_cast<void*>(&cr_ucrt_set_fmode)),
        e("_configure_wide_argv",
          reinterpret_cast<void*>(&cr_ucrt_configure_wide_argv)),
        e("_configthreadlocale",
          reinterpret_cast<void*>(&cr_ucrt_configthreadlocale)),
        e("_initterm_e", reinterpret_cast<void*>(&cr_ucrt_initterm_e)),
        e("_crt_atexit", reinterpret_cast<void*>(&cr_ucrt_crt_atexit)),
        e("_initialize_onexit_table",
          reinterpret_cast<void*>(&cr_ucrt_initialize_onexit_table)),
        e("_register_onexit_function",
          reinterpret_cast<void*>(&cr_ucrt_register_onexit_function)),
        e("_get_initial_wide_environment",
          reinterpret_cast<void*>(&cr_ucrt_get_initial_wide_environment)),
        e("_initialize_wide_environment",
          reinterpret_cast<void*>(&cr_ucrt_initialize_wide_environment)),
        e("_exit", reinterpret_cast<void*>(&cr_ucrt_exit_no_atexit)),
        e("_c_exit", reinterpret_cast<void*>(&cr_ucrt_exit_no_atexit)),
        e("terminate", reinterpret_cast<void*>(&cr_ucrt_terminate)),
        e("_set_new_mode", reinterpret_cast<void*>(&cr_ucrt_set_new_mode)),
        e("_callnewh", reinterpret_cast<void*>(&cr_ucrt_callnewh)),
        e("_seh_filter_exe", reinterpret_cast<void*>(&cr_ucrt_seh_filter_exe)),
        e("_register_thread_local_exe_atexit_callback",
          reinterpret_cast<void*>(&cr_ucrt_register_tls_atexit)),
        e("ceil", reinterpret_cast<void*>(&cr_ucrt_ceil)),
        e("pow", reinterpret_cast<void*>(&cr_ucrt_pow)),
        e("modf", reinterpret_cast<void*>(&cr_ucrt_modf)),
        e("strcpy_s", reinterpret_cast<void*>(&cr_ucrt_strcpy_s)),
        // The classic runtime's remaining face: the math the host spells
        // the same, the buffering the stream translation feeds (defined in
        // `winabi.cpp`, registered here where the msvcrt list lives), the
        // locale initializer a packed program resolves before it prints,
        // and the command-line pointer the startup hands to itself.
        e("exp", reinterpret_cast<void*>(&cr_exp)),
        e("tanh", reinterpret_cast<void*>(&cr_tanh)),
        e("setvbuf", reinterpret_cast<void*>(&cr_setvbuf)),
        e("__lconv_init", reinterpret_cast<void*>(&cr___lconv_init)),
        d("_acmdln", &g_acmdln),
    };
}

void add_crt(ExportList& out, const char* module) {
    // The module name is documentation: the list is one list, and every name
    // in it is a C runtime function that a program calling through any of
    // the runtime's module names reaches. The parameter is kept because the
    // call sites read better naming the module they are building, and
    // because a future version of this runtime may present a different
    // subset per module -- at which point the name is what selects the
    // subset, and it will already be here.
    static_cast<void>(module);
    add_crt_exports(out);
}

// The two facilities this block reaches for. `k32_ExitProcess` is the
// process layer's own exit, and the environment getter belongs to the
// system-information slice; both are reached by name because the calls
// below are the C runtime's spellings of the same two operations.
extern "C" __attribute__((ms_abi)) void k32_ExitProcess(
    std::uint32_t code) noexcept;
extern "C" __attribute__((ms_abi)) void* k32s2_GetEnvironmentStringsW(
    void) noexcept;

// ------------------------------------------------- the UCRT startup calls
//
// The Universal CRT's startup is a small protocol between the loader and the
// runtime: the loader fills in an argc/argv pair, calls `_set_app_type` to
// say what kind of program this is, runs the initialisers through
// `_initterm`/`_initterm_e`, and expects the runtime to keep a list of
// functions to call at exit. Each function below is one step of that
// protocol, and the list of exit functions is the one piece of state the
// whole group shares.
//
// The list is a real list rather than a counter because the order matters:
// `_crt_atexit` appends, `_register_onexit_function` walks the table the
// caller passed, and a program that registered a flush and a close in that
// order expects them run in that order.

namespace {

// The exit-function list. `_onexit_table_t` is three pointers -- first,
// last, end -- and the middle one is where the next function goes.
constexpr std::size_t kOnexitFirst = 0;
constexpr std::size_t kOnexitLast = 8;
constexpr std::size_t kOnexitEnd = 16;


// The functions registered through `_crt_atexit`. The guest's own table is
// used when it passed one; this vector is what `_crt_atexit` appends to,
// because that call has no table parameter and the runtime has to keep the
// list somewhere.
std::vector<GuestPvfv>& crt_atexit_list() noexcept {
    static std::vector<GuestPvfv> list;
    return list;
}

// What `_set_app_type` recorded lives in the guest's own state -- the
// `GuestState::app_type` field -- rather than in a file-scope variable,
// because the value is a fact about the *guest* and a second copy here would
// be a second answer to the same question.

// The thread-local-locale setting `_configthreadlocale` returns and stores.
std::int32_t g_thread_locale = 0;

// The new-handler mode `_set_new_mode` stores.
int g_new_mode = 0;

// The argc and the wide argv the loader configured. They are the addresses
// `__p___argc` and `__p___wargv` hand out, and the guest's startup reads
// through them, so they have to outlive every call.
int g_crt_argc = 0;
char16_t** g_crt_wargv = nullptr;

}  // namespace

extern "C" __attribute__((ms_abi)) void cr_ucrt_set_app_type(
    std::int32_t type) noexcept {
    // The value selects the startup path in a Windows runtime, and it is
    // observable: a caller that reads the guest's state back sees what the
    // startup set.
    GuestState* g = guest_state();
    if (g != nullptr) {
        g->app_type = static_cast<std::uint32_t>(type);
    }
}

extern "C" __attribute__((ms_abi)) int* cr_ucrt_p_argc() noexcept {
    // A pointer to the count, not the count: the guest writes through it
    // when it adjusts its own argument vector.
    return &g_crt_argc;
}

extern "C" __attribute__((ms_abi)) char16_t*** cr_ucrt_p_wargv() noexcept {
    return &g_crt_wargv;
}

extern "C" __attribute__((ms_abi)) int* cr_ucrt_p_commode() noexcept {
    return &g_commode;
}

extern "C" __attribute__((ms_abi)) int cr_ucrt_set_fmode(int mode) noexcept {
    const int previous = g_fmode;
    g_fmode = mode;
    return previous;
}

extern "C" __attribute__((ms_abi)) int cr_ucrt_configthreadlocale(
    int type) noexcept {
    // The four settings are per-thread in the UCRT and per-process in the
    // older CRT. This runtime runs one thread, so the two are the same state
    // and the call is a store that answers the previous value, which is what
    // an older-CRT caller expects and what a per-thread caller cannot tell
    // apart.
    const int previous = g_thread_locale;
    g_thread_locale = type;
    return previous;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_initterm_e(
    GuestInitFn* first, GuestInitFn* last) noexcept {
    // The error-returning form: each initialiser answers an error code and
    // the walk stops at the first that fails, whose code becomes this
    // call's answer.
    //
    // A walk that reaches the end answers zero, and that zero is the whole
    // of the contract rather than a formality. The startup around this call
    // tests the answer and ends the process with a failure when it is not
    // zero, so a value left behind in the register would end a program
    // whose initialisers had all succeeded -- and it would end it before
    // `main`, which is a failure with no sign of what produced it.
    for (GuestInitFn* p = first; p < last; ++p) {
        if (*p == nullptr) {
            continue;
        }
        const std::int32_t status = (*p)();
        if (status != 0) {
            return status;
        }
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) void cr_ucrt_crt_atexit(
    GuestPvfv function) noexcept {
    if (function != nullptr) {
        crt_atexit_list().push_back(function);
    }
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_initialize_onexit_table(
    void* table) noexcept {
    if (table == nullptr) {
        return -1;
    }
    // An initialised table has no room yet: the three pointers are cleared
    // and the caller's later registrations grow it. A table that was already
    // initialised is left alone, which is what makes a second call a no-op
    // rather than a leak of the first table's block.
    if (read_ptr(table, kOnexitFirst) != 0) {
        return 0;
    }
    write_ptr(table, kOnexitFirst, 0);
    write_ptr(table, kOnexitLast, 0);
    write_ptr(table, kOnexitEnd, 0);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_register_onexit_function(
    void* table, GuestPvfv function) noexcept {
    if (table == nullptr) {
        return -1;
    }
    const std::uint64_t first = read_ptr(table, kOnexitFirst);
    const std::uint64_t last = read_ptr(table, kOnexitLast);
    const std::uint64_t end = read_ptr(table, kOnexitEnd);
    if (last == end) {
        // The table is full. It is grown by allocating a larger block out of
        // the same arena the rest of this runtime's memory comes from, and
        // the entries are copied into it.
        //
        // The growth is what makes the table a table rather than a fixed
        // array: a program with more than a handful of initialisers is
        // ordinary, and refusing the registration would drop a function the
        // program is entitled to have run.
        const std::uint64_t capacity = (end - first) / 8;
        const std::uint64_t grown = capacity == 0 ? 16 : capacity * 2;
        void* block = heap_alloc(0, grown * 8);
        if (block == nullptr) {
            return -1;
        }
        if (first != 0 && capacity != 0) {
            std::memcpy(block, reinterpret_cast<const void*>(first),
                        static_cast<std::size_t>(capacity * 8));
        }
        write_ptr(table, kOnexitFirst, reinterpret_cast<std::uint64_t>(block));
        write_ptr(table, kOnexitLast,
                  reinterpret_cast<std::uint64_t>(block) + capacity * 8);
        write_ptr(table, kOnexitEnd,
                  reinterpret_cast<std::uint64_t>(block) + grown * 8);
        if (first != 0) {
            // The previous block came from this runtime's arena, so it goes
            // back to it. A table that kept the old block would leak one
            // block per growth.
            static_cast<void>(heap_free(reinterpret_cast<void*>(first)));
        }
    }
    const std::uint64_t where = read_ptr(table, kOnexitLast);
    write_ptr(reinterpret_cast<void*>(where), 0,
              reinterpret_cast<std::uint64_t>(function));
    write_ptr(table, kOnexitLast, where + 8);
    return 0;
}

extern "C" __attribute__((ms_abi)) void* cr_ucrt_get_initial_wide_environment(
    void) noexcept {
    // The environment the process started with, as the wide block the
    // startup expects. It is the same block `GetEnvironmentStringsW` builds
    // and it is handed out here rather than built again, so a guest that
    // reads it through either name reads the same text.
    return k32s2_GetEnvironmentStringsW();
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_initialize_wide_environment(
    void) noexcept {
    // Nothing to convert: this runtime's environment is already wide when it
    // is read, and the narrow view is derived from it. The call exists so
    // the startup's sequence is complete, and answering zero says the
    // environment is ready.
    return 0;
}

extern "C" __attribute__((ms_abi)) void cr_ucrt_exit(std::uint32_t code) noexcept {
    // The C runtime's exit: run the registered functions, flush the streams,
    // and end the process without running the image's own teardown. `_exit`
    // and `_c_exit` differ from `exit` in exactly that first step, and this
    // is the one that runs it.
    auto& list = crt_atexit_list();
    while (!list.empty()) {
        GuestPvfv last = list.back();
        list.pop_back();
        if (last != nullptr) {
            last();
        }
    }
    std::fflush(nullptr);
    k32_ExitProcess(code);
    __builtin_unreachable();
}

extern "C" __attribute__((ms_abi)) void cr_ucrt_exit_no_atexit(
    std::uint32_t code) noexcept {
    // `_exit` and `_c_exit`: no registered functions run, and the streams are
    // not flushed by this call. The distinction is the documented one and a
    // program that registered a flush and then called `_exit` is relying on
    // it not running.
    k32_ExitProcess(code);
    __builtin_unreachable();
}

extern "C" __attribute__((ms_abi)) void cr_ucrt_terminate(void) noexcept {
    // The C++ runtime's last resort: called when no exception handler
    // accepted a throw. It aborts, and a runtime that returned here would
    // leave the caller continuing past a point the standard says is
    // unreachable.
    k32_ExitProcess(3);  // the code the C++ runtime's abort uses
    __builtin_unreachable();
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_set_new_mode(
    int mode) noexcept {
    const int previous = g_new_mode;
    g_new_mode = mode;
    return previous;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_callnewh(
    std::size_t size) noexcept {
    // `_callnewh` asks the installed new-handler to make room for an
    // allocation of `size` bytes and answers whether it did. No handler is
    // installed for a guest here, so there is nothing that could have made
    // room, and the answer is no -- which is what makes the allocation fail
    // visibly rather than succeed and hand back memory nothing freed.
    static_cast<void>(size);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_seh_filter_exe(
    std::uint32_t code, void* record) noexcept {
    // The filter the startup installs around the initialisers. It decides
    // what to do about an exception raised before `main` runs. This runtime
    // has no guest exception dispatcher, so the honest answer is the one
    // that lets the exception continue to the process's own handler --
    // answering "handled" would swallow a fault that nothing handled.
    static_cast<void>(code);
    static_cast<void>(record);
    return 0;  // EXCEPTION_CONTINUE_SEARCH
}

extern "C" __attribute__((ms_abi)) void cr_ucrt_register_tls_atexit(
    void* callback) noexcept {
    // The callback a thread wants run when it ends. This runtime runs one
    // guest thread and ends it by returning from the entry point, so the
    // registration is kept for the same reason the exit list is: the state
    // is what the caller set, and discarding it would make a later read
    // disagree with the write.
    static std::vector<void*>& callbacks = *new std::vector<void*>();
    if (callback != nullptr) {
        callbacks.push_back(callback);
    }
}


// The wide argument vector the startup reads.
//
// `_configure_wide_argv` takes a mode, not an array. The mode says how much
// of the command line becomes arguments: none of it, all of it as written,
// or all of it with the wildcards the shell would have expanded. What the
// call does with that answer is build `__wargv` and count `__argc`, and the
// array it builds is the one `__p___wargv` hands out -- so that a program
// reading the arguments through either name reads the same ones.
//
// The split follows the rules `CommandLineToArgvW` implements, because the
// two are the same question asked twice: a program that takes its arguments
// from `__wargv` and one that calls `CommandLineToArgvW` on the same line
// must see the same arguments in the same places, or the startup and the
// program disagree about what the command line said.
//
// The blocks come from this runtime's arena because the array and its
// strings live in the guest's address space: the guest reads them with a
// pointer it was handed, and memory from anywhere else would be an address
// it cannot follow.

namespace {

// The mode that says the program wants no arguments at all. The other two
// differ only in whether wildcards are expanded, and this runtime expands
// none -- the guest receives the line the way the loader wrote it.
constexpr std::int32_t kArgvNoArguments = 0;

// The array and its strings, in one allocation: the pointers first, then
// each argument's characters, so that the whole of what the guest reads is
// one block and nothing has to be freed piecemeal.
void build_wide_arguments() noexcept {
    const char* line = k32_GetCommandLineA();
    if (line == nullptr) {
        return;
    }
    const std::vector<std::string> parts = split_command_line(line);
    if (parts.empty()) {
        return;
    }

    std::size_t total = (parts.size() + 1) * sizeof(char16_t*);
    std::vector<std::size_t> offsets;
    offsets.reserve(parts.size());
    for (const std::string& part : parts) {
        offsets.push_back(total);
        total += (part.size() + 1) * sizeof(char16_t);
    }

    auto* block = static_cast<std::uint8_t*>(heap_alloc(0, total));
    if (block == nullptr) {
        return;
    }
    std::memset(block, 0, total);

    for (std::size_t i = 0; i < parts.size(); ++i) {
        auto* text = reinterpret_cast<char16_t*>(block + offsets[i]);
        for (std::size_t c = 0; c < parts[i].size(); ++c) {
            // The command line is read as bytes and each becomes one wide
            // character. An argument that was not ASCII in the guest's own
            // encoding arrives here already converted by the loader, which
            // is the only place that knows what encoding the line was in.
            text[c] = static_cast<char16_t>(
                static_cast<unsigned char>(parts[i][c]));
        }
        text[parts[i].size()] = u'\0';
        write_ptr(block, i * sizeof(char16_t*),
                  reinterpret_cast<std::uint64_t>(text));
    }
    write_ptr(block, parts.size() * sizeof(char16_t*), 0);

    g_crt_wargv = reinterpret_cast<char16_t**>(block);
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_configure_wide_argv(
    std::int32_t mode) noexcept {
    if (mode == kArgvNoArguments) {
        // The program asked for no arguments. The count is what the startup
        // reads, and the array is left as it was rather than cleared --
        // a later call with a different mode has to find the line it was
        // given, not a null it wrote over it.
        g_crt_argc = 0;
        return 0;
    }

    if (g_crt_wargv == nullptr) {
        build_wide_arguments();
    }

    g_crt_argc = 0;
    if (g_crt_wargv == nullptr) {
        return 0;
    }
    while (g_crt_wargv[g_crt_argc] != nullptr) {
        ++g_crt_argc;
    }
    return 0;
}

// ------------------------------------------------------ the floating point
//
// The three transcendental calls the startup's arithmetic pulls in. Each is
// the host's own function rather than a reimplementation, because the
// result must be the correctly rounded one for the platform: a value
// computed by a hand-written series would differ in the last bit from the
// one the hardware produces, and a program that compares a computed
// coordinate against a constant would then take the other branch.

extern "C" __attribute__((ms_abi)) double cr_ucrt_ceil(double value) noexcept {
    return ::ceil(value);
}

extern "C" __attribute__((ms_abi)) double cr_ucrt_pow(double base,
                                                      double power) noexcept {
    return ::pow(base, power);
}

extern "C" __attribute__((ms_abi)) double cr_ucrt_modf(double value,
                                                       double* integral) noexcept {
    if (integral == nullptr) {
        // The integral part has nowhere to go, and the documented contract
        // says a null pointer here is invalid. Returning the value with the
        // sign cleared would be a plausible number the caller mistook for
        // an answer, so the call reports the error through the only channel
        // it has left.
        errno = EINVAL;
        return 0.0;
    }
    return ::modf(value, integral);
}

// ------------------------------------------------- the bounds-checked copy
//
// `strcpy_s` is the C runtime's checked copy, and its contract is what makes
// it worth writing out: a bad argument *clears the destination* before it
// reports the failure, so a caller that ignores the return value cannot
// then read a half-written string as if it were whole.
//
//   * an empty destination buffer is EINVAL
//   * a source that does not fit is ERANGE, with the destination cleared
//
// Both behaviours are the documented ones and both are relied on: the
// clearing is why this cannot be a call to `strncpy`.

extern "C" __attribute__((ms_abi)) std::int32_t cr_ucrt_strcpy_s(
    char* destination, std::size_t size, const char* source) noexcept {
    if (destination == nullptr || size == 0) {
        return EINVAL;
    }
    if (source == nullptr) {
        // A null source is invalid, and the destination is cleared so the
        // caller cannot read the buffer it passed as though it held text.
        destination[0] = '\0';
        return EINVAL;
    }
    const std::size_t needed = std::strlen(source) + 1;
    if (needed > size) {
        destination[0] = '\0';
        return ERANGE;
    }
    std::memcpy(destination, source, needed);
    return 0;
}

// --------------------------------------------------------------------------
// The classic runtime's math, buffering and locale face
// --------------------------------------------------------------------------

// The two transcendentals a packed program may resolve by name, both the
// host's own functions reached through the same ms_abi translation.
extern "C" __attribute__((ms_abi)) double cr_exp(double value) noexcept {
    return ::exp(value);
}

extern "C" __attribute__((ms_abi)) double cr_tanh(double value) noexcept {
    return ::tanh(value);
}

// The buffering call, with the same stream translation every stdio entry
// point uses: the guest hands a stream address this runtime issued, and
// the host's FILE* is what the request actually means. (The definition
// itself lives in `winabi.cpp` beside the rest of the stdio face; the
// registration there names it already.)

// The locale initializer. The real msvcrt fills a static `lconv` here and
// `localeconv` answers from it; this runtime's `localeconv` answers from
// the host's own, so there is nothing to fill -- the initializer exists
// so a program that resolves and calls it before printing succeeds.
extern "C" __attribute__((ms_abi)) void cr___lconv_init() noexcept {}

// The command-line pointer the classic runtime exports. The real
// `_acmdln` is a `char**` the startup fills with the ANSI command line;
// this runtime keeps the guest's command line in its state, and the
// pointer answers with a valid, terminated empty string, which is all a
// caller that resolves the data export and reads through it needs.
// Defined at file scope, outside the anonymous namespaces, because the
// export registration names it from another translation unit's view of
// this one.
char* g_acmdln_value = const_cast<char*>("");
char** g_acmdln = &g_acmdln_value;

}  // namespace occ::runtime::winabi


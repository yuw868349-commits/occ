// The modules this runtime presents, and the domains each is built from.
//
// `winabi.cpp` holds the machinery and the modules that predate this split;
// this file holds the ones that were added after it, so that a module whose
// whole surface is domains has a home that is only a list. A module named
// here is reachable through the export registry and through `LoadLibrary`
// at once, because both are built from this same table.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <initializer_list>
#include <string_view>

namespace occ::runtime::winabi {
void add_module_ntdll(ExportModule& module) {
    module.name = "NTDLL.dll";
    add_ntdll_rtl(module.host_exports);
    add_ntdll_rtl_str(module.host_exports);
    add_ntdll_rtl_mem1(module.host_exports);
    add_ntdll_rtl_mem2(module.host_exports);
    add_ntdll_rtl_mem3(module.host_exports);
    add_ntdll_nt(module.host_exports);
    add_ntdll_debug(module.host_exports);
    add_ntdll_antidebug(module.host_exports);
    // The loader and context spellings: `LdrLoadDll` and
    // `LdrGetProcedureAddress` reach the same registry the Win32 pair
    // uses, and the Nt context pair is the Win32 pair's spelling.
    add_ntdll_ldr_ext(module.host_exports);
    // The anti-debug and anti-vm answering surface, the shell-runtime
    // memory and section family, the loader-facing family beyond the first
    // one, and the Nt file surface.
    add_ntdll_antidebug2(module.host_exports);
    add_ntdll_shell_mem(module.host_exports);
    add_ntdll_ldr_ext2(module.host_exports);
    add_ntdll_file2(module.host_exports);
}

void add_module_gdi32(ExportModule& module) {
    module.name = "GDI32.dll";
    add_gdi32(module.host_exports);
}

void add_module_advapi32(ExportModule& module) {
    module.name = "ADVAPI32.dll";
    add_advapi32(module.host_exports);
    add_advapi32_reg(module.host_exports);
    add_advapi32_sec(module.host_exports);
    // The token manipulation: the group adjustment, the duplication and
    // the thread attachment, over the same token model.
    add_advapi32_token2(module.host_exports);
}

void add_module_rpcrt4(ExportModule& module) {
    module.name = "RPCRT4.dll";
    add_rpcrt4(module.host_exports);
}

void add_module_setupapi(ExportModule& module) {
    module.name = "SETUPAPI.dll";
    add_setupapi(module.host_exports);
}

void add_module_shell32(ExportModule& module) {
    module.name = "SHELL32.dll";
    add_shell32(module.host_exports);
    // The launcher: `ShellExecuteA` and `ShellExecuteW`, which start a
    // document or a program the way the shell would.
    add_shell32_exec(module.host_exports);
}

void add_module_crypt32(ExportModule& module) {
    module.name = "CRYPT32.dll";
    add_crypt32(module.host_exports);
}

void add_module_bcrypt(ExportModule& module) {
    module.name = "BCRYPT.dll";
    add_bcrypt(module.host_exports);
}

void add_module_bcryptprimitives(ExportModule& module) {
    module.name = "bcryptprimitives.dll";
    add_bcryptprimitives(module.host_exports);
}

void add_module_winmm(ExportModule& module) {
    module.name = "winmm.dll";
    add_winmm(module.host_exports);
}

void add_module_mscoree(ExportModule& module) {
    module.name = "MSCOREE.dll";
    add_mscoree(module.host_exports);
}

void add_module_ws2_32(ExportModule& module) {
    module.name = "WS2_32.dll";
    add_ws2_32(module.host_exports);
}

void add_module_wininet(ExportModule& module) {
    module.name = "WININET.dll";
    add_wininet(module.host_exports);
}

void add_module_urlmon(ExportModule& module) {
    module.name = "URLMON.dll";
    add_urlmon(module.host_exports);
}

void add_module_iphlpapi(ExportModule& module) {
    module.name = "IPHLPAPI.dll";
    add_iphlpapi(module.host_exports);
}

void add_module_ole32(ExportModule& module) {
    module.name = "OLE32.dll";
    add_ole32(module.host_exports);
}

void add_module_ucrtbase(ExportModule& module) {
    module.name = "UCRTBASE.dll";
    add_crt(module.host_exports, "ucrtbase.dll");
    // The modern surface the Universal CRT added: the secure functions,
    // the qualified heaps, the locale objects and the `__stdio_common`
    // entry points every `printf` from a modern toolchain compiles into.
    add_ucrt_extra(module.host_exports);
}

// The `api-ms-win-crt-*` family, as forwarder stubs.
//
// On a real system each of these modules is a `VERSIONINFO`-only stub
// whose export table holds strings -- `ucrtbase.printf` and the like --
// and a loader that reads them follows the strings. This runtime has no
// forwarder strings to write; the same names are registered directly in
// each module, which is what following the strings achieves and what a
// guest that loads one of these modules is actually asking for.
//
// The family split is a real thing: each `api-ms-win-crt-*` module
// carries exactly its family and nothing else, the families overlap in
// nothing, and two of the names the older table listed --
// `-stdlib` and `-ctype` -- are not modules Windows ships at all. The
// sets below are the real families' exports as far as this runtime
// implements them, and the table's contract is the one the test
// `test_crt_forwarders.cpp` asserts: every name in every set resolves,
// and it resolves to the implementation the base module holds.
// The names each family forwards, as the family's real export table
// states them: every name here is one the real module exports and this
// runtime implements, and a name outside a module's family is absent
// from it. The families whose names this runtime does not implement are
// listed in DESIGN.md's known gaps, with the counts.
const ForwardSet kCrtForwarders[] = {
    {"api-ms-win-crt-runtime-l1-1-0.dll",
        {"_Exit", "__control87_2", "__doserrno", "__fpe_flt_rounds",
        "__fpecode", "__p___argc", "__p___argv", "__p___wargv",
        "__p__pgmptr", "__p__wpgmptr", "__pxcptinfoptrs",
        "__sys_nerr", "__threadhandle", "__threadid", "_assert",
        "_beginthreadex", "_c_exit", "_cexit", "_clearfp",
        "_configure_narrow_argv", "_configure_wide_argv",
        "_control87", "_controlfp", "_controlfp_s",
        "_crt_at_quick_exit", "_crt_atexit", "_crt_debugger_hook",
        "_endthread", "_endthreadex", "_errno", "_exit", "_fpreset",
        "_get_doserrno", "_get_errno",
        "_get_initial_narrow_environment",
        "_get_initial_wide_environment",
        "_get_invalid_parameter_handler",
        "_get_narrow_winmain_command_line", "_get_pgmptr",
        "_get_terminate",
        "_get_thread_local_invalid_parameter_handler",
        "_get_wide_winmain_command_line", "_get_wpgmptr",
        "_getdllprocaddr", "_getpid",
        "_initialize_narrow_environment", "_initialize_onexit_table",
        "_initialize_wide_environment", "_initterm", "_initterm_e",
        "_invalid_parameter_noinfo",
        "_invalid_parameter_noinfo_noreturn", "_invoke_watson",
        "_query_app_type", "_register_onexit_function",
        "_register_thread_local_exe_atexit_callback",
        "_resetstkoflw", "_seh_filter_dll", "_seh_filter_exe",
        "_set_abort_behavior", "_set_app_type", "_set_controlfp",
        "_set_doserrno", "_set_errno", "_set_error_mode",
        "_set_invalid_parameter_handler", "_set_new_handler",
        "_set_thread_local_invalid_parameter_handler",
        "_seterrormode", "_sleep", "_statusfp", "_statusfp2",
        "_strerror", "_strerror_s", "_wassert", "_wcserror",
        "_wcserror_s", "_wperror", "_wsystem", "abort", "exit",
        "feclearexcept", "fegetenv", "fegetexceptflag", "fegetround",
        "feholdexcept", "fesetenv", "fesetexceptflag", "fesetround",
        "fetestexcept", "perror", "quick_exit", "raise",
        "set_terminate", "signal", "strerror", "strerror_s",
        "system", "terminate"}},
    {"api-ms-win-crt-stdio-l1-1-0.dll",
        {"__acrt_iob_func", "__p__commode", "__p__fmode",
        "__stdio_common_vfprintf", "__stdio_common_vfscanf",
        "__stdio_common_vfwprintf", "__stdio_common_vfwscanf",
        "__stdio_common_vsnwprintf_s", "__stdio_common_vsprintf",
        "__stdio_common_vsscanf", "__stdio_common_vswprintf",
        "__stdio_common_vswprintf_s", "__stdio_common_vswscanf",
        "_chsize", "_chsize_s", "_close", "_commit", "_creat",
        "_dup", "_dup2", "_eof", "_fclose_nolock", "_fcloseall",
        "_fflush_nolock", "_fgetc_nolock", "_fgetchar",
        "_fgetwc_nolock", "_fgetwchar", "_filelength",
        "_filelengthi64", "_fileno", "_flushall", "_fputc_nolock",
        "_fputchar", "_fputwc_nolock", "_fread_nolock",
        "_fread_nolock_s", "_fseek_nolock", "_fseeki64",
        "_fseeki64_nolock", "_fsopen", "_ftell_nolock", "_ftelli64",
        "_ftelli64_nolock", "_fwrite_nolock", "_get_fmode",
        "_get_osfhandle", "_get_printf_count_output",
        "_get_stream_buffer_pointers", "_getc_nolock", "_getcwd",
        "_getdcwd", "_getmaxstdio", "_getw", "_getwc_nolock",
        "_getws", "_getws_s", "_isatty", "_kbhit", "_locking",
        "_lseek", "_lseeki64", "_mktemp", "_mktemp_s", "_open",
        "_open_osfhandle", "_pclose", "_pipe", "_popen",
        "_putc_nolock", "_putw", "_putwc_nolock", "_putws", "_read",
        "_rmtmp", "_set_fmode", "_set_printf_count_output",
        "_setmaxstdio", "_setmode", "_sopen", "_sopen_dispatch",
        "_sopen_s", "_tell", "_telli64", "_tempnam",
        "_ungetc_nolock", "_ungetwc_nolock", "_wcreat", "_wfdopen",
        "_wfopen", "_wfopen_s", "_wfreopen", "_wfreopen_s",
        "_wfsopen", "_wmktemp", "_wmktemp_s", "_wopen", "_wpopen",
        "_write", "_wsopen", "_wsopen_dispatch", "_wsopen_s",
        "_wtempnam", "_wtmpnam", "_wtmpnam_s", "clearerr",
        "clearerr_s", "fclose", "feof", "ferror", "fflush", "fgetc",
        "fgetpos", "fgets", "fgetwc", "fgetws", "fopen", "fopen_s",
        "fputc", "fputs", "fputwc", "fputws", "fread", "fread_s",
        "freopen", "freopen_s", "fseek", "fsetpos", "ftell",
        "fwrite", "getc", "getchar", "gets", "gets_s", "getwc",
        "getwchar", "putc", "putchar", "puts", "putwc", "putwchar",
        "rewind", "setbuf", "setvbuf", "tmpfile", "tmpfile_s",
        "tmpnam", "tmpnam_s", "ungetc", "ungetwc"}},
    {"api-ms-win-crt-string-l1-1-0.dll",
        {"__isascii", "__iscsym", "__iscsymf", "__iswcsym",
        "__iswcsymf", "_isctype", "_isctype_l", "_isleadbyte_l",
        "_iswalnum_l", "_iswalpha_l", "_iswcntrl_l", "_iswctype_l",
        "_iswdigit_l", "_iswlower_l", "_iswprint_l", "_iswpunct_l",
        "_iswspace_l", "_iswupper_l", "_iswxdigit_l", "_memccpy",
        "_memicmp", "_memicmp_l", "_strcoll_l", "_strdup",
        "_stricmp", "_stricmp_l", "_stricoll", "_stricoll_l",
        "_strlwr", "_strlwr_l", "_strlwr_s", "_strlwr_s_l",
        "_strncoll_l", "_strnicmp", "_strnicmp_l", "_strnicoll",
        "_strnicoll_l", "_strnset", "_strnset_s", "_strrev",
        "_strset", "_strset_s", "_strupr", "_strupr_l", "_strupr_s",
        "_strupr_s_l", "_strxfrm_l", "_tolower", "_tolower_l",
        "_toupper", "_toupper_l", "_towlower_l", "_towupper_l",
        "_wcscoll_l", "_wcsdup", "_wcsicmp", "_wcsicmp_l",
        "_wcsicoll", "_wcsicoll_l", "_wcslwr", "_wcslwr_l",
        "_wcslwr_s", "_wcslwr_s_l", "_wcsncoll", "_wcsncoll_l",
        "_wcsnicmp_l", "_wcsnicoll", "_wcsnicoll_l", "_wcsnset",
        "_wcsnset_s", "_wcsrev", "_wcsset", "_wcsset_s", "_wcsupr",
        "_wcsupr_l", "_wcsupr_s", "_wcsupr_s_l", "_wcsxfrm_l",
        "is_wctype", "isalnum", "isalpha", "isblank", "iscntrl",
        "isdigit", "isgraph", "isleadbyte", "islower", "isprint",
        "ispunct", "isspace", "isupper", "iswalnum", "iswalpha",
        "iswascii", "iswblank", "iswcntrl", "iswctype", "iswdigit",
        "iswgraph", "iswlower", "iswprint", "iswpunct", "iswspace",
        "iswupper", "iswxdigit", "isxdigit", "mblen", "mbrlen",
        "memcpy_s", "memmove_s", "memset", "strcat", "strcat_s",
        "strcmp", "strcoll", "strcpy", "strcpy_s", "strcspn",
        "strlen", "strncat", "strncat_s", "strncmp", "strncpy",
        "strncpy_s", "strnlen", "strpbrk", "strspn", "strtok",
        "strtok_s", "strxfrm", "tolower", "toupper", "towctrans",
        "towlower", "towupper", "wcscat_s", "wcscmp", "wcscoll",
        "wcscpy", "wcscspn", "wcslen", "wcsncat", "wcsncmp",
        "wcsncpy", "wcsnlen", "wcspbrk", "wcsspn", "wcstok",
        "wcstok_s", "wcsxfrm", "wctype", "wmemcpy_s", "wmemmove_s"}},
    {"api-ms-win-crt-math-l1-1-0.dll",
        {"__setusermatherr", "_chgsign", "_chgsignf", "_copysign",
        "_copysignf", "_fdopen", "_finite", "_finitef", "_fpclass",
        "_fpclassf", "_ftol", "_get_FMA3_enable", "_hypot",
        "_hypotf", "_isnan", "_isnanf", "_j0", "_j1", "_jn", "_logb",
        "_logbf", "_nextafter", "_nextafterf", "_scalb", "_scalbf",
        "_set_FMA3_enable", "_set_SSE2_enable", "_y0", "_y1", "_yn",
        "acos", "acosf", "acosh", "acoshf", "acoshl", "asin",
        "asinf", "asinh", "asinhf", "asinhl", "atan", "atan2",
        "atan2f", "atanf", "atanh", "atanhf", "atanhl", "cbrt",
        "cbrtf", "cbrtl", "ceil", "ceilf", "copysign", "copysignf",
        "copysignl", "cos", "cosf", "cosh", "coshf", "erf", "erfc",
        "erfcf", "erfcl", "erff", "erfl", "exp", "exp2", "exp2f",
        "exp2l", "expf", "expm1", "expm1f", "expm1l", "fabs",
        "fabsf", "fdim", "fdimf", "fdiml", "floor", "floorf", "fma",
        "fmaf", "fmal", "fmax", "fmaxf", "fmaxl", "fmin", "fminf",
        "fminl", "fmod", "fmodf", "frexp", "hypot", "ilogb",
        "ilogbf", "ilogbl", "ldexp", "lgamma", "lgammaf", "lgammal",
        "llrint", "llrintf", "llrintl", "llround", "llroundf",
        "llroundl", "log", "log10", "log10f", "log1p", "log1pf",
        "log1pl", "log2", "log2f", "log2l", "logb", "logbf", "logbl",
        "logf", "lrint", "lrintf", "lrintl", "lround", "lroundf",
        "lroundl", "modf", "modff", "nan", "nanf", "nanl",
        "nearbyint", "nearbyintf", "nearbyintl", "nextafter",
        "nextafterf", "nextafterl", "nexttoward", "nexttowardf",
        "nexttowardl", "pow", "powf", "remainder", "remainderf",
        "remainderl", "remquo", "remquof", "remquol", "rint",
        "rintf", "rintl", "round", "roundf", "roundl", "scalbln",
        "scalblnf", "scalblnl", "scalbn", "scalbnf", "scalbnl",
        "sin", "sinf", "sinh", "sinhf", "sqrt", "sqrtf", "tan",
        "tanf", "tanh", "tanhf", "tgamma", "tgammaf", "tgammal",
        "trunc", "truncf", "truncl"}},
    {"api-ms-win-crt-locale-l1-1-0.dll",
        {"___lc_codepage_func", "___mb_cur_max_func",
        "__initialize_lconv_for_unsigned_char", "__pctype_func",
        "__pwctype_func", "_configthreadlocale", "_create_locale",
        "_free_locale", "_get_current_locale", "_getmbcp",
        "_lock_locales", "_setmbcp", "_unlock_locales",
        "_wcreate_locale", "_wsetlocale", "localeconv", "setlocale"}},
    {"api-ms-win-crt-time-l1-1-0.dll",
        {"_Getdays", "_Getmonths", "_Gettnames", "_Strftime",
        "_W_Getdays", "_W_Getmonths", "_W_Gettnames", "_Wcsftime",
        "__daylight", "__dstbias", "__timezone", "__tzname",
        "_ctime32", "_ctime32_s", "_ctime64", "_ctime64_s",
        "_difftime32", "_difftime64", "_futime32", "_futime64",
        "_get_daylight", "_get_dstbias", "_get_timezone",
        "_get_tzname", "_getsystime", "_gmtime32", "_gmtime32_s",
        "_gmtime64", "_gmtime64_s", "_localtime32", "_localtime32_s",
        "_localtime64", "_localtime64_s", "_mkgmtime32",
        "_mkgmtime64", "_mktime32", "_mktime64", "_setsystime",
        "_strdate", "_strdate_s", "_strftime_l", "_strtime",
        "_strtime_s", "_time32", "_time64", "_timespec32_get",
        "_timespec64_get", "_tzset", "_utime32", "_utime64",
        "_wasctime", "_wasctime_s", "_wcsftime_l", "_wctime32",
        "_wctime32_s", "_wctime64", "_wctime64_s", "_wstrdate",
        "_wstrdate_s", "_wstrtime", "_wstrtime_s", "_wutime32",
        "_wutime64", "asctime", "asctime_s", "clock", "strftime",
        "wcsftime"}},
    {"api-ms-win-crt-convert-l1-1-0.dll",
        {"__toascii", "_atoi64", "_ecvt", "_ecvt_s", "_fcvt",
        "_fcvt_s", "_gcvt", "_gcvt_s", "_i64toa", "_i64toa_s",
        "_i64tow", "_i64tow_s", "_itoa", "_itoa_s", "_itow",
        "_itow_s", "_ltoa", "_ltoa_s", "_ltow", "_ltow_s",
        "_strtod_l", "_strtoi64", "_strtoui64", "_ui64toa",
        "_ui64toa_s", "_ui64tow", "_ui64tow_s", "_ultoa", "_ultoa_s",
        "_ultow", "_ultow_s", "_wtof", "_wtof_l", "_wtoi", "_wtoi64",
        "_wtoi64_l", "_wtoi_l", "_wtol", "_wtol_l", "_wtoll",
        "_wtoll_l", "atof", "atoi", "atol", "atoll", "btowc",
        "mbrtowc", "mbsrtowcs", "mbstowcs", "mbstowcs_s", "mbtowc",
        "strtod", "strtof", "strtoimax", "strtol", "strtold",
        "strtoll", "strtoul", "strtoull", "strtoumax", "wcrtomb",
        "wcrtomb_s", "wcstod", "wcstof", "wcstoimax", "wcstol",
        "wcstold", "wcstoll", "wcstombs", "wcstombs_s", "wcstoul",
        "wcstoull", "wcstoumax", "wctob", "wctomb", "wctomb_s",
        "wctrans"}},
    {"api-ms-win-crt-heap-l1-1-0.dll",
        {"_aligned_free", "_aligned_malloc", "_aligned_msize",
        "_aligned_offset_malloc", "_aligned_offset_realloc",
        "_aligned_offset_recalloc", "_aligned_realloc",
        "_aligned_recalloc", "_callnewh", "_calloc_base", "_expand",
        "_free_base", "_get_heap_handle", "_heapchk", "_heapmin",
        "_heapwalk", "_malloc_base", "_msize", "_query_new_handler",
        "_query_new_mode", "_realloc_base", "_recalloc",
        "_set_new_mode", "calloc", "free", "malloc", "realloc"}},
    {"api-ms-win-crt-environment-l1-1-0.dll",
        {"__p__environ", "__p__wenviron", "_dupenv_s", "_putenv",
        "_putenv_s", "_searchenv", "_searchenv_s", "_wdupenv_s",
        "_wgetcwd", "_wgetdcwd", "_wgetenv", "_wgetenv_s",
        "_wputenv", "_wputenv_s", "_wsearchenv", "_wsearchenv_s",
        "getenv", "getenv_s"}},
    {"api-ms-win-crt-filesystem-l1-1-0.dll",
        {"_access", "_access_s", "_chdir", "_chdrive", "_chmod",
        "_findclose", "_findfirst32", "_findfirst32i64",
        "_findfirst64", "_findfirst64i32", "_findnext32",
        "_findnext32i64", "_findnext64", "_findnext64i32",
        "_fstat32", "_fstat32i64", "_fstat64", "_fstat64i32",
        "_fullpath", "_getdiskfree", "_getdrive", "_getdrives",
        "_lock_file", "_makepath", "_makepath_s", "_mkdir", "_rmdir",
        "_splitpath", "_splitpath_s", "_stat32", "_stat32i64",
        "_stat64", "_stat64i32", "_umask", "_umask_s", "_unlink",
        "_unlock_file", "_waccess", "_waccess_s", "_wchdir",
        "_wchmod", "_wfindfirst32", "_wfindfirst32i64",
        "_wfindfirst64", "_wfindfirst64i32", "_wfindnext32",
        "_wfindnext32i64", "_wfindnext64", "_wfindnext64i32",
        "_wfullpath", "_wmakepath", "_wmakepath_s", "_wmkdir",
        "_wremove", "_wrename", "_wrmdir", "_wsplitpath",
        "_wsplitpath_s", "_wstat32", "_wstat32i64", "_wstat64",
        "_wstat64i32", "_wunlink", "remove", "rename"}},
    {"api-ms-win-crt-process-l1-1-0.dll",
        {"_beep", "_cwait", "_execl", "_execle", "_execlp",
        "_execlpe", "_execv", "_execve", "_execvp", "_execvpe",
        "_loaddll", "_spawnl", "_spawnle", "_spawnlp", "_spawnlpe",
        "_spawnv", "_spawnve", "_spawnvp", "_spawnvpe", "_unloaddll",
        "_wexecl", "_wexecle", "_wexeclp", "_wexeclpe", "_wexecv",
        "_wexecve", "_wexecvp", "_wexecvpe", "_wspawnl", "_wspawnle",
        "_wspawnlp", "_wspawnlpe", "_wspawnv", "_wspawnve",
        "_wspawnvp", "_wspawnvpe"}},
    {"api-ms-win-crt-conio-l1-1-0.dll",
        {"__conio_common_vcprintf", "__conio_common_vcprintf_p",
        "__conio_common_vcprintf_s", "__conio_common_vcscanf",
        "__conio_common_vcwprintf", "__conio_common_vcwprintf_p",
        "__conio_common_vcwprintf_s", "__conio_common_vcwscanf",
        "_cgets", "_cgets_s", "_cgetws", "_cgetws_s", "_cputs",
        "_cputws", "_getch", "_getch_nolock", "_getche",
        "_getche_nolock", "_getwch", "_getwch_nolock", "_getwche",
        "_getwche_nolock", "_putch", "_putch_nolock", "_putwch",
        "_putwch_nolock", "_ungetch", "_ungetch_nolock", "_ungetwch",
        "_ungetwch_nolock"}},
    {"api-ms-win-crt-utility-l1-1-0.dll",
        {"_abs64", "_byteswap_uint64", "_byteswap_ulong",
        "_byteswap_ushort", "_lfind", "_lfind_s", "_lrotl", "_lrotr",
        "_lsearch", "_lsearch_s", "_rotl", "_rotl64", "_rotr",
        "_rotr64", "_swab", "abs", "bsearch", "bsearch_s", "div",
        "imaxabs", "imaxdiv", "labs", "ldiv", "llabs", "lldiv",
        "qsort", "qsort_s", "rand", "rand_s", "srand"}},
    {"api-ms-win-crt-multibyte-l1-1-0.dll",
        {"_mbtowc_l"}},
    {"api-ms-win-crt-private-l1-1-0.dll",
        {"__C_specific_handler", "_get_purecall_handler",
        "_get_unexpected", "_o__errno", "_purecall",
        "_set_purecall_handler", "_set_se_translator", "memchr",
        "memcmp", "memcpy", "memmove", "set_unexpected", "strchr",
        "strrchr", "strstr", "unexpected", "wcschr", "wcsrchr",
        "wcsstr"}},
    {nullptr, {}},
};

void add_module_api_ms_win_crt(ExportModule& module) {
    const std::string_view want(module.name);
    // The full surface this runtime has: the classic exports and the
    // modern ones, which together are what the forwarder stubs point at.
    ExportList full;
    add_crt_exports(full);
    add_ucrt_extra(full);
    add_crt_families(full);
    for (const ForwardSet& set : kCrtForwarders) {
        if (want != set.module) {
            continue;
        }
        for (const char* name : set.names) {
            for (const HostExport& entry : full) {
                if (entry.name == name) {
                    module.host_exports.push_back(entry);
                    break;
                }
            }
        }
        return;
    }
}

void add_module_msvcr70(ExportModule& module) {
    module.name = "MSVCR70.dll";
    add_crt(module.host_exports, "msvcr70.dll");
}

void add_module_msvcr71(ExportModule& module) {
    module.name = "MSVCR71.dll";
    add_crt(module.host_exports, "msvcr71.dll");
}

void add_module_msvcr80(ExportModule& module) {
    module.name = "MSVCR80.dll";
    add_crt(module.host_exports, "msvcr80.dll");
}

void add_module_msvcr90(ExportModule& module) {
    module.name = "MSVCR90.dll";
    add_crt(module.host_exports, "msvcr90.dll");
}

void add_module_msvcr100(ExportModule& module) {
    module.name = "MSVCR100.dll";
    add_crt(module.host_exports, "msvcr100.dll");
}

void add_module_msvcr110(ExportModule& module) {
    module.name = "MSVCR110.dll";
    add_crt(module.host_exports, "msvcr110.dll");
}

void add_module_msvcr120(ExportModule& module) {
    module.name = "MSVCR120.dll";
    add_crt(module.host_exports, "msvcr120.dll");
}

void add_module_msvcr120_app(ExportModule& module) {
    module.name = "MSVCR120_APP.dll";
    add_crt(module.host_exports, "msvcr120_app.dll");
}

void add_module_msvcrtd(ExportModule& module) {
    module.name = "MSVCRTD.dll";
    add_crt(module.host_exports, "msvcrtd.dll");
}

void add_module_msvcrt20(ExportModule& module) {
    module.name = "MSVCRT20.dll";
    add_crt(module.host_exports, "msvcrt20.dll");
}

void add_module_msvcrt40(ExportModule& module) {
    module.name = "MSVCRT40.dll";
    add_crt(module.host_exports, "msvcrt40.dll");
}

void add_module_msvcirt(ExportModule& module) {
    module.name = "MSVCIRT.dll";
    add_crt(module.host_exports, "msvcirt.dll");
}

}  // namespace occ::runtime::winabi

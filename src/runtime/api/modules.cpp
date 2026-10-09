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
// The subset each module carries is the subset its real counterpart
// exports, as far as this runtime implements it: `api-ms-win-crt-string`
// carries the string functions, `-crt-math` the arithmetic ones, and the
// names outside a module's family are absent from it, which is the
// answer a guest that asks the wrong module should get.
struct ForwardSet {
    const char* module;
    std::initializer_list<const char*> names;
};

// The names each family forwards.
const ForwardSet kCrtForwarders[] = {
    {"api-ms-win-crt-runtime-l1-1-0.dll",
     {"_initterm", "_initterm_e", "__getmainargs", "__set_app_type",
      "__setusermatherr", "_set_app_type", "_configure_wide_argv",
      "_configthreadlocale", "_initialize_onexit_table",
      "_register_onexit_function", "_crt_atexit", "_exit", "_c_exit",
      "_cexit", "exit", "abort", "_amsg_exit", "terminate", "_set_new_mode",
      "_callnewh", "_seh_filter_exe", "_get_initial_wide_environment",
      "_initialize_wide_environment", "_register_thread_local_exe_atexit_callback",
      "_invalid_parameter", "_invalid_parameter_noinfo",
      "_invalid_parameter_noinfo_noreturn", "_set_invalid_parameter_handler",
      "_get_errno", "_set_errno", "strerror", "signal"}},
    {"api-ms-win-crt-stdio-l1-1-0.dll",
     {"fopen", "_wfopen", "fclose", "fflush", "fread", "fwrite", "fseek",
      "fseeki64", "ftell", "ftelli64", "feof", "ferror", "fgetc", "fgets",
      "fputc", "fputs", "getc", "getchar", "putc", "putchar", "puts",
      "fprintf", "vfprintf", "sprintf_s", "snprintf_s", "vsnprintf_s",
      "vsprintf_s", "_snprintf", "_vsnprintf", "sprintf", "snprintf",
      "__stdio_common_vfprintf", "__stdio_common_vsprintf",
      "__stdio_common_vsnprintf", "__stdio_common_vfscanf",
      "__stdio_common_vsscanf", "__iob_func", "_read", "_set_fmode",
      "_get_printf_count_output"}},
    {"api-ms-win-crt-string-l1-1-0.dll",
     {"strcat", "strchr", "strcmp", "strcpy", "strcspn", "strlen",
      "strncat", "strncmp", "strncpy", "strnlen", "strpbrk", "strrchr",
      "strspn", "strstr", "strcpy_s", "strncpy_s", "strcat_s", "strncat_s",
      "strnlen_s", "memchr", "memcmp", "memcpy", "memmove", "memset",
      "memcpy_s", "memmove_s", "_stricmp", "_strnicmp", "_strlwr",
      "_strupr", "wcscat", "wcschr", "wcscmp", "wcscpy", "wcslen",
      "wcsncat", "wcsncmp", "wcsncpy", "wcsnlen", "wcsrchr", "wcsstr",
      "wcscat_s", "wcsdup", "_strrev", "strtok_s", "wcstok_s"}},
    {"api-ms-win-crt-stdlib-l1-1-0.dll",
     {"malloc", "calloc", "realloc", "free", "abs", "labs", "_abs64",
      "div", "ldiv", "lldiv", "atoi", "atol", "atof", "_atoi64", "itoa",
      "_itoa", "_ltoa", "_ultoa", "_i64toa", "_ui64toa", "_itoa_s",
      "_i64toa_s", "_ui64toa_s", "_ultoa_s", "_ltoa_s", "strtod", "strtol",
      "strtoll", "strtoul", "strtoull", "_strtoi64", "_strtoui64", "rand",
      "srand", "rand_s", "qsort", "bsearch", "getenv", "putenv", "_putenv",
      "_putenv_s", "system", "_wsystem", "_splitpath_s", "_makepath_s",
      "_fullpath", "_getcwd", "_chdir", "_mkdir", "_access", "_exit"}},
    {"api-ms-win-crt-math-l1-1-0.dll",
     {"ceil", "pow", "modf", "floor", "fabs", "sqrt", "sin", "cos", "tan",
      "log", "log10", "exp", "atan", "atan2", "round", "trunc", "fmod",
      "ldexp", "frexp", "hypot", "cbrt", "rint", "nearbyint"}},
    {"api-ms-win-crt-ctype-l1-1-0.dll",
     {"isalnum", "isalpha", "iscntrl", "isdigit", "isgraph", "islower",
      "isprint", "ispunct", "isspace", "isupper", "isxdigit", "tolower",
      "toupper", "isblank", "_isctype", "_tolower", "_toupper",
      "_tolower_l", "_toupper_l", "isleadbyte"}},
    {"api-ms-win-crt-locale-l1-1-0.dll",
     {"setlocale", "localeconv", "_create_locale", "_free_locale",
      "_get_current_locale", "___lc_codepage_func", "___mb_cur_max_func",
      "_configthreadlocale", "_getmbcp", "_setmbcp"}},
    {"api-ms-win-crt-time-l1-1-0.dll",
     {"time", "clock", "difftime", "mktime", "localtime", "gmtime", "ctime",
      "asctime", "strftime", "_time64", "_ctime64", "_gmtime64",
      "_localtime64", "_mktime64", "_mkgmtime", "_mkgmtime64", "localtime_s",
      "gmtime_s", "ctime_s", "_strtime_s", "_strdate_s"}},
    {"api-ms-win-crt-convert-l1-1-0.dll",
     {"atof", "atoi", "atol", "_atoi64", "strtod", "strtol", "strtoll",
      "strtoul", "strtoull", "_strtoi64", "_strtoui64", "_itoa", "_ltoa",
      "_ultoa", "_i64toa", "_ui64toa", "_itoa_s", "_ltoa_s", "_ultoa_s",
      "_i64toa_s", "_ui64toa_s", "mbstowcs", "wcstombs", "mbrtowc",
      "wcrtomb", "mbsrtowcs", "wcsrtombs", "btowc", "wctob"}},
    {"api-ms-win-crt-heap-l1-1-0.dll",
     {"malloc", "calloc", "realloc", "free", "_aligned_malloc",
      "_aligned_free", "_aligned_realloc", "_aligned_msize", "_heapchk",
      "_heapmin", "_heapwalk", "_msize", "_expand", "_recalloc"}},
    {"api-ms-win-crt-environment-l1-1-0.dll",
     {"getenv", "putenv", "_putenv", "_putenv_s", "_wgetenv", "_wputenv",
      "_wputenv_s", "_dupenv_s", "_wdupenv_s", "_searchenv", "_wsearchenv"}},
    {"api-ms-win-crt-filesystem-l1-1-0.dll",
     {"_access", "_chdir", "_chmod", "_mkdir", "_rmdir", "_remove", "_unlink",
      "_findfirst", "_findfirst64", "_findnext", "_findclose", "_stat",
      "_stat64", "_fstat", "_fstat64", "_fullpath", "_splitpath",
      "_splitpath_s", "_makepath_s", "_getcwd", "_wgetcwd", "_chsize"}},
    {"api-ms-win-crt-process-l1-1-0.dll",
     {"system", "_wsystem", "exit", "_exit", "_cexit", "_c_exit", "abort",
      "_execv", "_execve", "_spawnv", "_spawnve", "_wspawnv"}},
    {"api-ms-win-crt-conio-l1-1-0.dll",
     {"_getch", "_getche", "_kbhit", "_putch", "_cgets", "_cprintf",
      "_cputs", "_cscanf", "getchar", "putchar"}},
    {"api-ms-win-crt-utility-l1-1-0.dll",
     {"abs", "labs", "div", "ldiv", "qsort", "bsearch", "rand", "srand",
      "rand_s", "_rotl", "_rotr", "_lrotl", "_lrotr", "_byteswap_ushort",
      "_byteswap_ulong", "_byteswap_uint64"}},
    {"api-ms-win-crt-multibyte-l1-1-0.dll",
     {"mbstowcs", "wcstombs", "_mbstowcs_s", "_wcstombs_s", "_mbslen",
      "_mbschr", "_mbsrchr", "_mbsstr", "_mbsdup", "_mbccpy", "_mbclen",
      "_ismbblead", "_ismbbtrail"}},
    {"api-ms-win-crt-private-l1-1-0.dll",
     {"_lock", "_unlock", "_get_osfhandle", "_open_osfhandle",
      "_o__errno", "__C_specific_handler", "_getpid", "_gettid",
      "_crt_atexit", "_CrtDbgReport", "_CrtSetDbgFlag"}},
};

void add_module_api_ms_win_crt(ExportModule& module) {
    const std::string_view want(module.name);
    // The full surface this runtime has: the classic exports and the
    // modern ones, which together are what the forwarder stubs point at.
    ExportList full;
    add_crt_exports(full);
    add_ucrt_extra(full);
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

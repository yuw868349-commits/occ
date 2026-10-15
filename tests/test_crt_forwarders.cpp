// The `api-ms-win-crt-*` forwarder table, as the tests see it.
//
// The contract has three halves. Every name the table lists resolves,
// because a name in the set that does not resolve is a load the loader
// refuses with `MissingImport` -- the failure the table exists to prevent.
// Every name resolves to the implementation the base module holds, because
// a forwarder that answers a different function from `ucrtbase` would be
// two runtimes wearing one name. And the set is exactly the set: nothing
// the real module does not export is in it, and the two modules the older
// table carried that Windows does not ship at all are gone.

#include "occ/runtime/api.h"
#include "occ/runtime/exports.h"
#include "occ/runtime/winabi.h"

#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

namespace {

int failures = 0;
int checks = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

// The family-domain list, built the way the forwarder modules build it.
ExportList full_surface() {
    ExportList full;
    add_crt_exports(full);
    add_ucrt_extra(full);
    add_crt_families(full);
    return full;
}

[[nodiscard]] const HostExport* find_in(const ExportList& list,
                                        const char* name) {
    for (const HostExport& entry : list) {
        if (entry.name == name) {
            return &entry;
        }
    }
    return nullptr;
}

void test_every_listed_name_resolves() {
    ExportRegistry reg;
    register_host_modules(reg);
    ExportList full = full_surface();

    int sets_seen = 0;
    for (const ForwardSet* set = kCrtForwarders; set->module != nullptr;
         ++set) {
        ++sets_seen;
        const ExportModule* module = reg.find(set->module);
        check(module != nullptr, set->module);
        if (module == nullptr) {
            continue;
        }
        int listed = 0;
        for (const char* name : set->names) {
            ++listed;
            // The forwarder module carries the name.
            const auto forwarded =
                reg.find_by_name(set->module, name, 0);
            if (forwarded.address == 0) {
                std::fprintf(stderr, "  unlisted resolution: %s : %s\n",
                             set->module, name);
                ++failures;
                ++checks;
                continue;
            }
            ++checks;
            // It is the implementation the base list holds.
            const HostExport* base = find_in(full, name);
            if (base == nullptr) {
                std::fprintf(stderr, "  no base export: %s\n", name);
                ++failures;
                ++checks;
                continue;
            }
            ++checks;
            if (forwarded.address != base->address) {
                std::fprintf(stderr, "  different implementation: %s : %s\n",
                             set->module, name);
                ++failures;
            }
        }
        // The module carries exactly the set: no more, no less.
        check(static_cast<int>(module->host_exports.size()) == listed,
              set->module);
    }
    check(sets_seen == 15, "the table carries the fifteen real families");
}

void test_absent_modules_and_names() {
    ExportRegistry reg;
    register_host_modules(reg);

    // The two modules the older table carried are not modules Windows
    // ships, and a guest that imports one is refused the way the loader
    // refuses any module it cannot find.
    check(reg.find("api-ms-win-crt-stdlib-l1-1-0.dll") == nullptr,
          "the stdlib apiset does not exist on Windows");
    check(reg.find("api-ms-win-crt-ctype-l1-1-0.dll") == nullptr,
          "the ctype apiset does not exist on Windows");

    // The classic names that are header inlines on the UCRT are in no
    // family, and no family exports them.
    for (const char* name : {"printf", "fprintf", "sprintf", "time",
                             "mktime", "localtime", "gmtime", "ctime",
                             "difftime", "strdup", "strnlen_s", "atexit",
                             "putenv", "_snprintf"}) {
        const auto from_string =
            reg.find_by_name("api-ms-win-crt-string-l1-1-0.dll", name, 0);
        check(from_string.address == 0, name);
    }

    // A family's names are absent from the other families: the split is
    // real, and `memcpy` is the private family's to hand out.
    const auto memcpy_from_string =
        reg.find_by_name("api-ms-win-crt-string-l1-1-0.dll", "memcpy", 0);
    check(memcpy_from_string.address == 0,
          "memcpy is not the string family's");
    const auto memcpy_private =
        reg.find_by_name("api-ms-win-crt-private-l1-1-0.dll", "memcpy", 0);
    check(memcpy_private.address != 0, "it is the private family's");

    // A name no family implements -- the complex-math residual -- resolves
    // nowhere.
    const auto complex_math =
        reg.find_by_name("api-ms-win-crt-math-l1-1-0.dll", "cacos", 0);
    check(complex_math.address == 0,
          "the complex math residual resolves nowhere");
}

// The entry points the behavioural checks call, declared the way the
// other API tests declare them: the addresses the registry hands an
// import, callable without a load.
extern "C" __attribute__((ms_abi)) double crf_acos(double) noexcept;
extern "C" __attribute__((ms_abi)) double crf_asin(double) noexcept;
extern "C" __attribute__((ms_abi)) double crf_atan(double) noexcept;
extern "C" __attribute__((ms_abi)) double crf_atan2(double, double) noexcept;
extern "C" __attribute__((ms_abi)) double crf_cbrt(double) noexcept;
extern "C" __attribute__((ms_abi)) double crf_floor(double) noexcept;
extern "C" __attribute__((ms_abi)) double crf_trunc(double) noexcept;
extern "C" __attribute__((ms_abi)) double crf_round(double) noexcept;
extern "C" __attribute__((ms_abi)) double crf_fabs(double) noexcept;
extern "C" __attribute__((ms_abi)) double crf_fmod(double, double) noexcept;
extern "C" __attribute__((ms_abi)) double crf_ldexp(double,
                                                    std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) double crf_frexp(double,
                                                    std::int32_t*) noexcept;
extern "C" __attribute__((ms_abi)) double crf_hypot(double, double) noexcept;
extern "C" __attribute__((ms_abi)) double crf_fmax(double, double) noexcept;
extern "C" __attribute__((ms_abi)) double crf_fmin(double, double) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__finite(double) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__isnan(double) noexcept;
extern "C" __attribute__((ms_abi)) double crf__j0(double) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t crf__rotl(std::uint32_t,
                                                           std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t crf__rotr(std::uint32_t,
                                                           std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint16_t crf__byteswap_ushort(
    std::uint16_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t crf__byteswap_uint64(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t crf_llabs(std::int64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__ftol(double) noexcept;
extern "C" __attribute__((ms_abi)) void* crf__lfind(
    const void*, const void*, std::uint32_t*, std::uint32_t,
    std::int32_t (__attribute__((ms_abi))*)(const void*,
                                            const void*)) noexcept;
extern "C" __attribute__((ms_abi)) void* crf__lsearch(
    const void*, void*, std::uint32_t*, std::uint32_t,
    std::int32_t (__attribute__((ms_abi))*)(const void*,
                                            const void*)) noexcept;
extern "C" __attribute__((ms_abi)) void crf__swab(const char*, char*,
                                                  std::int32_t) noexcept;
struct IMaxDiv {
    std::int64_t quot;
    std::int64_t rem;
};
extern "C" __attribute__((ms_abi)) std::int64_t crf_imaxabs(
    std::int64_t) noexcept;
extern "C" __attribute__((ms_abi)) IMaxDiv crf_imaxdiv(std::int64_t,
                                                       std::int64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__stat64(const char*,
                                                            void*) noexcept;
extern "C" __attribute__((ms_abi)) std::intptr_t crf__findfirst64(
    const char*, void*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__findnext64(
    std::intptr_t, void*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__findclose(
    std::intptr_t) noexcept;
extern "C" __attribute__((ms_abi)) char* crf__fullpath(char*, const char*,
                                                       std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) void crf__splitpath(const char*, char*,
                                                       char*, char*,
                                                       char*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__access(const char*,
                                                            std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__unlink(const char*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr__putenv_s(const char*,
                                                             const char*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf_getenv_s(
    std::uint64_t*, char*, std::uint64_t, const char*) noexcept;
extern "C" __attribute__((ms_abi)) const char16_t* crf__wgetenv(
    const char16_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__wputenv_s(
    const char16_t*, const char16_t*) noexcept;
extern "C" __attribute__((ms_abi)) char* cr_getenv(const char*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__execv(
    const char*, char* const*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__cwait(std::int32_t*,
                                                           std::uint64_t,
                                                           std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) void* cr_malloc(std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) void cr_free(void*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t crf__msize(void*) noexcept;
extern "C" __attribute__((ms_abi)) void* crf__expand(void*,
                                                     std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) void* crf__aligned_offset_malloc(
    std::uint64_t, std::uint64_t, std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) void crf__aligned_offset_free(void*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__heapchk() noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__getmbcp() noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__setmbcp(std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) const char16_t** crf___lc_locale_name_func() noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t crf__get_osfhandle(std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__open_osfhandle(
    std::int64_t, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__getmaxstdio() noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__setmaxstdio(std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) char* crf_tmpnam(char*) noexcept;
extern "C" __attribute__((ms_abi)) char* crf__mktemp(char*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__open(const char*,
                                                          std::int32_t, ...) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__write(std::int32_t,
                                                           const void*,
                                                           std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t crf__lseeki64(std::int32_t,
                                                              std::int64_t,
                                                              std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int64_t crf__filelengthi64(std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__eof(std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__isatty(std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t crf__close(std::int32_t) noexcept;

void test_math_answers() {
    // The family's arithmetic is the host's, and the spot checks are the
    // values the host functions return for arguments whose answers are
    // exact.
    check(crf_acos(1.0) == 0.0, "acos of one is zero");
    check(crf_asin(0.0) == 0.0, "asin of zero is zero");
    check(crf_atan(0.0) == 0.0, "atan of zero is zero");
    check(crf_atan2(0.0, 1.0) == 0.0, "atan2 of the x axis is zero");
    check(crf_cbrt(8.0) == 2.0, "the cube root of eight is two");
    check(crf_floor(2.5) == 2.0, "floor of two and a half is two");
    check(crf_trunc(2.9) == 2.0, "trunc of two point nine is two");
    check(crf_round(2.5) == 3.0, "round of two and a half is three");
    check(crf_fabs(-3.0) == 3.0, "the absolute value of minus three");
    check(crf_fmod(5.0, 3.0) == 2.0, "five modulo three");
    check(crf_ldexp(1.0, 10) == 1024.0, "ldexp builds a power of two");
    int exponent = 0;
    check(crf_frexp(1024.0, &exponent) == 0.5 && exponent == 11,
          "frexp splits a power of two");
    check(crf_hypot(3.0, 4.0) == 5.0, "the three-four-five triangle");
    check(crf_fmax(2.0, 3.0) == 3.0, "fmax answers the larger");
    check(crf_fmin(2.0, 3.0) == 2.0, "fmin answers the smaller");
    check(crf__finite(1.0) == 1 &&
          crf__finite(static_cast<double>(INFINITY)) == 0,
          "_finite answers the obvious");
    check(crf__isnan(static_cast<double>(NAN)) == 1 &&
          crf__isnan(1.0) == 0, "_isnan answers");
    check(crf__j0(0.0) == 1.0, "the Bessel function at the origin");
    check(crf__rotl(0x80000001u, 1) == 0x00000003u, "the rotation wraps");
    check(crf__rotr(0x00000003u, 1) == 0x80000001u, "and back");
    check(crf__byteswap_ushort(0x1234) == 0x3412, "the byte swap");
    check(crf__byteswap_uint64(0x0123456789ABCDEFull) ==
              0xEFCDAB8967452301ull,
          "the sixty-four-bit byte swap");
    check(crf_llabs(-5) == 5, "llabs");
    check(crf__ftol(3.9) == 3, "_ftol truncates");
}

// The compare the linear searches take, in the calling convention the
// family's functions declare -- the guest's, which is not this host's
// default and which a host-ABI function would not satisfy.
extern "C" __attribute__((ms_abi)) std::int32_t int_compare(
    const void* a, const void* b) noexcept {
    return *static_cast<const std::int32_t*>(a) -
           *static_cast<const std::int32_t*>(b);
}

void test_utility_answers() {
    // The linear search finds what is there and says so otherwise. The
    // compare is the guest convention's, which is the convention the
    // family's functions declare.
    std::int32_t values[] = {1, 2, 3, 4};
    std::uint32_t count = 4;
    const std::int32_t key = 3;
    const auto* found = static_cast<const std::int32_t*>(
        crf__lfind(&key, values, &count, sizeof(std::int32_t),
                   &int_compare));
    check(found != nullptr && *found == 3, "_lfind finds the key");

    std::int32_t missing = 9;
    check(crf__lfind(&missing, values, &count, sizeof(std::int32_t),
                     &int_compare) == nullptr,
          "_lfind reports a miss");

    // `_lsearch` appends, which is what makes it the searching store.
    std::int32_t room[5] = {1, 2, 3, 4, 0};
    std::uint32_t room_count = 4;
    crf__lsearch(&missing, room, &room_count, sizeof(std::int32_t),
                 &int_compare);
    check(room_count == 5 && room[4] == 9, "_lsearch appends the key");

    // `_swab` exchanges the byte pairs; the even count leaves no tail.
    char swapped[7] = {};
    crf__swab("abcdef", swapped, 6);
    check(std::memcmp(swapped, "badcfe", 6) == 0, "_swab exchanges pairs");

    check(crf_imaxabs(-7) == 7, "imaxabs");
    const IMaxDiv parts = crf_imaxdiv(-7, 2);
    check(parts.quot == -3 && parts.rem == -1,
          "imaxdiv truncates toward zero");
}

void test_filesystem_answers() {
    // The confined root is the process's own working directory for the
    // test's purposes; a file created through the CRT's own open answers
    // a stat with the fields the layouts state.
    const char* path = "crt_families_test_file.txt";
    std::FILE* file = std::fopen(path, "wb");
    check(file != nullptr, "the test file opens");
    if (file == nullptr) {
        return;
    }
    std::fputs("hello", file);
    std::fclose(file);

    std::uint8_t stat64[56] = {};
    check(crf__stat64(path, stat64) == 0, "_stat64 answers");
    if (stat64[0] != 0) {
        // The mode carries the regular-file bit and the read bit, the
        // link count is one, and the size is the five bytes written.
        const std::uint16_t mode =
            static_cast<std::uint16_t>(stat64[6] | (stat64[7] << 8));
        check((mode & 0x8000) != 0, "_stat64 answers a regular file");
        const std::uint64_t size =
            *reinterpret_cast<const std::uint64_t*>(stat64 + 24);
        check(size == 5, "_stat64 answers the size");
        // The drive is the one the runtime mounts.
        const std::uint32_t dev =
            *reinterpret_cast<const std::uint32_t*>(stat64);
        check(dev == 26, "_stat64 answers the drive letter index");
    }

    // The find family walks the directory the file was created in.
    std::uint8_t finddata[304] = {};
    const std::intptr_t handle = crf__findfirst64("crt_families*", finddata);
    check(handle != -1, "_findfirst64 answers a handle");
    bool seen = false;
    while (handle != -1) {
        const char* name = reinterpret_cast<const char*>(finddata + 40);
        if (std::strcmp(name, "crt_families_test_file.txt") == 0) {
            seen = true;
            const std::uint32_t size = *reinterpret_cast<const std::uint32_t*>(
                finddata + 32);
            check(size == 5, "the walk reports the size");
            break;
        }
        if (crf__findnext64(handle, finddata) != 0) {
            break;
        }
    }
    check(seen, "the walk finds the file");
    if (handle != -1) {
        check(crf__findclose(handle) == 0, "_findclose releases the walk");
    }

    // The full path is lexical, and the drive is the guest's.
    char* absolute = crf__fullpath(nullptr, path, 0);
    check(absolute != nullptr, "_fullpath answers");
    if (absolute != nullptr) {
        check(absolute[0] == 'Z' && absolute[1] == ':',
              "_fullpath answers a drive-rooted path");
        check(std::strstr(absolute, "crt_families_test_file.txt") != nullptr,
              "_fullpath keeps the name");
        cr_free(absolute);
    }

    // The path split and join round-trip.
    char drive[3] = {};
    char dir[256] = {};
    char name[256] = {};
    char ext[256] = {};
    crf__splitpath("C:\\dir\\file.txt", drive, dir, name, ext);
    check(std::strcmp(drive, "C:") == 0, "the drive splits");
    check(std::strcmp(dir, "\\dir\\") == 0, "the directory splits");
    check(std::strcmp(name, "file") == 0, "the name splits");
    check(std::strcmp(ext, ".txt") == 0, "the extension splits");

    // The access and remove pair, through the confined calls.
    check(crf__access(path, 0) == 0, "_access answers existence");
    check(crf__unlink(path) == 0, "_unlink removes");
    check(crf__access(path, 0) != 0, "and it is gone");
}

void test_environment_and_process_answers() {
    // The putenv/getenv pair the family spellings share.
    check(cr__putenv_s("CRT_FAMILIES_TEST", "42") == 0, "_putenv_s sets");
    char* value = cr_getenv("CRT_FAMILIES_TEST");
    check(value != nullptr && std::strcmp(value, "42") == 0, "getenv reads");

    std::uint64_t needed = 0;
    char buffer[8] = {};
    check(crf_getenv_s(&needed, buffer, sizeof(buffer),
                       "CRT_FAMILIES_TEST") == 0 &&
              std::strcmp(buffer, "42") == 0,
          "getenv_s copies");
    check(crf_getenv_s(&needed, buffer, 2, "CRT_FAMILIES_TEST") == ERANGE,
          "getenv_s reports the small buffer");

    // The wide spelling reads the same table.
    const char16_t* wide = crf__wgetenv(u"CRT_FAMILIES_TEST");
    check(wide != nullptr && std::char_traits<char16_t>::length(wide) == 2,
          "_wgetenv reads the same table");
    check(crf__wputenv_s(u"CRT_FAMILIES_TEST", u"") == 0,
          "_wputenv_s clears");

    // The process family refuses the way CreateProcess refuses.
    char* arguments[] = {nullptr};
    check(crf__execv("anything.exe", arguments) == -1, "_execv refuses");
    check(errno == EINVAL, "with the mapped errno");
    check(crf__cwait(nullptr, 0, 0) == -1 && errno == ECHILD,
          "_cwait answers the childless wait");
}

void test_heap_and_locale_answers() {
    // The block header's size is what `_msize` answers with.
    void* block = cr_malloc(100);
    check(block != nullptr, "the heap allocates");
    if (block != nullptr) {
        check(crf__msize(block) == 100, "_msize answers the asked size");
        // `_expand` answers in place for a request the block can hold.
        check(crf__expand(block, 50) == block, "_expand keeps the block");
        cr_free(block);
    }

    // The aligned offset family, whose back-pointer the free reads.
    void* aligned = crf__aligned_offset_malloc(64, 64, 0);
    check(aligned != nullptr, "_aligned_offset_malloc answers");
    if (aligned != nullptr) {
        check(reinterpret_cast<std::uintptr_t>(aligned) % 64 == 0,
              "the block is aligned");
        crf__aligned_offset_free(aligned);
    }

    check(crf__heapchk() == -2, "_heapchk answers _HEAPOK");

    // The multi-byte code page state.
    check(crf__getmbcp() == 0, "the page starts at the ANSI one");
    check(crf__setmbcp(2) == 0, "_setmbcp answers the previous");
    check(crf__getmbcp() == 2, "and the page is recorded");
    crf__setmbcp(0);

    // The locale name is the C locale's.
    const char16_t** name = crf___lc_locale_name_func();
    check(name != nullptr && *name != nullptr && (*name)[0] == u'C',
          "the locale is the C locale");
}

void test_stdio_answers() {
    // The descriptor family, which the handle bridge pairs with.
    const std::int64_t stdout_handle = crf__get_osfhandle(1);
    check(stdout_handle == 0x2001, "_get_osfhandle maps stdout");
    const std::int32_t back = crf__open_osfhandle(stdout_handle, 0);
    check(back == 1, "_open_osfhandle reads it back");
    check(crf__get_osfhandle(99) == -1, "an unknown descriptor fails");

    // The stream limit, which the setter bounds.
    check(crf__getmaxstdio() == 512, "the limit starts at the default");
    check(crf__setmaxstdio(1024) == 512, "_setmaxstdio answers the old");
    check(crf__setmaxstdio(10) == -1, "and refuses an unbounded ask");
    crf__setmaxstdio(512);

    // The temporary names, which a guest can hand straight to fopen.
    char* temporary = crf_tmpnam(nullptr);
    check(temporary != nullptr && temporary[0] != '\0', "tmpnam answers");

    // The unique-name template, which fills its trailing X run.
    char pattern[64];
    std::memset(pattern, 0, sizeof(pattern));
    std::memcpy(pattern, "crt_tmp_XXXXXX", 15);
    check(crf__mktemp(pattern) != nullptr, "_mktemp answers");
    if (pattern[0] != '\0') {
        check(std::strncmp(pattern, "crt_tmp_", 8) == 0,
              "the base survives");
        check(std::strchr(pattern, 'X') == nullptr, "the X run is filled");
    }
}

void test_descriptor_family_answers() {
    // The low-level family over the confined open.
    const char* path = "crt_families_fd_test.txt";
    const std::int32_t fd = crf__open(path, 0x0001 | 0x0100 | 0x0200, 0600);
    check(fd >= 0, "_open issues a descriptor");
    if (fd < 0) {
        return;
    }
    check(crt_fd_is_valid(fd), "the descriptor is in the ledger");
    const std::int32_t written = crf__write(fd, "hello", 5);
    check(written == 5, "_write writes");
    check(crf__lseeki64(fd, 0, 0) == 0, "_lseeki64 repositions");
    check(crf__filelengthi64(fd) == 5, "_filelengthi64 answers the size");
    check(crf__eof(fd) == 0, "the descriptor is not at its end");
    check(crf__isatty(fd) == 0, "a file is not a terminal");
    check(crf__close(fd) == 0, "_close releases");
    check(!crt_fd_is_valid(fd), "and the ledger forgets it");
    std::remove(path);
}

}  // namespace

int main() {
    test_every_listed_name_resolves();
    test_absent_modules_and_names();
    test_math_answers();
    test_utility_answers();
    test_filesystem_answers();
    test_environment_and_process_answers();
    test_heap_and_locale_answers();
    test_stdio_answers();
    test_descriptor_family_answers();
    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

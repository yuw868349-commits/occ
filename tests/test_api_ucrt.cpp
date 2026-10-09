// The Universal CRT surface, as the tests see it.
//
// The contract has two halves. The secure functions answer the way the
// CRT documents them: the bounded copy either succeeds or fails with the
// destination zeroed, and the answer says which. The forwarder stubs
// answer the way following a forwarder answers: the names each
// `api-ms-win-crt-*` module carries are the names that module's real
// counterpart exports, resolved to the same implementations ucrtbase
// holds.

#include "occ/runtime/api.h"
#include "occ/runtime/exports.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

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

extern "C" __attribute__((ms_abi)) std::int32_t u32u_strcpy_s(
    char*, std::size_t, const char*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32u_strcat_s(
    char*, std::size_t, const char*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32u_memcpy_s(
    void*, std::size_t, const void*, std::size_t) noexcept;
extern "C" __attribute__((ms_abi)) std::size_t u32u_strnlen_s(
    const char*, std::size_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32u_sprintf_s(
    char*, std::size_t, const char*, ...) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32u_snprintf_s(
    char*, std::size_t, std::size_t, const char*, ...) noexcept;
extern "C" __attribute__((ms_abi)) void u32u_qsort(
    void*, std::size_t, std::size_t,
    std::int32_t(__attribute__((ms_abi))*)(const void*, const void*)) noexcept;
extern "C" __attribute__((ms_abi)) void* u32u_bsearch(
    const void*, const void*, std::size_t, std::size_t,
    std::int32_t(__attribute__((ms_abi))*)(const void*, const void*)) noexcept;
extern "C" __attribute__((ms_abi)) void* u32u__aligned_malloc(
    std::size_t, std::size_t) noexcept;
extern "C" __attribute__((ms_abi)) void u32u__aligned_free(void*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t u32u__create_locale(
    std::int32_t, const char*) noexcept;
extern "C" __attribute__((ms_abi)) void u32u__free_locale(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) char* u32u_setlocale(
    std::int32_t, const char*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32u__itoa_s(
    std::int32_t, char*, std::size_t, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32u__i64toa_s(
    std::int64_t, char*, std::size_t, std::int32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32u__kbhit() noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32u_system(
    const char*) noexcept;
using CrtHandler = void(__attribute__((ms_abi))*)(const char16_t*,
                                                  const char16_t*,
                                                  const char16_t*,
                                                  unsigned int,
                                                  std::uintptr_t);
extern "C" __attribute__((ms_abi)) CrtHandler
u32u__set_invalid_parameter_handler(CrtHandler) noexcept;

void test_secure_strings() {
    char buf[16] = {};

    // A copy that fits succeeds, and the bytes are the source's.
    check(u32u_strcpy_s(buf, sizeof(buf), "hello") == 0,
          "ucrt: a copy that fits succeeds");
    check(std::strcmp(buf, "hello") == 0, "ucrt: the bytes are the source's");

    // A copy that does not fit fails, and the destination is zeroed --
    // which is the whole point of the secure form.
    check(u32u_strcpy_s(buf, 4, "hello") != 0,
          "ucrt: a copy that does not fit fails");
    check(buf[0] == '\0', "ucrt: the destination is zeroed on failure");

    // The concatenation counts what is already there.
    std::memset(buf, 0, sizeof(buf));
    check(u32u_strcat_s(buf, sizeof(buf), "ab") == 0,
          "ucrt: the concatenation succeeds");
    check(u32u_strcat_s(buf, sizeof(buf), "cd") == 0,
          "ucrt: the second concatenation succeeds");
    check(std::strcmp(buf, "abcd") == 0, "ucrt: the result is both parts");
    check(u32u_strcat_s(buf, 6, "xyz") != 0,
          "ucrt: a concatenation past the buffer fails");
    check(buf[0] == '\0', "ucrt: and the destination is zeroed");

    // The bounded memory copy, both ways.
    char dst[8] = {};
    const char src[] = "12345";
    check(u32u_memcpy_s(dst, sizeof(dst), src, 6) == 0,
          "ucrt: memcpy_s copies what fits");
    check(std::strcmp(dst, "12345") == 0, "ucrt: the bytes arrive");
    check(u32u_memcpy_s(dst, 4, src, 6) != 0,
          "ucrt: memcpy_s refuses an overflow");
    check(dst[0] == '\0', "ucrt: and zeroes the destination");

    // The bounded length never runs past its limit.
    check(u32u_strnlen_s("abcdef", 3) == 3,
          "ucrt: strnlen_s stops at its bound");
    check(u32u_strnlen_s("abc", 100) == 3,
          "ucrt: strnlen_s stops at the terminator");
    check(u32u_strnlen_s(nullptr, 100) == 0,
          "ucrt: a null string is zero characters");
}

void test_formatted_output() {
    char buf[64] = {};

    // The secure formatter renders what the format says.
    check(u32u_sprintf_s(buf, sizeof(buf), "%d-%s", 42, "x") == 4,
          "ucrt: sprintf_s answers the length");
    check(std::strcmp(buf, "42-x") == 0, "ucrt: the rendering is right");

    // The bounded form stops at the count and still terminates.
    std::memset(buf, 0, sizeof(buf));
    check(u32u_snprintf_s(buf, sizeof(buf), 4, "%s", "abcdefg") >= 0,
          "ucrt: snprintf_s answers");
    check(std::strlen(buf) <= 3, "ucrt: the bounded rendering is bounded");
    check(buf[std::strlen(buf)] == '\0', "ucrt: and terminated");
}

// The comparison the sort uses: the caller's own, which is the point of
// the family -- a library cannot know the shape of what it orders.
std::int32_t __attribute__((ms_abi)) compare_ints(const void* a,
                                                const void* b) {
    const auto x = *static_cast<const std::int32_t*>(a);
    const auto y = *static_cast<const std::int32_t*>(b);
    return x < y ? -1 : (x > y ? 1 : 0);
}

void test_sort_and_search() {
    std::int32_t values[6] = {5, 2, 9, 1, 7, 3};
    u32u_qsort(values, 6, sizeof(std::int32_t), &compare_ints);
    bool ordered = true;
    for (int i = 1; i < 6; ++i) {
        if (values[i - 1] > values[i]) {
            ordered = false;
        }
    }
    check(ordered, "ucrt: qsort orders through the caller's comparison");
    check(values[0] == 1 && values[5] == 9, "ucrt: the ends are the ends");

    // The search finds what the sort put there.
    const std::int32_t key = 7;
    const void* found =
        u32u_bsearch(&key, values, 6, sizeof(std::int32_t), &compare_ints);
    check(found != nullptr, "ucrt: bsearch finds a present key");
    check(*static_cast<const std::int32_t*>(found) == 7,
          "ucrt: the answer is the key");
    const std::int32_t missing = 4;
    check(u32u_bsearch(&missing, values, 6, sizeof(std::int32_t),
                       &compare_ints) == nullptr,
          "ucrt: bsearch reports an absent key");
}

// The handler the test installs: it records the call and returns, which
// is the path that lets a failing secure call continue to its answer.
int invalid_calls = 0;

void __attribute__((ms_abi)) invalid_handler(const char16_t*,
                                            const char16_t*,
                                            const char16_t*, unsigned int,
                                            std::uintptr_t) {
    ++invalid_calls;
}

void test_aligned_heap() {
    void* p = u32u__aligned_malloc(64, 64);
    check(p != nullptr, "ucrt: the aligned allocation succeeds");
    if (p != nullptr) {
        check((reinterpret_cast<std::uintptr_t>(p) % 64) == 0,
              "ucrt: the block is aligned as asked");
        std::memset(p, 0xAB, 64);
        u32u__aligned_free(p);
    }
    // A misaligned request is refused rather than answered with a wrong
    // alignment: the contract says the alignment is a power of two, and
    // the invalid-parameter path is what reports it.
    const auto old =
        u32u__set_invalid_parameter_handler(&invalid_handler);
    check(u32u__aligned_malloc(16, 3) == nullptr,
          "ucrt: a non-power-of-two alignment is refused");
    check(invalid_calls == 1,
          "ucrt: the invalid parameter reached the handler");
    u32u__set_invalid_parameter_handler(old);
}

void test_locale_and_conversions() {
    // The locale the runtime implements is the C one, and the name it
    // answers with is what the C library answers.
    char* name = u32u_setlocale(0, "C");
    check(name != nullptr && std::strcmp(name, "C") == 0,
          "ucrt: setlocale answers the C locale");

    // The locale object is real: it is created, it is freed, and the two
    // are the pair the family promises.
    const std::uint64_t loc = u32u__create_locale(0, "en-US");
    check(loc != 0, "ucrt: the locale object is created");
    u32u__free_locale(loc);

    // The integer conversions render into the caller's buffer.
    char buf[32] = {};
    check(u32u__itoa_s(-1234, buf, sizeof(buf), 10) == 0,
          "ucrt: _itoa_s succeeds");
    check(std::strcmp(buf, "-1234") == 0, "ucrt: the digits are right");
    std::memset(buf, 0, sizeof(buf));
    check(u32u__i64toa_s(9000000000LL, buf, sizeof(buf), 10) == 0,
          "ucrt: _i64toa_s succeeds");
    check(std::strcmp(buf, "9000000000") == 0,
          "ucrt: the wide digits are right");
}

void test_console_and_process() {
    // The console a headless run has reports no key waiting, which is
    // what the call answers.
    check(u32u__kbhit() == 0, "ucrt: no key is waiting");

    // The command processor check: a null command answers the presence
    // question, which is what the call documents.
    check(u32u_system(nullptr) != 0,
          "ucrt: a null command answers the presence of a processor");
}

void test_forwarder_modules() {
    ExportRegistry reg;
    register_host_modules(reg);
    check(reg.size() >= 50, "ucrt: the module table is populated");

    // Each forwarder stub carries its family's names, and the names
    // resolve to the same implementations the base module holds.
    const ExportModule* strings =
        reg.find("api-ms-win-crt-string-l1-1-0.dll");
    check(strings != nullptr, "ucrt: the string forwarder is registered");
    if (strings != nullptr) {
        check(strings->host_exports.size() > 30,
              "ucrt: the string forwarder carries its family");
        const auto resolved = reg.find_by_name(
            "api-ms-win-crt-string-l1-1-0.dll", "strcpy_s", 0);
        check(resolved.address != 0, "ucrt: a forwarded name resolves");
        const auto base = reg.find_by_name("ucrtbase.dll", "strcpy_s", 0);
        check(resolved.address == base.address,
              "ucrt: the forwarded name is the same implementation");
    }

    const ExportModule* stdio =
        reg.find("api-ms-win-crt-stdio-l1-1-0.dll");
    check(stdio != nullptr, "ucrt: the stdio forwarder is registered");
    if (stdio != nullptr) {
        const auto common = reg.find_by_name(
            "api-ms-win-crt-stdio-l1-1-0.dll", "__stdio_common_vfprintf", 0);
        check(common.address != 0,
              "ucrt: the modern stdio entry point resolves");
    }

    // A name outside a family is absent from it, which is the answer a
    // guest that asks the wrong module gets.
    const auto wrong = reg.find_by_name(
        "api-ms-win-crt-string-l1-1-0.dll", "malloc", 0);
    check(wrong.address == 0,
          "ucrt: a name outside the family is absent");
    check(reg.find_by_name("api-ms-win-crt-heap-l1-1-0.dll", "malloc", 0)
                  .address != 0,
          "ucrt: and it is present in the family that owns it");
}

void test_registry() {
    ExportList list;
    add_ucrt_extra(list);
    bool ok = true;
    for (const HostExport& e : list) {
        if (e.name.empty() || e.address == 0) {
            ok = false;
        }
    }
    check(ok, "ucrt: every entry has a name and an address");
    check(list.size() >= 40, "ucrt: the modern surface registers");
}

}  // namespace

int main() {
    test_registry();
    test_secure_strings();
    test_formatted_output();
    test_sort_and_search();
    test_aligned_heap();
    test_locale_and_conversions();
    test_console_and_process();
    test_forwarder_modules();
    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

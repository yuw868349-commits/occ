// The process/thread/environment domain's own tests.
//
// Every expectation below comes from a reference rather than a preference:
//
//   * `ExpandEnvironmentStrings`' return conventions (the terminator
//     counted in the answer, the A form's one-byte over-report on a short
//     buffer, undefined variables copied through verbatim, no rescan of
//     replacement text) are the ones Wine's conformance tests pin in
//     `dlls/kernel32/tests/environ.c`.
//   * The structure offsets and sizes are the Windows x64 layouts as
//     mingw-w64's headers spell them.
//   * The error codes for the toolhelp walks (INSUFFICIENT_BUFFER for a
//     short `dwSize`, NO_MORE_FILES at the end) and the shutdown-parameter
//     defaults (0x280, 0) are Wine's `toolhelp.c` / `process.c`.
//
// The tests run without an installed guest state, so the identities the
// TEB would carry fall back to the host process's own -- the domain states
// that rule, and these tests exercise it.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <sched.h>
#include <unistd.h>

namespace occ::runtime::winabi {

void add_kernel32_proc(ExportList& out);

// The entry points the tests reach directly. The signatures are the
// entries'; declaring them here keeps the tests calling what a guest calls
// without going through a load.
extern "C" __attribute__((ms_abi)) std::uint32_t
k32p_ExpandEnvironmentStringsW(const char16_t* source, char16_t* buffer,
                               std::uint32_t count) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
k32p_ExpandEnvironmentStringsA(const char* source, char* buffer,
                               std::uint32_t count) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32p_GetSystemDirectoryW(
    char16_t* buffer, std::uint32_t count) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32p_GetSystemDirectoryA(
    char* buffer, std::uint32_t count) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32p_GetWindowsDirectoryW(
    char16_t* buffer, std::uint32_t count) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32p_GetWindowsDirectoryA(
    char* buffer, std::uint32_t count) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_GetComputerNameW(
    char16_t* buffer, std::uint32_t* size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_GetComputerNameA(
    char* buffer, std::uint32_t* size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_GetComputerNameExW(
    std::uint32_t format, char16_t* buffer, std::uint32_t* size) noexcept;
extern "C" __attribute__((ms_abi)) void k32p_GetSystemInfo(void* out) noexcept;
extern "C" __attribute__((ms_abi)) void k32p_GetNativeSystemInfo(
    void* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_IsProcessorFeaturePresent(
    std::uint32_t feature) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32p_GetCurrentProcessorNumber() noexcept;
extern "C" __attribute__((ms_abi)) void k32p_GetCurrentProcessorNumberEx(
    void* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_FlushInstructionCache(
    std::uint64_t handle, const void* base, std::uint64_t size) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32p_OpenProcess(
    std::uint32_t access, std::int32_t inherit, std::uint32_t pid) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32p_GetProcessId(
    std::uint64_t handle) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32p_GetProcessVersion(
    std::uint32_t pid) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_GetExitCodeProcess(
    std::uint64_t handle, std::uint32_t* code) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32p_OpenThread(
    std::uint32_t access, std::int32_t inherit, std::uint32_t tid) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_GetExitCodeThread(
    std::uint64_t handle, std::uint32_t* code) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32p_GetPriorityClass(
    std::uint64_t handle) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_SetPriorityClass(
    std::uint64_t handle, std::uint32_t priority) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_GetProcessShutdownParameters(
    std::uint32_t* level, std::uint32_t* flags) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_SetProcessShutdownParameters(
    std::uint32_t level, std::uint32_t flags) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_GetProcessWorkingSetSize(
    std::uint64_t handle, std::uint64_t* minimum,
    std::uint64_t* maximum) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_SetProcessWorkingSetSize(
    std::uint64_t handle, std::uint64_t minimum, std::uint64_t maximum) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_ProcessIdToSessionId(
    std::uint32_t pid, std::uint32_t* session) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32p_CreateToolhelp32Snapshot(
    std::uint32_t flags, std::uint32_t pid) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_Process32FirstW(
    std::uint64_t handle, void* entry) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_Process32NextW(
    std::uint64_t handle, void* entry) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_Process32FirstA(
    std::uint64_t handle, void* entry) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_Process32NextA(
    std::uint64_t handle, void* entry) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_Thread32First(
    std::uint64_t handle, void* entry) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_Thread32Next(
    std::uint64_t handle, void* entry) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_Module32FirstW(
    std::uint64_t handle, void* entry) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_Heap32ListFirst(
    std::uint64_t handle, void* entry) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_Heap32ListNext(
    std::uint64_t handle, void* entry) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_Heap32First(
    void* entry, std::uint32_t pid, std::uint64_t heap_id) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_Toolhelp32ReadProcessMemory(
    std::uint32_t pid, const void* base, void* buffer, std::uint64_t size,
    std::uint64_t* read) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32p_SuspendThread(
    std::uint64_t handle) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32p_CreateThread(
    void* attributes, std::uint64_t stack_size, std::uint64_t start,
    void* parameter, std::uint32_t flags, std::uint32_t* thread_id) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32p_CreateProcessW(
    const char16_t* application, char16_t* command_line,
    void* process_attributes, void* thread_attributes,
    std::int32_t inherit_handles, std::uint32_t flags, void* environment,
    const char16_t* current_directory, const void* startup_info,
    void* process_information) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32p_CreateThreadpool(
    void* reserved) noexcept;

}  // namespace occ::runtime::winabi

using namespace occ::runtime;
using namespace occ::runtime::winabi;
using occ::runtime::HostExport;

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

// One comparison for both the DWORD-answering and BOOL-answering entry
// points; the cast is internal so the call sites stay free of conversion
// noise.
template <typename T, typename U>
void check_eq(T got, U want, const char* what) {
    ++checks;
    const auto g = static_cast<unsigned long long>(got);
    const auto w = static_cast<unsigned long long>(want);
    if (g != w) {
        ++failures;
        std::fprintf(stderr, "FAIL %s: got %llu want %llu\n", what, g, w);
    }
}

// The error codes the assertions name, spelled as `winerror.h` does.
constexpr std::uint32_t kErrorInsufficientBuffer = 122;
constexpr std::uint32_t kErrorNoMoreFiles = 18;
constexpr std::uint32_t kErrorBufferOverflow = 111;
constexpr std::uint32_t kErrorMoreData = 234;
constexpr std::uint32_t kErrorInvalidHandle = 6;
constexpr std::uint32_t kErrorInvalidParameter = 87;
constexpr std::uint32_t kErrorAccessDenied = 5;
constexpr std::uint32_t kErrorCallNotImplemented = 120;

constexpr std::uint64_t kCurrentProcessPseudo = 0xFFFFFFFFFFFFFFFFULL;
constexpr std::uint64_t kCurrentThreadPseudo = 0xFFFFFFFFFFFFFFFEULL;

// The x64 structure sizes the Windows headers give.
constexpr std::size_t kProcessEntryBytesW = 568;
constexpr std::size_t kProcessEntryBytesA = 304;
constexpr std::size_t kThreadEntryBytes = 28;
constexpr std::size_t kHeapListBytes = 32;
constexpr std::size_t kHeapEntryBytes = 56;
constexpr std::size_t kSystemInfoBytes = 48;
constexpr std::size_t kProcessEntryExeOffset = 44;

std::string wide_to_narrow(const char16_t* text) {
    std::string out;
    for (std::size_t i = 0; text[i] != u'\0'; ++i) {
        out.push_back(static_cast<char>(text[i]));
    }
    return out;
}

// ----------------------------------------------------------- registration

void test_registration() {
    ExportList list;
    add_kernel32_proc(list);
    check_eq(list.size(), 60, "api: the domain registers 60 names");
    static const char* const names[] = {
        "CreateProcessA", "CreateProcessAsUserA", "CreateProcessAsUserW",
        "CreateProcessInternalA", "CreateProcessInternalW", "CreateProcessW",
        "CreateThread", "CreateThreadpool", "CreateThreadpoolCleanupGroup",
        "CreateThreadpoolIo", "CreateThreadpoolWork",
        "CreateToolhelp32Snapshot", "ExitThread",
        "ExpandEnvironmentStringsA", "ExpandEnvironmentStringsW",
        "FlushInstructionCache", "GetComputerNameA", "GetComputerNameExA",
        "GetComputerNameExW", "GetComputerNameW", "GetCurrentProcessorNumber",
        "GetCurrentProcessorNumberEx", "GetExitCodeProcess",
        "GetExitCodeThread", "GetNativeSystemInfo", "GetPriorityClass",
        "GetProcessId", "GetProcessShutdownParameters", "GetProcessVersion",
        "GetProcessWorkingSetSize", "GetSystemDirectoryA",
        "GetSystemDirectoryW", "GetSystemInfo", "GetWindowsDirectoryA",
        "GetWindowsDirectoryW", "Heap32First", "Heap32ListFirst",
        "Heap32ListNext", "Heap32Next", "IsProcessorFeaturePresent",
        "Module32First", "Module32FirstW", "Module32Next", "Module32NextW",
        "OpenProcess", "OpenThread", "Process32First", "Process32FirstW",
        "Process32Next", "Process32NextW", "ProcessIdToSessionId",
        "ResumeThread", "SetPriorityClass", "SetProcessShutdownParameters",
        "SetProcessWorkingSetSize", "SuspendThread", "TerminateThread",
        "Thread32First", "Thread32Next", "Toolhelp32ReadProcessMemory",
    };
    for (const char* name : names) {
        bool found = false;
        for (const HostExport& entry : list) {
            if (entry.name == name && entry.address != 0) {
                found = true;
                break;
            }
        }
        check(found, name);
    }
    bool no_duplicates = true;
    for (std::size_t i = 0; i < list.size(); ++i) {
        for (std::size_t k = i + 1; k < list.size(); ++k) {
            std::string a;
            std::string b;
            for (const char c : list[i].name) {
                a.push_back(static_cast<char>(
                    c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c));
            }
            for (const char c : list[k].name) {
                b.push_back(static_cast<char>(
                    c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c));
            }
            if (a == b) {
                no_duplicates = false;
            }
        }
    }
    check(no_duplicates, "api: no two exports share a name");
}

// ------------------------------------------------- environment expansion

void test_expand_environment_strings_w() {
    ::setenv("K32P_TVARIABLE", "WINE", 1);
    char16_t buffer[256] = {};

    // Wine's test: a fitting buffer answers the size *with* the terminator
    // and stores the text.
    const char16_t* source = u"%K32P_TVARIABLE% long long";
    const std::uint32_t ret =
        k32p_ExpandEnvironmentStringsW(source, buffer, 256);
    check_eq(ret, 15, "expand W: fitting buffer returns len+1");
    check(wide_to_narrow(buffer) == "WINE long long",
          "expand W: the variable is replaced");

    // A null buffer answers the size it needs and writes nothing.
    std::memset(buffer, 0x7A, sizeof(buffer));
    check_eq(k32p_ExpandEnvironmentStringsW(source, nullptr, 0), 15,
             "expand W: null buffer answers the needed size");

    // A short buffer answers the needed size and leaves the buffer alone.
    check_eq(k32p_ExpandEnvironmentStringsW(source, buffer, 5), 15,
             "expand W: short buffer answers the needed size");
    bool untouched = true;
    for (char16_t unit : buffer) {
        if (unit != 0x7A7A) {
            untouched = false;
        }
    }
    check(untouched, "expand W: short buffer is not written");

    // An exact fit stores the text and its terminator.
    check_eq(k32p_ExpandEnvironmentStringsW(source, buffer, 15), 15,
             "expand W: exact fit answers the needed size");
    check(wide_to_narrow(buffer) == "WINE long long",
          "expand W: exact fit stores the text");

    // An undefined variable is copied through, percent signs and all
    // (Wine's test 34-42 spell this out).
    const std::uint32_t undef = k32p_ExpandEnvironmentStringsW(
        u"%K32P_NO_SUCH_VAR_XYZ% ok", buffer, 256);
    check_eq(undef, 26, "expand W: undefined variable counts verbatim");
    check(wide_to_narrow(buffer) == "%K32P_NO_SUCH_VAR_XYZ% ok",
          "expand W: undefined variable is copied through");

    // An empty name is no variable at all.
    check_eq(k32p_ExpandEnvironmentStringsW(u"%%", buffer, 256), 3,
             "expand W: an empty name is literal");
    check(wide_to_narrow(buffer) == "%%", "expand W: %% stays %%");

    // A percent with no closing partner is literal.
    check_eq(k32p_ExpandEnvironmentStringsW(u"abc%def", buffer, 256), 8,
             "expand W: an unclosed percent is literal");
    check(wide_to_narrow(buffer) == "abc%def",
          "expand W: the unclosed text is copied");

    // Replacement text is not rescanned: one pass, like Wine's "Foo%VAR%"
    // indirect test.
    ::setenv("K32P_INDIRECT", "Foo%K32P_TVARIABLE%Bar", 1);
    check_eq(
        k32p_ExpandEnvironmentStringsW(u"-%K32P_INDIRECT%-", buffer, 256), 25,
        "expand W: indirect value counts without rescan");
    check(wide_to_narrow(buffer) == "-Foo%K32P_TVARIABLE%Bar-",
          "expand W: the replacement is not re-expanded");

    // A null source is refused, not crashed on.
    check_eq(k32p_ExpandEnvironmentStringsW(nullptr, buffer, 256), 0,
             "expand W: a null source answers zero");
    check_eq(winabi::k32_GetLastError(), kErrorInvalidParameter,
             "expand W: a null source sets ERROR_INVALID_PARAMETER");
}

void test_expand_environment_strings_a() {
    ::setenv("K32P_TVARIABLE", "WINE", 1);
    char buffer[256] = {};

    // Fitting: the answer is the length with the terminator (Wine's test:
    // 16 for "WINE long long").
    const std::uint32_t ret = k32p_ExpandEnvironmentStringsA(
        "%K32P_TVARIABLE% long long", buffer, sizeof(buffer));
    check_eq(ret, 15, "expand A: fitting buffer returns len+1");
    check(std::string(buffer) == "WINE long long",
          "expand A: the variable is replaced");

    // Short: the A form over-reports by one byte over the W form's answer,
    // which is what modern Windows does and Wine's tests pin.
    std::memset(buffer, 0x7A, sizeof(buffer));
    check_eq(k32p_ExpandEnvironmentStringsA("%K32P_TVARIABLE% long long",
                                            buffer, 5),
             16, "expand A: short buffer over-reports by one");
    check(buffer[0] == '\x7A', "expand A: short buffer is not written");

    // An exact fit is still the short-buffer path for the A form.
    check_eq(k32p_ExpandEnvironmentStringsA("%K32P_TVARIABLE% long long",
                                            buffer, 15),
             16, "expand A: exact fit takes the over-reported answer");

    // A and W agree on the text for the same input. The A buffer is
    // refilled here because the two A calls before it take the short path
    // and deliberately write nothing.
    std::memset(buffer, 0, sizeof(buffer));
    k32p_ExpandEnvironmentStringsA("%K32P_TVARIABLE% long long", buffer,
                                   sizeof(buffer));
    char16_t wide[256] = {};
    k32p_ExpandEnvironmentStringsW(u"%K32P_TVARIABLE% long long", wide, 256);
    check(std::string(buffer) == wide_to_narrow(wide),
          "expand: A and W agree on the same input");
}

// ------------------------------------------------------ system directories

void test_system_directories() {
    char16_t wide[300] = {};
    char narrow[300] = {};

    check_eq(k32p_GetSystemDirectoryW(wide, 300), 19,
             "system dir W: answers the length without the terminator");
    check(wide_to_narrow(wide) == "C:\\Windows\\System32",
          "system dir W: answers the canonical path");
    check_eq(k32p_GetSystemDirectoryA(narrow, 300), 19,
             "system dir A: answers the same length");
    check(std::string(narrow) == "C:\\Windows\\System32",
          "system dir A: answers the same path");

    // A short buffer answers the size needed, terminator included, and
    // writes nothing.
    std::memset(wide, 0x7A, sizeof(wide));
    check_eq(k32p_GetSystemDirectoryW(wide, 5), 20,
             "system dir W: short buffer answers the needed size");
    check(static_cast<char16_t>(wide[0]) == 0x7A7A,
          "system dir W: short buffer is not written");

    check_eq(k32p_GetWindowsDirectoryW(wide, 300), 10,
             "windows dir W: answers the length without the terminator");
    check(wide_to_narrow(wide) == "C:\\Windows",
          "windows dir W: answers the canonical path");
    check_eq(k32p_GetWindowsDirectoryA(narrow, 300), 10,
             "windows dir A: answers the same length");
    check(std::string(narrow) == "C:\\Windows",
          "windows dir A: answers the same path");
}

// ----------------------------------------------------------- computer name

void test_computer_name() {
    char host[256] = {};
    check(::gethostname(host, sizeof(host)) == 0, "hostname: readable");
    std::string name(host);
    if (name.size() > 15) {
        name.resize(15);
    }

    char16_t wide[64] = {};
    char narrow[64] = {};

    // The overflow path: FALSE, ERROR_BUFFER_OVERFLOW, and the size set to
    // the length without the terminator (the caller adds one).
    std::uint32_t size = 0;
    check_eq(k32p_GetComputerNameW(wide, &size), 0,
             "name W: a zero buffer fails");
    check_eq(winabi::k32_GetLastError(), kErrorBufferOverflow,
             "name W: overflow names ERROR_BUFFER_OVERFLOW");
    check_eq(size, name.size(),
             "name W: overflow answers the length without terminator");

    // The fitting path: TRUE, the size answered without the terminator.
    size = static_cast<std::uint32_t>(name.size()) + 1;
    check_eq(k32p_GetComputerNameW(wide, &size), 1,
             "name W: a fitting buffer succeeds");
    check_eq(size, name.size(),
             "name W: success answers the length without terminator");
    check(wide_to_narrow(wide) == name,
          "name W: the host's name, truncated to 15");

    size = 64;
    check_eq(k32p_GetComputerNameA(narrow, &size), 1, "name A: succeeds");
    check_eq(size, name.size(), "name A: answers the same length");
    check(std::string(narrow) == name, "name A: answers the same name");

    // The Ex form: overflow names ERROR_MORE_DATA there, and the size
    // includes the terminator.
    size = 0;
    check_eq(k32p_GetComputerNameExW(0, wide, &size), 0,
             "name ex W: a zero buffer fails");
    check_eq(winabi::k32_GetLastError(), kErrorMoreData,
             "name ex W: overflow names ERROR_MORE_DATA");
    check_eq(size, name.size() + 1,
             "name ex W: overflow answers the size with terminator");

    // A DNS-domain request answers an empty domain with success: a
    // machine that is not joined is a real state.
    size = 64;
    check_eq(k32p_GetComputerNameExW(2, wide, &size), 1,
             "name ex W: the domain query succeeds");
    check_eq(size, 0, "name ex W: the domain answer is empty");
    check(wide[0] == u'\0', "name ex W: the domain answer is a null");

    // An unknown format is refused.
    check_eq(k32p_GetComputerNameExW(99, wide, &size), 0,
             "name ex W: an unknown format fails");
    check_eq(winabi::k32_GetLastError(), kErrorInvalidParameter,
             "name ex W: an unknown format sets ERROR_INVALID_PARAMETER");

    // The physical forms answer what the logical ones answer.
    char16_t physical[64] = {};
    std::uint32_t logical_size = 64;
    std::uint32_t physical_size = 64;
    check_eq(k32p_GetComputerNameExW(0, wide, &logical_size), 1,
             "name ex W: NetBIOS form succeeds");
    check_eq(k32p_GetComputerNameExW(4, physical, &physical_size), 1,
             "name ex W: physical NetBIOS form succeeds");
    check(logical_size == physical_size && wide_to_narrow(wide) ==
                                              wide_to_narrow(physical),
          "name ex W: the physical form matches the logical one");
}

// ---------------------------------------------------------- system info

void test_system_info() {
    std::uint8_t info[kSystemInfoBytes] = {};
    std::uint8_t native[kSystemInfoBytes] = {};
    k32p_GetSystemInfo(info);
    k32p_GetNativeSystemInfo(native);
    check(std::memcmp(info, native, sizeof(info)) == 0,
          "sysinfo: native and regular answer identically");

    const auto u16_at = [&info](std::size_t at) {
        std::uint16_t v = 0;
        std::memcpy(&v, info + at, sizeof(v));
        return v;
    };
    const auto u32_at = [&info](std::size_t at) {
        std::uint32_t v = 0;
        std::memcpy(&v, info + at, sizeof(v));
        return v;
    };
    const auto ptr_at = [&info](std::size_t at) {
        std::uint64_t v = 0;
        std::memcpy(&v, info + at, sizeof(v));
        return v;
    };

    check_eq(u16_at(0), 9, "sysinfo: the architecture is AMD64");
    check_eq(u32_at(4), static_cast<std::uint32_t>(::sysconf(_SC_PAGESIZE)),
             "sysinfo: the page size is the host's");
    check_eq(ptr_at(8), 0x10000,
             "sysinfo: the minimum application address");
    check_eq(ptr_at(16), 0x7FFFFFFEFFFFULL,
             "sysinfo: the maximum application address");
    check_eq(u32_at(32),
             static_cast<std::uint32_t>(::sysconf(_SC_NPROCESSORS_ONLN)),
             "sysinfo: the processor count is the host's");
    check_eq(u32_at(36), 8664, "sysinfo: the processor type is AMD X8664");
    check_eq(u32_at(40), 65536, "sysinfo: the allocation granularity");
    check(u32_at(32) >= 1, "sysinfo: at least one processor");
}

void test_processor_features() {
    // `cmpxchg8b` is baseline on x86-64, 3DNow is gone, NX is part of
    // long mode, and an unknown index is absent.
    check_eq(k32p_IsProcessorFeaturePresent(2), 1,
             "pf: cmpxchg8b is present");
    check_eq(k32p_IsProcessorFeaturePresent(7), 0, "pf: 3DNow is absent");
    check_eq(k32p_IsProcessorFeaturePresent(12), 1, "pf: NX is present");
    check_eq(k32p_IsProcessorFeaturePresent(0xFFFF), 0,
             "pf: an unknown index is absent");

    const std::uint32_t cpu = k32p_GetCurrentProcessorNumber();
    const int sched_cpu = ::sched_getcpu();
    check(sched_cpu >= 0 && cpu == static_cast<std::uint32_t>(sched_cpu),
          "pf: the processor number is the host's");

    std::uint8_t number[4] = {1, 1, 1, 1};
    k32p_GetCurrentProcessorNumberEx(number);
    check_eq(number[0], 0, "pf ex: the group is zero");
    check_eq(number[2], cpu & 0xFF, "pf ex: the number is the host's");
    check_eq(number[3], 0, "pf ex: the reserved byte is zero");

    check_eq(k32p_FlushInstructionCache(0, nullptr, 0), 1,
             "pf: flushing the instruction cache succeeds");
}

// -------------------------------------------------------- process handles

void test_process_handles() {
    const auto self = static_cast<std::uint32_t>(::getpid());

    check_eq(k32p_GetProcessId(kCurrentProcessPseudo), self,
             "handles: the pseudo handle names this process");

    check_eq(k32p_GetProcessId(0x1234), 0,
             "handles: an unknown handle answers zero");
    check_eq(winabi::k32_GetLastError(), kErrorInvalidHandle,
             "handles: an unknown handle sets ERROR_INVALID_HANDLE");

    check_eq(k32p_OpenProcess(0x1F0FFF, 0, self), kCurrentProcessPseudo,
             "handles: opening this process answers the pseudo handle");
    check_eq(k32p_OpenProcess(0x1F0FFF, 0, 0), 0,
             "handles: pid zero is refused");
    check_eq(winabi::k32_GetLastError(), kErrorInvalidParameter,
             "handles: a refused open names ERROR_INVALID_PARAMETER");
    check_eq(k32p_OpenProcess(0x1F0FFF, 0, 0xFFFFFFFA), 0,
             "handles: a nonexistent pid is refused");

    check_eq(k32p_GetExitCodeProcess(kCurrentProcessPseudo, nullptr), 0,
             "exit code: a null store is refused");
    std::uint32_t code = 0;
    check_eq(k32p_GetExitCodeProcess(kCurrentProcessPseudo, &code), 1,
             "exit code: the pseudo handle succeeds");
    check_eq(code, 259, "exit code: the answer is STILL_ACTIVE");
    check_eq(k32p_GetExitCodeProcess(0x1234, &code), 0,
             "exit code: an unknown handle fails");
    check_eq(winabi::k32_GetLastError(), kErrorInvalidHandle,
             "exit code: an unknown handle names ERROR_INVALID_HANDLE");

    check_eq(k32p_GetProcessVersion(0), 0x000A0000,
             "version: the current process answers 10.0");
    check_eq(k32p_GetProcessVersion(0xFFFFFFFA), 0,
             "version: a nonexistent pid answers zero");
    check_eq(winabi::k32_GetLastError(), kErrorInvalidParameter,
             "version: a nonexistent pid names ERROR_INVALID_PARAMETER");

    std::uint32_t session = 9;
    check_eq(k32p_ProcessIdToSessionId(self, &session), 1,
             "session: the current pid succeeds");
    check_eq(session, 0, "session: the answer is session zero");
    check_eq(k32p_ProcessIdToSessionId(0, &session), 0,
             "session: pid zero fails");
    check_eq(winabi::k32_GetLastError(), kErrorInvalidParameter,
             "session: pid zero names ERROR_INVALID_PARAMETER");
}

void test_process_attributes() {
    const std::uint64_t self = kCurrentProcessPseudo;

    check_eq(k32p_SetPriorityClass(self, 0x80), 1,
             "priority: a real class is accepted");
    check_eq(k32p_GetPriorityClass(self), 0x80,
             "priority: the class reads back");
    check_eq(k32p_SetPriorityClass(self, 0x3), 0,
             "priority: a nonsense class is refused");
    check_eq(winabi::k32_GetLastError(), kErrorInvalidParameter,
             "priority: a nonsense class names ERROR_INVALID_PARAMETER");
    check_eq(k32p_GetPriorityClass(0x1234), 0,
             "priority: an unknown handle answers zero");
    check_eq(winabi::k32_GetLastError(), kErrorInvalidHandle,
             "priority: an unknown handle names ERROR_INVALID_HANDLE");

    std::uint32_t level = 0;
    std::uint32_t flags = 0;
    check_eq(k32p_GetProcessShutdownParameters(&level, &flags), 1,
             "shutdown: the query succeeds");
    check_eq(level, 0x280, "shutdown: the default level is 0x280");
    check_eq(flags, 0, "shutdown: the default flags are zero");
    check_eq(k32p_SetProcessShutdownParameters(0x123, 0x4), 1,
             "shutdown: the set succeeds");
    check_eq(k32p_GetProcessShutdownParameters(&level, &flags), 1,
             "shutdown: the query after the set succeeds");
    check_eq(level, 0x123, "shutdown: the level reads back");
    check_eq(flags, 0x4, "shutdown: the flags read back");
    check_eq(k32p_GetProcessShutdownParameters(nullptr, &flags), 0,
             "shutdown: a null level is refused");

    std::uint64_t minimum = 0;
    std::uint64_t maximum = 0;
    check_eq(k32p_GetProcessWorkingSetSize(self, &minimum, &maximum), 1,
             "working set: the query succeeds");
    check_eq(minimum, 204800, "working set: the default minimum");
    check_eq(maximum, 1048576, "working set: the default maximum");
    check_eq(k32p_SetProcessWorkingSetSize(self, 300, 200), 0,
             "working set: min above max is refused");
    check_eq(winabi::k32_GetLastError(), kErrorInvalidParameter,
             "working set: min above max names ERROR_INVALID_PARAMETER");
    check_eq(k32p_SetProcessWorkingSetSize(self, 100, 200), 1,
             "working set: a real pair is accepted");
    check_eq(k32p_GetProcessWorkingSetSize(self, &minimum, &maximum), 1,
             "working set: the query after the set succeeds");
    check_eq(minimum, 100, "working set: the minimum reads back");
    check_eq(maximum, 200, "working set: the maximum reads back");
}

void test_thread_handles() {
    check_eq(k32p_OpenThread(0x1FFFFF, 0, 0), 0,
             "threads: tid zero is refused");
    check_eq(k32p_OpenThread(0x1FFFFF, 0, 0xFFFFFFFE), 0,
             "threads: an unknown tid is refused");
    const auto self_tid = static_cast<std::uint32_t>(::gettid());
    check_eq(k32p_OpenThread(0x1FFFFF, 0, self_tid), kCurrentThreadPseudo,
             "threads: the current tid answers the pseudo handle");

    std::uint32_t code = 0;
    check_eq(k32p_GetExitCodeThread(kCurrentThreadPseudo, &code), 1,
             "threads: the current thread's exit code query succeeds");
    check_eq(code, 259, "threads: the answer is STILL_ACTIVE");
    check_eq(k32p_GetExitCodeThread(0x1234, &code), 0,
             "threads: an unknown handle fails");
    check_eq(winabi::k32_GetLastError(), kErrorInvalidHandle,
             "threads: an unknown handle names ERROR_INVALID_HANDLE");

    check_eq(k32p_SuspendThread(kCurrentThreadPseudo), 0xFFFFFFFFU,
             "threads: suspending is refused");
    check_eq(winabi::k32_GetLastError(), kErrorCallNotImplemented,
             "threads: suspending names ERROR_CALL_NOT_IMPLEMENTED");
    check_eq(k32p_CreateThread(nullptr, 0, 0, nullptr, 0, nullptr), 0,
             "threads: creating is refused");
    check_eq(winabi::k32_GetLastError(), kErrorCallNotImplemented,
             "threads: creating names ERROR_CALL_NOT_IMPLEMENTED");
    check_eq(k32p_CreateThreadpool(nullptr), 0,
             "threads: the threadpool is refused");
    check_eq(winabi::k32_GetLastError(), kErrorCallNotImplemented,
             "threads: the threadpool names ERROR_CALL_NOT_IMPLEMENTED");
    char16_t dummy_path[4] = {};
    check_eq(k32p_CreateProcessW(nullptr, nullptr, nullptr, nullptr, 0, 0,
                                 nullptr, dummy_path, nullptr, nullptr),
             0, "processes: creating is refused");
    check_eq(winabi::k32_GetLastError(), kErrorCallNotImplemented,
             "processes: creating names ERROR_CALL_NOT_IMPLEMENTED");
}

// ---------------------------------------------------------------- toolhelp

void test_toolhelp_processes() {
    check_eq(k32p_CreateToolhelp32Snapshot(0, 0), kInvalidHandleValue,
             "toolhelp: an empty flag set is refused");
    check_eq(winabi::k32_GetLastError(), kErrorInvalidParameter,
             "toolhelp: an empty flag set names ERROR_INVALID_PARAMETER");
    check_eq(k32p_CreateToolhelp32Snapshot(0x40, 0), kInvalidHandleValue,
             "toolhelp: an unknown flag is refused");

    const std::uint64_t snapshot = k32p_CreateToolhelp32Snapshot(2, 0);
    check(snapshot != kInvalidHandleValue && snapshot != 0,
          "toolhelp: the process snapshot opens");

    std::uint8_t entry[kProcessEntryBytesW] = {};
    const std::uint32_t entry_size_w = kProcessEntryBytesW;
    std::memcpy(entry, &entry_size_w, sizeof(entry_size_w));
    check_eq(k32p_Process32FirstW(snapshot, entry), 1,
             "toolhelp: the first process row reads");
    const auto u32_at = [&entry](std::size_t at) {
        std::uint32_t v = 0;
        std::memcpy(&v, entry + at, sizeof(v));
        return v;
    };
    check(u32_at(8) != 0, "toolhelp: the row names a process");
    check_eq(u32_at(0), kProcessEntryBytesW,
             "toolhelp: the row's size is written back");
    const auto pid_at = u32_at(8);
    const bool pid_self_or_other = pid_at != 0;
    check(pid_self_or_other, "toolhelp: the process id is nonzero");
    std::uint16_t name_first = 0;
    std::memcpy(&name_first, entry + kProcessEntryExeOffset, 2);
    check(name_first != 0, "toolhelp: the row carries a name");

    std::uint32_t rows = 1;
    while (k32p_Process32NextW(snapshot, entry) == 1) {
        ++rows;
    }
    check_eq(winabi::k32_GetLastError(), kErrorNoMoreFiles,
             "toolhelp: the walk ends with ERROR_NO_MORE_FILES");
    check(rows >= 1, "toolhelp: at least one process was walked");

    // The A walk over the SAME snapshot answers the same count. The
    // snapshot captured the process list when it was created, so a second
    // walk of the same handle is the same rows spelled differently -- which
    // is the property being asserted. Walking a fresh snapshot would compare
    // two captures of a host process table that other tests start and stop
    // in, and the counts would drift under a parallel run for reasons that
    // say nothing about the A and W entries.
    std::uint8_t entry_a[kProcessEntryBytesA] = {};
    const std::uint32_t entry_size_a = kProcessEntryBytesA;
    std::memcpy(entry_a, &entry_size_a, sizeof(entry_size_a));
    check_eq(k32p_Process32FirstA(snapshot, entry_a), 1,
             "toolhelp: the A walk starts over the same snapshot");
    std::uint32_t rows_a = 1;
    while (k32p_Process32NextA(snapshot, entry_a) == 1) {
        ++rows_a;
    }
    check_eq(rows_a, rows, "toolhelp: A and W walk the same rows");

    // A short declared size is refused.
    const std::uint64_t snapshot_2 = k32p_CreateToolhelp32Snapshot(2, 0);
    std::uint8_t short_entry[kProcessEntryBytesW] = {};
    const std::uint32_t tiny = 100;
    std::memcpy(short_entry, &tiny, sizeof(tiny));
    check_eq(k32p_Process32FirstW(snapshot_2, short_entry), 0,
             "toolhelp: a short declared size fails");
    check_eq(winabi::k32_GetLastError(), kErrorInsufficientBuffer,
             "toolhelp: a short declared size names INSUFFICIENT_BUFFER");

    check_eq(k32p_Process32NextW(0x1234, entry), 0,
             "toolhelp: an unknown snapshot handle fails");
    check_eq(winabi::k32_GetLastError(), kErrorInvalidHandle,
             "toolhelp: an unknown handle names ERROR_INVALID_HANDLE");
}

void test_toolhelp_threads_modules_heaps() {
    // Threads: a filter naming this process answers its one thread.
    const std::uint64_t snapshot =
        k32p_CreateToolhelp32Snapshot(4, static_cast<std::uint32_t>(::getpid()));
    check(snapshot != kInvalidHandleValue, "toolhelp: the thread snapshot opens");
    std::uint8_t entry[kThreadEntryBytes] = {};
    const std::uint32_t size = kThreadEntryBytes;
    std::memcpy(entry, &size, sizeof(size));
    check_eq(k32p_Thread32First(snapshot, entry), 1,
             "toolhelp: the first thread row reads");
    const auto u32_at = [&entry](std::size_t at) {
        std::uint32_t v = 0;
        std::memcpy(&v, entry + at, sizeof(v));
        return v;
    };
    check_eq(u32_at(12), static_cast<std::uint32_t>(::getpid()),
             "toolhelp: the thread's owner is this process");
    check_eq(k32p_Thread32Next(snapshot, entry), 0,
             "toolhelp: the one thread is the last row");

    // Modules: without a guest state there is no image to name, and the
    // honest answer is an empty walk.
    const std::uint64_t module_snapshot =
        k32p_CreateToolhelp32Snapshot(8, static_cast<std::uint32_t>(::getpid()));
    check(module_snapshot != kInvalidHandleValue,
          "toolhelp: the module snapshot opens");
    std::uint8_t module_entry[1080] = {};
    const std::uint32_t module_size = 1080;
    std::memcpy(module_entry, &module_size, sizeof(module_size));
    check_eq(k32p_Module32FirstW(module_snapshot, module_entry), 0,
             "toolhelp: a module walk without a guest is empty");
    check_eq(winabi::k32_GetLastError(), kErrorNoMoreFiles,
             "toolhelp: the empty module walk ends with NO_MORE_FILES");

    // Another process's modules are refused.
    check_eq(k32p_CreateToolhelp32Snapshot(8, 0xFFFFFFFA),
             kInvalidHandleValue,
             "toolhelp: another process's modules are refused");
    check_eq(winabi::k32_GetLastError(), kErrorInvalidParameter,
             "toolhelp: the module refusal names ERROR_INVALID_PARAMETER");

    // Heaps: one entry, the process heap.
    const std::uint64_t heap_snapshot =
        k32p_CreateToolhelp32Snapshot(1, static_cast<std::uint32_t>(::getpid()));
    check(heap_snapshot != kInvalidHandleValue,
          "toolhelp: the heap snapshot opens");
    std::uint8_t heap_entry[kHeapListBytes] = {};
    const std::uint64_t heap_list_size = kHeapListBytes;
    std::memcpy(heap_entry, &heap_list_size, sizeof(heap_list_size));
    check_eq(k32p_Heap32ListFirst(heap_snapshot, heap_entry), 1,
             "toolhelp: the heap list reads");
    const auto ptr_at = [&heap_entry](std::size_t at) {
        std::uint64_t v = 0;
        std::memcpy(&v, heap_entry + at, sizeof(v));
        return v;
    };
    const auto u32_at2 = [&heap_entry](std::size_t at) {
        std::uint32_t v = 0;
        std::memcpy(&v, heap_entry + at, sizeof(v));
        return v;
    };
    check_eq(u32_at2(8), static_cast<std::uint32_t>(::getpid()),
             "toolhelp: the heap list names this process");
    check(ptr_at(16) != 0, "toolhelp: the heap id is nonzero");
    check_eq(k32p_Heap32ListNext(heap_snapshot, heap_entry), 0,
             "toolhelp: one heap is the last row");
    check_eq(winabi::k32_GetLastError(), kErrorNoMoreFiles,
             "toolhelp: the heap list ends with NO_MORE_FILES");

    std::uint8_t block[kHeapEntryBytes] = {};
    const std::uint64_t block_size = kHeapEntryBytes;
    std::memcpy(block, &block_size, sizeof(block_size));
    check_eq(k32p_Heap32First(block, static_cast<std::uint32_t>(::getpid()),
                              ptr_at(16)),
             0, "toolhelp: heap blocks are not enumerated");
    check_eq(winabi::k32_GetLastError(), kErrorNoMoreFiles,
             "toolhelp: the empty heap answers NO_MORE_FILES");
}

void test_toolhelp_read_memory() {
    const std::uint32_t value = 0xC0FFEE42;
    std::uint32_t back = 0;
    std::uint64_t read = 9;
    check_eq(k32p_Toolhelp32ReadProcessMemory(
                 static_cast<std::uint32_t>(::getpid()), &value, &back,
                 sizeof(value), &read),
             1, "read memory: this process reads");
    check_eq(read, sizeof(value), "read memory: the count is answered");
    check_eq(back, value, "read memory: the bytes arrive");

    check_eq(k32p_Toolhelp32ReadProcessMemory(0xFFFFFFFA, &value, &back,
                                              sizeof(value), &read),
             0, "read memory: another process is refused");
    check_eq(winabi::k32_GetLastError(), kErrorAccessDenied,
             "read memory: the refusal names ERROR_ACCESS_DENIED");
    check_eq(k32p_Toolhelp32ReadProcessMemory(
                 static_cast<std::uint32_t>(::getpid()), &value, nullptr,
                 sizeof(value), &read),
             0, "read memory: a null buffer is refused");
    check_eq(winabi::k32_GetLastError(), kErrorInvalidParameter,
             "read memory: the null buffer names ERROR_INVALID_PARAMETER");
}

}  // namespace

int main() {
    test_registration();
    test_expand_environment_strings_w();
    test_expand_environment_strings_a();
    test_system_directories();
    test_computer_name();
    test_system_info();
    test_processor_features();
    test_process_handles();
    test_process_attributes();
    test_thread_handles();
    test_toolhelp_processes();
    test_toolhelp_threads_modules_heaps();
    test_toolhelp_read_memory();
    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

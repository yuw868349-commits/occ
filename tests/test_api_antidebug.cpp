// The anti-debug answering surface, as the tests see it.
//
// What this file checks is that each question a hardened program asks is
// answered the way an unwatched machine answers it: the debug port is empty,
// the debug flags say "no debug inherit", the debug object query fails the way
// it fails with no object, the kernel debugger is absent, an object's type is
// never `DebugObject`, and closing a handle that names nothing is refused with
// a status rather than raising. These are not "safe defaults" being asserted
// for their safeness -- each is the specific value a real machine produces,
// and the test names the machine's answer.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

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

// The statuses the answers use, so the assertions read as the kernel's
// names rather than as their numbers.
constexpr std::uint32_t kStatusSuccess = 0x00000000u;
constexpr std::uint32_t kStatusInvalidInfoClass = 0xC0000003u;
constexpr std::uint32_t kStatusInfoLengthMismatch = 0xC0000004u;
constexpr std::uint32_t kStatusInvalidHandle = 0xC0000008u;
constexpr std::uint32_t kStatusPortNotSet = 0xC0000353u;

// The process-information classes named, so the calls below read the way a
// program's source reads.
constexpr std::uint32_t kProcessBasicInformation = 0;
constexpr std::uint32_t kProcessDebugPort = 7;
constexpr std::uint32_t kProcessDebugObjectHandle = 0x1E;
constexpr std::uint32_t kProcessDebugFlags = 0x1F;
constexpr std::uint32_t kSystemKernelDebuggerInformation = 0x23;

extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtQueryInformationProcess(
    std::uint64_t, std::uint32_t, void*, std::uint32_t,
    std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtSetInformationProcess(
    std::uint64_t, std::uint32_t, const void*, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtQueryObject(
    std::uint64_t, std::uint32_t, void*, std::uint32_t,
    std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtQuerySystemInformation(
    std::uint32_t, void*, std::uint32_t, std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtClose(
    std::uint64_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtQueryVirtualMemory(
    std::uint64_t, const void*, std::uint32_t, void*, std::uint64_t,
    std::uint64_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtQueryPerformanceCounter(
    void*, void*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtQuerySystemTime(
    void*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtQueryDefaultLocale(
    std::uint32_t, void*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtYieldExecution() noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
nt_NtQueryInformationJobObject(std::uint64_t, std::uint32_t, void*,
                               std::uint32_t, std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32_CheckRemoteDebuggerPresent(
    std::uint64_t, std::int32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32_DebugActiveProcess(
    std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32_DebugActiveProcessStop(
    std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) void k32_OutputDebugStringA(
    const char*) noexcept;
extern "C" __attribute__((ms_abi)) void k32_OutputDebugStringW(
    const char16_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
k32_GetCurrentProcessId() noexcept;

// Little-endian readers for the buffers the calls fill.
[[nodiscard]] std::uint32_t rd32(const void* base, std::size_t off) {
    std::uint32_t v = 0;
    std::memcpy(&v, static_cast<const std::uint8_t*>(base) + off, 4);
    return v;
}
[[nodiscard]] std::uint64_t rd64(const void* base, std::size_t off) {
    std::uint64_t v = 0;
    std::memcpy(&v, static_cast<const std::uint8_t*>(base) + off, 8);
    return v;
}

// A guest state with a PEB address and an image path, installed so that the
// queries which read those answer with them rather than with zero. The other
// fields stay default: nothing under test reaches them.
GuestState g_state;

void install_state() {
    g_state.peb = 0x00000000DEADB000ULL;
    g_state.image_base = 0x140000000ULL;
    g_state.image_path_dos = "Z:\\tests\\antidebug.exe";
    set_guest_state(&g_state);
}

void test_process_basic_information() {
    std::uint8_t buffer[64] = {};
    std::uint32_t ret = 0;
    const std::uint32_t s = nt_NtQueryInformationProcess(
        ~std::uint64_t{0}, kProcessBasicInformation, buffer, sizeof(buffer),
        &ret);
    check(s == kStatusSuccess, "anti: ProcessBasicInformation succeeds");
    check(ret == 48, "anti: ProcessBasicInformation reports 48 bytes");
    check(rd64(buffer, 0x08) == g_state.peb,
          "anti: PebBaseAddress is the runtime's PEB");
    check(rd64(buffer, 0x20) == k32_GetCurrentProcessId(),
          "anti: UniqueProcessId is the current process");
}

void test_debug_port_and_flags() {
    std::uint64_t port = 0;
    std::uint32_t ret = 0;
    std::uint32_t s = nt_NtQueryInformationProcess(
        ~std::uint64_t{0}, kProcessDebugPort, &port, sizeof(port), &ret);
    check(s == kStatusSuccess && port == 0,
          "anti: ProcessDebugPort is empty, so no debugger");

    // The debug object handle must fail with STATUS_PORT_NOT_SET -- the error
    // a process with no debug object gets -- and not be a success carrying
    // zero, because a checker tells the two apart.
    std::uint64_t object = 0xFFFFFFFFFFFFFFFFULL;
    ret = 0;
    s = nt_NtQueryInformationProcess(~std::uint64_t{0},
                                     kProcessDebugObjectHandle, &object,
                                     sizeof(object), &ret);
    check(s == kStatusPortNotSet,
          "anti: ProcessDebugObjectHandle fails with STATUS_PORT_NOT_SET");

    std::uint32_t flags = 0;
    ret = 0;
    s = nt_NtQueryInformationProcess(~std::uint64_t{0}, kProcessDebugFlags,
                                     &flags, sizeof(flags), &ret);
    check(s == kStatusSuccess && flags == 1,
          "anti: ProcessDebugFlags reports no debug inherit");
}

void test_invalid_class() {
    std::uint8_t buffer[8] = {};
    std::uint32_t ret = 0;
    const std::uint32_t s = nt_NtQueryInformationProcess(
        ~std::uint64_t{0}, 0x7FFFFFFF, buffer, sizeof(buffer), &ret);
    check(s == kStatusInvalidInfoClass,
          "anti: an unknown process class is refused as such");
}

void test_short_buffer() {
    std::uint32_t small = 0;
    std::uint32_t ret = 0;
    const std::uint32_t s = nt_NtQueryInformationProcess(
        ~std::uint64_t{0}, kProcessBasicInformation, &small, sizeof(small),
        &ret);
    check(s == kStatusInfoLengthMismatch,
          "anti: a short buffer is a length mismatch");
    check(ret == 48, "anti: the length mismatch still reports 48");
}

void test_object_type_is_never_debug_object() {
    std::uint8_t buffer[512] = {};
    std::uint32_t ret = 0;
    constexpr std::uint32_t kObjectTypeInformation = 2;
    const std::uint32_t s = nt_NtQueryObject(0x1234, kObjectTypeInformation,
                                             buffer, sizeof(buffer), &ret);
    check(s == kStatusSuccess, "anti: the object type query succeeds");
    const std::uint16_t len = static_cast<std::uint16_t>(rd32(buffer, 0));
    const std::uint64_t name_at = rd64(buffer, 0x08);
    const std::u16string name(reinterpret_cast<const char16_t*>(name_at),
                              len / 2);
    check(name != u"DebugObject",
          "anti: a handle's type is never a debug object");

    // A handle in the file range names a file, which is what a program that
    // opened a file and asked its type expects to be told.
    std::uint8_t fbuf[512] = {};
    ret = 0;
    const std::uint32_t fs = nt_NtQueryObject(0x2000, kObjectTypeInformation,
                                              fbuf, sizeof(fbuf), &ret);
    check(fs == kStatusSuccess, "anti: a file handle's type query succeeds");
    const std::uint16_t flen = static_cast<std::uint16_t>(rd32(fbuf, 0));
    const std::uint64_t fname_at = rd64(fbuf, 0x08);
    const std::u16string fname(reinterpret_cast<const char16_t*>(fname_at),
                               flen / 2);
    check(fname == u"File", "anti: a file handle names the File type");
}

void test_object_types_list() {
    std::uint8_t buffer[4096] = {};
    std::uint32_t ret = 0;
    constexpr std::uint32_t kObjectTypesInformation = 3;
    const std::uint32_t s = nt_NtQueryObject(
        ~std::uint64_t{0}, kObjectTypesInformation, buffer, sizeof(buffer),
        &ret);
    check(s == kStatusSuccess, "anti: the object type enumeration succeeds");
    check(ret > 8 && ret <= sizeof(buffer),
          "anti: the enumeration reports a plausible size");
    // The list names types, and it may name `DebugObject` -- the type exists
    // on every machine -- but its entries carry no instance count, which is
    // what a checker reads to decide whether a debug object is present.
    check(rd32(buffer, 0) > 0, "anti: the enumeration names at least one type");
}

void test_kernel_debugger_information() {
    std::uint8_t buffer[8] = {};
    std::uint32_t ret = 0;
    const std::uint32_t s = nt_NtQuerySystemInformation(
        kSystemKernelDebuggerInformation, buffer, sizeof(buffer), &ret);
    check(s == kStatusSuccess, "anti: the kernel debugger query succeeds");
    const std::uint8_t enabled = buffer[0];
    const std::uint8_t not_present = buffer[1];
    check(enabled == 0 && not_present == 1,
          "anti: the kernel debugger is disabled and absent");
    check(ret == 2, "anti: the kernel debugger answer is two bytes");
}

void test_system_information_invalid_class() {
    std::uint8_t buffer[8] = {};
    std::uint32_t ret = 0;
    const std::uint32_t s = nt_NtQuerySystemInformation(0x7FFFFFFF, buffer,
                                                        sizeof(buffer), &ret);
    check(s == kStatusInvalidInfoClass,
          "anti: an unknown system class is refused as such");
}

void test_close() {
    // A handle this runtime did not issue, above its own range, is refused
    // with the invalid-handle status -- no exception, which is the
    // no-debugger shape.
    check(nt_NtClose(0xDEADBEEF12345678ULL) == kStatusInvalidHandle,
          "anti: NtClose refuses an unknown handle");
    check(nt_NtClose(0) == kStatusInvalidHandle,
          "anti: NtClose refuses the null handle");
    check(nt_NtClose(~std::uint64_t{0}) == kStatusInvalidHandle,
          "anti: NtClose refuses the current-process pseudo handle");
}

void test_clock() {
    std::uint64_t counter = 0;
    std::uint64_t frequency = 0;
    const std::uint32_t s =
        nt_NtQueryPerformanceCounter(&counter, &frequency);
    check(s == kStatusSuccess && frequency == 10000000ULL,
          "anti: the performance frequency is the standard 10 MHz");
    check(counter != 0, "anti: the performance counter advances");

    std::uint64_t now = 0;
    check(nt_NtQuerySystemTime(&now) == kStatusSuccess && now != 0,
          "anti: the system time is a real clock reading");

    std::uint32_t locale = 0;
    check(nt_NtQueryDefaultLocale(1, &locale) == kStatusSuccess &&
              locale == 0x0409,
          "anti: the default locale is US English");

    check(nt_NtYieldExecution() == kStatusSuccess,
          "anti: the yield succeeds");
}

void test_job_object() {
    std::uint8_t buffer[64] = {};
    std::uint32_t ret = 0;
    const std::uint32_t s = nt_NtQueryInformationJobObject(
        0, 1, buffer, sizeof(buffer), &ret);
    check(s == kStatusInvalidHandle,
          "anti: a process outside a job has no job to describe");
}

void test_kernel32_debugger_calls() {
    std::int32_t present = 1;
    const std::int32_t ok = k32_CheckRemoteDebuggerPresent(
        ~std::uint64_t{0}, &present);
    check(ok == 1 && present == 0,
          "anti: CheckRemoteDebuggerPresent reports no debugger");

    const std::uint32_t self = k32_GetCurrentProcessId();
    check(k32_DebugActiveProcess(self) == 1,
          "anti: self-debugging succeeds, so no debugger is attached");
    check(k32_DebugActiveProcessStop(self) == 1,
          "anti: stopping the self-debug succeeds");
    check(k32_DebugActiveProcess(self + 9999) == 0,
          "anti: attaching to another process is refused");

    // Neither debug-string call may fault or raise; they are the channel a
    // debugger would have listened on, and there is none here.
    k32_OutputDebugStringA("occ anti-debug test\n");
    k32_OutputDebugStringW(u"occ anti-debug test\n");
    check(true, "anti: the debug-string calls return without a debugger");
}

void test_query_memory_without_state() {
    // The memory query reads the region ledger, which is the guest state's.
    // A run with no state has none, and the call says so rather than
    // dereferencing null -- the answer a caller with no address space gets.
    set_guest_state(nullptr);
    std::uint8_t buffer[64] = {};
    std::uint64_t ret = 0;
    const std::uint32_t s = nt_NtQueryVirtualMemory(
        ~std::uint64_t{0}, reinterpret_cast<const void*>(0x140000000ULL), 0,
        buffer, sizeof(buffer), &ret);
    check(s == 0xC000000Du,
          "anti: a memory query with no address space is an invalid parameter");
    install_state();
}

}  // namespace

int main() {
    install_state();
    test_process_basic_information();
    test_debug_port_and_flags();
    test_invalid_class();
    test_short_buffer();
    test_object_type_is_never_debug_object();
    test_object_types_list();
    test_kernel_debugger_information();
    test_system_information_invalid_class();
    test_close();
    test_clock();
    test_job_object();
    test_kernel32_debugger_calls();
    test_query_memory_without_state();
    set_guest_state(nullptr);

    std::printf("antidebug: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

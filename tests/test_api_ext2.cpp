// The families added for the shell-runtime surface: the anti-debug and
// anti-vm answers, the Nt memory and section bridges, the loader-facing
// Ldr family, the file families and the token and random queries, as the
// tests see them without a live guest.
//
// What is checked here is the contract a caller can provoke without a
// guest installed: the refusal paths (a stranger's handle, an unknown
// policy, a mechanism this runtime does not enforce), the pure functions
// (case conversion, pointer walk, locale answers, keyboard answers), and a
// handle lifecycle that runs entirely on the host (an `NtCreateFile`
// handle opened, written, read, queried, locked and closed, with the
// close path shared with `CloseHandle`). What is not checked is what needs
// a live guest -- module resolution and thread suspension reach state only
// a real run installs -- so those are checked on their no-guest contracts
// instead, which is the part a caller can provoke here.

#include "occ/runtime/api.h"
#include "occ/runtime/exports.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include <sys/stat.h>
#include <unistd.h>

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

// The error and status constants the contracts below are checked against.
constexpr std::uint32_t kErrorInvalidHandle = 6;
constexpr std::uint32_t kErrorInvalidParameter = 87;
constexpr std::uint32_t kErrorInvalidFunction = 1;
constexpr std::uint32_t kErrorInsufficientBuffer = 122;
constexpr std::uint32_t kErrorAccessDenied = 5;
constexpr std::uint32_t kErrorNotSupported = 50;
constexpr std::uint32_t kErrorFileNotFound = 2;
constexpr std::uint32_t kErrorInvalidAddress = 487;

constexpr std::uint32_t kStSuccess = 0x00000000;
constexpr std::uint32_t kStUnsuccessful = 0xC0000001;
constexpr std::uint32_t kStNotImplemented = 0xC0000002;
constexpr std::uint32_t kStInvalidHandle = 0xC0000008;
constexpr std::uint32_t kStInvalidParameter = 0xC000000D;
constexpr std::uint32_t kStObjectNameNotFound = 0xC0000034;
constexpr std::uint32_t kStObjectPathNotFound = 0xC000003A;

// The functions under test, declared the way the domain files define them.
extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetLastError(void) noexcept;

// -- the anti-debug surface (antidebug2.cpp)
extern "C" __attribute__((ms_abi)) std::uint32_t ntad2_NtQueryTimerResolution(
    std::uint32_t* min, std::uint32_t* max, std::uint32_t* current) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ntad2_NtSetTimerResolution(
    std::uint32_t requested, std::uint32_t set, std::uint32_t* actual) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ntad2_NtQueryDebugFilterState(
    std::uint32_t filter_id, std::uint32_t* answer) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ntad2_NtTestAlert(void) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetVersionExW(
    std::uint8_t* info) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32si_GetVersionExA(
    std::uint8_t* info) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetProductInfo(
    std::uint32_t major, std::uint32_t minor, std::uint32_t sp_major,
    std::uint32_t sp_minor, std::uint32_t* product) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32ad2_GetUserDefaultLCID(
    void) noexcept;
extern "C" __attribute__((ms_abi)) std::uint16_t k32ad2_GetUserDefaultLangID(
    void) noexcept;
extern "C" __attribute__((ms_abi)) std::uint16_t k32ad2_GetSystemDefaultLangID(
    void) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetLocaleInfoA(
    std::uint32_t locale, std::uint32_t lc_type, char* buffer,
    std::uint32_t capacity) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32ad2_GetActiveProcessorCount(
    std::uint16_t group) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32ad2_GetKeyboardLayoutList(
    std::uint32_t entries, std::uint32_t* layouts) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32ad2_GetKeyboardType(
    std::uint32_t type_id) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32ad2_GetDriveTypeA(
    const char* root_path) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32ad2_GetSystemWow64DirectoryA(
    char* buffer, std::uint32_t size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_IsWow64Process(
    std::uint64_t process, std::uint32_t* wow64_process) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_IsWow64Process2(
    std::uint64_t process, std::uint16_t* process_machine,
    std::uint16_t* native_machine) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetProcessDEPPolicy(
    std::uint64_t process, std::uint32_t* flags,
    std::uint32_t* permanent) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_SetProcessDEPPolicy(
    std::uint32_t dw_flags) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_GetCPInfoExA(
    std::uint32_t code_page, std::uint32_t flags, void* buffer) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32ad2_SearchPathA(
    const char* path, const char* filename, const char* extension,
    char* buffer, std::uint32_t buffer_length, char** file_part) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32ad2_QueryIdleProcessorCycleTime(
    std::uint64_t* cycle_time) noexcept;

// -- the shell-memory and loader surfaces (shell_mem.cpp, ldr_ext2.cpp,
//    kernel32_sys2.cpp)
extern "C" __attribute__((ms_abi)) std::uint32_t ntsm_NtAllocateVirtualMemory(
    std::uint64_t process_handle, std::uint64_t* base_address,
    std::uint64_t* region_size, std::uint32_t allocation_type,
    std::uint32_t protect) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ntsm_NtFreeVirtualMemory(
    std::uint64_t process_handle, std::uint64_t* base_address,
    std::uint64_t* region_size, std::uint32_t type) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ntsm_NtProtectVirtualMemory(
    std::uint64_t process_handle, std::uint64_t* base_address,
    std::uint64_t* region_size, std::uint32_t new_protect,
    std::uint32_t* old_protect) noexcept;
extern "C" __attribute__((ms_abi)) void* k32sm_VirtualAlloc2(
    std::uint64_t process, void* address, std::uint64_t size,
    std::uint32_t allocation_type, std::uint32_t protect,
    const void* extended_parameters, std::uint32_t parameter_count) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32sm_GetProcessMitigationPolicy(
    std::uint64_t process, std::uint32_t policy, void* buffer,
    std::uint32_t length) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32sm_SetProcessMitigationPolicy(
    std::uint32_t policy, const void* buffer, std::uint32_t length) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32sm_GetProcessIdOfThread(
    std::uint64_t thread_handle) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32s2_GetProcessPriorityBoost(
    std::uint64_t process, std::int32_t* disabled) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32s2_SetProcessPriorityBoost(
    std::uint64_t process, std::int32_t disable) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32sm_GetPreferredUILanguages(
    std::uint32_t flags, std::uint32_t* num_languages, void* buffer,
    std::uint32_t* buffer_size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32sm_GetSystemDefaultLocaleName(
    char16_t* buffer, std::int32_t capacity) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrLockLoaderLock(
    std::uint32_t flags, std::uint64_t* cookie, std::uint32_t* state) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrUnlockLoaderLock(
    std::uint32_t flags, std::uint64_t cookie) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
ntl2_LdrRegisterDllNotification(std::uint32_t flags, std::uint64_t callback,
                                std::uint64_t context,
                                std::uint64_t* cookie) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t
ntl2_LdrUnregisterDllNotification(std::uint64_t cookie) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ntl2_LdrUnloadDll(
    std::uint64_t base_dll) noexcept;

// -- the case, OEM and pointer-walk families (strcase_ext.cpp)
extern "C" __attribute__((ms_abi)) std::int32_t k32sc_CharToOemW(
    const char16_t* source, char* destination) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32sc_OemToCharW(
    const char* source, char16_t* destination) noexcept;
extern "C" __attribute__((ms_abi)) char* u32sc_CharUpperA(char* string) noexcept;
extern "C" __attribute__((ms_abi)) char* u32sc_CharLowerA(char* string) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* u32sc_CharUpperW(
    char16_t* string) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* u32sc_CharLowerW(
    char16_t* string) noexcept;
extern "C" __attribute__((ms_abi)) const char* u32sc_AnsiNext(
    const char* current) noexcept;
extern "C" __attribute__((ms_abi)) const char* u32sc_AnsiPrev(
    const char* start, const char* current) noexcept;

// -- the self-check and file surfaces (selfcheck_ext.cpp, ntdl_file2.cpp,
//    kernel32_file3.cpp, ntdll_antidebug.cpp)
extern "C" __attribute__((ms_abi)) std::int32_t k32chk_IsBadReadPtr(
    const void* address, std::uint64_t size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32chk_IsBadWritePtr(
    const void* address, std::uint64_t size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32chk_IsBadCodePtr(
    const void* function) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32chk_QueryFullProcessImageNameA(
    std::uint64_t process, std::uint32_t flags, char* buffer,
    std::uint32_t* size) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32chk_GetProcessIoCounters(
    std::uint64_t process, void* io_counters) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32chk_GetFirmwareEnvironmentVariableA(
    const char* name, const char* guid, char* buffer,
    std::uint32_t size) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32chk_GetGuiResources(
    std::uint64_t process, std::uint32_t flags) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ntf2_RtlGenRandom(
    void* buffer, std::uint32_t length) noexcept;
extern "C" __attribute__((ms_abi)) void* ntf2_RtlGetCurrentTeb(void) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ntf2_NtQuerySystemEnvironmentValue(
    const std::uint8_t* name, void* value, std::uint32_t value_length,
    std::uint32_t* return_length) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ntf2_NtSetSystemEnvironmentValue(
    const std::uint8_t* name, const void* value, std::uint32_t value_length) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ntf2_NtCreateFile(
    std::uint64_t* handle, std::uint32_t desired_access,
    const std::uint8_t* object_attributes, std::uint8_t* io_status,
    const std::uint64_t* allocation_size, std::uint32_t file_attributes,
    std::uint32_t share_access, std::uint32_t create_disposition,
    std::uint32_t create_options, const void* ea_buffer,
    std::uint32_t ea_length) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ntf2_NtOpenFile(
    std::uint64_t* handle, std::uint32_t desired_access,
    const std::uint8_t* object_attributes, std::uint8_t* io_status,
    std::uint32_t share_access, std::uint32_t open_options) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ntf2_NtReadFile(
    std::uint64_t file_handle, std::uint64_t event, std::uint64_t apc_routine,
    std::uint64_t apc_context, std::uint8_t* io_status, void* buffer,
    std::uint32_t length, const std::uint64_t* byte_offset,
    std::uint64_t key) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ntf2_NtWriteFile(
    std::uint64_t file_handle, std::uint64_t event, std::uint64_t apc_routine,
    std::uint64_t apc_context, std::uint8_t* io_status, const void* buffer,
    std::uint32_t length, const std::uint64_t* byte_offset,
    std::uint64_t key) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t ntf2_NtQueryInformationFile(
    std::uint64_t file_handle, std::uint8_t* io_status, void* info,
    std::uint32_t length, std::uint32_t file_information_class) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t nt_NtClose(
    std::uint64_t handle) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32f3_SetFilePointer(
    void* file, std::int32_t distance_low, std::int32_t* distance_high,
    std::uint32_t move_method) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32f3_GetShortPathNameA(
    const char* path, char* buffer, std::uint32_t capacity) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_FlushViewOfFile(
    const void* address, std::uint64_t bytes) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_LockFile(
    void* file, std::uint32_t offset_low, std::uint32_t offset_high,
    std::uint32_t len_low, std::uint32_t len_high) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_UnlockFile(
    void* file, std::uint32_t offset_low, std::uint32_t offset_high,
    std::uint32_t len_low, std::uint32_t len_high) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32f3_GetCompressedFileSizeA(
    const char* file, std::uint32_t* high) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_GetVolumePathNameA(
    const char* path, char* buffer, std::uint32_t capacity) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_CreateHardLinkA(
    const char* new_name, const char* existing_name,
    const void* security_attributes) noexcept;

// The guest process handle every in-process call passes on Windows.
constexpr std::uint64_t kPseudoHandle = 0xFFFFFFFFFFFFFFFFULL;

// The constants the Nt file layer spells with.
constexpr std::uint32_t kFileCreate = 2;
constexpr std::uint32_t kGenericReadWrite = 0xC0000000;
constexpr std::uint64_t kFileUseFilePointerPosition = 0xFFFFFFFFFFFFFFFEULL;
constexpr std::uint32_t kFileStandardInformation = 5;
constexpr std::uint32_t kFileAttributeNormal = 0x80;

// A no-op notification callback: registration only checks that a callback
// is present, and nothing delivers notifications without a guest.
extern "C" __attribute__((ms_abi)) void dummy_notification(
    std::uint64_t, std::uint64_t, void*) noexcept {}

// Builds an OBJECT_ATTRIBUTES record (48 bytes: Length at 0, RootDirectory
// at 8, ObjectName pointer at 16) pointing at a UNICODE_STRING (Length at
// 0, Buffer pointer at 8) for the given DOS path, laid out in the caller's
// buffer. Returns the OBJECT_ATTRIBUTES pointer.
[[nodiscard]] const std::uint8_t* build_object_attributes(
    std::uint8_t* out, std::size_t out_capacity, const std::string& dos_path) {
    std::memset(out, 0, out_capacity);
    const auto write_u32 = [out](std::size_t at, std::uint32_t v) {
        std::memcpy(out + at, &v, sizeof(v));
    };
    const auto write_ptr = [out](std::size_t at, std::uint64_t v) {
        std::memcpy(out + at, &v, sizeof(v));
    };
    const auto write_u16 = [out](std::size_t at, std::uint16_t v) {
        std::memcpy(out + at, &v, sizeof(v));
    };
    std::uint8_t* name_block = out + 64;
    write_u32(0, 48);                       // OBJECT_ATTRIBUTES.Length
    write_ptr(16, reinterpret_cast<std::uint64_t>(name_block));
    write_u16(64, static_cast<std::uint16_t>(dos_path.size() * 2));
    write_u16(66, static_cast<std::uint16_t>(dos_path.size() * 2 + 2));
    write_ptr(72, reinterpret_cast<std::uint64_t>(out + 96));
    for (std::size_t i = 0; i < dos_path.size(); ++i) {
        std::memcpy(out + 96 + i * 2, &dos_path[i], 1);
    }
    return out;
}

}  // namespace

int main() {
    // -- timer resolution: the query is real, the set is a refusal.
    {
        std::uint32_t min_r = 0, max_r = 0, current = 0;
        check(ntad2_NtQueryTimerResolution(&min_r, &max_r, &current) == kStSuccess,
              "timer: query succeeds");
        check(min_r > 0 && max_r > 0 && current > 0,
              "timer: min/max/current are real values");
        std::uint32_t actual = 0;
        check(ntad2_NtSetTimerResolution(10000, 1, &actual) == kStNotImplemented,
              "timer: set refuses with STATUS_NOT_IMPLEMENTED");
    }

    // -- the debug filter: nothing is filtered, the answer is zero.
    {
        std::uint32_t answer = 1;
        check(ntad2_NtQueryDebugFilterState(0, &answer) == kStSuccess,
              "filter: query succeeds");
        check(answer == 0, "filter: no debug filter is enabled");
    }

    // -- the alert: no guest, no pending APC, an unsuccessful alert.
    check(ntad2_NtTestAlert() == kStUnsuccessful,
          "alert: without a guest the alert is unsuccessful");

    // -- the version record: the W spelling carries the same numbers as A.
    {
        std::uint8_t a_info[148];
        std::memset(a_info, 0, sizeof(a_info));
        *reinterpret_cast<std::uint32_t*>(a_info) = 148;
        const std::int32_t a_ok = k32si_GetVersionExA(a_info);
        std::uint8_t w_info[276];
        std::memset(w_info, 0, sizeof(w_info));
        *reinterpret_cast<std::uint32_t*>(w_info) = 276;
        const std::int32_t w_ok = k32ad2_GetVersionExW(w_info);
        check(w_ok == a_ok && w_ok == 1, "version: both spellings succeed");
        const auto u32 = [](const std::uint8_t* p) {
            return *reinterpret_cast<const std::uint32_t*>(p);
        };
        check(u32(w_info + 4) == u32(a_info + 4) &&
                  u32(w_info + 8) == u32(a_info + 8) &&
                  u32(w_info + 12) == u32(a_info + 12) &&
                  u32(w_info + 16) == 2,  // VER_PLATFORM_WIN32_NT
              "version: W numbers match A and the platform id is Win32 NT");
        std::uint8_t small[276];
        *reinterpret_cast<std::uint32_t*>(small) = 100;
        check(k32ad2_GetVersionExW(small) == 0 &&
                  k32_GetLastError() == kErrorInsufficientBuffer,
              "version: an undersized record is refused");
    }

    // -- the product query: the presented version answers Ultimate.
    {
        std::uint32_t product = 0;
        check(k32ad2_GetProductInfo(10, 0, 0, 0, &product) == 1 &&
                  product == 0x30,  // PRODUCT_ULTIMATE
              "product: the presented version answers a product type");
    }

    // -- the locale ids: user and system are one account on this runtime.
    {
        const std::uint32_t lcid = k32ad2_GetUserDefaultLCID();
        check(lcid != 0, "lcid: the default locale id is real");
        check(k32ad2_GetUserDefaultLangID() == (lcid & 0xFFFF),
              "lcid: the user language is the lcid's low half");
        check(k32ad2_GetSystemDefaultLangID() == k32ad2_GetUserDefaultLangID(),
              "lcid: system and user language agree");
        char buf[32];
        const std::int32_t n =
            k32ad2_GetLocaleInfoA(lcid, 0x59 /* LOCALE_SISO639LANGNAME */,
                                  buf, sizeof(buf));
        check(n > 1 && buf[n - 1] == '\0',
              "locale: a known LCType answers a real language name");
        check(k32ad2_GetLocaleInfoA(lcid, 0x9999, buf, sizeof(buf)) == 0 &&
                  k32_GetLastError() == kErrorInvalidParameter,
              "locale: an unknown LCType is refused");
    }

    // -- the machine answers: cores, keyboard, drives, wow64 directory.
    check(k32ad2_GetActiveProcessorCount(0xFFFF) > 0,
          "processor: the online count is real");
    {
        std::uint32_t layout = 0;
        check(u32ad2_GetKeyboardLayoutList(1, &layout) == 1 &&
                  layout == 0x04090409,
              "keyboard: one en-US layout");
        check(u32ad2_GetKeyboardType(0) == 4,
              "keyboard: an enhanced 101/102-key keyboard");
        check(k32ad2_GetDriveTypeA("C:\\") == 3,  // DRIVE_FIXED
              "drive: the system drive is fixed");
        check(k32ad2_GetDriveTypeA("Q:\\") == 1,  // DRIVE_NO_ROOT_DIR
              "drive: an unmounted drive has no root");
        const std::uint32_t need =
            k32ad2_GetSystemWow64DirectoryA(nullptr, 0);
        check(need > 1, "wow64dir: the required size is real");
        char wow[64];
        check(k32ad2_GetSystemWow64DirectoryA(wow, 1) == need,
              "wow64dir: an undersized buffer answers the required size");
    }

    // -- the wow64 and DEP answers of a native 64-bit process.
    {
        std::uint32_t wow = 1;
        check(k32ad2_IsWow64Process(kPseudoHandle, &wow) == 1 && wow == 0,
              "wow64: a native process is not a wow64 process");
        std::uint16_t pm = 0xFF, nm = 0;
        check(k32ad2_IsWow64Process2(kPseudoHandle, &pm, &nm) == 1 &&
                  pm == 0 && nm == 0x8664,
              "wow64: the native machine is amd64");
        std::uint32_t flags = 0, permanent = 1;
        check(k32ad2_GetProcessDEPPolicy(kPseudoHandle, &flags, &permanent) == 1 &&
                  flags == 1 && permanent == 0,
              "dep: the process is DEP-enabled, not permanently");
        check(k32ad2_SetProcessDEPPolicy(0) == 0 &&
                  k32_GetLastError() == kErrorAccessDenied,
              "dep: a 64-bit process cannot disable DEP");
    }

    // -- the code-page query: this runtime's ANSI page is UTF-8.
    {
        std::uint8_t cpinfo[284];
        check(k32ad2_GetCPInfoExA(0 /* CP_ACP */, 0, cpinfo) == 1,
              "codepage: the ANSI page is known");
        check(k32ad2_GetCPInfoExA(65001 /* CP_UTF8 */, 0, cpinfo) == 1,
              "codepage: utf-8 is known");
        check(k32ad2_GetCPInfoExA(1252, 0, cpinfo) == 0 &&
                  k32_GetLastError() == kErrorInvalidParameter,
              "codepage: an unserved page is refused");
    }

    // -- the search: a file in no reachable directory is not found.
    {
        char buf[64];
        char* file_part = nullptr;
        check(k32ad2_SearchPathA("Z:\\no_such_dir_occ", "occ_missing.bin",
                                 nullptr, buf, sizeof(buf), &file_part) == 0 &&
                  k32_GetLastError() == kErrorFileNotFound,
              "search: a missing file is not found");
    }

    // -- the idle cycle counter reads the machine's real idle time.
    {
        std::uint64_t cycles = 0;
        check(k32ad2_QueryIdleProcessorCycleTime(&cycles) == 1 && cycles > 0,
              "idle: the idle cycle time is real");
    }

    // -- the Nt memory family: a stranger's handle and a guestless call.
    {
        std::uint64_t base = 0, size = 0x1000;
        std::uint32_t old = 0;
        check(ntsm_NtAllocateVirtualMemory(0x1234, &base, &size, 0x2000, 4) ==
                  kStInvalidHandle,
              "ntmem: a foreign process handle is refused");
        check(ntsm_NtFreeVirtualMemory(kPseudoHandle, &base, &size, 0x8000) ==
                  kStInvalidHandle,
              "ntmem: without a guest the free is refused");
        check(ntsm_NtProtectVirtualMemory(kPseudoHandle, &base, &size, 4, &old) ==
                  kStInvalidHandle,
              "ntmem: without a guest the protect is refused");
        check(k32sm_VirtualAlloc2(0x1234, nullptr, 0x1000, 0x2000, 4, nullptr, 0) ==
                  nullptr &&
                  k32_GetLastError() == kErrorInvalidHandle,
              "ntmem: the extended allocation refuses a foreign process");
    }

    // -- the mitigation policies: none are forced, and setting one refuses.
    {
        std::uint8_t policy_buf[8];
        check(k32sm_GetProcessMitigationPolicy(kPseudoHandle, 0, policy_buf, 4) ==
                  0 &&
                  k32_GetLastError() == kErrorInsufficientBuffer,
              "mitigation: an undersized buffer is refused");
        check(k32sm_GetProcessMitigationPolicy(kPseudoHandle, 999, policy_buf,
                                               sizeof(policy_buf)) == 0 &&
                  k32_GetLastError() == kErrorInvalidParameter,
              "mitigation: an unknown policy is refused");
        check(k32sm_SetProcessMitigationPolicy(0, policy_buf,
                                               sizeof(policy_buf)) == 0 &&
                  k32_GetLastError() == kErrorNotSupported,
              "mitigation: setting a policy this runtime does not enforce is refused");
    }

    // -- the thread queries: only the current process's threads answer.
    {
        check(k32sm_GetProcessIdOfThread(0x1234) == 0 &&
                  k32_GetLastError() == kErrorInvalidHandle,
              "thread: a stranger's thread handle is refused");
    }

    // -- the priority-boost pair round-trips.
    {
        std::int32_t disabled = 0;
        check(k32s2_SetProcessPriorityBoost(kPseudoHandle, 1) == 1,
              "boost: disabling the boost succeeds");
        check(k32s2_GetProcessPriorityBoost(kPseudoHandle, &disabled) == 1 &&
                  disabled == 1,
              "boost: the disabled state reads back");
        check(k32s2_SetProcessPriorityBoost(kPseudoHandle, 0) == 1 &&
                  k32s2_GetProcessPriorityBoost(kPseudoHandle, &disabled) == 1 &&
                  disabled == 0,
              "boost: the enabled state reads back");
        check(k32s2_SetProcessPriorityBoost(0x1234, 1) == 0 &&
                  k32_GetLastError() == kErrorInvalidHandle,
              "boost: a foreign process handle is refused");
    }

    // -- the loader lock and the notification registry round-trip.
    {
        std::uint64_t cookie = 0;
        std::uint32_t state = 1;
        check(ntl2_LdrLockLoaderLock(0, &cookie, &state) == kStSuccess &&
                  cookie != 0 && state == 0,
              "ldrlock: the lock hands out a cookie and a healthy state");
        check(ntl2_LdrUnlockLoaderLock(0, cookie) == kStSuccess,
              "ldrlock: the cookie unlocks");
        check(ntl2_LdrUnlockLoaderLock(0, 0x1234) == kStInvalidParameter,
              "ldrlock: a stranger's cookie is refused");
        std::uint64_t notif = 0;
        check(ntl2_LdrRegisterDllNotification(
                  0, reinterpret_cast<std::uint64_t>(
                         reinterpret_cast<void*>(&dummy_notification)),
                  0, &notif) == kStSuccess &&
                  notif != 0,
              "ldrnotif: a notification registers");
        check(ntl2_LdrUnregisterDllNotification(notif) == kStSuccess,
              "ldrnotif: the registered notification unregisters");
        check(ntl2_LdrUnregisterDllNotification(notif) == kStInvalidParameter,
              "ldrnotif: an unknown notification cookie is refused");
        check(ntl2_LdrUnloadDll(0x1234) == kStInvalidHandle,
              "ldrunload: without a guest no module answers");
    }

    // -- the random and TEB queries.
    {
        std::uint8_t rand_buf[32];
        check(ntf2_RtlGenRandom(rand_buf, sizeof(rand_buf)) == 1,
              "random: the fill succeeds");
        bool nonzero = false;
        for (std::uint8_t b : rand_buf) {
            nonzero = nonzero || b != 0;
        }
        check(nonzero, "random: the fill is not all zero");
        check(ntf2_RtlGenRandom(rand_buf, 0) == 1, "random: zero length is fine");
        check(ntf2_RtlGetCurrentTeb() == nullptr,
              "teb: without a guest there is no teb");
    }

    // -- the UI languages and the locale name: one language, the default.
    {
        std::uint32_t num = 0, size = 64;
        char16_t lang[64];
        check(k32sm_GetPreferredUILanguages(0x8 /* MUI_LANGUAGE_NAME */, &num,
                                            lang, &size) == 1 &&
                  num == 1,
              "uilang: one preferred language");
        char16_t name[64];
        check(k32sm_GetSystemDefaultLocaleName(name, 64) > 0,
              "locname: the system locale name is real");
    }

    // -- the IsBad* families: null is bad, an address is judged by the map.
    {
        check(k32chk_IsBadReadPtr(nullptr, 0) == 1, "isbad: null is bad");
        check(k32chk_IsBadReadPtr(reinterpret_cast<const void*>(0x1000), 16) == 0,
              "isbad: without a guest every address is this process's");
        check(k32chk_IsBadWritePtr(reinterpret_cast<const void*>(0x2000), 16) == 0,
              "isbad: the write check agrees");
        check(k32chk_IsBadCodePtr(nullptr) == 1, "isbad: null code is bad");
    }

    // -- the process queries: a stranger's handle is refused everywhere.
    {
        char buf[64];
        std::uint32_t size = sizeof(buf);
        check(k32chk_QueryFullProcessImageNameA(0x1234, 0, buf, &size) == 0 &&
                  k32_GetLastError() == kErrorInvalidHandle,
              "image: a foreign process handle is refused");
        std::uint8_t io[48];
        check(k32chk_GetProcessIoCounters(0x1234, io) == 0 &&
                  k32_GetLastError() == kErrorInvalidHandle,
              "io: a foreign process handle is refused");
        check(k32chk_GetFirmwareEnvironmentVariableA(
                  "x", "{00000000-0000-0000-0000-000000000000}", buf,
                  sizeof(buf)) == 0 &&
                  k32_GetLastError() == kErrorInvalidFunction,
              "firmware: no uefi namespace answers");
        check(k32chk_GetGuiResources(0x1234, 0) == 0,
              "gui: no gui resources exist");
    }

    // -- the Nt file lifecycle: create, write, query, seek, read, lock,
    //    compress-size, close, all on the host.
    {
        const std::string path = "Z:\\tmp\\occ_ntf2_test.bin";
        // A clean slate: an earlier run may have left the file, and FILE_CREATE
        // must be able to create it fresh.
        ::unlink("/tmp/occ_ntf2_test.bin");
        std::uint8_t oa_buf[160];
        const std::uint8_t* oa = build_object_attributes(
            oa_buf, sizeof(oa_buf), path);
        std::uint64_t handle = 0;
        std::uint8_t iosb[16];
        std::memset(iosb, 0, sizeof(iosb));
        const std::uint32_t status = ntf2_NtCreateFile(
            &handle, kGenericReadWrite, oa, iosb, nullptr,
            kFileAttributeNormal, 0, kFileCreate, 0, nullptr, 0);
        check(status == kStSuccess && handle >= 0x2000,
              "ntfile: create makes a file handle");
        check(*reinterpret_cast<std::uint32_t*>(iosb) == kStSuccess &&
                  *reinterpret_cast<std::uint64_t*>(iosb + 8) == 2,
              "ntfile: the io status reports the file was created");

        std::memset(iosb, 0, sizeof(iosb));
        const std::uint64_t use_position = kFileUseFilePointerPosition;
        const std::uint32_t wrote = ntf2_NtWriteFile(
            handle, 0, 0, 0, iosb, "hello", 5, &use_position, 0);
        check(wrote == kStSuccess &&
                  *reinterpret_cast<std::uint64_t*>(iosb + 8) == 5,
              "ntfile: the write lands five bytes");

        std::uint8_t std_info[24];
        std::memset(iosb, 0, sizeof(iosb));
        check(ntf2_NtQueryInformationFile(handle, iosb, std_info,
                                          sizeof(std_info),
                                          kFileStandardInformation) ==
                  kStSuccess &&
                  *reinterpret_cast<std::uint64_t*>(std_info + 8) == 5,
              "ntfile: the standard information reports the size");

        check(k32f3_SetFilePointer(reinterpret_cast<void*>(handle), 0, nullptr,
                                   0 /* FILE_BEGIN */) == 0,
              "ntfile: the pointer moves back to the start");
        std::memset(iosb, 0, sizeof(iosb));
        char read_buf[8] = {0};
        const std::uint32_t read = ntf2_NtReadFile(
            handle, 0, 0, 0, iosb, read_buf, 5, &use_position, 0);
        check(read == kStSuccess && std::memcmp(read_buf, "hello", 5) == 0,
              "ntfile: the read round-trips the write");

        check(k32f3_LockFile(reinterpret_cast<void*>(handle), 0, 0, 1, 0) == 1,
              "ntfile: the lock lands");
        check(k32f3_UnlockFile(reinterpret_cast<void*>(handle), 0, 0, 1, 0) == 1,
              "ntfile: the unlock lands");

        std::uint32_t high = 1;
        struct ::stat st {};
        check(::stat("/tmp/occ_ntf2_test.bin", &st) == 0 &&
                  k32f3_GetCompressedFileSizeA("Z:\\tmp\\occ_ntf2_test.bin",
                                               &high) ==
                      static_cast<std::uint32_t>(st.st_blocks * 512) &&
                  high == 0,
              "ntfile: the compressed size is the allocated size");

        check(nt_NtClose(handle) == kStSuccess, "ntfile: the close lands");
        // A handle that names nothing closes successfully by this runtime's
        // documented design -- `CloseHandle` answers an unknown handle as a
        // valid handle with no resources behind it -- so a second close of
        // the same value is an idempotent success, not an invalid handle.
        check(nt_NtClose(handle) == kStSuccess,
              "ntfile: a second close is an idempotent success");

        // A path whose directory is absent fails with the path status.
        std::uint8_t oa_bad[160];
        const std::uint8_t* oa2 = build_object_attributes(
            oa_bad, sizeof(oa_bad), "Z:\\no_dir_xyz_occ\\f.bin");
        std::uint64_t h2 = 0;
        std::memset(iosb, 0, sizeof(iosb));
        check(ntf2_NtCreateFile(&h2, kGenericReadWrite, oa2, iosb, nullptr,
                                kFileAttributeNormal, 0, kFileCreate, 0,
                                nullptr, 0) == kStObjectPathNotFound,
              "ntfile: a missing directory answers the path status");

        // The open pair: an existing file opens, a missing one does not.
        std::uint8_t oa_open[160];
        const std::uint8_t* oa3 = build_object_attributes(
            oa_open, sizeof(oa_open), path);
        std::uint64_t h3 = 0;
        std::memset(iosb, 0, sizeof(iosb));
        check(ntf2_NtOpenFile(&h3, 0x80000000 /* GENERIC_READ */, oa3, iosb, 0,
                              0) == kStSuccess,
              "ntfile: the open finds the created file");
        check(nt_NtClose(h3) == kStSuccess, "ntfile: the open handle closes");
        std::uint8_t oa_miss[160];
        const std::uint8_t* oa4 = build_object_attributes(
            oa_miss, sizeof(oa_miss), "Z:\\tmp\\occ_ntf2_missing.bin");
        std::uint64_t h4 = 0;
        std::memset(iosb, 0, sizeof(iosb));
        check(ntf2_NtOpenFile(&h4, 0x80000000, oa4, iosb, 0, 0) ==
                  kStObjectNameNotFound,
              "ntfile: a missing file answers the name status");
    }

    // -- the path queries: short names are the long names on this volume.
    {
        char buf[128];
        const std::uint32_t n = k32f3_GetShortPathNameA(
            "Z:\\tmp\\occ_ntf2_test.bin", buf, sizeof(buf));
        check(n == std::strlen("Z:\\tmp\\occ_ntf2_test.bin") &&
                  std::strcmp(buf, "Z:\\tmp\\occ_ntf2_test.bin") == 0,
              "shortpath: a volume without 8.3 names answers the path itself");
        check(k32f3_GetVolumePathNameA("Z:\\tmp\\occ_ntf2_test.bin", buf,
                                       sizeof(buf)) == 1 &&
                  std::strcmp(buf, "Z:\\") == 0,
              "volpath: the path names the Z: volume");
        check(k32f3_FlushViewOfFile(reinterpret_cast<const void*>(&buf), 1) == 0 &&
                  k32_GetLastError() == kErrorInvalidAddress,
              "flush: an unmapped address is refused");
    }

    // -- the hard link: a real second name for the same file.
    {
        check(k32f3_CreateHardLinkA("Z:\\tmp\\occ_ntf2_hard.bin",
                                    "Z:\\tmp\\occ_ntf2_test.bin",
                                    nullptr) == 1,
              "hardlink: the link lands");
        struct ::stat a {};
        struct ::stat b {};
        check(::stat("/tmp/occ_ntf2_test.bin", &a) == 0 &&
                  ::stat("/tmp/occ_ntf2_hard.bin", &b) == 0 && a.st_ino == b.st_ino,
              "hardlink: both names are the same inode");
        ::unlink("/tmp/occ_ntf2_hard.bin");
    }

    // -- the string families: case, pointer walk and the OEM round-trip.
    {
        char narrow[8];
        std::memcpy(narrow, "aBc", 4);
        check(u32sc_CharUpperA(narrow) == narrow &&
                  std::strcmp(narrow, "ABC") == 0,
              "char: CharUpperA uppercases in place");
        check(u32sc_CharLowerA(narrow) == narrow &&
                  std::strcmp(narrow, "abc") == 0,
              "char: CharLowerA lowercases in place");
        char16_t wide[8];
        std::memcpy(wide, u"XyZ", 8);
        check(u32sc_CharUpperW(wide) == wide && wide[0] == u'X' &&
                  wide[1] == u'Y' && wide[2] == u'Z',
              "char: CharUpperW uppercases in place");
        std::memcpy(wide, u"XyZ", 8);
        check(u32sc_CharLowerW(wide) == wide && wide[0] == u'x' &&
                  wide[1] == u'y' && wide[2] == u'z',
              "char: CharLowerW lowercases in place");

        // The UTF-8 walk: 'A' is one byte, U+00E4 is two.
        const char utf8[] = {'A', static_cast<char>(0xC3),
                             static_cast<char>(0xA4), '\0'};
        const char* p = utf8;
        check(u32sc_AnsiNext(p) == p + 1, "ansi: next advances one byte");
        check(u32sc_AnsiNext(p + 1) == p + 3,
              "ansi: next advances across a two-byte character");
        check(u32sc_AnsiPrev(utf8, p + 3) == p + 1,
              "ansi: prev steps back to the character start");
        check(u32sc_AnsiPrev(utf8, utf8) == utf8,
              "ansi: prev at the start stays at the start");

        char oem[8];
        char16_t back[8];
        check(k32sc_CharToOemW(u"Ab", oem) == 1, "oem: the conversion runs");
        check(k32sc_OemToCharW(oem, back) == 1 && back[0] == u'A' &&
                  back[1] == u'b',
              "oem: the round trip restores the text");
    }

    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::fprintf(stderr, "%d checks passed\n", checks);
    return 0;
}

// The Windows API surface, split into domains.
//
// `winabi.cpp` holds the machinery that makes a guest's call arrive at a
// host function: the ABI stubs, the calling convention, the argument
// marshalling for the calls whose guest form differs from the host's. It
// was also holding every handler, which was fine at two hundred of them and
// is not at twenty thousand.
//
// A domain here owns one area of the API and contributes the names it
// implements. A module is a name plus the domains that make it up:
// KERNEL32 is the file domain and the path domain and the synchronization
// domain, and no single translation unit has to know how many others there
// are. Adding a name is adding a line to a domain's list; adding an area is
// adding a file.
//
// What a domain does not do is decide whether a name exists. The list it
// contributes is the module's export table, and a name absent from it is a
// name the module does not export -- which the loader reports to the guest
// the way the operating system does, rather than by answering a null
// address.

#ifndef OCC_RUNTIME_API_H
#define OCC_RUNTIME_API_H

#include "occ/runtime/exports.h"

#include <cstdint>
#include <vector>

namespace occ::runtime::winabi {

// One module's exports, as the domains fill it. Domains append, so that the
// order they are called in decides the order of the table and nothing else;
// two domains that export the same name are a mistake the registry reports
// rather than one where the later quietly wins.
using ExportList = std::vector<HostExport>;

// -------------------------------------------------------------------- paths

// The path grammar Windows uses, which is not the host's. A Windows path is
// `C:\dir\name.ext`, a UNC path adds `\\server\share\`, and both are
// handled here rather than by handing the string to the host and taking
// whatever it makes of it -- `/tmp/a` is a path on this machine and a
// relative path with a drive-less root on Windows, and a runtime that
// conflates them reports the wrong thing about a guest that meant the
// second.
//
// The rules these follow are Microsoft's, as Wine implements them:
// `dlls/shlwapi/path.c` for the SHLWAPI family and `dlls/kernelbase/path.c`
// for the Cch family that replaced it.
void add_path_shlwapi(ExportList& out);
void add_path_cch(ExportList& out);

// The entry points themselves, so that a test can call what a guest calls
// without going through a load. Each is the address the registry hands an
// import, and the compiler bridges the convention on the way in, which is
// what a guest's `call [iat]` does. They are declared here rather than in a
// private header because the tests are the reason they are visible at all.
extern "C" __attribute__((ms_abi)) char* sw_PathAddBackslashA(
    char* path) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_PathAddBackslashW(
    char16_t* path) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_PathRemoveBackslashA(
    char* path) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_PathRemoveBackslashW(
    char16_t* path) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_PathRemoveFileSpecA(
    char* path) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_PathRemoveFileSpecW(
    char16_t* path) noexcept;
extern "C" __attribute__((ms_abi)) void sw_PathStripPathA(char* path) noexcept;
extern "C" __attribute__((ms_abi)) void sw_PathStripPathW(
    char16_t* path) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_PathFindExtensionA(
    const char* path) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_PathFindExtensionW(
    const char16_t* path) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_PathFindFileNameA(
    const char* path) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_PathFindFileNameW(
    const char16_t* path) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_PathFindNextComponentA(
    const char* path) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_PathFindNextComponentW(
    const char16_t* path) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_PathGetDriveNumberA(
    const char* path) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_PathGetDriveNumberW(
    const char16_t* path) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_PathGetArgsA(
    const char* path) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_PathGetArgsW(
    const char16_t* path) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_PathSkipRootA(
    const char* path) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_PathSkipRootW(
    const char16_t* path) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_PathIsRootA(
    const char* path) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_PathIsRootW(
    const char16_t* path) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_PathIsRelativeA(
    const char* path) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_PathIsRelativeW(
    const char16_t* path) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_PathCommonPrefixA(
    const char* a, const char* b, char* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_PathCommonPrefixW(
    const char16_t* a, const char16_t* b, char16_t* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_PathAppendA(
    char* base, const char* more) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_PathAppendW(
    char16_t* base, const char16_t* more) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_PathCombineA(char* out,
                                                         const char* dir,
                                                         const char* file)
    noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_PathCombineW(
    char16_t* out, const char16_t* dir, const char16_t* file) noexcept;

// -------------------------------------------------------------------- strings

// The string helpers SHLWAPI exports. These are the `Str*` family: bounded
// copies, case-insensitive compares, substring searches, and the integer
// parsers. They are CRT-adjacent but not CRT: the bounds are checked
// differently, the failure answers are different, and `StrCmpLogicalW` sorts
// the way Explorer sorts, which is unlike anything in any C library.
void add_string_shlwapi(ExportList& out);
void add_string_kernelbase(ExportList& out);

// ------------------------------------------------------------------- files

// The file and directory family: attributes, directories, the current
// directory, full paths, the temporary directory, copies and moves. These
// answer through the host's own file system, so what each one decides is how
// the host's answer reads as a Windows one; the decisions are in the file.
void add_file_kernel32(ExportList& out);

// -------------------------------------------------------------------- time

// The time family: the two Windows clocks, the conversions between them and
// the host's, and the zone query. Every conversion here is between a tick
// count from the start of 1601, a broken-down calendar date, and the host's
// own count from the start of 1970.
void add_time_kernel32(ExportList& out);

// ----------------------------------------------------------------- memory

// The memory family: the three allocators that all mean the process heap,
// the virtual-memory calls that answer through the host's own mappings, and
// the two process-memory calls that are a copy because the guest's address
// space is this process's.
void add_memory_kernel32(ExportList& out);

// ---------------------------------------------------------------- console

// The console family and the handle family. A run this runtime performs has
// its standard handles redirected, so the console calls answer the way
// Windows answers a redirected process rather than inventing a console;
// `GetFileType` reads the descriptor and reports what it actually is, which
// is what decides which path a caller takes.
void add_console_kernel32(ExportList& out);

extern "C" __attribute__((ms_abi)) void* k32m_VirtualAlloc(
    void* address, std::uint64_t size, std::uint32_t type,
    std::uint32_t protect) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32m_VirtualFree(
    void* address, std::uint64_t size, std::uint32_t type) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32m_VirtualProtect(
    void* address, std::uint64_t size, std::uint32_t protect,
    std::uint32_t* old) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32m_VirtualQuery(
    const void* address, std::uint8_t* out, std::uint64_t out_size) noexcept;
extern "C" __attribute__((ms_abi)) void* k32m_GlobalAlloc(
    std::uint32_t flags, std::uint64_t bytes) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32m_GlobalFree(
    void* block) noexcept;
extern "C" __attribute__((ms_abi)) void* k32m_LocalAlloc(
    std::uint32_t flags, std::uint64_t bytes) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32m_LocalFree(
    void* block) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32m_GlobalSize(
    const void* block) noexcept;
extern "C" __attribute__((ms_abi)) void* k32m_HeapAlloc(
    std::uint64_t heap, std::uint32_t flags, std::uint64_t bytes) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32m_HeapFree(
    std::uint64_t heap, std::uint32_t flags, void* block) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32m_ReadProcessMemory(
    std::uint64_t process, const void* address, void* buffer,
    std::uint64_t bytes, std::uint64_t* read) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32m_WriteProcessMemory(
    std::uint64_t process, void* address, const void* buffer,
    std::uint64_t bytes, std::uint64_t* written) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32c_GetFileType(
    std::uint64_t handle) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32c_GetConsoleMode(
    std::uint64_t handle, std::uint32_t* mode) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32c_WriteConsoleA(
    std::uint64_t handle, const void* buffer, std::uint32_t length,
    std::uint32_t* written, void* reserved) noexcept;
extern "C" __attribute__((ms_abi)) void* k32c_GetConsoleWindow() noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32c_SetConsoleCtrlHandler(
    std::uint64_t handler, std::int32_t add) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32c_DuplicateHandle(
    std::uint64_t from_process, std::uint64_t source, std::uint64_t to_process,
    std::uint64_t* target, std::uint32_t access, std::int32_t inherit,
    std::uint32_t options) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32c_GetHandleInformation(
    std::uint64_t handle, std::uint32_t* flags) noexcept;

// The control routines a guest registered through `SetConsoleCtrlHandler`.
// Exposed so that the registration is a fact something reads rather than one
// that is recorded and dropped.
[[nodiscard]] std::size_t console_ctrl_handler_count() noexcept;
[[nodiscard]] std::uint64_t console_ctrl_handler(std::size_t index) noexcept;

extern "C" __attribute__((ms_abi)) void k32t_GetSystemTime(
    std::uint8_t* out) noexcept;
extern "C" __attribute__((ms_abi)) void k32t_GetLocalTime(
    std::uint8_t* out) noexcept;
extern "C" __attribute__((ms_abi)) void k32t_GetSystemTimeAsFileTime(
    std::uint8_t* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_SetSystemTime(
    const std::uint8_t* in) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_SetLocalTime(
    const std::uint8_t* in) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_SystemTimeToFileTime(
    const std::uint8_t* in, std::uint8_t* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_FileTimeToSystemTime(
    const std::uint8_t* in, std::uint8_t* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_FileTimeToLocalFileTime(
    const std::uint8_t* in, std::uint8_t* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_LocalFileTimeToFileTime(
    const std::uint8_t* in, std::uint8_t* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_CompareFileTime(
    const std::uint8_t* a, const std::uint8_t* b) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32t_GetTickCount() noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32t_GetTickCount64() noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32t_GetTimeZoneInformation(
    std::uint8_t* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t
k32t_SystemTimeToTzSpecificLocalTime(const std::uint8_t* zone,
                                     const std::uint8_t* utc,
                                     std::uint8_t* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t
k32t_TzSpecificLocalTimeToSystemTime(const std::uint8_t* zone,
                                     const std::uint8_t* local,
                                     std::uint8_t* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32t_GetSystemTimes(
    std::uint8_t* idle, std::uint8_t* kernel, std::uint8_t* user) noexcept;

extern "C" __attribute__((ms_abi)) std::uint32_t k32b_GetFileAttributesA(
    const char* path) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32b_GetFileAttributesW(
    const char16_t* path) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32b_SetFileAttributesA(
    const char* path, std::uint32_t attributes) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32b_SetFileAttributesW(
    const char16_t* path, std::uint32_t attributes) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32b_GetFileAttributesExA(
    const char* path, std::int32_t level, void* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32b_GetFileAttributesExW(
    const char16_t* path, std::int32_t level, void* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32b_CreateDirectoryA(
    const char* path, void* security) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32b_CreateDirectoryW(
    const char16_t* path, void* security) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32b_RemoveDirectoryA(
    const char* path) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32b_RemoveDirectoryW(
    const char16_t* path) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32b_GetCurrentDirectoryA(
    std::uint32_t capacity, char* out) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32b_GetCurrentDirectoryW(
    std::uint32_t capacity, char16_t* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32b_SetCurrentDirectoryA(
    const char* path) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32b_SetCurrentDirectoryW(
    const char16_t* path) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32b_GetFullPathNameA(
    const char* path, std::uint32_t capacity, char* out,
    char** file_part) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32b_GetFullPathNameW(
    const char16_t* path, std::uint32_t capacity, char16_t* out,
    char16_t** file_part) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32b_GetTempPathA(
    std::uint32_t capacity, char* out) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t k32b_GetTempPathW(
    std::uint32_t capacity, char16_t* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32b_CopyFileA(
    const char* from, const char* to, std::int32_t fail_if_exists) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32b_CopyFileW(
    const char16_t* from, const char16_t* to,
    std::int32_t fail_if_exists) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32b_MoveFileA(
    const char* from, const char* to) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32b_MoveFileW(
    const char16_t* from, const char16_t* to) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32b_MoveFileExA(
    const char* from, const char* to, std::uint32_t flags) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32b_MoveFileExW(
    const char16_t* from, const char16_t* to, std::uint32_t flags) noexcept;

// The `Str*` entry points. The signatures are the headers', and the ones
// worth reading twice are the two where a plausible guess is wrong:
// `StrChr` takes the character as a 16-bit value and not an `int`, and
// `StrTrim` takes the set of characters to remove and not a flag.
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCSpnA(
    const char* text, const char* set) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCSpnW(
    const char16_t* text, const char16_t* set) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCSpnIA(
    const char* text, const char* set) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCSpnIW(
    const char16_t* text, const char16_t* set) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_StrChrA(
    const char* text, std::uint16_t match) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_StrChrW(
    const char16_t* text, char16_t match) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_StrChrIA(
    const char* text, std::uint16_t match) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_StrChrIW(
    const char16_t* text, char16_t match) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_StrChrNW(
    const char16_t* text, char16_t match, std::uint32_t bound) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_StrRChrA(
    const char* text, const char* end, std::uint16_t match) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_StrRChrW(
    const char16_t* text, const char16_t* end, char16_t match) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_StrRChrIA(
    const char* text, const char* end, std::uint16_t match) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_StrRChrIW(
    const char16_t* text, const char16_t* end, char16_t match) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_StrPBrkA(const char* text,
                                                     const char* set) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_StrPBrkW(
    const char16_t* text, const char16_t* set) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrSpnA(
    const char* text, const char* set) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrSpnW(
    const char16_t* text, const char16_t* set) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_StrStrA(const char* hay,
                                                    const char* needle) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_StrStrW(
    const char16_t* hay, const char16_t* needle) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_StrStrIA(
    const char* hay, const char* needle) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_StrStrIW(
    const char16_t* hay, const char16_t* needle) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_StrStrNW(
    const char16_t* hay, const char16_t* needle, std::uint32_t bound) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_StrStrNIW(
    const char16_t* hay, const char16_t* needle, std::uint32_t bound) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_StrRStrIA(
    const char* hay, const char* last, const char* needle) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_StrRStrIW(
    const char16_t* hay, const char16_t* last, const char16_t* needle) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpW(
    const char16_t* a, const char16_t* b) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpIW(
    const char16_t* a, const char16_t* b) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpCA(
    const char* a, const char* b) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpCW(
    const char16_t* a, const char16_t* b) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpICA(
    const char* a, const char* b) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpICW(
    const char16_t* a, const char16_t* b) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpNA(
    const char* a, const char* b, std::int32_t bound) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpNW(
    const char16_t* a, const char16_t* b, std::int32_t bound) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpNCA(
    const char* a, const char* b, std::int32_t bound) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpNCW(
    const char16_t* a, const char16_t* b, std::int32_t bound) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpNIA(
    const char* a, const char* b, std::int32_t bound) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpNIW(
    const char16_t* a, const char16_t* b, std::int32_t bound) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpNICA(
    const char* a, const char* b, std::int32_t bound) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpNICW(
    const char16_t* a, const char16_t* b, std::int32_t bound) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrCmpLogicalW(
    const char16_t* a, const char16_t* b) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrIsIntlEqualA(
    std::int32_t case_sensitive, const char* a, const char* b,
    std::int32_t bound) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrIsIntlEqualW(
    std::int32_t case_sensitive, const char16_t* a, const char16_t* b,
    std::int32_t bound) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_StrCpyNW(
    char16_t* dest, const char16_t* source, std::int32_t capacity) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_StrCpyNXA(
    char* dest, const char* source, std::int32_t capacity) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_StrCpyNXW(
    char16_t* dest, const char16_t* source, std::int32_t capacity) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_StrCatBuffA(
    char* dest, const char* source, std::int32_t capacity) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_StrCatBuffW(
    char16_t* dest, const char16_t* source, std::int32_t capacity) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t sw_StrCatChainW(
    char16_t* dest, std::uint32_t capacity, std::uint32_t at,
    const char16_t* source) noexcept;
extern "C" __attribute__((ms_abi)) char* sw_StrDupA(const char* text) noexcept;
extern "C" __attribute__((ms_abi)) char16_t* sw_StrDupW(
    const char16_t* text) noexcept;
extern "C" __attribute__((ms_abi)) void sw_StrTrimA(char* text,
                                                    const char* set) noexcept;
extern "C" __attribute__((ms_abi)) void sw_StrTrimW(
    char16_t* text, const char16_t* set) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrToIntA(
    const char* text) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrToIntW(
    const char16_t* text) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrToIntExA(
    const char* text, std::int32_t flags, std::int32_t* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrToIntExW(
    const char16_t* text, std::int32_t flags, std::int32_t* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrToInt64ExA(
    const char* text, std::int32_t flags, std::int64_t* out) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t sw_StrToInt64ExW(
    const char16_t* text, std::int32_t flags, std::int64_t* out) noexcept;

// ------------------------------------------------------- the domains

// A module whose whole surface is domains is built by one function per
// module, in `runtime/api/modules.cpp`, and named in the table in
// `winabi.cpp`. A domain that extends a module this file already builds is
// named the same way and is appended by that module's own function, so the
// list of names a module exports is the union of the domains it is made of
// and nothing else.
// The KERNEL32 names that are not file, path, time, memory or console.
void add_kernel32_extra(ExportList& out);

// The KERNEL32 synchronization surface: the wait, the objects a wait can
// name, and the timers and thread-pool entries that hang off them. A wait
// is where a guest blocks, so this is the one area whose answer has a
// shape -- a wait consumes an auto-reset event's signal, it does not
// merely observe it -- and the distinction is in the file.
void add_kernel32_sync(ExportList& out);

// The KERNEL32 process, thread and environment surface. A guest's command
// line and its environment are answered from the one parse the runtime
// built before the guest started, so the three spellings of a command line
// cannot disagree with each other.
void add_kernel32_proc(ExportList& out);

// The KERNEL32 string surface: the `lstr*` family, the code-page
// conversions and the locale-driven compares. The `W` spellings carry the
// decisions and the `A` ones convert, because two implementations of one
// function is one more thing to keep in agreement.
void add_kernel32_str(ExportList& out);

// The KERNEL32 error surface: the last-error storage, the error mode, and
// the message formatter. `FormatMessage` is the one that earns this file
// -- its format is a language of its own, with position arguments and type
// suffixes, and a guest that reads an unformatted message cannot tell it
// from a missing one.
void add_kernel32_err(ExportList& out);

// The second slice of kernel32's system-information family: the environment
// block, the code pages, the processor set, the physical memory report and
// the process-wide switches that go with them.
void add_kernel32_sys2(ExportList& out);

// kernel32's file-by-name and directory-walk calls, and the module and
// thread-state calls that reach facilities the Rtl slices own.
void add_kernel32_file2(ExportList& out);
void add_kernel32_state2(ExportList& out);

// kernel32's context, exception and module calls: the pair a debugger
// builds on, the filter a process registers, and the bookkeeping that goes
// with asking about the image.
void add_kernel32_ctx2(ExportList& out);

// kernel32's handle-oriented I/O calls: the device control, the overlapped
// result, the cancellation, and the file-information setter.
void add_kernel32_io2(ExportList& out);

// The KERNELBASE names a guest imports from it directly.
void add_kernelbase_extra(ExportList& out);

// The USER32 surface beyond the two printf-style names already here.
void add_user32_extra(ExportList& out);

// The window station: the classes, the windows, the queue, the
// clipboard, the keyboard, the menus and the dialogs, as one headless
// station keeps them.
void add_user32_windows(ExportList& out);

// The process-status surface: the module list, the memory counters and
// the performance view, answered from this runtime's own state.
void add_psapi(ExportList& out);

// The version-information surface, read from the file itself.
void add_version(ExportList& out);

// The Rtl* half of ntdll: memory, strings, bits, sections, version.
void add_ntdll_rtl(ExportList& out);

// The Rtl* string surface: `UNICODE_STRING` and its siblings. The lengths
// in that structure are byte counts that exclude the terminator, and every
// function here is a different way of being wrong about that -- a length
// in characters, a length that includes the terminator, a compare that
// runs to the terminator instead of to the length.
void add_ntdll_rtl_str(ExportList& out);

// The Rtl* heap, bitmap, list and integer surface. The bitmaps are
// MSB-first over a ULONG array and the lists are the kernel's doubly-linked
// ones with a self-referential empty list, neither of which is what a host
// library of the same name does.
void add_ntdll_rtl_mem1(ExportList& out);

// The Rtl* surface's second slice: the lock-free stack, the security
// descriptor accessors, the large-integer arithmetic, the bitmap queries,
// the version and path queries, the 8.3 name generation and the atom-table
// lookups the first slice's tables answer through.
void add_ntdll_rtl_mem2(ExportList& out);

// The Rtl* surface's third slice: the clock arithmetic, the pseudo-random
// generators, the heap queries, the lock and run-once families, the
// environment blocks, the descriptor builders, the splay and red-black
// tree surgery, and the language and error-mode state.
void add_ntdll_rtl_mem3(ExportList& out);

// The Nt* and Zw* half of ntdll. In user mode the two are one function.
void add_ntdll_nt(ExportList& out);

// The GDI32 surface.
void add_gdi32(ExportList& out);

// The ADVAPI32 surface: registry, tokens, services, events.
void add_advapi32(ExportList& out);

// The registry half of ADVAPI32. The keys are a tree this runtime keeps
// rather than a mapping onto a host file, because a host has no registry
// and a mapping onto one directory would be a different thing with the
// same name: the seven predefined roots are handles with fixed values, and
// a key opened and closed is a handle that stops naming anything.
void add_advapi32_reg(ExportList& out);

// The security half of ADVAPI32: SIDs, tokens, descriptors, ACLs and
// accounts. The SID accessors answer pointers into the caller's own buffer
// rather than copies, which is the one behaviour here a caller is allowed
// to write through.
void add_advapi32_sec(ExportList& out);

// The RPCRT4 surface.
void add_rpcrt4(ExportList& out);

// The SETUPAPI surface.
void add_setupapi(ExportList& out);

// The SHELL32 surface.
void add_shell32(ExportList& out);

// The CRYPT32 surface.
void add_crypt32(ExportList& out);

// The OLE32 surface.
void add_ole32(ExportList& out);

// The C runtime. One implementation serves every module that exports it:
// `ucrtbase` is the modern base and the `msvcr*` names re-export the same
// functions, so the module argument selects which subset is registered
// rather than which implementation is used. Splitting the family into
// fourteen copies of the same table is how the family is built on Windows
// and how it would be built here, and it is not what a reader needs.
void add_crt(ExportList& out, const char* module);

// The C runtime's exports, as one list. Every module that presents the C
// runtime -- `ucrtbase.dll`, `msvcrt.dll`, and the versioned `MSVCR*.dll`
// family -- registers this same list, because a program built against any
// of them calls the same functions and a per-module copy would let the
// copies disagree about what the runtime provides.
void add_crt_exports(ExportList& out);

// The modules built from domains, named once each.
void add_module_ntdll(ExportModule& module);
void add_module_gdi32(ExportModule& module);
void add_module_advapi32(ExportModule& module);
void add_module_rpcrt4(ExportModule& module);
void add_module_setupapi(ExportModule& module);
void add_module_shell32(ExportModule& module);
void add_module_crypt32(ExportModule& module);
// The platform cryptography surface: the hash providers, the objects built
// from them, and the random generator. The algorithms themselves live in the
// domain file, written out rather than borrowed.
void add_bcrypt(ExportList& out);
void add_bcryptprimitives(ExportList& out);
void add_winmm(ExportList& out);
void add_mscoree(ExportList& out);
void add_module_bcrypt(ExportModule& module);
void add_module_bcryptprimitives(ExportModule& module);
void add_module_winmm(ExportModule& module);
void add_module_mscoree(ExportModule& module);

// The WinSock surface: the sockets themselves, the address conversion
// between the guest's layout and the host's, and name resolution, which is
// carried out by the host's own resolver.
void add_ws2_32(ExportList& out);
void add_module_ws2_32(ExportModule& module);

// The interface and address tables: the machine's own view of what it can
// reach, translated into the structures this module promises.
void add_iphlpapi(ExportList& out);
void add_module_iphlpapi(ExportModule& module);

void add_module_ole32(ExportModule& module);
void add_module_ucrtbase(ExportModule& module);
void add_module_msvcr70(ExportModule& module);
void add_module_msvcr71(ExportModule& module);
void add_module_msvcr80(ExportModule& module);
void add_module_msvcr90(ExportModule& module);
void add_module_msvcr100(ExportModule& module);
void add_module_msvcr110(ExportModule& module);
void add_module_msvcr120(ExportModule& module);
void add_module_msvcr120_app(ExportModule& module);
void add_module_msvcrtd(ExportModule& module);
void add_module_msvcrt20(ExportModule& module);
void add_module_msvcrt40(ExportModule& module);
void add_module_msvcirt(ExportModule& module);

}  // namespace occ::runtime::winabi

#endif  // OCC_RUNTIME_API_H

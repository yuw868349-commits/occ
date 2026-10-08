// The memory and console families.
//
// The memory calls answer through the host's own allocations, so what a test
// can check is that a block the guest is handed is one it can read and write
// and that the sizes come back the way Windows reports them. The console
// calls answer the way Windows answers a redirected process, which is the
// state every run here is in -- so the checks below are that they fail, and
// fail with the error a caller branches on.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

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

constexpr std::uint32_t kMemReserve = 0x00002000;
constexpr std::uint32_t kMemCommit = 0x00001000;
constexpr std::uint32_t kMemRelease = 0x00008000;
constexpr std::uint32_t kMemPrivate = 0x00020000;
constexpr std::uint32_t kPageReadOnly = 0x02;
constexpr std::uint32_t kPageReadWrite = 0x04;
constexpr std::uint64_t kCurrentProcess = 0xFFFFFFFFFFFFFFFFULL;
constexpr std::uint32_t kErrorInvalidHandle = 6;

void test_virtual_memory() {
    // A commit-and-reserve is one mapping on this host, and the returned
    // block is one the guest can actually use -- which is what the write
    // below checks rather than assuming.
    void* block = k32m_VirtualAlloc(nullptr, 4096, kMemCommit | kMemReserve,
                                    kPageReadWrite);
    check(block != nullptr, "memory: a committed region is mapped");
    if (block != nullptr) {
        auto* bytes = static_cast<std::uint8_t*>(block);
        bytes[0] = 0xAB;
        bytes[4095] = 0xCD;
        check(bytes[0] == 0xAB && bytes[4095] == 0xCD,
              "memory: and is readable and writable at both ends");

        // A protection change is the host's own call, and the old value is
        // reported so that a caller can put it back.
        std::uint32_t old = 0;
        check(k32m_VirtualProtect(block, 4096, kPageReadOnly, &old) == 1,
              "memory: a protection change succeeds");
        std::uint32_t back = 0;
        check(k32m_VirtualProtect(block, 4096, kPageReadWrite, &back) == 1,
              "memory: and can be undone");
        bytes[0] = 0xEF;
        check(bytes[0] == 0xEF, "memory: the region is writable again");

        check(k32m_VirtualFree(block, 0, kMemRelease) == 1,
              "memory: the region is released");
    }

    // A query answers the structure Windows answers, and the fields a
    // caller reads are in it at the offsets Windows puts them.
    std::uint8_t info[48];
    std::memset(info, 0, sizeof(info));
    const std::uint64_t got =
        k32m_VirtualQuery(block, info, sizeof(info));
    check(got == sizeof(info), "memory: a query answers one structure");
    std::uint32_t state = 0;
    std::uint32_t protect = 0;
    std::uint32_t type = 0;
    std::memcpy(&state, info + 32, 4);
    std::memcpy(&protect, info + 36, 4);
    std::memcpy(&type, info + 40, 4);
    check(state == kMemCommit, "memory: reporting committed memory");
    check(protect == kPageReadWrite, "memory: and its protection");
    check(type == kMemPrivate, "memory: and that it is private");

    // A request that names no type is a request with no meaning.
    set_last_error(0);
    check(k32m_VirtualAlloc(nullptr, 4096, 0, kPageReadWrite) == nullptr,
          "memory: an allocation with no type is refused");
    check(k32_GetLastError() != 0, "memory: and reports an error");
}

void test_the_three_allocators_are_one() {
    // Global, Local and Heap are the same arena, and a block from one is
    // freed by another. A runtime that kept them apart would fail here, and
    // a program that mixes them -- which is most of them -- would fail
    // there.
    // The size asked for is deliberately not a round number. A block of 64
    // bytes would answer 64 whether the size came back as what was asked for
    // or as what the host's allocator rounded it to, so a case built from a
    // power of two cannot tell the two apart -- and the difference is the
    // whole point of the call: a guest sizes a second buffer from this
    // answer and copies that many bytes.
    void* from_global = k32m_GlobalAlloc(0, 33);
    check(from_global != nullptr, "memory: GlobalAlloc hands back a block");
    std::memset(from_global, 0x5A, 33);
    check(k32m_GlobalSize(from_global) == 33,
          "memory: and its size is the size that was asked for");
    check(k32m_LocalFree(from_global) == 0,
          "memory: a Global block is freed by LocalFree");

    void* from_local = k32m_LocalAlloc(0, 32);
    check(from_local != nullptr, "memory: LocalAlloc hands back a block");
    check(k32m_HeapFree(0, 0, from_local) == 1,
          "memory: and a Local block is freed by HeapFree");

    // The heap handle is not consulted: every arena this runtime has is
    // the process heap, and the handle only tells the two families apart.
    void* from_heap = k32m_HeapAlloc(0, 0, 16);
    check(from_heap != nullptr, "memory: HeapAlloc hands back a block");
    check(k32m_GlobalFree(from_heap) == 0,
          "memory: and a Heap block is freed by GlobalFree");

    // A zeroed request is zeroed, which is the one flag that still means
    // something.
    constexpr std::uint32_t kHeapZeroMemory = 0x00000008;
    auto* zeroed = static_cast<std::uint8_t*>(k32m_GlobalAlloc(kHeapZeroMemory, 32));
    check(zeroed != nullptr, "memory: a zeroed request hands back a block");
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (zeroed[i] != 0) {
            all_zero = false;
        }
    }
    check(all_zero, "memory: and every byte of it is zero");
    k32m_GlobalFree(zeroed);

    // A block written by one allocator and read through another is the same
    // block, which is the property a program relies on when it hands a
    // buffer between libraries.
    void* shared = k32m_HeapAlloc(0, 0, 128);
    auto* bytes = static_cast<std::uint8_t*>(shared);
    bytes[127] = 0x77;
    check(k32m_GlobalSize(shared) == 128,
          "memory: a Heap block answers a Global size");
    check(bytes[127] == 0x77, "memory: and holds what was written to it");
    k32m_GlobalFree(shared);
}

void test_process_memory() {
    std::uint8_t source[16];
    for (int i = 0; i < 16; ++i) {
        source[i] = static_cast<std::uint8_t>(i);
    }
    std::uint8_t copy[16];
    std::memset(copy, 0, sizeof(copy));
    std::uint64_t moved = 0;
    check(k32m_ReadProcessMemory(kCurrentProcess, source, copy, 16, &moved) ==
              1,
          "memory: this process's memory is readable");
    check(moved == 16, "memory: and the count comes back");
    check(std::memcmp(source, copy, 16) == 0, "memory: with the bytes asked for");

    std::uint8_t replacement[16];
    std::memset(replacement, 0x99, sizeof(replacement));
    check(k32m_WriteProcessMemory(kCurrentProcess, copy, replacement, 16,
                                  &moved) == 1,
          "memory: and writable");
    check(copy[0] == 0x99 && copy[15] == 0x99,
          "memory: with the bytes written");

    // A handle for a process that is not this one is refused rather than
    // answered from this one's memory, which would be a program reading the
    // wrong bytes and finding plausible ones.
    set_last_error(0);
    check(k32m_ReadProcessMemory(0x1234, source, copy, 16, &moved) == 0,
          "memory: another process is refused");
    check(k32_GetLastError() == kErrorInvalidHandle,
          "memory: with the invalid-handle error");
}

void test_file_type() {
    // The one console-adjacent call whose answer is a reading rather than a
    // refusal: a program checks this before choosing between the console
    // path and the file path, and the answer decides which one it takes.
    const std::uint64_t out = 0xFFFFFFFFFFFFFFF5ULL;  // STD_OUTPUT_HANDLE
    const std::uint32_t type = k32c_GetFileType(out);
    check(type == 1 || type == 2 || type == 3,
          "console: the standard output has a real file type");

    // A handle nothing issued has no type, and the error says so.
    set_last_error(0);
    check(k32c_GetFileType(0xDEADBEEF) == 0,
          "console: an unissued handle has no type");
    check(k32_GetLastError() == kErrorInvalidHandle,
          "console: and reports invalid handle");
}

void test_no_console() {
    // Every one of these needs a console and there is not one, which is the
    // state a redirected process is in on Windows too. The checks are that
    // they fail and fail with the error a caller branches on.
    const std::uint64_t out = 0xFFFFFFFFFFFFFFF5ULL;
    std::uint32_t mode = 0;
    set_last_error(0);
    check(k32c_GetConsoleMode(out, &mode) == 0,
          "console: the console mode is not available");
    check(k32_GetLastError() == kErrorInvalidHandle,
          "console: with the invalid-handle error");

    std::uint32_t written = 0;
    set_last_error(0);
    check(k32c_WriteConsoleA(out, "x", 1, &written, nullptr) == 0,
          "console: writing to a console fails when there is none");
    check(k32_GetLastError() == kErrorInvalidHandle,
          "console: for the same reason");

    // The window handle is null, which is what a program tests before it
    // tries to use one.
    check(k32c_GetConsoleWindow() == nullptr,
          "console: there is no console window");
}

void test_control_handler() {
    // This one is real: the registration is kept so that a routine a caller
    // registered can be run, which is what the caller asked for.
    const std::uint64_t before = console_ctrl_handler_count();
    const std::uint64_t routine = 0x1234;
    check(k32c_SetConsoleCtrlHandler(routine, 1) == 1,
          "console: a control routine is registered");
    check(console_ctrl_handler_count() == before + 1,
          "console: and the count reflects it");
    bool found = false;
    for (std::uint64_t i = 0; i < console_ctrl_handler_count(); ++i) {
        if (console_ctrl_handler(i) == routine) {
            found = true;
        }
    }
    check(found, "console: and the routine is the one that was given");

    check(k32c_SetConsoleCtrlHandler(routine, 0) == 1,
          "console: and is removed again");
    check(console_ctrl_handler_count() == before,
          "console: leaving the count where it started");

    // Removing something that was never added is a failure, which is what
    // Windows reports and what a caller that checks relies on.
    set_last_error(0);
    check(k32c_SetConsoleCtrlHandler(0x5678, 0) == 0,
          "console: removing an unregistered routine fails");
}

void test_handles() {
    const std::uint64_t out = 0xFFFFFFFFFFFFFFF5ULL;
    std::uint64_t copy = 0;
    check(k32c_DuplicateHandle(kCurrentProcess, out, kCurrentProcess, &copy, 0,
                               0, 0) == 1,
          "handle: a handle is duplicated");
    check(copy == out, "handle: and names the same object");

    std::uint32_t flags = 0xFF;
    check(k32c_GetHandleInformation(out, &flags) == 1,
          "handle: the flags are readable");
    check(flags == 0, "handle: and no inheritance bit is set");

    set_last_error(0);
    check(k32c_GetHandleInformation(0xDEADBEEF, &flags) == 0,
          "handle: an unissued handle has no flags");
    check(k32_GetLastError() == kErrorInvalidHandle,
          "handle: with the invalid-handle error");
}

// The tables themselves.
void test_registration() {
    ExportList list;
    add_memory_kernel32(list);
    const std::size_t memory_count = list.size();
    add_console_kernel32(list);
    const std::size_t console_count = list.size() - memory_count;

    bool duplicate = false;
    for (std::size_t i = 0; i < list.size() && !duplicate; ++i) {
        for (std::size_t k = i + 1; k < list.size(); ++k) {
            if (list[i].name == list[k].name) {
                duplicate = true;
                break;
            }
        }
    }
    check(!duplicate, "api: no name is registered twice");

    bool addressed = true;
    for (const HostExport& entry : list) {
        if (entry.name.empty() || entry.address == 0) {
            addressed = false;
        }
    }
    check(addressed, "api: every entry has a name and an address");
    // Thirty-six: `GetProcessHeap` moved to `winabi.cpp`, which owns the
    // name, and a name registered twice would answer differently depending
    // on which table the export index read first.
    check(memory_count == 36, "api: the memory domain contributes thirty-six");
    check(console_count == 53, "api: the console domain contributes fifty-three");
}

}  // namespace

int main() {
    test_virtual_memory();
    test_the_three_allocators_are_one();
    test_process_memory();
    test_file_type();
    test_no_console();
    test_control_handler();
    test_handles();
    test_registration();

    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

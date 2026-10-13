// The loader's own door into the same machinery `LoadLibrary` and
// `GetProcAddress` use, and the NTDLL spellings of the context pair a
// debugger builds on.
//
// `LdrLoadDll` and `LdrGetProcedureAddress` are how a program that works at
// the ntdll level loads a module and finds a function, and both are the
// same operations the Win32 pair performs -- the module registry is the
// same registry, the trampoline is the same trampoline. The difference is
// the wire format: the names travel as `UNICODE_STRING` and `ANSI_STRING`
// records, and the answer is an NTSTATUS rather than a last-error value and
// a bare address. Each call bridges to the implementation the Win32 name
// uses, so the two doors agree about what a module is and where its
// functions live.
//
// `NtGetContextThread` and `NtSetContextThread` are the same pair as the
// Win32 `GetThreadContext` / `SetThreadContext`, answered through the same
// CONTEXT record handling; the ntdll spellings carry an NTSTATUS result
// instead of a boolean.

#include "occ/runtime/api_common.h"
#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace occ::runtime::winabi {
namespace {

// The NTSTATUS values these calls answer with. The success value is zero;
// the two failures name the thing that was not found.
constexpr std::uint32_t kStatusSuccess = 0;
constexpr std::uint32_t kStatusDllNotFound = 0xC0000135u;
constexpr std::uint32_t kStatusProcedureNotFound = 0xC000007Au;
constexpr std::uint32_t kStatusInvalidHandle = 0xC0000008u;

// A counted string record, as the loader spells it. `UNICODE_STRING` and
// `ANSI_STRING` share the layout: a byte length, a byte capacity, and a
// pointer to the characters. The length is what is copied; the record does
// not promise a terminator, so the reader adds one of its own.
struct CountedString {
    std::uint16_t length = 0;
    std::uint16_t maximum = 0;
    std::uint64_t buffer = 0;
};

// Reads a counted string record from guest memory. The characters are
// copied out to a host string with a terminator, because the record's own
// buffer is not guaranteed to be terminated and the Win32 bridge below
// expects a C string.
[[nodiscard]] bool read_counted_string(const std::uint8_t* record,
                                       std::string& out,
                                       bool wide) noexcept {
    if (record == nullptr) {
        return false;
    }
    CountedString cs;
    std::memcpy(&cs.length, record, 2);
    std::memcpy(&cs.maximum, record + 2, 2);
    std::memcpy(&cs.buffer, record + 8, 8);
    if (cs.buffer == 0) {
        return false;
    }
    if (wide) {
        const char16_t* chars =
            reinterpret_cast<const char16_t*>(cs.buffer);
        std::u16string text(chars, cs.length / 2);
        std::string narrow;
        for (char16_t c : text) {
            narrow.push_back(static_cast<char>(c));
        }
        out = std::move(narrow);
    } else {
        const char* chars = reinterpret_cast<const char*>(cs.buffer);
        out.assign(chars, cs.length);
    }
    return true;
}

// The Win32 pair this file bridges to. Both live in `winabi.cpp` and are
// declared here because the loader spellings call them.
extern "C" __attribute__((ms_abi)) std::uint64_t k32_LoadLibraryW(
    const char16_t* name) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t k32_GetProcAddress(
    std::uint64_t module, const char* name) noexcept;

// The Win32 context pair, declared here because the ntdll spellings are the
// same record handling and this file bridges to it. The setter does not
// return: restoring a context resumes the thread there, which is what the
// Windows call means by "setting".
extern "C" __attribute__((ms_abi)) std::int32_t k32c2_GetThreadContext(
    std::uint64_t thread, void* context) noexcept;
extern "C" __attribute__((ms_abi, noreturn)) void k32c2_SetThreadContext(
    std::uint64_t thread, const void* context) noexcept;

}  // namespace

// Loads a module by its counted name and writes its base address through
// the caller's pointer. The loading is the same loading `LoadLibraryW`
// performs; the answer is the NTSTATUS the loader contract asks for.
extern "C" __attribute__((ms_abi)) std::uint32_t k32ldr_LdrLoadDll(
    std::uint64_t search_path, std::uint64_t flags, const std::uint8_t* name,
    std::uint64_t* base) noexcept {
    static_cast<void>(search_path);
    static_cast<void>(flags);
    if (name == nullptr || base == nullptr) {
        return kStatusInvalidHandle;
    }
    // The name is a `UNICODE_STRING`: a byte length and a buffer of UTF-16
    // characters, copied out and terminated because the record does not
    // promise one and the Win32 bridge expects a C string.
    CountedString cs;
    std::memcpy(&cs.length, name, 2);
    std::memcpy(&cs.maximum, name + 2, 2);
    std::memcpy(&cs.buffer, name + 8, 8);
    if (cs.buffer == 0) {
        return kStatusInvalidHandle;
    }
    const char16_t* chars = reinterpret_cast<const char16_t*>(cs.buffer);
    const std::size_t chars_count = cs.length / 2;
    std::u16string wide(chars, chars_count);
    const std::uint64_t handle = k32_LoadLibraryW(wide.c_str());
    // `LoadLibraryW` answers zero for a module it could not load and sets
    // the last error, which is the Win32 way of saying "not found"; the
    // loader way is the NTSTATUS below.
    if (handle == 0) {
        return kStatusDllNotFound;
    }
    *base = handle;
    return kStatusSuccess;
}

// Finds a function in a module by its counted name, or by ordinal when the
// name record is empty and an ordinal is given. The resolution is the same
// resolution `GetProcAddress` performs, including the ordinal path that
// travels as a small pointer.
extern "C" __attribute__((ms_abi)) std::uint32_t k32ldr_LdrGetProcedureAddress(
    std::uint64_t module, const std::uint8_t* name, std::uint32_t ordinal,
    std::uint64_t* address) noexcept {
    if (address == nullptr) {
        return kStatusInvalidHandle;
    }
    if (ordinal != 0) {
        // An ordinal ask. `GetProcAddress` reads an ordinal as a small
        // pointer, which is how the two conventions meet.
        const std::uint64_t proc = k32_GetProcAddress(
            module, reinterpret_cast<const char*>(
                        static_cast<std::uintptr_t>(ordinal)));
        if (proc == 0) {
            return kStatusProcedureNotFound;
        }
        *address = proc;
        return kStatusSuccess;
    }
    if (name == nullptr) {
        return kStatusInvalidHandle;
    }
    std::string narrow;
    if (!read_counted_string(name, narrow, false)) {
        return kStatusInvalidHandle;
    }
    const std::uint64_t proc = k32_GetProcAddress(module, narrow.c_str());
    if (proc == 0) {
        return kStatusProcedureNotFound;
    }
    *address = proc;
    return kStatusSuccess;
}

// The ntdll spelling of `GetThreadContext`: the same CONTEXT record, the
// same capture, an NTSTATUS answer.
extern "C" __attribute__((ms_abi)) std::uint32_t k32ldr_NtGetContextThread(
    std::uint64_t thread, void* context) noexcept {
    if (context == nullptr) {
        return kStatusInvalidHandle;
    }
    return k32c2_GetThreadContext(thread, context) != 0
               ? kStatusSuccess
               : kStatusInvalidHandle;
}

// The ntdll spelling of `SetThreadContext`. The record is applied the same
// way, and the call does not return -- it resumes the thread at the context
// that was set.
extern "C" __attribute__((ms_abi, noreturn)) void
k32ldr_NtSetContextThread(std::uint64_t thread, const void* context) noexcept {
    k32c2_SetThreadContext(thread, context);
    __builtin_unreachable();
}

void add_ntdll_ldr_ext(ExportList& out) {
    const auto e = [](const char* n, void* fn) {
        HostExport entry;
        entry.name = n;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        return entry;
    };
    out.push_back(e("LdrLoadDll", reinterpret_cast<void*>(&k32ldr_LdrLoadDll)));
    out.push_back(e("LdrGetProcedureAddress",
                    reinterpret_cast<void*>(&k32ldr_LdrGetProcedureAddress)));
    out.push_back(e("NtGetContextThread",
                    reinterpret_cast<void*>(&k32ldr_NtGetContextThread)));
    out.push_back(e("NtSetContextThread",
                    reinterpret_cast<void*>(&k32ldr_NtSetContextThread)));
}

}  // namespace occ::runtime::winabi

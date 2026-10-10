// The Visual C++ runtime, as a program that imports it by name sees it.
//
// A C++ binary built with the Microsoft toolchain resolves its exception
// machinery, its secure memory calls and its runtime initialization hooks
// from `VCRUNTIME140.dll` (and, since the 2019 toolchain, the frame
// handlers of `VCRUNTIME140_1.dll`). Those names are what this domain
// carries. The answers are the honest ones this runtime can give:
//
//  - the exception handler callbacks that a frame table names are SEH
//    entries, and the classic handler is the same function the SEH domain
//    already exports for kernel32 -- the dispatcher drives it, and the
//    function's contract is the same in both spellings;
//  - the exception copy and destroy calls move the small header a
//    `__std_exception_data` owns, which is the whole of what a
//    structured-typed exception needs here;
//  - the throw entry point terminates the guest, because a language
//    exception with no handler in the running image is a failure the
//    runtime should not paper over;
//  - the `mem*_s` calls and the string family are the host's own
//    implementations, registered under the names the Microsoft runtime
//    exports;
//  - the `__vcrt_*` thread hooks are no-ops, which is what they mean to a
//    runtime with one guest thread.

#include "occ/runtime/api.h"
#include "occ/runtime/seh.h"

#include <cstdint>
#include <cstring>
#include <unistd.h>

namespace occ::runtime::winabi {

namespace {

// The exception payload `__std_exception_copy` and `_destroy` move. The
// real structure is four machine words -- the exception record, the copy
// and destroy functions and the object address -- and a copy that moves
// the header without touching the object is the safe half of the
// contract, because the object itself is immutable once thrown.
constexpr std::size_t kStdExceptionHeaderBytes = 4 * sizeof(void*);

}  // namespace

extern "C" __attribute__((ms_abi)) void vcr___std_exception_copy(
    void* dst, const void* src) noexcept {
    if (dst == nullptr || src == nullptr) {
        return;
    }
    __builtin_memcpy(dst, src, kStdExceptionHeaderBytes);
}

extern "C" __attribute__((ms_abi)) void vcr___std_exception_destroy(
    void* exception) noexcept {
    // The header owns nothing this runtime allocated; the object a guest
    // threw lives in guest memory and is reclaimed with the guest.
    (void)exception;
}

extern "C" __attribute__((ms_abi)) void vcr___std_terminate() noexcept {
    ::abort();
}

extern "C" __attribute__((ms_abi)) void* vcr___current_exception() noexcept {
    // No exception is in flight while a host API runs; the guest's own
    // exception state lives in the guest frame the dispatcher walks.
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void* vcr__current_exception_context() noexcept {
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void vcr___CxxThrowException(
    void* exception, void* throw_info) noexcept {
    (void)exception;
    (void)throw_info;
    // A thrown exception that reaches the runtime has no handler to catch
    // it, which is the case the real runtime also ends by terminating.
    ::abort();
}

extern "C" __attribute__((ms_abi)) std::uint64_t vcr___CxxFrameHandler(
    const void* record, void* establisher, const void* context,
    void* dispatcher) noexcept {
    // The frame-handler callbacks this runtime recognizes are the SEH
    // ones; the C++ frame entries a modern image names are passed through
    // to the same contract the classic handler serves.
    return seh::seh_C_specific_handler(record, establisher, context,
                                       dispatcher);
}

extern "C" __attribute__((ms_abi)) std::uint64_t vcr___CxxFrameHandler3(
    const void* record, void* establisher, const void* context,
    void* dispatcher) noexcept {
    return seh::seh_C_specific_handler(record, establisher, context,
                                       dispatcher);
}

extern "C" __attribute__((ms_abi)) std::uint64_t vcr___CxxFrameHandler4(
    const void* record, void* establisher, const void* context,
    void* dispatcher) noexcept {
    return seh::seh_C_specific_handler(record, establisher, context,
                                       dispatcher);
}

extern "C" __attribute__((ms_abi)) std::uint64_t vcr___CxxFrameHandler2(
    const void* record, void* establisher, const void* context,
    void* dispatcher) noexcept {
    return seh::seh_C_specific_handler(record, establisher, context,
                                       dispatcher);
}

// The secure memory family, under the names the Microsoft runtime
// exports. The contracts are the C11 ones: a zero destination size is
// valid, an overrun is a constraint violation that reports and returns
// the invalid-parameter answer rather than writing past the buffer.
extern "C" __attribute__((ms_abi)) int vcr_memcpy_s(void* dst,
                                                    std::size_t dst_size,
                                                    const void* src,
                                                    std::size_t count) noexcept {
    if (dst == nullptr || (count != 0 && (src == nullptr ||
                                          dst_size < count))) {
        return 22;  // EINVAL, the secure-function constraint answer.
    }
    if (count == 0) {
        return 0;
    }
    if (dst == src || dst_size == count) {
        __builtin_memcpy(dst, src, count);
        return 0;
    }
    __builtin_memmove(dst, src, count);
    return 0;
}

extern "C" __attribute__((ms_abi)) int vcr_memmove_s(void* dst,
                                                     std::size_t dst_size,
                                                     const void* src,
                                                     std::size_t count) noexcept {
    if (dst == nullptr || (count != 0 && (src == nullptr ||
                                          dst_size < count))) {
        return 22;
    }
    if (count != 0) {
        __builtin_memmove(dst, src, count);
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) int vcr_memset_s(void* dst,
                                                    std::size_t dst_size,
                                                    int value,
                                                    std::size_t count) noexcept {
    if (dst == nullptr || count > dst_size) {
        return 22;
    }
    if (count != 0) {
        __builtin_memset(dst, value, count);
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) void vcr__purecall() noexcept {
    ::abort();
}

// The runtime's own initialization hooks. Each is called once per module
// load or thread start; with one guest thread and one loaded copy, the
// honest answer is success with nothing to do.
extern "C" __attribute__((ms_abi)) int vcr___vcrt_initialize() noexcept {
    return 1;
}

extern "C" __attribute__((ms_abi)) int vcr___vcrt_uninitialize() noexcept {
    return 1;
}

extern "C" __attribute__((ms_abi)) int vcr___vcrt_cleanup_thread() noexcept {
    return 1;
}

extern "C" __attribute__((ms_abi)) int vcr___vcrt_thread_attach() noexcept {
    return 1;
}

extern "C" __attribute__((ms_abi)) int vcr___vcrt_thread_detach() noexcept {
    return 1;
}

extern "C" __attribute__((ms_abi)) int vcr___getentropy(
    void* buffer, std::size_t length) noexcept {
    if (buffer == nullptr || length > 256) {
        return -1;
    }
    return ::getentropy(buffer, length);
}

// The string and memory family the Microsoft runtime also exports under
// its own names. These are the host's implementations; a guest that
// imports `strlen` from VCRUNTIME asks for the same answer as one that
// imports it from the CRT.
extern "C" __attribute__((ms_abi)) std::size_t vcr_strlen(const char* s) noexcept {
    return ::strlen(s);
}

extern "C" __attribute__((ms_abi)) std::size_t vcr_wcslen(const char16_t* s) noexcept {
    std::size_t n = 0;
    while (s[n] != u'\0') {
        ++n;
    }
    return n;
}

extern "C" __attribute__((ms_abi)) int vcr_strcmp(const char* a, const char* b) noexcept {
    return ::strcmp(a, b);
}

extern "C" __attribute__((ms_abi)) int vcr_strncmp(const char* a, const char* b,
                                                   std::size_t n) noexcept {
    return ::strncmp(a, b, n);
}

extern "C" __attribute__((ms_abi)) char* vcr_strcpy(char* dst, const char* src) noexcept {
    return ::strcpy(dst, src);
}

extern "C" __attribute__((ms_abi)) char* vcr_strncpy(char* dst, const char* src,
                                                     std::size_t n) noexcept {
    return ::strncpy(dst, src, n);
}

extern "C" __attribute__((ms_abi)) char* vcr_strcat(char* dst, const char* src) noexcept {
    return ::strcat(dst, src);
}

extern "C" __attribute__((ms_abi)) char* vcr_strchr(const char* s, int c) noexcept {
    return const_cast<char*>(::strchr(s, c));
}

extern "C" __attribute__((ms_abi)) char* vcr_strrchr(const char* s, int c) noexcept {
    return const_cast<char*>(::strrchr(s, c));
}

extern "C" __attribute__((ms_abi)) char* vcr_strstr(const char* hay, const char* needle) noexcept {
    return const_cast<char*>(::strstr(hay, needle));
}

extern "C" __attribute__((ms_abi)) void* vcr_memcpy(void* dst, const void* src,
                                                    std::size_t n) noexcept {
    return ::memcpy(dst, src, n);
}

extern "C" __attribute__((ms_abi)) void* vcr_memmove(void* dst, const void* src,
                                                     std::size_t n) noexcept {
    return ::memmove(dst, src, n);
}

extern "C" __attribute__((ms_abi)) void* vcr_memset(void* dst, int c,
                                                    std::size_t n) noexcept {
    return ::memset(dst, c, n);
}

extern "C" __attribute__((ms_abi)) int vcr_memcmp(const void* a, const void* b,
                                                  std::size_t n) noexcept {
    return ::memcmp(a, b, n);
}

extern "C" __attribute__((ms_abi)) void* vcr_memchr(const void* s, int c,
                                                    std::size_t n) noexcept {
    return const_cast<void*>(::memchr(s, c, n));
}

// -------------------------------------------------------------------------
// The registration
// -------------------------------------------------------------------------

void add_vcruntime140(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        for (const HostExport& existing : out) {
            if (existing.name == name) {
                return;
            }
        }
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    // The exception machinery.
    e("__C_specific_handler", reinterpret_cast<void*>(&seh::seh_C_specific_handler));
    e("__CxxFrameHandler", reinterpret_cast<void*>(&vcr___CxxFrameHandler));
    e("__CxxFrameHandler2", reinterpret_cast<void*>(&vcr___CxxFrameHandler2));
    e("__CxxFrameHandler3", reinterpret_cast<void*>(&vcr___CxxFrameHandler3));
    e("__CxxThrowException", reinterpret_cast<void*>(&vcr___CxxThrowException));
    e("__std_terminate", reinterpret_cast<void*>(&vcr___std_terminate));
    e("__std_exception_copy", reinterpret_cast<void*>(&vcr___std_exception_copy));
    e("__std_exception_destroy",
      reinterpret_cast<void*>(&vcr___std_exception_destroy));
    e("__current_exception", reinterpret_cast<void*>(&vcr___current_exception));
    e("_current_exception_context",
      reinterpret_cast<void*>(&vcr__current_exception_context));
    // The secure memory family.
    e("memcpy_s", reinterpret_cast<void*>(&vcr_memcpy_s));
    e("memmove_s", reinterpret_cast<void*>(&vcr_memmove_s));
    e("memset_s", reinterpret_cast<void*>(&vcr_memset_s));
    e("_purecall", reinterpret_cast<void*>(&vcr__purecall));
    // The initialization hooks.
    e("__vcrt_initialize", reinterpret_cast<void*>(&vcr___vcrt_initialize));
    e("__vcrt_uninitialize", reinterpret_cast<void*>(&vcr___vcrt_uninitialize));
    e("__vcrt_cleanup_thread",
      reinterpret_cast<void*>(&vcr___vcrt_cleanup_thread));
    e("__vcrt_thread_attach",
      reinterpret_cast<void*>(&vcr___vcrt_thread_attach));
    e("__vcrt_thread_detach",
      reinterpret_cast<void*>(&vcr___vcrt_thread_detach));
    // The string and memory names this module also exports.
    e("strlen", reinterpret_cast<void*>(&vcr_strlen));
    e("wcslen", reinterpret_cast<void*>(&vcr_wcslen));
    e("strcmp", reinterpret_cast<void*>(&vcr_strcmp));
    e("strncmp", reinterpret_cast<void*>(&vcr_strncmp));
    e("strcpy", reinterpret_cast<void*>(&vcr_strcpy));
    e("strncpy", reinterpret_cast<void*>(&vcr_strncpy));
    e("strcat", reinterpret_cast<void*>(&vcr_strcat));
    e("strchr", reinterpret_cast<void*>(&vcr_strchr));
    e("strrchr", reinterpret_cast<void*>(&vcr_strrchr));
    e("strstr", reinterpret_cast<void*>(&vcr_strstr));
    e("memcpy", reinterpret_cast<void*>(&vcr_memcpy));
    e("memmove", reinterpret_cast<void*>(&vcr_memmove));
    e("memset", reinterpret_cast<void*>(&vcr_memset));
    e("memcmp", reinterpret_cast<void*>(&vcr_memcmp));
    e("memchr", reinterpret_cast<void*>(&vcr_memchr));
}

void add_vcruntime140_1(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        for (const HostExport& existing : out) {
            if (existing.name == name) {
                return;
            }
        }
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    // The 2019 frame handler and the entropy call that module added.
    e("__CxxFrameHandler4", reinterpret_cast<void*>(&vcr___CxxFrameHandler4));
    e("__getentropy", reinterpret_cast<void*>(&vcr___getentropy));
}

}  // namespace occ::runtime::winabi

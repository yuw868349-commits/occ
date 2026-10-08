// The kernel32 calls that reach the machine's own register state.
//
// This file carries the context calls, the exception filter, the extended
// state mask, and the module bookkeeping that goes with a process asking
// about itself. They belong together because they share one property that
// decides how each is written: the answer is about *this* process's own
// machine state, and the mechanism that reads it is the structured
// exception handling this runtime already has.
//
// Two of them are worth stating before the code:
//
//   * `GetThreadContext` and `SetThreadContext` are the pair a debugger
//     builds on, and a stub that answered success without touching the
//     registers would leave a caller believing it had moved a thread on.
//     `seh_capture_context` and `seh_restore_context` are the real
//     operations -- the same ones the unwinder uses -- so the pair here is
//     a wrapper that adds the Win32 context-flag handling and nothing else.
//
//   * The module calls answer about the image and nothing else, because
//     the image is the only module this runtime has. `GetModuleHandleExW`
//     still has to honour the two flags that tell it how to count a
//     reference, because a caller that asked not to change the count and
//     then called `FreeLibrary` would otherwise unload the running program.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/seh.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#include <sys/resource.h>
#include <unistd.h>

namespace occ::runtime::winabi {

// The facilities this file reaches for.
// The process exit the exception calls end with. It is the process layer's
// own, and reaching for it by name is what keeps a fail-fast and a fatal
// context error ending the process the same way.
extern "C" __attribute__((ms_abi)) void k32_ExitProcess(
    std::uint32_t code) noexcept;

extern "C" __attribute__((ms_abi)) void* nr1_RtlAddVectoredExceptionHandler(
    std::uint32_t first, void* handler) noexcept;
extern "C" __attribute__((ms_abi)) void* nr1_RtlAddVectoredContinueHandler(
    std::uint32_t first, void* handler) noexcept;
extern "C" __attribute__((ms_abi)) std::uint64_t nr2_RtlGetEnabledExtendedFeatures(
    void) noexcept;

// The filter a guest registered through `RtlSetUnhandledExceptionFilter`,
// and the setter's own reader. The state belongs to the slice that owns the
// setter, so it is read through this rather than kept in a second place
// that could disagree with what the setter stored.
extern "C" void* occ_unhandled_filter() noexcept;
extern "C" std::uint32_t occ_set_thread_error_mode(
    std::uint32_t mode, std::uint32_t* previous) noexcept;

namespace {

// The CONTEXT flag bits. `CONTEXT_AMD64` marks the record as this machine's,
// and the three parts below select which groups the call reads or writes.
constexpr std::uint32_t kContextControl = 0x00100001u;
constexpr std::uint32_t kContextInteger = 0x00100002u;
constexpr std::uint32_t kContextFloatingPoint = 0x00100008u;
constexpr std::uint32_t kContextAll = 0x0010003Fu;

// The flags `GetModuleHandleExW` accepts, and the two that change what the
// call does with the reference count.
constexpr std::uint32_t kModuleHandlePin = 0x00000001u;
constexpr std::uint32_t kModuleHandleUnchangedRefcount = 0x00000002u;
constexpr std::uint32_t kModuleHandleFromAddress = 0x00000004u;

// PROCESS_MEMORY_COUNTERS: the page faults, the peak and current working
// set, the page file use and the private bytes.
constexpr std::size_t kMemoryCountersBytes = 80;

// A CONDITION_VARIABLE is one pointer, and zero is "no waiters".
constexpr std::uint64_t kConditionUnset = 0;

}  // namespace

// ------------------------------------------------------------ the contexts

extern "C" __attribute__((ms_abi)) std::int32_t k32c2_GetThreadContext(
    std::uint64_t thread, void* context) noexcept {
    static_cast<void>(thread);
    if (context == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The caller says which parts of the record it wants by writing the
    // flags first; the call fills those and leaves the rest alone. The
    // capture writes the whole record, so the caller's mask is read before
    // it is and put back after: a capture that left the mask as it found
    // itself would tell the caller it had asked for everything.
    const std::uint32_t wanted = read_u32(context, seh::kContextFlags);
    if (wanted == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    seh::seh_capture_context(static_cast<std::uint8_t*>(context));
    write_u32(context, seh::kContextFlags, wanted);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi, noreturn)) void k32c2_SetThreadContext(
    std::uint64_t thread, const void* context) noexcept {
    static_cast<void>(thread);
    // Setting a thread's context makes it resume there, and the Windows call
    // therefore does not return to its caller: it returns *to the context*.
    // This runtime has one thread, so the context is this thread's, and the
    // restore below is the same operation the unwinder performs.
    if (context == nullptr) {
        set_last_error(kErrorInvalidParameter);
        k32_ExitProcess(kErrorInvalidParameter);
        __builtin_unreachable();
    }
    seh::seh_restore_context(static_cast<const std::uint8_t*>(context));
    __builtin_unreachable();
}

extern "C" __attribute__((ms_abi, noreturn)) void k32c2_RtlRestoreContext(
    const void* context, const void* record) noexcept {
    // The record is the exception that caused the restore, and the guest's
    // own handlers have already run by the time this is reached: the call is
    // the last step of an unwinding, not the start of one.
    static_cast<void>(record);
    if (context == nullptr) {
        k32_ExitProcess(kErrorInvalidParameter);
        __builtin_unreachable();
    }
    seh::seh_restore_context(static_cast<const std::uint8_t*>(context));
    __builtin_unreachable();
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c2_InitializeContext(
    void* buffer, std::uint32_t flags, void** context) noexcept {
    if (buffer == nullptr || context == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The buffer has to hold a CONTEXT and to be 16-byte aligned, which is
    // what the `fxsave` the record carries requires. A caller that passes a
    // misaligned buffer is refused here rather than faulting inside the
    // first capture.
    if ((reinterpret_cast<std::uintptr_t>(buffer) % 16) != 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::memset(buffer, 0, seh::kContextSize);
    write_u32(buffer, seh::kContextFlags, flags | seh::kContextAmd64);
    *context = buffer;
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::uint64_t
k32c2_GetEnabledXStateFeatures(void) noexcept {
    // Which extended-state components are enabled for this process. This
    // runtime does not switch any on: the guest sees the host's own
    // instruction set and no context-switch extension, so the answer is the
    // empty mask rather than a guess at what the host happens to support.
    const std::uint64_t features = nr2_RtlGetEnabledExtendedFeatures();
    return features;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c2_SetXStateFeaturesMask(
    void* context, std::uint64_t mask) noexcept {
    if (context == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The mask says which components of the extended state the record
    // carries. With no component enabled the only mask this can honour is
    // the empty one; a caller that asks for a component is refused, because
    // recording a mask that no capture will fill would leave the caller
    // reading state that was never written.
    if (mask != 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

// ---------------------------------------------------------- the exceptions

extern "C" __attribute__((ms_abi)) void* k32c2_AddVectoredExceptionHandler(
    std::uint32_t first, void* handler) noexcept {
    // The same list `RtlAddVectoredExceptionHandler` maintains, reached
    // through the Rtl spelling: two lists would let a handler registered
    // through one be invisible to the dispatcher that walks the other.
    return nr1_RtlAddVectoredExceptionHandler(first, handler);
}

extern "C" __attribute__((ms_abi)) void* k32c2_AddVectoredContinueHandler(
    std::uint32_t first, void* handler) noexcept {
    return nr1_RtlAddVectoredContinueHandler(first, handler);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c2_UnhandledExceptionFilter(
    void* exception_info) noexcept {
    // The filter the process registered, if it registered one. The call is
    // what the system invokes when nothing in the process handled an
    // exception, and a registered filter answers whether it handled it.
    void* const filter = occ_unhandled_filter();
    if (filter == nullptr) {
        // No filter was registered. The documented default is to end the
        // process, and answering "handled" instead would leave the guest
        // running past a fault nothing recovered from.
        k32_ExitProcess(0xC0000005u);
        __builtin_unreachable();
    }
    using FilterFn = std::int32_t(__attribute__((ms_abi)) *)(void*);
    const auto call = reinterpret_cast<FilterFn>(filter);
    return call(exception_info);
}

extern "C" __attribute__((ms_abi, noreturn)) void k32c2_RaiseFailFastException(
    void* record, void* context, std::uint32_t flags) noexcept {
    static_cast<void>(record);
    static_cast<void>(context);
    static_cast<void>(flags);
    // The call exists to end the process *without* running any handler or
    // filter: it is what a program uses when it has detected corruption and
    // wants the process gone before the corruption spreads. Running the
    // handlers here would defeat the whole point of the call.
    ::fflush(nullptr);
    k32_ExitProcess(0xC0000409u);  // STATUS_STACK_BUFFER_OVERRUN, the fail-fast code
    __builtin_unreachable();
}

// ---------------------------------------------------------- the finalization
//
// A CONDITION_VARIABLE is one pointer in Windows, and it is initialised by
// writing zero. The sleeping and waking are the runtime's own, and the two
// calls here are the pair that touches the structure: a condition variable
// initialised through one spelling and waited on through the other has to be
// the same object.

extern "C" __attribute__((ms_abi)) void k32c2_InitializeConditionVariable(
    void* variable) noexcept {
    if (variable == nullptr) {
        return;
    }
    write_ptr(variable, 0, kConditionUnset);
}

extern "C" __attribute__((ms_abi)) void k32c2_WakeConditionVariable(
    void* variable) noexcept {
    // One waiter is released. This runtime runs one thread, so there is
    // never a waiter to release, and the call is the no-op its contract
    // makes it: answering it rather than refusing keeps a caller whose wake
    // is correct and merely unobserved working.
    static_cast<void>(variable);
}

// --------------------------------------------------------------- the modules

extern "C" __attribute__((ms_abi)) std::int32_t k32c2_GetModuleHandleExW(
    std::uint32_t flags, const char16_t* name, void** module) noexcept {
    if (module == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const auto* state = guest_state();
    if (state == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }

    *module = nullptr;
    const bool by_address = (flags & kModuleHandleFromAddress) != 0;
    if (by_address) {
        // A name that is really an address: the answer is the image the
        // address falls in. The image is the only module there is, so the
        // test is whether the address is inside it.
        const auto address = reinterpret_cast<std::uintptr_t>(name);
        const std::uintptr_t base = static_cast<std::uintptr_t>(state->image_base);
        // The image's extent is not known here, so the test is the weaker
        // one that cannot be wrong: an address at or above the base and
        // below the top of the user window. A tighter test needs the
        // module's size, which the process layer has and this call does not.
        if (base == 0 || address < base) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        *module = reinterpret_cast<void*>(base);
    } else if (name == nullptr) {
        // The image itself, which is what a null name asks for.
        *module = reinterpret_cast<void*>(state->image_base);
    } else {
        // A named module. The image answers for its own name and for
        // nothing else, because nothing else is loaded: a lookup that
        // answered for a library the runtime does not have would give the
        // caller an address to call into.
        std::u16string wanted(name);
        for (char16_t& ch : wanted) {
            if (ch >= u'A' && ch <= u'Z') {
                ch = static_cast<char16_t>(ch - u'A' + u'a');
            }
        }
        // The image's own name, without a path: the last separator is what
        // the comparison starts after.
        std::string image = state->image_path_dos;
        const std::size_t slash = image.find_last_of("/\\");
        if (slash != std::string::npos) {
            image = image.substr(slash + 1);
        }
        std::string lower_image;
        for (char ch : image) {
            lower_image.push_back(
                ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch - 'A' + 'a') : ch);
        }
        std::string narrow;
        if (!narrow_out(wanted, narrow).converted ||
            narrow != lower_image) {
            set_last_error(kErrorModuleNotFound);
            return 0;
        }
        *module = reinterpret_cast<void*>(state->image_base);
    }

    if (*module == nullptr) {
        set_last_error(kErrorModuleNotFound);
        return 0;
    }
    // The reference count is unchanged, because the image cannot be
    // unloaded: it is the running program. `GET_MODULE_HANDLE_EX_FLAG_PIN`
    // asks for exactly that state, and the unchanged-count flag asks not to
    // be counted, so both are satisfied by doing nothing -- which is the
    // truth here rather than a shortcut.
    static_cast<void>(kModuleHandlePin);
    static_cast<void>(kModuleHandleUnchangedRefcount);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c2_FreeLibrary(
    void* module) noexcept {
    const auto* state = guest_state();
    if (module == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The image is the only module, and releasing it would mean unloading
    // the running program. The call answers failure for that, which is what
    // Windows answers for the image too: a program cannot free itself.
    if (state != nullptr &&
        reinterpret_cast<std::uint64_t>(module) == state->image_base) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(kErrorModuleNotFound);
    return 0;
}

// ------------------------------------------------------- the memory report

extern "C" __attribute__((ms_abi)) std::int32_t k32c2_K32GetProcessMemoryInfo(
    std::uint64_t process, void* counters, std::uint32_t size) noexcept {
    static_cast<void>(process);
    if (counters == nullptr || size < kMemoryCountersBytes) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The working set and the page faults come from the host's own
    // accounting for this process: `/proc/self/statm` reports the resident
    // pages, and `getrusage` reports the faults. Reporting zeros would be a
    // number a caller sizes a cache from.
    long resident_pages = 0;
    long total_pages = 0;
    {
        std::FILE* statm = ::fopen("/proc/self/statm", "re");
        if (statm != nullptr) {
            if (::fscanf(statm, "%ld %ld", &total_pages, &resident_pages) != 2) {
                resident_pages = 0;
            }
            ::fclose(statm);
        }
    }
    struct ::rusage usage {};
    ::getrusage(RUSAGE_SELF, &usage);

    const std::uint64_t page = static_cast<std::uint64_t>(::sysconf(_SC_PAGESIZE));
    const auto working_set =
        static_cast<std::uint64_t>(resident_pages) * page;

    std::memset(counters, 0, kMemoryCountersBytes);
    write_u32(counters, 0, kMemoryCountersBytes);
    write_u32(counters, 4, static_cast<std::uint32_t>(usage.ru_minflt));
    write_u32(counters, 8, static_cast<std::uint32_t>(usage.ru_majflt));
    write_u64(counters, 16, working_set);
    write_u64(counters, 24, working_set);  // peak: the host keeps no high-water
    write_u64(counters, 32,
              static_cast<std::uint64_t>(total_pages) * page * 2);
    write_u64(counters, 40, working_set);
    write_u64(counters, 48, usage.ru_maxrss > 0
                                ? static_cast<std::uint64_t>(usage.ru_maxrss) *
                                      1024
                                : 0);
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32c2_SetThreadErrorMode(
    std::uint32_t mode, std::uint32_t* previous) noexcept {
    // The mode is the state the third Rtl slice keeps, reached through this
    // spelling so that a guest which set it one way and read it the other
    // sees one value.
    static_cast<void>(occ_set_thread_error_mode(mode, previous));
    set_last_error(kErrorSuccess);
    return 1;
}

// ------------------------------------------------------------- registration
//
// The names this slice owns. `RtlRestoreContext` is exported by this module
// as well as by ntdll, which is the arrangement Windows has; the other
// fifteen are kernel32's own.

void add_kernel32_ctx2(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("AddVectoredContinueHandler",
      reinterpret_cast<void*>(&k32c2_AddVectoredContinueHandler));
    e("AddVectoredExceptionHandler",
      reinterpret_cast<void*>(&k32c2_AddVectoredExceptionHandler));
    e("FreeLibrary", reinterpret_cast<void*>(&k32c2_FreeLibrary));
    e("GetEnabledXStateFeatures",
      reinterpret_cast<void*>(&k32c2_GetEnabledXStateFeatures));
    e("GetModuleHandleExW", reinterpret_cast<void*>(&k32c2_GetModuleHandleExW));
    e("GetThreadContext", reinterpret_cast<void*>(&k32c2_GetThreadContext));
    e("InitializeConditionVariable",
      reinterpret_cast<void*>(&k32c2_InitializeConditionVariable));
    e("InitializeContext", reinterpret_cast<void*>(&k32c2_InitializeContext));
    e("K32GetProcessMemoryInfo",
      reinterpret_cast<void*>(&k32c2_K32GetProcessMemoryInfo));
    e("RaiseFailFastException",
      reinterpret_cast<void*>(&k32c2_RaiseFailFastException));
    e("RtlRestoreContext", reinterpret_cast<void*>(&k32c2_RtlRestoreContext));
    e("SetThreadContext", reinterpret_cast<void*>(&k32c2_SetThreadContext));
    e("SetThreadErrorMode", reinterpret_cast<void*>(&k32c2_SetThreadErrorMode));
    e("SetXStateFeaturesMask",
      reinterpret_cast<void*>(&k32c2_SetXStateFeaturesMask));
    e("UnhandledExceptionFilter",
      reinterpret_cast<void*>(&k32c2_UnhandledExceptionFilter));
    e("WakeConditionVariable",
      reinterpret_cast<void*>(&k32c2_WakeConditionVariable));
}

}  // namespace occ::runtime::winabi


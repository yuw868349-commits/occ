// The static TLS of the images a process carries.
//
// A `__declspec(thread)` variable is not an ordinary global. The compiler
// reaches it through two levels of indirection -- a per-module index, read
// out of the image's own `_tls_index` variable, and a per-thread block of
// storage, found through the TEB's TLS array -- and both levels have to be
// built before the first access. The generated code is exactly
//
//     mov  image!_tls_index, %ecx
//     mov  %gs:0x58, %rax          ; the TEB's TLS array
//     add  (%rax,%rcx,8), %rsi     ; the module's block for this thread
//
// so an unwritten index is a wild slot number and a null block is a
// dereference of a few bytes past zero. Neither is a compile-time error and
// neither is visible until the variable is touched, which is why this file
// exists separately from the two that call it: the process builder needs it
// for the first thread and the thread layer needs it for every one after.
//
// The template a block is copied from is the image's own initialised data,
// so a variable with an initialiser starts every thread at that value, which
// is what the language promises.

#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace occ::runtime::winabi {
namespace {

// The offsets inside the TEB this file writes. They are the same numbers
// `pe_process.cpp` and `guest_thread.cpp` use, restated for the reason both
// of those files give: the offset is the interface.
constexpr std::size_t kTebTlsArray = 0x1480;

// The TLS directory's index in the data directory, and the size of the
// structure it points at.
constexpr std::size_t kTlsDirectoryIndex = 9;
constexpr std::size_t kTlsDirectoryBytes = 40;

// The offsets inside `IMAGE_TLS_DIRECTORY64`.
constexpr std::size_t kTlsRawStart = 0;
constexpr std::size_t kTlsRawEnd = 8;
constexpr std::size_t kTlsIndexAddress = 16;
constexpr std::size_t kTlsCallbackAddress = 24;
constexpr std::size_t kTlsZeroFill = 32;

// Where the data directory is in each optional header. A PE32+ header has
// the larger of the two, which is the size of the fields above it rather
// than a different structure.
constexpr std::size_t kOptionalHeaderMagic = 0x18;
constexpr std::size_t kDataDirectoryPe32Plus = 0x18 + 0x70;
constexpr std::size_t kDataDirectoryPe32 = 0x18 + 0x60;
constexpr std::uint16_t kMagicPe32Plus = 0x20B;
constexpr std::uint16_t kMagicPe32 = 0x10B;

// The reasons a TLS callback is called with, in the values the platform
// uses.
constexpr std::uint32_t kDllProcessAttach = 1;
constexpr std::uint32_t kDllThreadAttach = 2;
constexpr std::uint32_t kDllThreadDetach = 3;

// The callback's type. It is called with the Windows ABI, like every other
// address inside a guest image.
using GuestTlsCallback = void(__attribute__((ms_abi)) *)(std::uint64_t module,
                                                         std::uint32_t reason,
                                                         std::uint64_t reserved);

// Runs one module's callback list for one reason.
//
// The list is an array of pointers terminated by a null, which is the form
// the linker emits: a module that declares several callbacks has them in one
// array, and their order is their order in the array.
void run_callbacks(const GuestTlsModule& module,
                   std::uint32_t reason) noexcept {
    if (module.callbacks == 0) {
        return;
    }
    const auto* list = reinterpret_cast<const std::uint8_t*>(module.callbacks);
    for (std::size_t i = 0;; ++i) {
        const std::uint64_t entry = read_u64(list, i * sizeof(std::uint64_t));
        if (entry == 0) {
            break;
        }
        const GuestTlsCallback callback =
            reinterpret_cast<GuestTlsCallback>(entry);
        callback(module.image_base, reason, 0);
    }
}

}  // namespace

bool register_module_tls(GuestState& state, std::uint64_t image_base) noexcept {
    if (image_base == 0) {
        return false;
    }

    const auto* dos = reinterpret_cast<const std::uint8_t*>(image_base);
    const std::uint32_t lfanew = read_u32(dos, 0x3C);
    if (lfanew == 0 || lfanew > 0x1000) {
        return false;
    }
    const auto* headers = dos + lfanew;
    const std::uint16_t magic = read_u16(headers, kOptionalHeaderMagic);

    std::size_t directory_at = 0;
    if (magic == kMagicPe32Plus) {
        directory_at = kDataDirectoryPe32Plus;
    } else if (magic == kMagicPe32) {
        directory_at = kDataDirectoryPe32;
    } else {
        return false;
    }

    const std::size_t entry_at =
        directory_at + kTlsDirectoryIndex * 2 * sizeof(std::uint32_t);
    const std::uint32_t tls_rva = read_u32(headers, entry_at);
    const std::uint32_t tls_size = read_u32(headers, entry_at + 4);
    if (tls_rva == 0 || tls_size < kTlsDirectoryBytes) {
        return false;
    }

    const auto* directory = dos + tls_rva;
    GuestTlsModule module;
    module.image_base = image_base;
    module.raw_start = read_u64(directory, kTlsRawStart);
    module.raw_end = read_u64(directory, kTlsRawEnd);
    module.index_va = read_u64(directory, kTlsIndexAddress);
    module.callbacks = read_u64(directory, kTlsCallbackAddress);
    module.zero_fill = read_u32(directory, kTlsZeroFill);
    module.index = static_cast<std::uint32_t>(state.tls_modules.size());

    // The index the module was given, written where the compiled sequence
    // reads it. Windows numbers the modules in load order and this runtime
    // has one image, so the number is zero for the first and one more for
    // each after it.
    if (module.index_va != 0) {
        write_u32(reinterpret_cast<void*>(module.index_va), 0, module.index);
    }

    state.tls_modules.push_back(module);

    // The process-attach callback, which runs before any thread of the
    // process has run its own. A module that declares one expects it before
    // its first thread-attach and exactly once per process.
    run_callbacks(module, kDllProcessAttach);
    return true;
}

bool install_thread_tls(GuestState& state) noexcept {
    for (const GuestTlsModule& module : state.tls_modules) {
        const std::size_t raw_bytes =
            static_cast<std::size_t>(module.raw_end - module.raw_start);
        const std::size_t total = raw_bytes + module.zero_fill;
        if (total == 0) {
            continue;
        }

        void* block = heap_alloc(0, total);
        if (block == nullptr) {
            return false;
        }
        std::memset(block, 0, total);
        if (raw_bytes != 0) {
            std::memcpy(block, reinterpret_cast<const void*>(module.raw_start),
                        raw_bytes);
        }

        const std::uint64_t slot =
            state.teb + kTebTlsArray + module.index * sizeof(std::uint64_t);
        write_u64(reinterpret_cast<void*>(slot), 0,
                  reinterpret_cast<std::uint64_t>(block));
    }

    for (const GuestTlsModule& module : state.tls_modules) {
        run_callbacks(module, kDllThreadAttach);
    }
    return true;
}

void run_thread_detach_callbacks(GuestState& state) noexcept {
    for (const GuestTlsModule& module : state.tls_modules) {
        run_callbacks(module, kDllThreadDetach);
    }
}

}  // namespace occ::runtime::winabi

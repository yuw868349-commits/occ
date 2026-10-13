// The process-and-firmware self checks, as kernel32 and user32 spell them.
//
// The `IsBad*` family asks whether an address a guest names is memory this
// runtime mapped. The honest answer comes from the address-space ledger, not
// from touching the bytes: a probe that read or wrote through a host address
// would be exactly the dereference the check exists to prevent. Every probe
// here therefore answers from `guest_range_is_ours`, which walks the ledger
// and never the memory, and the one member of the family that must read --
// `IsBadStringPtr` -- reads only inside pages the ledger has already vouched
// for, so a malformed guest pointer can be answered without faulting.
//
// The process-identity calls (`QueryFullProcessImageName`, the affinity-mode
// pair, `GetProcessIoCounters`) are real host reads: the image path lives in
// the guest state, the I/O counters come out of /proc/self/io, and the
// affinity update mode is stored so that set and query round-trip the way
// Windows' own bookkeeping does. The firmware pair is a refusal with a
// reason: Linux has no UEFI variable namespace, and Windows itself answers
// `ERROR_INVALID_FUNCTION` for a variable that is not there, which is the
// same honest answer this runtime gives. `GetGuiResources` answers zero
// because a headless run owns no GUI objects, and zero is the true count
// rather than a pretend one.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <unistd.h>

namespace occ::runtime::winabi {

// The Win32 image-path and exit bridges, declared here because the self-check
// spellings call them. `QueryFullProcessImageNameW` already serves the wide
// spelling from `GuestState::image_path_wide`; the narrow one below mirrors
// that same answer in UTF-8 rather than a second copy of the path.
extern "C" __attribute__((ms_abi, noreturn)) void k32_ExitProcess(
    std::uint32_t) noexcept;

// The current process id, which is one of the two spellings a caller can use
// for "this process" (the other being the all-ones pseudo handle).
extern "C" __attribute__((ms_abi)) std::uint32_t k32_GetCurrentProcessId() noexcept;

namespace {

// The current-process pseudo handle, the value a caller passes when it names
// the process it is running in.
constexpr std::uint64_t kCurrentProcessPseudo = ~std::uint64_t{0};

// The affinity update modes `SetProcessAffinityUpdateMode` accepts. Windows
// defines exactly these two bits; anything else is a malformed request.
constexpr std::uint32_t kAffinityEnableAutoUpdate = 0x00000001u;
constexpr std::uint32_t kAffinityDisableAutoUpdate = 0x00000002u;
constexpr std::uint32_t kAffinityValidMask = kAffinityEnableAutoUpdate |
                                             kAffinityDisableAutoUpdate;

// The update mode the affinity pair round-trips. This runtime has no NUMA
// rebalancing machinery -- it is one process on one host -- so the mode is
// recorded state rather than a knob something reads; keeping it makes
// `Set` followed by `Query` answer the same value the way Windows does.
std::uint32_t g_affinity_update_mode = 0;

// IO_COUNTERS, as the guest lays it out on the 64-bit ABI: six 8-byte
// counters, all at even offsets.
constexpr std::size_t kIoReadOperationCount = 0;
constexpr std::size_t kIoWriteOperationCount = 8;
constexpr std::size_t kIoOtherOperationCount = 16;
constexpr std::size_t kIoReadTransferCount = 24;
constexpr std::size_t kIoWriteTransferCount = 32;
constexpr std::size_t kIoOtherTransferCount = 40;
constexpr std::size_t kIoCountersBytes = 48;

// Whether `handle` names the process this runtime runs in: the all-ones
// pseudo handle or the current process id are the two spellings Windows
// accepts, and any other process cannot exist in a single-process run.
[[nodiscard]] bool is_self_process(std::uint64_t handle) noexcept {
    if (handle == kCurrentProcessPseudo) {
        return true;
    }
    return handle == static_cast<std::uint64_t>(k32_GetCurrentProcessId());
}

// Reads one `key: value` line out of /proc/self/io. The file's format is
// fixed -- a name, a colon, a decimal count -- and a line whose key is not
// the one asked for leaves `out` untouched.
void read_io_field(const char* text, const char* key, std::uint64_t& out) {
    const std::size_t key_len = std::strlen(key);
    if (std::strncmp(text, key, key_len) != 0 || text[key_len] != ':') {
        return;
    }
    const char* value = text + key_len + 1;
    char* end = nullptr;
    const unsigned long parsed = std::strtoul(value, &end, 10);
    if (end != value) {
        out = static_cast<std::uint64_t>(parsed);
    }
}

// The guest's wide image path, read from the state the process builder laid
// out. Returns the length in UTF-16 units, excluding the terminator.
[[nodiscard]] bool guest_image_path(std::u16string& out) noexcept {
    GuestState* g = guest_state();
    if (g == nullptr || g->image_path_wide == 0) {
        return false;
    }
    const char16_t* path = reinterpret_cast<const char16_t*>(g->image_path_wide);
    std::size_t len = 0;
    while (path[len] != u'\0') {
        ++len;
    }
    out.assign(path, len);
    return true;
}

}  // namespace

// `QueryFullProcessImageNameA`. The wide spelling's contract, served in
// UTF-8: `size` holds the caller's capacity in on entry and the answer's
// length (excluding the terminator) on success. The two checks this spelling
// adds are Windows' own: `flags` must be zero and the handle must name this
// process, because there is no other process to ask in a single-process run.
extern "C" __attribute__((ms_abi)) std::int32_t
k32chk_QueryFullProcessImageNameA(std::uint64_t process, std::uint32_t flags,
                                  char* buffer,
                                  std::uint32_t* size) noexcept {
    if (flags != 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (!is_self_process(process)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (buffer == nullptr || size == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string wide;
    if (!guest_image_path(wide)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(wide), narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::size_t len = narrow.size();
    if (len + 1 > static_cast<std::size_t>(*size)) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    std::memcpy(buffer, narrow.data(), len);
    buffer[len] = '\0';
    *size = static_cast<std::uint32_t>(len);
    set_last_error(kErrorSuccess);
    return 1;
}

// `IsBadReadPtr`: whether the range is readable. The ledger is the answer,
// and the range is never touched. A null range is bad by definition, and a
// range whose end wraps the address space is bad because no such range
// exists. A zero-length range at a live address is good -- there is nothing
// to read -- which is the answer Windows gives a caller probing nothing.
extern "C" __attribute__((ms_abi)) std::int32_t k32chk_IsBadReadPtr(
    const void* address, std::uint64_t size) noexcept {
    if (address == nullptr) {
        return 1;
    }
    if (size == 0) {
        return 0;
    }
    return guest_range_is_ours(address, size) ? 0 : 1;
}

// `IsBadWritePtr`: the same question for writes, answered from the same
// ledger. The ledger does not track write permission separately, so a range
// the runtime mapped is a range a guest may write -- which is the model the
// whole runtime runs on, host memory being the only thing off limits.
extern "C" __attribute__((ms_abi)) std::int32_t k32chk_IsBadWritePtr(
    const void* address, std::uint64_t size) noexcept {
    if (address == nullptr) {
        return 1;
    }
    if (size == 0) {
        return 0;
    }
    return guest_range_is_ours(address, size) ? 0 : 1;
}

// `IsBadCodePtr`: whether the address can be jumped to. Guest code lives in
// the guest's mapped image, which the ledger holds; a host function this
// runtime answers with lives behind its own export table and is never an
// address a guest would probe. The ledger check is therefore the whole
// answer, and a null pointer is bad by definition.
extern "C" __attribute__((ms_abi)) std::int32_t k32chk_IsBadCodePtr(
    const void* fn) noexcept {
    if (fn == nullptr) {
        return 1;
    }
    return guest_range_is_ours(fn, 1) ? 0 : 1;
}

// The string probes read byte by byte, and they are the one place this
// family touches memory. The touch is made safe first: every byte's page is
// checked against the ledger before it is dereferenced, so a pointer into
// host memory is refused without ever being read.
[[nodiscard]] bool string_range_readable(std::uint64_t at,
                                         std::uint64_t length) noexcept {
    for (std::uint64_t i = 0; i < length; ++i) {
        const std::uint64_t current = at + i;
        if (current < at) {
            return false;  // the range wrapped; no such memory
        }
        const std::uint64_t page = current & ~std::uint64_t{0xFFF};
        if (!guest_range_is_ours(reinterpret_cast<const void*>(page), 0x1000)) {
            return false;
        }
    }
    return true;
}

// `IsBadStringPtrA`: walks up to `max` bytes looking for a terminator. The
// answer is "bad" only when a byte outside the ledger would have to be read;
// running out of `max` bytes without a terminator is still a readable range,
// and Windows answers good for it too. `max == 0` reads nothing and answers
// good, and a null pointer is bad.
extern "C" __attribute__((ms_abi)) std::int32_t k32chk_IsBadStringPtrA(
    const char* address, std::uint64_t max) noexcept {
    if (address == nullptr) {
        return 1;
    }
    const std::uint64_t base = reinterpret_cast<std::uint64_t>(address);
    if (max == 0 || !string_range_readable(base, max)) {
        return max == 0 ? 0 : 1;
    }
    for (std::uint64_t i = 0; i < max; ++i) {
        if (address[i] == '\0') {
            return 0;
        }
    }
    return 0;
}

// `IsBadStringPtrW`: the wide spelling. `max` counts UTF-16 units and each
// step is two bytes, but the probe is otherwise the same.
extern "C" __attribute__((ms_abi)) std::int32_t k32chk_IsBadStringPtrW(
    const char16_t* address, std::uint64_t max) noexcept {
    if (address == nullptr) {
        return 1;
    }
    const std::uint64_t base = reinterpret_cast<std::uint64_t>(address);
    // The byte range covered is `max` units of two bytes each; a unit count
    // whose byte count wraps the address space is refused before reading.
    if (max > (std::uint64_t{0xFFFFFFFFFFFFFFFFULL} >> 1)) {
        return 1;
    }
    const std::uint64_t bytes = max * 2;
    if (bytes == 0 || !string_range_readable(base, bytes)) {
        return bytes == 0 ? 0 : 1;
    }
    for (std::uint64_t i = 0; i < max; ++i) {
        if (address[i] == u'\0') {
            return 0;
        }
    }
    return 0;
}

// `GetProcessIoCounters`. The counters come from /proc/self/io, which the
// kernel keeps for this process; the mapping to IO_COUNTERS pairs each
// operation count with the transfer count that belongs to it, with the
// cancelled-write byte count standing in for the other-transfer count the
// field layout needs. The file is absent only on kernels old enough not to
// count I/O at all, and for those the honest answer is that the call is not
// implemented rather than a table of zeroes.
extern "C" __attribute__((ms_abi)) std::int32_t k32chk_GetProcessIoCounters(
    std::uint64_t process, void* counters) noexcept {
    if (!is_self_process(process)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (counters == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const int fd = ::open("/proc/self/io", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        set_last_error(kErrorCallNotImplemented);
        return 0;
    }
    char text[2048];
    std::size_t used = 0;
    bool failed = false;
    while (used + 1 < sizeof(text)) {
        const ssize_t got =
            ::read(fd, text + used, sizeof(text) - 1 - used);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            failed = true;
            break;
        }
        if (got == 0) {
            break;
        }
        used += static_cast<std::size_t>(got);
    }
    ::close(fd);
    if (failed) {
        set_last_error(kErrorCallNotImplemented);
        return 0;
    }
    text[used] = '\0';

    std::uint64_t syscr = 0;
    std::uint64_t syscw = 0;
    std::uint64_t read_bytes = 0;
    std::uint64_t write_bytes = 0;
    std::uint64_t cancelled = 0;
    char* line = text;
    while (line != nullptr && *line != '\0') {
        char* nl = std::strchr(line, '\n');
        if (nl != nullptr) {
            *nl = '\0';
        }
        read_io_field(line, "read_bytes", read_bytes);
        read_io_field(line, "write_bytes", write_bytes);
        read_io_field(line, "syscr", syscr);
        read_io_field(line, "syscw", syscw);
        read_io_field(line, "cancelled_write_bytes", cancelled);
        line = nl == nullptr ? nullptr : nl + 1;
    }

    std::memset(counters, 0, kIoCountersBytes);
    write_u64(counters, kIoReadOperationCount, syscr);
    write_u64(counters, kIoWriteOperationCount, syscw);
    write_u64(counters, kIoOtherOperationCount, 0);
    write_u64(counters, kIoReadTransferCount, read_bytes);
    write_u64(counters, kIoWriteTransferCount, write_bytes);
    write_u64(counters, kIoOtherTransferCount, cancelled);
    set_last_error(kErrorSuccess);
    return 1;
}

// `SetProcessAffinityUpdateMode`: record the mode so the query answers the
// same value back. There is no scheduler to steer in this runtime, but the
// mode is observable state on Windows and a round-trip that drops it would
// answer a different process than the one the caller set up.
extern "C" __attribute__((ms_abi)) std::int32_t
k32chk_SetProcessAffinityUpdateMode(std::uint64_t process,
                                    std::uint32_t flags) noexcept {
    if (!is_self_process(process)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if ((flags & ~kAffinityValidMask) != 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    g_affinity_update_mode = flags;
    set_last_error(kErrorSuccess);
    return 1;
}

// `QueryProcessAffinityUpdateMode`: the stored mode, or zero for a process
// that never set one (which is Windows' own default).
extern "C" __attribute__((ms_abi)) std::int32_t
k32chk_QueryProcessAffinityUpdateMode(std::uint64_t process,
                                      std::uint32_t* flags) noexcept {
    if (!is_self_process(process)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    if (flags == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    *flags = g_affinity_update_mode;
    set_last_error(kErrorSuccess);
    return 1;
}

// `FatalAppExitA`: report the message and leave through the same exit path
// `ExitProcess` uses. The `uAction` argument is reserved by Windows and
// carries no meaning here either. The call never returns.
extern "C" __attribute__((ms_abi, noreturn)) void k32chk_FatalAppExitA(
    std::uint32_t action, const char* text) noexcept {
    (void)action;
    const char* message = text == nullptr ? "(no message)" : text;
    std::fprintf(stderr, "Fatal application error: %s\n", message);
    std::fflush(stderr);
    k32_ExitProcess(0);
}

// `FatalAppExitW`: the wide spelling, with the message converted to UTF-8
// for the host's error stream.
extern "C" __attribute__((ms_abi, noreturn)) void k32chk_FatalAppExitW(
    std::uint32_t action, const char16_t* text) noexcept {
    (void)action;
    std::string narrow;
    if (text != nullptr && narrow_out(std::u16string_view(text), narrow).converted) {
        std::fprintf(stderr, "Fatal application error: %s\n", narrow.c_str());
    } else {
        std::fprintf(stderr, "Fatal application error: (unprintable)\n");
    }
    std::fflush(stderr);
    k32_ExitProcess(0);
}

// `FreeLibraryAndExitThread`: drop the module's handle entry, then leave
// through the thread-exit path with the caller's code. The boundary is that
// only the handle table entry goes away: the module image and its registry
// entry belong to the process, and other handles to the same library keep it
// loaded, exactly as Windows' reference counting behaves.
extern "C" __attribute__((ms_abi, noreturn)) void
k32chk_FreeLibraryAndExitThread(std::uint64_t module,
                                std::uint32_t exit_code) noexcept {
    GuestState* g = guest_state();
    if (g != nullptr && module != 0) {
        g->libraries.erase(module);
    }
    exit_current_guest_thread(exit_code);
}

// `GetFirmwareEnvironmentVariableA`: there is no UEFI variable namespace on
// Linux for a non-root run to answer from, and Windows itself returns
// `ERROR_INVALID_FUNCTION` when the named variable does not exist. Answering
// that same code is the honest refusal -- the alternative is a pretend
// firmware that would let a guest believe a variable it set took effect.
extern "C" __attribute__((ms_abi)) std::uint32_t
k32chk_GetFirmwareEnvironmentVariableA(const char*, const char*, char*,
                                       std::uint32_t) noexcept {
    set_last_error(kErrorInvalidFunction);
    return 0;
}

// `GetFirmwareEnvironmentVariableW`: the wide spelling of the same refusal.
extern "C" __attribute__((ms_abi)) std::uint32_t
k32chk_GetFirmwareEnvironmentVariableW(const char16_t*, const char16_t*,
                                       char16_t*, std::uint32_t) noexcept {
    set_last_error(kErrorInvalidFunction);
    return 0;
}

// ------------------------------------------------------------- registration

void add_kernel32_selfcheck_ext(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("FatalAppExitA", reinterpret_cast<void*>(&k32chk_FatalAppExitA));
    e("FatalAppExitW", reinterpret_cast<void*>(&k32chk_FatalAppExitW));
    e("FreeLibraryAndExitThread",
      reinterpret_cast<void*>(&k32chk_FreeLibraryAndExitThread));
    e("GetFirmwareEnvironmentVariableA",
      reinterpret_cast<void*>(&k32chk_GetFirmwareEnvironmentVariableA));
    e("GetFirmwareEnvironmentVariableW",
      reinterpret_cast<void*>(&k32chk_GetFirmwareEnvironmentVariableW));
    e("GetProcessIoCounters",
      reinterpret_cast<void*>(&k32chk_GetProcessIoCounters));
    e("IsBadCodePtr", reinterpret_cast<void*>(&k32chk_IsBadCodePtr));
    e("IsBadReadPtr", reinterpret_cast<void*>(&k32chk_IsBadReadPtr));
    e("IsBadStringPtrA", reinterpret_cast<void*>(&k32chk_IsBadStringPtrA));
    e("IsBadStringPtrW", reinterpret_cast<void*>(&k32chk_IsBadStringPtrW));
    e("IsBadWritePtr", reinterpret_cast<void*>(&k32chk_IsBadWritePtr));
    e("QueryFullProcessImageNameA",
      reinterpret_cast<void*>(&k32chk_QueryFullProcessImageNameA));
    e("QueryProcessAffinityUpdateMode",
      reinterpret_cast<void*>(&k32chk_QueryProcessAffinityUpdateMode));
    e("SetProcessAffinityUpdateMode",
      reinterpret_cast<void*>(&k32chk_SetProcessAffinityUpdateMode));
}

// `GetGuiResources`: a headless run holds no GDI or USER objects, so the
// honest count for both resource classes is zero. Windows answers an error
// for a handle that does not name the current process and for a flag that is
// not one of the two classes; both are validated before the zero is returned.
extern "C" __attribute__((ms_abi)) std::uint32_t k32chk_GetGuiResources(
    std::uint64_t process, std::uint32_t flags) noexcept {
    if (!is_self_process(process)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    // GR_GDIOBJECTS = 0 and GR_USEROBJECTS = 1 are the only two classes.
    if (flags > 1) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 0;
}

void add_user32_selfcheck(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("GetGuiResources", reinterpret_cast<void*>(&k32chk_GetGuiResources));
}

}  // namespace occ::runtime::winabi

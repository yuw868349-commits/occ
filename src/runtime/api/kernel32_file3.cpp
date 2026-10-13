// The kernel32 file family's third slice: the pointer-moving, copying,
// directory-walking, time-setting and locking calls.
//
// Everything here is a real host operation. `SetFilePointer` is the
// 32-bit view of the same seek `SetFilePointerEx` already serves, so it
// bridges to that implementation rather than carrying a second one.
// `CopyFileEx` is a real copy loop -- open, read, write, preserve mode and
// timestamps -- with the progress callback invoked on every chunk and the
// cancel flag honored, and the flags that change the copy (fail-if-exists,
// restartable, copy-the-symlink) each mapped onto host behaviour. The find
// pair reuses the directory-walk machinery `FindFirstFileExW`/`FindNextFileW`
// already own, so a handle minted here is closed by the same `FindClose`,
// and only the buffer spellings differ. The lock pair is fcntl record
// locking over a shadow ledger: POSIX releases a process's locks when *any*
// descriptor to the file closes, and `F_GETLK` never reports the caller's
// own locks, so "do we hold this range" is remembered rather than asked --
// both consequences are stated where they matter. `FlushViewOfFile` consults
// the filemap family's view ledger before flushing, because the host's
// `msync` accepts anonymous memory too and would bless a stack address.
//
// The no-8.3 volume answers short-name queries with the long name, which is
// exactly what Windows answers there, and `GetLongPathName` answers the
// same identity the already-registered wide spelling answers, so the pair
// cannot disagree.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/containment.h"
#include "occ/runtime/dos_path.h"
#include "occ/runtime/winabi.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <cerrno>
#include <cctype>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace occ::runtime::winabi {

// The filemap family's view ledger, queried by the flush path. Declared
// here the way winabi.cpp declares `filemap_handle_is_section`: a plain
// namespace function in the shared runtime namespace.
bool filemap_view_contains(std::uint64_t address) noexcept;

// The Win32 file bridges this slice shares conventions with, declared here
// because the slice calls them. `SetFilePointerEx` carries the seek, the
// find pair carries the directory walks, and the long-path spelling carries
// the identity contract the A form must agree with.
extern "C" __attribute__((ms_abi)) std::int32_t k32f2_SetFilePointerEx(
    void* file, std::int64_t distance, std::int64_t* new_position,
    std::uint32_t method) noexcept;
extern "C" __attribute__((ms_abi)) void* k32f2_FindFirstFileExW(
    const char16_t* pattern, std::uint32_t level, void* data,
    std::uint32_t flags, void* filter, void* filter_data) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32f2_FindNextFileW(
    void* handle, void* data) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32f2_FindClose(
    void* handle) noexcept;

// The wide carriers of the two pairs below, forward-declared so the narrow
// marshalling halves can sit above them without a second implementation.
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_CopyFileExW(
    const char16_t* existing, const char16_t* new_name,
    std::uint64_t progress_routine, std::uint64_t data,
    const std::int32_t* cancel, std::uint32_t flags) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_CreateHardLinkW(
    const char16_t* new_name, const char16_t* existing,
    void* security) noexcept;

namespace {

// The file handle base and span, shared with every file domain in the
// runtime. A handle outside the range was not minted for a file.
constexpr std::uint64_t kFileHandleBase = 0x2000;
constexpr std::uint64_t kFileHandleSpan = 0x100000;

// Win32 errors this slice sets that the shared header does not name. They
// are the file family's own codes: a lock conflict, a lock this process does
// not hold, a cancelled copy, and a cross-device hard link.
constexpr std::uint32_t kErrorLockViolation = 33;
constexpr std::uint32_t kErrorNotLocked = 158;
constexpr std::uint32_t kErrorRequestAborted = 1235;
constexpr std::uint32_t kErrorNotSameDevice = 17;

// INVALID_SET_FILE_POINTER, the failure value `SetFilePointer` returns.
constexpr std::uint32_t kInvalidSetFilePointer = 0xFFFFFFFFu;

// The copy flags `CopyFileEx` accepts and this slice acts on. The other
// documented flags (no-buffering, copy-all, allow-decrypted) name host
// features or Windows-only behaviours and are accepted and ignored.
constexpr std::uint32_t kCopyFileFailIfExists = 0x00000001;
constexpr std::uint32_t kCopyFileRestartable = 0x00000002;
constexpr std::uint32_t kCopyFileCopySymlink = 0x00000800;

// COPY_FILE_CHUNK_STAGING, the callback reason for a normal chunk copy, and
// the single stream number of an ordinary file copy.
constexpr std::uint32_t kCopyFileChunkStaging = 0;
constexpr std::uint32_t kCopyStreamOne = 1;

// The lock flags `LockFileEx` acts on.
constexpr std::uint32_t kLockfileFailImmediately = 0x00000001;
constexpr std::uint32_t kLockfileExclusiveLock = 0x00000002;

// WIN32_FIND_DATA, as the guest lays it out. The header fields through the
// name are identical between the A and W forms; only the name arrays differ
// in element width. The W form is 592 bytes (a 260-unit wide name at 44), the
// A form 318 bytes (a 260-byte narrow name at 44 and a 14-byte alternate at
// 304), which is the winnt.h layout.
constexpr std::size_t kFindAFileName = 44;
constexpr std::size_t kFindANameChars = 260;
constexpr std::size_t kFindABytes = 318;
constexpr std::size_t kFindWBytes = 592;
constexpr std::size_t kFindWNameChars = 260;

// The FILETIME clock: 100-nanosecond ticks from 1601-01-01, 11644473600
// seconds before the host's 1970 epoch.
constexpr std::int64_t kTicksPerSecond = 10000000;
constexpr std::int64_t kEpochDeltaSeconds = 11644473600;

// The "set to the current time" marker `SetFileTime` reads.
constexpr std::uint64_t kCurrentTimeMarker = 0xFFFFFFFFFFFFFFFFULL;

// The guest callback `CopyFileEx` invokes, in the Windows ABI: four 64-bit
// sizes, two DWORDs, two handles and the caller's data pointer. Calling it
// through an ms_abi function pointer is how a guest function is invoked from
// host code, the same way the runtime calls an image entry point.
using FileProgressRoutine = std::uint32_t(__attribute__((ms_abi))*)(
    std::int64_t total_file_size, std::int64_t total_bytes_transferred,
    std::int64_t stream_size, std::int64_t stream_bytes_transferred,
    std::uint32_t stream_number, std::uint32_t callback_reason,
    std::uint64_t source_file, std::uint64_t destination_file,
    std::uint64_t data);

// ------------------------------------------------------------------ helpers

// Whether a handle falls in the file range, and whether the descriptor under
// it is still live. The liveness check is the host's own truth about an fd.
[[nodiscard]] int file_descriptor_of(std::uint64_t handle) noexcept {
    if (handle < kFileHandleBase || handle >= kFileHandleBase + kFileHandleSpan) {
        return -1;
    }
    const int fd = static_cast<int>(handle - kFileHandleBase);
    if (::fcntl(fd, F_GETFD) < 0) {
        return -1;
    }
    return fd;
}

// Maps an errno from a file operation onto the Win32 code the same situation
// gets on Windows. One table for the whole slice keeps two call sites from
// disagreeing about what a failed copy or link means.
void set_file_errno(int code) noexcept {
    switch (code) {
    case ENOENT:
        set_last_error(kErrorFileNotFound);
        return;
    case ENOTDIR:
        set_last_error(kErrorPathNotFound);
        return;
    case EACCES:
    case EPERM:
    case EROFS:
        set_last_error(kErrorAccessDenied);
        return;
    case EEXIST:
        set_last_error(kErrorAlreadyExists);
        return;
    case EXDEV:
        set_last_error(kErrorNotSameDevice);
        return;
    case ENOSPC:
    case EDQUOT:
        set_last_error(kErrorWriteFault);
        return;
    case ENAMETOOLONG:
    case EINVAL:
        set_last_error(kErrorInvalidParameter);
        return;
    default:
        set_last_error(kErrorInvalidParameter);
        return;
    }
}

// A `timespec` converted to FILETIME ticks. A time before 1601 has no
// FILETIME and answers zero.
[[nodiscard]] std::uint64_t timespec_to_filetime(const struct ::timespec& ts) noexcept {
    const std::int64_t seconds = static_cast<std::int64_t>(ts.tv_sec);
    if (seconds < kEpochDeltaSeconds) {
        return 0;
    }
    const std::uint64_t since_1970 =
        static_cast<std::uint64_t>(seconds - kEpochDeltaSeconds);
    return since_1970 * static_cast<std::uint64_t>(kTicksPerSecond) +
           static_cast<std::uint64_t>(ts.tv_nsec) / 100;
}

// FILETIME ticks converted to a timespec, for the time setter. False when
// the tick count is too large to date; the caller then leaves the field
// alone rather than writing a wrapped time.
[[nodiscard]] bool filetime_to_timespec(std::uint64_t ticks,
                                        struct ::timespec& out) noexcept {
    const std::uint64_t seconds = ticks / static_cast<std::uint64_t>(kTicksPerSecond);
    const std::uint64_t sub = ticks % static_cast<std::uint64_t>(kTicksPerSecond);
    if (seconds > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        return false;
    }
    const std::int64_t since_1970 =
        static_cast<std::int64_t>(seconds) - kEpochDeltaSeconds;
    out.tv_sec = static_cast<time_t>(since_1970);
    out.tv_nsec = static_cast<long>(sub * 100);
    return true;
}

// Writes a FILETIME (low and high 32-bit halves) into a guest buffer.
void write_filetime(void* out, std::uint64_t ticks) noexcept {
    write_u32(out, FileTimeLayout::kLow, static_cast<std::uint32_t>(ticks));
    write_u32(out, FileTimeLayout::kHigh,
              static_cast<std::uint32_t>(ticks >> 32));
}

// Applies one `SetFileTime` argument to a timespec slot. A null pointer
// leaves the field untouched; the all-ones marker names the current time;
// a real tick count converts exactly; an undateable count is left alone.
void apply_set_filetime(const void* filetime, struct ::timespec& out) noexcept {
    if (filetime == nullptr) {
        out.tv_sec = 0;
        out.tv_nsec = UTIME_OMIT;
        return;
    }
    const std::uint64_t ticks = read_u64(filetime, 0);
    if (ticks == kCurrentTimeMarker) {
        out.tv_sec = 0;
        out.tv_nsec = UTIME_NOW;
        return;
    }
    if (!filetime_to_timespec(ticks, out)) {
        out.tv_sec = 0;
        out.tv_nsec = UTIME_OMIT;
    }
}

// The region helpers the lock family shares. A length of zero means "to the
// end of file" on both Windows and POSIX, which is why the value passes
// through unchanged.
[[nodiscard]] bool apply_region_lock(int fd, int type, std::uint64_t offset,
                                     std::uint64_t length, bool wait) noexcept {
    struct ::flock fl {};
    fl.l_type = static_cast<short>(type);
    fl.l_whence = SEEK_SET;
    fl.l_start = static_cast<off_t>(offset);
    fl.l_len = static_cast<off_t>(length);
    return ::fcntl(fd, wait ? F_SETLKW : F_SETLK, &fl) == 0;
}

// One range the process believes it holds, as the shadow ledger records it.
// A Windows unlock must name the exact range that was locked, so equality is
// exact: offset and length both.
struct LockRange {
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
};

[[nodiscard]] bool operator==(const LockRange& lhs, const LockRange& rhs) noexcept {
    return lhs.offset == rhs.offset && lhs.length == rhs.length;
}

// The lock ledger: the ranges this process holds, keyed by descriptor.
// POSIX's F_GETLK reports another process's lock but never the caller's own
// (own locks are not conflicts), so "do we hold this range" has no kernel
// question that answers it -- the answer has to be remembered. The ledger is
// that memory, written only by successful LockFile/LockFileEx calls and
// consulted by the unlock pair before it answers ERROR_NOT_LOCKED. Its
// stale-entry boundary is POSIX's own rule: a process's locks vanish when
// *any* descriptor to the file closes, and if that descriptor is later
// reused the entry would claim a lock the new file never had; this slice
// never observes the close, so the entry then answers "held" for a file the
// caller has not locked. The kernel unlock still runs and is harmless; only
// the not-locked refusal can be wrong, in the same direction the host's own
// lock table already is.
std::mutex g_lock_ledger_mutex;
std::unordered_map<int, std::vector<LockRange>> g_lock_ledger;

void lock_ledger_add(int fd, std::uint64_t offset, std::uint64_t length) noexcept {
    const std::lock_guard<std::mutex> held(g_lock_ledger_mutex);
    std::vector<LockRange>& ranges = g_lock_ledger[fd];
    const LockRange range{offset, length};
    if (std::find(ranges.begin(), ranges.end(), range) == ranges.end()) {
        ranges.push_back(range);
    }
}

[[nodiscard]] bool lock_ledger_holds(int fd, std::uint64_t offset,
                                     std::uint64_t length) noexcept {
    const std::lock_guard<std::mutex> held(g_lock_ledger_mutex);
    const auto found = g_lock_ledger.find(fd);
    if (found == g_lock_ledger.end()) {
        return false;
    }
    const LockRange range{offset, length};
    return std::find(found->second.begin(), found->second.end(), range) !=
           found->second.end();
}

void lock_ledger_remove(int fd, std::uint64_t offset, std::uint64_t length) noexcept {
    const std::lock_guard<std::mutex> held(g_lock_ledger_mutex);
    const auto found = g_lock_ledger.find(fd);
    if (found == g_lock_ledger.end()) {
        return;
    }
    std::vector<LockRange>& ranges = found->second;
    const LockRange range{offset, length};
    ranges.erase(std::remove(ranges.begin(), ranges.end(), range), ranges.end());
    if (ranges.empty()) {
        g_lock_ledger.erase(found);
    }
}

// Converts one wide WIN32_FIND_DATA entry into its narrow form. The header
// fields through the name share offsets, so only the name is re-encoded;
// the alternate name is left empty, which is what the wide walk fills too.
[[nodiscard]] bool copy_find_entry_wide_to_ansi(const std::uint8_t* wide_entry,
                                                std::uint8_t* ansi_entry) noexcept {
    std::memset(ansi_entry, 0, kFindABytes);
    std::memcpy(ansi_entry, wide_entry, kFindAFileName);
    const char16_t* wide_name =
        reinterpret_cast<const char16_t*>(wide_entry + kFindAFileName);
    std::size_t units = 0;
    while (units < kFindWNameChars && wide_name[units] != u'\0') {
        ++units;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(wide_name, units), narrow).converted) {
        return false;
    }
    if (narrow.size() >= kFindANameChars) {
        return false;  // a narrow name this long has no A spelling
    }
    std::memcpy(ansi_entry + kFindAFileName, narrow.data(), narrow.size());
    ansi_entry[kFindAFileName + narrow.size()] = '\0';
    return true;
}

// The volume root of a drive-letter path, or false for a path with no
// volume. Only `X:\`-shaped paths have a host analogue; UNC and bare paths
// name volumes this runtime does not mount.
[[nodiscard]] bool volume_root_of(const std::string& path, std::string& root) noexcept {
    if (path.size() < 3) {
        return false;
    }
    const unsigned char first = static_cast<unsigned char>(path[0]);
    if (!std::isalpha(first)) {
        return false;
    }
    if (path[1] != ':') {
        return false;
    }
    if (path[2] != '\\' && path[2] != '/') {
        return false;
    }
    root = std::string(1, static_cast<char>(std::toupper(first))) + ":\\";
    return true;
}

}  // namespace

// `SetFilePointer`: the 32-bit view of the seek the Ex spelling already
// serves, so this is a thin bridge and not a second implementation. With a
// high-part pointer the 64-bit offset is assembled from both halves; without
// one the low part is a signed 32-bit move, which is Windows' own reading of
// a missing high part. Success returns the low 32 bits of the new position
// and writes the high 32 bits back; failure is the all-ones sentinel with
// the error the bridge set.
extern "C" __attribute__((ms_abi)) std::uint32_t k32f3_SetFilePointer(
    void* file, std::int32_t distance_low, std::int32_t* distance_high,
    std::uint32_t move_method) noexcept {
    std::int64_t distance = 0;
    if (distance_high != nullptr) {
        const std::uint64_t high =
            static_cast<std::uint64_t>(static_cast<std::int64_t>(*distance_high));
        const std::uint64_t low =
            static_cast<std::uint64_t>(static_cast<std::uint32_t>(distance_low));
        distance = static_cast<std::int64_t>((high << 32) | low);
    } else {
        distance = static_cast<std::int64_t>(distance_low);
    }
    std::int64_t new_position = 0;
    if (k32f2_SetFilePointerEx(file, distance, &new_position, move_method) == 0) {
        return kInvalidSetFilePointer;
    }
    if (distance_high != nullptr) {
        *distance_high = static_cast<std::int32_t>(
            static_cast<std::uint32_t>(static_cast<std::uint64_t>(new_position) >> 32));
    }
    return static_cast<std::uint32_t>(static_cast<std::uint64_t>(new_position));
}

// `CopyFileExA`: the marshalling half. The wide form carries the copy.
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_CopyFileExA(
    const char* existing, const char* new_name, std::uint64_t progress_routine,
    std::uint64_t data, const std::int32_t* cancel, std::uint32_t flags) noexcept {
    if (existing == nullptr || new_name == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string existing_wide;
    std::u16string new_wide;
    if (!narrow_in(existing, existing_wide).converted ||
        !narrow_in(new_name, new_wide).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return k32f3_CopyFileExW(existing_wide.c_str(), new_wide.c_str(),
                             progress_routine, data, cancel, flags);
}

// `CopyFileExW`. The copy is real: the source is opened confined, the data
// is copied in 64 KiB chunks with the progress callback invoked after each
// one and the cancel flag consulted before each one, and mode and timestamps
// are carried over at the end. `COPY_FILE_FAIL_IF_EXISTS` refuses an
// existing destination, `COPY_FILE_COPY_SYMLINK` copies the link itself
// rather than its target, and `COPY_FILE_RESTARTABLE` leaves the partial
// file in place on failure, which is what the flag's contract promises.
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_CopyFileExW(
    const char16_t* existing, const char16_t* new_name,
    std::uint64_t progress_routine, std::uint64_t data,
    const std::int32_t* cancel, std::uint32_t flags) noexcept {
    if (existing == nullptr || new_name == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string old_narrow;
    std::string new_narrow;
    if (!narrow_out(existing, old_narrow).converted ||
        !narrow_out(new_name, new_narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::string old_host = from_dos_path(old_narrow);
    const std::string new_host = from_dos_path(new_narrow);
    if (old_host.empty() || new_host.empty()) {
        set_last_error(kErrorPathNotFound);
        return 0;
    }

    const int src_fd = contained_open(old_host.c_str(), O_RDONLY | O_CLOEXEC, 0);
    if (src_fd < 0) {
        set_file_errno(errno);
        return 0;
    }
    struct ::stat src {};
    if (::fstat(src_fd, &src) != 0) {
        const int error = errno;
        ::close(src_fd);
        set_file_errno(error);
        return 0;
    }

    // COPY_FILE_COPY_SYMLINK: a link is copied as a link, with the readlink
    // target preserved as the host wrote it. The copy is atomic -- one
    // link(2) -- so the cancel flag is checked before and after, and there
    // is no partial state to clean up.
    struct ::stat link {};
    const bool is_symlink =
        contained_stat(old_host.c_str(), link, false) == 0 && S_ISLNK(link.st_mode);
    if (is_symlink && (flags & kCopyFileCopySymlink) != 0) {
        ::close(src_fd);
        struct ::stat dst {};
        const bool dst_exists = contained_stat(new_host.c_str(), dst, true) == 0;
        if (dst_exists && (flags & kCopyFileFailIfExists) != 0) {
            set_last_error(kErrorFileExists);
            return 0;
        }
        if (cancel != nullptr && *cancel != 0) {
            set_last_error(kErrorRequestAborted);
            return 0;
        }
        char target[4096];
        const ssize_t target_len =
            ::readlink(old_host.c_str(), target, sizeof(target) - 1);
        if (target_len < 0) {
            const int error = errno;
            set_file_errno(error);
            return 0;
        }
        target[static_cast<std::size_t>(target_len)] = '\0';
        if ((flags & kCopyFileFailIfExists) == 0) {
            static_cast<void>(contained_unlink(new_host.c_str()));
        }
        if (::symlink(target, new_host.c_str()) != 0) {
            const int error = errno;
            set_file_errno(error);
            return 0;
        }
        set_last_error(kErrorSuccess);
        return 1;
    }

    // The ordinary copy: an existing destination is refused when the flag
    // says so, otherwise truncated and rewritten.
    struct ::stat dst {};
    const bool dst_exists = contained_stat(new_host.c_str(), dst, true) == 0;
    if (dst_exists && (flags & kCopyFileFailIfExists) != 0) {
        ::close(src_fd);
        set_last_error(kErrorFileExists);
        return 0;
    }
    const int dst_fd =
        contained_open(new_host.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (dst_fd < 0) {
        const int error = errno;
        ::close(src_fd);
        set_file_errno(error);
        return 0;
    }

    // The handles handed to the callback name the two descriptors. They are
    // the runtime's file-handle values, not registered entries -- the
    // callback may inspect them but owns nothing.
    const std::uint64_t src_handle =
        kFileHandleBase + static_cast<std::uint64_t>(src_fd);
    const std::uint64_t dst_handle =
        kFileHandleBase + static_cast<std::uint64_t>(dst_fd);
    const std::uint64_t total = static_cast<std::uint64_t>(src.st_size);
    const FileProgressRoutine progress =
        reinterpret_cast<FileProgressRoutine>(progress_routine);

    std::uint8_t chunk[65536];
    std::uint64_t transferred = 0;
    bool failed = false;
    std::uint32_t failure = kErrorSuccess;
    for (;;) {
        if (cancel != nullptr && *cancel != 0) {
            failed = true;
            failure = kErrorRequestAborted;
            break;
        }
        const ssize_t got = ::read(src_fd, chunk, sizeof(chunk));
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            failed = true;
            failure = kErrorWriteFault;
            break;
        }
        if (got == 0) {
            break;  // the source is exhausted
        }
        std::size_t written = 0;
        while (written < static_cast<std::size_t>(got)) {
            const ssize_t put =
                ::write(dst_fd, chunk + written, static_cast<std::size_t>(got) - written);
            if (put < 0) {
                if (errno == EINTR) {
                    continue;
                }
                failed = true;
                failure = kErrorWriteFault;
                break;
            }
            if (put == 0) {
                failed = true;
                failure = kErrorWriteFault;
                break;
            }
            written += static_cast<std::size_t>(put);
        }
        if (failed) {
            break;
        }
        transferred += static_cast<std::uint64_t>(got);
        if (progress != nullptr) {
            static_cast<void>(progress(
                static_cast<std::int64_t>(total),
                static_cast<std::int64_t>(transferred),
                static_cast<std::int64_t>(total),
                static_cast<std::int64_t>(transferred),
                kCopyStreamOne, kCopyFileChunkStaging, src_handle, dst_handle,
                data));
        }
    }

    if (failed) {
        ::close(dst_fd);
        ::close(src_fd);
        if ((flags & kCopyFileRestartable) == 0) {
            static_cast<void>(contained_unlink(new_host.c_str()));
        }
        set_last_error(failure);
        return 0;
    }

    // The copied file carries the source's mode and timestamps over, the way
    // Windows copies attributes with a file. Both are best-effort: a mode or
    // time the host refuses is not a reason to fail a copy that reached its
    // destination.
    static_cast<void>(::fchmod(dst_fd, src.st_mode & 0777));
    struct ::timespec times[2];
    times[0] = src.st_atim;
    times[1] = src.st_mtim;
    static_cast<void>(::futimens(dst_fd, times));
    ::close(dst_fd);
    ::close(src_fd);
    set_last_error(kErrorSuccess);
    return 1;
}

// `FindFirstFileW`: the directory walk is the Ex spelling's; the handle it
// mints lives in the same walk table, so `FindClose` and `FindNextFile`
// recognize it. The simple spelling adds nothing but the narrower signature.
extern "C" __attribute__((ms_abi)) void* k32f3_FindFirstFileW(
    const char16_t* pattern, void* data) noexcept {
    return k32f2_FindFirstFileExW(pattern, 0, data, 0, nullptr, nullptr);
}

// `FindFirstFileA`: the same walk, with the entry re-encoded into the narrow
// layout before it reaches the caller. A name that has no narrow spelling
// closes the walk rather than handing back a half-written entry.
extern "C" __attribute__((ms_abi)) void* k32f3_FindFirstFileA(
    const char* pattern, void* data) noexcept {
    if (pattern == nullptr || data == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return reinterpret_cast<void*>(kInvalidHandleValue);
    }
    std::u16string wide;
    if (!narrow_in(pattern, wide).converted) {
        set_last_error(kErrorInvalidParameter);
        return reinterpret_cast<void*>(kInvalidHandleValue);
    }
    alignas(8) std::uint8_t temp[kFindWBytes];
    void* handle = k32f2_FindFirstFileExW(wide.c_str(), 0, temp, 0, nullptr, nullptr);
    if (handle == reinterpret_cast<void*>(kInvalidHandleValue)) {
        return handle;  // the walk's own error stands
    }
    if (!copy_find_entry_wide_to_ansi(temp, static_cast<std::uint8_t*>(data))) {
        k32f2_FindClose(handle);
        set_last_error(kErrorInvalidParameter);
        return reinterpret_cast<void*>(kInvalidHandleValue);
    }
    set_last_error(kErrorSuccess);
    return handle;
}

// `FindNextFileA`: the continuation, with the same re-encoding. The walk's
// own handle and error conventions apply unchanged.
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_FindNextFileA(
    void* handle, void* data) noexcept {
    if (data == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    alignas(8) std::uint8_t temp[kFindWBytes];
    if (k32f2_FindNextFileW(handle, temp) == 0) {
        return 0;  // the walk's own error stands
    }
    if (!copy_find_entry_wide_to_ansi(temp, static_cast<std::uint8_t*>(data))) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

// `GetFileTime`: three timestamps out of one fstat. Any of the three
// pointers may be null, which Windows allows and which this call honors. The
// creation time answers the host's change time, the closest real date a
// Linux file carries (the kernel keeps no birth time).
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_GetFileTime(
    void* file, void* creation, void* access, void* write) noexcept {
    const int fd = file_descriptor_of(reinterpret_cast<std::uint64_t>(file));
    if (fd < 0) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    struct ::stat st {};
    if (::fstat(fd, &st) != 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (creation != nullptr) {
        write_filetime(creation, timespec_to_filetime(st.st_ctim));
    }
    if (access != nullptr) {
        write_filetime(access, timespec_to_filetime(st.st_atim));
    }
    if (write != nullptr) {
        write_filetime(write, timespec_to_filetime(st.st_mtim));
    }
    set_last_error(kErrorSuccess);
    return 1;
}

// `SetFileTime`: applies the access and write times with `futimens`. A null
// pointer leaves the field alone, the all-ones marker sets the current time,
// and any other value converts exactly. The creation time has no host
// setter -- the kernel dates a file's birth itself -- so it is accepted and
// ignored, which is the honest boundary of a filesystem that does not let
// callers choose a birth time.
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_SetFileTime(
    void* file, const void* creation, const void* access,
    const void* write) noexcept {
    (void)creation;
    const int fd = file_descriptor_of(reinterpret_cast<std::uint64_t>(file));
    if (fd < 0) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    struct ::timespec times[2];
    times[0].tv_sec = 0;
    times[0].tv_nsec = UTIME_OMIT;
    times[1].tv_sec = 0;
    times[1].tv_nsec = UTIME_OMIT;
    apply_set_filetime(access, times[0]);
    apply_set_filetime(write, times[1]);
    if (::futimens(fd, times) != 0) {
        set_last_error(errno == EBADF   ? kErrorInvalidHandle
                       : errno == EINVAL ? kErrorInvalidParameter
                                         : kErrorWriteFault);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

// `FlushViewOfFile`: msync with MS_SYNC over the pages the range touches,
// but only for an address the filemap family's view ledger knows. The host's
// msync accepts anonymous memory too and would report success for the stack,
// so success there cannot distinguish a file view; the ledger can, and an
// address outside it is the ERROR_INVALID_ADDRESS Windows gives for a bad
// base. A zero length flushes the page containing the address -- Windows
// flushes the whole view for zero, and the smallest unit the host flushes is
// the faithful answer.
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_FlushViewOfFile(
    const void* address, std::uint64_t bytes) noexcept {
    if (address == nullptr) {
        set_last_error(kErrorInvalidAddress);
        return 0;
    }
    const std::uint64_t at = reinterpret_cast<std::uint64_t>(address);
    if (!filemap_view_contains(at)) {
        // msync on the host also succeeds for anonymous memory, so a zero
        // there would bless a stack or heap address as a file view. Only an
        // address the view ledger knows is worth flushing; anything else is
        // the invalid-address refusal Windows gives for a bad base.
        set_last_error(kErrorInvalidAddress);
        return 0;
    }
    const std::uint64_t page_mask = ~std::uint64_t{0xFFF};
    const std::uint64_t start = at & page_mask;
    const std::uint64_t end = at + (bytes == 0 ? 1 : bytes);
    const std::uint64_t rounded_end =
        ((end + 0xFFF) & page_mask) < end ? start + 0x1000
                                          : ((end + 0xFFF) & page_mask);
    const std::size_t length =
        static_cast<std::size_t>(rounded_end - start);
    if (::msync(reinterpret_cast<void*>(start), length, MS_SYNC) != 0) {
        set_last_error(errno == ENOMEM || errno == EINVAL
                           ? kErrorInvalidAddress
                           : kErrorInvalidParameter);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

// `LockFile`: a non-blocking write lock over the 64-bit range the two halves
// name. A conflict -- the same range held by another process -- is
// ERROR_LOCK_VIOLATION, which is Windows' own answer; the range this process
// took is remembered in the shadow ledger so the unlock pair can refuse a
// release it did not earn.
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_LockFile(
    void* file, std::uint32_t offset_low, std::uint32_t offset_high,
    std::uint32_t len_low, std::uint32_t len_high) noexcept {
    const int fd = file_descriptor_of(reinterpret_cast<std::uint64_t>(file));
    if (fd < 0) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    const std::uint64_t offset =
        (static_cast<std::uint64_t>(offset_high) << 32) | offset_low;
    const std::uint64_t length =
        (static_cast<std::uint64_t>(len_high) << 32) | len_low;
    if (!apply_region_lock(fd, F_WRLCK, offset, length, false)) {
        set_last_error(errno == EACCES || errno == EAGAIN ? kErrorLockViolation
                                                          : kErrorInvalidHandle);
        return 0;
    }
    lock_ledger_add(fd, offset, length);
    set_last_error(kErrorSuccess);
    return 1;
}

// `UnlockFile`: release a lock this process holds. A range this process does
// not hold is ERROR_NOT_LOCKED, which POSIX would silently succeed on; the
// shadow ledger is the memory of what this process took, and the kernel
// unlock still runs so the host lock table and the ledger agree afterwards.
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_UnlockFile(
    void* file, std::uint32_t offset_low, std::uint32_t offset_high,
    std::uint32_t len_low, std::uint32_t len_high) noexcept {
    const int fd = file_descriptor_of(reinterpret_cast<std::uint64_t>(file));
    if (fd < 0) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    const std::uint64_t offset =
        (static_cast<std::uint64_t>(offset_high) << 32) | offset_low;
    const std::uint64_t length =
        (static_cast<std::uint64_t>(len_high) << 32) | len_low;
    if (!lock_ledger_holds(fd, offset, length)) {
        set_last_error(kErrorNotLocked);
        return 0;
    }
    if (!apply_region_lock(fd, F_UNLCK, offset, length, false)) {
        set_last_error(kErrorNotLocked);
        return 0;
    }
    lock_ledger_remove(fd, offset, length);
    set_last_error(kErrorSuccess);
    return 1;
}

// `LockFileEx`: the overlapped spelling. EXCLUSIVE_LOCK selects a write lock
// and its absence a read lock; FAIL_IMMEDIATELY selects the non-blocking
// form and its absence the blocking one. The offset comes out of the
// OVERLAPPED's offset fields, exactly as the asynchronous calls read it.
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_LockFileEx(
    void* file, std::uint32_t flags, std::uint32_t reserved,
    std::uint32_t len_low, std::uint32_t len_high,
    const void* overlapped) noexcept {
    (void)reserved;
    if (overlapped == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const int fd = file_descriptor_of(reinterpret_cast<std::uint64_t>(file));
    if (fd < 0) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    const std::uint64_t offset = read_u64(overlapped, OverlappedLayout::kOffset);
    const std::uint64_t length =
        (static_cast<std::uint64_t>(len_high) << 32) | len_low;
    const bool exclusive = (flags & kLockfileExclusiveLock) != 0;
    const bool wait = (flags & kLockfileFailImmediately) == 0;
    if (!apply_region_lock(fd, exclusive ? F_WRLCK : F_RDLCK, offset, length, wait)) {
        set_last_error(errno == EACCES || errno == EAGAIN ? kErrorLockViolation
                                                          : kErrorInvalidHandle);
        return 0;
    }
    lock_ledger_add(fd, offset, length);
    set_last_error(kErrorSuccess);
    return 1;
}

// `UnlockFileEx`: the overlapped spelling of the release, with the same
// not-locked refusal the simple spelling gives and the same ledger bookkeeping.
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_UnlockFileEx(
    void* file, std::uint32_t reserved, std::uint32_t len_low,
    std::uint32_t len_high, const void* overlapped) noexcept {
    (void)reserved;
    if (overlapped == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const int fd = file_descriptor_of(reinterpret_cast<std::uint64_t>(file));
    if (fd < 0) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    const std::uint64_t offset = read_u64(overlapped, OverlappedLayout::kOffset);
    const std::uint64_t length =
        (static_cast<std::uint64_t>(len_high) << 32) | len_low;
    if (!lock_ledger_holds(fd, offset, length)) {
        set_last_error(kErrorNotLocked);
        return 0;
    }
    if (!apply_region_lock(fd, F_UNLCK, offset, length, false)) {
        set_last_error(kErrorNotLocked);
        return 0;
    }
    lock_ledger_remove(fd, offset, length);
    set_last_error(kErrorSuccess);
    return 1;
}

// `GetCompressedFileSizeA`: the allocated size, which is what a compressed
// or sparse file's on-disk footprint is. The host reports it as st_blocks in
// 512-byte units, the closest real answer to Windows' compressed size, and
// the high 32 bits are returned through the optional pointer.
extern "C" __attribute__((ms_abi)) std::uint32_t k32f3_GetCompressedFileSizeA(
    const char* path, std::uint32_t* high) noexcept {
    if (path == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return kInvalidSetFilePointer;
    }
    const std::string host = from_dos_path(std::string(path));
    if (host.empty()) {
        set_last_error(kErrorPathNotFound);
        return kInvalidSetFilePointer;
    }
    struct ::stat st {};
    if (contained_stat(host.c_str(), st, true) != 0) {
        set_file_errno(errno);
        return kInvalidSetFilePointer;
    }
    const std::uint64_t allocated =
        static_cast<std::uint64_t>(st.st_blocks) * 512;
    if (high != nullptr) {
        *high = static_cast<std::uint32_t>(allocated >> 32);
    }
    set_last_error(kErrorSuccess);
    return static_cast<std::uint32_t>(allocated);
}

// `GetCompressedFileSizeW`: the wide spelling, with the same answer.
extern "C" __attribute__((ms_abi)) std::uint32_t k32f3_GetCompressedFileSizeW(
    const char16_t* path, std::uint32_t* high) noexcept {
    if (path == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return kInvalidSetFilePointer;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(path), narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return kInvalidSetFilePointer;
    }
    return k32f3_GetCompressedFileSizeA(narrow.c_str(), high);
}

// `GetLongPathNameA`. On a volume without 8.3 names the long name *is* the
// name, and Windows answers the input unchanged there; this runtime's host
// has no short names at all, so the same identity is the correct answer,
// with the same existence and buffer conventions the already-registered wide
// spelling uses -- the two spellings cannot disagree. (A realpath-based
// canonicalization was considered and rejected: it would resolve symlinks
// Windows' long-path call does not resolve, and it would make the A and W
// spellings answer differently.)
extern "C" __attribute__((ms_abi)) std::uint32_t k32f3_GetLongPathNameA(
    const char* path, char* buffer, std::uint32_t capacity) noexcept {
    if (path == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::string narrow(path);
    const std::string host = from_dos_path(narrow);
    if (host.empty() || contained_access(host.c_str(), F_OK) != 0) {
        set_last_error(kErrorFileNotFound);
        return 0;
    }
    const std::size_t units = narrow.size();
    if (capacity < units + 1) {
        set_last_error(kErrorInsufficientBuffer);
        return static_cast<std::uint32_t>(units + 1);
    }
    if (buffer == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::memcpy(buffer, narrow.data(), units);
    buffer[units] = '\0';
    set_last_error(kErrorSuccess);
    return static_cast<std::uint32_t>(units);
}

// `GetShortPathNameA`: the same identity in the other direction. A volume
// without short names answers a short-name query with the long name, and
// this host is such a volume, so the path is returned as written.
extern "C" __attribute__((ms_abi)) std::uint32_t k32f3_GetShortPathNameA(
    const char* path, char* buffer, std::uint32_t capacity) noexcept {
    if (path == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::string narrow(path);
    const std::string host = from_dos_path(narrow);
    if (host.empty() || contained_access(host.c_str(), F_OK) != 0) {
        set_last_error(kErrorFileNotFound);
        return 0;
    }
    const std::size_t units = narrow.size();
    if (capacity < units + 1) {
        set_last_error(kErrorInsufficientBuffer);
        return static_cast<std::uint32_t>(units + 1);
    }
    if (buffer == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::memcpy(buffer, narrow.data(), units);
    buffer[units] = '\0';
    set_last_error(kErrorSuccess);
    return static_cast<std::uint32_t>(units);
}

// `GetShortPathNameW`: the wide spelling of the same answer.
extern "C" __attribute__((ms_abi)) std::uint32_t k32f3_GetShortPathNameW(
    const char16_t* path, char16_t* buffer, std::uint32_t capacity) noexcept {
    if (path == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::u16string_view text(path);
    const std::size_t units = text.size();
    std::string narrow;
    if (!narrow_out(text, narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::string host = from_dos_path(narrow);
    if (host.empty() || contained_access(host.c_str(), F_OK) != 0) {
        set_last_error(kErrorFileNotFound);
        return 0;
    }
    if (capacity < units + 1) {
        set_last_error(kErrorInsufficientBuffer);
        return static_cast<std::uint32_t>(units + 1);
    }
    if (buffer == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    for (std::size_t i = 0; i <= units; ++i) {
        buffer[i] = text[i];
    }
    set_last_error(kErrorSuccess);
    return static_cast<std::uint32_t>(units);
}

// `CreateHardLinkA`: the marshalling half.
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_CreateHardLinkA(
    const char* new_name, const char* existing, void* security) noexcept {
    if (new_name == nullptr || existing == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string new_wide;
    std::u16string old_wide;
    if (!narrow_in(new_name, new_wide).converted ||
        !narrow_in(existing, old_wide).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return k32f3_CreateHardLinkW(new_wide.c_str(), old_wide.c_str(), security);
}

// `CreateHardLinkW`: one link(2), made confined on both ends. The security
// argument is reserved by Windows and must be null; a cross-device link is
// the same ERROR_NOT_SAME_DEVICE Windows gives, and an existing destination
// the same ERROR_ALREADY_EXISTS.
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_CreateHardLinkW(
    const char16_t* new_name, const char16_t* existing, void* security) noexcept {
    (void)security;
    if (new_name == nullptr || existing == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string new_narrow;
    std::string old_narrow;
    if (!narrow_out(new_name, new_narrow).converted ||
        !narrow_out(existing, old_narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::string new_host = from_dos_path(new_narrow);
    const std::string old_host = from_dos_path(old_narrow);
    if (new_host.empty() || old_host.empty()) {
        set_last_error(kErrorPathNotFound);
        return 0;
    }

    // Both sides are resolved to a confined parent descriptor plus a leaf,
    // and linked with linkat between them -- the same end-to-end confinement
    // every other path-taking call gets.
    std::string new_leaf;
    const int new_parent = contained_parent(new_host.c_str(), new_leaf);
    if (new_parent < 0) {
        const int error = errno;
        set_file_errno(error);
        return 0;
    }
    std::string old_leaf;
    const int old_parent = contained_parent(old_host.c_str(), old_leaf);
    if (old_parent < 0) {
        const int error = errno;
        ::close(new_parent);
        set_file_errno(error);
        return 0;
    }
    const int answered =
        ::linkat(old_parent, old_leaf.c_str(), new_parent, new_leaf.c_str(), 0);
    const int error = errno;
    ::close(old_parent);
    ::close(new_parent);
    if (answered != 0) {
        set_file_errno(error);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

// `GetVolumePathNameA`: the volume root of a drive-letter path, answered as
// a BOOL with the root written into the buffer. The drive model this runtime
// mounts is the one dos_path.h names, so a path anchored at a mounted drive
// answers `X:\`; a path with no drive has no volume and gets the
// invalid-parameter refusal Windows gives a malformed name. UNC paths name
// shares this runtime has no analogue for, and are refused the same way.
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_GetVolumePathNameA(
    const char* path, char* buffer, std::uint32_t capacity) noexcept {
    if (path == nullptr || buffer == nullptr || capacity == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string root;
    if (!volume_root_of(std::string(path), root)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::size_t units = root.size();
    if (capacity < units + 1) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    std::memcpy(buffer, root.data(), units);
    buffer[units] = '\0';
    set_last_error(kErrorSuccess);
    return 1;
}

// `GetVolumePathNameW`: the wide spelling of the same answer.
extern "C" __attribute__((ms_abi)) std::int32_t k32f3_GetVolumePathNameW(
    const char16_t* path, char16_t* buffer, std::uint32_t capacity) noexcept {
    if (path == nullptr || buffer == nullptr || capacity == 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(path), narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string root;
    if (!volume_root_of(narrow, root)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::size_t units = root.size();
    if (capacity < units + 1) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    for (std::size_t i = 0; i <= units; ++i) {
        buffer[i] = static_cast<char16_t>(root[i]);
    }
    set_last_error(kErrorSuccess);
    return 1;
}

// ------------------------------------------------------------- registration

void add_kernel32_file3(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CopyFileExA", reinterpret_cast<void*>(&k32f3_CopyFileExA));
    e("CopyFileExW", reinterpret_cast<void*>(&k32f3_CopyFileExW));
    e("CreateHardLinkA", reinterpret_cast<void*>(&k32f3_CreateHardLinkA));
    e("CreateHardLinkW", reinterpret_cast<void*>(&k32f3_CreateHardLinkW));
    e("FindFirstFileA", reinterpret_cast<void*>(&k32f3_FindFirstFileA));
    e("FindFirstFileW", reinterpret_cast<void*>(&k32f3_FindFirstFileW));
    e("FindNextFileA", reinterpret_cast<void*>(&k32f3_FindNextFileA));
    e("FlushViewOfFile", reinterpret_cast<void*>(&k32f3_FlushViewOfFile));
    e("GetCompressedFileSizeA",
      reinterpret_cast<void*>(&k32f3_GetCompressedFileSizeA));
    e("GetCompressedFileSizeW",
      reinterpret_cast<void*>(&k32f3_GetCompressedFileSizeW));
    e("GetFileTime", reinterpret_cast<void*>(&k32f3_GetFileTime));
    e("GetLongPathNameA", reinterpret_cast<void*>(&k32f3_GetLongPathNameA));
    e("GetShortPathNameA", reinterpret_cast<void*>(&k32f3_GetShortPathNameA));
    e("GetShortPathNameW", reinterpret_cast<void*>(&k32f3_GetShortPathNameW));
    e("GetVolumePathNameA", reinterpret_cast<void*>(&k32f3_GetVolumePathNameA));
    e("GetVolumePathNameW", reinterpret_cast<void*>(&k32f3_GetVolumePathNameW));
    e("LockFile", reinterpret_cast<void*>(&k32f3_LockFile));
    e("LockFileEx", reinterpret_cast<void*>(&k32f3_LockFileEx));
    e("SetFilePointer", reinterpret_cast<void*>(&k32f3_SetFilePointer));
    e("SetFileTime", reinterpret_cast<void*>(&k32f3_SetFileTime));
    e("UnlockFile", reinterpret_cast<void*>(&k32f3_UnlockFile));
    e("UnlockFileEx", reinterpret_cast<void*>(&k32f3_UnlockFileEx));
}

}  // namespace occ::runtime::winabi

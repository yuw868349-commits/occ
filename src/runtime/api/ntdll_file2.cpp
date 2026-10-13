// The ntdll file family, as the kernel layer spells it.
//
// The `Nt*` calls here are the synchronous core of the file subsystem:
// create and open a file by counted name, read and write it at an explicit
// or current offset, and query or set the information classes a caller
// actually names. Each is implemented on the host's own file operations --
// open, pread, pwrite, fstat, futimens, ftruncate, lseek -- through the
// same confined path resolution the Win32 file domains use, and each mints
// its handles in the file domain's range (0x2000 base) and registers them
// with `add_file_handle`, so a handle created here is closed by the same
// `CloseHandle`/`NtClose` path that closes a `CreateFile` handle.
//
// The boundary is the model, not the mechanism. This runtime completes
// every I/O before it returns, so the `Event` and `ApcRoutine` arguments
// of the read/write pair describe an asynchronous completion that cannot
// occur: they are accepted and ignored, with the synchronous answer written
// into the IO_STATUS_BLOCK, exactly as the rest of the runtime answers
// overlapped calls. The environment-value pair is a refusal: Linux exposes
// no UEFI system environment namespace, so `NtQuery/SetSystemEnvironmentValue`
// answer `STATUS_NOT_IMPLEMENTED` rather than a pretend firmware.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/containment.h"
#include "occ/runtime/dos_path.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include <cerrno>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

namespace occ::runtime::winabi {

// The file-handle table this file shares its handles with. `add_file_handle`
// is how a handle created here becomes closable by the Win32 `CloseHandle`,
// which `take_file_handle`s it back out; the declaration lives here because
// the function is not in a header, exactly as the loader slice declares its
// bridges.
void add_file_handle(std::uint64_t handle) noexcept;

namespace {

// An NTSTATUS is a 32-bit value whose top bits carry the severity. The
// constants below are the statuses this file answers; the win32 errors stay
// in the Win32 domains, because a file call's contract is its status.
using Ntstatus = std::uint32_t;

constexpr Ntstatus kStSuccess = 0x00000000;
constexpr Ntstatus kStUnsuccessful = 0xC0000001;
constexpr Ntstatus kStNotImplemented = 0xC0000002;
constexpr Ntstatus kStInvalidInfoClass = 0xC0000003;
constexpr Ntstatus kStInfoLengthMismatch = 0xC0000004;
constexpr Ntstatus kStInvalidHandle = 0xC0000008;
constexpr Ntstatus kStInvalidParameter = 0xC000000D;
constexpr Ntstatus kStEndOfFile = 0xC0000011;
constexpr Ntstatus kStNoMemory = 0xC0000017;
constexpr Ntstatus kStAccessDenied = 0xC0000022;
constexpr Ntstatus kStObjectNameInvalid = 0xC0000033;
constexpr Ntstatus kStObjectNameNotFound = 0xC0000034;
constexpr Ntstatus kStObjectNameCollision = 0xC0000035;
constexpr Ntstatus kStObjectPathNotFound = 0xC000003A;
constexpr Ntstatus kStNotADirectory = 0xC0000103;
constexpr Ntstatus kStFileIsADirectory = 0xC00000BA;

// The file handle base and span, the same constants the Win32 file domains
// mint from. A handle outside the range was not minted for a file.
constexpr std::uint64_t kFileHandleBase = 0x2000;
constexpr std::uint64_t kFileHandleSpan = 0x100000;

// FILE_USE_FILE_POINTER_POSITION, the marker `NtReadFile`/`NtWriteFile` read
// when the caller means "use the current position" instead of an explicit
// offset. It is -2, a sentinel no real offset collides with.
constexpr std::uint64_t kFileUseFilePointerPosition = 0xFFFFFFFFFFFFFFFEULL;

// The create dispositions, as ntdll numbers them.
constexpr std::uint32_t kFileSupersede = 0;
constexpr std::uint32_t kFileOpen = 1;
constexpr std::uint32_t kFileCreate = 2;
constexpr std::uint32_t kFileOpenIf = 3;
constexpr std::uint32_t kFileOverwrite = 4;
constexpr std::uint32_t kFileOverwriteIf = 5;

// What `NtCreateFile`'s IO_STATUS_BLOCK.Information reports: which of the
// disposition outcomes actually happened. These are the ntifs.h constants.
constexpr std::uint64_t kFileSuperseded = 0;
constexpr std::uint64_t kFileOpened = 1;
constexpr std::uint64_t kFileCreated = 2;
constexpr std::uint64_t kFileOverwritten = 3;

// The create-option bits this file acts on. The synchronous flags describe
// what this runtime already is, and the buffering/sequential hints have no
// host analogue, so only the directory and non-directory demands and the
// delete-on-close request change the open.
constexpr std::uint32_t kFileDirectoryFile = 0x00000001;
constexpr std::uint32_t kFileNonDirectoryFile = 0x00000040;
constexpr std::uint32_t kFileDeleteOnClose = 0x00001000;

// The access bits that mean "read" and "write" at the nt layer: the generic
// pair plus the data and attribute bits a caller may ask for without the
// generic ones.
constexpr std::uint32_t kGenericRead = 0x80000000;
constexpr std::uint32_t kGenericWrite = 0x40000000;
constexpr std::uint32_t kFileReadData = 0x00000001;
constexpr std::uint32_t kFileWriteData = 0x00000002;
constexpr std::uint32_t kFileAppendData = 0x00000004;
constexpr std::uint32_t kFileReadAttributes = 0x00000080;

// FILE_ATTRIBUTE_READONLY, the one attribute bit that maps onto a host mode.
constexpr std::uint32_t kAttributeReadOnly = 0x00000001;
constexpr std::uint32_t kAttributeDirectory = 0x00000010;
constexpr std::uint32_t kAttributeNormal = 0x00000080;

// IO_STATUS_BLOCK, as the guest lays it out: a status at zero and a
// pointer-width Information field at eight.
constexpr std::size_t kIoStatus = 0;
constexpr std::size_t kIoInformation = 8;

// OBJECT_ATTRIBUTES, 48 bytes on the 64-bit ABI: length, root directory
// handle, counted-name pointer, attributes, security descriptor, QoS. The
// Length field is validated against the size below; the rest of the record
// (attributes, security descriptor, QoS) is not acted on by a runtime that
// has no security or object-attribute machinery.
constexpr std::size_t kObjectAttributesBytes = 48;
constexpr std::size_t kObjectAttributesLength = 0;
constexpr std::size_t kObjectAttributesRoot = 8;
constexpr std::size_t kObjectAttributesName = 16;

// UNICODE_STRING, as the loader reads it: a byte length, a byte capacity,
// and a pointer to the UTF-16 characters.
constexpr std::size_t kCountedLength = 0;
constexpr std::size_t kCountedMaximum = 2;
constexpr std::size_t kCountedBuffer = 8;

// The information classes this file answers. FileBasicInformation,
// FileStandardInformation, FilePositionInformation and
// FileEndOfFileInformation are the four the family's callers actually use
// for real file work; anything else is a question this file has no answer
// to and is refused with STATUS_INVALID_INFO_CLASS.
constexpr std::uint32_t kFileBasicInformation = 4;
constexpr std::uint32_t kFileStandardInformation = 5;
constexpr std::uint32_t kFilePositionInformation = 14;
constexpr std::uint32_t kFileEndOfFileInformation = 20;

// FILE_BASIC_INFORMATION, 40 bytes: four FILETIMEs, attributes, reserved.
constexpr std::size_t kBasicCreationTime = 0;
constexpr std::size_t kBasicLastAccessTime = 8;
constexpr std::size_t kBasicLastWriteTime = 16;
constexpr std::size_t kBasicChangeTime = 24;
constexpr std::size_t kBasicFileAttributes = 32;
constexpr std::size_t kBasicBytes = 40;

// FILE_STANDARD_INFORMATION, 24 bytes on the 64-bit ABI: two 64-bit sizes,
// a link count, then two byte flags and padding. The offsets are the real
// layout -- NumberOfLinks sits at 16 with the flags at 20/21 -- and the
// source for that is the wdm.h definition, which the MSDN structure page
// confirms.
constexpr std::size_t kStandardAllocationSize = 0;
constexpr std::size_t kStandardEndOfFile = 8;
constexpr std::size_t kStandardNumberOfLinks = 16;
constexpr std::size_t kStandardDeletePending = 20;
constexpr std::size_t kStandardDirectory = 21;
constexpr std::size_t kStandardBytes = 24;

// FILE_POSITION_INFORMATION and FILE_END_OF_FILE_INFORMATION are each one
// 64-bit value.
constexpr std::size_t kPositionCurrentOffset = 0;
constexpr std::size_t kPositionBytes = 8;
constexpr std::size_t kEndOfFileValue = 0;
constexpr std::size_t kEndOfFileBytes = 8;

// FILE_NETWORK_OPEN_INFORMATION, 56 bytes on the 64-bit ABI: four FILETIMEs,
// allocation and end-of-file sizes, and the attributes. The layout is the
// wdm.h definition (CreationTime at 0 ... FileAttributes at 48), confirmed
// against the MSDN structure page before being written here.
constexpr std::size_t kNetworkCreationTime = 0;
constexpr std::size_t kNetworkLastAccessTime = 8;
constexpr std::size_t kNetworkLastWriteTime = 16;
constexpr std::size_t kNetworkChangeTime = 24;
constexpr std::size_t kNetworkAllocationSize = 32;
constexpr std::size_t kNetworkEndOfFile = 40;
constexpr std::size_t kNetworkFileAttributes = 48;
constexpr std::size_t kNetworkBytes = 56;

// The FILETIME clock: 100-nanosecond ticks from 1601-01-01, which is
// 11644473600 seconds before the host's 1970 epoch.
constexpr std::int64_t kTicksPerSecond = 10000000;
constexpr std::int64_t kEpochDeltaSeconds = 11644473600;

// "Leave this timestamp alone", the value a caller writes for a time field
// it does not want changed.
constexpr std::uint64_t kIgnoreTime = 0xFFFFFFFFFFFFFFFFULL;

// ------------------------------------------------------------------ helpers

// Maps a host open failure onto the status Windows would give the same
// situation. The layer names the failure with errno; this table names it
// with a status.
[[nodiscard]] Ntstatus errno_status(int code) noexcept {
    switch (code) {
    case ENOENT:
        return kStObjectNameNotFound;
    case ENOTDIR:
        return kStObjectPathNotFound;
    case EEXIST:
        return kStObjectNameCollision;
    case EACCES:
    case EPERM:
    case EROFS:
        return kStAccessDenied;
    case EINVAL:
        return kStInvalidParameter;
    case ENAMETOOLONG:
    case ELOOP:
        return kStObjectNameInvalid;
    case ENOMEM:
        return kStNoMemory;
    case EISDIR:
        return kStFileIsADirectory;
    default:
        return kStUnsuccessful;
    }
}

// Whether `handle` falls in the file range this runtime mints from. The
// range check is the same one the Win32 file wrappers apply; whether the
// descriptor underneath is still live is asked of the descriptor itself.
[[nodiscard]] bool is_file_handle(std::uint64_t handle) noexcept {
    return handle >= kFileHandleBase && handle < kFileHandleBase + kFileHandleSpan;
}

// Decodes a file handle to its descriptor. The descriptor's liveness is
// checked with F_GETFD, the only truth a host can give about an fd without
// owning the handle table; a handle that was closed answers invalid here,
// exactly as it does in the Win32 file wrappers.
[[nodiscard]] int file_descriptor_of(std::uint64_t handle) noexcept {
    if (!is_file_handle(handle)) {
        return -1;
    }
    const int fd = static_cast<int>(handle - kFileHandleBase);
    if (::fcntl(fd, F_GETFD) < 0) {
        return -1;
    }
    return fd;
}

// A `timespec` converted to a FILETIME tick count. The conversion is exact
// over the range the structures can hold; a time before 1601 has no FILETIME
// and answers zero, which is what the guest sees for a file the host cannot
// date.
[[nodiscard]] std::uint64_t timespec_to_filetime(const struct ::timespec& ts) noexcept {
    const std::int64_t seconds = static_cast<std::int64_t>(ts.tv_sec);
    if (seconds < kEpochDeltaSeconds) {
        return 0;
    }
    const std::uint64_t since_1970 = static_cast<std::uint64_t>(seconds - kEpochDeltaSeconds);
    const std::uint64_t nsec_ticks =
        static_cast<std::uint64_t>(ts.tv_nsec) / 100;
    return since_1970 * static_cast<std::uint64_t>(kTicksPerSecond) + nsec_ticks;
}

// The attribute answer for a stat result. The host carries no hidden or
// system bits, so the answer is built from the three facts it does have:
// directory-ness, read-only-ness, and the normal default otherwise.
[[nodiscard]] std::uint32_t attributes_from_stat(const struct ::stat& st) noexcept {
    std::uint32_t out = kAttributeNormal;
    if (S_ISDIR(st.st_mode)) {
        out = kAttributeDirectory;
    }
    if ((st.st_mode & 0222) == 0) {
        out |= kAttributeReadOnly;
    }
    return out;
}

// Reads the counted name an OBJECT_ATTRIBUTES points at, into a host string
// of UTF-8. Returns false when the record is malformed or names nothing.
[[nodiscard]] bool read_object_name(const std::uint8_t* object_attributes,
                                    std::string& out) noexcept {
    if (object_attributes == nullptr) {
        return false;
    }
    // The record's Length field names the valid prefix; a record that does
    // not even cover its own header is malformed.
    if (read_u32(object_attributes, kObjectAttributesLength) <
        static_cast<std::uint32_t>(kObjectAttributesBytes)) {
        return false;
    }
    const std::uint64_t name_ptr = read_ptr(object_attributes, kObjectAttributesName);
    if (name_ptr == 0) {
        return false;
    }
    const std::uint8_t* name = reinterpret_cast<const std::uint8_t*>(name_ptr);
    const std::uint16_t length = read_u16(name, kCountedLength);
    const std::uint16_t maximum = read_u16(name, kCountedMaximum);
    const std::uint64_t buffer = read_ptr(name, kCountedBuffer);
    if (buffer == 0 || (length % 2) != 0 || length > maximum) {
        return false;
    }
    const char16_t* chars = reinterpret_cast<const char16_t*>(buffer);
    const std::size_t units = static_cast<std::size_t>(length) / 2;
    std::u16string wide(chars, units);
    return narrow_out(std::u16string_view(wide), out).converted;
}

// Resolves an OBJECT_ATTRIBUTES to a host path. The counted name is the
// path proper; a non-zero RootDirectory handle names a directory the path
// is relative to, and the directory's own host path is recovered through
// /proc/self/fd, so a relative name resolves exactly as Windows resolves it
// against the opened directory. An absolute name ignores the root, which is
// Windows' own rule.
[[nodiscard]] bool resolve_object_path(const std::uint8_t* object_attributes,
                                       std::string& host_path,
                                       Ntstatus& status) noexcept {
    if (!read_object_name(object_attributes, host_path)) {
        status = kStObjectNameInvalid;
        return false;
    }
    const std::uint64_t root = read_ptr(object_attributes, kObjectAttributesRoot);
    if (root == 0) {
        const std::string mapped = from_dos_path(host_path);
        if (mapped.empty()) {
            status = kStObjectNameInvalid;
            return false;
        }
        host_path = mapped;
        return true;
    }
    if (!is_file_handle(root)) {
        status = kStInvalidHandle;
        return false;
    }
    const int root_fd = static_cast<int>(root - kFileHandleBase);
    // The directory descriptor's name is read as one path: the prefix is
    // fixed and the descriptor number makes it unique.
    char link[4096];
    std::string proc_link = "/proc/self/fd/";
    proc_link += std::to_string(root_fd);
    const ssize_t len = ::readlink(proc_link.c_str(), link, sizeof(link) - 1);
    if (len < 0) {
        status = kStInvalidHandle;
        return false;
    }
    link[static_cast<std::size_t>(len)] = '\0';
    const std::string root_host(link, static_cast<std::size_t>(len));
    // A name that maps to an absolute host path is anchored at the root and
    // ignores the root directory; anything else is resolved beneath it.
    const std::string mapped = from_dos_path(host_path);
    if (!mapped.empty() && mapped[0] == '/') {
        host_path = mapped;
        return true;
    }
    host_path = root_host + "/" + host_path;
    return true;
}

// Whether a path existed before an open, which is what lets the create call
// report which disposition outcome happened. A path that fails with ENOENT
// simply did not exist; any other stat failure is a refusal.
[[nodiscard]] bool path_exists(const std::string& host_path,
                               struct ::stat& st,
                               Ntstatus& status) noexcept {
    if (contained_stat(host_path.c_str(), st, true) == 0) {
        return true;
    }
    if (errno == ENOENT) {
        return false;
    }
    status = errno_status(errno);
    return false;
}

// Classifies a missing final component by asking which part of the path is
// gone: a parent that does not exist names a missing path
// (STATUS_OBJECT_PATH_NOT_FOUND), a parent that exists with only the leaf
// absent names a missing object (STATUS_OBJECT_NAME_NOT_FOUND), and a parent
// component that is a file rather than a directory names a missing path too.
// The host path is already resolved, so the parent is a plain substring -- no
// second path translation is invented here. A root-level path has no parent
// segment to inspect and is missing as a name, which is Windows' answer for
// it as well.
[[nodiscard]] Ntstatus missing_component_status(const std::string& host_path) noexcept {
    const std::size_t slash = host_path.find_last_of('/');
    if (slash == std::string::npos || slash == 0) {
        return kStObjectNameNotFound;
    }
    const std::string parent = host_path.substr(0, slash);
    struct ::stat st {};
    if (contained_stat(parent.c_str(), st, true) == 0) {
        return kStObjectNameNotFound;
    }
    if (errno == ENOENT || errno == ENOTDIR) {
        return kStObjectPathNotFound;
    }
    return kStObjectNameNotFound;
}

// Opens the descriptor for a resolved path according to the create request.
// `directory_requested` forces the open onto directory semantics; the mode
// is the host's default, with the readonly attribute applied afterwards.
[[nodiscard]] int open_descriptor(const std::string& host_path, bool want_read,
                                  bool want_write, bool directory_requested,
                                  int extra_flags) noexcept {
    int host_flags = O_CLOEXEC | extra_flags;
    if (directory_requested) {
        // A directory handle is a read handle on Windows too; O_RDONLY with
        // O_DIRECTORY is the only mode the host accepts for one.
        host_flags |= O_RDONLY | O_DIRECTORY;
    } else if (want_read && want_write) {
        host_flags |= O_RDWR;
    } else if (want_write) {
        host_flags |= O_WRONLY;
    } else {
        host_flags |= O_RDONLY;
    }
    return contained_open(host_path.c_str(), host_flags, 0666);
}

// Writes a status and a byte count into an IO_STATUS_BLOCK, when the caller
// provided one.
void report_io_status(std::uint8_t* io_status, Ntstatus status,
                      std::uint64_t information) noexcept {
    if (io_status == nullptr) {
        return;
    }
    write_u32(io_status, kIoStatus, status);
    write_u64(io_status, kIoInformation, information);
}

// Fills a FILE_BASIC_INFORMATION from a stat result.
void fill_basic_information(void* info, const struct ::stat& st) noexcept {
    std::memset(info, 0, kBasicBytes);
    write_u64(info, kBasicCreationTime, timespec_to_filetime(st.st_ctim));
    write_u64(info, kBasicLastAccessTime, timespec_to_filetime(st.st_atim));
    write_u64(info, kBasicLastWriteTime, timespec_to_filetime(st.st_mtim));
    write_u64(info, kBasicChangeTime, timespec_to_filetime(st.st_ctim));
    write_u32(info, kBasicFileAttributes, attributes_from_stat(st));
}

}  // namespace

// `NtCreateFile`. The disposition maps onto the host's open flags, the
// access onto the read/write bits, and the name through the same confined
// path resolution the Win32 file calls use. Share access, the EA buffer and
// the allocation size are a single-process, non-encrypted world's absent
// features and are accepted and ignored; the synchronous flags describe what
// this runtime already is. The outcome -- opened, created, overwritten or
// superseded -- is reported in the IO_STATUS_BLOCK the way the create
// contract asks.
extern "C" __attribute__((ms_abi)) std::uint32_t ntf2_NtCreateFile(
    std::uint64_t* handle, std::uint32_t desired_access,
    const std::uint8_t* object_attributes, std::uint8_t* io_status,
    const std::uint64_t* allocation_size, std::uint32_t file_attributes,
    std::uint32_t share_access, std::uint32_t create_disposition,
    std::uint32_t create_options, const void* ea_buffer,
    std::uint32_t ea_length) noexcept {
    (void)allocation_size;
    (void)share_access;
    (void)ea_buffer;
    (void)ea_length;
    if (handle == nullptr) {
        return kStInvalidParameter;
    }
    if ((create_options & kFileDirectoryFile) != 0 &&
        (create_options & kFileNonDirectoryFile) != 0) {
        // The two demands contradict; Windows refuses the combination.
        report_io_status(io_status, kStInvalidParameter, 0);
        return kStInvalidParameter;
    }

    std::string host_path;
    Ntstatus path_status = kStSuccess;
    if (!resolve_object_path(object_attributes, host_path, path_status)) {
        report_io_status(io_status, path_status, 0);
        return path_status;
    }

    struct ::stat st {};
    Ntstatus stat_status = kStSuccess;
    const bool existed = path_exists(host_path, st, stat_status);
    if (!existed && stat_status != kStSuccess) {
        report_io_status(io_status, stat_status, 0);
        return stat_status;
    }

    // A disposition that demands an existing file and finds none, or that
    // refuses an existing one, fails before any descriptor is opened. A
    // missing leaf and a missing parent directory are different failures on
    // Windows, and the distinction is asked of the path itself.
    switch (create_disposition) {
    case kFileOpen:
    case kFileOverwrite:
        if (!existed) {
            const Ntstatus missing = missing_component_status(host_path);
            report_io_status(io_status, missing, 0);
            return missing;
        }
        break;
    case kFileCreate:
        if (existed) {
            report_io_status(io_status, kStObjectNameCollision, 0);
            return kStObjectNameCollision;
        }
        break;
    default:
        break;
    }

    const bool want_read =
        (desired_access & (kGenericRead | kFileReadData | kFileReadAttributes)) != 0;
    const bool want_write =
        (desired_access & (kGenericWrite | kFileWriteData | kFileAppendData)) != 0;
    const bool directory_requested = (create_options & kFileDirectoryFile) != 0;

    int extra_flags = 0;
    switch (create_disposition) {
    case kFileSupersede:
        extra_flags = O_CREAT | O_TRUNC;
        break;
    case kFileCreate:
        extra_flags = O_CREAT | O_EXCL;
        break;
    case kFileOpenIf:
        extra_flags = O_CREAT;
        break;
    case kFileOverwrite:
        extra_flags = O_TRUNC;
        break;
    case kFileOverwriteIf:
        extra_flags = O_CREAT | O_TRUNC;
        break;
    default:
        // A disposition this table does not name is a malformed request.
        report_io_status(io_status, kStInvalidParameter, 0);
        return kStInvalidParameter;
    }

    // A directory is created with mkdir -- the open flags have no "create a
    // directory" spelling -- and opened read-only, which is Windows' own
    // answer for a directory handle.
    if (directory_requested && !existed && extra_flags != 0) {
        if (contained_mkdir(host_path.c_str(), 0777) != 0) {
            const Ntstatus status =
                errno == ENOENT ? missing_component_status(host_path)
                                : errno_status(errno);
            report_io_status(io_status, status, 0);
            return status;
        }
        extra_flags = 0;
    }

    const int fd = open_descriptor(host_path, want_read, want_write,
                                   directory_requested, extra_flags);
    if (fd < 0) {
        const Ntstatus status =
            errno == ENOENT ? missing_component_status(host_path)
                            : errno_status(errno);
        report_io_status(io_status, status, 0);
        return status;
    }

    // The open result is cross-checked against what the caller demanded: a
    // directory must have been asked for as one, and a non-directory demand
    // must not have been answered with a directory.
    struct ::stat opened {};
    bool wrong_kind = false;
    Ntstatus kind_status = kStSuccess;
    if (::fstat(fd, &opened) != 0) {
        wrong_kind = true;
        kind_status = errno_status(errno);
    } else if (S_ISDIR(opened.st_mode) && !directory_requested) {
        wrong_kind = true;
        kind_status = kStFileIsADirectory;
    } else if (!S_ISDIR(opened.st_mode) && directory_requested) {
        wrong_kind = true;
        kind_status = kStNotADirectory;
    } else if ((create_options & kFileNonDirectoryFile) != 0 &&
               S_ISDIR(opened.st_mode)) {
        wrong_kind = true;
        kind_status = kStFileIsADirectory;
    }
    if (wrong_kind) {
        ::close(fd);
        report_io_status(io_status, kind_status, 0);
        return kind_status;
    }

    // DELETE_ON_CLOSE: the file is unlinked now, while the descriptor keeps
    // the inode alive until the last close -- the same observable effect as
    // Windows' delete-on-close. A directory or a failure to unlink is
    // tolerated the way Windows tolerates a delete it cannot complete.
    if ((create_options & kFileDeleteOnClose) != 0 && S_ISREG(opened.st_mode)) {
        static_cast<void>(contained_unlink(host_path.c_str()));
    }

    // The readonly attribute is applied to a file this call created or
    // truncated; on a file opened existing the attribute is a query answer,
    // not a mode a caller changes by opening.
    if ((file_attributes & kAttributeReadOnly) != 0 && S_ISREG(opened.st_mode) &&
        extra_flags != 0) {
        static_cast<void>(::fchmod(fd, 0444));
    }

    // Which disposition outcome happened: the existence before the open and
    // the disposition together name it.
    std::uint64_t information = kFileOpened;
    switch (create_disposition) {
    case kFileSupersede:
        information = existed ? kFileSuperseded : kFileCreated;
        break;
    case kFileCreate:
    case kFileOpenIf:
        information = existed ? kFileOpened : kFileCreated;
        break;
    case kFileOverwrite:
    case kFileOverwriteIf:
        information = existed ? kFileOverwritten : kFileCreated;
        break;
    default:
        information = kFileOpened;
        break;
    }

    const std::uint64_t out_handle =
        kFileHandleBase + static_cast<std::uint64_t>(fd);
    add_file_handle(out_handle);
    *handle = out_handle;
    report_io_status(io_status, kStSuccess, information);
    return kStSuccess;
}

// `NtOpenFile`: the open-existing half of the create pair. The disposition
// is fixed at OPEN, and the directory/non-directory demands are checked
// against the stat result before the descriptor is opened, which is the
// order Windows answers them in.
extern "C" __attribute__((ms_abi)) std::uint32_t ntf2_NtOpenFile(
    std::uint64_t* handle, std::uint32_t desired_access,
    const std::uint8_t* object_attributes, std::uint8_t* io_status,
    std::uint32_t share_access, std::uint32_t open_options) noexcept {
    (void)share_access;
    if (handle == nullptr) {
        return kStInvalidParameter;
    }
    if ((open_options & kFileDirectoryFile) != 0 &&
        (open_options & kFileNonDirectoryFile) != 0) {
        report_io_status(io_status, kStInvalidParameter, 0);
        return kStInvalidParameter;
    }

    std::string host_path;
    Ntstatus path_status = kStSuccess;
    if (!resolve_object_path(object_attributes, host_path, path_status)) {
        report_io_status(io_status, path_status, 0);
        return path_status;
    }

    struct ::stat st {};
    Ntstatus stat_status = kStSuccess;
    const bool existed = path_exists(host_path, st, stat_status);
    if (!existed && stat_status != kStSuccess) {
        report_io_status(io_status, stat_status, 0);
        return stat_status;
    }
    if (!existed) {
        const Ntstatus missing = missing_component_status(host_path);
        report_io_status(io_status, missing, 0);
        return missing;
    }

    const bool directory_requested = (open_options & kFileDirectoryFile) != 0;
    if (directory_requested && !S_ISDIR(st.st_mode)) {
        report_io_status(io_status, kStNotADirectory, 0);
        return kStNotADirectory;
    }
    if (!directory_requested && S_ISDIR(st.st_mode)) {
        report_io_status(io_status, kStFileIsADirectory, 0);
        return kStFileIsADirectory;
    }
    if ((open_options & kFileNonDirectoryFile) != 0 && S_ISDIR(st.st_mode)) {
        report_io_status(io_status, kStFileIsADirectory, 0);
        return kStFileIsADirectory;
    }

    const bool want_read =
        (desired_access & (kGenericRead | kFileReadData | kFileReadAttributes)) != 0;
    const bool want_write =
        (desired_access & (kGenericWrite | kFileWriteData | kFileAppendData)) != 0;
    const int fd = open_descriptor(host_path, want_read, want_write,
                                   directory_requested, 0);
    if (fd < 0) {
        const Ntstatus status =
            errno == ENOENT ? missing_component_status(host_path)
                            : errno_status(errno);
        report_io_status(io_status, status, 0);
        return status;
    }

    const std::uint64_t out_handle =
        kFileHandleBase + static_cast<std::uint64_t>(fd);
    add_file_handle(out_handle);
    *handle = out_handle;
    report_io_status(io_status, kStSuccess, kFileOpened);
    return kStSuccess;
}

// `NtReadFile`. An explicit byte offset is honored with `pread`, which reads
// without moving the file pointer -- the same observable behavior Windows'
// explicit-offset read has; a null offset or the FILE_USE_FILE_POINTER_POSITION
// marker reads at the current position. The Event and APC arguments describe
// asynchronous completion, which a synchronous runtime never produces, and
// are accepted and ignored. A read that reaches end-of-file with nothing to
// return is the status the call is defined to answer.
extern "C" __attribute__((ms_abi)) std::uint32_t ntf2_NtReadFile(
    std::uint64_t file_handle, std::uint64_t event, std::uint64_t apc_routine,
    std::uint64_t apc_context, std::uint8_t* io_status, void* buffer,
    std::uint32_t length, const std::uint64_t* byte_offset,
    std::uint64_t key) noexcept {
    (void)event;
    (void)apc_routine;
    (void)apc_context;
    (void)key;
    const int fd = file_descriptor_of(file_handle);
    if (fd < 0) {
        return kStInvalidHandle;
    }
    if (io_status == nullptr || (buffer == nullptr && length != 0)) {
        return kStInvalidParameter;
    }
    if (length == 0) {
        report_io_status(io_status, kStSuccess, 0);
        return kStSuccess;
    }

    std::uint64_t offset = kFileUseFilePointerPosition;
    if (byte_offset != nullptr) {
        offset = read_u64(byte_offset, 0);
    }

    std::size_t done = 0;
    while (done < length) {
        const std::size_t remaining =
            static_cast<std::size_t>(length) - done;
        std::uint8_t* at =
            static_cast<std::uint8_t*>(buffer) + done;
        ssize_t got = 0;
        if (offset == kFileUseFilePointerPosition) {
            got = ::read(fd, at, remaining);
        } else {
            got = ::pread(fd, at, remaining,
                          static_cast<off_t>(offset + static_cast<std::uint64_t>(done)));
        }
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            report_io_status(io_status, kStUnsuccessful,
                             static_cast<std::uint64_t>(done));
            return kStUnsuccessful;
        }
        if (got == 0) {
            break;  // end of file
        }
        done += static_cast<std::size_t>(got);
    }

    const Ntstatus status =
        done == 0 ? kStEndOfFile : kStSuccess;
    report_io_status(io_status, status, static_cast<std::uint64_t>(done));
    return status;
}

// `NtWriteFile`: the write half, with the same offset rules. There is no
// end-of-file status for a write -- extending a file is what a write does --
// so a completed write reports success with the byte count, and a zero-byte
// completion of a non-zero request is a host failure reported as such.
extern "C" __attribute__((ms_abi)) std::uint32_t ntf2_NtWriteFile(
    std::uint64_t file_handle, std::uint64_t event, std::uint64_t apc_routine,
    std::uint64_t apc_context, std::uint8_t* io_status, const void* buffer,
    std::uint32_t length, const std::uint64_t* byte_offset,
    std::uint64_t key) noexcept {
    (void)event;
    (void)apc_routine;
    (void)apc_context;
    (void)key;
    const int fd = file_descriptor_of(file_handle);
    if (fd < 0) {
        return kStInvalidHandle;
    }
    if (io_status == nullptr || (buffer == nullptr && length != 0)) {
        return kStInvalidParameter;
    }
    if (length == 0) {
        report_io_status(io_status, kStSuccess, 0);
        return kStSuccess;
    }

    std::uint64_t offset = kFileUseFilePointerPosition;
    if (byte_offset != nullptr) {
        offset = read_u64(byte_offset, 0);
    }

    std::size_t done = 0;
    while (done < length) {
        const std::size_t remaining =
            static_cast<std::size_t>(length) - done;
        const std::uint8_t* at =
            static_cast<const std::uint8_t*>(buffer) + done;
        ssize_t put = 0;
        if (offset == kFileUseFilePointerPosition) {
            put = ::write(fd, at, remaining);
        } else {
            put = ::pwrite(fd, at, remaining,
                           static_cast<off_t>(offset + static_cast<std::uint64_t>(done)));
        }
        if (put < 0) {
            if (errno == EINTR) {
                continue;
            }
            report_io_status(io_status, kStUnsuccessful,
                             static_cast<std::uint64_t>(done));
            return kStUnsuccessful;
        }
        if (put == 0) {
            report_io_status(io_status, kStUnsuccessful,
                             static_cast<std::uint64_t>(done));
            return kStUnsuccessful;
        }
        done += static_cast<std::size_t>(put);
    }

    report_io_status(io_status, kStSuccess, static_cast<std::uint64_t>(done));
    return kStSuccess;
}

// `NtQueryInformationFile`: the four information classes the file family's
// callers use, each filled from a live fstat of the open descriptor. A
// buffer too small for the class is told so with the mismatch status and
// nothing is written; a class outside the four is refused as invalid, which
// is the honest answer for a question this file has no answer to.
extern "C" __attribute__((ms_abi)) std::uint32_t ntf2_NtQueryInformationFile(
    std::uint64_t file_handle, std::uint8_t* io_status, void* info,
    std::uint32_t length, std::uint32_t file_information_class) noexcept {
    const int fd = file_descriptor_of(file_handle);
    if (fd < 0) {
        return kStInvalidHandle;
    }
    if (io_status == nullptr) {
        return kStInvalidParameter;
    }

    struct ::stat st {};
    if (::fstat(fd, &st) != 0) {
        const Ntstatus status = errno_status(errno);
        report_io_status(io_status, status, 0);
        return status;
    }

    std::size_t needed = 0;
    switch (file_information_class) {
    case kFileBasicInformation: {
        needed = kBasicBytes;
        if (info == nullptr || length < needed) {
            break;
        }
        fill_basic_information(info, st);
        break;
    }
    case kFileStandardInformation: {
        needed = kStandardBytes;
        if (info == nullptr || length < needed) {
            break;
        }
        std::memset(info, 0, kStandardBytes);
        const std::uint64_t allocated =
            static_cast<std::uint64_t>(st.st_blocks) * 512;
        write_u64(info, kStandardAllocationSize, allocated);
        write_u64(info, kStandardEndOfFile, static_cast<std::uint64_t>(st.st_size));
        write_u32(info, kStandardNumberOfLinks,
                  static_cast<std::uint32_t>(st.st_nlink));
        write_u8(info, kStandardDeletePending, 0);
        write_u8(info, kStandardDirectory, S_ISDIR(st.st_mode) ? 1 : 0);
        break;
    }
    case kFilePositionInformation: {
        needed = kPositionBytes;
        if (info == nullptr || length < needed) {
            break;
        }
        const off_t position = ::lseek(fd, 0, SEEK_CUR);
        if (position < 0) {
            const Ntstatus status = errno_status(errno);
            report_io_status(io_status, status, 0);
            return status;
        }
        write_u64(info, kPositionCurrentOffset,
                  static_cast<std::uint64_t>(position));
        break;
    }
    case kFileEndOfFileInformation: {
        needed = kEndOfFileBytes;
        if (info == nullptr || length < needed) {
            break;
        }
        write_u64(info, kEndOfFileValue, static_cast<std::uint64_t>(st.st_size));
        break;
    }
    default:
        report_io_status(io_status, kStInvalidInfoClass, 0);
        return kStInvalidInfoClass;
    }

    if (info == nullptr || length < needed) {
        report_io_status(io_status, kStInfoLengthMismatch, 0);
        return kStInfoLengthMismatch;
    }
    report_io_status(io_status, kStSuccess, static_cast<std::uint64_t>(needed));
    return kStSuccess;
}

// `NtSetInformationFile`. The basic-information class applies the two
// timestamps the host can set -- last access and last write -- through
// `futimens`, leaving a field alone when the caller marks it
// 0xFFFFFFFFFFFFFFFF and skipping the creation and change times, which the
// host has no setter for. Position and end-of-file are the lseek and
// ftruncate a caller would expect. The status block reports the length of
// the applied information on success.
extern "C" __attribute__((ms_abi)) std::uint32_t ntf2_NtSetInformationFile(
    std::uint64_t file_handle, std::uint8_t* io_status, const void* info,
    std::uint32_t length, std::uint32_t file_information_class) noexcept {
    const int fd = file_descriptor_of(file_handle);
    if (fd < 0) {
        return kStInvalidHandle;
    }
    if (io_status == nullptr) {
        return kStInvalidParameter;
    }

    switch (file_information_class) {
    case kFileBasicInformation: {
        if (info == nullptr || length < kBasicBytes) {
            report_io_status(io_status, kStInfoLengthMismatch, 0);
            return kStInfoLengthMismatch;
        }
        // FILE_BASIC_INFORMATION carries four FILETIMEs; the host can set
        // access and write times, and the change time updates itself on the
        // host the way it does on Windows when a file is written to.
        const std::uint64_t access_ticks = read_u64(info, kBasicLastAccessTime);
        const std::uint64_t write_ticks = read_u64(info, kBasicLastWriteTime);
        struct ::timespec times[2];
        times[0].tv_sec = 0;
        times[0].tv_nsec = UTIME_OMIT;
        times[1].tv_sec = 0;
        times[1].tv_nsec = UTIME_OMIT;
        if (access_ticks != kIgnoreTime) {
            times[0].tv_sec = static_cast<time_t>(
                static_cast<std::int64_t>(access_ticks / kTicksPerSecond) -
                kEpochDeltaSeconds);
            times[0].tv_nsec =
                static_cast<long>(access_ticks % kTicksPerSecond) * 100;
        }
        if (write_ticks != kIgnoreTime) {
            times[1].tv_sec = static_cast<time_t>(
                static_cast<std::int64_t>(write_ticks / kTicksPerSecond) -
                kEpochDeltaSeconds);
            times[1].tv_nsec =
                static_cast<long>(write_ticks % kTicksPerSecond) * 100;
        }
        if (::futimens(fd, times) != 0) {
            const Ntstatus status = errno_status(errno);
            report_io_status(io_status, status, 0);
            return status;
        }
        break;
    }
    case kFilePositionInformation: {
        if (info == nullptr || length < kPositionBytes) {
            report_io_status(io_status, kStInfoLengthMismatch, 0);
            return kStInfoLengthMismatch;
        }
        const std::uint64_t offset = read_u64(info, kPositionCurrentOffset);
        if (::lseek(fd, static_cast<off_t>(offset), SEEK_SET) < 0) {
            const Ntstatus status = errno_status(errno);
            report_io_status(io_status, status, 0);
            return status;
        }
        break;
    }
    case kFileEndOfFileInformation: {
        if (info == nullptr || length < kEndOfFileBytes) {
            report_io_status(io_status, kStInfoLengthMismatch, 0);
            return kStInfoLengthMismatch;
        }
        const std::uint64_t size = read_u64(info, kEndOfFileValue);
        if (::ftruncate(fd, static_cast<off_t>(size)) != 0) {
            const Ntstatus status = errno_status(errno);
            report_io_status(io_status, status, 0);
            return status;
        }
        break;
    }
    default:
        report_io_status(io_status, kStInvalidInfoClass, 0);
        return kStInvalidInfoClass;
    }

    report_io_status(io_status, kStSuccess, static_cast<std::uint64_t>(length));
    return kStSuccess;
}

// `NtQueryAttributesFile`: the attribute answer for a path that need not be
// opened. The stat follows the final component, which is Windows' behavior
// for a path that names a reparse point.
extern "C" __attribute__((ms_abi)) std::uint32_t ntf2_NtQueryAttributesFile(
    const std::uint8_t* object_attributes, void* file_basic_information) noexcept {
    std::string host_path;
    Ntstatus path_status = kStSuccess;
    if (!resolve_object_path(object_attributes, host_path, path_status)) {
        return path_status;
    }
    struct ::stat st {};
    if (contained_stat(host_path.c_str(), st, true) != 0) {
        return errno == ENOENT ? missing_component_status(host_path)
                               : errno_status(errno);
    }
    if (file_basic_information == nullptr) {
        return kStInvalidParameter;
    }
    fill_basic_information(file_basic_information, st);
    return kStSuccess;
}

// `NtQueryFullAttributesFile`: the network-open information answer, the
// 56-byte form the create path returns when a caller asks for everything at
// once. The layout is the wdm.h one confirmed against MSDN: four FILETIMEs,
// allocation and end-of-file sizes, and the attributes at 48.
extern "C" __attribute__((ms_abi)) std::uint32_t ntf2_NtQueryFullAttributesFile(
    const std::uint8_t* object_attributes, void* file_network_open_information) noexcept {
    std::string host_path;
    Ntstatus path_status = kStSuccess;
    if (!resolve_object_path(object_attributes, host_path, path_status)) {
        return path_status;
    }
    struct ::stat st {};
    if (contained_stat(host_path.c_str(), st, true) != 0) {
        return errno == ENOENT ? missing_component_status(host_path)
                               : errno_status(errno);
    }
    if (file_network_open_information == nullptr) {
        return kStInvalidParameter;
    }
    std::memset(file_network_open_information, 0, kNetworkBytes);
    write_u64(file_network_open_information, kNetworkCreationTime,
              timespec_to_filetime(st.st_ctim));
    write_u64(file_network_open_information, kNetworkLastAccessTime,
              timespec_to_filetime(st.st_atim));
    write_u64(file_network_open_information, kNetworkLastWriteTime,
              timespec_to_filetime(st.st_mtim));
    write_u64(file_network_open_information, kNetworkChangeTime,
              timespec_to_filetime(st.st_ctim));
    write_u64(file_network_open_information, kNetworkAllocationSize,
              static_cast<std::uint64_t>(st.st_blocks) * 512);
    write_u64(file_network_open_information, kNetworkEndOfFile,
              static_cast<std::uint64_t>(st.st_size));
    write_u32(file_network_open_information, kNetworkFileAttributes,
              attributes_from_stat(st));
    return kStSuccess;
}

// `NtQuerySystemEnvironmentValue`: there is no UEFI system-environment
// namespace on Linux, and the call is obsolete on Windows besides. The
// honest answer is STATUS_NOT_IMPLEMENTED -- a pretend firmware value would
// let a guest believe a variable existed when nothing did.
extern "C" __attribute__((ms_abi)) std::uint32_t
ntf2_NtQuerySystemEnvironmentValue(const std::uint8_t* name, void* value,
                                   std::uint32_t value_length,
                                   std::uint32_t* return_length) noexcept {
    (void)name;
    (void)value;
    (void)value_length;
    (void)return_length;
    return kStNotImplemented;
}

// `NtSetSystemEnvironmentValue`: the write half of the same refusal. There
// is no namespace to write into, so nothing is pretended.
extern "C" __attribute__((ms_abi)) std::uint32_t
ntf2_NtSetSystemEnvironmentValue(const std::uint8_t* name,
                                 const std::uint8_t* value,
                                 std::uint32_t value_length) noexcept {
    (void)name;
    (void)value;
    (void)value_length;
    return kStNotImplemented;
}

// `RtlGenRandom`: the kernel's getrandom(2), which never blocks for entropy
// the way an unseeded read of /dev/urandom historically could. A zero-length
// request is trivially satisfied.
extern "C" __attribute__((ms_abi)) std::int32_t ntf2_RtlGenRandom(
    void* buffer, std::uint32_t length) noexcept {
    if (buffer == nullptr && length != 0) {
        return 0;
    }
    if (length == 0) {
        return 1;
    }
    std::uint8_t* at = static_cast<std::uint8_t*>(buffer);
    std::uint32_t done = 0;
    while (done < length) {
        const ssize_t got =
            ::getrandom(at + done, static_cast<std::size_t>(length - done), 0);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == ENOSYS) {
                // A kernel without getrandom is served from /dev/urandom.
                const int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
                if (fd < 0) {
                    return 0;
                }
                bool ok = true;
                while (done < length) {
                    const ssize_t got2 =
                        ::read(fd, at + done, static_cast<std::size_t>(length - done));
                    if (got2 < 0) {
                        if (errno == EINTR) {
                            continue;
                        }
                        ok = false;
                        break;
                    }
                    if (got2 == 0) {
                        ok = false;
                        break;
                    }
                    done += static_cast<std::uint32_t>(got2);
                }
                ::close(fd);
                return ok ? 1 : 0;
            }
            return 0;
        }
        done += static_cast<std::uint32_t>(got);
    }
    return 1;
}

// `RtlGetCurrentTeb`: the guest's own TEB, which the state the process
// builder laid out names. There is no TEB before a guest is installed.
extern "C" __attribute__((ms_abi)) std::uint64_t ntf2_RtlGetCurrentTeb() noexcept {
    GuestState* g = guest_state();
    return g == nullptr ? 0 : g->teb;
}

// ------------------------------------------------------------- registration

void add_ntdll_file2(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    // The Nt/Zw pair: Windows exports both spellings of the kernel calls,
    // and a guest that resolves one must get the same function.
    const auto pair = [&e](const char* nt, const char* zw, void* fn) {
        e(nt, fn);
        e(zw, fn);
    };
    pair("NtCreateFile", "ZwCreateFile",
         reinterpret_cast<void*>(&ntf2_NtCreateFile));
    pair("NtOpenFile", "ZwOpenFile",
         reinterpret_cast<void*>(&ntf2_NtOpenFile));
    pair("NtReadFile", "ZwReadFile",
         reinterpret_cast<void*>(&ntf2_NtReadFile));
    pair("NtWriteFile", "ZwWriteFile",
         reinterpret_cast<void*>(&ntf2_NtWriteFile));
    pair("NtQueryInformationFile", "ZwQueryInformationFile",
         reinterpret_cast<void*>(&ntf2_NtQueryInformationFile));
    pair("NtSetInformationFile", "ZwSetInformationFile",
         reinterpret_cast<void*>(&ntf2_NtSetInformationFile));
    pair("NtQueryAttributesFile", "ZwQueryAttributesFile",
         reinterpret_cast<void*>(&ntf2_NtQueryAttributesFile));
    pair("NtQueryFullAttributesFile", "ZwQueryFullAttributesFile",
         reinterpret_cast<void*>(&ntf2_NtQueryFullAttributesFile));
    pair("NtQuerySystemEnvironmentValue", "ZwQuerySystemEnvironmentValue",
         reinterpret_cast<void*>(&ntf2_NtQuerySystemEnvironmentValue));
    pair("NtSetSystemEnvironmentValue", "ZwSetSystemEnvironmentValue",
         reinterpret_cast<void*>(&ntf2_NtSetSystemEnvironmentValue));
    e("RtlGenRandom", reinterpret_cast<void*>(&ntf2_RtlGenRandom));
    e("RtlGetCurrentTeb", reinterpret_cast<void*>(&ntf2_RtlGetCurrentTeb));
}

}  // namespace occ::runtime::winabi

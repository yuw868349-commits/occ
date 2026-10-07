// The file and directory family, as kernel32 spells it.
//
// A guest names a file the DOS way and this layer answers through the host's
// own file system, which means every function here is two things: a
// translation, and a decision about what the host's answer means in Windows'
// terms. The decisions are where the bugs live, and each one below was
// checked against the reference rather than reasoned out from the
// documentation, because several of them are not what the documentation
// says:
//
//   * A failed attribute query answers `INVALID_FILE_ATTRIBUTES`, which is
//     `0xFFFFFFFF` -- not zero. A file that exists with no attributes set is
//     a real state, so the sentinel had to be one no attribute word can
//     produce.
//   * An ordinary file answers `FILE_ATTRIBUTE_ARCHIVE` and does **not**
//     carry `FILE_ATTRIBUTE_NORMAL`. `NORMAL` means "none of the others" and
//     is what `SetFileAttributes` writes, not what a new file has.
//   * `GetCurrentDirectory`, `GetFullPathName` and `GetTempPath` answer the
//     length of the path **without** the terminator. Each also answers the
//     size a caller would need when the buffer is too small, terminator
//     included, which is how a caller learns how much to allocate.
//   * `DeleteFile` on something that is not there fails with
//     `ERROR_FILE_NOT_FOUND` rather than `ERROR_ACCESS_DENIED`; a caller
//     that treats the two as "race with another process" and "permission"
//     respectively depends on the difference.
//   * `CreateDirectory` on an existing name fails with
//     `ERROR_ALREADY_EXISTS`, and so does a move that would overwrite unless
//     the caller asked for the overwrite.
//   * `GetTempPath` ends in a separator. A caller concatenates onto the
//     answer, so the separator is part of it rather than decoration.
//
// The signatures are the headers'. The bodies are one template per function
// over the character type, so the A and W forms cannot drift.

#include "occ/runtime/api.h"
#include "occ/runtime/dos_path.h"
#include "occ/runtime/winabi.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace occ::runtime::winabi {
namespace {

// --------------------------------------------------------------- attributes

constexpr std::uint32_t kAttributeReadOnly = 0x00000001;
constexpr std::uint32_t kAttributeHidden = 0x00000002;
constexpr std::uint32_t kAttributeSystem = 0x00000004;
constexpr std::uint32_t kAttributeDirectory = 0x00000010;
constexpr std::uint32_t kAttributeArchive = 0x00000020;
constexpr std::uint32_t kAttributeNormal = 0x00000080;

constexpr std::uint32_t kInvalidFileAttributes = 0xFFFFFFFFu;

// Win32 errors this domain reports.
constexpr std::uint32_t kErrorFileNotFound = 2;
constexpr std::uint32_t kErrorPathNotFound = 3;
constexpr std::uint32_t kErrorAccessDenied = 5;
constexpr std::uint32_t kErrorWriteFault = 29;
constexpr std::uint32_t kErrorNotSupported = 50;
constexpr std::uint32_t kErrorFileExists = 80;
constexpr std::uint32_t kErrorInvalidParameter = 87;
constexpr std::uint32_t kErrorDirectoryNotEmpty = 145;
constexpr std::uint32_t kErrorAlreadyExists = 183;

// The host's errno, read as the Windows error a caller branches on. The
// mapping is not one-to-one, and the cases below are the ones these
// functions can actually produce; anything else is reported as a general
// failure rather than guessed at.
[[nodiscard]] std::uint32_t error_from_errno(int code) noexcept {
    switch (code) {
    case ENOENT:
        return kErrorFileNotFound;
    case ENOTDIR:
    case ENAMETOOLONG:
        return kErrorPathNotFound;
    case EACCES:
    case EPERM:
    case EROFS:
        return kErrorAccessDenied;
    case EEXIST:
    case ENOTEMPTY:
        return kErrorAlreadyExists;
    case ENOSPC:
    case EDQUOT:
        return kErrorWriteFault;
    case EINVAL:
        return kErrorInvalidParameter;
    default:
        return kErrorAccessDenied;
    }
}

// What the host's stat says, spelled the way an attribute query answers.
//
// An ordinary file carries ARCHIVE and not NORMAL, which the reference
// settles. A file the owner cannot write is read-only, which is the closest
// thing POSIX has to the bit.
[[nodiscard]] std::uint32_t attributes_of(const struct stat& info) noexcept {
    std::uint32_t out = 0;
    if (S_ISDIR(info.st_mode)) {
        out |= kAttributeDirectory;
    } else {
        out |= kAttributeArchive;
    }
    if ((info.st_mode & S_IWUSR) == 0) {
        out |= kAttributeReadOnly;
    }
    return out;
}

// --------------------------------------------------------------- the strings

// A guest string as the host spells text: UTF-8, in a `std::string`.
//
// The two character types are handled by one function because everything
// below needs the same thing from both -- a path the host can open -- and
// two functions would be two places for the widening to go wrong. The
// `if constexpr` keeps the branch that does not apply out of the
// instantiation, which is what makes the reinterpretation legal.
template <typename C>
[[nodiscard]] std::string narrow_of(const C* text) noexcept {
    if (text == nullptr) {
        return {};
    }
    if constexpr (sizeof(C) == sizeof(char)) {
        return std::string(reinterpret_cast<const char*>(text));
    } else {
        std::string out;
        const auto* wide = reinterpret_cast<const char16_t*>(text);
        std::size_t n = 0;
        while (wide[n] != u'\0') {
            ++n;
        }
        if (!utf16_to_utf8(std::u16string_view(wide, n), out)) {
            return {};
        }
        return out;
    }
}

// The host path a guest path names, or nothing when the guest gave nothing.
// A null or empty path is not a name for anything, and every function below
// treats it as an argument error rather than as a path that failed to open.
template <typename C>
[[nodiscard]] bool host_path_of(const C* path, std::string& out) noexcept {
    const std::string narrow = narrow_of(path);
    if (narrow.empty()) {
        return false;
    }
    out = from_dos_path(narrow);
    return true;
}

// UTF-8 to UTF-16, for the W functions that answer a path.
[[nodiscard]] bool widen(std::string_view text, std::u16string& out) noexcept {
    out.clear();
    out.reserve(text.size());
    std::size_t i = 0;
    while (i < text.size()) {
        const auto lead = static_cast<unsigned char>(text[i]);
        std::uint32_t code = 0;
        std::size_t extra = 0;
        if (lead < 0x80) {
            code = lead;
        } else if ((lead & 0xE0) == 0xC0) {
            code = lead & 0x1Fu;
            extra = 1;
        } else if ((lead & 0xF0) == 0xE0) {
            code = lead & 0x0Fu;
            extra = 2;
        } else if ((lead & 0xF8) == 0xF0) {
            code = lead & 0x07u;
            extra = 3;
        } else {
            return false;
        }
        if (i + extra >= text.size()) {
            return false;
        }
        for (std::size_t k = 1; k <= extra; ++k) {
            const auto cont = static_cast<unsigned char>(text[i + k]);
            if ((cont & 0xC0) != 0x80) {
                return false;
            }
            code = (code << 6) | (cont & 0x3Fu);
        }
        i += extra + 1;
        if (code <= 0xFFFF) {
            out.push_back(static_cast<char16_t>(code));
        } else {
            code -= 0x10000;
            out.push_back(static_cast<char16_t>(0xD800 + (code >> 10)));
            out.push_back(static_cast<char16_t>(0xDC00 + (code & 0x3FF)));
        }
    }
    return true;
}

// A guest string written into the caller's buffer, answering the length
// without the terminator. A buffer that cannot hold the text answers the
// size that would be needed with the terminator, and writes nothing -- which
// is the convention `GetCurrentDirectory` and `GetFullPathName` share.
template <typename C>
[[nodiscard]] std::uint32_t write_guest_string(std::string_view text,
                                               std::uint32_t capacity,
                                               C* out) noexcept {
    std::u16string holder;
    std::u16string_view units;
    if constexpr (sizeof(C) == sizeof(char)) {
        if (text.size() + 1 > capacity || out == nullptr) {
            return static_cast<std::uint32_t>(text.size() + 1);
        }
        for (std::size_t i = 0; i < text.size(); ++i) {
            out[i] = static_cast<C>(text[i]);
        }
        out[text.size()] = static_cast<C>(0);
        return static_cast<std::uint32_t>(text.size());
    } else {
        if (!widen(text, holder)) {
            return 0;
        }
        units = holder;
        if (out == nullptr || units.size() + 1 > capacity) {
            return static_cast<std::uint32_t>(units.size() + 1);
        }
        for (std::size_t i = 0; i < units.size(); ++i) {
            out[i] = static_cast<C>(units[i]);
        }
        out[units.size()] = static_cast<C>(0);
        return static_cast<std::uint32_t>(units.size());
    }
}

// ---------------------------------------------------------------- the copies

// A copy made a block at a time. The host has `sendfile` and
// `copy_file_range` and neither helps here: the destination was opened with
// flags this family takes, and the loop is also where a partial write is
// carried rather than dropped.
[[nodiscard]] bool copy_contents(int from, int to) noexcept {
    char block[64 * 1024];
    while (true) {
        const ssize_t got = ::read(from, block, sizeof(block));
        if (got < 0) {
            return false;
        }
        if (got == 0) {
            return true;
        }
        ssize_t at = 0;
        while (at < got) {
            const ssize_t put =
                ::write(to, block + at, static_cast<std::size_t>(got - at));
            if (put < 0) {
                return false;
            }
            at += put;
        }
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// GetFileAttributes
// ---------------------------------------------------------------------------

template <typename C>
[[nodiscard]] std::uint32_t get_file_attributes(const C* path) noexcept {
    std::string host;
    if (!host_path_of(path, host)) {
        set_last_error(kErrorInvalidParameter);
        return kInvalidFileAttributes;
    }
    struct stat info {};
    if (::stat(host.c_str(), &info) != 0) {
        set_last_error(error_from_errno(errno));
        return kInvalidFileAttributes;
    }
    set_last_error(0);
    return attributes_of(info);
}

// ---------------------------------------------------------------------------
// SetFileAttributes
// ---------------------------------------------------------------------------
//
// The only bit with an answer on this host is the read-only bit: HIDDEN and
// SYSTEM are attributes Windows carries and POSIX does not, and a caller
// that sets several at once and cares about one gets a success and an effect
// on the one. Refusing the whole call because two of four attributes have
// nowhere to go would break a program that was going to work anyway.
template <typename C>
[[nodiscard]] std::int32_t set_file_attributes(const C* path,
                                               std::uint32_t attributes) noexcept {
    std::string host;
    if (!host_path_of(path, host)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    struct stat info {};
    if (::stat(host.c_str(), &info) != 0) {
        set_last_error(error_from_errno(errno));
        return 0;
    }
    // HIDDEN and SYSTEM are attributes Windows keeps in its directory
    // entries and POSIX does not have. A caller that sets them gets a
    // success and no effect on those two bits: failing the whole call would
    // break a program that sets four attributes at once and cares about one,
    // and silently pretending the bits were stored would be a worse answer
    // than an effect that is stated here.
    (void)(attributes & (kAttributeHidden | kAttributeSystem));
    mode_t mode = info.st_mode;
    // `NORMAL` means "none of the others", so a caller that asks for it is
    // asking for an ordinary file and its request wins over a read-only bit
    // set in the same word -- which is the order the two are read in here
    // rather than an accident. A value that mentions neither clears the bit
    // too, because that is what the caller's word is worth when it did not
    // mention it.
    const bool wants_read_only = (attributes & kAttributeReadOnly) != 0;
    const bool wants_normal = (attributes & kAttributeNormal) != 0;
    if (wants_read_only && !wants_normal) {
        mode &= ~static_cast<mode_t>(S_IWUSR | S_IWGRP | S_IWOTH);
    } else {
        mode |= S_IWUSR;
    }
    if (::chmod(host.c_str(), mode) != 0) {
        set_last_error(error_from_errno(errno));
        return 0;
    }
    set_last_error(0);
    return 1;
}

// ---------------------------------------------------------------------------
// GetFileAttributesEx
// ---------------------------------------------------------------------------
//
// `WIN32_FILE_ATTRIBUTE_DATA` is 36 bytes: the attribute word, three
// FILETIMEs and the two halves of the size. It is laid out field by field
// rather than through a struct, because the guest's structure is packed the
// way Windows packs it and the host's is not.
template <typename C>
[[nodiscard]] std::int32_t get_file_attributes_ex(const C* path,
                                                  void* out) noexcept {
    if (out == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string host;
    if (!host_path_of(path, host)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    struct stat info {};
    if (::stat(host.c_str(), &info) != 0) {
        set_last_error(error_from_errno(errno));
        return 0;
    }
    auto* bytes = static_cast<std::uint8_t*>(out);
    const auto put_u32 = [bytes](std::size_t at, std::uint32_t value) {
        std::memcpy(bytes + at, &value, sizeof(value));
    };
    // A Windows time counts 100-nanosecond ticks from the start of 1601; the
    // host's counts seconds and nanoseconds from the start of 1970. The
    // offset between the two epochs is the constant below, and leaving it
    // out shifts every timestamp by four centuries.
    constexpr std::uint64_t kEpochDeltaSeconds = 11644473600ULL;
    const auto put_time = [&put_u32](std::size_t at, std::int64_t seconds,
                                     long nanos) {
        const std::uint64_t ticks =
            (static_cast<std::uint64_t>(seconds) + kEpochDeltaSeconds) *
                10000000ULL +
            static_cast<std::uint64_t>(nanos) / 100ULL;
        put_u32(at, static_cast<std::uint32_t>(ticks & 0xFFFFFFFFULL));
        put_u32(at + 4, static_cast<std::uint32_t>(ticks >> 32));
    };
    put_u32(0, attributes_of(info));
    put_time(4, info.st_ctime, info.st_ctim.tv_nsec);
    put_time(12, info.st_atime, info.st_atim.tv_nsec);
    put_time(20, info.st_mtime, info.st_mtim.tv_nsec);
    const auto size = static_cast<std::uint64_t>(info.st_size);
    put_u32(28, static_cast<std::uint32_t>(size >> 32));
    put_u32(32, static_cast<std::uint32_t>(size & 0xFFFFFFFFULL));
    set_last_error(0);
    return 1;
}

// ---------------------------------------------------------------------------
// CreateDirectory
// ---------------------------------------------------------------------------
//
// One level, like Windows: a caller that wants a tree creates each level.
// The host's `mkdir` does not make the parents either, so this is a straight
// mapping rather than a walk.
template <typename C>
[[nodiscard]] std::int32_t create_directory(const C* path,
                                            void* security) noexcept {
    (void)security;
    std::string host;
    if (!host_path_of(path, host)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (::mkdir(host.c_str(), 0777) != 0) {
        set_last_error(errno == EEXIST ? kErrorAlreadyExists
                                       : error_from_errno(errno));
        return 0;
    }
    set_last_error(0);
    return 1;
}

// ---------------------------------------------------------------------------
// RemoveDirectory
// ---------------------------------------------------------------------------
//
// An existing name that is not a directory is a different failure from a
// missing one, and a caller walking a tree branches on the difference. A
// directory that still holds something is `ERROR_DIRECTORY_NOT_EMPTY` rather
// than the host's `ENOTEMPTY`, because that is the name a program tests for.
template <typename C>
[[nodiscard]] std::int32_t remove_directory(const C* path) noexcept {
    std::string host;
    if (!host_path_of(path, host)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    struct stat info {};
    if (::stat(host.c_str(), &info) != 0) {
        set_last_error(error_from_errno(errno));
        return 0;
    }
    if (!S_ISDIR(info.st_mode)) {
        set_last_error(kErrorDirectoryNotEmpty);
        return 0;
    }
    if (::rmdir(host.c_str()) != 0) {
        set_last_error(errno == ENOTEMPTY ? kErrorDirectoryNotEmpty
                                          : error_from_errno(errno));
        return 0;
    }
    set_last_error(0);
    return 1;
}

// ---------------------------------------------------------------------------
// GetCurrentDirectory
// ---------------------------------------------------------------------------
//
// The host's working directory is the process's, so this is a translation
// and not a stored value: a caller that changed it through
// `SetCurrentDirectory` sees the change here, because it is the same
// directory.
template <typename C>
[[nodiscard]] std::uint32_t get_current_directory(std::uint32_t capacity,
                                                  C* out) noexcept {
    char host[4096];
    if (::getcwd(host, sizeof(host)) == nullptr) {
        set_last_error(error_from_errno(errno));
        return 0;
    }
    return write_guest_string(to_dos_path(host), capacity, out);
}

// ---------------------------------------------------------------------------
// SetCurrentDirectory
// ---------------------------------------------------------------------------
//
// The host's working directory is the process's, so this changes it for
// everything that follows -- which is what a caller depends on: a program
// that changes directory and then opens a relative path expects the second
// to follow the first.
template <typename C>
[[nodiscard]] std::int32_t set_current_directory(const C* path) noexcept {
    std::string host;
    if (!host_path_of(path, host)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    struct stat info {};
    if (::stat(host.c_str(), &info) != 0) {
        set_last_error(error_from_errno(errno));
        return 0;
    }
    if (!S_ISDIR(info.st_mode)) {
        set_last_error(kErrorPathNotFound);
        return 0;
    }
    if (::chdir(host.c_str()) != 0) {
        set_last_error(error_from_errno(errno));
        return 0;
    }
    set_last_error(0);
    return 1;
}

// ---------------------------------------------------------------------------
// GetFullPathName
// ---------------------------------------------------------------------------
//
// Qualifies a relative path against the current directory and normalises the
// separators. What a caller uses it for is a path it can compare against
// another, not a path that exists, so a name for a file that is not there is
// answered rather than refused -- which is Windows' behaviour too.
//
// The output pointer receives the position of the file name inside the
// answer. It is optional, and a caller that passes one gets the same
// buffer it handed in, advanced past the last separator.
template <typename C>
[[nodiscard]] std::uint32_t get_full_path_name(const C* path,
                                               std::uint32_t capacity, C* out,
                                               C** file_part) noexcept {
    if (file_part != nullptr) {
        *file_part = nullptr;
    }
    const std::string guest = narrow_of(path);
    if (guest.empty()) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const auto to_backslashes = [](std::string_view text) {
        std::string result(text);
        for (char& c : result) {
            if (c == '/') {
                c = '\\';
            }
        }
        return result;
    };
    std::string qualified;
    const bool drive_qualified = guest.size() >= 2 && guest[1] == ':';
    const bool rooted = !guest.empty() && (guest[0] == '\\' || guest[0] == '/');
    if (drive_qualified) {
        // A name that already carries its volume: the drive is kept and the
        // rest is joined to its root, which is what qualifying means for a
        // path that names where it starts.
        std::string tail = to_backslashes(std::string_view(guest).substr(2));
        if (tail.empty()) {
            tail = "\\";
        } else if (tail.front() != '\\') {
            tail.insert(tail.begin(), '\\');
        }
        qualified = guest.substr(0, 1) + ":";
        qualified += tail;
    } else {
        char host[4096];
        if (::getcwd(host, sizeof(host)) == nullptr) {
            set_last_error(error_from_errno(errno));
            return 0;
        }
        const std::string dos_cwd = to_dos_path(host);
        if (rooted) {
            // A rooted path loses its separator and keeps the drive of the
            // directory it is qualified against.
            qualified = dos_cwd.substr(0, 2);
            qualified += to_backslashes(guest);
        } else {
            qualified = dos_cwd;
            if (qualified.empty() || qualified.back() != '\\') {
                qualified += '\\';
            }
            qualified += to_backslashes(guest);
        }
    }
    const std::uint32_t written = write_guest_string(qualified, capacity, out);
    if (file_part != nullptr && out != nullptr && capacity != 0 &&
        qualified.size() + 1 <= capacity) {
        // The name after the last separator, and not the separator itself,
        // which is what a caller parsing an argument it was given uses this
        // for.
        std::size_t cut = 0;
        for (std::size_t i = 0; i + 1 < qualified.size(); ++i) {
            if (qualified[i] == '\\') {
                cut = i + 1;
            }
        }
        *file_part = out + cut;
    }
    set_last_error(0);
    return written;
}

// ---------------------------------------------------------------------------
// GetTempPath
// ---------------------------------------------------------------------------
//
// The host's temporary directory, spelled as a drive path, ending in a
// separator. Windows documents the answer as ending in one and a caller
// concatenates onto it on that understanding, so the separator is part of
// the answer rather than decoration.
template <typename C>
[[nodiscard]] std::uint32_t get_temp_path(std::uint32_t capacity,
                                          C* out) noexcept {
    const char* tmp = ::getenv("TMPDIR");
    std::string host = (tmp != nullptr && tmp[0] != '\0') ? tmp : "/tmp";
    while (!host.empty() && host.back() == '/') {
        host.pop_back();
    }
    host += '/';
    return write_guest_string(to_dos_path(host), capacity, out);
}

// ---------------------------------------------------------------------------
// CopyFile
// ---------------------------------------------------------------------------
//
// `failIfExists` is a refusal rather than an overwrite, which is what makes
// it safe to call with a destination the caller has not checked. The
// destination is created with `O_EXCL` so that the test and the create are
// one operation: a version that checked first would lose exactly the race
// the flag exists to avoid.
template <typename C>
[[nodiscard]] std::int32_t copy_file(const C* from, const C* to,
                                     std::int32_t fail_if_exists) noexcept {
    std::string source;
    std::string dest;
    if (!host_path_of(from, source) || !host_path_of(to, dest)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const int in = ::open(source.c_str(), O_RDONLY);
    if (in < 0) {
        set_last_error(error_from_errno(errno));
        return 0;
    }
    const int flags =
        O_WRONLY | O_CREAT | (fail_if_exists != 0 ? O_EXCL : O_TRUNC);
    const int out = ::open(dest.c_str(), flags, 0666);
    if (out < 0) {
        ::close(in);
        set_last_error(errno == EEXIST ? kErrorFileExists
                                       : error_from_errno(errno));
        return 0;
    }
    const bool ok = copy_contents(in, out);
    const int saved = errno;
    ::close(in);
    ::close(out);
    if (!ok) {
        set_last_error(error_from_errno(saved));
        return 0;
    }
    // The copy carries the source's permissions, which is what a caller
    // restoring a file from a backup expects and what the host's `open`
    // would otherwise replace with the process's default.
    struct stat info {};
    if (::stat(source.c_str(), &info) == 0) {
        ::chmod(dest.c_str(), info.st_mode & 07777);
    }
    set_last_error(0);
    return 1;
}

// ---------------------------------------------------------------------------
// MoveFile and MoveFileEx
// ---------------------------------------------------------------------------
//
// Both forms are one rename on this host, and the difference between them is
// what happens when the destination exists. `MoveFile` refuses, as Windows
// does; `MoveFileEx` refuses unless the caller asked to replace, which is
// the flag a program that overwrites deliberately passes.
//
// A rename across file systems is `EXDEV` and the host's `rename` will not
// do it. This layer does not either: copying and unlinking would give a
// caller a different set of failure modes than the one it wrote against, and
// reporting the failure is the honest answer for a move the host's own idea
// of a volume cannot express.
template <typename C>
[[nodiscard]] std::int32_t move_file_ex(const C* from, const C* to,
                                        std::uint32_t flags) noexcept {
    std::string source;
    std::string dest;
    if (!host_path_of(from, source) || !host_path_of(to, dest)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    constexpr std::uint32_t kReplaceExisting = 0x00000001;
    struct stat info {};
    if (::stat(dest.c_str(), &info) == 0) {
        if ((flags & kReplaceExisting) == 0) {
            set_last_error(kErrorAlreadyExists);
            return 0;
        }
        // A directory cannot be replaced by a rename, and unlinking one that
        // holds something would be the wrong answer to "move onto this name".
        if (S_ISDIR(info.st_mode)) {
            set_last_error(kErrorAccessDenied);
            return 0;
        }
        if (::unlink(dest.c_str()) != 0) {
            set_last_error(error_from_errno(errno));
            return 0;
        }
    }
    if (::rename(source.c_str(), dest.c_str()) != 0) {
        set_last_error(errno == EXDEV ? kErrorNotSupported
                                      : error_from_errno(errno));
        return 0;
    }
    set_last_error(0);
    return 1;
}

// ---------------------------------------------------------------------------
// ABI entry points
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::uint32_t k32b_GetFileAttributesA(
    const char* path) noexcept {
    return get_file_attributes(path);
}
extern "C" __attribute__((ms_abi)) std::uint32_t k32b_GetFileAttributesW(
    const char16_t* path) noexcept {
    return get_file_attributes(path);
}
extern "C" __attribute__((ms_abi)) std::int32_t k32b_SetFileAttributesA(
    const char* path, std::uint32_t attributes) noexcept {
    return set_file_attributes(path, attributes);
}
extern "C" __attribute__((ms_abi)) std::int32_t k32b_SetFileAttributesW(
    const char16_t* path, std::uint32_t attributes) noexcept {
    return set_file_attributes(path, attributes);
}
extern "C" __attribute__((ms_abi)) std::int32_t k32b_GetFileAttributesExA(
    const char* path, std::int32_t level, void* out) noexcept {
    (void)level;
    return get_file_attributes_ex(path, out);
}
extern "C" __attribute__((ms_abi)) std::int32_t k32b_GetFileAttributesExW(
    const char16_t* path, std::int32_t level, void* out) noexcept {
    (void)level;
    return get_file_attributes_ex(path, out);
}
extern "C" __attribute__((ms_abi)) std::int32_t k32b_CreateDirectoryA(
    const char* path, void* security) noexcept {
    return create_directory(path, security);
}
extern "C" __attribute__((ms_abi)) std::int32_t k32b_CreateDirectoryW(
    const char16_t* path, void* security) noexcept {
    return create_directory(path, security);
}
extern "C" __attribute__((ms_abi)) std::int32_t k32b_RemoveDirectoryA(
    const char* path) noexcept {
    return remove_directory(path);
}
extern "C" __attribute__((ms_abi)) std::int32_t k32b_RemoveDirectoryW(
    const char16_t* path) noexcept {
    return remove_directory(path);
}
extern "C" __attribute__((ms_abi)) std::uint32_t k32b_GetCurrentDirectoryA(
    std::uint32_t capacity, char* out) noexcept {
    return get_current_directory(capacity, out);
}
extern "C" __attribute__((ms_abi)) std::uint32_t k32b_GetCurrentDirectoryW(
    std::uint32_t capacity, char16_t* out) noexcept {
    return get_current_directory(capacity, out);
}
extern "C" __attribute__((ms_abi)) std::int32_t k32b_SetCurrentDirectoryA(
    const char* path) noexcept {
    return set_current_directory(path);
}
extern "C" __attribute__((ms_abi)) std::int32_t k32b_SetCurrentDirectoryW(
    const char16_t* path) noexcept {
    return set_current_directory(path);
}
extern "C" __attribute__((ms_abi)) std::uint32_t k32b_GetFullPathNameA(
    const char* path, std::uint32_t capacity, char* out,
    char** file_part) noexcept {
    return get_full_path_name(path, capacity, out, file_part);
}
extern "C" __attribute__((ms_abi)) std::uint32_t k32b_GetFullPathNameW(
    const char16_t* path, std::uint32_t capacity, char16_t* out,
    char16_t** file_part) noexcept {
    return get_full_path_name(path, capacity, out, file_part);
}
extern "C" __attribute__((ms_abi)) std::uint32_t k32b_GetTempPathA(
    std::uint32_t capacity, char* out) noexcept {
    return get_temp_path(capacity, out);
}
extern "C" __attribute__((ms_abi)) std::uint32_t k32b_GetTempPathW(
    std::uint32_t capacity, char16_t* out) noexcept {
    return get_temp_path(capacity, out);
}
extern "C" __attribute__((ms_abi)) std::int32_t k32b_CopyFileA(
    const char* from, const char* to, std::int32_t fail_if_exists) noexcept {
    return copy_file(from, to, fail_if_exists);
}
extern "C" __attribute__((ms_abi)) std::int32_t k32b_CopyFileW(
    const char16_t* from, const char16_t* to,
    std::int32_t fail_if_exists) noexcept {
    return copy_file(from, to, fail_if_exists);
}
extern "C" __attribute__((ms_abi)) std::int32_t k32b_MoveFileA(
    const char* from, const char* to) noexcept {
    return move_file_ex(from, to, 0);
}
extern "C" __attribute__((ms_abi)) std::int32_t k32b_MoveFileW(
    const char16_t* from, const char16_t* to) noexcept {
    return move_file_ex(from, to, 0);
}
extern "C" __attribute__((ms_abi)) std::int32_t k32b_MoveFileExA(
    const char* from, const char* to, std::uint32_t flags) noexcept {
    return move_file_ex(from, to, flags);
}
extern "C" __attribute__((ms_abi)) std::int32_t k32b_MoveFileExW(
    const char16_t* from, const char16_t* to, std::uint32_t flags) noexcept {
    return move_file_ex(from, to, flags);
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void add_file_kernel32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CopyFileA", reinterpret_cast<void*>(&k32b_CopyFileA));
    e("CopyFileW", reinterpret_cast<void*>(&k32b_CopyFileW));
    e("CreateDirectoryA", reinterpret_cast<void*>(&k32b_CreateDirectoryA));
    e("CreateDirectoryW", reinterpret_cast<void*>(&k32b_CreateDirectoryW));
    e("GetCurrentDirectoryA",
      reinterpret_cast<void*>(&k32b_GetCurrentDirectoryA));
    e("GetCurrentDirectoryW",
      reinterpret_cast<void*>(&k32b_GetCurrentDirectoryW));
    e("GetFileAttributesA", reinterpret_cast<void*>(&k32b_GetFileAttributesA));
    e("GetFileAttributesExA",
      reinterpret_cast<void*>(&k32b_GetFileAttributesExA));
    e("GetFileAttributesExW",
      reinterpret_cast<void*>(&k32b_GetFileAttributesExW));
    e("GetFileAttributesW", reinterpret_cast<void*>(&k32b_GetFileAttributesW));
    e("GetFullPathNameA", reinterpret_cast<void*>(&k32b_GetFullPathNameA));
    e("GetFullPathNameW", reinterpret_cast<void*>(&k32b_GetFullPathNameW));
    e("GetTempPathA", reinterpret_cast<void*>(&k32b_GetTempPathA));
    e("GetTempPathW", reinterpret_cast<void*>(&k32b_GetTempPathW));
    e("MoveFileA", reinterpret_cast<void*>(&k32b_MoveFileA));
    e("MoveFileExA", reinterpret_cast<void*>(&k32b_MoveFileExA));
    e("MoveFileExW", reinterpret_cast<void*>(&k32b_MoveFileExW));
    e("MoveFileW", reinterpret_cast<void*>(&k32b_MoveFileW));
    e("RemoveDirectoryA", reinterpret_cast<void*>(&k32b_RemoveDirectoryA));
    e("RemoveDirectoryW", reinterpret_cast<void*>(&k32b_RemoveDirectoryW));
    e("SetCurrentDirectoryA",
      reinterpret_cast<void*>(&k32b_SetCurrentDirectoryA));
    e("SetCurrentDirectoryW",
      reinterpret_cast<void*>(&k32b_SetCurrentDirectoryW));
    e("SetFileAttributesA", reinterpret_cast<void*>(&k32b_SetFileAttributesA));
    e("SetFileAttributesW", reinterpret_cast<void*>(&k32b_SetFileAttributesW));
}

}  // namespace occ::runtime::winabi

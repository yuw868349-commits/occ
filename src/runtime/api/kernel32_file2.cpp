// The kernel32 file, module and thread-state families.
//
// This file carries the calls a program makes to reach the file system by
// name, to find out what modules are loaded, and to set up the per-thread
// state a C runtime expects before `main` runs. They share a shape that
// decides how each is written: the kernel32 spelling is a thin shell over a
// facility this runtime already has, and the shell's whole job is the part
// the Rtl spelling does not do -- the narrow/wide conversion, the Win32
// error code, and the return value the caller tests.
//
// Where a facility already exists in this runtime the shell forwards to it
// rather than reimplementing it. Two implementations of the same lock would
// be two locks, and a guest that initialised a critical section through one
// and entered it through the other would be entering a structure nobody
// else can see. The forwards are written out one by one rather than through
// a table so that each one's conversion is visible where the signature is.
//
// The exception is `FindFirstFileExW` and its siblings, which have no Rtl
// counterpart here: the directory walk is written in this file, against the
// host's own directory entries, and the structure it fills is the guest's.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/dos_path.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

namespace occ::runtime::winabi {

// The two narrow file calls this file forwards to. They are defined with the
// rest of the kernel32 wrappers and are named here so the wide spellings can
// share one open path instead of growing a second one.
extern "C" __attribute__((ms_abi)) void* k32_CreateFileA(
    const char* name, std::uint32_t access, std::uint32_t share,
    void* security, std::uint32_t disposition, std::uint32_t flags,
    void* template_file) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t k32_DeleteFileA(
    const char* name) noexcept;

namespace {

// ---------------------------------------------------------------- layouts

// WIN32_FIND_DATAW: the attributes, three FILETIMEs, the two size halves,
// the two reserved words, then the long and short names. The long name is
// 260 wide characters and the short one 14, which puts the structure at 592
// bytes. The offsets are stated because the structure is the guest's and a
// compiler's padding is not.
constexpr std::size_t kFindAttributes = 0;
constexpr std::size_t kFindCreation = 4;
constexpr std::size_t kFindLastAccess = 12;
constexpr std::size_t kFindLastWrite = 20;
constexpr std::size_t kFindSizeHigh = 28;
constexpr std::size_t kFindSizeLow = 32;
constexpr std::size_t kFindReserved0 = 36;
constexpr std::size_t kFindReserved1 = 40;
constexpr std::size_t kFindName = 44;
constexpr std::size_t kFindNameChars = 260;
constexpr std::size_t kFindShortName = 564;
constexpr std::size_t kFindShortNameChars = 14;
constexpr std::size_t kFindBytes = 592;

// BY_HANDLE_FILE_INFORMATION, which is what `GetFileInformationByHandle`
// fills: the same attributes and times, then the volume serial, the size in
// two halves, the link count and two file indices.
constexpr std::size_t kByHandleBytes = 52;

// FILE_BASIC_INFO and FILE_STANDARD_INFO are what the Ex accessor answers.
// The basic one is the four times and the attributes, 40 bytes in all.
constexpr std::size_t kBasicInfoBytes = 40;
constexpr std::size_t kStandardInfoBytes = 24;

// The attributes a directory entry can carry. Windows spells them as bits
// and a guest tests them the same way, so the numbers matter: they are what
// a caller compares against `FILE_ATTRIBUTE_DIRECTORY`.
constexpr std::uint32_t kAttrReadOnly = 0x00000001;
constexpr std::uint32_t kAttrDirectory = 0x00000010;
constexpr std::uint32_t kAttrNormal = 0x00000080;

// The file handle base this runtime mints handles from. The value is the
// one the Win32 file wrappers in `winabi.cpp` already use, and reusing it is
// what lets a handle from `CreateFileW` be read by `ReadFile`, which was
// written against `CreateFileA`'s handles.
constexpr std::uint64_t kFileHandleBase = 0x2000;
constexpr std::uint64_t kFileHandleSpan = 0x100000;

// INVALID_HANDLE_VALUE, which is what a failed file open answers with. It is
// not null: a caller tests for this value and a runtime that answered null
// would leave the test passing on a failure.
constexpr std::uint64_t kInvalidHandleValue64 = 0xFFFFFFFFFFFFFFFFull;

// An open directory walk. `FindFirstFileExW` answers a handle to one of
// these and the following calls advance it, which is why the cursor is part
// of the state rather than recomputed: a caller that adds a file between two
// `FindNextFileW` calls must not see the walk skip an entry.
struct FindState {
    DIR* dir = nullptr;
    // The host directory this walk is reading, kept so that each entry can
    // be stat'ed by its full path. A `readdir` result is a name and nothing
    // else, and a walk that rebuilt the path from the current directory
    // would stat the wrong file for every search outside ".".
    std::string host_dir;
    std::string pattern;
    bool matched = false;
};

// The directory walks this runtime has handed out, keyed by handle. One
// guest thread runs, so there is no lock, and a destroyed handle is erased
// rather than marked so a reused handle cannot resurrect an old walk.
std::vector<std::pair<std::uint64_t, FindState>>& find_table() noexcept {
    static std::vector<std::pair<std::uint64_t, FindState>> table;
    return table;
}

std::uint64_t g_next_find_handle = 0x4000;

// The prefix a search pattern carries before its wildcard, which is the part
// a host `readdir` cannot filter for. Everything after it is matched here.
[[nodiscard]] bool wildcard_match(std::string_view pattern,
                                  std::string_view name) noexcept {
    // The match is the ordinary backtracking one, written iteratively so a
    // pattern with many `*` cannot recurse its way through the stack. `?`
    // matches one character and `*` matches any run, which is what the
    // Win32 pattern language allows; character classes are not part of it.
    std::size_t p = 0;
    std::size_t n = 0;
    std::size_t star = std::string_view::npos;
    std::size_t resume = 0;
    while (n < name.size()) {
        if (p < pattern.size() &&
            (pattern[p] == '?' || pattern[p] == name[n])) {
            ++p;
            ++n;
            continue;
        }
        if (p < pattern.size() && pattern[p] == '*') {
            star = p;
            resume = n;
            ++p;
            continue;
        }
        if (star != std::string_view::npos) {
            // The last `*` takes one more character and the match is retried
            // from just after it.
            p = star + 1;
            ++resume;
            n = resume;
            continue;
        }
        return false;
    }
    while (p < pattern.size() && pattern[p] == '*') {
        ++p;
    }
    return p == pattern.size();
}

// The attributes a host `stat` result maps to. The read-only bit is the
// absence of write permission for the owner, which is the closest thing the
// host has to the flag, and it only sets the guest's bit when the file is
// otherwise not writable.
[[nodiscard]] std::uint32_t attributes_of(const struct ::stat& st) noexcept {
    std::uint32_t attributes = 0;
    if (S_ISDIR(st.st_mode)) {
        attributes |= kAttrDirectory;
    }
    if ((st.st_mode & S_IWUSR) == 0) {
        attributes |= kAttrReadOnly;
    }
    if (attributes == 0) {
        attributes |= kAttrNormal;
    }
    return attributes;
}

// A FILETIME from a host timestamp: the 100-nanosecond count since 1601,
// which is the epoch Windows counts from. The offset between the two epochs
// is 11,644,473,600 seconds.
void write_file_time(void* base, std::size_t offset,
                     const struct ::timespec& ts) noexcept {
    constexpr std::int64_t kEpochOffsetSeconds = 11644473600;
    constexpr std::int64_t kTicksPerSecond = 10000000;
    const std::int64_t ticks =
        (static_cast<std::int64_t>(ts.tv_sec) - kEpochOffsetSeconds) *
            kTicksPerSecond +
        static_cast<std::int64_t>(ts.tv_nsec) / 100;
    write_u64(base, offset, static_cast<std::uint64_t>(ticks));
}

// The wide name of a host directory entry, upper- and lower-case as the host
// spells it. A name that is not valid UTF-8 is written as the empty string
// rather than as replacement characters: an empty name is a shape the caller
// can skip, and a name full of replacement characters is one it would treat
// as a real file.
void write_wide_name(void* entry, std::size_t offset, std::size_t chars,
                     const char* name) noexcept {
    auto* out = static_cast<char16_t*>(static_cast<void*>(
        static_cast<std::uint8_t*>(entry) + offset));
    std::u16string wide;
    if (!narrow_in(std::string_view(name), wide).converted) {
        wide.clear();
    }
    const std::size_t copy = wide.size() < chars - 1 ? wide.size() : chars - 1;
    for (std::size_t i = 0; i < copy; ++i) {
        out[i] = wide[i];
    }
    out[copy] = u'\0';
}

// Fills one guest entry from a host path. The path is a host path, so the
// stat is direct; the name is the entry's own name in the guest's spelling.
[[nodiscard]] bool fill_find_entry(void* entry, const std::string& host_path,
                                   const char* name) noexcept {
    struct ::stat st {};
    if (::stat(host_path.c_str(), &st) != 0) {
        return false;
    }
    std::memset(entry, 0, kFindBytes);
    write_u32(entry, kFindAttributes, attributes_of(st));
    write_file_time(entry, kFindCreation, st.st_ctim);
    write_file_time(entry, kFindLastAccess, st.st_atim);
    write_file_time(entry, kFindLastWrite, st.st_mtim);
    const auto size = static_cast<std::uint64_t>(st.st_size);
    write_u32(entry, kFindSizeHigh, static_cast<std::uint32_t>(size >> 32));
    write_u32(entry, kFindSizeLow, static_cast<std::uint32_t>(size & 0xFFFFFFFFu));
    write_wide_name(entry, kFindName, kFindNameChars, name);
    // The short name field is left empty rather than synthesised: this
    // runtime's directories have no 8.3 names, and inventing one would give
    // a caller a name that opens nothing.
    write_wide_name(entry, kFindShortName, kFindShortNameChars, "");
    return true;
}

// Finds the walk a handle names, or null when the handle is not one.
[[nodiscard]] FindState* find_state_of(std::uint64_t handle) noexcept {
    for (auto& [key, state] : find_table()) {
        if (key == handle) {
            return &state;
        }
    }
    return nullptr;
}

}  // namespace

// ------------------------------------------------------------ the files

extern "C" __attribute__((ms_abi)) void* k32f2_CreateFileW(
    const char16_t* name, std::uint32_t access, std::uint32_t share,
    void* security, std::uint32_t disposition, std::uint32_t flags,
    void* template_file) noexcept {
    if (name == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return reinterpret_cast<void*>(kInvalidHandleValue64);
    }
    // The wide name is converted to the narrow spelling the file wrappers
    // use and the call is the same one `CreateFileA` makes. Doing the
    // conversion here rather than beside the open is what keeps one open
    // path: a second copy of the disposition and access-flag translation
    // would be a second place for the two to disagree about `OPEN_ALWAYS`.
    std::string narrow;
    if (!narrow_out(std::u16string_view(name), narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return reinterpret_cast<void*>(kInvalidHandleValue64);
    }
    return k32_CreateFileA(narrow.c_str(), access, share, security,
                           disposition, flags, template_file);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32f2_DeleteFileW(
    const char16_t* name) noexcept {
    if (name == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(name), narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return k32_DeleteFileA(narrow.c_str());
}

extern "C" __attribute__((ms_abi)) std::int32_t k32f2_SetFilePointerEx(
    void* file, std::int64_t distance, std::int64_t* new_position,
    std::uint32_t method) noexcept {
    const std::uint64_t handle = reinterpret_cast<std::uint64_t>(file);
    if (handle < kFileHandleBase || handle >= kFileHandleBase + kFileHandleSpan) {
        // A handle this runtime did not mint for a file. A console or an
        // event handle cannot seek, and saying so is the honest answer: the
        // alternative is to seek the wrong descriptor.
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    const int fd = static_cast<int>(handle - kFileHandleBase);
    int whence = 0;
    switch (method) {
        case 0: whence = SEEK_SET; break;  // FILE_BEGIN
        case 1: whence = SEEK_CUR; break;  // FILE_CURRENT
        case 2: whence = SEEK_END; break;  // FILE_END
        default:
            set_last_error(kErrorInvalidParameter);
            return 0;
    }
    const off_t moved = ::lseek(fd, static_cast<off_t>(distance), whence);
    if (moved == static_cast<off_t>(-1)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (new_position != nullptr) {
        *new_position = static_cast<std::int64_t>(moved);
    }
    set_last_error(kErrorSuccess);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32f2_FlushFileBuffers(
    void* file) noexcept {
    const std::uint64_t handle = reinterpret_cast<std::uint64_t>(file);
    if (handle < kFileHandleBase || handle >= kFileHandleBase + kFileHandleSpan) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    const int fd = static_cast<int>(handle - kFileHandleBase);
    // `fsync` on a descriptor the host opened read-only fails with EBADF,
    // and the Win32 call succeeds there: flushing a file opened for reading
    // is a no-op, not an error, and a caller that flushes every handle it
    // holds would otherwise see a spurious failure on the read ones.
    const int access_mode = ::fcntl(fd, F_GETFL);
    if (access_mode != -1 && (access_mode & O_ACCMODE) == O_RDONLY) {
        set_last_error(kErrorSuccess);
        return 1;
    }
    if (::fsync(fd) != 0) {
        set_last_error(kErrorWriteFault);
        return 0;
    }
    set_last_error(kErrorSuccess);
    return 1;
}

// ------------------------------------------------------ the directory walks

extern "C" __attribute__((ms_abi)) void* k32f2_FindFirstFileExW(
    const char16_t* pattern, std::uint32_t level, void* data,
    std::uint32_t flags, void* filter, void* filter_data) noexcept {
    static_cast<void>(level);
    static_cast<void>(flags);
    static_cast<void>(filter);
    static_cast<void>(filter_data);
    if (pattern == nullptr || data == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return reinterpret_cast<void*>(kInvalidHandleValue64);
    }
    std::string narrow;
    if (!narrow_out(std::u16string_view(pattern), narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return reinterpret_cast<void*>(kInvalidHandleValue64);
    }
    // The pattern is split at its last separator: everything before it names
    // the directory to read and everything after it is the name pattern. A
    // pattern with no separator looks in the current directory.
    const std::size_t slash = narrow.find_last_of("/\\");
    std::string directory = slash == std::string::npos ? "." : narrow.substr(0, slash);
    std::string name_pattern =
        slash == std::string::npos ? narrow : narrow.substr(slash + 1);
    if (directory.empty()) {
        directory = "/";
    }

    std::string host_dir;
    if (directory == ".") {
        host_dir = ".";
    } else {
        host_dir = from_dos_path(directory);
        if (host_dir.empty()) {
            set_last_error(kErrorPathNotFound);
            return reinterpret_cast<void*>(kInvalidHandleValue64);
        }
    }
    DIR* dir = ::opendir(host_dir.c_str());
    if (dir == nullptr) {
        set_last_error(kErrorPathNotFound);
        return reinterpret_cast<void*>(kInvalidHandleValue64);
    }

    const std::uint64_t handle = g_next_find_handle++;
    find_table().push_back(
        {handle, FindState{dir, host_dir, name_pattern, false}});

    // The first matching entry is produced now, which is what makes the two
    // calls a pair: a caller that gets a handle has an entry in its buffer
    // without a second call, and a walk whose directory holds nothing
    // matching fails here with `ERROR_FILE_NOT_FOUND`.
    struct ::dirent* entry = nullptr;
    while ((entry = ::readdir(dir)) != nullptr) {
        if (std::strcmp(entry->d_name, ".") == 0 ||
            std::strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (!wildcard_match(name_pattern, entry->d_name)) {
            continue;
        }
        const std::string path =
            host_dir == "/" ? "/" + std::string(entry->d_name)
                            : host_dir + "/" + entry->d_name;
        if (!fill_find_entry(data, path, entry->d_name)) {
            continue;
        }
        find_state_of(handle)->matched = true;
        set_last_error(kErrorSuccess);
        return reinterpret_cast<void*>(handle);
    }

    // Nothing matched. The walk is closed and forgotten rather than handed
    // over, because a handle to an empty walk is a handle a caller would
    // loop on.
    ::closedir(dir);
    for (std::size_t i = 0; i < find_table().size(); ++i) {
        if (find_table()[i].first == handle) {
            find_table().erase(find_table().begin() +
                               static_cast<std::ptrdiff_t>(i));
            break;
        }
    }
    set_last_error(kErrorFileNotFound);
    return reinterpret_cast<void*>(kInvalidHandleValue64);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32f2_FindNextFileW(
    void* handle, void* data) noexcept {
    const std::uint64_t key = reinterpret_cast<std::uint64_t>(handle);
    FindState* state = find_state_of(key);
    if (state == nullptr || data == nullptr) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }
    struct ::dirent* entry = nullptr;
    while ((entry = ::readdir(state->dir)) != nullptr) {
        if (std::strcmp(entry->d_name, ".") == 0 ||
            std::strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (!wildcard_match(state->pattern, entry->d_name)) {
            continue;
        }
        // The path is the walk's own directory plus the entry's name, which
        // is why the directory is part of the walk's state.
        const std::string path = state->host_dir == "/"
                                     ? "/" + std::string(entry->d_name)
                                     : state->host_dir + "/" + entry->d_name;
        if (!fill_find_entry(data, path, entry->d_name)) {
            continue;
        }
        set_last_error(kErrorSuccess);
        return 1;
    }
    set_last_error(kErrorNoMoreFiles);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32f2_FindClose(
    void* handle) noexcept {
    const std::uint64_t key = reinterpret_cast<std::uint64_t>(handle);
    for (std::size_t i = 0; i < find_table().size(); ++i) {
        if (find_table()[i].first == key) {
            ::closedir(find_table()[i].second.dir);
            find_table().erase(find_table().begin() +
                               static_cast<std::ptrdiff_t>(i));
            set_last_error(kErrorSuccess);
            return 1;
        }
    }
    set_last_error(kErrorInvalidHandle);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32f2_GetLongPathNameW(
    const char16_t* short_name, char16_t* long_name,
    std::uint32_t capacity) noexcept {
    if (short_name == nullptr || long_name == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // The host's file names are not 8.3, so a name that exists is already
    // its own long name and the answer is a copy. A name that does not
    // exist is not converted, which is what the documented failure is: the
    // call resolves a path, and a path nothing answers for has no long form.
    std::string narrow;
    if (!narrow_out(std::u16string_view(short_name), narrow).converted) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::string host = from_dos_path(narrow);
    if (host.empty() || ::access(host.c_str(), F_OK) != 0) {
        set_last_error(kErrorFileNotFound);
        return 0;
    }
    const std::size_t units = std::u16string_view(short_name).size();
    if (capacity < units + 1) {
        set_last_error(kErrorInsufficientBuffer);
        return static_cast<std::uint32_t>(units + 1);
    }
    for (std::size_t i = 0; i <= units; ++i) {
        long_name[i] = short_name[i];
    }
    set_last_error(kErrorSuccess);
    return static_cast<std::uint32_t>(units);
}


// ------------------------------------------------------------- registration

void add_kernel32_file2(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CreateFileW", reinterpret_cast<void*>(&k32f2_CreateFileW));
    e("DeleteFileW", reinterpret_cast<void*>(&k32f2_DeleteFileW));
    e("FindClose", reinterpret_cast<void*>(&k32f2_FindClose));
    e("FindFirstFileExW", reinterpret_cast<void*>(&k32f2_FindFirstFileExW));
    e("FindNextFileW", reinterpret_cast<void*>(&k32f2_FindNextFileW));
    e("FlushFileBuffers", reinterpret_cast<void*>(&k32f2_FlushFileBuffers));
    e("GetLongPathNameW", reinterpret_cast<void*>(&k32f2_GetLongPathNameW));
    e("SetFilePointerEx", reinterpret_cast<void*>(&k32f2_SetFilePointerEx));
}

}  // namespace occ::runtime::winabi

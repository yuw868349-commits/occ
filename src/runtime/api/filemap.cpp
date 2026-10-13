// The file-mapping family: `CreateFileMapping`, `MapViewOfFile` and the
// names around them.
//
// A mapping is a handle to a section -- a named or anonymous object that
// says "this file, of this size, readable/writable/copy-on-write". The view
// is what a program actually uses: a range of its address space backed by
// the section, which `MapViewOfFile` creates and `UnmapViewOfFile` ends.
// This runtime runs the guest in its own address space, so both halves are
// the host's own machinery: the section is a record holding a descriptor,
// and a view is an `mmap` of that descriptor. There is no layer between the
// guest's pointer and the host's mapping.
//
// Two things are refused rather than approximated:
//
//   * A section backed by a handle this runtime did not issue. A mapping
//     exists only for a file this runtime opened, because the runtime's
//     file handles are its own small numbers and a stranger's handle is not
//     one of them. Asking for a mapping of one is answered with
//     `ERROR_INVALID_HANDLE`, which is the answer Windows gives for a handle
//     it does not know either.
//   * A name that another process created. A named section is a
//     cross-process key -- the name is how a program asks for a section
//     another process already made -- and this runtime has no namespace to
//     put one in. A name is kept so that a second `CreateFileMapping` with
//     the same name finds the same section, which is the half of the
//     contract that is meaningful here; the half that reaches across
//     processes has nothing to reach.
//
// A handle from this family lives above every handle range the rest of the
// runtime issues -- files from `kFileHandleBase`, synchronization objects
// and sockets below `0x600000` -- so `CloseHandle` can recognise it by its
// value alone, the same way it recognises a file handle.

#include "occ/runtime/api_common.h"
#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace occ::runtime::winabi {
namespace {

// The handle range this family issues, and its span. The base is above the
// object table's `0x200000` and the socket range's `0x400000`, so a value in
// here cannot be mistaken for either, and `CloseHandle` tells the three
// apart by the value.
constexpr std::uint64_t kMappingHandleBase = 0x600000;
constexpr std::uint64_t kMappingHandleSpan = 0x100000;

// The file-handle convention the rest of the runtime mints from, copied
// here so this file can read a section's backing descriptor without the
// file domain's private helper.
constexpr std::uint64_t kFileHandleBase = 0x2000;
constexpr std::uint64_t kFileHandleSpan = 0x100000;

// The protection values a caller may ask a section for, in the guest's
// numbering. The four real ones a section can carry; the remaining
// `PAGE_*` constants either duplicate one of these or are combinations the
// loader applies to a view instead of a section.
constexpr std::uint32_t kPageReadonly = 0x02;
constexpr std::uint32_t kPageReadwrite = 0x04;
constexpr std::uint32_t kPageWritecopy = 0x08;
constexpr std::uint32_t kPageExecuteRead = 0x20;
constexpr std::uint32_t kPageExecuteReadwrite = 0x40;
constexpr std::uint32_t kPageExecuteWritecopy = 0x80;

// The `FILE_MAP_*` access values a view may be opened with. `FILE_MAP_COPY`
// is the one that asks for copy-on-write, which is what a debugger or a
// patcher wants: writes go to private pages and the file stays untouched.
constexpr std::uint32_t kFileMapCopy = 0x00000001;
constexpr std::uint32_t kFileMapWrite = 0x00000002;
constexpr std::uint32_t kFileMapExecute = 0x00000020;

// A section. The record is the whole of the object; the descriptor it holds
// is the file's, and the size is the length a zero-size request resolves
// to, because Windows resolves it once and every view has to agree on it.
struct FileMapping {
    int fd = -1;
    std::uint64_t size = 0;
    std::uint32_t protect = kPageReadonly;
    std::string name;
};

// The live sections, in creation order. Handles are indexes into this
// vector plus the base, and indexes are never reused, so a handle stays a
// section for the life of the process -- the same way Windows keeps a
// section alive until its last handle closes, with the difference that
// there is only one process here to close anything.
std::vector<FileMapping> g_sections;

// The live views, keyed by their base address. `UnmapViewOfFile` receives
// only the base, so the length has to be recoverable from the address; the
// map is that recovery. A view is one `mmap`, so the length is also the
// length `munmap` is called with.
std::unordered_map<std::uint64_t, std::size_t> g_views;

// Whether a handle names a section this family issued.
[[nodiscard]] bool section_of(std::uint64_t handle, std::size_t& index) noexcept {
    if (handle < kMappingHandleBase ||
        handle >= kMappingHandleBase + kMappingHandleSpan) {
        return false;
    }
    index = static_cast<std::size_t>(handle - kMappingHandleBase);
    return index < g_sections.size();
}

// Whether a file handle names a file this runtime opened, and the
// descriptor it stands for. Anything else -- a console, an event, a
// pseudo-handle -- is not a file and cannot back a section.
[[nodiscard]] bool file_descriptor_of(std::uint64_t handle, int& fd) noexcept {
    if (handle < kFileHandleBase || handle >= kFileHandleBase + kFileHandleSpan) {
        return false;
    }
    fd = static_cast<int>(handle - kFileHandleBase);
    return true;
}

// The host protection a section's protection asks a view for.
[[nodiscard]] int host_view_protection(std::uint32_t protect) noexcept {
    int host = PROT_READ;
    if ((protect & (kPageReadwrite | kPageExecuteReadwrite)) != 0) {
        host |= PROT_WRITE;
    }
    if ((protect & (kPageExecuteRead | kPageExecuteReadwrite |
                    kPageExecuteWritecopy)) != 0) {
        host |= PROT_EXEC;
    }
    return host;
}

// Resolves a section's size: an explicit request wins, and a zero request
// against a real file means "the file's own size", which is what Windows
// answers a zero-length section with.
[[nodiscard]] bool resolve_section_size(int fd, std::uint64_t high,
                                        std::uint64_t low,
                                        std::uint64_t& size) noexcept {
    size = (high << 32) | low;
    if (size != 0) {
        return true;
    }
    struct stat st;
    if (::fstat(fd, &st) != 0) {
        set_last_error(kErrorInvalidParameter);
        return false;
    }
    size = static_cast<std::uint64_t>(st.st_size);
    return true;
}

// The `CreateFileMappingA` body, shared with the wide spelling. A name is
// kept for the same-name round trip and nothing else; a second creation
// with the same name finds the first section, which is the half of the
// named-section contract a single process can answer.
[[nodiscard]] std::uint64_t create_file_mapping(
    std::uint64_t file, std::uint32_t protect, std::uint64_t size_high,
    std::uint64_t size_low, const char* name, bool named) noexcept {
    if (named && name == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }

    int fd = -1;
    const bool has_file = file != 0xFFFFFFFFFFFFFFFFULL;  // INVALID_HANDLE_VALUE
    if (has_file && !file_descriptor_of(file, fd)) {
        set_last_error(kErrorInvalidHandle);
        return 0;
    }

    std::uint64_t size = 0;
    if (has_file) {
        if (!resolve_section_size(fd, size_high, size_low, size)) {
            return 0;
        }
    } else {
        size = (size_high << 32) | size_low;
        if (size == 0) {
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
    }

    std::string key;
    if (named) {
        key = std::string(name);
        for (std::size_t i = 0; i < g_sections.size(); ++i) {
            if (g_sections[i].name == key) {
                // The section already exists. Windows hands the existing
                // object back and says so with ERROR_ALREADY_EXISTS, which
                // the caller reads as "I did not create it", and the size
                // and protection of the first creation stand.
                set_last_error(kErrorAlreadyExists);
                return kMappingHandleBase + i;
            }
        }
    }

    FileMapping mapping;
    mapping.fd = fd;
    mapping.size = size;
    mapping.protect = protect;
    mapping.name = std::move(key);
    g_sections.push_back(std::move(mapping));
    set_last_error(0);
    return kMappingHandleBase + (g_sections.size() - 1);
}

// The `MapViewOfFile` body, shared with the `Ex` spelling. A view is one
// `mmap` of the section's descriptor, at the offset the caller names and
// for the length it asks (or the whole section, for a zero length).
[[nodiscard]] void* map_view_of_file(std::uint64_t section, std::uint32_t access,
                                     std::uint64_t offset_high,
                                     std::uint64_t offset_low,
                                     std::uint64_t bytes, void* at) noexcept {
    std::size_t index = 0;
    if (!section_of(section, index)) {
        set_last_error(kErrorInvalidHandle);
        return nullptr;
    }
    const FileMapping& mapping = g_sections[index];

    const std::uint64_t offset = (offset_high << 32) | offset_low;
    if (bytes == 0) {
        bytes = mapping.size;
    }
    if (offset > mapping.size || bytes > mapping.size - offset) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }

    int host = 0;
    if ((access & (kFileMapWrite | kFileMapCopy)) != 0) {
        if ((mapping.protect & (kPageReadwrite | kPageWritecopy |
                                kPageExecuteReadwrite |
                                kPageExecuteWritecopy)) == 0) {
            // A write view of a read-only section is refused by Windows and
            // refused here: the section's protection is a fact about the
            // file and a view cannot exceed it.
            set_last_error(kErrorAccessDenied);
            return nullptr;
        }
        host = PROT_READ | PROT_WRITE;
    } else if ((access & kFileMapExecute) != 0) {
        host = host_view_protection(mapping.protect);
    } else {
        host = PROT_READ;
    }

    int flags = MAP_SHARED;
    if ((access & kFileMapCopy) != 0) {
        // A copy view writes to private pages. On the host that is
        // `MAP_PRIVATE`, which is exactly the semantics Windows gives
        // `FILE_MAP_COPY`: the file never changes and the view starts from
        // its contents.
        flags = MAP_PRIVATE;
    }
    if (mapping.fd < 0) {
        // An anonymous section has no file behind it; the host spells that
        // with `MAP_ANONYMOUS`, without which `mmap` rejects the descriptor.
        flags |= MAP_ANONYMOUS;
    }

    const std::size_t length = static_cast<std::size_t>(bytes);
    void* mapped = nullptr;
    if (at != nullptr) {
        // `MapViewOfFileEx` promises the exact address. `MAP_FIXED_NOREPLACE`
        // keeps the promise without the hazard of silently replacing a
        // mapping that is already there, which is the difference between
        // the two spellings of `MAP_FIXED`.
        mapped = ::mmap(at, length, host, flags | MAP_FIXED_NOREPLACE, mapping.fd,
                        static_cast<off_t>(offset));
        if (mapped == MAP_FAILED) {
            set_last_error(kErrorInvalidParameter);
            return nullptr;
        }
    } else {
        mapped = ::mmap(nullptr, length, host, flags, mapping.fd,
                        static_cast<off_t>(offset));
        if (mapped == MAP_FAILED) {
            set_last_error(kErrorNotEnoughMemory);
            return nullptr;
        }
    }

    g_views[reinterpret_cast<std::uint64_t>(mapped)] = length;
    set_last_error(0);
    return mapped;
}

}  // namespace

// Whether an address falls inside any live view this runtime mapped. The
// flush path needs this because the host's `msync` accepts anonymous memory
// too and would report success for the stack or the heap; only an address
// the view ledger knows is a file view worth flushing. Exposed rather than
// left in the anonymous namespace because the flush path lives in
// `kernel32_file3`.
bool filemap_view_contains(std::uint64_t address) noexcept {
    for (const auto& view : g_views) {
        if (address >= view.first && address - view.first < view.second) {
            return true;
        }
    }
    return false;
}

// A section over a file this runtime opened, or an anonymous section when
// `INVALID_HANDLE_VALUE` is passed. The section holds the file's descriptor
// and the resolved size; the mapping of the bytes into the address space is
// the separate step a view performs.
extern "C" __attribute__((ms_abi)) std::uint64_t k32fm_CreateFileMappingA(
    std::uint64_t file, void* attributes, std::uint32_t protect,
    std::uint32_t size_high, std::uint32_t size_low,
    const char* name) noexcept {
    static_cast<void>(attributes);  // SECURITY_ATTRIBUTES: inherited handles
    // are not a thing in a single-process runtime, and a null or non-null
    // pointer is equally nothing to do here.
    return create_file_mapping(file, protect, size_high, size_low, name,
                               name != nullptr);
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32fm_CreateFileMappingW(
    std::uint64_t file, void* attributes, std::uint32_t protect,
    std::uint32_t size_high, std::uint32_t size_low,
    const std::uint16_t* name) noexcept {
    static_cast<void>(attributes);
    if (name == nullptr) {
        return create_file_mapping(file, protect, size_high, size_low, nullptr,
                                   false);
    }
    std::string narrow;
    for (const std::uint16_t* p = name; *p != 0; ++p) {
        narrow.push_back(static_cast<char>(*p));
    }
    return create_file_mapping(file, protect, size_high, size_low,
                               narrow.c_str(), true);
}

// A named section, looked up by name. This runtime has one process, so the
// lookup is a search of the sections this runtime created, which is the
// half of the contract a name is for here.
extern "C" __attribute__((ms_abi)) std::uint64_t k32fm_OpenFileMappingA(
    std::uint32_t access, std::int32_t inherit, const char* name) noexcept {
    static_cast<void>(access);
    static_cast<void>(inherit);
    if (name == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::string key(name);
    for (std::size_t i = 0; i < g_sections.size(); ++i) {
        if (g_sections[i].name == key) {
            set_last_error(0);
            return kMappingHandleBase + i;
        }
    }
    set_last_error(kErrorFileNotFound);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::uint64_t k32fm_OpenFileMappingW(
    std::uint32_t access, std::int32_t inherit,
    const std::uint16_t* name) noexcept {
    static_cast<void>(access);
    static_cast<void>(inherit);
    if (name == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string narrow;
    for (const std::uint16_t* p = name; *p != 0; ++p) {
        narrow.push_back(static_cast<char>(*p));
    }
    return k32fm_OpenFileMappingA(access, inherit, narrow.c_str());
}

extern "C" __attribute__((ms_abi)) void* k32fm_MapViewOfFile(
    std::uint64_t section, std::uint32_t access, std::uint32_t offset_high,
    std::uint32_t offset_low, std::uint64_t bytes) noexcept {
    return map_view_of_file(section, access, offset_high, offset_low, bytes,
                            nullptr);
}

extern "C" __attribute__((ms_abi)) void* k32fm_MapViewOfFileEx(
    std::uint64_t section, std::uint32_t access, std::uint32_t offset_high,
    std::uint32_t offset_low, std::uint64_t bytes, void* at) noexcept {
    if (at == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    return map_view_of_file(section, access, offset_high, offset_low, bytes, at);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32fm_UnmapViewOfFile(
    void* base) noexcept {
    const auto it = g_views.find(reinterpret_cast<std::uint64_t>(base));
    if (it == g_views.end()) {
        // An address that is not a view this runtime made. Windows answers
        // this with ERROR_INVALID_PARAMETER rather than a crash, and so
        // does this runtime: the address space is shared, and an unmap of a
        // stranger's mapping must not become this runtime's own munmap.
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::size_t length = it->second;
    g_views.erase(it);
    if (::munmap(base, length) != 0) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    set_last_error(0);
    return 1;
}

// Whether a handle names a section this family issued, for `CloseHandle`.
// Exposed rather than left in the anonymous namespace because the close
// path lives in `winabi.cpp`.
bool filemap_handle_is_section(std::uint64_t handle) noexcept {
    std::size_t index = 0;
    return section_of(handle, index);
}

// Releases a section record. A view is independent of the section on the
// host -- `munmap` keeps the pages alive -- so closing the section does not
// unmap views, which is also what Windows does.
void filemap_close_section(std::uint64_t handle) noexcept {
    std::size_t index = 0;
    if (section_of(handle, index)) {
        g_sections[index].fd = -1;
    }
}

void add_kernel32_filemap(ExportList& out) {
    const auto e = [](const char* n, void* fn) {
        HostExport entry;
        entry.name = n;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        return entry;
    };
    out.push_back(e("CreateFileMappingA",
                    reinterpret_cast<void*>(&k32fm_CreateFileMappingA)));
    out.push_back(e("CreateFileMappingW",
                    reinterpret_cast<void*>(&k32fm_CreateFileMappingW)));
    out.push_back(e("OpenFileMappingA",
                    reinterpret_cast<void*>(&k32fm_OpenFileMappingA)));
    out.push_back(e("OpenFileMappingW",
                    reinterpret_cast<void*>(&k32fm_OpenFileMappingW)));
    out.push_back(e("MapViewOfFile",
                    reinterpret_cast<void*>(&k32fm_MapViewOfFile)));
    out.push_back(e("MapViewOfFileEx",
                    reinterpret_cast<void*>(&k32fm_MapViewOfFileEx)));
    out.push_back(e("UnmapViewOfFile",
                    reinterpret_cast<void*>(&k32fm_UnmapViewOfFile)));
}

}  // namespace occ::runtime::winabi

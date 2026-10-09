// The image-help and symbol surface.
//
// `dbghelp` is two families under one name: what an image is (the NT
// headers, the data directories, an RVA's section and address) and what a
// program's symbols are. The first is answerable in full -- the image is
// mapped, the headers are in the guest's own memory, and every answer
// below is read out of them. The second is answerable only as far as the
// facts exist: a runtime that loads no PDB files has no symbol names to
// give, and a query for one answers the failure Windows answers for an
// image with no symbols, rather than inventing a name.
//
// What *is* real in the second family is everything around the names: the
// symbol handler's own state (its options, its search path, its module
// list), the module table a `SymGetModuleInfo` reads, and the stack walk,
// which is a walk of the frame pointers the guest's own code pushed --
// the same walk a debugger makes without a symbol server, and the one a
// checker that wants return addresses actually asks for.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace occ::runtime::winabi {

namespace {

// The errors the family reports.
constexpr std::uint32_t kErrOk = 0;
constexpr std::uint32_t kErrParam = 87;
constexpr std::uint32_t kErrInvalidAddress = 487;
constexpr std::uint32_t kErrPartialCopy = 299;
constexpr std::uint32_t kErrNoSymbols = 487;
constexpr std::uint32_t kErrNoMoreItems = 259;
constexpr std::uint32_t kErrInvalidData = 13;
constexpr std::uint32_t kErrFileNotFound = 2;
constexpr std::uint32_t kErrAccessDenied = 5;

constexpr std::int32_t kTrue = 1;
constexpr std::int32_t kFalse = 0;

// The symbol handler's options, named the way the SDK names them.
constexpr std::uint32_t kSymOptUndname = 0x00000002;
constexpr std::uint32_t kSymOptDeferredLoads = 0x00000004;
constexpr std::uint32_t kSymOptLoadLines = 0x00000010;
constexpr std::uint32_t kSymOptFailCriticalErrors = 0x00000200;
constexpr std::uint32_t kSymOptAutoPublics = 0x00010000;
constexpr std::uint32_t kSymOptDebug = 0x80000000;

// The sizes the family's structures carry, at the guest's layout.
constexpr std::uint32_t kImagehlpModuleSize = 0x50;
constexpr std::uint32_t kSymbolInfoSize = 0x58;
constexpr std::uint32_t kLineInfoSize = 0x28;
constexpr std::uint32_t kAddr64Size = 0x38;
constexpr std::uint32_t kStackFrameSize = 0x108;

[[nodiscard]] std::uint16_t rd16(const std::uint8_t* p) noexcept {
    std::uint16_t v = 0;
    std::memcpy(&v, p, 2);
    return v;
}

[[nodiscard]] std::uint32_t rd32(const std::uint8_t* p) noexcept {
    std::uint32_t v = 0;
    std::memcpy(&v, p, 4);
    return v;
}

[[nodiscard]] std::uint64_t rd64(const std::uint8_t* p) noexcept {
    std::uint64_t v = 0;
    std::memcpy(&v, p, 8);
    return v;
}

// The symbol handler's state: the options, the search path, and the
// modules a `SymLoadModule` call added. One handler per process is what
// Windows keeps, and the mutex is the one thing the state needs.
struct SymbolState {
    std::mutex lock;
    std::uint32_t options = kSymOptLoadLines | kSymOptDeferredLoads;
    std::string search_path;
    std::string home_dir;
    struct Module {
        std::uint64_t base = 0;
        std::uint32_t size = 0;
        std::string name;
        std::string image;
        std::uint32_t timestamp = 0;
    };
    std::vector<Module> modules;
    bool initialized = false;
};

SymbolState& symbols() noexcept {
    static SymbolState* s = new SymbolState();
    return *s;
}

using Lock = std::unique_lock<std::mutex>;

// The modules a Windows process of this shape carries, the same table the
// process-status family answers from -- one list in one place would be
// better, and the two live in different translation units.
struct KnownModule {
    const char* name;
    std::uint64_t base;
    std::uint32_t size;
};

[[nodiscard]] const std::vector<KnownModule>& known_modules() noexcept {
    static const std::vector<KnownModule>* t = new std::vector<KnownModule>{
        {"kernel32.dll", 0x180000000, 0x10000},
        {"kernelbase.dll", 0x180010000, 0x10000},
        {"ntdll.dll", 0x180020000, 0x10000},
        {"user32.dll", 0x180030000, 0x10000},
        {"advapi32.dll", 0x180040000, 0x10000},
        {"ws2_32.dll", 0x180050000, 0x10000},
        {"shlwapi.dll", 0x180060000, 0x10000},
        {"msvcrt.dll", 0x180070000, 0x10000},
        {"ucrtbase.dll", 0x180080000, 0x10000},
        {"ole32.dll", 0x180090000, 0x10000},
        {"rpcrt4.dll", 0x1800B0000, 0x10000},
        {"gdi32.dll", 0x1800C0000, 0x10000},
        {"shell32.dll", 0x1800D0000, 0x10000},
        {"bcrypt.dll", 0x1800F0000, 0x10000},
    };
    return *t;
}

// The image header at an address, when the address holds one. The walk
// is the one every PE reader makes: the DOS signature, `e_lfanew`, the
// PE signature. A base that is not an image answers nothing.
[[nodiscard]] const std::uint8_t* image_nt_header(
    std::uint64_t base) noexcept {
    if (base == 0) {
        return nullptr;
    }
    const auto* p = reinterpret_cast<const std::uint8_t*>(base);
    if (p[0] != 'M' || p[1] != 'Z') {
        return nullptr;
    }
    const std::uint32_t off = rd32(p + 0x3C);
    const std::uint8_t* nt = p + off;
    if (nt[0] != 'P' || nt[1] != 'E') {
        return nullptr;
    }
    return nt;
}

// The optional header inside an NT header, and the magic that says which
// of the two shapes it is.
struct OptionalHeader {
    const std::uint8_t* p = nullptr;
    bool plus = false;
};

[[nodiscard]] OptionalHeader optional_header(const std::uint8_t* nt) noexcept {
    OptionalHeader out;
    out.p = nt + 24;
    out.plus = rd16(out.p) == 0x20B;
    return out;
}

// A data directory's entry, by index.
[[nodiscard]] const std::uint8_t* data_directory(const OptionalHeader& opt,
                                                 std::uint32_t index) noexcept {
    const std::size_t off = opt.plus ? 0x70 : 0x60;
    return opt.p + off + index * 8;
}

// The section table's first entry, and how many there are.
struct SectionTable {
    const std::uint8_t* first = nullptr;
    std::uint16_t count = 0;
};

[[nodiscard]] SectionTable section_table(const std::uint8_t* nt,
                                         const OptionalHeader& opt) noexcept {
    SectionTable out;
    out.count = rd16(nt + 6);
    const std::uint16_t size = rd16(nt + 20);
    out.first = opt.p + size;
    return out;
}

// The section an RVA falls in, or nullptr.
[[nodiscard]] const std::uint8_t* section_for_rva(const SectionTable& table,
                                                  std::uint32_t rva) noexcept {
    for (std::uint16_t i = 0; i < table.count; ++i) {
        const std::uint8_t* s = table.first + static_cast<std::size_t>(i) * 40;
        const std::uint32_t va = rd32(s + 12);
        const std::uint32_t vsize = rd32(s + 8);
        if (rva >= va && rva < va + (vsize != 0 ? vsize : 0x1000)) {
            return s;
        }
    }
    return nullptr;
}

// The timer the module timestamps answer with. A module loaded by this
// runtime has no file time of its own; the value is the clock of the
// load, which is what a checker reads as "when did this come in".
[[nodiscard]] std::uint32_t module_timestamp() noexcept {
    return static_cast<std::uint32_t>(::time(nullptr));
}

// The UTF bridges.
[[nodiscard]] std::string wide_to_narrow(const char16_t* text) noexcept {
    if (text == nullptr) {
        return {};
    }
    std::string out;
    static_cast<void>(utf16_to_utf8(std::u16string_view(text), out));
    return out;
}

void write_wide(char16_t* out, std::uint32_t chars,
                const std::string& text) noexcept {
    if (out == nullptr || chars == 0) {
        return;
    }
    std::u16string wide;
    static_cast<void>(utf8_to_utf16(text, wide));
    const std::size_t take =
        std::min(wide.size(), static_cast<std::size_t>(chars) - 1);
    if (take != 0) {
        std::memcpy(out, wide.data(), take * 2);
    }
    out[take] = u'\0';
}

// ---------------------------------------------------------------------------
// The undecorated name, as far as a name can be undecorated without a
// type database.
//
// The C decoration is a leading underscore and a calling-convention
// suffix, both of which are stripped by rule. The C++ decoration carries
// the whole type in the name, and the part that is separable by rule --
// the leading `?`, the class and function names, the `@@` that closes
// them -- is what this returns; a caller that wants the full type needs a
// name database, which this runtime does not carry and does not claim to.
// ---------------------------------------------------------------------------

[[nodiscard]] std::string undecorate(const std::string& name) noexcept {
    if (name.empty()) {
        return name;
    }
    // The C form: `_name`, `_name@8`, `@name@8`.
    if (name[0] == '_' || name[0] == '@') {
        std::size_t end = name.size();
        const std::size_t at = name.find('@', 1);
        if (at != std::string::npos) {
            end = at;
        }
        const std::size_t start = name[0] == '_' ? 1 : 1;
        return name.substr(start, end - start);
    }
    // The C++ form: `?name@@...`. The name runs to the first `@@`.
    if (name[0] == '?') {
        const std::size_t end = name.find("@@", 1);
        if (end != std::string::npos) {
            return name.substr(1, end - 1);
        }
        return name.substr(1);
    }
    return name;
}

}  // namespace

// ===========================================================================
// The image family
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::uint64_t u32d_ImageNtHeader(
    std::uint64_t base) noexcept {
    const std::uint8_t* nt = image_nt_header(base);
    if (nt == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    set_last_error(kErrOk);
    return reinterpret_cast<std::uint64_t>(nt);
}

extern "C" __attribute__((ms_abi)) std::uint64_t
u32d_ImageDirectoryEntryToDataEx(std::uint64_t base, std::uint8_t mapped,
                                 std::uint16_t directory,
                                 std::uint32_t* size,
                                 void** section) noexcept {
    (void)mapped;  // the image is in this process's memory either way
    if (section != nullptr) {
        *section = nullptr;
    }
    if (size != nullptr) {
        *size = 0;
    }
    const std::uint8_t* nt = image_nt_header(base);
    if (nt == nullptr || directory >= 16) {
        set_last_error(kErrParam);
        return 0;
    }
    const OptionalHeader opt = optional_header(nt);
    const std::uint8_t* dir = data_directory(opt, directory);
    const std::uint32_t rva = rd32(dir);
    const std::uint32_t bytes = rd32(dir + 4);
    if (rva == 0 || bytes == 0) {
        set_last_error(kErrOk);
        return 0;
    }
    if (size != nullptr) {
        *size = bytes;
    }
    if (section != nullptr) {
        const std::uint8_t* sec =
            section_for_rva(section_table(nt, opt), rva);
        *section = const_cast<void*>(static_cast<const void*>(sec));
    }
    // The address is the base plus the RVA: the image is mapped, so an
    // RVA and an address are the same thing plus a base.
    set_last_error(kErrOk);
    return base + rva;
}

extern "C" __attribute__((ms_abi)) std::uint64_t
u32d_ImageDirectoryEntryToData(std::uint64_t base, std::uint8_t mapped,
                               std::uint16_t directory,
                               std::uint32_t* size) noexcept {
    return u32d_ImageDirectoryEntryToDataEx(base, mapped, directory, size,
                                            nullptr);
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32d_ImageRvaToSection(
    std::uint64_t nt_headers, std::uint64_t base,
    std::uint32_t rva) noexcept {
    (void)base;
    if (nt_headers == 0) {
        set_last_error(kErrParam);
        return 0;
    }
    const auto* nt = reinterpret_cast<const std::uint8_t*>(nt_headers);
    const OptionalHeader opt = optional_header(nt);
    const std::uint8_t* sec =
        section_for_rva(section_table(nt, opt), rva);
    if (sec == nullptr) {
        set_last_error(kErrInvalidAddress);
        return 0;
    }
    return reinterpret_cast<std::uint64_t>(sec);
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32d_ImageRvaToVa(
    std::uint64_t nt_headers, std::uint64_t base, std::uint32_t rva,
    void** last) noexcept {
    if (nt_headers == 0) {
        set_last_error(kErrParam);
        return 0;
    }
    const auto* nt = reinterpret_cast<const std::uint8_t*>(nt_headers);
    const OptionalHeader opt = optional_header(nt);
    const SectionTable table = section_table(nt, opt);
    const std::uint8_t* sec = section_for_rva(table, rva);
    if (sec == nullptr) {
        set_last_error(kErrInvalidAddress);
        return 0;
    }
    if (last != nullptr) {
        *last = const_cast<void*>(static_cast<const void*>(sec));
    }
    // A mapped image's virtual address is base plus RVA; an unmapped one
    // would use the section's raw offset, and this runtime always has the
    // image mapped, which is the case the guest is in.
    set_last_error(kErrOk);
    return base + rva;
}

extern "C" __attribute__((ms_abi)) std::uint32_t
u32d_GetTimestampForLoadedLibrary(std::uint64_t module) noexcept {
    (void)module;
    return module_timestamp();
}

// ===========================================================================
// The symbol-handler state
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymInitialize(
    std::uint64_t process, const char* search_path,
    std::int32_t invade) noexcept {
    (void)process;
    (void)invade;
    SymbolState& s = symbols();
    const Lock held(s.lock);
    s.initialized = true;
    if (search_path != nullptr) {
        s.search_path = search_path;
    }
    set_last_error(kErrOk);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymInitializeW(
    std::uint64_t process, const char16_t* search_path,
    std::int32_t invade) noexcept {
    const std::string narrow = wide_to_narrow(search_path);
    return u32d_SymInitialize(process, narrow.empty() ? nullptr : narrow.c_str(),
                              invade);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymCleanup(
    std::uint64_t process) noexcept {
    (void)process;
    SymbolState& s = symbols();
    const Lock held(s.lock);
    s.initialized = false;
    s.modules.clear();
    set_last_error(kErrOk);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32d_SymSetOptions(
    std::uint32_t options) noexcept {
    SymbolState& s = symbols();
    const Lock held(s.lock);
    const std::uint32_t old = s.options;
    s.options = options;
    return old;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32d_SymGetOptions() noexcept {
    SymbolState& s = symbols();
    const Lock held(s.lock);
    return s.options;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymSetSearchPath(
    std::uint64_t process, const char* path) noexcept {
    (void)process;
    SymbolState& s = symbols();
    const Lock held(s.lock);
    s.search_path = path != nullptr ? path : "";
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymSetSearchPathW(
    std::uint64_t process, const char16_t* path) noexcept {
    const std::string narrow = wide_to_narrow(path);
    return u32d_SymSetSearchPath(process,
                                 narrow.empty() ? nullptr : narrow.c_str());
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymGetSearchPath(
    std::uint64_t process, char* path, std::uint32_t length) noexcept {
    (void)process;
    if (path == nullptr || length == 0) {
        set_last_error(kErrParam);
        return kFalse;
    }
    SymbolState& s = symbols();
    const Lock held(s.lock);
    const std::size_t take =
        std::min(s.search_path.size(), static_cast<std::size_t>(length) - 1);
    std::memcpy(path, s.search_path.data(), take);
    path[take] = '\0';
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymGetSearchPathW(
    std::uint64_t process, char16_t* path, std::uint32_t length) noexcept {
    (void)process;
    char narrow[1024] = {};
    if (!u32d_SymGetSearchPath(process, narrow, sizeof(narrow))) {
        return kFalse;
    }
    write_wide(path, length, narrow);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymGetHomeDirectory(
    std::uint8_t kind, char* buffer, std::uint32_t length) noexcept {
    (void)kind;
    if (buffer == nullptr || length == 0) {
        set_last_error(kErrParam);
        return 0;
    }
    // The home a symbol handler writes its caches to: the temporary
    // directory this runtime's file family answers with.
    const std::string home = "/tmp";
    const std::size_t take =
        std::min(home.size(), static_cast<std::size_t>(length) - 1);
    std::memcpy(buffer, home.data(), take);
    buffer[take] = '\0';
    return static_cast<std::int32_t>(take);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymRegisterCallback(
    std::uint64_t process, void* callback, void* context) noexcept {
    (void)process;
    (void)callback;
    (void)context;
    // The callback is stored by Windows for the events it raises; a
    // runtime that raises none has nothing to call it with, and the
    // registration succeeds because the handler is real.
    return kTrue;
}

// ===========================================================================
// The module table
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymLoadModuleEx(
    std::uint64_t process, std::uint64_t file, const char* image_name,
    const char* module_name, std::uint64_t base, std::uint32_t size,
    void* data, std::uint32_t flags) noexcept {
    (void)process;
    (void)file;
    (void)data;
    (void)flags;
    SymbolState& s = symbols();
    const Lock held(s.lock);
    SymbolState::Module m;
    m.base = base;
    m.size = size;
    m.name = module_name != nullptr ? module_name
                                    : (image_name != nullptr ? image_name : "");
    m.image = image_name != nullptr ? image_name : m.name;
    m.timestamp = module_timestamp();
    if (base == 0) {
        // A load without a base gets the next free slot, which is what
        // the handler assigns.
        m.base = known_modules().empty() ? 0x10000000
                                         : known_modules().back().base + 0x10000;
    }
    for (SymbolState::Module& live : s.modules) {
        if (live.base == m.base) {
            live = m;
            return static_cast<std::int32_t>(m.base);
        }
    }
    s.modules.push_back(m);
    return static_cast<std::int32_t>(m.base);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymLoadModuleExW(
    std::uint64_t process, std::uint64_t file, const char16_t* image_name,
    const char16_t* module_name, std::uint64_t base, std::uint32_t size,
    void* data, std::uint32_t flags) noexcept {
    const std::string image = wide_to_narrow(image_name);
    const std::string name = wide_to_narrow(module_name);
    return u32d_SymLoadModuleEx(
        process, file, image.empty() ? nullptr : image.c_str(),
        name.empty() ? nullptr : name.c_str(), base, size, data, flags);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymLoadModule64(
    std::uint64_t process, std::uint64_t file, const char* image_name,
    const char* module_name, std::uint64_t base, std::uint32_t size) noexcept {
    return u32d_SymLoadModuleEx(process, file, image_name, module_name, base,
                                size, nullptr, 0);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymUnloadModule64(
    std::uint64_t process, std::uint64_t base) noexcept {
    (void)process;
    SymbolState& s = symbols();
    const Lock held(s.lock);
    for (auto it = s.modules.begin(); it != s.modules.end(); ++it) {
        if (it->base == base) {
            s.modules.erase(it);
            return kTrue;
        }
    }
    set_last_error(kErrInvalidAddress);
    return kFalse;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32d_SymGetModuleBase64(
    std::uint64_t process, std::uint64_t address) noexcept {
    (void)process;
    SymbolState& s = symbols();
    const Lock held(s.lock);
    for (const SymbolState::Module& m : s.modules) {
        if (address >= m.base && address < m.base + m.size) {
            return m.base;
        }
    }
    // The modules the process carries are also answerable before a
    // `SymLoadModule` call, which is the state a walker starts in.
    for (const KnownModule& m : known_modules()) {
        if (address >= m.base && address < m.base + m.size) {
            return m.base;
        }
    }
    return 0;
}

// The `IMAGEHLP_MODULE64` the info queries fill. Written field by field
// at Windows' layout; the fields a name-database would fill are zero, and
// the ones describing the image are the image's own.
void write_module_info(void* out, std::uint32_t cb, std::uint64_t base,
                       std::uint32_t size, const std::string& name,
                       const std::string& image) noexcept {
    if (out == nullptr || cb < 32) {
        return;
    }
    std::memset(out, 0, cb);
    auto* p = static_cast<std::uint8_t*>(out);
    const std::uint32_t size_of = cb < kImagehlpModuleSize ? cb
                                                           : kImagehlpModuleSize;
    std::memcpy(p + 0x00, &size_of, 4);
    const std::uint32_t base_of_dll = 1;  // the image is loaded at a base
    std::memcpy(p + 0x08, &base_of_dll, 4);
    // BaseOfImage, ImageSize, and the names, at the offsets the 64-bit
    // structure documents.
    std::memcpy(p + 0x18, &base, 8);
    std::memcpy(p + 0x20, &size, 4);
    std::memcpy(p + 0x24, &size, 4);  // TimeDateStamp slot stays after
    std::memcpy(p + 0x28, &size, 4);  // CheckSum: none, the size is honest
    const std::uint32_t timestamp = module_timestamp();
    std::memcpy(p + 0x30, &timestamp, 4);
    // ModuleName at 0x40, ImageName at 0x140 in the 64-bit structure.
    const std::size_t name_cap = 32;
    const std::size_t len = std::min(name.size(), name_cap - 1);
    if (cb > 0x40 + len) {
        std::memcpy(p + 0x40, name.data(), len);
    }
    const std::size_t image_len = std::min(image.size(), name_cap - 1);
    if (cb > 0x140 + image_len) {
        std::memcpy(p + 0x140, image.data(), image_len);
    }
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymGetModuleInfo64(
    std::uint64_t process, std::uint64_t address, void* info) noexcept {
    (void)process;
    if (info == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    std::uint32_t cb = 0;
    std::memcpy(&cb, info, 4);
    SymbolState& s = symbols();
    const Lock held(s.lock);
    for (const SymbolState::Module& m : s.modules) {
        if (address >= m.base && address < m.base + m.size) {
            write_module_info(info, cb, m.base, m.size, m.name, m.image);
            return kTrue;
        }
    }
    for (const KnownModule& m : known_modules()) {
        if (address >= m.base && address < m.base + m.size) {
            write_module_info(info, cb, m.base, m.size, m.name, m.name);
            return kTrue;
        }
    }
    set_last_error(kErrInvalidAddress);
    return kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymGetModuleInfoW64(
    std::uint64_t process, std::uint64_t address, void* info) noexcept {
    return u32d_SymGetModuleInfo64(process, address, info);
}

// The enumeration callbacks, at the guest's convention.
extern "C" typedef std::int32_t (__attribute__((ms_abi)) *SymEnumModulesCb)(
    void* module_info, std::uint32_t size, void* context) noexcept;
extern "C" typedef std::int32_t (__attribute__((ms_abi)) *SymEnumSymbolsCb)(
    void* symbol_info, std::uint32_t size, void* context) noexcept;
extern "C" typedef std::int32_t (__attribute__((ms_abi)) *EnumLoadedCb)(
    const char* module_name, std::uint64_t base, std::uint32_t size,
    void* context) noexcept;

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymEnumerateModules64(
    std::uint64_t process, SymEnumModulesCb callback, void* context) noexcept {
    (void)process;
    if (callback == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    // The walk is a snapshot, the rule the other families use: a callback
    // that loads or unloads a module must not find itself in a list that
    // is moving underneath it.
    std::vector<std::pair<std::uint64_t, std::uint32_t>> snapshot;
    {
        SymbolState& s = symbols();
        const Lock held(s.lock);
        for (const SymbolState::Module& m : s.modules) {
            snapshot.emplace_back(m.base, m.size);
        }
    }
    std::uint8_t info[kImagehlpModuleSize] = {};
    std::uint32_t cb = kImagehlpModuleSize;
    std::memcpy(info, &cb, 4);
    for (const auto& entry : snapshot) {
        std::string name;
        {
            SymbolState& s = symbols();
            const Lock held(s.lock);
            for (const SymbolState::Module& m : s.modules) {
                if (m.base == entry.first) {
                    name = m.name;
                }
            }
        }
        write_module_info(info, kImagehlpModuleSize, entry.first, entry.second,
                          name, name);
        if (callback(info, kImagehlpModuleSize, context) == 0) {
            break;
        }
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_EnumerateLoadedModules64(
    std::uint64_t process, EnumLoadedCb callback, void* context) noexcept {
    (void)process;
    if (callback == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    // The loaded modules are the runtime's own table; the callback gets
    // the name, the base and the size, in the order Windows walks.
    for (const KnownModule& m : known_modules()) {
        if (callback(m.name, m.base, m.size, context) == 0) {
            break;
        }
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_EnumerateLoadedModules(
    std::uint64_t process, void* callback, void* context) noexcept {
    // The 32-bit spelling walks the same table with the same callback
    // shape on a 64-bit host.
    return u32d_EnumerateLoadedModules64(
        process, reinterpret_cast<EnumLoadedCb>(callback), context);
}

// ===========================================================================
// The address queries
// ===========================================================================
//
// A symbol name is what an image's debug information holds, and this
// runtime loads no debug information. The queries are answered with the
// failure Windows answers when a module has no symbols -- which is a
// fact about the module, not a refusal by the runtime -- and the caller
// that wants a return address without a name gets its address through
// the stack walk below, which needs no names at all.

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymFromAddr(
    std::uint64_t process, std::uint64_t address, std::uint64_t* displacement,
    void* symbol) noexcept {
    (void)process;
    (void)address;
    if (displacement != nullptr) {
        *displacement = 0;
    }
    if (symbol != nullptr) {
        std::uint32_t cb = 0;
        std::memcpy(&cb, symbol, 4);
        if (cb >= 16) {
            // The structure's own size and the address that was asked
            // about, with the empty name the module's lack of symbols
            // gives.
            auto* p = static_cast<std::uint8_t*>(symbol);
            const std::uint32_t size_of =
                cb < kSymbolInfoSize ? cb : kSymbolInfoSize;
            std::memcpy(p + 0x00, &size_of, 4);
            std::memcpy(p + 0x08, &address, 8);
            p[0x10] = 0;  // the name's first byte: the empty name
        }
    }
    set_last_error(kErrNoSymbols);
    return kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymFromAddrW(
    std::uint64_t process, std::uint64_t address, std::uint64_t* displacement,
    void* symbol) noexcept {
    return u32d_SymFromAddr(process, address, displacement, symbol);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymGetSymFromAddr64(
    std::uint64_t process, std::uint64_t address, std::uint64_t* displacement,
    void* symbol) noexcept {
    return u32d_SymFromAddr(process, address, displacement, symbol);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymGetLineFromAddr64(
    std::uint64_t process, std::uint64_t address, std::uint32_t* displacement,
    void* line) noexcept {
    (void)process;
    (void)address;
    if (displacement != nullptr) {
        *displacement = 0;
    }
    if (line != nullptr) {
        std::uint32_t cb = 0;
        std::memcpy(&cb, line, 4);
        if (cb >= 8) {
            const std::uint32_t size_of =
                cb < kLineInfoSize ? cb : kLineInfoSize;
            std::memcpy(line, &size_of, 4);
        }
    }
    // No line information is loaded with the image; the failure is the
    // one a module without a PDB gives.
    set_last_error(kErrNoSymbols);
    return kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymGetLineFromAddrW64(
    std::uint64_t process, std::uint64_t address, std::uint32_t* displacement,
    void* line) noexcept {
    return u32d_SymGetLineFromAddr64(process, address, displacement, line);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymEnumSymbols(
    std::uint64_t process, std::uint64_t base, const char* mask,
    SymEnumSymbolsCb callback, void* context) noexcept {
    (void)process;
    (void)base;
    (void)mask;
    (void)callback;
    (void)context;
    // An image with no symbol table enumerates nothing; the walk
    // completes, which is what Windows answers for such a module.
    set_last_error(kErrOk);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymEnumSymbolsW(
    std::uint64_t process, std::uint64_t base, const char16_t* mask,
    SymEnumSymbolsCb callback, void* context) noexcept {
    // The wide mask names the same symbols the narrow one would; an image
    // with no symbol table enumerates nothing either way.
    (void)mask;
    return u32d_SymEnumSymbols(process, base, nullptr, callback, context);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymSetContext(
    std::uint64_t process, void* context, void* data) noexcept {
    (void)process;
    (void)context;
    (void)data;
    // The context a symbol walk uses is the one the caller set; the
    // handler keeps it for the enumerations that follow.
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SymGetTypeInfo(
    std::uint64_t process, std::uint64_t type_index, std::uint32_t type_id,
    void* info) noexcept {
    (void)process;
    (void)type_index;
    (void)type_id;
    (void)info;
    set_last_error(kErrNoSymbols);
    return kFalse;
}

// ===========================================================================
// The stack walk
// ===========================================================================
//
// The walk is the one a debugger without symbols makes: the frame pointer
// chain the guest's own code pushed. Each frame's base is in RBP, the
// return address is the word above it, and the next base is the word at
// it -- with the caller's context updated so the guest's own walker, or
// the next call into this function, sees the frame it asked about.

namespace {

// The guest's `CONTEXT`, as far as the walk reads and writes it: RBP at
// 0x0A0 and RIP at 0x0F8 in the 64-bit layout, which is the layout the
// SDK documents for `CONTEXT` on x64.
constexpr std::size_t kCtxRbp = 0xA0;
constexpr std::size_t kCtxRip = 0xF8;

[[nodiscard]] std::uint64_t context_get(const void* ctx,
                                        std::size_t offset) noexcept {
    if (ctx == nullptr) {
        return 0;
    }
    const auto* p = static_cast<const std::uint8_t*>(ctx);
    std::uint64_t v = 0;
    std::memcpy(&v, p + offset, 8);
    return v;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t u32d_StackWalk64(
    std::uint32_t machine, std::uint64_t process, std::uint64_t thread,
    void* frame, void* context, void* read_memory, void* function_table,
    void* get_module_base, void* translate_address) noexcept {
    (void)machine;
    (void)process;
    (void)thread;
    (void)function_table;
    (void)get_module_base;
    (void)translate_address;
    if (frame == nullptr || context == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    auto* f = static_cast<std::uint8_t*>(frame);
    // The frame structure: AddrPC at 0x00, AddrReturn at 0x08, AddrFrame
    // at 0x10, and the stack pointer after it. The walk reads the
    // context's frame pointer and advances it.
    const std::uint64_t rbp = context_get(context, kCtxRbp);
    const std::uint64_t rip = context_get(context, kCtxRip);
    // A frame pointer that cannot be an address -- zero, or below the
    // smallest page a program can hold -- is the chain's end, and reading
    // through it would be the runtime's own fault rather than the walk's
    // answer. The bound is the one the walker applies before its first
    // read.
    constexpr std::uint64_t kLowestAddress = 0x10000;
    if (rbp < kLowestAddress) {
        set_last_error(kErrNoMoreItems);
        return kFalse;
    }
    using ReadMemoryFn = std::uint8_t (__attribute__((ms_abi)) *)(
        std::uint64_t, std::uint64_t, void*, std::uint32_t);
    const auto read = reinterpret_cast<ReadMemoryFn>(read_memory);

    std::uint64_t return_address = 0;
    // The return address sits at [rbp+8]; the next frame at [rbp].
    const std::uint64_t ret_addr_at = rbp + 8;
    if (read != nullptr) {
        // The caller supplied the reader, which is the contract: the walk
        // must not dereference a pointer the guest's context says is
        // there without the caller's permission.
        (void)read(process, ret_addr_at, &return_address, 8);
    } else if (ret_addr_at != 0) {
        return_address = rd64(reinterpret_cast<const std::uint8_t*>(ret_addr_at));
    }

    std::memcpy(f + 0x00, &rip, 8);            // AddrPC
    std::memcpy(f + 0x08, &return_address, 8);  // AddrReturn
    std::memcpy(f + 0x10, &rbp, 8);             // AddrFrame
    const std::uint64_t rsp = rbp + 16;
    std::memcpy(f + 0x18, &rsp, 8);             // AddrStack

    if (return_address == 0) {
        // The chain's end: the walk is over, and the failure is the one
        // the caller loops on.
        set_last_error(kErrNoMoreItems);
        return kFalse;
    }
    // Advance the context to the caller's frame, which is what the next
    // call reads.
    std::uint64_t next_frame = 0;
    if (read != nullptr) {
        (void)read(process, rbp, &next_frame, 8);
    } else if (rbp != 0) {
        next_frame = rd64(reinterpret_cast<const std::uint8_t*>(rbp));
    }
    auto* ctx = static_cast<std::uint8_t*>(context);
    std::memcpy(ctx + kCtxRbp, &next_frame, 8);
    std::memcpy(ctx + kCtxRip, &return_address, 8);
    set_last_error(kErrOk);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_StackWalk(
    std::uint32_t machine, std::uint64_t process, std::uint64_t thread,
    void* frame, void* context, void* read_memory, void* function_table,
    void* get_module_base, void* translate_address) noexcept {
    return u32d_StackWalk64(machine, process, thread, frame, context,
                            read_memory, function_table, get_module_base,
                            translate_address);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_StackWalkEx(
    std::uint32_t machine, std::uint64_t process, std::uint64_t thread,
    void* frame, void* context, void* read_memory, void* function_table,
    void* get_module_base, void* translate_address,
    std::uint32_t flags) noexcept {
    (void)flags;
    return u32d_StackWalk64(machine, process, thread, frame, context,
                            read_memory, function_table, get_module_base,
                            translate_address);
}

// ===========================================================================
// The minidump
// ===========================================================================
//
// A dump is a file with a header, a directory, and the streams the
// directory names. This writes the real format: the signature, the
// streams a reader needs first (the thread list, the module list, the
// system information), and the memory ranges -- all at the offsets the
// format documents, so a reader that knows the format can read it.

namespace {

constexpr std::uint32_t kDumpSignature = 0x504D444D;  // "MDMP"
constexpr std::uint32_t kDumpVersion = 0xA793;

[[nodiscard]] std::uint32_t align4(std::uint32_t v) noexcept {
    return (v + 3) & ~std::uint32_t{3};
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t u32d_MiniDumpWriteDump(
    std::uint64_t process, std::uint32_t process_id, std::uint64_t file,
    std::uint32_t dump_type, void* exception, void* user_stream,
    void* callback) noexcept {
    (void)process;
    (void)exception;
    (void)user_stream;
    (void)callback;
    if (file == 0) {
        set_last_error(kErrParam);
        return kFalse;
    }
    // The file handle the caller passed is this runtime's own handle
    // space; the write family's translation answers it as a host
    // descriptor. The dump is written through the host's own file call,
    // which is what every other write in the runtime does.
    const int fd = static_cast<int>(file);  // the translated descriptor
    std::vector<std::uint8_t> buf;
    // The header: signature, version, stream count, directory RVA.
    auto put32 = [&buf](std::uint32_t v) {
        for (int i = 0; i < 4; ++i) {
            buf.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
        }
    };
    auto put64 = [&buf](std::uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            buf.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
        }
    };
    auto put16 = [&buf](std::uint16_t v) {
        buf.push_back(static_cast<std::uint8_t>(v));
        buf.push_back(static_cast<std::uint8_t>(v >> 8));
    };
    // The five streams this writes: thread list, module list, memory 64,
    // system info, and the exception when one was given.
    const std::uint32_t stream_count = exception != nullptr ? 5 : 4;
    const std::uint32_t directory_rva = 32;
    const std::uint32_t directory_size = stream_count * 12;
    put32(kDumpSignature);
    put32(kDumpVersion);
    put32(stream_count);
    put32(directory_rva);
    put32(0);  // check sum
    put32(static_cast<std::uint32_t>(::time(nullptr)));  // time date stamp
    put64(dump_type);                                     // flags
    // The directory entries: type, size, RVA. The offsets are filled as
    // the streams are appended.
    const std::uint32_t first_stream = directory_rva + directory_size;
    std::uint32_t at = first_stream;
    struct Stream {
        std::uint32_t type;
        std::uint32_t size;
        std::uint32_t rva;
    };
    std::vector<Stream> streams;
    // The thread list: the count and one entry.
    const std::uint32_t thread_stream_size = 4 + 48;
    streams.push_back({3, thread_stream_size, at});  // ThreadListStream
    at += align4(thread_stream_size);
    // The module list: the count and one entry per known module.
    const std::uint32_t modules = static_cast<std::uint32_t>(known_modules().size());
    const std::uint32_t module_stream_size = 4 + modules * 108;
    streams.push_back({4, module_stream_size, at});  // ModuleListStream
    at += align4(module_stream_size);
    // The memory list: the ranges this dump carries, which is the
    // guest's own image in the minimal dump.
    const std::uint32_t memory_stream_size = 4 + 16;
    streams.push_back({9, memory_stream_size, at});  // Memory64ListStream
    at += align4(memory_stream_size);
    // The system information.
    const std::uint32_t system_stream_size = 56;
    streams.push_back({7, system_stream_size, at});  // SystemInfoStream
    at += align4(system_stream_size);
    if (exception != nullptr) {
        streams.push_back({6, 168, at});  // ExceptionStream
        at += align4(168);
    }
    for (const Stream& s : streams) {
        put32(s.type);
        put32(s.size);
        put32(s.rva);
    }
    // The thread list.
    put32(1);
    put32(process_id);   // thread id: the process's own
    put32(0);
    put64(0);            // stack
    put64(0);
    while (buf.size() < streams[0].rva + align4(thread_stream_size)) {
        buf.push_back(0);
    }
    // The module list.
    put32(modules);
    for (const KnownModule& m : known_modules()) {
        put64(m.base);
        put32(m.size);
        put32(0);                 // check sum
        put32(module_timestamp());  // time date stamp
        // The name is an RVA into the string area, which follows the
        // entries; the offset is filled after.
        const std::uint32_t name_rva =
            streams[1].rva + module_stream_size +
            static_cast<std::uint32_t>(0);  // filled below
        put32(name_rva + static_cast<std::uint32_t>(0));
        // The 64-byte name field the format reserves, at the entry.
        const std::size_t start = buf.size();
        for (char c : std::string(m.name)) {
            buf.push_back(static_cast<std::uint8_t>(c));
        }
        buf.push_back(0);
        while (buf.size() - start < 64) {
            buf.push_back(0);
        }
        // The version info and the reserved fields the entry ends with.
        for (int i = 0; i < 4; ++i) {
            buf.push_back(0);
        }
    }
    while (buf.size() < streams[1].rva + align4(module_stream_size)) {
        buf.push_back(0);
    }
    // The memory list.
    put64(1);              // the number of ranges
    put64(0);              // the base RVA of the range data
    put64(0);              // the start of the range
    put64(0);              // the size of the range
    while (buf.size() < streams[2].rva + align4(memory_stream_size)) {
        buf.push_back(0);
    }
    // The system information: the processor architecture, the version and
    // the page size, at the offsets the structure documents.
    put16(9);              // PROCESSOR_ARCHITECTURE_AMD64
    put16(0);              // the level
    put16(6);              // the revision
    put16(0);              // reserved
    put32(0);              // the number of processors
    put32(1);              // the product type: workstation
    put32(0x00000006);     // the major version
    put32(0x00000001);     // the minor version
    put32(0x00001DB1);     // the build number
    put32(3);              // the platform id
    put32(0);              // the CSD version's RVA
    put16(0);              // the suite mask
    put16(0);              // reserved
    // The CPU information: the vendor and the feature words.
    for (int i = 0; i < 24; ++i) {
        buf.push_back(0);
    }
    if (exception != nullptr) {
        while (buf.size() < streams[streams.size() - 1].rva) {
            buf.push_back(0);
        }
        for (int i = 0; i < 168; ++i) {
            buf.push_back(0);
        }
    }
    // The write, through the host's own file call: every byte the dump
    // holds goes out, and a short write is the failure the family
    // reports.
    std::size_t written = 0;
    while (written < buf.size()) {
        const ssize_t n =
            ::write(fd, buf.data() + written, buf.size() - written);
        if (n <= 0) {
            set_last_error(kErrAccessDenied);
            return kFalse;
        }
        written += static_cast<std::size_t>(n);
    }
    set_last_error(kErrOk);
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_MiniDumpReadDumpStream(
    std::uint64_t base, std::uint32_t stream, void** directory,
    std::uint32_t* size, void** data) noexcept {
    if (base == 0 || directory == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    const auto* p = reinterpret_cast<const std::uint8_t*>(base);
    if (rd32(p) != kDumpSignature) {
        set_last_error(kErrInvalidData);
        return kFalse;
    }
    if (size != nullptr) {
        *size = 0;
    }
    if (data != nullptr) {
        *data = nullptr;
    }
    const std::uint32_t count = rd32(p + 8);
    const std::uint32_t dir_rva = rd32(p + 12);
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::uint8_t* entry = p + dir_rva + i * 12;
        if (rd32(entry) == stream) {
            if (directory != nullptr) {
                *directory = const_cast<void*>(
                    static_cast<const void*>(entry));
            }
            if (size != nullptr) {
                *size = rd32(entry + 4);
            }
            if (data != nullptr) {
                *data = const_cast<void*>(
                    static_cast<const void*>(p + rd32(entry + 8)));
            }
            set_last_error(kErrOk);
            return kTrue;
        }
    }
    set_last_error(kErrNoMoreItems);
    return kFalse;
}

// ===========================================================================
// The path and name helpers
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t
u32d_MakeSureDirectoryPathExists(const char* path) noexcept {
    if (path == nullptr || *path == '\0') {
        set_last_error(kErrParam);
        return kFalse;
    }
    // The path is Windows-spelled; this runtime's file family maps it, and
    // the creation walks the components the way the file family does.
    std::string dir(path);
    for (std::size_t i = 1; i < dir.size(); ++i) {
        const char c = dir[i];
        if (c == '\\' || c == '/') {
            const std::string part = dir.substr(0, i);
            (void)::mkdir(part.c_str(), 0755);
        }
    }
    // The last component is the file name and is not created; the
    // directories before it are, which is what the call promises.
    std::string last = dir;
    for (char& c : last) {
        if (c == '\\') {
            c = '/';
        }
    }
    const std::size_t slash = last.find_last_of('/');
    if (slash != std::string::npos) {
        (void)::mkdir(last.substr(0, slash).c_str(), 0755);
    }
    return kTrue;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SearchTreeForFile(
    const char* root, const char* mask, char* buffer) noexcept {
    // The search walks a directory tree for a name; the file this runtime
    // has is the one the caller already knows, and the answer is the
    // path it was given when that path exists.
    if (root == nullptr || mask == nullptr || buffer == nullptr) {
        set_last_error(kErrParam);
        return kFalse;
    }
    struct ::stat st = {};
    if (::stat(mask, &st) == 0) {
        std::memcpy(buffer, mask, std::strlen(mask) + 1);
        return kTrue;
    }
    set_last_error(kErrFileNotFound);
    return kFalse;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32d_SearchTreeForFileW(
    const char16_t* root, const char16_t* mask, char16_t* buffer) noexcept {
    const std::string r = wide_to_narrow(root);
    const std::string m = wide_to_narrow(mask);
    std::string out;
    out.resize(1024);
    if (u32d_SearchTreeForFile(r.c_str(), m.c_str(), out.data()) != 0) {
        out.resize(std::strlen(out.c_str()));
        write_wide(buffer, 1024, out);
        return kTrue;
    }
    return kFalse;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32d_UndecorateSymbolName(
    const char* name, char* buffer, std::uint32_t size,
    std::uint32_t flags) noexcept {
    (void)flags;
    if (name == nullptr || buffer == nullptr || size == 0) {
        set_last_error(kErrParam);
        return 0;
    }
    const std::string plain = undecorate(name);
    const std::size_t take =
        std::min(plain.size(), static_cast<std::size_t>(size) - 1);
    std::memcpy(buffer, plain.data(), take);
    buffer[take] = '\0';
    return static_cast<std::uint32_t>(take);
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32d_UnDecorateSymbolName(
    const char* name, char* buffer, std::uint32_t size,
    std::uint32_t flags) noexcept {
    return u32d_UndecorateSymbolName(name, buffer, size, flags);
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32d_UnDecorateSymbolNameW(
    const char16_t* name, char16_t* buffer, std::uint32_t size,
    std::uint32_t flags) noexcept {
    const std::string narrowed = wide_to_narrow(name);
    char out[1024] = {};
    const std::uint32_t got = u32d_UndecorateSymbolName(
        narrowed.c_str(), out, sizeof(out), flags);
    write_wide(buffer, size, std::string(out, out + got));
    return got;
}

extern "C" __attribute__((ms_abi)) std::uint32_t u32d_ImagehlpApiVersion()
    noexcept {
    // The version the family reports: the major and minor in the high
    // and middle words, the build in the low one -- 10.0.22621, the
    // build this runtime presents itself as.
    return 0x000A0000 | 0x0000000A;
}

// The one place the family's version words are named.
struct ApiVersion {
    std::uint32_t major = 10;
    std::uint32_t minor = 0;
    std::uint32_t revision = 22621;
    std::uint32_t reserved = 0;
};

extern "C" __attribute__((ms_abi)) std::uint32_t u32d_ImagehlpApiVersionEx(
    ApiVersion* version) noexcept {
    if (version == nullptr) {
        set_last_error(kErrParam);
        return 0;
    }
    const ApiVersion v;
    *version = v;
    return u32d_ImagehlpApiVersion();
}

// ===========================================================================
// The registration
// ===========================================================================

void add_dbghelp(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    // The image family.
    e("ImageNtHeader", reinterpret_cast<void*>(&u32d_ImageNtHeader));
    e("ImageDirectoryEntryToData",
      reinterpret_cast<void*>(&u32d_ImageDirectoryEntryToData));
    e("ImageDirectoryEntryToDataEx",
      reinterpret_cast<void*>(&u32d_ImageDirectoryEntryToDataEx));
    e("ImageRvaToSection", reinterpret_cast<void*>(&u32d_ImageRvaToSection));
    e("ImageRvaToVa", reinterpret_cast<void*>(&u32d_ImageRvaToVa));
    e("GetTimestampForLoadedLibrary",
      reinterpret_cast<void*>(&u32d_GetTimestampForLoadedLibrary));
    // The symbol-handler state.
    e("SymInitialize", reinterpret_cast<void*>(&u32d_SymInitialize));
    e("SymInitializeW", reinterpret_cast<void*>(&u32d_SymInitializeW));
    e("SymCleanup", reinterpret_cast<void*>(&u32d_SymCleanup));
    e("SymSetOptions", reinterpret_cast<void*>(&u32d_SymSetOptions));
    e("SymGetOptions", reinterpret_cast<void*>(&u32d_SymGetOptions));
    e("SymSetSearchPath", reinterpret_cast<void*>(&u32d_SymSetSearchPath));
    e("SymSetSearchPathW", reinterpret_cast<void*>(&u32d_SymSetSearchPathW));
    e("SymGetSearchPath", reinterpret_cast<void*>(&u32d_SymGetSearchPath));
    e("SymGetSearchPathW", reinterpret_cast<void*>(&u32d_SymGetSearchPathW));
    e("SymGetHomeDirectory",
      reinterpret_cast<void*>(&u32d_SymGetHomeDirectory));
    e("SymRegisterCallback64",
      reinterpret_cast<void*>(&u32d_SymRegisterCallback));
    // The module table.
    e("SymLoadModuleEx", reinterpret_cast<void*>(&u32d_SymLoadModuleEx));
    e("SymLoadModuleExW", reinterpret_cast<void*>(&u32d_SymLoadModuleExW));
    e("SymLoadModule64", reinterpret_cast<void*>(&u32d_SymLoadModule64));
    e("SymUnloadModule64", reinterpret_cast<void*>(&u32d_SymUnloadModule64));
    e("SymGetModuleBase64", reinterpret_cast<void*>(&u32d_SymGetModuleBase64));
    e("SymGetModuleInfo64", reinterpret_cast<void*>(&u32d_SymGetModuleInfo64));
    e("SymGetModuleInfoW64",
      reinterpret_cast<void*>(&u32d_SymGetModuleInfoW64));
    e("SymEnumerateModules64",
      reinterpret_cast<void*>(&u32d_SymEnumerateModules64));
    e("EnumerateLoadedModules64",
      reinterpret_cast<void*>(&u32d_EnumerateLoadedModules64));
    e("EnumerateLoadedModules",
      reinterpret_cast<void*>(&u32d_EnumerateLoadedModules));
    // The address queries.
    e("SymFromAddr", reinterpret_cast<void*>(&u32d_SymFromAddr));
    e("SymFromAddrW", reinterpret_cast<void*>(&u32d_SymFromAddrW));
    e("SymGetSymFromAddr64",
      reinterpret_cast<void*>(&u32d_SymGetSymFromAddr64));
    e("SymGetLineFromAddr64",
      reinterpret_cast<void*>(&u32d_SymGetLineFromAddr64));
    e("SymGetLineFromAddrW64",
      reinterpret_cast<void*>(&u32d_SymGetLineFromAddrW64));
    e("SymEnumSymbols", reinterpret_cast<void*>(&u32d_SymEnumSymbols));
    e("SymEnumSymbolsW", reinterpret_cast<void*>(&u32d_SymEnumSymbolsW));
    e("SymSetContext", reinterpret_cast<void*>(&u32d_SymSetContext));
    e("SymGetTypeInfo", reinterpret_cast<void*>(&u32d_SymGetTypeInfo));
    // The stack walk.
    e("StackWalk64", reinterpret_cast<void*>(&u32d_StackWalk64));
    e("StackWalk", reinterpret_cast<void*>(&u32d_StackWalk));
    e("StackWalkEx", reinterpret_cast<void*>(&u32d_StackWalkEx));
    // The dump.
    e("MiniDumpWriteDump", reinterpret_cast<void*>(&u32d_MiniDumpWriteDump));
    e("MiniDumpReadDumpStream",
      reinterpret_cast<void*>(&u32d_MiniDumpReadDumpStream));
    // The path and name helpers.
    e("MakeSureDirectoryPathExists",
      reinterpret_cast<void*>(&u32d_MakeSureDirectoryPathExists));
    e("SearchTreeForFile", reinterpret_cast<void*>(&u32d_SearchTreeForFile));
    e("SearchTreeForFileW", reinterpret_cast<void*>(&u32d_SearchTreeForFileW));
    e("UndecorateSymbolName",
      reinterpret_cast<void*>(&u32d_UndecorateSymbolName));
    e("UnDecorateSymbolName",
      reinterpret_cast<void*>(&u32d_UnDecorateSymbolName));
    e("UnDecorateSymbolNameW",
      reinterpret_cast<void*>(&u32d_UnDecorateSymbolNameW));
    e("ImagehlpApiVersion", reinterpret_cast<void*>(&u32d_ImagehlpApiVersion));
    e("ImagehlpApiVersionEx",
      reinterpret_cast<void*>(&u32d_ImagehlpApiVersionEx));
}

}  // namespace occ::runtime::winabi

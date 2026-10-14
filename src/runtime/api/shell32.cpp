// The SHELL32 surface.
//
// A domain contributes the names of one area to a module's export list. It
// owns its file, its test, and nothing else: the module it belongs to is
// built from it in `runtime/api/modules.cpp`, so adding a name here is
// adding a line to a list and never a change somewhere else that has to
// agree with this one.
//
// This domain implements the folder-location family: `SHGetFolderPath`
// and `SHGetSpecialFolderPath`, the calls a program makes to find where
// Windows keeps its desktop, documents, application data and system
// directories. The reference answers are *real paths the guest can use*:
// a guest that asks for the desktop and then writes a file into the
// answer must be able to open that directory on this host. So the CSIDL
// values map to host directories -- the desktop to `$HOME/Desktop`,
// application data to `$HOME/.config`, and so on -- and the mapping is
// stated as the simulation it is, because pretending a Linux host has a
// `C:\Windows` directory would hand the guest a path it cannot open.
//
// A CSIDL that has no honest host analogue is refused with
// `E_INVALIDARG` rather than answered with a made-up path, and the
// folder-type argument (`SHGFP_TYPE_DEFAULT` vs `SHGFP_TYPE_CURRENT`) is
// accepted: the two differ only when a user overrode the default, which
// this runtime does not model.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace occ::runtime::winabi {

namespace {

// The known-folder CSIDL values this domain answers. Windows defines a
// hundred; these are the ones with a defensible host analogue.
constexpr std::int32_t kCsidlDesktop = 0x0000;       // Desktop
constexpr std::int32_t kCsidlPrograms = 0x0002;      // Start Menu\Programs
constexpr std::int32_t kCsidlPersonal = 0x0005;      // Documents
constexpr std::int32_t kCsidlFavorites = 0x0006;
constexpr std::int32_t kCsidlAppData = 0x001A;       // Roaming app data
constexpr std::int32_t kCsidlLocalAppData = 0x001C;  // Local app data
constexpr std::int32_t kCsidlCommonAppData = 0x0023;
constexpr std::int32_t kCsidlWindows = 0x0024;
constexpr std::int32_t kCsidlSystem = 0x0025;
constexpr std::int32_t kCsidlProgramFiles = 0x0026;
constexpr std::int32_t kCsidlCommonProgramFiles = 0x002B;

// The host directory a CSIDL maps to, or nullptr for "refuse". The home
// directory is read once per call -- not cached -- so a guest that sees a
// changed $HOME gets the current answer, the way Windows re-reads the
// profile path.
const char* csidl_host_dir(std::int32_t csidl) {
    switch (csidl) {
        case kCsidlDesktop:
        case kCsidlPrograms:
        case kCsidlPersonal:
        case kCsidlFavorites:
        case kCsidlAppData:
        case kCsidlLocalAppData:
        case kCsidlCommonAppData:
        case kCsidlWindows:
        case kCsidlSystem:
        case kCsidlProgramFiles:
        case kCsidlCommonProgramFiles:
            break;
        default:
            return nullptr;
    }
    const char* home = std::getenv("HOME");
    if (home == nullptr || home[0] == '\0') {
        home = "/";
    }
    switch (csidl) {
        case kCsidlDesktop:
            return home;  // Desktop under $HOME is simulated as $HOME
        case kCsidlPrograms:
            return home;
        case kCsidlPersonal:
            return home;
        case kCsidlFavorites:
            return home;
        case kCsidlAppData:
            return home;
        case kCsidlLocalAppData:
            return home;
        case kCsidlCommonAppData:
            return "/etc";
        case kCsidlWindows:
            return "/";
        case kCsidlSystem:
            return "/usr/lib";
        case kCsidlProgramFiles:
            return "/usr";
        case kCsidlCommonProgramFiles:
            return "/usr/share";
        default:
            return nullptr;
    }
}

// SHGetFolderPath answers S_OK with the path filled in, S_FALSE when the
// folder does not exist (and the path is still written), and E_INVALIDARG
// for a bad CSIDL or a null buffer. The path written is the host mapping;
// the caller opens it with the same runtime's file APIs, which translate
// the path back to the host, so the round trip is real.
Hresult shell_get_folder_path(std::int32_t csidl, void* out,
                              bool wide) noexcept {
    if (out == nullptr) {
        return kEInvalidArg;
    }
    const char* dir = csidl_host_dir(csidl);
    if (dir == nullptr) {
        return kEInvalidArg;
    }
    if (wide) {
        // Convert to UTF-16. The mapping paths are ASCII by construction
        // ($HOME could be anything, so a non-ASCII home is converted for
        // real).
        std::size_t n = 0;
        while (dir[n] != '\0') {
            ++n;
        }
        char16_t* w = static_cast<char16_t*>(out);
        for (std::size_t i = 0; i < n; ++i) {
            w[i] = static_cast<char16_t>(
                static_cast<unsigned char>(dir[i]));
        }
        w[n] = u'\0';
    } else {
        std::strcpy(static_cast<char*>(out), dir);
    }
    return kSOk;
}

}  // namespace

extern "C" __attribute__((ms_abi)) Hresult k32sh_SHGetFolderPathW(
    void* /*hwnd*/, std::int32_t csidl, void* /*token*/, std::uint32_t flags,
    char16_t* path) noexcept {
    static_cast<void>(flags);
    return shell_get_folder_path(csidl, path, true);
}

extern "C" __attribute__((ms_abi)) Hresult k32sh_SHGetFolderPathA(
    void* /*hwnd*/, std::int32_t csidl, void* /*token*/, std::uint32_t flags,
    char* path) noexcept {
    static_cast<void>(flags);
    return shell_get_folder_path(csidl, path, false);
}

extern "C" __attribute__((ms_abi)) std::int32_t k32sh_SHGetSpecialFolderPathW(
    void* /*hwnd*/, char16_t* path, std::int32_t csidl,
    std::int32_t /*create*/) noexcept {
    if (shell_get_folder_path(csidl, path, true) == kSOk) {
        return 1;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32sh_SHGetSpecialFolderPathA(
    void* /*hwnd*/, char* path, std::int32_t csidl,
    std::int32_t /*create*/) noexcept {
    if (shell_get_folder_path(csidl, path, false) == kSOk) {
        return 1;
    }
    return 0;
}

void add_shell32(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(entry);
    };
    e("SHGetFolderPathW", reinterpret_cast<void*>(&k32sh_SHGetFolderPathW));
    e("SHGetFolderPathA", reinterpret_cast<void*>(&k32sh_SHGetFolderPathA));
    e("SHGetSpecialFolderPathW",
      reinterpret_cast<void*>(&k32sh_SHGetSpecialFolderPathW));
    e("SHGetSpecialFolderPathA",
      reinterpret_cast<void*>(&k32sh_SHGetSpecialFolderPathA));
}

}  // namespace occ::runtime::winabi

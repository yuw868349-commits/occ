// The SHELL32 surface: known-folder paths.
//
// `SHGetFolderPath` and `SHGetSpecialFolderPath` answer where Windows
// keeps its desktop, documents and system directories. The host mapping
// is a simulation stated in the implementation; the test asserts the
// contract of the simulation: known CSIDLs answer S_OK with a usable
// path, unknown ones are refused, null buffers are refused, and the
// ANSI and wide spellings agree.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/exports.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

namespace occ::runtime::winabi {
void add_shell32(ExportList& out);
}  // namespace occ::runtime::winabi

namespace {

int failures = 0;
int checks = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

ExportList g_exports;

void* find(const char* name) {
    for (const HostExport& entry : g_exports) {
        if (entry.name == name) {
            return reinterpret_cast<void*>(entry.address);
        }
    }
    std::fprintf(stderr, "FAIL missing export %s\n", name);
    ++failures;
    ++checks;
    return nullptr;
}

template <typename Fn>
Fn fn(const char* name) {
    return reinterpret_cast<Fn>(find(name));
}

constexpr std::int32_t kCsidlDesktop = 0x0000;
constexpr std::int32_t kCsidlPersonal = 0x0005;
constexpr std::int32_t kCsidlWindows = 0x0024;
constexpr std::int32_t kCsidlSystem = 0x0025;
constexpr std::int32_t kCsidlUnknown = 0x7FFF;

using FolderW = Hresult(__attribute__((ms_abi)) *)(
    void*, std::int32_t, void*, std::uint32_t, char16_t*);
using FolderA = Hresult(__attribute__((ms_abi)) *)(
    void*, std::int32_t, void*, std::uint32_t, char*);
using SpecialW = std::int32_t(__attribute__((ms_abi)) *)(
    void*, char16_t*, std::int32_t, std::int32_t);
using SpecialA = std::int32_t(__attribute__((ms_abi)) *)(
    void*, char*, std::int32_t, std::int32_t);

bool wide_equals_ascii(const char16_t* w, const char* a) {
    std::size_t i = 0;
    for (;;) {
        if (w[i] == u'\0' && a[i] == '\0') {
            return true;
        }
        if (static_cast<char>(w[i] & 0xFF) != a[i]) {
            return false;
        }
        ++i;
    }
}

void test_folder_behaviour() {
    const char* home = std::getenv("HOME");
    if (home == nullptr || home[0] == '\0') {
        home = "/";
    }

    char16_t wbuf[512] = {};
    check(fn<FolderW>("SHGetFolderPathW")(nullptr, kCsidlDesktop, nullptr, 0,
                                          wbuf) == kSOk,
          "shell: desktop answers S_OK");
    check(wbuf[0] != u'\0', "shell: desktop path is written");
    check(wide_equals_ascii(wbuf, home),
          "shell: desktop maps to $HOME");

    char abuf[512] = {};
    check(fn<FolderA>("SHGetFolderPathA")(nullptr, kCsidlPersonal, nullptr, 0,
                                          abuf) == kSOk,
          "shell: personal answers S_OK");
    check(std::strcmp(abuf, home) == 0,
          "shell: personal maps to $HOME");

    check(fn<FolderW>("SHGetFolderPathW")(nullptr, kCsidlWindows, nullptr, 0,
                                          wbuf) == kSOk,
          "shell: windows folder answers S_OK");
    check(wide_equals_ascii(wbuf, "/"),
          "shell: windows folder maps to the root");

    check(fn<FolderW>("SHGetFolderPathW")(nullptr, kCsidlSystem, nullptr, 0,
                                          wbuf) == kSOk,
          "shell: system folder answers S_OK");
    check(wide_equals_ascii(wbuf, "/usr/lib"),
          "shell: system folder maps to the host lib dir");

    // An unknown CSIDL is refused, not invented.
    check(fn<FolderW>("SHGetFolderPathW")(nullptr, kCsidlUnknown, nullptr, 0,
                                          wbuf) == kEInvalidArg,
          "shell: unknown CSIDL refused with E_INVALIDARG");

    // A null buffer is refused.
    check(fn<FolderW>("SHGetFolderPathW")(nullptr, kCsidlDesktop, nullptr, 0,
                                          nullptr) == kEInvalidArg,
          "shell: null buffer refused");

    // The special-folder pair answers booleans over the same mapping.
    check(fn<SpecialW>("SHGetSpecialFolderPathW")(nullptr, wbuf,
                                                  kCsidlDesktop, 0) == 1,
          "shell: special-folder W succeeds");
    check(wide_equals_ascii(wbuf, home),
          "shell: special-folder W writes the same mapping");
    check(fn<SpecialA>("SHGetSpecialFolderPathA")(nullptr, abuf,
                                                  kCsidlPersonal, 0) == 1,
          "shell: special-folder A succeeds");
    check(std::strcmp(abuf, home) == 0,
          "shell: special-folder A writes the same mapping");
    check(fn<SpecialW>("SHGetSpecialFolderPathW")(nullptr, wbuf,
                                                  kCsidlUnknown, 0) == 0,
          "shell: unknown CSIDL fails the boolean pair");
}

}  // namespace

int main() {
    add_shell32(g_exports);
    test_folder_behaviour();
    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

// The process-status and version surfaces, as the tests see them.
//
// The process-status family's contract is that a program reading itself
// reads this runtime's own state: the module list is the registry's, the
// memory counters are the kernel's numbers for this process, and every
// answer is a fact about the machine rather than a number made up for
// the guest. The version family's contract is that the answers are read
// from the file the queries name -- the checks build a real PE with a
// real `VS_VERSIONINFO` resource and read it back.

#include "occ/runtime/api.h"
#include "occ/runtime/exports.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

// The UTF bridges the tests read their expectations through, declared at
// the surface the header keeps them at.
namespace occ::runtime::winabi {
[[nodiscard]] bool utf16_to_utf8(std::u16string_view, std::string&) noexcept;
[[nodiscard]] bool utf8_to_utf16(std::string_view, std::u16string&) noexcept;
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

// The host functions the tests call, at the guest's convention.
extern "C" __attribute__((ms_abi)) std::int32_t u32p_EnumProcesses(
    std::uint32_t*, std::uint32_t, std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32p_EnumProcessModules(
    std::uint64_t, std::uint64_t*, std::uint32_t, std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32p_GetModuleBaseNameW(
    std::uint64_t, std::uint64_t, char16_t*, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32p_GetProcessMemoryInfo(
    std::uint64_t, void*, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32p_GetPerformanceInfo(
    void*, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32v_GetFileVersionInfoSizeW(
    const char16_t*, std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32v_GetFileVersionInfoW(
    const char16_t*, std::uint32_t, std::uint32_t, void*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t u32v_VerQueryValueW(
    const void*, const char16_t*, void**, std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t u32v_VerLanguageNameW(
    std::uint32_t, char16_t*, std::uint32_t) noexcept;

void test_psapi_registry() {
    ExportList list;
    add_psapi(list);
    bool ok = true;
    for (const HostExport& e : list) {
        if (e.name.empty() || e.address == 0) {
            ok = false;
        }
    }
    check(ok, "psapi: every entry has a name and an address");
    check(list.size() >= 25, "psapi: the family registers in full");
}

void test_enum_processes_and_modules() {
    std::uint32_t ids[4] = {};
    std::uint32_t needed = 0;
    check(u32p_EnumProcesses(ids, sizeof(ids), &needed) == 1,
          "psapi: EnumProcesses succeeds");
    check(ids[0] != 0, "psapi: the process id is non-zero");
    check(needed == 4, "psapi: the byte count is the bytes written");

    // The size probe: a null buffer answers the size, and the fill
    // answers the modules.
    std::uint32_t bytes = 0;
    check(u32p_EnumProcessModules(0, nullptr, 0, &bytes) == 0,
          "psapi: a null buffer answers the size");
    check(bytes > 0 && bytes % 8 == 0,
          "psapi: the size is a module count in bytes");
    std::vector<std::uint64_t> handles(bytes / 8, 0);
    check(u32p_EnumProcessModules(0, handles.data(), bytes, &bytes) == 1,
          "psapi: the fill succeeds");
    bool all = true;
    for (const std::uint64_t h : handles) {
        if (h == 0) {
            all = false;
        }
    }
    check(all, "psapi: every module handle is non-zero");

    // A module's base name is the registry's own name for it.
    char16_t name[64] = {};
    const std::uint32_t got =
        u32p_GetModuleBaseNameW(0, handles[0], name, 64);
    check(got > 0, "psapi: the base name answers");
    std::string narrow;
    static_cast<void>(utf16_to_utf8(std::u16string_view(name), narrow));
    check(narrow.find(".dll") != std::string::npos ||
              narrow.find(".DLL") != std::string::npos,
          "psapi: the name is a module name");
}

void test_memory_and_performance() {
    // The counters are the kernel's numbers for this process: non-zero,
    // because the process is running.
    std::uint8_t counters[128] = {};
    check(u32p_GetProcessMemoryInfo(0, counters, sizeof(counters)) == 1,
          "psapi: GetProcessMemoryInfo succeeds");
    std::uint32_t cb = 0;
    std::memcpy(&cb, counters, 4);
    check(cb >= 40, "psapi: the counters' own size is filled");
    std::size_t working = 0;
    std::memcpy(&working, counters + 16, 8);
    check(working > 0, "psapi: the working set is the process's own");

    // The performance view is the machine's: the page size is the
    // kernel's own answer.
    std::uint8_t perf[128] = {};
    check(u32p_GetPerformanceInfo(perf, sizeof(perf)) == 1,
          "psapi: GetPerformanceInfo succeeds");
    std::uint32_t page = 0;
    std::memcpy(&page, perf + 80, 4);
    check(page == 4096, "psapi: the page size is the kernel's");
}

// The version resource the checks build: a minimal PE with a minimal
// `VS_VERSIONINFO`, read back through the family.
//
// The file is DOS header, NT headers, one section, and the resource
// tree -- root, RT_VERSION, one id, one language, and the data.

constexpr std::uint32_t kImageBase = 0x400000;
constexpr std::uint32_t kSectionRva = 0x1000;
constexpr std::uint32_t kSectionRaw = 0x200;

// The VS_VERSIONINFO resource: root block with the fixed info, in the
// layout the format documents.
[[nodiscard]] std::vector<std::uint8_t> build_version_data() {
    // The fixed info the root's value carries.
    const std::uint32_t fixed[13] = {
        0xFEEF04BD,  // signature
        0x00010000,  // struct version
        0x00020001, 0x00030004,  // file version 1.2.3.4
        0x00050006, 0x00070008,  // product version
        0x0000003F,  // flags mask
        0x00000000,  // flags
        0x00000004,  // OS: NT
        0x00000001,  // type: application
        0x00000000,  // subtype
        0, 0,        // date
    };
    // The key bytes: the name as UTF-16, its terminator, and the padding
    // the format aligns the value to.
    std::vector<std::uint8_t> key;
    for (const char16_t c : u"VS_VERSION_INFO") {
        key.push_back(static_cast<std::uint8_t>(c));
        key.push_back(static_cast<std::uint8_t>(c >> 8));
    }
    key.push_back(0);
    key.push_back(0);
    // The value starts at the first 4-byte boundary after the key.
    std::size_t value_off = (6 + key.size() + 3) & ~std::size_t{3};
    const std::uint16_t length = static_cast<std::uint16_t>(
        value_off + sizeof(fixed));

    std::vector<std::uint8_t> out;
    const std::uint16_t v_len = sizeof(fixed);
    const std::uint16_t v_type = 0;
    auto put16 = [&out](std::uint16_t v) {
        out.push_back(static_cast<std::uint8_t>(v));
        out.push_back(static_cast<std::uint8_t>(v >> 8));
    };
    put16(length);
    put16(v_len);
    put16(v_type);
    out.insert(out.end(), key.begin(), key.end());
    while (out.size() < value_off) {
        out.push_back(0);
    }
    const auto* fp = reinterpret_cast<const std::uint8_t*>(fixed);
    out.insert(out.end(), fp, fp + sizeof(fixed));
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> build_pe_with_version(
    const std::vector<std::uint8_t>& version) {
    std::vector<std::uint8_t> pe(0x400, 0);
    // DOS header: MZ, e_lfanew at 0x80.
    pe[0] = 'M';
    pe[1] = 'Z';
    const std::uint32_t pe_off = 0x80;
    std::memcpy(pe.data() + 0x3C, &pe_off, 4);
    // PE signature and COFF header.
    pe[pe_off] = 'P';
    pe[pe_off + 1] = 'E';
    pe[pe_off + 2] = 0;
    pe[pe_off + 3] = 0;
    const std::uint16_t machine = 0x8664;
    const std::uint16_t sections = 1;
    const std::uint16_t opt_size = 0xF0;
    std::memcpy(pe.data() + pe_off + 4, &machine, 2);
    std::memcpy(pe.data() + pe_off + 6, &sections, 2);
    std::memcpy(pe.data() + pe_off + 20, &opt_size, 2);
    // Optional header: PE32+ magic 0x20B, resource directory at RVA
    // kSectionRva, size.
    const std::size_t opt = pe_off + 24;
    const std::uint16_t magic = 0x20B;
    std::memcpy(pe.data() + opt, &magic, 2);
    const std::size_t dir = opt + 0x70 + 2 * 8;
    const std::uint32_t res_rva = kSectionRva;
    const std::uint32_t res_size = 0x100;  // the tree's size
    std::memcpy(pe.data() + dir, &res_rva, 4);
    std::memcpy(pe.data() + dir + 4, &res_size, 4);
    // Section header: ".rsrc", VA kSectionRva, raw kSectionRaw, 0x400.
    const std::size_t sec = opt + opt_size;
    std::memcpy(pe.data() + sec, ".rsrc", 6);
    const std::uint32_t raw_size = 0x400;
    std::memcpy(pe.data() + sec + 8, &raw_size, 4);
    std::memcpy(pe.data() + sec + 12, &kSectionRva, 4);
    std::memcpy(pe.data() + sec + 16, &raw_size, 4);
    std::memcpy(pe.data() + sec + 20, &kSectionRaw, 4);
    // The resource tree, at the section's raw offset. Root directory,
    // one named entry (RT_VERSION = 16) pointing to a level-2 directory,
    // which points to a level-3, which points at the data entry.
    std::size_t tree = kSectionRaw;
    auto put32 = [&pe](std::size_t at, std::uint32_t v) {
        std::memcpy(pe.data() + at, &v, 4);
    };
    put32(tree + 12, 0);  // named entries
    put32(tree + 14, 1);  // id entries
    // Entry 0: id 16 (RT_VERSION), offset to level 2, as a directory
    // reference (high bit).
    put32(tree + 16, 16);
    put32(tree + 20, 0x80000010);
    // Level 2 at tree+0x10.
    put32(tree + 0x10 + 12, 0);
    put32(tree + 0x10 + 14, 1);
    put32(tree + 0x10 + 16, 1);
    put32(tree + 0x10 + 20, 0x80000020);
    // Level 3 at tree+0x20; its one entry sits at +16, which is tree+0x30,
    // and points at the data entry that follows it.
    put32(tree + 0x20 + 12, 0);
    put32(tree + 0x20 + 14, 1);
    put32(tree + 0x20 + 16, 0x409);
    put32(tree + 0x20 + 20, 0x80000038);
    // Data entry at tree+0x38: RVA and size of the version data.
    // The tree sits at the section's own RVA, so the data's RVA is the
    // section RVA plus the data's offset into the tree.
    const std::uint32_t data_rva =
        kSectionRva + static_cast<std::uint32_t>(tree - kSectionRaw) + 0x40;
    put32(tree + 0x38, data_rva);
    put32(tree + 0x3C, static_cast<std::uint32_t>(version.size()));
    // The data, at tree+0x40.
    std::memcpy(pe.data() + tree + 0x40, version.data(), version.size());
    return pe;
}

void test_version_reads_the_file() {
    const std::vector<std::uint8_t> version = build_version_data();
    const std::vector<std::uint8_t> pe =
        build_pe_with_version(version);
    const char* path = "/tmp/occ_test_version.exe";
    const int fd = ::open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    check(fd >= 0, "version: the test file opens");
    if (fd >= 0) {
        const ssize_t wrote = ::write(fd, pe.data(), pe.size());
        (void)wrote;
        ::close(fd);
    }

    // The size probe answers the resource's own size.
    std::uint32_t handle = 0;
    std::u16string wide;
    static_cast<void>(utf8_to_utf16(std::string_view(path), wide));
    const std::uint32_t size =
        u32v_GetFileVersionInfoSizeW(wide.c_str(), &handle);
    check(size == version.size(),
          "version: the size probe answers the resource's size");

    // The read fills the buffer with the resource's bytes.
    std::vector<std::uint8_t> read(size + 16, 0);
    check(u32v_GetFileVersionInfoW(wide.c_str(), handle, size + 16,
                                   read.data()) == 1,
          "version: the read succeeds");
    check(std::memcmp(read.data(), version.data(), version.size()) == 0,
          "version: the bytes are the resource's");

    // The root query answers the fixed info, with the version numbers
    // the test wrote.
    void* value = nullptr;
    std::uint32_t len = 0;
    check(u32v_VerQueryValueW(read.data(), u"\\", &value, &len) == 1,
          "version: the root query answers");
    check(len >= 52, "version: the fixed info is its own length");
    std::uint32_t sig = 0;
    std::memcpy(&sig, value, 4);
    check(sig == 0xFEEF04BD, "version: the signature is the resource's");
    std::uint32_t ms = 0;
    std::memcpy(&ms, static_cast<std::uint8_t*>(value) + 8, 4);
    std::uint32_t ls = 0;
    std::memcpy(&ls, static_cast<std::uint8_t*>(value) + 12, 4);
    check(ms == 0x00020001 && ls == 0x00030004,
          "version: the file version is the resource's");

    // A file with no version resource is refused, with the error the
    // family sets for it.
    const char* none = "/tmp/occ_test_noversion.exe";
    const int fd2 = ::open(none, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd2 >= 0) {
        const ssize_t w = ::write(fd2, pe.data(), 0x80);
        (void)w;
        ::close(fd2);
    }
    std::u16string wide2;
    static_cast<void>(utf8_to_utf16(std::string_view(none), wide2));
    check(u32v_GetFileVersionInfoSizeW(wide2.c_str(), &handle) == 0,
          "version: a file with no resource is refused");
    ::unlink(path);
    ::unlink(none);
}

void test_language_names() {
    char16_t name[64] = {};
    check(u32v_VerLanguageNameW(0x0409, name, 64) > 0,
          "version: the US English id names itself");
    std::string narrow;
    static_cast<void>(utf16_to_utf8(std::u16string_view(name), narrow));
    check(narrow.find("English") != std::string::npos,
          "version: the name is English");
}

}  // namespace

int main() {
    test_psapi_registry();
    test_enum_processes_and_modules();
    test_memory_and_performance();
    test_version_reads_the_file();
    test_language_names();
    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

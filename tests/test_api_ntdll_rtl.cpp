// The NTDLL Rtl surface: version, image-header and directory answers.
//
// `RtlGetVersion`, `RtlGetNtVersionNumbers`, `RtlImageNtHeader` and
// `RtlImageDirectoryEntryToData` are the Rtl* calls a packer, a
// version-gate or a loader probe makes first. The test resolves them
// through the domain table and drives real behaviour: the version
// record's size field is respected, the NT build number carries its
// high bit, and the image-header calls parse an actual PE buffer.

#include "occ/runtime/address_space.h"
#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/exports.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

namespace occ::runtime::winabi {
void add_ntdll_rtl_mem2(ExportList& out);
}  // namespace occ::runtime::winabi

namespace {

// Registers a buffer as a mapped image region for the duration of the
// scope, so the PE walkers bound themselves against it the way they
// bound against a loaded guest. The previous guest state is restored on
// the way out; a test that left it installed would answer the next
// test's questions about a buffer that is no longer there.
class ScopedImageRegion {
public:
    ScopedImageRegion(void* base, std::size_t size) {
        space_.reset(new occ::runtime::AddressSpace());
        const occ::runtime::Result<std::uint64_t> recorded =
            space_->record(reinterpret_cast<std::uint64_t>(base), size,
                           occ::runtime::PageProtection::ReadOnly,
                           occ::runtime::RegionKind::Image);
        if (!recorded.ok()) {
            return;
        }
        state_ = new occ::runtime::winabi::GuestState();
        state_->space = space_.get();
        previous_ = guest_state();
        set_guest_state(state_);
        held_ = true;
    }

    ~ScopedImageRegion() {
        if (!held_) {
            delete state_;
            return;
        }
        set_guest_state(previous_);
        delete state_;
    }

    ScopedImageRegion(const ScopedImageRegion&) = delete;
    ScopedImageRegion& operator=(const ScopedImageRegion&) = delete;

private:
    std::unique_ptr<occ::runtime::AddressSpace> space_;
    occ::runtime::winabi::GuestState* state_ = nullptr;
    occ::runtime::winabi::GuestState* previous_ = nullptr;
    bool held_ = false;
};

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

constexpr std::uint32_t kStSuccess = 0x00000000;
constexpr std::uint32_t kStInvalidParameter = 0xC000000D;

// The base OSVERSIONINFOW record: five 32-bit fields plus a 128-wide
// char16_t CSD string.
struct OsVersionInfo {
    std::uint32_t size = 0;
    std::uint32_t major = 0;
    std::uint32_t minor = 0;
    std::uint32_t build = 0;
    std::uint32_t platform = 0;
    char16_t csd[128] = {};
};
static_assert(sizeof(OsVersionInfo) == 20 + 128 * 2,
              "OSVERSIONINFOW layout");

// A minimal PE image buffer for the header queries: DOS stub, PE
// signature, COFF and a short optional header with one data directory.
struct PeBuffer {
    std::uint8_t data[0x2000] = {};
    PeBuffer() {
        data[0] = 'M';
        data[1] = 'Z';
        const std::uint32_t lfanew = 0x40;
        data[0x3C] = static_cast<std::uint8_t>(lfanew);
        data[0x3D] = static_cast<std::uint8_t>(lfanew >> 8);
        data[0x3E] = static_cast<std::uint8_t>(lfanew >> 16);
        data[0x3F] = static_cast<std::uint8_t>(lfanew >> 24);
        std::uint8_t* pe = data + lfanew;
        pe[0] = 'P';
        pe[1] = 'E';
        pe[2] = 0;
        pe[3] = 0;
        // COFF: machine, one section, 0xF0 optional header.
        const std::uint16_t machine = 0x8664;
        pe[4] = static_cast<std::uint8_t>(machine);
        pe[5] = static_cast<std::uint8_t>(machine >> 8);
        const std::uint16_t opt = 0xF0;
        pe[20] = static_cast<std::uint8_t>(opt);
        pe[21] = static_cast<std::uint8_t>(opt >> 8);
        // Optional header at pe+24: magic PE32+.
        std::uint8_t* oh = pe + 24;
        oh[0] = 0x0B;
        oh[1] = 0x02;
        // Number of data directories = 16 (PE32+ offset 0x6C).
        const std::uint32_t ndirs = 16;
        oh[0x6C] = static_cast<std::uint8_t>(ndirs);
        oh[0x6D] = static_cast<std::uint8_t>(ndirs >> 8);
        oh[0x6E] = static_cast<std::uint8_t>(ndirs >> 16);
        oh[0x6F] = static_cast<std::uint8_t>(ndirs >> 24);
        // Directory 0 (exports): VA 0x1000, size 0x80.
        std::uint8_t* dir = oh + 0x70;
        const std::uint32_t dva = 0x1000, dsz = 0x80;
        dir[0] = static_cast<std::uint8_t>(dva);
        dir[1] = static_cast<std::uint8_t>(dva >> 8);
        dir[2] = static_cast<std::uint8_t>(dva >> 16);
        dir[3] = static_cast<std::uint8_t>(dva >> 24);
        dir[4] = static_cast<std::uint8_t>(dsz);
        dir[5] = static_cast<std::uint8_t>(dsz >> 8);
        dir[6] = static_cast<std::uint8_t>(dsz >> 16);
        dir[7] = static_cast<std::uint8_t>(dsz >> 24);
        // Bytes at 0x1000 so RtlImageRvaToVa lands somewhere real.
        data[0x1000] = 0xAB;
    }
};

void test_version_behaviour() {
    using GetVersionFn = std::uint32_t(__attribute__((ms_abi)) *)(void*);
    using GetNtVerFn = void(__attribute__((ms_abi)) *)(
        std::uint32_t*, std::uint32_t*, std::uint32_t*);

    // RtlGetVersion: the caller declares its record size; the answer
    // honours it.
    OsVersionInfo info;
    info.size = sizeof(info);
    check(fn<GetVersionFn>("RtlGetVersion")(&info) == kStSuccess,
          "rtl: RtlGetVersion succeeds");
    check(info.size == sizeof(info),
          "rtl: the size field is rewritten with the written size");
    check(info.major == 10, "rtl: major version is 10");
    check(info.minor == 0, "rtl: minor version is 0");
    check(info.build == 19045, "rtl: build is 19045");
    check(info.platform == 2, "rtl: platform is VER_PLATFORM_WIN32_NT");
    check(info.csd[0] == u'\0', "rtl: no service pack is reported");

    // A declared size smaller than the base record is refused.
    info.size = 8;
    check(fn<GetVersionFn>("RtlGetVersion")(&info) == kStInvalidParameter,
          "rtl: undersized record refused");

    // Null is refused.
    check(fn<GetVersionFn>("RtlGetVersion")(nullptr) == kStInvalidParameter,
          "rtl: null record refused");

    // RtlGetNtVersionNumbers: the NT build carries its high bit.
    std::uint32_t major = 0, minor = 0, build = 0;
    fn<GetNtVerFn>("RtlGetNtVersionNumbers")(&major, &minor, &build);
    check(major == 10, "rtl: NT version major is 10");
    check(minor == 0, "rtl: NT version minor is 0");
    check((build & 0xF0000000u) != 0, "rtl: NT build has its high bit set");
}

void test_image_header_behaviour() {
    using NtHeaderFn = void*(__attribute__((ms_abi)) *)(const void*);
    using DirFn = void*(__attribute__((ms_abi)) *)(void*, std::uint8_t,
                                                   std::uint16_t,
                                                   std::uint32_t*);

    PeBuffer pe;

    // The header walkers only answer for memory the runtime knows is the
    // guest's -- a mapped image region -- which is the contract the test
    // must honour rather than bypass.
    ScopedImageRegion region(pe.data, sizeof(pe.data));

    // RtlImageNtHeader returns the PE header.
    void* nt = fn<NtHeaderFn>("RtlImageNtHeader")(pe.data);
    check(nt != nullptr, "rtl: RtlImageNtHeader finds the PE header");
    if (nt != nullptr) {
        const auto* b = static_cast<const std::uint8_t*>(nt);
        check(b[0] == 'P' && b[1] == 'E' && b[2] == 0 && b[3] == 0,
              "rtl: the returned header is the PE signature");
    }
    // A non-image buffer is refused.
    std::uint8_t junk[0x100] = {};
    check(fn<NtHeaderFn>("RtlImageNtHeader")(junk) == nullptr,
          "rtl: non-image buffer refused");

    // RtlImageDirectoryEntryToData reads directory 0 with its size.
    std::uint32_t dir_size = 0;
    void* dir = fn<DirFn>("RtlImageDirectoryEntryToData")(
        pe.data, 1, 0, &dir_size);
    check(dir != nullptr, "rtl: export directory resolved");
    check(dir_size == 0x80, "rtl: directory size reported");
    // An index past the declared count is refused.
    void* dir2 = fn<DirFn>("RtlImageDirectoryEntryToData")(pe.data, 1, 16,
                                                           &dir_size);
    check(dir2 == nullptr, "rtl: out-of-range directory index refused");
}

}  // namespace

int main() {
    add_ntdll_rtl_mem2(g_exports);
    test_version_behaviour();
    test_image_header_behaviour();
    if (failures != 0) {
        std::fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    std::printf("%d checks, 0 failures\n", checks);
    return 0;
}

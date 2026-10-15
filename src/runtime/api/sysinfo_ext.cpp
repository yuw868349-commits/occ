// The system-information and code-page family a probe reads a machine
// with: the firmware table an anti-VM check walks, the version a program
// gates its behaviour on, the locale id a regional branch branches on, and
// the OEM text conversions a console program shuffles between.
//
// The firmware answer is the host's own: the SMBIOS tables this machine
// exposes through the kernel's DMI interface are read and handed to the
// guest, so a guest that scans the tables for a virtual-machine signature
// reads the same tables it would read on Windows. A host with no DMI
// interface answers the way Windows answers a machine with no firmware
// table: zero and `ERROR_INVALID_FUNCTION`.
//
// The version is the one this runtime presents elsewhere: the PEB is built
// with a Windows 10 major version, and `GetVersionEx` answers the same
// numbers, so a program that gates on the version and one that reads the
// PEB agree about what Windows this is.
//
// The code-page conversions are the host's own `iconv`, which is part of
// the C library rather than a third-party dependency: the ANSI text this
// runtime keeps is UTF-8, the OEM code page is the DOS character set the
// console used, and the two meet where Windows meets them.

#include "occ/runtime/api_common.h"
#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <iconv.h>
#include <sys/stat.h>
#include <unistd.h>

namespace occ::runtime::winabi {
namespace {

// The layout of OSVERSIONINFOA, 148 bytes in the guest's memory. The size
// field is the one a caller must set before the call, and the service-pack
// string is the tail of the record.
constexpr std::size_t kOviSize = 0;
constexpr std::size_t kOviMajor = 4;
constexpr std::size_t kOviMinor = 8;
constexpr std::size_t kOviBuild = 12;
constexpr std::size_t kOviPlatform = 16;
constexpr std::size_t kOviCsd = 20;
constexpr std::size_t kOviBytes = 148;

// `VER_PLATFORM_WIN32_NT`, the platform id of every modern Windows.
constexpr std::uint32_t kPlatformWin32Nt = kReportedPlatformId;

// The version this runtime presents: the same numbers the PEB carries, so
// the two views of "what Windows is this" agree.
// The numbers themselves live in `api.h`, because `GetVersion` and the
// version-verification call answer with the same ones.
constexpr std::uint32_t kOsMajor = kReportedOsMajor;
constexpr std::uint32_t kOsMinor = kReportedOsMinor;
constexpr std::uint32_t kOsBuild = kReportedOsBuild;

// `GetSystemFirmwareTable`'s provider signature for the SMBIOS table set.
constexpr std::uint32_t kFirmwareProviderSmbios = 0x52534D42u;  // 'RSMB'

// Reads the host's raw SMBIOS tables. The kernel exposes them as one blob
// at this path on a machine with a firmware table at all; a machine or a
// container without one has no file, which is the "no firmware" answer.
[[nodiscard]] bool read_smbios(std::string& out) noexcept {
    static constexpr const char* kDmiPath = "/sys/firmware/dmi/tables/DMI";
    struct stat st;
    if (::stat(kDmiPath, &st) != 0 || st.st_size <= 0) {
        return false;
    }
    std::string data;
    data.resize(static_cast<std::size_t>(st.st_size));
    const int fd = ::open(kDmiPath, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    const ::ssize_t got = ::read(fd, data.data(), data.size());
    ::close(fd);
    if (got <= 0) {
        return false;
    }
    data.resize(static_cast<std::size_t>(got));
    out = std::move(data);
    return true;
}

// The LCID for the host's locale, as far as a short mapping reaches. A
// locale the mapping does not name is answered with the US id, which is the
// default a Windows installation without a regional setting uses.
[[nodiscard]] std::uint32_t locale_id_of_host() noexcept {
    const char* lang = std::getenv("LANG");
    if (lang == nullptr) {
        return 0x0409;
    }
    if (std::strncmp(lang, "zh_CN", 5) == 0) {
        return 0x0804;
    }
    if (std::strncmp(lang, "zh_TW", 5) == 0 || std::strncmp(lang, "zh_HK", 5) == 0) {
        return 0x0404;
    }
    if (std::strncmp(lang, "ja_JP", 5) == 0) {
        return 0x0411;
    }
    if (std::strncmp(lang, "ko_KR", 5) == 0) {
        return 0x0412;
    }
    if (std::strncmp(lang, "en_", 3) == 0 || std::strncmp(lang, "C", 1) == 0) {
        return 0x0409;
    }
    return 0x0409;
}

// One text conversion through the host's own iconv. `from` and `to` name
// the character sets; a conversion the host cannot perform leaves the text
// unchanged, which is the fallback a console on a machine without the code
// page gets from Windows too.
[[nodiscard]] bool convert_text(const char* from, const char* to,
                                const char* in, char* out,
                                std::size_t out_capacity) noexcept {
    if (in == nullptr || out == nullptr || out_capacity == 0) {
        return false;
    }
    iconv_t cd = ::iconv_open(to, from);
    if (cd == reinterpret_cast<iconv_t>(-1)) {
        return false;
    }
    std::size_t in_left = std::strlen(in) + 1;
    std::size_t out_left = out_capacity;
    char* in_ptr = const_cast<char*>(in);
    char* out_ptr = out;
    const std::size_t rc = ::iconv(cd, &in_ptr, &in_left, &out_ptr, &out_left);
    ::iconv_close(cd);
    if (rc == static_cast<std::size_t>(-1)) {
        // An untranslatable byte in the middle. The half that made it is
        // kept and the tail is copied through, so a console line with one
        // odd byte still reaches the screen.
        const std::size_t copy =
            std::min(in_left, out_left);
        std::memcpy(out_ptr, in_ptr, copy);
        out_ptr += copy;
        out_capacity -= static_cast<std::size_t>(out_ptr - out);
        if (out_capacity > 0) {
            out_ptr[0] = '\0';
        }
        return true;
    }
    return true;
}

}  // namespace

// The firmware table a guest asks for. The only table set this runtime can
// answer is the SMBIOS set, and the host's own DMI blob is the answer: the
// bytes the guest walks are the bytes this machine's firmware reported.
extern "C" __attribute__((ms_abi)) std::uint32_t k32si_GetSystemFirmwareTable(
    std::uint32_t provider, std::uint32_t id, void* buffer,
    std::uint32_t size) noexcept {
    static_cast<void>(id);
    if (provider != kFirmwareProviderSmbios) {
        set_last_error(kErrorInvalidFunction);
        return 0;
    }
    std::string blob;
    if (!read_smbios(blob)) {
        set_last_error(kErrorInvalidFunction);
        return 0;
    }
    const std::uint32_t needed = static_cast<std::uint32_t>(blob.size());
    if (buffer == nullptr || size < needed) {
        // The size the caller would need, which is the size a first call
        // with a null buffer is answered with. Windows does not set an
        // error for the too-small case; the size is the answer.
        return needed;
    }
    std::memcpy(buffer, blob.data(), blob.size());
    set_last_error(0);
    return needed;
}

// The version record. The caller writes the record's size first, the call
// fills the rest, and the numbers are the ones this runtime presents
// everywhere else.
extern "C" __attribute__((ms_abi)) std::int32_t k32si_GetVersionExA(
    std::uint8_t* info) noexcept {
    if (info == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    const std::uint32_t size = read_u32(info, kOviSize);
    if (size < kOviBytes) {
        set_last_error(kErrorInsufficientBuffer);
        return 0;
    }
    write_u32(info, kOviMajor, kOsMajor);
    write_u32(info, kOviMinor, kOsMinor);
    write_u32(info, kOviBuild, kOsBuild);
    write_u32(info, kOviPlatform, kPlatformWin32Nt);
    std::memset(info + kOviCsd, 0, kOviBytes - kOviCsd);
    set_last_error(0);
    return 1;
}

// The locale id of the system default. The host's locale is the closest
// thing a single-process runtime has to a system default, and the mapping
// above is the translation.
extern "C" __attribute__((ms_abi)) std::uint32_t k32si_GetSystemDefaultLCID(
    void) noexcept {
    return locale_id_of_host();
}

// Converts ANSI text to the OEM code page, in place when the two pointers
// are the same. The conversion is the host's, so the bytes a console
// program writes are the bytes this machine's character set produces.
extern "C" __attribute__((ms_abi)) std::int32_t k32si_CharToOemA(
    const char* source, char* destination) noexcept {
    if (source == nullptr || destination == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    if (source == destination) {
        // In place: the input is consumed as it is converted, so the copy
        // is made first and the conversion runs over the copy.
        std::string copy(source);
        char* tmp = new char[copy.size() + 1];
        const bool ok =
            convert_text("UTF-8", "CP437", copy.c_str(), tmp, copy.size() + 1);
        if (!ok) {
            delete[] tmp;
            set_last_error(kErrorInvalidParameter);
            return 0;
        }
        std::strcpy(destination, tmp);
        delete[] tmp;
        return 1;
    }
    std::string copy(source);
    if (!convert_text("UTF-8", "CP437", copy.c_str(), destination,
                      copy.size() + 1)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return 1;
}

// The inverse conversion: OEM text back to the ANSI code page.
extern "C" __attribute__((ms_abi)) std::int32_t k32si_OemToCharA(
    const char* source, char* destination) noexcept {
    if (source == nullptr || destination == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string copy(source);
    if (!convert_text("CP437", "UTF-8", copy.c_str(), destination,
                      copy.size() * 2 + 1)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    return 1;
}

void add_kernel32_sysinfo_ext(ExportList& out) {
    const auto e = [](const char* n, void* fn) {
        HostExport entry;
        entry.name = n;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        return entry;
    };
    out.push_back(e("GetSystemFirmwareTable",
                    reinterpret_cast<void*>(&k32si_GetSystemFirmwareTable)));
    out.push_back(e("GetVersionExA",
                    reinterpret_cast<void*>(&k32si_GetVersionExA)));
    out.push_back(e("GetSystemDefaultLCID",
                    reinterpret_cast<void*>(&k32si_GetSystemDefaultLCID)));
    out.push_back(e("CharToOemA",
                    reinterpret_cast<void*>(&k32si_CharToOemA)));
    out.push_back(e("OemToCharA",
                    reinterpret_cast<void*>(&k32si_OemToCharA)));
}

}  // namespace occ::runtime::winabi

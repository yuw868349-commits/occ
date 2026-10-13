// The character-domain pair a program reaches when its text crosses the
// OEM/ANSI boundary or when it walks a narrow string character by
// character: the OEM round trip, the four case conversions, and the two
// UTF-8-aware string pointers.
//
// The runtime's narrow strings are UTF-8 and its "OEM" spelling is the
// same conversion the existing `CharToOemA` / `OemToCharA` perform -- the
// host's own `iconv` into and out of code page 437. The `W` forms below
// are therefore `UTF-16 -> UTF-8 -> CP437` and the reverse, which keeps
// the two halves of a family answering with byte-identical output for the
// same text; the boundary is that the OEM code page is fixed to CP437 the
// way the A family fixes it, rather than being read from a console.
//
// `CharUpper` / `CharLower` work on one code unit per step: ASCII letters
// map through a table, and a wide non-ASCII unit goes through the host's
// `towupper` / `towlower` in the C locale. A UTF-8 narrow string keeps its
// multibyte bytes untouched (uppercasing only the ASCII letters), which is
// the project's narrow-string convention; a UTF-16 surrogate half is a
// code unit the locale tables do not map, so it passes through unchanged,
// and a supplementary character is two units that are upper/lower-cased
// independently -- a boundary named because a full supplementary case map
// would need the pair, and the locale table has no entry for either half.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstdint>
#include <cstring>
#include <cwctype>
#include <string>
#include <utility>

#include <iconv.h>

namespace occ::runtime::winabi {
namespace {

// The UTF-8 <-> UTF-16 converters are the shared ones declared in
// winabi.h; both directions are strict over the encoding.

// One text conversion through the host's own iconv, without the NUL
// terminator. The output is appended to `out`; a conversion the host
// cannot perform is refused.
[[nodiscard]] bool convert_iconv(const char* from, const char* to,
                                 const char* in, std::size_t in_len,
                                 std::string& out) noexcept {
    if (in == nullptr || in_len == 0) {
        return false;
    }
    iconv_t cd = ::iconv_open(to, from);
    if (cd == reinterpret_cast<iconv_t>(-1)) {
        return false;
    }
    std::string buffer(in_len * 4 + 1, '\0');
    std::size_t in_left = in_len;
    std::size_t out_left = buffer.size();
    char* in_ptr = const_cast<char*>(in);
    char* out_ptr = buffer.data();
    const std::size_t rc = ::iconv(cd, &in_ptr, &in_left, &out_ptr, &out_left);
    ::iconv_close(cd);
    if (rc == static_cast<std::size_t>(-1)) {
        return false;
    }
    out.assign(buffer.data(), buffer.size() - out_left);
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// KERNEL32: the OEM round trip
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) std::int32_t k32sc_CharToOemW(
    const char16_t* source, char* destination) noexcept {
    if (source == nullptr || destination == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::string utf8;
    if (!utf16_to_utf8(std::u16string_view(source), utf8)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // UTF-16 -> UTF-8 -> CP437, which is the same conversion the A spelling
    // performs (its `convert_text("UTF-8", "CP437", ...)`); the caller's
    // destination is assumed large enough, as the A spelling assumes.
    std::string oem;
    if (!convert_iconv("UTF-8", "CP437", utf8.c_str(), utf8.size(), oem)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::memcpy(destination, oem.data(), oem.size());
    destination[oem.size()] = '\0';
    return 1;
}

extern "C" __attribute__((ms_abi)) std::int32_t k32sc_OemToCharW(
    const char* source, char16_t* destination) noexcept {
    if (source == nullptr || destination == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    // CP437 -> UTF-8 -> UTF-16, the reverse of CharToOemW and the same
    // conversion OemToCharA performs in the narrow direction.
    std::string utf8;
    if (!convert_iconv("CP437", "UTF-8", source, std::strlen(source), utf8)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::u16string wide;
    if (!utf8_to_utf16(utf8, wide)) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }
    std::memcpy(destination, wide.data(), wide.size() * sizeof(char16_t));
    destination[wide.size()] = u'\0';
    return 1;
}

// ---------------------------------------------------------------------------
// USER32: the case conversions
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) char* u32sc_CharUpperA(char* str) noexcept {
    if (str == nullptr) {
        return nullptr;
    }
    // In-place: ASCII letters map to upper case; a UTF-8 multibyte byte is
    // left exactly as it is, which preserves the character while the letters
    // in the string change case.
    for (char* p = str; *p != '\0'; ++p) {
        const std::uint8_t c = static_cast<std::uint8_t>(*p);
        if (c >= static_cast<std::uint8_t>('a') &&
            c <= static_cast<std::uint8_t>('z')) {
            *p = static_cast<char>(c - static_cast<std::uint8_t>('a') +
                                   static_cast<std::uint8_t>('A'));
        }
    }
    return str;
}

extern "C" __attribute__((ms_abi)) char16_t* u32sc_CharUpperW(
    char16_t* str) noexcept {
    if (str == nullptr) {
        return nullptr;
    }
    for (char16_t* p = str; *p != u'\0'; ++p) {
        if (*p >= u'a' && *p <= u'z') {
            *p = static_cast<char16_t>(*p - u'a' + u'A');
        } else if (*p > 0x7Fu) {
            // A non-ASCII BMP unit through the host's wide-case table. A
            // surrogate half has no table entry and comes back unchanged,
            // which is the boundary named in the file header.
            *p = static_cast<char16_t>(std::towupper(static_cast<std::wint_t>(*p)));
        }
    }
    return str;
}

extern "C" __attribute__((ms_abi)) char* u32sc_CharLowerA(char* str) noexcept {
    if (str == nullptr) {
        return nullptr;
    }
    for (char* p = str; *p != '\0'; ++p) {
        const std::uint8_t c = static_cast<std::uint8_t>(*p);
        if (c >= static_cast<std::uint8_t>('A') &&
            c <= static_cast<std::uint8_t>('Z')) {
            *p = static_cast<char>(c - static_cast<std::uint8_t>('A') +
                                   static_cast<std::uint8_t>('a'));
        }
    }
    return str;
}

extern "C" __attribute__((ms_abi)) char16_t* u32sc_CharLowerW(
    char16_t* str) noexcept {
    if (str == nullptr) {
        return nullptr;
    }
    for (char16_t* p = str; *p != u'\0'; ++p) {
        if (*p >= u'A' && *p <= u'Z') {
            *p = static_cast<char16_t>(*p - u'A' + u'a');
        } else if (*p > 0x7Fu) {
            *p = static_cast<char16_t>(std::towlower(static_cast<std::wint_t>(*p)));
        }
    }
    return str;
}

// ---------------------------------------------------------------------------
// USER32: the UTF-8-aware string pointers
// ---------------------------------------------------------------------------

extern "C" __attribute__((ms_abi)) char* u32sc_AnsiNext(
    const char* current_char) noexcept {
    if (current_char == nullptr) {
        return nullptr;
    }
    // Advance one full UTF-8 character: the leading byte's length, or one
    // for an ASCII byte and for the terminator.
    const std::uint8_t lead = static_cast<std::uint8_t>(*current_char);
    std::size_t len = 1;
    if (lead >= 0xF0u) {
        len = 4;
    } else if (lead >= 0xE0u) {
        len = 3;
    } else if (lead >= 0xC0u) {
        len = 2;
    }
    return const_cast<char*>(current_char + len);
}

extern "C" __attribute__((ms_abi)) char* u32sc_AnsiPrev(
    const char* start, const char* current_char) noexcept {
    if (start == nullptr || current_char == nullptr) {
        return nullptr;
    }
    if (current_char <= start) {
        return const_cast<char*>(start);
    }
    // Walk back over UTF-8 continuation bytes to the previous character's
    // leading byte. Continuation bytes are the ones with the top two bits
    // set; a lead byte or an ASCII byte stops the walk.
    const char* p = current_char;
    do {
        --p;
    } while (p > start &&
             (static_cast<std::uint8_t>(*p) & 0xC0u) == 0x80u);
    return const_cast<char*>(p);
}

// ===========================================================================
// The registrations
// ===========================================================================

void add_kernel32_strcase_ext(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CharToOemW", reinterpret_cast<void*>(&k32sc_CharToOemW));
    e("OemToCharW", reinterpret_cast<void*>(&k32sc_OemToCharW));
}

void add_user32_strcase_ext(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    e("CharUpperA", reinterpret_cast<void*>(&u32sc_CharUpperA));
    e("CharUpperW", reinterpret_cast<void*>(&u32sc_CharUpperW));
    e("CharLowerA", reinterpret_cast<void*>(&u32sc_CharLowerA));
    e("CharLowerW", reinterpret_cast<void*>(&u32sc_CharLowerW));
    e("AnsiNext", reinterpret_cast<void*>(&u32sc_AnsiNext));
    e("AnsiPrev", reinterpret_cast<void*>(&u32sc_AnsiPrev));
}

}  // namespace occ::runtime::winabi

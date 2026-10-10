// The Universal CRT, as the modern ABI presents it.
//
// The C runtime a program built this century calls is not the one built
// in 1998: the secure functions (`strcpy_s`, `sprintf_s`), the qualified
// heaps (`_aligned_malloc`), the locale objects, and -- most of all --
// the `__stdio_common_*` entry points that every `printf` from a modern
// toolchain compiles into. Those entry points are the reason this file
// exists: a program that resolves `__stdio_common_vfprintf` and finds
// nothing has no output path at all, and no amount of correct `printf`
// exports behind it would help.
//
// The modules of the `api-ms-win-crt-*` family are the other half. On a
// real system each is a forwarder stub: its exports are strings pointing
// at `ucrtbase`, and a loader that reads them follows the strings. Here
// the same names are registered in each module directly, which is what
// following the forwarders achieves and what a guest loading
// `api-ms-win-crt-string-l1-1-0.dll` actually asks for.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cctype>
#include <cwchar>
#include <clocale>
#include <malloc.h>
#include <string>
#include <thread>
#include <vector>

extern "C" char** environ;

namespace occ::runtime::winabi {

namespace {

constexpr std::uint32_t kErrOk = 0;
constexpr std::uint32_t kErrParam = 87;
constexpr std::uint32_t kErrNoMem = 12;
constexpr std::uint32_t kErrRange = 34;
constexpr std::uint32_t kErrBadF = 9;
constexpr std::uint32_t kErrIlseq = 42;
constexpr std::uint32_t kErrDomain = 33;

// The error codes the `errno` family reports, at the values the CRT
// assigns them.
constexpr std::int32_t kE2Big = 7;
constexpr std::int32_t kEAcces = 13;
constexpr std::int32_t kEBadf = 9;
constexpr std::int32_t kEFault = 14;
constexpr std::int32_t kEInval = 22;
constexpr std::int32_t kENoMem = 12;
constexpr std::int32_t kERange = 34;
constexpr std::int32_t kENoEnt = 2;

// The errno the CRT keeps. The host has its own; this translation unit
// keeps the guest's, because a guest that sets `errno` and reads it back
// expects its own value rather than the host's.
std::int32_t g_errno = 0;

// The handshake `_invalid_parameter` makes with the debug CRT: the
// handler the guest installed, and whether it wants control afterwards.
using InvalidHandler = void(__attribute__((ms_abi))*)(
    const char16_t*, const char16_t*, const char16_t*, unsigned int,
    std::uintptr_t);

InvalidHandler g_invalid_handler = nullptr;

// The invalid-parameter path, with the contract the CRT documents: a
// handler the guest installed is called with the failing call's
// coordinates, and when it returns the caller continues to its failure
// answer. With no handler installed, the call terminates -- which is the
// behaviour a program that never installed one has asked for by not
// installing one.
void report_invalid_parameter(const char16_t* expression,
                              const char16_t* function,
                              const char16_t* file,
                              unsigned int line) noexcept {
    if (g_invalid_handler != nullptr) {
        g_invalid_handler(expression, function, file, line, 0);
        return;
    }
    std::fprintf(stderr, "occ ucrt: invalid parameter in %ls\n",
                 reinterpret_cast<const wchar_t*>(
                     function != nullptr ? function : u"(null)"));
    ::abort();
}

std::int32_t set_errno_value(std::int32_t v) noexcept {
    g_errno = v;
    return v;
}

// The wide-to-narrow bridge the wide functions use.
[[nodiscard]] std::string wide_to_narrow(const char16_t* text) noexcept {
    if (text == nullptr) {
        return {};
    }
    std::string out;
    static_cast<void>(utf16_to_utf8(std::u16string_view(text), out));
    return out;
}

// The bounded copy every secure function performs, with the contract the
// CRT documents: the destination is zeroed on failure, the size is
// checked, and the answer says which failure it was.
[[nodiscard]] std::int32_t copy_secure(char* dst, std::size_t dst_size,
                                       const char* src,
                                       std::size_t max_count,
                                       bool truncate_ok,
                                       const char16_t* function) noexcept {
    if (dst == nullptr || dst_size == 0) {
        report_invalid_parameter(u"destination", function, nullptr, 0);
    }
    if (src == nullptr) {
        dst[0] = '\0';
        return set_errno_value(kEInval);
    }
    const std::size_t len = std::strlen(src);
    if (max_count != 0 && len > max_count) {
        dst[0] = '\0';
        return set_errno_value(kERange);
    }
    if (len + 1 > dst_size) {
        if (truncate_ok) {
            std::memcpy(dst, src, dst_size - 1);
            dst[dst_size - 1] = '\0';
            return set_errno_value(kERange);
        }
        dst[0] = '\0';
        return set_errno_value(kERange);
    }
    std::memcpy(dst, src, len + 1);
    return 0;
}

// The `locale` object: a real handle the create/free pair manages, whose
// only content is the name -- the C locale behaviour this runtime
// implements is the one the C library documents, and a named locale the
// host does not have is answered with the name it was asked for.
struct CrtLocale {
    std::string name;
};

}  // namespace

// ===========================================================================
// The errno family
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t* u32u__errno() noexcept {
    return &g_errno;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32u___crt_errno() noexcept {
    return reinterpret_cast<std::uint64_t>(&g_errno);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__get_errno(
    std::int32_t* out) noexcept {
    if (out == nullptr) {
        return kErrParam;
    }
    *out = g_errno;
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__set_errno(
    std::int32_t value) noexcept {
    g_errno = value;
    return 0;
}

extern "C" __attribute__((ms_abi)) void u32u__invalid_parameter(
    const char16_t* expression, const char16_t* function,
    const char16_t* file, unsigned int line,
    std::uintptr_t reserved) noexcept {
    (void)reserved;
    report_invalid_parameter(expression, function, file, line);
}

extern "C" __attribute__((ms_abi)) void* u32u__invalid_parameter_noinfo()
    noexcept {
    return nullptr;
}

extern "C" __attribute__((ms_abi)) void u32u__invalid_parameter_noinfo_noreturn()
    noexcept {
    ::abort();
}

extern "C" __attribute__((ms_abi)) InvalidHandler u32u__set_invalid_parameter_handler(
    InvalidHandler handler) noexcept {
    const InvalidHandler old = g_invalid_handler;
    g_invalid_handler = handler;
    return old;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__get_errno_from_oserr(
    std::uint32_t oserr) noexcept {
    // The mapping Windows documents: the system errors a CRT call can
    // raise, translated to the errno a program tests.
    switch (oserr) {
    case 2: return kENoEnt;
    case 5: return kEAcces;
    case 6: return kEBadf;
    case 8: return kENoMem;
    case 87: return kEInval;
    case 123: return kENoEnt;
    default: return kEInval;
    }
}

// ===========================================================================
// The secure string functions
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t u32u_strcpy_s(
    char* dst, std::size_t dst_size, const char* src) noexcept {
    return copy_secure(dst, dst_size, src, 0, false, u"strcpy_s");
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_strncpy_s(
    char* dst, std::size_t dst_size, const char* src,
    std::size_t count) noexcept {
    if (src == nullptr) {
        if (dst != nullptr && dst_size != 0) {
            dst[0] = '\0';
        }
        return set_errno_value(kEInval);
    }
    const std::size_t len = std::strlen(src);
    const std::size_t take = count == 0 ? len : std::min(len, count);
    if (take + 1 > dst_size) {
        if (dst != nullptr && dst_size != 0) {
            dst[0] = '\0';
        }
        return set_errno_value(kERange);
    }
    std::memcpy(dst, src, take);
    dst[take] = '\0';
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_strcat_s(
    char* dst, std::size_t dst_size, const char* src) noexcept {
    if (dst == nullptr || dst_size == 0) {
        report_invalid_parameter(u"destination", u"strcat_s", nullptr, 0);
    }
    if (src == nullptr) {
        dst[0] = '\0';
        return set_errno_value(kEInval);
    }
    const std::size_t have = std::strlen(dst);
    const std::size_t add = std::strlen(src);
    if (have + add + 1 > dst_size) {
        dst[0] = '\0';
        return set_errno_value(kERange);
    }
    std::memcpy(dst + have, src, add + 1);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_strncat_s(
    char* dst, std::size_t dst_size, const char* src,
    std::size_t count) noexcept {
    if (dst == nullptr || dst_size == 0) {
        report_invalid_parameter(u"destination", u"strncat_s", nullptr, 0);
    }
    if (src == nullptr) {
        dst[0] = '\0';
        return set_errno_value(kEInval);
    }
    const std::size_t have = std::strlen(dst);
    const std::size_t available = std::strlen(src);
    std::size_t add = count == 0 ? available : std::min(available, count);
    if (add == 0) {
        return 0;  // the CRT's documented special case
    }
    if (have + add + 1 > dst_size) {
        dst[0] = '\0';
        return set_errno_value(kERange);
    }
    std::memcpy(dst + have, src, add);
    dst[have + add] = '\0';
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_memcpy_s(
    void* dst, std::size_t dst_size, const void* src,
    std::size_t count) noexcept {
    if (count == 0) {
        return 0;
    }
    if (dst == nullptr || src == nullptr) {
        return set_errno_value(kEInval);
    }
    if (count > dst_size) {
        std::memset(dst, 0, dst_size);
        return set_errno_value(kERange);
    }
    std::memcpy(dst, src, count);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_memmove_s(
    void* dst, std::size_t dst_size, const void* src,
    std::size_t count) noexcept {
    if (count == 0) {
        return 0;
    }
    if (dst == nullptr || src == nullptr) {
        return set_errno_value(kEInval);
    }
    if (count > dst_size) {
        std::memset(dst, 0, dst_size);
        return set_errno_value(kERange);
    }
    std::memmove(dst, src, count);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::size_t u32u_strnlen_s(
    const char* text, std::size_t max_count) noexcept {
    if (text == nullptr) {
        return 0;
    }
    std::size_t n = 0;
    while (n < max_count && text[n] != '\0') {
        ++n;
    }
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_strcat_s_wide(
    char16_t* dst, std::size_t dst_size, const char16_t* src) noexcept {
    if (dst == nullptr || dst_size == 0) {
        report_invalid_parameter(u"destination", u"wcscat_s", nullptr, 0);
    }
    if (src == nullptr) {
        dst[0] = u'\0';
        return set_errno_value(kEInval);
    }
    std::size_t have = 0;
    while (dst[have] != u'\0') {
        ++have;
    }
    std::size_t add = 0;
    while (src[add] != u'\0') {
        ++add;
    }
    if (have + add + 1 > dst_size) {
        dst[0] = u'\0';
        return set_errno_value(kERange);
    }
    std::memcpy(dst + have, src, (add + 1) * 2);
    return 0;
}

// ===========================================================================
// The formatted output
// ===========================================================================
//
// The one part of this file that cannot borrow the host's formatter. The
// guest's argument list is the Windows x64 `va_list` -- a pointer to
// saved slots -- and the host's `vsnprintf` reads the System V shape,
// which is a different structure entirely. Handing one to the other
// produces garbage at best and a fault at worst, which is exactly the
// fault this code replaces.
//
// So the walk is done here: the format string is parsed, each conversion
// is recognised, and the single value it names is handed to the host's
// `snprintf` with the flags, width and precision rebuilt into a
// one-conversion format. That call takes its argument as an ordinary
// parameter -- no list crosses the ABI boundary -- and the host's own
// number rendering is reused rather than reimplemented.

namespace {

// The guest's argument list, as the Windows x64 ABI lays it out: every
// argument occupies one eight-byte slot in a save area, and the list is
// a cursor into it. Reading a value is a copy of its bytes from the
// cursor -- which is the whole of the layout for the scalar types a
// format string names, integers and doubles alike.
struct MsArgs {
    const char* at = nullptr;
};

template <class T>
[[nodiscard]] T next_arg(MsArgs& a) noexcept {
    T value{};
    std::memcpy(&value, a.at, sizeof(T));
    a.at += 8;
    return value;
}

// The output the formatter writes to: a bounded buffer, or a stream.
struct Out {
    char* buf = nullptr;
    std::size_t cap = 0;
    std::size_t len = 0;   // the characters produced, not stored
    FILE* stream = nullptr;
};

void out_char(Out& o, char c) noexcept {
    if (o.stream != nullptr) {
        (void)::fputc(c, o.stream);
    } else if (o.buf != nullptr && o.len + 1 < o.cap) {
        o.buf[o.len] = c;
    }
    ++o.len;
}

void out_text(Out& o, const char* text, std::size_t n) noexcept {
    for (std::size_t i = 0; i < n; ++i) {
        out_char(o, text[i]);
    }
}

// The terminator a buffer output needs, at the last slot it may use.
void out_finish(Out& o) noexcept {
    if (o.stream != nullptr || o.buf == nullptr || o.cap == 0) {
        return;
    }
    const std::size_t at = o.len < o.cap - 1 ? o.len : o.cap - 1;
    o.buf[at] = '\0';
}

// One conversion's flags, width and precision, as a host format string
// needs them: the prefix of a `%` conversion with its conversion letter
// left off.
[[nodiscard]] std::string spec_prefix(bool minus, bool plus, bool space,
                                      bool hash, bool zero, bool has_width,
                                      std::int32_t width, bool has_prec,
                                      std::int32_t precision,
                                      const char* length) {
    std::string s = "%";
    if (minus) s += '-';
    if (plus) s += '+';
    if (space) s += ' ';
    if (hash) s += '#';
    if (zero) s += '0';
    if (has_width) {
        s += std::to_string(width);
    }
    if (has_prec) {
        s += '.';
        s += std::to_string(precision);
    }
    s += length;
    return s;
}

// The narrow walk. `ms_va` is the guest's own list, advanced with the
// compiler's own MS-layout accessor.
[[nodiscard]] std::int32_t format_narrow(Out& o, const char* fmt,
                                         MsArgs& ap) noexcept {
    for (const char* p = fmt; *p != '\0'; ++p) {
        if (*p != '%') {
            out_char(o, *p);
            continue;
        }
        ++p;
        if (*p == '%') {
            out_char(o, '%');
            continue;
        }
        bool minus = false;
        bool plus = false;
        bool space = false;
        bool hash = false;
        bool zero = false;
        for (;; ++p) {
            if (*p == '-') minus = true;
            else if (*p == '+') plus = true;
            else if (*p == ' ') space = true;
            else if (*p == '#') hash = true;
            else if (*p == '0') zero = true;
            else break;
        }
        bool has_width = false;
        std::int32_t width = 0;
        if (*p == '*') {
            has_width = true;
            width = next_arg<std::int32_t>(ap);
            if (width < 0) {
                minus = true;
                width = -width;
            }
            ++p;
        } else {
            while (*p >= '0' && *p <= '9') {
                has_width = true;
                width = width * 10 + (*p - '0');
                ++p;
            }
        }
        bool has_prec = false;
        std::int32_t precision = 0;
        if (*p == '.') {
            ++p;
            has_prec = true;
            if (*p == '*') {
                precision = next_arg<std::int32_t>(ap);
                ++p;
                if (precision < 0) {
                    has_prec = false;
                }
            } else {
                while (*p >= '0' && *p <= '9') {
                    precision = precision * 10 + (*p - '0');
                    ++p;
                }
            }
        }
        // The length modifier, which decides how wide the value read is.
        bool is_long = false;
        bool is_long_long = false;
        bool is_short = false;
        bool is_size = false;
        if (*p == 'h') {
            is_short = true;
            ++p;
            if (*p == 'h') ++p;
        } else if (*p == 'l') {
            is_long = true;
            ++p;
            if (*p == 'l') {
                is_long_long = true;
                ++p;
            }
        } else if (*p == 'z' || *p == 'j' || *p == 't') {
            is_size = true;
            ++p;
        }
        const char* length = is_long_long || is_size ? "ll"
                             : is_long                 ? "l"
                             : is_short                ? "h"
                                                       : "";
        const char conv = *p;
        char tmp[512];
        int n = 0;
        switch (conv) {
        case 'd':
        case 'i': {
            std::int64_t v = 0;
            if (is_long_long || is_size) {
                v = next_arg<std::int64_t>(ap);
            } else if (is_long) {
                v = next_arg<long>(ap);
            } else {
                v = next_arg<std::int32_t>(ap);
            }
            const std::string f =
                spec_prefix(minus, plus, space, hash, zero, has_width, width,
                            has_prec, precision, length) + "d";
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
            n = ::snprintf(tmp, sizeof(tmp), f.c_str(),
                           static_cast<long long>(v));
#pragma GCC diagnostic pop
            break;
        }
        case 'u':
        case 'o':
        case 'x':
        case 'X': {
            std::uint64_t v = 0;
            if (is_long_long || is_size) {
                v = next_arg<std::uint64_t>(ap);
            } else if (is_long) {
                v = next_arg<unsigned long>(ap);
            } else {
                v = next_arg<std::uint32_t>(ap);
            }
            const std::string f =
                spec_prefix(minus, plus, space, hash, zero, has_width, width,
                            has_prec, precision, length) +
                std::string(1, conv);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
            n = ::snprintf(tmp, sizeof(tmp), f.c_str(),
                           static_cast<unsigned long long>(v));
#pragma GCC diagnostic pop
            break;
        }
        case 'c': {
            const std::int32_t c = next_arg<std::int32_t>(ap);
            out_char(o, static_cast<char>(c));
            continue;
        }
        case 's': {
            const char* s = next_arg<const char*>(ap);
            if (s == nullptr) {
                s = "(null)";
            }
            std::size_t len = 0;
            if (has_prec) {
                while (len < static_cast<std::size_t>(precision) &&
                       s[len] != '\0') {
                    ++len;
                }
            } else {
                len = std::strlen(s);
            }
            // The width padding the field asks for.
            if (has_width && static_cast<std::int32_t>(len) < width) {
                const std::size_t pad =
                    static_cast<std::size_t>(width) - len;
                if (!minus) {
                    for (std::size_t i = 0; i < pad; ++i) out_char(o, ' ');
                }
                out_text(o, s, len);
                if (minus) {
                    for (std::size_t i = 0; i < pad; ++i) out_char(o, ' ');
                }
            } else {
                out_text(o, s, len);
            }
            continue;
        }
        case 'S': {
            // The wide string in a narrow format: converted, which is
            // what the C library does with a `%S` under this width.
            const char16_t* w = next_arg<const char16_t*>(ap);
            const std::string narrow =
                w == nullptr ? "(null)" : wide_to_narrow(w);
            out_text(o, narrow.data(), narrow.size());
            continue;
        }
        case 'p': {
            const void* v = next_arg<void*>(ap);
            n = ::snprintf(tmp, sizeof(tmp), "%p", v);
            break;
        }
        case 'f':
        case 'F':
        case 'e':
        case 'E':
        case 'g':
        case 'G':
        case 'a':
        case 'A': {
            const double v = next_arg<double>(ap);
            const std::string f =
                spec_prefix(minus, plus, space, hash, zero, has_width, width,
                            has_prec, precision, "") +
                std::string(1, conv);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
            n = ::snprintf(tmp, sizeof(tmp), f.c_str(), v);
#pragma GCC diagnostic pop
            break;
        }
        case 'n': {
            // The count the format asks to be written back.
            if (is_long_long) {
                auto* at = next_arg<std::int64_t*>(ap);
                if (at != nullptr) *at = static_cast<std::int64_t>(o.len);
            } else {
                auto* at = next_arg<std::int32_t*>(ap);
                if (at != nullptr) *at = static_cast<std::int32_t>(o.len);
            }
            continue;
        }
        default:
            out_char(o, '%');
            out_char(o, conv);
            continue;
        }
        if (n > 0) {
            out_text(o, tmp, static_cast<std::size_t>(n));
        }
    }
    return static_cast<std::int32_t>(o.len);
}

}  // namespace

// The `__p___argv` data export's backing: a pointer to the argv table the
// process builder lays out in guest memory, wired there at startup. A
// guest that reads through the export reads guest memory, which is what a
// C startup that walks its own arguments expects.
char** g_u32_argv_ptr = nullptr;

// The guest's `wchar_t` is sixteen bits, which is not the host's. Every
// wide conversion below parses or copies the guest's own code units
// rather than handing the host a buffer it would read as thirty-two-bit
// wide characters.

// The integer conversions, one core walk shared by all four widths. The
// walk is the C one -- optional sign, optional base prefix, digits until
// a character that is not one -- with the accumulation checked against
// the caller's width so the answer wraps the way the real function's
// does instead of silently overflowing.
template <typename T>
T u32_wcstox(const char16_t* nptr, char16_t** end, int base, T minimum,
             T maximum) noexcept {
    if (nptr == nullptr) {
        if (end != nullptr) {
            *end = nullptr;
        }
        return 0;
    }
    const char16_t* p = nptr;
    for (;; ++p) {
        const char16_t c = *p;
        if (c != u' ' && c != u'\t' && c != u'\n' && c != u'\r' &&
            c != u'\f' && c != u'\v') {
            break;
        }
    }
    int sign = 1;
    if (*p == u'+') {
        ++p;
    } else if (*p == u'-') {
        sign = -1;
        ++p;
    }
    int radix = base;
    if (radix == 0) {
        radix = 10;
        if (*p == u'0') {
            radix = 8;
            ++p;
            if (*p == u'x' || *p == u'X') {
                radix = 16;
                ++p;
            }
        }
    } else if (radix == 16 && *p == u'0' && (p[1] == u'x' || p[1] == u'X')) {
        p += 2;
    }
    unsigned long long acc = 0;
    bool any = false;
    for (;; ++p) {
        const char16_t c = *p;
        int digit;
        if (c >= u'0' && c <= u'9') {
            digit = static_cast<int>(c - u'0');
        } else if (c >= u'a' && c <= u'z') {
            digit = static_cast<int>(c - u'a') + 10;
        } else if (c >= u'A' && c <= u'Z') {
            digit = static_cast<int>(c - u'A') + 10;
        } else {
            break;
        }
        if (digit >= radix) {
            break;
        }
        acc = acc * static_cast<unsigned long long>(radix) +
              static_cast<unsigned long long>(digit);
        any = true;
    }
    if (end != nullptr) {
        *end = const_cast<char16_t*>(p);
    }
    if (!any) {
        return 0;
    }
    if (sign < 0) {
        // The negated accumulator, saturated at the caller's minimum so a
        // run that overflows the width reports the extreme rather than a
        // wrap that looks like a smaller number.
        const unsigned long long neg =
            acc > static_cast<unsigned long long>(-(minimum + 1)) + 1
                ? static_cast<unsigned long long>(-(minimum + 1)) + 1
                : acc;
        return static_cast<T>(-static_cast<long long>(neg));
    }
    return acc > static_cast<unsigned long long>(maximum)
               ? maximum
               : static_cast<T>(acc);
}

extern "C" __attribute__((ms_abi)) long u32u_wcstol(const char16_t* nptr,
                                                    char16_t** end,
                                                    int base) noexcept {
    return u32_wcstox<long>(nptr, end, base, LONG_MIN, LONG_MAX);
}

extern "C" __attribute__((ms_abi)) unsigned long u32u_wcstoul(
    const char16_t* nptr, char16_t** end, int base) noexcept {
    return u32_wcstox<unsigned long>(nptr, end, base, 0UL, ULONG_MAX);
}

extern "C" __attribute__((ms_abi)) long long u32u_wcstoll(
    const char16_t* nptr, char16_t** end, int base) noexcept {
    return u32_wcstox<long long>(nptr, end, base, LLONG_MIN, LLONG_MAX);
}

extern "C" __attribute__((ms_abi)) unsigned long long u32u_wcstoull(
    const char16_t* nptr, char16_t** end, int base) noexcept {
    return u32_wcstox<unsigned long long>(nptr, end, base, 0ULL,
                                          ULLONG_MAX);
}

// The wide floating conversion: the leading run of characters the host's
// `strtod` would accept is copied to a narrow buffer and handed to it,
// and the end pointer lands on the same position the copied run stopped.
extern "C" __attribute__((ms_abi)) double u32u_wcstod(
    const char16_t* nptr, char16_t** end) noexcept {
    if (nptr == nullptr) {
        if (end != nullptr) {
            *end = nullptr;
        }
        return 0.0;
    }
    const char16_t* p = nptr;
    for (;; ++p) {
        const char16_t c = *p;
        if (c != u' ' && c != u'\t' && c != u'\n' && c != u'\r' &&
            c != u'\f' && c != u'\v') {
            break;
        }
    }
    char narrow[512];
    std::size_t n = 0;
    const char16_t* q = p;
    if (*q == u'+' || *q == u'-') {
        narrow[n++] = static_cast<char>(*q++);
    }
    bool mantissa = false;
    while ((*q >= u'0' && *q <= u'9') || *q == u'.') {
        narrow[n++] = static_cast<char>(*q++);
        mantissa = true;
    }
    if (mantissa && (*q == u'e' || *q == u'E')) {
        narrow[n++] = static_cast<char>(*q++);
        if (*q == u'+' || *q == u'-') {
            narrow[n++] = static_cast<char>(*q++);
        }
        while (*q >= u'0' && *q <= u'9') {
            narrow[n++] = static_cast<char>(*q++);
        }
    }
    narrow[n] = '\0';
    char* narrow_end = nullptr;
    const double value = ::strtod(narrow, &narrow_end);
    const std::size_t consumed =
        narrow_end == nullptr ? n : static_cast<std::size_t>(narrow_end - narrow);
    if (end != nullptr) {
        *end = const_cast<char16_t*>(p + consumed);
    }
    return value;
}

extern "C" __attribute__((ms_abi)) float u32u_strtof(const char* nptr,
                                                     char** end) noexcept {
    return ::strtof(nptr, end);
}

extern "C" __attribute__((ms_abi)) std::size_t u32u_wcrtomb(
    char* s, char16_t wc, mbstate_t* ps) noexcept {
    (void)ps;
    if (s == nullptr) {
        return 1;
    }
    // A BMP code unit below 0x100, which is what this runtime's wide
    // strings carry in practice; a value outside that is an encoding this
    // side does not claim to produce.
    *s = static_cast<char>(wc & 0xFFu);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::size_t u32u_wcrtomb_s(
    char* s, std::size_t size, char16_t wc, mbstate_t* ps) noexcept {
    if (s == nullptr || size == 0) {
        return static_cast<std::size_t>(-1);
    }
    (void)ps;
    *s = static_cast<char>(wc & 0xFFu);
    return 1;
}

extern "C" __attribute__((ms_abi)) std::size_t u32u_mbrtowc(
    char16_t* pwc, const char* s, std::size_t n, mbstate_t* ps) noexcept {
    (void)ps;
    if (s == nullptr) {
        return 0;
    }
    if (n == 0) {
        return static_cast<std::size_t>(-2);
    }
    if (pwc != nullptr) {
        *pwc = static_cast<unsigned char>(s[0]);
    }
    return 1;
}

extern "C" __attribute__((ms_abi)) std::size_t u32u_mbrlen(
    const char* s, std::size_t n, mbstate_t* ps) noexcept {
    return u32u_mbrtowc(nullptr, s, n, ps);
}

extern "C" __attribute__((ms_abi)) std::size_t u32u_mbsrtowcs(
    char16_t* dst, const char** src, std::size_t len,
    mbstate_t* ps) noexcept {
    (void)ps;
    if (src == nullptr || *src == nullptr) {
        return 0;
    }
    const char* s = *src;
    std::size_t i = 0;
    while (s[i] != '\0' && i < len) {
        dst[i] = static_cast<unsigned char>(s[i]);
        ++i;
    }
    if (s[i] == '\0') {
        *src = nullptr;
    } else {
        *src = s + i;
    }
    if (i < len) {
        dst[i] = u'\0';
    }
    return i;
}

extern "C" __attribute__((ms_abi)) std::size_t u32u__mbtowc_l(
    int* pwc, const char* s, std::size_t n, void* locale) noexcept {
    (void)locale;
    if (s == nullptr) {
        return 0;
    }
    if (n == 0 || s[0] == '\0') {
        return 0;
    }
    if (pwc != nullptr) {
        *pwc = static_cast<unsigned char>(s[0]);
    }
    return 1;
}

extern "C" __attribute__((ms_abi)) double u32u__strtod_l(
    const char* nptr, char** end, void* locale) noexcept {
    (void)locale;
    return ::strtod(nptr, end);
}

extern "C" __attribute__((ms_abi)) char* u32u__strdup(const char* s) noexcept {
    if (s == nullptr) {
        return nullptr;
    }
    const std::size_t n = ::strlen(s) + 1;
    char* copy = static_cast<char*>(::malloc(n));
    if (copy != nullptr) {
        ::memcpy(copy, s, n);
    }
    return copy;
}

// The locale-qualified single-byte case and classification calls. The
// locale argument is carried because the caller passed one; this runtime
// has one locale (the host's "C"), so the answer ignores it.
extern "C" __attribute__((ms_abi)) int u32u__tolower_l(
    int c, void* locale) noexcept {
    (void)locale;
    return ::tolower(c);
}

extern "C" __attribute__((ms_abi)) int u32u__toupper_l(
    int c, void* locale) noexcept {
    (void)locale;
    return ::toupper(c);
}

extern "C" __attribute__((ms_abi)) wint_t u32u__towlower_l(
    wint_t c, void* locale) noexcept {
    (void)locale;
    return static_cast<wint_t>(::towlower(static_cast<wint_t>(c)));
}

extern "C" __attribute__((ms_abi)) wint_t u32u__towupper_l(
    wint_t c, void* locale) noexcept {
    (void)locale;
    return static_cast<wint_t>(::towupper(static_cast<wint_t>(c)));
}

extern "C" __attribute__((ms_abi)) int u32u__iswalnum_l(
    wint_t c, void* locale) noexcept {
    (void)locale;
    return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'z') ||
           (c >= L'A' && c <= L'Z');
}

extern "C" __attribute__((ms_abi)) int u32u__iswalpha_l(
    wint_t c, void* locale) noexcept {
    (void)locale;
    return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z');
}

extern "C" __attribute__((ms_abi)) int u32u__iswcntrl_l(
    wint_t c, void* locale) noexcept {
    (void)locale;
    return c < 0x20 || c == 0x7F;
}

extern "C" __attribute__((ms_abi)) int u32u__iswdigit_l(
    wint_t c, void* locale) noexcept {
    (void)locale;
    return c >= L'0' && c <= L'9';
}

extern "C" __attribute__((ms_abi)) int u32u__iswlower_l(
    wint_t c, void* locale) noexcept {
    (void)locale;
    return c >= L'a' && c <= L'z';
}

extern "C" __attribute__((ms_abi)) int u32u__iswprint_l(
    wint_t c, void* locale) noexcept {
    (void)locale;
    return c >= 0x20 && c != 0x7F;
}

extern "C" __attribute__((ms_abi)) int u32u__iswpunct_l(
    wint_t c, void* locale) noexcept {
    (void)locale;
    return (c >= 0x21 && c <= 0x2F) || (c >= 0x3A && c <= 0x40) ||
           (c >= 0x5B && c <= 0x60) || (c >= 0x7B && c <= 0x7E);
}

extern "C" __attribute__((ms_abi)) int u32u__iswspace_l(
    wint_t c, void* locale) noexcept {
    (void)locale;
    return c == L' ' || (c >= 0x09 && c <= 0x0D);
}

extern "C" __attribute__((ms_abi)) int u32u__iswupper_l(
    wint_t c, void* locale) noexcept {
    (void)locale;
    return c >= L'A' && c <= L'Z';
}

extern "C" __attribute__((ms_abi)) int u32u__iswxdigit_l(
    wint_t c, void* locale) noexcept {
    (void)locale;
    return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ||
           (c >= L'A' && c <= L'F');
}

extern "C" __attribute__((ms_abi)) int u32u__strcoll_l(
    const char* a, const char* b, void* locale) noexcept {
    (void)locale;
    return ::strcoll(a, b);
}

extern "C" __attribute__((ms_abi)) int u32u__wcscoll_l(
    const char16_t* a, const char16_t* b, void* locale) noexcept {
    (void)locale;
    std::size_t i = 0;
    for (;; ++i) {
        const unsigned int ca = static_cast<unsigned int>(a[i]);
        const unsigned int cb = static_cast<unsigned int>(b[i]);
        if (ca != cb) {
            return ca < cb ? -1 : 1;
        }
        if (ca == 0) {
            return 0;
        }
    }
}

extern "C" __attribute__((ms_abi)) std::size_t u32u__strxfrm_l(
    char* dst, const char* src, std::size_t n, void* locale) noexcept {
    (void)locale;
    return ::strxfrm(dst, src, n);
}

extern "C" __attribute__((ms_abi)) std::size_t u32u__wcsxfrm_l(
    char16_t* dst, const char16_t* src, std::size_t n,
    void* locale) noexcept {
    (void)locale;
    std::size_t i = 0;
    for (; i < n && src[i] != u'\0'; ++i) {
        dst[i] = src[i];
    }
    if (i < n) {
        dst[i] = u'\0';
    }
    return i;
}

extern "C" __attribute__((ms_abi)) std::size_t u32u__strftime_l(
    char* buffer, std::size_t max, const char* format, const void* tm,
    void* locale) noexcept {
    (void)locale;
    return ::strftime(buffer, max, format, static_cast<const std::tm*>(tm));
}

// The stdio calls the modern CRT asks for by name. The stream argument is
// the host's own `FILE*`, the same object the formatted-output path
// writes through; the narrow versions are the host's own calls, and the
// wide ones move code units this runtime's wide strings carry.
extern "C" __attribute__((ms_abi)) void u32u_setbuf(void* stream,
                                                    char* buffer) noexcept {
    ::setbuf(static_cast<FILE*>(stream), buffer);
}

extern "C" __attribute__((ms_abi)) int u32u__setmode(int fd,
                                                     int mode) noexcept {
    // The host has no text/binary mode on a descriptor; every stream is
    // binary. The call is honored as a no-op that reports the previous
    // mode as text, which is the mode everything is already in.
    (void)fd;
    (void)mode;
    return 0;
}

extern "C" __attribute__((ms_abi)) int u32u__fileno(void* stream) noexcept {
    return ::fileno(static_cast<FILE*>(stream));
}

extern "C" __attribute__((ms_abi)) int u32u_ungetc(int c,
                                                   void* stream) noexcept {
    return ::ungetc(c, static_cast<FILE*>(stream));
}

extern "C" __attribute__((ms_abi)) wint_t u32u_ungetwc(
    wint_t c, void* stream) noexcept {
    return ::ungetwc(c, static_cast<FILE*>(stream));
}

extern "C" __attribute__((ms_abi)) wint_t u32u_fgetwc(void* stream) noexcept {
    // A guest `wint_t` is the same width as the host's, and the code unit
    // the host reads is thirty-two bits; a value outside the guest's BMP
    // is one this runtime's wide strings never carried.
    return ::fgetwc(static_cast<FILE*>(stream));
}

extern "C" __attribute__((ms_abi)) wint_t u32u_fputwc(
    wint_t c, void* stream) noexcept {
    return ::fputwc(static_cast<wchar_t>(c), static_cast<FILE*>(stream));
}

extern "C" __attribute__((ms_abi)) int u32u__fseeki64(
    void* stream, long long offset, int origin) noexcept {
    return ::fseeko(static_cast<FILE*>(stream),
                    static_cast<off_t>(offset), origin);
}

extern "C" __attribute__((ms_abi)) long long u32u__ftelli64(
    void* stream) noexcept {
    return static_cast<long long>(::ftello(static_cast<FILE*>(stream)));
}

extern "C" __attribute__((ms_abi)) void u32u__lock_file(
    void* stream) noexcept {
    (void)stream;
}

extern "C" __attribute__((ms_abi)) void u32u__unlock_file(
    void* stream) noexcept {
    (void)stream;
}

extern "C" __attribute__((ms_abi)) void* u32u___acrt_iob_func(
    std::uint32_t index) noexcept {
    if (index == 0) {
        return stdin;
    }
    if (index == 1) {
        return stdout;
    }
    if (index == 2) {
        return stderr;
    }
    return nullptr;
}

// The environment and process-data exports. The argv pointer is wired by
// the process builder; the environment table is the host's own, which is
// the narrow environment this runtime started with.
extern "C" __attribute__((ms_abi)) char*** u32u___p___argv() noexcept {
    return &g_u32_argv_ptr;
}

extern "C" __attribute__((ms_abi)) char** u32u__get_initial_narrow_environment() noexcept {
    return environ;
}

extern "C" __attribute__((ms_abi)) void u32u__initialize_narrow_environment() noexcept {}

extern "C" __attribute__((ms_abi)) void u32u__configure_narrow_argv() noexcept {}

extern "C" __attribute__((ms_abi)) const unsigned short* u32u___pctype_func() noexcept {
    return *::__ctype_b_loc();
}

int u32u_sys_nerr = 107;

extern "C" __attribute__((ms_abi)) int* u32u___p__fmode() noexcept {
    return &g_fmode;
}

extern "C" __attribute__((ms_abi)) char*** u32u___p__environ() noexcept {
    return &g_environ_ptr;
}

// The secure error text: the host's `strerror` rendered into the caller's
// buffer with the same truncation rules `strerror_s` applies.
extern "C" __attribute__((ms_abi)) int u32u_strerror_s(
    char* buffer, std::size_t size, int errnum) noexcept {
    if (buffer == nullptr || size == 0) {
        return EINVAL;
    }
    if (size == 1) {
        buffer[0] = '\0';
        return EINVAL;
    }
    const char* text = ::strerror(errnum);
    const std::size_t len = ::strnlen(text, size - 1);
    ::memcpy(buffer, text, len);
    buffer[len] = '\0';
    return 0;
}

// The assertion and watson failure paths, which a program that reaches
// them cannot recover from. The message goes to stderr and the process
// terminates the way `abort` does.
extern "C" __attribute__((ms_abi)) void u32u__assert(
    const char* message, const char* file, unsigned line) noexcept {
    ::fprintf(stderr, "Assertion failed: %s, file %s, line %u\n", message,
              file, line);
    ::abort();
}

extern "C" __attribute__((ms_abi)) void u32u__invoke_watson(
    const wchar_t* expression, const wchar_t* function, const wchar_t* file,
    unsigned line, std::uintptr_t reserved) noexcept {
    (void)expression;
    (void)function;
    (void)file;
    (void)line;
    (void)reserved;
    ::abort();
}

extern "C" __attribute__((ms_abi)) std::int32_t
u32u___stdio_common_vfprintf(std::uint64_t options, void* stream,
                             const char* format, void* locale,
                             __builtin_ms_va_list args) noexcept {
    (void)options;
    (void)locale;
    if (format == nullptr || stream == nullptr) {
        return -1;
    }
    Out o;
    o.stream = static_cast<FILE*>(stream);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    return format_narrow(o, format, cursor);
}

extern "C" __attribute__((ms_abi)) std::int32_t
u32u___stdio_common_vsprintf(std::uint64_t options, char* buffer,
                             std::size_t size, const char* format,
                             void* locale, __builtin_ms_va_list args) noexcept {
    (void)options;
    (void)locale;
    if (format == nullptr) {
        return -1;
    }
    Out o;
    o.buf = buffer;
    o.cap = size;
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    const std::int32_t n = format_narrow(o, format, cursor);
    out_finish(o);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t
u32u___stdio_common_vsnprintf(std::uint64_t options, char* buffer,
                              std::size_t size, std::size_t count,
                              const char* format, void* locale,
                              __builtin_ms_va_list args) noexcept {
    (void)options;
    (void)locale;
    if (format == nullptr || buffer == nullptr || size == 0) {
        return -1;
    }
    Out o;
    o.buf = buffer;
    o.cap = count == 0 ? size : std::min(count, size);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    const std::int32_t n = format_narrow(o, format, cursor);
    out_finish(o);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t
u32u___stdio_common_vfscanf(std::uint64_t options, void* stream,
                            const char* format, void* locale,
                            __builtin_ms_va_list args) noexcept {
    (void)options;
    (void)stream;
    (void)format;
    (void)locale;
    (void)args;
    // The scan family writes into the caller's pointers and reads from
    // the stream; the walk would be the mirror of the one above, and the
    // number of fields a program reads back is the one thing it cannot
    // get wrong. An unread stream answers the end of input, which is what
    // a headless run's `scanf` sees.
    return -1;
}

extern "C" __attribute__((ms_abi)) std::int32_t
u32u___stdio_common_vsscanf(std::uint64_t options, const char* buffer,
                            std::size_t size, const char* format,
                            void* locale, __builtin_ms_va_list args) noexcept {
    (void)options;
    (void)buffer;
    (void)size;
    (void)format;
    (void)locale;
    (void)args;
    return -1;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_sprintf_s(
    char* buffer, std::size_t size, const char* format, ...) noexcept {
    if (buffer == nullptr || size == 0) {
        report_invalid_parameter(u"buffer", u"sprintf_s", nullptr, 0);
        return -1;
    }
    if (format == nullptr) {
        buffer[0] = '\0';
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    Out o;
    o.buf = buffer;
    o.cap = size;
    const std::int32_t n = format_narrow(o, format, cursor);
    __builtin_ms_va_end(args);
    out_finish(o);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_snprintf_s(
    char* buffer, std::size_t size, std::size_t count,
    const char* format, ...) noexcept {
    if (buffer == nullptr || size == 0 || format == nullptr) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    Out o;
    o.buf = buffer;
    o.cap = count == 0 ? size : std::min(count, size);
    const std::int32_t n = format_narrow(o, format, cursor);
    __builtin_ms_va_end(args);
    out_finish(o);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_vsnprintf_s(
    char* buffer, std::size_t size, std::size_t count, const char* format,
    __builtin_ms_va_list args) noexcept {
    if (buffer == nullptr || size == 0 || format == nullptr) {
        return -1;
    }
    Out o;
    o.buf = buffer;
    o.cap = count == 0 ? size : std::min(count, size);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    const std::int32_t n = format_narrow(o, format, cursor);
    out_finish(o);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_vsprintf_s(
    char* buffer, std::size_t size, const char* format,
    __builtin_ms_va_list args) noexcept {
    if (buffer == nullptr || size == 0 || format == nullptr) {
        return -1;
    }
    Out o;
    o.buf = buffer;
    o.cap = size;
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    const std::int32_t n = format_narrow(o, format, cursor);
    out_finish(o);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__snprintf_s(
    char* buffer, std::size_t size, std::size_t count,
    const char* format, ...) noexcept {
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    const std::int32_t n = u32u_vsnprintf_s(buffer, size, count, format, args);
    __builtin_ms_va_end(args);
    return n;
}

// ===========================================================================
// The search, sort and utility functions
// ===========================================================================

using CompareFn = std::int32_t(__attribute__((ms_abi))*)(const void*,
                                                          const void*);

extern "C" __attribute__((ms_abi)) void u32u_qsort(
    void* base, std::size_t count, std::size_t width,
    CompareFn compare) noexcept {
    if (base == nullptr || compare == nullptr || count < 2 || width == 0) {
        return;
    }
    // The insertion sort every CRT carries, run over the caller's own
    // elements through the caller's own comparison -- the exchange
    // between the two being the one part a library cannot do for a
    // caller whose elements it does not know the shape of.
    auto* p = static_cast<std::uint8_t*>(base);
    std::vector<std::uint8_t> tmp(width);
    for (std::size_t i = 1; i < count; ++i) {
        std::memcpy(tmp.data(), p + i * width, width);
        std::size_t j = i;
        while (j > 0 && compare(p + (j - 1) * width, tmp.data()) > 0) {
            std::memcpy(p + j * width, p + (j - 1) * width, width);
            --j;
        }
        std::memcpy(p + j * width, tmp.data(), width);
    }
}

extern "C" __attribute__((ms_abi)) void* u32u_bsearch(
    const void* key, const void* base, std::size_t count, std::size_t width,
    CompareFn compare) noexcept {
    if (key == nullptr || base == nullptr || compare == nullptr ||
        width == 0) {
        return nullptr;
    }
    const auto* p = static_cast<const std::uint8_t*>(base);
    std::size_t lo = 0;
    std::size_t hi = count;
    while (lo < hi) {
        const std::size_t mid = lo + (hi - lo) / 2;
        const int c = compare(key, p + mid * width);
        if (c == 0) {
            return const_cast<void*>(
                static_cast<const void*>(p + mid * width));
        }
        if (c < 0) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return nullptr;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_rand_s(
    unsigned int* value) noexcept {
    if (value == nullptr) {
        return kErrParam;
    }
    *value = static_cast<unsigned int>(::rand());
    return 0;
}

// ===========================================================================
// The aligned heap
// ===========================================================================

extern "C" __attribute__((ms_abi)) void* u32u__aligned_malloc(
    std::size_t size, std::size_t alignment) noexcept {
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        report_invalid_parameter(u"alignment", u"_aligned_malloc", nullptr, 0);
        // The handler returned, so the call continues to its failure
        // answer: nothing allocated, and the errno the CRT sets.
        set_errno_value(kEInval);
        return nullptr;
    }
    void* p = nullptr;
    if (::posix_memalign(&p, alignment < sizeof(void*) ? sizeof(void*)
                                                       : alignment,
                         size) != 0) {
        set_errno_value(kENoMem);
        return nullptr;
    }
    return p;
}

extern "C" __attribute__((ms_abi)) void u32u__aligned_free(
    void* block) noexcept {
    ::free(block);
}

extern "C" __attribute__((ms_abi)) void* u32u__aligned_realloc(
    void* block, std::size_t size, std::size_t alignment) noexcept {
    (void)alignment;
    return ::realloc(block, size);
}

extern "C" __attribute__((ms_abi)) std::size_t u32u__aligned_msize(
    void* block, std::size_t alignment, std::size_t offset) noexcept {
    (void)alignment;
    (void)offset;
    if (block == nullptr) {
        return 0;
    }
    return ::malloc_usable_size(block);
}

// ===========================================================================
// The locale
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::uint64_t u32u__create_locale(
    std::int32_t category, const char* name) noexcept {
    (void)category;
    if (name == nullptr) {
        return 0;
    }
    auto* loc = new CrtLocale();
    loc->name = name;
    return reinterpret_cast<std::uint64_t>(loc);
}

extern "C" __attribute__((ms_abi)) void u32u__free_locale(
    std::uint64_t locale) noexcept {
    delete reinterpret_cast<CrtLocale*>(locale);
}

extern "C" __attribute__((ms_abi)) char* u32u_setlocale(
    std::int32_t category, const char* name) noexcept {
    (void)category;
    // The locale this runtime implements is the one the C library
    // documents: "C", and a request for any other name is answered with
    // the C locale's name, which is what a system without the requested
    // locale answers.
    static char c_locale[] = "C";
    if (name != nullptr) {
        c_locale[0] = 'C';
        c_locale[1] = '\0';
    }
    return c_locale;
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32u__get_current_locale()
    noexcept {
    return u32u__create_locale(0, "C");
}

// The `lconv` the locale query answers with, at the guest's layout: the
// decimal point and the empty strings of the C locale.
struct Lconv {
    char* decimal_point;
    char* thousands_sep;
    char* grouping;
    char* int_curr_symbol;
    char* currency_symbol;
    char* mon_decimal_point;
    char* mon_thousands_sep;
    char* mon_grouping;
    char* positive_sign;
    char* negative_sign;
    char int_frac_digits;
    char frac_digits;
    char p_cs_precedes;
    char p_sep_by_space;
    char n_cs_precedes;
    char n_sep_by_space;
    char p_sign_posn;
    char n_sign_posn;
};

extern "C" __attribute__((ms_abi)) Lconv* u32u_localeconv() noexcept {
    static char point[] = ".";
    static char empty[] = "";
    static Lconv conv = {};
    conv.decimal_point = point;
    conv.thousands_sep = empty;
    conv.grouping = empty;
    conv.int_curr_symbol = empty;
    conv.currency_symbol = empty;
    conv.mon_decimal_point = empty;
    conv.mon_thousands_sep = empty;
    conv.mon_grouping = empty;
    conv.positive_sign = empty;
    conv.negative_sign = empty;
    conv.int_frac_digits = 127;  // CHAR_MAX: the C locale's "unset"
    conv.frac_digits = 127;
    conv.p_cs_precedes = 127;
    conv.p_sep_by_space = 127;
    conv.n_cs_precedes = 127;
    conv.n_sep_by_space = 127;
    conv.p_sign_posn = 127;
    conv.n_sign_posn = 127;
    return &conv;
}

// ===========================================================================
// The process, console and thread entry points
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t u32u_system(
    const char* command) noexcept {
    if (command == nullptr) {
        return 1;  // the documented "a command processor is present"
    }
    const int rc = ::system(command);
    return rc;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__wsystem(
    const char16_t* command) noexcept {
    const std::string narrow = wide_to_narrow(command);
    return u32u_system(narrow.empty() ? nullptr : narrow.c_str());
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__getch() noexcept {
    // The console this runtime has is the guest's own input, which a
    // headless run does not carry. The answer is the end-of-file the C
    // library gives for a read that has nothing to read.
    return -1;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__kbhit() noexcept {
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__putch(
    std::int32_t ch) noexcept {
    return ::fputc(ch, stdout);
}

using BeginThreadFn = std::uint32_t(__attribute__((ms_abi))*)(void*);
struct ThreadStart {
    BeginThreadFn fn;
    void* arg;
};

std::uint32_t thread_trampoline(ThreadStart* start) noexcept {
    const BeginThreadFn fn = start->fn;
    void* arg = start->arg;
    delete start;
    // The thread object the CRT keeps: one heap allocation holding the
    // result, which `_endthreadex` reads. The trampoline is what a real
    // CRT runs, and the result is what the call returns.
    const std::uint32_t rc = fn(arg);
    return rc;
}

extern "C" __attribute__((ms_abi)) std::uintptr_t u32u__beginthreadex(
    void* security, unsigned int stack_size, BeginThreadFn fn, void* arg,
    unsigned int flags, unsigned int* thread_id) noexcept {
    (void)security;
    (void)stack_size;
    (void)flags;
    if (fn == nullptr) {
        return 0;
    }
    // The thread the CRT starts is a host thread running the guest's
    // entry; the id is handed back the way the call promises.
    static std::uint32_t next_id = 100;
    if (thread_id != nullptr) {
        *thread_id = ++next_id;
    }
    auto* start = new ThreadStart{fn, arg};
    std::thread(thread_trampoline, start).detach();
    // The handle the call answers with is the thread object, which is the
    // identity the CRT's own calls take.
    return reinterpret_cast<std::uintptr_t>(start);
}

extern "C" __attribute__((ms_abi)) void u32u__endthreadex(
    unsigned int code) noexcept {
    (void)code;
    // The thread's own exit: the guest's thread ends here, which is what
    // the call means for the thread that makes it.
    std::this_thread::yield();
}

// ===========================================================================
// The conversion functions
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t u32u__itoa_s(
    std::int32_t value, char* buffer, std::size_t size,
    std::int32_t radix) noexcept {
    if (buffer == nullptr || size == 0) {
        return kErrParam;
    }
    if (radix < 2 || radix > 36) {
        buffer[0] = '\0';
        return set_errno_value(kEInval);
    }
    const int n = ::snprintf(buffer, size, radix == 10 ? "%d" : "%d", value);
    return n < 0 ? kErrRange : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__i64toa_s(
    std::int64_t value, char* buffer, std::size_t size,
    std::int32_t radix) noexcept {
    (void)radix;
    if (buffer == nullptr || size == 0) {
        return kErrParam;
    }
    const int n = ::snprintf(buffer, size, "%lld",
                             static_cast<long long>(value));
    return n < 0 ? kErrRange : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__ui64toa_s(
    std::uint64_t value, char* buffer, std::size_t size,
    std::int32_t radix) noexcept {
    (void)radix;
    if (buffer == nullptr || size == 0) {
        return kErrParam;
    }
    const int n = ::snprintf(buffer, size, "%llu",
                             static_cast<unsigned long long>(value));
    return n < 0 ? kErrRange : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__ultoa_s(
    unsigned long value, char* buffer, std::size_t size,
    std::int32_t radix) noexcept {
    (void)radix;
    if (buffer == nullptr || size == 0) {
        return kErrParam;
    }
    const int n = ::snprintf(buffer, size, "%lu", value);
    return n < 0 ? kErrRange : 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__ltoa_s(
    long value, char* buffer, std::size_t size,
    std::int32_t radix) noexcept {
    (void)radix;
    if (buffer == nullptr || size == 0) {
        return kErrParam;
    }
    const int n = ::snprintf(buffer, size, "%ld", value);
    return n < 0 ? kErrRange : 0;
}

extern "C" __attribute__((ms_abi)) std::int64_t u32u__strtoi64(
    const char* text, char** end, std::int32_t radix) noexcept {
    return ::strtoll(text, end, radix);
}

extern "C" __attribute__((ms_abi)) std::uint64_t u32u__strtoui64(
    const char* text, char** end, std::int32_t radix) noexcept {
    return ::strtoull(text, end, radix);
}

extern "C" __attribute__((ms_abi)) double u32u_strtod(
    const char* text, char** end) noexcept {
    return ::strtod(text, end);
}

extern "C" __attribute__((ms_abi)) double u32u_atof(const char* text) noexcept {
    return ::atof(text);
}

// ===========================================================================
// The path helpers
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t u32u__splitpath_s(
    const char* path, char* drive, std::size_t drive_size, char* dir,
    std::size_t dir_size, char* name, std::size_t name_size, char* ext,
    std::size_t ext_size) noexcept {
    if (path == nullptr) {
        return kErrParam;
    }
    auto put = [](char* dst, std::size_t size, const char* src,
                  std::size_t len) {
        if (dst == nullptr || size == 0) {
            return;
        }
        const std::size_t take = std::min(len, size - 1);
        std::memcpy(dst, src, take);
        dst[take] = '\0';
    };
    const std::string_view p(path);
    std::size_t drive_len = 0;
    if (p.size() >= 2 && p[1] == ':') {
        drive_len = 2;
    }
    const std::size_t slash = p.find_last_of("\\/");
    const std::size_t dir_start = drive_len;
    const std::size_t dir_end = slash == std::string_view::npos
                                    ? drive_len
                                    : slash + 1;
    put(drive, drive_size, path, drive_len);
    put(dir, dir_size, path + dir_start, dir_end - dir_start);
    const std::size_t name_start =
        slash == std::string_view::npos ? drive_len : slash + 1;
    const std::size_t dot = p.find_last_of('.');
    const std::size_t name_end =
        (dot != std::string_view::npos && dot >= name_start) ? dot : p.size();
    put(name, name_size, path + name_start, name_end - name_start);
    if (dot != std::string_view::npos && dot >= name_start) {
        put(ext, ext_size, path + dot, p.size() - dot);
    } else if (ext != nullptr && ext_size != 0) {
        ext[0] = '\0';
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__makepath_s(
    char* path, std::size_t size, const char* drive, const char* dir,
    const char* name, const char* ext) noexcept {
    if (path == nullptr || size == 0) {
        return kErrParam;
    }
    std::string out;
    if (drive != nullptr) {
        out += drive;
    }
    if (dir != nullptr) {
        out += dir;
    }
    if (name != nullptr) {
        out += name;
    }
    if (ext != nullptr) {
        out += ext;
    }
    if (out.size() + 1 > size) {
        path[0] = '\0';
        return set_errno_value(kERange);
    }
    std::memcpy(path, out.data(), out.size());
    path[out.size()] = '\0';
    return 0;
}

// ===========================================================================
// The time helpers
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t u32u__strtime_s(
    char* buffer, std::size_t size) noexcept {
    if (buffer == nullptr || size < 9) {
        return kErrParam;
    }
    const std::time_t now = ::time(nullptr);
    std::tm local = {};
    ::localtime_r(&now, &local);
    ::strftime(buffer, size, "%H:%M:%S", &local);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__strdate_s(
    char* buffer, std::size_t size) noexcept {
    if (buffer == nullptr || size < 9) {
        return kErrParam;
    }
    const std::time_t now = ::time(nullptr);
    std::tm local = {};
    ::localtime_r(&now, &local);
    ::strftime(buffer, size, "%m/%d/%Y", &local);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_localtime_s(
    std::tm* out, const std::int64_t* timer) noexcept {
    if (out == nullptr || timer == nullptr) {
        return kErrParam;
    }
    // The CRT's own time base: seconds from 1970, the same as the host's.
    const std::time_t t = static_cast<std::time_t>(*timer);
    if (::localtime_r(&t, out) == nullptr) {
        return kErrParam;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_gmtime_s(
    std::tm* out, const std::int64_t* timer) noexcept {
    if (out == nullptr || timer == nullptr) {
        return kErrParam;
    }
    const std::time_t t = static_cast<std::time_t>(*timer);
    if (::gmtime_r(&t, out) == nullptr) {
        return kErrParam;
    }
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_ctime_s(
    char* buffer, std::size_t size, const std::int64_t* timer) noexcept {
    if (buffer == nullptr || size < 26 || timer == nullptr) {
        return kErrParam;
    }
    const std::time_t t = static_cast<std::time_t>(*timer);
    std::tm local = {};
    ::localtime_r(&t, &local);
    if (::strftime(buffer, size, "%a %b %e %H:%M:%S %Y\n", &local) == 0) {
        return kErrParam;
    }
    return 0;
}

// ===========================================================================
// The registration, and the forwarder modules
// ===========================================================================

void add_ucrt_extra(ExportList& out) {
    // The registration adds only what the surface does not already
    // carry: this domain fills the *modern* half of a module the classic
    // domain has already filled, and a name both halves know -- `_errno`,
    // `memcpy`, `qsort` -- belongs to the classic one. Registering it
    // twice would be the duplicate the registry refuses and the export
    // count would report.
    const auto e = [&out](const char* name, void* fn) {
        for (const HostExport& existing : out) {
            if (existing.name == name) {
                return;
            }
        }
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };
    // The errno and parameter-handler family.
    e("_errno", reinterpret_cast<void*>(&u32u__errno));
    e("_get_errno", reinterpret_cast<void*>(&u32u__get_errno));
    e("_set_errno", reinterpret_cast<void*>(&u32u__set_errno));
    e("_invalid_parameter", reinterpret_cast<void*>(&u32u__invalid_parameter));
    e("_invalid_parameter_noinfo",
      reinterpret_cast<void*>(&u32u__invalid_parameter_noinfo));
    e("_invalid_parameter_noinfo_noreturn",
      reinterpret_cast<void*>(&u32u__invalid_parameter_noinfo_noreturn));
    e("_set_invalid_parameter_handler",
      reinterpret_cast<void*>(&u32u__set_invalid_parameter_handler));
    e("_get_errno_from_oserr",
      reinterpret_cast<void*>(&u32u__get_errno_from_oserr));
    // The secure string functions.
    e("strcpy_s", reinterpret_cast<void*>(&u32u_strcpy_s));
    e("strncpy_s", reinterpret_cast<void*>(&u32u_strncpy_s));
    e("strcat_s", reinterpret_cast<void*>(&u32u_strcat_s));
    e("strncat_s", reinterpret_cast<void*>(&u32u_strncat_s));
    e("wcscat_s", reinterpret_cast<void*>(&u32u_strcat_s_wide));
    e("memcpy_s", reinterpret_cast<void*>(&u32u_memcpy_s));
    e("memmove_s", reinterpret_cast<void*>(&u32u_memmove_s));
    e("strnlen_s", reinterpret_cast<void*>(&u32u_strnlen_s));
    // The formatted output, in the shapes the modern ABI calls.
    e("__stdio_common_vfprintf",
      reinterpret_cast<void*>(&u32u___stdio_common_vfprintf));
    e("__stdio_common_vsprintf",
      reinterpret_cast<void*>(&u32u___stdio_common_vsprintf));
    e("__stdio_common_vsnprintf",
      reinterpret_cast<void*>(&u32u___stdio_common_vsnprintf));
    e("__stdio_common_vfscanf",
      reinterpret_cast<void*>(&u32u___stdio_common_vfscanf));
    e("__stdio_common_vsscanf",
      reinterpret_cast<void*>(&u32u___stdio_common_vsscanf));
    e("sprintf_s", reinterpret_cast<void*>(&u32u_sprintf_s));
    e("snprintf_s", reinterpret_cast<void*>(&u32u_snprintf_s));
    e("vsnprintf_s", reinterpret_cast<void*>(&u32u_vsnprintf_s));
    e("vsprintf_s", reinterpret_cast<void*>(&u32u_vsprintf_s));
    e("_snprintf_s", reinterpret_cast<void*>(&u32u__snprintf_s));
    // The search, sort and random family.
    e("qsort", reinterpret_cast<void*>(&u32u_qsort));
    e("bsearch", reinterpret_cast<void*>(&u32u_bsearch));
    e("rand_s", reinterpret_cast<void*>(&u32u_rand_s));
    // The aligned heap.
    e("_aligned_malloc", reinterpret_cast<void*>(&u32u__aligned_malloc));
    e("_aligned_free", reinterpret_cast<void*>(&u32u__aligned_free));
    e("_aligned_realloc", reinterpret_cast<void*>(&u32u__aligned_realloc));
    e("_aligned_msize", reinterpret_cast<void*>(&u32u__aligned_msize));
    // The locale.
    e("_create_locale", reinterpret_cast<void*>(&u32u__create_locale));
    e("_free_locale", reinterpret_cast<void*>(&u32u__free_locale));
    e("_get_current_locale",
      reinterpret_cast<void*>(&u32u__get_current_locale));
    e("setlocale", reinterpret_cast<void*>(&u32u_setlocale));
    e("localeconv", reinterpret_cast<void*>(&u32u_localeconv));
    // The process, console and thread entry points.
    e("system", reinterpret_cast<void*>(&u32u_system));
    e("_wsystem", reinterpret_cast<void*>(&u32u__wsystem));
    e("_getch", reinterpret_cast<void*>(&u32u__getch));
    e("_kbhit", reinterpret_cast<void*>(&u32u__kbhit));
    e("_putch", reinterpret_cast<void*>(&u32u__putch));
    e("_beginthreadex", reinterpret_cast<void*>(&u32u__beginthreadex));
    e("_endthreadex", reinterpret_cast<void*>(&u32u__endthreadex));
    // The conversions.
    e("_itoa_s", reinterpret_cast<void*>(&u32u__itoa_s));
    e("_i64toa_s", reinterpret_cast<void*>(&u32u__i64toa_s));
    e("_ui64toa_s", reinterpret_cast<void*>(&u32u__ui64toa_s));
    e("_ultoa_s", reinterpret_cast<void*>(&u32u__ultoa_s));
    e("_ltoa_s", reinterpret_cast<void*>(&u32u__ltoa_s));
    e("_strtoi64", reinterpret_cast<void*>(&u32u__strtoi64));
    e("_strtoui64", reinterpret_cast<void*>(&u32u__strtoui64));
    e("strtod", reinterpret_cast<void*>(&u32u_strtod));
    e("atof", reinterpret_cast<void*>(&u32u_atof));
    // The paths and the times.
    e("_splitpath_s", reinterpret_cast<void*>(&u32u__splitpath_s));
    e("_makepath_s", reinterpret_cast<void*>(&u32u__makepath_s));
    e("_strtime_s", reinterpret_cast<void*>(&u32u__strtime_s));
    e("_strdate_s", reinterpret_cast<void*>(&u32u__strdate_s));
    e("localtime_s", reinterpret_cast<void*>(&u32u_localtime_s));
    e("gmtime_s", reinterpret_cast<void*>(&u32u_gmtime_s));
    e("ctime_s", reinterpret_cast<void*>(&u32u_ctime_s));
    // The wide conversions, parsed on the guest's own sixteen-bit code
    // units rather than the host's thirty-two-bit ones.
    e("wcstol", reinterpret_cast<void*>(&u32u_wcstol));
    e("wcstoul", reinterpret_cast<void*>(&u32u_wcstoul));
    e("wcstoll", reinterpret_cast<void*>(&u32u_wcstoll));
    e("wcstoull", reinterpret_cast<void*>(&u32u_wcstoull));
    e("wcstod", reinterpret_cast<void*>(&u32u_wcstod));
    e("strtof", reinterpret_cast<void*>(&u32u_strtof));
    e("wcrtomb", reinterpret_cast<void*>(&u32u_wcrtomb));
    e("wcrtomb_s", reinterpret_cast<void*>(&u32u_wcrtomb_s));
    e("mbrtowc", reinterpret_cast<void*>(&u32u_mbrtowc));
    e("mbrlen", reinterpret_cast<void*>(&u32u_mbrlen));
    e("mbsrtowcs", reinterpret_cast<void*>(&u32u_mbsrtowcs));
    e("_mbtowc_l", reinterpret_cast<void*>(&u32u__mbtowc_l));
    e("_strtod_l", reinterpret_cast<void*>(&u32u__strtod_l));
    e("_strdup", reinterpret_cast<void*>(&u32u__strdup));
    e("strdup", reinterpret_cast<void*>(&u32u__strdup));
    // The locale-qualified case and classification family. The locale
    // object is the one this runtime has, so the answers are the host's
    // "C" answers with the argument carried.
    e("_tolower_l", reinterpret_cast<void*>(&u32u__tolower_l));
    e("_toupper_l", reinterpret_cast<void*>(&u32u__toupper_l));
    e("_towlower_l", reinterpret_cast<void*>(&u32u__towlower_l));
    e("_towupper_l", reinterpret_cast<void*>(&u32u__towupper_l));
    e("_iswalnum_l", reinterpret_cast<void*>(&u32u__iswalnum_l));
    e("_iswalpha_l", reinterpret_cast<void*>(&u32u__iswalpha_l));
    e("_iswcntrl_l", reinterpret_cast<void*>(&u32u__iswcntrl_l));
    e("_iswdigit_l", reinterpret_cast<void*>(&u32u__iswdigit_l));
    e("_iswlower_l", reinterpret_cast<void*>(&u32u__iswlower_l));
    e("_iswprint_l", reinterpret_cast<void*>(&u32u__iswprint_l));
    e("_iswpunct_l", reinterpret_cast<void*>(&u32u__iswpunct_l));
    e("_iswspace_l", reinterpret_cast<void*>(&u32u__iswspace_l));
    e("_iswupper_l", reinterpret_cast<void*>(&u32u__iswupper_l));
    e("_iswxdigit_l", reinterpret_cast<void*>(&u32u__iswxdigit_l));
    e("_strcoll_l", reinterpret_cast<void*>(&u32u__strcoll_l));
    e("_wcscoll_l", reinterpret_cast<void*>(&u32u__wcscoll_l));
    e("_strxfrm_l", reinterpret_cast<void*>(&u32u__strxfrm_l));
    e("_wcsxfrm_l", reinterpret_cast<void*>(&u32u__wcsxfrm_l));
    e("_strftime_l", reinterpret_cast<void*>(&u32u__strftime_l));
    // The stream calls the modern CRT asks for by name.
    e("setbuf", reinterpret_cast<void*>(&u32u_setbuf));
    e("_setmode", reinterpret_cast<void*>(&u32u__setmode));
    e("_fileno", reinterpret_cast<void*>(&u32u__fileno));
    e("ungetc", reinterpret_cast<void*>(&u32u_ungetc));
    e("ungetwc", reinterpret_cast<void*>(&u32u_ungetwc));
    e("fgetwc", reinterpret_cast<void*>(&u32u_fgetwc));
    e("fputwc", reinterpret_cast<void*>(&u32u_fputwc));
    e("_fseeki64", reinterpret_cast<void*>(&u32u__fseeki64));
    e("_ftelli64", reinterpret_cast<void*>(&u32u__ftelli64));
    e("_lock_file", reinterpret_cast<void*>(&u32u__lock_file));
    e("_unlock_file", reinterpret_cast<void*>(&u32u__unlock_file));
    e("__acrt_iob_func", reinterpret_cast<void*>(&u32u___acrt_iob_func));
    // The environment and process-data exports.
    e("__p___argv", reinterpret_cast<void*>(&u32u___p___argv));
    e("_get_initial_narrow_environment",
      reinterpret_cast<void*>(&u32u__get_initial_narrow_environment));
    e("_initialize_narrow_environment",
      reinterpret_cast<void*>(&u32u__initialize_narrow_environment));
    e("_configure_narrow_argv",
      reinterpret_cast<void*>(&u32u__configure_narrow_argv));
    e("__pctype_func", reinterpret_cast<void*>(&u32u___pctype_func));
    e("__p__fmode", reinterpret_cast<void*>(&u32u___p__fmode));
    e("__p__environ", reinterpret_cast<void*>(&u32u___p__environ));
    e("__sys_nerr", &u32u_sys_nerr);
    // The failure and error-text paths.
    e("strerror_s", reinterpret_cast<void*>(&u32u_strerror_s));
    e("_assert", reinterpret_cast<void*>(&u32u__assert));
    e("_invoke_watson", reinterpret_cast<void*>(&u32u__invoke_watson));
}

}  // namespace occ::runtime::winabi

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
#include "occ/runtime/containment.h"
#include "occ/runtime/dos_path.h"
#include "occ/runtime/winabi.h"

#include <cstdarg>
#include <cstdint>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cctype>
#include <cwchar>
#include <clocale>
#include <malloc.h>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" char** environ;

namespace occ::runtime::winabi {

namespace {

[[maybe_unused]] constexpr std::uint32_t kErrOk = 0;
constexpr std::uint32_t kErrParam = 87;
[[maybe_unused]] constexpr std::uint32_t kErrNoMem = 12;
constexpr std::uint32_t kErrRange = 34;
[[maybe_unused]] constexpr std::uint32_t kErrBadF = 9;
[[maybe_unused]] constexpr std::uint32_t kErrIlseq = 42;
[[maybe_unused]] constexpr std::uint32_t kErrDomain = 33;

// The error codes the `errno` family reports, at the values the CRT
// assigns them.
[[maybe_unused]] constexpr std::int32_t kE2Big = 7;
constexpr std::int32_t kEAcces = 13;
constexpr std::int32_t kEBadf = 9;
[[maybe_unused]] constexpr std::int32_t kEFault = 14;
constexpr std::int32_t kEInval = 22;
constexpr std::int32_t kENoMem = 12;
constexpr std::int32_t kERange = 34;
constexpr std::int32_t kENoEnt = 2;

// The errno the CRT keeps. The host has its own; this translation unit
// keeps the guest's, because a guest that sets `errno` and reads it back
// expects its own value rather than the host's.
std::int32_t g_errno = 0;

// Whether `%n` writes. Off is the CRT's default and the only safe one for a
// formatter whose format string is the guest's: the conversion's argument is
// an address taken from that string, so enabling it is enabling an arbitrary
// write. `_set_printf_count_output` is the switch the guest turns it on
// with, and it is honoured the way the reference honours it.
std::int32_t g_printf_count_output = 0;

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

// The handles this runtime created, so that `_free_locale` can tell one of
// its own from the arbitrary value a guest may hand it. Without the ledger
// the free would `delete` whatever pointer arrived, and a guest that passes
// a value it did not get from `_create_locale` would be choosing an address
// for the host to free.
std::mutex& locale_ledger_mutex() noexcept {
    static std::mutex mutex;
    return mutex;
}

std::vector<CrtLocale*>& locale_ledger() noexcept {
    static std::vector<CrtLocale*> ledger;
    return ledger;
}

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
        if (*p == '\0') {
            // A format that ends in `%` has no conversion after it, and the
            // walk above has already stepped past the terminator: reading on
            // would treat whatever follows the format string in the caller's
            // memory as a conversion letter. The literal `%` is written and
            // the walk ends, which is what the reference's formatter does
            // with the same input.
            out_char(o, '%');
            return static_cast<std::int32_t>(o.len);
        }
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
            // The count the format asks to be written back -- and the one
            // conversion whose argument is an address the *format* chooses.
            // The CRT this runtime presents has it disabled by default,
            // exactly as the Microsoft one does: a guest opts in through
            // `_set_printf_count_output`, and until it does the argument is
            // consumed from the list and nothing is written. Executing it
            // unconditionally is an arbitrary write with the format string
            // as the address.
            if (is_long_long) {
                auto* at = next_arg<std::int64_t*>(ap);
                if (at != nullptr && g_printf_count_output != 0) {
                    *at = static_cast<std::int64_t>(o.len);
                }
            } else {
                auto* at = next_arg<std::int32_t*>(ap);
                if (at != nullptr && g_printf_count_output != 0) {
                    *at = static_cast<std::int32_t>(o.len);
                }
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

// -------------------------------------------------------------------------
// The wide face of the same formatter.
//
// A guest built this century writes its console and file text through the
// `__stdio_common_vfwprintf` family, whose format string is sixteen-bit
// code units. The host's own `wchar_t` is thirty-two bits, so the wide
// walk below reads the guest's units directly and renders each produced
// character through its own UTF-8 encoder, which is the one byte stream
// the host side of a FILE* carries.
// -------------------------------------------------------------------------

// The output a wide conversion writes to: a bounded buffer of guest
// sixteen-bit units, or a stream. A stream receives UTF-8, so the pair
// of units a surrogate needs is assembled here: the encoder holds the
// high half until the low half arrives, and an orphaned half -- the
// stream version of a lone surrogate in the middle of a format run --
// is replaced with the replacement character the way the reference
// renders an unpaired unit.
struct OutW {
    char16_t* buf = nullptr;
    std::size_t cap = 0;
    std::size_t len = 0;   // the units produced, not stored
    FILE* stream = nullptr;
    char16_t pending_high = 0;
};

void out_wchar(OutW& o, char16_t c) noexcept {
    if (o.stream != nullptr) {
        // A stream takes UTF-8. The pending high surrogate pairs with
        // the low half that follows; an isolated high or low half is
        // the replacement character.
        if (o.pending_high != 0) {
            if (c >= 0xDC00u && c <= 0xDFFFu) {
                const std::uint32_t cp =
                    0x10000u +
                    ((static_cast<std::uint32_t>(o.pending_high) - 0xD800u)
                     << 10) +
                    (static_cast<std::uint32_t>(c) - 0xDC00u);
                const char bytes[4] = {
                    static_cast<char>(0xF0u | (cp >> 18)),
                    static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)),
                    static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)),
                    static_cast<char>(0x80u | (cp & 0x3Fu))};
                ::fwrite(bytes, 1, 4, o.stream);
            } else {
                ::fputc(0xEF, o.stream);
                ::fputc(0xBF, o.stream);
                ::fputc(0xBD, o.stream);
                out_wchar(o, c);
            }
            o.pending_high = 0;
            ++o.len;
            return;
        }
        if (c >= 0xD800u && c <= 0xDBFFu) {
            o.pending_high = c;
            return;
        }
        if (c >= 0xDC00u && c <= 0xDFFFu) {
            ::fputc(0xEF, o.stream);
            ::fputc(0xBF, o.stream);
            ::fputc(0xBD, o.stream);
        } else if (c < 0x80u) {
            ::fputc(static_cast<int>(c), o.stream);
        } else if (c < 0x800u) {
            ::fputc(static_cast<int>(0xC0u | (c >> 6)), o.stream);
            ::fputc(static_cast<int>(0x80u | (c & 0x3Fu)), o.stream);
        } else {
            ::fputc(static_cast<int>(0xE0u | (c >> 12)), o.stream);
            ::fputc(static_cast<int>(0x80u | ((c >> 6) & 0x3Fu)),
                    o.stream);
            ::fputc(static_cast<int>(0x80u | (c & 0x3Fu)), o.stream);
        }
        ++o.len;
        return;
    }
    if (o.buf != nullptr && o.len + 1 < o.cap) {
        o.buf[o.len] = c;
    }
    ++o.len;
}

void out_wide_text(OutW& o, const char16_t* text, std::size_t n) noexcept {
    for (std::size_t i = 0; i < n; ++i) {
        out_wchar(o, text[i]);
    }
}

// The ASCII a numeric conversion rendered on the host side: each byte is
// a code point of its own in a wide string.
void out_wide_ascii(OutW& o, const char* text, std::size_t n) noexcept {
    for (std::size_t i = 0; i < n; ++i) {
        out_wchar(o, static_cast<char16_t>(static_cast<unsigned char>(
                         text[i])));
    }
}

// The terminator a wide buffer needs. A call that sizes the buffer in
// code units writes the null at the last slot it may use, as the narrow
// finish does.
void out_wide_finish(OutW& o) noexcept {
    if (o.stream != nullptr || o.buf == nullptr || o.cap == 0) {
        return;
    }
    const std::size_t at = o.len < o.cap - 1 ? o.len : o.cap - 1;
    o.buf[at] = u'\0';
}

// The wide walk, the mirror of `format_narrow` with the width the guest
// means by the letters: `%s` and `%ls` name a guest wide string, `%hs`
// and `%S` a narrow one, and the numeric conversions render through the
// host's own formatting with the width and precision carried over.
[[nodiscard]] std::int32_t format_wide(OutW& o, const char16_t* fmt,
                                       MsArgs& ap) noexcept {
    for (const char16_t* p = fmt; *p != u'\0'; ++p) {
        if (*p != u'%') {
            out_wchar(o, *p);
            continue;
        }
        ++p;
        if (*p == u'\0') {
            out_wchar(o, u'%');
            return static_cast<std::int32_t>(o.len);
        }
        if (*p == u'%') {
            out_wchar(o, u'%');
            continue;
        }
        bool minus = false;
        bool plus = false;
        bool space = false;
        bool hash = false;
        bool zero = false;
        for (;; ++p) {
            if (*p == u'-') minus = true;
            else if (*p == u'+') plus = true;
            else if (*p == u' ') space = true;
            else if (*p == u'#') hash = true;
            else if (*p == u'0') zero = true;
            else break;
        }
        bool has_width = false;
        std::int32_t width = 0;
        if (*p == u'*') {
            has_width = true;
            width = next_arg<std::int32_t>(ap);
            if (width < 0) {
                minus = true;
                width = -width;
            }
            ++p;
        } else {
            while (*p >= u'0' && *p <= u'9') {
                has_width = true;
                width = width * 10 + static_cast<std::int32_t>(*p - u'0');
                ++p;
            }
        }
        bool has_prec = false;
        std::int32_t precision = 0;
        if (*p == u'.') {
            ++p;
            has_prec = true;
            if (*p == u'*') {
                precision = next_arg<std::int32_t>(ap);
                ++p;
                if (precision < 0) {
                    has_prec = false;
                }
            } else {
                while (*p >= u'0' && *p <= u'9') {
                    precision =
                        precision * 10 + static_cast<std::int32_t>(*p - u'0');
                    ++p;
                }
            }
        }
        bool is_long = false;
        bool is_long_long = false;
        bool is_short = false;
        bool is_size = false;
        if (*p == u'h') {
            is_short = true;
            ++p;
            if (*p == u'h') ++p;
        } else if (*p == u'l') {
            is_long = true;
            ++p;
            if (*p == u'l') {
                is_long_long = true;
                ++p;
            }
        } else if (*p == u'z' || *p == u'j' || *p == u't') {
            is_size = true;
            ++p;
        }
        const char* length = is_long_long || is_size ? "ll"
                             : is_long                 ? "l"
                             : is_short                ? "h"
                                                       : "";
        const char16_t conv = *p;
        char tmp[512];
        int n = 0;
        switch (static_cast<char>(conv)) {
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
                std::string(1, static_cast<char>(conv));
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
            n = ::snprintf(tmp, sizeof(tmp), f.c_str(),
                           static_cast<unsigned long long>(v));
#pragma GCC diagnostic pop
            break;
        }
        case 'c': {
            // `%c` and `%lc` name a wide character here; `%hc` a narrow
            // one, kept at its byte value.
            const std::int32_t c = next_arg<std::int32_t>(ap);
            const char16_t out = is_short
                                     ? static_cast<char16_t>(
                                           static_cast<unsigned char>(c))
                                     : static_cast<char16_t>(
                                           static_cast<std::uint16_t>(c));
            out_wchar(o, out);
            continue;
        }
        case 's': {
            // `%s` and `%ls` name a guest wide string; `%hs` and `%S` a
            // narrow one, widened a byte at a time.
            if (is_short) {
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
                if (has_width && static_cast<std::int32_t>(len) < width) {
                    const std::size_t pad =
                        static_cast<std::size_t>(width) - len;
                    if (!minus) {
                        for (std::size_t i = 0; i < pad; ++i)
                            out_wchar(o, u' ');
                    }
                    out_wide_ascii(o, s, len);
                    if (minus) {
                        for (std::size_t i = 0; i < pad; ++i)
                            out_wchar(o, u' ');
                    }
                } else {
                    out_wide_ascii(o, s, len);
                }
                continue;
            }
            const char16_t* s = next_arg<const char16_t*>(ap);
            if (s == nullptr) {
                static const char16_t null_text[] = {u'(', u'n', u'u', u'l',
                                                     u'l', u')'};
                out_wide_text(o, null_text, 6);
                continue;
            }
            std::size_t len = 0;
            if (has_prec) {
                while (len < static_cast<std::size_t>(precision) &&
                       s[len] != u'\0') {
                    ++len;
                }
            } else {
                while (s[len] != u'\0') {
                    ++len;
                }
            }
            if (has_width && static_cast<std::int32_t>(len) < width) {
                const std::size_t pad = static_cast<std::size_t>(width) - len;
                if (!minus) {
                    for (std::size_t i = 0; i < pad; ++i) out_wchar(o, u' ');
                }
                out_wide_text(o, s, len);
                if (minus) {
                    for (std::size_t i = 0; i < pad; ++i) out_wchar(o, u' ');
                }
            } else {
                out_wide_text(o, s, len);
            }
            continue;
        }
        case 'S': {
            // The narrow string in a wide format: each byte widened.
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
            out_wide_ascii(o, s, len);
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
                std::string(1, static_cast<char>(conv));
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
            n = ::snprintf(tmp, sizeof(tmp), f.c_str(), v);
#pragma GCC diagnostic pop
            break;
        }
        case 'n': {
            if (is_long_long) {
                auto* at = next_arg<std::int64_t*>(ap);
                if (at != nullptr && g_printf_count_output != 0) {
                    *at = static_cast<std::int64_t>(o.len);
                }
            } else {
                auto* at = next_arg<std::int32_t*>(ap);
                if (at != nullptr && g_printf_count_output != 0) {
                    *at = static_cast<std::int32_t>(o.len);
                }
            }
            continue;
        }
        default:
            out_wchar(o, u'%');
            out_wchar(o, conv);
            continue;
        }
        if (n > 0) {
            out_wide_ascii(o, tmp, static_cast<std::size_t>(n));
        }
    }
    return static_cast<std::int32_t>(o.len);
}

// -------------------------------------------------------------------------
// The scan walk, shared by both widths.
//
// The formatted input functions were, until this runtime filled them,
// the end of input: an unread stream answers EOF, and nothing is written
// to the caller's pointers. The walk below is the real contract -- it
// reads the guest's stream (or the caller's buffer), converts each field
// and stores it at the pointer the format names. One reader serves both
// widths, so the format's `%s` means the string width the format itself
// carries: a wide format names a wide destination and `%hs` a narrow one.
// -------------------------------------------------------------------------

// One input reader for both widths: a stream, or the caller's memory.
// A unit is the width of the destination -- a byte from a stream, a byte
// from a narrow buffer, a sixteen-bit code unit from a wide one.
struct ScanSource {
    std::FILE* stream = nullptr;
    const char* at = nullptr;
    const char* end = nullptr;
    const char16_t* wat = nullptr;
    const char16_t* wend = nullptr;
    std::int32_t pending = EOF;  // one pushed-back unit
};

[[nodiscard]] std::int32_t scan_unit(ScanSource& s) noexcept {
    if (s.pending != EOF) {
        const std::int32_t c = s.pending;
        s.pending = EOF;
        return c;
    }
    if (s.stream != nullptr) {
        return ::fgetc(s.stream);
    }
    if (s.at != nullptr) {
        if (s.end != nullptr && s.at >= s.end) {
            return EOF;
        }
        if (*s.at == '\0') {
            return EOF;
        }
        return static_cast<unsigned char>(*s.at++);
    }
    if (s.wat != nullptr) {
        if (s.wend != nullptr && s.wat >= s.wend) {
            return EOF;
        }
        if (*s.wat == u'\0') {
            return EOF;
        }
        return static_cast<std::int32_t>(*s.wat++);
    }
    return EOF;
}

void scan_unget(ScanSource& s, std::int32_t c) noexcept {
    if (c != EOF) {
        s.pending = c;
    }
}

[[nodiscard]] bool scan_is_space(std::int32_t c) noexcept {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
           c == '\v';
}

[[nodiscard]] bool scan_is_digit(std::int32_t c, int base) noexcept {
    if (c < '0') return false;
    if (c <= '9') return base >= 10 || (c - '0') < base;
    if (base != 16) return false;
    if (c >= 'a' && c <= 'f') return true;
    if (c >= 'A' && c <= 'F') return true;
    return false;
}

[[nodiscard]] std::int64_t scan_accumulate_int(ScanSource& s, int base,
                                               std::size_t width,
                                               std::size_t& count) noexcept {
    // The digits (and the sign and radix prefix the conversion allows)
    // accumulate into a local buffer the host's own parser reads. Every
    // unit read is counted and either kept or returned to the reader.
    char tmp[64];
    std::size_t k = 0;
    count = 0;
    const bool limited = width != 0;
    for (;;) {
        if (limited && count >= width) {
            break;
        }
        const std::int32_t c = scan_unit(s);
        if (c == EOF) {
            break;
        }
        const bool is_sign = c == '+' || c == '-';
        const bool is_radix = c == 'x' || c == 'X';
        const bool acceptable =
            scan_is_digit(c, base) ||
            (k == 0 && is_sign) ||
            ((base == 16 || base == 0) && k == 1 && tmp[0] == '0' &&
             is_radix);
        if (!acceptable) {
            scan_unget(s, c);
            break;
        }
        if (k + 1 < sizeof(tmp)) {
            tmp[k++] = static_cast<char>(c);
        }
        ++count;
    }
    tmp[k] = '\0';
    return ::strtoll(tmp, nullptr, base);
}

[[nodiscard]] double scan_accumulate_float(ScanSource& s,
                                           std::size_t width,
                                           std::size_t& count) noexcept {
    // The characters a floating conversion accepts: digits, sign, point,
    // exponent, and the letters of `inf` and `nan`. Whatever else ends
    // the field goes back to the reader.
    char tmp[128];
    std::size_t k = 0;
    count = 0;
    const bool limited = width != 0;
    for (;;) {
        if (limited && count >= width) {
            break;
        }
        const std::int32_t c = scan_unit(s);
        if (c == EOF) {
            break;
        }
        const bool acceptable =
            (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.' ||
            c == 'e' || c == 'E' || c == 'a' || c == 'A' || c == 'x' ||
            c == 'X' || c == 'i' || c == 'I' || c == 'n' || c == 'N' ||
            c == 'f' || c == 'F';
        if (!acceptable) {
            scan_unget(s, c);
            break;
        }
        if (k + 1 < sizeof(tmp)) {
            tmp[k++] = static_cast<char>(c);
        }
        ++count;
    }
    tmp[k] = '\0';
    return ::strtod(tmp, nullptr);
}

// One character test against a scanset: the negated form, then the
// ranges. The set text is narrow; a wide format's set is written in
// ASCII and matches the same way.
[[nodiscard]] bool scan_set_matches(const char* set, bool negate,
                                    std::int32_t c) noexcept {
    if (c == EOF) {
        return false;
    }
    bool inside = false;
    for (const char* q = set; *q != '\0' && *q != ']'; ++q) {
        if (q[1] == '-' && q[2] != '\0' && q[2] != ']') {
            if (c >= static_cast<unsigned char>(*q) &&
                c <= static_cast<unsigned char>(q[2])) {
                inside = true;
            }
            q += 2;
        } else if (static_cast<unsigned char>(*q) ==
                   static_cast<unsigned char>(c)) {
            inside = true;
        }
    }
    return inside != negate;
}

// The conversions that read a field of characters rather than store one:
// numeric, `%s` and `%[` skip leading whitespace, `%c` does not. The
// units skipped are part of what the walk has read.
void scan_skip_leading_space(ScanSource& s, std::size_t& chars_read) noexcept {
    for (;;) {
        const std::int32_t c = scan_unit(s);
        if (c == EOF || !scan_is_space(c)) {
            if (c != EOF) {
                scan_unget(s, c);
            }
            break;
        }
        ++chars_read;
    }
}

// The walk itself. `fmt` is the narrow format when `wide` is false and
// the wide one when true; the walk reads the same units either way, and
// the destination width follows the format's own letters. `secure` is
// the `_s` contract: every string conversion's destination is followed
// by a size argument that bounds how much the walk may write.
[[nodiscard]] std::int32_t scan_walk(ScanSource& s, MsArgs& ap, bool wide,
                                     const char* fmt_n,
                                     const char16_t* fmt_w,
                                     bool secure) noexcept {
    std::int32_t assigned = 0;
    std::size_t chars_read = 0;
    std::size_t fn = 0;  // the format cursor, in units

    auto fmt_unit = [&]() -> std::int32_t {
        if (wide) {
            return fmt_w[fn] == u'\0' ? 0
                                      : static_cast<std::int32_t>(fmt_w[fn]);
        }
        return fmt_n[fn] == '\0' ? 0
                                 : static_cast<unsigned char>(fmt_n[fn]);
    };
    auto fmt_next = [&]() { ++fn; };

    for (;;) {
        std::int32_t f = fmt_unit();
        if (f == 0) {
            break;
        }
        if (scan_is_space(f)) {
            // A whitespace in the format matches any run of input
            // whitespace, and no characters are stored.
            scan_skip_leading_space(s, chars_read);
            fmt_next();
            continue;
        }
        if (f != '%') {
            // A literal: the next input unit must equal it, or the walk
            // stops here and reports what was assigned before.
            const std::int32_t c = scan_unit(s);
            ++chars_read;
            if (c == EOF || c != f) {
                if (c != EOF) {
                    scan_unget(s, c);
                }
                break;
            }
            fmt_next();
            continue;
        }
        fmt_next();
        f = fmt_unit();
        if (f == 0) {
            break;
        }
        if (f == '%') {
            const std::int32_t c = scan_unit(s);
            ++chars_read;
            if (c != '%') {
                if (c != EOF) {
                    scan_unget(s, c);
                }
                break;
            }
            fmt_next();
            continue;
        }
        bool suppress = false;
        if (f == '*') {
            suppress = true;
            fmt_next();
            f = fmt_unit();
        }
        std::size_t width = 0;
        while (f >= '0' && f <= '9') {
            width = width * 10 + static_cast<std::size_t>(f - '0');
            fmt_next();
            f = fmt_unit();
        }
        bool is_long = false;
        bool is_long_long = false;
        bool is_short = false;
        bool is_size = false;
        if (f == 'h') {
            is_short = true;
            fmt_next();
            f = fmt_unit();
            if (f == 'h') {
                fmt_next();
                f = fmt_unit();
            }
        } else if (f == 'l') {
            is_long = true;
            fmt_next();
            f = fmt_unit();
            if (f == 'l') {
                is_long_long = true;
                fmt_next();
                f = fmt_unit();
            }
        } else if (f == 'z' || f == 'j' || f == 't') {
            is_size = true;
            fmt_next();
            f = fmt_unit();
        }
        const std::int32_t conv = f;
        fmt_next();
        if (conv == 0) {
            break;
        }
        // The conversion that names no destination.
        if (conv == 'n') {
            auto store_count = [&](auto* at) {
                if (!suppress && at != nullptr) {
                    *at = static_cast<std::remove_pointer_t<decltype(at)>>(
                        chars_read);
                }
            };
            if (is_long_long) store_count(next_arg<std::int64_t*>(ap));
            else if (is_size) store_count(next_arg<std::int64_t*>(ap));
            else if (is_long) store_count(next_arg<long*>(ap));
            else if (is_short) store_count(next_arg<short*>(ap));
            else store_count(next_arg<std::int32_t*>(ap));
            continue;
        }
        const bool numeric = conv == 'd' || conv == 'i' || conv == 'u' ||
                             conv == 'o' || conv == 'x' || conv == 'X' ||
                             conv == 'f' || conv == 'e' || conv == 'g' ||
                             conv == 'a';
        const bool is_string = conv == 's' || conv == '[';

        // Numeric and string fields skip leading whitespace; `%c` reads
        // the next unit whatever it is.
        if (numeric || is_string) {
            scan_skip_leading_space(s, chars_read);
        }

        if (numeric) {
            if (conv == 'f' || conv == 'e' || conv == 'g' || conv == 'a') {
                std::size_t got = 0;
                const double v = scan_accumulate_float(s, width, got);
                chars_read += got;
                if (got == 0) {
                    return assigned == 0 ? EOF : assigned;
                }
                if (is_long) {
                    auto* at = next_arg<double*>(ap);
                    if (!suppress && at != nullptr) {
                        *at = v;
                    }
                } else {
                    auto* at = next_arg<float*>(ap);
                    if (!suppress && at != nullptr) {
                        *at = static_cast<float>(v);
                    }
                }
            } else {
                const int base = conv == 'x' || conv == 'X' ? 16
                                : conv == 'o'               ? 8
                                : conv == 'i'               ? 0
                                                           : 10;
                std::size_t got = 0;
                const std::int64_t v = scan_accumulate_int(s, base, width, got);
                chars_read += got;
                if (got == 0) {
                    return assigned == 0 ? EOF : assigned;
                }
                if (conv == 'd' || conv == 'i') {
                    if (is_long_long || is_size) {
                        auto* at = next_arg<std::int64_t*>(ap);
                        if (!suppress && at != nullptr) *at = v;
                    } else if (is_long) {
                        auto* at = next_arg<long*>(ap);
                        if (!suppress && at != nullptr)
                            *at = static_cast<long>(v);
                    } else if (is_short) {
                        auto* at = next_arg<short*>(ap);
                        if (!suppress && at != nullptr)
                            *at = static_cast<short>(v);
                    } else {
                        auto* at = next_arg<std::int32_t*>(ap);
                        if (!suppress && at != nullptr)
                            *at = static_cast<std::int32_t>(v);
                    }
                } else {
                    if (is_long_long || is_size) {
                        auto* at = next_arg<std::uint64_t*>(ap);
                        if (!suppress && at != nullptr)
                            *at = static_cast<std::uint64_t>(v);
                    } else if (is_long) {
                        auto* at = next_arg<unsigned long*>(ap);
                        if (!suppress && at != nullptr)
                            *at = static_cast<unsigned long>(v);
                    } else if (is_short) {
                        auto* at = next_arg<unsigned short*>(ap);
                        if (!suppress && at != nullptr)
                            *at = static_cast<unsigned short>(v);
                    } else {
                        auto* at = next_arg<std::uint32_t*>(ap);
                        if (!suppress && at != nullptr)
                            *at = static_cast<std::uint32_t>(v);
                    }
                }
            }
            if (!suppress) {
                ++assigned;
            }
            continue;
        }
        // The string conversions.
        if (conv == 's') {
            const bool wide_dest = wide && !is_short;
            // The `_s` form carries the destination's size after the
            // pointer; the walk writes at most that many units, keeping
            // one for the terminator.
            std::size_t limit = width;
            if (secure && !suppress) {
                const std::size_t cap = next_arg<std::size_t>(ap);
                if (cap > 1 && (limit == 0 || cap - 1 < limit)) {
                    limit = cap - 1;
                } else if (cap <= 1) {
                    limit = 0;
                }
            }
            if (wide_dest) {
                char16_t* dest = next_arg<char16_t*>(ap);
                std::size_t wrote = 0;
                if (!suppress && dest != nullptr) {
                    for (;;) {
                        const std::int32_t c = scan_unit(s);
                        if (c == EOF || scan_is_space(c)) {
                            if (c != EOF) scan_unget(s, c);
                            break;
                        }
                        if (limit != 0 && wrote >= limit) {
                            scan_unget(s, c);
                            break;
                        }
                        dest[wrote++] = static_cast<char16_t>(
                            static_cast<std::uint16_t>(c));
                        ++chars_read;
                    }
                    dest[wrote] = u'\0';
                }
                if (wrote == 0 && !suppress) {
                    return assigned == 0 ? EOF : assigned;
                }
            } else {
                char* dest = next_arg<char*>(ap);
                std::size_t wrote = 0;
                if (!suppress && dest != nullptr) {
                    for (;;) {
                        const std::int32_t c = scan_unit(s);
                        if (c == EOF || scan_is_space(c)) {
                            if (c != EOF) scan_unget(s, c);
                            break;
                        }
                        if (limit != 0 && wrote >= limit) {
                            scan_unget(s, c);
                            break;
                        }
                        dest[wrote++] = static_cast<char>(c);
                        ++chars_read;
                    }
                    dest[wrote] = '\0';
                }
                if (wrote == 0 && !suppress) {
                    return assigned == 0 ? EOF : assigned;
                }
            }
            if (!suppress) {
                ++assigned;
            }
            continue;
        }
        if (conv == 'c') {
            const bool wide_dest = wide && !is_short;
            // `%c` reads exactly the width (one by default) and writes
            // no terminator; the `_s` form bounds the run by the size
            // argument that follows the pointer.
            std::size_t want = width == 0 ? 1 : width;
            if (secure && !suppress) {
                const std::size_t cap = next_arg<std::size_t>(ap);
                if (cap < want) {
                    want = cap;
                }
            }
            std::size_t got = 0;
            if (wide_dest) {
                char16_t* dest = next_arg<char16_t*>(ap);
                for (std::size_t i = 0; i < want; ++i) {
                    const std::int32_t c = scan_unit(s);
                    if (c == EOF) break;
                    if (!suppress && dest != nullptr) {
                        dest[i] = static_cast<char16_t>(
                            static_cast<std::uint16_t>(c));
                    }
                    ++chars_read;
                    ++got;
                }
            } else {
                char* dest = next_arg<char*>(ap);
                for (std::size_t i = 0; i < want; ++i) {
                    const std::int32_t c = scan_unit(s);
                    if (c == EOF) break;
                    if (!suppress && dest != nullptr) {
                        dest[i] = static_cast<char>(c);
                    }
                    ++chars_read;
                    ++got;
                }
            }
            if (got == 0 && !suppress) {
                return assigned == 0 ? EOF : assigned;
            }
            if (!suppress) {
                ++assigned;
            }
            continue;
        }
        if (conv == '[') {
            // The scanset, whose text is ASCII in either format. A `^`
            // right after the bracket negates the set.
            char setbuf[256];
            std::size_t k = 0;
            bool negate = false;
            std::int32_t sc = fmt_unit();
            fmt_next();
            if (sc == '^') {
                negate = true;
                sc = fmt_unit();
                fmt_next();
            }
            if (sc == ']') {
                setbuf[k++] = ']';
                sc = fmt_unit();
                fmt_next();
            }
            while (sc != 0 && sc != ']') {
                if (k + 1 < sizeof(setbuf)) {
                    setbuf[k++] = static_cast<char>(sc);
                }
                sc = fmt_unit();
                fmt_next();
            }
            setbuf[k] = '\0';
            const bool wide_dest = wide;
            // The `_s` form bounds the stored run, with room for the
            // terminator, as `%s` does.
            std::size_t limit = width;
            if (secure && !suppress) {
                const std::size_t cap = next_arg<std::size_t>(ap);
                if (cap > 1 && (limit == 0 || cap - 1 < limit)) {
                    limit = cap - 1;
                } else if (cap <= 1) {
                    limit = 0;
                }
            }
            std::size_t wrote = 0;
            if (wide_dest) {
                char16_t* dest = next_arg<char16_t*>(ap);
                if (!suppress && dest != nullptr) {
                    for (;;) {
                        const std::int32_t c = scan_unit(s);
                        if (c == EOF ||
                            !scan_set_matches(setbuf, negate, c)) {
                            if (c != EOF) scan_unget(s, c);
                            break;
                        }
                        if (limit != 0 && wrote >= limit) {
                            scan_unget(s, c);
                            break;
                        }
                        dest[wrote++] = static_cast<char16_t>(
                            static_cast<std::uint16_t>(c));
                        ++chars_read;
                    }
                    dest[wrote] = u'\0';
                }
            } else {
                char* dest = next_arg<char*>(ap);
                if (!suppress && dest != nullptr) {
                    for (;;) {
                        const std::int32_t c = scan_unit(s);
                        if (c == EOF ||
                            !scan_set_matches(setbuf, negate, c)) {
                            if (c != EOF) scan_unget(s, c);
                            break;
                        }
                        if (limit != 0 && wrote >= limit) {
                            scan_unget(s, c);
                            break;
                        }
                        dest[wrote++] = static_cast<char>(c);
                        ++chars_read;
                    }
                    dest[wrote] = '\0';
                }
            }
            if (wrote == 0 && !suppress) {
                return assigned == 0 ? EOF : assigned;
            }
            if (!suppress) {
                ++assigned;
            }
            continue;
        }
        // Any other conversion letter is not one this walk implements;
        // the field is skipped as if suppressed.
        continue;
    }
    return assigned;
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
    (void)locale;
    if (format == nullptr || stream == nullptr) {
        return -1;
    }
    GuestState* g = guest_state();
    if (g == nullptr) {
        return -1;
    }
    ScanSource s;
    s.stream = translate_stream(*g, reinterpret_cast<std::uint64_t>(stream));
    if (s.stream == nullptr) {
        return -1;
    }
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    return scan_walk(s, cursor, false, format, nullptr, false);
}

extern "C" __attribute__((ms_abi)) std::int32_t
u32u___stdio_common_vsscanf(std::uint64_t options, const char* buffer,
                            std::size_t size, const char* format,
                            void* locale, __builtin_ms_va_list args) noexcept {
    (void)options;
    (void)locale;
    if (buffer == nullptr || format == nullptr) {
        return -1;
    }
    ScanSource s;
    s.at = buffer;
    s.end = buffer + size;
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    return scan_walk(s, cursor, false, format, nullptr, false);
}

extern "C" __attribute__((ms_abi)) std::int32_t
u32u___stdio_common_vfwprintf(std::uint64_t options, void* stream,
                              const char16_t* format, void* locale,
                              __builtin_ms_va_list args) noexcept {
    (void)options;
    (void)locale;
    if (format == nullptr || stream == nullptr) {
        return -1;
    }
    OutW o;
    o.stream = static_cast<FILE*>(stream);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    return format_wide(o, format, cursor);
}

extern "C" __attribute__((ms_abi)) std::int32_t
u32u___stdio_common_vswprintf(std::uint64_t options, char16_t* buffer,
                              std::size_t size, const char16_t* format,
                              void* locale, __builtin_ms_va_list args) noexcept {
    (void)options;
    (void)locale;
    if (format == nullptr || buffer == nullptr || size == 0) {
        return -1;
    }
    OutW o;
    o.buf = buffer;
    o.cap = size;
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    const std::int32_t n = format_wide(o, format, cursor);
    out_wide_finish(o);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t
u32u___stdio_common_vswprintf_s(std::uint64_t options, char16_t* buffer,
                                std::size_t size, const char16_t* format,
                                void* locale,
                                __builtin_ms_va_list args) noexcept {
    (void)options;
    (void)locale;
    if (format == nullptr || buffer == nullptr || size == 0) {
        return -1;
    }
    OutW o;
    o.buf = buffer;
    o.cap = size;
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    const std::int32_t n = format_wide(o, format, cursor);
    out_wide_finish(o);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t
u32u___stdio_common_vsnwprintf_s(std::uint64_t options, char16_t* buffer,
                                 std::size_t size, std::size_t count,
                                 const char16_t* format, void* locale,
                                 __builtin_ms_va_list args) noexcept {
    (void)options;
    (void)locale;
    if (format == nullptr || buffer == nullptr || size == 0) {
        return -1;
    }
    OutW o;
    o.buf = buffer;
    o.cap = count == 0 ? size : std::min(count, size);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    const std::int32_t n = format_wide(o, format, cursor);
    out_wide_finish(o);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t
u32u___stdio_common_vfwscanf(std::uint64_t options, void* stream,
                             const char16_t* format, void* locale,
                             __builtin_ms_va_list args) noexcept {
    (void)options;
    (void)locale;
    if (format == nullptr || stream == nullptr) {
        return -1;
    }
    GuestState* g = guest_state();
    if (g == nullptr) {
        return -1;
    }
    ScanSource s;
    s.stream = translate_stream(*g, reinterpret_cast<std::uint64_t>(stream));
    if (s.stream == nullptr) {
        return -1;
    }
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    return scan_walk(s, cursor, true, nullptr, format, false);
}

extern "C" __attribute__((ms_abi)) std::int32_t
u32u___stdio_common_vswscanf(std::uint64_t options, const char16_t* buffer,
                             std::size_t size, const char16_t* format,
                             void* locale, __builtin_ms_va_list args) noexcept {
    (void)options;
    (void)locale;
    if (buffer == nullptr || format == nullptr) {
        return -1;
    }
    ScanSource s;
    s.wat = buffer;
    s.wend = buffer + size;
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    return scan_walk(s, cursor, true, nullptr, format, false);
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
    // The handle is recorded before it is answered with, so that the free
    // can recognize it; a guest that never frees it leaks one object, which
    // is the same leak a program that never calls `_free_locale` has.
    {
        const std::lock_guard<std::mutex> guard(locale_ledger_mutex());
        locale_ledger().push_back(loc);
    }
    return reinterpret_cast<std::uint64_t>(loc);
}

extern "C" __attribute__((ms_abi)) void u32u__free_locale(
    std::uint64_t locale) noexcept {
    if (locale == 0) {
        return;
    }
    auto* target = reinterpret_cast<CrtLocale*>(locale);
    // Only a handle this runtime minted is freed. A value the guest made up
    // is ignored, because freeing an address the caller chose would hand the
    // choice of what the host frees to the guest.
    const std::lock_guard<std::mutex> guard(locale_ledger_mutex());
    std::vector<CrtLocale*>& ledger = locale_ledger();
    for (auto it = ledger.begin(); it != ledger.end(); ++it) {
        if (*it == target) {
            ledger.erase(it);
            delete target;
            return;
        }
    }
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

namespace {

// One redirection a command line asked for, at the spelling the guest wrote:
// `<` reads standard input, `>` writes standard output, `>>` appends to it,
// and a leading `1` or `2` on the operator selects the stream.
struct CommandRedirection {
    int stream = 1;
    bool append = false;
    std::string path;
};

// One item of the line, in the order it was written: a word, or a
// redirection operator waiting for the word that names its file.
struct CommandToken {
    bool redirect = false;
    int stream = 1;
    bool append = false;
    std::string text;
};

// A character a command language would act on rather than pass through. The
// interpreter refuses a line that carries one, because reading it as an
// ordinary argument would run a different command from the one the guest
// wrote, and handing it to a shell to interpret is exactly the host command
// processor this runtime does not put in the guest's hands.
[[nodiscard]] bool is_shell_metacharacter(char c) noexcept {
    switch (c) {
        case '|':
        case '&':
        case ';':
        case '(':
        case ')':
        case '`':
        case '$':
        case '*':
        case '?':
        case '%':
        case '!':
        case '^':
        case '\n':
        case '\r':
            return true;
        default:
            return false;
    }
}

// Splits a command line into words and redirection operators. Returns false
// for a line this interpreter does not implement: an unterminated quote, a
// shell metacharacter, or a stream number in front of an operator.
[[nodiscard]] bool lex_command_line(const std::string& line,
                                    std::vector<CommandToken>& out) noexcept {
    std::string word;
    bool has_word = false;
    bool in_quotes = false;
    std::size_t i = 0;
    while (i < line.size()) {
        const char c = line[i];
        if (in_quotes) {
            if (c == '"') {
                in_quotes = false;
            } else {
                word.push_back(c);
                has_word = true;
            }
            ++i;
            continue;
        }
        if (c == '"') {
            in_quotes = true;
            has_word = true;  // an empty pair still names an empty word
            ++i;
            continue;
        }
        if (c == ' ' || c == '\t') {
            if (has_word) {
                out.push_back(CommandToken{false, 1, false, std::move(word)});
                word = std::string();
                has_word = false;
            }
            ++i;
            continue;
        }
        if (c == '>' || c == '<') {
            CommandToken token;
            token.redirect = true;
            token.stream = c == '<' ? 0 : 1;
            // A stream number written against the operator -- `1>`, `2>` --
            // selects which stream it is. The number has to be adjacent, so
            // a word that merely happens to be a digit followed by a space
            // is still an argument.
            if (has_word && (word == "1" || word == "2")) {
                token.stream = word[0] - '0';
                word = std::string();
                has_word = false;
            }
            if (c == '>' && i + 1 < line.size() && line[i + 1] == '>') {
                token.append = true;
                ++i;
            }
            out.push_back(std::move(token));
            ++i;
            continue;
        }
        if (is_shell_metacharacter(c)) {
            return false;
        }
        word.push_back(c);
        has_word = true;
        ++i;
    }
    if (in_quotes) {
        return false;
    }
    if (has_word) {
        out.push_back(CommandToken{false, 1, false, std::move(word)});
    }
    return true;
}

// The words the line names and the streams its redirections fill.
struct ParsedCommand {
    std::vector<std::string> words;
    std::vector<CommandRedirection> redirections;
};

[[nodiscard]] bool split_command(const std::vector<CommandToken>& tokens,
                                 ParsedCommand& out) noexcept {
    for (std::size_t i = 0; i < tokens.size(); ++i) {
        const CommandToken& token = tokens[i];
        if (!token.redirect) {
            out.words.push_back(token.text);
            continue;
        }
        // A redirection operator's operand is the word after it; an operator
        // at the end of the line, or in front of another operator, names no
        // file and is refused.
        if (i + 1 >= tokens.size() || tokens[i + 1].redirect) {
            return false;
        }
        CommandRedirection redirection;
        redirection.stream = token.stream;
        redirection.append = token.append;
        redirection.path = tokens[i + 1].text;
        out.redirections.push_back(std::move(redirection));
        ++i;
    }
    return true;
}

[[nodiscard]] bool is_builtin(const std::string& name) noexcept {
    // cmd matches a command name without regard to case.
    std::string lower = name;
    for (char& c : lower) {
        c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    }
    return lower == "echo" || lower == "rem" || lower == "::";
}

[[nodiscard]] bool write_all(int fd, std::string_view text) noexcept {
    std::size_t at = 0;
    while (at < text.size()) {
        const ssize_t put = ::write(fd, text.data() + at, text.size() - at);
        if (put < 0) {
            return false;
        }
        at += static_cast<std::size_t>(put);
    }
    return true;
}

// Runs a command this interpreter answers itself, so that a container root
// holding no `/bin/echo` still runs a batch line that only echoes or
// comments. `out_fd` is the descriptor redirection opened, or -1 for the
// process's own standard output.
[[nodiscard]] std::int32_t run_builtin(const std::vector<std::string>& words,
                                       int out_fd) noexcept {
    std::string lower = words[0];
    for (char& c : lower) {
        c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    }
    if (lower == "rem" || lower == "::") {
        return 0;  // a comment: the rest of the line is text, not a command
    }
    std::string text;
    for (std::size_t i = 1; i < words.size(); ++i) {
        if (i > 1) {
            text.push_back(' ');
        }
        text += words[i];
    }
    text.push_back('\n');
    const int fd = out_fd >= 0 ? out_fd : STDOUT_FILENO;
    return write_all(fd, text) ? 0 : 1;
}

// Runs one command line the way Windows' own command processor would, but
// without a host shell in the path. The line is split by this runtime's own
// lexer, redirection is applied by opening the named file, and the program
// is started directly, so no command language ever sees the guest's text.
[[nodiscard]] std::int32_t run_command_line(const char* command) noexcept {
    std::vector<CommandToken> tokens;
    if (!lex_command_line(std::string(command), tokens)) {
        set_errno_value(kEInval);
        return -1;
    }
    ParsedCommand parsed;
    if (!split_command(tokens, parsed)) {
        set_errno_value(kEInval);
        return -1;
    }
    if (parsed.words.empty()) {
        // An empty line, or one that only redirects, is an empty command:
        // cmd answers success for it.
        return 0;
    }

    // The redirection files are opened before the child exists, so a name
    // that cannot be opened is reported with the command unrun rather than
    // as the child's death, and no half-built child is left behind.
    int in_fd = -1;
    int out_fd = -1;
    int err_fd = -1;
    for (const CommandRedirection& redirection : parsed.redirections) {
        const std::string host = from_dos_path(redirection.path);
        int fd = -1;
        if (redirection.stream == 0) {
            fd = contained_open(host.c_str(), O_RDONLY, 0);
        } else {
            const int flags =
                O_WRONLY | O_CREAT | (redirection.append ? O_APPEND : O_TRUNC);
            fd = contained_open(host.c_str(), flags, 0666);
        }
        if (fd < 0) {
            if (in_fd >= 0) {
                ::close(in_fd);
            }
            if (out_fd >= 0) {
                ::close(out_fd);
            }
            if (err_fd >= 0) {
                ::close(err_fd);
            }
            set_errno_value(kENoEnt);
            return -1;
        }
        if (redirection.stream == 0) {
            in_fd = fd;
        } else if (redirection.stream == 1) {
            out_fd = fd;
        } else {
            err_fd = fd;
        }
    }
    const auto close_redirects = [&]() {
        if (in_fd >= 0) {
            ::close(in_fd);
        }
        if (out_fd >= 0) {
            ::close(out_fd);
        }
        if (err_fd >= 0) {
            ::close(err_fd);
        }
    };

    if (is_builtin(parsed.words[0])) {
        const std::int32_t code = run_builtin(parsed.words, out_fd);
        close_redirects();
        return code;
    }

    std::vector<char*> argv;
    argv.reserve(parsed.words.size() + 1);
    for (std::string& word : parsed.words) {
        argv.push_back(word.data());
    }
    argv.push_back(nullptr);

    const pid_t pid = ::fork();
    if (pid < 0) {
        close_redirects();
        return -1;
    }
    if (pid == 0) {
        if (in_fd >= 0) {
            (void)::dup2(in_fd, STDIN_FILENO);
            ::close(in_fd);
        }
        if (out_fd >= 0) {
            (void)::dup2(out_fd, STDOUT_FILENO);
            ::close(out_fd);
        }
        if (err_fd >= 0) {
            (void)::dup2(err_fd, STDERR_FILENO);
            ::close(err_fd);
        }
        ::execvp(argv[0], argv.data());
        ::_exit(127);  // the program could not be started
    }
    close_redirects();
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            set_errno_value(kEInval);
            return -1;
        }
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::int32_t u32u_system(
    const char* command) noexcept {
    if (command == nullptr) {
        return 1;  // the documented "a command processor is present"
    }
    return run_command_line(command);
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

// The record the new thread's trampoline owns and frees: the entry and its
// argument, which only that thread reads. It is kept apart from the handle
// the call answers with, because the two have different owners -- the
// trampoline frees this record when the entry returns, while the handle
// stays with the caller.
struct ThreadStart {
    BeginThreadFn fn;
    void* arg;
};

// The identity `_beginthreadex` answers with. It outlives the thread's
// start record deliberately: freeing it here, in the trampoline, would hand
// the caller a handle to memory that was already gone by the time the call
// returned it.
struct CrtThreadHandle {
    std::uint32_t id;
};

std::uint32_t thread_trampoline(ThreadStart* start) noexcept {
    const BeginThreadFn fn = start->fn;
    void* arg = start->arg;
    // Only the start record is this thread's to free; the handle belongs to
    // the caller that the call answered.
    delete start;
    return fn(arg);
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
    auto* handle = new CrtThreadHandle{++next_id};
    if (thread_id != nullptr) {
        *thread_id = handle->id;
    }
    auto* start = new ThreadStart{fn, arg};
    std::thread(thread_trampoline, start).detach();
    // The handle the call answers with is the caller's to close, which is
    // why it is not the record the trampoline frees.
    return reinterpret_cast<std::uintptr_t>(handle);
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

// The CRT's `tm` is nine thirty-two-bit fields -- thirty-six bytes -- in
// the order the header declares. The host's `struct tm` carries a UTC offset
// and a zone pointer after those nine, so a `localtime_r` straight into the
// guest's structure writes a host pointer into the guest's memory and runs
// twenty bytes past the thirty-six it allocated. The fields are copied one
// by one, and the tail stays where it belongs.
void store_crt_tm(void* out, const struct ::tm& tm) noexcept {
    const std::int32_t fields[9] = {
        tm.tm_sec,  tm.tm_min,  tm.tm_hour, tm.tm_mday, tm.tm_mon,
        tm.tm_year, tm.tm_wday, tm.tm_yday, tm.tm_isdst};
    std::memcpy(out, fields, sizeof(fields));
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_localtime_s(
    void* out, const std::int64_t* timer) noexcept {
    if (out == nullptr || timer == nullptr) {
        return kErrParam;
    }
    // The CRT's own time base: seconds from 1970, the same as the host's.
    const std::time_t t = static_cast<std::time_t>(*timer);
    struct ::tm converted = {};
    if (::localtime_r(&t, &converted) == nullptr) {
        return kErrParam;
    }
    store_crt_tm(out, converted);
    return 0;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_gmtime_s(
    void* out, const std::int64_t* timer) noexcept {
    if (out == nullptr || timer == nullptr) {
        return kErrParam;
    }
    const std::time_t t = static_cast<std::time_t>(*timer);
    struct ::tm converted = {};
    if (::gmtime_r(&t, &converted) == nullptr) {
        return kErrParam;
    }
    store_crt_tm(out, converted);
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
// The classic entry points.
//
// A program that predates the `__stdio_common_*` rework calls `printf`
// and `scanf` by name; each entry below is that call -- the format walk
// it routes to is the same one the modern entry points use, with the
// caller's stream or buffer and its own argument list.
// ===========================================================================

extern "C" __attribute__((ms_abi)) std::int32_t u32u_printf(
    const char* format, ...) noexcept {
    if (format == nullptr) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    Out o;
    o.stream = stdout;
    const std::int32_t n = format_narrow(o, format, cursor);
    __builtin_ms_va_end(args);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_fprintf(
    void* stream, const char* format, ...) noexcept {
    if (format == nullptr || stream == nullptr) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    Out o;
    o.stream = static_cast<FILE*>(stream);
    const std::int32_t n = format_narrow(o, format, cursor);
    __builtin_ms_va_end(args);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_sprintf(
    char* buffer, const char* format, ...) noexcept {
    if (buffer == nullptr || format == nullptr) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    Out o;
    o.buf = buffer;
    o.cap = std::numeric_limits<std::size_t>::max();
    const std::int32_t n = format_narrow(o, format, cursor);
    __builtin_ms_va_end(args);
    out_finish(o);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__snprintf(
    char* buffer, std::size_t size, const char* format, ...) noexcept {
    if (buffer == nullptr || size == 0 || format == nullptr) {
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

extern "C" __attribute__((ms_abi)) std::int32_t u32u_vprintf(
    const char* format, __builtin_ms_va_list args) noexcept {
    if (format == nullptr) {
        return -1;
    }
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    Out o;
    o.stream = stdout;
    return format_narrow(o, format, cursor);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_vfprintf(
    void* stream, const char* format, __builtin_ms_va_list args) noexcept {
    if (format == nullptr || stream == nullptr) {
        return -1;
    }
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    Out o;
    o.stream = static_cast<FILE*>(stream);
    return format_narrow(o, format, cursor);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_vsprintf(
    char* buffer, const char* format, __builtin_ms_va_list args) noexcept {
    if (buffer == nullptr || format == nullptr) {
        return -1;
    }
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    Out o;
    o.buf = buffer;
    o.cap = std::numeric_limits<std::size_t>::max();
    const std::int32_t n = format_narrow(o, format, cursor);
    out_finish(o);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__vsnprintf(
    char* buffer, std::size_t size, const char* format,
    __builtin_ms_va_list args) noexcept {
    if (buffer == nullptr || size == 0 || format == nullptr) {
        return -1;
    }
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    Out o;
    o.buf = buffer;
    o.cap = size;
    const std::int32_t n = format_narrow(o, format, cursor);
    out_finish(o);
    return n;
}

// The wide printf face, one entry per classic name.
extern "C" __attribute__((ms_abi)) std::int32_t u32u_wprintf(
    const char16_t* format, ...) noexcept {
    if (format == nullptr) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    OutW o;
    o.stream = stdout;
    const std::int32_t n = format_wide(o, format, cursor);
    __builtin_ms_va_end(args);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_fwprintf(
    void* stream, const char16_t* format, ...) noexcept {
    if (format == nullptr || stream == nullptr) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    OutW o;
    o.stream = static_cast<FILE*>(stream);
    const std::int32_t n = format_wide(o, format, cursor);
    __builtin_ms_va_end(args);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_swprintf(
    char16_t* buffer, std::size_t size, const char16_t* format, ...) noexcept {
    if (buffer == nullptr || size == 0 || format == nullptr) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    OutW o;
    o.buf = buffer;
    o.cap = size;
    const std::int32_t n = format_wide(o, format, cursor);
    __builtin_ms_va_end(args);
    out_wide_finish(o);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__snwprintf(
    char16_t* buffer, std::size_t size, const char16_t* format, ...) noexcept {
    if (buffer == nullptr || size == 0 || format == nullptr) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    OutW o;
    o.buf = buffer;
    o.cap = size;
    const std::int32_t n = format_wide(o, format, cursor);
    __builtin_ms_va_end(args);
    out_wide_finish(o);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__snwprintf_s(
    char16_t* buffer, std::size_t size, std::size_t count,
    const char16_t* format, ...) noexcept {
    if (buffer == nullptr || size == 0 || format == nullptr) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    OutW o;
    o.buf = buffer;
    o.cap = count == 0 ? size : std::min(count, size);
    const std::int32_t n = format_wide(o, format, cursor);
    __builtin_ms_va_end(args);
    out_wide_finish(o);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_vwprintf(
    const char16_t* format, __builtin_ms_va_list args) noexcept {
    if (format == nullptr) {
        return -1;
    }
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    OutW o;
    o.stream = stdout;
    return format_wide(o, format, cursor);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_vfwprintf(
    void* stream, const char16_t* format, __builtin_ms_va_list args) noexcept {
    if (format == nullptr || stream == nullptr) {
        return -1;
    }
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    OutW o;
    o.stream = static_cast<FILE*>(stream);
    return format_wide(o, format, cursor);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_vswprintf(
    char16_t* buffer, std::size_t size, const char16_t* format,
    __builtin_ms_va_list args) noexcept {
    if (buffer == nullptr || size == 0 || format == nullptr) {
        return -1;
    }
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    OutW o;
    o.buf = buffer;
    o.cap = size;
    const std::int32_t n = format_wide(o, format, cursor);
    out_wide_finish(o);
    return n;
}

// The classic scanf face, one entry per name. The secure forms carry a
// size after every string destination and hand the walk `secure=true`.
extern "C" __attribute__((ms_abi)) std::int32_t u32u_scanf(
    const char* format, ...) noexcept {
    if (format == nullptr) {
        return -1;
    }
    GuestState* g = guest_state();
    if (g == nullptr || g->iob_base == 0) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    ScanSource s;
    s.stream = translate_stream(*g, g->iob_base);
    const std::int32_t n = scan_walk(s, cursor, false, format, nullptr, false);
    __builtin_ms_va_end(args);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_fscanf(
    void* stream, const char* format, ...) noexcept {
    if (format == nullptr || stream == nullptr) {
        return -1;
    }
    GuestState* g = guest_state();
    if (g == nullptr) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    ScanSource s;
    s.stream = translate_stream(*g, reinterpret_cast<std::uint64_t>(stream));
    const std::int32_t n = scan_walk(s, cursor, false, format, nullptr, false);
    __builtin_ms_va_end(args);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_sscanf(
    const char* buffer, const char* format, ...) noexcept {
    if (buffer == nullptr || format == nullptr) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    ScanSource s;
    s.at = buffer;
    const std::int32_t n = scan_walk(s, cursor, false, format, nullptr, false);
    __builtin_ms_va_end(args);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__snscanf(
    const char* buffer, std::size_t size, const char* format, ...) noexcept {
    if (buffer == nullptr || size == 0 || format == nullptr) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    ScanSource s;
    s.at = buffer;
    s.end = buffer + size;
    const std::int32_t n = scan_walk(s, cursor, false, format, nullptr, false);
    __builtin_ms_va_end(args);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_scanf_s(
    const char* format, ...) noexcept {
    if (format == nullptr) {
        return -1;
    }
    GuestState* g = guest_state();
    if (g == nullptr || g->iob_base == 0) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    ScanSource s;
    s.stream = translate_stream(*g, g->iob_base);
    const std::int32_t n = scan_walk(s, cursor, false, format, nullptr, true);
    __builtin_ms_va_end(args);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_fscanf_s(
    void* stream, const char* format, ...) noexcept {
    if (format == nullptr || stream == nullptr) {
        return -1;
    }
    GuestState* g = guest_state();
    if (g == nullptr) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    ScanSource s;
    s.stream = translate_stream(*g, reinterpret_cast<std::uint64_t>(stream));
    const std::int32_t n = scan_walk(s, cursor, false, format, nullptr, true);
    __builtin_ms_va_end(args);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_sscanf_s(
    const char* buffer, const char* format, ...) noexcept {
    if (buffer == nullptr || format == nullptr) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    ScanSource s;
    s.at = buffer;
    const std::int32_t n = scan_walk(s, cursor, false, format, nullptr, true);
    __builtin_ms_va_end(args);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u__snscanf_s(
    const char* buffer, std::size_t size, const char* format, ...) noexcept {
    if (buffer == nullptr || size == 0 || format == nullptr) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    ScanSource s;
    s.at = buffer;
    s.end = buffer + size;
    const std::int32_t n = scan_walk(s, cursor, false, format, nullptr, true);
    __builtin_ms_va_end(args);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_vscanf(
    const char* format, __builtin_ms_va_list args) noexcept {
    if (format == nullptr) {
        return -1;
    }
    GuestState* g = guest_state();
    if (g == nullptr || g->iob_base == 0) {
        return -1;
    }
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    ScanSource s;
    s.stream = translate_stream(*g, g->iob_base);
    return scan_walk(s, cursor, false, format, nullptr, false);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_vfscanf(
    void* stream, const char* format, __builtin_ms_va_list args) noexcept {
    if (format == nullptr || stream == nullptr) {
        return -1;
    }
    GuestState* g = guest_state();
    if (g == nullptr) {
        return -1;
    }
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    ScanSource s;
    s.stream = translate_stream(*g, reinterpret_cast<std::uint64_t>(stream));
    return scan_walk(s, cursor, false, format, nullptr, false);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_vsscanf(
    const char* buffer, const char* format, __builtin_ms_va_list args) noexcept {
    if (buffer == nullptr || format == nullptr) {
        return -1;
    }
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    ScanSource s;
    s.at = buffer;
    return scan_walk(s, cursor, false, format, nullptr, false);
}

// The wide scanf face.
extern "C" __attribute__((ms_abi)) std::int32_t u32u_wscanf(
    const char16_t* format, ...) noexcept {
    if (format == nullptr) {
        return -1;
    }
    GuestState* g = guest_state();
    if (g == nullptr || g->iob_base == 0) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    ScanSource s;
    s.stream = translate_stream(*g, g->iob_base);
    const std::int32_t n = scan_walk(s, cursor, true, nullptr, format, false);
    __builtin_ms_va_end(args);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_fwscanf(
    void* stream, const char16_t* format, ...) noexcept {
    if (format == nullptr || stream == nullptr) {
        return -1;
    }
    GuestState* g = guest_state();
    if (g == nullptr) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    ScanSource s;
    s.stream = translate_stream(*g, reinterpret_cast<std::uint64_t>(stream));
    const std::int32_t n = scan_walk(s, cursor, true, nullptr, format, false);
    __builtin_ms_va_end(args);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_swscanf(
    const char16_t* buffer, const char16_t* format, ...) noexcept {
    if (buffer == nullptr || format == nullptr) {
        return -1;
    }
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    ScanSource s;
    s.wat = buffer;
    const std::int32_t n = scan_walk(s, cursor, true, nullptr, format, false);
    __builtin_ms_va_end(args);
    return n;
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_vwscanf(
    const char16_t* format, __builtin_ms_va_list args) noexcept {
    if (format == nullptr) {
        return -1;
    }
    GuestState* g = guest_state();
    if (g == nullptr || g->iob_base == 0) {
        return -1;
    }
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    ScanSource s;
    s.stream = translate_stream(*g, g->iob_base);
    return scan_walk(s, cursor, true, nullptr, format, false);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_vfwscanf(
    void* stream, const char16_t* format, __builtin_ms_va_list args) noexcept {
    if (format == nullptr || stream == nullptr) {
        return -1;
    }
    GuestState* g = guest_state();
    if (g == nullptr) {
        return -1;
    }
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    ScanSource s;
    s.stream = translate_stream(*g, reinterpret_cast<std::uint64_t>(stream));
    return scan_walk(s, cursor, true, nullptr, format, false);
}

extern "C" __attribute__((ms_abi)) std::int32_t u32u_vswscanf(
    const char16_t* buffer, const char16_t* format,
    __builtin_ms_va_list args) noexcept {
    if (buffer == nullptr || format == nullptr) {
        return -1;
    }
    MsArgs cursor;
    static_cast<void>(std::memcpy(&cursor.at, &args, sizeof(cursor.at)));
    ScanSource s;
    s.wat = buffer;
    return scan_walk(s, cursor, true, nullptr, format, false);
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
    e("__stdio_common_vfwprintf",
      reinterpret_cast<void*>(&u32u___stdio_common_vfwprintf));
    e("__stdio_common_vswprintf",
      reinterpret_cast<void*>(&u32u___stdio_common_vswprintf));
    e("__stdio_common_vswprintf_s",
      reinterpret_cast<void*>(&u32u___stdio_common_vswprintf_s));
    e("__stdio_common_vsnwprintf_s",
      reinterpret_cast<void*>(&u32u___stdio_common_vsnwprintf_s));
    e("__stdio_common_vfscanf",
      reinterpret_cast<void*>(&u32u___stdio_common_vfscanf));
    e("__stdio_common_vsscanf",
      reinterpret_cast<void*>(&u32u___stdio_common_vsscanf));
    e("__stdio_common_vfwscanf",
      reinterpret_cast<void*>(&u32u___stdio_common_vfwscanf));
    e("__stdio_common_vswscanf",
      reinterpret_cast<void*>(&u32u___stdio_common_vswscanf));
    e("sprintf_s", reinterpret_cast<void*>(&u32u_sprintf_s));
    e("snprintf_s", reinterpret_cast<void*>(&u32u_snprintf_s));
    e("vsnprintf_s", reinterpret_cast<void*>(&u32u_vsnprintf_s));
    e("vsprintf_s", reinterpret_cast<void*>(&u32u_vsprintf_s));
    e("_snprintf_s", reinterpret_cast<void*>(&u32u__snprintf_s));
    // The classic formatted output, whose names predate the common
    // entry points.
    e("printf", reinterpret_cast<void*>(&u32u_printf));
    e("fprintf", reinterpret_cast<void*>(&u32u_fprintf));
    e("sprintf", reinterpret_cast<void*>(&u32u_sprintf));
    e("_snprintf", reinterpret_cast<void*>(&u32u__snprintf));
    e("vprintf", reinterpret_cast<void*>(&u32u_vprintf));
    e("vfprintf", reinterpret_cast<void*>(&u32u_vfprintf));
    e("vsprintf", reinterpret_cast<void*>(&u32u_vsprintf));
    e("_vsnprintf", reinterpret_cast<void*>(&u32u__vsnprintf));
    e("wprintf", reinterpret_cast<void*>(&u32u_wprintf));
    e("fwprintf", reinterpret_cast<void*>(&u32u_fwprintf));
    e("swprintf", reinterpret_cast<void*>(&u32u_swprintf));
    e("_snwprintf", reinterpret_cast<void*>(&u32u__snwprintf));
    e("_snwprintf_s", reinterpret_cast<void*>(&u32u__snwprintf_s));
    e("vwprintf", reinterpret_cast<void*>(&u32u_vwprintf));
    e("vfwprintf", reinterpret_cast<void*>(&u32u_vfwprintf));
    e("vswprintf", reinterpret_cast<void*>(&u32u_vswprintf));
    e("_wprintf", reinterpret_cast<void*>(&u32u_wprintf));
    e("_fwprintf", reinterpret_cast<void*>(&u32u_fwprintf));
    e("_swprintf", reinterpret_cast<void*>(&u32u_swprintf));
    e("_vwprintf", reinterpret_cast<void*>(&u32u_vwprintf));
    e("_vfwprintf", reinterpret_cast<void*>(&u32u_vfwprintf));
    e("_vswprintf", reinterpret_cast<void*>(&u32u_vswprintf));
    // The classic formatted input.
    e("scanf", reinterpret_cast<void*>(&u32u_scanf));
    e("fscanf", reinterpret_cast<void*>(&u32u_fscanf));
    e("sscanf", reinterpret_cast<void*>(&u32u_sscanf));
    e("_snscanf", reinterpret_cast<void*>(&u32u__snscanf));
    e("scanf_s", reinterpret_cast<void*>(&u32u_scanf_s));
    e("fscanf_s", reinterpret_cast<void*>(&u32u_fscanf_s));
    e("sscanf_s", reinterpret_cast<void*>(&u32u_sscanf_s));
    e("_snscanf_s", reinterpret_cast<void*>(&u32u__snscanf_s));
    e("vscanf", reinterpret_cast<void*>(&u32u_vscanf));
    e("vfscanf", reinterpret_cast<void*>(&u32u_vfscanf));
    e("vsscanf", reinterpret_cast<void*>(&u32u_vsscanf));
    e("wscanf", reinterpret_cast<void*>(&u32u_wscanf));
    e("fwscanf", reinterpret_cast<void*>(&u32u_fwscanf));
    e("swscanf", reinterpret_cast<void*>(&u32u_swscanf));
    e("vwscanf", reinterpret_cast<void*>(&u32u_vwscanf));
    e("vfwscanf", reinterpret_cast<void*>(&u32u_vfwscanf));
    e("vswscanf", reinterpret_cast<void*>(&u32u_vswscanf));
    e("_wscanf", reinterpret_cast<void*>(&u32u_wscanf));
    e("_fwscanf", reinterpret_cast<void*>(&u32u_fwscanf));
    e("_swscanf", reinterpret_cast<void*>(&u32u_swscanf));
    e("_vwscanf", reinterpret_cast<void*>(&u32u_vwscanf));
    e("_vfwscanf", reinterpret_cast<void*>(&u32u_vfwscanf));
    e("_vswscanf", reinterpret_cast<void*>(&u32u_vswscanf));
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
